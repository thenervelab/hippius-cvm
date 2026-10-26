//! `--dedicated-init-wipe` — the booted-OS half of an integrity slot's
//! first boot (docs/design/disk-tier-verification.md §4.2.1, guest
//! release 8).
//!
//! The initramfs opener ([`crate::dedicated`]) formats an integrity slot
//! with `--integrity-no-wipe`, opens it as `/dev/mapper/hippius-<slot>-init`
//! with no journal, writes its two ends, lists it in
//! `/run/hippius/dedicated/init` and reports it `initializing`. The KEK
//! and the slot key stay in the initramfs: what crosses `switch_root` is
//! the open mapping, and this mode needs nothing else. Started by
//! `hippius-dedicated-init.service` (the list's presence), off the boot's
//! critical path, it:
//!
//! 1. checks each listed slot: its state line says `initializing`, the
//!    record on the guest-keyed OS volume says `formatting <U> integrity`,
//!    and the `-init` mapping is the LUKS2 volume `<U>` (its device-mapper
//!    UUID) — anything else is closed and reported `mismatch init-mismatch`;
//! 2. writes zeros through the mapping ([`crate::wipe::wipe`], the OS
//!    overlay's wipe), all slots at once within the same writers budget,
//!    keeping each slot's `init-<percent>` in the state file current for
//!    the receipts;
//! 3. records `ready` (fsync'd) — only then is the slot the tenant's —,
//!    switches the dm-integrity layer to its journal (a table reload: no
//!    key is involved) and renames the stack `hippius-<slot>`, and reports
//!    `attached`.
//!
//! A wipe that fails or is interrupted (reboot, power loss, stop) leaves
//! the record `formatting`: the next boot formats the slot again and the
//! wipe starts from scratch. A finished one is never redone. The record
//! is reached by mounting the OS volume's device a second time in this
//! unit's private mount namespace (`PrivateMounts=yes`), never through the
//! tenant's root.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::Mutex;

use crate::dedicated::{
    init_mapper_name, kernel_name, load_record, mapper_name, render_record, valid_uuid,
    write_atomic, Record, RecordState, RECORD_NAME, STATE_MAGIC,
};
use crate::wipe;

/// One line of the slot-state file, as text (the progress reason is not a
/// closed code).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StateLine {
    pub slot: String,
    pub state: String,
    pub gib: String,
    pub dev: String,
    pub reason: String,
}

/// Parse the state file the opener wrote. Junk lines are dropped.
pub fn parse_state(text: &str) -> Vec<StateLine> {
    text.lines()
        .filter(|l| !l.starts_with('#'))
        .filter_map(|l| {
            let f: Vec<&str> = l.split(' ').collect();
            let [slot, state, gib, dev, reason] = f.as_slice() else {
                return None;
            };
            Some(StateLine {
                slot: (*slot).into(),
                state: (*state).into(),
                gib: (*gib).into(),
                dev: (*dev).into(),
                reason: (*reason).into(),
            })
        })
        .collect()
}

pub fn render_state(lines: &[StateLine]) -> String {
    let mut s = format!("{STATE_MAGIC}\n");
    for l in lines {
        s.push_str(&format!(
            "{} {} {} {} {}\n",
            l.slot, l.state, l.gib, l.dev, l.reason
        ));
    }
    s
}

/// The LUKS UUID a device-mapper UUID names, when it is the LUKS2 crypt
/// mapping `name` cryptsetup made: `CRYPT-LUKS2-<32 hex>-<name>`.
pub fn luks_uuid_of_dm_uuid(dm_uuid: &str, name: &str) -> Option<String> {
    let rest = dm_uuid.trim().strip_prefix("CRYPT-LUKS2-")?;
    let (hex, tail) = rest.split_at_checked(32)?;
    if tail != format!("-{name}") {
        return None;
    }
    let h = hex.to_ascii_lowercase();
    let uuid = format!(
        "{}-{}-{}-{}-{}",
        &h[..8],
        &h[8..12],
        &h[12..16],
        &h[16..20],
        &h[20..]
    );
    valid_uuid(&uuid).then_some(uuid)
}

/// `dmsetup table` of a dm-integrity layer with its mode switched from
/// `D` (no journal) to `J`. `None` unless the line is exactly one
/// `integrity` target in mode `D` or `J`.
pub fn journaled_table(table: &str) -> Option<String> {
    let lines: Vec<&str> = table.lines().filter(|l| !l.trim().is_empty()).collect();
    let [line] = lines.as_slice() else {
        return None;
    };
    // <start> <len> integrity <dev> <offset> <tag_size> <mode> <#args> …
    let mut f: Vec<&str> = line.split_ascii_whitespace().collect();
    if f.len() < 8 || f[2] != "integrity" || !matches!(f[6], "D" | "J") {
        return None;
    }
    f[6] = "J";
    Some(f.join(" "))
}

/// The host side of the wipe, a trait so the decisions are unit-tested.
pub trait InitHost: Sync {
    /// The LUKS UUID of the mapping `name` (from its dm UUID).
    fn mapping_uuid(&self, name: &str) -> Result<String, String>;
    /// Zero the mapping `name` with `workers` writers; `progress(0..=100)`.
    fn wipe(
        &self,
        name: &str,
        workers: usize,
        progress: &(dyn Fn(u8) + Sync),
    ) -> Result<(), String>;
    fn load_record(&self) -> Result<Record, &'static str>;
    fn write_record(&self, record: &Record) -> Result<(), String>;
    /// Switch `<name>_dif` to its journal.
    fn enable_journal(&self, name: &str) -> Result<(), String>;
    /// Rename the stack `from` (+ `from_dif`) to `to` (+ `to_dif`).
    fn rename(&self, from: &str, to: &str) -> Result<(), String>;
    fn close(&self, name: &str) -> bool;
    fn write_state(&self, lines: &[StateLine]) -> Result<(), String>;
}

fn set(lines: &Mutex<Vec<StateLine>>, host: &dyn InitHost, slot: &str, state: &str, reason: &str) {
    let mut l = lines
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if let Some(line) = l.iter_mut().find(|x| x.slot == slot) {
        if line.state == state && line.reason == reason {
            return;
        }
        line.state = state.into();
        line.reason = reason.into();
    }
    if let Err(e) = host.write_state(&l) {
        eprintln!("hippius-guest-release: dedicated-init: state file: {e}");
    }
}

/// Is `slot` one this wipe may take? The state says `initializing`, the
/// record `formatting <U> integrity`, and the `-init` mapping is `<U>`.
fn check_slot<H: InitHost>(
    host: &H,
    record: &Record,
    lines: &[StateLine],
    slot: &str,
) -> Result<(), &'static str> {
    if !lines
        .iter()
        .any(|l| l.slot == slot && l.state == "initializing")
    {
        return Err("init-mismatch");
    }
    let Some(e) = record.get(slot) else {
        return Err("init-mismatch");
    };
    if e.state != RecordState::Formatting || !e.integrity {
        return Err("init-mismatch");
    }
    match host.mapping_uuid(&init_mapper_name(slot)) {
        Ok(u) if u == e.uuid => Ok(()),
        _ => Err("init-mismatch"),
    }
}

/// `formatting` → `ready` for `slot`, on the record as it is NOW on disk
/// (another slot may have been promoted meanwhile).
fn promote<H: InitHost>(host: &H, record_lock: &Mutex<()>, slot: &str) -> Result<(), String> {
    let _guard = record_lock
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let mut record = host.load_record().map_err(str::to_string)?;
    let Some(e) = record.get_mut(slot) else {
        return Err("slot gone from the record".into());
    };
    if e.state != RecordState::Formatting || !e.integrity {
        return Err("record changed under the wipe".into());
    }
    e.state = RecordState::Ready;
    host.write_record(&record)
}

/// The whole decision flow over the listed `slots` and the opener's state
/// `lines`. Returns the final lines (also written as they change).
pub fn process<H: InitHost>(host: &H, slots: &[String], lines: Vec<StateLine>) -> Vec<StateLine> {
    let lines = Mutex::new(lines);
    let record = match host.load_record() {
        Ok(r) => r,
        Err(reason) => {
            eprintln!("hippius-guest-release: dedicated-init: {reason} — no slot is initialised");
            for s in slots {
                host.close(&init_mapper_name(s));
                set(&lines, host, s, "mismatch", reason);
            }
            return lines
                .into_inner()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
        }
    };
    let snapshot = lines
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone();
    let mut go = Vec::new();
    for s in slots {
        match check_slot(host, &record, &snapshot, s) {
            Ok(()) => go.push(s.clone()),
            Err(reason) => {
                eprintln!(
                    "hippius-guest-release: dedicated-init {s}: {reason} — closed, not wiped"
                );
                host.close(&init_mapper_name(s));
                set(&lines, host, s, "mismatch", reason);
            }
        }
    }
    // One writers budget for every slot together (the SEV bounce-buffer
    // bound of `wipe::WORKERS` × `wipe::BLOCK`), each slot on its own disk.
    let workers = (wipe::WORKERS / go.len().max(1)).max(1);
    let record_lock = Mutex::new(());
    std::thread::scope(|scope| {
        for slot in &go {
            let (lines, record_lock) = (&lines, &record_lock);
            scope.spawn(move || {
                let init = init_mapper_name(slot);
                eprintln!("hippius-guest-release: dedicated-init {slot}: wipe start ({workers} writers)");
                let progress = |p: u8| set(lines, host, slot, "initializing", &format!("init-{p}"));
                if let Err(e) = host.wipe(&init, workers, &progress) {
                    eprintln!("hippius-guest-release: dedicated-init {slot}: wipe FAILED: {e} — closed; the next boot starts again");
                    host.close(&init);
                    set(lines, host, slot, "mismatch", "wipe-failed");
                    return;
                }
                if let Err(e) = promote(host, record_lock, slot) {
                    eprintln!("hippius-guest-release: dedicated-init {slot}: record: {e} — closed; the next boot starts again");
                    host.close(&init);
                    set(lines, host, slot, "mismatch", "record-write-failed");
                    return;
                }
                // `ready` is durable: from here the slot is the tenant's.
                // Neither step below can lose data; each only degrades
                // this boot (the next one opens journaled, by its name).
                let mut reason = "-";
                if let Err(e) = host.enable_journal(&init) {
                    eprintln!("hippius-guest-release: dedicated-init {slot}: WARN journal not enabled this boot: {e}");
                    reason = "no-journal-this-boot";
                }
                if let Err(e) = host.rename(&init, &mapper_name(slot)) {
                    eprintln!("hippius-guest-release: dedicated-init {slot}: WARN still named {init} this boot: {e}");
                    reason = "init-name";
                }
                eprintln!("hippius-guest-release: dedicated-init {slot}: attached ({reason})");
                set(lines, host, slot, "attached", reason);
            });
        }
    });
    lines
        .into_inner()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

// ── The real host ───────────────────────────────────────────────────

/// How the record is reached.
#[derive(Debug, Clone)]
pub enum Volume {
    /// Mount the OS volume's device at `at` (the unit's private mount
    /// namespace) for the run.
    Mount { device: PathBuf, at: PathBuf },
    /// An already-reachable volume root (the end-to-end test).
    Dir(PathBuf),
}

pub struct SysInitHost {
    pub state: PathBuf,
    pub mapper: PathBuf,
    pub sys_block: PathBuf,
    pub volume_root: PathBuf,
    pub cryptsetup: PathBuf,
    pub dmsetup: PathBuf,
    pub min_gib: u64,
}

fn run_quiet(cmd: &mut Command) -> Result<String, String> {
    let out = cmd
        .stdin(Stdio::null())
        .stderr(Stdio::piped())
        .output()
        .map_err(|e| format!("spawn: {}", e.kind()))?;
    if !out.status.success() {
        let err = String::from_utf8_lossy(&out.stderr);
        return Err(format!(
            "exit {:?}: {}",
            out.status.code(),
            err.lines().last().unwrap_or("")
        ));
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

impl SysInitHost {
    fn dm(&self, args: &[&str]) -> Result<String, String> {
        run_quiet(Command::new(&self.dmsetup).args(args))
            .map_err(|e| format!("dmsetup {}: {e}", args.first().unwrap_or(&"")))
    }
}

impl InitHost for SysInitHost {
    fn mapping_uuid(&self, name: &str) -> Result<String, String> {
        let k = kernel_name(&self.sys_block, &self.mapper.join(name))
            .ok_or_else(|| format!("{name}: not a block device"))?;
        let u = std::fs::read_to_string(self.sys_block.join(&k).join("dm/uuid"))
            .map_err(|e| format!("{k}/dm/uuid: {}", e.kind()))?;
        luks_uuid_of_dm_uuid(&u, name).ok_or_else(|| format!("{name}: not our LUKS2 mapping"))
    }

    fn wipe(
        &self,
        name: &str,
        workers: usize,
        progress: &(dyn Fn(u8) + Sync),
    ) -> Result<(), String> {
        let path = self.mapper.join(name);
        wipe::check_target(&path).map_err(|e| e.to_string())?;
        let (file, size) = wipe::open_device(&path).map_err(|e| e.to_string())?;
        let last = std::sync::atomic::AtomicU8::new(0);
        let cb = |done: u64, size: u64| {
            let p = u8::try_from(done.saturating_mul(100) / size.max(1)).unwrap_or(100);
            if last.fetch_max(p, std::sync::atomic::Ordering::Relaxed) < p {
                progress(p);
            }
        };
        wipe::wipe(&file, size, workers, wipe::BLOCK, &cb).map_err(|e| e.to_string())?;
        file.sync_data().map_err(|e| format!("sync: {e}"))
    }

    fn load_record(&self) -> Result<Record, &'static str> {
        load_record(&self.volume_root, self.min_gib)
    }

    fn write_record(&self, record: &Record) -> Result<(), String> {
        write_atomic(
            &self.volume_root.join(RECORD_NAME),
            render_record(record).as_bytes(),
            0o600,
        )
    }

    fn enable_journal(&self, name: &str) -> Result<(), String> {
        let dif = format!("{name}_dif");
        let table = self.dm(&["table", &dif])?;
        let new = journaled_table(&table).ok_or("not a dm-integrity table in mode D/J")?;
        if new.trim() == table.trim() {
            return Ok(());
        }
        // Top first (flushes dm-crypt), then the integrity layer; load the
        // journaled table and resume both. On any failure the previous
        // table stays (or is restored) and both are resumed: never leave
        // the stack suspended.
        self.dm(&["suspend", name])?;
        let result = self
            .dm(&["suspend", &dif])
            .and_then(|_| self.dm(&["load", &dif, "--table", &new]))
            .and_then(|_| self.dm(&["resume", &dif]));
        if result.is_err() {
            let _ = self.dm(&["clear", &dif]);
            let _ = self.dm(&["resume", &dif]);
        }
        let resumed = self.dm(&["resume", name]);
        result?;
        resumed?;
        let now = self.dm(&["table", &dif])?;
        (journaled_table(&now).as_deref() == Some(now.trim()))
            .then_some(())
            .ok_or_else(|| "the reload did not take".to_string())
    }

    fn rename(&self, from: &str, to: &str) -> Result<(), String> {
        // `cryptsetup close <to>` finds the integrity layer as `<to>_dif`:
        // rename it first, then the crypt mapping; undo on failure.
        let (from_dif, to_dif) = (format!("{from}_dif"), format!("{to}_dif"));
        self.dm(&["rename", &from_dif, &to_dif])?;
        if let Err(e) = self.dm(&["rename", from, to]) {
            let _ = self.dm(&["rename", &to_dif, &from_dif]);
            return Err(e);
        }
        Ok(())
    }

    fn close(&self, name: &str) -> bool {
        let _ = run_quiet(Command::new(&self.cryptsetup).args(["close", name]));
        !self.mapper.join(name).exists()
    }

    fn write_state(&self, lines: &[StateLine]) -> Result<(), String> {
        write_atomic(&self.state, render_state(lines).as_bytes(), 0o644)
    }
}

/// The slots in the init list (one per line, each a dedicated slot).
pub fn parse_list(text: &str) -> Result<Vec<String>, String> {
    let mut out: Vec<String> = Vec::new();
    for l in text.lines() {
        let ok = l.starts_with('x') && hippius_types::disk_stats::is_valid_slot(l);
        if !ok || out.iter().any(|s| s == l) {
            return Err(format!("init list: bad line `{l}`"));
        }
        out.push(l.to_string());
    }
    Ok(out)
}

pub struct Config {
    pub list: PathBuf,
    pub state: PathBuf,
    pub volume: Volume,
    pub min_gib: u64,
}

/// The whole mode. `Ok` also when there is nothing to do.
pub fn run(cfg: &Config) -> Result<(), String> {
    let list = match std::fs::read_to_string(&cfg.list) {
        Ok(t) => parse_list(&t)?,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            eprintln!("hippius-guest-release: dedicated-init: no init list — nothing to do");
            return Ok(());
        }
        Err(e) => return Err(format!("init list: {}", e.kind())),
    };
    if list.is_empty() {
        return Ok(());
    }
    let lines = parse_state(
        &std::fs::read_to_string(&cfg.state).map_err(|e| format!("state file: {}", e.kind()))?,
    );
    let (root, mounted) = match &cfg.volume {
        Volume::Dir(d) => (d.clone(), None),
        Volume::Mount { device, at } => {
            std::fs::create_dir_all(at).map_err(|e| format!("mount point: {}", e.kind()))?;
            run_quiet(
                Command::new("mount")
                    .args(["-t", "ext4", "-o", "nosuid,nodev,noexec"])
                    .arg(device)
                    .arg(at),
            )
            .map_err(|e| format!("mount of the OS volume: {e}"))?;
            (at.clone(), Some(at.clone()))
        }
    };
    let host = SysInitHost {
        state: cfg.state.clone(),
        mapper: PathBuf::from("/dev/mapper"),
        sys_block: PathBuf::from("/sys/class/block"),
        volume_root: root,
        cryptsetup: PathBuf::from("cryptsetup"),
        dmsetup: PathBuf::from("dmsetup"),
        min_gib: cfg.min_gib,
    };
    let out = process(&host, &list, lines);
    if let Some(at) = mounted {
        if let Err(e) = run_quiet(Command::new("umount").arg(&at)) {
            eprintln!("hippius-guest-release: dedicated-init: WARN umount: {e}");
        }
    }
    let summary: BTreeMap<&str, usize> = out.iter().fold(BTreeMap::new(), |mut m, l| {
        *m.entry(l.state.as_str()).or_default() += 1;
        m
    });
    eprintln!("hippius-guest-release: dedicated-init: done {summary:?}");
    Ok(())
}

#[cfg(test)]
#[path = "dedicated_init_tests.rs"]
mod tests;
