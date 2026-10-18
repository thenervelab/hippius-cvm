//! Kernel block-layer and filesystem advisories from the journal (§18.3),
//! the `--mode kernel` run (every 5 min).
//!
//! `journalctl -o json` past the saved cursor, the kernel's own messages
//! only, read up to the runner's stdout cap (the tool is stopped there,
//! the rest read next run); each `MESSAGE` goes through a strict
//! allowlist ([`classify`]): `kernel_io_error`, `kernel_timeout_reset`,
//! `kernel_medium_error`, `fs_error`, `fs_remounted_ro`. A line matching
//! none is neither counted nor kept.
//!
//! **Which entries.** The very first run (no state at all) reads the
//! current boot's last [`FIRST_RUN_LINES`] (`-k -n`). Every later run
//! reads `_TRANSPORT=kernel --after-cursor=<saved>`: `-k` would restrict
//! to the current boot and lose the tail of a boot that crashed. A
//! `journalctl` failure keeps the cursor; after [`MAX_CURSOR_FAILURES`] in
//! a row (a cursor journald no longer knows), the run resumes from the
//! last entry's time (`--since=@<ts>`), never from `-n`.
//!
//! **Redaction.** No message text is ever kept. A matched line yields its
//! code, one device token and a sample REBUILT from a fixed template
//! (`"I/O error, dev sdb, sector 1234 op READ"`). The device token is kept
//! only when it is a kernel name ([`is_kernel_name`]); a device-mapper
//! name becomes its `dm-N` through sysfs, an `ataN` port or an `nvmeN`
//! controller its block device; anything else is `<redacted>` and the
//! line, with no device to attach to, is counted as unresolved and
//! dropped. Paths, process names, inode numbers, VM ids: never read.
//!
//! **Hand-off to the storage section.** Per `(device, code)` the kernel
//! run keeps the occurrences in a retention window, the first and last
//! time seen and the latest sample, in `<out>/.kernel-state.json` — the
//! SAME file as the cursor, written atomically under the collector's run
//! lock, so the cursor and the counts move together (an entry is counted
//! once). Every `full` / `counters` run folds the entries seen within
//! [`KERNEL_EVENT_RETENTION`] into the storage advisories (subjects mapped
//! like the SMART ones) and leaves the file alone: nothing is cleared on
//! a write that vali may never receive (a poster in back-off, two runs
//! within its gap, an invalid section). vali upserts an advisory per
//! `(subject, code)`, so the repeated folds are idempotent; an entry not
//! seen again for 24 h expires, its advisory is absent from the next
//! report, and vali resolves it. `count` is the occurrences since
//! `first_seen`, within the window; an expired entry seen again starts
//! over.

use std::collections::BTreeMap;
use std::path::Path;
use std::time::Duration;

use hippius_host_inventory::{is_kernel_name, AdvisoryCode, Severity, MAX_SAMPLE_LEN};
use serde::{Deserialize, Serialize};

use super::{clean_text, dir_names, read_trimmed, CommandError, CommandRunner, HostPaths};

/// `<out>/<KERNEL_STATE_NAME>.json`.
pub const KERNEL_STATE_NAME: &str = ".kernel-state";
/// The state file is never read past this.
const MAX_STATE_BYTES: u64 = 256 * 1024;
/// At most this many `(device, code)` entries; past it the least recently
/// seen is evicted.
pub const MAX_PENDING: usize = 128;
/// An entry not seen again for this long expires (its advisory resolves).
pub const KERNEL_EVENT_RETENTION: i64 = 24 * 3600;
/// Entries read on the very first run: the most recent ones.
pub const FIRST_RUN_LINES: &str = "1000";
/// `journalctl` failures in a row before the cursor is given up for the
/// last entry's time.
pub const MAX_CURSOR_FAILURES: u32 = 3;
/// How long one `journalctl` may take.
pub const JOURNAL_TIMEOUT: Duration = Duration::from_secs(30);
/// The kernel run's own deadline from process start (its unit runs every
/// 5 min).
pub const KERNEL_RUN_DEADLINE: Duration = Duration::from_secs(60);
/// How long the kernel run waits for the collector's run lock (a `full`
/// or `counters` run in progress) before it skips (exit 0).
pub const KERNEL_LOCK_WAIT: Duration = Duration::from_secs(15);
/// A journal cursor is at most this long.
const MAX_CURSOR_LEN: usize = 512;

/// The codes of this module, in their state-file spelling.
const CODES: [(AdvisoryCode, &str); 5] = [
    (AdvisoryCode::KernelIoError, "kernel_io_error"),
    (AdvisoryCode::KernelTimeoutReset, "kernel_timeout_reset"),
    (AdvisoryCode::KernelMediumError, "kernel_medium_error"),
    (AdvisoryCode::FsError, "fs_error"),
    (AdvisoryCode::FsRemountedRo, "fs_remounted_ro"),
];

fn code_name(code: AdvisoryCode) -> Option<&'static str> {
    CODES.iter().find(|(c, _)| *c == code).map(|(_, n)| *n)
}

/// One code seen on one device within the retention window.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KernelEvent {
    /// A kernel name ([`is_kernel_name`]).
    pub device: String,
    pub code: AdvisoryCode,
    /// Occurrences since `first_seen_unix`.
    pub count: u64,
    pub first_seen_unix: i64,
    pub last_seen_unix: i64,
    /// Rebuilt from a template; printable ASCII ≤ 120.
    pub sample: String,
}

/// `<out>/.kernel-state.json`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KernelState {
    /// The journal cursor of the last entry processed.
    #[serde(default)]
    pub cursor: Option<String>,
    /// That entry's `__REALTIME_TIMESTAMP` (µs): where a run resumes when
    /// the cursor is unusable.
    #[serde(default)]
    pub last_realtime_us: Option<i64>,
    /// `journalctl` failures in a row with the cursor.
    #[serde(default)]
    pub cursor_failures: u32,
    /// Entries by `<code>/<device>`.
    #[serde(default)]
    pub pending: BTreeMap<String, KernelEvent>,
}

impl KernelState {
    /// The state in `dir`; missing or unreadable starts over. Every entry
    /// is re-checked (code, device, sample, times): the file is the
    /// collector's own, but a hand-edited one is not trusted.
    pub fn load(dir: &Path) -> Self {
        use std::io::Read;
        let Ok(file) = std::fs::File::open(dir.join(format!("{KERNEL_STATE_NAME}.json"))) else {
            return Self::default();
        };
        let mut bytes = Vec::new();
        if file
            .take(MAX_STATE_BYTES + 1)
            .read_to_end(&mut bytes)
            .is_err()
            || bytes.len() as u64 > MAX_STATE_BYTES
        {
            return Self::default();
        }
        let mut state: Self = serde_json::from_slice(&bytes).unwrap_or_default();
        if state.cursor.as_deref().is_some_and(|c| !valid_cursor(c)) {
            state.cursor = None;
        }
        state.pending.retain(|key, e| {
            code_name(e.code).is_some_and(|n| *key == format!("{n}/{}", e.device))
                && is_kernel_name(&e.device)
                && e.last_seen_unix >= e.first_seen_unix
                && clean_text(e.sample.as_bytes(), MAX_SAMPLE_LEN).as_deref()
                    == Some(e.sample.as_str())
        });
        while state.pending.len() > MAX_PENDING {
            state.evict_oldest();
        }
        state
    }

    /// Write it to `dir` atomically.
    pub fn save(&self, dir: &Path) -> std::io::Result<()> {
        let bytes = serde_json::to_vec(self).map_err(std::io::Error::other)?;
        super::save_json(dir, KERNEL_STATE_NAME, &bytes)
    }

    /// The entries seen within the retention window of `now`, in key
    /// order: what a storage run folds.
    pub fn live_events(&self, now: i64) -> Vec<KernelEvent> {
        self.pending
            .values()
            .filter(|e| now.saturating_sub(e.last_seen_unix) <= KERNEL_EVENT_RETENTION)
            .cloned()
            .collect()
    }

    /// Drop the entries past the retention window.
    pub fn expire(&mut self, now: i64) {
        self.pending
            .retain(|_, e| now.saturating_sub(e.last_seen_unix) <= KERNEL_EVENT_RETENTION);
    }

    fn evict_oldest(&mut self) -> bool {
        let oldest = self
            .pending
            .iter()
            .min_by_key(|(_, e)| e.last_seen_unix)
            .map(|(k, _)| k.clone());
        match oldest {
            Some(k) => {
                self.pending.remove(&k);
                true
            }
            None => false,
        }
    }

    /// Count one matched entry. `true` when an older entry was evicted
    /// for it.
    fn record(&mut self, device: &str, code: AdvisoryCode, at: i64, sample: String) -> bool {
        let Some(name) = code_name(code) else {
            return false;
        };
        let key = format!("{name}/{device}");
        if let Some(e) = self.pending.get_mut(&key) {
            if at.saturating_sub(e.last_seen_unix) > KERNEL_EVENT_RETENTION {
                // Expired, seen again: a new episode.
                e.count = 1;
                e.first_seen_unix = at;
                e.last_seen_unix = at;
            } else {
                e.count = e.count.saturating_add(1);
                e.first_seen_unix = e.first_seen_unix.min(at);
                e.last_seen_unix = e.last_seen_unix.max(at);
            }
            e.sample = sample;
            return false;
        }
        let evicted = self.pending.len() >= MAX_PENDING && self.evict_oldest();
        self.pending.insert(
            key,
            KernelEvent {
                device: device.to_string(),
                code,
                count: 1,
                first_seen_unix: at,
                last_seen_unix: at,
                sample,
            },
        );
        evicted
    }
}

/// A journald cursor: printable, no blank, no shell-ish byte.
fn valid_cursor(c: &str) -> bool {
    !c.is_empty()
        && c.len() <= MAX_CURSOR_LEN
        && c.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'=' | b';' | b'-' | b'_'))
}

/// The severity of a kernel code.
pub fn severity(code: AdvisoryCode) -> Severity {
    match code {
        AdvisoryCode::KernelIoError | AdvisoryCode::KernelTimeoutReset => Severity::Warning,
        _ => Severity::Critical,
    }
}

/// How a device token found in a line maps to a kernel name (sysfs).
#[derive(Debug, Clone, Default)]
pub struct Resolver {
    /// dm name → `dm-N`.
    dm: BTreeMap<String, String>,
    /// `ataN` → the block device behind that port.
    ata: BTreeMap<String, String>,
    /// `nvmeN` → a block device of its namespaces.
    nvme: BTreeMap<String, String>,
}

/// `nvme<a>n<b>` / `nvme<a>c<c>n<b>` → `nvme<a>n<b>` (the block device of
/// a namespace, a multipath path's head).
fn namespace_block(name: &str) -> Option<String> {
    let rest = name.strip_prefix("nvme")?;
    let digits = |s: &str| !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit());
    let (sub, tail) = rest.split_once('n')?;
    let sub = sub.split('c').next().unwrap_or(sub);
    (digits(sub) && digits(tail)).then(|| format!("nvme{sub}n{tail}"))
}

impl Resolver {
    /// Read the maps from `/sys/block` and `/sys/class/nvme` (no device
    /// I/O).
    pub fn from_sysfs(paths: &HostPaths) -> Self {
        let block = paths.sys.join("block");
        let mut r = Self::default();
        for name in dir_names(&block) {
            if !is_kernel_name(&name) {
                continue;
            }
            let dir = block.join(&name);
            if name.starts_with("dm-") {
                if let Some(dm_name) = read_trimmed(&dir.join("dm/name")) {
                    r.dm.insert(dm_name, name.clone());
                }
            }
            if let Ok(real) = std::fs::canonicalize(&dir) {
                for c in real.components() {
                    let c = c.as_os_str().to_string_lossy();
                    if c.strip_prefix("ata")
                        .is_some_and(|n| !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()))
                    {
                        r.ata.entry(c.to_string()).or_insert_with(|| name.clone());
                    }
                }
            }
        }
        // A controller's namespaces (`nvme0n1`, or a multipath path
        // `nvme0c0n1` whose head is `nvme0n1`), as block devices.
        let class = paths.sys.join("class/nvme");
        for ctrl in dir_names(&class) {
            for entry in dir_names(&class.join(&ctrl)) {
                if let Some(ns) = namespace_block(&entry).filter(|n| block.join(n).exists()) {
                    r.nvme.entry(ctrl.clone()).or_insert(ns);
                }
            }
        }
        r
    }

    /// A device token as a kernel name, if it is one or maps to one.
    fn device(&self, token: &str) -> Option<String> {
        if is_kernel_name(token) {
            return Some(token.to_string());
        }
        self.dm.get(token).cloned()
    }
}

/// What one matched line is: its code, its device (resolved) and its
/// rebuilt sample.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Matched {
    pub code: AdvisoryCode,
    /// `None`: the device could not be resolved (the line is dropped).
    pub device: Option<String>,
    pub sample: String,
}

const REDACTED: &str = "<redacted>";

fn sample(text: &str) -> String {
    clean_text(text.as_bytes(), MAX_SAMPLE_LEN).unwrap_or_else(|| REDACTED.to_string())
}

/// The token after `marker` in `msg`, up to a space, comma, colon or
/// closing bracket.
fn token_after<'a>(msg: &'a str, marker: &str) -> Option<&'a str> {
    let rest = &msg[msg.find(marker)? + marker.len()..];
    let end = rest.find([',', ' ', ':', ')', ']']).unwrap_or(rest.len());
    let t = &rest[..end];
    (!t.is_empty()).then_some(t)
}

/// The decimal number after `marker`.
fn number_after(msg: &str, marker: &str) -> Option<u64> {
    let rest = &msg[msg.find(marker)? + marker.len()..];
    let digits: String = rest.chars().take_while(char::is_ascii_digit).collect();
    digits.parse().ok()
}

/// The `fs` word of a filesystem line, from a fixed vocabulary.
fn fs_word(msg: &str) -> Option<&'static str> {
    if msg.starts_with("EXT4-fs") {
        Some("EXT4-fs")
    } else if msg.starts_with("XFS") {
        Some("XFS")
    } else if msg.starts_with("BTRFS") {
        Some("BTRFS")
    } else {
        None
    }
}

/// The filesystem's device: `(device X)` or `FS (X)`.
fn fs_device(msg: &str) -> Option<&str> {
    token_after(msg, "(device ").or_else(|| token_after(msg, " ("))
}

/// The block layer's error kinds (`blk_errors[]`): `<kind> error, dev X`,
/// and the code each one is.
const BLK_ERRORS: [(&str, AdvisoryCode); 12] = [
    ("critical medium", AdvisoryCode::KernelMediumError),
    ("timeout", AdvisoryCode::KernelTimeoutReset),
    ("I/O", AdvisoryCode::KernelIoError),
    ("critical target", AdvisoryCode::KernelIoError),
    ("critical nexus", AdvisoryCode::KernelIoError),
    ("critical space allocation", AdvisoryCode::KernelIoError),
    ("recoverable transport", AdvisoryCode::KernelIoError),
    ("critical protection", AdvisoryCode::KernelIoError),
    ("protection", AdvisoryCode::KernelIoError),
    ("kernel resource", AdvisoryCode::KernelIoError),
    ("device resource", AdvisoryCode::KernelIoError),
    ("operation not supported", AdvisoryCode::KernelIoError),
];

/// `[blk_update_request: | <prefix>: ]<kind> error, dev X, sector N op
/// 0x0:(READ)`: the block layer's error line (`blk_print_req_error`),
/// with `kind` from [`BLK_ERRORS`].
fn block_error(msg: &str, resolver: &Resolver) -> Option<Matched> {
    let at = msg.find(" error, dev ")?;
    let head = &msg[..at];
    // The kind is what follows the last `: ` (a prefix such as
    // `blk_update_request: `), or the whole head.
    let kind = head.rsplit_once(": ").map_or(head, |(_, k)| k);
    let (kind, code) = BLK_ERRORS
        .iter()
        .find(|(k, _)| kind.eq_ignore_ascii_case(k))
        .map(|(k, c)| (*k, *c))?;
    let device = token_after(msg, ", dev ").and_then(|t| resolver.device(t));
    let op = if msg.contains("(READ)") {
        "READ"
    } else if msg.contains("(WRITE)") {
        "WRITE"
    } else {
        "OTHER"
    };
    let sector = number_after(msg, "sector ")
        .map(|s| format!(", sector {s}"))
        .unwrap_or_default();
    let shown = device.clone().unwrap_or_else(|| REDACTED.to_string());
    Some(Matched {
        code,
        sample: sample(&format!("{kind} error, dev {shown}{sector} op {op}")),
        device,
    })
}

/// The allowlist (§18.3). Only typed fields come out; the message itself
/// is never kept.
pub fn classify(msg: &str, resolver: &Resolver) -> Option<Matched> {
    let dev = |token: Option<&str>| token.and_then(|t| resolver.device(t));
    let show = |d: &Option<String>| d.clone().unwrap_or_else(|| REDACTED.to_string());

    // fs_remounted_ro: `<FS> (X): Remounting filesystem read-only`.
    if msg.contains("Remounting filesystem read-only") {
        let device = dev(fs_device(msg));
        let fs = fs_word(msg).unwrap_or("filesystem");
        return Some(Matched {
            code: AdvisoryCode::FsRemountedRo,
            sample: sample(&format!(
                "{fs} ({}): Remounting filesystem read-only",
                show(&device)
            )),
            device,
        });
    }
    // fs_error: `EXT4-fs error`, `XFS…(corruption|metadata I/O error)`,
    // and only BTRFS's error levels (`BTRFS error` / `BTRFS critical` /
    // `BTRFS: error`): `BTRFS info … errs:` and `read error corrected`
    // are not errors.
    let fs_err = if msg.starts_with("EXT4-fs error") {
        Some("EXT4-fs error")
    } else if msg.starts_with("XFS") && msg.contains("metadata I/O error") {
        Some("XFS metadata I/O error")
    } else if msg.starts_with("XFS") && msg.contains("orruption") {
        Some("XFS corruption")
    } else if msg.starts_with("BTRFS error")
        || msg.starts_with("BTRFS critical")
        || msg.starts_with("BTRFS: error")
    {
        Some("BTRFS error")
    } else {
        None
    };
    if let Some(what) = fs_err {
        let device = dev(fs_device(msg));
        return Some(Matched {
            code: AdvisoryCode::FsError,
            sample: sample(&format!("{what} (device {}): {REDACTED}", show(&device))),
            device,
        });
    }
    // kernel_medium_error: `[sdX] … Medium Error` / `Unrecovered read error`.
    for what in ["Medium Error", "Unrecovered read error"] {
        if msg.contains(what) {
            let device = dev(token_after(msg, "["));
            return Some(Matched {
                code: AdvisoryCode::KernelMediumError,
                sample: sample(&format!("{}: {what}", show(&device))),
                device,
            });
        }
    }
    // The block layer's `<kind> error, dev X`.
    if let Some(m) = block_error(msg, resolver) {
        return Some(m);
    }
    // kernel_timeout_reset: `ataN…(timeout|hard resetting|link reset)`.
    let first = msg.split([':', ' ']).next().unwrap_or("");
    let port = first.split('.').next().unwrap_or("");
    if port
        .strip_prefix("ata")
        .is_some_and(|n| !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()))
    {
        for (needle, what) in [
            ("hard resetting", "hard resetting link"),
            ("link reset", "link reset"),
            ("timeout", "command timeout"),
        ] {
            if msg.contains(needle) {
                let device = resolver.ata.get(port).cloned();
                return Some(Matched {
                    code: AdvisoryCode::KernelTimeoutReset,
                    sample: sample(&format!("{}: {what}", show(&device))),
                    device,
                });
            }
        }
    }
    // `nvme nvmeN: …`: a command timeout (`… QID n timeout, aborting`) or a
    // controller reset — never the `Shutdown timeout set to` notice.
    if let Some(ctrl) = msg
        .strip_prefix("nvme ")
        .and_then(|r| r.split(':').next())
        .filter(|c| c.starts_with("nvme"))
    {
        let what = if msg.contains("resetting controller") {
            Some("resetting controller")
        } else if msg.contains("timeout,") || (msg.contains("QID") && msg.contains("timeout")) {
            Some("command timeout")
        } else {
            None
        };
        if let Some(what) = what {
            let device = resolver.nvme.get(ctrl).cloned();
            return Some(Matched {
                code: AdvisoryCode::KernelTimeoutReset,
                sample: sample(&format!("{}: {what}", show(&device))),
                device,
            });
        }
    }
    None
}

/// One journal entry: its message, time (µs) and cursor (`-o json`):
/// `MESSAGE` as a string or a byte array.
fn entry(line: &str) -> Option<(String, Option<i64>, Option<String>)> {
    let v: serde_json::Value = serde_json::from_str(line).ok()?;
    let msg = match v.get("MESSAGE")? {
        serde_json::Value::String(s) => s.clone(),
        serde_json::Value::Array(a) => {
            let bytes: Vec<u8> = a
                .iter()
                .filter_map(|b| b.as_u64().and_then(|b| u8::try_from(b).ok()))
                .collect();
            String::from_utf8_lossy(&bytes).into_owned()
        }
        _ => return None,
    };
    let at_us = v
        .get("__REALTIME_TIMESTAMP")
        .and_then(|t| t.as_str())
        .and_then(|t| t.parse::<i64>().ok());
    let cursor = v
        .get("__CURSOR")
        .and_then(|c| c.as_str())
        .filter(|c| valid_cursor(c))
        .map(str::to_string);
    Some((msg, at_us, cursor))
}

/// What one run read.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct JournalStats {
    pub entries: u64,
    pub matched: u64,
    /// Matched, but no device to attach to (dropped).
    pub unresolved: u64,
    /// Older entries evicted to make room.
    pub overflow: u64,
}

/// Fold journal output into `state`: count every matched entry, advance
/// the cursor (and its time) to the last complete entry (a line cut by
/// the output cap is left for the next run). A SCSI medium error prints
/// two lines (`Sense Key : Medium Error`, `Add. Sense: Unrecovered read
/// error`): the second on the same device within the same second is the
/// same event. `now` dates an entry without a timestamp.
pub fn ingest(
    output: &str,
    state: &mut KernelState,
    resolver: &Resolver,
    now: i64,
) -> JournalStats {
    let mut stats = JournalStats::default();
    let mut last_medium: Option<(String, i64)> = None;
    for line in output.lines() {
        let Some((msg, at_us, cursor)) = entry(line) else {
            continue;
        };
        stats.entries += 1;
        let at = at_us.map_or(now, |us| us.div_euclid(1_000_000));
        if let Some(m) = classify(&msg, resolver) {
            stats.matched += 1;
            match m.device {
                Some(d) => {
                    let medium = m.code == AdvisoryCode::KernelMediumError;
                    let same = medium
                        && last_medium
                            .as_ref()
                            .is_some_and(|(ld, la)| *ld == d && *la == at);
                    if same {
                        if let Some(e) = state.pending.get_mut(&format!("kernel_medium_error/{d}"))
                        {
                            e.sample = m.sample;
                        }
                    } else if state.record(&d, m.code, at, m.sample) {
                        stats.overflow += 1;
                    }
                    if medium {
                        last_medium = Some((d, at));
                    }
                }
                None => stats.unresolved += 1,
            }
        }
        if let Some(c) = cursor {
            state.cursor = Some(c);
            state.last_realtime_us = at_us.or(state.last_realtime_us);
        }
    }
    stats
}

/// The `journalctl` arguments for `state`: the kernel transport past the
/// cursor; past the last entry's time once the cursor failed
/// [`MAX_CURSOR_FAILURES`] times; the current boot's recent entries only
/// on the very first run.
pub fn journal_args(state: &KernelState) -> Vec<String> {
    let mut args: Vec<String> = [
        "-o",
        "json",
        "--no-pager",
        "--output-fields=MESSAGE,__REALTIME_TIMESTAMP",
    ]
    .iter()
    .map(|s| (*s).to_string())
    .collect();
    match (&state.cursor, state.last_realtime_us) {
        (Some(c), _) if state.cursor_failures < MAX_CURSOR_FAILURES => {
            args.push("_TRANSPORT=kernel".into());
            args.push(format!("--after-cursor={c}"));
        }
        (_, Some(us)) => {
            // Just past the last entry read (journalctl takes `@<s>.<µs>`).
            let next = us.saturating_add(1);
            args.push("_TRANSPORT=kernel".into());
            args.push(format!(
                "--since=@{}.{:06}",
                next.div_euclid(1_000_000),
                next.rem_euclid(1_000_000)
            ));
        }
        _ => {
            args.insert(0, "-k".into());
            args.push("-n".into());
            args.push(FIRST_RUN_LINES.into());
        }
    }
    args
}

/// Read the journal past `state` within `timeout` and fold it in: up to
/// the runner's stdout cap, where the tool is stopped and what was read
/// is taken (`run_capped`). A failure keeps the cursor (and counts it).
pub fn read_journal(
    paths: &HostPaths,
    runner: &dyn CommandRunner,
    state: &mut KernelState,
    timeout: Duration,
    now: i64,
) -> Result<JournalStats, CommandError> {
    let args = journal_args(state);
    let argv: Vec<&str> = args.iter().map(String::as_str).collect();
    let by_time = args.iter().any(|a| a.starts_with("--since="));
    match runner.run_capped("journalctl", &argv, timeout) {
        Ok(out) => {
            state.cursor_failures = 0;
            if by_time {
                // The given-up cursor never comes back: the next run goes
                // on from this one's last entry (its cursor, else its time).
                state.cursor = None;
            }
            let stats = ingest(&out, state, &Resolver::from_sysfs(paths), now);
            state.expire(now);
            Ok(stats)
        }
        Err(CommandError::Failed) => {
            state.cursor_failures = state.cursor_failures.saturating_add(1);
            Err(CommandError::Failed)
        }
        Err(e) => Err(e),
    }
}

#[cfg(test)]
pub(crate) mod tests;
