//! The privileged half of dedicated disks: the exclusive hold while a VM
//! has a disk, and the release wipe after §24
//! (docs/design/disk-tier-verification.md §4.2, §6.1).
//!
//! The agent runs with `PrivateDevices=yes` and never sees a block device,
//! so both run in systemd template units OUTSIDE its sandbox, started by
//! the agent ([`super::assignment::SystemdHelper`]):
//!
//! - `hippius-miner-dedicated-hold@<id>.service` (`dedicated-hold`): opens
//!   the disk `O_RDONLY|O_EXCL` and keeps it open until stopped. QEMU's own
//!   (non-exclusive) open is unaffected; every other exclusive claim fails
//!   — a mount, md/dm/LVM assembly, a partition-table re-read — so the
//!   host can neither use the disk nor react to what the guest writes on
//!   it. It also installs a udev rule (persistent, so it applies from the
//!   next boot on, before any hold) that hides the disk and its partitions
//!   from udisks and systemd and clears the filesystem type ahead of the
//!   md/LVM auto-assembly rules.
//! - `hippius-miner-dedicated-release@<id>.service` (`dedicated-release`):
//!   zeroes the first and last 16 MiB of the disk and verifies with
//!   `blkid -p` that no signature (a `crypto_LUKS` header first of all)
//!   is left.
//!
//! Neither trusts the agent: each re-reads the agent's records itself and
//! acts only on a disk they allow. Hold: a VM record names the disk, with
//! the identity the device answers with now. Release: a release record
//! names the disk, NO VM record does, the device answers with the
//! recorded identity, NO process has it open (QEMU of a still-running
//! domain), and the exclusive open succeeds (nothing mounted or claimed).
//! Each writes its verdict to `<RESULT_DIR>/<id>.<hold|release>.json`
//! (`{"code": ""}` on success) for the agent.

use std::io::{Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use hippius_types::storage_report::is_valid_dedicated_disk_id;
use serde::{Deserialize, Serialize};

use super::assignment::{self, Owner};
use super::dedicated::{IdentityMap, SignatureProbe, SysPaths};

/// Where the helper writes its verdicts (the units' `RuntimeDirectory`).
pub const RESULT_DIR: &str = "/run/hippius-miner/dedicated";
/// Where the hold puts its udev rule.
pub const UDEV_RULES_DIR: &str = "/etc/udev/rules.d";
/// Bytes zeroed at each end of a released disk: every LUKS2 header and
/// keyslot area (16 MiB by default), GPT, md, LVM and ZFS labels.
pub const WIPE_BYTES: u64 = 16 * 1024 * 1024;
/// The hold unit's `TimeoutStartSec` / `TimeoutStopSec` (the play renders
/// them from here; the agent waits this long plus a margin).
pub const HOLD_UNIT_TIMEOUT_SECS: u64 = 60;
/// The release unit's `TimeoutStartSec`.
pub const RELEASE_UNIT_TIMEOUT_SECS: u64 = 300;
/// The hold's exit status when it refuses (not assigned, another device,
/// busy): the unit's `RestartPreventExitStatus`, so a refusal is not
/// retried every `RestartSec` — only a hold that died is.
pub const HOLD_REFUSED_EXIT: i32 = 3;

/// Every code the helper writes ([`read_result`] maps anything else to
/// `helper-failed`).
pub const CODES: [&str; 19] = [
    "helper-failed",
    "helper-bad-disk-id",
    "helper-records-unreadable",
    "helper-not-found",
    "helper-not-whole-disk",
    "helper-not-block-device",
    "helper-sysfs-mismatch",
    "helper-no-identity",
    "hold-not-assigned",
    "hold-identity-mismatch",
    "hold-busy",
    "release-not-pending",
    "release-assigned",
    "release-identity-mismatch",
    "release-device-open",
    "release-device-busy",
    "release-write-failed",
    "release-signature-remains",
    "release-verify-failed",
];

/// The helper's verdict file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HelperResult {
    pub code: String,
}

/// `<dir>/<disk_id>.<op>.json`.
pub fn result_path(dir: &Path, disk_id: &str, op: &str) -> PathBuf {
    dir.join(format!("{disk_id}.{op}.json"))
}

/// The verdict at `path` if it was written at or after `since`: `Some("")`
/// for success, `Some(code)` for a known refusal, `Some("helper-failed")`
/// for an unknown one; `None` when no fresh verdict exists.
pub fn read_result(path: &Path, since: std::time::SystemTime) -> Option<&'static str> {
    let meta = std::fs::metadata(path).ok()?;
    // mtime granularity: allow the second the call started in.
    let since = since.checked_sub(std::time::Duration::from_secs(1))?;
    if meta.modified().ok()? < since {
        return None;
    }
    let result: HelperResult = serde_json::from_slice(&std::fs::read(path).ok()?).ok()?;
    if result.code.is_empty() {
        return Some("");
    }
    Some(
        CODES
            .iter()
            .copied()
            .find(|c| *c == result.code)
            .unwrap_or("helper-failed"),
    )
}

/// Write the verdict (best effort: the unit's exit status still tells).
pub fn write_result(dir: &Path, disk_id: &str, op: &str, code: &str) {
    let _ = std::fs::create_dir_all(dir);
    let body = serde_json::to_vec(&HelperResult {
        code: code.to_string(),
    })
    .unwrap_or_default();
    let path = result_path(dir, disk_id, op);
    let tmp = dir.join(format!(".{disk_id}.{op}.tmp"));
    if std::fs::write(&tmp, body).is_ok() {
        let _ = std::fs::rename(&tmp, path);
    }
}

/// Where the helper reads the host. Real paths by default; fixtures in
/// tests.
#[derive(Debug, Clone)]
pub struct HelperEnv {
    pub paths: SysPaths,
    /// `/proc`: who has the device open.
    pub proc_dir: PathBuf,
    /// The agent's state root (its records and identity map).
    pub state_root: PathBuf,
    /// `None`: no udev rule (tests).
    pub udev_rules_dir: Option<PathBuf>,
}

impl HelperEnv {
    pub fn system(state_root: PathBuf) -> Self {
        Self {
            paths: SysPaths::default(),
            proc_dir: PathBuf::from("/proc"),
            state_root,
            udev_rules_dir: Some(PathBuf::from(UDEV_RULES_DIR)),
        }
    }
}

/// The device behind a by-id name, as checked.
#[derive(Debug, Clone)]
pub struct Device {
    pub path: PathBuf,
    /// The kernel name (`sdb`).
    pub name: String,
    pub identity: String,
    /// `st_rdev` when the host check is on.
    pub rdev: Option<u64>,
}

fn read_trimmed(path: &Path) -> Option<String> {
    std::fs::read_to_string(path)
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

/// Resolve `disk_id` to a whole-disk block device and read its identity
/// the way the inventory does ([`super::dedicated`]).
pub fn resolve(env: &HelperEnv, disk_id: &str) -> Result<Device, &'static str> {
    if !is_valid_dedicated_disk_id(disk_id) {
        return Err("helper-bad-disk-id");
    }
    let path =
        std::fs::canonicalize(env.paths.by_id.join(disk_id)).map_err(|_| "helper-not-found")?;
    let name = path
        .file_name()
        .and_then(|n| n.to_str())
        .map(str::to_string)
        .ok_or("helper-not-found")?;
    let sys = env.paths.sys_block.join(&name);
    if !sys.is_dir() {
        return Err("helper-not-whole-disk");
    }
    let mut rdev = None;
    if env.paths.require_block_device {
        use std::os::unix::fs::{FileTypeExt, MetadataExt};
        let meta = std::fs::metadata(&path).map_err(|_| "helper-not-found")?;
        if !meta.file_type().is_block_device() {
            return Err("helper-not-block-device");
        }
        if read_trimmed(&sys.join("dev")).as_deref()
            != Some(super::dedicated::dev_string(meta.rdev()).as_str())
        {
            return Err("helper-sysfs-mismatch");
        }
        rdev = Some(meta.rdev());
    }
    let identity = read_trimmed(&sys.join("device/wwid"))
        .or_else(|| read_trimmed(&sys.join("wwid")))
        .or_else(|| read_trimmed(&sys.join("device/serial")))
        .ok_or("helper-no-identity")?;
    Ok(Device {
        path,
        name,
        identity,
        rdev,
    })
}

/// The identity the agent bound for `disk_id`, when its map says one.
fn bound_identity(env: &HelperEnv, disk_id: &str) -> Result<Option<String>, &'static str> {
    let map = IdentityMap::load(&env.state_root).ok_or("helper-records-unreadable")?;
    Ok(map.disks.get(disk_id).cloned())
}

fn o_excl() -> i32 {
    nix::fcntl::OFlag::O_EXCL.bits()
}

/// The hold's checks, then the exclusive open. The returned file is the
/// hold: keep it open. A VM record must name `disk_id` with the identity
/// the device answers with now (and the agent's identity map must agree).
pub fn hold(env: &HelperEnv, disk_id: &str) -> Result<std::fs::File, &'static str> {
    let device = resolve(env, disk_id)?;
    let owners = assignment::owners(&env.state_root).map_err(|_| "helper-records-unreadable")?;
    let Some(Owner::Vm { identity, .. }) = owners.get(disk_id) else {
        return Err("hold-not-assigned");
    };
    if *identity != device.identity
        || bound_identity(env, disk_id)?.is_some_and(|b| b != device.identity)
    {
        return Err("hold-identity-mismatch");
    }
    use std::os::unix::fs::OpenOptionsExt;
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(o_excl())
        .open(&device.path)
        .map_err(|_| "hold-busy")?;
    if !same_device(env, disk_id, &device, &file) {
        return Err("hold-identity-mismatch");
    }
    if let Some(dir) = &env.udev_rules_dir {
        install_udev_rule(dir, disk_id);
    }
    Ok(file)
}

/// The open `file` is `device`, and `disk_id` still resolves to it with the
/// same identity (read again while the fd pins the device).
fn same_device(env: &HelperEnv, disk_id: &str, device: &Device, file: &std::fs::File) -> bool {
    use std::os::unix::fs::MetadataExt;
    if let Some(rdev) = device.rdev {
        if !file.metadata().is_ok_and(|m| m.rdev() == rdev) {
            return false;
        }
    }
    resolve(env, disk_id)
        .is_ok_and(|again| again.path == device.path && again.identity == device.identity)
}

/// `61-…`: after `60-persistent-storage.rules` (the by-id links and the
/// blkid import exist), before `63-md-raid-arrays` / `69-lvm` (which key
/// on `ID_FS_TYPE`).
pub fn udev_rule_path(dir: &Path, disk_id: &str) -> PathBuf {
    dir.join(format!("61-hippius-dedicated-{disk_id}.rules"))
}

/// The rule's text. `disk_id` is `[A-Za-z0-9._:-]` only (no udev glob or
/// quote character).
pub fn udev_rule(disk_id: &str) -> String {
    let attrs = "ENV{UDISKS_IGNORE}=\"1\", ENV{SYSTEMD_READY}=\"0\", ENV{ID_FS_TYPE}=\"\", \
                 ENV{ID_FS_USAGE}=\"\"";
    format!(
        "# Hippius: dedicated disk {disk_id} is assigned to a tenant VM. Hidden from the host\n\
         # (udisks, systemd, md/LVM auto-assembly) until the miner releases it.\n\
         SUBSYSTEM==\"block\", SYMLINK==\"disk/by-id/{disk_id}\", {attrs}\n\
         SUBSYSTEM==\"block\", SYMLINK==\"disk/by-id/{disk_id}-part*\", {attrs}\n"
    )
}

fn udev_reload() {
    let _ = std::process::Command::new("udevadm")
        .args(["control", "--reload"])
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status();
}

fn install_udev_rule(dir: &Path, disk_id: &str) {
    let path = udev_rule_path(dir, disk_id);
    let tmp = dir.join(format!(".61-hippius-dedicated-{disk_id}.tmp"));
    if std::fs::write(&tmp, udev_rule(disk_id)).is_ok() && std::fs::rename(&tmp, &path).is_ok() {
        udev_reload();
    } else {
        eprintln!("hippius-miner-agent: dedicated-hold: udev rule for {disk_id} not written");
    }
}

/// The disk ids whose hold rule is installed in `dir`.
pub fn rule_ids(dir: &Path) -> Vec<String> {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut ids: Vec<String> = entries
        .flatten()
        .filter_map(|e| e.file_name().into_string().ok())
        .filter_map(|n| {
            n.strip_prefix("61-hippius-dedicated-")
                .and_then(|r| r.strip_suffix(".rules"))
                .map(str::to_string)
        })
        .filter(|id| is_valid_dedicated_disk_id(id))
        .collect();
    ids.sort();
    ids
}

/// Drop the udev rule of a disk no record named when the caller looked,
/// putting it back if a launch claimed the disk meanwhile (its hold may
/// have written the rule just before the removal).
pub fn drop_unowned_rule(env: &HelperEnv, disk_id: &str) {
    let Some(dir) = &env.udev_rules_dir else {
        return;
    };
    remove_udev_rule(dir, disk_id);
    if !assignment::owners(&env.state_root).is_ok_and(|o| !o.contains_key(disk_id)) {
        install_udev_rule(dir, disk_id);
    }
}

/// Drop the hold's udev rule (the disk is the host's again).
pub fn remove_udev_rule(dir: &Path, disk_id: &str) {
    match std::fs::remove_file(udev_rule_path(dir, disk_id)) {
        Ok(()) => udev_reload(),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(_) => eprintln!("hippius-miner-agent: dedicated: udev rule for {disk_id} not removed"),
    }
}

/// When a hold stops: a disk a VM record still names keeps its udev rule
/// (it must stay hidden across a reboot, before the next hold); one no VM
/// holds any more (a launch rolled back) is the host's again. A release
/// record keeps it too: the release removes it once the disk is wiped.
pub fn after_hold(env: &HelperEnv, disk_id: &str) {
    let Some(dir) = &env.udev_rules_dir else {
        return;
    };
    match assignment::owners(&env.state_root) {
        Ok(owners) if !owners.contains_key(disk_id) => remove_udev_rule(dir, disk_id),
        // Held, being released, or cannot tell: keep it.
        _ => {}
    }
}

/// Whether a process other than this one has `device` open: one of its
/// `/proc/<pid>/fd/*` resolves to the device path, or is a block device
/// with its `st_rdev`.
pub fn opened_by_another(proc_dir: &Path, device: &Device) -> bool {
    use std::os::unix::fs::{FileTypeExt, MetadataExt};
    let me = std::process::id().to_string();
    let Ok(pids) = std::fs::read_dir(proc_dir) else {
        // Cannot tell: treat as open (fail closed).
        return true;
    };
    for pid in pids.flatten() {
        let pid_name = pid.file_name();
        let Some(pid_name) = pid_name.to_str() else {
            continue;
        };
        if pid_name == me || !pid_name.bytes().all(|b| b.is_ascii_digit()) {
            continue;
        }
        // A process that exited meanwhile (or an fd it closed) is gone;
        // any other error (EACCES, EPERM: an LSM, a hidepid mount) means
        // this scan cannot tell, and it is the guard against wiping under a
        // live QEMU: treated as open.
        let gone = |e: &std::io::Error| e.kind() == std::io::ErrorKind::NotFound;
        let fds = match std::fs::read_dir(pid.path().join("fd")) {
            Ok(fds) => fds,
            Err(e) if gone(&e) => continue,
            Err(_) => return true,
        };
        for fd in fds {
            let fd = match fd {
                Ok(fd) => fd,
                Err(e) if gone(&e) => continue,
                Err(_) => return true,
            };
            match std::fs::read_link(fd.path()) {
                Ok(target) if target == device.path => return true,
                Ok(_) => {}
                Err(e) if gone(&e) => continue,
                Err(_) => return true,
            }
            if let Some(rdev) = device.rdev {
                match std::fs::metadata(fd.path()) {
                    Ok(meta) if meta.file_type().is_block_device() && meta.rdev() == rdev => {
                        return true
                    }
                    Ok(_) => {}
                    Err(e) if gone(&e) => {}
                    Err(_) => return true,
                }
            }
        }
    }
    false
}

/// The release wipe: checks, then zero [`WIPE_BYTES`] at each end of the
/// disk, sync, and verify with `probe` that no signature is left.
pub fn release(
    env: &HelperEnv,
    disk_id: &str,
    probe: &dyn SignatureProbe,
) -> Result<(), &'static str> {
    if !is_valid_dedicated_disk_id(disk_id) {
        return Err("helper-bad-disk-id");
    }
    let owners = assignment::owners(&env.state_root).map_err(|_| "helper-records-unreadable")?;
    let pending = match owners.get(disk_id) {
        Some(Owner::Releasing { identity }) => identity.clone(),
        Some(Owner::Vm { .. }) => return Err("release-assigned"),
        None => {
            // Nobody's: nothing to wipe, but a udev rule a dead hold left
            // behind goes (the agent's sweep asks for exactly this). A launch
            // that claimed the disk meanwhile gets its rule back: its hold
            // may have written it between our read and the removal.
            drop_unowned_rule(env, disk_id);
            return Err("release-not-pending");
        }
    };
    // `owners` lets a VM record win over a release record, and refuses
    // (unreadable) when any record does not parse: a disk any VM record
    // names is never wiped.
    let device = resolve(env, disk_id)?;
    if device.identity != pending || bound_identity(env, disk_id)?.is_some_and(|b| b != pending) {
        return Err("release-identity-mismatch");
    }
    if opened_by_another(&env.proc_dir, &device) {
        return Err("release-device-open");
    }
    use std::os::unix::fs::OpenOptionsExt;
    let mut file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(o_excl())
        .open(&device.path)
        .map_err(|_| "release-device-busy")?;
    // From here the device cannot be mounted or claimed, and our fd pins it:
    // its kernel name is not given to another disk. Re-check that the fd is
    // the device that was checked (a disk swapped between the check and the
    // open), and that no process opened it meanwhile.
    if !same_device(env, disk_id, &device, &file) {
        return Err("release-identity-mismatch");
    }
    if opened_by_another(&env.proc_dir, &device) {
        return Err("release-device-open");
    }
    zero_ends(&mut file).map_err(|_| "release-write-failed")?;
    // A normal (non-exclusive) open cannot be locked out by any means the
    // kernel offers. What could make one is the host's own read-only probes
    // (udev, blkid, smartctl), never a guest: no VM record names this disk
    // and the agent gives a releasing disk to no launch. One still open now
    // is reported, and the disk is not offered again.
    if opened_by_another(&env.proc_dir, &device) {
        return Err("release-device-open");
    }
    // Verified through the fd still pinning the wiped device, never through
    // a name that could meanwhile point elsewhere.
    let pinned = PathBuf::from(format!(
        "/proc/{}/fd/{}",
        std::process::id(),
        std::os::fd::AsRawFd::as_raw_fd(&file)
    ));
    let verdict = probe.has_signature(if env.paths.require_block_device {
        &pinned
    } else {
        &device.path
    });
    drop(file);
    if env.paths.require_block_device {
        // Drop partitions the kernel read from the guest's table (best
        // effort: the collector reports any that remain).
        let _ = std::process::Command::new("blockdev")
            .arg("--rereadpt")
            .arg(&device.path)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status();
    }
    match verdict {
        Ok(false) => {}
        Ok(true) => return Err("release-signature-remains"),
        Err(_) => return Err("release-verify-failed"),
    }
    if let Some(dir) = &env.udev_rules_dir {
        remove_udev_rule(dir, disk_id);
    }
    Ok(())
}

/// Zero the first and last [`WIPE_BYTES`] (the whole device if smaller
/// than both), then make it durable.
pub fn zero_ends(file: &mut std::fs::File) -> std::io::Result<()> {
    let size = file.seek(SeekFrom::End(0))?;
    let chunk = vec![0u8; 1024 * 1024];
    let write_zeros = |file: &mut std::fs::File, from: u64, len: u64| -> std::io::Result<()> {
        file.seek(SeekFrom::Start(from))?;
        let mut left = len;
        while left > 0 {
            let n = usize::try_from(left.min(chunk.len() as u64)).unwrap_or(chunk.len());
            file.write_all(&chunk[..n])?;
            left -= n as u64;
        }
        Ok(())
    };
    let head = size.min(WIPE_BYTES);
    write_zeros(file, 0, head)?;
    let tail_start = size.saturating_sub(WIPE_BYTES).max(head);
    write_zeros(file, tail_start, size - tail_start)?;
    file.sync_all()
}

/// Tell systemd the hold is in place (`Type=notify`). No socket (run by
/// hand): nothing to do.
pub fn notify_ready() {
    use std::os::linux::net::SocketAddrExt;
    let Some(socket) = std::env::var_os("NOTIFY_SOCKET") else {
        return;
    };
    let socket = socket.to_string_lossy().into_owned();
    let addr = match socket.strip_prefix('@') {
        Some(name) => std::os::unix::net::SocketAddr::from_abstract_name(name.as_bytes()),
        None => std::os::unix::net::SocketAddr::from_pathname(&socket),
    };
    let sent = addr.and_then(|addr| {
        let sock = std::os::unix::net::UnixDatagram::unbound()?;
        sock.send_to_addr(b"READY=1", &addr)
    });
    if sent.is_err() {
        eprintln!("hippius-miner-agent: dedicated-hold: sd_notify failed");
    }
}

#[cfg(test)]
mod tests;
