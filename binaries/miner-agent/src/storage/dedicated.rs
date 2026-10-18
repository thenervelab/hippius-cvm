//! Dedicated-disk inventory (docs/design/disk-tier-verification.md §4.2).
//!
//! Each `[[storage.dedicated_disks]]` entry names a whole physical disk by
//! its `/dev/disk/by-id/` basename. It is checked READ-ONLY —
//! `/sys/block`, `/proc/self/mountinfo`, `/proc/swaps` and `blkid -p` — by
//! the collector ([`collect`], the `storage-collect` oneshot), which runs
//! outside the agent's sandbox: the agent runs with `PrivateDevices=yes`
//! and sees no `/dev/disk` and no block device. The agent judges the
//! declared names from the collector's facts ([`inventory`]) and reports
//! each in the `v7` heartbeat as `free`, `draining`,
//! `unavailable` (with the refusal code), `failed` (gone after having been
//! seen) or `replaced` (the by-id name now points at another device). The
//! agent never formats, wipes, partitions or mounts a disk: an operator
//! clears a signature with `wipefs -a` deliberately.
//!
//! Identity binding: the first time a disk passes every check, its WWID
//! (or serial) is recorded in `<state_disk_root>/dedicated-disks.json`. A
//! later mismatch means the by-id link silently points at a different
//! disk, and the disk is reported `replaced`, never offered again under
//! that name.
//!
//! Nothing is assigned to a VM in this phase, so no disk is ever reported
//! `assigned` here.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use hippius_types::storage_report::{DedicatedDiskReport, DedicatedDiskState};
use serde::{Deserialize, Serialize};

use crate::config::{DedicatedDiskConfig, StorageDesiredStateConfig};

/// Smallest disk worth dedicating (design §4.2), GiB.
pub const MIN_DEDICATED_DISK_GB: u64 = 1000;

/// Kernel block-device name prefixes that are not physical disks: loop,
/// device-mapper, md, network block, compressed RAM, Ceph RBD, a nested
/// host's virtio/Xen disks, optical drives.
const VIRTUAL_PREFIXES: [&str; 9] = ["loop", "dm-", "md", "nbd", "zram", "rbd", "vd", "xvd", "sr"];

/// Where the inventory reads the host. Real paths by default; fixtures in
/// tests.
#[derive(Debug, Clone)]
pub struct SysPaths {
    pub by_id: PathBuf,
    pub sys_block: PathBuf,
    pub mountinfo: PathBuf,
    pub swaps: PathBuf,
    /// Require the by-id target to be a block special file whose device
    /// number is the sysfs one. Always on for the host; fixtures (plain
    /// files) turn it off.
    pub require_block_device: bool,
}

impl Default for SysPaths {
    fn default() -> Self {
        Self {
            by_id: PathBuf::from("/dev/disk/by-id"),
            sys_block: PathBuf::from("/sys/block"),
            mountinfo: PathBuf::from("/proc/self/mountinfo"),
            swaps: PathBuf::from("/proc/swaps"),
            require_block_device: true,
        }
    }
}

/// How long one `blkid` may take before the disk is reported
/// `disk-probe-failed` (a dying disk can block a read for minutes).
const BLKID_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(15);

/// The signature probe itself failed (no verdict about the disk).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProbeFailed;

/// Whether a block device carries any on-disk signature (a filesystem,
/// LVM, ZFS, md, LUKS, a partition table). `Err` = the probe itself failed.
pub trait SignatureProbe: Send + Sync {
    fn has_signature(&self, device: &Path) -> Result<bool, ProbeFailed>;
}

/// `blkid -p -o export <device>`: a low-level, read-only superblock probe
/// (it ignores the blkid cache). Exit 2 means "nothing found".
#[derive(Debug, Clone, Copy, Default)]
pub struct BlkidProbe;

impl SignatureProbe for BlkidProbe {
    fn has_signature(&self, device: &Path) -> Result<bool, ProbeFailed> {
        use std::io::Read;
        let mut child = std::process::Command::new("blkid")
            .args(["-p", "-o", "export"])
            .arg(device)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .map_err(|_| ProbeFailed)?;
        let deadline = std::time::Instant::now() + BLKID_TIMEOUT;
        let status = loop {
            match child.try_wait() {
                Ok(Some(status)) => break status,
                Ok(None) if std::time::Instant::now() < deadline => {
                    std::thread::sleep(std::time::Duration::from_millis(50));
                }
                _ => {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(ProbeFailed);
                }
            }
        };
        let (mut stdout, mut stderr) = (String::new(), String::new());
        if let Some(mut out) = child.stdout.take() {
            let _ = out.read_to_string(&mut stdout);
        }
        if let Some(mut err) = child.stderr.take() {
            let _ = err.read_to_string(&mut stderr);
        }
        blkid_verdict(status.code(), &stdout, &stderr)
    }
}

/// `blkid -p -o export`'s answer: exit 0 with a `TYPE=`/`PTTYPE=` line is a
/// signature; exit 2 is "nothing found" ONLY when it printed nothing at
/// all — util-linux also exits 2 when it could not read the device.
fn blkid_verdict(code: Option<i32>, stdout: &str, stderr: &str) -> Result<bool, ProbeFailed> {
    match code {
        Some(0) => Ok(stdout
            .lines()
            .any(|l| l.starts_with("TYPE=") || l.starts_with("PTTYPE="))),
        Some(2) if stdout.trim().is_empty() && stderr.trim().is_empty() => Ok(false),
        _ => Err(ProbeFailed),
    }
}

/// `{by-id name: identity}` — what each disk was when it was first
/// accepted.
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IdentityMap {
    pub disks: BTreeMap<String, String>,
}

pub const IDENTITY_FILE: &str = "dedicated-disks.json";

impl IdentityMap {
    /// Load the map; a missing file is empty, a corrupt one is `None`
    /// (the caller reports nothing new rather than forgetting identities).
    pub fn load(state_root: &Path) -> Option<Self> {
        match std::fs::read(state_root.join(IDENTITY_FILE)) {
            Ok(bytes) => serde_json::from_slice(&bytes).ok(),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Some(Self::default()),
            Err(_) => None,
        }
    }

    pub fn save(&self, state_root: &Path) -> std::io::Result<()> {
        use std::io::Write;
        std::fs::create_dir_all(state_root)?;
        let mut tmp = tempfile::NamedTempFile::new_in(state_root)?;
        tmp.write_all(&serde_json::to_vec_pretty(self).map_err(std::io::Error::other)?)?;
        tmp.as_file().sync_all()?;
        tmp.persist(state_root.join(IDENTITY_FILE))
            .map_err(|e| e.error)?;
        // The rename is durable only once the directory is.
        std::fs::File::open(state_root)?.sync_all()?;
        Ok(())
    }
}

/// The identity map in memory, shared by everything that binds disks
/// (the heartbeat inventory, the `storage-config` route), so one never
/// works from a copy the other has moved past. Loaded on first use;
/// `Some(None)` = the file is corrupt.
#[derive(Debug, Default)]
pub struct IdentityStore {
    map: std::sync::Mutex<Option<Option<IdentityMap>>>,
}

impl IdentityStore {
    /// The loaded map, behind the store's lock (load it with
    /// [`IdentityMap::load`] on first use).
    pub fn lock(&self) -> std::sync::MutexGuard<'_, Option<Option<IdentityMap>>> {
        self.map
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

/// `major:minor` of a `st_dev`, as `/sys/block/<dev>/dev` and mountinfo
/// spell it (glibc's encoding).
pub fn dev_string(dev: u64) -> String {
    let major = ((dev >> 8) & 0xfff) | ((dev >> 32) & !0xfff);
    let minor = (dev & 0xff) | ((dev >> 12) & !0xff);
    format!("{major}:{minor}")
}

fn read_trimmed(path: &Path) -> Option<String> {
    std::fs::read_to_string(path)
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

/// One disk's verdict before its desired state is applied.
struct Inspection {
    size_mb: u64,
    /// `""` when every check passed.
    error: &'static str,
    /// `Some` when the device was found and identified.
    identity: Option<String>,
    /// `major:minor`, for the duplicate check.
    dev: Option<String>,
    found: bool,
    /// The kernel reports the device offline.
    offline: bool,
}

fn inspect(
    id: &str,
    paths: &SysPaths,
    probe: &dyn SignatureProbe,
    system_devs: &BTreeSet<String>,
    mounted_devs: &BTreeSet<String>,
    swap_devices: &BTreeSet<PathBuf>,
) -> Inspection {
    let mut out = Inspection {
        size_mb: 0,
        error: "",
        identity: None,
        dev: None,
        found: false,
        offline: false,
    };
    let Ok(device) = std::fs::canonicalize(paths.by_id.join(id)) else {
        out.error = "disk-not-found";
        return out;
    };
    out.found = true;
    let Some(name) = device
        .file_name()
        .and_then(|n| n.to_str())
        .map(str::to_string)
    else {
        out.error = "disk-not-found";
        return out;
    };
    // `/sys/block` lists whole disks only; a partition is not there.
    let sys = paths.sys_block.join(&name);
    if !sys.is_dir() {
        out.error = "disk-not-whole-device";
        return out;
    }
    // The kernel marks a failing disk `offline` (SCSI `device/state`).
    if read_trimmed(&sys.join("device/state")).is_some_and(|st| st != "running") {
        out.error = "disk-offline";
        out.offline = true;
        return out;
    }
    out.identity = read_trimmed(&sys.join("device/wwid"))
        .or_else(|| read_trimmed(&sys.join("wwid")))
        .or_else(|| read_trimmed(&sys.join("device/serial")));
    out.dev = read_trimmed(&sys.join("dev"));
    if paths.require_block_device {
        use std::os::unix::fs::{FileTypeExt, MetadataExt};
        let Ok(meta) = std::fs::metadata(&device) else {
            out.error = "disk-not-found";
            return out;
        };
        if !meta.file_type().is_block_device() {
            out.error = "disk-not-block-device";
            return out;
        }
        // The node by-id points at is the device sysfs describes.
        if out.dev.as_deref() != Some(dev_string(meta.rdev()).as_str()) {
            out.error = "disk-sysfs-mismatch";
            return out;
        }
    }
    let size_bytes = read_trimmed(&sys.join("size"))
        .and_then(|s| s.parse::<u64>().ok())
        .map(|sectors| sectors.saturating_mul(512));
    out.size_mb = size_bytes.unwrap_or(0) / (1024 * 1024);

    out.error = if VIRTUAL_PREFIXES.iter().any(|p| name.starts_with(p)) || is_virtual_device(&sys) {
        "disk-virtual"
    } else if has_partitions(&sys, &name) {
        "disk-has-partitions"
    } else if std::fs::read_dir(sys.join("holders")).is_ok_and(|mut d| d.next().is_some()) {
        "disk-holder-busy"
    } else if out.dev.as_ref().is_some_and(|d| system_devs.contains(d)) {
        "disk-is-system"
    } else if out.dev.as_ref().is_some_and(|d| mounted_devs.contains(d))
        || swap_devices.contains(&device)
    {
        "disk-in-use"
    } else if out.identity.is_none() {
        "disk-no-identity"
    } else if size_bytes.unwrap_or(0) < MIN_DEDICATED_DISK_GB * 1024 * 1024 * 1024 {
        "disk-too-small"
    } else {
        match probe.has_signature(&device) {
            Ok(false) => "",
            Ok(true) => "disk-has-signature",
            Err(ProbeFailed) => "disk-probe-failed",
        }
    };
    out
}

/// Whether sysfs places the disk under a virtual device or a virtio
/// transport (`/sys/block/<dev>` is a link into `/sys/devices/…`): a
/// virtio-SCSI disk is named `sdX` like a real one.
pub(crate) fn is_virtual_device(sys: &Path) -> bool {
    let Ok(real) = std::fs::canonicalize(sys) else {
        return false;
    };
    real.components().any(|c| {
        let c = c.as_os_str().to_string_lossy();
        c.starts_with("virtio") || c == "virtual"
    })
}

fn has_partitions(sys: &Path, name: &str) -> bool {
    !partition_names(sys, name).is_empty()
}

/// The partitions of the whole disk `name` at `sys` (`/sys/block/<name>`):
/// its `<name>…` subdirectories holding a `partition` file, sorted.
pub(crate) fn partition_names(sys: &Path, name: &str) -> Vec<String> {
    let Ok(entries) = std::fs::read_dir(sys) else {
        return Vec::new();
    };
    let mut names: Vec<String> = entries
        .flatten()
        .filter_map(|e| e.file_name().into_string().ok())
        .filter(|n| n.starts_with(name) && sys.join(n).join("partition").exists())
        .collect();
    names.sort();
    names
}

/// `major:minor` of every mounted filesystem.
fn mounted_devs(mountinfo: &Path) -> BTreeSet<String> {
    std::fs::read_to_string(mountinfo)
        .map(|text| {
            text.lines()
                .filter_map(|l| l.split(' ').nth(2).map(str::to_string))
                .collect()
        })
        .unwrap_or_default()
}

/// The device paths in use as swap.
fn swap_devices(swaps: &Path) -> BTreeSet<PathBuf> {
    std::fs::read_to_string(swaps)
        .map(|text| {
            text.lines()
                .skip(1)
                .filter_map(|l| l.split_whitespace().next())
                .filter_map(|p| std::fs::canonicalize(p).ok())
                .collect()
        })
        .unwrap_or_default()
}

/// What the collector found behind one `/dev/disk/by-id/` name
/// ([`collect`]). Every check that needs a block device (the node's type
/// and number, `blkid -p`) happens in the collector, which runs outside
/// the agent's sandbox: the agent runs with `PrivateDevices=yes` and sees
/// no `/dev/disk`, no block device.
// No `deny_unknown_fields`: a newer collector may add a field.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiskFact {
    pub size_mb: u64,
    /// The first refusal the collector's checks found, `""` when none.
    /// `disk-is-system` and `disk-duplicate` are the agent's (it alone
    /// knows its pools and its declared names).
    pub error: String,
    pub identity: Option<String>,
    /// `major:minor`.
    pub dev: Option<String>,
    pub offline: bool,
}

/// The collector's report: every candidate disk by by-id name, and when
/// it was read.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiskFacts {
    pub collected_at_unix: u64,
    pub disks: BTreeMap<String, DiskFact>,
}

/// Where the collector leaves its report, and the agent reads it.
pub const DISK_FACTS_PATH: &str = "/run/hippius-miner/disk-facts.json";

/// Older facts are not trusted (the collector's timer runs every 5 min).
pub const DISK_FACTS_MAX_AGE_SECS: u64 = 15 * 60;

/// Read the host's disks (collector side): every `/dev/disk/by-id/` name
/// that could be a dedicated disk, checked with `paths` and `probe`.
pub fn collect(paths: &SysPaths, probe: &dyn SignatureProbe, now_unix: u64) -> DiskFacts {
    // One `blkid` per device, however many by-id aliases it has (wwn-,
    // ata-, scsi-, nvme-eui…): each can take up to its timeout.
    let probe = &OncePerDevice {
        inner: probe,
        seen: std::sync::Mutex::new(BTreeMap::new()),
    };
    let mounted = mounted_devs(&paths.mountinfo);
    let swaps = swap_devices(&paths.swaps);
    let mut disks = BTreeMap::new();
    let names: Vec<String> = std::fs::read_dir(&paths.by_id)
        .map(|entries| {
            entries
                .flatten()
                .filter_map(|e| e.file_name().into_string().ok())
                .filter(|n| {
                    hippius_types::storage_report::is_valid_dedicated_disk_id(n)
                        && !is_partition_name(n)
                })
                .collect()
        })
        .unwrap_or_default();
    for name in names {
        let i = inspect(&name, paths, probe, &BTreeSet::new(), &mounted, &swaps);
        if !i.found {
            continue;
        }
        disks.insert(
            name,
            DiskFact {
                size_mb: i.size_mb,
                error: i.error.to_string(),
                identity: i.identity,
                dev: i.dev,
                offline: i.offline,
            },
        );
    }
    DiskFacts {
        collected_at_unix: now_unix,
        disks,
    }
}

/// `<name>-part<N>`: udev's link to a partition.
pub(crate) fn is_partition_name(name: &str) -> bool {
    name.rsplit_once("-part")
        .is_some_and(|(_, n)| !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()))
}

/// A probe answering once per device path.
struct OncePerDevice<'a> {
    inner: &'a dyn SignatureProbe,
    seen: std::sync::Mutex<BTreeMap<PathBuf, Result<bool, ProbeFailed>>>,
}

impl SignatureProbe for OncePerDevice<'_> {
    fn has_signature(&self, device: &Path) -> Result<bool, ProbeFailed> {
        let mut seen = self
            .seen
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        *seen
            .entry(device.to_path_buf())
            .or_insert_with(|| self.inner.has_signature(device))
    }
}

impl DiskFacts {
    /// Write the report atomically (collector side).
    pub fn save(&self, path: &Path) -> std::io::Result<()> {
        use std::io::Write;
        let dir = path
            .parent()
            .ok_or_else(|| std::io::Error::other("no parent"))?;
        std::fs::create_dir_all(dir)?;
        let mut tmp = tempfile::NamedTempFile::new_in(dir)?;
        tmp.write_all(&serde_json::to_vec_pretty(self).map_err(std::io::Error::other)?)?;
        tmp.as_file().sync_all()?;
        tmp.persist(path).map_err(|e| e.error)?;
        Ok(())
    }

    /// The report at `path` (agent side), refused when missing,
    /// unreadable or older than `max_age_secs` at `now_unix`.
    pub fn load(path: &Path, now_unix: u64, max_age_secs: u64) -> Result<Self, &'static str> {
        let bytes = match std::fs::read(path) {
            Ok(b) => b,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Err("disk-facts-missing"),
            Err(_) => return Err("disk-facts-unreadable"),
        };
        let facts: DiskFacts =
            serde_json::from_slice(&bytes).map_err(|_| "disk-facts-unreadable")?;
        if now_unix.saturating_sub(facts.collected_at_unix) > max_age_secs
            || facts.collected_at_unix > now_unix.saturating_add(300)
        {
            return Err("disk-facts-stale");
        }
        Ok(facts)
    }
}

/// Where the agent gets [`DiskFacts`].
pub trait FactsSource: Send + Sync {
    fn facts(&self) -> Result<DiskFacts, &'static str>;
    /// Ask for a fresh collection now (the `storage-config` route, before
    /// it judges declared disks). Best effort.
    fn refresh(&self) {}
}

/// The collector's report file, refreshed by starting its unit.
#[derive(Debug, Clone)]
pub struct FileFacts {
    pub path: PathBuf,
    pub max_age_secs: u64,
    /// The collector's systemd unit, started (and waited for) on refresh.
    pub unit: Option<String>,
}

/// The collector's unit (`deploy/ansible/.../miner-agent-install.yml`).
pub const COLLECTOR_UNIT: &str = "hippius-miner-storage-collect.service";

impl Default for FileFacts {
    fn default() -> Self {
        Self {
            path: PathBuf::from(DISK_FACTS_PATH),
            max_age_secs: DISK_FACTS_MAX_AGE_SECS,
            unit: Some(COLLECTOR_UNIT.to_string()),
        }
    }
}

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

impl FactsSource for FileFacts {
    fn facts(&self) -> Result<DiskFacts, &'static str> {
        DiskFacts::load(&self.path, now_unix(), self.max_age_secs)
    }

    fn refresh(&self) {
        let Some(unit) = &self.unit else { return };
        // `systemctl start` waits for a oneshot to finish; bounded.
        let Ok(mut child) = std::process::Command::new("systemctl")
            .args(["start", unit])
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
        else {
            return;
        };
        let deadline = std::time::Instant::now() + REFRESH_TIMEOUT;
        loop {
            match child.try_wait() {
                Ok(Some(_)) => return,
                Ok(None) if std::time::Instant::now() < deadline => {
                    std::thread::sleep(std::time::Duration::from_millis(100));
                }
                _ => {
                    let _ = child.kill();
                    let _ = child.wait();
                    return;
                }
            }
        }
    }
}

/// How long a refresh may wait for the collector.
/// Well under vali's 25 s order timeout; a slower collector finishes on
/// its own and the next order or timer run reads it.
const REFRESH_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(15);

/// The agent's verdict for one declared name, from the collector's fact.
fn from_fact(fact: Option<&DiskFact>, system_devs: &BTreeSet<String>) -> Inspection {
    let Some(f) = fact else {
        return Inspection {
            size_mb: 0,
            error: "disk-not-found",
            identity: None,
            dev: None,
            found: false,
            offline: false,
        };
    };
    // The collector's codes, as `'static`; an unknown one (a newer
    // collector) is unavailable.
    let mut error = CODES
        .iter()
        .copied()
        .find(|c| *c == f.error)
        .unwrap_or("disk-unavailable");
    // `disk-is-system` ranks before every later check (the order of
    // [`inspect`]): the collector does not know the agent's pools.
    if f.dev.as_ref().is_some_and(|d| system_devs.contains(d)) && AFTER_SYSTEM.contains(&error) {
        error = "disk-is-system";
    }
    Inspection {
        size_mb: f.size_mb,
        error,
        identity: f.identity.clone(),
        dev: f.dev.clone(),
        found: true,
        offline: f.offline,
    }
}

/// Every code [`inspect`] returns.
const CODES: [&str; 14] = [
    "",
    "disk-not-found",
    "disk-not-whole-device",
    "disk-offline",
    "disk-not-block-device",
    "disk-sysfs-mismatch",
    "disk-virtual",
    "disk-has-partitions",
    "disk-holder-busy",
    "disk-in-use",
    "disk-no-identity",
    "disk-too-small",
    "disk-has-signature",
    "disk-probe-failed",
];

/// The checks [`inspect`] runs after `disk-is-system`.
const AFTER_SYSTEM: [&str; 6] = [
    "",
    "disk-in-use",
    "disk-no-identity",
    "disk-too-small",
    "disk-has-signature",
    "disk-probe-failed",
];

/// Judge every declared disk from the collector's `facts` (agent side).
/// `system_devs` are the `major:minor` of the filesystems the host itself
/// needs (`/`, the state root, every pool). New identities are recorded in
/// `identities`. Facts the agent cannot use (missing, stale) make every
/// disk `unavailable` with that code: never `failed`, never forgotten.
pub fn inventory(
    disks: &[DedicatedDiskConfig],
    facts: Result<&DiskFacts, &'static str>,
    system_devs: &BTreeSet<String>,
    identities: &mut IdentityMap,
) -> Vec<DedicatedDiskReport> {
    let facts = match facts {
        Ok(f) => f,
        Err(code) => {
            let mut out: Vec<DedicatedDiskReport> = disks
                .iter()
                .map(|cfg| DedicatedDiskReport {
                    id: cfg.id.clone(),
                    size_mb: 0,
                    state: DedicatedDiskState::Unavailable,
                    vm: String::new(),
                    error: code.to_string(),
                })
                .collect();
            out.sort_by(|a, b| a.id.cmp(&b.id));
            return out;
        }
    };
    let mut seen_devs: BTreeSet<String> = BTreeSet::new();
    let mut reports: Vec<DedicatedDiskReport> = disks
        .iter()
        .map(|cfg| {
            let mut i = from_fact(facts.disks.get(&cfg.id), system_devs);
            if i.error.is_empty() {
                if let Some(dev) = &i.dev {
                    if !seen_devs.insert(dev.clone()) {
                        i.error = "disk-duplicate";
                    }
                }
            }
            let recorded = identities.disks.get(&cfg.id).cloned();
            let state = match (&recorded, &i.identity) {
                (Some(was), Some(now)) if was != now => DedicatedDiskState::Replaced,
                // Seen and accepted before, gone now: the device vanished.
                (Some(_), _) if !i.found || i.offline => DedicatedDiskState::Failed,
                _ if !i.error.is_empty() => DedicatedDiskState::Unavailable,
                _ if cfg.state == StorageDesiredStateConfig::Draining => {
                    DedicatedDiskState::Draining
                }
                _ => DedicatedDiskState::Free,
            };
            if recorded.is_none() && i.error.is_empty() {
                if let Some(identity) = &i.identity {
                    identities.disks.insert(cfg.id.clone(), identity.clone());
                }
            }
            DedicatedDiskReport {
                id: cfg.id.clone(),
                size_mb: i.size_mb,
                state,
                vm: String::new(),
                error: match state {
                    DedicatedDiskState::Unavailable | DedicatedDiskState::Failed => {
                        i.error.to_string()
                    }
                    _ => String::new(),
                },
            }
        })
        .collect();
    reports.sort_by(|a, b| a.id.cmp(&b.id));
    reports
}

/// Facts read from the host directly, each time (`storage-check
/// --collect`, tests): needs the devices the agent's sandbox hides.
pub struct LiveFacts {
    pub paths: SysPaths,
    pub probe: Box<dyn SignatureProbe>,
}

impl FactsSource for LiveFacts {
    fn facts(&self) -> Result<DiskFacts, &'static str> {
        Ok(collect(&self.paths, self.probe.as_ref(), now_unix()))
    }
}

/// [`collect`] then [`inventory`]: the host read directly (the collector,
/// `storage-check --collect`, tests).
pub fn inventory_live(
    disks: &[DedicatedDiskConfig],
    paths: &SysPaths,
    probe: &dyn SignatureProbe,
    system_devs: &BTreeSet<String>,
    identities: &mut IdentityMap,
) -> Vec<DedicatedDiskReport> {
    let facts = collect(paths, probe, now_unix());
    inventory(disks, Ok(&facts), system_devs, identities)
}

#[cfg(test)]
mod tests {
    use super::*;

    const TIB_SECTORS: u64 = 2 * 1024 * 1024 * 1024; // 1 TiB / 512

    /// A fixture host under a temp dir: `dev/`, `by-id/`, `sys/block/`.
    struct Host {
        dir: tempfile::TempDir,
    }

    impl Host {
        fn new() -> Self {
            let h = Self {
                dir: tempfile::tempdir().unwrap(),
            };
            for d in ["dev", "by-id", "sys"] {
                std::fs::create_dir_all(h.dir.path().join(d)).unwrap();
            }
            std::fs::write(h.dir.path().join("mountinfo"), "").unwrap();
            std::fs::write(
                h.dir.path().join("swaps"),
                "Filename Type Size Used Priority\n",
            )
            .unwrap();
            h
        }

        fn paths(&self) -> SysPaths {
            let r = self.dir.path();
            SysPaths {
                by_id: r.join("by-id"),
                sys_block: r.join("sys"),
                mountinfo: r.join("mountinfo"),
                swaps: r.join("swaps"),
                require_block_device: false,
            }
        }

        /// A whole disk `name` (`major:minor` `dev`) of `sectors`, with a
        /// WWID, linked as `id`.
        fn disk(&self, id: &str, name: &str, dev: &str, sectors: u64, wwid: &str) {
            let r = self.dir.path();
            std::fs::write(r.join("dev").join(name), b"").unwrap();
            let sys = r.join("sys").join(name);
            std::fs::create_dir_all(sys.join("device")).unwrap();
            std::fs::create_dir_all(sys.join("holders")).unwrap();
            std::fs::write(sys.join("size"), format!("{sectors}\n")).unwrap();
            std::fs::write(sys.join("dev"), format!("{dev}\n")).unwrap();
            std::fs::write(sys.join("device/wwid"), format!("{wwid}\n")).unwrap();
            self.link(id, name);
        }

        fn link(&self, id: &str, name: &str) {
            let r = self.dir.path();
            let link = r.join("by-id").join(id);
            let _ = std::fs::remove_file(&link);
            std::os::unix::fs::symlink(r.join("dev").join(name), link).unwrap();
        }

        fn sys(&self, name: &str) -> PathBuf {
            self.dir.path().join("sys").join(name)
        }
    }

    struct Probe(Result<bool, ProbeFailed>);
    impl SignatureProbe for Probe {
        fn has_signature(&self, _device: &Path) -> Result<bool, ProbeFailed> {
            self.0
        }
    }
    const CLEAN: Probe = Probe(Ok(false));

    fn cfg(id: &str) -> DedicatedDiskConfig {
        DedicatedDiskConfig {
            id: id.into(),
            state: StorageDesiredStateConfig::Active,
        }
    }

    fn run(
        host: &Host,
        disks: &[DedicatedDiskConfig],
        probe: &Probe,
        ids: &mut IdentityMap,
    ) -> Vec<DedicatedDiskReport> {
        inventory_live(disks, &host.paths(), probe, &BTreeSet::new(), ids)
    }

    fn one(host: &Host, id: &str, probe: &Probe) -> DedicatedDiskReport {
        run(host, &[cfg(id)], probe, &mut IdentityMap::default()).remove(0)
    }

    #[test]
    fn a_clean_whole_disk_is_free_and_its_identity_recorded() {
        let host = Host::new();
        host.disk(
            "wwn-0x1",
            "sdb",
            "8:16",
            18 * TIB_SECTORS,
            "naa.5000c500a1b2c3d4",
        );
        let mut ids = IdentityMap::default();
        let r = run(&host, &[cfg("wwn-0x1")], &CLEAN, &mut ids).remove(0);
        assert_eq!(r.state, DedicatedDiskState::Free);
        assert_eq!(r.error, "");
        assert_eq!(r.vm, "");
        assert_eq!(r.size_mb, 18 * 1024 * 1024);
        assert_eq!(ids.disks["wwn-0x1"], "naa.5000c500a1b2c3d4");
    }

    #[test]
    fn a_draining_disk_reports_draining() {
        let host = Host::new();
        host.disk("wwn-0x1", "sdb", "8:16", 2 * TIB_SECTORS, "w1");
        let mut c = cfg("wwn-0x1");
        c.state = StorageDesiredStateConfig::Draining;
        let r = run(&host, &[c], &CLEAN, &mut IdentityMap::default()).remove(0);
        assert_eq!(r.state, DedicatedDiskState::Draining);
    }

    fn assert_unavailable(r: &DedicatedDiskReport, code: &str) {
        assert_eq!(r.state, DedicatedDiskState::Unavailable, "{code}");
        assert_eq!(r.error, code);
    }

    #[test]
    fn every_refusal_has_its_code() {
        let host = Host::new();
        assert_unavailable(&one(&host, "wwn-0xmissing", &CLEAN), "disk-not-found");

        // A partition: a device not listed in /sys/block.
        std::fs::write(host.dir.path().join("dev/sdc1"), b"").unwrap();
        host.link("wwn-0xpart", "sdc1");
        assert_unavailable(&one(&host, "wwn-0xpart", &CLEAN), "disk-not-whole-device");

        host.disk("wwn-0xloop", "loop3", "7:3", 4 * TIB_SECTORS, "w");
        assert_unavailable(&one(&host, "wwn-0xloop", &CLEAN), "disk-virtual");
        host.disk("wwn-0xdm", "dm-0", "253:0", 4 * TIB_SECTORS, "w");
        assert_unavailable(&one(&host, "wwn-0xdm", &CLEAN), "disk-virtual");

        host.disk("wwn-0xparts", "sdd", "8:48", 4 * TIB_SECTORS, "w");
        std::fs::create_dir_all(host.sys("sdd").join("sdd1")).unwrap();
        std::fs::write(host.sys("sdd").join("sdd1/partition"), "1\n").unwrap();
        assert_unavailable(&one(&host, "wwn-0xparts", &CLEAN), "disk-has-partitions");

        host.disk("wwn-0xheld", "sde", "8:64", 4 * TIB_SECTORS, "w");
        std::fs::write(host.sys("sde").join("holders/md0"), b"").unwrap();
        assert_unavailable(&one(&host, "wwn-0xheld", &CLEAN), "disk-holder-busy");

        host.disk("wwn-0xsmall", "sdf", "8:80", 500 * 1024 * 1024 * 2, "w");
        assert_unavailable(&one(&host, "wwn-0xsmall", &CLEAN), "disk-too-small");

        host.disk("wwn-0xsig", "sdg", "8:96", 4 * TIB_SECTORS, "w");
        assert_unavailable(
            &one(&host, "wwn-0xsig", &Probe(Ok(true))),
            "disk-has-signature",
        );
        assert_unavailable(
            &one(&host, "wwn-0xsig", &Probe(Err(ProbeFailed))),
            "disk-probe-failed",
        );

        host.disk("wwn-0xanon", "sdh", "8:112", 4 * TIB_SECTORS, "w");
        std::fs::remove_file(host.sys("sdh").join("device/wwid")).unwrap();
        assert_unavailable(&one(&host, "wwn-0xanon", &CLEAN), "disk-no-identity");
        // …a serial is enough.
        std::fs::write(host.sys("sdh").join("device/serial"), "ZR5ABCDE\n").unwrap();
        assert_eq!(
            one(&host, "wwn-0xanon", &CLEAN).state,
            DedicatedDiskState::Free
        );
    }

    #[test]
    fn a_mounted_swap_or_system_disk_is_refused() {
        let host = Host::new();
        host.disk("wwn-0x1", "sdb", "8:16", 4 * TIB_SECTORS, "w");
        std::fs::write(
            host.dir.path().join("mountinfo"),
            "40 22 8:16 / /mnt/x rw - ext4 /dev/sdb rw\n",
        )
        .unwrap();
        assert_unavailable(&one(&host, "wwn-0x1", &CLEAN), "disk-in-use");

        std::fs::write(host.dir.path().join("mountinfo"), "").unwrap();
        let dev = host.dir.path().join("dev/sdb");
        std::fs::write(
            host.dir.path().join("swaps"),
            format!(
                "Filename Type Size Used Priority\n{} partition 1 0 -2\n",
                dev.display()
            ),
        )
        .unwrap();
        assert_unavailable(&one(&host, "wwn-0x1", &CLEAN), "disk-in-use");

        std::fs::write(host.dir.path().join("swaps"), "Filename Type\n").unwrap();
        let system: BTreeSet<String> = ["8:16".to_string()].into();
        let r = inventory_live(
            &[cfg("wwn-0x1")],
            &host.paths(),
            &CLEAN,
            &system,
            &mut IdentityMap::default(),
        );
        assert_unavailable(&r[0], "disk-is-system");
    }

    #[test]
    fn the_same_device_under_two_names_is_a_duplicate() {
        let host = Host::new();
        host.disk("wwn-0x1", "sdb", "8:16", 4 * TIB_SECTORS, "w");
        host.link("ata-ST4000_Z1", "sdb");
        let r = run(
            &host,
            &[cfg("ata-ST4000_Z1"), cfg("wwn-0x1")],
            &CLEAN,
            &mut IdentityMap::default(),
        );
        // Sorted by id; the first inspected (config order) wins.
        let by_id: BTreeMap<_, _> = r.iter().map(|d| (d.id.as_str(), d)).collect();
        assert_eq!(by_id["ata-ST4000_Z1"].state, DedicatedDiskState::Free);
        assert_unavailable(by_id["wwn-0x1"], "disk-duplicate");
    }

    #[test]
    fn a_different_device_behind_the_same_name_is_replaced() {
        let host = Host::new();
        host.disk("wwn-0x1", "sdb", "8:16", 4 * TIB_SECTORS, "naa.first");
        let mut ids = IdentityMap::default();
        run(&host, &[cfg("wwn-0x1")], &CLEAN, &mut ids);
        // The link now points at another disk.
        host.disk("wwn-0x1", "sdc", "8:32", 4 * TIB_SECTORS, "naa.second");
        let r = run(&host, &[cfg("wwn-0x1")], &CLEAN, &mut ids).remove(0);
        assert_eq!(r.state, DedicatedDiskState::Replaced);
        assert_eq!(r.error, "");
        // The recorded identity is kept, so it stays replaced.
        assert_eq!(ids.disks["wwn-0x1"], "naa.first");
    }

    #[test]
    fn a_seen_disk_that_vanishes_has_failed() {
        let host = Host::new();
        host.disk("wwn-0x1", "sdb", "8:16", 4 * TIB_SECTORS, "naa.first");
        let mut ids = IdentityMap::default();
        run(&host, &[cfg("wwn-0x1")], &CLEAN, &mut ids);
        std::fs::remove_file(host.dir.path().join("by-id/wwn-0x1")).unwrap();
        let r = run(&host, &[cfg("wwn-0x1")], &CLEAN, &mut ids).remove(0);
        assert_eq!(r.state, DedicatedDiskState::Failed);
        assert_eq!(r.error, "disk-not-found");
    }

    #[test]
    fn a_refused_disk_records_no_identity() {
        let host = Host::new();
        host.disk("wwn-0x1", "sdb", "8:16", 4 * TIB_SECTORS, "naa.first");
        let mut ids = IdentityMap::default();
        run(&host, &[cfg("wwn-0x1")], &Probe(Ok(true)), &mut ids);
        assert!(ids.disks.is_empty());
    }

    #[test]
    fn identities_round_trip_on_disk() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(IdentityMap::load(dir.path()), Some(IdentityMap::default()));
        let mut ids = IdentityMap::default();
        ids.disks.insert("wwn-0x1".into(), "naa.1".into());
        ids.save(dir.path()).unwrap();
        assert_eq!(IdentityMap::load(dir.path()), Some(ids));
        std::fs::write(dir.path().join(IDENTITY_FILE), b"{bad").unwrap();
        assert_eq!(IdentityMap::load(dir.path()), None);
    }

    #[test]
    fn dev_numbers_are_spelled_like_sysfs() {
        // makedev(8, 16) and makedev(259, 3) in glibc's encoding.
        assert_eq!(dev_string((8 << 8) | 16), "8:16");
        assert_eq!(dev_string((259 << 8) | 3), "259:3");
    }

    #[test]
    fn the_reports_satisfy_the_wire_rules() {
        use hippius_types::storage_report::StorageReport;
        let host = Host::new();
        host.disk("wwn-0x1", "sdb", "8:16", 4 * TIB_SECTORS, "w1");
        let disks = run(
            &host,
            &[cfg("wwn-0x2"), cfg("wwn-0x1")],
            &CLEAN,
            &mut IdentityMap::default(),
        );
        let report = StorageReport {
            disk_pools: vec![hippius_types::storage_report::DiskPoolReport {
                id: "default".into(),
                class: hippius_types::storage_report::PoolClass::Undeclared,
                total_gb: 0,
                available_gb: 0,
                budget_gb: 0,
                committed_gb: 0,
                os_disks: true,
                state: hippius_types::storage_report::PoolState::Active,
                error: String::new(),
            }],
            dedicated_disks: disks,
            storage_config_revision: 0,
        };
        assert_eq!(report.validate(), Ok(()));
    }

    #[test]
    fn a_disk_behind_a_virtio_transport_is_virtual() {
        let host = Host::new();
        // /sys/block/sdx is a link into /sys/devices/…/virtio3/…/block/sdx.
        let real = host
            .dir
            .path()
            .join("devices/pci0000:00/0000:00:04.0/virtio3/host0/target0:0:0/block/sdx");
        std::fs::create_dir_all(real.join("device")).unwrap();
        std::fs::create_dir_all(real.join("holders")).unwrap();
        std::fs::write(real.join("size"), format!("{}\n", 4 * TIB_SECTORS)).unwrap();
        std::fs::write(real.join("dev"), "8:16\n").unwrap();
        std::fs::write(real.join("device/wwid"), "w\n").unwrap();
        std::os::unix::fs::symlink(&real, host.sys("sdx")).unwrap();
        std::fs::write(host.dir.path().join("dev/sdx"), b"").unwrap();
        host.link("scsi-0QEMU_QEMU_HARDDISK_drive0", "sdx");
        assert_unavailable(
            &one(&host, "scsi-0QEMU_QEMU_HARDDISK_drive0", &CLEAN),
            "disk-virtual",
        );
    }

    #[test]
    fn an_offline_disk_is_unavailable_and_failed_once_accepted() {
        let host = Host::new();
        host.disk("wwn-0x1", "sdb", "8:16", 4 * TIB_SECTORS, "w1");
        let mut ids = IdentityMap::default();
        assert_eq!(
            run(&host, &[cfg("wwn-0x1")], &CLEAN, &mut ids)[0].state,
            DedicatedDiskState::Free
        );
        std::fs::write(host.sys("sdb").join("device/state"), "offline\n").unwrap();
        let r = run(&host, &[cfg("wwn-0x1")], &CLEAN, &mut ids).remove(0);
        assert_eq!(r.state, DedicatedDiskState::Failed);
        assert_eq!(r.error, "disk-offline");
        assert_unavailable(&one(&host, "wwn-0x1", &CLEAN), "disk-offline");
        std::fs::write(host.sys("sdb").join("device/state"), "running\n").unwrap();
        assert_eq!(
            one(&host, "wwn-0x1", &CLEAN).state,
            DedicatedDiskState::Free
        );
    }

    #[test]
    fn a_regular_file_is_not_a_block_device_on_the_host() {
        let host = Host::new();
        host.disk("wwn-0x1", "sdb", "8:16", 4 * TIB_SECTORS, "w1");
        let mut paths = host.paths();
        paths.require_block_device = true;
        let r = inventory_live(
            &[cfg("wwn-0x1")],
            &paths,
            &CLEAN,
            &BTreeSet::new(),
            &mut IdentityMap::default(),
        );
        assert_unavailable(&r[0], "disk-not-block-device");
    }

    #[test]
    fn the_agent_judges_from_the_collectors_facts_file() {
        let host = Host::new();
        host.disk("wwn-0x1", "sdb", "8:16", 4 * TIB_SECTORS, "w1");
        // Partition and foreign names are not collected.
        host.link("wwn-0x1-part1", "sdb");
        host.link("usb-Generic_Flash", "sdb");
        let facts = collect(&host.paths(), &CLEAN, 1_000);
        assert_eq!(facts.disks.keys().collect::<Vec<_>>(), ["wwn-0x1"]);
        let path = host.dir.path().join("facts.json");
        facts.save(&path).unwrap();
        let loaded = DiskFacts::load(&path, 1_100, DISK_FACTS_MAX_AGE_SECS).unwrap();
        assert_eq!(loaded, facts);
        let r = inventory(
            &[cfg("wwn-0x1")],
            Ok(&loaded),
            &BTreeSet::new(),
            &mut IdentityMap::default(),
        );
        assert_eq!(r[0].state, DedicatedDiskState::Free);
        // The agent's own rule on top: a disk its pools sit on.
        let system: BTreeSet<String> = ["8:16".to_string()].into();
        let r = inventory(
            &[cfg("wwn-0x1")],
            Ok(&loaded),
            &system,
            &mut IdentityMap::default(),
        );
        assert_unavailable(&r[0], "disk-is-system");
        // Stale, from the future, missing, garbage: every disk unavailable
        // with the reason, a recorded one never `failed`.
        assert_eq!(
            DiskFacts::load(
                &path,
                1_000 + DISK_FACTS_MAX_AGE_SECS + 1,
                DISK_FACTS_MAX_AGE_SECS
            ),
            Err("disk-facts-stale")
        );
        assert_eq!(
            DiskFacts::load(&path, 1, DISK_FACTS_MAX_AGE_SECS),
            Err("disk-facts-stale")
        );
        assert_eq!(
            DiskFacts::load(&host.dir.path().join("none"), 1_000, 60),
            Err("disk-facts-missing")
        );
        std::fs::write(&path, b"{").unwrap();
        assert_eq!(
            DiskFacts::load(&path, 1_000, 60),
            Err("disk-facts-unreadable")
        );
        let mut ids = IdentityMap::default();
        ids.disks.insert("wwn-0x1".into(), "w1".into());
        let r = inventory(
            &[cfg("wwn-0x1")],
            Err("disk-facts-stale"),
            &BTreeSet::new(),
            &mut ids,
        );
        assert_unavailable(&r[0], "disk-facts-stale");
    }

    #[test]
    fn a_device_with_several_names_is_probed_once() {
        struct Count(std::sync::Mutex<u32>);
        impl SignatureProbe for Count {
            fn has_signature(&self, _device: &Path) -> Result<bool, ProbeFailed> {
                *self.0.lock().unwrap() += 1;
                Ok(false)
            }
        }
        let host = Host::new();
        host.disk("wwn-0x1", "sdb", "8:16", 4 * TIB_SECTORS, "w1");
        host.link("ata-ST4000_Z1", "sdb");
        host.link("scsi-0ATA_ST4000_Z1", "sdb");
        let probe = Count(std::sync::Mutex::new(0));
        let facts = collect(&host.paths(), &probe, 1);
        assert_eq!(facts.disks.len(), 3);
        assert_eq!(*probe.0.lock().unwrap(), 1);
        assert!(is_partition_name("wwn-0x1-part2"));
        assert!(!is_partition_name("wwn-0x1-partner"));
    }

    #[test]
    fn blkid_exit_2_is_clean_only_when_silent() {
        assert_eq!(blkid_verdict(Some(2), "", ""), Ok(false));
        assert_eq!(
            blkid_verdict(Some(2), "", "blkid: error: /dev/sdb: Input/output error"),
            Err(ProbeFailed)
        );
        assert_eq!(
            blkid_verdict(Some(0), "DEVNAME=/dev/sdb\nTYPE=xfs\n", ""),
            Ok(true)
        );
        assert_eq!(
            blkid_verdict(Some(0), "DEVNAME=/dev/sdb\nPTTYPE=gpt\n", ""),
            Ok(true)
        );
        assert_eq!(blkid_verdict(Some(0), "DEVNAME=/dev/sdb\n", ""), Ok(false));
        assert_eq!(blkid_verdict(Some(4), "", ""), Err(ProbeFailed));
        assert_eq!(blkid_verdict(None, "", ""), Err(ProbeFailed));
    }
}
