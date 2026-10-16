//! Storage pools — where OS disks live (docs/design/disk-tier-verification.md
//! §4.1).
//!
//! A pool is an already-mounted filesystem the operator declares in
//! `[[storage.pools]]`. With no declaration the agent has exactly one
//! implicit pool, `default`, at `[storage] data_disk_root` with the
//! `[host] cvm_disk_gb_budget` budget: the historical single-root agent,
//! byte for byte.
//!
//! In this phase every OS disk still lands on `default` (vali cannot place
//! on another pool yet); the other pools are declared, checked, accounted
//! and reported so vali can probe them, and every §24 reclaim and the
//! removed-pool guard already walk them.
//!
//! A VM's pool is derived from where its writable disk lives (the pool
//! whose path contains it, `default` otherwise), never stored: an old
//! snapshot, a re-adoption and a fresh launch all agree by construction.

use std::collections::BTreeMap;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

use hippius_types::storage_report::{PoolClass, PoolState};

use crate::config::{
    PoolClassConfig, StorageDesiredStateConfig, StoragePoolConfig, StorageSection,
};

/// The id of the pool every OS disk lands on in this phase.
pub const DEFAULT_POOL_ID: &str = "default";

/// The 507 class of a full `default` pool — the historical class vali
/// already recognises.
pub const INSUFFICIENT_DISK_CLASS: &str = "insufficient-disk";

/// Prefix of the 507 class of a launch to a pool that cannot take it.
pub const POOL_UNAVAILABLE_CLASS: &str = "pool-unavailable";

/// Filesystems a pool may be on: ones that do `O_DIRECT` and keep data
/// across a reboot (no `tmpfs`, `ramfs`, `overlay`, network or FUSE).
pub const POOL_FSTYPES: [&str; 3] = ["ext4", "xfs", "btrfs"];

/// Free space a pool's budget must leave on its filesystem:
/// `max(5 %, 20 GiB)`.
pub fn pool_reserve_bytes(total: u64) -> u64 {
    (total / 20).max(20 * 1024 * 1024 * 1024)
}

/// One storage pool.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pool {
    pub id: String,
    pub path: PathBuf,
    /// [`PoolClass::Undeclared`] only for the implicit `default`.
    pub class: PoolClass,
    /// GiB. For `default` this is `[host] cvm_disk_gb_budget` (`0`
    /// disables the budget reservation, as it always has).
    pub budget_gb: u64,
    pub os_disks: bool,
    pub draining: bool,
}

impl Pool {
    pub fn is_default(&self) -> bool {
        self.id == DEFAULT_POOL_ID
    }

    /// The 507 class this pool's launch gate answers: `insufficient-disk`
    /// for `default`, `insufficient-disk:<id>` for the others. Made when
    /// a launch is refused, not when a pool set is built: a document that
    /// is only validated (a dry run) leaves nothing behind.
    pub fn insufficient_class(&self) -> &'static str {
        if self.is_default() {
            INSUFFICIENT_DISK_CLASS
        } else {
            leak_class(INSUFFICIENT_DISK_CLASS, &self.id)
        }
    }

    /// The 507 class of a launch this pool cannot take now (`draining`,
    /// not for OS disks, or failing its host checks):
    /// `pool-unavailable:<id>`.
    pub fn unavailable_class(&self) -> &'static str {
        leak_class(POOL_UNAVAILABLE_CLASS, &self.id)
    }
}

/// The host's storage pools, sorted by id, `default` always present.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoragePools {
    pools: Vec<Pool>,
    /// Whether `[[storage.pools]]` was declared at all.
    configured: bool,
}

/// `<prefix>:<id>` with a `'static` lifetime (a 507 class is a
/// `&'static str` across the order path). Interned: each class is leaked
/// once, on its first refused launch, however often it is refused
/// (bounded by the pools that ever took launches).
fn leak_class(prefix: &str, id: &str) -> &'static str {
    static CLASSES: std::sync::Mutex<BTreeMap<String, &'static str>> =
        std::sync::Mutex::new(BTreeMap::new());
    let class = format!("{prefix}:{id}");
    let mut classes = CLASSES
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if let Some(leaked) = classes.get(&class) {
        return leaked;
    }
    let leaked: &'static str = Box::leak(class.clone().into_boxed_str());
    classes.insert(class, leaked);
    leaked
}

impl StoragePools {
    /// The historical single root: one pool `default` at `data_root`.
    pub fn implicit(data_root: PathBuf, budget_gb: u64) -> Self {
        Self {
            pools: vec![Pool {
                id: DEFAULT_POOL_ID.to_string(),
                path: data_root,
                class: PoolClass::Undeclared,
                budget_gb,
                os_disks: true,
                draining: false,
            }],
            configured: false,
        }
    }

    /// The pools of a validated config ([`crate::config::Config::validate`]
    /// guarantees ids, count, and a `default` at `data_disk_root` with the
    /// host budget).
    pub fn from_config(storage: &StorageSection, host_disk_budget_gb: u64) -> Self {
        if storage.pools.is_empty() {
            return Self::implicit(storage.data_disk_root.clone(), host_disk_budget_gb);
        }
        let mut pools: Vec<Pool> = storage
            .pools
            .iter()
            .map(|p| Pool {
                id: p.id.clone(),
                path: p.path.clone(),
                class: match p.class {
                    PoolClassConfig::Nvme => PoolClass::Nvme,
                    PoolClassConfig::Ssd => PoolClass::Ssd,
                    PoolClassConfig::Hdd => PoolClass::Hdd,
                },
                budget_gb: p.budget_gb,
                os_disks: p.os_disks,
                draining: p.state == StorageDesiredStateConfig::Draining,
            })
            .collect();
        pools.sort_by(|a, b| a.id.cmp(&b.id));
        Self {
            pools,
            configured: true,
        }
    }

    /// This set plus `extra` pools, all `draining`: what the agent keeps
    /// accounting and reclaiming on but places nothing new on. An id or a
    /// path already in the set is skipped, and the set stays within
    /// [`MAX_DISK_POOLS`](hippius_types::storage_report::MAX_DISK_POOLS).
    pub fn with_draining(mut self, extra: &[StoragePoolConfig]) -> Self {
        for p in extra {
            if self.pools.len() >= hippius_types::storage_report::MAX_DISK_POOLS
                || self.pools.iter().any(|q| q.id == p.id || q.path == p.path)
            {
                continue;
            }
            self.pools.push(Pool {
                id: p.id.clone(),
                path: p.path.clone(),
                class: match p.class {
                    PoolClassConfig::Nvme => PoolClass::Nvme,
                    PoolClassConfig::Ssd => PoolClass::Ssd,
                    PoolClassConfig::Hdd => PoolClass::Hdd,
                },
                budget_gb: p.budget_gb,
                os_disks: p.os_disks,
                draining: true,
            });
            self.configured = true;
        }
        self.pools.sort_by(|a, b| a.id.cmp(&b.id));
        self
    }

    pub fn is_configured(&self) -> bool {
        self.configured
    }

    pub fn iter(&self) -> impl Iterator<Item = &Pool> {
        self.pools.iter()
    }

    pub fn get(&self, id: &str) -> Option<&Pool> {
        self.pools.iter().find(|p| p.id == id)
    }

    /// The `default` pool.
    pub fn default_pool(&self) -> &Pool {
        // Present by construction (implicit, or required by validation).
        self.pools
            .iter()
            .find(|p| p.is_default())
            .unwrap_or(&self.pools[0])
    }

    /// The pool a launch reserves on in this phase: always `default`.
    pub fn launch_pool(&self) -> &Pool {
        self.default_pool()
    }

    /// Every pool but `default` — the extra places a §24 reclaim and the
    /// removed-pool guard must look. Empty without `[[storage.pools]]`.
    pub fn non_default(&self) -> impl Iterator<Item = &Pool> {
        self.pools.iter().filter(|p| !p.is_default())
    }

    /// The pool a per-VM writable disk at `path` lives on: the non-default
    /// pool whose `overlay/` or `data/` directory holds it EXACTLY, else
    /// `default` — where every disk of the historical layout lives. An
    /// exact directory match (never a path prefix) cannot be fooled by a
    /// nested mount or by a legacy VM's boot disk in staging.
    pub fn pool_of(&self, path: &Path) -> &Pool {
        let Some(dir) = path.parent() else {
            return self.default_pool();
        };
        self.non_default()
            .find(|p| {
                dir == crate::lifecycle::golden::overlay_dir(&p.path)
                    || dir == crate::lifecycle::data_disk::data_dir(&p.path)
            })
            .unwrap_or_else(|| self.default_pool())
    }
}

/// What a check of the host found for one pool.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PoolCheck {
    pub state: PoolState,
    /// `""`, or the refusal code (design §9).
    pub error: &'static str,
}

/// One `stat` of a pool path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DirStat {
    pub dev: u64,
    pub uid: u32,
    pub mode: u32,
    pub is_dir: bool,
}

/// What the pool checks read from the host. A seam, so the checks run
/// against fixtures in tests.
pub trait PoolFs {
    /// The path with every symlink resolved, if it exists.
    fn canonical(&self, path: &Path) -> Option<PathBuf>;
    fn stat(&self, path: &Path) -> Option<DirStat>;
    /// The mount point and filesystem type of the mount holding `path`.
    fn mount_of(&self, path: &Path) -> Option<(PathBuf, String)>;
    /// Whether an aligned `O_DIRECT` write + fsync works in `path`.
    fn odirect_ok(&self, path: &Path) -> bool;
    /// `statvfs` size of the filesystem holding `path`, bytes.
    fn total_bytes(&self, path: &Path) -> Option<u64>;
}

/// Check every pool against the host (design §9's agent-side rules). Run
/// at startup and on every `v7` heartbeat, so a vanished mount shows up.
///
/// `default` is grandfathered: it is the historical data root, which may
/// legitimately sit on `/` with any ownership, so it is only required to
/// exist and not to share a filesystem with another pool.
///
/// `binding_errors` are the pools not on the filesystem they are bound to
/// ([`super::registry::PoolBindings::errors_now`]): `pool-fs-changed`,
/// `pool-unbound`.
pub fn check_pools(
    pools: &StoragePools,
    fs: &dyn PoolFs,
    binding_errors: &BTreeMap<String, &'static str>,
) -> BTreeMap<String, PoolCheck> {
    let root_dev = fs.stat(Path::new("/")).map(|s| s.dev);
    let mut errors: BTreeMap<String, &'static str> = BTreeMap::new();
    let mut devs: BTreeMap<u64, String> = BTreeMap::new();
    // `default` first: it is the historical root and always keeps its
    // filesystem; a newer pool sharing it is the one refused.
    let ordered = std::iter::once(pools.default_pool()).chain(pools.non_default());
    for pool in ordered {
        let error = match binding_errors.get(&pool.id) {
            Some(error) if !pool.is_default() => error,
            _ => check_one(pool, fs, root_dev, pools.is_configured()),
        };
        if error.is_empty() {
            if let Some(dev) = fs.stat(&pool.path).map(|s| s.dev) {
                // Two pools on one filesystem would sell the same space
                // twice: the later one (`default`, then by id) is refused.
                if devs.insert(dev, pool.id.clone()).is_some() {
                    errors.insert(pool.id.clone(), "pool-shared-fs");
                    continue;
                }
            }
        }
        errors.insert(pool.id.clone(), error);
    }
    pools
        .iter()
        .map(|pool| {
            let error = errors.get(&pool.id).copied().unwrap_or("");
            let state = if !error.is_empty() {
                PoolState::Unavailable
            } else if pool.draining {
                PoolState::Draining
            } else {
                PoolState::Active
            };
            (pool.id.clone(), PoolCheck { state, error })
        })
        .collect()
}

fn check_one(
    pool: &Pool,
    fs: &dyn PoolFs,
    root_dev: Option<u64>,
    configured: bool,
) -> &'static str {
    let Some(stat) = fs.stat(&pool.path) else {
        return "pool-path-missing";
    };
    if !stat.is_dir {
        return "pool-path-missing";
    }
    if pool.is_default() {
        // The implicit pool stays as it always was; a configured `default`
        // (budget `0` = no budget, as in `[host]`) must still cover what
        // its disks already hold.
        if configured && pool.budget_gb > 0 && pool.budget_gb < committed_gb(&pool.path) {
            return "pool-budget-below-committed";
        }
        return "";
    }
    if fs.canonical(&pool.path).as_deref() != Some(pool.path.as_path()) {
        return "pool-path-invalid";
    }
    if stat.uid != 0 || stat.mode & 0o022 != 0 {
        return "pool-path-perms";
    }
    let Some((mount_point, fstype)) = fs.mount_of(&pool.path) else {
        return "pool-not-a-mount";
    };
    if mount_point != pool.path {
        return "pool-not-a-mount";
    }
    if root_dev == Some(stat.dev) {
        return "pool-on-root-fs";
    }
    if !POOL_FSTYPES.contains(&fstype.as_str()) {
        return "pool-fstype-unsupported";
    }
    if !fs.odirect_ok(&pool.path) {
        return "pool-odirect-unsupported";
    }
    let Some(total) = fs.total_bytes(&pool.path) else {
        return "pool-path-missing";
    };
    let budget = pool.budget_gb.saturating_mul(1024 * 1024 * 1024);
    if budget > total.saturating_sub(pool_reserve_bytes(total)) {
        return "pool-budget-exceeds-fs";
    }
    // A budget shrunk below what the pool's disks already hold.
    if pool.budget_gb < committed_gb(&pool.path) {
        return "pool-budget-below-committed";
    }
    ""
}

/// The host's [`PoolFs`]: `stat`, `/proc/self/mountinfo`, `statvfs` and a
/// real `O_DIRECT` probe file.
#[derive(Debug, Clone)]
pub struct SystemPoolFs {
    pub mountinfo: PathBuf,
}

impl Default for SystemPoolFs {
    fn default() -> Self {
        Self {
            mountinfo: PathBuf::from("/proc/self/mountinfo"),
        }
    }
}

/// `(mount point, fstype)` of every line of a mountinfo file. Octal
/// escapes (`\040` for a space) in mount points are decoded.
pub fn parse_mountinfo(text: &str) -> Vec<(PathBuf, String)> {
    text.lines()
        .filter_map(|line| {
            let (left, right) = line.split_once(" - ")?;
            let mount_point = left.split(' ').nth(4)?;
            let fstype = right.split(' ').next()?;
            Some((
                PathBuf::from(unescape_octal(mount_point)),
                fstype.to_string(),
            ))
        })
        .collect()
}

/// `(mount point, root, mount source)` of every line of a mountinfo
/// file, in file order (a later line is a mount on top of an earlier
/// one). `root` is the directory of the filesystem mounted there (`/`, or
/// a bind mount's / subvolume's own path).
pub fn parse_mountinfo_sources(text: &str) -> Vec<(PathBuf, String, String)> {
    text.lines()
        .filter_map(|line| {
            let (left, right) = line.split_once(" - ")?;
            let mut fields = left.split(' ');
            let root = fields.nth(3)?;
            let mount_point = fields.next()?;
            let source = right.split(' ').nth(1)?;
            Some((
                PathBuf::from(unescape_octal(mount_point)),
                unescape_octal(root),
                unescape_octal(source),
            ))
        })
        .collect()
}

fn unescape_octal(raw: &str) -> String {
    let bytes = raw.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'\\'
            && i + 3 < bytes.len()
            && bytes[i + 1..i + 4]
                .iter()
                .all(|b| (b'0'..=b'7').contains(b))
        {
            let v = (bytes[i + 1] - b'0') * 64 + (bytes[i + 2] - b'0') * 8 + (bytes[i + 3] - b'0');
            out.push(v);
            i += 4;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

impl PoolFs for SystemPoolFs {
    fn canonical(&self, path: &Path) -> Option<PathBuf> {
        std::fs::canonicalize(path).ok()
    }

    fn stat(&self, path: &Path) -> Option<DirStat> {
        let meta = std::fs::metadata(path).ok()?;
        Some(DirStat {
            dev: meta.dev(),
            uid: meta.uid(),
            mode: meta.mode(),
            is_dir: meta.is_dir(),
        })
    }

    fn mount_of(&self, path: &Path) -> Option<(PathBuf, String)> {
        let text = std::fs::read_to_string(&self.mountinfo).ok()?;
        // The deepest mount point containing the path is the mount it is
        // on (a later, deeper mount shadows the ones above it).
        parse_mountinfo(&text)
            .into_iter()
            .filter(|(mount_point, _)| path.starts_with(mount_point))
            .max_by_key(|(mount_point, _)| mount_point.components().count())
    }

    fn odirect_ok(&self, path: &Path) -> bool {
        odirect_probe(path).is_ok()
    }

    fn total_bytes(&self, path: &Path) -> Option<u64> {
        crate::lifecycle::disk_space::fs_bytes(path).map(|(total, _)| total)
    }
}

/// Create, write 4 KiB with `O_DIRECT`, fsync and unlink a probe file in
/// `dir`.
fn odirect_probe(dir: &Path) -> std::io::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    const BLOCK: usize = 4096;
    // Unique per probe: the heartbeat and a `storage-config` validation
    // may probe the same pool at once.
    static PROBES: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let n = PROBES.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let probe = dir.join(format!(".hippius-odirect-probe-{}-{n}", std::process::id()));
    let result = (|| {
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .custom_flags(nix::libc::O_DIRECT)
            .open(&probe)?;
        // O_DIRECT wants a block-aligned buffer: take the aligned block
        // inside a buffer twice its size.
        let backing = vec![0u8; 2 * BLOCK];
        let offset = backing.as_ptr().align_offset(BLOCK);
        let block = backing
            .get(offset..offset + BLOCK)
            .ok_or_else(|| std::io::Error::other("align"))?;
        file.write_all(block)?;
        file.sync_all()
    })();
    let _ = std::fs::remove_file(&probe);
    result
}

/// GiB the per-VM writable disks on `pool` are promised: Σ apparent size
/// of the `*.img` files in its `overlay/` and `data/` directories, rounded
/// up. What the agent has committed there, read from the files themselves
/// (so a re-adopted VM is counted like a fresh one).
pub fn committed_gb(pool_path: &Path) -> u64 {
    let mut bytes: u64 = 0;
    for dir in [
        crate::lifecycle::data_disk::data_dir(pool_path),
        crate::lifecycle::golden::overlay_dir(pool_path),
    ] {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            if entry.path().extension().is_none_or(|ext| ext != "img") {
                continue;
            }
            if let Ok(meta) = entry.metadata() {
                if meta.is_file() {
                    bytes = bytes.saturating_add(meta.len());
                }
            }
        }
    }
    bytes.div_ceil(1024 * 1024 * 1024)
}

/// Whether `pool_path` holds any per-VM writable disk (`overlay/*.img`,
/// `data/*.img`). `None` when a directory exists but cannot be listed.
pub fn holds_vm_disks(pool_path: &Path) -> Option<bool> {
    for dir in [
        crate::lifecycle::data_disk::data_dir(pool_path),
        crate::lifecycle::golden::overlay_dir(pool_path),
    ] {
        let entries = match std::fs::read_dir(&dir) {
            Ok(entries) => entries,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(_) => return None,
        };
        for entry in entries {
            let Ok(entry) = entry else { return None };
            if entry.path().extension().is_some_and(|ext| ext == "img") {
                return Some(true);
            }
        }
    }
    Some(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::StoragePoolConfig;
    use std::collections::HashMap;

    fn pool_cfg(id: &str, path: &str) -> StoragePoolConfig {
        StoragePoolConfig {
            id: id.into(),
            path: path.into(),
            class: PoolClassConfig::Nvme,
            budget_gb: 100,
            os_disks: true,
            state: StorageDesiredStateConfig::Active,
        }
    }

    fn section(pools: Vec<StoragePoolConfig>) -> StorageSection {
        StorageSection {
            data_disk_root: "/var/lib/hippius-miner".into(),
            state_disk_root: "/var/lib/hippius-miner".into(),
            pools,
            dedicated_disks: Vec::new(),
        }
    }

    #[test]
    fn no_config_is_one_implicit_default_pool() {
        let pools = StoragePools::from_config(&section(Vec::new()), 3000);
        assert!(!pools.is_configured());
        let all: Vec<_> = pools.iter().collect();
        assert_eq!(all.len(), 1);
        let d = pools.default_pool();
        assert_eq!(d.id, "default");
        assert_eq!(d.path, PathBuf::from("/var/lib/hippius-miner"));
        assert_eq!(d.budget_gb, 3000);
        assert_eq!(d.class, PoolClass::Undeclared);
        assert_eq!(d.insufficient_class(), "insufficient-disk");
        assert_eq!(pools.non_default().count(), 0);
        assert_eq!(pools.launch_pool().id, "default");
    }

    #[test]
    fn configured_pools_are_sorted_and_classed() {
        let mut hdd = pool_cfg("hdd0", "/srv/hdd0");
        hdd.class = PoolClassConfig::Hdd;
        hdd.os_disks = false;
        hdd.state = StorageDesiredStateConfig::Draining;
        let pools = StoragePools::from_config(
            &section(vec![hdd, pool_cfg("default", "/var/lib/hippius-miner")]),
            100,
        );
        assert!(pools.is_configured());
        let ids: Vec<_> = pools.iter().map(|p| p.id.as_str()).collect();
        assert_eq!(ids, ["default", "hdd0"]);
        let hdd = pools.get("hdd0").unwrap();
        assert_eq!(hdd.class, PoolClass::Hdd);
        assert!(hdd.draining && !hdd.os_disks);
        assert_eq!(hdd.insufficient_class(), "insufficient-disk:hdd0");
        assert_eq!(
            pools.default_pool().insufficient_class(),
            "insufficient-disk"
        );
        assert_eq!(pools.launch_pool().id, "default");
    }

    #[test]
    fn a_path_belongs_to_the_pool_containing_it_else_default() {
        let pools = StoragePools::from_config(
            &section(vec![
                pool_cfg("default", "/var/lib/hippius-miner"),
                pool_cfg("hdd0", "/srv/hdd0"),
            ]),
            100,
        );
        assert_eq!(
            pools.pool_of(Path::new("/srv/hdd0/overlay/vm.img")).id,
            "hdd0"
        );
        assert_eq!(
            pools
                .pool_of(Path::new("/var/lib/hippius-miner/overlay/vm.img"))
                .id,
            "default"
        );
        // A sibling path that merely shares a prefix string is not inside.
        assert_eq!(
            pools.pool_of(Path::new("/srv/hdd00/overlay/vm.img")).id,
            "default"
        );
        assert_eq!(pools.pool_of(Path::new("/srv/hdd0/data/vm.img")).id, "hdd0");
        // Something else under the pool (a nested mount, a staged boot
        // disk) is not that pool's VM disk.
        assert_eq!(
            pools
                .pool_of(Path::new("/srv/hdd0/nested/overlay/vm.img"))
                .id,
            "default"
        );
        assert_eq!(
            pools.pool_of(Path::new("/srv/hdd0/staging/vm/disk")).id,
            "default"
        );
        assert_eq!(pools.pool_of(Path::new("")).id, "default");
    }

    /// A scripted host.
    #[derive(Default)]
    struct FakeFs {
        stats: HashMap<PathBuf, DirStat>,
        canon: HashMap<PathBuf, PathBuf>,
        mounts: HashMap<PathBuf, (PathBuf, String)>,
        no_odirect: Vec<PathBuf>,
        totals: HashMap<PathBuf, u64>,
    }

    const GIB: u64 = 1024 * 1024 * 1024;

    impl FakeFs {
        fn good_pool(&mut self, path: &str, dev: u64) {
            let p = PathBuf::from(path);
            self.stats.insert(
                p.clone(),
                DirStat {
                    dev,
                    uid: 0,
                    mode: 0o040755,
                    is_dir: true,
                },
            );
            self.canon.insert(p.clone(), p.clone());
            self.mounts.insert(p.clone(), (p.clone(), "xfs".into()));
            self.totals.insert(p, 10_000 * GIB);
        }
    }

    impl PoolFs for FakeFs {
        fn canonical(&self, path: &Path) -> Option<PathBuf> {
            self.canon.get(path).cloned()
        }
        fn stat(&self, path: &Path) -> Option<DirStat> {
            self.stats.get(path).copied()
        }
        fn mount_of(&self, path: &Path) -> Option<(PathBuf, String)> {
            self.mounts.get(path).cloned()
        }
        fn odirect_ok(&self, path: &Path) -> bool {
            !self.no_odirect.iter().any(|p| p == path)
        }
        fn total_bytes(&self, path: &Path) -> Option<u64> {
            self.totals.get(path).copied()
        }
    }

    fn two_pools() -> StoragePools {
        StoragePools::from_config(
            &section(vec![
                pool_cfg("default", "/var/lib/hippius-miner"),
                pool_cfg("hdd0", "/srv/hdd0"),
            ]),
            100,
        )
    }

    fn host() -> FakeFs {
        let mut fs = FakeFs::default();
        fs.good_pool("/", 1);
        fs.stats.insert(
            "/var/lib/hippius-miner".into(),
            DirStat {
                dev: 1,
                uid: 0,
                mode: 0o040755,
                is_dir: true,
            },
        );
        fs.good_pool("/srv/hdd0", 2);
        fs
    }

    fn error_of(fs: &FakeFs, id: &str) -> &'static str {
        check_pools(&two_pools(), fs, &Default::default())[id].error
    }

    #[test]
    fn a_good_host_is_active_and_default_may_sit_on_root() {
        let checks = check_pools(&two_pools(), &host(), &Default::default());
        assert_eq!(
            checks["default"],
            PoolCheck {
                state: PoolState::Active,
                error: ""
            }
        );
        assert_eq!(
            checks["hdd0"],
            PoolCheck {
                state: PoolState::Active,
                error: ""
            }
        );
    }

    #[test]
    fn a_draining_pool_reports_draining() {
        let mut cfg = pool_cfg("hdd0", "/srv/hdd0");
        cfg.state = StorageDesiredStateConfig::Draining;
        let pools = StoragePools::from_config(
            &section(vec![pool_cfg("default", "/var/lib/hippius-miner"), cfg]),
            100,
        );
        assert_eq!(
            check_pools(&pools, &host(), &Default::default())["hdd0"].state,
            PoolState::Draining
        );
    }

    #[test]
    fn each_rule_has_its_code() {
        let p = PathBuf::from("/srv/hdd0");
        let mut fs = host();
        fs.stats.remove(&p);
        assert_eq!(error_of(&fs, "hdd0"), "pool-path-missing");

        let mut fs = host();
        fs.canon.insert(p.clone(), "/mnt/elsewhere".into());
        assert_eq!(error_of(&fs, "hdd0"), "pool-path-invalid");

        let mut fs = host();
        fs.stats.get_mut(&p).unwrap().mode = 0o040777;
        assert_eq!(error_of(&fs, "hdd0"), "pool-path-perms");
        let mut fs = host();
        fs.stats.get_mut(&p).unwrap().uid = 1000;
        assert_eq!(error_of(&fs, "hdd0"), "pool-path-perms");

        let mut fs = host();
        fs.mounts.insert(p.clone(), ("/srv".into(), "xfs".into()));
        assert_eq!(error_of(&fs, "hdd0"), "pool-not-a-mount");
        let mut fs = host();
        fs.mounts.remove(&p);
        assert_eq!(error_of(&fs, "hdd0"), "pool-not-a-mount");

        let mut fs = host();
        fs.stats.get_mut(&p).unwrap().dev = 1;
        assert_eq!(error_of(&fs, "hdd0"), "pool-on-root-fs");

        let mut fs = host();
        fs.mounts.insert(p.clone(), (p.clone(), "tmpfs".into()));
        assert_eq!(error_of(&fs, "hdd0"), "pool-fstype-unsupported");

        let mut fs = host();
        fs.no_odirect.push(p.clone());
        assert_eq!(error_of(&fs, "hdd0"), "pool-odirect-unsupported");

        let mut fs = host();
        // 100 GiB budget on a 110 GiB filesystem leaves less than 20 GiB.
        fs.totals.insert(p.clone(), 110 * GIB);
        assert_eq!(error_of(&fs, "hdd0"), "pool-budget-exceeds-fs");
        fs.totals.insert(p, 120 * GIB);
        assert_eq!(error_of(&fs, "hdd0"), "");
    }

    #[test]
    fn a_budget_below_what_the_pool_holds_is_refused() {
        let hdd = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(hdd.path().join("overlay")).unwrap();
        std::fs::File::create(hdd.path().join("overlay/vm.img"))
            .unwrap()
            .set_len(150 * GIB)
            .unwrap();
        let path = hdd.path().to_str().unwrap();
        let pools = StoragePools::from_config(
            &section(vec![
                pool_cfg("default", "/var/lib/hippius-miner"),
                pool_cfg("hdd0", path),
            ]),
            100,
        );
        let mut fs = host();
        fs.good_pool(path, 3);
        // budget 100 GiB, 150 GiB held.
        assert_eq!(
            check_pools(&pools, &fs, &Default::default())["hdd0"].error,
            "pool-budget-below-committed"
        );
    }

    #[test]
    fn a_configured_default_budget_below_what_it_holds_is_refused() {
        let root = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(root.path().join("overlay")).unwrap();
        std::fs::File::create(root.path().join("overlay/vm.img"))
            .unwrap()
            .set_len(150 * GIB)
            .unwrap();
        let path = root.path().to_str().unwrap();
        let mut fs = host();
        fs.good_pool(path, 3);
        let configured = |budget_gb: u64| {
            let mut default = pool_cfg("default", path);
            default.budget_gb = budget_gb;
            let mut section = section(vec![default]);
            section.data_disk_root = path.into();
            StoragePools::from_config(&section, budget_gb)
        };
        // budget 100 GiB, 150 GiB held.
        assert_eq!(
            check_pools(&configured(100), &fs, &Default::default())["default"].error,
            "pool-budget-below-committed"
        );
        // `0` is no budget, as in `[host]`.
        assert_eq!(
            check_pools(&configured(0), &fs, &Default::default())["default"].error,
            ""
        );
        // The implicit pool is untouched, whatever it holds.
        let implicit = StoragePools::implicit(path.into(), 100);
        assert_eq!(
            check_pools(&implicit, &fs, &Default::default())["default"].error,
            ""
        );
    }

    #[test]
    fn an_unavailable_pool_is_unavailable_whatever_its_desired_state() {
        let mut fs = host();
        fs.stats.remove(Path::new("/srv/hdd0"));
        let check = check_pools(&two_pools(), &fs, &Default::default())["hdd0"];
        assert_eq!(check.state, PoolState::Unavailable);
    }

    #[test]
    fn two_pools_on_one_filesystem_refuse_the_later_one() {
        let mut fs = host();
        // hdd0 on the same device as default.
        fs.stats
            .get_mut(Path::new("/var/lib/hippius-miner"))
            .unwrap()
            .dev = 2;
        let checks = check_pools(&two_pools(), &fs, &Default::default());
        assert_eq!(checks["default"].error, "");
        assert_eq!(checks["hdd0"].error, "pool-shared-fs");
    }

    #[test]
    fn a_pool_sorting_before_default_never_takes_its_filesystem() {
        let pools = StoragePools::from_config(
            &section(vec![
                pool_cfg("default", "/var/lib/hippius-miner"),
                pool_cfg("a", "/srv/hdd0"),
            ]),
            100,
        );
        let mut fs = host();
        fs.stats
            .get_mut(Path::new("/var/lib/hippius-miner"))
            .unwrap()
            .dev = 2;
        let checks = check_pools(&pools, &fs, &Default::default());
        assert_eq!(checks["default"].error, "");
        assert_eq!(checks["a"].error, "pool-shared-fs");
    }

    #[test]
    fn a_pool_off_its_bound_filesystem_is_unavailable() {
        let changed = [
            ("hdd0".to_string(), "pool-fs-changed"),
            ("default".to_string(), "pool-fs-changed"),
        ]
        .into();
        let checks = check_pools(&two_pools(), &host(), &changed);
        assert_eq!(checks["hdd0"].state, PoolState::Unavailable);
        assert_eq!(checks["hdd0"].error, "pool-fs-changed");
        // `default` is exempt, as it always was.
        assert_eq!(checks["default"].error, "");
    }

    #[test]
    fn default_only_needs_to_exist() {
        let mut fs = host();
        fs.stats.remove(Path::new("/var/lib/hippius-miner"));
        assert_eq!(error_of(&fs, "default"), "pool-path-missing");
    }

    #[test]
    fn mountinfo_is_parsed_with_escapes() {
        let text = "\
22 1 8:2 / / rw,relatime shared:1 - ext4 /dev/sda2 rw
40 22 259:1 / /srv/hdd0 rw,relatime shared:2 - xfs /dev/nvme0n1 rw
41 22 0:50 / /mnt/with\\040space rw - tmpfs tmpfs rw
";
        let mounts = parse_mountinfo(text);
        assert_eq!(mounts[0], (PathBuf::from("/"), "ext4".to_string()));
        assert_eq!(mounts[1], (PathBuf::from("/srv/hdd0"), "xfs".to_string()));
        assert_eq!(
            mounts[2],
            (PathBuf::from("/mnt/with space"), "tmpfs".to_string())
        );
    }

    #[test]
    fn the_deepest_mount_holds_a_path() {
        let dir = tempfile::tempdir().unwrap();
        let mi = dir.path().join("mountinfo");
        std::fs::write(
            &mi,
            "22 1 8:2 / / rw - ext4 /dev/sda2 rw\n40 22 259:1 / /srv/hdd0 rw - xfs /dev/x rw\n",
        )
        .unwrap();
        let fs = SystemPoolFs { mountinfo: mi };
        assert_eq!(
            fs.mount_of(Path::new("/srv/hdd0")),
            Some((PathBuf::from("/srv/hdd0"), "xfs".to_string()))
        );
        assert_eq!(
            fs.mount_of(Path::new("/srv/hdd0/overlay")),
            Some((PathBuf::from("/srv/hdd0"), "xfs".to_string()))
        );
        assert_eq!(
            fs.mount_of(Path::new("/var/lib")),
            Some((PathBuf::from("/"), "ext4".to_string()))
        );
    }

    #[test]
    fn committed_and_holds_read_the_disk_files() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        assert_eq!(committed_gb(root), 0);
        assert_eq!(holds_vm_disks(root), Some(false));
        std::fs::create_dir_all(root.join("overlay")).unwrap();
        std::fs::create_dir_all(root.join("data")).unwrap();
        // Sparse: apparent size is what is promised.
        std::fs::File::create(root.join("overlay/a.img"))
            .unwrap()
            .set_len(10 * GIB)
            .unwrap();
        std::fs::File::create(root.join("data/b.img"))
            .unwrap()
            .set_len(GIB + 1)
            .unwrap();
        // Not disks: a part file and a retained original.
        std::fs::File::create(root.join("overlay/c.img.part"))
            .unwrap()
            .set_len(50 * GIB)
            .unwrap();
        assert_eq!(committed_gb(root), 12);
        assert_eq!(holds_vm_disks(root), Some(true));
    }

    #[test]
    fn the_reserve_is_five_percent_or_20_gib() {
        assert_eq!(pool_reserve_bytes(100 * GIB), 20 * GIB);
        assert_eq!(pool_reserve_bytes(1000 * GIB), 50 * GIB);
    }
}
