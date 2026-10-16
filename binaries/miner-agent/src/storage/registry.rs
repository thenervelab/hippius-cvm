//! The removed-pool guard (design §9, "live-disk safety").
//!
//! A pool dropped from `[[storage.pools]]` (or moved to another path)
//! while VM disks still sit on it would orphan them silently: no reclaim,
//! no accounting, no report. So the agent remembers the pools it last ran
//! with — each one's path AND the filesystem mounted there
//! ([`fs_identity`]: the filesystem UUID, else `st_dev`) — in
//! `<state_disk_root>/storage-pools.json`, and:
//!
//! - refuses to start when a remembered pool is gone from the config (or
//!   moved) unless its old path is still the same filesystem and holds no
//!   per-VM disk. A path that is gone, unreadable, or now another
//!   filesystem (an unmounted pool leaves an empty mount point) cannot be
//!   proven empty, so it is refused;
//! - reports a kept pool now on another filesystem as `pool-fs-changed`
//!   (unavailable) and keeps the old record, whether or not the new
//!   filesystem is empty: the disks may be on the one that is gone. The
//!   check runs at startup and on every `v7` heartbeat
//!   ([`PoolBindings::errors_now`]), so a remount under a running agent
//!   shows up too, and a remount of the right one clears it. Adopting a new filesystem is an operator act: delete
//!   the pool's entry from the file and restart.
//!
//! The way out of a refusal is to put the pool back (as `draining`), empty
//! it, then remove it. `default` is the historical data root and is exempt
//! from the filesystem check, as it always was.
//!
//! With no `[[storage.pools]]` and no file from an earlier run, nothing is
//! read or written: the single-root agent is untouched.
//!
//! The file lives under `state_disk_root`: moving that root (which already
//! strands every VM's boot-counter disk) in the same change as dropping a
//! pool is not caught.

use std::collections::BTreeMap;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::error::{MinerAgentError, Result};

use super::pools::{holds_vm_disks, StoragePools};

/// File name under `state_disk_root`.
pub const REGISTRY_FILE: &str = "storage-pools.json";

/// One remembered pool.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Entry {
    path: PathBuf,
    /// [`fs_identity`] of the path when it was recorded.
    fs: String,
}

#[derive(Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Registry {
    pools: BTreeMap<String, Entry>,
}

pub fn registry_path(state_root: &Path) -> PathBuf {
    state_root.join(REGISTRY_FILE)
}

/// Where [`fs_identity`] reads the host.
#[derive(Debug, Clone)]
pub struct FsIdentitySource {
    pub mountinfo: PathBuf,
    pub by_uuid: PathBuf,
}

impl Default for FsIdentitySource {
    fn default() -> Self {
        Self {
            mountinfo: PathBuf::from("/proc/self/mountinfo"),
            by_uuid: PathBuf::from("/dev/disk/by-uuid"),
        }
    }
}

/// The filesystem mounted on `path`, and which directory of it:
/// `uuid:<UUID>:<root>` when its source device has a `/dev/disk/by-uuid`
/// link (stable across reboots, unlike device numbers), else
/// `dev:<st_dev>:<root>`. `root` is mountinfo's (`/` for a whole
/// filesystem; a bind mount or subvolume names its own directory, so
/// swapping one for another on the same filesystem is a change too).
/// `None` when `path` is not a mount point (an unmounted pool's bare
/// mount point is the parent's filesystem, never the pool's) or cannot be
/// stat'ed.
pub fn fs_identity(src: &FsIdentitySource, path: &Path) -> Option<String> {
    let dev = std::fs::metadata(path).ok()?.dev();
    let text = std::fs::read_to_string(&src.mountinfo).ok()?;
    // The last mount on `path` is the one visible there.
    let (_, root, source) = super::pools::parse_mountinfo_sources(&text)
        .into_iter()
        .rev()
        .find(|(mount_point, _, _)| mount_point == path)?;
    Some(match uuid_of(src, &source) {
        Some(uuid) => format!("uuid:{uuid}:{root}"),
        None => format!("dev:{dev}:{root}"),
    })
}

/// What a pool is recorded against: [`fs_identity`], except that
/// `default` (the historical data root, often not a mount of its own)
/// falls back to the device number.
fn identity_of(src: &FsIdentitySource, id: &str, path: &Path) -> Option<String> {
    if id != super::DEFAULT_POOL_ID {
        return fs_identity(src, path);
    }
    fs_identity(src, path).or_else(|| {
        std::fs::metadata(path)
            .ok()
            .map(|m| format!("dev:{}", m.dev()))
    })
}

fn uuid_of(src: &FsIdentitySource, source: &str) -> Option<String> {
    if !source.starts_with('/') {
        return None;
    }
    let device = std::fs::canonicalize(source).ok()?;
    std::fs::read_dir(&src.by_uuid)
        .ok()?
        .flatten()
        .find(|link| std::fs::canonicalize(link.path()).ok().as_deref() == Some(device.as_path()))
        .and_then(|link| link.file_name().into_string().ok())
}

/// The filesystem each non-default pool is bound to, as [`enforce`]
/// recorded it.
#[derive(Debug, Clone, Default)]
pub struct PoolBindings {
    recorded: BTreeMap<String, String>,
}

impl PoolBindings {
    /// The pools not on their bound filesystem right now:
    /// `pool-fs-changed` on another one (a remount back clears it),
    /// `pool-unbound` for a pool not mounted at startup and mounted since
    /// (a restart binds it). A pool not mounted now is left to the pool
    /// check (`pool-path-missing`, `pool-not-a-mount`).
    pub fn errors_now(
        &self,
        pools: &StoragePools,
        src: &FsIdentitySource,
    ) -> BTreeMap<String, &'static str> {
        pools
            .non_default()
            .filter_map(|pool| {
                let now = fs_identity(src, &pool.path)?;
                let error = match self.recorded.get(&pool.id) {
                    Some(recorded) if *recorded == now => return None,
                    Some(_) => "pool-fs-changed",
                    None => "pool-unbound",
                };
                Some((pool.id.clone(), error))
            })
            .collect()
    }

    /// The filesystem pool `id` is bound to, if any.
    pub fn recorded(&self, id: &str) -> Option<&str> {
        self.recorded.get(id).map(String::as_str)
    }

    /// Whether pool `id` at `path` is on the filesystem it is bound to
    /// right now: what a missing file there proves anything about.
    pub fn is_bound(&self, id: &str, path: &Path, src: &FsIdentitySource) -> bool {
        self.recorded
            .get(id)
            .is_some_and(|recorded| fs_identity(src, path).as_deref() == Some(recorded.as_str()))
    }
}

/// Refuse a pool set that would abandon VM disks, then record it.
///
/// `Err(ConfigInvalid("storage.pools-removed-pool-holds-disks"))` names a
/// remembered pool, absent or moved now, that cannot be proven empty (the
/// id is logged: it is the operator's own config, never tenant data).
///
/// `Ok` carries the bindings the pool checks hold each pool to
/// ([`PoolBindings::errors_now`]).
pub fn enforce(state_root: &Path, pools: &StoragePools) -> Result<PoolBindings> {
    enforce_with(state_root, pools, &FsIdentitySource::default())
}

pub fn enforce_with(
    state_root: &Path,
    pools: &StoragePools,
    src: &FsIdentitySource,
) -> Result<PoolBindings> {
    let plan = plan_with(state_root, pools, src)?;
    plan.commit()?;
    Ok(plan.bindings)
}

/// [`enforce_with`]'s verdict and the record it would write, not yet
/// written: the `storage-config` route judges a document with it, then
/// persists the document, then commits the record (a record naming an
/// unapplied document could refuse the next start).
#[derive(Debug)]
pub struct RegistryPlan {
    /// The record to write, `None` when the file already says it.
    write: Option<(PathBuf, Registry)>,
    pub bindings: PoolBindings,
}

impl RegistryPlan {
    /// Write the record (atomic, fsynced).
    pub fn commit(&self) -> Result<()> {
        match &self.write {
            Some((path, registry)) => write_atomic(path, registry),
            None => Ok(()),
        }
    }
}

/// Judge `pools` against the record as [`enforce_with`] does, writing
/// nothing.
pub fn plan_with(
    state_root: &Path,
    pools: &StoragePools,
    src: &FsIdentitySource,
) -> Result<RegistryPlan> {
    let path = registry_path(state_root);
    let previous: Option<Registry> = match std::fs::read(&path) {
        Ok(bytes) => Some(
            serde_json::from_slice(&bytes)
                .map_err(|_| MinerAgentError::ConfigInvalid("storage.pools-registry-unreadable"))?,
        ),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
        Err(_) => {
            return Err(MinerAgentError::ConfigInvalid(
                "storage.pools-registry-unreadable",
            ))
        }
    };
    let mut keep_old: BTreeMap<String, Entry> = BTreeMap::new();
    if let Some(previous) = &previous {
        for (id, old) in &previous.pools {
            let now_fs = identity_of(src, id, &old.path);
            let kept = pools.get(id).is_some_and(|p| p.path == old.path);
            if kept {
                let is_default = id == super::DEFAULT_POOL_ID;
                if now_fs.is_none() {
                    // Unmounted / gone right now: the pool check reports it;
                    // remember it as it was.
                    keep_old.insert(id.clone(), old.clone());
                } else if !is_default && now_fs.as_deref() != Some(old.fs.as_str()) {
                    // Empty or not, the new filesystem cannot vouch for the
                    // old one's disks.
                    eprintln!(
                        "hippius-miner-agent: storage: pool {id:?} is on a different \
                         filesystem than the one recorded; reported unavailable until its \
                         entry is removed from {REGISTRY_FILE}"
                    );
                    keep_old.insert(id.clone(), old.clone());
                }
                continue;
            }
            if !old.path.is_dir()
                || now_fs.as_deref() != Some(old.fs.as_str())
                || holds_vm_disks(&old.path) != Some(false)
            {
                eprintln!(
                    "hippius-miner-agent: storage: pool {id:?} was removed or moved but its \
                     old path still holds VM disks (or cannot be proven empty); put it back \
                     as `draining` until it is empty"
                );
                return Err(MinerAgentError::ConfigInvalid(
                    "storage.pools-removed-pool-holds-disks",
                ));
            }
        }
    }
    if !pools.is_configured() && previous.is_none() {
        return Ok(RegistryPlan {
            write: None,
            bindings: PoolBindings::default(),
        });
    }
    let current = Registry {
        pools: pools
            .iter()
            .filter_map(|p| {
                if let Some(old) = keep_old.get(&p.id) {
                    return Some((p.id.clone(), old.clone()));
                }
                // A pool not mounted right now is recorded once it is.
                identity_of(src, &p.id, &p.path).map(|fs| {
                    (
                        p.id.clone(),
                        Entry {
                            path: p.path.clone(),
                            fs,
                        },
                    )
                })
            })
            .collect(),
    };
    let recorded = current
        .pools
        .iter()
        .filter(|(id, _)| id.as_str() != super::DEFAULT_POOL_ID)
        .map(|(id, entry)| (id.clone(), entry.fs.clone()))
        .collect();
    let write = (previous.as_ref() != Some(&current)).then_some((path, current));
    Ok(RegistryPlan {
        write,
        bindings: PoolBindings { recorded },
    })
}

fn write_atomic(path: &Path, registry: &Registry) -> Result<()> {
    use std::io::Write;
    let fail = |_| MinerAgentError::ConfigInvalid("storage.pools-registry-unwritable");
    let dir = path.parent().ok_or(MinerAgentError::ConfigInvalid(
        "storage.pools-registry-unwritable",
    ))?;
    std::fs::create_dir_all(dir).map_err(fail)?;
    let mut tmp = tempfile::NamedTempFile::new_in(dir).map_err(fail)?;
    let bytes = serde_json::to_vec_pretty(registry)
        .map_err(|_| MinerAgentError::ConfigInvalid("storage.pools-registry-unwritable"))?;
    tmp.write_all(&bytes).map_err(fail)?;
    tmp.as_file().sync_all().map_err(fail)?;
    tmp.persist(path)
        .map_err(|_| MinerAgentError::ConfigInvalid("storage.pools-registry-unwritable"))?;
    if let Ok(d) = std::fs::File::open(dir) {
        let _ = d.sync_all();
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{
        PoolClassConfig, StorageDesiredStateConfig, StoragePoolConfig, StorageSection,
    };

    fn pools(data_root: &Path, extra: &[(&str, &Path)]) -> StoragePools {
        let mut cfg = vec![StoragePoolConfig {
            id: "default".into(),
            path: data_root.to_path_buf(),
            class: PoolClassConfig::Nvme,
            budget_gb: 0,
            os_disks: true,
            state: StorageDesiredStateConfig::Active,
        }];
        for (id, path) in extra {
            cfg.push(StoragePoolConfig {
                id: (*id).into(),
                path: path.to_path_buf(),
                class: PoolClassConfig::Hdd,
                budget_gb: 0,
                os_disks: false,
                state: StorageDesiredStateConfig::Active,
            });
        }
        StoragePools::from_config(
            &StorageSection {
                data_disk_root: data_root.to_path_buf(),
                state_disk_root: data_root.to_path_buf(),
                pools: cfg,
                dedicated_disks: Vec::new(),
            },
            0,
        )
    }

    /// A scripted mount table: the listed paths are mount points (of a
    /// source with no by-uuid link, so identified by `st_dev`).
    struct Mounts {
        dir: tempfile::TempDir,
        src: FsIdentitySource,
    }

    impl Mounts {
        fn new(paths: &[&Path]) -> Self {
            let dir = tempfile::tempdir().unwrap();
            let src = FsIdentitySource {
                mountinfo: dir.path().join("mountinfo"),
                by_uuid: dir.path().join("by-uuid"),
            };
            let m = Self { dir, src };
            m.set(paths);
            m
        }

        fn set(&self, paths: &[&Path]) {
            let text: String = paths
                .iter()
                .map(|p| format!("36 1 8:17 / {} rw - xfs tmpfs rw\n", p.display()))
                .collect();
            std::fs::write(self.dir.path().join("mountinfo"), text).unwrap();
        }
    }

    fn enforce_on(state: &Path, set: &StoragePools, m: &Mounts) -> Result<PoolBindings> {
        enforce_with(state, set, &m.src)
    }

    fn flagged(
        bindings: &PoolBindings,
        set: &StoragePools,
        m: &Mounts,
    ) -> Vec<(String, &'static str)> {
        bindings.errors_now(set, &m.src).into_iter().collect()
    }

    fn read(state: &Path) -> Registry {
        serde_json::from_str(&std::fs::read_to_string(registry_path(state)).unwrap()).unwrap()
    }

    fn write(state: &Path, reg: &Registry) {
        std::fs::write(registry_path(state), serde_json::to_vec(reg).unwrap()).unwrap();
    }

    fn put_disk(pool_path: &Path) {
        std::fs::create_dir_all(pool_path.join("overlay")).unwrap();
        std::fs::write(pool_path.join("overlay/vm-1.img"), b"x").unwrap();
    }

    #[test]
    fn the_single_root_agent_reads_and_writes_nothing() {
        let state = tempfile::tempdir().unwrap();
        let implicit = StoragePools::implicit(state.path().to_path_buf(), 0);
        enforce(state.path(), &implicit).unwrap();
        assert!(!registry_path(state.path()).exists());
    }

    #[test]
    fn a_configured_set_is_recorded() {
        let state = tempfile::tempdir().unwrap();
        let hdd = tempfile::tempdir().unwrap();
        let m = Mounts::new(&[hdd.path()]);
        let set = pools(state.path(), &[("hdd0", hdd.path())]);
        enforce_on(state.path(), &set, &m).unwrap();
        let reg = read(state.path());
        // `default` need not be a mount of its own.
        assert!(reg.pools["default"].fs.starts_with("dev:"));
        assert!(reg.pools["hdd0"].fs.starts_with("dev:"));
    }

    #[test]
    fn removing_a_pool_that_holds_disks_refuses_to_start() {
        let state = tempfile::tempdir().unwrap();
        let hdd = tempfile::tempdir().unwrap();
        let m = Mounts::new(&[hdd.path()]);
        enforce_on(
            state.path(),
            &pools(state.path(), &[("hdd0", hdd.path())]),
            &m,
        )
        .unwrap();
        put_disk(hdd.path());
        let err = enforce_on(state.path(), &pools(state.path(), &[]), &m).unwrap_err();
        assert!(matches!(
            err,
            MinerAgentError::ConfigInvalid("storage.pools-removed-pool-holds-disks")
        ));
        // …also when the config drops `[[storage.pools]]` altogether.
        let implicit = StoragePools::implicit(state.path().to_path_buf(), 0);
        assert!(enforce_on(state.path(), &implicit, &m).is_err());
        // The record is untouched by a refused start.
        assert!(read(state.path()).pools.contains_key("hdd0"));
    }

    #[test]
    fn moving_a_pool_that_holds_disks_refuses_to_start() {
        let state = tempfile::tempdir().unwrap();
        let hdd = tempfile::tempdir().unwrap();
        let elsewhere = tempfile::tempdir().unwrap();
        let m = Mounts::new(&[hdd.path(), elsewhere.path()]);
        enforce_on(
            state.path(),
            &pools(state.path(), &[("hdd0", hdd.path())]),
            &m,
        )
        .unwrap();
        put_disk(hdd.path());
        let moved = pools(state.path(), &[("hdd0", elsewhere.path())]);
        assert!(enforce_on(state.path(), &moved, &m).is_err());
    }

    #[test]
    fn removing_an_empty_pool_is_allowed_and_recorded() {
        let state = tempfile::tempdir().unwrap();
        let hdd = tempfile::tempdir().unwrap();
        let m = Mounts::new(&[hdd.path()]);
        enforce_on(
            state.path(),
            &pools(state.path(), &[("hdd0", hdd.path())]),
            &m,
        )
        .unwrap();
        enforce_on(state.path(), &pools(state.path(), &[]), &m).unwrap();
        assert!(!read(state.path()).pools.contains_key("hdd0"));
    }

    #[test]
    fn a_vanished_path_cannot_prove_it_is_empty() {
        let state = tempfile::tempdir().unwrap();
        let hdd = tempfile::tempdir().unwrap();
        let hdd_path = hdd.path().to_path_buf();
        let m = Mounts::new(&[&hdd_path]);
        enforce_on(
            state.path(),
            &pools(state.path(), &[("hdd0", &hdd_path)]),
            &m,
        )
        .unwrap();
        drop(hdd);
        assert!(enforce_on(state.path(), &pools(state.path(), &[]), &m).is_err());
    }

    #[test]
    fn a_corrupt_registry_refuses_to_start() {
        let state = tempfile::tempdir().unwrap();
        std::fs::write(registry_path(state.path()), b"{not json").unwrap();
        let implicit = StoragePools::implicit(state.path().to_path_buf(), 0);
        assert!(enforce(state.path(), &implicit).is_err());
    }

    #[test]
    fn an_unmounted_removed_pool_cannot_prove_it_is_empty() {
        // An unmounted pool leaves its empty mount point on the parent
        // filesystem: that proves nothing about the disks on the pool.
        let state = tempfile::tempdir().unwrap();
        let hdd = tempfile::tempdir().unwrap();
        let m = Mounts::new(&[hdd.path()]);
        enforce_on(
            state.path(),
            &pools(state.path(), &[("hdd0", hdd.path())]),
            &m,
        )
        .unwrap();
        m.set(&[]);
        assert!(enforce_on(state.path(), &pools(state.path(), &[]), &m).is_err());
        // Another filesystem mounted there proves nothing either.
        m.set(&[hdd.path()]);
        let mut reg = read(state.path());
        reg.pools.get_mut("hdd0").unwrap().fs = "dev:0".into();
        write(state.path(), &reg);
        assert!(enforce_on(state.path(), &pools(state.path(), &[]), &m).is_err());
    }

    #[test]
    fn a_kept_pool_on_a_new_filesystem_is_flagged_and_not_readopted() {
        let state = tempfile::tempdir().unwrap();
        let hdd = tempfile::tempdir().unwrap();
        let m = Mounts::new(&[hdd.path()]);
        let set = pools(state.path(), &[("hdd0", hdd.path())]);
        enforce_on(state.path(), &set, &m).unwrap();
        put_disk(hdd.path());
        let mut reg = read(state.path());
        reg.pools.get_mut("hdd0").unwrap().fs = "dev:0".into();
        write(state.path(), &reg);
        let bindings = enforce_on(state.path(), &set, &m).unwrap();
        assert_eq!(
            flagged(&bindings, &set, &m),
            [("hdd0".to_string(), "pool-fs-changed")]
        );
        // The old filesystem identity is kept: flagged again next start.
        assert_eq!(read(state.path()).pools["hdd0"].fs, "dev:0");
        let bindings = enforce_on(state.path(), &set, &m).unwrap();
        assert!(!flagged(&bindings, &set, &m).is_empty());
    }

    #[test]
    fn a_kept_empty_pool_on_a_new_filesystem_is_flagged_too() {
        // The disks may be on the filesystem that is gone: an empty new
        // one proves nothing.
        let state = tempfile::tempdir().unwrap();
        let hdd = tempfile::tempdir().unwrap();
        let m = Mounts::new(&[hdd.path()]);
        let set = pools(state.path(), &[("hdd0", hdd.path())]);
        enforce_on(state.path(), &set, &m).unwrap();
        let mut reg = read(state.path());
        reg.pools.get_mut("hdd0").unwrap().fs = "dev:0".into();
        write(state.path(), &reg);
        let bindings = enforce_on(state.path(), &set, &m).unwrap();
        assert_eq!(
            flagged(&bindings, &set, &m),
            [("hdd0".to_string(), "pool-fs-changed")]
        );
        // The operator's way out: drop the entry, restart.
        let mut reg = read(state.path());
        assert_eq!(reg.pools["hdd0"].fs, "dev:0");
        reg.pools.remove("hdd0");
        write(state.path(), &reg);
        let bindings = enforce_on(state.path(), &set, &m).unwrap();
        assert!(flagged(&bindings, &set, &m).is_empty());
    }

    #[test]
    fn a_remount_under_a_running_agent_is_seen_on_the_next_check() {
        let state = tempfile::tempdir().unwrap();
        let hdd = tempfile::tempdir().unwrap();
        let m = Mounts::new(&[hdd.path()]);
        let set = pools(state.path(), &[("hdd0", hdd.path())]);
        let mut bindings = enforce_on(state.path(), &set, &m).unwrap();
        assert!(flagged(&bindings, &set, &m).is_empty());
        // As if another filesystem were mounted there since startup…
        let real = bindings.recorded.insert("hdd0".into(), "dev:0".into());
        assert_eq!(
            flagged(&bindings, &set, &m),
            [("hdd0".to_string(), "pool-fs-changed")]
        );
        // …and the right one mounted back.
        bindings.recorded.insert("hdd0".into(), real.unwrap());
        assert!(flagged(&bindings, &set, &m).is_empty());
        // Unmounted: left to the pool check.
        m.set(&[]);
        assert!(flagged(&bindings, &set, &m).is_empty());
        // `default` is never bound.
        assert!(!bindings.recorded.contains_key("default"));
    }

    #[test]
    fn a_pool_mounted_after_startup_is_unbound_until_a_restart() {
        // The usual case: the mount point exists, its disk is not mounted
        // yet. It must not be bound to the parent filesystem.
        let state = tempfile::tempdir().unwrap();
        let hdd = tempfile::tempdir().unwrap();
        let m = Mounts::new(&[]);
        let set = pools(state.path(), &[("hdd0", hdd.path())]);
        let bindings = enforce_on(state.path(), &set, &m).unwrap();
        assert!(!read(state.path()).pools.contains_key("hdd0"));
        assert!(flagged(&bindings, &set, &m).is_empty());
        m.set(&[hdd.path()]);
        assert_eq!(
            flagged(&bindings, &set, &m),
            [("hdd0".to_string(), "pool-unbound")]
        );
        let bindings = enforce_on(state.path(), &set, &m).unwrap();
        assert!(flagged(&bindings, &set, &m).is_empty());
    }

    #[test]
    fn a_mounted_pool_is_identified_by_its_filesystem_uuid() {
        let host = tempfile::tempdir().unwrap();
        let pool = tempfile::tempdir().unwrap();
        let h = host.path();
        std::fs::create_dir_all(h.join("by-uuid")).unwrap();
        std::fs::write(h.join("sdb1"), b"").unwrap();
        std::fs::write(h.join("sdc1"), b"").unwrap();
        std::os::unix::fs::symlink(h.join("sdc1"), h.join("by-uuid/other")).unwrap();
        std::os::unix::fs::symlink(h.join("sdb1"), h.join("by-uuid/1234-abcd")).unwrap();
        let mountinfo = format!(
            "36 1 8:17 / {} rw - xfs {} rw\n",
            pool.path().display(),
            h.join("sdb1").display()
        );
        std::fs::write(h.join("mountinfo"), mountinfo).unwrap();
        let src = FsIdentitySource {
            mountinfo: h.join("mountinfo"),
            by_uuid: h.join("by-uuid"),
        };
        assert_eq!(
            fs_identity(&src, pool.path()).as_deref(),
            Some("uuid:1234-abcd:/")
        );
        // Another directory of the same filesystem (a bind mount, a
        // subvolume) is another identity.
        let bind = format!(
            "36 1 8:17 /pools/a {} rw - xfs {} rw\n",
            pool.path().display(),
            h.join("sdb1").display()
        );
        std::fs::write(h.join("mountinfo"), bind).unwrap();
        assert_eq!(
            fs_identity(&src, pool.path()).as_deref(),
            Some("uuid:1234-abcd:/pools/a")
        );
        // Not a mount point: no identity.
        let inner = pool.path().join("x");
        std::fs::create_dir(&inner).unwrap();
        assert_eq!(fs_identity(&src, &inner), None);
        assert_eq!(fs_identity(&src, &pool.path().join("missing")), None);
        // …except for `default`, recorded by device number.
        let dev = std::fs::metadata(&inner).unwrap().dev();
        assert_eq!(
            identity_of(&src, "default", &inner),
            Some(format!("dev:{dev}"))
        );
    }
}
