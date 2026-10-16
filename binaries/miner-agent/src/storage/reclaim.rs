//! Per-VM disks a destroy could not reach (design §9: "destroy proves the
//! pool is mounted").
//!
//! A destroy unlinks a VM's disks on every pool. On a pool that is not on
//! its bound filesystem right now (unmounted, another filesystem mounted
//! there), a missing file proves nothing: the disk may sit on the
//! filesystem that is gone. So the destroy still succeeds (the KEK erase
//! makes the data dead; a §24 destroy must not fail on a host problem),
//! and records the VM against that pool in
//! `<state_disk_root>/pending-reclaim.json`. [`drain`] unlinks the VM's
//! files there once the pool is back on its filesystem, at startup and
//! periodically. Without `[[storage.pools]]` nothing is ever recorded.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use serde::{Deserialize, Serialize};

use crate::lifecycle::VmId;

use super::registry::FsIdentitySource;
use super::state::EffectiveStorage;

/// Seconds before a destroy within which a file's change still counts as
/// "after" it ([`unlink`]).
const MTIME_MARGIN_S: u64 = 5;

/// File name under `state_disk_root`.
pub const PENDING_FILE: &str = "pending-reclaim.json";

/// One pool's VMs whose disks are still to be unlinked.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PoolEntry {
    /// The pool id.
    pool: String,
    path: PathBuf,
    /// The filesystem the pool was bound to when the VMs were destroyed:
    /// the one their disks are on. `None`: never bound yet.
    target: Option<String>,
    /// VM → when it was destroyed (unix seconds). A file there changed
    /// after that is a new disk, never the destroyed one.
    vms: BTreeMap<String, u64>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Pending {
    /// Keyed by pool, path and filesystem: destroys that waited for one
    /// pool at two places (it moved, or was re-bound) are kept apart.
    pools: BTreeMap<String, PoolEntry>,
}

fn key(id: &str, path: &Path, target: Option<&str>) -> String {
    format!("{id}\n{}\n{}", path.display(), target.unwrap_or(""))
}

/// Serialises every read-modify-write of the file.
static FILE_LOCK: Mutex<()> = Mutex::new(());

fn lock() -> std::sync::MutexGuard<'static, ()> {
    FILE_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn load(state_root: &Path) -> std::io::Result<Pending> {
    match std::fs::read(state_root.join(PENDING_FILE)) {
        Ok(bytes) => serde_json::from_slice(&bytes).map_err(std::io::Error::other),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Pending::default()),
        Err(e) => Err(e),
    }
}

fn save(state_root: &Path, pending: &Pending) -> std::io::Result<()> {
    if pending.pools.is_empty() {
        return match std::fs::remove_file(state_root.join(PENDING_FILE)) {
            Err(e) if e.kind() != std::io::ErrorKind::NotFound => Err(e),
            _ => Ok(()),
        };
    }
    let bytes = serde_json::to_vec_pretty(pending).map_err(std::io::Error::other)?;
    crate::netpolicy::store::write_durable(state_root, PENDING_FILE, &bytes)
        .map_err(std::io::Error::other)
}

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// The per-VM files a destroy unlinks on a pool other than `default`.
pub fn pool_files(pool_path: &Path, vm_id: &VmId) -> Vec<PathBuf> {
    let overlay = crate::lifecycle::golden::overlay_disk_path(pool_path, vm_id);
    vec![
        crate::orders::migration::restore_marker_path(&overlay),
        overlay,
        crate::lifecycle::data_disk::data_disk_path(pool_path, vm_id),
    ]
}

/// The pools of `set` other than `default` that are not on their bound
/// filesystem right now, with that filesystem: where a destroy cannot
/// trust a missing file. Blocking (it stats the pools).
pub fn unbound_pools(
    set: &EffectiveStorage,
    src: &FsIdentitySource,
) -> Vec<(String, PathBuf, Option<String>)> {
    set.pools
        .non_default()
        .filter(|p| !set.bindings.is_bound(&p.id, &p.path, src))
        .map(|p| {
            (
                p.id.clone(),
                p.path.clone(),
                set.bindings.recorded(&p.id).map(str::to_string),
            )
        })
        .collect()
}

/// Remember that `vm_id`'s disks on the pools `unbound` (from
/// [`unbound_pools`]) are still to be unlinked. Blocking.
pub fn record(
    state_root: &Path,
    unbound: &[(String, PathBuf, Option<String>)],
    vm_id: &VmId,
) -> std::io::Result<()> {
    if unbound.is_empty() {
        return Ok(());
    }
    let _guard = lock();
    let mut pending = load(state_root)?;
    let now = now_unix();
    for (id, path, target) in unbound {
        let key = key(id, path, target.as_deref());
        if !pending.pools.contains_key(&key) && pending.pools.values().any(|e| e.pool == *id) {
            eprintln!(
                "hippius-miner-agent: storage: pool {id:?} has pending reclaims at another \
                 path/filesystem too; kept as a separate entry"
            );
        }
        let entry = pending.pools.entry(key).or_insert_with(|| PoolEntry {
            pool: id.clone(),
            path: path.clone(),
            target: target.clone(),
            vms: BTreeMap::new(),
        });
        entry.vms.entry(vm_id.as_str().to_string()).or_insert(now);
    }
    save(state_root, &pending)
}

/// A pending VM whose pool is back on the filesystem its disks are on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ready {
    key: String,
    pub pool: String,
    pub path: PathBuf,
    pub vm: VmId,
    /// When it was destroyed (unix seconds).
    pub destroyed_at: u64,
}

/// The pending VMs ready to reclaim now. Entries that can never be
/// drained are dropped here: the pool left the set or moved (the
/// removed-pool guard proved its old path empty, or refused the change),
/// or the operator re-bound it to another filesystem (the one holding
/// the disks is gone for good). Blocking.
pub fn ready(
    state_root: &Path,
    set: &EffectiveStorage,
    src: &FsIdentitySource,
) -> std::io::Result<Vec<Ready>> {
    let _guard = lock();
    let mut pending = load(state_root)?;
    if pending.pools.is_empty() {
        return Ok(Vec::new());
    }
    let before = pending.clone();
    pending.pools.retain(|_, entry| {
        let id = &entry.pool;
        let keep = set.pools.get(id).is_some_and(|p| p.path == entry.path)
            && (entry.target.is_none() || set.bindings.recorded(id) == entry.target.as_deref());
        if !keep {
            eprintln!(
                "hippius-miner-agent: storage: pending reclaim on pool {id:?} dropped (the pool \
                 moved, left, or was re-bound)"
            );
        }
        keep
    });
    let mut out = Vec::new();
    for (key, entry) in &pending.pools {
        if !set.bindings.is_bound(&entry.pool, &entry.path, src) {
            continue;
        }
        for (vm, at) in &entry.vms {
            if let Ok(vm) = VmId::new(vm) {
                out.push(Ready {
                    key: key.clone(),
                    pool: entry.pool.clone(),
                    path: entry.path.clone(),
                    vm,
                    destroyed_at: *at,
                });
            }
        }
    }
    if pending != before {
        save(state_root, &pending)?;
    }
    Ok(out)
}

/// Unlink `ready`'s files, except any changed after the destroy (a new
/// disk under the same name). Blocking. `Err` leaves it pending.
pub fn unlink(ready: &Ready) -> std::io::Result<()> {
    for file in pool_files(&ready.path, &ready.vm) {
        let modified = match std::fs::symlink_metadata(&file) {
            Ok(meta) => meta
                .modified()
                .ok()
                .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                .map_or(u64::MAX, |d| d.as_secs()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(e) => return Err(e),
        };
        // A file changed after the destroy, or within the margin before
        // it (whole seconds, a small clock step), is kept: a doubt keeps
        // a disk, it never deletes one.
        if modified.saturating_add(MTIME_MARGIN_S) >= ready.destroyed_at {
            continue;
        }
        match std::fs::remove_file(&file) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

/// Forget `ready` (reclaimed, or its id is live again).
pub fn done(state_root: &Path, ready: &Ready) -> std::io::Result<()> {
    let _guard = lock();
    let mut pending = load(state_root)?;
    let Some(entry) = pending.pools.get_mut(&ready.key) else {
        return Ok(());
    };
    if entry.vms.remove(ready.vm.as_str()).is_none() {
        return Ok(());
    }
    if entry.vms.is_empty() {
        pending.pools.remove(&ready.key);
    }
    save(state_root, &pending)
}

/// How often [`run`] drains the pending reclaims.
const DRAIN_EVERY: std::time::Duration = std::time::Duration::from_secs(300);

/// Drain the pending reclaims now and every [`DRAIN_EVERY`] (blocking
/// work off the async workers) until `cancel`.
pub async fn run(
    lifecycle: std::sync::Arc<crate::lifecycle::CvmLifecycle>,
    cancel: tokio_util::sync::CancellationToken,
) {
    loop {
        let lc = std::sync::Arc::clone(&lifecycle);
        match tokio::task::spawn_blocking(move || lc.reclaim_pending_pool_disks()).await {
            Ok(Ok(0)) => {}
            Ok(Ok(n)) => {
                eprintln!(
                    "hippius-miner-agent: storage: reclaimed the disks of {n} destroyed VM(s)"
                )
            }
            Ok(Err(_)) | Err(_) => {
                eprintln!("hippius-miner-agent: storage: {PENDING_FILE} could not be drained")
            }
        }
        tokio::select! {
            _ = cancel.cancelled() => return,
            _ = tokio::time::sleep(DRAIN_EVERY) => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::registry::PoolBindings;
    use crate::storage::StoragePools;
    use std::sync::Arc;

    fn set(data_root: &Path, hdd: &Path) -> EffectiveStorage {
        use crate::config::{
            PoolClassConfig, StorageDesiredStateConfig, StoragePoolConfig, StorageSection,
        };
        let pool = |id: &str, path: &Path| StoragePoolConfig {
            id: id.into(),
            path: path.to_path_buf(),
            class: PoolClassConfig::Hdd,
            budget_gb: 0,
            os_disks: true,
            state: StorageDesiredStateConfig::Active,
        };
        let pools = StoragePools::from_config(
            &StorageSection {
                data_disk_root: data_root.to_path_buf(),
                state_disk_root: data_root.to_path_buf(),
                pools: vec![pool("default", data_root), pool("hdd0", hdd)],
                dedicated_disks: Vec::new(),
            },
            0,
        );
        EffectiveStorage::local(Arc::new(pools), Vec::new(), PoolBindings::default())
    }

    #[test]
    fn an_entry_for_a_pool_that_moved_or_left_is_dropped() {
        let state = tempfile::tempdir().unwrap();
        let hdd = tempfile::tempdir().unwrap();
        let elsewhere = tempfile::tempdir().unwrap();
        let vm = VmId::new("tenant-1").unwrap();
        let unbound = [("hdd0".to_string(), hdd.path().to_path_buf(), None)];
        record(state.path(), &unbound, &vm).unwrap();
        record(state.path(), &unbound, &vm).unwrap();
        let src = FsIdentitySource::default();
        // Not bound: it waits.
        assert!(ready(state.path(), &set(state.path(), hdd.path()), &src)
            .unwrap()
            .is_empty());
        let pending = load(state.path()).unwrap();
        assert_eq!(pending.pools.len(), 1);
        assert_eq!(pending.pools.values().next().unwrap().vms.len(), 1);
        // The pool now sits elsewhere: the guard proved the old path empty.
        assert!(
            ready(state.path(), &set(state.path(), elsewhere.path()), &src)
                .unwrap()
                .is_empty()
        );
        assert!(!state.path().join(PENDING_FILE).exists());
    }

    #[test]
    fn a_file_changed_after_the_destroy_is_never_unlinked() {
        let hdd = tempfile::tempdir().unwrap();
        let vm = VmId::new("tenant-1").unwrap();
        let files = pool_files(hdd.path(), &vm);
        std::fs::create_dir_all(files[1].parent().unwrap()).unwrap();
        std::fs::write(&files[1], b"new disk").unwrap();
        let r = Ready {
            key: String::new(),
            pool: "hdd0".into(),
            path: hdd.path().to_path_buf(),
            vm,
            destroyed_at: now_unix() - 3600,
        };
        unlink(&r).unwrap();
        assert!(files[1].exists());
        // Changed within the margin before the destroy: kept as well.
        let r = Ready {
            destroyed_at: now_unix() + 2,
            ..r
        };
        unlink(&r).unwrap();
        assert!(files[1].exists());
        let r = Ready {
            destroyed_at: now_unix() + 3600,
            ..r
        };
        unlink(&r).unwrap();
        assert!(!files[1].exists());
    }
}
