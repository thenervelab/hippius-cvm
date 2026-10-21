//! Per-VM **pool record**: which storage pool holds a VM's writable disks
//! (`<root>/overlay/<vm>.img`, `<root>/data/<vm>.img`, `<root>/backup/<vm>`).
//!
//! Every path to a VM's disks used to be rebuilt from `data_disk_root`.
//! Once a VM can live on another pool that rebuild points at the wrong
//! filesystem, and every `ensure_*` provisioner then creates a BLANK disk
//! there: a relaunch, a §25 destination or a restore would boot the tenant
//! empty. So the pool a VM's disks live on is recorded once, at
//! `<state_root>/vm-pool/<vm_id>`, and every caller resolves through it.
//!
//! ## Lifetime
//! - Written atomically (temp + fsync + rename + dir fsync) BEFORE the
//!   first disk is created, by a first launch or a §25/restore arrival.
//! - `ran` turns true before the domain is first started, and for any VM
//!   that arrives with its data (§25, restore). From then on a missing
//!   disk is refused, never recreated blank.
//! - Kept across stop and a failed launch (the disks it names are kept
//!   too). Deleted LAST by §24 destroy.
//!
//! ## VMs older than the record
//! Agents before the record could only place disks on `default`. The
//! first start of this agent writes a `default` record for every VM it
//! finds ([`backfill`]), then [`BACKFILLED_MARKER`]. Until the marker
//! exists a missing record means `default` (the old behaviour); after it,
//! a missing record for a VM that has run is refused
//! (`vm-pool-record-missing`), never guessed.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::lifecycle::cvm_handle::VmId;

/// Under the agent's state root.
pub const DIR: &str = "vm-pool";

/// Written once every pre-record VM has its record (fsynced).
pub const BACKFILLED_MARKER: &str = ".backfilled";

/// What is recorded for one VM.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VmPoolRecord {
    /// The pool id when the record was written (informational: the
    /// pool's declaration can change, the disks do not move).
    pub pool_id: String,
    /// The pool root the VM's disks live under.
    pub root: PathBuf,
    /// Whether a guest may have used these disks: a missing disk is then
    /// refused instead of created blank.
    pub ran: bool,
}

/// A record that exists but cannot be used.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Unreadable;

pub fn dir(state_root: &Path) -> PathBuf {
    state_root.join(DIR)
}

pub fn record_path(state_root: &Path, vm_id: &VmId) -> PathBuf {
    dir(state_root).join(vm_id.as_str())
}

/// `Ok(None)`: no record. `Err`: a record that cannot be read or parsed —
/// never treated as absent.
pub fn read(state_root: &Path, vm_id: &VmId) -> Result<Option<VmPoolRecord>, Unreadable> {
    match std::fs::read(record_path(state_root, vm_id)) {
        Ok(bytes) => serde_json::from_slice(&bytes)
            .map(Some)
            .map_err(|_| Unreadable),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(_) => Err(Unreadable),
    }
}

/// Write `record` atomically and durably.
pub fn write(state_root: &Path, vm_id: &VmId, record: &VmPoolRecord) -> std::io::Result<()> {
    let bytes = serde_json::to_vec_pretty(record)?;
    write_durable(&dir(state_root), &record_path(state_root, vm_id), &bytes)
}

/// Write `record` only if `vm_id` has none yet (atomic, durable). `false`:
/// a record appeared meanwhile and is kept as it is.
pub fn create(state_root: &Path, vm_id: &VmId, record: &VmPoolRecord) -> std::io::Result<bool> {
    use std::io::Write;
    let dir = dir(state_root);
    let bytes = serde_json::to_vec_pretty(record)?;
    if !dir.is_dir() {
        std::fs::create_dir_all(&dir)?;
        if let Some(parent) = dir.parent() {
            sync_dir(parent)?;
        }
    }
    let mut tmp = tempfile::NamedTempFile::new_in(&dir)?;
    tmp.write_all(&bytes)?;
    tmp.as_file().sync_all()?;
    match tmp.persist_noclobber(record_path(state_root, vm_id)) {
        Ok(_) => sync_dir(&dir).map(|()| true),
        Err(err) if err.error.kind() == std::io::ErrorKind::AlreadyExists => Ok(false),
        Err(err) => Err(err.error),
    }
}

/// Remove `vm_id`'s record (a missing one is success).
pub fn remove(state_root: &Path, vm_id: &VmId) -> std::io::Result<()> {
    match std::fs::remove_file(record_path(state_root, vm_id)) {
        Ok(()) => sync_dir(&dir(state_root)),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(err),
    }
}

/// Whether [`backfill`] has completed on this host. An unreadable state
/// root reads as "done": a missing record is then refused, never guessed.
pub fn backfilled(state_root: &Path) -> bool {
    !matches!(
        dir(state_root).join(BACKFILLED_MARKER).try_exists(),
        Ok(false)
    )
}

/// Every record's root (for sweeps over the VMs' pools).
pub fn roots(state_root: &Path) -> Vec<PathBuf> {
    let Ok(entries) = std::fs::read_dir(dir(state_root)) else {
        return Vec::new();
    };
    let mut roots: Vec<PathBuf> = entries
        .flatten()
        .filter_map(|e| VmId::new(e.file_name().to_str()?).ok())
        .filter_map(|vm| read(state_root, &vm).ok().flatten())
        .map(|r| r.root)
        .collect();
    roots.sort();
    roots.dedup();
    roots
}

/// One-time record of every VM placed by an agent older than the record:
/// all of them are on `default` (`default_root`). Found from `known` (the
/// live domains and re-adoption snapshots) and from the files on disk:
/// overlays, data disks, §25 restore markers, backup dirs under
/// `default_root`; state disks and staging dirs under `state_root`. A VM
/// with a disk file (or `known`) is recorded `ran`; one with only a
/// staging or backup dir has not booted and is not.
///
/// A VM that already has a record keeps it. The marker is written only
/// after every record is durable; any failure leaves no marker, and the
/// next start runs it again. Returns how many records were written.
pub fn backfill(state_root: &Path, default_root: &Path, known: &[VmId]) -> std::io::Result<usize> {
    if backfilled(state_root) {
        return Ok(0);
    }
    let mut found: std::collections::BTreeMap<String, bool> = std::collections::BTreeMap::new();
    let mut note = |name: &str, ran: bool| {
        if VmId::new(name).is_ok() {
            let entry = found.entry(name.to_string()).or_insert(false);
            *entry |= ran;
        }
    };
    for vm in known {
        note(vm.as_str(), true);
    }
    for name in list(&default_root.join("overlay"))? {
        if let Some(vm) = name.strip_suffix(".img.restored-from") {
            note(vm, true);
        } else if let Some(vm) = name.strip_suffix(".img") {
            note(vm, true);
        }
    }
    for name in list(&default_root.join("data"))? {
        if let Some(vm) = name.strip_suffix(".img") {
            note(vm, true);
        }
    }
    for name in list(&state_root.join("state"))? {
        if let Some(vm) = name.strip_suffix(".raw") {
            note(vm, true);
        }
    }
    for name in list(&default_root.join("backup"))? {
        note(&name, false);
    }
    for name in list(&state_root.join("staging"))? {
        note(&name, false);
    }
    let mut written = 0;
    for (name, ran) in found {
        let Ok(vm) = VmId::new(&name) else { continue };
        match read(state_root, &vm) {
            Ok(Some(_)) => continue,
            Ok(None) => {}
            Err(Unreadable) => {
                return Err(std::io::Error::other(format!(
                    "vm-pool record for {name} unreadable"
                )))
            }
        }
        let record = VmPoolRecord {
            pool_id: crate::storage::pools::DEFAULT_POOL_ID.to_string(),
            root: default_root.to_path_buf(),
            ran,
        };
        write(state_root, &vm, &record)?;
        written += 1;
    }
    write_durable(
        &dir(state_root),
        &dir(state_root).join(BACKFILLED_MARKER),
        b"",
    )?;
    Ok(written)
}

/// Entry names of `dir`; a missing directory is empty, any other error
/// fails the backfill (an unlisted VM would later be refused).
fn list(dir: &Path) -> std::io::Result<Vec<String>> {
    match std::fs::read_dir(dir) {
        Ok(entries) => entries
            .map(|e| e.map(|e| e.file_name().to_string_lossy().into_owned()))
            .collect(),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(Vec::new()),
        Err(err) => Err(err),
    }
}

pub(crate) fn write_durable(dir: &Path, path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    if !dir.is_dir() {
        std::fs::create_dir_all(dir)?;
        // The new directory entry itself must survive a crash too.
        if let Some(parent) = dir.parent() {
            sync_dir(parent)?;
        }
    }
    let mut tmp = tempfile::NamedTempFile::new_in(dir)?;
    tmp.write_all(bytes)?;
    tmp.as_file().sync_all()?;
    tmp.persist(path).map_err(|e| e.error)?;
    sync_dir(dir)
}

fn sync_dir(dir: &Path) -> std::io::Result<()> {
    std::fs::File::open(dir)?.sync_all()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vm(s: &str) -> VmId {
        VmId::new(s).unwrap()
    }

    fn touch(path: &Path) {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, b"x").unwrap();
    }

    #[test]
    fn a_record_round_trips_and_an_unreadable_one_is_not_absent() {
        let dir = tempfile::tempdir().unwrap();
        let state = dir.path();
        assert_eq!(read(state, &vm("a")), Ok(None));
        let rec = VmPoolRecord {
            pool_id: "nvme0".into(),
            root: "/var/lib/hippius-miner/pools/nvme0".into(),
            ran: true,
        };
        write(state, &vm("a"), &rec).unwrap();
        assert_eq!(read(state, &vm("a")), Ok(Some(rec)));
        std::fs::write(record_path(state, &vm("a")), b"{garbage").unwrap();
        assert_eq!(read(state, &vm("a")), Err(Unreadable));
        remove(state, &vm("a")).unwrap();
        remove(state, &vm("a")).unwrap();
        assert_eq!(read(state, &vm("a")), Ok(None));
    }

    #[test]
    fn create_never_replaces_a_record() {
        let dir = tempfile::tempdir().unwrap();
        let state = dir.path();
        let rec = |ran| VmPoolRecord {
            pool_id: "default".into(),
            root: "/r".into(),
            ran,
        };
        assert!(create(state, &vm("a"), &rec(true)).unwrap());
        assert!(!create(state, &vm("a"), &rec(false)).unwrap());
        assert_eq!(read(state, &vm("a")), Ok(Some(rec(true))));
    }

    #[test]
    fn backfill_records_running_stopped_and_mid_migration_vms_on_default() {
        let dir = tempfile::tempdir().unwrap();
        let (state, data) = (dir.path().join("state-root"), dir.path().join("data-root"));
        // Stopped golden VM: its overlay + state disk, no domain, no snapshot.
        touch(&data.join("overlay/stopped.img"));
        touch(&state.join("state/stopped.raw"));
        // Stopped legacy VM: data disk only.
        touch(&data.join("data/legacy.img"));
        // A §25 destination whose download finished (marker) …
        touch(&data.join("overlay/arrived.img.restored-from"));
        // … and one still downloading (backup work dir only).
        std::fs::create_dir_all(data.join("backup/downloading/chain-restore")).unwrap();
        // Staged for a first launch, never booted.
        std::fs::create_dir_all(state.join("staging/fresh")).unwrap();
        // Noise.
        touch(&data.join("overlay/.tmpXYZ"));
        touch(&data.join("overlay/BAD_NAME.img"));
        // Already recorded elsewhere: untouched.
        let kept = VmPoolRecord {
            pool_id: "hdd0".into(),
            root: "/var/lib/hippius-miner/pools/hdd0".into(),
            ran: true,
        };
        write(&state, &vm("moved"), &kept).unwrap();
        touch(&data.join("overlay/moved.img"));

        let n = backfill(&state, &data, &[vm("running")]).unwrap();
        assert_eq!(n, 6);
        let rec = |name: &str| read(&state, &vm(name)).unwrap().unwrap();
        for name in ["running", "stopped", "legacy", "arrived"] {
            assert_eq!(
                rec(name),
                VmPoolRecord {
                    pool_id: "default".into(),
                    root: data.clone(),
                    ran: true
                },
                "{name}"
            );
        }
        assert!(!rec("downloading").ran);
        assert!(!rec("fresh").ran);
        assert_eq!(rec("moved"), kept);
        assert!(backfilled(&state));
        // Done once.
        touch(&data.join("overlay/later.img"));
        assert_eq!(backfill(&state, &data, &[]).unwrap(), 0);
        assert_eq!(read(&state, &vm("later")), Ok(None));
    }

    #[test]
    fn a_partial_backfill_leaves_no_marker_and_completes_on_the_next_start() {
        let dir = tempfile::tempdir().unwrap();
        let (state, data) = (dir.path().join("state-root"), dir.path().join("data-root"));
        touch(&data.join("overlay/a.img"));
        touch(&data.join("overlay/b.img"));
        // `b`'s record is corrupt: the backfill stops, without a marker.
        std::fs::create_dir_all(dir.path().join("state-root/vm-pool")).unwrap();
        std::fs::write(record_path(&state, &vm("b")), b"{").unwrap();
        assert!(backfill(&state, &data, &[]).is_err());
        assert!(!backfilled(&state));
        assert!(read(&state, &vm("a")).unwrap().is_some());
        // Repaired by an operator: the next start finishes it.
        std::fs::remove_file(record_path(&state, &vm("b"))).unwrap();
        assert_eq!(backfill(&state, &data, &[]).unwrap(), 1);
        assert!(backfilled(&state));
        assert!(read(&state, &vm("b")).unwrap().unwrap().ran);
    }

    #[test]
    fn roots_lists_each_recorded_root_once() {
        let dir = tempfile::tempdir().unwrap();
        let state = dir.path();
        for (name, root) in [("a", "/p/x"), ("b", "/p/y"), ("c", "/p/x")] {
            let rec = VmPoolRecord {
                pool_id: "p".into(),
                root: root.into(),
                ran: true,
            };
            write(state, &vm(name), &rec).unwrap();
        }
        assert_eq!(
            roots(state),
            vec![PathBuf::from("/p/x"), PathBuf::from("/p/y")]
        );
    }
}
