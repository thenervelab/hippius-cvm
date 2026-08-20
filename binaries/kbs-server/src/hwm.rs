//! File-backed monotonic high-water-mark store for the §22 allowlist
//! epoch (implements `kbs_core::allowlist::HighWaterStore`).
//!
//! kbs-core ships only `InMemoryHwm`, which is not durable across a
//! restart — an attacker who can crash-loop the KBS could then re-install
//! a stale (lower-epoch) allowlist. This persists the epoch to a single
//! file so allowlist-epoch rollback protection survives a restart.
//!
//! The compare-and-advance is serialised by an in-process mutex around a
//! read → compare → atomic-rename write. That is sound here because the
//! KBS runs as a single replica (K6 sets `replicas: 1` + a
//! PodDisruptionBudget). The locked design ultimately places the HWM in
//! tamper-safe Tier-0 storage — tracked as a follow-up.

use kbs_core::allowlist::HighWaterStore;
use kbs_core::error::{KbsError, Result};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

/// Durable, single-file high-water-mark store.
pub struct FileHighWaterStore {
    path: PathBuf,
    /// Serialises the read-modify-write of `compare_and_advance` so the
    /// CAS is atomic within the process.
    cas_lock: Mutex<()>,
}

impl FileHighWaterStore {
    /// Open the store, creating the parent directory if needed. The HWM
    /// file itself is created lazily on the first successful advance;
    /// until then [`HighWaterStore::get`] reports `None`.
    pub fn open(path: impl Into<PathBuf>) -> Result<Self> {
        let path = path.into();
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                fs::create_dir_all(parent).map_err(|e| {
                    KbsError::Policy(format!("hwm: create_dir_all {}: {e}", parent.display()))
                })?;
            }
        }
        Ok(Self {
            path,
            cas_lock: Mutex::new(()),
        })
    }

    fn read_current(&self) -> Result<Option<u64>> {
        match fs::read_to_string(&self.path) {
            Ok(s) => {
                let trimmed = s.trim();
                let v = trimmed
                    .parse::<u64>()
                    .map_err(|_| KbsError::Policy(format!("hwm: corrupt value {trimmed:?}")))?;
                Ok(Some(v))
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(KbsError::Policy(format!(
                "hwm: read {}: {e}",
                self.path.display()
            ))),
        }
    }
}

impl HighWaterStore for FileHighWaterStore {
    fn get(&self) -> Result<Option<u64>> {
        self.read_current()
    }

    fn compare_and_advance(&self, new_epoch: u64) -> Result<()> {
        let _guard = self
            .cas_lock
            .lock()
            .map_err(|_| KbsError::Policy("hwm: CAS lock poisoned".into()))?;
        if let Some(prev) = self.read_current()? {
            if new_epoch <= prev {
                return Err(KbsError::Policy(format!(
                    "hwm: refuses non-monotonic advance ({new_epoch} <= {prev})"
                )));
            }
        }
        atomic_write_u64(&self.path, new_epoch)
    }
}

/// temp-file → fsync → rename → fsync-parent: a crash leaves either the
/// old value or the new one, never a torn file — and the rename's
/// directory entry is itself made durable, so a crash right after the
/// rename cannot lose the advance and re-open a rollback window (the
/// whole point of persisting the mark).
fn atomic_write_u64(path: &Path, value: u64) -> Result<()> {
    let tmp = path.with_extension("tmp");
    {
        let mut f = fs::File::create(&tmp)
            .map_err(|e| KbsError::Policy(format!("hwm: create tmp: {e}")))?;
        f.write_all(value.to_string().as_bytes())
            .map_err(|e| KbsError::Policy(format!("hwm: write tmp: {e}")))?;
        f.write_all(b"\n")
            .map_err(|e| KbsError::Policy(format!("hwm: write tmp: {e}")))?;
        f.sync_all()
            .map_err(|e| KbsError::Policy(format!("hwm: fsync tmp: {e}")))?;
    }
    fs::rename(&tmp, path).map_err(|e| KbsError::Policy(format!("hwm: rename: {e}")))?;
    // fsync the parent directory so the rename itself is durable.
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            let dir = fs::File::open(parent)
                .map_err(|e| KbsError::Policy(format!("hwm: open parent dir for fsync: {e}")))?;
            dir.sync_all()
                .map_err(|e| KbsError::Policy(format!("hwm: fsync parent dir: {e}")))?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn store() -> (tempfile::TempDir, FileHighWaterStore) {
        let dir = tempfile::tempdir().unwrap();
        let s = FileHighWaterStore::open(dir.path().join("hwm")).unwrap();
        (dir, s)
    }

    #[test]
    fn fresh_store_has_no_mark() {
        let (_d, s) = store();
        assert_eq!(s.get().unwrap(), None);
    }

    #[test]
    fn advances_and_persists() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("hwm");
        {
            let s = FileHighWaterStore::open(&path).unwrap();
            s.compare_and_advance(5).unwrap();
            assert_eq!(s.get().unwrap(), Some(5));
        }
        // Re-open: the mark must survive (durable across restart).
        let reopened = FileHighWaterStore::open(&path).unwrap();
        assert_eq!(reopened.get().unwrap(), Some(5));
    }

    #[test]
    fn rejects_non_monotonic_advance() {
        let (_d, s) = store();
        s.compare_and_advance(10).unwrap();
        assert!(
            s.compare_and_advance(10).is_err(),
            "equal epoch must be rejected"
        );
        assert!(
            s.compare_and_advance(9).is_err(),
            "lower epoch must be rejected"
        );
        assert_eq!(
            s.get().unwrap(),
            Some(10),
            "store unchanged after rejected CAS"
        );
        s.compare_and_advance(11).unwrap();
        assert_eq!(s.get().unwrap(), Some(11));
    }
}
