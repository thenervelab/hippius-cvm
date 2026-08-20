//! Crash-safe atomic file write.
//!
//! [`atomic_write`] guarantees the target path is **never** observed
//! holding a partial file. Bytes go to a uniquely-named, `O_EXCL`-
//! created temp file in the target's own directory — so the rename is
//! a same-filesystem atomic replace, and a hostile co-process can
//! neither predict nor pre-place the temp path (no symlink-follow, no
//! TOCTOU). The temp is `fsync`'d, then `rename`'d onto the target:
//! the rename is the commit point. The parent directory is `fsync`'d
//! afterwards so the rename is durable across a power loss — that step
//! is best-effort, because the "no partial file" guarantee comes from
//! the rename's atomicity and holds whether or not it succeeds.
//!
//! A crash at any point leaves either the old target (or none) and at
//! worst an auto-removed temp — never a truncated target.

use std::fs::File;
use std::io::Write;
use std::path::Path;

use tempfile::NamedTempFile;

use crate::error::{Error, Result};

/// Atomically write `bytes` to `target`.
pub fn atomic_write(target: &Path, bytes: &[u8]) -> Result<()> {
    let dir = parent_dir(target);

    // A uniquely-named temp file, created `O_EXCL` in the target's
    // directory. `NamedTempFile` deletes it automatically if this
    // function returns early on any `?` — no partial temp lingers.
    let mut tmp = NamedTempFile::new_in(dir).map_err(|source| Error::Write {
        path: dir.to_path_buf(),
        source,
    })?;
    tmp.write_all(bytes).map_err(|source| Error::Write {
        path: tmp.path().to_path_buf(),
        source,
    })?;
    tmp.as_file().sync_all().map_err(|source| Error::Write {
        path: tmp.path().to_path_buf(),
        source,
    })?;

    // Commit point: the atomic rename. A reader sees either the old
    // target (or none) or the fully-written new one — never a mix.
    // Nothing after this may return `Err` — the install has happened.
    tmp.persist(target).map_err(|e| Error::Write {
        path: target.to_path_buf(),
        source: e.error,
    })?;

    // Durability belt: fsync the directory so the rename survives a
    // power loss. Best-effort — the rename has already committed, so a
    // failure here means the install is done but possibly not yet
    // durable, NOT that a partial file exists.
    if let Err(e) = sync_dir(dir) {
        eprintln!("miner-uki-fetch: warning: could not fsync {dir:?} after install: {e}");
    }
    Ok(())
}

/// The directory `target` lives in — `.` when `target` is a bare name.
fn parent_dir(target: &Path) -> &Path {
    match target.parent() {
        Some(p) if !p.as_os_str().is_empty() => p,
        _ => Path::new("."),
    }
}

fn sync_dir(dir: &Path) -> std::io::Result<()> {
    File::open(dir)?.sync_all()
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    #[test]
    fn writes_the_exact_bytes() {
        let dir = TempDir::new().unwrap();
        let target = dir.path().join("image.uki");
        atomic_write(&target, b"verified-uki-bytes").unwrap();
        assert_eq!(fs::read(&target).unwrap(), b"verified-uki-bytes");
    }

    #[test]
    fn leaves_no_temp_file_behind() {
        let dir = TempDir::new().unwrap();
        let target = dir.path().join("image.uki");
        atomic_write(&target, b"bytes").unwrap();
        // The directory holds exactly the target — the temp is gone.
        let entries: Vec<_> = fs::read_dir(dir.path()).unwrap().collect();
        assert_eq!(entries.len(), 1);
        assert!(target.exists());
    }

    #[test]
    fn replaces_an_existing_file_atomically() {
        let dir = TempDir::new().unwrap();
        let target = dir.path().join("image.uki");
        atomic_write(&target, b"first").unwrap();
        atomic_write(&target, b"second-and-longer").unwrap();
        assert_eq!(fs::read(&target).unwrap(), b"second-and-longer");
        let entries: Vec<_> = fs::read_dir(dir.path()).unwrap().collect();
        assert_eq!(entries.len(), 1, "no stray temp file after a replace");
    }

    #[test]
    fn fails_closed_when_the_directory_is_missing() {
        let dir = TempDir::new().unwrap();
        let target = dir.path().join("no-such-subdir").join("image.uki");
        assert!(atomic_write(&target, b"bytes").is_err());
        // The target was never created.
        assert!(!target.exists());
    }
}
