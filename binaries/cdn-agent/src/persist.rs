//! Atomic file replacement for agent state.
//!
//! A full disk can leave `open(p, "w")` truncated with no error at the
//! call site that matters. Every state file is therefore written to
//! `p.new`, flushed and fsynced, then renamed over `p`, and the parent
//! directory is fsynced. A crash or a full disk leaves either the old
//! file or the new one, never a torn mix.

use std::fs::{self, File, OpenOptions};
use std::io::{ErrorKind, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use crate::error::{CdnError, Result};

/// State files hold no cleartext secret, but they are still private to
/// the agent user.
const STATE_FILE_MODE: u32 = 0o600;

/// Write `bytes` to `path` atomically (see module docs).
pub fn atomic_write(path: &Path, bytes: &[u8]) -> Result<()> {
    let tmp = tmp_path(path);
    let result = write_and_rename(&tmp, path, bytes);
    if result.is_err() {
        // Best effort: never leave a half-written `.new` behind.
        let _ = fs::remove_file(&tmp);
    }
    result
}

/// Read `path`, distinguishing "absent" (`Ok(None)`) from a read error.
pub fn read_optional(path: &Path, max_len: u64) -> Result<Option<Vec<u8>>> {
    match fs::metadata(path) {
        Ok(meta) if meta.len() > max_len => return Err(CdnError::Io("state-file-too-large")),
        Ok(_) => {}
        Err(e) if e.kind() == ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err(CdnError::Io("state-file-stat")),
    }
    fs::read(path)
        .map(Some)
        .map_err(|_| CdnError::Io("state-file-read"))
}

/// Create `dir` (and parents) with mode 0700 if it does not exist.
pub fn ensure_private_dir(dir: &Path) -> Result<()> {
    use std::os::unix::fs::DirBuilderExt;
    fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(dir)
        .map_err(|_| CdnError::Io("state-dir-create"))
}

fn tmp_path(path: &Path) -> PathBuf {
    let mut name = path.as_os_str().to_os_string();
    name.push(".new");
    PathBuf::from(name)
}

fn write_and_rename(tmp: &Path, path: &Path, bytes: &[u8]) -> Result<()> {
    let mut f = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(STATE_FILE_MODE)
        .open(tmp)
        .map_err(|_| CdnError::Io("state-file-open"))?;
    f.write_all(bytes)
        .map_err(|_| CdnError::Io("state-file-write"))?;
    f.sync_all().map_err(|_| CdnError::Io("state-file-sync"))?;
    drop(f);
    fs::rename(tmp, path).map_err(|_| CdnError::Io("state-file-rename"))?;
    if let Some(parent) = path.parent() {
        File::open(parent)
            .and_then(|d| d.sync_all())
            .map_err(|_| CdnError::Io("state-dir-sync"))?;
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn replaces_the_file_and_leaves_no_temp() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("state.json");
        atomic_write(&p, b"one").unwrap();
        atomic_write(&p, b"two").unwrap();
        assert_eq!(fs::read(&p).unwrap(), b"two");
        assert!(!tmp_path(&p).exists());
        let mode = fs::metadata(&p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }

    #[test]
    fn read_optional_distinguishes_absent_and_oversized() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("x");
        assert!(read_optional(&p, 10).unwrap().is_none());
        fs::write(&p, b"0123456789AB").unwrap();
        assert!(read_optional(&p, 10).is_err());
        assert_eq!(read_optional(&p, 100).unwrap().unwrap().len(), 12);
    }
}
