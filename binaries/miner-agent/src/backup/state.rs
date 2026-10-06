//! The anti-rollback state disk in a backup: a byte copy of the 1 MiB
//! ext4 `state/<vm>.raw`, and the boot counter read out of that copy.
//!
//! The counter is what makes a backup restorable: vali accepts a run
//! only if its counter equals the KBS's stored counter for the VM (the
//! backup was taken at the current boot). The file holds the last
//! KBS-committed value as decimal text (`guest-release` writes it after
//! each release), so it is reported verbatim — no ±1.

use std::path::Path;

use tokio::process::Command;

use crate::error::{MinerAgentError, Result};
use crate::lifecycle::state_disk::STATE_DISK_BYTES;

/// Path of the counter inside the state filesystem.
const COUNTER_IN_FS: &str = "/boot-counter";

/// Cap on `debugfs`.
const DEBUGFS_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// Read the state disk into memory, refusing anything but exactly 1 MiB.
pub async fn read_state_disk(path: &Path) -> Result<Vec<u8>> {
    let bytes = tokio::fs::read(path)
        .await
        .map_err(|_| MinerAgentError::Backup("state-read"))?;
    if bytes.len() as u64 != STATE_DISK_BYTES {
        return Err(MinerAgentError::Backup("state-size"));
    }
    Ok(bytes)
}

/// The boot counter recorded in a state-disk image, read with
/// `debugfs` (no mount, no root). `None` when the file is missing,
/// empty or not a decimal u64 — i.e. the guest never completed a
/// release — which vali must treat as "not restorable".
pub async fn boot_counter(image: &[u8], scratch_dir: &Path) -> Option<u64> {
    let tmp = tempfile::Builder::new()
        .prefix(".state-copy-")
        .tempfile_in(scratch_dir)
        .ok()?;
    tokio::fs::write(tmp.path(), image).await.ok()?;
    let mut cmd = Command::new("debugfs");
    cmd.arg("-R")
        .arg(format!("cat {COUNTER_IN_FS}"))
        .arg(tmp.path())
        .stdin(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .kill_on_drop(true);
    let out = tokio::time::timeout(DEBUGFS_TIMEOUT, cmd.output())
        .await
        .ok()?
        .ok()?;
    if !out.status.success() {
        return None;
    }
    parse_counter(&out.stdout)
}

/// Parse the counter file's content.
pub fn parse_counter(raw: &[u8]) -> Option<u64> {
    std::str::from_utf8(raw).ok()?.trim().parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counter_parsing() {
        assert_eq!(parse_counter(b"7\n"), Some(7));
        assert_eq!(parse_counter(b" 12 "), Some(12));
        assert_eq!(parse_counter(b""), None);
        assert_eq!(parse_counter(b"-1"), None);
        assert_eq!(parse_counter(b"abc"), None);
    }

    /// Real `mkfs.ext4` + `debugfs` round trip — skipped where the
    /// e2fsprogs tools are absent.
    #[tokio::test]
    async fn reads_the_counter_out_of_a_real_state_disk() {
        let have = |b: &str| std::process::Command::new(b).arg("-V").output().is_ok();
        if !have("mkfs.ext4") || !have("debugfs") {
            eprintln!("skipping: e2fsprogs not installed");
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let img = dir.path().join("s.raw");
        let f = std::fs::File::create(&img).unwrap();
        f.set_len(STATE_DISK_BYTES).unwrap();
        drop(f);
        assert!(std::process::Command::new("mkfs.ext4")
            .args(["-q", "-F", "-L", "hippius-state"])
            .arg(&img)
            .status()
            .unwrap()
            .success());
        let bytes = std::fs::read(&img).unwrap();
        // Fresh disk: no counter yet.
        assert_eq!(boot_counter(&bytes, dir.path()).await, None);

        let src = dir.path().join("c");
        std::fs::write(&src, "41\n").unwrap();
        assert!(std::process::Command::new("debugfs")
            .arg("-w")
            .arg("-R")
            .arg(format!("write {} boot-counter", src.display()))
            .arg(&img)
            .output()
            .unwrap()
            .status
            .success());
        let bytes = read_state_disk(&img).await.unwrap();
        assert_eq!(boot_counter(&bytes, dir.path()).await, Some(41));
    }

    #[tokio::test]
    async fn wrong_size_state_disk_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("s.raw");
        std::fs::write(&p, [0u8; 10]).unwrap();
        assert!(matches!(
            read_state_disk(&p).await,
            Err(MinerAgentError::Backup("state-size"))
        ));
    }
}
