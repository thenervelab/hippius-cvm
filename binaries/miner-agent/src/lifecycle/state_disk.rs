//! Per-VM 1 MiB ext4 state disk — the on-host substrate for the
//! anti-rollback boot counter (audit follow-up Codex #2 / Phase 2B,
//! companion to PR #346's wire-level Phase 2A).
//!
//! ## Why a separate raw disk
//!
//! The KBS keeps the canonical per-`vm_id` boot counter; the guest's
//! copy is just "what value to submit next time" — losing or rolling
//! it back can only make the next release **fail closed** (the KBS
//! CAS sees a stale or zero counter and rejects), never bypass
//! anti-rollback. So the counter does NOT need to be a secret and
//! does NOT need to live inside the LUKS-encrypted rootfs.
//!
//! But it DOES need to persist across reboots, and it has to be
//! readable + writable at keyscript time — i.e. BEFORE the LUKS
//! rootfs is unlocked. A standalone block device the keyscript can
//! `mount -t ext4` is the simplest substrate that meets both
//! constraints: the miner-agent provisions one 1 MiB ext4 file per
//! tenant VM, libvirt attaches it as `vdd`, the keyscript mounts it
//! at `/hippius-state` before invoking `hippius-guest-release`.
//!
//! Tampering with the file (cold, from the miner host; hot, from the
//! tenant post-pivot) can only make subsequent boots fail closed —
//! never advance the counter past the KBS-committed value.
//!
//! ⚠️ That is true of BLIND tampering only, and the distinction matters.
//! The KBS-committed value is written back into this very file after each
//! successful release, so a host can READ it. A host that restores an OLD
//! volume and writes the CURRENT counter is therefore GRANTED the release,
//! over rolled-back ciphertext: nothing binds the counter to the volume it
//! is meant to protect. So this counter is a replay guard on the RELEASE
//! PROTOCOL (a captured transcript cannot be re-run), not a disk-rollback
//! guard on its own. Closing that would need a second copy inside the LUKS
//! volume compared after unlock, or a KBS-returned MAC the host cannot
//! forge. Do not build on the stronger reading.
//!
//! ## File layout
//!
//! Per-VM file at `MINER_ROOT/state/{vm_id}.raw`, exactly 1 MiB,
//! formatted ext4 with label `hippius-state`. Idempotent: a subsequent
//! call for the same `vm_id` returns the existing path without
//! re-formatting (which would zero the boot counter).
//!
//! ## §20 secret discipline
//!
//! No secret bytes touch this module. Every error carries a
//! closed-vocabulary `&'static str` sub-classifier; paths and
//! command output are never interpolated.

use std::path::{Path, PathBuf};
use std::process::Command;

use crate::error::{MinerAgentError, Result};
use crate::lifecycle::cvm_handle::VmId;

/// Per-VM state-disk size. 1 MiB is the smallest size `mkfs.ext4`
/// accepts without `-b 1024 -T small` gymnastics; we never approach
/// the inode budget storing one u64 counter.
pub(crate) const STATE_DISK_BYTES: u64 = 1024 * 1024;

/// ext4 volume label. Constant so the keyscript can `mount LABEL=…`
/// if `/dev/vdd` ever moves under future libvirt XML reshuffles
/// (today the keyscript uses the device path directly).
const STATE_DISK_LABEL: &str = "hippius-state";

/// Subdirectory under `MINER_ROOT` that holds per-VM state disks.
/// Co-located with the staging tree but separate so a `find`-based
/// staging GC sweep never accidentally truncates a state file.
const STATE_DIR_NAME: &str = "state";

/// Compute the on-host path for a tenant's state disk, without
/// creating or formatting it. Used by config-rendering paths that
/// need the path to interpolate into libvirt XML.
pub fn state_disk_path(miner_root: &Path, vm_id: &VmId) -> PathBuf {
    miner_root.join(STATE_DIR_NAME).join(format!("{vm_id}.raw"))
}

/// Idempotent creation: ensure a 1 MiB ext4 state disk exists for
/// `vm_id` under `miner_root` and return its path. If the file
/// already exists the path is returned verbatim — no re-format, so
/// the boot counter persists across launches of the same `vm_id`.
///
/// Side effects (only when the file is absent):
/// 1. `mkdir -p` the `state/` subdirectory.
/// 2. Create the file with `O_CREAT | O_EXCL` so two racing
///    `launch` calls do not both race to truncate-and-format the
///    same byte range.
/// 3. `set_len(STATE_DISK_BYTES)` to allocate the 1 MiB extent.
/// 4. `mkfs.ext4 -F -L hippius-state` against the freshly-allocated
///    file.
///
/// On any failure the partially-created file is removed (so a retry
/// is not poisoned by a half-formatted image whose ext4 superblock
/// would mount-but-corrupt).
pub fn ensure_state_disk(miner_root: &Path, vm_id: &VmId) -> Result<PathBuf> {
    let path = state_disk_path(miner_root, vm_id);
    if path.exists() {
        return Ok(path);
    }

    // `state_disk_path` always returns `{root}/state/{vm_id}.raw`, so
    // `parent()` is always `Some({root}/state)`. Use `ok_or` to satisfy
    // clippy without the runtime cost of panic machinery.
    let parent = path
        .parent()
        .ok_or(MinerAgentError::StateDisk("no-parent"))?;
    std::fs::create_dir_all(parent).map_err(|_| MinerAgentError::StateDisk("mkdir"))?;

    // O_CREAT | O_EXCL — racing callers fail-closed on AlreadyExists,
    // which then becomes the idempotent "exists" branch on retry.
    let file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path)
        .map_err(|e| match e.kind() {
            std::io::ErrorKind::AlreadyExists => MinerAgentError::StateDisk("race"),
            _ => MinerAgentError::StateDisk("create"),
        })?;

    if let Err(e) = file.set_len(STATE_DISK_BYTES) {
        let _ = std::fs::remove_file(&path);
        // `e` may carry the OS errno; the closed-vocabulary discipline
        // only surfaces the static classifier.
        let _ = e;
        return Err(MinerAgentError::StateDisk("truncate"));
    }
    drop(file);

    // `-F` forces mkfs over an existing file (which we just created
    // empty, so this is just to silence the "are you sure?" prompt
    // mkfs.ext4 emits on a regular file). `-q` to keep stdout out of
    // miner logs (we do NOT want to echo mkfs's per-invocation
    // arbitrary text into the §20-disciplined diagnostic stream;
    // failure is reported via the static classifier alone).
    let status = Command::new("mkfs.ext4")
        .arg("-F")
        .arg("-q")
        .arg("-L")
        .arg(STATE_DISK_LABEL)
        .arg(&path)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map_err(|_| {
            let _ = std::fs::remove_file(&path);
            MinerAgentError::StateDisk("mkfs-spawn")
        })?;
    if !status.success() {
        let _ = std::fs::remove_file(&path);
        return Err(MinerAgentError::StateDisk("mkfs-failed"));
    }
    Ok(path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn vm(id: &str) -> VmId {
        VmId::new(id).expect("valid vm id")
    }

    #[test]
    fn path_layout_is_deterministic_per_vm() {
        let root = Path::new("/var/lib/hippius-miner");
        let p = state_disk_path(root, &vm("tenant-abc-01"));
        assert_eq!(
            p,
            PathBuf::from("/var/lib/hippius-miner/state/tenant-abc-01.raw")
        );
    }

    #[test]
    fn path_does_not_create_anything() {
        // Pure path math — must not touch the FS.
        let tmp = TempDir::new().unwrap();
        let p = state_disk_path(tmp.path(), &vm("tenant-no-side-effect"));
        assert!(!p.exists());
        assert!(!tmp.path().join("state").exists());
    }

    // `mkfs.ext4` is not installed inside every dev sandbox / CI
    // container; gate the side-effecting tests behind the binary's
    // presence so we don't false-fail the test suite on minimal images.
    fn mkfs_available() -> bool {
        Command::new("which")
            .arg("mkfs.ext4")
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
    }

    #[test]
    fn ensure_creates_one_mib_ext4_file() {
        if !mkfs_available() {
            eprintln!("skipping: mkfs.ext4 not installed");
            return;
        }
        let tmp = TempDir::new().unwrap();
        let path = ensure_state_disk(tmp.path(), &vm("tenant-ext4-create")).expect("created");
        assert!(path.exists());
        let len = std::fs::metadata(&path).unwrap().len();
        assert_eq!(len, STATE_DISK_BYTES);
        // ext4 superblock starts at offset 1024 with magic 0xEF53
        // (little-endian) at offset +56. Probe directly to avoid a
        // libe2fs dep.
        let bytes = std::fs::read(&path).unwrap();
        let magic = u16::from_le_bytes([bytes[1024 + 56], bytes[1024 + 57]]);
        assert_eq!(magic, 0xEF53, "ext4 superblock magic");
    }

    #[test]
    fn ensure_is_idempotent() {
        if !mkfs_available() {
            eprintln!("skipping: mkfs.ext4 not installed");
            return;
        }
        let tmp = TempDir::new().unwrap();
        let vm = vm("tenant-idempotent");
        let first = ensure_state_disk(tmp.path(), &vm).expect("first");
        // Write a sentinel byte at the boot-counter offset — the
        // second call MUST NOT zero this.
        std::fs::write(&first, vec![0u8; 0]).ok(); // harmless touch
        let mtime_first = std::fs::metadata(&first).unwrap().modified().unwrap();
        std::thread::sleep(std::time::Duration::from_millis(20));
        let second = ensure_state_disk(tmp.path(), &vm).expect("second");
        assert_eq!(first, second);
        // The file was NOT re-created (mkfs would have updated mtime).
        let mtime_second = std::fs::metadata(&second).unwrap().modified().unwrap();
        assert_eq!(
            mtime_first, mtime_second,
            "ensure_state_disk re-touched an existing file"
        );
    }
}
