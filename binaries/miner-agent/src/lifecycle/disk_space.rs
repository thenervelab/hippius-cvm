//! Measured disk-space admission — the ONE ledger of this host's disk.
//!
//! The per-VM data disk (`data/<vm>.img`, legacy `/dev/vde`) and golden
//! overlay upper (`overlay/<vm>.img`, `/dev/vda`) are created SPARSE: a
//! `set_len` reserves nothing on the filesystem, and the space is consumed
//! only later, as the guest writes. A bare `statvfs` free-space check at
//! create time therefore sees neither the disks created a moment ago by a
//! concurrent launch nor the unwritten part of every disk already running,
//! and two launches (or one launch next to a half-written VM) could both be
//! admitted onto space that exists once. The same holds for every other
//! writer of this filesystem — backup targets, restore stagings, §25
//! snapshot downloads — which fill their files over minutes.
//!
//! This module closes that with a single account:
//!
//! - [`headroom_bytes`] is the filesystem's free space MINUS the unwritten
//!   tail (apparent size − allocated blocks) of every writable disk already
//!   on it, i.e. what is left after every existing disk is fully written —
//!   thick-provisioning semantics measured from the files themselves, not
//!   from anything the agent believes about them — MINUS the bytes the
//!   in-flight writers hold reserved;
//! - [`create_lock`] is that reserved-bytes counter behind the process-wide
//!   lock. It serialises the check-then-create of the sparse disks (the
//!   second of two concurrent creates measures the first one's file) and
//!   every reservation of the backup/restore
//!   [`SpaceLedger`](crate::backup::capture::SpaceLedger) and the §25
//!   download, so no two writers can count the same free blocks.
//!
//! Nothing here is trusted by vali: a miner can edit this code. It is the
//! miner's own fail-closed backstop, so an honest but over-committed host
//! refuses a launch cleanly (`insufficient-disk`) instead of pausing a live
//! guest on `ENOSPC` minutes into its dm-integrity format.

use std::os::unix::fs::MetadataExt;
use std::path::Path;
use std::sync::{Mutex, MutexGuard};

use super::{data_disk, golden};

/// Bytes reserved by in-flight writers (backup targets, restore stagings,
/// §25 downloads) on this host, behind the lock that also serialises every
/// "is there room? → create the sparse file" sequence of the per-VM
/// writable disks. Process-wide because the filesystem is.
static HOST_RESERVED: Mutex<u64> = Mutex::new(0);

/// Take the process-wide disk lock; the guard is the reserved-bytes
/// counter. A poisoned lock is recovered: every update of the counter is a
/// single saturating add or subtract, never left half-done.
pub(crate) fn create_lock() -> MutexGuard<'static, u64> {
    HOST_RESERVED
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// `statvfs` of the filesystem backing `dir`, as `(total, available)`
/// bytes (`f_blocks`/`f_bavail` × `f_frsize`). `None` if it can't be read.
pub(crate) fn fs_bytes(dir: &Path) -> Option<(u64, u64)> {
    let st = nix::sys::statvfs::statvfs(dir).ok()?;
    // `fsblkcnt_t`/`c_ulong` are u64 on this target (clippy's
    // useless-conversion) but narrower on 32-bit libc; keep the portable
    // conversion.
    #[allow(clippy::useless_conversion)]
    let frsize = u64::try_from(st.fragment_size()).unwrap_or(0);
    #[allow(clippy::useless_conversion)]
    let total = u64::try_from(st.blocks()).unwrap_or(0);
    #[allow(clippy::useless_conversion)]
    let avail = u64::try_from(st.blocks_available()).unwrap_or(0);
    Some((total.saturating_mul(frsize), avail.saturating_mul(frsize)))
}

/// Bytes the per-VM writable disks under `miner_root` that live on device
/// `dev` have been promised but not yet written: Σ max(0, apparent size −
/// allocated bytes) over the `*.img` files of the data and overlay
/// directories. Only `*.img`: a `.img.part` download is written in full
/// (its space is a reservation, not a tail), and a retained
/// `.img.pre-restore-*` original is charged what it holds, not what it
/// could grow to — only the disk at `<vm>.img` is attached to a guest. A
/// missing directory contributes 0; any other listing failure is `None`
/// (the caller fails closed).
pub(crate) fn unwritten_tail_bytes(miner_root: &Path, dev: u64) -> Option<u64> {
    let mut total: u64 = 0;
    for dir in [
        data_disk::data_dir(miner_root),
        golden::overlay_dir(miner_root),
    ] {
        let entries = match std::fs::read_dir(&dir) {
            Ok(entries) => entries,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(_) => return None,
        };
        for entry in entries {
            let Ok(entry) = entry else { return None };
            if entry.path().extension().is_none_or(|ext| ext != "img") {
                continue;
            }
            // A file removed between the listing and the stat (a §24
            // reclaim) holds no space any more — skip it.
            let Ok(meta) = entry.metadata() else { continue };
            if !meta.is_file() || meta.dev() != dev {
                continue;
            }
            // `st_blocks` is always in 512-byte units.
            let allocated = meta.blocks().saturating_mul(512);
            total = total.saturating_add(meta.len().saturating_sub(allocated));
        }
    }
    Some(total)
}

/// Free space on the filesystem backing `dir` once every writable disk
/// under `miner_root` on that filesystem is fully written and every
/// `reserved` byte (the [`create_lock`] counter, read under that lock) is
/// used. `Err` is the failure class: `statvfs` when the filesystem can't
/// be measured, `disk-list` when the disks on it can't be listed.
pub(crate) fn headroom_bytes(
    reserved: u64,
    miner_root: &Path,
    dir: &Path,
) -> Result<u64, &'static str> {
    let (_, avail) = fs_bytes(dir).ok_or("statvfs")?;
    let dev = std::fs::metadata(dir).map_err(|_| "statvfs")?.dev();
    let tail = unwritten_tail_bytes(miner_root, dev).ok_or("disk-list")?;
    Ok(avail.saturating_sub(tail).saturating_sub(reserved))
}

/// Taken by the tests whose free-space margin is tight (≤ a few GiB), and
/// by the one test that holds a GiB-scale reservation in the host counter
/// every create reads — so that reservation cannot fail them.
#[cfg(test)]
pub(crate) static TIGHT_TESTS: Mutex<()> = Mutex::new(());

#[cfg(test)]
pub(crate) fn tight_tests() -> MutexGuard<'static, ()> {
    TIGHT_TESTS
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn dev_of(p: &Path) -> u64 {
        std::fs::metadata(p).unwrap().dev()
    }

    #[test]
    fn a_sparse_disk_counts_its_whole_unwritten_tail() {
        let tmp = TempDir::new().unwrap();
        let data = data_disk::data_dir(tmp.path());
        std::fs::create_dir_all(&data).unwrap();
        let f = std::fs::File::create(data.join("vm-a.img")).unwrap();
        f.set_len(64 * 1024 * 1024).unwrap();
        let tail = unwritten_tail_bytes(tmp.path(), dev_of(tmp.path())).unwrap();
        // All of it is a hole (a filesystem may allocate a block or two of
        // metadata, never the whole extent).
        assert!(tail > 60 * 1024 * 1024, "tail = {tail}");
    }

    #[test]
    fn written_bytes_leave_the_tail() {
        use std::io::Write;
        let tmp = TempDir::new().unwrap();
        let overlay = golden::overlay_dir(tmp.path());
        std::fs::create_dir_all(&overlay).unwrap();
        let mut f = std::fs::File::create(overlay.join("vm-b.img")).unwrap();
        f.write_all(&vec![0xA5u8; 8 * 1024 * 1024]).unwrap();
        f.sync_all().unwrap();
        f.set_len(16 * 1024 * 1024).unwrap();
        let tail = unwritten_tail_bytes(tmp.path(), dev_of(tmp.path())).unwrap();
        // 16 MiB apparent, 8 MiB written → ~8 MiB of tail, not 16.
        assert!(tail <= 8 * 1024 * 1024, "tail = {tail}");
        assert!(tail > 7 * 1024 * 1024, "tail = {tail}");
    }

    #[test]
    fn no_disk_directories_is_zero_tail() {
        let tmp = TempDir::new().unwrap();
        assert_eq!(
            unwritten_tail_bytes(tmp.path(), dev_of(tmp.path())),
            Some(0)
        );
    }

    #[test]
    fn headroom_is_free_space_minus_the_tail() {
        let tmp = TempDir::new().unwrap();
        let (_, before) = fs_bytes(tmp.path()).unwrap();
        let data = data_disk::data_dir(tmp.path());
        std::fs::create_dir_all(&data).unwrap();
        let f = std::fs::File::create(data.join("vm-c.img")).unwrap();
        f.set_len(1 << 40).unwrap();
        let headroom = headroom_bytes(0, tmp.path(), tmp.path()).unwrap();
        // A 1 TiB promise on the same filesystem must eat (almost) the whole
        // headroom the free space showed — a bare statvfs would not move.
        assert!(
            headroom <= before.saturating_sub((1 << 40) - (1 << 20)),
            "headroom {headroom} before {before}"
        );
    }

    #[test]
    fn only_attached_disk_names_count_as_tail() {
        // A `.part` download and a retained pre-restore original are not
        // disks a guest can grow into: neither is charged a tail.
        let tmp = TempDir::new().unwrap();
        let overlay = golden::overlay_dir(tmp.path());
        std::fs::create_dir_all(&overlay).unwrap();
        for name in ["vm-d.img.part", "vm-d.img.pre-restore-r1", "notes"] {
            let f = std::fs::File::create(overlay.join(name)).unwrap();
            f.set_len(64 * 1024 * 1024).unwrap();
        }
        assert_eq!(
            unwritten_tail_bytes(tmp.path(), dev_of(tmp.path())),
            Some(0)
        );
    }

    #[test]
    fn disks_on_another_device_are_not_this_filesystems_tail() {
        let tmp = TempDir::new().unwrap();
        let data = data_disk::data_dir(tmp.path());
        std::fs::create_dir_all(&data).unwrap();
        let f = std::fs::File::create(data.join("vm-e.img")).unwrap();
        f.set_len(64 * 1024 * 1024).unwrap();
        let other = dev_of(tmp.path()).wrapping_add(1);
        assert_eq!(unwritten_tail_bytes(tmp.path(), other), Some(0));
    }

    #[test]
    fn reserved_bytes_come_off_the_headroom() {
        let tmp = TempDir::new().unwrap();
        let free = headroom_bytes(0, tmp.path(), tmp.path()).unwrap();
        let held = headroom_bytes(1 << 40, tmp.path(), tmp.path()).unwrap();
        // Up to a little churn from concurrent tests on the same filesystem.
        assert!(
            held <= free.saturating_sub((1 << 40) - (64 << 20)),
            "held {held} free {free}"
        );
    }

    #[test]
    fn an_unmeasurable_filesystem_is_the_statvfs_class() {
        let tmp = TempDir::new().unwrap();
        assert_eq!(
            headroom_bytes(0, tmp.path(), &tmp.path().join("absent")),
            Err("statvfs")
        );
    }

    #[test]
    fn an_unlistable_disk_directory_is_the_disk_list_class() {
        let tmp = TempDir::new().unwrap();
        // `data` exists but is not a directory: not "absent", so not 0.
        std::fs::write(data_disk::data_dir(tmp.path()), b"x").unwrap();
        assert_eq!(headroom_bytes(0, tmp.path(), tmp.path()), Err("disk-list"));
    }
}
