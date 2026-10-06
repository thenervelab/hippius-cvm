//! Per-VM tenant **data disk** — a blank sparse raw image the miner
//! attaches at the flavor's `disk_gb` size, formatted fresh inside the
//! guest at first boot (#365).
//!
//! ## Why a separate disk (and why blank)
//!
//! `--integrity hmac-sha256` makes a LUKS2 volume **un-growable**:
//! `cryptsetup resize` refuses an integrity-protected device outright,
//! so the original "bake minimal + grow at first boot" plan is dead.
//! Instead the rootfs (`/dev/vda`) stays a fixed, measured minimal
//! image, and bigger flavors get their space from a SECOND disk
//! (`/dev/vde`) the miner creates **blank** at `disk_gb` and the guest
//! formats fresh — a plain `luksFormat --integrity`, never a resize.
//!
//! The miner writes NO bytes of structure or secret into this file: it
//! is a sparse zero-filled extent. The guest generates the data-disk
//! key inside the SNP boundary, seals it on the (already confidential)
//! encrypted rootfs, and writes every dm-integrity HMAC tag itself — so
//! a miner who tampers any byte of this file makes the guest read fault
//! (EIO), exactly like the rootfs. Nothing here is trusted.
//!
//! ## Size anchoring
//!
//! The size is NOT trusted from this file's length: the guest enforces
//! the attested `hippius.disk_gb=` cmdline token (folded into the
//! SEV-SNP launch measurement) against the block device it is handed,
//! and refuses a short disk. The miner creating a wrong-sized file can
//! only make the guest fail visibly.
//!
//! ## File layout
//!
//! Per-VM file at `MINER_ROOT/data/{vm_id}.img`, exactly `disk_gb` GiB,
//! sparse (no blocks allocated until the guest's first-boot integrity
//! wipe writes them). Idempotent: a subsequent call for the same
//! `vm_id` returns the existing path WITHOUT re-creating it, so the
//! tenant's data survives a stop/relaunch of the same `vm_id`.
//!
//! ## §20 secret discipline
//!
//! No secret bytes touch this module. Every error carries a
//! closed-vocabulary `&'static str` sub-classifier; paths and lengths
//! are never interpolated.

use std::path::{Path, PathBuf};

use crate::error::{MinerAgentError, Result};
use crate::lifecycle::cvm_handle::VmId;
use crate::lifecycle::disk_space;

/// One GiB in bytes — the unit `disk_gb` is expressed in.
const GIB: u64 = 1024 * 1024 * 1024;

/// Subdirectory under `MINER_ROOT` that holds per-VM data disks.
/// Co-located with — but separate from — the `state/` and staging
/// trees so a `find`-based GC sweep can target each independently.
const DATA_DIR_NAME: &str = "data";

/// Compute the on-host path for a tenant's data disk, without creating
/// it. Used by config-rendering paths that need the path to interpolate
/// into the libvirt XML.
pub fn data_disk_path(miner_root: &Path, vm_id: &VmId) -> PathBuf {
    data_dir(miner_root).join(format!("{vm_id}.img"))
}

/// The directory holding every per-VM data disk under `miner_root`.
pub(crate) fn data_dir(miner_root: &Path) -> PathBuf {
    miner_root.join(DATA_DIR_NAME)
}

/// Idempotent creation: ensure a blank sparse `size_gb` GiB data disk
/// exists for `vm_id` under `miner_root` and return its path. If the
/// file already exists the path is returned verbatim — NO re-create, so
/// the tenant's data persists across launches of the same `vm_id`.
///
/// Side effects (only when the file is absent):
/// 1. `mkdir -p` the `data/` subdirectory.
/// 2. Create the file with `O_CREAT | O_EXCL` so two racing `launch`
///    calls do not both create the same byte range.
/// 3. `set_len(size_gb * 1 GiB)` to declare the size. On ext4/xfs this
///    is a sparse extent — no blocks are written here; the guest's
///    first-boot integrity format allocates them as it wipes tags.
///
/// The miner deliberately runs **no** `mkfs`/`luksFormat`: the disk is
/// formatted inside the SNP guest with a guest-held key. On any failure
/// the partially-created file is removed so a retry is not poisoned.
pub fn ensure_data_disk(miner_root: &Path, vm_id: &VmId, size_gb: u32) -> Result<PathBuf> {
    let bytes = (size_gb as u64)
        .checked_mul(GIB)
        .ok_or(MinerAgentError::DataDisk("size-overflow"))?;
    ensure_data_disk_bytes(miner_root, vm_id, bytes)
}

/// Byte-granular core of [`ensure_data_disk`]. Production always enters
/// through the GiB-denominated wrapper (the flavor's `disk_gb` is the
/// only size the miner is ever handed); this exists so the allocator —
/// **free-space pre-check included** — can be driven by tests at a
/// few-MiB fixture size that fits on any runner, instead of demanding a
/// spare GiB of real disk from CI. It is the same code path, not a stub:
/// the `statvfs` gate below runs identically for a 4 MiB ask and a
/// 256 GiB one.
pub(crate) fn ensure_data_disk_bytes(
    miner_root: &Path,
    vm_id: &VmId,
    bytes: u64,
) -> Result<PathBuf> {
    if bytes == 0 {
        return Err(MinerAgentError::DataDisk("size-zero"));
    }

    let path = data_disk_path(miner_root, vm_id);
    if path.exists() {
        return Ok(path);
    }

    // `data_disk_path` always returns `{root}/data/{vm_id}.img`, so
    // `parent()` is always `Some({root}/data)`.
    let parent = path
        .parent()
        .ok_or(MinerAgentError::DataDisk("no-parent"))?;
    std::fs::create_dir_all(parent).map_err(|_| MinerAgentError::DataDisk("mkdir"))?;

    // Free-space pre-check. The file is created SPARSE (`set_len`), so
    // ENOSPC does NOT surface here — it surfaces minutes later when the
    // GUEST writes the dm-integrity format, as a mid-format pause on the
    // live VM (observed live). Check the backing mount has room for the
    // whole disk up front, so an over-committed / over-declared miner is
    // rejected cleanly (`insufficient-disk`) BEFORE the VM is dispatched.
    // "Room" is the free space net of the unwritten tail of every
    // writable disk already there and of every in-flight writer's
    // reservation (backup, restore, §25 download), measured under the
    // process-wide disk lock — so neither a concurrent launch, a
    // half-written VM nor a running backup can be promised the same bytes
    // (`disk_space`). The lock is held through the
    // create below so the next measurer sees this file.
    let reserved = disk_space::create_lock();
    if path.exists() {
        return Ok(path);
    }
    let headroom = disk_space::headroom_bytes(*reserved, miner_root, parent)
        .map_err(MinerAgentError::DataDisk)?;
    if headroom < bytes {
        return Err(MinerAgentError::DataDisk("insufficient-space"));
    }

    // O_CREAT | O_EXCL — racing callers fail-closed on AlreadyExists,
    // which then becomes the idempotent "exists" branch on retry.
    let file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path)
        .map_err(|e| match e.kind() {
            std::io::ErrorKind::AlreadyExists => MinerAgentError::DataDisk("race"),
            _ => MinerAgentError::DataDisk("create"),
        })?;

    if let Err(e) = file.set_len(bytes) {
        let _ = std::fs::remove_file(&path);
        // `e` may carry the OS errno; the closed-vocabulary discipline
        // only surfaces the static classifier.
        let _ = e;
        return Err(MinerAgentError::DataDisk("truncate"));
    }
    Ok(path)
}

/// Bytes currently available to an unprivileged writer on the filesystem
/// backing `dir` (`statvfs` `f_bavail * f_frsize`) — the raw figure,
/// before [`disk_space::headroom_bytes`] nets out the sparse tails.
#[cfg(test)]
fn free_bytes(dir: &Path) -> Result<u64> {
    disk_space::fs_bytes(dir)
        .map(|(_, avail)| avail)
        .ok_or(MinerAgentError::DataDisk("statvfs"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn vm(id: &str) -> VmId {
        VmId::new(id).expect("valid vm id")
    }

    /// Fixture size for the happy-path allocator tests. A few MiB proves
    /// exactly what a GiB would — sparse `set_len`, idempotency, and the
    /// `overlay/` vs `data/` separation — without asking CI for a spare
    /// GiB of free disk. Sizing the fixture to a REALISTIC disk was the
    /// source of an environmental red on the required `rust` job; the
    /// insufficient-space branch is still covered, deliberately, by
    /// `ensure_rejects_more_than_the_mount_actually_has_free` below.
    const FIXTURE_BYTES: u64 = 4 * 1024 * 1024;

    #[test]
    fn path_layout_is_deterministic_per_vm() {
        let root = Path::new("/var/lib/hippius-miner");
        let p = data_disk_path(root, &vm("tenant-abc-01"));
        assert_eq!(
            p,
            PathBuf::from("/var/lib/hippius-miner/data/tenant-abc-01.img")
        );
    }

    #[test]
    fn path_does_not_create_anything() {
        let tmp = TempDir::new().unwrap();
        let p = data_disk_path(tmp.path(), &vm("tenant-no-side-effect"));
        assert!(!p.exists());
        assert!(!tmp.path().join("data").exists());
    }

    #[test]
    fn ensure_creates_a_sparse_sized_file() {
        let tmp = TempDir::new().unwrap();
        let path = ensure_data_disk_bytes(tmp.path(), &vm("tenant-data-create"), FIXTURE_BYTES)
            .expect("created");
        assert!(path.exists());
        let meta = std::fs::metadata(&path).unwrap();
        // Logical size is exactly what was asked for ...
        assert_eq!(meta.len(), FIXTURE_BYTES);
        // ... but it is sparse: NO blocks allocated on disk (the miner
        // wrote nothing; the guest allocates them on its integrity wipe).
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            assert_eq!(
                meta.blocks(),
                0,
                "data disk is not sparse: {} blocks allocated",
                meta.blocks()
            );
        }
    }

    #[test]
    fn gib_wrapper_denominates_the_flavor_size_in_gib() {
        // The production entrypoint is GiB-denominated. Prove the unit
        // conversion WITHOUT allocating a GiB: ask for just over the
        // mount's free space expressed in GiB. If the wrapper ever passed
        // `size_gb` through as raw BYTES, this ask would be a handful of
        // bytes, comfortably fit, and the call would succeed.
        let tmp = TempDir::new().unwrap();
        let free = free_bytes(tmp.path()).expect("statvfs");
        let over_free_gb = u32::try_from(free / GIB + 2).expect("free space fits in u32 GiB");
        assert!(matches!(
            ensure_data_disk(tmp.path(), &vm("tenant-gib-unit"), over_free_gb),
            Err(MinerAgentError::DataDisk("insufficient-space"))
        ));
        assert!(!data_disk_path(tmp.path(), &vm("tenant-gib-unit")).exists());
    }

    #[test]
    fn ensure_rejects_zero_size() {
        let tmp = TempDir::new().unwrap();
        assert!(matches!(
            ensure_data_disk(tmp.path(), &vm("tenant-zero"), 0),
            Err(MinerAgentError::DataDisk("size-zero"))
        ));
    }

    #[test]
    fn ensure_rejects_when_mount_cannot_hold_the_disk() {
        // A size larger than any real filesystem → the statvfs pre-check
        // fails closed BEFORE creating anything (no sparse file, no
        // ENOSPC-mid-format on a live guest). This is what catches a
        // miner that accepted a placement its disk can't honour.
        let tmp = TempDir::new().unwrap();
        let huge_gb = 1_000_000_000u32; // ~1 EiB
        assert!(matches!(
            ensure_data_disk(tmp.path(), &vm("tenant-too-big"), huge_gb),
            Err(MinerAgentError::DataDisk("insufficient-space"))
        ));
        // Nothing was created on the rejected path.
        assert!(!data_disk_path(tmp.path(), &vm("tenant-too-big")).exists());
    }

    #[test]
    fn ensure_rejects_more_than_the_mount_actually_has_free() {
        // The tight mutation target for the free-space pre-check. The ask
        // is derived from the REAL `statvfs` free space of this mount and
        // then overshot, so it is insufficient DELIBERATELY rather than
        // by accident of a full runner — and it stays insufficient on a
        // machine with terabytes free.
        //
        // Delete the `free < bytes` gate from `ensure_data_disk_bytes` and
        // this test fails: a sparse `set_len` of a size the mount cannot
        // back succeeds happily, which is precisely the bug the gate
        // exists to prevent (ENOSPC mid-format on a live guest instead of
        // a clean pre-dispatch refusal).
        let tmp = TempDir::new().unwrap();
        let over_free = free_bytes(tmp.path())
            .expect("statvfs")
            .saturating_add(64 * GIB);
        assert!(matches!(
            ensure_data_disk_bytes(tmp.path(), &vm("tenant-over-free"), over_free),
            Err(MinerAgentError::DataDisk("insufficient-space"))
        ));
        assert!(!data_disk_path(tmp.path(), &vm("tenant-over-free")).exists());
    }

    /// A sparse file under `<root>/data/` that promises all but
    /// `leave_bytes` of the filesystem's current free space.
    fn promise_all_but(root: &Path, name: &str, leave_bytes: u64) {
        let free = free_bytes(root).expect("statvfs");
        std::fs::create_dir_all(data_dir(root)).unwrap();
        let f = std::fs::File::create(data_dir(root).join(name)).unwrap();
        f.set_len(free.saturating_sub(leave_bytes)).unwrap();
    }

    #[test]
    fn a_second_disk_is_measured_against_the_first_ones_promise() {
        let _tight = disk_space::tight_tests();
        // 1.5 GiB of real headroom: one 1 GiB sparse disk fits, a second
        // does not — though a bare statvfs still shows the same free space
        // after the first create (it allocated nothing). The 512 MiB margin
        // absorbs concurrent tests' writes on the same filesystem.
        let tmp = TempDir::new().unwrap();
        promise_all_but(tmp.path(), "filler.img", 3 << 29);
        ensure_data_disk_bytes(tmp.path(), &vm("tenant-first"), 1 << 30).expect("the first fits");
        assert!(matches!(
            ensure_data_disk_bytes(tmp.path(), &vm("tenant-second"), 1 << 30),
            Err(MinerAgentError::DataDisk("insufficient-space"))
        ));
        assert!(!data_disk_path(tmp.path(), &vm("tenant-second")).exists());
    }

    #[test]
    fn a_create_waits_for_the_create_lock_and_measures_after_it() {
        // Concurrent creates are serialised: while another create holds the
        // lock this one neither measures nor creates, and once it runs it
        // sees what the holder promised in the meantime.
        let tmp = TempDir::new().unwrap();
        let root = tmp.path().to_path_buf();
        let held = disk_space::create_lock();
        let waiter = {
            let root = root.clone();
            std::thread::spawn(move || ensure_data_disk(&root, &vm("tenant-waiter"), 1))
        };
        std::thread::sleep(std::time::Duration::from_millis(200));
        assert!(!waiter.is_finished(), "the create ran past a held lock");
        assert!(!data_disk_path(&root, &vm("tenant-waiter")).exists());
        // What the lock holder promises before releasing it…
        promise_all_but(&root, "holder.img", 0);
        drop(held);
        // …is what the waiter is measured against.
        assert!(matches!(
            waiter.join().unwrap(),
            Err(MinerAgentError::DataDisk("insufficient-space"))
        ));
    }

    #[test]
    fn ensure_is_idempotent_and_preserves_data() {
        let tmp = TempDir::new().unwrap();
        let vm = vm("tenant-data-idempotent");
        let first = ensure_data_disk_bytes(tmp.path(), &vm, FIXTURE_BYTES).expect("first");
        // Simulate guest-written data: poke a sentinel byte in.
        std::fs::write(tmp.path().join("data").join("sentinel"), b"x").ok();
        let before = std::fs::metadata(&first).unwrap().modified().unwrap();
        std::thread::sleep(std::time::Duration::from_millis(20));
        // A second ensure for the same vm with a DIFFERENT (and much
        // larger) size must still return the existing file untouched —
        // never re-create / re-truncate a disk that may hold tenant data.
        // 256 GiB also proves the early-return happens BEFORE the
        // free-space gate: an existing disk is never re-admitted.
        let second = ensure_data_disk(tmp.path(), &vm, 256).expect("second");
        assert_eq!(first, second);
        let after = std::fs::metadata(&second).unwrap().modified().unwrap();
        assert_eq!(std::fs::metadata(&second).unwrap().len(), FIXTURE_BYTES);
        assert_eq!(
            before, after,
            "ensure_data_disk re-touched an existing file"
        );
    }
}
