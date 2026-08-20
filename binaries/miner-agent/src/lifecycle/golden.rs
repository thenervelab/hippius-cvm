//! GOLDEN-mode (golden-bake PR3) miner-agent building blocks: the
//! order-cmdline golden detector + the per-VM **overlay UPPER** disk
//! provisioner.
//!
//! ## What golden mode changes for the miner-agent
//!
//! In LEGACY mode `/dev/vda` is a per-VM LUKS2+integrity **baked**
//! qcow2 (the whole tenant OS, fetched from S3 by
//! [`crate::lifecycle::preflight`]). In GOLDEN mode the OS lives on the
//! SHARED read-only dm-verity base (`rootfs.img` on `/dev/vdb` +
//! `rootfs.verity` on `/dev/vdc`, cache-HITs across same-distro
//! tenants), and `/dev/vda` becomes a **blank per-VM overlay upper**:
//! the guest `luksFormat`s it with a master key generated INSIDE the
//! SNP boundary at first boot and mounts overlayfs (lower = RO verity,
//! upper = this disk) — see `scripts/initramfs/hippius-golden-overlay.sh`.
//!
//! ## Untrusted-miner invariant (identical to `/dev/vde`)
//!
//! The miner writes NO structure or secret into this file — it is a
//! blank sparse extent. The guest generates the LUKS master key inside
//! SNP (never leaves), and its keyslot is wrapped by the PER-VM KBS
//! KEK (released only to the attested guest, authorized per-VM by the
//! KBS ticket). The MK is NEVER the shared golden key (the golden base
//! is unkeyed dm-verity). `--integrity hmac-sha256` (written by the
//! guest) makes any miner byte-tamper read-fault (EIO). Size is
//! anchored by the MEASURED `hippius.disk_gb=` token, not this file's
//! length: the guest refuses a short disk.
//!
//! ## Golden detection
//!
//! Robust signal, consistent with the vali cmdline emitter (PR2), the
//! guest shell path (`hippius-golden-overlay.sh`) and the Rust guest
//! parser: golden ⇔ the MEASURED order cmdline carries `dm-verity.root=`
//! AND does NOT carry `hippius.luks_header_sha256=`. Requiring BOTH
//! fail-closes on a half-formed cmdline — and the cmdline is folded
//! into the SNP launch digest, so a miner cannot flip a legacy VM into
//! golden.

use std::path::{Path, PathBuf};

use crate::error::{MinerAgentError, Result};
use crate::lifecycle::cvm_handle::VmId;

/// One GiB in bytes — the unit `disk_gb` is expressed in.
const GIB: u64 = 1024 * 1024 * 1024;

/// Subdirectory under `MINER_ROOT` that holds per-VM overlay upper
/// disks. Co-located with — but separate from — `data/`, `state/` and
/// staging so a `find`-based GC sweep can target each independently.
const OVERLAY_DIR_NAME: &str = "overlay";

/// The cmdline token that signals a golden verity base is bound.
const CMDLINE_VERITY_ROOT: &str = "dm-verity.root";
/// The cmdline token whose PRESENCE marks a legacy per-VM LUKS root.
const CMDLINE_LUKS_HEADER: &str = "hippius.luks_header_sha256";

/// Whitespace-delimited `key=` presence check on a cmdline string.
/// Matches only a full `key=` token (never a suffix of another token).
fn cmdline_has_key(cmdline: &str, key: &str) -> bool {
    let prefix = format!("{key}=");
    cmdline
        .split_whitespace()
        .any(|tok| tok.starts_with(&prefix))
}

/// Is this launch order a GOLDEN-mode boot?
///
/// golden ⇔ `dm-verity.root=` PRESENT and `hippius.luks_header_sha256=`
/// ABSENT. Both conditions required (fail-closed on a half-formed
/// cmdline). The cmdline is SNP-measured, so this decision is
/// tamper-evident.
pub fn is_golden_cmdline(cmdline: &str) -> bool {
    cmdline_has_key(cmdline, CMDLINE_VERITY_ROOT) && !cmdline_has_key(cmdline, CMDLINE_LUKS_HEADER)
}

/// Compute the on-host path for a tenant's overlay upper disk, without
/// creating it. Used by config-rendering paths that need the path to
/// interpolate into the libvirt XML (the golden `/dev/vda` source).
pub fn overlay_disk_path(miner_root: &Path, vm_id: &VmId) -> PathBuf {
    miner_root
        .join(OVERLAY_DIR_NAME)
        .join(format!("{vm_id}.img"))
}

/// Idempotent creation: ensure a blank sparse `size_gb` GiB overlay
/// upper disk exists for `vm_id` under `miner_root`; return its path.
/// If the file already exists the path is returned verbatim — NO
/// re-create, so the tenant's overlay writes persist across launches of
/// the same `vm_id` (reboot / re-place / relaunch).
///
/// This is byte-for-byte the discipline of
/// [`crate::lifecycle::data_disk::ensure_data_disk`]: `O_CREAT|O_EXCL`
/// against racing launches, a `statvfs` free-space pre-check so an
/// over-committed miner is rejected BEFORE dispatch, a SPARSE
/// `set_len` (no `mkfs`/`luksFormat` — the guest formats fresh with a
/// key the miner never sees), and partial-file cleanup on failure.
pub fn ensure_overlay_disk(miner_root: &Path, vm_id: &VmId, size_gb: u32) -> Result<PathBuf> {
    let bytes = (size_gb as u64)
        .checked_mul(GIB)
        .ok_or(MinerAgentError::OverlayDisk("size-overflow"))?;
    ensure_overlay_disk_bytes(miner_root, vm_id, bytes)
}

/// Byte-granular core of [`ensure_overlay_disk`]. Production always
/// enters through the GiB-denominated wrapper (the flavor's `disk_gb` is
/// the only size the miner is ever handed); this exists so the allocator
/// — **free-space pre-check included** — can be driven by tests at a
/// few-MiB fixture size that fits on any runner, instead of demanding a
/// spare GiB of real disk from CI. It is the same code path, not a stub:
/// the `statvfs` gate below runs identically for a 4 MiB ask and a
/// 256 GiB one.
pub(crate) fn ensure_overlay_disk_bytes(
    miner_root: &Path,
    vm_id: &VmId,
    bytes: u64,
) -> Result<PathBuf> {
    if bytes == 0 {
        return Err(MinerAgentError::OverlayDisk("size-zero"));
    }

    let path = overlay_disk_path(miner_root, vm_id);
    if path.exists() {
        return Ok(path);
    }

    let parent = path
        .parent()
        .ok_or(MinerAgentError::OverlayDisk("no-parent"))?;
    std::fs::create_dir_all(parent).map_err(|_| MinerAgentError::OverlayDisk("mkdir"))?;

    // Free-space pre-check on the backing mount (the physical free
    // space cannot be faked, so this does not trust the miner). A
    // sparse `set_len` would otherwise surface ENOSPC mid-format on the
    // live guest instead of failing closed here at admission.
    let free = free_bytes(parent)?;
    if free < bytes {
        return Err(MinerAgentError::OverlayDisk("insufficient-space"));
    }

    // O_CREAT | O_EXCL — racing callers fail-closed on AlreadyExists,
    // which then becomes the idempotent "exists" branch on retry.
    let file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path)
        .map_err(|e| match e.kind() {
            std::io::ErrorKind::AlreadyExists => MinerAgentError::OverlayDisk("race"),
            _ => MinerAgentError::OverlayDisk("create"),
        })?;

    if let Err(e) = file.set_len(bytes) {
        let _ = std::fs::remove_file(&path);
        let _ = e; // closed-vocabulary discipline: only the static tag surfaces.
        return Err(MinerAgentError::OverlayDisk("truncate"));
    }
    Ok(path)
}

/// Bytes available to an unprivileged writer on the filesystem backing
/// `dir` (`statvfs` `f_bavail * f_frsize`). Mirrors
/// [`crate::lifecycle::data_disk`]'s `free_bytes`.
fn free_bytes(dir: &Path) -> Result<u64> {
    let st =
        nix::sys::statvfs::statvfs(dir).map_err(|_| MinerAgentError::OverlayDisk("statvfs"))?;
    #[allow(clippy::useless_conversion)]
    let avail = u64::try_from(st.blocks_available()).unwrap_or(0);
    #[allow(clippy::useless_conversion)]
    let frsize = u64::try_from(st.fragment_size()).unwrap_or(0);
    Ok(avail.saturating_mul(frsize))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn vm(id: &str) -> VmId {
        VmId::new(id).expect("valid vm id")
    }

    const HASH64: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    /// Fixture size for the happy-path allocator tests. A few MiB proves
    /// exactly what a GiB would — sparse `set_len`, idempotency, and the
    /// `overlay/` placement — without asking CI for a spare GiB of free
    /// disk. Sizing the fixture to a REALISTIC disk was the source of an
    /// environmental red on the required `rust` job; the
    /// insufficient-space branch is still covered, deliberately, by
    /// `ensure_rejects_more_than_the_mount_actually_has_free` below.
    const FIXTURE_BYTES: u64 = 4 * 1024 * 1024;

    // ── golden detection ────────────────────────────────────────────
    #[test]
    fn golden_cmdline_requires_verity_root_and_no_luks_header() {
        let golden =
            format!("ro quiet dm-verity.root={HASH64} hippius.disk_gb=10 boot=hippius-golden");
        assert!(is_golden_cmdline(&golden));
    }

    #[test]
    fn legacy_cmdline_is_not_golden() {
        let legacy = format!("ro quiet hippius.luks_header_sha256={HASH64} hippius.disk_gb=10");
        assert!(!is_golden_cmdline(&legacy));
    }

    #[test]
    fn both_tokens_fails_closed_not_golden() {
        // A miner splicing dm-verity.root onto a legacy cmdline to skip
        // the LUKS-header gate must NOT be treated as golden.
        let hostile = format!("ro dm-verity.root={HASH64} hippius.luks_header_sha256={HASH64}");
        assert!(!is_golden_cmdline(&hostile));
    }

    #[test]
    fn bare_cmdline_is_not_golden() {
        assert!(!is_golden_cmdline("ro quiet console=ttyS0"));
    }

    #[test]
    fn key_match_is_full_token_not_suffix() {
        // A token that merely CONTAINS the key as a substring must not
        // match (e.g. a hypothetical `x-dm-verity.root=`).
        assert!(!cmdline_has_key(
            "ro x-dm-verity.root=abc",
            "dm-verity.root"
        ));
        assert!(cmdline_has_key("ro dm-verity.root=abc", "dm-verity.root"));
    }

    // ── overlay upper disk provisioner (mirrors data_disk tests) ─────
    #[test]
    fn path_layout_is_deterministic_per_vm() {
        let root = Path::new("/var/lib/hippius-miner");
        let p = overlay_disk_path(root, &vm("tenant-abc-01"));
        assert_eq!(
            p,
            PathBuf::from("/var/lib/hippius-miner/overlay/tenant-abc-01.img")
        );
    }

    #[test]
    fn path_does_not_create_anything() {
        let tmp = TempDir::new().unwrap();
        let p = overlay_disk_path(tmp.path(), &vm("tenant-no-side-effect"));
        assert!(!p.exists());
        assert!(!tmp.path().join("overlay").exists());
    }

    #[test]
    fn ensure_creates_a_sparse_sized_file() {
        let tmp = TempDir::new().unwrap();
        let path =
            ensure_overlay_disk_bytes(tmp.path(), &vm("tenant-overlay-create"), FIXTURE_BYTES)
                .expect("created");
        assert!(path.exists());
        let meta = std::fs::metadata(&path).unwrap();
        assert_eq!(meta.len(), FIXTURE_BYTES);
        // Sparse: NO blocks allocated on disk — the miner writes nothing
        // into the overlay upper; the guest's `luksFormat` allocates.
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            assert_eq!(
                meta.blocks(),
                0,
                "overlay disk is not sparse: {} blocks allocated",
                meta.blocks()
            );
        }
    }

    #[test]
    fn gib_wrapper_denominates_the_flavor_size_in_gib() {
        // Prove the GiB unit conversion WITHOUT allocating a GiB: ask for
        // just over the mount's free space expressed in GiB. If the
        // wrapper ever passed `size_gb` through as raw BYTES this ask
        // would be a handful of bytes and would succeed.
        let tmp = TempDir::new().unwrap();
        let free = free_bytes(tmp.path()).expect("statvfs");
        let over_free_gb = u32::try_from(free / GIB + 2).expect("free space fits in u32 GiB");
        assert!(matches!(
            ensure_overlay_disk(tmp.path(), &vm("tenant-gib-unit"), over_free_gb),
            Err(MinerAgentError::OverlayDisk("insufficient-space"))
        ));
        assert!(!overlay_disk_path(tmp.path(), &vm("tenant-gib-unit")).exists());
    }

    #[test]
    fn ensure_rejects_zero_size() {
        let tmp = TempDir::new().unwrap();
        assert!(matches!(
            ensure_overlay_disk(tmp.path(), &vm("tenant-zero"), 0),
            Err(MinerAgentError::OverlayDisk("size-zero"))
        ));
    }

    #[test]
    fn ensure_rejects_when_mount_cannot_hold_the_disk() {
        let tmp = TempDir::new().unwrap();
        let huge_gb = 1_000_000_000u32; // ~1 EiB
        assert!(matches!(
            ensure_overlay_disk(tmp.path(), &vm("tenant-too-big"), huge_gb),
            Err(MinerAgentError::OverlayDisk("insufficient-space"))
        ));
        assert!(!overlay_disk_path(tmp.path(), &vm("tenant-too-big")).exists());
    }

    #[test]
    fn ensure_rejects_more_than_the_mount_actually_has_free() {
        // The tight mutation target for the free-space pre-check. The ask
        // is derived from the REAL `statvfs` free space of this mount and
        // then overshot, so it is insufficient DELIBERATELY rather than
        // by accident of a full runner — and it stays insufficient on a
        // machine with terabytes free.
        //
        // Delete the `free < bytes` gate from `ensure_overlay_disk_bytes`
        // and this test fails: a sparse `set_len` of a size the mount
        // cannot back succeeds happily, and the miner accepts a placement
        // it cannot back with real bytes.
        let tmp = TempDir::new().unwrap();
        let over_free = free_bytes(tmp.path())
            .expect("statvfs")
            .saturating_add(64 * GIB);
        assert!(matches!(
            ensure_overlay_disk_bytes(tmp.path(), &vm("tenant-over-free"), over_free),
            Err(MinerAgentError::OverlayDisk("insufficient-space"))
        ));
        assert!(!overlay_disk_path(tmp.path(), &vm("tenant-over-free")).exists());
    }

    #[test]
    fn ensure_is_idempotent_and_preserves_data() {
        let tmp = TempDir::new().unwrap();
        let vm = vm("tenant-overlay-idempotent");
        let first = ensure_overlay_disk_bytes(tmp.path(), &vm, FIXTURE_BYTES).expect("first");
        let before = std::fs::metadata(&first).unwrap().modified().unwrap();
        std::thread::sleep(std::time::Duration::from_millis(20));
        // A second ensure with a DIFFERENT (and much larger) size must
        // return the existing file untouched — never re-create a disk
        // that may hold tenant overlay writes. 256 GiB also proves the
        // early-return happens BEFORE the free-space gate.
        let second = ensure_overlay_disk(tmp.path(), &vm, 256).expect("second");
        assert_eq!(first, second);
        let after = std::fs::metadata(&second).unwrap().modified().unwrap();
        assert_eq!(std::fs::metadata(&second).unwrap().len(), FIXTURE_BYTES);
        assert_eq!(
            before, after,
            "ensure_overlay_disk re-touched an existing file"
        );
    }
}
