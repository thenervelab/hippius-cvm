//! Stage 8 — write the unwrapped user-data as a NoCloud seed on tmpfs
//! (PR-E1.5, §20 / §21 step 12).
//!
//! §20 pins the cloud-init datasource allow/deny: only
//! `[NoCloud, None]`. Everything else (ConfigDrive, OVF, SMBIOS
//! `seedfrom`, EC2/GCE/Azure metadata, network/block-device probing) is
//! disabled in the measured image — see [`crate::stages::hardening`],
//! which asserts the kernel command line pins `ds=nocloud` so cloud-init
//! never probes an attacker-controlled datasource. This stage only
//! *materialises* the seed; it does not configure cloud-init.
//!
//! The seed MUST live on **tmpfs** (never a miner-backed block device),
//! and MUST be consumed before any writable miner-backed device is
//! mounted. The boot path satisfies the ordering structurally: this is
//! §21 step 12, after the LUKS unlock and before `switch_root`.
//!
//! ## NoCloud layout
//!
//! `<seed_dir>/` is populated with the three standard NoCloud files:
//!
//! - `user-data`   — the unwrapped cloud-init plaintext (the secret).
//! - `meta-data`   — a minimal fixed `instance-id` (cloud-init requires
//!   the file to exist; the per-VM identity binding is already done
//!   cryptographically in §20, so the instance-id is mere bookkeeping).
//! - `vendor-data` — empty (present so cloud-init does not log a
//!   missing-file warning; Hippius ships no vendor-data).
//!
//! Every file is mode `0600`, the directory `0700` — the agent runs as
//! root (uid 0) in the initramfs, so owner-only is root-only.
//!
//! ## tmpfs guard (§20 "never a miner-backed device")
//!
//! [`RealSeedWriter`] statfs-checks that `seed_dir` resolves onto a
//! `tmpfs` filesystem and **fails closed** otherwise — a structural
//! guarantee that the cloud-init plaintext never lands on a miner-backed
//! disk. The check is Linux-only (the magic constant is Linux ABI); a
//! non-Linux dev host skips it (it never performs a real boot, and the
//! pipeline never reaches this stage there — the canned SNP report
//! fails KBS verification far earlier).
//!
//! ## Ownership / secret discipline (§20)
//!
//! [`write_nocloud`] / [`SeedWriter::write_seed`] take `userdata` **by
//! value** so the plaintext [`Zeroizing`] buffer drops (and wipes)
//! inside this stage — the file on tmpfs is then the only remaining
//! copy until cloud-init reads it (and the §F shutdown path unmounts +
//! discards the tmpfs). `switch_root` (`execve(2)`) does not run
//! destructors, so a by-reference signature would leave `userdata` live
//! in guest RAM across the pivot.
//!
//! The plaintext is **never logged** — not the bytes, not a length.
//! [`AgentError::Seed`] carries only a closed-vocabulary `&'static str`
//! classifier whose `Display` renders the fixed `"seed-failed"` tag.

use crate::pipeline::AgentError;
use core::cell::RefCell;
use std::fs;
use std::io::Write;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::Path;
use zeroize::Zeroizing;

/// Pinned NoCloud seed directory — a fixed path under the `/run` tmpfs
/// the kernel mounts before `/init` runs. cloud-init in the booted
/// rootfs reads its NoCloud datasource from here (`/run` is moved into
/// the new root by `switch_root`, see [`crate::stages::switch_root`]).
pub const NOCLOUD_SEED_DIR: &str = "/run/cloud-init/seed/nocloud-net";

/// Minimal NoCloud `meta-data`. cloud-init requires the file to exist;
/// the per-VM identity is bound cryptographically (§20), so a fixed
/// `instance-id` is sufficient bookkeeping for a single measured boot.
const META_DATA: &str = "instance-id: hippius-cvm\n";

/// Stable classifier strings for [`AgentError::Seed`]. `STATFS` is
/// raised only by the Linux-only tmpfs guard — hence the non-Linux
/// `dead_code` allowance (on Linux every entry is reachable).
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub(crate) mod cat {
    /// `seed_dir` does not resolve onto a `tmpfs` filesystem — writing
    /// the cloud-init plaintext there would risk it landing on a
    /// miner-backed disk (§20). Fail-closed.
    pub(crate) const NOT_TMPFS: &str = "not-tmpfs";
    /// `statfs` on `seed_dir` (or its nearest existing ancestor) failed
    /// — the path is unusable; fail-closed rather than write blind.
    pub(crate) const STATFS: &str = "statfs";
    /// Creating the seed directory failed.
    pub(crate) const MKDIR: &str = "mkdir";
    /// Writing one of the NoCloud files failed.
    pub(crate) const WRITE: &str = "write";
}

/// Source of NoCloud-seed writes.
///
/// Production: [`RealSeedWriter`] (tmpfs guard + real file I/O). Tests:
/// [`MockSeedWriter`]. Mirrors [`crate::stages::unlock::LuksUnlocker`] —
/// the §21 pipeline holds this as `&dyn SeedWriter`.
pub trait SeedWriter {
    /// Materialise the NoCloud seed under `seed_dir`.
    ///
    /// `userdata` is the unwrapped cloud-init plaintext, taken **by
    /// value** so its [`Zeroizing`] wipe fires inside the implementation
    /// — see the module "Ownership / secret discipline" docs.
    ///
    /// Fail-closed: any error (non-tmpfs target, mkdir, write) is
    /// terminal; there is no fallback path.
    fn write_seed(&self, seed_dir: &str, userdata: Zeroizing<Vec<u8>>) -> Result<(), AgentError>;
}

/// Stage entry function — write the NoCloud seed via `writer`.
///
/// A thin forwarder kept for parity with the other §21 stage modules.
/// `userdata` is moved straight through into [`SeedWriter::write_seed`],
/// where it is dropped + wiped.
pub fn write_nocloud(
    writer: &dyn SeedWriter,
    seed_dir: &str,
    userdata: Zeroizing<Vec<u8>>,
) -> Result<(), AgentError> {
    writer.write_seed(seed_dir, userdata)
}

/// Production [`SeedWriter`] — tmpfs guard + real file I/O.
///
/// Zero-sized: the seed directory is supplied per call, so the writer
/// carries no state. Mirrors [`crate::stages::luks_cryptsetup::RealLuksUnlocker`].
#[derive(Debug, Default)]
pub struct RealSeedWriter;

impl RealSeedWriter {
    /// Construct a writer. No-op (the type is stateless); kept as an
    /// explicit entry point for parity with the other stage providers.
    pub fn new() -> Self {
        Self
    }
}

impl SeedWriter for RealSeedWriter {
    fn write_seed(&self, seed_dir: &str, userdata: Zeroizing<Vec<u8>>) -> Result<(), AgentError> {
        // §20 tmpfs guard — refuse to write the plaintext anywhere that
        // is not memory-backed. Linux-only (the fs-magic constants are
        // Linux ABI); see the module docs for the non-Linux rationale.
        #[cfg(target_os = "linux")]
        ensure_memory_backed(Path::new(seed_dir))?;

        write_seed_files(Path::new(seed_dir), &userdata)
        // `userdata` (a `Zeroizing<Vec<u8>>`) drops here → the cloud-init
        // plaintext is wiped from the heap before control returns to the
        // pipeline, well before `switch_root`'s `execve(2)`.
    }
}

/// Write the three NoCloud files under `seed_dir`, creating the
/// directory (`0700`) and each file (`0600`). Pure file I/O — no tmpfs
/// guard — so it is unit-testable with a `tempfile::tempdir()` on any
/// OS; the guard is applied separately by [`RealSeedWriter::write_seed`].
fn write_seed_files(seed_dir: &Path, userdata: &[u8]) -> Result<(), AgentError> {
    fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(seed_dir)
        .map_err(|_| AgentError::Seed(cat::MKDIR))?;
    // `user-data` carries the secret; `meta-data` a fixed instance-id;
    // `vendor-data` is intentionally empty. All mode 0600.
    write_file_0600(&seed_dir.join("user-data"), userdata)?;
    write_file_0600(&seed_dir.join("meta-data"), META_DATA.as_bytes())?;
    write_file_0600(&seed_dir.join("vendor-data"), b"")?;
    Ok(())
}

/// Create `path` mode `0600` (owner-only; the agent is uid 0) and write
/// `contents`. Truncates an existing file. `0600` is set via
/// `OpenOptions::mode` so the file is owner-only from the instant it
/// exists — never a window at a wider mode.
fn write_file_0600(path: &Path, contents: &[u8]) -> Result<(), AgentError> {
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)
        .map_err(|_| AgentError::Seed(cat::WRITE))?;
    file.write_all(contents)
        .map_err(|_| AgentError::Seed(cat::WRITE))?;
    file.sync_all().map_err(|_| AgentError::Seed(cat::WRITE))?;
    Ok(())
}

/// Fail closed unless `dir` (or its nearest existing ancestor, since the
/// seed directory may not exist yet) resolves onto a `tmpfs` filesystem.
/// §20: the cloud-init plaintext must never touch a miner-backed block
/// device. The pinned seed path lives under `/run`, which a measured
/// initramfs always mounts as `tmpfs` — so a `tmpfs`-only check is both
/// correct here and the only memory-backed magic `nix` exposes.
#[cfg(target_os = "linux")]
fn ensure_memory_backed(dir: &Path) -> Result<(), AgentError> {
    use nix::sys::statfs::{statfs, TMPFS_MAGIC};

    // Walk up to the first ancestor that exists on disk — `statfs`
    // needs an extant path, and the seed directory itself is created
    // only after this check passes.
    let mut probe = dir;
    loop {
        if probe.exists() {
            break;
        }
        probe = probe.parent().ok_or(AgentError::Seed(cat::STATFS))?;
    }
    let fs = statfs(probe).map_err(|_| AgentError::Seed(cat::STATFS))?;
    if fs.filesystem_type() == TMPFS_MAGIC {
        Ok(())
    } else {
        Err(AgentError::Seed(cat::NOT_TMPFS))
    }
}

/// Test / non-Linux dev-host stand-in for [`RealSeedWriter`].
///
/// Records the `seed_dir` + the **length** of the user-data of its last
/// call — never the bytes. It consumes `userdata` by value exactly as
/// the real writer does, so the [`Zeroizing`] wipe-on-drop discipline is
/// exercised by the mock too.
pub struct MockSeedWriter {
    /// `Ok(())` ⇒ `write_seed` succeeds; `Err(class)` ⇒ it fails with
    /// `AgentError::Seed(class)`.
    outcome: Result<(), &'static str>,
    /// Last observed call: `(seed_dir, userdata_len)`. Length only — the
    /// bytes are consumed + wiped, never copied out.
    last_call: RefCell<Option<(String, usize)>>,
}

impl MockSeedWriter {
    /// A mock whose `write_seed` succeeds.
    pub fn new() -> Self {
        Self {
            outcome: Ok(()),
            last_call: RefCell::new(None),
        }
    }

    /// A mock whose `write_seed` fails closed with `AgentError::Seed(class)`.
    pub fn failing(class: &'static str) -> Self {
        Self {
            outcome: Err(class),
            last_call: RefCell::new(None),
        }
    }

    /// The `(seed_dir, userdata_len)` of the most recent `write_seed`,
    /// or `None` if it was never called.
    pub fn last_call(&self) -> Option<(String, usize)> {
        self.last_call.borrow().clone()
    }
}

impl Default for MockSeedWriter {
    fn default() -> Self {
        Self::new()
    }
}

impl SeedWriter for MockSeedWriter {
    fn write_seed(&self, seed_dir: &str, userdata: Zeroizing<Vec<u8>>) -> Result<(), AgentError> {
        // Record dir + LENGTH before `userdata` drops. The bytes are
        // never copied out — the mock holds no secret material.
        *self.last_call.borrow_mut() = Some((seed_dir.to_string(), userdata.len()));
        self.outcome.map_err(AgentError::Seed)
        // `userdata` drops here → wiped, even in the mock.
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn write_seed_files_materialises_the_three_nocloud_files() {
        let dir = tempfile::tempdir().unwrap();
        let seed = dir.path().join("nocloud-net");
        let userdata = b"#cloud-config\nhostname: vm-abc\n";
        write_seed_files(&seed, userdata).expect("seed write succeeds");

        // user-data carries the exact plaintext.
        assert_eq!(fs::read(seed.join("user-data")).unwrap(), userdata);
        // meta-data is the fixed minimal instance-id.
        assert_eq!(
            fs::read_to_string(seed.join("meta-data")).unwrap(),
            META_DATA
        );
        // vendor-data exists and is empty.
        assert_eq!(fs::read(seed.join("vendor-data")).unwrap(), b"");
    }

    #[test]
    fn seed_files_are_mode_0600() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let seed = dir.path().join("nocloud-net");
        write_seed_files(&seed, b"x").expect("seed write succeeds");
        for name in ["user-data", "meta-data", "vendor-data"] {
            let mode = fs::metadata(seed.join(name)).unwrap().permissions().mode();
            // Mask the file-type bits — assert the owner-only perm bits.
            assert_eq!(mode & 0o777, 0o600, "{name} must be mode 0600");
        }
    }

    #[test]
    fn write_nocloud_forwards_dir_and_userdata_length_to_the_writer() {
        let writer = MockSeedWriter::new();
        let userdata = Zeroizing::new(vec![0u8; 128]);
        write_nocloud(&writer, "/run/seed/nocloud-net", userdata).expect("mock succeeds");
        let (dir, len) = writer.last_call().expect("write_seed was called");
        assert_eq!(dir, "/run/seed/nocloud-net");
        assert_eq!(len, 128);
    }

    #[test]
    fn write_nocloud_is_fail_closed_on_a_writer_error() {
        let writer = MockSeedWriter::failing(cat::NOT_TMPFS);
        let err = write_nocloud(&writer, "/dev/sda1", Zeroizing::new(vec![1u8; 4]))
            .expect_err("a non-tmpfs target must fail closed");
        assert!(matches!(err, AgentError::Seed(_)));
        // §20: the error class is the fixed static tag — no path bytes.
        assert_eq!(err.class(), "seed-failed");
        assert_eq!(err.to_string(), "seed-failed");
    }

    #[test]
    fn seed_writer_trait_is_object_safe() {
        let writer: Box<dyn SeedWriter> = Box::new(MockSeedWriter::new());
        assert!(writer
            .write_seed("/run/seed", Zeroizing::new(Vec::new()))
            .is_ok());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn tmpfs_guard_rejects_a_disk_backed_path() {
        // A `tempfile::tempdir()` lands on the CI runner's real disk
        // (ext4/overlay) — the §20 guard must reject it.
        let dir = tempfile::tempdir().unwrap();
        let err = ensure_memory_backed(&dir.path().join("nocloud-net"))
            .expect_err("a disk-backed path must be rejected");
        assert!(matches!(err, AgentError::Seed(cat::NOT_TMPFS)));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn tmpfs_guard_accepts_a_tmpfs_path() {
        // `/dev/shm` is tmpfs on every Linux host (and writable by the
        // CI runner). The guard must accept a path under it — including
        // a not-yet-created child (it walks up to the first extant
        // ancestor).
        if !Path::new("/dev/shm").exists() {
            return; // environment without /dev/shm — skip, not fail.
        }
        ensure_memory_backed(Path::new("/dev/shm/hippius-seed-test/nocloud-net"))
            .expect("/dev/shm is tmpfs — the guard must accept it");
    }
}
