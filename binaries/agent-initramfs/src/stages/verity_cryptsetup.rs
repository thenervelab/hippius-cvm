//! Real `libcryptsetup` dm-verity activation — Phase A close.
//!
//! Implements [`crate::stages::verity::RootfsVerity`] on top of the
//! `libcryptsetup-rs` binding's `EncryptionFormat::Verity` path.
//! All FFI `unsafe` lives inside that binding crate; this module is
//! `safe` Rust (workspace `unsafe_code = "forbid"` inherited).
//!
//! Target-gated the same way [`crate::stages::luks_cryptsetup`] is —
//! `libcryptsetup` only exists on Linux.
//!
//! ## What we wrap
//!
//! 1. `crypt_init(<hash_device>)` — open a context on the verity hash
//!    backing device. dm-verity stores its superblock at the start of
//!    the hash device, so this is the right device to point
//!    libcryptsetup at (NOT the data device).
//! 2. `crypt_load(CRYPT_VERITY, NULL)` — read + parse the dm-verity
//!    superblock. The data device path is recorded inside the
//!    superblock (set at `veritysetup format` time) and libcryptsetup
//!    honours that pointer, so the caller does not separately wire
//!    the data device into the activation. We still validate that
//!    the data-device path the agent expects matches the cmdline
//!    token — a mismatch here is a §11 layout violation that fails
//!    closed at `data-device-mismatch`.
//! 3. `crypt_activate_by_volume_key(<MAPPER>, <root_hash_bytes>,
//!    CRYPT_ACTIVATE_READONLY)` — creates the dm-verity device-
//!    mapper target at `/dev/mapper/`[`super::verity::MAPPER_NAME`].
//!    The 32-byte root hash is the "volume key" for verity — the
//!    kernel checks every read against the hash tree built from that
//!    root. `READONLY` is mandatory: a dm-verity device is read-only
//!    by construction.
//!
//! ## Why a no-op log callback
//!
//! Same rationale as [`crate::stages::luks_cryptsetup`] — register a
//! no-op `set_log_callback` so libcryptsetup's diagnostics never
//! reach the serial console (§20 "no plaintext to logs"). The LUKS
//! stage runs first and already installs the callback in production;
//! we re-install here defensively so a future re-ordering that runs
//! verity before LUKS still respects the discipline.
//!
//! ## Secret discipline (§20)
//!
//! The dm-verity root hash is **not** a secret — it's an integrity
//! anchor that the launch digest covers, byte-for-byte. The mapper
//! name and device paths are not secret either. So no `Zeroizing`
//! plumbing here; the §20 discipline at this stage reduces to "no
//! libcryptsetup diagnostic strings on the serial console" via the
//! no-op log callback.

#![cfg(all(target_os = "linux", feature = "cryptsetup"))]

use crate::pipeline::AgentError;
use crate::stages::verity::{cat, RootfsVerity, MAPPER_NAME};
use libcryptsetup_rs::consts::flags::{CryptActivate, CryptVerity};
use libcryptsetup_rs::consts::vals::EncryptionFormat;
use libcryptsetup_rs::{set_log_callback, CryptInit, CryptParamsVerity, CryptParamsVerityRef};
use std::convert::TryInto;
use std::os::raw::{c_char, c_int, c_void};
use std::path::{Path, PathBuf};

/// A libcryptsetup log callback that drops every message — see the
/// module docs. Mirrors `drop_libcryptsetup_log` in
/// [`crate::stages::luks_cryptsetup`].
extern "C" fn drop_libcryptsetup_log(_level: c_int, _msg: *const c_char, _usrptr: *mut c_void) {}

/// Production [`RootfsVerity`] backed by `libcryptsetup`.
///
/// Zero-sized — libcryptsetup is initialised per-call against the
/// hash backing device, so the opener carries no state.
#[derive(Debug, Default)]
pub struct RealRootfsVerity;

impl RealRootfsVerity {
    pub fn new() -> Self {
        Self
    }
}

impl RootfsVerity for RealRootfsVerity {
    fn open(
        &self,
        data_device: &str,
        hash_device: &str,
        root_hash: &[u8],
    ) -> Result<(), AgentError> {
        // 0. Silence libcryptsetup BEFORE any call.
        set_log_callback::<()>(Some(drop_libcryptsetup_log), None);

        // 1. crypt_init on the HASH device — dm-verity's superblock
        //    lives at the start of the hash device, not the data.
        let mut crypt_device =
            CryptInit::init(Path::new(hash_device)).map_err(|_| AgentError::Verity(cat::INIT))?;

        // 2. crypt_load(CRYPT_VERITY, params) — read the superblock,
        //    OVERRIDING the data-device path baked in at
        //    `veritysetup format` time. The format-time path is
        //    typically a build-tree path (e.g. `/build/work/
        //    rootfs.img`) that does not exist at boot time in the
        //    guest; the kernel honors the superblock's pointer
        //    verbatim and the activation fails closed. Passing
        //    `data_device` here is what `veritysetup open <data>
        //    <name> <hash> <root_hash>` does internally; the rest of
        //    the params come from the superblock — we zero them out
        //    so libcryptsetup picks the on-disk values.
        let params = CryptParamsVerity {
            hash_name: String::new(),
            data_device: PathBuf::from(data_device),
            hash_device: None,
            fec_device: None,
            salt: Vec::new(),
            hash_type: 0,
            data_block_size: 0,
            hash_block_size: 0,
            data_size: 0,
            hash_area_offset: 0,
            fec_area_offset: 0,
            fec_roots: 0,
            flags: CryptVerity::empty(),
        };
        let mut params_ref: CryptParamsVerityRef<'_> = (&params)
            .try_into()
            .map_err(|_| AgentError::Verity(cat::HEADER_LOAD))?;
        crypt_device
            .context_handle()
            .load(Some(EncryptionFormat::Verity), Some(&mut params_ref))
            .map_err(|_| AgentError::Verity(cat::HEADER_LOAD))?;

        // 3. Activate the verity target read-only with the
        //    integrity-anchoring root hash. The kernel verifies the
        //    hash tree at activation and on every subsequent read.
        crypt_device
            .activate_handle()
            .activate_by_volume_key(Some(MAPPER_NAME), Some(root_hash), CryptActivate::READONLY)
            .map_err(|_| AgentError::Verity(cat::ACTIVATE))?;

        Ok(())
    }
}

// No unit tests here — `crypt_activate_by_volume_key(CRYPT_VERITY, …)`
// needs a real kernel device-mapper, root, and a verity-formatted
// hash backing device — none reachable from `cargo test`. Trait-level
// coverage lives in `crate::stages::verity::tests` (via
// `MockRootfsVerity`); the end-to-end verity open runs inside a real
// CVM under the §F measured UKI.
