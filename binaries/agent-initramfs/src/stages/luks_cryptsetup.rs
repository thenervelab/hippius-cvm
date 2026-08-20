//! Real `libcryptsetup` LUKS unlock — PR-E1.4.
//!
//! Implements [`crate::stages::unlock::LuksUnlocker`] on top of the
//! `libcryptsetup-rs` binding. All FFI `unsafe` lives inside that
//! binding crate; this module is `safe` Rust (workspace
//! `unsafe_code = "forbid"` inherited unmodified).
//!
//! ## Why a target-gated module
//!
//! `libcryptsetup` drives the Linux kernel device-mapper — it exists
//! only on Linux. Building `hippius-agent-initramfs` on a macOS dev
//! host MUST still succeed for `cargo check`/`cargo test`; the
//! `libcryptsetup-rs` dependency is therefore target-gated to
//! `target_os = "linux"` (see `Cargo.toml`) and this whole module is
//! `#![cfg(target_os = "linux")]`. Non-Linux builds simply do not see
//! [`RealLuksUnlocker`] and drive the pipeline through
//! [`crate::stages::unlock::MockLuksUnlocker`] instead. Same split as
//! [`crate::stages::snp_ioctl`] (PR-E1.2).
//!
//! ## What we wrap
//!
//! Three `libcryptsetup` calls, in order, each fail-closed:
//!
//! 1. `crypt_init(device)` — open a context handle on the backing
//!    block device.
//! 2. `crypt_load(CRYPT_LUKS2, NULL)` — read + validate the on-disk
//!    LUKS2 header. The format is **pinned to LUKS2** (§20 "pinned
//!    crypto profile"): a LUKS1 / plain / non-LUKS device fails the
//!    load and the boot aborts, rather than being silently accepted.
//! 3. `crypt_activate_by_passphrase(MAPPER_NAME, CRYPT_ANY_SLOT, key)`
//!    — unlock a keyslot with the released key and activate the
//!    plaintext device-mapper target at `/dev/mapper/`[`MAPPER_NAME`].
//!    `CRYPT_ANY_SLOT` tries the **one** released key against each
//!    keyslot — it is *not* a key fallback (there is only ever one
//!    key); a LUKS volume may legitimately hold the same passphrase in
//!    more than one slot.
//!
//! The activated dm-crypt mapping persists after `crypt_free` (the
//! `CryptDevice` `Drop`) — the kernel device-mapper target is
//! independent of the libcryptsetup handle, which is exactly what the
//! later mount / `switch_root` PR needs.
//!
//! ## Secret discipline (§20)
//!
//! - The key crosses the FFI boundary as `&[u8]` borrowed directly
//!   from the caller's [`Zeroizing`](zeroize::Zeroizing) buffer — there
//!   is **no** Rust-side intermediate copy that would escape the wipe.
//!   `libcryptsetup` copies the passphrase into its own
//!   `crypt_safe_alloc` buffers (mlock'd, wiped on free by the C
//!   library) for the keyslot unlock; that copy is libcryptsetup's own
//!   key hygiene, outside Rust's `Zeroizing` but handled by the C
//!   library's discipline.
//! - The owned `Zeroizing<Vec<u8>>` is dropped (and wiped) when
//!   `unlock` returns — before `switch_root`'s `execve(2)` (§20).
//! - Every `libcryptsetup` error is mapped to [`AgentError::Luks`]
//!   with a closed-vocabulary [`cat`] classifier; the underlying
//!   `LibcryptErr` is deliberately **discarded** (`|_|`) so no library
//!   diagnostic string can splice into a log line (§20 "no plaintext
//!   to logs"). `libcryptsetup` itself never logs key material.
//! - Before any libcryptsetup call, `unlock` registers an explicit
//!   no-op log callback ([`drop_libcryptsetup_log`]) via
//!   [`set_log_callback`]. libcryptsetup emits its diagnostics through
//!   that callback mechanism, which does nothing until a callback is
//!   set — registering an explicit sink makes the §20 "serial console
//!   must not echo it" property *structural* for this component rather
//!   than dependent on the no-callback default, and keeps it that way
//!   regardless of library version or of other code in the process
//!   installing a global default logger.
//!
//! ## Threading
//!
//! `libcryptsetup-rs` is depended on **without** its `mutex` feature,
//! so the binding panics if libcryptsetup is called from a thread
//! other than the one that first touched the library. Every
//! libcryptsetup call here — `set_log_callback` included — therefore
//! MUST stay on the single §21 pipeline thread. It does: the §21
//! pipeline ([`crate::pipeline::run`]) is single-threaded, and a
//! future PR that drove a stage from a worker thread would have to
//! revisit this (or enable the `mutex` feature).
//!
//! ## `mlock` deferred — same precedent as `keygen.rs`
//!
//! The released key sits in normal heap RAM for the duration of the
//! unlock. `mlock(2)` would additionally pin that page off swap and
//! out of core dumps, but it needs the raw syscall, which the
//! workspace `unsafe_code = "forbid"` lint makes a compile error
//! in-crate. As in [`crate::stages::keygen`], swap-leak / core-dump
//! exposure is therefore closed at the deployment layer instead: the
//! §F measured guest image runs with swap disabled and core dumps off
//! — strictly stronger than per-page `mlock`. (libcryptsetup's *own*
//! internal key buffers are separately mlock'd by the C library.)

#![cfg(all(target_os = "linux", feature = "cryptsetup"))]

use crate::pipeline::AgentError;
use crate::stages::unlock::{LuksUnlocker, MAPPER_NAME};
use libcryptsetup_rs::consts::flags::CryptActivate;
use libcryptsetup_rs::consts::vals::EncryptionFormat;
use libcryptsetup_rs::{set_log_callback, CryptInit};
use std::os::raw::{c_char, c_int, c_void};
use std::path::Path;
use zeroize::Zeroizing;

/// Stable classifier strings for [`AgentError::Luks`] raised from this
/// module. Kept in one place so the PR-E1.5 audit sink can map each
/// value to a metric code without grep-ing the codebase. `Display`
/// renders only the fixed `"luks-failed"` tag — these are for internal
/// triage, never a log line (§20).
pub(crate) mod cat {
    /// `crypt_init` failed — the backing device node is missing, not a
    /// block device, or not openable. Under a measured UKI this means
    /// the §11 block-device layout is not what was attested.
    pub(crate) const INIT: &str = "crypt-init";
    /// `crypt_load` failed — the device carries no valid LUKS2 header
    /// (wrong format, corrupt header, or a non-LUKS device). Pinned to
    /// LUKS2 per §20; a LUKS1 / plain device is rejected here.
    pub(crate) const HEADER_LOAD: &str = "header-load";
    /// `crypt_activate_by_passphrase` failed — the released key
    /// unlocked no keyslot, or the kernel device-mapper rejected the
    /// activation. Terminal: no retry, no alternative key (§14).
    pub(crate) const ACTIVATE: &str = "activate";
}

/// A libcryptsetup log callback that drops every message — see the
/// module "Secret discipline" docs. `libcryptsetup` routes all its
/// diagnostics here once registered via [`set_log_callback`], so none
/// reach the serial console (§20).
///
/// `extern "C"` with raw-pointer parameters is mandated by the
/// `libcryptsetup` callback ABI, but the body dereferences **nothing**
/// — so no `unsafe` is needed and the workspace `unsafe_code =
/// "forbid"` lint holds. The parameters are accepted and discarded.
extern "C" fn drop_libcryptsetup_log(_level: c_int, _msg: *const c_char, _usrptr: *mut c_void) {}

/// Production [`LuksUnlocker`] backed by `libcryptsetup`.
///
/// Zero-sized — `libcryptsetup` is initialised per-call against the
/// backing device, so the unlocker carries no state. Mirrors
/// [`crate::stages::snp_ioctl::SevGuestProvider`].
#[derive(Debug, Default)]
pub struct RealLuksUnlocker;

impl RealLuksUnlocker {
    /// Construct an unlocker. No-op (the type is stateless); kept as an
    /// explicit entry point for parity with the other stage providers.
    pub fn new() -> Self {
        Self
    }
}

impl LuksUnlocker for RealLuksUnlocker {
    fn unlock(&self, device: &str, key: Zeroizing<Vec<u8>>) -> Result<(), AgentError> {
        // 0. Silence libcryptsetup BEFORE any call — route every library
        //    diagnostic to a no-op sink so nothing reaches the serial
        //    console (§20). Idempotent: `unlock` runs once per boot.
        //    This is also the first libcryptsetup call, pinning the
        //    library to the single-threaded §21 pipeline thread — see
        //    the module "Threading" docs.
        set_log_callback::<()>(Some(drop_libcryptsetup_log), None);

        // 1. Open a libcryptsetup context on the backing device.
        let mut crypt_device =
            CryptInit::init(Path::new(device)).map_err(|_| AgentError::Luks(cat::INIT))?;

        // 2. Load + validate the on-disk header, pinned to LUKS2 (§20).
        //    `None` params: an existing device's parameters are read
        //    from its header, not supplied by us.
        crypt_device
            .context_handle()
            .load::<()>(Some(EncryptionFormat::Luks2), None)
            .map_err(|_| AgentError::Luks(cat::HEADER_LOAD))?;

        // 3. Unlock a keyslot with the released key and activate the
        //    plaintext mapping at `/dev/mapper/<MAPPER_NAME>`.
        //
        //    `key.as_slice()` borrows the `Zeroizing`-owned heap buffer
        //    directly — no Rust-side intermediate copy. `keyslot: None`
        //    (CRYPT_ANY_SLOT) tries the one released key against every
        //    keyslot; it is not a key fallback. `CryptActivate::empty()`
        //    — the per-VM LUKS volume is confidential *writable* state
        //    (§11), so no read-only flag.
        crypt_device
            .activate_handle()
            .activate_by_passphrase(
                Some(MAPPER_NAME),
                None,
                key.as_slice(),
                CryptActivate::empty(),
            )
            .map(|_keyslot| ())
            .map_err(|_| AgentError::Luks(cat::ACTIVATE))?;

        Ok(())
        // `key` (a `Zeroizing<Vec<u8>>`) drops here → the released LUKS
        // key is wiped before control returns to the pipeline, well
        // before `switch_root`'s `execve(2)`.
    }
}

// No unit tests here: a real `crypt_activate_by_passphrase` needs a
// LUKS-formatted block device, root, and a live kernel device-mapper —
// none reachable from `cargo test`. Behavioural coverage of the stage
// plumbing lives in `crate::stages::unlock::tests` (via
// `MockLuksUnlocker`); the end-to-end unlock runs inside a real CVM
// under the §F measured UKI, outside `cargo test`. The compile-gate
// test pins that `RealLuksUnlocker` implements `LuksUnlocker` so a
// future refactor cannot drop the impl unnoticed.
