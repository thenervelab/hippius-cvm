//! Stage 7 — LUKS-open the per-VM confidential volume (PR-E1.4).
//!
//! The verity rootfs is already integrity-anchored in the measured UKI
//! (§11); this stage unlocks ONLY the named per-VM LUKS volume with the
//! KBS-released key. The activated plaintext device is mapped at the
//! fixed name [`MAPPER_NAME`] — `/dev/mapper/hippius-data` — which the
//! later `switch_root` / mount PR consumes.
//!
//! ## Layering (mirrors the `SnpReportProvider` split, PR-E1.2)
//!
//! The real `libcryptsetup` binding is Linux-only — it drives the
//! kernel device-mapper. So this module owns the cross-platform
//! [`LuksUnlocker`] trait + the [`MockLuksUnlocker`], and the real
//! [`crate::stages::luks_cryptsetup::RealLuksUnlocker`] lives in a
//! sibling module gated to `target_os = "linux"`. Consequences:
//!
//! 1. macOS dev builds still `cargo check`/`cargo test` — they drive
//!    the pipeline through [`MockLuksUnlocker`]; the `libcryptsetup-rs`
//!    crate is not even compiled (it is a target-gated dependency).
//! 2. `libcryptsetup`'s FFI `unsafe` is encapsulated by the binding
//!    crate — `hippius-agent-initramfs` itself stays `unsafe`-free
//!    (workspace `unsafe_code = "forbid"` inherited).
//!
//! ## Ownership / secret discipline (§20)
//!
//! [`LuksUnlocker::unlock`] / [`open_luks`] take `key` **by value**.
//! Same reasoning as [`crate::stages::verify`]: `switch_root`
//! (`execve(2)`) bypasses `Drop`, so the [`Zeroizing`] wipe only fires
//! if `key` is dropped *before* the pivot. Consuming the value forces
//! the wipe the moment the unlock finishes with the bytes — never a
//! by-reference signature, which would leave the LUKS key live in
//! guest RAM across the pivot.
//!
//! The key is **never logged** — not the bytes, not a length, not a
//! prefix. [`AgentError::Luks`] carries only a closed-vocabulary
//! `&'static str` classifier whose `Display` renders the fixed
//! `"luks-failed"` tag (§20 "no plaintext to logs").
//!
//! ## Fail-closed
//!
//! A single key, a single attempt: any `libcryptsetup` error is a
//! terminal `Err` that aborts the boot. There is **no** "try another
//! key" fallback — the released key is the only key, and the §7
//! release is already spent (a second boot needs a fresh ticket, §14).
//!
//! ## Out of scope for PR-E1.4
//!
//! §11 also pins a block-device allowlist (the initramfs must reject
//! extra partitions, qcow2 backing-files, and overlays). That is
//! tracked separately under the §20 initramfs-hardening sub-task of
//! issue #42 — it is *not* part of this stage.

use crate::pipeline::AgentError;
use core::cell::RefCell;
use zeroize::Zeroizing;

/// Device-mapper name the unlocked LUKS volume is activated under. The
/// plaintext block device then appears at `/dev/mapper/hippius-data`.
///
/// Fixed (not configurable): the measured initramfs and the dm-verity
/// rootfs both reference this exact path, so a per-boot name would
/// break the §11 boot chain. The *backing* device is configurable
/// (see [`resolve_luks_device`]); the *mapped* name is not.
pub const MAPPER_NAME: &str = "hippius-data";

/// Env var the agent reads the LUKS backing-device path from (dev /
/// explicit override). Mirrors [`crate::stages::kbs_client::ENV_KBS_URL`].
pub const ENV_LUKS_DEVICE: &str = "HIPPIUS_LUKS_DEVICE";

/// `/proc/cmdline` key the agent reads the LUKS backing-device path
/// from in production — `hippius.luks_device=/dev/...`. The kernel
/// command line is folded into the SNP launch measurement (§20), so a
/// cmdline-supplied path is measured / tamper-evident.
pub const CMDLINE_LUKS_DEVICE_KEY: &str = "hippius.luks_device";

/// Source of LUKS volume unlocks.
///
/// Production: [`crate::stages::luks_cryptsetup::RealLuksUnlocker`],
/// which drives `libcryptsetup` (Linux only). Tests + non-Linux dev
/// hosts: [`MockLuksUnlocker`].
///
/// The §21 pipeline holds this as `&dyn LuksUnlocker` — trait-object
/// dispatch keeps `pipeline::run`'s signature simple (the pipeline is
/// not perf-critical).
pub trait LuksUnlocker {
    /// Unlock the LUKS volume backed by `device`, activating the
    /// plaintext mapping at `/dev/mapper/`[`MAPPER_NAME`].
    ///
    /// `key` is the KBS-released LUKS keyslot passphrase, taken **by
    /// value** so its [`Zeroizing`] wipe fires inside the implementation
    /// — see the module "Ownership / secret discipline" docs.
    ///
    /// Fail-closed: any error is terminal; there is no retry and no
    /// alternative-key fallback.
    fn unlock(&self, device: &str, key: Zeroizing<Vec<u8>>) -> Result<(), AgentError>;
}

/// Stage entry function — unlock `device` with `key` via `unlocker`.
///
/// A thin forwarder kept for parity with the other §21 stage modules
/// (each exposes one free entry function that [`crate::pipeline::run`]
/// calls). `key` is moved straight through into
/// [`LuksUnlocker::unlock`], where it is dropped + wiped.
pub fn open_luks(
    unlocker: &dyn LuksUnlocker,
    device: &str,
    key: Zeroizing<Vec<u8>>,
) -> Result<(), AgentError> {
    unlocker.unlock(device, key)
}

/// Resolve the LUKS backing-device path: the `HIPPIUS_LUKS_DEVICE` env
/// var first (dev / explicit override), then the `hippius.luks_device=`
/// token in `/proc/cmdline` (production — baked into the measured UKI's
/// kernel command line, §20). Absent both ⇒ `Err`, fail-closed.
///
/// Same precedence as [`crate::stages::kbs_client::resolve_kbs_url`];
/// the env-vs-cmdline decision is factored into the pure
/// [`resolve_luks_device_from`] so every branch is unit-testable
/// without a process-global env var or a real `/proc/cmdline`.
pub fn resolve_luks_device() -> Result<String, AgentError> {
    let env = std::env::var(ENV_LUKS_DEVICE).ok();
    let cmdline = std::fs::read_to_string("/proc/cmdline");
    resolve_luks_device_from(env.as_deref(), cmdline.as_deref().map_err(|_| ()))
}

/// The pure env-vs-cmdline precedence decision behind
/// [`resolve_luks_device`].
///
/// - `env` — the `HIPPIUS_LUKS_DEVICE` value (`None` if unset). A
///   non-empty value wins outright; an empty value falls through.
/// - `cmdline` — the `/proc/cmdline` contents, or `Err(())` if it could
///   not be read. Only consulted when `env` did not win — so a missing
///   `/proc/cmdline` is harmless when the env override is set.
///
/// Fail-closed: an unreadable `/proc/cmdline` in the fallback path ⇒
/// `Luks("cmdline-read")`; a readable cmdline with no device token ⇒
/// `Luks("device-missing")`.
fn resolve_luks_device_from(
    env: Option<&str>,
    cmdline: Result<&str, ()>,
) -> Result<String, AgentError> {
    if let Some(device) = env.filter(|d| !d.is_empty()) {
        return Ok(device.to_string());
    }
    let cmdline = cmdline.map_err(|()| AgentError::Luks("cmdline-read"))?;
    luks_device_from_cmdline(cmdline).ok_or(AgentError::Luks("device-missing"))
}

/// Extract `hippius.luks_device=<value>` from a `/proc/cmdline` string.
/// Pulled out so it is unit-testable without `/proc`. An empty value is
/// treated as absent.
pub fn luks_device_from_cmdline(cmdline: &str) -> Option<String> {
    let prefix = format!("{CMDLINE_LUKS_DEVICE_KEY}=");
    cmdline
        .split_whitespace()
        .find_map(|tok| tok.strip_prefix(&prefix))
        .filter(|v| !v.is_empty())
        .map(str::to_string)
}

/// What a [`MockLuksUnlocker`] observed on its last `unlock` call.
///
/// `key_len` only — **never** the key bytes. The mock is deliberately
/// not a place a secret can linger: a test can confirm a key of the
/// expected length flowed through without the mock ever retaining the
/// material.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MockUnlockCall {
    /// The backing-device path passed to `unlock`.
    pub device: String,
    /// The length of the LUKS key passed to `unlock`. Length only —
    /// the bytes are consumed + wiped, never copied out.
    pub key_len: usize,
}

/// Test / non-Linux dev-host stand-in for the real `libcryptsetup`
/// unlock.
///
/// Records the `device` + key length of its last call (see
/// [`MockUnlockCall`]) and returns a configurable outcome. It consumes
/// `key` by value exactly as the real unlocker does, so the
/// [`Zeroizing`] wipe-on-drop discipline is exercised by the mock too.
///
/// Public so [`crate::main`] can construct one on non-Linux targets and
/// so integration tests can drive the pipeline. Using one in production
/// would not unlock anything — `MockLuksUnlocker::new()` "succeeds"
/// without touching a device, but on a real boot the pipeline never
/// reaches this stage on a non-Linux build (the canned SNP report
/// fails KBS verification far earlier).
pub struct MockLuksUnlocker {
    /// `Ok(())` ⇒ `unlock` succeeds; `Err(class)` ⇒ it fails with
    /// `AgentError::Luks(class)`. `Copy`, so `unlock` reads it freely.
    outcome: Result<(), &'static str>,
    /// Last observed call. `RefCell` (not `Cell`) because
    /// [`MockUnlockCall`] is not `Copy`. Not thread-safe; the §21
    /// pipeline is single-threaded.
    last_call: RefCell<Option<MockUnlockCall>>,
}

impl MockLuksUnlocker {
    /// A mock whose `unlock` succeeds.
    pub fn new() -> Self {
        Self {
            outcome: Ok(()),
            last_call: RefCell::new(None),
        }
    }

    /// A mock whose `unlock` fails closed with `AgentError::Luks(class)`
    /// — used to pin the §21 fail-closed propagation.
    pub fn failing(class: &'static str) -> Self {
        Self {
            outcome: Err(class),
            last_call: RefCell::new(None),
        }
    }

    /// The [`MockUnlockCall`] from the most recent `unlock`, or `None`
    /// if `unlock` was never called on this mock.
    pub fn last_call(&self) -> Option<MockUnlockCall> {
        self.last_call.borrow().clone()
    }
}

impl Default for MockLuksUnlocker {
    fn default() -> Self {
        Self::new()
    }
}

impl LuksUnlocker for MockLuksUnlocker {
    fn unlock(&self, device: &str, key: Zeroizing<Vec<u8>>) -> Result<(), AgentError> {
        // Record device + key LENGTH before `key` is dropped. The bytes
        // are never copied out — the mock holds no secret material.
        *self.last_call.borrow_mut() = Some(MockUnlockCall {
            device: device.to_string(),
            key_len: key.len(),
        });
        self.outcome.map_err(AgentError::Luks)
        // `key` (a `Zeroizing<Vec<u8>>`) drops here → bytes wiped, even
        // in the mock — the by-value discipline is modelled, not faked.
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mapper_name_is_pinned() {
        // The dm-verity rootfs + measured initramfs reference this
        // exact path; a drift here breaks the §11 boot chain.
        assert_eq!(MAPPER_NAME, "hippius-data");
    }

    #[test]
    fn open_luks_forwards_device_and_key_to_the_unlocker() {
        let unlocker = MockLuksUnlocker::new();
        let key = Zeroizing::new(vec![0xABu8; 64]);
        open_luks(&unlocker, "/dev/vdb", key).expect("mock unlock succeeds");

        let call = unlocker.last_call().expect("unlock was called once");
        assert_eq!(call.device, "/dev/vdb");
        // The exact key length the released buffer carried flowed
        // through — by value, then dropped.
        assert_eq!(call.key_len, 64);
    }

    #[test]
    fn open_luks_is_fail_closed_on_an_unlock_error() {
        // A `libcryptsetup` failure (here: bad passphrase) is terminal.
        let unlocker = MockLuksUnlocker::failing("activate");
        let key = Zeroizing::new(vec![0u8; 32]);
        let err = open_luks(&unlocker, "/dev/vdb", key).expect_err("a failing unlock must Err");
        assert!(matches!(err, AgentError::Luks(_)));
        // §20: the error class is the fixed static tag — no device
        // path, no key context.
        assert_eq!(err.class(), "luks-failed");
        assert_eq!(err.to_string(), "luks-failed");
    }

    #[test]
    fn luks_unlocker_trait_is_object_safe() {
        // §21 `run` takes `&dyn LuksUnlocker` — a future non-object-
        // safe method would break this cast here, not at a call site.
        let unlocker: Box<dyn LuksUnlocker> = Box::new(MockLuksUnlocker::new());
        let key = Zeroizing::new(vec![1u8; 16]);
        assert!(unlocker.unlock("/dev/vdb", key).is_ok());
    }

    #[test]
    fn luks_device_from_cmdline_extracts_the_token() {
        let line = "ro quiet hippius.luks_device=/dev/vdb console=ttyS0";
        assert_eq!(luks_device_from_cmdline(line).as_deref(), Some("/dev/vdb"));
        assert_eq!(luks_device_from_cmdline("ro quiet console=ttyS0"), None);
        // An empty value is treated as absent.
        assert_eq!(luks_device_from_cmdline("hippius.luks_device="), None);
    }

    #[test]
    fn luks_device_from_cmdline_takes_the_first_match() {
        // Defensive: a duplicated token resolves deterministically to
        // the first occurrence (matches `split_whitespace` order).
        let line = "hippius.luks_device=/dev/vdb hippius.luks_device=/dev/vdc";
        assert_eq!(luks_device_from_cmdline(line).as_deref(), Some("/dev/vdb"));
    }

    #[test]
    fn resolve_device_env_overrides_the_cmdline() {
        let got = resolve_luks_device_from(
            Some("/dev/from-env"),
            Ok("ro hippius.luks_device=/dev/from-cmdline"),
        );
        assert_eq!(got.unwrap(), "/dev/from-env");
    }

    #[test]
    fn resolve_device_empty_env_falls_through_to_cmdline() {
        // An empty env value is treated as absent — the cmdline wins.
        let got = resolve_luks_device_from(Some(""), Ok("ro hippius.luks_device=/dev/vdb quiet"));
        assert_eq!(got.unwrap(), "/dev/vdb");
    }

    #[test]
    fn resolve_device_uses_cmdline_when_env_is_absent() {
        let got = resolve_luks_device_from(None, Ok("ro hippius.luks_device=/dev/vdb quiet"));
        assert_eq!(got.unwrap(), "/dev/vdb");
    }

    #[test]
    fn resolve_device_fails_closed_when_cmdline_is_unreadable() {
        // The fallback path: env absent + `/proc/cmdline` unreadable ⇒
        // a terminal `cmdline-read` error.
        let err = resolve_luks_device_from(None, Err(())).expect_err("must fail closed");
        assert!(matches!(err, AgentError::Luks("cmdline-read")));
    }

    #[test]
    fn resolve_device_fails_closed_when_no_source_supplies_a_device() {
        // Env absent (or empty) + a readable cmdline with no token ⇒
        // `device-missing`. Never a default device — fail-closed.
        let err = resolve_luks_device_from(None, Ok("ro quiet console=ttyS0"))
            .expect_err("must fail closed");
        assert!(matches!(err, AgentError::Luks("device-missing")));
        assert!(matches!(
            resolve_luks_device_from(Some(""), Ok("ro quiet")),
            Err(AgentError::Luks("device-missing"))
        ));
    }

    #[test]
    fn resolve_device_env_wins_even_if_cmdline_is_unreadable() {
        // A non-empty env override short-circuits before the cmdline is
        // consulted — an unreadable `/proc/cmdline` is then harmless.
        let got = resolve_luks_device_from(Some("/dev/from-env"), Err(()));
        assert_eq!(got.unwrap(), "/dev/from-env");
    }
}
