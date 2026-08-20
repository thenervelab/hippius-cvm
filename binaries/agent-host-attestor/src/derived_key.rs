//! The SNP **derived-key** provider — the stable per-platform secret the
//! host attestor stretches into its Ed25519 signer key.
//!
//! Unlike the tenant telemetry agent (which derives its key from the §7
//! lifecycle seed the KBS releases), the host attestor runs on the
//! bare-metal host with no released secret to start from. Instead it
//! asks the AMD Secure Processor for a **measurement-bound VCEK derived
//! key** via `/dev/sev-guest`'s `get_derived_key`: a value reproducible
//! only on this exact measured platform. That derived key is the
//! ikm the HKDF in [`crate::signer`] turns into the attestor's signer
//! seed, so the attestor's identity is cryptographically pinned to the
//! platform without persisting any secret to disk.
//!
//! ## R1 live-spike invariants (non-negotiable)
//!
//! - **`message_version = Some(1)`, never `None`.** The `sev` crate
//!   defaults `None` → v2, which the R1 spike PROVED returns
//!   `InvalidParam` on FW-1.55 miners AND *poisons* the serialized
//!   `/dev/sev-guest` channel — every subsequent `get_report` then fails
//!   with `UnknownSevError(0)` and does not self-heal. v1 works on both
//!   FW 1.55 and 1.58 and yields the identical key. So
//!   [`HostAttestorDerivedKeyRequest::measurement_bound`] pins
//!   `message_version = Some(1)`.
//! - **Fetch once, cache in RAM.** [`fetch_host_attestor_derived_key`]
//!   calls the provider exactly once; the caller (PR-4) caches the
//!   resulting signer and never re-invokes `get_derived_key`.
//! - **Fail-closed.** Any provider error propagates as
//!   [`crate::error::HostAttestorError::DerivedKey`]; there is no
//!   random-key fallback (that would silently break the stable-identity
//!   contract).
//! - **Serialization / sequencing.** `/dev/sev-guest` is a single
//!   serialized, sequence-numbered channel shared with the platform
//!   `get_report` call. The derived-key fetch MUST NOT race the SNP
//!   report call — a `None`→v2 derived-key request that poisons the
//!   channel would break a concurrent report. Real coordination (a
//!   single owner of the device / a mutex) lands in PR-4; this module
//!   only documents the invariant and pins v1 so the fetch is safe.

use zeroize::Zeroizing;

use crate::error::{HostAttestorError, Result};

/// A 32-byte SNP derived key. Secret-bearing: `Zeroizing` wipes it on
/// drop, and it never leaves the process (HKDF consumes it in-place).
pub type SnpDerivedKey = Zeroizing<[u8; 32]>;

/// Host-agnostic description of the `get_derived_key` request the host
/// attestor issues.
///
/// Deliberately free of the `sev` crate's `DerivedKey` type — that type
/// only exists on Linux/x86_64, so keeping the request as a plain
/// descriptor makes the exact parameters (VCEK root key,
/// measurement-only field select, `message_version = Some(1)`)
/// assertable in a unit test on **any** host, with no SEV hardware. The
/// real provider maps this into a `sev::DerivedKey` at the call site.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HostAttestorDerivedKeyRequest {
    /// The `root_key_select` value in `sev`'s ABI encoding: `false`
    /// selects the **VCEK** (0), `true` selects the VMRK (1). The host
    /// attestor always binds to the VCEK, so this is `false`.
    pub root_key_select: bool,
    /// Mix ONLY the launch `MEASUREMENT` into the derived key (bit 3 of
    /// `GuestFieldSelect`). No other guest field is selected, so the key
    /// is stable across boots of the same measured platform.
    pub measurement_only: bool,
    /// VMPL to mix in — 0 for the v1 Hippius platform (no SVSM / nested
    /// VMPL), matching the report path.
    pub vmpl: u32,
    /// Guest SVN to mix in — 0 (unused by the measurement-only binding).
    pub guest_svn: u32,
    /// TCB version to mix in — 0 (unused by the measurement-only
    /// binding).
    pub tcb_version: u64,
    /// Launch mitigation vector. With `message_version = Some(1)` the
    /// `sev` crate forces this field to `None` (it is a v2-only field),
    /// so the v1 spike form passes `None`.
    pub launch_mit_vector: Option<u64>,
    /// The `get_derived_key` message version. Pinned to `Some(1)` — see
    /// the module-level R1 invariant. NEVER `None` (which the `sev`
    /// crate defaults to v2).
    pub message_version: Option<u32>,
}

impl HostAttestorDerivedKeyRequest {
    /// The one request the host attestor ever issues: a **VCEK,
    /// measurement-only, message-version-1** derived key.
    ///
    /// Factored out (rather than inlined in the real provider) so a
    /// hardware-free unit test can assert every field — the R1 spike
    /// makes `message_version = Some(1)` a correctness invariant, not a
    /// default.
    pub fn measurement_bound() -> Self {
        Self {
            root_key_select: false, // VCEK
            measurement_only: true,
            vmpl: 0,
            guest_svn: 0,
            tcb_version: 0,
            launch_mit_vector: None,
            message_version: Some(1), // R1: NEVER None
        }
    }

    /// `true` iff this request derives from the VCEK (the platform
    /// endorsement key) rather than the VMRK.
    pub fn selects_vcek(&self) -> bool {
        !self.root_key_select
    }
}

/// Source of the stable SNP derived key. Production:
/// [`SevGuestDerivedKeyProvider`] (`/dev/sev-guest`). Tests / non-SNP
/// dev hosts: [`MockDerivedKeyProvider`].
pub trait DerivedKeyProvider {
    /// Fetch the 32-byte derived key for `request`.
    ///
    /// MUST be called **once** per boot (the SNP derived-key call is
    /// serialized on `/dev/sev-guest`; see the module docs). On any
    /// failure the implementation returns `Err` — it MUST NOT
    /// substitute a random key.
    fn derived_key(&self, request: &HostAttestorDerivedKeyRequest) -> Result<SnpDerivedKey>;
}

/// Fetch the host attestor's derived key with the canonical
/// measurement-bound request, exactly once.
///
/// This is the single seam callers use — it pins the R1
/// [`HostAttestorDerivedKeyRequest::measurement_bound`] request (so a
/// caller cannot accidentally pass `message_version = None`) and calls
/// the provider one time. PR-4 caches the resulting signer and never
/// re-invokes the provider.
pub fn fetch_host_attestor_derived_key(provider: &dyn DerivedKeyProvider) -> Result<SnpDerivedKey> {
    provider.derived_key(&HostAttestorDerivedKeyRequest::measurement_bound())
}

/// Test / non-SNP-dev-host stand-in for `/dev/sev-guest`.
///
/// Returns a fixed key AND captures the [`HostAttestorDerivedKeyRequest`]
/// it was asked for, so a test can pin — with no hardware — that the
/// real provider would issue a VCEK, measurement-only,
/// `message_version = Some(1)` request. Also supports an error mode to
/// prove the fail-closed contract (an `Err` propagates; no random-key
/// fallback exists to mask it).
pub struct MockDerivedKeyProvider {
    fixed_key: [u8; 32],
    fail: bool,
    captured: std::cell::Cell<Option<HostAttestorDerivedKeyRequest>>,
}

impl MockDerivedKeyProvider {
    /// A mock that returns `fixed_key`.
    pub fn new(fixed_key: [u8; 32]) -> Self {
        Self {
            fixed_key,
            fail: false,
            captured: std::cell::Cell::new(None),
        }
    }

    /// A mock that fails every fetch — for the fail-closed test.
    pub fn failing() -> Self {
        Self {
            fixed_key: [0u8; 32],
            fail: true,
            captured: std::cell::Cell::new(None),
        }
    }

    /// The most recent request that crossed [`DerivedKeyProvider::derived_key`].
    pub fn captured_request(&self) -> Option<HostAttestorDerivedKeyRequest> {
        self.captured.get()
    }
}

impl DerivedKeyProvider for MockDerivedKeyProvider {
    fn derived_key(&self, request: &HostAttestorDerivedKeyRequest) -> Result<SnpDerivedKey> {
        self.captured.set(Some(*request));
        if self.fail {
            return Err(HostAttestorError::DerivedKey("mock-fail"));
        }
        Ok(Zeroizing::new(self.fixed_key))
    }
}

// ── Real provider — /dev/sev-guest (Linux/x86_64 only) ──────────────

/// Production [`DerivedKeyProvider`] backed by `/dev/sev-guest`.
///
/// Target-gated: the character device only exists on a Linux/x86_64
/// SEV-SNP guest. The `unsafe` ioctl lives inside the `sev` crate — this
/// wrapper is `safe` Rust. No unit tests (it needs a real CVM);
/// behavioural coverage runs through [`MockDerivedKeyProvider`] plus
/// [`to_sev_derived_key`]'s parameter test.
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
#[derive(Debug, Default)]
pub struct SevGuestDerivedKeyProvider;

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
impl SevGuestDerivedKeyProvider {
    pub fn new() -> Self {
        Self
    }
}

/// Map the host-agnostic request into the `sev` crate's `DerivedKey`.
///
/// Split out so the mapping (VCEK root key, measurement-only field
/// select) is a single, target-gated, unit-tested seam rather than
/// inline ioctl-adjacent code.
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn to_sev_derived_key(request: &HostAttestorDerivedKeyRequest) -> sev::firmware::guest::DerivedKey {
    use sev::firmware::guest::{DerivedKey, GuestFieldSelect};

    let mut field_select = GuestFieldSelect::default();
    if request.measurement_only {
        // Bit 3 — MEASUREMENT — and ONLY that bit.
        field_select.set_measurement(true);
    }
    DerivedKey::new(
        request.root_key_select,
        field_select,
        request.vmpl,
        request.guest_svn,
        request.tcb_version,
        request.launch_mit_vector,
    )
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
impl DerivedKeyProvider for SevGuestDerivedKeyProvider {
    fn derived_key(&self, request: &HostAttestorDerivedKeyRequest) -> Result<SnpDerivedKey> {
        use sev::firmware::guest::Firmware;

        use zeroize::Zeroize;

        let mut fw = Firmware::open().map_err(|_| HostAttestorError::DerivedKey("open-failed"))?;
        let sev_request = to_sev_derived_key(request);
        // R1: `request.message_version` is `Some(1)` — NEVER `None`.
        // `None` → v2, which returns `InvalidParam` on FW 1.55 and
        // poisons the serialized `/dev/sev-guest` channel for later
        // `get_report` calls. Fail-closed: an ioctl error propagates.
        //
        // Secret discipline: the ioctl hands back the raw derived key as
        // a plain `[u8; 32]` on the stack. Move it into the wiping
        // `Zeroizing` wrapper, then scrub the now-stale transient so no
        // un-wiped copy of the secret lingers on the stack after this
        // returns — the only surviving copy is the `Zeroizing` one.
        let mut key = fw
            .get_derived_key(request.message_version, sev_request)
            .map_err(|_| HostAttestorError::DerivedKey("ioctl-failed"))?;
        let wrapped = Zeroizing::new(key);
        key.zeroize();
        Ok(wrapped)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn measurement_bound_request_is_vcek_measurement_only_msgver1() {
        let req = HostAttestorDerivedKeyRequest::measurement_bound();
        // VCEK, not VMRK.
        assert!(req.selects_vcek());
        assert!(!req.root_key_select);
        // Measurement is the only mixed field.
        assert!(req.measurement_only);
        // R1: message_version MUST be Some(1) — never None (=> v2).
        assert_eq!(req.message_version, Some(1));
        // v1 form: no launch mitigation vector.
        assert_eq!(req.launch_mit_vector, None);
        assert_eq!(req.vmpl, 0);
        assert_eq!(req.guest_svn, 0);
        assert_eq!(req.tcb_version, 0);
    }

    #[test]
    fn fetch_uses_the_canonical_measurement_bound_request() {
        // Drives the provider through the real `fetch_*` seam so the test
        // pins exactly what the production call site sends.
        let mock = MockDerivedKeyProvider::new([7u8; 32]);
        let key = fetch_host_attestor_derived_key(&mock).unwrap();
        assert_eq!(*key, [7u8; 32]);

        let captured = mock.captured_request().expect("request was captured");
        assert_eq!(captured, HostAttestorDerivedKeyRequest::measurement_bound());
        assert!(captured.selects_vcek());
        assert!(captured.measurement_only);
        assert_eq!(captured.message_version, Some(1));
    }

    #[test]
    fn fetch_is_fail_closed_no_random_fallback() {
        // A provider error must propagate — there is no code path that
        // substitutes a random key, so a failed derive can only surface
        // as an Err (which the caller turns into a non-zero exit).
        let mock = MockDerivedKeyProvider::failing();
        let err = fetch_host_attestor_derived_key(&mock)
            .expect_err("a derived-key failure must propagate, not fall back to a random key");
        assert_eq!(err.class(), "mock-fail");
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    #[test]
    fn sev_mapping_sets_vcek_and_measurement_only() {
        let req = HostAttestorDerivedKeyRequest::measurement_bound();
        let sev_req = to_sev_derived_key(&req);
        // root_key_select == 0 => VCEK.
        assert_eq!(sev_req.get_root_key_select(), 0);
        // MEASUREMENT bit set, and ONLY it (bit 3 => value 0b1000).
        assert!(sev_req.guest_field_select.get_measurement());
        assert!(!sev_req.guest_field_select.get_guest_policy());
        assert!(!sev_req.guest_field_select.get_image_id());
        assert!(!sev_req.guest_field_select.get_family_id());
        assert!(!sev_req.guest_field_select.get_svn());
        assert!(!sev_req.guest_field_select.get_tcb_version());
        assert!(!sev_req.guest_field_select.get_launch_mit_vector());
    }
}
