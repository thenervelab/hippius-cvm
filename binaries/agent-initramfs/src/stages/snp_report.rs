//! Stage 3 — request an SNP attestation report via `/dev/sev-guest`.
//!
//! Per §20 the kernel-supplied `REPORT_DATA` is exactly:
//!
//! ```text
//! REPORT_DATA[0..32]  = KBS_nonce
//! REPORT_DATA[32..64] = guest X25519 public key
//! ```
//!
//! The KBS recomputes this layout and rejects anything else — there is
//! no negotiated alternative.
//!
//! ## Layering
//!
//! The real ioctl wrapper lives in [`crate::stages::snp_ioctl`]
//! ([`crate::stages::snp_ioctl::SevGuestProvider`], gated to
//! `target_os = "linux"`, `target_arch = "x86_64"` because that's the
//! only place `/dev/sev-guest` exists). This module owns the
//! `SnpReportProvider` trait that both the real provider and the
//! [`MockSnpReportProvider`] (used by every test + by the binary on
//! non-SNP dev hosts) implement.
//!
//! Keeping the unsafe-touching ioctl behind a target-gated module
//! means:
//!
//! 1. macOS dev builds still `cargo check`/`cargo test` (no `sev`
//!    crate, no /dev/sev-guest call) — they must drive the pipeline
//!    via the mock.
//! 2. The `sev` crate's `unsafe` ioctl plumbing is encapsulated by
//!    that crate — `hippius-agent-initramfs` itself contains zero
//!    `unsafe` code (workspace `unsafe_code = "forbid"` lint
//!    inherited).

use crate::pipeline::AgentError;
use core::cell::Cell;

/// Pinned length of an SEV-SNP attestation report (`struct
/// snp_attestation_report`, AMD SEV-SNP ABI v1.55+). Anything else from
/// `SNP_GET_REPORT` is malformed — drop fail-closed.
pub const SNP_REPORT_LEN: usize = 1184;

/// Raw SNP attestation report bytes (`SNP_REPORT_LEN` = 1184 bytes per
/// the AMD spec). Kept opaque at this layer — the KBS verifies; the
/// guest only transports it. Non-secret (it crosses the wire to
/// Guardian → Edge → KBS), so `Debug` is fine.
#[derive(Debug)]
pub struct SnpReport(pub Vec<u8>);

/// Newtype-wrapped REPORT_DATA buffer.
///
/// The inner `[u8; 64]` is **private** and the only constructor
/// ([`ReportData::new`]) is `pub(crate)`, called only by
/// [`report_data`]. Therefore the §20 byte-exact layout
/// `nonce(32) ‖ pubkey(32)` is a single grep target — external code
/// (including the binary, integration tests, and future
/// `SnpReportProvider` impls) **cannot** hand a provider arbitrary
/// 64 bytes that bypass the layout helper. The compiler enforces it
/// structurally: `get_report` only accepts `ReportData`, and no
/// other code can build one.
///
/// `as_bytes` returns a reference so tests / the `sev` crate's ioctl
/// can read the bytes without exposing the private field. Non-secret
/// (it ships to the KBS in the attestation report) → `Debug` is fine.
#[derive(Debug, Clone, Copy)]
pub struct ReportData([u8; 64]);

impl ReportData {
    /// `pub(crate)` constructor — the ONLY caller is [`report_data`].
    /// External code cannot construct a `ReportData` directly, so
    /// the §20 layout invariant is structurally enforced.
    pub(crate) fn new(bytes: [u8; 64]) -> Self {
        Self(bytes)
    }

    /// Borrow the underlying 64 bytes. Used by the `sev` crate's
    /// `Firmware::get_report` (which takes `[u8; 64]` by value — see
    /// [`crate::stages::snp_ioctl`]) and by
    /// [`MockSnpReportProvider`] tests that pin the §20 layout.
    pub fn as_bytes(&self) -> &[u8; 64] {
        &self.0
    }
}

/// Build the 64-byte `REPORT_DATA` value per §20.
///
/// The single source of truth for the layout. Visible at module
/// scope so tests can pin the byte pattern directly; producing a
/// [`ReportData`] is the only way to obtain one that crosses the
/// [`SnpReportProvider`] boundary (structural enforcement).
pub fn report_data(kbs_nonce: &[u8; 32], guest_pub: &[u8; 32]) -> ReportData {
    let mut rd = [0u8; 64];
    rd[..32].copy_from_slice(kbs_nonce);
    rd[32..].copy_from_slice(guest_pub);
    ReportData::new(rd)
}

/// Build the 64-byte `REPORT_DATA` value for a §322 live-attestation
/// keepalive report — single source of truth for the layout (same
/// structural-enforcement story as [`report_data`]).
///
/// Wraps `hippius_types::report_data::live_attestation(nonce, vm_id)`,
/// which produces `nonce ‖ SHA-256(canonical-CBOR map binding
/// `LIVE_ATTESTATION_REPORT_DOMAIN` + `vm_id`)`. KBS recomputes the
/// same bytes via the same hippius-types helper before signing the
/// on-chain attestation.
pub fn live_attestation_report_data(
    kbs_nonce: &[u8; 32],
    vm_id: &str,
) -> Result<ReportData, AgentError> {
    let rd = hippius_types::report_data::live_attestation(kbs_nonce, vm_id)
        .map_err(|_| AgentError::SnpDevice("live-attestation-rd-build"))?;
    Ok(ReportData::new(rd))
}

/// Source of SNP attestation reports.
///
/// Production: [`crate::stages::snp_ioctl::SevGuestProvider`], which
/// opens `/dev/sev-guest` and issues `SNP_GET_REPORT` via the `sev`
/// crate. Tests + non-SNP dev hosts: [`MockSnpReportProvider`].
///
/// The trait takes [`ReportData`] (not `[u8; 64]`) so the §20 layout
/// is structurally enforced — see [`ReportData`]'s docs. A caller
/// cannot hand a provider arbitrary bytes that bypass the layout
/// helper; the only way to obtain a `ReportData` is via
/// [`report_data`].
pub trait SnpReportProvider {
    /// Request an SNP attestation report bound to `report_data`
    /// (already built via [`report_data`]).
    ///
    /// On success, returns exactly `SNP_REPORT_LEN` bytes. Real
    /// providers validate the response length before returning; mock
    /// providers MUST follow the same invariant (a 1184-byte canned
    /// blob is the contract for the type).
    fn get_report(&self, report_data: ReportData) -> Result<SnpReport, AgentError>;
}

/// Stage entry function — build `REPORT_DATA` and delegate to the
/// provider. Lifted here (instead of inside the provider) so the §20
/// byte-exact layout is enforced in one place regardless of which
/// provider runs.
///
/// `&dyn SnpReportProvider` (not generic) because the §21 pipeline is
/// not perf-critical; trait-object dispatch keeps `pipeline::run`'s
/// signature simple.
pub fn request(
    provider: &dyn SnpReportProvider,
    kbs_nonce: &[u8; 32],
    guest_pub: &[u8; 32],
) -> Result<SnpReport, AgentError> {
    let rd = report_data(kbs_nonce, guest_pub);
    provider.get_report(rd)
}

/// Byte offset of the `MEASUREMENT` field inside a `struct
/// snp_attestation_report` (AMD SEV-SNP ABI ≥ 1.55): `REPORT_DATA`
/// occupies `0x50..0x90`, `MEASUREMENT` the 48 bytes at `0x90`.
const MEASUREMENT_OFFSET: usize = 0x90;

/// Length of an SNP launch measurement (§20).
pub const MEASUREMENT_LEN: usize = 48;

/// Extract the 48-byte SNP launch measurement from `report`.
///
/// The guest needs its OWN measurement to build the `ExpectedRelease`
/// binding (PR-E1.3 verify stage). It MUST source it independently —
/// here, from the firmware-filled report it just generated — not trust
/// the value the KBS echoes back: the whole point of the §20
/// `measurement` binding is the guest confirming the KBS is talking
/// about *this* launch.
pub fn measurement(report: &SnpReport) -> Result<[u8; MEASUREMENT_LEN], AgentError> {
    report
        .0
        .get(MEASUREMENT_OFFSET..MEASUREMENT_OFFSET + MEASUREMENT_LEN)
        .and_then(|s| <[u8; MEASUREMENT_LEN]>::try_from(s).ok())
        .ok_or(AgentError::SnpDevice("short-report"))
}

/// Test / dev-host stand-in for the real `/dev/sev-guest` ioctl.
///
/// Captures every `REPORT_DATA` it sees so tests can pin the §20
/// layout end-to-end, and returns a deterministic 1184-byte canned
/// payload. Non-Linux dev builds of the binary use this to drive the
/// pipeline shape without claiming attestation — every downstream
/// step (KBS verify, HPKE unwrap) will fail closed because the canned
/// payload is not a real, AMD-signed attestation.
///
/// Public so [`crate::main`] can construct one on non-Linux targets
/// and so integration tests in `tests/` can pin the layout. Using one
/// in production would not bypass §20 — the KBS verifies the AMD
/// signature on the returned bytes and the canned payload has none.
pub struct MockSnpReportProvider {
    /// Canned 1184-byte response. `Vec<u8>` so the test can pre-load
    /// arbitrary patterns; the type-level length invariant is checked
    /// at [`Self::new`] time.
    canned_response: Vec<u8>,
    /// `Cell` so tests can observe what `REPORT_DATA` flowed through
    /// `get_report` without making the provider mutably-borrowed (the
    /// trait takes `&self` — production `SevGuestProvider` does not
    /// need interior mutability). Not thread-safe; the §21 pipeline
    /// is single-threaded.
    captured: Cell<Option<[u8; 64]>>,
}

impl MockSnpReportProvider {
    /// Build a mock whose `get_report` returns `canned_response`.
    ///
    /// Panics if `canned_response.len() != SNP_REPORT_LEN`: the
    /// production provider validates the same invariant, and a mock
    /// that returns the wrong size would mask a real bug at the next
    /// layer.
    pub fn new(canned_response: Vec<u8>) -> Self {
        assert_eq!(
            canned_response.len(),
            SNP_REPORT_LEN,
            "mock SNP report must be exactly {SNP_REPORT_LEN} bytes (got {})",
            canned_response.len(),
        );
        Self {
            canned_response,
            captured: Cell::new(None),
        }
    }

    /// Convenience constructor: a deterministic 1184-byte all-zero
    /// blob. Useful when a test only cares about the captured
    /// `REPORT_DATA`, not the response bytes.
    pub fn with_zeroed_response() -> Self {
        Self::new(vec![0u8; SNP_REPORT_LEN])
    }

    /// Pull the most recently captured `REPORT_DATA`. `None` if
    /// [`SnpReportProvider::get_report`] was never called on this
    /// mock; otherwise the exact 64 bytes that crossed the trait
    /// boundary.
    pub fn captured_report_data(&self) -> Option<[u8; 64]> {
        self.captured.get()
    }
}

impl SnpReportProvider for MockSnpReportProvider {
    fn get_report(&self, report_data: ReportData) -> Result<SnpReport, AgentError> {
        self.captured.set(Some(*report_data.as_bytes()));
        Ok(SnpReport(self.canned_response.clone()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn report_data_layout_is_exact() {
        // §20 byte-exact layout: nonce(32) ‖ pubkey(32).
        let nonce = [0xAAu8; 32];
        let pk = [0xBBu8; 32];
        let rd = report_data(&nonce, &pk);
        let bytes = rd.as_bytes();
        assert_eq!(&bytes[..32], &nonce);
        assert_eq!(&bytes[32..], &pk);
        assert_eq!(bytes.len(), 64);
    }

    #[test]
    fn mock_provider_captures_report_data() {
        // The mock MUST capture exactly the 64 bytes built by
        // `report_data` — used by `tests/compile_gate.rs` to pin the
        // §20 layout through the trait boundary.
        let provider = MockSnpReportProvider::with_zeroed_response();
        let nonce = [0x11u8; 32];
        let pk = [0x22u8; 32];
        let report = request(&provider, &nonce, &pk).unwrap();
        assert_eq!(report.0.len(), SNP_REPORT_LEN);

        let captured = provider
            .captured_report_data()
            .expect("get_report was called once");
        assert_eq!(&captured[..32], &nonce, "captured nonce drift");
        assert_eq!(&captured[32..], &pk, "captured pubkey drift");
    }

    #[test]
    fn mock_provider_returns_canned_bytes_verbatim() {
        let mut canned = vec![0u8; SNP_REPORT_LEN];
        canned[0] = 0xDE;
        canned[SNP_REPORT_LEN - 1] = 0xAD;
        let provider = MockSnpReportProvider::new(canned.clone());
        let report = request(&provider, &[0u8; 32], &[0u8; 32]).unwrap();
        assert_eq!(report.0, canned);
    }

    #[test]
    fn measurement_reads_the_48_bytes_at_offset_0x90() {
        // Plant a distinctive pattern at the MEASUREMENT offset and
        // confirm `measurement` slices exactly `0x90..0xC0`.
        let mut bytes = vec![0u8; SNP_REPORT_LEN];
        for (i, b) in bytes
            .iter_mut()
            .skip(MEASUREMENT_OFFSET)
            .take(MEASUREMENT_LEN)
            .enumerate()
        {
            *b = 0x40 | (i as u8);
        }
        let report = SnpReport(bytes);
        let m = measurement(&report).unwrap();
        assert_eq!(m.len(), 48);
        assert_eq!(m[0], 0x40);
        assert_eq!(m[47], 0x40 | 47);
    }

    #[test]
    fn measurement_rejects_a_short_report() {
        let report = SnpReport(vec![0u8; MEASUREMENT_OFFSET + 1]);
        assert!(matches!(
            measurement(&report),
            Err(AgentError::SnpDevice("short-report"))
        ));
    }

    #[test]
    #[should_panic(expected = "must be exactly")]
    fn mock_rejects_wrong_length_response() {
        // Defense in depth: a too-short canned blob would mask a
        // 1184-byte response-length regression in the real ioctl
        // wrapper. The mock pins the same invariant as the real
        // provider.
        let _ = MockSnpReportProvider::new(vec![0u8; SNP_REPORT_LEN - 1]);
    }
}
