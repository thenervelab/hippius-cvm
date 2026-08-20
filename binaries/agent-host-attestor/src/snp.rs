//! SNP attestation-report provider for the host-attestor enrollment
//! `REPORT_DATA` layout ([`hippius_types::report_data::host_attestor`]).
//!
//! Mirrors the sibling telemetry agent's `SnpReportProvider` (and the
//! initramfs agent's PR-E1.2 design): a trait the production
//! `/dev/sev-guest` provider and the test mock both implement, plus a
//! [`ReportData`] newtype whose constructor is crate-private so the
//! host-attestor layout cannot be bypassed — the only way to obtain a
//! [`ReportData`] is [`report_data`], which routes through the frozen
//! PR-1 helper.
//!
//! ## `/dev/sev-guest` serialization (R1 invariant)
//!
//! `/dev/sev-guest` is a single serialized, sequence-numbered channel
//! shared with the derived-key call in [`crate::derived_key`]. The
//! establish (derived-key) and enroll (report) interactions MUST NOT
//! race — a bad request poisons the channel for every later call. The
//! agent runs them strictly sequentially on the single main thread
//! (establish fully returns, closing its transient `Firmware` handle,
//! before enroll opens a new one), and NOTHING spawns a thread that
//! touches the device — the beacon loop signs with Ed25519 only and
//! never issues an SNP report. This provider therefore only ever runs
//! from the main thread, after establish has completed.

use core::cell::Cell;

use hippius_types::report_data::host_attestor;

use crate::error::{HostAttestorError, Result};

/// Pinned length of an SEV-SNP attestation report (AMD ABI v1.55+).
pub const SNP_REPORT_LEN: usize = 1184;

/// Raw SNP attestation-report bytes — opaque transport material. The
/// KBS verifies it; the agent only carries it (into the enrollment) and
/// reads its own platform fields ([`crate::platform`]). Non-secret (it
/// crosses the wire to the KBS).
#[derive(Debug, Clone)]
pub struct SnpReport(pub Vec<u8>);

/// The host-attestor enrollment `REPORT_DATA` value.
///
/// The inner `[u8; 64]` is **private** and the only constructor is
/// [`report_data`] — so the PR-1 byte-exact layout
/// `nonce ‖ SHA-256(canonical-cbor{domain, node_id, attestor_pubkey})`
/// is structurally enforced: a caller cannot hand a provider arbitrary
/// 64 bytes.
pub struct ReportData([u8; 64]);

impl ReportData {
    /// Borrow the 64 bytes — for the `sev` crate's `get_report`.
    pub fn as_bytes(&self) -> &[u8; 64] {
        &self.0
    }
}

/// Build the host-attestor enrollment `REPORT_DATA` — the single source
/// of the layout, and the only way to construct a [`ReportData`].
pub fn report_data(
    nonce: &[u8; 32],
    signer_pubkey: &[u8; 32],
    node_id: &str,
) -> Result<ReportData> {
    let rd = host_attestor(nonce, signer_pubkey, node_id)?;
    Ok(ReportData(rd))
}

/// Source of SNP attestation reports. Production: [`SevGuestProvider`]
/// (`/dev/sev-guest`). Tests / non-SNP dev hosts: [`MockSnpReportProvider`].
pub trait SnpReportProvider {
    /// Request an SNP report bound to `report_data`. On success returns
    /// exactly [`SNP_REPORT_LEN`] bytes.
    fn get_report(&self, report_data: ReportData) -> Result<SnpReport>;
}

/// Test / non-SNP-dev-host stand-in for `/dev/sev-guest`.
///
/// Captures every `REPORT_DATA` it sees (so a test can pin the enrollment
/// layout end-to-end) and returns a deterministic canned report. Using
/// one in production would not bypass attestation — the KBS verifies the
/// AMD signature on the bytes, which a canned blob does not carry.
pub struct MockSnpReportProvider {
    canned: Vec<u8>,
    captured: Cell<Option<[u8; 64]>>,
}

impl MockSnpReportProvider {
    /// Build a mock returning `canned`. `canned` MUST be exactly
    /// [`SNP_REPORT_LEN`] bytes — the production provider validates the
    /// same invariant, so a wrong-length mock would mask a real bug.
    pub fn new(canned: Vec<u8>) -> Result<Self> {
        if canned.len() != SNP_REPORT_LEN {
            return Err(HostAttestorError::Snp("mock-report-length"));
        }
        Ok(Self {
            canned,
            captured: Cell::new(None),
        })
    }

    /// A deterministic all-zero canned report.
    pub fn zeroed() -> Self {
        // `vec![0; SNP_REPORT_LEN]` is exactly the required length, so
        // `new` cannot fail here.
        Self {
            canned: vec![0u8; SNP_REPORT_LEN],
            captured: Cell::new(None),
        }
    }

    /// The most recent `REPORT_DATA` that crossed `get_report`.
    pub fn captured_report_data(&self) -> Option<[u8; 64]> {
        self.captured.get()
    }
}

impl SnpReportProvider for MockSnpReportProvider {
    fn get_report(&self, report_data: ReportData) -> Result<SnpReport> {
        self.captured.set(Some(*report_data.as_bytes()));
        Ok(SnpReport(self.canned.clone()))
    }
}

// ── Real provider — /dev/sev-guest (Linux/x86_64 only) ──────────────

/// Production [`SnpReportProvider`] backed by `/dev/sev-guest`.
///
/// Target-gated: the character device only exists on a Linux/x86_64
/// SEV-SNP guest. The `unsafe` ioctl lives inside the `sev` crate — this
/// wrapper is `safe` Rust. No unit tests (it needs a real CVM);
/// behavioural coverage runs through [`MockSnpReportProvider`].
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
#[derive(Debug, Default)]
pub struct SevGuestProvider;

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
impl SevGuestProvider {
    pub fn new() -> Self {
        Self
    }
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
impl SnpReportProvider for SevGuestProvider {
    fn get_report(&self, report_data: ReportData) -> Result<SnpReport> {
        use sev::firmware::guest::Firmware;

        let mut fw = Firmware::open().map_err(|_| HostAttestorError::Snp("open-failed"))?;
        // VMPL 0 — the v1 Hippius platform layout (no SVSM / nested
        // VMPL), same as the sibling telemetry / initramfs agents.
        // `message_version = None` → 1 for `get_report` (unlike
        // `get_derived_key`, where `None` → the poison-prone v2).
        let bytes = fw
            .get_report(None, Some(*report_data.as_bytes()), Some(0))
            .map_err(|_| HostAttestorError::Snp("ioctl-failed"))?;
        if bytes.len() != SNP_REPORT_LEN {
            return Err(HostAttestorError::Snp("short-report"));
        }
        Ok(SnpReport(bytes))
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn report_data_is_the_host_attestor_layout() {
        let rd = report_data(&[1u8; 32], &[2u8; 32], "node-host-1").unwrap();
        let expected = host_attestor(&[1u8; 32], &[2u8; 32], "node-host-1").unwrap();
        assert_eq!(rd.as_bytes(), &expected);
    }

    #[test]
    fn mock_captures_report_data_and_returns_canned_bytes() {
        let mock = MockSnpReportProvider::zeroed();
        let rd = report_data(&[9u8; 32], &[8u8; 32], "node-x").unwrap();
        let expected = *rd.as_bytes();
        let report = mock.get_report(rd).unwrap();
        assert_eq!(report.0.len(), SNP_REPORT_LEN);
        assert_eq!(mock.captured_report_data(), Some(expected));
    }

    #[test]
    fn mock_rejects_a_wrong_length_canned_report() {
        assert!(matches!(
            MockSnpReportProvider::new(vec![0u8; SNP_REPORT_LEN - 1]),
            Err(HostAttestorError::Snp("mock-report-length"))
        ));
    }
}
