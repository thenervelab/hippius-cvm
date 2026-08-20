//! SNP attestation report provider for the §23 `tenant_telemetry`
//! `REPORT_DATA` layout.
//!
//! Mirrors the initramfs agent's `SnpReportProvider` design (PR-E1.2):
//! a trait the production `/dev/sev-guest` provider and the test mock
//! both implement, plus a [`ReportData`] newtype whose constructor is
//! crate-private so the §23 layout cannot be bypassed — the only way
//! to obtain a `ReportData` is [`report_data`], which routes through
//! [`hippius_types::report_data::tenant_telemetry`].

use core::cell::Cell;

use hippius_types::report_data::tenant_telemetry;

use crate::error::{Result, TelemetryError};

/// Pinned length of an SEV-SNP attestation report (AMD ABI v1.55+).
pub const SNP_REPORT_LEN: usize = 1184;

/// Byte offset of the `MEASUREMENT` field in a `snp_attestation_report`.
const MEASUREMENT_OFFSET: usize = 0x90;

/// Length of an SNP launch measurement.
pub const MEASUREMENT_LEN: usize = 48;

/// Raw SNP attestation report bytes — opaque transport material. The
/// KBS verifies it; the agent only carries it + reads its own
/// `MEASUREMENT` field. Non-secret (it crosses the wire to the KBS).
#[derive(Debug)]
pub struct SnpReport(pub Vec<u8>);

/// The §23 `tenant_telemetry` `REPORT_DATA` value.
///
/// The inner `[u8; 64]` is **private** and the only constructor is
/// [`report_data`] — so the §20/§23 byte-exact layout
/// `nonce ‖ SHA-256(canonical-cbor{…})` is structurally enforced: a
/// caller cannot hand a provider arbitrary 64 bytes.
pub struct ReportData([u8; 64]);

impl ReportData {
    /// Borrow the 64 bytes — for the `sev` crate's `get_report`.
    pub fn as_bytes(&self) -> &[u8; 64] {
        &self.0
    }
}

/// Build the §23 `tenant_telemetry` `REPORT_DATA` — the single source
/// of the layout, and the only way to construct a [`ReportData`].
pub fn report_data(
    nonce: &[u8; 32],
    signer_pubkey: &[u8; 32],
    node_id: &[u8],
    vm_id: &str,
) -> Result<ReportData> {
    let rd = tenant_telemetry(nonce, signer_pubkey, node_id, vm_id)?;
    Ok(ReportData(rd))
}

/// Source of SNP attestation reports. Production: [`SevGuestProvider`]
/// (`/dev/sev-guest`). Tests / non-SNP dev hosts: [`MockSnpReportProvider`].
pub trait SnpReportProvider {
    /// Request an SNP report bound to `report_data`. On success returns
    /// exactly [`SNP_REPORT_LEN`] bytes.
    fn get_report(&self, report_data: ReportData) -> Result<SnpReport>;
}

/// Extract the 48-byte SNP launch measurement from `report`.
///
/// The agent reads its OWN measurement from the report it generated —
/// it never trusts a value echoed by the KBS. The telemetry-certificate
/// verifier re-binds the KBS-signed measurement against this value.
pub fn measurement(report: &SnpReport) -> Result<[u8; MEASUREMENT_LEN]> {
    report
        .0
        .get(MEASUREMENT_OFFSET..MEASUREMENT_OFFSET + MEASUREMENT_LEN)
        .and_then(|s| <[u8; MEASUREMENT_LEN]>::try_from(s).ok())
        .ok_or(TelemetryError::Snp("short-report"))
}

/// Test / non-SNP-dev-host stand-in for `/dev/sev-guest`.
///
/// Captures every `REPORT_DATA` it sees (so a test can pin the §23
/// layout end-to-end) and returns a deterministic canned report.
/// Using one in production would not bypass §23 — the KBS verifies the
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
            return Err(TelemetryError::Snp("mock-report-length"));
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
/// SEV-SNP guest. The `unsafe` ioctl lives inside the `sev` crate —
/// this wrapper is `safe` Rust. No unit tests (it needs a real CVM);
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

        let mut fw = Firmware::open().map_err(|_| TelemetryError::Snp("open-failed"))?;
        // VMPL 0 — the v1 Hippius CVM layout (no SVSM / nested VMPL),
        // same as the initramfs agent. `message_version = None` → 1.
        let bytes = fw
            .get_report(None, Some(*report_data.as_bytes()), Some(0))
            .map_err(|_| TelemetryError::Snp("ioctl-failed"))?;
        if bytes.len() != SNP_REPORT_LEN {
            return Err(TelemetryError::Snp("short-report"));
        }
        Ok(SnpReport(bytes))
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn report_data_is_the_tenant_telemetry_layout() {
        let rd = report_data(&[1u8; 32], &[2u8; 32], b"node-1", "vm-1").unwrap();
        let expected = tenant_telemetry(&[1u8; 32], &[2u8; 32], b"node-1", "vm-1").unwrap();
        assert_eq!(rd.as_bytes(), &expected);
    }

    #[test]
    fn mock_captures_report_data_and_returns_canned_bytes() {
        let mock = MockSnpReportProvider::zeroed();
        let rd = report_data(&[9u8; 32], &[8u8; 32], b"node-x", "vm-x").unwrap();
        let expected = *rd.as_bytes();
        let report = mock.get_report(rd).unwrap();
        assert_eq!(report.0.len(), SNP_REPORT_LEN);
        assert_eq!(mock.captured_report_data(), Some(expected));
    }

    #[test]
    fn mock_rejects_a_wrong_length_canned_report() {
        assert!(matches!(
            MockSnpReportProvider::new(vec![0u8; SNP_REPORT_LEN - 1]),
            Err(TelemetryError::Snp("mock-report-length"))
        ));
    }

    #[test]
    fn measurement_reads_the_48_bytes_at_offset_0x90() {
        let mut bytes = vec![0u8; SNP_REPORT_LEN];
        for (i, b) in bytes
            .iter_mut()
            .skip(MEASUREMENT_OFFSET)
            .take(MEASUREMENT_LEN)
            .enumerate()
        {
            *b = 0x40 | (i as u8);
        }
        let m = measurement(&SnpReport(bytes)).unwrap();
        assert_eq!(m[0], 0x40);
        assert_eq!(m[47], 0x40 | 47);
    }

    #[test]
    fn measurement_rejects_a_short_report() {
        assert!(matches!(
            measurement(&SnpReport(vec![0u8; MEASUREMENT_OFFSET + 1])),
            Err(TelemetryError::Snp("short-report"))
        ));
    }
}
