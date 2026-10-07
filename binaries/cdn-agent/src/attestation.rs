//! TLS-bound attestation report (spec §4.3.1).
//!
//! Every node serves its SNP report at `/.well-known/hippius-attestation`
//! with `REPORT_DATA = sha256(spki) ‖ 0^32`, where `spki` is the DER
//! SubjectPublicKeyInfo of the fleet wildcard certificate it serves. A
//! client that sees that certificate in its TLS handshake can check the
//! report's AMD signature and measurement and know which image served it.
//!
//! The report is refreshed whenever the wildcard key changes (I4 renews
//! it). Before the wildcard exists there is nothing to bind, and nothing
//! is served.

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use serde::Serialize;

use crate::error::{CdnError, Result};

/// Pinned length of an SEV-SNP attestation report.
pub const SNP_REPORT_LEN: usize = 1184;

/// `sha256(spki) ‖ 0^32`.
pub fn report_data(spki_sha256: &[u8; 32]) -> [u8; 64] {
    let mut rd = [0u8; 64];
    rd[..32].copy_from_slice(spki_sha256);
    rd
}

/// Source of SNP reports. Production: [`SevGuestProvider`].
pub trait SnpReportProvider: Send {
    fn get_report(&self, report_data: &[u8; 64]) -> Result<Vec<u8>>;
}

#[derive(Serialize)]
struct Doc {
    format: &'static str,
    spki_sha256_hex: String,
    report_b64: String,
}

/// The `PUT /v1/attestation` document.
pub fn document(spki_sha256: &[u8; 32], report: &[u8]) -> Result<Vec<u8>> {
    serde_json::to_vec(&Doc {
        format: "sev-snp-report-v1",
        spki_sha256_hex: hex::encode(spki_sha256),
        report_b64: B64.encode(report),
    })
    .map_err(|_| CdnError::Snp("encode"))
}

/// `/dev/sev-guest`, VMPL 0, like the other guest agents. The ioctl's
/// `unsafe` lives in the `sev` crate.
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
#[derive(Debug, Default)]
pub struct SevGuestProvider;

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
impl SnpReportProvider for SevGuestProvider {
    fn get_report(&self, report_data: &[u8; 64]) -> Result<Vec<u8>> {
        use sev::firmware::guest::Firmware;
        let mut fw = Firmware::open().map_err(|_| CdnError::Snp("open-failed"))?;
        let bytes = fw
            .get_report(None, Some(*report_data), Some(0))
            .map_err(|_| CdnError::Snp("ioctl-failed"))?;
        if bytes.len() != SNP_REPORT_LEN {
            return Err(CdnError::Snp("short-report"));
        }
        Ok(bytes)
    }
}

/// The platform provider, when this build has one.
pub fn platform_provider() -> Option<Box<dyn SnpReportProvider>> {
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    {
        Some(Box::new(SevGuestProvider))
    }
    #[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
    {
        None
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn report_data_layout() {
        let rd = report_data(&[0xab; 32]);
        assert_eq!(&rd[..32], &[0xab; 32]);
        assert_eq!(&rd[32..], &[0u8; 32]);
    }

    #[test]
    fn document_shape() {
        let d: serde_json::Value =
            serde_json::from_slice(&document(&[1u8; 32], &[2u8; 4]).unwrap()).unwrap();
        assert_eq!(d["format"], "sev-snp-report-v1");
        assert_eq!(d["spki_sha256_hex"], "01".repeat(32));
        assert_eq!(d["report_b64"], "AgICAg==");
    }
}
