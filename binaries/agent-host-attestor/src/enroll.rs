//! The once-per-boot host-attestor enrollment.
//!
//! After [`crate::establish`] builds the signer, the attestor requests
//! ONE platform SNP attestation report whose `REPORT_DATA` binds the
//! signer public key + `node_id` under
//! [`hippius_types::report_data::host_attestor`], and wraps it in a
//! [`HostEnrollment`] the KBS re-verifies against AMD's silicon root +
//! the platform allowlist before issuing the L0 enrollment cert.
//!
//! It also lifts the [`PlatformClaims`] (chip_id / measurement / TCB /
//! policy) out of that same report, so every later beacon self-declares
//! the platform identity that was actually attested — never free-form
//! bytes.
//!
//! ## `/dev/sev-guest` serialization (R1 invariant)
//!
//! This is the SECOND of the two per-boot device interactions. It runs
//! only after [`crate::establish`] has fully returned (its derived-key
//! `Firmware` handle closed), strictly sequenced on the single main
//! thread — never concurrent with the derived-key fetch, and never
//! interleaved with anything else (the beacon loop signs with Ed25519
//! only and never touches the device). See [`crate::establish`].

use hippius_types::host_attestor::{
    HostEnrollment, HOST_ATTESTOR_SCHEMA_VERSION, PUBKEY_LEN, SNP_REPORT_LEN,
};

use crate::error::{HostAttestorError, Result};
use crate::platform::PlatformClaims;
use crate::snp::{report_data, SnpReportProvider};

/// The result of a successful enrollment.
#[derive(Debug, Clone)]
pub struct Enrolled {
    /// The once-per-boot enrollment message to ship to the KBS.
    pub enrollment: HostEnrollment,
    /// The platform identity lifted from the enrollment report — folded
    /// into every subsequent beacon.
    pub platform: PlatformClaims,
}

/// Request the platform SNP report and assemble the [`HostEnrollment`].
///
/// `signer_pubkey` is [`crate::establish::Established::pubkey`]; `nonce`
/// is a fresh single-use nonce (see [`crate::nonce`] — a PR-10
/// placeholder until the vali nonce channel lands); `issued_at_unix` is
/// the enrollment timestamp.
///
/// Fails closed on a report request failure, a short report, or an
/// enrollment that fails its own [`HostEnrollment::validate`].
pub fn enroll(
    provider: &dyn SnpReportProvider,
    signer_pubkey: &[u8; PUBKEY_LEN],
    node_id: &str,
    boot_id: &str,
    nonce: &[u8; 32],
    issued_at_unix: u64,
) -> Result<Enrolled> {
    // Bind the signer key + node identity into the report's REPORT_DATA
    // via the frozen PR-1 helper — the single source of the layout.
    let rd = report_data(nonce, signer_pubkey, node_id)?;
    let report = provider.get_report(rd)?;

    // Lift the attested platform identity BEFORE consuming the report
    // bytes into the enrollment.
    let platform = PlatformClaims::from_report(&report)?;

    let snp_report: [u8; SNP_REPORT_LEN] = report
        .0
        .try_into()
        .map_err(|_| HostAttestorError::Snp("short-report"))?;

    let enrollment = HostEnrollment {
        schema_version: HOST_ATTESTOR_SCHEMA_VERSION,
        snp_report,
        signer_pubkey: *signer_pubkey,
        node_id: node_id.to_string(),
        boot_id: boot_id.to_string(),
        issued_at_unix,
    };
    // Fail closed early: surface an invalid enrollment here rather than
    // at frame-encode time.
    enrollment
        .validate()
        .map_err(|_| HostAttestorError::Enroll("invalid-enrollment"))?;

    Ok(Enrolled {
        enrollment,
        platform,
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::snp::{MockSnpReportProvider, SNP_REPORT_LEN};
    use hippius_types::report_data::host_attestor;

    fn planted_report() -> Vec<u8> {
        let mut b = vec![0u8; SNP_REPORT_LEN];
        // A non-zero chip_id so PlatformClaims is meaningful.
        for (i, byte) in b.iter_mut().skip(0x1A0).take(64).enumerate() {
            *byte = 0x80 | (i as u8);
        }
        b
    }

    #[test]
    fn enroll_binds_report_data_to_the_pubkey_and_node() {
        let provider = MockSnpReportProvider::new(planted_report()).unwrap();
        let pk = [0x22u8; PUBKEY_LEN];
        let nonce = [0x11u8; 32];
        let enrolled = enroll(
            &provider,
            &pk,
            "node-host-1",
            "boot-abc",
            &nonce,
            1_800_000_000,
        )
        .expect("enroll succeeds");

        // The REPORT_DATA the provider saw is exactly the frozen
        // host_attestor(nonce, pubkey, node_id) binding.
        let expected = host_attestor(&nonce, &pk, "node-host-1").unwrap();
        assert_eq!(provider.captured_report_data(), Some(expected));

        // The enrollment carries the bound key + identity.
        assert_eq!(enrolled.enrollment.signer_pubkey, pk);
        assert_eq!(enrolled.enrollment.node_id, "node-host-1");
        assert_eq!(enrolled.enrollment.boot_id, "boot-abc");
        assert_eq!(enrolled.enrollment.issued_at_unix, 1_800_000_000);
        assert_eq!(
            enrolled.enrollment.schema_version,
            HOST_ATTESTOR_SCHEMA_VERSION
        );
        // The platform claims were lifted from the same report.
        assert_eq!(enrolled.platform.chip_id()[0], 0x80);
    }

    #[test]
    fn enroll_round_trips_through_the_frozen_decoder() {
        let provider = MockSnpReportProvider::new(planted_report()).unwrap();
        let enrolled = enroll(
            &provider,
            &[0x22u8; PUBKEY_LEN],
            "node-host-1",
            "boot-abc",
            &[0x11u8; 32],
            1_800_000_000,
        )
        .unwrap();
        let body = enrolled.enrollment.canonical().unwrap();
        let decoded = HostEnrollment::decode(&body).unwrap();
        assert_eq!(decoded, enrolled.enrollment);
    }

    #[test]
    fn enroll_fails_closed_on_empty_node_id() {
        let provider = MockSnpReportProvider::new(planted_report()).unwrap();
        let err = enroll(
            &provider,
            &[0x22u8; PUBKEY_LEN],
            "",
            "boot-abc",
            &[0x11u8; 32],
            1_800_000_000,
        )
        .expect_err("an empty node_id must fail closed");
        assert_eq!(err.class(), "invalid-enrollment");
    }
}
