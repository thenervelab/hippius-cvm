//! SEV-SNP attestation binding (ARCHITECTURE.md §7).
//!
//! AMD cert-chain + signature verification (VCEK→ASK→ARK, against AMD KDS)
//! is an infrastructure boundary: it requires the AMD KDS and the `sev`
//! ecosystem and is the §17 production wiring. It is modelled here as the
//! [`AttestationVerifier`] trait, which MUST return a [`VerifiedReport`]
//! ONLY after a cryptographically sound chain+signature+TCB check. The
//! security *contract logic* the KBS performs over that verified report
//! ([`check_attestation`]) is fully implemented and tested.

use crate::error::{KbsError, Result};
use crate::report_data::{ct_eq, REPORT_DATA_LEN};

pub const MEASUREMENT_LEN: usize = 48;

/// Output of a sound AMD-chain + signature + TCB verification.
#[derive(Debug, Clone)]
pub struct VerifiedReport {
    pub measurement: [u8; MEASUREMENT_LEN],
    pub report_data: [u8; REPORT_DATA_LEN],
    /// Reported TCB as a comparable monotonically-increasing value.
    pub tcb: u64,
    /// Raw SNP guest policy bits.
    pub policy: u64,
    /// Per-CPU platform identity (CHIP_ID), §8/§23 platform binding.
    pub chip_id: [u8; 64],
    /// The AMD certificate chain (VCEK → ASK → ARK) in PEM that the
    /// verifier just verified the report against. Captured here so the
    /// §280 evidence bundle the release path archives can carry the
    /// same bytes a future client verifier would re-anchor to AMD's
    /// root. Empty when the verifier impl is a mock that doesn't
    /// carry a real chain (tests). Production
    /// [`crate::snp_real::SevChainVerifier`] always populates it.
    pub chain_pem: Vec<u8>,
}

/// Verifies the AMD cert chain + report signature + TCB floor and returns a
/// [`VerifiedReport`]. Implementations MUST fail closed.
pub trait AttestationVerifier {
    fn verify(&self, raw_report: &[u8]) -> Result<VerifiedReport>;
}

/// The trust CLASS a measurement occupies in the §22 allowlist.
///
/// The offline allowlist is otherwise a FLAT 48-byte set: any accepted
/// measurement is indistinguishable from any other. That aliases a
/// blackbox host-attestor image against a tenant guest image — either
/// could satisfy a gate meant for the other. This tag NAMESPACES a
/// measurement so a future verifier ([`MeasurementAllowlist::class_of`],
/// PR-5) can require the *correct* class for a given release path.
///
/// Back-compat: serde defaults to [`AllowlistClass::Tenant`], so every
/// pre-existing signed manifest — which carries no `class` key — decodes
/// unchanged as a tenant measurement. Wire form is the stable snake_case
/// string (`tenant` / `host_attestor`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AllowlistClass {
    /// A tenant guest measurement — the default and legacy class.
    #[default]
    Tenant,
    /// A blackbox host-attestor measurement.
    HostAttestor,
}

/// The offline KBS allowlist (§6/§7/§22): which measurements are accepted
/// and, per measurement, which L1 ticket-signing `kid`s the KBS will
/// trust and which KBS response-signing `kid`s it may sign with — so
/// neither L1 nor KBS rotation can produce a release the guest will
/// reject. §22 also requires the artifact to be re-validated before
/// every release ([`pre_release_validate`]); the default no-ops for
/// test impls, but production `InstalledAllowlist` overrides it.
pub trait MeasurementAllowlist {
    fn contains(&self, measurement: &[u8; MEASUREMENT_LEN]) -> bool;
    fn accepts_l1_kid(&self, measurement: &[u8; MEASUREMENT_LEN], kid: &[u8]) -> bool;
    fn accepts_kbs_kid(&self, measurement: &[u8; MEASUREMENT_LEN], kid: &[u8]) -> bool;
    /// The [`AllowlistClass`] of `measurement`, or `None` if it is not
    /// allowlisted at all.
    ///
    /// [`contains`](Self::contains) stays deliberately class-agnostic — a
    /// measurement of ANY class is still "contained" — so no existing
    /// verifier behaviour changes. `class_of` is the new PRECISE,
    /// namespaced check: PR-5 will use it to require a host-attestor
    /// measurement where a host-attestor is expected (and reject a tenant
    /// measurement there, and vice-versa). The default returns `None`
    /// (test stubs that do not track a class); production
    /// [`crate::allowlist::InstalledAllowlist`] returns the entry's class.
    fn class_of(&self, _measurement: &[u8; MEASUREMENT_LEN]) -> Option<AllowlistClass> {
        None
    }
    fn pre_release_validate(&self) -> crate::error::Result<()> {
        Ok(())
    }
    /// The §22 manifest epoch currently installed. `0` if the impl
    /// does not track an epoch (test stubs). Production
    /// [`crate::allowlist::InstalledAllowlist`] returns the value of
    /// the loaded `AllowlistBody::epoch`. Used by the §280 evidence
    /// bundle so a verifier knows under which allowlist epoch the
    /// release was admitted.
    fn current_epoch(&self) -> u64 {
        0
    }
    /// SHA-256 of the signed §22 manifest bytes currently installed.
    /// `[0; 32]` if the impl does not track a manifest digest (test
    /// stubs). Production
    /// [`crate::allowlist::InstalledAllowlist`] computes this once at
    /// install. Lets the §280 evidence bundle commit to the exact
    /// manifest bytes a verifier can re-fetch from the §22 source +
    /// re-hash, without inlining the (potentially large) manifest.
    fn current_manifest_digest(&self) -> [u8; 32] {
        [0u8; 32]
    }
}

#[derive(Debug, Clone)]
pub struct LaunchPolicy {
    pub min_tcb: u64,
    /// Policy bits that MUST be set (e.g. debug-off), and a mask of bits
    /// allowed to vary; anything outside is denied.
    pub required_bits: u64,
    pub allowed_mask: u64,
}

/// §7 contract over an already cryptographically-verified report:
/// measurement ∈ ticket's allowed set ∈ offline allowlist; TCB ≥ policy;
/// launch policy within bounds; `REPORT_DATA` byte-equals the expected
/// `nonce ‖ guest_pubkey` (constant time). The guest key is taken from the
/// verified report ONLY.
pub fn check_attestation(
    report: &VerifiedReport,
    ticket_allowed: &[Vec<u8>],
    offline: &dyn MeasurementAllowlist,
    expected_report_data: &[u8; REPORT_DATA_LEN],
    policy: &LaunchPolicy,
) -> Result<()> {
    let in_ticket = ticket_allowed
        .iter()
        .any(|m| m.len() == MEASUREMENT_LEN && ct_eq(m, &report.measurement));
    if !in_ticket {
        return Err(KbsError::Attestation(
            "measurement not in ticket's allowed set".into(),
        ));
    }
    if !offline.contains(&report.measurement) {
        return Err(KbsError::Attestation(
            "measurement not in offline KBS allowlist".into(),
        ));
    }
    if report.tcb < policy.min_tcb {
        return Err(KbsError::Policy("TCB below policy floor".into()));
    }
    if report.policy & policy.required_bits != policy.required_bits {
        return Err(KbsError::Policy("required launch-policy bits unset".into()));
    }
    if report.policy & !(policy.required_bits | policy.allowed_mask) != 0 {
        return Err(KbsError::Policy("launch-policy bits out of bounds".into()));
    }
    if !ct_eq(&report.report_data, expected_report_data) {
        return Err(KbsError::Attestation("REPORT_DATA mismatch".into()));
    }
    Ok(())
}

/// §322 keepalive variant of [`check_attestation`] — same crypto
/// gates as release, MINUS the ticket-allowed-measurement check
/// (a keepalive carries no [`crate::ticket::OrderTicket`]; the §22
/// allowlist is the authoritative gate). Used by
/// `crate::keepalive::process_keepalive`.
pub fn check_keepalive_attestation(
    report: &VerifiedReport,
    offline: &dyn MeasurementAllowlist,
    expected_report_data: &[u8; REPORT_DATA_LEN],
    policy: &LaunchPolicy,
) -> Result<()> {
    if !offline.contains(&report.measurement) {
        return Err(KbsError::Attestation(
            "measurement not in offline KBS allowlist".into(),
        ));
    }
    if report.tcb < policy.min_tcb {
        return Err(KbsError::Policy("TCB below policy floor".into()));
    }
    if report.policy & policy.required_bits != policy.required_bits {
        return Err(KbsError::Policy("required launch-policy bits unset".into()));
    }
    if report.policy & !(policy.required_bits | policy.allowed_mask) != 0 {
        return Err(KbsError::Policy("launch-policy bits out of bounds".into()));
    }
    if !ct_eq(&report.report_data, expected_report_data) {
        return Err(KbsError::Attestation("REPORT_DATA mismatch".into()));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    struct All;
    impl MeasurementAllowlist for All {
        fn contains(&self, _m: &[u8; MEASUREMENT_LEN]) -> bool {
            true
        }
        fn accepts_l1_kid(&self, _m: &[u8; MEASUREMENT_LEN], _k: &[u8]) -> bool {
            true
        }
        fn accepts_kbs_kid(&self, _m: &[u8; MEASUREMENT_LEN], _k: &[u8]) -> bool {
            true
        }
    }
    struct None_;
    impl MeasurementAllowlist for None_ {
        fn contains(&self, _m: &[u8; MEASUREMENT_LEN]) -> bool {
            false
        }
        fn accepts_l1_kid(&self, _m: &[u8; MEASUREMENT_LEN], _k: &[u8]) -> bool {
            false
        }
        fn accepts_kbs_kid(&self, _m: &[u8; MEASUREMENT_LEN], _k: &[u8]) -> bool {
            false
        }
    }

    fn report(rd: [u8; 64]) -> VerifiedReport {
        VerifiedReport {
            measurement: [7u8; 48],
            report_data: rd,
            tcb: 10,
            policy: 0b10,
            chip_id: [0u8; 64],
            chain_pem: Vec::new(),
        }
    }
    fn policy() -> LaunchPolicy {
        LaunchPolicy {
            min_tcb: 5,
            required_bits: 0b10,
            allowed_mask: 0b1101,
        }
    }

    #[test]
    fn happy_path() {
        let rd = [3u8; 64];
        check_attestation(&report(rd), &[vec![7u8; 48]], &All, &rd, &policy()).unwrap();
    }

    #[test]
    fn measurement_not_in_ticket_denied() {
        let rd = [3u8; 64];
        assert!(check_attestation(&report(rd), &[vec![1u8; 48]], &All, &rd, &policy()).is_err());
    }

    #[test]
    fn measurement_not_in_offline_allowlist_denied() {
        let rd = [3u8; 64];
        assert!(check_attestation(&report(rd), &[vec![7u8; 48]], &None_, &rd, &policy()).is_err());
    }

    #[test]
    fn report_data_mismatch_denied() {
        assert!(check_attestation(
            &report([3u8; 64]),
            &[vec![7u8; 48]],
            &All,
            &[4u8; 64],
            &policy()
        )
        .is_err());
    }

    #[test]
    fn low_tcb_denied() {
        let mut r = report([3u8; 64]);
        r.tcb = 1;
        assert!(check_attestation(&r, &[vec![7u8; 48]], &All, &[3u8; 64], &policy()).is_err());
    }

    #[test]
    fn missing_required_policy_bit_denied() {
        let mut r = report([3u8; 64]);
        r.policy = 0b00;
        assert!(check_attestation(&r, &[vec![7u8; 48]], &All, &[3u8; 64], &policy()).is_err());
    }

    #[test]
    fn out_of_bounds_policy_bit_denied() {
        let mut r = report([3u8; 64]);
        r.policy = 0b10 | 0b100000;
        assert!(check_attestation(&r, &[vec![7u8; 48]], &All, &[3u8; 64], &policy()).is_err());
    }
}
