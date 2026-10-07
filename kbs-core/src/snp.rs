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
/// string (`tenant` / `host_attestor` / `cdn_node`).
///
/// A KBS built before a variant existed rejects the WHOLE artifact that
/// carries it (`AllowlistEntry` is `deny_unknown_fields` and the enum is
/// closed), which denies every release. So a new class must be live on
/// the KBS before any manifest writes it: KBS first, then the allowlist
/// tool and vali.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AllowlistClass {
    /// A tenant guest measurement — the default and legacy class.
    #[default]
    Tenant,
    /// A blackbox host-attestor measurement.
    HostAttestor,
    /// One CDN node VM's launch measurement (`docs/design/cdn.md` §5.3).
    /// vali pins every CDN VM's measurement under this class
    /// individually — each launch measures differently (nonce, node id,
    /// family) — so the class, not one shared measurement, is what lets
    /// the KBS tell a CDN node from a tenant. See [`check_release_class`].
    CdnNode,
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
    /// measurement of ANY class is still "contained". `class_of` is the
    /// PRECISE, namespaced check: host-attestor enrolment requires
    /// [`AllowlistClass::HostAttestor`], and the release path requires
    /// the class that matches the ticket's role ([`check_release_class`]).
    /// The default treats every contained measurement as
    /// [`AllowlistClass::Tenant`] — what a legacy manifest decodes to,
    /// and what test stubs that track no class stand for; production
    /// [`crate::allowlist::InstalledAllowlist`] returns the entry's class.
    fn class_of(&self, measurement: &[u8; MEASUREMENT_LEN]) -> Option<AllowlistClass> {
        self.contains(measurement).then_some(AllowlistClass::Tenant)
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

/// What a ticket-backed release is FOR, resolved by [`check_release_class`]
/// from the attested measurement's allowlist class and the ticket's
/// signed `lifecycle_perms`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReleaseRole {
    /// An ordinary VM: its own disk key, userdata, lifecycle key.
    Tenant,
    /// A CDN node: the above plus the cdn-fleet keyring (K2).
    CdnNode,
}

/// The release-path class gate. Run right after [`check_attestation`]
/// (which proved the measurement is allowlisted at all).
///
/// The role is decided by TWO signed sources, and both must agree:
/// - the offline allowlist says the measurement is
///   [`AllowlistClass::CdnNode`] (signed by the §22 root);
/// - the OrderTicket carries [`crate::lifecycle::CDN_NODE_PERM`] in
///   `lifecycle_perms` (signed by L1 — vali registered this VM as a CDN
///   node).
///
/// A disagreement either way is refused: a tenant measurement with the
/// perm can never reach CDN fleet material, and a CDN measurement without
/// it can never be used as an ordinary VM (a miner holding a CDN node's
/// image cannot pair it with some tenant's ticket). Neither shape exists
/// before the first `cdn_node` pin, so this is inert until then.
///
/// What this does NOT defend against: today vali both pins measurements
/// (it holds the §22 signing seed) and mints tickets, so the two sources
/// are independent of the miner and the tenant, not of vali. A
/// compromised vali that pins its own image as `cdn_node` gets the fleet
/// keys, as it could already get any one VM's KEK. Binding `cdn_node` to
/// an offline-signed CDN image identity is the follow-up that closes it.
///
/// `refuse_host_attestor`: a [`AllowlistClass::HostAttestor`] measurement
/// listed in a ticket's `allowed_measurements` would otherwise pass a
/// release — the class was only ever checked at enrolment. Refused when
/// set (KBS config `[allowlist] enforce_release_class`), which ships off
/// so the flip can follow a check that no live VM depends on it.
pub fn check_release_class(
    offline: &dyn MeasurementAllowlist,
    measurement: &[u8; MEASUREMENT_LEN],
    lifecycle_perms: &[String],
    refuse_host_attestor: bool,
) -> Result<ReleaseRole> {
    let wants_cdn = lifecycle_perms
        .iter()
        .any(|p| p == crate::lifecycle::CDN_NODE_PERM);
    match (offline.class_of(measurement), wants_cdn) {
        (Some(AllowlistClass::Tenant), false) => Ok(ReleaseRole::Tenant),
        (Some(AllowlistClass::CdnNode), true) => Ok(ReleaseRole::CdnNode),
        (Some(AllowlistClass::HostAttestor), false) if !refuse_host_attestor => {
            Ok(ReleaseRole::Tenant)
        }
        (Some(AllowlistClass::HostAttestor), _) => Err(KbsError::Attestation(
            "release-class-mismatch: measurement is host_attestor-class".into(),
        )),
        (Some(AllowlistClass::Tenant), true) => Err(KbsError::Attestation(
            "cdn-perm-class-mismatch: ticket carries the cdn-node perm but the measurement \
             is not cdn_node-class"
                .into(),
        )),
        (Some(AllowlistClass::CdnNode), false) => Err(KbsError::Attestation(
            "cdn-class-without-perm: measurement is cdn_node-class but the ticket does not \
             carry the cdn-node perm"
                .into(),
        )),
        (None, _) => Err(KbsError::Attestation(
            "measurement not in offline KBS allowlist".into(),
        )),
    }
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

    /// Every measurement is allowlisted under one fixed class.
    struct Classed(AllowlistClass);
    impl MeasurementAllowlist for Classed {
        fn contains(&self, _m: &[u8; MEASUREMENT_LEN]) -> bool {
            true
        }
        fn accepts_l1_kid(&self, _m: &[u8; MEASUREMENT_LEN], _k: &[u8]) -> bool {
            true
        }
        fn accepts_kbs_kid(&self, _m: &[u8; MEASUREMENT_LEN], _k: &[u8]) -> bool {
            true
        }
        fn class_of(&self, _m: &[u8; MEASUREMENT_LEN]) -> Option<AllowlistClass> {
            Some(self.0)
        }
    }

    fn perms(p: &[&str]) -> Vec<String> {
        p.iter().map(|s| (*s).to_string()).collect()
    }

    #[test]
    fn default_class_of_is_tenant_for_contained_and_none_otherwise() {
        assert_eq!(All.class_of(&[7u8; 48]), Some(AllowlistClass::Tenant));
        assert_eq!(None_.class_of(&[7u8; 48]), None);
    }

    #[test]
    fn release_class_matrix() {
        use crate::lifecycle::CDN_NODE_PERM;
        let m = [7u8; 48];
        let cdn = perms(&[CDN_NODE_PERM]);
        let none = perms(&[]);
        let t = Classed(AllowlistClass::Tenant);
        let c = Classed(AllowlistClass::CdnNode);
        let h = Classed(AllowlistClass::HostAttestor);
        for enforce in [false, true] {
            assert_eq!(
                check_release_class(&t, &m, &none, enforce).unwrap(),
                ReleaseRole::Tenant
            );
            assert_eq!(
                check_release_class(&c, &m, &cdn, enforce).unwrap(),
                ReleaseRole::CdnNode
            );
            assert!(check_release_class(&t, &m, &cdn, enforce).is_err());
            assert!(check_release_class(&c, &m, &none, enforce).is_err());
            assert!(check_release_class(&h, &m, &cdn, enforce).is_err());
            assert!(check_release_class(&None_, &m, &none, enforce).is_err());
        }
        assert_eq!(
            check_release_class(&h, &m, &none, false).unwrap(),
            ReleaseRole::Tenant
        );
        assert!(check_release_class(&h, &m, &none, true).is_err());
    }

    #[test]
    fn the_cdn_perm_matches_exactly() {
        // A look-alike perm is not the perm: no prefix, case or padding games.
        let c = Classed(AllowlistClass::CdnNode);
        for p in ["cdn-node ", "CDN-NODE", "cdn-node-x", "cdn", ""] {
            assert!(
                check_release_class(&c, &[7u8; 48], &perms(&[p]), false).is_err(),
                "{p:?}"
            );
        }
    }
}
