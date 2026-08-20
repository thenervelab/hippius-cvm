//! Blackbox **host-attestor** enrollment verifier (blackbox
//! host-attestor chantier — PR-5).
//!
//! The host attestor is a small agent running on the bare-metal
//! SEV-SNP host — *outside* every tenant CVM. Once per boot it
//! generates an Ed25519 signer keypair, folds a
//! [`hippius_types::report_data::host_attestor`] binding
//! (`nonce ‖ SHA-256(canonical{domain, node_id, attestor_pubkey})`)
//! into its **platform** SNP report, and ships a
//! [`HostEnrollment`](hippius_types::host_attestor::HostEnrollment) to
//! the KBS. [`process_host_attestation`] re-verifies that report
//! against AMD's silicon root + the §22 allowlist and, on success,
//! mints a KBS-L0-signed
//! [`HostAttestorCert`](hippius_types::host_attestor::HostAttestorCert)
//! binding the now-trusted `attestor_pubkey` to the `node_id` + the
//! AMD-signed `chip_id`. The validator (a later PR) pins that cert and
//! then trusts the attestor's periodic
//! [`SignedHostBeacon`](hippius_types::host_attestor::SignedHostBeacon)s
//! against the enrolled key — no fresh full SNP verification per beat.
//!
//! ## Trust model — the platform SNP report is the anchor
//!
//! A miner host cannot forge an enrollment: it has no access to the L0
//! KBS signing key, and the KBS will not mint a cert for a report it
//! cannot cryptographically verify against AMD's root. The
//! `attestor_pubkey` + `node_id` are **not** trusted from the
//! self-declared envelope fields — they are recomputed into the
//! report's `REPORT_DATA` and byte-matched, so the cert credits only
//! the identity the silicon actually signed over.
//!
//! ## Verification chain (every gate fail-closed)
//!
//! 1. **AMD-root verify** the 1184-byte platform report (VCEK → ASK →
//!    ARK) → a [`VerifiedReport`](crate::snp::VerifiedReport).
//! 2. **Measurement class gate** — the measurement MUST be allowlisted
//!    with class [`AllowlistClass::HostAttestor`]. A `Tenant`-class (or
//!    un-allowlisted) measurement is rejected: this closes the
//!    tenant↔host measurement aliasing (a tenant image cannot enrol as
//!    a host attestor).
//! 3. **REPORT_DATA bind** — recompute
//!    [`report_data::host_attestor`]`(nonce, signer_pubkey, node_id)`
//!    from the KBS-minted `nonce` (NOT the envelope) + the enrollment's
//!    `signer_pubkey` + `node_id`, and require byte-exact equality with
//!    the verified report's `REPORT_DATA`. This is what makes
//!    `attestor_pubkey` + `node_id` *attested* rather than asserted.
//! 4. **Surface** `chip_id` + `measurement` + `tcb` from the verified
//!    report (the cert carries the AMD-signed `chip_id`, never a
//!    caller-supplied value).
//! 5. **Mint** the L0 [`HostAttestorCert`] and sign it with the KBS L0
//!    key under [`HOST_ATTESTOR_CERT_DOMAIN`].
//!
//! ## `boot_id` / `issued_at_unix` are NOT attested
//!
//! Those two envelope fields are **not** in `REPORT_DATA` (PR-1 note),
//! so they are unauthenticated. This verifier never reads them for any
//! security decision and never copies them into the cert. Anti-replay
//! rests solely on the single-use `nonce` folded into `REPORT_DATA`.
//!
//! Ships **inert** — no KBS-server route wires this yet (that is the
//! KBS-server + vali PR).

use ed25519_dalek::{Signer, SigningKey};
use hippius_types::host_attestor::{
    HostAttestorCert, HostEnrollment, SignedHostAttestorCert, HOST_ATTESTOR_SCHEMA_VERSION,
};
use hippius_types::report_data;

use crate::error::{KbsError, Result};
use crate::release::AuditSink;
use crate::report_data::ct_eq;
use crate::snp::{AllowlistClass, AttestationVerifier, MeasurementAllowlist};

/// Per-call inputs.
pub struct HostAttestationRequest<'a> {
    /// The once-per-boot enrollment envelope the attestor shipped. Its
    /// `snp_report` is the platform report the KBS re-verifies; its
    /// `signer_pubkey` + `node_id` are bound INTO `REPORT_DATA` (and so
    /// attested) — its `boot_id` / `issued_at_unix` are NOT attested and
    /// are never trusted here.
    pub enrollment: &'a HostEnrollment,
    /// The vali/KBS-minted single-use nonce this enrollment MUST bind
    /// into `REPORT_DATA[0..32]`. Passed in by the caller — it is the
    /// freshness anchor and is deliberately **NOT** taken from the
    /// enrollment envelope (which is attacker-controlled).
    pub nonce: &'a [u8; 32],
    /// `nowUnix` source — used for the audit window + to reject an
    /// already-expired cert window.
    pub now_unix: u64,
    /// Hard expiry for the minted cert, Unix seconds. MUST be strictly
    /// after `now_unix`; the validator rejects a cert whose
    /// `expiry_unix <= now`.
    pub expiry_unix: u64,
}

/// Per-call dependencies.
pub struct HostAttestationDeps<'a> {
    /// AMD cert-chain + signature + TCB verifier (production
    /// [`crate::snp_real::SevChainVerifier`]).
    pub attn: &'a dyn AttestationVerifier,
    /// The §22 offline allowlist — the authoritative measurement +
    /// class gate.
    pub allowlist: &'a dyn MeasurementAllowlist,
    /// The KBS L0 signing key — mints the enrollment cert. Same key the
    /// keepalive flow signs its bodies with.
    pub kbs_signing_key: &'a SigningKey,
    /// Audit sink — records the grant/deny decision.
    pub audit: &'a dyn AuditSink,
}

/// Process one host-attestor enrollment. On success: returns a
/// KBS-L0-signed [`SignedHostAttestorCert`]. On any failure: returns a
/// typed [`KbsError`] + records an audit denial; nothing is signed.
pub fn process_host_attestation(
    req: &HostAttestationRequest,
    deps: &HostAttestationDeps,
) -> Result<SignedHostAttestorCert> {
    match run(req, deps) {
        Ok(signed) => {
            deps.audit.record(
                true,
                None,
                Some(&req.enrollment.node_id),
                "host-attestor-enroll-granted",
            );
            Ok(signed)
        }
        Err(e) => {
            let reason = e.to_string();
            deps.audit
                .record(false, None, Some(&req.enrollment.node_id), &reason);
            Err(e)
        }
    }
}

fn run(req: &HostAttestationRequest, deps: &HostAttestationDeps) -> Result<SignedHostAttestorCert> {
    let enrollment = req.enrollment;

    // 0. Reject a malformed envelope up front (fail-closed) — empty
    // node_id / unknown schema would otherwise poison the cert.
    enrollment.validate()?;

    // 1. Cryptographic verify of the raw platform SNP report (VCEK →
    // ASK → ARK against AMD silicon root). Same trait + production impl
    // as release / keepalive.
    let report = deps.attn.verify(&enrollment.snp_report)?;

    // 2. Measurement CLASS gate — the measurement MUST be allowlisted
    // AND carry the host-attestor class. `class_of` returns `None` for
    // an un-allowlisted measurement and `Some(Tenant)` for a tenant
    // image; both are rejected here. This is the namespace security:
    // a tenant guest image cannot enrol as a host attestor.
    match deps.allowlist.class_of(&report.measurement) {
        Some(AllowlistClass::HostAttestor) => {}
        Some(AllowlistClass::Tenant) => {
            return Err(KbsError::Attestation(
                "measurement is Tenant-class, not a host-attestor measurement".into(),
            ));
        }
        None => {
            return Err(KbsError::Attestation(
                "measurement not in offline KBS allowlist (host-attestor class required)".into(),
            ));
        }
    }

    // 3. REPORT_DATA bind — recompute the expected 64 bytes from the
    // KBS-minted `nonce` (NOT the envelope) + the enrollment's
    // `signer_pubkey` + `node_id`, and require byte-exact equality with
    // the verified report. This binds the signer pubkey + node_id + a
    // fresh single-use nonce into the AMD-signed report, so both become
    // attested rather than self-declared.
    let expected_rd =
        report_data::host_attestor(req.nonce, &enrollment.signer_pubkey, &enrollment.node_id)?;
    if !ct_eq(&report.report_data, &expected_rd) {
        return Err(KbsError::Attestation(
            "REPORT_DATA mismatch (nonce / signer_pubkey / node_id do not match the report)".into(),
        ));
    }

    // 4. Reject an already-expired / inverted cert window (fail-closed).
    if req.expiry_unix <= req.now_unix {
        return Err(KbsError::Policy(
            "cert expiry_unix must be strictly after now_unix".into(),
        ));
    }

    // 5. Mint the L0 cert. `chip_id` / `measurement` / `tcb` are surfaced
    // from the AMD-signed report; `attestor_pubkey` / `node_id` are the
    // report_data-attested identity. Nothing here is a caller-supplied
    // platform value.
    let cert = HostAttestorCert {
        schema_version: HOST_ATTESTOR_SCHEMA_VERSION,
        node_id: enrollment.node_id.clone(),
        chip_id: report.chip_id,
        attestor_pubkey: enrollment.signer_pubkey,
        measurement: report.measurement,
        tcb: report.tcb,
        nonce: *req.nonce,
        expiry_unix: req.expiry_unix,
    };
    let body = cert.canonical()?;
    let sig = deps.kbs_signing_key.sign(&body).to_bytes();
    Ok(SignedHostAttestorCert { body, sig })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::snp::{VerifiedReport, MEASUREMENT_LEN};
    use ed25519_dalek::{Verifier, VerifyingKey};
    use hippius_types::report_data::REPORT_DATA_LEN;
    use std::sync::Mutex;

    // ── allowlist stubs (each fixes a `class_of` answer) ───────────

    struct HostClass;
    impl MeasurementAllowlist for HostClass {
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
            Some(AllowlistClass::HostAttestor)
        }
    }

    struct TenantClass;
    impl MeasurementAllowlist for TenantClass {
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
            Some(AllowlistClass::Tenant)
        }
    }

    // Not allowlisted at all — `class_of` returns `None` (the default).
    struct Unlisted;
    impl MeasurementAllowlist for Unlisted {
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

    /// Verifier stub that returns a canned [`VerifiedReport`].
    struct StubVerifier {
        report: VerifiedReport,
    }
    impl AttestationVerifier for StubVerifier {
        fn verify(&self, _raw: &[u8]) -> Result<VerifiedReport> {
            Ok(self.report.clone())
        }
    }

    /// Verifier stub whose AMD-chain verification fails (bad chain).
    struct FailVerifier;
    impl AttestationVerifier for FailVerifier {
        fn verify(&self, _raw: &[u8]) -> Result<VerifiedReport> {
            Err(KbsError::Attestation("mock: bad AMD chain".into()))
        }
    }

    type AuditRow = (bool, Option<String>, Option<String>, String);
    #[derive(Default)]
    struct RecordingAudit {
        records: Mutex<Vec<AuditRow>>,
    }
    impl AuditSink for RecordingAudit {
        fn record(
            &self,
            granted: bool,
            ticket_id: Option<&str>,
            vm_id: Option<&str>,
            reason: &str,
        ) {
            if let Ok(mut g) = self.records.lock() {
                g.push((
                    granted,
                    ticket_id.map(str::to_string),
                    vm_id.map(str::to_string),
                    reason.to_string(),
                ));
            }
        }
    }

    const NODE_ID: &str = "node-host-1";
    const SIGNER_PK: [u8; 32] = [0x22; 32];
    const NONCE: [u8; 32] = [0x42; 32];
    const CHIP_ID: [u8; 64] = [0x9C; 64];
    const MEASUREMENT: [u8; MEASUREMENT_LEN] = [0xAA; MEASUREMENT_LEN];

    fn mk_report(report_data: [u8; REPORT_DATA_LEN]) -> VerifiedReport {
        VerifiedReport {
            measurement: MEASUREMENT,
            report_data,
            tcb: 0x0708_0000_0000_000B,
            policy: 0,
            chip_id: CHIP_ID,
            chain_pem: vec![0xCE; 16],
        }
    }

    fn enrollment(signer_pubkey: [u8; 32], node_id: &str) -> HostEnrollment {
        HostEnrollment {
            schema_version: HOST_ATTESTOR_SCHEMA_VERSION,
            snp_report: [0u8; 1184],
            signer_pubkey,
            node_id: node_id.into(),
            boot_id: "boot-abc".into(),
            issued_at_unix: 1_800_000_000,
        }
    }

    fn key() -> SigningKey {
        SigningKey::from_bytes(&[0x11u8; 32])
    }

    #[test]
    fn happy_path_mints_cert_bound_to_the_report() {
        let expected_rd = report_data::host_attestor(&NONCE, &SIGNER_PK, NODE_ID).unwrap();
        let verifier = StubVerifier {
            report: mk_report(expected_rd),
        };
        let allowlist = HostClass;
        let signing_key = key();
        let audit = RecordingAudit::default();
        let enr = enrollment(SIGNER_PK, NODE_ID);
        let req = HostAttestationRequest {
            enrollment: &enr,
            nonce: &NONCE,
            now_unix: 1_800_000_000,
            expiry_unix: 1_800_003_600,
        };
        let deps = HostAttestationDeps {
            attn: &verifier,
            allowlist: &allowlist,
            kbs_signing_key: &signing_key,
            audit: &audit,
        };

        let signed = process_host_attestation(&req, &deps).expect("happy enroll");
        let cert = HostAttestorCert::decode(&signed.body).unwrap();

        // chip_id / measurement / tcb surfaced from the report.
        assert_eq!(cert.chip_id, CHIP_ID);
        assert_eq!(cert.measurement, MEASUREMENT);
        assert_eq!(cert.tcb, 0x0708_0000_0000_000B);
        // identity attested via report_data recompute.
        assert_eq!(cert.node_id, NODE_ID);
        assert_eq!(cert.attestor_pubkey, SIGNER_PK);
        assert_eq!(cert.nonce, NONCE);
        assert_eq!(cert.expiry_unix, 1_800_003_600);

        // The KBS L0 signature over the exact body verifies.
        let vk: VerifyingKey = signing_key.verifying_key();
        let sig = ed25519_dalek::Signature::from_bytes(&signed.sig);
        vk.verify(&signed.body, &sig).expect("L0 sig verifies");

        // Audit granted.
        let recs = audit.records.lock().unwrap();
        assert_eq!(recs.len(), 1);
        assert!(recs[0].0);
    }

    #[test]
    fn cert_binds_chip_id_from_report_not_caller() {
        // The caller passes NO chip_id — a distinctive report chip_id
        // must surface into the cert unchanged.
        let expected_rd = report_data::host_attestor(&NONCE, &SIGNER_PK, NODE_ID).unwrap();
        let mut report = mk_report(expected_rd);
        report.chip_id = [0x5E; 64];
        let verifier = StubVerifier { report };
        let allowlist = HostClass;
        let signing_key = key();
        let audit = RecordingAudit::default();
        let enr = enrollment(SIGNER_PK, NODE_ID);
        let req = HostAttestationRequest {
            enrollment: &enr,
            nonce: &NONCE,
            now_unix: 1_800_000_000,
            expiry_unix: 1_800_003_600,
        };
        let deps = HostAttestationDeps {
            attn: &verifier,
            allowlist: &allowlist,
            kbs_signing_key: &signing_key,
            audit: &audit,
        };
        let signed = process_host_attestation(&req, &deps).unwrap();
        let cert = HostAttestorCert::decode(&signed.body).unwrap();
        assert_eq!(cert.chip_id, [0x5E; 64]);
    }

    #[test]
    fn rejects_tenant_class_measurement() {
        let expected_rd = report_data::host_attestor(&NONCE, &SIGNER_PK, NODE_ID).unwrap();
        let verifier = StubVerifier {
            report: mk_report(expected_rd),
        };
        let allowlist = TenantClass;
        let signing_key = key();
        let audit = RecordingAudit::default();
        let enr = enrollment(SIGNER_PK, NODE_ID);
        let req = HostAttestationRequest {
            enrollment: &enr,
            nonce: &NONCE,
            now_unix: 1_800_000_000,
            expiry_unix: 1_800_003_600,
        };
        let deps = HostAttestationDeps {
            attn: &verifier,
            allowlist: &allowlist,
            kbs_signing_key: &signing_key,
            audit: &audit,
        };
        assert!(matches!(
            process_host_attestation(&req, &deps),
            Err(KbsError::Attestation(_))
        ));
        assert!(!audit.records.lock().unwrap()[0].0);
    }

    #[test]
    fn rejects_unallowlisted_measurement() {
        let expected_rd = report_data::host_attestor(&NONCE, &SIGNER_PK, NODE_ID).unwrap();
        let verifier = StubVerifier {
            report: mk_report(expected_rd),
        };
        let allowlist = Unlisted;
        let signing_key = key();
        let audit = RecordingAudit::default();
        let enr = enrollment(SIGNER_PK, NODE_ID);
        let req = HostAttestationRequest {
            enrollment: &enr,
            nonce: &NONCE,
            now_unix: 1_800_000_000,
            expiry_unix: 1_800_003_600,
        };
        let deps = HostAttestationDeps {
            attn: &verifier,
            allowlist: &allowlist,
            kbs_signing_key: &signing_key,
            audit: &audit,
        };
        assert!(matches!(
            process_host_attestation(&req, &deps),
            Err(KbsError::Attestation(_))
        ));
    }

    #[test]
    fn rejects_wrong_nonce() {
        // Report bound to a DIFFERENT nonce than the one passed in.
        let other = [0x99; 32];
        let bound_rd = report_data::host_attestor(&other, &SIGNER_PK, NODE_ID).unwrap();
        let verifier = StubVerifier {
            report: mk_report(bound_rd),
        };
        let allowlist = HostClass;
        let signing_key = key();
        let audit = RecordingAudit::default();
        let enr = enrollment(SIGNER_PK, NODE_ID);
        let req = HostAttestationRequest {
            enrollment: &enr,
            nonce: &NONCE,
            now_unix: 1_800_000_000,
            expiry_unix: 1_800_003_600,
        };
        let deps = HostAttestationDeps {
            attn: &verifier,
            allowlist: &allowlist,
            kbs_signing_key: &signing_key,
            audit: &audit,
        };
        assert!(matches!(
            process_host_attestation(&req, &deps),
            Err(KbsError::Attestation(_))
        ));
    }

    #[test]
    fn rejects_wrong_signer_pubkey() {
        // Report bound to a DIFFERENT pubkey than the enrollment carries.
        let bound_rd = report_data::host_attestor(&NONCE, &[0x77; 32], NODE_ID).unwrap();
        let verifier = StubVerifier {
            report: mk_report(bound_rd),
        };
        let allowlist = HostClass;
        let signing_key = key();
        let audit = RecordingAudit::default();
        let enr = enrollment(SIGNER_PK, NODE_ID);
        let req = HostAttestationRequest {
            enrollment: &enr,
            nonce: &NONCE,
            now_unix: 1_800_000_000,
            expiry_unix: 1_800_003_600,
        };
        let deps = HostAttestationDeps {
            attn: &verifier,
            allowlist: &allowlist,
            kbs_signing_key: &signing_key,
            audit: &audit,
        };
        assert!(matches!(
            process_host_attestation(&req, &deps),
            Err(KbsError::Attestation(_))
        ));
    }

    #[test]
    fn rejects_wrong_node_id() {
        // Report bound to a DIFFERENT node_id than the enrollment claims.
        let bound_rd = report_data::host_attestor(&NONCE, &SIGNER_PK, "node-OTHER").unwrap();
        let verifier = StubVerifier {
            report: mk_report(bound_rd),
        };
        let allowlist = HostClass;
        let signing_key = key();
        let audit = RecordingAudit::default();
        let enr = enrollment(SIGNER_PK, NODE_ID);
        let req = HostAttestationRequest {
            enrollment: &enr,
            nonce: &NONCE,
            now_unix: 1_800_000_000,
            expiry_unix: 1_800_003_600,
        };
        let deps = HostAttestationDeps {
            attn: &verifier,
            allowlist: &allowlist,
            kbs_signing_key: &signing_key,
            audit: &audit,
        };
        assert!(matches!(
            process_host_attestation(&req, &deps),
            Err(KbsError::Attestation(_))
        ));
    }

    #[test]
    fn rejects_bad_amd_chain() {
        let verifier = FailVerifier;
        let allowlist = HostClass;
        let signing_key = key();
        let audit = RecordingAudit::default();
        let enr = enrollment(SIGNER_PK, NODE_ID);
        let req = HostAttestationRequest {
            enrollment: &enr,
            nonce: &NONCE,
            now_unix: 1_800_000_000,
            expiry_unix: 1_800_003_600,
        };
        let deps = HostAttestationDeps {
            attn: &verifier,
            allowlist: &allowlist,
            kbs_signing_key: &signing_key,
            audit: &audit,
        };
        assert!(matches!(
            process_host_attestation(&req, &deps),
            Err(KbsError::Attestation(_))
        ));
    }

    #[test]
    fn rejects_expired_window() {
        let expected_rd = report_data::host_attestor(&NONCE, &SIGNER_PK, NODE_ID).unwrap();
        let verifier = StubVerifier {
            report: mk_report(expected_rd),
        };
        let allowlist = HostClass;
        let signing_key = key();
        let audit = RecordingAudit::default();
        let enr = enrollment(SIGNER_PK, NODE_ID);
        let req = HostAttestationRequest {
            enrollment: &enr,
            nonce: &NONCE,
            now_unix: 1_800_003_600,
            expiry_unix: 1_800_000_000, // already expired
        };
        let deps = HostAttestationDeps {
            attn: &verifier,
            allowlist: &allowlist,
            kbs_signing_key: &signing_key,
            audit: &audit,
        };
        assert!(matches!(
            process_host_attestation(&req, &deps),
            Err(KbsError::Policy(_))
        ));
    }
}
