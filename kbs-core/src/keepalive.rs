//! Post-boot live-attestation flow (issue #322 — Phase B).
//!
//! The in-VM guest agent (the "blackbox": measured-launched inside
//! the SEV-SNP CVM, so it cannot fake what it claims about itself)
//! asks the kernel for a fresh `SNP_GET_REPORT` periodically + POSTs
//! the raw report to the KBS `/v1/attest/keepalive` endpoint. KBS
//! runs [`process_keepalive`] on the report; on success it returns a
//! KBS-L0-signed
//! [`hippius_types::live_attestation::SignedLiveAttestation`] body
//! the validator batches + submits on chain via
//! `pallet-compute-scoring::submit_live_attestation`.
//!
//! ## Trust model — the in-VM agent is the trust anchor
//!
//! A miner host cannot forge a live attestation: it has no access
//! to the L0 KBS signing key. KBS will not sign a live attestation
//! for a VM it cannot cryptographically verify is running: the SNP
//! report must validate against AMD's silicon root + carry a
//! `REPORT_DATA` binding the §22 allowlist + a KBS-minted single-
//! use nonce. So a miner who stops a tenant VM cannot make it
//! "look alive" — the only entity that can mint the bytes the
//! pallet accepts is a KBS that has just verified a fresh report
//! from inside that exact running CVM.
//!
//! ## Verification chain (every gate fail-closed)
//!
//! 1. §22 pre-validate the allowlist artifact (same as release).
//! 2. Cryptographically verify the SNP report (VCEK → ASK → ARK).
//! 3. Single-use KBS nonce — verify unspent + bind into `REPORT_DATA`.
//! 4. `REPORT_DATA` byte-equals [`hippius_types::report_data::
//!    live_attestation`] for `(kbs_nonce, vm_id)`.
//! 5. `measurement ∈ §22 allowlist` + TCB / launch-policy bounds.
//! 6. KBS signing kid accepted for the attested measurement.
//! 7. Per-VM replay chain — match `LiveAttestationStateStore` CAS,
//!    advance to `(seq+1, sha256(body))`.
//! 8. Sign the canonical-CBOR body with the KBS L0 key.
//! 9. Spend the nonce + record off-chain best-effort + audit.

use ed25519_dalek::{Signer, SigningKey};
use hippius_types::live_attestation::{
    LiveAttestation, SignedLiveAttestation, DIGEST_LEN, LIVE_ATTESTATION_SCHEMA_VERSION,
    MEASUREMENT_LEN, PUBKEY_LEN,
};
use hippius_types::report_data;
use sha2::{Digest, Sha256};

use crate::error::{KbsError, Result};
use crate::live_attestation::{LiveAttestationSink, LiveAttestationStateStore};
use crate::persist::KbsNonceStore;
use crate::release::AuditSink;
use crate::snp::{
    check_keepalive_attestation, AttestationVerifier, LaunchPolicy, MeasurementAllowlist,
};

/// Per-call inputs.
pub struct KeepaliveRequest<'a> {
    /// Stable tenant VM identifier — same value the §K heartbeat +
    /// the §20 release used. The KBS binds it into the
    /// `REPORT_DATA` expectation via
    /// [`report_data::live_attestation`] so a report minted for VM A
    /// cannot replay as a keepalive for VM B.
    pub vm_id: &'a str,
    /// The miner's persistent Ed25519 node identity. Copied into
    /// the signed body so the pallet can credit the right miner
    /// without trusting the submitter. The caller-of-KBS is
    /// responsible for proving this matches the SNP `chip_id` ↔
    /// node_id binding off-chain (typically: the agent connecting
    /// via the miner-agent vsock, or the host's chip_id resolves
    /// via the miner-agent identity registry — whichever applies
    /// to the deployment). PR 3 keeps KBS oblivious to that
    /// mapping: it signs whatever `node_id` the caller asserts,
    /// because the §22 chain + the allowlist already pin the
    /// measurement to the booted UKI.
    pub node_id: &'a [u8; PUBKEY_LEN],
    /// Raw 1184-byte SEV-SNP report bytes from `SNP_GET_REPORT`.
    pub raw_snp_report: &'a [u8],
    /// KBS-minted single-use nonce already issued to the guest
    /// (same `KbsNonceStore` as release).
    pub kbs_nonce: &'a [u8; 32],
    /// `nowUnix` source — the chain's `pallet_timestamp` clock,
    /// passed in from the route handler. Used for the audit window
    /// + the body's `verified_at_unix` field.
    pub now_unix: u64,
    /// The compute-pallet epoch the resulting attestation falls
    /// into. Looked up by the route handler from the latest
    /// observed chain state (cached + refreshed per request).
    pub epoch: u64,
    /// Hard expiry for the resulting body, Unix seconds. The pallet
    /// rejects on `expiry_unix <= now_unix`, so callers set this to
    /// (e.g.) `now_unix + 10 * 60` — long enough to absorb network
    /// delay and the validator's batch latency, short enough that a
    /// stale signed body cannot be re-submitted weeks later to
    /// inflate uptime.
    pub expiry_unix: u64,
}

/// Per-call dependencies.
pub struct KeepaliveDeps<'a> {
    pub attn: &'a dyn AttestationVerifier,
    pub offline_allowlist: &'a dyn MeasurementAllowlist,
    pub launch_policy: &'a LaunchPolicy,
    pub kbs_nonce_store: &'a dyn KbsNonceStore,
    pub state: &'a dyn LiveAttestationStateStore,
    pub sink: &'a dyn LiveAttestationSink,
    pub kbs_signing_key: &'a SigningKey,
    pub kbs_kid: &'a [u8],
    pub audit: &'a dyn AuditSink,
    /// SHA-256 of the substrate compute-chain genesis hash — same
    /// `T::ComputeChainGenesis::get()` the pallet enforces.
    pub chain_genesis: [u8; DIGEST_LEN],
    /// Opaque 32-byte pallet-instance discriminator — same
    /// `T::ComputePalletInstance::get()` the pallet enforces.
    pub pallet_instance: [u8; DIGEST_LEN],
}

/// Process one keepalive request. On success: returns a KBS-L0-
/// signed [`SignedLiveAttestation`] body the validator can ship
/// on-chain. On any failure: returns `KbsError` + records an audit
/// denial; nothing is signed, the nonce is NOT spent, the chain
/// state is NOT advanced.
pub fn process_keepalive(
    req: &KeepaliveRequest,
    deps: &KeepaliveDeps,
) -> Result<SignedLiveAttestation> {
    let r = run(req, deps);
    match r {
        Ok(signed) => {
            deps.audit
                .record(true, None, Some(req.vm_id), "keepalive-granted");
            Ok(signed)
        }
        Err(e) => {
            let reason = e.to_string();
            deps.audit.record(false, None, Some(req.vm_id), &reason);
            Err(e)
        }
    }
}

fn run(req: &KeepaliveRequest, deps: &KeepaliveDeps) -> Result<SignedLiveAttestation> {
    // 0. §22 pre-release allowlist revalidation (same artifact gate
    // as release).
    deps.offline_allowlist.pre_release_validate()?;

    // 1. Cryptographic verify of the raw SNP report (VCEK → ASK →
    // ARK against AMD silicon root). Same trait + production impl
    // as release.
    let report = deps.attn.verify(req.raw_snp_report)?;

    // 2. KBS-nonce freshness — the nonce in REPORT_DATA must be one
    // we durably issued, not yet spent, and within its TTL. Same
    // store as release; the nonce will be spent only on the
    // success path below (after the chain advance).
    deps.kbs_nonce_store
        .verify_unspent(req.kbs_nonce, req.now_unix)?;

    // 3. Expected REPORT_DATA = nonce ‖ SHA-256(CBOR map binding
    // `LIVE_ATTESTATION_REPORT_DOMAIN` + `vm_id`). Self-delimiting
    // preimage — see `hippius_types::report_data::live_attestation`.
    let expected_rd = report_data::live_attestation(req.kbs_nonce, req.vm_id)?;

    // 4. Allowlist + TCB + launch policy + REPORT_DATA byte-eq.
    // No ticket-allowed list (no ticket in the keepalive flow); the
    // §22 allowlist is the authoritative measurement gate.
    check_keepalive_attestation(
        &report,
        deps.offline_allowlist,
        &expected_rd,
        deps.launch_policy,
    )?;

    // 5. KBS signing kid must be accepted for the attested
    // measurement (§6) — closes the rotation bypass.
    if !deps
        .offline_allowlist
        .accepts_kbs_kid(&report.measurement, deps.kbs_kid)
    {
        return Err(KbsError::Policy(
            "KBS kid not accepted for attested measurement".into(),
        ));
    }

    // 6. Compute the VCEK chain digest off the verified report so
    // the on-chain body cross-references the §280 evidence bundle
    // (both share the same digest). The verifier already populated
    // `chain_pem` (Phase 1 of #280).
    let vcek_chain_digest: [u8; DIGEST_LEN] = Sha256::digest(&report.chain_pem).into();
    let snp_report_digest: [u8; DIGEST_LEN] = Sha256::digest(req.raw_snp_report).into();

    // 7. KBS L0 verifying key — `SigningKey::verifying_key` is the
    // canonical Ed25519 public key derived from the secret.
    let signer_pubkey: [u8; PUBKEY_LEN] = deps.kbs_signing_key.verifying_key().to_bytes();

    // 8. Per-VM replay-chain seed.
    let chain = deps.state.get_chain(req.vm_id)?;

    // 9. Build the body. `measurement` must be exactly 48 bytes;
    // the verifier already enforced this (`SnpReport::measurement`
    // is `[u8; 48]`).
    let measurement: [u8; MEASUREMENT_LEN] = report.measurement;
    let body = LiveAttestation {
        schema_version: LIVE_ATTESTATION_SCHEMA_VERSION,
        chain_genesis: deps.chain_genesis,
        pallet_instance: deps.pallet_instance,
        vm_id: req.vm_id.to_string(),
        node_id: *req.node_id,
        attestation_seq: chain.next_seq,
        epoch: req.epoch,
        observed_at_unix: req.now_unix.saturating_sub(1),
        verified_at_unix: req.now_unix,
        snp_report_digest,
        vcek_chain_digest,
        measurement,
        prev_attestation_hash: chain.prev_attestation_hash,
        expiry_unix: req.expiry_unix,
        signer_pubkey,
    };
    let body_bytes = body.canonical()?;
    let body_hash: [u8; DIGEST_LEN] = Sha256::digest(&body_bytes).into();

    // 10. Atomically advance the per-VM chain — CAS against the
    // snapshot we read at (8). Mismatch ⇒ concurrent keepalive
    // landed first, fail closed; the nonce stays unspent.
    deps.state
        .commit_then_advance(req.vm_id, chain, chain.next_seq, body_hash)?;

    // 11. Sign the body with the KBS L0 key.
    let sig = deps.kbs_signing_key.sign(&body_bytes).to_bytes().to_vec();
    let signed = SignedLiveAttestation {
        body: body_bytes,
        sig,
    };

    // 12. Spend the nonce durably. A failure here AFTER the chain
    // advance is the same risk model as the §280 evidence bundle
    // archive — the durable side effect (chain advance) already
    // committed, the keepalive is materially issued. Logged via
    // the audit sink but does NOT roll back the chain (the next
    // keepalive will simply use the new seq).
    if let Err(e) = deps.kbs_nonce_store.spend(req.kbs_nonce, req.now_unix) {
        eprintln!(
            "live_attestation: nonce spend failed AFTER chain advance for vm_id={}: {}",
            req.vm_id, e
        );
    }

    // 13. Best-effort off-chain archive — readers (the future vali
    // batcher) ship these to the on-chain extrinsic.
    deps.sink.record(req.vm_id, &signed);
    Ok(signed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::live_attestation::{
        InMemoryLiveAttestationState, LiveAttestationChain, MockLiveAttestationSink,
        NullLiveAttestationSink,
    };
    use crate::persist::KbsNonceStore;
    use crate::snp::{VerifiedReport, MEASUREMENT_LEN as SNP_MEASUREMENT_LEN};
    use ed25519_dalek::SigningKey;
    use hippius_types::live_attestation::LiveAttestation;
    use hippius_types::report_data::REPORT_DATA_LEN;
    use std::collections::HashSet;
    use std::sync::Mutex;

    // In-memory `KbsNonceStore` — same shape as `release.rs::tests::
    // MockNonceStore`. `issue` fails because tests pre-load specific
    // nonces (no random generation needed at the test level).
    #[derive(Default)]
    struct MockNonceStore {
        issued: Mutex<HashSet<[u8; 32]>>,
        spent: Mutex<HashSet<[u8; 32]>>,
    }
    impl MockNonceStore {
        fn preissue(&self, n: [u8; 32]) {
            if let Ok(mut g) = self.issued.lock() {
                g.insert(n);
            }
        }
    }
    impl KbsNonceStore for MockNonceStore {
        fn issue(&self, _now: u64) -> Result<[u8; 32]> {
            Err(KbsError::Vault("mock: use preissue() in tests".into()))
        }
        fn verify_unspent(&self, n: &[u8; 32], _now: u64) -> Result<()> {
            let issued = self.issued.lock().map_err(|_| KbsError::Replay)?;
            if !issued.contains(n) {
                return Err(KbsError::Replay);
            }
            let spent = self.spent.lock().map_err(|_| KbsError::Replay)?;
            if spent.contains(n) {
                return Err(KbsError::Replay);
            }
            Ok(())
        }
        fn spend(&self, n: &[u8; 32], _now: u64) -> Result<()> {
            self.verify_unspent(n, 0)?;
            let mut spent = self.spent.lock().map_err(|_| KbsError::Replay)?;
            if !spent.insert(*n) {
                return Err(KbsError::Replay);
            }
            Ok(())
        }
    }

    // ── tiny stubs ────────────────────────────────────────────────

    struct AllAllowlist;
    impl MeasurementAllowlist for AllAllowlist {
        fn contains(&self, _m: &[u8; SNP_MEASUREMENT_LEN]) -> bool {
            true
        }
        fn accepts_l1_kid(&self, _m: &[u8; SNP_MEASUREMENT_LEN], _k: &[u8]) -> bool {
            true
        }
        fn accepts_kbs_kid(&self, _m: &[u8; SNP_MEASUREMENT_LEN], _k: &[u8]) -> bool {
            true
        }
    }

    struct DeniesKbsKid;
    impl MeasurementAllowlist for DeniesKbsKid {
        fn contains(&self, _m: &[u8; SNP_MEASUREMENT_LEN]) -> bool {
            true
        }
        fn accepts_l1_kid(&self, _m: &[u8; SNP_MEASUREMENT_LEN], _k: &[u8]) -> bool {
            true
        }
        fn accepts_kbs_kid(&self, _m: &[u8; SNP_MEASUREMENT_LEN], _k: &[u8]) -> bool {
            false
        }
    }

    /// Verifier stub whose `verify` returns a canned [`VerifiedReport`]
    /// built from the `(measurement, report_data)` we want.
    struct StubVerifier {
        report: VerifiedReport,
    }
    impl AttestationVerifier for StubVerifier {
        fn verify(&self, _raw: &[u8]) -> Result<VerifiedReport> {
            Ok(self.report.clone())
        }
    }

    /// Recording audit sink.
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

    fn mk_report(
        measurement: [u8; SNP_MEASUREMENT_LEN],
        report_data: [u8; REPORT_DATA_LEN],
    ) -> VerifiedReport {
        VerifiedReport {
            measurement,
            tcb: 0,
            policy: 0,
            chip_id: [0u8; 64],
            report_data,
            chain_pem: vec![0xCE; 16],
        }
    }

    fn policy() -> LaunchPolicy {
        LaunchPolicy {
            min_tcb: 0,
            required_bits: 0,
            allowed_mask: u64::MAX,
        }
    }

    /// Plumb a happy-path request + collect (request, deps, …) so
    /// each test can mutate one knob.
    fn happy_setup(vm_id: &str) -> (SigningKey, [u8; 32], MockNonceStore) {
        let key = SigningKey::from_bytes(&[0x42u8; 32]);
        let nonce = [0x42u8; 32];
        let store = MockNonceStore::default();
        store.preissue(nonce);
        let _ = vm_id;
        (key, nonce, store)
    }

    #[test]
    fn process_keepalive_happy_path() {
        let vm_id = "vm-kp-1";
        let (key, nonce, nonce_store) = happy_setup(vm_id);
        let expected_rd = report_data::live_attestation(&nonce, vm_id).unwrap();
        let verifier = StubVerifier {
            report: mk_report([0xAA; SNP_MEASUREMENT_LEN], expected_rd),
        };
        let allowlist = AllAllowlist;
        let policy = policy();
        let state = InMemoryLiveAttestationState::default();
        let sink = MockLiveAttestationSink::new();
        let audit = RecordingAudit::default();

        let req = KeepaliveRequest {
            vm_id,
            node_id: &[0xBB; 32],
            raw_snp_report: &[0u8; 1184],
            kbs_nonce: &nonce,
            now_unix: 1_800_000_000,
            epoch: 7,
            expiry_unix: 1_800_000_900,
        };
        let deps = KeepaliveDeps {
            attn: &verifier,
            offline_allowlist: &allowlist,
            launch_policy: &policy,
            kbs_nonce_store: &nonce_store,
            state: &state,
            sink: &sink,
            kbs_signing_key: &key,
            kbs_kid: b"kbs-l0",
            audit: &audit,
            chain_genesis: [0xCC; 32],
            pallet_instance: [0xDD; 32],
        };

        let signed = process_keepalive(&req, &deps).expect("happy keepalive");
        let body = LiveAttestation::decode(&signed.body).unwrap();
        assert_eq!(body.vm_id, vm_id);
        assert_eq!(body.node_id, [0xBB; 32]);
        assert_eq!(body.attestation_seq, 1);
        assert_eq!(body.prev_attestation_hash, [0u8; 32]);
        assert_eq!(body.epoch, 7);
        assert_eq!(body.chain_genesis, [0xCC; 32]);
        assert_eq!(body.pallet_instance, [0xDD; 32]);

        // State advanced.
        let after = state.get_chain(vm_id).unwrap();
        assert_eq!(after.next_seq, 2);
        assert_ne!(after.prev_attestation_hash, [0u8; 32]);

        // Sink recorded.
        assert_eq!(sink.len(), 1);

        // Audit granted.
        let recs = audit.records.lock().unwrap();
        assert_eq!(recs.len(), 1);
        assert!(recs[0].0); // granted
    }

    #[test]
    fn process_keepalive_chains_two_attestations() {
        let vm_id = "vm-kp-chain";
        let key = SigningKey::from_bytes(&[0x55u8; 32]);
        let nonce_store = MockNonceStore::default();
        let state = InMemoryLiveAttestationState::default();
        let sink = NullLiveAttestationSink;
        let audit = RecordingAudit::default();
        let policy = policy();

        // First keepalive.
        let n1 = [0x01u8; 32];
        nonce_store.preissue(n1);
        let rd1 = report_data::live_attestation(&n1, vm_id).unwrap();
        let v1 = StubVerifier {
            report: mk_report([0xAA; SNP_MEASUREMENT_LEN], rd1),
        };
        let allowlist = AllAllowlist;
        let req1 = KeepaliveRequest {
            vm_id,
            node_id: &[0xBB; 32],
            raw_snp_report: &[0u8; 1184],
            kbs_nonce: &n1,
            now_unix: 1_800_000_000,
            epoch: 7,
            expiry_unix: 1_800_000_900,
        };
        let deps1 = KeepaliveDeps {
            attn: &v1,
            offline_allowlist: &allowlist,
            launch_policy: &policy,
            kbs_nonce_store: &nonce_store,
            state: &state,
            sink: &sink,
            kbs_signing_key: &key,
            kbs_kid: b"kbs-l0",
            audit: &audit,
            chain_genesis: [0xCC; 32],
            pallet_instance: [0xDD; 32],
        };
        let s1 = process_keepalive(&req1, &deps1).unwrap();
        let body1 = LiveAttestation::decode(&s1.body).unwrap();
        let body1_hash: [u8; 32] = Sha256::digest(&s1.body).into();

        // Second keepalive.
        let n2 = [0x02u8; 32];
        nonce_store.preissue(n2);
        let rd2 = report_data::live_attestation(&n2, vm_id).unwrap();
        let v2 = StubVerifier {
            report: mk_report([0xAA; SNP_MEASUREMENT_LEN], rd2),
        };
        let req2 = KeepaliveRequest {
            vm_id,
            node_id: &[0xBB; 32],
            raw_snp_report: &[0u8; 1184],
            kbs_nonce: &n2,
            now_unix: 1_800_000_300,
            epoch: 7,
            expiry_unix: 1_800_001_200,
        };
        let deps2 = KeepaliveDeps { attn: &v2, ..deps1 };
        let s2 = process_keepalive(&req2, &deps2).unwrap();
        let body2 = LiveAttestation::decode(&s2.body).unwrap();
        assert_eq!(body2.attestation_seq, 2);
        assert_eq!(body2.prev_attestation_hash, body1_hash);
        assert!(body2.observed_at_unix > body1.observed_at_unix);
    }

    #[test]
    fn process_keepalive_rejects_spent_nonce() {
        let vm_id = "vm-kp-2";
        let (key, nonce, nonce_store) = happy_setup(vm_id);
        // Spend the nonce up-front; verify_unspent must reject.
        nonce_store.spend(&nonce, 0).unwrap();
        let expected_rd = report_data::live_attestation(&nonce, vm_id).unwrap();
        let verifier = StubVerifier {
            report: mk_report([0xAA; SNP_MEASUREMENT_LEN], expected_rd),
        };
        let allowlist = AllAllowlist;
        let policy = policy();
        let state = InMemoryLiveAttestationState::default();
        let sink = NullLiveAttestationSink;
        let audit = RecordingAudit::default();
        let req = KeepaliveRequest {
            vm_id,
            node_id: &[0xBB; 32],
            raw_snp_report: &[0u8; 1184],
            kbs_nonce: &nonce,
            now_unix: 1_800_000_000,
            epoch: 7,
            expiry_unix: 1_800_000_900,
        };
        let deps = KeepaliveDeps {
            attn: &verifier,
            offline_allowlist: &allowlist,
            launch_policy: &policy,
            kbs_nonce_store: &nonce_store,
            state: &state,
            sink: &sink,
            kbs_signing_key: &key,
            kbs_kid: b"kbs-l0",
            audit: &audit,
            chain_genesis: [0xCC; 32],
            pallet_instance: [0xDD; 32],
        };
        assert!(process_keepalive(&req, &deps).is_err());
        // No chain advance.
        assert_eq!(
            state.get_chain(vm_id).unwrap(),
            LiveAttestationChain::genesis()
        );
    }

    #[test]
    fn process_keepalive_rejects_wrong_report_data() {
        let vm_id = "vm-kp-3";
        let (key, nonce, nonce_store) = happy_setup(vm_id);
        // REPORT_DATA bound to a DIFFERENT vm_id ⇒ binding mismatch.
        let wrong_rd = report_data::live_attestation(&nonce, "vm-OTHER").unwrap();
        let verifier = StubVerifier {
            report: mk_report([0xAA; SNP_MEASUREMENT_LEN], wrong_rd),
        };
        let allowlist = AllAllowlist;
        let policy = policy();
        let state = InMemoryLiveAttestationState::default();
        let sink = NullLiveAttestationSink;
        let audit = RecordingAudit::default();
        let req = KeepaliveRequest {
            vm_id,
            node_id: &[0xBB; 32],
            raw_snp_report: &[0u8; 1184],
            kbs_nonce: &nonce,
            now_unix: 1_800_000_000,
            epoch: 7,
            expiry_unix: 1_800_000_900,
        };
        let deps = KeepaliveDeps {
            attn: &verifier,
            offline_allowlist: &allowlist,
            launch_policy: &policy,
            kbs_nonce_store: &nonce_store,
            state: &state,
            sink: &sink,
            kbs_signing_key: &key,
            kbs_kid: b"kbs-l0",
            audit: &audit,
            chain_genesis: [0xCC; 32],
            pallet_instance: [0xDD; 32],
        };
        assert!(process_keepalive(&req, &deps).is_err());
        assert_eq!(
            state.get_chain(vm_id).unwrap(),
            LiveAttestationChain::genesis()
        );
    }

    #[test]
    fn process_keepalive_rejects_unaccepted_kbs_kid() {
        let vm_id = "vm-kp-4";
        let (key, nonce, nonce_store) = happy_setup(vm_id);
        let expected_rd = report_data::live_attestation(&nonce, vm_id).unwrap();
        let verifier = StubVerifier {
            report: mk_report([0xAA; SNP_MEASUREMENT_LEN], expected_rd),
        };
        let allowlist = DeniesKbsKid;
        let policy = policy();
        let state = InMemoryLiveAttestationState::default();
        let sink = NullLiveAttestationSink;
        let audit = RecordingAudit::default();
        let req = KeepaliveRequest {
            vm_id,
            node_id: &[0xBB; 32],
            raw_snp_report: &[0u8; 1184],
            kbs_nonce: &nonce,
            now_unix: 1_800_000_000,
            epoch: 7,
            expiry_unix: 1_800_000_900,
        };
        let deps = KeepaliveDeps {
            attn: &verifier,
            offline_allowlist: &allowlist,
            launch_policy: &policy,
            kbs_nonce_store: &nonce_store,
            state: &state,
            sink: &sink,
            kbs_signing_key: &key,
            kbs_kid: b"kbs-l0",
            audit: &audit,
            chain_genesis: [0xCC; 32],
            pallet_instance: [0xDD; 32],
        };
        assert!(matches!(
            process_keepalive(&req, &deps),
            Err(KbsError::Policy(_))
        ));
    }
}
