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
//!    live_attestation`] for `(kbs_nonce, vm_id)` — or, when the guest
//!    sent its resources, [`hippius_types::report_data::
//!    live_attestation_with_resources`] for `(kbs_nonce, vm_id,
//!    resources)`, and the signed body (schema v3) states them; when it
//!    sent its guest components, [`hippius_types::report_data::
//!    live_attestation_with_components`] for `(kbs_nonce, vm_id,
//!    components, resources?)`, and the body (schema v4) states them.
//! 5. `measurement ∈ §22 allowlist` + TCB / launch-policy bounds.
//! 6. KBS signing kid accepted for the attested measurement.
//! 7. Per-VM replay chain — match `LiveAttestationStateStore` CAS,
//!    advance to `(seq+1, sha256(body))`.
//! 8. Sign the canonical-CBOR body with the KBS L0 key.
//! 9. Spend the nonce + record off-chain best-effort + audit.

use ed25519_dalek::{Signer, SigningKey};
use hippius_types::live_attestation::{
    BindingSource, GuestBinding, GuestComponents, GuestResources, LiveAttestation,
    SignedLiveAttestation, DIGEST_LEN, LIVE_ATTESTATION_SCHEMA_VERSION,
    LIVE_ATTESTATION_SCHEMA_VERSION_BOUND, LIVE_ATTESTATION_SCHEMA_VERSION_COMPONENTS,
    LIVE_ATTESTATION_SCHEMA_VERSION_RESOURCES, MEASUREMENT_LEN, PUBKEY_LEN,
};
use hippius_types::report_data;
use sha2::{Digest, Sha256};

use crate::error::{KbsError, Result};
use crate::keepalive_binding::{self, BindingMode, KeepaliveBindingStore};
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
    /// The vCPU / RAM figures the guest says it read, or `None` for a
    /// guest that predates them. When present they are part of the
    /// expected `REPORT_DATA`, so only the values the guest folded into
    /// its PSP-signed report pass; the body then carries them (v3).
    pub resources: Option<&'a GuestResources>,
    /// The guest components release and health the guest says it read,
    /// or `None` for a guest that does not attest them. When present the
    /// expected `REPORT_DATA` is the components layout (with the resources
    /// inside it when both are sent) and the body is v4.
    pub components: Option<&'a GuestComponents>,
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
    /// The release-time guest bindings (`crate::keepalive_binding`).
    pub bindings: &'a dyn KeepaliveBindingStore,
    /// `Off` ⇒ legacy v1 bodies, no binding check. `Record` / `Enforce`
    /// ⇒ the keepalive must come from the guest released for `vm_id`,
    /// and the v2 body states that guest.
    pub binding_mode: BindingMode,
    /// `enforce`'s post-restart grace window close time
    /// (`keepalive_binding::EnforceGrace`); `None` ⇒ strict.
    pub grace_closes_at_unix: Option<u64>,
    /// The lifecycle store, for the VM's current launch
    /// (`lifecycle::LaunchBinding`): a guest of a superseded launch gets
    /// no live attestation either.
    pub vm_states: &'a dyn crate::lifecycle::VmStateStore,
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
    // With resources, the map also binds them under their own domain:
    // the relay can neither change a value nor strip them (a stripped
    // request expects the resource-less bytes the report does not hold).
    // With components, a third layout under its own domain binds them
    // (and the resources, when sent): stripping either changes the bytes.
    let expected_rd = match (req.components, req.resources) {
        (Some(c), r) => {
            report_data::live_attestation_with_components(req.kbs_nonce, req.vm_id, c, r)?
        }
        (None, Some(r)) => {
            report_data::live_attestation_with_resources(req.kbs_nonce, req.vm_id, r)?
        }
        (None, None) => report_data::live_attestation(req.kbs_nonce, req.vm_id)?,
    };

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

    // 5a. The keepalive must come from the guest the KBS RELEASED for
    // this vm_id (`crate::keepalive_binding`): REPORT_DATA names a vm_id
    // but the guest chooses REPORT_DATA, so without this any running
    // allowlisted guest could attest for any other VM. Read off the SAME
    // raw bytes `attn.verify` just verified.
    let guest = match deps.binding_mode {
        BindingMode::Off => None,
        mode => {
            let b = keepalive_binding::check_keepalive(
                deps.bindings,
                mode,
                req.vm_id,
                req.raw_snp_report,
                keepalive_binding::EnforceGrace {
                    closes_at_unix: deps.grace_closes_at_unix,
                    now_unix: req.now_unix,
                },
            )?;
            Some(GuestBinding {
                chip_id: b.guest.chip_id,
                report_id: b.guest.report_id,
                source: b.source,
            })
        }
    };

    // 5b. A guest of a launch the VM's current one replaced (the pre-
    // resize size, booted with the pre-resize ticket) is not this VM's
    // guest any more: no live attestation, so its uptime earns nothing.
    // No ticket here, so no "newer launch takes over" — only a release
    // moves the binding.
    //
    // Evaluated AFTER the binding (5a): the guest chooses the vm_id in
    // REPORT_DATA, so before it any allowlisted guest could claim another
    // VM and have a genuine `superseded-launch` refusal logged against it.
    // The reason names where the guest's identity came from: only
    // `superseded-launch` (a release-recorded binding matched) says THIS
    // VM's guest of an earlier launch still runs; `-unbound` (binding off
    // or first-use) proves nothing about the VM.
    if let Some(current) = deps.vm_states.launch_binding(req.vm_id)? {
        if current.measurement != report.measurement {
            let verified = matches!(
                guest,
                Some(GuestBinding {
                    source: BindingSource::Release,
                    ..
                })
            );
            return Err(KbsError::Lifecycle(if verified {
                "superseded-launch: the attested measurement is not the VM's current launch".into()
            } else {
                "superseded-launch-unbound: the attested measurement is not the VM's current \
                 launch (guest identity not verified)"
                    .into()
            }));
        }
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
    // A v4 body's `observed_at_unix` is when its nonce was ISSUED: the
    // guest checks its components after it received the nonce, so the
    // health it states is no older than that — a request the relay held
    // back cannot pass for a later one (vali's soak reads it). Unknown
    // issuance ⇒ no v4 body. Earlier versions keep `now - 1`.
    let observed_at_unix = if req.components.is_some() {
        let issued = deps
            .kbs_nonce_store
            .issued_at_unix(req.kbs_nonce)?
            .ok_or_else(|| KbsError::Vault("nonce issuance time unknown".into()))?;
        issued.clamp(1, req.now_unix)
    } else {
        req.now_unix.saturating_sub(1)
    };
    let schema_version = match (req.components, req.resources, &guest) {
        (Some(_), _, _) => LIVE_ATTESTATION_SCHEMA_VERSION_COMPONENTS,
        (None, Some(_), _) => LIVE_ATTESTATION_SCHEMA_VERSION_RESOURCES,
        (None, None, Some(_)) => LIVE_ATTESTATION_SCHEMA_VERSION_BOUND,
        (None, None, None) => LIVE_ATTESTATION_SCHEMA_VERSION,
    };
    let body = LiveAttestation {
        schema_version,
        chain_genesis: deps.chain_genesis,
        pallet_instance: deps.pallet_instance,
        vm_id: req.vm_id.to_string(),
        node_id: *req.node_id,
        attestation_seq: chain.next_seq,
        epoch: req.epoch,
        observed_at_unix,
        verified_at_unix: req.now_unix,
        snp_report_digest,
        vcek_chain_digest,
        measurement,
        prev_attestation_hash: chain.prev_attestation_hash,
        expiry_unix: req.expiry_unix,
        signer_pubkey,
        guest,
        resources: req.resources.copied(),
        components: req.components.copied(),
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

    /// A lifecycle store with nothing recorded — keepalive tests that are
    /// not about the current-launch binding.
    struct NoStates;
    impl crate::lifecycle::VmStateStore for NoStates {
        fn get(&self, vm_id: &str) -> Result<crate::lifecycle::VmState> {
            Err(KbsError::Lifecycle(format!("no state for vm_id={vm_id}")))
        }
        fn key_mode(&self, _vm_id: &str) -> Result<hippius_types::guardian::KeyMode> {
            Ok(hippius_types::guardian::KeyMode::Hippius)
        }
    }
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
    /// When the mock store says its nonces were issued.
    const NONCE_ISSUED_AT: u64 = 1_799_999_900;

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
        fn issued_at_unix(&self, n: &[u8; 32]) -> Result<Option<u64>> {
            let issued = self.issued.lock().map_err(|_| KbsError::Replay)?;
            Ok(issued.contains(n).then_some(NONCE_ISSUED_AT))
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

    /// One keepalive for `vm_id` presenting `raw` under `mode`, against
    /// `bindings`. The verifier is stubbed to accept; the binding is the
    /// only thing that can refuse.
    fn keepalive_as(
        vm_id: &str,
        raw: &[u8],
        mode: BindingMode,
        bindings: &dyn KeepaliveBindingStore,
    ) -> Result<LiveAttestation> {
        keepalive_with_states(vm_id, raw, mode, bindings, &NoStates)
    }

    /// [`keepalive_as`] against a chosen lifecycle store (the VM's current
    /// launch). The stub guest attests measurement `[0xAA; 48]`.
    fn keepalive_with_states(
        vm_id: &str,
        raw: &[u8],
        mode: BindingMode,
        bindings: &dyn KeepaliveBindingStore,
        vm_states: &dyn crate::lifecycle::VmStateStore,
    ) -> Result<LiveAttestation> {
        let (key, nonce, nonce_store) = happy_setup(vm_id);
        let verifier = StubVerifier {
            report: mk_report(
                [0xAA; SNP_MEASUREMENT_LEN],
                report_data::live_attestation(&nonce, vm_id).unwrap(),
            ),
        };
        let state = InMemoryLiveAttestationState::default();
        let sink = NullLiveAttestationSink;
        let audit = RecordingAudit::default();
        let policy = policy();
        let req = KeepaliveRequest {
            vm_id,
            node_id: &[0xBB; 32],
            raw_snp_report: raw,
            kbs_nonce: &nonce,
            now_unix: 1_800_000_000,
            epoch: 7,
            expiry_unix: 1_800_000_900,
            resources: None,
            components: None,
        };
        let deps = KeepaliveDeps {
            attn: &verifier,
            offline_allowlist: &AllAllowlist,
            launch_policy: &policy,
            kbs_nonce_store: &nonce_store,
            state: &state,
            sink: &sink,
            kbs_signing_key: &key,
            kbs_kid: b"kbs-l0",
            audit: &audit,
            chain_genesis: [0xCC; 32],
            pallet_instance: [0xDD; 32],
            bindings,
            binding_mode: mode,
            grace_closes_at_unix: None,
            vm_states,
        };
        let signed = process_keepalive(&req, &deps)?;
        Ok(LiveAttestation::decode(&signed.body).unwrap())
    }

    /// One keepalive whose PSP-signed report binds `in_report` (the
    /// resources the guest folded into `REPORT_DATA`, or none) while the
    /// request — as the host relayed it — carries `in_request`.
    fn keepalive_with_resources(
        in_report: Option<GuestResources>,
        in_request: Option<GuestResources>,
        mode: BindingMode,
    ) -> Result<LiveAttestation> {
        keepalive_with((in_report, None), (in_request, None), mode)
    }

    /// One keepalive whose report binds `(resources, components)` as
    /// `in_report` while the relayed request carries `in_request`.
    fn keepalive_with(
        in_report: (Option<GuestResources>, Option<GuestComponents>),
        in_request: (Option<GuestResources>, Option<GuestComponents>),
        mode: BindingMode,
    ) -> Result<LiveAttestation> {
        use crate::keepalive_binding::tests::raw_report;
        let vm_id = "vm-res";
        let raw = raw_report(0x11, 0x22);
        let bindings = crate::keepalive_binding::InMemoryKeepaliveBindings::default();
        crate::keepalive_binding::record_release(&bindings, vm_id, (1, 1), &raw).unwrap();
        let (key, nonce, nonce_store) = happy_setup(vm_id);
        let rd = match &in_report {
            (r, Some(c)) => {
                report_data::live_attestation_with_components(&nonce, vm_id, c, r.as_ref()).unwrap()
            }
            (Some(r), None) => {
                report_data::live_attestation_with_resources(&nonce, vm_id, r).unwrap()
            }
            (None, None) => report_data::live_attestation(&nonce, vm_id).unwrap(),
        };
        let verifier = StubVerifier {
            report: mk_report([0xAA; SNP_MEASUREMENT_LEN], rd),
        };
        let state = InMemoryLiveAttestationState::default();
        let audit = RecordingAudit::default();
        let policy = policy();
        let req = KeepaliveRequest {
            vm_id,
            node_id: &[0xBB; 32],
            raw_snp_report: &raw,
            kbs_nonce: &nonce,
            now_unix: 1_800_000_000,
            epoch: 7,
            expiry_unix: 1_800_000_900,
            resources: in_request.0.as_ref(),
            components: in_request.1.as_ref(),
        };
        let deps = KeepaliveDeps {
            attn: &verifier,
            offline_allowlist: &AllAllowlist,
            launch_policy: &policy,
            kbs_nonce_store: &nonce_store,
            state: &state,
            sink: &NullLiveAttestationSink,
            kbs_signing_key: &key,
            kbs_kid: b"kbs-l0",
            audit: &audit,
            chain_genesis: [0xCC; 32],
            pallet_instance: [0xDD; 32],
            bindings: &bindings,
            binding_mode: mode,
            grace_closes_at_unix: None,
            vm_states: &NoStates,
        };
        let signed = process_keepalive(&req, &deps)?;
        Ok(LiveAttestation::decode(&signed.body).unwrap())
    }

    const LARGE: GuestResources = GuestResources {
        vcpus_online: 4,
        mem_firmware_kib: 16_776_164,
        mem_total_kib: 15_337_812,
        mem_unaccepted_kib: 0,
    };

    #[test]
    fn attested_resources_are_signed_into_a_v3_body() {
        for mode in [BindingMode::Off, BindingMode::Record, BindingMode::Enforce] {
            let body = keepalive_with_resources(Some(LARGE), Some(LARGE), mode).unwrap();
            assert_eq!(
                body.schema_version,
                LIVE_ATTESTATION_SCHEMA_VERSION_RESOURCES
            );
            assert_eq!(body.resources, Some(LARGE));
            assert_eq!(body.guest.is_some(), mode != BindingMode::Off, "{mode:?}");
        }
    }

    #[test]
    fn the_relay_cannot_change_or_strip_the_resources() {
        // The host shrank the VM and rewrites the figures in transit.
        let inflated = GuestResources {
            mem_firmware_kib: LARGE.mem_firmware_kib * 2,
            ..LARGE
        };
        assert!(
            keepalive_with_resources(Some(LARGE), Some(inflated), BindingMode::Enforce).is_err()
        );
        let more_cpus = GuestResources {
            vcpus_online: 8,
            ..LARGE
        };
        assert!(
            keepalive_with_resources(Some(LARGE), Some(more_cpus), BindingMode::Enforce).is_err()
        );
        // It drops them so the body says nothing: the report still binds them.
        assert!(keepalive_with_resources(Some(LARGE), None, BindingMode::Enforce).is_err());
        // It invents them for a guest that sent none.
        assert!(keepalive_with_resources(None, Some(LARGE), BindingMode::Enforce).is_err());
        // A legacy guest is unchanged: no resources, a v2 body.
        let legacy = keepalive_with_resources(None, None, BindingMode::Enforce).unwrap();
        assert_eq!(legacy.schema_version, LIVE_ATTESTATION_SCHEMA_VERSION_BOUND);
        assert!(legacy.resources.is_none());
    }

    const HEALTHY: GuestComponents = GuestComponents {
        release_version: 2,
        security_epoch: 1,
        health: hippius_types::live_attestation::components_health::ALL,
        instance: 0x1234_5678,
        unhealthy_ticks: 0,
    };

    #[test]
    fn attested_components_are_signed_into_a_v4_body() {
        for mode in [BindingMode::Off, BindingMode::Record, BindingMode::Enforce] {
            for resources in [None, Some(LARGE)] {
                let body =
                    keepalive_with((resources, Some(HEALTHY)), (resources, Some(HEALTHY)), mode)
                        .unwrap();
                assert_eq!(
                    body.schema_version,
                    LIVE_ATTESTATION_SCHEMA_VERSION_COMPONENTS
                );
                assert_eq!(
                    (body.components, body.resources),
                    (Some(HEALTHY), resources)
                );
                // Observed at the nonce's issuance, not at the request's
                // arrival (`now_unix` = 1_800_000_000).
                assert_eq!(body.observed_at_unix, NONCE_ISSUED_AT);
                assert_eq!(body.guest.is_some(), mode != BindingMode::Off, "{mode:?}");
            }
        }
    }

    #[test]
    fn the_relay_cannot_change_strip_or_invent_the_components() {
        let mode = BindingMode::Enforce;
        let failing = GuestComponents {
            health: 0,
            ..HEALTHY
        };
        // A failing guest's health rewritten to pass in transit.
        assert!(keepalive_with((None, Some(failing)), (None, Some(HEALTHY)), mode).is_err());
        // A failure count rewritten to hide failed ticks.
        let latched = GuestComponents {
            unhealthy_ticks: 3,
            ..HEALTHY
        };
        assert!(keepalive_with((None, Some(latched)), (None, Some(HEALTHY)), mode).is_err());
        // Another release claimed.
        let other = GuestComponents {
            release_version: 3,
            ..HEALTHY
        };
        assert!(keepalive_with((None, Some(HEALTHY)), (None, Some(other)), mode).is_err());
        // Stripped (the body would say nothing): the report still binds them.
        assert!(keepalive_with((None, Some(HEALTHY)), (None, None), mode).is_err());
        // Invented for a guest that sent none.
        assert!(keepalive_with((None, None), (None, Some(HEALTHY)), mode).is_err());
        // The resources stripped from a components report, or added to one.
        assert!(keepalive_with((Some(LARGE), Some(HEALTHY)), (None, Some(HEALTHY)), mode).is_err());
        assert!(keepalive_with((None, Some(HEALTHY)), (Some(LARGE), Some(HEALTHY)), mode).is_err());
        // A resources-only report replayed as a components request.
        assert!(keepalive_with((Some(LARGE), None), (Some(LARGE), Some(HEALTHY)), mode).is_err());
    }

    /// The VM was relaunched (resized): a guest of the earlier launch —
    /// the pre-resize size booted with the pre-resize ticket — gets no
    /// live attestation, so its uptime earns nothing. The current launch
    /// still does.
    #[test]
    fn a_guest_of_a_superseded_launch_gets_no_live_attestation() {
        struct Bound([u8; 48]);
        impl crate::lifecycle::VmStateStore for Bound {
            fn get(&self, vm_id: &str) -> Result<crate::lifecycle::VmState> {
                Err(KbsError::Lifecycle(format!("no state for vm_id={vm_id}")))
            }
            fn key_mode(&self, _vm_id: &str) -> Result<hippius_types::guardian::KeyMode> {
                Ok(hippius_types::guardian::KeyMode::Hippius)
            }
            fn launch_binding(
                &self,
                _vm_id: &str,
            ) -> Result<Option<crate::lifecycle::LaunchBinding>> {
                Ok(Some(crate::lifecycle::LaunchBinding {
                    measurement: self.0,
                    issue_time: 1,
                }))
            }
        }
        let bindings = crate::keepalive_binding::InMemoryKeepaliveBindings::default();
        let err = keepalive_with_states(
            "vm-r",
            &[0u8; 1184],
            BindingMode::Off,
            &bindings,
            &Bound([0xEE; 48]),
        )
        .unwrap_err()
        .to_string();
        // Binding off: nothing says this is the VM's guest.
        assert!(err.contains("superseded-launch-unbound"), "{err}");
        keepalive_with_states(
            "vm-r",
            &[0u8; 1184],
            BindingMode::Off,
            &bindings,
            &Bound([0xAA; 48]),
        )
        .expect("the current launch's guest still attests");
    }

    /// The superseded check runs AFTER the binding: a foreign guest that
    /// claims a VM is refused as a foreign guest, never as that VM's
    /// superseded guest; only the VM's released guest earns the plain
    /// `superseded-launch` reason (what a T4 detector may trust).
    #[test]
    fn superseded_launch_is_only_said_of_the_vms_own_released_guest() {
        use crate::keepalive_binding::tests::raw_report;
        struct Bound;
        impl crate::lifecycle::VmStateStore for Bound {
            fn get(&self, vm_id: &str) -> Result<crate::lifecycle::VmState> {
                Err(KbsError::Lifecycle(format!("no state for vm_id={vm_id}")))
            }
            fn key_mode(&self, _vm_id: &str) -> Result<hippius_types::guardian::KeyMode> {
                Ok(hippius_types::guardian::KeyMode::Hippius)
            }
            fn launch_binding(
                &self,
                _vm_id: &str,
            ) -> Result<Option<crate::lifecycle::LaunchBinding>> {
                // The current launch measures 0xEE; the guests below 0xAA.
                Ok(Some(crate::lifecycle::LaunchBinding {
                    measurement: [0xEE; 48],
                    issue_time: 1,
                }))
            }
        }
        let bindings = crate::keepalive_binding::InMemoryKeepaliveBindings::default();
        crate::keepalive_binding::record_release(
            &bindings,
            "vm-r",
            (1, 1),
            &raw_report(0x11, 0x22),
        )
        .unwrap();
        for mode in [BindingMode::Record, BindingMode::Enforce] {
            let own =
                keepalive_with_states("vm-r", &raw_report(0x11, 0x22), mode, &bindings, &Bound)
                    .unwrap_err()
                    .to_string();
            assert!(own.contains("superseded-launch:"), "{mode:?}: {own}");
            let foreign =
                keepalive_with_states("vm-r", &raw_report(0x11, 0x33), mode, &bindings, &Bound)
                    .unwrap_err()
                    .to_string();
            assert!(
                !foreign.contains("superseded-launch"),
                "{mode:?}: {foreign}"
            );
        }
        // Record mode, no release on record: first-use, unverified.
        let empty = crate::keepalive_binding::InMemoryKeepaliveBindings::default();
        let unbound = keepalive_with_states(
            "vm-r",
            &raw_report(0x11, 0x22),
            BindingMode::Record,
            &empty,
            &Bound,
        )
        .unwrap_err()
        .to_string();
        assert!(unbound.contains("superseded-launch-unbound"), "{unbound}");
    }

    #[test]
    fn one_guest_cannot_mint_a_live_attestation_for_another_vm() {
        // THE attack: vm-victim's guest (report 0x22) and the attacker's
        // guest (report 0x33) run on the SAME chip with the SAME image.
        // The attacker asks for a nonce and signs REPORT_DATA for
        // vm-victim — which it chooses freely.
        use crate::keepalive_binding::tests::raw_report;
        let bindings = crate::keepalive_binding::InMemoryKeepaliveBindings::default();
        crate::keepalive_binding::record_release(
            &bindings,
            "vm-victim",
            (1, 1),
            &raw_report(0x11, 0x22),
        )
        .unwrap();
        for mode in [BindingMode::Record, BindingMode::Enforce] {
            let forged = keepalive_as("vm-victim", &raw_report(0x11, 0x33), mode, &bindings);
            assert!(forged.is_err(), "{mode:?}: a foreign guest was accepted");
            let genuine =
                keepalive_as("vm-victim", &raw_report(0x11, 0x22), mode, &bindings).unwrap();
            assert_eq!(
                genuine.schema_version,
                LIVE_ATTESTATION_SCHEMA_VERSION_BOUND
            );
            let g = genuine.guest.unwrap();
            assert_eq!(g.report_id, [0x22; 32]);
            assert_eq!(g.chip_id, [0x11; 64]);
            assert_eq!(
                g.source,
                hippius_types::live_attestation::BindingSource::Release
            );
        }
    }

    #[test]
    fn off_mode_is_the_legacy_v1_body() {
        let bindings = crate::keepalive_binding::InMemoryKeepaliveBindings::default();
        let body = keepalive_as("vm-a", &[0u8; 1184], BindingMode::Off, &bindings).unwrap();
        assert_eq!(body.schema_version, LIVE_ATTESTATION_SCHEMA_VERSION);
        assert!(body.guest.is_none());
    }

    #[test]
    fn an_unreleased_vm_is_refused_in_enforce_and_first_use_in_record() {
        use crate::keepalive_binding::tests::raw_report;
        let bindings = crate::keepalive_binding::InMemoryKeepaliveBindings::default();
        assert!(
            keepalive_as("vm-new", &raw_report(1, 2), BindingMode::Enforce, &bindings).is_err()
        );
        let first =
            keepalive_as("vm-new", &raw_report(1, 2), BindingMode::Record, &bindings).unwrap();
        assert_eq!(
            first.guest.unwrap().source,
            hippius_types::live_attestation::BindingSource::FirstUse
        );
        assert_eq!(first.guest.unwrap().report_id, [2; 32]);
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
        let bindings = crate::keepalive_binding::InMemoryKeepaliveBindings::default();
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
            resources: None,
            components: None,
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
            bindings: &bindings,
            binding_mode: BindingMode::Off,
            grace_closes_at_unix: None,
            vm_states: &NoStates,
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
        let bindings = crate::keepalive_binding::InMemoryKeepaliveBindings::default();
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
            resources: None,
            components: None,
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
            bindings: &bindings,
            binding_mode: BindingMode::Off,
            grace_closes_at_unix: None,
            vm_states: &NoStates,
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
            resources: None,
            components: None,
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
        let bindings = crate::keepalive_binding::InMemoryKeepaliveBindings::default();
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
            resources: None,
            components: None,
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
            bindings: &bindings,
            binding_mode: BindingMode::Off,
            grace_closes_at_unix: None,
            vm_states: &NoStates,
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
        let bindings = crate::keepalive_binding::InMemoryKeepaliveBindings::default();
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
            resources: None,
            components: None,
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
            bindings: &bindings,
            binding_mode: BindingMode::Off,
            grace_closes_at_unix: None,
            vm_states: &NoStates,
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
        let bindings = crate::keepalive_binding::InMemoryKeepaliveBindings::default();
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
            resources: None,
            components: None,
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
            bindings: &bindings,
            binding_mode: BindingMode::Off,
            grace_closes_at_unix: None,
            vm_states: &NoStates,
        };
        assert!(matches!(
            process_keepalive(&req, &deps),
            Err(KbsError::Policy(_))
        ));
    }
}
