//! End-to-end release transaction (ARCHITECTURE.md §7/§21).
//!
//! Order (any failure ⇒ signed denial + audit, no commit, no secret emit):
//! - verify OrderTicket: sig, canonical CBOR+header, schema, expiry (§6).
//! - verify SNP report (trait): measurement/TCB/policy/REPORT_DATA (§7).
//! - attested CHIP_ID == ticket.platform_id (§8/§23).
//! - KBS signing kid in accepted_kbs_kids(measurement) (§6).
//! - lifecycle check_releasable (attested node) BEFORE Vault read (§24).
//! - atomic reserve (ticket_id, KBS_nonce) (§7).
//! - attestation-bound Vault capability (challenge→redeem); exact reads (§8/§19).
//! - recompute allowed_userdata_digest (streamed, zeroizing) + ct-cmp (§20).
//! - lifecycle check_releasable AGAIN before commit (§24).
//! - HPKE-wrap each secret bound to full context; sign response (§20).
//! - durably COMMIT release-once before returning; rollback ONLY on a pre-commit error, never after a commit attempt (§7).
//! - plaintext is Zeroizing → wiped on scope exit.

use crate::crypto::{
    hpke_wrap, sign_denial, sign_response, KbsResponse, ReleaseContext, SignedDenial,
    SignedResponse, HPKE_SUITE_ID, RELEASE_DOMAIN,
};
use crate::error::{KbsError, Result};
use crate::evidence::EvidenceSink;
use crate::lifecycle::{check_releasable, VmStateStore};
use crate::persist::KbsNonceStore;
use crate::replay::{ReleaseKey, ReleaseStore};
use crate::report_data::{ct_eq, tenant};
use crate::snp::{
    check_attestation, AttestationVerifier, LaunchPolicy, MeasurementAllowlist, VerifiedReport,
};
use crate::ticket::{verify_order_ticket, L1Keyring, OrderTicket};
use crate::vault::{AttestedVaultAuth, KbsAuthEvidence, VaultKv, VaultScope};
use ed25519_dalek::{Signer, SigningKey};
use hippius_types::evidence_bundle::{
    EvidenceBundle, SignedEvidenceBundle, EVIDENCE_BUNDLE_SCHEMA_VERSION,
};
use zeroize::Zeroizing;

// The pinned `allowed_userdata_digest` preimage is canonical in
// `hippius_types::digest` so L1 and the KBS compute it byte-identically.
use hippius_types::digest::userdata_digest;

/// §7: the KV version the per-VM lifecycle SIGNING key is read at. vali
/// stages it as the FIRST write to a fresh per-VM path, so it is always
/// version 1. Pinned (not "latest") per §19 exact `path@version`.
const LIFECYCLE_KEY_VERSION: u64 = 1;

/// The last path segment vali writes the LUKS KEK under (mirrors
/// `vali ... launch.py`'s `f"{prefix}/{vm}/luks-kek"`).
const LUKS_KEK_SEGMENT: &str = "luks-kek";
/// The last path segment vali writes the lifecycle SIGNING key under.
const LIFECYCLE_KEY_SEGMENT: &str = "lifecycle-key";

/// §7: derive the per-VM lifecycle SIGNING-key Vault path from the
/// ticket's LUKS-KEK path by swapping the final `luks-kek` segment for
/// `lifecycle-key`. Returns `None` when the luks path does not end in
/// the expected `…/luks-kek` segment — a non-standard layout the KBS
/// can't safely derive from, so it proceeds with no lifecycle key
/// (fail-closed: no key released, never a wrong-path read).
///
/// This keeps the OrderTicket schema fixed (§6 `deny_unknown_fields`):
/// the lifecycle path is a deterministic function of the already-signed
/// luks path, so no new signed field is needed and a hostile miner
/// cannot point the KBS at another VM's key (the luks path is itself
/// ticket-bound + measurement-gated).
fn derive_lifecycle_path(luks_path: &str) -> Option<String> {
    let suffix = format!("/{LUKS_KEK_SEGMENT}");
    luks_path
        .strip_suffix(&suffix)
        .map(|prefix| format!("{prefix}/{LIFECYCLE_KEY_SEGMENT}"))
}

/// Audit hook (§15/§21): every decision is recorded.
pub trait AuditSink {
    fn record(&self, granted: bool, ticket_id: Option<&str>, vm_id: Option<&str>, reason: &str);
}

pub struct ReleaseRequest<'a> {
    pub cose_ticket: &'a [u8],
    pub raw_snp_report: &'a [u8],
    pub kbs_nonce: &'a [u8; 32],
    pub now_unix: u64,
    /// Phase 1 of audit follow-up Codex #2 (LUKS + dm-integrity is not
    /// anti-rollback). The guest's reported value of "the boot counter
    /// I expect this release to advance to". On first boot, `Some(1)`.
    /// On subsequent boots, the guest reads the previous KBS-issued
    /// value from durable storage (specifics TBD by Phase 2) and
    /// submits `prev + 1`.
    ///
    /// `None` is accepted today for backward compat with guests that
    /// pre-date this field. When `None`, the release path SKIPS the
    /// counter check + advance — operators see no anti-rollback gate.
    /// When `Some(n)`, the release path calls
    /// `boot_counter_store.check_and_advance(vm_id, n)` BEFORE the
    /// Vault read; a mismatch fails-closed with `KbsError::Policy`
    /// (no KEK released, no auditable "released" record). A miner
    /// that rolls the qcow2 back to an earlier state submits an old
    /// counter and is refused. Guests that adopt the field should
    /// never submit `None` again — the operator runbook flips a
    /// guard once Phase 2 lands.
    pub submitted_boot_counter: Option<u64>,
}

pub struct Deps<'a> {
    pub l1_keyring: &'a dyn L1Keyring,
    pub attn: &'a dyn AttestationVerifier,
    pub offline_allowlist: &'a dyn MeasurementAllowlist,
    pub launch_policy: &'a LaunchPolicy,
    pub vm_states: &'a dyn VmStateStore,
    pub release_store: &'a dyn ReleaseStore,
    /// Durable KBS-nonce single-use store (§7). `verify_unspent` is
    /// called BEFORE Vault work; `spend` is called atomically as part
    /// of the at-most-once commit step.
    pub kbs_nonce_store: &'a dyn KbsNonceStore,
    pub vault_auth: &'a dyn AttestedVaultAuth,
    pub vault_kv: &'a dyn VaultKv,
    /// The KBS's OWN verified attestation, used to obtain the Vault
    /// capability (§8 — no static AppRole).
    pub kbs_attestation: &'a crate::snp::VerifiedReport,
    /// KBS channel/TLS-exporter pubkey bound into the Vault evidence (§8).
    pub kbs_auth_pubkey: &'a [u8],
    pub kbs_signing_key: &'a SigningKey,
    pub kbs_kid: &'a [u8],
    pub audit: &'a dyn AuditSink,
    /// §280 evidence archive — best-effort per-release persistence of
    /// the cryptographic raw materials a tenant verifier needs to
    /// re-check the SEV-SNP chain of custody offline. A `Null`
    /// implementation is provided in `crate::evidence` for ops that
    /// have evidence persistence disabled (KBS config
    /// `evidence.enabled = false`); a `Mock` is provided for tests.
    pub evidence: &'a dyn EvidenceSink,
    /// Phase 1 of audit follow-up Codex #2 — per-`vm_id` monotonic
    /// counter that the release path advances when
    /// `ReleaseRequest::submitted_boot_counter` is `Some`. The trait
    /// plus a file-backed prod impl plus an in-memory mock all live
    /// in [`crate::boot_counter`].
    pub boot_counter: &'a dyn crate::boot_counter::BootCounterStore,
    /// Per-`vm_id` CONFIRMED volume stamp — the anti-rollback reference
    /// for the guest-keyed overlay. The release path calls
    /// [`crate::volume_stamp::VolumeStampStore::note_release`] (mints
    /// the token that authorises the next advance, and durably counts
    /// this as one more release since the last confirm); it never calls
    /// `confirm` itself. The CONFIRMED stamp is advanced exclusively by
    /// [`crate::volume_stamp::confirm`], i.e. by a guest that has
    /// already written the stamp. Advancing it here instead would
    /// reintroduce the accumulating-gap brick this store exists to avoid
    /// — see the module docs.
    ///
    /// `note_release`'s returned unconfirmed-release count is also the
    /// input to the suppressed-confirm gate: once it exceeds
    /// [`Self::max_unconfirmed_releases`] (when that bound is armed),
    /// `run` refuses the release outright (see the call site and the
    /// module docs' "Suppressed-confirm detection" section) — a miner
    /// that relays the release but drops every confirm cannot suppress
    /// the release itself, so this is the signal the KBS uses to notice.
    pub volume_stamp: &'a dyn crate::volume_stamp::VolumeStampStore,
    /// The RESOLVED suppressed-confirm bound gate 5c enforces.
    /// `Some(bound)` ⇒ ARMED: a release is refused once `note_release`
    /// reports more than `bound` releases since the last confirm.
    /// `None` ⇒ DISABLED: gate 5c never refuses, no matter how many
    /// unconfirmed releases accumulate.
    ///
    /// This is a DEPLOYMENT-SAFETY knob, not a tuning one. The gate is
    /// unconditional per `vm_id` and a legacy guest — any initramfs
    /// predating the `/v1/kbs/volume-stamp/confirm` route — can NEVER
    /// confirm, so arming it (`Some(_)`) before EVERY golden image in
    /// the fleet has been re-baked to send confirms would brick each
    /// legacy VM after `bound` releases (boots, §25 migrations, and
    /// reboot-recovery relaunches all count). The operator-facing
    /// resolution — config absent ⇒ the compiled
    /// [`crate::volume_stamp::MAX_UNCONFIRMED_RELEASES`] default
    /// (ARMED, the secure state, mirroring `admin.require_mtls`'s
    /// fail-closed default); an explicit `0` ⇒ `None` (DISABLED, the
    /// value the chart MUST carry until the fleet is ready) — lives in
    /// `binaries/kbs-server` (`config.rs` / `wiring.rs`), one layer
    /// above this `Option<u64>`; `kbs-core` only ever sees the already-
    /// resolved bound and never encodes "off" as a magic numeric value
    /// itself.
    pub max_unconfirmed_releases: Option<u64>,
    /// KEK-HSM RA-08a/F2 — when `true`, the release path REFUSES a KEK that
    /// is not Vault-Transit-wrapped (no `vault:` prefix). This is the
    /// fail-closed TCB gate for the "KEK ciphertext at rest" invariant: a
    /// compromised online component with `create/update` on a `luks-kek`
    /// path can no longer stage a chosen PLAINTEXT KEK and have the KBS
    /// release it verbatim (the 2-component downgrade). Ships DEFAULT-OFF
    /// (`false`) for a zero-behavior-change rollout, then flipped ON via KBS
    /// config once every staging path wraps (baker #781 + vali #778/#780 +
    /// stage-script #782) and no legacy plaintext KEK is in use.
    pub require_wrapped_kek: bool,
}

#[allow(clippy::too_many_arguments)]
fn ctx<'a>(
    t: &'a OrderTicket,
    kbs_nonce: &'a [u8; 32],
    measurement: &'a [u8; 48],
    kbs_kid: &'a [u8],
    secret_type: &'a str,
    secret_path: &'a str,
    secret_version: u64,
    allowed_userdata_digest: &'a [u8; 32],
) -> ReleaseContext<'a> {
    ReleaseContext {
        v: t.v,
        ticket_id: &t.ticket_id,
        tenant_id: &t.tenant_id,
        vm_id: &t.vm_id,
        vm_generation: t.vm_generation,
        kbs_nonce,
        measurement,
        kbs_kid,
        secret_type,
        secret_path,
        secret_version,
        allowed_userdata_digest,
    }
}

/// §7/§21 release. Success ⇒ KBS-signed response; ANY failure ⇒ KBS-signed
/// denial. Both paths are audited.
pub fn process_release(
    req: &ReleaseRequest,
    deps: &Deps,
) -> core::result::Result<SignedResponse, SignedDenial> {
    // We capture ids for audit/denial even on early failure.
    let mut tid: Option<String> = None;
    let mut vid: Option<String> = None;
    let r = run(req, deps, &mut tid, &mut vid);
    match r {
        Ok(signed) => {
            deps.audit
                .record(true, tid.as_deref(), vid.as_deref(), "released");
            Ok(signed)
        }
        Err(e) => {
            let reason = e.to_string();
            deps.audit
                .record(false, tid.as_deref(), vid.as_deref(), &reason);
            // Best-effort signed denial; if even signing fails, surface an
            // unsigned denial (caller still treats as deny).
            let d = sign_denial(
                deps.kbs_signing_key,
                tid.as_deref(),
                vid.as_deref(),
                &reason,
            )
            .unwrap_or(SignedDenial {
                body: reason.into_bytes(),
                sig: Vec::new(),
            });
            Err(d)
        }
    }
}

fn run(
    req: &ReleaseRequest,
    deps: &Deps,
    tid: &mut Option<String>,
    vid: &mut Option<String>,
) -> Result<SignedResponse> {
    // 0. §22 pre-release allowlist revalidation (the artifact backing
    // every measurement/L1-kid/KBS-kid decision MUST be re-verified
    // before each release; fail-closed).
    deps.offline_allowlist.pre_release_validate()?;

    // 1. ticket
    let (ticket, ticket_kid) = verify_order_ticket(req.cose_ticket, deps.l1_keyring, req.now_unix)?;
    *tid = Some(ticket.ticket_id.clone());
    *vid = Some(ticket.vm_id.clone());

    // 2. attestation
    let report = deps.attn.verify(req.raw_snp_report)?;
    if !ct_eq(&report.report_data[0..32], req.kbs_nonce) {
        return Err(KbsError::Attestation(
            "KBS nonce not bound in REPORT_DATA".into(),
        ));
    }
    let mut guest_pub = [0u8; 32];
    guest_pub.copy_from_slice(&report.report_data[32..64]);
    let expected_rd = tenant(req.kbs_nonce, &guest_pub);
    let ticket_allowed: Vec<Vec<u8>> = ticket
        .allowed_measurements
        .iter()
        .map(|b| b.as_ref().to_vec())
        .collect();
    check_attestation(
        &report,
        &ticket_allowed,
        deps.offline_allowlist,
        &expected_rd,
        deps.launch_policy,
    )?;

    // 3. attested CHIP_ID must equal the ticket placement (§8/§23).
    //
    // Generation-aware length: Turin (Zen5) reports an 8-byte HWID
    // zero-padded into the 64-byte `chip_id` field; Milan/Genoa fill all
    // 64. The ticket's `platform_id` was registered from the SAME
    // generation's `hippius-miner-agent platform-id` (8 hex bytes for
    // Turin, 64 for Genoa — `sev` `Firmware::get_identifier()`), so
    // compare `chip_id` truncated to the ticket's byte-length. The
    // leading bytes ARE the genuine hardware id the VCEK is bound to
    // (the KDS VCEK URL itself uses `chip_id[..8]` for Turin —
    // `attest.rs::kds_vcek_url`); the trailing zeros carry no identity.
    // Genoa is unchanged (64 == 64). Fail closed on a malformed ticket.
    let id_len = ticket.platform_id.len() / 2; // hex chars → bytes
    if id_len == 0 || id_len > report.chip_id.len() {
        return Err(KbsError::Attestation(
            "attested platform_id != ticket placement".into(),
        ));
    }
    let attested_node = hex::encode(&report.chip_id[..id_len]);
    if attested_node != ticket.platform_id {
        return Err(KbsError::Attestation(
            "attested platform_id != ticket placement".into(),
        ));
    }

    // 4a. The ticket-signing L1 kid must be accepted for the attested
    // measurement (§6/§22 — closes a key-trust bypass where the L1
    // keyring could resolve a kid not allowlisted for this measurement).
    if !deps
        .offline_allowlist
        .accepts_l1_kid(&report.measurement, &ticket_kid)
    {
        return Err(KbsError::Policy(
            "L1 ticket kid not accepted for attested measurement".into(),
        ));
    }
    // 4b. KBS signing kid must be accepted for the attested measurement (§6)
    if !deps
        .offline_allowlist
        .accepts_kbs_kid(&report.measurement, deps.kbs_kid)
    {
        return Err(KbsError::Policy(
            "KBS kid not accepted for attested measurement".into(),
        ));
    }

    // 4c. KBS-nonce freshness (§7): the nonce in REPORT_DATA must be
    // one we durably issued, not yet spent, and within its TTL. Without
    // this, an attacker could supply any 32 bytes — REPORT_DATA binding
    // alone only proves an attested guest signed *over* those bytes,
    // not that the KBS minted them.
    deps.kbs_nonce_store
        .verify_unspent(req.kbs_nonce, req.now_unix)?;

    // 5. lifecycle BEFORE Vault read — bound to the ATTESTED node
    let state = deps.vm_states.get(&ticket.vm_id)?;
    check_releasable(
        &state,
        ticket.vm_generation,
        &ticket.lease_id,
        &attested_node,
    )?;

    // 5b. boot-counter CAS (audit follow-up Codex #2 — anti-rollback
    // for valid-old-ciphertext replay). When the guest submits a
    // counter, it MUST be exactly `stored + 1` (see
    // `boot_counter::BootCounterStore::check_and_advance`). On
    // mismatch we fail-closed BEFORE the Vault read so no KEK ever
    // crosses the wire for a rolled-back boot.
    //
    // The field is optional so a genuinely-fresh vm_id (never committed
    // a counter — e.g. a pre-Phase-2A guest) can still release. But once
    // a vm_id has EVER durably committed a counter, a request that OMITS
    // the counter is a rollback-via-omission (audit H8): a miner replays
    // an old disk snapshot and strips `submitted_boot_counter` to dodge
    // the `stored + 1` CAS. So `None` is refused, fail-closed before any
    // Vault read, whenever the store already holds a counter for this
    // vm_id. This guard is self-arming (no operator flag): it can only
    // fire after a prior successful `Some` commit, so it never affects a
    // guest that has never submitted.
    //
    // Phase 2A also echoes the committed counter back in the
    // `KbsResponse.boot_counter` field so the guest can persist
    // it post-unlock for the next boot's comparison.
    // Two-phase: CHECK now (fail-closed before the Vault read), COMMIT
    // only after the release durably succeeds (gate 11c below). A
    // single-step advance here would persist the counter even when a
    // later gate (Vault/broker/nonce) denies the release — leaving the
    // KBS one ahead of the guest's on-disk counter forever, since the
    // guest only advances on a 200. `committed_boot_counter` is the
    // value we WILL commit on success + echo back to the guest.
    let committed_boot_counter = match req.submitted_boot_counter {
        Some(submitted) => match deps.boot_counter.check_only(&ticket.vm_id, submitted) {
            Ok(v) => v,
            Err(refusal) => {
                // OPERATOR-ARMED ONE-SHOT RESYNC (`boot_counter::
                // arm_resync`). The guest's copy of the counter lives on
                // a 1 MiB plaintext ext4 on the MINER host; losing that
                // file makes the guest submit `1` forever against a
                // `stored = N` KBS, and `seed` cannot repair it (it
                // refuses a live row, and the counter may never be
                // walked down). Without this branch that is a permanent
                // brick — an unreplicated file on the untrusted party's
                // host is then a data-destruction primitive.
                //
                // Consulted ONLY after the strict CAS has already
                // refused, so an unarmed VM's path through this gate is
                // byte-identical to before.
                //
                // What is admitted: exactly one release, and it commits
                // `stored + 1` — NOT the submitted value. So the
                // counter still only moves up by one, exactly as a
                // normal boot moves it, and the number the miner
                // submitted buys it nothing. The guest re-learns the
                // truth from `KbsResponse.boot_counter`, which it
                // persists to its fresh state disk.
                //
                // What this does NOT relax: the volume-stamp gate below
                // (the one that actually binds anti-rollback to the
                // ENCRYPTED VOLUME) is untouched, and the arm can only
                // be set through the mTLS admin listener — never by the
                // miner, whose transport this request arrived on.
                if !deps.boot_counter.resync_armed(&ticket.vm_id)? {
                    return Err(refusal);
                }
                // Closed-vocabulary note on stderr (§20 — the refusal
                // text carries no secret, only the counter arithmetic
                // the operator already sees in the audit sink). The
                // ARMING is durably attributable in the hash-chained
                // admin log; this line is what ties a specific release
                // to it. Same stderr discipline as the "no lifecycle
                // key staged" note below.
                {
                    use std::io::Write;
                    let mut err = std::io::stderr().lock();
                    let _ = writeln!(
                        err,
                        "kbs-core::release: boot-counter-resync-consumed: an operator-armed \
                         one-shot resync admitted a release that the strict CAS refused \
                         ({refusal}); committing stored+1 and disarming"
                    );
                }
                let stored = deps.boot_counter.get(&ticket.vm_id)?;
                stored
                    .checked_add(1)
                    .ok_or_else(|| KbsError::Policy("boot-counter overflow".into()))?
            }
        },
        None => {
            let stored = deps.boot_counter.get(&ticket.vm_id)?;
            if stored > 0 {
                return Err(KbsError::Policy(format!(
                    "boot-counter: vm_id={} has a committed counter (stored={stored}) but \
                     this release omitted submitted_boot_counter — rollback-via-omission \
                     refused",
                    ticket.vm_id
                )));
            }
            0
        }
    };

    // 5c. SUPPRESSED-CONFIRM gate (`crate::volume_stamp`).
    //
    // The volume-stamp expectation only advances when the guest CONFIRMS,
    // and the miner controls the transport that confirm travels over. So
    // a miner that simply drops every confirm pins the expectation at 0
    // forever — and `0` is exactly the value the guest reads as "no
    // expectation on record", which makes it ADOPT whatever stamp it
    // finds. Dropping confirms would therefore disable the rollback gate
    // completely and silently, which is the bypass this gate closes.
    //
    // The miner cannot suppress the RELEASE — it needs the release to get
    // a KEK at all — so the release is the signal the KBS can count
    // without depending on the miner delivering anything.
    //
    // `note_release` durably increments the per-VM unconfirmed-release
    // counter and returns `(confirmed, unconfirmed)` read in the SAME
    // locked step, so the bound check below cannot race a concurrent
    // confirm or admin reset. This call ALWAYS happens, armed or not —
    // the counter must keep counting even while the gate is disabled, or
    // arming it later would start from a false "0" for every VM that was
    // already accumulating suppressed confirms. When `deps.
    // max_unconfirmed_releases` is `Some(bound)` and the count EXCEEDS
    // it, the release is refused here — BEFORE the Vault capability,
    // before any secret is read, and before the reservation — as a
    // DISTINCT, audited policy denial an operator can tell apart from an
    // attestation failure. `None` means DISABLED: see
    // `Deps::max_unconfirmed_releases` for why this has to be an
    // operator-armed knob rather than unconditional — a legacy guest
    // that can never confirm would otherwise be bricked by the very
    // first deploy of this gate.
    //
    // Placement: with the other pre-commit policy gates, immediately
    // after the boot-counter CAS. That ordering matters — a miner
    // replaying a stale counter is rejected by 5b and never reaches this
    // increment, so it cannot burn a VM's budget with rolled-back
    // submissions.
    //
    // DEADLOCK NOTE: a refused release means no boot, and no boot means
    // no confirm, so recovery can NEVER depend on the guest. The only
    // other way to clear the count is `admin_reset_unconfirmed`, an
    // authenticated ADMIN action on the mTLS admin listener, unreachable
    // from the guest-facing release/confirm routes. A miner can always
    // deny service; what it can no longer do is deny service AND keep
    // silent rollback.
    let (expected_volume_stamp, unconfirmed_releases) =
        deps.volume_stamp.note_release(&ticket.vm_id)?;
    // The denial carries a STABLE leading classifier so an operator (and
    // the audit sink, which records `KbsError::to_string()` verbatim for
    // every refusal — see `process_release`) can tell this apart from an
    // attestation or allowlist failure at a glance.
    if let Some(bound) = deps.max_unconfirmed_releases {
        if unconfirmed_releases > bound {
            return Err(KbsError::Policy(format!(
                "volume-stamp-confirm-suppressed: vm_id={} has {unconfirmed_releases} releases \
                 since the last confirm (max {bound}) — confirms are being suppressed, so the \
                 anti-rollback expectation cannot be trusted; refusing the release. An operator \
                 must clear this with the admin-only reset-unconfirmed route after establishing \
                 why the guest's confirms are not arriving.",
                ticket.vm_id,
            )));
        }
    }

    // 6. atomic reserve keyed by (ticket_id, KBS nonce in REPORT_DATA)
    let rkey = ReleaseKey {
        ticket_id: ticket.ticket_id.clone(),
        nonce: req.kbs_nonce.to_vec(),
    };
    deps.release_store.reserve(&rkey)?;

    // Pre-commit work; on ANY error here we rollback the reservation
    // (no secret emitted). Commit happens AFTER this, and is never
    // rolled back.
    let pre = (|| -> Result<SignedResponse> {
        // 7. attestation-bound Vault capability + exact reads
        //
        // §7: the per-VM lifecycle SIGNING-key path is DERIVED from the
        // ticket's luks path (the ticket schema is fixed + `deny_unknown
        // _fields`, so no new signed field is added). vali stages the
        // private key at `<vm-prefix>/lifecycle-key` alongside
        // `<vm-prefix>/luks-kek`, and the derivation just swaps the last
        // segment. The lifecycle key is always vali's FIRST write to that
        // fresh per-VM path ⇒ version 1 (§19 exact `path@version`). When
        // vali did NOT stage one (older VMs), the read below 404s and the
        // release proceeds with KEK+userdata only — fail-closed-but-not-
        // crash (no lifecycle key released, the guest signs nothing).
        let lifecycle_path = derive_lifecycle_path(&ticket.luks_vault_ref.path);
        let scope = VaultScope {
            vm_id: ticket.vm_id.clone(),
            luks_path: ticket.luks_vault_ref.path.clone(),
            luks_version: ticket.luks_vault_ref.version,
            userdata_path: ticket.userdata_vault_ref.path.clone(),
            userdata_version: ticket.userdata_vault_ref.version,
            lifecycle_path: lifecycle_path.clone(),
            lifecycle_version: lifecycle_path.as_ref().map(|_| LIFECYCLE_KEY_VERSION),
        };
        let challenge = deps.vault_auth.issue_challenge(&scope, req.now_unix)?;
        let ev = KbsAuthEvidence {
            verified: deps.kbs_attestation,
            challenge: &challenge,
            scope: &scope,
            auth_pubkey: deps.kbs_auth_pubkey,
        };
        let cap = deps.vault_auth.redeem(&ev, req.now_unix)?;
        let mut luks: Zeroizing<Vec<u8>> =
            deps.vault_kv
                .read_exact(&cap, &scope.luks_path, scope.luks_version)?;
        // Phase 2 (KEK-HSM): the KEK at rest is Vault-Transit CIPHERTEXT
        // (`vault:v1:…`), never plaintext — vali stores the wrapped form,
        // so a vali/broker/node compromise gets only ciphertext. Decrypt
        // it transiently HERE, inside the attested KBS CVM (the ONLY place
        // a plaintext KEK exists), before HPKE-wrapping to the guest. A
        // legacy plaintext KEK (no `vault:` prefix) passes through
        // unchanged — backward-compat during the staged rollout.
        //
        // RA-08a/F2 — fail-closed enforcement of "KEK ciphertext at rest":
        // once `require_wrapped_kek` is on, a non-`vault:` KEK is REFUSED, so
        // a compromised writer cannot stage a chosen plaintext KEK and have
        // the KBS release it verbatim (the 2-component downgrade). Off by
        // default; flipped on after every staging path wraps.
        if deps.require_wrapped_kek && !luks.starts_with(b"vault:") {
            return Err(KbsError::Policy(
                "require_wrapped_kek: refusing a non-Transit-wrapped (plaintext) KEK at rest"
                    .into(),
            ));
        }
        if luks.starts_with(b"vault:") {
            // Per-VM Transit key (`kek-<vm_id>`): the cap token's decrypt
            // grant is scoped to THIS VM's key, so it can never be a
            // general decryption oracle for another tenant's ciphertext.
            let transit_key = format!("kek-{}", ticket.vm_id);
            luks = deps.vault_kv.transit_decrypt(&cap, &transit_key, &luks)?;
        }
        let userdata: Zeroizing<Vec<u8>> =
            deps.vault_kv
                .read_exact(&cap, &scope.userdata_path, scope.userdata_version)?;

        // §7: read the lifecycle SIGNING key — OPTIONAL. A missing path
        // (older VM, or a Vault 404) yields `None`; the release then
        // omits the `lifecycle_key` field and the guest gets no key.
        // ANY other Vault error (auth, transport, malformed) is NOT
        // swallowed — only a not-found is treated as "no lifecycle key".
        let lifecycle: Option<Zeroizing<Vec<u8>>> =
            match (scope.lifecycle_path.as_deref(), scope.lifecycle_version) {
                (Some(path), Some(version)) => {
                    match deps.vault_kv.read_exact(&cap, path, version) {
                        Ok(seed) => Some(seed),
                        Err(KbsError::Vault(_)) => {
                            // Not-found / absent ⇒ pre-§7 VM. Log the class only
                            // (§20 — never the path-as-secret-context) and proceed.
                            use std::io::Write;
                            let mut err = std::io::stderr().lock();
                            let _ = writeln!(
                                err,
                                "kbs-core::release: no lifecycle key staged for this VM — \
                         proceeding KEK+userdata only (pre-§7 VM)"
                            );
                            None
                        }
                        Err(e) => return Err(e),
                    }
                }
                _ => None,
            };

        // 8. recompute user-data digest (streamed, zeroizing) + ct-compare
        let recomputed = userdata_digest(
            &ticket.tenant_id,
            &ticket.vm_id,
            &ticket.ticket_id,
            "userdata",
            &scope.userdata_path,
            scope.userdata_version,
            &userdata,
        );
        if !ct_eq(&recomputed, ticket.allowed_userdata_digest()) {
            return Err(KbsError::DigestMismatch);
        }

        // 9. lifecycle AGAIN before commit
        let state2 = deps.vm_states.get(&ticket.vm_id)?;
        check_releasable(
            &state2,
            ticket.vm_generation,
            &ticket.lease_id,
            &attested_node,
        )?;

        // 10. wrap each secret bound to its full context; sign response.
        // `verify_order_ticket` already enforced 32-byte length, so the
        // `try_into` is a re-statement of the invariant for the type
        // system; the `map_err` is for completeness.
        let allowed_ud_digest_arr: &[u8; 32] =
            ticket.allowed_userdata_digest().try_into().map_err(|_| {
                KbsError::Ticket("allowed_userdata_digest length invariant violated".into())
            })?;
        let luks_ctx = ctx(
            &ticket,
            req.kbs_nonce,
            &report.measurement,
            deps.kbs_kid,
            "luks",
            &scope.luks_path,
            scope.luks_version,
            allowed_ud_digest_arr,
        );
        let ud_ctx = ctx(
            &ticket,
            req.kbs_nonce,
            &report.measurement,
            deps.kbs_kid,
            "userdata",
            &scope.userdata_path,
            scope.userdata_version,
            allowed_ud_digest_arr,
        );
        let wrapped_luks = hpke_wrap(&guest_pub, &luks, &luks_ctx)?;
        let wrapped_userdata = hpke_wrap(&guest_pub, &userdata, &ud_ctx)?;

        // §7: HPKE-wrap the lifecycle SIGNING key — same per-secret
        // context binding as luks/userdata (vm/ticket/measurement/nonce
        // /kid + the secret_type/path/version), so a swapped or
        // cross-VM lifecycle blob fails the guest's AEAD open. The
        // miner never sees plaintext — it's sealed to the attested
        // guest's X25519 pubkey only. `None` ⇒ field omitted (pre-§7).
        let wrapped_lifecycle = match (lifecycle.as_ref(), scope.lifecycle_path.as_deref()) {
            (Some(seed), Some(lc_path)) => {
                let lc_ctx = ctx(
                    &ticket,
                    req.kbs_nonce,
                    &report.measurement,
                    deps.kbs_kid,
                    "lifecycle",
                    lc_path,
                    LIFECYCLE_KEY_VERSION,
                    allowed_ud_digest_arr,
                );
                Some(hpke_wrap(&guest_pub, seed, &lc_ctx)?)
            }
            _ => None,
        };
        // Anti-rollback for the guest-keyed overlay: echo the last
        // CONFIRMED volume stamp and mint the single-use token that
        // authorises advancing it to `expected + 1`. NOTHING is advanced
        // here — only the guest's later confirm moves the CONFIRMED
        // stamp, which is precisely what stops the expectation from
        // running ahead of a volume that was never stamped.
        //
        // `expected_volume_stamp` was read at gate 5c, in the SAME locked
        // step that incremented the suppressed-confirm counter, so it
        // cannot have raced a concurrent confirm or admin reset since.
        // The suppression BOUND is enforced there too — with the other
        // pre-commit policy gates, before the reservation and before any
        // Vault read — not here, where the Vault secrets have already
        // been fetched.
        let stamp_target = expected_volume_stamp
            .checked_add(1)
            .ok_or_else(|| KbsError::Policy("volume-stamp overflow".into()))?;
        let stamp_mac_key = crate::volume_stamp::stamp_mac_key(&deps.kbs_signing_key.to_bytes());
        let stamp_token =
            crate::volume_stamp::stamp_token(&stamp_mac_key, &ticket.vm_id, stamp_target);
        let stamp_ctx = ctx(
            &ticket,
            req.kbs_nonce,
            &report.measurement,
            deps.kbs_kid,
            "volume-stamp-token",
            "kbs/volume-stamp",
            stamp_target,
            allowed_ud_digest_arr,
        );
        let wrapped_stamp_token = Some(hpke_wrap(&guest_pub, &stamp_token, &stamp_ctx)?);

        let resp = KbsResponse {
            domain: RELEASE_DOMAIN.into(),
            v: ticket.v,
            ticket_id: ticket.ticket_id.clone(),
            tenant_id: ticket.tenant_id.clone(),
            vm_id: ticket.vm_id.clone(),
            vm_generation: ticket.vm_generation,
            kbs_nonce: req.kbs_nonce.to_vec(),
            measurement: report.measurement.to_vec(),
            kbs_kid: deps.kbs_kid.to_vec(),
            hpke_suite_id: HPKE_SUITE_ID,
            allowed_userdata_digest: ticket.allowed_userdata_digest().to_vec(),
            luks: wrapped_luks,
            userdata: wrapped_userdata,
            lifecycle_key: wrapped_lifecycle,
            // Echo the committed boot counter so the guest can
            // persist it for next boot's CAS submission.
            boot_counter: committed_boot_counter,
            expected_volume_stamp,
            volume_stamp_token: wrapped_stamp_token,
        };
        sign_response(deps.kbs_signing_key, &resp)
    })();

    match pre {
        Err(e) => {
            deps.release_store.rollback(&rkey);
            Err(e)
        }
        Ok(signed) => {
            // 11a. Durable spend of the KBS nonce FIRST. If it fails
            // (already spent in a race / TTL elapsed), rollback the
            // reservation and deny — no secret has been emitted yet.
            if let Err(e) = deps.kbs_nonce_store.spend(req.kbs_nonce, req.now_unix) {
                deps.release_store.rollback(&rkey);
                return Err(e);
            }
            // 11b. Durable release-once commit. A commit error here is
            // terminal (fail closed) — NEVER rolled back (the nonce is
            // already spent and the release may be durably spent too).
            deps.release_store.commit(&rkey)?;

            // 11c. Boot-counter commit — ONLY now, after the release is
            // durably committed. The guest will advance its on-disk
            // counter on receiving this 200, so the KBS persists the
            // matching advance here in lockstep. A pre-commit denial
            // (Vault/broker/nonce above) never reaches this line, so
            // the counter never runs ahead of the guest (the bug the
            // two-phase split closes). A commit error is terminal +
            // fail-closed, like the release commit above.
            if req.submitted_boot_counter.is_some() {
                deps.boot_counter
                    .commit(&ticket.vm_id, committed_boot_counter)?;
            }

            // 12. §280 evidence archive — best-effort. Failures here
            // are internally logged by the sink (`crate::evidence`)
            // and do NOT propagate: the durable release just
            // committed above is what the tenant sees, the audit
            // record below is what KBS commits durably for §15, and
            // the evidence bundle is an additive forensic artifact
            // (issue #280 Phase 1). The §22 epoch + manifest digest
            // are read once here (O(1) field access on
            // `InstalledAllowlist`) — they ARE re-read fresh rather
            // than captured earlier in `run` so a manifest swap
            // between `pre_release_validate` and now would be visible
            // in the bundle (which is the truth-of-the-moment a
            // verifier wants).
            record_evidence_bundle(deps, req, &ticket, &report);

            Ok(signed)
        }
    }
}

/// Best-effort §280 evidence-bundle build + sign + record. Called once
/// per granted release, after the durable commit, before returning the
/// signed response to the caller. Bundle build failures are logged via
/// stderr (matching the `crate::audit::FileAuditSink::append` error
/// convention) and dropped — the release returns Ok regardless.
fn record_evidence_bundle(
    deps: &Deps,
    req: &ReleaseRequest,
    ticket: &OrderTicket,
    report: &VerifiedReport,
) {
    let bundle = EvidenceBundle {
        schema_version: EVIDENCE_BUNDLE_SCHEMA_VERSION,
        vm_id: ticket.vm_id.clone(),
        tenant_id: ticket.tenant_id.clone(),
        ticket_id: ticket.ticket_id.clone(),
        granted_at_unix: req.now_unix,
        measurement: report.measurement,
        allowlist_epoch: deps.offline_allowlist.current_epoch(),
        allowlist_manifest_digest: deps.offline_allowlist.current_manifest_digest(),
        snp_report_bytes: req.raw_snp_report.to_vec(),
        vcek_chain_pem: report.chain_pem.clone(),
        ticket_cose_bytes: req.cose_ticket.to_vec(),
        kbs_signer_pubkey: deps.kbs_signing_key.verifying_key().to_bytes(),
    };
    let body = match bundle.canonical() {
        Ok(b) => b,
        Err(e) => {
            // Same stderr discipline as `audit.rs:511`. The error is
            // closed-vocabulary text from `EvidenceBundle::validate`
            // / `to_canonical_vec` — never bundle CONTENT.
            use std::io::Write;
            let mut err = std::io::stderr().lock();
            let _ = writeln!(err, "kbs-core::release: evidence canonical encode: {e}");
            return;
        }
    };
    let sig = deps.kbs_signing_key.sign(&body).to_bytes().to_vec();
    let signed = SignedEvidenceBundle { body, sig };
    deps.evidence.record(&signed);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::boot_counter::BootCounterStore;
    use crate::cbor::to_canonical_vec;
    use crate::crypto::{verify_response, ReleaseContext};
    use crate::lifecycle::VmState;
    use crate::replay::InMemoryReleaseStore;
    use crate::snp::{VerifiedReport, MEASUREMENT_LEN};
    use crate::ticket::SCHEMA_V;
    use crate::vault::ChallengeVaultAuth;
    use crate::vault::VaultCapability;
    use crate::volume_stamp::VolumeStampStore;
    use ciborium::value::Value;
    use coset::CborSerializable;
    use ed25519_dalek::{Signer, SigningKey};
    use std::collections::HashMap;
    use std::sync::Mutex;

    const MEAS: [u8; 48] = [7u8; 48];

    struct Kr(Vec<u8>, ed25519_dalek::VerifyingKey);
    impl L1Keyring for Kr {
        fn verifying_key(&self, kid: &[u8]) -> Option<ed25519_dalek::VerifyingKey> {
            (kid == self.0).then_some(self.1)
        }
    }
    struct AllowAll;
    impl MeasurementAllowlist for AllowAll {
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
    struct OneState(VmState);
    impl VmStateStore for OneState {
        fn get(&self, _vm: &str) -> Result<VmState> {
            Ok(self.0.clone())
        }
    }
    struct Kv(HashMap<String, Vec<u8>>);
    impl VaultKv for Kv {
        fn read_exact(
            &self,
            _c: &VaultCapability,
            path: &str,
            _v: u64,
        ) -> Result<Zeroizing<Vec<u8>>> {
            self.0
                .get(path)
                .cloned()
                .map(Zeroizing::new)
                .ok_or_else(|| KbsError::Vault("path not found".into()))
        }
    }
    struct Av {
        rd: [u8; 64],
        chip: [u8; 64],
    }
    impl AttestationVerifier for Av {
        fn verify(&self, _r: &[u8]) -> Result<VerifiedReport> {
            Ok(VerifiedReport {
                measurement: MEAS,
                report_data: self.rd,
                tcb: 10,
                policy: 0b10,
                chip_id: self.chip,
                // A non-empty placeholder chain so the §280 evidence
                // bundle's `vcek_chain_pem must be non-empty` gate
                // passes. The production verifier
                // (`crate::snp_real::SevChainVerifier`) populates with
                // a real VCEK→ASK→ARK PEM; this mock returns a
                // syntactically-shaped placeholder so the bundle
                // encode succeeds in tests.
                chain_pem: b"-----BEGIN CERTIFICATE-----\nTEST\n-----END CERTIFICATE-----\n"
                    .to_vec(),
            })
        }
    }
    #[derive(Default)]
    struct Audit(Mutex<Vec<(bool, String)>>);
    impl AuditSink for Audit {
        fn record(&self, g: bool, _t: Option<&str>, _v: Option<&str>, reason: &str) {
            if let Ok(mut x) = self.0.lock() {
                x.push((g, reason.to_string()));
            }
        }
    }
    impl Audit {
        /// The reason string of the most recent record. `process_release`
        /// audits every denial with `KbsError::to_string()` verbatim, so
        /// this is how a test reads a denial's classifier (the SIGNED
        /// denial deliberately does not carry it).
        fn last_reason(&self) -> String {
            self.0
                .lock()
                .ok()
                .and_then(|x| x.last().map(|(_, r)| r.clone()))
                .unwrap_or_default()
        }
    }
    /// In-memory `KbsNonceStore` for tests. Pre-issue a known set; spend
    /// transitions it to the spent set; verify_unspent denies stale or
    /// unknown nonces.
    #[derive(Default)]
    struct MockNonceStore {
        issued: Mutex<std::collections::HashSet<[u8; 32]>>,
        spent: Mutex<std::collections::HashSet<[u8; 32]>>,
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

    fn cose_for(plat: &str, gen: u64, ud: &[u8]) -> (Vec<u8>, SigningKey, Vec<u8>) {
        cose_for_luks(plat, gen, ud, "kbs/vm/abc/luks")
    }

    fn cose_for_luks(
        plat: &str,
        gen: u64,
        ud: &[u8],
        luks_path: &str,
    ) -> (Vec<u8>, SigningKey, Vec<u8>) {
        let sk = SigningKey::from_bytes(&[42u8; 32]);
        let kid = b"l1".to_vec();
        let digest =
            userdata_digest("t", "abc", "tk-1", "userdata", "kbs/vm/abc/ud", 2, ud).to_vec();
        let v = Value::Map(vec![
            (
                Value::Text("allowed_measurements".into()),
                Value::Array(vec![Value::Bytes(MEAS.to_vec())]),
            ),
            (
                Value::Text("allowed_userdata_digest".into()),
                Value::Bytes(digest),
            ),
            (Value::Text("expiry".into()), Value::Integer(999.into())),
            (Value::Text("issue_time".into()), Value::Integer(100.into())),
            (
                Value::Text("lease_id".into()),
                Value::Text("lease-1".into()),
            ),
            (Value::Text("lifecycle_perms".into()), Value::Array(vec![])),
            (
                Value::Text("luks_vault_ref".into()),
                Value::Map(vec![
                    (Value::Text("path".into()), Value::Text(luks_path.into())),
                    (Value::Text("version".into()), Value::Integer(3.into())),
                ]),
            ),
            (Value::Text("node_id".into()), Value::Text(plat.into())),
            (Value::Text("nonce".into()), Value::Bytes(vec![1u8; 32])),
            (Value::Text("platform_id".into()), Value::Text(plat.into())),
            (Value::Text("flavor".into()), Value::Text("small".into())),
            (Value::Text("tenant_id".into()), Value::Text("t".into())),
            (Value::Text("ticket_id".into()), Value::Text("tk-1".into())),
            (Value::Text("user_id".into()), Value::Text("u".into())),
            (
                Value::Text("userdata_vault_ref".into()),
                Value::Map(vec![
                    (
                        Value::Text("path".into()),
                        Value::Text("kbs/vm/abc/ud".into()),
                    ),
                    (Value::Text("version".into()), Value::Integer(2.into())),
                ]),
            ),
            (Value::Text("v".into()), Value::Integer(2.into())),
            (
                Value::Text("vm_generation".into()),
                Value::Integer(gen.into()),
            ),
            (Value::Text("vm_id".into()), Value::Text("abc".into())),
        ]);
        let payload = to_canonical_vec(&v).unwrap();
        let protected = coset::HeaderBuilder::new()
            .algorithm(coset::iana::Algorithm::EdDSA)
            .key_id(kid.clone())
            .build();
        let cose = coset::CoseSign1Builder::new()
            .protected(protected)
            .payload(payload)
            .create_signature(b"", |t| sk.sign(t).to_bytes().to_vec())
            .build()
            .to_vec()
            .unwrap();
        (cose, sk, kid)
    }

    #[test]
    fn end_to_end_release_then_replay_denied() {
        let (pk, sec) = crate::crypto::test_support::gen_x25519();
        let nonce = [1u8; 32];
        let mut rd = [0u8; 64];
        rd[0..32].copy_from_slice(&nonce);
        rd[32..64].copy_from_slice(&pk);
        let chip = [0u8; 64];
        let plat = hex::encode(chip);
        let ud = b"USERDATA-with-netbird-key";
        let (cose, l1, kid) = cose_for(&plat, 5, ud);

        let kr = Kr(kid, l1.verifying_key());
        let av = Av { rd, chip };
        let al = AllowAll;
        let lp = LaunchPolicy {
            min_tcb: 1,
            required_bits: 0b10,
            allowed_mask: 0b1101,
        };
        let st = OneState(VmState::Active {
            gen: 5,
            host: plat.clone(),
            lease_id: "lease-1".into(),
        });
        let rs = InMemoryReleaseStore::default();
        let ok: fn(&[u8; 48]) -> bool = |_m| true;
        let va = ChallengeVaultAuth {
            kbs_measurement_ok: ok,
            policy: LaunchPolicy {
                min_tcb: 1,
                required_bits: 0,
                allowed_mask: u64::MAX,
            },
            challenge_ttl: 60,
            cap_ttl: 60,
            challenge_nonce: [2u8; 32],
        };
        let mut kvm = HashMap::new();
        kvm.insert("kbs/vm/abc/luks".to_string(), b"LUKSKEY".to_vec());
        kvm.insert("kbs/vm/abc/ud".to_string(), ud.to_vec());
        let kv = Kv(kvm);
        let kbs_rep = VerifiedReport {
            measurement: MEAS,
            report_data: [0u8; 64],
            tcb: 5,
            policy: 0,
            chip_id: [0u8; 64],
            chain_pem: Vec::new(),
        };
        let kbs_sk = SigningKey::from_bytes(&[9u8; 32]);
        let audit = Audit::default();
        let evidence = crate::evidence::MockEvidenceSink::new();
        let nonce_store = MockNonceStore::default();
        nonce_store.preissue(nonce);
        let boot_counter = crate::boot_counter::InMemoryBootCounterStore::default();
        let volume_stamp = crate::volume_stamp::InMemoryVolumeStampStore::default();
        let deps = Deps {
            l1_keyring: &kr,
            attn: &av,
            offline_allowlist: &al,
            launch_policy: &lp,
            vm_states: &st,
            release_store: &rs,
            vault_auth: &va,
            vault_kv: &kv,
            kbs_nonce_store: &nonce_store,
            kbs_attestation: &kbs_rep,
            kbs_auth_pubkey: b"kbs-channel-pub",
            kbs_signing_key: &kbs_sk,
            kbs_kid: b"kbs-kid",
            audit: &audit,
            evidence: &evidence,
            boot_counter: &boot_counter,
            volume_stamp: &volume_stamp,
            max_unconfirmed_releases: Some(crate::volume_stamp::MAX_UNCONFIRMED_RELEASES),
            require_wrapped_kek: false,
        };
        // `raw_snp_report` is 1184 B (the SEV-SNP report size) so the
        // §280 evidence bundle's `MIN_SNP_REPORT_LEN` gate is satisfied.
        // The Mock `AttestationVerifier` (`Av`) does not parse this
        // input — its `verify` returns a fixed `VerifiedReport` — so
        // the byte values are irrelevant for this test, only the
        // length matters.
        let raw_snp_report = vec![0u8; 1184];
        let req = ReleaseRequest {
            cose_ticket: &cose,
            raw_snp_report: &raw_snp_report,
            kbs_nonce: &nonce,
            now_unix: 200,
            submitted_boot_counter: None,
        };
        // RA-08a/F2: the same setup stages a PLAINTEXT KEK ("LUKSKEY", no
        // `vault:` prefix). Assert enforcement FIRST — while the nonce is
        // still UNSPENT — so the `require_wrapped_kek` guard is the ONLY gate
        // that can fail (the guard returns Err → rollback, no nonce spend).
        // Running this AFTER the flag-off release below would spend the nonce
        // and trip the replay guard instead, masking the gate under test.
        let deps_enforce = Deps {
            require_wrapped_kek: true,
            ..deps
        };
        assert!(
            process_release(&req, &deps_enforce).is_err(),
            "require_wrapped_kek must refuse a non-vault: (plaintext) KEK"
        );
        // Flag off (default): the same plaintext KEK still releases — proving
        // default behavior is unchanged.
        let signed = process_release(&req, &deps).expect("release ok");
        let resp = verify_response(&kbs_sk.verifying_key(), &signed).unwrap();
        assert_eq!(resp.vm_id, "abc");

        // §280 evidence: a granted release MUST have triggered exactly
        // one bundle write to the sink. The bundle decodes cleanly and
        // its fields match the ticket / report this test set up.
        assert_eq!(
            evidence.len(),
            1,
            "granted release must record exactly one evidence bundle"
        );
        let snap = evidence.snapshot();
        let signed_bundle = &snap[0];
        let body = EvidenceBundle::decode(&signed_bundle.body).unwrap();
        assert_eq!(body.vm_id, "abc");
        assert_eq!(body.tenant_id, "t");
        assert_eq!(body.ticket_id, "tk-1");
        assert_eq!(body.measurement, MEAS);
        assert_eq!(body.snp_report_bytes, req.raw_snp_report);
        assert_eq!(body.ticket_cose_bytes, req.cose_ticket);
        assert_eq!(body.kbs_signer_pubkey, kbs_sk.verifying_key().to_bytes());
        // The KBS L0 signature must verify under the bound pubkey.
        use ed25519_dalek::{Signature, Verifier, VerifyingKey};
        let vk = VerifyingKey::from_bytes(&body.kbs_signer_pubkey).unwrap();
        let sig = Signature::from_slice(&signed_bundle.sig).unwrap();
        vk.verify(&signed_bundle.body, &sig)
            .expect("KBS evidence sig must verify");

        // guest re-derives the luks context and unwraps
        let ud_digest = userdata_digest("t", "abc", "tk-1", "userdata", "kbs/vm/abc/ud", 2, ud);
        let lc = ReleaseContext {
            v: SCHEMA_V,
            ticket_id: "tk-1",
            tenant_id: "t",
            vm_id: "abc",
            vm_generation: 5,
            kbs_nonce: &nonce,
            measurement: &MEAS,
            kbs_kid: b"kbs-kid",
            secret_type: "luks",
            secret_path: "kbs/vm/abc/luks",
            secret_version: 3,
            allowed_userdata_digest: &ud_digest,
        };
        let pt = crate::crypto::hpke_unwrap(&sec, &resp.luks, &lc).unwrap();
        assert_eq!(pt.as_slice(), b"LUKSKEY");

        // replay: same ticket_id + KBS nonce ⇒ denied
        assert!(process_release(&req, &deps).is_err());
    }

    #[test]
    fn derive_lifecycle_path_swaps_segment() {
        // §7 derivation: `…/luks-kek` → `…/lifecycle-key`.
        assert_eq!(
            derive_lifecycle_path("hippius-compute/kbs/tenants/vm-1/luks-kek").as_deref(),
            Some("hippius-compute/kbs/tenants/vm-1/lifecycle-key")
        );
        // A path that does NOT end in `/luks-kek` ⇒ no derivation (the
        // KBS proceeds with no lifecycle key, never a wrong-path read).
        assert!(derive_lifecycle_path("kbs/vm/abc/luks").is_none());
        assert!(derive_lifecycle_path("luks-kek").is_none()); // no `/` prefix
    }

    /// §7 end-to-end: a release whose ticket uses the canonical
    /// `…/luks-kek` luks path AND has a lifecycle key staged in Vault
    /// emits a `lifecycle_key` the guest unwraps; the Ed25519 PUBLIC key
    /// of the unwrapped seed is what vali would have recorded as
    /// `Vm.lifecycle_vk`. A second release with NO lifecycle key staged
    /// (404) succeeds but omits the field (fail-closed-but-not-crash).
    #[test]
    fn release_includes_lifecycle_key_when_staged() {
        use ed25519_dalek::SigningKey as EdSigningKey;

        let (pk, sec) = crate::crypto::test_support::gen_x25519();
        let nonce = [1u8; 32];
        let mut rd = [0u8; 64];
        rd[0..32].copy_from_slice(&nonce);
        rd[32..64].copy_from_slice(&pk);
        let chip = [0u8; 64];
        let plat = hex::encode(chip);
        let ud = b"USERDATA";
        // Canonical luks path so `derive_lifecycle_path` resolves.
        let (cose, l1, kid) = cose_for_luks(&plat, 5, ud, "kbs/vm/abc/luks-kek");

        let kr = Kr(kid, l1.verifying_key());
        let av = Av { rd, chip };
        let al = AllowAll;
        let lp = LaunchPolicy {
            min_tcb: 1,
            required_bits: 0b10,
            allowed_mask: 0b1101,
        };
        let st = OneState(VmState::Active {
            gen: 5,
            host: plat.clone(),
            lease_id: "lease-1".into(),
        });
        let rs = InMemoryReleaseStore::default();
        let ok: fn(&[u8; 48]) -> bool = |_m| true;
        let va = ChallengeVaultAuth {
            kbs_measurement_ok: ok,
            policy: LaunchPolicy {
                min_tcb: 1,
                required_bits: 0,
                allowed_mask: u64::MAX,
            },
            challenge_ttl: 60,
            cap_ttl: 60,
            challenge_nonce: [2u8; 32],
        };
        // The vali-generated lifecycle seed staged at the DERIVED path.
        let lifecycle_seed: [u8; 32] = [0x5Au8; 32];
        let recorded_vk = EdSigningKey::from_bytes(&lifecycle_seed)
            .verifying_key()
            .to_bytes();
        let mut kvm = HashMap::new();
        kvm.insert("kbs/vm/abc/luks-kek".to_string(), b"LUKSKEY".to_vec());
        kvm.insert("kbs/vm/abc/ud".to_string(), ud.to_vec());
        kvm.insert(
            "kbs/vm/abc/lifecycle-key".to_string(),
            lifecycle_seed.to_vec(),
        );
        let kv = Kv(kvm);
        let kbs_rep = VerifiedReport {
            measurement: MEAS,
            report_data: [0u8; 64],
            tcb: 5,
            policy: 0,
            chip_id: [0u8; 64],
            chain_pem: Vec::new(),
        };
        let kbs_sk = SigningKey::from_bytes(&[9u8; 32]);
        let audit = Audit::default();
        let evidence = crate::evidence::MockEvidenceSink::new();
        let nonce_store = MockNonceStore::default();
        nonce_store.preissue(nonce);
        let boot_counter = crate::boot_counter::InMemoryBootCounterStore::default();
        let volume_stamp = crate::volume_stamp::InMemoryVolumeStampStore::default();
        let deps = Deps {
            l1_keyring: &kr,
            attn: &av,
            offline_allowlist: &al,
            launch_policy: &lp,
            vm_states: &st,
            release_store: &rs,
            vault_auth: &va,
            vault_kv: &kv,
            kbs_nonce_store: &nonce_store,
            kbs_attestation: &kbs_rep,
            kbs_auth_pubkey: b"kbs-channel-pub",
            kbs_signing_key: &kbs_sk,
            kbs_kid: b"kbs-kid",
            audit: &audit,
            evidence: &evidence,
            boot_counter: &boot_counter,
            volume_stamp: &volume_stamp,
            max_unconfirmed_releases: Some(crate::volume_stamp::MAX_UNCONFIRMED_RELEASES),
            require_wrapped_kek: false,
        };
        let raw_snp_report = vec![0u8; 1184];
        let req = ReleaseRequest {
            cose_ticket: &cose,
            raw_snp_report: &raw_snp_report,
            kbs_nonce: &nonce,
            now_unix: 200,
            submitted_boot_counter: None,
        };
        let signed = process_release(&req, &deps).expect("release ok");
        let resp = verify_response(&kbs_sk.verifying_key(), &signed).unwrap();

        // The response MUST carry a lifecycle key.
        let w = resp
            .lifecycle_key
            .as_ref()
            .expect("§7 release must include the lifecycle key");
        assert_eq!(w.secret_type, "lifecycle");
        assert_eq!(w.secret_path, "kbs/vm/abc/lifecycle-key");
        assert_eq!(w.secret_version, 1);

        // The guest re-derives the lifecycle context + unwraps the seed.
        let ud_digest = userdata_digest("t", "abc", "tk-1", "userdata", "kbs/vm/abc/ud", 2, ud);
        let lc = ReleaseContext {
            v: SCHEMA_V,
            ticket_id: "tk-1",
            tenant_id: "t",
            vm_id: "abc",
            vm_generation: 5,
            kbs_nonce: &nonce,
            measurement: &MEAS,
            kbs_kid: b"kbs-kid",
            secret_type: "lifecycle",
            secret_path: "kbs/vm/abc/lifecycle-key",
            secret_version: 1,
            allowed_userdata_digest: &ud_digest,
        };
        let seed = crate::crypto::hpke_unwrap(&sec, w, &lc).unwrap();
        assert_eq!(seed.as_slice(), &lifecycle_seed);
        // The pubkey of the unwrapped seed equals the vk vali recorded —
        // so a guest-signed ack verifies against `Vm.lifecycle_vk`.
        let guest_vk = EdSigningKey::from_bytes(seed.as_slice().try_into().unwrap())
            .verifying_key()
            .to_bytes();
        assert_eq!(guest_vk, recorded_vk);
    }

    /// §7 fail-closed-but-not-crash: a ticket with the canonical
    /// `…/luks-kek` path but NO lifecycle key staged in Vault (404) still
    /// releases the KEK+userdata, just omitting `lifecycle_key`.
    #[test]
    fn release_omits_lifecycle_key_when_absent() {
        let (pk, _sec) = crate::crypto::test_support::gen_x25519();
        let nonce = [1u8; 32];
        let mut rd = [0u8; 64];
        rd[0..32].copy_from_slice(&nonce);
        rd[32..64].copy_from_slice(&pk);
        let chip = [0u8; 64];
        let plat = hex::encode(chip);
        let ud = b"USERDATA";
        let (cose, l1, kid) = cose_for_luks(&plat, 5, ud, "kbs/vm/abc/luks-kek");

        let kr = Kr(kid, l1.verifying_key());
        let av = Av { rd, chip };
        let al = AllowAll;
        let lp = LaunchPolicy {
            min_tcb: 1,
            required_bits: 0b10,
            allowed_mask: 0b1101,
        };
        let st = OneState(VmState::Active {
            gen: 5,
            host: plat.clone(),
            lease_id: "lease-1".into(),
        });
        let rs = InMemoryReleaseStore::default();
        let ok: fn(&[u8; 48]) -> bool = |_m| true;
        let va = ChallengeVaultAuth {
            kbs_measurement_ok: ok,
            policy: LaunchPolicy {
                min_tcb: 1,
                required_bits: 0,
                allowed_mask: u64::MAX,
            },
            challenge_ttl: 60,
            cap_ttl: 60,
            challenge_nonce: [2u8; 32],
        };
        // NOTE: no `lifecycle-key` entry ⇒ the read 404s.
        let mut kvm = HashMap::new();
        kvm.insert("kbs/vm/abc/luks-kek".to_string(), b"LUKSKEY".to_vec());
        kvm.insert("kbs/vm/abc/ud".to_string(), ud.to_vec());
        let kv = Kv(kvm);
        let kbs_rep = VerifiedReport {
            measurement: MEAS,
            report_data: [0u8; 64],
            tcb: 5,
            policy: 0,
            chip_id: [0u8; 64],
            chain_pem: Vec::new(),
        };
        let kbs_sk = SigningKey::from_bytes(&[9u8; 32]);
        let audit = Audit::default();
        let evidence = crate::evidence::MockEvidenceSink::new();
        let nonce_store = MockNonceStore::default();
        nonce_store.preissue(nonce);
        let boot_counter = crate::boot_counter::InMemoryBootCounterStore::default();
        let volume_stamp = crate::volume_stamp::InMemoryVolumeStampStore::default();
        let deps = Deps {
            l1_keyring: &kr,
            attn: &av,
            offline_allowlist: &al,
            launch_policy: &lp,
            vm_states: &st,
            release_store: &rs,
            vault_auth: &va,
            vault_kv: &kv,
            kbs_nonce_store: &nonce_store,
            kbs_attestation: &kbs_rep,
            kbs_auth_pubkey: b"kbs-channel-pub",
            kbs_signing_key: &kbs_sk,
            kbs_kid: b"kbs-kid",
            audit: &audit,
            evidence: &evidence,
            boot_counter: &boot_counter,
            volume_stamp: &volume_stamp,
            max_unconfirmed_releases: Some(crate::volume_stamp::MAX_UNCONFIRMED_RELEASES),
            require_wrapped_kek: false,
        };
        let raw_snp_report = vec![0u8; 1184];
        let req = ReleaseRequest {
            cose_ticket: &cose,
            raw_snp_report: &raw_snp_report,
            kbs_nonce: &nonce,
            now_unix: 200,
            submitted_boot_counter: None,
        };
        let signed = process_release(&req, &deps).expect("release still succeeds");
        let resp = verify_response(&kbs_sk.verifying_key(), &signed).unwrap();
        assert!(
            resp.lifecycle_key.is_none(),
            "no key staged ⇒ field omitted, KEK+userdata still released"
        );
        assert_eq!(resp.luks.secret_type, "luks");
    }

    /// Phase 1 anti-rollback gate (audit follow-up Codex #2).
    ///
    /// When the guest opts in by submitting a boot counter, the
    /// release path must:
    ///
    /// - accept exactly `stored + 1` (advancing the store);
    /// - refuse a skip (`stored + 2` or higher);
    /// - refuse a rewind (`stored` or lower);
    /// - refuse re-submission of the same value across two
    ///   consecutive requests, since by then `stored` has already
    ///   advanced.
    ///
    /// When the guest does NOT submit a counter (`None`), the store
    /// MUST stay at its current value — backward compat with
    /// pre-counter guests.
    #[test]
    fn submitted_boot_counter_gates_release_and_advances_store() {
        let (pk, sec) = crate::crypto::test_support::gen_x25519();
        let mut nonce = [1u8; 32];
        let mut rd = [0u8; 64];
        rd[0..32].copy_from_slice(&nonce);
        rd[32..64].copy_from_slice(&pk);
        let chip = [0u8; 64];
        let plat = hex::encode(chip);
        let ud = b"USERDATA-with-netbird-key";
        let (cose, l1, kid) = cose_for(&plat, 5, ud);
        let _ = sec; // silence unused-binding lint (sec belongs to the keypair fixture)

        let kr = Kr(kid, l1.verifying_key());
        let av = Av { rd, chip };
        let al = AllowAll;
        let lp = LaunchPolicy {
            min_tcb: 1,
            required_bits: 0b10,
            allowed_mask: 0b1101,
        };
        let st = OneState(VmState::Active {
            gen: 5,
            host: plat.clone(),
            lease_id: "lease-1".into(),
        });
        let rs = InMemoryReleaseStore::default();
        let ok: fn(&[u8; 48]) -> bool = |_m| true;
        let va = ChallengeVaultAuth {
            kbs_measurement_ok: ok,
            policy: LaunchPolicy {
                min_tcb: 1,
                required_bits: 0,
                allowed_mask: u64::MAX,
            },
            challenge_ttl: 60,
            cap_ttl: 60,
            challenge_nonce: [2u8; 32],
        };
        let mut kvm = HashMap::new();
        kvm.insert("kbs/vm/abc/luks".to_string(), b"LUKSKEY".to_vec());
        kvm.insert("kbs/vm/abc/ud".to_string(), ud.to_vec());
        let kv = Kv(kvm);
        let kbs_rep = VerifiedReport {
            measurement: MEAS,
            report_data: [0u8; 64],
            tcb: 5,
            policy: 0,
            chip_id: [0u8; 64],
            chain_pem: Vec::new(),
        };
        let kbs_sk = SigningKey::from_bytes(&[9u8; 32]);
        let audit = Audit::default();
        let evidence = crate::evidence::MockEvidenceSink::new();
        let nonce_store = MockNonceStore::default();
        let boot_counter = crate::boot_counter::InMemoryBootCounterStore::default();
        let volume_stamp = crate::volume_stamp::InMemoryVolumeStampStore::default();

        let raw_snp_report = vec![0u8; 1184];

        // Stored = 0. Submitting 2 is a SKIP → denied. Store still 0.
        nonce_store.preissue(nonce);
        let deps = Deps {
            l1_keyring: &kr,
            attn: &av,
            offline_allowlist: &al,
            launch_policy: &lp,
            vm_states: &st,
            release_store: &rs,
            vault_auth: &va,
            vault_kv: &kv,
            kbs_nonce_store: &nonce_store,
            kbs_attestation: &kbs_rep,
            kbs_auth_pubkey: b"kbs-channel-pub",
            kbs_signing_key: &kbs_sk,
            kbs_kid: b"kbs-kid",
            audit: &audit,
            evidence: &evidence,
            boot_counter: &boot_counter,
            volume_stamp: &volume_stamp,
            max_unconfirmed_releases: Some(crate::volume_stamp::MAX_UNCONFIRMED_RELEASES),
            require_wrapped_kek: false,
        };
        let req = ReleaseRequest {
            cose_ticket: &cose,
            raw_snp_report: &raw_snp_report,
            kbs_nonce: &nonce,
            now_unix: 200,
            submitted_boot_counter: Some(2),
        };
        assert!(process_release(&req, &deps).is_err());
        assert_eq!(boot_counter.get("abc").unwrap(), 0);

        // First boot: submitted = 1 → accepted, advances to 1.
        // (The replay store is keyed by (ticket_id, kbs_nonce), so a
        // fresh nonce is enough to dodge the §7 single-use guard
        // without a new ticket. The Av mock honors whatever `rd` we
        // hand it.)
        nonce[0] = 0x02;
        rd[0..32].copy_from_slice(&nonce);
        let av2 = Av { rd, chip };
        let nonce_store2 = MockNonceStore::default();
        nonce_store2.preissue(nonce);
        let deps2 = Deps {
            l1_keyring: &kr,
            attn: &av2,
            offline_allowlist: &al,
            launch_policy: &lp,
            vm_states: &st,
            release_store: &rs,
            vault_auth: &va,
            vault_kv: &kv,
            kbs_nonce_store: &nonce_store2,
            kbs_attestation: &kbs_rep,
            kbs_auth_pubkey: b"kbs-channel-pub",
            kbs_signing_key: &kbs_sk,
            kbs_kid: b"kbs-kid",
            audit: &audit,
            evidence: &evidence,
            boot_counter: &boot_counter,
            volume_stamp: &volume_stamp,
            max_unconfirmed_releases: Some(crate::volume_stamp::MAX_UNCONFIRMED_RELEASES),
            require_wrapped_kek: false,
        };
        let req2 = ReleaseRequest {
            cose_ticket: &cose,
            raw_snp_report: &raw_snp_report,
            kbs_nonce: &nonce,
            now_unix: 201,
            submitted_boot_counter: Some(1),
        };
        // This release SUCCEEDS end-to-end (fresh nonce, valid ticket,
        // Vault keys present), so the boot counter is COMMITTED in the
        // success path (gate 11c). Two-phase semantics: the counter
        // advances because the release committed — NOT merely because
        // the check passed. A release that denies AFTER the check never
        // reaches the commit (covered by the boot_counter unit tests
        // `check_only_does_not_persist` +
        // `failed_release_then_retry_succeeds_file_backed`).
        process_release(&req2, &deps2).expect("req2 release should succeed");
        assert_eq!(
            boot_counter.get("abc").unwrap(),
            1,
            "boot-counter MUST commit to 1 once the release durably succeeds"
        );

        // Now stored = 1. A rewind (Some(1) again) MUST be refused;
        // the store stays at 1.
        nonce[0] = 0x03;
        rd[0..32].copy_from_slice(&nonce);
        let av3 = Av { rd, chip };
        let nonce_store3 = MockNonceStore::default();
        nonce_store3.preissue(nonce);
        let deps3 = Deps {
            l1_keyring: &kr,
            attn: &av3,
            offline_allowlist: &al,
            launch_policy: &lp,
            vm_states: &st,
            release_store: &rs,
            vault_auth: &va,
            vault_kv: &kv,
            kbs_nonce_store: &nonce_store3,
            kbs_attestation: &kbs_rep,
            kbs_auth_pubkey: b"kbs-channel-pub",
            kbs_signing_key: &kbs_sk,
            kbs_kid: b"kbs-kid",
            audit: &audit,
            evidence: &evidence,
            boot_counter: &boot_counter,
            volume_stamp: &volume_stamp,
            max_unconfirmed_releases: Some(crate::volume_stamp::MAX_UNCONFIRMED_RELEASES),
            require_wrapped_kek: false,
        };
        let req3 = ReleaseRequest {
            cose_ticket: &cose,
            raw_snp_report: &raw_snp_report,
            kbs_nonce: &nonce,
            now_unix: 202,
            submitted_boot_counter: Some(1),
        };
        assert!(process_release(&req3, &deps3).is_err());
        assert_eq!(boot_counter.get("abc").unwrap(), 1);

        // None submission once stored > 0 → rollback-via-omission
        // (audit H8): REFUSED, and the store stays unchanged.
        nonce[0] = 0x04;
        rd[0..32].copy_from_slice(&nonce);
        let av4 = Av { rd, chip };
        let nonce_store4 = MockNonceStore::default();
        nonce_store4.preissue(nonce);
        let deps4 = Deps {
            l1_keyring: &kr,
            attn: &av4,
            offline_allowlist: &al,
            launch_policy: &lp,
            vm_states: &st,
            release_store: &rs,
            vault_auth: &va,
            vault_kv: &kv,
            kbs_nonce_store: &nonce_store4,
            kbs_attestation: &kbs_rep,
            kbs_auth_pubkey: b"kbs-channel-pub",
            kbs_signing_key: &kbs_sk,
            kbs_kid: b"kbs-kid",
            audit: &audit,
            evidence: &evidence,
            boot_counter: &boot_counter,
            volume_stamp: &volume_stamp,
            max_unconfirmed_releases: Some(crate::volume_stamp::MAX_UNCONFIRMED_RELEASES),
            require_wrapped_kek: false,
        };
        let req4 = ReleaseRequest {
            cose_ticket: &cose,
            raw_snp_report: &raw_snp_report,
            kbs_nonce: &nonce,
            now_unix: 203,
            submitted_boot_counter: None,
        };
        assert!(
            process_release(&req4, &deps4).is_err(),
            "None once a counter is committed must be refused (H8)"
        );
        let last_reason = audit.0.lock().unwrap().last().cloned();
        assert!(
            matches!(last_reason, Some((false, ref m)) if m.contains("rollback-via-omission")),
            "None-after-commit must fail closed as rollback-via-omission: {last_reason:?}"
        );
        assert_eq!(
            boot_counter.get("abc").unwrap(),
            1,
            "refused None submission MUST NOT touch the boot-counter store"
        );
    }

    /// The recovery for a LOST miner-side state disk
    /// (`boot_counter::arm_resync`), exercised through the whole release
    /// path — and, in the same test, proof that it changes NOTHING when
    /// nobody armed it.
    ///
    /// The scenario is the real one: a VM has booted twice (KBS stores
    /// 2), its host loses `state/<vm>.raw`, `ensure_state_disk` formats
    /// a blank replacement, and the guest — reading an absent counter
    /// file — submits `1` forever. Without an arm that is a permanent
    /// brick: `check_only` refuses before any Vault read and `seed`
    /// cannot repair a live row.
    ///
    /// Every assertion below is about a property that must survive the
    /// recovery, not merely about it working:
    ///
    /// - UNARMED, the identical request is REFUSED (if this ever passes,
    ///   the gate is gone);
    /// - ARMED, the release is granted but commits `stored + 1` — NOT
    ///   the submitted value — so a miner submitting a rewind while an
    ///   arm happens to be set cannot pull the counter down;
    /// - the guest is handed that same value in the SIGNED response, so
    ///   it can re-establish its own file with no operator arithmetic;
    /// - the arm is CONSUMED: replaying the very same stale submission
    ///   immediately afterwards is refused again.
    #[test]
    fn an_armed_resync_admits_one_boot_commits_stored_plus_one_and_disarms() {
        let (pk, sec) = crate::crypto::test_support::gen_x25519();
        let mut rd = [0u8; 64];
        rd[32..64].copy_from_slice(&pk);
        let chip = [0u8; 64];
        let plat = hex::encode(chip);
        let ud = b"USERDATA-with-netbird-key";
        let (cose, l1, kid) = cose_for(&plat, 5, ud);
        let _ = sec;

        let kr = Kr(kid, l1.verifying_key());
        let al = AllowAll;
        let lp = LaunchPolicy {
            min_tcb: 1,
            required_bits: 0b10,
            allowed_mask: 0b1101,
        };
        let st = OneState(VmState::Active {
            gen: 5,
            host: plat.clone(),
            lease_id: "lease-1".into(),
        });
        let rs = InMemoryReleaseStore::default();
        let ok: fn(&[u8; 48]) -> bool = |_m| true;
        let va = ChallengeVaultAuth {
            kbs_measurement_ok: ok,
            policy: LaunchPolicy {
                min_tcb: 1,
                required_bits: 0,
                allowed_mask: u64::MAX,
            },
            challenge_ttl: 60,
            cap_ttl: 60,
            challenge_nonce: [2u8; 32],
        };
        let mut kvm = HashMap::new();
        kvm.insert("kbs/vm/abc/luks".to_string(), b"LUKSKEY".to_vec());
        kvm.insert("kbs/vm/abc/ud".to_string(), ud.to_vec());
        let kv = Kv(kvm);
        let kbs_rep = VerifiedReport {
            measurement: MEAS,
            report_data: [0u8; 64],
            tcb: 5,
            policy: 0,
            chip_id: [0u8; 64],
            chain_pem: Vec::new(),
        };
        let kbs_sk = SigningKey::from_bytes(&[9u8; 32]);
        let audit = Audit::default();
        let evidence = crate::evidence::MockEvidenceSink::new();
        let boot_counter = crate::boot_counter::InMemoryBootCounterStore::default();
        let volume_stamp = crate::volume_stamp::InMemoryVolumeStampStore::default();
        let raw_snp_report = vec![0u8; 1184];

        // One release attempt with a fresh nonce (the replay store is
        // keyed by (ticket_id, nonce), so a new nonce is all a repeat
        // request needs).
        let attempt = |tag: u8, submitted: Option<u64>| {
            let mut nonce = [1u8; 32];
            nonce[0] = tag;
            let mut rd = rd;
            rd[0..32].copy_from_slice(&nonce);
            let av = Av { rd, chip };
            let nonce_store = MockNonceStore::default();
            nonce_store.preissue(nonce);
            let deps = Deps {
                l1_keyring: &kr,
                attn: &av,
                offline_allowlist: &al,
                launch_policy: &lp,
                vm_states: &st,
                release_store: &rs,
                vault_auth: &va,
                vault_kv: &kv,
                kbs_nonce_store: &nonce_store,
                kbs_attestation: &kbs_rep,
                kbs_auth_pubkey: b"kbs-channel-pub",
                kbs_signing_key: &kbs_sk,
                kbs_kid: b"kbs-kid",
                audit: &audit,
                evidence: &evidence,
                boot_counter: &boot_counter,
                volume_stamp: &volume_stamp,
                // Disabled here so the suppressed-confirm bound (which
                // this VM would trip after a few unconfirmed boots)
                // cannot be what refuses a request; the boot counter is
                // the only gate under test.
                max_unconfirmed_releases: None,
                require_wrapped_kek: false,
            };
            let req = ReleaseRequest {
                cose_ticket: &cose,
                raw_snp_report: &raw_snp_report,
                kbs_nonce: &nonce,
                now_unix: 200 + tag as u64,
                submitted_boot_counter: submitted,
            };
            process_release(&req, &deps)
        };

        // Two ordinary boots: the KBS now stores 2.
        attempt(0x01, Some(1)).expect("boot 1");
        attempt(0x02, Some(2)).expect("boot 2");
        assert_eq!(boot_counter.get("abc").unwrap(), 2);

        // The host loses the state disk. The guest submits 1.
        // UNARMED this MUST be refused — the whole point of the gate.
        assert!(
            attempt(0x03, Some(1)).is_err(),
            "an unarmed VM submitting a stale counter must still be refused"
        );
        assert_eq!(boot_counter.get("abc").unwrap(), 2, "no partial advance");
        let refusal = audit.0.lock().unwrap().last().cloned();
        assert!(
            matches!(refusal, Some((false, ref m)) if m.contains("boot-counter-lost")),
            "the refusal must name the LOST shape so an operator can act: {refusal:?}"
        );

        // The operator establishes what happened and arms the resync on
        // the mTLS admin listener. Arming writes no counter.
        use crate::boot_counter::BootCounterStore as _;
        boot_counter.arm_resync("abc").unwrap();
        assert_eq!(boot_counter.get("abc").unwrap(), 2, "arming moves nothing");

        // The same submission now succeeds — and commits stored+1 = 3,
        // NOT the submitted 1. A hostile miner submitting a rewind into
        // an armed window therefore pulls the counter DOWN by exactly
        // nothing.
        let signed = attempt(0x04, Some(1)).expect("the armed boot is admitted");
        assert_eq!(
            boot_counter.get("abc").unwrap(),
            3,
            "the armed release must commit stored+1, never the submitted value"
        );
        let resp = verify_response(&kbs_sk.verifying_key(), &signed).unwrap();
        assert_eq!(
            resp.boot_counter, 3,
            "the guest must be handed the value to persist to its fresh state disk"
        );

        // ONE shot: the identical stale submission is refused again.
        assert!(
            attempt(0x05, Some(1)).is_err(),
            "the arm must be consumed by the release that used it"
        );
        assert_eq!(boot_counter.get("abc").unwrap(), 3);

        // …and the guest that persisted the echoed value is back in
        // lockstep: the next real boot submits 4 and is accepted on the
        // ordinary path, with no arm.
        assert!(!boot_counter.resync_armed("abc").unwrap());
        attempt(0x06, Some(4)).expect("the re-baselined guest boots normally");
        assert_eq!(boot_counter.get("abc").unwrap(), 4);
    }

    /// An arm covers the guest submitting a WRONG counter. It does NOT
    /// cover the guest submitting NONE.
    ///
    /// The two are different failures: a lost state disk still yields a
    /// mounted `/dev/vdd` and a guest that submits `1`, whereas an
    /// OMITTED counter means the state disk was never presented to the
    /// guest at all — which is also exactly what a miner does to dodge
    /// the CAS (audit H8, rollback-via-omission). Letting an arm admit
    /// an omission would turn one operator action into a blanket
    /// "release without any counter at all", so the omission guard is
    /// checked independently of the arm.
    #[test]
    fn an_arm_does_not_admit_a_release_that_omits_the_counter() {
        let (pk, sec) = crate::crypto::test_support::gen_x25519();
        let mut nonce = [7u8; 32];
        let mut rd = [0u8; 64];
        rd[0..32].copy_from_slice(&nonce);
        rd[32..64].copy_from_slice(&pk);
        let chip = [0u8; 64];
        let plat = hex::encode(chip);
        let ud = b"USERDATA-with-netbird-key";
        let (cose, l1, kid) = cose_for(&plat, 5, ud);
        let _ = sec;

        let kr = Kr(kid, l1.verifying_key());
        let al = AllowAll;
        let lp = LaunchPolicy {
            min_tcb: 1,
            required_bits: 0b10,
            allowed_mask: 0b1101,
        };
        let st = OneState(VmState::Active {
            gen: 5,
            host: plat.clone(),
            lease_id: "lease-1".into(),
        });
        let rs = InMemoryReleaseStore::default();
        let ok: fn(&[u8; 48]) -> bool = |_m| true;
        let va = ChallengeVaultAuth {
            kbs_measurement_ok: ok,
            policy: LaunchPolicy {
                min_tcb: 1,
                required_bits: 0,
                allowed_mask: u64::MAX,
            },
            challenge_ttl: 60,
            cap_ttl: 60,
            challenge_nonce: [2u8; 32],
        };
        let mut kvm = HashMap::new();
        kvm.insert("kbs/vm/abc/luks".to_string(), b"LUKSKEY".to_vec());
        kvm.insert("kbs/vm/abc/ud".to_string(), ud.to_vec());
        let kv = Kv(kvm);
        let kbs_rep = VerifiedReport {
            measurement: MEAS,
            report_data: [0u8; 64],
            tcb: 5,
            policy: 0,
            chip_id: [0u8; 64],
            chain_pem: Vec::new(),
        };
        let kbs_sk = SigningKey::from_bytes(&[9u8; 32]);
        let audit = Audit::default();
        let evidence = crate::evidence::MockEvidenceSink::new();
        let boot_counter = crate::boot_counter::InMemoryBootCounterStore::default();
        let volume_stamp = crate::volume_stamp::InMemoryVolumeStampStore::default();
        let raw_snp_report = vec![0u8; 1184];

        // The VM has booted once, and an operator has armed a resync.
        use crate::boot_counter::BootCounterStore as _;
        boot_counter.check_and_advance("abc", 1).unwrap();
        boot_counter.arm_resync("abc").unwrap();

        nonce[0] = 0x11;
        rd[0..32].copy_from_slice(&nonce);
        let av = Av { rd, chip };
        let nonce_store = MockNonceStore::default();
        nonce_store.preissue(nonce);
        let deps = Deps {
            l1_keyring: &kr,
            attn: &av,
            offline_allowlist: &al,
            launch_policy: &lp,
            vm_states: &st,
            release_store: &rs,
            vault_auth: &va,
            vault_kv: &kv,
            kbs_nonce_store: &nonce_store,
            kbs_attestation: &kbs_rep,
            kbs_auth_pubkey: b"kbs-channel-pub",
            kbs_signing_key: &kbs_sk,
            kbs_kid: b"kbs-kid",
            audit: &audit,
            evidence: &evidence,
            boot_counter: &boot_counter,
            volume_stamp: &volume_stamp,
            max_unconfirmed_releases: None,
            require_wrapped_kek: false,
        };
        let req = ReleaseRequest {
            cose_ticket: &cose,
            raw_snp_report: &raw_snp_report,
            kbs_nonce: &nonce,
            now_unix: 300,
            submitted_boot_counter: None,
        };
        assert!(
            process_release(&req, &deps).is_err(),
            "an armed VM must still refuse a release that carries no counter at all"
        );
        let last = audit.0.lock().unwrap().last().cloned();
        assert!(
            matches!(last, Some((false, ref m)) if m.contains("rollback-via-omission")),
            "and for the omission reason, not the counter-mismatch one: {last:?}"
        );
        assert_eq!(boot_counter.get("abc").unwrap(), 1);
        assert!(
            boot_counter.resync_armed("abc").unwrap(),
            "a refused release must not consume the operator's arm"
        );
    }

    /// The load-bearing test for the whole volume-stamp redesign (see the
    /// `volume_stamp` module docs). `MAX_UNCONFIRMED_RELEASES` consecutive
    /// SUCCESSFUL releases for the same `vm_id`, with NO guest confirm in
    /// between — modelling a host that boots the VM, lets it take the KEK,
    /// kills it before the guest can stamp its volume, and repeats — must
    /// leave `volume_stamp.get(vm_id)` untouched, and the volume must
    /// still be openable afterwards. (The suppressed-confirm REFUSAL that
    /// kicks in past this bound is a separate, focused test —
    /// `releases_beyond_the_unconfirmed_bound_are_refused_until_an_admin_
    /// resets_it` — so this one stays about the non-accumulation property
    /// alone.)
    ///
    /// Contrast with `boot_counter` in the SAME loop: it advances on
    /// every durably-committed release regardless of whether the guest
    /// ever finishes booting. Comparing an in-volume stamp against THAT
    /// value — the naive design the module docs reject — would grow the
    /// gap by one per aborted boot and permanently brick this VM after a
    /// handful of kill cycles, because nothing could ever re-stamp the
    /// volume to catch up. The volume stamp's confirm-only-advance
    /// semantics have no such tolerance to exhaust, because it never
    /// moves without an authenticated confirm.
    #[test]
    fn aborted_boots_do_not_advance_the_volume_stamp_so_no_gap_accumulates() {
        let (pk, sec) = crate::crypto::test_support::gen_x25519();
        let mut nonce = [1u8; 32];
        let mut rd = [0u8; 64];
        rd[0..32].copy_from_slice(&nonce);
        rd[32..64].copy_from_slice(&pk);
        let chip = [0u8; 64];
        let plat = hex::encode(chip);
        let ud = b"USERDATA-with-netbird-key";
        let (cose, l1, kid) = cose_for(&plat, 5, ud);

        let kr = Kr(kid, l1.verifying_key());
        let al = AllowAll;
        let lp = LaunchPolicy {
            min_tcb: 1,
            required_bits: 0b10,
            allowed_mask: 0b1101,
        };
        let st = OneState(VmState::Active {
            gen: 5,
            host: plat.clone(),
            lease_id: "lease-1".into(),
        });
        let rs = InMemoryReleaseStore::default();
        let ok: fn(&[u8; 48]) -> bool = |_m| true;
        let va = ChallengeVaultAuth {
            kbs_measurement_ok: ok,
            policy: LaunchPolicy {
                min_tcb: 1,
                required_bits: 0,
                allowed_mask: u64::MAX,
            },
            challenge_ttl: 60,
            cap_ttl: 60,
            challenge_nonce: [2u8; 32],
        };
        let mut kvm = HashMap::new();
        kvm.insert("kbs/vm/abc/luks".to_string(), b"LUKSKEY".to_vec());
        kvm.insert("kbs/vm/abc/ud".to_string(), ud.to_vec());
        let kv = Kv(kvm);
        let kbs_rep = VerifiedReport {
            measurement: MEAS,
            report_data: [0u8; 64],
            tcb: 5,
            policy: 0,
            chip_id: [0u8; 64],
            chain_pem: Vec::new(),
        };
        let kbs_sk = SigningKey::from_bytes(&[9u8; 32]);
        let audit = Audit::default();
        let evidence = crate::evidence::MockEvidenceSink::new();
        let boot_counter = crate::boot_counter::InMemoryBootCounterStore::default();
        let volume_stamp = crate::volume_stamp::InMemoryVolumeStampStore::default();
        let raw_snp_report = vec![0u8; 1184];

        assert_eq!(
            volume_stamp.get("abc").unwrap(),
            0,
            "before any release: a fresh store reads 0"
        );

        let mut last_resp = None;
        for i in 1..=crate::volume_stamp::MAX_UNCONFIRMED_RELEASES {
            nonce[0] = i as u8;
            rd[0..32].copy_from_slice(&nonce);
            let av_i = Av { rd, chip };
            let nonce_store_i = MockNonceStore::default();
            nonce_store_i.preissue(nonce);
            let deps_i = Deps {
                l1_keyring: &kr,
                attn: &av_i,
                offline_allowlist: &al,
                launch_policy: &lp,
                vm_states: &st,
                release_store: &rs,
                vault_auth: &va,
                vault_kv: &kv,
                kbs_nonce_store: &nonce_store_i,
                kbs_attestation: &kbs_rep,
                kbs_auth_pubkey: b"kbs-channel-pub",
                kbs_signing_key: &kbs_sk,
                kbs_kid: b"kbs-kid",
                audit: &audit,
                evidence: &evidence,
                boot_counter: &boot_counter,
                volume_stamp: &volume_stamp,
                max_unconfirmed_releases: Some(crate::volume_stamp::MAX_UNCONFIRMED_RELEASES),
                require_wrapped_kek: false,
            };
            let req_i = ReleaseRequest {
                cose_ticket: &cose,
                raw_snp_report: &raw_snp_report,
                kbs_nonce: &nonce,
                now_unix: 200 + i,
                // The guest DOES adopt the boot-counter field (so the
                // boot-counter side of the contrast below is real) but
                // is killed by the host before it ever writes+confirms
                // the volume stamp — the release completes, the boot
                // does not.
                submitted_boot_counter: Some(i),
            };
            let signed = process_release(&req_i, &deps_i)
                .unwrap_or_else(|_| panic!("release {i} should succeed"));
            let resp = verify_response(&kbs_sk.verifying_key(), &signed).unwrap();
            assert_eq!(
                resp.expected_volume_stamp, 0,
                "release {i}: the volume-stamp expectation must not have moved — \
                 no confirm has ever happened"
            );
            assert!(
                resp.volume_stamp_token.is_some(),
                "release {i}: a confirm token must still be minted every time"
            );
            // The real assertion: the store itself, before AND after
            // this release, reads 0 — not merely "confirm was never
            // called".
            assert_eq!(
                volume_stamp.get("abc").unwrap(),
                0,
                "release {i}: the store must be untouched after this release — \
                 only an authenticated confirm may move it, and none happened"
            );
            last_resp = Some(resp);
        }

        // Contrast: the boot counter — which advances on every durably
        // committed release regardless of whether the guest ever
        // finishes booting — DID accumulate across the same N cycles.
        // Comparing an in-volume stamp against THIS value (the design
        // the module docs reject) would already be unopenable after a
        // fixed tolerance; the volume stamp never had one to exhaust.
        assert_eq!(
            boot_counter.get("abc").unwrap(),
            crate::volume_stamp::MAX_UNCONFIRMED_RELEASES,
            "boot-counter accumulates one per aborted boot — this is exactly \
             the failure mode the volume stamp avoids"
        );

        // The volume is still openable on the NEXT cycle: unwrap the LAST
        // release's token (target is always 1, since the expectation
        // never moved off 0) and confirm — it succeeds because the
        // expectation never ran ahead of a volume that was never
        // stamped.
        let resp = last_resp.expect("at least one release ran");
        let w = resp
            .volume_stamp_token
            .as_ref()
            .expect("release must carry a volume-stamp token");
        let ud_digest = userdata_digest("t", "abc", "tk-1", "userdata", "kbs/vm/abc/ud", 2, ud);
        let lc = ReleaseContext {
            v: SCHEMA_V,
            ticket_id: "tk-1",
            tenant_id: "t",
            vm_id: "abc",
            vm_generation: 5,
            kbs_nonce: &nonce,
            measurement: &MEAS,
            kbs_kid: b"kbs-kid",
            secret_type: "volume-stamp-token",
            secret_path: "kbs/volume-stamp",
            secret_version: 1,
            allowed_userdata_digest: &ud_digest,
        };
        let token = crate::crypto::hpke_unwrap(&sec, w, &lc).unwrap();
        let mac_key = crate::volume_stamp::stamp_mac_key(&kbs_sk.to_bytes());
        let confirmed =
            crate::volume_stamp::confirm(&volume_stamp, &mac_key, "abc", 1, token.as_slice())
                .expect("the volume must still be confirmable after 10 aborted boots");
        assert_eq!(confirmed, 1);
        assert_eq!(volume_stamp.get("abc").unwrap(), 1);

        // Now that the store holds a NON-ZERO stamp, one more release must
        // echo THAT value — not a hardcoded 0 — and must mint a token for
        // stamp+1.
        //
        // This half is load-bearing and was found by mutation testing: with
        // only the zero-stamp assertions above, a release that reported
        // `expected_volume_stamp = 0` unconditionally passed every test,
        // yet it would silently DISABLE the gate in production — the guest
        // treats E == 0 as "no expectation on record" and adopts whatever
        // stamp it finds, so every rolled-back overlay would be accepted.
        nonce[0] = 200;
        rd[0..32].copy_from_slice(&nonce);
        let av_f = Av { rd, chip };
        let nonce_store_f = MockNonceStore::default();
        nonce_store_f.preissue(nonce);
        let deps_f = Deps {
            l1_keyring: &kr,
            attn: &av_f,
            offline_allowlist: &al,
            launch_policy: &lp,
            vm_states: &st,
            release_store: &rs,
            vault_auth: &va,
            vault_kv: &kv,
            kbs_nonce_store: &nonce_store_f,
            kbs_attestation: &kbs_rep,
            kbs_auth_pubkey: b"kbs-channel-pub",
            kbs_signing_key: &kbs_sk,
            kbs_kid: b"kbs-kid",
            audit: &audit,
            evidence: &evidence,
            boot_counter: &boot_counter,
            volume_stamp: &volume_stamp,
            max_unconfirmed_releases: Some(crate::volume_stamp::MAX_UNCONFIRMED_RELEASES),
            require_wrapped_kek: false,
        };
        let req_f = ReleaseRequest {
            cose_ticket: &cose,
            raw_snp_report: &raw_snp_report,
            kbs_nonce: &nonce,
            now_unix: 400,
            // boot_counter is at MAX_UNCONFIRMED_RELEASES (3) after the
            // loop; this release advances it to 4.
            submitted_boot_counter: Some(crate::volume_stamp::MAX_UNCONFIRMED_RELEASES + 1),
        };
        let signed_f =
            process_release(&req_f, &deps_f).expect("post-confirm release should succeed");
        let resp_f = verify_response(&kbs_sk.verifying_key(), &signed_f).unwrap();
        assert_eq!(
            resp_f.expected_volume_stamp, 1,
            "the release must echo the STORE's confirmed stamp; reporting 0 here would make \
             every guest take the adopt path and silently disable the rollback gate"
        );

        // ...and the token it minted authorises exactly stamp+1 = 2.
        let w_f = resp_f
            .volume_stamp_token
            .as_ref()
            .expect("release must carry a volume-stamp token");
        let lc_f = ReleaseContext {
            v: SCHEMA_V,
            ticket_id: "tk-1",
            tenant_id: "t",
            vm_id: "abc",
            vm_generation: 5,
            kbs_nonce: &nonce,
            measurement: &MEAS,
            kbs_kid: b"kbs-kid",
            secret_type: "volume-stamp-token",
            secret_path: "kbs/volume-stamp",
            secret_version: 2,
            allowed_userdata_digest: &ud_digest,
        };
        let token_f = crate::crypto::hpke_unwrap(&sec, w_f, &lc_f).unwrap();
        assert_eq!(
            crate::volume_stamp::confirm(&volume_stamp, &mac_key, "abc", 2, token_f.as_slice())
                .expect("the minted token must authorise stamp+1"),
            2
        );
        assert_eq!(volume_stamp.get("abc").unwrap(), 2);
    }

    /// The suppressed-confirm gate, exercised through the REAL release
    /// path (`process_release`), not through the store directly.
    ///
    /// A miner controls the transport that `/v1/kbs/volume-stamp/confirm`
    /// travels over, so it can drop every confirm. That pins the
    /// expectation at 0 — which the guest reads as "no expectation on
    /// record" and ADOPTS, disabling the rollback gate entirely. It
    /// cannot suppress the RELEASE (it needs the release to get a KEK),
    /// so the KBS counts releases-since-last-confirm and refuses once the
    /// count exceeds the bound.
    ///
    /// Three phases in one test so they share the (verbose) deps
    /// scaffolding:
    ///   A. STEADY STATE — release→confirm, ten times. Must NEVER trip:
    ///      a healthy VM rebooting forever is the common case, and a gate
    ///      that trips on it would be an outage generator.
    ///   B. SUPPRESSION — `MAX_UNCONFIRMED_RELEASES` releases with no
    ///      confirm succeed; the NEXT one is refused, with the stable
    ///      `volume-stamp-confirm-suppressed` classifier.
    ///   C. RECOVERY — only the ADMIN reset clears it; the next release
    ///      then succeeds again.
    #[test]
    fn suppressed_confirms_are_bounded_and_only_an_admin_reset_clears_them() {
        let (pk, sec) = crate::crypto::test_support::gen_x25519();
        let nonce = [1u8; 32];
        let mut rd = [0u8; 64];
        rd[0..32].copy_from_slice(&nonce);
        rd[32..64].copy_from_slice(&pk);
        let chip = [0u8; 64];
        let plat = hex::encode(chip);
        let ud = b"USERDATA-suppression";
        let (cose, l1, kid) = cose_for(&plat, 5, ud);

        let kr = Kr(kid, l1.verifying_key());
        let al = AllowAll;
        let lp = LaunchPolicy {
            min_tcb: 1,
            required_bits: 0b10,
            allowed_mask: 0b1101,
        };
        let st = OneState(VmState::Active {
            gen: 5,
            host: plat.clone(),
            lease_id: "lease-1".into(),
        });
        let rs = InMemoryReleaseStore::default();
        let ok: fn(&[u8; 48]) -> bool = |_m| true;
        let va = ChallengeVaultAuth {
            kbs_measurement_ok: ok,
            policy: LaunchPolicy {
                min_tcb: 1,
                required_bits: 0,
                allowed_mask: u64::MAX,
            },
            challenge_ttl: 60,
            cap_ttl: 60,
            challenge_nonce: [2u8; 32],
        };
        let mut kvm = HashMap::new();
        kvm.insert("kbs/vm/abc/luks".to_string(), b"LUKSKEY".to_vec());
        kvm.insert("kbs/vm/abc/ud".to_string(), ud.to_vec());
        let kv = Kv(kvm);
        let kbs_rep = VerifiedReport {
            measurement: MEAS,
            report_data: [0u8; 64],
            tcb: 5,
            policy: 0,
            chip_id: [0u8; 64],
            chain_pem: Vec::new(),
        };
        let kbs_sk = SigningKey::from_bytes(&[9u8; 32]);
        let audit = Audit::default();
        let evidence = crate::evidence::MockEvidenceSink::new();
        let boot_counter = crate::boot_counter::InMemoryBootCounterStore::default();
        let volume_stamp = crate::volume_stamp::InMemoryVolumeStampStore::default();
        let raw_snp_report = vec![0u8; 1184];
        let mac_key = crate::volume_stamp::stamp_mac_key(&kbs_sk.to_bytes());
        let ud_digest = userdata_digest("t", "abc", "tk-1", "userdata", "kbs/vm/abc/ud", 2, ud);

        // One release attempt. `n` is both the nonce discriminator and
        // the submitted boot counter, so every attempt is a fresh,
        // fully-valid request that only differs in those two.
        let attempt = |n: u64, bc: u64| -> core::result::Result<KbsResponse, String> {
            let mut nonce_n = nonce;
            nonce_n[0] = (n % 251) as u8;
            nonce_n[1] = (n / 251) as u8;
            let mut rd_n = rd;
            rd_n[0..32].copy_from_slice(&nonce_n);
            let av_n = Av { rd: rd_n, chip };
            let nonce_store_n = MockNonceStore::default();
            nonce_store_n.preissue(nonce_n);
            let deps_n = Deps {
                l1_keyring: &kr,
                attn: &av_n,
                offline_allowlist: &al,
                launch_policy: &lp,
                vm_states: &st,
                release_store: &rs,
                vault_auth: &va,
                vault_kv: &kv,
                kbs_nonce_store: &nonce_store_n,
                kbs_attestation: &kbs_rep,
                kbs_auth_pubkey: b"kbs-channel-pub",
                kbs_signing_key: &kbs_sk,
                kbs_kid: b"kbs-kid",
                audit: &audit,
                evidence: &evidence,
                boot_counter: &boot_counter,
                volume_stamp: &volume_stamp,
                max_unconfirmed_releases: Some(crate::volume_stamp::MAX_UNCONFIRMED_RELEASES),
                require_wrapped_kek: false,
            };
            let req_n = ReleaseRequest {
                cose_ticket: &cose,
                raw_snp_report: &raw_snp_report,
                kbs_nonce: &nonce_n,
                now_unix: 200 + n,
                submitted_boot_counter: Some(bc),
            };
            match process_release(&req_n, &deps_n) {
                Ok(signed) => Ok(verify_response(&kbs_sk.verifying_key(), &signed).unwrap()),
                // The signed denial does not carry the reason, so read it
                // off the audit sink, which records `to_string()` verbatim.
                Err(_) => Err(audit.last_reason()),
            }
        };

        // Unwrap the confirm token from a response and confirm it.
        let confirm_from = |resp: &KbsResponse, n: u64| {
            let mut nonce_n = nonce;
            nonce_n[0] = (n % 251) as u8;
            nonce_n[1] = (n / 251) as u8;
            let target = resp.expected_volume_stamp + 1;
            let lc = ReleaseContext {
                v: SCHEMA_V,
                ticket_id: "tk-1",
                tenant_id: "t",
                vm_id: "abc",
                vm_generation: 5,
                kbs_nonce: &nonce_n,
                measurement: &MEAS,
                kbs_kid: b"kbs-kid",
                secret_type: "volume-stamp-token",
                secret_path: "kbs/volume-stamp",
                secret_version: target,
                allowed_userdata_digest: &ud_digest,
            };
            let w = resp.volume_stamp_token.as_ref().expect("token");
            let token = crate::crypto::hpke_unwrap(&sec, w, &lc).unwrap();
            crate::volume_stamp::confirm(&volume_stamp, &mac_key, "abc", target, token.as_slice())
                .expect("confirm must succeed")
        };

        // ── Phase A: STEADY STATE. Ten healthy boots, each confirming.
        // The counter resets every cycle, so the bound is never
        // approached no matter how long the VM lives.
        let mut n = 0u64;
        // The boot-counter CAS (gate 5b) runs BEFORE the suppression gate
        // and only commits on success, so track the granted count and
        // always submit `granted + 1`. Otherwise a refused attempt would
        // desync the counter and the next call would be denied by 5b —
        // masking whether 5c is doing anything at all.
        let mut granted = 0u64;
        for cycle in 1..=10u64 {
            n += 1;
            let resp = attempt(n, granted + 1)
                .unwrap_or_else(|e| panic!("steady-state cycle {cycle} must be granted: {e}"));
            granted += 1;
            assert_eq!(
                resp.expected_volume_stamp,
                cycle - 1,
                "steady state: each release echoes the previous cycle's confirmed stamp"
            );
            assert_eq!(confirm_from(&resp, n), cycle);
        }
        assert_eq!(
            volume_stamp.get("abc").unwrap(),
            10,
            "ten confirmed boots advance the stamp to 10"
        );

        // ── Phase B: SUPPRESSION. From here on the miner drops every
        // confirm. Exactly MAX_UNCONFIRMED_RELEASES more releases are
        // granted, and the next one is refused.
        for k in 1..=crate::volume_stamp::MAX_UNCONFIRMED_RELEASES {
            n += 1;
            let resp = attempt(n, granted + 1).unwrap_or_else(|e| {
                panic!("suppressed release {k} (within the bound) must still be granted: {e}")
            });
            granted += 1;
            assert_eq!(
                resp.expected_volume_stamp, 10,
                "a dropped confirm must NOT move the expectation"
            );
        }
        n += 1;
        let refused = attempt(n, granted + 1).expect_err(
            "the release after MAX_UNCONFIRMED_RELEASES unconfirmed ones must be REFUSED — \
             otherwise a miner that drops every confirm keeps the expectation at 10 forever \
             and the guest's rollback gate stays disabled",
        );
        assert!(
            refused.contains("volume-stamp-confirm-suppressed"),
            "the denial must carry the stable classifier so an operator can tell it from an \
             attestation failure; got: {refused}"
        );
        // Fail-closed BEFORE anything else moved: the boot counter was
        // checked but never committed for the refused attempt.
        assert_eq!(
            volume_stamp.get("abc").unwrap(),
            10,
            "a refused release must not move the confirmed stamp"
        );
        // A suppression refusal must NOT burn a boot counter. Gate 5b
        // only `check_only`s (no persist); the commit lives at gate 11c,
        // which a 5c refusal never reaches. This is a non-obvious good
        // property worth pinning: if a refusal DID advance the KBS boot
        // counter, a miner could walk that counter away from the guest's
        // on-disk value by simply provoking suppression refusals, and
        // every later boot would be denied as a rollback — turning an
        // availability gate into the permanent brick this whole design
        // exists to avoid.
        assert_eq!(
            boot_counter.get("abc").unwrap(),
            granted,
            "a suppression refusal must not advance the KBS boot counter — it never reaches \
             the gate-11c commit, so the counter stays in lockstep with the guest's disk"
        );

        // Still refused on retry — a miner cannot simply try again.
        n += 1;
        let refused_again = attempt(n, granted + 1).expect_err(
            "a retry must STILL be refused — a miner cannot clear its own suppression by \
             simply trying again",
        );
        assert!(
            refused_again.contains("volume-stamp-confirm-suppressed"),
            "the retry must be refused by the SUPPRESSION gate, not incidentally by the \
             boot-counter CAS; got: {refused_again}"
        );

        // ── Phase C: RECOVERY is ADMIN-ONLY. Nothing the guest or the
        // miner can reach clears this; only the admin reset does.
        let cleared = volume_stamp.admin_reset_unconfirmed("abc").unwrap();
        assert!(
            cleared > crate::volume_stamp::MAX_UNCONFIRMED_RELEASES,
            "the admin reset reports the count it cleared (was {cleared})"
        );
        assert_eq!(
            volume_stamp.get("abc").unwrap(),
            10,
            "the admin reset must NOT touch the confirmed stamp"
        );

        n += 1;
        let resp = attempt(n, granted + 1).expect("after the admin reset the VM may boot again");
        assert_eq!(resp.expected_volume_stamp, 10);
        // ...and a confirm now lands, restoring the steady state.
        assert_eq!(confirm_from(&resp, n), 11);
        assert_eq!(volume_stamp.get("abc").unwrap(), 11);
    }

    /// DEPLOYMENT-SAFETY: `Deps::max_unconfirmed_releases = None` must
    /// disable gate 5c OUTRIGHT — no refusal, no matter how many
    /// unconfirmed releases accumulate. This is the state the chart MUST
    /// ship in until every golden image in the fleet has been re-baked
    /// to send confirms; arming this gate before that (the compiled
    /// `MAX_UNCONFIRMED_RELEASES` default is `Some(3)`) would brick
    /// every LEGACY VM — any guest whose initramfs predates the confirm
    /// route can NEVER confirm — after `bound` releases (boots, §25
    /// migrations, and reboot-recovery relaunches all count).
    #[test]
    fn suppressed_confirm_gate_disabled_never_refuses_no_matter_how_many_unconfirmed_releases() {
        let (pk, _sec) = crate::crypto::test_support::gen_x25519();
        let mut nonce = [1u8; 32];
        let mut rd = [0u8; 64];
        rd[0..32].copy_from_slice(&nonce);
        rd[32..64].copy_from_slice(&pk);
        let chip = [0u8; 64];
        let plat = hex::encode(chip);
        let ud = b"USERDATA-legacy";
        let (cose, l1, kid) = cose_for(&plat, 5, ud);

        let kr = Kr(kid, l1.verifying_key());
        let al = AllowAll;
        let lp = LaunchPolicy {
            min_tcb: 1,
            required_bits: 0b10,
            allowed_mask: 0b1101,
        };
        let st = OneState(VmState::Active {
            gen: 5,
            host: plat.clone(),
            lease_id: "lease-1".into(),
        });
        let rs = InMemoryReleaseStore::default();
        let ok: fn(&[u8; 48]) -> bool = |_m| true;
        let va = ChallengeVaultAuth {
            kbs_measurement_ok: ok,
            policy: LaunchPolicy {
                min_tcb: 1,
                required_bits: 0,
                allowed_mask: u64::MAX,
            },
            challenge_ttl: 60,
            cap_ttl: 60,
            challenge_nonce: [2u8; 32],
        };
        let mut kvm = HashMap::new();
        kvm.insert("kbs/vm/abc/luks".to_string(), b"LUKSKEY".to_vec());
        kvm.insert("kbs/vm/abc/ud".to_string(), ud.to_vec());
        let kv = Kv(kvm);
        let kbs_rep = VerifiedReport {
            measurement: MEAS,
            report_data: [0u8; 64],
            tcb: 5,
            policy: 0,
            chip_id: [0u8; 64],
            chain_pem: Vec::new(),
        };
        let kbs_sk = SigningKey::from_bytes(&[9u8; 32]);
        let audit = Audit::default();
        let evidence = crate::evidence::MockEvidenceSink::new();
        let boot_counter = crate::boot_counter::InMemoryBootCounterStore::default();
        let volume_stamp = crate::volume_stamp::InMemoryVolumeStampStore::default();
        let raw_snp_report = vec![0u8; 1184];

        // A legacy VM: every boot submits `submitted_boot_counter: None`
        // (this guest predates Phase 2A too) and NEVER confirms. Drive it
        // well past what the compiled default (3) would have tolerated —
        // if the gate were armed, this would already have been refused
        // three releases ago.
        for i in 1..=(crate::volume_stamp::MAX_UNCONFIRMED_RELEASES * 4) {
            nonce[0] = i as u8;
            rd[0..32].copy_from_slice(&nonce);
            let av_i = Av { rd, chip };
            let nonce_store_i = MockNonceStore::default();
            nonce_store_i.preissue(nonce);
            let deps_i = Deps {
                l1_keyring: &kr,
                attn: &av_i,
                offline_allowlist: &al,
                launch_policy: &lp,
                vm_states: &st,
                release_store: &rs,
                vault_auth: &va,
                vault_kv: &kv,
                kbs_nonce_store: &nonce_store_i,
                kbs_attestation: &kbs_rep,
                kbs_auth_pubkey: b"kbs-channel-pub",
                kbs_signing_key: &kbs_sk,
                kbs_kid: b"kbs-kid",
                audit: &audit,
                evidence: &evidence,
                boot_counter: &boot_counter,
                volume_stamp: &volume_stamp,
                // THE claim under test.
                max_unconfirmed_releases: None,
                require_wrapped_kek: false,
            };
            let req_i = ReleaseRequest {
                cose_ticket: &cose,
                raw_snp_report: &raw_snp_report,
                kbs_nonce: &nonce,
                now_unix: 100 + i,
                submitted_boot_counter: None,
            };
            process_release(&req_i, &deps_i).unwrap_or_else(|_| {
                panic!("release {i} must succeed — the gate is DISABLED (None)")
            });
        }
    }

    /// The bound is genuinely READ from `Deps`, not hardcoded to the
    /// compiled `MAX_UNCONFIRMED_RELEASES` default. Arms the gate at `1`
    /// — a bound the compiled default (3) would never produce — and
    /// proves the refusal fires at exactly `bound + 1`, one release
    /// earlier than every other test in this file exercises.
    #[test]
    fn suppressed_confirm_gate_armed_at_a_configured_bound_fires_at_bound_plus_one() {
        let (pk, _sec) = crate::crypto::test_support::gen_x25519();
        let mut nonce = [1u8; 32];
        let mut rd = [0u8; 64];
        rd[0..32].copy_from_slice(&nonce);
        rd[32..64].copy_from_slice(&pk);
        let chip = [0u8; 64];
        let plat = hex::encode(chip);
        let ud = b"USERDATA-custom-bound";
        let (cose, l1, kid) = cose_for(&plat, 5, ud);

        let kr = Kr(kid, l1.verifying_key());
        let al = AllowAll;
        let lp = LaunchPolicy {
            min_tcb: 1,
            required_bits: 0b10,
            allowed_mask: 0b1101,
        };
        let st = OneState(VmState::Active {
            gen: 5,
            host: plat.clone(),
            lease_id: "lease-1".into(),
        });
        let rs = InMemoryReleaseStore::default();
        let ok: fn(&[u8; 48]) -> bool = |_m| true;
        let va = ChallengeVaultAuth {
            kbs_measurement_ok: ok,
            policy: LaunchPolicy {
                min_tcb: 1,
                required_bits: 0,
                allowed_mask: u64::MAX,
            },
            challenge_ttl: 60,
            cap_ttl: 60,
            challenge_nonce: [2u8; 32],
        };
        let mut kvm = HashMap::new();
        kvm.insert("kbs/vm/abc/luks".to_string(), b"LUKSKEY".to_vec());
        kvm.insert("kbs/vm/abc/ud".to_string(), ud.to_vec());
        let kv = Kv(kvm);
        let kbs_rep = VerifiedReport {
            measurement: MEAS,
            report_data: [0u8; 64],
            tcb: 5,
            policy: 0,
            chip_id: [0u8; 64],
            chain_pem: Vec::new(),
        };
        let kbs_sk = SigningKey::from_bytes(&[9u8; 32]);
        let audit = Audit::default();
        let evidence = crate::evidence::MockEvidenceSink::new();
        let boot_counter = crate::boot_counter::InMemoryBootCounterStore::default();
        let volume_stamp = crate::volume_stamp::InMemoryVolumeStampStore::default();
        let raw_snp_report = vec![0u8; 1184];
        const CUSTOM_BOUND: u64 = 1;
        assert_ne!(
            CUSTOM_BOUND,
            crate::volume_stamp::MAX_UNCONFIRMED_RELEASES,
            "the bound under test must differ from the compiled default, or this test cannot \
             distinguish 'reads Deps' from 'ignores Deps and uses the const'"
        );

        // Release 1: within the custom bound (unconfirmed goes 0 → 1),
        // granted.
        nonce[0] = 1;
        rd[0..32].copy_from_slice(&nonce);
        let av1 = Av { rd, chip };
        let nonce_store1 = MockNonceStore::default();
        nonce_store1.preissue(nonce);
        let deps1 = Deps {
            l1_keyring: &kr,
            attn: &av1,
            offline_allowlist: &al,
            launch_policy: &lp,
            vm_states: &st,
            release_store: &rs,
            vault_auth: &va,
            vault_kv: &kv,
            kbs_nonce_store: &nonce_store1,
            kbs_attestation: &kbs_rep,
            kbs_auth_pubkey: b"kbs-channel-pub",
            kbs_signing_key: &kbs_sk,
            kbs_kid: b"kbs-kid",
            audit: &audit,
            evidence: &evidence,
            boot_counter: &boot_counter,
            volume_stamp: &volume_stamp,
            max_unconfirmed_releases: Some(CUSTOM_BOUND),
            require_wrapped_kek: false,
        };
        let req1 = ReleaseRequest {
            cose_ticket: &cose,
            raw_snp_report: &raw_snp_report,
            kbs_nonce: &nonce,
            now_unix: 100,
            submitted_boot_counter: None,
        };
        process_release(&req1, &deps1).expect("release 1 (unconfirmed=1) is within bound=1");

        // Release 2: unconfirmed goes 1 → 2, which EXCEEDS bound=1 — the
        // compiled default (3) would have granted this one too, so a
        // refusal here can only come from the configured bound.
        nonce[0] = 2;
        rd[0..32].copy_from_slice(&nonce);
        let av2 = Av { rd, chip };
        let nonce_store2 = MockNonceStore::default();
        nonce_store2.preissue(nonce);
        let deps2 = Deps {
            l1_keyring: &kr,
            attn: &av2,
            offline_allowlist: &al,
            launch_policy: &lp,
            vm_states: &st,
            release_store: &rs,
            vault_auth: &va,
            vault_kv: &kv,
            kbs_nonce_store: &nonce_store2,
            kbs_attestation: &kbs_rep,
            kbs_auth_pubkey: b"kbs-channel-pub",
            kbs_signing_key: &kbs_sk,
            kbs_kid: b"kbs-kid",
            audit: &audit,
            evidence: &evidence,
            boot_counter: &boot_counter,
            volume_stamp: &volume_stamp,
            max_unconfirmed_releases: Some(CUSTOM_BOUND),
            require_wrapped_kek: false,
        };
        let req2 = ReleaseRequest {
            cose_ticket: &cose,
            raw_snp_report: &raw_snp_report,
            kbs_nonce: &nonce,
            now_unix: 101,
            submitted_boot_counter: None,
        };
        assert!(
            process_release(&req2, &deps2).is_err(),
            "release 2 (unconfirmed=2) must be refused under bound=1"
        );
        let last_reason = audit.0.lock().unwrap().last().cloned();
        assert!(
            matches!(last_reason, Some((false, ref m)) if m.contains("volume-stamp-confirm-suppressed")),
            "must be refused by the CONFIGURED-bound gate specifically: {last_reason:?}"
        );
    }

    /// H8 focused: a genuinely-fresh vm_id (never committed a counter)
    /// may still release with `submitted_boot_counter: None` — the guard
    /// only arms after a prior `Some` commit, so pre-Phase-2A guests are
    /// unaffected. (The refusal side is covered by
    /// `submitted_boot_counter_gates_release_and_advances_store`.)
    #[test]
    fn none_boot_counter_allowed_only_while_store_is_fresh() {
        let (pk, sec) = crate::crypto::test_support::gen_x25519();
        let nonce = [1u8; 32];
        let mut rd = [0u8; 64];
        rd[0..32].copy_from_slice(&nonce);
        rd[32..64].copy_from_slice(&pk);
        let _ = sec;
        let chip = [0u8; 64];
        let plat = hex::encode(chip);
        let ud = b"USERDATA";
        let (cose, l1, kid) = cose_for(&plat, 5, ud);

        let kr = Kr(kid, l1.verifying_key());
        let av = Av { rd, chip };
        let al = AllowAll;
        let lp = LaunchPolicy {
            min_tcb: 1,
            required_bits: 0b10,
            allowed_mask: 0b1101,
        };
        let st = OneState(VmState::Active {
            gen: 5,
            host: plat.clone(),
            lease_id: "lease-1".into(),
        });
        let rs = InMemoryReleaseStore::default();
        let ok: fn(&[u8; 48]) -> bool = |_m| true;
        let va = ChallengeVaultAuth {
            kbs_measurement_ok: ok,
            policy: LaunchPolicy {
                min_tcb: 1,
                required_bits: 0,
                allowed_mask: u64::MAX,
            },
            challenge_ttl: 60,
            cap_ttl: 60,
            challenge_nonce: [2u8; 32],
        };
        let mut kvm = HashMap::new();
        kvm.insert("kbs/vm/abc/luks".to_string(), b"LUKSKEY".to_vec());
        kvm.insert("kbs/vm/abc/ud".to_string(), ud.to_vec());
        let kv = Kv(kvm);
        let kbs_rep = VerifiedReport {
            measurement: MEAS,
            report_data: [0u8; 64],
            tcb: 5,
            policy: 0,
            chip_id: [0u8; 64],
            chain_pem: Vec::new(),
        };
        let kbs_sk = SigningKey::from_bytes(&[9u8; 32]);
        let audit = Audit::default();
        let evidence = crate::evidence::MockEvidenceSink::new();
        let nonce_store = MockNonceStore::default();
        nonce_store.preissue(nonce);
        let boot_counter = crate::boot_counter::InMemoryBootCounterStore::default();
        let volume_stamp = crate::volume_stamp::InMemoryVolumeStampStore::default();
        let deps = Deps {
            l1_keyring: &kr,
            attn: &av,
            offline_allowlist: &al,
            launch_policy: &lp,
            vm_states: &st,
            release_store: &rs,
            vault_auth: &va,
            vault_kv: &kv,
            kbs_nonce_store: &nonce_store,
            kbs_attestation: &kbs_rep,
            kbs_auth_pubkey: b"kbs-channel-pub",
            kbs_signing_key: &kbs_sk,
            kbs_kid: b"kbs-kid",
            audit: &audit,
            evidence: &evidence,
            boot_counter: &boot_counter,
            volume_stamp: &volume_stamp,
            max_unconfirmed_releases: Some(crate::volume_stamp::MAX_UNCONFIRMED_RELEASES),
            require_wrapped_kek: false,
        };
        let raw_snp_report = vec![0u8; 1184];
        let req = ReleaseRequest {
            cose_ticket: &cose,
            raw_snp_report: &raw_snp_report,
            kbs_nonce: &nonce,
            now_unix: 200,
            submitted_boot_counter: None,
        };
        // Fresh store (get == 0) ⇒ None is allowed, release succeeds,
        // and the store is NOT advanced (a None boot never commits).
        assert_eq!(boot_counter.get("abc").unwrap(), 0);
        process_release(&req, &deps).expect("fresh None release must succeed");
        assert_eq!(
            boot_counter.get("abc").unwrap(),
            0,
            "a None release must not advance the counter"
        );
    }

    #[test]
    fn platform_mismatch_denied() {
        let (pk, _sec) = crate::crypto::test_support::gen_x25519();
        let nonce = [1u8; 32];
        let mut rd = [0u8; 64];
        rd[0..32].copy_from_slice(&nonce);
        rd[32..64].copy_from_slice(&pk);
        // ticket says platform "deadbeef", attested chip differs
        let (cose, l1, kid) = cose_for("deadbeef", 5, b"UD");
        let mut chip = [0u8; 64];
        chip[0] = 0x11;
        let kr = Kr(kid, l1.verifying_key());
        let av = Av { rd, chip };
        let al = AllowAll;
        let lp = LaunchPolicy {
            min_tcb: 1,
            required_bits: 0b10,
            allowed_mask: 0b1101,
        };
        let st = OneState(VmState::Active {
            gen: 5,
            host: "deadbeef".into(),
            lease_id: "lease-1".into(),
        });
        let rs = InMemoryReleaseStore::default();
        let ok: fn(&[u8; 48]) -> bool = |_m| true;
        let va = ChallengeVaultAuth {
            kbs_measurement_ok: ok,
            policy: LaunchPolicy {
                min_tcb: 1,
                required_bits: 0,
                allowed_mask: u64::MAX,
            },
            challenge_ttl: 60,
            cap_ttl: 60,
            challenge_nonce: [2u8; 32],
        };
        let kv = Kv(HashMap::new());
        let kbs_rep = VerifiedReport {
            measurement: MEAS,
            report_data: [0u8; 64],
            tcb: 5,
            policy: 0,
            chip_id: [0u8; 64],
            chain_pem: Vec::new(),
        };
        let kbs_sk = SigningKey::from_bytes(&[9u8; 32]);
        let audit = Audit::default();
        let evidence = crate::evidence::MockEvidenceSink::new();
        let nonce_store = MockNonceStore::default();
        nonce_store.preissue(nonce);
        let boot_counter = crate::boot_counter::InMemoryBootCounterStore::default();
        let volume_stamp = crate::volume_stamp::InMemoryVolumeStampStore::default();
        let deps = Deps {
            l1_keyring: &kr,
            attn: &av,
            offline_allowlist: &al,
            launch_policy: &lp,
            vm_states: &st,
            release_store: &rs,
            vault_auth: &va,
            vault_kv: &kv,
            kbs_nonce_store: &nonce_store,
            kbs_attestation: &kbs_rep,
            kbs_auth_pubkey: b"k",
            kbs_signing_key: &kbs_sk,
            kbs_kid: b"kbs-kid",
            audit: &audit,
            evidence: &evidence,
            boot_counter: &boot_counter,
            volume_stamp: &volume_stamp,
            max_unconfirmed_releases: Some(crate::volume_stamp::MAX_UNCONFIRMED_RELEASES),
            require_wrapped_kek: false,
        };
        let req = ReleaseRequest {
            cose_ticket: &cose,
            raw_snp_report: b"raw",
            kbs_nonce: &nonce,
            now_unix: 200,
            submitted_boot_counter: None,
        };
        assert!(process_release(&req, &deps).is_err());
    }
}
