//! End-to-end release transaction (ARCHITECTURE.md §7/§21).
//!
//! Order (any failure ⇒ signed denial + audit, no commit, no secret emit):
//! - verify OrderTicket: sig, canonical CBOR+header, schema, expiry (§6).
//! - verify SNP report (trait): measurement/TCB/policy/REPORT_DATA (§7).
//! - attested CHIP_ID == ticket.platform_id (§8/§23).
//! - KBS signing kid in accepted_kbs_kids(measurement) (§6).
//! - lifecycle check_releasable (attested node) BEFORE Vault read (§24).
//! - ticket key_mode == the mode pinned at register (customer-held keys).
//!   M1 (`split`) changes nothing below; M2 (`customer`) skips the KEK read
//!   and Transit decrypt, releases no `luks`, and neither notes nor mints
//!   a KBS volume stamp. Every gate is identical in all three modes.
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
use crate::lifecycle::{check_key_mode, check_releasable, VmStateStore};
use crate::persist::KbsNonceStore;
use crate::replay::{ReleaseKey, ReleaseStore};
use crate::report_data::{ct_eq, tenant};
use crate::snp::{
    check_attestation, AttestationVerifier, LaunchPolicy, MeasurementAllowlist, VerifiedReport,
};
use crate::ticket::{verify_order_ticket, L1Keyring, OrderTicket};
use crate::vault::{AttestedVaultAuth, KbsAuthEvidence, VaultCapability, VaultKv, VaultScope};
use ed25519_dalek::{Signer, SigningKey};
use hippius_types::evidence_bundle::{
    EvidenceBundle, SignedEvidenceBundle, EVIDENCE_BUNDLE_SCHEMA_VERSION,
};
use hippius_types::guardian::KeyMode;
use hippius_types::release::RELEASE_DOMAIN_V2;
use zeroize::Zeroizing;

// The pinned `allowed_userdata_digest` preimage is canonical in
// `hippius_types::digest` so L1 and the KBS compute it byte-identically.
use hippius_types::digest::userdata_digest;

/// §7: the KV version the per-VM lifecycle SIGNING key is read at. vali
/// stages it as the FIRST write to a fresh per-VM path, so it is always
/// version 1. Pinned (not "latest") per §19 exact `path@version`.
pub(crate) const LIFECYCLE_KEY_VERSION: u64 = 1;

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
pub(crate) fn derive_lifecycle_path(luks_path: &str) -> Option<String> {
    let suffix = format!("/{LUKS_KEK_SEGMENT}");
    luks_path
        .strip_suffix(&suffix)
        .map(|prefix| format!("{prefix}/{LIFECYCLE_KEY_SEGMENT}"))
}

/// Whether the KBS releases a disk KEK for a VM in `mode`.
///
/// `hippius` (M0): the KEK. `split` (M1): the same Vault-staged
/// `luks-kek`, which the guest now reads as the Hippius share `share_H` —
/// the release path does not change at all. `customer` (M2): nothing; the
/// KBS holds no key material for that VM, so there is no KEK to read,
/// no Transit decrypt to run, and no `luks` secret in the response.
fn releases_kek(mode: KeyMode) -> bool {
    match mode {
        KeyMode::Hippius | KeyMode::Split => true,
        KeyMode::Customer => false,
    }
}

use crate::volume_stamp::kbs_owns_volume_stamp;

/// The guest volume-stamp protocol this ATTESTED release reports, read
/// from the ONE place a miner cannot touch: the SNP-signed `REPORT_DATA`.
///
/// - `REPORT_DATA[0..32] == kbs_nonce` — the §20 layout every guest used
///   before stamp protocol v2 ([`hippius_types::report_data::tenant`]) ⇒
///   [`crate::volume_stamp::GUEST_STAMP_PROTOCOL_V1`];
/// - `REPORT_DATA[0..32] == SHA-256(TENANT_RELEASE_STAMP_V2_REPORT_DOMAIN ‖
///   kbs_nonce)` ([`hippius_types::report_data::tenant_stamp_v2`]) ⇒
///   [`crate::volume_stamp::GUEST_STAMP_PROTOCOL_V2`];
/// - anything else ⇒ `None`: the nonce is not bound at all (denied).
///
/// `REPORT_DATA` is inside the PSP's signature over the report, so the
/// miner — which relays every other byte of the request — can neither
/// add the v2 claim to an older guest's release nor strip it from a v2
/// guest's. Nothing else feeds this: no request field, no header. `[32..64]`
/// is the guest's HPKE key in both layouts. Gate 5a'' records the value,
/// `authorize-rollback` reads that record, and gate 5b requires it AGAIN
/// on the release an arm would admit (the arm was granted on an earlier
/// boot's record; the guest booting the restored disk is whatever the
/// miner launched now).
fn attested_guest_stamp_protocol(req: &ReleaseRequest, report: &VerifiedReport) -> Option<u8> {
    let bound = &report.report_data[0..32];
    if ct_eq(bound, req.kbs_nonce) {
        return Some(crate::volume_stamp::GUEST_STAMP_PROTOCOL_V1);
    }
    let v2 = hippius_types::report_data::tenant_stamp_v2_nonce_binding(req.kbs_nonce);
    if ct_eq(bound, &v2) {
        return Some(crate::volume_stamp::GUEST_STAMP_PROTOCOL_V2);
    }
    None
}

/// A fresh random timeline for the one release an authorized rollback
/// admits, and for a v2 release at `E == 0` (gate 5c'): never zero, never the VM's current timeline, never the restored
/// point's. 32 random bytes are never drawn twice in practice, and the KBS
/// never re-issues a timeline it moved a VM off (a revert goes BACK to the
/// replaced one, never forward to this one again).
fn fresh_timeline(avoid: &[[u8; 32]]) -> Result<[u8; 32]> {
    use rand::RngCore;
    for _ in 0..8 {
        let mut t = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut t);
        if t != crate::volume_stamp::ZERO_TIMELINE && !avoid.contains(&t) {
            return Ok(t);
        }
    }
    Err(KbsError::Crypto(
        "volume-stamp: could not draw a fresh timeline".into(),
    ))
}

/// The release-audit `reason` of a GRANTED release. `released` for M0 —
/// byte-identical to every record written before customer-held keys (the
/// audit schema is a fixed 8-key map, `sentinel/tools/kbs_audit.py`) —
/// and the mode appended otherwise, so the chain says which releases
/// carried no KEK (M2) or only the Hippius share (M1).
fn granted_audit_reason(mode: KeyMode) -> &'static str {
    match mode {
        KeyMode::Hippius => "released",
        KeyMode::Split => "released key_mode=split",
        KeyMode::Customer => "released key_mode=customer",
    }
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
    /// Phase 1 of audit follow-up Review #2 (LUKS + dm-integrity is not
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
    /// Phase 1 of audit follow-up Review #2 — per-`vm_id` monotonic
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
    /// The userdata counterpart of [`Deps::require_wrapped_kek`]: `true` ⇒
    /// the release REFUSES a userdata that is not Vault-Transit-wrapped at
    /// rest. Default `false` — legacy VMs staged their cloud-init in
    /// plaintext and must keep booting; flip it on once none of them can.
    ///
    /// Worth having as a gate rather than as a convention: the digest
    /// proves the bytes are the ones the ticket named, never that they are
    /// ciphertext, so nothing else in the system would notice a staging
    /// path that quietly went back to plaintext.
    pub require_wrapped_userdata: bool,
    /// Hash-chained ADMIN audit log (`crate::admin_audit`), where the
    /// authorized-rollback events the release path owns land: a
    /// `rollback-consume`, a `rollback-refused(<reason>)` for an arm that
    /// did not admit a release, a `rollback-cleared-by-boot` when a
    /// normal boot cleared a pending arm, a `rollback-commit-failed`.
    /// One row is MANDATORY: the `rollback-consume-intent` written before
    /// an arm-admitted release spends or commits anything — if it cannot
    /// be written (or this is `None`), that release is REFUSED. Every
    /// other row is best-effort: it follows a decision already taken, and
    /// a write failure is reported on stderr, never turned into a grant
    /// or a denial. `None` ⇒ no admin listener, so no arm can exist and
    /// nothing is recorded.
    pub rollback_audit: Option<&'a crate::admin_audit::FileAdminAuditSink>,
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
/// Transit-unwrap a secret staged at rest, if it is wrapped.
///
/// Vault Transit ciphertext is the string `vault:v<n>:…`, so the prefix is
/// an unambiguous discriminator: a plaintext secret that happened to start
/// with those bytes would have to be chosen by whoever staged it, and
/// whoever staged it is the party the wrapping protects against reading it
/// back — they gain nothing by confusing themselves.
///
/// Both the disk KEK and the cloud-init userdata go through here, under the
/// SAME per-VM Transit key (`kek-<vm_id>`). One key rather than two because
/// the capability token's decrypt grant is already scoped to exactly this
/// VM's key — so no new Vault policy — and because §24's crypto-erase
/// destroys that key, which then makes BOTH the disk and the userdata
/// unreadable. The userdata previously outlived the VM it belonged to: the
/// erase path never deleted its KV entry, version history included.
pub(crate) fn transit_unwrap_if_wrapped(
    vault_kv: &dyn VaultKv,
    cap: &VaultCapability,
    vm_id: &str,
    value: Zeroizing<Vec<u8>>,
) -> Result<Zeroizing<Vec<u8>>> {
    if !value.starts_with(b"vault:") {
        return Ok(value);
    }
    let transit_key = format!("kek-{vm_id}");
    vault_kv.transit_decrypt(cap, &transit_key, &value)
}

/// §6 gate — the ticket's `allowed_userdata_digest` must match the userdata
/// this release is about to hand the guest.
///
/// Computed over the PLAINTEXT, after the unwrap. That ordering is the
/// whole gate: hash the stored `vault:v1:…` bytes instead and every launch
/// denies. It is also not a two-party contract — the GUEST re-derives this
/// same digest over the plaintext it receives and refuses the release on a
/// mismatch (`hippius_guest::release`, baked into every tenant image), so
/// the preimage cannot be changed on this side alone.
fn verify_userdata_digest(
    ticket: &OrderTicket,
    scope: &VaultScope,
    plaintext: &[u8],
) -> Result<()> {
    let recomputed = userdata_digest(
        &ticket.tenant_id,
        &ticket.vm_id,
        &ticket.ticket_id,
        "userdata",
        &scope.userdata_path,
        scope.userdata_version,
        plaintext,
    );
    // `ct_eq` is `subtle::ConstantTimeEq` under the hood
    // (`hippius_types::report_data::ct_eq`) — the comparison must not leak,
    // through timing, HOW MUCH of a candidate digest an attacker got right,
    // which is what would turn a mismatch into an oracle for forging one.
    // A test cannot pin constant-time-ness; the only defence is that this
    // call site never degrades to `==`.
    if !ct_eq(&recomputed, ticket.allowed_userdata_digest()) {
        return Err(KbsError::DigestMismatch);
    }
    Ok(())
}

pub fn process_release(
    req: &ReleaseRequest,
    deps: &Deps,
) -> core::result::Result<SignedResponse, SignedDenial> {
    // We capture ids for audit/denial even on early failure.
    let mut tid: Option<String> = None;
    let mut vid: Option<String> = None;
    let r = run(req, deps, &mut tid, &mut vid);
    match r {
        Ok((signed, key_mode)) => {
            deps.audit.record(
                true,
                tid.as_deref(),
                vid.as_deref(),
                granted_audit_reason(key_mode),
            );
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
) -> Result<(SignedResponse, KeyMode)> {
    // 0. §22 pre-release allowlist revalidation (the artifact backing
    // every measurement/L1-kid/KBS-kid decision MUST be re-verified
    // before each release; fail-closed).
    deps.offline_allowlist.pre_release_validate()?;

    // 1. ticket
    let (ticket, ticket_kid) = verify_order_ticket(req.cose_ticket, deps.l1_keyring, req.now_unix)?;
    *tid = Some(ticket.ticket_id.clone());
    *vid = Some(ticket.vm_id.clone());
    // Customer-held keys: the signed mode (absent ⇒ `hippius`). It only
    // ever REMOVES work from this path (M2: no KEK, no KBS stamp); every
    // gate below runs identically in all three modes.
    let key_mode = ticket.key_mode();

    // 2. attestation. The nonce binding in `REPORT_DATA[0..32]` also says
    // which stamp protocol the guest speaks — see
    // `attested_guest_stamp_protocol`: the claim is PSP-signed.
    let report = deps.attn.verify(req.raw_snp_report)?;
    let guest_stamp_protocol = attested_guest_stamp_protocol(req, &report)
        .ok_or_else(|| KbsError::Attestation("KBS nonce not bound in REPORT_DATA".into()))?;
    let speaks_stamp_v2 = guest_stamp_protocol >= crate::volume_stamp::GUEST_STAMP_PROTOCOL_V2;
    let mut guest_pub = [0u8; 32];
    guest_pub.copy_from_slice(&report.report_data[32..64]);
    let expected_rd = if speaks_stamp_v2 {
        hippius_types::report_data::tenant_stamp_v2(req.kbs_nonce, &guest_pub)
    } else {
        tenant(req.kbs_nonce, &guest_pub)
    };
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
    // 5a. The ticket's key mode must be the one pinned at register. The
    // pin cannot change once set (register refuses a mode change), so one
    // check before any secret work is enough.
    check_key_mode(deps.vm_states.key_mode(&ticket.vm_id)?, key_mode)?;

    // 5a''. The ticket's launch must be the VM's CURRENT one: a ticket of a
    // launch a later one replaced (the pre-resize ticket, still within its
    // 24 h) is refused even though its measurement may still be allowlisted
    // (`lifecycle::check_current_launch`). A newer launch's first release
    // makes it current — the path of a §25-moved VM's relaunch, which no
    // register precedes.
    deps.vm_states
        .admit_launch(&ticket.vm_id, &report.measurement, ticket.issue_time)?;

    // 5a'. AUTHORIZED-ROLLBACK HOUSEKEEPING (`crate::rollback::
    // reconcile_pending`): a rollback whose stamp step was applied but
    // whose authorisation is gone without a delivered release is reverted
    // HERE, before any stamp is read. A no-op read when nothing is
    // pending — every VM that was never rolled back.
    crate::rollback::reconcile_pending(
        &ticket.vm_id,
        deps.boot_counter,
        deps.volume_stamp,
        deps.rollback_audit,
        req.now_unix,
    )?;

    // 5a-t. A VM an authorized rollback moved to a non-zero TIMELINE only
    // releases to a guest that attested stamp protocol v2: a v1 guest
    // compares the stamp VALUE alone, so it would accept a disk of the
    // abandoned timeline carrying the same number — exactly what the
    // timeline exists to refuse (blocker B1). A VM never rolled back is on
    // the zero timeline and a v1 guest takes the path below byte for byte.
    // It also refuses a v1 attestation of such a VM however a miner
    // provokes one (an R6 guest never downgrades by itself: a denied v2
    // release is final).
    let owns_stamp = kbs_owns_volume_stamp(key_mode);
    if owns_stamp && !speaks_stamp_v2 {
        let timeline = deps.volume_stamp.timeline(&ticket.vm_id)?;
        if timeline != crate::volume_stamp::ZERO_TIMELINE {
            return Err(KbsError::Policy(format!(
                "volume-stamp-timeline-requires-v2: vm_id={} was rolled back to timeline {} and \
                 this guest did not attest stamp protocol v2 — refusing a release it could not \
                 bind to that timeline",
                ticket.vm_id,
                hex::encode(timeline)
            )));
        }
    }

    // 5a''. Record the guest stamp protocol this attested release reports
    // (`attested_guest_stamp_protocol`): `authorize-rollback` arms only a
    // VM whose guest speaks a timeline-bound stamp. Latest release wins,
    // in both directions. A write only happens when the value changes,
    // and a failed write refuses the release: a stale record must never
    // keep a VM armable after its guest went back to v1. AFTER 5a-t, so a
    // v1 attempt refused there (e.g. one a miner provoked with a forged
    // 403 to the v2 attempt) does not demote the record of a VM on a
    // rolled-back timeline. (Residual: a v1 attempt that passed 5a-t just
    // before a concurrent rollback committed can still demote it; the
    // restored guest's next v2 release records v2 again. Availability of
    // the NEXT rollback only — never a key.)
    deps.volume_stamp
        .record_guest_stamp_protocol(&ticket.vm_id, guest_stamp_protocol)?;

    // 5b. boot-counter CAS (audit follow-up Review #2 — anti-rollback
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
    // `Some(arm)` ⇒ this release was admitted by an authorized-rollback
    // arm (see the rewind branch below). Everything the arm changes —
    // the stamp echoed, the token epoch, the commit — keys off it.
    let mut rollback_admitted: Option<crate::rollback::RollbackArm> = None;
    // The timeline of the restored point (from its signed V2 checkpoint,
    // recorded at arm time): the `expected` timeline of the one release
    // the arm admits.
    let mut rollback_from_timeline: Option<[u8; 32]> = None;
    // Every release-path rollback audit row names the release it is about:
    // the ticket and the ATTESTED chip.
    let rb_where = || {
        format!(
            "ticket_id={} attested_chip={attested_node}",
            ticket.ticket_id
        )
    };
    let committed_boot_counter = match req.submitted_boot_counter {
        Some(submitted) => match deps.boot_counter.check_only(&ticket.vm_id, submitted) {
            Ok(v) => v,
            Err(refusal) => {
                // AUTHORIZED ROLLBACK (`crate::rollback`). Consulted
                // ONLY when the strict CAS refused a REWIND
                // (`submitted <= stored`) AND an arm exists for this VM,
                // so a VM with no arm takes exactly the path below, byte
                // for byte. The arm admits iff it is unexpired, the
                // ticket generation is `arm.new_gen`, the ATTESTED chip
                // is `arm.dest`, and `submitted == arm.from_counter + 1`
                // — every one of those is either attested or bound at
                // arm time by vali's mTLS-authenticated call, never
                // chosen by the miner. What it commits is still
                // `stored + 1`: the counter never moves down.
                let stored = deps.boot_counter.get(&ticket.vm_id)?;
                let arm = if submitted <= stored {
                    deps.boot_counter.rollback_state(&ticket.vm_id)?.0
                } else {
                    None
                };
                let admitted = match arm {
                    // M2: the guardian owns the stamp, so an arm has no
                    // stamp to restore. And the guest booting NOW must
                    // itself speak a timeline-bound stamp: the arm was
                    // granted on an earlier boot's record, the miner
                    // chose this launch. Either ⇒ never admitted.
                    Some(arm) => match if !kbs_owns_volume_stamp(key_mode) {
                        Err("kbs-does-not-own-stamp")
                    } else if !crate::volume_stamp::guest_stamp_protocol_is_rollback_capable(
                        guest_stamp_protocol,
                    ) {
                        Err("guest-not-rollback-capable")
                    } else {
                        crate::rollback::arm_admits(
                            &arm,
                            ticket.vm_generation,
                            &attested_node,
                            submitted,
                            stored,
                            req.now_unix,
                        )
                        .and_then(|()| {
                            // No recorded checkpoint timeline ⇒ nothing to
                            // bind the restored disk to: admit nothing.
                            match deps
                                .volume_stamp
                                .arm_timeline(&ticket.vm_id, &arm.restore_id)
                            {
                                Ok(Some(t)) => Ok(t),
                                Ok(None) => Err("arm-timeline-missing"),
                                Err(_) => Err("arm-timeline-unreadable"),
                            }
                        })
                    } {
                        Ok(from_timeline) => Some((arm, from_timeline)),
                        Err(why) => {
                            let reason = format!("rollback-refused({why}) {}", rb_where());
                            crate::rollback::record_rollback_event_best_effort(
                                deps.rollback_audit,
                                &crate::rollback::RollbackAuditEvent {
                                    op: "rollback-refused",
                                    url_vm_id: &ticket.vm_id,
                                    restore_id: Some(&arm.restore_id),
                                    applied: false,
                                    status_code: 403,
                                    reason: &reason,
                                    peer_san: None,
                                    peer_serial: None,
                                    body_sha256: crate::rollback::arm_checkpoint_sha(&arm),
                                },
                                req.now_unix,
                            );
                            None
                        }
                    },
                    None => None,
                };
                if let Some((arm, from_timeline)) = admitted {
                    let committed = stored
                        .checked_add(1)
                        .ok_or_else(|| KbsError::Policy("boot-counter overflow".into()))?;
                    rollback_admitted = Some(arm);
                    rollback_from_timeline = Some(from_timeline);
                    committed
                } else {
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

    // 5b'. A rollback still pending after reconciliation (its arm is live,
    // or its release is in flight) makes the stamp PROVISIONAL: only the
    // release that same arm admits may proceed. Anything else is refused
    // before it reads the stamp — a normal boot must never be handed a
    // provisionally lowered expectation. Reachable only inside a failed
    // or in-flight rollback's window.
    if let Some(p) = deps.volume_stamp.pending_rollback(&ticket.vm_id)? {
        let same = rollback_admitted
            .as_ref()
            .is_some_and(|a| a.restore_id == p.restore_id);
        if !same {
            return Err(KbsError::Policy(format!(
                "volume-stamp-rollback-pending: vm_id={} has an authorized rollback ({}) in \
                 progress — refusing any other release until it is delivered or reverted",
                ticket.vm_id, p.restore_id
            )));
        }
    }

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
    //
    // M2 (`customer`): skipped entirely — no note, no count, no bound. The
    // guardian owns that VM's stamp, so its guest never confirms to the
    // KBS; counting its releases here would lock it out after `bound`
    // boots. `expected_volume_stamp = 0` and no token (below) is what the
    // response then carries. (An authorized rollback never reaches here
    // for M2: the arm path refuses a VM whose stamp the KBS does not own.)
    //
    // AUTHORIZED ROLLBACK: the arm path neither counts nor bounds. The
    // unconfirmed count belongs to the timeline being abandoned (a VM
    // that "won't come up" is exactly one that piled up unconfirmed
    // releases), the commit resets it to 0, and the expectation echoed is
    // the checkpoint's `E_T`, not the live row. The confirm token is
    // minted under the NEXT token epoch, which the commit installs — so
    // every token of the abandoned timeline is dead from then on.
    //
    // STAMP PROTOCOL v2 (`volume_stamp_transition`): a normal release of a
    // v2 guest expects AND targets the VM's current timeline (at `E == 0`
    // gate 5c' below replaces that with zero → a FRESH one); the rollback
    // release expects the restored point's timeline and targets a FRESH
    // one, which its commit installs. A v1 guest gets no transition at all
    // — its response is the one it always got.
    let (
        expected_volume_stamp,
        unconfirmed_releases,
        token_epoch,
        mut read_timeline,
        mut transition,
    ) = match (&rollback_admitted, owns_stamp) {
        (_, false) => (0, 0, 0, crate::volume_stamp::ZERO_TIMELINE, None),
        (Some(arm), true) => {
            let next_epoch = deps
                .volume_stamp
                .token_epoch(&ticket.vm_id)?
                .checked_add(1)
                .ok_or_else(|| KbsError::Policy("volume-stamp token epoch overflow".into()))?;
            let current = deps.volume_stamp.timeline(&ticket.vm_id)?;
            let from = rollback_from_timeline.ok_or_else(|| {
                KbsError::Policy("rollback admitted without a timeline — fail closed".into())
            })?;
            let target = fresh_timeline(&[current, from])?;
            (arm.to_stamp, 0, next_epoch, current, Some((from, target)))
        }
        (None, true) => {
            let (e, u) = deps.volume_stamp.note_release(&ticket.vm_id)?;
            let epoch = deps.volume_stamp.token_epoch(&ticket.vm_id)?;
            let current = deps.volume_stamp.timeline(&ticket.vm_id)?;
            (
                e,
                u,
                epoch,
                current,
                speaks_stamp_v2.then_some((current, current)),
            )
        }
    };
    // The denial carries a STABLE leading classifier so an operator (and
    // the audit sink, which records `KbsError::to_string()` verbatim for
    // every refusal — see `process_release`) can tell this apart from an
    // attestation or allowlist failure at a glance.
    if let (Some(bound), None, true) = (
        deps.max_unconfirmed_releases,
        &rollback_admitted,
        owns_stamp,
    ) {
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

    // 5c'. STAMP PROTOCOL v2 at `E == 0` — a FRESH TIMELINE. After a KBS
    // restart (emptyDir wipe: every row back to `E = 0` on the zero
    // timeline) every VM would count from 1 on the zero timeline again,
    // so every zero-timeline disk — including the disks an earlier
    // authorized rollback abandoned — would become acceptable once `E`
    // caught up with it: blocker B1 reopened. So a v2 release at `E == 0`
    // moves the VM to a fresh random timeline no release ever issued; the
    // guest adopts whatever it finds at `E == 0` anyway, stamps
    // `(T_fresh, 1)` and confirms on `T_fresh`, after which every disk of
    // an earlier timeline is refused whatever its value. The transition
    // is `expected = zero` (the adopt case: nothing is expected) → target
    // `T_fresh`. The move is DURABLE before the reply; a lost response
    // costs nothing (the next release is still at `E == 0`, adopts, and
    // draws another). A v1 guest is never moved: its response stays
    // byte-identical, and gate 5a-t refuses it on any non-zero timeline.
    // M2 (`owns_stamp == false`) and the rollback release never get here.
    if owns_stamp && speaks_stamp_v2 && rollback_admitted.is_none() && expected_volume_stamp == 0 {
        let fresh = fresh_timeline(&[read_timeline])?;
        deps.volume_stamp
            .adopt_fresh_timeline(&ticket.vm_id, &fresh)?;
        read_timeline = fresh;
        transition = Some((crate::volume_stamp::ZERO_TIMELINE, fresh));
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
        // M2 (`customer`): no KEK exists for this VM — no read, no
        // `require_wrapped_kek` (there is nothing at rest to be wrapped), no
        // Transit decrypt. The scope keeps `luks_path` so the broker wire is
        // unchanged; the grant on a path that holds nothing is never used.
        let luks: Option<Zeroizing<Vec<u8>>> = if releases_kek(key_mode) {
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
            // Per-VM Transit key: the cap token's decrypt grant is scoped to
            // THIS VM's key, so it can never be a general decryption oracle for
            // another tenant's ciphertext.
            luks = transit_unwrap_if_wrapped(deps.vault_kv, &cap, &ticket.vm_id, luks)?;
            Some(luks)
        } else {
            None
        };
        // Userdata, unwrapped the same way the KEK just was.
        //
        // The KEK-HSM work wrapped the disk key so a vali/Vault-reader
        // compromise could not read it back, and left the userdata beside
        // it in plaintext — yet a tenant's cloud-init routinely carries SSH
        // keys, API tokens and enrolment secrets. This closes that
        // asymmetry.
        //
        // Same per-VM Transit key as the KEK (`kek-<vm_id>`) rather than a
        // second one: the capability token's decrypt grant is already scoped
        // to exactly this VM, so no new Vault policy — and §24's
        // `crypto_erase_kek_transit` DESTROYS that key, which now makes the
        // userdata cryptographically unreadable at decommission too. That
        // was a real hole: crypto-erase never deleted the userdata path, so
        // a destroyed VM's cloud-init outlived it indefinitely, KV version
        // history included.
        //
        let at_rest: Zeroizing<Vec<u8>> =
            deps.vault_kv
                .read_exact(&cap, &scope.userdata_path, scope.userdata_version)?;
        // The userdata counterpart of `require_wrapped_kek`, and for the
        // same reason: the digest gate proves the bytes are the ones the
        // ticket named, never that they are CIPHERTEXT. Without this, a
        // rolled-back writer, a hand-run staging script or a regression in
        // any staging path silently reinstates plaintext cloud-init at
        // rest and nothing notices. Off by default (legacy VMs staged
        // before the wrapping landed still hold plaintext); flipped on
        // once no such VM can still boot.
        if deps.require_wrapped_userdata && !at_rest.starts_with(b"vault:") {
            return Err(KbsError::Policy(
                "require_wrapped_userdata: refusing a non-Transit-wrapped (plaintext) \
                 userdata at rest"
                    .into(),
            ));
        }
        let userdata: Zeroizing<Vec<u8>> =
            transit_unwrap_if_wrapped(deps.vault_kv, &cap, &ticket.vm_id, at_rest)?;
        // A value that is STILL Transit ciphertext after one unwrap was
        // wrapped twice — the shape a mixed-version vali produces if it
        // re-wraps a blob that was already wrapped at intake. Releasing it
        // hands the guest the literal string `vault:v1:…` as its
        // cloud-config: the VM boots with no SSH key, no NetBird
        // enrolment, and nothing anywhere reports an error. Refuse
        // instead. No real cloud-init starts with `vault:` (cloud-init
        // requires `#cloud-config`, a shebang, or a MIME header).
        if userdata.starts_with(b"vault:") {
            return Err(KbsError::Policy(
                "userdata is still Transit ciphertext after unwrapping — refusing to \
                 release a double-wrapped blob as cloud-config"
                    .into(),
            ));
        }

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
                        // ONLY a not-found (Vault 404) means "no lifecycle key
                        // staged". It used to match every `KbsError::Vault(_)`,
                        // so a transport failure, a 403 or a 500 read as "pre-§7
                        // VM" and the release went ahead — handing the guest a
                        // KEK with no lifecycle signing key, i.e. silently
                        // dropping the §24/§25 guest-signed fence for the life
                        // of that VM, during exactly the incident where a Vault
                        // read fails. Everything that is not a 404 now fails
                        // closed: no lifecycle key ⇒ no release.
                        Err(KbsError::VaultNotFound(_)) => {
                            // Absent ⇒ pre-§7 VM. Log the class only
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
        verify_userdata_digest(&ticket, &scope, &userdata)?;

        // 9. lifecycle AGAIN before commit
        let state2 = deps.vm_states.get(&ticket.vm_id)?;
        check_releasable(
            &state2,
            ticket.vm_generation,
            &ticket.lease_id,
            &attested_node,
        )?;
        // …and the current launch: a later launch registered (or released)
        // while this one was reading Vault supersedes it here too.
        if let Some(current) = deps.vm_states.launch_binding(&ticket.vm_id)? {
            if current.measurement != report.measurement {
                return Err(KbsError::Lifecycle(
                    "superseded-launch: a later launch became current during this release".into(),
                ));
            }
        }

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
        let wrapped_luks = match luks.as_ref() {
            Some(kek) => Some(hpke_wrap(&guest_pub, kek, &luks_ctx)?),
            None => None,
        };
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
        //
        // M2: no token at all — the KBS stamp is off for that VM, so there
        // is nothing a confirm could advance.
        let wrapped_stamp_token = if owns_stamp {
            let stamp_target = expected_volume_stamp
                .checked_add(1)
                .ok_or_else(|| KbsError::Policy("volume-stamp overflow".into()))?;
            let stamp_mac_key =
                crate::volume_stamp::stamp_mac_key(&deps.kbs_signing_key.to_bytes());
            // v1 guest: epoch 0 (a VM never rolled back) is byte-identical
            // to the pre-epoch token; see `volume_stamp::stamp_token_epoch`.
            // v2 guest: the token is bound to the TARGET timeline too, and
            // only confirms on it (`volume_stamp::confirm_timeline`).
            let stamp_token = match &transition {
                Some((_, target)) => crate::volume_stamp::stamp_token_timeline(
                    &stamp_mac_key,
                    &ticket.vm_id,
                    stamp_target,
                    token_epoch,
                    target,
                ),
                None => crate::volume_stamp::stamp_token_epoch(
                    &stamp_mac_key,
                    &ticket.vm_id,
                    stamp_target,
                    token_epoch,
                ),
            };
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
            Some(hpke_wrap(&guest_pub, &stamp_token, &stamp_ctx)?)
        } else {
            None
        };

        // INVARIANT: the V2 domain (and the transition) ONLY for a guest
        // whose SNP-signed REPORT_DATA attested stamp protocol v2 — a v1
        // guest's response is exactly the one it always got.
        let domain = match &transition {
            Some(_) => RELEASE_DOMAIN_V2,
            None => RELEASE_DOMAIN,
        };
        let resp = KbsResponse {
            domain: domain.into(),
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
            volume_stamp_transition: transition.as_ref().map(|(expected, target)| {
                hippius_types::release::VolumeStampTransition {
                    expected_timeline_id: expected.to_vec(),
                    target_timeline_id: target.to_vec(),
                }
            }),
        };
        sign_response(deps.kbs_signing_key, &resp)
    })();

    match pre {
        Err(e) => {
            deps.release_store.rollback(&rkey);
            Err(e)
        }
        Ok(signed) => {
            // 11-. AUTHORIZED ROLLBACK consume INTENT — MANDATORY. The
            // full binding (ticket, attested chip, arm) goes into the
            // admin hash chain BEFORE anything is spent or committed, and
            // the release is refused if it cannot be written (or no admin
            // chain is wired): no rollback is ever consumed without a
            // preceding audit row, whatever happens to the outcome rows
            // after it. Mirrors `authorize-rollback-intent`.
            if let Some(arm) = &rollback_admitted {
                let detail = format!(
                    "intent to_counter={committed_boot_counter} token_epoch={token_epoch} {} {} {}",
                    timeline_detail(transition.as_ref()),
                    rb_where(),
                    crate::rollback::arm_detail(arm),
                );
                let written = match deps.rollback_audit {
                    Some(sink) => crate::rollback::record_rollback_event(
                        sink,
                        &crate::rollback::RollbackAuditEvent {
                            op: "rollback-consume-intent",
                            url_vm_id: &ticket.vm_id,
                            restore_id: Some(&arm.restore_id),
                            applied: false,
                            status_code: 0,
                            reason: &detail,
                            peer_san: None,
                            peer_serial: None,
                            body_sha256: crate::rollback::arm_checkpoint_sha(arm),
                        },
                        req.now_unix,
                    )
                    .map(|_| ()),
                    None => Err(KbsError::Policy("no admin audit chain is wired".into())),
                };
                if let Err(e) = written {
                    deps.release_store.rollback(&rkey);
                    return Err(KbsError::Policy(format!(
                        "rollback-audit-unavailable: vm_id={} restore_id={} the consume intent \
                         could not be recorded ({e}) — refusing the rollback release",
                        ticket.vm_id, arm.restore_id
                    )));
                }
            }
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

            let mut rollback_consumed: Option<crate::rollback::RollbackArm> = None;
            // 11c. Boot-counter commit — ONLY now, after the release is
            // durably committed. The guest will advance its on-disk
            // counter on receiving this 200, so the KBS persists the
            // matching advance here in lockstep. A pre-commit denial
            // (Vault/broker/nonce above) never reaches this line, so
            // the counter never runs ahead of the guest (the bug the
            // two-phase split closes). A commit error is terminal +
            // fail-closed, like the release commit above.
            //
            // AUTHORIZED ROLLBACK commit, in the documented order: (i) the
            // stamp store takes `E_T`, `unconfirmed := 0` and the new
            // token epoch; (ii) the counter commits `stored + 1` and the
            // arm is consumed — (i) runs INSIDE `commit_rollback`, under
            // the boot-counter lock, after the arm was re-validated there,
            // so a concurrent release admitted by the same arm can never
            // lower the stamp once the arm is gone. Crash between (i) and
            // (ii): see `crate::rollback` ("Crash between (i) and (ii)").
            if req.submitted_boot_counter.is_some() {
                match &rollback_admitted {
                    Some(arm) => {
                        let vm_id = ticket.vm_id.as_str();
                        let mut apply = |live: &crate::rollback::RollbackArm| -> Result<()> {
                            if live != arm {
                                return Err(KbsError::Policy(format!(
                                    "rollback-commit: vm_id={vm_id} arm changed since the \
                                     release was admitted — fail closed"
                                )));
                            }
                            // The fence the arm is bound to, re-read UNDER the
                            // counter lock: an `activate`/fence that already
                            // landed stops the rollback before the stamp moves.
                            let row = deps.vm_states.get(vm_id)?;
                            if !matches!(&row, crate::lifecycle::VmState::Migrating {
                                new_gen, dest, ..
                            } if *new_gen == live.new_gen && *dest == live.dest)
                            {
                                return Err(KbsError::Policy(format!(
                                    "rollback-commit: vm_id={vm_id} lifecycle row moved off \
                                     Migrating{{new_gen={}, dest}} — fail closed",
                                    live.new_gen
                                )));
                            }
                            let (_, target) = transition.ok_or_else(|| {
                                KbsError::Policy(
                                    "rollback-commit: no timeline transition — fail closed".into(),
                                )
                            })?;
                            deps.volume_stamp.apply_rollback(
                                vm_id,
                                live.to_stamp,
                                token_epoch,
                                &live.restore_id,
                                &target,
                            )
                        };
                        match deps.boot_counter.commit_rollback(
                            vm_id,
                            &arm.restore_id,
                            committed_boot_counter,
                            req.now_unix,
                            &mut apply,
                        ) {
                            Ok(consumed) => rollback_consumed = Some(consumed),
                            Err(e) => {
                                let reason = format!("rollback-commit-failed: {e} {}", rb_where());
                                crate::rollback::record_rollback_event_best_effort(
                                    deps.rollback_audit,
                                    &crate::rollback::RollbackAuditEvent {
                                        op: "rollback-commit-failed",
                                        url_vm_id: vm_id,
                                        restore_id: Some(&arm.restore_id),
                                        applied: false,
                                        status_code: 403,
                                        reason: &reason,
                                        peer_san: None,
                                        peer_serial: None,
                                        body_sha256: crate::rollback::arm_checkpoint_sha(arm),
                                    },
                                    req.now_unix,
                                );
                                return Err(e);
                            }
                        }
                    }
                    None => {
                        // Under the counter lock: refuse if an authorized
                        // rollback's stamp step ran since this release read
                        // the stamp (its epoch moved, or it is pending) —
                        // the token and expectation this release minted
                        // would belong to a timeline that no longer is.
                        let vm_id = ticket.vm_id.as_str();
                        let mut stamp_unchanged = || -> Result<()> {
                            // The TIMELINE too: a rollback's stamp step can
                            // land after this release passed 5b' and be
                            // reverted before this commit (its arm consume
                            // failed, then it was disarmed) — the epoch stays
                            // bumped and nothing is pending any more, but the
                            // expectation this release read belongs to the
                            // reverted timeline.
                            if deps.volume_stamp.pending_rollback(vm_id)?.is_some()
                                || deps.volume_stamp.token_epoch(vm_id)? != token_epoch
                                || (owns_stamp
                                    && deps.volume_stamp.timeline(vm_id)? != read_timeline)
                            {
                                return Err(KbsError::Policy(format!(
                                    "volume-stamp-rollback-raced: vm_id={vm_id} an authorized \
                                     rollback moved the stamp during this release — refusing"
                                )));
                            }
                            Ok(())
                        };
                        if let Some(cleared) = deps.boot_counter.commit_reporting_guarded(
                            vm_id,
                            committed_boot_counter,
                            Some(req.now_unix),
                            &mut stamp_unchanged,
                        )? {
                            let detail = format!(
                                "cleared-by-normal-boot counter={committed_boot_counter} {} {}",
                                rb_where(),
                                crate::rollback::arm_detail(&cleared)
                            );
                            crate::rollback::record_rollback_event_best_effort(
                                deps.rollback_audit,
                                &crate::rollback::RollbackAuditEvent {
                                    op: "rollback-cleared-by-boot",
                                    url_vm_id: &ticket.vm_id,
                                    restore_id: Some(&cleared.restore_id),
                                    applied: true,
                                    status_code: 200,
                                    reason: &detail,
                                    peer_san: None,
                                    peer_serial: None,
                                    body_sha256: crate::rollback::arm_checkpoint_sha(&cleared),
                                },
                                req.now_unix,
                            );
                        }
                    }
                }
            }

            // 11d. Lifecycle a THIRD time, after every commit and before
            // the secret leaves. Gate 9 read the state, then released the
            // store's lock; a §24 fence (`decommission` / `tombstone`) or a
            // §25 `activate` can commit in the gap and return 200 to its
            // caller while this release still holds a KEK read before the
            // fence. Re-checking here makes the fence's promise exact: once
            // a fence write is durable, no release that has not yet
            // returned hands out a secret. The price — a spent nonce and a
            // committed counter for a boot that gets nothing — is only ever
            // paid by a VM that was fenced or moved during its own release.
            let gate_11d = deps
                .vm_states
                .get(&ticket.vm_id)
                .and_then(|state3| {
                    check_releasable(
                        &state3,
                        ticket.vm_generation,
                        &ticket.lease_id,
                        &attested_node,
                    )
                })
                // …and the current launch the same way: a superseding
                // register that committed during this release (a resize
                // relaunch) leaves this one with nothing.
                .and_then(|()| match deps.vm_states.launch_binding(&ticket.vm_id)? {
                    Some(current) if current.measurement != report.measurement => {
                        Err(KbsError::Lifecycle(
                            "superseded-launch: a later launch became current during this release"
                                .into(),
                        ))
                    }
                    _ => Ok(()),
                });

            // 11e. AUTHORIZED ROLLBACK delivery: only now, with every gate
            // passed, is the rollback FINAL (its undo record dropped). If
            // 11d denied — a fence or `activate` landed during the commit —
            // or the finalize cannot be written, the stamp is put back
            // (compensation): a rollback that is not delivered must not
            // stay applied for whatever generation holds the VM next.
            if let Some(consumed) = &rollback_consumed {
                let vm_id = ticket.vm_id.as_str();
                let delivered = match &gate_11d {
                    Ok(()) => deps
                        .volume_stamp
                        .finalize_rollback(vm_id, &consumed.restore_id)
                        .and_then(|f| {
                            f.map(|_| ()).ok_or_else(|| {
                                KbsError::Policy(format!(
                                    "rollback-finalize: vm_id={vm_id} undo record of {} vanished \
                                     before delivery — fail closed",
                                    consumed.restore_id
                                ))
                            })
                        }),
                    Err(e) => Err(KbsError::Lifecycle(format!("{e}"))),
                };
                match delivered {
                    Ok(()) => {
                        let detail = format!(
                            "consumed from_counter={} to_counter={committed_boot_counter} \
                             stamp={} token_epoch={token_epoch} {} delivered {} {}",
                            consumed.from_counter,
                            consumed.to_stamp,
                            timeline_detail(transition.as_ref()),
                            rb_where(),
                            crate::rollback::arm_detail(consumed),
                        );
                        crate::rollback::record_rollback_event_best_effort(
                            deps.rollback_audit,
                            &crate::rollback::RollbackAuditEvent {
                                op: "rollback-consume",
                                url_vm_id: vm_id,
                                restore_id: Some(&consumed.restore_id),
                                applied: true,
                                status_code: 200,
                                reason: &detail,
                                peer_san: None,
                                peer_serial: None,
                                body_sha256: crate::rollback::arm_checkpoint_sha(consumed),
                            },
                            req.now_unix,
                        );
                    }
                    Err(e) => {
                        // Best-effort: if the revert itself fails, the undo
                        // record stays and the next reconciliation (every
                        // release of this VM runs one first) reverts it.
                        let reverted = deps
                            .volume_stamp
                            .revert_rollback(vm_id, &consumed.restore_id)
                            .map(|r| r.is_some())
                            .unwrap_or(false);
                        let reason = format!(
                            "rollback-not-delivered: {e}; stamp reverted={reverted} (arm \
                             consumed, counter committed, no key released) {}",
                            rb_where()
                        );
                        crate::rollback::record_rollback_event_best_effort(
                            deps.rollback_audit,
                            &crate::rollback::RollbackAuditEvent {
                                op: "rollback-commit-failed",
                                url_vm_id: vm_id,
                                restore_id: Some(&consumed.restore_id),
                                applied: false,
                                status_code: 403,
                                reason: &reason,
                                peer_san: None,
                                peer_serial: None,
                                body_sha256: crate::rollback::arm_checkpoint_sha(consumed),
                            },
                            req.now_unix,
                        );
                        return Err(gate_11d.err().unwrap_or(e));
                    }
                }
            }
            gate_11d?;

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

            Ok((signed, key_mode))
        }
    }
}

/// `timeline_from=<hex> timeline_to=<hex>` for the rollback audit rows.
fn timeline_detail(transition: Option<&([u8; 32], [u8; 32])>) -> String {
    match transition {
        Some((from, to)) => format!(
            "timeline_from={} timeline_to={}",
            hex::encode(from),
            hex::encode(to)
        ),
        None => "timeline=none".into(),
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
        fn key_mode(&self, _vm: &str) -> Result<KeyMode> {
            Ok(KeyMode::Hippius)
        }
    }
    /// A single VM row registered under an explicit key mode.
    struct KeyedState {
        state: VmState,
        mode: KeyMode,
        /// The VM's current launch (`lifecycle::LaunchBinding`).
        launch: Mutex<Option<crate::lifecycle::LaunchBinding>>,
        /// `(n, b)`: from the n-th `launch_binding` read on, a concurrent
        /// register has made `b` current (the race of gates 9 / 11d).
        launch_flip: Mutex<Option<(usize, crate::lifecycle::LaunchBinding)>>,
        launch_reads: Mutex<usize>,
    }
    impl VmStateStore for KeyedState {
        fn get(&self, _vm: &str) -> Result<VmState> {
            Ok(self.state.clone())
        }
        fn key_mode(&self, _vm: &str) -> Result<KeyMode> {
            Ok(self.mode)
        }
        fn launch_binding(&self, _vm: &str) -> Result<Option<crate::lifecycle::LaunchBinding>> {
            let mut reads = self.launch_reads.lock().unwrap();
            *reads += 1;
            if let Some((n, b)) = *self.launch_flip.lock().unwrap() {
                if *reads >= n {
                    return Ok(Some(b));
                }
            }
            Ok(*self.launch.lock().unwrap())
        }
        fn bind_launch(&self, _vm: &str, b: crate::lifecycle::LaunchBinding) -> Result<()> {
            *self.launch.lock().unwrap() = Some(b);
            Ok(())
        }
    }
    struct Kv(HashMap<String, Vec<u8>>);

    /// A capability shaped like the broker mints — the unwrap helper only
    /// passes it through to `transit_decrypt`, so the scope is nominal.
    fn test_cap() -> VaultCapability {
        VaultCapability::new(
            VaultScope {
                vm_id: "abc".into(),
                luks_path: "kbs/vm/abc/luks".into(),
                luks_version: 1,
                userdata_path: "kbs/vm/abc/ud".into(),
                userdata_version: 1,
                lifecycle_path: None,
                lifecycle_version: None,
            },
            u64::MAX,
            Zeroizing::new(b"cap-token".to_vec()),
        )
    }

    /// Reversible stand-in for Vault Transit: `vault:v1:<hex>` → bytes.
    /// Keyed on the transit key name so a test can prove the WRONG key is
    /// refused rather than silently returning something.
    fn test_wrap(transit_key: &str, plaintext: &[u8]) -> Vec<u8> {
        format!("vault:v1:{transit_key}:{}", hex::encode(plaintext)).into_bytes()
    }

    impl VaultKv for Kv {
        fn transit_decrypt(
            &self,
            _c: &VaultCapability,
            transit_key: &str,
            ciphertext: &[u8],
        ) -> Result<Zeroizing<Vec<u8>>> {
            let s = core::str::from_utf8(ciphertext)
                .map_err(|_| KbsError::Vault("not utf-8".into()))?;
            let rest = s
                .strip_prefix("vault:v1:")
                .ok_or_else(|| KbsError::Vault("not transit ciphertext".into()))?;
            let (key, hexed) = rest
                .split_once(':')
                .ok_or_else(|| KbsError::Vault("malformed".into()))?;
            if key != transit_key {
                return Err(KbsError::Vault("wrong transit key".into()));
            }
            Ok(Zeroizing::new(
                hex::decode(hexed).map_err(|_| KbsError::Vault("bad hex".into()))?,
            ))
        }

        fn read_exact(
            &self,
            _c: &VaultCapability,
            path: &str,
            _v: u64,
        ) -> Result<Zeroizing<Vec<u8>>> {
            // NOT-FOUND, specifically — the real client maps a Vault 404 to
            // this variant and the OPTIONAL lifecycle read is allowed to
            // proceed on it alone. A mock that returned the generic
            // `Vault(_)` here would let the release path go back to
            // swallowing transport failures without a test noticing.
            self.0
                .get(path)
                .cloned()
                .map(Zeroizing::new)
                .ok_or_else(|| KbsError::VaultNotFound("path not found".into()))
        }
    }

    /// A `Kv` that fails ONE path with a non-404 error — the Vault outage
    /// shape (transport / 403 / 500) that must never be mistaken for
    /// "nothing staged here".
    struct KvFailing {
        inner: Kv,
        fail_path: String,
    }
    impl VaultKv for KvFailing {
        fn read_exact(
            &self,
            c: &VaultCapability,
            path: &str,
            v: u64,
        ) -> Result<Zeroizing<Vec<u8>>> {
            if path == self.fail_path {
                return Err(KbsError::Vault("KV read: Vault transport error".into()));
            }
            self.inner.read_exact(c, path, v)
        }
        fn transit_decrypt(
            &self,
            c: &VaultCapability,
            transit_key: &str,
            ciphertext: &[u8],
        ) -> Result<Zeroizing<Vec<u8>>> {
            self.inner.transit_decrypt(c, transit_key, ciphertext)
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
        cose_for_keyed(plat, gen, ud, luks_path, "tk-1", None)
    }

    /// The general minter: `key_mode = None` leaves the field OFF the
    /// wire — the exact bytes every M0 minter emits.
    fn cose_for_keyed(
        plat: &str,
        gen: u64,
        ud: &[u8],
        luks_path: &str,
        ticket_id: &str,
        key_mode: Option<KeyMode>,
    ) -> (Vec<u8>, SigningKey, Vec<u8>) {
        let sk = SigningKey::from_bytes(&[42u8; 32]);
        let kid = b"l1".to_vec();
        let digest =
            userdata_digest("t", "abc", ticket_id, "userdata", "kbs/vm/abc/ud", 2, ud).to_vec();
        let mut entries = vec![
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
            (
                Value::Text("ticket_id".into()),
                Value::Text(ticket_id.into()),
            ),
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
        ];
        if let Some(mode) = key_mode {
            entries.push((
                Value::Text("key_mode".into()),
                Value::Text(mode.as_wire().into()),
            ));
        }
        let v = Value::Map(entries);
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
            require_wrapped_userdata: false,
            rollback_audit: None,
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
        let pt = crate::crypto::hpke_unwrap(&sec, resp.luks.as_ref().unwrap(), &lc).unwrap();
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
            require_wrapped_userdata: false,
            rollback_audit: None,
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
            require_wrapped_userdata: false,
            rollback_audit: None,
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
        assert_eq!(resp.luks.as_ref().unwrap().secret_type, "luks");
    }

    /// Phase 1 anti-rollback gate (audit follow-up Review #2).
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
            require_wrapped_userdata: false,
            rollback_audit: None,
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
            require_wrapped_userdata: false,
            rollback_audit: None,
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
            require_wrapped_userdata: false,
            rollback_audit: None,
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
            require_wrapped_userdata: false,
            rollback_audit: None,
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
                require_wrapped_userdata: false,
                rollback_audit: None,
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
            require_wrapped_userdata: false,
            rollback_audit: None,
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
                require_wrapped_userdata: false,
                rollback_audit: None,
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
            require_wrapped_userdata: false,
            rollback_audit: None,
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
                require_wrapped_userdata: false,
                rollback_audit: None,
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
                require_wrapped_userdata: false,
                rollback_audit: None,
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
            require_wrapped_userdata: false,
            rollback_audit: None,
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
            require_wrapped_userdata: false,
            rollback_audit: None,
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
            require_wrapped_userdata: false,
            rollback_audit: None,
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
            require_wrapped_userdata: false,
            rollback_audit: None,
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

    // ── Transit unwrap at rest (KEK + userdata) ──────────────────────

    #[test]
    fn plaintext_at_rest_passes_through_untouched() {
        // Back-compat is the load-bearing half: this must ship and be
        // DEPLOYED before vali starts wrapping, and while nothing is
        // wrapped it has to be a no-op.
        let kv = Kv(HashMap::new());
        let cap = test_cap();
        let out = transit_unwrap_if_wrapped(
            &kv,
            &cap,
            "abc",
            Zeroizing::new(b"#cloud-config\nplain".to_vec()),
        )
        .unwrap();
        assert_eq!(out.as_slice(), b"#cloud-config\nplain");
    }

    #[test]
    fn wrapped_at_rest_is_unwrapped_under_the_per_vm_key() {
        let kv = Kv(HashMap::new());
        let cap = test_cap();
        let wrapped = test_wrap("kek-abc", b"#cloud-config\nsecret");
        let out = transit_unwrap_if_wrapped(&kv, &cap, "abc", Zeroizing::new(wrapped)).unwrap();
        assert_eq!(out.as_slice(), b"#cloud-config\nsecret");
    }

    #[test]
    fn another_vms_ciphertext_is_refused() {
        // The capability token is scoped per VM, so this can never be a
        // decryption oracle for a neighbour's secret. Pin it.
        let kv = Kv(HashMap::new());
        let cap = test_cap();
        let wrapped = test_wrap("kek-someone-else", b"not yours");
        assert!(transit_unwrap_if_wrapped(&kv, &cap, "abc", Zeroizing::new(wrapped)).is_err());
    }

    #[test]
    fn the_kek_and_the_userdata_take_the_same_path() {
        // One helper, one key, so the two cannot drift — and so §24's
        // Transit destroy covers both. If someone re-splits them, this
        // test is the reminder that erasure coverage was the reason.
        let kv = Kv(HashMap::new());
        let cap = test_cap();
        let kek = test_wrap("kek-abc", b"LUKSKEY");
        let ud = test_wrap("kek-abc", b"USERDATA");
        assert_eq!(
            transit_unwrap_if_wrapped(&kv, &cap, "abc", Zeroizing::new(kek))
                .unwrap()
                .as_slice(),
            b"LUKSKEY"
        );
        assert_eq!(
            transit_unwrap_if_wrapped(&kv, &cap, "abc", Zeroizing::new(ud))
                .unwrap()
                .as_slice(),
            b"USERDATA"
        );
    }

    // ── §6 userdata digest: over the AT-REST bytes ───────────────────
    //
    // These four run the WHOLE release transaction (`process_release`),
    // not the unwrap helper: the helper-level tests could not have caught
    // a digest computed over the wrong form, which is exactly the bug that
    // shipped (`migration_ticket` digests the stored bytes, so every §25
    // migration and KBS-state recovery would have failed closed).

    /// One-call setup for a full `process_release` run. The older tests
    /// each open-code ~60 lines of this; four more variants of it is
    /// three too many.
    struct Harness {
        kr: Kr,
        av: Av,
        al: AllowAll,
        lp: LaunchPolicy,
        st: KeyedState,
        rs: InMemoryReleaseStore,
        va: ChallengeVaultAuth<fn(&[u8; 48]) -> bool>,
        max_unconfirmed_releases: Option<u64>,
        require_wrapped_kek: bool,
        kbs_rep: VerifiedReport,
        kbs_sk: SigningKey,
        audit: Audit,
        evidence: crate::evidence::MockEvidenceSink,
        nonce_store: MockNonceStore,
        boot_counter: crate::boot_counter::InMemoryBootCounterStore,
        volume_stamp: crate::volume_stamp::InMemoryVolumeStampStore,
    }

    impl Harness {
        fn new(kid: Vec<u8>, l1_vk: ed25519_dalek::VerifyingKey, rd: [u8; 64], plat: &str) -> Self {
            let ok: fn(&[u8; 48]) -> bool = |_m| true;
            let nonce_store = MockNonceStore::default();
            nonce_store.preissue([1u8; 32]);
            Self {
                kr: Kr(kid, l1_vk),
                av: Av {
                    rd,
                    chip: [0u8; 64],
                },
                al: AllowAll,
                lp: LaunchPolicy {
                    min_tcb: 1,
                    required_bits: 0b10,
                    allowed_mask: 0b1101,
                },
                st: KeyedState {
                    state: VmState::Active {
                        gen: 5,
                        host: plat.to_string(),
                        lease_id: "lease-1".into(),
                    },
                    mode: KeyMode::Hippius,
                    launch: Mutex::new(None),
                    launch_flip: Mutex::new(None),
                    launch_reads: Mutex::new(0),
                },
                rs: InMemoryReleaseStore::default(),
                max_unconfirmed_releases: Some(crate::volume_stamp::MAX_UNCONFIRMED_RELEASES),
                require_wrapped_kek: false,
                va: ChallengeVaultAuth {
                    kbs_measurement_ok: ok,
                    policy: LaunchPolicy {
                        min_tcb: 1,
                        required_bits: 0,
                        allowed_mask: u64::MAX,
                    },
                    challenge_ttl: 60,
                    cap_ttl: 60,
                    challenge_nonce: [2u8; 32],
                },
                kbs_rep: VerifiedReport {
                    measurement: MEAS,
                    report_data: [0u8; 64],
                    tcb: 5,
                    policy: 0,
                    chip_id: [0u8; 64],
                    chain_pem: Vec::new(),
                },
                kbs_sk: SigningKey::from_bytes(&[9u8; 32]),
                audit: Audit::default(),
                evidence: crate::evidence::MockEvidenceSink::new(),
                nonce_store,
                boot_counter: crate::boot_counter::InMemoryBootCounterStore::default(),
                volume_stamp: crate::volume_stamp::InMemoryVolumeStampStore::default(),
            }
        }

        /// From now on the guest's SNP report binds the nonce the stamp
        /// protocol v2 way (`report_data::tenant_stamp_v2`), same key.
        fn attest_stamp_v2(&mut self) {
            let mut pk = [0u8; 32];
            pk.copy_from_slice(&self.av.rd[32..64]);
            self.av.rd = hippius_types::report_data::tenant_stamp_v2(&[1u8; 32], &pk);
        }

        fn deps<'a>(&'a self, kv: &'a dyn VaultKv) -> Deps<'a> {
            Deps {
                l1_keyring: &self.kr,
                attn: &self.av,
                offline_allowlist: &self.al,
                launch_policy: &self.lp,
                vm_states: &self.st,
                release_store: &self.rs,
                vault_auth: &self.va,
                vault_kv: kv,
                kbs_nonce_store: &self.nonce_store,
                kbs_attestation: &self.kbs_rep,
                kbs_auth_pubkey: b"kbs-channel-pub",
                kbs_signing_key: &self.kbs_sk,
                kbs_kid: b"kbs-kid",
                audit: &self.audit,
                evidence: &self.evidence,
                boot_counter: &self.boot_counter,
                volume_stamp: &self.volume_stamp,
                max_unconfirmed_releases: self.max_unconfirmed_releases,
                require_wrapped_kek: self.require_wrapped_kek,
                require_wrapped_userdata: false,
                rollback_audit: None,
            }
        }
    }

    /// Everything the four tests below share: an attested guest keypair,
    /// the report_data that binds it, and the 1184-byte SNP report blob.
    fn guest_and_report() -> ([u8; 32], [u8; 32], [u8; 64], Vec<u8>) {
        let (pk, sec) = crate::crypto::test_support::gen_x25519();
        let mut rd = [0u8; 64];
        rd[0..32].copy_from_slice(&[1u8; 32]);
        rd[32..64].copy_from_slice(&pk);
        (pk, sec, rd, vec![0u8; 1184])
    }

    fn release_req<'a>(
        cose: &'a [u8],
        report: &'a [u8],
        nonce: &'a [u8; 32],
    ) -> ReleaseRequest<'a> {
        ReleaseRequest {
            cose_ticket: cose,
            raw_snp_report: report,
            kbs_nonce: nonce,
            now_unix: 200,
            submitted_boot_counter: None,
        }
    }

    /// One release of the harness ticket (issued at 100, measurement
    /// `MEAS`) against a VM whose current launch is `recorded`. Returns the
    /// outcome and the binding afterwards.
    fn release_against_launch(
        recorded: Option<crate::lifecycle::LaunchBinding>,
    ) -> (
        std::result::Result<(), String>,
        Option<crate::lifecycle::LaunchBinding>,
    ) {
        release_against_launch_flipping(recorded, None)
    }

    fn release_against_launch_flipping(
        recorded: Option<crate::lifecycle::LaunchBinding>,
        flip: Option<(usize, crate::lifecycle::LaunchBinding)>,
    ) -> (
        std::result::Result<(), String>,
        Option<crate::lifecycle::LaunchBinding>,
    ) {
        let (_pk, _sec, rd, report) = guest_and_report();
        let nonce = [1u8; 32];
        let plat = hex::encode([0u8; 64]);
        let plaintext = b"#cloud-config\n";
        let (cose, l1, kid) = cose_for(&plat, 5, plaintext);
        let mut kvm = HashMap::new();
        kvm.insert(
            "kbs/vm/abc/luks".to_string(),
            test_wrap("kek-abc", b"LUKSKEY"),
        );
        kvm.insert("kbs/vm/abc/ud".to_string(), test_wrap("kek-abc", plaintext));
        let kv = Kv(kvm);
        let h = Harness::new(kid, l1.verifying_key(), rd, &plat);
        *h.st.launch.lock().unwrap() = recorded;
        *h.st.launch_flip.lock().unwrap() = flip;
        let out = process_release(&release_req(&cose, &report, &nonce), &h.deps(&kv));
        let after = *h.st.launch.lock().unwrap();
        // The denial reason is what the audit sink recorded.
        let reason = h
            .audit
            .0
            .lock()
            .unwrap()
            .last()
            .map(|(_, r)| r.clone())
            .unwrap_or_default();
        (out.map(|_| ()).map_err(|_| reason), after)
    }

    /// The post-resize hole. The VM was relaunched (resized): its current
    /// launch is another measurement, from a ticket issued after this one.
    /// The pre-resize ticket — still within its 24 h, its measurement still
    /// allowlisted — must not get the key.
    #[test]
    fn a_superseded_launchs_ticket_is_refused() {
        let resized = crate::lifecycle::LaunchBinding {
            measurement: [0xEE; 48],
            issue_time: 150,
        };
        let (out, after) = release_against_launch(Some(resized));
        let err = out.unwrap_err();
        assert!(err.contains("superseded-launch"), "{err}");
        assert_eq!(
            after,
            Some(resized),
            "a refused ticket never moves the binding"
        );
    }

    /// A resize's superseding register commits WHILE this release runs:
    /// the re-checks before the secret leaves (gate 9, then 11d after the
    /// commits) refuse it. `n` = the `launch_binding` read the register
    /// lands before (1 = the admission at gate 5).
    #[test]
    fn a_supersede_landing_during_the_release_withholds_the_secret() {
        let resized = crate::lifecycle::LaunchBinding {
            measurement: [0xEE; 48],
            issue_time: 150,
        };
        for n in [2usize, 3] {
            let (out, _) = release_against_launch_flipping(None, Some((n, resized)));
            let err = out.expect_err("a superseded release must hand out nothing");
            assert!(err.contains("superseded-launch"), "read {n}: {err}");
        }
    }

    /// The same launch (a re-minted ticket, the re-pushed one of an
    /// in-guest reboot, a §25 destination) always releases; a ticket newer
    /// than the binding is a later launch and takes it over (a relaunch of
    /// a §25-moved VM, which no register precedes); nothing recorded yet
    /// binds this launch.
    #[test]
    fn the_current_or_a_later_launch_releases_and_binds() {
        let same = crate::lifecycle::LaunchBinding {
            measurement: MEAS,
            issue_time: 160,
        };
        let (out, after) = release_against_launch(Some(same));
        out.expect("the current launch releases whatever its ticket's age");
        assert_eq!(after, Some(same));

        let older = crate::lifecycle::LaunchBinding {
            measurement: [0xEE; 48],
            issue_time: 50,
        };
        let (out, after) = release_against_launch(Some(older));
        out.expect("a later launch releases");
        assert_eq!(
            after.map(|b| (b.measurement, b.issue_time)),
            Some((MEAS, 100))
        );

        let (out, after) = release_against_launch(None);
        out.expect("first sight releases");
        assert_eq!(after.map(|b| b.measurement), Some(MEAS));
    }

    /// THE production shape: the userdata is Transit CIPHERTEXT at rest and
    /// the ticket's digest is over the PLAINTEXT inside it. So the unwrap
    /// MUST happen before the digest — move it after and every launch
    /// denies with DigestMismatch.
    ///
    /// The digest is a THREE-party contract: vali mints it, this recomputes
    /// it, and the guest re-derives it a third time over the plaintext it
    /// receives (`hippius_guest::release`, baked into every tenant image).
    /// Nothing here may change the preimage unilaterally.
    ///
    /// Mutation that must kill this: digest `at_rest` instead of the
    /// unwrapped plaintext (i.e. hoist the digest above the unwrap).
    #[test]
    fn a_wrapped_userdata_is_unwrapped_before_it_is_digested() {
        let (_pk, sec, rd, report) = guest_and_report();
        let nonce = [1u8; 32];
        let plat = hex::encode([0u8; 64]);
        let plaintext = b"#cloud-config\nssh_authorized_keys: [ssh-ed25519 AAAA]";
        // Ticket binds the PLAINTEXT digest; Vault holds the ciphertext.
        let (cose, l1, kid) = cose_for(&plat, 5, plaintext);
        let mut kvm = HashMap::new();
        kvm.insert(
            "kbs/vm/abc/luks".to_string(),
            test_wrap("kek-abc", b"LUKSKEY"),
        );
        kvm.insert("kbs/vm/abc/ud".to_string(), test_wrap("kek-abc", plaintext));
        let kv = Kv(kvm);
        let h = Harness::new(kid, l1.verifying_key(), rd, &plat);
        let signed = process_release(&release_req(&cose, &report, &nonce), &h.deps(&kv))
            .expect("a wrapped userdata with a plaintext-derived digest must release");
        let resp = verify_response(&h.kbs_sk.verifying_key(), &signed).unwrap();

        // …and the guest receives the PLAINTEXT, not the ciphertext.
        let ud_digest = userdata_digest(
            "t",
            "abc",
            "tk-1",
            "userdata",
            "kbs/vm/abc/ud",
            2,
            plaintext,
        );
        let uc = ReleaseContext {
            v: SCHEMA_V,
            ticket_id: "tk-1",
            tenant_id: "t",
            vm_id: "abc",
            vm_generation: 5,
            kbs_nonce: &nonce,
            measurement: &MEAS,
            kbs_kid: b"kbs-kid",
            secret_type: "userdata",
            secret_path: "kbs/vm/abc/ud",
            secret_version: 2,
            allowed_userdata_digest: &ud_digest,
        };
        let got = crate::crypto::hpke_unwrap(&sec, &resp.userdata, &uc).unwrap();
        assert_eq!(got.as_slice(), plaintext.as_slice());
    }

    /// The §6 gate itself. A ticket whose digest matches NEITHER form is
    /// refused, nothing is emitted, and — because the denial happens
    /// pre-commit — the reservation is rolled back, so the very same
    /// (ticket_id, nonce) can still be redeemed once Vault holds the bytes
    /// the ticket actually binds.
    ///
    /// Mutation that must kill this: `if false && !ct_eq(...)` at the
    /// comparison, or dropping the `Err(DigestMismatch)` arm.
    #[test]
    fn a_mismatching_userdata_digest_emits_nothing_and_rolls_back() {
        let (_pk, _sec, rd, report) = guest_and_report();
        let nonce = [1u8; 32];
        let plat = hex::encode([0u8; 64]);
        let expected = b"#cloud-config\nthe-bytes-the-ticket-binds";
        let at_rest = test_wrap("kek-abc", expected);
        // The ticket binds the PLAINTEXT digest (the three-party
        // convention); Vault holds the ciphertext.
        let (cose, l1, kid) = cose_for(&plat, 5, expected);
        let kek_at_rest = test_wrap("kek-abc", b"LUKSKEY");

        // Vault holds SOMETHING ELSE at the signed path@version.
        let mut kvm = HashMap::new();
        kvm.insert("kbs/vm/abc/luks".to_string(), kek_at_rest.clone());
        kvm.insert(
            "kbs/vm/abc/ud".to_string(),
            test_wrap("kek-abc", b"#cloud-config\nsubstituted"),
        );
        let kv = Kv(kvm);
        let h = Harness::new(kid, l1.verifying_key(), rd, &plat);
        let req = release_req(&cose, &report, &nonce);
        let denial = process_release(&req, &h.deps(&kv))
            .expect_err("a digest mismatch must deny the release");
        assert_eq!(
            h.audit.last_reason(),
            "user-data digest mismatch (ticket vs Vault)"
        );
        // No secret material anywhere in the signed denial — neither the
        // KEK nor either userdata form.
        for needle in [
            b"LUKSKEY".as_slice(),
            kek_at_rest.as_slice(),
            b"substituted".as_slice(),
            expected.as_slice(),
        ] {
            assert!(
                !denial.body.windows(needle.len()).any(|w| w == needle),
                "the denial body carried secret material"
            );
        }

        // Reservation rolled back: the SAME ticket + nonce releases once
        // Vault holds the bytes the ticket binds. (A leaked reservation
        // would deny with `Replay` here — and would have bricked that VM's
        // boot for the ticket's lifetime.)
        let mut fixed = HashMap::new();
        fixed.insert("kbs/vm/abc/luks".to_string(), kek_at_rest);
        fixed.insert("kbs/vm/abc/ud".to_string(), at_rest);
        let kv2 = Kv(fixed);
        process_release(&req, &h.deps(&kv2))
            .expect("the rolled-back reservation must be re-usable");
    }

    // ── customer-held keys: M0 / M1 (split) / M2 (customer) ──────────

    /// Every Vault call a release makes, for asserting what M2 does NOT do.
    struct RecordingKv {
        inner: Kv,
        reads: Mutex<Vec<String>>,
        decrypts: Mutex<Vec<Vec<u8>>>,
    }
    impl RecordingKv {
        fn new(inner: Kv) -> Self {
            Self {
                inner,
                reads: Mutex::new(Vec::new()),
                decrypts: Mutex::new(Vec::new()),
            }
        }
        fn reads(&self) -> Vec<String> {
            self.reads.lock().unwrap().clone()
        }
        fn decrypts(&self) -> Vec<Vec<u8>> {
            self.decrypts.lock().unwrap().clone()
        }
    }
    impl VaultKv for RecordingKv {
        fn read_exact(
            &self,
            c: &VaultCapability,
            path: &str,
            v: u64,
        ) -> Result<Zeroizing<Vec<u8>>> {
            self.reads.lock().unwrap().push(path.to_string());
            self.inner.read_exact(c, path, v)
        }
        fn transit_decrypt(
            &self,
            c: &VaultCapability,
            transit_key: &str,
            ciphertext: &[u8],
        ) -> Result<Zeroizing<Vec<u8>>> {
            self.decrypts.lock().unwrap().push(ciphertext.to_vec());
            self.inner.transit_decrypt(c, transit_key, ciphertext)
        }
    }

    const KM_LUKS: &str = "kbs/vm/abc/luks-kek";
    const KM_LIFECYCLE: &str = "kbs/vm/abc/lifecycle-key";
    const KM_UD: &[u8] = b"#cloud-config\nkey-mode-test";

    /// Vault as vali stages it: a Transit-wrapped KEK (M0/M1 only — an M2
    /// VM has none, but it is staged here anyway so the test proves M2
    /// does not READ it, not merely that it was absent), wrapped userdata,
    /// and a lifecycle key.
    fn key_mode_vault() -> RecordingKv {
        let mut kvm = HashMap::new();
        kvm.insert(
            KM_LUKS.to_string(),
            test_wrap("kek-abc", b"SHARE_H-LUKSKEY"),
        );
        kvm.insert("kbs/vm/abc/ud".to_string(), test_wrap("kek-abc", KM_UD));
        kvm.insert(KM_LIFECYCLE.to_string(), vec![0x5a; 32]);
        RecordingKv::new(Kv(kvm))
    }

    /// One release of VM `abc` under `(registered, ticket)` modes with a
    /// fresh `ticket_id`/nonce, submitting `counter`.
    fn key_mode_release(
        h: &Harness,
        kv: &dyn VaultKv,
        ticket: Option<KeyMode>,
        n: u8,
        counter: u64,
        report: &[u8],
    ) -> core::result::Result<SignedResponse, SignedDenial> {
        let plat = hex::encode([0u8; 64]);
        let ticket_id = format!("tk-{n}");
        let (cose, _l1, _kid) = cose_for_keyed(&plat, 5, KM_UD, KM_LUKS, &ticket_id, ticket);
        let nonce = [1u8; 32];
        let req = ReleaseRequest {
            cose_ticket: &cose,
            raw_snp_report: report,
            kbs_nonce: &nonce,
            now_unix: 200,
            submitted_boot_counter: Some(counter),
        };
        // Each release spends the nonce; re-issue it so the next one is
        // fresh as far as the store is concerned.
        h.nonce_store.spent.lock().unwrap().clear();
        process_release(&req, &h.deps(kv))
    }

    fn key_mode_harness(mode: KeyMode) -> (Harness, [u8; 32], Vec<u8>) {
        let (_pk, sec, rd, report) = guest_and_report();
        let plat = hex::encode([0u8; 64]);
        let (_c, l1, kid) = cose_for(&plat, 5, KM_UD);
        let mut h = Harness::new(kid, l1.verifying_key(), rd, &plat);
        h.st.mode = mode;
        (h, sec, report)
    }

    fn ctx_for<'a>(
        secret_type: &'a str,
        path: &'a str,
        version: u64,
        ticket_id: &'a str,
        nonce: &'a [u8; 32],
        digest: &'a [u8; 32],
    ) -> ReleaseContext<'a> {
        ReleaseContext {
            v: SCHEMA_V,
            ticket_id,
            tenant_id: "t",
            vm_id: "abc",
            vm_generation: 5,
            kbs_nonce: nonce,
            measurement: &MEAS,
            kbs_kid: b"kbs-kid",
            secret_type,
            secret_path: path,
            secret_version: version,
            allowed_userdata_digest: digest,
        }
    }

    /// The pre-customer-keys response type (`luks` REQUIRED) — what every
    /// baked guest decodes with, and what the KBS serialised before.
    #[derive(serde::Serialize, serde::Deserialize)]
    struct PreChangeKbsResponse {
        domain: String,
        v: u32,
        ticket_id: String,
        tenant_id: String,
        vm_id: String,
        vm_generation: u64,
        #[serde(with = "serde_bytes")]
        kbs_nonce: Vec<u8>,
        #[serde(with = "serde_bytes")]
        measurement: Vec<u8>,
        #[serde(with = "serde_bytes")]
        kbs_kid: Vec<u8>,
        hpke_suite_id: u16,
        #[serde(with = "serde_bytes")]
        allowed_userdata_digest: Vec<u8>,
        luks: crate::crypto::WrappedSecret,
        userdata: crate::crypto::WrappedSecret,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        lifecycle_key: Option<crate::crypto::WrappedSecret>,
        #[serde(default)]
        boot_counter: u64,
        #[serde(default)]
        expected_volume_stamp: u64,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        volume_stamp_token: Option<crate::crypto::WrappedSecret>,
    }

    /// M0 is byte-identical on the wire: the signed body the KBS emits for
    /// an M0 ticket decodes with the PRE-change type, and re-encoding it
    /// through that type (the KBS's own canonical path) and re-signing
    /// with the KBS key reproduces the release BYTE FOR BYTE — body and
    /// signature. (HPKE is randomised per release, so the comparison is
    /// against the same release's content, not a stored blob; the frozen
    /// byte vector of the shape lives in
    /// `hippius-types/tests/release_response_kat.rs`.)
    ///
    /// Also pins the rest of M0: KEK read + Transit-unwrapped + released,
    /// stamp noted + token minted, audit reason exactly `released`.
    #[test]
    fn m0_release_is_byte_identical_to_the_pre_change_encoding() {
        let (h, sec, report) = key_mode_harness(KeyMode::Hippius);
        let kv = key_mode_vault();
        let signed = key_mode_release(&h, &kv, None, 1, 1, &report).expect("M0 releases");

        let old: PreChangeKbsResponse = ciborium::de::from_reader(signed.body.as_slice())
            .expect("an M0 body decodes with the pre-change guest parser");
        let reencoded = crate::cbor::to_canonical_vec(&Value::serialized(&old).unwrap()).unwrap();
        assert_eq!(reencoded, signed.body, "M0 body bytes drifted");
        assert_eq!(
            h.kbs_sk.sign(&reencoded).to_bytes().to_vec(),
            signed.sig,
            "M0 signature drifted"
        );

        let resp = verify_response(&h.kbs_sk.verifying_key(), &signed).unwrap();
        let digest = userdata_digest("t", "abc", "tk-1", "userdata", "kbs/vm/abc/ud", 2, KM_UD);
        let nonce = [1u8; 32];
        let lc = ctx_for("luks", KM_LUKS, 3, "tk-1", &nonce, &digest);
        let kek = crate::crypto::hpke_unwrap(&sec, resp.luks.as_ref().unwrap(), &lc).unwrap();
        assert_eq!(kek.as_slice(), b"SHARE_H-LUKSKEY");
        assert!(resp.volume_stamp_token.is_some());
        assert!(kv.reads().contains(&KM_LUKS.to_string()));
        assert_eq!(kv.decrypts().len(), 2, "KEK + userdata Transit unwraps");
        assert_eq!(h.volume_stamp.snapshot().unwrap().len(), 1);
        assert_eq!(h.audit.last_reason(), "released");
    }

    /// INVARIANT 1 of stamp protocol v2 — a guest that did NOT attest v2
    /// (every guest baked before it) gets BYTE-IDENTICAL release bytes.
    ///
    /// A known-answer test on the FULL signed response (body and
    /// signature) of two consecutive M0 releases of a v1 guest: a fresh VM
    /// (no stamp) and the next boot after one confirm (stamp 1, token for
    /// 2). HPKE randomness and the guest key are pinned, so the bytes are
    /// a pure function of the release code. The vectors were computed on
    /// the code BEFORE stamp protocol v2 existed; any drift for a v1 guest
    /// fails here.
    #[test]
    fn a_v1_guest_release_is_byte_identical_to_the_pre_v2_kat() {
        use sha2::{Digest, Sha256};
        let (pk, _sec) = crate::crypto::test_support::fixed_x25519(b"hippius-v1-guest-kat");
        let nonce = [1u8; 32];
        let rd = tenant(&nonce, &pk);
        let plat = hex::encode([0u8; 64]);
        let (_c, l1, kid) = cose_for(&plat, 5, KM_UD);
        let h = Harness::new(kid, l1.verifying_key(), rd, &plat);
        let kv = key_mode_vault();
        let report = vec![0u8; 1184];
        crate::crypto::test_rng::seed(0x5eed_0001);
        let first = key_mode_release(&h, &kv, None, 1, 1, &report);
        h.volume_stamp.confirm("abc", 1).unwrap();
        let second = key_mode_release(&h, &kv, None, 2, 2, &report);
        crate::crypto::test_rng::clear();
        let got: Vec<(String, String)> = [first, second]
            .into_iter()
            .map(|r| {
                let s = r.expect("a v1 guest releases");
                (
                    hex::encode(Sha256::digest(&s.body)),
                    hex::encode(Sha256::digest(&s.sig)),
                )
            })
            .collect();
        let want = [(V1_KAT_BODY_1, V1_KAT_SIG_1), (V1_KAT_BODY_2, V1_KAT_SIG_2)];
        for (i, ((b, s), (wb, ws))) in got.iter().zip(want).enumerate() {
            assert_eq!(
                (b.as_str(), s.as_str()),
                (wb, ws),
                "v1 release #{i} drifted"
            );
        }
    }

    /// sha256 of the signed body / signature of the two releases above,
    /// computed BEFORE stamp protocol v2.
    const V1_KAT_BODY_1: &str = "3cb517b8b4fb07d92c5fc6a6cd383086b0c4cbc5d33d098a35c5a5bd20f68e02";
    const V1_KAT_SIG_1: &str = "3d8240ba4a0cab698ed53503d92c8cb458311d6ead72feb78b5a50fe2c576939";
    const V1_KAT_BODY_2: &str = "51dc2ea6bedca8bda29f0ed906b3badbec7a41a4335f8821c7d6d9505ffa8c18";
    const V1_KAT_SIG_2: &str = "3d58c6bade2ebb3b45c899962853bc90c8af76bbdce005e73b24bb79bd205ada";

    /// M1 changes nothing on the release path: the same `luks-kek` is
    /// released (the guest reads it as `share_H`), the stamp is noted and
    /// its token minted. Only the audit reason names the mode.
    #[test]
    fn m1_split_releases_exactly_what_m0_does_and_audits_the_mode() {
        let (h, sec, report) = key_mode_harness(KeyMode::Split);
        let kv = key_mode_vault();
        let signed =
            key_mode_release(&h, &kv, Some(KeyMode::Split), 1, 1, &report).expect("M1 releases");
        let resp = verify_response(&h.kbs_sk.verifying_key(), &signed).unwrap();
        let digest = userdata_digest("t", "abc", "tk-1", "userdata", "kbs/vm/abc/ud", 2, KM_UD);
        let nonce = [1u8; 32];
        let lc = ctx_for("luks", KM_LUKS, 3, "tk-1", &nonce, &digest);
        let share_h = crate::crypto::hpke_unwrap(&sec, resp.luks.as_ref().unwrap(), &lc).unwrap();
        assert_eq!(share_h.as_slice(), b"SHARE_H-LUKSKEY");
        assert!(resp.volume_stamp_token.is_some());
        assert!(resp.lifecycle_key.is_some());
        let rows = h.volume_stamp.snapshot().unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].unconfirmed_releases, 1);
        assert_eq!(h.boot_counter.get("abc").unwrap(), 1);
        assert_eq!(h.audit.last_reason(), "released key_mode=split");
    }

    /// M2 releases WITHOUT a KEK: the luks path is never read, the KEK is
    /// never Transit-decrypted (only the userdata is), the response has no
    /// `luks` and no stamp token, and no stamp is noted. Everything else —
    /// boot counter, userdata, lifecycle key — is released as in M0.
    /// `require_wrapped_kek` is ON with nothing wrapped for luks: it does
    /// not apply to a VM with no KEK.
    #[test]
    fn m2_customer_releases_no_kek_notes_no_stamp_and_never_reads_the_kek() {
        let (mut h, sec, report) = key_mode_harness(KeyMode::Customer);
        h.require_wrapped_kek = true;
        let kv = key_mode_vault();
        let signed =
            key_mode_release(&h, &kv, Some(KeyMode::Customer), 1, 1, &report).expect("M2 releases");
        let resp = verify_response(&h.kbs_sk.verifying_key(), &signed).unwrap();

        assert!(resp.luks.is_none(), "an M2 release carries no KEK");
        assert!(resp.volume_stamp_token.is_none());
        assert_eq!(resp.expected_volume_stamp, 0);
        assert_eq!(resp.boot_counter, 1);
        // No luks key on the wire at all (not even CBOR null).
        let Value::Map(entries) =
            ciborium::de::from_reader::<Value, _>(signed.body.as_slice()).unwrap()
        else {
            panic!("body is not a map")
        };
        assert!(entries.iter().all(|(k, _)| k.as_text() != Some("luks")));

        // Vault: the KEK path was never read, and the only Transit
        // decrypt was the userdata's.
        let reads = kv.reads();
        assert!(!reads.contains(&KM_LUKS.to_string()), "{reads:?}");
        assert_eq!(
            reads,
            vec!["kbs/vm/abc/ud".to_string(), KM_LIFECYCLE.to_string()]
        );
        assert_eq!(kv.decrypts(), vec![test_wrap("kek-abc", KM_UD)]);

        // The KBS stamp is off for this VM: nothing noted.
        assert!(h.volume_stamp.snapshot().unwrap().is_empty());
        // Boot counter CAS still ran and committed.
        assert_eq!(h.boot_counter.get("abc").unwrap(), 1);

        // Userdata + lifecycle key released exactly as in M0.
        let digest = userdata_digest("t", "abc", "tk-1", "userdata", "kbs/vm/abc/ud", 2, KM_UD);
        let nonce = [1u8; 32];
        let uc = ctx_for("userdata", "kbs/vm/abc/ud", 2, "tk-1", &nonce, &digest);
        let ud = crate::crypto::hpke_unwrap(&sec, &resp.userdata, &uc).unwrap();
        assert_eq!(ud.as_slice(), KM_UD);
        let lcw = resp.lifecycle_key.as_ref().expect("lifecycle key released");
        let lcc = ctx_for("lifecycle", KM_LIFECYCLE, 1, "tk-1", &nonce, &digest);
        let seed = crate::crypto::hpke_unwrap(&sec, lcw, &lcc).unwrap();
        assert_eq!(seed.as_slice(), &[0x5a; 32]);

        assert_eq!(h.audit.last_reason(), "released key_mode=customer");
    }

    /// An M2 guest confirms its stamp to the GUARDIAN, never to the KBS.
    /// If M2 releases counted toward `max_unconfirmed_releases`, the VM
    /// would lock itself out after `bound` boots. Armed at the tightest
    /// bound, M2 keeps booting; the same run in M0 is refused.
    #[test]
    fn m2_releases_never_count_toward_max_unconfirmed_releases() {
        let (mut h, _sec, report) = key_mode_harness(KeyMode::Customer);
        h.max_unconfirmed_releases = Some(1);
        let kv = key_mode_vault();
        for boot in 1..=4u8 {
            key_mode_release(
                &h,
                &kv,
                Some(KeyMode::Customer),
                boot,
                u64::from(boot),
                &report,
            )
            .unwrap_or_else(|_| panic!("M2 boot {boot} must release"));
        }
        assert!(h.volume_stamp.snapshot().unwrap().is_empty());
        assert_eq!(h.boot_counter.get("abc").unwrap(), 4);

        // Contrast: M0 at the same bound is refused on its second
        // unconfirmed release.
        let (mut h0, _sec, report) = key_mode_harness(KeyMode::Hippius);
        h0.max_unconfirmed_releases = Some(1);
        let kv0 = key_mode_vault();
        key_mode_release(&h0, &kv0, None, 1, 1, &report).expect("first M0 boot");
        assert!(key_mode_release(&h0, &kv0, None, 2, 2, &report).is_err());
        let reason = h0.audit.last_reason();
        assert!(
            reason.contains("volume-stamp-confirm-suppressed"),
            "{reason}"
        );
    }

    /// An authorized-rollback arm never admits an M2 release: the KBS does
    /// not own that VM's stamp, so there is nothing for the arm to
    /// restore. Contrast: the SAME arm on an M0 VM is admitted (and then
    /// refused only because this harness wires no admin audit chain for
    /// the mandatory consume-intent row).
    #[test]
    fn an_m2_release_is_never_admitted_by_a_rollback_arm() {
        for (mode, ticket) in [
            (KeyMode::Hippius, None),
            (KeyMode::Customer, Some(KeyMode::Customer)),
        ] {
            let (mut h, _sec, report) = key_mode_harness(mode);
            let kv = key_mode_vault();
            for boot in 1..=3u8 {
                key_mode_release(&h, &kv, ticket, boot, u64::from(boot), &report)
                    .unwrap_or_else(|_| panic!("{mode:?} boot {boot} must release"));
            }
            let arm = crate::rollback::RollbackArm {
                vm_id: "abc".into(),
                restore_id: "r-1".into(),
                manifest_sha256_hex: "ab".repeat(32),
                new_gen: 5,
                dest: hex::encode([0u8; 64]),
                from_counter: 1,
                to_stamp: 1,
                checkpoint_sha256_hex: "cd".repeat(32),
                armed_at_unix: 200,
                expires_at_unix: 800,
                requested_by: "tenant:42".into(),
                armed_by: String::new(),
            };
            h.boot_counter.arm_rollback(arm, 1800, 200).unwrap();
            h.volume_stamp
                .record_arm_timeline("abc", "r-1", &crate::volume_stamp::ZERO_TIMELINE)
                .unwrap();
            // A guest that ATTESTS the timeline-bound stamp, so only the
            // key mode can be what refuses the M2 arm.
            h.attest_stamp_v2();
            let out = key_mode_release(&h, &kv, ticket, 9, 2, &report);
            assert!(out.is_err());
            let reason = h.audit.last_reason();
            let admitted = reason.contains("no admin audit chain is wired");
            assert_eq!(admitted, mode == KeyMode::Hippius, "{mode:?}: {reason}");
            assert_eq!(h.boot_counter.get("abc").unwrap(), 3);
            assert_eq!(h.volume_stamp.token_epoch("abc").unwrap(), 0);
        }
    }

    /// INVARIANT 2 of stamp protocol v2 — the v2 capability comes ONLY
    /// from the SNP-signed REPORT_DATA. Every other input of the release
    /// is relayed (and may be rewritten) by the miner; none of them makes
    /// a v1 report read as v2:
    ///
    /// - the request's `kbs_nonce` is the only other input the reading
    ///   takes, and for ANY value it names, a v1 report is v1 or unbound
    ///   (never v2: that needs `SHA-256(domain ‖ n) == REPORT_DATA[0..32]`);
    /// - a VM whose record already says v2 (a stale claim) is recorded v1
    ///   again by a v1 report, gets the V1 response, and is NOT armable.
    #[test]
    fn a_v2_claim_outside_the_signed_report_data_is_never_honoured() {
        let nonce = [1u8; 32];
        let pk = [0x44u8; 32];
        let v1 = VerifiedReport {
            measurement: MEAS,
            report_data: tenant(&nonce, &pk),
            tcb: 10,
            policy: 0b10,
            chip_id: [0u8; 64],
            chain_pem: Vec::new(),
        };
        let v2 = VerifiedReport {
            report_data: hippius_types::report_data::tenant_stamp_v2(&nonce, &pk),
            ..v1.clone()
        };
        let req = |n: &'static [u8; 32]| ReleaseRequest {
            cose_ticket: &[],
            raw_snp_report: &[],
            kbs_nonce: n,
            now_unix: 0,
            submitted_boot_counter: Some(7),
        };
        static NONCE: [u8; 32] = [1u8; 32];
        static OTHER: [u8; 32] = [2u8; 32];
        use crate::volume_stamp::{GUEST_STAMP_PROTOCOL_V1 as P1, GUEST_STAMP_PROTOCOL_V2 as P2};
        assert_eq!(attested_guest_stamp_protocol(&req(&NONCE), &v1), Some(P1));
        assert_eq!(attested_guest_stamp_protocol(&req(&NONCE), &v2), Some(P2));
        // The miner names another nonce: unbound, never v2.
        assert_eq!(attested_guest_stamp_protocol(&req(&OTHER), &v1), None);
        assert_eq!(attested_guest_stamp_protocol(&req(&OTHER), &v2), None);
        // Sweep: no request nonce turns the v1 report into v2.
        for b in 0..=255u8 {
            let n: &'static [u8; 32] = Box::leak(Box::new([b; 32]));
            assert_ne!(attested_guest_stamp_protocol(&req(n), &v1), Some(P2));
        }

        // Through the full release: a VM whose record ALREADY says v2
        // (e.g. a claim some other path left behind) and a v1 report.
        let (h, _sec, report) = key_mode_harness(KeyMode::Hippius);
        let kv = key_mode_vault();
        h.volume_stamp
            .record_guest_stamp_protocol("abc", P2)
            .unwrap();
        let signed = key_mode_release(&h, &kv, None, 1, 1, &report).expect("v1 releases");
        let resp = verify_response(&h.kbs_sk.verifying_key(), &signed).unwrap();
        assert_eq!(
            resp.domain, RELEASE_DOMAIN,
            "the response domain did not change"
        );
        assert!(resp.volume_stamp_transition.is_none());
        assert_eq!(h.volume_stamp.guest_stamp_protocol("abc").unwrap(), P1);
        assert!(!crate::rollback::rollback_capable("abc", &h.st, &h.volume_stamp).unwrap());
    }

    /// The downgrade direction: a miner that relabels a v2 guest's report
    /// as v1 (by sending `REPORT_DATA[0..32]` as the `kbs_nonce`) names a
    /// nonce the KBS never issued — denied before anything is recorded.
    #[test]
    fn relabeling_a_v2_report_as_v1_is_refused_before_anything_is_recorded() {
        let (mut h, _sec, report) = key_mode_harness(KeyMode::Hippius);
        h.attest_stamp_v2();
        let kv = key_mode_vault();
        let mut relabeled = [0u8; 32];
        relabeled.copy_from_slice(&h.av.rd[0..32]);
        let plat = hex::encode([0u8; 64]);
        let (cose, _l1, _kid) = cose_for_keyed(&plat, 5, KM_UD, KM_LUKS, "tk-1", None);
        let req = ReleaseRequest {
            cose_ticket: &cose,
            raw_snp_report: &report,
            kbs_nonce: &relabeled,
            now_unix: 200,
            submitted_boot_counter: Some(1),
        };
        assert!(process_release(&req, &h.deps(&kv)).is_err());
        assert_eq!(h.volume_stamp.guest_stamp_protocol("abc").unwrap(), 1);
        assert!(
            h.volume_stamp.snapshot().unwrap().is_empty(),
            "nothing noted"
        );
        assert_eq!(h.boot_counter.get("abc").unwrap(), 0);
    }

    /// A v2 guest's first release (`E = 0`): V2 domain, the transition
    /// expects the zero timeline (the adopt case) and targets a FRESH one
    /// the store now holds (gate 5c'), the record says v2 — and the VM
    /// becomes armable.
    #[test]
    fn a_v2_guest_is_answered_in_the_v2_domain_and_recorded_armable() {
        let (mut h, _sec, report) = key_mode_harness(KeyMode::Hippius);
        h.attest_stamp_v2();
        let kv = key_mode_vault();
        let signed = key_mode_release(&h, &kv, None, 1, 1, &report).expect("v2 releases");
        let resp = verify_response(&h.kbs_sk.verifying_key(), &signed).unwrap();
        assert_eq!(resp.domain, hippius_types::release::RELEASE_DOMAIN_V2);
        assert_eq!(resp.expected_volume_stamp, 0);
        let (e, t) = resp.volume_stamp_transition.unwrap().ids().unwrap();
        assert_eq!(e, [0u8; 32], "E = 0: nothing is expected");
        assert_ne!(t, [0u8; 32], "E = 0: a fresh non-zero target");
        assert_eq!(
            h.volume_stamp.timeline("abc").unwrap(),
            t,
            "the move is held"
        );
        assert_eq!(h.volume_stamp.guest_stamp_protocol("abc").unwrap(), 2);
        assert!(crate::rollback::rollback_capable("abc", &h.st, &h.volume_stamp).unwrap());
    }

    /// M2 is unaffected: the KBS owns no stamp there, so even a report
    /// that attests v2 gets the V1 response with no transition and no
    /// token, and the VM is never armable.
    #[test]
    fn m2_never_gets_a_v2_response_and_is_never_armable() {
        let (mut h, _sec, report) = key_mode_harness(KeyMode::Customer);
        h.attest_stamp_v2();
        let kv = key_mode_vault();
        let signed =
            key_mode_release(&h, &kv, Some(KeyMode::Customer), 1, 1, &report).expect("M2 releases");
        let resp = verify_response(&h.kbs_sk.verifying_key(), &signed).unwrap();
        assert_eq!(resp.domain, RELEASE_DOMAIN);
        assert!(resp.volume_stamp_transition.is_none());
        assert!(resp.volume_stamp_token.is_none());
        assert!(h.volume_stamp.snapshot().unwrap().is_empty());
        assert_eq!(
            h.volume_stamp.timeline("abc").unwrap(),
            crate::volume_stamp::ZERO_TIMELINE,
            "M2 at E = 0 is never moved to a fresh timeline"
        );
        assert!(!crate::rollback::rollback_capable("abc", &h.st, &h.volume_stamp).unwrap());
    }

    /// Gate 5a'' records the guest stamp protocol every attested release
    /// reports — v1 for every guest today — and the latest release wins:
    /// a VM recorded at v2 whose guest now releases as v1 is recorded v1
    /// again (so it is no longer armable).
    #[test]
    fn every_release_records_the_attested_guest_stamp_protocol() {
        let (h, _sec, report) = key_mode_harness(KeyMode::Hippius);
        let kv = key_mode_vault();
        h.volume_stamp
            .record_guest_stamp_protocol("abc", 2)
            .unwrap();
        key_mode_release(&h, &kv, None, 1, 1, &report).expect("releases");
        assert_eq!(
            h.volume_stamp.guest_stamp_protocol("abc").unwrap(),
            crate::volume_stamp::GUEST_STAMP_PROTOCOL_V1
        );
    }

    /// A ticket whose mode differs from the one pinned at register is
    /// refused before ANY secret work: no Vault read, no stamp noted, no
    /// counter moved, no reservation leaked.
    #[test]
    fn a_ticket_whose_key_mode_differs_from_the_registered_one_is_refused_before_vault() {
        for (registered, ticket) in [
            (KeyMode::Hippius, Some(KeyMode::Customer)),
            (KeyMode::Hippius, Some(KeyMode::Split)),
            (KeyMode::Customer, None),
            (KeyMode::Split, Some(KeyMode::Customer)),
            (KeyMode::Split, None),
        ] {
            let (h, _sec, report) = key_mode_harness(registered);
            let kv = key_mode_vault();
            let denial = key_mode_release(&h, &kv, ticket, 1, 1, &report)
                .expect_err("a mode mismatch must deny");
            assert!(
                h.audit.last_reason().contains("key-mode-mismatch"),
                "{registered:?}/{ticket:?}: {}",
                h.audit.last_reason()
            );
            assert!(!denial.body.windows(7).any(|w| w == b"LUKSKEY"));
            assert!(kv.reads().is_empty(), "no Vault read on a mode mismatch");
            assert!(h.volume_stamp.snapshot().unwrap().is_empty());
            assert_eq!(h.boot_counter.get("abc").unwrap(), 0);
        }
    }

    /// A fence that commits while a release is between its last
    /// pre-commit lifecycle check and its return must still win: the
    /// release returns a denial, and no secret leaves.
    ///
    /// Mutation that must kill this: delete gate 11d.
    #[test]
    fn a_fence_that_lands_during_the_commit_denies_the_release() {
        struct FencedOnThirdRead {
            reads: std::sync::Mutex<u32>,
            active: VmState,
        }
        impl VmStateStore for FencedOnThirdRead {
            fn get(&self, _vm: &str) -> Result<VmState> {
                let mut n = self.reads.lock().unwrap();
                *n += 1;
                Ok(if *n >= 3 {
                    VmState::Decommissioning
                } else {
                    self.active.clone()
                })
            }
            fn key_mode(&self, _vm: &str) -> Result<KeyMode> {
                Ok(KeyMode::Hippius)
            }
        }
        let (_pk, _sec, rd, report) = guest_and_report();
        let nonce = [1u8; 32];
        let plat = hex::encode([0u8; 64]);
        let ud = b"#cloud-config\n";
        let (cose, l1, kid) = cose_for(&plat, 5, ud);
        let mut kvm = HashMap::new();
        kvm.insert("kbs/vm/abc/luks".to_string(), b"LUKSKEY".to_vec());
        kvm.insert("kbs/vm/abc/ud".to_string(), ud.to_vec());
        let kv = Kv(kvm);
        let h = Harness::new(kid, l1.verifying_key(), rd, &plat);
        let fenced = FencedOnThirdRead {
            reads: std::sync::Mutex::new(0),
            active: h.st.state.clone(),
        };
        // Control: with a store that never changes, the same request is
        // released — so the denial below is the fence, nothing else.
        process_release(&release_req(&cose, &report, &nonce), &h.deps(&kv))
            .expect("control: an unfenced VM releases");

        let h = Harness::new(h.kr.0.clone(), l1.verifying_key(), rd, &plat);
        let mut deps = h.deps(&kv);
        deps.vm_states = &fenced;
        let denial = process_release(&release_req(&cose, &report, &nonce), &deps)
            .expect_err("a fence committed before the return must deny");
        assert_eq!(*fenced.reads.lock().unwrap(), 3);
        assert!(!denial.body.windows(7).any(|w| w == b"LUKSKEY"));
        assert_eq!(h.audit.last_reason(), "lifecycle: vm is decommissioning");
    }

    /// §7 fail-closed: the lifecycle-key read is optional ONLY for a
    /// not-found. A transport failure / 403 / 500 on that path denies the
    /// release outright — releasing anyway would hand the guest a KEK with
    /// no lifecycle signing key and silently drop the §24/§25 guest-signed
    /// fence for the life of the VM.
    ///
    /// Mutation that must kill this: widen the match arm back to
    /// `Err(KbsError::Vault(_)) => None`.
    #[test]
    fn a_non_404_lifecycle_read_failure_denies_the_release() {
        let (_pk, _sec, rd, report) = guest_and_report();
        let nonce = [1u8; 32];
        let plat = hex::encode([0u8; 64]);
        let ud = b"#cloud-config\nx";
        // Canonical luks path so the lifecycle path is derived and read.
        let (cose, l1, kid) = cose_for_luks(&plat, 5, ud, "kbs/vm/abc/luks-kek");
        let mut kvm = HashMap::new();
        kvm.insert("kbs/vm/abc/luks-kek".to_string(), b"LUKSKEY".to_vec());
        kvm.insert("kbs/vm/abc/ud".to_string(), ud.to_vec());
        kvm.insert("kbs/vm/abc/lifecycle-key".to_string(), vec![0x5Au8; 32]);
        let kv = KvFailing {
            inner: Kv(kvm),
            fail_path: "kbs/vm/abc/lifecycle-key".to_string(),
        };
        let h = Harness::new(kid, l1.verifying_key(), rd, &plat);
        assert!(
            process_release(&release_req(&cose, &report, &nonce), &h.deps(&kv)).is_err(),
            "a non-404 lifecycle read failure must deny the release"
        );
        assert_eq!(
            h.audit.last_reason(),
            "vault: KV read: Vault transport error"
        );
    }

    /// The userdata counterpart of `require_wrapped_kek`. The digest gate
    /// proves the released bytes are the ones the ticket named — never
    /// that they are CIPHERTEXT. Without this gate a staging path that
    /// quietly went back to plaintext would release happily and nothing
    /// anywhere would notice.
    ///
    /// Mutation that must kill this: drop the `deps.require_wrapped_userdata
    /// && !at_rest.starts_with(b"vault:")` refusal.
    #[test]
    fn plaintext_userdata_at_rest_is_refused_once_the_gate_is_armed() {
        let (_pk, _sec, rd, report) = guest_and_report();
        let nonce = [1u8; 32];
        let plat = hex::encode([0u8; 64]);
        let plaintext = b"#cloud-config\nstaged-in-the-clear";
        let (cose, l1, kid) = cose_for(&plat, 5, plaintext);
        let mut kvm = HashMap::new();
        kvm.insert(
            "kbs/vm/abc/luks".to_string(),
            test_wrap("kek-abc", b"LUKSKEY"),
        );
        kvm.insert("kbs/vm/abc/ud".to_string(), plaintext.to_vec());
        let kv = Kv(kvm);
        let h = Harness::new(kid, l1.verifying_key(), rd, &plat);
        let req = release_req(&cose, &report, &nonce);

        // ARMED first (nonce still unspent, so this gate is the only thing
        // that can deny).
        let armed = Deps {
            require_wrapped_userdata: true,
            rollback_audit: None,
            ..h.deps(&kv)
        };
        assert!(
            process_release(&req, &armed).is_err(),
            "armed: a plaintext userdata at rest must be refused"
        );
        assert!(
            h.audit.last_reason().contains("require_wrapped_userdata"),
            "denial reason was {:?}",
            h.audit.last_reason()
        );
        // Default off: a legacy VM whose cloud-init predates the wrapping
        // still boots.
        process_release(&req, &h.deps(&kv)).expect("default must still release");
    }

    /// A value that is STILL ciphertext after one unwrap was wrapped
    /// twice — the shape a mixed-version vali produces when it re-wraps a
    /// blob that intake already wrapped. Releasing it hands the guest the
    /// literal `vault:v1:…` string as its cloud-config: no SSH key, no
    /// NetBird enrolment, and NOTHING reports an error. Refuse instead.
    ///
    /// Mutation that must kill this: drop the post-unwrap `vault:` check.
    #[test]
    fn a_double_wrapped_userdata_is_never_released_as_cloud_config() {
        let (_pk, _sec, rd, report) = guest_and_report();
        let nonce = [1u8; 32];
        let plat = hex::encode([0u8; 64]);
        let inner = test_wrap("kek-abc", b"#cloud-config\nreal");
        let outer = test_wrap("kek-abc", &inner);
        // The ticket digests the AT-REST bytes, so this passes the §6 gate
        // — the double-wrap check is the ONLY thing standing in the way.
        let (cose, l1, kid) = cose_for(&plat, 5, &outer);
        let mut kvm = HashMap::new();
        kvm.insert(
            "kbs/vm/abc/luks".to_string(),
            test_wrap("kek-abc", b"LUKSKEY"),
        );
        kvm.insert("kbs/vm/abc/ud".to_string(), outer);
        let kv = Kv(kvm);
        let h = Harness::new(kid, l1.verifying_key(), rd, &plat);
        assert!(
            process_release(&release_req(&cose, &report, &nonce), &h.deps(&kv)).is_err(),
            "a double-wrapped userdata must not be released"
        );
        assert!(
            h.audit.last_reason().contains("double-wrapped"),
            "denial reason was {:?}",
            h.audit.last_reason()
        );
    }

    /// Authorized rollback (A2) through the REAL release path. Every
    /// negative is its own test; each asserts the refusal AND that the
    /// protected state (counter, stamp, arm) is untouched.
    mod rollback {
        use super::*;
        use crate::admin_audit::FileAdminAuditSink;
        use crate::boot_counter::{FileBootCounterStore, InMemoryBootCounterStore};
        use crate::rollback::{ArmRollbackOutcome, RollbackArm};
        use crate::volume_stamp::InMemoryVolumeStampStore;

        /// A lifecycle row that can CHANGE after a given number of reads —
        /// how the tests land an `activate`/fence at an exact point of a
        /// release (reads: gate 5, gate 9, the in-lock commit check, 11d).
        pub(super) struct MutState(
            pub Mutex<VmState>,
            pub Mutex<Option<(usize, VmState)>>,
            pub std::sync::atomic::AtomicUsize,
        );
        impl VmStateStore for MutState {
            fn key_mode(&self, _vm: &str) -> Result<hippius_types::guardian::KeyMode> {
                Ok(hippius_types::guardian::KeyMode::Hippius)
            }
            fn get(&self, _vm: &str) -> Result<VmState> {
                let n = self.2.fetch_add(1, std::sync::atomic::Ordering::SeqCst) + 1;
                if let Some((after, next)) = self.1.lock().unwrap().clone() {
                    if n > after {
                        return Ok(next);
                    }
                }
                Ok(self.0.lock().unwrap().clone())
            }
        }
        impl MutState {
            fn new(row: VmState) -> Self {
                Self(
                    Mutex::new(row),
                    Mutex::new(None),
                    std::sync::atomic::AtomicUsize::new(0),
                )
            }
            /// From the `after + 1`-th read on, report `next`.
            fn switch_after(&self, after: usize, next: VmState) {
                self.2.store(0, std::sync::atomic::Ordering::SeqCst);
                *self.1.lock().unwrap() = Some((after, next));
            }
        }

        const CHIP_A: [u8; 64] = [0u8; 64];
        const CHIP_B: [u8; 64] = [0xbbu8; 64];
        /// Stored counter before the rollback, and the confirmed stamp.
        const STORED: u64 = 4;
        const CONFIRMED: u64 = 7;
        /// The checkpoint the arm carries.
        const C_T: u64 = 2;
        const E_T: u64 = 5;
        const NEW_GEN: u64 = 6;
        // The fixture ticket expires at 999; every release here runs before it.
        const NOW: u64 = 300;

        fn plat(chip: [u8; 64]) -> String {
            hex::encode(chip)
        }

        pub(super) struct World<
            B: BootCounterStore,
            V: VolumeStampStore + Default = InMemoryVolumeStampStore,
        > {
            kr: Kr,
            al: AllowAll,
            lp: LaunchPolicy,
            pub st: MutState,
            rs: InMemoryReleaseStore,
            va: ChallengeVaultAuth<fn(&[u8; 48]) -> bool>,
            kv: Kv,
            kbs_rep: VerifiedReport,
            pub kbs_sk: SigningKey,
            pub audit: Audit,
            evidence: crate::evidence::MockEvidenceSink,
            pub bc: B,
            pub vs: V,
            pub admin_audit: FileAdminAuditSink,
            pub td: tempfile::TempDir,
            pk: [u8; 32],
            sec: [u8; 32],
            l1: SigningKey,
            ud: Vec<u8>,
            /// The stamp protocol this world's guest ATTESTS in its
            /// REPORT_DATA (v2 unless a test says otherwise).
            pub protocol: std::cell::Cell<u8>,
        }

        pub(super) struct Granted {
            pub resp: KbsResponse,
            pub token: Vec<u8>,
            /// The target timeline of a v2 response (`None` for v1).
            pub target_timeline: Option<[u8; 32]>,
        }

        fn world_with<B: BootCounterStore>(bc: B, td: tempfile::TempDir) -> World<B> {
            world_with_stamps::<B, InMemoryVolumeStampStore>(bc, td)
        }

        fn world_with_stamps<B: BootCounterStore, V: VolumeStampStore + Default>(
            bc: B,
            td: tempfile::TempDir,
        ) -> World<B, V> {
            let (pk, sec) = crate::crypto::test_support::gen_x25519();
            let ud = b"USERDATA".to_vec();
            let (_cose, l1, kid) = cose_for(&plat(CHIP_A), NEW_GEN, &ud);
            let ok: fn(&[u8; 48]) -> bool = |_m| true;
            let mut kvm = HashMap::new();
            kvm.insert("kbs/vm/abc/luks".to_string(), b"LUKSKEY".to_vec());
            kvm.insert("kbs/vm/abc/ud".to_string(), ud.clone());
            let w = World {
                kr: Kr(kid, l1.verifying_key()),
                al: AllowAll,
                lp: LaunchPolicy {
                    min_tcb: 1,
                    required_bits: 0b10,
                    allowed_mask: 0b1101,
                },
                st: MutState::new(VmState::Migrating {
                    old_gen: NEW_GEN - 1,
                    new_gen: NEW_GEN,
                    source: plat(CHIP_B),
                    dest: plat(CHIP_A),
                    lease_id: "lease-1".into(),
                }),
                rs: InMemoryReleaseStore::default(),
                va: ChallengeVaultAuth {
                    kbs_measurement_ok: ok,
                    policy: LaunchPolicy {
                        min_tcb: 1,
                        required_bits: 0,
                        allowed_mask: u64::MAX,
                    },
                    challenge_ttl: 60,
                    cap_ttl: 60,
                    challenge_nonce: [2u8; 32],
                },
                kv: Kv(kvm),
                kbs_rep: VerifiedReport {
                    measurement: MEAS,
                    report_data: [0u8; 64],
                    tcb: 5,
                    policy: 0,
                    chip_id: [0u8; 64],
                    chain_pem: Vec::new(),
                },
                kbs_sk: SigningKey::from_bytes(&[9u8; 32]),
                audit: Audit::default(),
                evidence: crate::evidence::MockEvidenceSink::new(),
                bc,
                vs: V::default(),
                admin_audit: FileAdminAuditSink::open(td.path().join("admin-audit")).unwrap(),
                td,
                pk,
                sec,
                l1,
                ud,
                protocol: std::cell::Cell::new(crate::volume_stamp::GUEST_STAMP_PROTOCOL_V2),
            };
            w.bc.seed("abc", STORED).unwrap();
            for v in 1..=CONFIRMED {
                w.vs.confirm("abc", v).unwrap();
            }
            w
        }

        pub(super) fn world() -> World<InMemoryBootCounterStore> {
            world_with(
                InMemoryBootCounterStore::default(),
                tempfile::tempdir().unwrap(),
            )
        }

        pub(super) fn arm(restore_id: &str) -> RollbackArm {
            RollbackArm {
                vm_id: "abc".into(),
                restore_id: restore_id.into(),
                manifest_sha256_hex: "ab".repeat(32),
                new_gen: NEW_GEN,
                dest: plat(CHIP_A),
                from_counter: C_T,
                to_stamp: E_T,
                checkpoint_sha256_hex: "cd".repeat(32),
                armed_at_unix: NOW,
                expires_at_unix: NOW + 600,
                requested_by: "tenant:42".into(),
                armed_by: "spiffe://hippius.network/vali".into(),
            }
        }

        impl<B: BootCounterStore, V: VolumeStampStore + Default> World<B, V> {
            /// Plant an arm straight in the store (the admin route's own
            /// checks are tested in `crate::rollback`; here the release
            /// path is under test, including arms the admin route would
            /// never produce).
            pub fn plant(&self, a: RollbackArm) {
                self.plant_on(a, crate::volume_stamp::ZERO_TIMELINE);
            }

            /// Plant an arm whose checkpoint names `timeline`.
            pub fn plant_on(&self, a: RollbackArm, timeline: [u8; 32]) {
                let restore_id = a.restore_id.clone();
                assert!(matches!(
                    self.bc.arm_rollback(a, 1800, NOW).unwrap(),
                    ArmRollbackOutcome::Armed(_)
                ));
                self.vs
                    .record_arm_timeline("abc", &restore_id, &timeline)
                    .unwrap();
            }

            pub fn release(
                &self,
                tag: u8,
                gen: u64,
                chip: [u8; 64],
                submitted: Option<u64>,
                now: u64,
            ) -> core::result::Result<Granted, SignedDenial> {
                self.release_audited(tag, gen, chip, submitted, now, Some(&self.admin_audit))
            }

            pub fn release_audited(
                &self,
                tag: u8,
                gen: u64,
                chip: [u8; 64],
                submitted: Option<u64>,
                now: u64,
                rollback_audit: Option<&FileAdminAuditSink>,
            ) -> core::result::Result<Granted, SignedDenial> {
                let (cose, _l1, _kid) = {
                    let (c, l, k) = cose_for(&plat(chip), gen, &self.ud);
                    assert_eq!(l.to_bytes(), self.l1.to_bytes());
                    (c, l, k)
                };
                let mut nonce = [1u8; 32];
                nonce[0] = tag;
                let rd = if self.protocol.get() >= crate::volume_stamp::GUEST_STAMP_PROTOCOL_V2 {
                    hippius_types::report_data::tenant_stamp_v2(&nonce, &self.pk)
                } else {
                    tenant(&nonce, &self.pk)
                };
                let av = Av { rd, chip };
                let nonce_store = MockNonceStore::default();
                nonce_store.preissue(nonce);
                let raw = vec![0u8; 1184];
                let deps = Deps {
                    l1_keyring: &self.kr,
                    attn: &av,
                    offline_allowlist: &self.al,
                    launch_policy: &self.lp,
                    vm_states: &self.st,
                    release_store: &self.rs,
                    vault_auth: &self.va,
                    vault_kv: &self.kv,
                    kbs_nonce_store: &nonce_store,
                    kbs_attestation: &self.kbs_rep,
                    kbs_auth_pubkey: b"kbs-channel-pub",
                    kbs_signing_key: &self.kbs_sk,
                    kbs_kid: b"kbs-kid",
                    audit: &self.audit,
                    evidence: &self.evidence,
                    boot_counter: &self.bc,
                    volume_stamp: &self.vs,
                    max_unconfirmed_releases: Some(crate::volume_stamp::MAX_UNCONFIRMED_RELEASES),
                    require_wrapped_kek: false,
                    require_wrapped_userdata: false,
                    rollback_audit,
                };
                let req = ReleaseRequest {
                    cose_ticket: &cose,
                    raw_snp_report: &raw,
                    kbs_nonce: &nonce,
                    now_unix: now,
                    submitted_boot_counter: submitted,
                };
                let signed = process_release(&req, &deps)?;
                let resp = verify_response(&self.kbs_sk.verifying_key(), &signed).unwrap();
                let w = resp.volume_stamp_token.clone().expect("token");
                let ud_digest =
                    userdata_digest("t", "abc", "tk-1", "userdata", "kbs/vm/abc/ud", 2, &self.ud);
                let lc = ReleaseContext {
                    v: SCHEMA_V,
                    ticket_id: "tk-1",
                    tenant_id: "t",
                    vm_id: "abc",
                    vm_generation: gen,
                    kbs_nonce: &nonce,
                    measurement: &MEAS,
                    kbs_kid: b"kbs-kid",
                    secret_type: "volume-stamp-token",
                    secret_path: "kbs/volume-stamp",
                    secret_version: resp.expected_volume_stamp + 1,
                    allowed_userdata_digest: &ud_digest,
                };
                let token = crate::crypto::hpke_unwrap(&self.sec, &w, &lc)
                    .unwrap()
                    .to_vec();
                // The V2 domain comes WITH the transition, never one
                // without the other.
                assert_eq!(
                    resp.domain == hippius_types::release::RELEASE_DOMAIN_V2,
                    resp.volume_stamp_transition.is_some(),
                    "domain/transition mismatch"
                );
                let target_timeline = resp
                    .volume_stamp_transition
                    .as_ref()
                    .map(|t| t.ids().expect("32-byte ids").1);
                Ok(Granted {
                    resp,
                    token,
                    target_timeline,
                })
            }

            /// Confirm the way the guest that got `g` does: on the target
            /// timeline its v2 response named (v1: the plain confirm).
            pub fn confirm(&self, value: u64, g: &Granted) -> Result<u64> {
                let k = crate::volume_stamp::stamp_mac_key(&self.kbs_sk.to_bytes());
                match &g.target_timeline {
                    Some(t) => crate::volume_stamp::confirm_timeline(
                        &self.vs, &k, "abc", value, &g.token, t,
                    ),
                    None => crate::volume_stamp::confirm(&self.vs, &k, "abc", value, &g.token),
                }
            }

            pub fn admin_ops(&self) -> Vec<(String, String)> {
                let raw = std::fs::read_to_string(self.td.path().join("admin-audit/admin.log"))
                    .unwrap_or_default();
                raw.lines()
                    .map(|l| {
                        let body = hex::decode(l.split(':').nth(1).unwrap()).unwrap();
                        let v: Value = ciborium::de::from_reader(body.as_slice()).unwrap();
                        let get = |k: &str| match &v {
                            Value::Map(m) => m
                                .iter()
                                .find(|(kk, _)| kk == &Value::Text(k.into()))
                                .and_then(|(_, vv)| vv.as_text().map(str::to_string))
                                .unwrap_or_default(),
                            _ => String::new(),
                        };
                        (get("op"), get("reason"))
                    })
                    .collect()
            }

            /// `(delivered, reverted)` of the last rollback as `GET
            /// …/rollback` reports it.
            pub fn last_outcome(&self) -> Option<(bool, bool)> {
                let last = self.bc.rollback_state("abc").unwrap().1?;
                let w = last.to_wire(self.vs.rollback_resolution("abc").unwrap().as_ref());
                Some((w.delivered, w.reverted))
            }

            /// State a refused release must not touch.
            pub fn assert_untouched(&self, arm_live: bool) {
                assert_eq!(self.bc.get("abc").unwrap(), STORED, "counter moved");
                assert_eq!(self.vs.get("abc").unwrap(), CONFIRMED, "stamp moved");
                assert_eq!(self.vs.token_epoch("abc").unwrap(), 0, "epoch moved");
                assert_eq!(
                    self.bc.rollback_state("abc").unwrap().0.is_some(),
                    arm_live,
                    "arm liveness changed"
                );
            }
        }

        #[test]
        fn the_full_rollback_release_restores_the_stamp_and_keeps_the_counter_monotonic() {
            let w = world();
            w.plant(arm("r-1"));
            let g = w
                .release(0x10, NEW_GEN, CHIP_A, Some(C_T + 1), NOW + 1)
                .expect("the armed restore point must be released");
            // The counter commits stored + 1 — never the submitted C_T+1,
            // never lowered — and the guest is told that value.
            assert_eq!(g.resp.boot_counter, STORED + 1);
            assert_eq!(w.bc.get("abc").unwrap(), STORED + 1);
            // The stamp: the response echoes E_T, the store holds E_T with
            // no unconfirmed release, under token epoch 1.
            assert_eq!(g.resp.expected_volume_stamp, E_T);
            assert_eq!(w.vs.row("abc").unwrap(), (E_T, 0));
            assert_eq!(w.vs.token_epoch("abc").unwrap(), 1);
            // The arm is consumed and recorded.
            let (live, last) = w.bc.rollback_state("abc").unwrap();
            assert!(live.is_none(), "one-shot");
            let last = last.expect("last_rollback recorded");
            assert_eq!(
                (
                    last.from_counter,
                    last.to_counter,
                    last.stamp,
                    last.restore_id.as_str()
                ),
                (C_T, STORED + 1, E_T, "r-1")
            );
            // The guest's token confirms E_T + 1 under the new epoch, and
            // it is NOT the epoch-0 token for the same target.
            let k = crate::volume_stamp::stamp_mac_key(&w.kbs_sk.to_bytes());
            assert_ne!(
                g.token,
                crate::volume_stamp::stamp_token(&k, "abc", E_T + 1).to_vec()
            );
            assert_eq!(w.confirm(E_T + 1, &g).unwrap(), E_T + 1);
            // Delivered — the key went out.
            assert_eq!(w.last_outcome(), Some((true, false)));
            // Audited: the mandatory intent FIRST, then the consume, both
            // naming the ticket and the attested chip.
            let ops = w.admin_ops();
            let intent = ops
                .iter()
                .position(|(op, r)| {
                    op == "rollback-consume-intent"
                        && r.contains("ticket_id=tk-1")
                        && r.contains(&format!("attested_chip={}", plat(CHIP_A)))
                        && r.contains("from_counter=2")
                })
                .expect("consume intent audited");
            let consume = ops
                .iter()
                .position(|(op, r)| {
                    op == "rollback-consume"
                        && r.contains("to_counter=5")
                        && r.contains("ticket_id=tk-1")
                        && r.contains(&format!("attested_chip={}", plat(CHIP_A)))
                })
                .expect("consume audited");
            assert!(intent < consume, "the intent precedes the consume");
        }

        /// The consume intent is MANDATORY: an admin chain that cannot take
        /// it refuses the release before anything is spent or moved, and
        /// the arm stays usable once the chain is back.
        #[test]
        fn a_consume_the_audit_log_cannot_record_is_refused_before_anything_moves() {
            let w = world();
            w.plant(arm("r-1"));
            let log = w.td.path().join("admin-audit/admin.log");
            let _ = std::fs::remove_file(&log);
            std::fs::create_dir_all(&log).unwrap();
            assert!(
                w.release(0x40, NEW_GEN, CHIP_A, Some(C_T + 1), NOW + 1)
                    .is_err(),
                "no audit row, no rollback"
            );
            assert!(
                w.audit.last_reason().contains("rollback-audit-unavailable"),
                "{:?}",
                w.audit.last_reason()
            );
            w.assert_untouched(true);
            assert!(w.vs.pending_rollback("abc").unwrap().is_none());
            assert_eq!(w.last_outcome(), None, "nothing consumed");
            // No admin chain wired at all: refused the same way.
            std::fs::remove_dir(&log).unwrap();
            assert!(w
                .release_audited(0x42, NEW_GEN, CHIP_A, Some(C_T + 1), NOW + 1, None)
                .is_err());
            assert!(w.audit.last_reason().contains("rollback-audit-unavailable"));
            w.assert_untouched(true);
            std::fs::create_dir_all(&log).unwrap();
            // Chain back: the same restore point goes through.
            std::fs::remove_dir(&log).unwrap();
            w.release(0x41, NEW_GEN, CHIP_A, Some(C_T + 1), NOW + 2)
                .expect("the arm is still live");
            assert_eq!(w.last_outcome(), Some((true, false)));
        }

        /// The arm was granted on the record of an earlier (v2) boot, but
        /// the guest the miner launches for the restore is attested as v1:
        /// refused (audited `rollback-refused(guest-not-rollback-capable)`),
        /// nothing moves, the arm stays.
        #[test]
        fn a_v1_guest_is_never_admitted_by_an_arm() {
            let w = world();
            w.plant(arm("r-1"));
            w.protocol.set(crate::volume_stamp::GUEST_STAMP_PROTOCOL_V1);
            let out = w.release(0x10, NEW_GEN, CHIP_A, Some(C_T + 1), NOW + 1);
            w.protocol.set(crate::volume_stamp::GUEST_STAMP_PROTOCOL_V2);
            assert!(out.is_err());
            w.assert_untouched(true);
            assert!(w.admin_ops().iter().any(|(op, r)| op == "rollback-refused"
                && r.contains("rollback-refused(guest-not-rollback-capable)")));
            // The same arm admits the same release from a v2 guest.
            w.release(0x11, NEW_GEN, CHIP_A, Some(C_T + 1), NOW + 1)
                .expect("a v2 guest is admitted");
        }

        #[test]
        fn no_arm_refuses_the_rewind_and_touches_nothing() {
            let w = world();
            assert!(w
                .release(0x11, NEW_GEN, CHIP_A, Some(C_T + 1), NOW + 1)
                .is_err());
            assert!(w.audit.last_reason().contains("boot-counter-rewind"));
            w.assert_untouched(false);
        }

        #[test]
        fn a_different_point_is_refused_wrong_counter() {
            let w = world();
            w.plant(arm("r-1"));
            // The host presents ANOTHER point: one whose counter is C_T-1,
            // or C_T+1 (both still rewinds).
            for (tag, submitted) in [(0x12, C_T), (0x13, C_T + 2)] {
                assert!(w
                    .release(tag, NEW_GEN, CHIP_A, Some(submitted), NOW + 1)
                    .is_err());
                w.assert_untouched(true);
            }
            assert!(w.admin_ops().iter().any(|(op, r)| op == "rollback-refused"
                && r.starts_with("rollback-refused(wrong-counter) ticket_id=tk-1 attested_chip=")));
        }

        #[test]
        fn a_different_chip_is_refused_even_when_the_row_would_admit_it() {
            let w = world();
            // The row admits chip B at NEW_GEN (as if vali re-pointed the
            // SAME gen — which activate itself refuses), the arm is bound
            // to chip A: the arm's own chip binding must refuse.
            *w.st.0.lock().unwrap() = VmState::Migrating {
                old_gen: NEW_GEN - 1,
                new_gen: NEW_GEN,
                source: plat(CHIP_A),
                dest: plat(CHIP_B),
                lease_id: "lease-1".into(),
            };
            w.plant(arm("r-1"));
            assert!(w
                .release(0x14, NEW_GEN, CHIP_B, Some(C_T + 1), NOW + 1)
                .is_err());
            w.assert_untouched(true);
            assert!(w.admin_ops().iter().any(|(_, r)| r
                .starts_with("rollback-refused(wrong-chip) ticket_id=tk-1 attested_chip=")));
        }

        #[test]
        fn a_different_generation_is_refused_even_when_the_row_would_admit_it() {
            let w = world();
            let mut a = arm("r-1");
            a.new_gen = NEW_GEN + 1;
            w.plant(a);
            assert!(w
                .release(0x15, NEW_GEN, CHIP_A, Some(C_T + 1), NOW + 1)
                .is_err());
            w.assert_untouched(true);
            assert!(w.admin_ops().iter().any(|(_, r)| r
                .starts_with("rollback-refused(wrong-generation) ticket_id=tk-1 attested_chip=")));
        }

        #[test]
        fn a_replay_after_the_consume_is_refused_and_does_not_lower_the_stamp_again() {
            let w = world();
            w.plant(arm("r-1"));
            let g = w
                .release(0x16, NEW_GEN, CHIP_A, Some(C_T + 1), NOW + 1)
                .unwrap();
            w.confirm(E_T + 1, &g).unwrap();
            // The same restore point booted a second time.
            assert!(w
                .release(0x17, NEW_GEN, CHIP_A, Some(C_T + 1), NOW + 2)
                .is_err());
            assert_eq!(w.bc.get("abc").unwrap(), STORED + 1);
            assert_eq!(
                w.vs.get("abc").unwrap(),
                E_T + 1,
                "the stamp stays where the guest put it"
            );
            assert_eq!(w.vs.token_epoch("abc").unwrap(), 1);
        }

        #[test]
        fn an_expired_arm_is_refused() {
            let w = world();
            w.plant(arm("r-1"));
            assert!(w
                .release(0x18, NEW_GEN, CHIP_A, Some(C_T + 1), NOW + 600)
                .is_err());
            w.assert_untouched(true);
            assert!(w.admin_ops().iter().any(|(_, r)| r
                .starts_with("rollback-refused(arm-expired) ticket_id=tk-1 attested_chip=")));
        }

        #[test]
        fn a_disarmed_arm_admits_nothing() {
            let w = world();
            w.plant(arm("r-1"));
            assert!(w
                .bc
                .disarm_rollback("abc", "r-1", Some(NOW))
                .unwrap()
                .is_some());
            assert!(w
                .release(0x19, NEW_GEN, CHIP_A, Some(C_T + 1), NOW + 1)
                .is_err());
            w.assert_untouched(false);
        }

        #[test]
        fn a_lifecycle_clear_leaves_nothing_to_consume() {
            let w = world();
            w.plant(arm("r-1"));
            crate::rollback::clear_for_lifecycle(
                &w.bc,
                Some(&w.admin_audit),
                "abc",
                "decommission",
                None,
                None,
                NOW,
            )
            .expect("an arm was cleared");
            assert!(w
                .release(0x1a, NEW_GEN, CHIP_A, Some(C_T + 1), NOW + 1)
                .is_err());
            w.assert_untouched(false);
            assert!(w
                .admin_ops()
                .iter()
                .any(|(op, r)| op == "rollback-lifecycle-clear"
                    && r.starts_with("lifecycle-decommission")));
        }

        #[test]
        fn a_normal_boot_clears_a_pending_arm_and_audits_it() {
            let w = world();
            w.plant(arm("r-1"));
            w.release(0x1b, NEW_GEN, CHIP_A, Some(STORED + 1), NOW + 1)
                .expect("the current disk boots normally");
            assert!(w.bc.rollback_state("abc").unwrap().0.is_none());
            assert!(w
                .admin_ops()
                .iter()
                .any(|(op, r)| op == "rollback-cleared-by-boot" && r.contains("ticket_id=tk-1")));
            // `GET …/rollback` tells vali WHY the arm is gone.
            let clear =
                w.bc.rollback_last_clear("abc")
                    .unwrap()
                    .expect("last_clear");
            assert_eq!(
                (
                    clear.restore_id.as_str(),
                    clear.reason.as_str(),
                    clear.at_unix
                ),
                ("r-1", crate::rollback::CLEAR_BY_BOOT, NOW + 1)
            );
            // …and the restore point can no longer use it.
            assert!(w
                .release(0x1c, NEW_GEN, CHIP_A, Some(C_T + 1), NOW + 2)
                .is_err());
            assert_eq!(w.bc.get("abc").unwrap(), STORED + 1);
        }

        #[test]
        fn a_non_armed_release_is_unchanged_epoch_zero_token_and_normal_stamp_path() {
            let w = world();
            // A v1 guest: exactly the response it always got.
            w.protocol.set(crate::volume_stamp::GUEST_STAMP_PROTOCOL_V1);
            let g = w
                .release(0x1d, NEW_GEN, CHIP_A, Some(STORED + 1), NOW + 1)
                .unwrap();
            assert_eq!(g.resp.expected_volume_stamp, CONFIRMED);
            let k = crate::volume_stamp::stamp_mac_key(&w.kbs_sk.to_bytes());
            assert_eq!(
                g.token,
                crate::volume_stamp::stamp_token(&k, "abc", CONFIRMED + 1).to_vec(),
                "a VM never rolled back must get the pre-epoch token bytes"
            );
            assert_eq!(g.resp.domain, RELEASE_DOMAIN);
            assert!(g.resp.volume_stamp_transition.is_none());
            // note_release counted it, exactly as before.
            assert_eq!(w.vs.row("abc").unwrap(), (CONFIRMED, 1));
            assert!(w.admin_ops().is_empty(), "no rollback event without an arm");
        }

        /// S2 — a KBS restart wipes the stamp store (emptyDir): the VM is
        /// back at `E = 0` on the zero timeline. The first v2 release moves
        /// it to a FRESH timeline (durably, before the reply) with the
        /// transition zero → fresh; a LOST response costs nothing (the
        /// retry is still at `E = 0` and draws another; the lost token
        /// never confirms); once the guest confirms, every later release
        /// expects the fresh timeline — so every disk of an earlier one
        /// (the zero timeline the VM would otherwise count from again, a
        /// pre-wipe abandoned rollback timeline) is refused by the guest
        /// gate whatever its value.
        #[test]
        fn after_a_store_wipe_a_v2_release_moves_to_a_fresh_timeline() {
            let mut w = world();
            let abandoned = [0x5b; 32];
            w.vs.apply_rollback("abc", 1, 1, "r-pre", &abandoned)
                .unwrap();
            w.vs.finalize_rollback("abc", "r-pre").unwrap();
            // The restart: the store is gone, every VM at E = 0, zero timeline.
            w.vs = InMemoryVolumeStampStore::default();
            let ids = |g: &Granted| {
                g.resp
                    .volume_stamp_transition
                    .as_ref()
                    .unwrap()
                    .ids()
                    .unwrap()
            };
            let zero = crate::volume_stamp::ZERO_TIMELINE;
            let lost = w
                .release(0x61, NEW_GEN, CHIP_A, Some(STORED + 1), NOW + 1)
                .unwrap();
            assert_eq!(lost.resp.expected_volume_stamp, 0);
            let (e1, t1) = ids(&lost);
            assert_eq!(e1, zero, "E = 0: the adopt case expects nothing");
            assert!(t1 != zero && t1 != abandoned);
            assert_eq!(w.vs.timeline("abc").unwrap(), t1, "held before the reply");
            // The response is lost; the retry draws ANOTHER fresh timeline.
            let g = w
                .release(0x62, NEW_GEN, CHIP_A, Some(STORED + 2), NOW + 2)
                .unwrap();
            let (e2, t2) = ids(&g);
            assert_eq!(e2, zero);
            assert!(t2 != zero && t2 != t1);
            assert!(w.confirm(1, &lost).is_err(), "the lost token never lands");
            assert_eq!(w.confirm(1, &g).unwrap(), 1);
            // From now on only (t2, ·) is accepted — never zero, t1 or the
            // abandoned timeline, which a normal release never names again.
            let next = w
                .release(0x63, NEW_GEN, CHIP_A, Some(STORED + 3), NOW + 3)
                .unwrap();
            assert_eq!(next.resp.expected_volume_stamp, 1);
            assert_eq!(ids(&next), (t2, t2));
            assert_eq!(w.confirm(2, &next).unwrap(), 2);
        }

        /// S2 is v2-only: a v1 guest at `E = 0` gets the pre-v2 response
        /// (no transition) and the VM stays on the zero timeline.
        #[test]
        fn a_v1_guest_at_e_zero_is_never_moved_to_a_fresh_timeline() {
            let mut w = world();
            w.vs = InMemoryVolumeStampStore::default();
            w.protocol.set(crate::volume_stamp::GUEST_STAMP_PROTOCOL_V1);
            let g = w
                .release(0x64, NEW_GEN, CHIP_A, Some(STORED + 1), NOW + 1)
                .unwrap();
            assert!(g.resp.volume_stamp_transition.is_none());
            assert_eq!(
                w.vs.timeline("abc").unwrap(),
                crate::volume_stamp::ZERO_TIMELINE
            );
            assert_eq!(w.confirm(1, &g).unwrap(), 1);
        }

        /// A v2 guest's NORMAL release: the V2 domain, a transition that
        /// expects AND targets the VM's current timeline (zero: never
        /// rolled back), a token bound to that timeline — which confirms
        /// only naming it — and the stamp path otherwise unchanged.
        #[test]
        fn a_v2_guest_normal_release_stays_on_its_timeline() {
            let w = world();
            let g = w
                .release(0x1d, NEW_GEN, CHIP_A, Some(STORED + 1), NOW + 1)
                .unwrap();
            assert_eq!(g.resp.domain, hippius_types::release::RELEASE_DOMAIN_V2);
            let (expected, target) = g
                .resp
                .volume_stamp_transition
                .as_ref()
                .unwrap()
                .ids()
                .unwrap();
            assert_eq!(expected, crate::volume_stamp::ZERO_TIMELINE);
            assert_eq!(target, crate::volume_stamp::ZERO_TIMELINE);
            assert_eq!(g.resp.expected_volume_stamp, CONFIRMED);
            let k = crate::volume_stamp::stamp_mac_key(&w.kbs_sk.to_bytes());
            assert_eq!(
                g.token,
                crate::volume_stamp::stamp_token_timeline(
                    &k,
                    "abc",
                    CONFIRMED + 1,
                    0,
                    &crate::volume_stamp::ZERO_TIMELINE
                )
                .to_vec()
            );
            assert_eq!(w.vs.row("abc").unwrap(), (CONFIRMED, 1));
            // The v1 confirm path cannot spend a timeline-bound token.
            assert!(
                crate::volume_stamp::confirm(&w.vs, &k, "abc", CONFIRMED + 1, &g.token).is_err()
            );
            assert_eq!(w.confirm(CONFIRMED + 1, &g).unwrap(), CONFIRMED + 1);
        }

        #[test]
        fn a_token_from_the_abandoned_timeline_no_longer_confirms() {
            let w = world();
            // Before the rollback: a normal boot mints a token for
            // CONFIRMED + 1 (epoch 0). The miner relays the guest's
            // confirm and so sees it in clear — keep it.
            let old = w
                .release(0x1e, NEW_GEN, CHIP_A, Some(STORED + 1), NOW + 1)
                .unwrap();
            // Rollback to a checkpoint whose stamp E_T makes E_T + 1 the
            // SAME target the captured token authorises.
            let mut a = arm("r-1");
            a.to_stamp = CONFIRMED;
            // The normal commit above cleared any arm; plant after it.
            // (rate limit: plant uses its own clock)
            w.bc.arm_rollback(a, 0, NOW + 2).unwrap();
            w.vs.record_arm_timeline("abc", "r-1", &crate::volume_stamp::ZERO_TIMELINE)
                .unwrap();
            let g = w
                .release(0x1f, NEW_GEN, CHIP_A, Some(C_T + 1), NOW + 3)
                .unwrap();
            assert_eq!(g.resp.expected_volume_stamp, CONFIRMED);
            // The abandoned-timeline token is dead…
            assert!(w.confirm(CONFIRMED + 1, &old).is_err());
            assert_eq!(w.vs.get("abc").unwrap(), CONFIRMED);
            // …the restored guest's is not.
            w.confirm(CONFIRMED + 1, &g).unwrap();
        }

        #[test]
        fn a_rollback_release_is_not_refused_by_the_abandoned_timelines_suppression_count() {
            let w = world();
            for _ in 0..10 {
                w.vs.note_release("abc").unwrap();
            }
            w.plant(arm("r-1"));
            w.release(0x20, NEW_GEN, CHIP_A, Some(C_T + 1), NOW + 1)
                .expect("the arm path resets the count instead of tripping on it");
            assert_eq!(w.vs.row("abc").unwrap(), (E_T, 0));
        }

        /// Crash between (i) and (ii), modelled as the consume write
        /// failing after the stamp was rolled back: the arm stays live, the
        /// counter does not move, the release is denied — and the retry
        /// completes under a FURTHER epoch.
        #[test]
        fn a_failure_between_the_stamp_and_the_consume_fails_closed_and_the_retry_completes() {
            let td = tempfile::tempdir().unwrap();
            let bc = FileBootCounterStore::open(td.path().join("boot-counters.json")).unwrap();
            let w = world_with(bc, td);
            w.plant(arm("r-1"));
            let blocker = w.td.path().join(".boot-counters-rollback-arms.json.tmp");
            std::fs::create_dir(&blocker).unwrap();
            assert!(w
                .release(0x21, NEW_GEN, CHIP_A, Some(C_T + 1), NOW + 1)
                .is_err());
            assert_eq!(w.bc.get("abc").unwrap(), STORED, "counter unmoved");
            assert!(
                w.bc.rollback_state("abc").unwrap().0.is_some(),
                "arm still live"
            );
            assert_eq!(w.vs.row("abc").unwrap(), (E_T, 0), "(i) already applied");
            assert_eq!(w.vs.token_epoch("abc").unwrap(), 1);
            assert!(w
                .admin_ops()
                .iter()
                .any(|(op, _)| op == "rollback-commit-failed"));
            // While the rollback is pending, NO other release may read the
            // provisionally lowered stamp — not even the current disk.
            std::fs::remove_dir(&blocker).unwrap();
            assert!(w
                .release(0x23, NEW_GEN, CHIP_A, Some(STORED + 1), NOW + 2)
                .is_err());
            assert!(w
                .audit
                .last_reason()
                .contains("volume-stamp-rollback-pending"));
            assert_eq!(w.bc.get("abc").unwrap(), STORED);
            let g = w
                .release(0x22, NEW_GEN, CHIP_A, Some(C_T + 1), NOW + 2)
                .expect("the retry completes the authorized rollback");
            assert_eq!(g.resp.boot_counter, STORED + 1);
            assert_eq!(w.vs.token_epoch("abc").unwrap(), 2);
            assert!(
                w.vs.pending_rollback("abc").unwrap().is_none(),
                "delivered ⇒ final"
            );
            w.confirm(E_T + 1, &g).unwrap();
        }

        fn failed_rollback_world() -> World<FileBootCounterStore> {
            let td = tempfile::tempdir().unwrap();
            let bc = FileBootCounterStore::open(td.path().join("boot-counters.json")).unwrap();
            let w = world_with(bc, td);
            w.plant(arm("r-1"));
            let blocker = w.td.path().join(".boot-counters-rollback-arms.json.tmp");
            std::fs::create_dir(&blocker).unwrap();
            assert!(w
                .release(0x30, NEW_GEN, CHIP_A, Some(C_T + 1), NOW + 1)
                .is_err());
            std::fs::remove_dir(&blocker).unwrap();
            assert_eq!(w.vs.row("abc").unwrap(), (E_T, 0), "(i) applied, pending");
            assert_ne!(
                w.vs.timeline("abc").unwrap(),
                crate::volume_stamp::ZERO_TIMELINE,
                "(i) moved the timeline too"
            );
            w
        }

        /// M1: a rollback applied but never delivered, whose arm is then
        /// DISARMED, must not leave the stamp lowered.
        #[test]
        fn an_undelivered_rollback_is_reverted_once_its_arm_is_disarmed() {
            let w = failed_rollback_world();
            w.bc.disarm_rollback("abc", "r-1", Some(NOW))
                .unwrap()
                .unwrap();
            let out = crate::rollback::reconcile_pending(
                "abc",
                &w.bc,
                &w.vs,
                Some(&w.admin_audit),
                NOW + 2,
            )
            .unwrap();
            assert!(matches!(
                out,
                crate::rollback::ReconcileOutcome::Reverted(_)
            ));
            assert_eq!(w.vs.row("abc").unwrap(), (CONFIRMED, 0), "stamp back");
            assert_eq!(
                w.vs.token_epoch("abc").unwrap(),
                1,
                "epoch never moves back"
            );
            assert!(w.vs.pending_rollback("abc").unwrap().is_none());
            assert_eq!(w.bc.get("abc").unwrap(), STORED);
            assert!(w
                .admin_ops()
                .iter()
                .any(|(op, _)| op == "rollback-reverted"));
            // …and the TIMELINE the rollback replaced is back: the original
            // disk is on it.
            assert_eq!(
                w.vs.timeline("abc").unwrap(),
                crate::volume_stamp::ZERO_TIMELINE
            );
            // The current disk boots normally against the ORIGINAL stamp.
            let g = w
                .release(0x31, NEW_GEN, CHIP_A, Some(STORED + 1), NOW + 3)
                .unwrap();
            assert_eq!(g.resp.expected_volume_stamp, CONFIRMED);
            assert_eq!(
                g.target_timeline,
                Some(crate::volume_stamp::ZERO_TIMELINE),
                "expects the original timeline again"
            );
        }

        /// Two failed attempts, then the arm dies: the revert must restore
        /// the row from BEFORE the first attempt, not the lowered one the
        /// second attempt found.
        #[test]
        fn a_second_failed_attempt_keeps_the_first_undo_row() {
            let w = failed_rollback_world();
            let blocker = w.td.path().join(".boot-counters-rollback-arms.json.tmp");
            std::fs::create_dir(&blocker).unwrap();
            assert!(w
                .release(0x35, NEW_GEN, CHIP_A, Some(C_T + 1), NOW + 2)
                .is_err());
            std::fs::remove_dir(&blocker).unwrap();
            assert_eq!(w.vs.token_epoch("abc").unwrap(), 2);
            w.bc.disarm_rollback("abc", "r-1", Some(NOW))
                .unwrap()
                .unwrap();
            crate::rollback::reconcile_pending("abc", &w.bc, &w.vs, None, NOW + 3).unwrap();
            assert_eq!(w.vs.row("abc").unwrap(), (CONFIRMED, 0));
        }

        /// The arm the commit finds must be the arm the release was
        /// admitted by: a store that reports one arm at admission and holds
        /// another at commit must refuse, before the stamp moves.
        #[test]
        fn an_arm_that_changed_between_admission_and_commit_is_refused() {
            struct Skewed(InMemoryBootCounterStore);
            impl BootCounterStore for Skewed {
                fn check_only(&self, v: &str, s: u64) -> Result<u64> {
                    self.0.check_only(v, s)
                }
                fn commit(&self, v: &str, x: u64) -> Result<()> {
                    self.0.commit(v, x)
                }
                fn get(&self, v: &str) -> Result<u64> {
                    self.0.get(v)
                }
                fn seed(&self, v: &str, x: u64) -> Result<crate::boot_counter::SeedOutcome> {
                    self.0.seed(v, x)
                }
                fn arm_resync(&self, v: &str) -> Result<crate::boot_counter::ResyncOutcome> {
                    self.0.arm_resync(v)
                }
                fn resync_armed(&self, v: &str) -> Result<bool> {
                    self.0.resync_armed(v)
                }
                fn arm_rollback(
                    &self,
                    a: RollbackArm,
                    m: u64,
                    n: u64,
                ) -> Result<ArmRollbackOutcome> {
                    self.0.arm_rollback(a, m, n)
                }
                // Admission sees a DIFFERENT (lower) stamp than the arm
                // the commit will find.
                fn rollback_state(
                    &self,
                    v: &str,
                ) -> Result<(Option<RollbackArm>, Option<crate::rollback::LastRollback>)>
                {
                    let (a, l) = self.0.rollback_state(v)?;
                    Ok((
                        a.map(|mut a| {
                            a.to_stamp = 0;
                            a
                        }),
                        l,
                    ))
                }
                fn commit_rollback(
                    &self,
                    v: &str,
                    r: &str,
                    x: u64,
                    n: u64,
                    f: &mut dyn FnMut(&RollbackArm) -> Result<()>,
                ) -> Result<RollbackArm> {
                    self.0.commit_rollback(v, r, x, n, f)
                }
            }
            let w = world_with(
                Skewed(InMemoryBootCounterStore::default()),
                tempfile::tempdir().unwrap(),
            );
            w.plant(arm("r-1"));
            assert!(w
                .release(0x36, NEW_GEN, CHIP_A, Some(C_T + 1), NOW + 1)
                .is_err());
            assert_eq!(w.vs.row("abc").unwrap(), (CONFIRMED, 0), "stamp untouched");
            assert_eq!(w.bc.get("abc").unwrap(), STORED);
        }

        /// M1 (expiry): the next release itself reverts a pending rollback
        /// whose arm expired, BEFORE reading the stamp.
        #[test]
        fn the_next_release_reverts_a_pending_rollback_whose_arm_expired() {
            let w = failed_rollback_world();
            let g = w
                .release(0x32, NEW_GEN, CHIP_A, Some(STORED + 1), NOW + 600)
                .expect("the arm is dead: reverted, then a normal boot");
            assert_eq!(g.resp.expected_volume_stamp, CONFIRMED);
            assert!(w.vs.pending_rollback("abc").unwrap().is_none());
        }

        /// Review HIGH: an `activate`/fence landing AFTER the rollback
        /// committed makes 11d deny — the stamp must then go back, so the
        /// rollback never benefits the generation that holds the VM next.
        #[test]
        fn a_fence_landing_after_the_commit_reverts_the_stamp_and_releases_nothing() {
            let w = world();
            w.plant(arm("r-1"));
            // Reads 1-3 (gate 5, gate 9, in-lock check) see the arm's row;
            // 11d sees the next hop.
            w.st.switch_after(
                3,
                VmState::Migrating {
                    old_gen: NEW_GEN,
                    new_gen: NEW_GEN + 1,
                    source: plat(CHIP_A),
                    dest: plat(CHIP_B),
                    lease_id: "lease-1".into(),
                },
            );
            assert!(w
                .release(0x33, NEW_GEN, CHIP_A, Some(C_T + 1), NOW + 1)
                .is_err());
            assert_eq!(w.vs.row("abc").unwrap(), (CONFIRMED, 0), "stamp reverted");
            assert!(w.vs.pending_rollback("abc").unwrap().is_none());
            assert_eq!(
                w.bc.get("abc").unwrap(),
                STORED + 1,
                "counter never moves down"
            );
            assert!(w.bc.rollback_state("abc").unwrap().0.is_none(), "arm spent");
            // Consumed, but NOT delivered: reported reverted.
            assert_eq!(w.last_outcome(), Some((false, true)));
            assert!(w
                .admin_ops()
                .iter()
                .any(|(op, r)| op == "rollback-commit-failed" && r.contains("reverted=true")));
            assert!(!w.admin_ops().iter().any(|(op, _)| op == "rollback-consume"));
        }

        /// An `activate` that landed BEFORE the commit stops the rollback
        /// under the counter lock, before the stamp moves.
        #[test]
        fn an_activate_before_the_commit_stops_it_before_the_stamp_moves() {
            let w = world();
            w.plant(arm("r-1"));
            w.st.switch_after(
                2,
                VmState::Migrating {
                    old_gen: NEW_GEN,
                    new_gen: NEW_GEN + 1,
                    source: plat(CHIP_A),
                    dest: plat(CHIP_B),
                    lease_id: "lease-1".into(),
                },
            );
            assert!(w
                .release(0x34, NEW_GEN, CHIP_A, Some(C_T + 1), NOW + 1)
                .is_err());
            w.assert_untouched(true);
            assert!(w.vs.pending_rollback("abc").unwrap().is_none());
        }

        /// A rollback whose release is IN FLIGHT (consumed moments ago,
        /// not yet finalized) is kept; past the grace it is reverted.
        #[test]
        fn a_consumed_but_unfinalized_rollback_is_kept_in_flight_then_reverted() {
            let w = world();
            w.plant(arm("r-1"));
            let mut apply = |a: &RollbackArm| {
                w.vs.apply_rollback("abc", a.to_stamp, 1, &a.restore_id, &[0x77; 32])
            };
            w.bc.commit_rollback("abc", "r-1", STORED + 1, NOW + 1, &mut apply)
                .unwrap();
            let kept = crate::rollback::reconcile_pending(
                "abc",
                &w.bc,
                &w.vs,
                None,
                NOW + crate::rollback::IN_FLIGHT_GRACE_S,
            )
            .unwrap();
            assert!(matches!(
                kept,
                crate::rollback::ReconcileOutcome::Kept { .. }
            ));
            assert_eq!(w.vs.row("abc").unwrap(), (E_T, 0));
            assert_eq!(w.last_outcome(), Some((false, false)), "in flight");
            let gone = crate::rollback::reconcile_pending(
                "abc",
                &w.bc,
                &w.vs,
                None,
                NOW + 1 + crate::rollback::IN_FLIGHT_GRACE_S,
            )
            .unwrap();
            assert!(matches!(
                gone,
                crate::rollback::ReconcileOutcome::Reverted(_)
            ));
            assert_eq!(w.vs.row("abc").unwrap(), (CONFIRMED, 0));
            assert_eq!(
                w.last_outcome(),
                Some((false, true)),
                "reverted, never delivered"
            );
        }

        const ZT: [u8; 32] = crate::volume_stamp::ZERO_TIMELINE;

        /// B1, KBS side. The rollback release expects the restored point's
        /// timeline and targets a FRESH one; the commit moves the VM onto
        /// it; every later release expects and targets THAT timeline, so
        /// a disk of the abandoned timeline — which carries the very
        /// numbers the restored timeline writes next — is never expected
        /// again, whatever its value (the guest's gate refuses it; see
        /// scripts/dev/golden-stamp-test.sh §16).
        #[test]
        fn a_rollback_moves_the_vm_to_a_fresh_timeline_that_every_later_release_expects() {
            let w = world();
            let from = [0x5c; 32];
            w.plant_on(arm("r-1"), from);
            let g = w
                .release(0x50, NEW_GEN, CHIP_A, Some(C_T + 1), NOW + 1)
                .unwrap();
            assert_eq!(g.resp.domain, hippius_types::release::RELEASE_DOMAIN_V2);
            let (expected, target) = g
                .resp
                .volume_stamp_transition
                .as_ref()
                .unwrap()
                .ids()
                .unwrap();
            assert_eq!(expected, from, "the restored point's timeline is expected");
            assert_ne!(target, from, "a FRESH target");
            assert_ne!(target, ZT);
            assert_ne!(target, ZT, "never the VM's previous timeline");
            assert_eq!(
                w.vs.timeline("abc").unwrap(),
                target,
                "the commit moved the VM"
            );
            // The confirm lands on the new timeline only.
            let k = crate::volume_stamp::stamp_mac_key(&w.kbs_sk.to_bytes());
            assert!(crate::volume_stamp::confirm_timeline(
                &w.vs,
                &k,
                "abc",
                E_T + 1,
                &g.token,
                &from
            )
            .is_err());
            assert!(crate::volume_stamp::confirm(&w.vs, &k, "abc", E_T + 1, &g.token).is_err());
            assert_eq!(w.vs.get("abc").unwrap(), E_T);
            w.confirm(E_T + 1, &g).unwrap();
            // Every later release: target -> target, never the abandoned one.
            for (tag, counter) in [(0x51u8, STORED + 2), (0x52, STORED + 3)] {
                let n = w
                    .release(tag, NEW_GEN, CHIP_A, Some(counter), NOW + 2)
                    .unwrap();
                let (e2, t2) = n
                    .resp
                    .volume_stamp_transition
                    .as_ref()
                    .unwrap()
                    .ids()
                    .unwrap();
                assert_eq!((e2, t2), (target, target));
                w.confirm(n.resp.expected_volume_stamp + 1, &n).unwrap();
            }
            // The audit rows name both timelines.
            assert!(w.admin_ops().iter().any(|(op, r)| op == "rollback-consume"
                && r.contains(&format!("timeline_from={}", hex::encode(from)))
                && r.contains(&format!("timeline_to={}", hex::encode(target)))));
        }

        /// R4 — gate 5c' (the `E == 0` fresh-timeline move) must NEVER
        /// run for an admitted rollback, even one whose arm restores to
        /// `to_stamp = 0` (the admin route refuses such a checkpoint; this
        /// arm is planted to force the `E == 0` rollback arm through the
        /// release). The rollback release keeps ITS transition — the
        /// restored point's timeline → the fresh target its commit installs —
        /// and is not rewritten into a zero → fresh adopt (which would drop
        /// the restored point's timeline and move the VM twice).
        #[test]
        fn gate_5c_prime_never_rewrites_an_admitted_rollback_at_e_zero() {
            let w = world();
            let from = [0x5c; 32];
            let mut a = arm("r-0");
            a.to_stamp = 0;
            w.plant_on(a, from);
            let g = w
                .release(0x5f, NEW_GEN, CHIP_A, Some(C_T + 1), NOW + 1)
                .unwrap();
            assert_eq!(g.resp.expected_volume_stamp, 0, "the arm's E_T = 0");
            let (expected, target) = g
                .resp
                .volume_stamp_transition
                .as_ref()
                .unwrap()
                .ids()
                .unwrap();
            assert_eq!(
                expected, from,
                "the rollback's transition, never gate 5c''s zero -> fresh"
            );
            assert_ne!(target, from);
            assert_ne!(target, ZT);
            assert_eq!(
                w.vs.timeline("abc").unwrap(),
                target,
                "the VM is on the rollback's target, not a 5c' timeline"
            );
        }

        /// A VM moved to a non-zero timeline releases ONLY to a guest that
        /// attested v2: a v1 guest compares the value alone and would take
        /// an abandoned-timeline disk. Refused before anything moves, however
        /// the v1 attestation came about.
        #[test]
        fn a_v1_guest_is_refused_once_the_vm_is_on_a_rolled_back_timeline() {
            let w = world();
            w.plant(arm("r-1"));
            let g = w
                .release(0x53, NEW_GEN, CHIP_A, Some(C_T + 1), NOW + 1)
                .unwrap();
            let target = g.target_timeline.unwrap();
            w.protocol.set(crate::volume_stamp::GUEST_STAMP_PROTOCOL_V1);
            let before = (w.bc.get("abc").unwrap(), w.vs.row("abc").unwrap());
            assert!(w
                .release(0x54, NEW_GEN, CHIP_A, Some(STORED + 2), NOW + 2)
                .is_err());
            assert!(
                w.audit
                    .last_reason()
                    .contains("volume-stamp-timeline-requires-v2"),
                "{}",
                w.audit.last_reason()
            );
            assert_eq!((w.bc.get("abc").unwrap(), w.vs.row("abc").unwrap()), before);
            assert_eq!(w.vs.timeline("abc").unwrap(), target);
            // …and the refused v1 attempt did not demote the VM's record:
            // it stays armable (a miner-forged 403 buys nothing).
            assert_eq!(
                w.vs.guest_stamp_protocol("abc").unwrap(),
                crate::volume_stamp::GUEST_STAMP_PROTOCOL_V2
            );
            // The same boot attested v2 goes through.
            w.protocol.set(crate::volume_stamp::GUEST_STAMP_PROTOCOL_V2);
            w.release(0x55, NEW_GEN, CHIP_A, Some(STORED + 2), NOW + 2)
                .expect("a v2 guest on the new timeline");
        }

        /// A LOST first rollback response fails closed: the KBS committed
        /// the move to T_new, the guest never wrote it, so every later
        /// release expects T_new and the restored disk (still on the old
        /// timeline) is refused by the gate. A NEW authorized rollback of
        /// the same point recovers it, to ANOTHER fresh timeline — T_new
        /// is never issued again.
        #[test]
        fn a_lost_first_rollback_response_fails_closed_and_a_new_arm_recovers() {
            let w = world();
            let from = [0x5c; 32];
            w.plant_on(arm("r-1"), from);
            let lost = w
                .release(0x56, NEW_GEN, CHIP_A, Some(C_T + 1), NOW + 1)
                .unwrap();
            let t_new = lost.target_timeline.unwrap();
            // The guest never saw it: its next boot is a normal release,
            // which expects T_new — not the disk's timeline.
            let next = w
                .release(0x57, NEW_GEN, CHIP_A, Some(STORED + 2), NOW + 2)
                .unwrap();
            let (e, t) = next
                .resp
                .volume_stamp_transition
                .as_ref()
                .unwrap()
                .ids()
                .unwrap();
            assert_eq!((e, t), (t_new, t_new));
            assert_ne!(e, from, "the restored disk's timeline is not expected");
            // vali arms the same point again (a new restore id).
            let mut again = arm("r-2");
            again.armed_at_unix = NOW + 3;
            again.expires_at_unix = NOW + 600;
            w.bc.arm_rollback(again, 0, NOW + 3).unwrap();
            w.vs.record_arm_timeline("abc", "r-2", &from).unwrap();
            let g = w
                .release(0x58, NEW_GEN, CHIP_A, Some(C_T + 1), NOW + 4)
                .unwrap();
            let (e2, t2) = g
                .resp
                .volume_stamp_transition
                .as_ref()
                .unwrap()
                .ids()
                .unwrap();
            assert_eq!(e2, from);
            assert_ne!(t2, t_new, "the lost T_new is never issued again");
            assert_ne!(t2, from);
            assert_eq!(w.vs.timeline("abc").unwrap(), t2);
        }

        /// An arm whose checkpoint timeline was never recorded admits
        /// nothing (`arm-timeline-missing`): no unbound rollback.
        #[test]
        fn an_arm_without_a_recorded_timeline_admits_nothing() {
            let w = world();
            assert!(matches!(
                w.bc.arm_rollback(arm("r-1"), 1800, NOW).unwrap(),
                ArmRollbackOutcome::Armed(_)
            ));
            assert!(w
                .release(0x59, NEW_GEN, CHIP_A, Some(C_T + 1), NOW + 1)
                .is_err());
            w.assert_untouched(true);
            assert_eq!(w.vs.timeline("abc").unwrap(), ZT);
            assert!(w.admin_ops().iter().any(|(op, r)| op == "rollback-refused"
                && r.contains("rollback-refused(arm-timeline-missing)")));
            // A timeline recorded for ANOTHER restore id does not count.
            w.vs.record_arm_timeline("abc", "r-other", &ZT).unwrap();
            assert!(w
                .release(0x5a, NEW_GEN, CHIP_A, Some(C_T + 1), NOW + 1)
                .is_err());
            w.assert_untouched(true);
        }

        /// A stamp store where an authorized rollback's stamp step lands
        /// right AFTER a normal release read the stamp (between 5b' and
        /// the commit) — the TOCTOU the guarded commit closes.
        #[derive(Default)]
        pub(super) struct RacyStamps {
            inner: InMemoryVolumeStampStore,
            fire: std::sync::atomic::AtomicBool,
        }
        impl VolumeStampStore for RacyStamps {
            fn get(&self, v: &str) -> Result<u64> {
                self.inner.get(v)
            }
            fn note_release(&self, v: &str) -> Result<(u64, u64)> {
                let out = self.inner.note_release(v)?;
                if self.fire.swap(false, std::sync::atomic::Ordering::SeqCst) {
                    let next = self.inner.token_epoch(v)? + 1;
                    self.inner
                        .apply_rollback(v, E_T, next, "r-race", &[0x66; 32])?;
                }
                Ok(out)
            }
            fn confirm(&self, v: &str, x: u64) -> Result<u64> {
                self.inner.confirm(v, x)
            }
            fn admin_reset_unconfirmed(&self, v: &str) -> Result<u64> {
                self.inner.admin_reset_unconfirmed(v)
            }
            fn snapshot(&self) -> Result<Vec<crate::volume_stamp::VolumeStampStatus>> {
                self.inner.snapshot()
            }
            fn token_epoch(&self, v: &str) -> Result<u64> {
                self.inner.token_epoch(v)
            }
            fn confirm_at_epoch(&self, v: &str, x: u64, e: u64) -> Result<u64> {
                self.inner.confirm_at_epoch(v, x, e)
            }
            fn apply_rollback(&self, v: &str, c: u64, e: u64, r: &str, t: &[u8; 32]) -> Result<()> {
                self.inner.apply_rollback(v, c, e, r, t)
            }
            fn timeline(&self, v: &str) -> Result<[u8; 32]> {
                self.inner.timeline(v)
            }
            fn confirm_at(&self, v: &str, x: u64, e: u64, t: &[u8; 32]) -> Result<u64> {
                self.inner.confirm_at(v, x, e, t)
            }
            fn record_arm_timeline(&self, v: &str, r: &str, t: &[u8; 32]) -> Result<()> {
                self.inner.record_arm_timeline(v, r, t)
            }
            fn adopt_fresh_timeline(&self, v: &str, t: &[u8; 32]) -> Result<()> {
                self.inner.adopt_fresh_timeline(v, t)
            }
            fn arm_timeline(&self, v: &str, r: &str) -> Result<Option<[u8; 32]>> {
                self.inner.arm_timeline(v, r)
            }
            fn pending_rollback(
                &self,
                v: &str,
            ) -> Result<Option<crate::volume_stamp::PendingRollback>> {
                self.inner.pending_rollback(v)
            }
            fn guest_stamp_protocol(&self, v: &str) -> Result<u8> {
                self.inner.guest_stamp_protocol(v)
            }
            fn record_guest_stamp_protocol(&self, v: &str, p: u8) -> Result<()> {
                self.inner.record_guest_stamp_protocol(v, p)
            }
        }

        /// The rollback's stamp step lands after a normal release read the
        /// stamp, then is REVERTED before that release commits (its arm
        /// consume failed, then vali disarmed it): nothing is pending any
        /// more and the epoch the release minted under is the current one —
        /// but the expectation it read (the lowered one, on the rollback's
        /// timeline) is not the VM's. Only the timeline re-check sees it.
        #[derive(Default)]
        pub(super) struct RevertingStamps {
            inner: InMemoryVolumeStampStore,
            fire: std::sync::atomic::AtomicBool,
            applied: std::sync::atomic::AtomicBool,
        }
        impl VolumeStampStore for RevertingStamps {
            fn get(&self, v: &str) -> Result<u64> {
                self.inner.get(v)
            }
            fn note_release(&self, v: &str) -> Result<(u64, u64)> {
                if self.fire.swap(false, std::sync::atomic::Ordering::SeqCst) {
                    let next = self.inner.token_epoch(v)? + 1;
                    self.inner
                        .apply_rollback(v, E_T, next, "r-race", &[0x66; 32])?;
                    self.applied
                        .store(true, std::sync::atomic::Ordering::SeqCst);
                }
                self.inner.note_release(v)
            }
            fn confirm(&self, v: &str, x: u64) -> Result<u64> {
                self.inner.confirm(v, x)
            }
            fn admin_reset_unconfirmed(&self, v: &str) -> Result<u64> {
                self.inner.admin_reset_unconfirmed(v)
            }
            fn snapshot(&self) -> Result<Vec<crate::volume_stamp::VolumeStampStatus>> {
                self.inner.snapshot()
            }
            fn token_epoch(&self, v: &str) -> Result<u64> {
                self.inner.token_epoch(v)
            }
            fn timeline(&self, v: &str) -> Result<[u8; 32]> {
                self.inner.timeline(v)
            }
            fn adopt_fresh_timeline(&self, v: &str, t: &[u8; 32]) -> Result<()> {
                self.inner.adopt_fresh_timeline(v, t)
            }
            fn pending_rollback(
                &self,
                v: &str,
            ) -> Result<Option<crate::volume_stamp::PendingRollback>> {
                // The guard's read: the rollback is reverted just before.
                if self
                    .applied
                    .swap(false, std::sync::atomic::Ordering::SeqCst)
                {
                    self.inner.revert_rollback(v, "r-race")?;
                }
                self.inner.pending_rollback(v)
            }
            fn guest_stamp_protocol(&self, v: &str) -> Result<u8> {
                self.inner.guest_stamp_protocol(v)
            }
            fn record_guest_stamp_protocol(&self, v: &str, p: u8) -> Result<()> {
                self.inner.record_guest_stamp_protocol(v, p)
            }
        }

        #[test]
        fn a_normal_release_whose_read_a_reverted_rollback_touched_is_refused_at_commit() {
            let w = world_with_stamps::<InMemoryBootCounterStore, RevertingStamps>(
                InMemoryBootCounterStore::default(),
                tempfile::tempdir().unwrap(),
            );
            w.vs.fire.store(true, std::sync::atomic::Ordering::SeqCst);
            assert!(w
                .release(0x41, NEW_GEN, CHIP_A, Some(STORED + 1), NOW + 1)
                .is_err());
            assert!(
                w.audit
                    .last_reason()
                    .contains("volume-stamp-rollback-raced"),
                "{}",
                w.audit.last_reason()
            );
            assert_eq!(w.bc.get("abc").unwrap(), STORED, "no commit, no key");
            assert_eq!(w.vs.row("abc").unwrap().0, CONFIRMED, "reverted");
        }

        #[test]
        fn a_normal_release_racing_a_rollback_stamp_step_is_refused_at_commit() {
            let w = world_with_stamps::<InMemoryBootCounterStore, RacyStamps>(
                InMemoryBootCounterStore::default(),
                tempfile::tempdir().unwrap(),
            );
            w.vs.fire.store(true, std::sync::atomic::Ordering::SeqCst);
            assert!(w
                .release(0x40, NEW_GEN, CHIP_A, Some(STORED + 1), NOW + 1)
                .is_err());
            assert!(w
                .audit
                .last_reason()
                .contains("volume-stamp-rollback-raced"));
            assert_eq!(w.bc.get("abc").unwrap(), STORED, "no commit, no key");
        }
    }
}
