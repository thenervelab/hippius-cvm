//! The KBS service-layer trait the transport calls into.
//!
//! Decoupling the HTTP handlers from [`kbs_core::release::Deps`] means:
//! - the transport can be tested with a tiny mock (no SNP/Vault stubs);
//! - the production wiring lives in one place (`DefaultKbsService`);
//! - alternative front-doors (gRPC, in-process) can target the same trait.

use ed25519_dalek::SigningKey;
use hippius_types::custody::{CustodyBindRequest, CustodyRekeyRequest, CustodyRenewRequest};
use hippius_types::host_attestor::{HostEnrollment, SignedHostAttestorCert};
use hippius_types::live_attestation::{GuestComponents, GuestResources, SignedLiveAttestation};
use hippius_types::release::{SignedDenial, SignedResponse};
use kbs_core::boot_counter::BootCounterStore;
use kbs_core::custody::{CustodyDeps, CustodyReply, CustodyRuntime};
use kbs_core::error::Result;
use kbs_core::evidence::EvidenceSink;
use kbs_core::host_attestor::{
    process_host_attestation, HostAttestationDeps, HostAttestationRequest,
};
use kbs_core::keepalive::{process_keepalive, KeepaliveDeps, KeepaliveRequest};
use kbs_core::keepalive_binding::{
    self, BindingMode, InMemoryKeepaliveBindings, KeepaliveBindingStore,
};
use kbs_core::lifecycle::VmStateStore;
use kbs_core::live_attestation::{LiveAttestationSink, LiveAttestationStateStore};
use kbs_core::persist::KbsNonceStore;
use kbs_core::release::{process_release, AuditSink, Deps, ReleaseRequest};
use kbs_core::replay::ReleaseStore;
use kbs_core::snp::{AttestationVerifier, LaunchPolicy, MeasurementAllowlist, VerifiedReport};
use kbs_core::ticket::L1Keyring;
use kbs_core::vault::{AttestedVaultAuth, VaultKv};
use kbs_core::volume_stamp::VolumeStampStore;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

/// Run nonce-store GC every N successful issuances. Bound by the rate
/// limiter at 100/sec by default, so a GC sweep happens at most a few
/// times per second under load — cheap relative to a Vault round trip.
pub const GC_EVERY_N_ISSUANCES: u64 = 256;

/// 32 — re-exported here so trait users don't have to reach into `wire`.
pub const NONCE_LEN: usize = crate::wire::NONCE_LEN;

/// Validity window the KBS stamps on a freshly minted host-attestor
/// enrollment cert (blackbox host-attestor chantier — PR-10b-S2b).
///
/// The attestor re-enrols per boot and hourly (blackbox plan), so a
/// 2-hour window survives one missed re-enrolment while still bounding
/// how long a rotated/withdrawn attestor key stays trusted. The KBS
/// picks this itself — the enroll request never carries an expiry — so a
/// lying/untrusted relay cannot ask for a long-lived cert. `now_unix +
/// TTL` is passed to [`kbs_core::host_attestor::process_host_attestation`]
/// as `expiry_unix` (which fail-closes on `expiry <= now`).
pub const HOST_ATTESTOR_CERT_TTL_SECS: u64 = 2 * 60 * 60;

/// High-level KBS operations exposed to the transport layer.
///
/// Implementations MUST be `Send + Sync` (axum hands them to per-request
/// tasks across worker threads).
pub trait KbsService: Send + Sync {
    /// Mint and durably record a fresh KBS nonce (§7). The nonce is the
    /// freshness primitive the guest folds into `REPORT_DATA[0..32]`; the
    /// store rejects any later release that doesn't reference a minted,
    /// unspent, unexpired nonce.
    fn issue_nonce(&self, now_unix: u64) -> Result<[u8; NONCE_LEN]>;

    /// Run the full §7/§21 release pipeline against an attested guest.
    /// `Ok` is the KBS-signed wrapped-secret response; `Err` is the
    /// KBS-signed denial (the protocol's negative-acknowledgement form —
    /// the caller MUST treat both as legitimate protocol outcomes).
    ///
    /// `submitted_boot_counter` (audit follow-up Review #2): when
    /// `Some(n)`, the release path verifies `n == stored + 1` and
    /// advances the store before reading Vault. `None` short-
    /// circuits the check for backward compat with pre-Phase-2A
    /// guests.
    fn process_release(
        &self,
        cose_ticket: &[u8],
        raw_snp_report: &[u8],
        kbs_nonce: &[u8; NONCE_LEN],
        now_unix: u64,
        submitted_boot_counter: Option<u64>,
    ) -> core::result::Result<SignedResponse, SignedDenial>;

    /// Run the §322 keepalive pipeline — verify a fresh SNP report
    /// from inside a tenant CVM and return a KBS-L0-signed
    /// `SignedLiveAttestation` the validator can submit on-chain via
    /// `pallet-compute-scoring::submit_live_attestation`.
    ///
    /// Returns `Err(KbsError)` on any verification failure (audit
    /// records the reason; nothing is signed, the nonce is NOT
    /// spent, the per-VM chain is NOT advanced). Unlike `release`,
    /// the denial form is NOT a signed envelope here — the
    /// keepalive flow has no tenant-facing protocol contract; the
    /// validator just sees an error and retries.
    #[allow(clippy::too_many_arguments)]
    fn process_keepalive(
        &self,
        vm_id: &str,
        node_id: &[u8; NONCE_LEN],
        raw_snp_report: &[u8],
        kbs_nonce: &[u8; NONCE_LEN],
        epoch: u64,
        expiry_unix: u64,
        resources: Option<&GuestResources>,
        components: Option<&GuestComponents>,
        now_unix: u64,
    ) -> Result<SignedLiveAttestation>;

    /// Verify a relayed blackbox **host-attestor** enrollment and, on
    /// success, mint a KBS-L0-signed
    /// [`SignedHostAttestorCert`](hippius_types::host_attestor::SignedHostAttestorCert)
    /// (blackbox host-attestor chantier — PR-10b-S2b).
    ///
    /// This is a thin adapter over
    /// [`kbs_core::host_attestor::process_host_attestation`] — it reuses
    /// the SAME AMD verifier, §22 offline allowlist (the host-attestor
    /// measurement-class gate lives inside `process_host_attestation`),
    /// and L0 signing key as the release/keepalive flows. No new key
    /// path, no second verifier.
    ///
    /// `nonce` is the vali-minted single-use nonce the guest folded into
    /// `REPORT_DATA[0..32]`; the caller (the S2a relay) supplies it. The
    /// KBS binds it into the cert but does **not** check its
    /// freshness/single-use — that is vali's job at cert-ingest (PR-8 /
    /// PR-10). A wrong `nonce` simply fails the `REPORT_DATA` byte-match
    /// inside `process_host_attestation`, so nothing is minted.
    ///
    /// The cert `expiry_unix` is KBS-decided (`now + `
    /// [`HOST_ATTESTOR_CERT_TTL_SECS`]) — never taken from the untrusted
    /// request. Returns `Err(KbsError)` on ANY verification failure (the
    /// audit sink records the reason; nothing is signed).
    fn process_host_enroll(
        &self,
        enrollment: &HostEnrollment,
        nonce: &[u8; NONCE_LEN],
        now_unix: u64,
    ) -> Result<SignedHostAttestorCert>;

    /// `POST /v1/kbs/volume-stamp/confirm` — advance the guest-keyed
    /// overlay's CONFIRMED volume stamp for `vm_id` to `value`.
    ///
    /// This is the ONLY thing that moves `kbs_core::volume_stamp`; the
    /// release path only reads it (see [`Deps::volume_stamp`] and the
    /// module docs — advancing it anywhere else reintroduces the
    /// accumulating-gap remote-brick bug the store exists to avoid). The
    /// call is authenticated by `token`, the single-use authenticator the
    /// guest unwrapped from `KbsResponse::volume_stamp_token` in the
    /// release that echoed `expected_volume_stamp == value - 1`; a
    /// bad/absent token or a `value` that is not exactly `stored + 1`
    /// refuses fail-closed WITHOUT touching the store.
    fn process_volume_stamp_confirm(&self, vm_id: &str, value: u64, token: &[u8]) -> Result<u64>;

    /// The stamp-protocol-v2 confirm: the guest names the TIMELINE it
    /// stamped (the `target` of its release's `volume_stamp_transition`),
    /// and only the token minted for that timeline, while it is still the
    /// VM's current one, advances the stamp
    /// (`kbs_core::volume_stamp::confirm_timeline`). The default refuses —
    /// an implementation without timelines can confirm nothing on one.
    fn process_volume_stamp_confirm_timeline(
        &self,
        vm_id: &str,
        value: u64,
        _token: &[u8],
        _timeline: &[u8; 32],
    ) -> Result<u64> {
        Err(kbs_core::error::KbsError::Policy(format!(
            "volume-stamp confirm: vm_id={vm_id} value={value} — this KBS has no timelines, \
             fail closed"
        )))
    }

    /// `POST /v1/kbs/custody/bind` (see `kbs_core::custody`). The default
    /// is custody switched off — every implementation that does not wire
    /// a `CustodyRuntime` answers 404 `custody-disabled`.
    fn process_custody_bind(&self, _req: &CustodyBindRequest, _now_unix: u64) -> CustodyReply {
        CustodyReply::disabled()
    }

    /// `POST /v1/kbs/custody/renew`.
    fn process_custody_renew(&self, _req: &CustodyRenewRequest, _now_unix: u64) -> CustodyReply {
        CustodyReply::disabled()
    }

    /// `POST /v1/kbs/custody/rekey`.
    fn process_custody_rekey(&self, _req: &CustodyRekeyRequest, _now_unix: u64) -> CustodyReply {
        CustodyReply::disabled()
    }
}

/// Reference implementation. Each kbs-core trait lives behind an `Arc<dyn
/// Trait + Send + Sync>` so production swaps (file-backed vs in-memory
/// stores, fake vs real Vault) compose without touching the transport.
pub struct DefaultKbsService {
    pub l1_keyring: Arc<dyn L1Keyring + Send + Sync>,
    pub attn: Arc<dyn AttestationVerifier + Send + Sync>,
    pub offline_allowlist: Arc<dyn MeasurementAllowlist + Send + Sync>,
    pub launch_policy: Arc<LaunchPolicy>,
    pub vm_states: Arc<dyn VmStateStore + Send + Sync>,
    pub release_store: Arc<dyn ReleaseStore + Send + Sync>,
    pub kbs_nonce_store: Arc<dyn KbsNonceStore + Send + Sync>,
    pub vault_auth: Arc<dyn AttestedVaultAuth + Send + Sync>,
    pub vault_kv: Arc<dyn VaultKv + Send + Sync>,
    pub kbs_attestation: Arc<VerifiedReport>,
    pub kbs_auth_pubkey: Arc<Vec<u8>>,
    pub kbs_signing_key: Arc<SigningKey>,
    pub kbs_kid: Arc<Vec<u8>>,
    pub audit: Arc<dyn AuditSink + Send + Sync>,
    /// §280 per-release evidence-bundle sink. Best-effort persistence
    /// of the cryptographic raw materials a tenant verifier needs
    /// (SNP report bytes, VCEK chain, allowlist epoch + manifest
    /// digest, ticket bytes) signed by the KBS L0 key. A
    /// `NullEvidenceSink` is passed when the operator hasn't
    /// bootstrapped a directory for it.
    pub evidence: Arc<dyn EvidenceSink>,
    /// §322 per-VM live-attestation chain state. Durable: the
    /// pallet's monotonic `attestation_seq + prev_attestation_hash`
    /// chain depends on this; a crash-induced rewind would break
    /// the chain at the next keepalive (fail-closed).
    pub live_attestation_state: Arc<dyn LiveAttestationStateStore>,
    /// §322 per-VM live-attestation archive. Best-effort: the
    /// validator batcher reads these to submit to chain (a missed
    /// archive write means the validator picks up the attestation
    /// from the next keepalive instead — `LiveAttestationCount` on
    /// chain is what the ranker uses).
    pub live_attestation_sink: Arc<dyn LiveAttestationSink>,
    /// 32-byte substrate compute-chain genesis discriminator —
    /// pinned at config load. Copied into every signed live-
    /// attestation body the KBS issues; the pallet enforces
    /// `view.chain_genesis == T::ComputeChainGenesis::get()`.
    pub compute_chain_genesis: [u8; 32],
    /// 32-byte compute-pallet instance discriminator — same
    /// discipline.
    pub compute_pallet_instance: [u8; 32],
    /// Per-VM monotonic boot counter (Phase 1 of audit follow-up
    /// Review #2 — anti-rollback for valid-old-ciphertext replay).
    /// Today the release path ONLY advances the counter when the
    /// guest submits `submitted_boot_counter: Some(_)` in the
    /// `ReleaseRequest`. Until Phase 2 wires the guest to read +
    /// write the counter from durable storage, this field is mostly
    /// dormant — but the wire format is fixed, so a future operator
    /// flip enables enforcement without an admin-API migration.
    /// See [`kbs_core::boot_counter`].
    pub boot_counter: Arc<dyn BootCounterStore>,
    /// KEK-HSM RA-08a/F2 — when `true`, the release path REFUSES a KEK that
    /// is not Vault-Transit-wrapped (`vault:` prefix). Default `false`
    /// (set via [`Self::with_require_wrapped_kek`] from KBS config) for a
    /// zero-behavior-change rollout, then flipped on once every staging
    /// path wraps and no legacy plaintext KEK is in use.
    pub require_wrapped_kek: bool,
    /// §6 — when `true`, the release path REFUSES a userdata that is not
    /// Vault-Transit-wrapped at rest (the userdata counterpart of
    /// [`Self::require_wrapped_kek`]). Default `false`; set via
    /// [`Self::with_require_wrapped_userdata`] from KBS config.
    pub require_wrapped_userdata: bool,
    /// Anti-rollback for the guest-keyed overlay — the per-`vm_id`
    /// CONFIRMED volume stamp (`kbs_core::volume_stamp`). The release
    /// path only READS it (and mints the next-advance token); this
    /// service's `process_volume_stamp_confirm` is the only caller of
    /// `kbs_core::volume_stamp::confirm`, which is the only thing that
    /// ever advances it.
    pub volume_stamp: Arc<dyn VolumeStampStore>,
    /// The RESOLVED suppressed-confirm bound forwarded verbatim into
    /// every release's `Deps::max_unconfirmed_releases`. `Some(bound)` =
    /// ARMED, `None` = DISABLED. Deliberately a REQUIRED constructor
    /// argument, not a builder default like [`Self::with_require_
    /// wrapped_kek`]: unlike that flag (which ships permissive-by-
    /// default for a staged rollout), this one's compiled-in secure
    /// state is ARMED, so there is no safe "if the caller forgets to
    /// set it" default to fall back to here — the resolution (config
    /// absent ⇒ `Some(kbs_core::volume_stamp::MAX_UNCONFIRMED_RELEASES)`;
    /// explicit `0` ⇒ `None`) lives one layer up, in `binaries/
    /// kbs-server`'s `wiring.rs`, and every caller of `new` must supply
    /// its result explicitly.
    pub max_unconfirmed_releases: Option<u64>,
    /// Guest custody lease (`kbs_core::custody`). `None` ⇒ the three
    /// custody routes answer 404 `custody-disabled` (the default; set via
    /// [`Self::with_custody`] when `[custody] enabled = true`).
    pub custody: Option<Arc<CustodyRuntime>>,
    /// The release-time guest bindings keepalives are checked against
    /// (`kbs_core::keepalive_binding`). EVERY successful release records
    /// one, whatever [`Self::keepalive_binding_mode`] says — so switching
    /// the mode on later needs no reboot for VMs released since.
    pub keepalive_bindings: Arc<dyn KeepaliveBindingStore>,
    /// `Off` (default) ⇒ legacy v1 keepalive bodies; `Record` / `Enforce`
    /// ⇒ bound v2 bodies. Set via [`Self::with_keepalive_binding`].
    pub keepalive_binding_mode: BindingMode,
    /// `enforce` grace window close time (`EnforceGrace`); `None` ⇒ strict.
    pub keepalive_grace_closes_at_unix: Option<u64>,
    /// The ADMIN audit chain the release path writes authorized-rollback
    /// events to (`kbs_core::rollback`): consume-intent (MANDATORY — an
    /// arm-admitted release is refused if it cannot be written, or if
    /// this is `None`), consume, refused, cleared-by-boot, commit-failed.
    /// The SAME `Arc` the admin router appends to —
    /// a second `FileAdminAuditSink::open` over the same directory would
    /// block on its exclusive lock. `None` until the admin listener is
    /// wired ([`Self::set_rollback_audit`]); with no admin listener no
    /// arm can be created, so there is nothing to record.
    pub rollback_audit: Option<Arc<kbs_core::admin_audit::FileAdminAuditSink>>,
    /// Monotonic counter; every `GC_EVERY_N_ISSUANCES` issuances we
    /// sweep the nonce store for expired markers. Not user-tunable —
    /// production ops gets this for free.
    issuance_counter: Arc<AtomicU64>,
}

impl DefaultKbsService {
    /// Construct from fully-wired dependencies. We could derive most of
    /// this with `..Default::default()` but the trait objects make it
    /// awkward; for now an explicit-fields constructor is enough.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        l1_keyring: Arc<dyn L1Keyring + Send + Sync>,
        attn: Arc<dyn AttestationVerifier + Send + Sync>,
        offline_allowlist: Arc<dyn MeasurementAllowlist + Send + Sync>,
        launch_policy: Arc<LaunchPolicy>,
        vm_states: Arc<dyn VmStateStore + Send + Sync>,
        release_store: Arc<dyn ReleaseStore + Send + Sync>,
        kbs_nonce_store: Arc<dyn KbsNonceStore + Send + Sync>,
        vault_auth: Arc<dyn AttestedVaultAuth + Send + Sync>,
        vault_kv: Arc<dyn VaultKv + Send + Sync>,
        kbs_attestation: Arc<VerifiedReport>,
        kbs_auth_pubkey: Arc<Vec<u8>>,
        kbs_signing_key: Arc<SigningKey>,
        kbs_kid: Arc<Vec<u8>>,
        audit: Arc<dyn AuditSink + Send + Sync>,
        evidence: Arc<dyn EvidenceSink>,
        live_attestation_state: Arc<dyn LiveAttestationStateStore>,
        live_attestation_sink: Arc<dyn LiveAttestationSink>,
        compute_chain_genesis: [u8; 32],
        compute_pallet_instance: [u8; 32],
        boot_counter: Arc<dyn BootCounterStore>,
        volume_stamp: Arc<dyn VolumeStampStore>,
        max_unconfirmed_releases: Option<u64>,
    ) -> Self {
        Self {
            l1_keyring,
            attn,
            offline_allowlist,
            launch_policy,
            vm_states,
            release_store,
            kbs_nonce_store,
            vault_auth,
            vault_kv,
            kbs_attestation,
            kbs_auth_pubkey,
            kbs_signing_key,
            kbs_kid,
            audit,
            evidence,
            live_attestation_state,
            live_attestation_sink,
            compute_chain_genesis,
            compute_pallet_instance,
            boot_counter,
            volume_stamp,
            max_unconfirmed_releases,
            require_wrapped_kek: false,
            require_wrapped_userdata: false,
            custody: None,
            keepalive_bindings: Arc::new(InMemoryKeepaliveBindings::default()),
            keepalive_binding_mode: BindingMode::Off,
            keepalive_grace_closes_at_unix: None,
            rollback_audit: None,
            issuance_counter: Arc::new(AtomicU64::new(0)),
        }
    }

    /// Share the admin router's audit chain with the release path so the
    /// authorized-rollback events it owns are recorded in the SAME
    /// hash chain as the arm that authorised them.
    pub fn set_rollback_audit(&mut self, audit: Arc<kbs_core::admin_audit::FileAdminAuditSink>) {
        self.rollback_audit = Some(audit);
    }

    /// Set the keepalive binding mode (KBS config `[keepalive] binding`).
    #[must_use]
    pub fn with_keepalive_binding(mut self, mode: BindingMode) -> Self {
        self.keepalive_binding_mode = mode;
        self
    }

    /// Open `enforce`'s post-restart grace window until `closes_at_unix`
    /// (see `kbs_core::keepalive_binding::EnforceGrace`).
    #[must_use]
    pub fn with_keepalive_grace(mut self, closes_at_unix: Option<u64>) -> Self {
        self.keepalive_grace_closes_at_unix = closes_at_unix;
        self
    }

    /// Use `store` for the keepalive binding records — in production the
    /// file-backed store in the state dir, SHARED with the admin listener
    /// (which seeds it after a pod restart). Default: in-memory.
    #[must_use]
    pub fn with_keepalive_bindings(mut self, store: Arc<dyn KeepaliveBindingStore>) -> Self {
        self.keepalive_bindings = store;
        self
    }

    /// KEK-HSM RA-08a/F2 — opt into fail-closed enforcement of "KEK
    /// ciphertext at rest" (refuse a non-`vault:` KEK at release). Builder
    /// so the many-arg `new()` (and its callers) stay unchanged; the wiring
    /// sets it from KBS config. Default (unset) = off.
    #[must_use]
    pub fn with_require_wrapped_kek(mut self, require: bool) -> Self {
        self.require_wrapped_kek = require;
        self
    }

    /// §6 — opt into fail-closed enforcement of "userdata ciphertext at
    /// rest" (refuse a non-`vault:` userdata at release). Same shape and
    /// same staged-rollout reason as [`Self::with_require_wrapped_kek`].
    #[must_use]
    pub fn with_require_wrapped_userdata(mut self, require: bool) -> Self {
        self.require_wrapped_userdata = require;
        self
    }

    /// Switch the guest custody lease on, sharing `runtime` with the admin
    /// router (its report and policy routes read and write the same one).
    #[must_use]
    pub fn with_custody(mut self, runtime: Arc<CustodyRuntime>) -> Self {
        self.custody = Some(runtime);
        self
    }

    fn custody_deps<'a>(&'a self, runtime: &'a CustodyRuntime) -> CustodyDeps<'a> {
        CustodyDeps {
            l1_keyring: self.l1_keyring.as_ref(),
            attn: self.attn.as_ref(),
            offline_allowlist: self.offline_allowlist.as_ref(),
            launch_policy: &self.launch_policy,
            vm_states: self.vm_states.as_ref(),
            kbs_nonce_store: self.kbs_nonce_store.as_ref(),
            vault_auth: self.vault_auth.as_ref(),
            vault_kv: self.vault_kv.as_ref(),
            kbs_attestation: &self.kbs_attestation,
            kbs_auth_pubkey: self.kbs_auth_pubkey.as_ref(),
            kbs_signing_key: &self.kbs_signing_key,
            kbs_kid: self.kbs_kid.as_ref(),
            audit: self.audit.as_ref(),
            boot_counter: self.boot_counter.as_ref(),
            require_wrapped_kek: self.require_wrapped_kek,
            runtime,
        }
    }
}

impl DefaultKbsService {
    /// After a SUCCESSFUL release: record the guest it released to as the
    /// only guest allowed to keepalive for that `vm_id`, at the position
    /// the release committed (`vm_generation`, `boot_counter` from the
    /// response it just signed). The release already verified this exact
    /// report, so re-reading it here only extracts `(chip_id, report_id)`.
    ///
    /// Never fails the release (it is already committed). A failure is
    /// audited, and `record_after_release` has POISONED the VM: the stale
    /// record (naming the previous guest) is dropped and its keepalives
    /// are refused in `Record` and `Enforce` alike until its next release
    /// or an admin seed. If the signed response itself does not verify
    /// there is no trustworthy `vm_id` to poison, so that case is audited
    /// only.
    fn record_keepalive_binding(&self, signed: &SignedResponse, raw_snp_report: &[u8]) {
        let recorded = keepalive_binding::record_after_release(
            self.keepalive_bindings.as_ref(),
            &self.kbs_signing_key.verifying_key(),
            signed,
            raw_snp_report,
        );
        if let Err(e) = recorded {
            self.audit.record(
                false,
                None,
                None,
                &format!(
                    "keepalive-binding not recorded after release (the VM is poisoned: its \
                     keepalives are refused until its next release): {e}"
                ),
            );
        }
    }
}

impl KbsService for DefaultKbsService {
    fn issue_nonce(&self, now_unix: u64) -> Result<[u8; NONCE_LEN]> {
        let nonce = self.kbs_nonce_store.issue(now_unix)?;
        // Opportunistic GC: every Nth successful issuance, sweep expired
        // markers. GC errors are logged via audit-sink semantics (best
        // effort) and never block issuance — a temporary FS hiccup must
        // not deny service. (§13 — bounded growth is the goal, not
        // strict bookkeeping.)
        let n = self.issuance_counter.fetch_add(1, Ordering::Relaxed);
        if n.is_multiple_of(GC_EVERY_N_ISSUANCES) {
            let _ = self.kbs_nonce_store.gc_expired(now_unix);
        }
        Ok(nonce)
    }

    fn process_release(
        &self,
        cose_ticket: &[u8],
        raw_snp_report: &[u8],
        kbs_nonce: &[u8; NONCE_LEN],
        now_unix: u64,
        submitted_boot_counter: Option<u64>,
    ) -> core::result::Result<SignedResponse, SignedDenial> {
        let req = ReleaseRequest {
            cose_ticket,
            raw_snp_report,
            kbs_nonce,
            now_unix,
            // Phase 2A of audit follow-up Review #2: the transport
            // now decodes the field from `ReleaseRequestBody` and
            // forwards it here. `None` is the pre-Phase-2A wire
            // shape — kbs-core short-circuits the boot-counter
            // CAS for that case.
            submitted_boot_counter,
        };
        // `Arc<dyn Trait + Send + Sync>` coerces to `&dyn Trait` via
        // auto-trait removal (stable trait-object upcasting, Rust ≥ 1.86).
        let deps = Deps {
            l1_keyring: self.l1_keyring.as_ref(),
            attn: self.attn.as_ref(),
            offline_allowlist: self.offline_allowlist.as_ref(),
            launch_policy: &self.launch_policy,
            vm_states: self.vm_states.as_ref(),
            release_store: self.release_store.as_ref(),
            kbs_nonce_store: self.kbs_nonce_store.as_ref(),
            vault_auth: self.vault_auth.as_ref(),
            vault_kv: self.vault_kv.as_ref(),
            kbs_attestation: &self.kbs_attestation,
            kbs_auth_pubkey: self.kbs_auth_pubkey.as_ref(),
            kbs_signing_key: &self.kbs_signing_key,
            kbs_kid: self.kbs_kid.as_ref(),
            audit: self.audit.as_ref(),
            evidence: self.evidence.as_ref(),
            boot_counter: self.boot_counter.as_ref(),
            volume_stamp: self.volume_stamp.as_ref(),
            max_unconfirmed_releases: self.max_unconfirmed_releases,
            require_wrapped_kek: self.require_wrapped_kek,
            require_wrapped_userdata: self.require_wrapped_userdata,
            rollback_audit: self.rollback_audit.as_deref(),
        };
        let outcome = process_release(&req, &deps);
        if let Ok(signed) = &outcome {
            self.record_keepalive_binding(signed, raw_snp_report);
        }
        outcome
    }

    fn process_keepalive(
        &self,
        vm_id: &str,
        node_id: &[u8; NONCE_LEN],
        raw_snp_report: &[u8],
        kbs_nonce: &[u8; NONCE_LEN],
        epoch: u64,
        expiry_unix: u64,
        resources: Option<&GuestResources>,
        components: Option<&GuestComponents>,
        now_unix: u64,
    ) -> Result<SignedLiveAttestation> {
        let req = KeepaliveRequest {
            vm_id,
            node_id,
            raw_snp_report,
            kbs_nonce,
            now_unix,
            epoch,
            expiry_unix,
            resources,
            components,
        };
        let deps = KeepaliveDeps {
            attn: self.attn.as_ref(),
            offline_allowlist: self.offline_allowlist.as_ref(),
            launch_policy: &self.launch_policy,
            kbs_nonce_store: self.kbs_nonce_store.as_ref(),
            state: self.live_attestation_state.as_ref(),
            sink: self.live_attestation_sink.as_ref(),
            kbs_signing_key: &self.kbs_signing_key,
            kbs_kid: self.kbs_kid.as_ref(),
            audit: self.audit.as_ref(),
            chain_genesis: self.compute_chain_genesis,
            pallet_instance: self.compute_pallet_instance,
            bindings: self.keepalive_bindings.as_ref(),
            binding_mode: self.keepalive_binding_mode,
            grace_closes_at_unix: self.keepalive_grace_closes_at_unix,
            vm_states: self.vm_states.as_ref(),
        };
        process_keepalive(&req, &deps)
    }

    fn process_host_enroll(
        &self,
        enrollment: &HostEnrollment,
        nonce: &[u8; NONCE_LEN],
        now_unix: u64,
    ) -> Result<SignedHostAttestorCert> {
        let req = HostAttestationRequest {
            enrollment,
            nonce,
            now_unix,
            // KBS-decided window — the request never carries an expiry, so
            // an untrusted relay cannot request a long-lived cert.
            // `saturating_add` keeps a near-`u64::MAX` clock from wrapping
            // (which would invert the `expiry > now` gate); the gate then
            // holds because the sum stays `> now_unix`.
            expiry_unix: now_unix.saturating_add(HOST_ATTESTOR_CERT_TTL_SECS),
        };
        // Reuse the EXACT same deps the release/keepalive flows use — the
        // production AMD verifier, the §22 offline allowlist (whose
        // `class_of` gate `process_host_attestation` enforces), the L0
        // signing key, and the audit sink. No new key path.
        let deps = HostAttestationDeps {
            attn: self.attn.as_ref(),
            allowlist: self.offline_allowlist.as_ref(),
            kbs_signing_key: &self.kbs_signing_key,
            audit: self.audit.as_ref(),
        };
        process_host_attestation(&req, &deps)
    }

    fn process_volume_stamp_confirm(&self, vm_id: &str, value: u64, token: &[u8]) -> Result<u64> {
        // The MAC key is derived from the SAME KBS signing seed the
        // release path used to mint the token in the first place (see
        // `kbs_core::volume_stamp::stamp_mac_key`) — no second secret to
        // provision or rotate.
        let mac_key = kbs_core::volume_stamp::stamp_mac_key(&self.kbs_signing_key.to_bytes());
        kbs_core::volume_stamp::confirm(self.volume_stamp.as_ref(), &mac_key, vm_id, value, token)
    }

    fn process_volume_stamp_confirm_timeline(
        &self,
        vm_id: &str,
        value: u64,
        token: &[u8],
        timeline: &[u8; 32],
    ) -> Result<u64> {
        let mac_key = kbs_core::volume_stamp::stamp_mac_key(&self.kbs_signing_key.to_bytes());
        kbs_core::volume_stamp::confirm_timeline(
            self.volume_stamp.as_ref(),
            &mac_key,
            vm_id,
            value,
            token,
            timeline,
        )
    }

    fn process_custody_bind(&self, req: &CustodyBindRequest, now_unix: u64) -> CustodyReply {
        match &self.custody {
            Some(rt) => kbs_core::custody::process_bind(req, now_unix, &self.custody_deps(rt)),
            None => CustodyReply::disabled(),
        }
    }

    fn process_custody_renew(&self, req: &CustodyRenewRequest, now_unix: u64) -> CustodyReply {
        match &self.custody {
            Some(rt) => kbs_core::custody::process_renew(req, now_unix, &self.custody_deps(rt)),
            None => CustodyReply::disabled(),
        }
    }

    fn process_custody_rekey(&self, req: &CustodyRekeyRequest, now_unix: u64) -> CustodyReply {
        match &self.custody {
            Some(rt) => kbs_core::custody::process_rekey(req, now_unix, &self.custody_deps(rt)),
            None => CustodyReply::disabled(),
        }
    }
}
