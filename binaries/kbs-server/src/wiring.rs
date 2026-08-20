//! Wires the validated [`Config`] into a `kbs_transport::DefaultKbsService`.
//!
//! Ordering is a review invariant. `FileAuditSink::open` is taken FIRST:
//! its exclusive OS lock is the single-process gate, so a second KBS
//! process blocks there and can never race the allowlist high-water-mark
//! mutation below. Every durable store is then opened before
//! `server::run` builds the router and binds the listener — no release
//! path can run un-wired.

use crate::attest;
use crate::config::Config;
use crate::error::Error;
use crate::hwm::FileHighWaterStore;
use crate::l1_keyring::ConfigL1Keyring;
use crate::vault_mvp::StaticTokenVaultKv;
use ed25519_dalek::{SigningKey, VerifyingKey};
use kbs_core::admin::VmStateRegister;
use kbs_core::admin_audit::FileAdminAuditSink;
use kbs_core::allowlist::{parse_and_verify_any, HighWaterStore, InstalledAllowlist};
use kbs_core::audit::FileAuditSink;
use kbs_core::persist::{
    FileIdempotencyStore, FileKbsNonceStore, FileReleaseStore, FileVmStateStore, IdempotencyStore,
};
use kbs_core::snp::LaunchPolicy;
use kbs_core::ticket::L1Keyring;
use kbs_core::vault::{AttestedVaultAuth, ChallengeVaultAuth};
use kbs_transport::{AdminState, DefaultKbsService, NonceRateLimiter, RateConfig};
use std::sync::Arc;
use zeroize::Zeroizing;

/// Fingerprint a hex-encoded public key for the posture readout: the
/// first 8 bytes of `SHA-256(decoded_bytes)`, lower-case hex.
///
/// A fingerprint rather than the key itself — the key is public and
/// already in Git, but `GET /v1/admin/config` answers "is this process
/// anchored to the key I think?" and that question needs 16 hex chars,
/// not a key-distribution surface. Reproducible by an operator with
/// `echo -n <hex> | xxd -r -p | sha256sum | cut -c1-16`.
///
/// Never fails: an undecodable value yields the literal
/// `"unparseable"` (the binary would not have started with one, but a
/// posture readout must not be the thing that panics).
fn pubkey_fingerprint(hex_str: &str) -> String {
    use sha2::{Digest, Sha256};
    match hex::decode(hex_str.trim()) {
        Ok(bytes) => {
            let digest = Sha256::digest(&bytes);
            hex::encode(&digest[..8])
        }
        Err(_) => "unparseable".to_string(),
    }
}

/// The EFFECTIVE security posture of a process wired from `cfg` —
/// booleans, bounds, counts, labels and fingerprints, never material.
///
/// This is the ONE derivation. It is called by [`build_admin_state`] to
/// populate `GET /v1/admin/config`, and by
/// `tests/chart_deploy_safety.rs` to derive the SAME posture from the
/// bytes `deploy/gitops/apps/kbs` actually renders — which is what lets
/// CI assert that vali's declared expectation (`VALI_KBS_EXPECTED_
/// POSTURE`, diffed against the running process every 15 minutes by
/// `apps.synthetic.checks.check_kbs_config_drift`) agrees with the
/// chart. Two hand-maintained copies of "what the chart means" would be
/// two things that drift; this is one.
///
/// Note what it does NOT do: re-read the config file, consult a store,
/// or ask the OS anything. It is a pure function of the `Config` value
/// the process was wired from, so what it reports is by construction
/// what this process is running.
pub fn config_posture(cfg: &Config) -> hippius_types::admin::AdminConfigPostureResponse {
    use crate::admin_tls::AdminListenerMode;

    // The admin listener mode is taken from the SAME pure decision
    // function `server::spawn_admin_listener` binds on
    // (`AdminListenerMode::decide`), not from `require_mtls` — that flag
    // is not the enforcement switch (present material enforces mTLS
    // whatever it says), and reporting it as if it were is the exact
    // misreading the chart's own comment warns about.
    let admin_listener_mode = match cfg.admin.as_ref().map(AdminListenerMode::decide) {
        Some(AdminListenerMode::Mtls(_)) => "mtls",
        Some(AdminListenerMode::PlaintextOptIn) => "plaintext-opt-in",
        Some(AdminListenerMode::Refuse(_)) => "refuse",
        // `[admin]` absent ⇒ no admin listener exists at all. Nobody can
        // read this field in that case (there is no endpoint to read it
        // from); it is reported for completeness of the derivation.
        None => "disabled",
    }
    .to_string();

    let max_unconfirmed_releases =
        Config::resolve_max_unconfirmed_releases(cfg.storage.max_unconfirmed_releases);

    hippius_types::admin::AdminConfigPostureResponse {
        v: 1,
        require_wrapped_kek: cfg.require_wrapped_kek,
        max_unconfirmed_releases,
        volume_stamp_gate_armed: max_unconfirmed_releases.is_some(),
        admin_listener_mode,
        evidence_sink_wired: cfg.storage.evidence_dir.is_some(),
        live_attestation_sink_wired: cfg.storage.live_attestation_dir.is_some(),
        allowlist_root_pubkey_fpr: pubkey_fingerprint(&cfg.allowlist.root_pubkey_hex),
        allowlist_root_next_pubkey_fpr: cfg
            .allowlist
            .root_pubkey_hex_next
            .as_deref()
            .filter(|s| !s.trim().is_empty())
            .map(pubkey_fingerprint),
        allowlist_signed_path_configured: cfg.allowlist.signed_path.is_some(),
        l1_key_count: u32::try_from(cfg.l1_keys.len()).unwrap_or(u32::MAX),
        min_tcb: cfg.launch_policy.min_tcb,
        required_bits: cfg.launch_policy.required_bits,
        allowed_mask: cfg.launch_policy.allowed_mask,
        snp_chain_wired: cfg.snp.is_some(),
        snp_generation: cfg.snp.as_ref().map(|s| {
            match s.generation {
                crate::config::SnpGeneration::Milan => "milan",
                crate::config::SnpGeneration::Genoa => "genoa",
                crate::config::SnpGeneration::Turin => "turin",
            }
            .to_string()
        }),
        snp_kds_fetch_enabled: cfg
            .snp
            .as_ref()
            .and_then(|s| s.kds_url.as_deref())
            .is_some_and(|u| !u.trim().is_empty()),
        vault_broker_wired: cfg
            .vault
            .broker_url
            .as_deref()
            .is_some_and(|u| !u.trim().is_empty()),
        vault_broker_ca_pinned: cfg.vault.broker_ca_path.is_some(),
        vault_ca_pinned: cfg.vault.ca_cert_path.is_some(),
        vault_dev_environment: cfg.vault.dev_environment,
        vault_dev_allow_any_kbs_measurement: cfg.vault.dev_allow_any_kbs_measurement,
        vault_dev_skip_tls_verify: cfg.vault.dev_skip_tls_verify,
    }
}

/// Decode a hex string into exactly 32 bytes, or a config error.
fn hex32(field: &str, s: &str) -> Result<[u8; 32], Error> {
    let v =
        hex::decode(s.trim()).map_err(|e| Error::Config(format!("{field}: invalid hex: {e}")))?;
    v.try_into()
        .map_err(|_| Error::Config(format!("{field}: must be exactly 32 bytes")))
}

/// Decode a hex Ed25519 public key, or a config error.
fn verifying_key(field: &str, s: &str) -> Result<VerifyingKey, Error> {
    let b = hex32(field, s)?;
    VerifyingKey::from_bytes(&b)
        .map_err(|e| Error::Config(format!("{field}: not a valid Ed25519 key: {e}")))
}

/// Decode a non-empty hex byte string, or a config error.
fn hex_nonempty(field: &str, s: &str) -> Result<Vec<u8>, Error> {
    let v =
        hex::decode(s.trim()).map_err(|e| Error::Config(format!("{field}: invalid hex: {e}")))?;
    if v.is_empty() {
        return Err(Error::Config(format!("{field} must not be empty")));
    }
    Ok(v)
}

/// Build the production SNP self-report provider for the §8 broker
/// path. `/dev/sev-guest` exists only inside a Linux/x86_64 SEV-SNP
/// guest (the KBS pod is a kata-qemu-snp CVM), so on any other target
/// a configured `vault.broker_url` is a wiring error — the binary must
/// never start with a broker URL it cannot honour (fail closed).
fn build_self_report_provider() -> Result<Arc<dyn crate::kbs_self_report::SelfReportProvider>, Error>
{
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    {
        Ok(Arc::new(crate::kbs_self_report::SevGuestSelfReport::new()))
    }
    #[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
    {
        Err(Error::Wiring(
            "vault.broker_url: broker auth requires /dev/sev-guest (linux x86_64)".into(),
        ))
    }
}

/// Bundle returned by [`build_service`]: the wired release-path
/// service plus the `Arc`s the admin transport needs to share. Holding
/// these `Arc`s here (rather than re-opening) is the contract that
/// admin writes the same lifecycle file the release path reads.
pub struct WiredKbs {
    pub service: DefaultKbsService,
    pub l1_keyring: Arc<ConfigL1Keyring>,
    pub vm_states: Arc<FileVmStateStore>,
    /// Concrete handle into the live §22 allowlist. The release path
    /// holds an `Arc<dyn MeasurementAllowlist>` (read-only); the admin
    /// path needs the concrete `Arc<InstalledAllowlist>` for the
    /// `/v1/admin/allowlist/reload` swap (see
    /// [`crate::handlers::admin::handle_reload_allowlist`]).
    pub allowlist: Arc<InstalledAllowlist>,
    /// The SAME boot-counter store the release path advances (RA-L-NEW-2).
    /// `FileBootCounterStore` caches in memory and `get()` reads the
    /// cache, so a SECOND handle over the same file froze at its open-
    /// time snapshot → the admin `GET …/evidence` counter went stale
    /// after any release advanced it. Sharing one `Arc` (like
    /// `l1_keyring`/`vm_states`) keeps the admin readout current.
    pub boot_counter: Arc<dyn kbs_core::boot_counter::BootCounterStore>,
    /// The SAME volume-stamp store the release path's `note_release`
    /// advances and the guest-facing confirm route resets — needed by
    /// `/v1/admin/vm/:vm_id/reset-volume-stamp-suppression` (the
    /// operator recovery for the suppressed-confirm anti-rollback gate,
    /// `kbs_core::volume_stamp`). Same RA-L-NEW-2 sharing discipline as
    /// `boot_counter` above: a second `FileVolumeStampStore::open` would
    /// cache its own stale snapshot.
    pub volume_stamp: Arc<dyn kbs_core::volume_stamp::VolumeStampStore>,
}

/// Build the fully-wired KBS service.
///
/// `vault_token` is the static `VAULT_TOKEN` consumed by the MVP Vault
/// KV client ([`StaticTokenVaultKv`]). Any fault returns `Err` and the
/// caller aborts startup — the binary never serves a half-wired KBS.
pub fn build_service(cfg: &Config, vault_token: Zeroizing<String>) -> Result<WiredKbs, Error> {
    // ── KBS response-signing key (mounted secret) ───────────────────
    let key_bytes = Zeroizing::new(std::fs::read(&cfg.keys.signing_key_path).map_err(|e| {
        Error::Config(format!(
            "keys.signing_key_path {}: {e}",
            cfg.keys.signing_key_path.display()
        ))
    })?);
    if key_bytes.len() != 32 {
        return Err(Error::Config(
            "keys.signing_key_path: file must be exactly 32 bytes".into(),
        ));
    }
    // Copy the seed straight into a zeroizing buffer — no un-wiped
    // intermediate `[u8; 32]`. `SigningKey` itself wipes on drop (the
    // `zeroize` feature is enabled in Cargo.toml).
    let mut key_seed: Zeroizing<[u8; 32]> = Zeroizing::new([0u8; 32]);
    key_seed.copy_from_slice(&key_bytes);
    let signing_key = SigningKey::from_bytes(&key_seed);

    let kid = hex_nonempty("keys.kid_hex", &cfg.keys.kid_hex)?;
    let auth_pubkey = hex_nonempty("keys.auth_pubkey_hex", &cfg.keys.auth_pubkey_hex)?;

    // ── hash-chained audit sink — opened FIRST ──────────────────────
    // Its exclusive OS lock is the single-process gate: a second KBS
    // process blocks here and never reaches the allowlist HWM mutation
    // below, so that file CAS cannot race cross-process. The lock is
    // also held before any store opens or any release path can run.
    let audit = FileAuditSink::open(&cfg.storage.audit_dir)
        .map_err(|e| Error::Wiring(format!("audit sink: {e}")))?;

    // ── §280 evidence-bundle sink ──────────────────────────────────
    // Best-effort archive of per-release cryptographic evidence — see
    // `kbs-core::evidence`. When `storage.evidence_dir` is absent the
    // operator has opted out (or hasn't bootstrapped yet); a
    // `NullEvidenceSink` keeps the release path code-identical without
    // disk writes. The sink is shared via `Arc` so the release route
    // can pass `&*evidence` into `Deps` without owning it.
    let evidence: std::sync::Arc<dyn kbs_core::evidence::EvidenceSink> =
        match &cfg.storage.evidence_dir {
            Some(dir) => {
                let sink = kbs_core::evidence::FileEvidenceSink::open(dir)
                    .map_err(|e| Error::Wiring(format!("evidence sink: {e}")))?;
                eprintln!(
                    "kbs-server: §280 evidence sink at {}",
                    sink.root().display(),
                );
                std::sync::Arc::new(sink)
            }
            None => {
                eprintln!(
                    "kbs-server: §280 evidence sink DISABLED \
                     (config storage.evidence_dir absent — release decisions \
                     stay in the audit log only)"
                );
                std::sync::Arc::new(kbs_core::evidence::NullEvidenceSink)
            }
        };

    // ── §22 offline measurement allowlist ───────────────────────────
    // Boot ordering: snapshot the durable HWM FIRST, then decide between
    // `install` (CAS-advance) and `revalidate_with` (replay-load) based
    // on how the artifact's epoch compares to the persisted HWM. Calling
    // `install()` blindly on every boot crashloops on the second start —
    // the CAS rejects `epoch <= current` (anti-rollback contract). The
    // audit-log lock taken above is the single-process gate, so this
    // get→branch is race-free for this process.
    // The accepted §22 root set: the primary pubkey, plus the optional
    // `next` pubkey during a key rotation (the KBS then accepts an
    // allowlist signed by EITHER — no atomic flag-day, no rotation risk
    // window). See `kbs_core::allowlist::parse_and_verify_any`.
    let mut roots = vec![verifying_key(
        "allowlist.root_pubkey_hex",
        &cfg.allowlist.root_pubkey_hex,
    )?];
    if let Some(next_hex) = cfg
        .allowlist
        .root_pubkey_hex_next
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        roots.push(verifying_key("allowlist.root_pubkey_hex_next", next_hex)?);
        eprintln!(
            "kbs-server: §22 allowlist key ROTATION active — accepting artifacts signed by \
             the primary OR the next root pubkey ({} accepted roots)",
            roots.len(),
        );
    }
    let hwm = FileHighWaterStore::open(cfg.storage.state_dir.join("allowlist-hwm"))
        .map_err(|e| Error::Wiring(format!("allowlist HWM: {e}")))?;
    let hwm_snapshot = hwm
        .get()
        .map_err(|e| Error::Wiring(format!("allowlist HWM read: {e}")))?;
    let allowlist = InstalledAllowlist::new_multi(roots.clone(), Box::new(hwm));
    match &cfg.allowlist.signed_path {
        Some(p) => {
            let bytes = std::fs::read(p).map_err(|e| {
                Error::Config(format!("allowlist.signed_path {}: {e}", p.display()))
            })?;
            // Pre-parse + verify against the in-binary root so we can
            // route on the artifact's epoch. `parse_and_verify` runs
            // the SAME checks the runtime's release path runs — it's
            // the cheapest correct way to peek the epoch.
            let body = parse_and_verify_any(&bytes, &roots)
                .map_err(|e| Error::Wiring(format!("allowlist parse_and_verify: {e}")))?;
            match hwm_snapshot {
                None => {
                    // First boot — `install` CAS-advances from `None`.
                    allowlist
                        .install(&bytes)
                        .map_err(|e| Error::Wiring(format!("allowlist install: {e}")))?;
                    eprintln!(
                        "kbs-server: §22 allowlist installed from {} (epoch={})",
                        p.display(),
                        body.epoch,
                    );
                }
                Some(current) if body.epoch == current => {
                    // Restart with the same artifact — `revalidate_with`
                    // re-runs the signature + canonical-CBOR + epoch=HWM
                    // checks and loads the active body in-memory without
                    // touching the HWM.
                    allowlist
                        .revalidate_with(&bytes)
                        .map_err(|e| Error::Wiring(format!("allowlist revalidate: {e}")))?;
                    eprintln!(
                        "kbs-server: §22 allowlist re-validated from {} (epoch={current}, replay)",
                        p.display(),
                    );
                }
                Some(current) if body.epoch > current => {
                    // Rotation — `install` CAS-advances `current → body.epoch`.
                    allowlist
                        .install(&bytes)
                        .map_err(|e| Error::Wiring(format!("allowlist rotate install: {e}")))?;
                    eprintln!(
                        "kbs-server: §22 allowlist rotated from {} ({current} → {})",
                        p.display(),
                        body.epoch,
                    );
                }
                Some(current) => {
                    // body.epoch < current ⇒ downgrade attempt. Fail
                    // closed loud — there's no "accept" path here.
                    return Err(Error::Wiring(format!(
                        "allowlist downgrade refused: artifact epoch {} < persisted HWM {current} \
                         (re-mint with epoch > {current} or roll the state-dir back deliberately)",
                        body.epoch
                    )));
                }
            }
        }
        None => {
            eprintln!(
                "kbs-server: WARNING — no [allowlist].signed_path configured; \
                 every release fails closed until an allowlist is installed"
            );
        }
    }

    // ── L1 OrderTicket keyring ──────────────────────────────────────
    let mut l1_entries = Vec::with_capacity(cfg.l1_keys.len());
    for (i, k) in cfg.l1_keys.iter().enumerate() {
        let kid_bytes = hex_nonempty(&format!("l1_keys[{i}].kid_hex"), &k.kid_hex)?;
        let vk = verifying_key(&format!("l1_keys[{i}].pubkey_hex"), &k.pubkey_hex)?;
        l1_entries.push((kid_bytes, vk));
    }
    let l1_keyring = Arc::new(ConfigL1Keyring::from_entries(l1_entries).map_err(Error::Config)?);
    eprintln!("kbs-server: {} L1 ticket key(s) loaded", l1_keyring.len());

    // ── durable stores — opened before the listener binds ───────────
    let release_store = FileReleaseStore::open(cfg.storage.state_dir.join("releases"))
        .map_err(|e| Error::Wiring(format!("release store: {e}")))?;
    // `FileVmStateStore` is held as a single `Arc` so the release path
    // (read-only `VmStateStore::get`) and the admin path (write-side
    // `VmStateRegister::register`) share the in-memory cache + the
    // single on-disk file. Two `Arc`s = two views of the same store.
    let vm_states_concrete = Arc::new(
        FileVmStateStore::open(cfg.storage.state_dir.join("vm-states.json"))
            .map_err(|e| Error::Wiring(format!("vm-state store: {e}")))?,
    );
    let nonce_store = FileKbsNonceStore::open(
        cfg.storage.state_dir.join("nonces"),
        cfg.storage.nonce_ttl_secs,
    )
    .map_err(|e| Error::Wiring(format!("nonce store: {e}")))?;

    // ── SNP launch-policy floor ─────────────────────────────────────
    let launch_policy = LaunchPolicy {
        min_tcb: cfg.launch_policy.min_tcb,
        required_bits: cfg.launch_policy.required_bits,
        allowed_mask: cfg.launch_policy.allowed_mask,
    };

    // ── SNP attestation verifier (production) ───────────────────────
    // `attest::build` selects deny-closed vs SevChainVerifier based on
    // whether `[snp]` is configured + the VEK file is readable. A
    // configured-but-unreadable VEK aborts startup; an absent `[snp]`
    // wires the deny-closed branch (every release fails closed at the
    // chain step). The SAME `RealSnpVerifier` runs in both branches —
    // version pin, MaskedChipId refusal, TCB rollback all still fire.
    let attestation_verifier = attest::build(cfg.snp.as_ref())?;

    // ── Vault seam (MVP) ────────────────────────────────────────────
    // KV reads: the static-token client. Auth / capability: kbs-core's
    // reference `ChallengeVaultAuth`, configured fail-closed by default
    // (the measurement predicate is always false and the TCB floor is
    // u64::MAX) — the SNP-attestation-bound broker (#102) replaces it.
    // The MVP Vault step is therefore structurally unreachable in prod:
    // any release that somehow cleared the SNP gate would still fail
    // closed here. The fixed all-zero `challenge_nonce` below is sound
    // ONLY because of that unreachability — the broker replacement MUST
    // mint a fresh random challenge nonce.
    //
    // `vault.dev_allow_any_kbs_measurement` is a DEV-ONLY override that
    // widens the three KBS-side gates so the placeholder all-zero
    // `VerifiedReport` from `attest::placeholder_verified_report()`
    // passes — letting downstream dev work (#138 attestation
    // persistence, cloud-init validation, NetBird mesh smoke) exercise
    // the full chain while #102 is being built. Default `false`; the
    // production posture is unchanged. Set + a prod-marker substring
    // (`tier0`, `prod`, `hippius.network`) in `vault.address` is
    // refused at config validation (see `Config::validate`).
    let dev_open = cfg.vault.dev_allow_any_kbs_measurement;
    let dev_skip_tls = cfg.vault.dev_skip_tls_verify;
    if dev_open {
        eprintln!(
            "kbs-server: ⚠️  DEV-MODE: vault.dev_allow_any_kbs_measurement=true — \
             KBS measurement / TCB / launch-policy gates bypassed. \
             NEVER ENABLE IN PROD. Closes when #102 lands."
        );
    }
    if let Some(p) = &cfg.vault.ca_cert_path {
        eprintln!("kbs-server: Vault TLS pinned to CA at {}", p.display());
    } else if dev_skip_tls {
        eprintln!(
            "kbs-server: ⚠️  DEV-MODE: vault.dev_skip_tls_verify=true — \
             Vault server certificate verification disabled. \
             NEVER ENABLE IN PROD. Reverts once the prod Vault CA \
             bundle is mounted into the pod."
        );
    }
    // §8 / #102 PR B: a non-empty `vault.broker_url` selects the
    // production SNP-attestation-bound broker for BOTH halves of the
    // Vault seam: the broker mints the per-VM-scoped token (auth, below)
    // AND that scoped token — not the broad static one — is what the KV
    // read authenticates with (`with_capability_token`). A compromised
    // KBS in broker mode can therefore only read the one VM's KEK +
    // userdata the broker attested, never the whole tenant keyspace.
    let broker_url = cfg
        .vault
        .broker_url
        .as_deref()
        .map(str::trim)
        .filter(|u| !u.is_empty());

    let vault_kv = StaticTokenVaultKv::new_with_tls(
        &cfg.vault.address,
        &cfg.vault.kv_mount,
        vault_token,
        dev_skip_tls,
        cfg.vault.ca_cert_path.as_deref(),
    )
    .map_err(Error::Wiring)?
    .with_capability_token(broker_url.is_some());

    // §8 / #102 PR B: `vault.broker_url` set ⇒ the production
    // SNP-attestation-bound broker client replaces the dev seam. The
    // KBS mints a FRESH `/dev/sev-guest` self-report per redeem,
    // binding `challenge_nonce ‖ auth_pubkey` via REPORT_DATA; the
    // broker verifies it against the AMD chain + ITS KBS-measurement
    // allowlist and returns a per-VM-scoped short-TTL Vault token.
    // `Config::validate` already refused the combination with
    // `dev_allow_any_kbs_measurement`, so `dev_open` is necessarily
    // false in the broker branch.
    let vault_auth: Arc<dyn AttestedVaultAuth + Send + Sync> = match broker_url {
        Some(url) => {
            eprintln!("kbs-server: §8 vault auth = SNP-attestation-bound broker at {url}");
            let self_report = build_self_report_provider()?;
            // RA-KBS-M1 — pin the broker's server cert when a CA is
            // configured (broker_url = https://…); else plain HTTP.
            Arc::new(
                crate::remote_broker_auth::RemoteBrokerVaultAuth::new_tls(
                    url,
                    self_report,
                    cfg.vault.broker_ca_path.as_deref(),
                )
                .map_err(Error::Config)?,
            )
        }
        None => {
            let measurement_predicate: fn(&[u8; 48]) -> bool =
                if dev_open { |_| true } else { |_| false };
            let (min_tcb, required_bits) = if dev_open {
                (0u64, 0u64)
            } else {
                (u64::MAX, u64::MAX)
            };
            Arc::new(ChallengeVaultAuth {
                kbs_measurement_ok: measurement_predicate,
                policy: LaunchPolicy {
                    min_tcb,
                    required_bits,
                    allowed_mask: 0,
                },
                challenge_ttl: 30,
                cap_ttl: 30,
                challenge_nonce: [0u8; 32],
            })
        }
    };

    // ── assemble ────────────────────────────────────────────────────
    // Wrap the allowlist as `Arc<InstalledAllowlist>` BEFORE the
    // release service consumes it — the admin path also needs a
    // concrete handle (for `install` on `/v1/admin/allowlist/reload`),
    // and the release-side trait-object `Arc<dyn MeasurementAllowlist>`
    // doesn't expose the swap API.
    let allowlist_arc = Arc::new(allowlist);

    // ── §322 live-attestation state + sink ─────────────────────────
    // For the PR-3b bring-up we wire in-memory implementations of
    // both. The state store is process-local (a KBS restart resets
    // every per-VM chain — guests + pallet recover at the next
    // keepalive once `LastLiveAttestation` falls back to genesis on
    // chain). A durable file-backed store is a PR-3b.1 follow-up;
    // mirrors the §280 evidence sink — operators bootstrap a
    // directory before flipping the production switch.
    let live_attestation_state: Arc<dyn kbs_core::live_attestation::LiveAttestationStateStore> =
        Arc::new(kbs_core::live_attestation::InMemoryLiveAttestationState::default());
    let live_attestation_sink: Arc<dyn kbs_core::live_attestation::LiveAttestationSink> =
        match &cfg.storage.live_attestation_dir {
            Some(dir) => {
                let sink = kbs_core::live_attestation::FileLiveAttestationSink::open(dir)
                    .map_err(|e| Error::Wiring(format!("live-attestation sink: {e}")))?;
                eprintln!(
                    "kbs-server: §322 live-attestation sink at {}",
                    sink.root().display(),
                );
                Arc::new(sink)
            }
            None => {
                eprintln!(
                    "kbs-server: §322 live-attestation sink DISABLED \
                     (config storage.live_attestation_dir absent — keepalives \
                     are signed + returned to caller but nothing is archived \
                     for the vali batcher to ship on-chain)"
                );
                Arc::new(kbs_core::live_attestation::NullLiveAttestationSink)
            }
        };
    let compute_chain_genesis = hex32(
        "live_attestation.compute_chain_genesis_hex",
        &cfg.live_attestation.compute_chain_genesis_hex,
    )?;
    let compute_pallet_instance = hex32(
        "live_attestation.compute_pallet_instance_hex",
        &cfg.live_attestation.compute_pallet_instance_hex,
    )?;

    // Phase 1 of audit follow-up Codex #2 — anti-rollback wiring.
    // Defaults to `{state_dir}/boot-counters.json` so a fresh deploy
    // gets the file without an explicit config bump.
    let boot_counter_path = cfg
        .storage
        .boot_counter_path
        .clone()
        .unwrap_or_else(|| cfg.storage.state_dir.join("boot-counters.json"));
    let boot_counter = Arc::new(
        kbs_core::boot_counter::FileBootCounterStore::open(&boot_counter_path)
            .map_err(|e| Error::Config(format!("boot-counter store: {e}")))?,
    ) as Arc<dyn kbs_core::boot_counter::BootCounterStore>;

    // Anti-rollback for the guest-keyed overlay (`kbs_core::volume_stamp`).
    // Defaults to `{state_dir}/volume-stamps.json` — same sibling-file
    // discipline as the boot-counter store above. Advanced ONLY by the
    // `/v1/kbs/volume-stamp/confirm` route (via `DefaultKbsService::
    // process_volume_stamp_confirm`); the release path only reads it.
    let volume_stamp_path = cfg
        .storage
        .volume_stamp_path
        .clone()
        .unwrap_or_else(|| cfg.storage.state_dir.join("volume-stamps.json"));
    let volume_stamp = Arc::new(
        kbs_core::volume_stamp::FileVolumeStampStore::open(&volume_stamp_path)
            .map_err(|e| Error::Config(format!("volume-stamp store: {e}")))?,
    ) as Arc<dyn kbs_core::volume_stamp::VolumeStampStore>;

    // Suppressed-confirm anti-rollback BOUND — see `Config::
    // resolve_max_unconfirmed_releases` for the full deployment-safety
    // rationale (config absent ⇒ ARMED at the compiled default; explicit
    // `0` ⇒ DISABLED, the value the chart carries until the fleet has
    // been re-baked to send confirms).
    let max_unconfirmed_releases =
        Config::resolve_max_unconfirmed_releases(cfg.storage.max_unconfirmed_releases);
    if max_unconfirmed_releases.is_none() {
        eprintln!(
            "kbs-server: ⚠️  storage.max_unconfirmed_releases=0 — the suppressed-confirm \
             anti-rollback gate is DISABLED. A miner that drops every /v1/kbs/volume-stamp/ \
             confirm can suppress the volume-stamp rollback gate undetected until this is \
             armed. Expected during the fleet re-bake window; arm it once every golden image \
             sends confirms."
        );
    }

    let service = DefaultKbsService::new(
        Arc::clone(&l1_keyring) as Arc<dyn L1Keyring + Send + Sync>,
        Arc::new(attestation_verifier),
        Arc::clone(&allowlist_arc) as Arc<dyn kbs_core::snp::MeasurementAllowlist + Send + Sync>,
        Arc::new(launch_policy),
        Arc::clone(&vm_states_concrete) as Arc<dyn kbs_core::lifecycle::VmStateStore + Send + Sync>,
        Arc::new(release_store),
        Arc::new(nonce_store),
        vault_auth,
        Arc::new(vault_kv),
        Arc::new(attest::placeholder_verified_report()),
        Arc::new(auth_pubkey),
        Arc::new(signing_key),
        Arc::new(kid),
        Arc::new(audit),
        evidence,
        live_attestation_state,
        live_attestation_sink,
        compute_chain_genesis,
        compute_pallet_instance,
        Arc::clone(&boot_counter),
        Arc::clone(&volume_stamp),
        max_unconfirmed_releases,
    )
    // KEK-HSM RA-08a/F2 — opt into fail-closed refusal of a non-`vault:`
    // (plaintext) KEK at release, from `[require_wrapped_kek]` config.
    .with_require_wrapped_kek(cfg.require_wrapped_kek);

    Ok(WiredKbs {
        service,
        l1_keyring,
        vm_states: vm_states_concrete,
        allowlist: allowlist_arc,
        boot_counter,
        volume_stamp,
    })
}

/// Build the admin endpoint state, sharing the lifecycle + L1 keyring
/// with the release service. Called when `[admin]` is configured.
///
/// `l1_keyring` is the SAME `Arc<ConfigL1Keyring>` `build_service`
/// wired into the release path: a register must verify the OrderTicket
/// under the same trust anchor the release path later checks against.
/// `vm_states` is the SAME `Arc<FileVmStateStore>` — admin writes the
/// state the release path reads.
pub fn build_admin_state(
    cfg: &Config,
    l1_keyring: Arc<ConfigL1Keyring>,
    vm_states: Arc<FileVmStateStore>,
    allowlist: Arc<InstalledAllowlist>,
    boot_counter: Arc<dyn kbs_core::boot_counter::BootCounterStore>,
    volume_stamp: Arc<dyn kbs_core::volume_stamp::VolumeStampStore>,
) -> Result<AdminState, Error> {
    let admin_cfg = cfg
        .admin
        .as_ref()
        .ok_or_else(|| Error::Config("[admin] missing — admin endpoint not configured".into()))?;

    // Admin idempotency store — sibling of the release nonce store.
    let idem_dir = cfg.storage.state_dir.join(&admin_cfg.idempotency_subdir);
    let idem = FileIdempotencyStore::open(idem_dir, admin_cfg.idempotency_ttl_secs)
        .map_err(|e| Error::Wiring(format!("admin idem store: {e}")))?;

    // Admin audit sink — sibling of the release audit log, separate
    // hash chain (different domain tag, different file, different
    // lock).
    let audit_dir = cfg.storage.audit_dir.join(&admin_cfg.audit_subdir);
    let audit = FileAdminAuditSink::open(audit_dir)
        .map_err(|e| Error::Wiring(format!("admin audit sink: {e}")))?;

    let limiter = NonceRateLimiter::new(RateConfig {
        // `as f64` of a `u64` is widening — but values up to ~2^53 are
        // exact, and the operator-supplied `rate_per_sec` is bounded
        // by sensible TOML values. Lints elsewhere flag wider casts.
        refill_per_sec: admin_cfg.rate_per_sec as f64,
        burst: admin_cfg.burst,
    });

    let kr_dyn: Arc<dyn L1Keyring + Send + Sync> = l1_keyring as _;
    let vm_dyn: Arc<dyn VmStateRegister + Send + Sync> = vm_states as _;
    let idem_dyn: Arc<dyn IdempotencyStore + Send + Sync> = Arc::new(idem);

    // Read-only handle into the SAME evidence directory the release
    // path writes. `FileEvidenceSink::latest_for_vm` re-reads the file
    // on every call (no in-memory cache), so a second handle genuinely
    // reads what the release path wrote. The `GET …/evidence` endpoint
    // serves the latest bundle + the boot counter to the owning tenant.
    let evidence: Arc<dyn kbs_core::evidence::EvidenceSink> = match &cfg.storage.evidence_dir {
        Some(dir) => Arc::new(
            kbs_core::evidence::FileEvidenceSink::open(dir)
                .map_err(|e| Error::Wiring(format!("admin evidence sink: {e}")))?,
        ),
        None => Arc::new(kbs_core::evidence::NullEvidenceSink),
    };
    // RA-L-NEW-2: SHARE the release path's boot-counter handle (passed
    // in), NOT a second `FileBootCounterStore::open` — that store caches
    // in memory and `get()` reads the cache, so a separate handle froze
    // at its open-time snapshot and served a stale counter after any
    // release advanced it. One shared `Arc` keeps the readout current.

    Ok(AdminState {
        keyring: kr_dyn,
        vm_states: vm_dyn,
        idempotency: idem_dyn,
        audit: Arc::new(audit),
        limiter: Arc::new(limiter),
        allowlist,
        evidence,
        boot_counter,
        volume_stamp,
        // Reported (never enforced) by `GET /v1/admin/volume-stamp`, so
        // the arming readout says which side of the cutover this process
        // is actually on. Resolved by the SAME function the release path
        // uses, from the SAME config field, so the report cannot claim
        // the gate is armed while gate 5c has it disabled.
        configured_max_unconfirmed_releases: Config::resolve_max_unconfirmed_releases(
            cfg.storage.max_unconfirmed_releases,
        ),
        // Same rule, generalised: what `GET /v1/admin/config` reports is
        // derived HERE, from the config value this process was wired
        // from — never re-read from disk, so it cannot answer a
        // question about a file the running process has never seen.
        posture: Arc::new(config_posture(cfg)),
    })
}
