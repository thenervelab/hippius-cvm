//! Operator-facing TOML configuration.
//!
//! Every struct is `#[serde(deny_unknown_fields)]` — an unrecognised or
//! misspelt key aborts startup rather than being silently ignored.
//! [`Config::load`] fails closed on any read, parse, or validation error.
//!
//! No secret value lives in this file. The KBS response-signing key is a
//! mounted file referenced by path; the Vault token is the `VAULT_TOKEN`
//! environment variable. Public keys (allowlist root, L1 kids, the KBS
//! channel pubkey) are hex and safe to keep in config.

use crate::error::Error;
use serde::Deserialize;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

/// Top-level configuration. Loaded once at startup.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub listen: Listen,
    pub storage: Storage,
    pub allowlist: Allowlist,
    pub keys: Keys,
    pub vault: Vault,
    pub launch_policy: LaunchPolicy,
    /// KEK-HSM RA-08a/F2 — when `true`, the KBS REFUSES a non-Transit-wrapped
    /// (plaintext) KEK at release (fail-closed "KEK ciphertext at rest").
    /// `#[serde(default)]` = `false` for a zero-behavior-change rollout that
    /// keeps `deny_unknown_fields` happy on existing configs; flip on once
    /// every staging path wraps (baker/vali/stage-script) + no legacy
    /// plaintext KEK is in use.
    #[serde(default)]
    pub require_wrapped_kek: bool,
    /// §6 — when `true`, the KBS REFUSES a userdata that is not
    /// Transit-wrapped at rest (the userdata counterpart of
    /// `require_wrapped_kek`). `#[serde(default)]` = `false`: a VM whose
    /// cloud-init was staged before the wrapping landed still holds
    /// plaintext and must keep booting. Flip on once none can.
    #[serde(default)]
    pub require_wrapped_userdata: bool,
    /// L1 OrderTicket-signing keys, keyed by `kid`. May be empty — with
    /// no keys every ticket fails signature verification (fail closed).
    #[serde(default)]
    pub l1_keys: Vec<L1Key>,
    /// AMD SEV-SNP attestation chain wiring (`[snp]`). Absent ⇒ the KBS
    /// wires a deny-closed chain verifier (release fails closed); present
    /// ⇒ the binary anchors the chain to a built-in AMD ARK + reads the
    /// per-host VEK PEM from `vek_pem_path`. The per-CHIP_ID VEK fetch +
    /// cache is the §17 follow-up.
    #[serde(default)]
    pub snp: Option<SnpConfig>,
    /// `[admin]` — KBS admin endpoint (`/v1/admin/vm/{vm_id}/register-vm`,
    /// plus Phase B `decommission`, `crypto-erase`, `activate`). Listens on
    /// a SEPARATE port from the public release transport so the public
    /// Ingress on `:8000` never receives a state-mutating request.
    /// Network ACL (CiliumNetworkPolicy) restricts callers to the vali
    /// pod. Cryptographic auth is the L1-signed `OrderTicket` in the
    /// request body — even a compromised network ACL cannot forge a
    /// register without an L1-signed ticket. Absent ⇒ admin disabled
    /// (the binary doesn't bind the admin port). Phase B: layered
    /// mTLS adds belt-#2 caller identity for §13 audit attribution.
    #[serde(default)]
    pub admin: Option<AdminConfig>,
    /// `[live_attestation]` — §322 Phase B. Pins the substrate
    /// compute-pallet identity bound into every signed
    /// `LiveAttestation` body. Mandatory: a missing or wrong value
    /// here would silently produce attestations the on-chain pallet
    /// rejects.
    pub live_attestation: LiveAttestationConfig,
    /// `[custody]` — the guest custody lease (`kbs_core::custody`).
    /// Absent, or `enabled = false` (the default), ⇒ the three
    /// `/v1/kbs/custody/*` routes answer 404 `custody-disabled` and
    /// nothing custody-related is stored.
    #[serde(default)]
    pub custody: Option<CustodyConfig>,
    /// `[rollback]` — the authorized rollback (A2, `kbs_core::rollback`).
    /// Absent ⇒ the compiled defaults (`min_interval_s = 1800`,
    /// `max_ttl_s = 3600`). The feature itself has no on/off switch here:
    /// with no arm nothing changes, and only vali (behind its own flag)
    /// creates arms.
    #[serde(default)]
    pub rollback: Option<RollbackConfig>,
    /// `[cdn_fleet]` — the CDN fleet keyring (`kbs_core::cdn_fleet`).
    /// Absent, or `enabled = false` (the default), ⇒ a CDN node release is
    /// refused (`cdn-fleet-disabled`) and `POST /v1/admin/cdn-fleet/public`
    /// answers 404; nothing else changes.
    #[serde(default)]
    pub cdn_fleet: CdnFleetConfig,
}

/// `[cdn_fleet]`.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CdnFleetConfig {
    /// Release the cdn-fleet keyring to a CDN node whose measurement is
    /// `cdn_node`-class AND whose ticket carries the `cdn-node` perm, and
    /// serve the admin public-key route. Needs the broker's
    /// `vault.cdn_fleet_policy` and the Vault side
    /// (`deploy/terraform/policies/kbs-cap-cdn-fleet.hcl`, Transit key
    /// `cdn-fleet`).
    #[serde(default)]
    pub enabled: bool,
}

/// `[rollback]`.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RollbackConfig {
    /// One rollback per VM per this many seconds (arm or consume).
    #[serde(default = "rollback_default_min_interval_s")]
    pub min_interval_s: u64,
    /// Longest arm TTL accepted; at most 3600.
    #[serde(default = "rollback_default_max_ttl_s")]
    pub max_ttl_s: u64,
}

fn rollback_default_min_interval_s() -> u64 {
    kbs_core::rollback::DEFAULT_MIN_INTERVAL_S
}
fn rollback_default_max_ttl_s() -> u64 {
    kbs_core::rollback::DEFAULT_MAX_TTL_S
}

/// `[custody]`. Every field but `enabled` has the production default; the
/// lease values are validated by `kbs_core::custody::CustodyPolicy`.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CustodyConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "custody_default_ttl_s")]
    pub ttl_s: u32,
    #[serde(default = "custody_default_stage2_s")]
    pub stage2_s: u32,
    #[serde(default = "custody_default_renew_s")]
    pub renew_s: u32,
    /// Allowed slowness of a guest's clock before `skew_suspected`, ppm.
    #[serde(default = "custody_default_skew_tolerance_ppm")]
    pub skew_tolerance_ppm: u64,
    #[serde(default = "custody_default_skew_min_window_s")]
    pub skew_min_window_s: u64,
    #[serde(default = "custody_default_skew_slack_s")]
    pub skew_slack_s: u64,
}

impl CustodyConfig {
    pub fn policy(&self) -> kbs_core::custody::CustodyPolicy {
        kbs_core::custody::CustodyPolicy {
            ttl_s: self.ttl_s,
            stage2_s: self.stage2_s,
            renew_s: self.renew_s,
        }
    }

    pub fn skew(&self) -> kbs_core::custody::SkewConfig {
        kbs_core::custody::SkewConfig {
            tolerance_ppm: self.skew_tolerance_ppm,
            min_window_s: self.skew_min_window_s,
            slack_s: self.skew_slack_s,
        }
    }
}

fn custody_default_ttl_s() -> u32 {
    kbs_core::custody::CustodyPolicy::default().ttl_s
}
fn custody_default_stage2_s() -> u32 {
    kbs_core::custody::CustodyPolicy::default().stage2_s
}
fn custody_default_renew_s() -> u32 {
    kbs_core::custody::CustodyPolicy::default().renew_s
}
fn custody_default_skew_tolerance_ppm() -> u64 {
    kbs_core::custody::SkewConfig::default().tolerance_ppm
}
fn custody_default_skew_min_window_s() -> u64 {
    kbs_core::custody::SkewConfig::default().min_window_s
}
fn custody_default_skew_slack_s() -> u64 {
    kbs_core::custody::SkewConfig::default().slack_s
}

/// HTTP transport bind settings.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Listen {
    /// Bind address, e.g. `"0.0.0.0:8000"`.
    pub addr: SocketAddr,
}

/// Durable on-disk state.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Storage {
    /// State root — holds `releases/`, `nonces/`, `vm-states.json` and
    /// `allowlist-hwm`. A PVC in the K6 deployment.
    pub state_dir: PathBuf,
    /// Hash-chained audit log directory. Its own PVC in K6 — the audit
    /// trail must survive independently of release state.
    pub audit_dir: PathBuf,
    /// KBS-nonce time-to-live, seconds. Must be > 0.
    pub nonce_ttl_secs: u64,
    /// §280 evidence-bundle archive directory. One CBOR file per
    /// granted release at `{evidence_dir}/{vm_id}/{ticket_id}.cbor`.
    /// Best-effort: a write failure is logged + dropped, the release
    /// still succeeds. Optional — when absent the KBS wires a
    /// `NullEvidenceSink` and persistence is disabled. Sibling of
    /// `audit_dir` in the K6 deployment, intended for its own PVC so
    /// retention/GC can be policy'd separately from the audit chain.
    #[serde(default)]
    pub evidence_dir: Option<PathBuf>,
    /// §322 live-attestation sink directory. One CBOR file per
    /// granted keepalive at
    /// `{live_attestation_dir}/pending/{vm_id}/{body_hash16}.cbor`.
    /// The vali batcher reads from `pending/` and moves submitted
    /// files to `submitted/` after the on-chain extrinsic lands.
    /// Best-effort, like `evidence_dir`. Optional — when absent the
    /// KBS wires a `NullLiveAttestationSink` and keepalive responses
    /// still flow to the caller but nothing is archived for the
    /// validator to pick up.
    #[serde(default)]
    pub live_attestation_dir: Option<PathBuf>,
    /// Per-`vm_id` monotonic boot counter file (Phase 1 of audit
    /// follow-up Review #2 — anti-rollback for valid-old-ciphertext
    /// replay). Default `{state_dir}/boot-counters.json`. Mirrors
    /// the `vm-states.json` discipline: atomic tmp+rename, parent-
    /// dir fsync, in-memory `Mutex<HashMap<String, u64>>` cache.
    ///
    /// The store also writes a SIBLING `<stem>-resync.json` next to it
    /// (`boot-counters-resync.json` by default) holding the one-shot
    /// operator resync arms — deliberately a second file so this one's
    /// `{vm_id: u64}` shape stays decodable by an older binary, i.e. so
    /// a KBS rollback cannot fail to `open` the store and lock out
    /// every tenant. There is no separate config key for it.
    #[serde(default)]
    pub boot_counter_path: Option<PathBuf>,
    /// Per-`vm_id` CONFIRMED volume stamp file (`kbs_core::volume_stamp`
    /// — anti-rollback for the guest-keyed overlay). Default
    /// `{state_dir}/volume-stamps.json`. Same atomic tmp+rename,
    /// parent-dir fsync, in-memory `Mutex<HashMap<String, u64>>` cache
    /// discipline as `boot_counter_path`.
    #[serde(default)]
    pub volume_stamp_path: Option<PathBuf>,
    /// Suppressed-confirm anti-rollback bound override
    /// (`kbs_core::volume_stamp::MAX_UNCONFIRMED_RELEASES`). This is a
    /// DEPLOYMENT-SAFETY knob, not a tuning one — see
    /// [`Config::resolve_max_unconfirmed_releases`] for the full
    /// rationale and the exact resolution rule. Two states, and ONLY
    /// two — do not read anything into other values beyond "raise or
    /// lower the bound":
    ///
    /// - Absent (`None`) ⇒ the COMPILED-IN default (ARMED, the secure
    ///   state — same fail-closed-by-default precedent as
    ///   `admin.require_mtls`). A config that says nothing about this
    ///   gets the safe behaviour.
    /// - `Some(0)` ⇒ DISABLED. The ONE way to turn the gate off
    ///   entirely: no VM is EVER refused for unconfirmed releases, no
    ///   matter how many accumulate. This is the value the chart MUST
    ///   render until the fleet is ready — see the module-level
    ///   deployment-sequence doc on [`Config::resolve_max_unconfirmed_
    ///   releases`].
    #[serde(default)]
    pub max_unconfirmed_releases: Option<u64>,
}

/// §22 offline measurement allowlist.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Allowlist {
    /// Allowlist-root Ed25519 public key, 32-byte hex. The §22 ceremony
    /// key; the KBS verifies every allowlist artifact against it.
    ///
    /// SPEC NOTE (`kbs_core::allowlist` module docs): the §22 spec calls
    /// for the root pubkey to be **compiled into the KBS binary** —
    /// rotation = binary redeploy. This binary currently reads it from
    /// operator config because the production ceremony root has not yet
    /// been chosen (#102 / §22-ceremony follow-up). In the GitOps
    /// deploy the ConfigMap is itself a signed Git commit, so an
    /// operator changing the root requires a chart PR + Argo sync — the
    /// same provenance gate the image digest goes through. The
    /// `in-binary` constant lands in lockstep with the production
    /// ceremony.
    pub root_pubkey_hex: String,
    /// OPTIONAL second accepted allowlist-root pubkey, 32-byte hex — the
    /// §22 KEY-ROTATION knob. When set, the KBS accepts an allowlist
    /// signed by EITHER `root_pubkey_hex` (primary/outgoing) OR this one
    /// (incoming). This lets a root-key rotation re-sign the artifact and
    /// swap the pinned pubkey WITHOUT an atomic flag-day: deploy with
    /// `next` = new pubkey (KBS accepts old or new), re-sign + upload the
    /// artifact under the new key, then promote `next` to primary and drop
    /// the old. Empty/absent ⇒ single-root steady state.
    #[serde(default)]
    pub root_pubkey_hex_next: Option<String>,
    /// COSE_Sign1 signed allowlist artifact path (fetched out-of-band
    /// from the `hippius-compute-allowlist` S3 bucket — in K6 by an
    /// init container). Absent ⇒ no allowlist installed and every
    /// release fails closed.
    #[serde(default)]
    pub signed_path: Option<PathBuf>,
    /// `true` ⇒ the release path refuses a `host_attestor`-class
    /// measurement (`kbs_core::snp::check_release_class`). Default `false`:
    /// the class was never checked on release before, so flip it only
    /// after confirming no live VM's measurement is pinned under it. The
    /// `cdn_node` class rules do not depend on this flag.
    #[serde(default)]
    pub enforce_release_class: bool,
}

/// KBS key material.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Keys {
    /// Path to the 32-byte Ed25519 seed for KBS response signing. A
    /// mounted secret — never inline in config.
    pub signing_key_path: PathBuf,
    /// KBS response-signing `kid`, hex. Non-empty; must be accepted by
    /// the installed allowlist for any release to succeed.
    pub kid_hex: String,
    /// KBS channel / TLS-exporter public key, hex. Non-empty. Bound into
    /// the attested-Vault evidence (§8).
    pub auth_pubkey_hex: String,
}

/// Vault access (MVP static-token KV client — see `vault_mvp`).
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Vault {
    /// Base URL, e.g. `"https://vault.example.invalid:8200"`. May be a
    /// bare IP:port — see `vault_endpoint_is_public`.
    pub address: String,
    /// KV-v2 secrets-engine mount, e.g. `"secret"`.
    pub kv_mount: String,
    /// **DEV-ONLY** override that bypasses the KBS-side measurement /
    /// TCB / launch-policy gates in `ChallengeVaultAuth`. Default
    /// `false` (production posture: every release fails closed at the
    /// Vault auth gate, per the MVP wiring documented in
    /// `wiring.rs`). When `true`, the binary widens the gates to
    /// `kbs_measurement_ok = |_| true`, `min_tcb = 0`,
    /// `required_bits = 0` so the placeholder all-zero
    /// `VerifiedReport` passes — letting downstream development
    /// (cloud-init validation, NetBird mesh smoke, #138 attestation
    /// persistence wire-up) exercise the full chain while the real
    /// SNP-attestation-bound broker (#102) is being built.
    ///
    /// This flag is debt, not a path to production. The binary:
    /// - prints a loud `⚠️  DEV-MODE` boot warning to stderr when set,
    /// - refuses to start if `vault.address` contains a production
    ///   marker substring (`tier0`, `prod`, `hippius.network`).
    ///
    /// Production deploys MUST leave this `false` (or omit it
    /// entirely). #102 closes the underlying gap and removes this
    /// override.
    #[serde(default)]
    pub dev_allow_any_kbs_measurement: bool,
    /// **DEV-ONLY** switch that skips TLS server-cert verification on
    /// the static-token Vault KV client. Default `false`. When `true`,
    /// `StaticTokenVaultKv` builds a rustls `ClientConfig` whose
    /// `ServerCertVerifier` accepts every certificate — letting the
    /// binary talk to a self-signed Tier-0 Vault (one that presents a
    /// leaf issued by its own self-CA) without baking that CA bundle
    /// into the image.
    ///
    /// Subject to the same prod-marker guard as
    /// `dev_allow_any_kbs_measurement`: the binary refuses to start
    /// with this flag set if `vault.address` lowercases to anything
    /// containing `tier0`, `prod`, or `hippius.network`. Boot stderr
    /// emits a loud `⚠️  DEV-MODE: vault.dev_skip_tls_verify=true`
    /// line. Production must leave this `false` (or omit it).
    #[serde(default)]
    pub dev_skip_tls_verify: bool,
    /// EXPLICIT non-production opt-in (audit H7). Every DEV-ONLY override
    /// above (`dev_allow_any_kbs_measurement`, `dev_skip_tls_verify`) is
    /// FAIL-CLOSED: `Config::validate` refuses to start with any of them
    /// set UNLESS this is `true` — AND the Vault endpoint is non-public.
    /// The old guard keyed off a prod-marker SUBSTRING in `vault.address`
    /// (`tier0`/`prod`/`hippius.network`), which a production Vault
    /// addressed by bare `IP:port` does NOT contain — so the guard never
    /// fired there and a config slip could open the measurement gate or
    /// MITM the KEK read. The address is now classified structurally
    /// (`vault_endpoint_is_public`), not by substring. Default
    /// `false` ⇒ production (which never sets this) can never enable a
    /// dev override, whatever the address.
    #[serde(default)]
    pub dev_environment: bool,
    /// PROD: path to the Vault CA bundle (PEM). When set, the KV-read
    /// client verifies the Vault server cert against EXACTLY this CA
    /// (normal chain + SAN) instead of `dev_skip_tls_verify`. Takes
    /// precedence over the dev skip; the two are mutually exclusive.
    #[serde(default)]
    pub ca_cert_path: Option<std::path::PathBuf>,
    /// §8 / #102 — base URL of the SNP-attestation-bound Vault broker
    /// (e.g. `http://kbs-vault-broker.kbs.svc:8100`). When set
    /// (non-empty), the KBS authenticates to the broker for EVERY
    /// release instead of the dev `ChallengeVaultAuth` seam: fresh
    /// challenge → fresh `/dev/sev-guest` self-report binding
    /// `nonce ‖ auth_pubkey` via `REPORT_DATA` → short-TTL per-VM
    /// Vault token. Mutually exclusive with
    /// `dev_allow_any_kbs_measurement` — the broker IS the
    /// measurement gate (see `Config::validate`). Absent / empty ⇒
    /// the existing dev seam is wired unchanged.
    #[serde(default)]
    pub broker_url: Option<String>,
    /// RA-KBS-M1 — PEM CA bundle the KBS pins for the broker's server cert
    /// when `broker_url` is `https://…`. Set ⇒ the broker↔KBS hop is TLS
    /// with this exact CA (the minted per-VM Vault token no longer transits
    /// the pod network in cleartext). Absent ⇒ plain HTTP (backward
    /// compatible with an `http://` broker_url).
    #[serde(default)]
    pub broker_ca_path: Option<std::path::PathBuf>,
}

/// §322 Phase B — on-chain bindings for the live-attestation flow.
///
/// Pins the compute-pallet identity the KBS copies into every signed
/// body. The pallet enforces both fields against
/// `T::ComputeChainGenesis::get()` /
/// `T::ComputePalletInstance::get()`; a mismatch fails closed at
/// `submit_live_attestation`.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LiveAttestationConfig {
    /// 32-byte compute-pallet chain-genesis discriminator, hex.
    pub compute_chain_genesis_hex: String,
    /// 32-byte compute-pallet instance discriminator, hex.
    pub compute_pallet_instance_hex: String,
    /// How keepalives are bound to the guest the KBS released to
    /// (`kbs_core::keepalive_binding`): `off` (default — legacy v1
    /// bodies, no binding), `record` (v2 bodies; a release-time binding is
    /// enforced, a VM with none is pinned on first use and flagged so), or
    /// `enforce` (v2; no release-time binding ⇒ refused). Consumers of v2
    /// (vali's verifier) must be deployed before this leaves `off`.
    #[serde(default = "default_keepalive_binding")]
    pub keepalive_binding: String,
    /// `enforce` only: seconds after the KBS state EPOCH (the first start
    /// on a fresh state dir, i.e. a pod replacement — see
    /// `kbs_core::keepalive_binding::grace_epoch_start`) during which a VM
    /// with NO binding record is served as `first-use` instead of
    /// refused, until `vali_kbs_recover` re-seeds it. Bound VMs are
    /// enforced strictly throughout. `0` (default) ⇒ strict enforce.
    /// Capped at [`MAX_KEEPALIVE_GRACE_SECS`].
    #[serde(default)]
    pub keepalive_binding_grace_secs: u64,
}

/// Upper bound on [`LiveAttestationConfig::keepalive_binding_grace_secs`]:
/// the window only has to cover a restart→recovery gap (minutes).
pub const MAX_KEEPALIVE_GRACE_SECS: u64 = 3_600;

fn default_keepalive_binding() -> String {
    "off".into()
}

impl LiveAttestationConfig {
    /// The parsed mode; `validate` has already refused anything else.
    pub fn keepalive_binding_mode(&self) -> kbs_core::keepalive_binding::BindingMode {
        kbs_core::keepalive_binding::BindingMode::parse(&self.keepalive_binding).unwrap_or_default()
    }
}

/// SNP launch-policy floor (`kbs_core::snp::LaunchPolicy`).
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LaunchPolicy {
    /// Minimum packed TCB version a guest must report.
    pub min_tcb: u64,
    /// Launch-policy bits that MUST be set.
    pub required_bits: u64,
    /// Bits allowed to vary beyond `required_bits`.
    pub allowed_mask: u64,
}

/// One L1 OrderTicket-signing key.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct L1Key {
    /// Key id, hex. Non-empty.
    pub kid_hex: String,
    /// Ed25519 public key, 32-byte hex.
    pub pubkey_hex: String,
}

/// AMD SEV-SNP attestation chain configuration.
///
/// The tenant-release verifier is generation-AGNOSTIC: per incoming
/// guest report it identifies the CPU generation (Milan / Genoa /
/// Turin) from the report itself and anchors to the matching built-in
/// AMD ARK + ASK, resolving the VCEK from (1) any cert table carried in
/// the report, (2) an AMD KDS fetch keyed by the report's chip_id + TCB
/// (when `kds_url` is set), or (3) the operator-mounted static VEK
/// below (only when its `generation` matches the report's). The static
/// VEK fallback keeps the existing single-generation Genoa-only
/// deploy working unchanged.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SnpConfig {
    /// AMD-generation root for the STATIC-VEK FALLBACK chain. Selects
    /// which `sev::certs::snp::builtin::*` pair anchors `vek_pem_path`.
    /// Does NOT constrain the generation-agnostic per-report path,
    /// which picks the ARK/ASK from each report's own CPU generation.
    /// See [`SnpGeneration`].
    pub generation: SnpGeneration,
    /// Per-host VEK certificate path (PEM) used as the fallback leaf
    /// when an incoming guest report carries no VCEK cert table AND
    /// KDS fetch is disabled. In a Genoa-only static-VEK deploy a sidecar
    /// fetches the per-CHIP_ID VEK and drops it here. Reading the file
    /// fails closed.
    pub vek_pem_path: PathBuf,
    /// AMD KDS base URL (e.g. `https://kdsintf.amd.com`) for fetching
    /// the per-chip VCEK of an incoming guest report that carries no
    /// cert table — the usual case for bare 1184-byte guest reports,
    /// and the ONLY VCEK source for a Turin guest whose chip differs
    /// from the configured static-VEK generation. The verifier derives
    /// the exact `/vcek/v1/{gen}/{chip_id}?…SPL=` URL from the report's
    /// chip_id + reported TCB (Turin = 8-byte chip_id form), fetches
    /// once, and caches the VCEK by URL so a release never blocks on
    /// KDS twice. Empty / absent disables KDS fetch — then a report
    /// with no cert table can only be served from the static VEK
    /// fallback (matching generation only). Mirrors the broker's
    /// `[snp].kds_url`.
    #[serde(default)]
    pub kds_url: Option<String>,
}

/// AMD SEV-SNP host generation — selects which built-in ARK + ASK the
/// binary anchors the **static-VEK fallback** chain to.
///
/// This field ONLY governs the legacy static-VEK fallback path (a
/// report that carries no VCEK cert table AND for which KDS fetch is
/// disabled — e.g. a Genoa-only static-VEK deploy). The primary
/// tenant-release path is generation-AGNOSTIC: it identifies the
/// generation from each incoming guest report's own CPU fields and
/// anchors to the matching built-in ARK/ASK + the report-resolved
/// VCEK, so a Turin guest verifies even when `generation = "genoa"` is
/// configured for the static fallback (see `attest::MultiGenChainVerifier`).
///
/// `milan` (3rd-gen EPYC), `genoa` (4th-gen EPYC) and `turin` (5th-gen
/// EPYC) are all accepted. Their ARK/ASK pairs are NOT byte-identical
/// (the `sev` crate ships separate `builtin::{milan,genoa,turin}`
/// modules), so the operator MUST pick the one matching the physical
/// host whose chip signed the mounted VEK fallback. Turin guests emit
/// v3/v5 reports, accepted by `kbs_core::snp_real::SUPPORTED_REPORT_
/// VERSIONS = [2, 5]`.
#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SnpGeneration {
    Milan,
    Genoa,
    Turin,
}

/// `[admin]` — KBS admin endpoint configuration.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdminConfig {
    /// Admin listener bind address, e.g. `"0.0.0.0:8001"`. Distinct
    /// from `listen.addr` so the public release Ingress never
    /// receives an admin request. Authentication on this listener is
    /// mTLS — see [`Self::require_mtls`] and
    /// [`crate::admin_tls`].
    pub addr: SocketAddr,
    /// Sub-directory under `storage.state_dir` for the admin
    /// idempotency store. Created on first start.
    #[serde(default = "default_admin_idem_subdir")]
    pub idempotency_subdir: PathBuf,
    /// Sub-directory under `storage.audit_dir` for the admin
    /// hash-chained log (`admin.log` + `admin.head.sha256`).
    /// Created on first start; INDEPENDENT chain from the release
    /// `audit.log`.
    #[serde(default = "default_admin_audit_subdir")]
    pub audit_subdir: PathBuf,
    /// Admin idempotency store TTL, seconds. Default 24 h. A
    /// successful register stays recallable for this long; a
    /// retry within the window is cached, after that a fresh apply
    /// is allowed. Should comfortably exceed the longest plausible
    /// operator retry window.
    #[serde(default = "default_admin_idem_ttl")]
    pub idempotency_ttl_secs: u64,
    /// Per-process admin rate-limit: tokens/sec sustained.
    /// Default 10 — the admin endpoint runs at vali-launch QPS
    /// (very low), not at guest-boot QPS.
    #[serde(default = "default_admin_rate_per_sec")]
    pub rate_per_sec: u64,
    /// Per-process admin rate-limit: max burst.
    #[serde(default = "default_admin_burst")]
    pub burst: u32,

    // ── mTLS (the admin listener's ONLY authentication) ──────────────
    /// Refuse to bind the admin listener unless the mTLS material below
    /// is configured. **Defaults to `true`** — a config that says
    /// nothing about TLS gets the fail-closed answer, because the admin
    /// routes mutate the lifecycle state that decides which host may
    /// unlock a tenant disk and there is no per-request credential
    /// behind them.
    ///
    /// Setting it to `false` NO LONGER serves the routes in plaintext on
    /// its own: without material the listener is refused unless
    /// [`Self::dev_allow_plaintext`] is also set. It does NOT downgrade a
    /// listener whose material IS present — certs, once configured, are
    /// always enforced.
    #[serde(default = "default_admin_require_mtls")]
    pub require_mtls: bool,
    /// DEV ONLY: serve the admin routes in PLAINTEXT when no mTLS
    /// material is configured (and `require_mtls = false`). Network
    /// policy is then the only control over the API that decides which
    /// host may unlock a tenant disk, so it is logged at every start as
    /// UNAUTHENTICATED. Default `false`; production never sets it.
    #[serde(default)]
    pub dev_allow_plaintext: bool,
    /// SPIFFE IDs allowed on the admin listener. A CA-verified leaf is
    /// admitted only if it carries ≥1 URI SAN, EVERY URI SAN is listed
    /// here, and it carries no other SAN type (see
    /// `admin_tls::authorize_admin_peer`); DNS SANs and the Subject CN
    /// are never identities. Each entry must be a canonical
    /// `spiffe://` ID — anything else fails the config load. Chaining to
    /// the admin CA is necessary but NOT sufficient: a leaf minted for
    /// any other purpose is dropped before a request is read. Default:
    /// vali's identity, the only client leaf issued
    /// (`spiffe://hippius.network/vali`).
    #[serde(default = "default_admin_allowed_client_identities")]
    pub allowed_client_identities: Vec<kbs_transport::SpiffeId>,
    /// PEM server cert chain the admin listener presents (leaf first).
    #[serde(default)]
    pub tls_cert_path: Option<PathBuf>,
    /// PEM private key for `tls_cert_path` (PKCS#8 / SEC1).
    #[serde(default)]
    pub tls_key_path: Option<PathBuf>,
    /// **Pinned** PEM CA bundle. Every admin client cert must chain to
    /// it; rustls refuses the handshake otherwise. Its SANs become the
    /// `peer_san` attribution in the admin audit chain.
    #[serde(default)]
    pub client_ca_path: Option<PathBuf>,
}

fn default_admin_idem_subdir() -> PathBuf {
    PathBuf::from("admin-idempotency")
}

fn default_admin_audit_subdir() -> PathBuf {
    PathBuf::from("admin")
}

fn default_admin_idem_ttl() -> u64 {
    86_400
}

fn default_admin_rate_per_sec() -> u64 {
    10
}

fn default_admin_burst() -> u32 {
    20
}

/// The one admin client identity issued (vali's client leaf).
pub const VALI_ADMIN_IDENTITY: &str = "spiffe://hippius.network/vali";

pub(crate) fn default_admin_allowed_client_identities() -> Vec<kbs_transport::SpiffeId> {
    // A compile-time constant that the parser tests pin as valid.
    #[allow(clippy::expect_used)]
    let vali = kbs_transport::SpiffeId::parse(VALI_ADMIN_IDENTITY)
        .expect("VALI_ADMIN_IDENTITY is a valid SPIFFE ID");
    vec![vali]
}

/// Fail-closed default: an `[admin]` block that says nothing about TLS
/// requires TLS.
fn default_admin_require_mtls() -> bool {
    true
}

impl Config {
    /// The resolved `[rollback]` policy (compiled defaults when absent).
    pub fn rollback_policy(&self) -> kbs_core::rollback::RollbackPolicy {
        match &self.rollback {
            Some(r) => kbs_core::rollback::RollbackPolicy {
                min_interval_s: r.min_interval_s,
                max_ttl_s: r.max_ttl_s,
            },
            None => kbs_core::rollback::RollbackPolicy::default(),
        }
    }

    /// Read, parse, and validate. Any failure is fatal (fail closed).
    pub fn load(path: &Path) -> Result<Config, Error> {
        let raw = std::fs::read_to_string(path)
            .map_err(|e| Error::Config(format!("read {}: {e}", path.display())))?;
        let cfg: Config = toml::from_str(&raw)
            .map_err(|e| Error::Config(format!("parse {}: {e}", path.display())))?;
        cfg.validate()?;
        Ok(cfg)
    }

    /// Resolve `storage.max_unconfirmed_releases` into the value
    /// `kbs_core::release::Deps::max_unconfirmed_releases` actually
    /// enforces (threaded through `wiring::build_service` →
    /// `DefaultKbsService::new`). This is the ONE place "off" is
    /// decided from raw operator input — `kbs-core` and `kbs-transport`
    /// downstream only ever see the already-resolved `Option<u64>` and
    /// never re-derive meaning from a config value themselves.
    ///
    /// | `storage.max_unconfirmed_releases` | resolves to | meaning |
    /// |---|---|---|
    /// | absent (`None`) | `Some(MAX_UNCONFIRMED_RELEASES)` | ARMED at the compiled default |
    /// | `Some(0)` | `None` | DISABLED — no VM is ever refused |
    /// | `Some(n)`, `n >= 1` | `Some(n)` | ARMED at `n` |
    ///
    /// ## Why this exists at all — the deployment hazard
    ///
    /// The suppressed-confirm gate (`kbs_core::volume_stamp`) is
    /// unconditional per `vm_id`: every release counts against it, with
    /// no exemption for a guest that has no way to ever confirm. A
    /// LEGACY VM — any guest whose initramfs predates the
    /// `/v1/kbs/volume-stamp/confirm` route — is exactly that guest.
    /// Ship this KBS build with the gate ARMED against a fleet that
    /// hasn't been re-baked yet and every legacy VM is refused after
    /// `bound` releases (a release happens on every boot, every §25
    /// migration, and every reboot-recovery relaunch — not only a
    /// deliberate reboot). Nothing can un-brick it except the admin
    /// reset, which buys exactly `bound` more releases before it trips
    /// again — a fuse, not a fix.
    ///
    /// A legacy EXEMPTION keyed on `confirmed == 0` was considered and
    /// rejected: it reopens the exact hole this gate exists to close. A
    /// miner that suppresses confirms from a VM's very FIRST boot keeps
    /// `confirmed` at 0 forever, so an exemption keyed on it would never
    /// arm for precisely the VM under attack — a compatibility bypass
    /// wearing a legacy-guest costume.
    ///
    /// So arming has to be an OPERATOR STEP, sequenced explicitly
    /// (mirrors `admin.require_mtls`'s code-default-secure /
    /// chart-carries-the-transitional-override precedent — see
    /// `deploy/gitops/apps/kbs/values.yaml`'s `admin.requireMtls`):
    ///   1. deploy this KBS build with `max_unconfirmed_releases = 0`
    ///      (DISABLED) still rendered in the chart;
    ///   2. re-bake and re-bless every golden image against it;
    ///   3. verify confirms are arriving fleet-wide (the admin audit
    ///      chain / `note_release` no longer accumulating per VM);
    ///   4. THEN raise or remove `max_unconfirmed_releases` in the
    ///      chart to arm the gate.
    ///
    /// Until step 4, the anti-rollback gate this whole module exists
    /// for is bypassable by confirm suppression — that is the accepted,
    /// documented cost of not bricking the fleet on day one.
    pub fn resolve_max_unconfirmed_releases(configured: Option<u64>) -> Option<u64> {
        match configured {
            None => Some(kbs_core::volume_stamp::MAX_UNCONFIRMED_RELEASES),
            Some(0) => None,
            Some(n) => Some(n),
        }
    }

    /// Semantic checks beyond what `serde` enforces structurally. Hex /
    /// key-byte validation happens in `wiring` (it needs the decoded
    /// values); both paths fail closed.
    fn validate(&self) -> Result<(), Error> {
        if let Some(admin) = &self.admin {
            // Each entry is already a parsed `SpiffeId` (a non-`spiffe://`
            // entry fails deserialization); only emptiness is left.
            if admin.allowed_client_identities.is_empty() {
                return Err(Error::Config(
                    "admin.allowed_client_identities must list at least one spiffe:// identity \
                     — an empty allowlist would admit no one"
                        .into(),
                ));
            }
        }
        if kbs_core::keepalive_binding::BindingMode::parse(&self.live_attestation.keepalive_binding)
            .is_none()
        {
            return Err(Error::Config(format!(
                "live_attestation.keepalive_binding = {:?}: expected off, record or enforce",
                self.live_attestation.keepalive_binding
            )));
        }
        let grace = self.live_attestation.keepalive_binding_grace_secs;
        if grace > MAX_KEEPALIVE_GRACE_SECS {
            return Err(Error::Config(format!(
                "live_attestation.keepalive_binding_grace_secs = {grace}: above the \
                 {MAX_KEEPALIVE_GRACE_SECS} s cap"
            )));
        }
        if grace > 0
            && self.live_attestation.keepalive_binding_mode()
                != kbs_core::keepalive_binding::BindingMode::Enforce
        {
            return Err(Error::Config(
                "live_attestation.keepalive_binding_grace_secs is only meaningful with \
                 keepalive_binding = \"enforce\""
                    .into(),
            ));
        }
        if self.storage.nonce_ttl_secs == 0 {
            return Err(Error::Config("storage.nonce_ttl_secs must be > 0".into()));
        }
        // A bad lease policy is fatal at load, whether or not custody is
        // enabled yet — flipping `enabled` later must never be the moment
        // an invalid TTL is discovered.
        if let Some(custody) = &self.custody {
            custody
                .policy()
                .validate()
                .map_err(|e| Error::Config(format!("[custody]: {e}")))?;
        }
        self.rollback_policy()
            .validate()
            .map_err(|e| Error::Config(format!("[rollback]: {e}")))?;
        // Admin mTLS material is all-or-nothing. A server cert with no
        // pinned client CA is TLS *without authentication* — it would
        // look encrypted while accepting any caller — and a client CA
        // with no server identity cannot bind at all. Partial material
        // is never a legitimate intermediate state, so it is fatal at
        // load rather than silently degraded at bind.
        if let Some(admin) = &self.admin {
            let present = [
                admin.tls_cert_path.is_some(),
                admin.tls_key_path.is_some(),
                admin.client_ca_path.is_some(),
            ];
            if present.iter().any(|p| *p) && !present.iter().all(|p| *p) {
                return Err(Error::Config(
                    "admin.{tls_cert_path,tls_key_path,client_ca_path} must be set together \
                     — a partial mTLS config would serve the lifecycle-mutation API without \
                     authenticating its callers"
                        .into(),
                ));
            }
        }
        if self.vault.address.trim().is_empty() {
            return Err(Error::Config("vault.address must not be empty".into()));
        }
        if self.vault.kv_mount.trim().is_empty() {
            return Err(Error::Config("vault.kv_mount must not be empty".into()));
        }
        // §8 / #102: with the broker wired, the broker's own KBS
        // measurement allowlist is THE auth gate — letting the dev
        // measurement bypass coexist would suggest it still widens
        // something (it wouldn't) and invites leaving it on in prod.
        // `dev_skip_tls_verify` stays allowed: it governs the KV-read
        // TLS toward the self-signed Tier-0 Vault, orthogonal to the
        // broker hop.
        if self
            .vault
            .broker_url
            .as_deref()
            .is_some_and(|u| !u.trim().is_empty())
            && self.vault.dev_allow_any_kbs_measurement
        {
            return Err(Error::Config(
                "vault.broker_url and vault.dev_allow_any_kbs_measurement are mutually \
                 exclusive — the broker IS the measurement gate"
                    .into(),
            ));
        }
        // CA-pin and dev-skip are mutually exclusive (CA wins).
        if self.vault.ca_cert_path.is_some() && self.vault.dev_skip_tls_verify {
            return Err(Error::Config(
                "vault.ca_cert_path and vault.dev_skip_tls_verify are mutually exclusive \
                 — drop the dev skip when pinning the Vault CA"
                    .into(),
            ));
        }
        // FAIL-CLOSED guard for both DEV-ONLY overrides (audit H7). The
        // old guard refused only when `vault.address` contained a
        // prod-marker SUBSTRING (`tier0`/`prod`/`hippius.network`) — which
        // did NOT match the IP-addressed production Vault, so a config
        // slip could enable a dev override in prod. Now the overrides are
        // default-DENY: refused unless the operator EXPLICITLY asserts
        // `vault.dev_environment=true` AND the Vault endpoint is non-public
        // (loopback/private/link-local IP, or absent host). A production
        // config (which never sets `dev_environment`) can never enable
        // them, whatever the address.
        let dev_flags: &[(bool, &str)] = &[
            (
                self.vault.dev_allow_any_kbs_measurement,
                "dev_allow_any_kbs_measurement",
            ),
            (self.vault.dev_skip_tls_verify, "dev_skip_tls_verify"),
        ];
        if dev_flags.iter().any(|(on, _)| *on) {
            let flag_list = dev_flags
                .iter()
                .filter(|(on, _)| *on)
                .map(|(_, name)| *name)
                .collect::<Vec<_>>()
                .join(", ");
            if !self.vault.dev_environment {
                return Err(Error::Config(format!(
                    "vault.{{{}}}=true requires an EXPLICIT vault.dev_environment=true \
                     opt-in (fail-closed — these overrides are never for production; \
                     #102 closes the underlying gap properly).",
                    flag_list,
                )));
            }
            if vault_endpoint_is_public(&self.vault.address) {
                return Err(Error::Config(format!(
                    "vault.{{{}}}=true is refused against the public Vault endpoint \
                     ({:?}) even with dev_environment=true — dev overrides are only \
                     for a loopback/private dev Vault.",
                    flag_list, self.vault.address,
                )));
            }
        }
        Ok(())
    }
}

/// Classify a `vault.address` as a PUBLIC (globally-routable) endpoint
/// for the fail-closed dev-override guard (audit H7). Returns `true` when
/// the host parses as a public IP address OR is a non-local DNS name —
/// i.e. NOT a loopback/private/link-local IP and NOT a `localhost` /
/// `*.local` / `*.localhost` name. A public endpoint — including a
/// production Vault reached by bare `IP:port`, which carries no
/// prod-marker substring — can never host a dev override. Fail-closed on a
/// host we can't confidently classify as local (returns `true`).
fn vault_endpoint_is_public(address: &str) -> bool {
    // Strip scheme, path, and :port to isolate the host.
    let no_scheme = address
        .split_once("://")
        .map(|(_, rest)| rest)
        .unwrap_or(address);
    let host = no_scheme
        .split('/')
        .next()
        .unwrap_or(no_scheme)
        // `host:port` — but an IPv6 literal is `[::1]:8200`; handle both.
        .trim();
    let host = if let Some(inner) = host.strip_prefix('[') {
        // `[ipv6]:port` → the part before `]`.
        inner.split(']').next().unwrap_or(inner)
    } else {
        // `host:port` — split off a trailing `:port` only if the head has
        // no other colon (so a bare IPv6 without brackets stays intact).
        match host.rsplit_once(':') {
            Some((h, p)) if !h.contains(':') && p.chars().all(|c| c.is_ascii_digit()) => h,
            _ => host,
        }
    };
    if host.is_empty() {
        return true; // can't classify ⇒ fail-closed (treat as public)
    }
    if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        // A non-local IP is public.
        return !(ip.is_loopback()
            || ip.is_unspecified()
            || match ip {
                std::net::IpAddr::V4(v4) => v4.is_private() || v4.is_link_local(),
                // ULA (fc00::/7) + link-local (fe80::/10) are the IPv6
                // "private" ranges; `is_unique_local`/`is_unicast_link_local`
                // are unstable, so match the prefixes directly.
                std::net::IpAddr::V6(v6) => {
                    let seg = v6.segments();
                    (seg[0] & 0xfe00) == 0xfc00 || (seg[0] & 0xffc0) == 0xfe80
                }
            });
    }
    // A DNS name: only RFC-standardised local names are non-public.
    // `localhost`/`*.localhost` are RFC 6761 guaranteed-loopback;
    // `.local` is RFC 6762 mDNS link-local (also k8s `.cluster.local`).
    // `.internal` was DROPPED (RA-KBS-VL4): it has NO standards basis
    // for being local — a self-hosted `vault.internal` resolves to an
    // arbitrary (possibly public) address, so treating it as local
    // could let a `dev_environment` deploy skip TLS verify toward a
    // real remote Vault. Now classified public ⇒ dev overrides refused.
    let h = host.to_ascii_lowercase();
    !(h == "localhost" || h.ends_with(".localhost") || h.ends_with(".local"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn write_tmp(body: &str) -> tempfile::NamedTempFile {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        f.write_all(body.as_bytes()).unwrap();
        f
    }

    const MINIMAL: &str = r#"
[listen]
addr = "0.0.0.0:8000"

[storage]
state_dir = "/var/lib/kbs/state"
audit_dir = "/var/lib/kbs/audit"
nonce_ttl_secs = 300

[allowlist]
root_pubkey_hex = "aa"

[keys]
signing_key_path = "/etc/kbs/signing.key"
kid_hex = "6b6273"
auth_pubkey_hex = "6b6273"

[vault]
address = "https://vault:8200"
kv_mount = "secret"

[launch_policy]
min_tcb = 0
required_bits = 0
allowed_mask = 0

[live_attestation]
compute_chain_genesis_hex = "6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e"
compute_pallet_instance_hex = "c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0"
"#;

    #[test]
    fn loads_minimal_config() {
        let f = write_tmp(MINIMAL);
        let cfg = Config::load(f.path()).expect("minimal config should load");
        assert_eq!(cfg.storage.nonce_ttl_secs, 300);
        assert!(cfg.l1_keys.is_empty());
        assert!(cfg.allowlist.signed_path.is_none());
        // [snp] is absent by default — the binary wires the deny-closed
        // chain verifier in that branch (fail closed until VEK mounted).
        assert!(cfg.snp.is_none());
        // Deployment-safety default: a config that says nothing about
        // the suppressed-confirm bound parses to `None` — see
        // `resolve_max_unconfirmed_releases` for what that resolves to.
        assert!(cfg.storage.max_unconfirmed_releases.is_none());
    }

    #[test]
    fn custody_is_off_unless_explicitly_enabled() {
        let cfg = Config::load(write_tmp(MINIMAL).path()).unwrap();
        assert!(cfg.custody.is_none());
        assert!(crate::wiring::build_custody(&cfg).unwrap().is_none());
        let with_section = format!("{MINIMAL}\n[custody]\n");
        let cfg = Config::load(write_tmp(&with_section).path()).unwrap();
        let c = cfg.custody.as_ref().unwrap();
        assert!(!c.enabled, "an empty [custody] section stays off");
        assert_eq!(c.policy(), kbs_core::custody::CustodyPolicy::default());
        assert!(crate::wiring::build_custody(&cfg).unwrap().is_none());
    }

    #[test]
    fn enabled_custody_builds_a_runtime_under_the_state_dir() {
        let td = tempfile::TempDir::new().unwrap();
        let body = MINIMAL.replace("/var/lib/kbs/state", td.path().to_str().unwrap())
            + "\n[custody]\nenabled = true\nttl_s = 7200\nrenew_s = 300\n";
        let cfg = Config::load(write_tmp(&body).path()).unwrap();
        let rt = crate::wiring::build_custody(&cfg).unwrap().unwrap();
        assert_eq!(rt.policy().ttl_s, 7200);
        assert_eq!(rt.policy().renew_s, 300);
    }

    #[test]
    fn an_out_of_bounds_custody_policy_is_fatal_even_while_disabled() {
        for bad in [
            "ttl_s = 604801",
            "ttl_s = 60",
            "renew_s = 1",
            "stage2_s = 0",
        ] {
            let body = format!("{MINIMAL}\n[custody]\n{bad}\n");
            assert!(Config::load(write_tmp(&body).path()).is_err(), "{bad}");
        }
        let body = format!("{MINIMAL}\n[custody]\ngrant_all = true\n");
        assert!(
            Config::load(write_tmp(&body).path()).is_err(),
            "unknown key"
        );
    }

    #[test]
    fn rollback_defaults_apply_when_the_section_is_absent_or_empty() {
        let cfg = Config::load(write_tmp(MINIMAL).path()).unwrap();
        assert!(cfg.rollback.is_none());
        assert_eq!(
            cfg.rollback_policy(),
            kbs_core::rollback::RollbackPolicy {
                min_interval_s: 1800,
                max_ttl_s: 3600
            }
        );
        let cfg = Config::load(write_tmp(&format!("{MINIMAL}\n[rollback]\n")).path()).unwrap();
        assert_eq!(
            cfg.rollback_policy(),
            kbs_core::rollback::RollbackPolicy::default()
        );
        let body = format!("{MINIMAL}\n[rollback]\nmin_interval_s = 600\nmax_ttl_s = 900\n");
        let cfg = Config::load(write_tmp(&body).path()).unwrap();
        assert_eq!(
            cfg.rollback_policy(),
            kbs_core::rollback::RollbackPolicy {
                min_interval_s: 600,
                max_ttl_s: 900
            }
        );
    }

    #[test]
    fn a_rollback_policy_past_the_one_hour_ttl_ceiling_is_fatal() {
        for bad in [
            "max_ttl_s = 3601",
            "max_ttl_s = 59",
            "min_interval_s = 0",
            "enabled = true",
        ] {
            let body = format!("{MINIMAL}\n[rollback]\n{bad}\n");
            assert!(Config::load(write_tmp(&body).path()).is_err(), "{bad}");
        }
    }

    #[test]
    fn max_unconfirmed_releases_parses_an_explicit_value() {
        let body = MINIMAL.replace(
            "nonce_ttl_secs = 300",
            "nonce_ttl_secs = 300\nmax_unconfirmed_releases = 0",
        );
        let f = write_tmp(&body);
        let cfg = Config::load(f.path()).expect("explicit max_unconfirmed_releases should parse");
        assert_eq!(cfg.storage.max_unconfirmed_releases, Some(0));
    }

    // ── suppressed-confirm bound resolution (deployment safety) ──────

    #[test]
    fn resolve_max_unconfirmed_releases_absent_config_arms_the_compiled_default() {
        // CLAIM: a config that says nothing about this gets the SECURE
        // state — same fail-closed-by-default precedent as
        // `admin.require_mtls`. A mutant that flips this to `None`
        // (disabled) would silently ship every fresh deploy unarmed.
        assert_eq!(
            Config::resolve_max_unconfirmed_releases(None),
            Some(kbs_core::volume_stamp::MAX_UNCONFIRMED_RELEASES)
        );
    }

    #[test]
    fn resolve_max_unconfirmed_releases_explicit_zero_disables() {
        // CLAIM: `0` is the ONE way to disable the gate. This is the
        // value the chart MUST render until the fleet is re-baked.
        assert_eq!(Config::resolve_max_unconfirmed_releases(Some(0)), None);
    }

    #[test]
    fn resolve_max_unconfirmed_releases_nonzero_override_is_used_verbatim() {
        // CLAIM: any non-zero configured value raises or lowers the
        // bound from the compiled default — it is not clamped or
        // reinterpreted.
        for n in [1u64, 2, 3, 4, 100, u64::MAX] {
            assert_eq!(
                Config::resolve_max_unconfirmed_releases(Some(n)),
                Some(n),
                "n={n}"
            );
        }
    }

    #[test]
    fn admin_require_mtls_defaults_to_true() {
        // CLAIM: an `[admin]` block that says nothing about TLS gets the
        // FAIL-CLOSED answer. If this default ever flipped, every
        // existing deployment would silently serve the lifecycle
        // admin API unauthenticated.
        let body = format!("{MINIMAL}\n\n[admin]\naddr = \"0.0.0.0:8001\"\n");
        let f = write_tmp(&body);
        let cfg = Config::load(f.path()).expect("[admin] without TLS keys must still parse");
        let admin = cfg.admin.expect("admin must parse");
        assert!(admin.require_mtls);
        assert!(admin.tls_cert_path.is_none());
        assert!(admin.client_ca_path.is_none());
    }

    #[test]
    fn admin_identities_default_to_vali_and_a_bad_list_refuses_to_load() {
        let body = format!("{MINIMAL}\n\n[admin]\naddr = \"0.0.0.0:8001\"\n");
        let f = write_tmp(&body);
        let admin = Config::load(f.path()).unwrap().admin.unwrap();
        assert_eq!(
            admin
                .allowed_client_identities
                .iter()
                .map(|i| i.as_str())
                .collect::<Vec<_>>(),
            vec![VALI_ADMIN_IDENTITY]
        );
        assert!(!admin.dev_allow_plaintext);
        // A listed identity may only be a canonical spiffe:// URI: a DNS
        // name, a CN, another scheme, a padded or non-canonical spelling,
        // or one bad entry among good ones all refuse the whole config.
        for list in [
            "[]",
            "[\"\"]",
            "[\" spiffe://hippius.network/vali\"]",
            "[\"vali\"]",
            "[\"vali.hippius.svc\"]",
            "[\"https://hippius.network/vali\"]",
            "[\"SPIFFE://hippius.network/vali\"]",
            "[\"spiffe://hippius.network/vali/\"]",
            "[\"spiffe://hippius.network/vali\", \"vali.hippius.svc\"]",
        ] {
            let body = format!(
                "{MINIMAL}\n\n[admin]\naddr = \"0.0.0.0:8001\"\nallowed_client_identities = {list}\n"
            );
            let f = write_tmp(&body);
            assert!(
                Config::load(f.path()).is_err(),
                "{list} must refuse to load"
            );
        }
        let body = format!(
            "{MINIMAL}\n\n[admin]\naddr = \"0.0.0.0:8001\"\nallowed_client_identities = \
             [\"spiffe://hippius.network/vali\", \"spiffe://hippius.network/operator\"]\n"
        );
        let f = write_tmp(&body);
        assert_eq!(
            Config::load(f.path())
                .unwrap()
                .admin
                .unwrap()
                .allowed_client_identities
                .len(),
            2
        );
    }

    #[test]
    fn admin_mtls_paths_parse_and_the_opt_out_is_explicit() {
        // The chart's rendered shape. `require_mtls = false` is the ONE
        // way to get an unauthenticated admin listener and it has to be
        // written out in the config to happen.
        let body = format!(
            "{MINIMAL}\n\n[admin]\naddr = \"0.0.0.0:8001\"\nrequire_mtls = false\n\
             tls_cert_path = \"/etc/kbs-admin-tls/tls.crt\"\n\
             tls_key_path = \"/etc/kbs-admin-tls/tls.key\"\n\
             client_ca_path = \"/etc/kbs-admin-tls/ca.crt\"\n"
        );
        let f = write_tmp(&body);
        let cfg = Config::load(f.path()).expect("full admin mTLS config must load");
        let admin = cfg.admin.expect("admin must parse");
        assert!(!admin.require_mtls);
        assert_eq!(
            admin.tls_cert_path,
            Some(PathBuf::from("/etc/kbs-admin-tls/tls.crt"))
        );
        assert_eq!(
            admin.tls_key_path,
            Some(PathBuf::from("/etc/kbs-admin-tls/tls.key"))
        );
        assert_eq!(
            admin.client_ca_path,
            Some(PathBuf::from("/etc/kbs-admin-tls/ca.crt"))
        );
    }

    #[test]
    fn partial_admin_mtls_material_is_refused_at_load() {
        // CLAIM: all-or-nothing. A server cert with no pinned client CA
        // is TLS *without authentication* — it would look encrypted
        // while admitting any caller — so it must never load.
        for extra in [
            "tls_cert_path = \"/c\"\ntls_key_path = \"/k\"\n",
            "tls_cert_path = \"/c\"\nclient_ca_path = \"/a\"\n",
            "client_ca_path = \"/a\"\n",
        ] {
            let body = format!("{MINIMAL}\n\n[admin]\naddr = \"0.0.0.0:8001\"\n{extra}");
            let f = write_tmp(&body);
            let err = Config::load(f.path()).expect_err("partial mTLS material must be refused");
            assert!(
                format!("{err}").contains("must be set together"),
                "unexpected error: {err}"
            );
        }
    }

    #[test]
    fn loads_l1_keys_section() {
        // The helm chart renders `[[l1_keys]]` from `.Values.l1Keys`; this
        // test pins the parser shape it produces — kid_hex + pubkey_hex,
        // one table per key. A drift in the template field names surfaces
        // as a parse failure rather than a silent empty keyring.
        let body = format!(
            "{MINIMAL}\n\n[[l1_keys]]\nkid_hex = \"6c312d6f726465722d7469636b65742d6465762d7631\"\npubkey_hex = \"611ed9f2d689c8ba965f353b146309fb559a419b3247a33aa4a9d2781dd39159\"\n"
        );
        let f = write_tmp(&body);
        let cfg = Config::load(f.path()).expect("config with [[l1_keys]] must load");
        assert_eq!(cfg.l1_keys.len(), 1);
        assert_eq!(
            cfg.l1_keys[0].kid_hex,
            "6c312d6f726465722d7469636b65742d6465762d7631"
        );
        assert_eq!(
            cfg.l1_keys[0].pubkey_hex,
            "611ed9f2d689c8ba965f353b146309fb559a419b3247a33aa4a9d2781dd39159"
        );
    }

    #[test]
    fn loads_snp_section() {
        // `milan`, `genoa` and `turin` are accepted for the static-VEK
        // fallback; the operator picks the one matching the chip that
        // signed the mounted VEK.
        for (gen_str, expected) in [
            ("milan", SnpGeneration::Milan),
            ("genoa", SnpGeneration::Genoa),
            ("turin", SnpGeneration::Turin),
        ] {
            let body = format!(
                "{MINIMAL}\n\n[snp]\ngeneration = \"{gen_str}\"\nvek_pem_path = \"/etc/kbs/vek.pem\"\n"
            );
            let f = write_tmp(&body);
            let cfg = Config::load(f.path()).expect("config with [snp] should load");
            let snp = cfg.snp.expect("snp must parse");
            // SnpGeneration is Copy + we matched literally above, so
            // discriminant comparison is the cleanest assertion.
            assert!(
                matches!(
                    (snp.generation, expected),
                    (SnpGeneration::Milan, SnpGeneration::Milan)
                        | (SnpGeneration::Genoa, SnpGeneration::Genoa)
                        | (SnpGeneration::Turin, SnpGeneration::Turin)
                ),
                "generation = {gen_str:?} parsed wrong"
            );
            assert_eq!(snp.vek_pem_path, PathBuf::from("/etc/kbs/vek.pem"));
            // `kds_url` is optional and defaults to None.
            assert!(snp.kds_url.is_none());
        }
    }

    #[test]
    fn loads_snp_section_with_kds_url() {
        let body = format!(
            "{MINIMAL}\n\n[snp]\ngeneration = \"genoa\"\nvek_pem_path = \"/etc/kbs/vek.pem\"\nkds_url = \"https://kdsintf.amd.com\"\n"
        );
        let f = write_tmp(&body);
        let cfg = Config::load(f.path()).expect("config with [snp].kds_url should load");
        let snp = cfg.snp.expect("snp must parse");
        assert_eq!(snp.kds_url.as_deref(), Some("https://kdsintf.amd.com"));
    }

    #[test]
    fn snp_rejects_unknown_field() {
        let body = format!(
            "{MINIMAL}\n\n[snp]\ngeneration = \"milan\"\nvek_pem_path = \"/etc/kbs/vek.pem\"\ntypo = true\n"
        );
        let f = write_tmp(&body);
        assert!(
            Config::load(f.path()).is_err(),
            "[snp].typo must be rejected"
        );
    }

    #[test]
    fn snp_rejects_unknown_generation() {
        // `milan`/`genoa`/`turin` are the only accepted values; a typo
        // or unsupported generation MUST be rejected at config parse
        // rather than silently downgrade to a no-op verifier. (`bergamo`
        // and `siena` are Genoa-family but the binary anchors them via
        // the per-report path, not a config alias.)
        for unknown in ["bergamo", "siena", "MILAN", "naples"] {
            let body = format!(
                "{MINIMAL}\n\n[snp]\ngeneration = \"{unknown}\"\nvek_pem_path = \"/etc/kbs/vek.pem\"\n"
            );
            let f = write_tmp(&body);
            assert!(
                Config::load(f.path()).is_err(),
                "unknown generation {unknown:?} must be rejected"
            );
        }
    }

    #[test]
    fn unknown_field_is_rejected() {
        let body = format!("{MINIMAL}\n[extra]\nbogus = 1\n");
        let f = write_tmp(&body);
        let err = Config::load(f.path()).expect_err("unknown table must be rejected");
        assert!(matches!(err, Error::Config(_)));
    }

    #[test]
    fn unknown_key_in_known_table_is_rejected() {
        let body = MINIMAL.replace("nonce_ttl_secs = 300", "nonce_ttl_secs = 300\ntypo = true");
        let f = write_tmp(&body);
        assert!(
            Config::load(f.path()).is_err(),
            "deny_unknown_fields must reject"
        );
    }

    #[test]
    fn enforce_release_class_defaults_off_and_parses() {
        let f = write_tmp(MINIMAL);
        assert!(
            !Config::load(f.path())
                .unwrap()
                .allowlist
                .enforce_release_class
        );
        let body = MINIMAL.replace(
            "root_pubkey_hex = \"aa\"",
            "root_pubkey_hex = \"aa\"\nenforce_release_class = true",
        );
        let f = write_tmp(&body);
        assert!(
            Config::load(f.path())
                .unwrap()
                .allowlist
                .enforce_release_class
        );
    }

    #[test]
    fn cdn_fleet_defaults_off_and_parses() {
        let f = write_tmp(MINIMAL);
        assert!(!Config::load(f.path()).unwrap().cdn_fleet.enabled);
        let f = write_tmp(&format!("{MINIMAL}\n[cdn_fleet]\nenabled = true\n"));
        assert!(Config::load(f.path()).unwrap().cdn_fleet.enabled);
        let f = write_tmp(&format!(
            "{MINIMAL}\n[cdn_fleet]\nenabled = true\ntypo = 1\n"
        ));
        assert!(Config::load(f.path()).is_err(), "deny_unknown_fields");
    }

    #[test]
    fn zero_nonce_ttl_is_rejected() {
        let body = MINIMAL.replace("nonce_ttl_secs = 300", "nonce_ttl_secs = 0");
        let f = write_tmp(&body);
        assert!(
            Config::load(f.path()).is_err(),
            "nonce_ttl_secs = 0 must fail closed"
        );
    }

    #[test]
    fn missing_file_fails_closed() {
        let err = Config::load(Path::new("/nonexistent/kbs/config.toml"))
            .expect_err("missing file must fail closed");
        assert!(matches!(err, Error::Config(_)));
    }

    #[test]
    fn dev_allow_any_kbs_measurement_defaults_false() {
        let f = write_tmp(MINIMAL);
        let cfg = Config::load(f.path()).expect("minimal config should load");
        assert!(
            !cfg.vault.dev_allow_any_kbs_measurement,
            "default must be the fail-closed posture"
        );
    }

    #[test]
    fn dev_allow_any_kbs_measurement_accepts_dev_env_loopback() {
        // The dev override loads ONLY with the explicit dev_environment
        // opt-in AND a loopback/private Vault endpoint (audit H7).
        let body = MINIMAL
            .replace(
                "address = \"https://vault:8200\"",
                "address = \"https://127.0.0.1:8200\"",
            )
            .replace(
                "kv_mount = \"secret\"",
                "kv_mount = \"secret\"\ndev_environment = true\ndev_allow_any_kbs_measurement = true",
            );
        let f = write_tmp(&body);
        let cfg = Config::load(f.path()).expect("dev override on dev_env + loopback must load");
        assert!(cfg.vault.dev_allow_any_kbs_measurement);
    }

    #[test]
    fn dev_flag_without_dev_environment_is_refused() {
        // Fail-closed primary gate: a dev override on a loopback addr is
        // STILL refused unless dev_environment is explicitly asserted — a
        // prod config never sets it, so a slip can't enable the override.
        let body = MINIMAL
            .replace(
                "address = \"https://vault:8200\"",
                "address = \"https://127.0.0.1:8200\"",
            )
            .replace(
                "kv_mount = \"secret\"",
                "kv_mount = \"secret\"\ndev_allow_any_kbs_measurement = true",
            );
        let f = write_tmp(&body);
        let err = Config::load(f.path())
            .expect_err("dev override without dev_environment must be refused");
        assert!(
            matches!(err, Error::Config(msg)
                if msg.contains("dev_allow_any_kbs_measurement")
                    && msg.contains("dev_environment")),
            "rejection must name the flag and the required opt-in"
        );
    }

    #[test]
    fn dev_flag_on_public_endpoint_is_refused_even_with_dev_environment() {
        // Belt-and-suspenders: even WITH dev_environment=true, a public
        // Vault endpoint (a bare public IP, or any non-local DNS name)
        // refuses the override — dev seams are only for a
        // loopback/private Vault.
        for public_addr in [
            // RFC 5737 documentation range — stands in for a production
            // Vault addressed by bare IP:port (no prod-marker substring).
            "https://203.0.113.10:8200",
            "https://vault:8200", // bare DNS name (not *.local)
            "https://vault.example.com:8200",
            "https://[2606:4700::1111]:8200", // public IPv6
            "https://vault.internal:8200",    // RA-KBS-VL4: .internal now public
        ] {
            let body = MINIMAL
                .replace(
                    "address = \"https://vault:8200\"",
                    &format!("address = \"{public_addr}\""),
                )
                .replace(
                    "kv_mount = \"secret\"",
                    "kv_mount = \"secret\"\ndev_environment = true\ndev_allow_any_kbs_measurement = true",
                );
            let f = write_tmp(&body);
            let err = Config::load(f.path()).expect_err(&format!(
                "dev override on public endpoint {public_addr:?} must be rejected"
            ));
            assert!(
                matches!(err, Error::Config(msg) if msg.contains("public Vault endpoint")),
                "rejection message should cite the public-endpoint refusal for {public_addr:?}"
            );
        }
    }

    #[test]
    fn broker_url_defaults_none() {
        let f = write_tmp(MINIMAL);
        let cfg = Config::load(f.path()).expect("minimal config should load");
        assert!(cfg.vault.broker_url.is_none());
    }

    #[test]
    fn broker_url_accepted_without_dev_measurement_override() {
        let body = MINIMAL.replace(
            "kv_mount = \"secret\"",
            "kv_mount = \"secret\"\nbroker_url = \"http://kbs-vault-broker.kbs.svc:8100\"",
        );
        let f = write_tmp(&body);
        let cfg = Config::load(f.path()).expect("broker_url alone must load");
        assert_eq!(
            cfg.vault.broker_url.as_deref(),
            Some("http://kbs-vault-broker.kbs.svc:8100")
        );
    }

    #[test]
    fn broker_url_with_dev_skip_tls_verify_is_allowed() {
        // dev_skip_tls_verify governs the KV-read TLS toward the
        // self-signed Tier-0 Vault — orthogonal to the broker hop. It is
        // still a DEV-ONLY seam, so it needs the dev_environment opt-in +
        // a loopback endpoint (audit H7).
        let body = MINIMAL
            .replace(
                "address = \"https://vault:8200\"",
                "address = \"https://127.0.0.1:8200\"",
            )
            .replace(
                "kv_mount = \"secret\"",
                "kv_mount = \"secret\"\nbroker_url = \"http://kbs-vault-broker.kbs.svc:8100\"\ndev_environment = true\ndev_skip_tls_verify = true",
            );
        let f = write_tmp(&body);
        Config::load(f.path()).expect("broker_url + dev_skip_tls_verify must load");
    }

    #[test]
    fn broker_url_refuses_dev_allow_any_kbs_measurement() {
        let body = MINIMAL.replace(
            "kv_mount = \"secret\"",
            "kv_mount = \"secret\"\nbroker_url = \"http://kbs-vault-broker.kbs.svc:8100\"\ndev_allow_any_kbs_measurement = true",
        );
        let f = write_tmp(&body);
        let err = Config::load(f.path())
            .expect_err("broker_url + dev_allow_any_kbs_measurement must be refused");
        assert!(
            matches!(err, Error::Config(ref msg) if msg.contains("mutually")
                && msg.contains("broker_url")
                && msg.contains("dev_allow_any_kbs_measurement")),
            "rejection must name both keys: {err}"
        );
    }

    #[test]
    fn empty_broker_url_does_not_trip_the_mutual_exclusion() {
        // `broker_url = ""` is "not set" — the dev seam stays wired,
        // so the dev measurement override remains legal (dev_environment +
        // loopback addr, audit H7).
        let body = MINIMAL
            .replace(
                "address = \"https://vault:8200\"",
                "address = \"https://127.0.0.1:8200\"",
            )
            .replace(
                "kv_mount = \"secret\"",
                "kv_mount = \"secret\"\nbroker_url = \"\"\ndev_environment = true\ndev_allow_any_kbs_measurement = true",
            );
        let f = write_tmp(&body);
        Config::load(f.path()).expect("empty broker_url must not trip the refusal");
    }

    #[test]
    fn dev_allow_any_kbs_measurement_off_does_not_check_addr() {
        // With the override OFF, prod-marker addresses must still load
        // — this is the default production posture.
        let body = MINIMAL.replace(
            "address = \"https://vault:8200\"",
            "address = \"https://vault.tier0.internal:8200\"",
        );
        let f = write_tmp(&body);
        Config::load(f.path()).expect("off-by-default override must not gate prod-addr load");
    }
}
