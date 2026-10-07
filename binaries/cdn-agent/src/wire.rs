//! Node ↔ backend wire types (CDN plan §C).
//!
//! The backend owns these endpoints and may still change their shapes,
//! so every path, header, signing domain and JSON body lives in this one
//! module. Nothing outside it names a backend field.
//!
//! Decoding policy: responses tolerate **unknown** fields (the backend may
//! add some), but every field the agent uses is typed, and `feed`
//! validates the values before anything is applied. Requests are built
//! from these structs only.
//!
//! Signing domains: the node key signs two things, so each message is
//! prefixed with a distinct, versioned domain tag and a NUL. The backend
//! must verify against the same construction ([`register_message`],
//! [`usage_message`]).

use std::collections::BTreeMap;
use std::fmt;
use std::net::IpAddr;

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

// ── Paths ────────────────────────────────────────────────────────────

pub const PATH_REGISTER_CHALLENGE: &str = "/api/cdn/node/register/challenge/";
pub const PATH_REGISTER: &str = "/api/cdn/node/register/";
/// Bootstrap: public node certificate, `?vm_id=`. No client auth.
pub const PATH_NODE_CERT: &str = "/api/cdn/node/cert/";
pub const PATH_FEED: &str = "/api/cdn/node/feed/";
pub const PATH_USAGE: &str = "/api/cdn/node/usage/";
/// I4: upload a sealed certificate key + public chain.
pub const PATH_CERTS: &str = "/api/cdn/node/certs/";
/// I4: per-hostname issuance lease.
pub const PATH_ACME_LEASE: &str = "/api/cdn/node/acme/lease/";
/// I4: DNS-01 TXT write.
pub const PATH_ACME_DNS01: &str = "/api/cdn/node/acme/dns01/";

// ── Headers and signing domains ──────────────────────────────────────

/// Detached Ed25519 signature (base64) over [`usage_message`].
pub const HEADER_SIGNATURE: &str = "X-Hippius-Cdn-Signature";
/// The `vm_id` whose node key produced [`HEADER_SIGNATURE`].
pub const HEADER_NODE: &str = "X-Hippius-Cdn-Node";

/// Domain tag of the registration challenge signature.
pub const REGISTER_DOMAIN: &[u8] = b"HIPPIUS_CDN_REGISTER_V1";
/// Domain tag of the usage report signature.
pub const USAGE_DOMAIN: &[u8] = b"HIPPIUS_CDN_USAGE_V1";

/// `REGISTER_DOMAIN ‖ 0x00 ‖ vm_id ‖ 0x00 ‖ generation (u64 BE) ‖ challenge`.
///
/// Binding `vm_id` and `generation` stops a signature over one node's
/// challenge from registering another identity.
pub fn register_message(vm_id: &str, generation: u64, challenge: &[u8]) -> Vec<u8> {
    let mut m = Vec::with_capacity(REGISTER_DOMAIN.len() + vm_id.len() + challenge.len() + 10);
    m.extend_from_slice(REGISTER_DOMAIN);
    m.push(0);
    m.extend_from_slice(vm_id.as_bytes());
    m.push(0);
    m.extend_from_slice(&generation.to_be_bytes());
    m.extend_from_slice(challenge);
    m
}

/// `USAGE_DOMAIN ‖ 0x00 ‖ body`, where `body` is the exact request bytes.
pub fn usage_message(body: &[u8]) -> Vec<u8> {
    let mut m = Vec::with_capacity(USAGE_DOMAIN.len() + 1 + body.len());
    m.extend_from_slice(USAGE_DOMAIN);
    m.push(0);
    m.extend_from_slice(body);
    m
}

// ── Errors ───────────────────────────────────────────────────────────

/// The backend's `{code, detail}` error envelope. Only `code` is ever
/// logged.
#[derive(Debug, Clone, Deserialize)]
pub struct ErrorBody {
    pub code: String,
    #[serde(default)]
    pub detail: Option<String>,
}

// ── Registration ─────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize)]
pub struct ChallengeRequest<'a> {
    pub vm_id: &'a str,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ChallengeResponse {
    pub challenge_b64: String,
    pub expires_at: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct RegisterRequest<'a> {
    pub vm_id: &'a str,
    pub generation: u64,
    pub cert_pem: &'a str,
    pub challenge_b64: &'a str,
    pub signature_b64: String,
}

/// A bearer session token. Never printed; wiped on drop.
#[derive(Clone)]
pub struct SessionToken(Zeroizing<String>);

impl<'de> Deserialize<'de> for SessionToken {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        String::deserialize(d).map(|s| Self(Zeroizing::new(s)))
    }
}

impl SessionToken {
    pub fn expose(&self) -> &str {
        self.0.as_str()
    }

    #[cfg(test)]
    pub fn for_tests(s: &str) -> Self {
        Self(Zeroizing::new(s.to_string()))
    }
}

impl fmt::Debug for SessionToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SessionToken(<redacted>)")
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct RegisterResponse {
    pub session_token: SessionToken,
    /// The session's public id, signed into every request (§C.0, §C.2):
    /// `sess_` + 24 hex, new on every registration.
    #[serde(default)]
    pub session_token_id: Option<String>,
    /// The same value under its older name (backends before #393 send only
    /// this one). Both may be present: they are two fields, not aliases.
    #[serde(default)]
    pub session_id: Option<String>,
    pub expires_at: String,
}

/// `GET /api/cdn/node/cert/?vm_id=` and `self.cert_pem` in the feed.
#[derive(Debug, Clone, Deserialize)]
pub struct NodeCertResponse {
    pub cert_pem: String,
}

// ── Feed ─────────────────────────────────────────────────────────────

/// `snapshot` replaces the node's state; `delta` patches it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FeedMode {
    Snapshot,
    Delta,
}

/// `GET /api/cdn/node/feed/?since=<rev>` body.
///
/// `zones`, `hostnames`, `purges`, `blocks` and `certs` are upserts (the
/// full set in a snapshot); `removed` lists ids to drop in a delta.
/// `acme_http01`, `fleet_key_versions`, `self` and `peers` are always the
/// complete current value.
#[derive(Debug, Clone, Deserialize)]
pub struct FeedResponse {
    pub revision: u64,
    pub mode: FeedMode,
    #[serde(default)]
    pub zones: Vec<Zone>,
    #[serde(default)]
    pub hostnames: Vec<Hostname>,
    #[serde(default)]
    pub purges: Vec<PurgeGenerations>,
    #[serde(default)]
    pub blocks: Vec<Block>,
    #[serde(default)]
    pub certs: Vec<SealedCert>,
    #[serde(default)]
    pub removed: Removed,
    #[serde(default)]
    pub acme_http01: Vec<AcmeHttp01>,
    #[serde(default)]
    pub fleet_key_versions: Vec<FleetKeyVersion>,
    #[serde(rename = "self")]
    pub self_state: SelfState,
    #[serde(default)]
    pub peers: Vec<Peer>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Removed {
    #[serde(default)]
    pub zones: Vec<String>,
    #[serde(default)]
    pub hostnames: Vec<String>,
    #[serde(default)]
    pub blocks: Vec<String>,
    #[serde(default)]
    pub certs: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ZoneState {
    Active,
    /// Spend cap reached: answer 503, never go to the origin.
    Paused,
    /// Abuse or arrears: refuse.
    Suspended,
}

/// A customer zone. `settings` (rules, CORS, headers, compression MIME
/// list, signed-URL policy) is opaque to the agent and passed to
/// OpenResty after a size check.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Zone {
    pub zone_id: String,
    pub state: ZoneState,
    pub origin: Origin,
    #[serde(default)]
    pub shield_region: Option<String>,
    #[serde(default)]
    pub secrets: Vec<SealedSecret>,
    #[serde(default)]
    pub settings: serde_json::Value,
}

/// An origin. `type` selects the kind; the remaining keys are the kind's
/// parameters. The beta admits `s3` only (see `hooks::OriginPolicy`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Origin {
    #[serde(rename = "type")]
    pub kind: String,
    #[serde(flatten)]
    pub params: serde_json::Map<String, serde_json::Value>,
}

/// A secret sealed to a fleet key version: a private-bucket SubToken
/// (`s3_credentials`), a signed-URL key (`signed_url_key:<kid>`), an
/// origin header secret (I6).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SealedSecret {
    pub name: String,
    pub fleet_key_version: u32,
    pub sealed_b64: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Hostname {
    pub hostname_id: String,
    pub hostname: String,
    pub zone_id: String,
    /// A claimed hostname (`verified` / `cert_pending`) that has no
    /// certificate yet: in the feed for ACME only, never routed.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub needs_cert: bool,
}

/// Purge generations of one zone. Generations only ever increase; the
/// agent keeps the maximum it has seen. `prefixes` keys end in `/` and
/// cover every path below them; `paths` keys are one exact path each.
/// Both are percent-encoded request paths. An absent map is empty.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PurgeGenerations {
    pub zone_id: String,
    pub zone_generation: u64,
    #[serde(default)]
    pub prefixes: BTreeMap<String, u64>,
    #[serde(default)]
    pub paths: BTreeMap<String, u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Block {
    pub block_id: String,
    #[serde(default)]
    pub zone_id: Option<String>,
    /// `hostname`, `path` or `prefix`.
    pub kind: String,
    pub value: String,
}

/// A served certificate: the public chain plus the private key sealed to
/// a fleet key version. The sealed plaintext is the key's PEM.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SealedCert {
    pub hostname_id: String,
    pub hostname: String,
    pub cert_chain_pem: String,
    pub fleet_key_version: u32,
    pub sealed_blob_b64: String,
    pub not_after: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AcmeHttp01 {
    pub token: String,
    pub key_authorization: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FleetKeyState {
    Pending,
    Active,
    Retiring,
    Retired,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FleetKeyVersion {
    pub version: u32,
    pub state: FleetKeyState,
    /// When present, the node checks its own key's public half against it.
    #[serde(default)]
    pub x25519_public_b64: Option<String>,
}

/// vali's view of this node, relayed by the backend.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SelfState {
    #[serde(default)]
    pub state: String,
    #[serde(default)]
    pub draining: bool,
    /// The region quota guard (spec §11.2) is tripped.
    #[serde(default)]
    pub quota_guard: bool,
    /// The node's current certificate, for renewal.
    #[serde(default)]
    pub cert_pem: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Peer {
    pub node_id: String,
    pub region: String,
    pub public_ip: IpAddr,
    /// Hex SHA-256 of the peer's node certificate DER.
    pub cert_fingerprint: String,
}

// ── Usage ────────────────────────────────────────────────────────────

/// Monotonic totals for one `(zone, client_region)` (spec §9.1).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CounterSet {
    pub billable_bytes_out: u64,
    pub billable_requests: u64,
    pub rejected_bytes_out: u64,
    pub rejected_requests: u64,
    pub hits: u64,
    pub misses: u64,
    pub bytes_from_origin: u64,
    pub bytes_from_shield: u64,
    pub status_2xx: u64,
    pub status_3xx: u64,
    pub status_4xx: u64,
    pub status_5xx: u64,
}

/// `POST /api/cdn/node/usage/` body. Totals since `counter_epoch`
/// started; `seq` increases by one per report within an epoch.
/// `zones` maps zone id → client BILLING region (upper-case ISO 3166
/// alpha-2, the vali region codes: `FR`, `NL`, `AU`…; `XX` when unknown,
/// held unbilled by the backend) → counters. `unattributed` holds
/// requests with no zone (unknown host 421).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UsageReport {
    pub node: String,
    pub counter_epoch: String,
    pub seq: u64,
    pub at: String,
    pub applied_revision: u64,
    pub geoip_db: String,
    pub zones: BTreeMap<String, BTreeMap<String, CounterSet>>,
    pub unattributed: CounterSet,
}

// ── I4 (ACME) ────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize)]
pub struct CertUpload<'a> {
    pub hostname_id: &'a str,
    pub sealed_blob_b64: &'a str,
    pub fleet_key_version: u32,
    pub cert_chain_pem: &'a str,
    pub not_after: &'a str,
}

#[derive(Debug, Clone, Serialize)]
pub struct AcmeLeaseRequest<'a> {
    pub hostname_id: &'a str,
}

#[derive(Debug, Clone, Deserialize)]
pub struct AcmeLeaseResponse {
    pub lease_id: String,
    pub expires_at: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct Dns01Request<'a> {
    pub lease_id: &'a str,
    pub name: &'a str,
    pub value: &'a str,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Dns01Response {
    pub change_id: String,
    pub insync: bool,
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn signing_messages_are_domain_separated() {
        let r = register_message("vm-1", 3, b"chal");
        assert!(r.starts_with(b"HIPPIUS_CDN_REGISTER_V1\0vm-1\0"));
        assert!(r.ends_with(b"\0\0\0\0\0\0\0\x03chal"));
        let u = usage_message(b"{}");
        assert_eq!(u, b"HIPPIUS_CDN_USAGE_V1\0{}");
        // A usage body can never collide with a registration message.
        assert!(!usage_message(&r).starts_with(REGISTER_DOMAIN));
    }

    #[test]
    fn session_token_debug_is_redacted() {
        let t: RegisterResponse =
            serde_json::from_str(r#"{"session_token":"s3cr3t","expires_at":"x"}"#).unwrap();
        let dbg = format!("{t:?}");
        assert!(!dbg.contains("s3cr3t"));
        assert_eq!(t.session_token.expose(), "s3cr3t");
        // Current backends send both names at once.
        let both: RegisterResponse = serde_json::from_str(
            r#"{"session_token":"t","session_token_id":"sess_example_id","session_id":"sess_example_id","expires_at":"x"}"#,
        )
        .unwrap();
        assert_eq!(both.session_token_id.as_deref(), Some("sess_example_id"));
    }

    #[test]
    fn feed_decodes_with_defaults_and_tolerates_new_fields() {
        let f: FeedResponse = serde_json::from_str(
            r#"{"revision":7,"mode":"delta","self":{"state":"ready"},"future_field":[1]}"#,
        )
        .unwrap();
        assert_eq!(f.revision, 7);
        assert_eq!(f.mode, FeedMode::Delta);
        assert!(f.zones.is_empty());
        assert!(!f.self_state.draining);
    }

    #[test]
    fn origin_keeps_kind_specific_params() {
        let o: Origin =
            serde_json::from_str(r#"{"type":"s3","bucket":"b","prefix":"p/"}"#).unwrap();
        assert_eq!(o.kind, "s3");
        assert_eq!(o.params["bucket"], "b");
        let back = serde_json::to_value(&o).unwrap();
        assert_eq!(back["type"], "s3");
        assert_eq!(back["prefix"], "p/");
    }

    #[test]
    fn usage_report_round_trips() {
        let mut zones = BTreeMap::new();
        let mut regions = BTreeMap::new();
        regions.insert(
            "FR".to_string(),
            CounterSet {
                billable_bytes_out: 10,
                billable_requests: 1,
                ..CounterSet::default()
            },
        );
        zones.insert("z1".to_string(), regions);
        let r = UsageReport {
            node: "n".into(),
            counter_epoch: "00".repeat(16),
            seq: 2,
            at: "2026-10-20T10:00:00Z".into(),
            applied_revision: 9,
            geoip_db: "dbip-2026-10".into(),
            zones,
            unattributed: CounterSet::default(),
        };
        let bytes = serde_json::to_vec(&r).unwrap();
        let back: UsageReport = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(back, r);
    }
}
