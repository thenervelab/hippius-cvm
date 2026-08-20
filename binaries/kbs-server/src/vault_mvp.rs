//! Transitional static-token Vault KV-v2 client (§D MVP).
//!
//! ⚠️  This is the TRANSITIONAL Vault access path. It authenticates with
//! a STATIC token (`VAULT_TOKEN`, sourced from a mounted secret) instead
//! of the locked SNP-attestation-bound broker (ARCHITECTURE.md §8). The
//! attested broker is a dedicated security-reviewed follow-up — see the
//! crate `README.md`.
//!
//! Scope: this provides the `VaultKv` seam only (the exact-path KV-v2
//! read of release secrets, §19). The `AttestedVaultAuth` seam keeps
//! kbs-core's reference `ChallengeVaultAuth`, configured fail-closed in
//! `wiring`. KBS *response signing* is unaffected — it is an in-process
//! Ed25519 key, never a Vault transit call.
//!
//! ## Per-tenant secret schema (PR-V `tenant-secrets-stage.sh` contract)
//!
//! KV-v2 stores arbitrary JSON objects under `data.data`. To keep the
//! HPKE-wrapped plaintext byte-identical to what the operator staged —
//! the `kbs-core` / `hippius-guest` in-memory test fixtures all assume
//! raw bytes round-trip — every per-tenant secret MUST conform to the
//! single-field schema:
//!
//! ```json
//! { "value": "<base64-standard>" }
//! ```
//!
//! `read_exact` extracts `data.data.value` (string), base64-decodes it
//! (RFC 4648 §4 STANDARD alphabet, no URL-safe, no line wraps), and
//! returns the raw bytes. Any deviation — missing field, non-string,
//! invalid base64, or extra fields tolerated only because Vault stored
//! them — fails closed as `KbsError::Vault`.
//!
//! WHY: the previous shape `serde_json::to_vec(data.data)` re-encoded
//! the whole map to JSON, so the bytes the guest received were
//! `{"value":"..."}` (or whatever map shape Vault returned) instead of
//! the operator's intended plaintext. That broke both LUKS unlock
//! (passphrase wouldn't match the image) and NoCloud cloud-init
//! (`/run/cloud-init-seed/user-data` got a JSON envelope instead of
//! YAML). Locking to a single field with explicit base64 makes the
//! KBS plaintext = the operator plaintext byte-for-byte.
//!
//! Fail-closed: any transport, HTTP-status, JSON-shape, or base64
//! error becomes a `KbsError::Vault` (a release denial). The token is
//! held in `Zeroizing` and is never written to a log or an error
//! message; neither are the decoded secret bytes.

use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use base64::Engine;
use kbs_core::error::{KbsError, Result};
use kbs_core::vault::{VaultCapability, VaultKv};
use std::time::Duration;
use zeroize::Zeroizing;

/// Vault KV-v2 read client.
///
/// Two token sources, selected by `prefer_capability_token`:
/// - `true` (production, §8/#102): read with the **broker-minted
///   per-VM scoped token** carried in the [`VaultCapability`] —
///   the SNP-attestation-bound broker authorised exactly this VM's
///   KEK + userdata, so the read can touch nothing else. `token`
///   below is then unused.
/// - `false` (dev / no-broker): read with the static `token` (a broad
///   `hippius-compute-kbs-read` operator token). The capability carries
///   a synthetic non-Vault token in this path, so it is ignored.
pub struct StaticTokenVaultKv {
    agent: ureq::Agent,
    /// `{address}/v1/{mount}/data` — the KV-v2 data-API prefix.
    data_api: String,
    /// `{address}/v1/transit` — the Transit-engine API prefix (Phase 2
    /// KEK-HSM). `transit_decrypt` POSTs to `{transit_api}/decrypt/<key>`.
    transit_api: String,
    token: Zeroizing<String>,
    /// When set, `read_exact` authenticates with the broker-minted
    /// capability token instead of the static `token`.
    prefer_capability_token: bool,
}

impl StaticTokenVaultKv {
    /// Construct the client with system-root TLS + no CA pin (used by
    /// tests). Infallible — no CA file is read, so it builds the agent
    /// directly rather than going through the fallible `new_with_tls`.
    pub fn new(address: &str, kv_mount: &str, token: Zeroizing<String>) -> Self {
        let agent = ureq::AgentBuilder::new()
            .timeout_connect(Duration::from_secs(5))
            .timeout_read(Duration::from_secs(10))
            .build();
        let base = address.trim_end_matches('/');
        let data_api = format!("{}/v1/{}/data", base, kv_mount.trim_matches('/'));
        let transit_api = format!("{}/v1/transit", base);
        Self {
            agent,
            data_api,
            transit_api,
            token,
            prefer_capability_token: false,
        }
    }

    /// Switch the read to authenticate with the broker-minted
    /// capability token (§8/#102) instead of the static token. Wiring
    /// sets this when `vault.broker_url` is configured.
    pub fn with_capability_token(mut self, prefer: bool) -> Self {
        self.prefer_capability_token = prefer;
        self
    }

    /// Same as [`Self::new`] plus a DEV-ONLY `dev_skip_tls_verify`
    /// switch. When `true`, the rustls config wired into `ureq` accepts
    /// any server certificate — letting the binary talk to a Vault
    /// behind a self-signed CA (a dev Tier-0 instance whose leaf is
    /// issued by its own self-CA) without baking that CA bundle into
    /// the image. The
    /// caller (`wiring.rs`) is responsible for the prod-marker
    /// address validator that refuses this in production-marked
    /// deploys; see `Config::validate`.
    ///
    /// Lives behind the same `vault.dev_skip_tls_verify` flag as the
    /// sibling `dev_allow_any_kbs_measurement`. Boot-time stderr
    /// emits a loud `⚠️  DEV-MODE` line when the switch is on.
    pub fn new_with_tls(
        address: &str,
        kv_mount: &str,
        token: Zeroizing<String>,
        dev_skip_tls_verify: bool,
        ca_cert_path: Option<&std::path::Path>,
    ) -> std::result::Result<Self, String> {
        let mut builder = ureq::AgentBuilder::new()
            .timeout_connect(Duration::from_secs(5))
            .timeout_read(Duration::from_secs(10));
        // CA-pin (prod) takes precedence; dev-skip is the fallback.
        if let Some(path) = ca_cert_path {
            let pem = std::fs::read(path)
                .map_err(|e| format!("vault.ca_cert_path {}: {e}", path.display()))?;
            builder = builder.tls_config(std::sync::Arc::new(ca_pinned_tls_config(&pem)?));
        } else if dev_skip_tls_verify {
            builder = builder.tls_config(std::sync::Arc::new(dev_insecure_tls_config()));
        }
        let agent = builder.build();
        let base = address.trim_end_matches('/');
        let data_api = format!("{}/v1/{}/data", base, kv_mount.trim_matches('/'));
        let transit_api = format!("{}/v1/transit", base);
        Ok(Self {
            agent,
            data_api,
            transit_api,
            token,
            prefer_capability_token: false,
        })
    }

    /// The KV-v2 data-API URL for an exact `path@version` read. Exposed
    /// for unit testing the URL construction.
    pub fn read_url(&self, path: &str, version: u64) -> String {
        format!(
            "{}/{}?version={}",
            self.data_api,
            path.trim_start_matches('/'),
            version,
        )
    }
}

/// Build a rustls `ClientConfig` that accepts ANY server cert. DEV-ONLY
/// — gated behind `vault.dev_skip_tls_verify` and the prod-marker
/// address validator in `Config::validate`. Used to talk to the
/// self-signed Tier-0 Vault (`hippius-vault-tier0` CN) without baking
/// its CA bundle into the image.
///
/// The `rustls::client::danger::ServerCertVerifier` impl below accepts
/// every certificate — this is exactly the same posture as
/// `VAULT_SKIP_VERIFY=true` on the `vault` CLI, and it's gated by the
/// same loud `⚠️  DEV-MODE` boot warning + prod-marker refusal as the
/// sibling `dev_allow_any_kbs_measurement` flag. The named-by-design
/// `dev_skip_tls_verify` is intentionally hard to enable accidentally
/// in production.
fn dev_insecure_tls_config() -> ureq::rustls::ClientConfig {
    use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
    use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
    use rustls::{DigitallySignedStruct, SignatureScheme};
    use ureq::rustls;

    #[derive(Debug)]
    struct AcceptAnyCert;

    impl ServerCertVerifier for AcceptAnyCert {
        fn verify_server_cert(
            &self,
            _end_entity: &CertificateDer<'_>,
            _intermediates: &[CertificateDer<'_>],
            _server_name: &ServerName<'_>,
            _ocsp_response: &[u8],
            _now: UnixTime,
        ) -> std::result::Result<ServerCertVerified, rustls::Error> {
            Ok(ServerCertVerified::assertion())
        }

        fn verify_tls12_signature(
            &self,
            _message: &[u8],
            _cert: &CertificateDer<'_>,
            _dss: &DigitallySignedStruct,
        ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
            Ok(HandshakeSignatureValid::assertion())
        }

        fn verify_tls13_signature(
            &self,
            _message: &[u8],
            _cert: &CertificateDer<'_>,
            _dss: &DigitallySignedStruct,
        ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
            Ok(HandshakeSignatureValid::assertion())
        }

        fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
            vec![
                SignatureScheme::RSA_PKCS1_SHA256,
                SignatureScheme::RSA_PKCS1_SHA384,
                SignatureScheme::RSA_PKCS1_SHA512,
                SignatureScheme::ECDSA_NISTP256_SHA256,
                SignatureScheme::ECDSA_NISTP384_SHA384,
                SignatureScheme::RSA_PSS_SHA256,
                SignatureScheme::RSA_PSS_SHA384,
                SignatureScheme::RSA_PSS_SHA512,
                SignatureScheme::ED25519,
            ]
        }
    }

    rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(std::sync::Arc::new(AcceptAnyCert))
        .with_no_client_auth()
}

/// Production TLS: PIN exactly the certificate(s) in `ca_pem` (the
/// operator-mounted Vault cert). The Tier-0 Vault presents a
/// self-signed cert marked `CA:TRUE` as its TLS leaf, which
/// rustls/webpki refuse as an end-entity (`CaUsedAsEndEntity`); so we
/// pin the exact cert DER + verify the handshake signature for real
/// against its key (the `verify_tls1*_signature` hooks call the crypto
/// provider, NOT accept-all). Certificate pinning of a self-signed
/// endpoint. Replaces `dev_skip_tls_verify` once the CA is mounted.
pub(crate) fn ca_pinned_tls_config(
    ca_pem: &[u8],
) -> std::result::Result<ureq::rustls::ClientConfig, String> {
    use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
    use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
    use rustls::{DigitallySignedStruct, SignatureScheme};
    use std::sync::Arc;
    use ureq::rustls;

    let pinned: Vec<CertificateDer<'static>> =
        rustls_pemfile::certs(&mut std::io::BufReader::new(ca_pem))
            .map(|r| r.map(|d| d.into_owned()))
            .collect::<std::result::Result<_, _>>()
            .map_err(|e| format!("Vault CA PEM parse: {e}"))?;
    if pinned.is_empty() {
        return Err("Vault CA bundle contained no certificates".to_string());
    }
    // ureq does not install a PROCESS-default CryptoProvider; it uses
    // its compiled-in `ring` provider (the same one `builder()` below
    // selects). Use it directly for the verifier's signature checks so
    // the algorithms match the config's provider.
    let provider = Arc::new(rustls::crypto::ring::default_provider());

    #[derive(Debug)]
    struct PinnedVerifier {
        pinned: Vec<CertificateDer<'static>>,
        provider: Arc<rustls::crypto::CryptoProvider>,
    }
    impl ServerCertVerifier for PinnedVerifier {
        fn verify_server_cert(
            &self,
            end_entity: &CertificateDer<'_>,
            _intermediates: &[CertificateDer<'_>],
            _server_name: &ServerName<'_>,
            _ocsp_response: &[u8],
            _now: UnixTime,
        ) -> std::result::Result<ServerCertVerified, rustls::Error> {
            if self
                .pinned
                .iter()
                .any(|c| c.as_ref() == end_entity.as_ref())
            {
                Ok(ServerCertVerified::assertion())
            } else {
                Err(rustls::Error::General(
                    "server cert does not match the pinned Vault cert".into(),
                ))
            }
        }
        fn verify_tls12_signature(
            &self,
            message: &[u8],
            cert: &CertificateDer<'_>,
            dss: &DigitallySignedStruct,
        ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
            rustls::crypto::verify_tls12_signature(
                message,
                cert,
                dss,
                &self.provider.signature_verification_algorithms,
            )
        }
        fn verify_tls13_signature(
            &self,
            message: &[u8],
            cert: &CertificateDer<'_>,
            dss: &DigitallySignedStruct,
        ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
            rustls::crypto::verify_tls13_signature(
                message,
                cert,
                dss,
                &self.provider.signature_verification_algorithms,
            )
        }
        fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
            self.provider
                .signature_verification_algorithms
                .supported_schemes()
        }
    }

    Ok(rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(PinnedVerifier { pinned, provider }))
        .with_no_client_auth())
}

/// Reject a Vault KV path that is empty or carries any character
/// outside a conservative slash-delimited-identifier set. A signed
/// OrderTicket's `VaultRef.path` is not URL-validated by kbs-core; a `?`
/// or `#` in it could otherwise rewrite or drop the `version=` query and
/// break the §19 "exact path@version, never latest" contract.
fn validate_kv_path(path: &str) -> Result<()> {
    if path.is_empty() {
        return Err(KbsError::Vault("KV read: empty path".into()));
    }
    let safe = path
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'/' | b'-' | b'_' | b'.'));
    if !safe {
        return Err(KbsError::Vault(
            "KV read: path has disallowed characters".into(),
        ));
    }
    Ok(())
}

/// Map a `ureq` error to a non-secret, operator-useful reason. The HTTP
/// status code is safe to surface; the response body and transport
/// detail (which could echo headers) are deliberately dropped.
fn classify_ureq_error(e: &ureq::Error) -> String {
    match e {
        ureq::Error::Status(code, _) => format!("KV read: Vault returned HTTP {code}"),
        ureq::Error::Transport(_) => "KV read: Vault transport error".to_string(),
    }
}

/// Extract the per-tenant release plaintext from a Vault KV-v2 read
/// response body. Pulled out of [`StaticTokenVaultKv::read_exact`] so
/// the JSON-shape + base64 contract is unit-testable without a real
/// HTTP roundtrip.
///
/// Schema: `data.data.value` is a STANDARD-base64 string; the decoded
/// bytes are returned in `Zeroizing` (wiped on drop). Any deviation —
/// malformed JSON, missing/non-string `value`, invalid base64 — is a
/// `KbsError::Vault` (release denial). See module docs for the
/// "why single-field + base64" rationale.
fn parse_kv_secret_body(body: &str) -> Result<Zeroizing<Vec<u8>>> {
    let json: serde_json::Value = serde_json::from_str(body)
        .map_err(|_| KbsError::Vault("KV read: malformed JSON".into()))?;
    // Hold the base64 string in `Zeroizing` so the encoded form is
    // wiped on drop too, not just the decoded plaintext.
    let encoded = Zeroizing::new(
        json.get("data")
            .and_then(|d| d.get("data"))
            .and_then(|dd| dd.get("value"))
            .and_then(|v| v.as_str())
            .ok_or_else(|| {
                KbsError::Vault("KV read: missing data.data.value (must be a base64 string)".into())
            })?
            .to_string(),
    );
    let decoded = BASE64_STANDARD
        .decode(encoded.as_str())
        .map_err(|_| KbsError::Vault("KV read: data.data.value is not valid base64".into()))?;
    Ok(Zeroizing::new(decoded))
}

impl VaultKv for StaticTokenVaultKv {
    fn read_exact(
        &self,
        cap: &VaultCapability,
        path: &str,
        version: u64,
    ) -> Result<Zeroizing<Vec<u8>>> {
        // §19 exact read — the version is pinned explicitly, never
        // "latest".
        //
        // §8/#102: in broker mode (`prefer_capability_token`) the read
        // authenticates with the **broker-minted per-VM scoped token**
        // carried in `cap` — the SNP-attestation-bound broker authorised
        // exactly this VM's KEK + userdata path, so a compromised KBS
        // cannot read any other tenant's secret. The broad static token
        // is the dev / no-broker fallback only.
        validate_kv_path(path)?;
        let vault_token: &str = if self.prefer_capability_token {
            core::str::from_utf8(cap.token()).map_err(|_| {
                KbsError::Vault("KV read: broker capability token is not valid UTF-8".into())
            })?
        } else {
            self.token.as_str()
        };
        let url = self.read_url(path, version);
        let resp = self
            .agent
            .get(&url)
            .set("X-Vault-Token", vault_token)
            .call()
            .map_err(|e| KbsError::Vault(classify_ureq_error(&e)))?;
        let body = resp
            .into_string()
            .map_err(|_| KbsError::Vault("KV read: response body error".into()))?;
        parse_kv_secret_body(&body)
    }

    fn transit_decrypt(
        &self,
        cap: &VaultCapability,
        transit_key: &str,
        ciphertext: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>> {
        // Phase 2 (KEK-HSM): decrypt a Vault-Transit-wrapped KEK. The
        // ciphertext is a Transit string (`vault:v1:…`). In broker mode
        // the call authenticates with the SNP-attestation-bound
        // broker-minted capability, which the broker scopes to `update` on
        // `transit/decrypt/<transit_key>` where `transit_key = kek-<vm_id>`
        // — a PER-VM key, so a compromised KBS holding this cap can decrypt
        // ONLY this VM's KEK (never a general oracle). The static token is
        // the dev / no-broker fallback.
        let ct = core::str::from_utf8(ciphertext).map_err(|_| {
            KbsError::Vault("transit_decrypt: ciphertext is not valid UTF-8".into())
        })?;
        let vault_token: &str = if self.prefer_capability_token {
            core::str::from_utf8(cap.token()).map_err(|_| {
                KbsError::Vault(
                    "transit_decrypt: broker capability token is not valid UTF-8".into(),
                )
            })?
        } else {
            self.token.as_str()
        };
        let url = format!("{}/decrypt/{}", self.transit_api, transit_key);
        // Build the JSON body via serde_json (no ureq `json` feature dep).
        let req_body = serde_json::json!({ "ciphertext": ct }).to_string();
        let resp = self
            .agent
            .post(&url)
            .set("X-Vault-Token", vault_token)
            .set("Content-Type", "application/json")
            .send_string(&req_body)
            .map_err(|e| KbsError::Vault(classify_ureq_error(&e)))?;
        let body = resp
            .into_string()
            .map_err(|_| KbsError::Vault("transit_decrypt: response body error".into()))?;
        parse_transit_plaintext(&body)
    }
}

/// Vault `transit/decrypt` response shape: `{"data":{"plaintext":"<b64>"}}`
/// — extract + base64-decode the plaintext KEK. Fail-closed on any shape /
/// base64 error; the bytes are `Zeroizing` and never logged.
fn parse_transit_plaintext(body: &str) -> Result<Zeroizing<Vec<u8>>> {
    let v: serde_json::Value = serde_json::from_str(body)
        .map_err(|_| KbsError::Vault("transit_decrypt: non-JSON response".into()))?;
    let b64 = v
        .get("data")
        .and_then(|d| d.get("plaintext"))
        .and_then(|p| p.as_str())
        .ok_or_else(|| {
            KbsError::Vault("transit_decrypt: response missing data.plaintext".into())
        })?;
    let raw = BASE64_STANDARD
        .decode(b64)
        .map_err(|_| KbsError::Vault("transit_decrypt: plaintext is not valid base64".into()))?;
    Ok(Zeroizing::new(raw))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn client() -> StaticTokenVaultKv {
        StaticTokenVaultKv::new(
            "https://vault.example:8200/",
            "/secret/",
            Zeroizing::new("test-token".to_string()),
        )
    }

    #[test]
    fn capability_token_flag_defaults_off_and_toggles() {
        // `new` (dev / test) reads with the static token …
        let c = client();
        assert!(!c.prefer_capability_token);
        // … `with_capability_token(true)` (broker mode) flips the read to
        // the broker-minted per-VM scoped token carried in the capability.
        let c = c.with_capability_token(true);
        assert!(c.prefer_capability_token);
    }

    #[test]
    fn parse_transit_plaintext_decodes_and_fails_closed() {
        // Happy path: Vault transit/decrypt shape → base64 → raw KEK bytes.
        let kek = b"\x00\x01\x02\x03unlocks-the-luks-header-32bytes!";
        let b64 = BASE64_STANDARD.encode(kek);
        let body = format!("{{\"data\":{{\"plaintext\":\"{b64}\"}}}}");
        let out = parse_transit_plaintext(&body).unwrap();
        assert_eq!(&out[..], &kek[..]);
        // Fail-closed on a missing field, non-JSON, and bad base64.
        assert!(parse_transit_plaintext("{\"data\":{}}").is_err());
        assert!(parse_transit_plaintext("not json").is_err());
        assert!(parse_transit_plaintext("{\"data\":{\"plaintext\":\"@@@\"}}").is_err());
    }

    #[test]
    fn builds_exact_version_pinned_url() {
        let c = client();
        assert_eq!(
            c.read_url("hippius-compute/kbs/vm/abc/luks", 7),
            "https://vault.example:8200/v1/secret/data/hippius-compute/kbs/vm/abc/luks?version=7",
        );
    }

    #[test]
    fn url_normalises_slashes() {
        let c = client();
        // Leading slash on the path must not double up against data_api.
        assert_eq!(
            c.read_url("/leading", 1),
            "https://vault.example:8200/v1/secret/data/leading?version=1",
        );
    }

    // ── parse_kv_secret_body: PR-V single-field base64 schema ────────

    /// Build the Vault KV-v2 read-response shape the real server emits
    /// (matters: `data.data.value`, NOT `data.value`). `extras`
    /// inside `data.data` simulates additional fields the operator may
    /// have written; the parser must ignore them and accept the read.
    fn kv_response_body(b64_value: &str, extras: &[(&str, &str)]) -> String {
        let mut data_data = serde_json::Map::new();
        data_data.insert("value".into(), serde_json::Value::String(b64_value.into()));
        for (k, v) in extras {
            data_data.insert((*k).into(), serde_json::Value::String((*v).into()));
        }
        let metadata = serde_json::json!({"version": 1, "destroyed": false});
        let envelope = serde_json::json!({
            "data": { "data": serde_json::Value::Object(data_data), "metadata": metadata },
        });
        envelope.to_string()
    }

    #[test]
    fn parses_base64_value_and_returns_raw_bytes() {
        // base64("hello") = "aGVsbG8="
        let body = kv_response_body("aGVsbG8=", &[]);
        let out = parse_kv_secret_body(&body).expect("valid body");
        assert_eq!(out.as_slice(), b"hello");
    }

    #[test]
    fn parses_thirty_two_random_bytes_roundtrip() {
        // Simulates a 32-byte LUKS KEK round-trip — the operator stages
        // base64(KEK), the KBS hands back the raw KEK bytes.
        let kek: [u8; 32] = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
            0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c,
            0x1d, 0x1e, 0x1f, 0x20,
        ];
        let b64 = BASE64_STANDARD.encode(kek);
        let body = kv_response_body(&b64, &[]);
        let out = parse_kv_secret_body(&body).expect("valid body");
        assert_eq!(out.as_slice(), &kek);
    }

    #[test]
    fn extra_fields_in_data_data_are_tolerated() {
        // The operator might have staged provenance metadata alongside
        // `value`. The parser MUST ignore the extras and still return
        // exactly the decoded `value` bytes — no JSON re-encoding leak.
        let body = kv_response_body(
            "aGVsbG8=",
            &[("staged_by", "operator-x"), ("staged_at", "2026-05-25Z")],
        );
        let out = parse_kv_secret_body(&body).expect("valid body");
        assert_eq!(out.as_slice(), b"hello");
    }

    #[test]
    fn missing_value_field_fails_closed() {
        // `data.data` exists but lacks `value` — operator forgot the
        // schema. Release must deny rather than fall through to "what
        // bytes are these even".
        let body = r#"{"data":{"data":{"other":"x"},"metadata":{}}}"#;
        let err = parse_kv_secret_body(body).expect_err("must reject");
        // Reason text MUST not leak the body — only mention the schema.
        let s = format!("{err:?}");
        assert!(s.contains("data.data.value"), "got: {s}");
        assert!(!s.contains("\"other\""), "must not echo body: {s}");
    }

    #[test]
    fn non_string_value_field_fails_closed() {
        // `value` present but not a string (e.g. number) — schema
        // violation. Vault never produces this for `vault kv put` k=v
        // input, but a hand-rolled `vault write` could.
        let body = r#"{"data":{"data":{"value":42},"metadata":{}}}"#;
        let err = parse_kv_secret_body(body).expect_err("must reject");
        assert!(matches!(err, KbsError::Vault(_)));
    }

    #[test]
    fn invalid_base64_value_fails_closed() {
        // Schema-shape ok, base64 garbage — release denies.
        let body = kv_response_body("!!!!!not-base64!!!!!", &[]);
        let err = parse_kv_secret_body(&body).expect_err("must reject");
        let s = format!("{err:?}");
        assert!(s.contains("base64"), "got: {s}");
        // The bad string must not be echoed back to logs.
        assert!(!s.contains("!!!!!"), "must not echo input: {s}");
    }

    #[test]
    fn missing_outer_data_envelope_fails_closed() {
        // The whole `data.data` envelope is missing — Vault returned an
        // unexpected shape (auth failure mislabeled? mount mismatch?).
        // Must deny, not panic.
        let body = r#"{"errors":["permission denied"]}"#;
        let err = parse_kv_secret_body(body).expect_err("must reject");
        assert!(matches!(err, KbsError::Vault(_)));
    }

    #[test]
    fn malformed_json_fails_closed() {
        let err = parse_kv_secret_body("not json at all").expect_err("must reject");
        let s = format!("{err:?}");
        assert!(s.contains("malformed JSON"), "got: {s}");
    }

    #[test]
    fn validate_kv_path_accepts_normal_and_rejects_injection() {
        assert!(validate_kv_path("hippius-compute/kbs/vm/abc/luks").is_ok());
        assert!(validate_kv_path("a/b_c/d.e").is_ok());
        assert!(validate_kv_path("").is_err(), "empty path");
        assert!(
            validate_kv_path("evil?version=1").is_err(),
            "query injection"
        );
        assert!(validate_kv_path("evil#frag").is_err(), "fragment injection");
        assert!(validate_kv_path("space here").is_err(), "whitespace");
        assert!(validate_kv_path("pct%41").is_err(), "percent escape");
    }
}
