//! `POST /v1/admin/cdn-fleet/public` — the KBS-vouched public half of a
//! cdn-fleet key version (`kbs_core::cdn_fleet`).
//!
//! vali calls it after minting a version (or the operator, through
//! `hippius-kbs-admin-client cdn-fleet-public`) and publishes the result
//! in `GET /v1/cdn/nodes` `fleet_keys[]`. Only public data leaves: the
//! KBS unwraps the key with a fleet-only broker capability, derives the
//! X25519 public key, signs it and wipes the secret.
//!
//! Request `{"version": N}`. 200 [`CdnFleetPublicResponse`]. Errors are
//! JSON `{"reason": …}`: 404 `cdn-fleet-disabled` (`[cdn_fleet] enabled =
//! false`), 400 `cdn-fleet-body-decode` / `cdn-fleet-bad-version`, 403
//! `admin-client-cert-required`, 502 `cdn-fleet-unwrap-failed` (Vault,
//! broker, a version never minted, a plaintext entry), 429. Every call is
//! one row in the admin audit chain (`op = "cdn-fleet-public"`).

use crate::admin_handler::{AdminState, PeerCertInfo};
use axum::body::to_bytes;
use axum::extract::{Request, State};
use axum::http::{header, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use ed25519_dalek::SigningKey;
use kbs_core::cdn_fleet::{derive_public_key, FleetPublicDeps, FleetPublicKey};
use kbs_core::error::Result;
use kbs_core::snp::VerifiedReport;
use kbs_core::vault::{AttestedVaultAuth, VaultKv};
use sha2::{Digest, Sha256};
use std::sync::Arc;

/// Largest request body: `{"version": 4294967295}` and some slack.
const MAX_BODY_BYTES: usize = 256;

/// Derives and signs a fleet public key. The production impl is
/// [`ServiceCdnFleetPublisher`]; tests swap in a stub.
pub trait CdnFleetPublisher: Send + Sync {
    fn public_key(&self, version: u64, now_unix: u64) -> Result<FleetPublicKey>;
    /// The Ed25519 key the signatures verify under (the KBS response key).
    fn kbs_public_key(&self) -> [u8; 32];
}

/// The production publisher: the SAME broker, Vault client, attestation
/// and response key the release path uses (`DefaultKbsService`).
pub struct ServiceCdnFleetPublisher {
    pub vault_auth: Arc<dyn AttestedVaultAuth + Send + Sync>,
    pub vault_kv: Arc<dyn VaultKv + Send + Sync>,
    pub kbs_attestation: Arc<VerifiedReport>,
    pub kbs_auth_pubkey: Arc<Vec<u8>>,
    pub kbs_signing_key: Arc<SigningKey>,
    pub kbs_kid: Arc<Vec<u8>>,
}

impl CdnFleetPublisher for ServiceCdnFleetPublisher {
    fn public_key(&self, version: u64, now_unix: u64) -> Result<FleetPublicKey> {
        derive_public_key(
            &FleetPublicDeps {
                vault_auth: self.vault_auth.as_ref(),
                vault_kv: self.vault_kv.as_ref(),
                kbs_attestation: &self.kbs_attestation,
                kbs_auth_pubkey: self.kbs_auth_pubkey.as_ref(),
                kbs_signing_key: &self.kbs_signing_key,
                kbs_kid: self.kbs_kid.as_ref(),
            },
            version,
            now_unix,
        )
    }

    fn kbs_public_key(&self) -> [u8; 32] {
        self.kbs_signing_key.verifying_key().to_bytes()
    }
}

#[derive(Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CdnFleetPublicRequest {
    pub version: u64,
}

/// The `fleet_keys[]` fields of vali's `GET /v1/cdn/nodes`, as the KBS
/// vouches for them. `kbs_signature_b64` is Ed25519 by the KBS response
/// key over `kbs_core::cdn_fleet::public_key_message`.
/// `kbs_public_key_hex` is informational: a verifier checks the signature
/// against the response key it pinned out of band, and only compares
/// this field to notice a KBS key rotation.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CdnFleetPublicResponse {
    pub v: u32,
    pub version: u64,
    pub x25519_public_b64: String,
    pub kbs_kid_hex: String,
    pub kbs_signature_b64: String,
    pub kbs_public_key_hex: String,
}

fn json_reason(status: StatusCode, reason: &str) -> Response {
    let mut resp = (status, Json(serde_json::json!({ "reason": reason }))).into_response();
    if status == StatusCode::TOO_MANY_REQUESTS {
        resp.headers_mut()
            .insert(header::RETRY_AFTER, HeaderValue::from_static("1"));
    }
    resp
}

pub async fn handle_cdn_fleet_public(
    State(state): State<AdminState>,
    request: Request,
) -> Response {
    use kbs_core::admin_audit::AdminAuditRecord;
    if !state.limiter.try_acquire() {
        return json_reason(StatusCode::TOO_MANY_REQUESTS, "rate-limited");
    }
    let (parts, body) = request.into_parts();
    let peer = parts.extensions.get::<PeerCertInfo>().cloned();
    let Ok(bytes) = to_bytes(body, MAX_BODY_BYTES).await else {
        return json_reason(StatusCode::PAYLOAD_TOO_LARGE, "body-too-large");
    };
    let mut body_sha = [0u8; 32];
    body_sha.copy_from_slice(Sha256::digest(&bytes).as_slice());
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    let outcome: core::result::Result<CdnFleetPublicResponse, (StatusCode, &'static str)> = async {
        // Like the rollback routes: a verified client identity per
        // request, whatever the listener's mode.
        if peer.is_none() {
            return Err((StatusCode::FORBIDDEN, "admin-client-cert-required"));
        }
        let publisher = state
            .cdn_fleet
            .clone()
            .ok_or((StatusCode::NOT_FOUND, "cdn-fleet-disabled"))?;
        let req: CdnFleetPublicRequest = serde_json::from_slice(&bytes)
            .map_err(|_| (StatusCode::BAD_REQUEST, "cdn-fleet-body-decode"))?;
        if req.version == 0 || req.version > u64::from(u32::MAX) {
            return Err((StatusCode::BAD_REQUEST, "cdn-fleet-bad-version"));
        }
        if now == 0 {
            return Err((StatusCode::INTERNAL_SERVER_ERROR, "clock-unavailable"));
        }
        // Broker + Vault round trips: off the async workers.
        let version = req.version;
        let kbs_public_key = publisher.kbs_public_key();
        let derived = tokio::task::spawn_blocking(move || publisher.public_key(version, now))
            .await
            .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "cdn-fleet-task-failed"))?
            .map_err(|e| {
                eprintln!("kbs-transport: cdn-fleet-public v{version}: {e}");
                (StatusCode::BAD_GATEWAY, "cdn-fleet-unwrap-failed")
            })?;
        Ok(CdnFleetPublicResponse {
            v: 1,
            version: derived.version,
            x25519_public_b64: B64.encode(derived.x25519_public),
            kbs_kid_hex: hex::encode(&derived.kbs_kid),
            kbs_signature_b64: B64.encode(derived.signature),
            kbs_public_key_hex: hex::encode(kbs_public_key),
        })
    }
    .await;

    let (status, reason, detail) = match &outcome {
        Ok(r) => (200u16, None, format!("version={}", r.version)),
        Err((code, r)) => (code.as_u16(), Some(*r), String::new()),
    };
    let reason = reason.or(Some(detail.as_str()).filter(|d| !d.is_empty()));
    let _ = state.audit.append(
        &AdminAuditRecord {
            op: "cdn-fleet-public",
            url_vm_id: "",
            ticket_id: None,
            vm_id: None,
            applied: false,
            status_code: status,
            reason,
            peer_san: peer.as_ref().map(|p| p.audit_identity()),
            peer_serial: peer.as_ref().map(|p| p.serial_hex.as_str()),
            body_sha256: &body_sha,
        },
        now,
    );
    match outcome {
        Ok(r) => (StatusCode::OK, Json(r)).into_response(),
        Err((code, reason)) => json_reason(code, reason),
    }
}

/// A [`ServiceCdnFleetPublisher`] over the reference challenge auth and an
/// in-memory Vault holding fleet key `v<version>` = `raw` (Transit mocked
/// as a reversible `vault:v1:cdn-fleet:<hex>` wrap).
#[cfg(test)]
pub(crate) mod test_support {
    use super::*;
    use kbs_core::error::KbsError;
    use kbs_core::snp::LaunchPolicy;
    use kbs_core::vault::{ChallengeVaultAuth, VaultCapability};
    use std::collections::HashMap;
    use zeroize::Zeroizing;

    pub struct Kv(pub HashMap<String, Vec<u8>>);
    impl VaultKv for Kv {
        fn read_exact(
            &self,
            _cap: &VaultCapability,
            path: &str,
            _version: u64,
        ) -> Result<Zeroizing<Vec<u8>>> {
            self.0
                .get(path)
                .cloned()
                .map(Zeroizing::new)
                .ok_or_else(|| KbsError::VaultNotFound("path not found".into()))
        }
        fn transit_decrypt(
            &self,
            _cap: &VaultCapability,
            transit_key: &str,
            ciphertext: &[u8],
        ) -> Result<Zeroizing<Vec<u8>>> {
            let s = core::str::from_utf8(ciphertext).map_err(|_| KbsError::Vault("utf8".into()))?;
            let hexed = s
                .strip_prefix(&format!("vault:v1:{transit_key}:"))
                .ok_or_else(|| KbsError::Vault("wrong transit key".into()))?;
            Ok(Zeroizing::new(
                hex::decode(hexed).map_err(|_| KbsError::Vault("hex".into()))?,
            ))
        }
    }

    pub fn publisher(
        version: u64,
        raw: [u8; 32],
        signing_seed: [u8; 32],
    ) -> ServiceCdnFleetPublisher {
        let ok: fn(&[u8; 48]) -> bool = |_m| true;
        let kv = Kv(HashMap::from([(
            kbs_core::cdn_fleet::secret_path(version),
            format!("vault:v1:cdn-fleet:{}", hex::encode(raw)).into_bytes(),
        )]));
        ServiceCdnFleetPublisher {
            vault_auth: Arc::new(ChallengeVaultAuth {
                kbs_measurement_ok: ok,
                policy: LaunchPolicy {
                    min_tcb: 0,
                    required_bits: 0,
                    allowed_mask: u64::MAX,
                },
                challenge_ttl: 30,
                cap_ttl: 30,
                challenge_nonce: [4u8; 32],
            }),
            vault_kv: Arc::new(kv),
            kbs_attestation: Arc::new(VerifiedReport {
                measurement: [0u8; 48],
                report_data: [0u8; 64],
                tcb: 1,
                policy: 0,
                chip_id: [0u8; 64],
                chain_pem: Vec::new(),
            }),
            kbs_auth_pubkey: Arc::new(b"pk".to_vec()),
            kbs_signing_key: Arc::new(SigningKey::from_bytes(&signing_seed)),
            kbs_kid: Arc::new(b"kbs-kid".to_vec()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kbs_core::cdn_fleet::{clamp, public_key, verify_public_key};

    #[test]
    fn the_service_publisher_derives_and_signs_with_the_response_key() {
        let raw = [0x42u8; 32];
        let p = test_support::publisher(5, raw, [6u8; 32]);
        let k = p.public_key(5, 100).unwrap();
        assert_eq!(k.x25519_public, public_key(&clamp(&raw)));
        assert_eq!(k.kbs_kid, b"kbs-kid");
        let vk = ed25519_dalek::VerifyingKey::from_bytes(&p.kbs_public_key()).unwrap();
        assert_eq!(vk, SigningKey::from_bytes(&[6u8; 32]).verifying_key());
        verify_public_key(&vk, 5, &k.x25519_public, &k.signature).unwrap();
        // A version that was never minted is an error, not a key.
        assert!(p.public_key(6, 100).is_err());
    }
}
