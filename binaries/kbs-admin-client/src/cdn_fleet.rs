//! `cdn-fleet-public`: check the KBS's answer for a cdn-fleet key version
//! before anyone publishes it.
//!
//! The KBS signs `"HIPPIUS_CDN_FLEET_PUB_V1" ‖ u64be(version) ‖
//! x25519_public` with its response key (`kbs_core::cdn_fleet`, rebuilt
//! here because this client never links kbs-core). The caller pins that
//! key out of band (`--kbs-vk-hex`); the `kbs_public_key_hex` the KBS
//! echoes is only compared, never trusted. Test vector:
//! `test_vectors/cdn_fleet/public_key_signature.json`.

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};

/// The exact bytes the KBS signs.
pub fn public_key_message(version: u64, x25519_public: &[u8; 32]) -> Vec<u8> {
    let mut m = Vec::with_capacity(64);
    m.extend_from_slice(b"HIPPIUS_CDN_FLEET_PUB_V1");
    m.extend_from_slice(&version.to_be_bytes());
    m.extend_from_slice(x25519_public);
    m
}

/// `POST /v1/admin/cdn-fleet/public` 200 body.
#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub struct CdnFleetPublic {
    pub v: u32,
    pub version: u64,
    pub x25519_public_b64: String,
    pub kbs_kid_hex: String,
    pub kbs_signature_b64: String,
    pub kbs_public_key_hex: String,
}

/// Decode `body` and verify it is the KBS's signature, under `pinned_vk`,
/// over fleet key `version`. Any mismatch is an error.
pub fn verify(body: &[u8], pinned_vk: &[u8; 32], version: u64) -> Result<CdnFleetPublic, String> {
    let r: CdnFleetPublic =
        serde_json::from_slice(body).map_err(|e| format!("response decode: {e}"))?;
    if r.v != 1 {
        return Err(format!("response v={} (want 1)", r.v));
    }
    if r.version != version {
        return Err(format!(
            "KBS answered version {} for version {version}",
            r.version
        ));
    }
    if r.kbs_public_key_hex != hex::encode(pinned_vk) {
        return Err(
            "the KBS signs with a different response key than the pinned one (key rotated?)".into(),
        );
    }
    let public: [u8; 32] = B64
        .decode(&r.x25519_public_b64)
        .ok()
        .and_then(|b| b.try_into().ok())
        .ok_or("x25519_public_b64 is not 32 bytes of base64")?;
    let sig: [u8; 64] = B64
        .decode(&r.kbs_signature_b64)
        .ok()
        .and_then(|b| b.try_into().ok())
        .ok_or("kbs_signature_b64 is not 64 bytes of base64")?;
    let vk = VerifyingKey::from_bytes(pinned_vk).map_err(|e| format!("pinned key: {e}"))?;
    vk.verify(
        &public_key_message(version, &public),
        &Signature::from_bytes(&sig),
    )
    .map_err(|_| "signature does not verify under the pinned KBS key".to_string())?;
    Ok(r)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vector() -> serde_json::Value {
        serde_json::from_str(include_str!(
            "../../../test_vectors/cdn_fleet/public_key_signature.json"
        ))
        .unwrap()
    }

    fn body(v: &serde_json::Value, version: u64) -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({
            "v": 1,
            "version": version,
            "x25519_public_b64": v["x25519_public_b64"],
            "kbs_kid_hex": "6b6273",
            "kbs_signature_b64": v["signature_b64"],
            "kbs_public_key_hex": v["kbs_public_key_hex"],
        }))
        .unwrap()
    }

    fn pinned(v: &serde_json::Value) -> [u8; 32] {
        hex::decode(v["kbs_public_key_hex"].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap()
    }

    #[test]
    fn the_shared_vector_verifies_and_its_message_matches() {
        let v = vector();
        let version = v["version"].as_u64().unwrap();
        let public: [u8; 32] = hex::decode(v["x25519_public_hex"].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap();
        assert_eq!(
            hex::encode(public_key_message(version, &public)),
            v["message_hex"].as_str().unwrap()
        );
        verify(&body(&v, version), &pinned(&v), version).unwrap();
    }

    #[test]
    fn a_wrong_version_key_or_signature_is_refused() {
        let v = vector();
        let version = v["version"].as_u64().unwrap();
        // Signed for `version`, presented as another one.
        let mut wrong = serde_json::from_slice::<serde_json::Value>(&body(&v, version)).unwrap();
        wrong["version"] = serde_json::json!(version + 1);
        assert!(verify(
            &serde_json::to_vec(&wrong).unwrap(),
            &pinned(&v),
            version + 1
        )
        .is_err());
        // Asked for one version, answered another.
        assert!(verify(&body(&v, version), &pinned(&v), version + 1).is_err());
        // A different pinned key.
        assert!(verify(&body(&v, version), &[1u8; 32], version).is_err());
        // A tampered public key.
        let mut t = serde_json::from_slice::<serde_json::Value>(&body(&v, version)).unwrap();
        t["x25519_public_b64"] = serde_json::json!(B64.encode([9u8; 32]));
        assert!(verify(&serde_json::to_vec(&t).unwrap(), &pinned(&v), version).is_err());
    }
}
