//! Ed25519 sign / verify for the §22 image provenance map.
//!
//! The signing key is the **§22 offline allowlist root** (PR-F4 ships
//! a committed dev placeholder; production swaps the key file, no code
//! change). The key seed is treated as sensitive throughout — every
//! intermediate buffer is `Zeroizing`, and `ed25519_dalek::SigningKey`
//! is built with the `zeroize` feature so it scrubs itself on drop.
//!
//! `verify_provenance` is the consumer side: it decodes + canonical-
//! checks the body, pins the in-body `signer_pubkey` to the verifier's
//! expected §22 root, and only then runs `verify_strict`.

use std::path::Path;

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use hippius_types::provenance::{ProvenanceMap, SignedProvenance, SHA256_LEN, SIGNATURE_LEN};
use zeroize::Zeroizing;

use crate::error::{Error, Result};

/// Ed25519 seed / public-key length.
const KEY_LEN: usize = 32;

/// Load the §22 root signing key from a hex-seed file.
///
/// The file is 64 lowercase-hex characters (the 32-byte Ed25519 seed),
/// optionally with surrounding whitespace. Every buffer that touches
/// the seed is zeroized; the returned `SigningKey` scrubs on drop.
pub fn load_signing_key(path: &Path) -> Result<SigningKey> {
    let raw = Zeroizing::new(std::fs::read(path).map_err(|source| Error::Read {
        path: path.to_path_buf(),
        source,
    })?);
    // Hex-decode straight from the (zeroized) file bytes — no
    // intermediate `String`, so the seed is never copied into an
    // un-zeroized buffer, not even on the malformed-file error path.
    let seed_vec = Zeroizing::new(
        hex::decode(raw.trim_ascii())
            .map_err(|_| Error::Key("signing-key file is not hex".into()))?,
    );
    if seed_vec.len() != KEY_LEN {
        return Err(Error::Key(format!(
            "signing-key seed must be {KEY_LEN} bytes, got {}",
            seed_vec.len()
        )));
    }
    let mut seed = Zeroizing::new([0u8; KEY_LEN]);
    seed.copy_from_slice(&seed_vec);
    Ok(SigningKey::from_bytes(&seed))
}

/// Load a §22 root *public* key from a hex file (not sensitive).
pub fn load_verifying_key(path: &Path) -> Result<VerifyingKey> {
    let raw = std::fs::read(path).map_err(|source| Error::Read {
        path: path.to_path_buf(),
        source,
    })?;
    let text =
        String::from_utf8(raw).map_err(|_| Error::Key("public-key file is not UTF-8".into()))?;
    let bytes =
        hex::decode(text.trim()).map_err(|_| Error::Key("public-key file is not hex".into()))?;
    let arr: [u8; KEY_LEN] = bytes.as_slice().try_into().map_err(|_| {
        Error::Key(format!(
            "public key must be {KEY_LEN} bytes, got {}",
            bytes.len()
        ))
    })?;
    VerifyingKey::from_bytes(&arr)
        .map_err(|e| Error::Key(format!("public key is not a valid Ed25519 point: {e}")))
}

/// The 32-byte public key of a signing key — what goes in the map's
/// `signer_pubkey` field and is committed as the §22 root anchor.
pub fn public_key_bytes(sk: &SigningKey) -> [u8; SHA256_LEN] {
    sk.verifying_key().to_bytes()
}

/// Sign a provenance map with the §22 root key.
///
/// The produced signature is verified back before returning — a
/// belt-and-braces self-check that catches a wrong key, a broken
/// canonical encoder, or a decode round-trip bug at the source rather
/// than at the miner.
pub fn sign_provenance(sk: &SigningKey, map: &ProvenanceMap) -> Result<SignedProvenance> {
    // The signed body MUST commit to the signer — otherwise a verifier
    // could not pin the signature to the §22 root identity.
    if map.signer_pubkey != public_key_bytes(sk) {
        return Err(Error::Signature(
            "provenance signer_pubkey does not match the signing key".into(),
        ));
    }
    let body = map.canonical()?;
    let sig = sk.sign(&body);
    let signed = SignedProvenance {
        body,
        sig: sig.to_bytes().to_vec(),
    };
    verify_provenance(&signed, &sk.verifying_key())?;
    Ok(signed)
}

/// Verify a signed provenance envelope against an expected §22 root.
///
/// Steps, all fail-closed: decode + canonical-check the body; pin the
/// in-body `signer_pubkey` to the caller's expected root key; then
/// `verify_strict` the detached signature. Returns the decoded map.
pub fn verify_provenance(
    signed: &SignedProvenance,
    expected_root: &VerifyingKey,
) -> Result<ProvenanceMap> {
    // Pin the 64-byte signature invariant at this entry point too —
    // `verify_provenance` is `pub` and takes a caller-built envelope,
    // so it must not rely on `SignedProvenance::decode` having run.
    if signed.sig.len() != SIGNATURE_LEN {
        return Err(Error::Signature(format!(
            "signature must be {SIGNATURE_LEN} bytes, got {}",
            signed.sig.len()
        )));
    }
    let map = ProvenanceMap::decode(&signed.body)?;

    // The body must name the key the verifier trusts. Without this a
    // valid signature by some *other* key would pass `verify_strict`
    // if a caller mistakenly passed that other key as `expected_root`.
    if map.signer_pubkey != expected_root.to_bytes() {
        return Err(Error::Signature(
            "provenance signer_pubkey does not match the expected §22 root key".into(),
        ));
    }
    let sig = Signature::from_slice(&signed.sig)
        .map_err(|e| Error::Signature(format!("signature decode: {e}")))?;
    expected_root
        .verify_strict(&signed.body, &sig)
        .map_err(|e| Error::Signature(format!("ed25519 verification failed: {e}")))?;
    Ok(map)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use hippius_types::provenance::{
        SnpLaunchConfig, LAUNCH_MEASUREMENT_LEN, MEASUREMENT_KIND_SNP, PROVENANCE_SCHEMA_VERSION,
    };

    fn key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    fn map_for(sk: &SigningKey) -> ProvenanceMap {
        ProvenanceMap {
            schema_version: PROVENANCE_SCHEMA_VERSION,
            measurement_kind: MEASUREMENT_KIND_SNP.to_string(),
            launch_measurement: [0xA1; LAUNCH_MEASUREMENT_LEN],
            artifact_sha256: [0xA2; SHA256_LEN],
            verity_root_hash: [0xA3; SHA256_LEN],
            kernel_sha256: [0xA4; SHA256_LEN],
            initrd_sha256: [0xA5; SHA256_LEN],
            cmdline_sha256: [0xA6; SHA256_LEN],
            ovmf_sha256: [0xA7; SHA256_LEN],
            snp_launch_config: SnpLaunchConfig {
                vcpus: 1,
                vcpu_type: "EpycV4".to_string(),
                guest_features: "0x1".to_string(),
            },
            s3_bucket: "hippius-compute-images".to_string(),
            s3_key: "images/abc/kbs.uki".to_string(),
            built_at_unix: 1_700_000_000,
            signer_pubkey: public_key_bytes(sk),
        }
    }

    #[test]
    fn sign_then_verify_round_trips() {
        let sk = key(7);
        let map = map_for(&sk);
        let signed = sign_provenance(&sk, &map).unwrap();
        let recovered = verify_provenance(&signed, &sk.verifying_key()).unwrap();
        assert_eq!(map, recovered);
    }

    #[test]
    fn sign_rejects_a_map_naming_a_different_signer() {
        let sk = key(7);
        let mut map = map_for(&sk);
        map.signer_pubkey = public_key_bytes(&key(8)); // names a different key
        assert!(matches!(
            sign_provenance(&sk, &map),
            Err(Error::Signature(_))
        ));
    }

    #[test]
    fn verify_rejects_a_wrong_root_key() {
        let sk = key(7);
        let signed = sign_provenance(&sk, &map_for(&sk)).unwrap();
        // A different §22 root must not accept this provenance.
        assert!(verify_provenance(&signed, &key(8).verifying_key()).is_err());
    }

    #[test]
    fn verify_rejects_a_tampered_body() {
        let sk = key(7);
        let mut signed = sign_provenance(&sk, &map_for(&sk)).unwrap();
        let last = signed.body.len() - 1;
        signed.body[last] ^= 0xff;
        assert!(verify_provenance(&signed, &sk.verifying_key()).is_err());
    }

    #[test]
    fn verify_rejects_a_tampered_signature() {
        let sk = key(7);
        let mut signed = sign_provenance(&sk, &map_for(&sk)).unwrap();
        signed.sig[0] ^= 0xff;
        assert!(verify_provenance(&signed, &sk.verifying_key()).is_err());
    }

    #[test]
    fn verify_rejects_a_substituted_signer_pubkey() {
        // Re-sign a body whose signer_pubkey claims key 8 with key 8,
        // but ask a verifier expecting key 7 — must be rejected on the
        // signer_pubkey pin, not just the signature.
        let sk7 = key(7);
        let sk8 = key(8);
        let mut map = map_for(&sk8);
        map.signer_pubkey = public_key_bytes(&sk8);
        let signed = sign_provenance(&sk8, &map).unwrap();
        assert!(verify_provenance(&signed, &sk7.verifying_key()).is_err());
    }
}
