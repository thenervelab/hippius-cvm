//! Telemetry-signer certificate verifier (ARCHITECTURE.md §7/§21/§23).
//!
//! The §23 tenant telemetry signer key is generated *inside* the
//! measured guest; the KBS, after verifying the SNP attestation that
//! binds the signer public key, issues a [`SignedTelemetryCert`]. This
//! module is the consumer side:
//!
//! - the tenant telemetry agent calls [`verify_telemetry_cert`] to
//!   confirm the KBS really certified the key it just generated (and
//!   nothing was swapped by a hostile relay);
//! - the validator (vali, §23) later calls it to bind a
//!   `ServedDeliveryReceipt` to a KBS-certified signer.
//!
//! [`verify_telemetry_cert`] re-derives the canonical CBOR body from
//! the fields the caller independently knows and byte-compares it to
//! the wire body **before** checking the KBS signature — the same
//! body-equality discipline as [`crate::verify_served_receipt`], so a
//! producer cannot smuggle bytes the field checks never saw.

use crate::error::{GuestError, Result};
use ed25519_dalek::{Signature, VerifyingKey};
use hippius_types::telemetry_cert::{
    SignedTelemetryCert, TelemetryCert, TELEMETRY_CERT_SCHEMA_VERSION,
};

/// The fields the verifier knows independently of the wire body — the
/// guest from its own state (the key it generated, the nonce it folded
/// into `REPORT_DATA`, its own measurement), the validator from the
/// scheduler / on-chain record.
#[derive(Debug, Clone)]
pub struct ExpectedTelemetryCert<'a> {
    pub v: u32,
    pub kbs_kid: &'a [u8],
    pub kbs_nonce: &'a [u8; 32],
    pub measurement: &'a [u8; 48],
    pub node_id: &'a [u8],
    pub signer_pubkey: &'a [u8; 32],
    pub vm_id: &'a str,
}

/// Verify a KBS [`SignedTelemetryCert`] against the caller's expected
/// fields and the pinned KBS verifying key.
///
/// Order (any failure ⇒ `Err`, fail-closed):
/// 0. Refuse an unknown certificate schema version outright.
/// 1. Re-derive the canonical body from `expected`.
/// 2. Byte-compare it to `signed.body` — a mismatch means the KBS
///    certified *different* values than the caller expects (a swapped
///    / stale / forged cert); reject before touching the signature.
/// 3. `verify_strict` the KBS Ed25519 signature over `signed.body`.
pub fn verify_telemetry_cert(
    kbs_vk: &VerifyingKey,
    signed: &SignedTelemetryCert,
    expected: &ExpectedTelemetryCert,
) -> Result<()> {
    // Fail closed on an unsupported schema version — the verifier must
    // never even attempt to accept a certificate shape it cannot
    // reason about, regardless of what the caller passed.
    if expected.v != TELEMETRY_CERT_SCHEMA_VERSION {
        return Err(GuestError::Schema(format!(
            "unsupported telemetry cert schema version {}",
            expected.v
        )));
    }
    let expected_body = TelemetryCert {
        v: expected.v,
        kbs_kid: expected.kbs_kid,
        kbs_nonce: expected.kbs_nonce,
        measurement: expected.measurement,
        node_id: expected.node_id,
        signer_pubkey: expected.signer_pubkey,
        vm_id: expected.vm_id,
    }
    .canonical()
    .map_err(|e| GuestError::Schema(format!("telemetry cert encode: {e}")))?;

    // Body-equality BEFORE signature verification: a hostile producer
    // cannot put values in `body` that the field checks never saw.
    if expected_body != signed.body {
        return Err(GuestError::Binding {
            field: "telemetry_cert_body",
            expected: format!("len={}", expected_body.len()),
            got: format!("len={}", signed.body.len()),
        });
    }

    let sig = Signature::from_slice(&signed.sig)
        .map_err(|e| GuestError::Signature(format!("telemetry cert sig decode: {e}")))?;
    kbs_vk
        .verify_strict(&signed.body, &sig)
        .map_err(|e| GuestError::Signature(format!("telemetry cert ed25519 verify: {e}")))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use hippius_types::telemetry_cert::TELEMETRY_CERT_SCHEMA_VERSION;

    fn kbs_key() -> SigningKey {
        SigningKey::from_bytes(&[42u8; 32])
    }

    const NONCE: [u8; 32] = [3u8; 32];
    const MEASUREMENT: [u8; 48] = [7u8; 48];
    const SIGNER_PUB: [u8; 32] = [9u8; 32];

    fn expected() -> ExpectedTelemetryCert<'static> {
        ExpectedTelemetryCert {
            v: TELEMETRY_CERT_SCHEMA_VERSION,
            kbs_kid: b"kbs-kid-1",
            kbs_nonce: &NONCE,
            measurement: &MEASUREMENT,
            node_id: b"node-1",
            signer_pubkey: &SIGNER_PUB,
            vm_id: "vm-1",
        }
    }

    /// Sign the canonical body for `exp` with `sk`.
    fn signed_for(sk: &SigningKey, exp: &ExpectedTelemetryCert) -> SignedTelemetryCert {
        let body = TelemetryCert {
            v: exp.v,
            kbs_kid: exp.kbs_kid,
            kbs_nonce: exp.kbs_nonce,
            measurement: exp.measurement,
            node_id: exp.node_id,
            signer_pubkey: exp.signer_pubkey,
            vm_id: exp.vm_id,
        }
        .canonical()
        .unwrap();
        let sig = sk.sign(&body);
        SignedTelemetryCert {
            body,
            sig: sig.to_bytes().to_vec(),
        }
    }

    #[test]
    fn sign_then_verify_ok() {
        let sk = kbs_key();
        let exp = expected();
        let signed = signed_for(&sk, &exp);
        verify_telemetry_cert(&sk.verifying_key(), &signed, &exp).unwrap();
    }

    #[test]
    fn wrong_kbs_key_rejected() {
        let signer = kbs_key();
        let exp = expected();
        let signed = signed_for(&signer, &exp);
        let attacker = SigningKey::from_bytes(&[1u8; 32]);
        assert!(verify_telemetry_cert(&attacker.verifying_key(), &signed, &exp).is_err());
    }

    #[test]
    fn tampered_body_rejected() {
        let sk = kbs_key();
        let exp = expected();
        let mut signed = signed_for(&sk, &exp);
        let last = signed.body.len() - 1;
        signed.body[last] ^= 0xff;
        assert!(verify_telemetry_cert(&sk.verifying_key(), &signed, &exp).is_err());
    }

    #[test]
    fn tampered_signature_rejected() {
        let sk = kbs_key();
        let exp = expected();
        let mut signed = signed_for(&sk, &exp);
        signed.sig[0] ^= 0xff;
        assert!(verify_telemetry_cert(&sk.verifying_key(), &signed, &exp).is_err());
    }

    #[test]
    fn malformed_signature_length_rejected() {
        let sk = kbs_key();
        let exp = expected();
        let mut signed = signed_for(&sk, &exp);
        signed.sig = vec![0u8; 63]; // Ed25519 sig must be 64 bytes
        assert!(verify_telemetry_cert(&sk.verifying_key(), &signed, &exp).is_err());
    }

    #[test]
    fn field_mismatch_rejected() {
        // The KBS signed a cert for `signer_pubkey = [9; 32]`; the
        // caller expects a different signer key ⇒ body mismatch.
        let sk = kbs_key();
        let signed = signed_for(&sk, &expected());
        let other_pub = [0xAAu8; 32];
        let mut wrong = expected();
        wrong.signer_pubkey = &other_pub;
        assert!(matches!(
            verify_telemetry_cert(&sk.verifying_key(), &signed, &wrong),
            Err(GuestError::Binding {
                field: "telemetry_cert_body",
                ..
            })
        ));
    }

    #[test]
    fn unknown_schema_version_rejected() {
        // A caller asking to verify against an unsupported schema
        // version is refused before any body/signature work.
        let sk = kbs_key();
        let signed = signed_for(&sk, &expected());
        let mut wrong = expected();
        wrong.v = TELEMETRY_CERT_SCHEMA_VERSION + 1;
        assert!(matches!(
            verify_telemetry_cert(&sk.verifying_key(), &signed, &wrong),
            Err(GuestError::Schema(_))
        ));
    }

    #[test]
    fn nonce_mismatch_rejected() {
        let sk = kbs_key();
        let signed = signed_for(&sk, &expected());
        let other_nonce = [0xBBu8; 32];
        let mut wrong = expected();
        wrong.kbs_nonce = &other_nonce;
        assert!(verify_telemetry_cert(&sk.verifying_key(), &signed, &wrong).is_err());
    }
}
