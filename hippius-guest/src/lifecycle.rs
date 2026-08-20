//! Guest-signed end-of-life acknowledgement (ARCHITECTURE.md §24/§25).
//!
//! Producer-side (guest): `sign_stopped_ack` signs the canonical body
//! emitted by `hippius_types::stopped::StoppedAck::canonical()` with
//! the guest's lifecycle Ed25519 key.
//!
//! Consumer-side (orchestrator/KBS): `verify_stopped_ack` re-derives
//! the same canonical bytes from the expected fields and Ed25519-
//! verifies. A mismatch is fail-closed: the orchestrator MUST NOT
//! commit `Destroyed{gen}` or activate the §25 destination guest.

use crate::error::{GuestError, Result};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use hippius_types::stopped::{SignedStoppedAck, StoppedAck};

/// Sign the canonical-CBOR `StoppedAck` body with the guest's lifecycle
/// key. The signing key is held inside the attested guest's mlocked
/// memory; production initramfs agents should zeroize it after the
/// ack is emitted.
pub fn sign_stopped_ack(sk: &SigningKey, ack: &StoppedAck) -> Result<SignedStoppedAck> {
    let body = ack
        .canonical()
        .map_err(|e| GuestError::StoppedAck(format!("encode: {e}")))?;
    let sig = sk.sign(&body);
    Ok(SignedStoppedAck {
        body,
        sig: sig.to_bytes().to_vec(),
    })
}

/// Verify a `SignedStoppedAck` against a re-derived `StoppedAck` body.
///
/// The verifier MUST supply the same fields the guest signed — the body
/// bytes from the wire are NOT trusted directly: we recompute them so
/// a hostile producer that puts garbage in the signed body (different
/// vm_id, larger nonce, etc.) cannot bypass field checks.
pub fn verify_stopped_ack(
    vk: &VerifyingKey,
    signed: &SignedStoppedAck,
    expected: &StoppedAck,
) -> Result<()> {
    let expected_body = expected
        .canonical()
        .map_err(|e| GuestError::StoppedAck(format!("expected encode: {e}")))?;
    if expected_body != signed.body {
        return Err(GuestError::StoppedAck(
            "body mismatch (expected fields differ from signed body)".into(),
        ));
    }
    let sig = Signature::from_slice(&signed.sig)
        .map_err(|e| GuestError::StoppedAck(format!("sig decode: {e}")))?;
    vk.verify_strict(&signed.body, &sig)
        .map_err(|e| GuestError::StoppedAck(format!("ed25519 verify: {e}")))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key() -> SigningKey {
        SigningKey::from_bytes(&[42u8; 32])
    }

    #[test]
    fn sign_then_verify_ok() {
        let sk = key();
        let n = [3u8; 32];
        let ack = StoppedAck {
            vm_id: "abc",
            lease_id: "lease-1",
            vm_generation: 7,
            nonce: &n,
            now_unix: 1_000_000,
        };
        let signed = sign_stopped_ack(&sk, &ack).unwrap();
        verify_stopped_ack(&sk.verifying_key(), &signed, &ack).unwrap();
    }

    #[test]
    fn body_mismatch_rejected() {
        let sk = key();
        let n = [3u8; 32];
        let ack = StoppedAck {
            vm_id: "abc",
            lease_id: "lease-1",
            vm_generation: 7,
            nonce: &n,
            now_unix: 1_000_000,
        };
        let signed = sign_stopped_ack(&sk, &ack).unwrap();
        let bumped = StoppedAck {
            vm_generation: 8,
            ..ack
        };
        assert!(verify_stopped_ack(&sk.verifying_key(), &signed, &bumped).is_err());
    }

    #[test]
    fn wrong_signer_rejected() {
        let sk = key();
        let attacker = SigningKey::from_bytes(&[9u8; 32]);
        let n = [3u8; 32];
        let ack = StoppedAck {
            vm_id: "abc",
            lease_id: "lease-1",
            vm_generation: 7,
            nonce: &n,
            now_unix: 1_000_000,
        };
        let signed = sign_stopped_ack(&attacker, &ack).unwrap();
        assert!(verify_stopped_ack(&sk.verifying_key(), &signed, &ack).is_err());
    }

    #[test]
    fn tampered_sig_rejected() {
        let sk = key();
        let n = [3u8; 32];
        let ack = StoppedAck {
            vm_id: "abc",
            lease_id: "lease-1",
            vm_generation: 7,
            nonce: &n,
            now_unix: 1_000_000,
        };
        let mut signed = sign_stopped_ack(&sk, &ack).unwrap();
        signed.sig[0] ^= 0xff;
        assert!(verify_stopped_ack(&sk.verifying_key(), &signed, &ack).is_err());
    }
}
