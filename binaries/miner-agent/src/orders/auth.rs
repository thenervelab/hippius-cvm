//! Lifecycle-order authentication — Ed25519 `verify_strict` against
//! the pinned Edge gateway order-signing key (MA-5).
//!
//! ## Trust model
//!
//! A lifecycle order is authorized by L1 / vali and relayed to the
//! miner over the Edge gateway, which signs it with its order-signing
//! Ed25519 key. The miner-agent runs on an **untrusted host** and the
//! orders HTTP listener is reachable by every NetBird mesh peer, so an
//! order is acted on **only** if its signature verifies against the
//! one pinned Edge public key — checked BEFORE the body is decoded
//! into a typed order and BEFORE anything is dispatched to the
//! lifecycle. An unsigned or wrongly-signed order is rejected at the
//! wire, never launched.
//!
//! ## `verify_strict`
//!
//! Verification uses [`VerifyingKey::verify_strict`], not `verify` —
//! it rejects the malleable low-order-`A` / non-canonical-`R` edge
//! cases, the same hardening the KBS, the edge-gateway telemetry
//! verifier and `ticket-validator` apply to every signature in the
//! stack.

use ed25519_dalek::{Signature, VerifyingKey};

use crate::error::{MinerAgentError, Result};

use super::types::SignedOrder;

/// Length of an Ed25519 public key / detached signature seed in hex
/// characters (32 bytes × 2).
const PUBKEY_HEX_LEN: usize = 64;

/// Verifies lifecycle orders against the pinned Edge gateway
/// order-signing public key.
#[derive(Debug)]
pub struct OrderVerifier {
    /// The one Edge order-signing key. An order signed by anything
    /// else is rejected.
    edge_key: VerifyingKey,
}

impl OrderVerifier {
    /// Build a verifier from the Edge order-signing public key, given
    /// as 64 lowercase-hex characters (the operator-configured value,
    /// `[edge].order_signing_pubkey`).
    ///
    /// Fail-closed: a wrong-length, non-hex or non-curve value yields
    /// `ConfigInvalid("edge.order_signing_pubkey")` so a miner with a
    /// broken order key never boots into "accept everything".
    pub fn from_hex(pubkey_hex: &str) -> Result<Self> {
        let bad = || MinerAgentError::ConfigInvalid("edge.order_signing_pubkey");
        if pubkey_hex.len() != PUBKEY_HEX_LEN {
            return Err(bad());
        }
        let raw = hex::decode(pubkey_hex).map_err(|_| bad())?;
        let bytes: [u8; 32] = raw.as_slice().try_into().map_err(|_| bad())?;
        let edge_key = VerifyingKey::from_bytes(&bytes).map_err(|_| bad())?;
        Ok(Self { edge_key })
    }

    /// Verify `signed`'s detached signature over its `body` bytes.
    ///
    /// `Ok(())` means the body is authentically the Edge gateway's —
    /// the caller may now decode + dispatch it. `Err` is a static
    /// classifier for the audit log: `malformed-sig` (the signature
    /// field was not a 64-byte Ed25519 signature) or `bad-signature`
    /// (well-formed but did not verify under the pinned key).
    pub fn verify(&self, signed: &SignedOrder) -> std::result::Result<(), &'static str> {
        let sig = Signature::from_slice(&signed.sig).map_err(|_| "malformed-sig")?;
        self.edge_key
            .verify_strict(&signed.body, &sig)
            .map_err(|_| "bad-signature")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use serde_bytes::ByteBuf;

    /// A deterministic Edge signing key + a verifier over its pubkey.
    fn key_pair() -> (SigningKey, OrderVerifier) {
        let sk = SigningKey::from_bytes(&[9u8; 32]);
        let verifier =
            OrderVerifier::from_hex(&hex::encode(sk.verifying_key().to_bytes())).unwrap();
        (sk, verifier)
    }

    fn signed(sk: &SigningKey, body: &[u8]) -> SignedOrder {
        SignedOrder {
            body: ByteBuf::from(body.to_vec()),
            sig: ByteBuf::from(sk.sign(body).to_bytes().to_vec()),
        }
    }

    #[test]
    fn a_correctly_signed_order_verifies() {
        let (sk, verifier) = key_pair();
        assert!(verifier.verify(&signed(&sk, b"order-body-bytes")).is_ok());
    }

    #[test]
    fn an_order_signed_by_another_key_is_rejected() {
        let (_sk, verifier) = key_pair();
        let attacker = SigningKey::from_bytes(&[1u8; 32]);
        assert_eq!(
            verifier.verify(&signed(&attacker, b"order-body-bytes")),
            Err("bad-signature")
        );
    }

    #[test]
    fn a_tampered_body_is_rejected() {
        let (sk, verifier) = key_pair();
        let mut order = signed(&sk, b"order-body-bytes");
        order.body[0] ^= 0xff;
        assert_eq!(verifier.verify(&order), Err("bad-signature"));
    }

    #[test]
    fn a_malformed_signature_is_rejected() {
        let (sk, verifier) = key_pair();
        let mut order = signed(&sk, b"order-body-bytes");
        order.sig = ByteBuf::from(vec![0u8; 10]); // not 64 bytes
        assert_eq!(verifier.verify(&order), Err("malformed-sig"));
    }

    #[test]
    fn from_hex_rejects_a_bad_pubkey() {
        for bad in ["", "zz", &"0".repeat(63), &"0".repeat(66)] {
            assert!(matches!(
                OrderVerifier::from_hex(bad),
                Err(MinerAgentError::ConfigInvalid("edge.order_signing_pubkey"))
            ));
        }
    }
}
