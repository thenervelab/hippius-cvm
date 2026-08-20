//! Integration tests for lifecycle-order authentication (MA-5) — the
//! public `OrderVerifier` against realistic signed-order envelopes.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use ed25519_dalek::{Signer, SigningKey};
use serde_bytes::ByteBuf;

use hippius_miner_agent::orders::{
    OrderBody, OrderKind, OrderVerifier, SignedOrder, StopOrder, ORDER_DOMAIN,
};
use hippius_miner_agent::{MinerAgentError, VmId};

/// Build a `SignedOrder` over a realistic `OrderBody<StopOrder>`,
/// signed with `sk`.
fn signed_stop_order(sk: &SigningKey, order_id: &str) -> SignedOrder {
    let body_struct = OrderBody {
        domain: ORDER_DOMAIN.to_string(),
        order_id: order_id.to_string(),
        kind: OrderKind::Stop,
        target_miner_id: "cc-test-miner".to_string(),
        issued_at_unix: 1_770_000_000,
        payload: StopOrder {
            vm_id: VmId::new("tenant-auth-1").unwrap(),
            graceful: true,
        },
    };
    let mut body = Vec::new();
    ciborium::ser::into_writer(&body_struct, &mut body).unwrap();
    let sig = sk.sign(&body).to_bytes().to_vec();
    SignedOrder {
        body: ByteBuf::from(body),
        sig: ByteBuf::from(sig),
    }
}

fn verifier_for(sk: &SigningKey) -> OrderVerifier {
    OrderVerifier::from_hex(&hex::encode(sk.verifying_key().to_bytes())).unwrap()
}

#[test]
fn an_order_signed_by_the_edge_key_verifies() {
    let sk = SigningKey::from_bytes(&[3u8; 32]);
    let verifier = verifier_for(&sk);
    assert!(verifier.verify(&signed_stop_order(&sk, "ord-1")).is_ok());
}

#[test]
fn an_order_signed_by_an_unknown_key_is_rejected() {
    let edge = SigningKey::from_bytes(&[3u8; 32]);
    let attacker = SigningKey::from_bytes(&[99u8; 32]);
    let verifier = verifier_for(&edge);
    // The order is well-formed but signed by the wrong key.
    assert_eq!(
        verifier.verify(&signed_stop_order(&attacker, "ord-1")),
        Err("bad-signature")
    );
}

#[test]
fn a_tampered_order_body_is_rejected() {
    let sk = SigningKey::from_bytes(&[3u8; 32]);
    let verifier = verifier_for(&sk);
    let mut order = signed_stop_order(&sk, "ord-1");
    // Flip a byte of the signed body — the signature no longer covers it.
    order.body[0] ^= 0xff;
    assert_eq!(verifier.verify(&order), Err("bad-signature"));
}

#[test]
fn a_truncated_signature_is_rejected_as_malformed() {
    let sk = SigningKey::from_bytes(&[3u8; 32]);
    let verifier = verifier_for(&sk);
    let mut order = signed_stop_order(&sk, "ord-1");
    order.sig = ByteBuf::from(vec![0u8; 32]); // not a 64-byte signature
    assert_eq!(verifier.verify(&order), Err("malformed-sig"));
}

#[test]
fn from_hex_fails_closed_on_a_malformed_pubkey() {
    for bad in ["", "deadbeef", &"z".repeat(64)] {
        assert!(matches!(
            OrderVerifier::from_hex(bad),
            Err(MinerAgentError::ConfigInvalid("edge.order_signing_pubkey"))
        ));
    }
}
