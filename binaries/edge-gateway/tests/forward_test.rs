//! PR-H8 — `ForwardClient` / `MockForwardClient` tests.
//!
//! The opaque-byte-relay seam: a `ForwardClient` ships a validated
//! envelope's body bytes onward to the inner control plane verbatim.
//! These tests pin the [`MockForwardClient`] test double — the seam
//! the `tests/miner_router_test.rs` routing tests depend on — and the
//! `ForwardError` → classifier contract.
//!
//! The production [`ReqwestForwardClient`] is exercised by its own
//! in-module unit tests (builder success, URL joining) plus the
//! router integration tests; it is not driven against a live KBS /
//! vali here (that needs a real cluster).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use hippius_edge_gateway::{
    ForwardClient, ForwardError, MessageKind, MockForwardClient, ReqwestForwardClient,
};

#[tokio::test]
async fn mock_forward_records_each_call_with_its_kind() {
    // The mock must record which `forward_*` method the router routed
    // through — that is what the routing-correctness assertions in
    // `miner_router_test.rs` read back.
    let mock = MockForwardClient::with_response(202, Vec::new());
    let env = build_validated_signed_envelope(MessageKind::ServedReceipt);

    let resp = mock.forward_served_receipt(&env).await.unwrap();
    assert_eq!(resp.status, 202);

    let calls = mock.calls();
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].kind, MessageKind::ServedReceipt);
}

#[tokio::test]
async fn mock_forward_relays_body_bytes_verbatim() {
    // Opaque byte relay: the bytes the mock was handed must be the
    // exact envelope body — no re-encoding anywhere on the path.
    let mock = MockForwardClient::with_response(200, Vec::new());
    let env = build_validated_signed_envelope(MessageKind::StoppedAck);
    let expected = signed_envelope_body();

    mock.forward_stopped_ack(&env).await.unwrap();
    let calls = mock.calls();
    assert_eq!(calls[0].body, expected, "forward must relay body verbatim");
}

#[tokio::test]
async fn mock_forward_can_return_a_transport_error() {
    // Drives the router's "forward transport failure → 502" path.
    let mock = MockForwardClient::with_error(ForwardError::Transport);
    let env = build_validated_signed_envelope(MessageKind::ServedAggregate);
    let err = mock.forward_served_aggregate(&env).await.unwrap_err();
    assert!(matches!(err, ForwardError::Transport));
}

#[test]
fn reqwest_forward_client_builds_against_cluster_dns_defaults() {
    // A builder failure would be boot-fatal — pin that the default
    // cluster-DNS endpoints build cleanly.
    let client = ReqwestForwardClient::new(
        "http://kbs-server.kbs.svc.cluster.local:8000",
        "http://vali.vali.svc.cluster.local:8000",
        None,
    );
    assert!(client.is_ok());
}

#[test]
fn forward_error_classifiers_are_stable_static_strings() {
    for (err, class) in [
        (ForwardError::ClientBuild, "forward-client-build"),
        (ForwardError::Transport, "forward-transport"),
        (ForwardError::ResponseTooLarge, "forward-response-too-large"),
        (ForwardError::ResponseRead, "forward-response-read"),
    ] {
        assert_eq!(err.class(), class);
        // `Display` must equal `class()` — no body / URL interpolation.
        assert_eq!(err.to_string(), class);
    }
}

// ─── helpers ────────────────────────────────────────────────────────

/// Canonical-CBOR `{body, sig}` — the shape every `Signed*` kind
/// shares; the bytes the `ServedReceipt` / `ServedAggregate` /
/// `StoppedAck` wire gate accepts.
fn signed_envelope_body() -> Vec<u8> {
    use ciborium::value::Value;
    use hippius_types::cbor::to_canonical_vec;
    let v = Value::Map(vec![
        (Value::Text("body".into()), Value::Bytes(vec![0u8; 16])),
        (Value::Text("sig".into()), Value::Bytes(vec![0u8; 64])),
    ]);
    to_canonical_vec(&v).unwrap()
}

/// Build a `ValidatedEnvelope` of `kind` via the production wire gate
/// — the only path to one. `kind` must be a `Signed*` kind (the test
/// helper only builds the `{body, sig}` shape).
fn build_validated_signed_envelope(
    kind: MessageKind,
) -> hippius_edge_gateway::stages::envelope::ValidatedEnvelope {
    use hippius_edge_gateway::mtls::PeerId;
    use hippius_edge_gateway::stages::envelope::RawEnvelope;
    use hippius_edge_gateway::stages::validate::validate;
    use hippius_edge_gateway::Direction;

    let raw = RawEnvelope::from_wire(
        Direction::MinerToInner,
        kind,
        PeerId::new("hippius-miner:test"),
        signed_envelope_body(),
    );
    validate(raw).expect("signed-envelope body must pass the wire gate")
}
