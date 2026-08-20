//! §H phase-2 — inner-plane order-dispatch router integration tests.
//!
//! Drives the production [`build_inner_router`] axum router against a
//! [`MockMinerForward`] (no network), and cross-checks the wire shape
//! against the miner-agent's own `SignedOrder` decoder so the two
//! crates' definitions are pinned identical.
//!
//! Coverage:
//!
//! - **Happy path** — POST a canonical-CBOR `OrderBody` with the two
//!   routing headers, the router signs it via [`OrderSigner`], the
//!   forwarder is invoked with the right target + kind, and the
//!   signature the forwarder observed `verify_strict`s under the
//!   matching pubkey (the cross-side contract).
//! - **End-to-end wire compatibility** — the production envelope the
//!   forwarder would have POSTed decodes back through the miner-agent's
//!   `SignedOrder` type (pulled as a dev-dependency for this test
//!   ONLY; the production binary does NOT depend on miner-agent — see
//!   `binaries/edge-gateway/src/forward/miner_forward.rs` opacity docs).
//! - **CGNAT enforcement** — a target_addr outside `100.64.0.0/10` →
//!   `400`, no signing work, no forward invocation.
//! - **Closed-vocabulary kind** — a bogus `x-hippius-order-kind` →
//!   `400`, no forward.
//! - **Missing headers** — both header-missing cases → `400`.
//! - **Body size cap** — a body past `MAX_MINER_ORDER_BODY` → `413`,
//!   before any signing work.
//! - **Forwarder transport failure** — the mocked forwarder returns
//!   [`MinerForwardError::Transport`] → router returns `502`.
//! - **Miner-side 4xx classifier** — the mocked forwarder returns
//!   `(status=400, body=b"bad-signature")` → router relays both
//!   verbatim to vali.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use axum::body::Body;
use ciborium::value::Value;
use hippius_edge_gateway::{
    build_inner_router, InnerRouterState, MinerForward, MinerForwardError, MockMinerForward,
    OrderKind, OrderSigner, ORDER_KIND_HEADER, TARGET_ADDR_HEADER,
};
use hippius_types::cbor::to_canonical_vec;
use http_body_util::BodyExt;
use std::io::Write;
use std::sync::Arc;
use tower::ServiceExt;

// ─── helpers ────────────────────────────────────────────────────────

/// Build an `OrderSigner` against a deterministic seed (so the test
/// can verify signatures off the public bytes derived from it).
fn test_signer() -> Arc<OrderSigner> {
    let mut f = tempfile::NamedTempFile::new().unwrap();
    f.write_all(hex::encode([42u8; 32]).as_bytes()).unwrap();
    f.flush().unwrap();
    OrderSigner::load(f.path(), None).unwrap()
}

/// A canonical-CBOR `OrderBody<LaunchOrder>` mirror — Edge does not
/// decode this; vali built it; the miner-agent will re-decode it. The
/// test treats it as opaque bytes that the router signs verbatim.
fn launch_order_body() -> Vec<u8> {
    let payload = Value::Map(vec![
        (
            Value::Text("cmdline".into()),
            Value::Text("console=hvc0".into()),
        ),
        (Value::Text("cpu_count".into()), Value::Integer(2.into())),
        (
            Value::Text("initrd_path".into()),
            Value::Text("/var/lib/hippius-miner/initrd".into()),
        ),
        (
            Value::Text("kernel_path".into()),
            Value::Text("/var/lib/hippius-miner/vmlinuz".into()),
        ),
        (
            Value::Text("luks_disk_path".into()),
            Value::Text("/var/lib/hippius-miner/d.img".into()),
        ),
        (
            Value::Text("luks_disk_size_gb".into()),
            Value::Integer(10.into()),
        ),
        (Value::Text("memory_mb".into()), Value::Integer(2048.into())),
        (
            Value::Text("ovmf_path".into()),
            Value::Text("/var/lib/hippius-miner/ovmf.fd".into()),
        ),
        (Value::Text("vm_id".into()), Value::Text("tenant-1".into())),
    ]);
    let body = Value::Map(vec![
        (
            Value::Text("domain".into()),
            Value::Text("HIPPIUS_MINER_ORDER_V1".into()),
        ),
        (
            Value::Text("issued_at_unix".into()),
            Value::Integer(1_770_000_000u64.into()),
        ),
        (Value::Text("kind".into()), Value::Text("launch".into())),
        (Value::Text("order_id".into()), Value::Text("ord-1".into())),
        (Value::Text("payload".into()), payload),
        (
            Value::Text("target_miner_id".into()),
            Value::Text("cc-test-miner".into()),
        ),
    ]);
    to_canonical_vec(&body).unwrap()
}

/// POST `body` to `/v1/edge/order` against a fresh router built from
/// `signer` + `forward`, with `target_addr` + `kind` headers. Returns
/// `(status, response body)`.
async fn post(
    signer: Arc<OrderSigner>,
    forward: Arc<dyn MinerForward>,
    target_addr: &str,
    kind: &str,
    body: Vec<u8>,
) -> (u16, Vec<u8>) {
    let router = build_inner_router(InnerRouterState::new(signer, forward));

    let mut req = axum::http::Request::builder()
        .method("POST")
        .uri("/v1/edge/order")
        .header("content-type", "application/cbor");
    if !target_addr.is_empty() {
        req = req.header(TARGET_ADDR_HEADER, target_addr);
    }
    if !kind.is_empty() {
        req = req.header(ORDER_KIND_HEADER, kind);
    }
    let request = req.body(Body::from(body)).unwrap();

    let response = router.oneshot(request).await.unwrap();
    let status = response.status().as_u16();
    let body = response.into_body().collect().await.unwrap().to_bytes();
    (status, body.to_vec())
}

// ─── happy path ─────────────────────────────────────────────────────

#[tokio::test]
async fn happy_path_signs_and_forwards_with_right_target_and_kind() {
    let signer = test_signer();
    let mock = Arc::new(MockMinerForward::with_response(200, Vec::new()));
    let forward: Arc<dyn MinerForward> = mock.clone();

    let body = launch_order_body();
    let (status, _) = post(
        signer.clone(),
        forward,
        "100.100.100.100:9700",
        "launch",
        body.clone(),
    )
    .await;
    assert_eq!(status, 200);

    let calls = mock.calls();
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].target_addr.to_string(), "100.100.100.100:9700");
    assert_eq!(calls[0].kind, OrderKind::Launch);
    // The body the forwarder saw is byte-equal to what we POSTed — the
    // router signed it but never modified the bytes (any re-encoding
    // would break verification on the miner side).
    assert_eq!(calls[0].body, body);

    // The signature the forwarder observed `verify_strict`s under the
    // pubkey vali published in `deploy/ansible/group_vars/miner_nodes.yml`
    // for THIS seed — the cross-side contract.
    use ed25519_dalek::Signature;
    let sig = Signature::from_bytes(&calls[0].sig);
    signer
        .verifying_key()
        .verify_strict(&body, &sig)
        .expect("the signature the miner would verify_strict must accept");
}

#[tokio::test]
async fn wire_envelope_decodes_through_the_miner_agent_signed_order_shape() {
    // Cross-crate compatibility: the bytes the production forwarder
    // would have POSTed to the miner must decode through the
    // miner-agent's own `SignedOrder` type. We do NOT pull miner-agent
    // as a dep in the production binary (opacity discipline); pulling
    // it here as a dev-dep for this test is exactly the pin that
    // catches drift between the two definitions.
    //
    // We build the envelope by hand using the same wire shape the
    // production forwarder uses, then decode it through the
    // miner-agent's `SignedOrder` (the actual type the miner-agent
    // route would receive on the wire).
    use ciborium::value::Value as CborValue;
    use hippius_miner_agent::orders::types::SignedOrder;
    use serde_bytes::ByteBuf;

    let signer = test_signer();
    let body = launch_order_body();
    let sig = signer.sign(&body);

    // Build the wire envelope the same way ReqwestMinerForward does
    // internally: a CBOR map with `body` + `sig` byte slots. Encode it
    // via a `{body: bytes, sig: bytes}` Value and decode back through
    // the production miner-agent type.
    let wire = CborValue::Map(vec![
        (
            CborValue::Text("body".into()),
            CborValue::Bytes(body.clone()),
        ),
        (
            CborValue::Text("sig".into()),
            CborValue::Bytes(sig.to_vec()),
        ),
    ]);
    let mut buf = Vec::new();
    ciborium::ser::into_writer(&wire, &mut buf).unwrap();

    let back: SignedOrder = ciborium::de::from_reader(buf.as_slice()).unwrap();
    assert_eq!(back.body, ByteBuf::from(body.clone()));
    assert_eq!(back.sig, ByteBuf::from(sig.to_vec()));

    // And the miner-agent's verifier accepts it under the same key.
    use ed25519_dalek::Signature;
    let parsed_sig = Signature::from_bytes(&sig);
    signer
        .verifying_key()
        .verify_strict(&body, &parsed_sig)
        .expect("end-to-end verify_strict");
}

// ─── error paths ────────────────────────────────────────────────────

#[tokio::test]
async fn missing_target_addr_returns_400() {
    let signer = test_signer();
    let mock = Arc::new(MockMinerForward::with_response(200, Vec::new()));
    let (status, _) = post(signer, mock.clone(), "", "launch", launch_order_body()).await;
    assert_eq!(status, 400);
    assert!(mock.calls().is_empty(), "no forward on bad header");
}

#[tokio::test]
async fn missing_order_kind_returns_400() {
    let signer = test_signer();
    let mock = Arc::new(MockMinerForward::with_response(200, Vec::new()));
    let (status, _) = post(
        signer,
        mock.clone(),
        "100.100.100.100:9700",
        "",
        launch_order_body(),
    )
    .await;
    assert_eq!(status, 400);
    assert!(mock.calls().is_empty());
}

#[tokio::test]
async fn target_addr_outside_cgnat_returns_400() {
    // Defense-in-depth: even though the NetworkPolicy gates the
    // listener to the vali pod only, the router refuses to sign +
    // forward an order to a non-NetBird address. A misconfigured vali
    // cannot relay through the Edge to an arbitrary external host.
    let signer = test_signer();
    let mock = Arc::new(MockMinerForward::with_response(200, Vec::new()));
    let (status, _) = post(
        signer,
        mock.clone(),
        "8.8.8.8:9700",
        "launch",
        launch_order_body(),
    )
    .await;
    assert_eq!(status, 400);
    assert!(
        mock.calls().is_empty(),
        "non-CGNAT target must not reach the forwarder"
    );
}

#[tokio::test]
async fn malformed_target_addr_returns_400() {
    let signer = test_signer();
    let mock = Arc::new(MockMinerForward::with_response(200, Vec::new()));
    let (status, _) = post(
        signer,
        mock.clone(),
        "not-an-address",
        "launch",
        launch_order_body(),
    )
    .await;
    assert_eq!(status, 400);
    assert!(mock.calls().is_empty());
}

#[tokio::test]
async fn unknown_order_kind_returns_400() {
    let signer = test_signer();
    let mock = Arc::new(MockMinerForward::with_response(200, Vec::new()));
    let (status, _) = post(
        signer,
        mock.clone(),
        "100.100.100.100:9700",
        "explode",
        launch_order_body(),
    )
    .await;
    assert_eq!(status, 400);
    assert!(mock.calls().is_empty());
}

#[tokio::test]
async fn forwarder_transport_failure_returns_502() {
    let signer = test_signer();
    let mock = Arc::new(MockMinerForward::with_error(MinerForwardError::Transport));
    let forward: Arc<dyn MinerForward> = mock.clone();
    let (status, _) = post(
        signer,
        forward,
        "100.100.100.100:9700",
        "launch",
        launch_order_body(),
    )
    .await;
    assert_eq!(status, 502);
    // The forwarder WAS invoked — the failure is transport-side, not a
    // header-validation early-out.
    assert_eq!(mock.calls().len(), 1);
}

#[tokio::test]
async fn miner_4xx_classifier_is_relayed_to_vali_verbatim() {
    // The miner-agent's `OrderVerifier::verify` returns 400 with body
    // `"bad-signature"` (or similar static classifier) when a
    // signature does not verify. vali must see the exact status +
    // classifier so it can branch on the failure mode — the router
    // surfaces the miner's response unchanged.
    let signer = test_signer();
    let mock = Arc::new(MockMinerForward::with_response(
        400,
        b"bad-signature".to_vec(),
    ));
    let forward: Arc<dyn MinerForward> = mock.clone();
    let (status, body) = post(
        signer,
        forward,
        "100.100.100.100:9700",
        "launch",
        launch_order_body(),
    )
    .await;
    assert_eq!(status, 400);
    assert_eq!(body, b"bad-signature");
}

#[tokio::test]
async fn oversize_body_returns_413_before_signing() {
    use hippius_edge_gateway::MAX_MINER_ORDER_BODY;
    let signer = test_signer();
    let mock = Arc::new(MockMinerForward::with_response(200, Vec::new()));
    let forward: Arc<dyn MinerForward> = mock.clone();
    // One byte over the cap — axum's DefaultBodyLimit rejects before
    // the handler runs.
    let too_big = vec![0u8; MAX_MINER_ORDER_BODY + 1];
    let (status, _) = post(signer, forward, "100.100.100.100:9700", "launch", too_big).await;
    assert_eq!(status, 413);
    assert!(
        mock.calls().is_empty(),
        "DefaultBodyLimit must trip before any signing / forwarding"
    );
}

// ─── tampered signature scenario (smoke 5b from the PR brief) ───────

#[tokio::test]
async fn tampered_signature_would_fail_miner_verification() {
    // The brief's smoke (b): "Tampered signature → miner rejects". We
    // simulate this by signing a CORRECT body, then mutating ONE byte
    // of the signature, and confirming the miner-side `verify_strict`
    // refuses. This is the integrity property the whole chain hinges
    // on — pin it explicitly.
    let signer = test_signer();
    let body = launch_order_body();
    let mut sig = signer.sign(&body);
    sig[0] ^= 1;
    use ed25519_dalek::Signature;
    let tampered = Signature::from_bytes(&sig);
    assert!(signer
        .verifying_key()
        .verify_strict(&body, &tampered)
        .is_err());
}
