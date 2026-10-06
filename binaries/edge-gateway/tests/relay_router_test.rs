//! §25 migration **M1** — Edge relay router integration tests.
//!
//! Drives the production [`build_inner_router`] (which mounts the §25
//! M1 relay routes) against a [`MockMinerForward`] — no network — and
//! asserts:
//!
//! - A `POST /v1/relay/{vm}/quiesce` builds + signs a `migrate-quiesce`
//!   order and forwards it to the source miner address (CGNAT-checked),
//!   with the signed body decoding back through a mirror of the
//!   miner-agent's `OrderBody<MigrateQuiesceOrder>` shape (the
//!   cross-crate wire contract).
//! - A `POST /v1/relay/{vm}/snapshot` forwards a `migrate-snapshot`
//!   order carrying the presigned `put_url`.
//! - A `GET /v1/relay/{vm}/snapshot` proxies the miner's
//!   `{"status": …}` JSON back verbatim (the shape vali's
//!   `poll_snapshot` expects).
//! - CGNAT enforcement + vm_id charset validation reject bad input with
//!   `400` and NEVER invoke the forwarder.
//! - A forwarder transport failure → `502`.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use axum::body::Body;
use ed25519_dalek::Verifier;
use hippius_edge_gateway::{
    build_inner_router, InnerRouterState, MinerForward, MinerForwardError, MockMinerForward,
    OrderKind, OrderSigner, TARGET_ADDR_HEADER,
};
use http_body_util::BodyExt;
use serde::Deserialize;
use std::io::Write;
use std::sync::Arc;
use tower::ServiceExt;

const MINER_ADDR: &str = "100.64.0.7:9700";

fn test_signer() -> Arc<OrderSigner> {
    let mut f = tempfile::NamedTempFile::new().unwrap();
    f.write_all(hex::encode([42u8; 32]).as_bytes()).unwrap();
    f.flush().unwrap();
    OrderSigner::load(f.path(), None).unwrap()
}

/// POST a JSON relay body to `path` against a fresh router built from
/// `signer` + `forward`. Returns `(status, response body)`.
async fn post_relay(
    signer: Arc<OrderSigner>,
    forward: Arc<dyn MinerForward>,
    path: &str,
    json: &str,
) -> (u16, Vec<u8>) {
    let router = build_inner_router(InnerRouterState::new(signer, forward));
    let request = axum::http::Request::builder()
        .method("POST")
        .uri(path)
        .header("content-type", "application/json")
        .body(Body::from(json.to_string()))
        .unwrap();
    let response = router.oneshot(request).await.unwrap();
    let status = response.status().as_u16();
    let body = response.into_body().collect().await.unwrap().to_bytes();
    (status, body.to_vec())
}

/// GET `path` against a fresh router. Returns `(status, response body)`.
async fn get_relay(
    signer: Arc<OrderSigner>,
    forward: Arc<dyn MinerForward>,
    path: &str,
    target_addr: &str,
) -> (u16, Vec<u8>) {
    let router = build_inner_router(InnerRouterState::new(signer, forward));
    let mut req = axum::http::Request::builder().method("GET").uri(path);
    if !target_addr.is_empty() {
        req = req.header(TARGET_ADDR_HEADER, target_addr);
    }
    let response = router
        .oneshot(req.body(Body::empty()).unwrap())
        .await
        .unwrap();
    let status = response.status().as_u16();
    let body = response.into_body().collect().await.unwrap().to_bytes();
    (status, body.to_vec())
}

// Mirror of the miner-agent's `OrderBody<MigrateQuiesceOrder>` — the
// Edge does not depend on the miner-agent crate; this mirror pins the
// wire shape the relay builds against what the miner re-decodes.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireQuiesce {
    vm_id: String,
    node_id: String,
    // §25 M3/M4 producer fields — `#[serde(default)]` so an M1 quiesce
    // (no producer step) still decodes (the keys are absent).
    #[serde(default)]
    lease_id: String,
    #[serde(default)]
    source_gen: u64,
    #[serde(default)]
    eol_nonce_hex: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireSnapshot {
    vm_id: String,
    node_id: String,
    put_url: String,
    /// `Option` so the ABSENT case (no state disk carried) is a distinct,
    /// assertable outcome from an empty string — the difference that
    /// decides whether a not-yet-upgraded miner accepts the order at all.
    /// `deny_unknown_fields` on the struct means a future field added to
    /// the relay without updating this mirror fails the decode instead of
    /// passing silently.
    #[serde(default)]
    state_put_url: Option<String>,
}
#[derive(Deserialize)]
struct WireBody<P> {
    domain: String,
    kind: String,
    target_miner_id: String,
    issued_at_unix: u64,
    order_id: String,
    payload: P,
}

#[tokio::test]
async fn quiesce_builds_signs_and_forwards_a_migrate_quiesce_order() {
    let signer = test_signer();
    let vk = signer.public_key_bytes();
    let mock = Arc::new(MockMinerForward::with_response(200, Vec::new()));
    let json = format!(r#"{{"node_id":"miner-a","miner_addr":"{MINER_ADDR}"}}"#);
    let (status, _body) = post_relay(
        Arc::clone(&signer),
        Arc::clone(&mock) as Arc<dyn MinerForward>,
        "/v1/relay/tenant-x/quiesce",
        &json,
    )
    .await;
    assert_eq!(status, 200);

    // The forwarder was invoked exactly once, to the source miner addr,
    // with the migrate-quiesce kind.
    let calls = mock.calls();
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].target_addr.to_string(), MINER_ADDR);
    assert_eq!(calls[0].kind, OrderKind::MigrateQuiesce);

    // The signed body decodes through the miner-agent's OrderBody shape.
    let back: WireBody<WireQuiesce> = ciborium::de::from_reader(calls[0].body.as_slice()).unwrap();
    assert_eq!(back.domain, "HIPPIUS_MINER_ORDER_V1");
    assert_eq!(back.kind, "migrate-quiesce");
    assert_eq!(back.target_miner_id, "miner-a");
    assert_eq!(back.payload.vm_id, "tenant-x");
    assert_eq!(back.payload.node_id, "miner-a");
    assert!(back.issued_at_unix > 0);
    assert!(back.order_id.starts_with("mig-migrate-quiesce-tenant-x-"));

    // The signature the forwarder observed verifies under the Edge's
    // pubkey over the EXACT body bytes — what the miner's `verify_strict`
    // would check.
    let sig = ed25519_dalek::Signature::from_bytes(&calls[0].sig);
    let vk = ed25519_dalek::VerifyingKey::from_bytes(&vk).unwrap();
    vk.verify(&calls[0].body, &sig).unwrap();

    // M1 caller (no producer fields) ⇒ the producer keys are ABSENT from
    // the body (they serde-default to empty / 0 on the miner side).
    assert_eq!(back.payload.lease_id, "");
    assert_eq!(back.payload.source_gen, 0);
    assert_eq!(back.payload.eol_nonce_hex, "");
    let needle = b"eol_nonce_hex";
    assert!(
        !calls[0]
            .body
            .windows(needle.len())
            .any(|w| w == needle.as_slice()),
        "eol_nonce_hex key must be absent on an M1 quiesce"
    );
}

#[tokio::test]
async fn quiesce_forwards_the_m3_producer_nonce_and_source_gen() {
    // §25 M3/M4 — when vali's quiesce carries the fresh `eol_nonce_hex` +
    // `source_gen` + `lease_id`, the Edge relay forwards them through to the
    // miner so the guest signer receives the inputs. Before this wiring the
    // `deny_unknown_fields` QuiesceBody REJECTED these fields (bad-relay-body)
    // and the producer never received them — the §25 ack could never be
    // produced. This pins the transport closed.
    let signer = test_signer();
    let mock = Arc::new(MockMinerForward::with_response(200, Vec::new()));
    let nonce = "ab".repeat(32); // 64-byte hex
    let json = format!(
        r#"{{"node_id":"miner-a","miner_addr":"{MINER_ADDR}","lease_id":"lease-7","source_gen":5,"eol_nonce_hex":"{nonce}"}}"#
    );
    let (status, _body) = post_relay(
        Arc::clone(&signer),
        Arc::clone(&mock) as Arc<dyn MinerForward>,
        "/v1/relay/tenant-x/quiesce",
        &json,
    )
    .await;
    assert_eq!(status, 200);

    let calls = mock.calls();
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].kind, OrderKind::MigrateQuiesce);

    // The producer fields decode through the miner-agent's
    // `OrderBody<MigrateQuiesceOrder>` shape — exactly what the miner's
    // `source_ack_inputs()` reads to drive the guest signer.
    let back: WireBody<WireQuiesce> = ciborium::de::from_reader(calls[0].body.as_slice()).unwrap();
    assert_eq!(back.kind, "migrate-quiesce");
    assert_eq!(back.payload.vm_id, "tenant-x");
    assert_eq!(back.payload.node_id, "miner-a");
    assert_eq!(back.payload.lease_id, "lease-7");
    assert_eq!(back.payload.source_gen, 5);
    assert_eq!(back.payload.eol_nonce_hex, nonce);

    // The whole body still verifies under the Edge key — the producer
    // fields are part of the signed payload, not a side channel.
    let vk = signer.public_key_bytes();
    let sig = ed25519_dalek::Signature::from_bytes(&calls[0].sig);
    let vk = ed25519_dalek::VerifyingKey::from_bytes(&vk).unwrap();
    vk.verify(&calls[0].body, &sig).unwrap();
}

#[tokio::test]
async fn snapshot_trigger_forwards_a_migrate_snapshot_order_with_the_put_url() {
    let signer = test_signer();
    let mock = Arc::new(MockMinerForward::with_response(200, Vec::new()));
    let put_url = "https://s3.example/migrations/tenant-x/job.luks?sig=abc";
    let json =
        format!(r#"{{"node_id":"miner-a","miner_addr":"{MINER_ADDR}","put_url":"{put_url}"}}"#);
    let (status, _body) = post_relay(
        Arc::clone(&signer),
        Arc::clone(&mock) as Arc<dyn MinerForward>,
        "/v1/relay/tenant-x/snapshot",
        &json,
    )
    .await;
    assert_eq!(status, 200);

    let calls = mock.calls();
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].kind, OrderKind::MigrateSnapshot);
    let back: WireBody<WireSnapshot> = ciborium::de::from_reader(calls[0].body.as_slice()).unwrap();
    assert_eq!(back.kind, "migrate-snapshot");
    assert_eq!(back.payload.vm_id, "tenant-x");
    assert_eq!(back.payload.node_id, "miner-a");
    assert_eq!(back.payload.put_url, put_url);
    // No `state_put_url` in the request ⇒ the key must be ABSENT from the
    // signed body, not present-and-empty: the miner's
    // `deny_unknown_fields` would reject the order outright, and it would
    // do so after the quiesce had already stopped the tenant guest.
    assert_eq!(back.payload.state_put_url, None);
}

#[tokio::test]
async fn snapshot_trigger_forwards_the_state_disk_put_url_when_carried() {
    // §25 — the anti-rollback boot counter travels with the volume. If
    // this key never reaches the miner the source uploads nothing, the
    // destination formats a blank counter, and the KBS refuses the
    // release: the migrated guest boots and never unlocks.
    let signer = test_signer();
    let mock = Arc::new(MockMinerForward::with_response(200, Vec::new()));
    let put_url = "https://s3.example/migrations/tenant-x/job.luks?sig=abc";
    let state_put_url = "https://s3.example/migrations/tenant-x/job.state?sig=def";
    let json = format!(
        r#"{{"node_id":"miner-a","miner_addr":"{MINER_ADDR}","put_url":"{put_url}","state_put_url":"{state_put_url}"}}"#
    );
    let (status, _body) = post_relay(
        Arc::clone(&signer),
        Arc::clone(&mock) as Arc<dyn MinerForward>,
        "/v1/relay/tenant-x/snapshot",
        &json,
    )
    .await;
    assert_eq!(status, 200);

    let calls = mock.calls();
    let back: WireBody<WireSnapshot> = ciborium::de::from_reader(calls[0].body.as_slice()).unwrap();
    assert_eq!(back.payload.put_url, put_url);
    assert_eq!(back.payload.state_put_url.as_deref(), Some(state_put_url));

    // The state URL is inside the SIGNED body, not a side channel.
    let vk = ed25519_dalek::VerifyingKey::from_bytes(&signer.public_key_bytes()).unwrap();
    let sig = ed25519_dalek::Signature::from_bytes(&calls[0].sig);
    vk.verify(&calls[0].body, &sig).unwrap();
}

#[tokio::test]
async fn snapshot_status_get_proxies_the_miner_json_verbatim() {
    let signer = test_signer();
    // The mock returns the miner's status JSON; the relay must pass it
    // back unchanged (vali's `poll_snapshot` parses `{"status": …}`).
    let mock = Arc::new(MockMinerForward::with_response(
        200,
        br#"{"status":"running"}"#.to_vec(),
    ));
    let (status, body) = get_relay(
        Arc::clone(&signer),
        Arc::clone(&mock) as Arc<dyn MinerForward>,
        "/v1/relay/tenant-x/snapshot",
        MINER_ADDR,
    )
    .await;
    assert_eq!(status, 200);
    assert_eq!(body, br#"{"status":"running"}"#);

    // The forwarder's status method was invoked for the right vm + addr.
    let scalls = mock.status_calls();
    assert_eq!(scalls.len(), 1);
    assert_eq!(scalls[0].target_addr.to_string(), MINER_ADDR);
    assert_eq!(scalls[0].vm_id, "tenant-x");
}

#[tokio::test]
async fn snapshot_status_404_from_the_miner_is_relayed() {
    let signer = test_signer();
    // A miner with no recorded migration replies 404; the relay surfaces
    // it so vali's poll can retry.
    let mock = Arc::new(MockMinerForward::with_response(
        404,
        b"no-migration".to_vec(),
    ));
    let (status, _body) = get_relay(
        signer,
        mock as Arc<dyn MinerForward>,
        "/v1/relay/tenant-x/snapshot",
        MINER_ADDR,
    )
    .await;
    assert_eq!(status, 404);
}

#[tokio::test]
async fn a_non_cgnat_miner_addr_is_rejected_without_forwarding() {
    let signer = test_signer();
    let mock = Arc::new(MockMinerForward::with_response(200, Vec::new()));
    let json = r#"{"node_id":"miner-a","miner_addr":"8.8.8.8:9700"}"#;
    let (status, body) = post_relay(
        signer,
        Arc::clone(&mock) as Arc<dyn MinerForward>,
        "/v1/relay/tenant-x/quiesce",
        json,
    )
    .await;
    assert_eq!(status, 400);
    assert_eq!(body, b"cgnat-violation");
    // The forwarder was never invoked — the bad address never dialed.
    assert!(mock.calls().is_empty());
}

#[tokio::test]
async fn a_malformed_vm_id_is_rejected_without_forwarding() {
    let signer = test_signer();
    let mock = Arc::new(MockMinerForward::with_response(200, Vec::new()));
    let json = format!(r#"{{"node_id":"miner-a","miner_addr":"{MINER_ADDR}"}}"#);
    let (status, body) = post_relay(
        signer,
        Arc::clone(&mock) as Arc<dyn MinerForward>,
        "/v1/relay/Bad_Id/quiesce",
        &json,
    )
    .await;
    assert_eq!(status, 400);
    assert_eq!(body, b"bad-vm-id");
    assert!(mock.calls().is_empty());
}

#[tokio::test]
async fn an_unknown_relay_body_field_is_rejected() {
    let signer = test_signer();
    let mock = Arc::new(MockMinerForward::with_response(200, Vec::new()));
    // `deny_unknown_fields` — an extra field is rejected before forward.
    let json = format!(r#"{{"node_id":"miner-a","miner_addr":"{MINER_ADDR}","extra":"x"}}"#);
    let (status, body) = post_relay(
        signer,
        Arc::clone(&mock) as Arc<dyn MinerForward>,
        "/v1/relay/tenant-x/quiesce",
        &json,
    )
    .await;
    assert_eq!(status, 400);
    assert_eq!(body, b"bad-relay-body");
    assert!(mock.calls().is_empty());
}

#[tokio::test]
async fn a_forwarder_transport_failure_maps_to_502() {
    let signer = test_signer();
    let mock = Arc::new(MockMinerForward::with_error(MinerForwardError::Transport));
    let json = format!(r#"{{"node_id":"miner-a","miner_addr":"{MINER_ADDR}"}}"#);
    let (status, _body) = post_relay(
        signer,
        mock as Arc<dyn MinerForward>,
        "/v1/relay/tenant-x/quiesce",
        &json,
    )
    .await;
    assert_eq!(status, 502);
}

// ─── §25 M2 source-ack relay tests ──────────────────────────────────

#[tokio::test]
async fn source_ack_get_proxies_the_miner_signed_ack_json_verbatim() {
    let signer = test_signer();
    // The mock returns the miner's surfaced ack JSON; the relay must pass
    // it back unchanged (vali's `poll_source_ack` parses `signed_ack_hex`).
    let mock = Arc::new(MockMinerForward::with_response(
        200,
        br#"{"signed_ack_hex":"deadbeef"}"#.to_vec(),
    ));
    let (status, body) = get_relay(
        Arc::clone(&signer),
        Arc::clone(&mock) as Arc<dyn MinerForward>,
        "/v1/relay/tenant-x/source-ack",
        MINER_ADDR,
    )
    .await;
    assert_eq!(status, 200);
    assert_eq!(body, br#"{"signed_ack_hex":"deadbeef"}"#);

    // The forwarder's source-ack method was invoked for the right vm+addr
    // (recorded into the shared status-calls vec by the mock).
    let scalls = mock.status_calls();
    assert_eq!(scalls.len(), 1);
    assert_eq!(scalls[0].target_addr.to_string(), MINER_ADDR);
    assert_eq!(scalls[0].vm_id, "tenant-x");
}

#[tokio::test]
async fn source_ack_404_from_the_miner_is_relayed_so_vali_keeps_waiting() {
    let signer = test_signer();
    // The guest has not produced an ack yet ⇒ miner 404s ⇒ relay surfaces
    // it ⇒ vali's poll keeps waiting (fail-closed: NO dest activation
    // until a verified ack is surfaced).
    let mock = Arc::new(MockMinerForward::with_response(
        404,
        b"no-source-ack".to_vec(),
    ));
    let (status, _body) = get_relay(
        signer,
        mock as Arc<dyn MinerForward>,
        "/v1/relay/tenant-x/source-ack",
        MINER_ADDR,
    )
    .await;
    assert_eq!(status, 404);
}

#[tokio::test]
async fn source_ack_without_a_target_addr_header_is_rejected() {
    let signer = test_signer();
    let mock = Arc::new(MockMinerForward::with_response(200, Vec::new()));
    // No `x-hippius-target-addr` header ⇒ the relay cannot route ⇒ 400,
    // never dials.
    let (status, _body) = get_relay(
        signer,
        Arc::clone(&mock) as Arc<dyn MinerForward>,
        "/v1/relay/tenant-x/source-ack",
        "",
    )
    .await;
    assert_eq!(status, 400);
    assert!(mock.status_calls().is_empty());
}

// ─── reboot-recovery domain-state relay tests ──────────────────────

#[tokio::test]
async fn domain_state_get_proxies_the_miner_running_json_verbatim() {
    let signer = test_signer();
    // The mock returns the miner's liveness JSON; the relay must pass it
    // back unchanged.
    let mock = Arc::new(MockMinerForward::with_response(
        200,
        br#"{"running":true}"#.to_vec(),
    ));
    let (status, body) = get_relay(
        Arc::clone(&signer),
        Arc::clone(&mock) as Arc<dyn MinerForward>,
        "/v1/relay/tenant-x/domain-state",
        MINER_ADDR,
    )
    .await;
    assert_eq!(status, 200);
    assert_eq!(body, br#"{"running":true}"#);

    // The forwarder's domain-state method was invoked for the right
    // vm+addr (recorded into the shared status-calls vec by the mock).
    let scalls = mock.status_calls();
    assert_eq!(scalls.len(), 1);
    assert_eq!(scalls[0].target_addr.to_string(), MINER_ADDR);
    assert_eq!(scalls[0].vm_id, "tenant-x");
}

#[tokio::test]
async fn domain_state_503_from_the_miner_is_relayed() {
    let signer = test_signer();
    // The miner's own libvirt is unreachable ⇒ 503; the relay must
    // surface that rather than fold it into a definite answer.
    let mock = Arc::new(MockMinerForward::with_response(
        503,
        b"libvirt-unreachable".to_vec(),
    ));
    let (status, _body) = get_relay(
        signer,
        mock as Arc<dyn MinerForward>,
        "/v1/relay/tenant-x/domain-state",
        MINER_ADDR,
    )
    .await;
    assert_eq!(status, 503);
}

#[tokio::test]
async fn domain_state_without_a_target_addr_header_is_rejected() {
    let signer = test_signer();
    let mock = Arc::new(MockMinerForward::with_response(200, Vec::new()));
    // No `x-hippius-target-addr` header ⇒ the relay cannot route ⇒ 400,
    // never dials.
    let (status, _body) = get_relay(
        signer,
        Arc::clone(&mock) as Arc<dyn MinerForward>,
        "/v1/relay/tenant-x/domain-state",
        "",
    )
    .await;
    assert_eq!(status, 400);
    assert!(mock.status_calls().is_empty());
}

// ─── backup status relay tests ─────────────────────────────────────

#[tokio::test]
async fn backup_status_get_proxies_the_miner_json_verbatim() {
    let signer = test_signer();
    let json = br#"{"vm_id":"tenant-x","bitmap_present":true,"boot_counter":4,"run":null}"#;
    let mock = Arc::new(MockMinerForward::with_response(200, json.to_vec()));
    let (status, body) = get_relay(
        Arc::clone(&signer),
        Arc::clone(&mock) as Arc<dyn MinerForward>,
        "/v1/relay/tenant-x/backup",
        MINER_ADDR,
    )
    .await;
    assert_eq!(status, 200);
    assert_eq!(body, json.to_vec());
    let scalls = mock.status_calls();
    assert_eq!(scalls.len(), 1);
    assert_eq!(scalls[0].target_addr.to_string(), MINER_ADDR);
    assert_eq!(scalls[0].vm_id, "tenant-x");
}

#[tokio::test]
async fn backup_status_404_from_the_miner_is_relayed() {
    let signer = test_signer();
    let mock = Arc::new(MockMinerForward::with_response(404, b"no-domain".to_vec()));
    let (status, _body) = get_relay(
        signer,
        mock as Arc<dyn MinerForward>,
        "/v1/relay/tenant-x/backup",
        MINER_ADDR,
    )
    .await;
    assert_eq!(status, 404);
}

#[tokio::test]
async fn backup_status_without_a_target_addr_header_is_rejected() {
    let signer = test_signer();
    let mock = Arc::new(MockMinerForward::with_response(200, Vec::new()));
    let (status, _body) = get_relay(
        signer,
        Arc::clone(&mock) as Arc<dyn MinerForward>,
        "/v1/relay/tenant-x/backup",
        "",
    )
    .await;
    assert_eq!(status, 400);
    assert!(mock.status_calls().is_empty());
}

#[tokio::test]
async fn backup_status_rejects_a_bad_vm_id_before_dialing() {
    let signer = test_signer();
    let mock = Arc::new(MockMinerForward::with_response(200, Vec::new()));
    let (status, _body) = get_relay(
        signer,
        Arc::clone(&mock) as Arc<dyn MinerForward>,
        "/v1/relay/Tenant_X/backup",
        MINER_ADDR,
    )
    .await;
    assert_eq!(status, 400);
    assert!(mock.status_calls().is_empty());
}

#[tokio::test]
async fn a_relay_body_past_its_own_cap_is_shed_before_signing() {
    // The inner router's cap is sized for multipart orders (2 MiB); the
    // relay routes keep their own `MAX_RELAY_BODY`.
    use hippius_edge_gateway::listeners::relay_router::MAX_RELAY_BODY;
    let mock = Arc::new(MockMinerForward::with_response(200, Vec::new()));
    let pad = "x".repeat(MAX_RELAY_BODY);
    let json = format!(r#"{{"node_id":"miner-a","miner_addr":"{MINER_ADDR}","pad":"{pad}"}}"#);
    let (status, _) = post_relay(
        test_signer(),
        Arc::clone(&mock) as Arc<dyn MinerForward>,
        "/v1/relay/tenant-x/quiesce",
        &json,
    )
    .await;
    assert_eq!(status, 413);
    assert!(mock.calls().is_empty());
}

// ─── restore status relay tests ────────────────────────────────────

#[tokio::test]
async fn restore_status_get_proxies_the_miner_json_verbatim() {
    let signer = test_signer();
    let json = br#"{"vm_id":"tenant-x","restore_id":"0123456789abcdef0123456789abcdef","op":"stage","state":"staging","bytes_done":1,"bytes_total":2,"reason":null,"swapped":false,"pre_restore_present":false,"domain_live":true}"#;
    let mock = Arc::new(MockMinerForward::with_response(200, json.to_vec()));
    let (status, body) = get_relay(
        Arc::clone(&signer),
        Arc::clone(&mock) as Arc<dyn MinerForward>,
        "/v1/relay/tenant-x/restore",
        MINER_ADDR,
    )
    .await;
    assert_eq!(status, 200);
    assert_eq!(body, json.to_vec());
    let scalls = mock.status_calls();
    assert_eq!(scalls.len(), 1);
    assert_eq!(scalls[0].target_addr.to_string(), MINER_ADDR);
    assert_eq!(scalls[0].vm_id, "tenant-x");
}

#[tokio::test]
async fn restore_status_404_from_the_miner_is_relayed() {
    let signer = test_signer();
    let mock = Arc::new(MockMinerForward::with_response(404, b"no-restore".to_vec()));
    let (status, _body) = get_relay(
        signer,
        mock as Arc<dyn MinerForward>,
        "/v1/relay/tenant-x/restore",
        MINER_ADDR,
    )
    .await;
    assert_eq!(status, 404);
}

#[tokio::test]
async fn restore_status_rejects_a_bad_vm_id_or_target_before_dialing() {
    for (path, addr) in [
        ("/v1/relay/Tenant_X/restore", MINER_ADDR),
        ("/v1/relay/tenant-x/restore", ""),
    ] {
        let mock = Arc::new(MockMinerForward::with_response(200, Vec::new()));
        let (status, _body) = get_relay(
            test_signer(),
            Arc::clone(&mock) as Arc<dyn MinerForward>,
            path,
            addr,
        )
        .await;
        assert_eq!(status, 400, "{path} {addr:?}");
        assert!(mock.status_calls().is_empty());
    }
}
