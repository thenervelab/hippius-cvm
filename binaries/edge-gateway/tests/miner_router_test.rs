//! PR-H8 — miner envelope router integration tests.
//!
//! Drives the production [`build_router`] axum router (the
//! `crate::listeners::miner_router` module) as a `tower::Service`,
//! exercising the full per-request pipeline: body-size cap → wire
//! gate → forward → audit → response relay.
//!
//! Coverage:
//!
//! - **KAT routing** — a valid `KbsRequest` body posted to the
//!   `kbs-request` route passes the wire gate and is forwarded
//!   through the `forward_kbs_request` method (right endpoint), and
//!   the upstream body is relayed back verbatim.
//! - **Wrong kind** — a `ServedReceipt`-shaped body on the
//!   `kbs-request` route fails the typed decode → `400`, no forward.
//! - **Over the size cap** — a body past `MAX_ENVELOPE_BYTES` is
//!   `413` (axum's `DefaultBodyLimit`), before any decode, no forward.
//! - **Bad / non-canonical CBOR** — garbage bytes → `400`, no forward.
//! - **Forward upstream non-2xx** → Edge returns `502` and audits a
//!   `forward-upstream-status` shed.
//! - **Audit completeness** — every transaction emits exactly one
//!   telemetry record (relayed or shed).
//! - **End-to-end over real mTLS** — a happy-path envelope driven
//!   through `run_miner_listener` over a loopback mTLS HTTP/2 stream.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

#[path = "mtls_test_helpers.rs"]
mod helpers;

use axum::body::Body;
use axum::extract::Extension;
use ciborium::value::Value;
use helpers::TestPki;
use hippius_edge_gateway::mtls::{CertPaths, MtlsAcceptor, MtlsRuntime, PeerId};
use hippius_edge_gateway::telemetry::{TelemetryEvent, TelemetrySink};
use hippius_edge_gateway::{
    build_router, run_miner_listener, ForwardClient, ForwardError, MessageKind, MinerRouterState,
    MockForwardClient, PerSourceRateLimiter, RateLimitConfig, MAX_ENVELOPE_BYTES,
};

/// A generous per-source limiter (default budget: 50/s, burst 100) — the
/// router tests here assert routing / audit behaviour, never the rate
/// limit, so nothing they send is ever shed.
fn test_limiter() -> Arc<PerSourceRateLimiter> {
    Arc::new(PerSourceRateLimiter::new(
        RateLimitConfig::default(),
        std::time::Duration::from_secs(3600),
        1024,
    ))
}
use hippius_types::cbor::to_canonical_vec;
use http_body_util::BodyExt;
use std::sync::{Arc, Mutex};
use tower::ServiceExt;

// ─── recording telemetry sink ───────────────────────────────────────

/// A [`TelemetrySink`] that records every [`TelemetryEvent`] so a test
/// can assert the §15 audit chain — one record per transaction, with
/// the right shed flag + classifier.
#[derive(Default)]
struct RecordingTelemetry {
    events: Mutex<Vec<TelemetryEvent>>,
}

impl RecordingTelemetry {
    fn events(&self) -> Vec<TelemetryEvent> {
        self.events.lock().expect("telemetry lock").clone()
    }
}

impl TelemetrySink for RecordingTelemetry {
    fn record(&self, event: TelemetryEvent) {
        self.events.lock().expect("telemetry lock").push(event);
    }
}

// ─── envelope-body builders ─────────────────────────────────────────

/// Canonical-CBOR `KbsReleaseRequest` body — `{cose_ticket, kbs_nonce,
/// snp_report}`, the shape the `kbs-request` route's wire gate
/// accepts. `kbs_nonce` is the §20-mandated 32 bytes.
fn kbs_request_body() -> Vec<u8> {
    let v = Value::Map(vec![
        (
            Value::Text("cose_ticket".into()),
            Value::Bytes(vec![0xAA; 16]),
        ),
        (
            Value::Text("kbs_nonce".into()),
            Value::Bytes(vec![0xBB; 32]),
        ),
        (
            Value::Text("snp_report".into()),
            Value::Bytes(vec![0xCC; 64]),
        ),
    ]);
    to_canonical_vec(&v).unwrap()
}

/// Canonical-CBOR `{body, sig}` — the shape every `Signed*` kind
/// (`ServedReceipt`, `ServedAggregate`, `StoppedAck`) shares.
fn signed_envelope_body() -> Vec<u8> {
    let v = Value::Map(vec![
        (Value::Text("body".into()), Value::Bytes(vec![0u8; 16])),
        (Value::Text("sig".into()), Value::Bytes(vec![0u8; 64])),
    ]);
    to_canonical_vec(&v).unwrap()
}

// ─── router-as-Service driver ───────────────────────────────────────

/// Build the production router + record sink, POST `body` to `path`,
/// and return `(status, response_body, telemetry_events)`.
async fn post(
    forward: Arc<dyn ForwardClient>,
    path: &str,
    body: Vec<u8>,
) -> (u16, Vec<u8>, Vec<TelemetryEvent>) {
    let telemetry = Arc::new(RecordingTelemetry::default());
    let telemetry_sink: Arc<dyn TelemetrySink + Send + Sync> = telemetry.clone();
    let state = MinerRouterState::new(forward, telemetry_sink, test_limiter());

    // The production router. The handshake-derived `PeerId` is layered
    // on as a request `Extension` — the same way `miner_listener`
    // injects it per-connection.
    let router = build_router(state).layer(Extension(PeerId::new("hippius-miner:kat")));

    let request = axum::http::Request::builder()
        .method("POST")
        .uri(path)
        .header("content-type", "application/cbor")
        .body(Body::from(body))
        .unwrap();
    let response = router.oneshot(request).await.unwrap();
    let status = response.status().as_u16();
    let bytes = response
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes()
        .to_vec();
    (status, bytes, telemetry.events())
}

// ─── KAT routing ────────────────────────────────────────────────────

#[tokio::test]
async fn valid_kbs_request_routes_to_kbs_and_relays_response() {
    // The upstream KBS answers 200 with an opaque (HPKE-wrapped)
    // release body — the Edge must relay it back verbatim.
    let upstream_body = b"opaque-kbs-release-bytes".to_vec();
    let mock = Arc::new(MockForwardClient::with_response(200, upstream_body.clone()));
    let (status, body, events) =
        post(mock.clone(), "/v1/edge/kbs-request", kbs_request_body()).await;

    assert_eq!(status, 200);
    assert_eq!(body, upstream_body, "the KBS response must relay verbatim");

    // Routed through the KbsRequest method — never a vali method.
    let calls = mock.calls();
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].kind, MessageKind::KbsRequest);
    assert_eq!(calls[0].body, kbs_request_body(), "body relayed verbatim");

    // Exactly one audit record, relayed (not shed).
    assert_eq!(events.len(), 1);
    assert!(!events[0].shed);
    assert_eq!(events[0].message_kind, MessageKind::KbsRequest);
    assert_eq!(events[0].bytes_out as usize, upstream_body.len());
}

#[tokio::test]
async fn served_receipt_routes_to_vali_served_receipt_method() {
    let mock = Arc::new(MockForwardClient::with_response(202, Vec::new()));
    let (status, _body, events) = post(
        mock.clone(),
        "/v1/edge/served-receipt",
        signed_envelope_body(),
    )
    .await;

    assert_eq!(status, 202, "the upstream status relays through");
    let calls = mock.calls();
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].kind, MessageKind::ServedReceipt);
    assert_eq!(events.len(), 1);
    assert!(!events[0].shed);
}

#[tokio::test]
async fn served_aggregate_stopped_ack_and_heartbeat_route_to_their_methods() {
    for (path, kind) in [
        ("/v1/edge/served-aggregate", MessageKind::ServedAggregate),
        ("/v1/edge/stopped-ack", MessageKind::StoppedAck),
        // PR-MA-6: the heartbeat route relays via `forward_heartbeat`.
        ("/v1/edge/heartbeat", MessageKind::Heartbeat),
        // The graceful-exit route relays via `forward_graceful_exit`.
        ("/v1/edge/graceful-exit", MessageKind::GracefulExit),
    ] {
        let mock = Arc::new(MockForwardClient::with_response(200, Vec::new()));
        let (status, _b, events) = post(mock.clone(), path, signed_envelope_body()).await;
        assert_eq!(status, 200, "path {path}");
        let calls = mock.calls();
        assert_eq!(calls.len(), 1, "path {path}");
        assert_eq!(calls[0].kind, kind, "path {path}");
        assert_eq!(events.len(), 1, "path {path}");
    }
}

#[tokio::test]
async fn heartbeat_body_relays_verbatim_to_vali_and_audits_one_record() {
    // PR-MA-6: a valid `SignedMinerHeartbeat`-shaped `{body, sig}`
    // envelope posted to the heartbeat route is relayed to vali
    // verbatim and emits exactly one §15 audit record.
    let mock = Arc::new(MockForwardClient::with_response(202, Vec::new()));
    let (status, _body, events) =
        post(mock.clone(), "/v1/edge/heartbeat", signed_envelope_body()).await;

    assert_eq!(status, 202, "the vali ingest status relays through");
    let calls = mock.calls();
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].kind, MessageKind::Heartbeat);
    assert_eq!(
        calls[0].body,
        signed_envelope_body(),
        "the heartbeat body must relay verbatim — opaque relay"
    );
    assert_eq!(events.len(), 1);
    assert!(!events[0].shed);
    assert_eq!(events[0].message_kind, MessageKind::Heartbeat);
}

#[tokio::test]
async fn healthz_returns_200_and_does_not_forward() {
    let mock = Arc::new(MockForwardClient::with_response(200, Vec::new()));
    let telemetry = Arc::new(RecordingTelemetry::default());
    let telemetry_sink: Arc<dyn TelemetrySink + Send + Sync> = telemetry.clone();
    let state = MinerRouterState::new(mock.clone(), telemetry_sink, test_limiter());
    let router = build_router(state).layer(Extension(PeerId::new("hippius-miner:probe")));

    let request = axum::http::Request::builder()
        .method("GET")
        .uri("/healthz")
        .body(Body::empty())
        .unwrap();
    let response = router.oneshot(request).await.unwrap();
    assert_eq!(response.status().as_u16(), 200);
    // A liveness probe is not an envelope — no forward, no audit.
    assert!(mock.calls().is_empty());
    assert!(telemetry.events().is_empty());
}

// ─── wrong-kind: route enforces its specific MessageKind ─────────────

#[tokio::test]
async fn served_receipt_body_on_kbs_request_route_is_rejected_400() {
    // A `{body, sig}` (ServedReceipt-shaped) body posted to the
    // KbsRequest route. The route fixes `kind = KbsRequest`, so the
    // wire gate runs the `KbsReleaseRequest` typed decode — which
    // rejects the wrong shape. Edge returns 400; nothing is forwarded.
    let mock = Arc::new(MockForwardClient::with_response(200, Vec::new()));
    let (status, _body, events) =
        post(mock.clone(), "/v1/edge/kbs-request", signed_envelope_body()).await;

    assert_eq!(status, 400);
    assert!(
        mock.calls().is_empty(),
        "a wrong-kind body must not forward"
    );
    // One shed audit record at the wire gate.
    assert_eq!(events.len(), 1);
    assert!(events[0].shed);
    assert_eq!(events[0].shed_reason, Some("schema-invalid"));
}

// ─── over the size cap → 413 ────────────────────────────────────────

#[tokio::test]
async fn body_over_the_size_cap_is_rejected_413_before_decode() {
    // One byte past `MAX_ENVELOPE_BYTES`. axum's `DefaultBodyLimit`
    // layer rejects it with 413 before the handler — so before any
    // CBOR decode / recursion-bounded canonical check runs.
    let mock = Arc::new(MockForwardClient::with_response(200, Vec::new()));
    let oversized = vec![0u8; MAX_ENVELOPE_BYTES + 1];
    let (status, _body, _events) = post(mock.clone(), "/v1/edge/served-receipt", oversized).await;

    assert_eq!(status, 413);
    assert!(
        mock.calls().is_empty(),
        "an oversized body must not be forwarded"
    );
}

// ─── bad / non-canonical CBOR → 400 ─────────────────────────────────

#[tokio::test]
async fn garbage_non_cbor_body_is_rejected_400() {
    let mock = Arc::new(MockForwardClient::with_response(200, Vec::new()));
    let (status, _body, events) = post(
        mock.clone(),
        "/v1/edge/served-receipt",
        vec![0xff, 0xff, 0xff],
    )
    .await;

    assert_eq!(status, 400);
    assert!(mock.calls().is_empty());
    assert_eq!(events.len(), 1);
    assert!(events[0].shed);
}

#[tokio::test]
async fn non_canonical_cbor_body_is_rejected_400() {
    // A structurally-valid but NON-canonical CBOR map: RFC 8949
    // §4.2.1 sorts map keys by encoded length then bytewise, so the
    // canonical order is `sig` (4-byte encoding) before `body`
    // (5-byte encoding). Emitting `body` first is non-canonical and
    // must trip the canonical-CBOR gate → 400, no forward.
    let mut noncanon = Vec::new();
    let v = Value::Map(vec![
        (Value::Text("body".into()), Value::Bytes(vec![0u8; 16])),
        (Value::Text("sig".into()), Value::Bytes(vec![0u8; 64])),
    ]);
    ciborium::ser::into_writer(&v, &mut noncanon).unwrap();
    let mock = Arc::new(MockForwardClient::with_response(200, Vec::new()));
    let (status, _b, events) = post(mock.clone(), "/v1/edge/served-receipt", noncanon).await;

    assert_eq!(status, 400);
    assert!(mock.calls().is_empty());
    assert_eq!(events.len(), 1);
    assert!(events[0].shed);
}

#[tokio::test]
async fn empty_body_is_rejected_400() {
    let mock = Arc::new(MockForwardClient::with_response(200, Vec::new()));
    let (status, _b, events) = post(mock.clone(), "/v1/edge/served-receipt", Vec::new()).await;
    assert_eq!(status, 400);
    assert!(mock.calls().is_empty());
    assert_eq!(events.len(), 1);
    assert!(events[0].shed);
}

// ─── slow-loris: a stalled request body is bounded, not parked ──────

/// An `http_body::Body` that never yields a frame and never ends —
/// models a peer that opens a stream, declares a body, then drips
/// nothing. `DefaultBodyLimit` caps SIZE, never TIME; the production
/// `RequestBodyTimeoutLayer` caps body-ingestion TIME, so the `Bytes`
/// extractor errors out instead of awaiting this forever.
struct PendingBody;

impl http_body::Body for PendingBody {
    type Data = bytes::Bytes;
    type Error = std::convert::Infallible;

    fn poll_frame(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Result<http_body::Frame<Self::Data>, Self::Error>>> {
        // Never ready — the body never completes.
        std::task::Poll::Pending
    }
}

#[tokio::test]
async fn a_stalled_request_body_is_bounded_not_parked() {
    // PR-H8 round-2: the production miner listener applies
    // `RequestBodyTimeoutLayer` (bounds only body INGESTION, not the
    // handler or the forward — so a slow forward is never cut into an
    // un-audited 408). Here at a short 300 ms so the test is fast.
    //
    // A request whose body never arrives must be REJECTED, not parked:
    // `RequestBodyTimeoutLayer` makes the body stream error after the
    // timeout, the `Bytes` extractor fails, and axum answers a 4xx.
    // Crucially the request never became a complete "envelope", so no
    // §15 audit record is owed — nothing reached the wire gate or the
    // forward client.
    use std::time::Duration;
    use tower_http::timeout::RequestBodyTimeoutLayer;

    let mock = Arc::new(MockForwardClient::with_response(200, Vec::new()));
    let telemetry = Arc::new(RecordingTelemetry::default());
    let telemetry_sink: Arc<dyn TelemetrySink + Send + Sync> = telemetry.clone();
    let state = MinerRouterState::new(mock.clone(), telemetry_sink, test_limiter());
    let router = build_router(state)
        .layer(RequestBodyTimeoutLayer::new(Duration::from_millis(300)))
        .layer(Extension(PeerId::new("hippius-miner:slow")));

    let request = axum::http::Request::builder()
        .method("POST")
        .uri("/v1/edge/served-receipt")
        .header("content-type", "application/cbor")
        .body(Body::new(PendingBody))
        .unwrap();

    // A generous outer bound: if the body timeout did NOT fire, this
    // `oneshot` would never resolve and the `timeout` would trip
    // instead — failing the test loudly rather than hanging it.
    let response = tokio::time::timeout(Duration::from_secs(5), router.oneshot(request))
        .await
        .expect("the body timeout must fire — the request must not park")
        .unwrap();
    // The body never completed → the `Bytes` extractor failed → a 4xx
    // rejection (axum maps a failed body buffer to 400). The point is
    // it is REJECTED and bounded, never parked.
    assert!(
        response.status().is_client_error(),
        "a stalled body must be rejected with a 4xx, got {}",
        response.status()
    );
    // A body that never fully arrived never became an envelope —
    // nothing reached the wire gate or the forward client, and no
    // §15 audit record is owed.
    assert!(mock.calls().is_empty());
    assert!(telemetry.events().is_empty());
}

#[tokio::test]
async fn a_fully_arrived_envelope_with_a_slow_forward_is_still_relayed_and_audited() {
    // PR-H8 round-2 invariant: the body-only timeout must NOT cut the
    // forward. A valid envelope that fully arrived, then takes a long
    // time to forward, must STILL be relayed and emit its §15 audit
    // record — never become an un-audited 408. The forward here waits
    // 600 ms (well past the 300 ms body timeout used elsewhere) and
    // the request must still complete normally.
    use std::time::Duration;
    use tower_http::timeout::RequestBodyTimeoutLayer;

    let mock = Arc::new(MockForwardClient::with_delayed_response(
        200,
        b"slow-but-delivered".to_vec(),
        Duration::from_millis(600),
    ));
    let telemetry = Arc::new(RecordingTelemetry::default());
    let telemetry_sink: Arc<dyn TelemetrySink + Send + Sync> = telemetry.clone();
    let state = MinerRouterState::new(mock.clone(), telemetry_sink, test_limiter());
    // Same body-only timeout the production listener uses, deliberately
    // SHORTER (200 ms) than the 600 ms forward — proving the body
    // timeout does not govern the forward.
    let router = build_router(state)
        .layer(RequestBodyTimeoutLayer::new(Duration::from_millis(200)))
        .layer(Extension(PeerId::new("hippius-miner:slowfwd")));

    let request = axum::http::Request::builder()
        .method("POST")
        .uri("/v1/edge/served-receipt")
        .header("content-type", "application/cbor")
        .body(Body::from(signed_envelope_body()))
        .unwrap();
    let response = router.oneshot(request).await.unwrap();

    // The slow forward completed — 200 relayed, NOT a 408.
    assert_eq!(response.status().as_u16(), 200);
    assert_eq!(mock.calls().len(), 1);
    // Exactly one §15 audit record, and it is the relayed (not shed)
    // outcome — the slow forward was audited, never cut short.
    assert_eq!(telemetry.events().len(), 1);
    assert!(!telemetry.events()[0].shed);
}

// ─── forward failure → 502 + audited forward failure ────────────────

#[tokio::test]
async fn forward_upstream_500_makes_edge_return_502_and_audit_a_failure() {
    // The wire gate passes (valid body) but the upstream answers 500.
    // Edge maps the non-2xx to a miner-facing 502 and audits a shed.
    let mock = Arc::new(MockForwardClient::with_response(
        500,
        b"inner-error".to_vec(),
    ));
    let (status, body, events) = post(
        mock.clone(),
        "/v1/edge/served-receipt",
        signed_envelope_body(),
    )
    .await;

    assert_eq!(status, 502);
    assert!(
        body.is_empty(),
        "an inner-plane error body must NOT relay to the miner"
    );
    // Forward WAS attempted (the body passed the gate).
    assert_eq!(mock.calls().len(), 1);
    // One audit record — a shed, classified as a forward failure.
    assert_eq!(events.len(), 1);
    assert!(events[0].shed);
    assert_eq!(events[0].shed_reason, Some("forward-upstream-status"));
}

#[tokio::test]
async fn forward_transport_failure_makes_edge_return_502() {
    // The forward client itself fails (DNS / connect / TLS / timeout)
    // — a transport error, distinct from an upstream non-2xx. Still
    // 502 to the miner, still one audited shed.
    let mock = Arc::new(MockForwardClient::with_error(ForwardError::Transport));
    let (status, _body, events) = post(
        mock.clone(),
        "/v1/edge/served-receipt",
        signed_envelope_body(),
    )
    .await;

    assert_eq!(status, 502);
    assert_eq!(mock.calls().len(), 1);
    assert_eq!(events.len(), 1);
    assert!(events[0].shed);
    assert_eq!(events[0].shed_reason, Some("forward-transport"));
}

// ─── end-to-end over a real mTLS HTTP/2 stream ──────────────────────

#[tokio::test]
async fn end_to_end_envelope_relays_over_a_real_mtls_stream() {
    use hyper_util::rt::{TokioExecutor, TokioIo};
    use tokio::net::{TcpListener, TcpStream};
    use tokio::sync::watch;

    let pki = TestPki::mint();

    // Production mTLS acceptor (no CRL — revocation is mtls_integration
    // .rs's concern).
    let acceptor = {
        let paths = CertPaths {
            ca: pki.ca_path.clone(),
            cert: pki.server_cert_path.clone(),
            key: pki.server_key_path.clone(),
            crl: None,
        };
        Arc::new(MtlsAcceptor::new(MtlsRuntime::load(paths).unwrap()))
    };

    // The router state: a mock forward client returning a known body.
    let upstream = b"e2e-relayed-kbs-body".to_vec();
    let mock = Arc::new(MockForwardClient::with_response(200, upstream.clone()));
    let telemetry = Arc::new(RecordingTelemetry::default());
    let telemetry_sink: Arc<dyn TelemetrySink + Send + Sync> = telemetry.clone();
    let mock_dyn: Arc<dyn ForwardClient> = mock.clone();
    let state = MinerRouterState::new(mock_dyn, telemetry_sink, test_limiter());

    // The production listener loop.
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (cancel_tx, cancel_rx) = watch::channel(false);
    let loop_task = tokio::spawn(run_miner_listener(listener, acceptor, state, cancel_rx));

    // Client side: a TLS-1.3 mTLS connector presenting the valid cert.
    let connector = {
        use rustls::pki_types::{CertificateDer, PrivateKeyDer};
        use rustls::{ClientConfig, RootCertStore};
        let mut roots = RootCertStore::empty();
        for entry in rustls_pemfile::certs(&mut std::io::Cursor::new(
            std::fs::read(&pki.ca_path).unwrap(),
        )) {
            roots.add(entry.unwrap()).unwrap();
        }
        let chain: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut std::io::Cursor::new(
            pki.valid_client_cert_pem.as_bytes(),
        ))
        .filter_map(Result::ok)
        .collect();
        let key: PrivateKeyDer<'static> = rustls_pemfile::private_key(&mut std::io::Cursor::new(
            pki.valid_client_key_pem.as_bytes(),
        ))
        .unwrap()
        .unwrap();
        let mut cfg = ClientConfig::builder()
            .with_root_certificates(roots)
            .with_client_auth_cert(chain, key)
            .unwrap();
        // ALPN h2 — the wire is HTTP/2 over mTLS.
        cfg.alpn_protocols = vec![b"h2".to_vec()];
        tokio_rustls::TlsConnector::from(Arc::new(cfg))
    };

    let tcp = TcpStream::connect(addr).await.unwrap();
    let sni = rustls::pki_types::ServerName::try_from("edge.test").unwrap();
    let tls = connector.connect(sni, tcp).await.expect("mTLS handshake");

    // Drive an HTTP/2 request over the mTLS stream.
    let (mut sender, conn) =
        hyper::client::conn::http2::handshake(TokioExecutor::new(), TokioIo::new(tls))
            .await
            .expect("h2 handshake");
    tokio::spawn(async move {
        let _ = conn.await;
    });

    let request = hyper::Request::builder()
        .method("POST")
        .uri("/v1/edge/kbs-request")
        .header("content-type", "application/cbor")
        .body(http_body_util::Full::new(bytes::Bytes::from(
            kbs_request_body(),
        )))
        .unwrap();
    let response = sender.send_request(request).await.expect("h2 request");
    assert_eq!(response.status().as_u16(), 200);
    let body = response
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes()
        .to_vec();
    assert_eq!(body, upstream, "the KBS body must relay back over mTLS");

    // The forward client saw exactly the posted envelope body.
    let calls = mock.calls();
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].kind, MessageKind::KbsRequest);
    assert_eq!(calls[0].body, kbs_request_body());

    // One audit record for the transaction.
    assert_eq!(telemetry.events().len(), 1);
    assert!(!telemetry.events()[0].shed);

    cancel_tx.send(true).unwrap();
    let _ = tokio::time::timeout(std::time::Duration::from_secs(5), loop_task).await;
}
