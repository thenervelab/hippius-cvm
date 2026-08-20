//! The miner-facing envelope router (PR-H8, §H phase 2).
//!
//! An [`axum`] [`Router`] served — by [`crate::miner_listener`] — over
//! every already-mTLS-terminated miner connection. The wire is
//! **HTTP/2 over mTLS** (LOCKED); routing is by URL path, one route
//! per Miner→Inner [`MessageKind`].
//!
//! ## Routes
//!
//! | Method · path                      | `MessageKind`     |
//! |------------------------------------|-------------------|
//! | `POST /v1/edge/kbs-request`        | `KbsRequest`      |
//! | `POST /v1/edge/served-receipt`     | `ServedReceipt`   |
//! | `POST /v1/edge/served-aggregate`   | `ServedAggregate` |
//! | `POST /v1/edge/stopped-ack`        | `StoppedAck`      |
//! | `POST /v1/edge/heartbeat`          | `Heartbeat`       |
//! | `POST /v1/edge/graceful-exit`      | `GracefulExit`    |
//! | `GET  /healthz`                    | — (liveness)      |
//!
//! There is **no `KbsResponse` route**: that kind is `Inner→Miner`
//! and never ingresses here (the direction gate would reject it
//! anyway).
//!
//! ## Per-request pipeline (each `POST` handler)
//!
//! 1. **Body-size cap** — [`DefaultBodyLimit::max`] with
//!    [`MAX_ENVELOPE_BYTES`] is layered on the router, so an oversized
//!    body is rejected `413` **before** the handler runs and therefore
//!    before any CBOR decode / recursion-bounded canonical check.
//! 2. **Envelope shell** — wrap the body bytes in a [`RawEnvelope`]
//!    tagged `Direction::MinerToInner` + the route's fixed
//!    `MessageKind`.
//! 3. **Wire gate** — [`validate::validate`] runs the §10 gate:
//!    canonical-CBOR, direction-vs-kind, `deny_unknown_fields` typed
//!    decode. A miner that posts e.g. a `ServedReceipt` body to the
//!    `kbs-request` route fails the typed decode → `400`.
//! 4. **Forward** — [`ForwardClient`] relays the validated body bytes
//!    verbatim to the inner endpoint for the kind (opaque relay).
//! 5. **Audit** — exactly one [`TelemetryEvent`] is emitted per
//!    transaction (relayed or shed), so §15 "every transaction is
//!    audited" holds: `{accepted+forwarded}` ⇒ `shed=false`,
//!    `{accepted+forward-failed}` and `{rejected-at-gate}` ⇒
//!    `shed=true` with the static classifier.
//! 6. **Relay the response** — the upstream body is returned to the
//!    miner verbatim with `content-type: application/cbor`.
//!
//! ## Logging discipline
//!
//! No envelope body is ever logged — only the peer, the kind, the
//! body length, and a static outcome classifier (the crate-wide
//! `&'static str` discipline; see [`crate::stages::log`]).

use crate::forward::{ForwardClient, ForwardError, ForwardResponse, MAX_ENVELOPE_BYTES};
use crate::mtls::PeerId;
use crate::pipeline::{Direction, EdgeError, MessageKind};
use crate::rate_limit::PerSourceRateLimiter;
use crate::stages::envelope::RawEnvelope;
use crate::stages::validate;
use crate::telemetry::{TelemetryEvent, TelemetrySink};
use axum::body::Bytes;
use axum::extract::{DefaultBodyLimit, Extension, State};
use axum::http::{header, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::Router;
use std::sync::Arc;

/// `content-type` of every envelope body — request and relayed
/// response alike. The §9 wire is canonical CBOR.
const CONTENT_TYPE_CBOR: &str = "application/cbor";

/// Shared state every router handler reads. Cheap to clone — both
/// fields are `Arc`s.
#[derive(Clone)]
pub struct MinerRouterState {
    /// In-cluster forward client. `Arc<dyn …>` so production
    /// (`ReqwestForwardClient`) and the test `MockForwardClient` share
    /// one handler code path.
    forward: Arc<dyn ForwardClient>,
    /// Telemetry sink — one [`TelemetryEvent`] per transaction lands
    /// here (§15 audit). `Arc<dyn …>` so tests can inject a
    /// `NoopTelemetry` and production the signing `TelemetryRecorder`.
    telemetry: Arc<dyn TelemetrySink + Send + Sync>,
    /// Per-source token-bucket rate limiter (audit M-ratelimit). Keyed
    /// on the mTLS-derived [`PeerId`], consulted once per request at the
    /// top of [`relay`]. Shared (same `Arc`) with the HA peer link so a
    /// shed is counted once and folded into the outgoing health beats.
    limiter: Arc<PerSourceRateLimiter>,
}

impl MinerRouterState {
    /// Build the shared state from a forward client + telemetry sink +
    /// the per-source rate limiter.
    pub fn new(
        forward: Arc<dyn ForwardClient>,
        telemetry: Arc<dyn TelemetrySink + Send + Sync>,
        limiter: Arc<PerSourceRateLimiter>,
    ) -> Self {
        Self {
            forward,
            telemetry,
            limiter,
        }
    }
}

/// Build the miner-facing [`Router`].
///
/// The returned router is **not** bound to a connection — every
/// accepted mTLS stream is served the *same* router by
/// [`crate::miner_listener`], with that connection's [`PeerId`]
/// injected as a request [`Extension`] per-connection (each
/// connection is one already-terminated mTLS peer).
///
/// The [`DefaultBodyLimit`] layer caps every request body at
/// [`MAX_ENVELOPE_BYTES`]; axum answers `413` itself for an oversized
/// body, before any handler — and so before any CBOR decode — runs.
pub fn build_router(state: MinerRouterState) -> Router {
    Router::new()
        .route("/v1/edge/kbs-request", post(handle_kbs_request))
        .route("/v1/edge/served-receipt", post(handle_served_receipt))
        .route("/v1/edge/served-aggregate", post(handle_served_aggregate))
        .route("/v1/edge/stopped-ack", post(handle_stopped_ack))
        .route("/v1/edge/heartbeat", post(handle_heartbeat))
        .route("/v1/edge/graceful-exit", post(handle_graceful_exit))
        .route("/v1/edge/vm-progress", post(handle_vm_progress))
        .route(
            "/v1/edge/host-attestor-challenge",
            post(handle_host_attestor_challenge),
        )
        .route(
            "/v1/edge/host-attestor-enroll",
            post(handle_host_attestor_enroll),
        )
        .route(
            "/v1/edge/host-attestor-beacon",
            post(handle_host_attestor_beacon),
        )
        .route(
            "/v1/edge/vm-live-attestation",
            post(handle_vm_live_attestation),
        )
        .route("/healthz", get(handle_healthz))
        // Body cap BEFORE any handler / decode (§10, PR-H3 size cap).
        .layer(DefaultBodyLimit::max(MAX_ENVELOPE_BYTES))
        .with_state(state)
}

/// `GET /healthz` — unauthenticated-at-the-app-layer liveness probe
/// (the mTLS handshake already authenticated the connection). Returns
/// a static `200`; no envelope work, nothing that could surface
/// secrets through an error.
async fn handle_healthz() -> StatusCode {
    StatusCode::OK
}

// ─── per-kind handlers ──────────────────────────────────────────────
//
// Each handler is a one-liner over `relay`, pinning its route's fixed
// `MessageKind`. The kind is NEVER read from the request — it is the
// route, so a miner cannot post one kind's body to another kind's
// route and have it accepted (the wire gate's typed decode rejects a
// shape mismatch; see `relay`).

/// `POST /v1/edge/kbs-request` → [`MessageKind::KbsRequest`].
async fn handle_kbs_request(
    State(state): State<MinerRouterState>,
    Extension(peer): Extension<PeerId>,
    body: Bytes,
) -> Response {
    relay(&state, &peer, MessageKind::KbsRequest, body).await
}

/// `POST /v1/edge/served-receipt` → [`MessageKind::ServedReceipt`].
async fn handle_served_receipt(
    State(state): State<MinerRouterState>,
    Extension(peer): Extension<PeerId>,
    body: Bytes,
) -> Response {
    relay(&state, &peer, MessageKind::ServedReceipt, body).await
}

/// `POST /v1/edge/served-aggregate` → [`MessageKind::ServedAggregate`].
async fn handle_served_aggregate(
    State(state): State<MinerRouterState>,
    Extension(peer): Extension<PeerId>,
    body: Bytes,
) -> Response {
    relay(&state, &peer, MessageKind::ServedAggregate, body).await
}

/// `POST /v1/edge/stopped-ack` → [`MessageKind::StoppedAck`].
async fn handle_stopped_ack(
    State(state): State<MinerRouterState>,
    Extension(peer): Extension<PeerId>,
    body: Bytes,
) -> Response {
    relay(&state, &peer, MessageKind::StoppedAck, body).await
}

/// `POST /v1/edge/heartbeat` → [`MessageKind::Heartbeat`] (PR-MA-6).
async fn handle_heartbeat(
    State(state): State<MinerRouterState>,
    Extension(peer): Extension<PeerId>,
    body: Bytes,
) -> Response {
    relay(&state, &peer, MessageKind::Heartbeat, body).await
}

/// `POST /v1/edge/graceful-exit` → [`MessageKind::GracefulExit`].
///
/// Mirrors [`handle_heartbeat`]: the connection's mTLS [`PeerId`] is
/// the only miner-identity the Edge stamps; vali resolves which
/// registered key to verify the opaque `SignedGracefulExit` body
/// against from it (the Edge never decodes the body — §5.6).
async fn handle_graceful_exit(
    State(state): State<MinerRouterState>,
    Extension(peer): Extension<PeerId>,
    body: Bytes,
) -> Response {
    relay(&state, &peer, MessageKind::GracefulExit, body).await
}

/// `POST /v1/edge/vm-progress` → [`MessageKind::VmProgress`].
///
/// Mirrors [`handle_heartbeat`]: the connection's mTLS [`PeerId`] is the
/// only miner-identity the Edge stamps; vali resolves which registered
/// key to verify the opaque `SignedVmProgress` body against from it (the
/// Edge never decodes the body — §5.6).
async fn handle_vm_progress(
    State(state): State<MinerRouterState>,
    Extension(peer): Extension<PeerId>,
    body: Bytes,
) -> Response {
    relay(&state, &peer, MessageKind::VmProgress, body).await
}

/// `POST /v1/edge/host-attestor-challenge` →
/// [`MessageKind::HostAttestorChallenge`] (PR-10).
///
/// A blackbox host-attestor (relayed by the miner-agent over its mTLS
/// leg) asks vali to mint a fresh single-use enrollment nonce. The
/// connection's mTLS [`PeerId`] is the only miner-identity the Edge
/// stamps; vali binds the minted nonce to it + the request's
/// `signer_pubkey` (the Edge never decodes the body beyond the shape
/// check — §5.6). The minted nonce is relayed back down verbatim.
async fn handle_host_attestor_challenge(
    State(state): State<MinerRouterState>,
    Extension(peer): Extension<PeerId>,
    body: Bytes,
) -> Response {
    relay(&state, &peer, MessageKind::HostAttestorChallenge, body).await
}

/// `POST /v1/edge/host-attestor-enroll` →
/// [`MessageKind::HostAttestorEnroll`] (PR-10b-S2a).
///
/// A blackbox host-attestor's once-per-boot enrollment (relayed by the
/// miner-agent over its mTLS leg). The Edge decodes the enrollment,
/// extracts the vali-minted nonce from its SNP report, ORCHESTRATES the
/// KBS mint + the vali cert ingest, and returns vali's verdict. Fail-closed
/// at every hop (a KBS reject never reaches vali).
async fn handle_host_attestor_enroll(
    State(state): State<MinerRouterState>,
    Extension(peer): Extension<PeerId>,
    body: Bytes,
) -> Response {
    relay(&state, &peer, MessageKind::HostAttestorEnroll, body).await
}

/// `POST /v1/edge/host-attestor-beacon` →
/// [`MessageKind::HostAttestorBeacon`] (PR-10b-S2a).
///
/// A blackbox host-attestor liveness beacon. Mirrors
/// [`handle_heartbeat`]: the connection's mTLS [`PeerId`] is the only
/// host-identity the Edge stamps; vali resolves the `node_id` from it and
/// verifies the opaque `SignedHostBeacon` against the certified key (§5.6).
async fn handle_host_attestor_beacon(
    State(state): State<MinerRouterState>,
    Extension(peer): Extension<PeerId>,
    body: Bytes,
) -> Response {
    relay(&state, &peer, MessageKind::HostAttestorBeacon, body).await
}

/// `POST /v1/edge/vm-live-attestation` →
/// [`MessageKind::VmLiveAttestation`] (§23 uptime coverage).
///
/// The tenant guest asks the KBS for a fresh SNP-rooted live
/// attestation and pushes the KBS-L0-signed result down its vsock; the
/// miner-agent relays it here. Edge stamps NO identity on this one: the
/// L0 signature is the entire credential, and the miner in the middle
/// can neither mint nor edit the bytes it is carrying.
async fn handle_vm_live_attestation(
    State(state): State<MinerRouterState>,
    Extension(peer): Extension<PeerId>,
    body: Bytes,
) -> Response {
    relay(&state, &peer, MessageKind::VmLiveAttestation, body).await
}

// ─── the shared relay pipeline ──────────────────────────────────────

/// Run one envelope through the §9/§10 relay for a fixed
/// `MessageKind`: wire gate → forward → audit → response.
///
/// Always emits exactly ONE [`TelemetryEvent`] before returning, so
/// the §15 invariant ("every transaction is audited") holds
/// structurally on every path. The HTTP status:
///
/// - wire-gate reject (non-canonical / schema-invalid / decode) →
///   `400`,
/// - forward transport failure OR upstream non-2xx → `502`,
/// - relayed OK → the upstream status (typically `200`/`202`), body
///   relayed verbatim.
///
/// (`413` for an oversized body is handled by the router's
/// [`DefaultBodyLimit`] layer — the body never reaches this function.)
async fn relay(
    state: &MinerRouterState,
    peer: &PeerId,
    kind: MessageKind,
    body: Bytes,
) -> Response {
    let bytes_in = body.len() as u64;

    // One telemetry record per transaction — emitted on EVERY return
    // path below. `bytes_out` is the relayed-back body length on
    // success and `0` on a shed (opaque relay: a shed egresses
    // nothing). `shed_reason` is a closed-vocabulary static
    // classifier — never caller-built text, never body bytes.
    let emit = |bytes_out: u64, shed: bool, shed_reason: Option<&'static str>| {
        state.telemetry.record(TelemetryEvent {
            peer: peer.clone(),
            direction: Direction::MinerToInner,
            message_kind: kind,
            bytes_in,
            bytes_out,
            shed,
            shed_reason,
        });
    };

    // (0) Per-source rate limit (audit M-ratelimit). Consulted BEFORE
    //     the wire gate + forward so a flooding peer cannot make the
    //     Edge do CBOR-decode or upstream-forward work. `try_acquire`
    //     already tallies the shed on the peer's bucket (which the HA
    //     health beats surface); on a shed we still emit exactly one
    //     §15 telemetry record and answer `429` (opaque relay: nothing
    //     egresses). The default budget (50/s sustained, burst 100 per
    //     peer) is far above a legitimate miner's heartbeat +
    //     served-receipt cadence, so real traffic is never shed.
    if !state.limiter.try_acquire(peer) {
        log_relay(peer, kind, bytes_in, "rate-limited");
        emit(0, true, Some("rate-limited"));
        return StatusCode::TOO_MANY_REQUESTS.into_response();
    }

    // (1) Envelope shell. `Direction::MinerToInner` is fixed — this
    //     listener only ever ingresses miner traffic; the route fixes
    //     `kind`. The wire gate re-checks direction-vs-kind, so an
    //     Inner→Miner kind could not be smuggled even if a route
    //     mis-tagged one.
    let raw = RawEnvelope::from_wire(Direction::MinerToInner, kind, peer.clone(), body.to_vec());

    // (2) Wire gate (§10). Consumes `raw`; canonical-CBOR + direction
    //     + `deny_unknown_fields` typed decode. The recursion-bounded
    //     canonical check runs here — AFTER the body-size cap layer,
    //     never before.
    let validated = match validate::validate(raw) {
        Ok(v) => v,
        Err(err) => {
            // Schema-invalid / non-canonical / decode failure — a shed
            // at the wire gate. Attribute with the error's OWN static
            // classifier.
            log_relay(peer, kind, bytes_in, "rejected");
            emit(0, true, Some(err.class()));
            return edge_error_response(&err);
        }
    };
    log_relay(peer, kind, bytes_in, "accepted");

    // (3) Forward — opaque byte relay to the inner endpoint for this
    //     kind. The `ForwardClient` method is selected by `kind`, so
    //     a `KbsRequest` can only ever reach the KBS, a telemetry
    //     kind only ever vali.
    let forwarded = match kind {
        MessageKind::KbsRequest => state.forward.forward_kbs_request(&validated).await,
        MessageKind::ServedReceipt => state.forward.forward_served_receipt(&validated).await,
        MessageKind::ServedAggregate => state.forward.forward_served_aggregate(&validated).await,
        MessageKind::StoppedAck => state.forward.forward_stopped_ack(&validated).await,
        MessageKind::Heartbeat => state.forward.forward_heartbeat(&validated).await,
        MessageKind::GracefulExit => state.forward.forward_graceful_exit(&validated).await,
        MessageKind::VmProgress => state.forward.forward_vm_progress(&validated).await,
        MessageKind::HostAttestorChallenge => {
            state
                .forward
                .forward_host_attestor_challenge(&validated)
                .await
        }
        MessageKind::HostAttestorEnroll => {
            state.forward.forward_host_attestor_enroll(&validated).await
        }
        MessageKind::HostAttestorBeacon => {
            state.forward.forward_host_attestor_beacon(&validated).await
        }
        MessageKind::VmLiveAttestation => {
            state.forward.forward_vm_live_attestation(&validated).await
        }
        // `KbsResponse` has no route into this listener and the wire
        // gate's direction check already rejected it above — this arm
        // is the type-exhaustive fallback, never reached at runtime.
        MessageKind::KbsResponse => {
            log_relay(peer, kind, bytes_in, "forward-failed");
            emit(0, true, Some("forward-direction"));
            return StatusCode::BAD_REQUEST.into_response();
        }
    };

    // (4) Audit the forward result + relay the response.
    match forwarded {
        Ok(resp) if (200..300).contains(&resp.status) => {
            // {accepted + forwarded} — the §15 success record.
            log_relay(peer, kind, resp.body.len() as u64, "forwarded");
            emit(resp.body.len() as u64, false, None);
            forward_response_relay(resp)
        }
        Ok(_resp) => {
            // Upstream answered, but non-2xx. Not a transport failure
            // — a {accepted + forward-failed} record. The miner sees
            // `502`; the upstream body is NOT relayed (it is an
            // inner-plane error shape, opaque to the miner).
            log_relay(peer, kind, bytes_in, "forward-upstream-error");
            emit(0, true, Some("forward-upstream-status"));
            StatusCode::BAD_GATEWAY.into_response()
        }
        Err(err) => {
            // Transport failure — {accepted + forward-failed}.
            log_relay(peer, kind, bytes_in, err.class());
            emit(0, true, Some(forward_error_class(&err)));
            StatusCode::BAD_GATEWAY.into_response()
        }
    }
}

/// Relay a successful [`ForwardResponse`] back to the miner: the
/// upstream status + the upstream body **verbatim**
/// (`content-type: application/cbor`). The body bytes are never
/// re-encoded — an opaque relay (§5.6).
fn forward_response_relay(resp: ForwardResponse) -> Response {
    // The upstream status is in `200..300` (checked by the caller);
    // `from_u16` cannot realistically fail, but fall back to `200`
    // rather than `unwrap` (crate-wide `unwrap_used` is denied).
    let status = StatusCode::from_u16(resp.status).unwrap_or(StatusCode::OK);
    (
        status,
        [(
            header::CONTENT_TYPE,
            HeaderValue::from_static(CONTENT_TYPE_CBOR),
        )],
        resp.body,
    )
        .into_response()
}

/// Map a wire-gate [`EdgeError`] to a miner-facing HTTP response.
///
/// Schema / canonical / decode failures are `400` — the only error
/// classes [`validate::validate`] can return on this path. Any other
/// variant (rate-limit, queue, mTLS — none reachable from the router)
/// folds to `400` too: a fail-closed default that never leaks an
/// inner-plane status. The body is empty — Edge does not echo a
/// classifier to the (untrusted) miner; the classifier goes to the
/// audit record only.
fn edge_error_response(err: &EdgeError) -> Response {
    match err {
        EdgeError::NonCanonical(_) | EdgeError::HippiusTypes(_) | EdgeError::SchemaInvalid(_) => {
            StatusCode::BAD_REQUEST
        }
        // Not reachable from the router (the wire gate only emits the
        // three classes above) — fail-closed to `400` rather than a
        // misleading `5xx`.
        EdgeError::Todo(_)
        | EdgeError::RateLimited
        | EdgeError::QueueFull
        | EdgeError::WorkerGone
        | EdgeError::MtlsFailed(_) => StatusCode::BAD_REQUEST,
    }
    .into_response()
}

/// Static classifier for a [`ForwardError`] — identical to
/// [`ForwardError::class`]. Pulled into a named fn so the
/// `shed_reason` argument is unambiguously `&'static str`.
fn forward_error_class(err: &ForwardError) -> &'static str {
    err.class()
}

/// Structured relay log — peer + kind + body length + a static
/// outcome classifier. NEVER the body bytes (§20 / §5.6). `peer` is
/// emitted via `Display` (the cert-derived identity string only).
fn log_relay(peer: &PeerId, kind: MessageKind, body_len: u64, outcome: &'static str) {
    eprintln!(
        "hippius-edge-gateway: miner-router: peer={} kind={} body_len={} outcome={}",
        peer,
        kind.as_class_str(),
        body_len,
        outcome,
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::RateLimitConfig;
    use crate::forward::MockForwardClient;
    use crate::telemetry::NoopTelemetry;
    use std::time::Duration;

    /// A limiter that never sheds in a short test (generous default
    /// budget: 50/s sustained, burst 100 per peer).
    fn generous_limiter() -> Arc<PerSourceRateLimiter> {
        Arc::new(PerSourceRateLimiter::new(
            RateLimitConfig::default(),
            Duration::from_secs(3600),
            1024,
        ))
    }

    fn state(forward: Arc<dyn ForwardClient>) -> MinerRouterState {
        MinerRouterState::new(forward, Arc::new(NoopTelemetry), generous_limiter())
    }

    #[test]
    fn router_builds_without_panicking() {
        // A construction smoke test — `Router::new().route(...)`
        // panics on a malformed path / duplicate route, so a clean
        // build pins the route table shape.
        let _router = build_router(state(Arc::new(MockForwardClient::with_response(
            200,
            Vec::new(),
        ))));
    }

    #[test]
    fn edge_error_maps_schema_failures_to_400() {
        for err in [
            EdgeError::NonCanonical("empty-body"),
            EdgeError::SchemaInvalid("decode"),
            EdgeError::HippiusTypes(hippius_types::HippiusTypesError::Cbor("x".into())),
        ] {
            assert_eq!(
                edge_error_response(&err).status(),
                StatusCode::BAD_REQUEST,
                "{err:?}"
            );
        }
    }

    #[test]
    fn forward_error_class_is_static() {
        assert_eq!(
            forward_error_class(&ForwardError::Transport),
            "forward-transport"
        );
    }

    #[tokio::test]
    async fn relay_sheds_over_the_per_source_rate_limit() {
        // Audit M-ratelimit: a peer over its token budget is refused 429
        // at the top of `relay`, BEFORE the wire gate / forward. Build a
        // burst-1 no-refill limiter so the second request in the same
        // instant has no token.
        let limiter = Arc::new(PerSourceRateLimiter::new(
            RateLimitConfig {
                refill_per_sec: 0.0,
                burst: 1,
            },
            Duration::from_secs(3600),
            1024,
        ));
        let st = MinerRouterState::new(
            Arc::new(MockForwardClient::with_response(200, Vec::new())),
            Arc::new(NoopTelemetry),
            limiter,
        );
        let peer = PeerId::new("hippius-node:abcd");

        // 1st request spends the single token — it reaches the wire gate,
        // where the empty body is rejected 400. The point: it is NOT 429.
        let r1 = relay(&st, &peer, MessageKind::Heartbeat, Bytes::new()).await;
        assert_ne!(
            r1.status(),
            StatusCode::TOO_MANY_REQUESTS,
            "1st must not shed"
        );

        // 2nd request has no token → shed 429 before any gate/forward.
        let r2 = relay(&st, &peer, MessageKind::Heartbeat, Bytes::new()).await;
        assert_eq!(
            r2.status(),
            StatusCode::TOO_MANY_REQUESTS,
            "2nd must be rate-limited"
        );

        // A DIFFERENT peer has its own bucket → not shed by peer-1's flood.
        let other = PeerId::new("hippius-node:ef01");
        let r3 = relay(&st, &other, MessageKind::Heartbeat, Bytes::new()).await;
        assert_ne!(
            r3.status(),
            StatusCode::TOO_MANY_REQUESTS,
            "a different peer must not be shed"
        );
    }
}
