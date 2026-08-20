//! §24/§25 guest stopped-ack relay route — the Edge's thin,
//! UNauthenticated forwarder for the confidential guest's signed
//! `stopped{}` ack.
//!
//! ## Why this listener exists
//!
//! A tenant CVM has NO IP route to vali (vali has no public ingress;
//! its ClusterIP is unreachable from the guest). The guest delivers its
//! signed stopped-ack the same way it reaches the KBS: over AF_VSOCK to
//! its miner host, which forwards the OPAQUE bytes onward
//! ([`binaries/miner-agent/src/vsock/kbs_proxy.rs`], the `[lifecycle]`
//! backend). But the MINER HOST cannot reach vali's ClusterIP either —
//! it only reaches the KBS ingress and the Edge LoadBalancer (both
//! published as mesh addresses) over the NetBird mesh. So the miner
//! forwards the ack
//! to THIS Edge route, and the Edge — which IS in-cluster — relays it
//! verbatim to vali's `POST /v1/lifecycle/stopped` ingress (the
//! `StoppedAckIngest` store `effects.poll_source_ack` reads).
//!
//! This is the §25 sibling of the graceful-exit relay
//! ([`crate::forward::vali_forward::GRACEFUL_EXIT_INGEST_PATH`]): "a
//! real miner box cannot reach vali directly, but it reaches the Edge".
//! The graceful-exit relay rides the mTLS miner listener (the miner has
//! a client cert there); the stopped-ack rides the guest's vsock-proxy
//! reqwest hop, which has no client cert, so it lands HERE on a plain
//! listener whose TLS is terminated by nginx-ingress with a PUBLIC cert
//! (exactly like the KBS guest ingress) — the guest/miner reqwest client
//! trusts a public root, not the private Edge CA.
//!
//! ## Route
//!
//! | Method · path                  | forwards to vali                 |
//! |--------------------------------|----------------------------------|
//! | `POST /v1/lifecycle/stopped`   | `POST /v1/lifecycle/stopped`     |
//!
//! The `?vm_id=&generation=` query the guest supplies (read from its
//! MEASURED cmdline) is forwarded VERBATIM — vali's ingest `400`s
//! without both. The request body is the OPAQUE canonical-CBOR
//! `SignedStoppedAck`; it is relayed byte-for-byte.
//!
//! ## Opacity + trust (§5.6)
//!
//! The Edge NEVER decodes, forges, or alters the ack — it routes on the
//! path component alone and copies the query + body through. vali's
//! `_verify_ack` is the actual trust gate (Ed25519 signature at
//! `source_gen` + single-use nonce + generation). A forged / absent /
//! stale ack relayed here is inert: it just fails that verification and
//! the migration never advances (fail-closed). The relay carries NO
//! authority of its own — it is a transport, mirroring the KBS-over-vsock
//! proxy and the inner order relay.
//!
//! ## Why a SEPARATE listener (not the inner or miner listener)
//!
//! - The **inner listener** (`:8444`) is NetworkPolicy-gated to the vali
//!   pod only — a miner cannot reach it.
//! - The **miner listener** (`:8443`) requires a client cert (mTLS); the
//!   guest's vsock-proxy reqwest hop presents none.
//!
//! So this is its own plain-HTTP listener on a dedicated container port,
//! published to the miner mesh through nginx-ingress (public TLS), gated
//! to the NetBird CGNAT range by the same CiliumNetworkPolicy the relay
//! ingress uses.

use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::{RawQuery, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};

/// vali's stopped-ack ingest path. The Edge forwards verbatim to
/// `<vali_base>/v1/lifecycle/stopped?<query>`. Pinned here so a rename
/// on either side surfaces in the test below.
pub const VALI_STOPPED_ACK_PATH: &str = "/v1/lifecycle/stopped";

/// Hard cap on the relayed stopped-ack body. The ack is a small
/// canonical-CBOR `SignedStoppedAck` (a few hundred bytes); vali's own
/// ingest caps at `VALI_STOPPED_ACK_MAX_HEX_LEN/2` (~2 KiB). 16 KiB is
/// generous head-room and bounds a hostile allocation before any
/// forward.
pub const MAX_LIFECYCLE_BODY: usize = 16 * 1024;

/// The seam the route depends on: forward the OPAQUE stopped-ack body +
/// the verbatim query to vali's `/v1/lifecycle/stopped` ingress. A trait
/// so tests inject a recording stub and the route stays off the network.
#[async_trait::async_trait]
pub trait LifecycleForward: Send + Sync {
    /// POST `body` to `<vali_base>/v1/lifecycle/stopped?<query>` and
    /// return `(status, response_body)`. `query` is the verbatim
    /// `vm_id=…&generation=…` string (no leading `?`), empty when the
    /// guest sent none (vali then `400`s — fail-closed). `Err(())` is a
    /// transport failure (DNS / connect / timeout); the route maps it to
    /// `502`.
    async fn forward_stopped_ack(&self, query: &str, body: &[u8]) -> Result<(u16, Vec<u8>), ()>;
}

/// Production [`LifecycleForward`] — a `reqwest` client to the in-cluster
/// vali base. No mTLS (the Cilium NetworkPolicy is the who-calls-who
/// control on the forward leg, exactly like [`crate::forward::
/// ReqwestForwardClient`]); `rustls`, no redirects, bounded timeouts.
pub struct ReqwestLifecycleForward {
    vali_base: String,
    client: reqwest::Client,
}

impl ReqwestLifecycleForward {
    /// Build the forwarder for the vali base URL (e.g.
    /// `http://vali.vali.svc.cluster.local:8000`).
    pub fn new(vali_base: impl Into<String>) -> Result<Self, crate::forward::ForwardError> {
        let client = reqwest::Client::builder()
            .use_rustls_tls()
            .connect_timeout(std::time::Duration::from_secs(5))
            .timeout(std::time::Duration::from_secs(30))
            .redirect(reqwest::redirect::Policy::none())
            .no_proxy()
            .build()
            .map_err(|_| crate::forward::ForwardError::ClientBuild)?;
        Ok(Self {
            vali_base: vali_base.into().trim_end_matches('/').to_string(),
            client,
        })
    }
}

#[async_trait::async_trait]
impl LifecycleForward for ReqwestLifecycleForward {
    async fn forward_stopped_ack(&self, query: &str, body: &[u8]) -> Result<(u16, Vec<u8>), ()> {
        // Re-attach the verbatim query (vali reads vm_id+generation from
        // it). The body content-type is irrelevant to vali's ingest
        // (it reads `request.body` raw), but mirror the guest's
        // `application/cbor` so an intermediary never re-interprets it.
        let url = if query.is_empty() {
            format!("{}{}", self.vali_base, VALI_STOPPED_ACK_PATH)
        } else {
            format!("{}{}?{}", self.vali_base, VALI_STOPPED_ACK_PATH, query)
        };
        let resp = self
            .client
            .post(&url)
            .header(reqwest::header::CONTENT_TYPE, "application/cbor")
            .body(body.to_vec())
            .send()
            .await
            .map_err(|_| ())?;
        let status = resp.status().as_u16();
        let bytes = resp.bytes().await.map_err(|_| ())?;
        if bytes.len() > MAX_LIFECYCLE_BODY {
            return Err(());
        }
        Ok((status, bytes.to_vec()))
    }
}

/// Shared state the route closes over — just the forwarder (behind an
/// `Arc`, cheap to clone).
#[derive(Clone)]
pub struct LifecycleRouterState {
    forward: Arc<dyn LifecycleForward>,
}

impl LifecycleRouterState {
    /// Build the route state from the vali forwarder.
    pub fn new(forward: Arc<dyn LifecycleForward>) -> Self {
        Self { forward }
    }
}

/// `POST /v1/lifecycle/stopped?vm_id=…&generation=…` — relay the guest's
/// signed stopped-ack to vali. Opaque: the body + query are forwarded
/// verbatim; the Edge never decodes the ack (§5.6).
async fn handle_stopped_ack(
    State(state): State<LifecycleRouterState>,
    RawQuery(query): RawQuery,
    body: Bytes,
) -> Response {
    if body.is_empty() {
        // vali rejects an empty body too, but reject here so we never
        // open a vali round-trip for a no-op (fail-closed, never relay
        // a degenerate ack).
        log_relay(0, None, "empty-body");
        return StatusCode::BAD_REQUEST.into_response();
    }
    let query = query.unwrap_or_default();
    let bytes_in = body.len();
    match state.forward.forward_stopped_ack(&query, &body).await {
        Ok((status, resp_body)) => {
            let outcome = if (200..300).contains(&status) {
                "accepted"
            } else {
                "vali-rejected"
            };
            log_relay(bytes_in, Some(status), outcome);
            let code = StatusCode::from_u16(status).unwrap_or(StatusCode::BAD_GATEWAY);
            (code, resp_body).into_response()
        }
        Err(()) => {
            log_relay(bytes_in, None, "forward-transport");
            StatusCode::BAD_GATEWAY.into_response()
        }
    }
}

/// `GET /healthz` — liveness; static `200`, no relay work.
async fn handle_healthz() -> StatusCode {
    StatusCode::OK
}

/// Structured audit log — body length + upstream status + a static
/// outcome class. NEVER the body bytes and NEVER the query (the query
/// carries the vm_id/generation; vm_id is operator-meaningful but the
/// §20 discipline keeps the log to a closed-vocabulary class only).
fn log_relay(body_len: usize, upstream_status: Option<u16>, outcome: &'static str) {
    let status_s = upstream_status
        .map(|s| s.to_string())
        .unwrap_or_else(|| "-".into());
    eprintln!(
        "hippius-edge-gateway: lifecycle-router: body_len={body_len} upstream={status_s} outcome={outcome}"
    );
}

/// Build the lifecycle relay [`axum::Router`]. One relay route + a
/// healthz. The `DefaultBodyLimit` caps the body at [`MAX_LIFECYCLE_BODY`]
/// before the handler runs (an oversized body is rejected `413`).
pub fn build_lifecycle_router(state: LifecycleRouterState) -> axum::Router {
    use axum::extract::DefaultBodyLimit;
    use axum::routing::{get, post};
    axum::Router::new()
        .route(VALI_STOPPED_ACK_PATH, post(handle_stopped_ack))
        .route("/healthz", get(handle_healthz))
        .layer(DefaultBodyLimit::max(MAX_LIFECYCLE_BODY))
        .with_state(state)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    /// Recording stub — captures the (query, body) it was handed and
    /// returns a canned `(status, body)`.
    struct RecordingForward {
        canned_status: u16,
        seen: Mutex<Option<(String, Vec<u8>)>>,
    }

    #[async_trait::async_trait]
    impl LifecycleForward for RecordingForward {
        async fn forward_stopped_ack(
            &self,
            query: &str,
            body: &[u8],
        ) -> Result<(u16, Vec<u8>), ()> {
            *self.seen.lock().unwrap() = Some((query.to_string(), body.to_vec()));
            Ok((self.canned_status, Vec::new()))
        }
    }

    #[test]
    fn vali_path_is_stable() {
        // vali's StoppedAckIngestView is mounted at this exact path; a
        // rename on either side silently breaks the §25 ack delivery.
        assert_eq!(VALI_STOPPED_ACK_PATH, "/v1/lifecycle/stopped");
    }

    #[tokio::test]
    async fn relays_the_opaque_body_and_verbatim_query() {
        let fwd = Arc::new(RecordingForward {
            canned_status: 202,
            seen: Mutex::new(None),
        });
        let state = LifecycleRouterState::new(fwd.clone());
        let resp = handle_stopped_ack(
            State(state),
            RawQuery(Some("vm_id=mig-e2e-2&generation=2".to_string())),
            Bytes::from_static(b"opaque-signed-ack-cbor"),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::ACCEPTED);
        let (query, body) = fwd.seen.lock().unwrap().clone().unwrap();
        // The query is forwarded VERBATIM (vali reads vm_id+generation).
        assert_eq!(query, "vm_id=mig-e2e-2&generation=2");
        // The body is relayed BYTE-FOR-BYTE (opaque, §5.6).
        assert_eq!(body, b"opaque-signed-ack-cbor");
    }

    #[tokio::test]
    async fn empty_body_is_rejected_before_any_forward() {
        let fwd = Arc::new(RecordingForward {
            canned_status: 202,
            seen: Mutex::new(None),
        });
        let state = LifecycleRouterState::new(fwd.clone());
        let resp = handle_stopped_ack(
            State(state),
            RawQuery(Some("vm_id=x&generation=1".to_string())),
            Bytes::new(),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        // Never opened a forward for a degenerate ack.
        assert!(fwd.seen.lock().unwrap().is_none());
    }

    #[tokio::test]
    async fn a_vali_non_2xx_is_surfaced_verbatim() {
        // vali `400`s on a missing query — the Edge surfaces that status
        // (the miner/guest sees it), it does not mask it as a 502.
        let fwd = Arc::new(RecordingForward {
            canned_status: 400,
            seen: Mutex::new(None),
        });
        let state = LifecycleRouterState::new(fwd.clone());
        let resp =
            handle_stopped_ack(State(state), RawQuery(None), Bytes::from_static(b"ack")).await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        // The empty query was forwarded verbatim (vali owns the
        // vm_id/generation requirement).
        let (query, _) = fwd.seen.lock().unwrap().clone().unwrap();
        assert_eq!(query, "");
    }

    #[test]
    fn router_builds_without_panicking() {
        let fwd = Arc::new(RecordingForward {
            canned_status: 202,
            seen: Mutex::new(None),
        });
        let _router = build_lifecycle_router(LifecycleRouterState::new(fwd));
    }
}
