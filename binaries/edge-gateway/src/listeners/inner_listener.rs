//! The cluster-internal **inner** listener — vali's entry point to the
//! Edge order-signing chain.
//!
//! [`inner_router`](super::inner_router) is the axum router; this
//! module is the TCP bind + serve loop in front of it. The listener is
//! deliberately MUCH simpler than [`crate::miner_listener`]:
//!
//! - **Plain HTTP** — no mTLS, no rustls, no ALPN gate. Vali does not
//!   own a client cert against the Edge CA (the operator-side mTLS
//!   material under `/Users/dubs/dev/everything/hippius-compute-key/`
//!   issues the Edge server cert + per-miner client certs only); the
//!   inner listener is gated at L3 by a Cilium NetworkPolicy that
//!   admits the vali pod's PodSelector and nothing else. See
//!   `deploy/gitops/apps/edge-gateway/templates/networkpolicy.yaml`.
//! - **HTTP/1.1 + HTTP/2** — `axum::serve` picks per-connection; vali
//!   uses stdlib `urllib` (HTTP/1.1) on the issuing side, the
//!   integration test uses `reqwest` (HTTP/2).
//! - **One graceful-shutdown signal** — the loop returns on the same
//!   `watch::Receiver<bool>` `main` uses for the miner listener, so
//!   the two listeners drain together on SIGTERM.
//!
//! ## Bind address
//!
//! `main` picks the bind address from `EDGE_INNER_LISTENER_ADDR` (a
//! cluster-internal address, e.g. `0.0.0.0:8444`); the listener does
//! NOT default to a global bind — an unset env var is treated as
//! "subsystem disabled" by `main` (the inner listener is only stood up
//! when [`OrderSigner`](crate::order_signing::OrderSigner) loaded
//! successfully).
//!
//! ## Body cap + timeouts
//!
//! Both already live on the router: a `DefaultBodyLimit` for the
//! 64 KiB request cap (matching the miner-agent's `MAX_ORDER_BODY`),
//! and the [`MinerForward`](crate::forward::MinerForward) client's
//! own 5 s connect / 30 s request timeouts for the outbound leg. No
//! listener-level whole-request timeout layer here — the inner
//! listener serves exactly one route whose pipeline is short
//! (parse headers → sign → forward), and a slow inbound body is
//! bounded by Hyper's default read timeout for plain HTTP.

use std::sync::Arc;

use tokio::net::TcpListener;
use tokio::sync::watch;

use super::inner_router::{build_inner_router, InnerRouterState};
use crate::forward::MinerForward;
use crate::order_signing::OrderSigner;

/// Default container port the inner-plane listener binds. The cluster-
/// internal Service publishes a matching port and the NetworkPolicy
/// admits only the vali pod's PodSelector. Operator override via
/// `EDGE_INNER_LISTENER_ADDR` in `main.rs`.
pub const INNER_LISTENER_PORT: u16 = 8444;

/// Run the inner-plane order-dispatch accept loop until `cancel` is
/// signalled.
///
/// `signer` is the loaded [`OrderSigner`] (a Some-only path — see
/// `main.rs`: the listener is not bound at all when the order-signing
/// subsystem is disabled). `forward` is the production
/// [`ReqwestMinerForward`](crate::forward::ReqwestMinerForward) in
/// release builds; tests inject `MockMinerForward`.
///
/// On `cancel.changed()` the listener stops accepting and returns; any
/// in-flight request is allowed to complete because `axum::serve` with
/// `.with_graceful_shutdown` drains in-flight handlers before the
/// future resolves.
pub async fn run_inner_listener(
    listener: TcpListener,
    signer: Arc<OrderSigner>,
    forward: Arc<dyn MinerForward>,
    mut cancel: watch::Receiver<bool>,
) {
    let state = InnerRouterState::new(signer, forward);
    let router = build_inner_router(state);

    // `axum::serve` accepts a `TcpListener`, builds a hyper
    // service-per-connection, and runs `Router` as a `tower::Service`.
    // We rely on its default HTTP/1.1 + HTTP/2 negotiation — vali
    // talks HTTP/1.1 over stdlib `urllib`; the integration test
    // exercises HTTP/2 via reqwest.
    log_listener("listening");
    let shutdown = async move {
        // Wait for any change (or a dropped sender) on the cancel
        // signal — `main` only ever flips it to `true` once.
        let _ = cancel.changed().await;
        log_listener("shutdown");
    };
    if let Err(_e) = axum::serve(listener, router)
        .with_graceful_shutdown(shutdown)
        .await
    {
        // `axum::serve`'s `Err` collapses the accept loop's transient
        // errors into one — we treat the whole future as fail-closed:
        // the loop terminated, so the inner listener is no longer
        // serving. `main` exits the process on listener termination so
        // Kubernetes restarts the pod cleanly (matches the miner
        // listener's posture).
        log_listener("serve-error");
    }
    log_listener("drained");
}

/// Log a listener-lifecycle event (static class only) — same shape as
/// [`miner_listener::log_listener`](crate::miner_listener).
fn log_listener(event: &'static str) {
    eprintln!("hippius-edge-gateway: inner-listener: {event}");
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::forward::MockMinerForward;
    use std::io::Write;
    use std::time::Duration;

    fn test_signer() -> Arc<OrderSigner> {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        f.write_all(hex::encode([3u8; 32]).as_bytes()).unwrap();
        f.flush().unwrap();
        OrderSigner::load(f.path(), None).unwrap()
    }

    #[tokio::test]
    async fn listener_returns_on_cancel() {
        // Bind a free loopback port and prove the listener returns
        // promptly when the cancel signal is flipped — required so
        // `main`'s SIGTERM drain finishes within the
        // `terminationGracePeriodSeconds`.
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let signer = test_signer();
        let forward: Arc<dyn MinerForward> =
            Arc::new(MockMinerForward::with_response(200, Vec::new()));
        let (tx, rx) = watch::channel(false);

        let task = tokio::spawn(async move {
            run_inner_listener(listener, signer, forward, rx).await;
        });

        // Give the bind + serve a chance to start.
        tokio::time::sleep(Duration::from_millis(50)).await;
        tx.send(true).unwrap();

        // `axum::serve` drains on graceful_shutdown; with no in-flight
        // requests it returns immediately.
        tokio::time::timeout(Duration::from_secs(2), task)
            .await
            .expect("inner listener must return on cancel within 2s")
            .expect("task must not panic");
    }
}
