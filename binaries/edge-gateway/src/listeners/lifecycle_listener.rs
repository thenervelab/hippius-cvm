//! The §24/§25 guest stopped-ack relay listener — the TLS bind + serve
//! loop in front of [`lifecycle_router`](super::lifecycle_router).
//!
//! ## Transport
//!
//! TLS 1.3, **server cert only** (NO client cert — the hop arrives from
//! a miner host's vsock-proxy `reqwest` client that presents none). The
//! Edge serves its OWN server cert (the same one the mTLS miner relay
//! presents); the miner verifies it against the hippius-compute CA it
//! was shipped. The Edge cert carries the Edge LoadBalancer's mesh
//! address as an `IP:` SAN, so the
//! miner dials the LoadBalancer IP directly over the NetBird mesh — **no
//! public DNS and no public Let's Encrypt cert are needed** for this
//! internal mesh hop (mirroring how the KBS-over-vsock relay reaches the
//! KBS without the guest owning any network identity).
//!
//! HTTP/2 only (the Edge's `hyper`/`hyper-util` are `http2`-feature
//! builds); `reqwest` upgrades to h2 via the `h2` ALPN the server
//! advertises, exactly like the miner relay.
//!
//! ## Access control (in depth)
//!
//! 1. the CiliumNetworkPolicy pins the NetBird CGNAT source range, and
//! 2. the listener serves a SINGLE opaque relay route that lands in
//!    vali's fail-closed `StoppedAckIngest` store — a forged ack is
//!    inert, vali's `_verify_ack` is the trust gate.
//!
//! ## Shutdown
//!
//! One graceful-shutdown signal — the same `watch::Receiver<bool>`
//! `main` uses for the other listeners — so all drain together on
//! SIGTERM. The per-connection handler is short (relay one ack to vali).

use std::sync::Arc;
use std::time::Duration;

use hyper::body::Incoming;
use hyper::server::conn::http2;
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use tokio::net::TcpListener;
use tokio::sync::watch;
use tokio_rustls::TlsAcceptor;
use tower::Service;

use super::lifecycle_router::{build_lifecycle_router, LifecycleForward, LifecycleRouterState};

/// Default container port the lifecycle relay TLS listener binds. The
/// `LoadBalancer` Service publishes a matching external port and maps it
/// here. Distinct from the miner relay (`:8443`), the inner listener
/// (`:8444`), the (legacy plain) lifecycle port, and the telemetry API
/// (`:9465`).
pub const LIFECYCLE_LISTENER_PORT: u16 = 8446;

/// Bound on how long one connection may take to complete the TLS
/// handshake — a peer that opens TCP but stalls is dropped (slow-loris).
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// Max concurrent HTTP/2 streams per connection. One ack POST is one
/// stream; a miner has no reason to fan out.
const MAX_CONCURRENT_STREAMS: u32 = 16;

/// HTTP/2 keep-alive ping interval — reclaims a slot held by a silently
/// dead peer.
const H2_KEEPALIVE_INTERVAL: Duration = Duration::from_secs(20);

/// How long the server waits for a keep-alive ping ACK before dropping.
const H2_KEEPALIVE_TIMEOUT: Duration = Duration::from_secs(10);

/// Run the lifecycle relay TLS accept loop until `cancel` is signalled.
///
/// `tls` is the server-cert-only [`tokio_rustls::TlsAcceptor`] (built
/// from [`crate::mtls::cert_store::build_server_config_no_client_auth`]).
/// `forward` is the production
/// [`ReqwestLifecycleForward`](super::lifecycle_router::ReqwestLifecycleForward).
/// Each accepted TCP connection is TLS-terminated then served the
/// lifecycle router over an HTTP/2 connection. A failed handshake / serve
/// is logged with a static class and dropped.
pub async fn run_lifecycle_listener(
    listener: TcpListener,
    tls: TlsAcceptor,
    forward: Arc<dyn LifecycleForward>,
    mut cancel: watch::Receiver<bool>,
) {
    let state = LifecycleRouterState::new(forward);
    let router = build_lifecycle_router(state);

    log_listener("listening");
    if *cancel.borrow() {
        log_listener("shutdown");
        return;
    }
    loop {
        tokio::select! {
            _ = cancel.changed() => {
                log_listener("shutdown");
                break;
            }
            accepted = listener.accept() => {
                let tcp = match accepted {
                    Ok((tcp, _addr)) => tcp,
                    Err(_) => {
                        log_listener("accept-error");
                        tokio::time::sleep(Duration::from_millis(20)).await;
                        continue;
                    }
                };
                let tls = tls.clone();
                let router = router.clone();
                // Each connection handled on its own DETACHED task: the
                // handler is short (terminate TLS → serve one ack POST →
                // forward to vali). On shutdown the accept loop stops; an
                // in-flight ack relay finishes within hyper's own bounds.
                tokio::spawn(async move {
                    handle_conn(tcp, tls, router).await;
                });
            }
        }
    }
    log_listener("drained");
}

/// Terminate TLS on one accepted TCP connection and serve the lifecycle
/// router over HTTP/2. All failures fold to a static-class log line and
/// a dropped connection (fail-closed; never a panic).
async fn handle_conn(tcp: tokio::net::TcpStream, tls: TlsAcceptor, router: axum::Router) {
    let tls_stream = match tokio::time::timeout(HANDSHAKE_TIMEOUT, tls.accept(tcp)).await {
        Ok(Ok(s)) => s,
        Ok(Err(_)) => {
            log_listener("handshake-failed");
            return;
        }
        Err(_) => {
            log_listener("handshake-timeout");
            return;
        }
    };

    // Adapt the axum `Router` (a `tower::Service`) to a hyper service.
    // `Router::call` takes `&mut self`, so clone the router per request
    // so the returned future owns its own service instance.
    let hyper_svc = hyper::service::service_fn(move |req: hyper::Request<Incoming>| {
        let mut svc = router.clone();
        async move { svc.call(req).await }
    });

    let io = TokioIo::new(tls_stream);
    let mut builder = http2::Builder::new(TokioExecutor::new());
    builder
        .max_concurrent_streams(MAX_CONCURRENT_STREAMS)
        .timer(TokioTimer::new())
        .keep_alive_interval(H2_KEEPALIVE_INTERVAL)
        .keep_alive_timeout(H2_KEEPALIVE_TIMEOUT);
    if builder.serve_connection(io, hyper_svc).await.is_err() {
        log_listener("serve-error");
    }
}

/// Log a listener-lifecycle event (static class only) — same shape as
/// the other listeners.
fn log_listener(event: &'static str) {
    eprintln!("hippius-edge-gateway: lifecycle-listener: {event}");
}
