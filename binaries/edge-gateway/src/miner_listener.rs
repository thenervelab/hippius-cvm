//! Miner-facing `:443` mTLS relay listener (PR-H7 + PR-H8, §H phase 2).
//!
//! PR-K8 wired every Edge subsystem except the one that accepts
//! production miner traffic — `main.rs` explicitly deferred "the real
//! miner-facing TCP accept loop" to PR-H7. This module is that accept
//! loop.
//!
//! ## PR-H7 — mTLS termination
//!
//! A [`TcpListener`] whose every connection is driven through
//! [`MtlsAcceptor::accept`] — the production PR-H4 handshake (TLS 1.3
//! only, client cert REQUIRED, verified against the hippius-compute
//! CA, CRL fail-closed). A connection that fails the handshake is
//! logged with its static failure class and dropped.
//!
//! ## PR-H8 — the envelope protocol over the mTLS stream
//!
//! PR-H7 *closed* a connection right after the handshake because the
//! miner↔Edge wire frame had no written spec. PR-H8 is that spec,
//! LOCKED to **HTTP/2 over the mTLS stream**: each authenticated
//! connection is now served the [`crate::listeners::miner_router`]
//! axum [`Router`] — instead of being closed — for the connection's
//! lifetime.
//!
//! `axum::serve` cannot be used: it wants to own a `TcpListener` and
//! do its own accept, but here mTLS is terminated **per-connection**
//! in [`handle_miner_conn`]. So the router (a `tower::Service`) is
//! driven over each accepted [`tokio_rustls`] stream by `hyper`'s
//! **HTTP/2-only** server connection + [`TokioIo`]. The wire is
//! LOCKED to HTTP/2: ALPN advertises `h2` only, the server uses the
//! `http2`-only connection builder, and the connection carries a
//! max-concurrent-streams cap + keep-alive pings so one peer cannot
//! park a connection slot. A whole-request `TimeoutLayer` bounds a
//! slow-body upload. The handshake's [`PeerId`] is injected as a
//! per-connection request `Extension` (each connection is exactly
//! one already-terminated mTLS peer).
//!
//! ## Logging
//!
//! Connection accept / reject events are static-class log lines (the
//! crate's `&'static str` discipline). The per-envelope audit chain
//! (§15) is driven inside the router via the [`TelemetryRecorder`] —
//! a bare connection carries no envelope, so connection-level events
//! are not chained.
//!
//! [`Router`]: axum::Router
//! [`TokioIo`]: hyper_util::rt::TokioIo
//! [`PeerId`]: crate::mtls::PeerId
//! [`TelemetryRecorder`]: crate::telemetry::TelemetryRecorder

use std::sync::Arc;
use std::time::Duration;

use axum::extract::Extension;
use hyper::body::Incoming;
use hyper::server::conn::http2;
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{watch, Semaphore};
use tokio::task::JoinSet;
use tower::Service;
use tower_http::timeout::RequestBodyTimeoutLayer;

use crate::listeners::MinerRouterState;
use crate::mtls::MtlsAcceptor;
use crate::pipeline::EdgeError;

/// Container port the miner-facing relay binds. The `LoadBalancer`
/// Service publishes `:443` and maps it to this target port.
pub const MINER_LISTENER_PORT: u16 = 8443;

/// Upper bound on how long one connection may take to complete the
/// mTLS handshake. A peer that opens TCP but stalls the handshake is
/// dropped rather than parking a handler task (slow-loris guard).
/// Kept at or below the caller's shutdown grace so a connection
/// in-flight at shutdown drains within that grace.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);

/// Back-off after a transient `accept()` error, so an fd-exhaustion
/// spell cannot hot-spin the accept task.
const ACCEPT_BACKOFF: Duration = Duration::from_millis(10);

/// Request-**body** ingestion timeout, applied via a
/// [`RequestBodyTimeoutLayer`]. `HANDSHAKE_TIMEOUT` only bounds the
/// TLS handshake; without this an authenticated peer could open an
/// HTTP/2 stream and then drip a request body indefinitely into the
/// body extractor (`DefaultBodyLimit` caps size, never time).
///
/// This bounds ONLY body ingestion — the actual slow-loris vector —
/// NOT the handler or the forward. A whole-request timeout would be
/// wrong here: a valid envelope can pass validation, start a forward
/// (the reqwest client allows 30 s), and a 15 s outer cap would then
/// cancel the handler *before* it emits its §15 audit record →
/// an un-audited 408. With a body-only timeout the handler ALWAYS
/// reaches `relay()`'s telemetry emit: a slow / failed forward
/// becomes an audited 502, never an un-audited 408. A body that
/// never fully arrives never became an "envelope", so no audit is
/// owed — the connection just sees its stream reset.
const REQUEST_BODY_TIMEOUT: Duration = Duration::from_secs(15);

/// Max concurrent HTTP/2 streams per miner connection. One envelope
/// POST is one stream; a miner has no reason to fan out — this caps a
/// single peer opening thousands of slow streams on one connection.
const MAX_CONCURRENT_STREAMS: u32 = 16;

/// HTTP/2 keep-alive ping interval. The server pings an idle
/// connection; a peer that stops answering is dropped (see
/// [`H2_KEEPALIVE_TIMEOUT`]) — this reclaims a connection slot held
/// by a silently-dead or stalled peer.
const H2_KEEPALIVE_INTERVAL: Duration = Duration::from_secs(20);

/// How long the server waits for a keep-alive ping ACK before
/// dropping the connection. With [`H2_KEEPALIVE_INTERVAL`] this
/// bounds how long a dead/stalled peer can hold a connection slot
/// — but only AFTER the H2 connection is established (the keep-alive
/// pings arm post-preface).
const H2_KEEPALIVE_TIMEOUT: Duration = Duration::from_secs(10);

/// Deadline for a connection to dispatch its first request. Closes
/// the "negotiated `h2` ALPN, then never sent the H2 client preface"
/// residual: hyper's keep-alive pings only arm after the preface +
/// settings exchange, so a pre-preface silent peer is NOT covered by
/// `H2_KEEPALIVE_*`. A real miner client sends its preface and
/// envelope POST within milliseconds of the handshake — this bound
/// only ever catches a silent / stalled peer, and a connection that
/// has served ≥1 request is past it (and then governed by the
/// keep-alive pings).
const H2_FIRST_REQUEST_TIMEOUT: Duration = Duration::from_secs(15);

/// Upper bound on a single connection's post-`graceful_shutdown`
/// drain. After GOAWAY a connection with NO in-flight request
/// finishes fast, but one with a request mid-relay must be given
/// time to COMPLETE — its forward to the inner plane can run up to
/// the forward client's 30 s timeout, and cutting it earlier would
/// drop the envelope before `relay()` emits its §15 audit record.
/// So this bound covers the worst-case forward (30 s) + slack. A
/// peer that never sent the HTTP/2 preface has no in-flight request
/// and is dropped at once (it cannot reach this drain path with work
/// pending). Shutdown timing chain (each ≥ the previous + slack):
/// `GRACEFUL_DRAIN_TIMEOUT` (35 s, here) ≤ `main`'s `SHUTDOWN_GRACE`
/// (40 s) ≤ the Deployment's `terminationGracePeriodSeconds` (45 s).
const GRACEFUL_DRAIN_TIMEOUT: Duration = Duration::from_secs(35);

/// Maximum concurrent in-flight connection handlers. Each handler is
/// a mTLS handshake followed by an HTTP/2 envelope-relay session —
/// `HANDSHAKE_TIMEOUT` bounds the handshake but the session is
/// long-lived. Capping concurrency stops a mesh peer flooding the
/// accept loop into task / memory exhaustion; a connection beyond the
/// cap is shed at the TCP layer, no handshake.
const MAX_INFLIGHT_CONNS: usize = 256;

/// Run the miner-facing accept loop until `cancel` is signalled.
///
/// Each accepted TCP connection is handed to [`handle_miner_conn`] on
/// its own task, tracked in a [`JoinSet`] — NOT detached — so a
/// shutdown can drain in-flight connections rather than have the
/// runtime abort one mid-session. A transient `accept()` error backs
/// off briefly. When `cancel` changes (or its sender is dropped) the
/// loop stops accepting, drains the in-flight handler tasks, and
/// returns.
///
/// `router_state` is the [`crate::listeners::miner_router`] shared
/// state (forward client + telemetry sink); every accepted connection
/// is served the same router built from it.
pub async fn run_miner_listener(
    listener: TcpListener,
    acceptor: Arc<MtlsAcceptor>,
    router_state: MinerRouterState,
    mut cancel: watch::Receiver<bool>,
) {
    // In-flight per-connection handler tasks. Tracked, not detached.
    let mut conns: JoinSet<()> = JoinSet::new();
    // Concurrency cap on in-flight handlers (see MAX_INFLIGHT_CONNS).
    let permits = Arc::new(Semaphore::new(MAX_INFLIGHT_CONNS));

    // Already cancelled before the first accept — nothing to serve.
    if *cancel.borrow() {
        log_listener("shutdown");
        return;
    }
    loop {
        tokio::select! {
            // Any change (or a dropped sender) means "stop accepting".
            // `main` only ever flips this to `true` once.
            _ = cancel.changed() => {
                log_listener("shutdown");
                break;
            }
            accepted = listener.accept() => {
                let tcp = match accepted {
                    Ok((tcp, _addr)) => tcp,
                    // Transient accept error (e.g. fd pressure) — log a
                    // static class and back off so it cannot hot-spin
                    // the task.
                    Err(_) => {
                        log_listener("accept-error");
                        tokio::time::sleep(ACCEPT_BACKOFF).await;
                        continue;
                    }
                };
                // Bound concurrency — shed at the TCP layer (no
                // handshake) when at capacity. The permit is held by
                // the handler task and released when it ends.
                let permit = match Arc::clone(&permits).try_acquire_owned() {
                    Ok(permit) => permit,
                    Err(_) => {
                        log_rejected("at-capacity");
                        drop(tcp);
                        continue;
                    }
                };
                let acceptor = Arc::clone(&acceptor);
                let state = router_state.clone();
                // Each handler gets its OWN cancel receiver: a PR-H8
                // connection is a long-lived HTTP/2 session, so the
                // handler must stop its session on shutdown — the
                // accept-loop drain alone would block forever waiting
                // on a still-open keepalive connection.
                let conn_cancel = cancel.clone();
                conns.spawn(async move {
                    let _permit = permit;
                    handle_miner_conn(tcp, acceptor, state, conn_cancel).await;
                });
            }
            // Reap finished handler tasks so the set does not grow
            // without bound while the listener runs.
            Some(_) = conns.join_next(), if !conns.is_empty() => {}
        }
    }
    // Cancelled — stop accepting, then DRAIN the in-flight handler
    // tasks so each finishes cleanly. Every handler is bounded (the
    // handshake by `HANDSHAKE_TIMEOUT`; the HTTP session by the
    // caller's shutdown grace, which the `main` graceful-stop caps).
    while conns.join_next().await.is_some() {}
    log_listener("drained");
}

/// Drive one inbound miner connection: mTLS handshake, then serve the
/// envelope router over the TLS stream.
///
/// On a successful handshake the peer is CA-authenticated; its
/// [`crate::PeerId`] is logged and injected into the router as a
/// per-connection request `Extension`, and the
/// [`crate::listeners::miner_router`] axum router is served over the
/// HTTP/2-on-mTLS stream for the connection's lifetime. On a
/// handshake failure the static failure class is logged and the
/// connection dropped.
///
/// `cancel` is the shutdown signal: a PR-H8 connection is a
/// long-lived HTTP/2 session, so the serve loop is `select!`-ed
/// against `cancel.changed()` — on shutdown the connection is
/// gracefully closed rather than parking the accept-loop's drain.
async fn handle_miner_conn(
    tcp: TcpStream,
    acceptor: Arc<MtlsAcceptor>,
    router_state: MinerRouterState,
    mut cancel: watch::Receiver<bool>,
) {
    // The handshake is bounded — a peer that opens TCP but never
    // completes TLS cannot park this task.
    match tokio::time::timeout(HANDSHAKE_TIMEOUT, acceptor.accept(tcp)).await {
        Ok(Ok((peer_id, tls))) => {
            // ALPN gate — the wire is LOCKED to HTTP/2. The server
            // advertises `h2` only, but rustls still COMPLETES the
            // handshake for a client that offers no ALPN extension
            // (or `http/1.1`): that connection would then never send
            // an HTTP/2 preface and would park one of the
            // `MAX_INFLIGHT_CONNS` slots. Require the negotiated
            // protocol to be exactly `h2`, else drop here. This gate
            // is miner-listener-specific — the HA peer link reuses
            // `MtlsAcceptor` but not this function, so HA is
            // unaffected (its dialer offers no ALPN, by design).
            if tls.get_ref().1.alpn_protocol() != Some(b"h2") {
                log_rejected("alpn-not-h2");
                return;
            }
            log_connection("accepted", peer_id.as_str());
            // The router is the SAME for every connection; the only
            // per-connection difference is the authenticated peer
            // identity, layered on as a request `Extension`. Each
            // handler reads it back via `Extension<PeerId>`.
            //
            // `RequestBodyTimeoutLayer` bounds ONLY request-body
            // ingestion — the slow-loris vector — not the handler or
            // the forward. A peer that drips a body has its stream
            // reset; a valid envelope whose forward is slow still
            // reaches `relay()`'s §15 audit emit (an audited 502),
            // never an un-audited 408. See `REQUEST_BODY_TIMEOUT`.
            let router = crate::listeners::build_router(router_state)
                .layer(RequestBodyTimeoutLayer::new(REQUEST_BODY_TIMEOUT))
                .layer(Extension(peer_id.clone()));
            // `saw_request` is flipped true by the service the first
            // time hyper dispatches a request on this connection. It
            // closes the "negotiated `h2`, then never sent the H2
            // preface" residual: hyper's keep-alive pings only arm
            // AFTER the preface + settings exchange, so a pre-preface
            // silent peer is not covered by `keep_alive_*`. The guard
            // below drops such a connection after a bounded idle
            // window (see `H2_FIRST_REQUEST_TIMEOUT`).
            let saw_request = Arc::new(std::sync::atomic::AtomicBool::new(false));
            // axum `Router` → a `tower::Service<Request<Incoming>>`.
            // Wrap it per-hyper-request: hyper hands each request to a
            // fresh `service_fn` invocation; the router clone makes
            // that cheap (it is `Arc`-backed).
            let svc_saw_request = Arc::clone(&saw_request);
            let hyper_service = hyper::service::service_fn(move |req: hyper::Request<Incoming>| {
                svc_saw_request.store(true, std::sync::atomic::Ordering::Relaxed);
                let mut router = router.clone();
                async move { router.call(req).await }
            });
            // HTTP/2-ONLY connection server (the wire is LOCKED to
            // HTTP/2). The per-connection limits below stop one peer
            // parking the server: a max-concurrent-streams cap bounds
            // stream fan-out, and keep-alive pings reclaim a slot held
            // by a silently-dead / stalled peer once the connection is
            // established. The connection future supports graceful
            // shutdown: on a shutdown signal it drains in-flight
            // requests, then stops. A serve error (peer reset,
            // protocol error) is logged as a static class — the body
            // bytes never reach a log.
            let io = TokioIo::new(tls);
            let mut builder = http2::Builder::new(TokioExecutor::new());
            builder
                // The HTTP/2 keep-alive timers need a `Timer` — the
                // bare `http2::Builder` has none by default (the
                // `hyper_util::auto` builder wired one for us).
                .timer(TokioTimer::new())
                .max_concurrent_streams(MAX_CONCURRENT_STREAMS)
                .keep_alive_interval(H2_KEEPALIVE_INTERVAL)
                .keep_alive_timeout(H2_KEEPALIVE_TIMEOUT);
            let conn = builder.serve_connection(io, hyper_service);
            tokio::pin!(conn);
            // First-request guard: a connection that has not dispatched
            // a single request within `H2_FIRST_REQUEST_TIMEOUT` is a
            // silent peer (no H2 preface, so keep-alive never armed) —
            // drop it so it cannot hold a connection slot. A real
            // miner client sends its preface + envelope POST
            // immediately; once a connection has served ≥1 request
            // (`saw_request` is set) the guard is satisfied and the
            // connection is governed thereafter by the H2 keep-alive
            // pings. The deadline arm RE-CHECKS `saw_request` when it
            // fires (the `tokio::select!` precondition is evaluated
            // only once, so the re-check cannot live in an `if`
            // guard): if a request did arrive, the timer is ignored
            // and we fall through to plain serve-or-cancel.
            let first_request_deadline = tokio::time::sleep(H2_FIRST_REQUEST_TIMEOUT);
            tokio::pin!(first_request_deadline);
            let mut deadline_armed = true;
            loop {
                tokio::select! {
                    served = conn.as_mut() => {
                        if served.is_err() {
                            log_connection("session-error", peer_id.as_str());
                        }
                        break;
                    }
                    _ = &mut first_request_deadline, if deadline_armed => {
                        deadline_armed = false;
                        if !saw_request.load(std::sync::atomic::Ordering::Relaxed) {
                            // Deadline elapsed with zero requests
                            // dispatched — a post-handshake-silent
                            // peer. Drop the connection (`conn` drops
                            // at end of scope).
                            log_rejected("h2-idle-no-request");
                            break;
                        }
                        // A request DID arrive before the deadline —
                        // the connection is legit. Disarm the timer
                        // and keep serving (keep-alive now governs).
                    }
                    _ = cancel.changed() => {
                        // Shutdown: ask the connection to drain
                        // in-flight requests (sends GOAWAY), then
                        // finish. The drain await is BOUNDED so an
                        // unresponsive peer cannot hang the accept-
                        // loop drain; on timeout the connection future
                        // is dropped, abruptly closing the stream.
                        conn.as_mut().graceful_shutdown();
                        match tokio::time::timeout(GRACEFUL_DRAIN_TIMEOUT, conn).await {
                            Ok(Ok(())) => {}
                            Ok(Err(_)) => log_connection("session-error", peer_id.as_str()),
                            Err(_) => log_connection("drain-timeout", peer_id.as_str()),
                        }
                        break;
                    }
                }
            }
            log_connection("closed", peer_id.as_str());
        }
        Ok(Err(EdgeError::MtlsFailed(detail))) => {
            // Handshake failed: unknown CA, no / expired / revoked
            // client cert, no identity carrier, or CRL fail-closed.
            // `detail` is the specific static classifier — log it
            // directly (`EdgeError::class()` would flatten every mTLS
            // failure to "mtls-failed", losing the operator signal).
            log_rejected(detail);
        }
        Ok(Err(err)) => {
            // `MtlsAcceptor::accept` only ever returns `MtlsFailed`;
            // this arm is the type-exhaustive fallback.
            log_rejected(err.class());
        }
        Err(_) => {
            // The handshake did not complete within HANDSHAKE_TIMEOUT.
            log_rejected("handshake-timeout");
        }
    }
}

/// Log an authenticated connection event. `peer` is the mTLS-derived
/// `PeerId` — a CA-issued identity: auditable, never secret. It is
/// emitted via `{:?}` so any unexpected control characters in a
/// mis-issued cert's SAN / CN are escaped, never written raw to a log.
fn log_connection(outcome: &'static str, peer: &str) {
    eprintln!("hippius-edge-gateway: miner-connection: {outcome} peer={peer:?}");
}

/// Log a rejected connection — the handshake never yielded an
/// identity, so only the static failure class is emitted.
fn log_rejected(class: &'static str) {
    eprintln!("hippius-edge-gateway: miner-connection: rejected class={class}");
}

/// Log a listener-lifecycle event (static class only).
fn log_listener(event: &'static str) {
    eprintln!("hippius-edge-gateway: miner-listener: {event}");
}
