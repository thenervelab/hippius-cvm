//! `hippius-edge-gateway` — Edge / Miner Gateway binary entrypoint.
//!
//! Spec: `ARCHITECTURE.md` §5 (Edge = application relay, not IP
//! router), §9 (diode), §10 (compromise containment — rate limits +
//! bounded queues before anything reaches inner), §17.8 (sequenced
//! plan).
//!
//! **PR-H4 boot**: the binary now:
//!
//! 1. Loads [`EdgeGatewayConfig`] from `$EDGE_GATEWAY_CONFIG`
//!    (TOML) or falls back to baked defaults.
//! 2. Loads mTLS material from
//!    `$EDGE_MTLS_{CA,CERT,KEY}_PATH` and (optional) CRL from
//!    `$EDGE_MTLS_CRL_PATH`. Builds a TLS 1.3-only
//!    [`MtlsAcceptor`] via `rustls`. CRL polled every 60 s on a
//!    background tokio task; missing / corrupt CRL ⇒ fail-closed
//!    (acceptor drops every connection until the file comes back).
//! 3. Builds a [`PerSourceRateLimiter`] keyed on the mTLS-derived
//!    [`PeerId`] (the HA peer link folds its shed counters into the
//!    health beats).
//! 4. Builds the PR-H8 [`ReqwestForwardClient`] — the in-cluster
//!    relay egress to the KBS / vali.
//! 5. Parks on a SIGTERM/SIGINT shutdown signal so the spawned
//!    subsystems run for the process lifetime — the Edge is a
//!    long-lived service. (Before PR-K8 `main` ran a fixed
//!    mock-accept sweep and then exited.)
//!
//! **PR-H5 adds** an optional HA peer link (step 3b): when
//! `$EDGE_PEER_ENDPOINT` names the sister Edge instance, the binary
//! spawns the active/active peer link — an mTLS channel (PR-H4 CA +
//! cert reused) carrying health beats + shed counters, plus a
//! liveness watchdog and a Prometheus `/metrics` endpoint. There is
//! no leader election: a peer-down is logged + metered, never
//! promoted. Absent the env var, the Edge runs single-instance and
//! the HA subsystem stays dormant. See the `ha` module docs.
//!
//! **PR-H6 adds** the telemetry subsystem (step 2b): a boot-generated
//! Ed25519 signing key, a hash-chained audit log under `$EDGE_AUDIT_DIR`,
//! and a read-only `/v1/edge/{pubkey,audit/verify}` HTTP API. Every
//! relay transaction emits one signed, audit-chained telemetry
//! envelope (counters + routing metadata only — never body bytes).
//! §15 audit is mandatory: a telemetry-subsystem failure is boot-fatal
//! (`EXIT_AUDIT`). This closes §H.
//!
//! **PR-K8 wiring**: `main` stays up. Every subsystem above is a
//! background task; `main` parks on SIGTERM/SIGINT and returns
//! cleanly, so the Edge runs as a long-lived service.
//!
//! **PR-H7 adds** (step 5) the miner-facing `:443` mTLS relay
//! listener: a `TcpListener` whose every connection is driven through
//! the PR-H4 [`MtlsAcceptor`] — TLS 1.3, client cert REQUIRED,
//! verified against the hippius-compute CA, CRL fail-closed.
//!
//! **PR-H8 adds** (step 4b + 5) the miner↔Edge envelope protocol —
//! HTTP/2 over the mTLS stream. Each authenticated connection is now
//! served the [`MinerRouterState`] axum router (4 `MessageKind`
//! ingress routes); the router relays a validated envelope's body to
//! the in-cluster KBS / vali via a [`ReqwestForwardClient`] and emits
//! one signed telemetry record per transaction. On shutdown the
//! accept loop stops and each in-flight HTTP session is gracefully
//! drained within the shutdown grace.

use hippius_edge_gateway::edge_api::EDGE_API_PORT;
use hippius_edge_gateway::ha;
use hippius_edge_gateway::listeners::{
    run_inner_listener, run_lifecycle_listener, LifecycleForward, MinerRouterState,
    ReqwestLifecycleForward, INNER_LISTENER_PORT, LIFECYCLE_LISTENER_PORT,
};
use hippius_edge_gateway::miner_listener;
use hippius_edge_gateway::mtls::cert_store::{
    build_server_config_no_client_auth, load_cert_chain, load_key_pem,
};
use hippius_edge_gateway::mtls::{cert_store, registry, revocation, MtlsAcceptor, MtlsRuntime};
use hippius_edge_gateway::order_signing;
use hippius_edge_gateway::telemetry::TelemetrySink;
use hippius_edge_gateway::{
    EdgeApiServer, EdgeAuditSink, EdgeGatewayConfig, EdgeSigner, ForwardClient, MinerForward,
    OrderSigner, PerSourceRateLimiter, ReqwestForwardClient, ReqwestMinerForward,
    TelemetryRecorder,
};
use std::net::{Ipv4Addr, SocketAddr};
use std::path::Path;
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpListener;
use tokio::task::JoinHandle;
use tokio_rustls::TlsAcceptor;

/// Env var naming the directory the hash-chained telemetry audit log
/// lives in (PR-H6). Required — §15 audit is not optional.
const ENV_AUDIT_DIR: &str = "EDGE_AUDIT_DIR";

/// Exit code on config-load failure. Distinct from the mTLS / HA /
/// audit boot codes so the runbook can grep boot-time TOML errors
/// apart from the other fail-closed boot paths.
const EXIT_CONFIG: u8 = 3;

/// Exit code on mTLS material load failure (missing PEM, unreadable
/// key, etc.). Distinct from `EXIT_CONFIG` so the runbook can grep
/// `mtls-` separately — these failures point at the §B Q11 cert-
/// distribution path, not the TOML.
const EXIT_MTLS: u8 = 4;

/// Exit code on HA-subsystem boot failure (PR-H5): a malformed
/// `EDGE_PEER_ENDPOINT`, or a peer-link / metrics socket that failed
/// to bind. Distinct from `EXIT_MTLS` so the runbook greps `ha-`
/// separately. Note: a peer that is merely *unreachable* is NOT a
/// boot failure — the dialer just retries — so this only fires on
/// genuine local misconfiguration.
const EXIT_HA: u8 = 5;

/// Exit code on telemetry-subsystem boot failure (PR-H6): `EDGE_AUDIT_DIR`
/// unset, the audit log unopenable or tamper-detected at boot, or the
/// `/v1/edge/*` API socket failing to bind. Distinct so the runbook
/// greps `audit-` / `edge-api-` separately. §15 audit is mandatory —
/// the Edge refuses to boot without a working audit sink.
const EXIT_AUDIT: u8 = 6;

/// Exit code on the PR-H7 miner-facing relay listener failing to bind
/// its TCP port. Distinct so the runbook greps `miner-listener-` apart
/// from the other fail-closed boot paths.
const EXIT_MINER_LISTENER: u8 = 7;

/// Exit code on the PR-H8 in-cluster forward client failing to build
/// (a broken TLS backend). Distinct so the runbook greps `forward-`
/// apart from the other fail-closed boot paths.
const EXIT_FORWARD: u8 = 8;

/// Exit code on the §H phase-2 order-signing key load failing (the
/// operator set `EDGE_ORDER_SIGNING_KEY_PATH` but Vault-materialised
/// the wrong file, or the optional `EDGE_ORDER_SIGNING_EXPECTED_PUBKEY`
/// pin did not match the derived pubkey). Distinct so the runbook
/// greps `order-signing-` apart from the other fail-closed boot
/// paths. Unset `EDGE_ORDER_SIGNING_KEY_PATH` is NOT a failure: the
/// subsystem stays disabled and `main` boots through.
const EXIT_ORDER_SIGNING: u8 = 9;

/// Exit code on the inner-plane order-dispatch listener failing to bind
/// its TCP port (`EDGE_INNER_LISTENER_ADDR` malformed or port already
/// in use). Distinct so the runbook greps `inner-listener-` apart from
/// the miner-listener bind failure (`EXIT_MINER_LISTENER`). The inner
/// listener is only stood up when the order-signing subsystem loaded
/// successfully — an unset `EDGE_ORDER_SIGNING_KEY_PATH` skips this
/// bind entirely.
const EXIT_INNER_LISTENER: u8 = 10;

/// Exit code on the §24/§25 lifecycle stopped-ack relay listener
/// failing to build its TLS config or bind its TCP port (`:8446`).
/// Distinct so the runbook
/// greps `lifecycle-listener-` apart from the miner / inner listener
/// bind failures. This listener is unconditional — the §25 cold-
/// migration split-brain fence depends on the guest's stopped-ack
/// reaching vali through it.
const EXIT_LIFECYCLE_LISTENER: u8 = 11;

/// Env var optionally overriding the bind address of the inner-plane
/// order-dispatch listener. Defaults to `0.0.0.0:8444` (so the
/// cluster-internal Service can map a Pod port to it; the
/// NetworkPolicy gates access to the vali pod). Operator override is
/// only ever useful for bind-to-loopback in a local dev run.
const ENV_INNER_LISTENER_ADDR: &str = "EDGE_INNER_LISTENER_ADDR";

/// Grace period for the miner listener to drain after a shutdown
/// signal. A PR-H8 connection that is mid-relay at shutdown must be
/// allowed to FINISH so its §15 audit record is written — its
/// forward to the inner plane can run up to the forward client's
/// 30 s timeout. So this is sized above the listener's per-connection
/// `GRACEFUL_DRAIN_TIMEOUT` (35 s), with slack for the accept loop
/// itself to wind down. Shutdown timing chain (each ≥ the previous):
/// per-connection drain 35 s ≤ `SHUTDOWN_GRACE` 40 s ≤ the
/// edge-gateway Deployment's `terminationGracePeriodSeconds` 45 s
/// (set explicitly there — the k8s default of 30 s would SIGKILL the
/// pod before a worst-case in-flight relay completes).
const SHUTDOWN_GRACE: Duration = Duration::from_secs(40);

#[tokio::main(flavor = "current_thread")]
async fn main() -> ExitCode {
    // (1) Config. Absence is fine (defaults); a TOML present at
    //     `$EDGE_GATEWAY_CONFIG` that fails to parse / validate is fatal.
    let cfg = match EdgeGatewayConfig::load_from_env() {
        Ok(c) => c,
        Err(e) => {
            log_fatal(config_error_class(&e));
            return ExitCode::from(EXIT_CONFIG);
        }
    };

    // (2) mTLS material. CA + own cert/key are required; CRL is
    //     optional (operator opts in via `EDGE_MTLS_CRL_PATH`, see
    //     `mtls::cert_store`). If a CRL path was specified but the
    //     initial load failed, the acceptor starts unhealthy and the
    //     CRL poller will flip it back when the file appears.
    let cert_paths = match cert_store::CertPaths::from_env() {
        Ok(p) => p,
        Err(e) => {
            log_fatal(e.class());
            return ExitCode::from(EXIT_MTLS);
        }
    };
    // Miner-auth mode (`EDGE_MINER_AUTH`, default `ca`). `onchain` is
    // the permissionless model: self-signed identity certs gated on
    // the on-chain registered+`Active` set — no operator CA. A
    // malformed `onchain` env is boot-fatal (never a silent CA
    // fallback). See `docs/design/permissionless-miner-auth.md`.
    let registry_env = match registry::from_env() {
        Ok(r) => r,
        Err(e) => {
            log_fatal(e.class());
            return ExitCode::from(EXIT_MTLS);
        }
    };
    let runtime = match &registry_env {
        None => MtlsRuntime::load(cert_paths),
        Some(env) => {
            let store = Arc::new(registry::RegistryStore::new(
                env.feed_url.clone(),
                env.feed_pubkey,
            ));
            MtlsRuntime::load_onchain(cert_paths, store)
        }
    };
    let runtime = match runtime {
        Ok(r) => r,
        Err(e) => {
            log_fatal(e.class());
            return ExitCode::from(EXIT_MTLS);
        }
    };
    let acceptor = Arc::new(MtlsAcceptor::new(Arc::clone(&runtime)));
    // CRL poller (CA mode). Spawned only if the operator configured a
    // CRL path; without one there's nothing to poll. On each tick it
    // calls `runtime.refresh()` which re-reads the CRL file and
    // rebuilds the live `ServerConfig` with the fresh snapshot.
    let _crl_poller = if runtime.has_crl_store() {
        Some(revocation::spawn_poller(Arc::clone(&runtime)))
    } else {
        None
    };
    // Registry poller (on-chain mode). Refreshes the registered+
    // `Active` allow set from the chain every `refresh` seconds; the
    // accept gate fails closed while the snapshot is stale.
    let _registry_poller = match (&registry_env, runtime.registry()) {
        (Some(env), Some(store)) => Some(registry::spawn_poller(Arc::clone(store), env.refresh)),
        _ => None,
    };

    // (2b) Telemetry subsystem (PR-H6, §15). Generates the Edge's own
    //      Ed25519 signing key at boot (in-memory, never from Vault),
    //      opens the hash-chained audit log under `$EDGE_AUDIT_DIR`,
    //      and spawns the read-only `/v1/edge/{pubkey,audit/verify}`
    //      HTTP API. Every relay transaction below emits one signed,
    //      audit-chained telemetry envelope through `recorder`. §15
    //      audit is mandatory — a failure here is boot-fatal.
    let (recorder, _edge_api) = match start_telemetry().await {
        Ok(t) => t,
        Err(class) => {
            log_fatal(class);
            return ExitCode::from(EXIT_AUDIT);
        }
    };

    // (3) Per-source rate limiter. `Arc` on the limiter is load-
    //     bearing for the HA peer link, which folds the limiter's
    //     shed counters into its outgoing health beats (the limiter
    //     is NOT `Clone` — its `Mutex<HashMap>` would be unsound to
    //     clone). PR-H8: the miner router relays via the
    //     `ForwardClient` directly, so the PR-H1 bounded
    //     validate→forward queue is no longer assembled here — the
    //     `queue` module + `relay_once` remain library code for the
    //     pipeline integration tests.
    let limiter = Arc::new(PerSourceRateLimiter::from_config(&cfg));

    // (3b) HA peer link (PR-H5). Active/active — no leader election,
    //      no Raft, no shared state. Enabled only when the operator
    //      points `EDGE_PEER_ENDPOINT` at the sister Edge instance;
    //      absent, the Edge runs single-instance and the HA subsystem
    //      (peer link + watchdog + Prometheus `/metrics`) stays
    //      dormant. The peer link reuses the PR-H4 mTLS CA + cert —
    //      always mTLS, never plaintext — and carries health beats +
    //      shed counters so each instance can OBSERVE the other.
    //      Neither instance ever promotes (see the `ha` module docs).
    //      The handle is held in `_ha` for the process lifetime; like
    //      the PR-H4 CRL poller it is torn down when `main` returns.
    let _ha = match start_ha(&runtime, &limiter).await {
        Ok(handle) => handle,
        Err(class) => {
            log_fatal(class);
            return ExitCode::from(EXIT_HA);
        }
    };

    // (4) PR-H8 forward client. The in-cluster reqwest client that
    //     relays a validated envelope's body to the KBS / vali
    //     endpoints (TLS 1.3, rustls, no native-tls, no mTLS — the
    //     Cilium NetworkPolicy is the who-calls-who control). Built
    //     from the config's `[forward]` endpoints, which default to
    //     the cluster-DNS service names. A builder failure is
    //     boot-fatal (a broken TLS backend) — fail-closed.
    // The served-receipt JSON path authenticates to vali with a
    // ServiceToken bearer (the raw-CBOR heartbeat path is token-exempt).
    // Sourced from a k8s Secret via env — never the config file.
    let vali_ingest_token = std::env::var("HIPPIUS_EDGE_VALI_INGEST_TOKEN").ok();
    let forward_client: Arc<dyn ForwardClient> = match ReqwestForwardClient::new(
        cfg.forward.kbs_endpoint.clone(),
        cfg.forward.vali_endpoint.clone(),
        vali_ingest_token,
    ) {
        Ok(c) => Arc::new(c),
        Err(e) => {
            log_fatal(e.class());
            return ExitCode::from(EXIT_FORWARD);
        }
    };
    // The miner-router shared state: the forward client + the
    // telemetry recorder. Every relayed envelope emits one signed,
    // audit-chained telemetry record through `recorder` (§15). The
    // method-form `.clone()` resolves on the concrete `Arc`, then the
    // `let` annotation drives the unsizing coercion to the trait
    // object (`Arc::clone` can't — it would unify the type param).
    let telemetry_sink: Arc<dyn TelemetrySink + Send + Sync> = recorder.clone();
    // Share the SAME limiter `Arc` the HA peer link folds into its health
    // beats (audit M-ratelimit) — the miner router now enforces it per
    // request, unifying the shed counters.
    let router_state = MinerRouterState::new(forward_client, telemetry_sink, Arc::clone(&limiter));

    // (4b) Order-signing key (§H phase-2 follow-up). OPTIONAL — when
    //      `EDGE_ORDER_SIGNING_KEY_PATH` is unset the subsystem stays
    //      disabled and the Edge boots through (existing clusters are
    //      unaffected by this PR). When set, the priv key is loaded
    //      from the Vault-materialised file at that path; an optional
    //      `EDGE_ORDER_SIGNING_EXPECTED_PUBKEY` pins the expected
    //      pubkey in deployment config and fails closed on mismatch
    //      (catches a Vault key that drifted from the one the
    //      Ansible-rendered miner config pins). The loaded pubkey is
    //      logged once at boot so operators can visually confirm it
    //      matches every miner's `edge.order_signing_pubkey`. The
    //      handle is held for the process lifetime; the matching
    //      `POST /v1/edge/order` route + Edge → miner forwarder is a
    //      follow-up — until they land, the chain is exercised by
    //      operator-side smoke (see README "Order signing").
    let _order_signer = match start_order_signing() {
        Ok(Some(s)) => {
            log_order_signing_up(&hex::encode(s.public_key_bytes()));
            Some(s)
        }
        Ok(None) => {
            log_lifecycle("order-signing-disabled");
            None
        }
        Err(class) => {
            log_fatal(class);
            return ExitCode::from(EXIT_ORDER_SIGNING);
        }
    };

    // (5) Miner-facing :443 mTLS relay listener (PR-H7 + PR-H8, §H
    //     phase 2). Binds the miner port and drives every inbound
    //     connection through the PR-H4 handshake — TLS 1.3 only, client
    //     cert REQUIRED, verified against the hippius-compute CA, CRL
    //     fail-closed. PR-H8: each authenticated connection is then
    //     served the envelope router (HTTP/2 over the mTLS stream).
    let miner_addr = SocketAddr::from((Ipv4Addr::UNSPECIFIED, miner_listener::MINER_LISTENER_PORT));
    // This bind is the last boot step: a failure here returns after the
    // other subsystems are already spawned, so they (and the audit
    // sink) are torn down by the runtime rather than stopped cleanly.
    // A `:8443` port conflict is a rare boot-time misconfiguration and
    // the pod simply restarts — the asymmetry vs. the earlier `EXIT_*`
    // paths is accepted rather than reordering the boot sequence.
    let miner_tcp = match TcpListener::bind(miner_addr).await {
        Ok(listener) => listener,
        Err(_) => {
            log_fatal("miner-listener-bind");
            return ExitCode::from(EXIT_MINER_LISTENER);
        }
    };
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let miner_task = tokio::spawn(miner_listener::run_miner_listener(
        miner_tcp,
        Arc::clone(&acceptor),
        router_state,
        shutdown_rx.clone(),
    ));
    log_lifecycle("miner-listener-up");

    // (5b) Inner-plane order-dispatch listener (§H phase-2 follow-up).
    //      Plain HTTP, cluster-internal — NetworkPolicy gates access to
    //      the vali pod. Stood up ONLY when the order-signing subsystem
    //      loaded successfully: a None `_order_signer` means the
    //      operator opted out, and this listener is skipped entirely
    //      (existing clusters that have not yet provisioned the Vault
    //      seed are unaffected). The forwarder is the production
    //      `ReqwestMinerForward` (HTTP, 5s connect / 30s request, 64
    //      KiB caps) — built once and shared with the router state.
    let inner_task = match _order_signer.as_ref().cloned() {
        Some(signer) => {
            let forward: Arc<dyn MinerForward> = match ReqwestMinerForward::new() {
                Ok(c) => Arc::new(c),
                Err(e) => {
                    log_fatal(e.class());
                    return ExitCode::from(EXIT_INNER_LISTENER);
                }
            };
            let inner_addr = match resolve_inner_listener_addr() {
                Ok(a) => a,
                Err(class) => {
                    log_fatal(class);
                    return ExitCode::from(EXIT_INNER_LISTENER);
                }
            };
            let inner_tcp = match TcpListener::bind(inner_addr).await {
                Ok(listener) => listener,
                Err(_) => {
                    log_fatal("inner-listener-bind");
                    return ExitCode::from(EXIT_INNER_LISTENER);
                }
            };
            let task = tokio::spawn(run_inner_listener(
                inner_tcp,
                signer,
                forward,
                shutdown_rx.clone(),
            ));
            log_lifecycle("inner-listener-up");
            Some(task)
        }
        None => {
            // Subsystem disabled — no inner listener at all (vali's
            // order-dispatch path is correspondingly off; the existing
            // miner heartbeat / KBS-request relays are unaffected).
            log_lifecycle("inner-listener-skipped");
            None
        }
    };

    // (5c) §24/§25 lifecycle stopped-ack relay listener. TLS 1.3,
    //      server-cert-only (NO client cert): the confidential guest's
    //      stopped-ack is relayed by its miner host's vsock proxy with a
    //      reqwest client that presents no client cert but DOES verify
    //      the Edge's server cert (which carries the Edge LB's mesh
    //      address as an IP: SAN, so the miner dials the LB IP
    //      directly over the mesh — no
    //      public DNS / public cert needed). The route forwards the
    //      opaque ack verbatim to vali's `/v1/lifecycle/stopped` ingress
    //      (the `StoppedAckIngest` store `effects.poll_source_ack`
    //      reads). The forward leg reuses the configured vali base; no
    //      mTLS on it (the Cilium NetworkPolicy is the who-calls-who
    //      control). UNCONDITIONAL — the §25 split-brain fence depends on
    //      this hop; a build / bind failure is boot-fatal.
    let lifecycle_forward: Arc<dyn LifecycleForward> =
        match ReqwestLifecycleForward::new(cfg.forward.vali_endpoint.clone()) {
            Ok(c) => Arc::new(c),
            Err(e) => {
                log_fatal(e.class());
                return ExitCode::from(EXIT_LIFECYCLE_LISTENER);
            }
        };
    // Build the server-cert-only TLS acceptor from the SAME Edge cert +
    // key the mTLS relay presents (re-read the env paths — cheap, and
    // `cert_paths` was already moved into the MtlsRuntime above).
    let lifecycle_tls = match build_lifecycle_tls() {
        Ok(acc) => acc,
        Err(class) => {
            log_fatal(class);
            return ExitCode::from(EXIT_LIFECYCLE_LISTENER);
        }
    };
    let lifecycle_addr = SocketAddr::from((Ipv4Addr::UNSPECIFIED, LIFECYCLE_LISTENER_PORT));
    let lifecycle_tcp = match TcpListener::bind(lifecycle_addr).await {
        Ok(listener) => listener,
        Err(_) => {
            log_fatal("lifecycle-listener-bind");
            return ExitCode::from(EXIT_LIFECYCLE_LISTENER);
        }
    };
    let lifecycle_task = tokio::spawn(run_lifecycle_listener(
        lifecycle_tcp,
        lifecycle_tls,
        lifecycle_forward,
        shutdown_rx.clone(),
    ));
    log_lifecycle("lifecycle-listener-up");

    wait_for_shutdown().await;
    log_lifecycle("shutdown-signal");

    // Graceful stop: signal both accept loops to stop taking new
    // connections; each then drains in-flight handshakes / sessions.
    // Both listeners share ONE deadline (`SHUTDOWN_GRACE` from now) —
    // sequentially-counted timeouts would let two slow drains exceed
    // the Deployment's 45 s `terminationGracePeriodSeconds` and have
    // the kubelet SIGKILL the pod mid-drain (review r1 Medium).
    let _ = shutdown_tx.send(true);
    let deadline = tokio::time::Instant::now() + SHUTDOWN_GRACE;
    match tokio::time::timeout_at(deadline, miner_task).await {
        Ok(Ok(())) => log_lifecycle("miner-listener-drained"),
        // The listener task panicked — surface it distinctly so the
        // runbook can grep it apart from a clean drain.
        Ok(Err(_)) => log_lifecycle("miner-listener-panic"),
        Err(_) => log_lifecycle("miner-listener-drain-timeout"),
    }
    if let Some(task) = inner_task {
        // Same `deadline` as the miner listener — the inner listener's
        // handler pipeline is short (sign + forward) so under normal
        // conditions it has drained long before this point. A miner
        // listener that ate most of the grace shortens (or zeroes)
        // the inner one's window, which is correct: the alternative
        // is an un-drained pod being SIGKILLed.
        match tokio::time::timeout_at(deadline, task).await {
            Ok(Ok(())) => log_lifecycle("inner-listener-drained"),
            Ok(Err(_)) => log_lifecycle("inner-listener-panic"),
            Err(_) => log_lifecycle("inner-listener-drain-timeout"),
        }
    }
    // Drain the lifecycle relay listener on the SAME deadline — its
    // handler pipeline is short (relay one ack to vali), so it has
    // normally drained long before this point.
    match tokio::time::timeout_at(deadline, lifecycle_task).await {
        Ok(Ok(())) => log_lifecycle("lifecycle-listener-drained"),
        Ok(Err(_)) => log_lifecycle("lifecycle-listener-panic"),
        Err(_) => log_lifecycle("lifecycle-listener-drain-timeout"),
    }
    ExitCode::SUCCESS
}

/// Resolve the inner-plane listener's bind address from
/// `EDGE_INNER_LISTENER_ADDR` (set in deployment YAML to a cluster-
/// internal address) or, when unset, default to `0.0.0.0:INNER_LISTENER_PORT`.
/// A malformed value returns a static classifier — fail-closed so the
/// runbook catches a typo at boot rather than serving on an unexpected
/// interface.
fn resolve_inner_listener_addr() -> Result<SocketAddr, &'static str> {
    match std::env::var(ENV_INNER_LISTENER_ADDR) {
        Ok(s) if !s.is_empty() => s.parse().map_err(|_| "inner-listener-addr-malformed"),
        // Set-but-empty is treated as malformed (same posture as the
        // order-signing env vars) — never silently fall back to the
        // wildcard bind when the operator did set the env var.
        Ok(_) => Err("inner-listener-addr-malformed"),
        Err(_) => Ok(SocketAddr::from((
            Ipv4Addr::UNSPECIFIED,
            INNER_LISTENER_PORT,
        ))),
    }
}

/// Build the server-cert-only TLS acceptor for the §24/§25 lifecycle
/// stopped-ack relay listener. Re-reads the Edge cert + key from the
/// same `EDGE_MTLS_{CERT,KEY}_PATH` env paths the mTLS runtime used
/// (cheap; `CertPaths` was already moved into the `MtlsRuntime`). The
/// config presents the Edge cert with NO client-cert verifier — the
/// stopped-ack hop has no client cert; the access control is the
/// CiliumNetworkPolicy + vali's fail-closed verifier. Returns a static
/// classifier on any load / build failure so the boot fails closed.
fn build_lifecycle_tls() -> Result<TlsAcceptor, &'static str> {
    let paths = cert_store::CertPaths::from_env().map_err(|e| e.class())?;
    let chain = load_cert_chain(&paths.cert).map_err(|e| e.class())?;
    let key = load_key_pem(&paths.key).map_err(|e| e.class())?;
    let config = build_server_config_no_client_auth(chain, key).map_err(|e| e.class())?;
    Ok(TlsAcceptor::from(Arc::new(config)))
}

/// Park until the process receives a termination signal — SIGTERM
/// (Kubernetes pod stop / `systemctl stop`) or SIGINT (Ctrl-C). The
/// relay pipeline is stateless by the PR-H1 invariant, so a clean
/// shutdown is just "stop hosting the servers and return" — there is
/// nothing buffered to drain. Panic-free: if a signal handler cannot
/// be installed its branch is dropped and the other still arms; if
/// neither can, the process runs until the runtime is torn down.
async fn wait_for_shutdown() {
    use tokio::signal::unix::{signal, SignalKind};
    let mut sigterm = signal(SignalKind::terminate()).ok();
    let mut sigint = signal(SignalKind::interrupt()).ok();
    match (sigterm.as_mut(), sigint.as_mut()) {
        (Some(term), Some(int)) => {
            tokio::select! {
                _ = term.recv() => {}
                _ = int.recv() => {}
            }
        }
        (Some(term), None) => {
            term.recv().await;
        }
        (None, Some(int)) => {
            int.recv().await;
        }
        (None, None) => std::future::pending::<()>().await,
    }
}

/// Bring up the PR-H6 telemetry subsystem.
///
/// Generates the Edge's boot-time Ed25519 signing key, opens the
/// hash-chained audit log at `$EDGE_AUDIT_DIR`, and spawns the
/// read-only `/v1/edge/*` HTTP API on [`EDGE_API_PORT`]. Returns the
/// telemetry recorder (passed to every `relay_once` call) plus the
/// API server's task handle, held for the process lifetime. `Err` is
/// a static classifier: `EDGE_AUDIT_DIR` unset, the audit log
/// unopenable / tamper-detected at boot, or the API socket failing to
/// bind.
async fn start_telemetry() -> Result<(Arc<TelemetryRecorder>, JoinHandle<()>), &'static str> {
    // §15 audit is mandatory — refuse to boot without a directory.
    let audit_dir = match std::env::var(ENV_AUDIT_DIR) {
        Ok(d) if !d.is_empty() => d,
        _ => return Err("audit-dir-missing"),
    };
    // `EdgeAuditSink::open` walks the existing log, so a tamper that
    // happened while the process was down is caught here, at boot.
    let audit = Arc::new(EdgeAuditSink::open(audit_dir).map_err(|e| e.class())?);
    // A fresh keypair every boot — rotation is redeploy (see `signer`).
    let signer = Arc::new(EdgeSigner::generate());
    // `Arc` so the recorder can be shared with the PR-H8 miner router
    // (every relayed envelope emits one signed telemetry record).
    let recorder = Arc::new(TelemetryRecorder::new(
        Arc::clone(&signer),
        Arc::clone(&audit),
    ));

    // The read-only API binds all interfaces on the fixed port;
    // Sentinel + the Validator fetch the pubkey + audit head here.
    let api_addr = SocketAddr::from((Ipv4Addr::UNSPECIFIED, EDGE_API_PORT));
    let api = EdgeApiServer::bind(api_addr).await?;
    let api_task = tokio::spawn(api.run(signer, audit));
    Ok((recorder, api_task))
}

/// Bring up the PR-H5 HA subsystem.
///
/// Returns `Ok(None)` when `EDGE_PEER_ENDPOINT` is unset
/// (single-instance mode), `Ok(Some(handle))` when the peer link is
/// running, and `Err(class)` — a static classifier — when the
/// endpoint is malformed or a socket fails to bind. The peer link
/// reuses `runtime` (PR-H4 mTLS CA + cert) for both its listener and
/// its dialer; `limiter` is the shed-counter source folded into the
/// outgoing health beats.
async fn start_ha(
    runtime: &Arc<MtlsRuntime>,
    limiter: &Arc<PerSourceRateLimiter>,
) -> Result<Option<ha::HaHandle>, &'static str> {
    let Some(ha_cfg) = ha::HaConfig::from_env().map_err(|e| e.class())? else {
        return Ok(None);
    };
    // Production binds the fixed vRack-internal ports on all
    // interfaces; the sister instance's `EDGE_PEER_ENDPOINT` points
    // back here at `PEER_LINK_PORT`.
    let listen = SocketAddr::from((Ipv4Addr::UNSPECIFIED, ha::PEER_LINK_PORT));
    let metrics = SocketAddr::from((Ipv4Addr::UNSPECIFIED, ha::METRICS_PORT));
    // `Arc<PerSourceRateLimiter>` → `Arc<dyn LocalShedSource>`: the HA
    // layer depends on the trait, not the concrete limiter. The
    // method-form clone resolves on the concrete receiver, then the
    // `let` annotation drives the unsizing coercion to the trait
    // object (`Arc::clone` can't — it would unify the type param).
    let shed: Arc<dyn ha::LocalShedSource> = limiter.clone();
    let node = ha::HaNode::bind(
        Arc::clone(runtime),
        listen,
        metrics,
        ha::HaTiming::production(),
        shed,
    )
    .await
    .map_err(|e| e.class())?;
    Ok(Some(node.start(ha_cfg.peer_endpoint)))
}

/// Bring up the §H phase-2 order-signing subsystem.
///
/// Returns `Ok(None)` when `EDGE_ORDER_SIGNING_KEY_PATH` is unset —
/// the subsystem stays disabled and the Edge boots through unchanged,
/// so this PR's chart toggle defaults to off keep existing clusters
/// working. Returns `Ok(Some(signer))` when the priv key loaded and
/// (when set) matched `EDGE_ORDER_SIGNING_EXPECTED_PUBKEY`. Returns
/// `Err(class)` — a static classifier — on any load failure: an
/// empty env-var value, a missing / unreadable seed file, a malformed
/// hex, a pubkey mismatch.
///
/// The Vault-materialised seed file at the given path holds the raw
/// 32-byte Ed25519 seed as 64 lowercase-hex chars (the same shape the
/// miner-agent's `edge.order_signing_pubkey` uses).
fn start_order_signing() -> Result<Option<Arc<OrderSigner>>, &'static str> {
    let path = match std::env::var(order_signing::ENV_KEY_PATH) {
        Ok(s) if !s.is_empty() => s,
        // Set-but-empty is an explicit misconfig (the operator did
        // set the env var, just to nothing). Fail closed so the
        // runbook grep catches the typo instead of treating it as
        // "subsystem deliberately disabled".
        Ok(_) => return Err(order_signing::OrderSigningError::EnvEmpty.class()),
        Err(_) => return Ok(None),
    };
    let expected = match std::env::var(order_signing::ENV_EXPECTED_PUBKEY) {
        Ok(s) if !s.is_empty() => Some(s),
        // Symmetric with `ENV_KEY_PATH` (just above): set-but-empty
        // is an explicit operator misconfig (the env var was set;
        // an empty hex pin is malformed). The chart omits the env
        // var entirely when the Helm value is empty, so seeing an
        // empty value here means manual interference — fail closed.
        // (review r1 medium.)
        Ok(_) => return Err(order_signing::OrderSigningError::ExpectedPubkeyHex.class()),
        Err(_) => None,
    };
    let signer = OrderSigner::load(Path::new(&path), expected.as_deref()).map_err(|e| e.class())?;
    Ok(Some(signer))
}

/// Static-string-only diagnostic emitter for fail-closed events:
/// config invalid at boot, worker gone, worker panicked. Mirror of
/// `hippius-agent-initramfs::log_fatal`. Production (PR-H6) routes
/// this through the audit sink; the call contract stays the same —
/// `&'static str` only.
fn log_fatal(class: &'static str) {
    eprintln!("hippius-edge-gateway: fail-closed: {class}");
}

/// Static-string-only emitter for process-lifecycle events (a clean
/// shutdown). Same `&'static str` discipline as `log_fatal`, with a
/// distinct `lifecycle:` prefix.
fn log_lifecycle(class: &'static str) {
    eprintln!("hippius-edge-gateway: lifecycle: {class}");
}

/// Lifecycle event for the order-signing boot, carrying the loaded
/// pubkey hex. The pubkey is PUBLIC — the same value sits in every
/// miner's `edge.order_signing_pubkey` — so it is safe to log, and
/// the operator NEEDS to be able to read it to confirm the Ansible
/// match. Static-prefix, dynamic-value-only-for-the-pubkey (not a key
/// classifier — that stays `&'static str` everywhere else).
fn log_order_signing_up(pubkey_hex: &str) {
    eprintln!("hippius-edge-gateway: lifecycle: order-signing-up pubkey={pubkey_hex}");
}

/// Map a [`hippius_edge_gateway::config::ConfigError`] to its static
/// classifier without going through `Display` (which is also a
/// static string, but keeping the mapping inside the binary keeps
/// the `&'static str` contract local to the call site).
fn config_error_class(err: &hippius_edge_gateway::config::ConfigError) -> &'static str {
    use hippius_edge_gateway::config::ConfigError::*;
    match err {
        Read => "config-read",
        Parse => "config-parse",
        Invalid(_) => "config-invalid",
    }
}
