//! The §K heartbeat pusher (PR-MA-6).
//!
//! [`run_pusher`] is the tokio task that drains the bounded
//! [`HeartbeatQueue`] and POSTs each signed heartbeat over mTLS to the
//! Edge gateway's `/v1/edge/heartbeat` route. It is the miner-agent's
//! only outward heartbeat surface.
//!
//! ## Transport — mTLS, TLS 1.3 only
//!
//! [`ReqwestHeartbeatClient`] builds a `reqwest` client from the
//! operator-provisioned mTLS material (the same CA + client cert + key
//! PR-H7 uses): `rustls` only (no native-tls), a TLS-1.3 floor, and a
//! short connect / request timeout. The heartbeat body is posted
//! verbatim as `application/cbor` — the Edge relays it opaquely.
//!
//! ## Backoff — capped, responsively cancellable
//!
//! A failed POST does not drop the heartbeat: the pusher backs off
//! exponentially (1s, 2s, 4s … capped at [`MAX_BACKOFF`]) and retries.
//! Every sleep — the idle wait and the backoff wait alike — races the
//! [`CancellationToken`], so a shutdown is honoured immediately and
//! never has to wait out a 60-second backoff.
//!
//! ## Logging discipline (§K)
//!
//! A log line carries only the heartbeat `body_hash` (hex), the
//! `kind`, an outcome classifier, and counters — NEVER the body bytes.

use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use hippius_types::heartbeat::{SignedMinerHeartbeat, MAX_AGE_SECONDS};
use tokio_util::sync::CancellationToken;

use crate::config::EdgeSection;
use crate::error::{MinerAgentError, Result};
use crate::identity::MinerIdentity;

use super::queue::HeartbeatQueue;

/// `content-type` of the posted heartbeat body — canonical CBOR. The
/// Edge `/v1/edge/heartbeat` route speaks this on the §9 wire.
const CONTENT_TYPE_CBOR: &str = "application/cbor";

/// The Edge route a heartbeat is POSTed to. Appended to the
/// configured Edge endpoint.
const HEARTBEAT_ROUTE: &str = "/v1/edge/heartbeat";

/// Strict TCP+TLS connect timeout — a peer slower than this is treated
/// as unreachable (the heartbeat is retried after a backoff).
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

/// Strict whole-request timeout (send + Edge work + response read).
const REQUEST_TIMEOUT: Duration = Duration::from_secs(15);

/// First backoff step after a failed POST.
const INITIAL_BACKOFF: Duration = Duration::from_secs(1);

/// Hard cap on the exponential backoff — a long-down Edge never
/// stretches the retry interval past one minute.
pub const MAX_BACKOFF: Duration = Duration::from_secs(60);

/// Wall-clock cap on the graceful-shutdown final drain pass. An
/// unreachable Edge makes each `drain_once` push block up to
/// `REQUEST_TIMEOUT`; without this bound a full queue could stall
/// process exit. Kept strictly below `main`'s `HEARTBEAT_DRAIN_GRACE`
/// so the pusher task always returns inside that grace.
const DRAIN_BUDGET: Duration = Duration::from_secs(7);

/// Safety margin (seconds) carved out of vali's anti-skew window for
/// the pusher's local staleness check — a heartbeat is dropped before
/// it is sent once its `timestamp_unix` is more than
/// [`STALE_AFTER_SECS`] behind the current wall clock. 60 s gives the
/// build→push pipeline comfortable headroom to deliver inside vali's
/// 300 s window even under a brief Edge stall.
const STALE_SAFETY_MARGIN_SECS: i64 = 60;

/// Threshold (seconds) past which a queued or in-flight heartbeat is
/// considered stale by the pusher and dropped without sending — vali
/// would reject it anyway, and re-signing would break the canonical-
/// CBOR signed-envelope invariant. Equals
/// `MAX_AGE_SECONDS - STALE_SAFETY_MARGIN_SECS` (240 s with the
/// 300 s anti-skew window).
const STALE_AFTER_SECS: i64 = MAX_AGE_SECONDS - STALE_SAFETY_MARGIN_SECS;

/// Outcome of one heartbeat delivery attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PushOutcome {
    /// The Edge accepted the heartbeat (a 2xx response).
    Delivered,
    /// The Edge answered with a non-2xx status — a transient inner
    /// failure; the heartbeat is retried after a backoff.
    Rejected,
    /// The request did not reach the Edge / no response — DNS,
    /// connect, TLS, or timeout. Retried after a backoff.
    Transport,
}

/// The seam the pusher delivers through. Production is
/// [`ReqwestHeartbeatClient`]; tests inject a mock.
#[async_trait]
pub trait HeartbeatClient: Send + Sync {
    /// POST one signed heartbeat to the Edge. Returns the
    /// [`PushOutcome`] — `Delivered` clears the backoff, anything else
    /// retries.
    async fn push(&self, signed: &SignedMinerHeartbeat) -> PushOutcome;
}

/// Production [`HeartbeatClient`] — a `reqwest` mTLS client.
pub struct ReqwestHeartbeatClient {
    client: reqwest::Client,
    /// Full `https://…/v1/edge/heartbeat` URL, resolved once at boot.
    url: String,
}

impl ReqwestHeartbeatClient {
    /// Build the mTLS client from the `[edge]` config + the node
    /// identity.
    ///
    /// The CA pins the Edge server cert. The client identity is the
    /// miner's mTLS cert: in the permissionless model (the prod
    /// default) the agent mints a **self-signed** cert from `identity`
    /// whose key IS the node identity (no operator CA); if the legacy
    /// `client_cert`/`client_key` are pinned in config, those are used
    /// instead. `rustls` only, TLS 1.3 floor. Fails closed at boot
    /// ([`MinerAgentError::HeartbeatClient`]) on any material problem so
    /// a misconfigured miner never silently degrades to no heartbeats.
    pub fn new(edge: &EdgeSection, identity: &MinerIdentity) -> Result<Self> {
        let client = build_edge_mtls_client(edge, identity)?;
        let url = format!("{}{}", edge.endpoint.trim_end_matches('/'), HEARTBEAT_ROUTE);
        Ok(Self { client, url })
    }
}

/// Build the miner→Edge mTLS `reqwest` client from the `[edge]` config +
/// node identity — the single mTLS-transport code path shared by the §K
/// heartbeat pusher AND the `request-graceful-exit` command (both POST a
/// signed canonical-CBOR envelope to an Edge `/v1/edge/*` route over the
/// same mTLS leg; only the route + body differ).
///
/// The CA pins the Edge server cert. The client identity is the miner's
/// mTLS cert: in the permissionless model (the prod default) the agent
/// mints a **self-signed** cert from `identity` whose key IS the node
/// identity (no operator CA); if the legacy `client_cert`/`client_key`
/// are pinned in config, those are used instead. `rustls` only, TLS 1.3
/// floor, HTTP/2 prior knowledge (the Edge listener is h2-only). Fails
/// closed ([`MinerAgentError::HeartbeatClient`]) on any material problem.
pub fn build_edge_mtls_client(
    edge: &EdgeSection,
    identity: &MinerIdentity,
) -> Result<reqwest::Client> {
    let ca_pem =
        std::fs::read(&edge.ca_cert).map_err(|_| MinerAgentError::HeartbeatClient("ca"))?;
    let ca = reqwest::Certificate::from_pem(&ca_pem)
        .map_err(|_| MinerAgentError::HeartbeatClient("ca"))?;

    // reqwest's `Identity::from_pem` wants the client cert chain + its
    // private key concatenated in one PEM buffer. Either the operator
    // pinned both files (legacy CA bootstrap), or — the prod default —
    // the agent self-signs from its identity key.
    let client_identity = match (&edge.client_cert, &edge.client_key) {
        (Some(cert_path), Some(key_path)) => {
            let mut identity_pem = std::fs::read(cert_path)
                .map_err(|_| MinerAgentError::HeartbeatClient("client-identity"))?;
            let key_pem = std::fs::read(key_path)
                .map_err(|_| MinerAgentError::HeartbeatClient("client-identity"))?;
            identity_pem.push(b'\n');
            identity_pem.extend_from_slice(&key_pem);
            reqwest::Identity::from_pem(&identity_pem)
                .map_err(|_| MinerAgentError::HeartbeatClient("client-identity"))?
        }
        _ => {
            let self_signed = identity.self_signed_client_pem()?;
            reqwest::Identity::from_pem(self_signed.as_bytes())
                .map_err(|_| MinerAgentError::HeartbeatClient("client-identity"))?
        }
    };

    reqwest::Client::builder()
        // `rustls`, TLS 1.3 floor — no native-tls, no downgrade.
        .use_rustls_tls()
        .min_tls_version(reqwest::tls::Version::TLS_1_3)
        .tls_built_in_root_certs(false)
        .add_root_certificate(ca)
        .identity(client_identity)
        // The Edge miner listener is LOCKED to HTTP/2 (its ALPN list is
        // `["h2"]` only, with a server-side gate that refuses anything
        // else). Without prior knowledge, reqwest's default behavior is
        // to attempt an HTTP/1.1 request first; the Edge then RSTs the
        // stream and the caller sees an opaque
        // `hyper::Error(IncompleteMessage)` / `BrokenPipe` instead of a
        // real response. Forcing h2 up front sidesteps the negotiation.
        .http2_prior_knowledge()
        .connect_timeout(CONNECT_TIMEOUT)
        .timeout(REQUEST_TIMEOUT)
        .redirect(reqwest::redirect::Policy::none())
        .no_proxy()
        .build()
        .map_err(|_| MinerAgentError::HeartbeatClient("build"))
}

#[async_trait]
impl HeartbeatClient for ReqwestHeartbeatClient {
    async fn push(&self, signed: &SignedMinerHeartbeat) -> PushOutcome {
        // The opaque relay: POST the canonical-CBOR `{body, sig}`
        // envelope verbatim. A non-canonical encode is impossible here
        // — `signed` was built by `canonical()` upstream — but on the
        // off chance the wrapper encode fails, treat it as transport.
        let bytes = match signed.canonical() {
            Ok(b) => b,
            Err(_) => return PushOutcome::Transport,
        };
        match self
            .client
            .post(&self.url)
            .header(reqwest::header::CONTENT_TYPE, CONTENT_TYPE_CBOR)
            .body(bytes)
            .send()
            .await
        {
            Ok(resp) if resp.status().is_success() => PushOutcome::Delivered,
            Ok(_) => PushOutcome::Rejected,
            Err(_) => PushOutcome::Transport,
        }
    }
}

/// Run the pusher task until `cancel` fires.
///
/// The loop: pop a heartbeat (or wait for one) → deliver → on success
/// clear the backoff and move on; on failure re-queue nothing (the
/// heartbeat is held locally) and back off before retrying the SAME
/// heartbeat. Every wait races `cancel`, so shutdown is immediate.
///
/// On `cancel`, [`drain_once`] makes one final best-effort pass over
/// whatever is still queued before the task returns — the graceful-
/// shutdown "drain the queue once" invariant.
pub async fn run_pusher(
    queue: Arc<HeartbeatQueue>,
    client: Arc<dyn HeartbeatClient>,
    cancel: CancellationToken,
) {
    let mut backoff = INITIAL_BACKOFF;
    // The heartbeat currently being retried, if a previous attempt
    // failed. Held here (not re-queued) so a failing Edge cannot stall
    // the queue or reorder heartbeats.
    let mut in_flight: Option<SignedMinerHeartbeat> = None;

    loop {
        let now = now_unix();

        // Prune a retried heartbeat that has aged past the local
        // staleness threshold. Its signature is frozen at build time,
        // so it can never recover from a long outage — vali's anti-
        // skew gate would reject it forever. Re-signing is not an
        // option (the canonical-CBOR signed-envelope invariant is
        // load-bearing); drop it and let the next loop iteration pop
        // a fresh one. Surfaced in the §K end-to-end test after a
        // 26-min outage left the pusher retry-spinning a stale envelope.
        if let Some(hb) = in_flight.as_ref() {
            if is_stale(hb, now) {
                log_push(hb, "stale-dropped");
                in_flight = None;
                backoff = INITIAL_BACKOFF;
            }
        }

        // Take the in-flight retry, else pop the next FRESH queued
        // heartbeat — `pop_fresh` drops aged-out heads too.
        let next = match in_flight.take() {
            Some(hb) => Some(hb),
            None => {
                let (hb, dropped) = queue.pop_fresh(now, STALE_AFTER_SECS).await;
                if dropped > 0 {
                    log_stale_count("stale-dropped", dropped);
                }
                hb
            }
        };

        let Some(hb) = next else {
            // Idle — nothing queued. Wait briefly for the builder to
            // enqueue one, but wake at once on cancel.
            tokio::select! {
                _ = cancel.cancelled() => break,
                _ = tokio::time::sleep(Duration::from_millis(200)) => continue,
            }
        };

        // The live-loop push races cancel so a shutdown landing
        // mid-push (a request can take up to `REQUEST_TIMEOUT`) does
        // not delay the loop break — otherwise `main`'s drain grace
        // could elapse before the final `drain_once` even starts.
        //
        // `biased`: the push branch is polled FIRST, so a push that
        // has already resolved is consumed even when `cancel` fired in
        // the same wake — a confirmed delivery is never re-sent. Only a
        // push still genuinely in-flight yields to `cancel`.
        //
        // The residual: a push whose request reached the Edge but
        // whose response is lost when shutdown abandons it is held in
        // `in_flight` and re-tried by `drain_once`. That is intentional
        // — the heartbeat transport is **at-least-once**; vali's
        // monotonic `sequence` gate is the exactly-once / replay
        // enforcement point (a re-sent heartbeat is rejected there).
        let outcome = tokio::select! {
            biased;
            outcome = client.push(&hb) => outcome,
            _ = cancel.cancelled() => {
                // Abandon the in-flight push, hold the heartbeat for
                // the final drain, and stop the loop at once.
                in_flight = Some(hb);
                break;
            }
        };
        match outcome {
            PushOutcome::Delivered => {
                log_push(&hb, "delivered");
                backoff = INITIAL_BACKOFF;
            }
            outcome => {
                // Failed — hold the heartbeat, back off, retry. The
                // backoff sleep races cancel: a shutdown does not wait
                // it out.
                log_push(&hb, push_failure_class(outcome));
                in_flight = Some(hb);
                tokio::select! {
                    _ = cancel.cancelled() => break,
                    _ = tokio::time::sleep(backoff) => {}
                }
                backoff = next_backoff(backoff);
            }
        }
    }

    // Graceful shutdown — one final, time-bounded best-effort drain.
    // `DRAIN_BUDGET` caps the pass so an unreachable Edge (each push
    // can block up to `REQUEST_TIMEOUT`) cannot stall process exit;
    // it is kept below `main`'s `HEARTBEAT_DRAIN_GRACE` so the pusher
    // task always returns within that grace.
    let _ = tokio::time::timeout(
        DRAIN_BUDGET,
        drain_once(&queue, client.as_ref(), in_flight.take()),
    )
    .await;
}

/// One best-effort drain pass at shutdown: deliver the held in-flight
/// heartbeat (if any) then everything still queued, oldest-first. A
/// failed delivery here is logged and the heartbeat dropped — the
/// process is exiting; there is no retry budget left.
async fn drain_once(
    queue: &HeartbeatQueue,
    client: &dyn HeartbeatClient,
    in_flight: Option<SignedMinerHeartbeat>,
) {
    let mut pending = in_flight;
    loop {
        let now = now_unix();
        let hb = match pending.take() {
            Some(hb) if is_stale(&hb, now) => {
                // A stale in-flight at shutdown: drop it rather than
                // burn a full `REQUEST_TIMEOUT` on an envelope vali
                // will refuse for skew. Drain budget is precious here.
                log_push(&hb, "drain-stale-dropped");
                continue;
            }
            Some(hb) => hb,
            None => {
                let (hb, dropped) = queue.pop_fresh(now, STALE_AFTER_SECS).await;
                if dropped > 0 {
                    log_stale_count("drain-stale-dropped", dropped);
                }
                match hb {
                    Some(hb) => hb,
                    None => break,
                }
            }
        };
        match client.push(&hb).await {
            PushOutcome::Delivered => log_push(&hb, "drain-delivered"),
            outcome => log_push(&hb, drain_failure_class(outcome)),
        }
    }
}

/// Wall-clock now as Unix seconds, or `None` on a clock-before-epoch
/// failure. The staleness call sites treat `None` as fail-OPEN — do
/// not drop a heartbeat against a clock the caller could not even
/// read (the builder is already failing closed on the same clock, so
/// there is nothing left to discard anyway).
fn now_unix() -> Option<i64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|d| i64::try_from(d.as_secs()).ok())
}

/// Whether `hb` is outside vali's anti-skew window by more than
/// [`STALE_AFTER_SECS`] — too far from `now_unix` in EITHER direction
/// to clear the gate. A heartbeat whose body cannot be decoded is
/// also stale (vali would refuse to verify it). A `None` clock is
/// fail-OPEN: a heartbeat with a decodable body stays.
fn is_stale(hb: &SignedMinerHeartbeat, now_unix: Option<i64>) -> bool {
    match (hb.timestamp_unix(), now_unix) {
        (None, _) => true,
        (Some(_), None) => false,
        (Some(ts), Some(now)) => {
            let max = u64::try_from(STALE_AFTER_SECS).unwrap_or(u64::MAX);
            now.abs_diff(ts) > max
        }
    }
}

/// Aggregate-log a `pop_fresh` purge — `event` is one of
/// `"stale-dropped"` / `"drain-stale-dropped"`, `count` is how many
/// entries were dropped. No per-entry `body_hash` here: the entries
/// are already discarded.
fn log_stale_count(event: &'static str, count: usize) {
    eprintln!("hippius-miner-agent: heartbeat-pusher: {event} count={count}");
}

/// Next backoff step — double, capped at [`MAX_BACKOFF`].
fn next_backoff(current: Duration) -> Duration {
    let doubled = current.saturating_mul(2);
    if doubled > MAX_BACKOFF {
        MAX_BACKOFF
    } else {
        doubled
    }
}

/// Static classifier for a failed live-loop push.
fn push_failure_class(outcome: PushOutcome) -> &'static str {
    match outcome {
        PushOutcome::Delivered => "delivered",
        PushOutcome::Rejected => "rejected",
        PushOutcome::Transport => "transport-failed",
    }
}

/// Static classifier for a failed shutdown-drain push.
fn drain_failure_class(outcome: PushOutcome) -> &'static str {
    match outcome {
        PushOutcome::Delivered => "drain-delivered",
        PushOutcome::Rejected => "drain-rejected",
        PushOutcome::Transport => "drain-transport-failed",
    }
}

/// Structured push log — `body_hash` (hex) + a static outcome
/// classifier. NEVER the body bytes (§K logging discipline).
fn log_push(hb: &SignedMinerHeartbeat, outcome: &'static str) {
    eprintln!(
        "hippius-miner-agent: heartbeat-pusher: kind=heartbeat body_hash={} outcome={}",
        hex::encode(hb.body_hash()),
        outcome,
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use hippius_types::heartbeat::{MinerHeartbeat, DOMAIN, SCHEMA_VERSION};
    use std::sync::Mutex;
    use std::time::Instant;

    /// Wall-clock Unix seconds — for tests that build heartbeats with
    /// timestamps relative to "now" so the new staleness check (which
    /// reads `SystemTime::now()`) sees them as fresh / stale as
    /// intended.
    fn wall_now() -> i64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_secs() as i64
    }

    /// A heartbeat whose canonical-CBOR body carries `timestamp_unix=ts`
    /// and `sequence=seq` — lets tests construct fresh / stale
    /// heartbeats deterministically.
    fn hb_ts(seq: u8, ts: i64) -> SignedMinerHeartbeat {
        let h = MinerHeartbeat {
            schema_version: SCHEMA_VERSION,
            miner_id: "miner-test".into(),
            timestamp_unix: ts,
            sequence: seq as u64,
            vm_count_running: 0,
            vm_count_total: 0,
            cpu_load_1m_centi: 0,
            memory_total_mib: 0,
            memory_available_mib: 0,
            domain: DOMAIN.into(),
            graceful_exit_requested: false,
            cvm_cpu_budget: 0,
            cvm_memory_mb_budget: 0,
            asid_capacity: 0,
            asid_used: 0,
            disk: hippius_types::heartbeat::DiskDeclaration::default(),
            host_health: hippius_types::heartbeat::HostHealthDeclaration::default(),
            agent_version: String::new(),
        };
        SignedMinerHeartbeat {
            body: h.canonical().expect("canonical encode"),
            sig: vec![0u8; 64],
        }
    }

    /// A *fresh* heartbeat (timestamp = wall now) — the existing
    /// pusher-loop tests all use this; the new staleness check sees
    /// them as in-window so the behaviour they exercise is unchanged.
    fn hb(seq: u8) -> SignedMinerHeartbeat {
        hb_ts(seq, wall_now())
    }

    /// A `HeartbeatClient` that records every pushed heartbeat and
    /// returns a scripted sequence of outcomes (the last is repeated).
    struct ScriptedClient {
        pushed: Mutex<Vec<SignedMinerHeartbeat>>,
        outcomes: Mutex<Vec<PushOutcome>>,
    }

    impl ScriptedClient {
        fn new(outcomes: Vec<PushOutcome>) -> Self {
            Self {
                pushed: Mutex::new(Vec::new()),
                outcomes: Mutex::new(outcomes),
            }
        }

        fn pushed(&self) -> Vec<SignedMinerHeartbeat> {
            self.pushed.lock().expect("pushed lock").clone()
        }
    }

    #[async_trait]
    impl HeartbeatClient for ScriptedClient {
        async fn push(&self, signed: &SignedMinerHeartbeat) -> PushOutcome {
            self.pushed.lock().expect("lock").push(signed.clone());
            let mut o = self.outcomes.lock().expect("lock");
            if o.len() > 1 {
                o.remove(0)
            } else {
                o.first().copied().unwrap_or(PushOutcome::Delivered)
            }
        }
    }

    #[test]
    fn backoff_doubles_and_caps_at_max() {
        let mut b = INITIAL_BACKOFF;
        for _ in 0..20 {
            b = next_backoff(b);
        }
        assert_eq!(b, MAX_BACKOFF);
        assert_eq!(next_backoff(Duration::from_secs(1)), Duration::from_secs(2));
        assert_eq!(next_backoff(Duration::from_secs(2)), Duration::from_secs(4));
        // Just below the cap doubles past it → clamps.
        assert_eq!(next_backoff(Duration::from_secs(40)), MAX_BACKOFF);
    }

    #[tokio::test]
    async fn pusher_delivers_a_queued_heartbeat() {
        let queue = Arc::new(HeartbeatQueue::new(8));
        let expected = hb(1);
        queue.push(expected.clone()).await;
        let client = Arc::new(ScriptedClient::new(vec![PushOutcome::Delivered]));
        let cancel = CancellationToken::new();

        let task = tokio::spawn(run_pusher(queue.clone(), client.clone(), cancel.clone()));
        // Give the pusher a moment to drain, then stop it.
        tokio::time::sleep(Duration::from_millis(100)).await;
        cancel.cancel();
        task.await.expect("pusher task joins");

        let pushed = client.pushed();
        assert_eq!(pushed.len(), 1);
        assert_eq!(pushed[0], expected);
        assert!(queue.is_empty().await);
    }

    #[tokio::test]
    async fn a_cancel_during_backoff_is_responsive() {
        // The client always fails ⇒ the pusher enters a backoff. The
        // first backoff is 1s; the cancel must NOT have to wait it out.
        let queue = Arc::new(HeartbeatQueue::new(8));
        queue.push(hb(1)).await;
        let client = Arc::new(ScriptedClient::new(vec![PushOutcome::Transport]));
        let cancel = CancellationToken::new();

        let task = tokio::spawn(run_pusher(queue.clone(), client.clone(), cancel.clone()));
        // Let the first (failed) attempt happen + the pusher enter the
        // 1s backoff sleep.
        tokio::time::sleep(Duration::from_millis(150)).await;
        let t0 = Instant::now();
        cancel.cancel();
        task.await.expect("pusher task joins");
        // If the cancel had to wait out the 1s backoff this would be
        // ≥1s — a responsive cancel returns in well under that.
        assert!(
            t0.elapsed() < Duration::from_millis(700),
            "cancel must not wait out the backoff sleep, took {:?}",
            t0.elapsed()
        );
    }

    #[tokio::test]
    async fn a_failed_push_is_retried_not_dropped() {
        // First attempt fails, second succeeds — the SAME heartbeat
        // must be re-pushed (held in-flight, never lost). The
        // staleness check is irrelevant here: the heartbeat is fresh.
        let queue = Arc::new(HeartbeatQueue::new(8));
        let expected = hb(7);
        queue.push(expected.clone()).await;
        let client = Arc::new(ScriptedClient::new(vec![
            PushOutcome::Transport,
            PushOutcome::Delivered,
        ]));
        let cancel = CancellationToken::new();

        let task = tokio::spawn(run_pusher(queue.clone(), client.clone(), cancel.clone()));
        // 1s initial backoff + delivery — give it ~1.5s.
        tokio::time::sleep(Duration::from_millis(1500)).await;
        cancel.cancel();
        task.await.expect("pusher task joins");

        let pushed = client.pushed();
        assert!(pushed.len() >= 2, "the failed heartbeat must be retried");
        // Every push is the same heartbeat — never reordered / lost.
        assert!(pushed.iter().all(|p| p == &expected));
    }

    #[tokio::test]
    async fn shutdown_drains_the_queue_once() {
        // Several heartbeats queued; cancel BEFORE the pusher drains
        // them naturally — the final `drain_once` must still deliver
        // every one.
        let queue = Arc::new(HeartbeatQueue::new(8));
        for s in 0..5 {
            queue.push(hb(s)).await;
        }
        let client = Arc::new(ScriptedClient::new(vec![PushOutcome::Delivered]));
        let cancel = CancellationToken::new();
        // Cancel immediately — the loop may not have popped anything.
        cancel.cancel();
        run_pusher(queue.clone(), client.clone(), cancel).await;

        assert_eq!(
            client.pushed().len(),
            5,
            "graceful shutdown must drain every queued heartbeat once"
        );
        assert!(queue.is_empty().await);
    }

    #[tokio::test]
    async fn the_pusher_drops_a_stale_heartbeat_and_delivers_the_next_fresh_one() {
        // Reproduces the §K end-to-end defect this PR closes:
        //
        // A heartbeat was queued during a long Edge outage. The Edge
        // becomes reachable again >300 s later. The original envelope's
        // `timestamp_unix` is now past vali's anti-skew window — any
        // retry would loop forever (vali rejects every attempt for
        // skew). Before this fix the pusher held the stale envelope
        // in-flight and back-off-spun on it; observed in production
        // as 26 min of `skew_failed` after a real outage, recoverable
        // only by an agent restart. The pusher must DROP it and
        // deliver a fresher heartbeat instead.
        let now = wall_now();
        // 500 s old — well past STALE_AFTER_SECS (240 s).
        let stale = hb_ts(1, now - 500);
        // 30 s old — comfortably inside vali's anti-skew window.
        let fresh = hb_ts(2, now - 30);

        let queue = Arc::new(HeartbeatQueue::new(8));
        queue.push(stale).await;
        queue.push(fresh.clone()).await;

        // The single push attempt the pusher makes succeeds — so the
        // count of pushes is exactly the count of NON-stale envelopes
        // that reached the wire.
        let client = Arc::new(ScriptedClient::new(vec![PushOutcome::Delivered]));
        let cancel = CancellationToken::new();
        let task = tokio::spawn(run_pusher(queue.clone(), client.clone(), cancel.clone()));

        // A brief sleep — the stale drop + the fresh delivery both
        // complete inside one loop iteration.
        tokio::time::sleep(Duration::from_millis(200)).await;
        cancel.cancel();
        task.await.expect("pusher task joins");

        let pushed = client.pushed();
        assert_eq!(
            pushed.len(),
            1,
            "the stale heartbeat must be dropped before any push — no wasted send"
        );
        assert_eq!(
            pushed[0], fresh,
            "the delivered heartbeat must be the fresh one"
        );
        assert!(queue.is_empty().await);
    }

    #[test]
    fn is_stale_classifies_the_anti_skew_window_correctly() {
        // `is_stale` is the staleness oracle shared by the live loop
        // and the shutdown drain — a pure unit test pins its math so
        // any drift from the symmetric `±STALE_AFTER_SECS` rule
        // surfaces here.
        let now = 1_700_000_000_i64;

        // Exactly at the past threshold — still fresh (the check is `>`).
        let at_threshold = hb_ts(1, now - STALE_AFTER_SECS);
        assert!(!is_stale(&at_threshold, Some(now)));

        // One second past the threshold (in the past) — stale.
        let just_past = hb_ts(1, now - STALE_AFTER_SECS - 1);
        assert!(is_stale(&just_past, Some(now)));

        // Long-ago — stale.
        assert!(is_stale(&hb_ts(1, now - 10_000), Some(now)));

        // A small future skew (within the window) is fresh.
        assert!(!is_stale(&hb_ts(1, now + 100), Some(now)));

        // A future timestamp PAST the threshold is also stale: vali's
        // anti-skew is symmetric, so a build-time clock step back is
        // just as unrecoverable as a long Edge outage. Without this
        // check a backward-clocked envelope would block fresher heads.
        assert!(is_stale(&hb_ts(1, now + STALE_AFTER_SECS + 1), Some(now)));

        // An undecodable body is treated as stale (vali's verify would
        // refuse it anyway — drop it rather than burn the wire).
        let poison = SignedMinerHeartbeat {
            body: vec![0xff, 0xff, 0xff],
            sig: vec![0u8; 64],
        };
        assert!(is_stale(&poison, Some(now)));

        // A broken-clock fallback (`now = None`) does NOT prune fresh
        // heartbeats — fail-OPEN for staleness (the builder would
        // already be failing closed on the same clock).
        assert!(!is_stale(&at_threshold, None));
        // But an undecodable body is still dropped — the clock has no
        // bearing on poison-body classification.
        assert!(is_stale(&poison, None));
    }
}
