//! HA pair — **active/active**, no leader election (PR-H5, §5 / §17.8).
//!
//! ## The design, in one paragraph
//!
//! The Edge runs as two instances behind NetBird DNS round-robin.
//! Miners resolve the Edge name and connect to whichever address the
//! round-robin hands them; if their TCP connection drops they re-
//! resolve and land on either instance. That is the entire failover
//! mechanism. There is **no leader election, no Raft, no shared
//! state, no session stickiness** — the relay is stateless by the
//! PR-H1 invariant (`accept → rate-limit → validate → enqueue →
//! forward`, nothing persisted between envelopes), so two instances
//! running the identical code path cannot corrupt each other. They
//! never coordinate; they only *observe*.
//!
//! ## What the peer link is for
//!
//! Set [`ENV_PEER_ENDPOINT`] (`EDGE_PEER_ENDPOINT`) to the sister
//! instance's address and this instance opens an mTLS channel to it —
//! reusing the PR-H4 CA + Edge cert, never plaintext. Across that
//! channel each instance sends, every [`BEAT_INTERVAL`]:
//!
//! - a **health beat** — liveness;
//! - its **shed total** — a load signal, so an operator can watch
//!   the two instances for round-robin imbalance.
//!
//! If the peer goes silent past [`PEER_DOWN_THRESHOLD`] the watchdog
//! logs it and increments `edge_ha_peer_down_total`. **That is the
//! complete reaction.** No promotion, no takeover, no behaviour
//! change — the surviving instance was already serving every miner
//! that round-robin sent it, and keeps doing exactly that. Robustness
//! is a property of *symmetry*, not of failover logic.
//!
//! `EDGE_PEER_ENDPOINT` is optional: with it unset the Edge runs
//! single-instance and this whole subsystem (peer link + watchdog +
//! `/metrics`) stays dormant.
//!
//! ## Module map
//!
//! - [`peer_link`] — the mTLS channel: listener + dialer + beat frames.
//! - [`health`] — [`HealthMonitor`]: liveness observation, no promotion.
//! - [`balance_metric`] — [`Metrics`] + the Prometheus `/metrics`
//!   endpoint (PR-H6 layers signed telemetry on this infra).
//!
//! ## Zero shared state
//!
//! Two [`HaNode`]s in one process (the integration test does exactly
//! this) share **nothing**: separate [`HealthMonitor`], separate
//! [`Metrics`], separate sockets. The only thing that ever crosses
//! between them is a [`peer_link::HealthBeat`] on the wire — a copy of
//! two `u64`s. There is no `Arc`, file, or memory region held in
//! common, so there is no contended state and therefore no race.

pub mod balance_metric;
pub mod health;
pub mod peer_link;

pub use balance_metric::{Metrics, MetricsServer};
pub use health::{HealthMonitor, PeerState};
pub use peer_link::{HealthBeat, LocalShedSource};

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use tokio::net::TcpListener;
use tokio::task::JoinHandle;

use crate::mtls::{MtlsAcceptor, MtlsRuntime};

/// Env var naming the sister instance's peer-link endpoint. Unset ⇒
/// single-instance mode (no peer link). Value is an IP, optionally
/// `IP:port`; a bare IP defaults the port to [`PEER_LINK_PORT`].
pub const ENV_PEER_ENDPOINT: &str = "EDGE_PEER_ENDPOINT";

/// How often the dialer sends a health beat to the peer.
pub const BEAT_INTERVAL: Duration = Duration::from_secs(5);

/// Silence past this horizon flips the peer to [`PeerState::Down`].
/// Six missed beats — slack for a GC pause or a brief network blip
/// without crying wolf.
pub const PEER_DOWN_THRESHOLD: Duration = Duration::from_secs(30);

/// How often the watchdog re-evaluates peer liveness.
pub const WATCHDOG_INTERVAL: Duration = Duration::from_secs(5);

/// Backoff between peer-link dial attempts after a connection drops.
pub const RECONNECT_BACKOFF: Duration = Duration::from_secs(5);

/// Fixed vRack-internal TCP port the peer-link mTLS listener binds.
/// Distinct from the (future) miner-facing port — the peer link lives
/// entirely on the trusted vRack segment.
pub const PEER_LINK_PORT: u16 = 9443;

/// Fixed TCP port the Prometheus `/metrics` endpoint binds.
pub const METRICS_PORT: u16 = 9464;

/// TLS SNI the peer-link dialer presents, and the name the peer's
/// server cert must carry as a SAN. A fixed service name (not a
/// per-host name) so the stock webpki verifier does full hostname
/// verification without a custom verifier — the §H Ansible playbook
/// adds this SAN to every Edge cert.
pub const PEER_LINK_SNI: &str = "edge-ha-peer.hippius.internal";

/// Hard cap on a single beat frame. A beat is ~20 bytes of CBOR; the
/// cap exists so a hostile or buggy peer cannot drive an unbounded
/// allocation via the length prefix.
pub const MAX_BEAT_FRAME: usize = 4096;

/// Stable static-classifier errors for the HA subsystem. Same
/// `&'static str`-only `Display` discipline as `EdgeError` /
/// `CertStoreError` — the audit sink keys on these.
#[derive(Debug, thiserror::Error)]
pub enum HaError {
    /// `EDGE_PEER_ENDPOINT` was set but did not parse as an IP or
    /// `IP:port`. Boot-fatal — better than silently disabling HA.
    #[error("ha-endpoint-invalid")]
    BadEndpoint,
    /// A peer-link / metrics socket failed to bind.
    #[error("ha-bind")]
    Bind,
}

impl HaError {
    /// Static classifier for the audit sink.
    pub fn class(&self) -> &'static str {
        match self {
            HaError::BadEndpoint => "ha-endpoint-invalid",
            HaError::Bind => "ha-bind",
        }
    }
}

/// Operator-supplied HA configuration, read from the environment.
#[derive(Debug, Clone)]
pub struct HaConfig {
    /// The sister instance's peer-link endpoint to dial.
    pub peer_endpoint: SocketAddr,
}

impl HaConfig {
    /// Read [`ENV_PEER_ENDPOINT`]. Returns `Ok(None)` when unset or
    /// empty (single-instance mode), `Ok(Some)` when it parses, and
    /// `Err(BadEndpoint)` when it is set but malformed — a malformed
    /// value fails the boot rather than silently dropping HA.
    pub fn from_env() -> Result<Option<Self>, HaError> {
        match std::env::var(ENV_PEER_ENDPOINT) {
            Ok(s) if !s.is_empty() => Ok(Some(Self {
                peer_endpoint: parse_endpoint(&s)?,
            })),
            _ => Ok(None),
        }
    }
}

/// Parse an `EDGE_PEER_ENDPOINT` value: `IP:port`, or a bare `IP`
/// (port defaults to [`PEER_LINK_PORT`]). The spec pins this to an IP
/// — DNS round-robin is the *miner*-facing mechanism, the peer link
/// addresses the sister instance directly.
fn parse_endpoint(s: &str) -> Result<SocketAddr, HaError> {
    if let Ok(addr) = s.parse::<SocketAddr>() {
        return Ok(addr);
    }
    if let Ok(ip) = s.parse::<IpAddr>() {
        return Ok(SocketAddr::new(ip, PEER_LINK_PORT));
    }
    Err(HaError::BadEndpoint)
}

/// Timing knobs for the HA subsystem. Production values come from the
/// module constants via [`HaTiming::production`]; the integration
/// test builds a fast variant so it runs in well under a second.
///
/// All fields must be non-zero — `tokio::time::interval` panics on a
/// zero period. The two constructors here both produce non-zero
/// values; a hand-built `HaTiming` is the caller's responsibility.
#[derive(Debug, Clone, Copy)]
pub struct HaTiming {
    /// Interval between outgoing health beats.
    pub beat_interval: Duration,
    /// Silence horizon before the peer is reported down.
    pub peer_down_threshold: Duration,
    /// Interval between watchdog liveness re-evaluations.
    pub watchdog_interval: Duration,
    /// Backoff between dial attempts after a connection drop.
    pub reconnect_backoff: Duration,
}

impl HaTiming {
    /// Production timing — the §H runbook cadence (5 s beats, 30 s
    /// down horizon).
    pub fn production() -> Self {
        Self {
            beat_interval: BEAT_INTERVAL,
            peer_down_threshold: PEER_DOWN_THRESHOLD,
            watchdog_interval: WATCHDOG_INTERVAL,
            reconnect_backoff: RECONNECT_BACKOFF,
        }
    }
}

impl Default for HaTiming {
    fn default() -> Self {
        Self::production()
    }
}

/// One Edge instance's HA subsystem, bound but not yet running.
///
/// Split into [`HaNode::bind`] (binds the peer-link + metrics
/// sockets) and [`HaNode::start`] (spawns the tasks) so a caller can
/// read back the OS-assigned ports — [`HaNode::peer_link_addr`] /
/// [`HaNode::metrics_addr`] — before wiring the pair together. The
/// integration test relies on this; production binds fixed ports and
/// uses it the same way.
pub struct HaNode {
    runtime: Arc<MtlsRuntime>,
    peer_listener: TcpListener,
    peer_link_addr: SocketAddr,
    metrics_server: MetricsServer,
    timing: HaTiming,
    shed: Arc<dyn LocalShedSource>,
}

impl HaNode {
    /// Bind this instance's peer-link listener (`listen_addr`) and
    /// Prometheus `/metrics` listener (`metrics_addr`). Either port
    /// may be `0` for an OS-assigned ephemeral port.
    ///
    /// `runtime` is the PR-H4 mTLS runtime — reused for both the
    /// listener's `ServerConfig` and the dialer's `ClientConfig`, so
    /// the peer link carries the same CA + Edge cert as the miner-
    /// facing side. `shed` feeds the load signal into outgoing beats.
    pub async fn bind(
        runtime: Arc<MtlsRuntime>,
        listen_addr: SocketAddr,
        metrics_addr: SocketAddr,
        timing: HaTiming,
        shed: Arc<dyn LocalShedSource>,
    ) -> Result<Self, HaError> {
        let peer_listener = TcpListener::bind(listen_addr)
            .await
            .map_err(|_| HaError::Bind)?;
        let peer_link_addr = peer_listener.local_addr().map_err(|_| HaError::Bind)?;
        let metrics_server = MetricsServer::bind(metrics_addr).await?;
        Ok(Self {
            runtime,
            peer_listener,
            peer_link_addr,
            metrics_server,
            timing,
            shed,
        })
    }

    /// The address the peer-link listener bound to — the value the
    /// sister instance puts in *its* `EDGE_PEER_ENDPOINT`.
    pub fn peer_link_addr(&self) -> SocketAddr {
        self.peer_link_addr
    }

    /// The address the Prometheus `/metrics` endpoint bound to.
    pub fn metrics_addr(&self) -> SocketAddr {
        self.metrics_server.local_addr()
    }

    /// Spawn the four HA tasks — peer-link listener, peer-link
    /// dialer, liveness watchdog, `/metrics` server — and return the
    /// [`HaHandle`]. `peer_endpoint` is the sister instance's
    /// peer-link address (from `EDGE_PEER_ENDPOINT`).
    pub fn start(self, peer_endpoint: SocketAddr) -> HaHandle {
        let HaNode {
            runtime,
            peer_listener,
            peer_link_addr,
            metrics_server,
            timing,
            shed,
        } = self;

        let metrics_addr = metrics_server.local_addr();
        // Per-node state — NOT shared with the peer. Two `HaNode`s in
        // one process each get their own monitor + metrics.
        let monitor = Arc::new(HealthMonitor::new(timing.peer_down_threshold));
        let metrics = Arc::new(Metrics::new());
        // The peer-link listener reuses the PR-H4 acceptor: CA-pinned
        // client-cert verification + CRL fail-closed gate.
        let acceptor = Arc::new(MtlsAcceptor::new(Arc::clone(&runtime)));

        let tasks = vec![
            tokio::spawn(peer_link::run_listener(
                peer_listener,
                acceptor,
                Arc::clone(&monitor),
                Arc::clone(&metrics),
                MAX_BEAT_FRAME,
                // A connection idle past the down threshold is dead —
                // drop it so a silent peer cannot park reader tasks.
                timing.peer_down_threshold,
            )),
            tokio::spawn(peer_link::run_dialer(
                Arc::clone(&runtime),
                peer_endpoint,
                Arc::clone(&metrics),
                Arc::clone(&shed),
                timing,
            )),
            tokio::spawn(run_watchdog(
                Arc::clone(&monitor),
                Arc::clone(&metrics),
                timing.watchdog_interval,
            )),
            tokio::spawn(metrics_server.run(Arc::clone(&metrics))),
        ];

        HaHandle {
            monitor,
            metrics,
            peer_link_addr,
            metrics_addr,
            tasks,
        }
    }
}

/// Handle to a running [`HaNode`]. Holds the per-instance observation
/// state ([`HaHandle::monitor`], [`HaHandle::metrics`]) and the spawned
/// task handles. Dropping the handle aborts every HA task — which is
/// also how the integration test simulates an instance crash.
pub struct HaHandle {
    /// This instance's peer-liveness observer.
    pub monitor: Arc<HealthMonitor>,
    /// This instance's metrics registry (scraped at [`Self::metrics_addr`]).
    pub metrics: Arc<Metrics>,
    /// Address the peer-link listener is bound to.
    pub peer_link_addr: SocketAddr,
    /// Address the Prometheus `/metrics` endpoint is bound to.
    pub metrics_addr: SocketAddr,
    tasks: Vec<JoinHandle<()>>,
}

impl Drop for HaHandle {
    fn drop(&mut self) {
        // Abort the top-level HA tasks. Per-connection reader tasks
        // spawned by the listener finish on their own when their
        // socket closes — which it does once the peer's dialer (also
        // aborted, on the peer's own drop) goes away.
        for task in &self.tasks {
            task.abort();
        }
    }
}

/// Watchdog task: every `interval`, re-evaluate peer liveness. On a
/// transition into [`PeerState::Down`] the ENTIRE reaction is a log
/// line plus a metric increment — no promotion, no pipeline change,
/// no process exit. Active/active robustness is symmetry, not failover.
async fn run_watchdog(monitor: Arc<HealthMonitor>, metrics: Arc<Metrics>, interval: Duration) {
    let mut tick = tokio::time::interval(interval);
    loop {
        tick.tick().await;
        if monitor.poll() {
            metrics.inc_peer_down();
            metrics.set_peer_up(false);
            // Clear the peer's shed gauge: once the peer is down its
            // last-reported shed total is stale, and a non-zero value
            // next to `edge_ha_peer_up 0` would read as live data
            // from a dead instance.
            metrics.set_peer_shed(0);
            log_ha("peer-down");
        }
    }
}

/// Static-string-only diagnostic emitter for HA events. Same
/// `&'static str` discipline as `main::log_fatal` — `class` is a
/// closed-vocabulary classifier, never caller-built text, so the
/// peer-down / peer-up events cannot leak anything.
pub(crate) fn log_ha(class: &'static str) {
    eprintln!("hippius-edge-gateway: ha: {class}");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_endpoint_accepts_ip_and_port() {
        let addr = parse_endpoint("10.0.0.7:9443").unwrap();
        assert_eq!(addr, "10.0.0.7:9443".parse().unwrap());
    }

    #[test]
    fn parse_endpoint_defaults_port_for_bare_ip() {
        let addr = parse_endpoint("10.0.0.7").unwrap();
        assert_eq!(addr.port(), PEER_LINK_PORT);
        assert_eq!(addr.ip(), "10.0.0.7".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn parse_endpoint_accepts_ipv6() {
        let addr = parse_endpoint("::1").unwrap();
        assert_eq!(addr.port(), PEER_LINK_PORT);
    }

    #[test]
    fn parse_endpoint_rejects_garbage() {
        assert!(matches!(
            parse_endpoint("not-an-ip"),
            Err(HaError::BadEndpoint)
        ));
        // A bare DNS name is rejected — the peer endpoint is an IP by
        // spec (DNS round-robin is the miner-facing mechanism).
        assert!(matches!(
            parse_endpoint("edge-2.hippius.internal"),
            Err(HaError::BadEndpoint)
        ));
    }

    #[test]
    fn from_env_returns_none_when_unset() {
        // Snapshot + clear so a stray env var from the runner doesn't
        // make this flaky; restore on the way out.
        let prev = std::env::var(ENV_PEER_ENDPOINT).ok();
        std::env::remove_var(ENV_PEER_ENDPOINT);
        assert!(HaConfig::from_env().unwrap().is_none());
        if let Some(v) = prev {
            std::env::set_var(ENV_PEER_ENDPOINT, v);
        }
    }

    #[test]
    fn ha_error_class_is_stable() {
        assert_eq!(HaError::BadEndpoint.class(), "ha-endpoint-invalid");
        assert_eq!(HaError::Bind.class(), "ha-bind");
        // `Display` equals `class` — accidental `{err}` is safe.
        assert_eq!(HaError::BadEndpoint.to_string(), "ha-endpoint-invalid");
        assert_eq!(HaError::Bind.to_string(), "ha-bind");
    }

    #[test]
    fn production_timing_matches_constants() {
        let t = HaTiming::production();
        assert_eq!(t.beat_interval, BEAT_INTERVAL);
        assert_eq!(t.peer_down_threshold, PEER_DOWN_THRESHOLD);
        assert_eq!(t.watchdog_interval, WATCHDOG_INTERVAL);
        assert_eq!(t.reconnect_backoff, RECONNECT_BACKOFF);
        // Down horizon must comfortably exceed the beat interval, or
        // a single late beat would false-positive a peer-down.
        assert!(t.peer_down_threshold > t.beat_interval);
    }

    #[test]
    fn peer_link_sni_is_a_valid_dns_name() {
        // The dialer relies on this parsing as a `ServerName`.
        use rustls::pki_types::ServerName;
        assert!(ServerName::try_from(PEER_LINK_SNI).is_ok());
    }
}
