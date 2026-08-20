//! HA balance metrics + Prometheus `/metrics` endpoint (PR-H5).
//!
//! PR-H5 builds the *metrics infrastructure* the §H runbook scrapes;
//! PR-H6 layers signed telemetry envelopes on top. The counters here
//! are intentionally cheap, lock-free atomics — they exist so an
//! operator can SEE the HA pair's behaviour, never to drive it.
//!
//! ## The balance story
//!
//! Active/active means miner load is split by NetBird DNS round-robin
//! — but round-robin is not load-aware, so one instance can drift
//! busier than the other. The two instances exchange their shed
//! totals over the peer link; each side exposes both numbers:
//!
//! - `edge_ha_local_shed_total` — this instance's shed total.
//! - `edge_ha_peer_shed_total`  — the sister instance's, as last
//!   reported in a health beat.
//!
//! A scrape that compares the two across both instances reveals
//! imbalance. PR-H5 only *exposes* it — there is no rebalancing
//! actuator, because that would need shared state / coordination,
//! which the active/active design deliberately forbids.
//!
//! ## Why a hand-rolled exposition format
//!
//! The body is a dozen lines of Prometheus text. Pulling in the
//! `prometheus` crate (plus its registry, its `protobuf`, its lazy
//! statics) to print that would dwarf the feature. The renderer below
//! emits the [text exposition format] directly — same slim-dependency
//! posture as the rest of the crate.
//!
//! [text exposition format]: https://prometheus.io/docs/instrumenting/exposition_formats/

use std::fmt::Write as _;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use super::HaError;

/// How long a `/metrics` connection may take to deliver its request
/// line before we give up on it. Bounds a trivial slow-client DoS on
/// the scrape endpoint.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(5);

/// Largest request prefix we read off a `/metrics` connection. We only
/// need the request line (`GET /metrics HTTP/1.1`), so a small cap is
/// plenty and bounds the per-connection buffer.
const REQUEST_PREFIX_CAP: usize = 1024;

/// HA metrics registry. All fields are plain atomics — incremented on
/// the peer-link hot path, read by the `/metrics` renderer. `Relaxed`
/// ordering throughout: these are observability counters, never a
/// synchronisation channel between tasks.
#[derive(Debug, Default)]
pub struct Metrics {
    /// Counter — transitions of the peer into the `Down` state.
    peer_down_total: AtomicU64,
    /// Counter — health beats this instance has sent to the peer.
    beats_sent_total: AtomicU64,
    /// Counter — health beats this instance has received from the peer.
    beats_received_total: AtomicU64,
    /// Gauge (0/1) — whether the peer is currently observed `Up`.
    peer_up: AtomicU64,
    /// Gauge — the peer's shed total, as last reported in a beat.
    peer_shed_total: AtomicU64,
    /// Gauge — this instance's shed total, as last sent in a beat.
    local_shed_total: AtomicU64,
}

impl Metrics {
    /// Fresh registry, all counters zero.
    pub fn new() -> Self {
        Self::default()
    }

    /// Record one transition of the peer into `Down`. Called by the
    /// watchdog on a down edge — once per edge, never per tick.
    pub fn inc_peer_down(&self) {
        self.peer_down_total.fetch_add(1, Ordering::Relaxed);
    }

    /// Record that a beat was sent to the peer.
    pub fn inc_beats_sent(&self) {
        self.beats_sent_total.fetch_add(1, Ordering::Relaxed);
    }

    /// Record that a beat was received from the peer.
    pub fn inc_beats_received(&self) {
        self.beats_received_total.fetch_add(1, Ordering::Relaxed);
    }

    /// Set the observed peer-up gauge.
    pub fn set_peer_up(&self, up: bool) {
        self.peer_up.store(u64::from(up), Ordering::Relaxed);
    }

    /// Record the peer's shed total from its latest beat.
    pub fn set_peer_shed(&self, total: u64) {
        self.peer_shed_total.store(total, Ordering::Relaxed);
    }

    /// Record this instance's shed total as last sent in a beat.
    pub fn set_local_shed(&self, total: u64) {
        self.local_shed_total.store(total, Ordering::Relaxed);
    }

    /// Snapshot accessors — used by the renderer and by tests.
    pub fn peer_down_total(&self) -> u64 {
        self.peer_down_total.load(Ordering::Relaxed)
    }
    pub fn beats_sent_total(&self) -> u64 {
        self.beats_sent_total.load(Ordering::Relaxed)
    }
    pub fn beats_received_total(&self) -> u64 {
        self.beats_received_total.load(Ordering::Relaxed)
    }
    pub fn peer_up(&self) -> u64 {
        self.peer_up.load(Ordering::Relaxed)
    }
    pub fn peer_shed_total(&self) -> u64 {
        self.peer_shed_total.load(Ordering::Relaxed)
    }
    pub fn local_shed_total(&self) -> u64 {
        self.local_shed_total.load(Ordering::Relaxed)
    }

    /// Render the registry as Prometheus text exposition format.
    pub fn render(&self) -> String {
        let mut out = String::with_capacity(1024);
        emit(
            &mut out,
            "edge_ha_peer_down_total",
            "counter",
            "Transitions of the HA peer into the observed-down state.",
            self.peer_down_total(),
        );
        emit(
            &mut out,
            "edge_ha_beats_sent_total",
            "counter",
            "Health beats sent to the HA peer.",
            self.beats_sent_total(),
        );
        emit(
            &mut out,
            "edge_ha_beats_received_total",
            "counter",
            "Health beats received from the HA peer.",
            self.beats_received_total(),
        );
        emit(
            &mut out,
            "edge_ha_peer_up",
            "gauge",
            "Whether the HA peer is currently observed up (1) or not (0).",
            self.peer_up(),
        );
        emit(
            &mut out,
            "edge_ha_local_shed_total",
            "gauge",
            "This instance's shed total, as last reported to the peer.",
            self.local_shed_total(),
        );
        emit(
            &mut out,
            "edge_ha_peer_shed_total",
            "gauge",
            "The HA peer's shed total, as last reported in a beat.",
            self.peer_shed_total(),
        );
        out
    }
}

/// Append one `# HELP` / `# TYPE` / sample triple to `out`.
fn emit(out: &mut String, name: &str, kind: &str, help: &str, value: u64) {
    // `writeln!` into a `String` is infallible; the `let _` keeps the
    // workspace `unwrap`/`expect` ban satisfied without a panic path.
    let _ = writeln!(out, "# HELP {name} {help}");
    let _ = writeln!(out, "# TYPE {name} {kind}");
    let _ = writeln!(out, "{name} {value}");
}

/// The Prometheus `/metrics` HTTP server for one Edge instance.
///
/// Bound separately from started so a caller (notably the integration
/// test) can read back the OS-assigned port before the accept loop
/// runs. Production binds the fixed [`crate::ha::METRICS_PORT`].
pub struct MetricsServer {
    listener: TcpListener,
    addr: SocketAddr,
}

impl MetricsServer {
    /// Bind the scrape listener. `addr`'s port may be `0` for an
    /// OS-assigned ephemeral port — read it back with [`Self::local_addr`].
    pub async fn bind(addr: SocketAddr) -> Result<Self, HaError> {
        let listener = TcpListener::bind(addr).await.map_err(|_| HaError::Bind)?;
        let addr = listener.local_addr().map_err(|_| HaError::Bind)?;
        Ok(Self { listener, addr })
    }

    /// The address the scrape listener is actually bound to.
    pub fn local_addr(&self) -> SocketAddr {
        self.addr
    }

    /// Serve `/metrics` forever. One short-lived task per connection;
    /// every request gets `Connection: close`, so there is no
    /// keep-alive state to leak. Consumes `self` — call from a
    /// `tokio::spawn`.
    pub async fn run(self, metrics: Arc<Metrics>) {
        loop {
            let stream = match self.listener.accept().await {
                Ok((stream, _)) => stream,
                // Transient accept error — back off so a hard failure
                // (fd exhaustion) does not hot-spin the task. Mirrors
                // `peer_link::run_listener`.
                Err(_) => {
                    tokio::time::sleep(Duration::from_millis(10)).await;
                    continue;
                }
            };
            let metrics = Arc::clone(&metrics);
            tokio::spawn(async move {
                // A failed connection is dropped silently — a broken
                // scrape is the scraper's problem, not a relay event.
                let _ = serve_one(stream, &metrics).await;
            });
        }
    }
}

/// The request-line prefix that selects the metrics handler. Reading
/// this many bytes is enough to classify the request conclusively.
const METRICS_REQUEST_PREFIX: &[u8] = b"GET /metrics ";

/// Handle a single `/metrics` connection: read the request line,
/// answer `200` with the exposition body for `GET /metrics`, `404`
/// otherwise. HTTP/1.1, `Connection: close`.
async fn serve_one(mut stream: TcpStream, metrics: &Metrics) -> std::io::Result<()> {
    // Accumulate until we hold enough bytes to classify the request
    // line. A scrape request arrives in one tiny segment in practice,
    // but a fragmented read must not make us 404 a valid
    // `GET /metrics` — so loop rather than reading exactly once.
    let mut buf = [0u8; REQUEST_PREFIX_CAP];
    let mut len = 0usize;
    while len < METRICS_REQUEST_PREFIX.len() {
        let n = match tokio::time::timeout(REQUEST_TIMEOUT, stream.read(&mut buf[len..])).await {
            Ok(Ok(0)) => break, // peer closed before sending a full request line
            Ok(Ok(n)) => n,
            // Timeout or read error → drop the connection without replying.
            _ => return Ok(()),
        };
        len += n;
    }

    let response = if buf[..len].starts_with(METRICS_REQUEST_PREFIX) {
        let body = metrics.render();
        format!(
            "HTTP/1.1 200 OK\r\n\
             Content-Type: text/plain; version=0.0.4; charset=utf-8\r\n\
             Content-Length: {}\r\n\
             Connection: close\r\n\
             \r\n\
             {body}",
            body.len(),
        )
    } else {
        "HTTP/1.1 404 Not Found\r\n\
         Content-Length: 0\r\n\
         Connection: close\r\n\
         \r\n"
            .to_string()
    };

    stream.write_all(response.as_bytes()).await?;
    stream.flush().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn render_emits_every_metric_in_exposition_format() {
        let m = Metrics::new();
        m.inc_peer_down();
        m.inc_beats_sent();
        m.inc_beats_received();
        m.set_peer_up(true);
        m.set_local_shed(7);
        m.set_peer_shed(99);
        let text = m.render();

        // Each metric carries its HELP + TYPE + sample line.
        for name in [
            "edge_ha_peer_down_total",
            "edge_ha_beats_sent_total",
            "edge_ha_beats_received_total",
            "edge_ha_peer_up",
            "edge_ha_local_shed_total",
            "edge_ha_peer_shed_total",
        ] {
            assert!(
                text.contains(&format!("# HELP {name} ")),
                "missing HELP {name}"
            );
            assert!(
                text.contains(&format!("# TYPE {name} ")),
                "missing TYPE {name}"
            );
        }
        assert!(text.contains("edge_ha_peer_down_total 1"));
        assert!(text.contains("edge_ha_peer_up 1"));
        assert!(text.contains("edge_ha_local_shed_total 7"));
        assert!(text.contains("edge_ha_peer_shed_total 99"));
    }

    #[test]
    fn counters_start_at_zero() {
        let m = Metrics::new();
        assert_eq!(m.peer_down_total(), 0);
        assert_eq!(m.beats_sent_total(), 0);
        assert_eq!(m.beats_received_total(), 0);
        assert_eq!(m.peer_up(), 0);
        assert_eq!(m.peer_shed_total(), 0);
        assert_eq!(m.local_shed_total(), 0);
    }

    #[test]
    fn increments_and_gauges_are_independent() {
        let m = Metrics::new();
        m.inc_beats_sent();
        m.inc_beats_sent();
        m.inc_beats_received();
        m.set_peer_up(true);
        m.set_peer_up(false);
        assert_eq!(m.beats_sent_total(), 2);
        assert_eq!(m.beats_received_total(), 1);
        assert_eq!(m.peer_down_total(), 0);
        assert_eq!(m.peer_up(), 0);
    }
}
