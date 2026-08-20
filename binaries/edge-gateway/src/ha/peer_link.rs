//! mTLS peer link between the two Edge instances (PR-H5, §5 HA pair).
//!
//! Each instance of the active/active pair runs **both** ends of a
//! symmetric link:
//!
//! - a **listener** ([`run_listener`]) — accepts the sister
//!   instance's connection and reads its health beats;
//! - a **dialer** ([`run_dialer`]) — connects out to the sister
//!   instance and writes this instance's health beats.
//!
//! So instance A's dialer feeds A's beats into B's listener, and B's
//! dialer feeds B's beats into A's listener. Each instance's
//! [`HealthMonitor`] is driven solely by what its *own listener*
//! receives. Nothing else crosses the link — no shared `Arc`, no
//! shared file, no shared memory. The only thing on the wire is a
//! copy of two `u64`s per beat ([`HealthBeat`]). Two instances
//! therefore cannot race each other: there is no contended state to
//! race over.
//!
//! ## Always mTLS, never plaintext
//!
//! Both ends are TLS 1.3 — pinned at the config level by
//! `build_server_config` / `build_client_config` via
//! `builder_with_protocol_versions(&[&TLS13])`, independent of the
//! `rustls` `"tls12"` feature (which cargo unification can turn on
//! transitively). The listener reuses the PR-H4 [`MtlsAcceptor`], so it
//! inherits CA-pinned client-cert verification *and* the CRL
//! fail-closed gate. The dialer goes through [`dial`], which builds a
//! mutual-auth [`rustls::ClientConfig`]. There is no code path here
//! that opens a raw `TcpStream` for beats — the frame I/O functions
//! are generic over `AsyncRead`/`AsyncWrite`, but every caller in
//! this module hands them a `TlsStream`.
//!
//! ## Beat framing
//!
//! `u32` big-endian length prefix + CBOR body. The reader rejects a
//! zero or over-cap length before allocating ([`super::MAX_BEAT_FRAME`]),
//! so a hostile or buggy peer cannot drive an unbounded allocation.

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsConnector;

use rustls::pki_types::ServerName;

use crate::mtls::{MtlsAcceptor, MtlsRuntime};
use crate::rate_limit::PerSourceRateLimiter;

use super::balance_metric::Metrics;
use super::health::HealthMonitor;
use super::{log_ha, HaTiming, PEER_LINK_SNI};

/// One health beat exchanged over the peer link.
///
/// Deliberately tiny: the peer link carries liveness + a load signal,
/// nothing else. It is NOT a control channel — there is no field that
/// could ask the other instance to do anything (no "you are leader",
/// no "shed harder"), because active/active has no such command.
///
/// `deny_unknown_fields` so a future field added on one instance is a
/// hard decode error on an un-upgraded peer rather than a silent
/// misread.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HealthBeat {
    /// Monotonic sequence number — incremented for every beat the
    /// dialer sends this process lifetime (it does NOT reset on a
    /// reconnect). Lets a reader (and, later, PR-H6 telemetry) spot
    /// dropped beats.
    pub seq: u64,
    /// The sender's current shed total — the load signal the peer
    /// exposes as `edge_ha_peer_shed_total` so an operator can see
    /// active/active imbalance.
    pub shed_total: u64,
}

/// Source of this instance's shed total for the outgoing beat.
///
/// The peer link depends on this trait, not on the concrete
/// [`PerSourceRateLimiter`], so the dialer stays decoupled from the
/// rate-limit internals and is trivially unit-testable with a fake.
pub trait LocalShedSource: Send + Sync + 'static {
    /// Current shed total to advertise to the peer.
    fn local_shed_total(&self) -> u64;
}

impl LocalShedSource for PerSourceRateLimiter {
    /// Sum of the per-peer shed counters currently tracked. This is a
    /// gauge, not a process-lifetime counter — GC drops dormant
    /// buckets and their counts — but that is exactly the right shape
    /// for the §H balance-observation use case (PR-H6 replaces it
    /// with a signed monotonic counter).
    fn local_shed_total(&self) -> u64 {
        self.shed_snapshot().values().copied().sum()
    }
}

/// Encode + write one beat as a length-prefixed CBOR frame.
pub(crate) async fn write_beat<W>(w: &mut W, beat: &HealthBeat) -> io::Result<()>
where
    W: AsyncWrite + Unpin,
{
    let mut body = Vec::new();
    ciborium::into_writer(beat, &mut body)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "ha-beat-encode"))?;
    let len = u32::try_from(body.len())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "ha-beat-oversize"))?;
    w.write_all(&len.to_be_bytes()).await?;
    w.write_all(&body).await?;
    w.flush().await?;
    Ok(())
}

/// Read + decode one length-prefixed CBOR beat frame.
///
/// Rejects a zero or `> max_frame` length before allocating the body
/// buffer — a peer cannot trigger an unbounded allocation.
pub(crate) async fn read_beat<R>(r: &mut R, max_frame: usize) -> io::Result<HealthBeat>
where
    R: AsyncRead + Unpin,
{
    let mut len_buf = [0u8; 4];
    r.read_exact(&mut len_buf).await?;
    let len = u32::from_be_bytes(len_buf) as usize;
    if len == 0 || len > max_frame {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "ha-beat-frame-bounds",
        ));
    }
    let mut body = vec![0u8; len];
    r.read_exact(&mut body).await?;
    ciborium::from_reader(&body[..])
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "ha-beat-decode"))
}

/// Listener half of the peer link. Accepts the sister instance's mTLS
/// connection and drains its health beats into `monitor`.
///
/// `idle_timeout` bounds how long a connection may sit without a beat
/// (or stall the TLS handshake) before it is dropped — so an
/// authenticated-but-silent peer cannot accumulate parked tasks.
///
/// Loops forever — the caller spawns it and aborts on shutdown.
pub(crate) async fn run_listener(
    listener: TcpListener,
    acceptor: Arc<MtlsAcceptor>,
    monitor: Arc<HealthMonitor>,
    metrics: Arc<Metrics>,
    max_frame: usize,
    idle_timeout: Duration,
) {
    loop {
        let (tcp, _) = match listener.accept().await {
            Ok(pair) => pair,
            // Transient accept error — back off a touch so a hard
            // failure (fd exhaustion) does not hot-spin the task.
            Err(_) => {
                tokio::time::sleep(Duration::from_millis(10)).await;
                continue;
            }
        };
        let acceptor = Arc::clone(&acceptor);
        let monitor = Arc::clone(&monitor);
        let metrics = Arc::clone(&metrics);
        tokio::spawn(async move {
            handle_peer_conn(tcp, acceptor, monitor, metrics, max_frame, idle_timeout).await;
        });
    }
}

/// Drive one inbound peer connection: mTLS handshake, then read beats
/// until the connection closes or goes idle past `idle_timeout`.
async fn handle_peer_conn(
    tcp: TcpStream,
    acceptor: Arc<MtlsAcceptor>,
    monitor: Arc<HealthMonitor>,
    metrics: Arc<Metrics>,
    max_frame: usize,
    idle_timeout: Duration,
) {
    // Reuse the PR-H4 acceptor — CA-pinned client-cert verification +
    // CRL fail-closed gate. A non-Edge or revoked cert never reaches
    // the beat loop. The handshake runs under `idle_timeout` so a peer
    // that opens TCP but stalls the TLS handshake cannot park this
    // task. The peer's `PeerId` is not needed past the handshake (the
    // link is point-to-point), so it is dropped.
    let mut tls = match tokio::time::timeout(idle_timeout, acceptor.accept(tcp)).await {
        Ok(Ok((_peer_id, tls))) => tls,
        // Handshake failed (bad / revoked cert, …) or timed out.
        _ => return,
    };
    loop {
        match tokio::time::timeout(idle_timeout, read_beat(&mut tls, max_frame)).await {
            Ok(Ok(beat)) => {
                metrics.inc_beats_received();
                metrics.set_peer_shed(beat.shed_total);
                if monitor.record_beat() {
                    // Transition into Up — log the recovery / first
                    // contact and raise the gauge.
                    metrics.set_peer_up(true);
                    log_ha("peer-up");
                }
            }
            // EOF, a decode error, or no beat within `idle_timeout` →
            // the peer's dialer is gone or silent. Drop the connection
            // (freeing this task); the watchdog observes the silence
            // and the peer's dialer reconnects on its own backoff.
            _ => return,
        }
    }
}

/// Dialer half of the peer link. Maintains an mTLS connection to the
/// sister instance and writes a health beat every `beat_interval`.
///
/// Loops forever — on any connection failure it backs off
/// [`HaTiming::reconnect_backoff`] and re-dials. Reconnects are
/// **silent**: peer-down is surfaced once, by the watchdog, not as
/// per-retry log spam.
pub(crate) async fn run_dialer(
    runtime: Arc<MtlsRuntime>,
    peer_endpoint: SocketAddr,
    metrics: Arc<Metrics>,
    shed: Arc<dyn LocalShedSource>,
    timing: HaTiming,
) {
    let mut seq: u64 = 0;
    loop {
        // Bound the dial: a blackholed peer endpoint (SYN dropped)
        // would otherwise park `TcpStream::connect` until the OS TCP
        // timeout (minutes), stalling re-establishment when the peer
        // returns. The down threshold is the natural ceiling.
        let dialed =
            tokio::time::timeout(timing.peer_down_threshold, dial(&runtime, peer_endpoint)).await;
        if let Ok(Ok(mut tls)) = dialed {
            let mut tick = tokio::time::interval(timing.beat_interval);
            // `interval`'s first tick is immediate → a beat fires
            // right after the handshake, so the peer flips Up fast.
            loop {
                tick.tick().await;
                seq = seq.wrapping_add(1);
                let shed_total = shed.local_shed_total();
                let beat = HealthBeat { seq, shed_total };
                // Bound the write: a peer that stops reading must not
                // park the dialer forever. A stall past the down
                // threshold means the connection is dead → reconnect.
                match tokio::time::timeout(timing.peer_down_threshold, write_beat(&mut tls, &beat))
                    .await
                {
                    Ok(Ok(())) => {
                        metrics.inc_beats_sent();
                        metrics.set_local_shed(shed_total);
                    }
                    // Write error or stalled write → reconnect below.
                    _ => break,
                }
            }
        }
        tokio::time::sleep(timing.reconnect_backoff).await;
    }
}

/// Open one mTLS connection to the peer.
///
/// The client config is rebuilt per attempt so a 90-day cert rotation
/// (§B Q11) is picked up on the next reconnect without a process
/// restart, and so the embedded CRL snapshot is fresh. Connects with
/// the fixed [`PEER_LINK_SNI`]; the peer's server cert must carry
/// that name as a SAN, so the stock webpki verifier does full
/// hostname verification — no custom verifier.
async fn dial(
    runtime: &MtlsRuntime,
    peer_endpoint: SocketAddr,
) -> Result<tokio_rustls::client::TlsStream<TcpStream>, ()> {
    // Fail closed: refuse to dial while the CRL store is unhealthy —
    // the CRL snapshot embedded in the client config could be stale.
    // Same posture as the `MtlsAcceptor` accept gate. The dialer
    // retries; the watchdog reports the peer down meanwhile.
    if !runtime.is_healthy() {
        return Err(());
    }
    let client_cfg = runtime.build_client_config().map_err(|_| ())?;
    let tcp = TcpStream::connect(peer_endpoint).await.map_err(|_| ())?;
    let connector = TlsConnector::from(client_cfg);
    let sni = ServerName::try_from(PEER_LINK_SNI).map_err(|_| ())?;
    connector.connect(sni, tcp).await.map_err(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::RateLimitConfig;
    use crate::mtls::PeerId;

    #[tokio::test]
    async fn beat_frame_round_trips() {
        let (mut a, mut b) = tokio::io::duplex(256);
        let sent = HealthBeat {
            seq: 42,
            shed_total: 1234,
        };
        write_beat(&mut a, &sent).await.unwrap();
        let got = read_beat(&mut b, super::super::MAX_BEAT_FRAME)
            .await
            .unwrap();
        assert_eq!(got, sent);
    }

    #[tokio::test]
    async fn read_beat_rejects_oversize_length() {
        // A peer claiming a 4 GiB frame must be rejected at the length
        // check, before any body allocation.
        let (mut a, mut b) = tokio::io::duplex(64);
        a.write_all(&u32::MAX.to_be_bytes()).await.unwrap();
        let err = read_beat(&mut b, 4096).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    #[tokio::test]
    async fn read_beat_rejects_zero_length() {
        let (mut a, mut b) = tokio::io::duplex(64);
        a.write_all(&0u32.to_be_bytes()).await.unwrap();
        let err = read_beat(&mut b, 4096).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    #[tokio::test]
    async fn read_beat_surfaces_eof_when_peer_hangs_up() {
        let (a, mut b) = tokio::io::duplex(64);
        drop(a); // peer closed the connection
        let err = read_beat(&mut b, 4096).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);
    }

    #[test]
    fn rate_limiter_reports_summed_shed_total() {
        // `LocalShedSource` for the production limiter sums the live
        // per-peer shed counters.
        let cfg = RateLimitConfig {
            refill_per_sec: 0.0,
            burst: 1,
        };
        let rl = PerSourceRateLimiter::new(cfg, Duration::from_secs(3600), usize::MAX);
        let p = PeerId::new("peer-x");
        assert!(rl.try_acquire(&p)); // consumes the single token
        assert!(!rl.try_acquire(&p)); // shed #1
        assert!(!rl.try_acquire(&p)); // shed #2
        assert_eq!(rl.local_shed_total(), 2);
    }
}
