//! PR-H5 — HA pair (active/active) integration tests.
//!
//! Spawns **two** full HA instances inside one test process, each
//! with its own [`MtlsRuntime`], [`hippius_edge_gateway::ha::HealthMonitor`],
//! and [`hippius_edge_gateway::ha::Metrics`] — i.e. zero shared state
//! — and cross-wires their peer links over loopback. The tests prove:
//!
//! 1. **The mTLS peer link works + beats are exchanged.** Both
//!    instances reach `PeerState::Up`, beats flow both ways, and the
//!    shed counters carried in the beats land on the other side.
//!
//! 2. **A peer-down is observed, never promoted.** Crash one
//!    instance; the survivor flips its observed state to `Down`,
//!    increments `edge_ha_peer_down_total` exactly once, and does
//!    nothing else — there is no leader role for it to assume (the
//!    `HealthMonitor` type has no promotion surface; see its
//!    compile-fail doc-test).
//!
//! 3. **The Prometheus `/metrics` endpoint serves.** A plain HTTP
//!    GET returns the exposition text; a non-`/metrics` path 404s.
//!
//! 4. **The peer link enforces CRL revocation on both directions.**
//!    With the shared Edge cert revoked, neither the dialer's
//!    server-cert check nor the listener's client-cert check lets a
//!    handshake through — zero beats either way.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use hippius_edge_gateway::ha::{HaNode, HaTiming, LocalShedSource, PeerState, PEER_LINK_SNI};
use hippius_edge_gateway::mtls::{CertPaths, MtlsRuntime};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

// ---------------------------------------------------------------------
// Test PKI — a CA + one Edge cert carrying the peer-link SNI as a SAN.
// ---------------------------------------------------------------------

/// Filesystem-backed mTLS material for the HA tests. The single Edge
/// cert is minted with `SAN: DNS = PEER_LINK_SNI` and BOTH the
/// `ServerAuth` + `ClientAuth` EKUs, so it works on both ends of the
/// symmetric peer link (each instance is a TLS server for its
/// listener and a TLS client for its dialer).
struct HaPki {
    _dir: tempfile::TempDir,
    ca: PathBuf,
    cert: PathBuf,
    key: PathBuf,
    /// A CRL that revokes the one Edge cert above. A runtime loaded
    /// against it must fail-close the peer link in BOTH directions —
    /// the dialer's server-cert check and the listener's client-cert
    /// check. Exercised by `peer_link_rejects_revoked_certs_via_crl`.
    crl: PathBuf,
}

impl HaPki {
    /// Paths with no CRL — the peer link establishes normally.
    fn paths(&self) -> CertPaths {
        CertPaths {
            ca: self.ca.clone(),
            cert: self.cert.clone(),
            key: self.key.clone(),
            crl: None,
        }
    }

    /// Paths wired to the revoking CRL. The peer link must then
    /// fail closed on both the dialer and the listener side.
    fn paths_with_crl(&self) -> CertPaths {
        CertPaths {
            ca: self.ca.clone(),
            cert: self.cert.clone(),
            key: self.key.clone(),
            crl: Some(self.crl.clone()),
        }
    }
}

/// One PKI per test process — minted on first use (~150 ms).
fn pki() -> &'static HaPki {
    static PKI: OnceLock<HaPki> = OnceLock::new();
    PKI.get_or_init(mint_ha_pki)
}

fn mint_ha_pki() -> HaPki {
    use rcgen::{
        BasicConstraints, CertificateParams, CertificateRevocationListParams,
        ExtendedKeyUsagePurpose, IsCa, KeyIdMethod, KeyPair, KeyUsagePurpose, RevocationReason,
        RevokedCertParams, SanType, SerialNumber,
    };
    use std::io::Write;
    use time::{Duration as TDuration, OffsetDateTime};

    let now = OffsetDateTime::now_utc();

    // Fixed serial for the Edge cert so the CRL below can revoke it.
    let edge_serial = SerialNumber::from(0x5eed_u64);

    // CA — short-lived, like the PR-H4 test CA.
    let ca_kp = KeyPair::generate().unwrap();
    let mut ca_params = CertificateParams::new(Vec::<String>::new()).unwrap();
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params.key_usages = vec![KeyUsagePurpose::CrlSign, KeyUsagePurpose::KeyCertSign];
    ca_params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "hippius-edge-ha-test-ca");
    ca_params.not_before = now - TDuration::hours(1);
    ca_params.not_after = now + TDuration::hours(1);
    let ca_cert = ca_params.self_signed(&ca_kp).unwrap();

    // Edge cert — the SAN carries `PEER_LINK_SNI` so the dialer's
    // stock webpki verifier does full hostname verification; both
    // EKUs so it serves on the listener AND authenticates on the
    // dialer.
    let edge_kp = KeyPair::generate().unwrap();
    let mut edge_params = CertificateParams::new(Vec::<String>::new()).unwrap();
    edge_params.subject_alt_names = vec![SanType::DnsName(PEER_LINK_SNI.try_into().unwrap())];
    edge_params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "edge-ha");
    edge_params.extended_key_usages = vec![
        ExtendedKeyUsagePurpose::ServerAuth,
        ExtendedKeyUsagePurpose::ClientAuth,
    ];
    edge_params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    edge_params.serial_number = Some(edge_serial.clone());
    edge_params.not_before = now - TDuration::hours(1);
    edge_params.not_after = now + TDuration::hours(1);
    let edge_cert = edge_params.signed_by(&edge_kp, &ca_cert, &ca_kp).unwrap();

    // CRL revoking the Edge cert — used by the revocation test to
    // prove the peer link fails closed on both the dialer and the
    // listener.
    let crl_params = CertificateRevocationListParams {
        this_update: now,
        next_update: now + TDuration::hours(1),
        crl_number: SerialNumber::from(1u64),
        issuing_distribution_point: None,
        revoked_certs: vec![RevokedCertParams {
            serial_number: edge_serial,
            revocation_time: now,
            reason_code: Some(RevocationReason::KeyCompromise),
            invalidity_date: None,
        }],
        key_identifier_method: KeyIdMethod::Sha256,
    };
    let crl_cert = crl_params.signed_by(&ca_cert, &ca_kp).unwrap();

    let dir = tempfile::tempdir().unwrap();
    let write = |name: &str, content: &str| -> PathBuf {
        let p = dir.path().join(name);
        let mut f = std::fs::File::create(&p).unwrap();
        f.write_all(content.as_bytes()).unwrap();
        p
    };
    let ca = write("ca.pem", &ca_cert.pem());
    let cert = write("edge.pem", &edge_cert.pem());
    let key = write("edge.key", &edge_kp.serialize_pem());
    let crl = write("crl.pem", &crl_cert.pem().unwrap());

    HaPki {
        _dir: dir,
        ca,
        cert,
        key,
        crl,
    }
}

// ---------------------------------------------------------------------
// Helpers.
// ---------------------------------------------------------------------

/// A fixed shed total, standing in for the production
/// `PerSourceRateLimiter`. Lets a test assert exactly which number
/// crossed the peer link.
struct FakeShed(u64);

impl LocalShedSource for FakeShed {
    fn local_shed_total(&self) -> u64 {
        self.0
    }
}

/// Fast timing so the suite runs in a couple of seconds. The down
/// threshold is generous (2 s) versus the loopback TLS handshake
/// (sub-millisecond) so a slow CI runner cannot false-positive a
/// peer-down before the first beat arrives.
fn test_timing() -> HaTiming {
    HaTiming {
        beat_interval: Duration::from_millis(50),
        peer_down_threshold: Duration::from_secs(2),
        watchdog_interval: Duration::from_millis(50),
        reconnect_backoff: Duration::from_millis(50),
    }
}

/// Poll `cond` until it holds or `timeout` elapses. Returns the final
/// value of `cond`.
async fn wait_until<F: Fn() -> bool>(cond: F, timeout: Duration) -> bool {
    let deadline = tokio::time::Instant::now() + timeout;
    while tokio::time::Instant::now() < deadline {
        if cond() {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    cond()
}

/// Loopback `SocketAddr` with an OS-assigned ephemeral port.
fn ephemeral() -> SocketAddr {
    SocketAddr::from(([127, 0, 0, 1], 0))
}

/// Issue a one-shot HTTP/1.1 GET and return the full raw response.
async fn http_get(addr: SocketAddr, path: &str) -> String {
    let mut stream = TcpStream::connect(addr).await.unwrap();
    let req = format!("GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n");
    stream.write_all(req.as_bytes()).await.unwrap();
    let mut resp = Vec::new();
    stream.read_to_end(&mut resp).await.unwrap();
    String::from_utf8_lossy(&resp).into_owned()
}

// ---------------------------------------------------------------------
// Tests.
// ---------------------------------------------------------------------

#[tokio::test]
async fn peer_link_exchanges_health_beats_active_active() {
    let pki = pki();
    let timing = test_timing();

    // Two fully independent instances — separate runtimes, separate
    // shed sources. Nothing is shared but the CA/cert files on disk,
    // which both read independently.
    let rt_a = MtlsRuntime::load(pki.paths()).unwrap();
    let rt_b = MtlsRuntime::load(pki.paths()).unwrap();
    let shed_a: Arc<dyn LocalShedSource> = Arc::new(FakeShed(7));
    let shed_b: Arc<dyn LocalShedSource> = Arc::new(FakeShed(99));

    let node_a = HaNode::bind(rt_a, ephemeral(), ephemeral(), timing, shed_a)
        .await
        .unwrap();
    let node_b = HaNode::bind(rt_b, ephemeral(), ephemeral(), timing, shed_b)
        .await
        .unwrap();
    let addr_a = node_a.peer_link_addr();
    let addr_b = node_b.peer_link_addr();

    // Cross-wire: each instance dials the other.
    let ha_a = node_a.start(addr_b);
    let ha_b = node_b.start(addr_a);

    // Both instances must observe the other as Up.
    assert!(
        wait_until(
            || ha_a.monitor.peer_state() == PeerState::Up
                && ha_b.monitor.peer_state() == PeerState::Up,
            Duration::from_secs(10),
        )
        .await,
        "both instances should reach PeerState::Up"
    );

    // Beats flowed both ways.
    assert!(ha_a.metrics.beats_sent_total() > 0, "A sent beats");
    assert!(ha_b.metrics.beats_sent_total() > 0, "B sent beats");
    assert!(ha_a.metrics.beats_received_total() > 0, "A received beats");
    assert!(ha_b.metrics.beats_received_total() > 0, "B received beats");

    // The shed counters carried in the beats crossed the link:
    // A observes B's total (99), B observes A's total (7).
    assert!(
        wait_until(
            || ha_a.metrics.peer_shed_total() == 99 && ha_b.metrics.peer_shed_total() == 7,
            Duration::from_secs(10),
        )
        .await,
        "shed counters should propagate over the peer link"
    );

    // Active/active: while both are healthy neither instance saw a
    // peer-down, and neither put itself in any kind of leader state —
    // there is no such state to be in.
    assert_eq!(ha_a.metrics.peer_down_total(), 0, "A: no spurious down");
    assert_eq!(ha_b.metrics.peer_down_total(), 0, "B: no spurious down");
    assert_eq!(ha_a.metrics.peer_up(), 1);
    assert_eq!(ha_b.metrics.peer_up(), 1);
}

#[tokio::test]
async fn peer_down_is_observed_without_promotion() {
    let pki = pki();
    let timing = test_timing();

    let rt_a = MtlsRuntime::load(pki.paths()).unwrap();
    let rt_b = MtlsRuntime::load(pki.paths()).unwrap();
    let shed_a: Arc<dyn LocalShedSource> = Arc::new(FakeShed(0));
    let shed_b: Arc<dyn LocalShedSource> = Arc::new(FakeShed(0));

    let node_a = HaNode::bind(rt_a, ephemeral(), ephemeral(), timing, shed_a)
        .await
        .unwrap();
    let node_b = HaNode::bind(rt_b, ephemeral(), ephemeral(), timing, shed_b)
        .await
        .unwrap();
    let addr_a = node_a.peer_link_addr();
    let addr_b = node_b.peer_link_addr();

    let ha_a = node_a.start(addr_b);
    let ha_b = node_b.start(addr_a);

    assert!(
        wait_until(
            || ha_a.monitor.peer_state() == PeerState::Up,
            Duration::from_secs(10),
        )
        .await,
        "A should first observe B as Up"
    );

    // Crash instance B: dropping its handle aborts every B task.
    drop(ha_b);

    // A observes the peer go down.
    assert!(
        wait_until(
            || ha_a.monitor.peer_state() == PeerState::Down,
            Duration::from_secs(10),
        )
        .await,
        "A should observe the peer Down after it crashes"
    );

    // The ENTIRE reaction: one metric increment + the peer-up gauge
    // cleared. No promotion — A has no leader role to assume (the
    // `HealthMonitor` type exposes no such surface). A keeps running
    // its normal pipeline unchanged.
    assert_eq!(ha_a.metrics.peer_down_total(), 1, "exactly one down edge");
    assert_eq!(ha_a.metrics.peer_up(), 0);

    // `edge_ha_peer_down_total` increments once per down EDGE, not
    // once per watchdog tick — re-check after many more ticks.
    tokio::time::sleep(Duration::from_millis(400)).await;
    assert_eq!(
        ha_a.metrics.peer_down_total(),
        1,
        "down is metered once, not per-tick"
    );
    assert_eq!(ha_a.monitor.peer_state(), PeerState::Down);

    // A is still fully alive — its observation surface still answers.
    // There is, by construction, nothing else for it to have become.
    assert!(!ha_a.metrics.render().is_empty());
}

#[tokio::test]
async fn metrics_endpoint_serves_prometheus_text() {
    let pki = pki();
    let timing = test_timing();
    let rt = MtlsRuntime::load(pki.paths()).unwrap();
    let shed: Arc<dyn LocalShedSource> = Arc::new(FakeShed(0));

    let node = HaNode::bind(rt, ephemeral(), ephemeral(), timing, shed)
        .await
        .unwrap();
    // No real peer — point the dialer at an unused port. It just
    // retries; the /metrics endpoint serves regardless.
    let no_peer = SocketAddr::from(([127, 0, 0, 1], 1));
    let ha = node.start(no_peer);

    let body = http_get(ha.metrics_addr, "/metrics").await;
    assert!(body.starts_with("HTTP/1.1 200 OK"), "got: {body}");
    assert!(body.contains("# TYPE edge_ha_peer_down_total counter"));
    assert!(body.contains("edge_ha_peer_down_total 0"));
    assert!(body.contains("edge_ha_beats_sent_total"));
    assert!(body.contains("edge_ha_peer_shed_total"));
    assert!(body.contains("Content-Type: text/plain"));

    // A non-/metrics path 404s.
    let other = http_get(ha.metrics_addr, "/not-metrics").await;
    assert!(other.starts_with("HTTP/1.1 404"), "got: {other}");
}

#[tokio::test]
async fn peer_link_rejects_revoked_certs_via_crl() {
    // The peer link must enforce CRL revocation on BOTH directions:
    // the dialer's check of the peer's *server* cert and the
    // listener's check of the peer's *client* cert. Here the CRL
    // revokes the one shared Edge cert, so no handshake can complete
    // in either direction — zero beats sent, zero received.
    let pki = pki();
    let timing = test_timing();

    // Instance A loads the revoking CRL; instance B is a normal peer
    // still presenting the (now-revoked) Edge cert.
    let rt_a = MtlsRuntime::load(pki.paths_with_crl()).unwrap();
    let rt_b = MtlsRuntime::load(pki.paths()).unwrap();
    assert!(
        rt_a.is_healthy(),
        "A's CRL loaded cleanly → runtime healthy"
    );
    let shed_a: Arc<dyn LocalShedSource> = Arc::new(FakeShed(0));
    let shed_b: Arc<dyn LocalShedSource> = Arc::new(FakeShed(0));

    let node_a = HaNode::bind(rt_a, ephemeral(), ephemeral(), timing, shed_a)
        .await
        .unwrap();
    let node_b = HaNode::bind(rt_b, ephemeral(), ephemeral(), timing, shed_b)
        .await
        .unwrap();
    let addr_a = node_a.peer_link_addr();
    let addr_b = node_b.peer_link_addr();
    let ha_a = node_a.start(addr_b);
    let _ha_b = node_b.start(addr_a);

    // Ample time for the dialer + listener to (fail to) handshake and
    // retry many times — handshakes fail fast, backoff is 50 ms.
    tokio::time::sleep(Duration::from_millis(800)).await;

    // A's dialer rejected B's revoked SERVER cert → no beats sent.
    // (Without the CRL on the dialer's client config this would be
    // non-zero — this is the regression guard for that path.)
    assert_eq!(
        ha_a.metrics.beats_sent_total(),
        0,
        "dialer must reject a revoked peer server cert"
    );
    // A's listener rejected B's revoked CLIENT cert → no beats in.
    assert_eq!(
        ha_a.metrics.beats_received_total(),
        0,
        "listener must reject a revoked peer client cert"
    );
    // The peer is never observed Up over a CRL-rejected link.
    assert_ne!(ha_a.monitor.peer_state(), PeerState::Up);
}
