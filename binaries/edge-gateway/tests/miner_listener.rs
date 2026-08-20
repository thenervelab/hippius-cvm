//! PR-H7 — miner-facing listener integration tests.
//!
//! Drives the production [`run_miner_listener`] accept loop over
//! loopback TCP with dynamically-minted certs (the shared
//! `tests/mtls_test_helpers.rs`). The mTLS *handshake* mechanics
//! themselves are covered by `mtls_integration.rs`; these tests cover
//! the PR-H7 wiring — the loop accepts connections, drives each through
//! the mTLS acceptor (so mTLS is genuinely required), and stops
//! cleanly on cancel. PR-H8: the loop now also takes a
//! [`MinerRouterState`] (served over each authenticated connection);
//! the end-to-end envelope routing is exercised in
//! `tests/miner_router_test.rs`.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

#[path = "mtls_test_helpers.rs"]
mod helpers;

use helpers::TestPki;
use hippius_edge_gateway::mtls::{CertPaths, MtlsAcceptor, MtlsRuntime};
use hippius_edge_gateway::telemetry::{NoopTelemetry, TelemetrySink};
use hippius_edge_gateway::{
    run_miner_listener, ForwardClient, MinerRouterState, MockForwardClient, PerSourceRateLimiter,
    RateLimitConfig,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use rustls::{ClientConfig, RootCertStore};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;
use tokio_rustls::TlsConnector;

/// Build the production [`MtlsAcceptor`] over the minted PKI (no CRL —
/// revocation behaviour is `mtls_integration.rs`'s concern).
fn acceptor_for(pki: &TestPki) -> Arc<MtlsAcceptor> {
    let paths = CertPaths {
        ca: pki.ca_path.clone(),
        cert: pki.server_cert_path.clone(),
        key: pki.server_key_path.clone(),
        crl: None,
    };
    let runtime = MtlsRuntime::load(paths).unwrap();
    Arc::new(MtlsAcceptor::new(runtime))
}

/// A minimal router state for the PR-H7 wiring tests — the forward
/// client is never reached (these tests assert handshake / cancel
/// behaviour, not envelope routing).
fn router_state() -> MinerRouterState {
    let forward: Arc<dyn ForwardClient> =
        Arc::new(MockForwardClient::with_response(200, Vec::new()));
    let telemetry: Arc<dyn TelemetrySink + Send + Sync> = Arc::new(NoopTelemetry);
    // Generous default budget — these tests assert handshake / cancel
    // behaviour, never the rate limit.
    let limiter = Arc::new(PerSourceRateLimiter::new(
        RateLimitConfig::default(),
        Duration::from_secs(3600),
        1024,
    ));
    MinerRouterState::new(forward, telemetry, limiter)
}

fn ca_roots(pki: &TestPki) -> RootCertStore {
    let mut roots = RootCertStore::empty();
    for entry in rustls_pemfile::certs(&mut std::io::Cursor::new(
        std::fs::read(&pki.ca_path).unwrap(),
    )) {
        roots.add(entry.unwrap()).unwrap();
    }
    roots
}

/// A TLS-1.3 mTLS client presenting `cert_pem` + `key_pem`, offering
/// the given ALPN protocol list. PR-H8: the miner listener gates on a
/// negotiated `h2` ALPN, so a client must offer `h2` to be served.
fn mtls_client_with_alpn(
    pki: &TestPki,
    cert_pem: &str,
    key_pem: &str,
    alpn: &[&[u8]],
) -> TlsConnector {
    let cert_chain: Vec<CertificateDer<'static>> =
        rustls_pemfile::certs(&mut std::io::Cursor::new(cert_pem.as_bytes()))
            .filter_map(Result::ok)
            .collect();
    let key: PrivateKeyDer<'static> =
        rustls_pemfile::private_key(&mut std::io::Cursor::new(key_pem.as_bytes()))
            .unwrap()
            .unwrap();
    let mut cfg = ClientConfig::builder()
        .with_root_certificates(ca_roots(pki))
        .with_client_auth_cert(cert_chain, key)
        .unwrap();
    cfg.alpn_protocols = alpn.iter().map(|p| p.to_vec()).collect();
    TlsConnector::from(Arc::new(cfg))
}

/// A TLS-1.3 mTLS client offering `h2` ALPN — the conformant miner
/// shape the listener serves.
fn mtls_client(pki: &TestPki, cert_pem: &str, key_pem: &str) -> TlsConnector {
    mtls_client_with_alpn(pki, cert_pem, key_pem, &[b"h2"])
}

/// A TLS client that presents NO client certificate.
fn anonymous_client(pki: &TestPki) -> TlsConnector {
    let cfg = ClientConfig::builder()
        .with_root_certificates(ca_roots(pki))
        .with_no_client_auth();
    TlsConnector::from(Arc::new(cfg))
}

#[tokio::test]
async fn valid_client_handshake_succeeds_through_the_listener() {
    let pki = TestPki::mint();
    let acceptor = acceptor_for(&pki);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let (tx, rx) = watch::channel(false);
    let loop_task = tokio::spawn(run_miner_listener(listener, acceptor, router_state(), rx));

    // A CA-issued client cert offering `h2` ALPN handshakes
    // successfully — the listener drove the connection through the
    // production mTLS acceptor and the ALPN gate accepted `h2`.
    let connector = mtls_client(&pki, &pki.valid_client_cert_pem, &pki.valid_client_key_pem);
    let tcp = TcpStream::connect(addr).await.unwrap();
    let sni = ServerName::try_from("edge.test").unwrap();
    let tls = connector.connect(sni, tcp).await;
    assert!(
        tls.is_ok(),
        "a CA-valid miner offering h2 must complete the mTLS handshake"
    );
    // Drop the client connection so the server's per-connection
    // handler observes a peer close and exits promptly — otherwise
    // the cancel-path drain would wait out the first-request /
    // graceful-drain bounds. The full H2 envelope round-trip is
    // covered by `miner_router_test::end_to_end_envelope_*`.
    drop(tls);

    tx.send(true).unwrap();
    assert!(
        tokio::time::timeout(Duration::from_secs(5), loop_task)
            .await
            .is_ok(),
        "the listener must stop after cancel"
    );
}

#[tokio::test]
async fn client_without_a_certificate_is_rejected() {
    let pki = TestPki::mint();
    let acceptor = acceptor_for(&pki);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let (tx, rx) = watch::channel(false);
    let loop_task = tokio::spawn(run_miner_listener(listener, acceptor, router_state(), rx));

    // No client cert — the listener's mTLS acceptor REQUIRES one, so
    // the connection must NOT yield a working stream. mTLS is not
    // optional on the relay port.
    let connector = anonymous_client(&pki);
    let tcp = TcpStream::connect(addr).await.unwrap();
    let sni = ServerName::try_from("edge.test").unwrap();
    match connector.connect(sni, tcp).await {
        // Rejected outright at the handshake — the clean case.
        Err(_) => {}
        // TLS 1.3: the client can finish its half before the server's
        // certificate-required rejection alert arrives, so `connect`
        // may return `Ok`. The rejection then surfaces on the first
        // read — EOF or an error, never application data.
        Ok(mut tls) => {
            use tokio::io::AsyncReadExt;
            let mut buf = [0u8; 1];
            let read = tls.read(&mut buf).await;
            assert!(
                matches!(read, Ok(0) | Err(_)),
                "a client presenting no certificate must not get a working stream"
            );
        }
    }

    tx.send(true).unwrap();
    assert!(
        tokio::time::timeout(Duration::from_secs(5), loop_task)
            .await
            .is_ok(),
        "the listener must stop after cancel"
    );
}

#[tokio::test]
async fn client_offering_no_alpn_is_rejected_at_the_h2_gate() {
    // PR-H8 round-2: the wire is LOCKED to HTTP/2. A client that
    // completes the mTLS handshake but offers NO ALPN extension
    // (rustls still completes such a handshake) must be dropped at
    // the listener's ALPN gate — it would otherwise park a slot.
    let pki = TestPki::mint();
    let acceptor = acceptor_for(&pki);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let (tx, rx) = watch::channel(false);
    let loop_task = tokio::spawn(run_miner_listener(listener, acceptor, router_state(), rx));

    // mTLS-valid cert, but an empty ALPN list — no `h2` offered.
    let connector = mtls_client_with_alpn(
        &pki,
        &pki.valid_client_cert_pem,
        &pki.valid_client_key_pem,
        &[],
    );
    let tcp = TcpStream::connect(addr).await.unwrap();
    let sni = ServerName::try_from("edge.test").unwrap();
    // The TLS handshake itself succeeds (no ALPN extension ⇒ no
    // mismatch), but the server's ALPN gate then drops the
    // connection — the client gets no working stream.
    match connector.connect(sni, tcp).await {
        Err(_) => {}
        Ok(mut tls) => {
            use tokio::io::AsyncReadExt;
            let mut buf = [0u8; 1];
            let read = tls.read(&mut buf).await;
            assert!(
                matches!(read, Ok(0) | Err(_)),
                "a no-ALPN client must not get a working H2 stream"
            );
        }
    }

    tx.send(true).unwrap();
    assert!(
        tokio::time::timeout(Duration::from_secs(5), loop_task)
            .await
            .is_ok(),
        "the listener must stop after cancel"
    );
}

#[tokio::test]
async fn client_offering_http1_alpn_is_rejected() {
    // A client that offers ONLY `http/1.1` — no `h2` — must not get a
    // working stream. The server advertises `h2` only, so rustls
    // fails the handshake with `no_application_protocol`; even if it
    // did not, the listener's ALPN gate would drop the connection.
    let pki = TestPki::mint();
    let acceptor = acceptor_for(&pki);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let (tx, rx) = watch::channel(false);
    let loop_task = tokio::spawn(run_miner_listener(listener, acceptor, router_state(), rx));

    let connector = mtls_client_with_alpn(
        &pki,
        &pki.valid_client_cert_pem,
        &pki.valid_client_key_pem,
        &[b"http/1.1"],
    );
    let tcp = TcpStream::connect(addr).await.unwrap();
    let sni = ServerName::try_from("edge.test").unwrap();
    match connector.connect(sni, tcp).await {
        Err(_) => {}
        Ok(mut tls) => {
            use tokio::io::AsyncReadExt;
            let mut buf = [0u8; 1];
            let read = tls.read(&mut buf).await;
            assert!(
                matches!(read, Ok(0) | Err(_)),
                "an http/1.1-only client must not get a working stream"
            );
        }
    }

    tx.send(true).unwrap();
    assert!(
        tokio::time::timeout(Duration::from_secs(5), loop_task)
            .await
            .is_ok(),
        "the listener must stop after cancel"
    );
}

#[tokio::test]
async fn cancel_before_first_accept_returns_immediately() {
    let pki = TestPki::mint();
    let acceptor = acceptor_for(&pki);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();

    // Watch already holding `true` — the loop must return at once,
    // before accepting anything. `_tx` is held so the channel stays open.
    let (_tx, rx) = watch::channel(true);
    let loop_task = tokio::spawn(run_miner_listener(listener, acceptor, router_state(), rx));
    let finished = tokio::time::timeout(Duration::from_secs(2), loop_task).await;
    assert!(
        finished.is_ok(),
        "a pre-cancelled listener must return immediately"
    );
}

#[tokio::test]
async fn cancel_stops_a_running_listener() {
    let pki = TestPki::mint();
    let acceptor = acceptor_for(&pki);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();

    let (tx, rx) = watch::channel(false);
    let loop_task = tokio::spawn(run_miner_listener(listener, acceptor, router_state(), rx));
    // Let the loop reach its accept await, then signal shutdown.
    tokio::time::sleep(Duration::from_millis(50)).await;
    tx.send(true).unwrap();
    let finished = tokio::time::timeout(Duration::from_secs(5), loop_task).await;
    assert!(
        finished.is_ok(),
        "the listener must return promptly after a cancel"
    );
}
