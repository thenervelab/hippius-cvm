//! Integration test: the two halves of the admin mTLS gate, together.
//!
//! `admin_mtls.rs` proves the SERVER refuses unauthenticated peers, using
//! a hand-rolled rustls client. This file proves the other, equally
//! load-bearing half: that `hippius-kbs-admin-client` — the binary vali
//! shells out to for every §24 `register-vm`, and the thing whose absence
//! kept `require_mtls = false` in production — actually completes that
//! handshake, and refuses the connections it must refuse.
//!
//! Why in one process: a mutual-TLS gate has two failure modes that no
//! single-sided test can see. If the client cannot present an acceptable
//! cert, EVERY launch fails at the pre-registration step; if the client
//! would accept a server it should not, the pinning is decorative. Both
//! are exercised here against the REAL `serve_admin_mtls` and the REAL
//! `mtls::build_client_config`, over a real loopback socket.
//!
//! Separate-crate integration target, so it carries its own lint
//! allowance.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use axum::routing::get;
use axum::Router;
use hippius_kbs_admin_client::mtls::{self, AdminClientTlsPaths};
use hippius_kbs_server::admin_tls::{build_server_config, AdminTlsPaths};
use rcgen::{
    BasicConstraints, Certificate, CertificateParams, DnType, IsCa, KeyPair, KeyUsagePurpose,
    SanType,
};
use rustls::{ClientConfig, RootCertStore};
use std::net::{IpAddr, Ipv4Addr};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use tokio_rustls::TlsAcceptor;

const VALI_SAN_URI: &str = "spiffe://hippius.network/vali";
const LOOPBACK: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);

// ── throwaway PKI ───────────────────────────────────────────────────

fn mint_ca(cn: &str) -> (Certificate, KeyPair) {
    let kp = KeyPair::generate().unwrap();
    let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    params.distinguished_name.push(DnType::CommonName, cn);
    let ca = params.self_signed(&kp).unwrap();
    (ca, kp)
}

/// Server leaf with an IP SAN for 127.0.0.1, so a client can dial
/// `https://127.0.0.1:<port>` and rustls' ordinary hostname/IP
/// verification applies — no `dangerous()` shortcut anywhere.
fn mint_server_leaf(ca: &Certificate, ca_kp: &KeyPair) -> (String, String) {
    let kp = KeyPair::generate().unwrap();
    let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
    params.subject_alt_names.push(SanType::IpAddress(LOOPBACK));
    params
        .distinguished_name
        .push(DnType::CommonName, "kbs-server-admin");
    let leaf = params.signed_by(&kp, ca, ca_kp).unwrap();
    (leaf.pem(), kp.serialize_pem())
}

/// Client leaf carrying the SPIFFE SAN URI the KBS reads back as the
/// admin audit row's `peer_san`.
fn mint_client_leaf(ca: &Certificate, ca_kp: &KeyPair) -> (String, String) {
    let kp = KeyPair::generate().unwrap();
    let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
    params
        .subject_alt_names
        .push(SanType::URI(VALI_SAN_URI.try_into().unwrap()));
    params.distinguished_name = rcgen::DistinguishedName::new();
    let leaf = params.signed_by(&kp, ca, ca_kp).unwrap();
    (leaf.pem(), kp.serialize_pem())
}

fn write(dir: &Path, name: &str, contents: &str) -> PathBuf {
    let p = dir.join(name);
    std::fs::write(&p, contents).unwrap();
    p
}

// ── the probe server ────────────────────────────────────────────────

struct Harness {
    addr: std::net::SocketAddr,
    hits: Arc<AtomicUsize>,
    _shutdown: tokio::sync::oneshot::Sender<()>,
}

/// Serve `serve_admin_mtls` on an ephemeral loopback port.
///
/// `server_ca` signs the listener's own cert; `client_ca_pem` is the
/// PINNED bundle every client cert must chain to. Splitting them is what
/// lets a test point the client at the wrong server CA (or sign a client
/// cert with a rogue CA) without touching anything else.
async fn start(dir: &Path, server_ca: &(Certificate, KeyPair), client_ca_pem: &str) -> Harness {
    let (srv_cert, srv_key) = mint_server_leaf(&server_ca.0, &server_ca.1);
    let paths = AdminTlsPaths {
        cert: write(dir, "server.crt", &srv_cert),
        key: write(dir, "server.key", &srv_key),
        client_ca: write(dir, "client-ca.crt", client_ca_pem),
    };
    let acceptor = TlsAcceptor::from(Arc::new(build_server_config(&paths).unwrap()));

    let hits = Arc::new(AtomicUsize::new(0));
    let router = {
        let hits = Arc::clone(&hits);
        Router::new().route(
            "/v1/admin/vm/:vm_id/evidence",
            get(move || {
                let hits = Arc::clone(&hits);
                async move {
                    hits.fetch_add(1, Ordering::SeqCst);
                    "reached-the-handler"
                }
            }),
        )
    };

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (tx, rx) = tokio::sync::oneshot::channel();
    tokio::spawn(async move {
        hippius_kbs_server::admin_tls::serve_admin_mtls(listener, acceptor, router, async {
            let _ = rx.await;
        })
        .await;
    });
    // Let the accept loop reach `listener.accept()`.
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    Harness {
        addr,
        hits,
        _shutdown: tx,
    }
}

/// Outcome of one blocking ureq round-trip, classified the way the CLI
/// classifies it.
#[derive(Debug, PartialEq, Eq)]
enum Outcome {
    /// A handler answered with this status.
    Status(u16),
    /// Transport-level failure — for this test, always a rejected TLS
    /// handshake. The string is kept for diagnosis, not asserted on
    /// (rustls wording is not a stable API).
    Transport(String),
}

/// Drive a real HTTP GET through `agent`. ureq is blocking, so this runs
/// on the blocking pool.
async fn http_get(agent: ureq::Agent, url: String) -> Outcome {
    tokio::task::spawn_blocking(move || match agent.get(&url).call() {
        Ok(r) => Outcome::Status(r.status()),
        Err(ureq::Error::Status(s, _)) => Outcome::Status(s),
        Err(ureq::Error::Transport(t)) => Outcome::Transport(t.to_string()),
    })
    .await
    .unwrap()
}

fn url_for(h: &Harness) -> String {
    format!("https://{}/v1/admin/vm/probe-vm/evidence", h.addr)
}

/// An agent built the way the SHIPPED CLI builds it — the real
/// `mtls::build_client_config`, no test-local TLS assembly.
fn shipped_agent(paths: &AdminClientTlsPaths) -> ureq::Agent {
    let cfg = mtls::build_client_config(paths).unwrap();
    ureq::AgentBuilder::new()
        .timeout(std::time::Duration::from_secs(5))
        .tls_config(Arc::new(cfg))
        .build()
}

// ── the claims ──────────────────────────────────────────────────────

#[tokio::test]
async fn shipped_client_config_completes_the_handshake_and_reaches_a_handler() {
    // THE availability claim. If this fails, flipping `require_mtls` on
    // takes down every launch (§24 register-vm) and every §22 auto-pin —
    // which is exactly why the flag could not be flipped before this
    // client existed. It is not enough that each side is individually
    // "correct": they have to interoperate.
    let dir = tempfile::tempdir().unwrap();
    let ca = mint_ca("hippius-kbs-admin-ca");
    let ca_pem = ca.0.pem();
    let h = start(dir.path(), &ca, &ca_pem).await;

    let (cli_cert, cli_key) = mint_client_leaf(&ca.0, &ca.1);
    let paths = AdminClientTlsPaths {
        cert: write(dir.path(), "vali.crt", &cli_cert),
        key: write(dir.path(), "vali.key", &cli_key),
        ca: write(dir.path(), "pinned-ca.crt", &ca_pem),
    };

    let outcome = http_get(shipped_agent(&paths), url_for(&h)).await;
    assert_eq!(
        outcome,
        Outcome::Status(200),
        "mTLS round-trip must succeed"
    );
    assert_eq!(h.hits.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn a_client_that_presents_no_certificate_never_reaches_a_handler() {
    // The mutation this kills: dropping `with_client_auth_cert` from
    // `build_client_config` (or "temporarily" building an anonymous
    // agent) would leave a client that still speaks TLS and still looks
    // like it is doing something secure. It must not be served.
    let dir = tempfile::tempdir().unwrap();
    let ca = mint_ca("hippius-kbs-admin-ca");
    let ca_pem = ca.0.pem();
    let h = start(dir.path(), &ca, &ca_pem).await;

    let mut roots = RootCertStore::empty();
    for c in rustls_pemfile::certs(&mut std::io::Cursor::new(ca_pem.as_bytes())) {
        roots.add(c.unwrap()).unwrap();
    }
    let anon =
        ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth();
    let agent = ureq::AgentBuilder::new()
        .timeout(std::time::Duration::from_secs(5))
        .tls_config(Arc::new(anon))
        .build();

    let outcome = http_get(agent, url_for(&h)).await;
    assert!(
        matches!(outcome, Outcome::Transport(_)),
        "anonymous client must be refused, got {outcome:?}"
    );
    assert_eq!(
        h.hits.load(Ordering::SeqCst),
        0,
        "no request may reach a handler without a client certificate"
    );
}

#[tokio::test]
async fn the_client_refuses_a_server_whose_cert_is_from_an_unpinned_ca() {
    // The mutation this kills: pinning the CA with `webpki_roots` bolted
    // on, or an `ServerCertVerifier` that accepts anything. Without this
    // property a peer that wins the ClusterIP race — or anyone holding a
    // public cert for the admin Service DNS — collects vali's client
    // certificate presentation and its lifecycle payload.
    let dir = tempfile::tempdir().unwrap();
    let pinned = mint_ca("hippius-kbs-admin-ca");
    let rogue = mint_ca("rogue-ca");
    // The listener's identity is signed by the ROGUE CA; its client-CA
    // pin is still the real one, so the ONLY thing wrong is the server's
    // own cert.
    let h = start(dir.path(), &rogue, &pinned.0.pem()).await;

    let (cli_cert, cli_key) = mint_client_leaf(&pinned.0, &pinned.1);
    let paths = AdminClientTlsPaths {
        cert: write(dir.path(), "vali.crt", &cli_cert),
        key: write(dir.path(), "vali.key", &cli_key),
        // We pin the REAL CA — which the rogue server cannot chain to.
        ca: write(dir.path(), "pinned-ca.crt", &pinned.0.pem()),
    };

    let outcome = http_get(shipped_agent(&paths), url_for(&h)).await;
    assert!(
        matches!(outcome, Outcome::Transport(_)),
        "an unpinned server cert must be refused, got {outcome:?}"
    );
    assert_eq!(h.hits.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn the_server_refuses_a_client_cert_signed_by_an_unpinned_ca() {
    // Symmetric mutation: a client verifier built over the wrong bundle
    // (or one extended with the system roots) would admit any cert some
    // public CA will issue. Here the client is otherwise perfect — right
    // server pin, real key, valid chain — and is refused solely because
    // its issuer is not the pinned admin CA.
    let dir = tempfile::tempdir().unwrap();
    let pinned = mint_ca("hippius-kbs-admin-ca");
    let rogue = mint_ca("rogue-ca");
    let h = start(dir.path(), &pinned, &pinned.0.pem()).await;

    let (cli_cert, cli_key) = mint_client_leaf(&rogue.0, &rogue.1);
    let paths = AdminClientTlsPaths {
        cert: write(dir.path(), "rogue.crt", &cli_cert),
        key: write(dir.path(), "rogue.key", &cli_key),
        ca: write(dir.path(), "pinned-ca.crt", &pinned.0.pem()),
    };

    let outcome = http_get(shipped_agent(&paths), url_for(&h)).await;
    assert!(
        matches!(outcome, Outcome::Transport(_)),
        "a client cert from an unpinned CA must be refused, got {outcome:?}"
    );
    assert_eq!(h.hits.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn a_plaintext_client_gets_nothing_from_an_mtls_listener() {
    // The rollout-order claim, from the client side: if vali is still on
    // `http://` after the KBS has been cut over, the calls FAIL LOUDLY —
    // there is no downgrade path in which an admin mutation lands
    // unauthenticated. (This is why the runbook flips vali immediately
    // after the KBS, and why the failure is a retryable
    // `EffectUnavailable`, not a silent success.)
    let dir = tempfile::tempdir().unwrap();
    let ca = mint_ca("hippius-kbs-admin-ca");
    let h = start(dir.path(), &ca, &ca.0.pem()).await;

    let agent = ureq::AgentBuilder::new()
        .timeout(std::time::Duration::from_secs(5))
        .build();
    let url = format!("http://{}/v1/admin/vm/probe-vm/evidence", h.addr);
    let outcome = http_get(agent, url).await;
    assert!(
        matches!(outcome, Outcome::Transport(_)),
        "plaintext against an mTLS listener must fail, got {outcome:?}"
    );
    assert_eq!(h.hits.load(Ordering::SeqCst), 0);
}
