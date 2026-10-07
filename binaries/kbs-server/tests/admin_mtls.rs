//! Integration test: the admin listener's mTLS gate.
//!
//! Every claim here is about a REAL rustls handshake over a real
//! loopback socket — the point of the finding this closes is that the
//! docs described an mTLS gate that no code implemented, so a mock would
//! prove nothing. The probe router counts how many requests reached a
//! handler; "refused" means that counter never moves.
//!
//! Separate-crate integration target, so it carries its own lint
//! allowance (`lib.rs`'s `#![cfg_attr(test, ...)]` does not reach here).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use axum::routing::get;
use axum::Router;
use hippius_kbs_server::admin_tls::{build_server_config, AdminTlsPaths};
use kbs_transport::{PeerCertInfo, SpiffeId};
use rcgen::{
    BasicConstraints, Certificate, CertificateParams, DnType, IsCa, KeyPair, KeyUsagePurpose,
    SanType,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use rustls::{ClientConfig, RootCertStore};
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_rustls::{TlsAcceptor, TlsConnector};

const SERVER_DNS: &str = "admin.kbs.test";
const VALI_SAN_URI: &str = "spiffe://hippius.network/vali";

const OPERATOR_SAN_URI: &str = "spiffe://hippius.network/operator";

/// The identities these harnesses admit: vali's, plus a second SPIFFE ID
/// so a leaf carrying BOTH can be exercised. Anything else chaining to
/// the same CA must be dropped.
fn allowed() -> Arc<Vec<SpiffeId>> {
    Arc::new(vec![
        SpiffeId::parse(VALI_SAN_URI).unwrap(),
        SpiffeId::parse(OPERATOR_SAN_URI).unwrap(),
    ])
}

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

/// Mint a leaf signed by `ca`. `san_uri`/`dns`/`cn` are each optional so
/// a test can build a cert with NO identity carrier at all.
fn mint_leaf(
    ca: &Certificate,
    ca_kp: &KeyPair,
    dns: Option<&str>,
    san_uri: Option<&str>,
    cn: Option<&str>,
) -> (String, String) {
    let kp = KeyPair::generate().unwrap();
    let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
    if let Some(d) = dns {
        params
            .subject_alt_names
            .push(SanType::DnsName(d.try_into().unwrap()));
    }
    if let Some(u) = san_uri {
        params
            .subject_alt_names
            .push(SanType::URI(u.try_into().unwrap()));
    }
    // rcgen's default params carry a `CN=rcgen self signed cert`, which
    // would silently give every "no identity" cert an identity — clear
    // the DN unless the caller asked for one.
    params.distinguished_name = rcgen::DistinguishedName::new();
    if let Some(c) = cn {
        params.distinguished_name.push(DnType::CommonName, c);
    }
    let leaf = params.signed_by(&kp, ca, ca_kp).unwrap();
    (leaf.pem(), kp.serialize_pem())
}

/// Mint a leaf signed by `ca` with exactly these SANs (none ⇒ no SAN
/// extension), this CN, and these raw extra extensions.
fn mint_leaf_sans(
    ca: &Certificate,
    ca_kp: &KeyPair,
    sans: Vec<SanType>,
    cn: Option<&str>,
    extra: Vec<rcgen::CustomExtension>,
) -> (String, String) {
    let kp = KeyPair::generate().unwrap();
    let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
    params.subject_alt_names = sans;
    params.custom_extensions = extra;
    params.distinguished_name = rcgen::DistinguishedName::new();
    if let Some(c) = cn {
        params.distinguished_name.push(DnType::CommonName, c);
    }
    let leaf = params.signed_by(&kp, ca, ca_kp).unwrap();
    (leaf.pem(), kp.serialize_pem())
}

fn uri_san(s: &str) -> SanType {
    SanType::URI(s.try_into().unwrap())
}

fn write(dir: &std::path::Path, name: &str, contents: &str) -> PathBuf {
    let p = dir.join(name);
    std::fs::write(&p, contents).unwrap();
    p
}

fn certs_from_pem(pem: &str) -> Vec<CertificateDer<'static>> {
    rustls_pemfile::certs(&mut std::io::Cursor::new(pem.as_bytes()))
        .map(|c| c.unwrap())
        .collect()
}

fn key_from_pem(pem: &str) -> PrivateKeyDer<'static> {
    rustls_pemfile::private_key(&mut std::io::Cursor::new(pem.as_bytes()))
        .unwrap()
        .unwrap()
}

// ── the probe server ────────────────────────────────────────────────

/// Shared record of what actually reached a handler.
#[derive(Default)]
struct Probe {
    hits: AtomicUsize,
    seen_peer: Mutex<Vec<Option<PeerCertInfo>>>,
}

struct Harness {
    addr: std::net::SocketAddr,
    probe: Arc<Probe>,
    /// Server-CA roots a client needs to verify the listener.
    server_roots: RootCertStore,
    _shutdown: tokio::sync::oneshot::Sender<()>,
}

/// Spin up `serve_admin_mtls` on an ephemeral port with a probe router,
/// using a client-CA-pinned config built from real PEM files on disk.
async fn start(dir: &std::path::Path) -> (Harness, Certificate, KeyPair) {
    let (ca, ca_kp) = mint_ca("hippius-admin-ca");
    let (srv_cert, srv_key) = mint_leaf(&ca, &ca_kp, Some(SERVER_DNS), None, Some(SERVER_DNS));

    let paths = AdminTlsPaths {
        cert: write(dir, "server.crt", &srv_cert),
        key: write(dir, "server.key", &srv_key),
        client_ca: write(dir, "ca.crt", &ca.pem()),
    };
    let acceptor = TlsAcceptor::from(Arc::new(build_server_config(&paths).unwrap()));

    let probe = Arc::new(Probe::default());
    let probe_for_router = Arc::clone(&probe);
    let router = Router::new().route(
        "/probe",
        get(move |req: axum::extract::Request| {
            let probe = Arc::clone(&probe_for_router);
            async move {
                probe.hits.fetch_add(1, Ordering::SeqCst);
                probe
                    .seen_peer
                    .lock()
                    .unwrap()
                    .push(req.extensions().get::<PeerCertInfo>().cloned());
                "ok"
            }
        }),
    );

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (tx, rx) = tokio::sync::oneshot::channel::<()>();
    tokio::spawn(async move {
        hippius_kbs_server::admin_tls::serve_admin_mtls(
            listener,
            acceptor,
            router,
            allowed(),
            async {
                let _ = rx.await;
            },
        )
        .await;
    });

    let mut server_roots = RootCertStore::empty();
    server_roots.add(ca.der().clone()).unwrap();

    (
        Harness {
            addr,
            probe,
            server_roots,
            _shutdown: tx,
        },
        ca,
        ca_kp,
    )
}

/// Outcome of one client exchange. The two failure shapes are kept
/// APART on purpose: "the TLS layer rejected me" and "the TLS layer
/// accepted me and then something dropped the connection" are the same
/// from a caller's point of view but NOT the same security property.
/// Folding them together lets a mutant that deletes the client-cert
/// requirement pass, because the post-handshake identity check would
/// still drop an anonymous peer.
#[derive(Debug)]
enum Exchange {
    /// A response came back.
    Response(String),
    /// The TLS layer itself refused (alert / handshake failure).
    TlsRejected(String),
    /// Handshake completed, then the peer was dropped with no reply.
    DroppedAfterHandshake,
}

/// One HTTP/1.1 exchange over TLS. `client` is `None` for an anonymous
/// (no client cert) peer.
async fn request(h: &Harness, client: Option<(String, String)>) -> Exchange {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let builder = ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_root_certificates(h.server_roots.clone());
    let cfg = match client {
        Some((cert_pem, key_pem)) => builder
            .with_client_auth_cert(certs_from_pem(&cert_pem), key_from_pem(&key_pem))
            .unwrap(),
        None => builder.with_no_client_auth(),
    };

    let tcp = tokio::net::TcpStream::connect(h.addr).await.unwrap();
    let name = ServerName::try_from(SERVER_DNS).unwrap();
    let mut tls = match TlsConnector::from(Arc::new(cfg)).connect(name, tcp).await {
        Ok(s) => s,
        Err(e) => return classify(e),
    };
    // In TLS 1.3 the client finishes its side before the server has
    // validated the client cert, so a rejection surfaces as an alert on
    // the first write/read rather than at `connect`.
    if let Err(e) = tls
        .write_all(b"GET /probe HTTP/1.1\r\nHost: admin\r\nConnection: close\r\n\r\n")
        .await
    {
        return classify(e);
    }
    let mut out = String::new();
    match tls.read_to_string(&mut out).await {
        Err(e) => classify(e),
        Ok(_) if out.is_empty() => Exchange::DroppedAfterHandshake,
        Ok(_) => Exchange::Response(out),
    }
}

/// Separate a TLS-level refusal from a transport-level drop. rustls
/// surfaces a peer alert / protocol failure as `InvalidData`; a
/// connection the server closed after a successful handshake shows up as
/// a reset / unexpected EOF / broken pipe.
fn classify(e: std::io::Error) -> Exchange {
    match e.kind() {
        std::io::ErrorKind::InvalidData => Exchange::TlsRejected(e.to_string()),
        _ => Exchange::DroppedAfterHandshake,
    }
}

/// The body of a successful exchange, or a panic naming what happened.
fn response_of(x: Exchange) -> String {
    match x {
        Exchange::Response(body) => body,
        other => panic!("expected a response, got {other:?}"),
    }
}

/// Give the server task a beat to finish refusing before we assert that
/// nothing reached a handler.
async fn settle() {
    tokio::time::sleep(Duration::from_millis(200)).await;
}

// ── claims ──────────────────────────────────────────────────────────

#[tokio::test]
async fn peer_with_no_client_cert_is_refused_before_any_handler() {
    // THE finding: an unauthenticated caller could POST
    // `/v1/admin/vm/<id>/seed-boot-counter` and get a 200. With the gate
    // in place the peer never reaches routing at all.
    let dir = tempfile::TempDir::new().unwrap();
    let (h, _ca, _ca_kp) = start(dir.path()).await;

    // The TLS layer itself must do the rejecting. Asserting only "no
    // response" would also pass if the client-cert requirement were
    // dropped and the peer merely fell through to the post-handshake
    // identity check — a strictly weaker gate.
    match request(&h, None).await {
        // The message is the peer alert rustls raised — proof the
        // refusal came from the TLS layer, not from a socket that
        // happened to close.
        Exchange::TlsRejected(msg) => assert!(msg.contains("alert"), "not a TLS alert: {msg}"),
        other => panic!("an anonymous peer must be rejected BY TLS, got {other:?}"),
    }
    settle().await;
    assert_eq!(
        h.probe.hits.load(Ordering::SeqCst),
        0,
        "no handler may run for a peer that presented no client cert"
    );
}

#[tokio::test]
async fn peer_from_a_different_ca_is_refused_before_any_handler() {
    // A cert is not enough — it must chain to the PINNED client CA.
    // Otherwise anyone who can mint any cert (i.e. anyone) is admitted.
    let dir = tempfile::TempDir::new().unwrap();
    let (h, _ca, _ca_kp) = start(dir.path()).await;

    let (rogue_ca, rogue_kp) = mint_ca("rogue-ca");
    let rogue = mint_leaf(&rogue_ca, &rogue_kp, None, Some(VALI_SAN_URI), Some("vali"));

    match request(&h, Some(rogue)).await {
        Exchange::TlsRejected(msg) => assert!(msg.contains("alert"), "not a TLS alert: {msg}"),
        other => panic!("an unpinned-CA cert must be rejected BY TLS, got {other:?}"),
    }
    settle().await;
    assert_eq!(h.probe.hits.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn peer_with_a_pinned_ca_cert_reaches_the_handler_with_its_identity() {
    // The other half of the contract: the legitimate caller still works,
    // AND its verified identity is carried into the request so the admin
    // audit row gets a real `peer_san` instead of `None`.
    let dir = tempfile::TempDir::new().unwrap();
    let (h, ca, ca_kp) = start(dir.path()).await;

    let vali = mint_leaf(&ca, &ca_kp, None, Some(VALI_SAN_URI), Some("vali"));
    let resp = response_of(request(&h, Some(vali)).await);
    assert!(resp.starts_with("HTTP/1.1 200"), "unexpected: {resp}");

    assert_eq!(h.probe.hits.load(Ordering::SeqCst), 1);
    let seen = h.probe.seen_peer.lock().unwrap();
    let peer = seen[0]
        .as_ref()
        .expect("PeerCertInfo must be injected into the request extensions");
    assert_eq!(peer.audit_identity(), VALI_SAN_URI);
    assert!(
        !peer.serial_hex.is_empty(),
        "the cert serial is the second half of the attribution"
    );
}

#[tokio::test]
async fn ca_issued_cert_without_any_identity_carrier_is_dropped() {
    // A cert the CA signed but that names nobody (no SAN URI, no SAN
    // DNS, no CN) would land in the audit chain as an empty `peer_san`,
    // indistinguishable from "no cert at all". Refuse instead.
    let dir = tempfile::TempDir::new().unwrap();
    let (h, ca, ca_kp) = start(dir.path()).await;

    // This one is dropped AFTER a successful handshake — the cert is
    // valid, it just names nobody.
    let anon = mint_leaf(&ca, &ca_kp, None, None, None);
    match request(&h, Some(anon)).await {
        Exchange::DroppedAfterHandshake => {}
        other => panic!("an unnamed peer must be dropped post-handshake, got {other:?}"),
    }
    settle().await;
    assert_eq!(h.probe.hits.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn every_leaf_that_is_not_uri_sans_only_all_listed_is_dropped() {
    // Chaining to the admin CA is necessary, not sufficient. Each of
    // these completes the handshake (the TLS layer accepts it — the gate
    // under test is ours, not webpki's) and is then dropped before any
    // handler: a CN or a DNS SAN never stands in for the URI, and a
    // listed URI beside anything else is an ambiguous leaf, not vali.
    let dir = tempfile::TempDir::new().unwrap();
    let (h, ca, ca_kp) = start(dir.path()).await;

    let email = SanType::Rfc822Name("vali@hippius.network".try_into().unwrap());
    let ip = SanType::IpAddress("127.0.0.1".parse().unwrap());
    let dns = |d: &str| SanType::DnsName(d.try_into().unwrap());
    let other_name = SanType::OtherName((
        vec![1, 3, 6, 1, 4, 1, 311, 20, 2, 3],
        rcgen::OtherNameValue::Utf8String("vali@hippius.network".into()),
    ));
    let cases: Vec<(&str, Vec<SanType>, Option<&str>)> = vec![
        ("CN-only spelling the URI", vec![], Some(VALI_SAN_URI)),
        ("CN-only vali", vec![], Some("vali")),
        ("DNS SAN spelling the URI", vec![dns(VALI_SAN_URI)], None),
        (
            "URI + DNS",
            vec![uri_san(VALI_SAN_URI), dns("vali.hippius.svc")],
            None,
        ),
        ("URI + IP", vec![uri_san(VALI_SAN_URI), ip], Some("vali")),
        (
            "URI + email",
            vec![uri_san(VALI_SAN_URI), email],
            Some("vali"),
        ),
        (
            "URI + otherName",
            vec![uri_san(VALI_SAN_URI), other_name],
            None,
        ),
        (
            "two URIs, one unlisted",
            vec![
                uri_san(VALI_SAN_URI),
                uri_san("spiffe://hippius.network/evil"),
            ],
            None,
        ),
        (
            "one unlisted URI",
            vec![uri_san("spiffe://hippius.network/evil")],
            None,
        ),
    ];
    for (label, sans, cn) in cases {
        let leaf = mint_leaf_sans(&ca, &ca_kp, sans, cn, vec![]);
        match request(&h, Some(leaf)).await {
            Exchange::DroppedAfterHandshake => {}
            other => panic!("{label}: must be dropped after the handshake, got {other:?}"),
        }
    }
    // A CONSTRUCTED [6] wrapping vali's exact bytes: webpki accepts the
    // leaf and x509-parser reads it as a URI SAN — the gate must not.
    let mut constructed_uri = vec![0xa6, VALI_SAN_URI.len() as u8];
    constructed_uri.extend_from_slice(VALI_SAN_URI.as_bytes());
    let mut san = vec![0x30, constructed_uri.len() as u8];
    san.extend(constructed_uri);
    let raw = rcgen::CustomExtension::from_oid_content(&[2, 5, 29, 17], san);
    let leaf = mint_leaf_sans(&ca, &ca_kp, vec![], None, vec![raw]);
    match request(&h, Some(leaf)).await {
        Exchange::DroppedAfterHandshake => {}
        other => panic!("constructed [6] URI: must be dropped after the handshake, got {other:?}"),
    }
    settle().await;
    assert_eq!(h.probe.hits.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn a_leaf_with_several_listed_uris_is_recorded_by_all_of_them() {
    // The audit identity is the full sorted URI list — not "the first
    // SAN" — so neither identity can hide behind the other.
    let dir = tempfile::TempDir::new().unwrap();
    let (h, ca, ca_kp) = start(dir.path()).await;

    let both = mint_leaf_sans(
        &ca,
        &ca_kp,
        vec![uri_san(VALI_SAN_URI), uri_san(OPERATOR_SAN_URI)],
        None,
        vec![],
    );
    let resp = response_of(request(&h, Some(both)).await);
    assert!(resp.starts_with("HTTP/1.1 200"));
    let seen = h.probe.seen_peer.lock().unwrap();
    assert_eq!(
        seen[0].as_ref().unwrap().audit_identity(),
        format!("{OPERATOR_SAN_URI},{VALI_SAN_URI}")
    );
}

// ── real router coverage: the suppressed-confirm admin reset ──────────
//
// Every test above proves the mTLS gate via a stand-in PROBE router —
// the strongest form of "the LISTENER is the gate, not any individual
// handler", since the same `TlsAcceptor` wraps whatever `Router` it is
// handed. This test proves it end to end for one specific,
// security-sensitive route instead of trusting that generalisation: it
// serves the REAL `kbs_transport::build_admin_router` (not a probe)
// over a REAL TLS handshake, with a REAL in-memory `AdminState` whose
// `volume_stamp` store already has a blocked VM in it. An anonymous
// caller reaching the handler would flip that VM's suppression counter
// back to zero — so "the store is unchanged after the request" is the
// same "no handler ran" proof the probe's hit-counter gives, just
// grounded in the actual route instead of a stand-in.

/// A distinctive posture for the `GET /v1/admin/config` wire tests.
/// Values are deliberately NOT the defaults so a handler that served a
/// zeroed/`Default` struct instead of the wired one would be visible.
/// (The DERIVATION from a real `Config` is tested separately in
/// `tests/admin_config_posture.rs`; this one tests the transport.)
fn test_posture() -> hippius_types::admin::AdminConfigPostureResponse {
    hippius_types::admin::AdminConfigPostureResponse {
        v: 1,
        require_wrapped_kek: true,
        require_wrapped_userdata: true,
        max_unconfirmed_releases: Some(3),
        volume_stamp_gate_armed: true,
        admin_listener_mode: "mtls".into(),
        evidence_sink_wired: true,
        live_attestation_sink_wired: true,
        allowlist_root_pubkey_fpr: "aabbccddeeff0011".into(),
        allowlist_root_next_pubkey_fpr: None,
        allowlist_signed_path_configured: true,
        l1_key_count: 2,
        min_tcb: 7,
        required_bits: 3,
        allowed_mask: 15,
        snp_chain_wired: true,
        snp_generation: Some("turin".into()),
        snp_kds_fetch_enabled: true,
        vault_broker_wired: true,
        vault_broker_ca_pinned: true,
        vault_ca_pinned: true,
        vault_dev_environment: false,
        vault_dev_allow_any_kbs_measurement: false,
        vault_dev_skip_tls_verify: false,
    }
}

/// Serve the REAL admin router (not the probe) behind the same mTLS
/// acceptor. Returns the volume-stamp store so the test can assert it
/// was never touched.
async fn start_with_real_admin_router(
    dir: &std::path::Path,
) -> (
    Harness,
    Certificate,
    KeyPair,
    Arc<kbs_core::volume_stamp::InMemoryVolumeStampStore>,
) {
    let (ca, ca_kp) = mint_ca("hippius-admin-ca");
    let (srv_cert, srv_key) = mint_leaf(&ca, &ca_kp, Some(SERVER_DNS), None, Some(SERVER_DNS));

    let paths = AdminTlsPaths {
        cert: write(dir, "server.crt", &srv_cert),
        key: write(dir, "server.key", &srv_key),
        client_ca: write(dir, "ca.crt", &ca.pem()),
    };
    let acceptor = TlsAcceptor::from(Arc::new(build_server_config(&paths).unwrap()));

    let keyring: Arc<dyn kbs_core::ticket::L1Keyring + Send + Sync> =
        Arc::new(hippius_kbs_server::l1_keyring::ConfigL1Keyring::from_entries(vec![]).unwrap());
    let vm_states: Arc<dyn kbs_core::admin::VmStateRegister + Send + Sync> =
        Arc::new(kbs_core::persist::FileVmStateStore::open(dir.join("vm-states.json")).unwrap());
    let idempotency: Arc<dyn kbs_core::persist::IdempotencyStore + Send + Sync> =
        Arc::new(kbs_core::persist::FileIdempotencyStore::open(dir.join("idem"), 86_400).unwrap());
    let audit =
        Arc::new(kbs_core::admin_audit::FileAdminAuditSink::open(dir.join("admin-audit")).unwrap());
    let limiter = Arc::new(kbs_transport::NonceRateLimiter::new(
        kbs_transport::RateConfig::default(),
    ));
    let allowlist_root = ed25519_dalek::SigningKey::from_bytes(&[9u8; 32]).verifying_key();
    let allowlist = Arc::new(kbs_core::allowlist::InstalledAllowlist::new(
        allowlist_root,
        Box::new(kbs_core::allowlist::InMemoryHwm::default()),
    ));
    let volume_stamp = Arc::new(kbs_core::volume_stamp::InMemoryVolumeStampStore::default());
    // Seed the target VM as BLOCKED. If the handler ever ran — the bug
    // this test exists to catch — the reset would clear it, flipping
    // the post-request assertion below from "still blocked" to "clear".
    {
        use kbs_core::volume_stamp::VolumeStampStore;
        for _ in 0..4 {
            volume_stamp.note_release("vm-guarded").unwrap();
        }
    }

    let admin_state = kbs_transport::AdminState {
        keyring,
        vm_states,
        idempotency,
        audit,
        limiter,
        allowlist,
        evidence: Arc::new(kbs_core::evidence::NullEvidenceSink),
        boot_counter: Arc::new(kbs_core::boot_counter::InMemoryBootCounterStore::default()),
        volume_stamp: Arc::clone(&volume_stamp)
            as Arc<dyn kbs_core::volume_stamp::VolumeStampStore>,
        // Mirrors the chart: the suppressed-confirm gate is DISABLED,
        // which is exactly the state in which an operator needs the
        // read route to decide whether it is safe to arm.
        configured_max_unconfirmed_releases: None,
        posture: Arc::new(test_posture()),
        custody: None,
        keepalive_bindings: std::sync::Arc::new(
            kbs_core::keepalive_binding::InMemoryKeepaliveBindings::default(),
        ),
        rollback: None,
        release_audit: None,
        cdn_fleet: None,
    };
    let router = kbs_transport::build_admin_router(admin_state);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (tx, rx) = tokio::sync::oneshot::channel::<()>();
    tokio::spawn(async move {
        hippius_kbs_server::admin_tls::serve_admin_mtls(
            listener,
            acceptor,
            router,
            allowed(),
            async {
                let _ = rx.await;
            },
        )
        .await;
    });

    let mut server_roots = RootCertStore::empty();
    server_roots.add(ca.der().clone()).unwrap();

    (
        Harness {
            addr,
            // Unused by this harness — the real router has no probe —
            // kept only so `Harness` stays one shape for `request()`.
            probe: Arc::new(Probe::default()),
            server_roots,
            _shutdown: tx,
        },
        ca,
        ca_kp,
        volume_stamp,
    )
}

/// Same TLS exchange as [`request`], but against an arbitrary path
/// instead of the fixed `/probe` — needed to reach the real admin
/// route.
async fn request_path(h: &Harness, client: Option<(String, String)>, path: &str) -> Exchange {
    request_method_path(h, client, "POST", path).await
}

/// [`request_path`] with an explicit HTTP method — the volume-stamp
/// report is a GET.
async fn request_method_path(
    h: &Harness,
    client: Option<(String, String)>,
    method: &str,
    path: &str,
) -> Exchange {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let builder = ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_root_certificates(h.server_roots.clone());
    let cfg = match client {
        Some((cert_pem, key_pem)) => builder
            .with_client_auth_cert(certs_from_pem(&cert_pem), key_from_pem(&key_pem))
            .unwrap(),
        None => builder.with_no_client_auth(),
    };

    let tcp = tokio::net::TcpStream::connect(h.addr).await.unwrap();
    let name = ServerName::try_from(SERVER_DNS).unwrap();
    let mut tls = match TlsConnector::from(Arc::new(cfg)).connect(name, tcp).await {
        Ok(s) => s,
        Err(e) => return classify(e),
    };
    let req = format!(
        "{method} {path} HTTP/1.1\r\nHost: admin\r\nContent-Type: application/json\r\n\
         Content-Length: 0\r\nConnection: close\r\n\r\n"
    );
    if let Err(e) = tls.write_all(req.as_bytes()).await {
        return classify(e);
    }
    let mut out = String::new();
    match tls.read_to_string(&mut out).await {
        Err(e) => classify(e),
        Ok(_) if out.is_empty() => Exchange::DroppedAfterHandshake,
        Ok(_) => Exchange::Response(out),
    }
}

#[tokio::test]
async fn reset_volume_stamp_suppression_is_refused_without_a_client_cert() {
    // The claim: an anonymous caller hitting the REAL
    // `/v1/admin/vm/:vm_id/reset-volume-stamp-suppression` route is
    // rejected by TLS before the handler — and specifically before it
    // could clear a VM's suppression counter, which is the entire
    // point of the route being admin-only (a miner able to clear its
    // own suppression would make the anti-rollback gate ornamental).
    let dir = tempfile::TempDir::new().unwrap();
    let (h, _ca, _ca_kp, volume_stamp) = start_with_real_admin_router(dir.path()).await;

    match request_path(
        &h,
        None,
        "/v1/admin/vm/vm-guarded/reset-volume-stamp-suppression",
    )
    .await
    {
        Exchange::TlsRejected(msg) => assert!(msg.contains("alert"), "not a TLS alert: {msg}"),
        other => panic!("an anonymous peer must be rejected BY TLS, got {other:?}"),
    }
    settle().await;

    // The real proof: the handler never ran, so the seeded suppression
    // is UNCHANGED — a fresh `note_release` still sees the VM well past
    // the bound, not reset to a low count.
    use kbs_core::volume_stamp::VolumeStampStore;
    let (confirmed, unconfirmed) = volume_stamp.note_release("vm-guarded").unwrap();
    assert_eq!(
        confirmed, 0,
        "an anonymous caller must not touch the confirmed stamp either"
    );
    assert_eq!(
        unconfirmed, 5,
        "the seeded count (4) plus this test's own probe call (5) — if the anonymous \
         request's reset had run, this would read 1 instead"
    );
}

#[tokio::test]
async fn every_rollback_route_is_refused_by_tls_without_a_client_cert() {
    // The authorized rollback is the one KBS path that admits a rewound
    // boot. Nothing without an admin client cert may reach any of its
    // routes: TLS must drop the peer before routing.
    let dir = tempfile::TempDir::new().unwrap();
    let (h, _ca, _ca_kp, _vs) = start_with_real_admin_router(dir.path()).await;
    for (method, path) in [
        ("POST", "/v1/admin/vm/vm-1/rollback-checkpoint"),
        ("POST", "/v1/admin/vm/vm-1/authorize-rollback"),
        ("DELETE", "/v1/admin/vm/vm-1/authorize-rollback/r-1"),
        ("GET", "/v1/admin/vm/vm-1/rollback"),
    ] {
        match request_method_path(&h, None, method, path).await {
            Exchange::TlsRejected(msg) => assert!(msg.contains("alert"), "{method} {path}: {msg}"),
            other => {
                panic!("{method} {path}: an anonymous peer must be rejected BY TLS, got {other:?}")
            }
        }
    }
}

#[tokio::test]
async fn reset_volume_stamp_suppression_succeeds_for_a_pinned_ca_peer() {
    // The other half: a legitimately mTLS-authenticated caller (the
    // SAME identity path every other admin route uses) really can
    // reach and use this route over the real listener — the gate above
    // is a gate, not a permanent lockout.
    let dir = tempfile::TempDir::new().unwrap();
    let (h, ca, ca_kp, volume_stamp) = start_with_real_admin_router(dir.path()).await;

    let vali = mint_leaf(&ca, &ca_kp, None, Some(VALI_SAN_URI), Some("vali"));
    let resp = response_of(
        request_path(
            &h,
            Some(vali),
            "/v1/admin/vm/vm-guarded/reset-volume-stamp-suppression",
        )
        .await,
    );
    assert!(resp.starts_with("HTTP/1.1 200"), "unexpected: {resp}");

    use kbs_core::volume_stamp::VolumeStampStore;
    // The reset landed: `confirmed` is untouched, but the suppression
    // count is back at 0 — the next release is no longer refused.
    assert_eq!(volume_stamp.get("vm-guarded").unwrap(), 0);
    assert_eq!(
        volume_stamp.note_release("vm-guarded").unwrap(),
        (0, 1),
        "count resumed from 0 after the authenticated reset"
    );
}

// ── the volume-stamp READ route (cutover step 3) ─────────────────────
//
// The read route is deliberately STRICTER than every write route in
// this module: the writes are gated by the LISTENER (a plaintext
// listener serves them — the documented `require_mtls=false` opt-in the
// cluster runs today), while the read ADDITIONALLY requires the request
// to carry a VERIFIED client cert. These tests pin both halves: it
// answers over real mTLS, and it refuses on a plaintext listener that
// happily serves its siblings.

/// Extract the JSON body of an `HTTP/1.1 …` response string.
fn json_body(resp: &str) -> serde_json::Value {
    let body = resp
        .split_once("\r\n\r\n")
        .map(|(_, b)| b)
        .unwrap_or_else(|| panic!("no body in: {resp}"));
    serde_json::from_str(body.trim()).unwrap_or_else(|e| panic!("body not JSON ({e}): {body}"))
}

#[tokio::test]
async fn volume_stamp_report_answers_for_a_pinned_ca_peer_and_reflects_note_release() {
    // The claim: an mTLS-authenticated operator can actually PERFORM
    // cutover step 3 — read the per-VM released/confirmed counters back
    // out of a store that lives on an emptyDir inside a Kata CVM.
    let dir = tempfile::TempDir::new().unwrap();
    let (h, ca, ca_kp, volume_stamp) = start_with_real_admin_router(dir.path()).await;

    // `start_with_real_admin_router` seeded vm-guarded with 4
    // unconfirmed releases and no confirm. Add a healthy VM.
    {
        use kbs_core::volume_stamp::VolumeStampStore;
        volume_stamp.note_release("vm-healthy").unwrap();
        volume_stamp.confirm("vm-healthy", 1).unwrap();
    }

    let vali = mint_leaf(&ca, &ca_kp, None, Some(VALI_SAN_URI), Some("vali"));
    let resp = response_of(
        request_method_path(&h, Some(vali), "GET", "/v1/admin/volume-stamp?bound=3").await,
    );
    assert!(resp.starts_with("HTTP/1.1 200"), "unexpected: {resp}");
    let v = json_body(&resp);

    // The report must reflect the REAL counters, not zeros: a route that
    // never actually read `note_release`'s state would report a green
    // fleet here.
    assert_eq!(v["evaluated_bound"], 3);
    assert_eq!(v["configured_bound"], serde_json::Value::Null);
    assert_eq!(v["gate_armed"], false);
    assert_eq!(v["vms"], 2);
    assert_eq!(v["never_confirmed"], 1);
    assert_eq!(v["would_refuse_now"], 1);
    assert_eq!(v["ready_to_arm"], false);

    let rows = v["rows"].as_array().unwrap();
    assert_eq!(rows[0]["vm_id"], "vm-guarded");
    assert_eq!(rows[0]["confirmed"], 0);
    assert_eq!(rows[0]["unconfirmed_releases"], 4);
    assert_eq!(rows[0]["has_ever_confirmed"], false);
    assert_eq!(rows[0]["would_refuse_next_release"], true);
    assert_eq!(rows[1]["vm_id"], "vm-healthy");
    assert_eq!(rows[1]["confirmed"], 1);
    assert_eq!(rows[1]["unconfirmed_releases"], 0);
    assert_eq!(rows[1]["has_ever_confirmed"], true);
    assert_eq!(rows[1]["would_refuse_next_release"], false);

    // And it changed NOTHING: the suppression streak the operator was
    // inspecting is exactly where it was. A read that reset a streak
    // would make the next count 1 instead of 5.
    use kbs_core::volume_stamp::VolumeStampStore;
    assert_eq!(
        volume_stamp.note_release("vm-guarded").unwrap(),
        (0, 5),
        "reading the report must not clear the suppression counter"
    );
    assert_eq!(volume_stamp.get("vm-healthy").unwrap(), 1);
}

#[tokio::test]
async fn config_posture_answers_for_a_pinned_ca_peer() {
    // The claim half 2 exists for: an mTLS-authenticated operator (or
    // the synthetic monitor) can ask the RUNNING process what it is
    // actually enforcing, instead of reading a ConfigMap the process may
    // never have seen.
    let dir = tempfile::TempDir::new().unwrap();
    let (h, ca, ca_kp, _volume_stamp) = start_with_real_admin_router(dir.path()).await;

    let vali = mint_leaf(&ca, &ca_kp, None, Some(VALI_SAN_URI), Some("vali"));
    let resp = response_of(request_method_path(&h, Some(vali), "GET", "/v1/admin/config").await);
    assert!(resp.starts_with("HTTP/1.1 200"), "unexpected: {resp}");
    let v = json_body(&resp);

    // The WIRED posture, not a default-constructed one.
    assert_eq!(v["v"], 1);
    assert_eq!(v["max_unconfirmed_releases"], 3);
    assert_eq!(v["volume_stamp_gate_armed"], true);
    assert_eq!(v["require_wrapped_kek"], true);
    assert_eq!(v["require_wrapped_userdata"], true);
    assert_eq!(v["admin_listener_mode"], "mtls");
    assert_eq!(v["min_tcb"], 7);
    assert_eq!(v["l1_key_count"], 2);
    assert_eq!(v["allowlist_root_pubkey_fpr"], "aabbccddeeff0011");
    assert_eq!(
        v["allowlist_root_next_pubkey_fpr"],
        serde_json::Value::Null,
        "an absent rotation root must be null, not an empty string"
    );
}

#[tokio::test]
async fn config_posture_is_refused_without_a_client_cert() {
    let dir = tempfile::TempDir::new().unwrap();
    let (h, _ca, _ca_kp, _volume_stamp) = start_with_real_admin_router(dir.path()).await;

    match request_method_path(&h, None, "GET", "/v1/admin/config").await {
        Exchange::TlsRejected(msg) => assert!(msg.contains("alert"), "not a TLS alert: {msg}"),
        other => panic!("an anonymous peer must be rejected BY TLS, got {other:?}"),
    }
}

#[tokio::test]
async fn volume_stamp_report_is_refused_without_a_client_cert() {
    let dir = tempfile::TempDir::new().unwrap();
    let (h, _ca, _ca_kp, _volume_stamp) = start_with_real_admin_router(dir.path()).await;

    match request_method_path(&h, None, "GET", "/v1/admin/volume-stamp").await {
        Exchange::TlsRejected(msg) => assert!(msg.contains("alert"), "not a TLS alert: {msg}"),
        other => panic!("an anonymous peer must be rejected BY TLS, got {other:?}"),
    }
}

/// Serve the REAL admin router on a PLAIN `TcpListener` — byte-for-byte
/// what `admin.require_mtls=false` with no TLS material does today
/// (`server::spawn_admin_listener`'s `AdminListenerMode::PlaintextOptIn`
/// arm). No `PeerCertInfo` is ever injected on this path.
async fn start_plaintext_admin_router(
    dir: &std::path::Path,
) -> (
    std::net::SocketAddr,
    Arc<kbs_core::volume_stamp::InMemoryVolumeStampStore>,
    tokio::sync::oneshot::Sender<()>,
) {
    let keyring: Arc<dyn kbs_core::ticket::L1Keyring + Send + Sync> =
        Arc::new(hippius_kbs_server::l1_keyring::ConfigL1Keyring::from_entries(vec![]).unwrap());
    let vm_states: Arc<dyn kbs_core::admin::VmStateRegister + Send + Sync> =
        Arc::new(kbs_core::persist::FileVmStateStore::open(dir.join("vm-states.json")).unwrap());
    let idempotency: Arc<dyn kbs_core::persist::IdempotencyStore + Send + Sync> =
        Arc::new(kbs_core::persist::FileIdempotencyStore::open(dir.join("idem"), 86_400).unwrap());
    let audit =
        Arc::new(kbs_core::admin_audit::FileAdminAuditSink::open(dir.join("admin-audit")).unwrap());
    let limiter = Arc::new(kbs_transport::NonceRateLimiter::new(
        kbs_transport::RateConfig::default(),
    ));
    let allowlist_root = ed25519_dalek::SigningKey::from_bytes(&[9u8; 32]).verifying_key();
    let allowlist = Arc::new(kbs_core::allowlist::InstalledAllowlist::new(
        allowlist_root,
        Box::new(kbs_core::allowlist::InMemoryHwm::default()),
    ));
    let volume_stamp = Arc::new(kbs_core::volume_stamp::InMemoryVolumeStampStore::default());
    {
        use kbs_core::volume_stamp::VolumeStampStore;
        for _ in 0..4 {
            volume_stamp.note_release("vm-guarded").unwrap();
        }
    }
    let router = kbs_transport::build_admin_router(kbs_transport::AdminState {
        keyring,
        vm_states,
        idempotency,
        audit,
        limiter,
        allowlist,
        evidence: Arc::new(kbs_core::evidence::NullEvidenceSink),
        boot_counter: Arc::new(kbs_core::boot_counter::InMemoryBootCounterStore::default()),
        volume_stamp: Arc::clone(&volume_stamp)
            as Arc<dyn kbs_core::volume_stamp::VolumeStampStore>,
        configured_max_unconfirmed_releases: None,
        posture: Arc::new(test_posture()),
        custody: None,
        keepalive_bindings: std::sync::Arc::new(
            kbs_core::keepalive_binding::InMemoryKeepaliveBindings::default(),
        ),
        rollback: None,
        release_audit: None,
        cdn_fleet: None,
    });

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (tx, rx) = tokio::sync::oneshot::channel::<()>();
    tokio::spawn(async move {
        let _ = axum::serve(listener, router)
            .with_graceful_shutdown(async {
                let _ = rx.await;
            })
            .await;
    });
    (addr, volume_stamp, tx)
}

/// One plaintext HTTP/1.1 request/response over TCP.
async fn plaintext_request(addr: std::net::SocketAddr, method: &str, path: &str) -> String {
    let mut tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
    let req = format!(
        "{method} {path} HTTP/1.1\r\nHost: admin\r\nContent-Type: application/json\r\n\
         Content-Length: 0\r\nConnection: close\r\n\r\n"
    );
    tcp.write_all(req.as_bytes()).await.unwrap();
    let mut out = Vec::new();
    tcp.read_to_end(&mut out).await.unwrap();
    String::from_utf8_lossy(&out).into_owned()
}

#[tokio::test]
async fn volume_stamp_report_refuses_while_the_admin_listener_is_plaintext() {
    // THE disclosure claim. The cluster runs `admin.require_mtls=false`
    // with a NetworkPolicy as the only control, so a route that dumped
    // per-VM release/confirm counters over that listener would hand
    // anything that can reach the port a per-tenant operational readout
    // — including which VMs are one release away from being refused. It
    // must refuse, and refuse WITHOUT disclosing a row.
    let dir = tempfile::TempDir::new().unwrap();
    let (addr, volume_stamp, _shutdown) = start_plaintext_admin_router(dir.path()).await;

    let resp = plaintext_request(addr, "GET", "/v1/admin/volume-stamp").await;
    assert!(
        resp.starts_with("HTTP/1.1 403"),
        "the read route must refuse on a plaintext listener, got: {resp}"
    );
    assert!(
        !resp.contains("vm-guarded"),
        "the refusal must not leak a single row: {resp}"
    );

    // Same gate on the posture readout. On an unauthenticated listener
    // this endpoint would hand anything that can reach the port a list
    // of which gates are off — a shopping list, not a health check.
    let posture = plaintext_request(addr, "GET", "/v1/admin/config").await;
    assert!(
        posture.starts_with("HTTP/1.1 403"),
        "the posture route must refuse on a plaintext listener, got: {posture}"
    );
    assert!(
        !posture.contains("max_unconfirmed_releases") && !posture.contains("admin_listener_mode"),
        "the refusal must not leak a single posture field: {posture}"
    );

    // Control: the WRITE routes are UNCHANGED — this change did not
    // tighten (or loosen) the existing listener policy, it only added a
    // route with a stricter one. If this ever fails, the diff has
    // touched an existing gate and must be re-reviewed.
    let reset = plaintext_request(
        addr,
        "POST",
        "/v1/admin/vm/vm-guarded/reset-volume-stamp-suppression",
    )
    .await;
    assert!(
        reset.starts_with("HTTP/1.1 200"),
        "existing admin write behaviour on a plaintext listener must be UNCHANGED, got: {reset}"
    );
    use kbs_core::volume_stamp::VolumeStampStore;
    assert_eq!(volume_stamp.note_release("vm-guarded").unwrap(), (0, 1));
}
