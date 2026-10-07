//! `GET /v1/admin/audit` against the REAL wiring and the REAL mTLS
//! listener.
//!
//! Two claims a unit test inside kbs-transport cannot make:
//! 1. `?log=release` reads the SAME release chain the release path
//!    appends to — `wiring::build_service` hands one `FileAuditSink` to
//!    both (a second `open` would block on its exclusive lock).
//! 2. The route inherits the admin listener's client allowlist: vali's
//!    identity gets the chain, a leaf the same CA minted for anyone else
//!    — or no client cert at all — never reaches the handler.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use ed25519_dalek::SigningKey;
use hippius_kbs_server::admin_tls::{build_server_config, AdminTlsPaths};
use hippius_kbs_server::config::Config;
use hippius_kbs_server::wiring::{build_admin_state, build_service, WiredKbs};
use kbs_transport::SpiffeId;
use rcgen::{
    BasicConstraints, Certificate, CertificateParams, DnType, IsCa, KeyPair, KeyUsagePurpose,
    SanType,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use rustls::{ClientConfig, RootCertStore};
use std::io::Write;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_rustls::{TlsAcceptor, TlsConnector};
use zeroize::Zeroizing;

const SERVER_DNS: &str = "admin.kbs.test";
const VALI_SAN_URI: &str = "spiffe://hippius.network/vali";

// ── a real wired KBS with [admin] ───────────────────────────────────

fn wired(dir: &std::path::Path) -> (Config, WiredKbs) {
    let state = dir.join("state");
    let audit = dir.join("audit");
    std::fs::create_dir_all(&state).unwrap();
    std::fs::create_dir_all(&audit).unwrap();
    let key_path = dir.join("signing.key");
    std::fs::write(&key_path, [7u8; 32]).unwrap();
    let root_hex = hex::encode(
        SigningKey::from_bytes(&[3u8; 32])
            .verifying_key()
            .to_bytes(),
    );
    let toml = format!(
        r#"
[listen]
addr = "127.0.0.1:8000"

[storage]
state_dir = "{state}"
audit_dir = "{audit}"
nonce_ttl_secs = 300

[allowlist]
root_pubkey_hex = "{root_hex}"

[keys]
signing_key_path = "{key}"
kid_hex = "6b62732d6b6964"
auth_pubkey_hex = "6b62732d617574682d7075626b6579"

[vault]
address = "https://127.0.0.1:8200"
kv_mount = "secret"

[launch_policy]
min_tcb = 0
required_bits = 0
allowed_mask = 0

[live_attestation]
compute_chain_genesis_hex = "6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e"
compute_pallet_instance_hex = "c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0"

[admin]
addr = "127.0.0.1:8001"
"#,
        state = state.display(),
        audit = audit.display(),
        key = key_path.display(),
    );
    let mut f = tempfile::NamedTempFile::new().unwrap();
    f.write_all(toml.as_bytes()).unwrap();
    let cfg = Config::load(f.path()).expect("config must load");
    let wired = build_service(&cfg, Zeroizing::new("t".to_string())).expect("wires");
    (cfg, wired)
}

/// The admin router exactly as `server::spawn_admin_listener` builds it.
fn admin_router(cfg: &Config, w: &WiredKbs) -> axum::Router {
    let state = build_admin_state(
        cfg,
        Arc::clone(&w.l1_keyring),
        Arc::clone(&w.service.kbs_signing_key),
        Arc::clone(&w.vm_states),
        Arc::clone(&w.allowlist),
        Arc::clone(&w.boot_counter),
        Arc::clone(&w.volume_stamp),
        w.custody.clone(),
        Arc::clone(&w.keepalive_bindings),
        Arc::clone(&w.release_audit),
        w.cdn_fleet.clone(),
    )
    .unwrap();
    kbs_transport::build_admin_router(state)
}

// ── throwaway PKI + a raw TLS client ────────────────────────────────

fn mint_ca() -> (Certificate, KeyPair) {
    let kp = KeyPair::generate().unwrap();
    let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    params
        .distinguished_name
        .push(DnType::CommonName, "hippius-admin-ca");
    let ca = params.self_signed(&kp).unwrap();
    (ca, kp)
}

fn mint_leaf(ca: &Certificate, ca_kp: &KeyPair, san: SanType) -> (String, String) {
    let kp = KeyPair::generate().unwrap();
    let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
    params.subject_alt_names.push(san);
    params.distinguished_name = rcgen::DistinguishedName::new();
    let leaf = params.signed_by(&kp, ca, ca_kp).unwrap();
    (leaf.pem(), kp.serialize_pem())
}

fn uri(u: &str) -> SanType {
    SanType::URI(u.try_into().unwrap())
}

#[derive(Debug)]
enum Exchange {
    Response(String),
    TlsRejected(String),
    DroppedAfterHandshake,
}

struct Listener {
    addr: std::net::SocketAddr,
    roots: RootCertStore,
    _shutdown: tokio::sync::oneshot::Sender<()>,
}

async fn serve(dir: &std::path::Path, router: axum::Router) -> (Listener, Certificate, KeyPair) {
    let (ca, ca_kp) = mint_ca();
    let (srv_cert, srv_key) = mint_leaf(
        &ca,
        &ca_kp,
        SanType::DnsName(SERVER_DNS.try_into().unwrap()),
    );
    let write = |name: &str, body: &str| {
        let p = dir.join(name);
        std::fs::write(&p, body).unwrap();
        p
    };
    let paths = AdminTlsPaths {
        cert: write("server.crt", &srv_cert),
        key: write("server.key", &srv_key),
        client_ca: write("ca.crt", &ca.pem()),
    };
    let acceptor = TlsAcceptor::from(Arc::new(build_server_config(&paths).unwrap()));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (tx, rx) = tokio::sync::oneshot::channel::<()>();
    tokio::spawn(async move {
        hippius_kbs_server::admin_tls::serve_admin_mtls(
            listener,
            acceptor,
            router,
            Arc::new(vec![SpiffeId::parse(VALI_SAN_URI).unwrap()]),
            async {
                let _ = rx.await;
            },
        )
        .await;
    });
    let mut roots = RootCertStore::empty();
    roots.add(ca.der().clone()).unwrap();
    (
        Listener {
            addr,
            roots,
            _shutdown: tx,
        },
        ca,
        ca_kp,
    )
}

async fn get(l: &Listener, client: Option<(String, String)>, path: &str) -> Exchange {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let builder = ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_root_certificates(l.roots.clone());
    let cfg = match client {
        Some((cert, key)) => {
            let certs: Vec<CertificateDer<'static>> =
                rustls_pemfile::certs(&mut std::io::Cursor::new(cert.as_bytes()))
                    .map(|c| c.unwrap())
                    .collect();
            let key: PrivateKeyDer<'static> =
                rustls_pemfile::private_key(&mut std::io::Cursor::new(key.as_bytes()))
                    .unwrap()
                    .unwrap();
            builder.with_client_auth_cert(certs, key).unwrap()
        }
        None => builder.with_no_client_auth(),
    };
    let classify = |e: std::io::Error| match e.kind() {
        std::io::ErrorKind::InvalidData => Exchange::TlsRejected(e.to_string()),
        _ => Exchange::DroppedAfterHandshake,
    };
    let tcp = tokio::net::TcpStream::connect(l.addr).await.unwrap();
    let name = ServerName::try_from(SERVER_DNS).unwrap();
    let mut tls = match TlsConnector::from(Arc::new(cfg)).connect(name, tcp).await {
        Ok(s) => s,
        Err(e) => return classify(e),
    };
    let req = format!("GET {path} HTTP/1.1\r\nHost: admin\r\nConnection: close\r\n\r\n");
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

fn page_of(x: Exchange) -> hippius_types::admin::AdminAuditPageResponse {
    let Exchange::Response(resp) = x else {
        panic!("expected a response, got {x:?}")
    };
    assert!(resp.starts_with("HTTP/1.1 200"), "unexpected: {resp}");
    let body = resp.split_once("\r\n\r\n").unwrap().1;
    // `Connection: close` responses may be chunked; the JSON object is
    // the only `{…}` span in the body.
    let (start, end) = (body.find('{').unwrap(), body.rfind('}').unwrap());
    serde_json::from_str(&body[start..=end]).unwrap()
}

// ── claims ──────────────────────────────────────────────────────────

#[tokio::test]
async fn release_log_route_reads_the_chain_the_release_path_writes() {
    let td = tempfile::TempDir::new().unwrap();
    let (cfg, w) = wired(td.path());
    let router = admin_router(&cfg, &w);
    // A release decision recorded through the SERVICE's sink handle —
    // the one `process_release` uses.
    w.service
        .audit
        .record(true, Some("tk-canary"), Some("vm-canary"), "released");
    let (l, ca, ca_kp) = serve(td.path(), router).await;
    let vali = mint_leaf(&ca, &ca_kp, uri(VALI_SAN_URI));

    let page = page_of(get(&l, Some(vali.clone()), "/v1/admin/audit?log=release").await);
    assert_eq!(page.log, "release");
    assert_eq!(page.entries.len(), 1);
    let on_disk = std::fs::read_to_string(td.path().join("audit/audit.log")).unwrap();
    let line = format!(
        "0:{}:{}",
        page.entries[0].body_cbor_hex, page.entries[0].sha256_hex
    );
    assert_eq!(on_disk.trim_end(), line, "the page is the persisted line");
    let body = hex::decode(&page.entries[0].body_cbor_hex).unwrap();
    let v: ciborium::value::Value = ciborium::de::from_reader(body.as_slice()).unwrap();
    let dbg = format!("{v:?}");
    assert!(
        dbg.contains("vm-canary") && dbg.contains("released"),
        "{dbg}"
    );

    // The admin chain is served too (empty on a fresh KBS).
    let admin = page_of(get(&l, Some(vali), "/v1/admin/audit?log=admin").await);
    assert_eq!(admin.log, "admin");
    assert_eq!(admin.genesis_hash_hex, None);
}

#[tokio::test]
async fn only_an_allowlisted_identity_reaches_the_audit_route() {
    let td = tempfile::TempDir::new().unwrap();
    let (cfg, w) = wired(td.path());
    w.service
        .audit
        .record(true, Some("tk"), Some("vm"), "released");
    let (l, ca, ca_kp) = serve(td.path(), admin_router(&cfg, &w)).await;

    // Same CA, unlisted identity: dropped after the handshake, no body.
    let operator = mint_leaf(&ca, &ca_kp, uri("spiffe://hippius.network/operator"));
    match get(&l, Some(operator), "/v1/admin/audit?log=release").await {
        Exchange::DroppedAfterHandshake => {}
        other => panic!("an unlisted identity must be dropped, got {other:?}"),
    }
    // No client cert: refused by TLS itself.
    match get(&l, None, "/v1/admin/audit?log=release").await {
        Exchange::TlsRejected(msg) => assert!(msg.contains("alert"), "{msg}"),
        other => panic!("an anonymous peer must be rejected by TLS, got {other:?}"),
    }
    // A different CA: refused by TLS.
    let (other_ca, other_kp) = mint_ca();
    let stranger = mint_leaf(&other_ca, &other_kp, uri(VALI_SAN_URI));
    match get(&l, Some(stranger), "/v1/admin/audit?log=release").await {
        Exchange::TlsRejected(_) => {}
        other => panic!("a foreign-CA peer must be rejected by TLS, got {other:?}"),
    }
    // Control: vali gets the chain on the same listener.
    let vali = mint_leaf(&ca, &ca_kp, uri(VALI_SAN_URI));
    assert_eq!(
        page_of(get(&l, Some(vali), "/v1/admin/audit?log=release").await)
            .entries
            .len(),
        1
    );
}
