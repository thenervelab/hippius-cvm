//! PR-2 — permissionless on-chain miner-auth integration tests.
//!
//! Drives the production [`MtlsAcceptor`] in **on-chain mode** over
//! loopback TCP. The miner presents a **self-signed** Ed25519 identity
//! cert (exactly what `miner-agent`'s
//! `MinerIdentity::self_signed_client_pem` mints) — there is no
//! operator CA. Admission is decided purely by the on-chain
//! registered+`Active` set held in a [`RegistryStore`], here driven by
//! an injected fetch stub so the test needs no live Substrate node.
//!
//! These tests pin the property that unblocked the whole redesign:
//! each miner is admitted by **its own** registered identity, and a
//! cert can no longer stand in for a different node (the observed
//! failure where two distinct miners shared one cert).
//!
//! 1. A registered node's self-signed cert is admitted; the PeerId is
//!    its `hippius-node:<node_id>` SAN.
//! 2. An UN-registered node's (otherwise valid) self-signed cert is
//!    rejected post-handshake with `not-registered`.
//! 3. A stale (unhealthy) registry fails closed before the handshake.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

#[path = "mtls_test_helpers.rs"]
mod helpers;

use helpers::TestPki;
use hippius_edge_gateway::mtls::registry::RegistryStore;
use hippius_edge_gateway::mtls::{CertPaths, MtlsAcceptor, MtlsRuntime, PeerId};
use hippius_edge_gateway::EdgeError;
use hippius_onchain_registry::{MinerRecord, MinerStatus, RegistrySnapshot};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use rustls::{ClientConfig, RootCertStore};
use std::sync::Arc;
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsConnector;

/// Mint a self-signed Ed25519 identity cert + key (concatenated PEM is
/// not needed here — the test client wants them separately). Returns
/// `(cert_pem, key_pem, node_id)` where node_id is the cert's own
/// Ed25519 public key, stamped in the SAN as `hippius-node:<hex>` —
/// byte-for-byte the agent's `self_signed_client_pem` shape.
fn mint_identity(seed_tag: u8) -> (String, String, [u8; 32]) {
    use rcgen::{CertificateParams, ExtendedKeyUsagePurpose, Ia5String, KeyPair, SanType};
    let _ = seed_tag; // each call generates a fresh random key anyway
    let kp = KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
    let spki = kp.public_key_der();
    let mut node_id = [0u8; 32];
    node_id.copy_from_slice(&spki[spki.len() - 32..]);

    let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
    let uri = Ia5String::try_from(format!("hippius-node:{}", hex::encode(node_id))).unwrap();
    params.subject_alt_names.push(SanType::URI(uri));
    params
        .extended_key_usages
        .push(ExtendedKeyUsagePurpose::ClientAuth);
    let cert = params.self_signed(&kp).unwrap();
    (cert.pem(), kp.serialize_pem(), node_id)
}

fn server_paths(pki: &TestPki) -> CertPaths {
    CertPaths {
        ca: pki.ca_path.clone(),
        cert: pki.server_cert_path.clone(),
        key: pki.server_key_path.clone(),
        crl: None,
    }
}

/// A registry pre-loaded (and marked healthy) with `active` node_ids.
fn registry_with(active: &[[u8; 32]]) -> Arc<RegistryStore> {
    let active = active.to_vec();
    let store = RegistryStore::with_fetcher(
        "http://vali/v1/edge/registry",
        Arc::new(move |_| {
            Ok(RegistrySnapshot {
                current_epoch: 1,
                pallet_live: true,
                miners: active
                    .iter()
                    .map(|id| MinerRecord {
                        node_id: *id,
                        status: MinerStatus::Active,
                        last_transition_epoch: 0,
                        data_epoch: 1,
                        quality: 1,
                        price: None,
                    })
                    .collect(),
            })
        }),
    );
    store.refresh().expect("stub refresh");
    Arc::new(store)
}

/// Build a TLS-1.3 client that trusts the Edge's CA (to verify the
/// server cert) and presents `cert_pem` + `key_pem` (the self-signed
/// miner identity) as its client cert.
fn make_client(pki: &TestPki, cert_pem: &str, key_pem: &str) -> TlsConnector {
    let mut roots = RootCertStore::empty();
    for entry in rustls_pemfile::certs(&mut std::io::Cursor::new(
        std::fs::read(&pki.ca_path).unwrap(),
    )) {
        roots.add(entry.unwrap()).unwrap();
    }
    let cert_chain: Vec<CertificateDer<'static>> =
        rustls_pemfile::certs(&mut std::io::Cursor::new(cert_pem.as_bytes()))
            .filter_map(Result::ok)
            .collect();
    let key: PrivateKeyDer<'static> =
        rustls_pemfile::private_key(&mut std::io::Cursor::new(key_pem.as_bytes()))
            .unwrap()
            .unwrap();
    let client_config = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_client_auth_cert(cert_chain, key)
        .unwrap();
    TlsConnector::from(Arc::new(client_config))
}

async fn bind_one_shot() -> TcpListener {
    TcpListener::bind("127.0.0.1:0").await.unwrap()
}

#[tokio::test]
async fn registered_self_signed_identity_is_admitted() {
    let pki = TestPki::mint();
    let (cert_pem, key_pem, node_id) = mint_identity(1);
    let registry = registry_with(&[node_id]);
    let runtime = MtlsRuntime::load_onchain(server_paths(&pki), registry).unwrap();
    assert!(runtime.is_healthy());
    let acceptor = Arc::new(MtlsAcceptor::new(Arc::clone(&runtime)));

    let listener = bind_one_shot().await;
    let addr = listener.local_addr().unwrap();
    let acceptor_clone = Arc::clone(&acceptor);
    let server = tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.unwrap();
        acceptor_clone.accept(tcp).await.map(|(pid, _)| pid)
    });

    let connector = make_client(&pki, &cert_pem, &key_pem);
    let tcp = TcpStream::connect(addr).await.unwrap();
    let sni = ServerName::try_from("edge.test").unwrap();
    connector.connect(sni, tcp).await.expect("handshake ok");

    let peer_id = server.await.unwrap().expect("accept must succeed");
    assert_eq!(
        peer_id,
        PeerId::new(&format!("hippius-node:{}", hex::encode(node_id)))
    );
}

#[tokio::test]
async fn unregistered_self_signed_identity_is_rejected() {
    let pki = TestPki::mint();
    // The registry knows about SOME other node, not this one.
    let (cert_pem, key_pem, node_id) = mint_identity(2);
    let (_other_cert, _other_key, other_id) = mint_identity(3);
    assert_ne!(node_id, other_id);
    let registry = registry_with(&[other_id]);
    let runtime = MtlsRuntime::load_onchain(server_paths(&pki), registry).unwrap();
    let acceptor = Arc::new(MtlsAcceptor::new(Arc::clone(&runtime)));

    let listener = bind_one_shot().await;
    let addr = listener.local_addr().unwrap();
    let acceptor_clone = Arc::clone(&acceptor);
    let server = tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.unwrap();
        acceptor_clone.accept(tcp).await
    });

    // The TLS handshake itself SUCCEEDS (the verifier accepts any
    // self-signed cert); the rejection is the post-handshake on-chain
    // gate, so the client connect resolves Ok then the server drops it.
    let connector = make_client(&pki, &cert_pem, &key_pem);
    let tcp = TcpStream::connect(addr).await.unwrap();
    let sni = ServerName::try_from("edge.test").unwrap();
    let _ = connector.connect(sni, tcp).await;

    match server.await.unwrap() {
        Err(EdgeError::MtlsFailed("not-registered")) => {}
        other => panic!("expected MtlsFailed(not-registered), got {other:?}"),
    }
}

#[tokio::test]
async fn stale_registry_fails_closed_before_handshake() {
    let pki = TestPki::mint();
    let (cert_pem, key_pem, node_id) = mint_identity(4);
    // A registry whose fetch always errors → never healthy.
    let store = RegistryStore::with_fetcher(
        "http://vali/v1/edge/registry",
        Arc::new(|_| {
            Err(hippius_onchain_registry::RegistryError::new(
                "rpc-request",
                "down".to_string(),
            ))
        }),
    );
    let _ = store.refresh(); // fails → unhealthy
    let registry = Arc::new(store);
    assert!(!registry.contains(&node_id));
    let runtime = MtlsRuntime::load_onchain(server_paths(&pki), registry).unwrap();
    assert!(!runtime.is_healthy());
    let acceptor = Arc::new(MtlsAcceptor::new(Arc::clone(&runtime)));

    let listener = bind_one_shot().await;
    let addr = listener.local_addr().unwrap();
    let acceptor_clone = Arc::clone(&acceptor);
    let server = tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.unwrap();
        acceptor_clone.accept(tcp).await
    });

    let connector = make_client(&pki, &cert_pem, &key_pem);
    let tcp = TcpStream::connect(addr).await.unwrap();
    let sni = ServerName::try_from("edge.test").unwrap();
    let _ = connector.connect(sni, tcp).await;

    match server.await.unwrap() {
        Err(EdgeError::MtlsFailed("registry-unhealthy")) => {}
        other => panic!("expected MtlsFailed(registry-unhealthy), got {other:?}"),
    }
}
