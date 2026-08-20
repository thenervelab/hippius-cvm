//! PR-H4 — mTLS integration-test helpers.
//!
//! Mints a fresh CA + server cert + two client certs (one valid,
//! one revoked) + a CRL revoking the second client cert, every
//! time the test process starts. No key material is committed to
//! git — each `cargo test` run gets brand-new keys, so a leaked
//! test cert is structurally impossible. The CA is also short-
//! lived (10 minutes total validity) so even if a test process
//! exports the PEM the blast radius is bounded.
//!
//! This file is also a regular test binary by cargo's auto-
//! discovery rules; it carries one smoke `#[test]` so the binary
//! isn't empty. The real integration tests live in
//! `tests/mtls_integration.rs` which `#[path]`-imports this module.

#![allow(dead_code, clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use rcgen::{
    BasicConstraints, Certificate, CertificateParams, CertificateRevocationList,
    CertificateRevocationListParams, ExtendedKeyUsagePurpose, IsCa, KeyIdMethod, KeyPair,
    KeyUsagePurpose, RevocationReason, RevokedCertParams, SanType, SerialNumber,
};
use std::io::Write;
use std::time::Duration;
use tempfile::TempDir;
use time::{Duration as TDuration, OffsetDateTime};

/// Pre-baked mTLS material the integration tests drive through the
/// production loader. Filesystem-backed because the
/// [`hippius_edge_gateway::mtls::cert_store`] surface only takes
/// file paths — matching the production code path bit-for-bit
/// rather than introducing a "load from bytes" hatch tests could
/// use but production can't.
pub struct TestPki {
    /// `TempDir` keeps the test files alive until the helper is
    /// dropped (and cleans them up afterwards). The PEM file paths
    /// below live inside this dir.
    pub dir: TempDir,
    pub ca_path: std::path::PathBuf,
    pub server_cert_path: std::path::PathBuf,
    pub server_key_path: std::path::PathBuf,
    pub crl_path: std::path::PathBuf,
    /// Valid client cert + key, in-memory. The integration test feeds
    /// these into a `tokio_rustls::TlsConnector` to drive the client
    /// side of the handshake.
    pub valid_client_cert_pem: String,
    pub valid_client_key_pem: String,
    /// The SAN URI we encode in the valid client cert. The
    /// integration test asserts that the [`hippius_edge_gateway::
    /// mtls::PeerId`] extracted post-handshake equals this string.
    pub valid_client_peer_id: String,
    pub revoked_client_cert_pem: String,
    pub revoked_client_key_pem: String,
    pub revoked_client_peer_id: String,
    // CA + serial-numbers retained so the
    // `write_crl_revoking_all_clients` helper can mint a fresh CRL
    // post-construction (drives the PR-H4 v2 CRL-refresh propagation
    // integration test). `Certificate` is Clone in rcgen 0.13; the
    // `KeyPair` is not Clone, so we keep the PEM serialisation and
    // re-parse via `KeyPair::from_pem` inside the helper.
    ca_cert: Certificate,
    ca_key_pem: String,
    valid_client_serial: SerialNumber,
    revoked_client_serial: SerialNumber,
}

impl TestPki {
    /// Build the full PKI. ~150ms per call on M2; the integration
    /// test caches it across cases via a `OnceLock` so we pay the
    /// cost exactly once per binary.
    pub fn mint() -> Self {
        let dir = tempfile::tempdir().expect("tempdir");
        // (1) CA. Short lifetime — the integration test only runs for
        //     a few seconds, but 10 minutes gives us slack for slow
        //     CI runners without making it long-lived enough to be a
        //     test artifact someone might pick up.
        let (ca_cert, ca_kp) = mint_ca();

        // (2) Server cert. SAN = `edge.test`; matches the SNI the
        //     test client sends.
        let (server_cert, server_kp) = mint_leaf(
            &ca_cert,
            &ca_kp,
            vec![SanType::DnsName("edge.test".try_into().unwrap())],
            "edge.test",
            ExtendedKeyUsagePurpose::ServerAuth,
        );

        // (3) Valid client cert. SAN URI carries the PeerId we expect
        //     to see post-handshake. Production §17.7 mint script
        //     uses the `hippius-miner:<uuid>` scheme.
        let valid_uri = "hippius-miner:11111111-1111-1111-1111-111111111111";
        let (valid_client_cert, valid_client_kp) = mint_leaf(
            &ca_cert,
            &ca_kp,
            vec![SanType::URI(valid_uri.try_into().unwrap())],
            "valid-client",
            ExtendedKeyUsagePurpose::ClientAuth,
        );

        // (4) Revoked client cert. Same shape, different serial — we
        //     pull the serial out below and feed it to the CRL.
        let revoked_uri = "hippius-miner:22222222-2222-2222-2222-222222222222";
        let (revoked_client_cert, revoked_client_kp) = mint_leaf(
            &ca_cert,
            &ca_kp,
            vec![SanType::URI(revoked_uri.try_into().unwrap())],
            "revoked-client",
            ExtendedKeyUsagePurpose::ClientAuth,
        );

        // (5) CRL with the revoked client serial entered. rcgen needs
        //     the exact serial we minted above; it's exposed via
        //     `Certificate::params().serial_number`.
        let revoked_serial = revoked_client_cert
            .params()
            .serial_number
            .clone()
            .expect("revoked cert must have a serial");
        let now = OffsetDateTime::now_utc();
        let crl_params = CertificateRevocationListParams {
            this_update: now,
            next_update: now + TDuration::days(7),
            crl_number: SerialNumber::from(1u64),
            issuing_distribution_point: None,
            revoked_certs: vec![RevokedCertParams {
                serial_number: revoked_serial.clone(),
                revocation_time: now,
                reason_code: Some(RevocationReason::KeyCompromise),
                invalidity_date: None,
            }],
            key_identifier_method: KeyIdMethod::Sha256,
        };
        let crl: CertificateRevocationList =
            crl_params.signed_by(&ca_cert, &ca_kp).expect("crl-sign");

        // (6) Materialise everything to disk so the production loader
        //     can read it via env-var paths.
        let ca_path = write_pem(&dir, "ca.pem", &ca_cert.pem());
        let server_cert_path = write_pem(&dir, "server.pem", &server_cert.pem());
        let server_key_path = write_pem(&dir, "server.key", &server_kp.serialize_pem());
        let crl_path = write_pem(&dir, "crl.pem", &crl.pem().expect("crl-pem"));
        let valid_client_serial = valid_client_cert
            .params()
            .serial_number
            .clone()
            .expect("valid cert must have a serial");

        Self {
            dir,
            ca_path,
            server_cert_path,
            server_key_path,
            crl_path,
            valid_client_cert_pem: valid_client_cert.pem(),
            valid_client_key_pem: valid_client_kp.serialize_pem(),
            valid_client_peer_id: valid_uri.to_string(),
            revoked_client_cert_pem: revoked_client_cert.pem(),
            revoked_client_key_pem: revoked_client_kp.serialize_pem(),
            revoked_client_peer_id: revoked_uri.to_string(),
            ca_cert,
            ca_key_pem: ca_kp.serialize_pem(),
            valid_client_serial,
            revoked_client_serial: revoked_serial,
        }
    }
}

/// Mint a fresh CRL that revokes BOTH client certs (valid + revoked)
/// and overwrite the on-disk CRL at [`TestPki::crl_path`]. Used by
/// `tests/mtls_integration.rs::crl_refresh_propagates_new_revocations_to_live_config`
/// to simulate an operator-pushed runtime revocation. CRL number is
/// bumped to 2 so `WebPkiClientVerifier` accepts the rotation.
pub fn write_crl_revoking_all_clients(pki: &TestPki) {
    // Re-parse the CA keypair from its PEM serialisation —
    // `KeyPair` isn't Clone in rcgen 0.13 so this is the cheapest
    // way to get a fresh handle that signs against the same DN as
    // the original `ca_cert`.
    let ca_kp = KeyPair::from_pem(&pki.ca_key_pem).expect("CA keypair re-parse must succeed");
    let now = OffsetDateTime::now_utc();
    let crl_params = CertificateRevocationListParams {
        this_update: now,
        next_update: now + TDuration::days(7),
        // Bump the CRL number — `WebPkiClientVerifier` requires a
        // monotonic CRL series across rotations.
        crl_number: SerialNumber::from(2u64),
        issuing_distribution_point: None,
        revoked_certs: vec![
            RevokedCertParams {
                serial_number: pki.revoked_client_serial.clone(),
                revocation_time: now,
                reason_code: Some(RevocationReason::KeyCompromise),
                invalidity_date: None,
            },
            RevokedCertParams {
                serial_number: pki.valid_client_serial.clone(),
                revocation_time: now,
                reason_code: Some(RevocationReason::KeyCompromise),
                invalidity_date: None,
            },
        ],
        key_identifier_method: KeyIdMethod::Sha256,
    };
    let crl: CertificateRevocationList = crl_params
        .signed_by(&pki.ca_cert, &ca_kp)
        .expect("crl-resign");
    let pem = crl.pem().expect("crl-pem");
    std::fs::write(&pki.crl_path, pem).expect("overwrite crl path");
}

fn mint_ca() -> (Certificate, KeyPair) {
    let kp = KeyPair::generate().expect("ca-keypair");
    let mut params = CertificateParams::new(Vec::<String>::new()).expect("ca-params");
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![KeyUsagePurpose::CrlSign, KeyUsagePurpose::KeyCertSign];
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "hippius-edge-test-ca");
    // Short lifetime — production CA per §B Q11 is 90 days; tests are
    // only minutes long. A bug that lets a test cert escape the
    // tempdir cleans itself up in 10 minutes anyway.
    let now = OffsetDateTime::now_utc();
    params.not_before = now - TDuration::minutes(1);
    params.not_after = now + TDuration::minutes(10);
    params.serial_number = Some(SerialNumber::from(1u64));
    let cert = params.self_signed(&kp).expect("ca-self-sign");
    (cert, kp)
}

fn mint_leaf(
    ca_cert: &Certificate,
    ca_kp: &KeyPair,
    sans: Vec<SanType>,
    common_name: &str,
    eku: ExtendedKeyUsagePurpose,
) -> (Certificate, KeyPair) {
    static NEXT_SERIAL: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(100);

    let kp = KeyPair::generate().expect("leaf-keypair");
    let mut params = CertificateParams::new(Vec::<String>::new()).expect("leaf-params");
    params.subject_alt_names = sans;
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, common_name);
    params.extended_key_usages = vec![eku];
    params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    let now = OffsetDateTime::now_utc();
    params.not_before = now - TDuration::minutes(1);
    params.not_after = now + TDuration::minutes(10);
    let serial = NEXT_SERIAL.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    params.serial_number = Some(SerialNumber::from(serial));
    let cert = params.signed_by(&kp, ca_cert, ca_kp).expect("leaf-sign");
    (cert, kp)
}

fn write_pem(dir: &TempDir, name: &str, content: &str) -> std::path::PathBuf {
    let p = dir.path().join(name);
    let mut f = std::fs::File::create(&p).unwrap();
    f.write_all(content.as_bytes()).unwrap();
    p
}

/// Small wait helper for the CRL poller's first tick. Used by the
/// "fail-closed on missing CRL" integration test where we mutate
/// the on-disk file mid-test.
pub async fn settle() {
    tokio::time::sleep(Duration::from_millis(50)).await;
}

#[cfg(test)]
mod smoke {
    use super::*;
    use hippius_edge_gateway::mtls::cert_store;

    /// Sanity check: the minted PKI parses via the production
    /// loader. If rcgen or rustls-pemfile change their PEM output
    /// shape this trips before any real integration test does.
    #[test]
    fn minted_pki_loads_via_production_paths() {
        let pki = TestPki::mint();
        let roots = cert_store::load_ca_roots(&pki.ca_path).unwrap();
        assert!(!roots.is_empty());
        let chain = cert_store::load_cert_chain(&pki.server_cert_path).unwrap();
        assert_eq!(chain.len(), 1);
        let _key = cert_store::load_key_pem(&pki.server_key_path).unwrap();
    }
}
