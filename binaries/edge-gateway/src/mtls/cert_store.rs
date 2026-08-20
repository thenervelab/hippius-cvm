//! mTLS material loading + `ServerConfig` build (PR-H4, §10).
//!
//! ## Why all of this lives here, not in `main.rs`
//!
//! The PR-H4 reviewer brief explicitly calls out two anti-patterns:
//!
//! 1. **No fallback to insecure / weak cipher suites.** Edge MUST
//!    refuse any handshake that doesn't reach TLS 1.3. Both
//!    [`build_server_config`] and [`build_client_config`] call
//!    `builder_with_protocol_versions(&[&rustls::version::TLS13])`,
//!    restricting the negotiable versions to TLS 1.3 **at the config
//!    level**. This does NOT rely on the `rustls` `"tls12"` feature
//!    being off: cargo feature unification can turn that feature on
//!    transitively (a sibling workspace crate's HTTP stack pulls it
//!    — e.g. `reqwest` in `agent-initramfs`), so the version
//!    restriction is pinned explicitly in code, where unification
//!    cannot reach it.
//! 2. **No path that exports the private key.** The owned-key half of
//!    the cert is loaded by [`load_key_pem`] into a
//!    `PrivateKeyDer<'static>`, fed straight into rustls's
//!    `ServerConfig::with_single_cert`, and **dropped at end of
//!    scope** — there is no getter, no `Debug` impl that surfaces
//!    bytes, no helper to "dump the loaded key for diagnostics".
//!    The only places the key bytes live in process memory are
//!    rustls-internal state + the brief stack frame inside
//!    [`build_server_config`].
//!
//! ## Env vars
//!
//! Three required, one optional. The PR-K7 Ansible playbook (still
//! unwritten as of PR-H4) renders these out to fixed paths under
//! `/etc/hippius-edge/mtls/` and points the systemd unit at them.
//! The values below are the production defaults; the loader does NOT
//! synthesise the defaults if the env vars are unset — that's a
//! deliberate "fail to boot rather than fall back to a known-public
//! cert" posture.
//!
//! | env var | role | required |
//! |---|---|---|
//! | `EDGE_MTLS_CA_PATH`   | CA bundle for client-cert validation | yes |
//! | `EDGE_MTLS_CERT_PATH` | Edge server cert chain (leaf + intermediates) | yes |
//! | `EDGE_MTLS_KEY_PATH`  | Edge server private key (PKCS#8 / SEC1 PEM) | yes |
//! | `EDGE_MTLS_CRL_PATH`  | CRL bundle for client-cert revocation | no  |
//!
//! Absent `EDGE_MTLS_CRL_PATH` is a deliberate choice the operator
//! must make in the runbook — the §B Q11 cadence is "rotate every 90
//! days", which is the same window during which a missing CRL is
//! tolerable. Operators that need shorter revocation latency MUST
//! point this env var at a CRL file (see [`crate::mtls::revocation`]).

use rustls::client::WebPkiServerVerifier;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::WebPkiClientVerifier;
use rustls::{ClientConfig, RootCertStore, ServerConfig};
use std::path::{Path, PathBuf};
use std::sync::Arc;

/// Env-var names. Public so the binary + integration tests can name
/// them by the same constants — typos would surface as compile errors
/// in cargo test, not silent runtime ignores.
pub const ENV_CA_PATH: &str = "EDGE_MTLS_CA_PATH";
pub const ENV_CERT_PATH: &str = "EDGE_MTLS_CERT_PATH";
pub const ENV_KEY_PATH: &str = "EDGE_MTLS_KEY_PATH";
pub const ENV_CRL_PATH: &str = "EDGE_MTLS_CRL_PATH";

/// Stable static-classifier errors. Same `&'static str`-only
/// `Display` discipline as `EdgeError` / `ConfigError`. The audit
/// log keys on these — variants must never `{0}` a runtime string.
#[derive(Debug, thiserror::Error)]
pub enum CertStoreError {
    /// Required env var was unset (or empty). PR-H4 boot policy is
    /// "fail fast" — no falling back to baked test certs.
    #[error("mtls-env-missing")]
    EnvMissing(&'static str),
    /// `std::fs::read` failed for one of the three PEM files. Usually
    /// permissions or a typo in the env var path.
    #[error("mtls-read")]
    Read(&'static str),
    /// PEM block did not decode (CA / cert chain / key alike).
    #[error("mtls-parse")]
    Parse(&'static str),
    /// PEM file existed and parsed but contained zero blocks of the
    /// required kind. Almost always a misconfigured path (e.g.
    /// pointed at the CRL file when CA was meant).
    #[error("mtls-empty")]
    Empty(&'static str),
    /// rustls reported the config build failed — typically an
    /// unsupported key type or a verifier-builder error.
    #[error("mtls-build")]
    Build,
}

impl CertStoreError {
    /// Static classifier for the audit sink. Mirrors the pattern in
    /// `EdgeError::class` — pattern-match the variant rather than
    /// `Display`-formatting (which is also static, but routing via
    /// the named function keeps the contract explicit).
    pub fn class(&self) -> &'static str {
        match self {
            CertStoreError::EnvMissing(_) => "mtls-env-missing",
            CertStoreError::Read(_) => "mtls-read",
            CertStoreError::Parse(_) => "mtls-parse",
            CertStoreError::Empty(_) => "mtls-empty",
            CertStoreError::Build => "mtls-build",
        }
    }
}

/// File paths Edge will load mTLS material from. Public so tests can
/// build one directly without setting env vars (process-global env
/// would race across parallel tests).
#[derive(Debug, Clone)]
pub struct CertPaths {
    pub ca: PathBuf,
    pub cert: PathBuf,
    pub key: PathBuf,
    /// `None` ⇒ no CRL revocation. The accept gate still works (no
    /// `crl_healthy` check), but a compromised peer's only TTL is
    /// the cert lifetime. Operator runbook §B Q11.
    pub crl: Option<PathBuf>,
}

impl CertPaths {
    /// Collect every required env var. Missing / empty values
    /// surface as `EnvMissing(name)` — the static classifier — so
    /// the runbook can grep `mtls-env-missing` to find boot
    /// failures.
    pub fn from_env() -> Result<Self, CertStoreError> {
        let ca = nonempty_env(ENV_CA_PATH)?;
        let cert = nonempty_env(ENV_CERT_PATH)?;
        let key = nonempty_env(ENV_KEY_PATH)?;
        // CRL is optional — only set the field if the env var is
        // non-empty. The downstream code distinguishes "no CRL
        // configured" from "CRL configured but currently
        // unhealthy" via the `Option`.
        let crl = match std::env::var(ENV_CRL_PATH) {
            Ok(s) if !s.is_empty() => Some(PathBuf::from(s)),
            _ => None,
        };
        Ok(Self {
            ca: PathBuf::from(ca),
            cert: PathBuf::from(cert),
            key: PathBuf::from(key),
            crl,
        })
    }
}

fn nonempty_env(name: &'static str) -> Result<String, CertStoreError> {
    match std::env::var(name) {
        Ok(s) if !s.is_empty() => Ok(s),
        _ => Err(CertStoreError::EnvMissing(name)),
    }
}

/// Load a PEM file containing one or more CA certs and pack them
/// into a `RootCertStore`. Used to validate the **client** cert
/// chain at handshake — the standard CA-pinned mTLS setup.
pub fn load_ca_roots(path: &Path) -> Result<RootCertStore, CertStoreError> {
    let raw = std::fs::read(path).map_err(|_| CertStoreError::Read("ca"))?;
    let certs = parse_certs_pem(&raw, "ca")?;
    let mut roots = RootCertStore::empty();
    for cert in certs {
        roots.add(cert).map_err(|_| CertStoreError::Parse("ca"))?;
    }
    if roots.is_empty() {
        return Err(CertStoreError::Empty("ca"));
    }
    Ok(roots)
}

/// Load the Edge server cert chain (leaf + any intermediates).
pub fn load_cert_chain(path: &Path) -> Result<Vec<CertificateDer<'static>>, CertStoreError> {
    let raw = std::fs::read(path).map_err(|_| CertStoreError::Read("cert"))?;
    let certs = parse_certs_pem(&raw, "cert")?;
    if certs.is_empty() {
        return Err(CertStoreError::Empty("cert"));
    }
    Ok(certs)
}

/// Load the Edge server private key. PKCS#8 first, then SEC1 EC,
/// then RSA PKCS#1 — the order rustls examples use. The returned
/// `PrivateKeyDer<'static>` is **moved** into rustls; this function
/// has no path to clone, log, or otherwise surface the bytes.
pub fn load_key_pem(path: &Path) -> Result<PrivateKeyDer<'static>, CertStoreError> {
    let raw = std::fs::read(path).map_err(|_| CertStoreError::Read("key"))?;
    let mut cursor = std::io::Cursor::new(&raw[..]);
    match rustls_pemfile::private_key(&mut cursor) {
        Ok(Some(key)) => Ok(key),
        Ok(None) => Err(CertStoreError::Empty("key")),
        Err(_) => Err(CertStoreError::Parse("key")),
    }
}

/// Parse a PEM blob into a vector of `CertificateDer`. `label` is the
/// caller's source-tag (`"ca"` / `"cert"`) used to attribute parse
/// errors back to the right env var in the audit log.
fn parse_certs_pem(
    pem: &[u8],
    label: &'static str,
) -> Result<Vec<CertificateDer<'static>>, CertStoreError> {
    let mut cursor = std::io::Cursor::new(pem);
    let mut out = Vec::new();
    for entry in rustls_pemfile::certs(&mut cursor) {
        let cert = entry.map_err(|_| CertStoreError::Parse(label))?;
        out.push(cert);
    }
    Ok(out)
}

/// Build the rustls `ServerConfig` from already-loaded material.
/// `crl_snapshot` may be empty — that's the "CRL not configured"
/// shape (or the unhealthy state where we keep the snapshot stale
/// but mark the [`crate::mtls::CrlStore`] unhealthy at the accept
/// gate).
///
/// **TLS 1.3 only**: built via `builder_with_protocol_versions(&[&TLS13])`,
/// which restricts the negotiable versions to TLS 1.3 regardless of
/// whether the `rustls` `"tls12"` feature is compiled in (cargo
/// feature unification can turn it on transitively — see the module
/// docs). A TLS 1.2 client gets a handshake failure.
///
/// Returns the raw `ServerConfig` (not `Arc`-wrapped) so the caller
/// can store it in an [`arc_swap::ArcSwap`] for live rotation. The
/// [`crate::mtls::MtlsRuntime`] owns that swap and rebuilds the
/// config on every successful CRL refresh — Blocker #1 from the
/// codex PR-H4 review.
pub fn build_server_config(
    ca_roots: RootCertStore,
    cert_chain: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
    crl_snapshot: Vec<rustls::pki_types::CertificateRevocationListDer<'static>>,
) -> Result<ServerConfig, CertStoreError> {
    let mut verifier = WebPkiClientVerifier::builder(Arc::new(ca_roots));
    for crl in crl_snapshot {
        verifier = verifier.with_crls(vec![crl]);
    }
    // Build the verifier. We do NOT call `.allow_unauthenticated()` —
    // every connecting peer MUST present a CA-issued cert. A future
    // PR that flips this would have to add the call explicitly,
    // visible in diff.
    let verifier = verifier.build().map_err(|_| CertStoreError::Build)?;

    // Pin TLS 1.3 explicitly at the config level — see the module
    // docs: the `"tls12"` feature can be unified on by a sibling
    // crate's deps, so the restriction must NOT rely on the feature.
    let mut config = ServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
        .with_client_cert_verifier(verifier)
        .with_single_cert(cert_chain, key)
        .map_err(|_| CertStoreError::Build)?;
    // PR-H8: the miner↔Edge wire is **HTTP/2 only** over this mTLS
    // stream (LOCKED wire decision). Advertise `h2` and nothing else
    // — a miner client that offers only `http/1.1` gets a
    // `no_application_protocol` TLS alert rather than a silent
    // HTTP/1.1 downgrade; `miner_listener` then serves the connection
    // with the HTTP/2-only hyper builder.
    //
    // This `ServerConfig` is shared with the HA peer-link listener
    // (`HaNode` reuses the same `MtlsRuntime`). That is safe: the HA
    // dialer (`build_client_config` below) sets NO `alpn_protocols`,
    // so it offers no ALPN extension — an `h2`-only server ALPN list
    // is simply unused for an HA handshake (which then runs HA's own
    // non-HTTP frame protocol). Were the HA dialer to start offering
    // ALPN, this list would need to be scoped to the miner path.
    config.alpn_protocols = vec![b"h2".to_vec()];
    Ok(config)
}

/// Build the `ServerConfig` for the **permissionless on-chain**
/// miner-auth mode (`docs/design/permissionless-miner-auth.md`):
/// identical to [`build_server_config`] except the client-cert
/// verifier accepts **self-signed** client certs
/// ([`super::onchain_verifier::SelfSignedClientVerifier`]) instead of
/// chaining to the operator CA. There is no CA root and no CRL — a
/// connecting miner is admitted by the post-handshake on-chain
/// registered+`Active` gate in [`super::MtlsAcceptor::accept`], not by
/// a cert signature. The Edge still presents its OWN server cert
/// (`cert_chain` / `key`), which the miner verifies against the CA it
/// was shipped — server auth is unchanged; only client auth flips.
pub fn build_server_config_onchain(
    cert_chain: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
) -> Result<ServerConfig, CertStoreError> {
    // The default `ring` provider — the Edge pins `ring` (Cargo.toml).
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let verifier = Arc::new(super::onchain_verifier::SelfSignedClientVerifier::new(
        provider,
    ));

    // Same TLS-1.3 pin + `h2`-only ALPN as the CA path.
    let mut config = ServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
        .with_client_cert_verifier(verifier)
        .with_single_cert(cert_chain, key)
        .map_err(|_| CertStoreError::Build)?;
    config.alpn_protocols = vec![b"h2".to_vec()];
    Ok(config)
}

/// Build a **server-cert-only** rustls `ServerConfig` (NO client-cert
/// verifier) presenting the Edge's own cert + key.
///
/// Used by the §24/§25 guest stopped-ack relay TLS listener: the hop
/// arrives from a miner host's vsock-proxy reqwest client that presents
/// NO client cert (so the mTLS `build_server_config` would reject it at
/// the handshake), but DOES verify the Edge's server cert against the
/// hippius-compute CA it was shipped (the Edge cert carries
/// the Edge LoadBalancer's mesh address as an `IP:` SAN, so the miner
/// can dial the LB IP directly
/// — no public DNS / public cert needed). The access control on this
/// listener is the CiliumNetworkPolicy (NetBird CGNAT range) + the fact
/// that it serves ONE opaque relay route into vali's fail-closed
/// `StoppedAckIngest` store (a forged ack is inert; vali's verifier is
/// the trust gate). ALPN advertises `http/1.1` + `h2` — reqwest
/// negotiates HTTP/1.1; the lifecycle router is served over either.
pub fn build_server_config_no_client_auth(
    cert_chain: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
) -> Result<ServerConfig, CertStoreError> {
    let mut config = ServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
        .with_no_client_auth()
        .with_single_cert(cert_chain, key)
        .map_err(|_| CertStoreError::Build)?;
    // HTTP/2 only (the Edge's `hyper`/`hyper-util` are built with the
    // `http2` feature only, no `http1`). The stopped-ack hop is a
    // `reqwest` client; reqwest upgrades to HTTP/2 when the server
    // advertises `h2` via ALPN (the same mechanism the miner relay
    // uses). Advertising `h2` alone makes an h1-only client fail at the
    // ALPN layer rather than silently downgrade to an unsupported wire.
    config.alpn_protocols = vec![b"h2".to_vec()];
    Ok(config)
}

/// Build the rustls `ClientConfig` for the **HA peer link** (PR-H5).
///
/// PR-H5 dials a sister Edge instance over mTLS to exchange health
/// beats. This is the client half of that channel — the peer link's
/// listener side reuses the existing server [`build_server_config`].
/// The peer link reuses the **same** CA + Edge cert/key as the
/// miner-facing side (the §H Ansible playbook mints one Edge cert;
/// the spec calls for no separate peer-link PKI):
///
/// - `ca_roots` — the shared private CA. The dialer validates the
///   peer's *server* cert against it. Any cert chaining here is, by
///   construction, a trusted Edge-fleet member — same trust posture
///   as the server side's [`WebPkiClientVerifier`].
/// - `cert_chain` + `key` — our own Edge cert, presented to the peer
///   as the *client* cert so the peer's `WebPkiClientVerifier` (and
///   its CRL gate) authenticates us in return. Fully mutual: there
///   is no path here that builds a server-auth-only or anonymous
///   client.
///
/// **TLS 1.3 only**, same as the server side — built via
/// `builder_with_protocol_versions(&[&TLS13])` (see the module docs
/// on why the version pin is at the config level, not the feature
/// flag). The dialer connects with a fixed SNI
/// ([`crate::ha::PEER_LINK_SNI`]); the peer's server cert must carry
/// that name as a SAN, so the stock webpki server verifier does full
/// hostname verification — no custom / verification-skipping verifier.
///
/// `crl_snapshot` is folded into the [`WebPkiServerVerifier`] exactly
/// as [`build_server_config`] folds it into the client verifier — so
/// the dialer rejects a **revoked** peer server cert just as the
/// listener side rejects a revoked client cert. The peer link is
/// CRL-symmetric: revocation is enforced on both directions.
pub fn build_client_config(
    ca_roots: RootCertStore,
    cert_chain: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
    crl_snapshot: Vec<rustls::pki_types::CertificateRevocationListDer<'static>>,
) -> Result<ClientConfig, CertStoreError> {
    let mut verifier = WebPkiServerVerifier::builder(Arc::new(ca_roots));
    for crl in crl_snapshot {
        verifier = verifier.with_crls(vec![crl]);
    }
    let verifier = verifier.build().map_err(|_| CertStoreError::Build)?;
    // Pin TLS 1.3 explicitly — see `build_server_config` + module docs.
    ClientConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
        .with_webpki_verifier(verifier)
        .with_client_auth_cert(cert_chain, key)
        .map_err(|_| CertStoreError::Build)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    /// Mint a throwaway CA via rcgen (dev-dep). Used by the loader
    /// tests so we don't ship key material in the repo. The
    /// integration test exercises the full handshake.
    fn mint_ca_pem() -> (String, String, String, String) {
        use rcgen::{CertificateParams, IsCa, KeyPair, KeyUsagePurpose};
        let ca_kp = KeyPair::generate().unwrap();
        let mut ca_params = CertificateParams::new(Vec::<String>::new()).unwrap();
        ca_params.is_ca = IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        ca_params.key_usages = vec![KeyUsagePurpose::CrlSign, KeyUsagePurpose::KeyCertSign];
        ca_params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "test-ca");
        let ca_cert = ca_params.self_signed(&ca_kp).unwrap();
        let ca_pem = ca_cert.pem();

        // Server cert signed by CA.
        let srv_kp = KeyPair::generate().unwrap();
        let mut srv_params = CertificateParams::new(vec!["edge.test".to_string()]).unwrap();
        srv_params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "edge.test");
        let srv_cert = srv_params.signed_by(&srv_kp, &ca_cert, &ca_kp).unwrap();
        let srv_cert_pem = srv_cert.pem();
        let srv_key_pem = srv_kp.serialize_pem();

        // Garbage file content used by the negative-paths tests.
        let garbage_pem =
            "-----BEGIN CERTIFICATE-----\nNOT-A-CERT\n-----END CERTIFICATE-----\n".to_string();

        (ca_pem, srv_cert_pem, srv_key_pem, garbage_pem)
    }

    fn write_tmp(content: &str) -> NamedTempFile {
        let mut tf = NamedTempFile::new().unwrap();
        tf.write_all(content.as_bytes()).unwrap();
        tf
    }

    #[test]
    fn load_ca_roots_happy_path() {
        let (ca, _, _, _) = mint_ca_pem();
        let tf = write_tmp(&ca);
        let roots = load_ca_roots(tf.path()).unwrap();
        assert!(!roots.is_empty());
    }

    #[test]
    fn load_ca_roots_rejects_missing_file() {
        let err = load_ca_roots(Path::new("/nonexistent/ca.pem")).unwrap_err();
        assert!(matches!(err, CertStoreError::Read("ca")), "got {err:?}");
    }

    #[test]
    fn load_ca_roots_rejects_empty_pem() {
        let tf = write_tmp("");
        let err = load_ca_roots(tf.path()).unwrap_err();
        assert!(matches!(err, CertStoreError::Empty("ca")), "got {err:?}");
    }

    #[test]
    fn load_cert_chain_happy_path() {
        let (_, cert, _, _) = mint_ca_pem();
        let tf = write_tmp(&cert);
        let chain = load_cert_chain(tf.path()).unwrap();
        assert_eq!(chain.len(), 1);
    }

    #[test]
    fn load_key_pem_happy_path() {
        let (_, _, key, _) = mint_ca_pem();
        let tf = write_tmp(&key);
        // Successfully extracting + dropping. The function MUST NOT
        // expose the key bytes anywhere — this test only asserts
        // it can be loaded into the rustls-owned shape.
        let _ = load_key_pem(tf.path()).unwrap();
    }

    #[test]
    fn load_key_pem_rejects_missing_file() {
        let err = load_key_pem(Path::new("/nonexistent/key.pem")).unwrap_err();
        assert!(matches!(err, CertStoreError::Read("key")), "got {err:?}");
    }

    #[test]
    fn load_key_pem_rejects_pem_without_key_block() {
        // A CA cert PEM has no `PRIVATE KEY` block → loader reports
        // Empty (no key blocks found).
        let (ca, _, _, _) = mint_ca_pem();
        let tf = write_tmp(&ca);
        let err = load_key_pem(tf.path()).unwrap_err();
        assert!(matches!(err, CertStoreError::Empty("key")), "got {err:?}");
    }

    #[test]
    fn build_server_config_with_valid_material() {
        let (ca, cert, key, _) = mint_ca_pem();
        let ca_tf = write_tmp(&ca);
        let cert_tf = write_tmp(&cert);
        let key_tf = write_tmp(&key);
        let roots = load_ca_roots(ca_tf.path()).unwrap();
        let chain = load_cert_chain(cert_tf.path()).unwrap();
        let key = load_key_pem(key_tf.path()).unwrap();
        // Build returns the raw `ServerConfig`; callers wrap in
        // `Arc` / `ArcSwap` as needed.
        let _cfg: rustls::ServerConfig =
            build_server_config(roots, chain, key, Vec::new()).unwrap();
    }

    #[test]
    fn cert_paths_from_env_requires_every_path() {
        // Sweep each env var. Setting/unsetting env in parallel
        // tests is racy → wrap the whole block in a single test +
        // a Mutex via `serial_test` would be ideal, but we keep
        // dependencies minimal: just snapshot, modify, restore.
        let _saved = EnvGuard::snapshot();
        std::env::set_var(ENV_CA_PATH, "/tmp/ca.pem");
        std::env::set_var(ENV_CERT_PATH, "/tmp/cert.pem");
        std::env::set_var(ENV_KEY_PATH, "/tmp/key.pem");
        std::env::remove_var(ENV_CRL_PATH);
        let p = CertPaths::from_env().unwrap();
        assert_eq!(p.ca, Path::new("/tmp/ca.pem"));
        assert_eq!(p.cert, Path::new("/tmp/cert.pem"));
        assert_eq!(p.key, Path::new("/tmp/key.pem"));
        assert!(p.crl.is_none());

        std::env::remove_var(ENV_KEY_PATH);
        let err = CertPaths::from_env().unwrap_err();
        assert!(matches!(err, CertStoreError::EnvMissing(ENV_KEY_PATH)));
    }

    #[test]
    fn cert_store_error_class_is_stable() {
        for (err, expect) in [
            (CertStoreError::EnvMissing("X"), "mtls-env-missing"),
            (CertStoreError::Read("X"), "mtls-read"),
            (CertStoreError::Parse("X"), "mtls-parse"),
            (CertStoreError::Empty("X"), "mtls-empty"),
            (CertStoreError::Build, "mtls-build"),
        ] {
            assert_eq!(err.class(), expect);
            assert_eq!(err.to_string(), expect);
        }
    }

    /// Snapshot + restore env vars across tests that mutate them.
    /// Cargo runs tests in parallel; we can't fully isolate here, but
    /// snapshotting on construction + restoring on drop bounds the
    /// blast radius.
    struct EnvGuard {
        ca: Option<String>,
        cert: Option<String>,
        key: Option<String>,
        crl: Option<String>,
    }
    impl EnvGuard {
        fn snapshot() -> Self {
            Self {
                ca: std::env::var(ENV_CA_PATH).ok(),
                cert: std::env::var(ENV_CERT_PATH).ok(),
                key: std::env::var(ENV_KEY_PATH).ok(),
                crl: std::env::var(ENV_CRL_PATH).ok(),
            }
        }
    }
    impl Drop for EnvGuard {
        fn drop(&mut self) {
            fn restore(name: &str, prev: Option<&String>) {
                match prev {
                    Some(v) => std::env::set_var(name, v),
                    None => std::env::remove_var(name),
                }
            }
            restore(ENV_CA_PATH, self.ca.as_ref());
            restore(ENV_CERT_PATH, self.cert.as_ref());
            restore(ENV_KEY_PATH, self.key.as_ref());
            restore(ENV_CRL_PATH, self.crl.as_ref());
        }
    }
}
