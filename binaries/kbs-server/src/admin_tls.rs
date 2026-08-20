//! mTLS termination for the KBS **admin** listener (§13/§24/§25).
//!
//! ## What this closes
//!
//! The admin listener serves `register-vm`, `activate` (the §25
//! split-brain fence), `seed-boot-counter` and `allowlist/reload` — every
//! one of them mutates the lifecycle state that decides *which host may
//! unlock a tenant's encrypted disk*. Until this module existed the
//! listener was a plain `TcpListener`: `kbs_transport::admin_handler`
//! documented "mTLS at the listener level … rejects unauthenticated
//! peers", but nothing implemented it, so the ONLY control was a
//! CiliumNetworkPolicy label match. Any workload that could reach the
//! port — an in-cluster compromise, a pod that spoofs the vali label, a
//! future namespace whose policy drifts — could seed boot counters and
//! drive the migration fence, and `PeerCertInfo` was never populated so
//! every admin audit row recorded `peer_san=None`.
//!
//! ## The gate
//!
//! rustls, TLS 1.3 only, `WebPkiClientVerifier` over an operator-pinned
//! client-CA bundle and **no** `allow_unauthenticated()`. A peer that
//! presents no client cert, or one that does not chain to that CA, never
//! completes the handshake — it is refused before any axum handler, any
//! route match, any body read. A peer that does complete it has its leaf
//! parsed for a stable identity (SAN URI → SAN DNS → Subject CN) plus the
//! cert serial; both are injected as [`PeerCertInfo`] into every request
//! on that connection, which is what puts a real `peer_san` in the admin
//! audit chain. A verified cert with NO identity carrier is dropped —
//! an admin peer that cannot be named cannot be audited.
//!
//! ## Fail-closed vs. deployable
//!
//! [`AdminListenerMode::decide`] is the whole policy, in one place:
//!
//! | `require_mtls` | material | outcome |
//! |---|---|---|
//! | (either) | complete | [`AdminListenerMode::Mtls`] — enforced |
//! | `true` (default) | absent | [`AdminListenerMode::Refuse`] — the listener is NOT bound |
//! | `false` (explicit opt-out) | absent | [`AdminListenerMode::PlaintextOptIn`] — loud warning |
//!
//! There is deliberately no "configured but unreadable ⇒ plaintext"
//! path: a build failure on present-but-broken material propagates and
//! the listener is refused. The default is `true` so a config that says
//! nothing about TLS gets the safe answer; the opt-out exists only so a
//! fleet whose certs have not been issued yet can be upgraded to this
//! binary in one step and cut over in another, with the insecure state
//! visible in the rendered config rather than implicit in the code.
//!
//! Refusal is scoped to the ADMIN listener, not the process: the release
//! path (`/v1/kbs/release`) keeps serving, so a misconfiguration costs
//! new launches / migrations, not the KEK unlock of every running VM.

use crate::config::AdminConfig;
use kbs_transport::PeerCertInfo;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::WebPkiClientVerifier;
use rustls::{RootCertStore, ServerConfig};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use tokio_rustls::TlsAcceptor;
use x509_parser::extensions::GeneralName;
use x509_parser::oid_registry::OID_X509_COMMON_NAME;
use x509_parser::prelude::*;

/// Cap on how long a peer may hold a connection without finishing the
/// TLS handshake. Without it a slow-loris could pin admin accept-loop
/// tasks indefinitely.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// Static-classifier errors — every variant's `Display` is a fixed
/// token, so a log line can never leak a path or key material.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum AdminTlsError {
    /// One of the three PEM files could not be read.
    #[error("admin-tls-read")]
    Read(&'static str),
    /// A PEM file was read but did not decode.
    #[error("admin-tls-parse")]
    Parse(&'static str),
    /// A PEM file decoded but held zero blocks of the required kind
    /// (e.g. the client-CA path pointed at an empty file).
    #[error("admin-tls-empty")]
    Empty(&'static str),
    /// rustls refused to build the config (bad key type, verifier
    /// build failure).
    #[error("admin-tls-build")]
    Build,
}

/// The three operator-supplied PEM paths. All three are required
/// together: a server identity without a client CA would be TLS with no
/// authentication, which is exactly the hole this module closes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdminTlsPaths {
    /// Server cert chain presented to the caller (leaf first).
    pub cert: PathBuf,
    /// Server private key (PKCS#8 / SEC1 PEM).
    pub key: PathBuf,
    /// **Pinned** CA bundle every client cert must chain to.
    pub client_ca: PathBuf,
}

/// What [`crate::server::run`] should do with the admin listener.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AdminListenerMode {
    /// Serve with mTLS from these paths.
    Mtls(AdminTlsPaths),
    /// Serve plaintext — ONLY reachable via an explicit
    /// `require_mtls = false` in the config.
    PlaintextOptIn,
    /// Do not bind the admin listener at all. The `&'static str` is the
    /// operator-facing reason.
    Refuse(&'static str),
}

impl AdminListenerMode {
    /// The fail-closed decision. Pure — no I/O — so the policy is
    /// testable without a filesystem and cannot differ between the
    /// startup log line and what actually gets bound.
    pub fn decide(cfg: &AdminConfig) -> Self {
        match (
            cfg.tls_cert_path.as_ref(),
            cfg.tls_key_path.as_ref(),
            cfg.client_ca_path.as_ref(),
        ) {
            (Some(cert), Some(key), Some(client_ca)) => Self::Mtls(AdminTlsPaths {
                cert: cert.clone(),
                key: key.clone(),
                client_ca: client_ca.clone(),
            }),
            // Partial material never reaches here — `Config::validate`
            // rejects it at load as an unambiguous operator mistake. It
            // is handled anyway (and fail-closed) so this function is
            // total on its own.
            _ if cfg.require_mtls => Self::Refuse(
                "admin.require_mtls is true but admin.{tls_cert_path,tls_key_path,client_ca_path} \
                 are not all set",
            ),
            _ => Self::PlaintextOptIn,
        }
    }
}

/// Load a PEM bundle of CA certs into a `RootCertStore` — the pinned
/// trust anchors for CLIENT cert validation.
fn load_ca_roots(path: &Path) -> Result<RootCertStore, AdminTlsError> {
    let raw = std::fs::read(path).map_err(|_| AdminTlsError::Read("client_ca"))?;
    let mut roots = RootCertStore::empty();
    for cert in parse_certs_pem(&raw, "client_ca")? {
        roots
            .add(cert)
            .map_err(|_| AdminTlsError::Parse("client_ca"))?;
    }
    if roots.is_empty() {
        return Err(AdminTlsError::Empty("client_ca"));
    }
    Ok(roots)
}

fn load_cert_chain(path: &Path) -> Result<Vec<CertificateDer<'static>>, AdminTlsError> {
    let raw = std::fs::read(path).map_err(|_| AdminTlsError::Read("cert"))?;
    let certs = parse_certs_pem(&raw, "cert")?;
    if certs.is_empty() {
        return Err(AdminTlsError::Empty("cert"));
    }
    Ok(certs)
}

/// Load the server private key. The returned `PrivateKeyDer` is moved
/// straight into rustls and never re-surfaced — there is no getter, no
/// `Debug` print, no diagnostic dump of these bytes anywhere in this
/// module.
fn load_key_pem(path: &Path) -> Result<PrivateKeyDer<'static>, AdminTlsError> {
    let raw = std::fs::read(path).map_err(|_| AdminTlsError::Read("key"))?;
    let mut cursor = std::io::Cursor::new(&raw[..]);
    match rustls_pemfile::private_key(&mut cursor) {
        Ok(Some(key)) => Ok(key),
        Ok(None) => Err(AdminTlsError::Empty("key")),
        Err(_) => Err(AdminTlsError::Parse("key")),
    }
}

fn parse_certs_pem(
    pem: &[u8],
    label: &'static str,
) -> Result<Vec<CertificateDer<'static>>, AdminTlsError> {
    let mut cursor = std::io::Cursor::new(pem);
    let mut out = Vec::new();
    for entry in rustls_pemfile::certs(&mut cursor) {
        out.push(entry.map_err(|_| AdminTlsError::Parse(label))?);
    }
    Ok(out)
}

/// Build the admin listener's rustls `ServerConfig` from `paths`.
///
/// Two properties a reviewer should be able to check by eye:
///
/// 1. The client verifier is built from the pinned CA and
///    `.allow_unauthenticated()` is NEVER called — a peer with no client
///    cert fails the handshake. Flipping that would have to be an
///    explicit, diff-visible line.
/// 2. TLS 1.3 is pinned at the config level rather than by relying on
///    the `tls12` cargo feature being off (feature unification from a
///    sibling crate can turn it on — `ureq` also links rustls here).
///
/// The crypto provider is passed explicitly (`ring`) instead of relying
/// on the process default, which would panic at runtime if two providers
/// were ever unified in.
pub fn build_server_config(paths: &AdminTlsPaths) -> Result<ServerConfig, AdminTlsError> {
    let roots = load_ca_roots(&paths.client_ca)?;
    let chain = load_cert_chain(&paths.cert)?;
    let key = load_key_pem(&paths.key)?;

    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let verifier = WebPkiClientVerifier::builder_with_provider(Arc::new(roots), provider.clone())
        .build()
        .map_err(|_| AdminTlsError::Build)?;

    let mut config = ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|_| AdminTlsError::Build)?
        .with_client_cert_verifier(verifier)
        .with_single_cert(chain, key)
        .map_err(|_| AdminTlsError::Build)?;
    // The admin API is HTTP/1.1 (vali posts it with stdlib `urllib`).
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(config)
}

/// Derive the audit identity of an already-CA-verified leaf cert.
///
/// Trust is NOT established here — rustls already vouched that this leaf
/// chains to the pinned CA. This is identity *reading*, in the same
/// most-specific-first order the Edge uses: SAN URI (the spec'd carrier,
/// `spiffe://hippius.network/vali`), then SAN DNS, then Subject CN.
///
/// `None` ⇒ the leaf did not parse, or carries no identity at all. The
/// caller drops the connection: an admin peer that cannot be named
/// cannot be attributed in the audit chain, and a `peer_san` of `""`
/// would be indistinguishable from "no cert" in the log.
pub fn peer_cert_info(leaf_der: &[u8]) -> Option<PeerCertInfo> {
    let (_, parsed) = X509Certificate::from_der(leaf_der).ok()?;
    let serial_hex = parsed
        .raw_serial_as_string()
        .replace(':', "")
        .to_lowercase();

    let mut san_uri: Option<String> = None;
    if let Ok(Some(san)) = parsed.subject_alternative_name() {
        for name in &san.value.general_names {
            if let GeneralName::URI(uri) = name {
                san_uri = Some((*uri).to_string());
                break;
            }
        }
        if san_uri.is_none() {
            for name in &san.value.general_names {
                if let GeneralName::DNSName(dns) = name {
                    san_uri = Some((*dns).to_string());
                    break;
                }
            }
        }
    }
    if san_uri.is_none() {
        for attr in parsed.subject().iter_attributes() {
            if attr.attr_type() == &OID_X509_COMMON_NAME {
                if let Ok(s) = attr.attr_value().as_str() {
                    if !s.is_empty() {
                        san_uri = Some(s.to_string());
                        break;
                    }
                }
            }
        }
    }

    Some(PeerCertInfo {
        san_uri: san_uri?,
        serial_hex,
    })
}

/// Serve `router` over mTLS on `listener` until `shutdown` completes.
///
/// One task per connection. Every failure mode — handshake timeout,
/// handshake rejection (no cert / wrong CA / expired), a verified cert
/// with no identity carrier — ends in a dropped connection and a
/// static-class log line. None of them reaches `router`.
pub async fn serve_admin_mtls<F>(
    listener: tokio::net::TcpListener,
    tls: TlsAcceptor,
    router: axum::Router,
    shutdown: F,
) where
    F: std::future::Future<Output = ()> + Send + 'static,
{
    let mut shutdown = Box::pin(shutdown);
    loop {
        tokio::select! {
            _ = &mut shutdown => break,
            accepted = listener.accept() => {
                let Ok((tcp, _peer_addr)) = accepted else {
                    log_admin_tls("accept-error");
                    tokio::time::sleep(Duration::from_millis(20)).await;
                    continue;
                };
                let tls = tls.clone();
                let router = router.clone();
                tokio::spawn(async move { handle_conn(tcp, tls, router).await });
            }
        }
    }
    log_admin_tls("drained");
}

/// Terminate TLS on one accepted connection, stamp the verified peer
/// identity into every request it carries, and serve the admin router
/// over HTTP/1.1.
async fn handle_conn(tcp: tokio::net::TcpStream, tls: TlsAcceptor, router: axum::Router) {
    let stream = match tokio::time::timeout(HANDSHAKE_TIMEOUT, tls.accept(tcp)).await {
        Ok(Ok(s)) => s,
        // rustls refused the peer: no client cert, a cert that does not
        // chain to the pinned CA, an expired cert, or a sub-TLS-1.3
        // client. The router is never constructed into a call.
        Ok(Err(_)) => return log_admin_tls("handshake-refused"),
        Err(_) => return log_admin_tls("handshake-timeout"),
    };

    // The verifier already accepted the chain; read the identity off the
    // leaf for audit attribution.
    let peer = {
        let (_, session) = stream.get_ref();
        match session
            .peer_certificates()
            .and_then(|chain| chain.first())
            .and_then(|leaf| peer_cert_info(leaf.as_ref()))
        {
            Some(p) => p,
            None => return log_admin_tls("peer-identity-missing"),
        }
    };

    let hyper_svc =
        hyper::service::service_fn(move |mut req: hyper::Request<hyper::body::Incoming>| {
            // Per-request injection: `admin_handler` reads this back out of
            // the extensions for the audit row's `peer_san` / `peer_serial`.
            req.extensions_mut().insert(peer.clone());
            let mut svc = router.clone();
            async move { tower::Service::call(&mut svc, req).await }
        });

    if hyper::server::conn::http1::Builder::new()
        .serve_connection(hyper_util::rt::TokioIo::new(stream), hyper_svc)
        .await
        .is_err()
    {
        log_admin_tls("serve-error");
    }
}

fn log_admin_tls(event: &'static str) {
    eprintln!("kbs-server: admin-tls: {event}");
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(
        require_mtls: bool,
        cert: Option<&str>,
        key: Option<&str>,
        ca: Option<&str>,
    ) -> AdminConfig {
        AdminConfig {
            addr: "127.0.0.1:8001".parse().unwrap(),
            idempotency_subdir: PathBuf::from("admin-idempotency"),
            audit_subdir: PathBuf::from("admin"),
            idempotency_ttl_secs: 86_400,
            rate_per_sec: 10,
            burst: 20,
            require_mtls,
            tls_cert_path: cert.map(PathBuf::from),
            tls_key_path: key.map(PathBuf::from),
            client_ca_path: ca.map(PathBuf::from),
        }
    }

    #[test]
    fn missing_material_with_require_mtls_refuses_the_listener() {
        // THE fail-closed claim: nothing configured + the default
        // `require_mtls` ⇒ the admin listener is not bound at all. Any
        // other arm here would publish an unauthenticated
        // lifecycle-mutation API.
        let mode = AdminListenerMode::decide(&cfg(true, None, None, None));
        assert!(matches!(mode, AdminListenerMode::Refuse(_)));
    }

    #[test]
    fn partial_material_with_require_mtls_refuses_the_listener() {
        // A server identity with no client CA is TLS without
        // authentication — must not be treated as "configured".
        for (c, k, a) in [
            (Some("/c"), Some("/k"), None),
            (Some("/c"), None, Some("/a")),
            (None, Some("/k"), Some("/a")),
        ] {
            let mode = AdminListenerMode::decide(&cfg(true, c, k, a));
            assert!(
                matches!(mode, AdminListenerMode::Refuse(_)),
                "partial material {c:?}/{k:?}/{a:?} must refuse"
            );
        }
    }

    #[test]
    fn complete_material_enforces_mtls_even_when_require_is_false() {
        // `require_mtls=false` is an opt-out for MISSING material only.
        // Once certs exist they are always enforced — flipping the flag
        // must not silently downgrade a working mTLS listener.
        let mode = AdminListenerMode::decide(&cfg(false, Some("/c"), Some("/k"), Some("/a")));
        assert_eq!(
            mode,
            AdminListenerMode::Mtls(AdminTlsPaths {
                cert: PathBuf::from("/c"),
                key: PathBuf::from("/k"),
                client_ca: PathBuf::from("/a"),
            })
        );
    }

    #[test]
    fn explicit_opt_out_without_material_is_plaintext() {
        // The single deployable escape hatch — must require BOTH an
        // explicit `require_mtls=false` AND absent material.
        assert_eq!(
            AdminListenerMode::decide(&cfg(false, None, None, None)),
            AdminListenerMode::PlaintextOptIn
        );
    }

    #[test]
    fn build_server_config_fails_closed_on_unreadable_material() {
        // Present-but-broken material must NOT degrade to plaintext: the
        // error propagates and `run` refuses the listener.
        let err = build_server_config(&AdminTlsPaths {
            cert: PathBuf::from("/nonexistent/cert.pem"),
            key: PathBuf::from("/nonexistent/key.pem"),
            client_ca: PathBuf::from("/nonexistent/ca.pem"),
        })
        .unwrap_err();
        assert_eq!(err, AdminTlsError::Read("client_ca"));
    }

    #[test]
    fn peer_cert_info_rejects_unparseable_leaf() {
        assert!(peer_cert_info(b"not-a-cert").is_none());
    }

    #[test]
    fn admin_tls_error_display_is_static() {
        // The log/audit classifier contract: no variant may interpolate
        // a path (which would put operator filesystem layout in logs).
        assert_eq!(AdminTlsError::Read("cert").to_string(), "admin-tls-read");
        assert_eq!(AdminTlsError::Parse("key").to_string(), "admin-tls-parse");
        assert_eq!(
            AdminTlsError::Empty("client_ca").to_string(),
            "admin-tls-empty"
        );
        assert_eq!(AdminTlsError::Build.to_string(), "admin-tls-build");
    }
}
