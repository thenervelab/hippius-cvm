//! mTLS termination for the KBS **admin** listener (§13/§24/§25).
//!
//! ## What this closes
//!
//! The admin listener serves `register-vm`, `activate` (the §25
//! split-brain fence), `seed-boot-counter`, `seed-keepalive-binding` and
//! `allowlist/reload` — every
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
//! route match, any body read. A peer that does complete it is then
//! AUTHORIZED by [`authorize_admin_peer`], by its URI SANs only:
//!
//! | leaf carries | outcome |
//! |---|---|
//! | ≥1 URI SAN, every one in `allowed_client_identities`, nothing else | admitted |
//! | no SAN extension (a CN, even `CN=spiffe://…/vali`, is never read) | dropped |
//! | a SAN extension that does not parse, is duplicated, or is empty | dropped |
//! | ANY non-URI SAN (DNS, IP, email, otherName, …) — even beside a listed URI | dropped |
//! | a URI SAN not in the allowlist — even beside a listed one | dropped |
//!
//! Refusing every non-URI SAN outright (rather than ignoring it) removes
//! the carrier ambiguity: a DNS SAN or CN spelling `spiffe://…/vali` can
//! never stand in for the URI, and no leaf is "vali plus something
//! else". The admitted URIs (sorted) and the cert serial are injected as
//! [`PeerCertInfo`] into every request on that connection, which is what
//! puts a real `peer_san` in the admin audit chain.
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
use kbs_transport::SpiffeId;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::WebPkiClientVerifier;
use rustls::{RootCertStore, ServerConfig};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use tokio_rustls::TlsAcceptor;
use x509_parser::der_parser::asn1_rs::{Any, Class, Tag};
use x509_parser::oid_registry::OID_X509_EXT_SUBJECT_ALT_NAME;
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
    /// Serve plaintext — ONLY reachable with no material, an explicit
    /// `require_mtls = false` AND `dev_allow_plaintext = true`.
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
            (None, None, None) if cfg.require_mtls => Self::Refuse(
                "admin.require_mtls is true but admin.{tls_cert_path,tls_key_path,client_ca_path} \
                 are not all set",
            ),
            (None, None, None) if !cfg.dev_allow_plaintext => Self::Refuse(
                "no admin mTLS material, and plaintext needs admin.dev_allow_plaintext = true \
                 (require_mtls = false alone no longer serves it)",
            ),
            (None, None, None) => Self::PlaintextOptIn,
            _ => Self::Refuse(
                "admin.{tls_cert_path,tls_key_path,client_ca_path} are only partly set — \
                 refusing rather than serving TLS without client authentication or plaintext",
            ),
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

/// Why a CA-verified admin leaf was refused. Each [`Self::as_str`] is a
/// fixed log token — never a SAN value, which is peer-controlled text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerRefusal {
    /// The leaf DER did not parse.
    LeafUnparseable,
    /// No SAN extension. The Subject CN is never an identity carrier.
    SanMissing,
    /// The SAN extension appears more than once, is not a DER SEQUENCE
    /// of GeneralNames, or carries a URI in a non-primitive encoding.
    SanMalformed,
    /// A SAN extension with no names in it.
    SanEmpty,
    /// A SAN of a type other than URI (DNS, IP, email, otherName, …).
    NonUriSan,
    /// The same URI SAN twice — the leaf is not a set of identities.
    DuplicateUri,
    /// An extension OID that is not minimally encoded — a possible
    /// second spelling of the SAN extension.
    NonCanonicalOid,
    /// A URI SAN that is not in the allowlist.
    NotAllowed,
}

impl PeerRefusal {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::LeafUnparseable => "peer-leaf-unparseable",
            Self::SanMissing => "peer-san-missing",
            Self::SanMalformed => "peer-san-malformed",
            Self::SanEmpty => "peer-san-empty",
            Self::NonUriSan => "peer-san-non-uri",
            Self::DuplicateUri => "peer-san-duplicate-uri",
            Self::NonCanonicalOid => "peer-ext-oid-noncanonical",
            Self::NotAllowed => "peer-identity-not-allowed",
        }
    }
}

/// GeneralName `uniformResourceIdentifier [6] IA5String` (RFC 5280).
const GENERAL_NAME_URI_TAG: Tag = Tag(6);

/// Identifier octets of a primitive context-specific `[6]`.
const URI_IDENTIFIER: u8 = 0x86;

/// Identifier octets of a universal constructed SEQUENCE.
const SEQUENCE_IDENTIFIER: u8 = 0x30;

/// `true` iff `raw` is exactly the canonical DER TLV
/// `identifier ‖ minimal definite length ‖ data`.
///
/// asn1-rs normalizes what it reads — a high-tag-number form of tag 6
/// (`9f 06`) or a non-minimal length (`86 81 1d`) parse the same as the
/// canonical header — and webpki accepts such a leaf. Re-encoding and
/// comparing byte-for-byte is the one check that no such alias survives.
fn is_canonical_tlv(raw: &[u8], identifier: u8, data: &[u8]) -> bool {
    let mut header = vec![identifier];
    let len = data.len();
    if len < 0x80 {
        header.push(len as u8);
    } else {
        let be = len.to_be_bytes();
        let significant = &be[be.iter().take_while(|b| **b == 0).count()..];
        header.push(0x80 | significant.len() as u8);
        header.extend_from_slice(significant);
    }
    raw.len() == header.len() + len && raw.starts_with(&header) && raw.ends_with(data)
}

/// `true` iff an OID's content octets are minimally encoded (X.690
/// 8.19.2): no subidentifier starts with `0x80`, and the last octet
/// closes a subidentifier. A non-minimal encoding is a second spelling
/// of the same OID — e.g. `55 1d 80 11` for SAN — which a raw-bytes
/// comparison would not recognise as the SAN extension.
fn oid_is_canonical(der: &[u8]) -> bool {
    der.last().is_some_and(|last| last & 0x80 == 0)
        && der
            .iter()
            .enumerate()
            .all(|(i, b)| *b != 0x80 || (i > 0 && der[i - 1] & 0x80 != 0))
}

/// The URI SANs of a raw `SubjectAltName` extension value, read
/// STRICTLY from the DER: a canonical SEQUENCE of canonical primitive
/// context-specific `[6]`s and nothing else. x509-parser's own
/// `GeneralName` view is not used, because it is lenient in ways that
/// matter here — it reads a CONSTRUCTED `[6]` as a URI, and webpki
/// accepts such a leaf.
fn strict_uri_sans(raw: &[u8]) -> Result<Vec<&[u8]>, PeerRefusal> {
    let (rest, seq) = Any::from_der(raw).map_err(|_| PeerRefusal::SanMalformed)?;
    if !rest.is_empty() || !is_canonical_tlv(raw, SEQUENCE_IDENTIFIER, seq.data) {
        return Err(PeerRefusal::SanMalformed);
    }
    let mut body = seq.data;
    let mut uris = Vec::new();
    while !body.is_empty() {
        let (next, name) = Any::from_der(body).map_err(|_| PeerRefusal::SanMalformed)?;
        let element = &body[..body.len() - next.len()];
        body = next;
        if name.header.class() != Class::ContextSpecific {
            return Err(PeerRefusal::SanMalformed);
        }
        if name.tag() != GENERAL_NAME_URI_TAG {
            return Err(PeerRefusal::NonUriSan);
        }
        // Rejects a constructed [6], a high-tag-number form of 6 and a
        // non-minimal length alike.
        if !is_canonical_tlv(element, URI_IDENTIFIER, name.data) {
            return Err(PeerRefusal::SanMalformed);
        }
        uris.push(name.data);
    }
    Ok(uris)
}

/// Authorize an already-CA-verified admin client leaf.
///
/// Trust in the ISSUER is NOT established here — rustls already vouched
/// that this leaf chains to the pinned CA. This decides whether the leaf
/// was issued for THIS purpose, by its URI SANs alone:
///
/// * every extension OID must be minimally encoded;
/// * the leaf must carry exactly one SAN extension, canonical DER, with
///   ≥1 name;
/// * every name must be a URI (any other SAN type refuses the leaf);
/// * no URI may appear twice;
/// * every URI must be byte-for-byte in `allowed` (ALL, not ANY).
///
/// The Subject CN is never consulted. On success the returned
/// [`PeerCertInfo`] holds exactly the admitted URIs (sorted) — the full
/// audit identity.
pub fn authorize_admin_peer(
    leaf_der: &[u8],
    allowed: &[SpiffeId],
) -> Result<PeerCertInfo, PeerRefusal> {
    let (_, parsed) =
        X509Certificate::from_der(leaf_der).map_err(|_| PeerRefusal::LeafUnparseable)?;
    // An extension OID with a second spelling could smuggle a second SAN
    // past `get_extension_unique`, which compares raw OID bytes.
    if parsed
        .extensions()
        .iter()
        .any(|ext| !oid_is_canonical(ext.oid.as_bytes()))
    {
        return Err(PeerRefusal::NonCanonicalOid);
    }
    // `get_extension_unique` refuses a duplicated SAN extension.
    let san = parsed
        .get_extension_unique(&OID_X509_EXT_SUBJECT_ALT_NAME)
        .map_err(|_| PeerRefusal::SanMalformed)?
        .ok_or(PeerRefusal::SanMissing)?;
    let uris = strict_uri_sans(san.value)?;
    // The identity recorded is the ALLOWLIST's value, which equals the
    // SAN byte-for-byte — so a peer URI need not be decoded itself: one
    // that is not a canonical SPIFFE ID (non-ASCII, NUL, …) can never
    // equal a listed entry.
    let mut admitted: Vec<SpiffeId> = Vec::with_capacity(uris.len());
    for uri in uris {
        let listed = allowed
            .iter()
            .find(|a| a.as_str().as_bytes() == uri)
            .ok_or(PeerRefusal::NotAllowed)?;
        if admitted.contains(listed) {
            return Err(PeerRefusal::DuplicateUri);
        }
        admitted.push(listed.clone());
    }
    let serial_hex = parsed
        .raw_serial_as_string()
        .replace(':', "")
        .to_lowercase();
    // Every name reached `admitted`, so it is empty iff the SAN
    // extension named nobody — the one guard for that case.
    PeerCertInfo::new(admitted, serial_hex).ok_or(PeerRefusal::SanEmpty)
}

/// Serve `router` over mTLS on `listener` until `shutdown` completes.
///
/// One task per connection. Every failure mode — handshake timeout,
/// handshake rejection (no cert / wrong CA / expired), a verified cert
/// that [`authorize_admin_peer`] refuses — ends in a dropped connection
/// and a static-class log line. None of them reaches `router`.
pub async fn serve_admin_mtls<F>(
    listener: tokio::net::TcpListener,
    tls: TlsAcceptor,
    router: axum::Router,
    allowed: Arc<Vec<SpiffeId>>,
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
                let allowed = Arc::clone(&allowed);
                tokio::spawn(async move { handle_conn(tcp, tls, router, allowed).await });
            }
        }
    }
    log_admin_tls("drained");
}

/// Terminate TLS on one accepted connection, stamp the verified peer
/// identity into every request it carries, and serve the admin router
/// over HTTP/1.1.
async fn handle_conn(
    tcp: tokio::net::TcpStream,
    tls: TlsAcceptor,
    router: axum::Router,
    allowed: Arc<Vec<SpiffeId>>,
) {
    let stream = match tokio::time::timeout(HANDSHAKE_TIMEOUT, tls.accept(tcp)).await {
        Ok(Ok(s)) => s,
        // rustls refused the peer: no client cert, a cert that does not
        // chain to the pinned CA, an expired cert, or a sub-TLS-1.3
        // client. The router is never constructed into a call.
        Ok(Err(_)) => return log_admin_tls("handshake-refused"),
        Err(_) => return log_admin_tls("handshake-timeout"),
    };

    // Chaining to the admin CA proves who issued the leaf, not what it
    // was issued FOR: authorize it by its URI SANs before any request is
    // read.
    let peer = {
        let (_, session) = stream.get_ref();
        let Some(leaf) = session.peer_certificates().and_then(|chain| chain.first()) else {
            return log_admin_tls("peer-cert-missing");
        };
        match authorize_admin_peer(leaf.as_ref(), &allowed) {
            Ok(p) => p,
            Err(refusal) => return log_admin_tls(refusal.as_str()),
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
            dev_allow_plaintext: false,
            allowed_client_identities: crate::config::default_admin_allowed_client_identities(),
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
    fn require_mtls_false_alone_no_longer_serves_plaintext() {
        assert!(matches!(
            AdminListenerMode::decide(&cfg(false, None, None, None)),
            AdminListenerMode::Refuse(_)
        ));
    }

    #[test]
    fn plaintext_needs_the_dev_flag_and_no_material() {
        let mut c = cfg(false, None, None, None);
        c.dev_allow_plaintext = true;
        assert_eq!(
            AdminListenerMode::decide(&c),
            AdminListenerMode::PlaintextOptIn
        );
        // …and never while require_mtls is true,
        let mut c = cfg(true, None, None, None);
        c.dev_allow_plaintext = true;
        assert!(matches!(
            AdminListenerMode::decide(&c),
            AdminListenerMode::Refuse(_)
        ));
        // …and never over present material.
        let mut c = cfg(false, Some("/c"), Some("/k"), Some("/a"));
        c.dev_allow_plaintext = true;
        assert!(matches!(
            AdminListenerMode::decide(&c),
            AdminListenerMode::Mtls(_)
        ));
    }

    #[test]
    fn partial_material_refuses_even_with_the_dev_flag() {
        for (c, k, a) in [
            (Some("/c"), Some("/k"), None),
            (Some("/c"), None, None),
            (None, None, Some("/a")),
        ] {
            let mut conf = cfg(false, c, k, a);
            conf.dev_allow_plaintext = true;
            assert!(
                matches!(
                    AdminListenerMode::decide(&conf),
                    AdminListenerMode::Refuse(_)
                ),
                "partial {c:?}/{k:?}/{a:?} must refuse"
            );
        }
    }

    // ── authorize_admin_peer: one case per carrier shape ─────────────

    const VALI: &str = crate::config::VALI_ADMIN_IDENTITY;
    const OPERATOR: &str = "spiffe://hippius.network/operator";

    fn id(s: &str) -> SpiffeId {
        SpiffeId::parse(s).unwrap()
    }

    fn vali_only() -> Vec<SpiffeId> {
        vec![id(VALI)]
    }

    /// A self-signed leaf with exactly these SANs, this CN (if any) and
    /// these raw extra extensions. rcgen emits no SAN extension at all
    /// when `sans` is empty.
    fn leaf_with(
        sans: Vec<rcgen::SanType>,
        cn: Option<&str>,
        extra: Vec<rcgen::CustomExtension>,
    ) -> Vec<u8> {
        let kp = rcgen::KeyPair::generate().unwrap();
        let mut p = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
        p.subject_alt_names = sans;
        p.custom_extensions = extra;
        p.distinguished_name = rcgen::DistinguishedName::new();
        if let Some(cn) = cn {
            p.distinguished_name.push(rcgen::DnType::CommonName, cn);
        }
        p.self_signed(&kp).unwrap().der().to_vec()
    }

    fn uri(s: &str) -> rcgen::SanType {
        rcgen::SanType::URI(s.try_into().unwrap())
    }

    fn dns(s: &str) -> rcgen::SanType {
        rcgen::SanType::DnsName(s.try_into().unwrap())
    }

    /// A raw SAN extension (OID 2.5.29.17) with this DER content.
    fn raw_san(content: Vec<u8>) -> rcgen::CustomExtension {
        rcgen::CustomExtension::from_oid_content(&[2, 5, 29, 17], content)
    }

    #[test]
    fn the_live_vali_leaf_is_admitted_with_its_uri_as_the_identity() {
        // The shape of the real `vali-kbs-admin-tls` leaf: CN=vali, one
        // URI SAN, nothing else.
        let peer = authorize_admin_peer(
            &leaf_with(vec![uri(VALI)], Some("vali"), vec![]),
            &vali_only(),
        )
        .unwrap();
        assert_eq!(peer.san_uris(), &[id(VALI)]);
        // Byte-identical to the pre-list `peer_san` of the same leaf.
        assert_eq!(peer.audit_identity(), VALI);
        assert!(!peer.serial_hex.is_empty());
    }

    #[test]
    fn a_cn_is_never_an_identity() {
        // No SAN extension at all: the CN — even spelling the listed URI
        // exactly — names nobody.
        for cn in [VALI, "vali"] {
            assert_eq!(
                authorize_admin_peer(&leaf_with(vec![], Some(cn), vec![]), &vali_only())
                    .unwrap_err(),
                PeerRefusal::SanMissing,
                "CN={cn}"
            );
        }
        assert_eq!(
            authorize_admin_peer(&leaf_with(vec![], None, vec![]), &vali_only()).unwrap_err(),
            PeerRefusal::SanMissing
        );
    }

    #[test]
    fn a_dns_san_is_never_an_identity_even_spelling_the_uri() {
        // `spiffe://hippius.network/vali` as a DNS SAN (rcgen does not
        // validate DNS syntax) is a different carrier and is refused.
        assert_eq!(
            authorize_admin_peer(&leaf_with(vec![dns(VALI)], None, vec![]), &vali_only())
                .unwrap_err(),
            PeerRefusal::NonUriSan
        );
    }

    #[test]
    fn any_non_uri_san_beside_a_listed_uri_refuses_the_leaf() {
        let other_name = rcgen::SanType::OtherName((
            vec![1, 3, 6, 1, 4, 1, 311, 20, 2, 3],
            rcgen::OtherNameValue::Utf8String("vali@hippius.network".into()),
        ));
        for (label, extra) in [
            ("dns", dns("vali.hippius.svc")),
            (
                "ip",
                rcgen::SanType::IpAddress("127.0.0.1".parse().unwrap()),
            ),
            (
                "email",
                rcgen::SanType::Rfc822Name("vali@hippius.network".try_into().unwrap()),
            ),
            ("otherName", other_name),
        ] {
            // Both orders: the refusal must not depend on which SAN a
            // loop happens to reach first.
            for sans in [
                vec![uri(VALI), extra.clone()],
                vec![extra.clone(), uri(VALI)],
            ] {
                assert_eq!(
                    authorize_admin_peer(&leaf_with(sans, Some("vali"), vec![]), &vali_only())
                        .unwrap_err(),
                    PeerRefusal::NonUriSan,
                    "URI + {label}"
                );
            }
        }
    }

    #[test]
    fn every_uri_san_must_be_listed() {
        let leaf = leaf_with(vec![uri(VALI), uri(OPERATOR)], None, vec![]);
        assert_eq!(
            authorize_admin_peer(&leaf, &vali_only()).unwrap_err(),
            PeerRefusal::NotAllowed
        );
        // Unlisted alone, near-misses included (exact, case-sensitive).
        for other in [
            OPERATOR,
            "spiffe://hippius.network/vali/extra",
            "spiffe://hippius.network/Vali",
            "https://hippius.network/vali",
        ] {
            assert_eq!(
                authorize_admin_peer(&leaf_with(vec![uri(other)], None, vec![]), &vali_only())
                    .unwrap_err(),
                PeerRefusal::NotAllowed,
                "{other}"
            );
        }
    }

    #[test]
    fn a_leaf_with_several_listed_uris_is_recorded_by_all_of_them_sorted() {
        // Listed in both, SAN order vali-then-operator: the audit identity
        // is the FULL sorted list, not the first SAN.
        let allowed = vec![id(VALI), id(OPERATOR)];
        let leaf = leaf_with(vec![uri(VALI), uri(OPERATOR)], None, vec![]);
        let peer = authorize_admin_peer(&leaf, &allowed).unwrap();
        assert_eq!(peer.san_uris(), &[id(OPERATOR), id(VALI)]);
        assert_eq!(peer.audit_identity(), format!("{OPERATOR},{VALI}"));
        // The same URI twice is refused, not silently collapsed into a
        // record that looks like a single-URI leaf.
        let twice = leaf_with(vec![uri(VALI), uri(VALI)], None, vec![]);
        assert_eq!(
            authorize_admin_peer(&twice, &allowed).unwrap_err(),
            PeerRefusal::DuplicateUri
        );
    }

    #[test]
    fn an_empty_or_malformed_or_duplicated_san_extension_refuses_the_leaf() {
        // SEQUENCE {} — a SAN extension naming nobody.
        assert_eq!(
            authorize_admin_peer(
                &leaf_with(vec![], Some(VALI), vec![raw_san(vec![0x30, 0x00])]),
                &vali_only()
            )
            .unwrap_err(),
            PeerRefusal::SanEmpty
        );
        // Not a SEQUENCE; and a SEQUENCE whose [6] URI length overruns.
        for bad in [vec![0x04, 0x00], vec![0x30, 0x03, 0x86, 0x7f, b'x']] {
            assert_eq!(
                authorize_admin_peer(
                    &leaf_with(vec![], Some(VALI), vec![raw_san(bad.clone())]),
                    &vali_only()
                )
                .unwrap_err(),
                PeerRefusal::SanMalformed,
                "{bad:02x?}"
            );
        }
        // Two SAN extensions: which one is "the" identity is ambiguous.
        let vali_uri_san = {
            let mut der = vec![0x86, VALI.len() as u8];
            der.extend_from_slice(VALI.as_bytes());
            let mut seq = vec![0x30, der.len() as u8];
            seq.extend(der);
            seq
        };
        assert_eq!(
            authorize_admin_peer(
                &leaf_with(vec![uri(VALI)], None, vec![raw_san(vali_uri_san)]),
                &vali_only()
            )
            .unwrap_err(),
            PeerRefusal::SanMalformed
        );
    }

    /// DER TLV with a short-form length.
    fn tlv(tag: u8, body: &[u8]) -> Vec<u8> {
        assert!(body.len() < 0x80);
        let mut v = vec![tag, body.len() as u8];
        v.extend_from_slice(body);
        v
    }

    /// A raw SAN extension: SEQUENCE { these already-encoded names }.
    fn san_of(names: &[Vec<u8>]) -> rcgen::CustomExtension {
        raw_san(tlv(0x30, &names.concat()))
    }

    fn refusal_of(names: &[Vec<u8>]) -> PeerRefusal {
        authorize_admin_peer(&leaf_with(vec![], None, vec![san_of(names)]), &vali_only())
            .unwrap_err()
    }

    #[test]
    fn a_raw_uri_san_is_admitted_only_in_its_primitive_encoding() {
        let good = tlv(0x86, VALI.as_bytes());
        let peer = authorize_admin_peer(
            &leaf_with(vec![], None, vec![san_of(&[good])]),
            &vali_only(),
        )
        .unwrap();
        assert_eq!(peer.audit_identity(), VALI);
        // Constructed [6] wrapping the right bytes: x509-parser reads it as
        // a URI and webpki accepts the leaf — the strict DER walk must not.
        assert_eq!(
            refusal_of(&[tlv(0xa6, VALI.as_bytes())]),
            PeerRefusal::SanMalformed
        );
        // A universal (not context-specific) element in the sequence.
        assert_eq!(
            refusal_of(&[tlv(0x16, VALI.as_bytes())]),
            PeerRefusal::SanMalformed
        );
    }

    #[test]
    fn a_non_canonical_der_header_never_aliases_a_uri_san() {
        let v = VALI.as_bytes();
        // High-tag-number form of [6].
        let mut high_tag = vec![0x9f, 0x06, v.len() as u8];
        high_tag.extend_from_slice(v);
        // Long-form length where the short form fits.
        let mut long_len = vec![0x86, 0x81, v.len() as u8];
        long_len.extend_from_slice(v);
        for (label, element) in [("high-tag [6]", high_tag), ("long-form length", long_len)] {
            assert_eq!(refusal_of(&[element]), PeerRefusal::SanMalformed, "{label}");
        }
        // Long-form length on the outer SEQUENCE.
        let inner = tlv(0x86, v);
        let mut outer = vec![0x30, 0x81, inner.len() as u8];
        outer.extend(inner);
        assert_eq!(
            authorize_admin_peer(&leaf_with(vec![], None, vec![raw_san(outer)]), &vali_only())
                .unwrap_err(),
            PeerRefusal::SanMalformed
        );
    }

    #[test]
    fn a_second_spelling_of_the_san_oid_refuses_the_leaf() {
        // Carry a DNS SAN under OID 2.5.29.2193 (content `55 1d 91 11`),
        // then rewrite it in place to `55 1d 80 11` — a non-minimal
        // spelling of 2.5.29.17 (SAN), same length. The signature no
        // longer verifies, which does not matter here: the gate runs on
        // a leaf rustls has already verified.
        let dns_san = tlv(0x30, &tlv(0x82, b"evil.hippius.svc"));
        let extra = rcgen::CustomExtension::from_oid_content(&[2, 5, 29, 2193], dns_san);
        let mut leaf = leaf_with(vec![uri(VALI)], None, vec![extra]);
        // Unaliased, the extra extension is some other extension and the
        // leaf is vali's.
        assert!(authorize_admin_peer(&leaf, &vali_only()).is_ok());
        let at = leaf
            .windows(5)
            .position(|w| w == [0x06, 0x04, 0x55, 0x1d, 0x91])
            .unwrap();
        leaf[at + 4] = 0x80;
        leaf[at + 5] = 0x11;
        assert_eq!(
            authorize_admin_peer(&leaf, &vali_only()).unwrap_err(),
            PeerRefusal::NonCanonicalOid
        );
    }

    #[test]
    fn oid_canonicity_follows_x690() {
        assert!(oid_is_canonical(&[0x55, 0x1d, 0x11]));
        assert!(oid_is_canonical(&[0x55, 0x1d, 0x91, 0x11]));
        assert!(!oid_is_canonical(&[0x55, 0x1d, 0x80, 0x11]));
        assert!(!oid_is_canonical(&[0x80, 0x55]));
        assert!(!oid_is_canonical(&[0x55, 0x9d]));
        assert!(!oid_is_canonical(&[]));
    }

    #[test]
    fn canonical_tlv_uses_the_minimal_length_form() {
        let data = vec![b'a'; 200];
        let mut good = vec![0x86, 0x81, 200];
        good.extend_from_slice(&data);
        assert!(is_canonical_tlv(&good, 0x86, &data));
        let mut padded = vec![0x86, 0x82, 0x00, 200];
        padded.extend_from_slice(&data);
        assert!(!is_canonical_tlv(&padded, 0x86, &data));
        assert!(is_canonical_tlv(&[0x86, 0x01, b'a'], 0x86, b"a"));
        assert!(!is_canonical_tlv(&[0xa6, 0x01, b'a'], 0x86, b"a"));
    }

    #[test]
    fn every_other_general_name_type_refuses_the_leaf() {
        // x400Address [3], directoryName [4], ediPartyName [5] (all
        // constructed), registeredID [8] (primitive) — each beside a
        // valid, listed URI.
        for (label, other) in [
            ("x400Address", tlv(0xa3, &tlv(0x30, &[]))),
            ("directoryName", tlv(0xa4, &tlv(0x30, &[]))),
            ("ediPartyName", tlv(0xa5, &tlv(0xa1, &tlv(0x0c, b"x")))),
            ("registeredID", tlv(0x88, &[0x2a, 0x03])),
        ] {
            assert_eq!(
                refusal_of(&[tlv(0x86, VALI.as_bytes()), other]),
                PeerRefusal::NonUriSan,
                "{label}"
            );
        }
    }

    #[test]
    fn a_uri_that_only_resembles_a_listed_one_is_not_it() {
        // Non-ASCII, an embedded NUL, a trailing NUL: never equal to a
        // listed (canonical, ASCII) SPIFFE ID.
        let mut nul_inside = b"spiffe://hippius.network/va".to_vec();
        nul_inside.extend_from_slice(b"\0li");
        let mut nul_after = VALI.as_bytes().to_vec();
        nul_after.push(0);
        let cyrillic_a = "spiffe://hippius.network/v\u{0430}li".as_bytes().to_vec();
        for bytes in [cyrillic_a, nul_inside, nul_after] {
            assert_eq!(
                refusal_of(&[tlv(0x86, &bytes)]),
                PeerRefusal::NotAllowed,
                "{bytes:02x?}"
            );
        }
    }

    #[test]
    fn an_unparseable_leaf_is_refused() {
        assert_eq!(
            authorize_admin_peer(b"not-a-cert", &vali_only()).unwrap_err(),
            PeerRefusal::LeafUnparseable
        );
    }

    #[test]
    fn peer_cert_info_cannot_be_empty() {
        assert!(PeerCertInfo::new(vec![], "01".into()).is_none());
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
