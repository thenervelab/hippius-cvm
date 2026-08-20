//! Client half of the KBS **admin** listener's mTLS gate
//! (`binaries/kbs-server/src/admin_tls.rs`).
//!
//! ## What this closes
//!
//! The server side of the gate has existed since #894 and is
//! fail-closed by default (`require_mtls = true`), but nothing could
//! actually *talk* to it: this binary — the one vali shells out to for
//! every §24 `register-vm` — had four flags, no client identity, and no
//! notion of https at all. So the only deployable configuration was the
//! server's explicit `require_mtls = false` opt-out, i.e. the lifecycle
//! admin API served UNAUTHENTICATED with a CiliumNetworkPolicy label
//! match as its sole control. This module is the missing half.
//!
//! ## The gate, from the client side
//!
//! rustls, TLS 1.3 only, and BOTH directions authenticated:
//!
//! 1. **We authenticate the server** against an operator-pinned CA
//!    bundle — [`build_client_config`] installs those roots and ONLY
//!    those roots. The webpki/system trust store is never loaded, and
//!    `dangerous()` (custom verifier, hostname bypass) is never called,
//!    so a public-CA cert for the admin Service DNS — or any self-signed
//!    cert an in-cluster attacker generates — fails the handshake. That
//!    matters: without it a peer that could win the ClusterIP race would
//!    harvest a valid client certificate presentation.
//! 2. **The server authenticates us** — the client cert + key are
//!    installed with `with_client_auth_cert`, so the leaf is presented
//!    on demand; the KBS's `WebPkiClientVerifier` (no
//!    `allow_unauthenticated()`) refuses the connection otherwise, and
//!    the leaf's SAN URI becomes the `peer_san` of every admin audit row.
//!
//! ## Fail-closed vs. deployable
//!
//! [`AdminClientMode::decide`] is the whole policy, in one place, and it
//! is the MIRROR of the server's `AdminListenerMode::decide`:
//!
//! | URL scheme | material | outcome |
//! |---|---|---|
//! | `https` | complete | [`AdminClientMode::Mtls`] — pinned CA + client identity |
//! | `https` | absent / partial | [`DecideError::MaterialIncomplete`] — refuse to dial |
//! | `http`  | absent | [`AdminClientMode::Plaintext`] — pre-cutover only |
//! | `http`  | any present | [`DecideError::PlaintextWithMaterial`] — refuse to dial |
//!
//! Two refusals, both deliberate. `https` + missing material must NOT
//! degrade to "TLS with system roots and no client cert": that would
//! silently drop client authentication (the whole point) while still
//! *looking* encrypted in the URL. `http` + material present must NOT
//! quietly send admin traffic in the clear when the operator has plainly
//! provisioned certs and believes the hop is authenticated — the
//! mismatch is a config error, and an error at spawn time is cheaper
//! than a lifecycle mutation crossing the pod network unauthenticated.
//!
//! The `http` + absent arm is the single deployable escape hatch, and it
//! exists only so the fleet can be cut over in an order that never
//! strands vali (see `docs/operator/kbs-admin-mtls-cutover-runbook.md`).

use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::{ClientConfig, RootCertStore};
use std::path::{Path, PathBuf};
use std::sync::Arc;

/// Static-classifier errors — every variant's `Display` is a fixed
/// token, so a log line can never leak an operator path or key material
/// (§20). Mirrors `admin_tls::AdminTlsError` on the server.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum AdminClientTlsError {
    /// One of the three PEM files could not be read.
    #[error("admin-client-tls-read")]
    Read(&'static str),
    /// A PEM file was read but did not decode.
    #[error("admin-client-tls-parse")]
    Parse(&'static str),
    /// A PEM file decoded but held zero blocks of the required kind.
    #[error("admin-client-tls-empty")]
    Empty(&'static str),
    /// rustls refused to build the config (bad key type, key/cert
    /// mismatch).
    #[error("admin-client-tls-build")]
    Build,
}

/// Why [`AdminClientMode::decide`] refused. Static `Display` for the
/// same reason as [`AdminClientTlsError`].
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum DecideError {
    /// `https://` was requested without all three of cert/key/ca. Never
    /// degrade to system roots + anonymous client.
    #[error(
        "--kbs-url is https but --client-cert/--client-key/--ca-cert are not all set: refusing \
         to dial the admin API without a pinned server CA and a client identity"
    )]
    MaterialIncomplete,
    /// `http://` was requested with TLS material configured — the
    /// operator believes this hop is authenticated and it would not be.
    #[error(
        "--kbs-url is plaintext http but TLS material was supplied: refusing to send lifecycle \
         admin traffic in the clear (use an https:// URL, or unset the material)"
    )]
    PlaintextWithMaterial,
    /// Neither `http://` nor `https://`.
    #[error("--kbs-url must start with http:// or https://")]
    UnsupportedScheme,
}

/// The three operator-supplied PEM paths. All three are required
/// together: a client identity without a pinned server CA would let any
/// TLS peer that wins the ClusterIP race collect our presentation, and a
/// pinned CA without a client identity is TLS with no authentication —
/// exactly the hole this closes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdminClientTlsPaths {
    /// Client cert chain presented to the KBS (leaf first). Its SAN URI
    /// becomes the `peer_san` of every admin audit row.
    pub cert: PathBuf,
    /// Client private key (PKCS#8 / SEC1 PEM).
    pub key: PathBuf,
    /// **Pinned** CA bundle the KBS admin listener's server cert must
    /// chain to. Replaces — never extends — the system trust store.
    pub ca: PathBuf,
}

/// What the CLI should do with the connection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AdminClientMode {
    /// Dial https with mTLS from these paths.
    Mtls(AdminClientTlsPaths),
    /// Dial plain http — reachable ONLY with an `http://` URL and no
    /// material at all (the pre-cutover state).
    Plaintext,
}

impl AdminClientMode {
    /// The fail-closed decision. Pure — no I/O — so the policy is
    /// testable without a filesystem and cannot differ between what the
    /// startup log claims and what is actually dialled.
    pub fn decide(
        kbs_url: &str,
        cert: Option<&Path>,
        key: Option<&Path>,
        ca: Option<&Path>,
    ) -> Result<Self, DecideError> {
        let https = if kbs_url.starts_with("https://") {
            true
        } else if kbs_url.starts_with("http://") {
            false
        } else {
            return Err(DecideError::UnsupportedScheme);
        };
        match (https, cert, key, ca) {
            (true, Some(cert), Some(key), Some(ca)) => Ok(Self::Mtls(AdminClientTlsPaths {
                cert: cert.to_path_buf(),
                key: key.to_path_buf(),
                ca: ca.to_path_buf(),
            })),
            (true, _, _, _) => Err(DecideError::MaterialIncomplete),
            (false, None, None, None) => Ok(Self::Plaintext),
            (false, _, _, _) => Err(DecideError::PlaintextWithMaterial),
        }
    }
}

/// Build the rustls `ClientConfig` for the admin hop.
///
/// Three properties a reviewer should be able to check by eye:
///
/// 1. `with_root_certificates(roots)` is fed ONLY the operator's pinned
///    bundle — there is no `webpki_roots`, no `rustls-native-certs`, no
///    "extend the system store" call anywhere in this crate. Adding one
///    would have to be an explicit, diff-visible line.
/// 2. `dangerous()` is never called, so rustls' default server-cert
///    verifier (chain + validity + hostname) stands.
/// 3. TLS 1.3 is pinned at the config level rather than by relying on a
///    cargo feature being off — feature unification from a sibling crate
///    can turn `tls12` back on.
///
/// The crypto provider is passed explicitly (`ring`) instead of relying
/// on the process default, which would panic at runtime if two providers
/// were ever unified in.
pub fn build_client_config(
    paths: &AdminClientTlsPaths,
) -> Result<ClientConfig, AdminClientTlsError> {
    let roots = load_ca_roots(&paths.ca)?;
    let chain = load_cert_chain(&paths.cert)?;
    let key = load_key_pem(&paths.key)?;

    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut config = ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|_| AdminClientTlsError::Build)?
        .with_root_certificates(roots)
        .with_client_auth_cert(chain, key)
        .map_err(|_| AdminClientTlsError::Build)?;
    // The admin API is HTTP/1.1; the KBS listener advertises exactly
    // this. Offering it explicitly keeps the negotiation unambiguous.
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(config)
}

/// Load a PEM bundle of CA certs into a `RootCertStore` — the pinned
/// trust anchors for SERVER cert validation. An empty bundle is an
/// error: an empty store would reject every server, but failing here
/// names the real problem instead of surfacing as a mystery handshake
/// failure at 03:00.
fn load_ca_roots(path: &Path) -> Result<RootCertStore, AdminClientTlsError> {
    let raw = std::fs::read(path).map_err(|_| AdminClientTlsError::Read("ca"))?;
    let mut roots = RootCertStore::empty();
    for cert in parse_certs_pem(&raw, "ca")? {
        roots
            .add(cert)
            .map_err(|_| AdminClientTlsError::Parse("ca"))?;
    }
    if roots.is_empty() {
        return Err(AdminClientTlsError::Empty("ca"));
    }
    Ok(roots)
}

fn load_cert_chain(path: &Path) -> Result<Vec<CertificateDer<'static>>, AdminClientTlsError> {
    let raw = std::fs::read(path).map_err(|_| AdminClientTlsError::Read("cert"))?;
    let certs = parse_certs_pem(&raw, "cert")?;
    if certs.is_empty() {
        return Err(AdminClientTlsError::Empty("cert"));
    }
    Ok(certs)
}

/// Load the client private key. The returned `PrivateKeyDer` is moved
/// straight into rustls and never re-surfaced — no getter, no `Debug`
/// print, no diagnostic dump of these bytes anywhere in this crate.
fn load_key_pem(path: &Path) -> Result<PrivateKeyDer<'static>, AdminClientTlsError> {
    let raw = std::fs::read(path).map_err(|_| AdminClientTlsError::Read("key"))?;
    let mut cursor = std::io::Cursor::new(&raw[..]);
    match rustls_pemfile::private_key(&mut cursor) {
        Ok(Some(key)) => Ok(key),
        Ok(None) => Err(AdminClientTlsError::Empty("key")),
        Err(_) => Err(AdminClientTlsError::Parse("key")),
    }
}

fn parse_certs_pem(
    pem: &[u8],
    label: &'static str,
) -> Result<Vec<CertificateDer<'static>>, AdminClientTlsError> {
    let mut cursor = std::io::Cursor::new(pem);
    let mut out = Vec::new();
    for entry in rustls_pemfile::certs(&mut cursor) {
        out.push(entry.map_err(|_| AdminClientTlsError::Parse(label))?);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    const HTTPS: &str = "https://kbs-server-admin.kbs.svc.cluster.local:8001";
    const HTTP: &str = "http://kbs-server-admin.kbs.svc.cluster.local:8001";

    fn p(s: &str) -> PathBuf {
        PathBuf::from(s)
    }

    #[test]
    fn https_with_complete_material_is_mtls() {
        let mode =
            AdminClientMode::decide(HTTPS, Some(&p("/c")), Some(&p("/k")), Some(&p("/a"))).unwrap();
        assert_eq!(
            mode,
            AdminClientMode::Mtls(AdminClientTlsPaths {
                cert: p("/c"),
                key: p("/k"),
                ca: p("/a"),
            })
        );
    }

    #[test]
    fn https_without_material_refuses_rather_than_dialling_anonymously() {
        // THE fail-closed claim on this side: an https URL with no
        // client identity must NOT become "TLS with system roots and no
        // client cert". That connection looks encrypted, carries no
        // authentication, and the KBS would refuse it anyway — but only
        // if the KBS is the one we reached.
        assert_eq!(
            AdminClientMode::decide(HTTPS, None, None, None).unwrap_err(),
            DecideError::MaterialIncomplete
        );
    }

    #[test]
    fn https_with_partial_material_refuses() {
        // A client identity with no pinned CA, or a pinned CA with no
        // identity, are each half a gate. Neither may be treated as
        // "configured".
        for (c, k, a) in [
            (Some(p("/c")), Some(p("/k")), None),
            (Some(p("/c")), None, Some(p("/a"))),
            (None, Some(p("/k")), Some(p("/a"))),
            (Some(p("/c")), None, None),
            (None, None, Some(p("/a"))),
        ] {
            assert_eq!(
                AdminClientMode::decide(HTTPS, c.as_deref(), k.as_deref(), a.as_deref())
                    .unwrap_err(),
                DecideError::MaterialIncomplete,
                "partial material {c:?}/{k:?}/{a:?} must refuse"
            );
        }
    }

    #[test]
    fn http_without_material_is_the_pre_cutover_plaintext_path() {
        // The single deployable escape hatch, and it requires BOTH a
        // plaintext URL AND no material whatsoever.
        assert_eq!(
            AdminClientMode::decide(HTTP, None, None, None).unwrap(),
            AdminClientMode::Plaintext
        );
    }

    #[test]
    fn http_with_material_refuses_instead_of_silently_downgrading() {
        // The operator provisioned certs and believes this hop is
        // authenticated. Sending the lifecycle mutation in the clear
        // anyway is the worst of the four outcomes, because it is the
        // only one nobody notices.
        for (c, k, a) in [
            (Some(p("/c")), Some(p("/k")), Some(p("/a"))),
            (Some(p("/c")), None, None),
            (None, None, Some(p("/a"))),
        ] {
            assert_eq!(
                AdminClientMode::decide(HTTP, c.as_deref(), k.as_deref(), a.as_deref())
                    .unwrap_err(),
                DecideError::PlaintextWithMaterial,
            );
        }
    }

    #[test]
    fn a_non_http_scheme_is_refused() {
        for url in ["kbs-server-admin:8001", "file:///etc/passwd", "ftp://x"] {
            assert_eq!(
                AdminClientMode::decide(url, None, None, None).unwrap_err(),
                DecideError::UnsupportedScheme
            );
        }
    }

    #[test]
    fn build_client_config_fails_closed_on_unreadable_material() {
        // Present-but-broken material must NOT degrade to "no client
        // cert" or "system roots": the error propagates and the CLI
        // exits 64 without dialling.
        let err = build_client_config(&AdminClientTlsPaths {
            cert: p("/nonexistent/cert.pem"),
            key: p("/nonexistent/key.pem"),
            ca: p("/nonexistent/ca.pem"),
        })
        .unwrap_err();
        assert_eq!(err, AdminClientTlsError::Read("ca"));
    }

    #[test]
    fn build_client_config_rejects_an_empty_ca_bundle() {
        // An empty bundle would build a store that trusts nothing. That
        // *is* fail-closed, but it surfaces as an unattributable
        // handshake failure; name it here instead.
        let dir = tempfile::tempdir().unwrap();
        let ca = dir.path().join("ca.pem");
        std::fs::write(&ca, b"").unwrap();
        let cert = dir.path().join("cert.pem");
        std::fs::write(&cert, b"").unwrap();
        let key = dir.path().join("key.pem");
        std::fs::write(&key, b"").unwrap();
        assert_eq!(
            build_client_config(&AdminClientTlsPaths { cert, key, ca }).unwrap_err(),
            AdminClientTlsError::Empty("ca")
        );
    }

    #[test]
    fn tls_error_display_is_static() {
        // The log classifier contract: no variant may interpolate a
        // path, which would put operator filesystem layout in logs.
        assert_eq!(
            AdminClientTlsError::Read("cert").to_string(),
            "admin-client-tls-read"
        );
        assert_eq!(
            AdminClientTlsError::Parse("key").to_string(),
            "admin-client-tls-parse"
        );
        assert_eq!(
            AdminClientTlsError::Empty("ca").to_string(),
            "admin-client-tls-empty"
        );
        assert_eq!(
            AdminClientTlsError::Build.to_string(),
            "admin-client-tls-build"
        );
    }
}
