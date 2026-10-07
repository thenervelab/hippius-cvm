//! Node configuration.
//!
//! Two inputs, both fail closed:
//!
//! - the **agent config** (`/etc/hippius/cdn-agent.toml`), baked into the
//!   measured `cdn-node` image, so every value in it is covered by the
//!   SNP measurement;
//! - the **node identity file**, written from the KBS-released user-data
//!   (`{node_id, vm_id, region, backend_url}`). It carries identity only,
//!   never software or keys.
//!
//! Unknown keys, relative paths, a non-`https` backend, out-of-range
//! timers and a disagreement between the baked backend URL and the
//! identity file's are all refused at start: the agent exits rather than
//! run on a config it does not fully understand.

use std::fs;
use std::path::{Path, PathBuf};

use reqwest::Url;
use serde::Deserialize;

use crate::error::{CdnError, Result};

/// Default agent config path (baked).
pub const DEFAULT_CONFIG_PATH: &str = "/etc/hippius/cdn-agent.toml";

/// Upper bound on either config file. Both are a few hundred bytes.
const MAX_CONFIG_LEN: u64 = 64 * 1024;

/// Compression codecs the data plane may be told to use.
///
/// Brotli is the hook for a later OpenResty build with `ngx_brotli`: the
/// variant exists on the wire to OpenResty, but the beta image is
/// gzip-only, so config validation refuses it until that build lands.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, serde::Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Compression {
    Gzip,
    Brotli,
}

/// Whether this build's data plane ships the Brotli module. Flip with
/// the OpenResty build that adds `ngx_brotli`.
pub const BROTLI_AVAILABLE: bool = false;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawConfig {
    #[serde(default)]
    backend: RawBackend,
    #[serde(default)]
    identity: RawIdentity,
    #[serde(default)]
    paths: RawPaths,
    #[serde(default)]
    data_plane: RawDataPlane,
    #[serde(default)]
    timing: RawTiming,
    #[serde(default)]
    acme: RawAcme,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawAcme {
    enabled: Option<bool>,
    directory: Option<String>,
    fallback_directory: Option<String>,
    contact: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawBackend {
    url: Option<String>,
    ca_bundle: Option<PathBuf>,
    request_signatures: Option<bool>,
    request_timeout_s: Option<u64>,
    feed_poll_s: Option<u64>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawIdentity {
    node_file: Option<PathBuf>,
    lifecycle_key: Option<PathBuf>,
    fleet_key_dir: Option<PathBuf>,
    trust_domain: Option<String>,
    fleet_wildcard_hostname: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawPaths {
    state_dir: Option<PathBuf>,
    data_mount: Option<PathBuf>,
    cache_dir: Option<PathBuf>,
    control_socket: Option<PathBuf>,
    control_socket_uid: Option<u32>,
    metering_socket: Option<PathBuf>,
    geoip_version_file: Option<PathBuf>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawDataPlane {
    compression: Option<Vec<Compression>>,
    cache_fill_percent: Option<u8>,
    attestation: Option<bool>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawTiming {
    usage_interval_s: Option<u64>,
    persist_interval_s: Option<u64>,
    health_interval_s: Option<u64>,
    feed_stale_after_s: Option<u64>,
    lkg_max_age_s: Option<u64>,
    resync_interval_s: Option<u64>,
}

/// The user-data identity file. Field set is closed.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawNodeIdentity {
    node_id: String,
    #[serde(default)]
    vm_id: Option<String>,
    region: String,
    #[serde(default)]
    backend_url: Option<String>,
    /// The fallback CA's external account binding (secret, so it comes
    /// with the KBS-released identity, never with the image).
    #[serde(default)]
    acme_eab: Option<RawEab>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawEab {
    kid: String,
    #[serde(deserialize_with = "zeroizing_string")]
    hmac_b64u: zeroize::Zeroizing<String>,
}

/// A secret string, wiped on drop (the `String` is moved, not copied).
fn zeroizing_string<'de, D: serde::Deserializer<'de>>(
    d: D,
) -> std::result::Result<zeroize::Zeroizing<String>, D::Error> {
    String::deserialize(d).map(zeroize::Zeroizing::new)
}

impl std::fmt::Debug for RawEab {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "RawEab {{ kid: {:?}, hmac: <redacted> }}", self.kid)
    }
}

/// The `host` line of a request signature (§C.0): the host, plus the port
/// only when it is not the scheme's default.
pub fn signed_host(url: &Url) -> String {
    let host = url.host_str().unwrap_or_default();
    match url.port() {
        Some(port) => format!("{host}:{port}"),
        None => host.to_string(),
    }
}

/// A validated backend base URL: `https`, a host, no userinfo, no query
/// or fragment. Tests may build a loopback `http` URL; production code
/// cannot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackendUrl(Url);

impl BackendUrl {
    /// Parse and validate a production backend URL.
    pub fn parse(s: &str) -> Result<Self> {
        let url = Url::parse(s).map_err(|_| CdnError::Config("backend-url-invalid"))?;
        if url.scheme() != "https" {
            return Err(CdnError::Config("backend-url-not-https"));
        }
        Self::check_shape(url)
    }

    /// A plaintext loopback URL for the mock-backend tests.
    #[cfg(test)]
    pub fn loopback_for_tests(addr: std::net::SocketAddr) -> Self {
        Self(Url::parse(&format!("http://{addr}/")).unwrap_or_else(|_| unreachable!()))
    }

    fn check_shape(url: Url) -> Result<Self> {
        if url.host_str().is_none_or(str::is_empty) {
            return Err(CdnError::Config("backend-url-no-host"));
        }
        if !url.username().is_empty() || url.password().is_some() {
            return Err(CdnError::Config("backend-url-userinfo"));
        }
        if url.query().is_some() || url.fragment().is_some() {
            return Err(CdnError::Config("backend-url-query"));
        }
        Ok(Self(url))
    }

    /// Join an absolute API path (`/api/cdn/...`) onto the base.
    pub fn join(&self, path: &str) -> Result<Url> {
        let base = self.0.path().trim_end_matches('/');
        let mut url = self.0.clone();
        url.set_path(&format!("{base}{path}"));
        Ok(url)
    }

    /// The `host` line of a request signature (§C.0) for this backend.
    pub fn signed_host(&self) -> String {
        signed_host(&self.0)
    }

    /// The scheme + host + port, used to compare two configured URLs.
    fn origin(&self) -> String {
        self.0.origin().ascii_serialization()
    }

    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

/// This node, as vali registered it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeIdentity {
    pub node_id: String,
    pub vm_id: String,
    /// Two-letter region code (`FR`, `AU`, ...).
    pub region: String,
}

/// Backend settings.
#[derive(Debug, Clone)]
pub struct BackendConfig {
    pub url: BackendUrl,
    /// PEM bundle that REPLACES the built-in web roots when set.
    pub ca_bundle: Option<PathBuf>,
    /// Sign every session request with the node key (§C.0). Harmless
    /// before the backend enforces it; there is no mTLS.
    pub request_signatures: bool,
    pub request_timeout_s: u64,
    /// Long-poll window the backend may hold a feed request open.
    pub feed_poll_s: u64,
}

/// Where the key material and the user-data identity come from.
#[derive(Debug, Clone)]
pub struct IdentityConfig {
    pub node_file: PathBuf,
    pub lifecycle_key: PathBuf,
    pub fleet_key_dir: PathBuf,
    /// SPIFFE trust domain of the node certificate SAN URI.
    pub trust_domain: String,
    /// The fleet wildcard (default certificate, health check SNI).
    pub fleet_wildcard_hostname: String,
}

/// Local paths.
#[derive(Debug, Clone)]
pub struct PathsConfig {
    pub state_dir: PathBuf,
    /// The guest-keyed data volume mount point.
    pub data_mount: PathBuf,
    pub cache_dir: PathBuf,
    pub control_socket: PathBuf,
    /// When set, the agent pushes secrets only to a control socket owned
    /// by this uid (the OpenResty user), never to one someone else bound.
    pub control_socket_uid: Option<u32>,
    /// Must sit in a directory only the agent can write (not the
    /// control socket's directory, which OpenResty writes).
    pub metering_socket: PathBuf,
    pub geoip_version_file: Option<PathBuf>,
}

/// What the agent tells OpenResty about the data plane.
#[derive(Debug, Clone)]
pub struct DataPlaneConfig {
    pub compression: Vec<Compression>,
    pub cache_fill_percent: u8,
    pub attestation: bool,
}

/// Loop timers, all in seconds.
#[derive(Debug, Clone)]
pub struct TimingConfig {
    pub usage_interval_s: u64,
    pub persist_interval_s: u64,
    pub health_interval_s: u64,
    pub feed_stale_after_s: u64,
    pub lkg_max_age_s: u64,
    pub resync_interval_s: u64,
}

/// Let's Encrypt, the primary CA (spec §8.4).
pub const LETS_ENCRYPT_DIRECTORY: &str = "https://acme-v02.api.letsencrypt.org/directory";
/// Google Trust Services, the fallback CA; it needs an external account
/// binding.
pub const GTS_DIRECTORY: &str = "https://dv.acme-v02.api.pki.goog/directory";

/// ACME issuance (I4).
#[derive(Debug, Clone)]
pub struct AcmeConfig {
    pub enabled: bool,
    pub directory: String,
    /// Used only with an external account binding.
    pub fallback_directory: String,
    /// `mailto:` contact for the account.
    pub contact: Option<String>,
    pub fallback_eab: Option<crate::acme::Eab>,
}

/// The fully validated agent configuration.
#[derive(Debug, Clone)]
pub struct Config {
    pub node: NodeIdentity,
    pub backend: BackendConfig,
    pub identity: IdentityConfig,
    pub paths: PathsConfig,
    pub data_plane: DataPlaneConfig,
    pub timing: TimingConfig,
    pub acme: AcmeConfig,
}

impl Config {
    /// Load the baked config at `path`, then the identity file it names.
    pub fn load(path: &Path) -> Result<Self> {
        let raw = read_bounded(path, "config-read-failed")?;
        let text = std::str::from_utf8(&raw).map_err(|_| CdnError::Config("config-not-utf8"))?;
        let cfg: RawConfig = toml::from_str(text).map_err(|_| CdnError::Config("config-parse"))?;
        let node_file = abs_path(
            cfg.identity.node_file.clone(),
            "/run/hippius/cdn-node.json",
            "identity-node-file-relative",
        )?;
        // The identity may carry a secret (the CA binding): wiped on drop.
        let node_raw = zeroize::Zeroizing::new(read_bounded(&node_file, "node-file-read-failed")?);
        Self::from_parts(cfg, &node_raw, node_file)
    }

    /// Parse both documents from strings (tests, `check-config`).
    pub fn from_strs(config_toml: &str, node_json: &str) -> Result<Self> {
        let cfg: RawConfig =
            toml::from_str(config_toml).map_err(|_| CdnError::Config("config-parse"))?;
        let node_file = abs_path(
            cfg.identity.node_file.clone(),
            "/run/hippius/cdn-node.json",
            "identity-node-file-relative",
        )?;
        Self::from_parts(cfg, node_json.as_bytes(), node_file)
    }

    fn from_parts(cfg: RawConfig, node_raw: &[u8], node_file: PathBuf) -> Result<Self> {
        let node_doc: RawNodeIdentity =
            serde_json::from_slice(node_raw).map_err(|_| CdnError::Config("node-file-parse"))?;
        let node = validate_node(&node_doc)?;
        let backend = resolve_backend(&cfg.backend, node_doc.backend_url.as_deref())?;
        let identity = resolve_identity(&cfg.identity, node_file)?;
        let paths = resolve_paths(&cfg.paths)?;
        let data_plane = resolve_data_plane(&cfg.data_plane)?;
        let timing = resolve_timing(&cfg.timing)?;
        let acme = resolve_acme(&cfg.acme, node_doc.acme_eab.as_ref())?;
        if timing.feed_stale_after_s > timing.lkg_max_age_s {
            return Err(CdnError::Config("timing-stale-exceeds-lkg"));
        }
        // With attestation on, the node vouches for the TLS key it serves;
        // its secrets must only reach the OpenResty that serves it.
        if data_plane.attestation && paths.control_socket_uid.is_none() {
            return Err(CdnError::Config("control-socket-uid-required"));
        }
        Ok(Self {
            node,
            backend,
            identity,
            paths,
            data_plane,
            timing,
            acme,
        })
    }
}

fn read_bounded(path: &Path, class: &'static str) -> Result<Vec<u8>> {
    let meta = fs::metadata(path).map_err(|_| CdnError::Config(class))?;
    if meta.len() > MAX_CONFIG_LEN {
        return Err(CdnError::Config("config-too-large"));
    }
    fs::read(path).map_err(|_| CdnError::Config(class))
}

fn validate_node(doc: &RawNodeIdentity) -> Result<NodeIdentity> {
    if !is_valid_id(&doc.node_id) {
        return Err(CdnError::Config("node-id-invalid"));
    }
    let vm_id = doc.vm_id.clone().unwrap_or_else(|| doc.node_id.clone());
    if !is_valid_id(&vm_id) {
        return Err(CdnError::Config("vm-id-invalid"));
    }
    if !is_valid_region(&doc.region) {
        return Err(CdnError::Config("region-invalid"));
    }
    Ok(NodeIdentity {
        node_id: doc.node_id.clone(),
        vm_id,
        region: doc.region.clone(),
    })
}

/// vali VM and node ids: `[A-Za-z0-9._-]`, 1-128 bytes, no leading dot
/// (they end up in file names and SAN URIs).
pub fn is_valid_id(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 128
        && !s.starts_with('.')
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
}

/// A two-letter upper-case region code.
pub fn is_valid_region(s: &str) -> bool {
    s.len() == 2 && s.bytes().all(|b| b.is_ascii_uppercase())
}

fn resolve_backend(raw: &RawBackend, from_identity: Option<&str>) -> Result<BackendConfig> {
    let baked = raw.url.as_deref().map(BackendUrl::parse).transpose()?;
    let given = from_identity.map(BackendUrl::parse).transpose()?;
    let url = match (baked, given) {
        (Some(b), Some(g)) if b.origin() != g.origin() => {
            return Err(CdnError::Config("backend-url-mismatch"));
        }
        (Some(b), _) => b,
        (None, Some(g)) => g,
        (None, None) => return Err(CdnError::Config("backend-url-missing")),
    };
    let ca_bundle = raw
        .ca_bundle
        .clone()
        .map(|p| require_abs(p, "backend-ca-bundle-relative"))
        .transpose()?;
    Ok(BackendConfig {
        url,
        ca_bundle,
        request_signatures: raw.request_signatures.unwrap_or(true),
        request_timeout_s: bounded(raw.request_timeout_s, 15, 1, 120, "request-timeout")?,
        feed_poll_s: bounded(raw.feed_poll_s, 25, 1, 60, "feed-poll")?,
    })
}

fn resolve_identity(raw: &RawIdentity, node_file: PathBuf) -> Result<IdentityConfig> {
    let trust_domain = raw
        .trust_domain
        .clone()
        .unwrap_or_else(|| "hippius.network".to_string());
    if !crate::hostname::is_valid_hostname(&trust_domain) || trust_domain.starts_with("*.") {
        return Err(CdnError::Config("trust-domain-invalid"));
    }
    let fleet_wildcard_hostname = raw
        .fleet_wildcard_hostname
        .clone()
        .unwrap_or_else(|| "*.cdn.hippius.com".to_string());
    if !crate::hostname::is_valid_hostname(&fleet_wildcard_hostname) {
        return Err(CdnError::Config("fleet-wildcard-invalid"));
    }
    Ok(IdentityConfig {
        node_file,
        lifecycle_key: abs_path(
            raw.lifecycle_key.clone(),
            "/run/credentials/hippius-cdn-agent.service/lifecycle.key",
            "lifecycle-key-relative",
        )?,
        fleet_key_dir: abs_path(
            raw.fleet_key_dir.clone(),
            "/run/credentials/hippius-cdn-agent.service",
            "fleet-key-dir-relative",
        )?,
        trust_domain,
        fleet_wildcard_hostname,
    })
}

fn resolve_paths(raw: &RawPaths) -> Result<PathsConfig> {
    Ok(PathsConfig {
        state_dir: abs_path(
            raw.state_dir.clone(),
            "/var/lib/hippius-data/cdn",
            "state-dir-relative",
        )?,
        data_mount: abs_path(
            raw.data_mount.clone(),
            "/var/lib/hippius-data",
            "data-mount-relative",
        )?,
        cache_dir: abs_path(
            raw.cache_dir.clone(),
            "/var/lib/hippius-data/cache",
            "cache-dir-relative",
        )?,
        control_socket: abs_path(
            raw.control_socket.clone(),
            "/run/cdn/ctl.sock",
            "control-socket-relative",
        )?,
        control_socket_uid: raw.control_socket_uid,
        metering_socket: abs_path(
            raw.metering_socket.clone(),
            "/run/cdn-agent/meter.sock",
            "metering-socket-relative",
        )?,
        geoip_version_file: raw
            .geoip_version_file
            .clone()
            .map(|p| require_abs(p, "geoip-version-file-relative"))
            .transpose()?,
    })
}

fn resolve_data_plane(raw: &RawDataPlane) -> Result<DataPlaneConfig> {
    let compression = raw
        .compression
        .clone()
        .unwrap_or_else(|| vec![Compression::Gzip]);
    if compression.contains(&Compression::Brotli) && !BROTLI_AVAILABLE {
        return Err(CdnError::Config("brotli-not-built"));
    }
    let mut dedup = compression.clone();
    dedup.dedup();
    if dedup.len() != compression.len() {
        return Err(CdnError::Config("compression-duplicate"));
    }
    let cache_fill_percent = raw.cache_fill_percent.unwrap_or(75);
    if !(10..=90).contains(&cache_fill_percent) {
        return Err(CdnError::Config("cache-fill-percent-range"));
    }
    Ok(DataPlaneConfig {
        compression,
        cache_fill_percent,
        attestation: raw.attestation.unwrap_or(true),
    })
}

fn resolve_acme(raw: &RawAcme, eab: Option<&RawEab>) -> Result<AcmeConfig> {
    let directory = acme_directory(raw.directory.as_deref(), LETS_ENCRYPT_DIRECTORY)?;
    let fallback_directory = acme_directory(raw.fallback_directory.as_deref(), GTS_DIRECTORY)?;
    let contact = match raw.contact.as_deref() {
        None => None,
        Some(c) => {
            let addr = c
                .strip_prefix("mailto:")
                .ok_or(CdnError::Config("acme-contact"))?;
            let ok = addr.len() <= 254
                && addr
                    .split_once('@')
                    .is_some_and(|(l, d)| !l.is_empty() && d.contains('.'))
                && addr.bytes().all(|b| b.is_ascii_graphic() && b != b',');
            if !ok {
                return Err(CdnError::Config("acme-contact"));
            }
            Some(c.to_string())
        }
    };
    let fallback_eab = match eab {
        None => None,
        Some(e) => {
            let kid_ok = !e.kid.is_empty()
                && e.kid.len() <= 256
                && e.kid.bytes().all(|b| b.is_ascii_graphic());
            let mac_ok = !e.hmac_b64u.is_empty()
                && e.hmac_b64u.len() <= 512
                && e.hmac_b64u
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'='));
            if !(kid_ok && mac_ok) {
                return Err(CdnError::Config("acme-eab"));
            }
            Some(crate::acme::Eab {
                kid: e.kid.clone(),
                hmac_b64u: e.hmac_b64u.clone(),
            })
        }
    };
    Ok(AcmeConfig {
        enabled: raw.enabled.unwrap_or(true),
        directory,
        fallback_directory,
        contact,
        fallback_eab,
    })
}

fn acme_directory(raw: Option<&str>, default: &str) -> Result<String> {
    let s = raw.unwrap_or(default);
    let url = Url::parse(s).map_err(|_| CdnError::Config("acme-directory"))?;
    if url.scheme() != "https" || url.host_str().is_none() {
        return Err(CdnError::Config("acme-directory"));
    }
    Ok(s.to_string())
}

fn resolve_timing(raw: &RawTiming) -> Result<TimingConfig> {
    Ok(TimingConfig {
        usage_interval_s: bounded(raw.usage_interval_s, 60, 10, 600, "usage-interval")?,
        persist_interval_s: bounded(raw.persist_interval_s, 10, 1, 60, "persist-interval")?,
        health_interval_s: bounded(raw.health_interval_s, 5, 1, 60, "health-interval")?,
        feed_stale_after_s: bounded(raw.feed_stale_after_s, 300, 30, 3_600, "feed-stale")?,
        lkg_max_age_s: bounded(raw.lkg_max_age_s, 86_400, 300, 7 * 86_400, "lkg-max-age")?,
        resync_interval_s: bounded(raw.resync_interval_s, 300, 30, 3_600, "resync-interval")?,
    })
}

fn bounded(v: Option<u64>, default: u64, min: u64, max: u64, class: &'static str) -> Result<u64> {
    let v = v.unwrap_or(default);
    if (min..=max).contains(&v) {
        Ok(v)
    } else {
        Err(CdnError::Config(class))
    }
}

fn abs_path(v: Option<PathBuf>, default: &str, class: &'static str) -> Result<PathBuf> {
    require_abs(v.unwrap_or_else(|| PathBuf::from(default)), class)
}

fn require_abs(p: PathBuf, class: &'static str) -> Result<PathBuf> {
    if p.is_absolute() && !p.components().any(|c| c == std::path::Component::ParentDir) {
        Ok(p)
    } else {
        Err(CdnError::Config(class))
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
pub(crate) mod tests {
    use super::*;

    const NODE: &str =
        r#"{"node_id":"cdn-fr-7k2m","region":"FR","backend_url":"https://api.example.test"}"#;

    /// The minimal valid baked config: attestation is on by default, so
    /// the control-socket owner is required.
    pub(crate) const UID: &str = "[paths]\ncontrol_socket_uid = 990\n";

    fn class(r: Result<Config>) -> &'static str {
        match r {
            Ok(_) => "ok",
            Err(e) => e.class(),
        }
    }

    #[test]
    fn acme_defaults_contact_and_binding() {
        let cfg = Config::from_strs(UID, NODE).unwrap();
        assert!(cfg.acme.enabled);
        assert_eq!(cfg.acme.directory, LETS_ENCRYPT_DIRECTORY);
        assert_eq!(cfg.acme.fallback_directory, GTS_DIRECTORY);
        assert!(cfg.acme.contact.is_none() && cfg.acme.fallback_eab.is_none());

        let toml = format!("{UID}[acme]\ncontact = \"mailto:ops@example.test\"\n");
        let node = r#"{"node_id":"cdn-fr-7k2m","region":"FR","backend_url":"https://api.example.test","acme_eab":{"kid":"k1","hmac_b64u":"c2VjcmV0X2tleV8xMjM0NTY3ODkw"}}"#;
        let cfg = Config::from_strs(&toml, node).unwrap();
        assert_eq!(cfg.acme.contact.as_deref(), Some("mailto:ops@example.test"));
        let eab = cfg.acme.fallback_eab.clone().unwrap();
        assert_eq!(eab.kid, "k1");
        assert!(
            !format!("{cfg:?}").contains("c2VjcmV0"),
            "the MAC key is never printed"
        );

        for bad in [
            "[acme]\ncontact = \"ops@example.test\"\n",
            "[acme]\ncontact = \"mailto:a,b@x.y\"\n",
            "[acme]\ndirectory = \"http://acme.example.test/dir\"\n",
            "[acme]\nunknown = 1\n",
        ] {
            assert!(
                Config::from_strs(&format!("{UID}{bad}"), NODE).is_err(),
                "{bad}"
            );
        }
        let bad_eab = r#"{"node_id":"n","region":"FR","backend_url":"https://api.example.test","acme_eab":{"kid":"k","hmac_b64u":"a b"}}"#;
        assert!(Config::from_strs(UID, bad_eab).is_err());
    }

    #[test]
    fn signed_host_omits_the_default_port() {
        let u = BackendUrl::parse("https://api.example.test/").unwrap();
        assert_eq!(u.signed_host(), "api.example.test");
        let u = BackendUrl::parse("https://API.example.test:443/base/").unwrap();
        assert_eq!(u.signed_host(), "api.example.test");
        let u = BackendUrl::parse("https://api.example.test:8443/").unwrap();
        assert_eq!(u.signed_host(), "api.example.test:8443");
    }

    #[test]
    fn minimal_config_takes_the_backend_from_the_identity_file() {
        let cfg = Config::from_strs(UID, NODE).unwrap();
        assert_eq!(cfg.node.vm_id, "cdn-fr-7k2m");
        assert_eq!(cfg.node.region, "FR");
        assert!(cfg.backend.request_signatures);
        assert_eq!(cfg.backend.url.as_str(), "https://api.example.test/");
        assert_eq!(cfg.data_plane.compression, vec![Compression::Gzip]);
        assert_eq!(cfg.timing.lkg_max_age_s, 86_400);
        assert_eq!(cfg.identity.fleet_wildcard_hostname, "*.cdn.hippius.com");
    }

    #[test]
    fn unknown_keys_are_refused() {
        assert_eq!(
            class(Config::from_strs("surprise = 1\n", NODE)),
            "config-parse"
        );
        assert_eq!(
            class(Config::from_strs("[backend]\nurl_typo = \"x\"\n", NODE)),
            "config-parse"
        );
        let node = r#"{"node_id":"a","region":"FR","backend_url":"https://x.test","extra":1}"#;
        assert_eq!(class(Config::from_strs("", node)), "node-file-parse");
    }

    #[test]
    fn backend_must_be_https_and_agree() {
        let node = r#"{"node_id":"a","region":"FR","backend_url":"http://x.test"}"#;
        assert_eq!(class(Config::from_strs("", node)), "backend-url-not-https");
        let cfg = "[backend]\nurl = \"https://other.test\"\n";
        assert_eq!(class(Config::from_strs(cfg, NODE)), "backend-url-mismatch");
        let node = r#"{"node_id":"a","region":"FR"}"#;
        assert_eq!(class(Config::from_strs("", node)), "backend-url-missing");
        let cfg = "[backend]\nurl = \"https://u:p@x.test\"\n";
        assert_eq!(class(Config::from_strs(cfg, node)), "backend-url-userinfo");
        let cfg = "[backend]\nurl = \"https://x.test/?a=b\"\n";
        assert_eq!(class(Config::from_strs(cfg, node)), "backend-url-query");
        let cfg = format!("[backend]\nurl = \"https://api.example.test/base\"\n{UID}");
        assert_eq!(class(Config::from_strs(&cfg, NODE)), "ok");
    }

    #[test]
    fn attestation_requires_the_control_socket_owner() {
        assert_eq!(
            class(Config::from_strs("", NODE)),
            "control-socket-uid-required"
        );
        let cfg = Config::from_strs(UID, NODE).unwrap();
        assert_eq!(cfg.paths.control_socket_uid, Some(990));
        let off = "[data_plane]\nattestation = false\n";
        assert_eq!(class(Config::from_strs(off, NODE)), "ok");
    }

    #[test]
    fn identity_fields_are_validated() {
        let bad_region = r#"{"node_id":"a","region":"fr","backend_url":"https://x.test"}"#;
        assert_eq!(class(Config::from_strs("", bad_region)), "region-invalid");
        let bad_id = r#"{"node_id":"../etc","region":"FR","backend_url":"https://x.test"}"#;
        assert_eq!(class(Config::from_strs("", bad_id)), "node-id-invalid");
    }

    #[test]
    fn paths_must_be_absolute_and_timers_bounded() {
        let cfg = "[paths]\nstate_dir = \"var/lib\"\n";
        assert_eq!(class(Config::from_strs(cfg, NODE)), "state-dir-relative");
        let cfg = "[paths]\nstate_dir = \"/var/lib/../etc\"\n";
        assert_eq!(class(Config::from_strs(cfg, NODE)), "state-dir-relative");
        let cfg = "[timing]\nusage_interval_s = 1\n";
        assert_eq!(class(Config::from_strs(cfg, NODE)), "usage-interval");
        let cfg = "[timing]\nfeed_stale_after_s = 3600\nlkg_max_age_s = 600\n";
        assert_eq!(
            class(Config::from_strs(cfg, NODE)),
            "timing-stale-exceeds-lkg"
        );
    }

    #[test]
    fn brotli_is_a_hook_refused_until_built() {
        let cfg = "[data_plane]\ncompression = [\"gzip\", \"brotli\"]\n";
        assert_eq!(class(Config::from_strs(cfg, NODE)), "brotli-not-built");
        let cfg = "[data_plane]\ncompression = [\"zstd\"]\n";
        assert_eq!(class(Config::from_strs(cfg, NODE)), "config-parse");
    }

    #[test]
    fn join_keeps_a_base_path() {
        let u = BackendUrl::parse("https://x.test/base/").unwrap();
        assert_eq!(
            u.join("/api/cdn/node/feed/").unwrap().as_str(),
            "https://x.test/base/api/cdn/node/feed/"
        );
    }
}
