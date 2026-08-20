//! Operator configuration — `/etc/hippius-miner/config.toml`.
//!
//! Parsed from TOML with `deny_unknown_fields` (a typo in the config
//! is a hard error, never a silently-ignored key) and then validated:
//! a config that parses but is unusable fails closed at load time
//! rather than at first use.
//!
//! The config carries **no secrets**. The mTLS material it references
//! is delivered out-of-band by the operator (never via Vault — the
//! miner is untrusted); the identity key is self-generated. The config
//! holds only paths and endpoints.

use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};

use serde::Deserialize;

use crate::error::{MinerAgentError, Result};

/// Default heartbeat interval, seconds — used when `[heartbeat]` is
/// absent entirely.
const DEFAULT_HEARTBEAT_INTERVAL_SECS: u64 = 60;

/// Default bounded heartbeat queue depth — used when `[heartbeat]` is
/// absent entirely.
const DEFAULT_HEARTBEAT_MAX_PENDING: usize = 100;

/// The full miner-agent configuration.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub miner: MinerSection,
    pub edge: EdgeSection,
    pub identity: IdentitySection,
    pub image: ImageSection,
    pub orders: OrdersSection,
    pub host: HostSection,
    /// `[storage]` — per-VM disk locations. Optional: a config without
    /// the table keeps the historical `/var/lib/hippius-miner` defaults.
    #[serde(default)]
    pub storage: StorageSection,
    /// `[heartbeat]` — the §K periodic liveness heartbeat (PR-MA-6).
    /// Optional: a config without the table uses the built-in defaults.
    #[serde(default)]
    pub heartbeat: HeartbeatSection,
    /// `[kbs]` — the KBS-over-vsock proxy (the tenant guest relays its
    /// §21 release exchange through the agent instead of reaching the
    /// KBS over the network). Optional: absent ⇒ the proxy is off and
    /// guests must use a network `hippius.kbs_url=https://…` (legacy).
    #[serde(default)]
    pub kbs: Option<KbsSection>,
    /// `[lifecycle]` — the §24/§25 guest stopped-ack vali ingress the
    /// vsock proxy forwards `/v1/lifecycle/stopped` pushes to. Optional:
    /// absent ⇒ the stopped-ack path is REFUSED (`no-vali-backend`) and
    /// the migration/decommission times out vali-side (fail-closed). The
    /// stopped-ack rides the SAME vsock proxy port (`[kbs]`) the guest
    /// already uses for the KBS exchange.
    #[serde(default)]
    pub lifecycle: Option<LifecycleSection>,
    /// `[host_attestor]` — the diskless blackbox host-attestor Infra CVM
    /// (PR-7). Optional AND default-disabled: absent, or present with
    /// `enabled = false` (the default), means the miner-agent NEVER
    /// launches the host-attestor. Ships INERT — the auto-spawn trigger
    /// arrives in a later PR. When `enabled = true` the `serve` loop
    /// supervises the singleton attestor domain, booting the pinned
    /// blackbox UKI.
    #[serde(default)]
    pub host_attestor: Option<HostAttestorSection>,
}

/// `[host_attestor]` — the diskless blackbox host-attestor Infra CVM
/// (PR-7).
///
/// INERT by default: `enabled` defaults to `false`, so a config that
/// merely *carries* the table still launches nothing. Only an operator
/// who both writes the table AND sets `enabled = true` arms the
/// supervision loop. The `measurement_sha256` pin is asserted locally
/// against the recomputed launch digest before the attestor UKI boots —
/// a tampered local UKI is refused (fail-closed).
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostAttestorSection {
    /// Master switch. Default `false` (INERT). `true` arms the
    /// supervision loop in `serve`.
    #[serde(default)]
    pub enabled: bool,
    /// Pinned, SEV-SNP-capable OVMF firmware (the same file the tenant
    /// launch path measures against).
    pub ovmf_path: PathBuf,
    /// The blackbox UKI's guest kernel.
    pub kernel_path: PathBuf,
    /// The blackbox UKI's initrd — booted as the diskless root.
    pub initrd_path: PathBuf,
    /// The blackbox UKI's kernel command line (a measured launch input).
    pub cmdline: String,
    /// Lowercase-hex (96 chars) SEV-SNP launch digest the local
    /// `compute_launch_digest` MUST reproduce before the attestor boots.
    /// Operator / vali pinned from the CI-built blackbox measurement; a
    /// mismatch fails the launch closed.
    pub measurement_sha256: String,
}

/// `[kbs]` — host-side KBS endpoint the vsock proxy forwards to.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KbsSection {
    /// Base URL of the real KBS the agent forwards guest release POSTs
    /// to, e.g. `https://kbs.hippius.network`. The agent reaches this
    /// over ITS OWN network (the host's NetBird mesh) — the tenant
    /// guest never does. Only the §21 release paths are forwarded
    /// (`hippius_types::kbs_vsock::ALLOWED_PATHS`); the proxy is not a
    /// general SSRF carrier.
    pub endpoint: String,

    /// Optional PEM CA (or self-signed pinned leaf) to trust ON TOP of
    /// the webpki built-in roots when dialing `endpoint`. Mirrors
    /// `[lifecycle].ca_cert`: the KBS is an INTERNAL service reached only
    /// over the host's NetBird mesh, so it can serve a private-CA /
    /// pinned cert (dialed by its DNS/IP SAN) instead of depending on a
    /// public ACME cert + an external DNS zone. Absent ⇒ webpki roots
    /// only (public cert required).
    pub ca_cert: Option<PathBuf>,
}

/// `[lifecycle]` — host-side vali ingress the vsock proxy forwards the
/// §24/§25 guest stopped-ack push to.
///
/// The confidential guest has no IP route to vali (vali has no public
/// ingress; its ClusterIP is unreachable from the guest). So the guest
/// POSTs its signed `stopped{}` ack over the SAME host vsock proxy it
/// uses for the KBS exchange, and the agent forwards the OPAQUE bytes
/// here over ITS OWN network. The agent never decodes/forges the ack —
/// vali's verifier owns the signature/generation check (§5.6 opacity;
/// the split-brain fence stays vali-side).
///
/// ⚠️ The agent reaches this base URL over the host's network the same
/// way the KBS backend reaches the KBS. The operator MUST point it at a
/// vali ingress reachable FROM THE MINER HOST (a vali Ingress/LB on the
/// mesh, or an Edge route that lands the body in vali's
/// `/v1/lifecycle/stopped`). Only the lifecycle stopped-ack path is
/// forwarded here — not a general SSRF carrier.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LifecycleSection {
    /// Base URL of the vali lifecycle ingress, e.g.
    /// `https://vali.hippius.network`. The proxy appends the guest's
    /// `/v1/lifecycle/stopped?vm_id=…&generation=…` path verbatim.
    pub vali_url: String,
    /// OPTIONAL PEM CA bundle the forward client adds to its trust roots
    /// for `vali_url`. Set this when `vali_url` points at the Edge's
    /// stopped-ack relay (which serves the Edge's OWN server cert, issued
    /// by the private hippius-compute CA — NOT a public Let's Encrypt
    /// cert). The Edge cert carries the Edge LoadBalancer's mesh address
    /// as an `IP:` SAN, so `vali_url = https://<EDGE_LB_IP>:8446`
    /// validates against it with this CA added — no public DNS / public
    /// cert needed for the internal mesh hop.
    /// Absent ⇒ the client uses only the webpki
    /// built-in roots (for a publicly-trusted vali ingress).
    #[serde(default)]
    pub ca_cert: Option<PathBuf>,
}

/// `[miner]` — this miner's stable operator-assigned id.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MinerSection {
    /// Operator-assigned miner identifier, e.g. `miner-a`.
    pub miner_id: String,
}

/// `[edge]` — the Edge gateway endpoint + the mTLS material used to
/// reach it. The mTLS files are operator-provisioned out-of-band.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EdgeSection {
    /// Edge gateway URL, e.g. `https://edge.hippius.network:443`.
    pub endpoint: String,
    /// Miner mTLS client certificate (operator-delivered). **Optional**
    /// in the permissionless model: when omitted (the prod default),
    /// the agent mints a self-signed client cert from its node identity
    /// key at boot (`MinerIdentity::self_signed_client_pem`,
    /// docs/design/permissionless-miner-auth.md). Set both this and
    /// `client_key` only to pin an operator-issued cert (legacy CA
    /// bootstrap path).
    #[serde(default)]
    pub client_cert: Option<PathBuf>,
    /// Miner mTLS client private key (operator-delivered). Optional —
    /// see `client_cert`. Both must be set together or both omitted.
    #[serde(default)]
    pub client_key: Option<PathBuf>,
    /// CA certificate that signs the Edge server cert.
    pub ca_cert: PathBuf,
    /// The Edge gateway's order-signing Ed25519 **public** key, 64
    /// lowercase-hex characters (MA-5). Every lifecycle order the
    /// miner-agent acts on must `verify_strict` against this key — it
    /// is the one trust anchor for the orders HTTP server. Not a
    /// secret (a public key); operator-provisioned out-of-band like
    /// the mTLS material.
    pub order_signing_pubkey: String,
}

/// `[orders]` — the lifecycle-order HTTP server (MA-5).
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OrdersSection {
    /// Socket address the orders server binds. MUST be a NetBird mesh
    /// address (`100.64.0.0/10`) — `validate` rejects a public or
    /// wildcard bind so the order intake is never exposed off-mesh.
    pub bind_addr: String,
}

/// `[host]` — the CPU / memory budget the host allots to tenant CVMs.
///
/// Operator-declared, not auto-detected: the operator deliberately
/// **reserves** headroom for the host OS + the miner-agent itself, so
/// the budget is a policy decision, not the raw machine size. The
/// lifecycle refuses any launch that would overcommit it.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostSection {
    /// Total vCPUs allotted to tenant CVMs.
    pub cvm_cpu_budget: u32,
    /// Total MiB of RAM allotted to tenant CVMs.
    pub cvm_memory_mb_budget: u64,
    /// Total GiB of tenant DATA disk the host commits to (the operator's
    /// declared disk capacity). The scheduler uses it for placement and
    /// the miner reserves against it so concurrent launches can't
    /// over-commit. Optional — defaults to 0, which DISABLES the disk
    /// reservation (cpu/mem budgets still apply + the per-create statvfs
    /// backstop still rejects a genuinely full mount). Set it to the
    /// real free capacity of `[storage].data_disk_root`.
    #[serde(default)]
    pub cvm_disk_gb_budget: u64,
    /// When `true`, a graceful agent shutdown (SIGTERM — `systemctl
    /// restart`, an upgrade, a k8s stop) does **NOT** stop the running
    /// tenant CVMs: the qemu domains are libvirt-`define`d + live in
    /// libvirtd's own cgroup, so they keep running while the agent
    /// restarts. This makes an agent restart/upgrade transparent to
    /// tenants instead of tearing every VM down.
    ///
    /// Default `false` preserves the historical "stop every CVM on
    /// shutdown" behaviour. **Caveat until startup re-adoption ships:**
    /// after a restart the agent's in-memory handle map is empty, so a
    /// left-running CVM is UNTRACKED — its data-disk still counts
    /// against the host on disk but not in the cpu/mem budget, and a
    /// guest `reboot` won't get its OrderTicket re-pushed. Enable this
    /// on miners where surviving an agent restart matters more than
    /// that gap (the follow-up re-adopts running domains at startup).
    #[serde(default)]
    pub skip_shutdown_teardown: bool,
}

/// `[heartbeat]` — the §K periodic liveness heartbeat (PR-MA-6).
///
/// Every `interval_secs` the agent builds + signs a `MinerHeartbeat`
/// and queues it; a pusher drains the bounded queue to the Edge over
/// mTLS. The monotonic `sequence` counter is persisted to
/// `sequence_path` so it survives a restart (vali rejects a
/// non-monotone sequence as a replay).
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HeartbeatSection {
    /// Seconds between heartbeats. Default 60.
    #[serde(default = "default_heartbeat_interval_secs")]
    pub interval_secs: u64,
    /// Bounded heartbeat-queue depth. On overflow the OLDEST queued
    /// heartbeat is dropped (LRU) — the newest liveness signal is the
    /// one worth keeping. Default 100.
    #[serde(default = "default_heartbeat_max_pending")]
    pub max_pending: usize,
    /// File the monotonic `sequence` counter is persisted to. Defaults
    /// to a sibling of the identity key under `/var/lib/hippius-miner`.
    #[serde(default = "default_heartbeat_sequence_path")]
    pub sequence_path: PathBuf,
}

impl Default for HeartbeatSection {
    fn default() -> Self {
        Self {
            interval_secs: default_heartbeat_interval_secs(),
            max_pending: default_heartbeat_max_pending(),
            sequence_path: default_heartbeat_sequence_path(),
        }
    }
}

fn default_heartbeat_interval_secs() -> u64 {
    DEFAULT_HEARTBEAT_INTERVAL_SECS
}

fn default_heartbeat_max_pending() -> usize {
    DEFAULT_HEARTBEAT_MAX_PENDING
}

fn default_heartbeat_sequence_path() -> PathBuf {
    PathBuf::from("/var/lib/hippius-miner/heartbeat.seq")
}

/// `[identity]` — where the self-generated miner identity lives.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IdentitySection {
    /// Secret key file (`0400`).
    pub key_path: PathBuf,
    /// Public key sidecar (`0444`).
    pub pub_path: PathBuf,
}

/// `[image]` — UKI image fetch + cache settings.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ImageSection {
    /// Content-addressed local image cache directory.
    pub cache_dir: PathBuf,
    /// Directory verified images are installed into.
    pub staging_dir: PathBuf,
    /// Hippius S3 endpoint for UKI image fetch.
    pub s3_endpoint: String,
    /// Hippius S3 bucket holding the published UKIs.
    pub s3_bucket: String,
}

/// `[storage]` — where per-VM disks physically live on the host.
///
/// Historically every per-VM disk was hardcoded under
/// `/var/lib/hippius-miner` (the OS root). This section lets an operator
/// keep tenant DATA disks on dedicated storage (e.g. an NVMe RAID mount)
/// — off the OS root, away from OS/swap I/O — **without touching code**.
/// Optional: omit the `[storage]` table to keep the historical defaults.
///
/// Security is unchanged regardless of location: the `/data` disk is
/// fresh-`luksFormat`ed with a guest-held key inside the SNP boundary,
/// so the host only ever sees ciphertext wherever the image file sits.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StorageSection {
    /// Root dir for per-VM DATA disks — a `data/` subdir is appended, so
    /// the image lands at `<data_disk_root>/data/<vm_id>.img`. The data
    /// disk carries the heaviest tenant I/O (the first-boot dm-integrity
    /// wipe), so this is the one worth pointing at fast dedicated
    /// storage. Default `/var/lib/hippius-miner`.
    #[serde(default = "default_storage_root")]
    pub data_disk_root: PathBuf,
    /// Root dir for per-VM 1 MiB STATE disks (a `state/` subdir is
    /// appended → `<state_disk_root>/state/<vm_id>.raw`). Tiny; rarely
    /// worth moving. Default `/var/lib/hippius-miner`.
    #[serde(default = "default_storage_root")]
    pub state_disk_root: PathBuf,
}

impl Default for StorageSection {
    fn default() -> Self {
        Self {
            data_disk_root: default_storage_root(),
            state_disk_root: default_storage_root(),
        }
    }
}

fn default_storage_root() -> PathBuf {
    PathBuf::from("/var/lib/hippius-miner")
}

/// Convert a `toml` parse failure into a bare (line, column).
///
/// Deliberately drops the error's message and its rendered snippet: the
/// crate's Display quotes the offending source line, and this binary's
/// error type exists precisely so that no run-time content reaches a log.
/// A byte span resolved against the input gives an operator somewhere to
/// look while echoing none of what is there. A span the crate does not
/// supply degrades to `line 0 col 0` rather than inventing a location.
fn config_parse_at(text: &str, e: &toml::de::Error) -> MinerAgentError {
    let (line, col) = match e.span() {
        Some(span) => {
            let upto = &text[..span.start.min(text.len())];
            let line = upto.matches('\n').count() + 1;
            let col = upto
                .rsplit('\n')
                .next()
                .map_or(1, |l| l.chars().count() + 1);
            (line, col)
        }
        None => (0, 0),
    };
    MinerAgentError::ConfigParse { line, col }
}

impl Config {
    /// Read + parse + validate the config at `path`.
    pub fn load(path: &Path) -> Result<Self> {
        let text = std::fs::read_to_string(path).map_err(MinerAgentError::ConfigRead)?;
        let config: Config = toml::from_str(&text).map_err(|e| config_parse_at(&text, &e))?;
        config.validate()?;
        Ok(config)
    }

    /// Reject a parsed-but-unusable config. All sub-classifiers are
    /// compile-time constants — no field value is ever echoed.
    pub fn validate(&self) -> Result<()> {
        if self.miner.miner_id.trim().is_empty() {
            return Err(MinerAgentError::ConfigInvalid("miner_id-empty"));
        }

        require_https(&self.edge.endpoint, "edge.endpoint")?;
        // mTLS client material is optional: present together (legacy
        // operator-CA cert) or both absent (self-signed identity cert,
        // the permissionless default). Validate paths only when pinned.
        match (&self.edge.client_cert, &self.edge.client_key) {
            (Some(cert), Some(key)) => {
                require_absolute(cert, "edge.client_cert")?;
                require_absolute(key, "edge.client_key")?;
            }
            (None, None) => {}
            _ => return Err(MinerAgentError::ConfigInvalid("edge.client_cert-key-pair")),
        }
        require_absolute(&self.edge.ca_cert, "edge.ca_cert")?;
        require_hex64(&self.edge.order_signing_pubkey, "edge.order_signing_pubkey")?;

        require_absolute(&self.identity.key_path, "identity.key_path")?;
        require_absolute(&self.identity.pub_path, "identity.pub_path")?;

        require_absolute(&self.image.cache_dir, "image.cache_dir")?;
        require_absolute(&self.image.staging_dir, "image.staging_dir")?;

        require_absolute(&self.storage.data_disk_root, "storage.data_disk_root")?;
        require_absolute(&self.storage.state_disk_root, "storage.state_disk_root")?;
        require_https(&self.image.s3_endpoint, "image.s3_endpoint")?;
        if self.image.s3_bucket.trim().is_empty() {
            return Err(MinerAgentError::ConfigInvalid("s3_bucket-empty"));
        }

        // The orders server must bind the NetBird mesh, never a public
        // or wildcard address — the order intake is mesh-internal.
        require_netbird_addr(&self.orders.bind_addr, "orders.bind_addr")?;

        // The §K heartbeat — a zero interval / queue is unusable; the
        // sequence-counter file must be absolute (no stable cwd).
        if self.heartbeat.interval_secs == 0 {
            return Err(MinerAgentError::ConfigInvalid("heartbeat.interval_secs"));
        }
        if self.heartbeat.max_pending == 0 {
            return Err(MinerAgentError::ConfigInvalid("heartbeat.max_pending"));
        }
        require_absolute(&self.heartbeat.sequence_path, "heartbeat.sequence_path")?;

        // `[kbs]` / `[lifecycle]` are optional. When present, the vsock
        // proxy forwards over the host's network to these HTTPS bases —
        // require https so a typo'd plaintext base fails fast at load
        // rather than silently downgrading the §25 ack hop.
        if let Some(kbs) = &self.kbs {
            require_https(&kbs.endpoint, "kbs.endpoint")?;
            // An optional CA/pinned-cert PEM (for an internal-mesh KBS
            // serving a private-CA cert) must be an absolute path so the
            // daemon's cwd cannot shift which file is read — fail fast at
            // load, mirroring `[lifecycle].ca_cert` below.
            if let Some(ca) = &kbs.ca_cert {
                require_absolute(ca, "kbs.ca_cert")?;
            }
        }
        if let Some(lifecycle) = &self.lifecycle {
            require_https(&lifecycle.vali_url, "lifecycle.vali_url")?;
            // An optional CA bundle (for the Edge-relay's private-CA
            // cert) must be an absolute path so the daemon's cwd cannot
            // shift which file is read.
            if let Some(ca) = &lifecycle.ca_cert {
                require_absolute(ca, "lifecycle.ca_cert")?;
            }
        }
        // `[host_attestor]` is optional + default-disabled (INERT). When
        // present the boot inputs are validated fail-fast at load —
        // absolute measured-artifact paths, a non-empty cmdline, and a
        // 96-hex-char measurement pin — so a misconfigured attestor is
        // caught at load, not at first (later-PR) launch.
        if let Some(ha) = &self.host_attestor {
            require_absolute(&ha.ovmf_path, "host_attestor.ovmf_path")?;
            require_absolute(&ha.kernel_path, "host_attestor.kernel_path")?;
            require_absolute(&ha.initrd_path, "host_attestor.initrd_path")?;
            if ha.cmdline.trim().is_empty() {
                return Err(MinerAgentError::ConfigInvalid("host_attestor.cmdline"));
            }
            require_hex(
                &ha.measurement_sha256,
                96,
                "host_attestor.measurement_sha256",
            )?;
        }
        Ok(())
    }
}

/// Require a lowercase-hex string of exactly `len` characters. The
/// SEV-SNP launch digest is 48 bytes (96 hex chars); the on-the-wire
/// Ed25519 key is 32 bytes (64 hex chars) — see [`require_hex64`].
fn require_hex(raw: &str, len: usize, field: &'static str) -> Result<()> {
    let ok = raw.len() == len
        && raw
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b));
    if ok {
        Ok(())
    } else {
        Err(MinerAgentError::ConfigInvalid(field))
    }
}

/// Require a 64-character lowercase-hex string — the on-the-wire form
/// of an Ed25519 public key. Does NOT check the value is a valid curve
/// point; that is the `OrderVerifier`'s job at serve time. This is the
/// fail-fast format gate at config load.
fn require_hex64(raw: &str, field: &'static str) -> Result<()> {
    let ok = raw.len() == 64
        && raw
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b));
    if ok {
        Ok(())
    } else {
        Err(MinerAgentError::ConfigInvalid(field))
    }
}

/// Require a socket address inside the NetBird CGNAT range
/// (`100.64.0.0/10`, RFC 6598). This rejects a wildcard bind
/// (`0.0.0.0`), loopback, any public IP, and IPv6 — the orders HTTP
/// server is reachable only as a NetBird mesh peer, never off-mesh.
fn require_netbird_addr(raw: &str, field: &'static str) -> Result<()> {
    let addr: SocketAddr = raw
        .parse()
        .map_err(|_| MinerAgentError::ConfigInvalid(field))?;
    match addr.ip() {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            // 100.64.0.0/10 — the second octet runs 64..=127.
            if o[0] == 100 && (64..=127).contains(&o[1]) {
                Ok(())
            } else {
                Err(MinerAgentError::ConfigInvalid(field))
            }
        }
        IpAddr::V6(_) => Err(MinerAgentError::ConfigInvalid(field)),
    }
}

/// Require a URL that is non-empty and `https://` — the miner never
/// speaks plaintext HTTP to the control plane.
fn require_https(url: &str, field: &'static str) -> Result<()> {
    if url.trim().is_empty() {
        return Err(MinerAgentError::ConfigInvalid(field));
    }
    if !url.starts_with("https://") {
        return Err(MinerAgentError::ConfigInvalid(field));
    }
    Ok(())
}

/// Require a non-empty, absolute path — the miner-agent runs as a
/// systemd service with no stable working directory.
fn require_absolute(path: &Path, field: &'static str) -> Result<()> {
    if path.as_os_str().is_empty() || !path.is_absolute() {
        return Err(MinerAgentError::ConfigInvalid(field));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const VALID: &str = r#"
[miner]
miner_id = "miner-a"

[edge]
endpoint = "https://edge.hippius.network:443"
client_cert = "/var/lib/hippius-miner/edge-mtls.crt"
client_key = "/var/lib/hippius-miner/edge-mtls.key"
ca_cert = "/var/lib/hippius-miner/edge-ca.crt"
order_signing_pubkey = "1111111111111111111111111111111111111111111111111111111111111111"

[identity]
key_path = "/var/lib/hippius-miner/identity.key"
pub_path = "/var/lib/hippius-miner/identity.pub"

[image]
cache_dir = "/var/lib/hippius-miner/images"
staging_dir = "/var/lib/hippius-miner/staging"
s3_endpoint = "https://s3.hippius.com"
s3_bucket = "hippius-compute-images"

[orders]
bind_addr = "100.64.0.10:9700"

[host]
cvm_cpu_budget = 8
cvm_memory_mb_budget = 16384
"#;

    fn parse(s: &str) -> Result<Config> {
        let c: Config = toml::from_str(s).map_err(|e| config_parse_at(s, &e))?;
        c.validate()?;
        Ok(c)
    }

    #[test]
    fn storage_defaults_to_miner_root_when_absent() {
        // VALID carries no `[storage]` — `#[serde(default)]` fills it
        // with the historical `/var/lib/hippius-miner` root.
        let c = parse(VALID).unwrap();
        assert_eq!(
            c.storage.data_disk_root,
            PathBuf::from("/var/lib/hippius-miner")
        );
        assert_eq!(
            c.storage.state_disk_root,
            PathBuf::from("/var/lib/hippius-miner")
        );
    }

    #[test]
    fn skip_shutdown_teardown_defaults_false_and_parses_true() {
        // Omitted → false: the historical "stop every CVM on graceful
        // shutdown" behaviour is preserved unless the operator opts in.
        let c = parse(VALID).unwrap();
        assert!(!c.host.skip_shutdown_teardown);
        // Explicit true → the agent leaves tenant CVMs running across a
        // restart (they live in libvirtd's cgroup, not the agent's).
        let cfg = format!("{VALID}skip_shutdown_teardown = true\n");
        let c = parse(&cfg).unwrap();
        assert!(c.host.skip_shutdown_teardown);
    }

    #[test]
    fn storage_section_points_data_disks_at_a_dedicated_mount() {
        let cfg = format!(
            "{VALID}\n[storage]\n\
             data_disk_root = \"/mnt/hippius-data\"\n\
             state_disk_root = \"/var/lib/hippius-miner\"\n"
        );
        let c = parse(&cfg).unwrap();
        assert_eq!(c.storage.data_disk_root, PathBuf::from("/mnt/hippius-data"));
        assert_eq!(
            c.storage.state_disk_root,
            PathBuf::from("/var/lib/hippius-miner")
        );
    }

    #[test]
    fn storage_root_must_be_absolute() {
        let cfg = format!("{VALID}\n[storage]\ndata_disk_root = \"relative/data\"\n");
        assert!(
            parse(&cfg).is_err(),
            "relative storage root must be rejected"
        );
    }

    #[test]
    fn valid_config_parses_and_validates() {
        let c = parse(VALID).unwrap();
        assert_eq!(c.miner.miner_id, "miner-a");
        assert_eq!(c.image.s3_bucket, "hippius-compute-images");
        // The optional vsock-proxy sections default to absent.
        assert!(c.kbs.is_none());
        assert!(c.lifecycle.is_none());
    }

    #[test]
    fn kbs_and_lifecycle_sections_parse_and_carry_their_endpoints() {
        let cfg = format!(
            "{VALID}\n[kbs]\nendpoint = \"https://kbs.hippius.network\"\n\
             [lifecycle]\nvali_url = \"https://vali.hippius.network\"\n"
        );
        let c = parse(&cfg).unwrap();
        assert_eq!(
            c.kbs.as_ref().unwrap().endpoint,
            "https://kbs.hippius.network"
        );
        assert_eq!(
            c.lifecycle.as_ref().unwrap().vali_url,
            "https://vali.hippius.network"
        );
    }

    #[test]
    fn kbs_ca_cert_is_optional_and_parses() {
        // Absent ⇒ None (webpki-roots-only, the public-cert default).
        let without = format!("{VALID}\n[kbs]\nendpoint = \"https://kbs.hippius.network\"\n");
        assert_eq!(parse(&without).unwrap().kbs.unwrap().ca_cert, None);
        // Present ⇒ the PEM path the agent trusts on top of webpki (the
        // internal-mesh KBS may serve a private-CA / pinned cert).
        let with = format!(
            "{VALID}\n[kbs]\nendpoint = \"https://kbs.hippius.network\"\n\
             ca_cert = \"/var/lib/hippius-miner/mtls/kbs-ca.crt\"\n"
        );
        assert_eq!(
            parse(&with).unwrap().kbs.unwrap().ca_cert,
            Some(std::path::PathBuf::from(
                "/var/lib/hippius-miner/mtls/kbs-ca.crt"
            ))
        );
    }

    #[test]
    fn plaintext_lifecycle_vali_url_is_rejected() {
        // A typo'd plaintext vali reach must fail fast at load — the §25
        // ack hop must not silently downgrade.
        let bad = format!("{VALID}\n[lifecycle]\nvali_url = \"http://vali.hippius.network\"\n");
        assert!(matches!(
            parse(&bad),
            Err(MinerAgentError::ConfigInvalid("lifecycle.vali_url"))
        ));
    }

    #[test]
    fn unknown_key_is_rejected() {
        let bad = format!("{VALID}\n[extra]\nrogue = true\n");
        assert!(matches!(
            parse(&bad),
            Err(MinerAgentError::ConfigParse { .. })
        ));
    }

    #[test]
    fn the_shipped_example_config_is_structurally_complete() {
        // `examples/miner-agent-config.toml.example` is what a new miner
        // copies. It shipped MISSING two required things — `[orders]`
        // entirely, and `edge.order_signing_pubkey` — so anyone who
        // copied it got `config-parse` and, before the position was
        // added to that error, no way to find out why.
        //
        // The assertion is deliberately about the CLASS of failure, not
        // success: the file is full of `<PLACEHOLDER>` values, so it
        // cannot validate. What it must do is PARSE — every required
        // field present and correctly typed — and then fail on a named
        // field the operator has to fill. `ConfigParse` means the
        // example's structure is wrong, which is ours to fix, not theirs.
        let example = include_str!("../examples/miner-agent-config.toml.example");
        match parse(example) {
            Err(MinerAgentError::ConfigParse { line, col }) => panic!(
                "the shipped example does not parse — line {line} col {col}. \
                 A miner copying it cannot start the agent."
            ),
            Err(MinerAgentError::ConfigInvalid(field)) => {
                assert!(
                    field.contains('.'),
                    "expected a qualified field name, got {field}"
                );
            }
            Err(other) => panic!("unexpected error from the example: {other:?}"),
            Ok(_) => panic!(
                "the example validated — its placeholders must have been \
                 replaced with real-looking values, which is the trap this \
                 repository already fell into once"
            ),
        }
    }

    #[test]
    fn config_parse_reports_the_real_line_and_column() {
        // The point of the position is that it is CORRECT. A parse error
        // that always said "line 1" would satisfy a `matches!` check and
        // help nobody, so assert the coordinate against a fault we place
        // ourselves — and assert the message carries no source text,
        // which is the reason the classifier exists.
        let bad = "[miner]\nminer_id = \"m\"\nbroken = <NOT_TOML>\n";
        let err = parse(bad).expect_err("must reject");
        match err {
            MinerAgentError::ConfigParse { line, col } => {
                assert_eq!(line, 3, "the fault is on the third line");
                assert_eq!(col, 10, "column of the offending value");
                let shown = format!("{}", MinerAgentError::ConfigParse { line, col });
                assert!(!shown.contains("NOT_TOML"), "must not echo source: {shown}");
                assert!(!shown.contains("broken"), "must not echo source: {shown}");
            }
            other => panic!("expected ConfigParse, got {other:?}"),
        }
    }

    #[test]
    fn plaintext_edge_endpoint_is_rejected() {
        let bad = VALID.replace(
            "https://edge.hippius.network",
            "http://edge.hippius.network",
        );
        assert!(matches!(
            parse(&bad),
            Err(MinerAgentError::ConfigInvalid("edge.endpoint"))
        ));
    }

    #[test]
    fn relative_identity_path_is_rejected() {
        let bad = VALID.replace("/var/lib/hippius-miner/identity.key", "identity.key");
        assert!(matches!(
            parse(&bad),
            Err(MinerAgentError::ConfigInvalid("identity.key_path"))
        ));
    }

    #[test]
    fn empty_miner_id_is_rejected() {
        let bad = VALID.replace("miner-a", "");
        assert!(matches!(
            parse(&bad),
            Err(MinerAgentError::ConfigInvalid("miner_id-empty"))
        ));
    }

    #[test]
    fn missing_section_is_a_parse_error() {
        let bad = VALID.replace("[image]", "[unused]");
        assert!(parse(&bad).is_err());
    }

    #[test]
    fn valid_config_carries_the_orders_and_host_sections() {
        let c = parse(VALID).unwrap();
        assert_eq!(c.orders.bind_addr, "100.64.0.10:9700");
        assert_eq!(c.host.cvm_cpu_budget, 8);
        assert_eq!(c.host.cvm_memory_mb_budget, 16384);
        // Absent from VALID → defaults to 0 (disk reservation disabled).
        assert_eq!(c.host.cvm_disk_gb_budget, 0);
    }

    #[test]
    fn host_disk_budget_is_parsed_when_declared() {
        // An operator who declares the disk capacity gets it surfaced for
        // the lifecycle reservation + the scheduler's disk-aware placement.
        let with_disk = VALID.replace(
            "cvm_memory_mb_budget = 16384",
            "cvm_memory_mb_budget = 16384\ncvm_disk_gb_budget = 2048",
        );
        let c = parse(&with_disk).unwrap();
        assert_eq!(c.host.cvm_disk_gb_budget, 2048);
    }

    #[test]
    fn a_non_hex_order_pubkey_is_rejected() {
        let bad = VALID.replace(
            "1111111111111111111111111111111111111111111111111111111111111111",
            "not-a-key",
        );
        assert!(matches!(
            parse(&bad),
            Err(MinerAgentError::ConfigInvalid("edge.order_signing_pubkey"))
        ));
    }

    #[test]
    fn a_public_orders_bind_addr_is_rejected() {
        // A routable public address — must be refused; the orders
        // server is NetBird-mesh-internal only.
        let bad = VALID.replace("100.64.0.10:9700", "203.0.113.7:9700");
        assert!(matches!(
            parse(&bad),
            Err(MinerAgentError::ConfigInvalid("orders.bind_addr"))
        ));
    }

    #[test]
    fn a_wildcard_orders_bind_addr_is_rejected() {
        // `0.0.0.0` would expose the order intake on every interface.
        let bad = VALID.replace("100.64.0.10:9700", "0.0.0.0:9700");
        assert!(matches!(
            parse(&bad),
            Err(MinerAgentError::ConfigInvalid("orders.bind_addr"))
        ));
    }

    #[test]
    fn the_netbird_cgnat_range_is_accepted() {
        // Both ends of 100.64.0.0/10 must validate.
        for addr in ["100.64.0.1:9700", "100.127.255.254:9700"] {
            let ok = VALID.replace("100.64.0.10:9700", addr);
            assert!(parse(&ok).is_ok(), "expected {addr} to validate");
        }
    }

    #[test]
    fn an_absent_heartbeat_table_uses_defaults() {
        // `VALID` carries no `[heartbeat]` — the `#[serde(default)]`
        // path must yield the built-in defaults.
        let c = parse(VALID).unwrap();
        assert_eq!(c.heartbeat.interval_secs, 60);
        assert_eq!(c.heartbeat.max_pending, 100);
        assert_eq!(
            c.heartbeat.sequence_path,
            PathBuf::from("/var/lib/hippius-miner/heartbeat.seq")
        );
    }

    #[test]
    fn an_explicit_heartbeat_table_is_honoured() {
        let cfg = format!(
            "{VALID}\n[heartbeat]\ninterval_secs = 30\nmax_pending = 8\n\
             sequence_path = \"/var/lib/hippius-miner/hb.seq\"\n"
        );
        let c = parse(&cfg).unwrap();
        assert_eq!(c.heartbeat.interval_secs, 30);
        assert_eq!(c.heartbeat.max_pending, 8);
        assert_eq!(
            c.heartbeat.sequence_path,
            PathBuf::from("/var/lib/hippius-miner/hb.seq")
        );
    }

    #[test]
    fn a_zero_heartbeat_interval_is_rejected() {
        let cfg = format!("{VALID}\n[heartbeat]\ninterval_secs = 0\n");
        assert!(matches!(
            parse(&cfg),
            Err(MinerAgentError::ConfigInvalid("heartbeat.interval_secs"))
        ));
    }

    #[test]
    fn a_zero_heartbeat_max_pending_is_rejected() {
        let cfg = format!("{VALID}\n[heartbeat]\nmax_pending = 0\n");
        assert!(matches!(
            parse(&cfg),
            Err(MinerAgentError::ConfigInvalid("heartbeat.max_pending"))
        ));
    }

    #[test]
    fn a_relative_heartbeat_sequence_path_is_rejected() {
        let cfg = format!("{VALID}\n[heartbeat]\nsequence_path = \"hb.seq\"\n");
        assert!(matches!(
            parse(&cfg),
            Err(MinerAgentError::ConfigInvalid("heartbeat.sequence_path"))
        ));
    }

    // ── PR-7 `[host_attestor]` (INERT by default) ────────────────────

    const HA_TABLE: &str = "\n[host_attestor]\n\
        ovmf_path = \"/var/lib/hippius-miner/ovmf.fd\"\n\
        kernel_path = \"/var/lib/hippius-miner/attestor-vmlinuz\"\n\
        initrd_path = \"/var/lib/hippius-miner/attestor-initrd\"\n\
        cmdline = \"quiet panic=0 console=ttyS0\"\n\
        measurement_sha256 = \"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"\n";

    #[test]
    fn host_attestor_is_absent_by_default() {
        // The default deploy carries no `[host_attestor]` — the attestor
        // is never launched (INERT).
        let c = parse(VALID).unwrap();
        assert!(c.host_attestor.is_none());
    }

    #[test]
    fn host_attestor_parses_and_defaults_disabled() {
        // A present table with no `enabled` key defaults to `false` — the
        // supervisor is still not armed. Wiring ships INERT.
        let c = parse(&format!("{VALID}{HA_TABLE}")).unwrap();
        let ha = c.host_attestor.unwrap();
        assert!(!ha.enabled);
        assert_eq!(
            ha.kernel_path,
            PathBuf::from("/var/lib/hippius-miner/attestor-vmlinuz")
        );
        assert_eq!(ha.measurement_sha256.len(), 96);
    }

    #[test]
    fn host_attestor_enabled_is_honoured() {
        let c = parse(&format!("{VALID}{HA_TABLE}enabled = true\n")).unwrap();
        assert!(c.host_attestor.unwrap().enabled);
    }

    #[test]
    fn host_attestor_rejects_a_relative_kernel_path() {
        let bad = format!("{VALID}{HA_TABLE}").replace(
            "/var/lib/hippius-miner/attestor-vmlinuz",
            "attestor-vmlinuz",
        );
        assert!(matches!(
            parse(&bad),
            Err(MinerAgentError::ConfigInvalid("host_attestor.kernel_path"))
        ));
    }

    #[test]
    fn host_attestor_rejects_a_short_measurement_pin() {
        // A 48-byte launch digest is 96 hex chars — a 64-char value (an
        // Ed25519-key-length mistake) is refused.
        let bad = format!("{VALID}{HA_TABLE}").replace(
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        );
        assert!(matches!(
            parse(&bad),
            Err(MinerAgentError::ConfigInvalid(
                "host_attestor.measurement_sha256"
            ))
        ));
    }
}
