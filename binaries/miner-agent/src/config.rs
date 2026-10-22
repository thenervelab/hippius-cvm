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
    /// `[backup]` — live VM backup tuning. Optional: a config without
    /// the table uses the built-in defaults.
    #[serde(default)]
    pub backup: BackupSection,
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
    /// `[inventory]` — the §18.10 host-inventory poster: reads the
    /// collector's `<section>.json` files, signs and posts them to the
    /// Edge. Optional AND default-disabled: absent, or `enabled = false`,
    /// spawns nothing.
    #[serde(default)]
    pub inventory: InventorySection,
}

/// `[inventory]` — the §18.10 host-inventory poster
/// ([`crate::host_inventory::poster`]).
///
/// Ships disabled: vali and the Edge must accept the report first. The
/// state (`sequence`, the digests sent, the cadence clocks) lives at
/// `<storage.state_disk_root>/inventory-state.json`.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InventorySection {
    /// Master switch. Default `false`.
    #[serde(default)]
    pub enabled: bool,
    /// Where the collector leaves its sections. Default
    /// `/run/hippius-miner/inventory`.
    #[serde(default = "default_inventory_dir")]
    pub dir: PathBuf,
    /// A `full` report every this many seconds (plus jitter). Default
    /// 86400 (24 h).
    #[serde(default = "default_inventory_full_interval_secs")]
    pub full_interval_secs: u64,
    /// The `full` cadence's jitter, ± seconds. Default 3600; below
    /// `full_interval_secs`.
    #[serde(default = "default_inventory_full_jitter_secs")]
    pub full_jitter_secs: u64,
    /// A `counters` report every this many seconds. Default 21600 (6 h).
    #[serde(default = "default_inventory_counters_interval_secs")]
    pub counters_interval_secs: u64,
    /// The least gap between two reports of any kind (the `change`
    /// debounce). Default 300; never below 300, which keeps the agent
    /// within vali's 12 reports per hour.
    #[serde(default = "default_inventory_min_gap_secs")]
    pub min_gap_secs: u64,
    /// How often the sections are re-read. Default 60.
    #[serde(default = "default_inventory_poll_secs")]
    pub poll_secs: u64,
}

impl Default for InventorySection {
    fn default() -> Self {
        Self {
            enabled: false,
            dir: default_inventory_dir(),
            full_interval_secs: default_inventory_full_interval_secs(),
            full_jitter_secs: default_inventory_full_jitter_secs(),
            counters_interval_secs: default_inventory_counters_interval_secs(),
            min_gap_secs: default_inventory_min_gap_secs(),
            poll_secs: default_inventory_poll_secs(),
        }
    }
}

/// The floor of `[inventory] min_gap_secs`: vali takes at most 12 reports
/// per node and hour, counted at ARRIVAL. 300 s would leave no margin (a
/// slow post, up to its 15 s timeout, then fast ones can land a 13th in
/// vali's window), so the floor is 300 s plus a 20 s margin.
pub const INVENTORY_MIN_GAP_FLOOR_SECS: u64 = 320;

/// No `[inventory]` interval is above this (30 days).
pub const INVENTORY_MAX_INTERVAL_SECS: u64 = 30 * 24 * 3600;

fn default_inventory_dir() -> PathBuf {
    PathBuf::from(crate::host_inventory::INVENTORY_DIR)
}

fn default_inventory_full_interval_secs() -> u64 {
    24 * 3600
}

fn default_inventory_full_jitter_secs() -> u64 {
    3600
}

fn default_inventory_counters_interval_secs() -> u64 {
    6 * 3600
}

fn default_inventory_min_gap_secs() -> u64 {
    INVENTORY_MIN_GAP_FLOOR_SECS
}

fn default_inventory_poll_secs() -> u64 {
    60
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

    /// Relay the guest custody-lease paths
    /// (`hippius_types::kbs_vsock::CUSTODY_PATHS`) to the KBS. Default
    /// OFF: a custody request is then answered locally with `503
    /// custody-disabled` and never forwarded, which the guest daemon
    /// treats as "retry, change nothing". Turn it on only once the KBS
    /// serves the custody routes — until then a forward would only reach
    /// a 404. When on, custody requests are rate-limited per VM on top of
    /// the proxy's global connection cap (see `vsock::kbs_proxy`).
    #[serde(default)]
    pub custody_relay: bool,
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
    /// declared disk capacity). The miner reserves against it so
    /// concurrent launches can't over-commit, and declares it in the `v4`
    /// heartbeat (`[heartbeat] schema_disk`), where vali may only use it to
    /// LOWER its own disk ledger. Optional — defaults to 0, which DISABLES
    /// the budget reservation (cpu/mem budgets still apply, and the
    /// measured free-space gate still rejects a genuinely full mount). Set
    /// it to the capacity of `[storage].data_disk_root` the operator is
    /// prepared to sell, leaving headroom for staging and backups.
    #[serde(default)]
    pub cvm_disk_gb_budget: u64,
    /// When `true`, a graceful agent shutdown (SIGTERM — `systemctl
    /// restart`, an upgrade, a k8s stop) does **NOT** stop the running
    /// tenant CVMs: the qemu domains are libvirt-`define`d + live in
    /// libvirtd's own cgroup, so they keep running while the agent
    /// restarts. This makes an agent restart/upgrade transparent to
    /// tenants instead of tearing every VM down.
    ///
    /// Default `true`: an absent key leaves the CVMs running. The old
    /// `false` default destroyed every domain on the host (tenants +
    /// host-attestor) on a plain `systemctl stop` whenever a hand-written
    /// config lacked the key (2026-09-21). Startup re-adoption
    /// (`readopt_running`) restores tracking of the CVMs left running.
    /// An explicit `false` still opts in to the teardown; `serve` logs a
    /// WARNING at startup when it does.
    #[serde(default = "default_skip_shutdown_teardown")]
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
    /// Emit the `v3` heartbeat (capacity v2): the ordinary body plus the
    /// `[host]` CPU/memory budgets and the SEV-ES ASID pool, which vali
    /// uses as down-only clamps. Default `false` — the fleet keeps
    /// emitting `v1` until vali (whose verifier must accept `v3` FIRST)
    /// is live. The preflight ASID gate does NOT depend on this flag.
    #[serde(default)]
    pub schema_capacity: bool,
    /// Emit the `v4` heartbeat instead: the `v3` body plus the disk
    /// declarations (`[host] cvm_disk_gb_budget` and a `statvfs` of the
    /// data + staging filesystems), which vali uses as down-only clamps on
    /// its committed-disk ledger. Requires `schema_capacity` (`v4` is a
    /// superset of `v3`). Default `false`: vali's verifier must accept
    /// `v4` FIRST.
    #[serde(default)]
    pub schema_disk: bool,
    /// Emit the `v5` heartbeat instead: the `v4` body plus the SEV-SNP
    /// host-health report (`snp_enabled`, `cpus_offline`,
    /// `snp_launches_since_boot`, `df_flush_failures` — see
    /// [`crate::host_health`]), which vali only alerts on. Requires
    /// `schema_disk` (`v5` is a superset of `v4`). Default `false`: vali's
    /// verifier must accept `v5` FIRST.
    #[serde(default)]
    pub schema_host_health: bool,
    /// Emit the `v6` heartbeat instead: the `v5` body plus `agent_version`,
    /// this binary's release tag ([`crate::release::RELEASE_TAG`]), which
    /// vali only records. Requires `schema_host_health` (`v6` is a superset
    /// of `v5`). Default `false`: this is miner → vali data, so vali's
    /// verifier (the `ticket-validator` in the vali image) must accept `v6`
    /// FIRST.
    #[serde(default)]
    pub schema_agent_version: bool,
    /// Emit the `v7` heartbeat instead: the `v6` body plus the storage
    /// report — every storage pool (`[[storage.pools]]`, or the implicit
    /// `default` one) and every declared dedicated disk
    /// (`[[storage.dedicated_disks]]`), with their state and refusal code
    /// ([`crate::storage`]). Requires `schema_agent_version` (`v7` is a
    /// superset of `v6`). Default `false`: vali's verifier must accept `v7`
    /// FIRST.
    #[serde(default)]
    pub emit_pools: bool,
}

impl Default for HeartbeatSection {
    fn default() -> Self {
        Self {
            interval_secs: default_heartbeat_interval_secs(),
            max_pending: default_heartbeat_max_pending(),
            sequence_path: default_heartbeat_sequence_path(),
            schema_capacity: false,
            schema_disk: false,
            schema_host_health: false,
            schema_agent_version: false,
            emit_pools: false,
        }
    }
}

fn default_skip_shutdown_teardown() -> bool {
    true
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

/// `[backup]` — live VM backup tuning.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BackupSection {
    /// HOST budget for the QEMU copies of backups, bytes/s: every job gets
    /// an equal share per run slot (`backup::job_speed`), so concurrent
    /// runs never exceed it together. `0` leaves them uncapped. Default
    /// 384 MiB/s — 192 MiB/s per job (see
    /// `backup::DEFAULT_HOST_SPEED_BYTES_PER_SEC` for why).
    #[serde(default = "default_backup_host_speed")]
    pub host_speed_bytes_per_sec: u64,
}

impl Default for BackupSection {
    fn default() -> Self {
        Self {
            host_speed_bytes_per_sec: default_backup_host_speed(),
        }
    }
}

fn default_backup_host_speed() -> u64 {
    crate::backup::DEFAULT_HOST_SPEED_BYTES_PER_SEC
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
    /// `[[storage.pools]]` — the storage pools OS disks may live on
    /// (docs/design/disk-tier-verification.md §4.1). Optional: absent, the
    /// agent has ONE implicit pool `default` at `data_disk_root` with the
    /// `[host] cvm_disk_gb_budget` budget, which is exactly the historical
    /// single-root behaviour. When present it must include a pool
    /// `id = "default"` at `data_disk_root`: every OS disk still lands
    /// there until vali can place on the others.
    #[serde(default)]
    pub pools: Vec<StoragePoolConfig>,
    /// `[[storage.dedicated_disks]]` — whole physical disks offered for
    /// passthrough, by `/dev/disk/by-id/` name (design §4.2). Optional.
    /// The agent only inspects and reports them; it never formats or wipes.
    #[serde(default)]
    pub dedicated_disks: Vec<DedicatedDiskConfig>,
}

impl Default for StorageSection {
    fn default() -> Self {
        Self {
            data_disk_root: default_storage_root(),
            state_disk_root: default_storage_root(),
            pools: Vec::new(),
            dedicated_disks: Vec::new(),
        }
    }
}

/// A storage pool's declared class — a hint, never a tier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum PoolClassConfig {
    Nvme,
    Ssd,
    Hdd,
}

/// The desired state of a pool or dedicated disk: `draining` takes no new
/// disks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum StorageDesiredStateConfig {
    #[default]
    Active,
    Draining,
}

/// One `[[storage.pools]]` entry.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StoragePoolConfig {
    /// `[a-z0-9-]{1,32}`.
    pub id: String,
    /// An already-mounted filesystem (absolute). The agent never mounts.
    pub path: PathBuf,
    pub class: PoolClassConfig,
    /// GiB the operator offers on this pool. For `default` it must equal
    /// `[host] cvm_disk_gb_budget`, the budget the launch gate reserves.
    pub budget_gb: u64,
    /// Whether OS disks may be placed here. Default `true`.
    #[serde(default = "default_true")]
    pub os_disks: bool,
    #[serde(default)]
    pub state: StorageDesiredStateConfig,
}

/// One `[[storage.dedicated_disks]]` entry.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DedicatedDiskConfig {
    /// A `/dev/disk/by-id/` basename (`wwn-…`, `ata-…`, `scsi-…`, `nvme-…`).
    pub id: String,
    #[serde(default)]
    pub state: StorageDesiredStateConfig,
}

fn default_true() -> bool {
    true
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
        let mut config = Self::read(path)?;
        config.drop_invalid_storage();
        Ok(config)
    }

    /// [`Self::load`] keeping an invalid storage declaration as written
    /// (`storage-check` reports it).
    pub fn read(path: &Path) -> Result<Self> {
        let text = std::fs::read_to_string(path).map_err(MinerAgentError::ConfigRead)?;
        let config: Config = toml::from_str(&text).map_err(|e| config_parse_at(&text, &e))?;
        config.validate()?;
        Ok(config)
    }

    /// The first problem with `[[storage.pools]]` /
    /// `[[storage.dedicated_disks]]`, if any.
    pub fn storage_error(&self) -> Option<&'static str> {
        match self.validate_storage() {
            Err(MinerAgentError::ConfigInvalid(code)) => Some(code),
            Err(_) => Some("storage-invalid"),
            Ok(()) => None,
        }
    }

    /// A storage declaration that does not validate never stops the
    /// agent: it runs with the implicit `default` pool and no dedicated
    /// disk, and says why (the removed-pool guard still keeps any pool
    /// that holds disks, as `draining`). Returns the problem it dropped.
    pub fn drop_invalid_storage(&mut self) -> Option<&'static str> {
        let error = self.storage_error()?;
        eprintln!(
            "hippius-miner-agent: config: [[storage.*]] ignored ({error}); running with the \
             implicit default pool"
        );
        self.storage.pools.clear();
        self.storage.dedicated_disks.clear();
        Some(error)
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
        // `v4` extends `v3`: the disk declarations ride on a body that
        // already carries the capacity ones.
        if self.heartbeat.schema_disk && !self.heartbeat.schema_capacity {
            return Err(MinerAgentError::ConfigInvalid(
                "heartbeat.schema_disk-requires-schema_capacity",
            ));
        }
        // `v5` extends `v4` the same way.
        if self.heartbeat.schema_host_health && !self.heartbeat.schema_disk {
            return Err(MinerAgentError::ConfigInvalid(
                "heartbeat.schema_host_health-requires-schema_disk",
            ));
        }
        // …and `v6` extends `v5`.
        if self.heartbeat.schema_agent_version && !self.heartbeat.schema_host_health {
            return Err(MinerAgentError::ConfigInvalid(
                "heartbeat.schema_agent_version-requires-schema_host_health",
            ));
        }
        // …and `v7` extends `v6`.
        if self.heartbeat.emit_pools && !self.heartbeat.schema_agent_version {
            return Err(MinerAgentError::ConfigInvalid(
                "heartbeat.emit_pools-requires-schema_agent_version",
            ));
        }
        // `[[storage.*]]` is judged apart (`drop_invalid_storage`): a bad
        // pool declaration must never keep the agent down.

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
        // `[inventory]`: checked whether enabled or not, so a bad value is
        // caught before the day it is switched on.
        let inv = &self.inventory;
        require_absolute(&inv.dir, "inventory.dir")?;
        let within = |s: u64| (1..=INVENTORY_MAX_INTERVAL_SECS).contains(&s);
        if !within(inv.full_interval_secs) || inv.full_jitter_secs >= inv.full_interval_secs {
            return Err(MinerAgentError::ConfigInvalid(
                "inventory.full_interval_secs",
            ));
        }
        if !within(inv.counters_interval_secs) {
            return Err(MinerAgentError::ConfigInvalid(
                "inventory.counters_interval_secs",
            ));
        }
        if inv.min_gap_secs < INVENTORY_MIN_GAP_FLOOR_SECS || !within(inv.min_gap_secs) {
            return Err(MinerAgentError::ConfigInvalid("inventory.min_gap_secs"));
        }
        if inv.poll_secs == 0 || inv.poll_secs > inv.min_gap_secs {
            return Err(MinerAgentError::ConfigInvalid("inventory.poll_secs"));
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

impl Config {
    /// The static rules of `[[storage.pools]]` / `[[storage.dedicated_disks]]`.
    /// What can only be checked on the host (mounts, filesystem types,
    /// `O_DIRECT`, the disks themselves) is checked at run time by
    /// [`crate::storage`] and reported per pool / disk, never a load error.
    fn validate_storage(&self) -> Result<()> {
        use hippius_types::storage_report::{
            is_valid_dedicated_disk_id, is_valid_pool_id, MAX_DEDICATED_DISKS, MAX_DISK_POOLS,
        };
        let pools = &self.storage.pools;
        if pools.len() > MAX_DISK_POOLS {
            return Err(MinerAgentError::ConfigInvalid("storage.pools-too-many"));
        }
        let mut ids = std::collections::BTreeSet::new();
        let mut paths = std::collections::BTreeSet::new();
        for pool in pools {
            if !is_valid_pool_id(&pool.id) {
                return Err(MinerAgentError::ConfigInvalid("storage.pools.id"));
            }
            require_absolute(&pool.path, "storage.pools.path")?;
            if !ids.insert(pool.id.as_str()) {
                return Err(MinerAgentError::ConfigInvalid("storage.pools.id-duplicate"));
            }
            if !paths.insert(pool.path.as_path()) {
                return Err(MinerAgentError::ConfigInvalid(
                    "storage.pools.path-duplicate",
                ));
            }
        }
        if !pools.is_empty() {
            // Every OS disk still lands on `default` (vali cannot place on
            // another pool yet), and backups, restores and migrations work
            // on `data_disk_root`: the default pool must be that root,
            // budgeted as the launch gate reserves.
            let default = pools
                .iter()
                .find(|p| p.id == crate::storage::DEFAULT_POOL_ID)
                .ok_or(MinerAgentError::ConfigInvalid("storage.pools-no-default"))?;
            if default.path != self.storage.data_disk_root {
                return Err(MinerAgentError::ConfigInvalid(
                    "storage.pools.default-path-not-data_disk_root",
                ));
            }
            if default.budget_gb != self.host.cvm_disk_gb_budget {
                return Err(MinerAgentError::ConfigInvalid(
                    "storage.pools.default-budget-not-host-budget",
                ));
            }
            if !default.os_disks || default.state != StorageDesiredStateConfig::Active {
                return Err(MinerAgentError::ConfigInvalid(
                    "storage.pools.default-must-take-os-disks",
                ));
            }
        }
        let disks = &self.storage.dedicated_disks;
        if disks.len() > MAX_DEDICATED_DISKS {
            return Err(MinerAgentError::ConfigInvalid(
                "storage.dedicated_disks-too-many",
            ));
        }
        let mut disk_ids = std::collections::BTreeSet::new();
        for disk in disks {
            if !is_valid_dedicated_disk_id(&disk.id) {
                return Err(MinerAgentError::ConfigInvalid("storage.dedicated_disks.id"));
            }
            if !disk_ids.insert(disk.id.as_str()) {
                return Err(MinerAgentError::ConfigInvalid(
                    "storage.dedicated_disks.id-duplicate",
                ));
            }
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

/// Where `serve` and the one-shot commands read the config by default.
pub const DEFAULT_CONFIG_PATH: &str = "/etc/hippius-miner/config.toml";

/// Where the play installs the Edge server CA
/// (`{{ mtls.cert_dir }}/ca.crt` in the config template) — the fallback
/// of the one-shot commands on a host without a config.
pub const PLAY_EDGE_CA_CERT: &str = "/var/lib/hippius-miner/mtls/ca.crt";

/// The identity files `init-identity` writes by default.
pub const DEFAULT_IDENTITY_KEY: &str = "/var/lib/hippius-miner/identity.key";
/// See [`DEFAULT_IDENTITY_KEY`].
pub const DEFAULT_IDENTITY_PUB: &str = "/var/lib/hippius-miner/identity.pub";

impl Config {
    /// [`Self::read`] for the one-shot commands. `None` (no explicit
    /// path) reads [`DEFAULT_CONFIG_PATH`] and answers `None` when no
    /// file is there; an explicit path that is missing, or any config
    /// that does not parse or validate, is an error — never a silent
    /// fallback to defaults that would contradict the running agent.
    pub fn read_optional(path: Option<&Path>) -> Result<Option<Self>> {
        Self::read_optional_or(path, Path::new(DEFAULT_CONFIG_PATH))
    }

    fn read_optional_or(path: Option<&Path>, default: &Path) -> Result<Option<Self>> {
        let explicit = path.is_some();
        match Self::read(path.unwrap_or(default)) {
            Ok(config) => Ok(Some(config)),
            Err(MinerAgentError::ConfigRead(e))
                if !explicit && e.kind() == std::io::ErrorKind::NotFound =>
            {
                Ok(None)
            }
            Err(e) => Err(e),
        }
    }
}

/// The flags of `request-graceful-exit`; each one left out falls back to
/// this host's config, then to the play's paths ([`EdgeCliFlags::resolve`]).
#[derive(Debug, Clone, Default)]
pub struct EdgeCliFlags {
    pub miner_id: Option<String>,
    pub edge_url: Option<String>,
    pub ca_cert: Option<PathBuf>,
    pub key_path: Option<PathBuf>,
    pub pub_path: Option<PathBuf>,
    pub client_cert: Option<PathBuf>,
    pub client_key: Option<PathBuf>,
}

/// What a one-shot Edge command signs with and talks to.
#[derive(Debug, Clone)]
pub struct EdgeCliTarget {
    pub miner_id: String,
    pub key_path: PathBuf,
    pub pub_path: PathBuf,
    /// `order_signing_pubkey` is empty: it only gates inbound orders,
    /// never an outbound POST.
    pub edge: EdgeSection,
}

impl EdgeCliFlags {
    /// Whether the config must be read: not when the operator gave the
    /// miner id, the Edge URL and the CA, so a drain run with every flag
    /// works even past a config the binary cannot parse (and keeps the
    /// pre-fallback behaviour: identity at the default paths, a
    /// self-signed client cert unless both client flags are given).
    pub fn needs_config(&self) -> bool {
        self.miner_id.is_none() || self.edge_url.is_none() || self.ca_cert.is_none()
    }

    /// Flag, else `config`, else the play default. `miner_id` and the
    /// Edge URL have no default: without a flag and a config they are an
    /// error. The client cert/key pair is taken as a pair — both flags,
    /// else the config's pair (legacy operator-CA mode), else none
    /// (self-signed from the identity key).
    pub fn resolve(self, config: Option<&Config>) -> Result<EdgeCliTarget> {
        let miner_id = self
            .miner_id
            .or_else(|| config.map(|c| c.miner.miner_id.clone()))
            .ok_or(MinerAgentError::GracefulExit("miner-id-missing"))?;
        let endpoint = self
            .edge_url
            .or_else(|| config.map(|c| c.edge.endpoint.clone()))
            .ok_or(MinerAgentError::GracefulExit("edge-url-missing"))?;
        let ca_cert = self
            .ca_cert
            .or_else(|| config.map(|c| c.edge.ca_cert.clone()))
            .unwrap_or_else(|| PathBuf::from(PLAY_EDGE_CA_CERT));
        let key_path = self
            .key_path
            .or_else(|| config.map(|c| c.identity.key_path.clone()))
            .unwrap_or_else(|| PathBuf::from(DEFAULT_IDENTITY_KEY));
        let pub_path = self
            .pub_path
            .or_else(|| config.map(|c| c.identity.pub_path.clone()))
            .unwrap_or_else(|| PathBuf::from(DEFAULT_IDENTITY_PUB));
        let (client_cert, client_key) = match (self.client_cert, self.client_key) {
            (None, None) => config
                .map(|c| (c.edge.client_cert.clone(), c.edge.client_key.clone()))
                .unwrap_or((None, None)),
            (Some(cert), Some(key)) => (Some(cert), Some(key)),
            _ => return Err(MinerAgentError::GracefulExit("client-cert-key-pair")),
        };
        Ok(EdgeCliTarget {
            miner_id,
            key_path,
            pub_path,
            edge: EdgeSection {
                endpoint,
                client_cert,
                client_key,
                ca_cert,
                order_signing_pubkey: String::new(),
            },
        })
    }
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

    #[test]
    fn inventory_defaults_off_with_the_design_cadence() {
        let c = parse(VALID).unwrap();
        let inv = &c.inventory;
        assert!(!inv.enabled);
        assert_eq!(inv.dir, PathBuf::from("/run/hippius-miner/inventory"));
        assert_eq!(
            (
                inv.full_interval_secs,
                inv.full_jitter_secs,
                inv.counters_interval_secs,
                inv.min_gap_secs,
                inv.poll_secs
            ),
            (86400, 3600, 21600, 320, 60)
        );
    }

    #[test]
    fn inventory_overrides_and_their_refusals() {
        let with = |table: &str| format!("{VALID}\n[inventory]\n{table}\n");
        let c = parse(&with(
            "enabled = true\ndir = \"/srv/inv\"\nfull_interval_secs = 7200\n\
             full_jitter_secs = 600\ncounters_interval_secs = 1800\nmin_gap_secs = 600\n\
             poll_secs = 30",
        ))
        .unwrap();
        assert!(c.inventory.enabled);
        assert_eq!(c.inventory.dir, PathBuf::from("/srv/inv"));
        assert_eq!(c.inventory.min_gap_secs, 600);
        for (table, field) in [
            ("dir = \"relative/inv\"", "inventory.dir"),
            ("full_jitter_secs = 86400", "inventory.full_interval_secs"),
            ("full_interval_secs = 0", "inventory.full_interval_secs"),
            (
                "counters_interval_secs = 0",
                "inventory.counters_interval_secs",
            ),
            // Past 30 days.
            (
                "full_interval_secs = 2592001",
                "inventory.full_interval_secs",
            ),
            (
                "counters_interval_secs = 2592001",
                "inventory.counters_interval_secs",
            ),
            ("min_gap_secs = 2592001", "inventory.min_gap_secs"),
            // Below vali's budget of 12 reports an hour.
            ("min_gap_secs = 319", "inventory.min_gap_secs"),
            ("poll_secs = 0", "inventory.poll_secs"),
            ("poll_secs = 321", "inventory.poll_secs"),
        ] {
            match parse(&with(table)) {
                Err(MinerAgentError::ConfigInvalid(f)) => assert_eq!(f, field, "{table}"),
                other => panic!("{table}: {other:?}"),
            }
        }
        // An unknown key fails loudly, like every other section.
        assert!(matches!(
            parse(&with("enabled = true\ncadence = 5")),
            Err(MinerAgentError::ConfigParse { .. })
        ));
    }

    /// The checks `load` runs, storage refusals included (as errors, so
    /// the storage tests read them; `load` itself drops the section).
    fn parse(s: &str) -> Result<Config> {
        let c: Config = toml::from_str(s).map_err(|e| config_parse_at(s, &e))?;
        c.validate()?;
        if let Some(code) = c.storage_error() {
            return Err(MinerAgentError::ConfigInvalid(code));
        }
        Ok(c)
    }

    fn edge_cli_flags_error(flags: EdgeCliFlags, config: Option<&Config>) -> &'static str {
        match flags.resolve(config) {
            Err(MinerAgentError::GracefulExit(code)) => code,
            other => panic!("expected a graceful-exit error, got {other:?}"),
        }
    }

    #[test]
    fn graceful_exit_flags_fall_back_to_the_agent_config() {
        let config = parse(VALID).unwrap();
        let t = EdgeCliFlags::default().resolve(Some(&config)).unwrap();
        assert_eq!(t.miner_id, "miner-a");
        assert_eq!(t.edge.endpoint, "https://edge.hippius.network:443");
        assert_eq!(
            t.edge.ca_cert,
            Path::new("/var/lib/hippius-miner/edge-ca.crt")
        );
        assert_eq!(t.key_path, Path::new("/var/lib/hippius-miner/identity.key"));
        assert_eq!(t.pub_path, Path::new("/var/lib/hippius-miner/identity.pub"));
        // The config's operator-CA pair: a self-signed cert would be
        // refused by an Edge in `ca` mode.
        assert_eq!(
            t.edge.client_cert.as_deref(),
            Some(Path::new("/var/lib/hippius-miner/edge-mtls.crt"))
        );
        assert_eq!(
            t.edge.client_key.as_deref(),
            Some(Path::new("/var/lib/hippius-miner/edge-mtls.key"))
        );
    }

    #[test]
    fn graceful_exit_flags_win_over_the_config() {
        let config = parse(VALID).unwrap();
        let flags = EdgeCliFlags {
            miner_id: Some("m-0123456789abcdef".into()),
            edge_url: Some("https://edge.example:8443".into()),
            ca_cert: Some("/tmp/ca.pem".into()),
            key_path: Some("/tmp/id.key".into()),
            pub_path: Some("/tmp/id.pub".into()),
            client_cert: Some("/tmp/c.crt".into()),
            client_key: Some("/tmp/c.key".into()),
        };
        let t = flags.resolve(Some(&config)).unwrap();
        assert_eq!(t.miner_id, "m-0123456789abcdef");
        assert_eq!(t.edge.endpoint, "https://edge.example:8443");
        assert_eq!(t.edge.ca_cert, Path::new("/tmp/ca.pem"));
        assert_eq!(t.key_path, Path::new("/tmp/id.key"));
        assert_eq!(t.pub_path, Path::new("/tmp/id.pub"));
        assert_eq!(t.edge.client_cert.as_deref(), Some(Path::new("/tmp/c.crt")));
        assert_eq!(t.edge.client_key.as_deref(), Some(Path::new("/tmp/c.key")));
    }

    #[test]
    fn graceful_exit_without_a_config_uses_the_play_paths() {
        let flags = EdgeCliFlags {
            miner_id: Some("m-0123456789abcdef".into()),
            edge_url: Some("https://edge.example:8443".into()),
            ..EdgeCliFlags::default()
        };
        let t = flags.resolve(None).unwrap();
        assert_eq!(
            t.edge.ca_cert,
            Path::new("/var/lib/hippius-miner/mtls/ca.crt")
        );
        assert_eq!(t.key_path, Path::new(DEFAULT_IDENTITY_KEY));
        assert_eq!(t.pub_path, Path::new(DEFAULT_IDENTITY_PUB));
        assert_eq!(t.edge.client_cert, None);
        assert_eq!(t.edge.client_key, None);
    }

    #[test]
    fn graceful_exit_refuses_what_it_cannot_resolve() {
        assert_eq!(
            edge_cli_flags_error(EdgeCliFlags::default(), None),
            "miner-id-missing"
        );
        let no_url = EdgeCliFlags {
            miner_id: Some("m-0123456789abcdef".into()),
            ..EdgeCliFlags::default()
        };
        assert_eq!(edge_cli_flags_error(no_url, None), "edge-url-missing");
        // Half a pair never silently falls back to the self-signed cert.
        let config = parse(VALID).unwrap();
        let half = EdgeCliFlags {
            client_cert: Some("/tmp/c.crt".into()),
            ..EdgeCliFlags::default()
        };
        assert_eq!(
            edge_cli_flags_error(half, Some(&config)),
            "client-cert-key-pair"
        );
        let other_half = EdgeCliFlags {
            client_key: Some("/tmp/c.key".into()),
            ..EdgeCliFlags::default()
        };
        assert_eq!(
            edge_cli_flags_error(other_half, Some(&config)),
            "client-cert-key-pair"
        );
    }

    #[test]
    fn graceful_exit_with_every_target_flag_skips_the_config() {
        let mut flags = EdgeCliFlags {
            miner_id: Some("m-0123456789abcdef".into()),
            edge_url: Some("https://edge.example:8443".into()),
            ca_cert: Some("/tmp/ca.pem".into()),
            ..EdgeCliFlags::default()
        };
        assert!(!flags.needs_config());
        flags.ca_cert = None;
        assert!(flags.needs_config());
        assert!(EdgeCliFlags::default().needs_config());
    }

    #[test]
    fn play_edge_ca_is_where_the_play_installs_it() {
        // mtls-cert-mount.yml copies the Edge CA to `{{ mtls.cert_dir }}/ca.crt`
        // and the template renders `[edge].ca_cert` from the same path.
        let template = include_str!(
            "../../../deploy/ansible/playbooks/miner-tasks/templates/miner-agent-config.toml.j2"
        );
        assert!(template.contains("ca_cert = \"{{ mtls.cert_dir }}/ca.crt\""));
        let group_vars = include_str!("../../../deploy/ansible/group_vars/miner_nodes.yml");
        let cert_dirs: Vec<&str> = group_vars
            .lines()
            .filter_map(|l| l.trim().strip_prefix("cert_dir:"))
            .map(|v| v.trim().trim_matches('"'))
            .collect();
        assert_eq!(cert_dirs.len(), 1, "one mtls.cert_dir in group_vars");
        assert_eq!(format!("{}/ca.crt", cert_dirs[0]), PLAY_EDGE_CA_CERT);
    }

    #[test]
    fn read_optional_skips_only_a_missing_default_config() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("absent.toml");
        assert!(Config::read_optional_or(None, &missing).unwrap().is_none());
        // An explicit path must exist.
        assert!(matches!(
            Config::read_optional_or(Some(&missing), &missing),
            Err(MinerAgentError::ConfigRead(_))
        ));
        // A default config that is there but broken is an error, not a
        // silent fallback.
        let broken = dir.path().join("broken.toml");
        std::fs::write(&broken, "[miner]\nminer_id = \"\"\n").unwrap();
        assert!(Config::read_optional_or(None, &broken).is_err());
        let good = dir.path().join("config.toml");
        std::fs::write(&good, VALID).unwrap();
        let c = Config::read_optional_or(None, &good).unwrap().unwrap();
        assert_eq!(c.miner.miner_id, "miner-a");
    }

    #[test]
    fn a_bad_storage_declaration_is_dropped_never_fatal() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        // A pool set without `default`.
        std::fs::write(
            &path,
            format!(
                "{VALID}\n[storage]\n[[storage.pools]]\nid = \"hdd0\"\npath = \"/srv/hdd0\"\n\
                 class = \"hdd\"\nbudget_gb = 100\n"
            ),
        )
        .unwrap();
        let c = Config::load(&path).unwrap();
        assert!(c.storage.pools.is_empty());
        assert!(c.storage.dedicated_disks.is_empty());
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
    fn skip_shutdown_teardown_absent_key_leaves_cvms_running() {
        // Omitted → true: a hand-written config that forgets the key must
        // not destroy every domain on the next `systemctl stop`
        // (2026-09-21).
        assert!(!VALID.contains("skip_shutdown_teardown"));
        let c = parse(VALID).unwrap();
        assert!(c.host.skip_shutdown_teardown);
    }

    #[test]
    fn skip_shutdown_teardown_explicit_values_keep_their_meaning() {
        // Explicit true → the agent leaves tenant CVMs running across a
        // restart (they live in libvirtd's cgroup, not the agent's).
        let cfg = format!("{VALID}skip_shutdown_teardown = true\n");
        let c = parse(&cfg).unwrap();
        assert!(c.host.skip_shutdown_teardown);
        // Explicit false → still an opt-in to the teardown.
        let cfg = format!("{VALID}skip_shutdown_teardown = false\n");
        let c = parse(&cfg).unwrap();
        assert!(!c.host.skip_shutdown_teardown);
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
    fn kbs_custody_relay_defaults_off_and_parses_when_set() {
        // Absent ⇒ OFF: an existing miner config keeps refusing the
        // custody paths locally after the upgrade.
        let without = format!("{VALID}\n[kbs]\nendpoint = \"https://kbs.hippius.network\"\n");
        assert!(!parse(&without).unwrap().kbs.unwrap().custody_relay);
        let with = format!(
            "{VALID}\n[kbs]\nendpoint = \"https://kbs.hippius.network\"\n\
             custody_relay = true\n"
        );
        assert!(parse(&with).unwrap().kbs.unwrap().custody_relay);
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

    /// The `[host]` section of a config file, header line excluded, up to
    /// the next table header or Jinja block.
    fn host_section(text: &str) -> Vec<&str> {
        text.lines()
            .skip_while(|l| l.trim() != "[host]")
            .skip(1)
            .take_while(|l| !l.trim_start().starts_with('[') && !l.trim_start().starts_with("{%"))
            .collect()
    }

    #[test]
    fn deployed_and_example_configs_keep_cvms_across_an_agent_restart() {
        // 2026-09-21: an Ansible re-render had silently dropped this key
        // (it was only ever hand-added), so `systemctl stop` on miner-3
        // tore down every tenant domain. The agent now defaults to true,
        // but an older binary (the updater's rollback target, a pinned
        // release) still defaults to false — so the configs keep spelling
        // the key out, and the updater still refuses to swap without it.
        let sources = [
            (
                "ansible template",
                include_str!(
                    "../../../deploy/ansible/playbooks/miner-tasks/templates/miner-agent-config.toml.j2"
                ),
            ),
            (
                "shipped example",
                include_str!("../examples/miner-agent-config.toml.example"),
            ),
        ];
        for (name, text) in sources {
            let host = host_section(text);
            assert!(!host.is_empty(), "{name}: no [host] section");
            assert!(
                host.iter()
                    .any(|l| l.trim() == "skip_shutdown_teardown = true"),
                "{name}: [host] must set `skip_shutdown_teardown = true`"
            );
        }
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
    fn the_backup_speed_defaults_and_is_overridable() {
        // `VALID` carries no `[backup]` — existing configs keep parsing.
        assert_eq!(
            parse(VALID).unwrap().backup.host_speed_bytes_per_sec,
            384 << 20
        );
        let cfg = format!("{VALID}\n[backup]\nhost_speed_bytes_per_sec = 0\n");
        assert_eq!(parse(&cfg).unwrap().backup.host_speed_bytes_per_sec, 0);
        let cfg = format!("{VALID}\n[backup]\nspeed_bytes_per_sec = 1\n");
        assert!(parse(&cfg).is_err(), "unknown key refused");
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
    fn schema_disk_defaults_false_and_requires_schema_capacity() {
        assert!(!parse(VALID).unwrap().heartbeat.schema_disk);
        assert!(!HeartbeatSection::default().schema_disk);
        let cfg = format!("{VALID}\n[heartbeat]\nschema_capacity = true\nschema_disk = true\n");
        assert!(parse(&cfg).unwrap().heartbeat.schema_disk);
        let cfg = format!("{VALID}\n[heartbeat]\nschema_disk = true\n");
        assert!(matches!(
            parse(&cfg),
            Err(MinerAgentError::ConfigInvalid(
                "heartbeat.schema_disk-requires-schema_capacity"
            ))
        ));
    }

    #[test]
    fn schema_agent_version_defaults_false_and_requires_schema_host_health() {
        assert!(!parse(VALID).unwrap().heartbeat.schema_agent_version);
        assert!(!HeartbeatSection::default().schema_agent_version);
        let cfg = format!(
            "{VALID}\n[heartbeat]\nschema_capacity = true\nschema_disk = true\nschema_host_health = true\nschema_agent_version = true\n"
        );
        assert!(parse(&cfg).unwrap().heartbeat.schema_agent_version);
        let cfg = format!(
            "{VALID}\n[heartbeat]\nschema_capacity = true\nschema_disk = true\nschema_agent_version = true\n"
        );
        assert!(matches!(
            parse(&cfg),
            Err(MinerAgentError::ConfigInvalid(
                "heartbeat.schema_agent_version-requires-schema_host_health"
            ))
        ));
    }

    #[test]
    fn schema_host_health_defaults_false_and_requires_schema_disk() {
        assert!(!parse(VALID).unwrap().heartbeat.schema_host_health);
        assert!(!HeartbeatSection::default().schema_host_health);
        let cfg = format!(
            "{VALID}\n[heartbeat]\nschema_capacity = true\nschema_disk = true\nschema_host_health = true\n"
        );
        assert!(parse(&cfg).unwrap().heartbeat.schema_host_health);
        let cfg =
            format!("{VALID}\n[heartbeat]\nschema_capacity = true\nschema_host_health = true\n");
        assert!(matches!(
            parse(&cfg),
            Err(MinerAgentError::ConfigInvalid(
                "heartbeat.schema_host_health-requires-schema_disk"
            ))
        ));
    }

    #[test]
    fn schema_capacity_defaults_false_and_parses_true() {
        // Absent table AND absent key both mean `false` — the fleet keeps
        // emitting v1 until vali accepts v3.
        assert!(!parse(VALID).unwrap().heartbeat.schema_capacity);
        assert!(!HeartbeatSection::default().schema_capacity);
        let cfg = format!("{VALID}\n[heartbeat]\ninterval_secs = 30\n");
        assert!(!parse(&cfg).unwrap().heartbeat.schema_capacity);
        let cfg = format!("{VALID}\n[heartbeat]\nschema_capacity = true\n");
        assert!(parse(&cfg).unwrap().heartbeat.schema_capacity);
    }

    #[test]
    fn an_unknown_heartbeat_key_is_still_rejected() {
        // `deny_unknown_fields` survives the new key — a typo fails loudly.
        let cfg = format!("{VALID}\n[heartbeat]\nschema_capacityy = true\n");
        assert!(parse(&cfg).is_err());
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

    // ── [[storage.pools]] / [[storage.dedicated_disks]] ──────────────

    fn with_storage(extra: &str) -> String {
        format!("{VALID}\n[storage]\ndata_disk_root = \"/var/lib/hippius-miner\"\n{extra}")
    }

    const DEFAULT_POOL: &str = r#"
[[storage.pools]]
id = "default"
path = "/var/lib/hippius-miner"
class = "nvme"
budget_gb = 0
"#;

    fn refused(cfg: &str, class: &str) {
        match parse(cfg) {
            Err(MinerAgentError::ConfigInvalid(got)) => assert_eq!(got, class),
            other => panic!("expected {class}, got {other:?}"),
        }
    }

    #[test]
    fn a_config_without_pools_has_no_pools() {
        let c = parse(VALID).unwrap();
        assert!(c.storage.pools.is_empty());
        assert!(c.storage.dedicated_disks.is_empty());
        assert!(!c.heartbeat.emit_pools);
    }

    #[test]
    fn pools_and_dedicated_disks_parse() {
        let c = parse(&with_storage(&format!(
            "{DEFAULT_POOL}
[[storage.pools]]
id = \"hdd0\"
path = \"/srv/hdd0/hippius\"
class = \"hdd\"
budget_gb = 16000
os_disks = false
state = \"draining\"

[[storage.dedicated_disks]]
id = \"wwn-0x5000c500a1b2c3d4\"

[[storage.dedicated_disks]]
id = \"ata-ST18000NM000J_ZR5ABCDE\"
state = \"draining\"
"
        )))
        .unwrap();
        assert_eq!(c.storage.pools.len(), 2);
        let hdd = &c.storage.pools[1];
        assert_eq!(hdd.class, PoolClassConfig::Hdd);
        assert_eq!(hdd.budget_gb, 16000);
        assert!(!hdd.os_disks);
        assert_eq!(hdd.state, StorageDesiredStateConfig::Draining);
        // Defaults: os_disks true, state active.
        assert!(c.storage.pools[0].os_disks);
        assert_eq!(c.storage.pools[0].state, StorageDesiredStateConfig::Active);
        assert_eq!(c.storage.dedicated_disks.len(), 2);
        assert_eq!(
            c.storage.dedicated_disks[1].state,
            StorageDesiredStateConfig::Draining
        );
    }

    #[test]
    fn an_unknown_pool_key_or_class_is_a_parse_error() {
        assert!(parse(&with_storage(
            &DEFAULT_POOL.replace("budget_gb = 0", "budget_gb = 0\nsize = 1")
        ))
        .is_err());
        assert!(parse(&with_storage(&DEFAULT_POOL.replace("nvme", "tape"))).is_err());
    }

    #[test]
    fn pools_need_a_default_at_the_data_root_with_the_host_budget() {
        refused(
            &with_storage(&DEFAULT_POOL.replace("id = \"default\"", "id = \"nvme0\"")),
            "storage.pools-no-default",
        );
        refused(
            &with_storage(
                &DEFAULT_POOL.replace("path = \"/var/lib/hippius-miner\"", "path = \"/srv/nvme0\""),
            ),
            "storage.pools.default-path-not-data_disk_root",
        );
        refused(
            &with_storage(&DEFAULT_POOL.replace("budget_gb = 0", "budget_gb = 10")),
            "storage.pools.default-budget-not-host-budget",
        );
        refused(
            &with_storage(
                &DEFAULT_POOL.replace("budget_gb = 0", "budget_gb = 0\nos_disks = false"),
            ),
            "storage.pools.default-must-take-os-disks",
        );
        refused(
            &with_storage(
                &DEFAULT_POOL.replace("budget_gb = 0", "budget_gb = 0\nstate = \"draining\""),
            ),
            "storage.pools.default-must-take-os-disks",
        );
    }

    fn extra_pool(id: &str, path: &str) -> String {
        format!(
            "\n[[storage.pools]]\nid = \"{id}\"\npath = \"{path}\"\nclass = \"hdd\"\nbudget_gb = 1\n"
        )
    }

    #[test]
    fn pool_ids_paths_and_counts_are_checked() {
        refused(
            &with_storage(&format!("{DEFAULT_POOL}{}", extra_pool("Bad_Id", "/srv/a"))),
            "storage.pools.id",
        );
        refused(
            &with_storage(&format!("{DEFAULT_POOL}{}", extra_pool("a", "relative"))),
            "storage.pools.path",
        );
        refused(
            &with_storage(&format!(
                "{DEFAULT_POOL}{}",
                extra_pool("default", "/srv/a")
            )),
            "storage.pools.id-duplicate",
        );
        refused(
            &with_storage(&format!(
                "{DEFAULT_POOL}{}",
                extra_pool("a", "/var/lib/hippius-miner")
            )),
            "storage.pools.path-duplicate",
        );
        let five: String = ["a", "b", "c", "d"]
            .iter()
            .map(|id| extra_pool(id, &format!("/srv/{id}")))
            .collect();
        refused(
            &with_storage(&format!("{DEFAULT_POOL}{five}")),
            "storage.pools-too-many",
        );
        let four: String = ["a", "b", "c"]
            .iter()
            .map(|id| extra_pool(id, &format!("/srv/{id}")))
            .collect();
        assert!(parse(&with_storage(&format!("{DEFAULT_POOL}{four}"))).is_ok());
    }

    fn disk(id: &str) -> String {
        format!("\n[[storage.dedicated_disks]]\nid = \"{id}\"\n")
    }

    #[test]
    fn dedicated_disk_ids_and_counts_are_checked() {
        refused(&with_storage(&disk("sda")), "storage.dedicated_disks.id");
        refused(
            &with_storage(&disk("wwn-0x1-part1")),
            "storage.dedicated_disks.id",
        );
        refused(
            &with_storage(&format!("{}{}", disk("wwn-0x1"), disk("wwn-0x1"))),
            "storage.dedicated_disks.id-duplicate",
        );
        let many: String = (0..25).map(|i| disk(&format!("wwn-0x{i:02}"))).collect();
        refused(&with_storage(&many), "storage.dedicated_disks-too-many");
        // Dedicated disks need no pool declaration.
        assert!(parse(&with_storage(&disk("nvme-eui.0025388b91c0a1b2"))).is_ok());
    }

    #[test]
    fn emit_pools_requires_the_agent_version_heartbeat() {
        let base = format!("{VALID}\n[heartbeat]\nemit_pools = true\n");
        refused(&base, "heartbeat.emit_pools-requires-schema_agent_version");
        let full = format!(
            "{VALID}\n[heartbeat]\nschema_capacity = true\nschema_disk = true\n\
             schema_host_health = true\nschema_agent_version = true\nemit_pools = true\n"
        );
        assert!(parse(&full).unwrap().heartbeat.emit_pools);
    }
}
