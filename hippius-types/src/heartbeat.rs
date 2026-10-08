//! Miner-agent periodic signed heartbeat (ARCHITECTURE.md §K / §13).
//!
//! A miner-agent runs on an **untrusted** bare-metal host. To prove it
//! is alive — so vali's scheduler does not quarantine it — it builds a
//! signed [`MinerHeartbeat`] every `[heartbeat] interval_secs`, queues
//! it, and a pusher relays it over mTLS to the Edge gateway, which
//! forwards it to vali's §9 telemetry ingest. vali verifies the
//! Ed25519 signature against the out-of-band-registered miner identity,
//! enforces a monotonic `sequence` (replay defence) and a `±300 s`
//! timestamp anti-skew, then refreshes the miner's `last_seen_at`.
//!
//! This module owns only the **wire format** — the canonical encoder
//! and the [`SignedMinerHeartbeat`] envelope. The Ed25519 sign /
//! verify live with their callers (the miner-agent's `MinerIdentity`,
//! vali's `ticket-validator` shell-out) so this crate stays crypto-free
//! and `no_std`.
//!
//! ## Domain separation
//!
//! [`DOMAIN`] is **distinct** from every other signed payload in the
//! stack (`RELEASE_DOMAIN`, `RECEIPT_DOMAIN`, `STOPPED_DOMAIN`,
//! `AUDIT_VM_CERT_DOMAIN`, …) so a signature minted over a heartbeat
//! body can never be lifted into another scheme. The domain tag is a
//! field of the signed body, so a cross-scheme replay produces
//! different bytes and fails verification.
//!
//! ## Schema (`v1` / `v2` / `v3` / `v4` / `v5` / `v6`) — fixed, fail-closed
//!
//! Every field is mandatory. [`MinerHeartbeat::validate`] runs on both
//! the encode and (caller-side) decode paths; [`canonical`] rejects a
//! malformed heartbeat at encode time so a signature over an
//! impossible value can never exist. `#[serde(deny_unknown_fields)]`
//! on [`SignedMinerHeartbeat`] blocks extra-key smuggling past the
//! envelope decode.

#[allow(unused_imports)]
// per-module slice of the alloc prelude — not every module needs every item
use alloc::{
    boxed::Box,
    format,
    string::{String, ToString},
    vec,
    vec::Vec,
};

use crate::cbor::to_canonical_vec;
use ciborium::value::Value;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Replay-domain separator — the first field of every signed heartbeat
/// body. Distinct from every other signed-payload domain in the stack.
pub const DOMAIN: &str = "HIPPIUS_MINER_HEARTBEAT_V1";

/// The baseline `schema_version` — the original 10-field heartbeat.
/// Every existing miner emits this; its wire bytes are frozen by the
/// `heartbeat_kat` known-answer test and MUST never shift.
pub const SCHEMA_VERSION: u8 = 1;

/// The `schema_version` of a `v2` heartbeat — identical to the `v1`
/// body plus one extra `graceful_exit_requested` bool (which, being the
/// longest key, the RFC 8949 deterministic encoder places last). A
/// `v2` heartbeat is OPT-IN: a miner emits it only when it wants to
/// carry the graceful-exit flag (transport (B), the always-on passive
/// complement to the Edge-relayed graceful-exit request). vali accepts
/// BOTH versions; a `v1` heartbeat is byte-identical to before.
pub const SCHEMA_VERSION_GRACEFUL_EXIT: u8 = 2;

/// The `schema_version` of a `v3` heartbeat — the full `v2` body
/// (`graceful_exit_requested` included) PLUS four `u32` capacity
/// declarations: `cvm_cpu_budget`, `cvm_memory_mb_budget`,
/// `asid_capacity`, `asid_used` (capacity v2 §2.3/§2.4). `0` in any of
/// them means "the host could not read it / unknown".
///
/// The miner is UNTRUSTED: vali uses these only as DOWN-ONLY clamps on
/// its own trusted bound, so a miner inflating them gains nothing and
/// deflating them only throttles itself.
///
/// Graceful exit: a `v3` body carries the flag like `v2` does, and a
/// verifier MUST honour it on both. The miner-agent nevertheless keeps
/// emitting its graceful-exit heartbeat as `v2`
/// ([`MinerHeartbeat::graceful_exit`]) — a leaving miner has no use for
/// capacity declarations, and a `v2` exit stays understood by a vali
/// that predates `v3`.
///
/// `v3` is OPT-IN (the miner-agent's `[heartbeat] schema_capacity`);
/// vali MUST accept it before any miner emits it.
pub const SCHEMA_VERSION_CAPACITY: u8 = 3;

/// The `schema_version` of a `v4` heartbeat — the full `v3` body PLUS the
/// four `u32` GiB disk declarations of [`DiskDeclaration`]
/// (`cvm_disk_gb_budget`, `data_disk_total_gb`, `data_disk_available_gb`,
/// `staging_disk_available_gb`). `0` in any of them = unknown.
///
/// Disk cannot be attested by SNP, so — exactly like `v3` — vali uses
/// these only as DOWN-ONLY clamps on its own committed-disk ledger: an
/// inflated figure buys a miner launches it then fails (`insufficient-disk`,
/// counted against it), a deflated one only throttles itself.
///
/// `v4` is OPT-IN (the miner-agent's `[heartbeat] schema_disk`); vali's
/// verifier MUST accept it before any miner emits it.
pub const SCHEMA_VERSION_DISK: u8 = 4;

/// The `schema_version` of a `v5` heartbeat — the full `v4` body PLUS the
/// four host-health fields of [`HostHealthDeclaration`] (`snp_enabled`,
/// `cpus_offline`, `snp_launches_since_boot`, `df_flush_failures`).
///
/// They exist to see SEV-SNP ASID recycling break before it does: the
/// kernel recycles a destroyed guest's ASID only through `SNP_DF_FLUSH`,
/// which the firmware refuses (`WBINVD_REQUIRED`) while a CPU it counted
/// at `SNP_INIT` is offline. A host in that state launches roughly one
/// ASID pool's worth of guests after boot, then refuses every new one
/// until it reboots.
///
/// Observability only — vali alerts on them and never lets them change
/// placement, so a miner misreporting them can only hide its own fault
/// from the operator.
///
/// `v5` is OPT-IN (the miner-agent's `[heartbeat] schema_host_health`);
/// vali's verifier MUST accept it before any miner emits it.
pub const SCHEMA_VERSION_HOST_HEALTH: u8 = 5;

/// The `schema_version` of a `v6` heartbeat — the full `v5` body PLUS one
/// `agent_version` text key: the release tag the miner-agent binary was
/// built from (`dev` for an untagged build).
///
/// Observability only — vali records it to see which hosts run which
/// agent release (and whether an auto-update landed), and never lets it
/// change placement. A miner lying about it only misleads the operator
/// about itself.
///
/// `v6` is OPT-IN (the miner-agent's `[heartbeat] schema_agent_version`,
/// which requires `schema_host_health`). This is miner → vali data, so
/// vali's verifier (the `ticket-validator` binary in the vali image) MUST
/// accept it before any miner emits it.
pub const SCHEMA_VERSION_AGENT_VERSION: u8 = 6;

/// Hard upper bound on the `v6` `agent_version` length, in bytes. Mirrors
/// the vali `MinerCapacity.agent_version` column (`max_length=32`).
pub const MAX_AGENT_VERSION_LEN: usize = 32;

/// `true` when `v` is a well-formed `v6` `agent_version`: 1 to
/// [`MAX_AGENT_VERSION_LEN`] bytes of ASCII `[0-9A-Za-z._-]`. The narrow
/// charset keeps the value safe to put in a log line or a metric label.
pub fn is_valid_agent_version(v: &str) -> bool {
    !v.is_empty()
        && v.len() <= MAX_AGENT_VERSION_LEN
        && v.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'_' || b == b'-')
}

/// Anti-skew window, in seconds. vali rejects a heartbeat whose
/// `timestamp_unix` is more than this far from its own clock — in
/// either direction.
pub const MAX_AGE_SECONDS: i64 = 300;

/// Hard upper bound on the `miner_id` length, in bytes. Mirrors the
/// `vali` `MinerIdentity.miner_id` column (`max_length=64`). A longer
/// id is malformed — fail closed at encode.
pub const MAX_MINER_ID_LEN: usize = 64;

/// Length of an Ed25519 signature — the `sig` field of the envelope.
pub const SIGNATURE_LEN: usize = 64;

/// Fixed-classifier error for the heartbeat wire format.
///
/// Every `Display` is a `&'static str` — there is no `{0}`
/// interpolation that could splice a run-time value into a log line
/// (the §K logging discipline). The variants are a closed vocabulary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HeartbeatError {
    /// `schema_version` was not [`SCHEMA_VERSION`].
    SchemaVersion,
    /// `domain` was not [`DOMAIN`].
    Domain,
    /// `miner_id` was empty or longer than [`MAX_MINER_ID_LEN`].
    MinerId,
    /// `sig` was not [`SIGNATURE_LEN`] bytes.
    SignatureLength,
    /// The canonical-CBOR encode failed.
    Encode,
    /// A `v3` capacity declaration was self-contradictory
    /// (`asid_used > asid_capacity` with a known, non-zero capacity), or a
    /// `v4` disk declaration was (`data_disk_available_gb >
    /// data_disk_total_gb` with a known, non-zero total).
    Capacity,
    /// A `v6` `agent_version` was empty, longer than
    /// [`MAX_AGENT_VERSION_LEN`], or outside `[0-9A-Za-z._-]`.
    AgentVersion,
}

impl core::fmt::Display for HeartbeatError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl HeartbeatError {
    /// The fixed classifier — identical to the `Display` impl. Named
    /// contract for callers that log a classifier.
    pub fn as_str(&self) -> &'static str {
        match self {
            HeartbeatError::SchemaVersion => "heartbeat-schema-version",
            HeartbeatError::Domain => "heartbeat-domain",
            HeartbeatError::MinerId => "heartbeat-miner-id",
            HeartbeatError::SignatureLength => "heartbeat-signature-length",
            HeartbeatError::Encode => "heartbeat-encode",
            HeartbeatError::Capacity => "heartbeat-capacity",
            HeartbeatError::AgentVersion => "heartbeat-agent-version",
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for HeartbeatError {}

/// Crate-local result alias for the heartbeat wire format.
pub type Result<T> = core::result::Result<T, HeartbeatError>;

/// The body the miner-agent signs (and vali re-derives + verifies).
///
/// Fields chosen so the heartbeat ALONE pins liveness to a single
/// miner at a single instant:
///
/// - `miner_id` — which registered miner (the trust-registry key);
/// - `timestamp_unix` — the miner's wall-clock view, anti-skew-checked;
/// - `sequence` — a per-miner monotonic counter, persisted across
///   restarts; vali rejects any value ≤ the last accepted one (replay
///   defence);
/// - the `vm_*` / `cpu_*` / `memory_*` counters — coarse host state the
///   scheduler may use as a soft signal;
/// - `domain` — the replay-context separator (also encoded into the
///   signed bytes).
///
/// `schema_version` pins the wire format; an unknown value fails
/// closed at [`validate`](Self::validate).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MinerHeartbeat {
    /// Wire-format version. MUST be [`SCHEMA_VERSION`].
    pub schema_version: u8,
    /// Operator-assigned miner identifier — the `vali` registry key.
    pub miner_id: String,
    /// The miner's wall-clock at build time, Unix seconds.
    pub timestamp_unix: i64,
    /// Per-miner monotonic counter, persisted to disk across restarts.
    pub sequence: u64,
    /// Tenant CVMs currently in the running phase.
    pub vm_count_running: u32,
    /// Tenant CVMs the lifecycle is tracking (any phase).
    pub vm_count_total: u32,
    /// 1-minute load average, in centi-units (load × 100).
    pub cpu_load_1m_centi: u32,
    /// Total host RAM, MiB.
    pub memory_total_mib: u32,
    /// Available host RAM, MiB.
    pub memory_available_mib: u32,
    /// Replay-domain tag. MUST be [`DOMAIN`].
    pub domain: String,
    /// `v2`-only graceful-exit flag (transport (B)). When `true`, this
    /// heartbeat is ALSO a self-requested graceful exit: vali accepts the
    /// heartbeat (the miner is alive, just leaving) AND quarantines the
    /// miner so the §13/§25 auto-migration warm-migrates its VMs off. It
    /// is the always-on passive complement to the Edge-relayed
    /// `SignedGracefulExit` request — a second, redundant signal path.
    ///
    /// A `v1` heartbeat ([`SCHEMA_VERSION`]) NEVER carries this: it is
    /// not in the `v1` canonical map, and [`validate`](Self::validate)
    /// rejects a `v1` body whose flag is `true`. Only a `v2` heartbeat
    /// ([`SCHEMA_VERSION_GRACEFUL_EXIT`]) encodes it.
    pub graceful_exit_requested: bool,
    /// `v3`-only: the vCPU budget the miner's own preflight gate admits
    /// tenant CVMs against (`[host] cvm_cpu_budget`). `0` = unknown.
    /// Never in a `v1`/`v2` body ([`validate`](Self::validate) rejects a
    /// non-zero value there).
    pub cvm_cpu_budget: u32,
    /// `v3`-only: the memory budget (MiB) of the miner's own preflight
    /// gate (`[host] cvm_memory_mb_budget`). `0` = unknown.
    pub cvm_memory_mb_budget: u32,
    /// `v3`-only: SEV-ES ASIDs the host kernel exposes
    /// (`misc.capacity sev_es`). `0` = unknown.
    pub asid_capacity: u32,
    /// `v3`-only: SEV-ES ASIDs in use (`misc.current sev_es`). `0` =
    /// unknown or none in use. Never above a non-zero `asid_capacity`.
    pub asid_used: u32,
    /// `v4`/`v5` disk declarations. All zero (= absent) in a
    /// `v1`/`v2`/`v3` body ([`validate`](Self::validate) rejects a
    /// non-zero value there).
    pub disk: DiskDeclaration,
    /// `v5`/`v6` host-health report. All zero / `false` (= absent) in
    /// every earlier body ([`validate`](Self::validate) rejects anything
    /// else there).
    pub host_health: HostHealthDeclaration,
    /// `v6`-only: the miner-agent's release tag. Empty (= absent) in every
    /// earlier body ([`validate`](Self::validate) rejects anything else
    /// there); in a `v6` body it must pass [`is_valid_agent_version`].
    pub agent_version: String,
}

impl MinerHeartbeat {
    /// Every semantic invariant of a well-formed heartbeat. Run by
    /// [`canonical`](Self::canonical) so a signature over an impossible
    /// value can never be produced; a decoder MUST run it too.
    pub fn validate(&self) -> Result<()> {
        // Accept the six wire versions — `v1` (the frozen 10-field
        // baseline), `v2` (the 11-field graceful-exit-flag form), `v3`
        // (`v2` + the four capacity declarations), `v4` (`v3` + the four
        // disk declarations), `v5` (`v4` + the four host-health fields)
        // and `v6` (`v5` + `agent_version`). Any other value fails closed.
        if self.schema_version != SCHEMA_VERSION
            && self.schema_version != SCHEMA_VERSION_GRACEFUL_EXIT
            && self.schema_version != SCHEMA_VERSION_CAPACITY
            && self.schema_version != SCHEMA_VERSION_DISK
            && self.schema_version != SCHEMA_VERSION_HOST_HEALTH
            && self.schema_version != SCHEMA_VERSION_AGENT_VERSION
        {
            return Err(HeartbeatError::SchemaVersion);
        }
        // A `v1` heartbeat CANNOT carry the graceful-exit flag: the flag
        // is not a `v1` wire field, so a `v1` body with it set is
        // malformed (it would never round-trip through the `v1`
        // canonical map). This keeps the flag strictly a `v2` concept.
        if self.schema_version == SCHEMA_VERSION && self.graceful_exit_requested {
            return Err(HeartbeatError::SchemaVersion);
        }
        // Same rule for the capacity declarations: they are `v3`/`v4`
        // wire fields only, so a `v1`/`v2` body carrying any of them
        // non-zero would never round-trip through its own canonical map.
        if !self.carries_capacity_keys() && self.has_capacity_fields() {
            return Err(HeartbeatError::SchemaVersion);
        }
        // …the disk declarations are `v4`/`v5`-only…
        if !self.carries_disk_keys() && self.disk != DiskDeclaration::default() {
            return Err(HeartbeatError::SchemaVersion);
        }
        // …the host-health report is `v5`/`v6`-only…
        if !self.carries_host_health_keys() && self.host_health != HostHealthDeclaration::default()
        {
            return Err(HeartbeatError::SchemaVersion);
        }
        // …and `agent_version` is `v6`-only, where it is mandatory and
        // well-formed.
        if self.schema_version == SCHEMA_VERSION_AGENT_VERSION {
            if !is_valid_agent_version(&self.agent_version) {
                return Err(HeartbeatError::AgentVersion);
            }
        } else if !self.agent_version.is_empty() {
            return Err(HeartbeatError::SchemaVersion);
        }
        // A known ASID capacity bounds the in-use count. (`capacity == 0`
        // is "unknown", so `asid_used` is unconstrained there.)
        if self.asid_capacity != 0 && self.asid_used > self.asid_capacity {
            return Err(HeartbeatError::Capacity);
        }
        // Likewise a known data-fs size bounds its free space (`statvfs`
        // `f_bavail <= f_blocks`).
        if self.disk.data_disk_total_gb != 0
            && self.disk.data_disk_available_gb > self.disk.data_disk_total_gb
        {
            return Err(HeartbeatError::Capacity);
        }
        if self.domain != DOMAIN {
            return Err(HeartbeatError::Domain);
        }
        if self.miner_id.is_empty() || self.miner_id.len() > MAX_MINER_ID_LEN {
            return Err(HeartbeatError::MinerId);
        }
        Ok(())
    }

    /// `true` for the versions whose canonical map carries the four
    /// capacity keys (`v3` and its supersets `v4`, `v5` and `v6`).
    fn carries_capacity_keys(&self) -> bool {
        self.schema_version == SCHEMA_VERSION_CAPACITY || self.carries_disk_keys()
    }

    /// `true` for the versions whose canonical map carries the four disk
    /// keys (`v4` and its supersets `v5` and `v6`).
    fn carries_disk_keys(&self) -> bool {
        self.schema_version == SCHEMA_VERSION_DISK || self.carries_host_health_keys()
    }

    /// `true` for the versions whose canonical map carries the four
    /// host-health keys (`v5` and its superset `v6`).
    fn carries_host_health_keys(&self) -> bool {
        self.schema_version == SCHEMA_VERSION_HOST_HEALTH
            || self.schema_version == SCHEMA_VERSION_AGENT_VERSION
    }

    /// `true` when any `v3`-only capacity field is non-zero.
    fn has_capacity_fields(&self) -> bool {
        self.cvm_cpu_budget != 0
            || self.cvm_memory_mb_budget != 0
            || self.asid_capacity != 0
            || self.asid_used != 0
    }

    /// Deterministic-CBOR encoding of the to-be-signed body — the
    /// signature preimage. Fails closed on any
    /// [`validate`](Self::validate) violation.
    pub fn canonical(&self) -> Result<Vec<u8>> {
        self.validate()?;
        // `to_canonical_vec` re-sorts the map by its ENCODED key bytes
        // (RFC 8949 §4.2.1 deterministic encoding: length-first, then
        // bytewise), so the order we push entries in here is irrelevant —
        // the encoder fixes it. `graceful_exit_requested` (23 chars) is
        // the longest key, so it canonically sorts LAST.
        //
        // `v1` emits EXACTLY the 10 keys it always has — the flag is
        // NOT pushed, so a `v1` heartbeat re-encodes byte-identically to
        // every prior build (the `heartbeat_kat` vector is unchanged).
        // `v2` adds the 11th key, which the canonical encoder places at
        // the end. The `schema_version` value is the ONLY change to a
        // shared field's encoding between the two versions. `v3` is the
        // `v2` map plus the four capacity keys (the encoder sorts them in),
        // `v4` is the `v3` map plus the four disk keys, `v5` is the `v4`
        // map plus the four host-health keys, and `v6` is the `v5` map plus
        // `agent_version`.
        let mut entries = vec![
            (
                Value::Text("cpu_load_1m_centi".into()),
                Value::Integer(self.cpu_load_1m_centi.into()),
            ),
            (Value::Text("domain".into()), Value::Text(DOMAIN.into())),
        ];
        if self.schema_version == SCHEMA_VERSION_GRACEFUL_EXIT || self.carries_capacity_keys() {
            entries.push((
                Value::Text("graceful_exit_requested".into()),
                Value::Bool(self.graceful_exit_requested),
            ));
        }
        if self.carries_capacity_keys() {
            entries.extend([
                (
                    Value::Text("asid_capacity".into()),
                    Value::Integer(self.asid_capacity.into()),
                ),
                (
                    Value::Text("asid_used".into()),
                    Value::Integer(self.asid_used.into()),
                ),
                (
                    Value::Text("cvm_cpu_budget".into()),
                    Value::Integer(self.cvm_cpu_budget.into()),
                ),
                (
                    Value::Text("cvm_memory_mb_budget".into()),
                    Value::Integer(self.cvm_memory_mb_budget.into()),
                ),
            ]);
        }
        if self.carries_disk_keys() {
            entries.extend([
                (
                    Value::Text("cvm_disk_gb_budget".into()),
                    Value::Integer(self.disk.cvm_disk_gb_budget.into()),
                ),
                (
                    Value::Text("data_disk_total_gb".into()),
                    Value::Integer(self.disk.data_disk_total_gb.into()),
                ),
                (
                    Value::Text("data_disk_available_gb".into()),
                    Value::Integer(self.disk.data_disk_available_gb.into()),
                ),
                (
                    Value::Text("staging_disk_available_gb".into()),
                    Value::Integer(self.disk.staging_disk_available_gb.into()),
                ),
            ]);
        }
        if self.carries_host_health_keys() {
            entries.extend([
                (
                    Value::Text("cpus_offline".into()),
                    Value::Integer(self.host_health.cpus_offline.into()),
                ),
                (
                    Value::Text("df_flush_failures".into()),
                    Value::Integer(self.host_health.df_flush_failures.into()),
                ),
                (
                    Value::Text("snp_enabled".into()),
                    Value::Bool(self.host_health.snp_enabled),
                ),
                (
                    Value::Text("snp_launches_since_boot".into()),
                    Value::Integer(self.host_health.snp_launches_since_boot.into()),
                ),
            ]);
        }
        if self.schema_version == SCHEMA_VERSION_AGENT_VERSION {
            entries.push((
                Value::Text("agent_version".into()),
                Value::Text(self.agent_version.clone()),
            ));
        }
        entries.extend([
            (
                Value::Text("memory_available_mib".into()),
                Value::Integer(self.memory_available_mib.into()),
            ),
            (
                Value::Text("memory_total_mib".into()),
                Value::Integer(self.memory_total_mib.into()),
            ),
            (
                Value::Text("miner_id".into()),
                Value::Text(self.miner_id.clone()),
            ),
            (
                Value::Text("schema_version".into()),
                Value::Integer(self.schema_version.into()),
            ),
            (
                Value::Text("sequence".into()),
                Value::Integer(self.sequence.into()),
            ),
            (
                Value::Text("timestamp_unix".into()),
                Value::Integer(self.timestamp_unix.into()),
            ),
            (
                Value::Text("vm_count_running".into()),
                Value::Integer(self.vm_count_running.into()),
            ),
            (
                Value::Text("vm_count_total".into()),
                Value::Integer(self.vm_count_total.into()),
            ),
        ]);
        to_canonical_vec(&Value::Map(entries)).map_err(|_| HeartbeatError::Encode)
    }

    /// Build a `v2` graceful-exit heartbeat from the live metrics of an
    /// ordinary heartbeat — transport (B).
    ///
    /// Takes every field of a normally-built heartbeat (`miner_id`, the
    /// timestamp, the monotonic `sequence`, the VM + host counters) and
    /// produces the SAME body with `schema_version = `
    /// [`SCHEMA_VERSION_GRACEFUL_EXIT`] and `graceful_exit_requested =
    /// true`. The miner-agent emits one of these to piggyback its
    /// graceful-exit intent on the liveness channel; vali accepts the
    /// heartbeat AND quarantines the miner.
    ///
    /// `domain` is forced to [`DOMAIN`] — the flag rides the SAME signed
    /// heartbeat scheme, never a separate one.
    #[allow(clippy::too_many_arguments)]
    pub fn graceful_exit(
        miner_id: String,
        timestamp_unix: i64,
        sequence: u64,
        vm_count_running: u32,
        vm_count_total: u32,
        cpu_load_1m_centi: u32,
        memory_total_mib: u32,
        memory_available_mib: u32,
    ) -> Self {
        Self {
            schema_version: SCHEMA_VERSION_GRACEFUL_EXIT,
            miner_id,
            timestamp_unix,
            sequence,
            vm_count_running,
            vm_count_total,
            cpu_load_1m_centi,
            memory_total_mib,
            memory_available_mib,
            domain: DOMAIN.into(),
            graceful_exit_requested: true,
            cvm_cpu_budget: 0,
            cvm_memory_mb_budget: 0,
            asid_capacity: 0,
            asid_used: 0,
            disk: DiskDeclaration::default(),
            host_health: HostHealthDeclaration::default(),
            agent_version: String::new(),
        }
    }

    /// Upgrade an ordinary (`v1`) heartbeat to `v3`, attaching the
    /// miner's capacity declarations. Every other field is preserved;
    /// `graceful_exit_requested` is left as-is (an ordinary heartbeat
    /// carries `false`).
    pub fn with_capacity(mut self, capacity: CapacityDeclaration) -> Self {
        self.schema_version = SCHEMA_VERSION_CAPACITY;
        self.cvm_cpu_budget = capacity.cvm_cpu_budget;
        self.cvm_memory_mb_budget = capacity.cvm_memory_mb_budget;
        self.asid_capacity = capacity.asid_capacity;
        self.asid_used = capacity.asid_used;
        self
    }

    /// Upgrade an ordinary (`v1`) heartbeat to `v4`: the `v3` capacity
    /// declarations plus the disk declarations. Every other field is
    /// preserved, like [`with_capacity`](Self::with_capacity).
    pub fn with_disk(self, capacity: CapacityDeclaration, disk: DiskDeclaration) -> Self {
        let mut hb = self.with_capacity(capacity);
        hb.schema_version = SCHEMA_VERSION_DISK;
        hb.disk = disk;
        hb
    }

    /// Upgrade an ordinary (`v1`) heartbeat to `v5`: the `v4` capacity and
    /// disk declarations plus the host-health report. Every other field is
    /// preserved, like [`with_capacity`](Self::with_capacity).
    pub fn with_host_health(
        self,
        capacity: CapacityDeclaration,
        disk: DiskDeclaration,
        host_health: HostHealthDeclaration,
    ) -> Self {
        let mut hb = self.with_disk(capacity, disk);
        hb.schema_version = SCHEMA_VERSION_HOST_HEALTH;
        hb.host_health = host_health;
        hb
    }

    /// Upgrade an ordinary (`v1`) heartbeat to `v6`: the `v5` capacity,
    /// disk and host-health declarations plus the agent's release tag.
    /// Every other field is preserved, like
    /// [`with_capacity`](Self::with_capacity). A malformed tag is caught by
    /// [`validate`](Self::validate), not here.
    pub fn with_agent_version(
        self,
        capacity: CapacityDeclaration,
        disk: DiskDeclaration,
        host_health: HostHealthDeclaration,
        agent_version: String,
    ) -> Self {
        let mut hb = self.with_host_health(capacity, disk, host_health);
        hb.schema_version = SCHEMA_VERSION_AGENT_VERSION;
        hb.agent_version = agent_version;
        hb
    }
}

/// The four `v3` capacity declarations, as the miner-agent reads them.
/// `0` in any field = unknown.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct CapacityDeclaration {
    /// `[host] cvm_cpu_budget` of the miner's own preflight gate.
    pub cvm_cpu_budget: u32,
    /// `[host] cvm_memory_mb_budget` of the miner's own preflight gate.
    pub cvm_memory_mb_budget: u32,
    /// `misc.capacity sev_es`.
    pub asid_capacity: u32,
    /// `misc.current sev_es`.
    pub asid_used: u32,
}

/// The four `v4` disk declarations, in GiB (rounded down). `0` in any
/// field = unknown / undeclared. All are miner self-reports — vali only
/// ever lets them LOWER its own disk ledger.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct DiskDeclaration {
    /// `[host] cvm_disk_gb_budget` — the tenant disk the operator
    /// declares, and the budget the miner's own gates reserve against.
    pub cvm_disk_gb_budget: u32,
    /// `statvfs` size of the filesystem holding the per-VM writable disks
    /// (`[storage] data_disk_root`).
    pub data_disk_total_gb: u32,
    /// `statvfs` space available to the agent on that filesystem, raw
    /// (`f_bavail`). The per-VM disks are sparse, so this is NOT net of the
    /// space they have been promised but not yet written.
    pub data_disk_available_gb: u32,
    /// `statvfs` space available on the filesystem holding the agent's
    /// staging / image cache (`/var/lib/hippius-miner`). Equal to
    /// `data_disk_available_gb` when both live on one filesystem.
    pub staging_disk_available_gb: u32,
}

/// The four `v5` host-health fields. Miner self-reports, used by vali only
/// to alert: none of them moves placement.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct HostHealthDeclaration {
    /// `kvm_amd` has SEV-SNP enabled (`/sys/module/kvm_amd/parameters/sev_snp`).
    /// `false` also when it cannot be read.
    pub snp_enabled: bool,
    /// Present CPUs that are offline (`present` minus `online`, `/sys/devices/system/cpu`).
    /// Non-zero next to `snp_enabled` = `SNP_DF_FLUSH` fails, so the host
    /// stops launching SNP guests once its ASID pool is used up.
    pub cpus_offline: u32,
    /// SNP guest starts the agent has issued since the host booted (each
    /// one may draw a fresh ASID). `0` = none, or unknown. A lower bound:
    /// counting starts with the first agent that had the counter this boot.
    pub snp_launches_since_boot: u32,
    /// Kernel `DF_FLUSH failed` lines since boot. Non-zero = the host
    /// refuses every new SNP guest until it reboots.
    pub df_flush_failures: u32,
}

/// Signed heartbeat envelope.
///
/// `body` is the canonical CBOR of a [`MinerHeartbeat`] (its
/// [`canonical`](MinerHeartbeat::canonical) output); `sig` is the
/// 64-byte Ed25519 signature over `body` by the miner identity key.
///
/// `#[serde(deny_unknown_fields)]` blocks an extra-key smuggle past
/// the envelope decode — defence in depth for the relay path.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SignedMinerHeartbeat {
    #[serde(with = "serde_bytes")]
    pub body: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub sig: Vec<u8>,
}

impl SignedMinerHeartbeat {
    /// Deterministic-CBOR encoding of the `{body, sig}` envelope.
    ///
    /// `body` is already canonical (it is the inner heartbeat's
    /// `canonical()` output); this wraps it with the signature so the
    /// whole envelope re-encodes byte-identically on every hop. This
    /// is exactly the blob the Edge relays opaquely (§5.6) and vali
    /// ingests.
    pub fn canonical(&self) -> Result<Vec<u8>> {
        if self.sig.len() != SIGNATURE_LEN {
            return Err(HeartbeatError::SignatureLength);
        }
        let v = Value::Map(vec![
            (Value::Text("body".into()), Value::Bytes(self.body.clone())),
            (Value::Text("sig".into()), Value::Bytes(self.sig.clone())),
        ]);
        to_canonical_vec(&v).map_err(|_| HeartbeatError::Encode)
    }

    /// SHA-256 over the `body` of the signed heartbeat — the value a
    /// log line carries instead of the body bytes (§K logging
    /// discipline: only `body_hash + kind + miner_id`, never bytes).
    pub fn body_hash(&self) -> [u8; 32] {
        let mut out = [0u8; 32];
        out.copy_from_slice(Sha256::digest(&self.body).as_slice());
        out
    }

    /// Extract the inner `MinerHeartbeat.timestamp_unix` directly from
    /// the canonical-CBOR `body` — a read-only accessor, no decode of
    /// the full struct.
    ///
    /// The miner-agent's pusher uses this to drop heartbeats that have
    /// aged past vali's [`MAX_AGE_SECONDS`] anti-skew window: the
    /// envelope is signed at build time, so a stale one cannot be
    /// rescued by re-signing (that would break the canonical-CBOR
    /// signed-envelope invariant) — it must be discarded rather than
    /// burned indefinitely on the wire.
    ///
    /// Returns `None` on a corrupt / wrong-shape body, or a body that
    /// does not carry the field as a CBOR integer; the caller treats
    /// it as stale-equivalent (vali would refuse to verify it anyway).
    /// Note: a body that is decodable but **not canonically** encoded
    /// also returns the field — this accessor's job is the local
    /// staleness check, not canonical validation. The wire path's
    /// canonical-CBOR check lives in vali's verifier shell-out.
    pub fn timestamp_unix(&self) -> Option<i64> {
        let v: Value = ciborium::de::from_reader(self.body.as_slice()).ok()?;
        let entries = match v {
            Value::Map(e) => e,
            _ => return None,
        };
        for (k, val) in entries {
            if matches!(&k, Value::Text(t) if t == "timestamp_unix") {
                if let Value::Integer(i) = val {
                    let n: i128 = i.into();
                    return i64::try_from(n).ok();
                }
                return None;
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cbor::assert_canonical;

    fn sample() -> MinerHeartbeat {
        MinerHeartbeat {
            schema_version: SCHEMA_VERSION,
            miner_id: "miner-a".into(),
            timestamp_unix: 1_700_000_000,
            sequence: 42,
            vm_count_running: 3,
            vm_count_total: 5,
            cpu_load_1m_centi: 175,
            memory_total_mib: 262_144,
            memory_available_mib: 131_072,
            domain: DOMAIN.into(),
            graceful_exit_requested: false,
            cvm_cpu_budget: 0,
            cvm_memory_mb_budget: 0,
            asid_capacity: 0,
            asid_used: 0,
            disk: DiskDeclaration::default(),
            host_health: HostHealthDeclaration::default(),
            agent_version: String::new(),
        }
    }

    fn host_health() -> HostHealthDeclaration {
        HostHealthDeclaration {
            snp_enabled: true,
            cpus_offline: 24,
            snp_launches_since_boot: 97,
            df_flush_failures: 3,
        }
    }

    fn disk() -> DiskDeclaration {
        DiskDeclaration {
            cvm_disk_gb_budget: 3_000,
            data_disk_total_gb: 3_500,
            data_disk_available_gb: 2_900,
            staging_disk_available_gb: 400,
        }
    }

    fn capacity() -> CapacityDeclaration {
        CapacityDeclaration {
            cvm_cpu_budget: 44,
            cvm_memory_mb_budget: 120_000,
            asid_capacity: 99,
            asid_used: 2,
        }
    }

    #[test]
    fn canonical_is_stable_and_canonical() {
        let hb = sample();
        let a = hb.canonical().unwrap();
        let b = hb.canonical().unwrap();
        assert_eq!(a, b);
        assert_canonical(&a).unwrap();
    }

    /// Walk the top-level CBOR map and return its keys in wire order —
    /// a test helper that proves the canonical key sequence.
    fn canonical_keys(bytes: &[u8]) -> Vec<String> {
        let v: Value = ciborium::de::from_reader(bytes).unwrap();
        match v {
            Value::Map(entries) => entries
                .into_iter()
                .map(|(k, _)| match k {
                    Value::Text(t) => t,
                    _ => panic!("non-text key"),
                })
                .collect(),
            _ => panic!("body is not a CBOR map"),
        }
    }

    #[test]
    fn v1_canonical_has_exactly_the_ten_frozen_keys() {
        // The `v1` baseline — the flag is NOT present, the key set + order
        // are byte-frozen (also pinned by the `heartbeat_kat` vector).
        let hb = sample();
        assert_eq!(hb.schema_version, SCHEMA_VERSION);
        let keys = canonical_keys(&hb.canonical().unwrap());
        // RFC 8949 deterministic order — by ENCODED key bytes
        // (length-first, then bytewise), NOT plain lexicographic.
        assert_eq!(
            keys,
            vec![
                "domain",
                "miner_id",
                "sequence",
                "schema_version",
                "timestamp_unix",
                "vm_count_total",
                "memory_total_mib",
                "vm_count_running",
                "cpu_load_1m_centi",
                "memory_available_mib",
            ],
            "v1 canonical key set/order must never shift"
        );
    }

    #[test]
    fn v2_canonical_inserts_the_flag_in_sorted_position() {
        // `v2` adds exactly one key, `graceful_exit_requested`, sorted
        // AFTER `domain` and BEFORE `memory_available_mib` — 11 keys.
        let hb = MinerHeartbeat::graceful_exit(
            "miner-a".into(),
            1_700_000_000,
            42,
            3,
            5,
            175,
            262_144,
            131_072,
        );
        let bytes = hb.canonical().unwrap();
        assert_canonical(&bytes).unwrap();
        let keys = canonical_keys(&bytes);
        // The 23-char flag key is the LONGEST, so RFC 8949 length-first
        // deterministic ordering places it LAST. The other 10 keys keep
        // their exact v1 positions.
        assert_eq!(
            keys,
            vec![
                "domain",
                "miner_id",
                "sequence",
                "schema_version",
                "timestamp_unix",
                "vm_count_total",
                "memory_total_mib",
                "vm_count_running",
                "cpu_load_1m_centi",
                "memory_available_mib",
                "graceful_exit_requested",
            ],
            "v2 appends the flag as the canonically-last (longest) key"
        );
    }

    #[test]
    fn v1_and_v2_differ_only_by_the_flag_key_and_schema_version() {
        // The shared metric fields are byte-identical between versions —
        // the ONLY differences are the inserted flag key and the
        // `schema_version` value. Proven by stripping both back to a
        // common projection. (Direct evidence that adding the flag did
        // not perturb any v1 field encoding.)
        let v1 = sample();
        let v2 = MinerHeartbeat::graceful_exit(
            v1.miner_id.clone(),
            v1.timestamp_unix,
            v1.sequence,
            v1.vm_count_running,
            v1.vm_count_total,
            v1.cpu_load_1m_centi,
            v1.memory_total_mib,
            v1.memory_available_mib,
        );
        let v1_keys = canonical_keys(&v1.canonical().unwrap());
        let v2_keys: Vec<String> = canonical_keys(&v2.canonical().unwrap())
            .into_iter()
            .filter(|k| k != "graceful_exit_requested")
            .collect();
        assert_eq!(v1_keys, v2_keys);
    }

    #[test]
    fn v2_with_flag_false_is_still_valid_and_eleven_keys() {
        // A `v2` heartbeat with the flag `false` is a legitimate
        // (non-exiting) heartbeat — it still carries the 11th key (the
        // version, not the flag value, decides the wire shape).
        let mut hb = MinerHeartbeat::graceful_exit("m".into(), 1, 1, 0, 0, 0, 0, 0);
        hb.graceful_exit_requested = false;
        assert!(hb.validate().is_ok());
        assert_eq!(canonical_keys(&hb.canonical().unwrap()).len(), 11);
    }

    #[test]
    fn v1_body_with_the_flag_true_is_rejected() {
        // A `v1` heartbeat MUST NOT carry the flag — fail closed.
        let mut hb = sample();
        hb.graceful_exit_requested = true;
        assert_eq!(hb.validate(), Err(HeartbeatError::SchemaVersion));
        assert!(hb.canonical().is_err());
    }

    #[test]
    fn graceful_exit_constructor_sets_v2_and_the_flag() {
        let hb = MinerHeartbeat::graceful_exit("m".into(), 1, 1, 0, 0, 0, 0, 0);
        assert_eq!(hb.schema_version, SCHEMA_VERSION_GRACEFUL_EXIT);
        assert!(hb.graceful_exit_requested);
        assert_eq!(hb.domain, DOMAIN);
        assert!(hb.validate().is_ok());
    }

    #[test]
    fn v3_canonical_is_v2_plus_the_four_capacity_keys() {
        let hb = sample().with_capacity(capacity());
        assert_eq!(hb.schema_version, SCHEMA_VERSION_CAPACITY);
        assert!(!hb.graceful_exit_requested);
        let bytes = hb.canonical().unwrap();
        assert_canonical(&bytes).unwrap();
        assert_eq!(
            canonical_keys(&bytes),
            vec![
                "domain",
                "miner_id",
                "sequence",
                "asid_used",
                "asid_capacity",
                "cvm_cpu_budget",
                "schema_version",
                "timestamp_unix",
                "vm_count_total",
                "memory_total_mib",
                "vm_count_running",
                "cpu_load_1m_centi",
                "cvm_memory_mb_budget",
                "memory_available_mib",
                "graceful_exit_requested",
            ],
        );
    }

    #[test]
    fn v3_with_all_capacity_unknown_still_carries_the_keys() {
        // The version, not the values, decides the wire shape.
        let hb = sample().with_capacity(CapacityDeclaration::default());
        assert!(hb.validate().is_ok());
        assert_eq!(canonical_keys(&hb.canonical().unwrap()).len(), 15);
    }

    #[test]
    fn v3_may_carry_the_graceful_exit_flag() {
        let mut hb = sample().with_capacity(capacity());
        hb.graceful_exit_requested = true;
        assert!(hb.validate().is_ok());
        let v: Value = ciborium::de::from_reader(hb.canonical().unwrap().as_slice()).unwrap();
        let Value::Map(entries) = v else {
            panic!("not a map")
        };
        assert!(entries.iter().any(|(k, v)| {
            matches!(k, Value::Text(t) if t == "graceful_exit_requested") && *v == Value::Bool(true)
        }));
    }

    #[test]
    fn v1_and_v2_bodies_with_any_capacity_field_are_rejected() {
        let setters: &[fn(&mut MinerHeartbeat)] = &[
            |h| h.cvm_cpu_budget = 1,
            |h| h.cvm_memory_mb_budget = 1,
            |h| h.asid_capacity = 1,
            |h| h.asid_used = 1,
        ];
        for set in setters {
            let mut v1 = sample();
            set(&mut v1);
            assert_eq!(v1.validate(), Err(HeartbeatError::SchemaVersion));
            assert!(v1.canonical().is_err());
            let mut v2 = MinerHeartbeat::graceful_exit("m".into(), 1, 1, 0, 0, 0, 0, 0);
            set(&mut v2);
            assert_eq!(v2.validate(), Err(HeartbeatError::SchemaVersion));
        }
    }

    #[test]
    fn asid_used_above_a_known_capacity_is_rejected_at_the_exact_boundary() {
        let mut hb = sample().with_capacity(capacity());
        hb.asid_capacity = 99;
        hb.asid_used = 99;
        assert!(hb.validate().is_ok(), "used == capacity is legal");
        hb.asid_used = 100;
        assert_eq!(hb.validate(), Err(HeartbeatError::Capacity));
        assert!(hb.canonical().is_err());
        // Unknown capacity (0) leaves `asid_used` unconstrained.
        hb.asid_capacity = 0;
        assert!(hb.validate().is_ok());
    }

    #[test]
    fn v3_capacity_fields_are_all_signed() {
        let base = sample().with_capacity(capacity()).canonical().unwrap();
        let mutate: &[fn(&mut MinerHeartbeat)] = &[
            |h| h.cvm_cpu_budget += 1,
            |h| h.cvm_memory_mb_budget += 1,
            |h| h.asid_capacity += 1,
            |h| h.asid_used += 1,
        ];
        for m in mutate {
            let mut h = sample().with_capacity(capacity());
            m(&mut h);
            assert_ne!(
                base,
                h.canonical().unwrap(),
                "a field escaped the signature"
            );
        }
    }

    #[test]
    fn v4_canonical_is_v3_plus_the_four_disk_keys() {
        let hb = sample().with_disk(capacity(), disk());
        assert_eq!(hb.schema_version, SCHEMA_VERSION_DISK);
        let bytes = hb.canonical().unwrap();
        assert_canonical(&bytes).unwrap();
        let v3_keys = canonical_keys(&sample().with_capacity(capacity()).canonical().unwrap());
        let v4_keys = canonical_keys(&bytes);
        let disk_keys = [
            "cvm_disk_gb_budget",
            "data_disk_total_gb",
            "data_disk_available_gb",
            "staging_disk_available_gb",
        ];
        assert_eq!(v4_keys.len(), 19);
        for k in disk_keys {
            assert!(v4_keys.iter().any(|x| x == k), "missing {k}");
        }
        let stripped: Vec<String> = v4_keys
            .into_iter()
            .filter(|k| !disk_keys.contains(&k.as_str()))
            .collect();
        assert_eq!(stripped, v3_keys, "v4 must not move a v3 key");
    }

    #[test]
    fn v4_with_all_disk_unknown_still_carries_the_keys() {
        let hb = sample().with_disk(capacity(), DiskDeclaration::default());
        assert!(hb.validate().is_ok());
        assert_eq!(canonical_keys(&hb.canonical().unwrap()).len(), 19);
    }

    #[test]
    fn v1_v2_v3_bodies_with_any_disk_field_are_rejected() {
        let setters: &[fn(&mut MinerHeartbeat)] = &[
            |h| h.disk.cvm_disk_gb_budget = 1,
            |h| h.disk.data_disk_total_gb = 1,
            |h| h.disk.data_disk_available_gb = 1,
            |h| h.disk.staging_disk_available_gb = 1,
        ];
        for set in setters {
            for mut hb in [
                sample(),
                MinerHeartbeat::graceful_exit("m".into(), 1, 1, 0, 0, 0, 0, 0),
                sample().with_capacity(capacity()),
            ] {
                set(&mut hb);
                assert_eq!(hb.validate(), Err(HeartbeatError::SchemaVersion));
                assert!(hb.canonical().is_err());
            }
        }
    }

    #[test]
    fn v4_data_available_above_a_known_total_is_rejected_at_the_exact_boundary() {
        let mut d = disk();
        d.data_disk_total_gb = 100;
        d.data_disk_available_gb = 100;
        assert!(sample().with_disk(capacity(), d).validate().is_ok());
        d.data_disk_available_gb = 101;
        let hb = sample().with_disk(capacity(), d);
        assert_eq!(hb.validate(), Err(HeartbeatError::Capacity));
        assert!(hb.canonical().is_err());
        // Unknown total (0) leaves `available` unconstrained.
        d.data_disk_total_gb = 0;
        assert!(sample().with_disk(capacity(), d).validate().is_ok());
    }

    #[test]
    fn v4_disk_and_capacity_fields_are_all_signed() {
        let base = sample().with_disk(capacity(), disk()).canonical().unwrap();
        let mutate: &[fn(&mut MinerHeartbeat)] = &[
            |h| h.disk.cvm_disk_gb_budget += 1,
            |h| h.disk.data_disk_total_gb += 1,
            |h| h.disk.data_disk_available_gb += 1,
            |h| h.disk.staging_disk_available_gb += 1,
            |h| h.cvm_cpu_budget += 1,
            |h| h.asid_used += 1,
        ];
        for m in mutate {
            let mut h = sample().with_disk(capacity(), disk());
            m(&mut h);
            assert_ne!(
                base,
                h.canonical().unwrap(),
                "a field escaped the signature"
            );
        }
    }

    const HOST_HEALTH_KEYS: [&str; 4] = [
        "cpus_offline",
        "df_flush_failures",
        "snp_enabled",
        "snp_launches_since_boot",
    ];

    #[test]
    fn v5_canonical_is_v4_plus_the_four_host_health_keys() {
        let hb = sample().with_host_health(capacity(), disk(), host_health());
        assert_eq!(hb.schema_version, SCHEMA_VERSION_HOST_HEALTH);
        let bytes = hb.canonical().unwrap();
        assert_canonical(&bytes).unwrap();
        let v4_keys = canonical_keys(&sample().with_disk(capacity(), disk()).canonical().unwrap());
        let v5_keys = canonical_keys(&bytes);
        assert_eq!(v5_keys.len(), 23);
        for k in HOST_HEALTH_KEYS {
            assert!(v5_keys.iter().any(|x| x == k), "missing {k}");
        }
        let stripped: Vec<String> = v5_keys
            .into_iter()
            .filter(|k| !HOST_HEALTH_KEYS.contains(&k.as_str()))
            .collect();
        assert_eq!(stripped, v4_keys, "v5 must not move a v4 key");
    }

    #[test]
    fn v5_with_a_healthy_host_still_carries_the_keys() {
        let hb = sample().with_host_health(capacity(), disk(), HostHealthDeclaration::default());
        assert!(hb.validate().is_ok());
        assert_eq!(canonical_keys(&hb.canonical().unwrap()).len(), 23);
    }

    #[test]
    fn earlier_bodies_with_any_host_health_field_are_rejected() {
        let setters: &[fn(&mut MinerHeartbeat)] = &[
            |h| h.host_health.snp_enabled = true,
            |h| h.host_health.cpus_offline = 1,
            |h| h.host_health.snp_launches_since_boot = 1,
            |h| h.host_health.df_flush_failures = 1,
        ];
        for set in setters {
            for mut hb in [
                sample(),
                MinerHeartbeat::graceful_exit("m".into(), 1, 1, 0, 0, 0, 0, 0),
                sample().with_capacity(capacity()),
                sample().with_disk(capacity(), disk()),
            ] {
                set(&mut hb);
                assert_eq!(hb.validate(), Err(HeartbeatError::SchemaVersion));
                assert!(hb.canonical().is_err());
            }
        }
    }

    #[test]
    fn v5_keeps_the_v4_coherence_rules() {
        let mut d = disk();
        d.data_disk_total_gb = 100;
        d.data_disk_available_gb = 101;
        let hb = sample().with_host_health(capacity(), d, host_health());
        assert_eq!(hb.validate(), Err(HeartbeatError::Capacity));
        let mut c = capacity();
        c.asid_used = c.asid_capacity + 1;
        let hb = sample().with_host_health(c, disk(), host_health());
        assert_eq!(hb.validate(), Err(HeartbeatError::Capacity));
    }

    #[test]
    fn v5_host_health_fields_are_all_signed() {
        let base = sample()
            .with_host_health(capacity(), disk(), host_health())
            .canonical()
            .unwrap();
        let mutate: &[fn(&mut MinerHeartbeat)] = &[
            |h| h.host_health.snp_enabled = false,
            |h| h.host_health.cpus_offline += 1,
            |h| h.host_health.snp_launches_since_boot += 1,
            |h| h.host_health.df_flush_failures += 1,
            |h| h.disk.data_disk_total_gb += 1,
            |h| h.asid_used += 1,
        ];
        for m in mutate {
            let mut h = sample().with_host_health(capacity(), disk(), host_health());
            m(&mut h);
            assert_ne!(
                base,
                h.canonical().unwrap(),
                "a field escaped the signature"
            );
        }
    }

    fn v6() -> MinerHeartbeat {
        sample().with_agent_version(capacity(), disk(), host_health(), "v0.42.1".into())
    }

    #[test]
    fn v6_canonical_is_v5_plus_agent_version() {
        let hb = v6();
        assert_eq!(hb.schema_version, SCHEMA_VERSION_AGENT_VERSION);
        let bytes = hb.canonical().unwrap();
        assert_canonical(&bytes).unwrap();
        let v5_keys = canonical_keys(
            &sample()
                .with_host_health(capacity(), disk(), host_health())
                .canonical()
                .unwrap(),
        );
        let v6_keys = canonical_keys(&bytes);
        assert_eq!(v6_keys.len(), 24);
        let stripped: Vec<String> = v6_keys
            .into_iter()
            .filter(|k| k != "agent_version")
            .collect();
        assert_eq!(stripped, v5_keys, "v6 must not move a v5 key");
    }

    #[test]
    fn v6_accepts_the_dev_fallback_and_the_full_charset() {
        for tag in ["dev", "v1.2.3", "miner-agent_2026.10-rc.1", "A"] {
            let mut hb = v6();
            hb.agent_version = tag.into();
            assert!(hb.validate().is_ok(), "{tag}");
        }
        let mut hb = v6();
        hb.agent_version = "x".repeat(MAX_AGENT_VERSION_LEN);
        assert!(hb.validate().is_ok());
    }

    #[test]
    fn v6_rejects_a_missing_or_malformed_agent_version() {
        let long = "x".repeat(MAX_AGENT_VERSION_LEN + 1);
        for bad in [
            "",
            long.as_str(),
            "v1 2",
            "v1/2",
            "v1\n",
            "é",
            "v1:2",
            "v1+g",
        ] {
            let mut hb = v6();
            hb.agent_version = bad.into();
            assert_eq!(hb.validate(), Err(HeartbeatError::AgentVersion), "{bad:?}");
            assert!(hb.canonical().is_err());
        }
    }

    #[test]
    fn earlier_bodies_with_an_agent_version_are_rejected() {
        for mut hb in [
            sample(),
            MinerHeartbeat::graceful_exit("m".into(), 1, 1, 0, 0, 0, 0, 0),
            sample().with_capacity(capacity()),
            sample().with_disk(capacity(), disk()),
            sample().with_host_health(capacity(), disk(), host_health()),
        ] {
            hb.agent_version = "v1.0.0".into();
            assert_eq!(hb.validate(), Err(HeartbeatError::SchemaVersion));
            assert!(hb.canonical().is_err());
        }
    }

    #[test]
    fn v6_keeps_the_v5_and_v4_coherence_rules() {
        let mut d = disk();
        d.data_disk_total_gb = 100;
        d.data_disk_available_gb = 101;
        let hb = sample().with_agent_version(capacity(), d, host_health(), "dev".into());
        assert_eq!(hb.validate(), Err(HeartbeatError::Capacity));
        let mut c = capacity();
        c.asid_used = c.asid_capacity + 1;
        let hb = sample().with_agent_version(c, disk(), host_health(), "dev".into());
        assert_eq!(hb.validate(), Err(HeartbeatError::Capacity));
    }

    #[test]
    fn v6_fields_are_all_signed() {
        let base = v6().canonical().unwrap();
        let mutate: &[fn(&mut MinerHeartbeat)] = &[
            |h| h.agent_version = "v0.42.2".into(),
            |h| h.host_health.df_flush_failures += 1,
            |h| h.disk.data_disk_total_gb += 1,
            |h| h.asid_used += 1,
        ];
        for m in mutate {
            let mut h = v6();
            m(&mut h);
            assert_ne!(
                base,
                h.canonical().unwrap(),
                "a field escaped the signature"
            );
        }
    }

    #[test]
    fn wrong_schema_version_rejected() {
        // An UNKNOWN version (not 1 through 6) still fails closed.
        let mut hb = sample();
        hb.schema_version = 7;
        assert_eq!(hb.validate(), Err(HeartbeatError::SchemaVersion));
        assert!(hb.canonical().is_err());
    }

    #[test]
    fn wrong_domain_rejected() {
        let mut hb = sample();
        hb.domain = "HIPPIUS_OTHER_V1".into();
        assert_eq!(hb.validate(), Err(HeartbeatError::Domain));
        assert!(hb.canonical().is_err());
    }

    #[test]
    fn empty_or_oversize_miner_id_rejected() {
        let mut hb = sample();
        hb.miner_id = String::new();
        assert_eq!(hb.validate(), Err(HeartbeatError::MinerId));
        let mut hb = sample();
        hb.miner_id = "x".repeat(MAX_MINER_ID_LEN + 1);
        assert_eq!(hb.validate(), Err(HeartbeatError::MinerId));
    }

    #[test]
    fn changing_any_field_changes_signed_bytes() {
        let base = sample().canonical().unwrap();
        let mutate: &[fn(&mut MinerHeartbeat)] = &[
            |h| h.miner_id = "other-miner".into(),
            |h| h.timestamp_unix += 1,
            |h| h.sequence += 1,
            |h| h.vm_count_running += 1,
            |h| h.vm_count_total += 1,
            |h| h.cpu_load_1m_centi += 1,
            |h| h.memory_total_mib += 1,
            |h| h.memory_available_mib += 1,
        ];
        for m in mutate {
            let mut h = sample();
            m(&mut h);
            assert_ne!(
                base,
                h.canonical().unwrap(),
                "a field escaped the signature"
            );
        }
    }

    #[test]
    fn signed_envelope_canonical_is_stable_and_canonical() {
        let s = SignedMinerHeartbeat {
            body: sample().canonical().unwrap(),
            sig: vec![7u8; SIGNATURE_LEN],
        };
        let a = s.canonical().unwrap();
        let b = s.canonical().unwrap();
        assert_eq!(a, b);
        assert_canonical(&a).unwrap();
    }

    #[test]
    fn signed_envelope_rejects_wrong_sig_length() {
        let s = SignedMinerHeartbeat {
            body: sample().canonical().unwrap(),
            sig: vec![0u8; 63],
        };
        assert_eq!(s.canonical(), Err(HeartbeatError::SignatureLength));
    }

    #[test]
    fn body_hash_is_stable_and_32_bytes() {
        let s = SignedMinerHeartbeat {
            body: sample().canonical().unwrap(),
            sig: vec![0u8; SIGNATURE_LEN],
        };
        let d1 = s.body_hash();
        let d2 = s.body_hash();
        assert_eq!(d1, d2);
        assert_eq!(d1.len(), 32);
    }

    #[test]
    fn signed_envelope_timestamp_unix_reads_the_canonical_body() {
        let mut h = sample();
        h.timestamp_unix = 1_700_000_042;
        let s = SignedMinerHeartbeat {
            body: h.canonical().unwrap(),
            sig: vec![0u8; SIGNATURE_LEN],
        };
        assert_eq!(s.timestamp_unix(), Some(1_700_000_042));
    }

    #[test]
    fn signed_envelope_timestamp_unix_is_none_on_a_corrupt_body() {
        // A non-canonical body (not CBOR at all) — the accessor must
        // not panic; the caller treats `None` as stale-equivalent.
        let s = SignedMinerHeartbeat {
            body: vec![0xff, 0xff, 0xff],
            sig: vec![0u8; SIGNATURE_LEN],
        };
        assert!(s.timestamp_unix().is_none());
    }

    #[test]
    fn signed_envelope_timestamp_unix_is_none_when_the_field_is_missing() {
        // A valid CBOR map without `timestamp_unix` — accessor returns
        // `None`, the caller treats it as stale.
        let v = Value::Map(vec![(
            Value::Text("other".into()),
            Value::Integer(0.into()),
        )]);
        let bytes = to_canonical_vec(&v).unwrap();
        let s = SignedMinerHeartbeat {
            body: bytes,
            sig: vec![0u8; SIGNATURE_LEN],
        };
        assert!(s.timestamp_unix().is_none());
    }

    #[test]
    fn signed_envelope_rejects_unknown_field() {
        // `deny_unknown_fields` must trip — a `{body, sig, extra}`
        // envelope is a smuggle attempt.
        let v = Value::Map(vec![
            (Value::Text("body".into()), Value::Bytes(vec![1u8; 8])),
            (Value::Text("extra".into()), Value::Integer(0.into())),
            (
                Value::Text("sig".into()),
                Value::Bytes(vec![0u8; SIGNATURE_LEN]),
            ),
        ]);
        let bytes = to_canonical_vec(&v).unwrap();
        let decoded: core::result::Result<SignedMinerHeartbeat, _> =
            ciborium::de::from_reader(bytes.as_slice());
        assert!(decoded.is_err());
    }

    #[test]
    fn error_classifiers_are_stable() {
        for (err, class) in [
            (HeartbeatError::SchemaVersion, "heartbeat-schema-version"),
            (HeartbeatError::Domain, "heartbeat-domain"),
            (HeartbeatError::MinerId, "heartbeat-miner-id"),
            (
                HeartbeatError::SignatureLength,
                "heartbeat-signature-length",
            ),
            (HeartbeatError::Encode, "heartbeat-encode"),
            (HeartbeatError::Capacity, "heartbeat-capacity"),
            (HeartbeatError::AgentVersion, "heartbeat-agent-version"),
        ] {
            assert_eq!(err.as_str(), class);
            assert_eq!(err.to_string(), class);
        }
    }
}
