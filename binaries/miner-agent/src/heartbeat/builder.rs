//! The §K heartbeat builder (PR-MA-6).
//!
//! [`HeartbeatBuilder`] samples host metrics + the CVM lifecycle,
//! stamps the current Unix time, draws the next monotonic `sequence`,
//! encodes the canonical-CBOR body, and signs it with the miner
//! identity — producing a [`SignedMinerHeartbeat`] for the queue.
//!
//! ## Monotonic sequence — persisted across restarts
//!
//! vali rejects any heartbeat whose `sequence` is not strictly greater
//! than the last one it accepted (replay defence). The counter must
//! therefore SURVIVE a miner-agent restart: it is persisted to a small
//! file ([`SequenceStore`]) — read at startup, bumped + re-persisted
//! before each heartbeat is signed. The persist is crash-safe (temp
//! file → fsync → atomic rename) so a crash never leaves a torn or
//! regressed counter.
//!
//! No `chrono` dependency — `timestamp_unix` comes from
//! `SystemTime::now().duration_since(UNIX_EPOCH)`.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use hippius_types::heartbeat::{
    is_valid_agent_version, CapacityDeclaration, DiskDeclaration, HostHealthDeclaration,
    MinerHeartbeat, SignedMinerHeartbeat, DOMAIN, SCHEMA_VERSION,
};
use tempfile::NamedTempFile;

use crate::error::{MinerAgentError, Result};
use crate::host_health::HostHealthSource;
use crate::identity::MinerIdentity;
use crate::lifecycle::{CvmLifecycle, CvmPhase};
use crate::sev_asid::AsidSource;

use super::metrics::MetricsSource;

/// A crash-safe, monotonic on-disk counter for the heartbeat
/// `sequence`.
///
/// The file holds the last-used sequence as plain decimal ASCII. The
/// store reads it once, then [`next`](Self::next) bumps it and
/// re-persists atomically. Drawing the counter is fail-closed: an
/// unreadable / unparsable file is an error, never a silent reset to
/// `0` (a reset would let vali see a regressed sequence and reject
/// every heartbeat until it caught up).
pub struct SequenceStore {
    path: PathBuf,
    /// The last sequence number successfully persisted.
    last: u64,
}

impl SequenceStore {
    /// Open the store at `path`. A missing file starts the counter at
    /// `0` (the first [`next`](Self::next) yields `1`); an existing
    /// file MUST parse, or the open fails closed.
    pub fn open(path: &Path) -> Result<Self> {
        let last = match std::fs::read_to_string(path) {
            Ok(raw) => raw
                .trim()
                .parse::<u64>()
                .map_err(|_| MinerAgentError::HeartbeatSequence("parse"))?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => 0,
            Err(_) => return Err(MinerAgentError::HeartbeatSequence("read")),
        };
        Ok(Self {
            path: path.to_path_buf(),
            last,
        })
    }

    /// Draw the next sequence number: `last + 1`, persisted atomically
    /// to disk BEFORE it is returned, so a crash after this call can
    /// never re-issue the same value.
    ///
    /// Named `next` for clarity — a `SequenceStore` is a persisted
    /// monotonic counter, not an iterator; `clippy::should_implement_
    /// trait` is allowed here deliberately.
    #[allow(clippy::should_implement_trait)]
    pub fn next(&mut self) -> Result<u64> {
        let next = self
            .last
            .checked_add(1)
            .ok_or(MinerAgentError::HeartbeatSequence("write"))?;
        self.persist(next)?;
        self.last = next;
        Ok(next)
    }

    /// The last persisted sequence — for tests / diagnostics.
    pub fn last(&self) -> u64 {
        self.last
    }

    /// Crash-safe write of `value`: temp file in the target dir →
    /// fsync → atomic rename → directory fsync.
    fn persist(&self, value: u64) -> Result<()> {
        use std::io::Write;
        let dir = self
            .path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        std::fs::create_dir_all(dir).map_err(|_| MinerAgentError::HeartbeatSequence("write"))?;
        let mut tmp =
            NamedTempFile::new_in(dir).map_err(|_| MinerAgentError::HeartbeatSequence("write"))?;
        tmp.write_all(value.to_string().as_bytes())
            .map_err(|_| MinerAgentError::HeartbeatSequence("write"))?;
        tmp.flush()
            .map_err(|_| MinerAgentError::HeartbeatSequence("write"))?;
        tmp.as_file()
            .sync_all()
            .map_err(|_| MinerAgentError::HeartbeatSequence("write"))?;
        tmp.persist(&self.path)
            .map_err(|_| MinerAgentError::HeartbeatSequence("write"))?;
        if let Ok(d) = std::fs::File::open(dir) {
            // Directory fsync makes the rename durable; a failure here
            // is non-fatal (the data file is already fsynced).
            let _ = d.sync_all();
        }
        Ok(())
    }
}

/// Builds + signs one [`SignedMinerHeartbeat`] per call to
/// [`build`](Self::build).
pub struct HeartbeatBuilder {
    miner_id: String,
    identity: Arc<MinerIdentity>,
    lifecycle: Arc<CvmLifecycle>,
    metrics: Arc<dyn MetricsSource>,
    /// When set, [`build`](Self::build) emits the `v3` capacity
    /// heartbeat; `None` keeps the periodic heartbeat `v1`
    /// (`[heartbeat] schema_capacity = false`, the default).
    capacity: Option<CapacityDeclarer>,
    /// When set (with `capacity`), [`build`](Self::build) emits the `v4`
    /// disk heartbeat instead (`[heartbeat] schema_disk = true`).
    disk: Option<DiskDeclarer>,
    /// When set (with `capacity` and `disk`), [`build`](Self::build) emits
    /// the `v5` host-health heartbeat instead (`[heartbeat]
    /// schema_host_health = true`).
    host_health: Option<Arc<dyn HostHealthSource>>,
    /// When set (with `capacity`, `disk` and `host_health`) AND
    /// well-formed, [`build`](Self::build) emits the `v6` heartbeat
    /// carrying it (`[heartbeat] schema_agent_version = true`).
    agent_version: Option<String>,
}

/// What a `v3` heartbeat declares: the operator's `[host]` budgets (the
/// same numbers the #668 preflight gate admits against) and a live read
/// of the SEV-ES ASID pool.
pub struct CapacityDeclarer {
    /// `[host] cvm_cpu_budget`.
    pub cvm_cpu_budget: u32,
    /// `[host] cvm_memory_mb_budget`, saturated into `u32` MiB.
    pub cvm_memory_mb_budget: u32,
    /// The ASID pool reader.
    pub asids: Arc<dyn AsidSource>,
}

impl CapacityDeclarer {
    fn declare(&self) -> CapacityDeclaration {
        let asids = self.asids.read().coherent();
        CapacityDeclaration {
            cvm_cpu_budget: self.cvm_cpu_budget,
            cvm_memory_mb_budget: self.cvm_memory_mb_budget,
            asid_capacity: asids.capacity,
            asid_used: asids.used,
        }
    }
}

/// What a `v4` heartbeat declares about disk: the operator's `[host]
/// cvm_disk_gb_budget` and a live `statvfs` of the data + staging
/// filesystems.
pub struct DiskDeclarer {
    /// `[host] cvm_disk_gb_budget`, saturated into `u32` GiB.
    pub cvm_disk_gb_budget: u32,
    /// The filesystem reader.
    pub source: Arc<dyn DiskSource>,
}

/// A `statvfs` reading of the two filesystems a `v4` heartbeat reports.
/// GiB, rounded down; `0` = unknown.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct DiskReading {
    /// Size of the filesystem holding `[storage] data_disk_root`.
    pub data_total_gb: u32,
    /// Space still free on it for a new disk: `f_bavail` net of the
    /// unwritten tail of every per-VM disk there and of every in-flight
    /// reservation — the figure the agent's own create gate admits against
    /// ([`crate::lifecycle::disk_space::headroom_bytes`]).
    pub data_available_gb: u32,
    /// Space available on the staging / image-cache filesystem.
    pub staging_available_gb: u32,
}

/// The seam the `v4` declaration reads the filesystems through.
pub trait DiskSource: Send + Sync {
    /// Read the filesystems. Never fails: an unreadable one is `0`.
    fn read(&self) -> DiskReading;
}

/// Production [`DiskSource`] — `statvfs` of the data-disk root (net of
/// what the per-VM disks on it are promised) and of the staging root.
#[derive(Debug, Clone)]
pub struct StatvfsDiskSource {
    /// `[storage] data_disk_root`.
    pub data_root: PathBuf,
    /// The agent's staging / image-cache root (`/var/lib/hippius-miner`).
    pub staging_root: PathBuf,
}

impl DiskSource for StatvfsDiskSource {
    fn read(&self) -> DiskReading {
        use crate::lifecycle::disk_space;
        let (data_total, _) = disk_space::fs_bytes(&self.data_root).unwrap_or((0, 0));
        // A measurable filesystem whose disks can't be listed declares no
        // room (a real 0 next to its total), as the create gate refuses.
        let reserved = *disk_space::create_lock();
        let data_available =
            disk_space::headroom_bytes(reserved, &self.data_root, &self.data_root).unwrap_or(0);
        let (_, staging_available) =
            crate::lifecycle::disk_space::fs_bytes(&self.staging_root).unwrap_or((0, 0));
        DiskReading {
            data_total_gb: gib(data_total),
            data_available_gb: gib(data_available),
            staging_available_gb: gib(staging_available),
        }
    }
}

/// Bytes → whole GiB, saturating into `u32`.
fn gib(bytes: u64) -> u32 {
    u32::try_from(bytes / (1024 * 1024 * 1024)).unwrap_or(u32::MAX)
}

impl DiskDeclarer {
    fn declare(&self) -> DiskDeclaration {
        let mut reading = self.source.read();
        // An impossible pair (free above size — a racing resize, a strange
        // filesystem) fails the schema's own validation; declare the data
        // pair unknown rather than stop heartbeating over it.
        if reading.data_total_gb != 0 && reading.data_available_gb > reading.data_total_gb {
            reading.data_total_gb = 0;
            reading.data_available_gb = 0;
        }
        DiskDeclaration {
            cvm_disk_gb_budget: self.cvm_disk_gb_budget,
            data_disk_total_gb: reading.data_total_gb,
            data_disk_available_gb: reading.data_available_gb,
            staging_disk_available_gb: reading.staging_available_gb,
        }
    }
}

impl HeartbeatBuilder {
    /// Construct a builder. `miner_id` is the operator-assigned id
    /// vali registered; `identity` signs the heartbeat body;
    /// `lifecycle` supplies the VM counts; `metrics` supplies the
    /// coarse host snapshot.
    pub fn new(
        miner_id: String,
        identity: Arc<MinerIdentity>,
        lifecycle: Arc<CvmLifecycle>,
        metrics: Arc<dyn MetricsSource>,
    ) -> Self {
        Self {
            miner_id,
            identity,
            lifecycle,
            metrics,
            capacity: None,
            disk: None,
            host_health: None,
            agent_version: None,
        }
    }

    /// Opt into the `v3` capacity heartbeat (`[heartbeat]
    /// schema_capacity = true`). Only the periodic [`build`](Self::build)
    /// is affected; the graceful-exit heartbeat stays `v2`.
    pub fn with_capacity_declaration(mut self, capacity: CapacityDeclarer) -> Self {
        self.capacity = Some(capacity);
        self
    }

    /// Opt into the `v4` disk heartbeat (`[heartbeat] schema_disk =
    /// true`). `v4` is a superset of `v3`, so this takes effect only
    /// together with [`with_capacity_declaration`](Self::with_capacity_declaration)
    /// (the config refuses `schema_disk` without `schema_capacity`).
    pub fn with_disk_declaration(mut self, disk: DiskDeclarer) -> Self {
        self.disk = Some(disk);
        self
    }

    /// Opt into the `v5` host-health heartbeat (`[heartbeat]
    /// schema_host_health = true`). `v5` is a superset of `v4`, so this
    /// takes effect only together with the capacity and disk declarations
    /// (the config refuses `schema_host_health` without `schema_disk`).
    pub fn with_host_health(mut self, source: Arc<dyn HostHealthSource>) -> Self {
        self.host_health = Some(source);
        self
    }

    /// Opt into the `v6` heartbeat (`[heartbeat] schema_agent_version =
    /// true`), carrying `agent_version` (the agent passes its compiled-in
    /// [`crate::release::RELEASE_TAG`]). `v6` is a superset of `v5`, so
    /// this takes effect only together with the host-health source (the
    /// config refuses `schema_agent_version` without `schema_host_health`).
    ///
    /// A tag the heartbeat schema would refuse (it comes from the build
    /// environment, so a hand build could carry anything) degrades the
    /// heartbeat to `v5` rather than failing every build: liveness must
    /// never depend on a cosmetic field.
    pub fn with_agent_version(mut self, agent_version: String) -> Self {
        self.agent_version = Some(agent_version);
        self
    }

    /// Sample, stamp, draw `sequence`, encode, and sign — yielding a
    /// signed heartbeat ready for the queue.
    ///
    /// `sequence` is drawn from `seq` (persisted before this returns,
    /// so a crash can't re-issue it). A metrics-read failure aborts
    /// the build fail-closed — vali treats a soft-signal value of `0`
    /// as legitimate, so a heartbeat must never carry a *fabricated*
    /// metric.
    pub async fn build(&self, seq: &mut SequenceStore) -> Result<SignedMinerHeartbeat> {
        let mut heartbeat = self.sample(seq).await?;
        // The periodic builder emits `v1`, or `v3` when the capacity
        // declaration is enabled — never with the graceful-exit flag,
        // which only the dedicated one-shot graceful-exit-heartbeat
        // command carries (as `v2`, transport (B)).
        heartbeat.schema_version = SCHEMA_VERSION;
        heartbeat.graceful_exit_requested = false;
        match (&self.capacity, &self.disk, &self.host_health) {
            (Some(capacity), Some(disk), Some(host_health)) => {
                let (capacity, disk, host_health) =
                    (capacity.declare(), disk.declare(), host_health.read().await);
                heartbeat = match self
                    .agent_version
                    .as_deref()
                    .filter(|v| is_valid_agent_version(v))
                {
                    Some(version) => heartbeat.with_agent_version(
                        capacity,
                        disk,
                        host_health,
                        version.to_string(),
                    ),
                    None => heartbeat.with_host_health(capacity, disk, host_health),
                };
            }
            (Some(capacity), Some(disk), None) => {
                heartbeat = heartbeat.with_disk(capacity.declare(), disk.declare());
            }
            (Some(capacity), None, _) => heartbeat = heartbeat.with_capacity(capacity.declare()),
            (None, _, _) => {}
        }
        self.sign(heartbeat)
    }

    /// Build + sign ONE `v2` graceful-exit heartbeat (transport (B)).
    ///
    /// Identical sampling to [`build`](Self::build) — the SAME live host
    /// metrics, VM counts, timestamp, and monotonic `sequence` — but the
    /// body is the `v2` form with `graceful_exit_requested = true`. The
    /// miner-agent emits exactly one of these to piggyback its
    /// graceful-exit intent on the liveness channel; vali accepts the
    /// heartbeat (records liveness) AND quarantines the miner.
    ///
    /// The `sequence` is drawn from `seq` exactly as an ordinary
    /// heartbeat, so it is monotone relative to the periodic heartbeats —
    /// vali's replay gate accepts it (a non-increasing sequence would be
    /// refused). Pass the SAME on-disk `SequenceStore` the serve loop
    /// uses so the counter never regresses.
    pub async fn build_graceful_exit(
        &self,
        seq: &mut SequenceStore,
    ) -> Result<SignedMinerHeartbeat> {
        let sampled = self.sample(seq).await?;
        let heartbeat = MinerHeartbeat::graceful_exit(
            sampled.miner_id,
            sampled.timestamp_unix,
            sampled.sequence,
            sampled.vm_count_running,
            sampled.vm_count_total,
            sampled.cpu_load_1m_centi,
            sampled.memory_total_mib,
            sampled.memory_available_mib,
        );
        self.sign(heartbeat)
    }

    /// Sample host metrics + the CVM lifecycle, stamp the time, and draw
    /// the next monotonic `sequence` — the shared body of [`build`] and
    /// [`build_graceful_exit`]. Returns a `v1`-shaped [`MinerHeartbeat`]
    /// (the version/flag are set by the caller). A metrics-read failure
    /// aborts fail-closed BEFORE the sequence is drawn, so no number is
    /// burned on a partial build.
    async fn sample(&self, seq: &mut SequenceStore) -> Result<MinerHeartbeat> {
        let host = self.metrics.sample()?;

        // Tenant-only enumeration — the singleton Infra host-attestor is
        // EXCLUDED from the heartbeat's `vm_count_*` (it is not a tenant
        // VM and must never inflate vali's capacity / billing view).
        let phases = self
            .lifecycle
            .list_tenants()
            .await
            .map_err(|_| MinerAgentError::HeartbeatBuild("lifecycle"))?;
        let vm_count_total = u32::try_from(phases.len()).unwrap_or(u32::MAX);
        let vm_count_running = u32::try_from(
            phases
                .iter()
                .filter(|(_, phase)| matches!(phase, CvmPhase::Running))
                .count(),
        )
        .unwrap_or(u32::MAX);

        let timestamp_unix = now_unix()?;
        // Draw + persist the sequence LAST, so a build that fails on an
        // earlier step does not burn a sequence number.
        let sequence = seq.next()?;

        Ok(MinerHeartbeat {
            schema_version: SCHEMA_VERSION,
            miner_id: self.miner_id.clone(),
            timestamp_unix,
            sequence,
            vm_count_running,
            vm_count_total,
            cpu_load_1m_centi: host.cpu_load_1m_centi,
            memory_total_mib: host.memory_total_mib,
            memory_available_mib: host.memory_available_mib,
            domain: DOMAIN.to_string(),
            graceful_exit_requested: false,
            cvm_cpu_budget: 0,
            cvm_memory_mb_budget: 0,
            asid_capacity: 0,
            asid_used: 0,
            disk: DiskDeclaration::default(),
            host_health: HostHealthDeclaration::default(),
            agent_version: String::new(),
        })
    }

    /// Canonical-encode + Ed25519-sign a heartbeat into a wire envelope.
    fn sign(&self, heartbeat: MinerHeartbeat) -> Result<SignedMinerHeartbeat> {
        let body = heartbeat
            .canonical()
            .map_err(|_| MinerAgentError::HeartbeatBuild("encode"))?;
        let sig = self.identity.sign(&body).to_bytes().to_vec();
        Ok(SignedMinerHeartbeat { body, sig })
    }
}

/// The current wall-clock as Unix seconds. No `chrono` — `SystemTime`
/// only. A clock before the Unix epoch is fail-closed.
fn now_unix() -> Result<i64> {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| MinerAgentError::HeartbeatBuild("clock"))?
        .as_secs();
    i64::try_from(secs).map_err(|_| MinerAgentError::HeartbeatBuild("clock"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::heartbeat::metrics::{HostMetrics, MockMetricsSource};
    use crate::lifecycle::{HostResources, MockLaunchDigest, MockLibvirtDriver};
    use hippius_types::heartbeat::SignedMinerHeartbeat as Hb;
    use tempfile::tempdir;

    fn lifecycle() -> Arc<CvmLifecycle> {
        // The builder only calls `lifecycle.list()` — nothing is ever
        // launched in these tests, so the digest computer is unused;
        // a `failing()` mock is a fine placeholder.
        Arc::new(CvmLifecycle::new(
            Arc::new(MockLibvirtDriver::default()),
            Arc::new(MockLaunchDigest::failing()),
            HostResources {
                total_cpus: 16,
                total_memory_mb: 65_536,
                total_disk_gb: 0,
            },
        ))
    }

    fn builder(metrics: Arc<dyn MetricsSource>) -> HeartbeatBuilder {
        HeartbeatBuilder::new(
            "miner-a".to_string(),
            Arc::new(MinerIdentity::generate().unwrap()),
            lifecycle(),
            metrics,
        )
    }

    #[test]
    fn sequence_store_starts_at_zero_when_absent() {
        let dir = tempdir().unwrap();
        let store = SequenceStore::open(&dir.path().join("hb.seq")).unwrap();
        assert_eq!(store.last(), 0);
    }

    #[test]
    fn sequence_store_is_monotone_and_persists() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("hb.seq");
        let mut store = SequenceStore::open(&path).unwrap();
        assert_eq!(store.next().unwrap(), 1);
        assert_eq!(store.next().unwrap(), 2);
        assert_eq!(store.next().unwrap(), 3);
        // A fresh open recovers the persisted counter — the next draw
        // continues from 4, surviving a "restart".
        let mut reopened = SequenceStore::open(&path).unwrap();
        assert_eq!(reopened.last(), 3);
        assert_eq!(reopened.next().unwrap(), 4);
    }

    #[test]
    fn sequence_store_rejects_a_corrupt_file() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("hb.seq");
        std::fs::write(&path, "not-a-number").unwrap();
        assert!(matches!(
            SequenceStore::open(&path),
            Err(MinerAgentError::HeartbeatSequence("parse"))
        ));
    }

    #[tokio::test]
    async fn build_produces_a_signed_verifiable_heartbeat() {
        let dir = tempdir().unwrap();
        let mut seq = SequenceStore::open(&dir.path().join("hb.seq")).unwrap();
        let b = builder(Arc::new(MockMetricsSource::default()));
        let signed = b.build(&mut seq).await.unwrap();

        // The envelope decodes + the signature verifies under the
        // builder's identity — a real, valid heartbeat.
        let hb: Hb = ciborium::de::from_reader(signed.canonical().unwrap().as_slice()).unwrap();
        assert_eq!(hb.body, signed.body);
        assert_eq!(signed.sig.len(), 64);
    }

    #[tokio::test]
    async fn consecutive_builds_have_monotone_sequences() {
        let dir = tempdir().unwrap();
        let mut seq = SequenceStore::open(&dir.path().join("hb.seq")).unwrap();
        let b = builder(Arc::new(MockMetricsSource::default()));
        let first = b.build(&mut seq).await.unwrap();
        let second = b.build(&mut seq).await.unwrap();
        // Decode the inner bodies — the second sequence must exceed
        // the first.
        let d1: MinerHeartbeat = decode(&first.body);
        let d2: MinerHeartbeat = decode(&second.body);
        assert!(d2.sequence > d1.sequence);
    }

    #[tokio::test]
    async fn build_folds_in_the_sampled_metrics() {
        let dir = tempdir().unwrap();
        let mut seq = SequenceStore::open(&dir.path().join("hb.seq")).unwrap();
        let m = HostMetrics {
            cpu_load_1m_centi: 333,
            memory_total_mib: 12_345,
            memory_available_mib: 6_789,
        };
        let b = builder(Arc::new(MockMetricsSource::new(m)));
        let signed = b.build(&mut seq).await.unwrap();
        let hb: MinerHeartbeat = decode(&signed.body);
        assert_eq!(hb.cpu_load_1m_centi, 333);
        assert_eq!(hb.memory_total_mib, 12_345);
        assert_eq!(hb.memory_available_mib, 6_789);
        assert_eq!(hb.miner_id, "miner-a");
    }

    #[tokio::test]
    async fn build_graceful_exit_produces_a_signed_v2_heartbeat_with_the_flag() {
        use ciborium::value::Value;
        let dir = tempdir().unwrap();
        let mut seq = SequenceStore::open(&dir.path().join("hb.seq")).unwrap();
        let m = HostMetrics {
            cpu_load_1m_centi: 50,
            memory_total_mib: 100,
            memory_available_mib: 40,
        };
        let b = builder(Arc::new(MockMetricsSource::new(m)));
        let signed = b.build_graceful_exit(&mut seq).await.unwrap();

        // The body is v2 (schema_version 2) and carries the flag true,
        // alongside the SAME live metrics an ordinary heartbeat samples.
        let v: Value = ciborium::de::from_reader(signed.body.as_slice()).unwrap();
        let entries = match v {
            Value::Map(e) => e,
            _ => panic!("body is not a map"),
        };
        let get = |key: &str| -> &Value {
            entries
                .iter()
                .find_map(|(k, val)| match k {
                    Value::Text(t) if t == key => Some(val),
                    _ => None,
                })
                .unwrap_or_else(|| panic!("missing {key}"))
        };
        assert_eq!(get("schema_version"), &Value::Integer(2.into()));
        assert_eq!(get("graceful_exit_requested"), &Value::Bool(true));
        assert_eq!(get("cpu_load_1m_centi"), &Value::Integer(50.into()));
        assert_eq!(entries.len(), 11);
        assert_eq!(signed.sig.len(), 64);
    }

    #[tokio::test]
    async fn graceful_exit_sequence_is_monotone_after_ordinary_heartbeats() {
        // The graceful-exit heartbeat draws from the SAME sequence store,
        // so its sequence strictly exceeds the prior ordinary ones — vali
        // accepts it (a non-increasing sequence would be a replay).
        let dir = tempdir().unwrap();
        let mut seq = SequenceStore::open(&dir.path().join("hb.seq")).unwrap();
        let b = builder(Arc::new(MockMetricsSource::default()));
        let first = b.build(&mut seq).await.unwrap();
        let exit = b.build_graceful_exit(&mut seq).await.unwrap();
        let d1: MinerHeartbeat = decode(&first.body);
        // `decode` ignores the flag/version, but `sequence` is read.
        let d2: MinerHeartbeat = decode(&exit.body);
        assert!(d2.sequence > d1.sequence);
    }

    #[tokio::test]
    async fn a_metrics_failure_aborts_the_build_and_does_not_burn_a_sequence() {
        let dir = tempdir().unwrap();
        let mut seq = SequenceStore::open(&dir.path().join("hb.seq")).unwrap();
        let b = builder(Arc::new(MockMetricsSource::failing()));
        assert!(matches!(
            b.build(&mut seq).await,
            Err(MinerAgentError::HeartbeatBuild("metrics"))
        ));
        // The metric read failed before the sequence was drawn — the
        // counter is untouched, so no number is wasted.
        assert_eq!(seq.last(), 0);
    }

    /// The body's top-level `(key, value)` map — test helper.
    fn body_map(body: &[u8]) -> Vec<(String, ciborium::value::Value)> {
        let v: ciborium::value::Value = ciborium::de::from_reader(body).unwrap();
        match v {
            ciborium::value::Value::Map(e) => e
                .into_iter()
                .map(|(k, v)| match k {
                    ciborium::value::Value::Text(t) => (t, v),
                    _ => panic!("non-text key"),
                })
                .collect(),
            _ => panic!("body is not a CBOR map"),
        }
    }

    fn int(map: &[(String, ciborium::value::Value)], key: &str) -> Option<i128> {
        map.iter().find(|(k, _)| k == key).map(|(_, v)| match v {
            ciborium::value::Value::Integer(i) => (*i).into(),
            _ => panic!("{key} is not an integer"),
        })
    }

    fn declarer(asids: crate::sev_asid::AsidUsage) -> CapacityDeclarer {
        CapacityDeclarer {
            cvm_cpu_budget: 44,
            cvm_memory_mb_budget: 120_000,
            asids: Arc::new(crate::sev_asid::FixedAsidSource(asids)),
        }
    }

    struct FixedDisk(DiskReading);
    impl DiskSource for FixedDisk {
        fn read(&self) -> DiskReading {
            self.0
        }
    }

    fn disk_declarer(reading: DiskReading) -> DiskDeclarer {
        DiskDeclarer {
            cvm_disk_gb_budget: 3_000,
            source: Arc::new(FixedDisk(reading)),
        }
    }

    #[tokio::test]
    async fn with_the_disk_declaration_the_periodic_heartbeat_is_v4() {
        let dir = tempdir().unwrap();
        let mut seq = SequenceStore::open(&dir.path().join("hb.seq")).unwrap();
        let b = builder(Arc::new(MockMetricsSource::default()))
            .with_capacity_declaration(declarer(crate::sev_asid::AsidUsage {
                capacity: 99,
                used: 2,
            }))
            .with_disk_declaration(disk_declarer(DiskReading {
                data_total_gb: 3_500,
                data_available_gb: 2_900,
                staging_available_gb: 400,
            }));
        let map = body_map(&b.build(&mut seq).await.unwrap().body);
        assert_eq!(int(&map, "schema_version"), Some(4));
        assert_eq!(map.len(), 19);
        assert_eq!(int(&map, "cvm_cpu_budget"), Some(44));
        assert_eq!(int(&map, "cvm_disk_gb_budget"), Some(3_000));
        assert_eq!(int(&map, "data_disk_total_gb"), Some(3_500));
        assert_eq!(int(&map, "data_disk_available_gb"), Some(2_900));
        assert_eq!(int(&map, "staging_disk_available_gb"), Some(400));
    }

    #[tokio::test]
    async fn the_disk_declaration_alone_does_not_change_the_version() {
        // v4 is a superset of v3: without the capacity declarer the
        // builder stays v1 (the config refuses this combination anyway).
        let dir = tempdir().unwrap();
        let mut seq = SequenceStore::open(&dir.path().join("hb.seq")).unwrap();
        let b = builder(Arc::new(MockMetricsSource::default()))
            .with_disk_declaration(disk_declarer(DiskReading::default()));
        let map = body_map(&b.build(&mut seq).await.unwrap().body);
        assert_eq!(int(&map, "schema_version"), Some(1));
    }

    #[tokio::test]
    async fn an_incoherent_disk_reading_is_declared_unknown_not_fatal() {
        let dir = tempdir().unwrap();
        let mut seq = SequenceStore::open(&dir.path().join("hb.seq")).unwrap();
        let b = builder(Arc::new(MockMetricsSource::default()))
            .with_capacity_declaration(declarer(crate::sev_asid::AsidUsage::default()))
            .with_disk_declaration(disk_declarer(DiskReading {
                data_total_gb: 100,
                data_available_gb: 101,
                staging_available_gb: 7,
            }));
        let map = body_map(&b.build(&mut seq).await.unwrap().body);
        assert_eq!(int(&map, "schema_version"), Some(4));
        assert_eq!(int(&map, "data_disk_total_gb"), Some(0));
        assert_eq!(int(&map, "data_disk_available_gb"), Some(0));
        assert_eq!(int(&map, "staging_disk_available_gb"), Some(7));
        assert_eq!(int(&map, "cvm_disk_gb_budget"), Some(3_000));
    }

    #[test]
    fn statvfs_disk_source_reads_a_real_filesystem() {
        let dir = tempdir().unwrap();
        let r = StatvfsDiskSource {
            data_root: dir.path().to_path_buf(),
            staging_root: dir.path().to_path_buf(),
        }
        .read();
        assert!(r.data_total_gb >= r.data_available_gb);
        // No disks and nothing reserved beyond a concurrent test's churn:
        // the same filesystem, within a (rounded) GiB.
        assert!(r.staging_available_gb.abs_diff(r.data_available_gb) <= 2);
        // An unreadable root is unknown, not an error.
        let gone = StatvfsDiskSource {
            data_root: dir.path().join("missing"),
            staging_root: dir.path().join("missing"),
        }
        .read();
        assert_eq!(gone, DiskReading::default());
    }

    #[test]
    fn the_declared_available_space_is_net_of_the_disks_promises() {
        let dir = tempdir().unwrap();
        let (_, free) = crate::lifecycle::disk_space::fs_bytes(dir.path()).unwrap();
        let data = crate::lifecycle::data_disk::data_dir(dir.path());
        std::fs::create_dir_all(&data).unwrap();
        let f = std::fs::File::create(data.join("vm-a.img")).unwrap();
        f.set_len(free.saturating_sub(2 << 30)).unwrap();
        let r = StatvfsDiskSource {
            data_root: dir.path().to_path_buf(),
            staging_root: dir.path().to_path_buf(),
        }
        .read();
        // Raw `f_bavail` did not move (the disk is sparse); the declared
        // figure did.
        assert!(r.data_available_gb <= 2, "{r:?}");
        assert!(r.staging_available_gb > 2 || free < (3 << 30), "{r:?}");
    }

    struct FixedHostHealth(HostHealthDeclaration);
    #[async_trait::async_trait]
    impl HostHealthSource for FixedHostHealth {
        async fn read(&self) -> HostHealthDeclaration {
            self.0
        }
    }

    #[tokio::test]
    async fn with_the_host_health_source_the_periodic_heartbeat_is_v5() {
        let dir = tempdir().unwrap();
        let mut seq = SequenceStore::open(&dir.path().join("hb.seq")).unwrap();
        let b = builder(Arc::new(MockMetricsSource::default()))
            .with_capacity_declaration(declarer(crate::sev_asid::AsidUsage {
                capacity: 99,
                used: 4,
            }))
            .with_disk_declaration(disk_declarer(DiskReading {
                data_total_gb: 3_500,
                data_available_gb: 2_900,
                staging_available_gb: 400,
            }))
            .with_host_health(Arc::new(FixedHostHealth(HostHealthDeclaration {
                snp_enabled: true,
                cpus_offline: 24,
                snp_launches_since_boot: 97,
                df_flush_failures: 3,
            })));
        let map = body_map(&b.build(&mut seq).await.unwrap().body);
        assert_eq!(int(&map, "schema_version"), Some(5));
        assert_eq!(map.len(), 23);
        assert_eq!(int(&map, "asid_used"), Some(4));
        assert_eq!(int(&map, "data_disk_total_gb"), Some(3_500));
        assert_eq!(int(&map, "cpus_offline"), Some(24));
        assert_eq!(int(&map, "snp_launches_since_boot"), Some(97));
        assert_eq!(int(&map, "df_flush_failures"), Some(3));
        let snp = map
            .iter()
            .find(|(k, _)| k == "snp_enabled")
            .map(|(_, v)| v.clone());
        assert_eq!(snp, Some(ciborium::value::Value::Bool(true)));
    }

    fn v5_builder() -> HeartbeatBuilder {
        builder(Arc::new(MockMetricsSource::default()))
            .with_capacity_declaration(declarer(crate::sev_asid::AsidUsage {
                capacity: 99,
                used: 4,
            }))
            .with_disk_declaration(disk_declarer(DiskReading {
                data_total_gb: 3_500,
                data_available_gb: 2_900,
                staging_available_gb: 400,
            }))
            .with_host_health(Arc::new(FixedHostHealth(HostHealthDeclaration {
                snp_enabled: true,
                cpus_offline: 0,
                snp_launches_since_boot: 7,
                df_flush_failures: 0,
            })))
    }

    fn text(map: &[(String, ciborium::value::Value)], key: &str) -> Option<String> {
        map.iter()
            .find(|(k, _)| k == key)
            .and_then(|(_, v)| match v {
                ciborium::value::Value::Text(t) => Some(t.clone()),
                _ => None,
            })
    }

    #[tokio::test]
    async fn with_the_agent_version_the_periodic_heartbeat_is_v6() {
        let dir = tempdir().unwrap();
        let mut seq = SequenceStore::open(&dir.path().join("hb.seq")).unwrap();
        let b = v5_builder().with_agent_version(crate::release::RELEASE_TAG.to_string());
        let map = body_map(&b.build(&mut seq).await.unwrap().body);
        assert_eq!(int(&map, "schema_version"), Some(6));
        assert_eq!(map.len(), 24);
        assert_eq!(
            text(&map, "agent_version").as_deref(),
            Some(crate::release::RELEASE_TAG)
        );
        assert_eq!(int(&map, "snp_launches_since_boot"), Some(7));
        assert_eq!(int(&map, "asid_used"), Some(4));
    }

    #[tokio::test]
    async fn without_the_agent_version_the_heartbeat_stays_v5() {
        let dir = tempdir().unwrap();
        let mut seq = SequenceStore::open(&dir.path().join("hb.seq")).unwrap();
        let map = body_map(&v5_builder().build(&mut seq).await.unwrap().body);
        assert_eq!(int(&map, "schema_version"), Some(5));
        assert_eq!(text(&map, "agent_version"), None);
    }

    #[tokio::test]
    async fn a_malformed_release_tag_degrades_to_v5_instead_of_failing() {
        let dir = tempdir().unwrap();
        let mut seq = SequenceStore::open(&dir.path().join("hb.seq")).unwrap();
        for bad in ["", "v1 2", "x".repeat(33).as_str()] {
            let b = v5_builder().with_agent_version(bad.to_string());
            let map = body_map(&b.build(&mut seq).await.unwrap().body);
            assert_eq!(int(&map, "schema_version"), Some(5), "{bad:?}");
        }
    }

    #[tokio::test]
    async fn the_agent_version_without_the_host_health_source_stays_v4() {
        // v6 is a superset of v5: no version jump (the config refuses this).
        let dir = tempdir().unwrap();
        let mut seq = SequenceStore::open(&dir.path().join("hb.seq")).unwrap();
        let b = builder(Arc::new(MockMetricsSource::default()))
            .with_capacity_declaration(declarer(crate::sev_asid::AsidUsage::default()))
            .with_disk_declaration(disk_declarer(DiskReading::default()))
            .with_agent_version("v1.2.3".into());
        let map = body_map(&b.build(&mut seq).await.unwrap().body);
        assert_eq!(int(&map, "schema_version"), Some(4));
    }

    #[tokio::test]
    async fn the_host_health_source_without_the_disk_declaration_stays_v3() {
        // v5 is a superset of v4: without the disk declarer the builder
        // does not jump a version (the config refuses this anyway).
        let dir = tempdir().unwrap();
        let mut seq = SequenceStore::open(&dir.path().join("hb.seq")).unwrap();
        let b = builder(Arc::new(MockMetricsSource::default()))
            .with_capacity_declaration(declarer(crate::sev_asid::AsidUsage::default()))
            .with_host_health(Arc::new(FixedHostHealth(HostHealthDeclaration::default())));
        let map = body_map(&b.build(&mut seq).await.unwrap().body);
        assert_eq!(int(&map, "schema_version"), Some(3));
    }

    #[tokio::test]
    async fn without_the_capacity_flag_the_periodic_heartbeat_stays_v1() {
        let dir = tempdir().unwrap();
        let mut seq = SequenceStore::open(&dir.path().join("hb.seq")).unwrap();
        let signed = builder(Arc::new(MockMetricsSource::default()))
            .build(&mut seq)
            .await
            .unwrap();
        let map = body_map(&signed.body);
        assert_eq!(int(&map, "schema_version"), Some(1));
        assert_eq!(map.len(), 10);
        for key in [
            "cvm_cpu_budget",
            "cvm_memory_mb_budget",
            "asid_capacity",
            "asid_used",
        ] {
            assert_eq!(int(&map, key), None, "{key} leaked into a v1 heartbeat");
        }
    }

    #[tokio::test]
    async fn with_the_capacity_declaration_the_periodic_heartbeat_is_v3() {
        let dir = tempdir().unwrap();
        let mut seq = SequenceStore::open(&dir.path().join("hb.seq")).unwrap();
        let b = builder(Arc::new(MockMetricsSource::default())).with_capacity_declaration(
            declarer(crate::sev_asid::AsidUsage {
                capacity: 99,
                used: 2,
            }),
        );
        let signed = b.build(&mut seq).await.unwrap();
        let map = body_map(&signed.body);
        assert_eq!(int(&map, "schema_version"), Some(3));
        assert_eq!(map.len(), 15);
        assert_eq!(int(&map, "cvm_cpu_budget"), Some(44));
        assert_eq!(int(&map, "cvm_memory_mb_budget"), Some(120_000));
        assert_eq!(int(&map, "asid_capacity"), Some(99));
        assert_eq!(int(&map, "asid_used"), Some(2));
        assert!(map
            .iter()
            .any(|(k, v)| k == "graceful_exit_requested"
                && *v == ciborium::value::Value::Bool(false)));
    }

    #[tokio::test]
    async fn an_incoherent_asid_reading_is_declared_unknown_not_fatal() {
        // used > capacity would fail the schema's own validation; the
        // heartbeat must still go out, with the pair declared unknown.
        let dir = tempdir().unwrap();
        let mut seq = SequenceStore::open(&dir.path().join("hb.seq")).unwrap();
        let b = builder(Arc::new(MockMetricsSource::default())).with_capacity_declaration(
            declarer(crate::sev_asid::AsidUsage {
                capacity: 99,
                used: 100,
            }),
        );
        let map = body_map(&b.build(&mut seq).await.unwrap().body);
        assert_eq!(int(&map, "schema_version"), Some(3));
        assert_eq!(int(&map, "asid_capacity"), Some(0));
        assert_eq!(int(&map, "asid_used"), Some(0));
        assert_eq!(int(&map, "cvm_cpu_budget"), Some(44));
    }

    #[tokio::test]
    async fn graceful_exit_stays_v2_even_with_the_capacity_declaration() {
        let dir = tempdir().unwrap();
        let mut seq = SequenceStore::open(&dir.path().join("hb.seq")).unwrap();
        let b = builder(Arc::new(MockMetricsSource::default())).with_capacity_declaration(
            declarer(crate::sev_asid::AsidUsage {
                capacity: 99,
                used: 2,
            }),
        );
        let map = body_map(&b.build_graceful_exit(&mut seq).await.unwrap().body);
        assert_eq!(int(&map, "schema_version"), Some(2));
        assert_eq!(map.len(), 11);
    }

    /// Decode an inner heartbeat body — test helper.
    fn decode(body: &[u8]) -> MinerHeartbeat {
        let v: ciborium::value::Value = ciborium::de::from_reader(body).unwrap();
        let entries = match v {
            ciborium::value::Value::Map(e) => e,
            _ => panic!("body is not a CBOR map"),
        };
        let get_int = |key: &str| -> i128 {
            for (k, val) in &entries {
                if matches!(k, ciborium::value::Value::Text(t) if t == key) {
                    if let ciborium::value::Value::Integer(i) = val {
                        return (*i).into();
                    }
                }
            }
            panic!("missing integer field {key}");
        };
        let sequence = get_int("sequence") as u64;
        let timestamp_unix = get_int("timestamp_unix") as i64;
        let vm_count_running = get_int("vm_count_running") as u32;
        let vm_count_total = get_int("vm_count_total") as u32;
        let cpu_load_1m_centi = get_int("cpu_load_1m_centi") as u32;
        let memory_total_mib = get_int("memory_total_mib") as u32;
        let memory_available_mib = get_int("memory_available_mib") as u32;
        let schema_version = get_int("schema_version") as u8;
        let mut miner_id = String::new();
        for (k, val) in &entries {
            if matches!(k, ciborium::value::Value::Text(t) if t == "miner_id") {
                if let ciborium::value::Value::Text(t) = val {
                    miner_id = t.clone();
                }
            }
        }
        MinerHeartbeat {
            schema_version,
            miner_id,
            timestamp_unix,
            sequence,
            vm_count_running,
            vm_count_total,
            cpu_load_1m_centi,
            memory_total_mib,
            memory_available_mib,
            domain: DOMAIN.to_string(),
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
}
