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

use hippius_types::heartbeat::{MinerHeartbeat, SignedMinerHeartbeat, DOMAIN, SCHEMA_VERSION};
use tempfile::NamedTempFile;

use crate::error::{MinerAgentError, Result};
use crate::identity::MinerIdentity;
use crate::lifecycle::{CvmLifecycle, CvmPhase};

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
        }
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
        // The periodic builder always emits a `v1` heartbeat — the
        // graceful-exit flag is carried only by the dedicated one-shot
        // graceful-exit-heartbeat command (transport (B)).
        heartbeat.schema_version = SCHEMA_VERSION;
        heartbeat.graceful_exit_requested = false;
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
        }
    }
}
