//! The §K periodic signed-heartbeat subsystem (PR-MA-6).
//!
//! A miner-agent runs on an **untrusted** bare-metal host. To prove it
//! is alive — so vali's scheduler does not quarantine it — it emits a
//! signed [`hippius_types::heartbeat::MinerHeartbeat`] every
//! `[heartbeat] interval_secs`. The subsystem is two cooperating
//! tokio tasks plus a bounded queue between them:
//!
//! - **builder task** ([`run_builder`]) — every `interval_secs`,
//!   [`builder::HeartbeatBuilder`] samples host metrics + the CVM
//!   lifecycle, draws the next persisted monotonic `sequence`, encodes
//!   the canonical-CBOR body, signs it with the miner identity, and
//!   pushes the [`SignedMinerHeartbeat`] onto the queue;
//! - **pusher task** ([`pusher::run_pusher`]) — drains the queue and
//!   relays each heartbeat over mTLS to the Edge gateway's
//!   `/v1/edge/heartbeat` route, with a capped, responsively-
//!   cancellable exponential backoff;
//! - **queue** ([`queue::HeartbeatQueue`]) — a bounded
//!   `VecDeque<SignedMinerHeartbeat>` with LRU-drop-oldest on overflow
//!   (the freshest liveness signal always survives).
//!
//! Both tasks are wired to the process-wide shutdown
//! [`CancellationToken`]; on shutdown the pusher makes one final
//! best-effort drain of the queue.
//!
//! ## What this subsystem does NOT do
//!
//! It never decrypts anything, never speaks to the Vault or the KBS.
//! The heartbeat body is signed by the miner's own self-generated
//! identity ([`crate::identity::MinerIdentity`]); the Edge relays it
//! opaquely; vali verifies it against the out-of-band-registered key.

pub mod builder;
pub mod metrics;
pub mod pusher;
pub mod queue;

use std::sync::Arc;
use std::time::Duration;

use tokio_util::sync::CancellationToken;

pub use builder::{HeartbeatBuilder, SequenceStore};
pub use metrics::{HostMetrics, MetricsSource, MockMetricsSource, ProcMetricsSource};
pub use pusher::{
    build_edge_mtls_client, run_pusher, HeartbeatClient, PushOutcome, ReqwestHeartbeatClient,
};
pub use queue::HeartbeatQueue;

// Re-export the wire types so callers depend on one module.
pub use hippius_types::heartbeat::{MinerHeartbeat, SignedMinerHeartbeat};

/// Run the periodic heartbeat builder until `cancel` fires.
///
/// Every `interval` it builds + signs a heartbeat and pushes it onto
/// `queue`. A build failure (a `/proc` read error, a lifecycle query
/// failure) is logged and SKIPPED — one missed heartbeat is not fatal;
/// the next tick tries again. The interval `tick` and the cancel race
/// in a `select!`, so a shutdown is honoured immediately.
///
/// `seq` carries the persisted monotonic sequence counter; it is
/// owned by this task (the only writer).
pub async fn run_builder(
    builder: Arc<HeartbeatBuilder>,
    queue: Arc<HeartbeatQueue>,
    mut seq: SequenceStore,
    interval: Duration,
    cancel: CancellationToken,
) {
    let mut tick = tokio::time::interval(interval);
    // Skip missed ticks rather than firing a burst after a slow build.
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        tokio::select! {
            _ = cancel.cancelled() => break,
            _ = tick.tick() => {
                match builder.build(&mut seq).await {
                    Ok(signed) => {
                        let dropped = queue.push(signed).await;
                        if dropped {
                            // LRU shed — the queue was full; a stale
                            // heartbeat was evicted for this fresh one.
                            eprintln!(
                                "hippius-miner-agent: heartbeat-builder: \
                                 queue-overflow — oldest heartbeat dropped"
                            );
                        }
                    }
                    Err(e) => {
                        // `MinerAgentError`'s Display is a fixed
                        // classifier — no path / value is echoed.
                        eprintln!(
                            "hippius-miner-agent: heartbeat-builder: \
                             build-skipped ({e})"
                        );
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::MinerIdentity;
    use crate::lifecycle::{CvmLifecycle, HostResources, MockLaunchDigest, MockLibvirtDriver};
    use metrics::MockMetricsSource;
    use tempfile::tempdir;

    fn builder() -> Arc<HeartbeatBuilder> {
        let lifecycle = Arc::new(CvmLifecycle::new(
            Arc::new(MockLibvirtDriver::default()),
            Arc::new(MockLaunchDigest::failing()),
            HostResources {
                total_cpus: 16,
                total_memory_mb: 65_536,
                total_disk_gb: 0,
            },
        ));
        Arc::new(HeartbeatBuilder::new(
            "miner-a".to_string(),
            Arc::new(MinerIdentity::generate().unwrap()),
            lifecycle,
            Arc::new(MockMetricsSource::default()),
        ))
    }

    #[tokio::test]
    async fn builder_task_enqueues_heartbeats_until_cancelled() {
        let dir = tempdir().unwrap();
        let seq = SequenceStore::open(&dir.path().join("hb.seq")).unwrap();
        let queue = Arc::new(HeartbeatQueue::new(16));
        let cancel = CancellationToken::new();

        let task = tokio::spawn(run_builder(
            builder(),
            queue.clone(),
            seq,
            Duration::from_millis(40),
            cancel.clone(),
        ));
        // A handful of ticks worth of time.
        tokio::time::sleep(Duration::from_millis(180)).await;
        cancel.cancel();
        task.await.expect("builder task joins");

        assert!(
            !queue.is_empty().await,
            "the builder task must have enqueued at least one heartbeat"
        );
    }

    #[tokio::test]
    async fn builder_task_stops_promptly_on_cancel() {
        let dir = tempdir().unwrap();
        let seq = SequenceStore::open(&dir.path().join("hb.seq")).unwrap();
        let queue = Arc::new(HeartbeatQueue::new(16));
        let cancel = CancellationToken::new();
        // A long interval — cancel must not have to wait for a tick.
        let task = tokio::spawn(run_builder(
            builder(),
            queue,
            seq,
            Duration::from_secs(3600),
            cancel.clone(),
        ));
        cancel.cancel();
        let joined = tokio::time::timeout(Duration::from_secs(2), task).await;
        assert!(joined.is_ok(), "cancel must not wait out the interval");
    }
}
