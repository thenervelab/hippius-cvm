//! Bounded validate→forward queue (PR-H3, §10).
//!
//! `accept → rate-limit → validate` runs synchronously on the inbound
//! task. `forward` is its own consumer (eventually a long-lived task
//! writing to the vRack-side socket / pull broker). The bounded queue
//! is the §10 "bounded queues before anything reaches inner" gate —
//! when the consumer falls behind, the producer drops new envelopes
//! at the wire rather than buffering unboundedly (which would hand a
//! memory-pressure DoS to whichever peer is fastest).
//!
//! ## Design choices
//!
//! - `tokio::sync::mpsc` with a hard capacity. `try_send` is
//!   non-blocking: on `Full` we shed; on `Closed` we treat it as a
//!   process bug (the worker died) and fail-closed.
//! - `try_send` returns the envelope back on `Full` so the caller
//!   can read its `peer()` / `kind()` for the shed log without
//!   re-deriving it. `ValidatedEnvelope` is non-`Clone` (§5.6
//!   structural pin in `stages/envelope.rs`) — without the return
//!   path the caller would have to log BEFORE attempting the send
//!   and then have nothing to drop on success.
//! - The sink half is `Clone` because a future PR-H5 (HA pair) may
//!   have multiple accept tasks feeding the same worker. The source
//!   half is NOT `Clone` — there's exactly one forward worker.

use crate::stages::envelope::ValidatedEnvelope;
use tokio::sync::mpsc;

/// Producer end. `Clone` so multiple accept tasks can fan-in.
#[derive(Clone)]
pub struct BoundedSink {
    tx: mpsc::Sender<ValidatedEnvelope>,
}

/// Consumer end. NOT `Clone` — single forward worker.
pub struct BoundedSource {
    rx: mpsc::Receiver<ValidatedEnvelope>,
}

/// Outcome of attempting to enqueue into the bounded queue. The shape
/// is intentionally explicit (no `Result<(), TrySendError<_>>`)
/// because the two failure modes mean different things to the audit
/// log:
///
/// - `QueueFull` is normal back-pressure (§10) — increment the per-IP
///   shed counter and drop the bytes. Source gets no signal.
/// - `WorkerGone` means the forward worker task crashed; the relay
///   has lost its inner side and must fail-closed (§10) — the binary
///   should exit so the HA peer (PR-H5) takes over.
pub enum SendOutcome {
    /// Envelope landed in the queue.
    Enqueued,
    /// Queue is at capacity — caller sheds (bumps counter, logs,
    /// drops). The envelope is returned by value so the caller can
    /// pull peer / kind off it for the log.
    QueueFull(ValidatedEnvelope),
    /// Consumer is gone (RX dropped). Process-level failure mode;
    /// caller must fail-closed.
    WorkerGone,
}

impl BoundedSink {
    /// Non-blocking enqueue. Maps `tokio::mpsc::error::TrySendError`
    /// to the explicit [`SendOutcome`] so callers don't have to know
    /// the tokio error shape.
    pub fn try_send(&self, env: ValidatedEnvelope) -> SendOutcome {
        match self.tx.try_send(env) {
            Ok(()) => SendOutcome::Enqueued,
            Err(mpsc::error::TrySendError::Full(env)) => SendOutcome::QueueFull(env),
            Err(mpsc::error::TrySendError::Closed(_)) => SendOutcome::WorkerGone,
        }
    }

    /// Capacity available right now. Useful for tests / telemetry —
    /// production code MUST NOT branch on this value (TOCTOU between
    /// the check and the send).
    pub fn capacity(&self) -> usize {
        self.tx.capacity()
    }
}

impl BoundedSource {
    /// Receive the next envelope or `None` if all sinks have been
    /// dropped. The forward worker `loop { while let Some(env) =
    /// source.recv().await { forward(env).await } }` is the only
    /// production consumer.
    pub async fn recv(&mut self) -> Option<ValidatedEnvelope> {
        self.rx.recv().await
    }
}

/// Build a (sink, source) pair with `capacity` slots. `capacity` of
/// `0` is rejected by tokio at runtime; callers source it from
/// [`crate::config::EdgeGatewayConfig::queue_capacity`] which has a
/// non-zero default and a `deny_unknown_fields` validator.
pub fn bounded_queue(capacity: usize) -> (BoundedSink, BoundedSource) {
    let (tx, rx) = mpsc::channel(capacity);
    (BoundedSink { tx }, BoundedSource { rx })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mtls::PeerId;
    use crate::pipeline::{Direction, MessageKind};
    use crate::stages::envelope::RawEnvelope;
    use crate::stages::validate::validate;
    use ciborium::value::Value;
    use hippius_types::cbor::to_canonical_vec;

    /// Build a `ValidatedEnvelope` via the only path (`validate`) —
    /// keeps the test honest re: the typestate barrier.
    fn validated() -> ValidatedEnvelope {
        let v = Value::Map(vec![
            (Value::Text("body".into()), Value::Bytes(vec![0u8; 8])),
            (Value::Text("sig".into()), Value::Bytes(vec![0u8; 64])),
        ]);
        let body = to_canonical_vec(&v).unwrap();
        let raw = RawEnvelope::from_wire(
            Direction::MinerToInner,
            MessageKind::ServedReceipt,
            PeerId::new("test-peer"),
            body,
        );
        validate(raw).unwrap()
    }

    #[tokio::test]
    async fn enqueue_then_dequeue() {
        let (sink, mut source) = bounded_queue(4);
        match sink.try_send(validated()) {
            SendOutcome::Enqueued => {}
            _ => panic!("expected enqueue"),
        }
        let got = source.recv().await.unwrap();
        assert_eq!(got.kind(), MessageKind::ServedReceipt);
    }

    #[tokio::test]
    async fn queue_full_returns_envelope_for_shed_log() {
        // Cap=1, fill, then assert the second try_send returns the
        // envelope by value so the caller can read peer/kind for the
        // shed log without ever cloning.
        let (sink, _source) = bounded_queue(1);
        match sink.try_send(validated()) {
            SendOutcome::Enqueued => {}
            _ => panic!("first send must enqueue"),
        }
        match sink.try_send(validated()) {
            SendOutcome::QueueFull(env) => {
                // We get the rejected envelope back — drop it after
                // pulling routing metadata for the log.
                assert_eq!(env.kind(), MessageKind::ServedReceipt);
            }
            _ => panic!("second send must report QueueFull"),
        }
    }

    #[tokio::test]
    async fn worker_gone_when_source_dropped() {
        let (sink, source) = bounded_queue(1);
        drop(source);
        match sink.try_send(validated()) {
            SendOutcome::WorkerGone => {}
            _ => panic!("dropping source must surface WorkerGone"),
        }
    }

    #[tokio::test]
    async fn sink_is_clone_for_ha_fanin() {
        // PR-H5 will have two accept tasks (HA pair) feeding the
        // same forward worker — sink must be `Clone`. This isn't a
        // behavior test; it pins the trait contract so a future PR
        // that drops `Clone` fails compile here.
        fn assert_clone<T: Clone>() {}
        assert_clone::<BoundedSink>();
        let (sink, _src) = bounded_queue(1);
        let _sink2 = sink.clone();
    }
}
