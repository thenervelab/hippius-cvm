//! A bounded buffer of signed beacons awaiting push.
//!
//! The beacon loop fills this queue; the vsock pusher drains it — the
//! queue is the loop/pusher seam, shared through an `Arc<Mutex<…>>`
//! (the loop pushes, the pusher drains).
//!
//! ## Bound
//!
//! At most [`MAX_PENDING`] beacons are held. A push into a full queue
//! evicts the OLDEST beacon (keep-newest) — never the freshest — and the
//! eviction is surfaced so the caller can log it. In normal operation
//! the pusher keeps it drained; a sustained host outage steady-state-
//! evicts the oldest.

use std::collections::VecDeque;

use hippius_types::host_attestor::SignedHostBeacon;

/// The default queue bound — ~16 h of history at one beacon/minute.
pub const MAX_PENDING: usize = 1000;

/// The outcome of a [`BeaconQueue::push`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PushOutcome {
    /// The beacon was buffered with room to spare.
    Buffered,
    /// The beacon was buffered, but the queue was full so the OLDEST
    /// beacon was evicted to make room. Callers should log this.
    DroppedOldest,
}

/// A bounded FIFO buffer of [`SignedHostBeacon`]s.
pub struct BeaconQueue {
    pending: VecDeque<SignedHostBeacon>,
    capacity: usize,
}

impl BeaconQueue {
    /// A queue bounded at [`MAX_PENDING`].
    pub fn new() -> Self {
        Self::with_capacity(MAX_PENDING)
    }

    /// A queue bounded at `capacity` (clamped to at least 1 — a
    /// zero-capacity queue would drop every beacon).
    pub fn with_capacity(capacity: usize) -> Self {
        let capacity = capacity.max(1);
        Self {
            pending: VecDeque::with_capacity(capacity),
            capacity,
        }
    }

    /// Buffer `beacon`. If the queue is at capacity the OLDEST beacon is
    /// evicted first — the newest is never the one dropped.
    pub fn push(&mut self, beacon: SignedHostBeacon) -> PushOutcome {
        let outcome = if self.pending.len() >= self.capacity {
            let _ = self.pending.pop_front();
            PushOutcome::DroppedOldest
        } else {
            PushOutcome::Buffered
        };
        self.pending.push_back(beacon);
        outcome
    }

    /// Number of buffered beacons.
    pub fn len(&self) -> usize {
        self.pending.len()
    }

    /// Whether the queue holds no beacons.
    pub fn is_empty(&self) -> bool {
        self.pending.is_empty()
    }

    /// The configured upper bound.
    pub fn capacity(&self) -> usize {
        self.capacity
    }

    /// Remove and return up to `n` beacons from the FRONT (oldest first
    /// — FIFO). The pusher drains the queue with this.
    pub fn drain(&mut self, n: usize) -> Vec<SignedHostBeacon> {
        let take = n.min(self.pending.len());
        self.pending.drain(..take).collect()
    }

    /// Return a previously-[`drain`](Self::drain)ed `batch` to the FRONT
    /// of the queue after a failed send — FIFO order preserved. The
    /// capacity bound still holds: a surplus is evicted from the FRONT
    /// (the oldest — keep-newest). Returns the number evicted.
    pub fn requeue_front(&mut self, batch: Vec<SignedHostBeacon>) -> usize {
        for beacon in batch.into_iter().rev() {
            self.pending.push_front(beacon);
        }
        let mut evicted = 0;
        while self.pending.len() > self.capacity {
            let _ = self.pending.pop_front();
            evicted += 1;
        }
        evicted
    }
}

impl Default for BeaconQueue {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    /// A signed beacon whose `body` is the single tag byte `tag`.
    fn tagged(tag: u8) -> SignedHostBeacon {
        SignedHostBeacon {
            body: vec![tag],
            sig: [0u8; 64],
        }
    }

    fn tag_of(b: &SignedHostBeacon) -> u8 {
        b.body[0]
    }

    #[test]
    fn push_at_capacity_drops_oldest_keeps_newest() {
        let mut q = BeaconQueue::with_capacity(3);
        assert_eq!(q.push(tagged(1)), PushOutcome::Buffered);
        assert_eq!(q.push(tagged(2)), PushOutcome::Buffered);
        assert_eq!(q.push(tagged(3)), PushOutcome::Buffered);
        assert_eq!(q.push(tagged(4)), PushOutcome::DroppedOldest);
        assert_eq!(q.len(), 3);
        let drained: Vec<u8> = q.drain(99).iter().map(tag_of).collect();
        assert_eq!(drained, vec![2, 3, 4]);
    }

    #[test]
    fn drain_takes_fifo_and_is_bounded_by_len() {
        let mut q = BeaconQueue::with_capacity(10);
        for tag in 1..=5u8 {
            q.push(tagged(tag));
        }
        let first_two: Vec<u8> = q.drain(2).iter().map(tag_of).collect();
        assert_eq!(first_two, vec![1, 2]);
        assert_eq!(q.len(), 3);
        assert!(q.drain(999).len() == 3);
        assert!(q.is_empty());
        assert!(q.drain(5).is_empty());
    }

    #[test]
    fn requeue_front_restores_a_failed_batch_in_fifo_order() {
        let mut q = BeaconQueue::with_capacity(10);
        for tag in 1..=5u8 {
            q.push(tagged(tag));
        }
        let batch = q.drain(2);
        assert_eq!(q.requeue_front(batch), 0);
        let drained: Vec<u8> = q.drain(99).iter().map(tag_of).collect();
        assert_eq!(drained, vec![1, 2, 3, 4, 5]);
    }

    #[test]
    fn zero_capacity_is_clamped_to_one() {
        let mut q = BeaconQueue::with_capacity(0);
        assert_eq!(q.capacity(), 1);
        assert_eq!(q.push(tagged(1)), PushOutcome::Buffered);
        assert_eq!(q.push(tagged(2)), PushOutcome::DroppedOldest);
    }

    #[test]
    fn default_uses_the_max_pending_bound() {
        assert_eq!(BeaconQueue::default().capacity(), MAX_PENDING);
    }
}
