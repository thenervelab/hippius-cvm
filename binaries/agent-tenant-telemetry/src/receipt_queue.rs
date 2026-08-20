//! A bounded buffer of signed receipts awaiting push.
//!
//! PR-E2.2's loop fills this queue; PR-E2.3's Edge pusher will drain
//! it — the queue is the E2.2/E2.3 seam.
//!
//! It is intentionally NOT thread-safe: the §E agent track is
//! single-threaded and synchronous (no tokio), so the receipt loop is
//! the only writer and the only reader. Wrapping it for a future
//! concurrent drainer is PR-E2.3's call, not a cost paid here.
//!
//! ## Bound
//!
//! At most [`MAX_PENDING`] receipts are held. A push into a full queue
//! evicts the OLDEST receipt (LRU) — never the newest, so a freshly
//! signed receipt is always kept — and the eviction is surfaced to the
//! caller so it can log it. With no Edge pusher in E2.2 the queue fills
//! to the bound and then steady-state-evicts the oldest; PR-E2.3's
//! pusher keeps it drained in normal operation.

use std::collections::VecDeque;

use hippius_types::served_receipt::SignedServedDeliveryReceipt;

/// The default queue bound — ~16 h of history at one receipt/minute.
/// Past this the oldest receipt is evicted on each new push.
pub const MAX_PENDING: usize = 1000;

/// The outcome of a [`ReceiptQueue::push`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PushOutcome {
    /// The receipt was buffered with room to spare.
    Buffered,
    /// The receipt was buffered, but the queue was full so the OLDEST
    /// receipt was evicted to make room. Callers should log this.
    DroppedOldest,
}

/// A bounded FIFO buffer of signed `ServedDeliveryReceipt`s.
pub struct ReceiptQueue {
    pending: VecDeque<SignedServedDeliveryReceipt>,
    capacity: usize,
}

impl ReceiptQueue {
    /// A queue bounded at [`MAX_PENDING`].
    pub fn new() -> Self {
        Self::with_capacity(MAX_PENDING)
    }

    /// A queue bounded at `capacity` (clamped to at least 1 — a
    /// zero-capacity queue would drop every receipt).
    pub fn with_capacity(capacity: usize) -> Self {
        let capacity = capacity.max(1);
        Self {
            pending: VecDeque::with_capacity(capacity),
            capacity,
        }
    }

    /// Buffer `receipt`. If the queue is at capacity the OLDEST receipt
    /// is evicted first (LRU) — the newest is never the one dropped.
    pub fn push(&mut self, receipt: SignedServedDeliveryReceipt) -> PushOutcome {
        let outcome = if self.pending.len() >= self.capacity {
            // At capacity — evict the front (oldest) before pushing.
            let _ = self.pending.pop_front();
            PushOutcome::DroppedOldest
        } else {
            PushOutcome::Buffered
        };
        self.pending.push_back(receipt);
        outcome
    }

    /// Number of buffered receipts.
    pub fn len(&self) -> usize {
        self.pending.len()
    }

    /// Whether the queue holds no receipts.
    pub fn is_empty(&self) -> bool {
        self.pending.is_empty()
    }

    /// The configured upper bound.
    pub fn capacity(&self) -> usize {
        self.capacity
    }

    /// Remove and return up to `n` receipts from the FRONT (oldest
    /// first — FIFO). PR-E2.3's Edge pusher drains the queue with this.
    pub fn drain(&mut self, n: usize) -> Vec<SignedServedDeliveryReceipt> {
        let take = n.min(self.pending.len());
        self.pending.drain(..take).collect()
    }

    /// Return a previously-[`drain`](Self::drain)ed `batch` to the
    /// FRONT of the queue after a failed send (PR-E2.3).
    ///
    /// The batch was the oldest receipts; restoring it to the front
    /// keeps FIFO order — a plain [`push`](Self::push) would instead
    /// treat just-failed receipts as the newest and let a later
    /// overflow evict genuinely-older ones. The capacity bound still
    /// holds: if the queue refilled while the batch was off-queue, the
    /// surplus is evicted from the FRONT (the oldest — consistent with
    /// `push`'s keep-newest policy). Returns the number evicted so the
    /// caller can log a non-zero drop.
    pub fn requeue_front(&mut self, batch: Vec<SignedServedDeliveryReceipt>) -> usize {
        // Prepend in reverse so `batch` keeps its own internal order.
        for receipt in batch.into_iter().rev() {
            self.pending.push_front(receipt);
        }
        let mut evicted = 0;
        while self.pending.len() > self.capacity {
            let _ = self.pending.pop_front();
            evicted += 1;
        }
        evicted
    }
}

impl Default for ReceiptQueue {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    /// A signed receipt whose `body` is the single tag byte `tag` — so
    /// tests can identify receipts after they move through the queue.
    fn tagged(tag: u8) -> SignedServedDeliveryReceipt {
        SignedServedDeliveryReceipt {
            body: vec![tag],
            sig: vec![0u8; 64],
        }
    }

    fn tag_of(r: &SignedServedDeliveryReceipt) -> u8 {
        r.body[0]
    }

    #[test]
    fn push_below_capacity_buffers() {
        let mut q = ReceiptQueue::with_capacity(3);
        assert!(q.is_empty());
        assert_eq!(q.push(tagged(1)), PushOutcome::Buffered);
        assert_eq!(q.push(tagged(2)), PushOutcome::Buffered);
        assert_eq!(q.len(), 2);
        assert!(!q.is_empty());
    }

    #[test]
    fn push_at_capacity_drops_oldest_keeps_newest() {
        let mut q = ReceiptQueue::with_capacity(3);
        assert_eq!(q.push(tagged(1)), PushOutcome::Buffered);
        assert_eq!(q.push(tagged(2)), PushOutcome::Buffered);
        assert_eq!(q.push(tagged(3)), PushOutcome::Buffered);
        // Full — the next push evicts the oldest (tag 1).
        assert_eq!(q.push(tagged(4)), PushOutcome::DroppedOldest);
        assert_eq!(q.len(), 3); // still bounded
                                // FIFO order is now 2, 3, 4 — oldest gone, newest kept.
        let drained: Vec<u8> = q.drain(99).iter().map(tag_of).collect();
        assert_eq!(drained, vec![2, 3, 4]);
    }

    #[test]
    fn sustained_overflow_keeps_only_the_newest_capacity_receipts() {
        let mut q = ReceiptQueue::with_capacity(2);
        for tag in 1..=10u8 {
            q.push(tagged(tag));
        }
        let drained: Vec<u8> = q.drain(99).iter().map(tag_of).collect();
        // Only the two most-recent survive.
        assert_eq!(drained, vec![9, 10]);
    }

    #[test]
    fn drain_takes_fifo_and_is_bounded_by_len() {
        let mut q = ReceiptQueue::with_capacity(10);
        for tag in 1..=5u8 {
            q.push(tagged(tag));
        }
        // Partial drain takes the oldest first.
        let first_two: Vec<u8> = q.drain(2).iter().map(tag_of).collect();
        assert_eq!(first_two, vec![1, 2]);
        assert_eq!(q.len(), 3);
        // Draining more than is held returns everything, no panic.
        let rest: Vec<u8> = q.drain(999).iter().map(tag_of).collect();
        assert_eq!(rest, vec![3, 4, 5]);
        assert!(q.is_empty());
        // Draining an empty queue is a no-op.
        assert!(q.drain(5).is_empty());
    }

    #[test]
    fn requeue_front_restores_a_failed_batch_in_fifo_order() {
        let mut q = ReceiptQueue::with_capacity(10);
        for tag in 1..=5u8 {
            q.push(tagged(tag));
        }
        // Drain the two oldest (a "batch"), as the pusher would.
        let batch = q.drain(2);
        assert_eq!(batch.iter().map(tag_of).collect::<Vec<_>>(), vec![1, 2]);
        // The send failed — return the batch to the front, no eviction.
        assert_eq!(q.requeue_front(batch), 0);
        // FIFO is intact: 1, 2 are once again the oldest.
        let drained: Vec<u8> = q.drain(99).iter().map(tag_of).collect();
        assert_eq!(drained, vec![1, 2, 3, 4, 5]);
    }

    #[test]
    fn requeue_front_evicts_from_the_front_when_the_queue_refilled() {
        let mut q = ReceiptQueue::with_capacity(3);
        for tag in 1..=3u8 {
            q.push(tagged(tag));
        }
        let batch = q.drain(2); // tags 1, 2 — the oldest
                                // The producer refilled the queue to capacity while the batch
                                // was off-queue.
        for tag in 4..=6u8 {
            q.push(tagged(tag));
        }
        // Restoring the 2-receipt batch to a full (cap 3) queue evicts
        // the 2 oldest — the batch itself (the genuinely-oldest).
        let evicted = q.requeue_front(batch);
        assert_eq!(evicted, 2);
        assert_eq!(q.len(), 3);
        // The newest receipts always survive (keep-newest policy).
        let drained: Vec<u8> = q.drain(99).iter().map(tag_of).collect();
        assert_eq!(drained, vec![4, 5, 6]);
    }

    #[test]
    fn zero_capacity_is_clamped_to_one() {
        let mut q = ReceiptQueue::with_capacity(0);
        assert_eq!(q.capacity(), 1);
        assert_eq!(q.push(tagged(1)), PushOutcome::Buffered);
        assert_eq!(q.push(tagged(2)), PushOutcome::DroppedOldest);
        let drained: Vec<u8> = q.drain(99).iter().map(tag_of).collect();
        assert_eq!(drained, vec![2]);
    }

    #[test]
    fn default_uses_the_max_pending_bound() {
        assert_eq!(ReceiptQueue::default().capacity(), MAX_PENDING);
        assert_eq!(ReceiptQueue::new().capacity(), MAX_PENDING);
    }
}
