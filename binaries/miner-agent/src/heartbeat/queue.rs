//! The bounded heartbeat queue (PR-MA-6).
//!
//! [`HeartbeatQueue`] sits between the periodic builder task (the
//! producer) and the pusher task (the consumer). It is a bounded
//! `VecDeque<SignedMinerHeartbeat>` behind a [`tokio::sync::Mutex`] so
//! both tasks share it across `.await` points.
//!
//! ## LRU-drop-oldest on overflow
//!
//! When the queue is at `max_pending` and a fresh heartbeat is pushed,
//! the **oldest** queued heartbeat is dropped to make room — the
//! newest liveness signal is always the one worth keeping (vali only
//! cares that the miner is alive *now*, and it enforces a monotonic
//! sequence so a stale heartbeat is worthless anyway). A drop is a
//! normal shed, counted but never fatal.

use std::collections::VecDeque;

use hippius_types::heartbeat::SignedMinerHeartbeat;
use tokio::sync::Mutex;

/// A bounded, async-safe FIFO of signed heartbeats with
/// LRU-drop-oldest overflow.
pub struct HeartbeatQueue {
    inner: Mutex<VecDeque<SignedMinerHeartbeat>>,
    /// Hard cap. A `push` past this drops the front entry.
    capacity: usize,
}

impl HeartbeatQueue {
    /// A queue holding at most `capacity` heartbeats. `capacity` is
    /// validated `> 0` by [`crate::config::Config::validate`]; this
    /// constructor clamps a stray `0` to `1` defensively so a `push`
    /// can never panic on an empty `VecDeque`.
    pub fn new(capacity: usize) -> Self {
        Self {
            inner: Mutex::new(VecDeque::with_capacity(capacity.max(1))),
            capacity: capacity.max(1),
        }
    }

    /// Enqueue `hb`. Returns `true` if a stale heartbeat had to be
    /// dropped to make room (an overflow shed), `false` otherwise.
    pub async fn push(&self, hb: SignedMinerHeartbeat) -> bool {
        let mut q = self.inner.lock().await;
        let dropped = if q.len() >= self.capacity {
            // LRU: evict the OLDEST so the freshest signal survives.
            q.pop_front();
            true
        } else {
            false
        };
        q.push_back(hb);
        dropped
    }

    /// Pop the oldest queued heartbeat, or `None` if the queue is
    /// empty. The pusher drains FIFO so heartbeats relay in build
    /// order (their `sequence` is therefore monotone on the wire).
    pub async fn pop(&self) -> Option<SignedMinerHeartbeat> {
        self.inner.lock().await.pop_front()
    }

    /// Pop the oldest **non-stale** heartbeat, dropping any front
    /// entries whose `timestamp_unix` differs from `now_unix` by more
    /// than `max_age` seconds in EITHER direction (matching vali's
    /// symmetric anti-skew window), or whose body cannot be decoded
    /// — vali would reject those anyway. Returns the next fresh
    /// heartbeat (if any) together with the count dropped, for the
    /// pusher to log.
    ///
    /// `now_unix = None` disables the staleness check (a broken wall
    /// clock — fail-OPEN: do not drop fresh entries against a clock
    /// the caller could not read; undecodable bodies are still dropped).
    ///
    /// vali enforces an anti-skew window on a heartbeat's timestamp
    /// (`hippius_types::heartbeat::MAX_AGE_SECONDS`, ±300 s); the
    /// envelope is signed at build time, so a heartbeat aged past that
    /// window cannot be rescued by re-signing (that would tug the
    /// canonical-CBOR signed-envelope invariant). The pusher would
    /// otherwise retry the same stale envelope until process restart
    /// — observed in the §K end-to-end heartbeat test after a 26-min
    /// outage. Dropping the stale heads at pop time, with a built-in
    /// margin below the wire window, ends that loop.
    pub async fn pop_fresh(
        &self,
        now_unix: Option<i64>,
        max_age: i64,
    ) -> (Option<SignedMinerHeartbeat>, usize) {
        let max_age_u = u64::try_from(max_age).unwrap_or(u64::MAX);
        let mut q = self.inner.lock().await;
        let mut dropped = 0usize;
        while let Some(front) = q.pop_front() {
            let stale = match (front.timestamp_unix(), now_unix) {
                // An undecodable body cannot pass vali's verify either;
                // treat it as stale-equivalent and drop it.
                (None, _) => true,
                // Broken clock — fail-OPEN: keep the fresh entry.
                (Some(_), None) => false,
                // Symmetric anti-skew: a heartbeat too far in EITHER
                // direction is unrecoverable.
                (Some(ts), Some(now)) => now.abs_diff(ts) > max_age_u,
            };
            if stale {
                dropped += 1;
                continue;
            }
            return (Some(front), dropped);
        }
        (None, dropped)
    }

    /// The current queue depth — for the shutdown drain + tests.
    pub async fn len(&self) -> usize {
        self.inner.lock().await.len()
    }

    /// Whether the queue is currently empty.
    pub async fn is_empty(&self) -> bool {
        self.inner.lock().await.is_empty()
    }

    /// The configured capacity.
    pub fn capacity(&self) -> usize {
        self.capacity
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hippius_types::heartbeat::{MinerHeartbeat, DOMAIN, SCHEMA_VERSION};

    fn hb(seq: u64) -> SignedMinerHeartbeat {
        // The queue never inspects the body — a marker `body` whose
        // first byte is the sequence is enough to assert ordering.
        SignedMinerHeartbeat {
            body: vec![seq as u8],
            sig: vec![0u8; 64],
        }
    }

    /// A heartbeat whose canonical-CBOR `body` carries the given
    /// `timestamp_unix` — for the `pop_fresh` staleness tests, which
    /// have to look inside the body.
    fn hb_ts(ts: i64) -> SignedMinerHeartbeat {
        let h = MinerHeartbeat {
            schema_version: SCHEMA_VERSION,
            miner_id: "miner-test".into(),
            timestamp_unix: ts,
            sequence: ts as u64,
            vm_count_running: 0,
            vm_count_total: 0,
            cpu_load_1m_centi: 0,
            memory_total_mib: 0,
            memory_available_mib: 0,
            domain: DOMAIN.into(),
            graceful_exit_requested: false,
        };
        SignedMinerHeartbeat {
            body: h.canonical().unwrap(),
            sig: vec![0u8; 64],
        }
    }

    #[tokio::test]
    async fn push_then_pop_is_fifo() {
        let q = HeartbeatQueue::new(8);
        for s in 0..4 {
            assert!(!q.push(hb(s)).await);
        }
        assert_eq!(q.len().await, 4);
        for s in 0..4 {
            assert_eq!(q.pop().await.unwrap().body, vec![s as u8]);
        }
        assert!(q.pop().await.is_none());
    }

    #[tokio::test]
    async fn overflow_drops_the_oldest_and_keeps_the_newest() {
        let q = HeartbeatQueue::new(3);
        assert!(!q.push(hb(0)).await);
        assert!(!q.push(hb(1)).await);
        assert!(!q.push(hb(2)).await);
        // The 4th push overflows — `0` (oldest) is dropped.
        assert!(q.push(hb(3)).await, "an overflow push must report a drop");
        assert_eq!(q.len().await, 3);
        // Remaining, oldest-first: 1, 2, 3 — the newest survived.
        assert_eq!(q.pop().await.unwrap().body, vec![1]);
        assert_eq!(q.pop().await.unwrap().body, vec![2]);
        assert_eq!(q.pop().await.unwrap().body, vec![3]);
    }

    #[tokio::test]
    async fn capacity_one_keeps_only_the_latest() {
        let q = HeartbeatQueue::new(1);
        q.push(hb(10)).await;
        assert!(q.push(hb(11)).await);
        assert_eq!(q.len().await, 1);
        assert_eq!(q.pop().await.unwrap().body, vec![11]);
    }

    #[tokio::test]
    async fn zero_capacity_is_clamped_to_one() {
        let q = HeartbeatQueue::new(0);
        assert_eq!(q.capacity(), 1);
        assert!(!q.push(hb(1)).await);
        assert!(q.push(hb(2)).await);
        assert_eq!(q.len().await, 1);
    }

    #[tokio::test]
    async fn pop_fresh_drops_stale_heads_and_returns_the_first_fresh() {
        let q = HeartbeatQueue::new(8);
        let now = 1_000_000_i64;
        // Two stale (> 240 s old), then two fresh.
        q.push(hb_ts(now - 1_000)).await;
        q.push(hb_ts(now - 500)).await;
        q.push(hb_ts(now - 10)).await;
        q.push(hb_ts(now - 5)).await;
        let (hb, dropped) = q.pop_fresh(Some(now), 240).await;
        assert_eq!(dropped, 2);
        let hb = hb.expect("a fresh heartbeat must be returned");
        assert_eq!(hb.timestamp_unix(), Some(now - 10));
        // The second fresh entry survives — `pop_fresh` returns ONE.
        assert_eq!(q.len().await, 1);
    }

    #[tokio::test]
    async fn pop_fresh_drops_future_skewed_entries_too() {
        // vali's anti-skew is symmetric (±MAX_AGE_SECONDS); a heartbeat
        // signed under a clock step BACK is also unrecoverable — must
        // be dropped just like a too-old one.
        let q = HeartbeatQueue::new(4);
        let now = 1_000_000_i64;
        q.push(hb_ts(now + 1_000)).await; // 1000 s in the future
        q.push(hb_ts(now - 5)).await; // fresh
        let (hb, dropped) = q.pop_fresh(Some(now), 240).await;
        assert_eq!(dropped, 1);
        let hb = hb.expect("the fresh entry survives");
        assert_eq!(hb.timestamp_unix(), Some(now - 5));
    }

    #[tokio::test]
    async fn pop_fresh_returns_none_and_a_count_when_every_entry_is_stale() {
        let q = HeartbeatQueue::new(8);
        let now = 1_000_000_i64;
        for ago in [1_000_i64, 500, 300] {
            q.push(hb_ts(now - ago)).await;
        }
        let (hb, dropped) = q.pop_fresh(Some(now), 240).await;
        assert!(hb.is_none(), "no fresh heartbeat to return");
        assert_eq!(dropped, 3, "every entry was stale and dropped");
        assert!(q.is_empty().await);
    }

    #[tokio::test]
    async fn pop_fresh_treats_an_undecodable_body_as_stale() {
        let q = HeartbeatQueue::new(4);
        // A heartbeat whose `body` is not canonical CBOR — vali would
        // refuse to verify it; the queue treats it as stale-equivalent.
        q.push(SignedMinerHeartbeat {
            body: vec![0xff, 0xff, 0xff],
            sig: vec![0u8; 64],
        })
        .await;
        let (hb, dropped) = q.pop_fresh(Some(0), 240).await;
        assert!(hb.is_none());
        assert_eq!(dropped, 1);
    }

    #[tokio::test]
    async fn pop_fresh_with_a_broken_clock_keeps_fresh_entries() {
        // `now = None` (clock failed) — must NOT drop a decodable
        // heartbeat just because we cannot measure its skew. Fail-OPEN.
        let q = HeartbeatQueue::new(4);
        q.push(hb_ts(1_700_000_000)).await;
        let (hb, dropped) = q.pop_fresh(None, 240).await;
        assert!(hb.is_some());
        assert_eq!(dropped, 0);
    }

    #[tokio::test]
    async fn pop_fresh_with_a_broken_clock_still_drops_undecodable_bodies() {
        // A poison body is always dropped — the clock is irrelevant.
        let q = HeartbeatQueue::new(4);
        q.push(SignedMinerHeartbeat {
            body: vec![0xff, 0xff],
            sig: vec![0u8; 64],
        })
        .await;
        let (hb, dropped) = q.pop_fresh(None, 240).await;
        assert!(hb.is_none());
        assert_eq!(dropped, 1);
    }

    #[tokio::test]
    async fn pop_fresh_on_an_empty_queue_returns_none_and_zero() {
        let q = HeartbeatQueue::new(4);
        let (hb, dropped) = q.pop_fresh(Some(1_000_000), 240).await;
        assert!(hb.is_none());
        assert_eq!(dropped, 0);
    }

    #[tokio::test]
    async fn is_empty_tracks_depth() {
        let q = HeartbeatQueue::new(4);
        assert!(q.is_empty().await);
        q.push(hb(1)).await;
        assert!(!q.is_empty().await);
        q.pop().await;
        assert!(q.is_empty().await);
    }
}
