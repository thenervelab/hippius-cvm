//! Per-source token-bucket rate limiter (PR-H3, §10; PR-H4 keying).
//!
//! Edge is the only network path between the untrusted miner NetBird
//! mesh and the inner vRack control plane (§5 / §9). A compromised
//! or runaway miner peer can issue requests at arbitrary rate; the
//! per-process token bucket in `kbs_transport::rate_limit` is
//! defence-in-depth (it can't discriminate between callers), so the
//! authoritative per-source layer belongs **here**, at the Edge.
//!
//! ## Design
//!
//! - One `Bucket` per [`PeerId`] (PR-H4: cryptographic identity
//!   extracted from the mTLS leaf cert; PR-H3 keyed on socket IP
//!   which collapsed CGNAT'd peers into one bucket).
//!   `try_acquire(&peer)` lazily upserts.
//! - Default cfg: 50 tokens/sec sustained, burst 100. Configurable
//!   via the [`crate::config::EdgeGatewayConfig`] TOML loader.
//! - On reject the bucket's `shed_total` counter increments — the
//!   per-peer counter LIVES INSIDE the bucket, so when GC drops a
//!   dormant bucket the counter goes with it (no parallel map to
//!   keep in sync, no second DoS surface).
//! - **Hard cap on the bucket map** (`max_tracked_peers`, default
//!   65k). On insert-at-cap the limiter evicts the oldest-`last_seen`
//!   bucket, so the map size is **bounded at all times** — codex
//!   review of PR-H3 v1 caught the original "GC every 4096 calls
//!   inside the 1h horizon" window where memory could grow linearly.
//! - Dormant buckets are also GC'd at 1h of inactivity, default —
//!   the cap handles the worst case (unique-peer flood), the
//!   opportunistic GC handles the normal case (legit peer drops).
//!
//! ## What this is NOT
//!
//! - NOT an L4 firewall. `ip_forward=0` + vRack micro-segment (§5,
//!   §10) handle that. This is application-layer shedding for
//!   schema-valid traffic.
//! - NOT a response generator. Edge is OPAQUE (§5.6): on shed we
//!   drop the bytes, log a static-classifier outcome, bump the
//!   counter, and return — the source gets no signal it was
//!   rate-limited. That's deliberate (§10: "drop at the wire").

use crate::config::RateLimitConfig;
use crate::mtls::PeerId;
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// How often (in `try_acquire` calls) the opportunistic GC sweep
/// runs. Picked to amortize the `O(N)` sweep cost: at 50 req/s per
/// peer, a sweep every ~80s of activity is well below the 1h
/// dormant horizon. The constant has no security impact — choosing
/// `1` would just make every call O(map_size).
const GC_SWEEP_PERIOD: u64 = 4096;

/// Per-source bucket. The struct is a private detail of
/// [`PerSourceRateLimiter`]; nothing outside the module can read or
/// build one.
#[derive(Debug, Clone, Copy)]
struct Bucket {
    tokens: f64,
    /// Most recent `try_acquire_at` or `note_shed_at` timestamp. GC
    /// uses this as the dormancy clock — touching the bucket (even
    /// to record a shed) keeps it alive.
    last_seen: Instant,
    /// Total sheds attributed to this source IP since the bucket was
    /// created. Lives INSIDE the bucket on purpose so GC drops the
    /// counter alongside the bucket — there is no parallel map to
    /// fall out of sync.
    shed_total: u64,
}

/// Per-source-IP token-bucket rate limiter. Thread-safe via a single
/// short-critical-section `Mutex` on the per-IP map.
///
/// The mutex is poisoned-deny: a poisoned lock means a prior caller
/// panicked mid-update, so the safe default at the wire is to drop
/// the current request (return `false`) rather than risk doubling a
/// shed counter or refilling a corrupted bucket. Matches the
/// `kbs_transport::rate_limit::NonceRateLimiter` posture.
pub struct PerSourceRateLimiter {
    cfg: RateLimitConfig,
    /// Inactivity horizon — buckets whose `last_seen` is older than
    /// `now - idle_horizon` get dropped by GC. Configurable via TOML
    /// (default 1h); the field is here, not in `RateLimitConfig`, so
    /// the bucket math is decoupled from the eviction policy.
    idle_horizon: Duration,
    /// Hard cap on `state.buckets.len()` — the limiter NEVER lets
    /// the map exceed this. On insert-at-cap the oldest bucket
    /// (smallest `last_seen`) is evicted to make room. Sourced from
    /// `EdgeGatewayConfig::max_tracked_peers`.
    max_tracked_peers: usize,
    state: Mutex<State>,
}

#[derive(Debug)]
struct State {
    buckets: HashMap<PeerId, Bucket>,
    /// Monotone counter incremented on every `try_acquire_at`. Used
    /// purely as a "have we hit the sweep period yet" check — no
    /// security meaning. `u64` so it can't wrap in any realistic
    /// process lifetime.
    calls_since_gc: u64,
}

impl PerSourceRateLimiter {
    /// Construct with explicit knobs. Most callers should prefer
    /// [`Self::from_config`] which sources every field from the
    /// validated [`crate::config::EdgeGatewayConfig`].
    ///
    /// `max_tracked_peers = 0` would make the limiter unusable; the
    /// config validator forbids it, and callers passing a config
    /// through `from_config` are protected. If you build a limiter
    /// directly with `new(_, _, 0)` (only the tests do), `try_acquire`
    /// will always fail to insert and shed-counter snapshots will
    /// be empty — a behaviour that's safe but useless. There's no
    /// `debug_assert!` here because the production path can't reach
    /// it (config validation runs first).
    pub fn new(cfg: RateLimitConfig, idle_horizon: Duration, max_tracked_peers: usize) -> Self {
        Self {
            cfg,
            idle_horizon,
            max_tracked_peers,
            state: Mutex::new(State {
                buckets: HashMap::new(),
                calls_since_gc: 0,
            }),
        }
    }

    /// Build a limiter from the full [`crate::config::EdgeGatewayConfig`].
    /// Convenience for callers that already have one.
    pub fn from_config(cfg: &crate::config::EdgeGatewayConfig) -> Self {
        Self::new(cfg.rate_limit, cfg.idle_horizon(), cfg.max_tracked_peers)
    }

    /// Try to consume one token from `peer`'s bucket. Returns `true`
    /// on success (caller proceeds); on `false` the call is shed —
    /// the bucket's `shed_total` has already been bumped.
    ///
    /// `now` injection is exposed via [`Self::try_acquire_at`] for
    /// deterministic tests.
    pub fn try_acquire(&self, peer: &PeerId) -> bool {
        self.try_acquire_at(peer, Instant::now())
    }

    fn try_acquire_at(&self, peer: &PeerId, now: Instant) -> bool {
        let Ok(mut state) = self.state.lock() else {
            return false;
        };

        state.calls_since_gc = state.calls_since_gc.saturating_add(1);
        if state.calls_since_gc >= GC_SWEEP_PERIOD {
            state.calls_since_gc = 0;
            sweep(&mut state.buckets, now, self.idle_horizon);
        }

        // PR-H3 review (codex+gemini): enforce the hard cap BEFORE
        // `or_insert` could allocate a new bucket — sweep + evict-
        // oldest if we're at capacity and the peer is new. Bounded
        // memory under unique-peer flood: the map size never exceeds
        // `max_tracked_peers`.
        if !state.buckets.contains_key(peer) {
            self.ensure_capacity_for_new(&mut state, now);
            if state.buckets.len() >= self.max_tracked_peers {
                // Cap is 0 (only reachable from a hand-rolled `new`,
                // not from validated config) → refuse to insert and
                // shed silently. Cannot bump `shed_total` because
                // there's no bucket to bump.
                return false;
            }
        }

        let bucket = state.buckets.entry(peer.clone()).or_insert(Bucket {
            tokens: f64::from(self.cfg.burst),
            last_seen: now,
            shed_total: 0,
        });

        let elapsed = now.saturating_duration_since(bucket.last_seen);
        if elapsed > Duration::ZERO {
            let refill = elapsed.as_secs_f64() * self.cfg.refill_per_sec;
            bucket.tokens = (bucket.tokens + refill).min(f64::from(self.cfg.burst));
        }
        bucket.last_seen = now;

        if bucket.tokens >= 1.0 {
            bucket.tokens -= 1.0;
            true
        } else {
            bucket.shed_total = bucket.shed_total.saturating_add(1);
            false
        }
    }

    /// Make room for a new peer bucket: opportunistically GC, then
    /// evict the oldest-`last_seen` entry if we're still at cap. The
    /// scan is `O(N)` but only fires on cap-bound inserts, which is
    /// the attack path itself — i.e., the attacker pays the cost.
    fn ensure_capacity_for_new(&self, state: &mut State, now: Instant) {
        if state.buckets.len() < self.max_tracked_peers {
            return;
        }
        // Opportunistic sweep first — frees dormant buckets without
        // touching active ones.
        sweep(&mut state.buckets, now, self.idle_horizon);
        if state.buckets.len() < self.max_tracked_peers {
            return;
        }
        // Still at cap → pick the bucket with the smallest
        // `last_seen` and evict it. Under unique-IP flood the
        // attacker's own buckets are the "freshest", so this evicts
        // legit peers first IF the attacker outpaces them — which
        // is the same outcome a real L4 SYN flood would have. The
        // alternative (refuse new IPs) would be worse: it would
        // freeze the bucket set against any future legit peer.
        if let Some(oldest) = state
            .buckets
            .iter()
            .min_by_key(|(_, b)| b.last_seen)
            .map(|(p, _)| p.clone())
        {
            state.buckets.remove(&oldest);
        }
    }

    /// Record a shed for `peer` without trying to acquire a token.
    /// Used by the bounded-queue stage: when validate succeeds but
    /// the forward queue is full we still attribute the drop to the
    /// peer so `edge_gw_shed_total{source=...}` covers both
    /// rate-limit AND queue-full drops.
    ///
    /// Creates a bucket on demand if `peer` has none — same dormancy
    /// rules apply, so GC will collect it.
    pub fn note_shed(&self, peer: &PeerId) {
        self.note_shed_at(peer, Instant::now());
    }

    fn note_shed_at(&self, peer: &PeerId, now: Instant) {
        let Ok(mut state) = self.state.lock() else {
            return;
        };
        // Same cap enforcement as `try_acquire_at` — `note_shed` is
        // reachable from the queue-full path before any prior
        // `try_acquire` if the bucket was GC'd in between, so it
        // must also be bounded.
        if !state.buckets.contains_key(peer) {
            self.ensure_capacity_for_new(&mut state, now);
            if state.buckets.len() >= self.max_tracked_peers {
                return;
            }
        }
        let bucket = state.buckets.entry(peer.clone()).or_insert(Bucket {
            tokens: f64::from(self.cfg.burst),
            last_seen: now,
            shed_total: 0,
        });
        bucket.last_seen = now;
        bucket.shed_total = bucket.shed_total.saturating_add(1);
    }

    /// Run the dormant-bucket sweep against `now`. Exposed for the
    /// integration tests so they can drive GC deterministically;
    /// production relies on the opportunistic in-call sweep.
    pub fn gc_at(&self, now: Instant) {
        let Ok(mut state) = self.state.lock() else {
            return;
        };
        sweep(&mut state.buckets, now, self.idle_horizon);
        state.calls_since_gc = 0;
    }

    /// Snapshot of per-source shed counts. Returns a `HashMap` rather
    /// than streaming under the lock — the bucket map is bounded by
    /// active peers (GC ensures), so the allocation is small. Used by
    /// the eventual PR-H6 metrics dump for
    /// `edge_gw_shed_total{source=PeerId}`.
    pub fn shed_snapshot(&self) -> HashMap<PeerId, u64> {
        let Ok(state) = self.state.lock() else {
            return HashMap::new();
        };
        state
            .buckets
            .iter()
            .filter(|(_, b)| b.shed_total > 0)
            .map(|(p, b)| (p.clone(), b.shed_total))
            .collect()
    }

    /// Number of buckets currently tracked. Used by GC tests to
    /// assert eviction; not meaningful in production telemetry
    /// (active-peer count is the same number with a fixed offset).
    pub fn tracked_peers(&self) -> usize {
        self.state.lock().map(|s| s.buckets.len()).unwrap_or(0)
    }
}

fn sweep(buckets: &mut HashMap<PeerId, Bucket>, now: Instant, idle_horizon: Duration) {
    buckets.retain(|_, b| now.saturating_duration_since(b.last_seen) < idle_horizon);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn peer(n: u8) -> PeerId {
        PeerId::new(&format!("test-peer-{n}"))
    }

    fn cfg(refill: f64, burst: u32) -> RateLimitConfig {
        RateLimitConfig {
            refill_per_sec: refill,
            burst,
        }
    }

    /// Pre-cap-enforcement helper: the existing unit tests don't
    /// exercise `max_tracked_peers`, so they should pass a value
    /// large enough never to trigger eviction. The dedicated cap
    /// tests use the public `new` constructor directly.
    impl PerSourceRateLimiter {
        fn new_for_tests(cfg: RateLimitConfig, idle_horizon: Duration) -> Self {
            Self::new(cfg, idle_horizon, usize::MAX)
        }
    }

    #[test]
    fn bucket_starts_full_per_source() {
        let rl = PerSourceRateLimiter::new_for_tests(cfg(1.0, 3), Duration::from_secs(3600));
        let p = peer(1);
        // Each new peer gets a fresh full bucket.
        for _ in 0..3 {
            assert!(rl.try_acquire(&p));
        }
        assert!(!rl.try_acquire(&p));
    }

    #[test]
    fn bucket_refills_at_rate() {
        let rl = PerSourceRateLimiter::new_for_tests(cfg(10.0, 1), Duration::from_secs(3600));
        let t0 = Instant::now();
        let p = peer(1);
        assert!(rl.try_acquire_at(&p, t0));
        assert!(!rl.try_acquire_at(&p, t0));
        // 10 tokens/sec → 1 token in 100ms.
        assert!(rl.try_acquire_at(&p, t0 + Duration::from_millis(100)));
    }

    #[test]
    fn bucket_capped_at_burst() {
        let rl = PerSourceRateLimiter::new_for_tests(cfg(1000.0, 5), Duration::from_secs(3600));
        let t0 = Instant::now();
        let p = peer(1);
        for _ in 0..5 {
            assert!(rl.try_acquire_at(&p, t0));
        }
        assert!(!rl.try_acquire_at(&p, t0));
        // 10 sec elapsed would refill 10000 tokens — must cap at burst=5.
        let t1 = t0 + Duration::from_secs(10);
        for _ in 0..5 {
            assert!(rl.try_acquire_at(&p, t1));
        }
        assert!(!rl.try_acquire_at(&p, t1));
    }

    #[test]
    fn per_source_isolation() {
        // Two peers must each get their own bucket — saturating peer A
        // must not affect peer B's allowance.
        let rl = PerSourceRateLimiter::new_for_tests(cfg(1.0, 2), Duration::from_secs(3600));
        let a = peer(1);
        let b = peer(2);
        assert!(rl.try_acquire(&a));
        assert!(rl.try_acquire(&a));
        assert!(!rl.try_acquire(&a)); // a exhausted
                                      // b is untouched.
        assert!(rl.try_acquire(&b));
        assert!(rl.try_acquire(&b));
        assert!(!rl.try_acquire(&b));
    }

    #[test]
    fn shed_counter_increments_on_reject_only() {
        let rl = PerSourceRateLimiter::new_for_tests(cfg(0.0, 1), Duration::from_secs(3600));
        let p = peer(1);
        assert!(rl.try_acquire(&p));
        for _ in 0..5 {
            assert!(!rl.try_acquire(&p));
        }
        let snap = rl.shed_snapshot();
        assert_eq!(snap.get(&p).copied(), Some(5));
    }

    #[test]
    fn note_shed_creates_bucket_if_missing() {
        // Queue-full path bumps shed for peers that may never have
        // gone through `try_acquire` (e.g., the limiter was given a
        // generous cfg and didn't shed at the rate-limit step).
        let rl = PerSourceRateLimiter::new_for_tests(cfg(50.0, 100), Duration::from_secs(3600));
        let p = peer(7);
        assert!(rl.shed_snapshot().is_empty());
        rl.note_shed(&p);
        rl.note_shed(&p);
        let snap = rl.shed_snapshot();
        assert_eq!(snap.get(&p).copied(), Some(2));
    }

    #[test]
    fn gc_drops_dormant_buckets() {
        let rl = PerSourceRateLimiter::new_for_tests(cfg(1.0, 1), Duration::from_secs(3600));
        let t0 = Instant::now();
        for n in 0..10u8 {
            assert!(rl.try_acquire_at(&peer(n), t0));
        }
        assert_eq!(rl.tracked_peers(), 10);
        // 1h + 1ns elapsed — every bucket is dormant.
        rl.gc_at(t0 + Duration::from_secs(3600) + Duration::from_nanos(1));
        assert_eq!(rl.tracked_peers(), 0);
    }

    #[test]
    fn map_size_is_hard_capped_via_oldest_eviction() {
        // PR-H3 review (codex blocker, gemini concern): the bucket
        // map MUST never exceed `max_tracked_peers`. Insert
        // cap+overflow unique peers and assert the map size sits
        // exactly at cap throughout.
        let cap = 4;
        let rl = PerSourceRateLimiter::new(cfg(0.0, 1), Duration::from_secs(3600), cap);
        let t0 = Instant::now();
        // Insert cap peers with monotonically increasing timestamps
        // so the oldest-`last_seen` is the first one.
        for n in 0..cap as u8 {
            assert!(rl.try_acquire_at(&peer(n), t0 + Duration::from_secs(n as u64)));
        }
        assert_eq!(rl.tracked_peers(), cap);

        // Insert one more — must evict the oldest (peer(0)) and keep
        // the rest.
        let new_peer = peer(99);
        assert!(rl.try_acquire_at(&new_peer, t0 + Duration::from_secs(1000)));
        assert_eq!(rl.tracked_peers(), cap);

        // peer(0) was evicted → next acquire on it re-creates a
        // bucket (which itself evicts the next-oldest, i.e. peer(1)).
        assert!(rl.try_acquire_at(&peer(0), t0 + Duration::from_secs(2000)));
        assert_eq!(rl.tracked_peers(), cap);
    }

    #[test]
    fn cap_eviction_prefers_dormant_buckets_first() {
        // A bucket older than `idle_horizon` should be reaped by the
        // pre-eviction sweep — no oldest-`last_seen` scan needed.
        let cap = 2;
        let horizon = Duration::from_secs(60);
        let rl = PerSourceRateLimiter::new(cfg(0.0, 1), horizon, cap);
        let t0 = Instant::now();
        assert!(rl.try_acquire_at(&peer(1), t0));
        // Far in the future: peer(1) is now dormant.
        let t1 = t0 + Duration::from_secs(120);
        assert!(rl.try_acquire_at(&peer(2), t1));
        // Inserting peer(3) at cap should sweep peer(1) out — both
        // peer(2) and the new peer(3) survive.
        let t2 = t1 + Duration::from_secs(1);
        assert!(rl.try_acquire_at(&peer(3), t2));
        assert_eq!(rl.tracked_peers(), 2);
    }

    #[test]
    fn cap_of_zero_silently_sheds() {
        // Hand-rolled `new(_, _, 0)` is the only path to this state
        // — config validation forbids it in production. The expected
        // behaviour: `try_acquire` always returns false, the map
        // stays empty, no panic.
        let rl = PerSourceRateLimiter::new(cfg(50.0, 100), Duration::from_secs(3600), 0);
        assert!(!rl.try_acquire(&peer(1)));
        assert_eq!(rl.tracked_peers(), 0);
    }

    #[test]
    fn gc_keeps_recently_active_buckets() {
        // `refill=0` means a drained bucket stays drained — gives us
        // an unambiguous identity test post-GC: the surviving bucket
        // for `fresh` must still be drained, while a fresh
        // `try_acquire` on the evicted `stale` peer gets a brand-new
        // (full) bucket.
        let rl = PerSourceRateLimiter::new_for_tests(cfg(0.0, 1), Duration::from_secs(3600));
        let t0 = Instant::now();
        let stale = peer(1);
        let fresh = peer(2);
        assert!(rl.try_acquire_at(&stale, t0)); // stale → 0
        let t1 = t0 + Duration::from_secs(1800);
        assert!(rl.try_acquire_at(&fresh, t1)); // fresh → 0
                                                // 1h after `stale`'s last activity: `stale` evicted, `fresh` kept.
        rl.gc_at(t0 + Duration::from_secs(3601));
        assert_eq!(rl.tracked_peers(), 1);
        // The surviving bucket is `fresh` and is still drained.
        assert!(!rl.try_acquire_at(&fresh, t0 + Duration::from_secs(3601)));
        // The evicted `stale` peer now gets a brand-new full bucket.
        assert!(rl.try_acquire_at(&stale, t0 + Duration::from_secs(3601)));
    }
}
