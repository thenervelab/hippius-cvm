//! PR-H3 integration tests — per-source rate limiting + bounded
//! queue, driven via the public `relay_once` entry point.
//!
//! These tests prove the §10 invariants from the *outside* of the
//! crate (the unit tests in `src/rate_limit.rs` and `src/queue.rs`
//! prove the building blocks in isolation; here we exercise the
//! whole pipeline with the limiter + sink wired in):
//!
//! 1. **Saturate one source → shed the rest.** Burst-many envelopes
//!    from peer A succeed; the next one shed with
//!    `Err(RateLimited)` and the per-IP counter increments. No
//!    response to the source — opaque relay.
//! 2. **Per-source isolation.** Peer A saturated does not affect
//!    peer B's allowance.
//! 3. **Queue full → shed AND attribute to source.** With queue
//!    capacity 1 and no consumer, the second envelope returns
//!    `Err(QueueFull)` and the per-IP shed counter goes up.
//! 4. **GC drops dormant buckets.** After 1h of inactivity (driven
//!    via `gc_at`), the per-IP map is empty.
//! 5. **WorkerGone is surfaced as a fail-closed.** Dropping the
//!    source half before `relay_once` causes the third send to
//!    return `Err(WorkerGone)` — process-level fail-closed.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use hippius_edge_gateway::{
    bounded_queue, relay_once, BoundedSink, Direction, EdgeError, EdgeGatewayConfig, MessageKind,
    NoopTelemetry, PeerId, PerSourceRateLimiter, RateLimitConfig,
};
use std::time::Duration;

fn peer(n: u8) -> PeerId {
    PeerId::new(&format!("test-peer-{n}"))
}

/// `relay_once` with a no-op telemetry sink. These tests assert on
/// rate-limit / queue behaviour; PR-H6 telemetry emission is covered
/// by `tests/telemetry_integration.rs`, so a [`NoopTelemetry`] keeps
/// the call sites here focused.
async fn relay(
    direction: Direction,
    kind: MessageKind,
    peer: PeerId,
    limiter: &PerSourceRateLimiter,
    sink: &BoundedSink,
) -> Result<(), EdgeError> {
    relay_once(direction, kind, peer, limiter, sink, &NoopTelemetry).await
}

/// Build a limiter with refill=0 (drained-stays-drained — easier to
/// reason about in test) and a small burst, plus a default-cap sink.
/// `idle_horizon` defaults to 1h.
fn small_limiter(burst: u32) -> PerSourceRateLimiter {
    PerSourceRateLimiter::new(
        RateLimitConfig {
            refill_per_sec: 0.0,
            burst,
        },
        Duration::from_secs(3600),
        // Cap high enough that the test cases here never trigger
        // eviction — the cap-eviction integration test lives in
        // the unit module where it can drive cap directly.
        usize::MAX,
    )
}

#[tokio::test]
async fn saturating_one_peer_sheds_subsequent_requests() {
    let limiter = small_limiter(3);
    let (sink, mut source) = bounded_queue(128);
    let p = peer(1);

    // First 3 send → enqueue; 4th → RateLimited.
    for _ in 0..3 {
        relay(
            Direction::MinerToInner,
            MessageKind::ServedReceipt,
            p.clone(),
            &limiter,
            &sink,
        )
        .await
        .expect("within-burst envelope must enqueue");
    }
    let err = relay(
        Direction::MinerToInner,
        MessageKind::ServedReceipt,
        p.clone(),
        &limiter,
        &sink,
    )
    .await
    .unwrap_err();
    assert!(
        matches!(err, EdgeError::RateLimited),
        "expected RateLimited, got {err:?}"
    );

    // Shed counter must show exactly one drop attributed to `p`.
    let snap = limiter.shed_snapshot();
    assert_eq!(snap.get(&p).copied(), Some(1));

    // Drain the queue so the worker side (this test) doesn't leak.
    for _ in 0..3 {
        assert!(source.recv().await.is_some());
    }
}

#[tokio::test]
async fn per_source_isolation_under_saturation() {
    // Peer A drains its bucket; Peer B's bucket is unaffected.
    let limiter = small_limiter(1);
    let (sink, mut source) = bounded_queue(16);
    let a = peer(1);
    let b = peer(2);

    relay(
        Direction::MinerToInner,
        MessageKind::ServedReceipt,
        a.clone(),
        &limiter,
        &sink,
    )
    .await
    .expect("a within burst");
    let err = relay(
        Direction::MinerToInner,
        MessageKind::ServedReceipt,
        a.clone(),
        &limiter,
        &sink,
    )
    .await
    .unwrap_err();
    assert!(matches!(err, EdgeError::RateLimited));

    // B is untouched — still within its own burst.
    relay(
        Direction::MinerToInner,
        MessageKind::ServedReceipt,
        b.clone(),
        &limiter,
        &sink,
    )
    .await
    .expect("b within burst (untouched by a's saturation)");

    // Drain the two enqueued envelopes so the test leaves no
    // dangling worker-side state.
    assert!(source.recv().await.is_some());
    assert!(source.recv().await.is_some());
}

#[tokio::test]
async fn queue_full_sheds_and_attributes_to_source() {
    // Generous limiter (won't trip) + capacity-1 queue with no
    // consumer → second enqueue is QueueFull, third is QueueFull
    // again, counter shows both.
    let limiter = PerSourceRateLimiter::from_config(&EdgeGatewayConfig::default());
    let (sink, _source) = bounded_queue(1);
    let p = peer(42);

    relay(
        Direction::MinerToInner,
        MessageKind::ServedReceipt,
        p.clone(),
        &limiter,
        &sink,
    )
    .await
    .expect("first enqueue must succeed");
    for _ in 0..2 {
        let err = relay(
            Direction::MinerToInner,
            MessageKind::ServedReceipt,
            p.clone(),
            &limiter,
            &sink,
        )
        .await
        .unwrap_err();
        assert!(
            matches!(err, EdgeError::QueueFull),
            "expected QueueFull, got {err:?}"
        );
    }
    let snap = limiter.shed_snapshot();
    assert_eq!(snap.get(&p).copied(), Some(2));
}

#[tokio::test]
async fn worker_gone_is_fail_closed() {
    // Dropping the source half before the first send causes
    // `try_send` to return `Closed` — the relay surfaces it as
    // `WorkerGone`, which the binary maps to a process-level exit.
    let limiter = PerSourceRateLimiter::from_config(&EdgeGatewayConfig::default());
    let (sink, source) = bounded_queue(1);
    drop(source);
    let err = relay(
        Direction::MinerToInner,
        MessageKind::ServedReceipt,
        peer(1),
        &limiter,
        &sink,
    )
    .await
    .unwrap_err();
    assert!(
        matches!(err, EdgeError::WorkerGone),
        "expected WorkerGone, got {err:?}"
    );
}

#[test]
fn gc_drops_dormant_buckets_after_idle_horizon() {
    // Drive the limiter directly (no async needed). After 1h of
    // inactivity all buckets evict — pins the "spawn millions of
    // fake unique peers" DoS-resistance contract from the integration
    // side.
    let limiter = small_limiter(1);
    let t0 = std::time::Instant::now();
    for n in 0..32u8 {
        // `try_acquire` is the only public time-injection-free entry,
        // but the cfg(refill=0, burst=1) ensures each call drains the
        // peer's bucket once and that's it. We don't need an `Instant`
        // injection at the integration boundary — we just call
        // `gc_at` later with a synthetic future Instant.
        assert!(limiter.try_acquire(&peer(n)));
    }
    assert_eq!(limiter.tracked_peers(), 32);
    // 1h + 1ns past `t0`. NOTE: `t0` was sampled before the
    // `try_acquire` calls, so the actual `last_seen` on each bucket
    // is *after* `t0` — but it's a few microseconds at most. 1h is
    // well outside that fuzz, so all 32 still evict.
    limiter.gc_at(t0 + Duration::from_secs(3600) + Duration::from_secs(1));
    assert_eq!(limiter.tracked_peers(), 0);
}

#[tokio::test]
async fn shed_counter_keys_per_peer() {
    // Two peers, each saturated separately → snapshot has two
    // entries, each = 1. Pins the
    // `edge_gw_shed_total{source=PeerId}` attribution contract
    // from the integration side. PR-H4 swapped `source=IP` for
    // `source=PeerId` (NAT survives, see [`crate::mtls::peer_id`]).
    let limiter = small_limiter(1);
    let (sink, mut source) = bounded_queue(16);
    let a = peer(1);
    let b = peer(2);

    // 1 ok + 1 shed each.
    relay(
        Direction::MinerToInner,
        MessageKind::ServedReceipt,
        a.clone(),
        &limiter,
        &sink,
    )
    .await
    .unwrap();
    let err = relay(
        Direction::MinerToInner,
        MessageKind::ServedReceipt,
        a.clone(),
        &limiter,
        &sink,
    )
    .await
    .unwrap_err();
    assert!(matches!(err, EdgeError::RateLimited));
    relay(
        Direction::MinerToInner,
        MessageKind::ServedReceipt,
        b.clone(),
        &limiter,
        &sink,
    )
    .await
    .unwrap();
    let err = relay(
        Direction::MinerToInner,
        MessageKind::ServedReceipt,
        b.clone(),
        &limiter,
        &sink,
    )
    .await
    .unwrap_err();
    assert!(matches!(err, EdgeError::RateLimited));

    let snap = limiter.shed_snapshot();
    assert_eq!(snap.get(&a).copied(), Some(1));
    assert_eq!(snap.get(&b).copied(), Some(1));

    // Drain enqueued.
    assert!(source.recv().await.is_some());
    assert!(source.recv().await.is_some());
}
