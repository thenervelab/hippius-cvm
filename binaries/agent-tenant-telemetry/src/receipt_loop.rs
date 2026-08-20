//! The synchronous periodic receipt loop.
//!
//! [`tick`] is the unit of work: pull the current validator challenge
//! and observed degradation, build + sign ONE receipt, buffer it. It is
//! deterministic given `now_unix` — the basis for the loop's tests.
//!
//! [`run_receipt_loop`] is the driver: it calls `tick` once per
//! `interval`, sleeping between ticks in short polls so a `SIGTERM`
//! latched in the [`ShutdownWatch`] ends the loop within
//! [`POLL_CHUNK`]. It is synchronous — `std::thread::sleep`, no tokio —
//! matching the rest of the §E agent track.

use std::sync::Mutex;
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::challenge::ChallengeSource;
use crate::error::{Result, TelemetryError};
use crate::receipt_builder::ReceiptBuilder;
use crate::receipt_queue::{PushOutcome, ReceiptQueue};
use crate::served_work::ServedWorkSource;
use crate::shutdown::ShutdownWatch;
use crate::signer::TelemetrySigner;

/// The granularity at which the loop re-checks the shutdown latch while
/// sleeping out an interval. Small enough that a `SIGTERM` is honored
/// promptly; large enough not to busy-spin.
pub const POLL_CHUNK: Duration = Duration::from_millis(500);

/// What one [`tick`] did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TickOutcome {
    /// No validator challenge was available — no receipt was built.
    Idle,
    /// A receipt was built, signed, and buffered.
    Buffered,
    /// A receipt was built, signed, and buffered, but the queue bound
    /// forced eviction of the oldest buffered receipt.
    BufferedDroppedOldest,
}

/// Execute one loop tick for the interval ending at `now_unix`.
///
/// Pulls the current challenge ([`ChallengeSource`]) and observed
/// degradation ([`ServedWorkSource`]), then — if a challenge is
/// available — builds, signs, and buffers one receipt. A `None`
/// challenge yields [`TickOutcome::Idle`] (the agent has nothing to
/// attest to yet); that is not an error.
///
/// Deterministic given `now_unix` — this is the function the loop's
/// behaviour tests drive directly, with no clock and no sleeping.
pub fn tick(
    builder: &mut ReceiptBuilder,
    queue: &mut ReceiptQueue,
    challenge_source: &dyn ChallengeSource,
    work_source: &dyn ServedWorkSource,
    signer: &dyn TelemetrySigner,
    now_unix: u64,
    ttl_secs: u64,
) -> Result<TickOutcome> {
    let Some(challenge) = challenge_source.current_challenge()? else {
        return Ok(TickOutcome::Idle);
    };
    let degradation = work_source.observed_degradation_bps()?;
    // `build_next` returns only a `SignedServedDeliveryReceipt` — the
    // receipt is signed before it can reach the queue, so an unsigned
    // receipt can never be buffered.
    let signed = builder.build_next(signer, &challenge, degradation, now_unix, ttl_secs)?;
    Ok(match queue.push(signed) {
        PushOutcome::Buffered => TickOutcome::Buffered,
        PushOutcome::DroppedOldest => TickOutcome::BufferedDroppedOldest,
    })
}

/// Tuning for [`run_receipt_loop`].
pub struct ReceiptLoopConfig {
    /// Wall time between ticks.
    pub interval: Duration,
    /// `expiry = period_end + ttl_secs` for each receipt.
    pub ttl_secs: u64,
}

/// Run the receipt loop until a shutdown signal is latched.
///
/// Each `interval`: build + sign + buffer one receipt (see [`tick`]).
/// The interval is waited out *before* every tick, so each receipt
/// covers a full `interval`-long window. A tick error is logged by
/// static class and the interval skipped — one bad interval never ends
/// the loop. The loop returns `Ok(())` once `shutdown` reports pending;
/// `main` then drops the established signer, zeroizing the key.
///
/// `queue` is a `&Mutex<ReceiptQueue>` (PR-E2.3): this loop is one of
/// two threads sharing it — it pushes, the vsock pusher drains. The
/// lock is held only for the [`tick`] (build + sign + push), never
/// across the interval sleep, so the pusher is never starved. A
/// poisoned lock (the pusher panicked holding it) ends the loop
/// fail-closed with `Err(TelemetryError::Receipt("queue-poisoned"))`.
///
/// `config.interval` MUST be at least 1 second (receipts are
/// second-granular) — a shorter interval returns
/// `Err(TelemetryError::Receipt("receipt-interval-too-short"))`.
pub fn run_receipt_loop(
    builder: &mut ReceiptBuilder,
    queue: &Mutex<ReceiptQueue>,
    challenge_source: &dyn ChallengeSource,
    work_source: &dyn ServedWorkSource,
    signer: &dyn TelemetrySigner,
    shutdown: &dyn ShutdownWatch,
    config: &ReceiptLoopConfig,
) -> Result<()> {
    // Receipts are second-granular: two ticks inside the same whole
    // second produce a non-advancing window, which `build_next` rejects.
    // An interval below 1 s would therefore fail every tick (and a zero
    // interval would additionally busy-spin `sleep_until_due_or_shutdown`).
    // `Config::resolve` already rejects a zero interval; the loop
    // enforces the ≥ 1 s floor fail-closed for any caller, so the
    // "always makes progress, never busy-spins" invariant lives with
    // the loop itself — not only at the config entry point.
    if config.interval < Duration::from_secs(1) {
        return Err(TelemetryError::Receipt("receipt-interval-too-short"));
    }
    // Whether the last tick was idle — so "no challenge" is logged once
    // on entry into idle, not every interval.
    let mut logged_idle = false;
    loop {
        if shutdown.is_pending() {
            return Ok(());
        }
        // Wait out the interval BEFORE the tick, so the first receipt —
        // like every later one — covers a full `interval`-long window.
        if sleep_until_due_or_shutdown(config.interval, shutdown) {
            return Ok(());
        }
        let now = match unix_now() {
            Ok(n) => n,
            Err(e) => {
                eprintln!(
                    "hippius-agent-tenant-telemetry: receipt tick skipped: {}",
                    e.class()
                );
                continue;
            }
        };
        // Hold the shared queue lock only for the tick (build + sign +
        // push) — released at the end of this block, before the match
        // arms and well before the next interval sleep, so the vsock
        // pusher draining the same queue is never starved.
        let outcome = {
            let mut q = match queue.lock() {
                Ok(q) => q,
                // The pusher thread panicked holding the lock. The loop
                // cannot safely buffer any more — end fail-closed.
                Err(_) => return Err(TelemetryError::Receipt("queue-poisoned")),
            };
            tick(
                builder,
                &mut q,
                challenge_source,
                work_source,
                signer,
                now,
                config.ttl_secs,
            )
        };
        match outcome {
            Ok(TickOutcome::Idle) => {
                if !logged_idle {
                    eprintln!(
                        "hippius-agent-tenant-telemetry: receipt loop idle — no validator challenge"
                    );
                    logged_idle = true;
                }
            }
            Ok(TickOutcome::Buffered) => {
                logged_idle = false;
                eprintln!("hippius-agent-tenant-telemetry: receipt buffered");
            }
            Ok(TickOutcome::BufferedDroppedOldest) => {
                logged_idle = false;
                eprintln!(
                    "hippius-agent-tenant-telemetry: receipt buffered — queue full, oldest evicted"
                );
            }
            Err(e) => {
                // One bad interval is skipped, not fatal — the loop
                // keeps the established signer alive and tries again.
                eprintln!(
                    "hippius-agent-tenant-telemetry: receipt tick skipped: {}",
                    e.class()
                );
            }
        }
    }
}

/// Read the current Unix time in whole seconds. `main` uses it for the
/// loop's genesis `period_start`; the loop uses it each tick.
pub fn unix_now() -> Result<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .map_err(|_| TelemetryError::Receipt("clock-before-epoch"))
}

/// Sleep for `interval`, re-checking `shutdown` every [`POLL_CHUNK`].
/// Returns `true` if shutdown became pending — the caller then ends the
/// loop without waiting out the rest of the interval.
fn sleep_until_due_or_shutdown(interval: Duration, shutdown: &dyn ShutdownWatch) -> bool {
    let mut slept = Duration::ZERO;
    while slept < interval {
        if shutdown.is_pending() {
            return true;
        }
        let chunk = POLL_CHUNK.min(interval - slept);
        thread::sleep(chunk);
        slept += chunk;
    }
    shutdown.is_pending()
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::challenge::{Challenge, StaticChallengeSource};
    use crate::served_work::StaticServedWorkSource;
    use crate::signer::Ed25519TelemetrySigner;
    use hippius_guest::verify_served_receipt;
    use hippius_types::served_receipt::ServedDeliveryReceipt;

    fn challenge() -> Challenge {
        Challenge {
            validator_id: b"validator-1".to_vec(),
            validator_nonce: [8u8; 32],
            epoch: 3,
        }
    }

    fn builder(genesis: u64) -> ReceiptBuilder {
        ReceiptBuilder::new(
            "vm-1".to_string(),
            "lease-1".to_string(),
            b"family-1".to_vec(),
            b"node-1".to_vec(),
            "std".to_string(),
            genesis,
        )
    }

    #[test]
    fn tick_with_a_challenge_builds_signs_and_buffers() {
        let signer = Ed25519TelemetrySigner::generate().unwrap();
        let mut b = builder(100);
        let mut q = ReceiptQueue::new();
        let cs = StaticChallengeSource::new(challenge());
        let ws = StaticServedWorkSource::new(0).unwrap();

        let outcome = tick(&mut b, &mut q, &cs, &ws, &signer, 160, 3_600).unwrap();
        assert_eq!(outcome, TickOutcome::Buffered);
        assert_eq!(q.len(), 1);

        // The buffered receipt is genuinely signed + well-formed.
        let nonce = [8u8; 32];
        let expected = ServedDeliveryReceipt {
            validator_id: b"validator-1",
            validator_nonce: &nonce,
            epoch: 3,
            vm_id: "vm-1",
            lease_id: "lease-1",
            family_id: b"family-1",
            node_id: b"node-1",
            resource_class: "std",
            monotonic_seq: 1,
            observed_degradation_bps: 0,
            period_start: 100,
            period_end: 160,
            expiry: 160 + 3_600,
        };
        let buffered = q.drain(1);
        verify_served_receipt(&signer.verifying_key(), &buffered[0], &expected).unwrap();
    }

    #[test]
    fn tick_with_no_challenge_is_idle_and_buffers_nothing() {
        let signer = Ed25519TelemetrySigner::generate().unwrap();
        let mut b = builder(100);
        let mut q = ReceiptQueue::new();
        let cs = StaticChallengeSource::idle();
        let ws = StaticServedWorkSource::new(0).unwrap();

        let outcome = tick(&mut b, &mut q, &cs, &ws, &signer, 160, 3_600).unwrap();
        assert_eq!(outcome, TickOutcome::Idle);
        assert!(q.is_empty());
        // An idle tick burns no sequence number.
        assert_eq!(b.next_seq(), 1);
    }

    #[test]
    fn successive_ticks_accumulate_distinct_receipts() {
        let signer = Ed25519TelemetrySigner::generate().unwrap();
        let mut b = builder(100);
        let mut q = ReceiptQueue::new();
        let cs = StaticChallengeSource::new(challenge());
        let ws = StaticServedWorkSource::new(0).unwrap();

        // Five intervals, each ending one minute after the last.
        for (i, now) in [160u64, 220, 280, 340, 400].into_iter().enumerate() {
            let outcome = tick(&mut b, &mut q, &cs, &ws, &signer, now, 3_600).unwrap();
            assert_eq!(outcome, TickOutcome::Buffered);
            assert_eq!(q.len(), i + 1);
        }
        assert_eq!(q.len(), 5);
        // Every buffered receipt is byte-distinct (monotonic_seq differs).
        let drained = q.drain(99);
        for i in 0..drained.len() {
            for j in (i + 1)..drained.len() {
                assert_ne!(drained[i].body, drained[j].body);
            }
        }
    }

    #[test]
    fn tick_full_queue_reports_dropped_oldest() {
        let signer = Ed25519TelemetrySigner::generate().unwrap();
        let mut b = builder(100);
        let mut q = ReceiptQueue::with_capacity(2);
        let cs = StaticChallengeSource::new(challenge());
        let ws = StaticServedWorkSource::new(0).unwrap();

        assert_eq!(
            tick(&mut b, &mut q, &cs, &ws, &signer, 160, 3_600).unwrap(),
            TickOutcome::Buffered
        );
        assert_eq!(
            tick(&mut b, &mut q, &cs, &ws, &signer, 220, 3_600).unwrap(),
            TickOutcome::Buffered
        );
        // Third tick — queue full, oldest evicted.
        assert_eq!(
            tick(&mut b, &mut q, &cs, &ws, &signer, 280, 3_600).unwrap(),
            TickOutcome::BufferedDroppedOldest
        );
        assert_eq!(q.len(), 2);
    }

    #[test]
    fn tick_propagates_a_non_advancing_interval_error() {
        let signer = Ed25519TelemetrySigner::generate().unwrap();
        let mut b = builder(100);
        let mut q = ReceiptQueue::new();
        let cs = StaticChallengeSource::new(challenge());
        let ws = StaticServedWorkSource::new(0).unwrap();

        // now == genesis — the interval has not advanced.
        let err = tick(&mut b, &mut q, &cs, &ws, &signer, 100, 3_600)
            .expect_err("a non-advancing interval must surface as an error");
        assert_eq!(err.class(), "interval-not-advanced");
        assert!(q.is_empty());
    }
}
