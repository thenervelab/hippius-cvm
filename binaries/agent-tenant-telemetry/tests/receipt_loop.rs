//! End-to-end receipt-loop test (PR-E2.2).
//!
//! Drives the receipt loop with the crate's real components — a real
//! `Ed25519TelemetrySigner`, the real `ReceiptBuilder` / `ReceiptQueue`
//! — and the `Static*` sources standing in for the I/O seams. The
//! crypto is entirely real: every buffered receipt is signature-checked
//! against the established signer's key.
//!
//! Two paths are exercised:
//! - [`tick`] driven directly with a controlled clock — deterministic,
//!   exact assertions over many intervals.
//! - [`run_receipt_loop`] — the real synchronous driver, ended by a
//!   wall-clock shutdown latch.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::sync::Mutex;
use std::time::{Duration, Instant};

use ed25519_dalek::Signature;
use hippius_agent_tenant_telemetry::receipt_loop::unix_now;
use hippius_agent_tenant_telemetry::{
    run_receipt_loop, tick, Challenge, Ed25519TelemetrySigner, ReceiptBuilder, ReceiptLoopConfig,
    ReceiptQueue, ShutdownWatch, StaticChallengeSource, StaticServedWorkSource, TelemetrySigner,
    TickOutcome,
};
use hippius_guest::verify_served_receipt;
use hippius_types::served_receipt::{ServedDeliveryReceipt, SignedServedDeliveryReceipt};

const GENESIS: u64 = 1_000;
const INTERVAL: u64 = 60;
const TTL: u64 = 3_600;
const DEGRADATION: u32 = 125;

// A `static` (not `const`) so `&VALIDATOR_NONCE` is a `&'static` ref —
// the borrowed `ServedDeliveryReceipt` needs `&'static [u8; 32]` here.
static VALIDATOR_NONCE: [u8; 32] = [0x2Au8; 32];

fn challenge() -> Challenge {
    Challenge {
        validator_id: b"validator-e22".to_vec(),
        validator_nonce: VALIDATOR_NONCE,
        epoch: 17,
    }
}

fn builder(genesis: u64) -> ReceiptBuilder {
    ReceiptBuilder::new(
        "vm-e22".to_string(),
        "lease-e22".to_string(),
        b"family-e22".to_vec(),
        b"node-e22".to_vec(),
        "high-mem".to_string(),
        genesis,
    )
}

/// The receipt the loop is EXPECTED to have signed for the `seq`-th
/// interval (controlled-clock path) — built independently so its
/// `canonical()` can be re-derived and checked against the buffered
/// signed body by `verify_served_receipt`.
fn expected(seq: u64) -> ServedDeliveryReceipt<'static> {
    let period_start = GENESIS + (seq - 1) * INTERVAL;
    let period_end = GENESIS + seq * INTERVAL;
    ServedDeliveryReceipt {
        validator_id: b"validator-e22",
        validator_nonce: &VALIDATOR_NONCE,
        epoch: 17,
        vm_id: "vm-e22",
        lease_id: "lease-e22",
        family_id: b"family-e22",
        node_id: b"node-e22",
        resource_class: "high-mem",
        monotonic_seq: seq,
        observed_degradation_bps: DEGRADATION,
        period_start,
        period_end,
        expiry: period_end + TTL,
    }
}

/// Assert `signed` is the genuine signed receipt for interval `seq` —
/// the full §23 body-equality + signature check.
fn assert_is_receipt(
    signer: &Ed25519TelemetrySigner,
    signed: &SignedServedDeliveryReceipt,
    seq: u64,
) {
    verify_served_receipt(&signer.verifying_key(), signed, &expected(seq))
        .unwrap_or_else(|_| panic!("buffered receipt {seq} must verify"));
}

#[test]
fn five_intervals_via_tick_buffer_five_chained_receipts() {
    let signer = Ed25519TelemetrySigner::generate().unwrap();
    let mut b = builder(GENESIS);
    let mut q = ReceiptQueue::new();
    let cs = StaticChallengeSource::new(challenge());
    let ws = StaticServedWorkSource::new(DEGRADATION).unwrap();

    for seq in 1..=5u64 {
        let now = GENESIS + seq * INTERVAL;
        let outcome = tick(&mut b, &mut q, &cs, &ws, &signer, now, TTL).unwrap();
        assert_eq!(outcome, TickOutcome::Buffered);
        assert_eq!(q.len() as u64, seq);
    }

    // The queue holds exactly the five signed receipts, in order, each
    // a genuine signature over the expected §23 body.
    let buffered = q.drain(99);
    assert_eq!(buffered.len(), 5);
    for (i, signed) in buffered.iter().enumerate() {
        assert_is_receipt(&signer, signed, (i + 1) as u64);
    }
    // Every receipt is byte-distinct (monotonic_seq + window differ).
    for i in 0..buffered.len() {
        for j in (i + 1)..buffered.len() {
            assert_ne!(buffered[i].body, buffered[j].body);
        }
    }
}

#[test]
fn an_idle_challenge_source_buffers_nothing() {
    let signer = Ed25519TelemetrySigner::generate().unwrap();
    let mut b = builder(GENESIS);
    let mut q = ReceiptQueue::new();
    let cs = StaticChallengeSource::idle();
    let ws = StaticServedWorkSource::new(DEGRADATION).unwrap();

    for seq in 1..=10u64 {
        let now = GENESIS + seq * INTERVAL;
        assert_eq!(
            tick(&mut b, &mut q, &cs, &ws, &signer, now, TTL).unwrap(),
            TickOutcome::Idle
        );
    }
    assert!(q.is_empty());
    // No idle interval burned a sequence number.
    assert_eq!(b.next_seq(), 1);
}

#[test]
fn sustained_overflow_keeps_only_the_newest_receipts() {
    let signer = Ed25519TelemetrySigner::generate().unwrap();
    let mut b = builder(GENESIS);
    let mut q = ReceiptQueue::with_capacity(3);
    let cs = StaticChallengeSource::new(challenge());
    let ws = StaticServedWorkSource::new(DEGRADATION).unwrap();

    for seq in 1..=10u64 {
        let now = GENESIS + seq * INTERVAL;
        let outcome = tick(&mut b, &mut q, &cs, &ws, &signer, now, TTL).unwrap();
        if seq <= 3 {
            assert_eq!(outcome, TickOutcome::Buffered);
        } else {
            assert_eq!(outcome, TickOutcome::BufferedDroppedOldest);
        }
    }
    // Only the three most-recent receipts survive — seqs 8, 9, 10.
    let buffered = q.drain(99);
    assert_eq!(buffered.len(), 3);
    for (signed, seq) in buffered.iter().zip(8..=10u64) {
        assert_is_receipt(&signer, signed, seq);
    }
}

/// A [`ShutdownWatch`] that latches at a wall-clock instant.
struct DeadlineShutdown {
    deadline: Instant,
}

impl DeadlineShutdown {
    /// Latches `delay` from now.
    fn after(delay: Duration) -> Self {
        Self {
            deadline: Instant::now() + delay,
        }
    }

    /// Already latched.
    fn already() -> Self {
        Self {
            deadline: Instant::now(),
        }
    }
}

impl ShutdownWatch for DeadlineShutdown {
    fn is_pending(&self) -> bool {
        Instant::now() >= self.deadline
    }
}

#[test]
fn run_receipt_loop_returns_at_once_when_already_shut_down() {
    let signer = Ed25519TelemetrySigner::generate().unwrap();
    let mut b = builder(GENESIS);
    // PR-E2.3 — the loop now takes the queue behind a `Mutex` (shared
    // with the vsock pusher); the tests lock it to inspect.
    let q = Mutex::new(ReceiptQueue::new());
    let cs = StaticChallengeSource::new(challenge());
    let ws = StaticServedWorkSource::new(DEGRADATION).unwrap();
    let shutdown = DeadlineShutdown::already();
    let config = ReceiptLoopConfig {
        interval: Duration::from_secs(INTERVAL),
        ttl_secs: TTL,
    };

    let started = Instant::now();
    run_receipt_loop(&mut b, &q, &cs, &ws, &signer, &shutdown, &config)
        .expect("the loop returns Ok on shutdown");
    // A pre-latched shutdown is honored before the first tick — it must
    // not have slept out an interval.
    assert!(started.elapsed() < Duration::from_secs(INTERVAL));
    assert!(q.lock().unwrap().is_empty());
}

#[test]
fn run_receipt_loop_buffers_real_receipts_then_stops_on_shutdown() {
    let signer = Ed25519TelemetrySigner::generate().unwrap();
    // Genesis is "now" so the live clock's seconds advance the window.
    let genesis = unix_now().unwrap();
    let mut b = builder(genesis);
    let q = Mutex::new(ReceiptQueue::new());
    let cs = StaticChallengeSource::new(challenge());
    let ws = StaticServedWorkSource::new(DEGRADATION).unwrap();
    // A 1.1 s interval keeps consecutive ticks in distinct whole
    // seconds (receipts are second-granular); shut down after ~2.6 s.
    let config = ReceiptLoopConfig {
        interval: Duration::from_millis(1_100),
        ttl_secs: TTL,
    };
    let shutdown = DeadlineShutdown::after(Duration::from_millis(2_600));

    let started = Instant::now();
    run_receipt_loop(&mut b, &q, &cs, &ws, &signer, &shutdown, &config)
        .expect("the loop returns Ok on shutdown");
    let elapsed = started.elapsed();

    // Terminated promptly after the latch — not left running.
    assert!(
        elapsed < Duration::from_secs(6),
        "loop did not stop promptly"
    );
    // The real driver ran: ≥1 interval elapsed and a genuine receipt
    // was built, signed, and buffered.
    let buffered = q.lock().unwrap().drain(99);
    assert!(
        !buffered.is_empty(),
        "the loop should have buffered >= 1 receipt"
    );

    let vk = signer.verifying_key();
    for signed in &buffered {
        // Window fields are clock-driven (not predictable), so verify
        // the signature DIRECTLY over the canonical body rather than
        // re-deriving expected bytes.
        assert_eq!(signed.sig.len(), 64);
        let sig = Signature::from_slice(&signed.sig).expect("64-byte signature");
        vk.verify_strict(&signed.body, &sig)
            .expect("a buffered receipt must carry the signer's signature");
    }
    // Receipts are byte-distinct across intervals.
    for i in 0..buffered.len() {
        for j in (i + 1)..buffered.len() {
            assert_ne!(buffered[i].body, buffered[j].body);
        }
    }
}

#[test]
fn run_receipt_loop_rejects_a_sub_second_interval() {
    let signer = Ed25519TelemetrySigner::generate().unwrap();
    let cs = StaticChallengeSource::new(challenge());
    let ws = StaticServedWorkSource::new(DEGRADATION).unwrap();
    let shutdown = DeadlineShutdown::after(Duration::from_secs(3_600));

    // A zero interval would busy-spin; any sub-second interval would
    // land every tick inside the same whole second (a non-advancing
    // window). Both are refused fail-closed, before the first tick,
    // regardless of the shutdown latch.
    for interval in [
        Duration::ZERO,
        Duration::from_millis(100),
        Duration::from_millis(999),
    ] {
        let mut b = builder(GENESIS);
        let q = Mutex::new(ReceiptQueue::new());
        let config = ReceiptLoopConfig {
            interval,
            ttl_secs: TTL,
        };
        let started = Instant::now();
        let err = run_receipt_loop(&mut b, &q, &cs, &ws, &signer, &shutdown, &config)
            .expect_err("a sub-second interval must be rejected");
        assert_eq!(err.class(), "receipt-interval-too-short");
        assert!(q.lock().unwrap().is_empty());
        assert!(started.elapsed() < Duration::from_secs(1));
    }
}
