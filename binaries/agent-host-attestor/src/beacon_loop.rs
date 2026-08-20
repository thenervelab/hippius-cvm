//! The synchronous periodic beacon loop.
//!
//! [`tick`] is the unit of work: draw a fresh nonce, build + sign ONE
//! beacon, buffer it. It is deterministic given `now_unix` + the nonce
//! source — the basis for the loop's tests.
//!
//! [`run_beacon_loop`] is the driver: it calls `tick` once per
//! `interval`, sleeping between beats in short polls so a `SIGTERM`
//! latched in the [`ShutdownWatch`] ends the loop within [`POLL_CHUNK`].
//! It is synchronous — `std::thread::sleep`, no tokio — matching the
//! rest of the agent (a measured TCB stays minimal).
//!
//! Unlike the tenant telemetry receipt loop there is no "idle" tick: a
//! running host is always alive, so every beat emits a beacon. The
//! expensive SNP report is minted once at enrollment; a beat is an
//! Ed25519 signature only (see [`crate::beacon_builder`]).

use std::sync::Mutex;
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::beacon_builder::BeaconBuilder;
use crate::beacon_queue::{BeaconQueue, PushOutcome};
use crate::error::{HostAttestorError, Result};
use crate::nonce::NonceSource;
use crate::shutdown::ShutdownWatch;
use crate::signer::HostAttestorSigner;

/// The granularity at which the loop re-checks the shutdown latch while
/// sleeping out an interval.
pub const POLL_CHUNK: Duration = Duration::from_millis(500);

/// What one [`tick`] did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TickOutcome {
    /// A beacon was built, signed, and buffered.
    Buffered,
    /// A beacon was built, signed, and buffered, but the queue bound
    /// forced eviction of the oldest buffered beacon.
    BufferedDroppedOldest,
}

/// Execute one loop tick observed at `now_unix`.
///
/// Draws a fresh nonce ([`NonceSource`]), builds + signs one beacon with
/// `expiry = now_unix + window_secs`, and buffers it. Deterministic
/// given `now_unix` + a deterministic nonce source — this is the
/// function the loop's behaviour tests drive directly, with no clock and
/// no sleeping.
pub fn tick(
    builder: &mut BeaconBuilder,
    queue: &mut BeaconQueue,
    signer: &HostAttestorSigner,
    nonce_source: &dyn NonceSource,
    now_unix: u64,
    window_secs: u64,
) -> Result<TickOutcome> {
    let nonce = nonce_source.fresh_nonce()?;
    // `build_next` returns only a `SignedHostBeacon` — the beacon is
    // signed before it can reach the queue, so an unsigned beacon can
    // never be buffered.
    let signed = builder.build_next(signer, nonce, now_unix, window_secs)?;
    Ok(match queue.push(signed) {
        PushOutcome::Buffered => TickOutcome::Buffered,
        PushOutcome::DroppedOldest => TickOutcome::BufferedDroppedOldest,
    })
}

/// Tuning for [`run_beacon_loop`].
pub struct BeaconLoopConfig {
    /// Wall time between beats.
    pub interval: Duration,
    /// `expiry = observed + window_secs` for each beacon. MUST be ≥ 1.
    pub window_secs: u64,
}

/// Run the beacon loop until a shutdown signal is latched.
///
/// Each `interval`: build + sign + buffer one beacon (see [`tick`]). The
/// interval is waited out *before* every beat. A tick error is logged by
/// static class and the interval skipped — one bad beat never ends the
/// loop. The loop returns `Ok(())` once `shutdown` reports pending;
/// `main` then drops the established signer, zeroizing the key.
///
/// `queue` is a `&Mutex<BeaconQueue>`: this loop is one of two threads
/// sharing it — it pushes, the vsock pusher drains. The lock is held
/// only for the [`tick`], never across the interval sleep. A poisoned
/// lock (the pusher panicked holding it) ends the loop fail-closed.
///
/// `config.window_secs` MUST be ≥ 1 (a beacon's `expiry` must be
/// strictly after `observed`) and `config.interval` ≥ 1 s — otherwise
/// the loop returns fail-closed before the first beat.
pub fn run_beacon_loop(
    builder: &mut BeaconBuilder,
    queue: &Mutex<BeaconQueue>,
    signer: &HostAttestorSigner,
    nonce_source: &dyn NonceSource,
    shutdown: &dyn ShutdownWatch,
    config: &BeaconLoopConfig,
) -> Result<()> {
    // A sub-second interval would busy-spin the poll sleep; a zero
    // window would produce a beacon whose `expiry == observed`, which
    // `canonical()` rejects. Enforce both fail-closed for any caller.
    if config.interval < Duration::from_secs(1) {
        return Err(HostAttestorError::Beacon("beacon-interval-too-short"));
    }
    if config.window_secs == 0 {
        return Err(HostAttestorError::Beacon("beacon-window-zero"));
    }
    loop {
        if shutdown.is_pending() {
            return Ok(());
        }
        // Wait out the interval BEFORE the beat.
        if sleep_until_due_or_shutdown(config.interval, shutdown) {
            return Ok(());
        }
        let now = match unix_now() {
            Ok(n) => n,
            Err(e) => {
                eprintln!(
                    "hippius-agent-host-attestor: beacon tick skipped: {}",
                    e.class()
                );
                continue;
            }
        };
        // Hold the shared queue lock only for the tick.
        let outcome = {
            let mut q = match queue.lock() {
                Ok(q) => q,
                Err(_) => return Err(HostAttestorError::Beacon("queue-poisoned")),
            };
            tick(
                builder,
                &mut q,
                signer,
                nonce_source,
                now,
                config.window_secs,
            )
        };
        match outcome {
            Ok(TickOutcome::Buffered) => {
                eprintln!("hippius-agent-host-attestor: beacon buffered");
            }
            Ok(TickOutcome::BufferedDroppedOldest) => {
                eprintln!(
                    "hippius-agent-host-attestor: beacon buffered — queue full, oldest evicted"
                );
            }
            Err(e) => {
                // One bad beat is skipped, not fatal — the loop keeps the
                // established signer alive and tries again.
                eprintln!(
                    "hippius-agent-host-attestor: beacon tick skipped: {}",
                    e.class()
                );
            }
        }
    }
}

/// Read the current Unix time in whole seconds.
pub fn unix_now() -> Result<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .map_err(|_| HostAttestorError::Beacon("clock-before-epoch"))
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
    use crate::nonce::{NonceSource, NONCE_LEN};
    use crate::platform::PlatformClaims;
    use crate::signer::HostAttestorSigner;
    use crate::snp::{SnpReport, SNP_REPORT_LEN};
    use hippius_types::host_attestor::{HostAliveBeacon, DIGEST_LEN, PUBKEY_LEN};
    use std::cell::Cell;
    use zeroize::Zeroizing;

    /// A deterministic nonce source: each call returns `[counter; 32]`,
    /// incrementing the counter, so tests can pin per-beat nonces.
    struct SeqNonceSource {
        next: Cell<u8>,
    }
    impl SeqNonceSource {
        fn new() -> Self {
            Self { next: Cell::new(1) }
        }
    }
    impl NonceSource for SeqNonceSource {
        fn fresh_nonce(&self) -> Result<[u8; NONCE_LEN]> {
            let n = self.next.get();
            self.next.set(n + 1);
            Ok([n; NONCE_LEN])
        }
    }

    fn platform() -> PlatformClaims {
        let mut b = vec![0u8; SNP_REPORT_LEN];
        for (i, byte) in b.iter_mut().skip(0x1A0).take(64).enumerate() {
            *byte = 0x80 | (i as u8);
        }
        PlatformClaims::from_report(&SnpReport(b)).unwrap()
    }

    fn signer() -> HostAttestorSigner {
        HostAttestorSigner::from_snp_derived_key(&Zeroizing::new([3u8; 32])).unwrap()
    }

    fn builder(signer: &HostAttestorSigner) -> BeaconBuilder {
        BeaconBuilder::new(
            "node-host-1".to_string(),
            "boot-abc".to_string(),
            [0xAAu8; DIGEST_LEN],
            [0xDDu8; DIGEST_LEN],
            signer.pubkey(),
            &platform(),
        )
    }

    #[test]
    fn tick_builds_signs_and_buffers_a_beacon() {
        let s = signer();
        let mut b = builder(&s);
        let mut q = BeaconQueue::new();
        let ns = SeqNonceSource::new();
        assert_eq!(
            tick(&mut b, &mut q, &s, &ns, 1_800_000_000, 300).unwrap(),
            TickOutcome::Buffered
        );
        assert_eq!(q.len(), 1);
        let signed = q.drain(1).pop().unwrap();
        let beacon = HostAliveBeacon::decode(&signed.body).unwrap();
        assert_eq!(beacon.seq, 1);
        assert_eq!(beacon.nonce, [1u8; PUBKEY_LEN]);
    }

    #[test]
    fn successive_ticks_accumulate_distinct_beacons() {
        let s = signer();
        let mut b = builder(&s);
        let mut q = BeaconQueue::new();
        let ns = SeqNonceSource::new();
        for (i, now) in [1_000u64, 1_060, 1_120].into_iter().enumerate() {
            assert_eq!(
                tick(&mut b, &mut q, &s, &ns, now, 60).unwrap(),
                TickOutcome::Buffered
            );
            assert_eq!(q.len(), i + 1);
        }
        let drained = q.drain(99);
        for i in 0..drained.len() {
            for j in (i + 1)..drained.len() {
                assert_ne!(drained[i].body, drained[j].body);
            }
        }
    }

    #[test]
    fn tick_full_queue_reports_dropped_oldest() {
        let s = signer();
        let mut b = builder(&s);
        let mut q = BeaconQueue::with_capacity(2);
        let ns = SeqNonceSource::new();
        assert_eq!(
            tick(&mut b, &mut q, &s, &ns, 1_000, 60).unwrap(),
            TickOutcome::Buffered
        );
        assert_eq!(
            tick(&mut b, &mut q, &s, &ns, 1_060, 60).unwrap(),
            TickOutcome::Buffered
        );
        assert_eq!(
            tick(&mut b, &mut q, &s, &ns, 1_120, 60).unwrap(),
            TickOutcome::BufferedDroppedOldest
        );
        assert_eq!(q.len(), 2);
    }
}
