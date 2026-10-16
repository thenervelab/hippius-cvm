//! The keepalive daemon's loop and its stop (docs: issue #1562).
//!
//! [`run`] ticks every `interval` until a stop latches (SIGTERM/SIGINT,
//! [`install_stop_latch`]), sleeping in short polls so a stop is seen
//! within [`POLL`]. On the stop it runs ONE final tick — a real one: fresh
//! KBS nonce, SNP report, `SignedLiveAttestation` relayed to vali — so the
//! uptime meter, which credits a liveness sample BACKWARD from its
//! verification instant, covers the window up to the stop. Without it the
//! last receipt window of every stop is never paid.
//!
//! The stop is bounded FROM THE SIGNAL: a watchdog started with the loop
//! sees the latch within [`STOP_POLL`], runs `on_stop` (production: freeze
//! the components checks on their last pre-stop reading — the units they
//! look at are stopping too), and fires `on_deadline` (production: exit the
//! process) once `final_deadline` has passed since — whether the final tick
//! or a periodic tick the signal landed in is still running. A KBS or a
//! host relay that hangs cannot hold the shutdown. It is skipped when no tick
//! ever minted an attestation: a guest that never got through to the KBS
//! (a bare VM, a blocked path) has nothing to prove and should stop at once.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

/// How often a sleeping loop re-checks the stop latch.
pub const POLL: Duration = Duration::from_millis(500);
/// How often the watchdog checks the stop latch.
pub const STOP_POLL: Duration = Duration::from_millis(100);
/// The final tick's bound. `hippius-keepalive.service` sets
/// `TimeoutStopSec` above it.
pub const FINAL_DEADLINE: Duration = Duration::from_secs(10);

/// A latch a stop sets — signals in production, a test by hand.
#[derive(Clone, Default)]
pub struct StopLatch(Arc<AtomicBool>);

impl StopLatch {
    /// A latch nothing sets but [`StopLatch::set`].
    pub fn manual() -> Self {
        Self::default()
    }

    pub fn set(&self) {
        self.0.store(true, Ordering::SeqCst);
    }

    pub fn is_set(&self) -> bool {
        self.0.load(Ordering::SeqCst)
    }
}

/// Turn SIGTERM / SIGINT into the latch instead of an immediate kill.
pub fn install_stop_latch() -> std::io::Result<StopLatch> {
    let latch = StopLatch::manual();
    for signal in [signal_hook::consts::SIGTERM, signal_hook::consts::SIGINT] {
        signal_hook::flag::register(signal, Arc::clone(&latch.0))?;
    }
    Ok(latch)
}

/// What one tick did: an attestation was minted (pushed or not), or not.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Tick {
    Minted,
    Failed,
}

/// How [`run`] ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FinalTick {
    /// No tick ever minted an attestation: nothing to prove, none run.
    Skipped,
    /// The final tick ran within the deadline.
    Ran(Tick),
}

/// Tick every `interval` until `stop`, then the final tick (see the
/// module docs). `on_stop` runs as soon as the stop is seen; `on_deadline`
/// if the process is still ticking `final_deadline` after it — the tick in
/// progress is then abandoned.
pub fn run<T>(
    mut tick: T,
    stop: &StopLatch,
    interval: Duration,
    final_deadline: Duration,
    on_stop: Box<dyn FnOnce() + Send>,
    on_deadline: Box<dyn FnOnce() + Send>,
) -> FinalTick
where
    T: FnMut() -> Tick,
{
    let done = Arc::new(AtomicBool::new(false));
    watchdog(
        stop.clone(),
        Arc::clone(&done),
        final_deadline,
        on_stop,
        on_deadline,
    );
    let outcome = ticks(&mut tick, stop, interval);
    done.store(true, Ordering::SeqCst);
    outcome
}

fn watchdog(
    stop: StopLatch,
    done: Arc<AtomicBool>,
    final_deadline: Duration,
    on_stop: Box<dyn FnOnce() + Send>,
    on_deadline: Box<dyn FnOnce() + Send>,
) {
    thread::spawn(move || {
        while !stop.is_set() {
            if done.load(Ordering::SeqCst) {
                return;
            }
            thread::sleep(STOP_POLL);
        }
        on_stop();
        let until = Instant::now() + final_deadline;
        while Instant::now() < until {
            if done.load(Ordering::SeqCst) {
                return;
            }
            thread::sleep(STOP_POLL.min(until.saturating_duration_since(Instant::now())));
        }
        if !done.load(Ordering::SeqCst) {
            eprintln!(
                "hippius-agent-keepalive: stop: past the deadline since the signal — exiting"
            );
            on_deadline();
        }
    });
}

fn ticks<T: FnMut() -> Tick>(tick: &mut T, stop: &StopLatch, interval: Duration) -> FinalTick {
    let mut minted = false;
    while !stop.is_set() {
        if tick() == Tick::Minted {
            minted = true;
        }
        sleep_unless_stopped(interval, stop);
    }
    if !minted {
        eprintln!("hippius-agent-keepalive: stop: no attestation was ever minted — no final tick");
        return FinalTick::Skipped;
    }
    let outcome = tick();
    eprintln!("hippius-agent-keepalive: stop: final tick {outcome:?}");
    FinalTick::Ran(outcome)
}

fn sleep_unless_stopped(total: Duration, stop: &StopLatch) {
    let until = Instant::now() + total;
    while !stop.is_set() {
        let left = until.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return;
        }
        thread::sleep(POLL.min(left));
    }
}
