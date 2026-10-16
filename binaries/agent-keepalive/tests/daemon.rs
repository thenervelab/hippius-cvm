//! The keepalive daemon's stop: one final, bounded tick (issue #1562).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{mpsc, Arc};
use std::thread;
use std::time::{Duration, Instant};

use hippius_agent_keepalive::daemon::{run, FinalTick, StopLatch, Tick};

fn never() -> Box<dyn FnOnce() + Send> {
    Box::new(|| panic!("the deadline must not fire"))
}

fn nothing() -> Box<dyn FnOnce() + Send> {
    Box::new(|| {})
}

#[test]
fn a_stop_runs_one_final_tick_after_a_minted_one() {
    let stop = StopLatch::manual();
    let calls = Arc::new(AtomicUsize::new(0));
    let (latch, counter) = (stop.clone(), Arc::clone(&calls));
    let tick = move || {
        // The stop arrives during the first tick's sleep.
        if counter.fetch_add(1, Ordering::SeqCst) == 0 {
            latch.set();
        }
        Tick::Minted
    };
    let out = run(
        tick,
        &stop,
        Duration::from_secs(300),
        Duration::from_secs(10),
        nothing(),
        never(),
    );
    assert_eq!(out, FinalTick::Ran(Tick::Minted));
    assert_eq!(
        calls.load(Ordering::SeqCst),
        2,
        "the periodic tick, then the final one"
    );
}

#[test]
fn no_final_tick_when_nothing_was_ever_minted() {
    // A bare VM (no KBS path, never released): nothing to prove.
    let stop = StopLatch::manual();
    let calls = Arc::new(AtomicUsize::new(0));
    let (latch, counter) = (stop.clone(), Arc::clone(&calls));
    let tick = move || {
        if counter.fetch_add(1, Ordering::SeqCst) == 2 {
            latch.set();
        }
        Tick::Failed
    };
    let out = run(
        tick,
        &stop,
        Duration::from_millis(10),
        Duration::from_secs(10),
        nothing(),
        never(),
    );
    assert_eq!(out, FinalTick::Skipped);
    assert_eq!(calls.load(Ordering::SeqCst), 3, "no extra tick on the stop");
}

#[test]
fn a_stop_during_the_interval_is_seen_promptly() {
    let stop = StopLatch::manual();
    let latch = stop.clone();
    thread::spawn(move || {
        thread::sleep(Duration::from_millis(200));
        latch.set();
    });
    let started = Instant::now();
    let out = run(
        || Tick::Minted,
        &stop,
        Duration::from_secs(3_600),
        Duration::from_secs(10),
        nothing(),
        never(),
    );
    assert_eq!(out, FinalTick::Ran(Tick::Minted));
    assert!(
        started.elapsed() < Duration::from_secs(2),
        "not the hour-long interval"
    );
}

#[test]
fn an_unreachable_kbs_at_the_stop_cannot_hold_the_shutdown_past_the_deadline() {
    // The final tick hangs (a KBS / relay that never answers): the deadline
    // fires on time, whatever the tick does.
    let stop = StopLatch::manual();
    let (fired_tx, fired_rx) = mpsc::channel();
    let calls = Arc::new(AtomicUsize::new(0));
    let (latch, counter) = (stop.clone(), Arc::clone(&calls));
    let tick = move || {
        if counter.fetch_add(1, Ordering::SeqCst) == 0 {
            latch.set();
            return Tick::Minted;
        }
        thread::sleep(Duration::from_secs(60)); // the hung final tick
        Tick::Failed
    };
    let deadline = Duration::from_millis(300);
    let started = Instant::now();
    thread::spawn(move || {
        run(
            tick,
            &stop,
            Duration::from_secs(300),
            deadline,
            nothing(),
            Box::new(move || fired_tx.send(Instant::now()).unwrap()),
        );
    });
    let fired = fired_rx
        .recv_timeout(Duration::from_secs(5))
        .expect("the deadline fired");
    let after = fired.duration_since(started);
    assert!(after >= deadline, "not before the deadline");
    assert!(
        after < deadline + Duration::from_secs(2),
        "promptly after it: {after:?}"
    );
}

#[test]
fn a_final_tick_within_the_deadline_never_fires_it() {
    let stop = StopLatch::manual();
    let calls = Arc::new(AtomicUsize::new(0));
    let (latch, counter) = (stop.clone(), Arc::clone(&calls));
    let tick = move || {
        if counter.fetch_add(1, Ordering::SeqCst) == 0 {
            latch.set();
        }
        Tick::Minted
    };
    let out = run(
        tick,
        &stop,
        Duration::from_secs(300),
        Duration::from_millis(100),
        nothing(),
        never(),
    );
    assert_eq!(out, FinalTick::Ran(Tick::Minted));
    // Past the deadline: the watchdog saw the tick done and did not fire.
    thread::sleep(Duration::from_millis(400));
}

#[test]
fn the_deadline_counts_from_the_signal_even_mid_periodic_tick() {
    // The stop lands while a periodic tick hangs on the KBS: no final tick
    // can start, and the deadline still fires on time from the signal.
    let stop = StopLatch::manual();
    let (fired_tx, fired_rx) = mpsc::channel();
    let (stopped_tx, stopped_rx) = mpsc::channel();
    let latch = stop.clone();
    let tick = move || {
        latch.set();
        thread::sleep(Duration::from_secs(60)); // the hung periodic tick
        Tick::Minted
    };
    let deadline = Duration::from_millis(300);
    let started = Instant::now();
    thread::spawn(move || {
        run(
            tick,
            &stop,
            Duration::from_secs(300),
            deadline,
            Box::new(move || stopped_tx.send(Instant::now()).unwrap()),
            Box::new(move || fired_tx.send(Instant::now()).unwrap()),
        );
    });
    let stopped = stopped_rx
        .recv_timeout(Duration::from_secs(5))
        .expect("on_stop ran");
    assert!(
        stopped.duration_since(started) < Duration::from_secs(1),
        "promptly"
    );
    let fired = fired_rx
        .recv_timeout(Duration::from_secs(5))
        .expect("the deadline fired");
    assert!(fired.duration_since(started) < deadline + Duration::from_secs(2));
}
