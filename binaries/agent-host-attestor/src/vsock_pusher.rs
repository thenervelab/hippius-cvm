//! The host-attestor → miner-agent vsock pusher.
//!
//! The beacon loop fills a bounded [`BeaconQueue`]; this pusher drains
//! it. A dedicated thread dials the host miner-agent over `AF_VSOCK` and
//! writes:
//!
//! 1. the current **enrollment** frame as a preamble on EVERY fresh
//!    connection (so a reconnect re-enrols — idempotent; vali's ingest,
//!    PR-8, upserts by `chip_id`), AND re-sends it on the live connection
//!    whenever the periodic re-enroll loop installs a fresher one (the
//!    [`EnrollFrameSlot`] version bumps) — the miner relay keeps ONE
//!    connection open for hours, so a fresh cert must reach the KBS
//!    without waiting for a reconnect, then
//! 2. the buffered **beacon** frames.
//!
//! The host miner-agent's vsock listener (PR-7) reads those length-
//! prefixed CBOR frames and forwards them to vali's host-attestor ingest
//! (PR-8). Both agents share one listener; it demuxes by frame `kind`.
//!
//! ## Synchronous by design
//!
//! No tokio: one connection to one endpoint with a simple back-off —
//! `std::thread` + a sync `vsock` socket. The pusher runs on its own
//! thread and shares the [`BeaconQueue`] with the beacon loop through an
//! `Arc<Mutex<…>>`; the lock is held only to move beacons in/out, never
//! across socket I/O.
//!
//! ## Loss discipline
//!
//! A drained batch is removed from the queue before the write; on a
//! write failure the unsent beacons are restored to the FRONT
//! ([`BeaconQueue::requeue_front`]) — FIFO order intact, resend deduped
//! downstream. A beacon that cannot even be *encoded* is a poison
//! message: dropped, never re-queued, so it cannot wedge the drain.
//!
//! Nothing here logs a beacon body or any derivative — only static error
//! classes (§20).

use std::io::Write;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use hippius_types::host_attestor::SignedHostBeacon;

use crate::beacon_queue::BeaconQueue;
use crate::error::{HostAttestorError, Result};
use crate::frame::encode_beacon_frame;
use crate::reenroll::EnrollFrameSlot;
use crate::shutdown::ShutdownWatch;

/// `VMADDR_CID_HOST` — the well-known vsock context id of the host (the
/// L0 the measured attestor runs on), where the miner-agent's listener
/// lives. A fixed kernel ABI constant, defined here so a non-Linux dev
/// build (which does not link the `vsock` crate) can still name it.
pub const VSOCK_HOST_CID: u32 = 2;

/// Beacons drained from the queue per write batch.
const DRAIN_BATCH: usize = 50;

/// Reconnect back-off floor — also the retry cadence for a flapping host.
const MIN_BACKOFF: Duration = Duration::from_millis(500);

/// Reconnect back-off ceiling — a long host outage settles here.
const MAX_BACKOFF: Duration = Duration::from_secs(60);

/// Idle poll when the connection is healthy but the queue is empty.
const IDLE_POLL: Duration = Duration::from_millis(500);

/// Granularity at which a back-off / idle sleep re-checks the shutdown
/// latch — so a `SIGTERM` is never delayed by a full back-off period.
const SHUTDOWN_POLL: Duration = Duration::from_millis(100);

/// Per-connection write timeout — a stalled host cannot park the pusher
/// thread indefinitely.
#[cfg(target_os = "linux")]
const WRITE_TIMEOUT: Duration = Duration::from_secs(10);

/// Double the back-off, capped at [`MAX_BACKOFF`].
fn next_backoff(current: Duration) -> Duration {
    (current * 2).min(MAX_BACKOFF)
}

/// Sleep for `total`, re-checking `shutdown` every [`SHUTDOWN_POLL`].
/// Returns `true` if the shutdown latch fired during the sleep.
fn sleep_responsive(total: Duration, shutdown: &dyn ShutdownWatch) -> bool {
    let mut slept = Duration::ZERO;
    while slept < total {
        if shutdown.is_pending() {
            return true;
        }
        let chunk = SHUTDOWN_POLL.min(total - slept);
        thread::sleep(chunk);
        slept += chunk;
    }
    shutdown.is_pending()
}

/// Log a pusher lifecycle event — static classes only (§20).
fn log_pusher(event: &'static str, detail: &'static str) {
    eprintln!("hippius-agent-host-attestor: vsock-pusher: {event} ({detail})");
}

/// Drains a shared [`BeaconQueue`] to the host miner-agent over vsock,
/// re-sending the enrollment preamble on every fresh connection.
///
/// Generic over the shutdown latch (the production
/// [`Shutdown`](crate::shutdown::Shutdown) and a test fake share one
/// path) and, in [`Self::run_with`], over the stream type (production
/// wires a vsock dial, tests a TCP loopback), so every line except the
/// vsock syscall is exercised on any host.
pub struct VsockPusher<S> {
    /// Host vsock context id — always [`VSOCK_HOST_CID`] in production.
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    cid: u32,
    /// Host vsock port the miner-agent's listener binds.
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    port: u32,
    /// The shared, swappable enrollment frame — written as a preamble on
    /// every fresh connection, and re-sent on the live connection when the
    /// re-enroll loop installs a fresher one (version bump).
    enroll: EnrollFrameSlot,
    /// The queue shared with the beacon loop.
    queue: Arc<Mutex<BeaconQueue>>,
    /// The shutdown latch — the loop stops once it reads pending.
    shutdown: S,
}

impl<S: ShutdownWatch> VsockPusher<S> {
    /// Build a pusher for the host endpoint `(cid, port)` with the shared
    /// `enroll` frame slot.
    pub fn new(
        cid: u32,
        port: u32,
        enroll: EnrollFrameSlot,
        queue: Arc<Mutex<BeaconQueue>>,
        shutdown: S,
    ) -> Self {
        Self {
            cid,
            port,
            enroll,
            queue,
            shutdown,
        }
    }

    /// Run the reconnect → enrol → drain → back-off loop until shutdown.
    ///
    /// `connect` obtains a fresh stream — the only platform-variant seam.
    /// On each fresh connection the enrollment preamble is written first,
    /// then the beacon queue is drained. A connect/write failure is
    /// logged by static class and retried after an exponential back-off,
    /// capped at [`MAX_BACKOFF`]; a healthy connect resets it. Returns
    /// `Ok(())` once the shutdown latch is observed.
    pub fn run_with<W, C>(&self, connect: C) -> Result<()>
    where
        W: Write,
        C: Fn() -> Result<W>,
    {
        let mut backoff = MIN_BACKOFF;
        while !self.shutdown.is_pending() {
            match connect() {
                Ok(mut stream) => {
                    backoff = MIN_BACKOFF;
                    match self.serve_connection(&mut stream) {
                        // `serve_connection` returns `Ok` only once the
                        // shutdown latch is set AND the queue is dry.
                        Ok(()) => return Ok(()),
                        // A poisoned queue lock is unrecoverable.
                        Err(e) if e.class() == "queue-poisoned" => return Err(e),
                        Err(e) => log_pusher("connection-lost", e.class()),
                    }
                }
                Err(e) => log_pusher("connect-failed", e.class()),
            }
            if sleep_responsive(backoff, &self.shutdown) {
                break;
            }
            backoff = next_backoff(backoff);
        }
        // Reached only when shutdown latched while the connection was
        // down. One last best-effort dial to flush what is still queued.
        if let Ok(mut stream) = connect() {
            if let Err(e) = self.serve_connection(&mut stream) {
                log_pusher("final-drain-failed", e.class());
            }
        }
        Ok(())
    }

    /// Write the enrollment preamble, then drain beacons, on one live
    /// `writer` until shutdown or an I/O failure.
    fn serve_connection<W: Write>(&self, writer: &mut W) -> Result<()> {
        // Enrollment preamble — the CURRENT frame from the shared slot.
        // Remember its version so a later re-enroll (version bump) triggers
        // a re-send on THIS live connection (see `drain_beacons`).
        let (frame, mut flushed_version) = self.enroll.snapshot()?;
        write_enroll(writer, &frame)?;
        self.drain_beacons(writer, &mut flushed_version)
    }

    /// Drain the beacon queue to `writer`, re-sending the enrollment
    /// preamble whenever the re-enroll loop installs a fresher one.
    ///
    /// Returns `Ok(())` only when the queue is empty *and* shutdown is
    /// pending. Returns `Err` on a write/flush failure, having re-queued
    /// the unsent beacons so the caller can reconnect and resend.
    ///
    /// `flushed_version` is the enrollment slot version last written on
    /// this connection; when the slot advances (the periodic re-enroll
    /// minted a fresh cert) the new frame is flushed before the next
    /// beacon batch — so a fresh cert reaches the KBS promptly even on a
    /// long-lived connection, without waiting for a reconnect.
    fn drain_beacons<W: Write>(&self, writer: &mut W, flushed_version: &mut u64) -> Result<()> {
        loop {
            // Re-send a freshly re-enrolled preamble on the live connection.
            let (frame, version) = self.enroll.snapshot()?;
            if version != *flushed_version {
                write_enroll(writer, &frame)?;
                *flushed_version = version;
                log_pusher("re-enroll-resent", "fresh-cert");
            }
            let batch = self.take_batch()?;
            if batch.is_empty() {
                if self.shutdown.is_pending() {
                    return Ok(());
                }
                sleep_responsive(IDLE_POLL, &self.shutdown);
                continue;
            }
            // Encode up front. A beacon that cannot be encoded is poison
            // — dropped here, never re-queued. `frames`/`sendable` stay
            // index-aligned.
            let mut frames: Vec<Vec<u8>> = Vec::with_capacity(batch.len());
            let mut sendable: Vec<SignedHostBeacon> = Vec::with_capacity(batch.len());
            for beacon in batch {
                match encode_beacon_frame(&beacon) {
                    Ok(frame) => {
                        frames.push(frame);
                        sendable.push(beacon);
                    }
                    Err(e) => log_pusher("frame-dropped", e.class()),
                }
            }
            if let Err(e) = write_all_frames(writer, &frames) {
                self.requeue(sendable)?;
                return Err(e);
            }
        }
    }

    /// Remove up to [`DRAIN_BATCH`] beacons from the front of the queue.
    fn take_batch(&self) -> Result<Vec<SignedHostBeacon>> {
        let mut q = self
            .queue
            .lock()
            .map_err(|_| HostAttestorError::Vsock("queue-poisoned"))?;
        Ok(q.drain(DRAIN_BATCH))
    }

    /// Restore an un-sent batch to the FRONT of the queue after a write
    /// failure — FIFO preserved. Returns nothing; a non-zero eviction is
    /// logged.
    fn requeue(&self, batch: Vec<SignedHostBeacon>) -> Result<()> {
        let evicted = {
            let mut q = self
                .queue
                .lock()
                .map_err(|_| HostAttestorError::Vsock("queue-poisoned"))?;
            q.requeue_front(batch)
        };
        if evicted > 0 {
            log_pusher("requeue-evicted", "queue-full");
        }
        Ok(())
    }
}

/// Write the enrollment preamble frame to `writer`, then flush.
fn write_enroll<W: Write>(writer: &mut W, frame: &[u8]) -> Result<()> {
    writer
        .write_all(frame)
        .map_err(|_| HostAttestorError::Vsock("enroll-write"))?;
    writer
        .flush()
        .map_err(|_| HostAttestorError::Vsock("enroll-flush"))?;
    Ok(())
}

/// Write every frame to `writer`, then flush once.
fn write_all_frames<W: Write>(writer: &mut W, frames: &[Vec<u8>]) -> Result<()> {
    for frame in frames {
        writer
            .write_all(frame)
            .map_err(|_| HostAttestorError::Vsock("vsock-write"))?;
    }
    writer
        .flush()
        .map_err(|_| HostAttestorError::Vsock("vsock-flush"))?;
    Ok(())
}

/// Dial the host miner-agent's vsock listener and set a write timeout.
/// Linux-only — `AF_VSOCK` is a Linux socket family.
///
/// The dial is a *blocking* `connect()` syscall the `vsock` crate offers
/// no timed variant for (and `forbid(unsafe_code)` rules out a
/// hand-rolled non-blocking connect). A wedged host could park this
/// thread; that is bounded by `main`'s join timeout, and during normal
/// operation only degrades liveness reporting (the bounded queue fills),
/// never safety.
#[cfg(target_os = "linux")]
fn vsock_connect(cid: u32, port: u32) -> Result<vsock::VsockStream> {
    let stream = vsock::VsockStream::connect_with_cid_port(cid, port)
        .map_err(|_| HostAttestorError::Vsock("vsock-connect"))?;
    stream
        .set_write_timeout(Some(WRITE_TIMEOUT))
        .map_err(|_| HostAttestorError::Vsock("vsock-set-timeout"))?;
    Ok(stream)
}

#[cfg(target_os = "linux")]
impl<S: ShutdownWatch + Send + 'static> VsockPusher<S> {
    /// Spawn the pusher on its own OS thread.
    ///
    /// The returned handle joins once the shutdown latch is observed —
    /// `main` joins it after the beacon loop ends, so the buffered
    /// beacons get their final drain before the process exits.
    pub fn spawn(self) -> Result<thread::JoinHandle<Result<()>>> {
        thread::Builder::new()
            .name("host-attestor-vsock-pusher".to_string())
            .spawn(move || {
                let cid = self.cid;
                let port = self.port;
                self.run_with(move || vsock_connect(cid, port))
            })
            .map_err(|_| HostAttestorError::Vsock("pusher-thread-spawn"))
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;

    #[test]
    fn next_backoff_doubles_then_caps() {
        assert_eq!(next_backoff(MIN_BACKOFF), Duration::from_secs(1));
        assert_eq!(next_backoff(Duration::from_secs(1)), Duration::from_secs(2));
        assert_eq!(next_backoff(Duration::from_secs(40)), MAX_BACKOFF);
        assert_eq!(next_backoff(MAX_BACKOFF), MAX_BACKOFF);
    }
}
