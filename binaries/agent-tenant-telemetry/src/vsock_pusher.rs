//! PR-E2.3 — the tenant→host receipt pusher.
//!
//! PR-E2.2 fills a bounded [`ReceiptQueue`] with signed
//! `ServedDeliveryReceipt`s. PR-E2.3 drains it: a dedicated thread
//! dials the host miner-agent over `AF_VSOCK` and writes the buffered
//! receipts as length-prefixed canonical-CBOR frames. The host
//! miner-agent (MA-4) reads those frames and HTTP-forwards them to the
//! Edge gateway; the Edge relays them to vali's telemetry broker.
//!
//! ## The tenant CVM never talks to the Edge directly
//!
//! ```text
//! TenantTelemetryAgent (in the SEV-SNP CVM)
//!   ├── ReceiptQueue            (PR-E2.2)
//!   └── VsockPusher  ───────────(PR-E2.3, this module)
//!            │  AF_VSOCK, CID = VMADDR_CID_HOST
//!            ▼
//!       miner-agent  (host, MA-4 vsock listener)
//!            │  HTTP POST  (PR-MA-4 → PR-H8 Edge endpoint)
//!            ▼
//!       Edge gateway ──▶ vali telemetry broker
//! ```
//!
//! ## Synchronous by design (§E)
//!
//! The whole §E tenant-agent track is synchronous — no tokio. A CVM
//! guest agent's TCB is measured into the launch digest (§22); every
//! transitive crate is attack surface a ceremony reviewer must account
//! for. This pusher needs exactly one connection to one endpoint with
//! a simple back-off — `std::thread` + a sync `vsock` socket cover it
//! with a handful of transitive crates. It runs on its own thread and
//! shares the [`ReceiptQueue`] with the receipt loop through an
//! `Arc<Mutex<…>>`; the lock is held only to move receipts in/out,
//! never across socket I/O.
//!
//! ## Frame format (the MA-4 contract)
//!
//! Each receipt is one frame: a 4-byte big-endian `u32` length, then
//! that many bytes of the receipt's canonical CBOR
//! ([`SignedServedDeliveryReceipt::canonical`]). Fire-and-forget — no
//! per-frame ack at the vsock layer; vali's telemetry broker dedupes
//! on a content digest, so an at-least-once resend after a reconnect
//! is safe.
//!
//! ## Loss discipline
//!
//! A drained batch is removed from the queue before the write. On a
//! write/flush failure the unsent receipts are restored to the FRONT
//! of the queue ([`ReceiptQueue::requeue_front`]) — FIFO order intact,
//! resend deduped downstream by vali's broker. The only receipt that
//! can still be dropped is one the bounded queue evicts under the
//! §9 keep-newest policy when a sustained outage keeps it full — the
//! pusher logs that eviction. A receipt that cannot even be *encoded*
//! is a poison message (§9): dropped, never re-queued, so it cannot
//! wedge the drain.
//!
//! Nothing here logs a receipt body or any derivative — only static
//! error classes (§20).

use std::io::Write;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use hippius_types::served_receipt::SignedServedDeliveryReceipt;

use crate::error::{Result, TelemetryError};
use crate::receipt_queue::ReceiptQueue;
use crate::shutdown::ShutdownWatch;

/// `VMADDR_CID_HOST` — the well-known vsock context id of the host
/// (the L0 the SEV-SNP guest runs on), where the miner-agent's MA-4
/// listener lives. A fixed kernel ABI constant, defined here so a
/// non-Linux dev build (which does not link the `vsock` crate) can
/// still name it.
pub const VSOCK_HOST_CID: u32 = 2;

/// Receipts drained from the queue per write batch — bounds the work
/// done under one lock acquisition and the memory held off-queue.
const DRAIN_BATCH: usize = 50;

/// Reconnect back-off floor — also the retry cadence for a flapping
/// host. Low enough to recover fast, high enough never to busy-spin.
const MIN_BACKOFF: Duration = Duration::from_millis(500);

/// Reconnect back-off ceiling — a long host outage settles here.
const MAX_BACKOFF: Duration = Duration::from_secs(60);

/// Idle poll when the connection is healthy but the queue is empty.
const IDLE_POLL: Duration = Duration::from_millis(500);

/// Granularity at which a back-off / idle sleep re-checks the shutdown
/// latch — so a `SIGTERM` is never delayed by a full back-off period.
const SHUTDOWN_POLL: Duration = Duration::from_millis(100);

/// Per-connection write timeout — a stalled host miner-agent cannot
/// park the pusher thread indefinitely.
#[cfg(target_os = "linux")]
const WRITE_TIMEOUT: Duration = Duration::from_secs(10);

/// Upper bound on one encoded frame. A `ServedDeliveryReceipt` is a
/// few hundred bytes; this cap only ever trips on a corrupt receipt,
/// which is then dropped as poison rather than written. Sized to
/// vali's `VALI_TELEMETRY_MAX_ENVELOPE_BYTES` (16 KiB): a frame the
/// pusher accepts must also clear the broker's envelope cap, so an
/// over-cap receipt is dropped here rather than after a wasted hop.
const MAX_FRAME_BYTES: usize = 16 * 1024;

/// Encode one signed receipt as a length-prefixed CBOR frame: a 4-byte
/// big-endian `u32` length, then the CBOR of the host miner-agent's
/// `GuestFrame` wire shape — a map `{kind: "served-receipt", body:
/// <receipt canonical CBOR>}`. The miner-agent's MA-4 vsock reader
/// decodes this into `GuestFrame { kind: EnvelopeKind, body: ByteBuf }`
/// and routes by `kind` to the Edge served-receipt route; the inner
/// `body` stays opaque (the already-signed receipt vali verifies).
///
/// `kind` is the kebab-case rendering of `EnvelopeKind::ServedReceipt`
/// (`"served-receipt"`) and `body` a CBOR byte string, so the two sides'
/// serde shapes match exactly (`#[serde(deny_unknown_fields)]` on the
/// decoder ⇒ NO extra fields).
pub fn encode_frame(receipt: &SignedServedDeliveryReceipt) -> Result<Vec<u8>> {
    let receipt_cbor = receipt
        .canonical()
        .map_err(|_| TelemetryError::Vsock("vsock-encode"))?;
    let frame_value = ciborium::value::Value::Map(vec![
        (
            ciborium::value::Value::Text("kind".to_string()),
            ciborium::value::Value::Text("served-receipt".to_string()),
        ),
        (
            ciborium::value::Value::Text("body".to_string()),
            ciborium::value::Value::Bytes(receipt_cbor),
        ),
    ]);
    let mut body = Vec::new();
    ciborium::into_writer(&frame_value, &mut body)
        .map_err(|_| TelemetryError::Vsock("vsock-encode"))?;
    if body.len() > MAX_FRAME_BYTES {
        return Err(TelemetryError::Vsock("vsock-frame-too-large"));
    }
    // Checked above: `body.len() <= MAX_FRAME_BYTES` ⇒ the length is
    // far below `u32::MAX` and the cast cannot truncate.
    let len = body.len() as u32;
    let mut frame = Vec::with_capacity(4 + body.len());
    frame.extend_from_slice(&len.to_be_bytes());
    frame.extend_from_slice(&body);
    Ok(frame)
}

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

/// Log a pusher lifecycle event — static classes only (§20: no
/// receipt body, no key material, ever reaches a log line).
fn log_pusher(event: &'static str, detail: &'static str) {
    eprintln!("hippius-agent-tenant-telemetry: vsock-pusher: {event} ({detail})");
}

/// Drains a shared [`ReceiptQueue`] to the host miner-agent over vsock.
///
/// Generic over the shutdown latch so the production
/// [`Shutdown`](crate::shutdown::Shutdown) and a test fake share one
/// code path. The reconnect/drain/back-off loop ([`Self::run_with`])
/// is itself generic over the stream type — production wires it to a
/// vsock dial, tests to a TCP loopback — so every line except the
/// vsock syscall is exercised on any host.
pub struct VsockPusher<S> {
    /// Host vsock context id — always [`VSOCK_HOST_CID`] in production.
    /// Read only by the Linux-only [`Self::spawn`].
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    cid: u32,
    /// Host vsock port the miner-agent's MA-4 listener binds. Read
    /// only by the Linux-only [`Self::spawn`].
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    port: u32,
    /// The queue shared with the PR-E2.2 receipt loop.
    queue: Arc<Mutex<ReceiptQueue>>,
    /// The shutdown latch — the loop stops once it reads pending.
    shutdown: S,
}

impl<S: ShutdownWatch> VsockPusher<S> {
    /// Build a pusher for the host endpoint `(cid, port)`.
    pub fn new(cid: u32, port: u32, queue: Arc<Mutex<ReceiptQueue>>, shutdown: S) -> Self {
        Self {
            cid,
            port,
            queue,
            shutdown,
        }
    }

    /// Run the reconnect → drain → back-off loop until shutdown.
    ///
    /// `connect` obtains a fresh stream — the only platform-variant
    /// seam (production: a vsock dial; tests: a TCP loopback). A
    /// connect or write failure is logged by static class and retried
    /// after an exponential back-off, capped at [`MAX_BACKOFF`]; a
    /// healthy connect resets the back-off. Returns `Ok(())` once the
    /// shutdown latch is observed — the drain flushes whatever is
    /// still queued first whenever the connection allows.
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
                    match self.drain_connection(&mut stream) {
                        // `drain_connection` returns `Ok` only once the
                        // shutdown latch is set AND the queue is dry —
                        // the graceful drain already completed.
                        Ok(()) => return Ok(()),
                        // A poisoned queue lock is unrecoverable —
                        // reconnecting cannot help. End the pusher so
                        // `join` surfaces it instead of retry-spinning.
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
        // down (never mid-drain). One last best-effort dial to flush
        // what is still queued; `drain_connection` returns promptly
        // because the shutdown latch is already set.
        if let Ok(mut stream) = connect() {
            if let Err(e) = self.drain_connection(&mut stream) {
                log_pusher("final-drain-failed", e.class());
            }
        }
        Ok(())
    }

    /// Drain the queue to one live `writer` until shutdown or an I/O
    /// failure.
    ///
    /// Returns `Ok(())` only when the queue is empty *and* shutdown is
    /// pending — the caller then stops. Returns `Err` on a write/flush
    /// failure, having re-queued the unsent receipts so the caller can
    /// reconnect and resend (vali dedupes the resend).
    fn drain_connection<W: Write>(&self, writer: &mut W) -> Result<()> {
        loop {
            let batch = self.take_batch()?;
            if batch.is_empty() {
                // Nothing queued. Done iff shutting down; else idle.
                if self.shutdown.is_pending() {
                    return Ok(());
                }
                sleep_responsive(IDLE_POLL, &self.shutdown);
                continue;
            }
            // Encode up front. A receipt that cannot be encoded is a
            // poison message (§9) — dropped here, never re-queued, so
            // it can never wedge the drain. `frames`/`sendable` stay
            // index-aligned: every kept frame has its receipt.
            let mut frames: Vec<Vec<u8>> = Vec::with_capacity(batch.len());
            let mut sendable: Vec<SignedServedDeliveryReceipt> = Vec::with_capacity(batch.len());
            for receipt in batch {
                match encode_frame(&receipt) {
                    Ok(frame) => {
                        frames.push(frame);
                        sendable.push(receipt);
                    }
                    Err(e) => log_pusher("frame-dropped", e.class()),
                }
            }
            // Write every frame, then flush once. On any I/O error the
            // whole sendable batch is re-queued — vali's broker
            // dedupes, so an at-least-once resend is safe — and the
            // caller reconnects.
            if let Err(e) = write_all_frames(writer, &frames) {
                self.requeue(sendable)?;
                return Err(e);
            }
        }
    }

    /// Remove up to [`DRAIN_BATCH`] receipts from the front of the
    /// shared queue. The lock is held only for this `drain`, never
    /// across socket I/O.
    fn take_batch(&self) -> Result<Vec<SignedServedDeliveryReceipt>> {
        let mut q = self
            .queue
            .lock()
            .map_err(|_| TelemetryError::Vsock("queue-poisoned"))?;
        Ok(q.drain(DRAIN_BATCH))
    }

    /// Restore an un-sent batch to the FRONT of the shared queue after
    /// a write failure — FIFO order preserved, so the next connection
    /// resends the genuinely-oldest receipts first. The capacity bound
    /// still applies (a sustained outage that keeps the queue full can
    /// evict the oldest); a non-zero eviction is logged.
    fn requeue(&self, batch: Vec<SignedServedDeliveryReceipt>) -> Result<()> {
        let evicted = {
            let mut q = self
                .queue
                .lock()
                .map_err(|_| TelemetryError::Vsock("queue-poisoned"))?;
            q.requeue_front(batch)
        };
        if evicted > 0 {
            log_pusher("requeue-evicted", "queue-full");
        }
        Ok(())
    }
}

/// Write every frame to `writer`, then flush once.
fn write_all_frames<W: Write>(writer: &mut W, frames: &[Vec<u8>]) -> Result<()> {
    for frame in frames {
        writer
            .write_all(frame)
            .map_err(|_| TelemetryError::Vsock("vsock-write"))?;
    }
    writer
        .flush()
        .map_err(|_| TelemetryError::Vsock("vsock-flush"))?;
    Ok(())
}

/// Dial the host miner-agent's vsock listener and set a write
/// timeout. Linux-only — `AF_VSOCK` is a Linux socket family.
///
/// The dial itself is a *blocking* `connect()` syscall: the `vsock`
/// crate exposes no timed-connect API, and the workspace
/// `forbid(unsafe_code)` rules out a hand-rolled non-blocking
/// `connect`+`poll`. A wedged host could therefore park this thread
/// inside `connect()`. That is bounded where it matters — `main`'s
/// `PUSHER_JOIN_TIMEOUT` caps the graceful-shutdown wait — and, during
/// normal operation, a stalled dial only degrades telemetry (the
/// bounded queue fills), never the agent's safety.
#[cfg(target_os = "linux")]
fn vsock_connect(cid: u32, port: u32) -> Result<vsock::VsockStream> {
    let stream = vsock::VsockStream::connect_with_cid_port(cid, port)
        .map_err(|_| TelemetryError::Vsock("vsock-connect"))?;
    stream
        .set_write_timeout(Some(WRITE_TIMEOUT))
        .map_err(|_| TelemetryError::Vsock("vsock-set-timeout"))?;
    Ok(stream)
}

#[cfg(target_os = "linux")]
impl<S: ShutdownWatch + Send + 'static> VsockPusher<S> {
    /// Spawn the pusher on its own OS thread.
    ///
    /// The returned handle joins once the shutdown latch is observed —
    /// `main` joins it after the receipt loop ends, so the buffered
    /// receipts get their final drain before the process exits.
    pub fn spawn(self) -> Result<thread::JoinHandle<Result<()>>> {
        thread::Builder::new()
            .name("tenant-telemetry-vsock-pusher".to_string())
            .spawn(move || {
                let cid = self.cid;
                let port = self.port;
                self.run_with(move || vsock_connect(cid, port))
            })
            .map_err(|_| TelemetryError::Vsock("pusher-thread-spawn"))
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;

    fn receipt(tag: u8) -> SignedServedDeliveryReceipt {
        SignedServedDeliveryReceipt {
            body: vec![tag; 8],
            sig: vec![tag; 64],
        }
    }

    #[test]
    fn encode_frame_is_length_prefixed_guest_frame_cbor() {
        let r = receipt(0x11);
        let frame = encode_frame(&r).unwrap();
        // First four bytes: big-endian u32 body length.
        let declared = u32::from_be_bytes(frame[..4].try_into().unwrap()) as usize;
        assert_eq!(declared, frame.len() - 4);
        // The body after the prefix is the miner-agent's `GuestFrame`
        // wire shape: a CBOR map {kind: "served-receipt", body: <receipt
        // canonical CBOR>}.
        let body = &frame[4..];
        let value: ciborium::value::Value = ciborium::de::from_reader(body).unwrap();
        let ciborium::value::Value::Map(entries) = value else {
            panic!("frame body is not a CBOR map");
        };
        let mut kind = None;
        let mut inner = None;
        for (k, v) in &entries {
            match k.as_text() {
                Some("kind") => kind = v.as_text().map(str::to_string),
                Some("body") => inner = v.as_bytes().cloned(),
                _ => panic!("unexpected GuestFrame field"),
            }
        }
        assert_eq!(kind.as_deref(), Some("served-receipt"));
        let inner = inner.expect("body field present");
        // The inner bytes are exactly the receipt's canonical CBOR.
        assert_eq!(inner.as_slice(), r.canonical().unwrap().as_slice());
        let round: SignedServedDeliveryReceipt =
            ciborium::de::from_reader(inner.as_slice()).unwrap();
        assert_eq!(round, r);
    }

    #[test]
    fn encode_frame_rejects_an_oversize_receipt() {
        let huge = SignedServedDeliveryReceipt {
            body: vec![0u8; MAX_FRAME_BYTES + 1],
            sig: vec![0u8; 64],
        };
        let err = encode_frame(&huge).expect_err("an oversize frame must be refused");
        assert_eq!(err.class(), "vsock-frame-too-large");
    }

    #[test]
    fn next_backoff_doubles_then_caps() {
        assert_eq!(next_backoff(MIN_BACKOFF), Duration::from_secs(1));
        assert_eq!(next_backoff(Duration::from_secs(1)), Duration::from_secs(2));
        assert_eq!(next_backoff(Duration::from_secs(40)), MAX_BACKOFF);
        // Already at the ceiling — it stays there, never overflows.
        assert_eq!(next_backoff(MAX_BACKOFF), MAX_BACKOFF);
    }
}
