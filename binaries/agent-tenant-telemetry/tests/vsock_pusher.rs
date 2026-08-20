//! PR-E2.3 — vsock pusher integration tests.
//!
//! [`VsockPusher::run_with`] is generic over the stream type and over
//! how a stream is obtained, so the production vsock dial is the only
//! platform-specific line. These tests drive the real reconnect →
//! drain → back-off loop over a **TCP loopback** stand-in — exercising
//! framing, batching, the no-loss re-queue, connect back-off, and
//! shutdown promptness on any host (this darwin dev box and Linux CI
//! alike). The vsock syscall itself only runs inside a real CVM.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use hippius_agent_tenant_telemetry::{ReceiptQueue, ShutdownWatch, TelemetryError, VsockPusher};
use hippius_types::served_receipt::SignedServedDeliveryReceipt;

/// A test shutdown latch — an `Arc<AtomicBool>` the test flips.
#[derive(Clone)]
struct TestShutdown(Arc<AtomicBool>);

impl TestShutdown {
    fn new() -> Self {
        Self(Arc::new(AtomicBool::new(false)))
    }
    fn trigger(&self) {
        self.0.store(true, Ordering::SeqCst);
    }
}

impl ShutdownWatch for TestShutdown {
    fn is_pending(&self) -> bool {
        self.0.load(Ordering::SeqCst)
    }
}

/// A `Write` that fails every call — stands in for a broken socket.
struct FailingWriter;

impl Write for FailingWriter {
    fn write(&mut self, _buf: &[u8]) -> io::Result<usize> {
        Err(io::Error::new(
            io::ErrorKind::BrokenPipe,
            "test: write fails",
        ))
    }
    fn flush(&mut self) -> io::Result<()> {
        Err(io::Error::new(
            io::ErrorKind::BrokenPipe,
            "test: flush fails",
        ))
    }
}

/// A signed receipt whose every byte is `tag` — identifiable after it
/// round-trips through the queue, the framing, and a CBOR decode.
fn receipt(tag: u8) -> SignedServedDeliveryReceipt {
    SignedServedDeliveryReceipt {
        body: vec![tag; 24],
        sig: vec![tag; 64],
    }
}

/// A shared queue pre-loaded with `tags.len()` receipts.
fn queue_with(tags: &[u8]) -> Arc<Mutex<ReceiptQueue>> {
    let q = ReceiptQueue::new();
    let shared = Arc::new(Mutex::new(q));
    {
        let mut guard = shared.lock().unwrap();
        for &tag in tags {
            guard.push(receipt(tag));
        }
    }
    shared
}

/// Read one length-prefixed frame off `stream`, unwrap the miner-agent's
/// `GuestFrame` CBOR map ({kind: "served-receipt", body: <cbor>}), and
/// decode the inner body back to a [`SignedServedDeliveryReceipt`].
fn read_frame(stream: &mut TcpStream) -> SignedServedDeliveryReceipt {
    let mut len_buf = [0u8; 4];
    stream
        .read_exact(&mut len_buf)
        .expect("frame length prefix");
    let len = u32::from_be_bytes(len_buf) as usize;
    let mut body = vec![0u8; len];
    stream.read_exact(&mut body).expect("frame body");
    let value: ciborium::value::Value =
        ciborium::de::from_reader(&body[..]).expect("frame body is a GuestFrame CBOR map");
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
    ciborium::de::from_reader(inner.expect("body field present").as_slice())
        .expect("inner body is canonical receipt CBOR")
}

/// A connector closure that dials `addr` over TCP loopback.
fn tcp_connector(
    addr: SocketAddr,
) -> impl Fn() -> Result<TcpStream, TelemetryError> + Send + 'static {
    move || TcpStream::connect(addr).map_err(|_| TelemetryError::Vsock("test-connect"))
}

#[test]
fn pushes_buffered_receipts_as_length_prefixed_cbor_frames() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let queue = queue_with(&[1, 2, 3]);
    let shutdown = TestShutdown::new();

    let pusher = VsockPusher::new(2, 5000, Arc::clone(&queue), shutdown.clone());
    let connector = tcp_connector(addr);
    let pusher_thread = thread::spawn(move || pusher.run_with(connector));

    // The pusher dials in; read the three frames it writes.
    let (mut peer, _) = listener.accept().unwrap();
    peer.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let received: Vec<SignedServedDeliveryReceipt> =
        (0..3).map(|_| read_frame(&mut peer)).collect();
    assert_eq!(received, vec![receipt(1), receipt(2), receipt(3)]);

    shutdown.trigger();
    pusher_thread
        .join()
        .expect("pusher thread joins")
        .expect("pusher returns Ok on shutdown");
}

#[test]
fn a_write_failure_requeues_the_batch_so_no_receipt_is_lost() {
    let queue = queue_with(&[7, 8, 9]);
    let shutdown = TestShutdown::new();

    // Every connection the pusher gets is a writer that fails — the
    // drained batch must be pushed back, never dropped.
    let pusher = VsockPusher::new(2, 5000, Arc::clone(&queue), shutdown.clone());
    let pusher_thread =
        thread::spawn(move || pusher.run_with(|| Ok::<_, TelemetryError>(FailingWriter)));

    // Give the loop time for at least one drain → write-fail → requeue
    // → back-off cycle, then stop it.
    thread::sleep(Duration::from_millis(400));
    shutdown.trigger();
    pusher_thread
        .join()
        .expect("pusher thread joins")
        .expect("pusher returns Ok even when every write fails");

    // All three receipts survived the failed writes — re-queued, intact.
    let survivors = queue.lock().unwrap().drain(99);
    assert_eq!(survivors.len(), 3, "a write failure must not lose receipts");
}

#[test]
fn connect_failures_back_off_and_then_recover() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let queue = queue_with(&[42]);
    let shutdown = TestShutdown::new();

    // The connector refuses the first two dials, then succeeds — the
    // pusher must back off and retry, not give up or busy-spin.
    let attempts = Arc::new(AtomicUsize::new(0));
    let attempts_for_connector = Arc::clone(&attempts);
    let connector = move || {
        let n = attempts_for_connector.fetch_add(1, Ordering::SeqCst);
        if n < 2 {
            return Err(TelemetryError::Vsock("test-connect-refused"));
        }
        TcpStream::connect(addr).map_err(|_| TelemetryError::Vsock("test-connect"))
    };

    let pusher = VsockPusher::new(2, 5000, Arc::clone(&queue), shutdown.clone());
    let started = Instant::now();
    let pusher_thread = thread::spawn(move || pusher.run_with(connector));

    let (mut peer, _) = listener.accept().unwrap();
    peer.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    assert_eq!(read_frame(&mut peer), receipt(42));
    // Two refused dials ⇒ at least one MIN_BACKOFF (500 ms) elapsed
    // before the receipt got through.
    assert!(
        started.elapsed() >= Duration::from_millis(500),
        "the pusher must back off between failed connects"
    );
    assert!(attempts.load(Ordering::SeqCst) >= 3, "it retried the dial");

    shutdown.trigger();
    pusher_thread
        .join()
        .expect("pusher thread joins")
        .expect("pusher returns Ok on shutdown");
}

#[test]
fn shutdown_stops_an_idle_pusher_promptly() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    // Empty queue — the pusher connects, then idle-polls.
    let queue = Arc::new(Mutex::new(ReceiptQueue::new()));
    let shutdown = TestShutdown::new();

    let pusher = VsockPusher::new(2, 5000, Arc::clone(&queue), shutdown.clone());
    let connector = tcp_connector(addr);
    let pusher_thread = thread::spawn(move || pusher.run_with(connector));

    let (_peer, _) = listener.accept().unwrap();
    // Let the pusher settle into its idle poll, then shut it down.
    thread::sleep(Duration::from_millis(200));
    let stop = Instant::now();
    shutdown.trigger();
    pusher_thread
        .join()
        .expect("pusher thread joins")
        .expect("pusher returns Ok on shutdown");
    assert!(
        stop.elapsed() < Duration::from_secs(2),
        "an idle pusher must observe shutdown promptly"
    );
}

#[test]
fn idle_pusher_resumes_draining_when_a_receipt_arrives() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let queue = queue_with(&[100]);
    let shutdown = TestShutdown::new();

    let pusher = VsockPusher::new(2, 5000, Arc::clone(&queue), shutdown.clone());
    let connector = tcp_connector(addr);
    let pusher_thread = thread::spawn(move || pusher.run_with(connector));

    let (mut peer, _) = listener.accept().unwrap();
    peer.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    // First receipt drains immediately.
    assert_eq!(read_frame(&mut peer), receipt(100));

    // Pusher is now idle-polling an empty queue. A late arrival must
    // still be picked up and drained on the same live connection.
    thread::sleep(Duration::from_millis(300));
    queue.lock().unwrap().push(receipt(101));
    assert_eq!(read_frame(&mut peer), receipt(101));

    shutdown.trigger();
    pusher_thread
        .join()
        .expect("pusher thread joins")
        .expect("pusher returns Ok on shutdown");
}
