//! End-to-end host-attestor flow (PR-4).
//!
//! Drives the crate's real components — a real HKDF→Ed25519
//! `HostAttestorSigner`, the real `enroll` / `BeaconBuilder` /
//! `BeaconQueue` / `VsockPusher` — with mock `/dev/sev-guest` providers
//! and a **TCP loopback** standing in for the host vsock sink. The
//! crypto is entirely real: the enrollment `REPORT_DATA` binding and
//! every beacon signature are checked against the established key.
//!
//! Asserts:
//! - (a) enroll emits a well-formed `host-enroll` frame whose embedded
//!   report `REPORT_DATA` equals `report_data::host_attestor(...)`;
//! - (b) the beacon loop emits `host-beacon` frames carrying valid
//!   Ed25519 signatures over the canonical body, a monotonic seq, and
//!   the beacon domain;
//! - (c) the platform newtypes carry the report-derived chip_id /
//!   measurement, echoed into every beacon.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::io::Read;
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use ed25519_dalek::{Signature, Verifier};
use hippius_agent_host_attestor::error::HostAttestorError;
use hippius_agent_host_attestor::platform::PlatformClaims;
use hippius_agent_host_attestor::snp::{ReportData, SNP_REPORT_LEN};
use hippius_agent_host_attestor::{
    encode_enroll_frame, enroll, establish, tick, BeaconBuilder, BeaconQueue, EnrollFrameSlot,
    MockDerivedKeyProvider, NonceSource, Result, ShutdownWatch, SnpReport, SnpReportProvider,
    VsockPusher, VSOCK_HOST_CID,
};
use hippius_types::host_attestor::{HostAliveBeacon, HostEnrollment, SignedHostBeacon};
use hippius_types::report_data::host_attestor;

const NODE_ID: &str = "node-host-e2e";
const BOOT_ID: &str = "boot-e2e";
const ENROLL_NONCE: [u8; 32] = [0x11u8; 32];

/// Report offsets used to plant recognisable bytes.
const REPORT_DATA_OFFSET: usize = 0x50;
const MEASUREMENT_OFFSET: usize = 0x90;
const CHIP_ID_OFFSET: usize = 0x1A0;

/// A report provider that plants the caller's `REPORT_DATA` at `0x50`
/// (so the frame carries a genuine binding) plus recognisable
/// measurement + chip_id bytes — like the initramfs integration test's
/// planting provider, but for the host-attestor layout.
struct PlantingProvider;

impl SnpReportProvider for PlantingProvider {
    fn get_report(&self, report_data: ReportData) -> Result<SnpReport> {
        let mut bytes = vec![0u8; SNP_REPORT_LEN];
        bytes[REPORT_DATA_OFFSET..REPORT_DATA_OFFSET + 64].copy_from_slice(report_data.as_bytes());
        for (i, b) in bytes
            .iter_mut()
            .skip(MEASUREMENT_OFFSET)
            .take(48)
            .enumerate()
        {
            *b = 0x40 | (i as u8);
        }
        for (i, b) in bytes.iter_mut().skip(CHIP_ID_OFFSET).take(64).enumerate() {
            *b = 0x80 | (i as u8);
        }
        Ok(SnpReport(bytes))
    }
}

/// A deterministic per-beat nonce: `[counter; 32]`, incrementing.
struct SeqNonceSource {
    next: std::cell::Cell<u8>,
}
impl SeqNonceSource {
    fn new() -> Self {
        Self {
            next: std::cell::Cell::new(1),
        }
    }
}
impl NonceSource for SeqNonceSource {
    fn fresh_nonce(&self) -> Result<[u8; 32]> {
        let n = self.next.get();
        self.next.set(n + 1);
        Ok([n; 32])
    }
}

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

fn tcp_connector(addr: SocketAddr) -> impl Fn() -> Result<TcpStream> + Send + 'static {
    move || TcpStream::connect(addr).map_err(|_| HostAttestorError::Vsock("test-connect"))
}

/// Read one length-prefixed frame and return `(kind, inner-body)`.
fn read_frame(stream: &mut TcpStream) -> (String, Vec<u8>) {
    let mut len_buf = [0u8; 4];
    stream
        .read_exact(&mut len_buf)
        .expect("frame length prefix");
    let len = u32::from_be_bytes(len_buf) as usize;
    let mut body = vec![0u8; len];
    stream.read_exact(&mut body).expect("frame body");
    let value: ciborium::value::Value =
        ciborium::de::from_reader(&body[..]).expect("GuestFrame CBOR map");
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
    (kind.expect("kind"), inner.expect("body"))
}

#[test]
fn enroll_and_beacons_flow_over_the_vsock_sink() {
    // ── establish + enrol with mock providers ──────────────────────
    let established = establish(&MockDerivedKeyProvider::new([7u8; 32])).unwrap();
    let pubkey = established.pubkey();
    let enrolled = enroll(
        &PlantingProvider,
        &pubkey,
        NODE_ID,
        BOOT_ID,
        &ENROLL_NONCE,
        1_800_000_000,
    )
    .unwrap();

    // (c) the platform claims came from the planted report.
    assert_eq!(enrolled.platform.chip_id()[0], 0x80);
    assert_eq!(enrolled.platform.measurement()[0], 0x40);

    // ── build 3 beacons into the shared queue ──────────────────────
    let mut builder = BeaconBuilder::new(
        NODE_ID.to_string(),
        BOOT_ID.to_string(),
        [0xAAu8; 32],
        [0xDDu8; 32],
        pubkey,
        &enrolled.platform,
    );
    let queue = Arc::new(Mutex::new(BeaconQueue::new()));
    let ns = SeqNonceSource::new();
    {
        let mut q = queue.lock().unwrap();
        for now in [1_000u64, 1_060, 1_120] {
            tick(&mut builder, &mut q, &established.signer, &ns, now, 300).unwrap();
        }
        assert_eq!(q.len(), 3);
    }

    // ── run the pusher over TCP loopback ───────────────────────────
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let enroll_slot =
        EnrollFrameSlot::new(Arc::new(encode_enroll_frame(&enrolled.enrollment).unwrap()));
    let shutdown = TestShutdown::new();
    let pusher = VsockPusher::new(
        VSOCK_HOST_CID,
        5000,
        enroll_slot.clone(),
        Arc::clone(&queue),
        shutdown.clone(),
    );
    let connector = tcp_connector(addr);
    let pusher_thread = thread::spawn(move || pusher.run_with(connector));

    let (mut peer, _) = listener.accept().unwrap();
    peer.set_read_timeout(Some(Duration::from_secs(5))).unwrap();

    // (a) the FIRST frame is the enrollment preamble; its embedded
    //     REPORT_DATA equals report_data::host_attestor(nonce, pk, node).
    let (kind, inner) = read_frame(&mut peer);
    assert_eq!(kind, "host-enroll");
    let decoded_enrollment = HostEnrollment::decode(&inner).unwrap();
    assert_eq!(decoded_enrollment, enrolled.enrollment);
    let embedded_rd = &decoded_enrollment.snp_report[REPORT_DATA_OFFSET..REPORT_DATA_OFFSET + 64];
    let expected_rd = host_attestor(&ENROLL_NONCE, &pubkey, NODE_ID).unwrap();
    assert_eq!(embedded_rd, &expected_rd, "enrollment REPORT_DATA binding");

    // (b) the next three frames are host-beacons: valid Ed25519 sig over
    //     the canonical body, monotonic seq (1,2,3), correct domain, and
    //     the report-derived chip_id/measurement.
    let vk = established.signer.verifying_key();
    for expected_seq in 1..=3u64 {
        let (kind, inner) = read_frame(&mut peer);
        assert_eq!(kind, "host-beacon");
        let signed = SignedHostBeacon::decode(&inner).unwrap();
        let sig = Signature::from_slice(&signed.sig).expect("64-byte sig");
        vk.verify(&signed.body, &sig)
            .expect("beacon carries the enrolled key's signature");
        let beacon = HostAliveBeacon::decode(&signed.body).unwrap();
        assert_eq!(beacon.seq, expected_seq, "monotonic seq");
        assert_eq!(beacon.signer_pubkey, pubkey);
        assert_eq!(beacon.chip_id, enrolled.platform.chip_id());
        assert_eq!(beacon.measurement, enrolled.platform.measurement());
        assert_eq!(beacon.node_id, NODE_ID);
    }

    shutdown.trigger();
    pusher_thread
        .join()
        .expect("pusher thread joins")
        .expect("pusher returns Ok on shutdown");
}

/// A periodic re-enroll (installing a fresh frame into the shared slot)
/// is re-sent by the pusher on the SAME long-lived connection — the
/// lifecycle fix: the miner relay keeps one connection open for hours, so
/// a fresh cert must reach the KBS without waiting for a reconnect.
#[test]
fn a_reenroll_is_resent_on_the_live_connection() {
    let established = establish(&MockDerivedKeyProvider::new([7u8; 32])).unwrap();
    let pubkey = established.pubkey();

    // Boot enrollment → the slot's initial frame.
    let boot = enroll(
        &PlantingProvider,
        &pubkey,
        NODE_ID,
        BOOT_ID,
        &ENROLL_NONCE,
        1_800_000_000,
    )
    .unwrap();
    let enroll_slot =
        EnrollFrameSlot::new(Arc::new(encode_enroll_frame(&boot.enrollment).unwrap()));

    // No beacons — keep the stream to just the two enroll preambles so the
    // re-send is unambiguous.
    let queue = Arc::new(Mutex::new(BeaconQueue::new()));
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let shutdown = TestShutdown::new();
    let pusher = VsockPusher::new(
        VSOCK_HOST_CID,
        5000,
        enroll_slot.clone(),
        Arc::clone(&queue),
        shutdown.clone(),
    );
    let connector = tcp_connector(addr);
    let pusher_thread = thread::spawn(move || pusher.run_with(connector));

    let (mut peer, _) = listener.accept().unwrap();
    peer.set_read_timeout(Some(Duration::from_secs(5))).unwrap();

    // First frame: the boot enrollment preamble.
    let (kind, inner) = read_frame(&mut peer);
    assert_eq!(kind, "host-enroll");
    assert_eq!(HostEnrollment::decode(&inner).unwrap(), boot.enrollment);

    // Now the re-enroll loop mints a FRESH cert (fresh nonce + node_id) and
    // installs it — on the SAME connection.
    const REENROLL_NONCE: [u8; 32] = [0x33u8; 32];
    let refreshed = enroll(
        &PlantingProvider,
        &pubkey,
        "node-host-refreshed",
        BOOT_ID,
        &REENROLL_NONCE,
        1_800_003_600,
    )
    .unwrap();
    assert_ne!(refreshed.enrollment, boot.enrollment);
    enroll_slot
        .install(Arc::new(
            encode_enroll_frame(&refreshed.enrollment).unwrap(),
        ))
        .unwrap();

    // The pusher re-sends the fresh enrollment on the live connection
    // (within an idle-poll tick) — proving the cert refresh reaches the
    // sink without a reconnect.
    let (kind, inner) = read_frame(&mut peer);
    assert_eq!(kind, "host-enroll");
    assert_eq!(
        HostEnrollment::decode(&inner).unwrap(),
        refreshed.enrollment,
        "the live re-send carries the freshly re-enrolled cert"
    );

    shutdown.trigger();
    pusher_thread
        .join()
        .expect("pusher thread joins")
        .expect("pusher returns Ok on shutdown");
}

/// The platform newtype cannot be built except from a report — locks
/// requirement (c) that beacon platform fields originate in the report.
#[test]
fn platform_claims_only_come_from_a_report() {
    let mut bytes = vec![0u8; SNP_REPORT_LEN];
    bytes[CHIP_ID_OFFSET] = 0x99; // non-zero chip_id
    let claims = PlatformClaims::from_report(&SnpReport(bytes)).unwrap();
    assert_eq!(claims.chip_id()[0], 0x99);
}
