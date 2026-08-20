//! End-to-end integration tests for the lifecycle-order HTTP server
//! (MA-5). Spawns a real `OrdersServer` over loopback, drives it with
//! signed orders over real HTTP/1.1, and asserts the dispatch + auth +
//! idempotency behaviour.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use ciborium::value::Value;
use coset::{CborSerializable, CoseSign1Builder, HeaderBuilder};
use ed25519_dalek::{Signer, SigningKey};
use serde::Serialize;
use serde_bytes::ByteBuf;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;

use hippius_miner_agent::lifecycle::{MockLaunchDigest, MockLibvirtDriver};
use hippius_miner_agent::orders::{
    Clock, DestroyOrder, IdempotencyStore, LaunchOrder, MigrateActivateOrder, MigrateOrder,
    MigrateQuiesceOrder, MigrateSnapshotOrder, MigrationStore, OrderBody, OrderKind, OrderState,
    OrderVerifier, OrdersServer, SignedOrder, SnapshotDownloader, SnapshotUploader, StopOrder,
    ORDER_DOMAIN,
};
use hippius_miner_agent::snp_config::{install_for_tests, SnpCpuConfig};
use hippius_miner_agent::{CvmLifecycle, HostResources, VmId};

/// Build a minimal valid CoseSign1 OrderTicket carrying `flavor:
/// "medium"`. Since #317, `CvmLifecycle::launch` PEEKS the COSE
/// payload to extract the §312 flavor BEFORE any libvirt call; an
/// arbitrary byte string like `"fake-cose-ticket-bytes"` 422s at
/// `ticket-peek/cose-decode` before the dispatch tests can assert on
/// the `launched` outcome. The peek does NOT verify the L1 Ed25519
/// signature, so the sig bytes stay bogus; only the COSE frame +
/// CBOR-map shape matter. `flavor = "medium"` pairs with the
/// `cpu_count: 2` in `launch_payload()` below
/// (Flavor::Medium.vcpus() = 2).
fn ticket_medium() -> Vec<u8> {
    let payload = Value::Map(vec![
        (Value::Text("v".into()), Value::Integer(2.into())),
        (Value::Text("flavor".into()), Value::Text("medium".into())),
    ]);
    let mut payload_buf = Vec::new();
    ciborium::ser::into_writer(&payload, &mut payload_buf).unwrap();
    let protected = HeaderBuilder::new()
        .algorithm(coset::iana::Algorithm::EdDSA)
        .build();
    CoseSign1Builder::new()
        .protected(protected)
        .payload(payload_buf)
        .create_signature(b"", |_| vec![0u8; 64])
        .build()
        .to_vec()
        .unwrap()
}

/// Issue #116 — `QemuConfig::validate` now probes the host SNP CPU
/// params via `snp_config::global()`, and CI hosts aren't AMD EPYC.
/// Pre-seed with the Genoa / Turin shape so `validate` returns Ok
/// instead of `Err(SnpProbe)` and the lifecycle layer can be
/// exercised end-to-end through the orders handler. Idempotent —
/// `OnceLock::set` short-circuits on repeat calls.
fn seed_snp_probe() {
    install_for_tests(SnpCpuConfig {
        cbitpos: 51,
        reduced_phys_bits: 1,
    });
}

/// Miner identity the test fleet pins. The signed-body
/// `target_miner_id` and the `OrderState.self_miner_id` agree, so the
/// gemini-r1 target-binding check passes on the happy path.
const TEST_MINER_ID: &str = "cc-test-miner";

/// Pinned "now" — every signed order in this test crate carries the
/// same `issued_at_unix`, and the `FixedClock` below returns the same
/// value, so age-check is deterministic regardless of wall time.
/// Set well past `EARLIEST_VALID_ISSUED_AT_UNIX` (the gemini-r2 broken-
/// clock bypass guard) so the stale-by-floor + stale-by-window
/// branches are both exercisable from this base.
const TEST_NOW_UNIX: u64 = 1_770_000_000;

/// `Clock` impl that always returns a pinned value — deterministic
/// freshness check across the integration tests. Production wires
/// `SystemClock` in `binaries/miner-agent/src/main.rs`.
struct FixedClock(u64);

impl Clock for FixedClock {
    fn now_unix(&self) -> u64 {
        self.0
    }
}

/// A no-op [`SnapshotUploader`] for the dispatch integration tests:
/// records every `(disk_path, put_url)` it was asked to upload and
/// returns success, so the migration-snapshot route can be exercised
/// end-to-end without S3 or a real multi-GB disk.
#[derive(Default)]
struct RecordingUploader {
    calls: std::sync::Mutex<Vec<(std::path::PathBuf, String)>>,
}

impl RecordingUploader {
    fn calls(&self) -> Vec<(std::path::PathBuf, String)> {
        self.calls.lock().unwrap().clone()
    }
}

#[async_trait::async_trait]
impl SnapshotUploader for RecordingUploader {
    async fn upload(
        &self,
        disk_path: &std::path::Path,
        put_url: &str,
    ) -> hippius_miner_agent::Result<()> {
        self.calls
            .lock()
            .unwrap()
            .push((disk_path.to_path_buf(), put_url.to_string()));
        Ok(())
    }
}

/// A recording [`SnapshotDownloader`] for the §25 M2 dest-activation
/// tests: records every `(get_url, dest_path)` and actually writes a
/// small non-empty ciphertext stand-in to `dest_path` (so the
/// subsequent launch attaches it, and the test can assert the disk
/// landed). `fail` makes every download error (drives the fail-closed
/// path). Optionally counts calls so the idempotent re-drive test can
/// assert the download ran only once.
#[derive(Default)]
struct RecordingDownloader {
    calls: std::sync::Mutex<Vec<(String, std::path::PathBuf)>>,
    fail: bool,
}

impl RecordingDownloader {
    fn calls(&self) -> Vec<(String, std::path::PathBuf)> {
        self.calls.lock().unwrap().clone()
    }
}

#[async_trait::async_trait]
impl SnapshotDownloader for RecordingDownloader {
    async fn download(
        &self,
        get_url: &str,
        dest_path: &std::path::Path,
    ) -> hippius_miner_agent::Result<()> {
        self.calls
            .lock()
            .unwrap()
            .push((get_url.to_string(), dest_path.to_path_buf()));
        if self.fail {
            return Err(hippius_miner_agent::error::MinerAgentError::Migration(
                "download-send",
            ));
        }
        if let Some(parent) = dest_path.parent() {
            let _ = tokio::fs::create_dir_all(parent).await;
        }
        // Write a small non-empty stand-in for the encrypted volume.
        tokio::fs::write(dest_path, b"luks-ciphertext-stand-in")
            .await
            .map_err(|_| {
                hippius_miner_agent::error::MinerAgentError::Migration("download-write")
            })?;
        Ok(())
    }
}

/// Spawn an orders server over loopback. Returns its address, the Edge
/// signing key the verifier was built from, and a handle to the
/// lifecycle for state assertions.
async fn spawn_server() -> (SocketAddr, SigningKey, Arc<CvmLifecycle>) {
    let (addr, sk, lifecycle, _mig, _up, _dl) = spawn_server_with_migration().await;
    (addr, sk, lifecycle)
}

/// As [`spawn_server`] but also returns the migration store + the
/// recording uploader so the §25 M1 quiesce/snapshot tests can assert
/// the recorded migration phase + that the encrypted volume was
/// streamed to the presigned URL. The download path uses a non-failing
/// [`RecordingDownloader`].
async fn spawn_server_with_migration() -> (
    SocketAddr,
    SigningKey,
    Arc<CvmLifecycle>,
    Arc<MigrationStore>,
    Arc<RecordingUploader>,
    Arc<RecordingDownloader>,
) {
    spawn_server_with_downloader(Arc::new(RecordingDownloader::default())).await
}

/// As [`spawn_server_with_migration`] but with a caller-supplied
/// [`RecordingDownloader`] (so the §25 M2 dest-activation tests can use a
/// failing downloader to drive the fail-closed path).
async fn spawn_server_with_downloader(
    downloader: Arc<RecordingDownloader>,
) -> (
    SocketAddr,
    SigningKey,
    Arc<CvmLifecycle>,
    Arc<MigrationStore>,
    Arc<RecordingUploader>,
    Arc<RecordingDownloader>,
) {
    let sk = SigningKey::from_bytes(&[42u8; 32]);
    let verifier =
        Arc::new(OrderVerifier::from_hex(&hex::encode(sk.verifying_key().to_bytes())).unwrap());
    let lifecycle = Arc::new(
        CvmLifecycle::new(
            Arc::new(MockLibvirtDriver::new()),
            Arc::new(MockLaunchDigest::fixed([0u8; 48])),
            HostResources {
                total_cpus: 16,
                total_memory_mb: 65536,
                total_disk_gb: 0,
            },
        )
        .skip_state_disk_provision_for_tests(),
    );
    // The integration tests use a fixed `miner_id` (`TEST_MINER_ID`)
    // and a clock pinned to `TEST_NOW_UNIX` — the same value
    // `signed_wire` stamps into every `issued_at_unix` so every order
    // falls in the fresh window without flake from `SystemTime::now`.
    let clock: Arc<dyn hippius_miner_agent::orders::Clock> = Arc::new(FixedClock(TEST_NOW_UNIX));
    // Mock ticket pusher — exercises the producer-side empty /
    // oversize guards but skips the real AF_VSOCK connect (no
    // listening guest in these dispatch tests).
    let ticket_pusher: Arc<dyn hippius_miner_agent::vsock::ticket_push::TicketPusher> =
        Arc::new(hippius_miner_agent::vsock::ticket_push::MockTicketPusher::new());
    let migration = Arc::new(MigrationStore::new());
    let uploader = Arc::new(RecordingUploader::default());
    // §25 — the production fail-closed COLD-migration ack signer (returns no
    // ack until the guest EOL shutdown-hook bake ships). The dispatch tests
    // assert the quiesce route succeeds; they do not assert ack production
    // (that is unit-tested in `orders::migration` with a mock).
    let ack_signer: Arc<dyn hippius_miner_agent::orders::GuestStoppedAckSigner> =
        Arc::new(hippius_miner_agent::orders::EolShutdownAckSigner::new());
    let state = OrderState::new(
        Arc::clone(&lifecycle),
        verifier,
        Arc::new(IdempotencyStore::new()),
        TEST_MINER_ID,
        clock,
        ticket_pusher,
        Arc::clone(&migration),
        Arc::clone(&uploader) as Arc<dyn SnapshotUploader>,
        Arc::clone(&downloader) as Arc<dyn SnapshotDownloader>,
        ack_signer,
        TaskTracker::new(),
    );
    let server = OrdersServer::bind("127.0.0.1:0".parse().unwrap())
        .await
        .unwrap();
    let addr = server.local_addr();
    tokio::spawn(server.serve(state, CancellationToken::new()));
    (addr, sk, lifecycle, migration, uploader, downloader)
}

/// A valid `LaunchOrder` for `vm` — paths under the miner root so the
/// lifecycle's `QemuConfig::validate` accepts it.
fn launch_payload(vm: &str) -> LaunchOrder {
    // The validate path now reads `snp_config::global()`; seed it
    // before any test that drives a launch. Idempotent.
    seed_snp_probe();
    LaunchOrder {
        vm_id: VmId::new(vm).unwrap(),
        ovmf_path: "/var/lib/hippius-miner/ovmf.fd".into(),
        kernel_path: "/var/lib/hippius-miner/vmlinuz".into(),
        initrd_path: "/var/lib/hippius-miner/initrd".into(),
        cmdline: "quiet panic=0".to_string(),
        luks_disk_path: format!("/var/lib/hippius-miner/{vm}.img").into(),
        luks_disk_size_gb: 10,
        data_disk_size_gb: 0,
        rootfs_data_path: "/var/lib/hippius-miner/rootfs.img".into(),
        rootfs_hash_path: "/var/lib/hippius-miner/rootfs.verity".into(),
        cpu_count: 2,
        memory_mb: 2048,
        // The orders intake exercises the FULL dispatch including
        // `CvmLifecycle::launch`'s §317 flavor peek + the post-launch
        // vsock ticket push. The peek's CoseSign1 decode runs before
        // any libvirt or vsock I/O, so the integration tests must
        // supply a CoseSign1-shaped buffer with a CBOR-map payload
        // carrying `flavor`. The push's `empty` guard runs afterwards;
        // the bytes here are placeholder (no real L1 signature). The
        // mock driver doesn't boot a guest, so the push's vsock
        // connect fails fast (returns `connect-timeout` AFTER both
        // the peek and the empty guard have already passed).
        cose_ticket: ByteBuf::from(ticket_medium()),
    }
}

/// Encode + sign an order, returning the `SignedOrder` wire bytes.
fn signed_wire<T: Serialize>(
    sk: &SigningKey,
    order_id: &str,
    kind: OrderKind,
    payload: T,
) -> Vec<u8> {
    let body_struct = OrderBody {
        domain: ORDER_DOMAIN.to_string(),
        order_id: order_id.to_string(),
        kind,
        target_miner_id: TEST_MINER_ID.to_string(),
        issued_at_unix: TEST_NOW_UNIX,
        payload,
    };
    let mut body = Vec::new();
    ciborium::ser::into_writer(&body_struct, &mut body).unwrap();
    let sig = sk.sign(&body).to_bytes().to_vec();
    let signed = SignedOrder {
        body: ByteBuf::from(body),
        sig: ByteBuf::from(sig),
    };
    let mut wire = Vec::new();
    ciborium::ser::into_writer(&signed, &mut wire).unwrap();
    wire
}

/// Minimal HTTP/1.1 `POST` — returns `(status, body)`.
async fn post(addr: SocketAddr, path: &str, body: &[u8]) -> (u16, String) {
    let fut = async {
        let mut stream = TcpStream::connect(addr).await.unwrap();
        let header = format!(
            "POST {path} HTTP/1.1\r\nHost: miner\r\n\
             Content-Type: application/cbor\r\nContent-Length: {}\r\n\
             Connection: close\r\n\r\n",
            body.len()
        );
        stream.write_all(header.as_bytes()).await.unwrap();
        stream.write_all(body).await.unwrap();
        stream.flush().await.unwrap();
        let mut resp = Vec::new();
        stream.read_to_end(&mut resp).await.unwrap();
        resp
    };
    parse_response(
        &tokio::time::timeout(Duration::from_secs(10), fut)
            .await
            .expect("HTTP POST timed out"),
    )
}

/// Minimal HTTP/1.1 `GET` — returns `(status, body)`.
async fn get(addr: SocketAddr, path: &str) -> (u16, String) {
    let fut = async {
        let mut stream = TcpStream::connect(addr).await.unwrap();
        let req = format!("GET {path} HTTP/1.1\r\nHost: miner\r\nConnection: close\r\n\r\n");
        stream.write_all(req.as_bytes()).await.unwrap();
        stream.flush().await.unwrap();
        let mut resp = Vec::new();
        stream.read_to_end(&mut resp).await.unwrap();
        resp
    };
    parse_response(
        &tokio::time::timeout(Duration::from_secs(10), fut)
            .await
            .expect("HTTP GET timed out"),
    )
}

/// Split a raw HTTP/1.1 response into `(status_code, body)`.
fn parse_response(resp: &[u8]) -> (u16, String) {
    let text = String::from_utf8_lossy(resp);
    let status = text
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|code| code.parse().ok())
        .expect("malformed HTTP status line");
    let body = text.split("\r\n\r\n").nth(1).unwrap_or("").to_string();
    (status, body)
}

#[tokio::test]
async fn healthz_returns_200() {
    let (addr, _sk, _lc) = spawn_server().await;
    let (status, _) = get(addr, "/healthz").await;
    assert_eq!(status, 200);
}

#[tokio::test]
async fn a_signed_launch_order_is_dispatched_to_the_lifecycle() {
    let (addr, sk, lifecycle) = spawn_server().await;
    let wire = signed_wire(
        &sk,
        "ord-launch-1",
        OrderKind::Launch,
        launch_payload("tenant-l1"),
    );
    let (status, body) = post(addr, "/v1/miner/order/launch", &wire).await;
    assert_eq!(status, 200, "body={body}");
    assert_eq!(body, "launched");
    // The CVM is actually tracked by the lifecycle.
    let listed = lifecycle.list().await.unwrap();
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].0.as_str(), "tenant-l1");
}

#[tokio::test]
async fn a_replayed_order_id_is_an_idempotent_no_op() {
    let (addr, sk, lifecycle) = spawn_server().await;
    let wire = signed_wire(
        &sk,
        "ord-dup",
        OrderKind::Launch,
        launch_payload("tenant-dup"),
    );
    let (s1, b1) = post(addr, "/v1/miner/order/launch", &wire).await;
    assert_eq!((s1, b1.as_str()), (200, "launched"));
    // The exact same signed wire bytes again — same order_id.
    let (s2, b2) = post(addr, "/v1/miner/order/launch", &wire).await;
    assert_eq!((s2, b2.as_str()), (200, "idempotent-replay"));
    // ...and the CVM was launched exactly once.
    assert_eq!(lifecycle.list().await.unwrap().len(), 1);
}

#[tokio::test]
async fn an_order_with_a_bad_signature_is_rejected_401() {
    let (addr, sk, _lc) = spawn_server().await;
    let mut wire = signed_wire(
        &sk,
        "ord-bad",
        OrderKind::Launch,
        launch_payload("tenant-bad"),
    );
    // Corrupt the trailing signature bytes of the SignedOrder.
    let n = wire.len();
    wire[n - 1] ^= 0xff;
    wire[n - 2] ^= 0xff;
    let (status, _) = post(addr, "/v1/miner/order/launch", &wire).await;
    assert_eq!(status, 401);
}

#[tokio::test]
async fn a_non_cbor_body_is_rejected_400() {
    let (addr, _sk, _lc) = spawn_server().await;
    let (status, _) = post(addr, "/v1/miner/order/launch", b"this is not cbor").await;
    assert_eq!(status, 400);
}

#[tokio::test]
async fn a_launch_body_posted_to_the_stop_route_is_rejected() {
    // A correctly-signed launch order replayed onto the /stop route —
    // the kind / payload-shape gate must refuse it.
    let (addr, sk, _lc) = spawn_server().await;
    let wire = signed_wire(&sk, "ord-x", OrderKind::Launch, launch_payload("tenant-x"));
    let (status, _) = post(addr, "/v1/miner/order/stop", &wire).await;
    assert!((400..500).contains(&status), "expected a 4xx, got {status}");
}

#[tokio::test]
async fn stop_then_destroy_walk_a_cvm_through_its_lifecycle() {
    let (addr, sk, lifecycle) = spawn_server().await;
    // Launch.
    let launch = signed_wire(&sk, "o-1", OrderKind::Launch, launch_payload("tenant-life"));
    assert_eq!(post(addr, "/v1/miner/order/launch", &launch).await.0, 200);
    // Stop.
    let stop = signed_wire(
        &sk,
        "o-2",
        OrderKind::Stop,
        StopOrder {
            vm_id: VmId::new("tenant-life").unwrap(),
            graceful: true,
        },
    );
    let (status, body) = post(addr, "/v1/miner/order/stop", &stop).await;
    assert_eq!((status, body.as_str()), (200, "stopped"));
    assert!(lifecycle.list().await.unwrap().is_empty());
    // Destroy of an already-gone CVM is an idempotent success (§24).
    let destroy = signed_wire(
        &sk,
        "o-3",
        OrderKind::Destroy,
        DestroyOrder {
            vm_id: VmId::new("tenant-life").unwrap(),
        },
    );
    let (status, body) = post(addr, "/v1/miner/order/destroy", &destroy).await;
    assert_eq!((status, body.as_str()), (200, "destroyed"));
}

#[tokio::test]
async fn a_migrate_order_is_authenticated_but_not_yet_wired() {
    let (addr, sk, _lc) = spawn_server().await;
    let wire = signed_wire(
        &sk,
        "ord-mig",
        OrderKind::Migrate,
        MigrateOrder {
            vm_id: VmId::new("tenant-mig").unwrap(),
        },
    );
    let (status, _) = post(addr, "/v1/miner/order/migrate", &wire).await;
    assert_eq!(status, 501, "migration mechanics are a §25 follow-up");
}

#[tokio::test]
async fn an_oversize_body_is_shed_before_decode() {
    let (addr, _sk, _lc) = spawn_server().await;
    // 128 KiB — over the 64 KiB order-body cap.
    let huge = vec![0u8; 128 * 1024];
    let (status, _) = post(addr, "/v1/miner/order/launch", &huge).await;
    assert_eq!(status, 413);
}

/// Build a `SignedOrder` whose `target_miner_id` field is operator-set.
/// Used to drive the cross-miner replay test below.
fn signed_wire_with_target<T: Serialize>(
    sk: &SigningKey,
    order_id: &str,
    kind: OrderKind,
    target_miner_id: &str,
    issued_at_unix: u64,
    payload: T,
) -> Vec<u8> {
    let body_struct = OrderBody {
        domain: ORDER_DOMAIN.to_string(),
        order_id: order_id.to_string(),
        kind,
        target_miner_id: target_miner_id.to_string(),
        issued_at_unix,
        payload,
    };
    let mut body = Vec::new();
    ciborium::ser::into_writer(&body_struct, &mut body).unwrap();
    let sig = sk.sign(&body).to_bytes().to_vec();
    let signed = SignedOrder {
        body: ByteBuf::from(body),
        sig: ByteBuf::from(sig),
    };
    let mut wire = Vec::new();
    ciborium::ser::into_writer(&signed, &mut wire).unwrap();
    wire
}

#[tokio::test]
async fn an_order_addressed_to_another_miner_is_rejected() {
    // gemini r1 High — cross-miner replay. A signed order whose
    // `target_miner_id` names a sibling miner must be rejected here
    // even though every miner pins the same Edge order-signing key
    // and the signature itself verifies.
    let (addr, sk, _lc) = spawn_server().await;
    let wire = signed_wire_with_target(
        &sk,
        "ord-wrong-miner",
        OrderKind::Stop,
        "cc-OTHER-miner",
        TEST_NOW_UNIX,
        StopOrder {
            vm_id: VmId::new("tenant-1").unwrap(),
            graceful: true,
        },
    );
    let (status, body) = post(addr, "/v1/miner/order/stop", &wire).await;
    assert_eq!(status, 400);
    assert_eq!(body, "order-wrong-miner");
}

#[tokio::test]
async fn a_stale_order_is_rejected() {
    // gemini r1 High — long-term replay. A signed order whose
    // `issued_at_unix` is past the ±MAX_ORDER_AGE_SECS window must be
    // rejected. The miner's clock is pinned by `FixedClock(TEST_NOW_UNIX)`
    // so we can directly construct a stale order.
    let (addr, sk, _lc) = spawn_server().await;
    let one_hour = 3_600u64;
    let wire = signed_wire_with_target(
        &sk,
        "ord-stale",
        OrderKind::Stop,
        TEST_MINER_ID,
        TEST_NOW_UNIX - one_hour,
        StopOrder {
            vm_id: VmId::new("tenant-1").unwrap(),
            graceful: true,
        },
    );
    let (status, body) = post(addr, "/v1/miner/order/stop", &wire).await;
    assert_eq!(status, 400);
    assert_eq!(body, "order-stale");
}

#[tokio::test]
async fn an_order_dated_before_the_floor_is_rejected() {
    // gemini r2 Medium — broken-clock bypass. A miner whose
    // `SystemClock` saturates to `0` would otherwise accept an
    // attacker-crafted order with `issued_at_unix == 0` because
    // `|0 - 0| <= MAX_ORDER_AGE_SECS`. The independent
    // `EARLIEST_VALID_ISSUED_AT_UNIX` floor catches this REGARDLESS of
    // the local clock — even if the `FixedClock` here returned 0, the
    // order would still be rejected.
    let (addr, sk, _lc) = spawn_server().await;
    let wire = signed_wire_with_target(
        &sk,
        "ord-floored",
        OrderKind::Stop,
        TEST_MINER_ID,
        0, // the bypass attempt — < EARLIEST_VALID_ISSUED_AT_UNIX
        StopOrder {
            vm_id: VmId::new("tenant-1").unwrap(),
            graceful: true,
        },
    );
    let (status, body) = post(addr, "/v1/miner/order/stop", &wire).await;
    assert_eq!(status, 400);
    assert_eq!(body, "order-stale");
}

#[tokio::test]
async fn target_miner_id_match_is_case_insensitive() {
    // gemini r2 Low — defense in depth against a manual config-vs-
    // Ansible casing typo. Ansible enforces lowercase, but a hand-
    // edited config that uppercased the id should still match. The
    // signed body's `target_miner_id` differs from `TEST_MINER_ID`
    // only in case here, and the order MUST be dispatched.
    let (addr, sk, _lc) = spawn_server().await;
    let uppercase = TEST_MINER_ID.to_ascii_uppercase();
    let wire = signed_wire_with_target(
        &sk,
        "ord-case",
        OrderKind::Stop,
        &uppercase,
        TEST_NOW_UNIX,
        StopOrder {
            vm_id: VmId::new("tenant-case").unwrap(),
            graceful: true,
        },
    );
    let (status, _body) = post(addr, "/v1/miner/order/stop", &wire).await;
    // 200 (stopped) — case-insensitive match passes the target gate.
    assert_eq!(status, 200);
}

#[tokio::test]
async fn a_future_dated_order_is_also_rejected() {
    // The freshness window is SYMMETRIC — an order issued an hour in
    // the future (e.g. attacker probing for a clock-skew window past
    // the legitimate ±5 min tolerance) must also fail.
    let (addr, sk, _lc) = spawn_server().await;
    let one_hour = 3_600u64;
    let wire = signed_wire_with_target(
        &sk,
        "ord-future",
        OrderKind::Stop,
        TEST_MINER_ID,
        TEST_NOW_UNIX + one_hour,
        StopOrder {
            vm_id: VmId::new("tenant-1").unwrap(),
            graceful: true,
        },
    );
    let (status, body) = post(addr, "/v1/miner/order/stop", &wire).await;
    assert_eq!(status, 400);
    assert_eq!(body, "order-stale");
}

// ─── §25 migration M1 — source-side quiesce + snapshot + status ──────

#[tokio::test]
async fn a_migrate_quiesce_order_cleanly_stops_the_vm_and_records_state() {
    let (addr, sk, lifecycle, migration, _up, _dl) = spawn_server_with_migration().await;
    // Launch a VM so there is a running domain to quiesce.
    let launch = signed_wire(
        &sk,
        "ord-q-launch",
        OrderKind::Launch,
        launch_payload("tenant-q1"),
    );
    let (s, b) = post(addr, "/v1/miner/order/launch", &launch).await;
    assert_eq!((s, b.as_str()), (200, "launched"));
    assert_eq!(lifecycle.list().await.unwrap().len(), 1);

    // Quiesce it.
    let wire = signed_wire(
        &sk,
        "ord-quiesce-1",
        OrderKind::MigrateQuiesce,
        MigrateQuiesceOrder {
            vm_id: VmId::new("tenant-q1").unwrap(),
            node_id: TEST_MINER_ID.to_string(),
            lease_id: "lease-q1".to_string(),
            source_gen: 5,
            eol_nonce_hex: "ab".repeat(32),
        },
    );
    let (status, body) = post(addr, "/v1/miner/order/migrate-quiesce", &wire).await;
    assert_eq!(status, 200, "body={body}");
    assert_eq!(body, "quiesced");
    // The VM was cleanly stopped — the lifecycle no longer tracks it.
    assert_eq!(lifecycle.list().await.unwrap().len(), 0);
    // Migration state recorded — status route reports a non-terminal
    // "running" (quiesce done, snapshot not yet started).
    let phase = migration.phase(&VmId::new("tenant-q1").unwrap()).unwrap();
    assert_eq!(phase.as_status_str(), "running");
}

#[tokio::test]
async fn migrate_quiesce_is_idempotent_on_an_already_stopped_vm() {
    let (addr, sk, _lc, _mig, _up, _dl) = spawn_server_with_migration().await;
    // No launch — quiesce a VM the lifecycle is not tracking. Idempotent
    // success (the desired end state, guest static, is already met).
    let wire = signed_wire(
        &sk,
        "ord-quiesce-noop",
        OrderKind::MigrateQuiesce,
        MigrateQuiesceOrder {
            vm_id: VmId::new("tenant-gone").unwrap(),
            node_id: TEST_MINER_ID.to_string(),
            lease_id: "lease-gone".to_string(),
            source_gen: 5,
            eol_nonce_hex: "ab".repeat(32),
        },
    );
    let (status, body) = post(addr, "/v1/miner/order/migrate-quiesce", &wire).await;
    assert_eq!(status, 200, "body={body}");
    assert_eq!(body, "quiesced");
    // A second, fresh-order-id quiesce still succeeds (idempotent by
    // outcome — not just an exact order_id replay).
    let wire2 = signed_wire(
        &sk,
        "ord-quiesce-noop-2",
        OrderKind::MigrateQuiesce,
        MigrateQuiesceOrder {
            vm_id: VmId::new("tenant-gone").unwrap(),
            node_id: TEST_MINER_ID.to_string(),
            lease_id: "lease-gone".to_string(),
            source_gen: 5,
            eol_nonce_hex: "ab".repeat(32),
        },
    );
    let (status2, body2) = post(addr, "/v1/miner/order/migrate-quiesce", &wire2).await;
    assert_eq!((status2, body2.as_str()), (200, "quiesced"));
}

#[tokio::test]
async fn migrate_snapshot_streams_the_volume_and_marks_done() {
    let (addr, sk, _lc, migration, uploader, _dl) = spawn_server_with_migration().await;
    // Launch + quiesce so a writable-volume path is captured.
    let launch = signed_wire(
        &sk,
        "ord-s-launch",
        OrderKind::Launch,
        launch_payload("tenant-s1"),
    );
    let (s, _) = post(addr, "/v1/miner/order/launch", &launch).await;
    assert_eq!(s, 200);
    let quiesce = signed_wire(
        &sk,
        "ord-s-quiesce",
        OrderKind::MigrateQuiesce,
        MigrateQuiesceOrder {
            vm_id: VmId::new("tenant-s1").unwrap(),
            node_id: TEST_MINER_ID.to_string(),
            lease_id: "lease-s1".to_string(),
            source_gen: 5,
            eol_nonce_hex: "ab".repeat(32),
        },
    );
    let (sq, _) = post(addr, "/v1/miner/order/migrate-quiesce", &quiesce).await;
    assert_eq!(sq, 200);

    // Snapshot to a presigned PUT URL.
    let put_url = "https://s3.example/snapshots/tenant-s1?sig=abc";
    let snap = signed_wire(
        &sk,
        "ord-snapshot-1",
        OrderKind::MigrateSnapshot,
        MigrateSnapshotOrder {
            vm_id: VmId::new("tenant-s1").unwrap(),
            node_id: TEST_MINER_ID.to_string(),
            put_url: put_url.to_string(),
            state_put_url: String::new(),
        },
    );
    let (status, body) = post(addr, "/v1/miner/order/migrate-snapshot", &snap).await;
    assert_eq!(status, 200, "body={body}");
    // The order ACKs the moment the upload is LAUNCHED — the multi-GB
    // stream runs on a background task so vali's relay/effect timeout is
    // not blocked. vali tracks completion via the status poll below.
    assert_eq!(body, "snapshot-accepted");

    // Poll the migration store until the background upload completes
    // (the mock uploader returns immediately, so this converges fast).
    let vm = VmId::new("tenant-s1").unwrap();
    let mut phase_str = "running";
    for _ in 0..50 {
        match migration.phase(&vm) {
            Some(p) if p.as_status_str() == "done" => {
                phase_str = "done";
                break;
            }
            _ => tokio::time::sleep(std::time::Duration::from_millis(20)).await,
        }
    }
    assert_eq!(phase_str, "done", "background upload never reached done");

    // The uploader streamed the CAPTURED writable volume path to the
    // exact presigned URL (and only the encrypted volume — the miner
    // never decrypts).
    let calls = uploader.calls();
    assert_eq!(calls.len(), 1);
    assert_eq!(
        calls[0].0,
        std::path::PathBuf::from("/var/lib/hippius-miner/tenant-s1.img")
    );
    assert_eq!(calls[0].1, put_url);
}

#[tokio::test]
async fn migrate_snapshot_without_a_prior_quiesce_is_refused() {
    let (addr, sk, _lc, _mig, uploader, _dl) = spawn_server_with_migration().await;
    // No quiesce — the source guest may still be writing, so the
    // snapshot must be refused (`not-quiesced`).
    let snap = signed_wire(
        &sk,
        "ord-snap-noq",
        OrderKind::MigrateSnapshot,
        MigrateSnapshotOrder {
            vm_id: VmId::new("tenant-noq").unwrap(),
            node_id: TEST_MINER_ID.to_string(),
            put_url: "https://s3.example/put".to_string(),
            state_put_url: String::new(),
        },
    );
    let (status, body) = post(addr, "/v1/miner/order/migrate-snapshot", &snap).await;
    // 500 migration-failed — the detail log carries the `not-quiesced`
    // sub-class. Crucially the uploader never ran.
    assert_eq!(status, 500, "body={body}");
    assert_eq!(body, "migration-failed");
    assert!(uploader.calls().is_empty());
}

#[tokio::test]
async fn migration_status_route_reports_running_done_and_404() {
    let (addr, sk, _lc, _mig, _up, _dl) = spawn_server_with_migration().await;
    // Unknown vm_id → 404 (vali maps that to a retryable poll error).
    let (s404, _) = get(addr, "/v1/miner/migration/tenant-unknown/status").await;
    assert_eq!(s404, 404);

    // Launch + quiesce → status reports "running".
    let launch = signed_wire(
        &sk,
        "ord-st-launch",
        OrderKind::Launch,
        launch_payload("tenant-st"),
    );
    let (s, _) = post(addr, "/v1/miner/order/launch", &launch).await;
    assert_eq!(s, 200);
    let quiesce = signed_wire(
        &sk,
        "ord-st-quiesce",
        OrderKind::MigrateQuiesce,
        MigrateQuiesceOrder {
            vm_id: VmId::new("tenant-st").unwrap(),
            node_id: TEST_MINER_ID.to_string(),
            lease_id: "lease-st".to_string(),
            source_gen: 5,
            eol_nonce_hex: "ab".repeat(32),
        },
    );
    let (sq, _) = post(addr, "/v1/miner/order/migrate-quiesce", &quiesce).await;
    assert_eq!(sq, 200);
    let (s_run, b_run) = get(addr, "/v1/miner/migration/tenant-st/status").await;
    assert_eq!(s_run, 200);
    assert_eq!(b_run, r#"{"status":"running"}"#);

    // Snapshot → status reports "done".
    let snap = signed_wire(
        &sk,
        "ord-st-snap",
        OrderKind::MigrateSnapshot,
        MigrateSnapshotOrder {
            vm_id: VmId::new("tenant-st").unwrap(),
            node_id: TEST_MINER_ID.to_string(),
            put_url: "https://s3.example/put".to_string(),
            state_put_url: String::new(),
        },
    );
    let (ss, _) = post(addr, "/v1/miner/order/migrate-snapshot", &snap).await;
    assert_eq!(ss, 200);
    // The upload runs on a background task; poll the status route until it
    // reports "done" (the mock uploader returns immediately).
    let mut b_done = String::new();
    for _ in 0..50 {
        let (s_done, body) = get(addr, "/v1/miner/migration/tenant-st/status").await;
        assert_eq!(s_done, 200);
        b_done = body;
        if b_done == r#"{"status":"done"}"# {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    assert_eq!(b_done, r#"{"status":"done"}"#);
}

#[tokio::test]
async fn migration_status_rejects_a_malformed_vm_id() {
    let (addr, _sk, _lc, _mig, _up, _dl) = spawn_server_with_migration().await;
    // An uppercase / injection-charset vm_id is rejected at the route
    // boundary (same charset gate every order's vm_id passes).
    let (status, body) = get(addr, "/v1/miner/migration/Bad_Id/status").await;
    assert_eq!(status, 400);
    assert_eq!(body, "bad-vm-id");
}

// ─── §25 M2 dest-activation (migrate-activate) integration tests ─────

/// A `migrate-activate` order pointing OVMF/kernel/initrd at paths that
/// do NOT exist (no pre-staging). `data_disk_size_gb` is implicit 0 (the
/// migrated data rides inside the downloaded LUKS volume).
fn activate_payload(vm: &str, get_url: &str) -> MigrateActivateOrder {
    seed_snp_probe();
    MigrateActivateOrder {
        vm_id: VmId::new(vm).unwrap(),
        get_url: get_url.to_string(),
        state_get_url: String::new(),
        new_gen: 6,
        // Deliberately non-existent on the test host (no M3 staging).
        ovmf_path: "/var/lib/hippius-miner/missing-ovmf.fd".into(),
        kernel_path: "/var/lib/hippius-miner/missing-vmlinuz".into(),
        initrd_path: "/var/lib/hippius-miner/missing-initrd".into(),
        cmdline: "ro hippius.vm_generation=6".to_string(),
        luks_disk_path: format!("/var/lib/hippius-miner/{vm}.img").into(),
        luks_disk_size_gb: 10,
        rootfs_data_path: "/var/lib/hippius-miner/rootfs.img".into(),
        rootfs_hash_path: "/var/lib/hippius-miner/rootfs.verity".into(),
        cpu_count: 2,
        memory_mb: 2048,
        cose_ticket: ByteBuf::from(ticket_medium()),
        // No M3 staging in these M2 dest-activation tests — the artifacts
        // are deliberately absent so the fail-closed existence check fires.
        boot_artifacts: None,
    }
}

#[tokio::test]
async fn migrate_activate_route_acks_then_fails_async_without_staged_artifacts() {
    // §25 M2 dest-activation is ACK-then-async (the restore is a multi-GB
    // download + boot that far exceeds the order-relay timeout): the route
    // is reachable through the SAME signed-order pipeline as launch/stop and
    // ACKs `activate-accepted` immediately, then runs the restore on a
    // background task. With the boot artifacts NOT pre-staged on the dest
    // (M3 wires staging), the background restore fails CLOSED
    // (`dest-artifacts-missing`) → the DEST migration status flips to
    // `failed` (which vali's `poll_dest_activation` reads). Crucially the
    // snapshot was NOT pulled for a mis-staged dest.
    let downloader = std::sync::Arc::new(RecordingDownloader::default());
    let (addr, sk, _lc, _mig, _up, dl) =
        spawn_server_with_downloader(std::sync::Arc::clone(&downloader)).await;

    let wire = signed_wire(
        &sk,
        "ord-activate-1",
        OrderKind::MigrateActivate,
        activate_payload("tenant-act", "https://s3.example/snap?sig=abc"),
    );
    let (status, body) = post(addr, "/v1/miner/order/migrate-activate", &wire).await;
    assert_eq!(status, 200, "body={body}");
    assert_eq!(body, "activate-accepted");

    // The background restore fails closed → the dest status becomes `failed`
    // (poll the SAME status surface vali reads).
    let mut saw_failed = false;
    for _ in 0..100 {
        let (_s, b) = get(addr, "/v1/miner/migration/tenant-act/status").await;
        if b.contains("failed") {
            saw_failed = true;
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    assert!(saw_failed, "dest status never reached failed");
    // A mis-staged dest must NOT trigger a multi-GB download.
    assert!(dl.calls().is_empty());
}

#[tokio::test]
async fn migrate_activate_rejects_a_kind_mismatch_on_the_wrong_route() {
    // Defense in depth: a signed `migrate-activate` body replayed onto
    // another order route is rejected on the `kind` cross-check, even
    // though the signature verifies.
    let (addr, sk, _lc, _mig, _up, _dl) = spawn_server_with_migration().await;
    let wire = signed_wire(
        &sk,
        "ord-activate-mismatch",
        OrderKind::MigrateActivate,
        activate_payload("tenant-mm", "https://s3.example/snap"),
    );
    // POST a MigrateActivate-kind body to the /stop route.
    let (status, body) = post(addr, "/v1/miner/order/stop", &wire).await;
    assert_eq!(status, 400, "body={body}");
}

// ─── §25 M2 source stopped-ack surfacing (non-destructive quiesce) ───

#[tokio::test]
async fn source_ack_route_404s_until_ingested_then_surfaces_the_hex() {
    // vali's `poll_source_ack` GETs this route; a 404 means "not produced
    // yet" (fail-closed — vali never advances to dest activation without
    // a verified ack). After the guest-signed ack is ingested, the GET
    // surfaces it as `{"signed_ack_hex": "<hex>"}` — the exact shape
    // vali's `_poll_ack` parses.
    let (addr, _sk, _lc, _mig, _up, _dl) = spawn_server_with_migration().await;

    // Before any ack: 404.
    let (s404, b404) = get(addr, "/v1/miner/migration/tenant-ack/source-ack").await;
    assert_eq!(s404, 404, "body={b404}");
    assert_eq!(b404, "no-source-ack");

    // Ingest a (stand-in) signed-ack blob — the miner stores it opaque.
    let ack_bytes: &[u8] = &[0xde, 0xad, 0xbe, 0xef, 0x01, 0x02];
    let (s_in, b_in) = post(addr, "/v1/miner/migration/tenant-ack/source-ack", ack_bytes).await;
    assert_eq!(s_in, 200, "body={b_in}");
    assert_eq!(b_in, "ack-surfaced");

    // Now the GET surfaces the exact hex vali will hand its verifier.
    let (s_ok, b_ok) = get(addr, "/v1/miner/migration/tenant-ack/source-ack").await;
    assert_eq!(s_ok, 200, "body={b_ok}");
    assert_eq!(b_ok, r#"{"signed_ack_hex":"deadbeef0102"}"#);
}

#[tokio::test]
async fn ingest_source_ack_rejects_an_empty_body_and_a_bad_vm_id() {
    let (addr, _sk, _lc, _mig, _up, _dl) = spawn_server_with_migration().await;
    // Empty ack body — rejected (a producer that sent nothing is a bug).
    let (s_empty, b_empty) = post(addr, "/v1/miner/migration/tenant-ack/source-ack", b"").await;
    assert_eq!(s_empty, 400, "body={b_empty}");
    assert_eq!(b_empty, "empty-ack");
    // Malformed vm_id — rejected at the charset gate.
    let (s_bad, b_bad) = post(addr, "/v1/miner/migration/Bad_Id/source-ack", b"x").await;
    assert_eq!(s_bad, 400, "body={b_bad}");
    assert_eq!(b_bad, "bad-vm-id");
}
