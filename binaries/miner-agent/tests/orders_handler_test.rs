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

use hippius_miner_agent::backup::image_tool::QemuImg;
use hippius_miner_agent::backup::qmp::VirshQmp;
use hippius_miner_agent::backup::restore::{BackupChainRestorer, ChainPiece, RestoreChain};
use hippius_miner_agent::backup::staged::{RestoreManager, RestoreOp};
use hippius_miner_agent::backup::transfer::Transfer;
use hippius_miner_agent::backup::transfer::{PartReceipt, PieceReceipt};
use hippius_miner_agent::backup::{BackupKind, BackupManager};
use hippius_miner_agent::lifecycle::{DomainId, DomainState, MockLaunchDigest, MockLibvirtDriver};
use hippius_miner_agent::orders::{
    BackupOrder, Clock, DestroyOrder, IdempotencyStore, LaunchOrder, MigrateActivateOrder,
    MigrateOrder, MigrateQuiesceOrder, MigrateSnapshotOrder, MigrationStore, OnGuestPoweroff,
    OrderBody, OrderKind, OrderState, OrderVerifier, OrdersServer, PowerPolicyOrder, RestoreOrder,
    SignedOrder, SnapshotDownloader, SnapshotUploader, StopOrder, ORDER_DOMAIN,
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
/// review-r1 target-binding check passes on the happy path.
const TEST_MINER_ID: &str = "cc-test-miner";

/// Pinned "now" — every signed order in this test crate carries the
/// same `issued_at_unix`, and the `FixedClock` below returns the same
/// value, so age-check is deterministic regardless of wall time.
/// Set well past `EARLIEST_VALID_ISSUED_AT_UNIX` (the review-r2 broken-
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

    async fn upload_parts(
        &self,
        disk_path: &std::path::Path,
        part_size: u64,
        part_urls: &[String],
    ) -> hippius_miner_agent::Result<PieceReceipt> {
        self.calls.lock().unwrap().push((
            disk_path.to_path_buf(),
            format!("parts:{part_size}:{}", part_urls.len()),
        ));
        Ok(PieceReceipt {
            parts: (1..=part_urls.len() as u32)
                .map(|n| PartReceipt {
                    part_number: n,
                    etag: format!("\"etag-{n}\""),
                    sha256_hex: "00".repeat(32),
                    size: part_size,
                })
                .collect(),
            size: part_size * part_urls.len() as u64,
            sha256_hex: "11".repeat(32),
        })
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
    spawn_server_inner(downloader, None, Arc::new(MockLibvirtDriver::new()), None).await
}

/// The shared server fixture; `backup` enables the backup routes.
async fn spawn_server_inner(
    downloader: Arc<RecordingDownloader>,
    backup: Option<Arc<BackupManager>>,
    driver: Arc<MockLibvirtDriver>,
    restore_root: Option<&std::path::Path>,
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
            driver,
            Arc::new(MockLaunchDigest::fixed([0u8; 48])),
            HostResources {
                total_cpus: 16,
                total_memory_mb: 65536,
                total_disk_gb: 0,
            },
        )
        .skip_state_disk_provision_for_tests()
        .with_state_disk_root(
            restore_root
                .map(std::path::Path::to_path_buf)
                .unwrap_or_else(|| "/var/lib/hippius-miner".into()),
        ),
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
    let state = match backup {
        Some(b) => {
            let space = b.space_ledger();
            state.with_backup(
                b,
                Arc::new(BackupChainRestorer::new(Transfer::new().unwrap(), space)),
            )
        }
        None => state,
    };
    let state = match restore_root {
        Some(_) => state.with_restore(Arc::new(RestoreManager::new(
            Arc::new(Transfer::new().unwrap()),
            Arc::default(),
        ))),
        None => state,
    };
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
        require_existing_disks: false,
        guardian_ep: None,
        net: None,
        on_guest_poweroff: None,
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
    // The replay echoes the original outcome class.
    assert_eq!((s2, b2.as_str()), (200, "launched"));
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
    // review r1 High — cross-miner replay. A signed order whose
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
async fn a_replayed_stop_still_says_it_found_nothing_to_stop() {
    // vali's §24 counts a stop as ITS stop only if the miner `stopped` a
    // guest. A re-ask of the same order_id (the Edge lost the first answer)
    // must not launder a `not-running` into a generic success.
    let (addr, sk, _lc) = spawn_server().await;
    let wire = signed_wire(
        &sk,
        "ord-stop-nothing",
        OrderKind::Stop,
        StopOrder {
            vm_id: VmId::new("tenant-absent").unwrap(),
            graceful: true,
        },
    );
    let (s1, b1) = post(addr, "/v1/miner/order/stop", &wire).await;
    assert_eq!((s1, b1.as_str()), (200, "not-running"));
    let (s2, b2) = post(addr, "/v1/miner/order/stop", &wire).await;
    assert_eq!((s2, b2.as_str()), (200, "not-running"));
}

#[tokio::test]
async fn a_stale_order_is_rejected() {
    // review r1 High — long-term replay. A signed order whose
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
    // review r2 Medium — broken-clock bypass. A miner whose
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
    // review r2 Low — defense in depth against a manual config-vs-
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
            disk_part_urls: Vec::new(),
            part_size: 0,
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
async fn destroying_a_migrated_source_clears_its_completed_leg() {
    // Seen in production (A→B→A): the reclaim destroyed the source's copy but the
    // store kept `Done`, so the later migration BACK here was refused
    // (`activate-on-source`) while the status route reported `done`.
    let (addr, sk, _lc, migration, _up, _dl) = spawn_server_with_migration().await;
    let vm = VmId::new("tenant-back").unwrap();
    let launch = signed_wire(
        &sk,
        "ord-b-launch",
        OrderKind::Launch,
        launch_payload("tenant-back"),
    );
    assert_eq!(post(addr, "/v1/miner/order/launch", &launch).await.0, 200);
    let quiesce = signed_wire(
        &sk,
        "ord-b-quiesce",
        OrderKind::MigrateQuiesce,
        MigrateQuiesceOrder {
            vm_id: vm.clone(),
            node_id: TEST_MINER_ID.to_string(),
            lease_id: "lease-back".to_string(),
            source_gen: 5,
            eol_nonce_hex: "ab".repeat(32),
        },
    );
    assert_eq!(
        post(addr, "/v1/miner/order/migrate-quiesce", &quiesce)
            .await
            .0,
        200
    );
    let snap = signed_wire(
        &sk,
        "ord-b-snapshot",
        OrderKind::MigrateSnapshot,
        MigrateSnapshotOrder {
            vm_id: vm.clone(),
            node_id: TEST_MINER_ID.to_string(),
            put_url: "https://s3.example/snapshots/tenant-back?sig=abc".to_string(),
            state_put_url: String::new(),
            disk_part_urls: Vec::new(),
            part_size: 0,
        },
    );
    assert_eq!(
        post(addr, "/v1/miner/order/migrate-snapshot", &snap)
            .await
            .0,
        200
    );
    for _ in 0..50 {
        if migration.phase(&vm).map(|p| p.as_status_str()) == Some("done") {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    assert_eq!(
        migration.phase(&vm).map(|p| p.as_status_str()),
        Some("done")
    );

    let destroy = signed_wire(
        &sk,
        "ord-b-reclaim",
        OrderKind::Destroy,
        DestroyOrder { vm_id: vm.clone() },
    );
    assert_eq!(post(addr, "/v1/miner/order/destroy", &destroy).await.0, 200);
    assert_eq!(
        migration.phase(&vm),
        None,
        "the source leg is gone with its copy"
    );
    assert!(
        migration.begin_activate(&vm).unwrap(),
        "a migration back here is accepted"
    );
}

#[tokio::test]
async fn a_multipart_migrate_snapshot_uploads_parts_and_reports_their_receipts() {
    let (addr, sk, _lc, migration, uploader, _dl) = spawn_server_with_migration().await;
    let launch = signed_wire(
        &sk,
        "ord-mp-launch",
        OrderKind::Launch,
        launch_payload("tenant-mp"),
    );
    assert_eq!(post(addr, "/v1/miner/order/launch", &launch).await.0, 200);
    let quiesce = signed_wire(
        &sk,
        "ord-mp-quiesce",
        OrderKind::MigrateQuiesce,
        MigrateQuiesceOrder {
            vm_id: VmId::new("tenant-mp").unwrap(),
            node_id: TEST_MINER_ID.to_string(),
            lease_id: "lease-mp".to_string(),
            source_gen: 5,
            eol_nonce_hex: "ab".repeat(32),
        },
    );
    assert_eq!(
        post(addr, "/v1/miner/order/migrate-quiesce", &quiesce)
            .await
            .0,
        200
    );

    // 200 presigned parts — over the 64 KiB cap the other order routes keep.
    let part_urls: Vec<String> = (1..=200)
        .map(|i| {
            format!(
                "https://s3.example/hippius-compute-images/migrations/tenant-mp/j.luks\
                 ?partNumber={i}&uploadId=abcdefghijklmnopqrstuvwxyz0123456789\
                 &X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=AKIAEXAMPLE\
                 %2F20260925%2Fdecentralized%2Fs3%2Faws4_request&X-Amz-Date=20260925T000000Z\
                 &X-Amz-Expires=3600&X-Amz-SignedHeaders=host&X-Amz-Signature={}",
                "a".repeat(64)
            )
        })
        .collect();
    let snap = signed_wire(
        &sk,
        "ord-mp-snapshot",
        OrderKind::MigrateSnapshot,
        MigrateSnapshotOrder {
            vm_id: VmId::new("tenant-mp").unwrap(),
            node_id: TEST_MINER_ID.to_string(),
            put_url: String::new(),
            state_put_url: String::new(),
            disk_part_urls: part_urls,
            part_size: 1 << 30,
        },
    );
    assert!(snap.len() > 64 * 1024);
    let (status, body) = post(addr, "/v1/miner/order/migrate-snapshot", &snap).await;
    assert_eq!((status, body.as_str()), (200, "snapshot-accepted"));

    let vm = VmId::new("tenant-mp").unwrap();
    for _ in 0..50 {
        if migration.phase(&vm).map(|p| p.as_status_str()) == Some("done") {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    assert_eq!(
        uploader.calls(),
        vec![(
            std::path::PathBuf::from("/var/lib/hippius-miner/tenant-mp.img"),
            format!("parts:{}:200", 1u64 << 30)
        )],
        "the volume went up as parts, never as a single PUT"
    );
    let (status, body) = get(addr, "/v1/miner/migration/tenant-mp/status").await;
    assert_eq!(status, 200);
    let v: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(v["status"], "done");
    assert_eq!(v["disk"]["parts"].as_array().unwrap().len(), 200);
    assert_eq!(v["disk"]["parts"][0]["etag"], "\"etag-1\"");
    assert_eq!(v["disk"]["size"], 200u64 << 30);
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
            disk_part_urls: Vec::new(),
            part_size: 0,
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
            disk_part_urls: Vec::new(),
            part_size: 0,
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
        snapshot_size: 0,
        snapshot_sha256_hex: String::new(),
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
        backup_chain: None,
        staged_restore_id: String::new(),
        guardian_ep: None,
        settle_by_unix: 0,
        net: None,
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
    let mut failed_body = None;
    for _ in 0..100 {
        let (_s, b) = get(addr, "/v1/miner/migration/tenant-act/status").await;
        if b.contains("failed") {
            failed_body = Some(b);
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    // The failure carries its class, so vali can tell a restore that never
    // reached a boot from a CVM that could not start.
    let body: serde_json::Value =
        serde_json::from_str(&failed_body.expect("dest status never reached failed")).unwrap();
    assert_eq!(
        body,
        serde_json::json!({"status": "failed", "class": "migration/dest-artifacts-missing"})
    );
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

// ── live backup order ───────────────────────────────────────────────

/// A backup-enabled server. The QMP transport points at a virsh that
/// does not exist: these tests cover the order + status plumbing, not
/// QEMU (see `backup::live_tests` for that).
async fn spawn_backup_server() -> (SocketAddr, SigningKey) {
    // vm-a is defined here but shut off: the status route answers for it
    // (no points — bitmaps die with QEMU), and a backup of it is refused.
    let driver = Arc::new(MockLibvirtDriver::new());
    driver.seed_domain(
        DomainId::new("hippius-tenant-vm-a").unwrap(),
        DomainState::ShutOff,
    );
    let backup = Arc::new(BackupManager::new(
        Arc::new(VirshQmp::new("/nonexistent/virsh".into())),
        Arc::new(QemuImg::default()),
        Arc::new(Transfer::new().unwrap()),
    ));
    let (addr, sk, ..) = spawn_server_inner(
        Arc::new(RecordingDownloader::default()),
        Some(backup),
        driver,
        None,
    )
    .await;
    (addr, sk)
}

fn backup_payload(vm: &str, run: &str, parent: Option<&str>, parts: usize) -> BackupOrder {
    BackupOrder {
        vm_id: VmId::new(vm).unwrap(),
        run_id: run.to_string(),
        parent_run_id: parent.map(str::to_string),
        kind: BackupKind::Full,
        part_size: 256 << 20,
        disk_part_urls: (1..=parts)
            .map(|i| {
                format!(
                    "https://s3.example/hippius-vm-backups/backups/{vm}/{run}.full.raw\
                     ?partNumber={i}&uploadId=abcdefghijklmnopqrstuvwxyz0123456789\
                     &X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=AKIAEXAMPLE\
                     %2F20260924%2Fdecentralized%2Fs3%2Faws4_request&X-Amz-Date=20260924T000000Z\
                     &X-Amz-Expires=3600&X-Amz-SignedHeaders=host&X-Amz-Signature={}",
                    "a".repeat(64)
                )
            })
            .collect(),
        state_put_url: format!("https://s3.example/{vm}/state?X-Amz-Signature=b"),
    }
}

#[tokio::test]
async fn backup_routes_are_503_when_backups_are_not_wired() {
    let (addr, sk, _lc) = spawn_server().await;
    let wire = signed_wire(
        &sk,
        "bk-0",
        OrderKind::Backup,
        backup_payload("vm-a", "r1", None, 1),
    );
    let (status, body) = post(addr, "/v1/miner/order/backup", &wire).await;
    assert_eq!((status, body.as_str()), (503, "backup-disabled"));
    let (status, _) = get(addr, "/v1/miner/backup/vm-a/status").await;
    assert_eq!(status, 503);
}

#[tokio::test]
async fn a_backup_order_with_many_part_urls_is_accepted_and_reports_status() {
    let (addr, sk) = spawn_backup_server().await;
    let (status, body) = get(addr, "/v1/miner/backup/vm-b/status").await;
    assert_eq!((status, body.as_str()), (404, "no-domain"));
    let (status, body) = get(addr, "/v1/miner/backup/vm-a/status").await;
    assert_eq!(status, 200);
    let v: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(
        v,
        serde_json::json!({"vm_id": "vm-a",
            "live": {"boot_counter": null, "point_run_ids": []},
            "run": null}),
        "domain here, no run since start"
    );

    // 200 presigned parts (50 GiB at 256 MiB) — far over the 64 KiB cap
    // the other order routes keep.
    let wire = signed_wire(
        &sk,
        "bk-1",
        OrderKind::Backup,
        backup_payload("vm-a", "r1", Some("r0"), 200),
    );
    assert!(wire.len() > 64 * 1024);
    let (status, body) = post(addr, "/v1/miner/order/backup", &wire).await;
    assert_eq!((status, body.as_str()), (200, "backup-started"));

    // The VM is not running on this (mock) host: the async run fails
    // with a static class, and the status says so.
    let mut last = String::new();
    for _ in 0..100 {
        let (status, body) = get(addr, "/v1/miner/backup/vm-a/status").await;
        assert_eq!(status, 200);
        last = body;
        if last.contains("\"status\":\"failed\"") {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let v: serde_json::Value = serde_json::from_str(&last).unwrap();
    assert_eq!(v["vm_id"], "vm-a");
    assert_eq!(v["live"]["point_run_ids"], serde_json::json!([]));
    let v = &v["run"];
    assert_eq!(v["run_id"], "r1");
    assert_eq!(v["parent_run_id"], "r0");
    assert_eq!(v["kind"], "full");
    assert_eq!(v["status"], "failed");
    assert_eq!(v["error"], "vm-not-running");
    assert!(!last.contains("X-Amz"), "no URL ever leaks into the status");

    // Same order again: the order-id dedup answers.
    let (status, _) = post(addr, "/v1/miner/order/backup", &wire).await;
    assert_eq!(status, 200);
}

#[tokio::test]
async fn a_backup_order_with_a_bad_parent_id_is_422() {
    let (addr, sk) = spawn_backup_server().await;
    let wire = signed_wire(
        &sk,
        "bk-2",
        OrderKind::Backup,
        backup_payload("vm-a", "r1", Some("Run/../x"), 1),
    );
    let (status, body) = post(addr, "/v1/miner/order/backup", &wire).await;
    assert_eq!((status, body.as_str()), (422, "backup-invalid"));
}

#[tokio::test]
async fn a_multipart_snapshot_body_is_room_only_its_own_route_has() {
    let (addr, _sk, _lc, _mig, _up, _dl) = spawn_server_with_migration().await;
    // 1 MiB: past every other route's 64 KiB, within migrate-snapshot's
    // 2 MiB — it reaches order decoding (400), not the body limit (413).
    let body = vec![0u8; 1024 * 1024];
    let (status, _) = post(addr, "/v1/miner/order/migrate-snapshot", &body).await;
    assert_ne!(status, 413);
    let (status, _) = post(addr, "/v1/miner/order/launch", &body).await;
    assert_eq!(status, 413);
    let huge = vec![0u8; 2 * 1024 * 1024 + 1];
    let (status, _) = post(addr, "/v1/miner/order/migrate-snapshot", &huge).await;
    assert_eq!(status, 413);
}

#[tokio::test]
async fn a_backup_body_gets_the_multipart_room_and_no_more() {
    let (addr, _sk) = spawn_backup_server().await;
    // ~2,600 part URLs (the largest flavor at 512 MiB parts) is ~1.4 MB:
    // it reaches order decoding (400), not the body limit (413).
    let body = vec![0u8; 1_500_000];
    let (status, _) = post(addr, "/v1/miner/order/backup", &body).await;
    assert_ne!(status, 413);
    let huge = vec![0u8; 2 * 1024 * 1024 + 1];
    let (status, _) = post(addr, "/v1/miner/order/backup", &huge).await;
    assert_eq!(status, 413);
}

// ── staged restore order ────────────────────────────────────────────

const RID: &str = "0123456789abcdef0123456789abcdef";

/// A presigned-GET stand-in serving `objects` at `/o/<key>`.
async fn serve_objects(objects: std::collections::HashMap<String, Vec<u8>>) -> String {
    use axum::extract::{Path, State};
    async fn get_obj(
        State(objs): State<Arc<std::collections::HashMap<String, Vec<u8>>>>,
        Path(key): Path<String>,
    ) -> (axum::http::StatusCode, Vec<u8>) {
        match objs.get(&key) {
            Some(b) => (axum::http::StatusCode::OK, b.clone()),
            None => (axum::http::StatusCode::NOT_FOUND, Vec::new()),
        }
    }
    let app = axum::Router::new()
        .route("/o/:key", axum::routing::get(get_obj))
        .with_state(Arc::new(objects));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    format!("http://{addr}/o")
}

fn chain_piece(url: String, body: &[u8]) -> ChainPiece {
    use sha2::Digest;
    ChainPiece {
        url,
        sha256_hex: hex::encode(sha2::Sha256::digest(body)),
        size: body.len() as u64,
        part_size: 0,
        part_sha256_hex: Vec::new(),
    }
}

fn restore_order(
    vm: &str,
    op: RestoreOp,
    chain: Option<RestoreChain>,
    disk_bytes: u64,
) -> RestoreOrder {
    RestoreOrder {
        vm_id: VmId::new(vm).unwrap(),
        restore_id: RID.to_string(),
        op,
        chain,
        disk_bytes,
        streams: 8,
    }
}

async fn restore_status(addr: SocketAddr, vm: &str, want_state: &str) -> serde_json::Value {
    let mut last = String::new();
    for _ in 0..200 {
        let (status, body) = get(addr, &format!("/v1/miner/restore/{vm}/status")).await;
        assert_eq!(status, 200, "{body}");
        last = body;
        if last.contains(&format!("\"state\":\"{want_state}\"")) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    serde_json::from_str(&last).unwrap()
}

#[tokio::test]
async fn restore_routes_are_503_when_restores_are_not_wired() {
    let (addr, sk, _lc) = spawn_server().await;
    let wire = signed_wire(
        &sk,
        "rs-0",
        OrderKind::Restore,
        restore_order("vm-a", RestoreOp::Abort, None, 0),
    );
    let (status, body) = post(addr, "/v1/miner/order/restore", &wire).await;
    assert_eq!((status, body.as_str()), (503, "restore-disabled"));
    let (status, _) = get(addr, "/v1/miner/restore/vm-a/status").await;
    assert_eq!(status, 503);
}

#[tokio::test]
async fn a_restore_is_staged_reported_and_aborted_over_the_order_route() {
    let root = tempfile::tempdir().unwrap();
    let full = vec![3u8; 1 << 20];
    let state = vec![4u8; 1 << 20];
    let mut objs = std::collections::HashMap::new();
    objs.insert("full".to_string(), full.clone());
    objs.insert("state".to_string(), state.clone());
    let base = serve_objects(objs).await;
    let (addr, sk, lifecycle, ..) = spawn_server_inner(
        Arc::new(RecordingDownloader::default()),
        None,
        Arc::new(MockLibvirtDriver::new()),
        Some(root.path()),
    )
    .await;
    let vm = VmId::new("vm-a").unwrap();
    // The live disks, which a stage never touches.
    let overlay = lifecycle.golden_overlay_path(&vm);
    std::fs::create_dir_all(overlay.parent().unwrap()).unwrap();
    std::fs::write(&overlay, b"live").unwrap();

    let (status, body) = get(addr, "/v1/miner/restore/vm-a/status").await;
    assert_eq!((status, body.as_str()), (404, "no-restore"));

    let mut chain = RestoreChain {
        restore_id: RID.to_string(),
        full: chain_piece(format!("{base}/full?X-Amz-Signature=s"), &full),
        incrementals: Vec::new(),
        state: chain_piece(format!("{base}/state?X-Amz-Signature=s"), &state),
    };
    // A chain for another restore id is refused up front.
    chain.restore_id = "fedcba9876543210fedcba9876543210".into();
    let wire = signed_wire(
        &sk,
        "rs-bad",
        OrderKind::Restore,
        restore_order("vm-a", RestoreOp::Stage, Some(chain.clone()), 1 << 20),
    );
    let (status, body) = post(addr, "/v1/miner/order/restore", &wire).await;
    assert_eq!((status, body.as_str()), (422, "restore-id-mismatch"));
    chain.restore_id = RID.into();

    let wire = signed_wire(
        &sk,
        "rs-1",
        OrderKind::Restore,
        restore_order("vm-a", RestoreOp::Stage, Some(chain.clone()), 1 << 20),
    );
    let (status, body) = post(addr, "/v1/miner/order/restore", &wire).await;
    assert_eq!((status, body.as_str()), (200, "restore-staging"));
    let v = restore_status(addr, "vm-a", "staged").await;
    let total = 2u64 << 20;
    assert_eq!(
        v,
        serde_json::json!({"vm_id": "vm-a", "restore_id": RID, "op": "stage",
            "state": "staged", "bytes_done": total, "bytes_total": total, "reason": null,
            "swapped": false, "pre_restore_present": false, "domain_live": false})
    );
    assert_eq!(std::fs::read(&overlay).unwrap(), b"live");

    // A new order id for the same restore: already staged.
    let wire = signed_wire(
        &sk,
        "rs-2",
        OrderKind::Restore,
        restore_order("vm-a", RestoreOp::Stage, Some(chain), 1 << 20),
    );
    let (status, body) = post(addr, "/v1/miner/order/restore", &wire).await;
    assert_eq!((status, body.as_str()), (200, "restore-staged"));

    // Not swapped: reclaim would delete the only copy.
    let wire = signed_wire(
        &sk,
        "rs-3",
        OrderKind::Restore,
        restore_order("vm-a", RestoreOp::Reclaim, None, 0),
    );
    let (status, body) = post(addr, "/v1/miner/order/restore", &wire).await;
    assert_eq!((status, body.as_str()), (409, "restore-reclaim-refused"));

    // A staged-restore activation that also names a snapshot URL.
    let mut act = activate_payload("vm-a", "https://s3.example/snap?sig=x");
    act.staged_restore_id = RID.into();
    let wire = signed_wire(&sk, "rs-act", OrderKind::MigrateActivate, act);
    let (status, body) = post(addr, "/v1/miner/order/migrate-activate", &wire).await;
    assert_eq!((status, body.as_str()), (422, "staged-restore-conflict"));

    let wire = signed_wire(
        &sk,
        "rs-4",
        OrderKind::Restore,
        restore_order("vm-a", RestoreOp::Abort, None, 0),
    );
    let (status, body) = post(addr, "/v1/miner/order/restore", &wire).await;
    assert_eq!((status, body.as_str()), (200, "restore-aborted"));
    let v = restore_status(addr, "vm-a", "aborted").await;
    assert_eq!(v["op"], "abort");
    assert_eq!(std::fs::read(&overlay).unwrap(), b"live");

    // Aborted: an activation of it is refused on the order response.
    let mut act = activate_payload("vm-a", "");
    act.staged_restore_id = RID.into();
    let wire = signed_wire(&sk, "rs-act-2", OrderKind::MigrateActivate, act);
    let (status, body) = post(addr, "/v1/miner/order/migrate-activate", &wire).await;
    assert_eq!((status, body.as_str()), (409, "restore-not-staged"));
}

#[tokio::test]
async fn a_stage_carrying_many_part_shas_fits_its_route() {
    let root = tempfile::tempdir().unwrap();
    let (addr, sk, ..) = spawn_server_inner(
        Arc::new(RecordingDownloader::default()),
        None,
        Arc::new(MockLibvirtDriver::new()),
        Some(root.path()),
    )
    .await;
    // 1280 GiB in 512 MiB parts: 2,560 part shas, far past 64 KiB.
    let size = 1280u64 << 30;
    let mut full = chain_piece("https://s3.example/full".into(), b"x");
    full.size = size;
    full.part_size = 512 << 20;
    full.part_sha256_hex = vec!["a".repeat(64); 2560];
    let chain = RestoreChain {
        restore_id: RID.to_string(),
        full,
        incrementals: Vec::new(),
        state: chain_piece("https://s3.example/state".into(), &[0u8; 1 << 20]),
    };
    let wire = signed_wire(
        &sk,
        "rs-big",
        OrderKind::Restore,
        restore_order("vm-a", RestoreOp::Stage, Some(chain), size),
    );
    assert!(wire.len() > 64 * 1024);
    let (status, body) = post(addr, "/v1/miner/order/restore", &wire).await;
    // Decoded and validated (the body fit); the tempdir cannot hold it.
    assert_eq!((status, body.as_str()), (507, "insufficient-space"));
}

// ── guest-poweroff policy ───────────────────────────────────────────

fn power_policy_vector() -> serde_json::Value {
    serde_json::from_slice(
        &std::fs::read(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../test_vectors/orders/power_policy_v1.json"
        ))
        .unwrap(),
    )
    .unwrap()
}

/// Sign raw body bytes as the Edge does (the vector's bodies are vali's).
fn sign_body(sk: &SigningKey, body: Vec<u8>) -> Vec<u8> {
    let sig = sk.sign(&body).to_bytes().to_vec();
    let mut wire = Vec::new();
    ciborium::ser::into_writer(
        &SignedOrder {
            body: ByteBuf::from(body),
            sig: ByteBuf::from(sig),
        },
        &mut wire,
    )
    .unwrap();
    wire
}

#[test]
fn the_shared_power_policy_vector_decodes_into_the_agent_types() {
    let v = power_policy_vector();
    for case in v["cases"].as_array().unwrap() {
        let body = hex::decode(case["body_hex"].as_str().unwrap()).unwrap();
        let want = case["payload"]["on_guest_poweroff"].as_str().unwrap();
        match case["kind"].as_str().unwrap() {
            "power-policy" => {
                let o: OrderBody<PowerPolicyOrder> =
                    ciborium::de::from_reader(body.as_slice()).unwrap();
                assert_eq!(o.kind, OrderKind::PowerPolicy);
                assert_eq!(o.payload.vm_id.as_str(), "tenant-1");
                assert_eq!(o.payload.on_guest_poweroff.as_str(), want);
            }
            "launch" => {
                let o: OrderBody<LaunchOrder> = ciborium::de::from_reader(body.as_slice()).unwrap();
                assert_eq!(o.kind, OrderKind::Launch);
                assert_eq!(o.payload.on_guest_poweroff.map(|p| p.as_str()), Some(want));
            }
            other => panic!("unexpected kind {other}"),
        }
    }
}

#[test]
fn a_launch_without_a_policy_encodes_exactly_as_before() {
    // `skip_serializing_if`: an agent that predates the field still
    // decodes every launch vali sends a `restart` VM.
    let mut body = Vec::new();
    ciborium::ser::into_writer(&launch_payload("tenant-x"), &mut body).unwrap();
    assert!(!body.windows(17).any(|w| w == b"on_guest_poweroff"));
}

#[tokio::test]
async fn power_policy_orders_set_the_policy_of_a_vm_on_this_host() {
    seed_snp_probe();
    let root = tempfile::tempdir().unwrap();
    let driver = Arc::new(MockLibvirtDriver::new());
    let (addr, sk, lifecycle, ..) = spawn_server_inner(
        Arc::new(RecordingDownloader::default()),
        None,
        Arc::clone(&driver),
        Some(root.path()),
    )
    .await;
    let vm = VmId::new("tenant-1").unwrap();
    let mut launch = launch_payload("tenant-1");
    launch.on_guest_poweroff = Some(OnGuestPoweroff::Stop);
    let wire = signed_wire(&sk, "pp-l", OrderKind::Launch, launch);
    assert_eq!(post(addr, "/v1/miner/order/launch", &wire).await.0, 200);
    assert_eq!(lifecycle.power_policy(&vm).unwrap(), OnGuestPoweroff::Stop);

    // vali's own body (the shared vector), signed by the Edge: back to
    // `restart`. (The vector's cases share one order_id, so only one of
    // them can be applied per server — the rest would be replays.)
    let v = power_policy_vector();
    let case = v["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["name"] == "power-policy-restart")
        .unwrap();
    let body = hex::decode(case["body_hex"].as_str().unwrap()).unwrap();
    let wire = sign_body(&sk, body);
    let applied = (200, "power-policy:restart".to_string());
    assert_eq!(
        post(addr, "/v1/miner/order/power-policy", &wire).await,
        applied
    );
    assert_eq!(
        lifecycle.power_policy(&vm).unwrap(),
        OnGuestPoweroff::Restart
    );
    // A replay is the same answer and changes nothing.
    assert_eq!(
        post(addr, "/v1/miner/order/power-policy", &wire).await,
        applied
    );

    // A VM this host does not have.
    let ghost = signed_wire(
        &sk,
        "pp-ghost",
        OrderKind::PowerPolicy,
        PowerPolicyOrder {
            vm_id: VmId::new("tenant-ghost").unwrap(),
            on_guest_poweroff: OnGuestPoweroff::Stop,
        },
    );
    assert_eq!(
        post(addr, "/v1/miner/order/power-policy", &ghost).await,
        (404, "vm-not-found".to_string())
    );
    // A power-policy body on another route is refused.
    let misrouted = signed_wire(
        &sk,
        "pp-mis",
        OrderKind::PowerPolicy,
        PowerPolicyOrder {
            vm_id: vm.clone(),
            on_guest_poweroff: OnGuestPoweroff::Stop,
        },
    );
    assert_eq!(post(addr, "/v1/miner/order/stop", &misrouted).await.0, 400);
}

#[tokio::test]
async fn domain_state_reports_a_guest_poweroff_stop() {
    seed_snp_probe();
    let root = tempfile::tempdir().unwrap();
    let driver = Arc::new(MockLibvirtDriver::new());
    let (addr, sk, lifecycle, ..) = spawn_server_inner(
        Arc::new(RecordingDownloader::default()),
        None,
        Arc::clone(&driver),
        Some(root.path()),
    )
    .await;
    let vm = VmId::new("tenant-gp").unwrap();
    let mut launch = launch_payload("tenant-gp");
    launch.on_guest_poweroff = Some(OnGuestPoweroff::Stop);
    let wire = signed_wire(&sk, "gp-l", OrderKind::Launch, launch);
    assert_eq!(post(addr, "/v1/miner/order/launch", &wire).await.0, 200);
    let path = "/v1/miner/vm/tenant-gp/domain-state";
    assert_eq!(
        get(addr, path).await,
        (200, r#"{"running":true}"#.to_string())
    );

    // Settling refuses a domain libvirt still runs.
    assert!(lifecycle.settle_guest_poweroff(&vm, 1).await.is_err());
    assert!(!lifecycle.stopped_by_guest(&vm));

    driver.force_all_to_state(DomainState::ShutOff).unwrap();
    // A plain "down" until the agent decides it was the guest's poweroff.
    assert_eq!(
        get(addr, path).await,
        (200, r#"{"running":false}"#.to_string())
    );
    lifecycle
        .settle_guest_poweroff(&vm, 1_770_000_000)
        .await
        .unwrap();
    assert_eq!(
        get(addr, path).await,
        (
            200,
            r#"{"running":false,"stop_reason":"guest-poweroff"}"#.to_string()
        )
    );
    // The start relaunches it with the policy and the mark is gone.
    let mut start = launch_payload("tenant-gp");
    start.on_guest_poweroff = Some(OnGuestPoweroff::Stop);
    start.require_existing_disks = false;
    let wire = signed_wire(&sk, "gp-s", OrderKind::Launch, start);
    assert_eq!(post(addr, "/v1/miner/order/launch", &wire).await.0, 200);
    assert_eq!(
        get(addr, path).await,
        (200, r#"{"running":true}"#.to_string())
    );
}
