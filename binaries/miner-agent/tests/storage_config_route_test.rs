//! `storage-config` order intake over real HTTP: a signed document is
//! verified by the shared order pipeline, validated, applied and acked;
//! a dry run persists nothing; a refusal is a JSON body naming the pool;
//! replays are refused also after a restart over the same state root.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use ed25519_dalek::{Signer, SigningKey};
use serde::Serialize;
use serde_bytes::ByteBuf;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;

use hippius_miner_agent::lifecycle::{MockLaunchDigest, MockLibvirtDriver};
use hippius_miner_agent::orders::types::{StorageDesiredState, StoragePoolClass, StoragePoolSpec};
use hippius_miner_agent::orders::{
    Clock, EolShutdownAckSigner, IdempotencyStore, MigrationStore, OrderBody, OrderKind,
    OrderState, OrderVerifier, OrdersServer, ReqwestSnapshotDownloader, ReqwestSnapshotUploader,
    SignedOrder, StorageConfigOrder, ORDER_DOMAIN,
};
use hippius_miner_agent::storage::remote::{
    boot_set, content_sha256_hex, Host, LocalStorage, StorageConfigService,
};
use hippius_miner_agent::storage::state::{EffectiveStorage, StorageState};
use hippius_miner_agent::{CvmLifecycle, HostResources};

const TEST_MINER_ID: &str = "cc-test-miner";
const TEST_NOW_UNIX: u64 = 1_770_000_000;
const BUDGET_GB: u64 = 500;

struct FixedClock(u64);

impl Clock for FixedClock {
    fn now_unix(&self) -> u64 {
        self.0
    }
}

fn edge_key() -> SigningKey {
    SigningKey::from_bytes(&[42u8; 32])
}

fn local(root: &Path) -> LocalStorage {
    LocalStorage {
        data_root: root.to_path_buf(),
        state_root: root.to_path_buf(),
        host_budget_gb: BUDGET_GB,
        pools: Vec::new(),
        dedicated: Vec::new(),
    }
}

/// An orders server over `root` (`None` ⇒ route not wired). Returns the
/// shared storage set too.
async fn spawn(root: Option<&Path>) -> (SocketAddr, Option<Arc<StorageState>>) {
    let sk = edge_key();
    let verifier =
        Arc::new(OrderVerifier::from_hex(&hex::encode(sk.verifying_key().to_bytes())).unwrap());
    let lifecycle = Arc::new(CvmLifecycle::new(
        Arc::new(MockLibvirtDriver::new()),
        Arc::new(MockLaunchDigest::fixed([0u8; 48])),
        HostResources {
            total_cpus: 16,
            total_memory_mb: 65536,
            total_disk_gb: BUDGET_GB,
        },
    ));
    let state = OrderState::new(
        lifecycle,
        verifier,
        Arc::new(IdempotencyStore::new()),
        TEST_MINER_ID,
        Arc::new(FixedClock(TEST_NOW_UNIX)),
        Arc::new(hippius_miner_agent::vsock::ticket_push::MockTicketPusher::new()),
        Arc::new(MigrationStore::new()),
        Arc::new(ReqwestSnapshotUploader::new().unwrap()),
        Arc::new(ReqwestSnapshotDownloader::new().unwrap()),
        Arc::new(EolShutdownAckSigner::new()),
        TaskTracker::new(),
    );
    let (state, storage) = match root {
        Some(root) => {
            let local = local(root);
            let (pools, dedicated, revision) = boot_set(&local);
            let pools = Arc::new(pools);
            let bindings = hippius_miner_agent::storage::registry::enforce(root, &pools).unwrap();
            let storage = Arc::new(StorageState::new(EffectiveStorage {
                pools,
                dedicated,
                revision,
                bindings,
            }));
            let service = StorageConfigService::new(
                local,
                Arc::clone(&storage),
                Host::system(),
                Arc::default(),
            );
            (state.with_storage_config(Arc::new(service)), Some(storage))
        }
        None => (state, None),
    };
    let server = OrdersServer::bind("127.0.0.1:0".parse().unwrap())
        .await
        .unwrap();
    let addr = server.local_addr();
    tokio::spawn(server.serve(state, CancellationToken::new()));
    (addr, storage)
}

fn doc(root: &Path, revision: u64, dry_run: bool, budget_gb: u32) -> StorageConfigOrder {
    StorageConfigOrder {
        revision,
        not_after_unix: TEST_NOW_UNIX + 86_400,
        dry_run,
        pools: vec![StoragePoolSpec {
            id: "default".into(),
            path: root.to_str().unwrap().into(),
            class: StoragePoolClass::Nvme,
            budget_gb,
            os_disks: true,
            state: StorageDesiredState::Active,
        }],
        dedicated_disks: Vec::new(),
    }
}

fn signed<T: Serialize>(order_id: &str, kind: OrderKind, payload: T) -> Vec<u8> {
    let body = OrderBody {
        domain: ORDER_DOMAIN.to_string(),
        order_id: order_id.to_string(),
        kind,
        target_miner_id: TEST_MINER_ID.to_string(),
        issued_at_unix: TEST_NOW_UNIX,
        payload,
    };
    let mut bytes = Vec::new();
    ciborium::ser::into_writer(&body, &mut bytes).unwrap();
    let sig = edge_key().sign(&bytes).to_bytes().to_vec();
    let signed = SignedOrder {
        body: ByteBuf::from(bytes),
        sig: ByteBuf::from(sig),
    };
    let mut wire = Vec::new();
    ciborium::ser::into_writer(&signed, &mut wire).unwrap();
    wire
}

fn order(id: &str, payload: StorageConfigOrder) -> Vec<u8> {
    signed(id, OrderKind::StorageConfig, payload)
}

/// `(status, content-type, body)`.
async fn post(addr: SocketAddr, body: &[u8]) -> (u16, String, String) {
    let fut = async {
        let mut stream = TcpStream::connect(addr).await.unwrap();
        let header = format!(
            "POST /v1/miner/order/storage-config HTTP/1.1\r\nHost: miner\r\n\
             Content-Type: application/cbor\r\nContent-Length: {}\r\n\
             Connection: close\r\n\r\n",
            body.len()
        );
        stream.write_all(header.as_bytes()).await.unwrap();
        stream.write_all(body).await.unwrap();
        let mut resp = Vec::new();
        stream.read_to_end(&mut resp).await.unwrap();
        resp
    };
    let resp = tokio::time::timeout(Duration::from_secs(10), fut)
        .await
        .expect("HTTP POST timed out");
    let text = String::from_utf8_lossy(&resp).to_string();
    let (head, body) = text.split_once("\r\n\r\n").unwrap();
    let status = head
        .lines()
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|c| c.parse().ok())
        .unwrap();
    let content_type = head
        .lines()
        .find_map(|l| l.strip_prefix("content-type: "))
        .unwrap_or("")
        .to_string();
    (status, content_type, body.to_string())
}

#[tokio::test]
async fn a_document_is_applied_and_acked_with_its_digest() {
    let root = tempfile::tempdir().unwrap();
    let (addr, storage) = spawn(Some(root.path())).await;
    let storage = storage.unwrap();
    let d = doc(root.path(), 3, false, BUDGET_GB as u32);
    let sha = content_sha256_hex(&d).unwrap();
    let (status, _, body) = post(addr, &order("sc-1", d)).await;
    assert_eq!((status, body), (200, format!("applied:3:{sha}")));
    assert_eq!(storage.current().revision, 3);
    assert!(storage.current().pools.is_configured());
}

#[tokio::test]
async fn a_dry_run_is_acked_and_persists_nothing() {
    let root = tempfile::tempdir().unwrap();
    let (addr, storage) = spawn(Some(root.path())).await;
    let d = doc(root.path(), 3, true, BUDGET_GB as u32);
    let sha = content_sha256_hex(&d).unwrap();
    let (status, _, body) = post(addr, &order("sc-1", d)).await;
    assert_eq!((status, body), (200, format!("dry-run-ok:3:{sha}")));
    assert_eq!(storage.unwrap().current().revision, 0);
    assert!(!root.path().join("storage-config.json").exists());
}

#[tokio::test]
async fn a_refusal_is_json_naming_the_pool_and_is_not_cached() {
    let root = tempfile::tempdir().unwrap();
    let (addr, _) = spawn(Some(root.path())).await;
    // `default` must carry the host budget.
    let bad = order("sc-1", doc(root.path(), 3, false, 10));
    let (status, content_type, body) = post(addr, &bad).await;
    assert_eq!(status, 422);
    assert_eq!(content_type, "application/json");
    assert_eq!(body, r#"{"code":"pool-conflicts-local","pool":"default"}"#);
    // A refusal is not an idempotent outcome: the same order id is judged
    // again.
    assert_eq!(post(addr, &bad).await.0, 422);
}

#[tokio::test]
async fn replays_are_refused_also_after_a_restart() {
    let root = tempfile::tempdir().unwrap();
    {
        let (addr, _) = spawn(Some(root.path())).await;
        let (status, _, _) = post(addr, &order("sc-4", doc(root.path(), 4, false, 500))).await;
        assert_eq!(status, 200);
    }
    let (addr, storage) = spawn(Some(root.path())).await;
    assert_eq!(storage.unwrap().current().revision, 4);
    let (status, _, body) = post(addr, &order("sc-3", doc(root.path(), 3, false, 500))).await;
    assert_eq!(
        (status, body.as_str()),
        (409, r#"{"code":"storage-config-stale-revision"}"#)
    );
}

#[tokio::test]
async fn the_pipeline_checks_still_apply_and_an_unwired_route_is_disabled() {
    let root = tempfile::tempdir().unwrap();
    let (addr, _) = spawn(Some(root.path())).await;
    // An order of another kind on this route.
    let wrong = signed(
        "sc-1",
        OrderKind::NetPolicy,
        doc(root.path(), 3, false, 500),
    );
    let (status, _, body) = post(addr, &wrong).await;
    assert_eq!((status, body.as_str()), (400, "order-kind-mismatch"));
    // A forged signature.
    let mut forged = order("sc-2", doc(root.path(), 3, false, 500));
    let last = forged.len() - 1;
    forged[last] ^= 1;
    assert_eq!(post(addr, &forged).await.0, 401);
    let (addr, _) = spawn(None).await;
    let (status, _, body) = post(addr, &order("sc-3", doc(root.path(), 3, false, 500))).await;
    assert_eq!((status, body.as_str()), (503, "storage-config-disabled"));
}
