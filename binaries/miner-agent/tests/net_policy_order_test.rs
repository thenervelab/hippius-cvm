//! `net-policy` order intake over real HTTP: the ticket-validator's
//! encoded body from `test_vectors/orders/net_policy_v1.json`, signed with
//! the test Edge key, is accepted, loaded (into a fake `nft`) and acked;
//! replays are refused, also by a restarted agent over the same state
//! directory; a load failure is not acked.

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
use hippius_miner_agent::netpolicy::{
    GuestTaps, MockNft, NetPolicyEnforcer, NetPolicyStore, SmtpTap, VirshTuner, VmCaps,
};
use hippius_miner_agent::orders::{
    Clock, EolShutdownAckSigner, IdempotencyStore, MigrationStore, NetPolicyOrder, OrderBody,
    OrderKind, OrderState, OrderVerifier, OrdersServer, ReqwestSnapshotDownloader,
    ReqwestSnapshotUploader, SignedOrder, ORDER_DOMAIN,
};
use hippius_miner_agent::{CvmLifecycle, HostResources};

const TEST_MINER_ID: &str = "cc-test-miner";
const TEST_NOW_UNIX: u64 = 1_770_000_000;

struct FixedClock(u64);

impl Clock for FixedClock {
    fn now_unix(&self) -> u64 {
        self.0
    }
}

struct Vector {
    body: Vec<u8>,
    content_sha256: String,
    payload: NetPolicyOrder,
}

fn vector() -> Vector {
    let v: serde_json::Value = serde_json::from_slice(
        &std::fs::read(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../test_vectors/orders/net_policy_v1.json"
        ))
        .unwrap(),
    )
    .unwrap();
    let case = &v["cases"][0];
    let body = hex::decode(case["body_hex"].as_str().unwrap()).unwrap();
    let decoded: OrderBody<NetPolicyOrder> = ciborium::de::from_reader(body.as_slice()).unwrap();
    assert_eq!(decoded.target_miner_id, TEST_MINER_ID);
    assert_eq!(decoded.issued_at_unix, TEST_NOW_UNIX);
    Vector {
        body,
        content_sha256: case["content_sha256"].as_str().unwrap().to_string(),
        payload: decoded.payload,
    }
}

fn edge_key() -> SigningKey {
    SigningKey::from_bytes(&[42u8; 32])
}

struct NoTaps;

#[async_trait::async_trait]
impl GuestTaps for NoTaps {
    async fn taps(
        &self,
        _vms: &[hippius_miner_agent::lifecycle::VmId],
    ) -> hippius_miner_agent::Result<Vec<SmtpTap>> {
        Ok(Vec::new())
    }
}

/// An orders server whose `net-policy` route persists under `dir` and
/// loads into a fresh fake `nft` (`None` ⇒ route not wired).
async fn spawn(dir: Option<&Path>) -> SocketAddr {
    spawn_with(dir, Arc::new(MockNft::new())).await
}

async fn spawn_with(dir: Option<&Path>, nft: Arc<MockNft>) -> SocketAddr {
    let sk = edge_key();
    let verifier =
        Arc::new(OrderVerifier::from_hex(&hex::encode(sk.verifying_key().to_bytes())).unwrap());
    let lifecycle = Arc::new(CvmLifecycle::new(
        Arc::new(MockLibvirtDriver::new()),
        Arc::new(MockLaunchDigest::fixed([0u8; 48])),
        HostResources {
            total_cpus: 16,
            total_memory_mb: 65536,
            total_disk_gb: 0,
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
    let state = match dir {
        Some(dir) => state.with_net_policy(Arc::new(NetPolicyEnforcer::new(
            Arc::new(NetPolicyStore::new(dir)),
            nft,
            Arc::new(NoTaps),
            Arc::new(VmCaps::new(
                Arc::new(MockLibvirtDriver::new()),
                Arc::new(VirshTuner::new("/nonexistent/virsh".into())),
            )),
        ))),
        None => state,
    };
    let server = OrdersServer::bind("127.0.0.1:0".parse().unwrap())
        .await
        .unwrap();
    let addr = server.local_addr();
    tokio::spawn(server.serve(state, CancellationToken::new()));
    addr
}

fn sign_raw(body: Vec<u8>) -> Vec<u8> {
    let sig = edge_key().sign(&body).to_bytes().to_vec();
    let signed = SignedOrder {
        body: ByteBuf::from(body),
        sig: ByteBuf::from(sig),
    };
    let mut wire = Vec::new();
    ciborium::ser::into_writer(&signed, &mut wire).unwrap();
    wire
}

fn signed_policy<T: Serialize>(order_id: &str, target: &str, payload: T) -> Vec<u8> {
    let body = OrderBody {
        domain: ORDER_DOMAIN.to_string(),
        order_id: order_id.to_string(),
        kind: OrderKind::NetPolicy,
        target_miner_id: target.to_string(),
        issued_at_unix: TEST_NOW_UNIX,
        payload,
    };
    let mut bytes = Vec::new();
    ciborium::ser::into_writer(&body, &mut bytes).unwrap();
    sign_raw(bytes)
}

async fn post(addr: SocketAddr, body: &[u8]) -> (u16, String) {
    let fut = async {
        let mut stream = TcpStream::connect(addr).await.unwrap();
        let header = format!(
            "POST /v1/miner/order/net-policy HTTP/1.1\r\nHost: miner\r\n\
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
    let text = String::from_utf8_lossy(&resp);
    let status = text
        .lines()
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|c| c.parse().ok())
        .unwrap();
    (
        status,
        text.split("\r\n\r\n").nth(1).unwrap_or("").to_string(),
    )
}

#[tokio::test]
async fn the_encoded_vector_is_accepted_and_acked() {
    let dir = tempfile::tempdir().unwrap();
    let nft = Arc::new(MockNft::new());
    let addr = spawn_with(Some(dir.path()), nft.clone()).await;
    let v = vector();
    let (status, body) = post(addr, &sign_raw(v.body.clone())).await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body, format!("applied:7:{}", v.content_sha256));
    let stored = NetPolicyStore::new(dir.path()).current().unwrap().unwrap();
    assert_eq!(stored.order().unwrap(), v.payload);
    // Loaded before the ack, with the vector's uplink hint, and saved
    // for the boot unit.
    let live = nft.live().unwrap();
    assert!(live.contains(&v.content_sha256), "{live}");
    assert!(
        live.contains("oifname != { \"eth0\", \"virbr0\" }"),
        "{live}"
    );
    assert_eq!(
        std::fs::read_to_string(dir.path().join("ruleset.nft")).unwrap(),
        live
    );

    // A re-send under a fresh order id (vali's periodic repair) acks the same.
    let (status, again) = post(addr, &signed_policy("np-7-b", TEST_MINER_ID, &v.payload)).await;
    assert_eq!((status, again), (200, body));
}

#[tokio::test]
async fn replays_are_refused_also_after_a_restart() {
    let dir = tempfile::tempdir().unwrap();
    let v = vector();
    let addr = spawn(Some(dir.path())).await;
    assert_eq!(post(addr, &sign_raw(v.body.clone())).await.0, 200);

    let mut older = v.payload.clone();
    older.revision = 6;
    older.enforce = false;
    let mut conflicting = v.payload.clone();
    conflicting.local_action = hippius_miner_agent::orders::NetPolicyLocalAction::Drop;

    for addr in [addr, spawn(Some(dir.path())).await] {
        assert_eq!(
            post(addr, &signed_policy("np-6", TEST_MINER_ID, &older)).await,
            (409, "net-policy-stale-revision".to_string())
        );
        assert_eq!(
            post(addr, &signed_policy("np-7-x", TEST_MINER_ID, &conflicting)).await,
            (409, "net-policy-revision-conflict".to_string())
        );
    }
    // A higher revision moves on, and the old one is now stale too.
    let addr = spawn(Some(dir.path())).await;
    let mut newer = v.payload.clone();
    newer.revision = 8;
    let (status, body) = post(addr, &signed_policy("np-8", TEST_MINER_ID, &newer)).await;
    assert_eq!(status, 200);
    assert!(body.starts_with("applied:8:"), "{body}");
    assert_eq!(
        post(addr, &signed_policy("np-7-c", TEST_MINER_ID, &v.payload)).await,
        (409, "net-policy-stale-revision".to_string())
    );
}

#[tokio::test]
async fn expired_wrong_miner_and_unwired_are_refused() {
    let dir = tempfile::tempdir().unwrap();
    let addr = spawn(Some(dir.path())).await;
    let v = vector();
    let mut expired = v.payload.clone();
    expired.not_after_unix = TEST_NOW_UNIX - 1;
    assert_eq!(
        post(addr, &signed_policy("np-exp", TEST_MINER_ID, &expired)).await,
        (422, "net-policy-expired".to_string())
    );
    assert_eq!(
        post(
            addr,
            &signed_policy("np-other", "cc-other-miner", &v.payload)
        )
        .await,
        (400, "order-wrong-miner".to_string())
    );
    let mut bad = v.payload.clone();
    bad.region_miners.push("10.0.0.01".into());
    assert_eq!(
        post(addr, &signed_policy("np-bad", TEST_MINER_ID, &bad)).await,
        (422, "net-policy-invalid".to_string())
    );
    assert_eq!(NetPolicyStore::new(dir.path()).current().unwrap(), None);

    let unwired = spawn(None).await;
    assert_eq!(
        post(unwired, &sign_raw(v.body)).await,
        (503, "net-policy-disabled".to_string())
    );
}

#[tokio::test]
async fn a_load_failure_is_not_acked_and_the_resend_is() {
    let dir = tempfile::tempdir().unwrap();
    let nft = Arc::new(MockNft::new());
    nft.set_fail_apply(true);
    let addr = spawn_with(Some(dir.path()), nft.clone()).await;
    let v = vector();
    assert_eq!(
        post(addr, &sign_raw(v.body.clone())).await,
        (500, "net-policy-apply".to_string())
    );
    assert_eq!(nft.live(), None);

    nft.set_fail_apply(false);
    let (status, body) = post(addr, &signed_policy("np-7-r", TEST_MINER_ID, &v.payload)).await;
    assert_eq!(
        (status, body),
        (200, format!("applied:7:{}", v.content_sha256))
    );
    assert!(nft.live().is_some());
}

#[tokio::test]
async fn an_edge_mode_policy_is_refused_unpersisted() {
    let dir = tempfile::tempdir().unwrap();
    let nft = Arc::new(MockNft::new());
    let addr = spawn_with(Some(dir.path()), nft.clone()).await;
    let mut edge = vector().payload;
    edge.mode = hippius_miner_agent::orders::NetPolicyMode::Edge;
    assert_eq!(
        post(addr, &signed_policy("np-edge", TEST_MINER_ID, &edge)).await,
        (422, "net-policy-unsupported".to_string())
    );
    assert_eq!(NetPolicyStore::new(dir.path()).current().unwrap(), None);
    assert!(nft.applied().is_empty());
}
