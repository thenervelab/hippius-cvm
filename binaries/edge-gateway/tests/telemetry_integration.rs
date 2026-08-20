//! PR-H6 — signed telemetry + audit log integration tests.
//!
//! Drives the production [`relay_once`] entry point with a real
//! [`TelemetryRecorder`] (a boot-generated [`EdgeSigner`] + a
//! file-backed [`EdgeAuditSink`]) and proves, end to end:
//!
//! 1. **A relayed transaction emits a verifiable signed envelope.**
//!    The audit log holds one record; its [`SignedEdgeTelemetry`]
//!    verifies under the Edge pubkey and decodes to the expected
//!    counters + routing metadata.
//! 2. **The hash chain holds after N envelopes.** `audit.verify()`
//!    walks the log clean; per-record counters run `0..N`; tampering
//!    a byte trips `verify()`.
//! 3. **A shed transaction is recorded with its reason.** A
//!    rate-limited transaction lands in the log with `shed = true`,
//!    `shed_reason = "rate-limited"`, `bytes_out = 0`.
//! 4. **The `/v1/edge/*` API serves the pubkey + audit head.**

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use hippius_edge_gateway::wire::verify_signed_telemetry;
use hippius_edge_gateway::{
    bounded_queue, relay_once, Direction, EdgeApiServer, EdgeAuditSink, EdgeError,
    EdgeGatewayConfig, EdgeSigner, MessageKind, PeerId, PerSourceRateLimiter, RateLimitConfig,
    SignedEdgeTelemetry, TelemetryEvent, TelemetryRecorder, TelemetrySink,
};
use tempfile::TempDir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

// ---------------------------------------------------------------------
// Helpers.
// ---------------------------------------------------------------------

/// Read the on-disk audit log back into its `SignedEdgeTelemetry`
/// records. Parses the documented `<seq>:<hex_record>:<hex_hash>` line
/// format and pulls the `sig` + `telemetry` fields out of each
/// canonical-CBOR record body. (The audit log's chain integrity is
/// asserted separately via `EdgeAuditSink::verify`.)
fn read_signed_telemetry(dir: &Path) -> Vec<SignedEdgeTelemetry> {
    let log = std::fs::read_to_string(dir.join("audit.log")).unwrap_or_default();
    log.lines()
        .map(|line| {
            let mut parts = line.splitn(3, ':');
            let _seq = parts.next().expect("seq");
            let body_hex = parts.next().expect("body");
            let _hash = parts.next().expect("hash");
            let record = hex::decode(body_hex).expect("record hex");
            let value: ciborium::value::Value =
                ciborium::de::from_reader(&record[..]).expect("record cbor");
            let ciborium::value::Value::Map(entries) = value else {
                panic!("audit record is not a CBOR map");
            };
            let mut sig = None;
            let mut telemetry = None;
            for (k, v) in entries {
                let ciborium::value::Value::Text(key) = k else {
                    continue;
                };
                match (key.as_str(), v) {
                    ("sig", ciborium::value::Value::Bytes(b)) => sig = Some(b),
                    ("telemetry", ciborium::value::Value::Bytes(b)) => telemetry = Some(b),
                    _ => {}
                }
            }
            SignedEdgeTelemetry {
                body: telemetry.expect("telemetry field"),
                sig: sig.expect("sig field"),
            }
        })
        .collect()
}

/// Build a `(recorder, signer, audit)` triple over a fresh tempdir.
fn telemetry_stack(dir: &Path) -> (TelemetryRecorder, Arc<EdgeSigner>, Arc<EdgeAuditSink>) {
    let signer = Arc::new(EdgeSigner::generate());
    let audit = Arc::new(EdgeAuditSink::open(dir).unwrap());
    let recorder = TelemetryRecorder::new(Arc::clone(&signer), Arc::clone(&audit));
    (recorder, signer, audit)
}

/// Issue a one-shot HTTP/1.1 GET, return the full raw response.
async fn http_get(addr: SocketAddr, path: &str) -> String {
    let mut stream = TcpStream::connect(addr).await.unwrap();
    let req = format!("GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n");
    stream.write_all(req.as_bytes()).await.unwrap();
    let mut resp = Vec::new();
    stream.read_to_end(&mut resp).await.unwrap();
    String::from_utf8_lossy(&resp).into_owned()
}

// ---------------------------------------------------------------------
// Tests.
// ---------------------------------------------------------------------

#[tokio::test]
async fn relay_loop_emits_verifiable_signed_telemetry() {
    let td = TempDir::new().unwrap();
    let (recorder, signer, audit) = telemetry_stack(td.path());

    let cfg = EdgeGatewayConfig::default();
    let limiter = PerSourceRateLimiter::from_config(&cfg);
    let (sink, mut source) = bounded_queue(cfg.queue_capacity);
    let peer = PeerId::new("hippius-miner:telemetry-test");

    relay_once(
        Direction::MinerToInner,
        MessageKind::ServedReceipt,
        peer.clone(),
        &limiter,
        &sink,
        &recorder,
    )
    .await
    .expect("happy-path relay must enqueue");
    let _ = source.recv().await.expect("worker side receives");

    assert_eq!(audit.record_count(), 1, "one transaction ⇒ one record");

    // Pull the signed envelope back out and verify it under the Edge
    // pubkey — exactly what Sentinel / the Validator do.
    let records = read_signed_telemetry(td.path());
    assert_eq!(records.len(), 1);
    let envelope = verify_signed_telemetry(&signer.verifying_key(), &records[0])
        .expect("telemetry signature must verify under the Edge pubkey");

    assert_eq!(envelope.peer_id, "hippius-miner:telemetry-test");
    assert_eq!(envelope.direction, Direction::MinerToInner);
    assert_eq!(envelope.message_kind, MessageKind::ServedReceipt);
    assert_eq!(envelope.counter, 0, "first record's counter is 0");
    assert!(!envelope.shed);
    assert_eq!(envelope.shed_reason, None);
    assert!(envelope.bytes_in > 0);
    // Opaque relay: a relayed body egresses verbatim.
    assert_eq!(envelope.bytes_out, envelope.bytes_in);

    // A tampered signature must fail verification.
    let mut tampered = records[0].clone();
    tampered.sig[0] ^= 0xff;
    assert!(verify_signed_telemetry(&signer.verifying_key(), &tampered).is_err());
}

#[tokio::test]
async fn audit_chain_verifies_after_n_envelopes() {
    let td = TempDir::new().unwrap();
    let (recorder, signer, audit) = telemetry_stack(td.path());

    let cfg = EdgeGatewayConfig::default();
    let limiter = PerSourceRateLimiter::from_config(&cfg);
    let (sink, mut source) = bounded_queue(cfg.queue_capacity);

    const N: u64 = 12;
    for i in 0..N {
        relay_once(
            Direction::MinerToInner,
            MessageKind::ServedReceipt,
            PeerId::new(&format!("hippius-miner:{i}")),
            &limiter,
            &sink,
            &recorder,
        )
        .await
        .expect("relay must enqueue");
        let _ = source.recv().await.expect("worker side receives");
    }

    // The chain walks clean and the count matches.
    let verified = audit.verify().expect("chain must verify after N envelopes");
    assert_eq!(verified.records, N);
    assert_eq!(audit.record_count(), N);

    // Every record's signature verifies and the counters run 0..N.
    let records = read_signed_telemetry(td.path());
    assert_eq!(records.len() as u64, N);
    for (i, signed) in records.iter().enumerate() {
        let envelope = verify_signed_telemetry(&signer.verifying_key(), signed)
            .expect("each archived envelope must verify");
        assert_eq!(envelope.counter, i as u64, "counters are dense + ordered");
    }

    // Flip one byte in the first record's body — the chain must break.
    let log_path = td.path().join("audit.log");
    let content = std::fs::read_to_string(&log_path).unwrap();
    let flip = content.find("0:").unwrap() + 2;
    let mut bytes = content.into_bytes();
    bytes[flip] = if bytes[flip] == b'a' { b'b' } else { b'a' };
    std::fs::write(&log_path, bytes).unwrap();
    assert!(
        audit.verify().is_err(),
        "a tampered audit log must fail verification"
    );
}

#[tokio::test]
async fn shed_transaction_is_recorded_with_reason() {
    let td = TempDir::new().unwrap();
    let (recorder, signer, audit) = telemetry_stack(td.path());

    // burst = 1 ⇒ the first transaction passes, the second is shed.
    let limiter = PerSourceRateLimiter::new(
        RateLimitConfig {
            refill_per_sec: 0.0,
            burst: 1,
        },
        Duration::from_secs(3600),
        usize::MAX,
    );
    let (sink, mut source) = bounded_queue(16);
    let peer = PeerId::new("hippius-miner:shed-test");

    relay_once(
        Direction::MinerToInner,
        MessageKind::ServedReceipt,
        peer.clone(),
        &limiter,
        &sink,
        &recorder,
    )
    .await
    .expect("first transaction within burst");
    let err = relay_once(
        Direction::MinerToInner,
        MessageKind::ServedReceipt,
        peer.clone(),
        &limiter,
        &sink,
        &recorder,
    )
    .await
    .expect_err("second transaction must be rate-limited");
    assert!(matches!(err, EdgeError::RateLimited));
    let _ = source.recv().await.expect("the one enqueued envelope");

    // BOTH transactions — relayed AND shed — are in the audit log.
    assert_eq!(audit.record_count(), 2);
    let records = read_signed_telemetry(td.path());
    let relayed = verify_signed_telemetry(&signer.verifying_key(), &records[0]).unwrap();
    let shed = verify_signed_telemetry(&signer.verifying_key(), &records[1]).unwrap();

    assert!(!relayed.shed);
    assert!(shed.shed, "the rate-limited transaction is recorded shed");
    assert_eq!(shed.shed_reason.as_deref(), Some("rate-limited"));
    assert_eq!(shed.bytes_out, 0, "a shed transaction egresses nothing");
}

#[tokio::test]
async fn edge_api_serves_pubkey_and_audit_verify() {
    let td = TempDir::new().unwrap();
    let (recorder, signer, audit) = telemetry_stack(td.path());

    // Land one record so the audit count is non-zero.
    recorder.record(TelemetryEvent {
        peer: PeerId::new("hippius-miner:api-test"),
        direction: Direction::MinerToInner,
        message_kind: MessageKind::ServedReceipt,
        bytes_in: 64,
        bytes_out: 64,
        shed: false,
        shed_reason: None,
    });

    let api = EdgeApiServer::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
        .await
        .unwrap();
    let addr = api.local_addr();
    let task = tokio::spawn(api.run(Arc::clone(&signer), Arc::clone(&audit)));

    // /v1/edge/pubkey — the published Ed25519 public key.
    let pubkey_resp = http_get(addr, "/v1/edge/pubkey").await;
    assert!(
        pubkey_resp.starts_with("HTTP/1.1 200 OK"),
        "got: {pubkey_resp}"
    );
    assert!(pubkey_resp.contains("\"algorithm\":\"ed25519\""));
    assert!(pubkey_resp.contains(&hex::encode(signer.public_key_bytes())));

    // /v1/edge/audit/verify — walks + chain-verifies the log, then
    // returns the verified head + record count.
    let verify_resp = http_get(addr, "/v1/edge/audit/verify").await;
    assert!(
        verify_resp.starts_with("HTTP/1.1 200 OK"),
        "got: {verify_resp}"
    );
    assert!(verify_resp.contains("\"verified\":true"));
    assert!(verify_resp.contains("\"record_count\":1"));
    assert!(verify_resp.contains(&hex::encode(audit.head())));

    // An unknown path 404s.
    let miss = http_get(addr, "/v1/edge/nope").await;
    assert!(miss.starts_with("HTTP/1.1 404"), "got: {miss}");

    task.abort();
}
