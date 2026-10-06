//! Integration tests for the KBS HTTP transport.
//!
//! These exercise the axum router end-to-end via `tower::ServiceExt::oneshot`
//! (no TCP socket) against a tiny `MockKbsService`. The service-layer
//! contract is already validated by kbs-core's tests; here we focus on
//! the transport surface: content-type, CBOR canonicalization, size cap,
//! status codes, rate limiting, and the success/denial bifurcation.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use axum::body::Body;
use axum::http::{header, Request, StatusCode};
use bytes::Bytes;
use ed25519_dalek::{Signer, SigningKey};
use hippius_types::cbor::{assert_canonical, to_canonical_vec};
use hippius_types::host_attestor::{
    HostAttestorCert, HostEnrollment, SignedHostAttestorCert, HOST_ATTESTOR_SCHEMA_VERSION,
    PUBKEY_LEN, SNP_REPORT_LEN,
};
use hippius_types::release::{SignedDenial, SignedResponse};
use http_body_util::BodyExt;
use kbs_core::error::{KbsError, Result};
use kbs_transport::rate_limit::RateConfig;
use kbs_transport::router::{build_router_with_rate, build_router_with_rates};
use kbs_transport::wire::{
    HostEnrollResponseBody, NonceResponse, VolumeStampConfirmResponse, MAX_REQUEST_BYTES,
};
use kbs_transport::{build_router, KbsService, NONCE_LEN};
use std::sync::Arc;
use std::sync::Mutex;
use tower::ServiceExt;

/// Configurable mock: each operation can be programmed to return Ok or a
/// canned error. We record calls so we can assert side-effects.
/// `(cose_ticket, snp_report, kbs_nonce, submitted_boot_counter)`.
type ReleaseArgs = (Vec<u8>, Vec<u8>, [u8; NONCE_LEN], Option<u64>);

struct MockSvc {
    nonce: Mutex<Result<[u8; NONCE_LEN]>>,
    release: Mutex<core::result::Result<SignedResponse, SignedDenial>>,
    host_enroll: Mutex<Result<SignedHostAttestorCert>>,
    volume_stamp_confirm: Mutex<Result<u64>>,
    calls: Mutex<Vec<String>>,
    /// Exactly what each `process_release` received.
    release_args: Mutex<Vec<ReleaseArgs>>,
}

impl MockSvc {
    fn new() -> Self {
        let body = b"OK".to_vec();
        let sig = vec![9u8; 64];
        Self {
            nonce: Mutex::new(Ok([7u8; NONCE_LEN])),
            release: Mutex::new(Ok(SignedResponse { body, sig })),
            // Default: mint a canonical cert so the happy-path handler
            // test can round-trip the response. Overridden per test.
            host_enroll: Mutex::new(Ok(sample_signed_cert())),
            volume_stamp_confirm: Mutex::new(Ok(1)),
            calls: Mutex::new(Vec::new()),
            release_args: Mutex::new(Vec::new()),
        }
    }
    fn set_nonce(&self, r: Result<[u8; NONCE_LEN]>) {
        *self.nonce.lock().unwrap() = r;
    }
    fn set_release(&self, r: core::result::Result<SignedResponse, SignedDenial>) {
        *self.release.lock().unwrap() = r;
    }
    fn set_host_enroll(&self, r: Result<SignedHostAttestorCert>) {
        *self.host_enroll.lock().unwrap() = r;
    }
    fn set_volume_stamp_confirm(&self, r: Result<u64>) {
        *self.volume_stamp_confirm.lock().unwrap() = r;
    }
    fn calls(&self) -> Vec<String> {
        self.calls.lock().unwrap().clone()
    }
}

/// A well-formed `SignedHostAttestorCert` (canonical cert body + a real
/// L0 signature over it) the mock returns on the happy path.
fn sample_signed_cert() -> SignedHostAttestorCert {
    let cert = HostAttestorCert {
        schema_version: HOST_ATTESTOR_SCHEMA_VERSION,
        node_id: "node-host-1".into(),
        chip_id: [0x9C; 64],
        attestor_pubkey: [0x22; PUBKEY_LEN],
        measurement: [0xAA; 48],
        tcb: 0x0708_0000_0000_000B,
        nonce: [0x42; 32],
        expiry_unix: 1_800_003_600,
    };
    let body = cert.canonical().unwrap();
    let sk = SigningKey::from_bytes(&[0x11u8; 32]);
    let sig = sk.sign(&body).to_bytes();
    SignedHostAttestorCert { body, sig }
}

/// A valid inner enrollment's canonical CBOR bytes.
fn sample_enrollment_bytes() -> Vec<u8> {
    HostEnrollment {
        schema_version: HOST_ATTESTOR_SCHEMA_VERSION,
        snp_report: [0x5A; SNP_REPORT_LEN],
        signer_pubkey: [0x22; PUBKEY_LEN],
        node_id: "node-host-1".into(),
        boot_id: "boot-abc".into(),
        issued_at_unix: 1_800_000_000,
    }
    .canonical()
    .unwrap()
}

/// Canonical `{enrollment, nonce}` request body.
fn canonical_host_enroll_body(enrollment: &[u8], nonce: &[u8]) -> Vec<u8> {
    let v = ciborium::value::Value::Map(vec![
        (
            ciborium::value::Value::Text("enrollment".into()),
            ciborium::value::Value::Bytes(enrollment.to_vec()),
        ),
        (
            ciborium::value::Value::Text("nonce".into()),
            ciborium::value::Value::Bytes(nonce.to_vec()),
        ),
    ]);
    to_canonical_vec(&v).unwrap()
}

impl KbsService for MockSvc {
    fn issue_nonce(&self, _now: u64) -> Result<[u8; NONCE_LEN]> {
        self.calls.lock().unwrap().push("issue_nonce".into());
        match &*self.nonce.lock().unwrap() {
            Ok(n) => Ok(*n),
            Err(KbsError::Replay) => Err(KbsError::Replay),
            Err(e) => Err(KbsError::Vault(e.to_string())),
        }
    }
    fn process_release(
        &self,
        cose: &[u8],
        snp: &[u8],
        nonce: &[u8; NONCE_LEN],
        _now: u64,
        submitted_boot_counter: Option<u64>,
    ) -> core::result::Result<SignedResponse, SignedDenial> {
        self.calls.lock().unwrap().push("process_release".into());
        self.release_args.lock().unwrap().push((
            cose.to_vec(),
            snp.to_vec(),
            *nonce,
            submitted_boot_counter,
        ));
        self.release.lock().unwrap().clone()
    }
    fn process_keepalive(
        &self,
        _vm_id: &str,
        _node_id: &[u8; NONCE_LEN],
        _snp: &[u8],
        _nonce: &[u8; NONCE_LEN],
        _epoch: u64,
        _expiry_unix: u64,
        _resources: Option<&hippius_types::live_attestation::GuestResources>,
        _components: Option<&hippius_types::live_attestation::GuestComponents>,
        _now: u64,
    ) -> Result<hippius_types::live_attestation::SignedLiveAttestation> {
        self.calls.lock().unwrap().push("process_keepalive".into());
        // The transport tests don't drive the keepalive route directly
        // (the PR-3b test file lives next door); deny by default so a
        // misrouted release test that hits this path fails loudly.
        Err(KbsError::Replay)
    }
    fn process_host_enroll(
        &self,
        _enrollment: &HostEnrollment,
        _nonce: &[u8; NONCE_LEN],
        _now: u64,
    ) -> Result<SignedHostAttestorCert> {
        self.calls
            .lock()
            .unwrap()
            .push("process_host_enroll".into());
        // `KbsError` is not `Clone`; reconstruct on the Err arm (the
        // handler maps ANY Err to a generic 403, so the exact variant is
        // immaterial to the transport test).
        match &*self.host_enroll.lock().unwrap() {
            Ok(c) => Ok(c.clone()),
            Err(e) => Err(KbsError::Attestation(e.to_string())),
        }
    }
    fn process_volume_stamp_confirm(
        &self,
        _vm_id: &str,
        _value: u64,
        _token: &[u8],
    ) -> Result<u64> {
        self.calls
            .lock()
            .unwrap()
            .push("process_volume_stamp_confirm".into());
        // `KbsError` is not `Clone`; reconstruct on the Err arm (the
        // handler maps ANY Err to a generic 403, so the exact variant is
        // immaterial to the transport test).
        match &*self.volume_stamp_confirm.lock().unwrap() {
            Ok(v) => Ok(*v),
            Err(e) => Err(KbsError::Policy(e.to_string())),
        }
    }
    fn process_volume_stamp_confirm_timeline(
        &self,
        _vm_id: &str,
        _value: u64,
        _token: &[u8],
        timeline: &[u8; 32],
    ) -> Result<u64> {
        self.calls.lock().unwrap().push(format!(
            "process_volume_stamp_confirm_timeline:{:02x}",
            timeline[0]
        ));
        match &*self.volume_stamp_confirm.lock().unwrap() {
            Ok(v) => Ok(*v),
            Err(e) => Err(KbsError::Policy(e.to_string())),
        }
    }
}

/// Canonical `{token: bstr, value: uint, vm_id: tstr}` request body.
fn canonical_volume_stamp_confirm_body(vm_id: &str, value: u64, token: &[u8]) -> Vec<u8> {
    let v = ciborium::value::Value::Map(vec![
        (
            ciborium::value::Value::Text("token".into()),
            ciborium::value::Value::Bytes(token.to_vec()),
        ),
        (
            ciborium::value::Value::Text("value".into()),
            ciborium::value::Value::Integer(value.into()),
        ),
        (
            ciborium::value::Value::Text("vm_id".into()),
            ciborium::value::Value::Text(vm_id.into()),
        ),
    ]);
    to_canonical_vec(&v).unwrap()
}

fn canonical_release_body(cose: &[u8], snp: &[u8], nonce: &[u8]) -> Vec<u8> {
    let v = ciborium::value::Value::Map(vec![
        (
            ciborium::value::Value::Text("cose_ticket".into()),
            ciborium::value::Value::Bytes(cose.to_vec()),
        ),
        (
            ciborium::value::Value::Text("kbs_nonce".into()),
            ciborium::value::Value::Bytes(nonce.to_vec()),
        ),
        (
            ciborium::value::Value::Text("snp_report".into()),
            ciborium::value::Value::Bytes(snp.to_vec()),
        ),
    ]);
    to_canonical_vec(&v).unwrap()
}

async fn read_body(resp: axum::response::Response) -> (StatusCode, Vec<u8>, axum::http::HeaderMap) {
    let status = resp.status();
    let headers = resp.headers().clone();
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    (status, body.to_vec(), headers)
}

/// Generous rate config so non-rate tests don't trip the limiter.
fn fast_rate() -> RateConfig {
    RateConfig {
        refill_per_sec: 10_000.0,
        burst: 10_000,
    }
}

#[tokio::test]
async fn healthz_returns_200() {
    let svc = Arc::new(MockSvc::new());
    let app = build_router(svc);
    let resp = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/healthz")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let (status, body, _) = read_body(resp).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, b"ok");
}

#[tokio::test]
async fn issue_nonce_returns_canonical_cbor_with_32_bytes_and_no_store() {
    let svc = Arc::new(MockSvc::new());
    let app = build_router_with_rate(svc.clone(), fast_rate());
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/kbs/nonce")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let (status, body, headers) = read_body(resp).await;
    assert_eq!(status, StatusCode::OK);
    let decoded: NonceResponse = ciborium::de::from_reader(body.as_slice()).unwrap();
    assert_eq!(decoded.nonce.len(), NONCE_LEN);
    assert_eq!(decoded.nonce.as_ref(), &[7u8; NONCE_LEN]);
    // The encoded body MUST itself be canonical CBOR — the protocol
    // discipline (§20) covers responses too.
    assert_canonical(&body).unwrap();
    assert_eq!(
        headers
            .get(header::CACHE_CONTROL)
            .map(|h| h.to_str().unwrap()),
        Some("no-store")
    );
    assert_eq!(svc.calls(), vec!["issue_nonce".to_string()]);
}

#[tokio::test]
async fn issue_nonce_rejects_non_empty_body() {
    let svc = Arc::new(MockSvc::new());
    let app = build_router_with_rate(svc.clone(), fast_rate());
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/kbs/nonce")
                .header(header::CONTENT_LENGTH, "3")
                .body(Body::from(vec![1u8, 2, 3]))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    assert!(svc.calls().is_empty());
}

#[tokio::test]
async fn issue_nonce_internal_error_returns_generic_500_body() {
    let svc = Arc::new(MockSvc::new());
    svc.set_nonce(Err(KbsError::Vault(
        "INTERNAL/SECRET: opaque vault path /var/lib/kbs/leaky".into(),
    )));
    let app = build_router_with_rate(svc, fast_rate());
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/kbs/nonce")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let (status, body, _) = read_body(resp).await;
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
    let text = std::str::from_utf8(&body).unwrap();
    // Public message only; the leaky internal detail MUST NOT be present.
    assert_eq!(text, "nonce issuance failed");
    assert!(!text.contains("INTERNAL/SECRET"));
    assert!(!text.contains("leaky"));
}

#[tokio::test]
async fn issue_nonce_rate_limited_returns_429_with_retry_after() {
    let svc = Arc::new(MockSvc::new());
    let app = build_router_with_rate(
        svc,
        RateConfig {
            refill_per_sec: 0.0001, // effectively no refill in test window
            burst: 1,
        },
    );
    // First request consumes the only token.
    let resp1 = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/kbs/nonce")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp1.status(), StatusCode::OK);
    // Second is shed.
    let resp2 = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/kbs/nonce")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let (status, _body, headers) = read_body(resp2).await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
    assert!(headers.get(header::RETRY_AFTER).is_some());
}

#[tokio::test]
async fn release_ok_returns_200_canonical_cbor_signed_response_and_no_store() {
    let sk = SigningKey::from_bytes(&[42u8; 32]);
    let signed = SignedResponse {
        body: b"BODY-BYTES".to_vec(),
        sig: sk.sign(b"BODY-BYTES").to_bytes().to_vec(),
    };
    let svc = Arc::new(MockSvc::new());
    svc.set_release(Ok(signed.clone()));
    let app = build_router_with_rate(svc.clone(), fast_rate());

    let body = canonical_release_body(b"cose", b"snp", &[1u8; 32]);
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/kbs/release")
                .header(header::CONTENT_TYPE, "application/cbor")
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();
    let (status, bytes, headers) = read_body(resp).await;
    assert_eq!(status, StatusCode::OK);
    let decoded: SignedResponse = ciborium::de::from_reader(bytes.as_slice()).unwrap();
    assert_eq!(decoded, signed);
    assert_canonical(&bytes).unwrap();
    assert_eq!(
        headers
            .get(header::CACHE_CONTROL)
            .map(|h| h.to_str().unwrap()),
        Some("no-store")
    );
    assert_eq!(svc.calls(), vec!["process_release".to_string()]);
}

#[tokio::test]
async fn release_denial_returns_403_canonical_cbor_signed_denial_and_no_store() {
    let denial = SignedDenial {
        body: b"DENY".to_vec(),
        sig: vec![1u8; 64],
    };
    let svc = Arc::new(MockSvc::new());
    svc.set_release(Err(denial.clone()));
    let app = build_router_with_rate(svc, fast_rate());

    let body = canonical_release_body(b"cose", b"snp", &[2u8; 32]);
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/kbs/release")
                .header(header::CONTENT_TYPE, "application/cbor")
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();
    let (status, bytes, headers) = read_body(resp).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let decoded: SignedDenial = ciborium::de::from_reader(bytes.as_slice()).unwrap();
    assert_eq!(decoded, denial);
    assert_canonical(&bytes).unwrap();
    assert_eq!(
        headers
            .get(header::CACHE_CONTROL)
            .map(|h| h.to_str().unwrap()),
        Some("no-store")
    );
}

#[tokio::test]
async fn release_rejects_wrong_content_type_before_service_call() {
    let svc = Arc::new(MockSvc::new());
    let app = build_router_with_rate(svc.clone(), fast_rate());
    let body = canonical_release_body(b"cose", b"snp", &[1u8; 32]);
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/kbs/release")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);
    // MIME check must fail BEFORE body materialization → service never invoked.
    assert!(svc.calls().is_empty());
}

#[tokio::test]
async fn release_accepts_content_type_with_parameters() {
    let svc = Arc::new(MockSvc::new());
    let app = build_router_with_rate(svc, fast_rate());
    let body = canonical_release_body(b"cose", b"snp", &[1u8; 32]);
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/kbs/release")
                .header(header::CONTENT_TYPE, "application/cbor; charset=binary")
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn release_rejects_missing_content_type() {
    let svc = Arc::new(MockSvc::new());
    let app = build_router_with_rate(svc, fast_rate());
    let body = canonical_release_body(b"cose", b"snp", &[1u8; 32]);
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/kbs/release")
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn release_rejects_non_canonical_cbor() {
    let svc = Arc::new(MockSvc::new());
    let app = build_router_with_rate(svc, fast_rate());
    // Unsorted keys → not canonical.
    let v = ciborium::value::Value::Map(vec![
        (
            ciborium::value::Value::Text("snp_report".into()),
            ciborium::value::Value::Bytes(vec![1]),
        ),
        (
            ciborium::value::Value::Text("cose_ticket".into()),
            ciborium::value::Value::Bytes(vec![1]),
        ),
        (
            ciborium::value::Value::Text("kbs_nonce".into()),
            ciborium::value::Value::Bytes(vec![1u8; 32]),
        ),
    ]);
    let mut bytes = Vec::new();
    ciborium::ser::into_writer(&v, &mut bytes).unwrap();
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/kbs/release")
                .header(header::CONTENT_TYPE, "application/cbor")
                .body(Body::from(bytes))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn release_rejects_wrong_nonce_length() {
    let svc = Arc::new(MockSvc::new());
    let app = build_router_with_rate(svc.clone(), fast_rate());
    let body = canonical_release_body(b"cose", b"snp", &[1u8; 31]);
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/kbs/release")
                .header(header::CONTENT_TYPE, "application/cbor")
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    assert!(svc.calls().is_empty());
}

#[tokio::test]
async fn release_rejects_oversized_body() {
    let svc = Arc::new(MockSvc::new());
    let app = build_router_with_rate(svc, fast_rate());
    let big = vec![0u8; MAX_REQUEST_BYTES + 1];
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/kbs/release")
                .header(header::CONTENT_TYPE, "application/cbor")
                .body(Body::from(Bytes::from(big)))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);
}

#[tokio::test]
async fn release_rejects_unknown_fields_in_body() {
    let svc = Arc::new(MockSvc::new());
    let app = build_router_with_rate(svc, fast_rate());
    let v = ciborium::value::Value::Map(vec![
        (
            ciborium::value::Value::Text("cose_ticket".into()),
            ciborium::value::Value::Bytes(vec![1]),
        ),
        (
            ciborium::value::Value::Text("extra".into()),
            ciborium::value::Value::Integer(0.into()),
        ),
        (
            ciborium::value::Value::Text("kbs_nonce".into()),
            ciborium::value::Value::Bytes(vec![1u8; 32]),
        ),
        (
            ciborium::value::Value::Text("snp_report".into()),
            ciborium::value::Value::Bytes(vec![1]),
        ),
    ]);
    let canonical = to_canonical_vec(&v).unwrap();
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/kbs/release")
                .header(header::CONTENT_TYPE, "application/cbor")
                .body(Body::from(canonical))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn release_500_message_does_not_leak_internal_text() {
    // Force a service-layer SignedDenial — that's the protocol path —
    // but here we also assert that bad-request / 500-class messages do
    // not echo back library-derived strings (no `e:` patterns, no path
    // fragments). We use a bad CBOR body to drive the 400 path and
    // confirm the public message is stable.
    let svc = Arc::new(MockSvc::new());
    let app = build_router_with_rate(svc, fast_rate());
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/kbs/release")
                .header(header::CONTENT_TYPE, "application/cbor")
                .body(Body::from(vec![0xff, 0xff, 0xff])) // junk
                .unwrap(),
        )
        .await
        .unwrap();
    let (status, body, _) = read_body(resp).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let text = std::str::from_utf8(&body).unwrap();
    assert_eq!(text, "malformed request");
}

#[tokio::test]
async fn unknown_route_returns_404_with_no_store() {
    let svc = Arc::new(MockSvc::new());
    let app = build_router_with_rate(svc, fast_rate());
    let resp = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/does-not-exist")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let (status, _body, headers) = read_body(resp).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    // The 404 doesn't traverse our handler `ErrorBody` path; the
    // router-level `SetResponseHeaderLayer` is what guarantees no-store
    // here.
    assert_eq!(
        headers
            .get(header::CACHE_CONTROL)
            .map(|h| h.to_str().unwrap()),
        Some("no-store")
    );
}

#[tokio::test]
async fn release_rate_limited_returns_429_with_retry_after() {
    // §13 — release endpoint sheds at its own configured rate. Use a
    // stingy config so the second request is shed deterministically.
    let svc = Arc::new(MockSvc::new());
    let app = build_router_with_rates(
        svc,
        // Nonce limiter: don't care, generous.
        fast_rate(),
        // Release limiter: 1 token, no refill in test window.
        RateConfig {
            refill_per_sec: 0.0001,
            burst: 1,
        },
    );
    let body = canonical_release_body(b"cose", b"snp", &[1u8; 32]);
    let resp1 = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/kbs/release")
                .header(header::CONTENT_TYPE, "application/cbor")
                .body(Body::from(body.clone()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp1.status(), StatusCode::OK);
    let resp2 = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/kbs/release")
                .header(header::CONTENT_TYPE, "application/cbor")
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();
    let (status, _body, headers) = read_body(resp2).await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
    assert!(headers.get(header::RETRY_AFTER).is_some());
}

#[tokio::test]
async fn oversized_413_carries_no_store_header() {
    // The body-limit layer emits its own 413 before our handler runs —
    // verify the router-level `SetResponseHeaderLayer` still injects
    // `Cache-Control: no-store` so the invariant holds for ALL responses.
    let svc = Arc::new(MockSvc::new());
    let app = build_router_with_rate(svc, fast_rate());
    let big = vec![0u8; MAX_REQUEST_BYTES + 1];
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/kbs/release")
                .header(header::CONTENT_TYPE, "application/cbor")
                .body(Body::from(Bytes::from(big)))
                .unwrap(),
        )
        .await
        .unwrap();
    let (status, _body, headers) = read_body(resp).await;
    assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);
    assert_eq!(
        headers
            .get(header::CACHE_CONTROL)
            .map(|h| h.to_str().unwrap()),
        Some("no-store")
    );
}

// ── #322 keepalive route ──────────────────────────────────────────────

fn canonical_keepalive_body(
    vm_id: &str,
    node_id: &[u8; 32],
    snp: &[u8],
    nonce: &[u8; 32],
    epoch: u64,
    expiry_unix: u64,
) -> Vec<u8> {
    let v = ciborium::value::Value::Map(vec![
        (
            ciborium::value::Value::Text("epoch".into()),
            ciborium::value::Value::Integer(epoch.into()),
        ),
        (
            ciborium::value::Value::Text("expiry_unix".into()),
            ciborium::value::Value::Integer(expiry_unix.into()),
        ),
        (
            ciborium::value::Value::Text("kbs_nonce".into()),
            ciborium::value::Value::Bytes(nonce.to_vec()),
        ),
        (
            ciborium::value::Value::Text("node_id".into()),
            ciborium::value::Value::Bytes(node_id.to_vec()),
        ),
        (
            ciborium::value::Value::Text("snp_report".into()),
            ciborium::value::Value::Bytes(snp.to_vec()),
        ),
        (
            ciborium::value::Value::Text("vm_id".into()),
            ciborium::value::Value::Text(vm_id.into()),
        ),
    ]);
    to_canonical_vec(&v).unwrap()
}

#[tokio::test]
async fn keepalive_denied_returns_forbidden() {
    // The default mock returns Err(Replay) from process_keepalive, so a
    // valid-shape request should surface a 403 — denials in the keepalive
    // flow are NOT signed (unlike release), they're a plain HTTP 403.
    let svc = Arc::new(MockSvc::new());
    let router = build_router(svc.clone());
    let body = canonical_keepalive_body(
        "vm-1",
        &[0xBB; 32],
        b"snp-report-bytes",
        &[0x42; 32],
        7,
        1_800_000_900,
    );
    let resp = router
        .oneshot(
            Request::builder()
                .uri("/v1/attest/keepalive")
                .method("POST")
                .header(header::CONTENT_TYPE, "application/cbor")
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();
    let (status, _body, headers) = read_body(resp).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(
        headers
            .get(header::CACHE_CONTROL)
            .map(|h| h.to_str().unwrap()),
        Some("no-store"),
    );
    assert_eq!(svc.calls(), vec!["process_keepalive".to_string()]);
}

#[tokio::test]
async fn keepalive_rejects_wrong_nonce_length() {
    let svc = Arc::new(MockSvc::new());
    let router = build_router(svc.clone());
    // Build a body whose `kbs_nonce` is 31 bytes (one short).
    let v = ciborium::value::Value::Map(vec![
        (
            ciborium::value::Value::Text("epoch".into()),
            ciborium::value::Value::Integer(7u64.into()),
        ),
        (
            ciborium::value::Value::Text("expiry_unix".into()),
            ciborium::value::Value::Integer(1_800_000_900u64.into()),
        ),
        (
            ciborium::value::Value::Text("kbs_nonce".into()),
            ciborium::value::Value::Bytes(vec![0u8; 31]),
        ),
        (
            ciborium::value::Value::Text("node_id".into()),
            ciborium::value::Value::Bytes(vec![0xBB; 32]),
        ),
        (
            ciborium::value::Value::Text("snp_report".into()),
            ciborium::value::Value::Bytes(b"snp".to_vec()),
        ),
        (
            ciborium::value::Value::Text("vm_id".into()),
            ciborium::value::Value::Text("vm-1".into()),
        ),
    ]);
    let body = to_canonical_vec(&v).unwrap();
    let resp = router
        .oneshot(
            Request::builder()
                .uri("/v1/attest/keepalive")
                .method("POST")
                .header(header::CONTENT_TYPE, "application/cbor")
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();
    let (status, _body, _headers) = read_body(resp).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    // The handler should have rejected at the length check, BEFORE
    // touching the service.
    assert!(!svc.calls().contains(&"process_keepalive".to_string()));
}

#[tokio::test]
async fn keepalive_rejects_wrong_content_type() {
    let svc = Arc::new(MockSvc::new());
    let router = build_router(svc.clone());
    let body = canonical_keepalive_body("vm-1", &[0xBB; 32], b"x", &[0x42; 32], 7, 1_800_000_900);
    let resp = router
        .oneshot(
            Request::builder()
                .uri("/v1/attest/keepalive")
                .method("POST")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();
    let (status, _body, _headers) = read_body(resp).await;
    assert_eq!(status, StatusCode::UNSUPPORTED_MEDIA_TYPE);
    assert!(!svc.calls().contains(&"process_keepalive".to_string()));
}

// ── PR-10b-S2b host-attestor enroll route ──────────────────────────────

#[tokio::test]
async fn host_enroll_ok_returns_200_canonical_signed_cert_and_no_store() {
    let cert = sample_signed_cert();
    let svc = Arc::new(MockSvc::new());
    svc.set_host_enroll(Ok(cert.clone()));
    let router = build_router(svc.clone());
    let body = canonical_host_enroll_body(&sample_enrollment_bytes(), &[0x42; 32]);
    let resp = router
        .oneshot(
            Request::builder()
                .uri("/v1/kbs/host-attestor/enroll")
                .method("POST")
                .header(header::CONTENT_TYPE, "application/cbor")
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();
    let (status, bytes, headers) = read_body(resp).await;
    assert_eq!(status, StatusCode::OK);
    // The response is a canonical HostEnrollResponseBody carrying the
    // encoded SignedHostAttestorCert; decode it back and confirm it round
    // trips to the exact cert the service minted.
    assert_canonical(&bytes).unwrap();
    let resp_body: HostEnrollResponseBody = ciborium::de::from_reader(bytes.as_slice()).unwrap();
    let decoded = SignedHostAttestorCert::decode(resp_body.signed_cert.as_ref()).unwrap();
    assert_eq!(decoded, cert);
    assert_eq!(
        headers
            .get(header::CACHE_CONTROL)
            .map(|h| h.to_str().unwrap()),
        Some("no-store")
    );
    assert_eq!(svc.calls(), vec!["process_host_enroll".to_string()]);
}

#[tokio::test]
async fn host_enroll_denied_returns_403() {
    // Any kbs-core verification failure (bad AMD chain, wrong-class
    // measurement, REPORT_DATA mismatch, expiry) surfaces as an Err from
    // the service → generic 403, no cert on the wire.
    let svc = Arc::new(MockSvc::new());
    svc.set_host_enroll(Err(KbsError::Attestation(
        "mock: measurement is Tenant-class".into(),
    )));
    let router = build_router(svc.clone());
    let body = canonical_host_enroll_body(&sample_enrollment_bytes(), &[0x42; 32]);
    let resp = router
        .oneshot(
            Request::builder()
                .uri("/v1/kbs/host-attestor/enroll")
                .method("POST")
                .header(header::CONTENT_TYPE, "application/cbor")
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();
    let (status, body, headers) = read_body(resp).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    // No cert leaked; stable public message; no library detail echoed.
    let text = std::str::from_utf8(&body).unwrap();
    assert_eq!(text, "host-enroll denied");
    assert!(!text.contains("Tenant-class"));
    assert_eq!(
        headers
            .get(header::CACHE_CONTROL)
            .map(|h| h.to_str().unwrap()),
        Some("no-store")
    );
    assert_eq!(svc.calls(), vec!["process_host_enroll".to_string()]);
}

#[tokio::test]
async fn host_enroll_rejects_malformed_inner_enrollment() {
    // Outer envelope is well-formed canonical CBOR, but the inner
    // `enrollment` bytes are not a valid HostEnrollment → 400 BEFORE the
    // service is touched.
    let svc = Arc::new(MockSvc::new());
    let router = build_router(svc.clone());
    let body = canonical_host_enroll_body(b"not-a-valid-enrollment", &[0x42; 32]);
    let resp = router
        .oneshot(
            Request::builder()
                .uri("/v1/kbs/host-attestor/enroll")
                .method("POST")
                .header(header::CONTENT_TYPE, "application/cbor")
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();
    let (status, body, _headers) = read_body(resp).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(std::str::from_utf8(&body).unwrap(), "malformed enrollment");
    assert!(!svc.calls().contains(&"process_host_enroll".to_string()));
}

#[tokio::test]
async fn host_enroll_rejects_wrong_nonce_length() {
    let svc = Arc::new(MockSvc::new());
    let router = build_router(svc.clone());
    // 31-byte nonce (one short).
    let body = canonical_host_enroll_body(&sample_enrollment_bytes(), &[0x42; 31]);
    let resp = router
        .oneshot(
            Request::builder()
                .uri("/v1/kbs/host-attestor/enroll")
                .method("POST")
                .header(header::CONTENT_TYPE, "application/cbor")
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();
    let (status, _body, _headers) = read_body(resp).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(!svc.calls().contains(&"process_host_enroll".to_string()));
}

#[tokio::test]
async fn host_enroll_rejects_non_canonical_outer_cbor() {
    let svc = Arc::new(MockSvc::new());
    let router = build_router(svc.clone());
    // Unsorted keys → not canonical. Canonical order sorts "nonce"
    // (shorter length-prefix) before "enrollment"; writing "enrollment"
    // first is the non-canonical order.
    let v = ciborium::value::Value::Map(vec![
        (
            ciborium::value::Value::Text("enrollment".into()),
            ciborium::value::Value::Bytes(sample_enrollment_bytes()),
        ),
        (
            ciborium::value::Value::Text("nonce".into()),
            ciborium::value::Value::Bytes(vec![0x42; 32]),
        ),
    ]);
    let mut bytes = Vec::new();
    ciborium::ser::into_writer(&v, &mut bytes).unwrap();
    let resp = router
        .oneshot(
            Request::builder()
                .uri("/v1/kbs/host-attestor/enroll")
                .method("POST")
                .header(header::CONTENT_TYPE, "application/cbor")
                .body(Body::from(bytes))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    assert!(!svc.calls().contains(&"process_host_enroll".to_string()));
}

#[tokio::test]
async fn host_enroll_rejects_wrong_content_type() {
    let svc = Arc::new(MockSvc::new());
    let router = build_router(svc.clone());
    let body = canonical_host_enroll_body(&sample_enrollment_bytes(), &[0x42; 32]);
    let resp = router
        .oneshot(
            Request::builder()
                .uri("/v1/kbs/host-attestor/enroll")
                .method("POST")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);
    assert!(!svc.calls().contains(&"process_host_enroll".to_string()));
}

/// CLAIM (auth boundary): the admin `seed-boot-counter` route — the one
/// mutation that can move an anti-rollback counter outside the release
/// path — is served ONLY by `build_admin_router`, i.e. only on the
/// admin listener (ClusterIP-only, mTLS + CiliumNetworkPolicy, no
/// public Ingress). The public release router, which IS internet-facing
/// and takes UNAUTHENTICATED requests from guests, must not serve it.
///
/// This is the whole authentication story for the endpoint: there is no
/// per-request principal check in any admin handler (see
/// `admin_handler.rs` module docs) — the listener is the gate. So the
/// testable form of "requires admin auth" is "is not reachable from the
/// unauthenticated surface".
#[tokio::test]
async fn seed_boot_counter_is_not_served_by_the_public_release_router() {
    let svc = Arc::new(MockSvc::new());
    let app = build_router(svc.clone());
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/admin/vm/vm-1/seed-boot-counter")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(br#"{"counter":99}"#.as_ref()))
                .unwrap(),
        )
        .await
        .unwrap();
    let (status, _, _) = read_body(resp).await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "the public router must not expose any /v1/admin/* mutation"
    );
}

/// Same claim for the sibling admin routes, so a future refactor that
/// merges the two routers fails here rather than silently exposing the
/// lifecycle store to the internet.
#[tokio::test]
async fn no_admin_route_is_served_by_the_public_release_router() {
    let svc = Arc::new(MockSvc::new());
    for uri in [
        "/v1/admin/vm/vm-1/register-vm",
        "/v1/admin/vm/vm-1/activate",
        "/v1/admin/vm/vm-1/seed-boot-counter",
        "/v1/admin/vm/vm-1/seed-keepalive-binding",
        "/v1/admin/allowlist/reload",
    ] {
        let app = build_router(svc.clone());
        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(uri)
                    .header(header::CONTENT_TYPE, "application/cbor")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let (status, _, _) = read_body(resp).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "public router serves {uri}");
    }
}

// ── /v1/kbs/volume-stamp/confirm ────────────────────────────────────────

#[tokio::test]
async fn volume_stamp_confirm_ok_returns_200_canonical_cbor_and_no_store() {
    let svc = Arc::new(MockSvc::new());
    svc.set_volume_stamp_confirm(Ok(3));
    let app = build_router(svc.clone());
    let body = canonical_volume_stamp_confirm_body("vm-1", 3, &[0xAB; 32]);
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/kbs/volume-stamp/confirm")
                .header(header::CONTENT_TYPE, "application/cbor")
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();
    let (status, bytes, headers) = read_body(resp).await;
    assert_eq!(status, StatusCode::OK);
    assert_canonical(&bytes).unwrap();
    let decoded: VolumeStampConfirmResponse = ciborium::de::from_reader(bytes.as_slice()).unwrap();
    assert_eq!(decoded.confirmed, 3);
    assert_eq!(
        headers
            .get(header::CACHE_CONTROL)
            .map(|h| h.to_str().unwrap()),
        Some("no-store")
    );
    assert_eq!(
        svc.calls(),
        vec!["process_volume_stamp_confirm".to_string()]
    );
}

/// CLAIM: a denial (bad/absent token, or a non-`stored + 1` value) is a
/// generic 403 and the presented token is NEVER echoed anywhere in the
/// error body — see the module docs: an unauthenticated confirm is a
/// permanent remote brick, so the response must not leak anything that
/// would help an attacker guess the real token.
#[tokio::test]
async fn volume_stamp_confirm_denied_returns_403_and_never_echoes_the_token() {
    let svc = Arc::new(MockSvc::new());
    svc.set_volume_stamp_confirm(Err(KbsError::Policy(
        "volume-stamp confirm: vm_id=vm-1 value=3 — bad or absent token, fail closed".into(),
    )));
    let app = build_router(svc.clone());
    let token = [0xCDu8; 32];
    let body = canonical_volume_stamp_confirm_body("vm-1", 3, &token);
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/kbs/volume-stamp/confirm")
                .header(header::CONTENT_TYPE, "application/cbor")
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();
    let (status, body, headers) = read_body(resp).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let text = std::str::from_utf8(&body).unwrap();
    assert_eq!(text, "volume-stamp confirm denied");
    assert!(!text.contains("bad or absent token"));
    let hex_token = hex::encode(token);
    assert!(!text.contains(&hex_token));
    assert_eq!(
        headers
            .get(header::CACHE_CONTROL)
            .map(|h| h.to_str().unwrap()),
        Some("no-store")
    );
    assert_eq!(
        svc.calls(),
        vec!["process_volume_stamp_confirm".to_string()]
    );
}

#[tokio::test]
async fn volume_stamp_confirm_rejects_wrong_content_type_before_service_call() {
    let svc = Arc::new(MockSvc::new());
    let app = build_router(svc.clone());
    let body = canonical_volume_stamp_confirm_body("vm-1", 1, &[0x01; 32]);
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/kbs/volume-stamp/confirm")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);
    assert!(svc.calls().is_empty());
}

#[tokio::test]
async fn volume_stamp_confirm_rejects_non_canonical_cbor() {
    let svc = Arc::new(MockSvc::new());
    let app = build_router(svc.clone());
    // Unsorted keys → not canonical.
    let v = ciborium::value::Value::Map(vec![
        (
            ciborium::value::Value::Text("vm_id".into()),
            ciborium::value::Value::Text("vm-1".into()),
        ),
        (
            ciborium::value::Value::Text("token".into()),
            ciborium::value::Value::Bytes(vec![1u8; 32]),
        ),
        (
            ciborium::value::Value::Text("value".into()),
            ciborium::value::Value::Integer(1.into()),
        ),
    ]);
    let mut bytes = Vec::new();
    ciborium::ser::into_writer(&v, &mut bytes).unwrap();
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/kbs/volume-stamp/confirm")
                .header(header::CONTENT_TYPE, "application/cbor")
                .body(Body::from(bytes))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    assert!(svc.calls().is_empty());
}

#[tokio::test]
async fn volume_stamp_confirm_rejects_unknown_fields_in_body() {
    let svc = Arc::new(MockSvc::new());
    let app = build_router(svc.clone());
    let v = ciborium::value::Value::Map(vec![
        (
            ciborium::value::Value::Text("extra".into()),
            ciborium::value::Value::Integer(0.into()),
        ),
        (
            ciborium::value::Value::Text("token".into()),
            ciborium::value::Value::Bytes(vec![1u8; 32]),
        ),
        (
            ciborium::value::Value::Text("value".into()),
            ciborium::value::Value::Integer(1.into()),
        ),
        (
            ciborium::value::Value::Text("vm_id".into()),
            ciborium::value::Value::Text("vm-1".into()),
        ),
    ]);
    let canonical = to_canonical_vec(&v).unwrap();
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/kbs/volume-stamp/confirm")
                .header(header::CONTENT_TYPE, "application/cbor")
                .body(Body::from(canonical))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    assert!(svc.calls().is_empty());
}

#[tokio::test]
async fn volume_stamp_confirm_rejects_oversized_body() {
    let svc = Arc::new(MockSvc::new());
    let app = build_router(svc);
    let big = vec![0u8; MAX_REQUEST_BYTES + 1];
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/kbs/volume-stamp/confirm")
                .header(header::CONTENT_TYPE, "application/cbor")
                .body(Body::from(Bytes::from(big)))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);
}

/// The recovery for a LOST miner-side boot counter
/// (`kbs_core::boot_counter::arm_resync`) must be reachable ONLY from
/// the mTLS admin listener.
///
/// This is the property that makes the recovery safe to have at all.
/// The miner is the transport for every guest-facing route AND the
/// holder of the state disk whose loss the arm exists to repair — if it
/// could arm its own tenants, it could re-baseline a counter whenever
/// the CAS caught it, and "an operator decided this host really did lose
/// its disk" would become "the host asserts it lost its disk".
///
/// Adding a route to the wrong router is a one-line mistake with no
/// compile-time signal, so it is pinned rather than inspected.
#[tokio::test]
async fn guest_router_does_not_expose_the_admin_boot_counter_resync_arm() {
    let svc = Arc::new(MockSvc::new());
    let app = build_router(svc.clone());
    for uri in [
        "/v1/admin/vm/vm-1/arm-boot-counter-resync",
        "/v1/kbs/vm/vm-1/arm-boot-counter-resync",
        "/v1/kbs/boot-counter/resync",
    ] {
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(uri)
                    .header(header::CONTENT_TYPE, "application/cbor")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::NOT_FOUND,
            "{uri} must not be routable from the guest-facing listener — a miner reaching it \
             could re-baseline its own tenants' anti-rollback counters"
        );
    }
}

/// The ADMIN-only suppression reset must NOT be reachable on the
/// guest-facing router.
///
/// `kbs_core::volume_stamp`'s bound is only meaningful if a miner cannot
/// clear its own suppression counter. The miner controls the transport
/// for everything on THIS router (it relays `/v1/kbs/release` and
/// `/v1/kbs/volume-stamp/confirm` for the guest), so the reset lives on
/// the mTLS admin listener — `build_admin_router`, served exclusively
/// through `kbs_server::admin_tls`, which drops any connection that
/// fails client-cert verification before the router ever sees it.
///
/// Pinned as a test rather than left to inspection: adding a route to
/// the wrong router is a one-line mistake with no compile-time signal.
#[tokio::test]
async fn guest_router_does_not_expose_the_admin_suppression_reset() {
    let svc = Arc::new(MockSvc::new());
    let app = build_router(svc.clone());
    for uri in [
        "/v1/admin/vm/vm-1/reset-volume-stamp-suppression",
        "/v1/kbs/vm/vm-1/reset-volume-stamp-suppression",
        "/v1/kbs/volume-stamp/reset",
    ] {
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(uri)
                    .header(header::CONTENT_TYPE, "application/cbor")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::NOT_FOUND,
            "{uri} must not be routable from the guest-facing listener — a miner reaching it \
             could clear its own suppression counter and void the anti-rollback bound"
        );
    }
}

#[tokio::test]
async fn guest_router_does_not_expose_any_rollback_route() {
    // The authorized rollback (A2) is the one path that admits a
    // rewound boot. A miner reaching ANY of these routes on the
    // guest-facing listener could arm, read or disarm its own tenants'
    // rollbacks, so each must 404 here (they exist ONLY on the mTLS
    // admin router).
    let svc = Arc::new(MockSvc::new());
    let app = build_router(svc.clone());
    for (method, uri) in [
        ("POST", "/v1/admin/vm/vm-1/rollback-checkpoint"),
        ("POST", "/v1/admin/vm/vm-1/authorize-rollback"),
        ("DELETE", "/v1/admin/vm/vm-1/authorize-rollback/r-1"),
        ("GET", "/v1/admin/vm/vm-1/rollback"),
        ("POST", "/v1/kbs/vm/vm-1/authorize-rollback"),
        ("POST", "/v1/kbs/authorize-rollback"),
    ] {
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(method)
                    .uri(uri)
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from("{}"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::NOT_FOUND,
            "{method} {uri} must not be routable from the guest-facing listener"
        );
    }
}

#[tokio::test]
async fn guest_router_does_not_expose_the_admin_volume_stamp_report() {
    // The READ side of the same gate. `GET /v1/admin/volume-stamp` is a
    // per-tenant operational readout — which VMs exist, how many
    // releases each has taken, and precisely which of them are one
    // release away from being refused once the gate is armed. On the
    // public-Ingress release listener that is a targeting list handed
    // to the exact party (the miner) the gate exists to constrain.
    let svc = Arc::new(MockSvc::new());
    let app = build_router(svc.clone());
    for uri in [
        "/v1/admin/volume-stamp",
        "/v1/admin/volume-stamp?bound=3",
        "/v1/kbs/volume-stamp",
        "/v1/kbs/volume-stamp/report",
        // Same reasoning for the posture readout: on the public-Ingress
        // release listener, "which of this KBS's gates are OFF" is a
        // shopping list handed to the miner the gates constrain.
        "/v1/admin/config",
        "/v1/kbs/config",
    ] {
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri(uri)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::NOT_FOUND,
            "{uri} must not be routable from the guest-facing listener"
        );
    }
}

// ── stamp protocol v2: the v2 claim is ONLY in the SNP-signed report ──

fn release_request(body: Vec<u8>, header_claim: bool) -> Request<Body> {
    let mut b = Request::builder()
        .method("POST")
        .uri("/v1/kbs/release")
        .header(header::CONTENT_TYPE, "application/cbor");
    if header_claim {
        b = b
            .header("x-hippius-guest-stamp-protocol", "2")
            .header("x-hippius-stamp-protocol", "2");
    }
    b.body(Body::from(body)).unwrap()
}

/// CLAIM (invariant 2): a miner adding a stamp-protocol claim to the
/// release BODY is refused before the service is reached — the body is
/// `deny_unknown_fields`, so no unmeasured field can carry a v2 claim.
#[tokio::test]
async fn a_stamp_protocol_claim_in_the_release_body_never_reaches_the_service() {
    for field in [
        "guest_stamp_protocol",
        "stamp_protocol",
        "volume_stamp_transition",
    ] {
        let svc = Arc::new(MockSvc::new());
        let app = build_router_with_rate(svc.clone(), fast_rate());
        let v = ciborium::value::Value::Map(vec![
            (
                ciborium::value::Value::Text("cose_ticket".into()),
                ciborium::value::Value::Bytes(b"cose".to_vec()),
            ),
            (
                ciborium::value::Value::Text("kbs_nonce".into()),
                ciborium::value::Value::Bytes(vec![1u8; 32]),
            ),
            (
                ciborium::value::Value::Text("snp_report".into()),
                ciborium::value::Value::Bytes(b"snp".to_vec()),
            ),
            (
                ciborium::value::Value::Text(field.into()),
                ciborium::value::Value::Integer(2.into()),
            ),
        ]);
        let resp = app
            .oneshot(release_request(to_canonical_vec(&v).unwrap(), false))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST, "{field}");
        assert!(svc.calls().is_empty(), "{field}: the service was reached");
    }
}

/// CLAIM (invariant 2): a stamp-protocol HEADER changes nothing — the
/// service receives exactly the same inputs with or without it (the
/// report, the nonce, the ticket, the counter: the protocol is read from
/// the report's signed REPORT_DATA and from nowhere else).
#[tokio::test]
async fn a_stamp_protocol_header_does_not_change_what_the_service_sees() {
    let mut seen = Vec::new();
    for header_claim in [false, true] {
        let svc = Arc::new(MockSvc::new());
        let app = build_router_with_rate(svc.clone(), fast_rate());
        let body = canonical_release_body(b"cose", b"snp", &[1u8; 32]);
        let resp = app
            .oneshot(release_request(body, header_claim))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        seen.push(svc.release_args.lock().unwrap().clone());
    }
    assert_eq!(seen[0], seen[1]);
    assert_eq!(seen[0].len(), 1);
}

/// A v2 confirm (a `timeline_id`) takes the timeline-bound CAS; a v1
/// one the plain CAS; a malformed timeline is refused before either.
#[tokio::test]
async fn a_confirm_naming_a_timeline_takes_the_timeline_cas() {
    let body = |timeline: Option<Vec<u8>>| {
        let mut e = vec![
            (
                ciborium::value::Value::Text("token".into()),
                ciborium::value::Value::Bytes(vec![7u8; 32]),
            ),
            (
                ciborium::value::Value::Text("value".into()),
                ciborium::value::Value::Integer(5.into()),
            ),
            (
                ciborium::value::Value::Text("vm_id".into()),
                ciborium::value::Value::Text("vm-1".into()),
            ),
        ];
        if let Some(t) = timeline {
            e.push((
                ciborium::value::Value::Text("timeline_id".into()),
                ciborium::value::Value::Bytes(t),
            ));
        }
        to_canonical_vec(&ciborium::value::Value::Map(e)).unwrap()
    };
    for (t, status, calls) in [
        (
            Some(vec![0xab; 32]),
            StatusCode::OK,
            vec!["process_volume_stamp_confirm_timeline:ab".to_string()],
        ),
        (
            None,
            StatusCode::OK,
            vec!["process_volume_stamp_confirm".to_string()],
        ),
        (Some(vec![0xab; 31]), StatusCode::BAD_REQUEST, vec![]),
    ] {
        let svc = Arc::new(MockSvc::new());
        svc.set_volume_stamp_confirm(Ok(5));
        let app = build_router_with_rate(svc.clone(), fast_rate());
        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/kbs/volume-stamp/confirm")
                    .header(header::CONTENT_TYPE, "application/cbor")
                    .body(Body::from(body(t.clone())))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), status, "{t:?}");
        assert_eq!(svc.calls(), calls, "{t:?}");
    }
}
