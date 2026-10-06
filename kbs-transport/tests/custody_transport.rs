//! Transport shell of the custody routes: status mapping, CBOR framing,
//! the disabled default. The custody LOGIC is tested in
//! `kbs_core::custody`.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use axum::body::Body;
use axum::http::{header, Request, StatusCode};
use hippius_types::custody::{
    decode_canonical, encode_canonical, CustodyBindRequest, CustodyRekeyRequest,
    CustodyRenewRequest, SignedCustodyVerdict,
};
use hippius_types::host_attestor::{HostEnrollment, SignedHostAttestorCert};
use hippius_types::release::{SignedDenial, SignedResponse};
use http_body_util::BodyExt;
use kbs_core::custody::CustodyReply;
use kbs_core::error::{KbsError, Result};
use kbs_transport::{build_router, KbsService, NONCE_LEN};
use std::sync::{Arc, Mutex};
use tower::ServiceExt;

/// A service with NO custody override — the trait default.
struct NoCustody;

/// A service whose custody methods return a scripted reply.
struct Scripted(Mutex<Option<CustodyReply>>, Mutex<Vec<&'static str>>);

macro_rules! base_methods {
    () => {
        fn issue_nonce(&self, _now: u64) -> Result<[u8; NONCE_LEN]> {
            Err(KbsError::Replay)
        }
        fn process_release(
            &self,
            _c: &[u8],
            _s: &[u8],
            _n: &[u8; NONCE_LEN],
            _now: u64,
            _b: Option<u64>,
        ) -> core::result::Result<SignedResponse, SignedDenial> {
            Err(SignedDenial {
                body: vec![],
                sig: vec![],
            })
        }
        fn process_keepalive(
            &self,
            _v: &str,
            _n: &[u8; NONCE_LEN],
            _s: &[u8],
            _k: &[u8; NONCE_LEN],
            _e: u64,
            _x: u64,
            _r: Option<&hippius_types::live_attestation::GuestResources>,
            _c: Option<&hippius_types::live_attestation::GuestComponents>,
            _now: u64,
        ) -> Result<hippius_types::live_attestation::SignedLiveAttestation> {
            Err(KbsError::Replay)
        }
        fn process_host_enroll(
            &self,
            _e: &HostEnrollment,
            _n: &[u8; NONCE_LEN],
            _now: u64,
        ) -> Result<SignedHostAttestorCert> {
            Err(KbsError::Replay)
        }
        fn process_volume_stamp_confirm(&self, _v: &str, _x: u64, _t: &[u8]) -> Result<u64> {
            Err(KbsError::Replay)
        }
    };
}

impl KbsService for NoCustody {
    base_methods!();
}

impl KbsService for Scripted {
    base_methods!();
    fn process_custody_bind(&self, _r: &CustodyBindRequest, _n: u64) -> CustodyReply {
        self.1.lock().unwrap().push("bind");
        self.0.lock().unwrap().clone().unwrap()
    }
    fn process_custody_renew(&self, _r: &CustodyRenewRequest, _n: u64) -> CustodyReply {
        self.1.lock().unwrap().push("renew");
        self.0.lock().unwrap().clone().unwrap()
    }
    fn process_custody_rekey(&self, _r: &CustodyRekeyRequest, _n: u64) -> CustodyReply {
        self.1.lock().unwrap().push("rekey");
        self.0.lock().unwrap().clone().unwrap()
    }
}

fn body_for(path: &str) -> Vec<u8> {
    match path {
        "/v1/kbs/custody/bind" => encode_canonical(&CustodyBindRequest {
            body: vec![1],
            lifecycle_sig: vec![2; 64],
        })
        .unwrap(),
        _ => renew_body(),
    }
}

fn renew_body() -> Vec<u8> {
    encode_canonical(&CustodyRenewRequest {
        body: vec![1, 2, 3],
        sig: vec![4; 64],
    })
    .unwrap()
}

async fn post(
    router: axum::Router,
    path: &str,
    body: Vec<u8>,
) -> (StatusCode, Vec<u8>, Option<String>) {
    let resp = router
        .oneshot(
            Request::post(path)
                .header(header::CONTENT_TYPE, "application/cbor")
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = resp.status();
    let cc = resp
        .headers()
        .get(header::CACHE_CONTROL)
        .map(|v| v.to_str().unwrap().to_string());
    let bytes = resp
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes()
        .to_vec();
    (status, bytes, cc)
}

#[tokio::test]
async fn custody_routes_are_disabled_by_default() {
    for path in [
        "/v1/kbs/custody/bind",
        "/v1/kbs/custody/renew",
        "/v1/kbs/custody/rekey",
    ] {
        let (status, body, _) = post(build_router(Arc::new(NoCustody)), path, body_for(path)).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{path}");
        assert_eq!(body, b"custody-disabled");
    }
}

#[tokio::test]
async fn a_verdict_is_a_200_cbor_body_and_a_retry_an_unsigned_status() {
    let verdict = SignedCustodyVerdict {
        body: vec![0xa0],
        kid: b"kid".to_vec(),
        sig: vec![7; 64],
    };
    let svc = Arc::new(Scripted(
        Mutex::new(Some(CustodyReply::Verdict(verdict.clone()))),
        Mutex::new(vec![]),
    ));
    let (status, body, cc) = post(
        build_router(Arc::clone(&svc)),
        "/v1/kbs/custody/renew",
        renew_body(),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(cc.as_deref(), Some("no-store"));
    let back: SignedCustodyVerdict = decode_canonical(&body).unwrap();
    assert_eq!(back, verdict);

    *svc.0.lock().unwrap() = Some(CustodyReply::Retry {
        status: 503,
        reason: "rebind-required",
    });
    let (status, body, _) = post(
        build_router(Arc::clone(&svc)),
        "/v1/kbs/custody/renew",
        renew_body(),
    )
    .await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(body, b"rebind-required");
    assert_eq!(*svc.1.lock().unwrap(), vec!["renew", "renew"]);
}

#[tokio::test]
async fn each_path_reaches_its_own_method() {
    let svc = Arc::new(Scripted(
        Mutex::new(Some(CustodyReply::Retry {
            status: 503,
            reason: "unavailable",
        })),
        Mutex::new(vec![]),
    ));
    for path in [
        "/v1/kbs/custody/bind",
        "/v1/kbs/custody/renew",
        "/v1/kbs/custody/rekey",
    ] {
        let body = match path {
            "/v1/kbs/custody/bind" => encode_canonical(&CustodyBindRequest {
                body: vec![1],
                lifecycle_sig: vec![2; 64],
            })
            .unwrap(),
            _ => renew_body(),
        };
        post(build_router(Arc::clone(&svc)), path, body).await;
    }
    assert_eq!(*svc.1.lock().unwrap(), vec!["bind", "renew", "rekey"]);
}

#[tokio::test]
async fn a_non_canonical_or_wrong_type_body_is_a_400_without_reaching_the_service() {
    let svc = Arc::new(Scripted(Mutex::new(None), Mutex::new(vec![])));
    let mut noncanon = Vec::new();
    ciborium::ser::into_writer(
        &CustodyRenewRequest {
            body: vec![1],
            sig: vec![2],
        },
        &mut noncanon,
    )
    .unwrap();
    // `serde` emits `body` before `sig` — canonical order too for these
    // two keys, so corrupt it with a trailing byte instead.
    noncanon.push(0);
    for body in [noncanon, vec![0xff, 0x00]] {
        let (status, _, _) = post(
            build_router(Arc::clone(&svc)),
            "/v1/kbs/custody/renew",
            body,
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }
    assert!(svc.1.lock().unwrap().is_empty());
}
