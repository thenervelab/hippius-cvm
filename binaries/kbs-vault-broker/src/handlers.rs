//! axum transport — `/v1/broker/challenge` + `/v1/broker/redeem`.
//!
//! Both endpoints take + return canonical-CBOR
//! (`hippius_types::vault_broker`). Errors map to the broker's
//! closed-vocabulary HTTP status + reason; no secret (the minted token)
//! is ever put in an error.

use std::sync::Arc;

use crate::redeem::SelfReportVerifier;
use axum::body::Bytes;
use axum::extract::State;
use axum::http::{header, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use axum::Router;
use hippius_types::vault_broker::{
    ChallengeRequest, ChallengeResponse, RedeemRequest, RedeemResponse,
};
use kbs_core::snp::LaunchPolicy;

use crate::error::BrokerError;
use crate::redeem::{redeem, ChallengeStore, KbsMeasurementAllowlist, VaultTokenMinter};

/// Hard cap on a request body (the SNP report dominates; 16 KiB is
/// generous + bounded).
const MAX_BODY: usize = 16 * 1024;

pub struct BrokerState {
    pub verifier: Box<dyn SelfReportVerifier + Send + Sync>,
    pub challenges: Box<dyn ChallengeStore>,
    pub allowlist: Box<dyn KbsMeasurementAllowlist>,
    pub minter: Box<dyn VaultTokenMinter>,
    pub policy: LaunchPolicy,
    /// Injected clock — `fn() -> u64` Unix seconds. Real binary passes
    /// the system clock; tests pass a fixed stamp.
    pub now_unix: fn() -> u64,
}

pub fn router(state: Arc<BrokerState>) -> Router {
    Router::new()
        .route("/v1/broker/challenge", post(challenge))
        .route("/v1/broker/redeem", post(redeem_handler))
        .route("/healthz", axum::routing::get(|| async { "ok" }))
        .with_state(state)
}

fn cbor(body: Vec<u8>) -> Response {
    let mut resp = (StatusCode::OK, body).into_response();
    resp.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/cbor"),
    );
    resp
}

fn err_response(e: &BrokerError) -> Response {
    let status = StatusCode::from_u16(e.http_status()).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    // Reason only — never the inner classifier detail to the peer (it
    // can carry path/identifier context). The full error is logged.
    eprintln!("kbs-vault-broker: deny {} — {e}", e.reason());
    (status, e.reason()).into_response()
}

async fn challenge(State(state): State<Arc<BrokerState>>, body: Bytes) -> Response {
    if body.len() > MAX_BODY {
        return err_response(&BrokerError::BadRequest("body too large".into()));
    }
    let req = match ChallengeRequest::decode(&body) {
        Ok(r) => r,
        Err(e) => return err_response(&BrokerError::BadRequest(format!("{e}"))),
    };
    let now = (state.now_unix)();
    match state.challenges.issue(&req.scope, now) {
        Ok((nonce, expiry_unix)) => {
            let resp = ChallengeResponse { nonce, expiry_unix };
            match resp.canonical() {
                Ok(bytes) => cbor(bytes),
                Err(e) => err_response(&BrokerError::Config(format!("encode: {e}"))),
            }
        }
        Err(e) => err_response(&e),
    }
}

async fn redeem_handler(State(state): State<Arc<BrokerState>>, body: Bytes) -> Response {
    if body.len() > MAX_BODY {
        return err_response(&BrokerError::BadRequest("body too large".into()));
    }
    let req = match RedeemRequest::decode(&body) {
        Ok(r) => r,
        Err(e) => return err_response(&BrokerError::BadRequest(format!("{e}"))),
    };
    let now = (state.now_unix)();
    let result: Result<RedeemResponse, BrokerError> = redeem(
        &req,
        state.verifier.as_ref(),
        state.challenges.as_ref(),
        state.allowlist.as_ref(),
        &state.policy,
        state.minter.as_ref(),
        now,
    );
    match result {
        Ok(resp) => match resp.canonical() {
            Ok(bytes) => cbor(bytes),
            Err(e) => err_response(&BrokerError::Config(format!("encode: {e}"))),
        },
        Err(e) => err_response(&e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::allowlist::FixedMeasurementAllowlist;
    use axum::body::{to_bytes, Body};
    use axum::http::Request;
    use hippius_types::vault_broker::BrokerScope;
    use kbs_core::error::{KbsError, Result as KbsResult};
    use kbs_core::snp::VerifiedReport;
    use std::sync::Mutex;
    use tower::ServiceExt;
    use zeroize::Zeroizing;

    const NONCE: [u8; 32] = [7u8; 32];
    const PUBKEY: [u8; 32] = [9u8; 32];

    fn scope() -> BrokerScope {
        BrokerScope {
            vm_id: "vm-1".into(),
            luks_path: "hippius-compute/kbs/tenants/vm-1/luks-kek".into(),
            luks_version: 1,
            userdata_path: "hippius-compute/kbs/tenants/vm-1/userdata".into(),
            userdata_version: 1,
            lifecycle_path: None,
            lifecycle_version: None,
        }
    }

    /// Challenge store that always issues + accepts the FIXED `NONCE`
    /// (scope-checked, single-use per instance) — lets a handler test
    /// drive challenge→redeem deterministically.
    struct FixedNonce {
        spent: Mutex<bool>,
    }
    impl ChallengeStore for FixedNonce {
        fn issue(&self, _s: &BrokerScope, now: u64) -> Result<([u8; 32], u64), BrokerError> {
            Ok((NONCE, now + 30))
        }
        fn consume(&self, nonce: &[u8; 32], s: &BrokerScope, _now: u64) -> Result<(), BrokerError> {
            if nonce != &NONCE || s != &scope() {
                return Err(BrokerError::Challenge("mismatch".into()));
            }
            let mut spent = self.spent.lock().unwrap();
            if *spent {
                return Err(BrokerError::Challenge("spent".into()));
            }
            *spent = true;
            Ok(())
        }
    }

    /// Verifier whose report binds `NONCE ‖ PUBKEY` + an allowlisted
    /// measurement.
    struct BoundVerifier;
    impl SelfReportVerifier for BoundVerifier {
        fn verify(&self, _r: &[u8], _vek: &[u8]) -> KbsResult<VerifiedReport> {
            let mut rd = [0u8; 64];
            rd[..32].copy_from_slice(&NONCE);
            rd[32..].copy_from_slice(&PUBKEY);
            Ok(VerifiedReport {
                measurement: [0xAB; 48],
                report_data: rd,
                tcb: 10,
                policy: 0,
                chip_id: [1; 64],
                chain_pem: Vec::new(),
            })
        }
    }
    struct DenyVerifier;
    impl SelfReportVerifier for DenyVerifier {
        fn verify(&self, _r: &[u8], _vek: &[u8]) -> KbsResult<VerifiedReport> {
            Err(KbsError::Attestation("denied".into()))
        }
    }

    struct Minter;
    impl VaultTokenMinter for Minter {
        fn mint_scoped(
            &self,
            _s: &BrokerScope,
            now: u64,
        ) -> Result<(Zeroizing<Vec<u8>>, u64), BrokerError> {
            Ok((Zeroizing::new(b"hvs.tok".to_vec()), now + 60))
        }
    }

    fn state(verifier: Box<dyn SelfReportVerifier + Send + Sync>) -> Arc<BrokerState> {
        Arc::new(BrokerState {
            verifier,
            challenges: Box::new(FixedNonce {
                spent: Mutex::new(false),
            }),
            allowlist: Box::new(FixedMeasurementAllowlist::new([[0xABu8; 48]])),
            minter: Box::new(Minter),
            policy: LaunchPolicy {
                min_tcb: 5,
                required_bits: 0,
                allowed_mask: 0,
            },
            now_unix: || 1000,
        })
    }

    async fn post(st: Arc<BrokerState>, path: &str, body: Vec<u8>) -> Response {
        router(st)
            .oneshot(Request::post(path).body(Body::from(body)).unwrap())
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn challenge_returns_fixed_nonce() {
        let body = ChallengeRequest { scope: scope() }.canonical().unwrap();
        let resp = post(state(Box::new(BoundVerifier)), "/v1/broker/challenge", body).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let bytes = to_bytes(resp.into_body(), MAX_BODY).await.unwrap();
        let ch = ChallengeResponse::decode(&bytes).unwrap();
        assert_eq!(ch.nonce, NONCE);
    }

    #[tokio::test]
    async fn redeem_happy_path_mints_token() {
        let body = RedeemRequest {
            scope: scope(),
            challenge_nonce: NONCE,
            auth_pubkey: PUBKEY,
            snp_report: vec![0u8; 1184],
            vek_der: Vec::new(),
        }
        .canonical()
        .unwrap();
        let resp = post(state(Box::new(BoundVerifier)), "/v1/broker/redeem", body).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let bytes = to_bytes(resp.into_body(), MAX_BODY).await.unwrap();
        let rr = RedeemResponse::decode(&bytes).unwrap();
        assert_eq!(rr.vault_token, b"hvs.tok");
    }

    #[tokio::test]
    async fn redeem_unknown_nonce_is_401() {
        let body = RedeemRequest {
            scope: scope(),
            challenge_nonce: [0u8; 32],
            auth_pubkey: PUBKEY,
            snp_report: vec![0u8; 1184],
            vek_der: Vec::new(),
        }
        .canonical()
        .unwrap();
        let resp = post(state(Box::new(BoundVerifier)), "/v1/broker/redeem", body).await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn redeem_bad_chain_is_403() {
        let body = RedeemRequest {
            scope: scope(),
            challenge_nonce: NONCE,
            auth_pubkey: PUBKEY,
            snp_report: vec![0u8; 1184],
            vek_der: Vec::new(),
        }
        .canonical()
        .unwrap();
        let resp = post(state(Box::new(DenyVerifier)), "/v1/broker/redeem", body).await;
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn malformed_body_is_400() {
        let resp = post(
            state(Box::new(BoundVerifier)),
            "/v1/broker/challenge",
            vec![0xFF, 0xFF],
        )
        .await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }
}
