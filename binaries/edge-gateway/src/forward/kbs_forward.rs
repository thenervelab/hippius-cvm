//! `ReqwestForwardClient` — the production [`ForwardClient`]
//! (PR-H8, §H phase 2).
//!
//! One `reqwest` client serves both inner-plane destinations (the KBS
//! and vali). It is built once at boot from the
//! [`ForwardConfig`](crate::config::ForwardConfig) base URLs and
//! shared (behind an `Arc`) by every miner-router handler.
//!
//! ## Why one client, not two
//!
//! `reqwest::Client` is an `Arc`-backed connection-pool handle —
//! cheap to clone, designed to be shared. A second client would
//! double the pool with no benefit. The KBS-vs-vali routing lives in
//! the [`ForwardClient`] method the router picks, not in the client
//! identity; the per-destination *path* constants live in
//! [`super::kbs_forward`] (this file) and [`super::vali_forward`].
//!
//! ## Transport posture (see [`super`] module docs)
//!
//! - `rustls` TLS, **TLS 1.3 minimum** — no native-tls, matching
//!   `agent-initramfs`.
//! - `connect_timeout` 5 s, whole-request `timeout` 30 s — the §20
//!   slow-loris bounds, identical to the agent's KBS client.
//! - No redirect following (the inner endpoints are exact), no proxy.
//! - The forward leg is plaintext-or-TLS as the operator's endpoint
//!   dictates; there is **no mTLS** — the Cilium NetworkPolicy is the
//!   who-calls-who control.
//!
//! ## Opaque byte relay
//!
//! Every `forward_*` method POSTs the [`ValidatedEnvelope`]'s body
//! bytes **verbatim** with `content-type: application/cbor` and reads
//! the upstream response body back (hard-capped by
//! [`MAX_ENVELOPE_BYTES`]). Nothing is decoded, re-encoded, or logged
//! as bytes — only a body-length + status classifier.

use super::vali_forward;
use super::{ForwardClient, ForwardError, ForwardResponse, MAX_ENVELOPE_BYTES};
use crate::mtls::PeerId;
use crate::stages::envelope::ValidatedEnvelope;
use async_trait::async_trait;
use std::time::Duration;

/// `content-type` every forwarded body carries — canonical CBOR. The
/// inner endpoints (`kbs-server`, vali) speak this on the §9 wire.
const CONTENT_TYPE_CBOR: &str = "application/cbor";

/// KBS release endpoint path — appended to the configured KBS base
/// URL. `kbs-server` exposes `POST /v1/kbs/release` (confirmed
/// against `binaries/agent-initramfs/src/stages/kbs_client.rs`,
/// which is the other client of this exact route).
const KBS_RELEASE_PATH: &str = "/v1/kbs/release";

/// KBS host-attestor enroll endpoint path (PR-10b-S2b) — appended to the
/// configured KBS base URL. `kbs-server` exposes
/// `POST /v1/kbs/host-attestor/enroll`, which mints a
/// `SignedHostAttestorCert` from a `{enrollment, nonce}` body.
const KBS_HOST_ENROLL_PATH: &str = "/v1/kbs/host-attestor/enroll";

/// Byte offset of `REPORT_DATA` inside a SEV-SNP attestation report (the
/// AMD ABI ATTESTATION_REPORT layout). `REPORT_DATA` is 64 bytes; the
/// blackbox host-attestor folds the vali-minted single-use nonce into its
/// FIRST 32 bytes (`REPORT_DATA[0..32]`), and the SHA-256 identity binding
/// into `[32..64]` (see `hippius_types::report_data::host_attestor`). This
/// offset is cross-checked by `agent-host-attestor`'s `platform.rs`, whose
/// sibling fields land at their own fixed offsets (measurement `0x90`,
/// reported_tcb `0x180`, chip_id `0x1A0`).
const REPORT_DATA_OFFSET: usize = 0x50;

/// Length of the vali-minted single-use enrollment nonce.
const HOST_ENROLL_NONCE_LEN: usize = 32;

/// Strict connect timeout — a peer slower than this to complete
/// TCP+TLS is treated as unreachable (§20 slow-loris bound on
/// connection setup).
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

/// Strict whole-request timeout (send + upstream work + response
/// read). Bounds an upstream that dribbles the body.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// Production [`ForwardClient`]: a `reqwest` client plus the two
/// resolved base URLs.
pub struct ReqwestForwardClient {
    client: reqwest::Client,
    /// Base URL of the in-cluster KBS server.
    kbs_base: String,
    /// Base URL of the in-cluster vali service.
    vali_base: String,
    /// Bearer token for vali's JSON telemetry-ingest path (served
    /// receipts). vali pins `ServiceTokenAuthentication` on the JSON
    /// wrapper (unlike the token-exempt raw-CBOR heartbeat path), so
    /// `post_json` stamps `Authorization: Bearer <token>`. Sourced from
    /// a k8s Secret via env — NEVER the config file. `None` ⇒ no header
    /// (a mis-provisioned deployment then gets vali's 401, surfaced as a
    /// 502 to the miner, rather than silently dropping the receipt).
    vali_ingest_token: Option<String>,
}

impl ReqwestForwardClient {
    /// Build the client from the configured base URLs.
    ///
    /// `Err(ForwardError::ClientBuild)` only on a `reqwest` builder
    /// failure (a broken TLS backend, etc.) — surfaced so `main` can
    /// fail-closed at boot rather than discover it on the first
    /// relayed envelope.
    pub fn new(
        kbs_base: impl Into<String>,
        vali_base: impl Into<String>,
        vali_ingest_token: Option<String>,
    ) -> Result<Self, ForwardError> {
        let client = reqwest::Client::builder()
            // `rustls`, TLS 1.3 floor — no native-tls. The forward
            // leg is in-cluster but still negotiates a modern
            // transport when the endpoint is `https://`.
            .use_rustls_tls()
            .min_tls_version(reqwest::tls::Version::TLS_1_3)
            .connect_timeout(CONNECT_TIMEOUT)
            .timeout(REQUEST_TIMEOUT)
            .redirect(reqwest::redirect::Policy::none())
            .no_proxy()
            .build()
            .map_err(|_| ForwardError::ClientBuild)?;
        Ok(Self {
            client,
            kbs_base: kbs_base.into(),
            vali_base: vali_base.into(),
            vali_ingest_token: vali_ingest_token.filter(|t| !t.is_empty()),
        })
    }

    /// Build the `content-type: application/cbor` POST request.
    ///
    /// When `peer` is `Some`, the connection's mTLS [`PeerId`] is
    /// stamped as the [`vali_forward::HEARTBEAT_PEER_ID_HEADER`] header
    /// — the heartbeat path uses this so vali can resolve the miner
    /// (see [`vali_forward`]); every other kind passes `None`. Split
    /// out from [`post_cbor`](Self::post_cbor) so the header wiring is
    /// unit-testable without a live upstream.
    fn build_cbor_request(
        &self,
        url: &str,
        body: &[u8],
        peer: Option<&PeerId>,
    ) -> Result<reqwest::Request, ForwardError> {
        let mut builder = self
            .client
            .post(url)
            .header(reqwest::header::CONTENT_TYPE, CONTENT_TYPE_CBOR)
            .body(body.to_vec());
        if let Some(peer) = peer {
            builder = builder.header(vali_forward::HEARTBEAT_PEER_ID_HEADER, peer.as_str());
        }
        // A builder error here is a malformed header value — a `PeerId`
        // that is not a valid HTTP header value cannot happen for a
        // CA-issued cert SAN, but fail closed (treated as transport)
        // rather than relay a request missing the identity header.
        builder.build().map_err(|_| ForwardError::Transport)
    }

    /// POST `body` to `url` with `content-type: application/cbor` and
    /// read the response — the single opaque-relay primitive every
    /// `forward_*` method runs through. `peer` is `Some` only for the
    /// heartbeat path (see [`build_cbor_request`](Self::build_cbor_request)).
    ///
    /// An `Err` is a transport failure (DNS / connect / TLS /
    /// timeout / oversized or unreadable response) — NEVER a non-2xx
    /// status, which is surfaced verbatim in
    /// [`ForwardResponse::status`] for the router to map to `502`.
    async fn post_cbor(
        &self,
        url: &str,
        body: &[u8],
        peer: Option<&PeerId>,
    ) -> Result<ForwardResponse, ForwardError> {
        let request = self.build_cbor_request(url, body, peer)?;
        self.execute_bounded(request).await
    }

    /// POST `json_body` to `url` with `content-type: application/json` —
    /// the served-receipt path (vali's JSON telemetry-ingest shape).
    async fn post_json(
        &self,
        url: &str,
        json_body: String,
    ) -> Result<ForwardResponse, ForwardError> {
        let mut builder = self
            .client
            .post(url)
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .body(json_body);
        // vali's JSON telemetry-ingest path pins `ServiceTokenAuthentication`
        // — stamp the bearer token so the served-receipt POST is not 401'd.
        if let Some(token) = &self.vali_ingest_token {
            builder = builder.header(reqwest::header::AUTHORIZATION, format!("Bearer {token}"));
        }
        let request = builder.build().map_err(|_| ForwardError::Transport)?;
        self.execute_bounded(request).await
    }

    /// Execute a built request + read the response under the size bound —
    /// shared by [`post_cbor`](Self::post_cbor) and
    /// [`post_json`](Self::post_json). An `Err` is a transport failure,
    /// NEVER a non-2xx status (that is a successful [`ForwardResponse`]).
    async fn execute_bounded(
        &self,
        request: reqwest::Request,
    ) -> Result<ForwardResponse, ForwardError> {
        let response = self
            .client
            .execute(request)
            .await
            .map_err(|_| ForwardError::Transport)?;
        let status = response.status().as_u16();
        // Hard-bound the upstream body: a hostile / buggy inner
        // endpoint cannot drive an unbounded allocation. `content-
        // length` is advisory — re-check the actual collected length.
        if let Some(len) = response.content_length() {
            if len > MAX_ENVELOPE_BYTES as u64 {
                return Err(ForwardError::ResponseTooLarge);
            }
        }
        let bytes = response
            .bytes()
            .await
            .map_err(|_| ForwardError::ResponseRead)?;
        if bytes.len() > MAX_ENVELOPE_BYTES {
            return Err(ForwardError::ResponseTooLarge);
        }
        Ok(ForwardResponse {
            status,
            body: bytes.to_vec(),
        })
    }
}

/// Split a `SignedServedDeliveryReceipt` CBOR body into the JSON shape
/// vali's telemetry ingest expects (`{schema_version, source, source_id,
/// kind, body_hex, sig_hex}`).
///
/// vali resolves the tenant telemetry verifying key from
/// `(tenant_vm, vm_id)`, so the `vm_id` is peeked from the inner (signed)
/// receipt body — an UNVERIFIED routing hint. A forged `vm_id` merely
/// selects the wrong key and fails vali's signature check, so peeking it
/// is safe (the guest Ed25519 signature remains the security gate).
fn served_receipt_ingest_json(body: &[u8]) -> Result<String, ForwardError> {
    use ciborium::value::Value;
    use hippius_types::served_receipt::SignedServedDeliveryReceipt;

    let signed: SignedServedDeliveryReceipt =
        ciborium::de::from_reader(body).map_err(|_| ForwardError::ReceiptEncode)?;

    // Peek `vm_id` from the inner receipt body (a CBOR map).
    let inner: Value = ciborium::de::from_reader(signed.body.as_slice())
        .map_err(|_| ForwardError::ReceiptEncode)?;
    let vm_id = match inner {
        Value::Map(entries) => entries.into_iter().find_map(|(k, v)| match (k, v) {
            (Value::Text(name), Value::Text(val)) if name == "vm_id" => Some(val),
            _ => None,
        }),
        _ => None,
    }
    .ok_or(ForwardError::ReceiptEncode)?;

    let json = serde_json::json!({
        "schema_version": 1,
        "source": "tenant_vm",
        "source_id": vm_id,
        "kind": "served_receipt",
        "body_hex": hex::encode(&signed.body),
        "sig_hex": hex::encode(&signed.sig),
    });
    serde_json::to_string(&json).map_err(|_| ForwardError::ReceiptEncode)
}

/// Join a base URL and an absolute path, collapsing a doubled `/`
/// (mirrors `agent-initramfs::kbs_client::join_url`).
fn join_url(base: &str, path: &str) -> String {
    format!("{}{}", base.trim_end_matches('/'), path)
}

/// Extract the vali-minted single-use enrollment nonce from an
/// enrollment's `snp_report` — `REPORT_DATA[0..32]`, i.e. the 32 bytes at
/// [`REPORT_DATA_OFFSET`]. STATELESS: the nonce IS those bytes (the guest
/// folded vali's minted value there), so there is no cache / per-connection
/// state — the KBS re-verifies the AMD signature over the whole report and
/// recomputes `REPORT_DATA`, so a wrong nonce simply fails the byte-match.
fn extract_report_data_nonce(
    snp_report: &[u8],
) -> Result<[u8; HOST_ENROLL_NONCE_LEN], ForwardError> {
    let end = REPORT_DATA_OFFSET + HOST_ENROLL_NONCE_LEN;
    snp_report
        .get(REPORT_DATA_OFFSET..end)
        .and_then(|s| <[u8; HOST_ENROLL_NONCE_LEN]>::try_from(s).ok())
        .ok_or(ForwardError::HostEnroll)
}

/// Build the canonical-CBOR `{enrollment, nonce}` body for the KBS
/// host-attestor enroll endpoint (`kbs_transport::wire::HostEnrollRequestBody`).
/// `enrollment` is the guest's ORIGINAL enrollment bytes (relayed verbatim
/// — the KBS re-decodes them with the frozen PR-1 parser); `nonce` is the
/// value extracted from `REPORT_DATA[0..32]`.
fn build_host_enroll_request(
    enrollment_bytes: &[u8],
    nonce: &[u8; HOST_ENROLL_NONCE_LEN],
) -> Result<Vec<u8>, ForwardError> {
    use ciborium::value::Value;
    // Canonical (alphabetic) key order: "enrollment" < "nonce".
    let v = Value::Map(vec![
        (
            Value::Text("enrollment".into()),
            Value::Bytes(enrollment_bytes.to_vec()),
        ),
        (Value::Text("nonce".into()), Value::Bytes(nonce.to_vec())),
    ]);
    hippius_types::cbor::to_canonical_vec(&v).map_err(|_| ForwardError::HostEnroll)
}

/// Decode the KBS `HostEnrollResponseBody` — extract the `signed_cert`
/// bytes (the `SignedHostAttestorCert` the Edge forwards to vali). The KBS
/// response is canonical CBOR `{signed_cert}`; a malformed body is a
/// fail-closed `HostEnroll` fault (never a fabricated cert into vali).
fn extract_signed_cert(kbs_body: &[u8]) -> Result<Vec<u8>, ForwardError> {
    use ciborium::value::Value;
    hippius_types::cbor::assert_canonical(kbs_body).map_err(|_| ForwardError::HostEnroll)?;
    let value: Value = ciborium::de::from_reader(kbs_body).map_err(|_| ForwardError::HostEnroll)?;
    let entries = match value {
        Value::Map(entries) => entries,
        _ => return Err(ForwardError::HostEnroll),
    };
    entries
        .into_iter()
        .find_map(|(k, v)| match (k, v) {
            (Value::Text(name), Value::Bytes(bytes)) if name == "signed_cert" => Some(bytes),
            _ => None,
        })
        .ok_or(ForwardError::HostEnroll)
}

#[async_trait]
impl ForwardClient for ReqwestForwardClient {
    async fn forward_kbs_request(
        &self,
        env: &ValidatedEnvelope,
    ) -> Result<ForwardResponse, ForwardError> {
        let url = join_url(&self.kbs_base, KBS_RELEASE_PATH);
        self.post_cbor(&url, env.body_bytes(), None).await
    }

    async fn forward_served_receipt(
        &self,
        env: &ValidatedEnvelope,
    ) -> Result<ForwardResponse, ForwardError> {
        // vali's telemetry ingest resolves the tenant telemetry key from
        // `(tenant_vm, vm_id)`, which it cannot read from the opaque CBOR
        // — so the Edge splits the `{body, sig}` receipt + peeks `vm_id`
        // into vali's JSON ingest shape. The guest signature is still
        // verified vali-side against the launch-provisioned key.
        let url = join_url(&self.vali_base, vali_forward::TELEMETRY_INGEST_PATH);
        let json = served_receipt_ingest_json(env.body_bytes())?;
        self.post_json(&url, json).await
    }

    async fn forward_served_aggregate(
        &self,
        env: &ValidatedEnvelope,
    ) -> Result<ForwardResponse, ForwardError> {
        let url = join_url(&self.vali_base, vali_forward::TELEMETRY_INGEST_PATH);
        self.post_cbor(&url, env.body_bytes(), None).await
    }

    async fn forward_stopped_ack(
        &self,
        env: &ValidatedEnvelope,
    ) -> Result<ForwardResponse, ForwardError> {
        let url = join_url(&self.vali_base, vali_forward::STOPPED_ACK_PATH);
        self.post_cbor(&url, env.body_bytes(), None).await
    }

    /// Relay a `Heartbeat` body to the vali telemetry ingest. Unlike
    /// every other kind this stamps the connection's mTLS [`PeerId`] as
    /// the [`vali_forward::HEARTBEAT_PEER_ID_HEADER`] header — vali
    /// resolves the miner's verifying key from it (see [`vali_forward`]).
    async fn forward_heartbeat(
        &self,
        env: &ValidatedEnvelope,
    ) -> Result<ForwardResponse, ForwardError> {
        let url = join_url(&self.vali_base, vali_forward::HEARTBEAT_INGEST_PATH);
        self.post_cbor(&url, env.body_bytes(), Some(env.peer()))
            .await
    }

    /// Relay a `GracefulExit` body to the vali graceful-exit ingest.
    /// Like [`forward_heartbeat`](Self::forward_heartbeat) it stamps the
    /// connection's mTLS [`PeerId`] as the
    /// [`vali_forward::HEARTBEAT_PEER_ID_HEADER`] header — vali resolves
    /// which registered miner key to verify the opaque
    /// `SignedGracefulExit` against from it (see [`vali_forward`]).
    async fn forward_graceful_exit(
        &self,
        env: &ValidatedEnvelope,
    ) -> Result<ForwardResponse, ForwardError> {
        let url = join_url(&self.vali_base, vali_forward::GRACEFUL_EXIT_INGEST_PATH);
        self.post_cbor(&url, env.body_bytes(), Some(env.peer()))
            .await
    }

    /// Relay a `VmProgress` body to the vali boot-progress ingest.
    /// Like [`forward_heartbeat`](Self::forward_heartbeat) it stamps the
    /// connection's mTLS [`PeerId`] as the
    /// [`vali_forward::HEARTBEAT_PEER_ID_HEADER`] header — vali resolves
    /// which registered miner key to verify the opaque `SignedVmProgress`
    /// against from it (see [`vali_forward`]).
    async fn forward_vm_progress(
        &self,
        env: &ValidatedEnvelope,
    ) -> Result<ForwardResponse, ForwardError> {
        let url = join_url(&self.vali_base, vali_forward::VM_PROGRESS_INGEST_PATH);
        self.post_cbor(&url, env.body_bytes(), Some(env.peer()))
            .await
    }

    /// Relay a `HostAttestorChallenge` body to the vali nonce authority
    /// (PR-10). Like [`forward_heartbeat`](Self::forward_heartbeat) it
    /// stamps the connection's mTLS [`PeerId`] as the
    /// [`vali_forward::HEARTBEAT_PEER_ID_HEADER`] header — vali binds the
    /// minted single-use nonce to the relay-metadata `node_id` + the
    /// request's `signer_pubkey` (never a body-declared node — §5.6). The
    /// minted nonce comes back in the 2xx body and is relayed down verbatim.
    async fn forward_host_attestor_challenge(
        &self,
        env: &ValidatedEnvelope,
    ) -> Result<ForwardResponse, ForwardError> {
        let url = join_url(
            &self.vali_base,
            vali_forward::HOST_ATTESTOR_CHALLENGE_INGEST_PATH,
        );
        self.post_cbor(&url, env.body_bytes(), Some(env.peer()))
            .await
    }

    /// ORCHESTRATE a `HostAttestorEnroll` (PR-10b-S2a): decode the
    /// enrollment → extract the `REPORT_DATA[0..32]` nonce → mint at the
    /// KBS → forward the cert to vali. Fail-closed at every hop.
    async fn forward_host_attestor_enroll(
        &self,
        env: &ValidatedEnvelope,
    ) -> Result<ForwardResponse, ForwardError> {
        let enrollment_bytes = env.body_bytes();

        // (1) Decode the enrollment in Rust (hostile-origin; already gated
        //     at the wire but re-decoded here to reach the SNP report). The
        //     enrollment bytes themselves are relayed VERBATIM to the KBS.
        let enrollment = hippius_types::host_attestor::HostEnrollment::decode(enrollment_bytes)
            .map_err(|_| ForwardError::HostEnroll)?;

        // (2) Extract the vali-minted nonce statelessly from
        //     REPORT_DATA[0..32] — the value the guest folded in.
        let nonce = extract_report_data_nonce(&enrollment.snp_report)?;

        // (3) POST the `{enrollment, nonce}` to the KBS enroll endpoint.
        let kbs_url = join_url(&self.kbs_base, KBS_HOST_ENROLL_PATH);
        let kbs_body = build_host_enroll_request(enrollment_bytes, &nonce)?;
        let kbs_resp = self.post_cbor(&kbs_url, &kbs_body, None).await?;

        // (4) Fail-closed: a KBS 4xx/5xx (report invalid / wrong class /
        //     nonce-mismatch) → surface the KBS status and DO NOT call vali.
        //     The router maps a non-2xx forward result to a miner `502`.
        if !(200..300).contains(&kbs_resp.status) {
            return Ok(ForwardResponse {
                status: kbs_resp.status,
                body: Vec::new(),
            });
        }

        // (5) On a minted cert, extract the `SignedHostAttestorCert` and
        //     forward it to vali's cert ingest, stamping the mTLS PeerId.
        //     vali's own verdict (2xx/reject) is surfaced verbatim — never
        //     a retry into a false-attested state.
        let signed_cert = extract_signed_cert(&kbs_resp.body)?;
        let vali_url = join_url(
            &self.vali_base,
            vali_forward::HOST_ATTESTOR_CERT_INGEST_PATH,
        );
        self.post_cbor(&vali_url, &signed_cert, Some(env.peer()))
            .await
    }

    /// Relay a `HostAttestorBeacon` body to vali's host-attestor heartbeat
    /// ingest (PR-10b-S2a). Stamps the connection's mTLS [`PeerId`] like
    /// [`forward_heartbeat`](Self::forward_heartbeat) — vali resolves the
    /// host `node_id` from it and verifies the opaque `SignedHostBeacon`
    /// against the CERTIFIED key (§5.6).
    async fn forward_host_attestor_beacon(
        &self,
        env: &ValidatedEnvelope,
    ) -> Result<ForwardResponse, ForwardError> {
        let url = join_url(
            &self.vali_base,
            vali_forward::HOST_ATTESTOR_BEACON_INGEST_PATH,
        );
        self.post_cbor(&url, env.body_bytes(), Some(env.peer()))
            .await
    }

    /// Relay a `VmLiveAttestation` body to vali's uptime-coverage ingest
    /// (§23). Opaque relay with NO peer stamp and NO bearer token: the
    /// KBS L0 signature over the body is the whole credential, and vali
    /// checks it against its own pinned key. The miner carrying these
    /// bytes has no way to forge or alter them.
    async fn forward_vm_live_attestation(
        &self,
        env: &ValidatedEnvelope,
    ) -> Result<ForwardResponse, ForwardError> {
        let url = join_url(&self.vali_base, vali_forward::VM_LIVENESS_INGEST_PATH);
        self.post_cbor(&url, env.body_bytes(), None).await
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn served_receipt_ingest_json_splits_and_peeks_vm_id() {
        use hippius_types::served_receipt::{ServedDeliveryReceipt, SignedServedDeliveryReceipt};
        // A real inner receipt → its canonical body is what vali verifies;
        // the outer {body, sig} is what travels the wire.
        let nonce = [3u8; 32];
        let inner = ServedDeliveryReceipt {
            validator_id: b"val",
            validator_nonce: &nonce,
            epoch: 7,
            vm_id: "vm-peek",
            lease_id: "lease-1",
            family_id: b"fam",
            node_id: &[0xcd; 32],
            resource_class: "small",
            monotonic_seq: 1,
            observed_degradation_bps: 0,
            period_start: 100,
            period_end: 160,
            expiry: 9_999,
        };
        let body = inner.canonical().unwrap();
        let signed = SignedServedDeliveryReceipt {
            body: body.clone(),
            sig: vec![0xab; 64],
        };
        let wire = signed.canonical().unwrap();

        let json = served_receipt_ingest_json(&wire).unwrap();
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(v["source"], "tenant_vm");
        assert_eq!(v["source_id"], "vm-peek"); // peeked from the signed body
        assert_eq!(v["kind"], "served_receipt");
        assert_eq!(v["schema_version"], 1);
        assert_eq!(v["body_hex"], hex::encode(&body)); // inner body → what vali verifies
        assert_eq!(v["sig_hex"], hex::encode([0xab; 64]));
    }

    #[test]
    fn served_receipt_ingest_json_rejects_garbage() {
        assert!(matches!(
            served_receipt_ingest_json(b"not-cbor"),
            Err(ForwardError::ReceiptEncode)
        ));
    }

    #[test]
    fn join_url_collapses_double_slash() {
        assert_eq!(
            join_url(
                "http://kbs-server.kbs.svc.cluster.local:8000/",
                "/v1/kbs/release"
            ),
            "http://kbs-server.kbs.svc.cluster.local:8000/v1/kbs/release"
        );
        assert_eq!(
            join_url(
                "http://kbs-server.kbs.svc.cluster.local:8000",
                "/v1/kbs/release"
            ),
            "http://kbs-server.kbs.svc.cluster.local:8000/v1/kbs/release"
        );
    }

    #[test]
    fn client_builds_with_default_endpoints() {
        // The production builder must succeed against the cluster-DNS
        // defaults — a builder failure here would be boot-fatal.
        let c = ReqwestForwardClient::new(
            "http://kbs-server.kbs.svc.cluster.local:8000",
            "http://vali.vali.svc.cluster.local:8000",
            None,
        );
        assert!(c.is_ok());
    }

    /// Helper: a client against the cluster-DNS defaults.
    fn test_client() -> ReqwestForwardClient {
        ReqwestForwardClient::new(
            "http://kbs-server.kbs.svc.cluster.local:8000",
            "http://vali.vali.svc.cluster.local:8000",
            None,
        )
        .unwrap()
    }

    #[test]
    fn heartbeat_request_carries_the_peer_id_header() {
        // The heartbeat path stamps the mTLS PeerId so vali can resolve
        // the miner's verifying key — verify the built request carries
        // it verbatim (the binding PR-Part4-B's vali side depends on).
        let client = test_client();
        let peer = PeerId::new("hippius-miner:miner-a");
        let request = client
            .build_cbor_request(
                "http://vali.vali.svc.cluster.local:8000/v1/telemetry/ingest",
                b"signed-heartbeat-cbor",
                Some(&peer),
            )
            .unwrap();
        assert_eq!(
            request
                .headers()
                .get(vali_forward::HEARTBEAT_PEER_ID_HEADER)
                .unwrap(),
            "hippius-miner:miner-a",
        );
        assert_eq!(
            request
                .headers()
                .get(reqwest::header::CONTENT_TYPE)
                .unwrap(),
            CONTENT_TYPE_CBOR,
        );
    }

    #[test]
    fn graceful_exit_request_carries_the_peer_id_header() {
        // Like the heartbeat path, the graceful-exit relay stamps the
        // mTLS PeerId so vali can resolve the miner's verifying key —
        // the body is opaque, so the header is the only identity carrier.
        let client = test_client();
        let peer = PeerId::new("hippius-miner:miner-a");
        let request = client
            .build_cbor_request(
                "http://vali.vali.svc.cluster.local:8000/v1/telemetry/graceful-exit",
                b"signed-graceful-exit-cbor",
                Some(&peer),
            )
            .unwrap();
        assert_eq!(
            request
                .headers()
                .get(vali_forward::HEARTBEAT_PEER_ID_HEADER)
                .unwrap(),
            "hippius-miner:miner-a",
        );
        assert_eq!(
            request
                .headers()
                .get(reqwest::header::CONTENT_TYPE)
                .unwrap(),
            CONTENT_TYPE_CBOR,
        );
    }

    // ─── PR-10b-S2a: host-attestor enroll orchestration ───────────────

    use crate::mtls::PeerId;
    use crate::pipeline::{Direction, MessageKind};
    use crate::stages::envelope::RawEnvelope;
    use crate::stages::validate::validate;
    use hippius_types::host_attestor::{
        HostEnrollment, HOST_ATTESTOR_SCHEMA_VERSION, SNP_REPORT_LEN,
    };
    use std::sync::Arc;

    /// A valid enrollment whose SNP report carries `nonce` at
    /// `REPORT_DATA[0..32]` (offset 0x50) — the byte layout the Edge reads.
    fn enrollment_with_nonce(nonce: &[u8; 32]) -> HostEnrollment {
        let mut snp_report = [0u8; SNP_REPORT_LEN];
        snp_report[REPORT_DATA_OFFSET..REPORT_DATA_OFFSET + 32].copy_from_slice(nonce);
        HostEnrollment {
            schema_version: HOST_ATTESTOR_SCHEMA_VERSION,
            snp_report,
            signer_pubkey: [0x22; 32],
            node_id: "node-host-1".into(),
            boot_id: "boot-abc".into(),
            issued_at_unix: 1_800_000_000,
        }
    }

    fn validated_enroll_env(
        enrollment: &HostEnrollment,
    ) -> crate::stages::envelope::ValidatedEnvelope {
        let body = enrollment.canonical().unwrap();
        let raw = RawEnvelope::from_wire(
            Direction::MinerToInner,
            MessageKind::HostAttestorEnroll,
            PeerId::new("hippius-miner:miner-a"),
            body,
        );
        validate(raw).expect("a valid enrollment passes the wire gate")
    }

    /// A recording HTTP server standing in for BOTH the KBS + vali: it
    /// records every path hit and (for the KBS enroll path) the request
    /// body, and returns canned responses keyed by path.
    #[derive(Clone)]
    struct Recorder {
        hits: Arc<std::sync::Mutex<Vec<String>>>,
        kbs_body_seen: Arc<std::sync::Mutex<Option<Vec<u8>>>>,
        cert_peer_seen: Arc<std::sync::Mutex<Option<String>>>,
        /// `Some(None)` = the vm-liveness path was hit WITHOUT a peer
        /// stamp (the correct posture); `Some(Some(_))` = it was stamped.
        live_attestation_peer_seen: Arc<std::sync::Mutex<Option<Option<String>>>>,
        kbs_status: u16,
        kbs_body: Vec<u8>,
    }

    async fn recorder_handler(
        axum::extract::State(rec): axum::extract::State<Recorder>,
        req: axum::extract::Request,
    ) -> axum::response::Response {
        use axum::response::IntoResponse;
        let path = req.uri().path().to_string();
        let peer = req
            .headers()
            .get(vali_forward::HEARTBEAT_PEER_ID_HEADER)
            .and_then(|v| v.to_str().ok())
            .map(str::to_string);
        rec.hits.lock().unwrap().push(path.clone());
        let bytes = axum::body::to_bytes(req.into_body(), 1 << 20)
            .await
            .unwrap();
        if path == KBS_HOST_ENROLL_PATH {
            *rec.kbs_body_seen.lock().unwrap() = Some(bytes.to_vec());
            (
                axum::http::StatusCode::from_u16(rec.kbs_status).unwrap(),
                rec.kbs_body.clone(),
            )
                .into_response()
        } else if path == vali_forward::HOST_ATTESTOR_CERT_INGEST_PATH {
            *rec.cert_peer_seen.lock().unwrap() = peer;
            (axum::http::StatusCode::OK, b"vali-ok".to_vec()).into_response()
        } else if path == vali_forward::VM_LIVENESS_INGEST_PATH {
            // §23 uptime coverage — record whether the relay stamped a
            // peer id (it must not: the KBS L0 signature is the whole
            // credential).
            *rec.live_attestation_peer_seen.lock().unwrap() = Some(peer);
            (axum::http::StatusCode::OK, b"vali-ok".to_vec()).into_response()
        } else {
            axum::http::StatusCode::NOT_FOUND.into_response()
        }
    }

    /// Spawn the recorder on an ephemeral loopback port; returns
    /// `(base_url, recorder)`.
    async fn spawn_recorder(kbs_status: u16, kbs_body: Vec<u8>) -> (String, Recorder) {
        let rec = Recorder {
            hits: Arc::new(std::sync::Mutex::new(Vec::new())),
            kbs_body_seen: Arc::new(std::sync::Mutex::new(None)),
            cert_peer_seen: Arc::new(std::sync::Mutex::new(None)),
            live_attestation_peer_seen: Arc::new(std::sync::Mutex::new(None)),
            kbs_status,
            kbs_body,
        };
        let app = axum::Router::new()
            .fallback(recorder_handler)
            .with_state(rec.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        (format!("http://{addr}"), rec)
    }

    fn client_at(base: &str) -> ReqwestForwardClient {
        ReqwestForwardClient::new(base, base, None).unwrap()
    }

    /// A canonical KBS `{signed_cert}` response body.
    fn kbs_signed_cert_body(cert: &[u8]) -> Vec<u8> {
        use ciborium::value::Value;
        let v = Value::Map(vec![(
            Value::Text("signed_cert".into()),
            Value::Bytes(cert.to_vec()),
        )]);
        hippius_types::cbor::to_canonical_vec(&v).unwrap()
    }

    #[test]
    fn extract_report_data_nonce_reads_offset_0x50() {
        let mut report = vec![0u8; SNP_REPORT_LEN];
        report[REPORT_DATA_OFFSET..REPORT_DATA_OFFSET + 32].copy_from_slice(&[0xAB; 32]);
        assert_eq!(extract_report_data_nonce(&report).unwrap(), [0xAB; 32]);
        // A short report fails closed.
        assert!(matches!(
            extract_report_data_nonce(&[0u8; 16]),
            Err(ForwardError::HostEnroll)
        ));
    }

    #[test]
    fn build_and_extract_round_trip() {
        let req = build_host_enroll_request(b"enrollment-bytes", &[0x11; 32]).unwrap();
        // Canonical + decodes to {enrollment, nonce} with the right values.
        hippius_types::cbor::assert_canonical(&req).unwrap();
        let v: ciborium::value::Value = ciborium::de::from_reader(req.as_slice()).unwrap();
        let map = match v {
            ciborium::value::Value::Map(m) => m,
            _ => panic!("not a map"),
        };
        let mut enrollment = None;
        let mut nonce = None;
        for (k, val) in map {
            if let (ciborium::value::Value::Text(name), ciborium::value::Value::Bytes(b)) = (k, val)
            {
                match name.as_str() {
                    "enrollment" => enrollment = Some(b),
                    "nonce" => nonce = Some(b),
                    _ => panic!("unexpected key"),
                }
            }
        }
        assert_eq!(enrollment.unwrap(), b"enrollment-bytes");
        assert_eq!(nonce.unwrap(), vec![0x11; 32]);

        // extract_signed_cert pulls the bytes back out.
        let body = kbs_signed_cert_body(b"the-cert");
        assert_eq!(extract_signed_cert(&body).unwrap(), b"the-cert");
        // A non-canonical / wrong-shape body fails closed.
        assert!(matches!(
            extract_signed_cert(b"not-cbor"),
            Err(ForwardError::HostEnroll)
        ));
    }

    #[tokio::test]
    async fn enroll_orchestration_mints_then_forwards_the_cert_to_vali() {
        // KBS mints a cert (200) → the Edge forwards it to vali → vali OK.
        let nonce = [0x11u8; 32];
        let (base, rec) = spawn_recorder(200, kbs_signed_cert_body(b"signed-cert-xyz")).await;
        let client = client_at(&base);
        let env = validated_enroll_env(&enrollment_with_nonce(&nonce));

        let resp = client.forward_host_attestor_enroll(&env).await.unwrap();
        assert_eq!(resp.status, 200);
        assert_eq!(resp.body, b"vali-ok");

        let hits = rec.hits.lock().unwrap().clone();
        // BOTH hops ran, KBS first then vali cert.
        assert_eq!(
            hits,
            vec![
                KBS_HOST_ENROLL_PATH.to_string(),
                vali_forward::HOST_ATTESTOR_CERT_INGEST_PATH.to_string(),
            ]
        );
        // The nonce the Edge attached is exactly REPORT_DATA[0..32].
        let kbs_body = rec.kbs_body_seen.lock().unwrap().clone().unwrap();
        let sent_nonce = extract_kbs_nonce(&kbs_body);
        assert_eq!(sent_nonce, nonce.to_vec());
        // The vali cert POST carried the miner's mTLS peer-id.
        assert_eq!(
            rec.cert_peer_seen.lock().unwrap().clone().unwrap(),
            "hippius-miner:miner-a"
        );
    }

    #[tokio::test]
    async fn enroll_orchestration_kbs_4xx_never_calls_vali() {
        // A KBS 403 (report invalid / wrong class / nonce-mismatch) →
        // the Edge surfaces the status and NEVER calls vali (fail-closed —
        // no false-attested cert). The router maps the non-2xx to a 502.
        let (base, rec) = spawn_recorder(403, b"denied".to_vec()).await;
        let client = client_at(&base);
        let env = validated_enroll_env(&enrollment_with_nonce(&[0x11; 32]));

        let resp = client.forward_host_attestor_enroll(&env).await.unwrap();
        assert_eq!(resp.status, 403, "KBS status surfaced");
        assert!(resp.body.is_empty(), "no body relayed on a KBS reject");

        let hits = rec.hits.lock().unwrap().clone();
        assert_eq!(hits, vec![KBS_HOST_ENROLL_PATH.to_string()]);
        assert!(
            rec.cert_peer_seen.lock().unwrap().is_none(),
            "vali cert ingest MUST NOT be called on a KBS reject"
        );
    }

    #[tokio::test]
    async fn enroll_orchestration_kbs_2xx_bad_body_fails_closed() {
        // KBS answers 200 but with a body that is not `{signed_cert}` →
        // fail-closed (never forward a bogus cert to vali).
        let (base, rec) = spawn_recorder(200, b"not-a-cert-envelope".to_vec()).await;
        let client = client_at(&base);
        let env = validated_enroll_env(&enrollment_with_nonce(&[0x11; 32]));

        let err = client.forward_host_attestor_enroll(&env).await.unwrap_err();
        assert!(matches!(err, ForwardError::HostEnroll));
        assert!(
            rec.cert_peer_seen.lock().unwrap().is_none(),
            "a bogus KBS body must not reach vali"
        );
    }

    #[tokio::test]
    async fn beacon_forwards_to_vali_heartbeat_with_peer_stamp() {
        // The beacon relay POSTs to the vali host-attestor heartbeat path
        // with the mTLS peer-id stamped.
        let (base, _rec) = spawn_recorder(200, Vec::new()).await;
        let client = client_at(&base);
        let request = client
            .build_cbor_request(
                &join_url(&base, vali_forward::HOST_ATTESTOR_BEACON_INGEST_PATH),
                b"signed-beacon-cbor",
                Some(&PeerId::new("hippius-miner:miner-a")),
            )
            .unwrap();
        assert_eq!(
            request
                .headers()
                .get(vali_forward::HEARTBEAT_PEER_ID_HEADER)
                .unwrap(),
            "hippius-miner:miner-a",
        );
        assert!(request
            .url()
            .as_str()
            .ends_with("/v1/telemetry/host-attestor/heartbeat"));
    }

    #[tokio::test]
    async fn live_attestation_forwards_to_vali_unstamped_and_untokened() {
        // §23 — the KBS L0 signature is the whole credential. The relay
        // must carry NO peer-id stamp (vali must not be tempted to
        // attribute the attestation to the relaying miner) and NO bearer
        // token (the ingest is token-exempt by design). A mutant that
        // stamps either fails here.
        let (base, _rec) = spawn_recorder(200, Vec::new()).await;
        let client = client_at(&base);
        let request = client
            .build_cbor_request(
                &join_url(&base, vali_forward::VM_LIVENESS_INGEST_PATH),
                b"signed-live-attestation-cbor",
                None,
            )
            .unwrap();
        assert!(request
            .url()
            .as_str()
            .ends_with("/v1/telemetry/vm-liveness"));
        assert!(request
            .headers()
            .get(vali_forward::HEARTBEAT_PEER_ID_HEADER)
            .is_none());
        assert!(request
            .headers()
            .get(reqwest::header::AUTHORIZATION)
            .is_none());
    }

    #[tokio::test]
    async fn live_attestation_relay_hits_the_vm_liveness_path() {
        // End-to-end through the real `forward_vm_live_attestation`: the
        // recorder sees exactly the vali uptime-coverage path.
        let (base, rec) = spawn_recorder(200, Vec::new()).await;
        let client = client_at(&base);
        // A well-shaped `{body, sig}` envelope — the same wrapper every
        // signed telemetry kind uses.
        let wire = hippius_types::cbor::to_canonical_vec(&ciborium::value::Value::Map(vec![
            (
                ciborium::value::Value::Text("body".into()),
                ciborium::value::Value::Bytes(vec![0xDD; 32]),
            ),
            (
                ciborium::value::Value::Text("sig".into()),
                ciborium::value::Value::Bytes(vec![0xEE; 64]),
            ),
        ]))
        .unwrap();
        let env = validate(RawEnvelope::from_wire(
            Direction::MinerToInner,
            MessageKind::VmLiveAttestation,
            PeerId::new("hippius-miner:miner-a"),
            wire,
        ))
        .expect("a well-shaped {body,sig} envelope validates");

        let resp = client.forward_vm_live_attestation(&env).await.unwrap();

        assert_eq!(resp.status, 200);
        assert_eq!(
            rec.hits.lock().unwrap().as_slice(),
            [vali_forward::VM_LIVENESS_INGEST_PATH.to_string()],
        );
        assert_eq!(
            *rec.live_attestation_peer_seen.lock().unwrap(),
            Some(None),
            "the uptime-coverage relay must not stamp a miner identity",
        );
    }

    /// Pull the `nonce` byte-string out of a canonical `{enrollment, nonce}`
    /// KBS request body (test helper).
    fn extract_kbs_nonce(body: &[u8]) -> Vec<u8> {
        let v: ciborium::value::Value = ciborium::de::from_reader(body).unwrap();
        if let ciborium::value::Value::Map(m) = v {
            for (k, val) in m {
                if let (ciborium::value::Value::Text(name), ciborium::value::Value::Bytes(b)) =
                    (k, val)
                {
                    if name == "nonce" {
                        return b;
                    }
                }
            }
        }
        panic!("no nonce field");
    }

    #[test]
    fn non_heartbeat_request_omits_the_peer_id_header() {
        // Only the heartbeat path forwards the peer identity — every
        // other kind (KBS / served-receipt / aggregate / stopped-ack)
        // posts the body alone.
        let client = test_client();
        let request = client
            .build_cbor_request(
                "http://kbs-server.kbs.svc.cluster.local:8000/v1/kbs/release",
                b"kbs-request",
                None,
            )
            .unwrap();
        assert!(request
            .headers()
            .get(vali_forward::HEARTBEAT_PEER_ID_HEADER)
            .is_none());
        assert_eq!(
            request
                .headers()
                .get(reqwest::header::CONTENT_TYPE)
                .unwrap(),
            CONTENT_TYPE_CBOR,
        );
    }
}
