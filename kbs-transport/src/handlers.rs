//! axum handlers (ARCHITECTURE.md §7/§21).
//!
//! Each handler is a thin shell over the [`crate::KbsService`] trait:
//! decode-then-call-then-encode, with conservative size/MIME checks and
//! a deny-by-default error mapping. The HTTP layer never inspects the
//! request payload semantically — all policy is inside kbs-core.
//!
//! Order of work in `release`:
//! 1. Validate `Content-Type` (cheap, before body materialization).
//! 2. Read body with an explicit 64 KiB cap (defence-in-depth on top of
//!    the router's body-limit layer — a misconfigured layer order would
//!    otherwise let a hostile peer stream junk into memory).
//! 3. Reject non-canonical or unknown-field CBOR (§20).
//! 4. Enforce 32-byte nonce length.
//! 5. Hand off to the service.
//!
//! Internal errors return a stable public message (no `Display` leakage
//! of inner library or path details). The audit channel inside kbs-core
//! already records the detailed reason via [`kbs_core::release::AuditSink`].

use crate::rate_limit::NonceRateLimiter;
use crate::service::{KbsService, NONCE_LEN};
use crate::wire::{
    decode_canonical, encode_cbor, HostEnrollRequestBody, HostEnrollResponseBody,
    KeepaliveRequestBody, KeepaliveResponseBody, NonceResponse, ReleaseRequestBody,
    VolumeStampConfirmBody, VolumeStampConfirmResponse, CONTENT_TYPE_CBOR, MAX_REQUEST_BYTES,
};
use axum::body::{to_bytes, Body};
use axum::extract::{Request, State};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use hippius_types::host_attestor::HostEnrollment;
use hippius_types::live_attestation::{GuestComponents, GuestResources};
use serde_bytes::ByteBuf;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

/// Composite state shared with every handler. Cloned per request — only
/// the `Arc`s are cloned, so this is cheap regardless of `S`. We
/// implement `Clone` manually (deriving would require `S: Clone`, which
/// the service trait does NOT mandate).
///
/// `release_limiter` is independent from `nonce_limiter` because the
/// two endpoints have very different cost profiles: nonce issuance
/// touches only the durable nonce store (cheap; ~100/s default).
/// Release runs the §7 pipeline (SNP verify + Vault round trip + HPKE
/// wrap; ~1000/s default) and is the §13 DoS attack surface — an
/// attacker who reaches the KBS at scale wants to exhaust the SNP
/// verifier or the Vault read quota, not the nonce store.
pub struct AppState<S: KbsService + 'static> {
    pub svc: Arc<S>,
    pub nonce_limiter: Arc<NonceRateLimiter>,
    pub release_limiter: Arc<NonceRateLimiter>,
    /// §322 keepalive — own bucket since cost profile is closer to a
    /// nonce mint than a release (no Vault, no HPKE), but call
    /// frequency is once per VM per N minutes ⇒ ten or hundreds of
    /// VMs can produce sustained traffic.
    pub keepalive_limiter: Arc<NonceRateLimiter>,
    /// Blackbox host-attestor enroll (PR-10b-S2b) — own bucket. This is
    /// the MOST expensive verify path (full AMD cert-chain verify), and
    /// enrollment is rare (per boot + hourly per host), so a stingy
    /// bucket sheds a flood at the cheapest point. Defence-in-depth: the
    /// Edge (S2a) throttles per-source too.
    pub host_enroll_limiter: Arc<NonceRateLimiter>,
    /// Volume-stamp confirm (`kbs_core::volume_stamp`) — own bucket.
    /// Cost profile mirrors `release_limiter` (a durable-store CAS write,
    /// no Vault/HPKE) and the call is paired 1:1 with a prior release, so
    /// it uses the same generous default rate.
    pub volume_stamp_confirm_limiter: Arc<NonceRateLimiter>,
    /// Custody lease bind/renew/rekey (`kbs_core::custody`) — own bucket.
    /// Every custody guest renews every few minutes, so this scales with
    /// the fleet like keepalive; the miner relay also rate-limits per VM.
    pub custody_limiter: Arc<NonceRateLimiter>,
    /// Custody BIND — its own, stingy bucket: a bind is rare (per boot /
    /// daemon restart / KBS restart) and may cost an AMD KDS fetch, so a
    /// bind flood must not be able to starve renews (which are cheap and
    /// what keeps guests' disks unlocked).
    pub custody_bind_limiter: Arc<NonceRateLimiter>,
}

impl<S: KbsService + 'static> Clone for AppState<S> {
    fn clone(&self) -> Self {
        Self {
            svc: Arc::clone(&self.svc),
            nonce_limiter: Arc::clone(&self.nonce_limiter),
            release_limiter: Arc::clone(&self.release_limiter),
            keepalive_limiter: Arc::clone(&self.keepalive_limiter),
            host_enroll_limiter: Arc::clone(&self.host_enroll_limiter),
            volume_stamp_confirm_limiter: Arc::clone(&self.volume_stamp_confirm_limiter),
            custody_limiter: Arc::clone(&self.custody_limiter),
            custody_bind_limiter: Arc::clone(&self.custody_bind_limiter),
        }
    }
}

/// Wall-clock seconds since the UNIX epoch. The KBS is the source of
/// truth for "now" in expiry/TTL checks (§7). On clock failure (system
/// pre-1970) we refuse to serve — denying is the only safe outcome.
fn now_unix() -> Result<u64, ErrorBody> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .map_err(|_| ErrorBody::internal("clock unavailable"))
}

/// Reject a request whose `Content-Type` is not `application/cbor`. We
/// allow trailing parameters (e.g. `application/cbor; charset=...`)
/// because some clients add them, but the primary type must match.
fn require_cbor(headers: &HeaderMap) -> Result<(), ErrorBody> {
    let Some(ct) = headers.get(header::CONTENT_TYPE) else {
        return Err(ErrorBody::bad_request("missing Content-Type"));
    };
    let s = ct
        .to_str()
        .map_err(|_| ErrorBody::bad_request("invalid Content-Type header"))?;
    let primary = s.split(';').next().unwrap_or("").trim();
    if !primary.eq_ignore_ascii_case(CONTENT_TYPE_CBOR) {
        return Err(ErrorBody::unsupported_media_type(
            "Content-Type must be application/cbor",
        ));
    }
    Ok(())
}

/// Best-effort `Content-Length` extraction. The transport rejects
/// non-empty nonce-issuance requests by header value alone (no body
/// drain) — if the header is absent or malformed we still proceed to
/// `to_bytes` with a zero cap, which fails closed on any non-empty body.
fn header_content_length(headers: &HeaderMap) -> Option<u64> {
    headers
        .get(header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.trim().parse::<u64>().ok())
}

/// `GET /healthz` — liveness probe. Static 200 OK, no service work.
pub async fn health() -> Response {
    (StatusCode::OK, "ok").into_response()
}

/// `POST /v1/kbs/nonce` — issue a fresh single-use KBS nonce. The guest
/// folds the returned 32 bytes into `REPORT_DATA[0..32]` (§7/§20).
///
/// Request body: MUST be empty. We reject any positive `Content-Length`
/// up front and additionally cap body read at zero bytes so a chunked /
/// missing-CL request that streams data is also refused.
///
/// Rate-limited: per-process token bucket sheds bursts with `429`.
/// This is one layer of defense — the Edge gateway SHOULD also enforce
/// a per-source rate limit (see §13). Issuance is durable on disk; a
/// runaway client without a limit would otherwise fill the nonce store.
pub async fn issue_nonce<S: KbsService + 'static>(
    State(state): State<AppState<S>>,
    request: Request,
) -> Response {
    let (parts, body) = request.into_parts();
    if matches!(header_content_length(&parts.headers), Some(n) if n > 0) {
        return ErrorBody::bad_request("nonce request must have empty body").into_response();
    }
    // Read with cap=0 — succeeds for empty body, fails for any non-empty body.
    match to_bytes(body, 0).await {
        Ok(b) if b.is_empty() => {}
        Ok(_) => {
            return ErrorBody::bad_request("nonce request must have empty body").into_response();
        }
        Err(_) => {
            // Either a stream error or oversized (anything > 0 bytes).
            return ErrorBody::bad_request("nonce request must have empty body").into_response();
        }
    }
    if !state.nonce_limiter.try_acquire() {
        let mut resp = ErrorBody::too_many_requests("nonce issuance rate exceeded").into_response();
        // Retry-After hints; tower-http would set this for us but we keep
        // the layer set lean.
        resp.headers_mut()
            .insert(header::RETRY_AFTER, HeaderValue::from_static("1"));
        return resp;
    }
    let now = match now_unix() {
        Ok(n) => n,
        Err(e) => return e.into_response(),
    };
    let nonce = match state.svc.issue_nonce(now) {
        Ok(n) => n,
        Err(_) => {
            // Detailed cause is in the audit channel; don't leak it on
            // the wire.
            return ErrorBody::internal("nonce issuance failed").into_response();
        }
    };
    let body = NonceResponse {
        nonce: ByteBuf::from(nonce.to_vec()),
    };
    encode_to_response(StatusCode::OK, &body, /* no_store */ true)
}

/// `POST /v1/kbs/release` — the §7 release pipeline. Returns the
/// KBS-signed wrapped-secret response on grant, or the KBS-signed denial
/// on policy/auth failure (the latter is a protocol outcome, not an HTTP
/// error). Pure transport errors (malformed CBOR, oversized body) get
/// `4xx` codes.
pub async fn release<S: KbsService + 'static>(
    State(state): State<AppState<S>>,
    request: Request,
) -> Response {
    let (parts, body) = request.into_parts();
    if let Err(e) = require_cbor(&parts.headers) {
        return e.into_response();
    }
    // §13 — admission control BEFORE body materialization. Sheds
    // excess at the cheapest possible point in the pipeline.
    if !state.release_limiter.try_acquire() {
        let mut resp = ErrorBody::too_many_requests("release rate exceeded").into_response();
        resp.headers_mut()
            .insert(header::RETRY_AFTER, HeaderValue::from_static("1"));
        return resp;
    }
    let bytes = match to_bytes(body, MAX_REQUEST_BYTES).await {
        Ok(b) => b,
        Err(_) => {
            return ErrorBody::payload_too_large(&format!(
                "request body exceeds {MAX_REQUEST_BYTES} bytes"
            ))
            .into_response();
        }
    };
    let parsed = match decode_canonical::<ReleaseRequestBody>(&bytes) {
        Ok(v) => v,
        Err(_) => return ErrorBody::bad_request("malformed request").into_response(),
    };
    let nonce: [u8; NONCE_LEN] = match parsed.kbs_nonce.as_ref().try_into() {
        Ok(n) => n,
        Err(_) => {
            return ErrorBody::bad_request("kbs_nonce must be exactly 32 bytes").into_response();
        }
    };
    let now = match now_unix() {
        Ok(n) => n,
        Err(e) => return e.into_response(),
    };
    match state.svc.process_release(
        &parsed.cose_ticket,
        &parsed.snp_report,
        &nonce,
        now,
        parsed.submitted_boot_counter,
    ) {
        Ok(signed) => encode_to_response(StatusCode::OK, &signed, /* no_store */ true),
        Err(denial) => {
            encode_to_response(StatusCode::FORBIDDEN, &denial, /* no_store */ true)
        }
    }
}

/// `POST /v1/kbs/volume-stamp/confirm` — advance the guest-keyed
/// overlay's CONFIRMED volume stamp (`kbs_core::volume_stamp`) for the
/// caller's `vm_id`. Sent by the guest AFTER it has durably written the
/// stamp into its encrypted volume, authenticated by the single-use
/// token it unwrapped from `KbsResponse::volume_stamp_token` in the
/// release that issued it.
///
/// A denial (bad/absent token, or a value that isn't exactly
/// `stored + 1`) surfaces as a generic `403` — same discipline as
/// `release`/`keepalive`: the detailed reason never crosses the wire,
/// and in particular the expected token is NEVER echoed in the error
/// body (see the module docs — an unauthenticated confirm is a
/// permanent remote brick, so this must fail closed without leaking
/// anything that would help an attacker guess it).
///
/// # Why this route needs no per-request authentication of its own
///
/// This route is registered on the PUBLIC (unauthenticated-transport)
/// router — deliberately, since it is guest-facing over the same path
/// `/v1/kbs/release` already uses. The question worth answering
/// explicitly: what does a caller who is NOT the attested guest — in
/// particular the MINER, which relays this exact request over the
/// vsock proxy and therefore sees `token` in CLEARTEXT in the outgoing
/// body — gain by calling it?
///
/// - **Mint a token for a target it chooses**: impossible. `token` is
///   `HMAC(stamp_mac_key(kbs_signing_seed), vm_id, target)`
///   (`kbs_core::volume_stamp::stamp_token`); the miner never holds the
///   KBS signing seed, so it cannot compute a valid token for ANY
///   `(vm_id, target)` it hasn't already observed pass through it.
/// - **Cross-VM confusion**: closed separately — `vm_id` is folded into
///   the HMAC input (length-prefixed), so a token minted for one
///   `vm_id` never validates against another
///   (`vm_id_length_is_folded_in_so_concatenations_do_not_collide`).
/// - **Race a captured token against the guest's own confirm, SAME
///   boot**: harmless. The store's CAS accepts only `value == stored +
///   1` (`kbs_core::volume_stamp::VolumeStampStore::confirm`); whichever
///   of the miner's replay or the guest's own call lands first advances
///   the store to the SAME value, and the second submission is refused
///   as a rewind (`replaying_a_spent_token_is_refused_by_the_cas`).
/// - **Hold a captured token and replay it LATER, after rolling the
///   volume back**: this is the case worth naming precisely, because it
///   DOES brick the VM — a claim from an earlier draft of this comment
///   ("by the time a miner could act on a captured token, the value it
///   authorises is already on the volume") was wrong, and is corrected
///   here rather than quietly dropped. Sequence: a boot stamps the
///   volume to `N+1` and sends `confirm(N+1, token)`; the miner drops
///   that ONE confirm instead of relaying it (well within
///   `MAX_UNCONFIRMED_RELEASES`, so gate 5c does not catch this by
///   itself) but keeps `token`. The KBS stays at `N`. The miner then
///   restores an EARLIER snapshot whose in-volume stamp is `N` and
///   replays the kept `token`; the CAS legitimately accepts it
///   (`stored == N`, so `N+1 == stored + 1`) and the KBS advances to
///   `N+1`. The next boot reads `S = N` from the rolled-back volume
///   against `expected = N+1` — `S < E`, refused — and nothing can ever
///   again produce a legitimate `S = N+1`. The VM never opens again.
///
///   That is real, and it is not an escalation the token grants.
///   Reaching a state where the KBS is AHEAD of the volume presupposes
///   the miner has ALREADY rolled the volume back to an earlier
///   snapshot — and a miner willing to roll a tenant's volume back
///   already holds unconditional, token-independent power to destroy
///   that tenant's data outright (delete the overlay, never boot the VM
///   again, restore any snapshot it likes). Without the captured token,
///   that SAME rollback is simply TOLERATED: the guest reads `S = N`,
///   the KBS still expects `E = N` (the dropped confirm never advanced
///   it), `S == E` is the documented "no progress since the last
///   confirm" window, and the boot proceeds — a revert to the last
///   CONFIRMED state, which is exactly what an aborted boot is supposed
///   to look like. The captured token does not let the miner cause
///   damage it could not already cause by simply destroying the disk;
///   it only changes which of two host-caused outcomes follows a
///   rollback the host chose to perform. The brick in the sequence
///   above is attributable to the ROLLBACK, not to the token.
///
/// So: no per-request auth is needed on this route because nothing a
/// non-guest caller can do with it exceeds damage a miner already holds
/// unconditionally as the host. The one thing a miner CAN still do
/// without even needing a captured token is SUPPRESS confirms by never
/// relaying them at all; that is a distinct, already-closed attack — the
/// release path's suppressed-confirm gate
/// (`kbs_core::volume_stamp::note_release` + `MAX_UNCONFIRMED_RELEASES`),
/// not anything in this handler.
pub async fn volume_stamp_confirm<S: KbsService + 'static>(
    State(state): State<AppState<S>>,
    request: Request,
) -> Response {
    let (parts, body) = request.into_parts();
    if let Err(e) = require_cbor(&parts.headers) {
        return e.into_response();
    }
    if !state.volume_stamp_confirm_limiter.try_acquire() {
        let mut resp =
            ErrorBody::too_many_requests("volume-stamp confirm rate exceeded").into_response();
        resp.headers_mut()
            .insert(header::RETRY_AFTER, HeaderValue::from_static("1"));
        return resp;
    }
    let bytes = match to_bytes(body, MAX_REQUEST_BYTES).await {
        Ok(b) => b,
        Err(_) => {
            return ErrorBody::payload_too_large(&format!(
                "request body exceeds {MAX_REQUEST_BYTES} bytes"
            ))
            .into_response();
        }
    };
    let parsed = match decode_canonical::<VolumeStampConfirmBody>(&bytes) {
        Ok(v) => v,
        Err(_) => return ErrorBody::bad_request("malformed request").into_response(),
    };
    // v2 (a timeline named): the timeline-bound CAS; v1: the plain one.
    let outcome = match parsed.timeline_id.as_ref() {
        Some(t) => match <[u8; 32]>::try_from(t.as_ref()) {
            Ok(timeline) => state.svc.process_volume_stamp_confirm_timeline(
                &parsed.vm_id,
                parsed.value,
                parsed.token.as_ref(),
                &timeline,
            ),
            Err(_) => return ErrorBody::bad_request("malformed request").into_response(),
        },
        None => state.svc.process_volume_stamp_confirm(
            &parsed.vm_id,
            parsed.value,
            parsed.token.as_ref(),
        ),
    };
    match outcome {
        Ok(confirmed) => {
            let resp_body = VolumeStampConfirmResponse { confirmed };
            encode_to_response(StatusCode::OK, &resp_body, /* no_store */ true)
        }
        // Generic 403; detailed reason is in the audit channel, and
        // NEVER the presented/expected token either way.
        Err(_) => ErrorBody::forbidden("volume-stamp confirm denied").into_response(),
    }
}

/// `POST /v1/attest/keepalive` — §322 Phase B. Verify a fresh
/// SNP report from inside a tenant CVM, return a KBS-L0-signed
/// `SignedLiveAttestation` (canonical-CBOR-encoded inside a
/// `KeepaliveResponseBody`). A verification failure surfaces a
/// generic 403 — the audit channel inside kbs-core records the
/// detailed reason; the validator that submitted the request
/// retries on the next keepalive interval.
pub async fn keepalive<S: KbsService + 'static>(
    State(state): State<AppState<S>>,
    request: Request,
) -> Response {
    let (parts, body) = request.into_parts();
    if let Err(e) = require_cbor(&parts.headers) {
        return e.into_response();
    }
    if !state.keepalive_limiter.try_acquire() {
        let mut resp = ErrorBody::too_many_requests("keepalive rate exceeded").into_response();
        resp.headers_mut()
            .insert(header::RETRY_AFTER, HeaderValue::from_static("1"));
        return resp;
    }
    let bytes = match to_bytes(body, MAX_REQUEST_BYTES).await {
        Ok(b) => b,
        Err(_) => {
            return ErrorBody::payload_too_large(&format!(
                "request body exceeds {MAX_REQUEST_BYTES} bytes"
            ))
            .into_response();
        }
    };
    let parsed = match decode_canonical::<KeepaliveRequestBody>(&bytes) {
        Ok(v) => v,
        Err(_) => return ErrorBody::bad_request("malformed request").into_response(),
    };
    let nonce: [u8; NONCE_LEN] = match parsed.kbs_nonce.as_ref().try_into() {
        Ok(n) => n,
        Err(_) => {
            return ErrorBody::bad_request("kbs_nonce must be exactly 32 bytes").into_response();
        }
    };
    let node_id: [u8; NONCE_LEN] = match parsed.node_id.as_ref().try_into() {
        Ok(n) => n,
        Err(_) => {
            return ErrorBody::bad_request("node_id must be exactly 32 bytes").into_response();
        }
    };
    let now = match now_unix() {
        Ok(n) => n,
        Err(e) => return e.into_response(),
    };
    let resources: Option<GuestResources> = parsed.resources.map(GuestResources::from);
    let components: Option<GuestComponents> = parsed.components.map(GuestComponents::from);
    match state.svc.process_keepalive(
        &parsed.vm_id,
        &node_id,
        &parsed.snp_report,
        &nonce,
        parsed.epoch,
        parsed.expiry_unix,
        resources.as_ref(),
        components.as_ref(),
        now,
    ) {
        Ok(signed) => {
            let body = match signed.encode() {
                Ok(b) => b,
                Err(_) => {
                    return ErrorBody::internal("response encoding failed").into_response();
                }
            };
            let resp_body = KeepaliveResponseBody {
                signed_live_attestation: ByteBuf::from(body),
            };
            encode_to_response(StatusCode::OK, &resp_body, /* no_store */ true)
        }
        // Generic 403; detailed reason is in the audit channel.
        Err(_) => ErrorBody::forbidden("keepalive denied").into_response(),
    }
}

/// `POST /v1/kbs/host-attestor/enroll` — blackbox host-attestor
/// enrollment (blackbox host-attestor chantier — PR-10b-S2b). Decode the
/// relayed `{enrollment, nonce}`, re-verify the platform SNP report + the
/// host-attestor measurement-class gate + the `REPORT_DATA` bind inside
/// kbs-core, and on success return the KBS-L0-signed
/// `SignedHostAttestorCert` (canonical-CBOR-wrapped in a
/// [`HostEnrollResponseBody`]). Any verification failure surfaces a
/// generic 403 — the audit channel inside kbs-core records the detailed
/// reason; malformed/oversize CBOR gets a 4xx.
///
/// Mints ONLY from the AMD-verified report contents (`chip_id` /
/// `measurement` / `tcb` come from the `VerifiedReport`, never a
/// body-declared value) with a KBS-decided expiry. The nonce's
/// single-use/freshness is deliberately NOT checked here (vali does that
/// at cert-ingest); the KBS binds it exactly as PR-5 does.
///
/// Ships INERT: no caller reaches this route until the S2a relay is
/// wired.
pub async fn host_enroll<S: KbsService + 'static>(
    State(state): State<AppState<S>>,
    request: Request,
) -> Response {
    let (parts, body) = request.into_parts();
    if let Err(e) = require_cbor(&parts.headers) {
        return e.into_response();
    }
    // §13 — this is the most expensive verify path (full AMD chain).
    // Shed before body materialization.
    if !state.host_enroll_limiter.try_acquire() {
        let mut resp = ErrorBody::too_many_requests("host-enroll rate exceeded").into_response();
        resp.headers_mut()
            .insert(header::RETRY_AFTER, HeaderValue::from_static("1"));
        return resp;
    }
    let bytes = match to_bytes(body, MAX_REQUEST_BYTES).await {
        Ok(b) => b,
        Err(_) => {
            return ErrorBody::payload_too_large(&format!(
                "request body exceeds {MAX_REQUEST_BYTES} bytes"
            ))
            .into_response();
        }
    };
    let parsed = match decode_canonical::<HostEnrollRequestBody>(&bytes) {
        Ok(v) => v,
        Err(_) => return ErrorBody::bad_request("malformed request").into_response(),
    };
    // Decode the inner enrollment with the frozen PR-1 hostile-origin
    // parser — rejects non-canonical / unknown-field / wrong-length CBOR.
    let enrollment = match HostEnrollment::decode(&parsed.enrollment) {
        Ok(e) => e,
        Err(_) => return ErrorBody::bad_request("malformed enrollment").into_response(),
    };
    let nonce: [u8; NONCE_LEN] = match parsed.nonce.as_ref().try_into() {
        Ok(n) => n,
        Err(_) => {
            return ErrorBody::bad_request("nonce must be exactly 32 bytes").into_response();
        }
    };
    let now = match now_unix() {
        Ok(n) => n,
        Err(e) => return e.into_response(),
    };
    match state.svc.process_host_enroll(&enrollment, &nonce, now) {
        Ok(signed) => {
            let body = match signed.encode() {
                Ok(b) => b,
                Err(_) => {
                    return ErrorBody::internal("response encoding failed").into_response();
                }
            };
            let resp_body = HostEnrollResponseBody {
                signed_cert: ByteBuf::from(body),
            };
            encode_to_response(StatusCode::OK, &resp_body, /* no_store */ true)
        }
        // Generic 403; detailed reason is in the audit channel.
        Err(_) => ErrorBody::forbidden("host-enroll denied").into_response(),
    }
}

/// Which custody request a route carries.
enum CustodyRoute {
    Bind,
    Renew,
    Rekey,
}

/// `POST /v1/kbs/custody/bind` — see `kbs_core::custody::process_bind`.
pub async fn custody_bind<S: KbsService + 'static>(
    State(state): State<AppState<S>>,
    request: Request,
) -> Response {
    custody(state, request, CustodyRoute::Bind).await
}

/// `POST /v1/kbs/custody/renew` — see `kbs_core::custody::process_renew`.
pub async fn custody_renew<S: KbsService + 'static>(
    State(state): State<AppState<S>>,
    request: Request,
) -> Response {
    custody(state, request, CustodyRoute::Renew).await
}

/// `POST /v1/kbs/custody/rekey` — see `kbs_core::custody::process_rekey`.
pub async fn custody_rekey<S: KbsService + 'static>(
    State(state): State<AppState<S>>,
    request: Request,
) -> Response {
    custody(state, request, CustodyRoute::Rekey).await
}

/// Shared shell of the three custody routes. A signed verdict (or rekey
/// response) is a 200 CBOR body; everything else is an UNSIGNED status
/// with a closed-vocabulary text reason, which the guest treats as "retry,
/// change nothing".
async fn custody<S: KbsService + 'static>(
    state: AppState<S>,
    request: Request,
    route: CustodyRoute,
) -> Response {
    use hippius_types::custody::decode_canonical as decode;
    use kbs_core::custody::CustodyReply;
    let (parts, body) = request.into_parts();
    if let Err(e) = require_cbor(&parts.headers) {
        return e.into_response();
    }
    let limiter = match route {
        CustodyRoute::Bind => &state.custody_bind_limiter,
        CustodyRoute::Renew | CustodyRoute::Rekey => &state.custody_limiter,
    };
    if !limiter.try_acquire() {
        let mut resp = ErrorBody::too_many_requests("rate-limited").into_response();
        resp.headers_mut()
            .insert(header::RETRY_AFTER, HeaderValue::from_static("1"));
        return resp;
    }
    let bytes = match to_bytes(body, MAX_REQUEST_BYTES).await {
        Ok(b) => b,
        Err(_) => {
            return ErrorBody::payload_too_large(&format!(
                "request body exceeds {MAX_REQUEST_BYTES} bytes"
            ))
            .into_response();
        }
    };
    let now = match now_unix() {
        Ok(n) => n,
        Err(e) => return e.into_response(),
    };
    let reply = match route {
        CustodyRoute::Bind => match decode(&bytes) {
            Ok(req) => state.svc.process_custody_bind(&req, now),
            Err(_) => return ErrorBody::bad_request("malformed").into_response(),
        },
        CustodyRoute::Renew => match decode(&bytes) {
            Ok(req) => state.svc.process_custody_renew(&req, now),
            Err(_) => return ErrorBody::bad_request("malformed").into_response(),
        },
        CustodyRoute::Rekey => match decode(&bytes) {
            Ok(req) => state.svc.process_custody_rekey(&req, now),
            Err(_) => return ErrorBody::bad_request("malformed").into_response(),
        },
    };
    match reply {
        CustodyReply::Verdict(v) => {
            encode_to_response(StatusCode::OK, &v, /* no_store */ true)
        }
        CustodyReply::Rekey(r) => encode_to_response(StatusCode::OK, &r, /* no_store */ true),
        CustodyReply::Retry { status, reason } => ErrorBody {
            code: StatusCode::from_u16(status).unwrap_or(StatusCode::SERVICE_UNAVAILABLE),
            msg: reason.to_string(),
        }
        .into_response(),
    }
}

/// CBOR-encode `value` and wrap in an axum [`Response`] with status
/// `code`. When `no_store` is true the response is marked
/// `Cache-Control: no-store` to forbid any intermediary cache — KBS
/// outputs (grants and denials) are nonce-bound and time-bound and must
/// never be replayed from cache.
fn encode_to_response<T: serde::Serialize>(
    code: StatusCode,
    value: &T,
    no_store: bool,
) -> Response {
    match encode_cbor(value) {
        Ok(bytes) => {
            let mut resp = Response::new(Body::from(bytes));
            *resp.status_mut() = code;
            resp.headers_mut().insert(
                header::CONTENT_TYPE,
                HeaderValue::from_static(CONTENT_TYPE_CBOR),
            );
            if no_store {
                resp.headers_mut()
                    .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
            }
            resp
        }
        Err(_) => ErrorBody::internal("response encoding failed").into_response(),
    }
}

/// Transport-layer error → HTTP response. Bodies are plain UTF-8, kept
/// short, and never include `Display` output from inner libraries — the
/// audit channel inside kbs-core captures the detailed reason instead.
#[derive(Debug, Clone)]
pub struct ErrorBody {
    code: StatusCode,
    msg: String,
}

impl ErrorBody {
    pub fn bad_request(msg: &str) -> Self {
        Self {
            code: StatusCode::BAD_REQUEST,
            msg: msg.to_string(),
        }
    }
    pub fn unsupported_media_type(msg: &str) -> Self {
        Self {
            code: StatusCode::UNSUPPORTED_MEDIA_TYPE,
            msg: msg.to_string(),
        }
    }
    pub fn payload_too_large(msg: &str) -> Self {
        Self {
            code: StatusCode::PAYLOAD_TOO_LARGE,
            msg: msg.to_string(),
        }
    }
    pub fn too_many_requests(msg: &str) -> Self {
        Self {
            code: StatusCode::TOO_MANY_REQUESTS,
            msg: msg.to_string(),
        }
    }
    pub fn forbidden(msg: &str) -> Self {
        Self {
            code: StatusCode::FORBIDDEN,
            msg: msg.to_string(),
        }
    }
    pub fn internal(msg: &str) -> Self {
        Self {
            code: StatusCode::INTERNAL_SERVER_ERROR,
            msg: msg.to_string(),
        }
    }
}

impl IntoResponse for ErrorBody {
    fn into_response(self) -> Response {
        let mut resp = Response::new(Body::from(self.msg));
        *resp.status_mut() = self.code;
        resp.headers_mut().insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("text/plain; charset=utf-8"),
        );
        resp.headers_mut()
            .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
        resp
    }
}
