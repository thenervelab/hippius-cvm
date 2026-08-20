//! KBS admin endpoint transport (ARCHITECTURE.md §24/§25).
//!
//! Independent from the public-Ingress release transport
//! (`handlers.rs`). Phase A scope: `POST /v1/admin/register-vm` only.
//!
//! ## Auth model
//!
//! mTLS at the listener level: kbs-server binds a second port (default
//! `:8001`) configured with a server cert + a **pinned client-CA
//! bundle** (`hippius_kbs_server::admin_tls`). rustls completes no
//! handshake for a peer that presents no client cert or one that does
//! not chain to that CA, so such a request never reaches this module —
//! authentication is enforced BEFORE any handler, not inside one.
//!
//! **This module is not itself the gate.** Every route here mutates or
//! discloses lifecycle state and NONE of them re-authenticates; a caller
//! that reaches a handler is already trusted. The listener owner is
//! therefore responsible for refusing to serve at all when its TLS
//! material is absent — `admin_tls::AdminListenerMode` makes that
//! decision fail-closed (`require_mtls`, default `true`). Binding this
//! router on a plain `TcpListener` publishes an unauthenticated
//! lifecycle-mutation API to anything that can reach the port.
//!
//! The TLS layer (caller of [`build_admin_router`]) stuffs the verified
//! peer's cert info into the request extensions via [`PeerCertInfo`].
//! The handler reads it back for audit attribution. When the extension
//! is absent (in-process tests, mock servers, or an operator-opted-in
//! plaintext listener) the handler still functions but records
//! `peer_san=None` / `peer_serial=None` in the admin audit log — a row
//! with no `peer_san` means "this call was NOT authenticated by a
//! client cert".

use crate::rate_limit::NonceRateLimiter;
use crate::wire::CONTENT_TYPE_CBOR;
use axum::body::{to_bytes, Body};
use axum::extract::{Path, Request, State};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use hippius_types::admin::{
    AdminActivateRequest, AdminActivateResponse, AdminArmBootCounterResyncResponse,
    AdminConfigPostureResponse, AdminErrorResponse, AdminRegisterVmResponse,
    AdminReloadAllowlistResponse, AdminResetVolumeStampSuppressionResponse,
    AdminSeedBootCounterRequest, AdminSeedBootCounterResponse, AdminVolumeStampReportResponse,
    AdminVolumeStampRow,
};
use hippius_types::evidence_bundle::EvidenceBundle;
use kbs_core::admin::{
    process_admin_activate, process_admin_arm_boot_counter_resync, process_admin_register,
    process_admin_reset_volume_stamp_suppression, process_admin_seed_boot_counter,
    record_admin_activate_outcome, record_admin_arm_resync_outcome, record_admin_register_outcome,
    record_admin_reset_volume_stamp_suppression_outcome, record_admin_seed_outcome,
    AdminActivateErr, AdminRegisterErr, AdminRegisterOk, VmStateRegister, MAX_ADMIN_BODY_BYTES,
};
use kbs_core::admin_audit::FileAdminAuditSink;
use kbs_core::allowlist::InstalledAllowlist;
use kbs_core::boot_counter::BootCounterStore;
use kbs_core::evidence::EvidenceSink;
use kbs_core::persist::IdempotencyStore;
use kbs_core::ticket::L1Keyring;
use kbs_core::volume_stamp::VolumeStampStore;
use sha2::{Digest, Sha256};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tower_http::limit::RequestBodyLimitLayer;

/// Per-request peer-cert info, populated by the mTLS server before
/// the handler runs. Absent in tests + non-TLS mock setups.
#[derive(Debug, Clone)]
pub struct PeerCertInfo {
    /// SAN URI exact string ("spiffe://hippius.network/vali").
    pub san_uri: String,
    /// Cert serial number, hex.
    pub serial_hex: String,
}

/// Shared state injected into the admin router. Held by `Arc` so the
/// router can be cloned across axum workers without per-call lock
/// contention beyond what each store already incurs internally.
pub struct AdminState {
    pub keyring: Arc<dyn L1Keyring + Send + Sync>,
    pub vm_states: Arc<dyn VmStateRegister + Send + Sync>,
    pub idempotency: Arc<dyn IdempotencyStore + Send + Sync>,
    pub audit: Arc<FileAdminAuditSink>,
    pub limiter: Arc<NonceRateLimiter>,
    /// Concrete handle into the live §22 allowlist so the
    /// `/v1/admin/allowlist/reload` endpoint can call
    /// [`InstalledAllowlist::install`] for an atomic in-memory swap
    /// (same code path the file-fed startup uses). The release path
    /// continues to hold its trait-object reference via
    /// [`crate::service::KbsService::offline_allowlist`]; both point
    /// at the SAME `InstalledAllowlist` instance, so a reload is
    /// observable on the very next release.
    pub allowlist: Arc<InstalledAllowlist>,
    /// Read side of the per-release evidence archive — the tenant
    /// attestation endpoint (`GET /v1/admin/vm/:vm_id/evidence`) looks up
    /// the latest `SignedEvidenceBundle`. The SAME handle the release
    /// path writes through.
    pub evidence: Arc<dyn EvidenceSink>,
    /// The Phase 2B anti-rollback boot counter, surfaced alongside the
    /// evidence so the tenant sees the attested boot generation.
    pub boot_counter: Arc<dyn BootCounterStore>,
    /// The suppressed-confirm anti-rollback gate's store
    /// (`kbs_core::volume_stamp`). The release path (`KbsService::
    /// process_release`) and the guest-facing confirm route
    /// (`KbsService::process_volume_stamp_confirm`) both hold their OWN
    /// `Arc` to the SAME underlying store — this is a THIRD handle, used
    /// ONLY by `/v1/admin/vm/:vm_id/reset-volume-stamp-suppression` to
    /// clear a VM's unconfirmed-releases counter. Sharing one `Arc`
    /// (not a second `FileVolumeStampStore::open`) keeps the admin
    /// readout/write current — same discipline as `boot_counter` above
    /// (see RA-L-NEW-2 in `wiring.rs`).
    pub volume_stamp: Arc<dyn VolumeStampStore>,
    /// The RESOLVED suppressed-confirm bound this process is running
    /// with — the SAME `Option<u64>` handed to
    /// `kbs_core::release::Deps::max_unconfirmed_releases`. `None` ⇒ the
    /// gate is DISABLED.
    ///
    /// Read ONLY by `GET /v1/admin/volume-stamp`, and only to report it.
    /// Nothing in the admin router may act on this value: the gate is
    /// enforced in exactly one place (release gate 5c), and a second
    /// copy of the decision is a second thing that can drift from it.
    pub configured_max_unconfirmed_releases: Option<u64>,
    /// The EFFECTIVE security posture of this process, computed ONCE at
    /// wiring time from the SAME `Config` the release path was built
    /// from (`hippius_kbs_server::wiring::config_posture`). Served
    /// verbatim by `GET /v1/admin/config`.
    ///
    /// Precomputed rather than derived per request on purpose: it is BY
    /// DEFINITION the posture this process STARTED with, and re-reading
    /// the config file here would answer a different (and misleading)
    /// question — the whole point is to expose what the running process
    /// holds, not what is on disk now.
    ///
    /// Same discipline as `configured_max_unconfirmed_releases`: read
    /// only to report, never to act on.
    pub posture: Arc<AdminConfigPostureResponse>,
}

impl Clone for AdminState {
    fn clone(&self) -> Self {
        Self {
            keyring: Arc::clone(&self.keyring),
            vm_states: Arc::clone(&self.vm_states),
            idempotency: Arc::clone(&self.idempotency),
            audit: Arc::clone(&self.audit),
            limiter: Arc::clone(&self.limiter),
            allowlist: Arc::clone(&self.allowlist),
            evidence: Arc::clone(&self.evidence),
            boot_counter: Arc::clone(&self.boot_counter),
            volume_stamp: Arc::clone(&self.volume_stamp),
            configured_max_unconfirmed_releases: self.configured_max_unconfirmed_releases,
            posture: Arc::clone(&self.posture),
        }
    }
}

/// Build the admin axum router. Wraps the handler in a body-size
/// guard so an oversize body is dropped before this module's logic
/// runs.
pub fn build_admin_router(state: AdminState) -> Router {
    Router::new()
        .route("/v1/admin/vm/:vm_id/register-vm", post(handle_register_vm))
        .route("/v1/admin/vm/:vm_id/activate", post(handle_activate))
        .route("/v1/admin/vm/:vm_id/evidence", get(handle_get_evidence))
        .route(
            "/v1/admin/vm/:vm_id/seed-boot-counter",
            post(handle_seed_boot_counter),
        )
        .route(
            "/v1/admin/vm/:vm_id/reset-volume-stamp-suppression",
            post(handle_reset_volume_stamp_suppression),
        )
        .route(
            "/v1/admin/vm/:vm_id/arm-boot-counter-resync",
            post(handle_arm_boot_counter_resync),
        )
        .route(
            "/v1/admin/volume-stamp",
            get(handle_get_volume_stamp_report),
        )
        .route("/v1/admin/config", get(handle_get_config_posture))
        .route("/v1/admin/allowlist/reload", post(handle_reload_allowlist))
        .with_state(state)
        .layer(RequestBodyLimitLayer::new(MAX_ADMIN_BODY_BYTES))
}

/// Wall-clock seconds since UNIX epoch.
fn now_unix() -> Result<u64, AdminErrorResponse> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .map_err(|_| AdminErrorResponse {
            reason: "clock-unavailable".into(),
            ticket_id: None,
            vm_id: None,
        })
}

/// Require `Content-Type: application/cbor` (same shape as the
/// release transport's [`require_cbor`]).
fn require_cbor(headers: &HeaderMap) -> Result<(), AdminErrorResponse> {
    let Some(ct) = headers.get(header::CONTENT_TYPE) else {
        return Err(AdminErrorResponse {
            reason: "missing-content-type".into(),
            ticket_id: None,
            vm_id: None,
        });
    };
    let s = ct.to_str().map_err(|_| AdminErrorResponse {
        reason: "invalid-content-type".into(),
        ticket_id: None,
        vm_id: None,
    })?;
    let primary = s.split(';').next().unwrap_or("").trim();
    if !primary.eq_ignore_ascii_case(CONTENT_TYPE_CBOR) {
        return Err(AdminErrorResponse {
            reason: "wrong-content-type".into(),
            ticket_id: None,
            vm_id: None,
        });
    }
    Ok(())
}

fn err_response(status: StatusCode, body: &AdminErrorResponse) -> Response {
    let mut bytes = Vec::with_capacity(64);
    if ciborium::ser::into_writer(body, &mut bytes).is_err() {
        return (StatusCode::INTERNAL_SERVER_ERROR, "encode-error").into_response();
    }
    let mut resp = Response::new(Body::from(bytes));
    *resp.status_mut() = status;
    resp.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static(CONTENT_TYPE_CBOR),
    );
    resp
}

fn ok_response(body: &AdminRegisterVmResponse) -> Response {
    let mut bytes = Vec::with_capacity(128);
    if ciborium::ser::into_writer(body, &mut bytes).is_err() {
        return (StatusCode::INTERNAL_SERVER_ERROR, "encode-error").into_response();
    }
    let mut resp = Response::new(Body::from(bytes));
    *resp.status_mut() = StatusCode::OK;
    resp.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static(CONTENT_TYPE_CBOR),
    );
    resp
}

/// JSON 200 for `activate` — vali posts JSON and parses JSON back
/// (`effects._kbs_post` treats any 2xx as success; the echoed fields
/// are for vali's audit log). On a serialisation failure (impossible
/// for this all-owned struct) fall back to a static 500 body.
fn ok_activate_response(body: &AdminActivateResponse) -> Response {
    match serde_json::to_vec(body) {
        Ok(bytes) => {
            let mut resp = Response::new(Body::from(bytes));
            *resp.status_mut() = StatusCode::OK;
            resp.headers_mut().insert(
                header::CONTENT_TYPE,
                HeaderValue::from_static("application/json"),
            );
            resp
        }
        Err(_) => (StatusCode::INTERNAL_SERVER_ERROR, "encode-error").into_response(),
    }
}

/// JSON 200 for `seed-boot-counter` — the operator drives this with
/// curl, so the reply mirrors `activate`'s JSON shape rather than the
/// CBOR the signed-artifact endpoints use.
fn ok_seed_response(body: &AdminSeedBootCounterResponse) -> Response {
    match serde_json::to_vec(body) {
        Ok(bytes) => {
            let mut resp = Response::new(Body::from(bytes));
            *resp.status_mut() = StatusCode::OK;
            resp.headers_mut().insert(
                header::CONTENT_TYPE,
                HeaderValue::from_static("application/json"),
            );
            resp
        }
        Err(_) => (StatusCode::INTERNAL_SERVER_ERROR, "encode-error").into_response(),
    }
}

/// JSON 200 for `reset-volume-stamp-suppression` — same discipline as
/// `activate`/`seed-boot-counter`: a plain control-plane op with no
/// signed ticket, so JSON not CBOR.
fn ok_reset_volume_stamp_suppression_response(
    body: &AdminResetVolumeStampSuppressionResponse,
) -> Response {
    match serde_json::to_vec(body) {
        Ok(bytes) => {
            let mut resp = Response::new(Body::from(bytes));
            *resp.status_mut() = StatusCode::OK;
            resp.headers_mut().insert(
                header::CONTENT_TYPE,
                HeaderValue::from_static("application/json"),
            );
            resp
        }
        Err(_) => (StatusCode::INTERNAL_SERVER_ERROR, "encode-error").into_response(),
    }
}

/// JSON 200 for `arm-boot-counter-resync` — same discipline as its
/// siblings: a plain control-plane op with no signed ticket.
fn ok_arm_resync_response(body: &AdminArmBootCounterResyncResponse) -> Response {
    match serde_json::to_vec(body) {
        Ok(bytes) => {
            let mut resp = Response::new(Body::from(bytes));
            *resp.status_mut() = StatusCode::OK;
            resp.headers_mut().insert(
                header::CONTENT_TYPE,
                HeaderValue::from_static("application/json"),
            );
            resp
        }
        Err(_) => (StatusCode::INTERNAL_SERVER_ERROR, "encode-error").into_response(),
    }
}

fn ok_reload_response(body: &AdminReloadAllowlistResponse) -> Response {
    let mut bytes = Vec::with_capacity(128);
    if ciborium::ser::into_writer(body, &mut bytes).is_err() {
        return (StatusCode::INTERNAL_SERVER_ERROR, "encode-error").into_response();
    }
    let mut resp = Response::new(Body::from(bytes));
    *resp.status_mut() = StatusCode::OK;
    resp.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static(CONTENT_TYPE_CBOR),
    );
    resp
}

fn map_err_to_response(err: &AdminRegisterErr) -> Response {
    let status = StatusCode::from_u16(err.status_code()).unwrap_or(StatusCode::BAD_REQUEST);
    let body = AdminErrorResponse {
        reason: err.reason().to_string(),
        ticket_id: err.ticket_id().map(|s| s.to_string()),
        vm_id: err.vm_id().map(|s| s.to_string()),
    };
    err_response(status, &body)
}

fn map_ok_to_response(ok: &AdminRegisterOk) -> Response {
    let body = AdminRegisterVmResponse {
        v: 1,
        ticket_id: ok.ticket_id.clone(),
        vm_id: ok.vm_id.clone(),
        vm_generation: ok.vm_generation,
        host: ok.host.clone(),
        lease_id: ok.lease_id.clone(),
        applied_at: ok.applied_at,
        cached: ok.cached,
    };
    ok_response(&body)
}

/// `GET /v1/admin/vm/{vm_id}/evidence` — the most recent KBS-signed
/// attestation evidence for a VM, plus its anti-rollback boot counter.
///
/// Read-only. The `SignedEvidenceBundle` is already KBS-L0-signed, so a
/// tenant can verify the SNP report + VCEK chain + signature OFFLINE
/// against AMD's root + the pinned KBS L0 key. Returns 404 when no KEK
/// release has been recorded for the VM (it never attested / never
/// booted). No secret bytes — every field is already-public attestation
/// data (`hippius_types::evidence_bundle` docs).
pub async fn handle_get_evidence(
    State(state): State<AdminState>,
    Path(vm_id): Path<String>,
) -> Response {
    let bundle = match state.evidence.latest_for_vm(&vm_id) {
        Ok(Some(b)) => b,
        Ok(None) => {
            return (
                StatusCode::NOT_FOUND,
                Json(serde_json::json!({ "error": "no-evidence", "vm_id": vm_id })),
            )
                .into_response();
        }
        Err(_) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({ "error": "evidence-read-failed" })),
            )
                .into_response();
        }
    };
    let body = match EvidenceBundle::decode(&bundle.body) {
        Ok(b) => b,
        Err(_) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({ "error": "evidence-decode-failed" })),
            )
                .into_response();
        }
    };
    // The boot counter is independent of the evidence file — best-effort.
    let boot_counter = state.boot_counter.get(&vm_id).unwrap_or(0);

    let resp = serde_json::json!({
        "vm_id": body.vm_id,
        "tenant_id": body.tenant_id,
        "ticket_id": body.ticket_id,
        "granted_at_unix": body.granted_at_unix,
        // The attested SEV-SNP launch digest = the §22-admitted measurement.
        "measurement_hex": hex::encode(body.measurement),
        "allowlist_epoch": body.allowlist_epoch,
        "allowlist_manifest_digest_hex": hex::encode(body.allowlist_manifest_digest),
        // The raw SNP report the guest emitted (1184 B) — the tenant
        // re-verifies it against the VCEK chain below.
        "snp_report_hex": hex::encode(&body.snp_report_bytes),
        "vcek_chain_pem": String::from_utf8_lossy(&body.vcek_chain_pem),
        "ticket_cose_hex": hex::encode(&body.ticket_cose_bytes),
        "kbs_signer_pubkey_hex": hex::encode(body.kbs_signer_pubkey),
        // The KBS L0 signature over `bundle.body` — self-certifying.
        "kbs_signature_hex": hex::encode(&bundle.sig),
        "boot_counter": boot_counter,
    });
    (StatusCode::OK, Json(resp)).into_response()
}

/// Default `?bound=` — the value an operator gets by REMOVING
/// `storage.max_unconfirmed_releases` from the config, i.e. the most
/// likely thing step 4 of the cutover actually does.
const DEFAULT_EVALUATED_BOUND: u64 = kbs_core::volume_stamp::MAX_UNCONFIRMED_RELEASES;

/// Parse `?bound=N` out of a raw query string. `None` ⇒ absent.
///
/// Hand-rolled rather than `serde_urlencoded` so the one parameter this
/// route accepts has one obvious parse and a duplicate `bound=` cannot
/// resolve to a surprising one (first wins, explicitly).
fn parse_bound_param(query: Option<&str>) -> Result<Option<u64>, ()> {
    let Some(q) = query else { return Ok(None) };
    for pair in q.split('&') {
        let Some((k, v)) = pair.split_once('=') else {
            continue;
        };
        if k == "bound" {
            return v.parse::<u64>().map(Some).map_err(|_| ());
        }
    }
    Ok(None)
}

/// `GET /v1/admin/volume-stamp?bound=N` — the READ side of the
/// suppressed-confirm anti-rollback gate (`kbs_core::volume_stamp`).
///
/// ## Why this exists
///
/// `deploy/gitops/apps/kbs/values.yaml` ships `maxUnconfirmedReleases:
/// 0`, which DISABLES the gate, and documents a 4-step cutover to arm
/// it. Step 3 is "verify confirms are arriving fleet-wide". That step
/// was not performable: every path that touched the store was a WRITE
/// (the guest's `/v1/kbs/volume-stamp/confirm`, the release path's
/// `note_release`, this module's `reset-volume-stamp-suppression`), and
/// the store lives on an emptyDir inside a Kata CVM where `kubectl exec`
/// does not work — so there was no out-of-band read either. The operator
/// was asked to confirm a condition the system gave them no way to
/// observe, which leaves only the "arm blind" the cutover text itself
/// warns against. This is that read path.
///
/// ## Why it is on the ADMIN listener, and why it is STRICTER than its
/// siblings
///
/// The data is per-tenant operational state: which VMs exist, how often
/// each has been released, and — most usefully to an attacker — exactly
/// which VMs are one release away from being refused. On a fleet where
/// the gate IS armed that is a targeting list for a denial of service.
///
/// The admin listener is the right place (it already holds the
/// `volume_stamp` handle, it has no public Ingress, and it is the
/// listener the operator already drives), but it is TODAY served
/// UNAUTHENTICATED: `admin.require_mtls=false` with no TLS material is
/// an explicit, warned-about opt-in, and a CiliumNetworkPolicy is then
/// the only control. Adding an open GET there would trade an unarmable
/// gate for a new disclosure.
///
/// So this handler refuses unless the request carries [`PeerCertInfo`] —
/// i.e. unless it arrived over a client certificate that
/// `admin_tls::serve_admin_mtls` VERIFIED against the pinned operator
/// CA. Under today's plaintext opt-in it answers 403 to everyone,
/// including the operator, and it starts answering the moment the admin
/// PKI is issued. That ordering is the right way round: `require_mtls`
/// is a prerequisite of the cutover, not a casualty of it — a fleet-wide
/// anti-rollback decision taken on the strength of a readout anyone on
/// the pod network could have served is not a verification.
///
/// The gate is the per-request extension and NOT a config-derived
/// "mtls_enforced" boolean on purpose. The extension is written by the
/// code that actually verified the certificate, so it cannot disagree
/// with what terminated the connection; a boolean plumbed from config
/// can, and this repository has live examples of a rendered config
/// disagreeing with what is running. It also means that if this router
/// is ever bound on a second, plaintext socket, this route is closed by
/// construction rather than by someone remembering a flag.
///
/// ## Why it is not a write primitive
///
/// It calls exactly one store method,
/// [`kbs_core::volume_stamp::VolumeStampStore::snapshot`], whose
/// contract is read-only and whose purity is pinned by
/// `kbs_core::volume_stamp::tests::snapshot_is_a_pure_read_*` (it does
/// not even create the backing file). Nothing here can advance a stamp,
/// increment a release count, or clear a suppression streak — clearing
/// remains the exclusive privilege of a real guest confirm or the
/// audited `reset-volume-stamp-suppression` write.
///
/// Reads are not appended to the admin audit chain, matching
/// `GET …/evidence`: the chain records state CHANGES, the audit file is
/// an emptyDir, and a polled read would bloat it without recording
/// anything that happened to the system. The client certificate is the
/// accountability control for reads.
///
/// ## `?bound=`
///
/// The rows are evaluated against a PROSPECTIVE bound — the value the
/// operator intends to arm at — not the live one, because while the gate
/// is disabled there is no live bound and the answer would be
/// unconditionally green. Defaults to
/// [`kbs_core::volume_stamp::MAX_UNCONFIRMED_RELEASES`] (what removing
/// the config key gives you). `bound=0` is REFUSED: in the operator
/// vocabulary `0` means "disabled", so silently evaluating it as a
/// numeric bound would return the exact opposite of what was asked
/// (every VM refused) for an input the operator meant as "off".
///
/// Errors:
/// - 403 `admin-client-cert-required` — the request did not arrive over
///   a verified client certificate.
/// - 429 `rate-limited` — same gateway bucket as its siblings.
/// - 400 `bound-not-a-number` / 400 `bound-zero`.
/// - 500 `volume-stamp-read-failed` — the store could not be read.
pub async fn handle_get_volume_stamp_report(
    State(state): State<AdminState>,
    request: Request,
) -> Response {
    // 1. Client-cert gate FIRST — before the limiter, before the store.
    //    On a plaintext listener this route consults nothing at all.
    if request.extensions().get::<PeerCertInfo>().is_none() {
        return err_response(
            StatusCode::FORBIDDEN,
            &AdminErrorResponse {
                reason: "admin-client-cert-required".into(),
                ticket_id: None,
                vm_id: None,
            },
        );
    }

    // 2. Rate limit at the gateway (same posture as its siblings).
    if !state.limiter.try_acquire() {
        let mut resp = err_response(
            StatusCode::TOO_MANY_REQUESTS,
            &AdminErrorResponse {
                reason: "rate-limited".into(),
                ticket_id: None,
                vm_id: None,
            },
        );
        resp.headers_mut()
            .insert(header::RETRY_AFTER, HeaderValue::from_static("1"));
        return resp;
    }

    // 3. The prospective bound.
    let evaluated_bound = match parse_bound_param(request.uri().query()) {
        Ok(Some(0)) => {
            return err_response(
                StatusCode::BAD_REQUEST,
                &AdminErrorResponse {
                    reason: "bound-zero".into(),
                    ticket_id: None,
                    vm_id: None,
                },
            );
        }
        Ok(Some(b)) => b,
        Ok(None) => DEFAULT_EVALUATED_BOUND,
        Err(()) => {
            return err_response(
                StatusCode::BAD_REQUEST,
                &AdminErrorResponse {
                    reason: "bound-not-a-number".into(),
                    ticket_id: None,
                    vm_id: None,
                },
            );
        }
    };

    // 4. The one store call — read-only.
    let rows = match state.volume_stamp.snapshot() {
        Ok(r) => r,
        Err(_) => {
            return err_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                &AdminErrorResponse {
                    reason: "volume-stamp-read-failed".into(),
                    ticket_id: None,
                    vm_id: None,
                },
            );
        }
    };
    let readiness = kbs_core::volume_stamp::arming_readiness(&rows, evaluated_bound);

    let body = AdminVolumeStampReportResponse {
        v: 1,
        evaluated_bound,
        configured_bound: state.configured_max_unconfirmed_releases,
        gate_armed: state.configured_max_unconfirmed_releases.is_some(),
        vms: readiness.vms,
        never_confirmed: readiness.never_confirmed,
        would_refuse_now: readiness.would_refuse_now,
        ready_to_arm: readiness.ready_to_arm,
        rows: rows
            .iter()
            .map(|r| AdminVolumeStampRow {
                vm_id: r.vm_id.clone(),
                confirmed: r.confirmed,
                unconfirmed_releases: r.unconfirmed_releases,
                has_ever_confirmed: r.has_ever_confirmed(),
                would_refuse_next_release: r.would_refuse_next_release(evaluated_bound),
            })
            .collect(),
    };
    // JSON, like `activate`/`seed-boot-counter`: an operator drives this
    // with curl + jq, not a Rust client.
    (StatusCode::OK, Json(body)).into_response()
}

/// `GET /v1/admin/config` — the EFFECTIVE security posture of the
/// RUNNING process ([`AdminConfigPostureResponse`]).
///
/// ## Why a whole endpoint for "what is in the config"
///
/// Because the ConfigMap is NOT what is in the config. `Config::load`
/// runs once at startup and the KBS Deployment carries no
/// `checksum/config` annotation — correctly, since rolling the pod
/// wipes its `state`/`audit`/`evidence` emptyDirs inside a Kata CVM. So
/// an edited ConfigMap sits next to a process that has never read it,
/// for as long as the pod lives, while the gitops badge says `Synced`
/// and `Healthy`. That is not a hypothetical: on 2026-08-13 the
/// suppressed-confirm anti-rollback bound was raised `0 → 3` and the
/// rendered ConfigMap said so, while the 152-minute-old process was
/// still running with the gate DISABLED.
///
/// `GET /v1/admin/volume-stamp` already exposes that ONE key
/// (`configured_bound`) from the running process, which is why the
/// divergence was caught at all. This endpoint generalises it so the
/// same monitor can diff the rest of the posture —
/// `require_wrapped_kek`, the admin listener mode actually chosen, the
/// launch-policy floor, whether the evidence and live-attestation sinks
/// are wired — instead of one key.
///
/// ## Auth, and the same stricter-than-its-siblings gate
///
/// Identical to [`handle_get_volume_stamp_report`]: it refuses unless
/// the request carries [`PeerCertInfo`], i.e. unless `admin_tls::
/// serve_admin_mtls` VERIFIED a client cert against the pinned operator
/// CA. The admin listener can be served UNAUTHENTICATED
/// (`admin.require_mtls=false` with no material, network policy as the
/// only control); an open GET there would publish this fleet's security
/// posture — which gates are off, whether a dev override is live — to
/// anything that can reach the port. That is a shopping list. The gate
/// is the per-request extension rather than a config-derived boolean so
/// it cannot disagree with what actually terminated the connection.
///
/// ## Read-only by construction
///
/// It serves a value computed at wiring time and stored in
/// [`AdminState::posture`]. It consults no store, touches no file, and
/// cannot mutate anything. Not audit-logged, matching the other admin
/// READS (`…/evidence`, `…/volume-stamp`): the chain records state
/// CHANGES, it lives on an emptyDir, and a polled read would bloat it
/// without recording anything that happened to the system.
///
/// ## No material
///
/// See [`AdminConfigPostureResponse`] for the field-by-field rule and
/// what was deliberately left out. Enforced by
/// `binaries/kbs-server/tests/admin_config_posture.rs`, which builds
/// the posture from a config whose every path/URL/secret is a canary
/// string and asserts none of them appears in the response.
///
/// Errors:
/// - 403 `admin-client-cert-required` — no verified client certificate.
/// - 429 `rate-limited` — same gateway bucket as its siblings.
pub async fn handle_get_config_posture(
    State(state): State<AdminState>,
    request: Request,
) -> Response {
    // 1. Client-cert gate FIRST — before the limiter, before anything.
    if request.extensions().get::<PeerCertInfo>().is_none() {
        return err_response(
            StatusCode::FORBIDDEN,
            &AdminErrorResponse {
                reason: "admin-client-cert-required".into(),
                ticket_id: None,
                vm_id: None,
            },
        );
    }

    // 2. Rate limit at the gateway (same posture as its siblings).
    if !state.limiter.try_acquire() {
        let mut resp = err_response(
            StatusCode::TOO_MANY_REQUESTS,
            &AdminErrorResponse {
                reason: "rate-limited".into(),
                ticket_id: None,
                vm_id: None,
            },
        );
        resp.headers_mut()
            .insert(header::RETRY_AFTER, HeaderValue::from_static("1"));
        return resp;
    }

    // 3. Serve the precomputed posture. JSON, like its sibling reads:
    //    an operator drives this with curl + jq, and so does the
    //    synthetic monitor.
    (StatusCode::OK, Json(state.posture.as_ref())).into_response()
}

/// `POST /v1/admin/vm/{vm_id}/register-vm` — register a VmState.
pub async fn handle_register_vm(
    State(state): State<AdminState>,
    Path(url_vm_id): Path<String>,
    request: Request,
) -> Response {
    // 1. Rate limit at the gateway.
    if !state.limiter.try_acquire() {
        let mut resp = err_response(
            StatusCode::TOO_MANY_REQUESTS,
            &AdminErrorResponse {
                reason: "rate-limited".into(),
                ticket_id: None,
                vm_id: None,
            },
        );
        resp.headers_mut()
            .insert(header::RETRY_AFTER, HeaderValue::from_static("1"));
        return resp;
    }

    let (parts, body) = request.into_parts();
    if let Err(e) = require_cbor(&parts.headers) {
        let status = match e.reason.as_str() {
            "wrong-content-type" => StatusCode::UNSUPPORTED_MEDIA_TYPE,
            _ => StatusCode::BAD_REQUEST,
        };
        return err_response(status, &e);
    }

    // 2. Pull peer cert info from request extensions if the TLS
    //    layer populated it.
    let peer = parts.extensions.get::<PeerCertInfo>().cloned();

    // 3. Read the body (cap = MAX_ADMIN_BODY_BYTES — extra safety
    //    even though tower-http already enforced).
    let bytes = match to_bytes(body, MAX_ADMIN_BODY_BYTES).await {
        Ok(b) => b,
        Err(_) => {
            return err_response(
                StatusCode::PAYLOAD_TOO_LARGE,
                &AdminErrorResponse {
                    reason: "body-too-large".into(),
                    ticket_id: None,
                    vm_id: None,
                },
            );
        }
    };

    // 4. Apply.
    let now = match now_unix() {
        Ok(n) => n,
        Err(e) => return err_response(StatusCode::INTERNAL_SERVER_ERROR, &e),
    };
    let outcome = process_admin_register(
        &bytes,
        &url_vm_id,
        state.keyring.as_ref(),
        state.vm_states.as_ref(),
        state.idempotency.as_ref(),
        now,
    );

    // 5. Audit-log the outcome regardless of success/failure.
    let mut body_sha = [0u8; 32];
    body_sha.copy_from_slice(Sha256::digest(&bytes).as_slice());
    let _ = record_admin_register_outcome(
        state.audit.as_ref(),
        &url_vm_id,
        &body_sha,
        peer.as_ref().map(|p| p.san_uri.as_str()),
        peer.as_ref().map(|p| p.serial_hex.as_str()),
        &outcome,
        now,
    );

    // 6. HTTP response.
    match &outcome {
        Ok(ok) => map_ok_to_response(ok),
        Err(e) => map_err_to_response(e),
    }
}

/// `POST /v1/admin/vm/{vm_id}/activate` — §25 destination
/// re-activation (the split-brain fence on the KBS side).
///
/// **vali calls this ONLY after it has cryptographically verified the
/// source guest's signed `stopped{}` ack at the source generation**
/// (`vali/apps/orchestration/service.py::_h_mig_awaiting_source_ack`
/// gates `_h_mig_dest_activating`, which is the sole caller of
/// `effects.kbs_activate_dest`). This handler transitions the KBS
/// VmState `Active{old_gen,source} → Migrating{old_gen,new_gen,
/// source,dest}` — the moment after which
/// [`kbs_core::lifecycle::check_releasable`] lets ONLY the destination
/// attesting at `new_gen` unlock the rootfs KEK, while permanently
/// fencing out the source at `old_gen`. Two copies can therefore never
/// both unlock the same encrypted disk.
///
/// Auth: mTLS at the listener level (same client-cert allowlist
/// `register-vm` inherits). Body: JSON [`AdminActivateRequest`] — vali
/// posts it via `effects._kbs_post` (stdlib `urllib`, JSON). Plain
/// control-plane fields (`dest_node_id`, `new_gen`); no signed ticket,
/// so unlike `register-vm` it is JSON, not CBOR. The cryptographic
/// anchor stays the SAME encrypted disk + the SNP re-attestation at
/// `new_gen` the dest must pass before the KEK releases.
///
/// Idempotent: a re-drive that finds the VM already `Migrating` to this
/// exact `(new_gen, dest)` returns 200. A divergent re-target, or an
/// activate over a non-`Active` state, is a 409 — the fence never
/// force-moves. A `new_gen` that does not strictly exceed the stored
/// generation is a 409 `activate-not-monotonic` and writes nothing.
///
/// Every call — applied, cached, or refused — is appended to the
/// hash-chained admin audit log with `op="activate"` and the mTLS peer's
/// SAN/serial, so the one write that moves the fence is attributable.
pub async fn handle_activate(
    State(state): State<AdminState>,
    Path(url_vm_id): Path<String>,
    request: Request,
) -> Response {
    // 1. Rate limit at the gateway (same posture as register-vm).
    if !state.limiter.try_acquire() {
        let mut resp = err_response(
            StatusCode::TOO_MANY_REQUESTS,
            &AdminErrorResponse {
                reason: "rate-limited".into(),
                ticket_id: None,
                vm_id: None,
            },
        );
        resp.headers_mut()
            .insert(header::RETRY_AFTER, HeaderValue::from_static("1"));
        return resp;
    }

    let (parts, body) = request.into_parts();
    // Peer cert info for §13 audit attribution. `activate` is the §25
    // split-brain fence — the one admin write that moves which host may
    // unlock a tenant disk — so it is attributed and audited exactly
    // like `register-vm`, not left as vali's word alone.
    let peer = parts.extensions.get::<PeerCertInfo>().cloned();

    // 2. Read + JSON-decode the body (cap = MAX_ADMIN_BODY_BYTES).
    let bytes = match to_bytes(body, MAX_ADMIN_BODY_BYTES).await {
        Ok(b) => b,
        Err(_) => {
            return err_response(
                StatusCode::PAYLOAD_TOO_LARGE,
                &AdminErrorResponse {
                    reason: "body-too-large".into(),
                    ticket_id: None,
                    vm_id: None,
                },
            );
        }
    };
    let mut body_sha = [0u8; 32];
    body_sha.copy_from_slice(Sha256::digest(&bytes).as_slice());

    let now = match now_unix() {
        Ok(n) => n,
        Err(e) => return err_response(StatusCode::INTERNAL_SERVER_ERROR, &e),
    };

    let req: AdminActivateRequest = match serde_json::from_slice(&bytes) {
        Ok(r) => r,
        Err(_) => {
            // Audit the malformed attempt too — a garbled body against
            // the fence route is worth seeing in the chain.
            let outcome = Err(AdminActivateErr::BadRequest("activate-body-decode"));
            let _ = record_admin_activate_outcome(
                state.audit.as_ref(),
                &url_vm_id,
                &body_sha,
                peer.as_ref().map(|p| p.san_uri.as_str()),
                peer.as_ref().map(|p| p.serial_hex.as_str()),
                &outcome,
                now,
            );
            return err_response(
                StatusCode::BAD_REQUEST,
                &AdminErrorResponse {
                    reason: "activate-body-decode".into(),
                    ticket_id: None,
                    vm_id: Some(url_vm_id.clone()),
                },
            );
        }
    };

    // 3. Apply the fence transition via the kbs-core verdict function.
    let outcome = process_admin_activate(
        &url_vm_id,
        req.new_gen,
        &req.dest_node_id,
        state.vm_states.as_ref(),
    );

    // 4. Audit-log the outcome regardless of success/failure.
    let _ = record_admin_activate_outcome(
        state.audit.as_ref(),
        &url_vm_id,
        &body_sha,
        peer.as_ref().map(|p| p.san_uri.as_str()),
        peer.as_ref().map(|p| p.serial_hex.as_str()),
        &outcome,
        now,
    );

    // 5. HTTP response.
    match outcome {
        Ok(ok) => ok_activate_response(&AdminActivateResponse {
            v: 1,
            vm_id: ok.vm_id,
            old_gen: ok.old_gen,
            new_gen: ok.new_gen,
            dest: ok.dest,
            cached: ok.cached,
        }),
        Err(e) => {
            let status = StatusCode::from_u16(e.status_code()).unwrap_or(StatusCode::BAD_REQUEST);
            err_response(
                status,
                &AdminErrorResponse {
                    reason: e.reason().to_string(),
                    ticket_id: None,
                    vm_id: Some(url_vm_id.clone()),
                },
            )
        }
    }
}

/// `POST /v1/admin/vm/{vm_id}/seed-boot-counter` — operator disaster
/// recovery for a WIPED anti-rollback boot counter.
///
/// ## Why
///
/// The KBS state dir is an `emptyDir` on a Kata CVM: a pod restart
/// wipes `boot-counters.json`, and the store cannot be read back from
/// the host (distroless, SNP-encrypted memory) — it has to be
/// re-established through this API. A wiped store expects `1` from
/// every VM while a guest that has booted N times submits `N + 1`, and
/// the mismatch is fail-closed: those tenants never unlock again. The
/// authoritative value survives on the miner-side per-VM state disk
/// (`/var/lib/hippius-miner/state/<vm>.raw` — plain ext4 with a
/// `boot-counter` text file), which is what the operator posts here.
///
/// ## Why this is neither a rollback hole nor a DoS lever
///
/// The write does exactly ONE thing — restore a WIPED counter to a
/// plausible value — and all three guards are enforced inside the store,
/// under the store's own lock (no check-then-write window). Each writes
/// NOTHING — not the cache, not the file:
///
/// - `stored != 0` ⇒ 409 `seed-already-recovered`. Against a live VM
///   this endpoint is INERT, so admin-listener access does not buy a
///   fleet-wide denial of service. Consequence, deliberately fail-safe:
///   re-running a recovery REFUSES instead of overwriting.
/// - `counter > MAX_SEED_COUNTER` ⇒ 400 `seed-above-cap`. Without it,
///   one request could brick a VM by setting a counter its guest can
///   never reach from disk.
/// - `counter <= stored` ⇒ 409 `seed-not-monotonic`. A seed may only
///   ever RAISE, so it can never re-admit a snapshot whose counter has
///   already been burned.
///
/// `check_only` / `commit` — the real release gate — are untouched:
/// seeding to N leaves the store in exactly the state N real boots would
/// have left it in.
///
/// Auth: mTLS + network policy at the ADMIN LISTENER, identical to
/// `register-vm` / `activate` / `allowlist/reload`. This route is
/// registered ONLY on [`build_admin_router`]; the public-Ingress
/// release router does not serve it.
///
/// Body: JSON [`AdminSeedBootCounterRequest`] (`{"counter": N}`) — a
/// plain control-plane integer, like `activate`, so JSON not CBOR.
/// Every call (applied or refused) is appended to the hash-chained
/// admin audit log with `op="seed-boot-counter"`.
///
/// Errors (each refusal is distinct so an operator can tell "already
/// recovered" from "implausible value" from "rollback attempt"; NONE of
/// them mutates the store):
/// - 429 `rate-limited` — same gateway bucket as its siblings.
/// - 413 `body-too-large`.
/// - 400 `seed-body-decode` — body was not the expected JSON.
/// - 400 `counter-zero` — `0` is never a legitimate recovered value.
/// - 400 `seed-above-cap` — counter exceeds `MAX_SEED_COUNTER`.
/// - 409 `seed-already-recovered` — the row is not wiped; re-running a
///   recovery REFUSES rather than overwriting.
/// - 409 `seed-not-monotonic` — anti-rollback refusal.
/// - 500 `internal-error` — counter store failed; nothing written.
pub async fn handle_seed_boot_counter(
    State(state): State<AdminState>,
    Path(url_vm_id): Path<String>,
    request: Request,
) -> Response {
    // 1. Rate limit at the gateway (same posture as register-vm).
    if !state.limiter.try_acquire() {
        let mut resp = err_response(
            StatusCode::TOO_MANY_REQUESTS,
            &AdminErrorResponse {
                reason: "rate-limited".into(),
                ticket_id: None,
                vm_id: None,
            },
        );
        resp.headers_mut()
            .insert(header::RETRY_AFTER, HeaderValue::from_static("1"));
        return resp;
    }

    let (parts, body) = request.into_parts();
    // Peer cert info for §13 audit attribution (same as register-vm).
    let peer = parts.extensions.get::<PeerCertInfo>().cloned();

    // 2. Read the body (cap = MAX_ADMIN_BODY_BYTES).
    let bytes = match to_bytes(body, MAX_ADMIN_BODY_BYTES).await {
        Ok(b) => b,
        Err(_) => {
            return err_response(
                StatusCode::PAYLOAD_TOO_LARGE,
                &AdminErrorResponse {
                    reason: "body-too-large".into(),
                    ticket_id: None,
                    vm_id: None,
                },
            );
        }
    };
    let mut body_sha = [0u8; 32];
    body_sha.copy_from_slice(Sha256::digest(&bytes).as_slice());

    let now = match now_unix() {
        Ok(n) => n,
        Err(e) => return err_response(StatusCode::INTERNAL_SERVER_ERROR, &e),
    };

    let req: AdminSeedBootCounterRequest = match serde_json::from_slice(&bytes) {
        Ok(r) => r,
        Err(_) => {
            // Audit the malformed attempt too — a garbled body against
            // this route is worth seeing in the chain.
            let outcome = Err(kbs_core::admin::AdminSeedErr::BadRequest(
                "seed-body-decode",
            ));
            let _ = record_admin_seed_outcome(
                state.audit.as_ref(),
                &url_vm_id,
                &body_sha,
                peer.as_ref().map(|p| p.san_uri.as_str()),
                peer.as_ref().map(|p| p.serial_hex.as_str()),
                &outcome,
                now,
            );
            return err_response(
                StatusCode::BAD_REQUEST,
                &AdminErrorResponse {
                    reason: "seed-body-decode".into(),
                    ticket_id: None,
                    vm_id: Some(url_vm_id.clone()),
                },
            );
        }
    };

    // 3. Apply — the monotonic guard lives in kbs-core + the store.
    let outcome =
        process_admin_seed_boot_counter(&url_vm_id, req.counter, state.boot_counter.as_ref());

    // 4. Audit-log the outcome regardless of success/failure.
    let _ = record_admin_seed_outcome(
        state.audit.as_ref(),
        &url_vm_id,
        &body_sha,
        peer.as_ref().map(|p| p.san_uri.as_str()),
        peer.as_ref().map(|p| p.serial_hex.as_str()),
        &outcome,
        now,
    );

    // 5. HTTP response.
    match outcome {
        Ok(ok) => ok_seed_response(&AdminSeedBootCounterResponse {
            v: 1,
            vm_id: ok.vm_id,
            previous: ok.previous,
            counter: ok.counter,
        }),
        Err(e) => {
            let status = StatusCode::from_u16(e.status_code()).unwrap_or(StatusCode::BAD_REQUEST);
            err_response(
                status,
                &AdminErrorResponse {
                    reason: e.reason().to_string(),
                    ticket_id: None,
                    vm_id: Some(url_vm_id.clone()),
                },
            )
        }
    }
}

/// `POST /v1/admin/vm/{vm_id}/reset-volume-stamp-suppression` —
/// operator recovery for the suppressed-confirm anti-rollback gate
/// (`kbs_core::volume_stamp`).
///
/// ## Why
///
/// `kbs_core::release::run` gate 5c refuses a release once a VM has more
/// than `kbs_core::volume_stamp::MAX_UNCONFIRMED_RELEASES` releases with
/// no intervening confirm — the fail-closed response to a miner dropping
/// every `/v1/kbs/volume-stamp/confirm` it relays. That refusal can
/// never self-heal: a refused release means no boot, which means no
/// confirm, so the guest has no path to clear it. This endpoint is that
/// path, for an operator only.
///
/// ## Why this is neither a rollback hole nor a DoS lever
///
/// The write does exactly ONE thing — clear the unconfirmed-releases
/// counter — and it NEVER touches the confirmed volume stamp (the
/// actual anti-rollback reference). A reset against a VM that was never
/// blocked is a harmless no-op (`cleared == 0`), so unlike `seed-boot-
/// counter` there is no "already recovered" refusal to protect: nothing
/// here can brick a live VM, and nothing here can roll one back either.
///
/// Auth: mTLS + network policy at the ADMIN LISTENER, identical to every
/// other route in this module. Registered ONLY here — the public-Ingress
/// release router (which serves `/v1/kbs/volume-stamp/confirm`) does not
/// serve it and never will; a miner reaching this route would be exactly
/// the party the suppression gate exists to constrain.
///
/// Body: none required (control-plane op — `{vm_id}` from the URL is the
/// only input) — same JSON-not-CBOR discipline as `activate`/
/// `seed-boot-counter` since there is no signed ticket. Every call
/// (applied or refused) is appended to the hash-chained admin audit log
/// with `op="reset-volume-stamp-suppression"`.
pub async fn handle_reset_volume_stamp_suppression(
    State(state): State<AdminState>,
    Path(url_vm_id): Path<String>,
    request: Request,
) -> Response {
    // 1. Rate limit at the gateway (same posture as its siblings).
    if !state.limiter.try_acquire() {
        let mut resp = err_response(
            StatusCode::TOO_MANY_REQUESTS,
            &AdminErrorResponse {
                reason: "rate-limited".into(),
                ticket_id: None,
                vm_id: None,
            },
        );
        resp.headers_mut()
            .insert(header::RETRY_AFTER, HeaderValue::from_static("1"));
        return resp;
    }

    let (parts, body) = request.into_parts();
    // Peer cert info for §13 audit attribution (same as every other op).
    let peer = parts.extensions.get::<PeerCertInfo>().cloned();

    // 2. Read the body (cap = MAX_ADMIN_BODY_BYTES). No fields are
    //    decoded from it — the op takes no input beyond the URL — but it
    //    IS hashed into the audit record, like every other admin write.
    let bytes = match to_bytes(body, MAX_ADMIN_BODY_BYTES).await {
        Ok(b) => b,
        Err(_) => {
            return err_response(
                StatusCode::PAYLOAD_TOO_LARGE,
                &AdminErrorResponse {
                    reason: "body-too-large".into(),
                    ticket_id: None,
                    vm_id: None,
                },
            );
        }
    };
    let mut body_sha = [0u8; 32];
    body_sha.copy_from_slice(Sha256::digest(&bytes).as_slice());

    let now = match now_unix() {
        Ok(n) => n,
        Err(e) => return err_response(StatusCode::INTERNAL_SERVER_ERROR, &e),
    };

    // 3. Apply — the store is the only thing that can refuse (empty
    //    vm_id), and it can never move the confirmed stamp.
    let outcome =
        process_admin_reset_volume_stamp_suppression(&url_vm_id, state.volume_stamp.as_ref());

    // 4. Audit-log the outcome regardless of success/failure.
    let _ = record_admin_reset_volume_stamp_suppression_outcome(
        state.audit.as_ref(),
        &url_vm_id,
        &body_sha,
        peer.as_ref().map(|p| p.san_uri.as_str()),
        peer.as_ref().map(|p| p.serial_hex.as_str()),
        &outcome,
        now,
    );

    // 5. HTTP response.
    match outcome {
        Ok(ok) => {
            ok_reset_volume_stamp_suppression_response(&AdminResetVolumeStampSuppressionResponse {
                v: 1,
                vm_id: ok.vm_id,
                cleared: ok.cleared,
            })
        }
        Err(e) => {
            let status = StatusCode::from_u16(e.status_code()).unwrap_or(StatusCode::BAD_REQUEST);
            err_response(
                status,
                &AdminErrorResponse {
                    reason: e.reason().to_string(),
                    ticket_id: None,
                    vm_id: Some(url_vm_id.clone()),
                },
            )
        }
    }
}

/// `POST /v1/admin/vm/{vm_id}/arm-boot-counter-resync` — operator
/// disaster recovery for the OTHER direction of boot-counter loss from
/// `seed-boot-counter`.
///
/// ## Why
///
/// `seed-boot-counter` repairs a KBS that forgot, from the miner's
/// state disk. This repairs a GUEST that forgot, from the KBS's own
/// counter. The guest's copy lives on `/var/lib/hippius-miner/state/
/// <vm>.raw` — one unreplicated 1 MiB plaintext ext4 on the host of the
/// party we do not trust. Lose it and the guest submits `1` forever
/// while the KBS holds `N`; `check_only` refuses before any Vault read,
/// `seed` refuses because the row is live, and the counter may never be
/// walked down. Until this route existed, that was a permanent brick
/// with no recovery — one file on an untrusted host was a
/// data-destruction primitive.
///
/// ## Why this is neither a rollback hole nor a DoS lever
///
/// - It writes NO counter. It sets a one-shot arm; the release that
///   consumes it commits `stored + 1` — never the value the guest
///   submitted — so the counter moves exactly as one normal boot moves
///   it, and no burned boot is re-admitted.
/// - It cannot brick a VM. Unlike `seed-boot-counter` there is no
///   operator-chosen number to get wrong (hence no cap to enforce): the
///   re-baseline target is the KBS's own `stored + 1`, echoed to the
///   guest in the SIGNED release response and persisted by the guest.
/// - Against a `stored == 0` row it refuses (409
///   `resync-nothing-to-resync`) rather than leaving a silent arm on a
///   row that will later be some VM's first boot.
/// - It grants a hostile miner nothing: the submitted counter comes
///   from a file the miner can already read and write, so it could
///   always submit the accepted value. What an arm costs is one boot of
///   DETECTION on a signal that was never miner-proof. The gate that
///   binds anti-rollback to the ENCRYPTED VOLUME is
///   `kbs_core::volume_stamp`, and this route does not touch it.
///
/// Auth: mTLS + network policy at the ADMIN LISTENER, identical to every
/// other route in this module. Registered ONLY on [`build_admin_router`]
/// — a miner reaching it could re-baseline its own tenants' counters,
/// which is exactly the party the counter exists to constrain. That is
/// also why the recovery is an explicit operator action rather than the
/// KBS auto-re-baselining whenever it sees the `boot-counter-lost`
/// refusal shape: that shape is miner-forgeable, a human's belief that
/// a host really did lose its disk is not.
///
/// Body: none required (the URL's `{vm_id}` is the only input) — same
/// JSON-not-CBOR discipline as `activate`/`seed-boot-counter`. Every
/// call (applied or refused) is appended to the hash-chained admin audit
/// log with `op="arm-boot-counter-resync"`; that record is the only
/// durable trace that a resync was authorised.
pub async fn handle_arm_boot_counter_resync(
    State(state): State<AdminState>,
    Path(url_vm_id): Path<String>,
    request: Request,
) -> Response {
    // 1. Rate limit at the gateway (same posture as its siblings).
    if !state.limiter.try_acquire() {
        let mut resp = err_response(
            StatusCode::TOO_MANY_REQUESTS,
            &AdminErrorResponse {
                reason: "rate-limited".into(),
                ticket_id: None,
                vm_id: None,
            },
        );
        resp.headers_mut()
            .insert(header::RETRY_AFTER, HeaderValue::from_static("1"));
        return resp;
    }

    let (parts, body) = request.into_parts();
    // Peer cert info for §13 audit attribution (same as every other op).
    let peer = parts.extensions.get::<PeerCertInfo>().cloned();

    // 2. Read the body (cap = MAX_ADMIN_BODY_BYTES). No fields are
    //    decoded from it — the op takes no input beyond the URL — but it
    //    IS hashed into the audit record, like every other admin write.
    let bytes = match to_bytes(body, MAX_ADMIN_BODY_BYTES).await {
        Ok(b) => b,
        Err(_) => {
            return err_response(
                StatusCode::PAYLOAD_TOO_LARGE,
                &AdminErrorResponse {
                    reason: "body-too-large".into(),
                    ticket_id: None,
                    vm_id: None,
                },
            );
        }
    };
    let mut body_sha = [0u8; 32];
    body_sha.copy_from_slice(Sha256::digest(&bytes).as_slice());

    let now = match now_unix() {
        Ok(n) => n,
        Err(e) => return err_response(StatusCode::INTERNAL_SERVER_ERROR, &e),
    };

    // 3. Apply — every guard lives in the store, under its own lock.
    let outcome = process_admin_arm_boot_counter_resync(&url_vm_id, state.boot_counter.as_ref());

    // 4. Audit-log the outcome regardless of success/failure.
    let _ = record_admin_arm_resync_outcome(
        state.audit.as_ref(),
        &url_vm_id,
        &body_sha,
        peer.as_ref().map(|p| p.san_uri.as_str()),
        peer.as_ref().map(|p| p.serial_hex.as_str()),
        &outcome,
        now,
    );

    // 5. HTTP response.
    match outcome {
        Ok(ok) => ok_arm_resync_response(&AdminArmBootCounterResyncResponse {
            v: 1,
            vm_id: ok.vm_id,
            stored: ok.stored,
            already_armed: ok.already_armed,
        }),
        Err(e) => {
            let status = StatusCode::from_u16(e.status_code()).unwrap_or(StatusCode::BAD_REQUEST);
            err_response(
                status,
                &AdminErrorResponse {
                    reason: e.reason().to_string(),
                    ticket_id: None,
                    vm_id: Some(url_vm_id.clone()),
                },
            )
        }
    }
}

/// `POST /v1/admin/allowlist/reload` — atomically swap the in-memory
/// §22 allowlist with the operator-supplied COSE_Sign1 bytes.
///
/// Authn: mTLS at the listener level (same client-cert allowlist the
/// register-vm path inherits — no per-request token).
///
/// Authz: cryptographic — the body must verify against the binary-
/// compiled §22 root pubkey, and the embedded epoch must strictly
/// exceed the durable High-Water Mark (anti-rollback). Both checks run
/// inside [`InstalledAllowlist::install`]; on any failure the active
/// body is left untouched and the HWM is not advanced.
///
/// Errors:
/// - 400 `wrong-content-type` — Content-Type was not application/cbor.
/// - 413 `body-too-large` — body exceeded MAX_ADMIN_BODY_BYTES.
/// - 409 `install-rejected` — signature, schema or HWM check failed.
///   The static subclass is in the `reason` field; the server avoids
///   propagating the underlying error string verbatim because it can
///   echo the offender's epoch / format-detail (see kbs-core).
pub async fn handle_reload_allowlist(
    State(state): State<AdminState>,
    request: Request,
) -> Response {
    // 1. Rate limit at the gateway.
    if !state.limiter.try_acquire() {
        let mut resp = err_response(
            StatusCode::TOO_MANY_REQUESTS,
            &AdminErrorResponse {
                reason: "rate-limited".into(),
                ticket_id: None,
                vm_id: None,
            },
        );
        resp.headers_mut()
            .insert(header::RETRY_AFTER, HeaderValue::from_static("1"));
        return resp;
    }

    let (parts, body) = request.into_parts();
    if let Err(e) = require_cbor(&parts.headers) {
        let status = match e.reason.as_str() {
            "wrong-content-type" => StatusCode::UNSUPPORTED_MEDIA_TYPE,
            _ => StatusCode::BAD_REQUEST,
        };
        return err_response(status, &e);
    }

    let bytes = match to_bytes(body, MAX_ADMIN_BODY_BYTES).await {
        Ok(b) => b,
        Err(_) => {
            return err_response(
                StatusCode::PAYLOAD_TOO_LARGE,
                &AdminErrorResponse {
                    reason: "body-too-large".into(),
                    ticket_id: None,
                    vm_id: None,
                },
            );
        }
    };

    // 2. Install — verify signature + epoch HWM + atomic swap. On any
    //    sub-step failure the active body + HWM stay where they were.
    if let Err(_e) = state.allowlist.install(&bytes) {
        return err_response(
            StatusCode::CONFLICT,
            &AdminErrorResponse {
                reason: "install-rejected".into(),
                ticket_id: None,
                vm_id: None,
            },
        );
    }

    // 3. Build the confirmation envelope. The epoch we report is the
    //    one the KBS just committed (read-after-write of the in-memory
    //    state) — vali pins this in its activity log so a later
    //    `register-vm` against a stale allowlist surfaces loudly.
    let installed_epoch = match state.allowlist.epoch() {
        Ok(Some(e)) => e,
        _ => {
            // Should be impossible: install just succeeded.
            return err_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                &AdminErrorResponse {
                    reason: "post-install-empty".into(),
                    ticket_id: None,
                    vm_id: None,
                },
            );
        }
    };
    let mut hasher = Sha256::new();
    hasher.update(&bytes);
    let sha256_hex = hex_lower(&hasher.finalize());

    ok_reload_response(&AdminReloadAllowlistResponse {
        v: 1,
        epoch: installed_epoch,
        sha256_hex,
    })
}

/// Lowercase-hex of any `[u8]`-like slice — no external dep, no
/// allocator churn beyond the result `String`.
fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rate_limit::RateConfig;
    use axum::body::to_bytes as resp_to_bytes;
    use ciborium::value::Value;
    use coset::{iana, CborSerializable, CoseSign1Builder, HeaderBuilder};
    use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
    use hippius_types::cbor::to_canonical_vec;
    use hippius_types::ticket::{OrderTicket, VaultRef, SCHEMA_V};
    use kbs_core::admin_audit::FileAdminAuditSink;
    use kbs_core::persist::{FileIdempotencyStore, FileVmStateStore};
    use kbs_core::ticket::L1Keyring;
    use serde_bytes::ByteBuf;
    use std::collections::HashMap;
    use tempfile::TempDir;
    use tower::ServiceExt;

    struct StaticKeyring(HashMap<Vec<u8>, VerifyingKey>);
    impl L1Keyring for StaticKeyring {
        fn verifying_key(&self, kid: &[u8]) -> Option<VerifyingKey> {
            self.0.get(kid).copied()
        }
    }

    fn ticket_to_cbor_value(t: &OrderTicket) -> Value {
        Value::Map(vec![
            (
                Value::Text("allowed_measurements".into()),
                Value::Array(
                    t.allowed_measurements
                        .iter()
                        .map(|m| Value::Bytes(m.to_vec()))
                        .collect(),
                ),
            ),
            (
                Value::Text("allowed_userdata_digest".into()),
                Value::Bytes(t.allowed_userdata_digest.to_vec()),
            ),
            (
                Value::Text("expiry".into()),
                Value::Integer(t.expiry.into()),
            ),
            (
                Value::Text("issue_time".into()),
                Value::Integer(t.issue_time.into()),
            ),
            (
                Value::Text("lease_id".into()),
                Value::Text(t.lease_id.clone()),
            ),
            (
                Value::Text("lifecycle_perms".into()),
                Value::Array(
                    t.lifecycle_perms
                        .iter()
                        .map(|p| Value::Text(p.clone()))
                        .collect(),
                ),
            ),
            (
                Value::Text("luks_vault_ref".into()),
                Value::Map(vec![
                    (
                        Value::Text("path".into()),
                        Value::Text(t.luks_vault_ref.path.clone()),
                    ),
                    (
                        Value::Text("version".into()),
                        Value::Integer(t.luks_vault_ref.version.into()),
                    ),
                ]),
            ),
            (
                Value::Text("node_id".into()),
                Value::Text(t.node_id.clone()),
            ),
            (Value::Text("nonce".into()), Value::Bytes(t.nonce.to_vec())),
            (
                Value::Text("platform_id".into()),
                Value::Text(t.platform_id.clone()),
            ),
            (
                Value::Text("flavor".into()),
                Value::Text(t.flavor.as_str().into()),
            ),
            (
                Value::Text("tenant_id".into()),
                Value::Text(t.tenant_id.clone()),
            ),
            (
                Value::Text("ticket_id".into()),
                Value::Text(t.ticket_id.clone()),
            ),
            (
                Value::Text("user_id".into()),
                Value::Text(t.user_id.clone()),
            ),
            (Value::Text("v".into()), Value::Integer(t.v.into())),
            (
                Value::Text("vm_generation".into()),
                Value::Integer(t.vm_generation.into()),
            ),
            (Value::Text("vm_id".into()), Value::Text(t.vm_id.clone())),
            (
                Value::Text("userdata_vault_ref".into()),
                Value::Map(vec![
                    (
                        Value::Text("path".into()),
                        Value::Text(t.userdata_vault_ref.path.clone()),
                    ),
                    (
                        Value::Text("version".into()),
                        Value::Integer(t.userdata_vault_ref.version.into()),
                    ),
                ]),
            ),
        ])
    }

    fn mint_ticket(sk: &SigningKey, kid: &[u8], vm_id: &str, gen: u64, now: u64) -> Vec<u8> {
        let ticket = OrderTicket {
            v: SCHEMA_V,
            ticket_id: "tk-handler-1".into(),
            issue_time: now.saturating_sub(10),
            expiry: now.saturating_add(3600),
            nonce: ByteBuf::from(vec![1u8; 32]),
            tenant_id: "tenant-1".into(),
            user_id: "user-1".into(),
            vm_id: vm_id.into(),
            lease_id: "lease-1".into(),
            vm_generation: gen,
            node_id: "node-test".into(),
            platform_id: "chip-aaaa".into(),
            allowed_measurements: vec![ByteBuf::from(vec![0x11u8; 48])],
            userdata_vault_ref: VaultRef {
                path: "secret/u".into(),
                version: 1,
            },
            luks_vault_ref: VaultRef {
                path: "secret/l".into(),
                version: 1,
            },
            allowed_userdata_digest: ByteBuf::from(vec![0x22u8; 32]),
            flavor: hippius_types::flavor::Flavor::Small,
            lifecycle_perms: vec!["launch".into()],
        };
        let payload = to_canonical_vec(&ticket_to_cbor_value(&ticket)).unwrap();
        let protected = HeaderBuilder::new()
            .algorithm(iana::Algorithm::EdDSA)
            .key_id(kid.to_vec())
            .build();
        CoseSign1Builder::new()
            .protected(protected)
            .payload(payload)
            .create_signature(b"", |tbs| {
                let s: Signature = sk.sign(tbs);
                s.to_bytes().to_vec()
            })
            .build()
            .to_vec()
            .unwrap()
    }

    fn build_state(td: &TempDir) -> (AdminState, SigningKey, Vec<u8>) {
        let sk = SigningKey::from_bytes(&[7u8; 32]);
        let kid = b"l1-handler-test".to_vec();
        let mut map = HashMap::new();
        map.insert(kid.clone(), sk.verifying_key());
        let keyring: Arc<dyn L1Keyring + Send + Sync> = Arc::new(StaticKeyring(map));
        let vm_states_concrete = FileVmStateStore::open(td.path().join("vm-states.json")).unwrap();
        let vm_states: Arc<dyn VmStateRegister + Send + Sync> = Arc::new(vm_states_concrete);
        let idempotency: Arc<dyn IdempotencyStore + Send + Sync> =
            Arc::new(FileIdempotencyStore::open(td.path().join("idem"), 86400).unwrap());
        let audit = Arc::new(FileAdminAuditSink::open(td.path().join("audit")).unwrap());
        let limiter = Arc::new(NonceRateLimiter::new(RateConfig::default()));
        // The register-vm tests don't touch the allowlist; an empty
        // `InstalledAllowlist` (no body installed yet) is fine because
        // those tests verify under the release path's L1 keyring, not
        // under §22. The reload tests below build their own state with
        // a dev-signed body.
        let allowlist_root = SigningKey::from_bytes(&[8u8; 32]).verifying_key();
        let allowlist = Arc::new(InstalledAllowlist::new(
            allowlist_root,
            Box::new(kbs_core::allowlist::InMemoryHwm::default()),
        ));
        (
            AdminState {
                keyring,
                vm_states,
                idempotency,
                audit,
                limiter,
                allowlist,
                evidence: Arc::new(kbs_core::evidence::NullEvidenceSink),
                boot_counter: Arc::new(kbs_core::boot_counter::InMemoryBootCounterStore::default()),
                volume_stamp: Arc::new(kbs_core::volume_stamp::InMemoryVolumeStampStore::default()),
                // Test default mirrors the CHART: gate disabled.
                configured_max_unconfirmed_releases: None,
                posture: Arc::new(test_posture()),
            },
            sk,
            kid,
        )
    }

    /// A minimal posture for tests that never read it. The REAL
    /// derivation from a `Config` lives in `hippius_kbs_server::wiring::
    /// config_posture` and is tested there (kbs-transport has no
    /// `Config` — that is the point of precomputing it upstream).
    fn test_posture() -> AdminConfigPostureResponse {
        AdminConfigPostureResponse {
            v: 1,
            require_wrapped_kek: false,
            max_unconfirmed_releases: None,
            volume_stamp_gate_armed: false,
            admin_listener_mode: "mtls".into(),
            evidence_sink_wired: false,
            live_attestation_sink_wired: false,
            allowlist_root_pubkey_fpr: "0000000000000000".into(),
            allowlist_root_next_pubkey_fpr: None,
            allowlist_signed_path_configured: false,
            l1_key_count: 0,
            min_tcb: 0,
            required_bits: 0,
            allowed_mask: 0,
            snp_chain_wired: false,
            snp_generation: None,
            snp_kds_fetch_enabled: false,
            vault_broker_wired: false,
            vault_broker_ca_pinned: false,
            vault_ca_pinned: false,
            vault_dev_environment: false,
            vault_dev_allow_any_kbs_measurement: false,
            vault_dev_skip_tls_verify: false,
        }
    }

    #[tokio::test]
    async fn register_vm_happy_path_200() {
        let td = TempDir::new().unwrap();
        let (state, sk, kid) = build_state(&td);
        let router = build_admin_router(state);
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let body = mint_ticket(&sk, &kid, "vm-1", 1, now);

        let req = axum::http::Request::builder()
            .method("POST")
            .uri("/v1/admin/vm/vm-1/register-vm")
            .header("content-type", "application/cbor")
            .body(Body::from(body))
            .unwrap();
        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body_bytes = resp_to_bytes(resp.into_body(), 4096).await.unwrap();
        let parsed: AdminRegisterVmResponse =
            ciborium::de::from_reader(body_bytes.as_ref()).unwrap();
        assert_eq!(parsed.vm_id, "vm-1");
        assert!(!parsed.cached);
    }

    #[tokio::test]
    async fn register_vm_url_mismatch_400() {
        let td = TempDir::new().unwrap();
        let (state, sk, kid) = build_state(&td);
        let router = build_admin_router(state);
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let body = mint_ticket(&sk, &kid, "vm-A", 1, now);

        let req = axum::http::Request::builder()
            .method("POST")
            .uri("/v1/admin/vm/vm-WRONG/register-vm")
            .header("content-type", "application/cbor")
            .body(Body::from(body))
            .unwrap();
        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let body_bytes = resp_to_bytes(resp.into_body(), 4096).await.unwrap();
        let parsed: AdminErrorResponse = ciborium::de::from_reader(body_bytes.as_ref()).unwrap();
        assert_eq!(parsed.reason, "url-vm-id-mismatch");
    }

    #[tokio::test]
    async fn register_vm_wrong_content_type_415() {
        let td = TempDir::new().unwrap();
        let (state, _sk, _kid) = build_state(&td);
        let router = build_admin_router(state);
        let req = axum::http::Request::builder()
            .method("POST")
            .uri("/v1/admin/vm/vm-1/register-vm")
            .header("content-type", "application/json")
            .body(Body::from(b"{}".as_ref()))
            .unwrap();
        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);
    }

    #[tokio::test]
    async fn register_vm_idempotent_replay_returns_cached() {
        let td = TempDir::new().unwrap();
        let (state, sk, kid) = build_state(&td);
        let router = build_admin_router(state);
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let body = mint_ticket(&sk, &kid, "vm-2", 2, now);

        let req1 = axum::http::Request::builder()
            .method("POST")
            .uri("/v1/admin/vm/vm-2/register-vm")
            .header("content-type", "application/cbor")
            .body(Body::from(body.clone()))
            .unwrap();
        let resp1 = router.clone().oneshot(req1).await.unwrap();
        assert_eq!(resp1.status(), StatusCode::OK);

        let req2 = axum::http::Request::builder()
            .method("POST")
            .uri("/v1/admin/vm/vm-2/register-vm")
            .header("content-type", "application/cbor")
            .body(Body::from(body))
            .unwrap();
        let resp2 = router.oneshot(req2).await.unwrap();
        assert_eq!(resp2.status(), StatusCode::OK);
        let body_bytes = resp_to_bytes(resp2.into_body(), 4096).await.unwrap();
        let parsed: AdminRegisterVmResponse =
            ciborium::de::from_reader(body_bytes.as_ref()).unwrap();
        assert!(parsed.cached, "second apply must be cached");
    }

    // ── §25 activate route tests ────────────────────────────────────

    /// Seed an `Active{gen,host,lease}` row through the same
    /// `VmStateRegister::register` the handler uses, so the activate
    /// route has an Active state to transition.
    fn seed_active_via_register(
        state: &AdminState,
        vm_id: &str,
        gen: u64,
        host: &str,
        lease: &str,
    ) {
        state
            .vm_states
            .register(
                vm_id,
                kbs_core::lifecycle::VmState::Active {
                    gen,
                    host: host.into(),
                    lease_id: lease.into(),
                },
            )
            .unwrap();
    }

    #[tokio::test]
    async fn activate_happy_path_200_and_fences_state() {
        let td = TempDir::new().unwrap();
        let (state, _sk, _kid) = build_state(&td);
        seed_active_via_register(&state, "vm-mig", 5, "src-node", "lease-9");
        let router = build_admin_router(state);

        let body = serde_json::json!({
            "dest_node_id": "dst-node",
            "new_gen": 6,
            "snapshot_get_url": "https://s3/get?sig=x"
        });
        let req = axum::http::Request::builder()
            .method("POST")
            .uri("/v1/admin/vm/vm-mig/activate")
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_vec(&body).unwrap()))
            .unwrap();
        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body_bytes = resp_to_bytes(resp.into_body(), 4096).await.unwrap();
        let parsed: AdminActivateResponse = serde_json::from_slice(&body_bytes).unwrap();
        assert_eq!(parsed.old_gen, 5);
        assert_eq!(parsed.new_gen, 6);
        assert_eq!(parsed.dest, "dst-node");
        assert!(!parsed.cached);

        // The durable KBS state now fences the source: only dst@new_gen
        // unlocks. Re-open the persisted store to read the committed row
        // (the same file the release path reads).
        use kbs_core::lifecycle::VmStateStore;
        let persisted = FileVmStateStore::open(td.path().join("vm-states.json")).unwrap();
        let cur = persisted.get("vm-mig").unwrap();
        kbs_core::lifecycle::check_releasable(&cur, 6, "lease-9", "dst-node").unwrap();
        assert!(kbs_core::lifecycle::check_releasable(&cur, 5, "lease-9", "src-node").is_err());
    }

    #[tokio::test]
    async fn activate_unregistered_vm_409() {
        let td = TempDir::new().unwrap();
        let (state, _sk, _kid) = build_state(&td);
        let router = build_admin_router(state);
        // No register-vm first — activate must not fabricate a Migrating
        // state for an unknown VM (it would open the release path).
        let body = serde_json::json!({ "dest_node_id": "d", "new_gen": 2 });
        let req = axum::http::Request::builder()
            .method("POST")
            .uri("/v1/admin/vm/vm-ghost/activate")
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_vec(&body).unwrap()))
            .unwrap();
        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::CONFLICT);
    }

    #[tokio::test]
    async fn activate_bad_body_400() {
        let td = TempDir::new().unwrap();
        let (state, _sk, _kid) = build_state(&td);
        let router = build_admin_router(state);
        let req = axum::http::Request::builder()
            .method("POST")
            .uri("/v1/admin/vm/vm-x/activate")
            .header("content-type", "application/json")
            .body(Body::from(b"not-json".as_ref()))
            .unwrap();
        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let body_bytes = resp_to_bytes(resp.into_body(), 4096).await.unwrap();
        let parsed: AdminErrorResponse = ciborium::de::from_reader(body_bytes.as_ref()).unwrap();
        assert_eq!(parsed.reason, "activate-body-decode");
    }

    #[tokio::test]
    async fn activate_is_idempotent_on_redrive_200_cached() {
        let td = TempDir::new().unwrap();
        let (state, _sk, _kid) = build_state(&td);
        seed_active_via_register(&state, "vm-idem", 1, "src", "lease-1");
        let router = build_admin_router(state);
        let body = serde_json::json!({ "dest_node_id": "dst", "new_gen": 2 });

        let req1 = axum::http::Request::builder()
            .method("POST")
            .uri("/v1/admin/vm/vm-idem/activate")
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_vec(&body).unwrap()))
            .unwrap();
        let resp1 = router.clone().oneshot(req1).await.unwrap();
        assert_eq!(resp1.status(), StatusCode::OK);

        let req2 = axum::http::Request::builder()
            .method("POST")
            .uri("/v1/admin/vm/vm-idem/activate")
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_vec(&body).unwrap()))
            .unwrap();
        let resp2 = router.oneshot(req2).await.unwrap();
        assert_eq!(resp2.status(), StatusCode::OK);
        let body_bytes = resp_to_bytes(resp2.into_body(), 4096).await.unwrap();
        let parsed: AdminActivateResponse = serde_json::from_slice(&body_bytes).unwrap();
        assert!(parsed.cached, "re-drive must be an idempotent cached hit");
    }

    // ── activate: audit attribution (§13) ───────────────────────────

    /// One decoded row of the hash-chained admin audit log. Only the
    /// fields these tests assert on; ciborium ignores the rest.
    #[derive(serde::Deserialize)]
    struct AuditRow {
        op: String,
        applied: bool,
        status_code: u16,
        reason: String,
        peer_san: String,
        peer_serial: String,
        url_vm_id: String,
    }

    /// Read + decode every record the sink appended. The on-disk shape
    /// is `seq:hex(canonical-cbor body):hex(hash)` per line.
    fn read_audit_rows(td: &TempDir) -> Vec<AuditRow> {
        let raw =
            std::fs::read_to_string(td.path().join("audit").join("admin.log")).unwrap_or_default();
        raw.lines()
            .filter(|l| !l.is_empty())
            .map(|line| {
                let body_hex = line.split(':').nth(1).unwrap();
                let body = hex::decode(body_hex).unwrap();
                ciborium::de::from_reader(body.as_slice()).unwrap()
            })
            .collect()
    }

    fn activate_request(
        vm_id: &str,
        dest: &str,
        new_gen: u64,
        peer: Option<PeerCertInfo>,
    ) -> Request {
        let body = serde_json::json!({ "dest_node_id": dest, "new_gen": new_gen });
        let mut builder = axum::http::Request::builder()
            .method("POST")
            .uri(format!("/v1/admin/vm/{vm_id}/activate"))
            .header("content-type", "application/json");
        if let Some(p) = peer {
            builder = builder.extension(p);
        }
        builder
            .body(Body::from(serde_json::to_vec(&body).unwrap()))
            .unwrap()
    }

    fn vali_peer() -> PeerCertInfo {
        PeerCertInfo {
            san_uri: "spiffe://hippius.network/vali".into(),
            serial_hex: "0a1b2c3d".into(),
        }
    }

    #[tokio::test]
    async fn activate_success_writes_an_attributed_audit_record() {
        // CLAIM: the §25 fence — the one admin write that moves which
        // host may unlock a tenant disk — leaves a trace naming the
        // mTLS peer that drove it. It previously wrote NOTHING.
        let td = TempDir::new().unwrap();
        let (state, _sk, _kid) = build_state(&td);
        seed_active_via_register(&state, "vm-aud", 5, "src", "lease-9");
        let router = build_admin_router(state);

        let resp = router
            .oneshot(activate_request("vm-aud", "dst", 6, Some(vali_peer())))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let rows = read_audit_rows(&td);
        let row = rows
            .iter()
            .find(|r| r.op == "activate")
            .expect("activate must append an audit record");
        assert!(row.applied, "a real transition is applied=true");
        assert_eq!(row.status_code, 200);
        assert_eq!(row.url_vm_id, "vm-aud");
        // Attribution: the peer identity the mTLS layer verified, NOT
        // the empty string every admin row used to carry.
        assert_eq!(row.peer_san, "spiffe://hippius.network/vali");
        assert_eq!(row.peer_serial, "0a1b2c3d");
    }

    #[tokio::test]
    async fn activate_refusal_writes_an_audit_record_too() {
        // CLAIM: refusals are audited as well — a caller probing the
        // fence must show up as a run of applied=false rows, not as
        // silence.
        let td = TempDir::new().unwrap();
        let (state, _sk, _kid) = build_state(&td);
        let router = build_admin_router(state);

        // No register-vm first ⇒ 409 conflict.
        let resp = router
            .oneshot(activate_request("vm-ghost", "dst", 2, Some(vali_peer())))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::CONFLICT);

        let rows = read_audit_rows(&td);
        let row = rows
            .iter()
            .find(|r| r.op == "activate")
            .expect("a REFUSED activate must still append an audit record");
        assert!(!row.applied);
        assert_eq!(row.status_code, 409);
        assert_eq!(row.reason, "activate-conflict");
        assert_eq!(row.peer_san, "spiffe://hippius.network/vali");
    }

    #[tokio::test]
    async fn activate_redrive_is_audited_as_applied_false() {
        // CLAIM: `applied` means "this call changed durable state". An
        // idempotent re-drive writes nothing, so it must be recorded
        // applied=false — otherwise the log claims two fence moves where
        // only one happened, and "how many times did this VM's
        // generation actually move" becomes unanswerable.
        let td = TempDir::new().unwrap();
        let (state, _sk, _kid) = build_state(&td);
        seed_active_via_register(&state, "vm-redrive", 1, "src", "lease-1");
        let router = build_admin_router(state);

        for _ in 0..2 {
            let resp = router
                .clone()
                .oneshot(activate_request("vm-redrive", "dst", 2, Some(vali_peer())))
                .await
                .unwrap();
            assert_eq!(resp.status(), StatusCode::OK);
        }

        let rows: Vec<_> = read_audit_rows(&td)
            .into_iter()
            .filter(|r| r.op == "activate")
            .collect();
        assert_eq!(rows.len(), 2);
        assert!(rows[0].applied, "the first activate moved the fence");
        assert!(
            !rows[1].applied,
            "an idempotent re-drive wrote nothing and must not claim it did"
        );
        assert_eq!(rows[1].status_code, 200);
    }

    #[tokio::test]
    async fn activate_without_peer_cert_records_no_attribution() {
        // CLAIM: an unattributed call is DISTINGUISHABLE in the log. A
        // plaintext-opt-in listener (or an in-process test) yields an
        // empty peer_san — the audit reader can tell "not authenticated
        // by a client cert" from "authenticated as vali".
        let td = TempDir::new().unwrap();
        let (state, _sk, _kid) = build_state(&td);
        seed_active_via_register(&state, "vm-anon", 1, "src", "lease-1");
        let router = build_admin_router(state);

        let resp = router
            .oneshot(activate_request("vm-anon", "dst", 2, None))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let rows = read_audit_rows(&td);
        let row = rows.iter().find(|r| r.op == "activate").unwrap();
        assert_eq!(row.peer_san, "");
        assert_eq!(row.peer_serial, "");
    }

    #[tokio::test]
    async fn activate_malformed_body_is_audited() {
        // CLAIM: a garbled body against the fence route is worth seeing
        // in the chain — the pre-parse failure path audits too.
        let td = TempDir::new().unwrap();
        let (state, _sk, _kid) = build_state(&td);
        let router = build_admin_router(state);
        let req = axum::http::Request::builder()
            .method("POST")
            .uri("/v1/admin/vm/vm-x/activate")
            .header("content-type", "application/json")
            .extension(vali_peer())
            .body(Body::from(b"not-json".as_ref()))
            .unwrap();
        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

        let rows = read_audit_rows(&td);
        let row = rows.iter().find(|r| r.op == "activate").unwrap();
        assert!(!row.applied);
        assert_eq!(row.reason, "activate-body-decode");
        assert_eq!(row.peer_san, "spiffe://hippius.network/vali");
    }

    #[tokio::test]
    async fn activate_non_increasing_generation_is_refused_and_mutates_nothing() {
        // CLAIM: `new_gen <= old_gen` is refused. At `==` the fence would
        // leave the SOURCE's generation releasable (split-brain); at `<`
        // it would re-admit a burned generation (rollback). Neither may
        // touch the durable row.
        let td = TempDir::new().unwrap();
        let (state, _sk, _kid) = build_state(&td);
        seed_active_via_register(&state, "vm-mono", 5, "src-node", "lease-9");
        let router = build_admin_router(state);

        for bad_gen in [5u64, 4, 0] {
            let resp = router
                .clone()
                .oneshot(activate_request(
                    "vm-mono",
                    "dst",
                    bad_gen,
                    Some(vali_peer()),
                ))
                .await
                .unwrap();
            assert_eq!(
                resp.status(),
                StatusCode::CONFLICT,
                "new_gen={bad_gen} must be refused"
            );
            let body_bytes = resp_to_bytes(resp.into_body(), 4096).await.unwrap();
            let parsed: AdminErrorResponse =
                ciborium::de::from_reader(body_bytes.as_ref()).unwrap();
            assert_eq!(parsed.reason, "activate-not-monotonic");
        }

        // Durable state untouched: still Active on the SOURCE, and the
        // source can still unlock (nothing was fenced or moved).
        use kbs_core::lifecycle::VmStateStore;
        let persisted = FileVmStateStore::open(td.path().join("vm-states.json")).unwrap();
        let cur = persisted.get("vm-mono").unwrap();
        assert_eq!(
            cur,
            kbs_core::lifecycle::VmState::Active {
                gen: 5,
                host: "src-node".into(),
                lease_id: "lease-9".into(),
            }
        );
        // And every refusal is in the audit chain.
        let rows = read_audit_rows(&td);
        let refusals: Vec<_> = rows
            .iter()
            .filter(|r| r.op == "activate" && r.reason == "activate-not-monotonic")
            .collect();
        assert_eq!(refusals.len(), 3);
        assert!(refusals.iter().all(|r| !r.applied && r.status_code == 409));
    }

    // ── seed-boot-counter tests ─────────────────────────────────────

    /// Build an AdminState whose boot-counter store we keep a handle on,
    /// so a test can assert what the endpoint did (or did NOT do) to the
    /// counter — the "unchanged on refusal" half of the contract.
    fn build_state_with_counter(
        td: &TempDir,
    ) -> (
        AdminState,
        Arc<kbs_core::boot_counter::InMemoryBootCounterStore>,
    ) {
        let (mut state, _sk, _kid) = build_state(td);
        let counter = Arc::new(kbs_core::boot_counter::InMemoryBootCounterStore::default());
        state.boot_counter = Arc::clone(&counter) as Arc<dyn BootCounterStore>;
        (state, counter)
    }

    fn seed_request(vm_id: &str, counter: u64) -> axum::http::Request<Body> {
        axum::http::Request::builder()
            .method("POST")
            .uri(format!("/v1/admin/vm/{vm_id}/seed-boot-counter"))
            .header("content-type", "application/json")
            .body(Body::from(
                serde_json::to_vec(&serde_json::json!({ "counter": counter })).unwrap(),
            ))
            .unwrap()
    }

    #[tokio::test]
    async fn seed_boot_counter_happy_path_200_and_store_reflects_it() {
        let td = TempDir::new().unwrap();
        let (state, counter) = build_state_with_counter(&td);
        let router = build_admin_router(state);

        let resp = router.oneshot(seed_request("vm-seed", 9)).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body_bytes = resp_to_bytes(resp.into_body(), 4096).await.unwrap();
        let parsed: hippius_types::admin::AdminSeedBootCounterResponse =
            serde_json::from_slice(&body_bytes).unwrap();
        assert_eq!(parsed.v, 1);
        assert_eq!(parsed.vm_id, "vm-seed");
        assert_eq!(parsed.previous, 0);
        assert_eq!(parsed.counter, 9);
        assert_eq!(counter.get("vm-seed").unwrap(), 9);
        // The release gate now sits exactly where 9 real boots left it.
        assert!(counter.check_only("vm-seed", 9).is_err());
        assert_eq!(counter.check_only("vm-seed", 10).unwrap(), 10);
    }

    #[tokio::test]
    async fn seed_boot_counter_on_a_live_vm_is_409_and_leaves_the_store_untouched() {
        // THE security test, over HTTP: once a VM has a counter the route
        // is inert in EVERY direction — a rewind cannot re-admit a burned
        // boot and a jump cannot push the gate out of the guest's reach.
        // Both halves asserted; a mutant that 409s but still writes fails.
        let td = TempDir::new().unwrap();
        let (state, counter) = build_state_with_counter(&td);
        let router = build_admin_router(state);

        assert_eq!(
            router
                .clone()
                .oneshot(seed_request("vm-rb", 10))
                .await
                .unwrap()
                .status(),
            StatusCode::OK
        );

        for attempt in [10u64, 4, 1, 11, kbs_core::boot_counter::MAX_SEED_COUNTER] {
            let resp = router
                .clone()
                .oneshot(seed_request("vm-rb", attempt))
                .await
                .unwrap();
            assert_eq!(resp.status(), StatusCode::CONFLICT, "attempt {attempt}");
            let body_bytes = resp_to_bytes(resp.into_body(), 4096).await.unwrap();
            let parsed: AdminErrorResponse =
                ciborium::de::from_reader(body_bytes.as_ref()).unwrap();
            assert_eq!(parsed.reason, "seed-already-recovered", "attempt {attempt}");
            assert_eq!(
                counter.get("vm-rb").unwrap(),
                10,
                "a refused seed must not mutate the store (attempt {attempt})"
            );
        }
    }

    #[tokio::test]
    async fn seed_boot_counter_above_cap_is_400_and_writes_nothing() {
        // CLAIM: the brick vector is closed over HTTP too, with a reason
        // an operator can tell apart from the two conflicts.
        let td = TempDir::new().unwrap();
        let (state, counter) = build_state_with_counter(&td);
        let router = build_admin_router(state);
        let cap = kbs_core::boot_counter::MAX_SEED_COUNTER;

        for attempt in [cap + 1, u64::MAX] {
            let resp = router
                .clone()
                .oneshot(seed_request("vm-cap", attempt))
                .await
                .unwrap();
            assert_eq!(resp.status(), StatusCode::BAD_REQUEST, "attempt {attempt}");
            let body_bytes = resp_to_bytes(resp.into_body(), 4096).await.unwrap();
            let parsed: AdminErrorResponse =
                ciborium::de::from_reader(body_bytes.as_ref()).unwrap();
            assert_eq!(parsed.reason, "seed-above-cap", "attempt {attempt}");
            assert_eq!(counter.get("vm-cap").unwrap(), 0, "attempt {attempt}");
        }
        // The boundary itself still works — the cap is inclusive.
        assert_eq!(
            router
                .oneshot(seed_request("vm-cap", cap))
                .await
                .unwrap()
                .status(),
            StatusCode::OK
        );
        assert_eq!(counter.get("vm-cap").unwrap(), cap);
    }

    #[tokio::test]
    async fn seed_boot_counter_zero_is_400_and_writes_nothing() {
        let td = TempDir::new().unwrap();
        let (state, counter) = build_state_with_counter(&td);
        let router = build_admin_router(state);
        let resp = router.oneshot(seed_request("vm-zero", 0)).await.unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let body_bytes = resp_to_bytes(resp.into_body(), 4096).await.unwrap();
        let parsed: AdminErrorResponse = ciborium::de::from_reader(body_bytes.as_ref()).unwrap();
        assert_eq!(parsed.reason, "counter-zero");
        assert_eq!(counter.get("vm-zero").unwrap(), 0);
    }

    #[tokio::test]
    async fn seed_boot_counter_bad_body_400() {
        let td = TempDir::new().unwrap();
        let (state, counter) = build_state_with_counter(&td);
        let router = build_admin_router(state);
        let req = axum::http::Request::builder()
            .method("POST")
            .uri("/v1/admin/vm/vm-x/seed-boot-counter")
            .header("content-type", "application/json")
            .body(Body::from(b"not-json".as_ref()))
            .unwrap();
        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let body_bytes = resp_to_bytes(resp.into_body(), 4096).await.unwrap();
        let parsed: AdminErrorResponse = ciborium::de::from_reader(body_bytes.as_ref()).unwrap();
        assert_eq!(parsed.reason, "seed-body-decode");
        assert_eq!(counter.get("vm-x").unwrap(), 0);
    }

    #[tokio::test]
    async fn seed_boot_counter_is_audit_logged_applied_and_refused() {
        // CLAIM: every call — applied AND refused — lands in the
        // hash-chained admin log with op="seed-boot-counter".
        let td = TempDir::new().unwrap();
        let (state, _counter) = build_state_with_counter(&td);
        let audit = Arc::clone(&state.audit);
        let router = build_admin_router(state);

        assert_eq!(audit.verify().unwrap().records, 0);
        router
            .clone()
            .oneshot(seed_request("vm-aud", 5))
            .await
            .unwrap();
        assert_eq!(
            audit.verify().unwrap().records,
            1,
            "the applied seed must be audited"
        );
        router
            .clone()
            .oneshot(seed_request("vm-aud", 2))
            .await
            .unwrap();
        assert_eq!(
            audit.verify().unwrap().records,
            2,
            "the refused seed onto a live counter must be audited too"
        );
        router
            .clone()
            .oneshot(seed_request(
                "vm-aud2",
                kbs_core::boot_counter::MAX_SEED_COUNTER + 1,
            ))
            .await
            .unwrap();
        assert_eq!(
            audit.verify().unwrap().records,
            3,
            "the above-cap refusal must be audited too"
        );

        let log = std::fs::read_to_string(td.path().join("audit").join("admin.log")).unwrap();
        let decoded: Vec<String> = log
            .lines()
            .map(|l| {
                let bytes = hex::decode(l.split(':').nth(1).unwrap()).unwrap();
                format!(
                    "{:?}",
                    ciborium::de::from_reader::<Value, _>(bytes.as_slice()).unwrap()
                )
            })
            .collect();
        assert!(decoded[0].contains("seed-boot-counter"), "{}", decoded[0]);
        assert!(decoded[0].contains("vm-aud"), "{}", decoded[0]);
        assert!(decoded[0].contains("Bool(true)"), "{}", decoded[0]);
        assert!(
            decoded[1].contains("seed-already-recovered"),
            "{}",
            decoded[1]
        );
        assert!(decoded[1].contains("Bool(false)"), "{}", decoded[1]);
        assert!(decoded[2].contains("seed-above-cap"), "{}", decoded[2]);
        assert!(decoded[2].contains("Bool(false)"), "{}", decoded[2]);
    }

    #[tokio::test]
    async fn seed_boot_counter_re_running_a_recovery_refuses_over_http() {
        // CLAIM: the operator-visible consequence of guard 1 — replaying
        // the SAME recovery request is NOT idempotent, it is a 409. That
        // is the fail-safe direction: a repeat is either a duplicate or a
        // disagreement about the true value, and silently overwriting
        // would be the DoS this guard exists to close.
        let td = TempDir::new().unwrap();
        let (state, counter) = build_state_with_counter(&td);
        let router = build_admin_router(state);

        assert_eq!(
            router
                .clone()
                .oneshot(seed_request("vm-twice", 7))
                .await
                .unwrap()
                .status(),
            StatusCode::OK
        );
        let resp = router.oneshot(seed_request("vm-twice", 7)).await.unwrap();
        assert_eq!(resp.status(), StatusCode::CONFLICT);
        let body_bytes = resp_to_bytes(resp.into_body(), 4096).await.unwrap();
        let parsed: AdminErrorResponse = ciborium::de::from_reader(body_bytes.as_ref()).unwrap();
        assert_eq!(parsed.reason, "seed-already-recovered");
        assert_eq!(counter.get("vm-twice").unwrap(), 7);
    }

    #[tokio::test]
    async fn seed_boot_counter_shares_the_admin_rate_limit_bucket() {
        // CLAIM: the new route sits behind the SAME gateway guard as its
        // siblings — it is not a bypass lane.
        let td = TempDir::new().unwrap();
        let (mut state, counter) = build_state_with_counter(&td);
        state.limiter = Arc::new(NonceRateLimiter::new(RateConfig {
            refill_per_sec: 0.0,
            burst: 1,
        }));
        let router = build_admin_router(state);
        assert_eq!(
            router
                .clone()
                .oneshot(seed_request("vm-rl", 3))
                .await
                .unwrap()
                .status(),
            StatusCode::OK
        );
        let resp = router.oneshot(seed_request("vm-rl", 4)).await.unwrap();
        assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(counter.get("vm-rl").unwrap(), 3);
    }

    // ── arm-boot-counter-resync tests ───────────────────────────────

    fn arm_resync_request(vm_id: &str) -> axum::http::Request<Body> {
        axum::http::Request::builder()
            .method("POST")
            .uri(format!("/v1/admin/vm/{vm_id}/arm-boot-counter-resync"))
            .header("content-type", "application/json")
            .body(Body::empty())
            .unwrap()
    }

    #[tokio::test]
    async fn arm_resync_happy_path_200_arms_without_moving_the_counter() {
        // CLAIM: over HTTP, the op arms and reports the stored value —
        // and writes no counter. The response carries no operator-chosen
        // number at all, which is why (unlike seed) it needs no cap.
        let td = TempDir::new().unwrap();
        let (state, counter) = build_state_with_counter(&td);
        counter.check_and_advance("vm-lost", 1).unwrap();
        counter.check_and_advance("vm-lost", 2).unwrap();
        let router = build_admin_router(state);

        let resp = router.oneshot(arm_resync_request("vm-lost")).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = to_bytes(resp.into_body(), 64 * 1024).await.unwrap();
        let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(parsed["vm_id"], "vm-lost");
        assert_eq!(parsed["stored"], 2);
        assert_eq!(parsed["already_armed"], false);

        assert_eq!(counter.get("vm-lost").unwrap(), 2, "no counter was written");
        assert!(counter.resync_armed("vm-lost").unwrap());
    }

    #[tokio::test]
    async fn arm_resync_on_a_never_counted_vm_is_409_and_arms_nothing() {
        let td = TempDir::new().unwrap();
        let (state, counter) = build_state_with_counter(&td);
        let router = build_admin_router(state);

        let resp = router.oneshot(arm_resync_request("vm-new")).await.unwrap();
        assert_eq!(resp.status(), StatusCode::CONFLICT);
        let body = to_bytes(resp.into_body(), 64 * 1024).await.unwrap();
        let parsed: AdminErrorResponse = ciborium::de::from_reader(body.as_ref()).unwrap();
        assert_eq!(parsed.reason, "resync-nothing-to-resync");
        assert!(!counter.resync_armed("vm-new").unwrap());
    }

    #[tokio::test]
    async fn arm_resync_re_drive_is_200_already_armed() {
        let td = TempDir::new().unwrap();
        let (state, counter) = build_state_with_counter(&td);
        counter.check_and_advance("vm-again", 1).unwrap();
        let router = build_admin_router(state);

        assert_eq!(
            router
                .clone()
                .oneshot(arm_resync_request("vm-again"))
                .await
                .unwrap()
                .status(),
            StatusCode::OK
        );
        let resp = router
            .oneshot(arm_resync_request("vm-again"))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = to_bytes(resp.into_body(), 64 * 1024).await.unwrap();
        let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(parsed["already_armed"], true);
    }

    #[tokio::test]
    async fn arm_resync_is_audit_logged_with_peer_attribution() {
        // CLAIM: the arm is the only durable trace that a resync was
        // authorised, so it MUST be in the hash-chained admin log with
        // the mTLS peer that asked for it.
        let td = TempDir::new().unwrap();
        let (state, counter) = build_state_with_counter(&td);
        counter.check_and_advance("vm-audit", 1).unwrap();
        let audit_dir = td.path().join("audit");
        let router = build_admin_router(state);

        let mut req = arm_resync_request("vm-audit");
        req.extensions_mut().insert(PeerCertInfo {
            san_uri: "spiffe://hippius.network/operator".into(),
            serial_hex: "0a0b".into(),
        });
        assert_eq!(router.oneshot(req).await.unwrap().status(), StatusCode::OK);

        let log = std::fs::read_to_string(audit_dir.join("admin.log")).unwrap();
        let line = log.lines().next().expect("one record");
        let bytes = hex::decode(line.split(':').nth(1).unwrap()).unwrap();
        let decoded = format!(
            "{:?}",
            ciborium::de::from_reader::<ciborium::value::Value, _>(bytes.as_slice()).unwrap()
        );
        assert!(decoded.contains("arm-boot-counter-resync"), "{decoded}");
        assert!(decoded.contains("vm-audit"), "{decoded}");
        assert!(
            decoded.contains("spiffe://hippius.network/operator"),
            "{decoded}"
        );
        assert!(decoded.contains("Bool(true)"), "{decoded}");
    }

    #[tokio::test]
    async fn arm_resync_shares_the_admin_rate_limit_bucket() {
        // CLAIM: the new route sits behind the SAME gateway guard as its
        // siblings — it is not a bypass lane.
        let td = TempDir::new().unwrap();
        let (mut state, counter) = build_state_with_counter(&td);
        counter.check_and_advance("vm-rl2", 1).unwrap();
        state.limiter = Arc::new(NonceRateLimiter::new(RateConfig {
            refill_per_sec: 0.0,
            burst: 1,
        }));
        let router = build_admin_router(state);
        assert_eq!(
            router
                .clone()
                .oneshot(arm_resync_request("vm-rl2"))
                .await
                .unwrap()
                .status(),
            StatusCode::OK
        );
        let resp = router.oneshot(arm_resync_request("vm-rl2")).await.unwrap();
        assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
    }

    // ── reset-volume-stamp-suppression tests ─────────────────────────

    fn build_state_with_volume_stamp(
        td: &TempDir,
    ) -> (
        AdminState,
        Arc<kbs_core::volume_stamp::InMemoryVolumeStampStore>,
    ) {
        let (mut state, _sk, _kid) = build_state(td);
        let store = Arc::new(kbs_core::volume_stamp::InMemoryVolumeStampStore::default());
        state.volume_stamp = Arc::clone(&store) as Arc<dyn VolumeStampStore>;
        (state, store)
    }

    fn reset_volume_stamp_request(vm_id: &str) -> axum::http::Request<Body> {
        axum::http::Request::builder()
            .method("POST")
            .uri(format!(
                "/v1/admin/vm/{vm_id}/reset-volume-stamp-suppression"
            ))
            .header("content-type", "application/json")
            .body(Body::empty())
            .unwrap()
    }

    #[tokio::test]
    async fn reset_volume_stamp_suppression_happy_path_200_and_store_reflects_it() {
        let td = TempDir::new().unwrap();
        let (state, store) = build_state_with_volume_stamp(&td);
        store.note_release("vm-blocked").unwrap();
        store.note_release("vm-blocked").unwrap();
        store.note_release("vm-blocked").unwrap();
        store.note_release("vm-blocked").unwrap();
        let router = build_admin_router(state);

        let resp = router
            .oneshot(reset_volume_stamp_request("vm-blocked"))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body_bytes = resp_to_bytes(resp.into_body(), 4096).await.unwrap();
        let parsed: AdminResetVolumeStampSuppressionResponse =
            serde_json::from_slice(&body_bytes).unwrap();
        assert_eq!(parsed.vm_id, "vm-blocked");
        assert_eq!(parsed.cleared, 4);
        // The confirmed stamp — the actual anti-rollback reference — is
        // untouched by the reset.
        assert_eq!(store.get("vm-blocked").unwrap(), 0);
        // And releases resume: the counter is back at 0.
        assert_eq!(store.note_release("vm-blocked").unwrap(), (0, 1));
    }

    #[tokio::test]
    async fn reset_volume_stamp_suppression_on_an_unblocked_vm_is_a_harmless_200() {
        let td = TempDir::new().unwrap();
        let (state, _store) = build_state_with_volume_stamp(&td);
        let router = build_admin_router(state);

        let resp = router
            .oneshot(reset_volume_stamp_request("vm-fresh"))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body_bytes = resp_to_bytes(resp.into_body(), 4096).await.unwrap();
        let parsed: AdminResetVolumeStampSuppressionResponse =
            serde_json::from_slice(&body_bytes).unwrap();
        assert_eq!(parsed.cleared, 0);
    }

    #[tokio::test]
    async fn reset_volume_stamp_suppression_shares_the_admin_rate_limit_bucket() {
        // CLAIM: the new route sits behind the SAME gateway guard as its
        // siblings — it is not a bypass lane.
        let td = TempDir::new().unwrap();
        let (mut state, _store) = build_state_with_volume_stamp(&td);
        state.limiter = Arc::new(NonceRateLimiter::new(RateConfig {
            refill_per_sec: 0.0,
            burst: 1,
        }));
        let router = build_admin_router(state);
        assert_eq!(
            router
                .clone()
                .oneshot(reset_volume_stamp_request("vm-rl"))
                .await
                .unwrap()
                .status(),
            StatusCode::OK
        );
        let resp = router
            .oneshot(reset_volume_stamp_request("vm-rl"))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
    }

    #[tokio::test]
    async fn reset_volume_stamp_suppression_outcome_is_audit_logged() {
        let td = TempDir::new().unwrap();
        let (state, store) = build_state_with_volume_stamp(&td);
        store.note_release("vm-a").unwrap();
        let router = build_admin_router(state);

        let resp = router
            .oneshot(reset_volume_stamp_request("vm-a"))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let log = std::fs::read_to_string(td.path().join("audit").join("admin.log")).unwrap();
        let lines: Vec<&str> = log.lines().filter(|l| !l.is_empty()).collect();
        assert_eq!(lines.len(), 1);
        let body_hex = lines[0].split(':').nth(1).unwrap();
        let bytes = hex::decode(body_hex).unwrap();
        let decoded = format!(
            "{:?}",
            ciborium::de::from_reader::<ciborium::value::Value, _>(bytes.as_slice()).unwrap()
        );
        assert!(
            decoded.contains("reset-volume-stamp-suppression"),
            "{decoded}"
        );
        assert!(decoded.contains("Bool(true)"), "{decoded}");
    }

    // ── allowlist/reload tests ──────────────────────────────────────

    /// Build an AdminState whose §22 root keypair we own — needed to
    /// sign allowlist artifacts on the test side and have the in-process
    /// `InstalledAllowlist::install` accept them.
    fn build_state_with_allowlist_root(
        td: &TempDir,
        allowlist_root: ed25519_dalek::VerifyingKey,
    ) -> AdminState {
        let sk = SigningKey::from_bytes(&[7u8; 32]);
        let kid = b"l1-handler-test".to_vec();
        let mut map = HashMap::new();
        map.insert(kid, sk.verifying_key());
        let keyring: Arc<dyn L1Keyring + Send + Sync> = Arc::new(StaticKeyring(map));
        let vm_states_concrete = FileVmStateStore::open(td.path().join("vm-states.json")).unwrap();
        let vm_states: Arc<dyn VmStateRegister + Send + Sync> = Arc::new(vm_states_concrete);
        let idempotency: Arc<dyn IdempotencyStore + Send + Sync> =
            Arc::new(FileIdempotencyStore::open(td.path().join("idem"), 86400).unwrap());
        let audit = Arc::new(FileAdminAuditSink::open(td.path().join("audit")).unwrap());
        let limiter = Arc::new(NonceRateLimiter::new(RateConfig::default()));
        let allowlist = Arc::new(InstalledAllowlist::new(
            allowlist_root,
            Box::new(kbs_core::allowlist::InMemoryHwm::default()),
        ));
        AdminState {
            keyring,
            vm_states,
            idempotency,
            audit,
            limiter,
            allowlist,
            evidence: Arc::new(kbs_core::evidence::NullEvidenceSink),
            boot_counter: Arc::new(kbs_core::boot_counter::InMemoryBootCounterStore::default()),
            volume_stamp: Arc::new(kbs_core::volume_stamp::InMemoryVolumeStampStore::default()),
            configured_max_unconfirmed_releases: None,
            posture: Arc::new(test_posture()),
        }
    }

    fn build_allowlist_cose(sk: &SigningKey, epoch: u64) -> Vec<u8> {
        // Minimal valid body: one entry (sorted), the matching v=1
        // header + epoch. Mirrors `kbs_core::allowlist::tests::body_value`
        // — the SAME canonical-CBOR + COSE EdDSA the runtime expects.
        let meas = [7u8; 48];
        let entries = Value::Array(vec![Value::Array(vec![
            Value::Bytes(meas.to_vec()),
            Value::Map(vec![
                (
                    Value::Text("accepted_kbs_response_kids".into()),
                    Value::Array(vec![Value::Bytes(b"kbs-kid-1".to_vec())]),
                ),
                (
                    Value::Text("accepted_l1_kids".into()),
                    Value::Array(vec![Value::Bytes(b"l1-kid-1".to_vec())]),
                ),
            ]),
        ])]);
        let body = Value::Map(vec![
            (Value::Text("entries".into()), entries),
            (Value::Text("epoch".into()), Value::Integer(epoch.into())),
            (Value::Text("v".into()), Value::Integer(1.into())),
        ]);
        let payload = to_canonical_vec(&body).unwrap();
        let protected = HeaderBuilder::new()
            .algorithm(iana::Algorithm::EdDSA)
            .build();
        CoseSign1Builder::new()
            .protected(protected)
            .payload(payload)
            .create_signature(b"", |tbs| sk.sign(tbs).to_bytes().to_vec())
            .build()
            .to_vec()
            .unwrap()
    }

    #[tokio::test]
    async fn reload_allowlist_happy_path_200() {
        let td = TempDir::new().unwrap();
        let root_sk = SigningKey::from_bytes(&[42u8; 32]);
        let state = build_state_with_allowlist_root(&td, root_sk.verifying_key());
        let router = build_admin_router(state);

        let cose = build_allowlist_cose(&root_sk, 17);
        let req = axum::http::Request::builder()
            .method("POST")
            .uri("/v1/admin/allowlist/reload")
            .header("content-type", "application/cbor")
            .body(Body::from(cose.clone()))
            .unwrap();
        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body_bytes = resp_to_bytes(resp.into_body(), 4096).await.unwrap();
        let parsed: hippius_types::admin::AdminReloadAllowlistResponse =
            ciborium::de::from_reader(body_bytes.as_ref()).unwrap();
        assert_eq!(parsed.v, 1);
        assert_eq!(parsed.epoch, 17);
        // sha256 of the request body must round-trip in the response.
        let expected_sha = {
            let mut h = Sha256::new();
            h.update(&cose);
            hex_lower(&h.finalize())
        };
        assert_eq!(parsed.sha256_hex, expected_sha);
    }

    #[tokio::test]
    async fn reload_allowlist_rollback_409() {
        let td = TempDir::new().unwrap();
        let root_sk = SigningKey::from_bytes(&[42u8; 32]);
        let state = build_state_with_allowlist_root(&td, root_sk.verifying_key());
        let router = build_admin_router(state);

        // First reload pins epoch 5.
        let cose5 = build_allowlist_cose(&root_sk, 5);
        let req = axum::http::Request::builder()
            .method("POST")
            .uri("/v1/admin/allowlist/reload")
            .header("content-type", "application/cbor")
            .body(Body::from(cose5))
            .unwrap();
        let resp = router.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        // Second reload with the SAME epoch — anti-rollback (`epoch <=
        // current` is the same path as a true downgrade) rejects.
        let cose5_again = build_allowlist_cose(&root_sk, 5);
        let req2 = axum::http::Request::builder()
            .method("POST")
            .uri("/v1/admin/allowlist/reload")
            .header("content-type", "application/cbor")
            .body(Body::from(cose5_again))
            .unwrap();
        let resp2 = router.oneshot(req2).await.unwrap();
        assert_eq!(resp2.status(), StatusCode::CONFLICT);
        let body_bytes = resp_to_bytes(resp2.into_body(), 4096).await.unwrap();
        let parsed: AdminErrorResponse = ciborium::de::from_reader(body_bytes.as_ref()).unwrap();
        assert_eq!(parsed.reason, "install-rejected");
    }

    #[tokio::test]
    async fn reload_allowlist_wrong_content_type_415() {
        let td = TempDir::new().unwrap();
        let root_sk = SigningKey::from_bytes(&[42u8; 32]);
        let state = build_state_with_allowlist_root(&td, root_sk.verifying_key());
        let router = build_admin_router(state);
        let req = axum::http::Request::builder()
            .method("POST")
            .uri("/v1/admin/allowlist/reload")
            .header("content-type", "application/json")
            .body(Body::from(b"{}".as_ref()))
            .unwrap();
        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);
    }

    #[tokio::test]
    async fn reload_allowlist_wrong_signing_key_409() {
        let td = TempDir::new().unwrap();
        let root_sk = SigningKey::from_bytes(&[42u8; 32]);
        let state = build_state_with_allowlist_root(&td, root_sk.verifying_key());
        let router = build_admin_router(state);
        // Sign with a DIFFERENT key — install's parse_and_verify fails.
        let wrong_sk = SigningKey::from_bytes(&[99u8; 32]);
        let cose = build_allowlist_cose(&wrong_sk, 1);
        let req = axum::http::Request::builder()
            .method("POST")
            .uri("/v1/admin/allowlist/reload")
            .header("content-type", "application/cbor")
            .body(Body::from(cose))
            .unwrap();
        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::CONFLICT);
        let body_bytes = resp_to_bytes(resp.into_body(), 4096).await.unwrap();
        let parsed: AdminErrorResponse = ciborium::de::from_reader(body_bytes.as_ref()).unwrap();
        assert_eq!(parsed.reason, "install-rejected");
    }

    // ── GET /v1/admin/volume-stamp (cutover step 3) ─────────────────

    /// A state whose volume-stamp store we keep a handle on, so a test
    /// can assert the store both before and after a request.
    fn build_state_with_stamp_store(
        td: &TempDir,
        configured_bound: Option<u64>,
    ) -> (
        AdminState,
        Arc<kbs_core::volume_stamp::InMemoryVolumeStampStore>,
    ) {
        let (mut state, _sk, _kid) = build_state(td);
        let store = Arc::new(kbs_core::volume_stamp::InMemoryVolumeStampStore::default());
        state.volume_stamp = Arc::clone(&store) as Arc<dyn VolumeStampStore>;
        state.configured_max_unconfirmed_releases = configured_bound;
        (state, store)
    }

    /// A GET carrying a verified-peer extension — what
    /// `admin_tls::serve_admin_mtls` injects on every request that
    /// completed a client-cert handshake.
    fn authenticated_get(uri: &str) -> axum::http::Request<Body> {
        let mut req = axum::http::Request::builder()
            .method("GET")
            .uri(uri)
            .body(Body::empty())
            .unwrap();
        req.extensions_mut().insert(PeerCertInfo {
            san_uri: "spiffe://hippius.network/operator".into(),
            serial_hex: "01".into(),
        });
        req
    }

    async fn json_of(resp: Response) -> serde_json::Value {
        let bytes = resp_to_bytes(resp.into_body(), 1 << 20).await.unwrap();
        serde_json::from_slice(&bytes).unwrap()
    }

    #[tokio::test]
    async fn volume_stamp_report_reflects_note_release_and_confirm() {
        let td = TempDir::new().unwrap();
        let (state, store) = build_state_with_stamp_store(&td, None);
        // vm-never: released 4x, never confirmed → both red flags.
        for _ in 0..4 {
            store.note_release("vm-never").unwrap();
        }
        // vm-ok: released then confirmed → the steady state.
        store.note_release("vm-ok").unwrap();
        store.confirm("vm-ok", 1).unwrap();
        // vm-stalled: confirmed once long ago, then confirms stopped.
        store.note_release("vm-stalled").unwrap();
        store.confirm("vm-stalled", 1).unwrap();
        for _ in 0..3 {
            store.note_release("vm-stalled").unwrap();
        }

        let router = build_admin_router(state);
        let resp = router
            .oneshot(authenticated_get("/v1/admin/volume-stamp?bound=3"))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let v = json_of(resp).await;

        assert_eq!(v["v"], 1);
        assert_eq!(v["evaluated_bound"], 3);
        assert_eq!(v["gate_armed"], false);
        assert_eq!(v["configured_bound"], serde_json::Value::Null);
        assert_eq!(v["vms"], 3);
        assert_eq!(v["never_confirmed"], 1);
        // vm-never (4 >= 3) and vm-stalled (3 >= 3) — vm-ok is fine.
        assert_eq!(v["would_refuse_now"], 2);
        assert_eq!(v["ready_to_arm"], false);

        let rows = v["rows"].as_array().unwrap();
        assert_eq!(rows.len(), 3);
        // Sorted by vm_id.
        assert_eq!(rows[0]["vm_id"], "vm-never");
        assert_eq!(rows[1]["vm_id"], "vm-ok");
        assert_eq!(rows[2]["vm_id"], "vm-stalled");
        // "never confirmed" vs "confirmed once, long ago" — the SAME
        // `would_refuse_next_release`, opposite `has_ever_confirmed`.
        assert_eq!(rows[0]["has_ever_confirmed"], false);
        assert_eq!(rows[0]["would_refuse_next_release"], true);
        assert_eq!(rows[2]["has_ever_confirmed"], true);
        assert_eq!(rows[2]["would_refuse_next_release"], true);
        assert_eq!(rows[2]["confirmed"], 1);
        assert_eq!(rows[2]["unconfirmed_releases"], 3);
    }

    #[tokio::test]
    async fn volume_stamp_report_does_not_mutate_the_store() {
        let td = TempDir::new().unwrap();
        let (state, store) = build_state_with_stamp_store(&td, None);
        for _ in 0..3 {
            store.note_release("vm-a").unwrap();
        }
        let router = build_admin_router(state);
        for _ in 0..10 {
            let resp = router
                .clone()
                .oneshot(authenticated_get("/v1/admin/volume-stamp"))
                .await
                .unwrap();
            assert_eq!(resp.status(), StatusCode::OK);
        }
        // If the route had reset the streak (or incremented it), this
        // would not read 4.
        assert_eq!(store.note_release("vm-a").unwrap(), (0, 4));
        assert_eq!(store.get("vm-a").unwrap(), 0);
    }

    #[tokio::test]
    async fn volume_stamp_report_refuses_a_request_with_no_verified_peer_cert() {
        let td = TempDir::new().unwrap();
        let (state, store) = build_state_with_stamp_store(&td, None);
        store.note_release("vm-secret").unwrap();
        let router = build_admin_router(state);

        // No `PeerCertInfo` extension = a plaintext listener, or any
        // caller that did not present a client cert.
        let req = axum::http::Request::builder()
            .method("GET")
            .uri("/v1/admin/volume-stamp")
            .body(Body::empty())
            .unwrap();
        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        let bytes = resp_to_bytes(resp.into_body(), 4096).await.unwrap();
        let parsed: AdminErrorResponse = ciborium::de::from_reader(bytes.as_ref()).unwrap();
        assert_eq!(parsed.reason, "admin-client-cert-required");
        // Not one vm_id in the refusal body.
        assert!(!String::from_utf8_lossy(&bytes).contains("vm-secret"));
    }

    #[tokio::test]
    async fn volume_stamp_report_defaults_to_the_compiled_bound() {
        let td = TempDir::new().unwrap();
        let (state, store) = build_state_with_stamp_store(&td, None);
        store.note_release("vm-a").unwrap();
        let router = build_admin_router(state);
        let resp = router
            .oneshot(authenticated_get("/v1/admin/volume-stamp"))
            .await
            .unwrap();
        let v = json_of(resp).await;
        assert_eq!(
            v["evaluated_bound"],
            kbs_core::volume_stamp::MAX_UNCONFIRMED_RELEASES
        );
    }

    #[tokio::test]
    async fn volume_stamp_report_reports_the_live_bound_when_the_gate_is_armed() {
        let td = TempDir::new().unwrap();
        let (state, _store) = build_state_with_stamp_store(&td, Some(5));
        let router = build_admin_router(state);
        let resp = router
            .oneshot(authenticated_get("/v1/admin/volume-stamp?bound=9"))
            .await
            .unwrap();
        let v = json_of(resp).await;
        // `evaluated_bound` is what the OPERATOR asked about;
        // `configured_bound` is what the process is running. They are
        // independent, and conflating them is how a report ends up
        // green because the gate it is checking is off.
        assert_eq!(v["evaluated_bound"], 9);
        assert_eq!(v["configured_bound"], 5);
        assert_eq!(v["gate_armed"], true);
    }

    #[tokio::test]
    async fn volume_stamp_report_rejects_a_malformed_or_zero_bound() {
        let td = TempDir::new().unwrap();
        let (state, _store) = build_state_with_stamp_store(&td, None);
        let router = build_admin_router(state);
        for (uri, reason) in [
            ("/v1/admin/volume-stamp?bound=abc", "bound-not-a-number"),
            ("/v1/admin/volume-stamp?bound=-1", "bound-not-a-number"),
            // `0` means DISABLED in the operator's vocabulary; evaluated
            // as a number it would refuse every VM — the opposite of
            // what was asked.
            ("/v1/admin/volume-stamp?bound=0", "bound-zero"),
        ] {
            let resp = router
                .clone()
                .oneshot(authenticated_get(uri))
                .await
                .unwrap();
            assert_eq!(resp.status(), StatusCode::BAD_REQUEST, "{uri}");
            let bytes = resp_to_bytes(resp.into_body(), 4096).await.unwrap();
            let parsed: AdminErrorResponse = ciborium::de::from_reader(bytes.as_ref()).unwrap();
            assert_eq!(parsed.reason, reason, "{uri}");
        }
    }

    #[test]
    fn bound_param_parsing() {
        assert_eq!(parse_bound_param(None), Ok(None));
        assert_eq!(parse_bound_param(Some("")), Ok(None));
        assert_eq!(parse_bound_param(Some("other=1")), Ok(None));
        assert_eq!(parse_bound_param(Some("bound=7")), Ok(Some(7)));
        assert_eq!(parse_bound_param(Some("x=1&bound=7")), Ok(Some(7)));
        // First `bound=` wins, explicitly — no surprise last-write.
        assert_eq!(parse_bound_param(Some("bound=7&bound=9")), Ok(Some(7)));
        assert_eq!(parse_bound_param(Some("bound=")), Err(()));
        assert_eq!(parse_bound_param(Some("bound=x")), Err(()));
    }

    #[tokio::test]
    async fn volume_stamp_report_is_read_only_by_method() {
        // A POST to the read route must not be routable — axum answers
        // 405. Pinned so nobody later "helpfully" adds a mutating verb
        // on the same path.
        let td = TempDir::new().unwrap();
        let (state, _store) = build_state_with_stamp_store(&td, None);
        let router = build_admin_router(state);
        let mut req = axum::http::Request::builder()
            .method("POST")
            .uri("/v1/admin/volume-stamp")
            .body(Body::empty())
            .unwrap();
        req.extensions_mut().insert(PeerCertInfo {
            san_uri: "spiffe://hippius.network/operator".into(),
            serial_hex: "01".into(),
        });
        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::METHOD_NOT_ALLOWED);
    }
}
