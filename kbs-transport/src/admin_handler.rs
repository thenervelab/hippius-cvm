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
use crate::spiffe_id::SpiffeId;
use crate::wire::CONTENT_TYPE_CBOR;
use axum::body::{to_bytes, Body};
use axum::extract::{Path, Request, State};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post};
use axum::{Json, Router};
use hippius_types::admin::{
    AdminActivateRequest, AdminActivateResponse, AdminArmBootCounterResyncResponse,
    AdminConfigPostureResponse, AdminCustodyPolicy, AdminCustodyReport, AdminCustodyRow,
    AdminDecommissionRequest, AdminErrorResponse, AdminFenceResponse, AdminRegisterVmResponse,
    AdminReloadAllowlistResponse, AdminResetVolumeStampSuppressionResponse,
    AdminSeedBootCounterRequest, AdminSeedBootCounterResponse, AdminSeedKeepaliveBindingRequest,
    AdminSeedKeepaliveBindingResponse, AdminTombstoneRequest, AdminVolumeStampReportResponse,
    AdminVolumeStampRow,
};
use hippius_types::evidence_bundle::EvidenceBundle;
use hippius_types::rollback::{
    AdminAuthorizeRollbackRequest, AdminAuthorizeRollbackResponse, AdminRollbackStatusResponse,
    MAX_POINT_MANIFEST_LEN,
};
use kbs_core::admin::{
    process_admin_activate, process_admin_arm_boot_counter_resync, process_admin_decommission,
    process_admin_register, process_admin_reset_volume_stamp_suppression,
    process_admin_seed_boot_counter, process_admin_seed_keepalive_binding, process_admin_tombstone,
    record_admin_activate_outcome, record_admin_arm_resync_outcome, record_admin_fence_outcome,
    record_admin_register_outcome, record_admin_reset_volume_stamp_suppression_outcome,
    record_admin_seed_binding_outcome, record_admin_seed_outcome, AdminActivateErr, AdminFenceErr,
    AdminFenceOk, AdminRegisterErr, AdminRegisterOk, VmStateRegister, MAX_ADMIN_BODY_BYTES,
};
use kbs_core::admin_audit::FileAdminAuditSink;
use kbs_core::allowlist::InstalledAllowlist;
use kbs_core::boot_counter::BootCounterStore;
use kbs_core::evidence::EvidenceSink;
use kbs_core::lifecycle::VmStateStore;
use kbs_core::persist::IdempotencyStore;
use kbs_core::rollback::{
    arm_detail, clear_for_lifecycle, process_authorize_rollback, process_rollback_checkpoint,
    purge_expired_and_audit, reconcile_pending, record_rollback_event, rollback_capable,
    rollback_status, validate_authorize_request, RollbackAuditEvent, RollbackErr, RollbackPolicy,
};
use kbs_core::ticket::L1Keyring;
use kbs_core::volume_stamp::VolumeStampStore;
use sha2::{Digest, Sha256};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tower_http::limit::RequestBodyLimitLayer;

/// Body cap of `authorize-rollback`: it carries the restore point's
/// `manifest.json` (≤ [`MAX_POINT_MANIFEST_LEN`] bytes, base64 ⇒ 4/3)
/// plus a few small fields. Every other rollback route keeps
/// [`MAX_ADMIN_BODY_BYTES`].
pub const MAX_AUTHORIZE_ROLLBACK_BODY_BYTES: usize = MAX_POINT_MANIFEST_LEN / 3 * 4 + 64 * 1024;

/// Per-request peer-cert info, populated by the mTLS server before
/// the handler runs. Absent in tests + non-TLS mock setups.
///
/// The identity is typed: it can only hold the AUTHORIZED URI SANs of
/// the leaf, as validated [`SpiffeId`]s — never a DNS SAN or a Subject
/// CN. It is non-empty and sorted by construction.
#[derive(Debug, Clone)]
pub struct PeerCertInfo {
    san_uris: Vec<SpiffeId>,
    /// `san_uris` joined with `,` — cached so handlers can lend a `&str`
    /// to the audit row.
    audit_identity: String,
    /// Cert serial number, hex.
    pub serial_hex: String,
}

impl PeerCertInfo {
    /// `None` when `san_uris` is empty: a peer that no URI SAN names
    /// cannot be attributed, and an empty `peer_san` would read as "no
    /// client cert" in the audit chain.
    pub fn new(mut san_uris: Vec<SpiffeId>, serial_hex: String) -> Option<Self> {
        if san_uris.is_empty() {
            return None;
        }
        san_uris.sort();
        let audit_identity = san_uris
            .iter()
            .map(SpiffeId::as_str)
            .collect::<Vec<_>>()
            .join(",");
        Some(Self {
            san_uris,
            audit_identity,
            serial_hex,
        })
    }

    /// Every authorized URI SAN, sorted.
    pub fn san_uris(&self) -> &[SpiffeId] {
        &self.san_uris
    }

    /// The admin audit row's `peer_san`: the full sorted list of
    /// authorized URI SANs, comma-joined. A leaf with ONE URI SAN (vali's)
    /// yields exactly that URI, byte-identical to the row format before
    /// this list existed. Unambiguous because a [`SpiffeId`] cannot
    /// contain `,`.
    pub fn audit_identity(&self) -> &str {
        &self.audit_identity
    }
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
    /// The SAME custody runtime the public custody routes use. `None` ⇒
    /// custody is off: the report says so and the policy route refuses.
    pub custody: Option<Arc<kbs_core::custody::CustodyRuntime>>,
    /// The SAME keepalive binding store the release path records into
    /// and the keepalive path checks (`DefaultKbsService::
    /// keepalive_bindings`) — used ONLY by `/v1/admin/vm/:vm_id/
    /// seed-keepalive-binding` to re-establish a record a pod restart
    /// wiped. Shared `Arc`, same discipline as `boot_counter`.
    pub keepalive_bindings: Arc<dyn kbs_core::keepalive_binding::KeepaliveBindingStore>,
    /// Authorized rollback (A2, `kbs_core::rollback`). `None` ⇒ the four
    /// rollback routes answer 503 `rollback-unavailable` and nothing can
    /// be armed; lifecycle clears still run (there is nothing to clear).
    pub rollback: Option<Arc<RollbackAdmin>>,
    /// Read handle on the release audit chain (`audit.log`) — the SAME
    /// sink the release path appends through, so `GET /v1/admin/audit?
    /// log=release` pages from the live index. `None` ⇒ that log answers
    /// 503 `audit-log-unavailable` (the admin chain is always `audit`).
    pub release_audit: Option<Arc<kbs_core::audit::FileAuditSink>>,
    /// `[cdn_fleet] enabled`: derives + signs fleet public keys for
    /// `POST /v1/admin/cdn-fleet/public`. `None` ⇒ that route answers 404
    /// `cdn-fleet-disabled`.
    pub cdn_fleet: Option<Arc<dyn crate::cdn_fleet::CdnFleetPublisher>>,
}

/// What the rollback routes need beyond the shared stores.
pub struct RollbackAdmin {
    /// The KBS response key: signs checkpoints, and its public half
    /// verifies them at arm time. The SAME key the release path signs
    /// with (persistent, Vault-backed), so a checkpoint outlives a KBS
    /// restart.
    pub signing_key: Arc<ed25519_dalek::SigningKey>,
    /// Read handle on the SAME lifecycle store `vm_states` writes.
    pub vm_states: Arc<dyn VmStateStore + Send + Sync>,
    pub policy: RollbackPolicy,
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
            custody: self.custody.clone(),
            keepalive_bindings: Arc::clone(&self.keepalive_bindings),
            rollback: self.rollback.clone(),
            release_audit: self.release_audit.clone(),
            cdn_fleet: self.cdn_fleet.clone(),
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
        .route(
            "/v1/admin/vm/:vm_id/decommission",
            post(handle_decommission),
        )
        .route("/v1/admin/vm/:vm_id/tombstone", post(handle_tombstone))
        .route("/v1/admin/vm/:vm_id/evidence", get(handle_get_evidence))
        .route(
            "/v1/admin/vm/:vm_id/seed-boot-counter",
            post(handle_seed_boot_counter),
        )
        .route(
            "/v1/admin/vm/:vm_id/seed-keepalive-binding",
            post(handle_seed_keepalive_binding),
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
        .route("/v1/admin/audit", get(handle_get_audit_page))
        .route("/v1/admin/custody", get(handle_get_custody_report))
        .route("/v1/admin/custody/policy", post(handle_set_custody_policy))
        .route("/v1/admin/allowlist/reload", post(handle_reload_allowlist))
        .route(
            "/v1/admin/cdn-fleet/public",
            post(crate::cdn_fleet::handle_cdn_fleet_public),
        )
        .layer(RequestBodyLimitLayer::new(MAX_ADMIN_BODY_BYTES))
        // The rollback routes cap their own bodies in `rollback_prologue`
        // (per route, see `MAX_AUTHORIZE_ROLLBACK_BODY_BYTES`), so an
        // oversize body is refused — and AUDITED — by the handler rather
        // than by a layer that answers before any audit can run.
        .merge(
            Router::new()
                .route(
                    "/v1/admin/vm/:vm_id/rollback-checkpoint",
                    post(handle_rollback_checkpoint),
                )
                .route(
                    "/v1/admin/vm/:vm_id/authorize-rollback",
                    post(handle_authorize_rollback),
                )
                .route(
                    "/v1/admin/vm/:vm_id/authorize-rollback/:restore_id",
                    delete(handle_disarm_rollback),
                )
                .route("/v1/admin/vm/:vm_id/rollback", get(handle_get_rollback)),
        )
        .with_state(state)
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

/// The parsed `GET /v1/admin/audit` query.
#[derive(Debug, PartialEq, Eq)]
struct AuditQuery {
    log: kbs_core::audit_read::AuditLogKind,
    after_seq: Option<u64>,
    limit: u32,
}

/// Strict: `log` is required, every key at most once, no unknown key,
/// numbers are plain decimals. `limit` defaults to — and is clamped to —
/// [`hippius_types::admin::ADMIN_AUDIT_PAGE_MAX`]; `limit=0` is refused
/// (it would read as "caught up" forever).
fn parse_audit_query(query: Option<&str>) -> Result<AuditQuery, &'static str> {
    let mut log = None;
    let mut after_seq = None;
    let mut limit = None;
    for pair in query.unwrap_or("").split('&').filter(|p| !p.is_empty()) {
        let (k, v) = pair.split_once('=').ok_or("audit-query-malformed")?;
        let dup = match k {
            "log" => log
                .replace(kbs_core::audit_read::AuditLogKind::parse(v).ok_or("audit-log-unknown")?)
                .is_some(),
            "after_seq" => after_seq
                .replace(parse_decimal(v).ok_or("audit-after-seq-invalid")?)
                .is_some(),
            "limit" => limit
                .replace(parse_decimal(v).ok_or("audit-limit-invalid")?)
                .is_some(),
            _ => return Err("audit-query-unknown-key"),
        };
        if dup {
            return Err("audit-query-duplicate-key");
        }
    }
    let limit = match limit {
        None => hippius_types::admin::ADMIN_AUDIT_PAGE_MAX,
        Some(0) => return Err("audit-limit-invalid"),
        Some(n) => u32::try_from(n)
            .unwrap_or(u32::MAX)
            .min(hippius_types::admin::ADMIN_AUDIT_PAGE_MAX),
    };
    Ok(AuditQuery {
        log: log.ok_or("audit-log-required")?,
        after_seq,
        limit,
    })
}

/// A plain decimal `u64` — no sign, no whitespace (`str::parse` takes a
/// leading `+`).
fn parse_decimal(v: &str) -> Option<u64> {
    if v.is_empty() || !v.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    v.parse().ok()
}

/// `GET /v1/admin/audit?log=<admin|release>&after_seq=N&limit=M` — page
/// through one of the KBS hash-chained audit logs
/// ([`hippius_types::admin::AdminAuditPageResponse`]).
///
/// ## Why
///
/// Both chains live on an emptyDir inside the Kata CVM: unreadable from
/// the host, wiped by every restart. This is how vali copies them out
/// (`vali/apps/orchestration/kbs_audit.py`), re-verifying the chain as it
/// goes.
///
/// ## Contract
///
/// - The entries are the EXACT persisted records (`seq`, the stored
///   canonical-CBOR body, the stored hash) plus the body's decoded
///   `prev_hash`. Nothing is filtered: a page is every record after
///   `after_seq`, in order, up to `limit` records and
///   [`kbs_core::audit_read::MAX_AUDIT_PAGE_BYTES`] (at least one). A record that cannot be
///   served verbatim fails the whole call (500 `audit-read-failed`) —
///   it is never skipped.
/// - `genesis_hash_hex` (hash of `seq=0`) names the chain, so a reader
///   tells a KBS restart (new genesis) from a cut chain.
///
/// ## Read-only, and not audited
///
/// It reads a snapshot and writes nothing — no audit record, no purge,
/// no counter. Not auditing it is REQUIRED, not just the house rule for
/// admin reads: a polled read that appended to the chain it serves would
/// grow the emptyDir without bound on an idle KBS.
///
/// ## Auth
///
/// Same gate as `GET /v1/admin/config`: refused unless the request came
/// over a verified client certificate ([`PeerCertInfo`]), which on the
/// mTLS listener also means an allowlisted identity. The chains name
/// every VM, ticket and caller; a plaintext listener must not publish
/// them.
///
/// Errors:
/// - 403 `admin-client-cert-required`.
/// - 429 `rate-limited` — the shared admin bucket.
/// - 400 `audit-log-required` / `audit-log-unknown` /
///   `audit-after-seq-invalid` / `audit-limit-invalid` /
///   `audit-query-malformed` / `audit-query-unknown-key` /
///   `audit-query-duplicate-key`.
/// - 503 `audit-log-unavailable` — the release chain is not wired here.
/// - 500 `audit-read-failed`.
pub async fn handle_get_audit_page(State(state): State<AdminState>, request: Request) -> Response {
    // 1. Client-cert gate FIRST.
    if request.extensions().get::<PeerCertInfo>().is_none() {
        return admin_err(StatusCode::FORBIDDEN, "admin-client-cert-required");
    }
    // 2. The shared admin bucket.
    if !state.limiter.try_acquire() {
        return rate_limited();
    }
    // 3. The query.
    let q = match parse_audit_query(request.uri().query()) {
        Ok(q) => q,
        Err(reason) => return admin_err(StatusCode::BAD_REQUEST, reason),
    };
    // 4. One read-only page — on the blocking pool: it is disk IO, and the
    //    async workers are the ones serving releases.
    use kbs_core::audit_read::AuditLogKind;
    let (after, limit) = (q.after_seq, q.limit);
    let read = match q.log {
        AuditLogKind::Admin => {
            let sink = Arc::clone(&state.audit);
            tokio::task::spawn_blocking(move || sink.read_page(after, limit)).await
        }
        AuditLogKind::Release => match state.release_audit.as_ref() {
            Some(sink) => {
                let sink = Arc::clone(sink);
                tokio::task::spawn_blocking(move || sink.read_page(after, limit)).await
            }
            None => {
                return admin_err(StatusCode::SERVICE_UNAVAILABLE, "audit-log-unavailable");
            }
        },
    };
    let page = match read {
        Ok(page) => page,
        Err(e) => {
            eprintln!("kbs-transport: GET /v1/admin/audit: read task failed: {e}");
            return admin_err(StatusCode::INTERNAL_SERVER_ERROR, "audit-read-failed");
        }
    };
    match page {
        Ok(page) => (StatusCode::OK, Json(page.to_wire(q.log))).into_response(),
        Err(e) => {
            eprintln!(
                "kbs-transport: GET /v1/admin/audit log={}: {e}",
                q.log.as_str()
            );
            admin_err(StatusCode::INTERNAL_SERVER_ERROR, "audit-read-failed")
        }
    }
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
        peer.as_ref().map(|p| p.audit_identity()),
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
/// exact `(new_gen, dest)` returns 200. A divergent re-drive at that
/// `new_gen`, or an activate over no state / `Decommissioning` /
/// `Destroyed`, is a 409 — the fence never force-moves. A `new_gen` that
/// does not strictly exceed the current holder's generation is a 409
/// `activate-not-monotonic` and writes nothing. Over a `Migrating` row, a
/// strictly higher `new_gen` is the next hop: the previous dest becomes
/// the fenced-out source.
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
    purge_expired_arms_for_lifecycle(&state, "activate", now);

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
                peer.as_ref().map(|p| p.audit_identity()),
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
        peer.as_ref().map(|p| p.audit_identity()),
        peer.as_ref().map(|p| p.serial_hex.as_str()),
        &outcome,
        now,
    );

    // 4b. An APPLIED activate moves the fence, so any authorized-rollback
    // arm bound to the previous (gen, dest) is void: clear it (audited).
    // A CACHED re-drive of the same hop does NOT clear — vali activates
    // BEFORE it arms, and a retried activate must not destroy the arm it
    // is about to rely on.
    if let Ok(ok) = &outcome {
        if !ok.cached {
            clear_for_lifecycle(
                state.boot_counter.as_ref(),
                Some(state.audit.as_ref()),
                &url_vm_id,
                "activate",
                peer.as_ref().map(|p| p.audit_identity()),
                peer.as_ref().map(|p| p.serial_hex.as_str()),
                now,
            );
            // …and a rollback applied under that arm but never delivered
            // is put back (no-op when nothing is pending).
            if let Err(e) = reconcile_pending(
                &url_vm_id,
                state.boot_counter.as_ref(),
                state.volume_stamp.as_ref(),
                Some(state.audit.as_ref()),
                now,
            ) {
                eprintln!("kbs-transport: activate: rollback reconcile vm_id={url_vm_id}: {e}");
            }
        }
    }

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

/// The lazy expiry purge (each purged arm audited `rollback-expired`)
/// at the top of every lifecycle route, as on the rollback routes. It
/// never blocks the lifecycle write: a failure is reported, and the
/// release path refuses an expired arm on its own anyway.
fn purge_expired_arms_for_lifecycle(state: &AdminState, route: &str, now: u64) {
    if let Err(e) =
        purge_expired_and_audit(state.boot_counter.as_ref(), Some(state.audit.as_ref()), now)
    {
        eprintln!("kbs-transport: {route}: expired rollback-arm purge failed: {e}");
    }
}

fn admin_err(status: StatusCode, reason: &str) -> Response {
    err_response(
        status,
        &AdminErrorResponse {
            reason: reason.into(),
            ticket_id: None,
            vm_id: None,
        },
    )
}

fn rate_limited() -> Response {
    let mut resp = admin_err(StatusCode::TOO_MANY_REQUESTS, "rate-limited");
    resp.headers_mut()
        .insert(header::RETRY_AFTER, HeaderValue::from_static("1"));
    resp
}

fn custody_policy_wire(p: kbs_core::custody::CustodyPolicy) -> AdminCustodyPolicy {
    AdminCustodyPolicy {
        v: 1,
        ttl_s: p.ttl_s,
        stage2_s: p.stage2_s,
        renew_s: p.renew_s,
    }
}

/// `GET /v1/admin/custody` — every bound custody guest: lease age, the
/// guest's self-reported phase (a suspended guest says so here), claimed
/// clock mode, clock lag and skew flag, rebinds in the last hour. vali
/// polls it; after a KBS restart it is also how the ceremony verifies
/// that every enforce-mode guest re-bound. JSON, like the other reads.
pub async fn handle_get_custody_report(
    State(state): State<AdminState>,
    _request: Request,
) -> Response {
    if !state.limiter.try_acquire() {
        return rate_limited();
    }
    let now = match now_unix() {
        Ok(n) => n,
        Err(e) => return err_response(StatusCode::INTERNAL_SERVER_ERROR, &e),
    };
    let Some(rt) = state.custody.as_ref() else {
        return (
            StatusCode::OK,
            Json(AdminCustodyReport {
                v: 1,
                enabled: false,
                policy: None,
                now,
                vms: Vec::new(),
            }),
        )
            .into_response();
    };
    let records = match rt.store.list() {
        Ok(r) => r,
        Err(_) => return admin_err(StatusCode::INTERNAL_SERVER_ERROR, "internal-error"),
    };
    let vms = records
        .into_iter()
        .map(|r| {
            let since = r.last_grant_at.unwrap_or(r.bound_at);
            AdminCustodyRow {
                age_s: now.saturating_sub(since),
                last_verdict: match r.last_verdict {
                    Some(0) => "granted",
                    Some(1) => "revoked",
                    Some(2) => "superseded",
                    _ => "none",
                }
                .into(),
                phase: match r.phase {
                    0 => "armed",
                    1 => "suspended",
                    _ => "unbound",
                }
                .into(),
                clock_mode: if r.clock_mode == 1 {
                    "secure_tsc"
                } else {
                    "untrusted"
                }
                .into(),
                clock_trusted: false,
                rebinds_1h: r
                    .rebinds
                    .iter()
                    .filter(|t| now.saturating_sub(**t) < 3_600)
                    .count()
                    .try_into()
                    .unwrap_or(u32::MAX),
                vm_id: r.vm_id,
                generation: r.generation,
                boot_counter: r.boot_counter,
                node: r.node,
                bound_at: r.bound_at,
                last_request_at: r.last_request_at,
                last_grant_at: r.last_grant_at,
                suspended_s: r.suspended_s,
                since_last_grant_s: r.since_last_grant_s,
                lag_s: r.lag_s,
                skew_suspected: r.skew_suspected,
            }
        })
        .collect();
    (
        StatusCode::OK,
        Json(AdminCustodyReport {
            v: 1,
            enabled: true,
            policy: Some(custody_policy_wire(rt.policy())),
            now,
            vms,
        }),
    )
        .into_response()
}

/// `POST /v1/admin/custody/policy` — the fleet-wide kill switch: replace
/// the lease TTL / stage-2 / renew interval (JSON [`AdminCustodyPolicy`]),
/// e.g. raise the TTL before planned KBS maintenance. Bounded by
/// `CustodyPolicy::validate` — there is no "grant for ever" — and every
/// guest still clamps to the caps in its measured cmdline. In memory only:
/// a restart returns to the configured policy. Audited
/// (`op="custody-policy"`).
pub async fn handle_set_custody_policy(
    State(state): State<AdminState>,
    request: Request,
) -> Response {
    use kbs_core::admin_audit::AdminAuditRecord;
    if !state.limiter.try_acquire() {
        return rate_limited();
    }
    let (parts, body) = request.into_parts();
    let peer = parts.extensions.get::<PeerCertInfo>().cloned();
    let bytes = match to_bytes(body, MAX_ADMIN_BODY_BYTES).await {
        Ok(b) => b,
        Err(_) => return admin_err(StatusCode::PAYLOAD_TOO_LARGE, "body-too-large"),
    };
    let mut body_sha = [0u8; 32];
    body_sha.copy_from_slice(Sha256::digest(&bytes).as_slice());
    let now = match now_unix() {
        Ok(n) => n,
        Err(e) => return err_response(StatusCode::INTERNAL_SERVER_ERROR, &e),
    };
    let outcome: Result<AdminCustodyPolicy, (StatusCode, &'static str)> = (|| {
        let rt = state
            .custody
            .as_ref()
            .ok_or((StatusCode::CONFLICT, "custody-disabled"))?;
        let req: AdminCustodyPolicy = serde_json::from_slice(&bytes)
            .map_err(|_| (StatusCode::BAD_REQUEST, "custody-policy-body-decode"))?;
        if req.v != 1 {
            return Err((StatusCode::BAD_REQUEST, "custody-policy-body-decode"));
        }
        let policy = kbs_core::custody::CustodyPolicy {
            ttl_s: req.ttl_s,
            stage2_s: req.stage2_s,
            renew_s: req.renew_s,
        };
        rt.set_policy(policy)
            .map_err(|_| (StatusCode::BAD_REQUEST, "custody-policy-out-of-bounds"))?;
        Ok(custody_policy_wire(rt.policy()))
    })();
    let (applied, status, reason) = match &outcome {
        Ok(_) => (true, 200u16, None),
        Err((code, r)) => (false, code.as_u16(), Some(*r)),
    };
    let _ = state.audit.append(
        &AdminAuditRecord {
            op: "custody-policy",
            url_vm_id: "",
            ticket_id: None,
            vm_id: None,
            applied,
            status_code: status,
            reason,
            peer_san: peer.as_ref().map(|p| p.audit_identity()),
            peer_serial: peer.as_ref().map(|p| p.serial_hex.as_str()),
            body_sha256: &body_sha,
        },
        now,
    );
    match outcome {
        Ok(p) => (StatusCode::OK, Json(p)).into_response(),
        Err((code, reason)) => admin_err(code, reason),
    }
}

/// Which §24 fence a request is for, with its decoded body.
enum FenceRequest {
    Decommission,
    Tombstone { gen: u64 },
}

impl FenceRequest {
    fn op(&self) -> &'static str {
        match self {
            FenceRequest::Decommission => "decommission",
            FenceRequest::Tombstone { .. } => "tombstone",
        }
    }
}

/// `POST /v1/admin/vm/{vm_id}/decommission` — the §24 KBS fence
/// (`Active | Migrating | absent` → `Decommissioning`). vali posts it
/// right after its own decommission CAS, before the crypto-erase.
///
/// Body: JSON [`AdminDecommissionRequest`] (`{"v": 1}`). 200 JSON
/// [`AdminFenceResponse`]; refusals are the CBOR [`AdminErrorResponse`]
/// every sibling uses (400 body decode / 413 / 429 / 500). Applied and
/// refused calls both land in the hash-chained admin log
/// (`op="decommission"`).
pub async fn handle_decommission(
    State(state): State<AdminState>,
    Path(url_vm_id): Path<String>,
    request: Request,
) -> Response {
    handle_fence(state, url_vm_id, request, |bytes| {
        let req: AdminDecommissionRequest = serde_json::from_slice(bytes).ok()?;
        (req.v == 1).then_some(FenceRequest::Decommission)
    })
    .await
}

/// `POST /v1/admin/vm/{vm_id}/tombstone` — the permanent §24 marker
/// (`→ Destroyed{gen}`), posted by vali's destroy step and by
/// `vali_kbs_recover --reinstall-tombstones` after a KBS restart.
///
/// Body: JSON [`AdminTombstoneRequest`] (`{"v": 1, "gen": N}`). Same
/// responses as `decommission`, plus 409 `tombstone-generation-conflict`
/// when the VM is already `Destroyed` at another generation (nothing is
/// written; the caller must not retry that).
pub async fn handle_tombstone(
    State(state): State<AdminState>,
    Path(url_vm_id): Path<String>,
    request: Request,
) -> Response {
    handle_fence(state, url_vm_id, request, |bytes| {
        let req: AdminTombstoneRequest = serde_json::from_slice(bytes).ok()?;
        (req.v == 1).then_some(FenceRequest::Tombstone { gen: req.gen })
    })
    .await
}

async fn handle_fence(
    state: AdminState,
    url_vm_id: String,
    request: Request,
    decode: impl FnOnce(&[u8]) -> Option<FenceRequest>,
) -> Response {
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
    let peer = parts.extensions.get::<PeerCertInfo>().cloned();
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
    purge_expired_arms_for_lifecycle(&state, "fence", now);
    let (op, outcome): (&'static str, Result<AdminFenceOk, AdminFenceErr>) = match decode(&bytes) {
        Some(req) => {
            let op = req.op();
            let outcome = match req {
                FenceRequest::Decommission => {
                    process_admin_decommission(&url_vm_id, state.vm_states.as_ref())
                }
                FenceRequest::Tombstone { gen } => {
                    process_admin_tombstone(&url_vm_id, gen, state.vm_states.as_ref())
                }
            };
            (op, outcome)
        }
        // A garbled body against a fence route is worth a row in the
        // chain too; the op is the route's, named from the URL shape.
        None => (
            if parts.uri.path().ends_with("/tombstone") {
                "tombstone"
            } else {
                "decommission"
            },
            Err(AdminFenceErr::BadRequest("fence-body-decode")),
        ),
    };
    let _ = record_admin_fence_outcome(
        state.audit.as_ref(),
        op,
        &url_vm_id,
        &body_sha,
        peer.as_ref().map(|p| p.audit_identity()),
        peer.as_ref().map(|p| p.serial_hex.as_str()),
        &outcome,
        now,
    );
    // A §24 fence (applied OR already in place) ends every rollback
    // permission for the VM: clear its arm, audited.
    if outcome.is_ok() {
        clear_for_lifecycle(
            state.boot_counter.as_ref(),
            Some(state.audit.as_ref()),
            &url_vm_id,
            op,
            peer.as_ref().map(|p| p.audit_identity()),
            peer.as_ref().map(|p| p.serial_hex.as_str()),
            now,
        );
        if let Err(e) = reconcile_pending(
            &url_vm_id,
            state.boot_counter.as_ref(),
            state.volume_stamp.as_ref(),
            Some(state.audit.as_ref()),
            now,
        ) {
            eprintln!("kbs-transport: {op}: rollback reconcile vm_id={url_vm_id}: {e}");
        }
    }
    match outcome {
        Ok(ok) => match serde_json::to_vec(&AdminFenceResponse {
            v: 1,
            vm_id: ok.vm_id,
            previous: ok.previous.into(),
            state: ok.state.into(),
            cached: ok.cached,
        }) {
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
        },
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
                peer.as_ref().map(|p| p.audit_identity()),
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
        peer.as_ref().map(|p| p.audit_identity()),
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

/// `POST /v1/admin/vm/{vm_id}/seed-keepalive-binding` — re-establish a
/// keepalive binding record (`kbs_core::keepalive_binding`) that a pod
/// restart wiped, from the `(CHIP_ID, REPORT_ID)` vali last saw in a
/// KBS-signed, release-bound live attestation.
///
/// Body: JSON [`AdminSeedKeepaliveBindingRequest`]. Replies:
/// - 200 JSON [`AdminSeedKeepaliveBindingResponse`] `{seeded:true,
///   matched:false}` — the row was empty and is now seeded (at a position
///   every real release supersedes).
/// - 200 JSON `{seeded:false, matched:true}` — a record already names this
///   same guest; nothing written.
/// - 400 `seed-body-decode` / `vm-id-empty` / `vm-id-invalid` /
///   `chip-id-malformed` / `report-id-malformed` / `chip-id-zero` /
///   `report-id-zero` — nothing written.
/// - 412 `binding-vm-not-active` — the lifecycle row is absent,
///   decommissioning or destroyed. Nothing written.
/// - 412 `binding-chip-not-host` — the chip is not the platform the row
///   says the VM may be released on. Nothing written.
/// - 409 `binding-already-recorded` — a record names a different guest;
///   a seed never overwrites one. Nothing written.
/// - 409 `binding-poisoned` — the VM is poisoned (a release committed but
///   its guest could not be recorded); a seed never clears that. Nothing
///   written.
/// - 500 `internal-error` — a store failed; nothing written.
///
/// Errors are CBOR [`AdminErrorResponse`], like every route here. Every
/// call lands in the admin audit chain with `op="seed-keepalive-binding"`.
pub async fn handle_seed_keepalive_binding(
    State(state): State<AdminState>,
    Path(url_vm_id): Path<String>,
    request: Request,
) -> Response {
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
    let peer = parts.extensions.get::<PeerCertInfo>().cloned();
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

    let outcome = match serde_json::from_slice::<AdminSeedKeepaliveBindingRequest>(&bytes) {
        Ok(req) => process_admin_seed_keepalive_binding(
            &url_vm_id,
            &req.chip_id_hex,
            &req.report_id_hex,
            state.vm_states.as_ref(),
            state.keepalive_bindings.as_ref(),
        ),
        Err(_) => Err(kbs_core::admin::AdminSeedBindingErr::BadRequest(
            "seed-body-decode",
        )),
    };
    let _ = record_admin_seed_binding_outcome(
        state.audit.as_ref(),
        &url_vm_id,
        &body_sha,
        peer.as_ref().map(|p| p.audit_identity()),
        peer.as_ref().map(|p| p.serial_hex.as_str()),
        &outcome,
        now,
    );
    match outcome {
        Ok(ok) => match serde_json::to_vec(&AdminSeedKeepaliveBindingResponse {
            v: 1,
            vm_id: ok.vm_id,
            seeded: ok.seeded,
            matched: ok.matched,
        }) {
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
        },
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
        peer.as_ref().map(|p| p.audit_identity()),
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
        peer.as_ref().map(|p| p.audit_identity()),
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

// ─── authorized rollback (A2) ────────────────────────────────────────

fn json_response<T: serde::Serialize>(status: StatusCode, body: &T) -> Response {
    match serde_json::to_vec(body) {
        Ok(bytes) => {
            let mut resp = Response::new(Body::from(bytes));
            *resp.status_mut() = status;
            resp.headers_mut().insert(
                header::CONTENT_TYPE,
                HeaderValue::from_static("application/json"),
            );
            resp
        }
        Err(_) => (StatusCode::INTERNAL_SERVER_ERROR, "encode-error").into_response(),
    }
}

/// JSON error for the rollback routes (the whole route family is JSON,
/// so vali parses one format): [`RollbackErr::to_wire`] with
/// [`RollbackErr::status_code`]. 429 also sets `Retry-After`.
fn rollback_err_response(url_vm_id: &str, e: &RollbackErr) -> Response {
    let status = StatusCode::from_u16(e.status_code()).unwrap_or(StatusCode::BAD_REQUEST);
    let mut resp = json_response(status, &e.to_wire(url_vm_id));
    if let Some(s) = e.retry_after_s() {
        if let Ok(v) = HeaderValue::from_str(&s.to_string()) {
            resp.headers_mut().insert(header::RETRY_AFTER, v);
        }
    }
    resp
}

/// Common prologue of the four rollback routes: gateway rate limit,
/// peer identity, body (capped per route, hashed), clock, the rollback
/// context, the lazy purge of expired arms (each audited
/// `rollback-expired`) and the pending-rollback reconciliation.
///
/// Every refusal here is audited under the route's `op` with whatever
/// peer identity the request carried (none on a 403): 403
/// `admin-client-cert-required`, 413 `body-too-large`, 503
/// `rollback-unavailable`, and 429 `rate-limited` — the latter coalesced
/// to at most one row per second per process, so a flood the limiter
/// is shedding cannot turn into an fsync-per-request amplifier.
struct RollbackCall {
    peer: Option<PeerCertInfo>,
    bytes: axum::body::Bytes,
    body_sha: [u8; 32],
    now: u64,
    ctx: Arc<RollbackAdmin>,
}

/// The second of the last audited prologue 429.
static LAST_RATE_LIMIT_AUDIT_S: AtomicU64 = AtomicU64::new(0);

#[allow(clippy::too_many_arguments)]
fn audit_prologue_refusal(
    state: &AdminState,
    op: &'static str,
    url_vm_id: &str,
    peer: Option<&PeerCertInfo>,
    body_sha: [u8; 32],
    status_code: u16,
    reason: &str,
    now: u64,
) {
    let ev = RollbackAuditEvent {
        op,
        url_vm_id,
        restore_id: None,
        applied: false,
        status_code,
        reason,
        peer_san: peer.map(|p| p.audit_identity()),
        peer_serial: peer.map(|p| p.serial_hex.as_str()),
        body_sha256: body_sha,
    };
    if let Err(e) = record_rollback_event(state.audit.as_ref(), &ev, now) {
        eprintln!("kbs-transport: admin-audit append failed for {op} vm_id={url_vm_id}: {e}");
    }
}

async fn rollback_prologue(
    state: &AdminState,
    op: &'static str,
    url_vm_id: &str,
    body_cap: usize,
    request: Request,
) -> Result<RollbackCall, Response> {
    let (parts, body) = request.into_parts();
    let peer = parts.extensions.get::<PeerCertInfo>().cloned();
    // A clock failure is refused below; the refusal rows written before
    // it carry 0.
    let clock = now_unix().ok();
    let refuse = |e: &RollbackErr, body_sha: [u8; 32]| {
        audit_prologue_refusal(
            state,
            op,
            url_vm_id,
            peer.as_ref(),
            body_sha,
            e.status_code(),
            e.reason(),
            clock.unwrap_or(0),
        );
    };
    if !state.limiter.try_acquire() {
        let now_s = clock.unwrap_or(0);
        let last = LAST_RATE_LIMIT_AUDIT_S.load(Ordering::Relaxed);
        if now_s > last
            && LAST_RATE_LIMIT_AUDIT_S
                .compare_exchange(last, now_s, Ordering::Relaxed, Ordering::Relaxed)
                .is_ok()
        {
            refuse(&RollbackErr::GatewayRateLimited, [0u8; 32]);
        }
        return Err(rollback_err_response(
            url_vm_id,
            &RollbackErr::GatewayRateLimited,
        ));
    }
    // The rollback routes re-admit an OLD disk, so — like the two
    // stricter reads — they demand a VERIFIED client identity per
    // request, whatever the listener's mode. On a listener an operator
    // opted into plaintext (`require_mtls = false`, no material) they are
    // therefore unreachable, not merely network-gated.
    if peer.is_none() {
        refuse(&RollbackErr::ClientCertRequired, [0u8; 32]);
        return Err(rollback_err_response(
            url_vm_id,
            &RollbackErr::ClientCertRequired,
        ));
    }
    let Ok(bytes) = to_bytes(body, body_cap).await else {
        refuse(&RollbackErr::BodyTooLarge, [0u8; 32]);
        return Err(rollback_err_response(url_vm_id, &RollbackErr::BodyTooLarge));
    };
    let mut body_sha = [0u8; 32];
    body_sha.copy_from_slice(Sha256::digest(&bytes).as_slice());
    let Some(now) = clock else {
        refuse(&RollbackErr::ClockUnavailable, body_sha);
        return Err(rollback_err_response(
            url_vm_id,
            &RollbackErr::ClockUnavailable,
        ));
    };
    let Some(ctx) = state.rollback.clone() else {
        refuse(&RollbackErr::Unavailable, body_sha);
        return Err(rollback_err_response(url_vm_id, &RollbackErr::Unavailable));
    };
    purge_expired_and_audit(state.boot_counter.as_ref(), Some(state.audit.as_ref()), now)
        .map_err(|e| rollback_err_response(url_vm_id, &RollbackErr::Internal(e.to_string())))?;
    reconcile_pending(
        url_vm_id,
        state.boot_counter.as_ref(),
        state.volume_stamp.as_ref(),
        Some(state.audit.as_ref()),
        now,
    )
    .map_err(|e| rollback_err_response(url_vm_id, &RollbackErr::Internal(e.to_string())))?;
    Ok(RollbackCall {
        peer,
        bytes,
        body_sha,
        now,
        ctx,
    })
}

/// Append one rollback route outcome to the admin chain. An audit write
/// failure on a route that CHANGED state is surfaced as a 500 after the
/// fact by the caller's choice; here it is reported on stderr (same
/// posture as the sibling routes, which ignore the append result).
#[allow(clippy::too_many_arguments)]
fn audit_rollback(
    state: &AdminState,
    call: &RollbackCall,
    op: &'static str,
    url_vm_id: &str,
    restore_id: Option<&str>,
    applied: bool,
    status_code: u16,
    reason: &str,
) -> bool {
    let ev = RollbackAuditEvent {
        op,
        url_vm_id,
        restore_id,
        applied,
        status_code,
        reason,
        peer_san: call.peer.as_ref().map(|p| p.audit_identity()),
        peer_serial: call.peer.as_ref().map(|p| p.serial_hex.as_str()),
        body_sha256: call.body_sha,
    };
    match record_rollback_event(state.audit.as_ref(), &ev, call.now) {
        Ok(_) => true,
        Err(e) => {
            eprintln!("kbs-transport: admin-audit append failed for {op} vm_id={url_vm_id}: {e}");
            false
        }
    }
}

/// Body of `rollback-checkpoint`: empty, or `{}`.
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct EmptyBody {}

/// `POST /v1/admin/vm/{vm_id}/rollback-checkpoint` — sign the VM's
/// current anti-rollback state (C-4). Body `{}` (or empty). 200
/// `AdminRollbackCheckpointResponse`; 404 `no-vm-row`; 409
/// `no-boot-counter` (stored == 0) / `vm-fenced` (row decommissioning or
/// destroyed). Audited `rollback-checkpoint` (applied=false: it writes
/// nothing).
pub async fn handle_rollback_checkpoint(
    State(state): State<AdminState>,
    Path(url_vm_id): Path<String>,
    request: Request,
) -> Response {
    let call = match rollback_prologue(
        &state,
        "rollback-checkpoint",
        &url_vm_id,
        MAX_ADMIN_BODY_BYTES,
        request,
    )
    .await
    {
        Ok(c) => c,
        Err(resp) => return resp,
    };
    if !call.bytes.is_empty() && serde_json::from_slice::<EmptyBody>(&call.bytes).is_err() {
        let _ = audit_rollback(
            &state,
            &call,
            "rollback-checkpoint",
            &url_vm_id,
            None,
            false,
            400,
            RollbackErr::CheckpointBodyDecode.reason(),
        );
        return rollback_err_response(&url_vm_id, &RollbackErr::CheckpointBodyDecode);
    }
    let outcome = process_rollback_checkpoint(
        &url_vm_id,
        call.ctx.vm_states.as_ref(),
        state.boot_counter.as_ref(),
        state.volume_stamp.as_ref(),
        &call.ctx.signing_key,
        call.now,
    );
    match outcome {
        Ok(ok) => {
            let detail = format!(
                "signed boot_counter={} volume_stamp={} unconfirmed={} generation={}{}",
                ok.checkpoint.boot_counter,
                ok.checkpoint.volume_stamp,
                ok.checkpoint.unconfirmed_releases,
                ok.checkpoint.generation,
                if ok.checkpoint.volume_stamp == 0 {
                    " unstamped (not armable)"
                } else {
                    ""
                },
            );
            let _ = audit_rollback(
                &state,
                &call,
                "rollback-checkpoint",
                &url_vm_id,
                None,
                false,
                200,
                &detail,
            );
            json_response(StatusCode::OK, &ok.to_wire())
        }
        Err(e) => {
            let _ = audit_rollback(
                &state,
                &call,
                "rollback-checkpoint",
                &url_vm_id,
                None,
                false,
                e.status_code(),
                e.reason(),
            );
            rollback_err_response(&url_vm_id, &e)
        }
    }
}

/// `POST /v1/admin/vm/{vm_id}/authorize-rollback` — arm a one-shot
/// rollback (C-4). 201 `{arm}` fresh; 200 `{arm}` when the same
/// `restore_id` is already armed with the same binding. Refusals: 400
/// `bad-checkpoint-signature` / `checkpoint-vm-mismatch` /
/// `ttl-out-of-range` / `authorize-body-decode` / `manifest-mismatch` /
/// `bad-*` (incl. `bad-point-manifest`); 409 `not-a-rollback` /
/// `row-not-activated` / `arm-exists` / `checkpoint-unstamped`; 413
/// `body-too-large` over [`MAX_AUTHORIZE_ROLLBACK_BODY_BYTES`]; 429
/// `rollback-rate-limited` + `retry_after_s`. Every outcome is audited
/// `authorize-rollback` with the peer SAN/serial.
pub async fn handle_authorize_rollback(
    State(state): State<AdminState>,
    Path(url_vm_id): Path<String>,
    request: Request,
) -> Response {
    let call = match rollback_prologue(
        &state,
        "authorize-rollback",
        &url_vm_id,
        MAX_AUTHORIZE_ROLLBACK_BODY_BYTES,
        request,
    )
    .await
    {
        Ok(c) => c,
        Err(resp) => return resp,
    };
    let req: AdminAuthorizeRollbackRequest = match serde_json::from_slice(&call.bytes) {
        Ok(r) => r,
        Err(_) => {
            let _ = audit_rollback(
                &state,
                &call,
                "authorize-rollback",
                &url_vm_id,
                None,
                false,
                400,
                RollbackErr::AuthorizeBodyDecode.reason(),
            );
            return rollback_err_response(&url_vm_id, &RollbackErr::AuthorizeBodyDecode);
        }
    };
    // Shape first, side-effect free: a malformed body is refused (and its
    // outcome audited WITHOUT echoing its unvalidated fields) before the
    // intent row, so it can never land oversized values in the chain.
    if let Err(e) = validate_authorize_request(&url_vm_id, &req) {
        let _ = audit_rollback(
            &state,
            &call,
            "authorize-rollback",
            &url_vm_id,
            None,
            false,
            e.status_code(),
            e.reason(),
        );
        return rollback_err_response(&url_vm_id, &e);
    }
    // INTENT first: the full binding goes into the hash chain BEFORE any
    // arm can exist, and nothing is armed if it cannot be written. So
    // every arm the store ever holds has an audit row preceding it —
    // even if the outcome record below later fails, or a release
    // consumes the arm before it is written.
    let intent = format!(
        "intent restore_id={} manifest={} new_gen={} dest={} ttl_s={} requested_by={} \
         checkpoint_sha256={}",
        req.restore_id,
        req.point_manifest_sha256_hex,
        req.new_gen,
        req.dest_platform_id_hex,
        req.ttl_s,
        req.requested_by,
        hex_lower(&Sha256::digest(req.checkpoint_cbor_hex.as_bytes())),
    );
    if !audit_rollback(
        &state,
        &call,
        "authorize-rollback-intent",
        &url_vm_id,
        Some(&req.restore_id),
        false,
        0,
        &intent,
    ) {
        return rollback_err_response(&url_vm_id, &RollbackErr::AuditUnavailable);
    }
    let outcome = process_authorize_rollback(
        &url_vm_id,
        &req,
        call.ctx.vm_states.as_ref(),
        state.boot_counter.as_ref(),
        state.volume_stamp.as_ref(),
        &call.ctx.signing_key.verifying_key(),
        &call.ctx.policy,
        call.peer.as_ref().map(|p| p.audit_identity()),
        call.now,
    );
    match outcome {
        Ok(ok) => {
            let (status, verb) = if ok.fresh {
                (StatusCode::CREATED, "armed")
            } else {
                (StatusCode::OK, "already-armed")
            };
            let detail = format!("{verb} {}", arm_detail(&ok.arm));
            let _ = audit_rollback(
                &state,
                &call,
                "authorize-rollback",
                &url_vm_id,
                Some(&req.restore_id),
                ok.fresh,
                status.as_u16(),
                &detail,
            );
            json_response(
                status,
                &AdminAuthorizeRollbackResponse {
                    arm: ok.arm.to_wire(),
                },
            )
        }
        Err(e) => {
            let _ = audit_rollback(
                &state,
                &call,
                "authorize-rollback",
                &url_vm_id,
                Some(&req.restore_id),
                false,
                e.status_code(),
                e.reason(),
            );
            rollback_err_response(&url_vm_id, &e)
        }
    }
}

/// `DELETE /v1/admin/vm/{vm_id}/authorize-rollback/{restore_id}` —
/// disarm (C-4). Always 204 (idempotent); audited `rollback-disarm`,
/// `applied=true` only when an arm with that id was removed.
pub async fn handle_disarm_rollback(
    State(state): State<AdminState>,
    Path((url_vm_id, restore_id)): Path<(String, String)>,
    request: Request,
) -> Response {
    let call = match rollback_prologue(
        &state,
        "rollback-disarm",
        &url_vm_id,
        MAX_ADMIN_BODY_BYTES,
        request,
    )
    .await
    {
        Ok(c) => c,
        Err(resp) => return resp,
    };
    match state
        .boot_counter
        .disarm_rollback(&url_vm_id, &restore_id, Some(call.now))
    {
        Ok(removed) => {
            // A rollback applied under the arm just removed but never
            // delivered goes back now, not at the VM's next release.
            if let Err(e) = reconcile_pending(
                &url_vm_id,
                state.boot_counter.as_ref(),
                state.volume_stamp.as_ref(),
                Some(state.audit.as_ref()),
                call.now,
            ) {
                eprintln!("kbs-transport: disarm: rollback reconcile vm_id={url_vm_id}: {e}");
            }
            let detail = match &removed {
                Some(arm) => format!("disarmed {}", arm_detail(arm)),
                None => "not-armed".to_string(),
            };
            let _ = audit_rollback(
                &state,
                &call,
                "rollback-disarm",
                &url_vm_id,
                Some(&restore_id),
                removed.is_some(),
                204,
                &detail,
            );
            StatusCode::NO_CONTENT.into_response()
        }
        Err(e) => {
            let e = RollbackErr::Internal(e.to_string());
            let _ = audit_rollback(
                &state,
                &call,
                "rollback-disarm",
                &url_vm_id,
                Some(&restore_id),
                false,
                e.status_code(),
                e.reason(),
            );
            rollback_err_response(&url_vm_id, &e)
        }
    }
}

/// `GET /v1/admin/vm/{vm_id}/rollback` — `{arm | null, last_rollback |
/// null, last_clear | null}` (C-4). `last_rollback.delivered` /
/// `.reverted` say how the last consumed rollback ended (both false ⇒ in
/// flight); `last_clear {restore_id, reason, at}` is the last arm
/// that left WITHOUT a consume, and why. A pure read (after the lazy
/// expiry purge and reconciliation).
pub async fn handle_get_rollback(
    State(state): State<AdminState>,
    Path(url_vm_id): Path<String>,
    request: Request,
) -> Response {
    let call = match rollback_prologue(
        &state,
        "rollback-status",
        &url_vm_id,
        MAX_ADMIN_BODY_BYTES,
        request,
    )
    .await
    {
        Ok(c) => c,
        Err(resp) => return resp,
    };
    let read = || -> Result<AdminRollbackStatusResponse, RollbackErr> {
        let store = |e: kbs_core::error::KbsError| RollbackErr::Internal(e.to_string());
        let (arm, last) = state
            .boot_counter
            .rollback_state(&url_vm_id)
            .map_err(store)?;
        let resolution = state
            .volume_stamp
            .rollback_resolution(&url_vm_id)
            .map_err(store)?;
        let last_clear = state
            .boot_counter
            .rollback_last_clear(&url_vm_id)
            .map_err(store)?;
        let capable = rollback_capable(
            &url_vm_id,
            call.ctx.vm_states.as_ref(),
            state.volume_stamp.as_ref(),
        )?;
        Ok(rollback_status(
            arm.as_ref(),
            last.as_ref(),
            resolution.as_ref(),
            last_clear.as_ref(),
            capable,
            call.now,
        ))
    };
    match read() {
        Ok(body) => json_response(StatusCode::OK, &body),
        Err(e) => rollback_err_response(&url_vm_id, &e),
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
            key_mode: None,
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
        let vm_states_concrete =
            Arc::new(FileVmStateStore::open(td.path().join("vm-states.json")).unwrap());
        let vm_states: Arc<dyn VmStateRegister + Send + Sync> = vm_states_concrete.clone();
        let rollback = Arc::new(RollbackAdmin {
            signing_key: Arc::new(SigningKey::from_bytes(&ROLLBACK_TEST_KBS_SEED)),
            vm_states: vm_states_concrete,
            policy: RollbackPolicy::default(),
        });
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
                custody: None,
                keepalive_bindings: Arc::new(
                    kbs_core::keepalive_binding::InMemoryKeepaliveBindings::default(),
                ),
                rollback: Some(rollback),
                release_audit: None,
                cdn_fleet: None,
            },
            sk,
            kid,
        )
    }

    /// The KBS response seed the rollback tests' `RollbackAdmin` signs
    /// checkpoints with.
    const ROLLBACK_TEST_KBS_SEED: [u8; 32] = [11u8; 32];

    /// A minimal posture for tests that never read it. The REAL
    /// derivation from a `Config` lives in `hippius_kbs_server::wiring::
    /// config_posture` and is tested there (kbs-transport has no
    /// `Config` — that is the point of precomputing it upstream).
    fn test_posture() -> AdminConfigPostureResponse {
        AdminConfigPostureResponse {
            v: 1,
            require_wrapped_kek: false,
            require_wrapped_userdata: false,
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
                hippius_types::guardian::KeyMode::Hippius,
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

    #[tokio::test]
    async fn a_second_migration_activates_200_and_fences_the_first_dest() {
        // Bug 4b regression through the real route: after one §25 the row
        // stays `Migrating`, and the next activate used to be a 409.
        let td = TempDir::new().unwrap();
        let (state, _sk, _kid) = build_state(&td);
        seed_active_via_register(&state, "vm-2x", 1, "src", "lease-1");
        let router = build_admin_router(state);

        let first = router
            .clone()
            .oneshot(activate_request("vm-2x", "dst-a", 2, None))
            .await
            .unwrap();
        assert_eq!(first.status(), StatusCode::OK);

        let second = router
            .oneshot(activate_request("vm-2x", "dst-b", 3, None))
            .await
            .unwrap();
        assert_eq!(second.status(), StatusCode::OK);
        let body_bytes = resp_to_bytes(second.into_body(), 4096).await.unwrap();
        let parsed: AdminActivateResponse = serde_json::from_slice(&body_bytes).unwrap();
        assert_eq!((parsed.old_gen, parsed.new_gen), (2, 3));
        assert_eq!(parsed.dest, "dst-b");
        assert!(!parsed.cached);

        use kbs_core::lifecycle::VmStateStore;
        let persisted = FileVmStateStore::open(td.path().join("vm-states.json")).unwrap();
        let cur = persisted.get("vm-2x").unwrap();
        kbs_core::lifecycle::check_releasable(&cur, 3, "lease-1", "dst-b").unwrap();
        assert!(kbs_core::lifecycle::check_releasable(&cur, 2, "lease-1", "dst-a").is_err());
        assert!(kbs_core::lifecycle::check_releasable(&cur, 1, "lease-1", "src").is_err());
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

    fn custody_runtime() -> Arc<kbs_core::custody::CustodyRuntime> {
        Arc::new(
            kbs_core::custody::CustodyRuntime::new(
                Arc::new(kbs_core::custody::MapCustodyStore::in_memory()),
                kbs_core::custody::CustodyPolicy::default(),
                kbs_core::custody::SkewConfig::default(),
            )
            .unwrap(),
        )
    }

    async fn get_json<T: serde::de::DeserializeOwned>(router: Router, uri: &str) -> T {
        let resp = router
            .oneshot(
                axum::http::Request::builder()
                    .method("GET")
                    .uri(uri)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        serde_json::from_slice(&resp_to_bytes(resp.into_body(), 65536).await.unwrap()).unwrap()
    }

    fn policy_request(body: &serde_json::Value) -> Request {
        axum::http::Request::builder()
            .method("POST")
            .uri("/v1/admin/custody/policy")
            .header("content-type", "application/json")
            .extension(vali_peer())
            .body(Body::from(serde_json::to_vec(body).unwrap()))
            .unwrap()
    }

    #[tokio::test]
    async fn custody_report_says_disabled_when_custody_is_off() {
        let td = TempDir::new().unwrap();
        let (state, _sk, _kid) = build_state(&td);
        let r: AdminCustodyReport = get_json(build_admin_router(state), "/v1/admin/custody").await;
        assert!(!r.enabled);
        assert!(r.vms.is_empty() && r.policy.is_none());
    }

    #[tokio::test]
    async fn custody_report_lists_bound_guests_with_their_phase_and_age() {
        let td = TempDir::new().unwrap();
        let (mut state, _sk, _kid) = build_state(&td);
        let rt = custody_runtime();
        rt.store
            .bind(
                kbs_core::custody::CustodyRecord {
                    vm_id: "vm-c".into(),
                    generation: 3,
                    boot_counter: 9,
                    node: "n1".into(),
                    lease_id: "l".into(),
                    lease_pub: [1; 32],
                    last_seq: 4,
                    scope: kbs_core::custody::CustodyScope {
                        luks_path: "p".into(),
                        luks_version: 1,
                        userdata_path: "u".into(),
                        userdata_version: 1,
                    },
                    clock_mode: 0,
                    bound_at: 100,
                    bind_mono_ms: 0,
                    bind_tsc: 0,
                    last_request_at: 200,
                    last_mono_ms: 0,
                    last_grant_at: Some(150),
                    last_verdict: Some(0),
                    phase: 1,
                    since_last_grant_s: 50,
                    suspended_s: 7,
                    lag_s: 3,
                    skew_suspected: true,
                    rebinds: vec![],
                    measurement: String::new(),
                },
                &|_| {},
            )
            .unwrap();
        state.custody = Some(rt);
        let r: AdminCustodyReport = get_json(build_admin_router(state), "/v1/admin/custody").await;
        assert!(r.enabled);
        assert_eq!(r.policy.unwrap().ttl_s, 86_400);
        let row = &r.vms[0];
        assert_eq!(row.vm_id, "vm-c");
        assert_eq!(row.phase, "suspended");
        assert_eq!(row.last_verdict, "granted");
        assert_eq!(row.age_s, r.now - 150);
        assert!(row.skew_suspected && !row.clock_trusted);
        assert_eq!(row.clock_mode, "untrusted");
        assert_eq!(row.since_last_grant_s, 50);
    }

    #[tokio::test]
    async fn custody_policy_applies_in_bounds_refuses_out_of_bounds_and_is_audited() {
        let td = TempDir::new().unwrap();
        let (mut state, _sk, _kid) = build_state(&td);
        let rt = custody_runtime();
        state.custody = Some(Arc::clone(&rt));
        let router = build_admin_router(state);

        let ok = serde_json::json!({"v": 1, "ttl_s": 172_800, "stage2_s": 172_800, "renew_s": 600});
        let resp = router.clone().oneshot(policy_request(&ok)).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(rt.policy().ttl_s, 172_800);

        // A week and a second: out of bounds, nothing changes.
        let bad = serde_json::json!({"v": 1, "ttl_s": 604_801, "stage2_s": 1, "renew_s": 600});
        let resp = router.clone().oneshot(policy_request(&bad)).await.unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        assert_eq!(rt.policy().ttl_s, 172_800);

        let rows = read_audit_rows(&td);
        let rows: Vec<_> = rows.iter().filter(|r| r.op == "custody-policy").collect();
        assert_eq!(rows.len(), 2);
        assert!(rows[0].applied && !rows[1].applied);
    }

    #[tokio::test]
    async fn custody_policy_is_refused_when_custody_is_off() {
        let td = TempDir::new().unwrap();
        let (state, _sk, _kid) = build_state(&td);
        let ok = serde_json::json!({"v": 1, "ttl_s": 86_400, "stage2_s": 172_800, "renew_s": 600});
        let resp = build_admin_router(state)
            .oneshot(policy_request(&ok))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::CONFLICT);
    }

    fn fence_request(vm_id: &str, route: &str, body: &serde_json::Value) -> Request {
        axum::http::Request::builder()
            .method("POST")
            .uri(format!("/v1/admin/vm/{vm_id}/{route}"))
            .header("content-type", "application/json")
            .extension(vali_peer())
            .body(Body::from(serde_json::to_vec(body).unwrap()))
            .unwrap()
    }

    async fn fence_ok(resp: Response) -> AdminFenceResponse {
        assert_eq!(resp.status(), StatusCode::OK);
        let bytes = resp_to_bytes(resp.into_body(), 4096).await.unwrap();
        serde_json::from_slice(&bytes).unwrap()
    }

    #[tokio::test]
    async fn decommission_route_fences_an_active_vm_and_audits_it() {
        let td = TempDir::new().unwrap();
        let (state, _sk, _kid) = build_state(&td);
        seed_active_via_register(&state, "vm-d", 5, "n1", "lease-1");
        let router = build_admin_router(state);

        let body = serde_json::json!({ "v": 1 });
        let resp = router
            .clone()
            .oneshot(fence_request("vm-d", "decommission", &body))
            .await
            .unwrap();
        let parsed = fence_ok(resp).await;
        assert_eq!(
            parsed,
            AdminFenceResponse {
                v: 1,
                vm_id: "vm-d".into(),
                previous: "active".into(),
                state: "decommissioning".into(),
                cached: false,
            }
        );
        use kbs_core::lifecycle::VmStateStore;
        let persisted = FileVmStateStore::open(td.path().join("vm-states.json")).unwrap();
        let cur = persisted.get("vm-d").unwrap();
        assert!(kbs_core::lifecycle::check_releasable(&cur, 5, "lease-1", "n1").is_err());

        // A re-drive is a cached 200.
        let resp = router
            .oneshot(fence_request("vm-d", "decommission", &body))
            .await
            .unwrap();
        assert!(fence_ok(resp).await.cached);

        let rows = read_audit_rows(&td);
        let fences: Vec<_> = rows.iter().filter(|r| r.op == "decommission").collect();
        assert_eq!(fences.len(), 2);
        assert!(fences[0].applied && !fences[1].applied);
        assert_eq!(fences[0].peer_san, "spiffe://hippius.network/vali");
    }

    #[tokio::test]
    async fn tombstone_route_installs_on_an_absent_row_and_409s_a_generation_conflict() {
        let td = TempDir::new().unwrap();
        let (state, _sk, _kid) = build_state(&td);
        let router = build_admin_router(state);

        let resp = router
            .clone()
            .oneshot(fence_request(
                "vm-t",
                "tombstone",
                &serde_json::json!({ "v": 1, "gen": 4 }),
            ))
            .await
            .unwrap();
        let parsed = fence_ok(resp).await;
        assert_eq!(
            (parsed.previous.as_str(), parsed.state.as_str()),
            ("absent", "destroyed")
        );

        let resp = router
            .oneshot(fence_request(
                "vm-t",
                "tombstone",
                &serde_json::json!({ "v": 1, "gen": 5 }),
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::CONFLICT);
        let bytes = resp_to_bytes(resp.into_body(), 4096).await.unwrap();
        let err: AdminErrorResponse = ciborium::de::from_reader(bytes.as_ref()).unwrap();
        assert_eq!(err.reason, "tombstone-generation-conflict");
        use kbs_core::lifecycle::VmStateStore;
        let persisted = FileVmStateStore::open(td.path().join("vm-states.json")).unwrap();
        assert_eq!(
            persisted.get("vm-t").unwrap(),
            kbs_core::lifecycle::VmState::Destroyed { gen: 4 }
        );
    }

    #[tokio::test]
    async fn fence_routes_refuse_a_malformed_or_unknown_version_body_and_write_nothing() {
        let td = TempDir::new().unwrap();
        let (state, _sk, _kid) = build_state(&td);
        seed_active_via_register(&state, "vm-b", 1, "n", "l");
        let router = build_admin_router(state);
        for (route, body) in [
            ("decommission", serde_json::json!({ "v": 2 })),
            ("decommission", serde_json::json!({ "v": 1, "extra": true })),
            ("tombstone", serde_json::json!({ "v": 1 })),
            ("tombstone", serde_json::json!({ "v": 2, "gen": 1 })),
        ] {
            let resp = router
                .clone()
                .oneshot(fence_request("vm-b", route, &body))
                .await
                .unwrap();
            assert_eq!(resp.status(), StatusCode::BAD_REQUEST, "{route} {body}");
        }
        use kbs_core::lifecycle::VmStateStore;
        let persisted = FileVmStateStore::open(td.path().join("vm-states.json")).unwrap();
        assert!(matches!(
            persisted.get("vm-b").unwrap(),
            kbs_core::lifecycle::VmState::Active { .. }
        ));
        let rows = read_audit_rows(&td);
        assert_eq!(rows.iter().filter(|r| r.op == "tombstone").count(), 2);
        assert_eq!(rows.iter().filter(|r| r.op == "decommission").count(), 2);
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
        PeerCertInfo::new(
            vec![crate::SpiffeId::parse("spiffe://hippius.network/vali").unwrap()],
            "0a1b2c3d".into(),
        )
        .unwrap()
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

    // ── seed-keepalive-binding tests ────────────────────────────────

    /// Genoa-style 64-byte platform id the lifecycle row registers.
    const HOST_CHIP: &str = "11";
    /// Turin-style 8-byte platform id.
    const TURIN_PLATFORM: &str = "abcdef0123456789";

    /// State with a binding store we keep a handle on, and a lifecycle
    /// store holding `rows` (vm_id → state).
    fn build_state_with_bindings(
        td: &TempDir,
        rows: &[(&str, kbs_core::lifecycle::VmState)],
    ) -> (
        AdminState,
        Arc<kbs_core::keepalive_binding::InMemoryKeepaliveBindings>,
    ) {
        let (mut state, _sk, _kid) = build_state(td);
        let vm_states = FileVmStateStore::open(td.path().join("binding-vm-states.json")).unwrap();
        for (vm_id, row) in rows {
            vm_states
                .register(
                    vm_id,
                    row.clone(),
                    hippius_types::guardian::KeyMode::Hippius,
                )
                .unwrap();
        }
        state.vm_states = Arc::new(vm_states);
        let store = Arc::new(kbs_core::keepalive_binding::InMemoryKeepaliveBindings::default());
        state.keepalive_bindings =
            Arc::clone(&store) as Arc<dyn kbs_core::keepalive_binding::KeepaliveBindingStore>;
        (state, store)
    }

    fn active_on(host: &str) -> kbs_core::lifecycle::VmState {
        kbs_core::lifecycle::VmState::Active {
            gen: 1,
            host: host.to_string(),
            lease_id: "lease-1".into(),
        }
    }

    fn seed_binding_request(vm_id: &str, chip: &str, report: &str) -> axum::http::Request<Body> {
        axum::http::Request::builder()
            .method("POST")
            .uri(format!("/v1/admin/vm/{vm_id}/seed-keepalive-binding"))
            .header("content-type", "application/json")
            .body(Body::from(
                serde_json::to_vec(
                    &serde_json::json!({ "chip_id_hex": chip, "report_id_hex": report }),
                )
                .unwrap(),
            ))
            .unwrap()
    }

    async fn error_reason(resp: Response) -> String {
        let bytes = resp_to_bytes(resp.into_body(), 4096).await.unwrap();
        let parsed: AdminErrorResponse = ciborium::de::from_reader(bytes.as_ref()).unwrap();
        parsed.reason
    }

    async fn seed_ok(resp: Response) -> AdminSeedKeepaliveBindingResponse {
        assert_eq!(resp.status(), StatusCode::OK);
        let body = resp_to_bytes(resp.into_body(), 4096).await.unwrap();
        serde_json::from_slice(&body).unwrap()
    }

    #[tokio::test]
    async fn seed_keepalive_binding_200_seeded_200_matched_409_different() {
        use kbs_core::keepalive_binding::KeepaliveBindingStore;
        let td = TempDir::new().unwrap();
        let host = HOST_CHIP.repeat(64);
        let (state, store) = build_state_with_bindings(&td, &[("vm-kb", active_on(&host))]);
        let router = build_admin_router(state);
        let report = "22".repeat(32);

        let first = seed_ok(
            router
                .clone()
                .oneshot(seed_binding_request("vm-kb", &host, &report))
                .await
                .unwrap(),
        )
        .await;
        assert_eq!(
            (first.v, first.vm_id.as_str(), first.seeded, first.matched),
            (1, "vm-kb", true, false)
        );
        let rec = store.get("vm-kb").unwrap().unwrap();
        assert_eq!(rec.guest.report_id, [0x22; 32]);
        assert_eq!(rec.order, kbs_core::keepalive_binding::SEED_ORDER);

        // The SAME guest again: 200, a matched no-op.
        let again = seed_ok(
            router
                .clone()
                .oneshot(seed_binding_request("vm-kb", &host, &report))
                .await
                .unwrap(),
        )
        .await;
        assert_eq!((again.seeded, again.matched), (false, true));

        // A DIFFERENT guest: 409, nothing written.
        let resp = router
            .clone()
            .oneshot(seed_binding_request("vm-kb", &host, &"33".repeat(32)))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::CONFLICT);
        assert_eq!(error_reason(resp).await, "binding-already-recorded");
        assert_eq!(
            store.get("vm-kb").unwrap().unwrap().guest.report_id,
            [0x22; 32]
        );

        let rows = read_audit_rows(&td);
        let ops: Vec<_> = rows
            .iter()
            .filter(|r| r.op == "seed-keepalive-binding")
            .map(|r| (r.applied, r.status_code))
            .collect();
        assert_eq!(ops, vec![(true, 200), (false, 200), (false, 409)]);
    }

    #[tokio::test]
    async fn seed_keepalive_binding_on_a_poisoned_vm_is_409_and_it_stays_poisoned() {
        use kbs_core::keepalive_binding::KeepaliveBindingStore;
        let td = TempDir::new().unwrap();
        let host = HOST_CHIP.repeat(64);
        let (state, store) = build_state_with_bindings(&td, &[("vm-pz", active_on(&host))]);
        store.poison("vm-pz", (1, 2)).unwrap();
        let router = build_admin_router(state);
        let resp = router
            .clone()
            .oneshot(seed_binding_request("vm-pz", &host, &"22".repeat(32)))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::CONFLICT);
        assert_eq!(error_reason(resp).await, "binding-poisoned");
        assert!(store.is_poisoned("vm-pz").unwrap());
        assert!(store.get("vm-pz").unwrap().is_none());
        let rows = read_audit_rows(&td);
        assert!(rows
            .iter()
            .any(|r| r.op == "seed-keepalive-binding" && !r.applied && r.status_code == 409));
    }

    #[tokio::test]
    async fn seed_keepalive_binding_412_when_the_vm_is_not_releasable() {
        use kbs_core::keepalive_binding::KeepaliveBindingStore;
        let td = TempDir::new().unwrap();
        let host = HOST_CHIP.repeat(64);
        let (state, store) = build_state_with_bindings(
            &td,
            &[
                (
                    "vm-dead",
                    kbs_core::lifecycle::VmState::Destroyed { gen: 3 },
                ),
                ("vm-going", kbs_core::lifecycle::VmState::Decommissioning),
            ],
        );
        let router = build_admin_router(state);
        for vm in ["vm-absent", "vm-dead", "vm-going"] {
            let resp = router
                .clone()
                .oneshot(seed_binding_request(vm, &host, &"22".repeat(32)))
                .await
                .unwrap();
            assert_eq!(resp.status(), StatusCode::PRECONDITION_FAILED, "{vm}");
            assert_eq!(error_reason(resp).await, "binding-vm-not-active", "{vm}");
            assert!(store.get(vm).unwrap().is_none());
        }
    }

    #[tokio::test]
    async fn seed_keepalive_binding_412_when_the_chip_is_not_the_host() {
        use kbs_core::keepalive_binding::KeepaliveBindingStore;
        let td = TempDir::new().unwrap();
        let (state, store) = build_state_with_bindings(
            &td,
            &[
                ("vm-genoa", active_on(&HOST_CHIP.repeat(64))),
                ("vm-turin", active_on(TURIN_PLATFORM)),
                ("vm-noplat", active_on("")),
                (
                    "vm-moved",
                    kbs_core::lifecycle::VmState::Migrating {
                        old_gen: 1,
                        new_gen: 2,
                        source: HOST_CHIP.repeat(64),
                        dest: "44".repeat(64),
                        lease_id: "lease-1".into(),
                    },
                ),
            ],
        );
        let router = build_admin_router(state);
        let report = "22".repeat(32);
        let turin_chip = format!("{TURIN_PLATFORM}{}", "00".repeat(56));
        for (vm, chip, want_ok) in [
            ("vm-genoa", "55".repeat(64), false),
            ("vm-genoa", HOST_CHIP.repeat(64), true),
            // Turin: the chip is compared truncated to the 8-byte platform id.
            ("vm-turin", turin_chip.clone(), true),
            (
                "vm-turin",
                format!("{}{}", "ab".repeat(8), "00".repeat(56)),
                false,
            ),
            // An empty platform id matches nothing.
            ("vm-noplat", HOST_CHIP.repeat(64), false),
            // A migrated VM releases on its destination, not its source.
            ("vm-moved", HOST_CHIP.repeat(64), false),
            ("vm-moved", "44".repeat(64), true),
        ] {
            let resp = router
                .clone()
                .oneshot(seed_binding_request(vm, &chip, &report))
                .await
                .unwrap();
            if want_ok {
                assert_eq!(resp.status(), StatusCode::OK, "{vm} {chip}");
            } else {
                assert_eq!(
                    resp.status(),
                    StatusCode::PRECONDITION_FAILED,
                    "{vm} {chip}"
                );
                assert_eq!(error_reason(resp).await, "binding-chip-not-host");
            }
        }
        assert!(store.get("vm-noplat").unwrap().is_none());
    }

    #[tokio::test]
    async fn seed_keepalive_binding_malformed_is_400_and_writes_nothing() {
        use kbs_core::keepalive_binding::KeepaliveBindingStore;
        let td = TempDir::new().unwrap();
        let host = HOST_CHIP.repeat(64);
        let (state, store) = build_state_with_bindings(&td, &[("vm-bad", active_on(&host))]);
        let router = build_admin_router(state);
        let good_report = "22".repeat(32);
        for (vm, chip, report, reason) in [
            (
                "vm-bad",
                "11".repeat(8),
                good_report.clone(),
                "chip-id-malformed",
            ),
            (
                "vm-bad",
                "AB".repeat(64),
                good_report.clone(),
                "chip-id-malformed",
            ),
            (
                "vm-bad",
                host.clone(),
                "22".repeat(31),
                "report-id-malformed",
            ),
            (
                "vm-bad",
                host.clone(),
                "zz".repeat(32),
                "report-id-malformed",
            ),
            (
                "vm-bad",
                "00".repeat(64),
                good_report.clone(),
                "chip-id-zero",
            ),
            ("vm-bad", host.clone(), "00".repeat(32), "report-id-zero"),
            ("VM_Bad", host.clone(), good_report.clone(), "vm-id-invalid"),
            (
                &"a".repeat(65),
                host.clone(),
                good_report.clone(),
                "vm-id-invalid",
            ),
        ] {
            let resp = router
                .clone()
                .oneshot(seed_binding_request(vm, &chip, &report))
                .await
                .unwrap();
            assert_eq!(resp.status(), StatusCode::BAD_REQUEST, "{reason}");
            assert_eq!(error_reason(resp).await, reason);
        }
        let resp = router
            .clone()
            .oneshot(
                axum::http::Request::builder()
                    .method("POST")
                    .uri("/v1/admin/vm/vm-bad/seed-keepalive-binding")
                    .header("content-type", "application/json")
                    .body(Body::from("{\"counter\": 3}"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        assert_eq!(error_reason(resp).await, "seed-body-decode");
        assert!(store.get("vm-bad").unwrap().is_none());
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
        req.extensions_mut().insert(
            PeerCertInfo::new(
                vec![crate::SpiffeId::parse("spiffe://hippius.network/operator").unwrap()],
                "0a0b".into(),
            )
            .unwrap(),
        );
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
            custody: None,
            keepalive_bindings: Arc::new(
                kbs_core::keepalive_binding::InMemoryKeepaliveBindings::default(),
            ),
            rollback: None,
            release_audit: None,
            cdn_fleet: None,
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
        req.extensions_mut().insert(
            PeerCertInfo::new(
                vec![crate::SpiffeId::parse("spiffe://hippius.network/operator").unwrap()],
                "01".into(),
            )
            .unwrap(),
        );
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
        req.extensions_mut().insert(
            PeerCertInfo::new(
                vec![crate::SpiffeId::parse("spiffe://hippius.network/operator").unwrap()],
                "01".into(),
            )
            .unwrap(),
        );
        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::METHOD_NOT_ALLOWED);
    }

    // ── authorized rollback (A2) routes ──────────────────────────────

    mod rollback_routes {
        use super::*;
        use hippius_types::rollback::{
            AdminRollbackCheckpointResponse, AdminRollbackErrorResponse,
            AdminRollbackStatusResponse, RollbackCheckpoint,
        };

        const SRC: &str = "aa11";
        const DEST: &str = "bb22";

        fn json_req(method: &str, uri: String, body: Option<serde_json::Value>) -> Request {
            axum::http::Request::builder()
                .method(method)
                .uri(uri)
                .header("content-type", "application/json")
                .extension(vali_peer())
                .body(match body {
                    Some(b) => Body::from(serde_json::to_vec(&b).unwrap()),
                    None => Body::empty(),
                })
                .unwrap()
        }

        async fn json_body<T: serde::de::DeserializeOwned>(resp: Response) -> T {
            let bytes = resp_to_bytes(resp.into_body(), 64 * 1024).await.unwrap();
            serde_json::from_slice(&bytes).unwrap()
        }

        async fn checkpoint(router: &Router, vm: &str) -> AdminRollbackCheckpointResponse {
            let resp = router
                .clone()
                .oneshot(json_req(
                    "POST",
                    format!("/v1/admin/vm/{vm}/rollback-checkpoint"),
                    Some(serde_json::json!({})),
                ))
                .await
                .unwrap();
            assert_eq!(resp.status(), StatusCode::OK);
            json_body(resp).await
        }

        /// vali's `manifest.json` for the point `cp` was taken at.
        fn manifest_of(cp: &AdminRollbackCheckpointResponse) -> Vec<u8> {
            serde_json::to_vec_pretty(&serde_json::json!({
                "vm_id": cp.checkpoint.vm_id,
                "boot_counter": cp.checkpoint.boot_counter,
                "kbs_rollback_checkpoint": cp,
            }))
            .unwrap()
        }

        fn authorize_body(
            cp: &AdminRollbackCheckpointResponse,
            restore_id: &str,
            new_gen: u64,
            ttl_s: u64,
        ) -> serde_json::Value {
            use base64::Engine as _;
            let manifest = manifest_of(cp);
            serde_json::json!({
                "checkpoint_cbor_hex": cp.checkpoint_cbor_hex,
                "signature_hex": cp.signature_hex,
                "point_manifest_sha256_hex": hex::encode(Sha256::digest(&manifest)),
                "point_manifest_b64": base64::engine::general_purpose::STANDARD.encode(&manifest),
                "new_gen": new_gen,
                "dest_platform_id_hex": DEST,
                "restore_id": restore_id,
                "ttl_s": ttl_s,
                "requested_by": "tenant:42",
            })
        }

        async fn authorize(router: &Router, vm: &str, body: serde_json::Value) -> Response {
            router
                .clone()
                .oneshot(json_req(
                    "POST",
                    format!("/v1/admin/vm/{vm}/authorize-rollback"),
                    Some(body),
                ))
                .await
                .unwrap()
        }

        async fn status(router: &Router, vm: &str) -> AdminRollbackStatusResponse {
            let resp = router
                .clone()
                .oneshot(json_req("GET", format!("/v1/admin/vm/{vm}/rollback"), None))
                .await
                .unwrap();
            assert_eq!(resp.status(), StatusCode::OK);
            json_body(resp).await
        }

        /// TEST-ONLY: record that `vm`'s guest speaks the timeline-bound
        /// stamp protocol (v2). No guest reports it yet, so without this
        /// nothing can be armed; the fixtures that expect an arm to land
        /// go through here, and the negative tests leave it out.
        fn mark_rollback_capable_for_test(state: &AdminState, vm: &str) {
            state
                .volume_stamp
                .record_guest_stamp_protocol(
                    vm,
                    kbs_core::volume_stamp::GUEST_STAMP_PROTOCOL_ROLLBACK_MIN,
                )
                .unwrap();
        }

        async fn reason_of(resp: Response) -> (StatusCode, AdminRollbackErrorResponse) {
            let st = resp.status();
            (st, json_body(resp).await)
        }

        fn audit_ops(td: &TempDir) -> Vec<String> {
            std::fs::read_to_string(td.path().join("audit/admin.log"))
                .unwrap_or_default()
                .lines()
                .map(|l| {
                    let b = hex::decode(l.split(':').nth(1).unwrap()).unwrap();
                    format!(
                        "{:?}",
                        ciborium::de::from_reader::<ciborium::value::Value, _>(b.as_slice())
                            .unwrap()
                    )
                })
                .collect()
        }

        /// A VM at gen 1 on SRC whose checkpoint was taken at counter 2,
        /// then booted twice more (stored = 4), then activated to gen 2 on
        /// DEST — the exact state vali leaves before `authorize-rollback`.
        async fn prepared(td: &TempDir, vm: &str) -> (Router, AdminRollbackCheckpointResponse) {
            let (state, counter) = build_state_with_counter(td);
            seed_active_via_register(&state, vm, 1, SRC, "lease-1");
            counter.check_and_advance(vm, 1).unwrap();
            counter.check_and_advance(vm, 2).unwrap();
            // A confirmed stamp: an unstamped checkpoint is never armed.
            state.volume_stamp.confirm(vm, 1).unwrap();
            mark_rollback_capable_for_test(&state, vm);
            let router = build_admin_router(state);
            let cp = checkpoint(&router, vm).await;
            counter.check_and_advance(vm, 3).unwrap();
            counter.check_and_advance(vm, 4).unwrap();
            let resp = router
                .clone()
                .oneshot(activate_request(vm, DEST, 2, Some(vali_peer())))
                .await
                .unwrap();
            assert_eq!(resp.status(), StatusCode::OK);
            (router, cp)
        }

        #[tokio::test]
        async fn the_checkpoint_is_signed_by_the_kbs_key_and_carries_the_live_state() {
            let td = TempDir::new().unwrap();
            let (state, counter) = build_state_with_counter(&td);
            seed_active_via_register(&state, "vm-c", 3, SRC, "lease-1");
            counter.check_and_advance("vm-c", 1).unwrap();
            let router = build_admin_router(state);
            let cp = checkpoint(&router, "vm-c").await;
            let vk = SigningKey::from_bytes(&ROLLBACK_TEST_KBS_SEED).verifying_key();
            assert_eq!(cp.signer_pubkey_hex, hex::encode(vk.to_bytes()));
            let body = hex::decode(&cp.checkpoint_cbor_hex).unwrap();
            let sig = hex::decode(&cp.signature_hex).unwrap();
            let verified = kbs_core::rollback::verify_checkpoint(&vk, &body, &sig).unwrap();
            assert_eq!(verified, RollbackCheckpoint::decode(&body).unwrap());
            // V2: it names the VM's volume-stamp timeline (zero: never
            // rolled back), in the JSON and in the signed bytes.
            assert_eq!(cp.checkpoint.domain, "HIPPIUS_KBS_ROLLBACK_CHECKPOINT_V2");
            assert_eq!(
                cp.checkpoint.volume_stamp_timeline_id_hex.as_deref(),
                Some("00".repeat(32).as_str())
            );
            assert_eq!(verified.volume_stamp_timeline_id, Some([0u8; 32]));
            assert_eq!(
                (cp.checkpoint.boot_counter, cp.checkpoint.generation),
                (1, 3)
            );
            assert_eq!(verified.boot_counter, cp.checkpoint.boot_counter);

            let (st, e) = reason_of(
                router
                    .clone()
                    .oneshot(json_req(
                        "POST",
                        "/v1/admin/vm/vm-none/rollback-checkpoint".into(),
                        None,
                    ))
                    .await
                    .unwrap(),
            )
            .await;
            assert_eq!(
                (st, e.reason.as_str()),
                (StatusCode::NOT_FOUND, "no-vm-row")
            );
        }

        #[tokio::test]
        async fn a_vm_that_never_booted_has_no_checkpoint() {
            let td = TempDir::new().unwrap();
            let (state, _counter) = build_state_with_counter(&td);
            seed_active_via_register(&state, "vm-0", 1, SRC, "lease-1");
            let router = build_admin_router(state);
            let (st, e) = reason_of(
                router
                    .oneshot(json_req(
                        "POST",
                        "/v1/admin/vm/vm-0/rollback-checkpoint".into(),
                        None,
                    ))
                    .await
                    .unwrap(),
            )
            .await;
            assert_eq!(
                (st, e.reason.as_str()),
                (StatusCode::CONFLICT, "no-boot-counter")
            );
        }

        #[tokio::test]
        async fn arm_redrive_second_arm_status_disarm_and_rate_limit_over_http() {
            let td = TempDir::new().unwrap();
            let (router, cp) = prepared(&td, "vm-r").await;

            let resp = authorize(&router, "vm-r", authorize_body(&cp, "r-1", 2, 600)).await;
            assert_eq!(resp.status(), StatusCode::CREATED);
            let armed: serde_json::Value = json_body(resp).await;
            assert_eq!(armed["arm"]["from_counter"], 2);
            assert_eq!(armed["arm"]["dest_platform_id_hex"], DEST);
            assert_eq!(armed["arm"]["new_gen"], 2);

            // Same restore_id: idempotent 200.
            let resp = authorize(&router, "vm-r", authorize_body(&cp, "r-1", 2, 600)).await;
            assert_eq!(resp.status(), StatusCode::OK);
            // Another restore_id while armed: 409 arm-exists.
            let (st, e) =
                reason_of(authorize(&router, "vm-r", authorize_body(&cp, "r-2", 2, 600)).await)
                    .await;
            assert_eq!(
                (st, e.reason.as_str()),
                (StatusCode::CONFLICT, "arm-exists")
            );

            let s = status(&router, "vm-r").await;
            assert_eq!(s.arm.unwrap().restore_id, "r-1");
            assert!(s.last_rollback.is_none());
            assert!(s.last_clear.is_none());

            // DELETE, twice (idempotent).
            for _ in 0..2 {
                let resp = router
                    .clone()
                    .oneshot(json_req(
                        "DELETE",
                        "/v1/admin/vm/vm-r/authorize-rollback/r-1".into(),
                        None,
                    ))
                    .await
                    .unwrap();
                assert_eq!(resp.status(), StatusCode::NO_CONTENT);
            }
            let s = status(&router, "vm-r").await;
            assert!(s.arm.is_none());
            let clear = s.last_clear.expect("the disarm is reported");
            assert_eq!(
                (clear.restore_id.as_str(), clear.reason.as_str()),
                ("r-1", "rollback-disarmed")
            );

            // Re-arming inside min_interval_s: 429 + retry_after_s.
            let resp = authorize(&router, "vm-r", authorize_body(&cp, "r-3", 2, 600)).await;
            assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
            let retry = resp
                .headers()
                .get(header::RETRY_AFTER)
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.parse::<u64>().ok())
                .unwrap();
            let (_, e) = reason_of(resp).await;
            assert_eq!(e.reason, "rollback-rate-limited");
            assert_eq!(e.retry_after_s, Some(retry));
            assert!(retry > 1700 && retry <= 1800);

            let ops = audit_ops(&td);
            let intent_at = ops
                .iter()
                .position(|r| r.contains("authorize-rollback-intent") && r.contains("r-1"))
                .expect("intent audited");
            let armed_at = ops
                .iter()
                .position(|r| r.contains("armed from_counter=2"))
                .expect("outcome audited");
            assert!(intent_at < armed_at, "the intent precedes the arm");
            let armed_row = ops
                .iter()
                .find(|r| {
                    r.contains("\"authorize-rollback\"") && r.contains("armed from_counter=2")
                })
                .expect("arm audited");
            assert!(
                armed_row.contains("spiffe://hippius.network/vali"),
                "{armed_row}"
            );
            assert!(armed_row.contains("0a1b2c3d"), "peer serial: {armed_row}");
            assert!(ops.iter().any(|r| r.contains("arm-exists")));
            assert!(ops
                .iter()
                .any(|r| r.contains("rollback-disarm") && r.contains("disarmed")));
            assert!(ops.iter().any(|r| r.contains("rollback-rate-limited")));
        }

        #[tokio::test]
        async fn authorize_refusals_over_http_write_no_arm() {
            let td = TempDir::new().unwrap();
            let (router, cp) = prepared(&td, "vm-x").await;

            // Forged: signed by another key.
            let forged_sk = SigningKey::from_bytes(&[99u8; 32]);
            let cp_decoded =
                RollbackCheckpoint::decode(&hex::decode(&cp.checkpoint_cbor_hex).unwrap()).unwrap();
            let (cbor, sig) = kbs_core::rollback::sign_checkpoint(&forged_sk, &cp_decoded).unwrap();
            let mut forged = authorize_body(&cp, "r-1", 2, 600);
            forged["checkpoint_cbor_hex"] = hex::encode(&cbor).into();
            forged["signature_hex"] = hex::encode(sig).into();
            // Tampered: our signature, a lowered counter in the bytes.
            let mut lowered = cp_decoded.clone();
            lowered.boot_counter = 1;
            let mut tampered = authorize_body(&cp, "r-1", 2, 600);
            tampered["checkpoint_cbor_hex"] = hex::encode(lowered.canonical().unwrap()).into();

            for (body, status, reason) in [
                (forged, StatusCode::BAD_REQUEST, "bad-checkpoint-signature"),
                (
                    tampered,
                    StatusCode::BAD_REQUEST,
                    "bad-checkpoint-signature",
                ),
                (
                    authorize_body(&cp, "r-1", 2, 30),
                    StatusCode::BAD_REQUEST,
                    "ttl-out-of-range",
                ),
                (
                    authorize_body(&cp, "r-1", 2, 3601),
                    StatusCode::BAD_REQUEST,
                    "ttl-out-of-range",
                ),
                (
                    authorize_body(&cp, "r-1", 3, 600),
                    StatusCode::CONFLICT,
                    "row-not-activated",
                ),
            ] {
                let (st, e) = reason_of(authorize(&router, "vm-x", body).await).await;
                assert_eq!((st, e.reason.as_str()), (status, reason));
            }
            // The checkpoint of vm-x presented for another VM.
            let (st, e) =
                reason_of(authorize(&router, "vm-y", authorize_body(&cp, "r-1", 2, 600)).await)
                    .await;
            assert_eq!(
                (st, e.reason.as_str()),
                (StatusCode::BAD_REQUEST, "checkpoint-vm-mismatch")
            );
            assert!(status(&router, "vm-x").await.arm.is_none());
        }

        #[tokio::test]
        async fn a_checkpoint_of_the_current_boot_is_not_a_rollback() {
            let td = TempDir::new().unwrap();
            let (state, counter) = build_state_with_counter(&td);
            seed_active_via_register(&state, "vm-n", 1, SRC, "lease-1");
            counter.check_and_advance("vm-n", 1).unwrap();
            state.volume_stamp.confirm("vm-n", 1).unwrap();
            mark_rollback_capable_for_test(&state, "vm-n");
            let router = build_admin_router(state);
            let cp = checkpoint(&router, "vm-n").await;
            router
                .clone()
                .oneshot(activate_request("vm-n", DEST, 2, None))
                .await
                .unwrap();
            let (st, e) =
                reason_of(authorize(&router, "vm-n", authorize_body(&cp, "r-1", 2, 600)).await)
                    .await;
            assert_eq!(
                (st, e.reason.as_str()),
                (StatusCode::CONFLICT, "not-a-rollback")
            );
        }

        #[tokio::test]
        async fn an_applied_activate_clears_the_arm_but_a_redriven_one_does_not() {
            let td = TempDir::new().unwrap();
            let (router, cp) = prepared(&td, "vm-l").await;
            assert_eq!(
                authorize(&router, "vm-l", authorize_body(&cp, "r-1", 2, 600))
                    .await
                    .status(),
                StatusCode::CREATED
            );
            // Cached re-drive of the SAME hop: the arm survives.
            router
                .clone()
                .oneshot(activate_request("vm-l", DEST, 2, Some(vali_peer())))
                .await
                .unwrap();
            assert!(status(&router, "vm-l").await.arm.is_some());
            // A new hop: cleared, audited.
            router
                .clone()
                .oneshot(activate_request("vm-l", DEST, 3, Some(vali_peer())))
                .await
                .unwrap();
            assert!(status(&router, "vm-l").await.arm.is_none());
            assert!(audit_ops(&td).iter().any(
                |r| r.contains("rollback-lifecycle-clear") && r.contains("lifecycle-activate")
            ));
        }

        #[tokio::test]
        async fn decommission_and_tombstone_clear_the_arm() {
            for (route, body) in [
                ("decommission", serde_json::json!({ "v": 1 })),
                ("tombstone", serde_json::json!({ "v": 1, "gen": 2 })),
            ] {
                let td = TempDir::new().unwrap();
                let (router, cp) = prepared(&td, "vm-f").await;
                assert_eq!(
                    authorize(&router, "vm-f", authorize_body(&cp, "r-1", 2, 600))
                        .await
                        .status(),
                    StatusCode::CREATED
                );
                let resp = router
                    .clone()
                    .oneshot(fence_request("vm-f", route, &body))
                    .await
                    .unwrap();
                assert_eq!(resp.status(), StatusCode::OK, "{route}");
                let s = status(&router, "vm-f").await;
                assert!(s.arm.is_none(), "{route}");
                assert_eq!(
                    s.last_clear.map(|c| c.reason),
                    Some(format!("rollback-lifecycle-{route}"))
                );
                assert!(audit_ops(&td)
                    .iter()
                    .any(|r| r.contains(&format!("lifecycle-{route}"))));
            }
        }

        #[tokio::test]
        async fn an_expired_arm_is_purged_and_audited_on_the_next_admin_call() {
            let td = TempDir::new().unwrap();
            let (state, counter) = build_state_with_counter(&td);
            counter.seed("vm-e", 5).unwrap();
            let arm = kbs_core::rollback::RollbackArm {
                vm_id: "vm-e".into(),
                restore_id: "r-old".into(),
                manifest_sha256_hex: "ab".repeat(32),
                new_gen: 2,
                dest: DEST.into(),
                from_counter: 2,
                to_stamp: 1,
                checkpoint_sha256_hex: "cd".repeat(32),
                armed_at_unix: 10,
                expires_at_unix: 20,
                requested_by: "tenant:1".into(),
                armed_by: String::new(),
            };
            counter.arm_rollback(arm, 1800, 10).unwrap();
            let router = build_admin_router(state);
            let s = status(&router, "vm-e").await;
            assert!(s.arm.is_none());
            assert_eq!(
                s.last_clear.map(|c| (c.restore_id, c.reason)),
                Some(("r-old".to_string(), "rollback-expired".to_string()))
            );
            assert!(
                counter.rollback_state("vm-e").unwrap().0.is_none(),
                "purged, not hidden"
            );
            assert!(audit_ops(&td)
                .iter()
                .any(|r| r.contains("rollback-expired") && r.contains("r-old")));
        }

        #[tokio::test]
        async fn every_rollback_route_demands_a_verified_client_cert() {
            // Even on a listener serving plaintext (no PeerCertInfo), the
            // rollback routes refuse — they are never merely network-gated.
            let td = TempDir::new().unwrap();
            let (router, cp) = prepared(&td, "vm-p").await;
            for (method, uri, body) in [
                ("POST", "/v1/admin/vm/vm-p/rollback-checkpoint", None),
                (
                    "POST",
                    "/v1/admin/vm/vm-p/authorize-rollback",
                    Some(authorize_body(&cp, "r-1", 2, 600)),
                ),
                ("DELETE", "/v1/admin/vm/vm-p/authorize-rollback/r-1", None),
                ("GET", "/v1/admin/vm/vm-p/rollback", None),
            ] {
                let req = axum::http::Request::builder()
                    .method(method)
                    .uri(uri)
                    .header("content-type", "application/json")
                    .body(match body {
                        Some(b) => Body::from(serde_json::to_vec(&b).unwrap()),
                        None => Body::empty(),
                    })
                    .unwrap();
                let (st, e) = reason_of(router.clone().oneshot(req).await.unwrap()).await;
                assert_eq!(
                    (st, e.reason.as_str()),
                    (StatusCode::FORBIDDEN, "admin-client-cert-required"),
                    "{method} {uri}"
                );
            }
            assert!(
                status(&router, "vm-p").await.arm.is_none(),
                "nothing was armed"
            );
            // Each refusal is in the chain, under its route's op.
            let refused: Vec<String> = audit_ops(&td)
                .into_iter()
                .filter(|r| r.contains("admin-client-cert-required"))
                .collect();
            for op in [
                "\"rollback-checkpoint\"",
                "\"authorize-rollback\"",
                "\"rollback-disarm\"",
                "\"rollback-status\"",
            ] {
                assert!(
                    refused.iter().any(|r| r.contains(op) && r.contains("403")),
                    "{op} refusal audited: {refused:?}"
                );
            }
        }

        #[tokio::test]
        async fn no_checkpoint_while_a_rollback_is_pending() {
            let td = TempDir::new().unwrap();
            let (mut state, counter) = build_state_with_counter(&td);
            let stamps = Arc::new(kbs_core::volume_stamp::InMemoryVolumeStampStore::default());
            state.volume_stamp = stamps.clone();
            seed_active_via_register(&state, "vm-q", 1, SRC, "lease-1");
            counter.seed("vm-q", 4).unwrap();
            // A live arm and its applied-but-undelivered stamp step.
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs();
            let arm = kbs_core::rollback::RollbackArm {
                vm_id: "vm-q".into(),
                restore_id: "r-1".into(),
                manifest_sha256_hex: "ab".repeat(32),
                new_gen: 2,
                dest: DEST.into(),
                from_counter: 2,
                to_stamp: 0,
                checkpoint_sha256_hex: "cd".repeat(32),
                armed_at_unix: now,
                expires_at_unix: now + 600,
                requested_by: "tenant:1".into(),
                armed_by: String::new(),
            };
            counter.arm_rollback(arm, 1800, now).unwrap();
            stamps
                .apply_rollback("vm-q", 0, 1, "r-1", &[0x11; 32])
                .unwrap();
            let router = build_admin_router(state);
            let (st, e) = reason_of(
                router
                    .oneshot(json_req(
                        "POST",
                        "/v1/admin/vm/vm-q/rollback-checkpoint".into(),
                        None,
                    ))
                    .await
                    .unwrap(),
            )
            .await;
            assert_eq!(
                (st, e.reason.as_str()),
                (StatusCode::CONFLICT, "rollback-pending")
            );
        }

        #[tokio::test]
        async fn an_arm_the_audit_log_cannot_record_is_taken_back() {
            let td = TempDir::new().unwrap();
            let (router, cp) = prepared(&td, "vm-a").await;
            // Make the admin chain unwritable: the next append fails.
            std::fs::remove_dir_all(td.path().join("audit")).unwrap();
            std::fs::write(td.path().join("audit"), b"not a directory").unwrap();
            let (st, e) =
                reason_of(authorize(&router, "vm-a", authorize_body(&cp, "r-1", 2, 600)).await)
                    .await;
            assert_eq!(
                (st, e.reason.as_str()),
                (StatusCode::INTERNAL_SERVER_ERROR, "audit-unavailable")
            );
            assert!(
                status(&router, "vm-a").await.arm.is_none(),
                "fail closed: no unaudited arm"
            );
        }

        #[tokio::test]
        async fn without_a_rollback_context_the_routes_are_503() {
            let td = TempDir::new().unwrap();
            let (mut state, _counter) = build_state_with_counter(&td);
            state.rollback = None;
            let router = build_admin_router(state);
            let (st, e) = reason_of(
                router
                    .oneshot(json_req("GET", "/v1/admin/vm/vm-1/rollback".into(), None))
                    .await
                    .unwrap(),
            )
            .await;
            assert_eq!(
                (st, e.reason.as_str()),
                (StatusCode::SERVICE_UNAVAILABLE, "rollback-unavailable")
            );
            assert!(audit_ops(&td)
                .iter()
                .any(|r| r.contains("rollback-unavailable")
                    && r.contains("spiffe://hippius.network/vali")));
        }

        /// The rollback-capability gate over HTTP. A VM whose guest never
        /// reported a timeline-bound stamp (no record — every VM today) or
        /// reported v1 is refused 409 `guest-not-rollback-capable`,
        /// audited, nothing stored, and `GET …/rollback` says
        /// `rollback_capable: false`. The same VM once recorded v2 arms.
        #[tokio::test]
        async fn an_arm_is_refused_unless_the_guest_is_rollback_capable() {
            for record in [None, Some(kbs_core::volume_stamp::GUEST_STAMP_PROTOCOL_V1)] {
                let td = TempDir::new().unwrap();
                let (state, counter) = build_state_with_counter(&td);
                let vm = "vm-g";
                seed_active_via_register(&state, vm, 1, SRC, "lease-1");
                counter.check_and_advance(vm, 1).unwrap();
                counter.check_and_advance(vm, 2).unwrap();
                state.volume_stamp.confirm(vm, 1).unwrap();
                if let Some(p) = record {
                    state
                        .volume_stamp
                        .record_guest_stamp_protocol(vm, p)
                        .unwrap();
                }
                let stamps = Arc::clone(&state.volume_stamp);
                let router = build_admin_router(state);
                let cp = checkpoint(&router, vm).await;
                counter.check_and_advance(vm, 3).unwrap();
                router
                    .clone()
                    .oneshot(activate_request(vm, DEST, 2, Some(vali_peer())))
                    .await
                    .unwrap();
                assert!(!status(&router, vm).await.rollback_capable);
                let (st, e) =
                    reason_of(authorize(&router, vm, authorize_body(&cp, "r-1", 2, 600)).await)
                        .await;
                assert_eq!(
                    (st, e.reason.as_str()),
                    (StatusCode::CONFLICT, "guest-not-rollback-capable"),
                    "record={record:?}"
                );
                assert_eq!(e.vm_id.as_deref(), Some(vm));
                assert_eq!(e.retry_after_s, None);
                assert!(status(&router, vm).await.arm.is_none());
                assert!(audit_ops(&td)
                    .iter()
                    .any(|r| r.contains("authorize-rollback\"")
                        && r.contains("guest-not-rollback-capable")
                        && r.contains("spiffe://hippius.network/vali")));

                // The same VM, now recorded v2, arms.
                stamps
                    .record_guest_stamp_protocol(
                        vm,
                        kbs_core::volume_stamp::GUEST_STAMP_PROTOCOL_ROLLBACK_MIN,
                    )
                    .unwrap();
                let st = status(&router, vm).await;
                assert!(st.rollback_capable);
                let resp = authorize(&router, vm, authorize_body(&cp, "r-1", 2, 600)).await;
                assert_eq!(resp.status(), StatusCode::CREATED, "record={record:?}");
            }
        }

        /// B2 over HTTP: an unstamped checkpoint is still issued (vali
        /// decides), but never armed — 409, audited, nothing stored.
        #[tokio::test]
        async fn an_unstamped_checkpoint_is_issued_but_refused_at_arm_time() {
            let td = TempDir::new().unwrap();
            let (state, counter) = build_state_with_counter(&td);
            seed_active_via_register(&state, "vm-u", 1, SRC, "lease-1");
            counter.check_and_advance("vm-u", 1).unwrap();
            counter.check_and_advance("vm-u", 2).unwrap();
            mark_rollback_capable_for_test(&state, "vm-u");
            let router = build_admin_router(state);
            let cp = checkpoint(&router, "vm-u").await;
            assert_eq!(cp.checkpoint.volume_stamp, 0);
            counter.check_and_advance("vm-u", 3).unwrap();
            router
                .clone()
                .oneshot(activate_request("vm-u", DEST, 2, Some(vali_peer())))
                .await
                .unwrap();
            let (st, e) =
                reason_of(authorize(&router, "vm-u", authorize_body(&cp, "r-1", 2, 600)).await)
                    .await;
            assert_eq!(
                (st, e.reason.as_str()),
                (StatusCode::CONFLICT, "checkpoint-unstamped")
            );
            assert!(status(&router, "vm-u").await.arm.is_none());
            let ops = audit_ops(&td);
            assert!(ops.iter().any(
                |r| r.contains("rollback-checkpoint") && r.contains("unstamped (not armable)")
            ));
            assert!(ops.iter().any(
                |r| r.contains("\"authorize-rollback\"") && r.contains("checkpoint-unstamped")
            ));
        }

        #[tokio::test]
        async fn a_manifest_that_does_not_carry_the_checkpoint_is_refused_over_http() {
            use base64::Engine as _;
            let td = TempDir::new().unwrap();
            let (router, cp) = prepared(&td, "vm-m").await;
            // Self-consistent sha, but the manifest names no checkpoint.
            let bogus = br#"{"vm_id":"vm-m"}"#;
            let mut body = authorize_body(&cp, "r-1", 2, 600);
            body["point_manifest_b64"] = base64::engine::general_purpose::STANDARD
                .encode(bogus)
                .into();
            body["point_manifest_sha256_hex"] = hex::encode(Sha256::digest(bogus)).into();
            let (st, e) = reason_of(authorize(&router, "vm-m", body).await).await;
            assert_eq!(
                (st, e.reason.as_str()),
                (StatusCode::BAD_REQUEST, "manifest-mismatch")
            );
            // The field is REQUIRED.
            let mut missing = authorize_body(&cp, "r-1", 2, 600);
            missing
                .as_object_mut()
                .unwrap()
                .remove("point_manifest_b64");
            let (st, e) = reason_of(authorize(&router, "vm-m", missing).await).await;
            assert_eq!(
                (st, e.reason.as_str()),
                (StatusCode::BAD_REQUEST, "authorize-body-decode")
            );
            assert!(status(&router, "vm-m").await.arm.is_none());
            // A real manifest of ~200 KiB (a long parts list) is accepted:
            // the route's own cap is far above the 16 KiB admin default.
            let mut big: serde_json::Value = serde_json::from_slice(&manifest_of(&cp)).unwrap();
            big["parts"] = serde_json::Value::String("p".repeat(200 * 1024));
            let big = serde_json::to_vec(&big).unwrap();
            let mut body = authorize_body(&cp, "r-1", 2, 600);
            body["point_manifest_b64"] = base64::engine::general_purpose::STANDARD
                .encode(&big)
                .into();
            body["point_manifest_sha256_hex"] = hex::encode(Sha256::digest(&big)).into();
            assert_eq!(
                authorize(&router, "vm-m", body).await.status(),
                StatusCode::CREATED
            );
        }

        /// A malformed body is refused BEFORE the intent row: its
        /// unvalidated fields never reach the hash chain.
        #[tokio::test]
        async fn a_malformed_authorize_writes_no_intent_and_echoes_nothing() {
            let td = TempDir::new().unwrap();
            let (router, cp) = prepared(&td, "vm-s").await;
            let huge = "z".repeat(100 * 1024);
            let mut body = authorize_body(&cp, "r-1", 2, 600);
            body["restore_id"] = huge.clone().into();
            let (st, e) = reason_of(authorize(&router, "vm-s", body).await).await;
            assert_eq!(
                (st, e.reason.as_str()),
                (StatusCode::BAD_REQUEST, "bad-restore-id")
            );
            let mut body = authorize_body(&cp, "r-1", 2, 600);
            body["dest_platform_id_hex"] = "ab".repeat(65).into();
            let (st, e) = reason_of(authorize(&router, "vm-s", body).await).await;
            assert_eq!(
                (st, e.reason.as_str()),
                (StatusCode::BAD_REQUEST, "bad-dest-platform-id")
            );
            let ops = audit_ops(&td);
            assert!(!ops.iter().any(|r| r.contains("authorize-rollback-intent")));
            assert!(!ops.iter().any(|r| r.contains(&huge[..1024])));
            assert!(ops.iter().any(|r| r.contains("bad-restore-id")));
        }

        #[tokio::test]
        async fn an_oversize_body_is_413_and_audited() {
            let td = TempDir::new().unwrap();
            let (router, _cp) = prepared(&td, "vm-o").await;
            for (method, uri, cap) in [
                (
                    "POST",
                    "/v1/admin/vm/vm-o/authorize-rollback",
                    MAX_AUTHORIZE_ROLLBACK_BODY_BYTES,
                ),
                (
                    "POST",
                    "/v1/admin/vm/vm-o/rollback-checkpoint",
                    MAX_ADMIN_BODY_BYTES,
                ),
            ] {
                let req = axum::http::Request::builder()
                    .method(method)
                    .uri(uri)
                    .header("content-type", "application/json")
                    .extension(vali_peer())
                    .body(Body::from(vec![b' '; cap + 1]))
                    .unwrap();
                let (st, e) = reason_of(router.clone().oneshot(req).await.unwrap()).await;
                assert_eq!(
                    (st, e.reason.as_str()),
                    (StatusCode::PAYLOAD_TOO_LARGE, "body-too-large"),
                    "{uri}"
                );
            }
            let rows: Vec<String> = audit_ops(&td)
                .into_iter()
                .filter(|r| r.contains("body-too-large"))
                .collect();
            assert_eq!(rows.len(), 2, "{rows:?}");
            assert!(rows
                .iter()
                .all(|r| r.contains("spiffe://hippius.network/vali")));
        }

        /// A limiter 429 on a rollback route is audited, coalesced to one
        /// row per second so a shed flood cannot amplify into fsyncs.
        /// (The only test that drives the gateway limiter on a rollback
        /// route — the coalescing clock is process-wide.)
        #[tokio::test]
        async fn a_rate_limited_rollback_call_is_audited_once_per_second() {
            let td = TempDir::new().unwrap();
            let (mut state, _counter) = build_state_with_counter(&td);
            state.limiter = Arc::new(NonceRateLimiter::new(RateConfig {
                refill_per_sec: 0.0,
                burst: 1,
            }));
            let router = build_admin_router(state);
            let _ = status(&router, "vm-rl").await;
            let start = now_unix().unwrap();
            for _ in 0..5 {
                let (st, e) = reason_of(
                    router
                        .clone()
                        .oneshot(json_req("GET", "/v1/admin/vm/vm-rl/rollback".into(), None))
                        .await
                        .unwrap(),
                )
                .await;
                assert_eq!(
                    (st, e.reason.as_str()),
                    (StatusCode::TOO_MANY_REQUESTS, "rate-limited")
                );
            }
            let rows: Vec<String> = audit_ops(&td)
                .into_iter()
                .filter(|r| r.contains("\"rate-limited\""))
                .collect();
            // One row per wall-clock second the burst spanned (normally 1).
            let span = now_unix().unwrap() - start + 1;
            assert!(
                !rows.is_empty() && rows.len() as u64 <= span,
                "{} rows over {span} s: {rows:?}",
                rows.len()
            );
            assert!(rows[0].contains("rollback-status") && rows[0].contains("0a1b2c3d"));
        }

        /// A lifecycle route purges (and audits) expired arms first, as
        /// the rollback routes do.
        #[tokio::test]
        async fn a_lifecycle_route_purges_expired_arms() {
            let td = TempDir::new().unwrap();
            let (state, counter) = build_state_with_counter(&td);
            seed_active_via_register(&state, "vm-k", 1, SRC, "lease-1");
            counter.seed("vm-z", 5).unwrap();
            let arm = kbs_core::rollback::RollbackArm {
                vm_id: "vm-z".into(),
                restore_id: "r-stale".into(),
                manifest_sha256_hex: "ab".repeat(32),
                new_gen: 2,
                dest: DEST.into(),
                from_counter: 2,
                to_stamp: 1,
                checkpoint_sha256_hex: "cd".repeat(32),
                armed_at_unix: 10,
                expires_at_unix: 20,
                requested_by: "tenant:1".into(),
                armed_by: String::new(),
            };
            counter.arm_rollback(arm, 1800, 10).unwrap();
            let router = build_admin_router(state);
            router
                .oneshot(activate_request("vm-k", DEST, 2, Some(vali_peer())))
                .await
                .unwrap();
            assert!(counter.rollback_state("vm-z").unwrap().0.is_none());
            assert!(audit_ops(&td)
                .iter()
                .any(|r| r.contains("rollback-expired") && r.contains("r-stale")));
        }
    }

    mod audit_route {
        use super::*;
        use kbs_core::admin_audit::AdminAuditRecord;
        use kbs_core::audit::FileAuditSink;

        /// State with BOTH chains wired and populated: `n_admin` admin
        /// records and `n_release` release records.
        fn state_with_logs(td: &TempDir, n_admin: u64, n_release: u64) -> AdminState {
            let (mut state, _sk, _kid) = build_state(td);
            let body = [0x11; 32];
            for i in 0..n_admin {
                let vm = format!("vm-{i}");
                state
                    .audit
                    .append(
                        &AdminAuditRecord {
                            op: "register-vm",
                            url_vm_id: &vm,
                            ticket_id: Some("tk"),
                            vm_id: Some(&vm),
                            applied: true,
                            status_code: 200,
                            reason: None,
                            peer_san: Some("spiffe://hippius.network/vali"),
                            peer_serial: Some("0a"),
                            body_sha256: &body,
                        },
                        1_000 + i,
                    )
                    .unwrap();
            }
            let release = FileAuditSink::open(td.path().join("release-audit")).unwrap();
            for i in 0..n_release {
                release
                    .append(true, Some("tk"), Some("vm-r"), "released", 2_000 + i)
                    .unwrap();
            }
            state.release_audit = Some(Arc::new(release));
            state
        }

        fn disk(td: &TempDir, rel: &str) -> Vec<(u64, String, String)> {
            std::fs::read_to_string(td.path().join(rel))
                .unwrap()
                .lines()
                .map(|l| {
                    let mut p = l.splitn(3, ':');
                    (
                        p.next().unwrap().parse().unwrap(),
                        p.next().unwrap().into(),
                        p.next().unwrap().into(),
                    )
                })
                .collect()
        }

        async fn page(router: &Router, uri: &str) -> hippius_types::admin::AdminAuditPageResponse {
            let resp = router
                .clone()
                .oneshot(authenticated_get(uri))
                .await
                .unwrap();
            assert_eq!(resp.status(), StatusCode::OK, "{uri}");
            serde_json::from_value(json_of(resp).await).unwrap()
        }

        #[tokio::test]
        async fn serves_the_exact_bytes_of_both_chains() {
            let td = TempDir::new().unwrap();
            let router = build_admin_router(state_with_logs(&td, 3, 4));
            for (log, rel, n) in [
                ("admin", "audit/admin.log", 3),
                ("release", "release-audit/audit.log", 4),
            ] {
                let on_disk = disk(&td, rel);
                let p = page(&router, &format!("/v1/admin/audit?log={log}")).await;
                assert_eq!(p.v, 1);
                assert_eq!(p.log, log);
                assert_eq!(p.entries.len(), n);
                assert_eq!(p.head_seq, Some(n as u64 - 1));
                assert_eq!(p.head_hash_hex, on_disk[n - 1].2);
                assert_eq!(p.genesis_hash_hex.as_deref(), Some(on_disk[0].2.as_str()));
                for (e, (seq, body, hash)) in p.entries.iter().zip(&on_disk) {
                    assert_eq!((e.seq, &e.body_cbor_hex, &e.sha256_hex), (*seq, body, hash));
                }
                for w in p.entries.windows(2) {
                    assert_eq!(w[1].prev_hash_hex, w[0].sha256_hex);
                }
                assert_eq!(p.entries[0].prev_hash_hex, "00".repeat(32));
            }
        }

        #[tokio::test]
        async fn paginates_with_after_seq_and_limit() {
            let td = TempDir::new().unwrap();
            let router = build_admin_router(state_with_logs(&td, 0, 5));
            let p1 = page(&router, "/v1/admin/audit?log=release&limit=2").await;
            assert_eq!(p1.entries.iter().map(|e| e.seq).collect::<Vec<_>>(), [0, 1]);
            let p2 = page(&router, "/v1/admin/audit?log=release&after_seq=1&limit=2").await;
            assert_eq!(p2.entries.iter().map(|e| e.seq).collect::<Vec<_>>(), [2, 3]);
            let p3 = page(&router, "/v1/admin/audit?limit=2&after_seq=3&log=release").await;
            assert_eq!(p3.entries.iter().map(|e| e.seq).collect::<Vec<_>>(), [4]);
            let p4 = page(&router, "/v1/admin/audit?log=release&after_seq=4").await;
            assert!(p4.entries.is_empty());
            assert_eq!(
                p4.head_seq,
                Some(4),
                "the head is reported even past the end"
            );
        }

        #[tokio::test]
        async fn a_limit_above_the_cap_is_clamped_to_it() {
            let td = TempDir::new().unwrap();
            let cap = hippius_types::admin::ADMIN_AUDIT_PAGE_MAX;
            let router = build_admin_router(state_with_logs(&td, 0, u64::from(cap) + 1));
            let p = page(&router, "/v1/admin/audit?log=release&limit=99999999999").await;
            assert_eq!(p.entries.len(), cap as usize);
            let p = page(&router, "/v1/admin/audit?log=release").await;
            assert_eq!(p.entries.len(), cap as usize, "the default is the cap");
        }

        #[tokio::test]
        async fn bad_queries_are_400_with_a_reason() {
            let td = TempDir::new().unwrap();
            let router = build_admin_router(state_with_logs(&td, 1, 1));
            for (q, reason) in [
                ("", "audit-log-required"),
                ("?after_seq=1", "audit-log-required"),
                ("?log=evidence", "audit-log-unknown"),
                ("?log=admin&after_seq=-1", "audit-after-seq-invalid"),
                ("?log=admin&after_seq=+1", "audit-after-seq-invalid"),
                ("?log=admin&limit=0", "audit-limit-invalid"),
                ("?log=admin&limit=x", "audit-limit-invalid"),
                ("?log=admin&log=release", "audit-query-duplicate-key"),
                ("?log=admin&purge=1", "audit-query-unknown-key"),
                ("?log", "audit-query-malformed"),
            ] {
                let resp = router
                    .clone()
                    .oneshot(authenticated_get(&format!("/v1/admin/audit{q}")))
                    .await
                    .unwrap();
                assert_eq!(resp.status(), StatusCode::BAD_REQUEST, "{q}");
                assert_eq!(error_reason(resp).await, reason, "{q}");
            }
        }

        #[tokio::test]
        async fn refused_without_a_verified_client_cert() {
            let td = TempDir::new().unwrap();
            let router = build_admin_router(state_with_logs(&td, 1, 1));
            let req = axum::http::Request::builder()
                .method("GET")
                .uri("/v1/admin/audit?log=admin")
                .body(Body::empty())
                .unwrap();
            let resp = router.oneshot(req).await.unwrap();
            assert_eq!(resp.status(), StatusCode::FORBIDDEN);
            assert_eq!(error_reason(resp).await, "admin-client-cert-required");
        }

        #[tokio::test]
        async fn a_release_chain_not_wired_is_503_not_404() {
            // 404 means "this KBS predates the route" to vali, which then
            // skips quietly — an unwired chain must not look like that.
            let td = TempDir::new().unwrap();
            let (state, _sk, _kid) = build_state(&td);
            let resp = build_admin_router(state)
                .oneshot(authenticated_get("/v1/admin/audit?log=release"))
                .await
                .unwrap();
            assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
            assert_eq!(error_reason(resp).await, "audit-log-unavailable");
        }

        #[tokio::test]
        async fn it_is_read_only_and_never_audits_itself() {
            let td = TempDir::new().unwrap();
            let router = build_admin_router(state_with_logs(&td, 2, 2));
            let files = [
                "audit/admin.log",
                "audit/admin.head.sha256",
                "release-audit/audit.log",
                "release-audit/head.sha256",
            ];
            let before: Vec<Vec<u8>> = files
                .iter()
                .map(|f| std::fs::read(td.path().join(f)).unwrap())
                .collect();
            for _ in 0..5 {
                page(&router, "/v1/admin/audit?log=admin").await;
                page(&router, "/v1/admin/audit?log=release&after_seq=0").await;
            }
            let after: Vec<Vec<u8>> = files
                .iter()
                .map(|f| std::fs::read(td.path().join(f)).unwrap())
                .collect();
            assert_eq!(before, after, "a read changed an audit file");
            let p = page(&router, "/v1/admin/audit?log=admin").await;
            assert_eq!(
                p.head_seq,
                Some(1),
                "reads appended to the chain they serve"
            );
        }

        #[tokio::test]
        async fn only_get_is_routed() {
            let td = TempDir::new().unwrap();
            let router = build_admin_router(state_with_logs(&td, 1, 1));
            for method in ["POST", "PUT", "DELETE", "PATCH"] {
                let mut req = axum::http::Request::builder()
                    .method(method)
                    .uri("/v1/admin/audit?log=admin")
                    .body(Body::empty())
                    .unwrap();
                req.extensions_mut().insert(vali_peer());
                let resp = router.clone().oneshot(req).await.unwrap();
                assert_eq!(resp.status(), StatusCode::METHOD_NOT_ALLOWED, "{method}");
            }
        }

        #[tokio::test]
        async fn shares_the_admin_rate_limit_bucket() {
            let td = TempDir::new().unwrap();
            let mut state = state_with_logs(&td, 1, 0);
            state.limiter = Arc::new(NonceRateLimiter::new(RateConfig {
                refill_per_sec: 0.0,
                burst: 1,
            }));
            let router = build_admin_router(state);
            page(&router, "/v1/admin/audit?log=admin").await;
            let resp = router
                .oneshot(authenticated_get("/v1/admin/audit?log=admin"))
                .await
                .unwrap();
            assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
        }
    }

    // ── POST /v1/admin/cdn-fleet/public ─────────────────────────────────

    fn cdn_fleet_request(body: &str, peer: Option<PeerCertInfo>) -> Request {
        let mut builder = axum::http::Request::builder()
            .method("POST")
            .uri("/v1/admin/cdn-fleet/public")
            .header(header::CONTENT_TYPE, "application/json");
        if let Some(p) = peer {
            builder = builder.extension(p);
        }
        builder.body(Body::from(body.to_string())).unwrap()
    }

    async fn json_body(resp: Response) -> serde_json::Value {
        let bytes = to_bytes(resp.into_body(), 1 << 16).await.unwrap();
        serde_json::from_slice(&bytes).unwrap()
    }

    #[tokio::test]
    async fn cdn_fleet_public_is_404_when_the_class_is_off() {
        let td = TempDir::new().unwrap();
        let (state, _sk, _kid) = build_state(&td);
        let router = build_admin_router(state);
        let resp = router
            .oneshot(cdn_fleet_request(r#"{"version":1}"#, Some(vali_peer())))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
        assert_eq!(json_body(resp).await["reason"], "cdn-fleet-disabled");
    }

    #[tokio::test]
    async fn cdn_fleet_public_returns_a_signed_key_and_audits_the_call() {
        use base64::Engine;
        let td = TempDir::new().unwrap();
        let (mut state, _sk, _kid) = build_state(&td);
        let raw = [0x24u8; 32];
        state.cdn_fleet = Some(Arc::new(crate::cdn_fleet::test_support::publisher(
            3, raw, [6u8; 32],
        )));
        let router = build_admin_router(state);

        // No client identity: refused even on a plaintext listener.
        let resp = router
            .clone()
            .oneshot(cdn_fleet_request(r#"{"version":3}"#, None))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        // Bad bodies.
        for (body, want) in [
            (r#"{"version":0}"#, "cdn-fleet-bad-version"),
            (r#"{"version":4294967296}"#, "cdn-fleet-bad-version"),
            (r#"{"version":3,"x":1}"#, "cdn-fleet-body-decode"),
            ("not json", "cdn-fleet-body-decode"),
        ] {
            let resp = router
                .clone()
                .oneshot(cdn_fleet_request(body, Some(vali_peer())))
                .await
                .unwrap();
            assert_eq!(resp.status(), StatusCode::BAD_REQUEST, "{body}");
            assert_eq!(json_body(resp).await["reason"], want, "{body}");
        }
        // A version that was never minted.
        let resp = router
            .clone()
            .oneshot(cdn_fleet_request(r#"{"version":4}"#, Some(vali_peer())))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_GATEWAY);

        let resp = router
            .oneshot(cdn_fleet_request(r#"{"version":3}"#, Some(vali_peer())))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body: crate::cdn_fleet::CdnFleetPublicResponse =
            serde_json::from_value(json_body(resp).await).unwrap();
        let b64 = base64::engine::general_purpose::STANDARD;
        let public: [u8; 32] = b64
            .decode(&body.x25519_public_b64)
            .unwrap()
            .try_into()
            .unwrap();
        let sig: [u8; 64] = b64
            .decode(&body.kbs_signature_b64)
            .unwrap()
            .try_into()
            .unwrap();
        assert_eq!(body.version, 3);
        assert_eq!(body.kbs_kid_hex, hex::encode(b"kbs-kid"));
        assert_eq!(
            public,
            kbs_core::cdn_fleet::public_key(&kbs_core::cdn_fleet::clamp(&raw))
        );
        let vk = SigningKey::from_bytes(&[6u8; 32]).verifying_key();
        assert_eq!(body.kbs_public_key_hex, hex::encode(vk.to_bytes()));
        kbs_core::cdn_fleet::verify_public_key(&vk, 3, &public, &sig).unwrap();

        let log = std::fs::read_to_string(td.path().join("audit").join("admin.log")).unwrap();
        let decoded: Vec<String> = log
            .lines()
            .map(|line| {
                let bytes = hex::decode(line.split(':').nth(1).unwrap()).unwrap();
                format!(
                    "{:?}",
                    ciborium::de::from_reader::<ciborium::value::Value, _>(bytes.as_slice())
                        .unwrap()
                )
            })
            .collect();
        assert_eq!(decoded.len(), 7, "one row per call");
        assert!(decoded.iter().all(|d| d.contains("cdn-fleet-public")));
        let last = decoded.last().unwrap();
        assert!(last.contains("version=3"), "{last}");
        assert!(last.contains("spiffe://hippius.network/vali"), "{last}");
    }
}
