//! axum router assembly (ARCHITECTURE.md §17).
//!
//! Routes:
//! - `GET  /healthz`        — liveness probe, no service touch.
//! - `POST /v1/kbs/nonce`   — issue a single-use 32-byte nonce.
//! - `POST /v1/kbs/release` — full §7 release pipeline.
//! - `POST /v1/attest/keepalive` — §322 tenant-CVM live attestation.
//! - `POST /v1/kbs/host-attestor/enroll` — blackbox host-attestor
//!   enrollment → `SignedHostAttestorCert` (PR-10b-S2b; INERT until the
//!   S2a relay wires a caller).
//! - `POST /v1/kbs/volume-stamp/confirm` — advance the guest-keyed
//!   overlay's CONFIRMED volume stamp (`kbs_core::volume_stamp`), the
//!   anti-rollback reference for the overlay. Guest-facing (NOT the
//!   admin listener): the caller authenticates with the single-use
//!   token from a prior release, not a network-ACL identity.
//! - `POST /v1/kbs/custody/{bind,renew,rekey}` — the guest custody lease
//!   (`kbs_core::custody`); 404 `custody-disabled` unless the service was
//!   built with a custody runtime.
//!
//! Cross-cutting: a hard request-body cap ([`crate::MAX_REQUEST_BYTES`])
//! installed as a `tower-http` `RequestBodyLimitLayer` so an attacker
//! cannot exhaust memory before kbs-core can fail closed. Per-process
//! nonce-issuance rate-limit is enforced inside the handler.

use crate::handlers::{
    custody_bind, custody_rekey, custody_renew, health, host_enroll, issue_nonce, keepalive,
    release, volume_stamp_confirm, AppState,
};
use crate::rate_limit::{NonceRateLimiter, RateConfig};
use crate::service::KbsService;
use crate::wire::MAX_REQUEST_BYTES;
use axum::http::{header, HeaderValue};
use axum::routing::{get, post};
use axum::Router;
use std::sync::Arc;
use tower_http::limit::RequestBodyLimitLayer;
use tower_http::set_header::SetResponseHeaderLayer;

/// Default per-process release rate. Generous — the per-source rate
/// limit really belongs at the Edge gateway; this is one layer of
/// defence so a single KBS instance cannot be exhausted (§13).
const DEFAULT_RELEASE_RATE: RateConfig = RateConfig {
    refill_per_sec: 1_000.0,
    burst: 2_000,
};

/// Default per-process keepalive rate. Higher than release — many
/// tenant VMs each emit a keepalive every few minutes; the cost is
/// closer to a nonce-mint (no Vault, no HPKE) but the call frequency
/// scales with the deployed tenant count.
const DEFAULT_KEEPALIVE_RATE: RateConfig = RateConfig {
    refill_per_sec: 1_000.0,
    burst: 2_000,
};

/// Default per-process host-attestor enroll rate (blackbox host-attestor
/// chantier — PR-10b-S2b). Stingy on purpose: enrollment is rare (per
/// boot + hourly per host) but is the MOST expensive verify path (full
/// AMD cert-chain verify), so a low ceiling sheds a flood cheaply. The
/// Edge (S2a) is the per-source limiter; this in-process bucket is
/// defence-in-depth so one KBS instance can't be exhausted (§13).
const DEFAULT_HOST_ENROLL_RATE: RateConfig = RateConfig {
    refill_per_sec: 50.0,
    burst: 100,
};

/// Default per-process volume-stamp-confirm rate. Kept off the public
/// builder signatures (like [`DEFAULT_HOST_ENROLL_RATE`]) — the call is
/// paired 1:1 with a prior release (a durable-store CAS write, no
/// Vault/HPKE), so it mirrors [`DEFAULT_RELEASE_RATE`]'s generous
/// default rather than getting its own dedicated knob.
const DEFAULT_VOLUME_STAMP_CONFIRM_RATE: RateConfig = RateConfig {
    refill_per_sec: 1_000.0,
    burst: 2_000,
};

/// Default per-process custody renew + rekey rate. Same ceiling as
/// release: one renew per custody VM per renew interval (10 min) is far
/// below it. It sheds a flood before any signature check; the per-VM
/// budget inside `kbs_core::custody` is charged only after the lease
/// signature verifies, so junk never drains a guest's own budget. A flood
/// ABOVE this ceiling starves renews exactly as it would starve releases —
/// the answer to that is the per-source limit at the edge, with the lease
/// TTL (24 h) as the time to apply it.
const DEFAULT_CUSTODY_RATE: RateConfig = RateConfig {
    refill_per_sec: 1_000.0,
    burst: 2_000,
};

/// Default per-process custody BIND rate — rare, and the one custody call
/// that can reach AMD KDS. Mirrors the host-attestor enroll bucket.
const DEFAULT_CUSTODY_BIND_RATE: RateConfig = RateConfig {
    refill_per_sec: 50.0,
    burst: 100,
};

/// Build the KBS axum [`Router`] over a shared service. The handler
/// state holds `Arc<S>` plus a shared per-process nonce-issuance rate
/// limiter (default 100 req/s, burst 200) and a release rate limiter
/// (default 1_000 req/s, burst 2_000).
pub fn build_router<S>(svc: Arc<S>) -> Router
where
    S: KbsService + 'static,
{
    build_router_with_rates(svc, RateConfig::default(), DEFAULT_RELEASE_RATE)
}

/// Variant with a caller-chosen NONCE [`RateConfig`] (compat with the
/// pre-PR-#37 API; the release rate uses the default).
pub fn build_router_with_rate<S>(svc: Arc<S>, nonce_rate: RateConfig) -> Router
where
    S: KbsService + 'static,
{
    build_router_with_rates(svc, nonce_rate, DEFAULT_RELEASE_RATE)
}

/// Variant with caller-chosen rate configs for BOTH legacy endpoints.
/// The keepalive endpoint uses the [`DEFAULT_KEEPALIVE_RATE`].
pub fn build_router_with_rates<S>(
    svc: Arc<S>,
    nonce_rate: RateConfig,
    release_rate: RateConfig,
) -> Router
where
    S: KbsService + 'static,
{
    build_router_with_all_rates(svc, nonce_rate, release_rate, DEFAULT_KEEPALIVE_RATE)
}

/// Variant with caller-chosen rate configs for ALL THREE endpoints
/// (nonce, release, keepalive). New in PR 3b — preserves the older
/// 2-arg builder above for tests that already plumb the legacy
/// rates.
pub fn build_router_with_all_rates<S>(
    svc: Arc<S>,
    nonce_rate: RateConfig,
    release_rate: RateConfig,
    keepalive_rate: RateConfig,
) -> Router
where
    S: KbsService + 'static,
{
    let state = AppState {
        svc,
        nonce_limiter: Arc::new(NonceRateLimiter::new(nonce_rate)),
        release_limiter: Arc::new(NonceRateLimiter::new(release_rate)),
        keepalive_limiter: Arc::new(NonceRateLimiter::new(keepalive_rate)),
        // Host-attestor enroll uses a fixed default rate — kept off the
        // public builder signatures (the route is INERT until S2a wires a
        // caller). Mirrors the other expensive-verify buckets.
        host_enroll_limiter: Arc::new(NonceRateLimiter::new(DEFAULT_HOST_ENROLL_RATE)),
        volume_stamp_confirm_limiter: Arc::new(NonceRateLimiter::new(
            DEFAULT_VOLUME_STAMP_CONFIRM_RATE,
        )),
        custody_limiter: Arc::new(NonceRateLimiter::new(DEFAULT_CUSTODY_RATE)),
        custody_bind_limiter: Arc::new(NonceRateLimiter::new(DEFAULT_CUSTODY_BIND_RATE)),
    };
    // `SetResponseHeaderLayer::overriding` ensures `Cache-Control:
    // no-store` lands on EVERY response — including the built-in 413
    // emitted by `RequestBodyLimitLayer` and the auto-generated 404 /
    // 405 from axum's routing, which never pass through our handler
    // `ErrorBody` path.
    Router::new()
        .route("/healthz", get(health))
        .route("/v1/kbs/nonce", post(issue_nonce::<S>))
        .route("/v1/kbs/release", post(release::<S>))
        .route("/v1/attest/keepalive", post(keepalive::<S>))
        .route("/v1/kbs/host-attestor/enroll", post(host_enroll::<S>))
        .route(
            "/v1/kbs/volume-stamp/confirm",
            post(volume_stamp_confirm::<S>),
        )
        .route("/v1/kbs/custody/bind", post(custody_bind::<S>))
        .route("/v1/kbs/custody/renew", post(custody_renew::<S>))
        .route("/v1/kbs/custody/rekey", post(custody_rekey::<S>))
        .layer(RequestBodyLimitLayer::new(MAX_REQUEST_BYTES))
        .layer(SetResponseHeaderLayer::overriding(
            header::CACHE_CONTROL,
            HeaderValue::from_static("no-store"),
        ))
        .with_state(state)
}
