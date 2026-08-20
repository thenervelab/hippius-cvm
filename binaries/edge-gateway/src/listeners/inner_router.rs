//! The inner-plane order-dispatch router — the vali-facing axum
//! [`Router`] that closes the `vali → Edge sign → miner verify`
//! lifecycle-order chain.
//!
//! PR #144 shipped [`OrderSigner`](crate::order_signing::OrderSigner)
//! (load the Vault-materialised seed; sign body bytes); this module is
//! the HTTP surface that *uses* it: vali POSTs a canonical-CBOR
//! `OrderBody` here, the Edge signs it, and
//! [`MinerForward`](crate::forward::MinerForward) relays the
//! `SignedOrder { body, sig }` envelope to the target miner-agent's
//! `:9700` orders server.
//!
//! ## Routes
//!
//! | Method · path             | purpose                              |
//! |---------------------------|--------------------------------------|
//! | `POST /v1/edge/order`     | sign + forward one lifecycle order   |
//! | `GET  /healthz`           | liveness                             |
//!
//! Only ONE order route — the [`OrderKind`](crate::forward::OrderKind)
//! is carried in the [`ORDER_KIND_HEADER`] header (not the URL), so
//! every order goes through the same handler with the same body cap
//! and the same `&'static str` audit classifier vocabulary. The header
//! is parsed via [`OrderKind::from_header`](crate::forward::OrderKind::from_header)
//! — a CLOSED VOCABULARY — and the matching miner-side route segment
//! is built from a `&'static str` constant. No caller text reaches the
//! outbound URL.
//!
//! ## Wire contract (request)
//!
//! - `content-type: application/cbor`
//! - body: canonical-CBOR `OrderBody` bytes — **opaque** to the Edge
//!   (vali built it; the miner-agent's
//!   `binaries/miner-agent/src/orders/types.rs` re-decodes it).
//! - header [`ORDER_KIND_HEADER`] (`x-hippius-order-kind`): one of
//!   `launch` / `stop` / `destroy` / `migrate` — the
//!   [`OrderKind`](crate::forward::OrderKind) serde rename.
//! - header [`TARGET_ADDR_HEADER`] (`x-hippius-target-addr`): the
//!   miner's NetBird `100.64.x.y:9700` address (the orders server
//!   listens on the NetBird interface only — see
//!   `deploy/ansible/playbooks/miner-tasks/templates/miner-agent-config.toml.j2`).
//!   Validated as a [`SocketAddr`] AND range-checked against
//!   `100.64.0.0/10` (the NetBird CGNAT range). This is the routing-
//!   metadata-around-signed-body pattern PR-Part4-B introduced for
//!   `x-hippius-peer-id`: the body stays the signed-shape the miner
//!   verifies, the unsigned envelope carries routing info.
//!
//! ## Trust posture (no mTLS on this listener)
//!
//! This listener is **plain HTTP** bound to a cluster-internal address
//! — there is no mTLS here. Vali does not (yet) own a client cert
//! against the Edge CA (confirmed against
//! `/Users/dubs/dev/everything/hippius-compute-key/` — the CA has
//! issued the Edge server cert and per-miner client certs, but no
//! vali client cert), so the access control is the Cilium
//! NetworkPolicy gating the inner listener's Service to the vali
//! pod's PodSelector only (see
//! `deploy/gitops/apps/edge-gateway/templates/networkpolicy.yaml`).
//! Two complementary belts:
//!
//! 1. **NetworkPolicy** is the primary control — only vali can reach
//!    this listener at L3.
//! 2. **CGNAT range check** is defense-in-depth — even a misconfigured
//!    sidecar that smuggled traffic to this port could not be used to
//!    POST orders to an arbitrary external IP, because every request's
//!    `x-hippius-target-addr` MUST resolve to a NetBird `100.64.0.0/10`
//!    address before the forwarder is invoked.
//!
//! ## Body-size cap
//!
//! [`DefaultBodyLimit::max`] with
//! [`MAX_MINER_ORDER_BODY`](crate::forward::MAX_MINER_ORDER_BODY)
//! (64 KiB — matches the miner-agent's `MAX_ORDER_BODY`) is layered on
//! the router, so an oversized body is rejected `413` before the
//! handler runs and before any signing work.
//!
//! ## Logging discipline
//!
//! No body bytes are ever logged. Each transaction emits exactly one
//! structured `eprintln!` line: the target addr, the order kind, the
//! body length, the upstream status, and a static outcome classifier
//! (`accepted` / `bad-kind` / `bad-target` / `cgnat-violation` /
//! `forward-transport` / `forward-upstream-status` / …) — the same
//! `&'static str`-only discipline the miner router uses.

use crate::forward::{
    MinerForward, MinerForwardError, MinerForwardResponse, OrderKind, MAX_MINER_ORDER_BODY,
};
use crate::order_signing::OrderSigner;
use axum::body::Bytes;
use axum::extract::{DefaultBodyLimit, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::Router;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tower_http::timeout::RequestBodyTimeoutLayer;

/// Routing-metadata header carrying the target miner's NetBird socket
/// address (`100.64.x.y:9700`). The body is the signed `OrderBody`;
/// this header is the unsigned routing envelope around it, mirroring
/// PR-Part4-B's `x-hippius-peer-id` pattern for heartbeats.
pub const TARGET_ADDR_HEADER: &str = "x-hippius-target-addr";

/// Routing-metadata header carrying the kebab-case
/// [`OrderKind`](crate::forward::OrderKind) — `launch` / `stop` /
/// `destroy` / `migrate`. Parsed via
/// [`OrderKind::from_header`](crate::forward::OrderKind::from_header)
/// (closed vocabulary).
pub const ORDER_KIND_HEADER: &str = "x-hippius-order-kind";

/// NetBird CGNAT prefix — RFC 6598 100.64.0.0/10. Every miner's orders
/// server binds an address from this range (the miner-agent itself
/// refuses any other bind via the `orders.bind_addr` check); the Edge
/// requires it on the outbound side too, so a misconfigured caller
/// cannot use this listener to POST to an arbitrary external IP.
const CGNAT_PREFIX_FIRST_OCTET: u8 = 100;
const CGNAT_PREFIX_SECOND_LOWER: u8 = 64;
const CGNAT_PREFIX_SECOND_UPPER: u8 = 127;

/// Request-body ingestion timeout for the inner listener — bounds the
/// slow-loris vector a misbehaving / compromised vali pod could open
/// by dripping the CBOR body forever. `DefaultBodyLimit` caps SIZE not
/// TIME; the request-body cap caps both. Sized above the inbound side
/// of a normal POST (vali writes a few KiB CBOR in one shot) and well
/// below the §H phase-2 dispatch end-to-end timeout in
/// `vali/apps/orchestration/order_dispatch.py::DEFAULT_DISPATCH_TIMEOUT_S`
/// (45 s), so a stalled body becomes a 408 here rather than a
/// vali-side timeout. Matches the miner listener's own
/// `REQUEST_BODY_TIMEOUT` (15 s). (codex r1 Medium.)
const REQUEST_BODY_TIMEOUT: Duration = Duration::from_secs(15);

/// Shared state every router handler reads. Cheap to clone — every
/// field is an `Arc` (`OrderSigner` is wrapped in `Arc` by `load`,
/// `MinerForward` is held as a trait object).
#[derive(Clone)]
pub struct InnerRouterState {
    /// The Edge's Ed25519 order-signing key. Load is feature-flagged
    /// via `EDGE_ORDER_SIGNING_KEY_PATH` in `main.rs` — when the
    /// subsystem is disabled, the inner listener is NOT bound at all
    /// (so an in-flight handler can rely on `signer` being present).
    signer: Arc<OrderSigner>,
    /// The miner-side forwarder. `Arc<dyn …>` so production
    /// (`ReqwestMinerForward`) and the test `MockMinerForward` share
    /// one handler code path. Same pattern as `MinerRouterState`.
    forward: Arc<dyn MinerForward>,
}

impl InnerRouterState {
    /// Build the shared state from the order-signing key + forwarder.
    pub fn new(signer: Arc<OrderSigner>, forward: Arc<dyn MinerForward>) -> Self {
        Self { signer, forward }
    }
}

/// Build the inner-plane [`Router`].
///
/// The returned router is **not** bound to a connection — every
/// request landing on this listener has already been L3-gated by the
/// NetworkPolicy (see module docs). The
/// [`DefaultBodyLimit`] layer caps every request body at
/// [`MAX_MINER_ORDER_BODY`]; axum answers `413` itself for an oversized
/// body, before any handler / signing work runs.
pub fn build_inner_router(state: InnerRouterState) -> Router {
    // §25 migration M1 relay routes share this listener (same
    // NetworkPolicy gate + slow-loris bounds). They carry their own
    // state (the same signer + forwarder), merged in with the state
    // already applied so the composed router is `Router<()>`.
    let relay =
        super::relay_router::relay_routes().with_state(super::relay_router::RelayRouterState::new(
            Arc::clone(&state.signer),
            Arc::clone(&state.forward),
        ));
    Router::new()
        .route("/v1/edge/order", post(handle_order))
        .route("/healthz", get(handle_healthz))
        .merge(relay)
        // `DefaultBodyLimit` caps body SIZE; `RequestBodyTimeoutLayer`
        // caps body INGESTION TIME. Both apply BEFORE the handler
        // runs (and before any signing work), so an oversized OR
        // slow-dribbling body is rejected without the OrderSigner ever
        // being asked. The slow-loris protection covers a compromised
        // / broken vali pod even though the NetworkPolicy gate already
        // restricts who may connect — defense in depth.
        .layer(RequestBodyTimeoutLayer::new(REQUEST_BODY_TIMEOUT))
        .layer(DefaultBodyLimit::max(MAX_MINER_ORDER_BODY))
        .with_state(state)
}

/// `GET /healthz` — liveness probe. Returns a static `200`; no signing
/// work, nothing that could surface secrets through an error.
async fn handle_healthz() -> StatusCode {
    StatusCode::OK
}

/// `POST /v1/edge/order` — sign + forward one lifecycle order.
///
/// Pipeline:
///
/// 1. **Header parse** — pull and validate
///    [`TARGET_ADDR_HEADER`] + [`ORDER_KIND_HEADER`]. Both must be
///    present, well-formed, and the target must be a NetBird
///    `100.64.0.0/10` address.
/// 2. **Sign + forward** — [`MinerForward::forward_signed_order`]
///    builds the `SignedOrder { body, sig }` envelope and POSTs it to
///    the miner.
/// 3. **Relay the miner's response** — vali sees the miner's HTTP
///    status verbatim (`200` accepted, `4xx` static classifier like
///    `bad-signature` or `order-id-collision`). The miner's response
///    body is relayed unchanged.
///
/// HTTP statuses this handler returns:
///
/// - `400 Bad Request` — header missing / malformed / CGNAT-violation
///   / `kind` not in the closed vocabulary.
/// - `502 Bad Gateway` — forwarder transport failure
///   (`miner-forward-transport`, `miner-forward-response-too-large`,
///   `miner-forward-response-read`, `miner-forward-encode`).
/// - upstream status — on a successful POST to the miner, vali sees
///   the miner's status (200 / 4xx).
async fn handle_order(
    State(state): State<InnerRouterState>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let bytes_in = body.len();

    // (1) Header parse + CGNAT range check.
    let target_addr = match parse_target_addr(&headers) {
        Ok(a) => a,
        Err(class) => {
            log_order(None, None, bytes_in, None, class);
            return StatusCode::BAD_REQUEST.into_response();
        }
    };
    let kind = match parse_order_kind(&headers) {
        Ok(k) => k,
        Err(class) => {
            log_order(Some(target_addr), None, bytes_in, None, class);
            return StatusCode::BAD_REQUEST.into_response();
        }
    };

    // (2) Sign + forward. The body is OPAQUE — passed verbatim to the
    //     signer + the forwarder. The miner-agent's `verify_strict`
    //     will check the signature against the same bytes the operator
    //     sees here.
    match state
        .forward
        .forward_signed_order(&state.signer, target_addr, kind, &body)
        .await
    {
        Ok(resp) => relay_miner_response(target_addr, kind, bytes_in, resp),
        Err(err) => {
            log_order(Some(target_addr), Some(kind), bytes_in, None, err.class());
            // Encode failure on a body the router just sized-checked is
            // a defensive case (ciborium can't realistically fail on
            // `ByteBuf+ByteBuf`) — still classify it as bad-gateway so
            // vali retries through the same path as a transport blip.
            map_forward_error(&err)
        }
    }
}

/// Map a [`MinerForwardError`] to the vali-facing status. Every variant
/// folds to `502 Bad Gateway` — the audit classifier (visible in the
/// log line, see [`log_order`]) carries the distinguishing detail; vali
/// uses the status for retry-or-fail policy. Pulled into a named fn so
/// the `&'static str`-only discipline stays grep-able.
fn map_forward_error(_err: &MinerForwardError) -> Response {
    StatusCode::BAD_GATEWAY.into_response()
}

/// Relay the miner's response back to vali. The miner's status code is
/// surfaced verbatim, and the body bytes are passed through unchanged
/// (`content-type: application/octet-stream` — the miner-agent's
/// response shape on `4xx` is a short static classifier string, on
/// `2xx` an empty body). Vali branches on the exact status to decide
/// `Bound` vs `Failed`.
fn relay_miner_response(
    target_addr: SocketAddr,
    kind: OrderKind,
    bytes_in: usize,
    resp: MinerForwardResponse,
) -> Response {
    log_order(
        Some(target_addr),
        Some(kind),
        bytes_in,
        Some(resp.status),
        if (200..300).contains(&resp.status) {
            "accepted"
        } else {
            "miner-rejected"
        },
    );
    let status = StatusCode::from_u16(resp.status).unwrap_or(StatusCode::BAD_GATEWAY);
    (status, resp.body).into_response()
}

/// Pull [`TARGET_ADDR_HEADER`], parse as [`SocketAddr`], and confirm
/// the address sits in the NetBird CGNAT `100.64.0.0/10` range.
///
/// Returns a `&'static str` classifier on failure — the only outward
/// surface a malformed header gets, and the same audit-key the log
/// line uses.
fn parse_target_addr(headers: &HeaderMap) -> Result<SocketAddr, &'static str> {
    let raw = headers
        .get(TARGET_ADDR_HEADER)
        .ok_or("target-addr-missing")?;
    let text = raw.to_str().map_err(|_| "target-addr-malformed")?;
    let addr: SocketAddr = text.parse().map_err(|_| "target-addr-malformed")?;
    if !is_netbird_cgnat(addr.ip()) {
        return Err("cgnat-violation");
    }
    Ok(addr)
}

/// Pull [`ORDER_KIND_HEADER`] and parse via the closed-vocabulary
/// helper [`OrderKind::from_header`](crate::forward::OrderKind::from_header).
fn parse_order_kind(headers: &HeaderMap) -> Result<OrderKind, &'static str> {
    let raw = headers.get(ORDER_KIND_HEADER).ok_or("order-kind-missing")?;
    let text = raw.to_str().map_err(|_| "order-kind-malformed")?;
    OrderKind::from_header(text).ok_or("bad-kind")
}

/// `true` iff `ip` is in the NetBird CGNAT range `100.64.0.0/10`
/// (RFC 6598 shared-address space, the prefix every NetBird mesh
/// allocates miner addresses from). IPv6 is rejected — NetBird's
/// IPv4-only CGNAT prefix is the source of truth.
fn is_netbird_cgnat(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let [a, b, _, _] = v4.octets();
            a == CGNAT_PREFIX_FIRST_OCTET
                && (CGNAT_PREFIX_SECOND_LOWER..=CGNAT_PREFIX_SECOND_UPPER).contains(&b)
        }
        IpAddr::V6(_) => false,
    }
}

/// Structured audit log — target + kind + body length + upstream
/// status + a static outcome classifier. NEVER the body bytes (§20 /
/// §5.6). `target` / `kind` are emitted via `Display` of the typed
/// values (never the raw caller header) — so even a malformed header
/// that did not parse cannot smuggle bytes into the log line.
fn log_order(
    target: Option<SocketAddr>,
    kind: Option<OrderKind>,
    body_len: usize,
    upstream_status: Option<u16>,
    outcome: &'static str,
) {
    let target_s = target.map(|t| t.to_string()).unwrap_or_else(|| "-".into());
    let kind_s = kind.map(|k| k.as_class_str()).unwrap_or("-");
    let status_s = upstream_status
        .map(|s| s.to_string())
        .unwrap_or_else(|| "-".into());
    eprintln!(
        "hippius-edge-gateway: inner-router: target={} kind={} body_len={} upstream={} outcome={}",
        target_s, kind_s, body_len, status_s, outcome,
    );
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::forward::MockMinerForward;
    use axum::http::HeaderValue;
    use std::io::Write;

    fn test_signer() -> Arc<OrderSigner> {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        f.write_all(hex::encode([7u8; 32]).as_bytes()).unwrap();
        f.flush().unwrap();
        OrderSigner::load(f.path(), None).unwrap()
    }

    fn state_with(forward: Arc<dyn MinerForward>) -> InnerRouterState {
        InnerRouterState::new(test_signer(), forward)
    }

    #[test]
    fn router_builds_without_panicking() {
        let _ = build_inner_router(state_with(Arc::new(MockMinerForward::with_response(
            200,
            Vec::new(),
        ))));
    }

    #[test]
    fn cgnat_check_accepts_netbird_range() {
        // 100.64.0.0/10 — the NetBird mesh's RFC 6598 CGNAT block.
        assert!(is_netbird_cgnat("100.64.0.1".parse().unwrap()));
        assert!(is_netbird_cgnat("100.64.255.255".parse().unwrap()));
        assert!(is_netbird_cgnat("100.100.100.100".parse().unwrap()));
        assert!(is_netbird_cgnat("100.127.255.255".parse().unwrap()));
    }

    #[test]
    fn cgnat_check_rejects_anything_outside_the_range() {
        // 100.63.x.x is one bit below the CGNAT range — must fail.
        assert!(!is_netbird_cgnat("100.63.255.255".parse().unwrap()));
        // 100.128.x.x is one bit above — must fail.
        assert!(!is_netbird_cgnat("100.128.0.0".parse().unwrap()));
        // The classic RFC 1918 ranges must fail (the inner listener
        // must never POST to the cluster-internal pod network).
        assert!(!is_netbird_cgnat("10.0.0.1".parse().unwrap()));
        assert!(!is_netbird_cgnat("192.168.1.1".parse().unwrap()));
        assert!(!is_netbird_cgnat("172.16.0.1".parse().unwrap()));
        // Loopback + public must fail.
        assert!(!is_netbird_cgnat("127.0.0.1".parse().unwrap()));
        assert!(!is_netbird_cgnat("8.8.8.8".parse().unwrap()));
        // IPv6 categorically rejected — NetBird's IPv4 CGNAT is the
        // source of truth for miner addresses.
        assert!(!is_netbird_cgnat("::1".parse().unwrap()));
        assert!(!is_netbird_cgnat("fc00::1".parse().unwrap()));
    }

    #[test]
    fn parse_target_addr_requires_the_header() {
        let headers = HeaderMap::new();
        assert_eq!(
            parse_target_addr(&headers).unwrap_err(),
            "target-addr-missing"
        );
    }

    #[test]
    fn parse_target_addr_rejects_a_non_cgnat_address() {
        let mut headers = HeaderMap::new();
        headers.insert(TARGET_ADDR_HEADER, HeaderValue::from_static("8.8.8.8:9700"));
        assert_eq!(parse_target_addr(&headers).unwrap_err(), "cgnat-violation");
    }

    #[test]
    fn parse_target_addr_rejects_malformed_text() {
        let mut headers = HeaderMap::new();
        headers.insert(TARGET_ADDR_HEADER, HeaderValue::from_static("not-an-addr"));
        assert_eq!(
            parse_target_addr(&headers).unwrap_err(),
            "target-addr-malformed"
        );
        // A port with no IP is also malformed.
        let mut headers = HeaderMap::new();
        headers.insert(TARGET_ADDR_HEADER, HeaderValue::from_static(":9700"));
        assert_eq!(
            parse_target_addr(&headers).unwrap_err(),
            "target-addr-malformed"
        );
    }

    #[test]
    fn parse_target_addr_accepts_a_real_miner_address() {
        let mut headers = HeaderMap::new();
        headers.insert(
            TARGET_ADDR_HEADER,
            HeaderValue::from_static("100.100.100.100:9700"),
        );
        let addr = parse_target_addr(&headers).unwrap();
        assert_eq!(addr.to_string(), "100.100.100.100:9700");
    }

    #[test]
    fn parse_order_kind_requires_a_known_value() {
        let mut headers = HeaderMap::new();
        headers.insert(ORDER_KIND_HEADER, HeaderValue::from_static("launch"));
        assert_eq!(parse_order_kind(&headers).unwrap(), OrderKind::Launch);

        let mut headers = HeaderMap::new();
        headers.insert(ORDER_KIND_HEADER, HeaderValue::from_static("Launch"));
        assert_eq!(parse_order_kind(&headers).unwrap_err(), "bad-kind");

        let mut headers = HeaderMap::new();
        headers.insert(ORDER_KIND_HEADER, HeaderValue::from_static(""));
        assert_eq!(parse_order_kind(&headers).unwrap_err(), "bad-kind");

        let headers = HeaderMap::new();
        assert_eq!(
            parse_order_kind(&headers).unwrap_err(),
            "order-kind-missing"
        );
    }
}
