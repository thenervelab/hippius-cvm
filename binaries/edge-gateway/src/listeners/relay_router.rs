//! §25 warm-migration **M1** relay routes — the Edge's thin
//! authenticated relay for the source-side quiesce + snapshot.
//!
//! vali's §25 orchestrator
//! (`vali/apps/orchestration/effects.py`) posts guest-ward migration
//! commands to the Edge:
//!
//! | Method · path                       | vali effect            |
//! |-------------------------------------|------------------------|
//! | `POST /v1/relay/{vm_id}/quiesce`    | `relay_quiesce`        |
//! | `POST /v1/relay/{vm_id}/snapshot`   | `trigger_snapshot`     |
//! | `GET  /v1/relay/{vm_id}/snapshot`   | `poll_snapshot`        |
//! | `GET  /v1/relay/{vm_id}/source-ack` | `poll_source_ack` (§25 M2) |
//! | `GET  /v1/relay/{vm_id}/domain-state` | reboot-recovery liveness probe |
//! | `GET  /v1/relay/{vm_id}/backup`     | backup `poll_backup` (run status + live probe) |
//! | `GET  /v1/relay/{vm_id}/restore`    | staged-restore status poll |
//!
//! The `backup` and `restore` ORDERS themselves are not relayed here:
//! vali dispatches them through the generic `/v1/edge/order` inner router
//! (kinds `backup` / `restore`), like `migrate-activate`. Only their
//! unsigned status reads live here.
//!
//! These mirror the launch/stop order-dispatch path EXACTLY (the
//! [`crate::listeners::inner_router`] `/v1/edge/order` flow): the Edge
//! builds a canonical-CBOR `OrderBody`, signs it with the same
//! [`OrderSigner`], and forwards the `SignedOrder { body, sig }` to the
//! SOURCE miner's `:9700` orders server via the same
//! [`MinerForward`](crate::forward::MinerForward) client — to the new
//! `migrate-quiesce` / `migrate-snapshot` route segments the miner-agent
//! now serves. No new transport is invented.
//!
//! ## Why the relay carries BOTH `node_id` and `miner_addr`
//!
//! The miner-agent binds every signed order to a specific host
//! (`OrderBody::target_miner_id == self.miner_id`, the review-r1
//! cross-miner-replay gate). Routing needs the miner's NetBird socket
//! address. The launch/stop path resolves BOTH in vali
//! (`MinerIdentity.miner_id` + `.netbird_ip`) and the Edge re-validates
//! the address against the NetBird CGNAT range. The relay does the same:
//!
//! - `node_id` (vali's `vm.host` == the source `miner_id`) → the signed
//!   `OrderBody::target_miner_id`.
//! - `miner_addr` (the source miner's `100.64.x.y:9700`) → routing,
//!   CGNAT-validated here exactly like `x-hippius-target-addr`.
//!
//! ## Opacity + secret discipline
//!
//! The Edge builds the `OrderBody` via [`ciborium::value::Value`]
//! directly (the same technique `binaries/ticket-validator/src/
//! encode_order.rs` uses) so it does NOT depend on the miner-agent's
//! struct definitions. The presigned `put_url` is signed into the body
//! but NEVER logged. Every log line carries the vm_id, the kind, the
//! target, the upstream status, and a `&'static str` outcome class —
//! the §20 discipline the inner router already enforces.
//!
//! ## TODO — deferred to later milestones (NOT in M1)
//!
//! - M1 is **source-side only**. The destination download + restore +
//!   boot (M2/M3), the signed stopped-ack fence verification (M2), and
//!   the KBS dest re-activation at `new_gen` (M2) are separate. These
//!   relay routes drive the source miner; nothing here activates a
//!   destination. The whole path is inert until those land + a deploy.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::SystemTime;

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use ciborium::value::Value;
use hippius_types::cbor::to_canonical_vec;
use serde::Deserialize;

use crate::forward::{MinerForward, MinerForwardError, MinerForwardResponse, OrderKind};
use crate::order_signing::OrderSigner;

/// Domain-separation tag bound into every signed `OrderBody`. Mirrors
/// `binaries/miner-agent/src/orders/types.rs::ORDER_DOMAIN` (and
/// `encode_order.rs`'s copy) — a drift would surface immediately as a
/// `order-domain` rejection on the miner side.
const ORDER_DOMAIN: &str = "HIPPIUS_MINER_ORDER_V1";

/// Max `vm_id` length — the miner-agent's `VmId` cap (`VM_ID_MAX_LEN`).
/// The relay path validates the vm_id through the same `[a-z0-9-]`
/// charset gate so it can never inject a path component into the
/// outbound miner URL.
const VM_ID_MAX_LEN: usize = 64;

/// Cap on the relay JSON request body. A quiesce/snapshot body is a
/// node_id + an address + (for snapshot) a presigned URL — a few
/// hundred bytes; 16 KiB is generous head-room.
pub const MAX_RELAY_BODY: usize = 16 * 1024;

/// Shared state the relay routes close over — the order signer + the
/// miner forwarder. Both `Arc`, so cloning the state is cheap. Mirrors
/// [`crate::listeners::inner_router::InnerRouterState`].
#[derive(Clone)]
pub struct RelayRouterState {
    signer: Arc<OrderSigner>,
    forward: Arc<dyn MinerForward>,
}

impl RelayRouterState {
    /// Build the relay state from the order-signing key + the
    /// forwarder. The same two handles the inner order router holds.
    pub fn new(signer: Arc<OrderSigner>, forward: Arc<dyn MinerForward>) -> Self {
        Self { signer, forward }
    }
}

/// The JSON body of a `POST /v1/relay/{vm}/quiesce`.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct QuiesceBody {
    /// The source `miner_id` (vali's `vm.host`) — bound into the signed
    /// order's `target_miner_id`.
    node_id: String,
    /// The source miner's NetBird `100.64.x.y:9700` socket address.
    miner_addr: String,
    /// §25 M3/M4 — the lease the source `stopped{}` ack binds to. Carried
    /// through to the miner so it can hand the producer inputs to the guest
    /// signer. `default` for an M1 caller (no producer step).
    #[serde(default)]
    lease_id: String,
    /// §25 M3/M4 — the generation the SOURCE guest signs its ack at (the
    /// VM's CURRENT generation, NOT `new_gen`). `0` ⇒ no producer step.
    #[serde(default)]
    source_gen: u64,
    /// §25 M3/M4 — vali's fresh single-use 32-byte EOL nonce, hex-encoded,
    /// the guest folds into the signed ack. A §20 secret — signed into the
    /// order body but NEVER logged. Empty ⇒ no producer step.
    #[serde(default)]
    eol_nonce_hex: String,
}

/// The JSON body of a `POST /v1/relay/{vm}/snapshot`.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SnapshotBody {
    node_id: String,
    miner_addr: String,
    /// Short-TTL presigned S3 PUT URL. Signed into the order body,
    /// NEVER logged.
    put_url: String,
    /// Short-TTL presigned S3 PUT URL for the per-VM anti-rollback state
    /// disk (the guest's boot counter), carried alongside the volume so a
    /// migrated guest submits the counter the KBS expects. Signed into the
    /// order body, NEVER logged. `#[serde(default)]` so a vali predating
    /// the field is still accepted by `deny_unknown_fields`.
    #[serde(default)]
    state_put_url: String,
}

/// `POST /v1/relay/{vm_id}/quiesce` — relay the §25 M1 quiesce to the
/// source miner. Builds + signs a `migrate-quiesce` order and forwards
/// it; vali sees the miner's status verbatim.
async fn handle_quiesce(
    State(state): State<RelayRouterState>,
    Path(vm_id): Path<String>,
    body: axum::body::Bytes,
) -> Response {
    let vm_id = match validate_vm_id(&vm_id) {
        Ok(v) => v,
        Err(class) => return relay_reject(&vm_id, "quiesce", StatusCode::BAD_REQUEST, class),
    };
    let parsed: QuiesceBody = match serde_json::from_slice(&body) {
        Ok(b) => b,
        Err(_) => {
            return relay_reject(&vm_id, "quiesce", StatusCode::BAD_REQUEST, "bad-relay-body")
        }
    };
    let target = match parse_miner_addr(&parsed.miner_addr) {
        Ok(a) => a,
        Err(class) => return relay_reject(&vm_id, "quiesce", StatusCode::BAD_REQUEST, class),
    };

    // The `migrate-quiesce` payload mirrors the miner-agent's
    // `MigrateQuiesceOrder { vm_id, node_id, lease_id?, source_gen?,
    // eol_nonce_hex? }`. The §25 M3/M4 producer fields are forwarded ONLY
    // when present (vali sends them on the producer quiesce); an absent /
    // empty set keeps the body byte-identical to the M1 wire shape (the
    // miner-agent's `#[serde(default)]` accepts both). `to_canonical_vec`
    // sorts the keys — we hand it an unsorted vec.
    //
    // SECURITY (§20): `eol_nonce_hex` is a single-use secret — it is signed
    // into the order body but NEVER logged (no producer field reaches a log
    // line; `log_relay` carries only vm_id / cmd / target / status / class).
    let mut entries = vec![
        (
            Value::Text("node_id".into()),
            Value::Text(parsed.node_id.clone()),
        ),
        (Value::Text("vm_id".into()), Value::Text(vm_id.clone())),
    ];
    if !parsed.lease_id.is_empty() {
        entries.push((
            Value::Text("lease_id".into()),
            Value::Text(parsed.lease_id.clone()),
        ));
    }
    if parsed.source_gen != 0 {
        entries.push((
            Value::Text("source_gen".into()),
            Value::Integer(parsed.source_gen.into()),
        ));
    }
    if !parsed.eol_nonce_hex.is_empty() {
        entries.push((
            Value::Text("eol_nonce_hex".into()),
            Value::Text(parsed.eol_nonce_hex.clone()),
        ));
    }
    let payload = Value::Map(entries);
    forward_signed(
        &state,
        target,
        OrderKind::MigrateQuiesce,
        &vm_id,
        &parsed.node_id,
        payload,
        "quiesce",
    )
    .await
}

/// `POST /v1/relay/{vm_id}/snapshot` — relay the §25 M1 snapshot
/// trigger to the source miner. Builds + signs a `migrate-snapshot`
/// order carrying the presigned PUT URL and forwards it.
async fn handle_snapshot_trigger(
    State(state): State<RelayRouterState>,
    Path(vm_id): Path<String>,
    body: axum::body::Bytes,
) -> Response {
    let vm_id = match validate_vm_id(&vm_id) {
        Ok(v) => v,
        Err(class) => return relay_reject(&vm_id, "snapshot", StatusCode::BAD_REQUEST, class),
    };
    let parsed: SnapshotBody = match serde_json::from_slice(&body) {
        Ok(b) => b,
        Err(_) => {
            return relay_reject(
                &vm_id,
                "snapshot",
                StatusCode::BAD_REQUEST,
                "bad-relay-body",
            )
        }
    };
    let target = match parse_miner_addr(&parsed.miner_addr) {
        Ok(a) => a,
        Err(class) => return relay_reject(&vm_id, "snapshot", StatusCode::BAD_REQUEST, class),
    };

    // Mirrors `MigrateSnapshotOrder { vm_id, node_id, put_url,
    // state_put_url }`. Insertion order is irrelevant — `to_canonical_vec`
    // re-sorts every map by ENCODED key bytes (length-first, RFC 8949
    // §4.2.1), so the real wire order is
    // `vm_id` < `node_id` < `put_url` < `state_put_url`.
    //
    // The order body is REBUILT here rather than relayed, so a new field
    // only reaches the miner once it is listed here.
    //
    // `state_put_url` is pushed ONLY when non-empty — the same
    // conditional-push discipline `handle_quiesce` uses just above for
    // `lease_id`/`source_gen`/`eol_nonce_hex`. The miner's
    // `MigrateSnapshotOrder` is `deny_unknown_fields`, so emitting the key
    // unconditionally would make an Edge deployed AHEAD of a miner reject
    // EVERY migrate-snapshot for that miner — and it would do so after the
    // quiesce had already stopped the tenant guest. Conditional push makes
    // new-Edge + old-miner byte-identical to today's wire, so the rollout
    // has no ordering constraint between those two.
    let mut payload_entries = vec![
        (
            Value::Text("node_id".into()),
            Value::Text(parsed.node_id.clone()),
        ),
        (
            Value::Text("put_url".into()),
            Value::Text(parsed.put_url.clone()),
        ),
        (Value::Text("vm_id".into()), Value::Text(vm_id.clone())),
    ];
    if !parsed.state_put_url.is_empty() {
        payload_entries.push((
            Value::Text("state_put_url".into()),
            Value::Text(parsed.state_put_url.clone()),
        ));
    }
    let payload = Value::Map(payload_entries);
    forward_signed(
        &state,
        target,
        OrderKind::MigrateSnapshot,
        &vm_id,
        &parsed.node_id,
        payload,
        "snapshot",
    )
    .await
}

/// `GET /v1/relay/{vm_id}/snapshot` — relay the §25 M1 snapshot-status
/// poll to the source miner. The routing target (the source miner
/// address) is carried in the `x-hippius-target-addr` header by vali's
/// poll (the GET has no body); the Edge re-validates it against the
/// CGNAT range and proxies the miner's `{"status": …}` JSON back.
async fn handle_snapshot_status(
    State(state): State<RelayRouterState>,
    Path(vm_id): Path<String>,
    headers: axum::http::HeaderMap,
) -> Response {
    let vm_id = match validate_vm_id(&vm_id) {
        Ok(v) => v,
        Err(class) => {
            return relay_reject(&vm_id, "snapshot-status", StatusCode::BAD_REQUEST, class)
        }
    };
    let target = match parse_target_addr_header(&headers) {
        Ok(a) => a,
        Err(class) => {
            return relay_reject(&vm_id, "snapshot-status", StatusCode::BAD_REQUEST, class)
        }
    };
    match state.forward.forward_migration_status(target, &vm_id).await {
        Ok(resp) => relay_miner_response(&vm_id, "snapshot-status", target, resp),
        Err(err) => {
            log_relay(&vm_id, "snapshot-status", Some(target), None, err.class());
            map_forward_error(&err)
        }
    }
}

/// `GET /v1/relay/{vm_id}/source-ack` — relay the §25 M2 source-stopped
/// -ack poll to the SOURCE miner. Like the snapshot-status GET, the
/// routing target is carried in the `x-hippius-target-addr` header
/// (a GET has no body); the Edge re-validates it against the CGNAT
/// range and proxies the miner's `{"signed_ack_hex": …}` JSON (or `404`
/// when the guest has not produced one yet) back to vali's
/// `poll_source_ack`. The ack is the guest's own Ed25519 signature —
/// opaque to the Edge; only vali verifies it. This poll is what makes
/// the split-brain fence's SOURCE half observable to vali: vali advances
/// to dest-activation ONLY after it has verified the ack this route
/// surfaces.
async fn handle_source_ack(
    State(state): State<RelayRouterState>,
    Path(vm_id): Path<String>,
    headers: axum::http::HeaderMap,
) -> Response {
    let vm_id = match validate_vm_id(&vm_id) {
        Ok(v) => v,
        Err(class) => return relay_reject(&vm_id, "source-ack", StatusCode::BAD_REQUEST, class),
    };
    let target = match parse_target_addr_header(&headers) {
        Ok(a) => a,
        Err(class) => return relay_reject(&vm_id, "source-ack", StatusCode::BAD_REQUEST, class),
    };
    match state.forward.forward_source_ack(target, &vm_id).await {
        Ok(resp) => relay_miner_response(&vm_id, "source-ack", target, resp),
        Err(err) => {
            log_relay(&vm_id, "source-ack", Some(target), None, err.class());
            map_forward_error(&err)
        }
    }
}

/// `GET /v1/relay/{vm_id}/domain-state` — relay the reboot-recovery
/// per-VM liveness probe to the miner: "is tenant VM `vm_id` actually
/// running right now?". Like the snapshot-status / source-ack polls,
/// the routing target is carried in the `x-hippius-target-addr` header
/// (a GET has no body); the Edge re-validates it against the CGNAT
/// range and proxies the miner's `{"running": …}` JSON — or its `503`
/// when the miner's own libvirt is unreachable — straight back. Not a
/// signed order: no lifecycle change, no secret. This signal is
/// host-controlled and unattested, so a malicious miner can report EITHER
/// way; the reboot-recovery consumer is designed for that — the worst a
/// miner achieves is denying (fake "running") or forcing (fake "down") a
/// re-attested boot of its OWN tenant's VM, which it can already do by
/// simply (not) running the domain. Confidentiality/integrity stay gated
/// by attestation + the per-VM KEK + dm-integrity regardless of this bit.
async fn handle_domain_state(
    State(state): State<RelayRouterState>,
    Path(vm_id): Path<String>,
    headers: axum::http::HeaderMap,
) -> Response {
    let vm_id = match validate_vm_id(&vm_id) {
        Ok(v) => v,
        Err(class) => return relay_reject(&vm_id, "domain-state", StatusCode::BAD_REQUEST, class),
    };
    let target = match parse_target_addr_header(&headers) {
        Ok(a) => a,
        Err(class) => return relay_reject(&vm_id, "domain-state", StatusCode::BAD_REQUEST, class),
    };
    match state.forward.forward_domain_state(target, &vm_id).await {
        Ok(resp) => relay_miner_response(&vm_id, "domain-state", target, resp),
        Err(err) => {
            log_relay(&vm_id, "domain-state", Some(target), None, err.class());
            map_forward_error(&err)
        }
    }
}

/// `GET /v1/relay/{vm_id}/backup` — relay vali's backup poll to the miner
/// hosting the VM. Like the other unsigned polls, the routing target rides
/// the `x-hippius-target-addr` header (CGNAT-validated here); the miner's
/// status JSON (or `404` when it has no domain for the VM) comes
/// back verbatim. No side effect and no secret — the report carries sizes,
/// hashes and ETags, never a presigned URL.
async fn handle_backup_status(
    State(state): State<RelayRouterState>,
    Path(vm_id): Path<String>,
    headers: axum::http::HeaderMap,
) -> Response {
    let vm_id = match validate_vm_id(&vm_id) {
        Ok(v) => v,
        Err(class) => return relay_reject(&vm_id, "backup-status", StatusCode::BAD_REQUEST, class),
    };
    let target = match parse_target_addr_header(&headers) {
        Ok(a) => a,
        Err(class) => return relay_reject(&vm_id, "backup-status", StatusCode::BAD_REQUEST, class),
    };
    match state.forward.forward_backup_status(target, &vm_id).await {
        Ok(resp) => relay_miner_response(&vm_id, "backup-status", target, resp),
        Err(err) => {
            log_relay(&vm_id, "backup-status", Some(target), None, err.class());
            map_forward_error(&err)
        }
    }
}

/// `GET /v1/relay/{vm_id}/restore` — relay vali's staged-restore poll to
/// the miner named by `x-hippius-target-addr` (CGNAT-validated here). The
/// miner's status JSON (or `404` when it knows no restore of the VM) comes
/// back verbatim, capped like the backup poll. No side effect, no secret.
async fn handle_restore_status(
    State(state): State<RelayRouterState>,
    Path(vm_id): Path<String>,
    headers: axum::http::HeaderMap,
) -> Response {
    let vm_id = match validate_vm_id(&vm_id) {
        Ok(v) => v,
        Err(class) => {
            return relay_reject(&vm_id, "restore-status", StatusCode::BAD_REQUEST, class)
        }
    };
    let target = match parse_target_addr_header(&headers) {
        Ok(a) => a,
        Err(class) => {
            return relay_reject(&vm_id, "restore-status", StatusCode::BAD_REQUEST, class)
        }
    };
    match state.forward.forward_restore_status(target, &vm_id).await {
        Ok(resp) => relay_miner_response(&vm_id, "restore-status", target, resp),
        Err(err) => {
            log_relay(&vm_id, "restore-status", Some(target), None, err.class());
            map_forward_error(&err)
        }
    }
}

/// Build the canonical-CBOR `OrderBody`, sign it, and forward the
/// `SignedOrder` to the source miner. The shared tail of the quiesce +
/// snapshot-trigger handlers.
#[allow(clippy::too_many_arguments)]
async fn forward_signed(
    state: &RelayRouterState,
    target: SocketAddr,
    kind: OrderKind,
    vm_id: &str,
    target_miner_id: &str,
    payload: Value,
    cmd: &'static str,
) -> Response {
    if target_miner_id.is_empty() {
        return relay_reject(vm_id, cmd, StatusCode::BAD_REQUEST, "missing-node-id");
    }
    let body = match build_order_body(kind, vm_id, target_miner_id, payload) {
        Ok(b) => b,
        Err(class) => return relay_reject(vm_id, cmd, StatusCode::INTERNAL_SERVER_ERROR, class),
    };
    match state
        .forward
        .forward_signed_order(&state.signer, target, kind, &body)
        .await
    {
        Ok(resp) => relay_miner_response(vm_id, cmd, target, resp),
        Err(err) => {
            log_relay(vm_id, cmd, Some(target), None, err.class());
            map_forward_error(&err)
        }
    }
}

/// Assemble the canonical-CBOR `OrderBody` map. Mirrors
/// `encode_order.rs::build` — the canonical key order is enforced by
/// [`to_canonical_vec`], so the unsorted vec we hand it is fine.
fn build_order_body(
    kind: OrderKind,
    vm_id: &str,
    target_miner_id: &str,
    payload: Value,
) -> Result<Vec<u8>, &'static str> {
    // A unique idempotency key per relayed command. The miner-agent
    // dedups on `order_id`; vali's tick re-drive of the same migration
    // step uses a fresh order_id but the underlying op is idempotent
    // (quiesce: already-stopped ⇒ ok; snapshot: same object/URL).
    let order_id = relay_order_id(kind, vm_id);
    let issued_at_unix = now_unix();
    let body = Value::Map(vec![
        (
            Value::Text("domain".into()),
            Value::Text(ORDER_DOMAIN.into()),
        ),
        (
            Value::Text("issued_at_unix".into()),
            Value::Integer(issued_at_unix.into()),
        ),
        (
            Value::Text("kind".into()),
            Value::Text(kind.route_segment().into()),
        ),
        (Value::Text("order_id".into()), Value::Text(order_id)),
        (Value::Text("payload".into()), payload),
        (
            Value::Text("target_miner_id".into()),
            Value::Text(target_miner_id.into()),
        ),
    ]);
    to_canonical_vec(&body).map_err(|_| "canonical-encode")
}

/// A relay order id: `mig-{kind}-{vm_id}-{unix}`. Unique per second per
/// (kind, vm); the miner dedups exact replays and the op is idempotent.
fn relay_order_id(kind: OrderKind, vm_id: &str) -> String {
    format!("mig-{}-{}-{}", kind.route_segment(), vm_id, now_unix())
}

/// Current Unix seconds, saturating to 0 on a pre-epoch clock (the
/// miner-agent's freshness window then rejects it — fail closed, never
/// panic). Mirrors the miner-agent `SystemClock` posture.
fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Validate `vm_id` through the same `[a-z0-9-]`, 1..=64, no leading/
/// trailing hyphen gate the miner-agent's `VmId::new` applies. Returns
/// the validated id (owned) on success.
fn validate_vm_id(raw: &str) -> Result<String, &'static str> {
    let len = raw.len();
    if len == 0 || len > VM_ID_MAX_LEN {
        return Err("bad-vm-id");
    }
    if !raw
        .bytes()
        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
    {
        return Err("bad-vm-id");
    }
    if raw.starts_with('-') || raw.ends_with('-') {
        return Err("bad-vm-id");
    }
    Ok(raw.to_string())
}

/// Parse a `100.64.x.y:9700`-shaped miner address and CGNAT-validate it.
fn parse_miner_addr(raw: &str) -> Result<SocketAddr, &'static str> {
    let addr: SocketAddr = raw.parse().map_err(|_| "miner-addr-malformed")?;
    if !is_netbird_cgnat(addr.ip()) {
        return Err("cgnat-violation");
    }
    Ok(addr)
}

/// Pull + CGNAT-validate the `x-hippius-target-addr` header (the
/// snapshot-status GET carries the routing target there, since a GET
/// has no JSON body). Same header the inner order router reads.
fn parse_target_addr_header(headers: &axum::http::HeaderMap) -> Result<SocketAddr, &'static str> {
    let raw = headers
        .get(crate::listeners::TARGET_ADDR_HEADER)
        .ok_or("target-addr-missing")?;
    let text = raw.to_str().map_err(|_| "target-addr-malformed")?;
    parse_miner_addr(text)
}

/// `true` iff `ip` is in the NetBird CGNAT range `100.64.0.0/10`
/// (RFC 6598). IPv6 is rejected — NetBird's IPv4-only prefix is the
/// source of truth. Same predicate as the inner order router.
fn is_netbird_cgnat(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let [a, b, _, _] = v4.octets();
            a == 100 && (64..=127).contains(&b)
        }
        IpAddr::V6(_) => false,
    }
}

/// Relay the miner's response back to vali verbatim — status + body.
/// vali's `_edge_post` treats any 2xx as success; `poll_snapshot`
/// parses the `{"status": …}` JSON body.
fn relay_miner_response(
    vm_id: &str,
    cmd: &str,
    target: SocketAddr,
    resp: MinerForwardResponse,
) -> Response {
    let outcome = if (200..300).contains(&resp.status) {
        "accepted"
    } else {
        "miner-rejected"
    };
    log_relay(vm_id, cmd, Some(target), Some(resp.status), outcome);
    let status = StatusCode::from_u16(resp.status).unwrap_or(StatusCode::BAD_GATEWAY);
    (status, resp.body).into_response()
}

/// Every [`MinerForwardError`] folds to `502 Bad Gateway` — the audit
/// classifier carries the distinguishing detail; vali uses the status
/// for retry policy. Same posture as the inner order router.
fn map_forward_error(_err: &MinerForwardError) -> Response {
    StatusCode::BAD_GATEWAY.into_response()
}

/// Reject before the forward — log the vm_id + cmd + class, return the
/// status + the static classifier body.
fn relay_reject(vm_id: &str, cmd: &str, status: StatusCode, class: &'static str) -> Response {
    log_relay(vm_id, cmd, None, None, class);
    (status, class).into_response()
}

/// Structured audit log — vm_id + cmd + target + upstream status + a
/// static outcome class. NEVER the body (the presigned URL / node_id
/// payload). `vm_id` is charset-validated before it reaches here, so it
/// cannot smuggle bytes into the log line.
fn log_relay(
    vm_id: &str,
    cmd: &str,
    target: Option<SocketAddr>,
    upstream_status: Option<u16>,
    outcome: &str,
) {
    let target_s = target.map(|t| t.to_string()).unwrap_or_else(|| "-".into());
    let status_s = upstream_status
        .map(|s| s.to_string())
        .unwrap_or_else(|| "-".into());
    eprintln!(
        "hippius-edge-gateway: relay-router: vm={vm_id} cmd={cmd} target={target_s} upstream={status_s} outcome={outcome}"
    );
}

/// Attach the §25 M1 relay routes to an existing axum `Router`. Called
/// by [`crate::listeners::inner_router::build_inner_router`] so the
/// relay shares the inner listener's NetworkPolicy gate + slow-loris
/// bounds. The relay bodies are capped at [`MAX_RELAY_BODY`] here: the
/// inner router's own cap is sized for multipart orders (2 MiB).
pub fn relay_routes() -> axum::Router<RelayRouterState> {
    use axum::routing::get;
    use axum::routing::post;
    axum::Router::new()
        .route("/v1/relay/:vm_id/quiesce", post(handle_quiesce))
        .route(
            "/v1/relay/:vm_id/snapshot",
            post(handle_snapshot_trigger).get(handle_snapshot_status),
        )
        .route("/v1/relay/:vm_id/source-ack", get(handle_source_ack))
        .route("/v1/relay/:vm_id/domain-state", get(handle_domain_state))
        .route("/v1/relay/:vm_id/backup", get(handle_backup_status))
        .route("/v1/relay/:vm_id/restore", get(handle_restore_status))
        .layer(axum::extract::DefaultBodyLimit::max(MAX_RELAY_BODY))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn cgnat_check_matches_the_inner_router() {
        assert!(is_netbird_cgnat("100.64.0.1".parse().unwrap()));
        assert!(is_netbird_cgnat("100.100.100.100".parse().unwrap()));
        assert!(!is_netbird_cgnat("10.0.0.1".parse().unwrap()));
        assert!(!is_netbird_cgnat("100.63.255.255".parse().unwrap()));
        assert!(!is_netbird_cgnat("100.128.0.0".parse().unwrap()));
        assert!(!is_netbird_cgnat("::1".parse().unwrap()));
    }

    #[test]
    fn parse_miner_addr_rejects_non_cgnat_and_malformed() {
        assert!(parse_miner_addr("100.64.0.1:9700").is_ok());
        assert_eq!(parse_miner_addr("8.8.8.8:9700"), Err("cgnat-violation"));
        assert_eq!(parse_miner_addr("not-an-addr"), Err("miner-addr-malformed"));
    }

    #[test]
    fn validate_vm_id_matches_the_miner_charset_gate() {
        assert_eq!(validate_vm_id("tenant-1").as_deref(), Ok("tenant-1"));
        assert_eq!(validate_vm_id(""), Err("bad-vm-id"));
        assert_eq!(validate_vm_id("Tenant"), Err("bad-vm-id"));
        assert_eq!(validate_vm_id("a/b"), Err("bad-vm-id"));
        assert_eq!(validate_vm_id("-x"), Err("bad-vm-id"));
        assert_eq!(validate_vm_id("x-"), Err("bad-vm-id"));
        assert_eq!(validate_vm_id(&"a".repeat(65)), Err("bad-vm-id"));
    }

    #[test]
    fn build_order_body_is_canonical_and_decodes_to_the_miner_shape() {
        use hippius_types::cbor::assert_canonical;
        use serde::Deserialize;

        let payload = Value::Map(vec![
            (Value::Text("node_id".into()), Value::Text("miner-a".into())),
            (Value::Text("vm_id".into()), Value::Text("tenant-1".into())),
        ]);
        let bytes =
            build_order_body(OrderKind::MigrateQuiesce, "tenant-1", "miner-a", payload).unwrap();
        assert_canonical(&bytes).expect("relay-built body must be canonical");

        // Decode through a mirror of the miner-agent's
        // `OrderBody<MigrateQuiesceOrder>` shape — the strongest
        // cross-crate contract.
        #[derive(Deserialize)]
        struct WireQuiesce {
            vm_id: String,
            node_id: String,
        }
        #[derive(Deserialize)]
        struct WireBody {
            domain: String,
            kind: String,
            target_miner_id: String,
            payload: WireQuiesce,
        }
        let back: WireBody = ciborium::de::from_reader(bytes.as_slice()).unwrap();
        assert_eq!(back.domain, ORDER_DOMAIN);
        assert_eq!(back.kind, "migrate-quiesce");
        assert_eq!(back.target_miner_id, "miner-a");
        assert_eq!(back.payload.vm_id, "tenant-1");
        assert_eq!(back.payload.node_id, "miner-a");
    }

    #[test]
    fn snapshot_body_carries_the_put_url() {
        use serde::Deserialize;
        let payload = Value::Map(vec![
            (Value::Text("node_id".into()), Value::Text("miner-a".into())),
            (
                Value::Text("put_url".into()),
                Value::Text("https://s3/put?sig=x".into()),
            ),
            (Value::Text("vm_id".into()), Value::Text("tenant-1".into())),
        ]);
        let bytes =
            build_order_body(OrderKind::MigrateSnapshot, "tenant-1", "miner-a", payload).unwrap();
        #[derive(Deserialize)]
        struct WireSnap {
            put_url: String,
        }
        #[derive(Deserialize)]
        struct WireBody {
            kind: String,
            payload: WireSnap,
        }
        let back: WireBody = ciborium::de::from_reader(bytes.as_slice()).unwrap();
        assert_eq!(back.kind, "migrate-snapshot");
        assert_eq!(back.payload.put_url, "https://s3/put?sig=x");
    }
}
