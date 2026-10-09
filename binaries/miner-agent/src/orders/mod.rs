//! Tenant-CVM lifecycle orders — the signed-order HTTP intake (MA-5).
//!
//! The miner-agent receives launch / stop / destroy / migrate orders
//! over a small axum HTTP server. The server:
//!
//! - **binds the NetBird mesh interface only** — never a public or
//!   wildcard address. The bind address is operator config
//!   (`[orders].bind_addr`) and `Config::validate` rejects anything
//!   outside the NetBird CGNAT range (`100.64.0.0/10`);
//! - **authenticates every order** — each request body is a
//!   [`SignedOrder`]; its Ed25519 signature is `verify_strict`-checked
//!   against the pinned Edge gateway key ([`auth`]) BEFORE the body is
//!   decoded and BEFORE anything is dispatched;
//! - **is idempotent** — a replayed `order_id` is a no-op success
//!   ([`handler::IdempotencyStore`]);
//! - **caps the request body** — a 64 KiB [`DefaultBodyLimit`] sheds
//!   an oversize body before it is buffered, the size guard ordered
//!   ahead of any CBOR decode;
//! - **never logs an order body** — log lines carry the kind, the
//!   `order_id`, the tenant `vm_id` and a static outcome class only.
//!
//! Routes:
//!
//! - `POST /v1/miner/order/launch`   — [`LaunchOrder`]
//! - `POST /v1/miner/order/stop`     — [`StopOrder`]
//! - `POST /v1/miner/order/destroy`  — [`DestroyOrder`]
//! - `POST /v1/miner/order/migrate`  — [`MigrateOrder`] (501 — §25 stub)
//! - `POST /v1/miner/order/migrate-quiesce`  — [`MigrateQuiesceOrder`] (§25 M1)
//! - `POST /v1/miner/order/migrate-snapshot` — [`MigrateSnapshotOrder`] (§25 M1)
//! - `POST /v1/miner/order/migrate-activate` — [`MigrateActivateOrder`] (§25 M2)
//! - `GET  /v1/miner/migration/{vm_id}/status` — §25 M1 snapshot status
//! - `GET  /v1/miner/migration/{vm_id}/source-ack` — §25 M2 surface the
//!   guest-signed source stopped-ack to vali's `poll_source_ack`
//! - `POST /v1/miner/migration/{vm_id}/source-ack` — §25 M2 ingest the
//!   guest-signed source stopped-ack into the store
//! - `POST /v1/miner/order/restore`  — [`RestoreOrder`] (staged restore)
//! - `POST /v1/miner/order/net-policy` — [`NetPolicyOrder`] (host-wide;
//!   persisted, not applied yet)
//! - `POST /v1/miner/order/power-policy` — [`PowerPolicyOrder`] (a VM's
//!   guest-poweroff policy, applied in place)
//! - `GET  /v1/miner/restore/{vm_id}/status` — staged-restore status
//! - `GET  /v1/miner/vm/{vm_id}/domain-state` — read-only tenant-domain
//!   liveness probe for the reboot-recovery reconcile loop (NOT a
//!   signed order — no lifecycle change, no secret)
//! - `GET  /healthz`                 — liveness probe

pub mod auth;
pub mod handler;
pub mod migration;
pub mod types;

use std::net::SocketAddr;
use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::{DefaultBodyLimit, Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::Router;
use tokio::net::TcpListener;
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;

use crate::lifecycle::CvmLifecycle;

use handler::BeginOutcome;

// Re-exported so `crate::orders::X` keeps resolving after MA-3's
// `LaunchOrder`/`Order` were split into the `types` submodule, and so
// the serve loop can name the verifier + idempotency store.
pub use auth::OrderVerifier;
pub use handler::{IdempotencyStore, OrderRejection};
pub use migration::{
    DestStagingArtifacts, EolShutdownAckSigner, GuestStoppedAckSigner, MigrationPhase,
    MigrationStore, ReqwestSnapshotDownloader, ReqwestSnapshotUploader, SnapshotDownloader,
    SnapshotUploader, SourceAckInputs, StagedArtifact,
};
pub use types::{
    BackupOrder, DestroyOrder, LaunchOrder, MigrateActivateOrder, MigrateOrder,
    MigrateQuiesceOrder, MigrateSnapshotOrder, NetEndpoint, NetPolicyLocalAction, NetPolicyMode,
    NetPolicyOrder, NetProto, NetSpec, OnGuestPoweroff, Order, OrderBody, OrderKind, OrderSubject,
    PowerPolicyOrder, PreflightArtifact, RestoreOrder, SignedOrder, StopOrder,
    TenantPreflightOrder, ORDER_DOMAIN,
};

/// Default TCP port the orders HTTP server binds (on the NetBird
/// interface). Distinct from the vsock relay port (5000).
pub const ORDERS_PORT: u16 = 9700;

/// Upper bound on a signed-order request body. A lifecycle order is a
/// few hundred bytes; 64 KiB is generous head-room while bounding the
/// per-request buffer hard. Enforced by [`DefaultBodyLimit`] — an
/// oversize body is shed (`413`) before it is buffered or decoded.
pub const MAX_ORDER_BODY: usize = 64 * 1024;

/// Maximum age of a signed order — `|now - issued_at_unix|` must fit
/// in this window for the order to be dispatched. Closes the
/// long-term-replay vector: a signed order captured today cannot be
/// replayed weeks later (review r1 High). Symmetric ±5 min to absorb
/// the operator's clock-skew tolerance budget across the vali pod,
/// the Edge, and the miner host (the same `±300 s` window vali's
/// heartbeat ingest applies — see `vali/apps/telemetry/` discipline).
pub const MAX_ORDER_AGE_SECS: u64 = 300;

/// Sanity floor on `OrderBody.issued_at_unix`. A miner whose
/// `SystemClock` saturates to `0` (a host with a clock before UNIX
/// epoch — broken RTC) would otherwise accept an attacker-crafted
/// order with `issued_at_unix == 0`, since `|0 - 0| == 0 <=
/// MAX_ORDER_AGE_SECS` (review r2 Medium). Reject any order whose
/// timestamp is older than this floor — 2023-11-14 — independently of
/// the local clock. Picked to pre-date every §H phase-2 release
/// artefact in the repo: an order older than this is necessarily
/// stale REGARDLESS of what the local clock reports.
pub const EARLIEST_VALID_ISSUED_AT_UNIX: u64 = 1_700_000_000;

/// Upper bound on an `order_id` string — bounds both the log line and
/// the per-entry memory the idempotency store holds.
const MAX_ORDER_ID_LEN: usize = 128;

/// Shared state every order route closes over.
#[derive(Clone)]
pub struct OrderState {
    /// The CVM lifecycle orders are dispatched to.
    pub lifecycle: Arc<CvmLifecycle>,
    /// Verifies the Edge signature on every order.
    pub verifier: Arc<OrderVerifier>,
    /// `order_id` deduplication.
    pub idem: Arc<IdempotencyStore>,
    /// This miner's own `miner_id` — the receiving agent asserts
    /// `OrderBody::target_miner_id == self_miner_id` AFTER the
    /// signature verifies, so a signed order intended for a sibling
    /// miner is rejected here (review r1 High — cross-miner replay).
    pub self_miner_id: Arc<str>,
    /// Clock used to enforce the `MAX_ORDER_AGE_SECS` freshness window.
    /// Production wires `SystemClock`; tests inject a
    /// [`FixedClock`](handler::FixedClock) for deterministic age checks.
    pub clock: Arc<dyn Clock>,
    /// Host→guest ticket pusher. Production wires
    /// [`crate::vsock::ticket_push::VsockTicketPusher`]; tests inject
    /// [`crate::vsock::ticket_push::MockTicketPusher`] so the dispatch
    /// integration tests can run against a `MockLibvirtDriver` without
    /// a real AF_VSOCK listening guest CID.
    pub ticket_pusher: Arc<dyn crate::vsock::ticket_push::TicketPusher>,
    /// §25 migration **M1** state map (`quiescing`→`snapshotting`→
    /// `done`/`failed`). The source of truth for the
    /// `GET /v1/miner/migration/{vm_id}/status` route AND the gate that
    /// a snapshot was preceded by a quiesce.
    pub migration: Arc<MigrationStore>,
    /// §25 migration **M1** snapshot uploader — streams the encrypted
    /// LUKS volume to a presigned S3 PUT. Production wires
    /// [`ReqwestSnapshotUploader`]; tests inject a mock.
    pub uploader: Arc<dyn SnapshotUploader>,
    /// §25 source ack signer — drives the source guest's clean EOL
    /// shutdown-sign (the guest signs its `stopped{}` ack from its baked
    /// cmdline at the source generation) on a `migrate-quiesce`. Production
    /// wires [`EolShutdownAckSigner`] (fail-closed until the shutdown-hook
    /// bake ships); tests inject a mock so the producer logic is fully
    /// unit-tested.
    pub ack_signer: Arc<dyn GuestStoppedAckSigner>,
    /// §25 migration **M2** snapshot downloader — streams the encrypted
    /// LUKS volume DOWN from a presigned S3 GET into the dest disk on a
    /// `migrate-activate`. Production wires [`ReqwestSnapshotDownloader`];
    /// tests inject a mock.
    pub downloader: Arc<dyn SnapshotDownloader>,
    /// Tracks the detached order-dispatch tasks (see [`process_order`]
    /// step 6) so the serve loop can drain them at shutdown — a
    /// dispatch task is detached from its HTTP handler but must NOT be
    /// silently cancelled when the runtime is torn down.
    pub tasks: TaskTracker,
    /// Live VM backups (`backup` order + status route). `None` ⇒ the
    /// routes answer `503 backup-disabled`.
    pub backup: Option<Arc<crate::backup::BackupManager>>,
    /// Backup-chain restore for `migrate-activate` chain mode. `None` ⇒ a
    /// chain order fails `chain-unsupported`.
    pub chain_restorer: Option<Arc<dyn crate::backup::restore::ChainRestorer>>,
    /// Staged restores (`restore` order + status route). `None` ⇒ the
    /// routes answer `503 restore-disabled`.
    pub restore: Option<Arc<crate::backup::staged::RestoreManager>>,
    /// The host net policy (persisted and loaded). `None` ⇒ the
    /// `net-policy` route answers `503 net-policy-disabled`.
    pub net_policy: Option<Arc<crate::netpolicy::NetPolicyEnforcer>>,
}

impl OrderState {
    /// Assemble the order-route state.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        lifecycle: Arc<CvmLifecycle>,
        verifier: Arc<OrderVerifier>,
        idem: Arc<IdempotencyStore>,
        self_miner_id: impl Into<Arc<str>>,
        clock: Arc<dyn Clock>,
        ticket_pusher: Arc<dyn crate::vsock::ticket_push::TicketPusher>,
        migration: Arc<MigrationStore>,
        uploader: Arc<dyn SnapshotUploader>,
        downloader: Arc<dyn SnapshotDownloader>,
        ack_signer: Arc<dyn GuestStoppedAckSigner>,
        tasks: TaskTracker,
    ) -> Self {
        Self {
            lifecycle,
            verifier,
            idem,
            self_miner_id: self_miner_id.into(),
            clock,
            ticket_pusher,
            migration,
            uploader,
            downloader,
            ack_signer,
            tasks,
            backup: None,
            chain_restorer: None,
            restore: None,
            net_policy: None,
        }
    }

    /// Enable live backups and backup-chain restores.
    pub fn with_backup(
        mut self,
        backup: Arc<crate::backup::BackupManager>,
        chain_restorer: Arc<dyn crate::backup::restore::ChainRestorer>,
    ) -> Self {
        self.backup = Some(backup);
        self.chain_restorer = Some(chain_restorer);
        self
    }

    /// Accept `net-policy` orders through `enforcer`.
    pub fn with_net_policy(mut self, enforcer: Arc<crate::netpolicy::NetPolicyEnforcer>) -> Self {
        self.net_policy = Some(enforcer);
        self
    }

    /// Enable staged restores.
    pub fn with_restore(mut self, restore: Arc<crate::backup::staged::RestoreManager>) -> Self {
        self.restore = Some(restore);
        self
    }
}

/// Source of "now" for the freshness check — Send + Sync so the
/// `OrderState` can be cloned across handlers. Production is
/// [`SystemClock`]; tests can pass a `FixedClock`.
pub trait Clock: Send + Sync {
    /// Current Unix time in seconds. A failure (clock before epoch)
    /// must not be possible in any deployment we ship; the production
    /// impl panics on `SystemTime::now().duration_since(UNIX_EPOCH)`
    /// failure under `cfg(test)` and saturates to 0 otherwise so an
    /// impossible clock cannot crash production.
    fn now_unix(&self) -> u64;
}

/// Production [`Clock`] — `SystemTime::now()` since UNIX epoch.
pub struct SystemClock;

impl Clock for SystemClock {
    fn now_unix(&self) -> u64 {
        use std::time::{SystemTime, UNIX_EPOCH};
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            // A clock before UNIX epoch is a deeply broken host —
            // saturate to 0 so the freshness check fails closed
            // (every order with `issued_at_unix > 0` is too far in the
            // future) rather than panic the orders task.
            .unwrap_or(0)
    }
}

/// The orders HTTP server — bind decoupled from serve so a caller (and
/// the integration test) can read back an OS-assigned port.
pub struct OrdersServer {
    listener: TcpListener,
    addr: SocketAddr,
}

impl OrdersServer {
    /// Bind the orders listener. `addr`'s port may be `0` for an
    /// OS-assigned ephemeral port — read it back via [`Self::local_addr`].
    ///
    /// The NetBird-only constraint is enforced by `Config::validate` on
    /// the operator-supplied `bind_addr`; this constructor binds
    /// whatever `addr` it is handed, so tests can bind loopback.
    pub async fn bind(addr: SocketAddr) -> std::result::Result<Self, &'static str> {
        let listener = TcpListener::bind(addr).await.map_err(|_| "orders-bind")?;
        let addr = listener.local_addr().map_err(|_| "orders-bind")?;
        Ok(Self { listener, addr })
    }

    /// The address the listener is bound to.
    pub fn local_addr(&self) -> SocketAddr {
        self.addr
    }

    /// Serve orders until `cancel` fires, then drain in-flight
    /// requests (axum graceful shutdown) and return. Consumes `self`.
    pub async fn serve(self, state: OrderState, cancel: CancellationToken) {
        let app = build_orders_router(state);
        let shutdown = async move { cancel.cancelled().await };
        if axum::serve(self.listener, app)
            .with_graceful_shutdown(shutdown)
            .await
            .is_err()
        {
            eprintln!("hippius-miner-agent: orders: serve-error");
        }
    }
}

/// Compose the orders router with the body-size cap applied.
pub fn build_orders_router(state: OrderState) -> Router {
    Router::new()
        .route("/v1/miner/order/launch", post(route_launch))
        .route("/v1/miner/order/stop", post(route_stop))
        .route("/v1/miner/order/destroy", post(route_destroy))
        .route("/v1/miner/order/migrate", post(route_migrate))
        .route(
            "/v1/miner/order/migrate-quiesce",
            post(route_migrate_quiesce),
        )
        .route(
            "/v1/miner/order/migrate-activate",
            post(route_migrate_activate),
        )
        .route(
            "/v1/miner/migration/:vm_id/status",
            get(route_migration_status),
        )
        .route("/v1/miner/vm/:vm_id/domain-state", get(route_domain_state))
        .route(
            "/v1/miner/migration/:vm_id/source-ack",
            get(route_source_ack).post(route_ingest_source_ack),
        )
        .route(
            "/v1/miner/order/tenant-preflight",
            post(route_tenant_preflight),
        )
        .route("/v1/miner/order/net-policy", post(route_net_policy))
        .route("/v1/miner/order/power-policy", post(route_power_policy))
        .route("/healthz", get(route_healthz))
        // Size cap BEFORE any decode — an oversize body never buffers.
        .layer(DefaultBodyLimit::max(MAX_ORDER_BODY))
        // Added after the global cap so its own, larger cap applies: a
        // backup order carries one presigned URL per multipart part.
        .route(
            "/v1/miner/order/backup",
            post(route_backup).layer(DefaultBodyLimit::max(MAX_MULTIPART_ORDER_BODY)),
        )
        .route("/v1/miner/backup/:vm_id/status", get(route_backup_status))
        // A `stage` carries one per-part sha256 per 512 MiB of each piece.
        .route(
            "/v1/miner/order/restore",
            post(route_restore).layer(DefaultBodyLimit::max(MAX_MULTIPART_ORDER_BODY)),
        )
        .route("/v1/miner/restore/:vm_id/status", get(route_restore_status))
        // A multipart snapshot carries one presigned URL per part.
        .route(
            "/v1/miner/order/migrate-snapshot",
            post(route_migrate_snapshot).layer(DefaultBodyLimit::max(MAX_MULTIPART_ORDER_BODY)),
        )
        .with_state(state)
}

/// Body cap for the multipart orders (`backup`, `migrate-snapshot`): one
/// ~530-byte presigned URL per part, and the store takes parts of at most
/// 512 MiB, so the largest flavor's overlay (1280 GiB) needs ~2,600.
/// Mirrors the Edge's `MAX_MULTIPART_REQUEST_BYTES`. Still a hard bound
/// before decode.
pub const MAX_MULTIPART_ORDER_BODY: usize = 2 * 1024 * 1024;

/// Live VM backup — a signed order. Validates and registers the run,
/// spawns it on the serve loop's TaskTracker and ACKs at once; vali
/// polls `backup/{vm}/status`.
async fn route_backup(State(st): State<OrderState>, body: Bytes) -> Response {
    let Some(backup) = st.backup.clone() else {
        return reject(
            OrderKind::Backup,
            StatusCode::SERVICE_UNAVAILABLE,
            "backup-disabled",
        );
    };
    let tasks = st.tasks.clone();
    process_order(
        st,
        body,
        OrderKind::Backup,
        move |lifecycle, order: BackupOrder| async move {
            handler::handle_backup(lifecycle, backup, tasks, order)
        },
    )
    .await
}

/// `GET /v1/miner/backup/{vm_id}/status` — [`crate::backup::BackupStatus`]
/// as JSON: `{vm_id, live: {boot_counter, point_run_ids}, run}`, `run`
/// null when no run is known since the agent started. Unsigned and
/// side-effect-free like `migration/{vm}/status`; it carries no URL.
/// `404 no-domain` only when this host has no domain for the VM; `503`
/// when libvirt/QMP cannot be asked (never a guessed answer).
async fn route_backup_status(State(st): State<OrderState>, Path(vm_id): Path<String>) -> Response {
    let Some(backup) = st.backup.as_ref() else {
        return (StatusCode::SERVICE_UNAVAILABLE, "backup-disabled").into_response();
    };
    let vm_id = match crate::lifecycle::VmId::new(&vm_id) {
        Ok(v) => v,
        Err(_) => return (StatusCode::BAD_REQUEST, "bad-vm-id").into_response(),
    };
    match backup.live_status(&st.lifecycle, &vm_id).await {
        Ok(status) => match serde_json::to_string(&status) {
            Ok(body) => (
                StatusCode::OK,
                [(axum::http::header::CONTENT_TYPE, "application/json")],
                body,
            )
                .into_response(),
            Err(_) => (StatusCode::INTERNAL_SERVER_ERROR, "encode").into_response(),
        },
        Err(crate::backup::LiveStatusError::NoDomain) => {
            (StatusCode::NOT_FOUND, "no-domain").into_response()
        }
        Err(crate::backup::LiveStatusError::Unavailable) => {
            (StatusCode::SERVICE_UNAVAILABLE, "status-unavailable").into_response()
        }
    }
}

/// Staged restore — a signed order (`stage` / `abort` / `reclaim`).
/// `stage` registers and ACKs, the rebuild runs on the serve loop's
/// TaskTracker; vali polls `restore/{vm}/status`.
async fn route_restore(State(st): State<OrderState>, body: Bytes) -> Response {
    let Some(restore) = st.restore.clone() else {
        return reject(
            OrderKind::Restore,
            StatusCode::SERVICE_UNAVAILABLE,
            "restore-disabled",
        );
    };
    let tasks = st.tasks.clone();
    let migration = Arc::clone(&st.migration);
    process_order(
        st,
        body,
        OrderKind::Restore,
        move |lifecycle, order: RestoreOrder| async move {
            handler::handle_restore(lifecycle, restore, migration, tasks, order).await
        },
    )
    .await
}

/// `GET /v1/miner/restore/{vm_id}/status` —
/// [`crate::backup::staged::RestoreStatus`] as JSON. Unsigned and
/// side-effect-free like `backup/{vm}/status`; it carries no URL. `404
/// no-restore` when nothing is known for the VM; `503` when libvirt
/// cannot say whether the domain runs.
async fn route_restore_status(State(st): State<OrderState>, Path(vm_id): Path<String>) -> Response {
    let Some(restore) = st.restore.as_ref() else {
        return (StatusCode::SERVICE_UNAVAILABLE, "restore-disabled").into_response();
    };
    let vm_id = match crate::lifecycle::VmId::new(&vm_id) {
        Ok(v) => v,
        Err(_) => return (StatusCode::BAD_REQUEST, "bad-vm-id").into_response(),
    };
    match restore.status(&st.lifecycle, &vm_id).await {
        Ok(Some(status)) => match serde_json::to_string(&status) {
            Ok(body) => (
                StatusCode::OK,
                [(axum::http::header::CONTENT_TYPE, "application/json")],
                body,
            )
                .into_response(),
            Err(_) => (StatusCode::INTERNAL_SERVER_ERROR, "encode").into_response(),
        },
        Ok(None) => (StatusCode::NOT_FOUND, "no-restore").into_response(),
        Err(crate::backup::staged::StatusError::Unavailable) => {
            (StatusCode::SERVICE_UNAVAILABLE, "status-unavailable").into_response()
        }
    }
}

/// `GET /healthz` — liveness. The server binds only after the
/// lifecycle + verifier are wired, so a reply means ready.
async fn route_healthz() -> StatusCode {
    StatusCode::OK
}

async fn route_launch(State(st): State<OrderState>, body: Bytes) -> Response {
    // The launch closure must close over the ticket pusher (and clone
    // the `Arc`) so the spawned dispatch task in `process_order` step 6
    // can drive a push after `lifecycle.launch` returns. Cloning the
    // `Arc` is cheap and keeps the trait-object dispatch behind a
    // single owner; the closure stays `Send + 'static` for `tokio::spawn`.
    let pusher = Arc::clone(&st.ticket_pusher);
    let migration = Arc::clone(&st.migration);
    process_order(
        st,
        body,
        OrderKind::Launch,
        move |lifecycle, order: LaunchOrder| {
            let pusher = Arc::clone(&pusher);
            let migration = Arc::clone(&migration);
            async move {
                let vm_id = order.vm_id.clone();
                let out = handler::handle_launch(&lifecycle, pusher.as_ref(), order).await;
                if out.is_ok() {
                    // A plain `launch` on a host holding a COMPLETED SOURCE
                    // entry means the VM is ours again — the documented
                    // recovery from a failed migration is exactly this
                    // relaunch at `source_gen`, and reboot-recovery does the
                    // same for a VM that is merely down. Clear it, or the
                    // reboot-watcher keeps suppressing restarts and the VM
                    // dies silently on its first in-guest reboot.
                    //
                    // Only reached on the ORDER route: the §25 dest calls
                    // `handle_launch` directly from `activate_dest`, where
                    // the phase is `Activating` and must survive for vali's
                    // poll. `clear_completed_source` is a no-op on anything
                    // but a source's terminal `Done`.
                    migration.clear_completed_source(&vm_id);
                }
                out
            }
        },
    )
    .await
}

async fn route_stop(State(st): State<OrderState>, body: Bytes) -> Response {
    process_order(
        st,
        body,
        OrderKind::Stop,
        |lifecycle, order: StopOrder| async move { handler::handle_stop(&lifecycle, order).await },
    )
    .await
}

async fn route_power_policy(State(st): State<OrderState>, body: Bytes) -> Response {
    process_order(
        st,
        body,
        OrderKind::PowerPolicy,
        |lifecycle, order: PowerPolicyOrder| async move {
            handler::handle_power_policy(&lifecycle, order).await
        },
    )
    .await
}

async fn route_destroy(State(st): State<OrderState>, body: Bytes) -> Response {
    let migration = Arc::clone(&st.migration);
    let restore = st.restore.clone();
    process_order(
        st,
        body,
        OrderKind::Destroy,
        move |lifecycle, order: DestroyOrder| {
            let migration = Arc::clone(&migration);
            let restore = restore.clone();
            async move {
                let vm_id = order.vm_id.clone();
                let out = handler::handle_destroy(&lifecycle, restore.as_deref(), order).await;
                if out.is_ok() {
                    // The VM's copy on this host is gone (vali reclaims a
                    // migration's source only after the migration is
                    // Done), so a completed SOURCE entry describes nothing
                    // any more. Left behind, it refused a later migration
                    // BACK to this host (`activate-on-source`), and the
                    // status route kept reporting its `done` to the new
                    // job's destination poll (seen in production, A→B→A).
                    migration.clear_completed_source(&vm_id);
                }
                out
            }
        },
    )
    .await
}

async fn route_migrate(State(st): State<OrderState>, body: Bytes) -> Response {
    process_order(
        st,
        body,
        OrderKind::Migrate,
        |_lifecycle, order: MigrateOrder| async move { handler::handle_migrate(order).await },
    )
    .await
}

/// §25 migration **M1** — quiesce the source CVM. A signed order on
/// the same pipeline as launch/stop; the dispatch cleanly stops the
/// guest so its writable LUKS volume is static, recording migration
/// state along the way.
async fn route_migrate_quiesce(State(st): State<OrderState>, body: Bytes) -> Response {
    let migration = Arc::clone(&st.migration);
    let signer = Arc::clone(&st.ack_signer);
    process_order(
        st,
        body,
        OrderKind::MigrateQuiesce,
        move |lifecycle, order: MigrateQuiesceOrder| {
            let migration = Arc::clone(&migration);
            let signer = Arc::clone(&signer);
            async move {
                handler::handle_migrate_quiesce(
                    &lifecycle,
                    migration.as_ref(),
                    signer.as_ref(),
                    order,
                )
                .await
            }
        },
    )
    .await
}

/// §25 migration **M1** — snapshot + upload the source CVM's writable
/// volume. A signed order; the dispatch streams the encrypted volume to
/// the presigned S3 PUT URL.
async fn route_migrate_snapshot(State(st): State<OrderState>, body: Bytes) -> Response {
    let migration = Arc::clone(&st.migration);
    let uploader = Arc::clone(&st.uploader);
    // The snapshot upload runs on the serve loop's TaskTracker so it
    // survives the order ACK (the order returns the instant the upload is
    // launched; vali polls `migration/{vm}/status` for completion).
    let tasks = st.tasks.clone();
    process_order(
        st,
        body,
        OrderKind::MigrateSnapshot,
        move |lifecycle, order: MigrateSnapshotOrder| {
            let migration = Arc::clone(&migration);
            let uploader = Arc::clone(&uploader);
            let tasks = tasks.clone();
            async move {
                handler::handle_migrate_snapshot(&lifecycle, migration, uploader, tasks, order)
                    .await
            }
        },
    )
    .await
}

/// §25 migration **M2** — activate the DESTINATION CVM. A signed order
/// on the same pipeline; the dispatch downloads the encrypted LUKS
/// snapshot from the presigned S3 GET URL, writes it as the dest's
/// `{vm}.img`, and recreates + boots the libvirt domain at `new_gen`.
/// The split-brain fence is enforced upstream (vali's verified
/// source-ack + the KBS `Migrating{new_gen, dest}` transition); this
/// route is the mechanical restore. The launch path drives the vsock
/// ticket push, so the closure closes over the ticket pusher AND the
/// downloader.
async fn route_migrate_activate(State(st): State<OrderState>, body: Bytes) -> Response {
    let downloader = Arc::clone(&st.downloader);
    let pusher = Arc::clone(&st.ticket_pusher);
    let migration = Arc::clone(&st.migration);
    let restorer = st.chain_restorer.clone();
    // The restore runs on the serve loop's TaskTracker so it survives the
    // order ACK (the order returns the instant the restore is launched; vali
    // polls `migration/{vm}/status` on the DEST for completion) — mirroring
    // `route_migrate_snapshot`.
    let tasks = st.tasks.clone();
    process_order(
        st,
        body,
        OrderKind::MigrateActivate,
        move |lifecycle, order: MigrateActivateOrder| {
            let downloader = Arc::clone(&downloader);
            let pusher = Arc::clone(&pusher);
            let migration = Arc::clone(&migration);
            let tasks = tasks.clone();
            async move {
                handler::handle_migrate_activate(
                    lifecycle, downloader, pusher, restorer, migration, tasks, order,
                )
                .await
            }
        },
    )
    .await
}

/// `GET /v1/miner/migration/{vm_id}/status` — the §25 M1 snapshot
/// progress. NOT a signed order: it carries no side effect and reads
/// only the in-memory migration phase. The Edge relays this GET
/// verbatim to vali's `poll_snapshot`, which expects JSON
/// `{"status": "running"|"done"|"failed"}`. A `vm_id` with no recorded
/// migration is a `404` (the Edge maps that to a poll error vali can
/// retry).
async fn route_migration_status(
    State(st): State<OrderState>,
    Path(vm_id): Path<String>,
) -> Response {
    // Validate the path segment THROUGH the same charset gate every
    // order's `vm_id` passes — a malformed id can never reach a log
    // line or a map lookup as raw bytes.
    let vm_id = match crate::lifecycle::VmId::new(&vm_id) {
        Ok(v) => v,
        Err(_) => {
            return (StatusCode::BAD_REQUEST, "bad-vm-id").into_response();
        }
    };
    match st.migration.phase(&vm_id) {
        Some(phase) => {
            // A finished multipart snapshot also reports its part receipts:
            // vali completes the upload from them.
            let receipt = match phase {
                crate::orders::migration::MigrationPhase::Done => {
                    st.migration.snapshot_receipt(&vm_id)
                }
                _ => None,
            };
            // A failed dest activation also reports its class, so vali can
            // tell a restore that never booted from a CVM that could not
            // start. Absent for every other status — those bodies are as
            // before.
            let class = st.migration.failure_class(&vm_id);
            let body = match (receipt, class) {
                (Some(disk), _) => {
                    serde_json::json!({ "status": phase.as_status_str(), "disk": disk }).to_string()
                }
                (None, Some(class)) => {
                    serde_json::json!({ "status": phase.as_status_str(), "class": class })
                        .to_string()
                }
                (None, None) => format!(r#"{{"status":"{}"}}"#, phase.as_status_str()),
            };
            (
                StatusCode::OK,
                [(axum::http::header::CONTENT_TYPE, "application/json")],
                body,
            )
                .into_response()
        }
        None => (StatusCode::NOT_FOUND, "no-migration").into_response(),
    }
}

/// `GET /v1/miner/vm/{vm_id}/domain-state` — read-only liveness probe
/// for the reboot-recovery reconcile loop (PR-3): "is tenant VM
/// `vm_id` actually running right now?". NOT a signed order — no
/// lifecycle transition, no secret, mirrors the auth/extractor posture
/// of [`route_migration_status`] / [`route_source_ack`] rather than
/// the signed-order POST handlers.
///
/// `running: true` / `false` is a DEFINITE libvirt answer (live /
/// down). A down VM the agent left stopped after its guest powered off
/// (guest-poweroff policy `stop`) also carries `"stop_reason":
/// "guest-poweroff"`, so vali settles it `stopped` instead of relaunching
/// it; vali honours that only for a VM whose policy it set to `stop`. A libvirt-unreachable host cannot honestly answer either
/// way, so it is surfaced as `503` rather than folded into `false` —
/// an untrusted miner reporting "down" when it merely can't tell would
/// let it dodge a reboot-recovery relaunch it should actually receive.
async fn route_domain_state(State(st): State<OrderState>, Path(vm_id): Path<String>) -> Response {
    let vm_id = match crate::lifecycle::VmId::new(&vm_id) {
        Ok(v) => v,
        Err(_) => return (StatusCode::BAD_REQUEST, "bad-vm-id").into_response(),
    };
    match st.lifecycle.tenant_domain_liveness(&vm_id).await {
        crate::lifecycle::DomainLiveness::Live => (
            StatusCode::OK,
            [(axum::http::header::CONTENT_TYPE, "application/json")],
            r#"{"running":true}"#,
        )
            .into_response(),
        crate::lifecycle::DomainLiveness::Down => (
            StatusCode::OK,
            [(axum::http::header::CONTENT_TYPE, "application/json")],
            if st.lifecycle.stopped_by_guest(&vm_id) {
                r#"{"running":false,"stop_reason":"guest-poweroff"}"#
            } else {
                r#"{"running":false}"#
            },
        )
            .into_response(),
        crate::lifecycle::DomainLiveness::Unknown => {
            (StatusCode::SERVICE_UNAVAILABLE, "libvirt-unreachable").into_response()
        }
    }
}

/// `GET /v1/miner/migration/{vm_id}/source-ack` — surface the
/// guest-signed §25 `SignedStoppedAck` for vali's `poll_source_ack`
/// (relayed by the Edge `source-ack` route). NOT a signed order: it
/// reads only the in-memory ack the source guest produced on its
/// quiesce. The body shape is `{"signed_ack_hex": "<hex>"}` — exactly
/// what vali's `_poll_ack` parses. A `vm_id` with no surfaced ack yet is
/// a `404` (vali treats that as "not produced yet" and keeps waiting
/// until the phase deadline — fail-closed, never advances the migration
/// without a verified ack).
///
/// The ack is OPAQUE to the miner — only vali can verify the guest's
/// Ed25519 signature against the pinned lifecycle key + the single-use
/// nonce. An untrusted miner cannot forge it; surfacing a wrong / stale
/// ack only makes vali's `_verify_ack` reject it.
async fn route_source_ack(State(st): State<OrderState>, Path(vm_id): Path<String>) -> Response {
    let vm_id = match crate::lifecycle::VmId::new(&vm_id) {
        Ok(v) => v,
        Err(_) => return (StatusCode::BAD_REQUEST, "bad-vm-id").into_response(),
    };
    match st.migration.source_ack(&vm_id) {
        Some(ack) => {
            let body = format!(r#"{{"signed_ack_hex":"{}"}}"#, hex::encode(ack));
            (
                StatusCode::OK,
                [(axum::http::header::CONTENT_TYPE, "application/json")],
                body,
            )
                .into_response()
        }
        None => (StatusCode::NOT_FOUND, "no-source-ack").into_response(),
    }
}

/// `POST /v1/miner/migration/{vm_id}/source-ack` — ingest the
/// guest-signed §25 `SignedStoppedAck` into the migration store so the
/// GET above can surface it to vali. The body is the raw canonical-CBOR
/// `SignedStoppedAck` bytes (the exact bytes the guest's EOL signer
/// produced); the miner stores them verbatim, opaque, and re-surfaces
/// them — it never decodes or trusts them (only vali can verify).
///
/// **Producer note (M3 / deploy):** the live mechanism that drives the
/// running guest to sign at vali's fresh `eol_nonce` and push the result
/// here is a §24-shared runtime transport deferred to M3. This route is
/// the ingest endpoint that closes the loop once that producer lands;
/// until then vali's fence fails closed (no ack ⇒ no dest activation).
/// The 64 KiB body cap (the router's `DefaultBodyLimit`) bounds the
/// stored bytes; a `SignedStoppedAck` is ~100 bytes.
async fn route_ingest_source_ack(
    State(st): State<OrderState>,
    Path(vm_id): Path<String>,
    body: Bytes,
) -> Response {
    let vm_id = match crate::lifecycle::VmId::new(&vm_id) {
        Ok(v) => v,
        Err(_) => return (StatusCode::BAD_REQUEST, "bad-vm-id").into_response(),
    };
    if body.is_empty() {
        return (StatusCode::BAD_REQUEST, "empty-ack").into_response();
    }
    match st.migration.set_source_ack(&vm_id, body.to_vec()) {
        Ok(()) => (StatusCode::OK, "ack-surfaced").into_response(),
        Err(_) => (StatusCode::INTERNAL_SERVER_ERROR, "ack-store").into_response(),
    }
}

async fn route_tenant_preflight(State(st): State<OrderState>, body: Bytes) -> Response {
    // The preflight does I/O (HTTPS fetches) + a READ-ONLY DATA-disk
    // capacity check (no lifecycle mutation), so it now takes the
    // lifecycle handle. The result body is a JSON envelope (NOT the
    // static classifier shape of the other four routes): vali parses it
    // for the launch_digest_hex.
    process_order(
        st,
        body,
        OrderKind::TenantPreflight,
        |lifecycle, order: TenantPreflightOrder| async move {
            handler::handle_tenant_preflight(&lifecycle, order).await
        },
    )
    .await
}

/// Host-wide net policy — a signed order naming no VM. Persisted under
/// the replay rules of [`crate::netpolicy::store`] and loaded; the
/// response is the ack `applied:<revision>:<sha256>`.
async fn route_net_policy(State(st): State<OrderState>, body: Bytes) -> Response {
    let Some(enforcer) = st.net_policy.clone() else {
        return reject(
            OrderKind::NetPolicy,
            StatusCode::SERVICE_UNAVAILABLE,
            "net-policy-disabled",
        );
    };
    let clock = Arc::clone(&st.clock);
    process_order(
        st,
        body,
        OrderKind::NetPolicy,
        move |_lifecycle, order: NetPolicyOrder| async move {
            handler::handle_net_policy(&enforcer, clock.now_unix(), order).await
        },
    )
    .await
}

/// The shared order pipeline: decode → verify → decode body → domain /
/// kind check → idempotency → dispatch → record → respond.
///
/// Generic over the concrete order `T`; `dispatch` is the kind-specific
/// lifecycle call. The dispatch runs on a **detached task** so the
/// idempotency claim is always released and the lifecycle call always
/// completes — even if the HTTP client disconnects mid-request (see
/// step 6). The `Send + 'static` bounds are what let it cross that
/// `tokio::spawn` boundary.
async fn process_order<T, F, Fut>(
    st: OrderState,
    body: Bytes,
    expected: OrderKind,
    dispatch: F,
) -> Response
where
    T: serde::de::DeserializeOwned + OrderSubject + Send + 'static,
    F: FnOnce(Arc<CvmLifecycle>, T) -> Fut + Send + 'static,
    Fut: std::future::Future<Output = std::result::Result<String, OrderRejection>> + Send + 'static,
{
    // (1) Decode the SignedOrder envelope — straight into the typed
    //     shape, never a `ciborium::Value`.
    let signed: SignedOrder = match ciborium::de::from_reader(body.as_ref()) {
        Ok(s) => s,
        Err(_) => {
            return reject(expected, StatusCode::BAD_REQUEST, "signed-order-decode");
        }
    };

    // (2) Verify the Edge signature BEFORE decoding the inner body —
    //     an unauthenticated order is never parsed past this point.
    if let Err(class) = st.verifier.verify(&signed) {
        return reject(expected, StatusCode::UNAUTHORIZED, class);
    }

    // (3) Decode the verified body into the typed OrderBody<T>.
    let order: OrderBody<T> = match ciborium::de::from_reader(signed.body.as_ref()) {
        Ok(o) => o,
        Err(_) => {
            return reject(expected, StatusCode::BAD_REQUEST, "order-body-decode");
        }
    };

    // (4) Domain separation + kind / route + order_id sanity.
    if order.domain != ORDER_DOMAIN {
        return reject(expected, StatusCode::BAD_REQUEST, "order-domain");
    }
    if order.kind != expected {
        return reject(expected, StatusCode::BAD_REQUEST, "order-kind-mismatch");
    }
    if order.order_id.is_empty() || order.order_id.len() > MAX_ORDER_ID_LEN {
        return reject(expected, StatusCode::BAD_REQUEST, "order-id-invalid");
    }
    // (4a) Target binding — the order MUST name THIS miner. Closes the
    //      cross-miner replay vector (review r1 High): every miner pins
    //      the same Edge order-signing key, so a signed order for
    //      sibling miner B is otherwise cryptographically valid here
    //      too. `eq_ignore_ascii_case` (review r2 Low) gives defense-
    //      in-depth against a manual config-vs-Ansible casing typo —
    //      Ansible enforces lowercase, but a hand-edited config that
    //      uppercased the id should still match.
    if !order
        .target_miner_id
        .as_str()
        .eq_ignore_ascii_case(&st.self_miner_id)
    {
        return reject(expected, StatusCode::BAD_REQUEST, "order-wrong-miner");
    }
    // (4b) Freshness window — the order must be at most
    //      `MAX_ORDER_AGE_SECS` away from this miner's clock in EITHER
    //      direction (symmetric ±5 min absorbs the operator's
    //      tolerated clock skew). Closes the long-term-replay vector
    //      (review r1 High): a captured order from a week ago will not
    //      be dispatched even if its signature still verifies.
    //
    //      `EARLIEST_VALID_ISSUED_AT_UNIX` is the independent absolute
    //      floor on the timestamp (review r2 Medium): a broken-RTC host
    //      whose `SystemClock` saturated to `0` would otherwise accept
    //      an attacker-crafted order with `issued_at_unix == 0`, since
    //      `|0 - 0| <= MAX_ORDER_AGE_SECS`. With the floor we ALSO
    //      reject anything dated before the §H phase-2 rollout window,
    //      regardless of the local clock.
    let issued = order.issued_at_unix;
    if issued < EARLIEST_VALID_ISSUED_AT_UNIX {
        return reject(expected, StatusCode::BAD_REQUEST, "order-stale");
    }
    let now = st.clock.now_unix();
    if now.abs_diff(issued) > MAX_ORDER_AGE_SECS {
        return reject(expected, StatusCode::BAD_REQUEST, "order-stale");
    }
    let order_id = order.order_id;
    // A `VmId` is charset-validated at construction, and a host-wide
    // order logs the constant `host` — safe to log raw.
    let vm_id = order.payload.log_subject().to_string();

    // (5) Idempotency — claim the order_id, or short-circuit a replay.
    match st.idem.begin(&order_id) {
        Ok(BeginOutcome::AlreadyOk(class)) => {
            // Echo the ORIGINAL outcome — a replayed stop must still say
            // `stopped` vs `not-running` — or the generic marker when it
            // was not kept (too long, or recorded by an older build).
            let class = class.unwrap_or_else(|| "idempotent-replay".to_string());
            log_outcome(
                expected,
                &order_id,
                vm_id.as_str(),
                &format!("replay:{class}"),
            );
            return (StatusCode::OK, class).into_response();
        }
        Ok(BeginOutcome::InFlight) => {
            return reject(expected, StatusCode::CONFLICT, "order-in-flight");
        }
        Ok(BeginOutcome::Claimed) => {}
        Err(_) => {
            return reject(
                expected,
                StatusCode::INTERNAL_SERVER_ERROR,
                "idempotency-store",
            );
        }
    }

    // (6) Dispatch on a TRACKED, detached task. Spawning — rather than
    //     awaiting `dispatch` inline — makes the order cancellation-safe:
    //     if the HTTP client disconnects and axum drops this handler
    //     future, the task still runs the launch/stop/destroy to its
    //     fail-closed completion AND still records the idempotency
    //     outcome, so the `order_id` is never left stuck `InFlight`
    //     (which would 409 every legitimate retry). It is registered on
    //     the `TaskTracker` — NOT bare `tokio::spawn` — so the serve
    //     loop drains it at shutdown rather than the runtime cancelling
    //     a detached task mid-launch.
    //
    //     The outcome is LOGGED inside the task too: a graceful stop can
    //     outlast the Edge's forward timeout, which then hangs up — the
    //     handler future is dropped, and a log line written after
    //     `task.await` would never appear although the order completed.
    let lifecycle = Arc::clone(&st.lifecycle);
    let idem = Arc::clone(&st.idem);
    let dispatch_id = order_id.clone();
    let task_vm_id = vm_id.clone();
    let task = st.tasks.spawn(async move {
        let result = dispatch(lifecycle, order.payload).await;
        let _ = idem.finish(
            &dispatch_id,
            result.as_ref().ok().map(|class| class.as_str()),
        );
        let class = match &result {
            Ok(class) => class.as_str(),
            Err(rej) => rej.class,
        };
        log_outcome(expected, &dispatch_id, task_vm_id.as_str(), class);
        result
    });
    match task.await {
        Ok(Ok(class)) => (StatusCode::OK, class).into_response(),
        Ok(Err(rej)) => rej.into_response(),
        // The dispatch task panicked — `finish` inside it may not have
        // run, so mark the order failed (retryable). `panic` is denied
        // crate-wide, so this is near-unreachable; handled fail-closed.
        Err(_join) => {
            let _ = st.idem.finish(&order_id, None);
            log_outcome(expected, &order_id, vm_id.as_str(), "dispatch-panic");
            OrderRejection::new(StatusCode::INTERNAL_SERVER_ERROR, "dispatch-panic").into_response()
        }
    }
}

/// Reject before an `order_id` is known — log the kind + class only.
fn reject(kind: OrderKind, status: StatusCode, class: &'static str) -> Response {
    eprintln!(
        "hippius-miner-agent: orders: {} rejected={class}",
        kind.as_class_str()
    );
    OrderRejection::new(status, class).into_response()
}

/// Log a processed order — kind, `order_id`, tenant `vm_id`, outcome
/// class. NEVER an order body field (cmdline, paths). `order_id` is
/// escaped via `{:?}` so a control character cannot mangle the log.
fn log_outcome(kind: OrderKind, order_id: &str, vm_id: &str, class: &str) {
    eprintln!(
        "hippius-miner-agent: orders: {} order_id={order_id:?} vm={vm_id} outcome={class}",
        kind.as_class_str()
    );
}
