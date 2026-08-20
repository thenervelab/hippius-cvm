//! Lifecycle-order dispatch + idempotency (MA-5).
//!
//! Once an order is authenticated ([`super::auth`]) and decoded, it is
//! dispatched to the [`CvmLifecycle`]. Two cross-cutting concerns live
//! here:
//!
//! - **Idempotency** ([`IdempotencyStore`]) — the same `order_id`
//!   processed twice yields the same outcome, the second a no-op
//!   success. A bounded, FIFO-evicted cache; a *failed* order is left
//!   retryable.
//! - **Outcome → HTTP** ([`OrderRejection`]) — a dispatch failure is
//!   mapped to a status code + a static classifier, never a rendered
//!   error string carrying a path or a body byte.
//!
//! ## Desired-state idempotency
//!
//! Beyond the `order_id` cache, each dispatch is idempotent *by
//! outcome*: a launch of an already-live CVM, a stop of an
//! already-stopped CVM, a destroy of an already-gone CVM all return
//! **success** — the order's desired end state is already met (§24).
//! So a retry under a *fresh* `order_id` still converges, not just an
//! exact replay.

use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::sync::Mutex;

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};

use crate::error::MinerAgentError;
use crate::lifecycle::CvmLifecycle;

use super::migration::{MigrationStore, SnapshotDownloader, SnapshotUploader};
use super::types::{
    DestroyOrder, LaunchOrder, MigrateActivateOrder, MigrateOrder, MigrateQuiesceOrder,
    MigrateSnapshotOrder, StopOrder, TenantPreflightOrder,
};

/// Default upper bound on tracked `order_id`s. A miner processes a
/// handful of lifecycle orders per CVM over its life; 4096 distinct
/// ids is ample, and the FIFO eviction keeps memory bounded against a
/// hostile mesh peer spraying unique ids.
pub const DEFAULT_IDEM_CAPACITY: usize = 4096;

/// A rejected order — an HTTP status plus a static classifier. The
/// `class` is always a compile-time constant (the §H/§20 discipline):
/// a rejection response, or a log line built from one, can never echo
/// a path, a key byte, or any run-time value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OrderRejection {
    /// HTTP status to return.
    pub status: StatusCode,
    /// Static classifier — the response body and the audit tag.
    pub class: &'static str,
}

impl OrderRejection {
    /// Construct a rejection.
    pub fn new(status: StatusCode, class: &'static str) -> Self {
        Self { status, class }
    }
}

impl IntoResponse for OrderRejection {
    fn into_response(self) -> Response {
        (self.status, self.class).into_response()
    }
}

/// Map a lifecycle dispatch error to an [`OrderRejection`].
///
/// The HTTP status carries the severity (a `503` is retryable, a `500`
/// is not); the static `class` is the audit tag. The catch-all
/// `dispatch-failed` arm additionally emits a `dispatch-failed-detail`
/// log line carrying the underlying [`MinerAgentError`]'s `Display`
/// (itself a compile-time static classifier — see
/// [`crate::error::MinerAgentError`]) so the operator can tell a
/// libvirt fault from a poisoned lock from a launch that did not reach
/// running without grepping `journalctl` for a matching timestamp. The
/// already-classified arms (`insufficient-resources`,
/// `vsock-cid-exhausted`, `launch-input`, `not-yet-wired`) carry the
/// detail in `class` already; they do not double-log.
pub fn reject_dispatch(err: &MinerAgentError, vm_id: &str) -> OrderRejection {
    reject_dispatch_with_log(err, vm_id, |line| eprintln!("{line}"))
}

/// `reject_dispatch` with the detail-log sink injected — so tests can
/// observe whether the catch-all log line fires (and what it carries)
/// without grabbing the process stderr file descriptor. Production
/// passes `eprintln!`; tests pass a `Vec`-pushing closure.
fn reject_dispatch_with_log<L: FnOnce(String)>(
    err: &MinerAgentError,
    vm_id: &str,
    log_detail: L,
) -> OrderRejection {
    match err {
        // Retryable — the host is at capacity right now.
        MinerAgentError::InsufficientResources => {
            OrderRejection::new(StatusCode::SERVICE_UNAVAILABLE, "insufficient-resources")
        }
        MinerAgentError::VsockCid(_) => {
            OrderRejection::new(StatusCode::SERVICE_UNAVAILABLE, "vsock-cid-exhausted")
        }
        // The order itself is unprocessable — bad launch inputs.
        MinerAgentError::LaunchInput(_) | MinerAgentError::LaunchDigest(_) => {
            OrderRejection::new(StatusCode::UNPROCESSABLE_ENTITY, "launch-input")
        }
        MinerAgentError::NotYetWired => {
            OrderRejection::new(StatusCode::NOT_IMPLEMENTED, "not-yet-wired")
        }
        // The L1-minted OrderTicket could not be pushed to the guest
        // over vsock — a launch-blocking condition (the §21 boot
        // pipeline reads the ticket on the very first stage) but a
        // distinct class from libvirt / lock-poisoned failures, so the
        // operator can wire a targeted alert. The dedicated arm ALSO
        // emits a detail-log line (codex r2 P3) — the public class
        // `ticket-delivery-failed` flattens five sub-classes
        // (`empty` / `oversize` / `no-cid` / `connect-timeout` /
        // `write-failed`), and an operator can't tell a bad payload
        // from a guest-listener timeout from the public class alone.
        MinerAgentError::TicketDelivery(_) => {
            log_detail(format!(
                "hippius-miner-agent: orders: ticket-delivery-failed-detail vm={vm_id} class={err}"
            ));
            OrderRejection::new(StatusCode::INTERNAL_SERVER_ERROR, "ticket-delivery-failed")
        }
        // §25 migration M1 — a quiesce/snapshot step failed. The public
        // class stays the flattened `migration-failed`; the sub-class
        // (`quiesce-stop` / `not-quiesced` / `disk-missing` /
        // `disk-open` / `upload-send` / `upload-status` / …) lands on
        // the detail log so an operator can tell a libvirt quiesce fault
        // from an S3 upload failure. Vali learns the terminal outcome
        // from the snapshot status poll, not this status code.
        MinerAgentError::Migration(_) => {
            log_detail(format!(
                "hippius-miner-agent: orders: migration-failed-detail vm={vm_id} class={err}"
            ));
            OrderRejection::new(StatusCode::INTERNAL_SERVER_ERROR, "migration-failed")
        }
        // Everything else — a libvirt fault, a poisoned lock, a launch
        // that did not reach running — is an internal failure. The
        // public class stays `dispatch-failed` (no wire-side breaking
        // change); the `Display` of the underlying variant is logged
        // here so an operator can disambiguate without trawling
        // adjacent service logs for a matching timestamp.
        _ => {
            log_detail(format!(
                "hippius-miner-agent: orders: dispatch-failed-detail vm={vm_id} class={err}"
            ));
            OrderRejection::new(StatusCode::INTERNAL_SERVER_ERROR, "dispatch-failed")
        }
    }
}

/// Dispatch a `launch` order.
///
/// After the libvirt domain reaches `Running` for a **fresh** launch,
/// push the L1-minted OrderTicket COSE envelope to the guest over the
/// host→guest vsock channel ([`hippius_types::ticket_vsock::PORT`]).
/// The guest's §21 pipeline reads the ticket on its first stage, so a
/// push failure blocks every downstream step — promoted from a
/// `dispatch-failed` catch-all to a dedicated `ticket-delivery-failed`
/// class so an operator can wire a targeted alert.
///
/// `AlreadyLaunched` is mapped to **success** — the order's desired
/// end state (this `vm_id` running) is already met, so a re-issued
/// launch is a no-op, not an error (idempotent by outcome). On the
/// `AlreadyLaunched` path we **skip** the ticket push: the guest's
/// receiver is a one-shot listener that closes after the prior
/// launch's `recv_ticket` returned, so a second push would hang for
/// `PUSH_TIMEOUT_SECS` and surface a false `ticket-delivery-failed`
/// (codex r2 P2). The prior launch's push outcome already determined
/// the §21 pipeline's fate; a `Running` domain whose original push
/// failed would already be torn down by `teardown_failed_launch`, so
/// any `AlreadyLaunched` we see here means the original push *did*
/// succeed.
pub async fn handle_launch(
    lifecycle: &CvmLifecycle,
    pusher: &dyn crate::vsock::ticket_push::TicketPusher,
    order: LaunchOrder,
) -> std::result::Result<String, OrderRejection> {
    // `lifecycle.launch` consumes `order`; capture the `vm_id` AND the
    // COSE ticket bytes for the post-launch push BEFORE the move.
    let vm_id = order.vm_id.clone();
    let vm_id_str = vm_id.as_str().to_owned();
    let cose_ticket = order.cose_ticket.clone();

    match lifecycle.launch(order).await {
        Ok(_) => {}
        // Desired-state idempotency: the VM is already running. The
        // ticket push on the prior launch already drove the §21
        // pipeline; pushing again would hit a closed receiver.
        Err(MinerAgentError::AlreadyLaunched) => return Ok("already-launched".to_string()),
        Err(err) => return Err(reject_dispatch(&err, &vm_id_str)),
    }

    // Look up the CID the lifecycle assigned. A successful launch
    // guarantees the CID is allocated; a `None` here is a
    // launch-ordering bug that we surface as a static sub-classifier
    // rather than silently skipping the push.
    let cid = match lifecycle.cid_allocator().cid_for_vm(&vm_id) {
        Ok(Some(cid)) => cid,
        Ok(None) => {
            return Err(reject_dispatch(
                &MinerAgentError::TicketDelivery("no-cid"),
                &vm_id_str,
            ));
        }
        Err(err) => return Err(reject_dispatch(&err, &vm_id_str)),
    };

    if let Err(err) = pusher
        .push(cid, hippius_types::ticket_vsock::PORT, cose_ticket.as_ref())
        .await
    {
        return Err(reject_dispatch(&err, &vm_id_str));
    }

    Ok("launched".to_string())
}

/// Dispatch a `stop` order. A `stop` of a CVM the lifecycle is not
/// tracking is success — already not running.
pub async fn handle_stop(
    lifecycle: &CvmLifecycle,
    order: StopOrder,
) -> std::result::Result<String, OrderRejection> {
    match lifecycle.stop(&order.vm_id, order.graceful).await {
        Ok(()) => Ok("stopped".to_string()),
        Err(MinerAgentError::VmNotFound) => Ok("not-running".to_string()),
        Err(err) => Err(reject_dispatch(&err, order.vm_id.as_str())),
    }
}

/// Dispatch a `destroy` order (§24 decommission). The lifecycle's
/// `destroy` is itself idempotent — a destroy of an already-gone CVM
/// is a success no-op.
pub async fn handle_destroy(
    lifecycle: &CvmLifecycle,
    order: DestroyOrder,
) -> std::result::Result<String, OrderRejection> {
    match lifecycle.destroy(&order.vm_id).await {
        Ok(()) => Ok("destroyed".to_string()),
        Err(err) => Err(reject_dispatch(&err, order.vm_id.as_str())),
    }
}

/// Dispatch a `migrate` order (§25). The migration mechanics are a
/// dedicated follow-up — MA-5 ships only the authenticated, idempotent
/// route, so this fails closed with `501 Not Implemented`.
pub async fn handle_migrate(_order: MigrateOrder) -> std::result::Result<String, OrderRejection> {
    Err(OrderRejection::new(
        StatusCode::NOT_IMPLEMENTED,
        "migrate-not-yet-wired",
    ))
}

/// Dispatch a §25 migration **M1** `migrate-quiesce` order. Cleanly
/// stops the source guest so its writable LUKS volume is static, then
/// records migration state. Idempotent: an already-stopped CVM is a
/// success no-op (`super::migration::quiesce` maps `VmNotFound` to Ok).
///
/// TODO(M2 — fence): a clean stop only; the guest `SignedStoppedAck`
/// production + vali-side verification (the split-brain fence) is M2.
pub async fn handle_migrate_quiesce(
    lifecycle: &CvmLifecycle,
    migration: &MigrationStore,
    signer: &dyn super::migration::GuestStoppedAckSigner,
    order: MigrateQuiesceOrder,
) -> std::result::Result<String, OrderRejection> {
    let vm_id_str = order.vm_id.as_str().to_owned();
    // §25 M3 — derive the producer inputs (vali's nonce + source_gen) from
    // the order. `None` for an M1 caller ⇒ a plain clean stop.
    let ack_inputs = order.source_ack_inputs();
    match super::migration::quiesce(
        lifecycle,
        migration,
        signer,
        &order.vm_id,
        ack_inputs.as_ref(),
    )
    .await
    {
        Ok(()) => Ok("quiesced".to_string()),
        Err(err) => Err(reject_dispatch(&err, &vm_id_str)),
    }
}

/// Dispatch a §25 migration **M1** `migrate-snapshot` order. Validates
/// the prior quiesce (`not-quiesced` otherwise) synchronously, then
/// streams the (already-encrypted) writable LUKS volume to the presigned
/// S3 PUT URL on a BACKGROUND task, driving the migration state
/// `running → done`/`failed`.
///
/// The order ACKs `snapshot-accepted` the moment the upload is launched
/// — it does NOT block for the multi-GB transfer (which far exceeds
/// vali's order-relay/effect timeout). vali tracks the upload to
/// completion via the `migration/{vm}/status` poll (`poll_snapshot`),
/// which reads the same `MigrationStore` phase the background task moves
/// to `Done`/`Failed`. The task is registered on the serve loop's
/// `TaskTracker` so a runtime shutdown drains it rather than cancelling
/// the upload mid-stream.
pub async fn handle_migrate_snapshot(
    lifecycle: &CvmLifecycle,
    migration: Arc<MigrationStore>,
    uploader: Arc<dyn SnapshotUploader>,
    tasks: tokio_util::task::TaskTracker,
    order: MigrateSnapshotOrder,
) -> std::result::Result<String, OrderRejection> {
    let vm_id = order.vm_id.clone();
    let vm_id_str = vm_id.as_str().to_owned();
    // Fast, synchronous gate: a snapshot MUST follow a quiesce. Failing
    // here (before spawning) lets vali see `not-quiesced`/`disk-missing`
    // directly on the order response.
    let disk_path = match migration.begin_snapshot(&vm_id) {
        Ok(p) => p,
        Err(err) => return Err(reject_dispatch(&err, &vm_id_str)),
    };
    let put_url = order.put_url.clone();
    // The anti-rollback state disk travels WITH the volume. The guest is
    // already quiesced (the gate above), so the file is static — no torn
    // read. Resolved from the lifecycle's own `state_disk_root`, never
    // from the order, so a malicious vali cannot aim the upload at an
    // arbitrary host path.
    let state_put_url = order.state_put_url.clone();
    let state_disk_path = lifecycle.state_disk_path(&vm_id);
    tasks.spawn(async move {
        // Volume first (the multi-GB leg), then the 1 MiB state disk.
        // BOTH must land: a snapshot whose state disk is missing produces
        // a destination that boots and never unlocks, which §25 would
        // otherwise report as a successful migration. So the state upload
        // failing marks the whole snapshot failed — fail closed, vali
        // aborts the migration and the source stays authoritative.
        let volume = uploader.upload(&disk_path, &put_url).await;
        if volume.is_err() {
            migration.mark_snapshot_failed(&vm_id);
            return;
        }
        // Empty URL ⇒ a vali predating the field; nothing to carry, and
        // the pre-fix behaviour is what the dest already tolerates.
        if !state_put_url.is_empty() {
            // FAIL CLOSED on an absent or unreadable state disk.
            //
            // Skipping the upload is NOT a graceful degrade: vali sets
            // `snapshot_state_key` and presigns the dest's GET at
            // SNAPSHOTTING, before it can know whether we uploaded
            // anything. So a skipped upload does not give the dest a
            // blank counter — it gives it a 404, surfacing as
            // `download-status` AFTER the fence has already denied the
            // source forever. Failing here instead aborts the migration
            // while it is still PRE-FENCE and the source is still
            // authoritative, which is the difference between "migration
            // failed, tenant fine" and "tenant stranded".
            //
            // Matching only `Ok` also means an EIO/EACCES — or a
            // `state_disk_root` that no longer points where the VM was
            // launched — fails rather than being swallowed as "absent".
            // In practice the file always exists: `launch` calls
            // `ensure_state_disk` before any virsh, for golden and
            // legacy alike, so a VM that booted has one.
            match tokio::fs::metadata(&state_disk_path).await {
                Ok(meta) if meta.len() > 0 => {
                    if uploader
                        .upload(&state_disk_path, &state_put_url)
                        .await
                        .is_err()
                    {
                        migration.mark_snapshot_failed(&vm_id);
                        return;
                    }
                }
                _ => {
                    eprintln!(
                        "hippius-miner-agent: migrate-snapshot: vm={vm_id_str} \
                         state disk unreadable or empty — failing the snapshot \
                         (a dest without the boot counter can never unlock)"
                    );
                    migration.mark_snapshot_failed(&vm_id);
                    return;
                }
            }
        }
        let _ = migration.mark_snapshot_done(&vm_id);
    });
    Ok("snapshot-accepted".to_string())
}

/// Dispatch a §25 migration **M2** `migrate-activate` order — the
/// DESTINATION restore. Downloads the encrypted LUKS snapshot from the
/// presigned S3 GET URL, writes it as the dest's `{vm}.img`, and
/// recreates + boots the libvirt domain at the migration generation.
///
/// **Split-brain fence (the security invariant).** This handler is the
/// mechanical destination restore — the cryptographic fence that makes
/// two live copies impossible lives UPSTREAM and is already enforced:
///
/// 1. vali only dispatches this order from its `DestActivating` state,
///    which is reachable ONLY after `_h_mig_awaiting_source_ack`
///    verified the source guest's signed `stopped{}` ack at the source
///    generation (`vali/apps/orchestration/service.py`).
/// 2. vali calls the KBS `activate` admin endpoint BEFORE this order,
///    moving the KBS VmState to `Migrating{new_gen, dest}`. The KBS then
///    releases the rootfs KEK ONLY to the destination attesting at
///    `new_gen` and PERMANENTLY denies the source at the old generation
///    (`kbs_core::lifecycle::check_releasable`).
///
/// So even a forged / replayed `migrate-activate` cannot boot a second
/// LIVE copy: the guest cannot unlock its rootfs without the KEK, and
/// the KBS will not release it outside the fence. The dest miner writing
/// ciphertext to disk + starting a domain is inert without that release.
///
/// Boot artifacts (OVMF / kernel / initrd) are assumed pre-staged on the
/// dest (M3 wires the staging); a missing one fails closed with
/// `migration/dest-artifacts-missing`. Idempotent: an already-running
/// CVM is a success no-op and the disk download is skipped when the disk
/// is already present.
pub async fn handle_migrate_activate(
    lifecycle: Arc<CvmLifecycle>,
    downloader: Arc<dyn SnapshotDownloader>,
    pusher: Arc<dyn crate::vsock::ticket_push::TicketPusher>,
    migration: Arc<MigrationStore>,
    tasks: tokio_util::task::TaskTracker,
    order: MigrateActivateOrder,
) -> std::result::Result<String, OrderRejection> {
    // ASYNC like `handle_migrate_snapshot`: the restore is a multi-GB
    // download + boot + ticket push that far exceeds the order-relay whole-
    // request timeout (edge ~30s / vali dispatch ~45s). Running it inline
    // (as this handler used to) made the dispatch time out (502) while the
    // work kept running, and every retry hit the in-flight guard (409) —
    // vali read that as failure and its DestActivating step-timeout fired
    // before the sync restore finished, failing an otherwise-good migration.
    //
    // So: enter `Activating` synchronously (fast), spawn the restore on the
    // serve-loop TaskTracker (survives the ACK + a client disconnect, drained
    // at shutdown), and ACK immediately. vali polls the DEST's
    // `migration/{vm}/status` for the terminal `done`/`failed` — exactly the
    // proven §25 M1 snapshot coordination, mirrored on the dest side.
    let vm_id = order.vm_id.clone();
    let vm_id_str = vm_id.as_str().to_owned();
    if let Err(err) = migration.begin_activate(&vm_id) {
        return Err(reject_dispatch(&err, &vm_id_str));
    }
    tasks.spawn(async move {
        match super::migration::activate_dest(
            lifecycle.as_ref(),
            downloader.as_ref(),
            pusher.as_ref(),
            order,
        )
        .await
        {
            Ok(class) => {
                eprintln!(
                    "hippius-miner-agent: migrate-activate: vm={vm_id_str} dest restore ok ({class})"
                );
                let _ = migration.mark_activate_done(&vm_id);
            }
            Err(err) => {
                eprintln!(
                    "hippius-miner-agent: migrate-activate: vm={vm_id_str} dest restore failed: {err}"
                );
                migration.mark_activate_failed(&vm_id);
            }
        }
    });
    Ok("activate-accepted".to_string())
}

/// Parse the attested `hippius.disk_gb=<N>` token out of a kernel
/// cmdline, returning the DATA-disk size in GiB (or `0` if the token is
/// absent / unparseable — which disables the capacity fail-fast, exactly
/// as a `0` budget does). vali always appends this token (`#365`), so a
/// missing one means an old/hand-built cmdline, not an attack surface —
/// the launch path's own reservation remains the authoritative gate.
///
/// `pub(crate)` so the §25 dest-activation (`orders::types::into_launch_order`)
/// can size a migrated GOLDEN overlay from the SAME measured token rather than
/// the flavor-independent `luks_disk_size_gb` constant.
pub(crate) fn parse_disk_gb_token(cmdline: &str) -> u32 {
    cmdline
        .split_whitespace()
        .find_map(|tok| tok.strip_prefix("hippius.disk_gb="))
        .and_then(|v| v.parse::<u32>().ok())
        .unwrap_or(0)
}

/// Dispatch a `tenant-preflight` order. Fetches artifacts via S3
/// presigned URLs, verifies SHAs, stages under the canonical
/// staging dir, computes the SNP launch_digest. Returns a JSON
/// envelope vali parses for the digest.
pub async fn handle_tenant_preflight(
    lifecycle: &CvmLifecycle,
    order: TenantPreflightOrder,
) -> std::result::Result<String, OrderRejection> {
    let vm_id_str = order.vm_id.as_str().to_owned();
    // DATA-disk capacity fail-fast — BEFORE vali mints + KBS-registers.
    // The attested `hippius.disk_gb=` token in the cmdline is the same
    // size the launch will reserve; rejecting an over-budget disk here
    // (503 insufficient-resources) lets vali re-place onto another miner,
    // whereas the launch-time reservation lands after KBS-register and
    // can't be cleanly re-placed. The launch path still reserves under
    // the lock (the race-safe gate).
    let add_disk_gb = parse_disk_gb_token(order.cmdline.as_str());
    if let Err(err) = lifecycle.check_disk_budget(add_disk_gb) {
        return Err(reject_dispatch(&err, &vm_id_str));
    }
    // CPU + memory capacity fail-fast — SAME pre-register rationale as the
    // DATA-disk gate above. Without this, a CPU/RAM-constrained miner
    // passed preflight (only disk was gated) and rejected at LAUNCH, after
    // KBS-register, which vali can't cleanly re-place (the register 409s
    // `kbs-admin-conflict`). The preflight order carries the measured
    // `cpu_count` but not the RAM figure; vCPU counts are unique per
    // flavor, so recover `memory_mb` via `Flavor::from_vcpus`. An unknown
    // vCPU count (never emitted by vali; caught later by the launch-order
    // vCPU match) skips the RAM half but still gates CPU.
    let add_memory_mb = hippius_types::flavor::Flavor::from_vcpus(order.cpu_count)
        .map(|f| f.memory_mb())
        .unwrap_or(0);
    if let Err(err) = lifecycle.check_cpu_mem_budget(order.cpu_count, add_memory_mb) {
        return Err(reject_dispatch(&err, &vm_id_str));
    }
    // P9/#16 — a preflight for a vm_id whose domain is ALREADY UP may only
    // re-stage bytes that are byte-identical to what is on disk. Vali can
    // legitimately re-dispatch a preflight (a re-driven launch job, an
    // operator retry with a fresh order_id), and the staged artifacts are
    // the dm-verity base + kernel + initrd the running guest boots from;
    // rewriting them under it is a data-loss event, not a retry.
    //
    // `Unknown` (libvirt unreachable) is treated as LIVE — the same
    // fail-closed reading §24's reclaim uses. It costs nothing: a launch
    // could not proceed on that host anyway, and vali re-places.
    let policy = match lifecycle.tenant_domain_liveness(&order.vm_id).await {
        crate::lifecycle::DomainLiveness::Down => crate::lifecycle::preflight::StagePolicy::Replace,
        crate::lifecycle::DomainLiveness::Live | crate::lifecycle::DomainLiveness::Unknown => {
            crate::lifecycle::preflight::StagePolicy::PinnedByLiveVm
        }
    };
    match crate::lifecycle::preflight::run(order, policy).await {
        Ok(json) => Ok(json),
        Err(err) => Err(reject_dispatch(&err, &vm_id_str)),
    }
}

/// What [`IdempotencyStore::begin`] decided about an `order_id`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BeginOutcome {
    /// First sight of this `order_id` (or a retry of one that failed)
    /// — the caller owns it and must dispatch, then [`IdempotencyStore::finish`].
    Claimed,
    /// This `order_id` already completed successfully — the caller
    /// must NOT dispatch again; return a no-op success.
    AlreadyOk,
    /// This `order_id` is being processed by another in-flight
    /// request right now — the caller must reject with a conflict.
    InFlight,
}

/// One tracked `order_id`'s state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum IdemEntry {
    /// A request claimed this id and is dispatching it.
    InFlight,
    /// Dispatch finished — `true` = success, `false` = failure
    /// (failure is left retryable: a fresh claim overwrites it).
    Done(bool),
}

/// State behind the idempotency lock.
struct IdemState {
    /// `order_id → state`.
    entries: HashMap<String, IdemEntry>,
    /// Insertion order, for FIFO eviction. 1:1 with `entries` — an id
    /// is pushed once, on first claim, and removed only by eviction.
    fifo: VecDeque<String>,
}

/// Bounded, FIFO-evicted `order_id` deduplication store.
///
/// Guarantees the §K invariant "same `order_id` 2× = same outcome,
/// second one a no-op success" while keeping memory bounded — an
/// unbounded map would be a trivial OOM for any mesh peer that can
/// reach the orders listener.
pub struct IdempotencyStore {
    capacity: usize,
    state: Mutex<IdemState>,
}

impl IdempotencyStore {
    /// A store with the default capacity ([`DEFAULT_IDEM_CAPACITY`]).
    pub fn new() -> Self {
        Self::with_capacity(DEFAULT_IDEM_CAPACITY)
    }

    /// A store bounded at `capacity` distinct `order_id`s — tests use
    /// a tiny capacity to exercise eviction.
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            capacity: capacity.max(1),
            state: Mutex::new(IdemState {
                entries: HashMap::new(),
                fifo: VecDeque::new(),
            }),
        }
    }

    /// Claim `order_id` for dispatch, or report it already
    /// completed / in-flight. A poisoned lock fails closed.
    pub fn begin(&self, order_id: &str) -> crate::error::Result<BeginOutcome> {
        let mut state = self.lock()?;
        match state.entries.get(order_id).copied() {
            Some(IdemEntry::Done(true)) => Ok(BeginOutcome::AlreadyOk),
            Some(IdemEntry::InFlight) => Ok(BeginOutcome::InFlight),
            // A previously-failed order is retryable — re-claim it
            // (the map slot + FIFO position are reused, no new entry).
            Some(IdemEntry::Done(false)) => {
                state
                    .entries
                    .insert(order_id.to_string(), IdemEntry::InFlight);
                Ok(BeginOutcome::Claimed)
            }
            None => {
                // Evict the oldest tracked id if at capacity.
                if state.entries.len() >= self.capacity {
                    if let Some(old) = state.fifo.pop_front() {
                        state.entries.remove(&old);
                    }
                }
                state
                    .entries
                    .insert(order_id.to_string(), IdemEntry::InFlight);
                state.fifo.push_back(order_id.to_string());
                Ok(BeginOutcome::Claimed)
            }
        }
    }

    /// Record the outcome of a [`BeginOutcome::Claimed`] dispatch. A
    /// success becomes a cached no-op for any replay; a failure stays
    /// retryable. A poisoned lock fails closed.
    pub fn finish(&self, order_id: &str, success: bool) -> crate::error::Result<()> {
        let mut state = self.lock()?;
        // Only update an entry that still exists — an id evicted while
        // its dispatch ran is simply not re-inserted.
        if state.entries.contains_key(order_id) {
            state
                .entries
                .insert(order_id.to_string(), IdemEntry::Done(success));
        }
        Ok(())
    }

    /// Lock the state, mapping a poisoned lock to a fail-closed error.
    fn lock(&self) -> crate::error::Result<std::sync::MutexGuard<'_, IdemState>> {
        self.state.lock().map_err(|_| MinerAgentError::LockPoisoned)
    }
}

impl Default for IdempotencyStore {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_disk_gb_token_extracts_the_attested_value() {
        assert_eq!(parse_disk_gb_token("ro hippius.disk_gb=64 quiet"), 64);
        assert_eq!(parse_disk_gb_token("hippius.disk_gb=8"), 8);
    }

    #[test]
    fn parse_disk_gb_token_absent_or_malformed_is_zero() {
        // Absent → 0 (disables the fail-fast; the launch reservation
        // remains the authoritative gate).
        assert_eq!(parse_disk_gb_token("ro quiet console=ttyS0"), 0);
        assert_eq!(parse_disk_gb_token("hippius.disk_gb=notanum"), 0);
        assert_eq!(parse_disk_gb_token(""), 0);
        // A different `hippius.*` token must not be mistaken for it.
        assert_eq!(parse_disk_gb_token("hippius.luks_header_sha256=ab"), 0);
    }

    #[test]
    fn first_sight_is_claimed() {
        let store = IdempotencyStore::new();
        assert_eq!(store.begin("ord-1").unwrap(), BeginOutcome::Claimed);
    }

    #[test]
    fn a_completed_success_replays_as_already_ok() {
        let store = IdempotencyStore::new();
        assert_eq!(store.begin("ord-1").unwrap(), BeginOutcome::Claimed);
        store.finish("ord-1", true).unwrap();
        assert_eq!(store.begin("ord-1").unwrap(), BeginOutcome::AlreadyOk);
        // ... and stays AlreadyOk on every further replay.
        assert_eq!(store.begin("ord-1").unwrap(), BeginOutcome::AlreadyOk);
    }

    #[test]
    fn an_in_flight_order_conflicts() {
        let store = IdempotencyStore::new();
        assert_eq!(store.begin("ord-1").unwrap(), BeginOutcome::Claimed);
        // Claimed but not finished — a second arrival is in-flight.
        assert_eq!(store.begin("ord-1").unwrap(), BeginOutcome::InFlight);
    }

    #[test]
    fn a_failed_order_is_retryable() {
        let store = IdempotencyStore::new();
        assert_eq!(store.begin("ord-1").unwrap(), BeginOutcome::Claimed);
        store.finish("ord-1", false).unwrap();
        // A failed order can be re-claimed and re-dispatched.
        assert_eq!(store.begin("ord-1").unwrap(), BeginOutcome::Claimed);
    }

    #[test]
    fn eviction_keeps_the_store_bounded() {
        let store = IdempotencyStore::with_capacity(2);
        for id in ["a", "b", "c"] {
            assert_eq!(store.begin(id).unwrap(), BeginOutcome::Claimed);
            store.finish(id, true).unwrap();
        }
        // The two most-recent ids are still cached. Check them first:
        // a cache HIT (`AlreadyOk`) does not mutate the store, so the
        // assertions do not perturb each other.
        assert_eq!(store.begin("c").unwrap(), BeginOutcome::AlreadyOk);
        assert_eq!(store.begin("b").unwrap(), BeginOutcome::AlreadyOk);
        // "a" — the oldest — was evicted when "c" was claimed, so it is
        // a fresh claim again. (This DOES mutate, so it is checked last.)
        assert_eq!(store.begin("a").unwrap(), BeginOutcome::Claimed);
    }

    #[test]
    fn distinct_ids_are_independent() {
        let store = IdempotencyStore::new();
        store.begin("ord-1").unwrap();
        assert_eq!(store.begin("ord-2").unwrap(), BeginOutcome::Claimed);
    }

    /// Capture the detail-log line `reject_dispatch_with_log` would
    /// emit, or `None` if the variant's arm did not call the sink.
    fn capture_detail(err: &MinerAgentError, vm_id: &str) -> (OrderRejection, Option<String>) {
        let mut captured: Option<String> = None;
        let rej = reject_dispatch_with_log(err, vm_id, |line| {
            captured = Some(line);
        });
        (rej, captured)
    }

    /// Every variant that falls through `reject_dispatch`'s catch-all
    /// keeps the public class `dispatch-failed` (no wire-side breaking
    /// change) AND surfaces its static `Display` on the detail log line.
    /// `LockPoisoned`, `LibvirtDriver(_)`, `LaunchFailed(_)`, … all
    /// previously collapsed into an undifferentiated `dispatch-failed`
    /// outcome line — this is the regression check that the underlying
    /// classifier now reaches the operator's log too.
    #[test]
    fn catch_all_variants_log_their_static_display() {
        let cases: &[(MinerAgentError, &str)] = &[
            (MinerAgentError::LockPoisoned, "lock-poisoned"),
            (
                MinerAgentError::LibvirtDriver("virsh-spawn"),
                "libvirt-driver/virsh-spawn",
            ),
            (
                MinerAgentError::LaunchFailed("domain-error"),
                "cvm-launch-failed/domain-error",
            ),
            (MinerAgentError::CvmBusy, "cvm-busy"),
            (
                MinerAgentError::Destroy("disk-remove"),
                "cvm-destroy/disk-remove",
            ),
        ];
        for (err, expected_display) in cases {
            let (rej, line) = capture_detail(err, "tenant-x");
            // (1) wire class is unchanged — the regression check.
            assert_eq!(
                rej.class, "dispatch-failed",
                "{expected_display}: public class should stay dispatch-failed",
            );
            assert_eq!(rej.status, StatusCode::INTERNAL_SERVER_ERROR);
            // (2) the detail line fired and equals exactly the
            // expected static classifier — no libvirt path, no raw
            // cmdline byte, no tenant secret has crept in. The §H/§20
            // discipline holds by construction (every
            // `MinerAgentError` variant's Display is a `&'static str`),
            // but the exact-eq surfaces a future variant that
            // accidentally embedded a `String` as extra trailing
            // content here.
            let line = line.unwrap_or_else(|| {
                panic!("{expected_display}: catch-all should emit a detail log line")
            });
            assert_eq!(
                line,
                format!(
                    "hippius-miner-agent: orders: dispatch-failed-detail vm=tenant-x class={expected_display}"
                ),
            );
        }
    }

    /// The already-classified variants are NOT double-logged: their
    /// `class` already names the precise failure, so an extra
    /// `dispatch-failed-detail` line would only pollute the channel.
    #[test]
    fn classified_variants_do_not_emit_detail_log() {
        let cases: &[(MinerAgentError, &str)] = &[
            (
                MinerAgentError::InsufficientResources,
                "insufficient-resources",
            ),
            (
                MinerAgentError::VsockCid("exhausted"),
                "vsock-cid-exhausted",
            ),
            (MinerAgentError::LaunchInput("vm-id"), "launch-input"),
            (
                MinerAgentError::LaunchDigest("feature-disabled"),
                "launch-input",
            ),
            (MinerAgentError::NotYetWired, "not-yet-wired"),
        ];
        for (err, expected_class) in cases {
            let (rej, line) = capture_detail(err, "tenant-x");
            assert_eq!(rej.class, *expected_class);
            assert!(
                line.is_none(),
                "{expected_class}: classified variant should not emit a detail log (got `{}`)",
                line.unwrap_or_default(),
            );
        }
    }

    /// `TicketDelivery` is a dedicated arm AND emits a detail-log line
    /// (codex r2 P3) — the public class `ticket-delivery-failed`
    /// flattens five sub-classes; an operator needs the sub-class to
    /// distinguish a guest-listener timeout from a bad payload.
    #[test]
    fn ticket_delivery_emits_detail_log_with_subclass() {
        let cases: &[(MinerAgentError, &str)] = &[
            (
                MinerAgentError::TicketDelivery("empty"),
                "ticket-delivery/empty",
            ),
            (
                MinerAgentError::TicketDelivery("connect-timeout"),
                "ticket-delivery/connect-timeout",
            ),
            (
                MinerAgentError::TicketDelivery("write-failed"),
                "ticket-delivery/write-failed",
            ),
            (
                MinerAgentError::TicketDelivery("no-cid"),
                "ticket-delivery/no-cid",
            ),
            (
                MinerAgentError::TicketDelivery("oversize"),
                "ticket-delivery/oversize",
            ),
        ];
        for (err, expected_display) in cases {
            let (rej, line) = capture_detail(err, "tenant-x");
            // Public class is the flattened classifier (stable wire
            // contract); the sub-class lives in the detail log.
            assert_eq!(rej.class, "ticket-delivery-failed");
            let line = line.unwrap_or_else(|| {
                panic!("{expected_display}: ticket-delivery must emit a detail log")
            });
            assert_eq!(
                line,
                format!(
                    "hippius-miner-agent: orders: ticket-delivery-failed-detail vm=tenant-x class={expected_display}"
                ),
            );
        }
    }
}
