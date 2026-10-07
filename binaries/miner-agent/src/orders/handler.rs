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
    MigrateSnapshotOrder, NetPolicyOrder, StopOrder, TenantPreflightOrder,
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
        // The host's tenant DISK is full — the declared budget, or the
        // measured free space the per-VM disk create gates on. Its own
        // class (and 507, like the restore path's `insufficient-space`) so
        // vali reads it as a capacity event and re-places, never as the
        // generic `dispatch-failed` that is evidence of a SEV start fault.
        MinerAgentError::InsufficientDisk
        | MinerAgentError::DataDisk("insufficient-space")
        | MinerAgentError::OverlayDisk("insufficient-space") => {
            log_detail(format!(
                "hippius-miner-agent: orders: insufficient-disk-detail vm={vm_id} class={err}"
            ));
            OrderRejection::new(StatusCode::INSUFFICIENT_STORAGE, "insufficient-disk")
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
        // A relaunch found none of the VM's disks to reuse — this host
        // does not hold the VM. Its own class (vali must stop relaunching
        // here and escalate, not retry), and a detail line naming WHICH
        // disk, because that is what an operator checks first.
        MinerAgentError::RelaunchDisksMissing(_) => {
            log_detail(format!(
                "hippius-miner-agent: orders: relaunch-disks-missing-detail vm={vm_id} class={err}"
            ));
            OrderRejection::new(StatusCode::PRECONDITION_FAILED, "relaunch-disks-missing")
        }
        // Could not tell — retryable (503), and a class vali does NOT
        // latch on: nothing is known to be missing.
        MinerAgentError::RelaunchDisksUnreadable(_) => {
            log_detail(format!(
                "hippius-miner-agent: orders: relaunch-disks-unreadable-detail vm={vm_id} class={err}"
            ));
            OrderRejection::new(StatusCode::SERVICE_UNAVAILABLE, "relaunch-disks-unreadable")
        }
        // The L1-minted OrderTicket could not be pushed to the guest
        // over vsock — a launch-blocking condition (the §21 boot
        // pipeline reads the ticket on the very first stage) but a
        // distinct class from libvirt / lock-poisoned failures, so the
        // operator can wire a targeted alert. The dedicated arm ALSO
        // emits a detail-log line (review r2 P3) — the public class
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
        // `net-policy` refusals. The replay classes are vali's to act on
        // (409: send a higher revision); a bad shape or a store fault also
        // logs its sub-class.
        MinerAgentError::NetPolicyStaleRevision => {
            OrderRejection::new(StatusCode::CONFLICT, "net-policy-stale-revision")
        }
        MinerAgentError::NetPolicyRevisionConflict => {
            OrderRejection::new(StatusCode::CONFLICT, "net-policy-revision-conflict")
        }
        MinerAgentError::NetPolicyExpired => {
            OrderRejection::new(StatusCode::UNPROCESSABLE_ENTITY, "net-policy-expired")
        }
        MinerAgentError::NetPolicyInvalid(_) => {
            log_detail(format!(
                "hippius-miner-agent: orders: net-policy-invalid-detail vm={vm_id} class={err}"
            ));
            OrderRejection::new(StatusCode::UNPROCESSABLE_ENTITY, "net-policy-invalid")
        }
        MinerAgentError::NetPolicyStore(_) => {
            log_detail(format!(
                "hippius-miner-agent: orders: net-policy-store-detail vm={vm_id} class={err}"
            ));
            OrderRejection::new(StatusCode::INTERNAL_SERVER_ERROR, "net-policy-store")
        }
        MinerAgentError::NetPolicyUnsupported(_) => {
            log_detail(format!(
                "hippius-miner-agent: orders: net-policy-unsupported-detail vm={vm_id} class={err}"
            ));
            OrderRejection::new(StatusCode::UNPROCESSABLE_ENTITY, "net-policy-unsupported")
        }
        MinerAgentError::NetPolicyApply(_) => {
            log_detail(format!(
                "hippius-miner-agent: orders: net-policy-apply-detail vm={vm_id} class={err}"
            ));
            OrderRejection::new(StatusCode::INTERNAL_SERVER_ERROR, "net-policy-apply")
        }
        // Launch / migrate-in on a host whose edge-mode rules are not
        // loaded: retryable elsewhere, like a capacity refusal.
        MinerAgentError::NetPolicyNotLoaded => {
            OrderRejection::new(StatusCode::SERVICE_UNAVAILABLE, "net-policy-not-loaded")
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

/// Dispatch a `net-policy` order: persist it under the replay rules,
/// load its rules, and only then answer `applied:<revision>:<content
/// sha256 hex>` ([`crate::netpolicy::apply`]).
pub async fn handle_net_policy(
    enforcer: &crate::netpolicy::NetPolicyEnforcer,
    now: u64,
    order: NetPolicyOrder,
) -> Result<String, OrderRejection> {
    enforcer
        .accept(order, now)
        .await
        .map_err(|err| reject_dispatch(&err, "host"))
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
/// (review r2 P2).
///
/// `AlreadyLaunched` does NOT prove the guest got its ticket. A launch
/// whose own push failed (`ticket-delivery-failed`) leaves the domain
/// running on purpose: the reboot-watcher's re-push keeps trying for its
/// window after `Started`, which is how a slow boot still gets its ticket
/// — so a same-miner retry inside that window is answered
/// `already-launched` — the pre-existing behaviour. Nothing here, and
/// today nothing in vali either, catches a guest that never gets its
/// ticket (it never signals, so vali reads it `unknown`, not `wedged`):
/// that gap is tracked on the vali side. The §25 destination, where the
/// answer becomes vali's `done`, settles the re-push outcome itself
/// (`migration::launch_dest`).
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

    // Guarded: this push can spin in its connect loop for minutes, and a
    // stop landing meanwhile frees `cid` for the next launch — the ticket
    // must never reach whoever inherits it.
    let still_owner = || lifecycle.ticket_push_current(&vm_id, cid, cose_ticket.as_ref());
    if let Err(err) = pusher
        .push_guarded(
            cid,
            hippius_types::ticket_vsock::PORT,
            cose_ticket.as_ref(),
            &still_owner,
        )
        .await
    {
        // The reboot-watcher's re-push races this one for the guest's
        // one-shot listener; if it won, the guest has its ticket.
        if lifecycle.ticket_delivered(&vm_id) {
            return Ok("launched".to_string());
        }
        lifecycle.note_ticket_push_failed(&vm_id, cid, cose_ticket.as_ref());
        return Err(reject_dispatch(&err, &vm_id_str));
    }
    lifecycle.note_ticket_delivered(&vm_id, cid, cose_ticket.as_ref());

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
    restore: Option<&crate::backup::staged::RestoreManager>,
    order: DestroyOrder,
) -> std::result::Result<String, OrderRejection> {
    match lifecycle.destroy(&order.vm_id, restore).await {
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
    let disk_part_urls = order.disk_part_urls.clone();
    let part_size = order.part_size;
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
        let volume = if disk_part_urls.is_empty() {
            uploader.upload(&disk_path, &put_url).await.map(|()| None)
        } else {
            uploader
                .upload_parts(&disk_path, part_size, &disk_part_urls)
                .await
                .map(Some)
        };
        let receipt = match volume {
            Ok(receipt) => receipt,
            Err(err) => {
                eprintln!(
                    "hippius-miner-agent: migrate-snapshot: vm={vm_id_str} volume upload \
                     failed: {err}"
                );
                migration.mark_snapshot_failed(&vm_id);
                return;
            }
        };
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
                    if let Err(err) = uploader.upload(&state_disk_path, &state_put_url).await {
                        eprintln!(
                            "hippius-miner-agent: migrate-snapshot: vm={vm_id_str} state disk \
                             upload failed: {err}"
                        );
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
        let _ = match receipt {
            Some(receipt) => migration.mark_multipart_snapshot_done(&vm_id, receipt),
            None => migration.mark_snapshot_done(&vm_id),
        };
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
    restorer: Option<Arc<dyn crate::backup::restore::ChainRestorer>>,
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
    // Every activation enters `Activating` under the restore lock: an
    // abort or a reclaim (which renames or deletes this VM's disks) then
    // sees either no activation or the activation, never both at once.
    // A staged restore's cheap preconditions also answer on the order;
    // the background swap re-checks all of them under the same lock.
    if let Err(err) = lifecycle.check_net_policy_gate() {
        return Err(reject_dispatch(&err, &vm_id_str));
    }
    let _restore_lock = crate::backup::staged::restore_lock().await;
    if let Err(class) = check_staged_activate(&lifecycle, &order).await {
        let status = match class {
            "restore-not-staged" | "restore-vm-live" => StatusCode::CONFLICT,
            _ => StatusCode::UNPROCESSABLE_ENTITY,
        };
        return Err(OrderRejection::new(status, class));
    }
    match migration.begin_activate(&vm_id) {
        Ok(true) => {}
        // The first activation is still running — its outcome is what
        // vali's status poll will see.
        Ok(false) => return Ok("activate-in-progress".to_string()),
        Err(err) => return Err(reject_dispatch(&err, &vm_id_str)),
    }
    tasks.spawn(async move {
        match super::migration::activate_dest_with_chain(
            lifecycle.as_ref(),
            downloader.as_ref(),
            restorer.as_deref(),
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
                migration.mark_activate_failed(&vm_id, &err);
            }
        }
    });
    Ok("activate-accepted".to_string())
}

/// The synchronous half of a staged restore's `migrate-activate`: field
/// consistency, and — unless this restore is already swapped in — a
/// `staged` record for the id and a domain that is not running.
async fn check_staged_activate(
    lifecycle: &CvmLifecycle,
    order: &MigrateActivateOrder,
) -> std::result::Result<(), &'static str> {
    order.check_staged_restore()?;
    if order.staged_restore_id.is_empty() {
        return Ok(());
    }
    let status = crate::backup::staged::RestoreManager::peek(lifecycle, &order.vm_id).await;
    let rid = order.staged_restore_id.as_str();
    let swapped = status
        .as_ref()
        .is_some_and(|s| s.restore_id == rid && s.swapped);
    if swapped {
        return Ok(());
    }
    if !status.as_ref().is_some_and(|s| {
        s.restore_id == rid && s.state == crate::backup::staged::RestoreState::Staged
    }) {
        return Err("restore-not-staged");
    }
    if lifecycle.tenant_domain_liveness(&order.vm_id).await
        != crate::lifecycle::DomainLiveness::Down
    {
        return Err("restore-vm-live");
    }
    Ok(())
}

/// Staged restore — `stage` validates and registers synchronously (so
/// vali sees `restore-busy` / a bad chain / no room on the order
/// response), then runs on the serve loop's TaskTracker and ACKs;
/// `abort` and `reclaim` run inline. See [`crate::backup::staged`].
pub async fn handle_restore(
    lifecycle: Arc<CvmLifecycle>,
    restore: Arc<crate::backup::staged::RestoreManager>,
    migration: Arc<MigrationStore>,
    tasks: tokio_util::task::TaskTracker,
    order: crate::orders::types::RestoreOrder,
) -> std::result::Result<String, OrderRejection> {
    use crate::backup::staged::{RestoreOp, StageRequest, StageStart};
    order.validate().map_err(|e| restore_rejection(&e))?;
    let vm_id = order.vm_id.clone();
    match order.op {
        RestoreOp::Stage => {
            let chain = order.chain.ok_or(OrderRejection::new(
                StatusCode::UNPROCESSABLE_ENTITY,
                "restore-chain-missing",
            ))?;
            let req = StageRequest {
                vm_id,
                restore_id: order.restore_id,
                chain,
                disk_bytes: order.disk_bytes,
                streams: crate::backup::transfer::clamp_streams(order.streams),
            };
            match restore.begin_stage(&lifecycle, req).await {
                Ok(StageStart::Started(job)) => {
                    tasks.spawn(async move { restore.run_stage(job).await });
                    Ok("restore-staging".to_string())
                }
                Ok(StageStart::Staging) => Ok("restore-staging".to_string()),
                Ok(StageStart::Staged) => Ok("restore-staged".to_string()),
                Err(e) => Err(restore_rejection(&e)),
            }
        }
        RestoreOp::Abort => restore
            .abort(&lifecycle, &migration, &vm_id, &order.restore_id)
            .await
            .map(|()| "restore-aborted".to_string())
            .map_err(|e| restore_rejection(&e)),
        RestoreOp::Reclaim => restore
            .reclaim(&lifecycle, &migration, &vm_id, &order.restore_id)
            .await
            .map(|()| "restore-reclaimed".to_string())
            .map_err(|e| restore_rejection(&e)),
    }
}

/// Map a restore error to its order response: a state conflict is `409`,
/// no room `507`, a stop that did not take `503`, any other static class
/// `422` (the order itself is wrong), everything else `500`.
fn restore_rejection(err: &MinerAgentError) -> OrderRejection {
    match err {
        MinerAgentError::Backup(
            c @ ("restore-busy"
            | "restore-finished"
            | "restore-vm-live"
            | "restore-reclaim-refused"
            | "restore-activating"),
        ) => OrderRejection::new(StatusCode::CONFLICT, c),
        MinerAgentError::Backup(c @ "restore-host-busy") => {
            OrderRejection::new(StatusCode::SERVICE_UNAVAILABLE, c)
        }
        MinerAgentError::Backup(c @ "insufficient-space") => {
            OrderRejection::new(StatusCode::INSUFFICIENT_STORAGE, c)
        }
        MinerAgentError::Backup(c @ ("restore-stop-failed" | "restore-cancel-timeout")) => {
            OrderRejection::new(StatusCode::SERVICE_UNAVAILABLE, c)
        }
        MinerAgentError::Backup(
            c @ ("restore-record" | "restore-remove" | "restore-stat" | "restore-dir"
            | "restore-abort-io"),
        ) => OrderRejection::new(StatusCode::INTERNAL_SERVER_ERROR, c),
        MinerAgentError::Backup(c) => OrderRejection::new(StatusCode::UNPROCESSABLE_ENTITY, c),
        _ => OrderRejection::new(StatusCode::INTERNAL_SERVER_ERROR, "restore-internal"),
    }
}

/// Live backup — validate + register the run synchronously (so vali sees
/// `backup-in-flight` / a bad request on the order response), then run it
/// on the serve loop's TaskTracker and ACK. A repeat of the same `run_id`
/// is `backup-already-accepted` and starts nothing.
pub fn handle_backup(
    lifecycle: Arc<CvmLifecycle>,
    backup: Arc<crate::backup::BackupManager>,
    tasks: tokio_util::task::TaskTracker,
    order: crate::orders::types::BackupOrder,
) -> std::result::Result<String, OrderRejection> {
    let req = order.into_request();
    match backup.begin(&req) {
        Ok(true) => {}
        Ok(false) => return Ok("backup-already-accepted".to_string()),
        Err(MinerAgentError::Backup("backup-in-flight")) => {
            return Err(OrderRejection::new(
                StatusCode::CONFLICT,
                "backup-in-flight",
            ));
        }
        Err(MinerAgentError::Backup(_)) => {
            return Err(OrderRejection::new(
                StatusCode::UNPROCESSABLE_ENTITY,
                "backup-invalid",
            ));
        }
        Err(_) => {
            return Err(OrderRejection::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "backup-internal",
            ));
        }
    }
    tasks.spawn(async move {
        let vm = req.vm_id.clone();
        let run_id = req.run_id.clone();
        backup.run(lifecycle.as_ref(), req).await;
        if let Some(st) = backup.status(&vm) {
            eprintln!(
                "hippius-miner-agent: backup: vm={} run={run_id:?} status={:?} error={}",
                vm.as_str(),
                st.status,
                st.error.unwrap_or("-"),
            );
        }
    });
    Ok("backup-started".to_string())
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
    if let Err(err) = lifecycle.check_net_policy_gate() {
        return Err(reject_dispatch(&err, &vm_id_str));
    }
    // DATA-disk capacity fail-fast — BEFORE vali mints + KBS-registers.
    // The attested `hippius.disk_gb=` token in the cmdline is the same
    // size the launch will reserve; rejecting an over-budget disk here
    // (507 insufficient-disk) lets vali re-place onto another miner,
    // whereas the launch-time reservation lands after KBS-register and
    // can't be cleanly re-placed. The launch path still reserves under
    // the lock (the race-safe gate).
    let add_disk_gb = parse_disk_gb_token(order.cmdline.as_str());
    if let Err(err) = lifecycle.check_disk_budget(add_disk_gb) {
        return Err(reject_dispatch(&err, &vm_id_str));
    }
    // …and against the MEASURED free space (net of every existing disk's
    // unwritten sparse tail), so a host whose filesystem can't hold the
    // disk is refused here too — the declared budget may be 0 (disabled)
    // or simply wrong. Both answer 507 `insufficient-disk`.
    if let Err(err) = lifecycle.check_disk_space(&order.vm_id, add_disk_gb) {
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
        crate::lifecycle::DomainLiveness::Down => {
            // SEV-ES ASID fail-fast — same pre-register rationale as the
            // cpu/mem gate: an exhausted pool fails the launch inside
            // `sev_common_kvm_init`, after KBS-register. Only a DOWN domain
            // needs a new ASID (a live one already holds its own), and the
            // pass RESERVES it until the launch ends, so concurrent
            // preflights at the edge of the pool cannot all pass. Keeps one
            // ASID for the host-attestor / a migration destination; an
            // unreadable pool never gates.
            if let Err(err) =
                lifecycle.reserve_asid(&order.vm_id, crate::lifecycle::DomainProfile::Tenant)
            {
                return Err(reject_dispatch(&err, &vm_id_str));
            }
            crate::lifecycle::preflight::StagePolicy::Replace
        }
        crate::lifecycle::DomainLiveness::Live | crate::lifecycle::DomainLiveness::Unknown => {
            crate::lifecycle::preflight::StagePolicy::PinnedByLiveVm
        }
    };
    match crate::lifecycle::preflight::run(order, policy).await {
        Ok(json) => Ok(json),
        Err(err) => Err(reject_dispatch(&err, &vm_id_str)),
    }
}

/// Longest success class a replay can echo. Stop/launch/destroy classes are
/// a few bytes; a preflight's JSON is a few hundred. Anything longer is not
/// kept (bounded memory: [`DEFAULT_IDEM_CAPACITY`] entries) and replays as
/// the generic `idempotent-replay`.
pub const MAX_REPLAY_CLASS_LEN: usize = 1024;

/// What [`IdempotencyStore::begin`] decided about an `order_id`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BeginOutcome {
    /// First sight of this `order_id` (or a retry of one that failed)
    /// — the caller owns it and must dispatch, then [`IdempotencyStore::finish`].
    Claimed,
    /// This `order_id` already completed successfully — the caller
    /// must NOT dispatch again; return a no-op success, echoing the
    /// original outcome class when it was kept. A replayed `stop` must
    /// still say whether it `stopped` a guest or found it `not-running`:
    /// vali's §24 counts only the former as its stop.
    AlreadyOk(Option<String>),
    /// This `order_id` is being processed by another in-flight
    /// request right now — the caller must reject with a conflict.
    InFlight,
}

/// One tracked `order_id`'s state.
#[derive(Debug, Clone, PartialEq, Eq)]
enum IdemEntry {
    /// A request claimed this id and is dispatching it.
    InFlight,
    /// Dispatch succeeded, with its outcome class when short enough to keep.
    Ok(Option<String>),
    /// Dispatch failed — left retryable: a fresh claim overwrites it.
    Failed,
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
        match state.entries.get(order_id).cloned() {
            Some(IdemEntry::Ok(class)) => Ok(BeginOutcome::AlreadyOk(class)),
            Some(IdemEntry::InFlight) => Ok(BeginOutcome::InFlight),
            // A previously-failed order is retryable — re-claim it
            // (the map slot + FIFO position are reused, no new entry).
            Some(IdemEntry::Failed) => {
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

    /// Record the outcome of a [`BeginOutcome::Claimed`] dispatch:
    /// `Some(class)` for a success — a cached no-op for any replay, which
    /// echoes `class` — or `None` for a failure, which stays retryable. A
    /// poisoned lock fails closed.
    pub fn finish(&self, order_id: &str, success: Option<&str>) -> crate::error::Result<()> {
        let mut state = self.lock()?;
        // Only update an entry that still exists — an id evicted while
        // its dispatch ran is simply not re-inserted.
        if state.entries.contains_key(order_id) {
            let entry = match success {
                Some(class) => {
                    IdemEntry::Ok((class.len() <= MAX_REPLAY_CLASS_LEN).then(|| class.to_string()))
                }
                None => IdemEntry::Failed,
            };
            state.entries.insert(order_id.to_string(), entry);
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

    /// A pusher whose guest never takes the ticket.
    struct UnreachableGuestPusher;
    #[async_trait::async_trait]
    impl crate::vsock::ticket_push::TicketPusher for UnreachableGuestPusher {
        async fn push(&self, _cid: u32, _port: u32, _cose: &[u8]) -> crate::error::Result<()> {
            Err(MinerAgentError::TicketDelivery("connect-timeout"))
        }
    }

    fn medium_ticket() -> Vec<u8> {
        use ciborium::value::Value;
        use coset::{iana, CborSerializable, CoseSign1Builder, HeaderBuilder};
        let payload = Value::Map(vec![
            (Value::Text("v".into()), Value::Integer(2.into())),
            (Value::Text("flavor".into()), Value::Text("medium".into())),
        ]);
        let mut payload_buf = Vec::new();
        ciborium::ser::into_writer(&payload, &mut payload_buf).unwrap();
        CoseSign1Builder::new()
            .protected(
                HeaderBuilder::new()
                    .algorithm(iana::Algorithm::EdDSA)
                    .build(),
            )
            .payload(payload_buf)
            .create_signature(b"", |_| vec![0u8; 64])
            .build()
            .to_vec()
            .unwrap()
    }

    fn lifecycle() -> CvmLifecycle {
        use crate::lifecycle::{MockLaunchDigest, MockLibvirtDriver};
        crate::snp_config::install_for_tests(crate::snp_config::SnpCpuConfig {
            cbitpos: 51,
            reduced_phys_bits: 1,
        });
        CvmLifecycle::new(
            Arc::new(MockLibvirtDriver::new()),
            Arc::new(MockLaunchDigest::fixed([0u8; 48])),
            crate::HostResources {
                total_cpus: 16,
                total_memory_mb: 65536,
                total_disk_gb: 0,
            },
        )
        .skip_state_disk_provision_for_tests()
    }

    fn preflight_order(vm: &str) -> TenantPreflightOrder {
        let art = |n: &str| super::super::types::PreflightArtifact {
            url: format!("https://s3.invalid/{n}"),
            sha256_hex: "0".repeat(64),
        };
        TenantPreflightOrder {
            vm_id: crate::VmId::new(vm).unwrap(),
            ovmf_path: "/var/lib/hippius-miner/ovmf.fd".into(),
            luks_disk: art("disk"),
            kernel: art("vmlinuz"),
            initrd: art("initrd"),
            rootfs_hash: None,
            cmdline: "quiet".to_string(),
            cpu_count: 1,
        }
    }

    #[tokio::test]
    async fn preflight_refuses_a_tenant_when_the_asid_pool_is_full() {
        // capacity 99, used 98 ⇒ one more would eat the attestor reserve.
        let full = crate::sev_asid::AsidUsage {
            capacity: 99,
            used: 98,
        };
        let lc = lifecycle().with_asid_source(Arc::new(crate::sev_asid::FixedAsidSource(full)));
        let Err(rej) = handle_tenant_preflight(&lc, preflight_order("vm-asid-full")).await else {
            panic!("a full ASID pool must refuse the preflight");
        };
        assert_eq!(rej.class, "insufficient-resources");
    }

    #[tokio::test]
    async fn preflight_refuses_a_disk_the_filesystem_cannot_hold() {
        // No declared budget (0 = off): the MEASURED gate alone refuses a
        // disk larger than the data root's filesystem, with the typed class.
        let tmp = tempfile::tempdir().unwrap();
        let lc = lifecycle().with_state_disk_root(tmp.path().to_path_buf());
        let mut order = preflight_order("vm-disk-full");
        order.cmdline = format!("quiet hippius.disk_gb={}", u32::MAX);
        let Err(rej) = handle_tenant_preflight(&lc, order).await else {
            panic!("an unholdable disk must refuse the preflight");
        };
        assert_eq!(rej.class, "insufficient-disk");
        assert_eq!(rej.status, StatusCode::INSUFFICIENT_STORAGE);
    }

    #[tokio::test]
    async fn preflight_over_the_declared_disk_budget_is_insufficient_disk() {
        let tmp = tempfile::tempdir().unwrap();
        let lc = CvmLifecycle::new(
            Arc::new(crate::lifecycle::MockLibvirtDriver::new()),
            Arc::new(crate::lifecycle::MockLaunchDigest::fixed([0u8; 48])),
            crate::HostResources {
                total_cpus: 16,
                total_memory_mb: 65536,
                total_disk_gb: 1,
            },
        )
        .with_state_disk_root(tmp.path().to_path_buf());
        let mut order = preflight_order("vm-disk-budget");
        order.cmdline = "quiet hippius.disk_gb=2".to_string();
        let Err(rej) = handle_tenant_preflight(&lc, order).await else {
            panic!("over the declared budget must refuse the preflight");
        };
        assert_eq!(rej.class, "insufficient-disk");
    }

    #[tokio::test]
    async fn preflight_of_an_already_running_vm_is_not_asid_gated() {
        // A re-dispatched preflight for a LIVE domain needs no new ASID.
        let lc = std::sync::Arc::new(lifecycle());
        handle_launch(
            &lc,
            &WatcherWinsAny(lc.clone()),
            launch_order("tenant-live"),
        )
        .await
        .unwrap();
        let full = crate::sev_asid::AsidUsage {
            capacity: 99,
            used: 98,
        };
        let lc = std::sync::Arc::try_unwrap(lc)
            .ok()
            .expect("sole owner")
            .with_asid_source(Arc::new(crate::sev_asid::FixedAsidSource(full)));
        let res = handle_tenant_preflight(&lc, preflight_order("tenant-live")).await;
        if let Err(rej) = res {
            assert_ne!(rej.class, "insufficient-resources");
        }
    }

    #[tokio::test]
    async fn a_finished_launch_frees_its_asid_reservation() {
        // 99 / 97 in use ⇒ exactly one more tenant fits.
        let usage = crate::sev_asid::AsidUsage {
            capacity: 99,
            used: 97,
        };
        let lc = std::sync::Arc::new(
            lifecycle().with_asid_source(Arc::new(crate::sev_asid::FixedAsidSource(usage))),
        );
        let vm = |n: &str| crate::VmId::new(n).unwrap();
        lc.reserve_asid(&vm("tenant-live"), crate::lifecycle::DomainProfile::Tenant)
            .unwrap();
        assert!(lc
            .reserve_asid(&vm("tenant-next"), crate::lifecycle::DomainProfile::Tenant)
            .is_err());
        handle_launch(
            &lc,
            &WatcherWinsAny(lc.clone()),
            launch_order("tenant-live"),
        )
        .await
        .unwrap();
        lc.reserve_asid(&vm("tenant-next"), crate::lifecycle::DomainProfile::Tenant)
            .unwrap();
    }

    /// A pusher that reports the ticket delivered for whichever VM.
    struct WatcherWinsAny(std::sync::Arc<CvmLifecycle>);
    #[async_trait::async_trait]
    impl crate::vsock::ticket_push::TicketPusher for WatcherWinsAny {
        async fn push(&self, cid: u32, _port: u32, cose: &[u8]) -> crate::error::Result<()> {
            let vm = crate::VmId::new("tenant-live").unwrap();
            self.0.note_ticket_delivered(&vm, cid, cose);
            Ok(())
        }
    }

    fn launch_order(vm: &str) -> LaunchOrder {
        LaunchOrder {
            vm_id: crate::VmId::new(vm).unwrap(),
            ovmf_path: "/var/lib/hippius-miner/ovmf.fd".into(),
            kernel_path: "/var/lib/hippius-miner/vmlinuz".into(),
            initrd_path: "/var/lib/hippius-miner/initrd".into(),
            cmdline: "quiet".to_string(),
            luks_disk_path: format!("/var/lib/hippius-miner/{vm}.img").into(),
            luks_disk_size_gb: 10,
            data_disk_size_gb: 0,
            rootfs_data_path: "/var/lib/hippius-miner/rootfs.img".into(),
            rootfs_hash_path: "/var/lib/hippius-miner/rootfs.verity".into(),
            cpu_count: 2,
            memory_mb: 2048,
            cose_ticket: serde_bytes::ByteBuf::from(medium_ticket()),
            require_existing_disks: false,
            guardian_ep: None,
            net: None,
        }
    }

    #[tokio::test]
    async fn a_failed_push_leaves_the_domain_to_the_re_push() {
        let lc = lifecycle();
        let rej = handle_launch(&lc, &UnreachableGuestPusher, launch_order("tenant-slow"))
            .await
            .unwrap_err();
        assert_eq!(rej.class, "ticket-delivery-failed");
        assert_eq!(lc.list_tenants().await.unwrap().len(), 1);
        assert!(!lc.ticket_delivered(&crate::VmId::new("tenant-slow").unwrap()));
    }

    #[tokio::test]
    async fn a_push_the_reboot_watcher_won_is_a_launch() {
        // The watcher races the launch for the guest's one-shot listener;
        // when it wins, the launch's own push fails with the ticket
        // already delivered.
        struct WatcherWins(std::sync::Arc<CvmLifecycle>);
        #[async_trait::async_trait]
        impl crate::vsock::ticket_push::TicketPusher for WatcherWins {
            async fn push(&self, cid: u32, _port: u32, cose: &[u8]) -> crate::error::Result<()> {
                let vm = crate::VmId::new("tenant-race").unwrap();
                self.0.note_ticket_delivered(&vm, cid, cose);
                Err(MinerAgentError::TicketDelivery("connect-reset"))
            }
        }
        let lc = std::sync::Arc::new(lifecycle());
        let out = handle_launch(&lc, &WatcherWins(lc.clone()), launch_order("tenant-race"))
            .await
            .unwrap();
        assert_eq!(out, "launched");
    }

    /// A lifecycle latched by a persisted policy in `dir` (nothing loaded).
    fn gated_lifecycle(
        dir: &std::path::Path,
        mode: crate::orders::types::NetPolicyMode,
    ) -> CvmLifecycle {
        use crate::netpolicy::{MockNft, NetPolicyEnforcer, NetPolicyStore};
        let mut order = crate::netpolicy::tests::policy(1);
        order.mode = mode;
        crate::netpolicy::store::write_record_for_tests(dir, &order);
        let driver = Arc::new(crate::lifecycle::MockLibvirtDriver::new());
        lifecycle().with_net_policy_gate(Arc::new(NetPolicyEnforcer::new(
            Arc::new(NetPolicyStore::new(dir)),
            Arc::new(MockNft::new()),
            Arc::new(crate::netpolicy::LibvirtGuestTaps::new(driver.clone())),
            Arc::new(crate::netpolicy::VmCaps::new(
                driver,
                Arc::new(crate::netpolicy::caps::tests::FakeTuner::default()),
            )),
        )))
    }

    #[tokio::test]
    async fn an_unloaded_edge_policy_refuses_launch_and_preflight() {
        let dir = tempfile::tempdir().unwrap();
        let lc = gated_lifecycle(dir.path(), crate::orders::types::NetPolicyMode::Edge);
        let rej = handle_launch(&lc, &UnreachableGuestPusher, launch_order("tenant-edge"))
            .await
            .unwrap_err();
        assert_eq!(
            (rej.status, rej.class),
            (StatusCode::SERVICE_UNAVAILABLE, "net-policy-not-loaded")
        );
        assert!(lc.list_tenants().await.unwrap().is_empty());
        let rej = handle_tenant_preflight(&lc, preflight_order("tenant-edge"))
            .await
            .unwrap_err();
        assert_eq!(rej.class, "net-policy-not-loaded");
    }

    #[tokio::test]
    async fn a_local_policy_never_gates_a_launch() {
        let dir = tempfile::tempdir().unwrap();
        let lc = gated_lifecycle(dir.path(), crate::orders::types::NetPolicyMode::Local);
        let rej = handle_launch(&lc, &UnreachableGuestPusher, launch_order("tenant-local"))
            .await
            .unwrap_err();
        // Past the gate: the domain is up, only the (unreachable) push failed.
        assert_eq!(rej.class, "ticket-delivery-failed");
        assert_eq!(lc.list_tenants().await.unwrap().len(), 1);
    }

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
        store.finish("ord-1", Some("stopped")).unwrap();
        assert_eq!(
            store.begin("ord-1").unwrap(),
            BeginOutcome::AlreadyOk(Some("stopped".into()))
        );
        // ... and stays AlreadyOk on every further replay.
        assert_eq!(
            store.begin("ord-1").unwrap(),
            BeginOutcome::AlreadyOk(Some("stopped".into()))
        );
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
        store.finish("ord-1", None).unwrap();
        // A failed order can be re-claimed and re-dispatched.
        assert_eq!(store.begin("ord-1").unwrap(), BeginOutcome::Claimed);
    }

    #[test]
    fn eviction_keeps_the_store_bounded() {
        let store = IdempotencyStore::with_capacity(2);
        for id in ["a", "b", "c"] {
            assert_eq!(store.begin(id).unwrap(), BeginOutcome::Claimed);
            store.finish(id, Some("stopped")).unwrap();
        }
        // The two most-recent ids are still cached. Check them first:
        // a cache HIT (`AlreadyOk`) does not mutate the store, so the
        // assertions do not perturb each other.
        assert_eq!(
            store.begin("c").unwrap(),
            BeginOutcome::AlreadyOk(Some("stopped".into()))
        );
        assert_eq!(
            store.begin("b").unwrap(),
            BeginOutcome::AlreadyOk(Some("stopped".into()))
        );
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

    /// Every disk refusal — the declared budget, the preflight measured
    /// gate, and the launch-time create gate of either writable disk —
    /// answers ONE typed class, 507 `insufficient-disk`, never the generic
    /// `dispatch-failed` vali would read as a SEV start failure. Other
    /// disk-create faults keep `dispatch-failed`.
    #[test]
    fn every_disk_refusal_is_a_typed_insufficient_disk() {
        for (err, display) in [
            (MinerAgentError::InsufficientDisk, "cvm-insufficient-disk"),
            (
                MinerAgentError::DataDisk("insufficient-space"),
                "data-disk/insufficient-space",
            ),
            (
                MinerAgentError::OverlayDisk("insufficient-space"),
                "overlay-disk/insufficient-space",
            ),
        ] {
            let (rej, line) = capture_detail(&err, "tenant-d");
            assert_eq!(rej.class, "insufficient-disk", "{display}");
            assert_eq!(rej.status, StatusCode::INSUFFICIENT_STORAGE, "{display}");
            assert_eq!(
                line.as_deref(),
                Some(
                    format!(
                        "hippius-miner-agent: orders: insufficient-disk-detail vm=tenant-d class={display}"
                    )
                    .as_str()
                ),
            );
        }
        for err in [
            MinerAgentError::DataDisk("create"),
            MinerAgentError::OverlayDisk("statvfs"),
        ] {
            assert_eq!(capture_detail(&err, "t").0.class, "dispatch-failed");
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

    /// A relaunch refused for missing disks gets its OWN class and a
    /// `412` — vali keys "stop relaunching here and escalate" off that
    /// exact string, so it must never flatten into `dispatch-failed`
    /// (which vali reads as a SEV start failure) or `launch-input`.
    #[test]
    fn relaunch_disks_missing_has_its_own_class_and_detail_log() {
        let err = MinerAgentError::RelaunchDisksMissing("overlay");
        let (rej, line) = capture_detail(&err, "tenant-x");
        assert_eq!(rej.class, "relaunch-disks-missing");
        assert_eq!(rej.status, StatusCode::PRECONDITION_FAILED);
        assert_eq!(
            line.as_deref(),
            Some(
                "hippius-miner-agent: orders: relaunch-disks-missing-detail vm=tenant-x \
                 class=relaunch-disks-missing/overlay"
            ),
        );
    }

    #[test]
    fn relaunch_disks_unreadable_is_a_retryable_class_of_its_own() {
        let err = MinerAgentError::RelaunchDisksUnreadable("state-disk");
        let (rej, line) = capture_detail(&err, "tenant-x");
        assert_eq!(rej.class, "relaunch-disks-unreadable");
        assert_eq!(rej.status, StatusCode::SERVICE_UNAVAILABLE);
        assert!(line.is_some_and(|l| l.contains("relaunch-disks-unreadable/state-disk")));
    }

    /// `TicketDelivery` is a dedicated arm AND emits a detail-log line
    /// (review r2 P3) — the public class `ticket-delivery-failed`
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

    #[test]
    fn a_replay_echoes_the_original_outcome_class() {
        // vali's §24 counts a replayed stop as ITS stop only if the guest was
        // actually `stopped` — a bare "replay" would hide a `not-running`.
        let store = IdempotencyStore::new();
        assert_eq!(store.begin("s").unwrap(), BeginOutcome::Claimed);
        store.finish("s", Some("not-running")).unwrap();
        assert_eq!(
            store.begin("s").unwrap(),
            BeginOutcome::AlreadyOk(Some("not-running".into()))
        );
    }

    #[test]
    fn an_oversize_class_is_not_kept() {
        let store = IdempotencyStore::new();
        let long = "x".repeat(MAX_REPLAY_CLASS_LEN + 1);
        assert_eq!(store.begin("p").unwrap(), BeginOutcome::Claimed);
        store.finish("p", Some(&long)).unwrap();
        assert_eq!(store.begin("p").unwrap(), BeginOutcome::AlreadyOk(None));
    }
}
