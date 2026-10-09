"""Restore a VM from one of its backups — the vali side.

See `docs/design/backup-failover.md` §"Restore". A restore is a
`MigrationJob` with `kind=restore`, so it reuses the §25 machinery end to
end: the VM's `Migrating` state, `_h_mig_dest_activating`,
`_activate_dest_vm` (generation, host, billing and placement cutover), the
#1206 dest-proven + dest-alive reclaim gate, and the one-active-job-per-VM
constraint that serialises it against §25 and §24.

The phases, all of the original's data untouched until the commit point:

1. `restore_staging` — the ORIGINAL KEEPS RUNNING. The destination (the
   current host by default) downloads the chosen point and rebuilds it into
   a staging directory (`restore` op=stage). A staging failure fails the job
   (`stage-*`); the VM was never touched.
2. `restore_stopping` — the original's domain is stopped through the power
   API (so the reboot-watcher leaves it down and its ticket re-push is
   cancelled), and the job waits for its host to report it down.
3. `dest_activating` — the VM is fenced `Migrating`, the KBS activated at
   `new_gen` on the destination chip, and `migrate-activate` sent with the
   `staged_restore_id`: the destination moves the live files aside
   (`*.pre-restore-<id>`), installs the staged ones and boots.
4. `restore_verifying` — the job waits for the KBS evidence bundle of the
   restored guest's release at `new_gen`. That release is the COMMIT POINT:
   it commits `counter + 1`, after which the original disk is an older
   state. Then the VM is activated on the destination.
5. Reclaim (after `done`, outside the job): once the destination is proven
   and alive, the `*.pre-restore-*` files are deleted (`restore`
   op=reclaim) and, when the restore moved hosts, the source is reclaimed.

A point of an EARLIER boot (A2) is restored the same way, through a
KBS-authorized rollback: only on an explicit `accept_rollback` on behalf of
a named tenant or superuser, never by an automatic path (a failover never
rolls back), rate-limited per VM. Right after the KBS `activate`, vali arms
the KBS (`authorize-rollback`) with the run's own KBS-signed checkpoint;
the restored guest's first release consumes the arm, and the job is done
only once the KBS reports the arm consumed by THIS restore. Any failure
withdraws the arm. `RollbackEvent` is vali's audit copy.

A failure BEFORE the commit point reverts (`restore_reverting`): the KBS is
activated at `new_gen + 1` back on the source chip, the destination aborts
(swaps the original back), and the original is relaunched — only if it was
running. A failure AFTER it keeps the original disk
(`VALI_RESTORE_KEEP_ORIGINAL_S`) and says so loudly. An operator may then
put the original back (`start_undo`, `restore_undoing`): the original is
itself an older state by then, so that too is a KBS-authorized rollback, to
the checkpoint vali took of the original right before the fence.
"""

from __future__ import annotations

import hashlib
import json
import logging
import re
import secrets
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

from django.conf import settings
from django.db import IntegrityError, transaction
from django.db.models import Exists, F, OuterRef
from django.utils import timezone

from apps.lifecycle.models import Vm, VmBootPhase, VmPowerState, VmState

from . import effects, idempotency
from .effects import EffectError
from .idempotency import IdempotencyUnavailable
from .models import (
    TERMINAL_MIGRATION_STATES,
    DestAuthorization,
    MigrationJob,
    MigrationKind,
    MigrationState,
    RollbackEvent,
    RollbackOutcome,
    RollbackPurpose,
    SourceReclaimState,
)

log = logging.getLogger("apps.orchestration.restore")

#: Job kinds this module drives (failover lands with its own intake).
RESTORE_KINDS = frozenset({MigrationKind.RESTORE.value, MigrationKind.FAILOVER.value})

#: Pre-fence restore states: the VM is still `Active` and the KBS untouched.
PRE_FENCE_STATES = frozenset(
    {MigrationState.RESTORE_STAGING.value, MigrationState.RESTORE_STOPPING.value}
)
#: States past the fence and before the commit decision.
FENCED_STATES = frozenset(
    {MigrationState.DEST_ACTIVATING.value, MigrationState.RESTORE_VERIFYING.value}
)
CANCELLABLE_STATES = PRE_FENCE_STATES

_REQUEST_ID_RE = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")
_RUN_ID_RE = re.compile(r"^[0-9a-f]{32}$")
_STAGE_STATES = frozenset({"staging", "staged", "failed", "aborted", "reclaimed"})
_REASON_RE = re.compile(r"^[a-z0-9-]{1,64}$")
_BEHALF_KINDS = frozenset({"tenant", "superuser"})
_BEHALF_ID_RE = re.compile(r"^[A-Za-z0-9._:@-]{1,128}$")


class RestoreError(Exception):
    """A restore request was refused. `code` is the stable error the view
    returns (the C-2 / C-5 vocabulary); `detail` is for humans; `extra` is
    merged into the error body (`retry_after_s`)."""

    def __init__(self, code: str, detail: str, **extra: Any) -> None:
        super().__init__(detail)
        self.code = code
        self.detail = detail
        self.extra = extra


# ─── settings ────────────────────────────────────────────────────────


def enabled() -> bool:
    return bool(getattr(settings, "VALI_RESTORE_ENABLED", False))


def rollback_min_interval_s() -> float:
    """At most one rollback per VM this often (vali's side; the KBS
    enforces its own)."""
    return float(getattr(settings, "VALI_RESTORE_ROLLBACK_MIN_INTERVAL_S", 1800.0))


def _streams() -> int:
    return min(16, max(1, int(getattr(settings, "VALI_RESTORE_STREAMS", 8))))


def stage_timeout_s(job: MigrationJob) -> float:
    """How long staging may take: three times the ETA, at least
    `VALI_RESTORE_STAGE_TIMEOUT_S` (1 h), at most the presigned URLs' 12 h
    cap."""
    floor = float(getattr(settings, "VALI_RESTORE_STAGE_TIMEOUT_S", 3600.0))
    eta = float(job.restore_eta_s or 0)
    return min(12 * 3600.0, max(floor, 3 * eta))


def stop_timeout_s() -> float:
    return float(getattr(settings, "VALI_RESTORE_STOP_TIMEOUT_S", 600.0))


def verify_timeout_s() -> float:
    return float(getattr(settings, "VALI_RESTORE_VERIFY_TIMEOUT_S", 900.0))


def revert_timeout_s() -> float:
    return float(getattr(settings, "VALI_RESTORE_REVERT_TIMEOUT_S", 1800.0))


def keep_original_s() -> float:
    return float(getattr(settings, "VALI_RESTORE_KEEP_ORIGINAL_S", 86400.0))


def _stage_redispatch_s() -> float:
    return float(getattr(settings, "VALI_RESTORE_STAGE_REDISPATCH_S", 120.0))


def _stage_max_dispatches() -> int:
    return max(1, int(getattr(settings, "VALI_RESTORE_STAGE_MAX_DISPATCHES", 3)))


def job_timeout_s(job: MigrationJob) -> float | None:
    """The per-phase deadline of a restore-only state, `None` for a state
    the §25 table already times."""
    state = job.state
    if state == MigrationState.RESTORE_STAGING.value:
        return stage_timeout_s(job)
    if state == MigrationState.RESTORE_STOPPING.value:
        return stop_timeout_s()
    if state == MigrationState.RESTORE_VERIFYING.value:
        return verify_timeout_s()
    if state in (MigrationState.RESTORE_REVERTING.value, MigrationState.RESTORE_UNDOING.value):
        return revert_timeout_s()
    if state == MigrationState.DEST_ACTIVATING.value and job.kind == MigrationKind.FAILOVER.value:
        from . import service

        return activate_timeout_s(job, service._activate_timeout())
    return None


# ─── intake ──────────────────────────────────────────────────────────


def _validate_other_dest(vm: Vm, dest_node_id: str, *, source: str | None = None) -> None:
    """Refuse (`no-eligible-miner`) an operator-named destination other than
    the VM's host unless it can boot this VM: same SNP generation, live and
    dispatchable, not observed CVM-incapable, not zombie-quarantined, not
    cordoned, and with room for the flavor."""
    from apps.backup import service as backup_service
    from apps.miners.models import MinerIdentity
    from apps.orchestration.services import flavors
    from apps.scheduler import service as sched

    from . import service

    def refuse(why: str) -> RestoreError:
        return RestoreError("no-eligible-miner", f"destination {dest_node_id!r}: {why}")

    miner = MinerIdentity.objects.filter(miner_id=dest_node_id).first()
    if miner is None:
        raise refuse("unknown miner")
    verdict = sched.dispatchability(miner)
    if not verdict.dispatchable:
        raise refuse(f"not dispatchable ({verdict.reason})")
    try:
        if service._snp_generation(source or vm.host) != service._snp_generation(dest_node_id):
            raise refuse("another SNP generation than the VM's host")
        service._reject_cvm_incapable_dest(dest_node_id)
        service._reject_zombie_quarantined_dest(dest_node_id)
        service._reject_cordoned_dest(dest_node_id)
        service._reject_cdn_colocated_dest(vm, dest_node_id)
        service._reject_group_colocated_dest(vm, dest_node_id)
    except service.StartError as exc:
        raise refuse(exc.message) from exc
    try:
        backup_service.source_disk_bytes(vm)
        spec = _launch_flavor(vm)
        # The restored guest boots the recorded boot's size; its next start
        # the spec's (a stopped VM resized on the books): room for both.
        sizes = [flavors.resolve_flavor(f) for f in {spec, _booted_flavor(vm) or spec}]
        size = flavors.FlavorSize(
            cpu_count=max(s.cpu_count for s in sizes),
            memory_mb=max(s.memory_mb for s in sizes),
            data_disk_size_gb=max(s.data_disk_size_gb for s in sizes),
            luks_disk_size_gb=sizes[0].luks_disk_size_gb,
        )
    except (backup_service.BackupError, flavors.UnknownFlavor) as exc:
        raise RestoreError(
            "vm-not-restorable", f"the vm has no usable launch record: {exc}"
        ) from exc
    free = sched.host_resources_by_node().get(miner.chain_node_id or "")
    if (
        free is None
        or free.free_memory_mb is None
        or free.free_cpus is None
        or free.free_memory_mb < size.memory_mb
        or free.free_cpus < size.cpu_count
    ):
        raise refuse("no room for the vm's flavor (or its free resources are unknown)")
    from .services.launch_record import vm_data_disk_gb

    disk_reason = sched.disk_gate_refusal(
        miner.chain_node_id or "",
        spec,
        context="restore-dest",
        data_disk_gb=vm_data_disk_gb(vm.vm_id) or None,
    )
    if disk_reason:
        raise refuse(f"no room for the vm's data disk ({disk_reason})")


def _booted_flavor(vm: Vm) -> str:
    from .models import LaunchJob, LaunchJobState
    from .services.launch_record import booted_flavor

    record = (
        LaunchJob.objects.filter(vm_id=vm.vm_id, state=LaunchJobState.SUCCEEDED)
        .order_by("-finished_at")
        .first()
    )
    return booted_flavor(record) if record else ""


def _launch_flavor(vm: Vm) -> str:
    from .models import LaunchJob, LaunchJobState

    record = (
        LaunchJob.objects.filter(vm_id=vm.vm_id, state=LaunchJobState.SUCCEEDED)
        .order_by("-finished_at")
        .first()
    )
    return str(((record.spec_json or {}) if record else {}).get("flavor") or "")


def start_restore(
    *,
    vm: Vm,
    run_id: Any,
    request_id: Any,
    decided_by: Any,
    dest_node_id: Any = None,
    accept_rollback: Any = None,
    on_behalf_of: Any = None,
    customer_authorized: Any = None,
) -> tuple[MigrationJob, bool]:
    """Open a restore job for `vm` to backup run `run_id`. Returns `(job,
    created)`; the same `request_id` returns the job it created before.
    Raises `RestoreError` with the C-2 / C-5 codes.

    A point of an earlier boot (`rollback`) additionally needs the flag,
    a KBS checkpoint on the run, `on_behalf_of` (`on-behalf-of-required`),
    `accept_rollback: true` (`rollback-not-accepted`), no rollback of the VM
    armed in the last `VALI_RESTORE_ROLLBACK_MIN_INTERVAL_S`
    (`rollback-rate-limited`), and a KBS that serves the rollback routes.
    For an M2 (`key_mode=customer`) VM the rollback is the CUSTOMER'S
    decision, taken on their guardian: without `customer_authorized: true`
    it is `customer-rollback-authorization-required`, and vali never arms
    the KBS for it (`_refuse_kbs_rollback_of_m2`).

    The destination is the VM's current host unless the operator names
    another (`dest_node_id`), which must be able to boot the VM
    (`_validate_other_dest`)."""
    from apps.backup import service as backup_service

    from . import service

    if not isinstance(request_id, str) or not _REQUEST_ID_RE.fullmatch(request_id):
        raise RestoreError("bad-request", "request_id must match [A-Za-z0-9._:-]{1,128}")
    existing = _job_for_request(request_id)
    if existing is not None:
        # A replay answers the job it created, even with the flag turned off.
        return _replay(existing, vm, kind=MigrationKind.RESTORE.value), False
    if not enabled():
        raise RestoreError("restore-disabled", "restores are not enabled on this deployment")
    if not isinstance(run_id, str) or not _RUN_ID_RE.fullmatch(run_id):
        raise RestoreError("bad-request", "run_id must be 32 lower-case hex characters")
    if dest_node_id is not None and (
        not isinstance(dest_node_id, str) or not dest_node_id.strip() or len(dest_node_id) > 64
    ):
        raise RestoreError("bad-request", "dest_node_id must be a non-empty string")
    if accept_rollback is not None and not isinstance(accept_rollback, bool):
        raise RestoreError("bad-request", "accept_rollback must be a boolean")
    if customer_authorized is not None and not isinstance(customer_authorized, bool):
        raise RestoreError("bad-request", "customer_authorized must be a boolean")
    behalf = parse_on_behalf_of(on_behalf_of)
    if vm.state != VmState.ACTIVE or not vm.host:
        raise RestoreError("vm-not-restorable", f"the vm is {vm.state}, not active on a host")
    if vm.power_state not in (VmPowerState.RUNNING, VmPowerState.STOPPED):
        raise RestoreError(
            "vm-not-restorable", f"a power operation is in flight ({vm.power_state})"
        )
    if service._has_active_job(vm):
        raise RestoreError("job-in-flight", "the vm already has an in-flight orchestration job")

    from apps.backup.models import BackupRun

    run = BackupRun.objects.filter(pk=uuid.UUID(hex=run_id), vm=vm).select_related("chain").first()
    if run is None:
        raise RestoreError("point-not-restorable", "the vm has no such backup run")
    point = backup_service.classify_run(vm, run)
    rollback = point.klass == backup_service.PointClass.ROLLBACK
    if rollback:
        _admit_rollback(
            vm,
            point,
            behalf=behalf,
            accept_rollback=accept_rollback,
            customer_authorized=customer_authorized,
        )
    elif not point.restorable:
        raise RestoreError("point-not-restorable", "the run is not a restorable point")

    dest = (dest_node_id or "").strip() or vm.host
    if dest != vm.host:
        _validate_other_dest(vm, dest)
    else:
        from apps.miners.models import MinerIdentity

        if not MinerIdentity.objects.filter(miner_id=dest).exclude(platform_id="").exists():
            raise RestoreError("no-eligible-miner", "the vm's host has no registered chip")
    _preflight_dest_ticket(vm)

    prior = (
        VmPowerState.RUNNING.value
        if vm.power_state == VmPowerState.RUNNING
        else VmPowerState.STOPPED.value
    )
    eta = backup_service.restore_eta_s(
        point.runs, throughput_bps=backup_service.dest_throughput_bps(dest)
    )
    now = timezone.now()
    from apps.backup.models import BackupChain, BackupPolicy

    try:
        with transaction.atomic():
            # The chain's row lock orders this against `backup.prune`, which
            # marks a chain (`pruned_at`) under the same lock before it
            # deletes anything: a chain being pruned is never restored from,
            # and a pinned one is never pruned.
            chain = BackupChain.objects.select_for_update().get(pk=run.chain_id)
            if chain.pruned_at is not None:
                raise RestoreError("point-not-restorable", "the point's chain is being pruned")
            _recheck_no_active_job(vm)
            auth = DestAuthorization.objects.create(
                kind=MigrationKind.RESTORE.value,
                requested_by=decided_by,
                request_id=request_id,
                evidence={
                    "run_id": run.run_id,
                    "point_class": point.klass,
                    "dest_node_id": dest,
                    "requested_dest_node_id": (dest_node_id or "") or None,
                    "requested_at": now.isoformat(),
                },
                accept_rollback=rollback,
                on_behalf_of_kind=behalf[0] if behalf else "",
                on_behalf_of_id=behalf[1] if behalf else "",
            )
            job = MigrationJob.objects.create(
                job_id=secrets.token_hex(16),
                kind=MigrationKind.RESTORE.value,
                vm=vm,
                source_node_id=vm.host,
                dest_node_id=dest,
                source_gen=vm.generation,
                new_gen=vm.generation + 1,
                state=MigrationState.RESTORE_STAGING.value,
                phase_started_at=now,
                decided_by=decided_by,
                restore_run=run,
                restore_id=secrets.token_hex(16),
                request_id=request_id,
                prior_power_state=prior,
                # A stopped VM is booted by the restore (the release is the
                # commit and the liveness proof) and stopped again once it
                # proved it runs — `settle_cold_migrations`.
                cold=prior == VmPowerState.STOPPED.value,
                authorization=auth,
                restore_eta_s=eta,
            )
            if rollback:
                assert behalf is not None  # `_admit_rollback` required it
                policy = BackupPolicy.objects.filter(vm=vm).first()
                RollbackEvent.objects.create(
                    vm=vm,
                    job=job,
                    purpose=RollbackPurpose.RESTORE.value,
                    run=run,
                    restore_id=job.restore_id,
                    from_boot_counter=policy.observed_boot_counter if policy else None,
                    to_boot_counter=int(run.boot_counter or 0),
                    point_taken_at=run.created_at,
                    manifest_sha256=run.manifest_sha256,
                    requested_by_kind=behalf[0],
                    requested_by_id=behalf[1],
                )
    except IntegrityError as exc:
        existing = _job_for_request(request_id)
        if existing is not None:
            return _replay(existing, vm, kind=MigrationKind.RESTORE.value), False
        raise RestoreError(
            "job-in-flight", "the vm already has an in-flight orchestration job"
        ) from exc
    if rollback:
        log.warning(
            "ROLLBACK restore started: job=%s vm=%s to run %s of boot %s, on behalf of %s:%s",
            job.job_id,
            vm.vm_id,
            run.run_id,
            run.boot_counter,
            behalf[0] if behalf else "?",
            behalf[1] if behalf else "?",
        )
    log.info(
        "restore started: job=%s vm=%s run=%s %s→%s gen %d→%d (prior %s, eta %ss)",
        job.job_id,
        vm.vm_id,
        run.run_id,
        job.source_node_id,
        dest,
        job.source_gen,
        job.new_gen,
        prior,
        eta,
    )
    return job, True


def parse_on_behalf_of(raw: Any) -> tuple[str, str] | None:
    """`(kind, id)` of the C-5 `on_behalf_of: {kind: tenant|superuser, id}`,
    `None` when absent. Anything else is `on-behalf-of-required`."""
    if raw is None:
        return None
    if not isinstance(raw, dict) or set(raw) != {"kind", "id"}:
        raise RestoreError(
            "on-behalf-of-required", "on_behalf_of must be {kind: tenant|superuser, id}"
        )
    kind, ident = raw.get("kind"), raw.get("id")
    if isinstance(ident, int) and not isinstance(ident, bool):
        ident = str(ident)
    if kind not in _BEHALF_KINDS or not isinstance(ident, str) or not _BEHALF_ID_RE.fullmatch(
        ident
    ):
        raise RestoreError(
            "on-behalf-of-required",
            "on_behalf_of.kind must be tenant|superuser and on_behalf_of.id a non-empty id",
        )
    return kind, ident


def _admit_rollback(
    vm: Vm,
    point: Any,
    *,
    behalf: tuple[str, str] | None,
    accept_rollback: Any,
    customer_authorized: Any = None,
) -> None:
    """The A2 gates of a restore to a point of an earlier boot, in C-5 order.
    Raises `RestoreError`."""
    from apps.backup import service as backup_service

    if not backup_service.rollback_enabled():
        raise RestoreError(
            "rollback-unsupported",
            "the point was taken at an earlier boot of the vm; rollback restores are "
            "not enabled on this deployment",
        )
    if _is_customer_mode(vm):
        _admit_m2_rollback(vm, point, customer_authorized=customer_authorized)
    if backup_service.checkpoint_of(point.run) is None:
        raise RestoreError(
            "rollback-no-checkpoint",
            "the point was taken at an earlier boot and carries no KBS checkpoint, so "
            "it can never be restored",
        )
    if behalf is None:
        raise RestoreError(
            "on-behalf-of-required", "a rollback restore must say on whose behalf it is asked"
        )
    if accept_rollback is not True:
        raise RestoreError(
            "rollback-not-accepted",
            "the point was taken at an earlier boot of the vm: restoring it is a rollback "
            "and needs accept_rollback: true",
        )
    _rollback_gate(vm)


def _is_customer_mode(vm: Any) -> bool:
    from .services import customer_keys

    return getattr(vm, "key_mode", "") == customer_keys.KEY_MODE_CUSTOMER


#: The operator-facing instruction of `customer-rollback-authorization-required`.
_M2_ROLLBACK_INSTRUCTION = (
    "vm {vm_id} is key_mode=customer: its disk key and its volume stamp are held by "
    "the customer's key guardian, so restoring a point of an earlier boot (run "
    "{run_id}, boot {boot}, taken {taken}) is the CUSTOMER'S decision. Ask the "
    "customer to run `guardian authorize-rollback {vm_id} --to-stamp <the point's "
    "stamp>` on their guardian, then re-issue this request with "
    "customer_authorized: true."
)


def _admit_m2_rollback(vm: Vm, point: Any, *, customer_authorized: Any) -> None:
    """A2 for an M2 VM (design §2): the rollback is authorized at the
    customer's guardian (`guardian authorize-rollback`), never by a KBS arm.
    Without the operator saying the customer did so, refuse with the
    instruction. With it, the remaining obstacle is the KBS boot counter,
    which still fences every mode: see `_refuse_kbs_rollback_of_m2`."""
    if customer_authorized is not True:
        run = point.run
        raise RestoreError(
            "customer-rollback-authorization-required",
            _M2_ROLLBACK_INSTRUCTION.format(
                vm_id=vm.vm_id,
                run_id=run.run_id,
                boot=run.boot_counter,
                taken=run.created_at.isoformat() if run.created_at else "?",
            ),
        )
    _refuse_kbs_rollback_of_m2(vm)


def _refuse_kbs_rollback_of_m2(vm: Vm) -> None:
    """vali never asks the KBS to authorize a rollback of an M2 VM: its
    anti-rollback stamp is the customer's guardian's, and the KBS refuses
    every arm for it anyway (`kbs_core::rollback::rollback_capable` is
    false for M2 — it owns no volume stamp there). But the restored state
    disk carries the point's OLDER boot counter, which the KBS still fences
    in every mode, and the KBS has no counter-only rollback for M2 yet; a
    restore opened now would stop the VM, boot it, be refused at the KBS
    and revert. Refused here, before anything is touched, even once the
    customer authorized it."""
    if _is_customer_mode(vm):
        raise RestoreError(
            "rollback-not-capable",
            f"vm {vm.vm_id} is key_mode=customer: the rollback is authorized at the "
            "customer's guardian, but its boot counter is still fenced by the KBS, "
            "which has no rollback for an M2 VM yet (a KBS counter-only rollback is "
            "required first). Nothing was touched.",
        )


def _rollback_gate(vm: Vm) -> None:
    """The rate limit and the KBS's own view, before any rollback of `vm`
    is opened (a restore to an earlier boot, or an undo). Raises
    `RestoreError`: `rollback-rate-limited`, `rollback-unsupported` (the
    KBS lacks the routes or its rollback context), `rollback-not-capable`
    (the KBS says the guest cannot be rolled back, or an M2 VM, which is
    never KBS-rolled-back), `job-in-flight` (the KBS already holds an arm),
    `restore-unavailable` (the KBS cannot be read)."""
    from .services import kbs_rollback

    _refuse_kbs_rollback_of_m2(vm)

    last = (
        RollbackEvent.objects.filter(vm=vm, arm_requested_at__isnull=False)
        .order_by("-arm_requested_at")
        .values_list("arm_requested_at", flat=True)
        .first()
    )
    _rate_limit(last)
    try:
        status = kbs_rollback.rollback_status(vm.vm_id)
    except effects.KbsRouteMissing as exc:
        # A 404 route, or a 503 `rollback-unavailable` (no rollback context).
        raise RestoreError(
            "rollback-unsupported", "the KBS does not serve rollbacks"
        ) from exc
    except effects.EffectUnavailable as exc:
        raise RestoreError("restore-unavailable", f"could not reach the KBS: {exc}") from exc
    except EffectError as exc:
        raise RestoreError("restore-unavailable", f"the KBS rollback read failed: {exc}") from exc
    # The guest must be able to take a rollback at all (KBS-owned volume
    # stamp, guest stamp protocol v2): the KBS refuses every arm otherwise
    # (`guest-not-rollback-capable`), so refuse before the VM is touched.
    capable = status.get(kbs_rollback.WIRE_ROLLBACK_CAPABLE)
    kbs_rollback.note_rollback_capable(vm.vm_id, capable if isinstance(capable, bool) else None)
    if capable is not True:
        raise RestoreError(
            "rollback-not-capable",
            "the KBS reports the vm's guest cannot be rolled back (it does not "
            "speak the rollback-capable volume-stamp protocol)",
        )
    # The KBS's own view too (vali's rows may not know every rollback, e.g.
    # after a database restore): refuse here rather than after the VM was
    # staged, stopped and fenced.
    if status.get("arm") is not None:
        raise RestoreError(
            "job-in-flight", "the KBS already holds a rollback arm for the vm"
        )
    consumed_at = (status.get("last_rollback") or {}).get("consumed_at_unix")
    if isinstance(consumed_at, int) and not isinstance(consumed_at, bool) and consumed_at > 0:
        _rate_limit(datetime.fromtimestamp(consumed_at, tz=UTC))


def _rate_limit(last: Any) -> None:
    """`rollback-rate-limited` (with `retry_after_s`) when the vm's last
    rollback was less than `VALI_RESTORE_ROLLBACK_MIN_INTERVAL_S` ago."""
    if last is None:
        return
    wait = rollback_min_interval_s() - (timezone.now() - last).total_seconds()
    if wait > 0:
        raise RestoreError(
            "rollback-rate-limited",
            f"the vm was rolled back less than {int(rollback_min_interval_s())} s ago",
            retry_after_s=max(1, int(-(-wait // 1))),
        )


def _job_for_request(request_id: str) -> MigrationJob | None:
    return (
        MigrationJob.objects.filter(request_id=request_id)
        .select_related("vm", "restore_run", "restore_run__chain")
        .first()
    )


def _replay(job: MigrationJob, vm: Vm, *, kind: str | None = None) -> MigrationJob:
    """The job a repeated `request_id` answers with. `kind`, when given,
    pins the replay to the SAME kind the caller is asking for — a
    `restore` request_id reused at `/failover` (or the reverse) is a
    conflict, not a silent cross-kind answer, even though both share the
    `RESTORE_KINDS` job-shape (and so `cancel`/`sweep`/`list_jobs`, which
    do not care which of the two a caller wanted)."""
    if (
        job.vm_id != vm.pk
        or job.kind not in RESTORE_KINDS
        or (kind is not None and job.kind != kind)
    ):
        raise RestoreError(
            "request-id-conflict", "the request_id was already used for another request"
        )
    return job


def _preflight_dest_ticket(vm: Vm) -> None:
    """The destination ticket at `new_gen` is minted from the launch record
    and the userdata working copy, exactly as for §25: refuse now rather
    than after the original was stopped."""
    from apps.orchestration.services import migration_ticket as mig

    try:
        effects._launch_paths(vm)
        mig.assert_userdata_rebindable(vm)
    except mig.UserdataNotRebindable as exc:
        raise RestoreError("vm-not-restorable", f"vm not restorable: {exc}") from exc
    except effects.EffectUnavailable as exc:
        raise RestoreError("restore-unavailable", f"could not verify the vm: {exc}") from exc
    except effects.EffectError as exc:
        raise RestoreError("vm-not-restorable", f"vm not restorable: {exc}") from exc


def cancel_restore(*, job: MigrationJob, decided_by: Any) -> MigrationJob:
    """Cancel a restore still in `restore_staging` / `restore_stopping` (the
    KBS never moved, the VM is still `Active`). The staging directory is
    dropped and a VM this job stopped is started again by
    `sweep_restore_cleanups`. Raises `RestoreError("not-cancellable")`."""
    name = getattr(decided_by, "name", None) or "operator"
    now = timezone.now()
    updated = MigrationJob.objects.filter(
        id=job.id, kind__in=RESTORE_KINDS, state__in=CANCELLABLE_STATES
    ).update(
        state=MigrationState.FAILED.value,
        failed_from_state=F("state"),
        version=F("version") + 1,
        phase_started_at=now,
        finished_at=now,
        reason=f"cancelled by {name}"[:256],
        restore_cleanup_pending=True,
    )
    refreshed = MigrationJob.objects.select_related("vm", "restore_run").get(id=job.id)
    if not updated:
        raise RestoreError("not-cancellable", f"the restore is {phase(refreshed)}")
    log.info("restore %s CANCELLED by %s", refreshed.job_id, name)
    return refreshed


# ─── the miner's restore status ──────────────────────────────────────


@dataclass(frozen=True)
class RestoreStatus:
    restore_id: str
    op: str
    state: str
    bytes_done: int
    bytes_total: int
    reason: str
    swapped: bool
    pre_restore_present: bool
    domain_live: bool


def parse_restore_status(raw: Any, *, vm_id: str) -> RestoreStatus:
    """Type-check the miner's status (it is untrusted). Raises `ValueError`
    on anything off-shape, including a status about another VM."""
    if not isinstance(raw, dict):
        raise ValueError("status must be an object")
    if raw.get("vm_id") != vm_id:
        raise ValueError("status is about another vm")

    def text(name: str) -> str:
        v = raw.get(name)
        if not isinstance(v, str):
            raise ValueError(f"{name} must be a string")
        return v

    def uint(name: str) -> int:
        v = raw.get(name)
        if isinstance(v, bool) or not isinstance(v, int) or v < 0:
            raise ValueError(f"{name} must be a non-negative integer")
        return v

    def flag(name: str) -> bool:
        v = raw.get(name, False)
        if not isinstance(v, bool):
            raise ValueError(f"{name} must be a boolean")
        return v

    state = text("state")
    if state not in _STAGE_STATES:
        raise ValueError("state is unknown")
    reason = raw.get("reason")
    if reason is not None and not isinstance(reason, str):
        raise ValueError("reason must be a string or null")
    return RestoreStatus(
        restore_id=text("restore_id"),
        op=text("op"),
        state=state,
        bytes_done=uint("bytes_done"),
        bytes_total=uint("bytes_total"),
        reason=reason if reason and _REASON_RE.fullmatch(reason) else "",
        swapped=flag("swapped"),
        pre_restore_present=flag("pre_restore_present"),
        domain_live=flag("domain_live"),
    )


def _poll_status(job: MigrationJob) -> RestoreStatus | None:
    raw = effects.poll_restore_status(vm_id=job.vm.vm_id, miner_id=job.dest_node_id)
    if raw is None:
        return None
    try:
        return parse_restore_status(raw, vm_id=job.vm.vm_id)
    except ValueError as exc:
        raise EffectError(f"restore status: {exc}") from exc


def _order(job: MigrationJob, op: str, **extra: Any) -> dict[str, Any]:
    return {"vm_id": job.vm.vm_id, "restore_id": job.restore_id, "op": op, **extra}


# ─── handlers (driven by `service.advance_migration_job`) ────────────


class StepFailed(Exception):
    """A restore step failed for good; `str(exc)` is the job's reason."""


def h_staging(job: MigrationJob) -> Any:
    """Stage the point on the destination and follow it. The original keeps
    running; nothing here touches it."""
    status = _poll_status(job)
    if status is not None and status.restore_id == job.restore_id:
        MigrationJob.objects.filter(id=job.id).update(
            restore_bytes_done=status.bytes_done, restore_bytes_total=status.bytes_total
        )
        if status.state == "staged":
            return MigrationState.RESTORE_STOPPING.value, {
                "restore_bytes_done": status.bytes_done,
                "restore_bytes_total": status.bytes_total,
            }
        if status.state == "staging":
            return None
        raise StepFailed(f"stage-{status.reason or status.state}")
    # The destination knows nothing about this restore (not yet asked, or
    # its agent restarted and lost the task): ask, at most every
    # `_stage_redispatch_s`, a bounded number of times.
    now = timezone.now()
    if job.restore_dispatched_at is not None and (
        now - job.restore_dispatched_at < timedelta(seconds=_stage_redispatch_s())
    ):
        return None
    if job.restore_dispatches >= _stage_max_dispatches():
        raise StepFailed("stage-lost")
    _dispatch_stage(job, now)
    return None


def _dispatch_stage(job: MigrationJob, now: Any) -> None:
    from apps.backup import service as backup_service

    run = job.restore_run
    if run is None:
        raise StepFailed("stage-no-point")
    try:
        chain = backup_service.restore_chain(
            job.vm,
            run_id=run.run_id,
            restore_id=job.restore_id,
            allow_rollback=is_rollback(job),
        )
        disk_bytes = backup_service.source_disk_bytes(job.vm)
    except backup_service.BackupError as exc:
        # The point is no longer restorable (the VM rebooted since, …).
        raise StepFailed(f"stage-{exc.code}") from exc
    attempt = job.restore_dispatches
    # Recorded BEFORE the dispatch: a crash after it must still count the
    # attempt, never re-send it at once.
    MigrationJob.objects.filter(id=job.id).update(
        restore_dispatches=attempt + 1, restore_dispatched_at=now
    )
    try:
        effects.dispatch_restore(
            miner_id=job.dest_node_id,
            order_id=f"restore-stage-{job.restore_id}-{attempt}",
            payload=_order(
                job, "stage", chain=chain, disk_bytes=int(disk_bytes), streams=_streams()
            ),
        )
    except effects.RestoreRejected as exc:
        raise StepFailed(f"stage-{_reason(exc.classifier, 'rejected')}") from exc


def _recheck_no_active_job(vm: Vm) -> None:
    """The one-active-job rule again, under the VM's row lock — the lock §25,
    §24 and the resize intake take for the same check. A resize never moves
    `Vm.state`, so without it a restore and a resize could both start."""
    from . import service

    Vm.objects.select_for_update().filter(pk=vm.pk).first()
    if service._has_active_job(vm):
        raise RestoreError("job-in-flight", "the vm already has an in-flight orchestration job")


def _reason(raw: str, fallback: str) -> str:
    raw = (raw or "").strip()
    return raw if _REASON_RE.fullmatch(raw) else fallback


def h_stopping(job: MigrationJob) -> Any:
    """Stop the original's domain through the power API and wait for its
    host to report it down. Records that confirmation on the job's
    authorization — the guard requires it before `DestActivating`."""
    from .services import power

    vm = Vm.objects.get(id=job.vm_id)
    if vm.power_state == VmPowerState.RUNNING:
        if not MigrationJob.objects.filter(
            id=job.id, version=job.version, state=job.state
        ).exists():
            return None  # cancelled (or moved on) since this tick read it
        try:
            power.stop_vm(vm, by_migration=True)
        except power.PowerOpRefused as exc:
            raise EffectError(f"stop refused: {exc.reason}") from exc
        except Exception as exc:  # noqa: BLE001 — a failed dispatch is retried
            raise EffectError(f"stop failed: {exc}") from exc
        finally:
            # Recorded even when the job was cancelled meanwhile: cleanup
            # restarts a VM this job stopped (`_job_stopped_the_vm`) — and
            # it is reopened here, in case it already ran and found the VM
            # still up.
            _note_evidence(job, stopped_by_job_at=timezone.now().isoformat())
            MigrationJob.objects.filter(id=job.id, state=MigrationState.FAILED.value).update(
                restore_cleanup_pending=True
            )
        return None
    if vm.power_state == VmPowerState.STARTING:
        return None
    running = effects.poll_domain_running_on(vm, job.source_node_id)
    if running is not False:
        return None  # up, or unknown — never act on anything but a definite "down"
    if job.authorization_id is None:
        raise StepFailed("stop-without-authorization")
    # The original's anti-rollback state, signed by the KBS, right before
    # the fence: once the restored guest commits, the only way back to the
    # original is a rollback to exactly this (`start_undo`). Only with
    # rollbacks enabled, and never able to hold up or fail the restore.
    _capture_original_checkpoint(job)
    _note_evidence(
        job,
        source_domain_down=True,
        source_domain_down_at=timezone.now().isoformat(),
        source_node_id=job.source_node_id,
    )
    return MigrationState.DEST_ACTIVATING.value, {}


#: The manifest format of a restore's ORIGINAL as an undo point.
_ORIGINAL_MANIFEST_FORMAT = "hippius-vm-restore-original/1"


def original_manifest(job: MigrationJob, checkpoint: dict[str, Any]) -> bytes:
    """The manifest bytes an undo of `job` binds its KBS arm to: the
    original's identity and its KBS checkpoint (the same key a backup
    run's `manifest.json` embeds it under). Deterministic."""
    from .services import kbs_rollback

    doc = {
        "format": _ORIGINAL_MANIFEST_FORMAT,
        "vm_id": job.vm.vm_id,
        "restore_id": job.restore_id,
        "source_node_id": job.source_node_id,
        "source_gen": job.source_gen,
        kbs_rollback.MANIFEST_CHECKPOINT_KEY: checkpoint,
    }
    return json.dumps(doc, sort_keys=True, indent=2).encode("utf-8")


def _capture_original_checkpoint(job: MigrationJob) -> None:
    """Take the KBS checkpoint of the original (domain down, KBS not moved
    yet) once per job — only while rollbacks are enabled (an A1 restore
    never calls the KBS here). Best effort, ONE attempt bounded by
    `kbs_rollback.CHECKPOINT_TIMEOUT_S`: any failure (no route, a refusal,
    an off-shape body, a busy or unreachable KBS) is logged and the restore
    goes on without one — only a later undo is then unavailable (it refuses
    with `revert-no-checkpoint` / `undo-no-checkpoint`). Never raises."""
    from apps.backup import service as backup_service

    from .services import kbs_rollback

    if job.original_checkpoint is not None or not backup_service.rollback_enabled():
        return
    try:
        cp = kbs_rollback.fetch_checkpoint(
            job.vm.vm_id, timeout=kbs_rollback.CHECKPOINT_TIMEOUT_S
        )
        wire = cp.wire()
        manifest = original_manifest(job, wire)
    except Exception as exc:  # noqa: BLE001 — best effort: never holds up the restore
        log.warning(
            "restore %s: no KBS checkpoint of the original (%s: %s) — the restore goes on, "
            "but cannot be undone after its commit point",
            job.job_id,
            type(exc).__name__,
            exc,
        )
        return
    MigrationJob.objects.filter(id=job.id, original_checkpoint__isnull=True).update(
        original_checkpoint=wire, original_manifest=manifest.decode("utf-8")
    )
    job.original_checkpoint = wire
    job.original_manifest = manifest.decode("utf-8")


def _note_evidence(job: MigrationJob, **fields: Any) -> None:
    """Merge `fields` into the job's authorization evidence."""
    if job.authorization_id is None:
        return
    with transaction.atomic():
        auth = DestAuthorization.objects.select_for_update().get(id=job.authorization_id)
        evidence = dict(auth.evidence or {})
        evidence.update(fields)
        auth.evidence = evidence
        auth.save(update_fields=["evidence"])
    job.authorization = auth


def h_verifying(job: MigrationJob) -> Any:
    """Wait for the KBS evidence bundle of the restored guest's release at
    `new_gen` on the destination chip — the commit point — then activate the
    VM there. Never on the destination's own "done"."""
    from . import service

    vm = Vm.objects.get(id=job.vm_id)
    reason = service._kbs_grant_unproven_reason(job, vm)
    if reason is not None:
        log.info("restore %s: waiting for the commit proof (%s)", job.job_id, reason)
        return None
    consumed: dict[str, Any] | None = None
    if is_rollback(job):
        # A rollback is done only once the KBS says ITS arm was consumed by
        # this restore AND the release was delivered: the release that
        # unlocked the restored disk was the authorized rollback, not
        # something else, and the guest really got it.
        view = kbs_view(job.vm.vm_id, _restore_arm_id(job))
        if not view.served:
            # No rollback context on the KBS: this arm can never be consumed.
            raise StepFailed("rollback-unsupported")
        consumed = view.delivered_record
        if consumed is None:
            log.info(
                "restore %s: waiting for the KBS to report the rollback consumed and "
                "delivered",
                job.job_id,
            )
            return None
    with transaction.atomic():
        # Under the job's row lock, and the job's own CAS to `done` in the
        # same transaction: a concurrent tick that chose to revert (its CAS
        # moved the version) makes this a no-op, and once this commits its
        # revert CAS fails. The VM is never activated behind a revert.
        locked = (
            MigrationJob.objects.select_for_update()
            .filter(id=job.id, version=job.version, state=job.state)
            .first()
        )
        if locked is None:
            return None
        service._activate_dest_vm(job)
        if consumed is not None:
            _note_committed(_event(job), consumed)
        _mark_running(vm)
        _require_full_backup(vm)
        _abandon_backup_runs(vm)
        if not service._cas_migration(
            job, MigrationState.DONE.value, {"committed_at": timezone.now()}
        ):
            raise EffectError("restore job changed concurrently during its activation")
    return None


def _mark_running(vm: Vm) -> None:
    """The restored guest is up: the VM runs, whatever the original was.
    A stopped original is stopped again once the restored VM proved it runs
    (`settle_cold_migrations`)."""
    from .services import power

    fresh = Vm.objects.get(pk=vm.pk)
    power._set_power(fresh, VmPowerState.RUNNING)


def _require_full_backup(vm: Vm) -> None:
    from apps.backup.models import BackupPolicy

    BackupPolicy.objects.filter(vm=vm).update(full_required=True)


def _abandon_backup_runs(vm: Vm) -> None:
    """A backup run still in flight at the cutover copies the OLD disk (its
    miner may be the old host): it is failed, so its completion can never
    clear the fresh full the restored boot needs."""
    from apps.backup import service as backup_service
    from apps.backup.models import ACTIVE_RUN_STATUSES, BackupRun

    now = timezone.now()
    for run in BackupRun.objects.filter(vm=vm, status__in=ACTIVE_RUN_STATUSES).select_related(
        "chain", "vm"
    ):
        backup_service._fail(run, "vm-restored", now, full_required=True)


COMMITTED = "committed"
NOT_COMMITTED = "not-committed"
UNDECIDABLE = "undecidable"


def commit_state(job: MigrationJob) -> tuple[str, str]:
    """Whether the restored guest passed the commit point (its first KBS
    release at `new_gen`): `(COMMITTED | NOT_COMMITTED | UNDECIDABLE, why)`.
    Raises `EffectError` when the KBS cannot be read — that decides nothing.

    A revert overwrites the destination's restored disk with the original,
    which after a commit can never unlock again, so NOT_COMMITTED needs
    POSITIVE evidence: the KBS's latest recorded grant for the VM is one
    vali knows, at a generation below `new_gen`. Any sign of a release
    counts as COMMITTED — the KBS bundle at `new_gen` on the destination
    chip, an in-guest signal since the source domain was confirmed down
    (it is down and KBS-fenced, so only the restored guest can send one),
    a `kek_released` / `running` milestone (the fence cleared the
    original's). No bundle at all (a KBS restart erases them), a grant vali
    cannot attribute, or a `new_gen` grant somewhere else is UNDECIDABLE —
    unless the job never dispatched the destination and vali never minted a
    ticket at `new_gen` (`_never_dispatched`): then nothing can have
    released, whatever the KBS lost."""
    from . import service
    from .services import kbs_evidence

    vm = Vm.objects.get(id=job.vm_id)
    if (
        vm.state == VmState.ACTIVE
        and vm.host == job.source_node_id
        and vm.generation == job.source_gen
    ):
        # Never fenced: the fence precedes the KBS activate, so the KBS never
        # moved and nothing could release at `new_gen`.
        return NOT_COMMITTED, "never-fenced"
    if _never_dispatched(job, vm):
        # Before any KBS read: it needs none, and the KBS may be the thing
        # that is down.
        return NOT_COMMITTED, "never-dispatched"
    if service._kbs_grant_unproven_reason(job, vm) is None:
        if is_rollback(job):
            _note_rollback_released(job)
        return COMMITTED, "kbs-grant-at-new-gen"
    if is_rollback(job):
        verdict = rollback_commit_state(job)
        if verdict is not None:
            return verdict
    since = activation_started_at(job)
    if since is not None and vm.guest_signal_at is not None and vm.guest_signal_at > since:
        return COMMITTED, "guest-signal"
    if vm.state == VmState.MIGRATING and vm.boot_phase in (
        VmBootPhase.KEK_RELEASED.value,
        VmBootPhase.RUNNING.value,
    ):
        return COMMITTED, f"boot-phase-{vm.boot_phase}"
    bundle = kbs_evidence.fetch_evidence(vm.vm_id)
    if bundle is None:
        return UNDECIDABLE, "no-kbs-evidence-bundle"
    generation = _grant_generation(str(bundle.get("ticket_id") or ""), vm)
    if generation is None:
        return UNDECIDABLE, "latest-grant-unknown-to-vali"
    if generation >= job.new_gen:
        return UNDECIDABLE, f"latest-grant-generation:{generation}"
    return NOT_COMMITTED, f"latest-grant-generation:{generation}"


def note_dest_dispatch(job: MigrationJob) -> None:
    """Write-ahead, right BEFORE the first `migrate-activate` goes to the
    destination: from here on a ticket at `new_gen` may exist."""
    auth = job.authorization
    if auth is not None and not (auth.evidence or {}).get("dest_dispatch_at"):
        _note_evidence(job, dest_dispatch_at=timezone.now().isoformat())


def _never_dispatched(job: MigrationJob, vm: Vm) -> bool:
    """Positive proof nothing can have released at `new_gen`: the job never
    got as far as the destination dispatch (its write-ahead is absent) AND
    vali never minted this VM a ticket at `new_gen` or later (the only mint
    at that generation is the dispatch's, and it is persisted before the
    ticket leaves vali). A release needs such a ticket."""
    from apps.orders.models import OrderTicketIntake

    if job.kind != MigrationKind.RESTORE.value:
        return False
    auth = job.authorization
    if auth is None or (auth.evidence or {}).get("dest_dispatch_at"):
        return False
    return not OrderTicketIntake.objects.filter(
        vm_id=vm.vm_id, vm_generation__gte=job.new_gen
    ).exists()


def _grant_generation(ticket_id: str, vm: Vm) -> int | None:
    """The generation vali minted `ticket_id` at, for this VM; `None` when
    vali has no record of it."""
    from apps.orders.models import OrderTicketIntake

    from . import service

    if not ticket_id:
        return None
    intake = OrderTicketIntake.objects.filter(ticket_id=ticket_id).first()
    if intake is not None:
        return int(intake.vm_generation) if intake.vm_id == vm.vm_id else None
    grant = service._launch_ticket_grant(ticket_id)
    if grant is None or grant[0] != vm.vm_id:
        return None
    return int(grant[1])


def activation_started_at(job: MigrationJob) -> Any:
    """When the source domain was confirmed down — after the original's last
    boot, before the destination was told to boot anything. `None` when the
    job never recorded it."""
    auth = job.authorization
    raw = (auth.evidence or {}).get("source_domain_down_at") if auth is not None else None
    if not raw:
        return None
    try:
        return datetime.fromisoformat(str(raw))
    except ValueError:
        return None


def fail(job: MigrationJob, reason: str) -> None:
    """Route a restore job's failure by where it happened.

    - pre-fence (`restore_staging` / `restore_stopping`): the job fails, the
      original was never touched; the staging directory is dropped and a VM
      this job stopped is started again (`sweep_restore_cleanups`).
    - fenced, before the commit point: revert (`restore_reverting`).
    - fenced, after it: the job fails and the original disk is KEPT.
    - while reverting: the job fails; the VM stays fenced for an operator.
    """
    from . import service

    state = job.state
    if state in PRE_FENCE_STATES:
        if state == MigrationState.RESTORE_STAGING.value and not reason.startswith("stage-"):
            reason = f"stage-{reason}"
        service._fail_migration(job, reason=reason)
        MigrationJob.objects.filter(id=job.id, state=MigrationState.FAILED.value).update(
            restore_cleanup_pending=True
        )
        return
    if state in FENCED_STATES:
        try:
            verdict, why = commit_state(job)
        except EffectError as exc:
            if not _undecided_too_long(job):
                log.warning(
                    "restore %s: cannot tell whether the restored guest committed (%s) — "
                    "deciding next tick",
                    job.job_id,
                    exc,
                )
                return
            # The KBS has been unreadable for another full phase: stop
            # waiting, keep the original, and hand it to an operator.
            verdict, why = UNDECIDABLE, f"kbs-unreadable:{str(exc)[:60]}"
        if verdict == NOT_COMMITTED:
            log.error(
                "restore %s: failed before the commit point (%s) — reverting vm %s to its "
                "original on %s",
                job.job_id,
                reason,
                job.vm.vm_id,
                job.source_node_id,
            )
            service._cas_migration(
                job, MigrationState.RESTORE_REVERTING.value, {"reason": reason[:256]}
            )
            return
        prefix = "failed-after-commit" if verdict == COMMITTED else "blocked:commit-undecidable"
        _fail_after_commit(job, f"{prefix}:{reason}", why)
        if verdict == COMMITTED:
            _stamp_committed(job)
        return
    if state == MigrationState.RESTORE_UNDOING.value:
        vm = Vm.objects.get(id=job.vm_id)
        # The undo record as stored NOW: another tick may have armed and
        # sent the swap since this one read the job.
        fresh = MigrationJob.objects.filter(id=job.id).values_list("undo", flat=True).first()
        job.undo = fresh if isinstance(fresh, dict) else job.undo
        if _undo_past_swap(job, vm):
            # The original is back on the live paths and relaunched: it can
            # ONLY unlock through the undo's arm. The clock never ends the
            # undo while that arm may still be used — only its delivery (a
            # success), or the arm gone unused (expired, cleared).
            undo_event = _event(job, RollbackPurpose.UNDO.value)
            try:
                verdict, record = _undo_release_state(job, vm, undo_event)
            except EffectError as exc:
                if not _undecided_too_long(job):
                    log.warning(
                        "restore %s: the undo's release cannot be read (%s) — deciding "
                        "next tick",
                        job.job_id,
                        exc,
                    )
                    return
                verdict, record = "unknown", None
            if verdict == "delivered" and record is not None:
                _finish_undo(job, vm, undo_event, record)
                return
            if verdict == "pending" and (
                (job.undo or {}).get("armed") or not _undecided_too_long(job)
            ):
                # With an arm: never on the clock (the arm's own expiry
                # bounds it). With none: nothing can brick, so only up to
                # twice the deadline.
                log.warning(
                    "restore %s: the undo is past its deadline but the original may still "
                    "unlock — waiting for it",
                    job.job_id,
                )
                return
        given_back = False
        if not _undo_past_swap(job, vm):
            # The original was never swapped back: the VM goes back to the
            # restored disk instead of staying fenced.
            try:
                given_back = (
                    _undo_give_back(job, vm, int((job.undo or {}).get("undo_gen") or 0))
                    is not None
                )
            except Exception as exc:  # noqa: BLE001 — the job still ends; a resume finishes it
                log.error(
                    "restore %s: could not give vm %s back after the failed undo (%s) — it "
                    "stays fenced; asking the undo again resumes it",
                    job.job_id,
                    job.vm.vm_id,
                    exc,
                )
        log.error(
            "restore %s: the operator UNDO failed (%s) — vm %s %s; an operator must look (the "
            "original disk is still on %s)",
            job.job_id,
            reason,
            job.vm.vm_id,
            "was given back to the restored disk" if given_back else "may be fenced",
            job.source_node_id,
        )
        with transaction.atomic():
            service._fail_migration(job, reason=f"undo-failed:{reason}")
            if MigrationJob.objects.filter(
                id=job.id, state=MigrationState.FAILED.value, reverted=False
            ).exists():
                _note_undo(
                    job,
                    outcome="failed",
                    reason=reason[:256],
                    given_back=given_back,
                    only_pending=True,
                )
        return
    if state == MigrationState.RESTORE_REVERTING.value:
        log.error(
            "restore %s: the REVERT failed (%s) — vm %s stays fenced; an operator must "
            "look (the original disk is still on %s)",
            job.job_id,
            reason,
            job.vm.vm_id,
            job.source_node_id,
        )
        service._fail_migration(job, reason=f"revert-failed:{reason}")
        if "revert-raced-commit:" in reason:
            _stamp_committed(job)
        return
    service._fail_migration(job, reason=reason)


def _stamp_committed(job: MigrationJob) -> None:
    """Record the commit point on a job that failed past it (the restored
    guest released its key at `new_gen`): `committed_at` says when vali saw
    the job committed, whatever became of it after."""
    MigrationJob.objects.filter(id=job.id, committed_at__isnull=True).update(
        committed_at=timezone.now()
    )


def _undecided_too_long(job: MigrationJob) -> bool:
    """The phase is past TWICE its deadline: long enough to stop waiting for
    a KBS that cannot be read."""
    from . import service

    elapsed = (timezone.now() - job.phase_started_at).total_seconds()
    return elapsed > 2 * service._job_timeout(job)


def _fail_after_commit(job: MigrationJob, reason: str, committed: str) -> None:
    """Fail a job that may be past its commit point: nothing is reverted and
    the original disk is kept."""
    from . import service

    keep_until = timezone.now() + timedelta(seconds=keep_original_s())
    service._fail_migration(job, reason=reason)
    MigrationJob.objects.filter(id=job.id, state=MigrationState.FAILED.value).update(
        restore_keep_original_until=keep_until
    )
    log.error(
        "restore %s: FAILED, possibly after the commit point (%s; %s) — vm %s is fenced "
        "on %s at generation %d and the ORIGINAL disk is kept on %s until %s. An "
        "operator must look.",
        job.job_id,
        reason,
        committed,
        job.vm.vm_id,
        job.dest_node_id,
        job.new_gen,
        job.dest_node_id,
        keep_until.isoformat(),
    )


def on_timeout(job: MigrationJob) -> None:
    tag = {
        MigrationState.RESTORE_STAGING.value: "stage-timeout",
        MigrationState.RESTORE_STOPPING.value: "stop-timeout",
        MigrationState.DEST_ACTIVATING.value: "activate-timeout",
        MigrationState.RESTORE_VERIFYING.value: "verify-timeout",
        MigrationState.RESTORE_REVERTING.value: "revert-timeout",
        MigrationState.RESTORE_UNDOING.value: "undo-timeout",
    }.get(job.state, f"{job.state}:timeout")
    fail(job, tag)


# ─── revert (pre-commit failure) ─────────────────────────────────────


def _key(job: MigrationJob, step: str) -> str:
    return f"migration:{job.job_id}:{step}"


def _done(key: str) -> bool:
    return idempotency.recall(key) is not None


def _record(key: str) -> None:
    try:
        idempotency.record(key, idempotency.marker_hash(key))
    except IdempotencyUnavailable as exc:
        log.warning("idempotency: record failed for %s: %s", key, exc)


def h_reverting(job: MigrationJob) -> Any:
    """Put the original back exactly as it was, one idempotent step per
    tick where a step needs a peer:

    1. KBS `activate` at `new_gen + 1` on the SOURCE chip — forward-only,
       and it fences the restored guest from any future release;
    2. re-check the commit evidence: a restored guest that released inside
       the activate race means the original can no longer unlock — the job
       fails for an operator instead of relaunching a guest into a 403;
    3. `restore` op=abort on the destination (destroys the staged domain,
       swaps the original files back, drops the staging directory);
    4. the VM back to `Active` on its source at `new_gen + 1`;
    5. the original relaunched at that generation — only if it was running.
    """

    revert_gen = job.new_gen + 1
    vm = Vm.objects.get(id=job.vm_id)
    if vm.state == VmState.MIGRATING:
        if is_rollback(job):
            # Withdraw the arm FIRST: from then on no release can commit the
            # rollback, and the commit re-check below sees any that did.
            # An arm the KBS reports consumed but NOT delivered (or reverted)
            # never gave the restored guest its key: that is no commit.
            disarm_key = _key(job, "revert-disarm")
            if not _done(disarm_key):
                event = _event(job)
                if event is not None:
                    verdict, record = disarm_rollback(job.vm.vm_id, event)
                    if verdict == DISARM_CONSUMED:
                        _note_committed(event, record or {})
                        raise StepFailed("blocked:revert-raced-commit:kbs-rollback-consumed")
                _record(disarm_key)
        key = _key(job, "revert-activate")
        if not _done(key):
            effects.kbs_activate_dest(
                vm, dest_node_id=job.source_node_id, new_gen=revert_gen, get_url=""
            )
            _record(key)
        # Re-decided AFTER the fencing activate: a release that landed in
        # between is the one thing a revert must never run over.
        verdict, why = commit_state(job)
        if verdict == COMMITTED:
            raise StepFailed(f"blocked:revert-raced-commit:{why}")
        if verdict == UNDECIDABLE:
            raise StepFailed(f"blocked:commit-undecidable:{why}")
        _abort_on_dest(job, "revert")
        _confirm_aborted(job)
        _unfence_to_source(job, vm, revert_gen)
        vm = Vm.objects.get(id=job.vm_id)
    elif (
        vm.state == VmState.ACTIVE
        and vm.host == job.source_node_id
        and vm.generation == job.source_gen
    ):
        # Never fenced (the failure came before the fence landed): the KBS
        # never moved either — the fence precedes the KBS activate. Only
        # the destination's staging is dropped.
        _abort_on_dest(job, "revert")
    if (
        vm.state != VmState.ACTIVE
        or vm.host != job.source_node_id
        or vm.generation not in (revert_gen, job.source_gen)
    ):
        raise StepFailed(f"revert-vm-moved:{vm.state}:{vm.host}:{vm.generation}")
    if (
        job.kind != MigrationKind.FAILOVER.value
        and job.prior_power_state == VmPowerState.RUNNING.value
        and vm.power_state != VmPowerState.RUNNING
    ):
        # (A failover's source is dead: nothing to relaunch there now. The
        # VM is back `Active` on it at the new generation, and
        # reboot-recovery relaunches it there if the miner returns.)
        from .services import power

        try:
            power.start_vm(vm, by_migration=True)
        except power.PowerOpRefused as exc:
            if exc.reason == power.DISKS_MISSING_REASON:
                raise StepFailed("revert-relaunch-disks-missing") from exc
            raise EffectError(f"revert relaunch refused: {exc.reason}") from exc
        return None
    log.warning(
        "restore %s: REVERTED — vm %s is back on %s at generation %d (%s)",
        job.job_id,
        vm.vm_id,
        job.source_node_id,
        vm.generation,
        job.prior_power_state or "running",
    )
    return MigrationState.FAILED.value, {
        "reverted": True,
        "failed_from_state": MigrationState.RESTORE_REVERTING.value,
    }


def _abort_on_dest(job: MigrationJob, why: str) -> None:
    """`restore` op=abort on the destination, once per job and purpose. A
    refusal is retried under a fresh order id each minute (the miner replays
    an order id's first answer)."""
    key = _key(job, f"{why}-abort")
    if _done(key):
        return
    bucket = int((timezone.now() - job.phase_started_at).total_seconds() // 60)
    try:
        effects.dispatch_restore(
            miner_id=job.dest_node_id,
            order_id=f"restore-abort-{job.restore_id}-{why}-{bucket}",
            payload=_order(job, "abort", disk_bytes=0),
            in_flight_ok=False,
        )
    except effects.RestoreRejected as exc:
        raise EffectError(f"abort refused: {exc.classifier}") from exc
    _record(key)


def _confirm_aborted(job: MigrationJob) -> None:
    """The destination reports the abort finished: nothing known for the VM,
    another restore, or ours `aborted` with no live domain. Anything else
    (an abort still swapping files back) is retried — the source is never
    relaunched over a destination still busy with this restore."""
    status = _poll_status(job)
    if status is None or status.restore_id != job.restore_id:
        return
    if status.state == "aborted" and not status.domain_live:
        return
    raise EffectError(
        f"abort not finished on {job.dest_node_id} (state={status.state}, "
        f"domain_live={status.domain_live})"
    )


def _unfence_to_source(job: MigrationJob, vm: Vm, revert_gen: int) -> None:
    """CAS `Migrating{new_gen, dest}` → `Active{new_gen + 1, source}`. The
    KBS already holds `Migrating{new_gen + 1, source}` (step 1), which
    releases exactly what `Active` at that generation would."""
    updated = Vm.objects.filter(
        id=vm.id,
        version=vm.version,
        state=VmState.MIGRATING.value,
        migration_dest=job.dest_node_id,
        new_generation=job.new_gen,
    ).update(
        state=VmState.ACTIVE.value,
        generation=revert_gen,
        host=job.source_node_id,
        migration_dest="",
        new_generation=None,
        version=vm.version + 1,
    )
    if not updated:
        raise EffectError("vm changed concurrently during the revert")


# ─── cleanup of failed restores ──────────────────────────────────────


def sweep_restore_cleanups(*, limit: int = 10) -> int:
    """Finish the cleanup a failed restore owes (`restore_cleanup_pending`):
    drop the destination's staging directory and, when the job stopped a
    running VM, start it again — unless the tenant changed its power state
    since. Returns the number of jobs cleaned up. Never raises."""
    cleaned = 0
    jobs = MigrationJob.objects.filter(
        kind__in=RESTORE_KINDS,
        state=MigrationState.FAILED.value,
        restore_cleanup_pending=True,
    ).select_related("vm")[:limit]
    for job in jobs:
        try:
            if _cleanup_one(job):
                cleaned += 1
        except Exception:  # noqa: BLE001 — one job must not kill the sweep
            log.exception("restore %s: cleanup failed", job.job_id)
    return cleaned


def _cleanup_one(job: MigrationJob) -> bool:
    from .services import power

    vm = Vm.objects.filter(id=job.vm_id).first()
    if vm is None or vm.state == VmState.DESTROYED:
        MigrationJob.objects.filter(id=job.id).update(restore_cleanup_pending=False)
        return True
    if job.restore_id:
        try:
            _abort_on_dest(job, "cleanup")
        except EffectError as exc:
            log.warning("restore %s: staging not dropped yet: %s", job.job_id, exc)
            return False
    if _job_stopped_the_vm(job, vm):
        if vm.power_state == VmPowerState.STOPPED:
            running = effects.poll_domain_running_on(vm, vm.host)
            if running is None:
                return False
            if running is False:
                try:
                    power.start_vm(vm)
                except power.PowerOpRefused as exc:
                    log.warning("restore %s: restart refused (%s)", job.job_id, exc.reason)
                    if exc.reason != power.DISKS_MISSING_REASON:
                        return False
                except Exception as exc:  # noqa: BLE001 — retried next tick
                    log.warning("restore %s: restart failed: %s", job.job_id, exc)
                    return False
            else:
                # The domain never went down: the VM runs; say so.
                power._set_power(vm, VmPowerState.RUNNING)
        elif vm.power_state != VmPowerState.RUNNING:
            return False  # a power op in flight — next tick
    MigrationJob.objects.filter(id=job.id).update(restore_cleanup_pending=False)
    log.info("restore %s: cleanup done", job.job_id)
    return True


def _job_stopped_the_vm(job: MigrationJob, vm: Vm) -> bool:
    """The job found the VM running (so any stop since is the job's own) and
    nobody moved its power state since the job ended — or since the job's
    own stop returned, when that was after the job ended (a cancel racing
    the stop)."""
    if job.prior_power_state != VmPowerState.RUNNING.value or vm.state != VmState.ACTIVE:
        return False
    at = vm.power_state_at
    if at is None:
        return False
    marks = [job.finished_at] if job.finished_at is not None else []
    raw = (job.authorization.evidence or {}).get("stopped_by_job_at") if job.authorization else None
    if raw:
        try:
            marks.append(datetime.fromisoformat(str(raw)))
        except ValueError:
            pass
    return not marks or at <= max(marks)


# ─── reclaim (after done, via `service.reclaim_migrated_sources`) ────


def reclaim(job: MigrationJob, vm: Vm) -> None:
    """Delete what the restore left behind, once the restored VM is proven
    (or the VM destroyed): the `*.pre-restore-<id>` files (and staging
    directory) on the destination, and — when the restore moved hosts — the
    source's copy. Raises `EffectError` to retry."""
    destroyed = vm.state == VmState.DESTROYED
    try:
        effects.dispatch_restore(
            miner_id=job.dest_node_id,
            order_id=f"restore-reclaim-{job.restore_id}",
            payload=_order(job, "reclaim", disk_bytes=0),
            in_flight_ok=False,
        )
    except effects.RestoreRejected as exc:
        if not destroyed:
            raise EffectError(f"restore reclaim refused: {exc.classifier}") from exc
        # §24 already destroyed the live files the miner checks its marker
        # on; the key is erased, so what is left is inert ciphertext.
        log.warning(
            "restore %s: reclaim refused after the vm was destroyed (%s) — the "
            "pre-restore files on %s are inert ciphertext",
            job.job_id,
            exc.classifier,
            job.dest_node_id,
        )
    if job.source_node_id and job.source_node_id != job.dest_node_id:
        effects.dispatch_source_reclaim(
            vm, source_node_id=job.source_node_id, job_id=job.job_id
        )


# ─── manual failover (the VM's miner is dead) ─────────────────────────


def failover_enabled() -> bool:
    return bool(getattr(settings, "VALI_FAILOVER_MANUAL_ENABLED", False))


def dead_after_s() -> float:
    return float(getattr(settings, "VALI_FAILOVER_DEAD_AFTER_S", 600.0))


def dead_evidence(vm: Vm, miner_id: str, *, now: Any = None) -> dict[str, Any]:
    """Whether `miner_id` is dead, with the evidence. `dead` only when ALL
    hold: its last heartbeat is at least `VALI_FAILOVER_DEAD_AFTER_S` old,
    its NetBird peer is disconnected (or gone) and was last seen at least
    as long ago, and the Edge cannot reach it now. Anything vali cannot
    read counts against `dead`.

    A partitioned-but-alive host is what this guards against; the KBS
    `activate` to the new generation is what makes a failover safe anyway
    (the old instance never gets a key again)."""
    from apps.miners.geo import match_miner_peer, parse_netbird_ts
    from apps.miners.models import MinerIdentity

    now = now or timezone.now()
    after = dead_after_s()
    evidence: dict[str, Any] = {
        "miner_id": miner_id,
        "checked_at": now.isoformat(),
        "dead_after_s": after,
    }
    miner = MinerIdentity.objects.filter(miner_id=miner_id).first()
    if miner is None:
        evidence.update(dead=False, reason="unknown-miner")
        return evidence

    seen = miner.last_seen_at
    heartbeat_stale = seen is None or (now - seen).total_seconds() >= after
    evidence.update(
        heartbeat_last_seen_at=seen.isoformat() if seen else None,
        heartbeat_stale=heartbeat_stale,
    )

    netbird_dead = False
    try:
        peers = effects.list_netbird_peers()
    except EffectError as exc:
        evidence.update(netbird="unknown", netbird_error=str(exc)[:120])
    else:
        peer = match_miner_peer(
            peers,
            str(miner.netbird_ip) if miner.netbird_ip else None,
            miner.netbird_peer_id or "",
        )
        if peer is None:
            evidence.update(netbird="absent", netbird_connected=False)
            netbird_dead = True
        else:
            connected = bool(peer.get("connected"))
            last = parse_netbird_ts(peer.get("last_seen"))
            evidence.update(
                netbird="present",
                netbird_connected=connected,
                netbird_last_seen_at=last.isoformat() if last else None,
            )
            # A disconnected peer with no readable `last_seen` could have
            # dropped a second ago: unknown, which counts against `dead`.
            netbird_dead = (
                not connected
                and last is not None
                and (now - last).total_seconds() >= after
            )
    evidence["netbird_stale"] = netbird_dead

    edge = effects.probe_edge_session(vm, miner_id)
    evidence["edge"] = edge
    evidence["dead"] = bool(heartbeat_stale and netbird_dead and edge == "unreachable")
    return evidence


class MinerNotDead(RestoreError):
    """`POST /v1/vm/<id>/failover` refused: the evidence does not hold."""

    def __init__(self, evidence: dict[str, Any]) -> None:
        super().__init__("miner-not-dead", "the vm's miner is not proven dead")
        self.evidence = evidence


def _pick_failover_dest(vm: Vm, source: str) -> str:
    """The destination for a failover when the operator names none: a
    dispatchable miner of the source's SNP generation, in the VM's launch
    region when it was sold in one, not cordoned, with room for its flavor —
    the one with the most free memory. `no-eligible-miner` otherwise."""
    from apps.miners.models import MinerIdentity
    from apps.scheduler import service as sched

    region = sched.launch_region_for_vm(vm.vm_id)
    regions = sched.region_by_node() if region else {}
    free = sched.host_resources_by_node()
    # An operator-cordoned miner takes no new work (`_validate_other_dest`
    # refuses it below too; skipping it here keeps the pick honest).
    cordoned = sched.cordoned_node_ids()
    best: tuple[int, str] | None = None
    for miner in MinerIdentity.objects.exclude(miner_id=source).order_by("miner_id"):
        node = (miner.chain_node_id or "").lower()
        if node in cordoned:
            continue
        if region and regions.get(node) != region:
            continue
        try:
            _validate_other_dest(vm, miner.miner_id, source=source)
        except RestoreError:
            continue
        mem = (free.get(miner.chain_node_id or "") or free.get(node))
        score = int(mem.free_memory_mb or 0) if mem is not None else 0
        if best is None or score > best[0]:
            best = (score, miner.miner_id)
    if best is None:
        raise RestoreError(
            "no-eligible-miner",
            "no dispatchable miner of the same SNP generation"
            + (f" in region {region}" if region else "")
            + " has room for the vm",
        )
    return best[1]


def start_failover(
    *,
    vm: Vm,
    request_id: Any,
    decided_by: Any,
    run_id: Any = None,
    dest_node_id: Any = None,
) -> tuple[MigrationJob, bool]:
    """Open a manual failover of `vm` off its dead miner, restoring the
    newest current-boot point (or `run_id`) on another miner. Returns
    `(job, created)`; the same `request_id` returns its job. Raises
    `MinerNotDead` (with the evidence) unless the miner is proven dead, and
    `RestoreError` with the C-2 codes otherwise.

    The job enters `dest_activating` directly (no staging on a dead host,
    no stop possible): the destination downloads the chain as it activates."""
    from apps.backup import service as backup_service

    from . import service

    if not isinstance(request_id, str) or not _REQUEST_ID_RE.fullmatch(request_id):
        raise RestoreError("bad-request", "request_id must match [A-Za-z0-9._:-]{1,128}")
    existing = _job_for_request(request_id)
    if existing is not None:
        return _replay(existing, vm, kind=MigrationKind.FAILOVER.value), False
    if not failover_enabled():
        raise RestoreError("failover-disabled", "manual failover is not enabled on this deployment")
    if run_id is not None and (not isinstance(run_id, str) or not _RUN_ID_RE.fullmatch(run_id)):
        raise RestoreError("bad-request", "run_id must be 32 lower-case hex characters")
    if dest_node_id is not None and (
        not isinstance(dest_node_id, str) or not dest_node_id.strip() or len(dest_node_id) > 64
    ):
        raise RestoreError("bad-request", "dest_node_id must be a non-empty string")
    if vm.state != VmState.ACTIVE or not vm.host:
        raise RestoreError("vm-not-restorable", f"the vm is {vm.state}, not active on a host")
    if service._has_active_job(vm):
        raise RestoreError("job-in-flight", "the vm already has an in-flight orchestration job")
    source = vm.host

    from apps.backup.models import BackupRun

    if run_id is None:
        point = backup_service.restore_point(vm)
        if point is None:
            raise RestoreError(
                "no-backup-point",
                "the vm has no backup point from its current boot to fail over to",
            )
        run = point.latest
    else:
        run = BackupRun.objects.filter(pk=uuid.UUID(hex=run_id), vm=vm).first()
        if run is None:
            raise RestoreError("point-not-restorable", "the vm has no such backup run")
    klass = backup_service.classify_run(vm, run)
    if klass.klass == backup_service.PointClass.ROLLBACK:
        # A failover NEVER rolls back, whatever the flag: a rollback needs a
        # tenant's (or superuser's) explicit acceptance, never an operator
        # reacting to a dead host.
        raise RestoreError(
            "rollback-unsupported", "the point was taken at an earlier boot; a failover never "
            "rolls back"
        )
    if not klass.restorable:
        raise RestoreError("point-not-restorable", "the run is not a restorable point")

    evidence = dead_evidence(vm, source)
    if not evidence.get("dead"):
        raise MinerNotDead(evidence)

    dest = (dest_node_id or "").strip()
    if dest:
        if dest == source:
            raise RestoreError("no-eligible-miner", "the destination is the dead miner")
        _validate_other_dest(vm, dest, source=source)
    else:
        dest = _pick_failover_dest(vm, source)
    _preflight_dest_ticket(vm)

    prior = (
        VmPowerState.STOPPED.value
        if vm.power_state == VmPowerState.STOPPED
        else VmPowerState.RUNNING.value
    )
    eta = backup_service.restore_eta_s(
        klass.runs, throughput_bps=backup_service.dest_throughput_bps(dest)
    )
    now = timezone.now()
    from apps.backup.models import BackupChain

    try:
        with transaction.atomic():
            chain = BackupChain.objects.select_for_update().get(pk=run.chain_id)
            if chain.pruned_at is not None:
                raise RestoreError("point-not-restorable", "the point's chain is being pruned")
            _recheck_no_active_job(vm)
            auth = DestAuthorization.objects.create(
                kind=MigrationKind.FAILOVER.value,
                requested_by=decided_by,
                request_id=request_id,
                evidence={**evidence, "run_id": run.run_id, "dest_node_id": dest},
            )
            job = MigrationJob.objects.create(
                job_id=secrets.token_hex(16),
                kind=MigrationKind.FAILOVER.value,
                vm=vm,
                source_node_id=source,
                dest_node_id=dest,
                source_gen=vm.generation,
                new_gen=vm.generation + 1,
                state=MigrationState.DEST_ACTIVATING.value,
                phase_started_at=now,
                decided_by=decided_by,
                restore_run=run,
                restore_id=secrets.token_hex(16),
                request_id=request_id,
                prior_power_state=prior,
                cold=prior == VmPowerState.STOPPED.value,
                authorization=auth,
                restore_eta_s=eta,
            )
    except IntegrityError as exc:
        existing = _job_for_request(request_id)
        if existing is not None:
            return _replay(existing, vm, kind=MigrationKind.FAILOVER.value), False
        raise RestoreError(
            "job-in-flight", "the vm already has an in-flight orchestration job"
        ) from exc
    log.error(
        "FAILOVER started: job=%s vm=%s off DEAD miner %s → %s, run %s, gen %d→%d "
        "(evidence: heartbeat %s, netbird %s, edge %s)",
        job.job_id,
        vm.vm_id,
        source,
        dest,
        run.run_id,
        job.source_gen,
        job.new_gen,
        evidence.get("heartbeat_last_seen_at"),
        evidence.get("netbird"),
        evidence.get("edge"),
    )
    return job, True


def prepare_failover_activation(job: MigrationJob) -> None:
    """The failover's first steps in `dest_activating`, before the KBS moves:
    while the VM is not fenced yet, the source must STILL be dead (it may
    have come back since the request) — then the fence, the source
    quarantined, and the instant recorded. Idempotent.

    The fence itself (`service._fence_vm`) is called UNCONDITIONALLY, not
    only when `vm.state == Active`: a `MigrationJob`/`DecommissionJob`
    creation race can move the VM to something other than `Active` (or
    already `Migrating` for a DIFFERENT dest/gen) between this job's intake
    and its first tick here, and `_h_mig_dest_activating` would otherwise
    walk straight into `kbs_activate_dest` on an unfenced or wrongly-fenced
    VM. `_fence_vm` itself is the fail-closed check (`vm is ..., not Active
    — cannot fence` / `vm already migrating elsewhere`) and the idempotent
    no-op for a re-entry already fenced for THIS job — the same contract
    `restore.h_stopping`'s dest-activation branch relies on."""
    from . import service
    from .models import FailoverQuarantine

    vm = Vm.objects.get(id=job.vm_id)
    if vm.state == VmState.ACTIVE:
        evidence = dead_evidence(vm, job.source_node_id)
        if not evidence.get("dead"):
            _note_evidence(job, recheck=evidence)
            raise StepFailed("miner-not-dead-at-fence")
        _note_evidence(
            job,
            recheck=evidence,
            source_domain_down=True,
            source_domain_down_at=timezone.now().isoformat(),
        )
    service._fence_vm(job)
    FailoverQuarantine.objects.get_or_create(job=job, defaults={"miner_id": job.source_node_id})


def failover_chain(job: MigrationJob) -> dict[str, Any]:
    """The chain the failover's destination restores as it activates."""
    from apps.backup import service as backup_service

    run = job.restore_run
    if run is None:
        raise StepFailed("failover-no-point")
    try:
        return backup_service.restore_chain(job.vm, run_id=run.run_id, restore_id=job.restore_id)
    except backup_service.BackupError as exc:
        raise StepFailed(f"failover-{exc.code}") from exc


def activate_timeout_s(job: MigrationJob, default: float) -> float:
    """A failover's destination downloads the whole chain inside
    `dest_activating`: three times the ETA when that is longer than the §25
    default, capped at the presigned URLs' 12 h."""
    if job.kind != MigrationKind.FAILOVER.value:
        return default
    return min(12 * 3600.0, max(default, 3 * float(job.restore_eta_s or 0) + 600))


def source_back(job: MigrationJob) -> bool:
    """The failover's dead source heart-beats again (after its quarantine
    began)."""
    from apps.miners.models import MinerIdentity

    from .models import FailoverQuarantine

    q = FailoverQuarantine.objects.filter(job=job).first()
    seen = (
        MinerIdentity.objects.filter(miner_id=job.source_node_id)
        .values_list("last_seen_at", flat=True)
        .first()
    )
    since = q.created_at if q is not None else job.started_at
    return seen is not None and seen > since


def reconcile_failover_quarantines(*, limit: int = 20) -> int:
    """Reappearance reconciliation. For every failed-over miner that heart-
    beats again, force-stop any domain it still runs for a VM the failover
    moved away (the KBS already fences it from any key release; this takes
    it off the host). Its disks are reclaimed by the reclaim sweep once the
    VM is proven on its new host. A VM that is back on that miner because
    ITS OWN job reverted is never touched. Returns the number of stale
    domains stopped. Never raises.

    The query is pre-filtered to quarantines whose miner has ALREADY come
    back (`MinerIdentity.last_seen_at` newer than the quarantine's
    `created_at` — the same threshold `source_back` re-checks per row).
    Open quarantines persist until an operator clears them, so an unfiltered
    `order_by("created_at")[:limit]` would forever hand the sweep the SAME
    oldest still-dead miners and starve every miner that reappears after
    them from ever being polled."""
    from apps.miners.models import MinerIdentity

    from .models import FailoverQuarantine

    reappeared = MinerIdentity.objects.filter(
        miner_id=OuterRef("miner_id"), last_seen_at__gt=OuterRef("created_at")
    )
    stopped = 0
    for q in (
        FailoverQuarantine.objects.filter(cleared_at__isnull=True)
        .annotate(_reappeared=Exists(reappeared))
        .filter(_reappeared=True)
        .select_related("job", "job__vm")
        .order_by("created_at")[:limit]
    ):
        job = q.job
        try:
            if not source_back(job):
                continue  # the annotation's `since` is close but not identical
            if job.reverted:
                # THIS job's own revert put the vm back on q.miner_id —
                # legitimate, not stale. Any other terminal outcome (done
                # elsewhere, failed pre-fence, failed-after-commit with the
                # vm still fenced) leaves a domain here that must never be
                # trusted merely because `vm.host` has not moved yet (it
                # moves only at the restore's OWN commit, in `h_verifying`)
                # or because the vm was later destroyed on its new host.
                continue
            vm = Vm.objects.get(id=job.vm_id)
            if effects.poll_domain_running_on(vm, q.miner_id) is not True:
                continue
            effects.dispatch_force_stop_on(
                vm, node_id=q.miner_id, order_id=f"failover-stop-{vm.vm_id}-{job.job_id}"
            )
            stopped += 1
            log.error(
                "failover: miner %s REAPPEARED still running vm %s, which failed over "
                "(job %s, reverted=%s) — its stale domain was force-stopped; its disks "
                "are reclaimed once the vm is proven on its current host",
                q.miner_id,
                vm.vm_id,
                job.job_id,
                job.reverted,
            )
        except Exception:  # noqa: BLE001 — one miner must not kill the sweep
            log.exception("failover: reconciling %s failed", q.miner_id)
    return stopped


def clear_quarantine(miner_id: str, *, by: str) -> int:
    """Clear every open failover quarantine of `miner_id` (operator only).
    Returns the number cleared."""
    from .models import FailoverQuarantine

    return FailoverQuarantine.objects.filter(miner_id=miner_id, cleared_at__isnull=True).update(
        cleared_at=timezone.now(), cleared_by=by[:128]
    )


# ─── A2: the KBS-authorized rollback ─────────────────────────────────


def is_rollback(job: MigrationJob) -> bool:
    """The job restores a point of an earlier boot, as authorized at
    intake. Only a `restore` can be one: a failover never rolls back (the
    guard refuses a failover authorization that says otherwise)."""
    auth = job.authorization
    return (
        job.kind == MigrationKind.RESTORE.value
        and auth is not None
        and bool(auth.accept_rollback)
    )


def _event(
    job: MigrationJob, purpose: str = RollbackPurpose.RESTORE.value
) -> RollbackEvent | None:
    return RollbackEvent.objects.filter(job=job, purpose=purpose).first()


def _restore_arm_id(job: MigrationJob) -> str:
    """The id the restore's own KBS arm is keyed on."""
    event = _event(job)
    return event.restore_id if event is not None else job.restore_id


@dataclass(frozen=True)
class KbsRollbackView:
    """What the KBS reports now about ONE arm (by its restore id)."""

    #: The KBS serves the rollback routes, with its rollback context.
    served: bool
    #: `last_rollback` when it is this arm's (consumed — delivered or not).
    record: dict[str, Any] | None
    #: This arm is still live (not consumed, not withdrawn, not expired).
    live: bool
    #: `last_clear` — why and when the KBS last cleared the VM's arm.
    clear: dict[str, Any] | None

    @property
    def delivered_record(self) -> dict[str, Any] | None:
        """`record` when its release was DELIVERED (and not reverted): the
        rollback happened. A consumed-but-undelivered record never gave the
        guest its key — it is no commit."""
        from .services import kbs_rollback

        return self.record if kbs_rollback.delivered(self.record) else None


def kbs_view(vm_id: str, restore_id: str) -> KbsRollbackView:
    """Read the KBS's rollback status for `vm_id`, about arm `restore_id`.
    A KBS without the routes (or without its rollback context) reports
    `served=False` and nothing else. Raises `EffectError` when the KBS
    cannot be read — that decides nothing."""
    from .services import kbs_rollback

    try:
        status = kbs_rollback.rollback_status(vm_id)
    except effects.KbsRouteMissing:
        return KbsRollbackView(served=False, record=None, live=False, clear=None)
    last = status.get("last_rollback")
    arm = status.get("arm")
    clear = status.get(kbs_rollback.WIRE_LAST_CLEAR)
    return KbsRollbackView(
        served=True,
        record=last if isinstance(last, dict) and last.get("restore_id") == restore_id else None,
        live=isinstance(arm, dict) and arm.get("restore_id") == restore_id,
        clear=clear if isinstance(clear, dict) else None,
    )


def _dest_platform(node_id: str) -> str:
    from apps.miners.models import MinerIdentity

    platform = (
        MinerIdentity.objects.filter(miner_id=node_id)
        .values_list("platform_id", flat=True)
        .first()
    )
    if not platform:
        raise StepFailed("rollback-dest-chip-unknown")
    return str(platform).lower()


def _arm(
    job: MigrationJob,
    event: RollbackEvent,
    *,
    checkpoint: dict[str, Any],
    manifest: bytes,
    manifest_sha256: str,
    new_gen: int,
    node_id: str,
    requested_by: str,
    not_a_rollback_ok: bool = False,
    terminal: bool = True,
) -> bool:
    """`authorize-rollback` for `event`'s arm: ONE release of the VM at
    `new_gen` on `node_id`'s chip may present the checkpoint's counter + 1.
    Returns True once armed; False only with `not_a_rollback_ok` when the
    KBS says the checkpoint is not behind its counter (nothing to roll
    back). Every other KBS refusal, a KBS without rollbacks and a manifest
    that does not bind the checkpoint are a `StepFailed`; a KBS that cannot
    be reached, or whose admin gateway is busy, raises `EffectError`
    (retried). `terminal=False`: a refusal only records its reason and
    leaves the event `pending` — the caller retries it (the undo)."""
    from .services import kbs_rollback

    if _is_customer_mode(job.vm):
        # Defence in depth behind the intake / undo gates: an M2 VM's
        # rollback belongs to the customer's guardian. Nothing is armed.
        raise StepFailed("rollback-not-capable")
    platform = _dest_platform(node_id)
    # Before the call: from here on an arm may exist even if this process
    # dies before recording it.
    RollbackEvent.objects.filter(
        id=event.id, restore_id=event.restore_id, arm_requested_at__isnull=True
    ).update(
        arm_requested_at=timezone.now()
    )

    def refused(reason: str) -> None:
        if not terminal:
            RollbackEvent.objects.filter(id=event.id, restore_id=event.restore_id).update(
                reason=reason[:256]
            )
            return
        RollbackEvent.objects.filter(id=event.id, restore_id=event.restore_id).update(
            outcome=RollbackOutcome.REFUSED.value, reason=reason[:256]
        )

    try:
        kbs_rollback.authorize_rollback(
            job.vm.vm_id,
            checkpoint_cbor_hex=checkpoint["checkpoint_cbor_hex"],
            signature_hex=checkpoint["signature_hex"],
            manifest_sha256_hex=manifest_sha256,
            manifest=manifest,
            new_gen=new_gen,
            dest_platform_id_hex=platform,
            restore_id=event.restore_id,
            requested_by=requested_by,
            ttl_s=kbs_rollback.ARM_TTL_S,
        )
    except kbs_rollback.PointManifestInvalid as exc:
        refused(f"vali:manifest-mismatch:{exc}")
        raise StepFailed("rollback-manifest-mismatch") from exc
    except kbs_rollback.RollbackRefused as exc:
        if not_a_rollback_ok and exc.reason == "not-a-rollback":
            RollbackEvent.objects.filter(id=event.id, restore_id=event.restore_id).update(
                outcome=RollbackOutcome.ABANDONED.value,
                reason="kbs:not-a-rollback (the counter never moved past the checkpoint)",
            )
            return False
        refused(f"kbs:{exc.reason}")
        if exc.reason == kbs_rollback.REASON_GUEST_NOT_ROLLBACK_CAPABLE:
            # The guest lost (or never had) rollback capability since the
            # intake read: nothing was armed, the restore reverts.
            kbs_rollback.note_rollback_capable(job.vm.vm_id, False)
            raise StepFailed("rollback-not-capable") from exc
        raise StepFailed(f"rollback-refused:{exc.reason}") from exc
    except effects.KbsRouteMissing as exc:
        refused("kbs:route-missing")
        raise StepFailed("rollback-unsupported") from exc
    armed = RollbackEvent.objects.filter(id=event.id, restore_id=event.restore_id)
    if not armed.filter(outcome=RollbackOutcome.PENDING.value).update(
        outcome=RollbackOutcome.ARMED.value, armed_at=timezone.now()
    ) and not armed.filter(outcome=RollbackOutcome.ARMED.value).exists():
        # Re-keyed (a resumed undo) or settled meanwhile: this arm is not
        # the event's any more — nothing may act on it.
        raise EffectError(f"rollback event {event.restore_id} changed during its arm")
    return True


def arm_rollback(job: MigrationJob) -> None:
    """`authorize-rollback` on the KBS, right after the `activate` to
    `new_gen` (the KBS refuses an arm unless its row is exactly
    `Migrating{new_gen, dest chip}`), before the destination is told to
    boot. Every KBS refusal is a `StepFailed` — a pre-commit failure, so the
    restore reverts; an unreachable or busy KBS is retried until the phase
    times out (and reverts)."""
    from apps.backup import service as backup_service

    if not backup_service.rollback_enabled():
        raise StepFailed("rollback-disabled")
    if not is_rollback(job):
        raise StepFailed("rollback-not-authorized")
    auth = job.authorization
    run = job.restore_run
    if (
        auth is None
        or run is None
        or auth.on_behalf_of_kind not in _BEHALF_KINDS
        or not _BEHALF_ID_RE.fullmatch(auth.on_behalf_of_id or "")
    ):
        raise StepFailed("rollback-without-on-behalf-of")
    event = _event(job)
    if event is None:
        raise StepFailed("rollback-without-event")
    checkpoint = backup_service.checkpoint_of(run)
    if checkpoint is None:
        raise StepFailed("rollback-no-checkpoint")
    _arm(
        job,
        event,
        checkpoint=checkpoint,
        manifest=run.manifest_json.encode("utf-8"),
        manifest_sha256=run.manifest_sha256,
        new_gen=job.new_gen,
        node_id=job.dest_node_id,
        requested_by=auth.requested_for,
    )
    log.warning(
        "restore %s: KBS ARMED a rollback of vm %s to boot %s at gen %d on %s (for %s)",
        job.job_id,
        job.vm.vm_id,
        run.boot_counter,
        job.new_gen,
        job.dest_node_id,
        auth.requested_for,
    )


#: `disarm_rollback` verdicts.
DISARM_CONSUMED = "consumed"
DISARM_WITHDRAWN = "withdrawn"
DISARM_ABSENT = "absent"


def disarm_rollback(vm_id: str, event: RollbackEvent) -> tuple[str, dict[str, Any] | None]:
    """Withdraw `event`'s arm on the KBS and say what happened (raises
    `EffectError` to retry):

    - `DISARM_CONSUMED` + the KBS record — a release had already consumed
      it AND it was delivered (the rollback COMMITTED);
    - `DISARM_WITHDRAWN` — vali saw the arm live and unconsumed, deleted it,
      and it is still undelivered after the delete: no release can consume
      it any more. Recorded as `disarmed_at` (`commit_state` relies on it);
    - `DISARM_ABSENT` — there was no arm to withdraw and none delivered.

    A consumed-then-reverted record is no commit: the KBS took the
    authorisation back and the guest never got the key. One still in
    flight after the delete raises `EffectError` (retried).

    The re-read after the delete closes the read/delete race: a release
    that consumed the arm in between is seen, never recorded as abandoned."""
    from .services import kbs_rollback

    before = kbs_view(vm_id, event.restore_id)
    if before.delivered_record is not None:
        return DISARM_CONSUMED, before.delivered_record
    kbs_rollback.disarm(vm_id, event.restore_id)
    after = kbs_view(vm_id, event.restore_id)
    if after.delivered_record is not None:
        return DISARM_CONSUMED, after.delivered_record
    if kbs_rollback.in_flight(after.record):
        # Its authorisation is withdrawn now, so the KBS reverts it; until
        # it says so, nothing is settled.
        raise EffectError(f"kbs-admin: rollback {event.restore_id} still in flight")
    if before.live:
        RollbackEvent.objects.filter(
            id=event.id, restore_id=event.restore_id, disarmed_at__isnull=True
        ).update(
            disarmed_at=timezone.now()
        )
        return DISARM_WITHDRAWN, None
    return DISARM_ABSENT, None


def consumed_rollback(job: MigrationJob) -> dict[str, Any] | None:
    """The KBS's `last_rollback` when it is THIS restore's and was
    delivered, else None. Raises `EffectError` when the KBS cannot be read
    — that decides nothing."""
    return kbs_view(job.vm.vm_id, _restore_arm_id(job)).delivered_record


def rollback_commit_state(job: MigrationJob) -> tuple[str, str] | None:
    """The rollback half of `commit_state` for a job that may have armed the
    KBS: `(COMMITTED, why)` when the KBS reports this restore's arm consumed
    and delivered, `(UNDECIDABLE, why)` when an arm may have existed and
    nothing proves it unconsumed, `None` when the rollback cannot have
    committed (the generic evidence then decides). Raises `EffectError`
    when the KBS cannot be read.

    Absence of a KBS rollback record is NOT evidence: a KBS restart or an
    older KBS image loses it, and an evidence bundle (best-effort, written
    after the release) may still show the original's older grant. So an arm
    counts as unconsumed only on positive proof:

    - the KBS reports it consumed and then reverted, never delivered (one
      consumed and still in flight decides nothing: `EffectError`);
    - vali withdrew it while it was live (`disarmed_at`), it is still live,
      or the KBS refused it;
    - the KBS cleared THIS arm because the VM's normal boot committed
      (`last_clear {restore_id, reason: rollback-cleared-by-boot}`).
      Even then only the generic evidence may say NOT_COMMITTED: a KBS
      grant below `new_gen`, never mere absence."""
    from .services import kbs_rollback

    event = _event(job)
    if event is None or event.arm_requested_at is None:
        return None  # never asked: no arm can exist
    view = kbs_view(job.vm.vm_id, event.restore_id)
    if view.delivered_record is not None:
        # Recorded now: a job that fails after this commit still tells the
        # tenant its VM was rolled back (`rollback.committed_at`).
        _note_committed(event, view.delivered_record)
        return COMMITTED, "kbs-rollback-consumed"
    if kbs_rollback.in_flight(view.record):
        # Consumed, its release still being processed: it may deliver yet.
        # Decides nothing — asked again next tick.
        raise EffectError(f"restore {job.job_id}: the KBS rollback release is in flight")
    if view.record is not None:
        return None  # consumed, then reverted — never delivered: no commit
    if view.live or event.disarmed_at is not None or event.outcome == RollbackOutcome.REFUSED:
        return None
    if kbs_rollback.cleared_by_boot(view.clear, event.restore_id):
        return None
    return UNDECIDABLE, "rollback-arm-unaccounted"


def _released_at_new_gen(job: MigrationJob) -> bool:
    """The KBS evidence shows the restored guest's release at `new_gen` on
    the destination chip. Raises `EffectError` when it cannot be read."""
    from . import service

    return service._kbs_grant_unproven_reason(job, Vm.objects.get(id=job.vm_id)) is None


def _note_committed(event: RollbackEvent | None, record: dict[str, Any]) -> None:
    if event is None:
        return
    at = timezone.now()
    raw = record.get("consumed_at_unix")
    if isinstance(raw, int) and not isinstance(raw, bool) and raw > 0:
        at = datetime.fromtimestamp(raw, tz=UTC)
    RollbackEvent.objects.filter(
        id=event.id, restore_id=event.restore_id, committed_at__isnull=True
    ).update(
        outcome=RollbackOutcome.COMMITTED.value, committed_at=at, kbs_record=record
    )
    log.warning(
        "restore %s: vm %s ROLLED BACK (%s; KBS consumed and delivered arm %s: %s)",
        event.job.job_id,
        event.vm.vm_id,
        event.purpose,
        event.restore_id,
        record,
    )


def _note_rollback_released(job: MigrationJob) -> None:
    """A rollback restore's disk (an earlier boot) released at `new_gen` on
    the destination: only this restore's arm can have allowed it. Record the
    commit now, from the KBS's `last_rollback` when it still has it, else as
    `committed-unverified` (a KBS restart lost it). A KBS that cannot be read
    now records nothing — the sweep does it later."""
    event = _event(job)
    if event is None or event.committed_at is not None:
        return
    try:
        record = kbs_view(job.vm.vm_id, event.restore_id).delivered_record
    except EffectError as exc:
        log.warning("restore %s: rollback record unreadable now (%s)", job.job_id, exc)
        return
    if record is not None:
        _note_committed(event, record)
    else:
        _note_committed_unverified(event, "kbs-grant-at-new-gen")


def _note_committed_unverified(event: RollbackEvent | None, why: str) -> None:
    """The rollback committed on the KBS's release evidence, without its
    `last_rollback` record (lost to a KBS restart): `committed-unverified`,
    `committed_at` now. Never over a commit already recorded."""
    if event is None or event.arm_requested_at is None:
        return
    updated = RollbackEvent.objects.filter(
        id=event.id,
        restore_id=event.restore_id,
        committed_at__isnull=True,
        outcome__in=[RollbackOutcome.PENDING.value, RollbackOutcome.ARMED.value],
    ).update(
        outcome=RollbackOutcome.COMMITTED_UNVERIFIED.value,
        committed_at=timezone.now(),
        reason=f"committed-unverified:{why}"[:256],
    )
    if updated:
        log.warning(
            "restore %s: vm %s ROLLED BACK (%s; the KBS no longer holds the record of arm %s: %s)",
            event.job.job_id,
            event.vm.vm_id,
            event.purpose,
            event.restore_id,
            why,
        )


def sweep_rollback_events(*, limit: int = 20) -> int:
    """Settle every rollback whose job ended without a commit being
    recorded: if the KBS says the arm was consumed and delivered, record the
    commit (the job failed after it); otherwise WITHDRAW any arm still
    there and mark it abandoned. So no arm outlives its job, whatever path
    failed it. Returns the number settled. Never raises."""
    settled = 0
    unsettled = [RollbackOutcome.PENDING.value, RollbackOutcome.ARMED.value]

    def still(event: RollbackEvent) -> Any:
        # The event as this sweep read it: a resumed undo re-keys its event
        # (a fresh arm id, `_resume_undo`), and is never settled from here.
        return RollbackEvent.objects.filter(
            id=event.id, restore_id=event.restore_id, outcome__in=unsettled
        )

    for event in (
        RollbackEvent.objects.filter(
            outcome__in=unsettled,
            job__state__in=list(TERMINAL_MIGRATION_STATES),
        )
        .select_related("job", "job__vm", "job__authorization", "vm")
        .order_by("created_at")[:limit]
    ):
        job = event.job
        try:
            why = job.reason or job.state
            if event.purpose == RollbackPurpose.UNDO.value and _undo_past_swap(
                job, Vm.objects.get(id=job.vm_id)
            ):
                # The relaunched original needs this arm: never withdrawn.
                verdict, record = _undo_release_state(job, job.vm, event)
                if verdict == "pending":
                    continue
                if verdict == "delivered" and record is not None:
                    with transaction.atomic():
                        _note_committed(event, record)
                        _late_undo_success(job)
                    settled += 1
                    continue
                still(event).update(
                    outcome=RollbackOutcome.ABANDONED.value, reason=f"arm-unused:{why}"[:256]
                )
                settled += 1
                continue
            if event.arm_requested_at is not None:
                verdict, record = disarm_rollback(job.vm.vm_id, event)
                if verdict == DISARM_CONSUMED:
                    _note_committed(event, record or {})
                    settled += 1
                    continue
                if event.purpose == RollbackPurpose.RESTORE.value and (
                    _released_at_new_gen(job)
                ):
                    # No record of its consumption (a KBS restart lost it),
                    # but the restored disk released at `new_gen`: only the
                    # arm can have allowed that.
                    _note_committed_unverified(event, "kbs-grant-at-new-gen")
                    settled += 1
                    continue
                if verdict == DISARM_ABSENT:
                    why = f"arm-not-found:{why}"
            still(event).update(outcome=RollbackOutcome.ABANDONED.value, reason=why[:256])
            settled += 1
        except EffectError as exc:
            log.warning("restore %s: rollback arm not settled yet: %s", job.job_id, exc)
        except Exception:  # noqa: BLE001 — one job must not kill the sweep
            log.exception("restore %s: settling the rollback failed", job.job_id)
    return settled


# ─── undo: put the ORIGINAL back after the commit point (operator) ───
#
# A restore that failed AFTER its commit point left the original disk on the
# host (`*.pre-restore-<restore_id>`, or untouched on another source) and the
# restored guest holding the VM's counter. The original is then itself an
# older state, so bringing it back is a rollback: to the KBS checkpoint vali
# took of the original right before the fence (`_capture_original_checkpoint`),
# through the same `authorize-rollback` machinery, under its own arm id.
#
# `restore_undoing`, one idempotent step per tick where a peer is involved:
#   1. fence the VM `Migrating{undo_gen, source}` (from `Migrating{new_gen,
#      dest}` — the job failed fenced — or `Active{new_gen, dest}` — the
#      restored VM was activated but never proved alive);
#   2. KBS `activate` at `undo_gen` on the source chip: the restored guest can
#      never be released a key again, and the KBS clears any pending arm;
#   3. arm the rollback (the original's checkpoint + manifest). `not-a-rollback`
#      means the KBS counter never moved past the original: it boots as is;
#   4. `restore` op=abort on the destination: the restored guest down, the
#      retained originals renamed back over the live paths (the miner-agent's
#      existing abort — no new miner operation);
#   5. `Active{undo_gen, source}`, and the original relaunched there;
#   6. done once the KBS reports the arm consumed and delivered (or, with no
#      arm, a KBS grant at `undo_gen`): the job ends `failed`, `reverted`.

#: The C-5 `on_behalf_of.kind` an undo requires.
_UNDO_BEHALF_KIND = "superuser"


def original_checkpoint(job: MigrationJob) -> dict[str, Any] | None:
    """The job's checkpoint of its ORIGINAL when an undo can use it: about
    this VM, stamped, timeline-bound (V2), and embedded in the job's own
    manifest bytes."""
    from .services import kbs_rollback

    cp = job.original_checkpoint
    if not isinstance(cp, dict) or not job.original_manifest:
        return None
    body = cp.get("checkpoint")
    if not isinstance(body, dict) or body.get("vm_id") != job.vm.vm_id:
        return None
    stamp = body.get("volume_stamp")
    if isinstance(stamp, bool) or not isinstance(stamp, int) or stamp <= 0:
        return None
    # A V1 checkpoint names no timeline: the KBS never arms it.
    if not kbs_rollback.checkpoint_is_timeline_bound(cp):
        return None
    cbor_hex = cp.get("checkpoint_cbor_hex")
    if not isinstance(cbor_hex, str) or not isinstance(cp.get("signature_hex"), str):
        return None
    manifest = job.original_manifest.encode("utf-8")
    try:
        kbs_rollback.check_point_manifest(
            manifest,
            vm_id=job.vm.vm_id,
            sha256_hex=hashlib.sha256(manifest).hexdigest(),
            checkpoint_cbor_hex=cbor_hex,
        )
    except kbs_rollback.PointManifestInvalid:
        return None
    return cp


def _undo_gen(job: MigrationJob) -> int:
    """The generation the original relaunches at: past both `new_gen` and
    the `new_gen + 1` a pre-commit revert may already have activated."""
    return job.new_gen + 2


def _undo_shape(job: MigrationJob, vm: Vm) -> str | None:
    """`fenced` (the job failed with the VM `Migrating{new_gen, dest}`),
    `activated` (the restored VM was activated on the destination but never
    proved alive), or None — the VM moved on since and nothing is undone."""
    if (
        job.state == MigrationState.FAILED.value
        and vm.state == VmState.MIGRATING
        and vm.migration_dest == job.dest_node_id
        and vm.new_generation == job.new_gen
    ):
        return "fenced"
    if (
        job.state == MigrationState.DONE.value
        and phase(job) == "failed"
        and vm.state == VmState.ACTIVE
        and vm.host == job.dest_node_id
        and vm.generation == job.new_gen
    ):
        return "activated"
    return None


def start_undo(
    *, job: MigrationJob, decided_by: Any, on_behalf_of: Any
) -> tuple[MigrationJob, bool]:
    """Put the ORIGINAL of a restore that failed after its commit point
    back (`POST /v1/vm/<id>/restore/<job_id>/revert`). Operator-only:
    `on_behalf_of.kind` must be `superuser`. Returns `(job, started)`; a
    job already undoing (or undone) answers itself. Raises `RestoreError`:

    - `on-behalf-of-required` / `revert-superuser-only`;
    - `rollback-unsupported` (the flag is off, or the KBS lacks rollbacks);
    - `revert-not-applicable` — not a restore that failed after its commit
      point, the VM moved on since, the host no longer holds the original
      (asked of the miner), or an earlier undo failed;
    - `revert-cross-host-unsupported` — the restore moved hosts (only a
      same-host restore's retained original is verified and swapped back);
    - `restore-unavailable` — the host cannot be asked whether it still
      holds the original;
    - `revert-no-checkpoint` — no usable KBS checkpoint of the original was
      taken before the fence;
    - `revert-not-ready` — the restore's own rollback is not settled yet;
    - `rollback-rate-limited` / `job-in-flight` / `restore-unavailable`;
    - `rollback-not-capable` for an M2 (`key_mode=customer`) VM, always: an
      undo is a KBS-authorized rollback, which an M2 VM never gets
      (`_refuse_kbs_rollback_of_m2`). So an M2 restore, once past its commit
      point, CANNOT be undone — the operator must say so before starting one."""
    from apps.backup import service as backup_service

    behalf = parse_on_behalf_of(on_behalf_of)
    if behalf is None:
        raise RestoreError(
            "on-behalf-of-required", "an undo must say on whose behalf it is asked"
        )
    if behalf[0] != _UNDO_BEHALF_KIND:
        raise RestoreError(
            "revert-superuser-only", "only a superuser may put a restore's original back"
        )
    job = MigrationJob.objects.select_related("vm", "restore_run", "authorization").get(
        id=job.id
    )
    if isinstance(job.undo, dict):
        if job.undo.get("outcome") == "failed":
            if not enabled() or not backup_service.rollback_enabled():
                raise RestoreError(
                    "rollback-unsupported",
                    "putting a restore's original back needs rollbacks enabled",
                )
            resumed = _resume_undo(job, decided_by=decided_by, behalf=behalf)
            if resumed is not None:
                return resumed, True
            raise RestoreError(
                "revert-not-applicable",
                f"the undo already failed ({job.undo.get('reason') or job.reason}); an "
                "operator must look",
            )
        return job, False  # asked before: answer it
    if not enabled() or not backup_service.rollback_enabled():
        raise RestoreError(
            "rollback-unsupported", "putting a restore's original back needs rollbacks enabled"
        )
    if job.kind != MigrationKind.RESTORE.value or job.reverted:
        raise RestoreError("revert-not-applicable", "not a restore that failed after its commit")
    vm = Vm.objects.get(id=job.vm_id)
    shape = _undo_shape(job, vm)
    if shape is None:
        raise RestoreError(
            "revert-not-applicable",
            f"the restore is {phase(job)} and the vm is {vm.state} on {vm.host} at "
            f"generation {vm.generation}: nothing to put back",
        )
    if job.source_reclaim_state == SourceReclaimState.RECLAIMED.value:
        raise RestoreError("revert-not-applicable", "the original was already reclaimed")
    from . import service

    if service._has_active_job(vm):
        raise RestoreError(
            "job-in-flight", "the vm has an in-flight migration or decommission"
        )
    if job.dest_node_id != job.source_node_id:
        raise RestoreError(
            "revert-cross-host-unsupported",
            "the restore moved hosts; only a same-host restore's retained original can be "
            "put back (and verified present) here",
        )
    checkpoint = original_checkpoint(job)
    if checkpoint is None:
        raise RestoreError(
            "revert-no-checkpoint",
            "no usable KBS checkpoint of the original was taken before the fence",
        )
    try:
        missing = _original_missing(job)
    except EffectError as exc:
        raise RestoreError(
            "restore-unavailable", f"could not ask {job.dest_node_id} for the original: {exc}"
        ) from exc
    if missing:
        raise RestoreError(
            "revert-not-applicable",
            f"{job.dest_node_id} does not hold this restore's original any more ({missing})",
        )
    if RollbackEvent.objects.filter(
        job=job,
        purpose=RollbackPurpose.RESTORE.value,
        outcome__in=[RollbackOutcome.PENDING.value, RollbackOutcome.ARMED.value],
    ).exists():
        raise RestoreError(
            "revert-not-ready", "the restore's own rollback is not settled yet; retry shortly"
        )
    _rollback_gate(vm)

    now = timezone.now()
    undo = {
        "restore_id": secrets.token_hex(16),
        "undo_gen": _undo_gen(job),
        "shape": shape,
        "from_state": job.state,
        "from_reason": job.reason or "",
        "requested_by": {"kind": behalf[0], "id": behalf[1]},
        "decided_by": getattr(decided_by, "name", None) or "operator",
        "requested_at": now.isoformat(),
        "armed": None,
        "outcome": "pending",
    }
    body = checkpoint.get("checkpoint") or {}
    try:
        with transaction.atomic():
            # The VM's row first, like every job intake (§25, §24, restore,
            # resize): no other job starts beside the undo, and the lock
            # order is the same on every path.
            _recheck_no_active_job(vm)
            # Serialised with the reclaim sweep on the job row: a reclaim
            # that got there first has recorded `reclaimed` (refused here);
            # one that comes after finds the job taken and skips it. The
            # original is never reclaimed automatically from now on.
            updated = (
                MigrationJob.objects.filter(
                    id=job.id, version=job.version, state=job.state, undo__isnull=True
                )
                .exclude(source_reclaim_state=SourceReclaimState.RECLAIMED.value)
                .update(
                    state=MigrationState.RESTORE_UNDOING.value,
                    version=job.version + 1,
                    phase_started_at=now,
                    undo=undo,
                    source_reclaim_state=SourceReclaimState.SKIPPED.value,
                    source_reclaim_reason="undo-requested",
                    restore_keep_original_until=None,
                )
            )
            if not updated:
                raise RestoreError("job-in-flight", "the restore job changed meanwhile; retry")
            from apps.backup.models import BackupPolicy

            policy = BackupPolicy.objects.filter(vm=vm).first()
            policy_counter = policy.observed_boot_counter if policy else None
            RollbackEvent.objects.create(
                vm=vm,
                job=job,
                purpose=RollbackPurpose.UNDO.value,
                run=None,
                restore_id=undo["restore_id"],
                from_boot_counter=policy_counter,
                to_boot_counter=int(body.get("boot_counter") or 0),
                point_taken_at=datetime.fromtimestamp(
                    int(body.get("issued_at_unix") or 0), tz=UTC
                ),
                manifest_sha256=hashlib.sha256(
                    job.original_manifest.encode("utf-8")
                ).hexdigest(),
                requested_by_kind=behalf[0],
                requested_by_id=behalf[1],
            )
    except IntegrityError as exc:
        raise RestoreError(
            "job-in-flight", "the vm already has an in-flight orchestration job"
        ) from exc
    log.warning(
        "restore %s: UNDO asked by %s for %s:%s — vm %s goes back to its ORIGINAL on %s at "
        "generation %d, as a KBS-authorized rollback to boot %s",
        job.job_id,
        undo["decided_by"],
        behalf[0],
        behalf[1],
        vm.vm_id,
        job.source_node_id,
        undo["undo_gen"],
        body.get("boot_counter"),
    )
    return MigrationJob.objects.select_related("vm", "restore_run", "authorization").get(
        id=job.id
    ), True


def _resume_undo(
    job: MigrationJob, *, decided_by: Any, behalf: tuple[str, str]
) -> MigrationJob | None:
    """Resume a FAILED undo of `job` that left the VM fenced
    `Migrating{undo_gen, source}` (its give-back could not reach the KBS, or
    was never reached) and never swapped the original back: back to
    `restore_undoing`, outcome `pending`, the arm decided afresh (the KBS
    answers a re-arm of a still-live arm id idempotently). A started
    give-back is finished instead of re-arming. None when not resumable.
    Raises `RestoreError` (`revert-not-ready`) while the undo's rollback
    event is not settled yet — the sweep may still be withdrawing its arm."""
    from . import service

    undo = dict(job.undo or {})
    vm = Vm.objects.get(id=job.vm_id)
    undo_gen = _undo_gen(job)
    if (
        job.kind != MigrationKind.RESTORE.value
        or job.state != MigrationState.FAILED.value
        or job.reverted
        or int(undo.get("undo_gen") or 0) != undo_gen
        or vm.state != VmState.MIGRATING
        or vm.migration_dest != job.source_node_id
        or vm.new_generation != undo_gen
        or _undo_past_swap(job, vm)
    ):
        return None
    if service._has_active_job(vm):
        raise RestoreError("job-in-flight", "the vm has an in-flight migration or decommission")
    event = _event(job, RollbackPurpose.UNDO.value)
    if event is None:
        return None
    if event.outcome in (RollbackOutcome.PENDING.value, RollbackOutcome.ARMED.value):
        raise RestoreError(
            "revert-not-ready", "the failed undo's arm is not settled yet; retry shortly"
        )
    if event.outcome == RollbackOutcome.COMMITTED.value:
        return None
    now = timezone.now()
    for stale in ("reason", "armed", "arm_refused_at", "arm_refused_reason", "given_back"):
        undo.pop(stale, None)
    if not undo.get("give_back_at"):
        # A fresh arm id: a sweep still holding the settled event can only
        # ever withdraw the OLD arm, never the resumed undo's.
        undo["previous_restore_ids"] = [
            *list(undo.get("previous_restore_ids") or []),
            undo.get("restore_id"),
        ]
        undo["restore_id"] = secrets.token_hex(16)
    undo.update(
        armed=None,
        outcome="pending",
        resumed_at=now.isoformat(),
        resumed_by=getattr(decided_by, "name", None) or "operator",
        resumed_for={"kind": behalf[0], "id": behalf[1]},
        resumes=int(undo.get("resumes") or 0) + 1,
    )
    try:
        with transaction.atomic():
            if not MigrationJob.objects.filter(
                id=job.id, version=job.version, state=MigrationState.FAILED.value, reverted=False
            ).update(
                state=MigrationState.RESTORE_UNDOING.value,
                version=job.version + 1,
                phase_started_at=now,
                undo=undo,
            ):
                raise RestoreError("job-in-flight", "the restore job changed meanwhile; retry")
            if not undo.get("give_back_at"):
                if not RollbackEvent.objects.filter(
                    id=event.id,
                    restore_id=event.restore_id,
                    outcome=event.outcome,
                    committed_at__isnull=True,
                ).update(
                    restore_id=undo["restore_id"],
                    outcome=RollbackOutcome.PENDING.value,
                    reason="",
                    arm_requested_at=None,
                    armed_at=None,
                    disarmed_at=None,
                ):
                    raise RestoreError("job-in-flight", "the undo's arm changed meanwhile; retry")
    except IntegrityError as exc:
        raise RestoreError(
            "job-in-flight", "the vm already has an in-flight orchestration job"
        ) from exc
    log.warning(
        "restore %s: UNDO RESUMED by %s for %s:%s — vm %s is still fenced at gen %d on %s",
        job.job_id,
        undo["resumed_by"],
        behalf[0],
        behalf[1],
        vm.vm_id,
        undo_gen,
        job.source_node_id,
    )
    return MigrationJob.objects.select_related("vm", "restore_run", "authorization").get(
        id=job.id
    )


def _original_missing(job: MigrationJob) -> str | None:
    """Why the host does NOT hold this restore's retained original (the
    `*.pre-restore-<restore_id>` files the undo swaps back), or None when it
    does — asked of the miner itself, never inferred from vali's rows (a
    reclaim can delete them and die before vali records it). Raises
    `EffectError` when the miner cannot be asked."""
    status = _poll_status(job)
    if status is None:
        return "no-restore-status"
    if status.restore_id != job.restore_id:
        return f"another-restore:{status.restore_id}"
    if status.state == "reclaimed":
        return "reclaimed"
    if not status.pre_restore_present:
        return "no-pre-restore-files"
    return None


def _check_attempt(undo: dict[str, Any], attempt: str | None) -> None:
    if attempt is not None and undo.get("restore_id") != attempt:
        raise EffectError(f"the undo attempt changed ({attempt} is no longer current)")


def _note_undo(
    job: MigrationJob, *, only_pending: bool = False, attempt: str | None = None, **fields: Any
) -> None:
    """Merge `fields` into the job's undo record, under its row lock.
    `only_pending`: only while the outcome is still `pending` (a failure
    never overwrites a success recorded meanwhile)."""
    with transaction.atomic():
        locked = MigrationJob.objects.select_for_update().get(id=job.id)
        undo = dict(locked.undo or {})
        _check_attempt(undo, attempt)
        if only_pending and undo.get("outcome") != "pending":
            job.undo = undo
            return
        undo.update(fields)
        locked.undo = undo
        locked.save(update_fields=["undo"])
    job.undo = undo


def _claim_undo_step(
    job: MigrationJob, field: str, *, unless: str, attempt: str | None = None
) -> bool:
    """Write-ahead `field` (a timestamp) into the job's undo record under its
    row lock — unless `unless` was written first. The swap (`abort_sent_at`)
    and the give-back (`give_back_at`) claim each other this way: they are
    mutually exclusive, so a stale tick can never give the VM back (its KBS
    activate clears the undo's arm) under an abort already on its way.
    `attempt`: the undo's arm id the caller acted on — `EffectError` when a
    resume re-keyed it since."""
    with transaction.atomic():
        locked = MigrationJob.objects.select_for_update().get(id=job.id)
        undo = dict(locked.undo or {})
        _check_attempt(undo, attempt)
        if undo.get(unless):
            job.undo = undo
            return False
        if not undo.get(field):
            undo[field] = timezone.now().isoformat()
            locked.undo = undo
            locked.save(update_fields=["undo"])
    job.undo = undo
    return True


def _undo_fence(job: MigrationJob, vm: Vm, undo_gen: int) -> Vm:
    """CAS the VM to `Migrating{undo_gen, source}` from the shape the undo
    was asked on. Idempotent."""
    if (
        vm.state == VmState.MIGRATING
        and vm.migration_dest == job.source_node_id
        and vm.new_generation == undo_gen
    ):
        return vm
    shape = (job.undo or {}).get("shape")
    rows = Vm.objects.filter(id=vm.id, version=vm.version)
    if shape == "fenced":
        rows = rows.filter(
            state=VmState.MIGRATING.value,
            migration_dest=job.dest_node_id,
            new_generation=job.new_gen,
        )
    elif shape == "activated":
        rows = rows.filter(
            state=VmState.ACTIVE.value, host=job.dest_node_id, generation=job.new_gen
        )
    else:
        raise StepFailed("undo-without-shape")
    if not rows.update(
        state=VmState.MIGRATING.value,
        migration_dest=job.source_node_id,
        new_generation=undo_gen,
        version=vm.version + 1,
    ):
        raise StepFailed(f"undo-vm-moved:{vm.state}:{vm.host}:{vm.generation}")
    return Vm.objects.get(id=vm.id)


def _undo_unfence(job: MigrationJob, vm: Vm, undo_gen: int) -> Vm:
    """CAS `Migrating{undo_gen, source}` → `Active{undo_gen, source}, stopped`
    (the abort confirmed the domain down), until the relaunch. Idempotent."""
    if vm.state == VmState.ACTIVE and vm.host == job.source_node_id and vm.generation == undo_gen:
        return vm
    updated = Vm.objects.filter(
        id=vm.id,
        version=vm.version,
        state=VmState.MIGRATING.value,
        migration_dest=job.source_node_id,
        new_generation=undo_gen,
    ).update(
        state=VmState.ACTIVE.value,
        generation=undo_gen,
        host=job.source_node_id,
        migration_dest="",
        new_generation=None,
        version=vm.version + 1,
        # In the same write: a crash right after must not leave the VM
        # reading `running` with its domain down (nothing would relaunch it).
        power_state=VmPowerState.STOPPED.value,
        power_state_at=timezone.now(),
    )
    if not updated:
        raise EffectError("vm changed concurrently during the undo")
    return Vm.objects.get(id=vm.id)


def _undo_committed(
    job: MigrationJob, vm: Vm, event: RollbackEvent | None
) -> dict[str, Any] | None:
    """The proof the ORIGINAL was released its key at `undo_gen`: the KBS
    record of the undo's arm consumed and delivered — or, when nothing was
    armed (`not-a-rollback`), the KBS evidence bundle of a grant vali
    minted at `undo_gen` or later. None while not proven (a release in
    flight included); `EffectError` when the KBS cannot be read."""
    from .services import kbs_evidence

    undo = job.undo or {}
    if undo.get("armed"):
        if event is None:
            return None
        return kbs_view(vm.vm_id, event.restore_id).delivered_record
    bundle = kbs_evidence.fetch_evidence(vm.vm_id)
    if bundle is None:
        return None
    generation = _grant_generation(str(bundle.get("ticket_id") or ""), vm)
    if generation is None or generation < int(undo.get("undo_gen") or 0):
        return None
    return {"grant_generation": generation}


def h_undoing(job: MigrationJob) -> Any:
    """Drive an operator undo one step per tick (see the section notes)."""
    from apps.backup import service as backup_service

    from .services import power

    undo = job.undo if isinstance(job.undo, dict) else {}
    undo_gen = int(undo.get("undo_gen") or 0)
    if undo_gen != _undo_gen(job):
        raise StepFailed("undo-malformed")
    if not backup_service.rollback_enabled():
        raise StepFailed("rollback-disabled")
    checkpoint = original_checkpoint(job)
    if checkpoint is None:
        raise StepFailed("undo-no-checkpoint")
    event = _event(job, RollbackPurpose.UNDO.value)
    if event is None:
        raise StepFailed("undo-without-event")
    vm = Vm.objects.get(id=job.vm_id)
    if undo.get("give_back_at") and not _undo_past_swap(job, vm):
        # A give-back was started (the undo failed before the swap, or was
        # resumed after that): finish it, never re-drive the undo over it.
        _undo_give_back(job, vm, undo_gen)
        raise StepFailed(f"undo-given-back:{undo.get('arm_refused_reason') or 'resumed'}")
    if undo.get("armed") is None and not (
        vm.state == VmState.MIGRATING and vm.new_generation == undo_gen
    ):
        # Nothing touched yet: the original must still be on the host,
        # re-checked right before the fence (a reclaim may have raced the
        # request).
        missing = _original_missing(job)
        if missing:
            raise StepFailed(f"undo-original-missing:{missing}")
        # And the guest must still take a rollback, and the arm's chip be
        # known — both resolved BEFORE the fence (a refusal past it is only
        # retried, then given back: `_undo_arm_refused`).
        _require_rollback_capable(vm.vm_id)
        _dest_platform(job.source_node_id)
    if vm.state == VmState.MIGRATING or undo.get("armed") is None:
        vm = _undo_fence(job, vm, undo_gen)
        if undo.get("armed") is None:
            # Never once the arm is decided: a KBS `activate` clears the
            # VM's arms, so a repeat after arming would disarm the undo.
            key = _key(job, "undo-activate")
            if not _done(key):
                effects.kbs_activate_dest(
                    vm, dest_node_id=job.source_node_id, new_gen=undo_gen, get_url=""
                )
                _record(key)
            behalf = undo.get("requested_by") or {}
            manifest = job.original_manifest.encode("utf-8")
            try:
                armed = _arm(
                    job,
                    event,
                    checkpoint=checkpoint,
                    manifest=manifest,
                    manifest_sha256=hashlib.sha256(manifest).hexdigest(),
                    new_gen=undo_gen,
                    node_id=job.source_node_id,
                    requested_by=f"{behalf.get('kind')}:{behalf.get('id')}",
                    not_a_rollback_ok=True,
                    terminal=False,
                )
            except StepFailed as exc:
                _undo_arm_refused(job, event, str(exc))
                return None
            _note_undo(job, armed=armed, attempt=event.restore_id)
            log.warning(
                "restore %s: UNDO %s the KBS for vm %s at gen %d on %s",
                job.job_id,
                "ARMED" if armed else "needs no arm from",
                vm.vm_id,
                undo_gen,
                job.source_node_id,
            )
        # Write-ahead: from here on the host may have put the original back
        # on the live paths, and it can then ONLY unlock through the undo's
        # arm (`_undo_past_swap`). Never once a give-back was claimed.
        if not _claim_undo_step(
            job, "abort_sent_at", unless="give_back_at", attempt=event.restore_id
        ):
            raise StepFailed("undo-given-back-meanwhile")
        _abort_on_dest(job, "undo")
        _confirm_aborted(job)
        vm = _undo_unfence(job, vm, undo_gen)
    if vm.state != VmState.ACTIVE or vm.host != job.source_node_id or vm.generation != undo_gen:
        raise StepFailed(f"undo-vm-moved:{vm.state}:{vm.host}:{vm.generation}")
    if vm.power_state == VmPowerState.STOPPED:
        # The arm expires (`ARM_TTL_S`): the original is ALWAYS relaunched
        # now, whatever its power state before the restore.
        try:
            power.start_vm(vm, by_migration=True)
        except power.PowerOpRefused as exc:
            if exc.reason == power.DISKS_MISSING_REASON:
                raise StepFailed("undo-relaunch-disks-missing") from exc
            raise EffectError(f"undo relaunch refused: {exc.reason}") from exc
        return None
    record = _undo_committed(job, vm, event)
    if record is None:
        log.info("restore %s: undo waits for the original's key release", job.job_id)
        return None
    _finish_undo(job, vm, event, record)
    return None


def undo_arm_retry_s() -> float:
    """How long an undo past its fence keeps retrying a refused arm before
    it gives the VM back (`_undo_give_back`) — well inside the phase's own
    deadline, so the give-back runs from the handler, not the clock."""
    configured = float(getattr(settings, "VALI_RESTORE_UNDO_ARM_RETRY_S", 300.0))
    return max(0.0, min(configured, revert_timeout_s() / 2))


def _undo_arm_refused(job: MigrationJob, event: RollbackEvent, reason: str) -> None:
    """The KBS refused the undo's arm past the fence (the VM is
    `Migrating{undo_gen, source}`, the KBS activated there). Not terminal:
    the undo stays `pending` and the arm is retried next tick, up to
    `undo_arm_retry_s` after the first refusal. Then `StepFailed` — and
    `fail` gives the VM back (`_undo_give_back`)."""
    undo = job.undo if isinstance(job.undo, dict) else {}
    first_raw = undo.get("arm_refused_at")
    now = timezone.now()
    first = now
    if isinstance(first_raw, str):
        try:
            first = datetime.fromisoformat(first_raw)
        except ValueError:
            first = now
    _note_undo(
        job, only_pending=True, arm_refused_at=first.isoformat(), arm_refused_reason=reason[:128]
    )
    if (now - first).total_seconds() < undo_arm_retry_s():
        log.warning(
            "restore %s: the KBS refused the undo's arm (%s) — retrying (the vm stays fenced "
            "at gen %s until it arms or the undo gives it back)",
            job.job_id,
            reason,
            undo.get("undo_gen"),
        )
        return
    RollbackEvent.objects.filter(
        id=event.id, restore_id=event.restore_id, outcome=RollbackOutcome.PENDING.value
    ).update(outcome=RollbackOutcome.REFUSED.value)
    raise StepFailed(f"undo-arm-refused:{reason}")


def _undo_give_back(job: MigrationJob, vm: Vm, undo_gen: int) -> Vm | None:
    """An undo that failed BEFORE the host was sent the abort that swaps the
    original back: the restored disk is still on the live paths and holds
    the VM's counter. Give the VM back to it rather than leave it fenced —
    KBS `activate` at `undo_gen + 1` on the source chip (which also clears
    any arm of the undo), then `Migrating{undo_gen, source}` →
    `Active{undo_gen + 1, source}`. Idempotent; the KBS step is written
    ahead (`give_back_at`) so a resume finishes it instead of re-arming.
    Returns the VM, or None when the undo never fenced it or its swap was
    sent (claimed exclusively: `_claim_undo_step`). Raises `EffectError`
    when the KBS cannot be reached."""
    back_gen = undo_gen + 1
    if vm.state == VmState.ACTIVE and vm.host == job.source_node_id and vm.generation == back_gen:
        return vm
    if not (
        vm.state == VmState.MIGRATING
        and vm.migration_dest == job.source_node_id
        and vm.new_generation == undo_gen
    ):
        return None
    if not _claim_undo_step(job, "give_back_at", unless="abort_sent_at"):
        return None  # the swap was sent meanwhile: only the undo's arm unlocks now
    key = _key(job, "undo-give-back-activate")
    if not _done(key):
        effects.kbs_activate_dest(
            vm, dest_node_id=job.source_node_id, new_gen=back_gen, get_url=""
        )
        _record(key)
    updated = Vm.objects.filter(
        id=vm.id,
        version=vm.version,
        state=VmState.MIGRATING.value,
        migration_dest=job.source_node_id,
        new_generation=undo_gen,
    ).update(
        state=VmState.ACTIVE.value,
        generation=back_gen,
        host=job.source_node_id,
        migration_dest="",
        new_generation=None,
        version=vm.version + 1,
    )
    if not updated:
        raise EffectError("vm changed concurrently during the undo give-back")
    log.error(
        "restore %s: the UNDO did not arm — vm %s is given BACK to the restored disk on %s "
        "at generation %d (the original is still kept there)",
        job.job_id,
        vm.vm_id,
        job.source_node_id,
        back_gen,
    )
    return Vm.objects.get(id=vm.id)


def _require_rollback_capable(vm_id: str) -> None:
    """A fresh KBS read: `StepFailed` unless the guest is `rollback_capable`
    (`rollback-unsupported` for a KBS without the routes). A KBS that cannot
    be read raises `EffectError` (retried)."""
    from .services import kbs_rollback

    try:
        status = kbs_rollback.rollback_status(vm_id)
    except effects.KbsRouteMissing as exc:
        raise StepFailed("rollback-unsupported") from exc
    capable = status.get(kbs_rollback.WIRE_ROLLBACK_CAPABLE)
    kbs_rollback.note_rollback_capable(vm_id, capable if isinstance(capable, bool) else None)
    if capable is not True:
        raise StepFailed("rollback-not-capable")


def _undo_past_swap(job: MigrationJob, vm: Vm) -> bool:
    """The undo's arm is decided and the host was sent the abort that puts
    the original back on the live paths (a write-ahead: it may have swapped
    already even if vali never saw it confirmed). From then on the original
    can only unlock through the undo's arm."""
    undo = job.undo if isinstance(job.undo, dict) else {}
    return undo.get("armed") is not None and bool(undo.get("abort_sent_at"))


def _undo_release_state(
    job: MigrationJob, vm: Vm, event: RollbackEvent | None
) -> tuple[str, dict[str, Any] | None]:
    """`("delivered", record)` — the original was released its key;
    `("pending", None)` — the undo's arm is live or its release in flight
    (the original may still unlock), or, with no arm, its grant not seen
    yet; `("gone", None)` — the arm went unused. Raises `EffectError` when the KBS
    cannot be read."""
    from .services import kbs_rollback

    undo = job.undo if isinstance(job.undo, dict) else {}
    if not undo.get("armed"):
        record = _undo_committed(job, vm, event)
        return ("delivered", record) if record is not None else ("pending", None)
    if event is None:
        return "gone", None
    view = kbs_view(vm.vm_id, event.restore_id)
    if view.delivered_record is not None:
        return "delivered", view.delivered_record
    if view.live or kbs_rollback.in_flight(view.record):
        return "pending", None
    return "gone", None


def _restart_backups(vm: Vm) -> None:
    """The disk went back in time: no run of the discarded disk may complete
    into a chain, and the next backup is a full. Abandon FIRST, then require
    the full: a run that completes in between cannot clear it afterwards."""
    _abandon_backup_runs(vm)
    _require_full_backup(vm)


def _late_undo_success(job: MigrationJob) -> None:
    """An undo that was ended as failed (the KBS could not be read for
    twice its deadline), whose release was delivered after all: say so."""
    updated = MigrationJob.objects.filter(
        id=job.id, state=MigrationState.FAILED.value, reverted=False
    ).update(reverted=True, reason=f"undone-after-commit-late:{job.reason or ''}"[:256])
    if updated:
        _restart_backups(Vm.objects.get(id=job.vm_id))
        _note_undo(job, outcome="done", committed_at=timezone.now().isoformat())
        log.warning("restore %s: the undo DID complete (late KBS delivery)", job.job_id)


def _finish_undo(
    job: MigrationJob, vm: Vm, event: RollbackEvent | None, record: dict[str, Any]
) -> bool:
    """The original was released its key at `undo_gen`: the job ends
    `failed`, `reverted`. Returns whether this call ended it."""
    from . import service

    undo = job.undo if isinstance(job.undo, dict) else {}
    with transaction.atomic():
        # One settlement: the job's end, its undo record, the rollback's
        # audit row and the backup state commit together or not at all.
        ended = service._cas_migration(
            job,
            MigrationState.FAILED.value,
            {
                "reverted": True,
                "failed_from_state": MigrationState.RESTORE_UNDOING.value,
                "reason": f"undone-after-commit:{undo.get('from_reason') or ''}"[:256],
                "restore_keep_original_until": None,
                "source_reclaim_state": SourceReclaimState.SKIPPED.value,
                "source_reclaim_reason": "undone-to-original",
            },
        )
        if ended:
            if undo.get("armed"):
                _note_committed(event, record)
            _note_undo(job, outcome="done", committed_at=timezone.now().isoformat())
            _restart_backups(vm)
    if ended:
        log.warning(
            "restore %s: UNDONE — vm %s is back on its ORIGINAL on %s at generation %d",
            job.job_id,
            vm.vm_id,
            job.source_node_id,
            int(undo.get("undo_gen") or 0),
        )
    return ended


# ─── the wire shape (C-2 `RestoreJob`) ───────────────────────────────


def phase(job: MigrationJob) -> str:
    state = job.state
    if state == MigrationState.RESTORE_STAGING.value:
        return "staging"
    if state == MigrationState.RESTORE_STOPPING.value:
        return "stopping"
    if state in (
        MigrationState.DEST_ACTIVATING.value,
        MigrationState.RESTORE_REVERTING.value,
        MigrationState.RESTORE_UNDOING.value,
    ):
        return "activating"
    if state == MigrationState.RESTORE_VERIFYING.value:
        return "verifying"
    if state == MigrationState.DONE.value:
        # C-2: `verifying` covers the KBS evidence AND the liveness proof.
        # The job is done on the first (the VM is activated there); the
        # original is kept until the second, and a restored VM that never
        # proves it runs reads `failed` once the reclaim gives up on it.
        if job.source_reclaim_state == SourceReclaimState.SKIPPED.value and (
            job.source_reclaim_reason or ""
        ).startswith("dest-unproven"):
            return "failed"
        if job.source_reclaim_state == SourceReclaimState.PENDING.value and _not_alive_yet(job):
            return "verifying"
        if job.cold and job.cold_settled_at is None:
            return "settling"
        return "done"
    if state == MigrationState.FAILED.value:
        return "reverted" if job.reverted else "failed"
    return "activating"


def _not_alive_yet(job: MigrationJob) -> bool:
    from . import service

    vm = Vm.objects.filter(id=job.vm_id).first()
    if vm is None or vm.state == VmState.DESTROYED:
        return False
    return service._dest_not_alive_reason(job, vm) is not None


_TERMINAL_PHASES = frozenset({"done", "failed", "reverted"})


def outcome(job: MigrationJob, current: str | None = None) -> str | None:
    """`null` while the job runs; else `committed` (the restored guest took
    the key and runs), `reverted`, `cancelled` or `failed` (including a job
    that committed and then never proved the restored VM runs)."""
    current = current or phase(job)
    if current not in _TERMINAL_PHASES:
        return None
    if current == "done":
        return "committed"
    if current == "reverted":
        return "reverted"
    if (
        job.state == MigrationState.FAILED.value
        and job.failed_from_state in CANCELLABLE_STATES
        and (job.reason or "").startswith("cancelled by ")
    ):
        return "cancelled"
    return "failed"


def dead_miner_evidence(job: MigrationJob) -> dict[str, Any] | None:
    """A failover's dead-miner proof, as the contract states it: how long the
    heartbeat and the NetBird peer had been silent, and whether the Edge
    could reach the miner — from the re-check right before the fence when
    there was one, else from the intake. Null for a restore."""
    if job.kind != MigrationKind.FAILOVER.value or job.authorization is None:
        return None
    evidence = job.authorization.evidence if isinstance(job.authorization.evidence, dict) else {}
    snapshot = evidence.get("recheck") if isinstance(evidence.get("recheck"), dict) else evidence
    checked = _parse_ts(snapshot.get("checked_at"))

    def silent_s(key: str) -> int | None:
        seen = _parse_ts(snapshot.get(key))
        if checked is None:
            return None
        if seen is None:
            return None
        return max(0, int((checked - seen).total_seconds()))

    return {
        "heartbeat_silent_s": silent_s("heartbeat_last_seen_at"),
        "netbird_silent_s": silent_s("netbird_last_seen_at"),
        "edge_unreachable": snapshot.get("edge") == "unreachable",
    }


def _parse_ts(raw: Any) -> Any:
    from django.utils.dateparse import parse_datetime

    return parse_datetime(raw) if isinstance(raw, str) else None


def node_ref(node_id: str) -> str | None:
    """An opaque, stable name for a miner: never matchable to its id."""
    import hashlib
    import hmac

    if not node_id:
        return None
    key = str(settings.SECRET_KEY).encode()
    digest = hmac.new(key, b"hippius-node-ref:" + node_id.encode(), hashlib.sha256).hexdigest()
    return f"n-{digest[:10]}"


def last_failover_views(vm_pks: Any) -> dict[Any, dict[str, Any]]:
    """`{vm pk: last_failover_view}` for the VMs that ever failed over: one
    query for the jobs, one for the source regions."""
    from apps.miners import geo

    newest: dict[Any, MigrationJob] = {}
    for job in (
        MigrationJob.objects.filter(vm_id__in=list(vm_pks), kind=MigrationKind.FAILOVER.value)
        .select_related("restore_run")
        .order_by("vm_id", "-started_at")
    ):
        newest.setdefault(job.vm_id, job)
    regions = geo.last_known_countries({job.source_node_id for job in newest.values()})
    return {pk: last_failover_view(job, regions) for pk, job in newest.items()}


def last_failover_view(
    job: MigrationJob | None, regions: dict[str, str] | None = None
) -> dict[str, Any] | None:
    """`last_failover` on the VM: its newest failover, from the instant it
    starts until it ends; null when it never failed over. `from_region` is
    the source's last known country (`regions`, `{miner_id: country}`): a
    dead miner's location is stale by definition."""
    from apps.miners import geo

    if job is None:
        return None
    if regions is None:
        regions = geo.last_known_countries({job.source_node_id})
    current = phase(job)
    run = job.restore_run
    return {
        "failover_id": job.job_id,
        "at": job.started_at.isoformat(),
        "trigger": job.trigger,
        "phase": current,
        "outcome": outcome(job, current),
        "from_region": regions.get(job.source_node_id) or None,
        "to_node_ref": node_ref(job.dest_node_id),
        "restored_point_at": run.created_at.isoformat() if run is not None else None,
        "committed_at": job.committed_at.isoformat() if job.committed_at else None,
    }


def serialize(job: MigrationJob) -> dict[str, Any]:
    run = job.restore_run
    current = phase(job)
    reason = job.reason or None
    if current == "failed" and job.state == MigrationState.DONE.value:
        reason = f"failed-after-commit:{job.source_reclaim_reason}"[:256]
    pct = None
    if job.state == MigrationState.RESTORE_STAGING.value:
        total = int(job.restore_bytes_total or 0)
        pct = min(100, int(job.restore_bytes_done or 0) * 100 // total) if total > 0 else 0
    return {
        "job_id": job.job_id,
        "vm_id": job.vm.vm_id,
        "kind": job.kind,
        "failover_id": job.job_id if job.kind == MigrationKind.FAILOVER.value else None,
        "trigger": job.trigger,
        "outcome": outcome(job, current),
        "started_at": job.started_at.isoformat(),
        "committed_at": job.committed_at.isoformat() if job.committed_at else None,
        "restored_point_at": run.created_at.isoformat() if run is not None else None,
        "dead_miner_evidence": dead_miner_evidence(job),
        "run_id": run.run_id if run is not None else None,
        "chain_id": run.chain.chain_id if run is not None else None,
        "point_taken_at": run.created_at.isoformat() if run is not None else None,
        "phase": current,
        "pct": pct,
        "reason": reason,
        "reverted": bool(job.reverted),
        "prior_power_state": job.prior_power_state or VmPowerState.RUNNING.value,
        "source_node_id": job.source_node_id,
        "dest_node_id": job.dest_node_id,
        "eta_s": job.restore_eta_s,
        "rollback": _rollback_view(job),
        "undo": _undo_view(job),
        "created_at": job.started_at.isoformat(),
        # Null until the phase the caller sees is final (a done job is still
        # `verifying` / `settling` until the restored VM proved it runs).
        "finished_at": (
            job.finished_at.isoformat()
            if job.finished_at and current in _TERMINAL_PHASES
            else None
        ),
    }


def _undo_view(job: MigrationJob) -> dict[str, Any] | None:
    undo = job.undo if isinstance(job.undo, dict) else None
    if undo is None:
        return None
    event = _event(job, RollbackPurpose.UNDO.value)
    return {
        "requested_by": undo.get("requested_by"),
        "requested_at": undo.get("requested_at"),
        "outcome": undo.get("outcome"),
        "reason": undo.get("reason"),
        "generation": undo.get("undo_gen"),
        "rolled_back": undo.get("armed"),
        "committed_at": (
            event.committed_at.isoformat() if event is not None and event.committed_at else None
        ),
    }


def _rollback_view(job: MigrationJob) -> dict[str, Any] | None:
    event = _event(job)
    if event is None:
        return None
    return {
        "from_boot_counter": event.from_boot_counter,
        "to_boot_counter": event.to_boot_counter,
        "point_taken_at": event.point_taken_at.isoformat(),
        "requested_by": {"kind": event.requested_by_kind, "id": event.requested_by_id},
        "committed_at": event.committed_at.isoformat() if event.committed_at else None,
    }


def list_jobs(vm: Vm, *, limit: int) -> list[MigrationJob]:
    """The VM's restore and failover jobs, newest first."""
    return list(
        MigrationJob.objects.filter(vm=vm, kind__in=RESTORE_KINDS)
        .select_related("vm", "restore_run", "restore_run__chain", "authorization")
        .order_by("-started_at")[:limit]
    )


__all__ = [
    "RESTORE_KINDS",
    "RestoreError",
    "StepFailed",
    "TERMINAL_MIGRATION_STATES",
    "cancel_restore",
    "fail",
    "on_timeout",
    "serialize",
    "start_restore",
    "start_undo",
    "sweep_restore_cleanups",
]
