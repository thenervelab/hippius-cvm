"""VM resize — change a VM's vCPU/RAM, keep its data disk.

Design of record: `docs/design/vm-resize.md`.

WHAT A RESIZE IS. A relaunch of the VM on the miner that holds its disks,
at another flavor: the same overlay, the same KEK, the same data disk, a
new SNP measurement (the vCPU count is measured, and so is the
`hippius.resource_class` cmdline token). It reuses the power API's
stop and its start — `_reboot_recovery_relaunch` with a flavor override —
so every guarantee that path carries (the §22 auto-pin of the new
measurement, the KBS re-register at the VM's current generation,
`require_existing_disks`, the launch-record update) carries over. Nothing
here talks to a miner directly.

THE DISK NEVER CHANGES. The tenant data disk is LUKS2 with
`--integrity hmac-sha256`; cryptsetup refuses to resize such a volume
("Resize of LUKS2 device with integrity protection is not supported"), and
the guest anchors the disk size in its measured cmdline
(`hippius.disk_gb=`). So a resize takes ANY offered flavor's vCPU/RAM and
keeps the VM's launch disk: the launch record pins it
(`spec_json["data_disk_size_gb"]`, `launch_record.data_disk_gb`), the
relaunch measures and orders that size (the miner reuses the existing
sparse disk — never recreates it), and the placement accounts it
(`Placement.data_disk_gb`). A "large" may therefore carry a 40 GB disk, and
a VM may shrink below its flavor's disk: the disk stays.

WHERE IT RUNS. On the VM's own miner when the new size fits there once
the VM's current reservation is released. When it does not, a §25
migration first moves the VM (at its old size — §25 replays the source's
measured boot) to a miner the new size fits, its destination placement
opened at the new flavor; the in-place steps then run there. A STOPPED VM
is resized on the books only: its placement and launch record move to the
new flavor and it stays stopped — its next start boots the new size.

CAPACITY. The VM's `Placement` is the reservation admission counts. It is
swapped (`scheduler.service.swap_placement_class`, one transaction, under
the host's capacity-row lock, fit re-checked) so the ledger never counts
the VM twice nor zero times, and never below what physically runs:

- a GROW reserves the new size BEFORE the stop (the old guest still runs,
  so the ledger over-counts, never under-counts);
- a SHRINK keeps the old reservation until the new-size relaunch was
  accepted, then releases the difference.

ROLLBACK. Until the miner ACCEPTED the new-size relaunch, any failure puts
the VM back exactly as it was: reservation swapped back, launch record
never moved, and a VM that was running is started again at its old size
(`rolling_back` → `failed`, `rolled_back=True`). After the acceptance there
is nothing to roll back to without another reboot: a failure (no guest
signal in time) is reported as such, with the VM at its new size.
"""

from __future__ import annotations

import dataclasses
import logging
import secrets
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any

from django.conf import settings
from django.db import IntegrityError, transaction
from django.db.models import F
from django.utils import timezone

from apps.lifecycle.models import Vm, VmPowerState, VmState

from . import effects
from .models import (
    TERMINAL_LAUNCH_STATES,
    TERMINAL_MIGRATION_STATES,
    TERMINAL_RESIZE_STATES,
    LaunchJob,
    MigrationState,
    ResizeJob,
    ResizeState,
)
from .service import StartError, _has_active_job
from .services import flavors, launch_record

log = logging.getLogger("apps.orchestration.resize")

#: Neither the VM's miner nor any other can hold the new size right now.
NO_CAPACITY = "resize-no-capacity"

#: How many accepted-by-nobody relaunch attempts (`relaunch-rejected`) a
#: resize makes before it rolls back. Transient refusals (`allowlist-pin-
#: busy`) are retried until the state's deadline instead.
MAX_RELAUNCH_REJECTIONS = 3


def _timeout_s(name: str, default: float) -> float:
    return float(getattr(settings, name, default))


def _state_timeout(job: ResizeJob) -> float:
    """The deadline of `job`'s current state, in seconds."""
    if job.state == ResizeState.RELAUNCHING and job.relaunched_at is not None:
        # A relaunched guest has the boot-stall budget of a fresh boot.
        return _timeout_s("VALI_RESIZE_GUEST_TIMEOUT_S", 1200.0)
    return {
        ResizeState.PENDING.value: _timeout_s("VALI_RESIZE_PENDING_TIMEOUT_S", 600.0),
        # Longer than `power.STALE_POWER_MARKER`, so a stop whose dispatch
        # failed gets re-asked once its marker goes stale.
        ResizeState.STOPPING.value: _timeout_s("VALI_RESIZE_STOP_TIMEOUT_S", 1500.0),
        ResizeState.RELAUNCHING.value: _timeout_s("VALI_RESIZE_RELAUNCH_TIMEOUT_S", 1800.0),
        # The migration has its own per-phase deadlines; this only bounds a
        # job whose migration somehow never ends.
        ResizeState.MIGRATING.value: _timeout_s("VALI_RESIZE_MIGRATION_TIMEOUT_S", 6 * 3600.0),
        ResizeState.ROLLING_BACK.value: _timeout_s("VALI_RESIZE_ROLLBACK_TIMEOUT_S", 1800.0),
    }.get(job.state, 600.0)


def _pacing_s() -> float:
    """Minimum spacing between two power dispatches of one job."""
    return _timeout_s("VALI_RESIZE_DISPATCH_PACING_S", 60.0)


# ─── compatibility ──────────────────────────────────────────────────


def _sizes(from_flavor: str, to_flavor: str) -> tuple[tuple[int, int], tuple[int, int]]:
    """(vCPU, RAM) of both flavors — what a resize changes (never the disk)."""
    old = flavors.resolve_flavor(from_flavor)
    new = flavors.resolve_flavor(to_flavor)
    return (old.cpu_count, old.memory_mb), (new.cpu_count, new.memory_mb)


def _grows(from_flavor: str, to_flavor: str) -> bool:
    """Does `to_flavor` need at least as much of every resource? A grow is
    reserved (fit re-checked) BEFORE the stop: the old guest still running
    under a bigger reservation is an over-count, never an under-count."""
    old, new = _sizes(from_flavor, to_flavor)
    return all(n >= o for o, n in zip(old, new, strict=True))


def _shrinks(from_flavor: str, to_flavor: str) -> bool:
    """Does `to_flavor` need at most as much of every resource? A shrink
    always fits where the VM is, and keeps its larger reservation until the
    new size runs.

    Neither a grow nor a shrink (more vCPU, less RAM — or the reverse): its
    fit is checked like a grow's, but it is reserved only once the old guest
    is stopped, so the dimension that shrinks is never under-counted while
    the old guest still holds it."""
    old, new = _sizes(from_flavor, to_flavor)
    return all(n <= o for o, n in zip(old, new, strict=True))


def _migrates(vm: Vm, from_flavor: str, to_flavor: str) -> bool:
    """May a resize that does not fit here migrate? Only a grow: §25 first
    boots the OLD size on the destination, whose placement opens at the NEW
    one — an over-count for a grow, but for a mixed change an under-count of
    the dimension it shrinks, on a destination chosen for the new size
    alone (it may not even hold the old guest). And only a GOLDEN VM: §25
    carries a golden VM's writable overlay, but not a legacy VM's separate
    `/dev/vde` data disk."""
    return _grows(from_flavor, to_flavor) and _is_golden(vm)


def _is_golden(vm: Vm) -> bool:
    spec = (
        LaunchJob.objects.filter(vm_id=vm.vm_id, state="succeeded")
        .order_by("-finished_at")
        .values_list("spec_json", flat=True)
        .first()
    ) or {}
    return str(spec.get("disk_mode") or "") == "golden_verity_overlay"


def _chain_node_id(miner_id: str) -> str:
    from apps.miners.models import MinerIdentity

    return (
        MinerIdentity.objects.filter(miner_id=miner_id)
        .values_list("chain_node_id", flat=True)
        .first()
        or ""
    )


def _pinned_measurement(vm: Vm) -> str:
    """The operator-pinned `spec_json["measurement_hex"]` of the VM's launch
    record, `""` when none (every API launch)."""
    spec = (
        LaunchJob.objects.filter(vm_id=vm.vm_id, state="succeeded")
        .order_by("-finished_at")
        .values_list("spec_json", flat=True)
        .first()
    ) or {}
    return str(spec.get("measurement_hex") or "")


def _stopped_refusal(vm: Vm, from_flavor: str, to_flavor: str) -> tuple[str, str] | None:
    """`(category, detail)` refusing a resize of a STOPPED VM whose books
    cannot hold both its booted size (what a restore, failover or §25 hop
    before its next start replays) and its next-boot size in one
    reservation:

    - a mixed change (one dimension up, another down): no single flavor
      covers both sizes;
    - a VM already resized on the books since its last boot: a second
      change could leave the reservation below the booted size.

    Starting the VM first makes the resize an ordinary relaunch."""
    if vm.power_state != VmPowerState.STOPPED:
        return None
    job = (
        LaunchJob.objects.filter(vm_id=vm.vm_id, state="succeeded").order_by("-finished_at").first()
    )
    if job is not None and launch_record.booted_flavor(job) != from_flavor:
        return (
            "resize-pending-boot",
            "this stopped VM was already resized and has not booted at that size yet — "
            "start it first",
        )
    if not _grows(from_flavor, to_flavor) and not _shrinks(from_flavor, to_flavor):
        return (
            "resize-mixed-needs-running",
            "a stopped VM can only grow or shrink in every dimension at once — start it "
            "first to change vCPU and memory in opposite directions",
        )
    return None


def _pins_resource_class(vm: Vm) -> bool:
    """The record's BASE cmdline carries its own `hippius.resource_class=`:
    the launch keeps an operator-supplied token over the flavor's, so a
    resized guest would go on declaring the old size (and every receipt be
    refused against the new billing binding)."""
    from .services.launch import _RESOURCE_CLASS_CMDLINE_KEY

    spec = (
        LaunchJob.objects.filter(vm_id=vm.vm_id, state="succeeded")
        .order_by("-finished_at")
        .values_list("spec_json", flat=True)
        .first()
    ) or {}
    return f"{_RESOURCE_CLASS_CMDLINE_KEY}=" in str(spec.get("cmdline") or "")


def _active_placement(vm: Vm) -> Any:
    from apps.scheduler.models import ACTIVE_PLACEMENT_STATES, Placement

    return Placement.objects.filter(vm=vm, status__in=ACTIVE_PLACEMENT_STATES).first()


@dataclass(frozen=True)
class FlavorOption:
    """One flavor a VM could be resized to, and how."""

    flavor: str
    cpu_count: int
    memory_mb: int
    data_disk_size_gb: int
    #: The new size fits on the VM's own miner (its reservation released).
    fits_current_host: bool
    #: It does not, but another miner could take it: the resize migrates.
    needs_migration: bool
    #: A resize to it would be admitted right now.
    available: bool
    #: Why not, when `available` is false.
    reason: str = ""


@dataclass(frozen=True)
class CompatibleFlavors:
    vm_id: str
    current_flavor: str
    power_state: str
    #: Same data disk, offered, not the current one — the only targets a
    #: resize accepts. `available` says which of them would be admitted NOW.
    options: list[FlavorOption] = field(default_factory=list)
    #: Why nothing can be resized at all right now (job in flight, …), or "".
    blocked: str = ""


def compatible_flavors(vm: Vm) -> CompatibleFlavors:
    """The flavors `vm` may be resized to, each with whether a resize to it
    would be admitted right now. Read-only.

    A flavor with a different data disk never appears: offering it would
    only produce a refusal."""
    current = launch_record.recorded_flavor(vm.vm_id)
    blocked = ""
    try:
        _refuse_vm(vm)
    except StartError as exc:
        blocked = exc.category
    if not blocked and _pinned_measurement(vm):
        blocked = "resize-measurement-pinned"
    if not blocked and _pins_resource_class(vm):
        blocked = "resize-resource-class-pinned"
    if not current:
        return CompatibleFlavors(vm.vm_id, "", vm.power_state, [], blocked or "no-launch-record")
    if current not in flavors.FLAVOR_NAMES:
        return CompatibleFlavors(vm.vm_id, current, vm.power_state, [], "unknown-current-flavor")
    # Any offered flavor: only vCPU/RAM follow it, the disk stays.
    candidates = [
        name for name in flavors.FLAVOR_NAMES if name != current and flavors.is_offered(name)
    ]
    disk_gb = launch_record.vm_data_disk_gb(vm.vm_id)

    placement = _active_placement(vm)
    node = placement.miner_node_id if placement is not None else ""
    options: list[FlavorOption] = []
    for name in candidates:
        size = flavors.resolve_flavor(name)
        shortfall = _in_place_shortfall(vm, node, current, name) if node else "no-placement"
        stopped_refusal = _stopped_refusal(vm, current, name)
        if stopped_refusal:
            shortfall = stopped_refusal[0]
        fits_here = not shortfall
        needs_migration = False
        reason = ""
        if not fits_here:
            if vm.power_state == VmPowerState.RUNNING and node and _migrates(vm, current, name):
                dest, why = _pick_destination(vm, placement, name)
                needs_migration = dest is not None
                reason = "" if needs_migration else f"{NO_CAPACITY}: {why or shortfall}"
            else:
                reason = f"{NO_CAPACITY}: {shortfall}"
        options.append(
            FlavorOption(
                flavor=name,
                cpu_count=size.cpu_count,
                memory_mb=size.memory_mb,
                # Unchanged: the VM keeps its launch disk at any size.
                data_disk_size_gb=disk_gb,
                fits_current_host=fits_here,
                needs_migration=needs_migration,
                available=not blocked and (fits_here or needs_migration),
                reason=blocked or reason,
            )
        )
    return CompatibleFlavors(vm.vm_id, current, vm.power_state, options, blocked)


def _in_place_shortfall(vm: Vm, node_id: str, from_flavor: str, to_flavor: str) -> str:
    """`""` when `to_flavor` fits on `node_id` once `vm`'s own reservation
    is released (a shrink always does), else why not."""
    from apps.scheduler import service as sched

    if _shrinks(from_flavor, to_flavor):
        return ""
    return sched.resize_shortfall(
        node_id=node_id,
        old_class=from_flavor,
        new_class=to_flavor,
        vm_running=vm.power_state == VmPowerState.RUNNING,
    )


def _pick_destination(vm: Vm, placement: Any, to_flavor: str) -> tuple[str | None, str]:
    """A miner (`miner_id`) the VM could migrate to with room for
    `to_flavor`, or `(None, why)`. The same `decide_placement`, with the
    same gates a launch is placed through (`placement_arguments`), plus:
    never its own miner (the in-place answer was already no) nor a
    cross-generation one (§25 replays the measurement); and the new size's
    fit ENFORCED — under capacity v1 (`VALI_SCHEDULER_RESOURCE_ADMISSION`
    off) it would only shadow the choice, and a resize must never move a
    VM to a host that cannot run what it is moving for."""
    from apps.miners.models import MinerIdentity
    from apps.scheduler import chain
    from apps.scheduler import service as sched
    from apps.scheduler.placement import PlacementError, decide_placement

    from .service import _cross_gen_chain_ids

    try:
        snapshot = chain.read_miner_status()
    except chain.ChainReadUnavailable as exc:
        return None, f"chain-unavailable: {exc}"
    sched.refresh_miner_capacity(snapshot)
    arguments = sched.placement_arguments(
        snapshot=snapshot,
        tenant_id=placement.vm_family,
        user_id=placement.owner,
        flavor=to_flavor,
        excluded=frozenset({placement.miner_node_id})
        | _cross_gen_chain_ids(placement.miner_node_id, sched.dispatchable_node_ids()),
        region=sched.launch_region_for_vm(vm.vm_id),
        shadow_log=False,
        vm_id=vm.vm_id,
    )
    # The destination must hold the VM's REAL disk (its launch disk), not
    # the target flavor's.
    disk_gb = launch_record.vm_data_disk_gb(vm.vm_id)
    fit = sched.resource_fit(
        to_flavor, shadow_log=False, disk_gb=sched.placement_disk_gb(to_flavor, disk_gb or None)
    )
    if fit is None:
        return None, "capacity-unavailable"
    arguments["resource_fit"] = dataclasses.replace(fit, enforce=True)
    try:
        dest = decide_placement(snapshot=snapshot, **arguments)
    except PlacementError as exc:
        return None, exc.category or exc.message
    miner_id = (
        MinerIdentity.objects.filter(chain_node_id=dest).values_list("miner_id", flat=True).first()
    )
    if not miner_id:
        return None, "destination-unresolvable"
    return miner_id, ""


# ─── start ──────────────────────────────────────────────────────────


def _refuse_vm(vm: Vm) -> None:
    """The VM-state refusals, shared by the start and the options read."""
    if vm.state != VmState.ACTIVE:
        raise StartError(f"vm is {vm.state!r}, not active", "vm-not-active")
    if not vm.host:
        raise StartError("vm has no bound miner", "no-bound-miner")
    if _has_active_job(vm):
        raise StartError(
            "vm already has an in-flight orchestration job (migration, deletion or resize)",
            "job-in-flight",
        )
    if LaunchJob.objects.filter(vm_id=vm.vm_id).exclude(state__in=TERMINAL_LAUNCH_STATES).exists():
        raise StartError("vm is still launching", "job-in-flight")
    if vm.power_state not in (VmPowerState.RUNNING, VmPowerState.STOPPED):
        raise StartError(
            f"vm is {vm.power_state or 'not yet running'} — a resize starts from "
            "running or stopped",
            "power-op-in-flight",
        )


def start_resize(*, vm: Vm, to_flavor: str, decided_by: Any) -> ResizeJob:
    """Admit a resize of `vm` to `to_flavor` and create its job (`pending`).
    Raises [`StartError`] — every refusal happens HERE, before anything
    moves, so a refused resize leaves the VM untouched.

    Categories: `unknown-flavor`, `flavor-not-offered`, `same-flavor` (the
    caller's request); `vm-not-active`,
    `no-bound-miner`, `job-in-flight`, `power-op-in-flight`,
    `no-launch-record`, `unknown-current-flavor`, `no-placement`,
    `resize-no-capacity` (the VM's
    state or the fleet's)."""
    _refuse_vm(vm)
    try:
        flavors.resolve_flavor(to_flavor)
    except flavors.UnknownFlavor as exc:
        raise StartError(str(exc), "unknown-flavor") from exc
    if to_flavor not in flavors.FLAVOR_NAMES or not flavors.is_offered(to_flavor):
        # A runner flavor is launch-only: never a resize target.
        raise StartError(f"{to_flavor} is not offered", "flavor-not-offered")
    from_flavor = launch_record.recorded_flavor(vm.vm_id)
    if not from_flavor:
        raise StartError("vm has no launch record to resize from", "no-launch-record")
    if from_flavor not in flavors.FLAVOR_NAMES:
        # A runner VM (single-use, launch-only) — `compatible_flavors`
        # offers it nothing for the same reason.
        raise StartError(f"vm's flavor {from_flavor} cannot be resized", "unknown-current-flavor")
    if from_flavor == to_flavor:
        raise StartError(f"vm is already {to_flavor}", "same-flavor")
    if _pins_resource_class(vm):
        raise StartError(
            "vm's launch cmdline pins hippius.resource_class — the relaunch would keep "
            "declaring the old size; clear it first",
            "resize-resource-class-pinned",
        )
    if _pinned_measurement(vm):
        # An operator-pinned `measurement_hex` is replayed by every
        # relaunch; at another vCPU count it is a digest the guest can never
        # produce (refused under launch-digest ENFORCE, denied by the KBS
        # otherwise).
        raise StartError(
            "vm's launch record pins an explicit measurement — a resize would boot a "
            "different one; clear the pin first",
            "resize-measurement-pinned",
        )
    placement = _active_placement(vm)
    if placement is None or placement.miner_node_id != _chain_node_id(vm.host):
        # The reservation is what a resize swaps; without one on the VM's
        # host there is nothing to account the new size against.
        raise StartError(
            "vm has no active placement on its miner — its capacity cannot be accounted",
            "no-placement",
        )
    stopped_refusal = _stopped_refusal(vm, from_flavor, to_flavor)
    if stopped_refusal:
        raise StartError(stopped_refusal[1], stopped_refusal[0])
    shortfall = _in_place_shortfall(vm, placement.miner_node_id, from_flavor, to_flavor)
    if shortfall:
        if vm.power_state != VmPowerState.RUNNING:
            raise StartError(
                f"{to_flavor} does not fit on this VM's miner ({shortfall}); a stopped "
                "VM is resized in place only — start it and retry",
                NO_CAPACITY,
            )
        if not _migrates(vm, from_flavor, to_flavor):
            raise StartError(
                f"{to_flavor} does not fit on this VM's miner ({shortfall}), and this "
                "resize cannot migrate (a change that is neither a grow nor a shrink, or a "
                "legacy VM whose data disk §25 does not carry)",
                NO_CAPACITY,
            )
        dest, why = _pick_destination(vm, placement, to_flavor)
        if dest is None:
            raise StartError(
                f"no miner can take {to_flavor} now (here: {shortfall}; elsewhere: {why})",
                NO_CAPACITY,
            )
    now = timezone.now()
    try:
        with transaction.atomic():
            # Serialised with §25 / §24 intake on the VM's row: the
            # one-active-job check and the insert are one step, so a
            # migration and a resize can never both start.
            locked = Vm.objects.select_for_update().get(pk=vm.pk)
            _refuse_vm(locked)
            if (locked.host, locked.power_state) != (vm.host, vm.power_state) or (
                launch_record.recorded_flavor(vm.vm_id) != from_flavor
            ):
                # A power op or a move landed while this was admitted: the
                # checks above were made against another VM state.
                raise StartError(
                    "vm changed while the resize was being admitted — retry", "job-in-flight"
                )
            job = ResizeJob.objects.create(
                job_id=secrets.token_hex(16),
                vm=locked,
                from_flavor=from_flavor,
                to_flavor=to_flavor,
                node_id=locked.host,
                prior_power_state=locked.power_state,
                state=ResizeState.PENDING.value,
                phase_started_at=now,
                decided_by=decided_by,
            )
    except IntegrityError as exc:
        raise StartError("vm already has an in-flight resize", "job-in-flight") from exc
    log.info(
        "resize started: job=%s vm=%s %s→%s on %s (%s)",
        job.job_id,
        vm.vm_id,
        from_flavor,
        to_flavor,
        vm.host,
        vm.power_state,
    )
    return job


# ─── the state machine ──────────────────────────────────────────────


class _Retry(Exception):
    """This step could not complete this tick; try again next tick (until
    the state's deadline)."""


def _cas(job: ResizeJob, next_state: str, **patch: Any) -> bool:
    now = timezone.now()
    fields: dict[str, Any] = {
        "state": next_state,
        "version": job.version + 1,
        "phase_started_at": now,
        **patch,
    }
    if next_state != job.state:
        # A new state starts its own dispatch budget.
        fields.setdefault("attempts", 0)
        fields.setdefault("attempted_at", None)
    if next_state in TERMINAL_RESIZE_STATES:
        fields["finished_at"] = now
    updated = ResizeJob.objects.filter(id=job.id, version=job.version, state=job.state).update(
        **fields
    )
    if updated:
        log.info("resize %s: %s → %s", job.job_id, job.state, next_state)
    return updated == 1


def _patch(job: ResizeJob, **patch: Any) -> bool:
    """CAS a field update that does not change the state."""
    updated = ResizeJob.objects.filter(id=job.id, version=job.version, state=job.state).update(
        version=F("version") + 1, **patch
    )
    return updated == 1


def _claim_dispatch(job: ResizeJob) -> bool:
    """Count one power dispatch BEFORE it is sent; refuse inside the pacing
    window. False ⇒ do not dispatch this tick."""
    now = timezone.now()
    if job.attempted_at is not None and (now - job.attempted_at).total_seconds() < _pacing_s():
        return False
    if not _patch(job, attempts=job.attempts + 1, attempted_at=now):
        return False
    job.attempts += 1
    job.attempted_at = now
    job.version += 1
    return True


def _fail(job: ResizeJob, reason: str, *, rolled_back: bool, **patch: Any) -> None:
    _cas(job, ResizeState.FAILED.value, reason=reason[:256], rolled_back=rolled_back, **patch)
    log.warning(
        "resize %s FAILED (vm=%s %s→%s, rolled_back=%s): %s",
        job.job_id,
        job.vm.vm_id,
        job.from_flavor,
        job.to_flavor,
        rolled_back,
        reason,
    )


def _begin_rollback(job: ResizeJob, reason: str) -> None:
    """A failure before the new-size relaunch was accepted: put the VM back."""
    _cas(job, ResizeState.ROLLING_BACK.value, reason=reason[:256])


def _swap(
    job: ResizeJob,
    vm: Vm,
    new_class: str,
    *,
    check_fit: bool,
    stopped_at: Any = None,
) -> None:
    """Swap the VM's reservation on `job.node_id` to `new_class`. Whether
    the miner's RAM report still includes the guest follows its power
    state, or — `stopped_at`, right after its stop — the report's own age,
    judged under the capacity-row lock (`sched.resize_budget`)."""
    from apps.scheduler import service as sched

    sched.swap_placement_class(
        vm,
        node_id=_chain_node_id(job.node_id),
        new_class=new_class,
        reason=f"resized:{job.job_id}",
        decided_by=job.decided_by,
        check_fit=check_fit,
        vm_running=vm.power_state == VmPowerState.RUNNING,
        stopped_at=stopped_at,
    )


def _own_migration(job: ResizeJob, vm: Vm) -> Any:
    """The §25 job this resize started, when a tick died between starting
    it and recording it: same VM, `resize_to_flavor` = this target, started
    after this job. Adopted rather than orphaned — left alone, it would open
    the destination at the new size with nobody to relaunch at it."""
    from .models import MigrationJob

    return (
        MigrationJob.objects.filter(
            vm=vm, resize_to_flavor=job.to_flavor, started_at__gte=job.started_at
        )
        .order_by("-started_at")
        .first()
    )


def _h_pending(job: ResizeJob, vm: Vm) -> None:
    from apps.scheduler import service as sched

    orphan = _own_migration(job, vm)
    if orphan is not None:
        log.warning(
            "resize %s: adopting migration %s it started before its tick died",
            job.job_id,
            orphan.job_id,
        )
        _cas(job, ResizeState.MIGRATING.value, migration_job=orphan)
        return
    if vm.state != VmState.ACTIVE or vm.host != job.node_id:
        _fail(job, f"vm-changed: vm is {vm.state} on {vm.host!r}", rolled_back=True)
        return
    if job.prior_power_state == VmPowerState.STOPPED:
        _apply_to_stopped(job, vm)
        return
    if vm.power_state != VmPowerState.RUNNING:
        raise _Retry(f"vm is {vm.power_state}")
    if _shrinks(job.from_flavor, job.to_flavor):
        # A shrink keeps its larger reservation until the new size runs.
        _cas(job, ResizeState.STOPPING.value)
        return
    if not _grows(job.from_flavor, job.to_flavor):
        # A mixed change is reserved once the old guest is stopped — and
        # only where it is: it never migrates (see `_migrates`).
        shortfall = _in_place_shortfall(
            vm, _chain_node_id(job.node_id), job.from_flavor, job.to_flavor
        )
        if shortfall:
            _fail(job, f"{NO_CAPACITY}: {shortfall}", rolled_back=True)
        else:
            _cas(job, ResizeState.STOPPING.value)
        return
    try:
        _swap(job, vm, job.to_flavor, check_fit=True)
    except sched.ResizeNoRoom as exc:
        _start_migration(job, vm, shortfall=exc.shortfall)
        return
    except sched.PlacementSwapConflict as exc:
        _fail(job, f"placement-conflict: {exc}", rolled_back=True)
        return
    _cas(job, ResizeState.STOPPING.value, reserved=True)


def _apply_to_stopped(job: ResizeJob, vm: Vm) -> None:
    """A stopped VM: reserve the new size and move its launch record — its
    next start boots it. Nothing is dispatched; it stays stopped."""
    from apps.scheduler import service as sched

    if vm.power_state != VmPowerState.STOPPED:
        _fail(job, f"vm-changed: vm is {vm.power_state}, was stopped", rolled_back=True)
        return
    if _shrinks(job.from_flavor, job.to_flavor):
        # Its current boot — what a restore, failover or §25 hop before the
        # next start replays — is the larger old size: keep that reserved.
        # The next accepted relaunch releases the difference
        # (`service._reboot_recovery_relaunch`).
        try:
            launch_record.record_flavor(
                vm.vm_id, job.to_flavor, reason=f"resize:{job.job_id}", expected=job.from_flavor
            )
        except Exception as exc:  # noqa: BLE001 — nothing else moved
            _fail(job, f"record-failed: {exc}", rolled_back=True)
            return
        _cas(job, ResizeState.DONE.value)
        return
    try:
        _swap(job, vm, job.to_flavor, check_fit=True)
    except sched.ResizeNoRoom as exc:
        _fail(job, f"{NO_CAPACITY}: {exc.shortfall}", rolled_back=True)
        return
    except sched.PlacementSwapConflict as exc:
        _fail(job, f"placement-conflict: {exc}", rolled_back=True)
        return
    try:
        launch_record.record_flavor(
            vm.vm_id, job.to_flavor, reason=f"resize:{job.job_id}", expected=job.from_flavor
        )
    except Exception as exc:  # noqa: BLE001 — undone below, then reported.
        _swap(job, vm, job.from_flavor, check_fit=False)
        _fail(job, f"record-failed: {exc}", rolled_back=True)
        return
    _cas(job, ResizeState.DONE.value, reserved=True)


def _start_migration(job: ResizeJob, vm: Vm, *, shortfall: str) -> None:
    """The new size does not fit here: migrate (at the old size) to a miner
    it fits on, the destination placement opened at the new size."""
    from .service import start_migration

    placement = _active_placement(vm)
    if placement is None:
        _fail(job, "no-placement", rolled_back=True)
        return
    if not _migrates(vm, job.from_flavor, job.to_flavor):
        _fail(job, f"{NO_CAPACITY}: here {shortfall}; this VM cannot migrate", rolled_back=True)
        return
    dest, why = _pick_destination(vm, placement, job.to_flavor)
    if dest is None:
        _fail(job, f"{NO_CAPACITY}: here {shortfall}; elsewhere {why}", rolled_back=True)
        return
    with transaction.atomic():
        # The migration and the job's move to `migrating` commit together,
        # under the job's row lock: another tick cannot fail this job while
        # its migration is being created (its CAS waits, then loses), so
        # the migration is never left without the resize that owns it.
        locked = ResizeJob.objects.select_for_update().get(pk=job.pk)
        if (locked.state, locked.version) != (job.state, job.version):
            return
        try:
            migration = start_migration(
                vm=vm, dest_node_id=dest, decided_by=job.decided_by, resize_to_flavor=job.to_flavor
            )
        except StartError as exc:
            # Another tick of this job may have started it a moment ago.
            migration = _own_migration(job, vm)
            if migration is None:
                _fail(job, f"migration-refused: {exc.category}: {exc.message}", rolled_back=True)
                return
        _cas(job, ResizeState.MIGRATING.value, migration_job=migration)
    log.info(
        "resize %s: %s does not fit on %s (%s) — migrating to %s (job %s)",
        job.job_id,
        job.to_flavor,
        job.node_id,
        shortfall,
        dest,
        migration.job_id,
    )


def _h_migrating(job: ResizeJob, vm: Vm) -> None:
    migration = job.migration_job
    if migration is None:
        _fail(job, "migration-missing", rolled_back=False)
        return
    migration.refresh_from_db()
    if migration.state not in TERMINAL_MIGRATION_STATES:
        return
    if migration.state == MigrationState.FAILED:
        # The migration's own recovery owns the VM from here. It is back as
        # it was only if it never left its miner.
        back = vm.state == VmState.ACTIVE and vm.host == job.node_id
        _fail(job, f"migration-failed: {migration.reason}", rolled_back=back)
        return
    # Done: the VM runs, at its OLD size, on the destination — whose
    # placement already holds the NEW size (`resize_to_flavor`). Re-read:
    # the activation may have moved it after this tick read it.
    vm.refresh_from_db()
    _cas(job, ResizeState.STOPPING.value, node_id=vm.host, reserved=True)


def _stale_stopping(vm: Vm) -> bool:
    """`vm` carries a `stopping` marker old enough that the power API
    treats it as abandoned (a stop whose dispatch failed: the order may or
    may not have landed). A fresh stop is then allowed — and is the way to
    find out, since stopping a stopped domain is a no-op on the miner."""
    from .services import power

    return (
        vm.power_state == VmPowerState.STOPPING
        and vm.power_state_at is not None
        and timezone.now() - vm.power_state_at >= power.STALE_POWER_MARKER
    )


def _h_stopping(job: ResizeJob, vm: Vm) -> None:
    from .services import power

    if vm.power_state == VmPowerState.STOPPED:
        _stopped(job, vm)
        return
    if vm.power_state != VmPowerState.RUNNING and not _stale_stopping(vm):
        return  # a stop in flight — wait for it to settle
    if not _claim_dispatch(job):
        return
    try:
        power.stop_vm(vm, by_migration=True)
    except power.PowerOpRefused as exc:
        raise _Retry(f"stop refused: {exc.reason}") from exc
    except Exception as exc:  # noqa: BLE001 — the order may have landed; re-read next tick
        raise _Retry(f"stop dispatch failed: {exc}") from exc
    vm.refresh_from_db()
    _stopped(job, vm)


def _stopped(job: ResizeJob, vm: Vm) -> None:
    """The old guest is down. A mixed change (neither a grow nor a shrink)
    is reserved now — its whole old size is free, the fit re-checked — and
    rolls back when it no longer fits."""
    from apps.scheduler import service as sched

    if not job.reserved and not _shrinks(job.from_flavor, job.to_flavor):
        try:
            # A miner free-RAM report ingested before this job began to stop
            # the VM still counts the old guest: credit it back, as while it
            # ran. One ingested after may already show it freed (ingest time
            # is not sample time, and an earlier stop attempt may have
            # landed), so it is never credited.
            _swap(job, vm, job.to_flavor, check_fit=True, stopped_at=job.phase_started_at)
        except sched.ResizeNoRoom as exc:
            _begin_rollback(job, f"{NO_CAPACITY}: {exc.shortfall}")
            return
        _cas(job, ResizeState.RELAUNCHING.value, reserved=True)
        return
    _cas(job, ResizeState.RELAUNCHING.value)


def _h_relaunching(job: ResizeJob, vm: Vm) -> None:
    if job.relaunched_at is None:
        _relaunch(job, vm)
        return
    # Relaunched at the new size. The books follow first (retried every
    # tick until they hold), then the job waits for the domain to run and
    # the guest to prove it booted — an in-guest signal from AFTER the
    # relaunch.
    _settle(job, vm)
    if vm.power_state != VmPowerState.RUNNING:
        return
    if vm.guest_signal_at is None or vm.guest_signal_at <= job.relaunched_at:
        return
    if not _settled(job, vm):
        return
    _cas(job, ResizeState.DONE.value)


def _superseded(job: ResizeJob, vm: Vm) -> bool:
    """Did a launch since this job started already make the KBS refuse the
    pre-resize launch at its register?"""
    from .models import MeasurementLedger

    return MeasurementLedger.objects.filter(
        vm_id=vm.vm_id, superseded_at_register__gte=job.started_at
    ).exists()


def next_start_supersedes(vm: Vm) -> bool:
    """A stopped VM resized on the books (`_apply_to_stopped`) has not
    booted its new size yet: its next start supersedes the pre-resize
    launch at its register, like a running VM's relaunch, until one start
    got that far (`power.start_vm`) — and only while its miner reports the
    domain DOWN: an earlier start that timed out may have booted it, and a
    superseding register would strand it (it then becomes current at its
    first release instead)."""
    record = (
        LaunchJob.objects.filter(vm_id=vm.vm_id, state="succeeded").order_by("-finished_at").first()
    )
    if record is None:
        return False
    recorded = str((record.spec_json or {}).get("flavor") or "")
    if launch_record.booted_flavor(record) == recorded:
        return False
    job = (
        ResizeJob.objects.filter(
            vm=vm, state=ResizeState.DONE.value, prior_power_state=VmPowerState.STOPPED
        )
        .order_by("-started_at")
        .first()
    )
    if job is None or _superseded(job, vm):
        return False
    return effects.poll_domain_running(vm) is False


def _relaunch(job: ResizeJob, vm: Vm) -> None:
    from .services import power

    if vm.power_state == VmPowerState.RUNNING:
        # Only this job may start the VM (the power API refuses everyone
        # else while it is in flight): a running VM here means its relaunch
        # was accepted and the tick died before recording it.
        _relaunch_accepted(job, vm)
        return
    if vm.power_state != VmPowerState.STOPPED:
        return  # a start in flight (or an abandoned marker going stale)
    # Only a domain the miner reports DOWN is relaunched: an earlier attempt
    # answered as refused may have landed after all, and a second launch
    # would boot the same disks twice.
    if not _domain_down_or_handled(job, vm, after="relaunch"):
        return
    if not job.measurement_before:
        _patch(job, measurement_before=launch_record.recorded_measurement(vm.vm_id))
        job.refresh_from_db()
    if not _claim_dispatch(job):
        return
    try:
        # Supersede the pre-resize launch at the KBS register (its ticket
        # is refused from then on) until one relaunch of this job got that
        # far. After that a retry does not: that earlier attempt was
        # dispatched and may still come up, and a superseding register
        # would strand it — a retry's launch becomes current at its first
        # release instead (`kbs_core::lifecycle::check_current_launch`),
        # and the pre-resize ticket stays refused since that register. An
        # attempt that failed BEFORE its register dispatched nothing, so
        # the next one still supersedes.
        power.start_vm(
            vm, by_migration=True, flavor=job.to_flavor, supersede=not _superseded(job, vm)
        )
    except power.PowerOpRefused as exc:
        if exc.reason == power.PIN_BUSY_REASON:
            # Nothing was dispatched: not an attempt, and not paced.
            _patch(job, attempts=max(0, job.attempts - 1), attempted_at=None)
            raise _Retry("allowlist pin busy") from exc
        if exc.reason == power.DISKS_MISSING_REASON:
            # The miner does not hold the disks: no relaunch — at either
            # size — can succeed there. Release the new reservation and
            # leave the VM stopped for an operator.
            if job.reserved:
                _swap(job, vm, job.from_flavor, check_fit=False)
            _fail(job, "disks-missing: the miner does not hold this VM's disks", rolled_back=False)
            return
        # A refusal can be ambiguous (the order timed out at the Edge: the
        # miner may have booted the guest at the new size anyway). Only a
        # domain the miner reports DOWN is a relaunch to retry or undo.
        if not _domain_down_or_handled(job, vm, after=f"relaunch refused ({exc.reason})"):
            return
        if job.attempts >= MAX_RELAUNCH_REJECTIONS:
            _begin_rollback(job, f"relaunch-rejected: {exc.reason} ({job.attempts} attempts)")
            return
        raise _Retry(f"relaunch refused: {exc.reason}") from exc
    vm.refresh_from_db()
    _relaunch_accepted(job, vm)


#: The failure slug when a domain this job believed down turns out to run.
_OUTCOME_UNKNOWN = {
    ResizeState.RELAUNCHING.value: "relaunch-outcome-unknown",
    ResizeState.ROLLING_BACK.value: "rollback-outcome-unknown",
}


def _domain_down_or_handled(job: ResizeJob, vm: Vm, *, after: str) -> bool:
    """`True` when the miner reports the VM's domain DOWN — the only state
    in which this job may boot it. Otherwise handled here: unknown waits
    (raises `_Retry`); UP — "stopped" on the books, running on the miner:
    an ambiguous relaunch landed, at a size nobody knows — is recorded
    running (so no later start boots it again) and fails the job for an
    operator, keeping the reservation it holds (the larger of the two for a
    grow; the old, larger one for a shrink)."""
    from .services import power

    running = effects.poll_domain_running(vm)
    if running is None:
        raise _Retry(f"{after}: domain state unknown")
    if not running:
        return True
    power.settle_observed_running(vm)
    _fail(
        job,
        f"{_OUTCOME_UNKNOWN[job.state]}: {after}, but the domain runs — which size booted is "
        "unknown; an operator must check",
        rolled_back=False,
    )
    return False


def _relaunch_accepted(job: ResizeJob, vm: Vm) -> None:
    """The miner accepted the new-size relaunch — the point of no rollback,
    recorded BEFORE anything else can fail: from here a failure leaves the
    VM at the new size and says so, it never "rolls back" a VM that is no
    longer the old size."""
    if not _cas(job, job.state, relaunched_at=timezone.now()):
        return
    job.refresh_from_db()
    _settle(job, vm)


def _settled(job: ResizeJob, vm: Vm) -> bool:
    """The books describe the new-size boot: reservation, flavor, and the
    relaunch's own measurement (`record_relaunch` is best-effort in the
    relaunch path; a record still holding the old one would have a §25
    hop or a KBS-state recovery re-mint a measurement this guest never
    produced)."""
    return (
        job.reserved
        and launch_record.recorded_flavor(vm.vm_id) == job.to_flavor
        and _measurement_recorded(job, vm)
    )


def _measurement_recorded(job: ResizeJob, vm: Vm) -> bool:
    """The launch record holds a measurement, and not the one from before
    the relaunch (a record that had none before must have one now)."""
    now = launch_record.recorded_measurement(vm.vm_id)
    return bool(now) and now != job.measurement_before


def _settle(job: ResizeJob, vm: Vm) -> None:
    """Bring the books in line with the new-size boot. Idempotent, and
    retried every tick until it holds (a failure raises into the tick's
    log):

    - the launch record names the new flavor. `record_relaunch` writes it
      with the measurement, but that write is best-effort in the relaunch
      path — without it the next relaunch would silently boot the OLD size;
    - a shrink releases the size the VM no longer uses.

    Not while the record waits for the guest to attest which boot runs (an
    `already-launched` answer, `launch_record.boot_unverified`), nor once
    the guest attested the pre-resize one."""
    record = launch_record.latest_record(vm.vm_id)
    if record is not None and launch_record.boot_unverified(record):
        return
    attested = launch_record.attested_on_record(record) if record is not None else ""
    if (
        attested
        and datetime.fromisoformat(attested) >= job.started_at
        and not _measurement_recorded(job, vm)
    ):
        # The guest attested the PRE-resize boot after an `already-launched`
        # answer: the old size runs. The new flavor next to its measurement
        # would have a §25 hop boot it at the wrong vCPU count. The job stays
        # unsettled and its deadline reports it.
        return
    if launch_record.recorded_flavor(vm.vm_id) != job.to_flavor:
        launch_record.record_flavor(
            vm.vm_id,
            job.to_flavor,
            reason=f"resize:{job.job_id}",
            expected=job.from_flavor,
            booted=True,
        )
    if not job.reserved:
        _swap(job, vm, job.to_flavor, check_fit=False)
        _patch(job, reserved=True)
        job.refresh_from_db()


def _relaunch_was_accepted(job: ResizeJob, vm: Vm) -> bool:
    """Evidence that the new-size relaunch was accepted although the job
    never recorded it (a tick that died inside `start_vm`): the launch
    record already names the new flavor. Before `relaunched_at` only an
    ACCEPTED relaunch writes it (`record_relaunch`, with its measurement) —
    so this is never a rollback to make."""
    return job.relaunched_at is None and launch_record.recorded_flavor(vm.vm_id) == job.to_flavor


def _release_new_size(job: ResizeJob, vm: Vm) -> None:
    if job.reserved:
        _swap(job, vm, job.from_flavor, check_fit=False)
        _patch(job, reserved=False)
        job.refresh_from_db()


def _h_rolling_back(job: ResizeJob, vm: Vm) -> None:
    """Put the VM back as it was: old reservation, and running again if it
    was running. The launch record never moved (the relaunch was never
    accepted), so a plain start boots the old size."""
    from .services import power

    if _relaunch_was_accepted(job, vm):
        log.warning(
            "resize %s: vm=%s already relaunched at %s — not a rollback, finishing it",
            job.job_id,
            vm.vm_id,
            job.to_flavor,
        )
        _cas(job, ResizeState.RELAUNCHING.value, relaunched_at=timezone.now(), reason="")
        return
    if job.prior_power_state != VmPowerState.RUNNING or vm.power_state == VmPowerState.RUNNING:
        # Up at the old size (the stop never landed, or the restart below
        # did): the old reservation back, done.
        _release_new_size(job, vm)
        _cas(job, ResizeState.FAILED.value, rolled_back=True)
        return
    if _stale_stopping(vm):
        # The resize's stop never settled: whether the guest is up is
        # unknown. Settle it with a fresh stop, then start it below.
        if _claim_dispatch(job):
            try:
                power.stop_vm(vm, by_migration=True)
            except Exception as exc:  # noqa: BLE001 — retried until the deadline
                raise _Retry(f"rollback stop failed: {exc}") from exc
        return
    if vm.power_state != VmPowerState.STOPPED:
        return  # a power op settling — wait
    # Proven down before the new size's reservation is given back: an
    # ambiguous relaunch that booted after all keeps what it may be using.
    if not _domain_down_or_handled(job, vm, after=f"rollback after {job.reason}"):
        return
    _release_new_size(job, vm)
    if not _claim_dispatch(job):
        return
    try:
        power.start_vm(vm, by_migration=True)
    except power.PowerOpRefused as exc:
        raise _Retry(f"rollback start refused: {exc.reason}") from exc
    _cas(job, ResizeState.FAILED.value, rolled_back=True)


_HANDLERS = {
    ResizeState.PENDING.value: _h_pending,
    ResizeState.MIGRATING.value: _h_migrating,
    ResizeState.STOPPING.value: _h_stopping,
    ResizeState.RELAUNCHING.value: _h_relaunching,
    ResizeState.ROLLING_BACK.value: _h_rolling_back,
}


def _on_timeout(job: ResizeJob) -> None:
    elapsed = timedelta(seconds=_state_timeout(job))
    if job.state == ResizeState.ROLLING_BACK:
        _fail(job, f"rollback-timeout ({elapsed}) after: {job.reason}", rolled_back=False)
    elif job.state == ResizeState.RELAUNCHING and job.relaunched_at is not None:
        # Past the point of no rollback: the VM runs (or tries to) at the
        # new size. Reported, not undone — undoing is another reboot.
        if launch_record.recorded_flavor(job.vm.vm_id) != job.to_flavor or (
            not _measurement_recorded(job, job.vm)
        ):
            log.error(
                "resize %s: vm=%s relaunched at %s but its launch record still names %s — "
                "a later relaunch would boot the old size; run vali_backfill_launch_measurement",
                job.job_id,
                job.vm.vm_id,
                job.to_flavor,
                job.from_flavor,
            )
            reason = (
                "record-failed: the launch record does not describe the new-size boot "
                "(flavor or measurement); run vali_backfill_launch_measurement"
            )
        elif not job.reserved:
            reason = "reservation-not-settled: the placement still holds the old flavor"
        else:
            reason = f"guest-signal-timeout: no in-guest signal within {elapsed}"
        _fail(job, reason, rolled_back=False)
    elif job.state == ResizeState.MIGRATING:
        if job.migration_job is not None and job.migration_job.state not in (
            TERMINAL_MIGRATION_STATES
        ):
            # Its §25 job has its own deadlines and always ends; failing
            # the resize under it would leave that job opening the
            # destination at the new size with nobody to relaunch at it.
            log.warning(
                "resize %s: past %s, still waiting on migration %s (%s)",
                job.job_id,
                elapsed,
                job.migration_job.job_id,
                job.migration_job.state,
            )
            return
        _fail(job, f"migration-timeout ({elapsed})", rolled_back=False)
    elif (
        job.state == ResizeState.RELAUNCHING
        and job.vm is not None
        and _relaunch_was_accepted(job, job.vm)
    ):
        _cas(job, job.state, relaunched_at=timezone.now())
    elif job.state == ResizeState.PENDING:
        _fail(job, f"pending-timeout ({elapsed})", rolled_back=not job.reserved)
    else:
        _begin_rollback(job, f"{job.state}-timeout ({elapsed})")


#: The states in which the job runs power operations on `job.node_id`.
_ON_HOST_STATES = frozenset(
    {
        ResizeState.STOPPING.value,
        ResizeState.RELAUNCHING.value,
        ResizeState.ROLLING_BACK.value,
    }
)


def _settle_power_marker(vm: Vm) -> Vm:
    """A `starting`/`stopping` marker abandoned by a tick that died inside a
    power op is settled to what the miner runs (the same settle the
    reboot-recovery scan applies — which skips a VM with a job in flight)."""
    from .service import _scheduler_liveness_timeout_s, _settle_abandoned_power_marker

    if vm.power_state in (VmPowerState.STARTING, VmPowerState.STOPPING):
        now = timezone.now()
        _settle_abandoned_power_marker(
            vm, now=now, cutoff=now - timedelta(seconds=_scheduler_liveness_timeout_s())
        )
        vm.refresh_from_db()
    return vm


def advance_resize_job(job: ResizeJob) -> None:
    """Advance `job` by one bounded step. Never raises for a step failure."""
    if job.state in TERMINAL_RESIZE_STATES:
        return
    vm = Vm.objects.get(pk=job.vm_id)
    job.vm = vm
    if job.state in _ON_HOST_STATES and (vm.state != VmState.ACTIVE or vm.host != job.node_id):
        # Nothing else may move a VM a resize owns; if something did, the
        # job must not stop / start it on a host it is no longer on.
        _fail(
            job,
            f"vm-moved: vm is {vm.state} on {vm.host!r}, the resize ran on {job.node_id!r}",
            rolled_back=False,
        )
        return
    try:
        if job.state in _ON_HOST_STATES:
            vm = _settle_power_marker(vm)
        _HANDLERS[job.state](job, vm)
    except _Retry as exc:
        log.info("resize %s: %s — retrying (%s)", job.job_id, job.state, exc)
    except Exception:  # noqa: BLE001 — a bug must not kill the tick; the deadline bounds it.
        log.exception("resize %s: unhandled error in %s", job.job_id, job.state)
    job.refresh_from_db()
    if job.state in TERMINAL_RESIZE_STATES:
        return
    if (timezone.now() - job.phase_started_at).total_seconds() > _state_timeout(job):
        _on_timeout(job)


def tick_resizes() -> int:
    """Advance every in-flight resize one step. Returns how many."""
    jobs = list(
        ResizeJob.objects.exclude(state__in=TERMINAL_RESIZE_STATES).select_related(
            "vm", "migration_job", "decided_by"
        )
    )
    for job in jobs:
        try:
            advance_resize_job(job)
        except Exception:  # noqa: BLE001 — one job must not kill the tick.
            log.exception("resize %s: unhandled error in tick", job.job_id)
    return len(jobs)
