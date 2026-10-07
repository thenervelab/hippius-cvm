"""Guest rollout — move a set of VMs onto a guest components release in
waves (docs/design/guest-component-rollout.md, "`GuestRollout`").

A rollout only ADMITS `GuestUpgradeJob`s (`guest_upgrade.start_guest_upgrade`)
and watches them; each job moves its VM on its own, with its own gate and
rollback. The rollout decides who goes next and when to stop:

- its VMs are fixed when it is created (`members`: the scope's VMs then,
  minus canaries and VMs already on the release); a VM that joins the
  selector later is not in it, one that leaves it is skipped;
- wave 0 is the operator's canaries — at least one must be upgraded
  (`done`) before anything else; every later wave takes a cumulative
  percentage (`waves`) of the members, the next ones by id;
- at most `max_concurrent` of its jobs hold VMs at a time, at most one per
  miner across EVERY guest upgrade in flight; its pending jobs leave
  `pending` only with the rollout's leave (`may_start`): active, a free
  slot, a free miner — so a job parked on a stopped VM never starts behind
  a pause or beside another;
- a wave is complete when each of its VMs has a terminal job, a job pending
  on a stopped VM, or a benign admission refusal; the next one starts
  `wave_pause_s` later; the rollout is `done` only once every job is
  terminal;
- it STOPS (`paused`, no new job, its pending jobs wait) on any outcome but
  `done` / `rolled_back` (a canary must be `done`), `rolled_back` above
  `max_failure_ratio` of a wave (at least one), an admission refusal other
  than "already on the release" / "VM gone", or the release withdrawn.
  `resume` acknowledges what stopped it; only later outcomes stop it again.
  `abort` cancels its pending jobs.

Every decision that admits a job, lets one leave `pending` or moves a
rollout takes the global guest-upgrade lock first (`global_lock`), then the
rollout's row, then a VM's row — one order, so no deadlock, and two ticks,
a tick and an abort, or two creations never act at once.

The rollout's progress is its job rows; nothing here is lost to a restart.
"""

from __future__ import annotations

import logging
import math
import secrets
from datetime import datetime
from typing import Any

from django.db import transaction
from django.utils import timezone

from apps.lifecycle.models import Vm, VmPowerState, VmState

from . import guest_upgrade
from .models import (
    HOLDING_GUEST_UPGRADE_STATES,
    TERMINAL_GUEST_ROLLOUT_STATES,
    TERMINAL_GUEST_UPGRADE_STATES,
    GuestComponentRelease,
    GuestRollout,
    GuestRolloutState,
    GuestUpgradeJob,
    GuestUpgradeLock,
    GuestUpgradeState,
)
from .service import StartError
from .services import launch_record

log = logging.getLogger("apps.orchestration.guest_rollout")

R = GuestRolloutState
J = GuestUpgradeState

DEFAULT_WAVES = (5, 25, 50, 100)
_SCOPE_KEYS = ("vm_ids", "tenant_ids", "node_ids", "bake_ids")
#: Admission refusals that do not stop a rollout: the VM is on the release
#: already, it is gone, or it left the scope.
_BENIGN_SKIPS = frozenset({"already-on-target", "vm-not-active", "left-scope"})


def global_lock() -> None:
    """Take the guest-upgrade lock for the rest of the transaction (call
    inside `transaction.atomic`, before any rollout or VM row lock)."""
    try:
        GuestUpgradeLock.objects.select_for_update().get(pk=1)
    except GuestUpgradeLock.DoesNotExist:
        GuestUpgradeLock.objects.get_or_create(pk=1)
        GuestUpgradeLock.objects.select_for_update().get(pk=1)


class RolloutRefused(ValueError):
    """A rollout that cannot be created as asked. `missing` lists the VMs
    of its scope that have no build of the release."""

    def __init__(self, message: str, category: str, missing: list[str] | None = None) -> None:
        super().__init__(message)
        self.message = message
        self.category = category
        self.missing = missing or []


# ─── scope ───────────────────────────────────────────────────────────


def _bases(bake_ids: list[str]) -> set[tuple[str, str, str]]:
    from apps.tenant_bake.models import TenantBake

    return {
        (b.kernel_sha256.lower(), b.rootfs_img_sha256.lower(), b.verity_root_hash.lower())
        for b in TenantBake.objects.filter(bake_id__in=bake_ids)
    }


def _base_of(vm: Vm) -> tuple[str, str, str] | None:
    record = launch_record.latest_record(vm.vm_id)
    if record is None:
        return None
    spec = record.spec_json or {}
    return (
        str(spec.get("kernel_sha256_hex") or "").lower(),
        str(spec.get("rootfs_img_sha256_hex") or "").lower(),
        str(spec.get("verity_root_hash_hex") or "").lower(),
    )


def scope_vms(scope: dict[str, Any]) -> list[Vm]:
    """The active VMs `scope` selects, by id. Each key narrows (callers
    refuse an empty scope: it would select every VM)."""
    # Never a CDN node: it upgrades by replacement (`apps.cdn.reconcile`).
    qs = Vm.objects.filter(state=VmState.ACTIVE, cdn_node__isnull=True)
    if scope.get("vm_ids"):
        qs = qs.filter(vm_id__in=scope["vm_ids"])
    if scope.get("tenant_ids"):
        qs = qs.filter(tenant_id__in=scope["tenant_ids"])
    if scope.get("node_ids"):
        qs = qs.filter(host__in=scope["node_ids"])
    vms = list(qs.order_by("vm_id"))
    if scope.get("bake_ids"):
        bases = _bases(scope["bake_ids"])
        vms = [vm for vm in vms if _base_of(vm) in bases]
    return vms


def _on_release(vm: Vm, release: int) -> bool:
    from .services import guest_components

    record = launch_record.latest_record(vm.vm_id)
    if record is None:
        return False
    build = guest_components.build_for_initrd(
        str((record.spec_json or {}).get("initrd_sha256_hex") or "").lower()
    )
    return build is not None and int(build.release_id) == release


# ─── create / pause / resume / abort ─────────────────────────────────


def _validate(
    *,
    scope: dict[str, Any],
    waves: list[int],
    canary_vm_ids: list[str],
    max_concurrent: int,
    wave_pause_s: int,
    max_failure_ratio: float,
    not_before: datetime | None,
) -> None:
    unknown = set(scope) - set(_SCOPE_KEYS)
    if unknown:
        raise RolloutRefused(f"unknown scope keys {sorted(unknown)}", "wire")
    if not any(scope.get(k) for k in _SCOPE_KEYS) or any(
        not isinstance(v, list) or not v for v in scope.values()
    ):
        raise RolloutRefused(
            "the scope must name at least one non-empty selector (an empty one would be every VM)",
            "wire",
        )
    if (
        not waves
        or any(not isinstance(w, int) or isinstance(w, bool) or not 0 < w <= 100 for w in waves)
        or any(b <= a for a, b in zip(waves, waves[1:], strict=False))
        or waves[-1] != 100
    ):
        raise RolloutRefused("waves must be strictly increasing percentages ending at 100", "wire")
    if not canary_vm_ids:
        raise RolloutRefused("a rollout starts with at least one canary VM", "wire")
    if not 1 <= max_concurrent <= 50 or not 0 <= max_failure_ratio < 1 or wave_pause_s < 0:
        raise RolloutRefused("max_concurrent / max_failure_ratio / wave_pause_s", "wire")
    if not_before is not None and not_before.tzinfo is None:
        raise RolloutRefused("not_before must carry a timezone", "wire")


def create_rollout(
    *,
    release: int,
    canary_vm_ids: list[str],
    scope: dict[str, Any],
    decided_by: Any,
    waves: list[int] | None = None,
    max_concurrent: int = 2,
    wave_pause_s: int = 1800,
    max_failure_ratio: float = 0.1,
    not_before: datetime | None = None,
) -> GuestRollout:
    """Admit a rollout. Refuses (`RolloutRefused`) a malformed request (an
    empty scope included), an unknown or withdrawn release, a release
    without the health leg beyond its canaries, a VM in another open
    rollout, and — listing them — VMs whose base has no build of the
    release. Its members are fixed here."""
    waves = list(DEFAULT_WAVES) if waves is None else list(waves)
    _validate(
        scope=scope,
        waves=waves,
        canary_vm_ids=canary_vm_ids,
        max_concurrent=max_concurrent,
        wave_pause_s=wave_pause_s,
        max_failure_ratio=max_failure_ratio,
        not_before=not_before,
    )
    rel = GuestComponentRelease.objects.filter(version=release, withdrawn_at__isnull=True).first()
    if rel is None:
        raise RolloutRefused(f"no registered release {release}", "unknown-release")
    canary_ids = sorted(set(canary_vm_ids))
    canaries = list(Vm.objects.filter(vm_id__in=canary_ids, state=VmState.ACTIVE))
    if len(canaries) != len(canary_ids):
        raise RolloutRefused("a canary VM is unknown or not active", "unknown-canary")
    members = [
        vm
        for vm in scope_vms(scope)
        if vm.vm_id not in set(canary_ids) and not _on_release(vm, release)
    ]
    if members and not rel.health_mask:
        raise RolloutRefused(
            f"release {release} has no health checks: canaries only (gate condition 4)",
            "no-health-leg",
        )
    missing = [
        vm.vm_id
        for vm in canaries + members
        if not _on_release(vm, release) and guest_upgrade.build_for_vm(vm, release) is None
    ]
    if missing:
        raise RolloutRefused(
            f"{len(missing)} VM(s) have no build of release {release} for their base",
            "missing-builds",
            missing,
        )
    wanted = set(canary_ids) | {vm.vm_id for vm in members}
    with transaction.atomic():
        # Creations serialize on the global lock: two overlapping rollouts
        # cannot both pass this check.
        global_lock()
        open_rollouts = list(GuestRollout.objects.exclude(state__in=TERMINAL_GUEST_ROLLOUT_STATES))
        busy = sorted(
            wanted & {vm_id for r in open_rollouts for vm_id in [*r.canary_vm_ids, *r.members]}
        )
        if busy:
            raise RolloutRefused(
                f"{len(busy)} VM(s) belong to another open rollout", "vm-in-rollout", busy
            )
        rollout = GuestRollout.objects.create(
            rollout_id=f"gr-{secrets.token_hex(8)}",
            release=rel,
            canary_vm_ids=canary_ids,
            scope={k: list(v) for k, v in scope.items()},
            members=[vm.vm_id for vm in members],
            population=len(members),
            waves=waves,
            assigned={"0": canary_ids},
            max_concurrent=max_concurrent,
            wave_pause_s=wave_pause_s,
            max_failure_ratio=max_failure_ratio,
            not_before=not_before,
            decided_by=decided_by,
        )
    log.info(
        "guest rollout %s created: release %s, %d canary, %d member(s), waves %s",
        rollout.rollout_id,
        release,
        len(canary_ids),
        len(members),
        waves,
    )
    return rollout


def _locked(rollout: GuestRollout) -> GuestRollout:
    """The global lock, then the rollout's row, for the rest of the
    transaction."""
    global_lock()
    return (
        GuestRollout.objects.select_for_update()
        .select_related("release", "decided_by")
        .get(pk=rollout.pk)
    )


def _save(rollout: GuestRollout, **fields: Any) -> None:
    for k, v in fields.items():
        setattr(rollout, k, v)
    rollout.version += 1
    rollout.save(update_fields=[*fields, "version"])


def _pause_locked(rollout: GuestRollout, reason: str) -> None:
    _save(rollout, state=R.PAUSED.value, paused_reason=reason[:256])
    log.warning("guest rollout %s PAUSED: %s", rollout.rollout_id, reason)


def pause(rollout: GuestRollout, reason: str) -> None:
    with transaction.atomic():
        locked = _locked(rollout)
        if locked.state != R.ACTIVE:
            raise RolloutRefused(f"rollout {locked.rollout_id} is {locked.state}", "not-active")
        _pause_locked(locked, reason)
    rollout.refresh_from_db()


def resume(rollout: GuestRollout) -> None:
    """Resume a paused rollout, acknowledging what stopped it."""
    with transaction.atomic():
        locked = _locked(rollout)
        if locked.state != R.PAUSED:
            raise RolloutRefused(f"rollout {locked.rollout_id} is {locked.state}", "not-paused")
        _save(locked, state=R.ACTIVE.value, paused_reason="", acknowledged_at=timezone.now())
    rollout.refresh_from_db()
    log.info("guest rollout %s resumed", rollout.rollout_id)


def abort(rollout: GuestRollout, *, by: str) -> int:
    """Stop the rollout for good: its pending jobs are cancelled, the jobs
    holding a VM finish on their own. Returns how many were cancelled.
    Under the rollout's lock: no tick admits a job in between."""
    cancelled = 0
    with transaction.atomic():
        locked = _locked(rollout)
        if locked.state in TERMINAL_GUEST_ROLLOUT_STATES:
            raise RolloutRefused(f"rollout {locked.rollout_id} is {locked.state}", "finished")
        _save(locked, state=R.ABORTED.value, finished_at=timezone.now())
        for job in locked.jobs.filter(state=J.PENDING.value).select_related("vm", "target"):
            try:
                guest_upgrade.cancel_pending(job, by=f"rollout {locked.rollout_id} aborted by {by}")
                cancelled += 1
            except StartError:
                pass  # it took the VM in between: it finishes on its own
    rollout.refresh_from_db()
    log.warning("guest rollout %s ABORTED by %s (%d cancelled)", rollout.rollout_id, by, cancelled)
    return cancelled


# ─── the leave a pending job needs ───────────────────────────────────


def _parked(job: GuestUpgradeJob) -> bool:
    """Pending on a stopped VM: it waits for the VM's next start and neither
    holds a slot nor keeps its wave open (it still needs `may_start`)."""
    return job.state == J.PENDING and job.vm.power_state == VmPowerState.STOPPED


def _busy_hosts(exclude_job: Any = None) -> set[str]:
    """Miners with a guest upgrade holding a VM — any rollout's or none."""
    qs = GuestUpgradeJob.objects.filter(state__in=HOLDING_GUEST_UPGRADE_STATES)
    if exclude_job is not None:
        qs = qs.exclude(pk=exclude_job.pk)
    return set(qs.values_list("node_id", flat=True))


def may_start(job: GuestUpgradeJob) -> str:
    """Why a PENDING job may not take its VM now (`""` = it may). Called by
    the job's `pending` handler with the global lock held.

    Every job: its miner must not run another guest upgrade. A rollout's
    job also needs the rollout active, a free slot, and nothing that
    should stop the rollout (an outcome of this very tick included — the
    rollout's own tick may not have seen it yet)."""
    if job.node_id in _busy_hosts(exclude_job=job):
        return f"miner {job.node_id} runs another guest upgrade"
    if job.rollout_id is None:
        return ""
    rollout = (
        GuestRollout.objects.select_for_update().select_related("release").get(pk=job.rollout_id)
    )
    if rollout.state != R.ACTIVE:
        return f"rollout {rollout.rollout_id} is {rollout.state}"
    jobs = list(rollout.jobs.select_related("vm"))
    holding = [j for j in jobs if j.state in HOLDING_GUEST_UPGRADE_STATES and j.pk != job.pk]
    if len(holding) >= rollout.max_concurrent:
        return f"rollout {rollout.rollout_id}: {rollout.max_concurrent} upgrade(s) in flight"
    reason = _stop_reason(rollout, jobs)
    if reason:
        return f"rollout {rollout.rollout_id} must stop: {reason}"
    return ""


# ─── the tick ────────────────────────────────────────────────────────


def _skip(rollout: GuestRollout, vm_id: str, category: str) -> None:
    rollout.skipped = {
        **rollout.skipped,
        vm_id: {"category": category, "at": timezone.now().isoformat()},
    }


def _fresh(rollout: GuestRollout, when: datetime | None) -> bool:
    since = rollout.acknowledged_at
    return since is None or (when is not None and when > since)


def _stop_reason(rollout: GuestRollout, jobs: list[GuestUpgradeJob]) -> str:
    if rollout.release.withdrawn_at is not None:
        return f"release {rollout.release_id} withdrawn"
    for vm_id, entry in sorted(rollout.skipped.items()):
        at = datetime.fromisoformat(entry["at"])
        if entry["category"] not in _BENIGN_SKIPS and _fresh(rollout, at):
            return f"{vm_id} not admitted: {entry['category']}"
    fresh = [
        j
        for j in jobs
        if j.state in TERMINAL_GUEST_UPGRADE_STATES and _fresh(rollout, j.finished_at)
    ]
    for job in fresh:
        if _benign_cancel(job):
            continue
        if job.wave == 0 and job.state != J.DONE:
            return f"canary {job.vm.vm_id}: {job.state} ({job.reason})"
        if job.state not in (J.DONE, J.ROLLED_BACK):
            return f"{job.vm.vm_id}: {job.state} ({job.reason})"
    if rollout.current_wave == 0:
        # Every canary settled (terminal or skipped) and none upgraded: no
        # evidence, and nothing will produce any — stop rather than wait.
        canary_jobs = {j.vm.vm_id: j for j in jobs if j.wave == 0}
        settled = all(
            c in rollout.skipped
            or (c in canary_jobs and canary_jobs[c].state in TERMINAL_GUEST_UPGRADE_STATES)
            for c in rollout.canary_vm_ids
        )
        news = any(_fresh(rollout, j.finished_at) for j in canary_jobs.values()) or any(
            _fresh(rollout, datetime.fromisoformat(e["at"]))
            for c, e in rollout.skipped.items()
            if c in rollout.canary_vm_ids
        )
        if settled and news and not any(j.state == J.DONE for j in canary_jobs.values()):
            return "no canary was upgraded"
    # Every wave, not only the current one (a job parked on a stopped VM
    # can roll back after its wave closed), counting ALL its rollbacks — a
    # resume acknowledges the stop, not the failures: it takes a new one to
    # stop again.
    for wave, vm_ids in rollout.assigned.items():
        in_wave = [j for j in jobs if str(j.wave) == wave and j.state == J.ROLLED_BACK]
        new = [j for j in in_wave if _fresh(rollout, j.finished_at)]
        size = max(1, len(vm_ids))
        if new and len(in_wave) / size > rollout.max_failure_ratio:
            return f"wave {wave}: {len(in_wave)}/{size} rolled back"
    return ""


#: Cancellation reasons that say nothing about the release: the VM moved
#: (`vm-changed`) or left the rollout's scope (`left-scope`) before its
#: window.
_BENIGN_CANCELS = ("vm-changed", "left-scope")


def _benign_cancel(job: GuestUpgradeJob) -> bool:
    """Never for a canary: a canary that did not end `done` is no evidence."""
    return bool(job.wave) and job.state == J.CANCELLED and job.reason.startswith(_BENIGN_CANCELS)


def out_of_scope(job: GuestUpgradeJob, vm: Vm) -> bool:
    """A rollout member's job whose VM no longer matches the rollout's
    scope (checked on the LOCKED VM row as the job takes it)."""
    if job.rollout_id is None or not job.wave:
        return False
    rollout = GuestRollout.objects.get(pk=job.rollout_id)
    return not scope_vms({**rollout.scope, "vm_ids": [vm.vm_id]})


def _admit(rollout: GuestRollout, jobs: list[GuestUpgradeJob]) -> int:
    """Admit the current wave's next VMs within the concurrency and
    one-per-miner limits (under the rollout's lock). Returns how many."""
    wave = rollout.current_wave
    have = {j.vm.vm_id for j in jobs}
    holding = [j for j in jobs if j.state not in TERMINAL_GUEST_UPGRADE_STATES and not _parked(j)]
    hosts = _busy_hosts() | {j.node_id for j in holding}
    slots = rollout.max_concurrent - len(holding)
    admitted = 0
    for vm_id in rollout.assigned.get(str(wave), []):
        if slots <= 0:
            break
        if vm_id in have or vm_id in rollout.skipped:
            continue
        vm = Vm.objects.filter(vm_id=vm_id).first()
        if vm is None or vm.state != VmState.ACTIVE:
            _skip(rollout, vm_id, "vm-not-active")
            continue
        if wave > 0 and not scope_vms({**rollout.scope, "vm_ids": [vm_id]}):
            _skip(rollout, vm_id, "left-scope")
            continue
        if vm.host in hosts:
            continue  # one guest upgrade per miner at a time
        build = guest_upgrade.build_for_vm(vm, int(rollout.release_id))
        if build is None:
            if _on_release(vm, int(rollout.release_id)):
                _skip(rollout, vm_id, "already-on-target")
            else:
                _skip(rollout, vm_id, "no-build")
            continue
        try:
            guest_upgrade.start_guest_upgrade(
                vm=vm,
                build=build,
                decided_by=rollout.decided_by,
                not_before=rollout.not_before,
                rollout=rollout,
                wave=wave,
            )
        except StartError as exc:
            if exc.category == "job-in-flight":
                continue  # another operation holds it: retried next tick
            _skip(rollout, vm_id, exc.category)
            continue
        admitted += 1
        slots -= 1
        hosts.add(vm.host)
    return admitted


def _wave_complete(rollout: GuestRollout, jobs: list[GuestUpgradeJob]) -> bool:
    wave = rollout.current_wave
    by_vm = {j.vm.vm_id: j for j in jobs if j.wave == wave}
    for vm_id in rollout.assigned.get(str(wave), []):
        if vm_id in rollout.skipped:
            continue
        job = by_vm.get(vm_id)
        if job is None:
            return False
        if job.state not in TERMINAL_GUEST_UPGRADE_STATES and not _parked(job):
            return False
    if wave == 0:
        # The canaries are evidence only if one of them was upgraded.
        return any(j.state == J.DONE for j in by_vm.values())
    return True


def _next_wave(rollout: GuestRollout, jobs: list[GuestUpgradeJob]) -> None:
    """Start the next wave — or, after the last, finish once every job is
    terminal (a job parked on a stopped VM keeps the rollout open, and
    abortable)."""
    nxt = rollout.current_wave + 1
    if nxt > len(rollout.waves):
        if all(j.state in TERMINAL_GUEST_UPGRADE_STATES for j in jobs):
            _save(rollout, state=R.DONE.value, finished_at=timezone.now(), wave_done_at=None)
            log.info("guest rollout %s DONE", rollout.rollout_id)
        return
    taken = {vm_id for ids in rollout.assigned.values() for vm_id in ids}
    already = len(taken - set(rollout.canary_vm_ids))
    want = math.ceil(rollout.population * rollout.waves[nxt - 1] / 100)
    chosen = [vm_id for vm_id in rollout.members if vm_id not in taken][: max(0, want - already)]
    _save(
        rollout,
        current_wave=nxt,
        assigned={**rollout.assigned, str(nxt): chosen},
        wave_done_at=None,
    )
    log.info(
        "guest rollout %s: wave %d (%d%%) takes %d VM(s)",
        rollout.rollout_id,
        nxt,
        rollout.waves[nxt - 1],
        len(chosen),
    )


def advance_rollout(rollout: GuestRollout) -> None:
    with transaction.atomic():
        rollout = _locked(rollout)
        if rollout.state != R.ACTIVE:
            return
        jobs = list(rollout.jobs.select_related("vm"))
        reason = _stop_reason(rollout, jobs)
        if reason:
            _pause_locked(rollout, reason)
            return
        skipped_before = dict(rollout.skipped)
        _admit(rollout, jobs)
        if rollout.skipped != skipped_before:
            _save(rollout, skipped=rollout.skipped)
            reason = _stop_reason(rollout, jobs)
            if reason:
                _pause_locked(rollout, reason)
                return
        jobs = list(rollout.jobs.select_related("vm"))
        if not _wave_complete(rollout, jobs):
            return
        now = timezone.now()
        if rollout.wave_done_at is None:
            _save(rollout, wave_done_at=now)
            return
        if (now - rollout.wave_done_at).total_seconds() >= rollout.wave_pause_s:
            _next_wave(rollout, jobs)


def tick_guest_rollouts() -> int:
    """Advance every open rollout one step (behind the guest upgrade flag)."""
    if not guest_upgrade.enabled():
        return 0
    rollouts = list(GuestRollout.objects.exclude(state__in=TERMINAL_GUEST_ROLLOUT_STATES))
    for rollout in rollouts:
        try:
            advance_rollout(rollout)
        except Exception:  # noqa: BLE001 — one rollout must not kill the tick.
            log.exception("guest rollout %s: unhandled error in tick", rollout.rollout_id)
    return len(rollouts)


# ─── read ────────────────────────────────────────────────────────────


def serialize_rollout(rollout: GuestRollout) -> dict[str, Any]:
    jobs = list(rollout.jobs.select_related("vm"))
    per_wave: dict[str, dict[str, int]] = {}
    for job in jobs:
        bucket = per_wave.setdefault(str(job.wave), {})
        state = "pending-stopped" if _parked(job) else job.state
        bucket[state] = bucket.get(state, 0) + 1
    return {
        "rollout_id": rollout.rollout_id,
        "release": int(rollout.release_id),
        "state": rollout.state,
        "paused_reason": rollout.paused_reason or None,
        "current_wave": rollout.current_wave,
        "waves": rollout.waves,
        "canary_vm_ids": rollout.canary_vm_ids,
        "scope": rollout.scope,
        "members": rollout.members,
        "population": rollout.population,
        "assigned": rollout.assigned,
        "jobs": per_wave,
        "skipped": {vm_id: e["category"] for vm_id, e in rollout.skipped.items()},
        "max_concurrent": rollout.max_concurrent,
        "wave_pause_s": rollout.wave_pause_s,
        "max_failure_ratio": rollout.max_failure_ratio,
        "not_before": rollout.not_before.isoformat() if rollout.not_before else None,
        "decided_by": rollout.decided_by.name,
        "created_at": rollout.created_at.isoformat(),
        "finished_at": rollout.finished_at.isoformat() if rollout.finished_at else None,
    }
