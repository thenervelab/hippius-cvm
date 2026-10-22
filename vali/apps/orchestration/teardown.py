"""Tear down a vali-owned throwaway golden VM — the no-leak safety net.

Lifted out of the synthetic monitor (`apps/synthetic/e2e.py`) so any
in-process caller that launches its own short-lived VM (the synthetic
monitor today, the disk-tier probe next) shares one teardown:

  1. a no-op if the VM row is absent or already `destroyed`, else
  2. drive the real §24 decommission to completion, else
  3. force-erase (Vault transit key + KV) and destroy the domain
     in-process as a last resort.

A VM row that does not exist yet is reconciled against its async
`LaunchJob` (cancel-before-place, else poll-then-decommission), so a
launch whose response was lost never leaks either.

The caller supplies how §24 is driven (`decommission`), the force-destroy
it wants on the fallback path (`force_destroy`, so its own test seam is
honoured), its timeouts and clock, and the reason strings recorded on the
jobs it touches. Nothing here knows which tenant it is tearing down: the
"only ever my own VMs" invariant stays with the caller.
"""

from __future__ import annotations

import logging
import secrets
import time
from collections.abc import Callable
from typing import Any

from django.utils import timezone

log = logging.getLogger("apps.orchestration.teardown")

# Drive §24 for `vm_id` to `done` before the monotonic `deadline`; raise on
# failure or timeout.
Decommission = Callable[[str, float], object]
# The in-process force-erase + destroy; returns the step note.
ForceDestroy = Callable[[str], str]


def teardown_vm(
    vm_id: str,
    *,
    decommission: Decommission,
    force_destroy: ForceDestroy,
    timeout_s: float,
    poll_interval_s: float,
    cancel_reason: str,
    label: str,
    now: Callable[[], float] = time.monotonic,
    sleep: Callable[[float], None] = time.sleep,
) -> tuple[str, bool]:
    """Ensure the VM is gone. Returns (detail, forced) where `forced` marks
    that the in-process fallback had to run (alertable).

    Uses its OWN fresh deadline so even a fully-budget-exhausted run still
    gets a clean §24 attempt before falling back to force-destroy.

    Critically, the cleanup target is resolved from BOTH the `Vm` row AND
    the async `LaunchJob`: `POST /v1/vm/launch` commits a QUEUED
    `LaunchJob` and the `vali_launch_tick` worker materializes the `Vm`
    LATER. If the launch POST committed the job but its HTTP response was
    lost (timeout / mid-call pod restart), there is no `Vm` row YET — but
    the worker will still place + boot it. Reconciling against the pending
    `LaunchJob` (cancel-before-place, else poll-then-decommission) is what
    makes the no-leak guarantee hold across that handoff."""
    from apps.lifecycle.models import Vm, VmState

    vm = Vm.objects.filter(vm_id=vm_id).first()
    if vm is not None:
        if vm.state == VmState.DESTROYED:
            return "already destroyed (clean)", False
        return teardown_existing_vm(
            vm_id,
            decommission=decommission,
            force_destroy=force_destroy,
            timeout_s=timeout_s,
            now=now,
        )

    # No `Vm` row — but an async launch may have committed a `LaunchJob`
    # the worker will later turn into a booted VM. Reconcile so a
    # committed-but-lost-response launch never leaks.
    return reconcile_pending_launch(
        vm_id,
        decommission=decommission,
        force_destroy=force_destroy,
        timeout_s=timeout_s,
        poll_interval_s=poll_interval_s,
        cancel_reason=cancel_reason,
        label=label,
        now=now,
        sleep=sleep,
    )


def teardown_existing_vm(
    vm_id: str,
    *,
    decommission: Decommission,
    force_destroy: ForceDestroy,
    timeout_s: float,
    now: Callable[[], float] = time.monotonic,
) -> tuple[str, bool]:
    """Tear down a materialized (non-destroyed) `Vm`: prefer the real §24
    API, fall back to in-process force-erase + destroy."""
    from apps.lifecycle.models import Vm, VmState

    deadline = now() + timeout_s
    # 1) Prefer the real §24 API (exactly what the happy path does).
    try:
        decommission(vm_id, deadline)
        vm = Vm.objects.filter(vm_id=vm_id).first()
        if vm is not None and vm.state == VmState.DESTROYED:
            return "torn down via §24 API", False
    except Exception as exc:
        log.warning("teardown §24 API path failed for %s: %s", vm_id, exc)

    # 2) Last resort: force crypto-erase + destroy in-process so a stuck
    #    decommission never leaves a running VM or an un-erased KEK.
    return force_destroy(vm_id), True


def reconcile_pending_launch(
    vm_id: str,
    *,
    decommission: Decommission,
    force_destroy: ForceDestroy,
    timeout_s: float,
    poll_interval_s: float,
    cancel_reason: str,
    label: str,
    now: Callable[[], float] = time.monotonic,
    sleep: Callable[[float], None] = time.sleep,
) -> tuple[str, bool]:
    """No `Vm` row exists — reconcile against a possibly-committed async
    `LaunchJob` so a launch whose response was lost never leaks.

    Strategy (race-safe):
      1. If a non-terminal `LaunchJob` exists, try to CANCEL it via a CAS
         on the QUEUED state — a queued job the worker has not yet claimed
         will then never place a VM.
      2. If the CAS is lost (the worker already claimed it to `running`)
         or a VM raced into existence, POLL (bounded) for the `Vm` to
         materialize, then drive the real §24 decommission / force-erase
         so even a booted VM is erased + destroyed.
    """
    from apps.lifecycle.models import Vm
    from apps.orchestration.models import (
        TERMINAL_LAUNCH_STATES,
        LaunchJob,
        LaunchJobState,
        LaunchPhase,
    )

    job = (
        LaunchJob.objects.exclude(state__in=list(TERMINAL_LAUNCH_STATES))
        .filter(vm_id=vm_id)
        .order_by("-started_at")
        .first()
    )
    if job is None:
        return "no vm row and no pending launch — nothing to clean", False

    # 1) Cancel-before-place: only a still-QUEUED (unclaimed) job cancels
    #    cleanly. The CAS on (id, version, state=queued) loses if the
    #    worker already claimed it to `running`.
    cancelled = LaunchJob.objects.filter(
        id=job.id, version=job.version, state=LaunchJobState.QUEUED.value
    ).update(
        state=LaunchJobState.FAILED.value,
        version=job.version + 1,
        reason=cancel_reason,
        finished_at=timezone.now(),
        phase=LaunchPhase.FAILED.value,
        phase_started_at=timezone.now(),
    )
    if cancelled and not Vm.objects.filter(vm_id=vm_id).exists():
        log.info("%s teardown cancelled queued launch for %s (no VM placed)", label, vm_id)
        return "cancelled queued launch before placement (no leak)", False

    # 2) The worker already claimed it (placing/booting) or a VM raced in —
    #    wait (bounded) for the Vm to materialize, then tear it down.
    deadline = now() + timeout_s
    if not await_vm_materialize(
        vm_id, deadline, poll_interval_s=poll_interval_s, now=now, sleep=sleep
    ):
        return "pending launch did not materialize a vm (no leak)", False
    detail, forced = teardown_existing_vm(
        vm_id,
        decommission=decommission,
        force_destroy=force_destroy,
        timeout_s=timeout_s,
        now=now,
    )
    return f"reconciled pending launch → {detail}", forced


def await_vm_materialize(
    vm_id: str,
    deadline: float,
    *,
    poll_interval_s: float,
    now: Callable[[], float] = time.monotonic,
    sleep: Callable[[float], None] = time.sleep,
) -> bool:
    """Poll until the `Vm` row for a claimed launch appears, or the launch
    reaches a terminal state without one. Returns True iff a `Vm` exists
    (and therefore must be torn down)."""
    from apps.lifecycle.models import Vm
    from apps.orchestration.models import TERMINAL_LAUNCH_STATES, LaunchJob

    while now() < deadline:
        if Vm.objects.filter(vm_id=vm_id).exists():
            return True
        job = LaunchJob.objects.filter(vm_id=vm_id).order_by("-started_at").first()
        if job is None or job.state in TERMINAL_LAUNCH_STATES:
            # The launch finished (or vanished) without a VM — one last look.
            return Vm.objects.filter(vm_id=vm_id).exists()
        sleep(poll_interval_s)
    return Vm.objects.filter(vm_id=vm_id).exists()


def force_destroy(vm_id: str, *, handoff_reason: str, label: str) -> str:
    """Force crypto-erase + destroy a golden VM in-process. Returns the step
    note. `handoff_reason` is recorded on the forced §24 job opened when the
    destroy order cannot be delivered (see `hand_teardown_to_tick`)."""
    from apps.lifecycle.models import Vm, VmState, destroyed_power_fields
    from apps.orchestration import effects, service

    vm = Vm.objects.filter(vm_id=vm_id).first()
    if vm is None:
        return "forced: vm row vanished"
    if service._has_active_job(vm, ignore_storage_move=True):
        # A §24 job (the API teardown, or one handed off on an earlier reap)
        # owns this VM; tearing it down underneath would tombstone a VM the
        # job then cannot finish properly (placements, host, erase stamp).
        return "forced teardown: left-to-in-flight-job"
    steps: list[str] = []
    # Stop the domain FIRST. The order used to be erase → revoke → destroy
    # → tombstone, with a failed destroy only logged: live (on two
    # miners), this pod could not reach the Edge, so every forced teardown
    # erased the KEK and tombstoned the row while the domain kept RUNNING —
    # a zombie that then zombie-quarantined its miner for placement. The
    # data was dead; the VM was not. Now nothing is erased or tombstoned
    # here unless the destroy order went out; otherwise the teardown is
    # handed to the orchestration tick, which owns the Edge path and
    # retries the destroy (and re-drives a failed job) until it lands.
    try:
        effects.dispatch_destroy(vm)
        steps.append("domain-destroyed")
    except Exception as exc:
        log.error(
            "forced dispatch_destroy failed for %s: %s — NOT erasing or "
            "tombstoning in-process; handing the teardown to the tick",
            vm_id,
            exc,
        )
        steps.append(f"destroy-failed({exc})")
        steps.append(hand_teardown_to_tick(vm, reason=handoff_reason, label=label))
        return "forced teardown: " + ", ".join(steps)
    # Callers only ever tear down golden VMs — golden erase destroys the
    # Vault transit key (data-death) + deletes the KV. Idempotent.
    erased = False
    try:
        effects.crypto_erase_kek_transit(vm)
        steps.append("crypto-erased")
        erased = True
    except Exception as exc:
        # NOT a warning. A failed erase means the tenant KEK is still
        # live in Vault-Transit while we are about to call the VM dead.
        log.error(
            "forced crypto-erase FAILED for %s: %s — the KEK is still live; "
            "refusing to mark the VM Destroyed",
            vm_id,
            exc,
        )
        steps.append(f"crypto-erase-failed({exc})")
    if erased:
        # The §24 job this teardown bypasses revokes the NetBird peer after
        # the erase; tenant peers are persistent, so do the same here
        # (best-effort — the peer janitor collects it if this fails).
        try:
            effects.revoke_netbird(vm)
            steps.append("netbird-revoked")
        except Exception as exc:
            log.warning("forced revoke_netbird failed for %s: %s", vm_id, exc)
            steps.append(f"netbird-revoke-failed({exc})")
    # Mark Destroyed ONLY if the key is actually gone.
    #
    # This used to be unconditional "best-effort so it is not re-picked /
    # re-alarmed", which inverts the guarantee it is recording: an erase
    # failure was a `log.warning` and the VM was tombstoned anyway, so
    # §24's data-death promise would be written down as kept while
    # `kek-<vm_id>` stayed live in Vault.
    #
    # A fleet audit on 2026-07-29 found 37 VMs marked Destroyed with a live
    # KEK — 12 from §24 jobs that failed on the dead KBS crypto-erase route
    # (since fixed by #870), 25 tombstoned out-of-band. THIS path has not
    # produced one: when it was written it was reachable only for the
    # synthetic tenant, and every VM that provably took this fallback
    # probes KEK-gone. It is rewritten so that it never can.
    #
    # On failure the VM is CAS'd to Decommissioning rather than left
    # Active. That frees the capacity slot through the existing
    # `_drain_cause` "vm-terminal" path (which drains on DESTROYED *or*
    # DECOMMISSIONING) — leaving it Active would pin the miner's slot, RAM
    # and CPU indefinitely, one more per reap cycle under a persistent
    # erase failure. Decommissioning claims no data death, and the caller's
    # reaper re-picks anything non-DESTROYED, so it keeps retrying and
    # re-alarming until the erase actually succeeds. An unfulfilled erase
    # IS an alarm; the noise is the point.
    if erased:
        Vm.objects.filter(vm_id=vm_id).exclude(state=VmState.DESTROYED).update(
            state=VmState.DESTROYED, **destroyed_power_fields()
        )
        # Its dedicated disks, if any (E4): released for a wipe and a probe.
        from apps.disktier.dedicated import release_for_destroyed_vm

        destroyed = Vm.objects.filter(vm_id=vm_id).first()
        if destroyed is not None:
            release_for_destroyed_vm(destroyed)
    else:
        Vm.objects.filter(vm_id=vm_id).exclude(
            state__in=(VmState.DESTROYED, VmState.DECOMMISSIONING)
        ).update(state=VmState.DECOMMISSIONING)
        steps.append("NOT-tombstoned(kek-still-live)")
    return "forced teardown: " + ", ".join(steps)


def hand_teardown_to_tick(vm: Any, *, reason: str, label: str) -> str:
    """Open a forced §24 job for `vm` at `CryptoErasing`, for the
    orchestration tick to drive: it erases the KEK, dispatches the destroy
    over its own Edge path (retrying within the step window), tombstones
    only after that, and `sweep_stranded_decommissions` re-drives a job
    that fails. The same shape as that re-drive. A VM that already has a
    job in flight is left to it. Returns the step note."""
    from django.db import IntegrityError, transaction

    from apps.lifecycle.models import Vm, VmState
    from apps.orchestration import service
    from apps.orchestration.models import (
        DecommissionJob,
        DecommissionState,
        LaunchJob,
    )

    if service._has_active_job(vm, ignore_storage_move=True):
        return "left-to-in-flight-job"
    last = DecommissionJob.objects.filter(vm=vm).order_by("-started_at").first()
    if last is not None and last.state == DecommissionState.FAILED.value:
        # `sweep_stranded_decommissions` re-drives it, under its own cap;
        # opening another job here every reap would bypass that cap.
        return "left-to-stranded-sweep"
    decided_by = next(
        (
            j.decided_by
            for j in (
                DecommissionJob.objects.filter(vm=vm).order_by("-started_at").first(),
                LaunchJob.objects.filter(vm_id=vm.vm_id).order_by("-started_at").first(),
            )
            if j is not None and j.decided_by_id is not None
        ),
        None,
    )
    if decided_by is None:
        # Nothing to attribute a job to. Still kill the data: erase
        # in-process and fence the row to Decommissioning — never
        # Destroyed, since the domain may still run.
        log.error(
            "%s reaper: %s has no job to attribute a forced §24 to — "
            "erasing in-process, NOT tombstoning (domain may still run)",
            label,
            vm.vm_id,
        )
        from apps.orchestration import effects

        try:
            effects.crypto_erase_kek_transit(vm)
            note = "erased-in-process"
        except Exception as exc:
            note = f"crypto-erase-failed({exc})"
        Vm.objects.filter(pk=vm.pk).exclude(
            state__in=(VmState.DESTROYED, VmState.DECOMMISSIONING)
        ).update(state=VmState.DECOMMISSIONING)
        return f"NOT-handed-off(no-decider), {note}"
    now = timezone.now()
    try:
        with transaction.atomic():
            Vm.objects.filter(pk=vm.pk).exclude(
                state__in=(VmState.DESTROYED, VmState.DECOMMISSIONING)
            ).update(state=VmState.DECOMMISSIONING)
            job = DecommissionJob.objects.create(
                job_id=secrets.token_hex(16),
                vm=vm,
                state=DecommissionState.CRYPTO_ERASING.value,
                phase_started_at=now,
                decided_by=decided_by,
                forced=True,
                reason=reason,
            )
    except IntegrityError:
        return "left-to-in-flight-job"
    return f"handed-to-tick(job={job.job_id})"
