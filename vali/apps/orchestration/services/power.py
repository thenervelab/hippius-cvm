"""Operator power operations — stop / start / reboot.

WHY THIS IS NOT A LIFECYCLE TRANSITION. `Vm.state` mirrors
`kbs_core::lifecycle::VmState`, which the KBS checks serializably before
every KEK release. A stopped VM must be able to unlock again when it
starts, so it stays `active` there — a `Stopped` lifecycle variant would
make the KBS refuse the guest its own key. Power is a separate axis
(`Vm.power_state`), and this module is its writer — besides the settling
of an abandoned marker, and the §24 tombstone, which sets the terminal `off`.

WHAT A STOPPED VM KEEPS. Everything that makes `start` able to succeed:
the encrypted overlay, the Vault-Transit KEK, the anti-rollback counter,
and the slot on ONE specific miner. `start` relaunches on that same host —
never through the scheduler, which could place it on a miner whose disk
has no overlay.

⚠️ WHAT IT DOES NOT DO. It does not pay the miner. `UsageAccrual` accrues
only from guest-attested served-receipts, and a stopped guest emits none;
a miner is paid for VM time genuinely up, never for parked VMs. Tenant
billing — which DOES continue while stopped, because the reservation is
held — lives in the layer above this repo and reads `power_state` +
`power_state_at`. Two ledgers, two questions; do not wire one to the other.
"""

from __future__ import annotations

import logging
import uuid
from datetime import timedelta

from django.db import transaction
from django.utils import timezone

from apps.lifecycle.models import Vm, VmPowerState, VmState

log = logging.getLogger("apps.orchestration.power")

#: Total budget for a power stop's dispatch, re-asks included. The API runs
#: it inside the request, under gunicorn's 60 s worker timeout
#: (`vali/Dockerfile`): the common slow case — the Edge 502s at its 30 s
#: forward timeout, one re-ask 10 s later reads the recorded outcome — fits.
POWER_STOP_DEADLINE_S = 50.0


#: `PowerOpRefused.reason` for a start the miner refused because it does
#: not hold the VM's disks — never retryable on the same host.
DISKS_MISSING_REASON = "disks-missing"

#: `PowerOpRefused.reason` for a start whose allowlist pin waited out the
#: §22 pin lock behind other starts — transient: nothing changed, re-ask.
PIN_BUSY_REASON = "allowlist-pin-busy"


class PowerOpRefused(Exception):
    """The requested power operation is not legal for this VM right now.

    Carries a stable `reason` slug so callers can branch without parsing
    prose, and a sentence an operator can act on.
    """

    def __init__(self, reason: str, detail: str) -> None:
        super().__init__(detail)
        self.reason = reason
        self.detail = detail


def _require_active(vm: Vm) -> None:
    """A power op is only meaningful on a live lease.

    Refusing here rather than at dispatch keeps a migrating VM's fence and
    a decommissioning VM's teardown from racing an operator click.
    """
    if vm.state != VmState.ACTIVE:
        raise PowerOpRefused(
            "vm-not-active",
            f"vm {vm.vm_id!r} is {vm.state} — power operations apply only to "
            "an active VM (a migrating or decommissioning VM is mid-flight, "
            "and a destroyed one no longer has an overlay to power on)",
        )


def stop_vm(vm: Vm, *, by_migration: bool = False, by_guest_upgrade: str = "") -> Vm:
    """Graceful ACPI stop. The VM keeps its reservation.

    Reuses the SAME signed `stop` order §24 issues to collect the guest's
    EOL ack — the miner-side operation is identical, only the intent
    differs: here nothing is torn down afterwards.

    ⚠️ The dispatch happens OUTSIDE a transaction, on purpose. The
    `stopping` marker has to survive a dispatch failure: the order may well
    have reached the miner and taken effect, so reverting to `running`
    would assert a state we have no evidence for. Wrapping the whole
    function in `atomic` does exactly that — the rollback silently undoes
    the marker, and the VM reads as running while its guest is gone.
    """
    from apps.orchestration import effects

    vm = _claim(
        vm, VmPowerState.STOPPING, by_migration=by_migration, by_guest_upgrade=by_guest_upgrade
    )
    try:
        # A fresh order_id per stop: stop → start → stop within one
        # generation must stop the guest again, not replay the first stop's
        # recorded outcome. The deadline keeps the whole exchange (re-asks
        # of THIS id included) inside the request's worker timeout.
        effects.dispatch_graceful_stop(
            vm,
            order_id=f"pwr-stop-{vm.vm_id}-{uuid.uuid4().hex[:12]}",
            deadline_s=POWER_STOP_DEADLINE_S,
        )
    except Exception:
        log.exception(
            "power: vm=%s graceful stop dispatch failed — left STOPPING, the order may have landed",
            vm.vm_id,
        )
        raise
    _set_power(vm, VmPowerState.STOPPED, ordered=True)
    log.info("power: vm=%s stopped (reservation held)", vm.vm_id)
    return vm


#: An in-flight marker (`stopping`/`starting`) older than this was left by a
#: request that died before settling it — a killed worker, or a stop the
#: miner refused mid-relaunch. It no longer blocks the tenant: without this
#: the VM is locked forever (`start` refuses `already-starting`, `stop`
#: refuses `start-in-flight`, and nothing else writes `power_state`).
STALE_POWER_MARKER = timedelta(minutes=10)


def _require_no_migration(vm: Vm, *, by_guest_upgrade: str = "") -> None:
    """A §25 job owns the VM's power state from its start until it ends:
    before the fence the VM is still `Active`, so `_require_active` alone
    would let a click stop the guest the job is about to quiesce (no
    stopped-ack ⇒ the job times out and the VM is stranded `Migrating`), or
    start one a cold migration is starting itself. Only the job's own power
    ops (`by_migration=True`) pass. A resize owns the power state the same
    way, and passes the same flag for its own stop/relaunch."""
    from apps.orchestration.models import (
        TERMINAL_MIGRATION_STATES,
        TERMINAL_RESIZE_STATES,
        MigrationJob,
        ResizeJob,
    )

    if MigrationJob.objects.filter(vm=vm).exclude(state__in=TERMINAL_MIGRATION_STATES).exists():
        raise PowerOpRefused(
            "migration-in-flight",
            f"vm {vm.vm_id!r} is being migrated — power operations resume once the migration ends",
        )
    # A resize stops and relaunches the VM itself; a click in between would
    # boot it at the old size, or stop the relaunch it is waiting on.
    if ResizeJob.objects.filter(vm=vm).exclude(state__in=TERMINAL_RESIZE_STATES).exists():
        raise PowerOpRefused(
            "resize-in-flight",
            f"vm {vm.vm_id!r} is being resized — power operations resume once the resize ends",
        )
    # A guest upgrade holding the VM stops and relaunches it itself. Only
    # ITS OWN power ops pass (`by_guest_upgrade` = its job_id) — not a
    # generic bypass.
    from apps.orchestration.models import HOLDING_GUEST_UPGRADE_STATES, GuestUpgradeJob

    holder = (
        GuestUpgradeJob.objects.filter(vm=vm, state__in=HOLDING_GUEST_UPGRADE_STATES)
        .values_list("job_id", flat=True)
        .first()
    )
    if holder is not None and holder != by_guest_upgrade:
        raise PowerOpRefused(
            "guest-upgrade-in-flight",
            f"vm {vm.vm_id!r} is being moved onto new guest components — power "
            "operations resume once the upgrade ends",
        )
    if by_guest_upgrade and holder != by_guest_upgrade:
        raise PowerOpRefused(
            "guest-upgrade-not-holding",
            f"guest upgrade {by_guest_upgrade!r} does not hold vm {vm.vm_id!r}",
        )


def _recovery_relaunch_in_flight(vm: Vm) -> bool:
    """Reboot-recovery has marked a relaunch of `vm` in flight (and not
    abandoned it: a mark older than `STALE_POWER_MARKER` is a crashed tick's
    leftover and does not block the tenant)."""
    from apps.orchestration.models import RebootRecovery
    from apps.orchestration.service import RELAUNCH_IN_FLIGHT

    row = RebootRecovery.objects.filter(vm=vm).values("last_outcome", "last_relaunch_at").first()
    return bool(
        row
        and row["last_outcome"] == RELAUNCH_IN_FLIGHT
        and row["last_relaunch_at"] is not None
        and timezone.now() - row["last_relaunch_at"] < STALE_POWER_MARKER
    )


def _live_marker(vm: Vm, marker: str) -> bool:
    """`vm` holds the in-flight `marker` and it is still live. A marker
    with no timestamp is treated as live — refusing is the fail-safe side;
    `_set_power` always stamps the time."""
    if vm.power_state != marker:
        return False
    if vm.power_state_at is None or timezone.now() - vm.power_state_at < STALE_POWER_MARKER:
        return True
    log.warning(
        "power: vm=%s %s marker is %s old — treating it as abandoned",
        vm.vm_id,
        marker,
        timezone.now() - vm.power_state_at,
    )
    return False


@transaction.atomic
def _claim(
    vm: Vm, in_flight: str, *, by_migration: bool = False, by_guest_upgrade: str = ""
) -> Vm:
    """Re-read under a row lock, check the guards, and commit the in-flight
    marker — a SHORT transaction that ends before anything is dispatched.

    Two concurrent stops cannot both pass: the loser sees the marker the
    winner committed.
    """
    vm = Vm.objects.select_for_update().get(pk=vm.pk)
    _require_active(vm)
    if not by_migration:
        _require_no_migration(vm, by_guest_upgrade=by_guest_upgrade)
    if in_flight == VmPowerState.STOPPING and _recovery_relaunch_in_flight(vm):
        # Holding the Vm row lock the relaunch claim also takes: while
        # reboot-recovery is dispatching a relaunch, a stop would find no
        # domain yet, record `stopped`, and the relaunch would boot the
        # guest anyway. Retryable — the dispatch takes seconds.
        raise PowerOpRefused(
            "recovery-relaunch-in-flight",
            f"vm {vm.vm_id!r} is being relaunched by reboot-recovery — "
            "retry the stop in a few seconds",
        )
    if in_flight == VmPowerState.STOPPING:
        if vm.power_state == VmPowerState.STOPPED or _live_marker(vm, VmPowerState.STOPPING):
            raise PowerOpRefused(
                "already-stopping",
                f"vm {vm.vm_id!r} is already {vm.power_state}",
            )
        if _live_marker(vm, VmPowerState.STARTING):
            raise PowerOpRefused(
                "start-in-flight",
                f"vm {vm.vm_id!r} is starting — wait for it to reach running "
                "before stopping it, or the stop races the relaunch",
            )
    else:
        if vm.power_state == VmPowerState.RUNNING:
            raise PowerOpRefused("already-running", f"vm {vm.vm_id!r} is running")
        if _live_marker(vm, VmPowerState.STARTING):
            raise PowerOpRefused("already-starting", f"vm {vm.vm_id!r} is starting")
        if not vm.host:
            raise PowerOpRefused(
                "no-bound-miner",
                f"vm {vm.vm_id!r} has no bound miner — its overlay lives on "
                "one specific host and there is no record of which",
            )
    _set_power(vm, in_flight)
    return vm


def _require_down_over_abandoned_start(vm: Vm) -> None:
    """A start over an ABANDONED `starting` marker: the start it marks may
    have landed (a worker killed past the dispatch, a rejected answer held
    by `start_vm(claimed=True)`) — only on the miner's definite DOWN, never
    a second guest over it. A live marker is `_claim`'s to refuse."""
    from apps.orchestration import effects

    current = Vm.objects.get(pk=vm.pk)
    if current.power_state != VmPowerState.STARTING or _live_marker(
        current, VmPowerState.STARTING
    ):
        return
    running = effects.poll_domain_running(current)
    if running is None:
        raise PowerOpRefused(
            "domain-state-unknown",
            f"an earlier start of {vm.vm_id!r} may have landed and its miner does not "
            "answer whether the domain runs — retry once it does",
        )
    if running:
        raise PowerOpRefused(
            "already-running",
            f"an earlier start of {vm.vm_id!r} landed — its miner reports the domain up",
        )


def claim_start(vm: Vm) -> Vm:
    """Commit the `starting` marker of a start the caller dispatches next
    with `start_vm(..., claimed=True)`. Called inside the caller's
    transaction, so what it decided under the VM row lock (a launch record
    swap, an audit row) and the claim commit together: no other start can
    take the VM in between. Raises `PowerOpRefused` like `start_vm`."""
    return _claim(vm, VmPowerState.STARTING)


def start_vm(
    vm: Vm,
    *,
    by_migration: bool = False,
    by_guest_upgrade: str = "",
    flavor: str | None = None,
    supersede: bool = False,
    launch_ref: str = "",
    claimed: bool = False,
) -> Vm:
    """Relaunch a stopped VM on its OWN miner, reusing its overlay + KEK.

    Like `stop_vm`, the relaunch dispatches outside a transaction so the
    `starting` marker survives a failure.

    `flavor` boots it at another size than its launch record's (a resize's
    relaunch); `None` is the recorded size. `supersede` makes the KBS refuse
    every earlier launch from this relaunch's register on
    (`launch.launch_on_miner`) — only for a caller that knows no earlier
    attempt can still come up (a resize's relaunch until one registered).
    A plain start of a VM resized while stopped supersedes on its own
    (`resize.next_start_supersedes`). `launch_ref` tags the relaunch's
    measurement-ledger row (a guest upgrade's attempt id). `claimed`: the
    caller committed the `starting` marker itself (`claim_start`) and
    settles a relaunch answered as rejected: the marker is LEFT `starting`
    (the order may still land — no other start may claim the VM over it)
    until it goes stale and the reboot-recovery scan settles it to what the
    miner runs.
    """
    from apps.orchestration.service import (
        RelaunchDisksMissing,
        RelaunchPinBusy,
        _reboot_recovery_relaunch,
        mark_power_start_disks_missing,
    )

    if not supersede and flavor is None:
        from apps.orchestration import resize

        supersede = resize.next_start_supersedes(vm)
    if claimed:
        vm = Vm.objects.get(pk=vm.pk)
        if vm.power_state != VmPowerState.STARTING:
            raise PowerOpRefused(
                "not-claimed", f"vm {vm.vm_id!r} is {vm.power_state}, not claimed for a start"
            )
    else:
        _require_down_over_abandoned_start(vm)
        vm = _claim(
            vm,
            VmPowerState.STARTING,
            by_migration=by_migration,
            by_guest_upgrade=by_guest_upgrade,
        )
    try:
        if launch_ref:
            accepted = _reboot_recovery_relaunch(
                vm, vm.host, flavor=flavor, supersede=supersede, launch_ref=launch_ref
            )
        else:
            accepted = (
                _reboot_recovery_relaunch(vm, vm.host, flavor=flavor, supersede=supersede)
                if flavor or supersede
                else _reboot_recovery_relaunch(vm, vm.host)
            )
    except RelaunchPinBusy as exc:
        _set_power(vm, VmPowerState.STOPPED)
        raise PowerOpRefused(
            PIN_BUSY_REASON,
            f"other VM starts are pinning their measurements — {vm.vm_id!r} was "
            "not started (nothing changed); retry the start in a few seconds",
        ) from exc
    except RelaunchDisksMissing as exc:
        _set_power(vm, VmPowerState.STOPPED)
        # Same latch + ERROR as the reboot-recovery scan, so the per-tick
        # sweep surfaces a refused start too.
        mark_power_start_disks_missing(vm, vm.host)
        raise PowerOpRefused(
            DISKS_MISSING_REASON,
            f"the miner recorded as hosting {vm.vm_id!r} does not hold its "
            "disks — the VM stays stopped; an operator must locate its data",
        ) from exc
    if not accepted:
        if claimed:
            raise PowerOpRefused(
                "relaunch-rejected",
                f"the miner hosting {vm.vm_id!r} did not accept the relaunch — the VM is "
                "held starting until the dispatch settled (it may still land)",
            )
        _set_power(vm, VmPowerState.STOPPED)
        raise PowerOpRefused(
            "relaunch-rejected",
            f"the miner hosting {vm.vm_id!r} did not accept the relaunch — "
            "the VM stays stopped and its overlay is untouched",
        )
    _set_power(vm, VmPowerState.RUNNING)
    log.info("power: vm=%s started on host=%s", vm.vm_id, vm.host)
    return vm


def settle_observed_running(vm: Vm) -> bool:
    """Record `running` for a VM the books say is `stopped` but whose miner
    reports the domain up — a relaunch answered as refused (an Edge
    timeout) that had in fact landed. Left `stopped`, a later `start` would
    boot the same disks a second time. Returns `True` iff it was recorded
    (a CAS on the `stopped` read, so a concurrent power op wins)."""
    now = timezone.now()
    fields = {
        "power_state": VmPowerState.RUNNING,
        "power_state_at": now,
        "power_stop_ordered_at": None,
        "power_stop_proof": None,
    }
    if not (
        Vm.objects.filter(pk=vm.pk, power_state=VmPowerState.STOPPED)
        .exclude(state=VmState.DESTROYED)
        .update(**fields)
    ):
        return False
    for name, value in fields.items():
        setattr(vm, name, value)
    log.warning("power: vm=%s recorded running — its miner reports the domain up", vm.vm_id)
    return True


def reboot_vm(vm: Vm) -> Vm:
    """Graceful stop followed by a relaunch on the same miner.

    NOT `transaction.atomic` as a whole: the stop must be committed before
    the relaunch dispatches, or the miner would be asked to start a domain
    it has not been told to stop yet.

    A guest can also reboot itself (`reboot` inside the VM) — the domain
    survives and the miner-agent re-pushes the ticket on `event=Started`.
    This exists for the case where the guest is not cooperating.
    """
    stop_vm(vm)
    vm.refresh_from_db()
    return start_vm(vm)


def _set_power(vm: Vm, state: str, *, ordered: bool = False) -> None:
    """`ordered`: this `stopped` is a completed stop order's (only
    `stop_vm` passes it) — see `Vm.power_stop_ordered_at`."""
    now = timezone.now()
    fields: dict = {
        "power_state": state,
        "power_state_at": now,
        "power_stop_ordered_at": now if ordered and state == VmPowerState.STOPPED else None,
    }
    if state != VmPowerState.STOPPED:
        # A new stop proves itself afresh; a start leaves nothing proven.
        fields["power_stop_proof"] = None
    # A tombstone's `off` is terminal: a stop/start whose dispatch outlived
    # a §24 destroy must not write `stopped`/`running` over it.
    if not Vm.objects.filter(pk=vm.pk).exclude(state=VmState.DESTROYED).update(**fields):
        # The instance is left as the caller read it (its host still names
        # the miner the outcome came from).
        log.warning("power: vm=%s was destroyed meanwhile — %s not recorded", vm.vm_id, state)
        return
    for name, value in fields.items():
        setattr(vm, name, value)
