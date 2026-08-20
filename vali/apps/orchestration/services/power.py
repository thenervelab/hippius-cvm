"""Operator power operations — stop / start / reboot.

WHY THIS IS NOT A LIFECYCLE TRANSITION. `Vm.state` mirrors
`kbs_core::lifecycle::VmState`, which the KBS checks serializably before
every KEK release. A stopped VM must be able to unlock again when it
starts, so it stays `active` there — a `Stopped` lifecycle variant would
make the KBS refuse the guest its own key. Power is a separate axis
(`Vm.power_state`), and this module is the only writer of it.

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

from django.db import transaction
from django.utils import timezone

from apps.lifecycle.models import Vm, VmPowerState, VmState

log = logging.getLogger("apps.orchestration.power")


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


def stop_vm(vm: Vm) -> Vm:
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

    vm = _claim(vm, VmPowerState.STOPPING)
    try:
        effects.dispatch_graceful_stop(vm)
    except Exception:
        log.exception(
            "power: vm=%s graceful stop dispatch failed — left STOPPING, "
            "the order may have landed",
            vm.vm_id,
        )
        raise
    _set_power(vm, VmPowerState.STOPPED)
    log.info("power: vm=%s stopped (reservation held)", vm.vm_id)
    return vm


@transaction.atomic
def _claim(vm: Vm, in_flight: str) -> Vm:
    """Re-read under a row lock, check the guards, and commit the in-flight
    marker — a SHORT transaction that ends before anything is dispatched.

    Two concurrent stops cannot both pass: the loser sees the marker the
    winner committed.
    """
    vm = Vm.objects.select_for_update().get(pk=vm.pk)
    _require_active(vm)
    if in_flight == VmPowerState.STOPPING:
        if vm.power_state in (VmPowerState.STOPPING, VmPowerState.STOPPED):
            raise PowerOpRefused(
                "already-stopping",
                f"vm {vm.vm_id!r} is already {vm.power_state}",
            )
        if vm.power_state == VmPowerState.STARTING:
            raise PowerOpRefused(
                "start-in-flight",
                f"vm {vm.vm_id!r} is starting — wait for it to reach running "
                "before stopping it, or the stop races the relaunch",
            )
    else:
        if vm.power_state == VmPowerState.RUNNING:
            raise PowerOpRefused("already-running", f"vm {vm.vm_id!r} is running")
        if vm.power_state == VmPowerState.STARTING:
            raise PowerOpRefused("already-starting", f"vm {vm.vm_id!r} is starting")
        if not vm.host:
            raise PowerOpRefused(
                "no-bound-miner",
                f"vm {vm.vm_id!r} has no bound miner — its overlay lives on "
                "one specific host and there is no record of which",
            )
        # Refuse UP FRONT what the KBS would refuse anyway. A relaunch bakes
        # `hippius.vm_generation=1`, but a migrated VM's recorded state is
        # `Active{gen>=2}`, so the anti-rollback fence declines the release
        # and the guest boots into a retry loop. Better a clear refusal now
        # than a burned launch and a wedged domain.
        if (vm.generation or 1) > 1:
            raise PowerOpRefused(
                "migrated-vm-cannot-restart",
                f"vm {vm.vm_id!r} is at generation {vm.generation} (it has "
                "been migrated). A relaunch bakes generation 1, which the KBS "
                "anti-rollback fence refuses, so the guest could never "
                "unlock. The overlay is intact — recover it with a "
                "migration, not a start",
            )
    _set_power(vm, in_flight)
    return vm


def start_vm(vm: Vm) -> Vm:
    """Relaunch a stopped VM on its OWN miner, reusing its overlay + KEK.

    Like `stop_vm`, the relaunch dispatches outside a transaction so the
    `starting` marker survives a failure.
    """
    from apps.orchestration.service import _reboot_recovery_relaunch

    vm = _claim(vm, VmPowerState.STARTING)
    accepted = _reboot_recovery_relaunch(vm, vm.host)
    if not accepted:
        _set_power(vm, VmPowerState.STOPPED)
        raise PowerOpRefused(
            "relaunch-rejected",
            f"the miner hosting {vm.vm_id!r} did not accept the relaunch — "
            "the VM stays stopped and its overlay is untouched",
        )
    _set_power(vm, VmPowerState.RUNNING)
    log.info("power: vm=%s started on host=%s", vm.vm_id, vm.host)
    return vm


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


def _set_power(vm: Vm, state: str) -> None:
    vm.power_state = state
    vm.power_state_at = timezone.now()
    vm.save(update_fields=["power_state", "power_state_at"])
