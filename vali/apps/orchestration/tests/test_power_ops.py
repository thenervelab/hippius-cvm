"""Power operations — the refusals matter more than the happy paths.

A stop/start that works is easy to get right and easy to see. What is worth
pinning is everything the operation must REFUSE, because each refusal
stands in for a way to lose or wedge a tenant's VM:

- powering a migrating or decommissioning VM races a fence or a teardown;
- starting a migrated VM produces a guest the KBS will never unlock;
- starting one with no bound miner has nowhere to find its overlay;
- a double stop dispatches the same order twice.

And one invariant that is not a refusal at all: a stopped VM stays
`active`, because `state` is the KBS release gate and the VM must be able
to unlock again when it starts.
"""

from __future__ import annotations

import pytest

from apps.lifecycle.models import Vm, VmPowerState, VmState
from apps.orchestration.services import power

pytestmark = pytest.mark.django_db


def _vm(**kw) -> Vm:
    defaults = dict(
        vm_id="pw-1",
        lease_id="lease-1",
        state=VmState.ACTIVE,
        generation=1,
        host="miner-1",
        power_state=VmPowerState.RUNNING,
    )
    defaults.update(kw)
    return Vm.objects.create(**defaults)


class TestStopRefusals:
    @pytest.mark.parametrize(
        "state", [VmState.MIGRATING, VmState.DECOMMISSIONING, VmState.DESTROYED]
    )
    def test_refuses_a_vm_that_is_not_active(self, state) -> None:
        # A migrating row must name its destination (DB CHECK constraint
        # `lifecycle_vm_migrating_requires_dest`) — the fence needs it.
        extra = (
            {"migration_dest": "miner-2", "new_generation": 2}
            if state == VmState.MIGRATING
            else {}
        )
        vm = _vm(vm_id=f"pw-{state}", state=state, **extra)
        with pytest.raises(power.PowerOpRefused) as exc:
            power.stop_vm(vm)
        assert exc.value.reason == "vm-not-active"

    def test_refuses_a_second_stop(self, monkeypatch) -> None:
        """Two clicks must not dispatch two orders."""
        vm = _vm(vm_id="pw-double", power_state=VmPowerState.STOPPED)
        with pytest.raises(power.PowerOpRefused) as exc:
            power.stop_vm(vm)
        assert exc.value.reason == "already-stopping"

    def test_refuses_a_stop_while_a_start_is_in_flight(self) -> None:
        vm = _vm(vm_id="pw-race", power_state=VmPowerState.STARTING)
        with pytest.raises(power.PowerOpRefused) as exc:
            power.stop_vm(vm)
        assert exc.value.reason == "start-in-flight"


class TestStartRefusals:
    def test_refuses_a_migrated_vm(self) -> None:
        """`generation > 1` — a relaunch bakes generation 1, which the KBS
        anti-rollback fence declines, so the guest could never unlock.
        Refusing up front beats a burned launch and a wedged domain."""
        vm = _vm(vm_id="pw-migrated", generation=2, power_state=VmPowerState.STOPPED)
        with pytest.raises(power.PowerOpRefused) as exc:
            power.start_vm(vm)
        assert exc.value.reason == "migrated-vm-cannot-restart"

    def test_refuses_when_no_miner_is_bound(self) -> None:
        vm = _vm(vm_id="pw-nohost", host="", power_state=VmPowerState.STOPPED)
        with pytest.raises(power.PowerOpRefused) as exc:
            power.start_vm(vm)
        assert exc.value.reason == "no-bound-miner"

    def test_refuses_starting_a_running_vm(self) -> None:
        vm = _vm(vm_id="pw-running")
        with pytest.raises(power.PowerOpRefused) as exc:
            power.start_vm(vm)
        assert exc.value.reason == "already-running"


class TestStopSucceeds:
    def test_stop_keeps_the_vm_active_and_records_when(self, monkeypatch) -> None:
        """THE invariant. `state` is the KBS release gate: a stopped VM that
        lost `active` could never be given its own KEK back."""
        sent = []
        monkeypatch.setattr(
            "apps.orchestration.effects.dispatch_graceful_stop", sent.append
        )
        vm = _vm(vm_id="pw-ok")
        out = power.stop_vm(vm)

        assert out.power_state == VmPowerState.STOPPED
        assert out.state == VmState.ACTIVE, "a stopped VM must stay KBS-releasable"
        assert out.power_state_at is not None, "the billing layer reads this"
        assert [v.vm_id for v in sent] == ["pw-ok"], "exactly one order dispatched"

    def test_a_failed_dispatch_does_not_claim_running(self, monkeypatch) -> None:
        """The order may have reached the miner and taken effect. Reporting
        `running` after a failed dispatch asserts a state we cannot see."""

        def boom(_vm):
            raise RuntimeError("miner unreachable")

        monkeypatch.setattr("apps.orchestration.effects.dispatch_graceful_stop", boom)
        vm = _vm(vm_id="pw-boom")
        with pytest.raises(RuntimeError):
            power.stop_vm(vm)
        vm.refresh_from_db()
        assert vm.power_state != VmPowerState.RUNNING


class TestStartSucceeds:
    def test_start_relaunches_on_the_same_miner(self, monkeypatch) -> None:
        """Never through the scheduler: another miner's disk has no overlay."""
        seen = {}

        def fake_relaunch(vm, node_id):
            seen["node_id"] = node_id
            return True

        monkeypatch.setattr(
            "apps.orchestration.service._reboot_recovery_relaunch", fake_relaunch
        )
        vm = _vm(vm_id="pw-start", host="miner-7", power_state=VmPowerState.STOPPED)
        out = power.start_vm(vm)

        assert seen["node_id"] == "miner-7"
        assert out.power_state == VmPowerState.RUNNING

    def test_a_rejected_relaunch_leaves_the_vm_stopped(self, monkeypatch) -> None:
        monkeypatch.setattr(
            "apps.orchestration.service._reboot_recovery_relaunch",
            lambda vm, node_id: False,
        )
        vm = _vm(vm_id="pw-reject", power_state=VmPowerState.STOPPED)
        with pytest.raises(power.PowerOpRefused) as exc:
            power.start_vm(vm)
        assert exc.value.reason == "relaunch-rejected"
        vm.refresh_from_db()
        assert vm.power_state == VmPowerState.STOPPED
