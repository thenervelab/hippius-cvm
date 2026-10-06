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
from apps.orchestration import effects
from apps.orchestration.services import power

pytestmark = pytest.mark.django_db

# Captured before any autouse fixture can shadow the effect with a fake.
_REAL_GRACEFUL_STOP = effects.dispatch_graceful_stop


def _vm(**kw) -> Vm:
    defaults = dict(
        vm_id="pw-1",
        lease_id="lease-1",
        state=VmState.ACTIVE,
        generation=1,
        host="miner-a",
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
            {"migration_dest": "miner-b", "new_generation": 2}
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
    def test_starts_a_migrated_vm(self, monkeypatch) -> None:
        """A VM §25 moved relaunches like any other — at its current
        generation (`_reboot_recovery_relaunch` mints there)."""
        relaunched: list[str] = []
        monkeypatch.setattr(
            "apps.orchestration.service._reboot_recovery_relaunch",
            lambda vm, host: relaunched.append(vm.vm_id) or True,
        )
        vm = _vm(vm_id="pw-migrated", generation=2, power_state=VmPowerState.STOPPED)
        out = power.start_vm(vm)
        assert out.power_state == VmPowerState.RUNNING
        assert relaunched == ["pw-migrated"]

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
            "apps.orchestration.effects.dispatch_graceful_stop",
            lambda vm, **_kw: sent.append(vm),
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

        def boom(_vm, **_kw):
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
        vm = _vm(vm_id="pw-start", host="miner-g", power_state=VmPowerState.STOPPED)
        out = power.start_vm(vm)

        assert seen["node_id"] == "miner-g"
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


class TestStopOrderIdentity:
    def test_every_power_stop_gets_its_own_order_id_and_a_bounded_budget(
        self, monkeypatch
    ) -> None:
        """The miner dedups on `order_id`: a stop that reused the previous
        one's id (stop → start → stop in one generation) would be answered
        `idempotent-replay` and leave the guest running while vali recorded
        it STOPPED. And the whole exchange must fit the request's worker
        timeout."""
        seen: list[dict] = []
        monkeypatch.setattr(
            "apps.orchestration.effects.dispatch_graceful_stop",
            lambda vm, **kw: seen.append(kw),
        )
        vm = _vm(vm_id="pw-twice")
        power.stop_vm(vm)
        vm.refresh_from_db()
        vm.power_state = VmPowerState.RUNNING
        vm.save(update_fields=["power_state"])
        power.stop_vm(vm)

        ids = [kw["order_id"] for kw in seen]
        assert len(ids) == 2 and len(set(ids)) == 2, ids
        assert all(i.startswith("pwr-stop-pw-twice-") for i in ids)
        assert not any(i.startswith("dec-eol-stop-") for i in ids), (
            "the §24 per-generation id would be replayed by the miner"
        )
        assert all(kw["deadline_s"] == power.POWER_STOP_DEADLINE_S for kw in seen)
        assert power.POWER_STOP_DEADLINE_S < 60, "gunicorn --timeout 60"

    def test_a_stop_whose_502_hid_a_success_ends_stopped(self, monkeypatch) -> None:
        """End to end through the real effect: the Edge 502s (its forward
        timed out), the re-ask reads the miner's recorded success, and the
        VM ends STOPPED — not an API error with the VM left STOPPING."""
        from apps.miners.models import MinerIdentity
        from apps.orchestration import order_dispatch

        MinerIdentity.objects.create(
            miner_id="node-1",
            pubkey_hex="ab" * 32,
            platform_id="plat-1",
            netbird_ip="100.64.0.9",
        )
        answers = [
            order_dispatch.DispatchResult(ok=False, status=502, classifier=""),
            order_dispatch.DispatchResult(ok=True, status=200, classifier="idempotent-replay"),
        ]
        calls: list[dict] = []

        def _dispatch(**kw):
            calls.append(kw)
            return answers.pop(0)

        monkeypatch.setattr(
            "apps.orchestration.effects.dispatch_graceful_stop", _REAL_GRACEFUL_STOP
        )
        monkeypatch.setattr(order_dispatch, "dispatch_order", _dispatch)
        monkeypatch.setattr(order_dispatch.time, "sleep", lambda _s: None)
        vm = _vm(vm_id="pw-502", host="node-1")
        out = power.stop_vm(vm)
        assert out.power_state == VmPowerState.STOPPED
        assert len(calls) == 2 and calls[0]["order_id"] == calls[1]["order_id"]
        # The per-stop id reached the miner — not the §24 per-generation one.
        assert calls[0]["order_id"].startswith("pwr-stop-pw-502-")


class TestAbandonedMarkers:
    """An in-flight marker left by a request that died (worker killed, a stop
    the miner refused mid-relaunch) must not lock the VM forever — nothing
    but this module writes `power_state`, and reboot-recovery acts only on
    `running` VMs."""

    @staticmethod
    def _aged(vm_id: str, marker: str, minutes: int) -> Vm:
        from datetime import timedelta

        from django.utils import timezone

        return _vm(
            vm_id=vm_id,
            power_state=marker,
            power_state_at=timezone.now() - timedelta(minutes=minutes),
        )

    def test_a_live_start_still_refuses_stop_and_start(self) -> None:
        vm = self._aged("pw-live-start", VmPowerState.STARTING, 1)
        with pytest.raises(power.PowerOpRefused) as exc:
            power.stop_vm(vm)
        assert exc.value.reason == "start-in-flight"
        with pytest.raises(power.PowerOpRefused) as exc:
            power.start_vm(vm)
        assert exc.value.reason == "already-starting"

    def test_an_abandoned_start_can_be_stopped(self, monkeypatch) -> None:
        monkeypatch.setattr(
            "apps.orchestration.effects.dispatch_graceful_stop", lambda vm, **_kw: None
        )
        vm = self._aged("pw-dead-start", VmPowerState.STARTING, 11)
        assert power.stop_vm(vm).power_state == VmPowerState.STOPPED

    def test_an_abandoned_start_can_be_started_again(self, monkeypatch) -> None:
        from apps.orchestration import effects, service

        monkeypatch.setattr(service, "_reboot_recovery_relaunch", lambda vm, host: True)
        monkeypatch.setattr(effects, "poll_domain_running", lambda vm: False)
        vm = self._aged("pw-dead-start-2", VmPowerState.STARTING, 11)
        assert power.start_vm(vm).power_state == VmPowerState.RUNNING

    @pytest.mark.parametrize(
        ("running", "reason"), [(True, "already-running"), (None, "domain-state-unknown")]
    )
    def test_an_abandoned_start_is_restarted_only_over_a_domain_down(
        self, monkeypatch, running: bool | None, reason: str
    ) -> None:
        """The abandoned start may have landed: no second guest over it."""
        from apps.orchestration import effects, service

        relaunched: list[str] = []
        monkeypatch.setattr(
            service, "_reboot_recovery_relaunch", lambda vm, host: relaunched.append(vm.vm_id)
        )
        monkeypatch.setattr(effects, "poll_domain_running", lambda vm: running)
        vm = self._aged("pw-dead-start-3", VmPowerState.STARTING, 11)
        with pytest.raises(power.PowerOpRefused) as exc:
            power.start_vm(vm)
        assert exc.value.reason == reason
        assert relaunched == []

    def test_a_live_stop_refuses_a_second_stop(self) -> None:
        vm = self._aged("pw-live-stop", VmPowerState.STOPPING, 1)
        with pytest.raises(power.PowerOpRefused) as exc:
            power.stop_vm(vm)
        assert exc.value.reason == "already-stopping"

    def test_an_abandoned_stop_can_be_retried(self, monkeypatch) -> None:
        """A stop the miner refused (`CvmBusy` while a relaunch was in
        flight) leaves `stopping`; the tenant must be able to stop again."""
        monkeypatch.setattr(
            "apps.orchestration.effects.dispatch_graceful_stop", lambda vm, **_kw: None
        )
        vm = self._aged("pw-dead-stop", VmPowerState.STOPPING, 11)
        assert power.stop_vm(vm).power_state == VmPowerState.STOPPED

    def test_a_marker_without_a_timestamp_is_treated_as_live(self) -> None:
        vm = _vm(vm_id="pw-no-ts", power_state=VmPowerState.STARTING)
        with pytest.raises(power.PowerOpRefused):
            power.stop_vm(vm)


def test_a_power_stop_failure_is_labelled_as_a_power_stop(monkeypatch) -> None:
    """The power API shares the §24 effect; its errors must not read as a
    decommission in the logs."""
    from apps.miners.models import MinerIdentity
    from apps.orchestration import order_dispatch

    MinerIdentity.objects.create(
        miner_id="node-1", pubkey_hex="ab" * 32, platform_id="p", netbird_ip="100.64.0.9"
    )
    monkeypatch.setattr(
        "apps.orchestration.effects.dispatch_graceful_stop", _REAL_GRACEFUL_STOP
    )
    monkeypatch.setattr(
        order_dispatch,
        "dispatch_order",
        lambda **kw: order_dispatch.DispatchResult(ok=False, status=400, classifier="x"),
    )
    vm = _vm(vm_id="pw-label", host="node-1")
    with pytest.raises(Exception) as exc:
        power.stop_vm(vm)
    assert str(exc.value).startswith("power-stop:")



class TestPowerStopProof:
    """`Vm.power_stop_proof` (#1162) describes the LAST stop only."""

    def test_a_stop_keeps_the_proof_its_guest_recorded_on_the_way_down(
        self, monkeypatch
    ) -> None:
        def guest_acks(vm, **_kw):
            # What the ingest does while the VM is `stopping`.
            Vm.objects.filter(pk=vm.pk).update(power_stop_proof=b"n" * 32)
            return "stopped"

        monkeypatch.setattr("apps.orchestration.effects.dispatch_graceful_stop", guest_acks)
        vm = power.stop_vm(_vm(vm_id="pw-proof"))
        vm.refresh_from_db()
        assert vm.power_state == VmPowerState.STOPPED
        assert bytes(vm.power_stop_proof) == b"n" * 32

    def test_a_new_stop_does_not_inherit_the_previous_proof(self, monkeypatch) -> None:
        monkeypatch.setattr(
            "apps.orchestration.effects.dispatch_graceful_stop", lambda vm, **_kw: "stopped"
        )
        vm = _vm(vm_id="pw-stale", power_stop_proof=b"o" * 32)
        power.stop_vm(vm)
        vm.refresh_from_db()
        assert vm.power_state == VmPowerState.STOPPED
        assert vm.power_stop_proof is None

    @pytest.mark.parametrize(
        "state", [VmPowerState.STARTING, VmPowerState.RUNNING, VmPowerState.STOPPING]
    )
    def test_leaving_stopped_drops_the_proof(self, state) -> None:
        vm = _vm(
            vm_id=f"pw-leave-{state}",
            power_state=VmPowerState.STOPPED,
            power_stop_proof=b"o" * 32,
        )
        power._set_power(vm, state)
        vm.refresh_from_db()
        assert vm.power_stop_proof is None


def test_a_power_outcome_never_overwrites_a_tombstone() -> None:
    """A stop/start dispatched before a §24 destroy completes after it:
    the terminal `off` stays."""
    vm = _vm(vm_id="pw-tomb", power_state=VmPowerState.STOPPING)
    Vm.objects.filter(pk=vm.pk).update(state=VmState.DESTROYED, host="", power_state="off")
    power._set_power(vm, VmPowerState.STOPPED)
    row = Vm.objects.get(pk=vm.pk)
    assert row.power_state == VmPowerState.OFF
