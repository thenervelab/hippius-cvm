"""A launch that finds every miner busy booting WAITS for a boot slot.

Gate (g) (`scheduler.placement`, concurrent boots per miner) is transient by
nature: a boot slot frees up as soon as one guest comes up. The launch path
re-asks the scheduler without spending a miner attempt until
`VALI_SCHEDULER_BOOT_WAIT_S` runs out, and only then fails — under its own
outcome, never `no-eligible-miner`.
"""

from __future__ import annotations

import pytest
from django.test import override_settings

from apps.identity.models import PrincipalScope, ServiceClient
from apps.orchestration.services import launch
from apps.orchestration.tests.test_launch_service import _outcome, _register_miner, _spec
from apps.scheduler import chain, service
from apps.scheduler.tests.factories import make_miner, make_snapshot, node_id

pytestmark = pytest.mark.django_db


class _Clock:
    """`time.monotonic` + `time.sleep` for the launch module: sleeping
    advances the clock instead of the test."""

    def __init__(self) -> None:
        self.now = 1000.0
        self.slept: list[float] = []

    def monotonic(self) -> float:
        return self.now

    def sleep(self, s: float) -> None:
        self.slept.append(s)
        self.now += s


@pytest.fixture()
def clock(monkeypatch: pytest.MonkeyPatch) -> _Clock:
    c = _Clock()
    monkeypatch.setattr(launch.time, "monotonic", c.monotonic)
    monkeypatch.setattr(launch.time, "sleep", c.sleep)
    return c


def _actor() -> ServiceClient:
    return ServiceClient.objects.create(scope=PrincipalScope.OPERATOR.value, name="launcher")


@override_settings(VALI_SCHEDULER_BOOT_WAIT_S=120, VALI_SCHEDULER_BOOT_WAIT_POLL_S=15)
def test_the_launch_waits_for_a_boot_slot_then_lands(
    monkeypatch: pytest.MonkeyPatch, clock: _Clock
) -> None:
    _register_miner(1)
    monkeypatch.setattr(chain, "read_miner_status", lambda: make_snapshot(10, [make_miner(1)]))
    # Busy for the first three asks, then one guest comes up.
    asks: list[int] = []

    def booting() -> dict[str, int]:
        asks.append(1)
        return {node_id(1): 3} if len(asks) <= 3 else {node_id(1): 2}

    monkeypatch.setattr(service, "booting_by_node", booting)
    monkeypatch.setattr(
        launch, "launch_on_miner", lambda spec, miner: _outcome(launch.ACCEPTED, miner.miner_id)
    )

    result = launch.launch_vm(_spec(), _actor(), max_attempts=1)

    assert result.ok is True, result.emit
    assert result.miner_id == "miner-a"
    # The waits spent no miner attempt (max_attempts=1 still placed).
    assert clock.slept == [15, 15, 15]


@override_settings(VALI_SCHEDULER_BOOT_WAIT_S=40, VALI_SCHEDULER_BOOT_WAIT_POLL_S=15)
def test_a_fleet_that_stays_busy_fails_as_miners_booting(
    monkeypatch: pytest.MonkeyPatch, clock: _Clock
) -> None:
    _register_miner(1)
    monkeypatch.setattr(chain, "read_miner_status", lambda: make_snapshot(10, [make_miner(1)]))
    monkeypatch.setattr(service, "booting_by_node", lambda: {node_id(1): 3})
    monkeypatch.setattr(
        launch, "launch_on_miner", lambda spec, miner: pytest.fail("must not dispatch")
    )

    result = launch.launch_vm(_spec(), _actor())

    assert result.ok is False
    assert result.outcome == "miners-booting"
    assert clock.slept == [15, 15, 10]  # bounded by the wait, not the poll


@override_settings(VALI_SCHEDULER_MAX_BOOTING_PER_MINER=0)
def test_cap_zero_never_counts_or_waits(monkeypatch: pytest.MonkeyPatch, clock: _Clock) -> None:
    _register_miner(1)
    monkeypatch.setattr(chain, "read_miner_status", lambda: make_snapshot(10, [make_miner(1)]))
    monkeypatch.setattr(
        service, "booting_by_node", lambda: pytest.fail("the gate is off: nothing to count")
    )
    monkeypatch.setattr(
        launch, "launch_on_miner", lambda spec, miner: _outcome(launch.ACCEPTED, miner.miner_id)
    )

    assert launch.launch_vm(_spec(), _actor()).ok is True
    assert clock.slept == []


@override_settings(VALI_SCHEDULER_BOOT_WAIT_S=120, VALI_SCHEDULER_BOOT_WAIT_POLL_S=15)
def test_queue_time_is_spent_from_the_wait(monkeypatch: pytest.MonkeyPatch, clock: _Clock) -> None:
    """A job that already sat 100 s in the queue (behind others waiting for
    a slot) waits only the 20 s left: queue + wait stays inside the bound,
    so nothing launches after its caller's own timeout gave up on it."""
    _register_miner(1)
    monkeypatch.setattr(chain, "read_miner_status", lambda: make_snapshot(10, [make_miner(1)]))
    monkeypatch.setattr(service, "booting_by_node", lambda: {node_id(1): 3})

    actor = _actor()
    result = launch.launch_vm(_spec(), actor, queued_for_s=100)

    assert result.outcome == "miners-booting"
    assert clock.slept == [15, 5]

    clock.slept.clear()
    assert launch.launch_vm(_spec(vm_id="vm-2"), actor, queued_for_s=500).ok is False
    assert clock.slept == []  # past the bound already: fail at once
