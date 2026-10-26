"""Concurrent launch decisions never spend the same slot twice.

`VALI_LAUNCH_TICK_CONCURRENCY` runs several `launch_vm` at once. Every
admission count the scheduler reads — the boot cap (gate (g)), the host's
capacity slots, the owner sub-budget per miner — is a count at decision
time, and the `Pending` placement the next decision must count is written
right after. `apps.scheduler.decision_lock` makes the two one step.

Each test runs N real `launch_vm` on N threads (N DB connections) against
one fleet. `decide_placement` is wrapped to hold the decision a moment
after it chose (the window a real decision's queries take), and the
miner preflight (`launch_on_miner`) blocks until every thread has
decided, so all N placements are in flight together — the shape of a
burst of runner launches. The lock is a Postgres advisory lock, so this
runs in the CI Postgres lane (`--ds=vali.settings_test_pg`); on SQLite's
per-connection in-memory DB it is skipped.

`test_without_the_lock_the_race_is_real` removes the lock and shows the
same burst overspends: the guarded tests are not passing by accident.
"""

from __future__ import annotations

import contextlib
import threading
import time
from collections import Counter
from collections.abc import Callable, Iterator
from typing import Any

import pytest
from django.db import connection, connections
from django.test import override_settings
from django.utils import timezone

from apps.identity.models import PrincipalScope, ServiceClient
from apps.orchestration.models import LaunchJob, LaunchJobState
from apps.orchestration.services import launch
from apps.orchestration.tests.test_launch_service import _outcome, _register_miner, _spec
from apps.scheduler import chain, decision_lock, placement
from apps.scheduler.models import ACTIVE_PLACEMENT_STATES, MinerCapacity, Placement
from apps.scheduler.tests.factories import make_miner, make_snapshot, node_id

pytestmark = [
    pytest.mark.skipif(
        connection.vendor != "postgresql", reason="advisory lock needs Postgres (CI Postgres lane)"
    ),
    pytest.mark.django_db(transaction=True),
]

#: How long a decision holds after choosing — longer than the queries of
#: any sibling, so an unserialized burst always reads the same counts.
_HOLD_S = 0.3


class _Burst:
    """N `launch_vm` on N threads, all dispatching together."""

    def __init__(self, monkeypatch: pytest.MonkeyPatch, *, seeds: list[int], n: int) -> None:
        self.n = n
        self.decided = 0
        self.decided_lock = threading.Lock()
        self.all_decided = threading.Event()
        self.release = threading.Event()
        self.outcomes: list[str] = []
        self.errors: list[BaseException] = []
        self.after_decide: Callable[[], None] = lambda: time.sleep(_HOLD_S)
        snapshot = make_snapshot(10, [make_miner(s) for s in seeds])
        monkeypatch.setattr(chain, "read_miner_status", lambda: snapshot)
        real_decide = placement.decide_placement

        def decide(**kwargs: Any) -> str:
            try:
                return real_decide(**kwargs)
            finally:
                self.after_decide()
                with self.decided_lock:
                    self.decided += 1
                    if self.decided == self.n:
                        self.all_decided.set()

        monkeypatch.setattr(placement, "decide_placement", decide)

        def preflight(spec: Any, miner: Any, **_kw: Any) -> launch.LaunchOutcome:
            # Hold the placement `Pending` (a dispatch in flight) until the
            # whole burst has decided.
            assert self.release.wait(60)
            return _outcome(launch.ACCEPTED, miner.miner_id)

        monkeypatch.setattr(launch, "launch_on_miner", preflight)

    def run(self, *, owner: str = "u-1") -> None:
        actor = ServiceClient.objects.create(scope=PrincipalScope.OPERATOR.value, name="burst")
        vm_ids = [f"vm-burst-{i}" for i in range(self.n)]
        for vm_id in vm_ids:
            # The worker claimed each: a `running` job is what makes its
            # `Pending` placement count as a boot (`booting_by_node`).
            LaunchJob.objects.create(
                job_id=f"job-{vm_id}",
                vm_id=vm_id,
                tenant_id="t-launch",
                flavor="small",
                spec_json={},
                userdata_vault_path="p",
                userdata_vault_version=1,
                kek_vault_path="k",
                state=LaunchJobState.RUNNING.value,
                phase_started_at=timezone.now(),
                decided_by=actor,
            )

        def one(vm_id: str) -> None:
            try:
                result = launch.launch_vm(
                    _spec(vm_id=vm_id, lease_id=f"lease-{vm_id}", user_id=owner),
                    actor,
                    max_attempts=1,
                )
                self.outcomes.append(result.outcome)
            except BaseException as exc:  # surfaced by the assertions
                self.errors.append(exc)
            finally:
                connections.close_all()

        threads = [threading.Thread(target=one, args=(v,)) for v in vm_ids]
        for t in threads:
            t.start()
        decided = self.all_decided.wait(60)
        self.release.set()
        for t in threads:
            t.join(60)
        assert decided, f"only {self.decided}/{self.n} decisions ran"
        assert not any(t.is_alive() for t in threads)
        assert not self.errors, self.errors

    @staticmethod
    def placed() -> Counter[str]:
        return Counter(
            Placement.objects.filter(status__in=ACTIVE_PLACEMENT_STATES).values_list(
                "miner_node_id", flat=True
            )
        )


def _no_lock(monkeypatch: pytest.MonkeyPatch) -> None:
    @contextlib.contextmanager
    def unlocked() -> Iterator[None]:
        yield

    monkeypatch.setattr(decision_lock, "placement_decision_lock", unlocked)


def _fleet(*seeds: int, slots: int = 50) -> None:
    for s in seeds:
        _register_miner(s)
        MinerCapacity.objects.create(
            miner_node_id=node_id(s),
            status="active",
            capacity_slots=slots,
            observed_epoch=10,
            data_epoch=10,
            refreshed_at=timezone.now(),
        )


@override_settings(VALI_SCHEDULER_MAX_BOOTING_PER_MINER=2, VALI_SCHEDULER_BOOT_WAIT_S=0)
def test_a_burst_never_exceeds_the_boot_cap(monkeypatch: pytest.MonkeyPatch) -> None:
    _fleet(1, 2)
    burst = _Burst(monkeypatch, seeds=[1, 2], n=7)
    burst.run()

    placed = burst.placed()
    assert placed == Counter({node_id(1): 2, node_id(2): 2}), placed
    assert sorted(burst.outcomes) == ["miner-accepted"] * 4 + ["miners-booting"] * 3


@override_settings(VALI_SCHEDULER_MAX_BOOTING_PER_MINER=0)
def test_a_burst_never_exceeds_a_hosts_capacity(monkeypatch: pytest.MonkeyPatch) -> None:
    _fleet(1, slots=3)
    burst = _Burst(monkeypatch, seeds=[1], n=6)
    burst.run()

    assert burst.placed() == Counter({node_id(1): 3})
    assert sorted(burst.outcomes).count("miner-accepted") == 3


@override_settings(
    VALI_SCHEDULER_MAX_BOOTING_PER_MINER=0, VALI_SCHEDULER_MAX_OWNER_PLACEMENTS_PER_MINER=2
)
def test_a_burst_from_one_owner_keeps_its_per_miner_sub_budget(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The sub-budget is soft (a full fleet still places), so the burst is
    sized to fit it exactly: two per miner, never four on the best one."""
    _fleet(1, 2)
    burst = _Burst(monkeypatch, seeds=[1, 2], n=4)
    burst.run()

    assert burst.placed() == Counter({node_id(1): 2, node_id(2): 2})


@override_settings(VALI_SCHEDULER_MAX_BOOTING_PER_MINER=2, VALI_SCHEDULER_BOOT_WAIT_S=0)
def test_without_the_lock_the_race_is_real(monkeypatch: pytest.MonkeyPatch) -> None:
    """The mutation the tests above guard against: no lock, and every
    decision of the burst reads the same empty fleet before any writes."""
    _no_lock(monkeypatch)
    _fleet(1, 2)
    burst = _Burst(monkeypatch, seeds=[1, 2], n=7)
    barrier = threading.Barrier(burst.n)
    burst.after_decide = lambda: barrier.wait(30)
    burst.run()

    assert max(burst.placed().values()) > 2, burst.placed()


def test_the_lock_is_held_until_the_placement_commits() -> None:
    """A second session cannot take the lock while the first holds it, and
    takes it once the first commits."""
    took: list[bool] = []

    with decision_lock.placement_decision_lock():

        def other() -> None:
            try:
                with connection.cursor() as cursor:
                    cursor.execute(
                        "SELECT pg_try_advisory_xact_lock(%s)", [decision_lock._DECISION_LOCK_KEY]
                    )
                    took.append(bool(cursor.fetchone()[0]))
            finally:
                connections.close_all()

        t = threading.Thread(target=other)
        t.start()
        t.join(10)
    assert took == [False]

    t = threading.Thread(target=other)
    t.start()
    t.join(10)
    assert took == [False, True]


def test_a_stuck_holder_fails_the_wait_loudly(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(decision_lock, "DECISION_LOCK_TIMEOUT_S", 0.5)
    held, done = threading.Event(), threading.Event()

    def holder() -> None:
        try:
            with decision_lock.placement_decision_lock():
                held.set()
                assert done.wait(10)
        finally:
            connections.close_all()

    t = threading.Thread(target=holder)
    t.start()
    try:
        assert held.wait(10)
        with pytest.raises(decision_lock.PlacementDecisionBusy):
            with decision_lock.placement_decision_lock():
                pass
    finally:
        done.set()
        t.join(10)
    # The timeout is for the lock wait only: under the lock, the row locks
    # (dedicated disks) wait on the session's own setting.
    with decision_lock.placement_decision_lock():
        with connection.cursor() as cursor:
            cursor.execute("SHOW lock_timeout")
            assert cursor.fetchone()[0] == "0"
