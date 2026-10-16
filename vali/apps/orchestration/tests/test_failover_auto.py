"""The automatic failover worker (`apps.orchestration.failover_auto`)."""

from __future__ import annotations

import time
from datetime import timedelta
from typing import Any

import pytest
from django.conf import settings
from django.utils import timezone

from apps.backup.models import BackupPolicy, FailoverMode
from apps.lifecycle.models import Vm, VmPowerState, VmState
from apps.miners.models import LocationVerdict, MinerIdentity, MinerLocation
from apps.orchestration import effects, failover_auto, restore
from apps.orchestration.effects import EffectError
from apps.orchestration.models import (
    AutoFailover,
    AutoFailoverState,
    FailoverDeadWatch,
    MigrationJob,
    MigrationState,
)
from apps.scheduler import service as sched

from .conftest import FakeEffects
from .factories import make_launch_record, make_vm
from .test_failover import (  # noqa: F401 — autouse fixture
    _REAL_VALIDATE,
    _advance,
    _failover_env,
    _World,
)
from .test_restore import (  # noqa: F401 — autouse fixture
    _chain,
    _golden_vm,
    _Power,
    _restore_env,
)

pytestmark = pytest.mark.django_db

AFTER = 900.0
STEP = 60.0


class _Clock:
    """Ticks the worker at `STEP` intervals up to a point in the scenario,
    as the orchestration tick does (a gap in the checks restarts the proof)."""

    def __init__(self) -> None:
        self.at = 0.0
        self.base = timezone.now()
        self.ticked = False

    def tick(self, until: float | None = None) -> int:
        until = self.at if until is None else until
        started = 0
        if not self.ticked and until > self.at:
            started += self._one()
        while self.at + STEP < until:
            self.at += STEP
            started += self._one()
        self.at = until
        return started + self._one()

    def jump(self, to: float) -> int:
        """One tick at `to`, nothing in between (the worker did not run)."""
        self.at = to
        return self._one()

    def now(self) -> Any:
        return self.base + timedelta(seconds=self.at)

    def _one(self) -> int:
        self.ticked = True
        return failover_auto.tick(now=self.now())


@pytest.fixture
def clock() -> _Clock:
    return _Clock()


@pytest.fixture
def world(monkeypatch: pytest.MonkeyPatch) -> _World:
    return _World(monkeypatch)


@pytest.fixture
def pwr(monkeypatch: pytest.MonkeyPatch) -> _Power:
    return _Power(monkeypatch)


@pytest.fixture(autouse=True)
def _auto_env(monkeypatch: pytest.MonkeyPatch, _restore_env: Any) -> None:  # noqa: F811
    monkeypatch.setattr(settings, "VALI_FAILOVER_AUTO_ENABLED", True)
    monkeypatch.setattr(settings, "VALI_FAILOVER_AUTO_AFTER_S", AFTER)
    monkeypatch.setattr(settings, "VALI_FAILOVER_MANUAL_ENABLED", False)
    monkeypatch.setattr(settings, "VALI_SYNTHETIC_PUSHGATEWAY_URL", "")
    monkeypatch.setattr(failover_auto, "_last_push", 0.0)
    monkeypatch.setattr(failover_auto, "_pushed_undecided", False)
    monkeypatch.setattr(failover_auto, "_skips", {})
    monkeypatch.setattr(failover_auto, "_skips_logged", set())
    # Every VM was sold in FR, where the destinations are.
    monkeypatch.setattr(sched, "launch_region_for_vm", lambda vm_id: "FR")
    monkeypatch.setattr(sched, "region_by_node", lambda **kw: {"d" * 64: "FR", "e" * 64: "FR"})
    # The destination heart-beats far into every scenario.
    MinerIdentity.objects.filter(miner_id="node-dst").update(
        chain_node_id="d" * 64, last_seen_at=timezone.now() + timedelta(days=1)
    )
    # ... and is the source's failover peer: same generation, active on chain,
    # last seen in FR.
    from apps.scheduler.models import MinerCapacity

    MinerCapacity.objects.update_or_create(
        miner_node_id="d" * 64,
        defaults={
            "status": "active",
            "capacity_slots": 4,
            "observed_epoch": 10,
            "data_epoch": 10,
            "refreshed_at": timezone.now(),
        },
    )
    MinerLocation.objects.update_or_create(
        miner_id="node-dst",
        defaults={
            "country_code": "FR",
            "verdict": LocationVerdict.VERIFIED,
            "observed_at": timezone.now(),
        },
    )


def _auto_vm(vm_id: str = "vm-1", *, mode: str = FailoverMode.AUTO) -> Vm:
    if vm_id == "vm-1":
        vm = _golden_vm()
    else:
        vm = make_vm(vm_id, host="node-src")
        make_launch_record(vm, disk_mode="golden_verity_overlay", flavor="small")
        BackupPolicy.objects.create(
            vm=vm, interval_s=3600, observed_boot_counter=3, full_required=False
        )
    BackupPolicy.objects.filter(vm=vm).update(failover_mode=mode)
    _chain(vm)
    return vm


def _jobs() -> list[MigrationJob]:
    return list(MigrationJob.objects.filter(kind="failover").order_by("started_at"))


def _heartbeat(clock: _Clock, at: float) -> None:
    MinerIdentity.objects.filter(miner_id="node-src").update(
        last_seen_at=clock.base + timedelta(seconds=at)
    )


# ── the dead proof ───────────────────────────────────────────────────


def test_a_dead_miner_is_failed_over_only_once_the_proof_held(world, clock) -> None:
    vm = _auto_vm()
    world.kill()
    assert clock.tick() == 0, "dead NOW is not dead for long enough"
    watch = FailoverDeadWatch.objects.get(miner_id="node-src")
    assert clock.tick(AFTER - STEP) == 0 and _jobs() == []
    assert clock.tick(AFTER) == 1
    [job] = _jobs()
    assert (job.vm_id, job.trigger, job.source_node_id, job.dest_node_id) == (
        vm.pk,
        "auto",
        "node-src",
        "node-dst",
    )
    assert job.state == MigrationState.DEST_ACTIVATING.value
    af = AutoFailover.objects.get(job=job)
    assert af.failover_id == job.job_id and af.state == AutoFailoverState.STARTED
    evidence = job.authorization.evidence
    assert evidence["dead_since"] == watch.dead_since.isoformat()
    assert evidence["dead_after_s"] == AFTER and evidence["auto_after_s"] == AFTER
    assert job.decided_by.name == failover_auto.ACTOR


def test_a_partitioned_miner_the_edge_still_reaches_is_never_failed_over(world, clock) -> None:
    _auto_vm()
    world.kill()
    world.edge["node-src"] = "reachable"
    assert clock.tick(3 * AFTER) == 0
    assert _jobs() == [] and not FailoverDeadWatch.objects.exists()


def test_an_edge_that_cannot_tell_is_not_dead(world, clock) -> None:
    _auto_vm()
    world.kill()
    world.edge["node-src"] = "unknown"
    assert clock.tick(2 * AFTER) == 0 and _jobs() == []


def test_a_connected_netbird_peer_is_not_dead(world, clock) -> None:
    """vali's own heartbeat intake down: every miner looks silent, but the
    peer is connected to NetBird — alive."""
    _auto_vm()
    world.kill()
    world.peers[0]["connected"] = True
    assert clock.tick(2 * AFTER) == 0 and _jobs() == []


def test_netbird_unreadable_is_not_dead(world, clock) -> None:
    _auto_vm()
    world.kill()
    world.peers = EffectError("netbird api down")
    assert clock.tick(2 * AFTER) == 0 and _jobs() == []


def test_a_heartbeat_breaks_the_run(world, clock) -> None:
    _auto_vm()
    world.kill()
    clock.tick(AFTER - 2 * STEP)
    _heartbeat(clock, AFTER - STEP)
    assert clock.tick(AFTER) == 0
    assert not FailoverDeadWatch.objects.exists()
    world.kill()
    assert clock.tick(AFTER + AFTER - STEP) == 0, "the run starts again from the next check"
    assert clock.tick(2 * AFTER + STEP) == 1


def test_signals_silent_for_less_than_the_auto_window_are_not_dead(world, clock) -> None:
    _auto_vm()
    world.kill()
    _heartbeat(clock, -700)
    assert clock.tick() == 0
    assert not FailoverDeadWatch.objects.exists()


def test_a_gap_in_the_checks_restarts_the_proof(world, clock) -> None:
    """A proof nobody watched is not a proof: the tick down for an hour, or
    the worker turned off, then one dead check is not enough."""
    _auto_vm()
    world.kill()
    clock.tick(STEP)
    assert clock.jump(3600) == 0
    watch = FailoverDeadWatch.objects.get()
    assert watch.dead_since == clock.now()
    assert clock.tick(3600 + AFTER) == 1


def test_turning_the_worker_off_forgets_what_it_watched(world, clock, monkeypatch) -> None:
    _auto_vm()
    world.kill()
    clock.tick(AFTER - STEP)
    monkeypatch.setattr(settings, "VALI_FAILOVER_AUTO_ENABLED", False)
    assert clock.tick(AFTER) == 0
    assert not FailoverDeadWatch.objects.exists()
    monkeypatch.setattr(settings, "VALI_FAILOVER_AUTO_ENABLED", True)
    assert clock.tick(AFTER + STEP) == 0, "the run starts again"
    assert clock.tick(2 * AFTER + STEP) == 1


def test_the_flag_off_does_nothing(world, clock, monkeypatch) -> None:
    monkeypatch.setattr(settings, "VALI_FAILOVER_AUTO_ENABLED", False)
    _auto_vm()
    world.kill()
    assert clock.tick(2 * AFTER) == 0
    assert _jobs() == [] and not FailoverDeadWatch.objects.exists()


def test_the_proof_is_taken_afresh_right_before_the_job(world, clock, monkeypatch) -> None:
    """Between two probes the watch is trusted for the count, never to open a
    job: the final check sees the miner back and nothing opens."""
    _auto_vm()
    world.kill()
    clock.tick(AFTER - STEP)
    probes: list[str] = []
    real = failover_auto._probe

    def probe(vm_pk: int, miner_id: str, now: Any) -> dict[str, Any]:
        probes.append(miner_id)
        if len(probes) == 2:
            world.edge["node-src"] = "reachable"
        return real(vm_pk, miner_id, now)

    monkeypatch.setattr(failover_auto, "_probe", probe)
    assert clock.tick(AFTER) == 0
    assert _jobs() == [] and not FailoverDeadWatch.objects.exists()


# ── which VMs ────────────────────────────────────────────────────────


def test_a_vm_that_did_not_opt_in_is_never_touched(world, clock) -> None:
    vm = _auto_vm(mode=FailoverMode.MANUAL)
    world.kill()
    assert clock.tick(2 * AFTER) == 0
    assert _jobs() == [] and not AutoFailover.objects.exists()
    vm.refresh_from_db()
    assert (vm.state, vm.host) == (VmState.ACTIVE, "node-src")


def test_an_opt_out_racing_the_worker_wins(world, clock, monkeypatch) -> None:
    vm = _auto_vm()
    world.kill()
    clock.tick(AFTER - STEP)
    real = restore._pick_failover_dest

    def pick(vm_: Vm, source: str, *, region: str | None = None) -> str:
        BackupPolicy.objects.filter(vm=vm).update(failover_mode=FailoverMode.MANUAL)
        return real(vm_, source, region=region)

    monkeypatch.setattr(restore, "_pick_failover_dest", pick)
    assert clock.tick(AFTER) == 0 and _jobs() == []


def test_a_vm_whose_backups_are_not_local_is_refused(world, clock, monkeypatch) -> None:
    monkeypatch.setattr(sched, "launch_region_for_vm", lambda vm_id: "AU")
    _auto_vm()
    world.kill()
    assert clock.tick(2 * AFTER) == 0
    assert _jobs() == [] and not AutoFailover.objects.exists()


def test_a_vm_without_a_current_boot_point_is_left_alone(world, clock) -> None:
    vm = _auto_vm()
    BackupPolicy.objects.filter(vm=vm).update(observed_boot_counter=4)  # it rebooted since
    world.kill()
    assert clock.tick(2 * AFTER) == 0 and _jobs() == []


def test_a_vm_being_started_is_left_alone(world, clock) -> None:
    vm = _auto_vm()
    Vm.objects.filter(pk=vm.pk).update(power_state=VmPowerState.STARTING)
    world.kill()
    assert clock.tick(2 * AFTER) == 0 and _jobs() == []


def test_one_failover_at_a_time_per_dead_miner(world, clock) -> None:
    first = _auto_vm()
    second = _auto_vm("vm-2")
    world.kill()
    assert clock.tick(AFTER) == 1
    assert clock.tick(AFTER + 2 * STEP) == 0, "the first is still open"
    [job] = _jobs()
    assert job.vm_id == first.pk
    MigrationJob.objects.filter(pk=job.pk).update(
        state=MigrationState.DONE.value, finished_at=timezone.now()
    )
    assert clock.tick(AFTER + 3 * STEP) == 1
    assert [j.vm_id for j in _jobs()] == [first.pk, second.pk]


def test_a_failed_failover_backs_off_then_stops_for_an_operator(world, clock) -> None:
    _auto_vm()
    world.kill()
    t = AFTER
    for attempt in range(failover_auto.MAX_FAILED_ATTEMPTS):
        assert clock.tick(t) == 1, attempt
        MigrationJob.objects.filter(kind="failover").exclude(state="failed").update(
            state=MigrationState.FAILED.value,
            reason="dest-failed",
            finished_at=clock.now(),
        )
        assert clock.tick(t + STEP) == 0, "backing off"
        t += failover_auto.RETRY_BACKOFF_S + STEP
    assert clock.tick(t + 2 * failover_auto.RETRY_BACKOFF_S) == 0
    assert len(_jobs()) == failover_auto.MAX_FAILED_ATTEMPTS


# ── no room ──────────────────────────────────────────────────────────


def _no_room(monkeypatch: pytest.MonkeyPatch) -> None:
    def refuse(vm: Any, dest: str, source: Any = None, **kw: Any) -> None:
        raise restore.RestoreError("no-eligible-miner", f"destination {dest!r}: no room")

    monkeypatch.setattr(restore, "_validate_other_dest", refuse)


def test_no_room_waits_in_pending_capacity_and_starts_once_there_is(
    world, clock, monkeypatch, root_client
) -> None:
    vm = _auto_vm()
    world.kill()
    _no_room(monkeypatch)
    assert clock.tick(AFTER) == 0
    af = AutoFailover.objects.get()
    assert af.state == AutoFailoverState.PENDING_CAPACITY and af.attempts == 1
    listed = root_client.get(f"/v1/vm/{vm.vm_id}/restore").json()["jobs"]
    assert [(j["job_id"], j["phase"], j["trigger"], j["outcome"]) for j in listed] == [
        (af.failover_id, "pending_capacity", "auto", None)
    ]
    one = root_client.get(f"/v1/vm/{vm.vm_id}/restore/{af.failover_id}").json()
    assert one["phase"] == "pending_capacity"
    last = root_client.get(f"/v1/vm/{vm.vm_id}/state").json()["last_failover"]
    assert (last["failover_id"], last["phase"], last["trigger"]) == (
        af.failover_id,
        "pending_capacity",
        "auto",
    )
    assert clock.tick(AFTER + STEP) == 0
    af.refresh_from_db()
    assert af.attempts == 2, "retried every tick"

    monkeypatch.setattr(restore, "_validate_other_dest", lambda vm, dest, source=None, **kw: None)
    assert clock.tick(AFTER + 2 * STEP) == 1
    [job] = _jobs()
    af.refresh_from_db()
    assert job.job_id == af.failover_id, "the id it waited under is the job's"
    assert af.state == AutoFailoverState.STARTED and af.job_id == job.pk
    listed = root_client.get(f"/v1/vm/{vm.vm_id}/restore").json()["jobs"]
    assert [j["job_id"] for j in listed] == [job.job_id]


def test_a_miner_back_while_vms_wait_cancels_the_waits(world, clock, monkeypatch, root_client):
    vm = _auto_vm()
    world.kill()
    _no_room(monkeypatch)
    clock.tick(AFTER)
    _heartbeat(clock, AFTER + 30)
    clock.tick(AFTER + STEP)
    af = AutoFailover.objects.get()
    assert af.state == AutoFailoverState.CANCELLED and af.finished_at is not None
    [entry] = root_client.get(f"/v1/vm/{vm.vm_id}/restore").json()["jobs"]
    assert (entry["phase"], entry["outcome"]) == ("failed", "cancelled")
    assert _jobs() == []


def test_the_placement_group_steers_the_failover_away_from_a_sibling(
    world, clock, monkeypatch
) -> None:
    monkeypatch.setattr(restore, "_validate_other_dest", _REAL_VALIDATE)
    monkeypatch.setattr(sched, "dispatchability", lambda m, **kw: sched.Dispatchability(True, None))
    MinerIdentity.objects.create(
        miner_id="node-alt",
        pubkey_hex="ee" * 32,
        # Another chip of the destination's SNP generation (same id length).
        platform_id="5" * len(MinerIdentity.objects.get(miner_id="node-dst").platform_id),
        chain_node_id="e" * 64,
        last_seen_at=timezone.now() + timedelta(days=1),
    )
    # node-dst has the most room: it would be chosen without the group.
    monkeypatch.setattr(
        sched,
        "host_resources_by_node",
        lambda: {
            "d" * 64: sched.HostResources(64 * 1024, 8, 10**6, 64),
            "e" * 64: sched.HostResources(32 * 1024, 8, 10**6, 64),
        },
    )
    vm = _auto_vm()
    Vm.objects.filter(pk=vm.pk).update(tenant_id="t-g", placement_group="db")
    sibling = make_vm("vm-sibling", host="node-dst")
    Vm.objects.filter(pk=sibling.pk).update(tenant_id="t-g", placement_group="db")
    world.kill()
    assert clock.tick(AFTER) == 1
    [job] = _jobs()
    assert job.dest_node_id == "node-alt"


def test_a_placement_group_sibling_on_the_only_destination_means_no_room(
    world, clock, monkeypatch
) -> None:
    monkeypatch.setattr(restore, "_validate_other_dest", _REAL_VALIDATE)
    monkeypatch.setattr(sched, "dispatchability", lambda m, **kw: sched.Dispatchability(True, None))
    monkeypatch.setattr(
        sched,
        "host_resources_by_node",
        lambda: {"d" * 64: sched.HostResources(64 * 1024, 8, 10**6, 64)},
    )
    vm = _auto_vm()
    Vm.objects.filter(pk=vm.pk).update(tenant_id="t-g", placement_group="db")
    sibling = make_vm("vm-sibling", host="node-dst")
    Vm.objects.filter(pk=sibling.pk).update(tenant_id="t-g", placement_group="db")
    world.kill()
    assert clock.tick(AFTER) == 0
    assert AutoFailover.objects.get().state == AutoFailoverState.PENDING_CAPACITY
    assert _jobs() == []


# ── miner back before the KBS moves ──────────────────────────────────


def test_a_miner_back_before_the_fence_cancels_the_job_and_is_not_retried(
    fx: FakeEffects, world, clock, pwr, root_client
) -> None:
    vm = _auto_vm()
    world.kill()
    clock.tick(AFTER)
    [job] = _jobs()
    world.edge["node-src"] = "reachable"  # it came back
    fx.kbs_evidence = None
    job = _advance(_advance(job))
    assert job.state == MigrationState.FAILED.value
    assert not fx.did("kbs_activate_dest")
    assert not FailoverDeadWatch.objects.exists(), "the fence re-check is a live signal"
    [entry] = root_client.get(f"/v1/vm/{vm.vm_id}/restore").json()["jobs"]
    assert entry["outcome"] == "cancelled"
    vm.refresh_from_db()
    assert (vm.state, vm.host) == (VmState.ACTIVE, "node-src")
    world.edge["node-src"] = "unreachable"
    assert clock.tick(AFTER + 10) == 0, "never re-opened off a cached verdict"
    assert len(_jobs()) == 1


def test_a_heartbeat_back_before_the_fence_cancels_the_job(fx: FakeEffects, world, clock, pwr):
    _auto_vm()
    world.kill()
    clock.tick(AFTER)
    [job] = _jobs()
    MinerIdentity.objects.filter(miner_id="node-src").update(last_seen_at=timezone.now())
    fx.kbs_evidence = None
    job = _advance(_advance(job))
    assert job.state == MigrationState.FAILED.value
    assert job.reason.startswith("miner-not-dead-at-fence")
    assert restore.outcome(job) == "cancelled"
    assert not fx.did("kbs_activate_dest")


def _errored_activate(fx: FakeEffects, world, clock, monkeypatch) -> MigrationJob:
    """A job fenced whose KBS activate errored (it may have landed)."""
    _auto_vm()
    world.kill()
    clock.tick(AFTER)
    [job] = _jobs()

    def flaky(*a: Any, **k: Any) -> None:
        raise EffectError("kbs down")

    monkeypatch.setattr(effects, "kbs_activate_dest", flaky)
    fx.kbs_evidence = None
    job = _advance(job)
    assert Vm.objects.get(pk=job.vm_id).state == VmState.MIGRATING, "fenced"
    job.refresh_from_db()
    assert job.kbs_activate_first_attempt_at is not None and job.kbs_activated_at is None
    return job


def _audit_cursor() -> None:
    from apps.orchestration.models import KbsAuditCursor

    KbsAuditCursor.objects.create(
        log="admin",
        kbs_epoch="e1",
        last_seq=10,
        last_hash="0" * 64,
        head_seq=10,
        checked_at=timezone.now() + timedelta(hours=1),
    )


def _audit_activate(vm: Vm, at: Any) -> None:
    from apps.orchestration.models import KbsAuditEntry

    KbsAuditEntry.objects.create(
        log="admin",
        kbs_epoch="e1",
        seq=9,
        body_cbor=b"",
        sha256="1" * 64,
        prev_hash="0" * 64,
        fetched_at=timezone.now(),
        op="activate",
        vm_id=vm.vm_id,
        status_code=200,
        applied=True,
        event_unix=int(at.timestamp()),
    )


def test_fenced_kbs_undecided_and_the_source_back_waits(
    fx: FakeEffects, world, clock, pwr, monkeypatch
) -> None:
    """The activate errored and the audit log does not settle it: the job
    neither reverts onto the source nor activates elsewhere — it waits, and
    says since when."""
    job = _errored_activate(fx, world, clock, monkeypatch)
    world.edge["node-src"] = "reachable"
    calls = len(fx.calls)
    job = _advance(_advance(job))
    assert job.state == MigrationState.DEST_ACTIVATING.value, job.reason
    assert not [c for c in fx.calls[calls:] if c[0].startswith("dispatch")]
    assert job.authorization.evidence["fence_undecided_since"]
    text = failover_auto.report_metrics(now=clock.now()).render()
    assert "hippius_failover_fence_undecided_since_seconds{" in text


def test_fenced_but_never_asked_the_kbs_and_the_source_back_cancels(
    fx: FakeEffects, world, clock, pwr, monkeypatch
) -> None:
    """Fenced, then the tick died before the KBS activate was even asked:
    the KBS cannot have moved, so a live source cancels and gets its VM
    back."""
    from apps.orchestration import service

    _auto_vm()
    world.kill()
    clock.tick(AFTER)
    [job] = _jobs()

    def crash(job_: Any, get_url: str) -> None:
        raise EffectError("the tick died")

    monkeypatch.setattr(service, "_kbs_activate_stamped", crash)
    fx.kbs_evidence = None
    job = _advance(job)
    assert Vm.objects.get(pk=job.vm_id).state == VmState.MIGRATING
    assert restore.kbs_moved(job) is False
    world.edge["node-src"] = "reachable"
    job = _advance(_advance(job))
    assert job.state == MigrationState.FAILED.value
    assert job.reason == "miner-not-dead-at-fence"
    assert restore.outcome(job) == "cancelled"
    vm = Vm.objects.get(pk=job.vm_id)
    assert (vm.state, vm.host) == (VmState.ACTIVE, "node-src"), "back on its live source"


def test_the_audit_logs_silence_never_proves_the_kbs_did_not_move(
    fx: FakeEffects, world, clock, pwr, monkeypatch
) -> None:
    job = _errored_activate(fx, world, clock, monkeypatch)
    _audit_cursor()  # caught up, and no activate in it
    assert restore.kbs_moved(job) is None


def test_fenced_kbs_moved_per_the_audit_log_finishes_the_failover(
    fx: FakeEffects, world, clock, pwr, monkeypatch
) -> None:
    """The errored activate landed (the KBS audit log says so): the old
    instance never gets a key again, so the failover goes on even though the
    source answers."""
    job = _errored_activate(fx, world, clock, monkeypatch)
    _audit_cursor()
    _audit_activate(job.vm, job.kbs_activate_first_attempt_at)
    assert restore.kbs_moved(job) is True
    monkeypatch.setattr(effects, "kbs_activate_dest", lambda *a, **k: None)
    world.edge["node-src"] = "reachable"
    MinerIdentity.objects.filter(miner_id="node-src").update(last_seen_at=timezone.now())
    job = _advance(job)
    job.refresh_from_db()
    assert job.kbs_activated_at is not None, "the re-drive was acknowledged"
    assert job.state in (
        MigrationState.DEST_ACTIVATING.value,
        MigrationState.RESTORE_VERIFYING.value,
    ), job.reason
    assert not (job.reason or "").startswith("miner-not-dead")


def test_a_wiped_idempotency_store_mid_download_does_not_stop_the_failover(
    fx: FakeEffects, world, clock, pwr, monkeypatch
) -> None:
    """A pod replacement wipes the emptyDir store while the destination
    downloads; the source then answers, and the pool is held: the KBS moved
    (durable stamp), so nothing is re-checked and the job carries on."""
    from apps.orchestration import idempotency

    _auto_vm()
    world.kill()
    clock.tick(AFTER)
    [job] = _jobs()
    fx.kbs_evidence = None
    job = _advance(job)
    job.refresh_from_db()
    assert job.kbs_activated_at is not None and job.kbs_activated_gen == job.new_gen
    monkeypatch.setattr(idempotency, "recall", lambda key: None)  # the wipe
    world.edge["node-src"] = "reachable"
    MinerIdentity.objects.filter(miner_id="node-src").update(last_seen_at=timezone.now())
    monkeypatch.setattr(failover_auto, "held", lambda **kw: True)
    assert restore.kbs_moved(job) is True
    for _ in range(3):
        job = _advance(job)
        assert not (job.reason or "").startswith(("miner-not-dead", "failover-auto")), job.reason
    job.refresh_from_db()
    assert "fence_undecided_since" not in job.authorization.evidence, "never re-checked"
    assert job.authorization.evidence["recheck"]["edge"] == "unreachable", "the pre-KBS check"


def test_an_opt_out_with_an_open_pre_fence_job_cancels_it(
    fx: FakeEffects, world, clock, pwr
) -> None:
    vm = _auto_vm()
    world.kill()
    clock.tick(AFTER)
    [job] = _jobs()
    BackupPolicy.objects.filter(vm=vm).update(failover_mode=FailoverMode.MANUAL)
    fx.kbs_evidence = None
    job = _advance(_advance(job))
    assert job.reason == "failover-auto-disabled-at-fence"
    assert restore.outcome(job) == "cancelled"
    assert not fx.did("kbs_activate_dest")


def test_cancelled_is_never_reported_once_the_kbs_moved() -> None:
    job = MigrationJob(kind="failover", state="failed", reason="miner-not-dead-at-fence")
    assert restore.cancelled_at_fence(job) == "miner-back"
    job.kbs_activated_at = timezone.now()
    assert restore.cancelled_at_fence(job) is None


# ── the guard ────────────────────────────────────────────────────────


def test_too_many_dead_miners_at_once_holds_everything(world, clock) -> None:
    _auto_vm()
    for i in range(3):
        MinerIdentity.objects.create(
            miner_id=f"node-x{i}",
            pubkey_hex=f"{i:02x}" * 32,
            platform_id=f"{i:02x}" * 64,
            last_seen_at=timezone.now() - timedelta(hours=1),
        )  # registered active, silent (vali's heartbeat intake down)
    world.kill()
    assert clock.tick(AFTER + STEP) == 0 and _jobs() == []
    assert failover_auto.held(now=clock.now())
    MinerIdentity.objects.filter(miner_id__startswith="node-x").update(
        last_seen_at=timezone.now() + timedelta(days=1)
    )
    assert clock.tick(AFTER + 2 * STEP) == 1


# ── crashes ──────────────────────────────────────────────────────────


def test_a_crash_after_the_job_opened_is_repaired(world, clock, monkeypatch, root_client):
    vm = _auto_vm()
    world.kill()
    _no_room(monkeypatch)
    clock.tick(AFTER)
    af = AutoFailover.objects.get()
    monkeypatch.setattr(restore, "_validate_other_dest", lambda vm, dest, source=None, **kw: None)
    real_record = failover_auto._record_started
    monkeypatch.setattr(failover_auto, "_record_started", lambda *a, **k: None)  # the crash
    assert clock.tick(AFTER + STEP) == 1
    af.refresh_from_db()
    assert af.state == AutoFailoverState.PENDING_CAPACITY and af.job is None
    monkeypatch.setattr(failover_auto, "_record_started", real_record)
    clock.tick(AFTER + 2 * STEP)
    af.refresh_from_db()
    [job] = _jobs()
    assert af.state == AutoFailoverState.STARTED and af.job_id == job.pk
    one = root_client.get(f"/v1/vm/{vm.vm_id}/restore/{job.job_id}").json()
    assert one["phase"] != "pending_capacity"


def test_an_auto_job_without_its_audit_row_gets_one(world, clock, monkeypatch) -> None:
    _auto_vm()
    world.kill()
    real_record = failover_auto._record_started
    monkeypatch.setattr(failover_auto, "_record_started", lambda *a, **k: None)
    assert clock.tick(AFTER) == 1
    assert not AutoFailover.objects.exists()
    monkeypatch.setattr(failover_auto, "_record_started", real_record)
    clock.tick(AFTER + STEP)
    [job] = _jobs()
    af = AutoFailover.objects.get()
    assert af.job_id == job.pk and af.failover_id == job.job_id
    assert af.evidence["dead_since"]


# ── capacity reserved before the fence ───────────────────────────────


def test_the_destination_holds_the_room_from_the_moment_the_job_opens(world, clock) -> None:
    from apps.identity.models import ServiceClient
    from apps.scheduler.models import PlacementStatus
    from apps.scheduler.tests.factories import make_placement

    vm = _auto_vm()
    MinerIdentity.objects.filter(miner_id="node-src").update(chain_node_id="c" * 64)
    make_placement(vm, "c" * 64, status=PlacementStatus.BOUND.value, resource_class="small")
    assert sched.in_flight_move_reservations() == []
    assert "d" * 64 not in sched._committed_by_node()
    world.kill()
    clock.tick(AFTER)
    assert sched.in_flight_move_reservations() == [("d" * 64, "small", None)]
    assert sched._committed_by_node()["d" * 64].vms == 1, "capacity v2 and the disk gate"
    assert sched.decision_inputs("t")[1].get("d" * 64) == 1, "capacity v1"
    # Once the placement moves there at activation, it is counted once.
    sched.move_placement_to_node(
        vm, node_id="d" * 64, decided_by=ServiceClient.objects.first(), reason="test"
    )
    assert sched.in_flight_move_reservations() == []
    assert sched._committed_by_node()["d" * 64].vms == 1


# ── eligibility and gauges ───────────────────────────────────────────


def test_the_policy_reads_disabled_while_the_worker_is_off(monkeypatch) -> None:
    from apps.backup import service as backup_service

    vm = _auto_vm()
    policy = BackupPolicy.objects.get(vm=vm)
    assert backup_service.failover_auto_status(policy) == (True, None)
    monkeypatch.setattr(settings, "VALI_FAILOVER_AUTO_ENABLED", False)
    assert backup_service.failover_auto_status(policy) == (False, "disabled")


def test_the_gauges(world, clock, monkeypatch) -> None:
    _auto_vm()
    second = _auto_vm("vm-2")
    world.kill()
    clock.tick(AFTER)
    text = failover_auto.report_metrics(now=clock.now()).render()
    assert "hippius_failover_auto_jobs{" in text and 'phase="activating"' in text
    assert "hippius_failover_auto_enabled 1" in text
    assert "hippius_failover_auto_dead_miners 1" in text
    assert "hippius_failover_auto_held 0" in text
    _no_room(monkeypatch)
    MigrationJob.objects.filter(kind="failover").update(
        state=MigrationState.FAILED.value, reason="boom", finished_at=clock.now()
    )
    clock.tick(AFTER + STEP)
    text = failover_auto.report_metrics(now=clock.now()).render()
    assert f'vm="{second.vm_id}"' in text
    assert "hippius_failover_auto_pending_capacity_since_seconds{" in text
    assert "hippius_failover_auto_failed_24h{" in text and 'outcome="failed"' in text


# ── second review ────────────────────────────────────────────────────


def test_a_heartbeat_landing_during_the_probe_is_alive(world, clock, monkeypatch) -> None:
    """The heartbeat is read again after the NetBird and Edge calls: one that
    arrived while they ran wins over what they said."""
    _auto_vm()
    world.kill()

    def edge(vm: Any, node: str) -> str:
        _heartbeat(clock, clock.at)
        return "unreachable"

    monkeypatch.setattr(effects, "probe_edge_session", edge)
    assert clock.tick(2 * AFTER) == 0
    assert _jobs() == [] and not FailoverDeadWatch.objects.exists()


def test_a_vm_being_stopped_is_left_alone(world, clock) -> None:
    vm = _auto_vm()
    Vm.objects.filter(pk=vm.pk).update(power_state=VmPowerState.STOPPING)
    world.kill()
    assert clock.tick(2 * AFTER) == 0 and _jobs() == []


def test_a_vm_with_a_launch_in_flight_is_left_alone(world, clock) -> None:
    from apps.orchestration.models import LaunchJob, LaunchJobState

    from .factories import make_service_client

    vm = _auto_vm()
    LaunchJob.objects.create(
        job_id="job-relaunch",
        vm_id=vm.vm_id,
        tenant_id="t",
        flavor="small",
        spec_json={},
        userdata_vault_path="p",
        userdata_vault_version=1,
        kek_vault_path="k",
        state=LaunchJobState.RUNNING.value,
        phase_started_at=timezone.now(),
        decided_by=make_service_client(),
    )
    world.kill()
    assert clock.tick(2 * AFTER) == 0 and _jobs() == []


def test_a_cancelled_wait_whose_job_opened_is_linked_to_it(world, clock, monkeypatch) -> None:
    _auto_vm()
    world.kill()
    _no_room(monkeypatch)
    clock.tick(AFTER)
    af = AutoFailover.objects.get()
    monkeypatch.setattr(restore, "_validate_other_dest", lambda vm, dest, source=None, **kw: None)
    real_record = failover_auto._record_started
    monkeypatch.setattr(failover_auto, "_record_started", lambda *a, **k: None)  # the crash
    assert clock.tick(AFTER + STEP) == 1
    AutoFailover.objects.filter(pk=af.pk).update(state=AutoFailoverState.CANCELLED)
    monkeypatch.setattr(failover_auto, "_record_started", real_record)
    clock.tick(AFTER + 2 * STEP)
    af.refresh_from_db()
    [job] = _jobs()
    assert af.state == AutoFailoverState.STARTED and af.job_id == job.pk
    assert AutoFailover.objects.count() == 1


def test_the_room_stays_held_after_the_dead_sources_placement_closed(world, clock) -> None:
    from apps.orchestration.models import LaunchJob, LaunchJobState

    from .factories import make_service_client

    vm = _auto_vm()
    LaunchJob.objects.create(
        job_id="job-launch",
        vm_id=vm.vm_id,
        tenant_id="t",
        flavor="medium",
        spec_json={"flavor": "medium"},
        userdata_vault_path="p",
        userdata_vault_version=1,
        kek_vault_path="k",
        state=LaunchJobState.SUCCEEDED.value,
        phase_started_at=timezone.now(),
        finished_at=timezone.now(),
        decided_by=make_service_client(),
    )
    world.kill()
    clock.tick(AFTER)
    [(node, flavor, _disk)] = sched.in_flight_move_reservations()
    assert (node, flavor) == ("d" * 64, "medium")


def test_held_counts_watched_and_silent_miners_together(world, clock, monkeypatch) -> None:
    monkeypatch.setattr(settings, "VALI_FAILOVER_AUTO_MAX_DEAD_MINERS", 1)
    _auto_vm()
    world.kill()
    clock.tick()
    # node-src is watched; a different, silent active miner joins it.
    MinerIdentity.objects.create(
        miner_id="node-x",
        pubkey_hex="ab" * 32,
        platform_id="cd" * 64,
        last_seen_at=timezone.now() - timedelta(hours=1),
    )
    assert failover_auto.dead_count(now=clock.now()) == 2
    assert failover_auto.held(now=clock.now())


def test_a_hold_at_the_fence_cancels_as_held(fx: FakeEffects, world, clock, pwr, monkeypatch):
    _auto_vm()
    world.kill()
    clock.tick(AFTER)
    [job] = _jobs()
    monkeypatch.setattr(failover_auto, "held", lambda **kw: True)
    fx.kbs_evidence = None
    job = _advance(_advance(job))
    assert job.reason == "failover-auto-held-at-fence"
    assert restore.outcome(job) == "cancelled"
    assert restore.cancelled_at_fence(job) == "held"
    assert not fx.did("kbs_activate_dest")


def test_a_miner_never_heard_from_does_not_count_as_dead() -> None:
    MinerIdentity.objects.create(miner_id="node-ghost", pubkey_hex="ab" * 32, platform_id="cd" * 64)
    assert failover_auto.dead_count() == 0


def test_fenced_an_unreadable_signal_is_asked_again_not_a_cancel(
    fx: FakeEffects, world, clock, pwr, monkeypatch
) -> None:
    """Once fenced, NetBird unreadable at the re-check is not a live miner:
    the job waits for a readable verdict instead of stranding the VM."""
    _auto_vm()
    world.kill()
    clock.tick(AFTER)
    [job] = _jobs()
    real_activate = effects.kbs_activate_dest

    def flaky(*a: Any, **k: Any) -> None:
        raise EffectError("kbs down")

    monkeypatch.setattr(effects, "kbs_activate_dest", flaky)
    fx.kbs_evidence = None
    job = _advance(job)
    assert Vm.objects.get(pk=job.vm_id).state == VmState.MIGRATING
    world.peers = EffectError("netbird api down")
    job = _advance(job)
    assert job.state == MigrationState.DEST_ACTIVATING.value, job.reason
    world.kill()
    monkeypatch.setattr(effects, "kbs_activate_dest", real_activate)
    job = _advance(job)
    assert job.state in (
        MigrationState.DEST_ACTIVATING.value,
        MigrationState.RESTORE_VERIFYING.value,
    ), job.reason


def test_turned_off_before_the_fence_cancels_the_job(
    fx: FakeEffects, world, clock, pwr, monkeypatch
) -> None:
    _auto_vm()
    world.kill()
    clock.tick(AFTER)
    [job] = _jobs()
    monkeypatch.setattr(settings, "VALI_FAILOVER_AUTO_ENABLED", False)
    fx.kbs_evidence = None
    job = _advance(_advance(job))
    assert job.reason == "failover-auto-disabled-at-fence"
    assert restore.outcome(job) == "cancelled"
    assert not fx.did("kbs_activate_dest")


def test_an_abandoned_registration_does_not_hold_the_worker() -> None:
    long_ago = timezone.now() - timedelta(days=3)
    MinerIdentity.objects.create(
        miner_id="node-old", pubkey_hex="ab" * 32, platform_id="cd" * 64, last_seen_at=long_ago
    )
    assert failover_auto.dead_count() == 0
    # The same silence on a miner that hosts an Active VM counts.
    make_vm("vm-on-old", host="node-old")
    assert failover_auto.dead_count() == 1


def test_an_operator_reset_lets_the_worker_try_again(world, clock) -> None:
    from django.core.management import call_command

    vm = _auto_vm()
    world.kill()
    t = AFTER
    for _ in range(failover_auto.MAX_FAILED_ATTEMPTS):
        assert clock.tick(t) == 1
        MigrationJob.objects.filter(kind="failover").exclude(state="failed").update(
            state=MigrationState.FAILED.value, reason="dest-failed", finished_at=clock.now()
        )
        t += failover_auto.RETRY_BACKOFF_S + STEP
    assert clock.tick(t) == 0, "stopped for an operator"
    call_command("vali_failover_auto", "reset", "--vm-id", vm.vm_id, "--operator", "ops")
    from apps.orchestration.models import AutoFailoverReset

    AutoFailoverReset.objects.update(reset_at=clock.now())  # the scenario's clock
    assert clock.tick(t + STEP) == 1


def test_an_audit_activate_of_another_kbs_epoch_or_a_broken_chain_is_not_proof(
    fx: FakeEffects, world, clock, pwr, monkeypatch
) -> None:
    from apps.orchestration.models import KbsAuditEntry

    job = _errored_activate(fx, world, clock, monkeypatch)
    _audit_cursor()
    _audit_activate(job.vm, job.kbs_activate_first_attempt_at)
    KbsAuditEntry.objects.update(kbs_epoch="e0")
    assert restore.kbs_moved(job) is None
    KbsAuditEntry.objects.update(kbs_epoch="e1", chain_ok=False)
    assert restore.kbs_moved(job) is None
    KbsAuditEntry.objects.update(
        chain_ok=True, event_unix=int(job.kbs_activate_first_attempt_at.timestamp()) - 3600
    )
    assert restore.kbs_moved(job) is None, "an older activate is not this job's"


def test_the_migration_backfills_jobs_already_in_flight() -> None:
    import importlib

    from django.apps import apps as django_apps

    vm = _auto_vm()
    run = BackupPolicy.objects.get(vm=vm).vm.backup_runs.order_by("-seq").first()
    from .factories import make_service_client

    job, _ = restore.start_restore(
        vm=vm, run_id=run.run_id, request_id="r-bf", decided_by=make_service_client()
    )
    MigrationJob.objects.filter(pk=job.pk).update(state=MigrationState.DEST_ACTIVATING.value)
    module = importlib.import_module(
        "apps.orchestration.migrations.0041_failover_kbs_activate_stamp"
    )
    module.stamp_jobs_in_flight(django_apps, None)
    job.refresh_from_db()
    assert job.kbs_activate_first_attempt_at is not None and job.kbs_activated_at is None
    assert restore.kbs_moved(job) is None, "undecided, never 'never moved'"
    MigrationJob.objects.filter(pk=job.pk).update(
        state=MigrationState.RESTORE_VERIFYING.value,
        kbs_activate_first_attempt_at=None,
        kbs_activate_last_attempt_at=None,
    )
    module.stamp_jobs_in_flight(django_apps, None)
    job.refresh_from_db()
    assert job.kbs_activated_at is not None and restore.kbs_moved(job) is True


def test_a_settled_fence_clears_its_undecided_mark(
    fx: FakeEffects, world, clock, pwr, monkeypatch
) -> None:
    job = _errored_activate(fx, world, clock, monkeypatch)
    world.edge["node-src"] = "reachable"
    job = _advance(job)
    assert "fence_undecided_since" in job.authorization.evidence
    world.edge["node-src"] = "unreachable"  # dead again: the job goes on
    job = _advance(job)
    job.refresh_from_db()
    assert "fence_undecided_since" not in job.authorization.evidence


def test_an_audit_activate_another_job_of_the_vm_may_own_is_not_proof(
    fx: FakeEffects, world, clock, pwr, monkeypatch
) -> None:
    job = _errored_activate(fx, world, clock, monkeypatch)
    _audit_cursor()
    _audit_activate(job.vm, job.kbs_activate_first_attempt_at)
    assert restore.kbs_moved(job) is True
    other = MigrationJob.objects.get(pk=job.pk)
    other.pk = None
    other.job_id = "job-other"
    other.request_id = "req-other"
    other.state = MigrationState.FAILED.value
    other.finished_at = timezone.now()
    other.kbs_activated_at = None
    other.save()
    assert restore.kbs_moved(job) is None


def test_the_backfill_never_calls_a_revert_acknowledged() -> None:
    import importlib

    from django.apps import apps as django_apps

    from .factories import make_service_client

    vm = _auto_vm()
    run = vm.backup_runs.order_by("-seq").first()
    job, _ = restore.start_restore(
        vm=vm, run_id=run.run_id, request_id="r-rv", decided_by=make_service_client()
    )
    MigrationJob.objects.filter(pk=job.pk).update(state=MigrationState.RESTORE_REVERTING.value)
    importlib.import_module(
        "apps.orchestration.migrations.0041_failover_kbs_activate_stamp"
    ).stamp_jobs_in_flight(django_apps, None)
    job.refresh_from_db()
    assert job.kbs_activate_first_attempt_at is not None and job.kbs_activated_at is None


def test_a_settled_fence_withdraws_its_gauge_with_the_worker_off(
    fx: FakeEffects, world, clock, pwr, monkeypatch
) -> None:
    from apps.synthetic import metrics

    pushed: list[str] = []
    monkeypatch.setattr(metrics, "push", lambda ms, **kw: pushed.append(ms.render()) or True)
    job = _errored_activate(fx, world, clock, monkeypatch)
    world.edge["node-src"] = "reachable"
    _advance(job)
    monkeypatch.setattr(settings, "VALI_FAILOVER_AUTO_ENABLED", False)
    monkeypatch.setattr(failover_auto, "_last_push", 0.0)
    failover_auto.tick()
    assert "hippius_failover_fence_undecided_since_seconds{" in pushed[-1]
    world.edge["node-src"] = "unreachable"
    _advance(job)
    failover_auto.tick()
    assert "hippius_failover_fence_undecided_since_seconds{" not in pushed[-1], "withdrawn"
    count = len(pushed)
    failover_auto.tick()
    assert len(pushed) == count, "nothing more to say"


@pytest.mark.real_idempotency
def test_a_tick_restart_in_the_settle_window_still_honours_the_dests_done(
    fx: FakeEffects, world, clock, pwr, monkeypatch
) -> None:
    """The store is the table now: a tick pod replaced while the destination
    settles keeps its record that the order went out, so the destination's
    `done` — reported inside the last window, when no order is re-sent — is
    honoured instead of ignored until the phase times out."""
    from apps.orchestration import service

    _auto_vm()
    world.kill()
    clock.tick(AFTER)
    [job] = _jobs()
    fx.dest_activation_status = "running"
    job = _advance(job)
    assert job.state == MigrationState.DEST_ACTIVATING.value
    assert service._attempt_dispatched(job, 0), "recorded in the table"
    dispatches = [c for c in fx.calls if c[0] == "dispatch_migrate_activate"]
    assert len(dispatches) == 1
    # The pod is replaced: process state goes, the table keeps the record
    # (the companion test below shows what losing it did). The settle
    # window has begun: no re-dispatch.
    from apps.orchestration.models import IdempotencyRecord

    assert IdempotencyRecord.objects.filter(
        key__startswith=f"migration:{job.job_id}:dispatch"
    ).exists()
    monkeypatch.setattr(service, "_activate_settle_by_unix", lambda job_: int(time.time()) + 60)
    fx.dest_activation_status = "done"
    job = _advance(job)
    assert job.state != MigrationState.FAILED.value, job.reason
    assert job.state in (MigrationState.RESTORE_VERIFYING.value, MigrationState.DONE.value), (
        job.state
    )
    assert len([c for c in fx.calls if c[0] == "dispatch_migrate_activate"]) == 1


@pytest.mark.real_idempotency
def test_with_the_store_wiped_the_settle_window_done_was_ignored(
    fx: FakeEffects, world, clock, pwr, monkeypatch
) -> None:
    """The failure the table prevents, reproduced: the old emptyDir store,
    wiped by a pod replacement, loses the record that the order went out,
    and the destination's `done` in its settle window is ignored."""
    from apps.orchestration import service
    from apps.orchestration.models import IdempotencyRecord

    _auto_vm()
    world.kill()
    clock.tick(AFTER)
    [job] = _jobs()
    fx.dest_activation_status = "running"
    job = _advance(job)
    IdempotencyRecord.objects.all().delete()  # what a pod replacement did to /tmp
    monkeypatch.setattr(service, "_activate_settle_by_unix", lambda job_: int(time.time()) + 60)
    fx.dest_activation_status = "done"
    job = _advance(job)
    assert job.state == MigrationState.DEST_ACTIVATING.value, "the done was ignored"


# ── the region survives the miner's death (live canary 2026-10-11) ───


def test_a_dead_miners_vm_keeps_its_region_and_fails_over_in_it(
    world, clock, monkeypatch, settings
) -> None:
    """End to end, no region patched: a VM launched with no region, on a
    miner the geo-probe has just downgraded to unverified (it stopped
    answering). Its last verified country (FR) is its region, it stays
    eligible, and the destination is an FR miner — never the AU one."""
    from apps.miners.models import LocationVerdict, MinerLocation

    settings.VALI_GEO_REQUIRE_VERIFIED = True
    monkeypatch.setattr(sched, "launch_region_for_vm", lambda vm_id: "")
    now = timezone.now()
    MinerIdentity.objects.filter(miner_id="node-src").update(chain_node_id="c" * 64)
    MinerIdentity.objects.create(
        miner_id="node-au",
        pubkey_hex="ee" * 32,
        platform_id="5" * len(MinerIdentity.objects.get(miner_id="node-dst").platform_id),
        chain_node_id="e" * 64,
        last_seen_at=now + timedelta(days=1),
    )
    for miner_id, cc, verdict, last in (
        ("node-src", "FR", LocationVerdict.UNVERIFIED, "FR"),  # downgraded: unreachable
        ("node-dst", "FR", LocationVerdict.VERIFIED, "FR"),
        ("node-au", "AU", LocationVerdict.VERIFIED, "AU"),
    ):
        MinerLocation.objects.update_or_create(
            miner=MinerIdentity.objects.get(miner_id=miner_id),
            defaults={
                "country_code": cc,
                "verdict": verdict,
                "last_verified_country_code": last,
                "last_verified_at": now - timedelta(minutes=30),
                "observed_at": now,
            },
        )
    # The real region maps: the destinations' fresh verified rows.
    monkeypatch.setattr(sched, "region_by_node", lambda **kw: {"d" * 64: "FR", "e" * 64: "AU"})
    vm = _auto_vm()
    from apps.backup import service as backup_service

    policy = BackupPolicy.objects.get(vm=vm)
    assert backup_service.vm_region(vm) == "FR"
    assert backup_service.failover_auto_status(policy) == (True, None)
    world.kill()
    assert clock.tick(AFTER) == 1
    [job] = _jobs()
    assert job.dest_node_id == "node-dst"


def test_no_region_means_no_destination_at_all(world, monkeypatch) -> None:
    """A VM whose region cannot be told is never placed anywhere — not on
    whatever miner has room in another country (the canary picked AU for a
    FR VM)."""
    vm = _auto_vm()
    monkeypatch.setattr(sched, "launch_region_for_vm", lambda vm_id: "")
    with pytest.raises(restore.RestoreError) as exc:
        restore._pick_failover_dest(vm, "node-src", region="")
    assert exc.value.code == "region-unknown"
    with pytest.raises(restore.RestoreError) as exc:
        restore._pick_failover_dest(vm, "node-src")  # the VM's own region: unknown
    assert exc.value.code == "region-unknown"


def test_a_named_destination_is_refused_without_a_region_or_in_another(monkeypatch) -> None:
    monkeypatch.setattr(restore, "_validate_other_dest", _REAL_VALIDATE)
    monkeypatch.setattr(sched, "dispatchability", lambda m, **kw: sched.Dispatchability(True, None))
    monkeypatch.setattr(
        sched,
        "host_resources_by_node",
        lambda: {"d" * 64: sched.HostResources(64 * 1024, 8, 10**6, 64)},
    )
    vm = _auto_vm()
    monkeypatch.setattr(sched, "launch_region_for_vm", lambda vm_id: "")
    with pytest.raises(restore.RestoreError) as exc:
        restore._validate_other_dest(vm, "node-dst", source="node-src")
    assert exc.value.code == "region-unknown"
    monkeypatch.setattr(sched, "launch_region_for_vm", lambda vm_id: "AU")
    with pytest.raises(restore.RestoreError) as exc:
        restore._validate_other_dest(vm, "node-dst", source="node-src")
    assert exc.value.code == "no-eligible-miner" and "region" in exc.value.detail
    monkeypatch.setattr(sched, "launch_region_for_vm", lambda vm_id: "FR")
    restore._validate_other_dest(vm, "node-dst", source="node-src")


def test_the_operator_states_a_region_vali_cannot_tell_never_another_one(
    world, monkeypatch, root_client, settings
) -> None:
    """The manual way out: a VM whose region vali cannot tell (its host was
    downgraded before its country was ever kept) fails over only when the
    operator states its region — never to another region than one vali
    knows."""
    settings.VALI_FAILOVER_MANUAL_ENABLED = True
    vm = _auto_vm()
    monkeypatch.setattr(sched, "launch_region_for_vm", lambda vm_id: "")
    world.kill()
    url = f"/v1/vm/{vm.vm_id}/failover"
    resp = root_client.post(url, {"request_id": "fo-r1"}, format="json")
    assert resp.status_code == 409 and resp.json()["error"] == "region-unknown"
    resp = root_client.post(url, {"request_id": "fo-r2", "region": "fra"}, format="json")
    assert resp.status_code == 400
    resp = root_client.post(url, {"request_id": "fo-r3", "region": "fr"}, format="json")
    assert resp.status_code == 202, resp.content
    job = MigrationJob.objects.get(job_id=resp.json()["job_id"])
    assert job.dest_node_id == "node-dst"
    assert job.authorization.evidence["region"] == "FR"
    assert job.authorization.evidence["region_stated_by_operator"] is True


def test_a_stated_region_never_overrides_the_one_vali_knows(world, monkeypatch) -> None:
    vm = _auto_vm()  # FR (the launch region the fixture sets)
    assert restore.operator_region(vm, "FR") == ("FR", False)
    assert restore.operator_region(vm, None) == ("FR", False)
    with pytest.raises(restore.RestoreError) as exc:
        restore.operator_region(vm, "AU")
    assert exc.value.code == "region-conflict"


# ── a dead miner whose auto VMs are passed over is never silent ──────


def _capture_errors(monkeypatch: pytest.MonkeyPatch, errors: list[str]) -> None:
    class _Log:
        def error(self, msg: str, *args: Any, **kwargs: Any) -> None:
            errors.append(msg % args)

        def __getattr__(self, name: str) -> Any:
            return lambda *a, **k: None

    monkeypatch.setattr(failover_auto, "log", _Log())


def test_a_skipped_auto_vm_on_a_dead_miner_is_logged_once_gauged_and_blocks(
    world, clock, monkeypatch
) -> None:
    """The canary: the worker saw the miner dead, then passed over its only
    auto VM (not eligible) with no log, no row, no metric — 26 h without an
    alert. Now: one ERROR per (vm, reason), a skipped gauge, and the miner
    reported blocked once it has been dead for the auto window."""
    errors: list[str] = []

    _capture_errors(monkeypatch, errors)
    monkeypatch.setattr(sched, "launch_region_for_vm", lambda vm_id: "AU")
    vm = _auto_vm()
    world.kill()
    assert clock.tick(AFTER + 3 * STEP) == 0
    lines = [m for m in errors if "skipped" in m]
    assert lines == [
        f"failover-auto: dead miner node-src: auto vm {vm.vm_id} skipped "
        "(not-eligible:region-backups-not-local)"
    ], "once per (vm, reason), however many ticks"
    text = failover_auto.report_metrics(now=clock.now()).render()
    assert "hippius_failover_auto_skipped{" in text
    assert 'reason="not-eligible:region-backups-not-local"' in text
    assert 'hippius_failover_auto_blocked{miner="node-src"} 1' in text


def test_a_miner_with_its_failover_open_is_not_blocked(world, clock) -> None:
    _auto_vm()
    world.kill()
    assert clock.tick(AFTER) == 1
    text = failover_auto.report_metrics(now=clock.now()).render()
    assert "hippius_failover_auto_blocked{" not in text
    assert "hippius_failover_auto_skipped{" not in text


def test_a_miner_back_clears_its_skips(world, clock, monkeypatch) -> None:
    monkeypatch.setattr(sched, "launch_region_for_vm", lambda vm_id: "AU")
    _auto_vm()
    world.kill()
    clock.tick(AFTER + STEP)
    assert failover_auto._skips
    _heartbeat(clock, AFTER + 2 * STEP)
    clock.tick(AFTER + 2 * STEP + 10)
    assert not failover_auto._skips
    text = failover_auto.report_metrics(now=clock.now()).render()
    assert "hippius_failover_auto_blocked{" not in text


def test_a_hold_is_not_reported_as_each_miner_blocked(world, clock, monkeypatch) -> None:
    """Many miners silent at once is vali's own view failing:
    `HippiusAutoFailoverHeld` says it once, not one Blocked per miner."""
    monkeypatch.setattr(settings, "VALI_FAILOVER_AUTO_MAX_DEAD_MINERS", 1)
    monkeypatch.setattr(sched, "launch_region_for_vm", lambda vm_id: "AU")
    _auto_vm()
    MinerIdentity.objects.create(
        miner_id="node-x",
        pubkey_hex="ab" * 32,
        platform_id="cd" * 64,
        last_seen_at=timezone.now() - timedelta(hours=1),
    )
    world.kill()
    clock.tick(AFTER + STEP)
    assert failover_auto.held(now=clock.now())
    text = failover_auto.report_metrics(now=clock.now()).render()
    assert "hippius_failover_auto_blocked{" not in text
    assert "hippius_failover_auto_held 1" in text


def test_a_vm_no_longer_auto_on_the_dead_miner_drops_its_skip(world, clock, monkeypatch) -> None:
    monkeypatch.setattr(sched, "launch_region_for_vm", lambda vm_id: "AU")
    vm = _auto_vm()
    second = _auto_vm("vm-2")
    world.kill()
    clock.tick(AFTER + STEP)
    assert set(failover_auto._skips) == {vm.vm_id, second.vm_id}
    BackupPolicy.objects.filter(vm=vm).update(failover_mode=FailoverMode.MANUAL)
    Vm.objects.filter(pk=second.pk).update(host="node-dst")  # moved by hand
    clock.tick(AFTER + 2 * STEP)
    assert failover_auto._skips == {}
    text = failover_auto.report_metrics(now=clock.now()).render()
    assert "hippius_failover_auto_skipped{" not in text


def test_turning_the_worker_off_drops_the_skips(world, clock, monkeypatch) -> None:
    monkeypatch.setattr(sched, "launch_region_for_vm", lambda vm_id: "AU")
    _auto_vm()
    world.kill()
    clock.tick(AFTER + STEP)
    assert failover_auto._skips
    monkeypatch.setattr(settings, "VALI_FAILOVER_AUTO_ENABLED", False)
    clock.tick(AFTER + 2 * STEP)
    assert failover_auto._skips == {} and failover_auto._skips_logged == set()
    text = failover_auto.report_metrics(now=clock.now()).render()
    assert "hippius_failover_auto_skipped{" not in text
    assert "hippius_failover_auto_blocked{" not in text


def test_a_started_failover_keeps_the_other_vms_skips(world, clock, monkeypatch) -> None:
    """One at a time per dead miner: the pass stops at the job it opens, and
    a VM after it keeps what its last look said — the gauge does not flap."""
    first = _auto_vm()
    second = _auto_vm("vm-2")
    monkeypatch.setattr(
        sched, "launch_region_for_vm", lambda vm_id: "AU" if vm_id == second.vm_id else "FR"
    )
    world.kill()
    assert clock.tick(AFTER) == 1
    MigrationJob.objects.filter(kind="failover").update(
        state=MigrationState.FAILED.value, reason="dest-failed", finished_at=clock.now()
    )
    clock.tick(AFTER + STEP)  # the first backs off: the pass reaches the second
    assert failover_auto._skips[second.vm_id] == (
        "node-src",
        "not-eligible:region-backups-not-local",
    )
    t = AFTER + failover_auto.RETRY_BACKOFF_S + 2 * STEP
    assert clock.tick(t) == 1  # the first again: the pass stops there
    assert [j.vm_id for j in _jobs()] == [first.pk, first.pk]
    assert failover_auto._skips == {
        second.vm_id: ("node-src", "not-eligible:region-backups-not-local")
    }


def test_backoff_giving_up_is_logged_after_the_retries(world, clock, monkeypatch) -> None:
    errors: list[str] = []
    _capture_errors(monkeypatch, errors)
    _auto_vm()
    world.kill()
    t = AFTER
    for _ in range(failover_auto.MAX_FAILED_ATTEMPTS):
        assert clock.tick(t) == 1
        MigrationJob.objects.filter(kind="failover").exclude(state="failed").update(
            state=MigrationState.FAILED.value, reason="dest-failed", finished_at=clock.now()
        )
        clock.tick(t + STEP)
        t += failover_auto.RETRY_BACKOFF_S + STEP
    reasons = [m.split("(")[1].split(")")[0] for m in errors if "skipped" in m]
    assert reasons == ["backoff-retry", "backoff-exhausted"]
    text = failover_auto.report_metrics(now=clock.now()).render()
    assert 'reason="backoff-exhausted"' in text


def test_a_miner_dead_for_less_than_the_auto_window_is_not_blocked(
    world, clock, monkeypatch
) -> None:
    monkeypatch.setattr(sched, "launch_region_for_vm", lambda vm_id: "AU")
    _auto_vm()
    world.kill()
    clock.tick(AFTER - 2 * STEP)
    assert FailoverDeadWatch.objects.exists()
    text = failover_auto.report_metrics(now=clock.now()).render()
    assert "hippius_failover_auto_blocked{" not in text


def test_a_vm_waiting_for_room_is_not_blocked(world, clock, monkeypatch) -> None:
    _no_room(monkeypatch)
    _auto_vm()
    world.kill()
    clock.tick(AFTER + STEP)
    assert AutoFailover.objects.filter(state=AutoFailoverState.PENDING_CAPACITY).exists()
    text = failover_auto.report_metrics(now=clock.now()).render()
    assert "hippius_failover_auto_blocked{" not in text


def test_a_waiting_vm_moved_off_the_dead_miner_by_hand_ends_its_wait(
    world, clock, monkeypatch
) -> None:
    """Still an auto VM, but no longer on the miner it waited to leave: the
    wait is over, not a NoCapacity page forever."""
    _no_room(monkeypatch)
    vm = _auto_vm()
    _auto_vm("vm-2")  # keeps node-src watched
    world.kill()
    clock.tick(AFTER + STEP)
    af = AutoFailover.objects.get(vm=vm)
    assert af.state == AutoFailoverState.PENDING_CAPACITY
    Vm.objects.filter(pk=vm.pk).update(host="node-dst")
    clock.tick(AFTER + 2 * STEP)
    af.refresh_from_db()
    assert af.state == AutoFailoverState.CANCELLED


# ── no failover peer: never "protected" when no miner could take it ──


def _status(vm: Vm) -> tuple[bool, str | None]:
    from apps.backup import service as backup_service

    return backup_service.failover_auto_status(BackupPolicy.objects.get(vm=vm))


@pytest.mark.parametrize(
    "lose_the_peer",
    [
        pytest.param(
            lambda mp: MinerIdentity.objects.filter(miner_id="node-dst").update(
                platform_id="22" * 8
            ),
            id="another-generation",
        ),
        pytest.param(
            lambda mp: MinerLocation.objects.filter(miner_id="node-dst").update(
                country_code="AU", last_verified_country_code="AU"
            ),
            id="another-region",
        ),
        pytest.param(
            lambda mp: mp.setattr(sched, "cordoned_node_ids", lambda: {"d" * 64: "disk"}),
            id="cordoned",
        ),
        pytest.param(
            lambda mp: MinerIdentity.objects.filter(miner_id="node-dst").update(
                status="quarantined"
            ),
            id="quarantined",
        ),
        pytest.param(
            lambda mp: MinerLocation.objects.filter(miner_id="node-dst").delete(),
            id="never-located",
        ),
    ],
)
def test_no_failover_peer_blocks_auto_failover(world, clock, monkeypatch, lose_the_peer) -> None:
    """The canary: a VM on the lone FR Genoa read as protected while no
    miner could ever take its failover."""
    vm = _auto_vm()
    assert _status(vm) == (True, None)
    lose_the_peer(monkeypatch)
    assert _status(vm) == (False, "no-failover-peer")
    world.kill()
    assert clock.tick(AFTER + STEP) == 0 and _jobs() == []
    assert failover_auto._skips[vm.vm_id] == ("node-src", "not-eligible:no-failover-peer")


def test_a_peer_with_no_room_right_now_is_still_a_peer(world, clock, monkeypatch) -> None:
    """Room is asked at failover time (pending_capacity), not here."""
    _no_room(monkeypatch)
    vm = _auto_vm()
    assert _status(vm) == (True, None)
    world.kill()
    clock.tick(AFTER + STEP)
    assert AutoFailover.objects.get(vm=vm).state == AutoFailoverState.PENDING_CAPACITY


def test_the_policy_view_relays_no_failover_peer(world, monkeypatch) -> None:
    from apps.backup import service as backup_service

    vm = _auto_vm()
    MinerIdentity.objects.filter(miner_id="node-dst").update(platform_id="22" * 8)
    view = backup_service.policy_view(BackupPolicy.objects.get(vm=vm))
    assert (view["failover_auto_eligible"], view["failover_auto_blocker"]) == (
        False,
        "no-failover-peer",
    )


def test_a_wait_keeps_its_id_while_the_peer_is_cordoned(world, clock, monkeypatch) -> None:
    """No peer right now is the room the wait already waits for: the id the
    backend relayed survives a cordon."""
    _no_room(monkeypatch)
    vm = _auto_vm()
    world.kill()
    clock.tick(AFTER + STEP)
    af = AutoFailover.objects.get(vm=vm)
    monkeypatch.setattr(sched, "cordoned_node_ids", lambda: {"d" * 64: "disk"})
    clock.tick(AFTER + 2 * STEP)
    af.refresh_from_db()
    assert af.state == AutoFailoverState.PENDING_CAPACITY
    assert failover_auto._skips[vm.vm_id][1] == "not-eligible:no-failover-peer"


def test_an_open_failover_quarantine_is_gauged_until_cleared(world, clock) -> None:
    """It silently made a region not failover-capable: now it shows."""
    from apps.orchestration.models import FailoverQuarantine

    _auto_vm()
    world.kill()
    assert clock.tick(AFTER) == 1
    [job] = _jobs()
    FailoverQuarantine.objects.create(miner_id="node-src", job=job)
    text = failover_auto.report_metrics(now=timezone.now() + timedelta(hours=3)).render()
    assert 'hippius_failover_quarantine_open{miner="node-src"}' in text
    line = next(
        ln for ln in text.splitlines() if ln.startswith("hippius_failover_quarantine_open{")
    )
    assert float(line.split()[-1]) >= 3 * 3600 - 5
    FailoverQuarantine.objects.update(cleared_at=timezone.now())
    text = failover_auto.report_metrics(now=timezone.now()).render()
    assert "hippius_failover_quarantine_open{" not in text


def test_an_operator_failover_may_cross_regions_recorded(world, monkeypatch) -> None:
    """The only destination is in DE, the VM in FR: refused in-region; the
    operator's override names DE, and the job and its authorization record
    it."""
    from apps.orchestration.service import CrossRegion
    from apps.orchestration.tests.factories import make_service_client

    monkeypatch.setattr(settings, "VALI_FAILOVER_MANUAL_ENABLED", True)
    monkeypatch.setattr(sched, "region_by_node", lambda **kw: {"d" * 64: "DE"})
    vm = _auto_vm()
    world.kill()
    with pytest.raises(restore.RestoreError) as exc:
        restore.start_failover(vm=vm, request_id="op-1", decided_by=make_service_client())
    assert exc.value.code == "no-eligible-miner"
    job, created = restore.start_failover(
        vm=vm,
        request_id="op-2",
        decided_by=make_service_client(),
        cross_region=CrossRegion("DE", "FR has no room for weeks", "julien"),
    )
    assert created and job.dest_node_id == "node-dst"
    assert (job.region, job.cross_region_override, job.cross_region_from) == ("DE", True, "FR")
    assert job.authorization.evidence["cross_region"] == {
        "from": "FR",
        "to": "DE",
        "reason": "FR has no room for weeks",
        "operator": "julien",
    }
    assert restore.serialize(job)["cross_region"]["to"] == "DE"


def test_the_failover_api_takes_the_override(world, monkeypatch, root_client) -> None:
    monkeypatch.setattr(settings, "VALI_FAILOVER_MANUAL_ENABLED", True)
    monkeypatch.setattr(sched, "region_by_node", lambda **kw: {"d" * 64: "DE"})
    vm = _auto_vm()
    world.kill()
    url = f"/v1/vm/{vm.vm_id}/failover"
    resp = root_client.post(url, {"request_id": "op-1"}, format="json")
    assert resp.status_code == 409 and resp.json()["error"] == "no-eligible-miner"
    body = {"request_id": "op-2", "allow_cross_region": True, "region": "DE", "reason": "evac"}
    resp = root_client.post(url, body, format="json")
    assert resp.status_code == 400, "the deciding operator is required"
    resp = root_client.post(url, {**body, "operator": "julien"}, format="json")
    assert resp.status_code == 202, resp.content
    assert resp.json()["cross_region"] == {
        "from": "FR",
        "to": "DE",
        "reason": "evac",
        "operator": "julien",
    }
