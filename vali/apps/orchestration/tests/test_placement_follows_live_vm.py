"""A running VM always holds an active placement on the host it runs on.

The defect (found live 2026-09-24): three VMs on miner-b/3 were `active`
and running, but their ONLY placement was `failed / drain:miner-stale`.
The sequence:

  1. a host reboot made the miner's heartbeat stale;
  2. the §13 re-eval drained the VM's BOUND placement (`reeval_once`);
  3. reboot-recovery relaunched the VM on the SAME host — through
     `launch_on_miner`, which writes no placement — and nothing re-opened
     one.

Admission (`decision_inputs`, `host_resources_by_node`, feasibility)
counts only active placements, so from then on each host looked emptier
than it was by exactly those VMs' flavors, and could be over-booked.

Three fixes, each pinned below by the claim it makes:

  A. the drain HOLDS a placement whose VM is still live on that miner;
  B. a reboot-recovery relaunch re-binds the placement to its host;
  C. the tick's invariant sweep repairs any live VM that still breaks it
     (this is what heals the three rows already in production).
"""

from __future__ import annotations

from datetime import timedelta
from types import SimpleNamespace
from typing import Any

import pytest
from django.utils import timezone

from apps.lifecycle.models import Vm, VmState
from apps.miners.models import MinerIdentity
from apps.orchestration import service
from apps.orchestration.models import LaunchJob, LaunchJobState
from apps.scheduler import chain
from apps.scheduler import service as sched
from apps.scheduler.models import (
    ACTIVE_PLACEMENT_STATES,
    MinerCapacity,
    Placement,
    PlacementFailureSource,
    PlacementStatus,
)
from apps.scheduler.tests.factories import make_miner, make_snapshot
from apps.synthetic import checks

from .factories import make_migration_job, make_service_client, make_vm

pytestmark = pytest.mark.django_db

HOST = "cd" * 32  # miner-b's chain node_id
OTHER = "ef" * 32


@pytest.fixture(autouse=True)
def _miners() -> None:
    # Both hosts UP: a heartbeat just now.
    MinerIdentity.objects.create(
        miner_id="miner-b",
        pubkey_hex="11" * 32,
        platform_id="aa" * 64,
        chain_node_id=HOST,
        last_seen_at=timezone.now(),
    )
    MinerIdentity.objects.create(
        miner_id="miner-i",
        pubkey_hex="22" * 32,
        platform_id="bb" * 64,
        chain_node_id=OTHER,
        last_seen_at=timezone.now(),
    )
    # The trusted hardware anchor, so admission answers in real units.
    for nid in (HOST, OTHER):
        MinerCapacity.objects.create(
            miner_node_id=nid,
            status="active",
            capacity_slots=8,
            observed_epoch=10,
            data_epoch=10,
            refreshed_at=timezone.now(),
            total_memory_mb=125_000,
            total_cpus=24,
        )


def _host_goes_dark(miner_id: str = "miner-b", *, for_s: int = 3600) -> None:
    MinerIdentity.objects.filter(miner_id=miner_id).update(
        last_seen_at=timezone.now() - timedelta(seconds=for_s)
    )


def _running_vm(vm_id: str = "vm-1", *, host: str = "miner-b") -> Vm:
    return make_vm(vm_id, host=host)


def _placement(vm: Vm, node: str = HOST, **kw: Any) -> Placement:
    status = kw.pop("status", PlacementStatus.BOUND.value)
    now = timezone.now()
    return Placement.objects.create(
        vm=vm,
        vm_family="tenant-1",
        owner="user-1",
        resource_class=kw.pop("resource_class", "large"),
        miner_node_id=node,
        status=status,
        chain_epoch=10,
        bound_at=now,
        failed_at=now if status == PlacementStatus.FAILED.value else None,
        decided_by=make_service_client(),
        **kw,
    )


def _drained(vm: Vm) -> Placement:
    """The production row: the VM's only placement, drained on a stale
    heartbeat."""
    return _placement(
        vm,
        status=PlacementStatus.FAILED.value,
        reason="drain:miner-stale",
        failure_source=PlacementFailureSource.SCHEDULER_DRAIN.value,
    )


def _active(vm: Vm) -> list[Placement]:
    return list(Placement.objects.filter(vm=vm, status__in=ACTIVE_PLACEMENT_STATES))


def _committed(node: str = HOST) -> tuple[int, int | None]:
    """(slots counted, free RAM) admission sees on `node`."""
    _cap, load, _family = sched.decision_inputs("tenant-x")
    return load.get(node, 0), sched.host_resources_by_node()[node].free_memory_mb


def _stale_chain(monkeypatch: pytest.MonkeyPatch, *, status: str = "active") -> None:
    # Chain at epoch 10, the host's score frozen at 2 — `miner-stale`.
    snap = make_snapshot(10, [make_miner(HOST, status=status, data_epoch=2)])
    monkeypatch.setattr(chain, "read_miner_status", lambda: snap)


def _relaunch_accepted(monkeypatch: pytest.MonkeyPatch, vm: Vm) -> None:
    """A SUCCEEDED launch to rebuild from, and a miner that accepts."""
    from apps.orchestration.services import launch
    from apps.orchestration.services import vault_kv as vk

    LaunchJob.objects.create(
        job_id=f"succ-{vm.vm_id}",
        vm_id=vm.vm_id,
        tenant_id="tenant-1",
        flavor="large",
        spec_json={
            "tenant_id": "tenant-1",
            "user_id": "user-1",
            "vm_id": vm.vm_id,
            "lease_id": vm.lease_id,
            "s3_bucket": "b",
            "s3_key_prefix": "p",
            "luks_disk_sha256_hex": "a" * 64,
            "kernel_sha256_hex": "b" * 64,
            "initrd_sha256_hex": "c" * 64,
            "luks_header_sha256_hex": "d" * 64,
            "flavor": "large",
            "cmdline": "console=ttyS0",
        },
        userdata_vault_path=f"x/{vm.vm_id}/userdata",
        userdata_vault_version=1,
        kek_vault_path=f"x/{vm.vm_id}/luks-kek",
        state=LaunchJobState.SUCCEEDED.value,
        phase_started_at=timezone.now(),
        finished_at=timezone.now(),
        decided_by=make_service_client(),
    )
    monkeypatch.setattr(vk, "get_kv", lambda mount, path, version=None: b"user-data")
    monkeypatch.setattr(
        launch,
        "launch_on_miner",
        lambda spec, m, **_kw: SimpleNamespace(disposition=launch.ACCEPTED),
    )


# ─── A. the drain holds a live VM's placement ─────────────────────────


@pytest.mark.parametrize("status", ["active", "quarantined"])
def test_drain_holds_the_placement_of_a_vm_still_live_on_the_miner(
    monkeypatch: pytest.MonkeyPatch, status: str
) -> None:
    # Stale (a reboot) or quarantined (a graceful exit): either way the VM
    # is still running on the host and still holds its RAM/CPU there. The
    # quarantined case matters twice — graceful-exit enrols by BOUND
    # placement, so a drained row is a VM that never gets migrated off.
    vm = _running_vm()
    placement = _placement(vm)
    _stale_chain(monkeypatch, status=status)

    report = sched.reeval_once()

    placement.refresh_from_db()
    assert placement.status == PlacementStatus.BOUND.value
    assert (report.drained, report.held) == (0, 1)
    assert _committed()[0] == 1


def test_drain_still_frees_a_placement_whose_vm_is_not_on_that_miner(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # The hold is about WHERE the VM is, not a blanket exemption: a row on
    # a stale miner for a VM running elsewhere reserves nothing there.
    vm = _running_vm(host="miner-i")
    placement = _placement(vm, HOST)
    _stale_chain(monkeypatch)

    report = sched.reeval_once()

    placement.refresh_from_db()
    assert placement.status == PlacementStatus.FAILED.value
    assert placement.reason == "drain:miner-stale"
    assert (report.drained, report.held) == (1, 0)


def test_drain_still_frees_the_placement_on_a_dark_host(monkeypatch: pytest.MonkeyPatch) -> None:
    # No heartbeat: vali cannot tell the VM is still there, and the host
    # may never come back — holding would pin the VM to it forever.
    vm = _running_vm()
    placement = _placement(vm)
    _host_goes_dark()
    _stale_chain(monkeypatch)

    report = sched.reeval_once()

    placement.refresh_from_db()
    assert placement.status == PlacementStatus.FAILED.value
    assert (report.drained, report.held) == (1, 0)


def test_a_reboot_shorter_than_the_grace_drains_nothing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Dark for 5 min: past the 180 s liveness timeout (not dispatchable),
    # inside the 30 min hold grace. No drain ⇒ no circuit-breaker failure,
    # and no Bound→Failed→Bound churn once the heartbeat returns.
    vm = _running_vm()
    placement = _placement(vm)
    _host_goes_dark(for_s=300)
    _stale_chain(monkeypatch)

    report = sched.reeval_once()

    placement.refresh_from_db()
    assert placement.status == PlacementStatus.BOUND.value
    assert (report.drained, report.held) == (0, 1)
    assert sched.recent_failures_by_node().get(HOST, 0) == 0


def test_drain_never_holds_a_terminal_vm(monkeypatch: pytest.MonkeyPatch) -> None:
    vm = _running_vm()
    Vm.objects.filter(pk=vm.pk).update(state=VmState.DECOMMISSIONING.value)
    placement = _placement(vm)
    _stale_chain(monkeypatch)

    sched.reeval_once()

    placement.refresh_from_db()
    assert placement.reason == "drain:vm-terminal"


# ─── B. reboot-recovery re-binds ──────────────────────────────────────


def test_the_live_sequence_drain_then_relaunch_leaves_the_vm_counted(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # The exact production shape: the drain already happened (pre-fix),
    # then reboot-recovery relaunched on the SAME host.
    vm = _running_vm()
    _drained(vm)
    before_slots, before_free = _committed()
    assert before_slots == 0  # the defect: invisible to admission
    _relaunch_accepted(monkeypatch, vm)

    assert service._reboot_recovery_relaunch(vm, "miner-b") is True

    [row] = _active(vm)
    assert (row.miner_node_id, row.status, row.resource_class) == (
        HOST,
        PlacementStatus.BOUND.value,
        "large",
    )
    slots, free = _committed()
    assert slots == 1
    assert before_free is not None and free is not None and free < before_free


def test_relaunch_on_a_host_already_holding_the_placement_writes_nothing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    vm = _running_vm()
    _placement(vm)
    _relaunch_accepted(monkeypatch, vm)

    assert service._reboot_recovery_relaunch(vm, "miner-b") is True

    assert Placement.objects.filter(vm=vm).count() == 1


def test_a_refused_relaunch_re_binds_nothing(monkeypatch: pytest.MonkeyPatch) -> None:
    from apps.orchestration.services import launch

    vm = _running_vm()
    _drained(vm)
    _relaunch_accepted(monkeypatch, vm)
    monkeypatch.setattr(
        launch, "launch_on_miner", lambda spec, m, **_kw: SimpleNamespace(disposition="rejected")
    )

    assert service._reboot_recovery_relaunch(vm, "miner-b") is False
    assert _active(vm) == []


def test_rebind_from_a_stale_vm_snapshot_never_drags_the_placement_back() -> None:
    # The caller's `vm` says miner-b, but a §25 activation has since moved
    # `Vm.host` to miner-i.
    vm = _running_vm()
    _drained(vm)
    Vm.objects.filter(pk=vm.pk).update(host="miner-i")

    assert service.rebind_placement_to_host(vm, node_id=HOST, reason="t") is None
    assert _active(vm) == []


# ─── C. the invariant sweep ──────────────────────────────────────────


def test_sweep_repairs_a_running_vm_with_no_placement(monkeypatch: pytest.MonkeyPatch) -> None:
    vm = _running_vm()
    _drained(vm)
    errors: list[str] = []
    monkeypatch.setattr(service.log, "error", lambda msg, *a: errors.append(msg % a))

    assert service.sweep_live_vm_placements() == 1

    [row] = _active(vm)
    assert (row.miner_node_id, row.status, row.resource_class) == (
        HOST,
        PlacementStatus.BOUND.value,
        "large",
    )
    assert row.decided_by.name == "system:placement-reconciler"
    # ONE error per repair — each is a real under-count that existed.
    assert len(errors) == 1 and "NO active placement" in errors[0]
    # Idempotent: the next tick finds nothing to do.
    assert service.sweep_live_vm_placements() == 0
    assert Placement.objects.filter(vm=vm).count() == 2


def test_sweep_reports_but_never_moves_a_placement_bound_elsewhere() -> None:
    # `/fail` → re-place → `/bind` binds the destination before `Vm.host`
    # follows; the sweep cannot prove which host won, so it only reports.
    vm = _running_vm()
    old = _placement(vm, OTHER)

    assert [d.vm.vm_id for d in sched.live_vm_placement_drift()] == [vm.vm_id]
    assert service.sweep_live_vm_placements() == 0

    old.refresh_from_db()
    assert old.status == PlacementStatus.BOUND.value


def test_rebind_never_touches_an_existing_placement_elsewhere() -> None:
    # A re-placement decided while the sweep ran: the Pending destination
    # row must survive, whatever the sweep saw a moment earlier.
    vm = _running_vm()
    _drained(vm)
    pending = _placement(vm, OTHER, status=PlacementStatus.PENDING.value)

    assert service.rebind_placement_to_host(vm, node_id=HOST, reason="t") is None
    pending.refresh_from_db()
    assert pending.status == PlacementStatus.PENDING.value


def test_open_placement_loses_to_a_row_inserted_after_the_caller_looked() -> None:
    # The race boundary is the unique index, not the caller's read.
    vm = _running_vm()
    _drained(vm)
    winner = _placement(vm, OTHER, status=PlacementStatus.PENDING.value)

    assert (
        sched.open_placement_on_node(
            vm, node_id=HOST, decided_by=make_service_client(), reason="t"
        )
        is None
    )
    assert [p.id for p in _active(vm)] == [winner.id]


def test_a_pending_re_placement_elsewhere_is_not_drift() -> None:
    vm = _running_vm()
    _placement(vm, OTHER, status=PlacementStatus.PENDING.value)

    assert sched.live_vm_placement_drift() == []


def test_sweep_waits_for_a_dark_host_and_re_binds_when_it_returns() -> None:
    # The reboot, end to end: drained while dark, nothing resurrected
    # while dark, re-bound on the first tick after the heartbeat returns.
    vm = _running_vm()
    _drained(vm)
    _host_goes_dark()

    assert service.sweep_live_vm_placements() == 0
    assert _active(vm) == []

    MinerIdentity.objects.filter(miner_id="miner-b").update(last_seen_at=timezone.now())

    assert service.sweep_live_vm_placements() == 1
    assert [p.miner_node_id for p in _active(vm)] == [HOST]


def test_sweep_leaves_a_correctly_placed_vm_alone() -> None:
    vm = _running_vm()
    _placement(vm, status=PlacementStatus.PENDING.value)

    assert service.sweep_live_vm_placements() == 0
    assert Placement.objects.filter(vm=vm).count() == 1


def test_sweep_covers_a_migrating_vm_still_on_its_source() -> None:
    # `migrating` still occupies the source until activation; with no job
    # in flight (a stranded row) nothing else would put it back on books.
    vm = _running_vm()
    Vm.objects.filter(pk=vm.pk).update(
        state=VmState.MIGRATING.value, migration_dest="miner-i", new_generation=6
    )
    _drained(vm)

    assert service.sweep_live_vm_placements() == 1


def test_sweep_skips_a_vm_whose_migration_is_in_flight() -> None:
    # The migration owns the placement for its duration and moves it at
    # activation — a concurrent re-bind would race that hand-over.
    vm = _running_vm()
    _drained(vm)
    make_migration_job(vm)

    assert service.sweep_live_vm_placements() == 0
    assert _active(vm) == []


def test_sweep_skips_a_vm_whose_launch_is_in_flight() -> None:
    # The launch path owns the Pending→Bound (or →Failed) transition.
    vm = _running_vm()
    _drained(vm)
    LaunchJob.objects.create(
        job_id="running-1",
        vm_id=vm.vm_id,
        tenant_id="tenant-1",
        flavor="large",
        spec_json={},
        userdata_vault_path=f"x/{vm.vm_id}/userdata",
        userdata_vault_version=1,
        kek_vault_path=f"x/{vm.vm_id}/luks-kek",
        state=LaunchJobState.RUNNING.value,
        phase_started_at=timezone.now(),
        decided_by=make_service_client(),
    )

    assert service.sweep_live_vm_placements() == 0
    assert _active(vm) == []


@pytest.mark.parametrize(
    "state", [VmState.DESTROYED.value, VmState.DECOMMISSIONING.value]
)
def test_sweep_never_places_a_vm_that_is_not_live(state: str) -> None:
    vm = _running_vm()
    Vm.objects.filter(pk=vm.pk).update(state=state)
    _drained(vm)

    assert service.sweep_live_vm_placements() == 0
    assert _active(vm) == []


def test_sweep_does_not_guess_an_unnameable_host() -> None:
    # A host with no registered chain node_id: refuse, never invent one.
    vm = _running_vm(host="miner-unregistered")
    _drained(vm)

    assert service.sweep_live_vm_placements() == 0
    assert _active(vm) == []


def test_tick_runs_the_sweep_and_reports_it(fx: Any) -> None:
    vm = _running_vm()
    _drained(vm)

    report = service.tick_once()

    assert report.placements_repaired == 1
    assert [p.miner_node_id for p in _active(vm)] == [HOST]


def test_drain_and_sweep_do_not_fight(monkeypatch: pytest.MonkeyPatch) -> None:
    # A stale host with a live VM: the drain holds, the sweep has nothing
    # to repair — no churn of placement rows every cycle.
    vm = _running_vm()
    _placement(vm)
    _stale_chain(monkeypatch)

    for _ in range(3):
        sched.reeval_once()
        assert service.sweep_live_vm_placements() == 0
    assert Placement.objects.filter(vm=vm).count() == 1


# ─── the synthetic monitor sees it ───────────────────────────────────


def test_light_check_fails_on_an_unplaced_live_vm_and_clears_after_repair() -> None:
    vm = _running_vm()
    _drained(vm)

    bad = checks.check_live_vms_placed()
    assert not bad.ok
    assert bad.gauges["hippius_synthetic_unplaced_live_vms"] == 1.0
    assert vm.vm_id in bad.detail

    service.sweep_live_vm_placements()

    good = checks.check_live_vms_placed()
    assert good.ok
    assert good.gauges["hippius_synthetic_unplaced_live_vms"] == 0.0
    assert checks.check_live_vms_placed in checks.LIGHT_CHECKS


# ─── D. a Pending placement a crash left behind ──────────────────────
#
# `launch_on_miner` stamps `Vm.host` on the accepted dispatch; only then
# does its caller bind the placement. A vali crash in between leaves the
# VM running with its placement `Pending` for ever — counted by
# admission, missed by every `Bound` consumer.


def _old_pending(vm: Vm, node: str = HOST, *, age_s: int = 3 * 3600) -> Placement:
    row = _placement(vm, node, status=PlacementStatus.PENDING.value)
    Placement.objects.filter(pk=row.pk).update(
        bound_at=None, decided_at=timezone.now() - timedelta(seconds=age_s)
    )
    row.refresh_from_db()
    return row


def test_a_stale_pending_on_the_host_the_vm_runs_on_is_promoted(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    vm = _running_vm()
    row = _old_pending(vm)
    errors: list[str] = []
    monkeypatch.setattr(service.log, "error", lambda msg, *a: errors.append(msg % a))

    assert service.sweep_stale_pending_placements() == (1, 0)

    row.refresh_from_db()
    assert row.status == PlacementStatus.BOUND.value
    assert row.bound_at is not None
    assert len(errors) == 1 and "promoted to Bound" in errors[0]
    # Idempotent, and nothing else to repair.
    assert service.sweep_stale_pending_placements() == (0, 0)
    assert service.sweep_live_vm_placements() == 0


def test_a_young_pending_is_a_launch_in_flight_and_is_never_touched() -> None:
    vm = _running_vm()
    row = _old_pending(vm, age_s=600)
    Vm.objects.filter(pk=vm.pk).update(host="miner-i")  # would be a cancel

    assert service.sweep_stale_pending_placements() == (0, 0)
    row.refresh_from_db()
    assert row.status == PlacementStatus.PENDING.value


def test_a_stale_pending_on_a_dark_host_waits() -> None:
    vm = _running_vm()
    row = _old_pending(vm)
    _host_goes_dark()

    assert service.sweep_stale_pending_placements() == (0, 0)
    row.refresh_from_db()
    assert row.status == PlacementStatus.PENDING.value


def test_a_stale_pending_for_a_vm_on_another_host_is_cancelled_then_rebound() -> None:
    # The same tick then re-binds the VM on the host it really runs on.
    vm = _running_vm(host="miner-i")
    row = _old_pending(vm)

    report = service.tick_once()

    row.refresh_from_db()
    assert row.status == PlacementStatus.FAILED.value
    assert row.reason == "released:stale-pending:vm-on-other-host"
    assert row.failure_source == PlacementFailureSource.RELEASE.value
    assert (report.pending_promoted, report.pending_cancelled) == (0, 1)
    assert report.placements_repaired == 1
    assert [p.miner_node_id for p in _active(vm)] == [OTHER]


def test_a_stale_pending_for_a_destroyed_vm_is_cancelled() -> None:
    vm = _running_vm()
    Vm.objects.filter(pk=vm.pk).update(state=VmState.DESTROYED.value)
    row = _old_pending(vm)

    assert service.sweep_stale_pending_placements() == (0, 1)
    row.refresh_from_db()
    assert row.reason == "released:stale-pending:vm-destroyed"
    # Not a refusal: never feeds the circuit breaker's view of the node.
    assert row.failure_source == PlacementFailureSource.RELEASE.value


@pytest.mark.parametrize(
    ("state", "host"),
    [
        # Its guest may still run until the §24 stop; the destroy releases.
        (VmState.DECOMMISSIONING.value, "miner-b"),
        # No accepted dispatch on record — but a dispatch that timed out
        # may still have booted it somewhere vali cannot name.
        (VmState.ACTIVE.value, ""),
    ],
)
def test_a_stale_pending_vali_cannot_place_is_left_alone(state: str, host: str) -> None:
    vm = _running_vm()
    Vm.objects.filter(pk=vm.pk).update(state=state, host=host)
    row = _old_pending(vm, OTHER)

    assert service.sweep_stale_pending_placements() == (0, 0)
    row.refresh_from_db()
    assert row.status == PlacementStatus.PENDING.value


def _open_launch_job(vm: Vm) -> None:
    LaunchJob.objects.create(
        job_id=f"open-{vm.vm_id}",
        vm_id=vm.vm_id,
        tenant_id="tenant-1",
        flavor="large",
        spec_json={},
        userdata_vault_path=f"x/{vm.vm_id}/userdata",
        userdata_vault_version=1,
        kek_vault_path=f"x/{vm.vm_id}/luks-kek",
        state=LaunchJobState.RUNNING.value,
        phase_started_at=timezone.now(),
        decided_by=make_service_client(),
    )


def test_an_open_launch_job_blocks_a_cancel() -> None:
    # A same-miner retry can run the whole choreography again on the same
    # Pending row; only the job knows it is still trying.
    vm = _running_vm(host="miner-i")
    row = _old_pending(vm)
    _open_launch_job(vm)

    assert service.sweep_stale_pending_placements() == (0, 0)
    row.refresh_from_db()
    assert row.status == PlacementStatus.PENDING.value


def test_an_open_launch_job_does_not_block_a_promote() -> None:
    # THE crash case: the launch tick died after the accepted dispatch
    # stamped `Vm.host`, so its job stays `running` for ever.
    vm = _running_vm()
    row = _old_pending(vm)
    _open_launch_job(vm)

    assert service.sweep_stale_pending_placements() == (1, 0)
    row.refresh_from_db()
    assert row.status == PlacementStatus.BOUND.value


def test_a_stale_pending_waits_while_the_vms_other_host_is_dark() -> None:
    # Cancelling here would leave the VM with no placement at all: the
    # live-VM sweep cannot re-bind it on a host it cannot see.
    vm = _running_vm(host="miner-i")
    row = _old_pending(vm)
    _host_goes_dark("miner-i")

    assert service.sweep_stale_pending_placements() == (0, 0)
    row.refresh_from_db()
    assert row.status == PlacementStatus.PENDING.value


def test_a_stale_pending_whose_host_has_no_chain_identity_waits() -> None:
    vm = _running_vm(host="miner-unregistered")
    row = _old_pending(vm)

    assert service.sweep_stale_pending_placements() == (0, 0)
    row.refresh_from_db()
    assert row.status == PlacementStatus.PENDING.value


def test_the_launch_binding_it_first_wins(monkeypatch: pytest.MonkeyPatch) -> None:
    # The verdict was taken, then the launch's own `/bind` landed before
    # the sweep's locked re-check: the CAS on status=pending must lose.
    vm = _running_vm(host="miner-i")
    row = _old_pending(vm)
    real = sched.stale_pending_verdicts
    verdicts = real()
    assert [v.verdict for v in verdicts] == [sched.PENDING_CANCEL]
    Placement.objects.filter(pk=row.pk).update(
        status=PlacementStatus.BOUND.value, bound_at=timezone.now(), version=row.version + 1
    )
    monkeypatch.setattr(
        sched,
        "stale_pending_verdicts",
        lambda placements=None: verdicts if placements is None else real(placements),
    )

    assert service.sweep_stale_pending_placements() == (0, 0)
    row.refresh_from_db()
    assert row.status == PlacementStatus.BOUND.value


def test_light_check_fails_while_a_stale_pending_is_unresolved() -> None:
    vm = _running_vm()
    _old_pending(vm)

    bad = checks.check_live_vms_placed()
    assert not bad.ok
    assert bad.gauges["hippius_synthetic_stale_pending_placements"] == 1.0

    service.sweep_stale_pending_placements()

    assert checks.check_live_vms_placed().ok
