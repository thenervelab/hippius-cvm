"""Restore points: which runs can be restored, how long it takes, and the
chain a restore of one is handed."""

from __future__ import annotations

import secrets
from datetime import timedelta

import pytest
from django.utils import timezone

from apps.backup import service
from apps.backup.models import BackupChain, BackupKind, BackupPolicy, BackupRun, ChainState
from apps.backup.models import RunStatus as RS
from apps.orchestration.models import MigrationJob, MigrationState
from apps.orchestration.tests.factories import make_service_client

from .conftest import FakeMiner, make_vm
from .test_service import GIB, HOUR, MIB, RID, Clock, _full_done, _incremental_done, _policy, _tick

pytestmark = pytest.mark.django_db

CUR = service.PointClass.CURRENT_BOOT
ROLL = service.PointClass.ROLLBACK
NA = service.PointClass.UNAVAILABLE


@pytest.fixture
def clock() -> Clock:
    return Clock()


def _classes(vm) -> list[str]:
    return [
        service.classify_run(vm, r).klass
        for r in BackupRun.objects.filter(vm=vm).order_by("created_at")
    ]


def test_every_done_run_of_the_current_boot_is_restorable(
    clock: Clock, fake_miner: FakeMiner
) -> None:
    vm = make_vm()
    _policy(vm)
    full = _full_done(clock, fake_miner)
    inc1 = _incremental_done(clock, fake_miner)
    inc2 = _incremental_done(clock, fake_miner)
    assert _classes(vm) == [CUR, CUR, CUR]
    # Each point applies the full and every incremental up to itself.
    assert service.classify_run(vm, inc1).runs == (full, inc1)
    assert service.classify_run(vm, full).runs == (full,)
    assert service.classify_run(vm, inc2).restorable


def test_a_reboot_turns_the_earlier_points_into_rollbacks(
    clock: Clock, fake_miner: FakeMiner
) -> None:
    vm = make_vm()
    _policy(vm)
    _full_done(clock, fake_miner)
    _incremental_done(clock, fake_miner)
    BackupPolicy.objects.filter(vm=vm).update(observed_boot_counter=4)
    assert _classes(vm) == [ROLL, ROLL]
    assert not any(service.classify_run(vm, r).restorable for r in BackupRun.objects.all())


def test_a_completed_move_turns_the_earlier_points_into_rollbacks(
    clock: Clock, fake_miner: FakeMiner
) -> None:
    """A migration / restore boots the guest anew even before the host-read
    counter catches up."""
    vm = make_vm()
    _policy(vm)
    _full_done(clock, fake_miner)
    MigrationJob.objects.create(
        job_id=secrets.token_hex(16),
        vm=vm,
        source_node_id="miner-a",
        dest_node_id="miner-b",
        source_gen=1,
        new_gen=2,
        state=MigrationState.DONE.value,
        phase_started_at=timezone.now(),
        finished_at=timezone.now() + timedelta(seconds=1),
        decided_by=make_service_client(),
    )
    assert _classes(vm) == [ROLL]
    assert service.restore_point(vm) is None


def test_a_failed_run_is_unavailable_and_the_chain_still_serves(
    clock: Clock, fake_miner: FakeMiner
) -> None:
    vm = make_vm()
    _policy(vm)
    _full_done(clock, fake_miner)
    clock.advance(HOUR)
    _tick(clock)
    fake_miner.finish(status="failed", reason="upload-failed")
    _tick(clock)
    _incremental_done(clock, fake_miner, after=900)
    assert _classes(vm) == [CUR, NA, CUR]


def test_a_broken_link_makes_the_rest_of_the_chain_unavailable(
    clock: Clock, fake_miner: FakeMiner
) -> None:
    vm = make_vm()
    _policy(vm)
    _full_done(clock, fake_miner)
    inc1 = _incremental_done(clock, fake_miner)
    _incremental_done(clock, fake_miner)
    BackupRun.objects.filter(pk=inc1.pk).update(parent_run_id="0" * 32)
    assert _classes(vm) == [CUR, NA, NA]


def test_a_failed_or_pruned_chain_holds_no_point(clock: Clock, fake_miner: FakeMiner) -> None:
    vm = make_vm()
    _policy(vm)
    full = _full_done(clock, fake_miner)
    for state in (ChainState.FAILED, ChainState.PRUNED):
        BackupChain.objects.filter(pk=full.chain_id).update(state=state)
        assert _classes(vm) == [NA]


def test_the_ttl_covers_a_slow_download_within_bounds() -> None:
    assert service.restore_ttl_s(0) == 3600
    assert service.restore_ttl_s(40 * GIB) == max(3600, -(-40 * GIB // (5 * 10**6)))
    assert service.restore_ttl_s(10**15) == 12 * 3600


def test_the_eta_uses_the_destinations_measured_throughput(
    clock: Clock, fake_miner: FakeMiner
) -> None:
    vm = make_vm()
    _policy(vm)
    full = _full_done(clock, fake_miner)
    assert service.dest_throughput_bps("never-backed-up") == 100 * 10**6
    BackupRun.objects.filter(pk=full.pk).update(miner_duration_s=400)
    bps = service.dest_throughput_bps("miner-a")
    assert bps == (40 * GIB) // 400
    point = service.classify_run(vm, full)
    assert service.restore_eta_s(point.runs, throughput_bps=bps) == -(
        -(40 * GIB + MIB) // bps
    )


def test_backups_list_classifies_every_run(clock: Clock, fake_miner: FakeMiner) -> None:
    vm = make_vm()
    _policy(vm)
    _full_done(clock, fake_miner)
    _incremental_done(clock, fake_miner)
    view = service.backups_view(vm)
    points = [r["point"] for c in view["chains"] for r in c["runs"]]
    assert [p["class"] for p in points] == [CUR, CUR]
    assert all(p["restorable"] and p["eta_s"] > 0 for p in points)
    BackupPolicy.objects.filter(vm=vm).update(observed_boot_counter=9)
    points = [r["point"] for c in service.backups_view(vm)["chains"] for r in c["runs"]]
    assert [(p["class"], p["restorable"]) for p in points] == [(ROLL, False), (ROLL, False)]


def test_a_restore_chain_stops_at_the_chosen_run(clock: Clock, fake_miner: FakeMiner) -> None:
    vm = make_vm()
    _policy(vm)
    _full_done(clock, fake_miner)
    inc1 = _incremental_done(clock, fake_miner)
    _incremental_done(clock, fake_miner)
    chain = service.restore_chain(vm, run_id=inc1.run_id, restore_id=RID)
    assert len(chain["incrementals"]) == 1
    assert "0001.inc.qcow2" in chain["incrementals"][0]["url"]
    assert "0001.state" in chain["state"]["url"]


def test_a_restore_chain_refuses_a_rollback_point(clock: Clock, fake_miner: FakeMiner) -> None:
    vm = make_vm()
    _policy(vm)
    full = _full_done(clock, fake_miner)
    BackupPolicy.objects.filter(vm=vm).update(observed_boot_counter=4)
    with pytest.raises(service.BackupError) as exc:
        service.restore_chain(vm, run_id=full.run_id, restore_id=RID)
    assert exc.value.code == "rollback-unsupported"


def test_a_piece_whose_parts_do_not_tile_is_fetched_whole(
    clock: Clock, fake_miner: FakeMiner
) -> None:
    vm = make_vm()
    _policy(vm)
    full = _full_done(clock, fake_miner)
    BackupRun.objects.filter(pk=full.pk).update(part_sha256_hex=["b" * 64])
    chain = service.restore_chain(vm, run_id=full.run_id, restore_id=RID)
    assert (chain["full"]["part_size"], chain["full"]["part_sha256_hex"]) == (0, [])


def test_the_newest_restore_point_is_the_newest_current_boot_point(
    clock: Clock, fake_miner: FakeMiner
) -> None:
    vm = make_vm()
    _policy(vm)
    _full_done(clock, fake_miner)
    inc = _incremental_done(clock, fake_miner)
    point = service.restore_point(vm)
    assert point is not None and point.latest.pk == inc.pk
    assert [r.kind for r in point.runs] == [BackupKind.FULL, BackupKind.INCREMENTAL]
    BackupRun.objects.filter(pk=inc.pk).update(status=RS.FAILED)
    assert service.restore_point(vm).latest.kind == BackupKind.FULL
