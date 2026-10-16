"""External-miner approval (`apps.scheduler.approval`).

A miner first seen while `VALI_MINER_APPROVAL_REQUIRED` is on is PENDING:
it is folded into the cordon gate (no new work, nothing else changes)
until an operator approves it, which also sets its host-size anchor to
min(declared, heartbeat-measured). Off (the default) is today's behaviour.
"""

from __future__ import annotations

import json
from datetime import timedelta
from io import StringIO

import pytest
from django.core.management import CommandError, call_command
from django.db import connection
from django.db.migrations.executor import MigrationExecutor
from django.utils import timezone

from apps.scheduler import approval, service
from apps.scheduler.models import MinerCapacity, MinerCapacityAudit, PlacementStatus
from apps.scheduler.placement import PlacementError, decide_placement

from .factories import make_miner, make_placement, make_snapshot, make_vm, node_id

pytestmark = pytest.mark.django_db()


def _row(seed: int, **over: object) -> MinerCapacity:
    now = timezone.now()
    fields: dict[str, object] = dict(
        miner_node_id=node_id(seed),
        status="active",
        capacity_slots=8,
        observed_epoch=10,
        data_epoch=10,
        refreshed_at=now,
        # A fresh v4 heartbeat: 60-thread budget, 250 GiB free, 4 TiB data fs.
        declared_cpu_budget=60,
        declared_at=now,
        reported_memory_available_mib=250_000,
        reported_at=now,
        reported_data_disk_total_gb=4000,
        disk_reported_at=now,
    )
    fields.update(over)
    return MinerCapacity.objects.create(**fields)


def _approve(seed: int, **over: object) -> approval.ApprovalResult:
    kw: dict[str, object] = dict(
        cpus=64, memory_mb=256_000, disk_gb=3500, approver="ops@x", reason="onboarding"
    )
    kw.update(over)
    return approval.approve_miner(node_id(seed), **kw)  # type: ignore[arg-type]


# ─── the switch and the gate ─────────────────────────────────────────


def test_off_by_default_a_pending_row_is_not_held(settings) -> None:
    assert settings.VALI_MINER_APPROVAL_REQUIRED is False
    _row(1)
    assert approval.pending_approval_node_ids() == {}
    assert service.cordoned_node_ids() == {}


def test_on_a_pending_row_is_cordoned_with_its_reason(settings) -> None:
    settings.VALI_MINER_APPROVAL_REQUIRED = True
    _row(1)
    _row(2, approved_at=timezone.now(), approved_by="grandfathered")
    assert service.cordoned_node_ids() == {node_id(1): approval.PENDING_APPROVAL_REASON}
    assert node_id(1) in service.hard_gated_node_ids()
    assert node_id(2) not in service.hard_gated_node_ids()


def test_an_operator_cordon_keeps_its_own_reason(settings) -> None:
    settings.VALI_MINER_APPROVAL_REQUIRED = True
    _row(1, cordoned_at=timezone.now(), cordon_reason="disk")
    assert service.cordoned_node_ids() == {node_id(1): "disk"}


def test_a_pending_miner_is_never_placed_on(settings) -> None:
    settings.VALI_MINER_APPROVAL_REQUIRED = True
    _row(1)
    _row(2, approved_at=timezone.now())
    snap = make_snapshot(10, [make_miner(1), make_miner(2)])
    kw = dict(
        snapshot=snap,
        capacity_by_node={m.node_id: 8 for m in snap.miners},
        load_by_node={},
        family_load_by_node={},
        max_epoch_lag=2,
    )
    assert decide_placement(**kw, cordoned=service.cordoned_node_ids()) == node_id(2)
    MinerCapacity.objects.filter(miner_node_id=node_id(2)).update(approved_at=None)
    with pytest.raises(PlacementError) as exc:
        decide_placement(**kw, cordoned=service.cordoned_node_ids())
    assert exc.value.category == "no-eligible-miner"


def test_uncordon_does_not_approve(settings) -> None:
    settings.VALI_MINER_APPROVAL_REQUIRED = True
    _row(1, cordoned_at=timezone.now(), cordon_reason="x")
    MinerCapacity.objects.filter(miner_node_id=node_id(1)).update(cordoned_at=None)
    assert service.cordoned_node_ids() == {node_id(1): approval.PENDING_APPROVAL_REASON}


# ─── first sight ─────────────────────────────────────────────────────


def test_a_new_row_is_approved_on_sight_while_off() -> None:
    service.refresh_miner_capacity(make_snapshot(10, [make_miner(1)]))
    row = MinerCapacity.objects.get(miner_node_id=node_id(1))
    assert row.approved_at is not None
    assert row.approved_by == approval.AUTO_APPROVER


def test_a_new_row_starts_pending_while_on(settings) -> None:
    settings.VALI_MINER_APPROVAL_REQUIRED = True
    service.refresh_miner_capacity(make_snapshot(10, [make_miner(1)]))
    row = MinerCapacity.objects.get(miner_node_id=node_id(1))
    assert row.approved_at is None
    assert row.approved_by == ""


def test_a_refresh_never_touches_an_existing_approval(settings) -> None:
    settings.VALI_MINER_APPROVAL_REQUIRED = True
    _row(1)
    settings.VALI_MINER_APPROVAL_REQUIRED = False
    service.refresh_miner_capacity(make_snapshot(10, [make_miner(1)]))
    assert MinerCapacity.objects.get(miner_node_id=node_id(1)).approved_at is None


# ─── the approve step ────────────────────────────────────────────────


def test_approve_anchors_on_the_min_of_declared_and_measured() -> None:
    _row(1)
    result = _approve(1)
    row = MinerCapacity.objects.get(miner_node_id=node_id(1))
    # cpus: declared 64 vs measured 60 → 60. memory: 256000 vs 250000 →
    # 250000. disk: 3500 vs 4000 → 3500.
    assert (row.total_cpus, row.total_memory_mb, row.total_disk_gb) == (60, 250_000, 3500)
    assert result.binding == ("cpus:measured", "memory:measured", "disk:declared")
    assert row.approved_at is not None
    assert row.approved_by == "op:ops@x"
    assert row.trust_class == "earned"  # left as is


def test_approve_is_audited_field_by_field() -> None:
    _row(1)
    _approve(1, trust_class="operator")
    audits = {
        a.field: a
        for a in MinerCapacityAudit.objects.filter(miner_node_id=node_id(1))
    }
    assert set(audits) == {
        "total_cpus",
        "total_memory_mb",
        "total_disk_gb",
        "trust_class",
        "approved_at",
        "approved_by",
    }
    assert {a.actor for a in audits.values()} == {"op:ops@x"}
    assert {a.reason for a in audits.values()} == {"onboarding"}
    assert audits["approved_by"].after == "op:ops@x"


def test_an_approved_miner_is_released_from_the_gate(settings) -> None:
    settings.VALI_MINER_APPROVAL_REQUIRED = True
    _row(1)
    assert node_id(1) in service.cordoned_node_ids()
    _approve(1)
    assert service.cordoned_node_ids() == {}


def test_the_heartbeat_can_never_raise_the_declared_figure() -> None:
    _row(1, declared_cpu_budget=500, reported_memory_available_mib=9_000_000)
    _approve(1, disk_gb=None)
    row = MinerCapacity.objects.get(miner_node_id=node_id(1))
    assert (row.total_cpus, row.total_memory_mb, row.total_disk_gb) == (64, 256_000, 4000)


def test_no_disk_figure_on_either_side_leaves_the_disk_anchor() -> None:
    _row(1, reported_data_disk_total_gb=None, disk_reported_at=None)
    result = _approve(1, disk_gb=None)
    assert MinerCapacity.objects.get(miner_node_id=node_id(1)).total_disk_gb is None
    assert result.binding[2] == "disk:none"


def test_an_existing_disk_anchor_is_never_raised_by_the_heartbeat() -> None:
    _row(1, total_disk_gb=1000)
    result = _approve(1, disk_gb=None)
    assert MinerCapacity.objects.get(miner_node_id=node_id(1)).total_disk_gb == 1000
    assert result.binding[2] == "disk:declared"


def test_a_stale_heartbeat_is_refused_and_nothing_is_written() -> None:
    old = timezone.now() - timedelta(hours=1)
    _row(1, declared_at=old)
    with pytest.raises(approval.ApprovalRefused) as exc:
        _approve(1)
    assert exc.value.code == "not-measured"
    row = MinerCapacity.objects.get(miner_node_id=node_id(1))
    assert row.approved_at is None and row.total_cpus is None
    assert not MinerCapacityAudit.objects.exists()


def test_a_stale_disk_figure_is_dropped_not_refused() -> None:
    _row(1, disk_reported_at=timezone.now() - timedelta(hours=1))
    _approve(1, disk_gb=None)
    assert MinerCapacity.objects.get(miner_node_id=node_id(1)).total_disk_gb is None


@pytest.mark.parametrize(
    ("over", "code"),
    [
        ({"cpus": 0}, "invalid"),
        ({"cpus": True}, "invalid"),
        ({"memory_mb": 10}, "invalid"),
        ({"disk_gb": 0}, "invalid"),
        ({"trust_class": "root"}, "invalid"),
        ({"approver": " "}, "invalid"),
        ({"reason": ""}, "invalid"),
    ],
)
def test_bad_input_is_refused(over: dict[str, object], code: str) -> None:
    _row(1)
    with pytest.raises(approval.ApprovalRefused) as exc:
        _approve(1, **over)
    assert exc.value.code == code
    assert MinerCapacity.objects.get(miner_node_id=node_id(1)).approved_at is None


def test_unknown_and_already_approved_are_refused() -> None:
    with pytest.raises(approval.ApprovalRefused) as exc:
        _approve(1)
    assert exc.value.code == "not-found"
    _row(1, approved_at=timezone.now(), approved_by="grandfathered")
    with pytest.raises(approval.ApprovalRefused) as exc:
        _approve(1)
    assert exc.value.code == "already-approved"
    assert MinerCapacity.objects.get(miner_node_id=node_id(1)).total_cpus is None


def test_an_anchor_below_what_vali_placed_is_refused() -> None:
    _row(1, declared_cpu_budget=2)
    make_placement(make_vm(), miner_node_id=node_id(1), status=PlacementStatus.BOUND)
    make_placement(
        make_vm("vm-2", "lease-2"), miner_node_id=node_id(1), status=PlacementStatus.BOUND
    )
    with pytest.raises(approval.ApprovalRefused) as exc:
        _approve(1, cpus=1)
    assert exc.value.code == "below-committed"


def test_a_dry_run_writes_nothing() -> None:
    _row(1)
    result = _approve(1, dry_run=True)
    assert result.dry_run and result.total_cpus == 60
    row = MinerCapacity.objects.get(miner_node_id=node_id(1))
    assert row.approved_at is None and row.total_cpus is None
    assert not MinerCapacityAudit.objects.exists()


# ─── the command ─────────────────────────────────────────────────────


def _cmd(*args: str) -> str:
    out = StringIO()
    call_command("vali_approve_miner", *args, stdout=out)
    return out.getvalue()


def test_the_command_lists_approves_and_shows() -> None:
    _row(1)
    _row(2, approved_at=timezone.now())
    listing = _cmd("--list-pending")
    assert node_id(1) in listing and node_id(2) not in listing
    out = _cmd(
        "--node-id", node_id(1), "--cpus", "64", "--memory-mb", "256000",
        "--by", "ops@x", "--reason", "onboarding", "--trust", "operator",
    )
    body = json.loads(out.strip().splitlines()[-1])
    assert body["total_cpus"] == 60 and body["trust_class"] == "operator"
    shown = json.loads(_cmd("--node-id", node_id(1), "--show"))
    assert shown["approved"] is True and shown["approved_by"] == "op:ops@x"


def test_the_command_refuses_loudly() -> None:
    _row(1)
    with pytest.raises(CommandError, match="--cpus and --memory-mb"):
        _cmd("--node-id", node_id(1), "--by", "x", "--reason", "y")
    with pytest.raises(CommandError, match=r"\[invalid\]"):
        _cmd("--node-id", node_id(1), "--cpus", "64", "--memory-mb", "256000")
    with pytest.raises(CommandError, match="64 lower-case hex"):
        _cmd("--node-id", "nope", "--show")


# ─── grandfathering ──────────────────────────────────────────────────


@pytest.mark.django_db(transaction=True)
def test_migration_0021_grandfathers_every_existing_row() -> None:
    before = [("scheduler", "0020_minercapacity_agent_version")]
    after = [("scheduler", "0021_minercapacity_approval")]
    executor = MigrationExecutor(connection)
    executor.migrate(before)
    old = executor.loader.project_state(before).apps
    old.get_model("scheduler", "MinerCapacity").objects.create(
        miner_node_id=node_id(1),
        status="active",
        capacity_slots=8,
        observed_epoch=10,
        data_epoch=10,
        refreshed_at=timezone.now(),
    )
    executor = MigrationExecutor(connection)
    executor.migrate(after)
    executor = MigrationExecutor(connection)
    executor.migrate(executor.loader.graph.leaf_nodes())

    row = MinerCapacity.objects.get(miner_node_id=node_id(1))
    assert row.approved_at is not None
    assert row.approved_by == "grandfathered"
    audit = MinerCapacityAudit.objects.get(miner_node_id=node_id(1))
    assert (audit.field, audit.actor) == ("approved_at", "grandfathered")
