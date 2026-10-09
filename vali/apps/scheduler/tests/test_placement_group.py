"""Anti-affinity (`Vm.placement_group`): never two VMs of one (tenant,
group) on a miner, on every path that places or moves a VM."""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

from apps.lifecycle.models import Vm, VmState
from apps.scheduler import service
from apps.scheduler.models import PlacementStatus
from apps.scheduler.placement import (
    ANTI_AFFINITY_UNSATISFIABLE,
    MINERS_BOOTING,
    PlacementError,
    decide_placement,
)

from .factories import (
    make_dispatchable_identity,
    make_miner,
    make_placement,
    make_snapshot,
    node_id,
)

TENANT = "t-1"


def _decide(**kw):
    snap = make_snapshot(
        10,
        [
            make_miner(1, status="active", data_epoch=10),
            make_miner(2, status="active", data_epoch=10),
        ],
    )
    return decide_placement(
        snapshot=snap,
        capacity_by_node={node_id(1): 8, node_id(2): 8},
        load_by_node={},
        family_load_by_node={},
        max_epoch_lag=2,
        **kw,
    )


def test_a_host_of_the_group_is_skipped() -> None:
    assert _decide(group_occupied=frozenset({node_id(1).lower()})) == node_id(2)


def test_every_host_taken_is_unsatisfiable() -> None:
    with pytest.raises(PlacementError) as exc:
        _decide(group_occupied=frozenset({node_id(1).lower(), node_id(2).lower()}))
    assert exc.value.category == ANTI_AFFINITY_UNSATISFIABLE


def test_a_host_full_for_other_reasons_is_not_blamed_on_the_group() -> None:
    snap = make_snapshot(10, [make_miner(1, status="active", data_epoch=10)])
    with pytest.raises(PlacementError) as exc:
        decide_placement(
            snapshot=snap,
            capacity_by_node={node_id(1): 0},
            load_by_node={},
            family_load_by_node={},
            max_epoch_lag=2,
            group_occupied=frozenset({node_id(1).lower()}),
        )
    assert exc.value.category == "no-eligible-miner"


def test_a_booting_host_elsewhere_is_worth_waiting_for() -> None:
    with pytest.raises(PlacementError) as exc:
        _decide(
            group_occupied=frozenset({node_id(1).lower()}),
            booting_by_node={node_id(2): 3},
            max_booting_per_node=3,
        )
    assert exc.value.category == MINERS_BOOTING


def test_a_host_of_the_group_at_its_boot_cap_is_still_the_group() -> None:
    with pytest.raises(PlacementError) as exc:
        _decide(
            group_occupied=frozenset({node_id(1).lower(), node_id(2).lower()}),
            booting_by_node={node_id(1): 3},
            max_booting_per_node=3,
        )
    assert exc.value.category == ANTI_AFFINITY_UNSATISFIABLE


# ── what counts as "the group holds this host" ───────────────────────


def _vm(vm_id: str, host: str = "", *, group: str = "db", tenant: str = TENANT, **kw):
    from apps.orchestration.tests.factories import make_vm

    vm = make_vm(vm_id, host=host, **kw)
    Vm.objects.filter(pk=vm.pk).update(tenant_id=tenant, placement_group=group)
    vm.refresh_from_db()
    return vm


@pytest.mark.django_db
def test_hosts_moves_in_flight_and_unbound_launches_all_count() -> None:
    from apps.orchestration.models import MigrationState
    from apps.orchestration.tests.factories import make_migration_job

    m = {i: make_dispatchable_identity(i) for i in range(1, 6)}
    _vm("vm-a", m[1].miner_id)
    moving = _vm("vm-b", m[2].miner_id)
    make_migration_job(moving, dest_node_id=m[3].miner_id)
    finished = _vm("vm-c", m[4].miner_id)
    make_migration_job(finished, dest_node_id=m[5].miner_id, state=MigrationState.FAILED.value)
    # A launch in flight: placed (a pending row), not bound to a host yet.
    launching = _vm("vm-d", "")
    make_placement(launching, node_id(5), vm_family=TENANT, status=PlacementStatus.PENDING.value)

    held = service.group_nodes(TENANT, "db")
    assert held == {node_id(i).lower() for i in (1, 2, 3, 4, 5)}
    assert node_id(1).lower() not in service.group_nodes(TENANT, "db", exclude_vm_id="vm-a")


@pytest.mark.django_db
def test_a_destroyed_vm_frees_its_host_and_other_groups_never_count() -> None:
    m1 = make_dispatchable_identity(1)
    _vm("vm-a", m1.miner_id, state=VmState.DESTROYED)
    _vm("vm-b", m1.miner_id, group="web")
    _vm("vm-c", m1.miner_id, tenant="t-2")
    _vm("vm-d", m1.miner_id, group="")
    assert service.group_nodes(TENANT, "db") == frozenset()
    assert service.group_nodes(TENANT, "") == frozenset()


@pytest.mark.django_db
def test_placement_arguments_read_the_group_off_the_vm() -> None:
    m1 = make_dispatchable_identity(1)
    _vm("vm-a", m1.miner_id)
    _vm("vm-new", "")
    snap = make_snapshot(10, [make_miner(1, status="active", data_epoch=10)])
    args = service.placement_arguments(
        snapshot=snap,
        tenant_id=TENANT,
        user_id="u",
        flavor="small",
        shadow_log=False,
        vm_id="vm-new",
    )
    assert args["group_occupied"] == {node_id(1).lower()}
    plain = service.placement_arguments(
        snapshot=snap, tenant_id=TENANT, user_id="u", flavor="small", shadow_log=False
    )
    assert "group_occupied" not in plain


@pytest.mark.django_db
def test_a_named_destination_of_the_group_is_refused(monkeypatch: pytest.MonkeyPatch) -> None:
    from apps.orchestration import restore
    from apps.orchestration import service as orch

    m1, m2, m3 = (make_dispatchable_identity(i) for i in (1, 2, 3))
    _vm("vm-a", m1.miner_id)
    moving = _vm("vm-b", m2.miner_id)
    with pytest.raises(orch.StartError) as exc:
        orch._reject_group_colocated_dest(moving, m1.miner_id)
    assert exc.value.category == "placement-anti-affinity"
    orch._reject_group_colocated_dest(moving, m3.miner_id)
    monkeypatch.setattr(orch, "_snp_generation", lambda miner_id: "genoa")
    with pytest.raises(restore.RestoreError) as refused:
        restore._validate_other_dest(moving, m1.miner_id)
    assert refused.value.code == "no-eligible-miner" and "anti-affinity" in str(refused.value)


# ── every path ───────────────────────────────────────────────────────


def _decide_placement_calls() -> list[tuple[str, ast.Call]]:
    root = Path(__file__).resolve().parents[3]
    calls: list[tuple[str, ast.Call]] = []
    for path in sorted((root / "apps").rglob("*.py")):
        if "tests" in path.parts or "migrations" in path.parts:
            continue
        for node in ast.walk(ast.parse(path.read_text(), filename=str(path))):
            if isinstance(node, ast.Call) and (
                getattr(node.func, "id", None) == "decide_placement"
                or getattr(node.func, "attr", None) == "decide_placement"
            ):
                calls.append((f"{path.relative_to(root)}:{node.lineno}", node))
    return calls


def _passes_the_group(call: ast.Call) -> bool:
    for kw in call.keywords:
        if kw.arg == "group_occupied":
            return True
        if kw.arg is None and isinstance(kw.value, ast.Call):
            if getattr(kw.value.func, "attr", None) in ("placement_arguments", "group_arguments"):
                return True
        if kw.arg is None and isinstance(kw.value, ast.Name) and kw.value.id == "arguments":
            return True
    return False


def test_every_placement_path_passes_the_group() -> None:
    calls = _decide_placement_calls()
    assert len(calls) >= 6, calls
    assert [where for where, call in calls if not _passes_the_group(call)] == []


def test_every_named_destination_path_checks_the_group() -> None:
    root = Path(__file__).resolve().parents[3] / "apps" / "orchestration"
    for rel, needle in (
        ("service.py", "_reject_group_colocated_dest(vm, dest_node_id)"),
        ("restore.py", "_reject_group_colocated_dest(vm, dest_node_id)"),
        ("services/launch.py", "group_dest_reason("),
    ):
        assert needle in (root / rel).read_text(), rel
