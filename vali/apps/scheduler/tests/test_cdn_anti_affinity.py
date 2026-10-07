"""One CDN node per host (CDN plan N2): a hard cap of 1 for the CDN
tenant's family on every placement path, only while `VALI_CDN_ENABLED`
is on."""

from __future__ import annotations

import ast
from pathlib import Path

import pytest
from django.conf import settings

from apps.scheduler import service
from apps.scheduler.placement import PlacementError, decide_placement

from .factories import make_miner, make_snapshot, node_id

CDN = "hippius-cdn"


@pytest.fixture(autouse=True)
def _cdn(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "VALI_CDN_ENABLED", True)
    monkeypatch.setattr(settings, "VALI_CDN_TENANT_ID", CDN)
    monkeypatch.setattr(settings, "VALI_MAX_FAMILY_PER_NODE", "")


def test_the_paths_without_a_fleet_cap_take_the_cdn_cap_only(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(settings, "VALI_MAX_FAMILY_PER_NODE", "5")
    assert service.cdn_family_cap(CDN) == 1
    assert service.cdn_family_cap("tenant-a") is None
    monkeypatch.setattr(settings, "VALI_CDN_ENABLED", False)
    assert service.cdn_family_cap(CDN) is None


def test_the_cdn_family_is_capped_at_one_per_host() -> None:
    assert service.max_family_per_node(CDN) == 1
    assert service.max_family_per_node("tenant-a") is None
    assert service.max_family_per_node() is None


def test_the_cap_beats_a_looser_fleet_setting(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "VALI_MAX_FAMILY_PER_NODE", "5")
    assert service.max_family_per_node(CDN) == 1
    assert service.max_family_per_node("tenant-a") == 5


def test_inert_while_the_flag_is_off(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "VALI_CDN_ENABLED", False)
    assert service.max_family_per_node(CDN) is None


def test_a_blank_cdn_tenant_caps_nobody(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "VALI_CDN_TENANT_ID", "")
    assert service.max_family_per_node("") is None


def test_a_host_with_a_cdn_node_takes_no_second_one() -> None:
    snap = make_snapshot(
        10,
        [
            make_miner(1, status="active", data_epoch=10),
            make_miner(2, status="active", data_epoch=10),
        ],
    )
    common = dict(
        snapshot=snap,
        capacity_by_node={node_id(1): 8, node_id(2): 8},
        load_by_node={},
        max_epoch_lag=2,
        max_family_per_node=service.max_family_per_node(CDN),
    )

    chosen = decide_placement(family_load_by_node={node_id(1): 1}, **common)
    assert chosen == node_id(2)
    with pytest.raises(PlacementError) as exc:
        decide_placement(family_load_by_node={node_id(1): 1, node_id(2): 1}, **common)
    assert exc.value.category == "no-eligible-miner"


@pytest.mark.django_db
def test_placement_arguments_carry_the_cdn_cap(monkeypatch: pytest.MonkeyPatch) -> None:
    snap = make_snapshot(10, [make_miner(1, status="active", data_epoch=10)])
    for tenant, want in ((CDN, 1), ("tenant-a", None)):
        args = service.placement_arguments(
            snapshot=snap, tenant_id=tenant, user_id="u", flavor="small", shadow_log=False
        )
        assert args["max_family_per_node"] == want


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


def _passes_the_family_cap(call: ast.Call) -> bool:
    for kw in call.keywords:
        if kw.arg == "max_family_per_node":
            return True
        # `**service.placement_arguments(...)` sets it for the caller.
        if kw.arg is None and isinstance(kw.value, ast.Call):
            if getattr(kw.value.func, "attr", None) == "placement_arguments":
                return True
        # `**arguments`, built from `placement_arguments` just above
        # (`orchestration/resize.py`).
        if kw.arg is None and isinstance(kw.value, ast.Name) and kw.value.id == "arguments":
            return True
    return False


def test_every_placement_path_passes_the_family_cap() -> None:
    """The cap is only as good as its weakest caller: a re-placement, an
    auto-migration or a price-watch suggestion that leaves it out could put
    a second CDN node on a host."""
    calls = _decide_placement_calls()
    assert len(calls) >= 6, calls  # launch, feasibility, resize, /place, /fail, drain, price-watch
    missing = [where for where, call in calls if not _passes_the_family_cap(call)]
    assert missing == []


# ── what counts as "a CDN node is on this host" ───────────────────────


def _cdn_vm(vm_id: str, host: str, **kw: object):
    from apps.lifecycle.models import Vm
    from apps.orchestration.tests.factories import make_vm

    vm = make_vm(vm_id, host=host, **kw)
    Vm.objects.filter(pk=vm.pk).update(tenant_id=CDN)
    vm.refresh_from_db()
    return vm


@pytest.mark.django_db
def test_a_cdn_node_without_a_placement_row_still_holds_its_host() -> None:
    from .factories import make_dispatchable_identity

    m1, m2 = make_dispatchable_identity(1), make_dispatchable_identity(2)
    _cdn_vm("cdn-1", m1.miner_id)

    assert service.decision_inputs(CDN)[2] == {node_id(1): 1}
    assert service.decision_inputs("tenant-a")[2] == {}
    assert node_id(2) == m2.chain_node_id


@pytest.mark.django_db
def test_a_migration_in_flight_holds_its_destination() -> None:
    from apps.orchestration.models import MigrationState
    from apps.orchestration.tests.factories import make_migration_job

    from .factories import make_dispatchable_identity

    m1, m2, m3 = (make_dispatchable_identity(i) for i in (1, 2, 3))
    moving = _cdn_vm("cdn-1", m1.miner_id)
    make_migration_job(moving, dest_node_id=m2.miner_id)
    done = _cdn_vm("cdn-2", m3.miner_id)
    make_migration_job(done, dest_node_id=m2.miner_id, state=MigrationState.FAILED.value)

    load = service.decision_inputs(CDN)[2]

    assert load == {node_id(1): 1, node_id(2): 1, node_id(3): 1}


@pytest.mark.django_db
def test_a_destroyed_cdn_node_frees_its_host() -> None:
    from apps.lifecycle.models import VmState

    from .factories import make_dispatchable_identity

    m1 = make_dispatchable_identity(1)
    _cdn_vm("cdn-1", m1.miner_id, state=VmState.DESTROYED)

    assert service.decision_inputs(CDN)[2] == {}


@pytest.mark.django_db
def test_the_vm_records_are_not_read_while_the_flag_is_off(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from .factories import make_dispatchable_identity

    m1 = make_dispatchable_identity(1)
    _cdn_vm("cdn-1", m1.miner_id)
    monkeypatch.setattr(settings, "VALI_CDN_ENABLED", False)

    assert service.decision_inputs(CDN)[2] == {}


# ── destinations a caller names ───────────────────────────────────────


def _local_edge_for(miner: object) -> None:
    from django.utils import timezone

    from apps.miners.models import LocationVerdict, MinerLocation
    from apps.network import service as network
    from apps.network.models import PublicIpPool
    from apps.network.tests.conftest import make_edge

    MinerLocation.objects.create(
        miner=miner, country_code="FR", verdict=LocationVerdict.VERIFIED, observed_at=timezone.now()
    )
    edge = make_edge("edge-fr", "FR", ())
    network.add_addresses(edge, ["203.0.113.50"], PublicIpPool.CDN, 2000)


@pytest.mark.django_db
def test_a_named_destination_with_a_cdn_node_is_refused() -> None:
    from apps.orchestration import service as orch

    from .factories import make_dispatchable_identity

    m1, m2, m3 = (make_dispatchable_identity(i) for i in (1, 2, 3))
    _cdn_vm("cdn-1", m1.miner_id)
    moving = _cdn_vm("cdn-2", m2.miner_id)
    # m3 is otherwise fine for a CDN node: a verified country with a local edge.
    _local_edge_for(m3)

    with pytest.raises(orch.StartError) as exc:
        orch._reject_cdn_colocated_dest(moving, m1.miner_id)
    assert exc.value.category == "dest-has-cdn-node"
    orch._reject_cdn_colocated_dest(moving, m3.miner_id)
    # A VM never blocks its own move, nor a tenant VM's.
    assert service.cdn_colocation_reason(CDN, "cdn-1", m1.miner_id) is None
    assert service.cdn_colocation_reason("tenant-a", "vm-x", m1.miner_id) is None


@pytest.mark.django_db
def test_a_named_destination_is_free_while_the_flag_is_off(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from .factories import make_dispatchable_identity

    m1 = make_dispatchable_identity(1)
    _cdn_vm("cdn-1", m1.miner_id)
    monkeypatch.setattr(settings, "VALI_CDN_ENABLED", False)

    assert service.cdn_colocation_reason(CDN, "cdn-2", m1.miner_id) is None


def test_every_named_destination_path_checks_cdn_colocation() -> None:
    """`start_migration`, the restore / failover destination check and
    `vali_create_vm` name a miner instead of asking the scheduler."""
    root = Path(__file__).resolve().parents[3] / "apps" / "orchestration"
    for rel, needle in (
        ("service.py", "_reject_cdn_colocated_dest(vm, dest_node_id)"),
        ("restore.py", "_reject_cdn_colocated_dest(vm, dest_node_id)"),
        ("services/launch.py", "cdn_dest_reason(spec.tenant_id"),
    ):
        assert needle in (root / rel).read_text(), rel
