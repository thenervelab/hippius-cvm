"""No CDN node behind a remote edge (v1): a CDN node is placed only on a
miner whose VERIFIED country has an edge for it — the region of the
address it holds, else a region whose attachable edge has a free CDN
address — on every placement path, and refused on a named destination
that has none. Inert while `VALI_CDN_ENABLED` is off."""

from __future__ import annotations

import ast
from typing import Any

import pytest
from django.conf import settings

from apps.miners.models import LocationVerdict, MinerLocation
from apps.network import service as network
from apps.network.models import PublicIpPool
from apps.network.tests.conftest import make_edge
from apps.orchestration import service as orch
from apps.scheduler import service
from apps.scheduler.placement import PlacementError, decide_placement

from .factories import make_dispatchable_identity, make_miner, make_snapshot, node_id
from .test_cdn_anti_affinity import _cdn_vm, _decide_placement_calls

CDN = "hippius-cdn"

pytestmark = pytest.mark.django_db


@pytest.fixture(autouse=True)
def _cdn(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "VALI_CDN_ENABLED", True)
    monkeypatch.setattr(settings, "VALI_CDN_TENANT_ID", CDN)


def _located(seed: int, country: str, verdict: str = LocationVerdict.VERIFIED) -> Any:
    from django.utils import timezone

    miner = make_dispatchable_identity(seed)
    MinerLocation.objects.create(
        miner=miner, country_code=country, verdict=verdict, observed_at=timezone.now()
    )
    return miner


def _cdn_edge(name: str, region: str, *addresses: str) -> Any:
    edge = make_edge(name, region, ())
    network.add_addresses(edge, list(addresses), PublicIpPool.CDN, 2000)
    return edge


def _world() -> tuple[Any, Any, Any]:
    fr, nl, au = _located(1, "FR"), _located(2, "NL"), _located(3, "AU")
    _cdn_edge("edge-fr", "FR", "203.0.113.50")
    return fr, nl, au


# ── which nodes ───────────────────────────────────────────────────────


def test_only_miners_with_a_local_edge_take_a_cdn_node() -> None:
    _world()

    assert service.cdn_edge_arguments(CDN) == {"cdn_local_edge": frozenset({node_id(1)})}


def test_an_edge_with_no_free_cdn_address_is_no_local_edge() -> None:
    _world()
    au_edge = make_edge("edge-au", "AU", ("203.0.113.70",))  # general pool only
    assert au_edge.region == "AU"

    assert service.cdn_edge_arguments(CDN)["cdn_local_edge"] == frozenset({node_id(1)})


def test_an_unverified_country_takes_no_cdn_node(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "VALI_GEO_REQUIRE_VERIFIED", False)
    _located(1, "FR", LocationVerdict.UNVERIFIED)
    _cdn_edge("edge-fr", "FR", "203.0.113.50")

    assert service.cdn_edge_arguments(CDN)["cdn_local_edge"] == frozenset()


def test_a_node_holding_an_address_stays_in_its_edge_region() -> None:
    fr, _, au = _world()
    _cdn_edge("edge-au", "AU", "203.0.113.80")
    vm = _cdn_vm("cdn-1", fr.miner_id)
    network.attach_cdn(vm)

    # Free CDN addresses in AU too, but this node's address is on edge-fr.
    assert service.cdn_edge_arguments(CDN, "cdn-1")["cdn_local_edge"] == frozenset({node_id(1)})
    assert service.cdn_edge_arguments(CDN)["cdn_local_edge"] == frozenset({node_id(3)})


def test_no_gate_for_other_tenants_or_while_off(monkeypatch: pytest.MonkeyPatch) -> None:
    _world()
    assert service.cdn_edge_arguments("tenant-a") == {}
    monkeypatch.setattr(settings, "VALI_CDN_ENABLED", False)
    assert service.cdn_edge_arguments(CDN) == {}


# ── the gate ──────────────────────────────────────────────────────────


def _snap() -> Any:
    return make_snapshot(10, [make_miner(i, status="active", data_epoch=10) for i in (1, 2)])


def _decide(**kw: Any) -> str:
    return decide_placement(
        snapshot=_snap(),
        capacity_by_node={node_id(1): 8, node_id(2): 8},
        load_by_node={},
        family_load_by_node={},
        max_epoch_lag=2,
        **kw,
    )


def test_the_gate_keeps_only_the_listed_nodes() -> None:
    assert _decide(cdn_local_edge=frozenset({node_id(2)})) == node_id(2)
    with pytest.raises(PlacementError) as exc:
        _decide(cdn_local_edge=frozenset())
    assert exc.value.category == "no-eligible-miner"
    assert "CDN local-edge gate" in exc.value.message


def test_placement_arguments_carry_the_gate() -> None:
    _world()
    for tenant, want in ((CDN, frozenset({node_id(1)})), ("tenant-a", None)):
        args = service.placement_arguments(
            snapshot=_snap(), tenant_id=tenant, user_id="u", flavor="small", shadow_log=False
        )
        assert args.get("cdn_local_edge") == want


def _passes_the_edge_gate(call: ast.Call) -> bool:
    for kw in call.keywords:
        if kw.arg is not None or not isinstance(kw.value, (ast.Call, ast.Name)):
            continue
        if isinstance(kw.value, ast.Name) and kw.value.id == "arguments":
            return True
        if getattr(getattr(kw.value, "func", None), "attr", None) in (
            "placement_arguments",
            "cdn_edge_arguments",
        ):
            return True
    return False


def test_every_placement_path_passes_the_edge_gate() -> None:
    calls = _decide_placement_calls()
    assert len(calls) >= 6, calls
    assert [where for where, call in calls if not _passes_the_edge_gate(call)] == []


# ── named destinations ────────────────────────────────────────────────


def test_a_named_destination_without_a_local_edge_is_refused() -> None:
    fr, nl, _ = _world()
    other = _located(4, "FR")
    vm = _cdn_vm("cdn-1", fr.miner_id)

    with pytest.raises(orch.StartError) as exc:
        orch._reject_cdn_colocated_dest(vm, nl.miner_id)
    assert exc.value.category == "cdn-no-local-edge"
    orch._reject_cdn_colocated_dest(vm, other.miner_id)


def test_a_named_destination_with_no_location_is_refused() -> None:
    fr, _, _ = _world()
    bare = make_dispatchable_identity(5)
    vm = _cdn_vm("cdn-1", fr.miner_id)

    assert "unknown" in (service.cdn_edge_reason(CDN, vm.vm_id, bare.miner_id) or "")


def test_named_destinations_are_free_for_others_and_while_off(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _, nl, _ = _world()
    assert service.cdn_edge_reason("tenant-a", "vm-x", nl.miner_id) is None
    monkeypatch.setattr(settings, "VALI_CDN_ENABLED", False)
    assert service.cdn_edge_reason(CDN, "cdn-x", nl.miner_id) is None
    assert service.cdn_dest_reason(CDN, "cdn-x", nl.miner_id) is None
