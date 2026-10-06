"""Capacity v2 in the readouts: `/v1/operator/regions`,
`/v1/scheduler/capacity` and `/v1/operator/fleet` publish the ACTIVE
admission model's units and a truthful per-flavor headroom.

The headline: 4xlarge (32 vCPU / 128 GiB) is for sale, and must read as
available in NL (a 64-thread / 256 GB miner holds one) and as 0 in FR
(24-thread / 125 GB miners cannot), under both models."""

from __future__ import annotations

from decimal import Decimal

import pytest
from django.test import override_settings
from django.urls import reverse
from django.utils import timezone
from rest_framework.test import APIClient

from apps.miners.models import LocationVerdict, MinerLocation
from apps.scheduler import chain, service
from apps.scheduler.models import CapacityTrustClass, MinerCapacity, PlacementStatus
from apps.scheduler.tests import conftest as scheduler_conftest
from apps.scheduler.tests.factories import (
    make_dispatchable_identity,
    make_miner,
    make_placement,
    make_snapshot,
    make_vm,
    node_id,
)

pytestmark = pytest.mark.django_db


# The scheduler suite's root-principal client, for `/v1/scheduler/capacity`.
authed_client = scheduler_conftest.authed_client

ENFORCE = override_settings(
    VALI_SCHEDULER_RESOURCE_ADMISSION="true",
    VALI_SCHEDULER_SLOT_REF_CPUS=2,
    VALI_SCHEDULER_SLOT_REF_MEMORY_MB=8192,
)
REGIONS = reverse("operator_regions")


def _host(seed: int, country: str, *, cpus: int, memory_mb: int, slots: int = 32) -> None:
    miner = make_dispatchable_identity(seed)
    MinerLocation.objects.create(
        miner=miner,
        connection_ip=f"146.10.20.{seed}",
        country_code=country,
        latitude=48.8,
        longitude=2.3,
        verdict=LocationVerdict.VERIFIED,
        observed_at=timezone.now(),
    )
    MinerCapacity.objects.create(
        miner_node_id=node_id(seed),
        status="active",
        capacity_slots=slots,
        observed_epoch=10,
        data_epoch=10,
        refreshed_at=timezone.now(),
        trust_class=CapacityTrustClass.OPERATOR,
        total_cpus=cpus,
        total_memory_mb=memory_mb,
    )


@pytest.fixture
def fleet() -> None:
    _host(1, "FR", cpus=24, memory_mb=127_883)
    _host(2, "FR", cpus=24, memory_mb=384_395)
    _host(4, "NL", cpus=64, memory_mb=256_180)


def _regions(client: APIClient) -> dict[str, dict]:
    return {r["region"]: r["capacity"] for r in client.get(REGIONS).json()["regions"]}


def _place(seed: int, n: int, flavor: str) -> None:
    for i in range(n):
        make_placement(
            make_vm(f"vm-{seed}-{flavor}-{i}", f"lease-{seed}-{flavor}-{i}"),
            node_id(seed),
            status=PlacementStatus.BOUND.value,
            resource_class=flavor,
        )


# ─── 4xlarge, truthfully ────────────────────────────────────────────


def test_4xlarge_reads_available_in_nl_and_zero_in_fr_under_v1(
    fleet: None, operator_client: APIClient
) -> None:
    caps = _regions(operator_client)
    assert caps["NL"]["model"] == "v1"
    assert caps["NL"]["free_by_flavor"]["4xlarge"] == 1
    assert caps["FR"]["free_by_flavor"]["4xlarge"] == 0
    assert caps["FR"]["free_by_flavor"]["small"] > 0


@ENFORCE
def test_4xlarge_reads_available_in_nl_and_zero_in_fr_under_v2(
    fleet: None, operator_client: APIClient
) -> None:
    caps = _regions(operator_client)
    assert caps["NL"]["model"] == "v2"
    assert caps["NL"]["free_by_flavor"]["4xlarge"] == 1
    # FR: 22 usable threads < 32 vCPU, whatever the overcommit ratio.
    assert caps["FR"]["free_by_flavor"]["4xlarge"] == 0


@override_settings(VALI_SCHEDULER_MAX_FLAVOR="2xlarge")
def test_a_flavor_not_offered_reads_zero_even_where_it_fits(
    fleet: None, operator_client: APIClient
) -> None:
    assert _regions(operator_client)["NL"]["free_by_flavor"]["4xlarge"] == 0


# ─── v2 units ───────────────────────────────────────────────────────


@ENFORCE
def test_v2_units_are_resource_true_and_add_up(fleet: None, operator_client: APIClient) -> None:
    before = _regions(operator_client)["NL"]
    _place(4, 1, "2xlarge")
    after = _regions(operator_client)["NL"]
    assert before["free_units"] - after["free_units"] == 8  # 16 vCPU / 64 GiB = 8 mediums
    assert after["total_units"] == after["committed_units"] + after["free_units"]
    assert after["unit"] == {"cpus": 2, "memory_mb": 8192}
    assert after["free_vms"] == before["free_vms"] - 1


def test_v1_units_are_unchanged_slots(fleet: None, operator_client: APIClient) -> None:
    _place(4, 2, "2xlarge")
    nl = _regions(operator_client)["NL"]
    assert nl["free_vms"] is None
    # v1: one placement = one slot, whatever its size.
    assert nl["committed_units"] == 2


def test_views_agree_with_the_v1_admission_bound(fleet: None) -> None:
    cap, load, _ = service.decision_inputs("")
    for nid, view in service.capacity_views().items():
        assert view.total_units == cap[nid]
        assert view.free_units == max(0, cap[nid] - load.get(nid, 0))


@ENFORCE
def test_v2_view_matches_the_budget_admission_uses(fleet: None) -> None:
    from apps.scheduler.capacity import headroom

    budgets = service.host_budgets_by_node()
    for nid, view in service.capacity_views().items():
        assert view.free_by_flavor["small"] == headroom(
            budgets[nid], cpu_count=1, memory_mb=4096
        )


# ─── /v1/scheduler/capacity + fleet ─────────────────────────────────


@ENFORCE
def test_scheduler_capacity_view_reports_v2_units(
    fleet: None, authed_client: APIClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        chain, "read_miner_status", lambda: make_snapshot(10, [make_miner(s) for s in (1, 2, 4)])
    )
    body = authed_client.get(reverse("scheduler_capacity")).json()
    nl = next(m for m in body["miners"] if m["node_id"] == node_id(4))
    assert nl["model"] == "v2"
    assert nl["capacity_slots"] == nl["load"] + nl["free_slots"]
    assert nl["free_by_flavor"]["4xlarge"] == 1


@ENFORCE
def test_fleet_readout_carries_model_units_and_v2_budget(
    fleet: None, operator_client: APIClient
) -> None:
    MinerCapacity.objects.filter(miner_node_id=node_id(4)).update(cpu_ratio=Decimal("2.00"))
    body = operator_client.get(reverse("operator_fleet"), {"chain": "false"}).json()
    row = next(r for r in body["miners"] if r["node_id"] == node_id(4))
    cap = row["capacity"]
    assert cap["model"] == "v2"
    assert cap["units"]["total"] == cap["units"]["committed"] + cap["units"]["free"]
    assert cap["trust_class"] == "operator"
    assert cap["cpu_ratio"] == "2.00"
    assert cap["v2"]["vcpu_budget"] == 124  # (64 − 2) × 2
    assert cap["v2"]["binding"][0] == "vcpu:anchor"
    assert cap["flavor_headroom"]["4xlarge"]["fits_now"] == 1


# ─── per-flavor figures ─────────────────────────────────────────────


def test_v1_per_flavor_headroom_is_bounded_by_the_free_slots(
    operator_client: APIClient,
) -> None:
    """v1 admission needs a free SLOT: a host with RAM/CPU to spare but one
    slot left takes one more VM, not twenty."""
    _host(1, "FR", cpus=24, memory_mb=384_395, slots=3)
    _place(1, 2, "small")
    assert _regions(operator_client)["FR"]["free_by_flavor"]["small"] == 1


@pytest.mark.parametrize("enforce", [False, True])
def test_regions_sum_the_per_flavor_headroom_and_free_vms(
    operator_client: APIClient, enforce: bool
) -> None:
    _host(1, "FR", cpus=24, memory_mb=384_395)
    _host(2, "FR", cpus=24, memory_mb=384_395)
    with override_settings(
        VALI_SCHEDULER_RESOURCE_ADMISSION="true" if enforce else "false",
        VALI_SCHEDULER_SLOT_REF_CPUS=2,
        VALI_SCHEDULER_SLOT_REF_MEMORY_MB=8192,
    ):
        one = service.capacity_views()[node_id(1)]
        fr = _regions(operator_client)["FR"]
    assert fr["free_by_flavor"]["small"] == 2 * one.free_by_flavor["small"]
    if enforce:
        assert fr["free_vms"] == 2 * one.free_vms
    else:
        assert fr["free_vms"] is None


@ENFORCE
def test_fleet_headroom_is_the_v2_figure_when_v2_decides(
    fleet: None, operator_client: APIClient
) -> None:
    """Node 2 (24 threads, 384 GB) at 2:1 takes 32 smalls under v2 (the
    VM ceiling binds) where v1's arithmetic says 22 (vCPU at 1:1)."""
    body = operator_client.get(reverse("operator_fleet"), {"chain": "false"}).json()
    row = next(r for r in body["miners"] if r["node_id"] == node_id(2))
    assert row["capacity"]["flavor_headroom"]["small"]["fits_now"] == 32


# ─── hard gates zero the free figures (review follow-up) ────────────


@pytest.mark.parametrize("gate", ["inactive", "epoch-stale", "cvm-incapable", "zombie"])
def test_regions_offer_nothing_from_a_host_placement_would_refuse(
    fleet: None, operator_client: APIClient, monkeypatch: pytest.MonkeyPatch, gate: str
) -> None:
    nl = node_id(4)
    if gate == "inactive":
        MinerCapacity.objects.filter(miner_node_id=nl).update(status="quarantined")
    elif gate == "epoch-stale":
        MinerCapacity.objects.filter(miner_node_id=nl).update(observed_epoch=10_000)
    elif gate == "cvm-incapable":
        monkeypatch.setattr(service, "cvm_capability_by_node", lambda: {nl: "incapable"})
    else:
        monkeypatch.setattr(service, "zombie_quarantined_node_ids", lambda: frozenset({nl}))
    cap = _regions(operator_client)["NL"]
    assert cap["free_units"] == 0
    assert set(cap["free_by_flavor"].values()) == {0}
    assert cap["total_units"] == cap["committed_units"] > 0  # size kept, nothing offered


def test_scheduler_capacity_view_offers_nothing_from_an_inactive_or_zombie_miner(
    fleet: None, authed_client: APIClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        chain,
        "read_miner_status",
        lambda: make_snapshot(
            10, [make_miner(1, status="quarantined"), make_miner(2), make_miner(4)]
        ),
    )
    monkeypatch.setattr(service, "zombie_quarantined_node_ids", lambda: frozenset({node_id(4)}))
    body = authed_client.get(reverse("scheduler_capacity")).json()
    by_node = {m["node_id"]: m for m in body["miners"]}
    for nid in (node_id(1), node_id(4)):
        if nid in by_node:
            assert by_node[nid]["free_slots"] == 0
            assert set(by_node[nid]["free_by_flavor"].values()) <= {0}
    assert by_node[node_id(2)]["free_slots"] > 0


def test_scheduler_capacity_load_stays_the_placement_count_under_v1(
    authed_client: APIClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    _host(1, "FR", cpus=24, memory_mb=384_395, slots=2)
    _place(1, 3, "small")  # over-committed: 3 placements on a 2-slot host
    monkeypatch.setattr(chain, "read_miner_status", lambda: make_snapshot(10, [make_miner(1)]))
    [row] = authed_client.get(reverse("scheduler_capacity")).json()["miners"]
    assert (row["capacity_slots"], row["load"], row["free_slots"]) == (2, 3, 0)


@pytest.mark.parametrize(
    ("cap", "want"),
    [
        # v2 decides: slots are irrelevant, a fitting flavor is what counts.
        ({"model": "v2", "free_slots": 0, "free_by_flavor": {"small": 3}}, (True, None)),
        ({"model": "v2", "free_slots": 9, "free_by_flavor": {"small": 0}}, (False, "full")),
        # v1 decides: exactly as before.
        ({"model": "v1", "free_slots": 0, "free_by_flavor": {"small": 3}}, (False, "full")),
        ({"model": "v1", "free_slots": 2, "free_by_flavor": {"small": 0}}, (True, None)),
    ],
)
def test_fleet_calls_a_host_full_in_the_active_model(cap: dict, want: tuple) -> None:
    from apps.operator.fleet import _placement_verdict

    got = _placement_verdict(
        dispatchable=True,
        dispatch_reason=None,
        zombie_quarantined=False,
        chain_row={"status": "active", "data_epoch": 10},
        on_chain=True,
        current_epoch=10,
        cvm_verdict="proven",
        cap=cap,
    )
    assert got == want


@override_settings(VALI_SCHEDULER_MAX_FLAVOR="2xlarge")
def test_fleet_flavor_headroom_keeps_its_v1_meaning(
    fleet: None, operator_client: APIClient
) -> None:
    """Under v1 the existing `flavor_headroom` stays the physical figure
    (with `offered` beside it); the admission-true count is the NEW
    `free_by_flavor`."""
    body = operator_client.get(reverse("operator_fleet"), {"chain": "false"}).json()
    cap = next(r for r in body["miners"] if r["node_id"] == node_id(4))["capacity"]
    assert cap["flavor_headroom"]["4xlarge"] == {
        "fits_now": 1,
        "fits_hardware": True,
        "offered": False,
        # No disk data for this host: the disk dimension cannot say.
        "disk": {"need_gb": 1290, "fits_now": None, "fits_hardware": None},
    }
    assert cap["free_by_flavor"]["4xlarge"] == 0
