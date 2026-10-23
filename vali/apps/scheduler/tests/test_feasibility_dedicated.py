"""E4 contract §4: `GET /v1/scheduler/feasibility?dedicated_count=…` —
the question for a VM with dedicated disks, and byte-identity without it."""

from __future__ import annotations

import pytest
from django.test import override_settings
from django.urls import reverse

from apps.disktier.dedicated import DedicatedRequest
from apps.disktier.tests.dedicated_helpers import ON, capable, make_disk
from apps.scheduler import feasibility
from apps.scheduler.models import MinerCapacity

from .factories import node_id
from .test_feasibility import _PRE_TIER_KEYS, real_fleet  # noqa: F401 — the fixture

URL = reverse("scheduler_feasibility")
REQ = DedicatedRequest("hdd", 2, 16000)
Q = {"flavor": "small", "dedicated_count": "2", "dedicated_min_size_gb": "16000"}


def _disks(seed: int, n: int, size_gib: int = 22354) -> None:
    capable(node_id(seed))
    for i in range(n):
        make_disk(f"wwn-0x{seed}{i}", node=node_id(seed), size_gib=size_gib)


@pytest.mark.parametrize("flags", [{}, ON])
def test_no_dedicated_parameter_is_the_answer_before_dedicated_disks(
    real_fleet,  # noqa: F811
    authed_client,
    flags,
) -> None:
    _disks(1, 3)
    with override_settings(**flags):
        plain = authed_client.get(URL, {"flavor": "small"}).json()
        board = authed_client.get(URL).json()["flavors"]
    assert set(plain["flavors"][0]) == _PRE_TIER_KEYS
    assert all(set(f) == _PRE_TIER_KEYS for f in board)


@override_settings(**ON)
def test_placeable_with_the_disks_and_the_most_on_one_fitting_host(real_fleet) -> None:  # noqa: F811
    _disks(1, 1)
    _disks(2, 3)
    _disks(3, 2, size_gib=15000)  # too small
    result = feasibility.assess("small", dedicated=REQ)
    assert (result.verdict, result.reason) == ("yes", "")
    assert result.dedicated == {
        "tier": "hdd",
        "count": 2,
        "min_size_gb": 16000,
        "placeable": True,
        "max_count_at_size": 3,
    }


@override_settings(**ON)
def test_no_node_with_the_disks_is_no_dedicated_capacity(real_fleet) -> None:  # noqa: F811
    _disks(1, 1)
    result = feasibility.assess("small", dedicated=REQ)
    assert (result.verdict, result.reason) == ("not-now", "no-dedicated-capacity")
    assert result.dedicated == {**REQ.as_spec(), "placeable": False, "max_count_at_size": 1}


@override_settings(**ON)
def test_disks_on_a_node_that_does_not_take_the_vm_is_no_host_fits_disks(real_fleet) -> None:  # noqa: F811
    _disks(2, 3)
    MinerCapacity.objects.filter(miner_node_id=node_id(2)).update(
        cordoned_at="2026-10-20T00:00:00Z", cordon_reason="ops"
    )
    result = feasibility.assess("small", dedicated=REQ)
    assert (result.verdict, result.reason) == ("not-now", "no-host-fits-disks")
    assert result.dedicated["placeable"] is False


@override_settings(**ON)
def test_disks_only_on_a_host_too_small_for_the_vm_are_not_placeable(real_fleet) -> None:  # noqa: F811
    """Slot admission (v1) would pick the host with the disks, but the
    flavor does not physically fit there: not placeable, and the disks there
    do not count towards `max_count_at_size`."""
    _disks(2, 3)
    MinerCapacity.objects.filter(miner_node_id=node_id(2)).update(total_cpus=12)
    result = feasibility.assess("2xlarge", dedicated=REQ)
    assert node_id(2) not in {h.node_id for h in result.hosts if h.fits}
    assert (result.verdict, result.reason) == ("not-now", "no-host-fits-disks")
    assert result.dedicated == {**REQ.as_spec(), "placeable": False, "max_count_at_size": 0}
    # The same host with room: placeable, its disks counted.
    MinerCapacity.objects.filter(miner_node_id=node_id(2)).update(total_cpus=24)
    result = feasibility.assess("2xlarge", dedicated=REQ)
    assert result.dedicated == {**REQ.as_spec(), "placeable": True, "max_count_at_size": 3}


@override_settings(**ON)
def test_too_few_disks_on_a_host_too_small_is_no_dedicated_capacity(real_fleet) -> None:  # noqa: F811
    _disks(2, 1)
    MinerCapacity.objects.filter(miner_node_id=node_id(2)).update(total_cpus=12)
    result = feasibility.assess("2xlarge", dedicated=DedicatedRequest("hdd", 1, 16000))
    assert (result.verdict, result.reason) == ("not-now", "no-host-fits-disks")
    result = feasibility.assess("2xlarge", dedicated=REQ)
    assert (result.verdict, result.reason) == ("not-now", "no-dedicated-capacity")


@pytest.mark.parametrize(
    "flags",
    [{}, {**ON, "VALI_DEDICATED_ALLOWED_OWNERS": ["canary"]}],
)
def test_not_offered_is_never(real_fleet, flags) -> None:  # noqa: F811
    _disks(1, 3)
    with override_settings(**flags):
        result = feasibility.assess("small", dedicated=REQ, tenant_id="t", user_id="u")
    assert (result.verdict, result.reason) == ("never", "dedicated-disks-not-offered")
    assert result.dedicated == {**REQ.as_spec(), "placeable": False, "max_count_at_size": 0}


@override_settings(**ON)
def test_the_api_carries_the_block_on_every_answer(real_fleet, authed_client) -> None:  # noqa: F811
    _disks(1, 2)
    one = authed_client.get(URL, Q).json()["flavors"][0]
    assert set(one) == _PRE_TIER_KEYS | {"dedicated"}
    assert one["dedicated"]["placeable"] is True
    board = authed_client.get(
        URL, {"dedicated_count": "2", "dedicated_min_size_gb": "16000", "dedicated_tier": "hdd"}
    ).json()["flavors"]
    assert all("dedicated" in f for f in board)


@pytest.mark.parametrize(
    ("query", "category"),
    [
        ({"dedicated_count": "2"}, "dedicated-invalid"),
        ({"dedicated_min_size_gb": "16000"}, "dedicated-invalid"),
        ({"dedicated_tier": "hdd"}, "dedicated-invalid"),
        ({"dedicated_count": "two", "dedicated_min_size_gb": "16000"}, "dedicated-invalid"),
        ({**Q, "dedicated_tier": "sas"}, "dedicated-invalid"),
        ({**Q, "dedicated_tier": "SSD"}, "dedicated-invalid"),
        ({**Q, "dedicated_count": "0"}, "dedicated-count-invalid"),
        ({**Q, "dedicated_count": "9"}, "dedicated-count-invalid"),
        ({**Q, "dedicated_min_size_gb": "999"}, "dedicated-size-invalid"),
    ],
)
def test_invalid_parameters_are_400(real_fleet, authed_client, query, category) -> None:  # noqa: F811
    resp = authed_client.get(URL, query)
    assert (resp.status_code, resp.json()["category"]) == (400, category), resp.content


# ── tiers (contract §8) ─────────────────────────────────────────────

ALL_TIERS = {**ON, "VALI_DEDICATED_SELLABLE_TIERS": ["hdd", "ssd", "nvme"]}


def _tiered(seed: int, tiers: list[str]) -> None:
    capable(node_id(seed))
    for i, tier in enumerate(tiers):
        make_disk(f"wwn-0x{seed}{i}", node=node_id(seed), tier=tier)


@pytest.mark.parametrize("tier", ["ssd", "nvme"])
def test_a_tier_not_on_sale_is_never_not_offered(real_fleet, tier) -> None:  # noqa: F811
    _tiered(1, ["nvme", "nvme"])
    request = DedicatedRequest(tier, 2, 16000)
    with override_settings(**ON):  # the default: hdd only
        result = feasibility.assess("small", dedicated=request)
    assert (result.verdict, result.reason) == ("never", "dedicated-disks-not-offered")
    assert result.dedicated == {**request.as_spec(), "placeable": False, "max_count_at_size": 0}


@override_settings(**ALL_TIERS)
def test_a_tier_counts_only_disks_verified_at_or_above_it(real_fleet) -> None:  # noqa: F811
    _tiered(1, ["hdd", "ssd", "nvme", "nvme"])
    counts = {
        tier: feasibility.assess("small", dedicated=DedicatedRequest(tier, 2, 16000)).dedicated[
            "max_count_at_size"
        ]
        for tier in ("hdd", "ssd", "nvme")
    }
    assert counts == {"hdd": 4, "ssd": 3, "nvme": 2}
    result = feasibility.assess("small", dedicated=DedicatedRequest("nvme", 3, 16000))
    assert (result.verdict, result.reason) == ("not-now", "no-dedicated-capacity")


@override_settings(**ALL_TIERS)
def test_the_api_takes_each_tier(real_fleet, authed_client) -> None:  # noqa: F811
    _tiered(1, ["nvme", "nvme"])
    for tier in ("hdd", "ssd", "nvme"):
        body = authed_client.get(URL, {**Q, "dedicated_tier": tier}).json()["flavors"][0]
        assert body["dedicated"]["tier"] == tier
        assert body["dedicated"]["placeable"] is True
