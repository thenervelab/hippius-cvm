"""E4 contract §4: `GET /v1/operator/regions` adds per region
`dedicated_disks: {hdd: {sizes: [{size_gb, free, max_per_host}]}}` — only
while dedicated disks are sold (off, every row is byte-identical)."""

from __future__ import annotations

import pytest
from django.test import override_settings
from rest_framework.test import APIClient

from apps.disktier.tests.dedicated_helpers import ON, capable, make_disk
from apps.scheduler.models import MinerCapacity
from apps.scheduler.tests.factories import node_id

from .test_regions import ROW_KEYS, URL, _capacity, _located

pytestmark = pytest.mark.django_db


def _fleet() -> None:
    for seed, country in ((1, "FR"), (2, "FR"), (3, "DE")):
        _located(seed, country)
        _capacity(seed)
        capable(node_id(seed))
    # FR: host 1 two 22.3 TB disks and one 16 TB; host 2 one 22.3 TB.
    make_disk("wwn-0x11", node=node_id(1), size_gib=22354)
    make_disk("wwn-0x12", node=node_id(1), size_gib=22399)
    make_disk("wwn-0x13", node=node_id(1), size_gib=16050)
    make_disk("wwn-0x21", node=node_id(2), size_gib=22300)
    # Not sellable: assigned, too small, or on an agent too old (host 3).
    make_disk("wwn-0x22", node=node_id(2), state="pending_probe")
    make_disk("wwn-0x23", node=node_id(2), size_gib=999)
    make_disk("wwn-0x31", node=node_id(3))
    MinerCapacity.objects.filter(miner_node_id=node_id(3)).update(agent_version="v2020.01.01")


def test_off_every_row_is_byte_identical(operator_client: APIClient) -> None:
    _fleet()
    rows = operator_client.get(URL).json()["regions"]
    assert rows and all(set(r) == ROW_KEYS for r in rows)


@override_settings(**ON)
def test_the_free_disks_per_size_class(operator_client: APIClient) -> None:
    _fleet()
    by_region = {r["region"]: r for r in operator_client.get(URL).json()["regions"]}
    assert set(by_region["FR"]) == ROW_KEYS | {"dedicated_disks"}
    assert by_region["FR"]["dedicated_disks"] == {
        "hdd": {
            "sizes": [
                {"size_gb": 16000, "free": 1, "max_per_host": 1},
                {"size_gb": 22300, "free": 3, "max_per_host": 2},
            ]
        }
    }
    assert by_region["DE"]["dedicated_disks"] == {"hdd": {"sizes": []}}


@override_settings(**{**ON, "VALI_DEDICATED_TIER_MATCH": "minimum"})
def test_minimum_only_hdd_is_listed_and_every_faster_disk_counts_under_it(
    operator_client: APIClient,
) -> None:
    _fleet()
    from apps.disktier.models import DedicatedDisk

    DedicatedDisk.objects.filter(disk_id="wwn-0x11").update(verified_tier="nvme")
    DedicatedDisk.objects.filter(disk_id="wwn-0x12").update(verified_tier="ssd")
    fr = {r["region"]: r for r in operator_client.get(URL).json()["regions"]}["FR"]
    assert list(fr["dedicated_disks"]) == ["hdd"]
    assert fr["dedicated_disks"]["hdd"]["sizes"][-1] == {
        "size_gb": 22300,
        "free": 3,
        "max_per_host": 2,
    }


@override_settings(
    **{
        **ON,
        "VALI_DEDICATED_SELLABLE_TIERS": ["nvme", "hdd", "ssd"],
        "VALI_DEDICATED_TIER_MATCH": "minimum",
    }
)
def test_minimum_each_sold_tier_lists_every_disk_that_qualifies_for_it(
    operator_client: APIClient,
) -> None:
    _fleet()
    from apps.disktier.models import DedicatedDisk

    DedicatedDisk.objects.filter(disk_id="wwn-0x11").update(verified_tier="nvme")
    DedicatedDisk.objects.filter(disk_id="wwn-0x12").update(verified_tier="ssd")
    fr = {r["region"]: r for r in operator_client.get(URL).json()["regions"]}["FR"]
    assert fr["dedicated_disks"] == {
        "hdd": {
            "sizes": [
                {"size_gb": 16000, "free": 1, "max_per_host": 1},
                {"size_gb": 22300, "free": 3, "max_per_host": 2},
            ]
        },
        "ssd": {"sizes": [{"size_gb": 22300, "free": 2, "max_per_host": 2}]},
        "nvme": {"sizes": [{"size_gb": 22300, "free": 1, "max_per_host": 1}]},
    }
    assert list(fr["dedicated_disks"]) == ["hdd", "ssd", "nvme"]


@override_settings(**ON)
def test_exact_hdd_lists_only_hdd_disks(operator_client: APIClient) -> None:
    _fleet()
    from apps.disktier.models import DedicatedDisk

    DedicatedDisk.objects.filter(disk_id="wwn-0x11").update(verified_tier="nvme")
    DedicatedDisk.objects.filter(disk_id="wwn-0x12").update(verified_tier="ssd")
    fr = {r["region"]: r for r in operator_client.get(URL).json()["regions"]}["FR"]
    assert fr["dedicated_disks"] == {
        "hdd": {
            "sizes": [
                {"size_gb": 16000, "free": 1, "max_per_host": 1},
                {"size_gb": 22300, "free": 1, "max_per_host": 1},
            ]
        }
    }


@override_settings(**{**ON, "VALI_DEDICATED_SELLABLE_TIERS": ["nvme", "hdd", "ssd"]})
def test_exact_each_sold_tier_lists_only_its_own_disks(operator_client: APIClient) -> None:
    _fleet()
    from apps.disktier.models import DedicatedDisk

    DedicatedDisk.objects.filter(disk_id="wwn-0x11").update(verified_tier="nvme")
    DedicatedDisk.objects.filter(disk_id="wwn-0x12").update(verified_tier="ssd")
    fr = {r["region"]: r for r in operator_client.get(URL).json()["regions"]}["FR"]
    assert fr["dedicated_disks"] == {
        "hdd": {
            "sizes": [
                {"size_gb": 16000, "free": 1, "max_per_host": 1},
                {"size_gb": 22300, "free": 1, "max_per_host": 1},
            ]
        },
        "ssd": {"sizes": [{"size_gb": 22300, "free": 1, "max_per_host": 1}]},
        "nvme": {"sizes": [{"size_gb": 22300, "free": 1, "max_per_host": 1}]},
    }


@override_settings(**{**ON, "VALI_DEDICATED_SELLABLE_TIERS": ["ssd"]})
def test_a_tier_not_on_sale_is_not_listed(operator_client: APIClient) -> None:
    _fleet()
    fr = {r["region"]: r for r in operator_client.get(URL).json()["regions"]}["FR"]
    assert fr["dedicated_disks"] == {"ssd": {"sizes": []}}


@override_settings(**ON)
def test_a_gated_miner_offers_none(operator_client: APIClient) -> None:
    _fleet()
    MinerCapacity.objects.filter(miner_node_id=node_id(1)).update(status="quarantined")
    fr = {r["region"]: r for r in operator_client.get(URL).json()["regions"]}["FR"]
    assert fr["dedicated_disks"] == {
        "hdd": {"sizes": [{"size_gb": 22300, "free": 1, "max_per_host": 1}]}
    }
