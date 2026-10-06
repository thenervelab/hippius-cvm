"""Tests for `GET /v1/operator/regions`."""

from __future__ import annotations

import pytest
from django.urls import reverse
from django.utils import timezone
from rest_framework.test import APIClient

from apps.miners.models import LocationVerdict, MinerLocation
from apps.scheduler.models import MinerCapacity, PlacementStatus
from apps.scheduler.tests.factories import (
    make_dispatchable_identity,
    make_placement,
    make_vm,
    node_id,
)

pytestmark = pytest.mark.django_db


def _legacy(cap: dict) -> dict:
    """The three keys every consumer has read since #931."""
    return {k: cap[k] for k in ("total_units", "committed_units", "free_units")}


URL = reverse("operator_regions")
ROW_KEYS = {
    "region",
    "country_code",
    "miners_total",
    "miners_verified",
    "miners_dispatchable",
    "hosted_vm_count",
    "capacity",
    "node_ids",
}
BODY_KEYS = {"regions", "unlocated_miners", "require_verified", "vantage", "generated_at"}


def _capacity(seed: int, slots: int = 6) -> MinerCapacity:
    return MinerCapacity.objects.create(
        miner_node_id=node_id(seed),
        status="active",
        capacity_slots=slots,
        observed_epoch=10,
        data_epoch=10,
        refreshed_at=timezone.now(),
    )


def _located(seed: int, country: str, verdict: str = LocationVerdict.VERIFIED) -> MinerLocation:
    miner = make_dispatchable_identity(seed)
    return MinerLocation.objects.create(
        miner=miner,
        connection_ip=f"146.10.20.{seed}",
        country_code=country,
        latitude=48.8,
        longitude=2.3,
        asn=64500,
        rtt_ms=4.0,
        verdict=verdict,
        observed_at=timezone.now(),
    )


def test_tenant_principal_is_403(tenant_client: APIClient) -> None:
    assert tenant_client.get(URL).status_code == 403


def test_unauthenticated_is_401() -> None:
    assert APIClient().get(URL).status_code == 401


def test_post_is_405(operator_client: APIClient) -> None:
    assert operator_client.post(URL, {}).status_code == 405


def test_malformed_verified_only_is_400(operator_client: APIClient) -> None:
    resp = operator_client.get(URL, {"verified_only": "maybe"})
    assert resp.status_code == 400
    assert resp.json()["category"] == "wire"


def test_empty_fleet_returns_no_regions(operator_client: APIClient) -> None:
    body = operator_client.get(URL).json()
    assert set(body) == BODY_KEYS
    assert body["regions"] == [] and body["unlocated_miners"] == 0
    assert body["require_verified"] is True
    assert set(body["vantage"]) == {"name", "latitude", "longitude"}


def test_shape_of_a_region_row(operator_client: APIClient) -> None:
    _located(1, "FR")
    _capacity(1, slots=6)
    vm_a = make_vm("vm-a", "lease-a")
    vm_b = make_vm("vm-b", "lease-b")
    make_placement(vm_a, node_id(1), status=PlacementStatus.BOUND.value)
    make_placement(vm_b, node_id(1), status=PlacementStatus.PENDING.value)

    body = operator_client.get(URL).json()
    assert len(body["regions"]) == 1
    row = body["regions"][0]
    assert set(row) == ROW_KEYS
    assert row == {
        "region": "FR",
        "country_code": "FR",
        "miners_total": 1,
        "miners_verified": 1,
        "miners_dispatchable": 1,
        "hosted_vm_count": 2,
        "capacity": row["capacity"],
        "node_ids": [node_id(1)],
    }
    assert _legacy(row["capacity"]) == {"total_units": 6, "committed_units": 2, "free_units": 4}


def test_regions_are_sorted_by_code_and_capacity_summed(operator_client: APIClient) -> None:
    _located(1, "FR")
    _located(2, "FR")
    _located(3, "DE")
    _capacity(1, slots=4)
    _capacity(2, slots=8)
    body = operator_client.get(URL).json()
    assert [r["region"] for r in body["regions"]] == ["DE", "FR"]
    fr = body["regions"][1]
    assert fr["miners_total"] == 2 and fr["node_ids"] == sorted([node_id(1), node_id(2)])
    assert _legacy(fr["capacity"]) == {"total_units": 12, "committed_units": 0, "free_units": 12}
    assert body["regions"][0]["capacity"] is None  # DE reports no capacity row


def test_unverified_miners_are_counted_but_not_placeable_by_default(
    operator_client: APIClient,
) -> None:
    _located(1, "FR")
    _located(2, "FR", verdict=LocationVerdict.UNVERIFIED)
    _located(3, "FR", verdict=LocationVerdict.MISMATCH)
    row = operator_client.get(URL).json()["regions"][0]
    assert row["miners_total"] == 3
    assert row["miners_verified"] == 1
    assert row["miners_dispatchable"] == 1
    assert row["node_ids"] == [node_id(1)]


def test_verified_only_false_adds_unverified_but_never_mismatch(operator_client: APIClient) -> None:
    _located(1, "FR")
    _located(2, "FR", verdict=LocationVerdict.UNVERIFIED)
    _located(3, "FR", verdict=LocationVerdict.MISMATCH)
    body = operator_client.get(URL, {"verified_only": "false"}).json()
    assert body["require_verified"] is False
    row = body["regions"][0]
    assert row["node_ids"] == sorted([node_id(1), node_id(2)])
    assert row["miners_dispatchable"] == 2


def test_an_undispatchable_miner_adds_no_capacity(operator_client: APIClient) -> None:
    """Quarantined / stale hosts must not inflate a region's sellable capacity."""
    from datetime import timedelta

    _located(1, "FR")
    stale = _located(2, "FR")
    stale.miner.last_seen_at = timezone.now() - timedelta(days=3)
    stale.miner.save(update_fields=["last_seen_at"])
    _capacity(1, slots=4)
    _capacity(2, slots=8)
    row = operator_client.get(URL).json()["regions"][0]
    assert row["miners_total"] == 2 and row["miners_verified"] == 2
    assert row["node_ids"] == sorted([node_id(1), node_id(2)])  # located AND verified
    assert row["miners_dispatchable"] == 1
    assert _legacy(row["capacity"]) == {"total_units": 4, "committed_units": 0, "free_units": 4}


def test_free_units_is_summed_per_node(operator_client: APIClient) -> None:
    _located(1, "FR")
    _located(2, "FR")
    _capacity(1, slots=2)
    _capacity(2, slots=6)
    vm = make_vm("vm-a", "lease-a")
    vm_b = make_vm("vm-b", "lease-b")
    vm_c = make_vm("vm-c", "lease-c")
    make_placement(vm, node_id(1), status=PlacementStatus.BOUND.value)
    make_placement(vm_b, node_id(1), status=PlacementStatus.BOUND.value)
    make_placement(vm_c, node_id(1), status=PlacementStatus.BOUND.value)  # node 1 over-committed
    row = operator_client.get(URL).json()["regions"][0]
    # Σ max(0, total_i − load_i) = 0 + 6, not max(0, 8 − 3) = 5. An
    # over-committed node reports committed = its total (2, not 3), so
    # `total = committed + free` holds for every consumer.
    assert _legacy(row["capacity"]) == {"total_units": 8, "committed_units": 2, "free_units": 6}


def test_a_stale_row_is_not_in_any_region(operator_client: APIClient, settings) -> None:
    from datetime import timedelta

    settings.VALI_GEO_MAX_AGE_S = 3600
    old = _located(1, "FR")
    old.observed_at = timezone.now() - timedelta(hours=3)
    old.save(update_fields=["observed_at"])
    body = operator_client.get(URL).json()
    assert body["regions"] == []
    assert body["unlocated_miners"] == 1


def test_the_server_setting_is_the_default(operator_client: APIClient, settings) -> None:
    settings.VALI_GEO_REQUIRE_VERIFIED = False
    _located(2, "FR", verdict=LocationVerdict.UNVERIFIED)
    body = operator_client.get(URL).json()
    assert body["require_verified"] is False
    assert body["regions"][0]["node_ids"] == [node_id(2)]


def test_unlocated_miners_counts_bridged_identities_without_a_row(
    operator_client: APIClient,
) -> None:
    _located(1, "FR")
    make_dispatchable_identity(2)  # registered, never probed
    unknown = make_dispatchable_identity(3)  # probed, nothing found yet
    MinerLocation.objects.create(
        miner=unknown, verdict=LocationVerdict.UNKNOWN, observed_at=timezone.now()
    )
    body = operator_client.get(URL).json()
    assert body["unlocated_miners"] == 2
    assert [r["region"] for r in body["regions"]] == ["FR"]


def test_query_count_does_not_grow_with_miner_count(operator_client: APIClient) -> None:
    from django.db import connection
    from django.test.utils import CaptureQueriesContext

    for s in range(1, 4):
        _located(s, "FR")
        _capacity(s)
    with CaptureQueriesContext(connection) as few:
        assert operator_client.get(URL).status_code == 200
    for s in range(4, 40):
        _located(s, "DE" if s % 2 else "FR")
        _capacity(s)
    with CaptureQueriesContext(connection) as many:
        assert operator_client.get(URL).status_code == 200
    assert len(many) == len(few)
