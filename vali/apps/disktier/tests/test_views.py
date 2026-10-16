"""`GET /v1/operator/disk-profiles`."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from django.urls import reverse
from rest_framework.test import APIClient

from apps.disktier.models import DedicatedDisk, MinerStoragePool
from apps.lifecycle.models import Vm
from apps.scheduler.tests.factories import make_vm, node_id

pytestmark = pytest.mark.django_db

URL = reverse("operator_disk_profiles")

POOL_KEYS = {
    "pool_id",
    "declared_class",
    "os_disks",
    "total_gb",
    "available_gb",
    "budget_gb",
    "reported_at",
    "tier",
    "tier_since_on",
    "operator_override",
    "override_reason",
    "effective_tier",
    "health",
    "health_since_on",
    "next_probe_due_on",
    "retired",
}
DISK_KEYS = {
    "disk_id",
    "size_bytes",
    "desired_state",
    "state",
    "verified_tier",
    "last_probed_on",
    "behind_controller",
    "assigned",
}


def _pool(seed: int, pool_id: str = "default", **fields: object) -> MinerStoragePool:
    return MinerStoragePool.objects.create(miner_node_id=node_id(seed), pool_id=pool_id, **fields)


def _assigned_disk(seed: int, vm: Vm) -> DedicatedDisk:
    return DedicatedDisk.objects.create(
        miner_node_id=node_id(seed),
        disk_id="wwn-0x5000c500a1b2c3d4",
        size_bytes=18_000_207_937_536,
        state="assigned",
        verified_tier="hdd",
        assigned_vm=vm,
        assigned_slot="x0",
        probed_at=datetime(2026, 10, 14, 3, 17, 42, tzinfo=UTC),
    )


# ─── auth / scope ────────────────────────────────────────────────────


def test_unauthenticated_is_refused() -> None:
    assert APIClient().get(URL, {"node_id": node_id(1)}).status_code in (401, 403)


def test_tenant_principal_is_refused(tenant_client: APIClient) -> None:
    _pool(1)
    assert tenant_client.get(URL, {"node_id": node_id(1)}).status_code == 403


def test_operator_principal_is_served(operator_client: APIClient) -> None:
    assert operator_client.get(URL, {"node_id": node_id(1)}).status_code == 200


def test_only_get(operator_client: APIClient) -> None:
    assert operator_client.post(URL, {}, format="json").status_code == 405


# ─── shape ───────────────────────────────────────────────────────────


def test_no_rows_is_an_empty_list(operator_client: APIClient) -> None:
    assert operator_client.get(URL, {"node_id": node_id(1)}).json() == {"nodes": [], "count": 0}


def test_missing_node_id_is_400_never_the_whole_fleet(operator_client: APIClient) -> None:
    _pool(1)
    _pool(2)
    resp = operator_client.get(URL)
    assert resp.status_code == 400
    assert resp.json()["category"] == "wire"
    assert node_id(1) not in resp.content.decode()


def test_pools_and_disks_per_node(operator_client: APIClient) -> None:
    _pool(
        1,
        "nvme0",
        declared_class="nvme",
        total_gb=3500,
        available_gb=2900,
        budget_gb=3000,
        tier="nvme",
        tier_since=datetime(2026, 10, 1, 9, 30, tzinfo=UTC),
        next_probe_due_at=datetime(2026, 10, 20, 23, 59, tzinfo=UTC),
    )
    _pool(
        1,
        "hdd0",
        declared_class="hdd",
        os_disks=False,
        operator_override="unfit",
        override_reason="controller errors",
    )
    _assigned_disk(1, make_vm("vm-tenant-secret", "lease-secret"))
    _pool(2)

    body = operator_client.get(URL, {"node_id": [node_id(1), node_id(2)]}).json()
    assert body["count"] == 2
    first, second = body["nodes"]
    assert first["node_id"] == node_id(1)
    assert second["node_id"] == node_id(2)

    # Pools sorted by id, every key present.
    assert [p["pool_id"] for p in first["pools"]] == ["hdd0", "nvme0"]
    assert all(set(p) == POOL_KEYS for p in first["pools"])
    hdd0, nvme0 = first["pools"]
    assert nvme0["tier"] == "nvme"
    assert nvme0["effective_tier"] == "nvme"
    assert nvme0["budget_gb"] == 3000
    assert hdd0["tier"] == "unknown"
    assert hdd0["operator_override"] == "unfit"
    assert hdd0["effective_tier"] == "unfit"
    assert hdd0["os_disks"] is False

    (disk,) = first["dedicated_disks"]
    assert set(disk) == DISK_KEYS
    assert disk["state"] == "assigned"
    assert disk["assigned"] is True
    assert disk["size_bytes"] == 18_000_207_937_536

    assert second["pools"][0]["tier"] == "unknown"
    assert second["dedicated_disks"] == []


def test_probe_timing_is_served_as_a_date_only(operator_client: APIClient) -> None:
    _pool(
        1,
        tier="ssd",
        tier_since=datetime(2026, 10, 1, 9, 30, 12, tzinfo=UTC),
        health_since=datetime(2026, 10, 2, 22, 1, tzinfo=UTC),
        next_probe_due_at=datetime(2026, 10, 20, 23, 59, tzinfo=UTC),
    )
    _assigned_disk(1, make_vm("vm-a", "lease-a"))
    node = operator_client.get(URL, {"node_id": node_id(1)}).json()["nodes"][0]
    pool = node["pools"][0]
    assert pool["tier_since_on"] == "2026-10-01"
    assert pool["health_since_on"] == "2026-10-02"
    assert pool["next_probe_due_on"] == "2026-10-20"
    assert node["dedicated_disks"][0]["last_probed_on"] == "2026-10-14"


def test_no_tenant_or_probe_vm_is_named(operator_client: APIClient) -> None:
    _assigned_disk(1, make_vm("vm-tenant-secret", "lease-secret"))
    raw = operator_client.get(URL, {"node_id": node_id(1)}).content.decode()
    assert "vm-tenant-secret" not in raw
    assert "lease-secret" not in raw
    assert "assigned_vm" not in raw
    assert "assigned_slot" not in raw


# ─── node filter ─────────────────────────────────────────────────────


def test_node_filter(operator_client: APIClient) -> None:
    _pool(1)
    _pool(2)
    _pool(3)
    body = operator_client.get(URL, {"node_id": [node_id(3), node_id(1).upper()]}).json()
    assert [n["node_id"] for n in body["nodes"]] == [node_id(1), node_id(3)]


def test_unknown_node_is_absent(operator_client: APIClient) -> None:
    _pool(1)
    assert operator_client.get(URL, {"node_id": node_id(9)}).json() == {"nodes": [], "count": 0}


@pytest.mark.parametrize("bad", ["xyz", "a" * 63, " " + "a" * 64])
def test_malformed_node_id_is_400(operator_client: APIClient, bad: str) -> None:
    resp = operator_client.get(URL, {"node_id": bad})
    assert resp.status_code == 400
    assert resp.json()["category"] == "wire"


def test_too_many_node_ids_is_400(operator_client: APIClient) -> None:
    resp = operator_client.get(URL, {"node_id": [node_id(i) for i in range(101)]})
    assert resp.status_code == 400


# ─── schema ──────────────────────────────────────────────────────────


def test_published_in_the_openapi_schema(operator_client: APIClient) -> None:
    from drf_spectacular.generators import SchemaGenerator

    schema = SchemaGenerator().get_schema(request=None, public=True)
    op = schema["paths"]["/v1/operator/disk-profiles"]["get"]
    assert {"200", "400", "401", "403"} <= set(op["responses"])
