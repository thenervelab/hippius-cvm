"""`apps.disktier.ingest.record_storage_report` — the record-only write of a
`v7` heartbeat's storage report."""

from __future__ import annotations

from datetime import timedelta

import pytest
from django.utils import timezone

from apps.disktier.ingest import record_storage_report
from apps.disktier.models import DedicatedDisk, MinerStoragePool
from apps.scheduler.tests.factories import node_id
from apps.telemetry.verifier import DeclaredDedicatedDisk, DeclaredPool, DeclaredStorage

pytestmark = pytest.mark.django_db

NODE = node_id(1)


def pool(pool_id: str = "default", **overrides: object) -> DeclaredPool:
    fields: dict[str, object] = {
        "pool_id": pool_id,
        "declared_class": "nvme",
        "total_gb": 3500,
        "available_gb": 2900,
        "budget_gb": 3000,
        "committed_gb": 400,
        "os_disks": True,
        "state": "active",
        "error": "",
    }
    fields.update(overrides)
    return DeclaredPool(**fields)  # type: ignore[arg-type]


def disk(disk_id: str = "wwn-0x1", **overrides: object) -> DeclaredDedicatedDisk:
    fields: dict[str, object] = {
        "disk_id": disk_id,
        "size_mb": 17_166_336,
        "state": "free",
        "vm": "",
        "error": "",
    }
    fields.update(overrides)
    return DeclaredDedicatedDisk(**fields)  # type: ignore[arg-type]


def report(pools=(), disks=(), revision: int = 0) -> DeclaredStorage:
    return DeclaredStorage(
        pools=tuple(pools) or (pool(),),
        dedicated_disks=tuple(disks),
        storage_config_revision=revision,
    )


def test_pools_are_recorded() -> None:
    now = timezone.now()
    record_storage_report(
        NODE,
        report(
            [
                pool(),
                pool(
                    "hdd0",
                    declared_class="hdd",
                    os_disks=False,
                    state="draining",
                    error="pool-not-a-mount",
                ),
            ]
        ),
        now,
    )
    default, hdd0 = MinerStoragePool.objects.filter(miner_node_id=NODE).order_by("pool_id")
    assert (default.pool_id, default.declared_class, default.os_disks) == ("default", "nvme", True)
    assert (default.total_gb, default.available_gb, default.budget_gb) == (3500, 2900, 3000)
    assert default.committed_gb == 400
    assert default.reported_state == "active"
    assert default.reported_at == now
    assert hdd0.reported_state == "draining"
    assert hdd0.reported_error == "pool-not-a-mount"
    assert hdd0.os_disks is False


def test_the_report_never_sets_a_tier_or_health() -> None:
    record_storage_report(NODE, report(), timezone.now())
    p = MinerStoragePool.objects.get(miner_node_id=NODE)
    assert p.tier == "unknown"
    assert p.health == "ok"
    assert p.operator_override == ""


def test_a_later_report_updates_without_touching_vali_columns() -> None:
    record_storage_report(NODE, report(), timezone.now())
    MinerStoragePool.objects.filter(miner_node_id=NODE).update(
        tier="nvme", operator_override="ssd", override_reason="r"
    )
    record_storage_report(NODE, report([pool(available_gb=100)]), timezone.now())
    p = MinerStoragePool.objects.get(miner_node_id=NODE)
    assert p.available_gb == 100
    assert (p.tier, p.operator_override, p.override_reason) == ("nvme", "ssd", "r")


def test_zero_is_unknown_and_a_full_disk_is_kept() -> None:
    record_storage_report(
        NODE, report([pool(total_gb=0, available_gb=0, budget_gb=0)]), timezone.now()
    )
    p = MinerStoragePool.objects.get(miner_node_id=NODE)
    assert (p.total_gb, p.available_gb, p.budget_gb) == (None, None, None)
    record_storage_report(NODE, report([pool(available_gb=0)]), timezone.now())
    p.refresh_from_db()
    assert (p.total_gb, p.available_gb) == (3500, 0)


def test_a_pool_left_out_is_retired_and_comes_back() -> None:
    t0 = timezone.now()
    record_storage_report(NODE, report([pool(), pool("hdd0")]), t0)
    t1 = t0 + timedelta(minutes=1)
    record_storage_report(NODE, report([pool()]), t1)
    hdd0 = MinerStoragePool.objects.get(miner_node_id=NODE, pool_id="hdd0")
    assert hdd0.retired_at == t1
    # A second report without it keeps the first retirement instant.
    record_storage_report(NODE, report([pool()]), t1 + timedelta(minutes=1))
    hdd0.refresh_from_db()
    assert hdd0.retired_at == t1
    record_storage_report(NODE, report([pool(), pool("hdd0")]), t1 + timedelta(minutes=2))
    hdd0.refresh_from_db()
    assert hdd0.retired_at is None
    assert MinerStoragePool.objects.get(miner_node_id=NODE, pool_id="default").retired_at is None


def test_another_nodes_pools_are_untouched() -> None:
    other = node_id(2)
    record_storage_report(other, report([pool("hdd0")]), timezone.now())
    record_storage_report(NODE, report([pool()]), timezone.now())
    assert MinerStoragePool.objects.get(miner_node_id=other).retired_at is None


def test_dedicated_disks_start_pending_probe_and_keep_vali_state() -> None:
    t0 = timezone.now()
    record_storage_report(NODE, report(disks=[disk(state="assigned", vm="vm-9")]), t0)
    d = DedicatedDisk.objects.get(miner_node_id=NODE, disk_id="wwn-0x1")
    assert d.state == "pending_probe"
    assert d.verified_tier == "unknown"
    assert d.assigned_vm is None  # the agent's view is not an assignment
    assert (d.reported_state, d.reported_vm_id) == ("assigned", "vm-9")
    assert d.size_bytes == 17_166_336 * 1024 * 1024
    assert d.declared_at == t0

    DedicatedDisk.objects.filter(pk=d.pk).update(state="free", verified_tier="hdd")
    t1 = t0 + timedelta(minutes=1)
    record_storage_report(NODE, report(disks=[disk(state="failed", error="disk-not-found")]), t1)
    d.refresh_from_db()
    assert (d.state, d.verified_tier) == ("free", "hdd")
    assert (d.reported_state, d.reported_error, d.reported_vm_id) == (
        "failed",
        "disk-not-found",
        "",
    )
    assert d.reported_at == t1
    assert d.declared_at == t0


def test_a_disk_left_out_is_left_alone() -> None:
    record_storage_report(NODE, report(disks=[disk()]), timezone.now())
    record_storage_report(NODE, report(), timezone.now())
    assert DedicatedDisk.objects.get(miner_node_id=NODE).state == "pending_probe"


def test_an_out_of_range_size_is_unknown() -> None:
    record_storage_report(
        NODE, report([pool(total_gb=2**32 - 1)], [disk(size_mb=2**64 - 1)]), timezone.now()
    )
    assert MinerStoragePool.objects.get(miner_node_id=NODE).total_gb is None
    assert DedicatedDisk.objects.get(miner_node_id=NODE).size_bytes is None


def test_an_unknown_disk_size_is_stored_as_unknown() -> None:
    record_storage_report(NODE, report(disks=[disk(size_mb=0)]), timezone.now())
    assert DedicatedDisk.objects.get(miner_node_id=NODE).size_bytes is None
