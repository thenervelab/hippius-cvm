"""#1638: a pool off its filesystem while it holds VMs is measured (since
when, how many VMs) and pushed for an alert."""

from __future__ import annotations

from datetime import timedelta
from typing import Any

import pytest
from django.conf import settings
from django.utils import timezone

from apps.disktier import pool_health
from apps.disktier.ingest import record_storage_report
from apps.disktier.models import OS_SLOT, MinerStoragePool, PlacementDisk
from apps.orchestration.tests.factories import make_vm
from apps.scheduler.models import PlacementStatus
from apps.scheduler.tests.factories import make_placement, node_id

from .test_ingest import pool, report

pytestmark = pytest.mark.django_db

NODE = node_id(1)


def _row(pool_id: str = "nvme0") -> MinerStoragePool:
    return MinerStoragePool.objects.get(miner_node_id=NODE, pool_id=pool_id)


def _vm_on(name: str, pool_id: str | None, status: str = PlacementStatus.BOUND.value) -> None:
    placement = make_placement(
        make_vm(name),
        NODE,
        status=status,
        resource_class="small",
        reason="migrated:elsewhere" if status == PlacementStatus.MIGRATED.value else None,
    )
    if pool_id is not None:
        PlacementDisk.objects.create(
            placement=placement,
            slot=OS_SLOT,
            kind="pool",
            pool_id=pool_id,
            size_gb=50,
            required_tier="nvme",
        )


def test_unavailable_since_holds_across_reports_and_clears_on_return() -> None:
    t0 = timezone.now()
    dead = pool("nvme0", state="unavailable", error="pool-unbound", committed_gb=0)
    record_storage_report(NODE, report([pool(), dead]), t0)
    assert _row().unavailable_since == t0
    record_storage_report(NODE, report([pool(), dead]), t0 + timedelta(minutes=5))
    assert _row().unavailable_since == t0, "no break: the first report stays"
    record_storage_report(NODE, report([pool(), pool("nvme0")]), t0 + timedelta(minutes=6))
    assert _row().unavailable_since is None
    record_storage_report(NODE, report([pool(), dead]), t0 + timedelta(minutes=7))
    assert _row().unavailable_since == t0 + timedelta(minutes=7)
    assert _row("default").unavailable_since is None
    # Another reason: another outage, its own clock.
    other = pool("nvme0", state="unavailable", error="pool-fs-changed", committed_gb=0)
    record_storage_report(NODE, report([pool(), other]), t0 + timedelta(minutes=9))
    assert _row().unavailable_since == t0 + timedelta(minutes=9)


def test_only_pools_off_their_filesystem_holding_vms_are_listed() -> None:
    t0 = timezone.now()
    record_storage_report(
        NODE,
        report(
            [
                pool("default", state="unavailable", error="pool-fs-changed", committed_gb=40),
                pool("nvme0", state="unavailable", error="pool-unbound", committed_gb=0),
                pool("hdd0", state="unavailable", error="pool-not-a-mount", committed_gb=0),
                pool("ssd0", state="unavailable", error="pool-fs-changed", committed_gb=120),
                pool(
                    "nvme1",
                    state="unavailable",
                    error="pool-budget-below-committed",
                    committed_gb=300,
                ),
            ]
        ),
        t0,
    )
    _vm_on("vm-nvme0", "nvme0")
    _vm_on("vm-nvme0-b", "nvme0")
    _vm_on("vm-gone", "hdd0", status=PlacementStatus.MIGRATED.value)
    listed = {p.pool_id: p for p in pool_health.unavailable_holding_vms()}
    # hdd0 holds nothing (its placement left); default is never held for
    # its binding; nvme1 is closed to new disks only.
    assert set(listed) == {"nvme0", "ssd0"}
    assert (listed["nvme0"].vms, listed["nvme0"].error, listed["nvme0"].since) == (
        2,
        "pool-unbound",
        t0,
    )
    # Committed by the node's own count, even without a vali placement.
    assert (listed["ssd0"].vms, listed["ssd0"].committed_gb) == (0, 120)


def test_a_node_that_stopped_reporting_raises_nothing() -> None:
    old = timezone.now() - timedelta(hours=1)
    record_storage_report(
        NODE, report([pool(), pool("nvme0", state="unavailable", error="pool-unbound")]), old
    )
    assert pool_health.unavailable_holding_vms() == []


def test_vms_on_default_count_placements_without_a_disk_row() -> None:
    _vm_on("vm-legacy", None)
    _vm_on("vm-default", "default")
    _vm_on("vm-nvme0", "nvme0")
    assert pool_health.placed_vms(NODE, "default") == 2
    assert pool_health.placed_vms(NODE, "nvme0") == 1


def test_a_retired_pool_forgets_its_since() -> None:
    t0 = timezone.now()
    dead = pool("nvme0", state="unavailable", error="pool-unbound")
    record_storage_report(NODE, report([pool(), dead]), t0)
    record_storage_report(NODE, report([pool()]), t0 + timedelta(minutes=1))
    assert _row().unavailable_since is None and _row().retired_at is not None


def test_the_survey_pushes_since_and_vms(monkeypatch: pytest.MonkeyPatch) -> None:
    from apps.scheduler.management.commands import vali_scheduler_reeval
    from apps.synthetic import metrics

    t0 = timezone.now() - timedelta(minutes=30)
    dead = report([pool(), pool("nvme0", state="unavailable", error="pool-unbound")])
    record_storage_report(NODE, dead, t0)
    record_storage_report(NODE, dead, timezone.now())
    _vm_on("vm-nvme0", "nvme0")
    pushed: list[Any] = []
    monkeypatch.setattr(settings, "VALI_SYNTHETIC_PUSHGATEWAY_URL", "http://gw.invalid")
    monkeypatch.setattr(metrics, "push", lambda ms, **kw: pushed.append((ms, kw)) or True)
    vali_scheduler_reeval.storage_config_survey()
    ms, kw = pushed[0]
    assert kw["job"] == "vali-storage-config"
    by_name = {}
    for s in ms.samples:
        by_name.setdefault(s.name, []).append(s)
    [since] = by_name["hippius_storage_pool_unavailable_since_seconds"]
    assert since.labels == {"node_id": NODE, "pool": "nvme0", "error": "pool-unbound"}
    assert since.value == int(t0.timestamp())
    [vms] = by_name["hippius_storage_pool_unavailable_vms"]
    assert vms.value == 1
    assert "hippius_storage_survey_timestamp_seconds" in by_name
