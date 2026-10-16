"""`vali_disktier_gc` — retention of the passive disk tables, in bounded
batches — and the shape of the P1/P2 migration (additive only)."""

from __future__ import annotations

import importlib
from datetime import UTC, datetime, timedelta
from io import StringIO
from typing import Any

import pytest
from django.core.management import call_command
from django.db import migrations

from apps.disktier import gc
from apps.disktier.models import (
    DiskIoReceipt,
    DiskPassiveEvent,
    MinerDiskHealthHourly,
    VmDiskIoHourly,
)
from apps.scheduler.tests.factories import node_id

pytestmark = pytest.mark.django_db

NODE = node_id(1)
NOW = datetime(2026, 10, 16, 12, tzinfo=UTC)


def _seed(age: timedelta, n: int = 1) -> None:
    at = NOW - age
    for i in range(n):
        VmDiskIoHourly.objects.create(
            vm_id=f"vm-{age.days}-{i}", miner_node_id=NODE, device="vdb", hour=at
        )
        MinerDiskHealthHourly.objects.create(
            miner_node_id=NODE, pool_id=f"p{age.days}-{i}", hour=at
        )
        DiskPassiveEvent.objects.create(
            miner_node_id=NODE, hour=at, kind="would-reprobe", created_at=at
        )
        DiskIoReceipt.objects.create(
            receipt_digest=f"{age.days:08d}{i:056d}", vm_id="vm", ingested_at=at
        )


def test_each_table_keeps_its_retention() -> None:
    _seed(timedelta(hours=1))
    _seed(timedelta(days=2))
    _seed(timedelta(days=31))
    _seed(timedelta(days=181))
    deleted = gc.gc(now=NOW)
    assert deleted == {
        "vm_disk_io_hourly": 2,
        "miner_disk_health_hourly": 1,
        "disk_passive_event": 1,
        # Only the 1-hour-old dedupe row can still stop a replay.
        "disk_io_receipt": 3,
    }
    assert VmDiskIoHourly.objects.count() == 2
    assert MinerDiskHealthHourly.objects.count() == 3
    assert DiskIoReceipt.objects.count() == 1


def test_gc_is_bounded_and_carries_on(settings: Any) -> None:
    settings.VALI_DISK_GC_BATCH = 2
    settings.VALI_DISK_GC_MAX_BATCHES = 2
    _seed(timedelta(days=200), n=7)
    first = gc.gc(now=NOW)
    assert first["vm_disk_io_hourly"] == 4
    assert gc.gc(now=NOW)["vm_disk_io_hourly"] == 3
    assert gc.gc(now=NOW)["vm_disk_io_hourly"] == 0
    assert not MinerDiskHealthHourly.objects.exists()


def test_the_command_reports() -> None:
    out = StringIO()
    call_command("vali_disktier_gc", stdout=out)
    assert "vm_disk_io_hourly=0" in out.getvalue()


def test_the_passive_migration_is_additive() -> None:
    mod = importlib.import_module("apps.disktier.migrations.0004_passive_ingest")
    allowed = (migrations.CreateModel, migrations.AddField, migrations.AddIndex)
    for op in mod.Migration.operations:
        assert isinstance(op, allowed), op
        if isinstance(op, migrations.AddField):
            # A new column on an existing table must not need a backfill.
            assert op.field.null or op.field.has_default() or op.field.db_default, op
