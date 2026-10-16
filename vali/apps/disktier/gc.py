"""Retention of the passive disk tables (`vali_disktier_gc`, design §4.3).

- `VmDiskIoHourly` past `VALI_DISK_IO_RETENTION_DAYS` (30 d);
- `MinerDiskHealthHourly` and `DiskPassiveEvent` past
  `VALI_DISK_HEALTH_RETENTION_DAYS` (180 d);
- `DiskIoReceipt` once older than any receipt the ingest still accepts
  (`ingest.dedupe_keep`): past that, a replay is refused by its age.

Bounded: each table is reaped in DELETEs of at most `VALI_DISK_GC_BATCH`
rows, at most `VALI_DISK_GC_MAX_BATCHES` per table and run; the next run
carries on."""

from __future__ import annotations

from datetime import datetime, timedelta

from django.conf import settings
from django.db import models
from django.utils import timezone

from .ingest import dedupe_keep
from .models import DiskIoReceipt, DiskPassiveEvent, MinerDiskHealthHourly, VmDiskIoHourly


def _reap(
    model: type[models.Model], field: str, cutoff: datetime, *, batch: int, batches: int
) -> int:
    deleted = 0
    for _ in range(batches):
        ids = list(
            model.objects.filter(**{f"{field}__lt": cutoff})
            .order_by("pk")
            .values_list("pk", flat=True)[:batch]
        )
        if not ids:
            break
        n, _ = model.objects.filter(pk__in=ids).delete()
        deleted += n
        if len(ids) < batch:
            break
    return deleted


def gc(*, now: datetime | None = None) -> dict[str, int]:
    """One bounded sweep; returns the rows deleted per table."""
    now = now or timezone.now()
    batch = max(1, int(settings.VALI_DISK_GC_BATCH))
    batches = max(1, int(settings.VALI_DISK_GC_MAX_BATCHES))
    io_cutoff = now - timedelta(days=int(settings.VALI_DISK_IO_RETENTION_DAYS))
    health_cutoff = now - timedelta(days=int(settings.VALI_DISK_HEALTH_RETENTION_DAYS))
    plan: list[tuple[str, type[models.Model], str, datetime]] = [
        ("vm_disk_io_hourly", VmDiskIoHourly, "hour", io_cutoff),
        ("miner_disk_health_hourly", MinerDiskHealthHourly, "hour", health_cutoff),
        ("disk_passive_event", DiskPassiveEvent, "created_at", health_cutoff),
        ("disk_io_receipt", DiskIoReceipt, "ingested_at", now - dedupe_keep()),
    ]
    return {
        name: _reap(model, field, cutoff, batch=batch, batches=batches)
        for name, model, field, cutoff in plan
    }
