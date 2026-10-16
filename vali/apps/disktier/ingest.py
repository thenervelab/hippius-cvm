"""Record a miner's `v7` storage report (docs/design/disk-tier-verification.md
§4, §9) — RECORD ONLY.

The report is an untrusted self-report: it fills the miner-reported columns
of `MinerStoragePool` / `DedicatedDisk` (and the reported revision of a
node's `MinerStorageConfig`) and nothing else. It never sets a
tier, a health, a vali-side disk state or an assignment, and nothing reads
these rows for placement yet.

- A reported pool is upserted and un-retired; a known pool missing from
  the report is marked retired (its rows stay, so committed disks stay
  accounted once anything reads them).
- The report's `storage_config_revision` lands on the node's
  `MinerStorageConfig`, when it has one (`apps.disktier.storage_config`).
- A reported dedicated disk is created on first sight in `pending_probe`
  (vali's own state machine starts there); later reports only refresh the
  reported columns and the size. A disk missing from the report is left
  alone: vali alone decides when a disk leaves its inventory.

Sizes follow the `v4` convention: `0` on the wire is "unknown" (NULL), a
value above the column's range is not a real host (NULL), and an
`available` of 0 next to a known total is a full disk (kept).
"""

from __future__ import annotations

from datetime import datetime

from django.db import transaction

from apps.telemetry.verifier import DeclaredStorage

from .models import DedicatedDisk, MinerStoragePool
from .storage_config import desired_disk_states, record_reported_revision

_MIB = 1024 * 1024
# The `PositiveIntegerField` range shared by every backend.
_GB_MAX = 2_147_483_647
# The `PositiveBigIntegerField` range.
_BYTES_MAX = 9_223_372_036_854_775_807


def _known(value: int) -> int | None:
    return value if 0 < value <= _GB_MAX else None


def _available(value: int, total: int | None) -> int | None:
    if value == 0 and total is not None:
        return 0
    return _known(value)


def record_storage_report(node_id: str, report: DeclaredStorage, now: datetime) -> None:
    """Upsert `node_id`'s pools and dedicated disks from `report`."""
    with transaction.atomic():
        reported_pools = set()
        for pool in report.pools:
            reported_pools.add(pool.pool_id)
            total = _known(pool.total_gb)
            MinerStoragePool.objects.update_or_create(
                miner_node_id=node_id,
                pool_id=pool.pool_id,
                defaults={
                    "declared_class": pool.declared_class,
                    "os_disks": pool.os_disks,
                    "total_gb": total,
                    "available_gb": _available(pool.available_gb, total),
                    "budget_gb": _known(pool.budget_gb),
                    "committed_gb": pool.committed_gb if pool.committed_gb <= _GB_MAX else None,
                    "reported_state": pool.state,
                    "reported_error": pool.error,
                    "reported_at": now,
                    "retired_at": None,
                },
            )
        MinerStoragePool.objects.filter(miner_node_id=node_id, retired_at__isnull=True).exclude(
            pool_id__in=reported_pools
        ).update(retired_at=now)

        # A disk first seen after the desired document named it takes the
        # document's state from the start (a `draining` declaration must
        # not read as `active` until the next write).
        desired = desired_disk_states(node_id)
        for disk in report.dedicated_disks:
            reported = {
                "size_bytes": (
                    disk.size_mb * _MIB if 0 < disk.size_mb * _MIB <= _BYTES_MAX else None
                ),
                "reported_state": disk.state,
                "reported_error": disk.error,
                "reported_vm_id": disk.vm,
                "reported_at": now,
            }
            row, created = DedicatedDisk.objects.get_or_create(
                miner_node_id=node_id,
                disk_id=disk.disk_id,
                defaults={
                    **reported,
                    "declared_at": now,
                    "desired_state": desired.get(disk.disk_id, "active"),
                },
            )
            if not created:
                DedicatedDisk.objects.filter(pk=row.pk).update(**reported)

        # The revision of the vali-pushed document the agent has in force
        # (0 = its local config): the storage-config sync status and drift
        # repair read it. Only a node with a desired document keeps it.
        record_reported_revision(node_id, report.storage_config_revision, now)
