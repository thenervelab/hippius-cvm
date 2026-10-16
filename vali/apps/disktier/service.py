"""The rows `GET /v1/operator/disk-profiles` serves.

Probe timing is served at DAY granularity (`*_on` dates), never as an
instant: the upstream shows these rows to miner operators, and a miner that
can tell when the probe ran — or will run — can recognise the probe VM and
un-throttle for it (design §2). No probe vm_id, owner or tenant VM id is
served either: an assigned dedicated disk says `assigned: true`, not to
whom.
"""

from __future__ import annotations

from datetime import UTC, date, datetime
from typing import Any

from .models import DedicatedDisk, DedicatedDiskState, MinerStoragePool


def _day(at: datetime | None) -> date | None:
    return at.astimezone(UTC).date() if at is not None else None


def _pool_row(pool: MinerStoragePool) -> dict[str, Any]:
    return {
        "pool_id": pool.pool_id,
        "declared_class": pool.declared_class,
        "os_disks": pool.os_disks,
        "total_gb": pool.total_gb,
        "available_gb": pool.available_gb,
        "budget_gb": pool.budget_gb,
        "reported_at": pool.reported_at,
        "tier": pool.tier,
        "tier_since_on": _day(pool.tier_since),
        "operator_override": pool.operator_override,
        "override_reason": pool.override_reason,
        "effective_tier": pool.effective_tier,
        "health": pool.health,
        "health_since_on": _day(pool.health_since),
        "next_probe_due_on": _day(pool.next_probe_due_at),
        "retired": pool.retired_at is not None,
    }


def _disk_row(disk: DedicatedDisk) -> dict[str, Any]:
    return {
        "disk_id": disk.disk_id,
        "size_bytes": disk.size_bytes,
        "desired_state": disk.desired_state,
        "state": disk.state,
        "verified_tier": disk.verified_tier,
        "last_probed_on": _day(disk.probed_at),
        "behind_controller": disk.behind_controller,
        "assigned": disk.state == DedicatedDiskState.ASSIGNED,
    }


def disk_profile_rows(node_ids: list[str]) -> list[dict[str, Any]]:
    """One row per requested node that has at least one pool or dedicated
    disk row, sorted by node id. An unknown node is absent, not an error."""
    pools = MinerStoragePool.objects.filter(miner_node_id__in=node_ids)
    disks = DedicatedDisk.objects.filter(miner_node_id__in=node_ids)
    by_node: dict[str, dict[str, list[dict[str, Any]]]] = {}
    for pool in pools.order_by("miner_node_id", "pool_id"):
        by_node.setdefault(pool.miner_node_id, {"pools": [], "dedicated_disks": []})
        by_node[pool.miner_node_id]["pools"].append(_pool_row(pool))
    for disk in disks.order_by("miner_node_id", "disk_id"):
        by_node.setdefault(disk.miner_node_id, {"pools": [], "dedicated_disks": []})
        by_node[disk.miner_node_id]["dedicated_disks"].append(_disk_row(disk))
    return [{"node_id": node, **by_node[node]} for node in sorted(by_node)]
