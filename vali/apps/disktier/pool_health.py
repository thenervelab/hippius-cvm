"""Pools off their filesystem while they hold VMs (#1638).

A pool bound by device number (`dev:<st_dev>:<root>`, when no filesystem
UUID is readable) can stay unbound for good on LVM / md RAID whose minor
number changes across a reboot: every VM recorded there then gets a
retryable `relaunch-disks-unreadable/pool-not-mounted` forever, and
nothing else says so. The node reports such a pool `unavailable` (its
`reported_error` says why: `pool-unbound`, `pool-fs-changed`,
`pool-not-a-mount`, …); vali keeps since when (`unavailable_since`, at
ingest) and counts the VMs it places there. The orchestration survey
pushes it (`hippius_storage_pool_unavailable_since_seconds`), and an alert
fires past N minutes (docs/operator/onboarding-a-miner.md, "Storage
pools").
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from django.db.models import Exists, OuterRef
from django.utils import timezone

from .models import OS_SLOT, MinerStoragePool, PlacementDisk
from .routing import DEFAULT_POOL_ID, REPORT_MAX_AGE

#: The pool errors that keep the agent from relaunching a VM recorded on
#: the pool (`relaunch-disks-unreadable/pool-not-mounted`: the pool is not
#: on the filesystem it is bound to). Budget / permission / layout errors
#: only close the pool to NEW disks.
OFF_FILESYSTEM_ERRORS = frozenset(
    {"pool-unbound", "pool-fs-changed", "pool-not-a-mount", "pool-path-missing"}
)


@dataclass(frozen=True)
class UnavailablePool:
    node_id: str
    pool_id: str
    error: str
    since: datetime
    #: VMs vali places on the pool (active placements).
    vms: int
    #: What the node reports committed there (`None`: out of range).
    committed_gb: int | None


def placed_vms(node_id: str, pool_id: str) -> int:
    """Active placements of `node_id` whose OS disk is on `pool_id` (a
    placement without a disk row is on `default`)."""
    from apps.scheduler.models import ACTIVE_PLACEMENT_STATES, Placement

    active = Placement.objects.filter(
        miner_node_id=node_id, status__in=list(ACTIVE_PLACEMENT_STATES)
    )
    on_pool = active.filter(disks__slot=OS_SLOT, disks__pool_id=pool_id)
    count = on_pool.distinct().count()
    if pool_id == "default":
        has_row = PlacementDisk.objects.filter(placement=OuterRef("pk"), slot=OS_SLOT)
        count += active.exclude(Exists(has_row)).count()
    return count


def unavailable_holding_vms() -> list[UnavailablePool]:
    """Every pool a node currently reports off its filesystem (an
    `OFF_FILESYSTEM_ERRORS` error, a report younger than `REPORT_MAX_AGE`:
    a node that stopped reporting says nothing) that still holds VMs:
    placed by vali, or committed by the node's own count. Never `default`:
    the agent does not hold a VM on it for its binding."""
    out: list[UnavailablePool] = []
    for pool in (
        MinerStoragePool.objects.filter(
            retired_at__isnull=True,
            reported_state="unavailable",
            reported_error__in=sorted(OFF_FILESYSTEM_ERRORS),
            unavailable_since__isnull=False,
            reported_at__gte=timezone.now() - REPORT_MAX_AGE,
        )
        .exclude(pool_id=DEFAULT_POOL_ID)
        .order_by("miner_node_id", "pool_id")
    ):
        vms = placed_vms(pool.miner_node_id, pool.pool_id)
        holds = vms > 0 or pool.committed_gb is None or pool.committed_gb > 0
        if not holds:
            continue
        assert pool.unavailable_since is not None
        out.append(
            UnavailablePool(
                node_id=pool.miner_node_id,
                pool_id=pool.pool_id,
                error=pool.reported_error,
                since=pool.unavailable_since,
                vms=vms,
                committed_gb=pool.committed_gb,
            )
        )
    return out
