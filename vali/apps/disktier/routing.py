"""A4b: the storage pool a FIRST golden launch (or a §25 arrival) puts the
VM's OS disk on.

The miner decides nothing: vali names the pool in the order (`os_pool`),
the agent admits it (not draining, takes OS disks, active, bound) or
refuses `pool-unavailable:<pool>` / `insufficient-disk:<pool>` (507, which
re-places without counting against the host). A VM that already ran keeps
the pool its record names on the miner, whatever an order says, so vali
never sends `os_pool` on a relaunch.

Only to an agent at or above `VALI_POOL_ROUTING_MIN_AGENT_VERSION` (empty =
nobody): an older one refuses the key. `None` ⇒ the key is not sent and the
disk lands on `default`, byte for byte today's order.
"""

from __future__ import annotations

from datetime import timedelta

from django.conf import settings
from django.db.models import QuerySet
from django.utils import timezone

from .models import DeclaredClass, DiskHealth, MinerStoragePool
from .storage_config import agent_version, version_at_least
from .tiers import DiskTier

DEFAULT_POOL_ID = "default"
#: A pool report older than this is not routed to: the node may have
#: stopped reporting it (a v7 heartbeat that no longer carries pools).
REPORT_MAX_AGE = timedelta(minutes=15)


def supported(node_id: str) -> bool:
    """The node's agent takes `os_pool`."""
    minimum = str(getattr(settings, "VALI_POOL_ROUTING_MIN_AGENT_VERSION", "") or "")
    return bool(node_id) and version_at_least(agent_version(node_id), minimum)


def free_gb(pool: MinerStoragePool) -> int | None:
    """What the pool can still take: the smaller of its reported free space,
    its budget left and its earned ceiling left (vali's own). `None` when
    unknown."""
    if pool.available_gb is None:
        return None
    free = int(pool.available_gb)
    committed = int(pool.committed_gb or 0)
    for ceiling in (pool.budget_gb, pool.earned_gb):
        if ceiling:
            free = min(free, int(ceiling) - committed)
    return max(free, 0)


def sold_class_as_os_disk(pool: MinerStoragePool) -> bool:
    """The operator-side half of `sold_as_os_disk_tier`, without anything a
    probe verdict writes (`tier`, `health`): the pool is declared nvme, or
    the operator overrode it to nvme; an override to anything else wins
    over the declaration. What a pool is SOLD as, before any probe says
    whether it lives up to it."""
    if pool.operator_override:
        return pool.operator_override == DiskTier.NVME
    return pool.declared_class == DeclaredClass.NVME


def sold_as_os_disk_tier(pool: MinerStoragePool) -> bool:
    """The pool is what every OS disk is sold as today (nvme): verified (or
    overridden) nvme, or not probed yet and declared nvme — the probes (G3)
    demote a pool that is not. Healthy (`ok`, or only `suspect` pending a
    probe): a probe that fell below the floor (`degraded`) or worse is out."""
    tier = pool.effective_tier
    nvme = tier == DiskTier.NVME or (
        tier == DiskTier.UNKNOWN and pool.declared_class == DeclaredClass.NVME
    )
    return nvme and pool.health in (DiskHealth.OK, DiskHealth.SUSPECT)


def os_disk_pools(node_id: str) -> QuerySet[MinerStoragePool]:
    """The node's pools an order may name as `os_pool`: active, recently
    reported, not retired, taking OS disks (the agent admits the rest).
    Whatever their tier or health: the probe (`apps.disktier.probe`)
    measures exactly those; `choose_os_pool` narrows to the sold tier."""
    return MinerStoragePool.objects.filter(
        miner_node_id=node_id,
        retired_at__isnull=True,
        os_disks=True,
        reported_state="active",
        reported_at__gte=timezone.now() - REPORT_MAX_AGE,
    )


def choose_os_pool(node_id: str, need_gb: int) -> str | None:
    """The pool other than `default` to put a `need_gb` OS disk on: the
    node's active, recently reported, not retired, OS-disk pool of the sold
    tier with room for it and the most free, ties by id. `None` (⇒
    `default`) when the agent does not take `os_pool`, or no such pool has
    room."""
    if not supported(node_id):
        return None
    best: tuple[int, str] | None = None
    for pool in os_disk_pools(node_id).exclude(pool_id=DEFAULT_POOL_ID):
        if not sold_as_os_disk_tier(pool):
            continue
        free = free_gb(pool)
        if free is None or free < need_gb:
            continue
        key = (-free, pool.pool_id)
        if best is None or key < best:
            best = key
    return best[1] if best is not None else None
