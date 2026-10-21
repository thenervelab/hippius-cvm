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
from .tiers import SELLABLE_TIERS, DiskTier, rank, satisfies

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


def os_disk_tier_of(pool: MinerStoragePool) -> str | None:
    """The tier the pool holds OS disks at: its verified (or overridden)
    tier, or, not probed yet, its declared class — the probes (G3) demote a
    pool that is not what it says. `None` when it holds none: `unfit`, no
    class, or unhealthy (a probe that fell below the floor, `degraded`, or
    worse; only `suspect` pending a probe stays in)."""
    if pool.health not in (DiskHealth.OK, DiskHealth.SUSPECT):
        return None
    tier = pool.effective_tier
    if tier == DiskTier.UNKNOWN:
        tier = pool.declared_class
    return tier if tier in SELLABLE_TIERS else None


def serves_os_disk_tier(pool: MinerStoragePool, tier: str) -> bool:
    """The pool may hold an OS disk sold at `tier` (a minimum): its own tier
    is at least that. So an hdd pool holds only the OS disks sold hdd."""
    own = os_disk_tier_of(pool)
    return own is not None and satisfies(own, tier)


def sold_as_os_disk_tier(pool: MinerStoragePool) -> bool:
    """The pool is what every OS disk is sold as by default (nvme)."""
    return serves_os_disk_tier(pool, DiskTier.NVME)


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


def default_pool_tier(node_id: str) -> str | None:
    """The tier `default` holds OS disks at: its row's (`os_disk_tier_of`;
    not one taking OS disks ⇒ `None`), or nvme for a node that reports no
    such row — a pre-v7 agent's single pool, sold nvme as every OS disk
    always was."""
    pool = MinerStoragePool.objects.filter(
        miner_node_id=node_id, pool_id=DEFAULT_POOL_ID, retired_at__isnull=True
    ).first()
    if pool is None:
        return DiskTier.NVME
    return os_disk_tier_of(pool) if pool.os_disks else None


def choose_os_pool(node_id: str, need_gb: int, tier: str = DiskTier.NVME) -> str | None:
    """The pool other than `default` to put a `need_gb` OS disk sold at
    `tier` on: of the node's active, recently reported, not retired,
    OS-disk pools that hold `tier` and have room for it, the one of the
    lowest such tier, then the most free, ties by id. `None` (⇒ `default`)
    when the agent does not take `os_pool`, when no such pool has room, or
    when `default` holds `tier` at a lower tier than any of them (its room
    is the data-disk gate's). For nvme every candidate is of one tier: the
    pool other than `default` with the most free, as ever."""
    if not supported(node_id):
        return None
    best: tuple[int, int, str] | None = None
    for pool in os_disk_pools(node_id).exclude(pool_id=DEFAULT_POOL_ID):
        if not serves_os_disk_tier(pool, tier):
            continue
        free = free_gb(pool)
        if free is None or free < need_gb:
            continue
        key = (rank(os_disk_tier_of(pool) or ""), -free, pool.pool_id)
        if best is None or key < best:
            best = key
    if best is None:
        return None
    if tier != DiskTier.NVME:
        own = default_pool_tier(node_id)
        if own is not None and satisfies(own, tier) and rank(own) < best[0]:
            return None
    return best[2]
