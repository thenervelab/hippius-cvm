"""E1: the OS-disk tier a VM is sold at, and the nodes that can hold it
(docs/design/disk-tier-verification.md §10.7, §10.14).

- `os_disk_tier` on a launch is a MINIMUM (`nvme` > `ssd` > `hdd`); absent
  or `""` is nvme, what every OS disk was always sold as. Only a tier that
  is not nvme is written into `spec_json` (`launch_tier` reads `""` back
  as nvme), so every other launch's record is as before.
- [`refusal`] / [`refusals`]: the scheduler's tier gate
  (`VALI_SCHEDULER_DISK_TIER_GATE`). A node holds the tier when the pool
  dispatch would put the disk on holds it (`routing.choose_os_pool`): a
  pool other than `default` with room, or `default` itself (its room is
  the data-disk gate's).
- Nothing is measured: the tier only drives placement and billing.
"""

from __future__ import annotations

from collections.abc import Iterable

from django.conf import settings
from django.utils import timezone

from apps.scheduler.models import MinerCapacity

from .models import MinerStoragePool
from .routing import (
    DEFAULT_POOL_ID,
    REPORT_MAX_AGE,
    free_gb,
    os_disk_tier_of,
    serves_os_disk_tier,
)
from .storage_config import version_at_least
from .tiers import SELLABLE_TIERS, DiskTier, satisfies

#: What an absent `os_disk_tier` means: every OS disk was always sold so.
DEFAULT_TIER: str = DiskTier.NVME

GATE_OFF = "off"
GATE_RECORD = "record"
GATE_ENFORCE = "enforce"

#: Launch intake refusals (`launch_jobs`).
CATEGORY_INVALID = "disk-tier-invalid"
CATEGORY_NOT_OFFERED = "disk-tier-not-offered"
#: The scheduler's: no candidate holds the tier.
CATEGORY_NO_MINER_AT_TIER = "no-miner-at-tier"

#: Decision Q7: what one unit of a VM sold at each tier earns its miner,
#: in basis points (`VALI_DISK_TIER_UNIT_FACTOR`).
UNIT_FACTOR_BPS: dict[str, int] = {DiskTier.NVME: 10000, DiskTier.SSD: 8000, DiskTier.HDD: 6000}


def gate_mode() -> str:
    return str(getattr(settings, "VALI_SCHEDULER_DISK_TIER_GATE", GATE_OFF) or GATE_OFF)


def sellable_tiers() -> frozenset[str]:
    return frozenset(getattr(settings, "VALI_SELLABLE_OS_TIERS", [DiskTier.NVME]) or ())


def parse(value: object) -> str:
    """A requested `os_disk_tier`: `nvme` / `ssd` / `hdd`, `""` or `None`
    for nvme. Raises `ValueError` on anything else."""
    if value is None or value == "":
        return DiskTier.NVME
    if not isinstance(value, str) or value not in SELLABLE_TIERS:
        raise ValueError(f"os_disk_tier must be one of: {', '.join(SELLABLE_TIERS)}")
    return value


def tier_not_offered(tier: str) -> str:
    """Why no VM is sold at `tier` (`""` when some are): not in
    `VALI_SELLABLE_OS_TIERS`, or a tier other than nvme while the gate does
    not enforce it (vali would not place by it)."""
    if tier not in sellable_tiers():
        return f"os_disk_tier {tier!r} is not offered"
    if tier != DiskTier.NVME and gate_mode() != GATE_ENFORCE:
        return f"os_disk_tier {tier!r} is not offered (the tier gate is not enforced)"
    return ""


def not_offered(tier: str, flavor: str) -> str:
    """Why a VM of `flavor` is not sold at `tier` (`""` when it is):
    [`tier_not_offered`], or hdd above `VALI_HDD_OS_MAX_FLAVOR`."""
    from apps.orchestration.services import flavors

    why = tier_not_offered(tier)
    if why:
        return why
    if tier == DiskTier.HDD:
        cap = str(getattr(settings, "VALI_HDD_OS_MAX_FLAVOR", "") or "")
        try:
            size = flavors.FLAVOR_NAMES.index(flavors.ticket_flavor(flavor))
            limit = flavors.FLAVOR_NAMES.index(cap)
        except (ValueError, flavors.UnknownFlavor):
            return f"os_disk_tier 'hdd' is not offered for flavor {flavor!r}"
        if size > limit:
            return f"os_disk_tier 'hdd' is offered up to flavor {cap!r}, not {flavor!r}"
    return ""


def spec_tier(spec_json: dict[str, object]) -> str:
    """The tier a launch's `spec_json` (or `LaunchSpec` fields) was sold at."""
    tier = spec_json.get("os_disk_tier") or ""
    return tier if isinstance(tier, str) and tier in SELLABLE_TIERS else DiskTier.NVME


def launch_tier(vm_id: str) -> str:
    """The tier `vm_id` was sold at, from its launch (nvme without one)."""
    from apps.scheduler.service import _launch_spec

    return spec_tier(_launch_spec(vm_id)) if vm_id else DiskTier.NVME


def refusals(
    node_ids: Iterable[str], tier: str, need_gb: int, *, default_only: bool = False
) -> dict[str, str]:
    """`{node_id: why}` for each of `node_ids` (as given) with no OS pool
    at `tier` for a `need_gb` disk; a node that has one is absent.
    `default_only`: a disk that can only land on `default` (a legacy LUKS
    launch). Two queries for the lot (the pools, the agents that may be
    sent one)."""
    ids = list(node_ids)
    fresh = timezone.now() - REPORT_MAX_AGE
    by_node: dict[str, list[MinerStoragePool]] = {}
    for pool in MinerStoragePool.objects.filter(
        miner_node_id__in={nid.lower() for nid in ids} | set(ids), retired_at__isnull=True
    ):
        by_node.setdefault(pool.miner_node_id.lower(), []).append(pool)
    # The pools other than `default` that could hold the disk: only for an
    # agent that takes `os_pool` (`routing.supported`).
    others = {
        nid: [
            p
            for p in pools
            if p.pool_id != DEFAULT_POOL_ID
            and p.os_disks
            and p.reported_state == "active"
            and p.reported_at is not None
            and p.reported_at >= fresh
            and serves_os_disk_tier(p, tier)
            and (free_gb(p) or 0) >= need_gb
            and not default_only
        ]
        for nid, pools in by_node.items()
    }
    minimum = str(getattr(settings, "VALI_POOL_ROUTING_MIN_AGENT_VERSION", "") or "")
    wanted = {nid for nid, pools in others.items() if pools}
    versions = (
        {
            node.lower(): version
            for node, version in MinerCapacity.objects.filter(
                miner_node_id__in={n for n in ids if n.lower() in wanted}
            ).values_list("miner_node_id", "agent_version")
        }
        if wanted and minimum
        else {}
    )
    out: dict[str, str] = {}
    for nid in ids:
        key = nid.lower()
        pools = by_node.get(key, [])
        default = next((p for p in pools if p.pool_id == DEFAULT_POOL_ID), None)
        if _default_holds(default, tier):
            continue
        if others.get(key) and version_at_least(versions.get(key, ""), minimum):
            continue
        own = os_disk_tier_of(default) if default is not None and default.os_disks else None
        out[nid] = f"no OS pool at {tier} with {need_gb} GiB (default pool: {own or 'none'})"
    return out


def refusal(node_id: str, tier: str, need_gb: int) -> str:
    """[`refusals`] for one node: `""` when it holds `tier`."""
    return refusals([node_id], tier, need_gb).get(node_id, "")


def ever_holding(node_ids: Iterable[str], tier: str) -> set[str]:
    """Those of `node_ids` (as given) with an OS-disk pool CONFIGURED at
    `tier` or better — its verified (or overridden) tier, else its declared
    class — whatever its room, health, report freshness or agent: what a
    "never" must be judged on (missing data or a passing state is not
    knowledge). A node with no `default` row has the pre-v7 nvme pool."""
    ids = list(node_ids)
    by_node: dict[str, list[MinerStoragePool]] = {}
    for pool in MinerStoragePool.objects.filter(
        miner_node_id__in={nid.lower() for nid in ids} | set(ids), retired_at__isnull=True
    ):
        by_node.setdefault(pool.miner_node_id.lower(), []).append(pool)

    def configured(pool: MinerStoragePool) -> bool:
        own = pool.effective_tier if pool.effective_tier != DiskTier.UNKNOWN else ""
        own = own or pool.declared_class
        return pool.os_disks and own in SELLABLE_TIERS and satisfies(own, tier)

    out: set[str] = set()
    for nid in ids:
        pools = by_node.get(nid.lower(), [])
        has_default = any(p.pool_id == DEFAULT_POOL_ID for p in pools)
        if (not has_default and satisfies(DEFAULT_TIER, tier)) or any(map(configured, pools)):
            out.add(nid)
    return out


def _default_holds(default: MinerStoragePool | None, tier: str) -> bool:
    """`default` takes the disk whatever the order says; no row for it (a
    pre-v7 agent's single pool) is nvme, as every OS disk was sold."""
    if default is None:
        return satisfies(DEFAULT_TIER, tier)
    return default.os_disks and serves_os_disk_tier(default, tier)


def unit_factor_bps(tier: str) -> int:
    """What one unit of a VM sold at `tier` earns its miner, in basis
    points: 10000 unless `VALI_DISK_TIER_UNIT_FACTOR` is on."""
    if not getattr(settings, "VALI_DISK_TIER_UNIT_FACTOR", False):
        return 10000
    return UNIT_FACTOR_BPS.get(tier, 10000)
