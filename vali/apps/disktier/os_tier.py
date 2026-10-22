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
- [`may_fall_back`]: an owner in `VALI_DISK_TIER_FALLBACK_OWNERS` (our
  own runners), under `enforce` only, whose VM no candidate can hold at its
  sold tier, is placed at the first lower tier some candidate holds
  (`DiskTierFit.fallbacks`). The sold tier in `spec_json` never changes:
  where the disk landed is a placement fact ([`landing_tier`]), recorded on
  its `PlacementDisk` and billing binding ([`log_fallback`]).
"""

from __future__ import annotations

import json
import logging
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
from .tiers import SELLABLE_TIERS, DiskTier, rank, satisfies

log = logging.getLogger(__name__)

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


def fallback_owners() -> frozenset[str]:
    """`VALI_DISK_TIER_FALLBACK_OWNERS`, as strings."""
    raw = getattr(settings, "VALI_DISK_TIER_FALLBACK_OWNERS", ()) or ()
    return frozenset(str(o).strip() for o in raw if str(o).strip())


def may_fall_back(owner: object) -> bool:
    """Whether a VM of `owner` (`Placement.owner`: the launch's `user_id`,
    set by vali's operator-only launch API) may take a lower OS-disk tier
    than its sold one when none holds it: only under `enforce`, and only
    for an owner listed in `VALI_DISK_TIER_FALLBACK_OWNERS` — matched
    exactly, as the string vali stores (never a customer's VM)."""
    if gate_mode() != GATE_ENFORCE:
        return False
    return isinstance(owner, str) and bool(owner) and owner in fallback_owners()


def lower_tiers(tier: str) -> tuple[str, ...]:
    """The sellable tiers below `tier`, fastest first (nvme → ssd, hdd)."""
    return tuple(t for t in SELLABLE_TIERS if rank(t) < rank(tier))


def landing_tier(
    node_id: str, tier: str, need_gb: int, owner: object, *, default_only: bool = False
) -> str:
    """The tier a `need_gb` OS disk sold at `tier` goes at on `node_id`:
    `tier` itself, except for an owner that [`may_fall_back`] on a node
    that does not hold it — then the first lower tier the node holds
    (`tier` when it holds none: the gate refuses it as ever)."""
    if not may_fall_back(owner) or not refusal_at(node_id, tier, need_gb, default_only):
        return tier
    for lower in lower_tiers(tier):
        if not refusal_at(node_id, lower, need_gb, default_only):
            return lower
    return tier


def refusal_at(node_id: str, tier: str, need_gb: int, default_only: bool = False) -> str:
    """[`refusal`] with `default_only`."""
    return refusals([node_id], tier, need_gb, default_only=default_only).get(node_id, "")


def held_tier(node_id: str, pool_id: str, tier: str) -> str:
    """The tier an OS disk sold at `tier` sits at on `node_id`'s `pool_id`
    (`""` or `default` for the default pool): the pool's own OS-disk tier
    when it is below `tier`, else `tier` (a pool of unknown tier: `tier`)."""
    from .routing import default_pool_tier

    if not pool_id or pool_id == DEFAULT_POOL_ID:
        own = default_pool_tier(node_id)
    else:
        pool = MinerStoragePool.objects.filter(
            miner_node_id=node_id, pool_id=pool_id, retired_at__isnull=True
        ).first()
        own = os_disk_tier_of(pool) if pool is not None else None
    return own if own is not None and rank(own) < rank(tier) else tier


def vm_owner(vm_id: str) -> str:
    """The owner of `vm_id`'s newest placement (`""` without one)."""
    from apps.scheduler.models import Placement

    return (
        Placement.objects.filter(vm__vm_id=vm_id)
        .order_by("-decided_at")
        .values_list("owner", flat=True)
        .first()
        or ""
    )


def fallback_owner_of(vm_id: str) -> str:
    """`vm_id`'s owner ([`vm_owner`]) when it [`may_fall_back`], else `""`
    — no query while the gate is not enforced or nobody is listed."""
    if gate_mode() != GATE_ENFORCE or not fallback_owners():
        return ""
    owner = vm_owner(vm_id)
    return owner if may_fall_back(owner) else ""


def placed_tier(vm_id: str) -> str:
    """The tier recorded for `vm_id`'s OS disk on its active placement
    (`""` without such a row: a placement on `default` at its sold tier)."""
    from apps.scheduler.models import ACTIVE_PLACEMENT_STATES

    from .models import OS_SLOT, PlacementDisk

    return (
        PlacementDisk.objects.filter(
            placement__vm__vm_id=vm_id,
            placement__status__in=list(ACTIVE_PLACEMENT_STATES),
            slot=OS_SLOT,
        )
        .order_by("-placement__decided_at")
        .values_list("required_tier", flat=True)
        .first()
        or ""
    )


def log_fallback(
    *, vm_id: str, owner: str, node_id: str, sold: str, tier: str, context: str
) -> None:
    """A VM's OS disk placed below its sold tier: one structured WARNING
    under the stable event name `disk_tier_fallback` (like E1's
    `disk_tier_gate_would_reject`); the live count is the
    `hippius_disk_tier_fallback_vms{tier}` gauge ([`fallback_vm_counts`])."""
    log.warning(
        "%s",
        json.dumps(
            {
                "event": "disk_tier_fallback",
                "vm_id": vm_id,
                "owner": owner,
                "node_id": node_id,
                "os_disk_tier": sold,
                "placed_tier": tier,
                "context": context,
            },
            sort_keys=True,
        ),
    )


def fallback_vm_counts() -> dict[str, int]:
    """`{tier: active VMs whose OS disk is recorded below its sold tier}`
    for every tier below nvme. Only a fallback owner's VM can be, so only
    theirs are read (none while the list is empty)."""
    from apps.scheduler.models import ACTIVE_PLACEMENT_STATES

    from .models import OS_SLOT, PlacementDisk

    counts = dict.fromkeys(lower_tiers(DiskTier.NVME), 0)
    owners = fallback_owners()
    if not owners:
        return counts
    rows = PlacementDisk.objects.filter(
        slot=OS_SLOT,
        placement__status__in=list(ACTIVE_PLACEMENT_STATES),
        placement__owner__in=owners,
    ).values_list("placement__vm__vm_id", "required_tier")
    for vm_id, tier in rows:
        if tier in counts and rank(tier) < rank(launch_tier(vm_id)):
            counts[tier] += 1
    return counts


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
