"""Disk tiers and their order (design §3.1).

`nvme` > `ssd` > `hdd`; `unfit` (probed, below every floor) and `unknown`
(never probed) rank below all three and qualify for nothing. A requested
tier is a MINIMUM: a disk qualifies for every tier at or below its own —
except an OS disk under `VALI_OS_TIER_MATCH` `exact` ([`os_tier_fits`])
and a dedicated disk under `VALI_DEDICATED_TIER_MATCH` `exact`.
"""

from __future__ import annotations

from django.conf import settings
from django.db import models


class DiskTier(models.TextChoices):
    UNKNOWN = "unknown", "unknown"
    NVME = "nvme", "nvme"
    SSD = "ssd", "ssd"
    HDD = "hdd", "hdd"
    UNFIT = "unfit", "unfit"


#: The tiers a disk can be sold at — what a launch may require.
SELLABLE_TIERS: tuple[DiskTier, ...] = (DiskTier.NVME, DiskTier.SSD, DiskTier.HDD)

_RANK: dict[str, int] = {
    DiskTier.NVME: 3,
    DiskTier.SSD: 2,
    DiskTier.HDD: 1,
    DiskTier.UNFIT: 0,
    DiskTier.UNKNOWN: 0,
}


def rank(tier: str) -> int:
    """The tier's rank (higher is faster). `unfit` and `unknown` are 0.
    Raises `ValueError` on a string that is not a tier."""
    try:
        return _RANK[tier]
    except KeyError:
        raise ValueError(f"not a disk tier: {tier!r}") from None


def satisfies(actual: str, required: str) -> bool:
    """Whether a disk verified at `actual` may hold a disk sold at
    `required`. `required` must be a sellable tier; `unfit` and `unknown`
    satisfy nothing."""
    if required not in SELLABLE_TIERS:
        raise ValueError(f"not a sellable tier: {required!r}")
    return rank(actual) > 0 and rank(actual) >= rank(required)


#: `VALI_OS_TIER_MATCH` values ([`os_tier_match`]).
OS_TIER_MATCH_EXACT = "exact"
OS_TIER_MATCH_MINIMUM = "minimum"


def os_tier_match() -> str:
    """How an OS disk's sold tier matches a pool's: `minimum` (that tier or
    above) or `exact` (that very tier) — `VALI_OS_TIER_MATCH`."""
    return str(getattr(settings, "VALI_OS_TIER_MATCH", OS_TIER_MATCH_MINIMUM) or "")


def os_tier_fits(own: str, sold: str) -> bool:
    """Whether a pool holding OS disks at `own` may hold one sold at `sold`:
    [`satisfies`], or, under `VALI_OS_TIER_MATCH` `exact`, `own == sold`
    only (an hdd order never lands on an ssd or nvme pool). `sold` must be
    a sellable tier. Every OS-disk comparison goes through this one; the
    dedicated disks have their own (`dedicated.tier_match`)."""
    if os_tier_match() == OS_TIER_MATCH_EXACT:
        if sold not in SELLABLE_TIERS:
            raise ValueError(f"not a sellable tier: {sold!r}")
        return own == sold
    return satisfies(own, sold)


def capped(classified: str, declared: str | None) -> str:
    """What a dedicated disk is verified at: the lower of its probe grade
    and its operator's declared class, `hdd` when none is declared
    (downgrade-only: a declaration never raises a grade). `unfit` /
    `unknown` stay what they are."""
    cap = declared if declared in SELLABLE_TIERS else DiskTier.HDD
    if rank(classified) == 0:
        return classified
    return classified if rank(classified) <= rank(cap) else str(cap)
