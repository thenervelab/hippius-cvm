"""Disk tiers and their order (design §3.1).

`nvme` > `ssd` > `hdd`; `unfit` (probed, below every floor) and `unknown`
(never probed) rank below all three and qualify for nothing. A requested
tier is a MINIMUM: a disk qualifies for every tier at or below its own.
"""

from __future__ import annotations

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
