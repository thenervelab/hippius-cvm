"""The one audited writer of a pool's operator tier override.

An override wins over the probe-verified tier while it is set (an
emergency `unfit`, or a tier the probe cannot yet establish). Every change
lands one `MinerCapacityAudit` row in the same transaction — the existing
append-only capacity audit, so a miner's whole policy history reads from
one table:

- `miner_node_id` the pool's node;
- `field`         `disk_tier_override:<pool_id>`;
- `before`/`after` `{"override": "<tier>|''", "reason": "..."}`;
- `actor`         `op:<identity>`; `reason` the operator's reason.
"""

from __future__ import annotations

from dataclasses import dataclass

from django.db import transaction

from apps.scheduler.models import MinerCapacityAudit

from .models import MinerStoragePool
from .tiers import DiskTier

#: Tiers an operator may pin. `unknown` is "no override" — use clear.
OVERRIDE_TIERS: frozenset[str] = frozenset(
    {DiskTier.NVME, DiskTier.SSD, DiskTier.HDD, DiskTier.UNFIT}
)
AUDIT_FIELD_PREFIX = "disk_tier_override:"


@dataclass(frozen=True)
class OverrideChange:
    before: str
    after: str
    before_reason: str
    after_reason: str


def audit_field(pool_id: str) -> str:
    return f"{AUDIT_FIELD_PREFIX}{pool_id}"


def set_pool_override(
    pool: MinerStoragePool, override: str, *, actor: str, reason: str
) -> OverrideChange | None:
    """Set (`override` a tier) or clear (`override == ""`) the pool's
    operator override and audit it.

    The caller must hold `pool` under `select_for_update()` inside an atomic
    block, so the audited `before` is the value actually replaced. Returns
    the change, or `None` when the pool already carries exactly this
    override and reason (nothing written)."""
    if not transaction.get_connection().in_atomic_block:
        raise RuntimeError("set_pool_override needs a locked row inside transaction.atomic()")
    if not actor:
        raise ValueError("set_pool_override needs an actor")
    if not reason:
        raise ValueError("set_pool_override needs a reason")
    if override and override not in OVERRIDE_TIERS:
        raise ValueError(f"not an override tier: {override!r}")
    max_reason = MinerStoragePool._meta.get_field("override_reason").max_length
    if len(reason) > max_reason:
        raise ValueError(f"reason longer than {max_reason} characters")
    after_reason = reason if override else ""
    change = OverrideChange(
        before=pool.operator_override,
        after=override,
        before_reason=pool.override_reason,
        after_reason=after_reason,
    )
    if change.before == change.after and change.before_reason == change.after_reason:
        return None
    MinerStoragePool.objects.filter(pk=pool.pk).update(
        operator_override=override, override_reason=after_reason
    )
    pool.operator_override = override
    pool.override_reason = after_reason
    MinerCapacityAudit.objects.create(
        miner_node_id=pool.miner_node_id,
        actor=actor,
        field=audit_field(pool.pool_id),
        before={"override": change.before, "reason": change.before_reason},
        after={"override": change.after, "reason": change.after_reason},
        reason=reason,
    )
    return change
