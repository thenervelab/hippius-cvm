"""The one audited writer of `MinerCapacity` capacity-policy columns.

Capacity v2 lets three actors change a miner's capacity policy: the
operator (`vali_set_miner_capacity`), the earned-capacity tick, and the
vali-attributed penalty events. All of them go through
[`apply_capacity_change`], which writes the columns with a targeted
UPDATE and lands one `MinerCapacityAudit` row per AUDITED field that
actually changed, in the same transaction.

Two classes of column:

- **Audited** (`AUDITED_FIELDS`) — the decisions: the anchor, the VM
  ceiling, the ratio, the trust class, the earned ceiling, the proven
  peak, the per-miner boot cap and the cordon. Every change is a row.
- **Working state** (`WORKING_FIELDS`) — bookkeeping the tick rewrites
  every cycle (the candidate being held, timestamps, the last reason).
  Auditing them would bury the decisions in noise; they are still only
  written through here, so the column set stays closed.

A targeted UPDATE, never `row.save()`: the chain refresh and the
heartbeat write other columns of the same row concurrently, and a full
save would roll them back to what the caller read.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import datetime
from decimal import Decimal
from typing import Any

from django.db import models, transaction

from .models import MinerCapacity, MinerCapacityAudit

log = logging.getLogger("apps.scheduler.capacity_admin")

AUDITED_FIELDS: frozenset[str] = frozenset(
    {
        "total_cpus",
        "total_memory_mb",
        "capacity_slots",
        "cpu_ratio",
        "trust_class",
        "earned_vms",
        "earned_vcpus",
        "earned_memory_mb",
        "proven_peak_vms",
        "proven_peak_vcpus",
        "proven_peak_memory_mb",
        "total_disk_gb",
        "earned_disk_gb",
        "max_booting",
        "cordoned_at",
        "cordon_reason",
    }
)

WORKING_FIELDS: frozenset[str] = frozenset(
    {
        "proven_at",
        "candidate_vms",
        "candidate_vcpus",
        "candidate_memory_mb",
        "candidate_since",
        "earned_last_change_at",
        "earned_last_reason",
    }
)

#: The audit `field` of an operator note — records a decision, changes
#: no column.
NOTE_FIELD = "note"


@dataclass(frozen=True)
class FieldChange:
    field: str
    before: Any
    after: Any


def to_json(value: Any) -> Any:
    """A column value as JSON the audit row can hold."""
    if isinstance(value, Decimal):
        return str(value)
    if isinstance(value, datetime):
        return value.isoformat()
    return value


def normalise(field: str, value: Any) -> Any:
    """`value` coerced to what `field` stores, or `ValueError`.

    The command validates its own input, but the earned tick and the
    penalty writers call [`apply_capacity_change`] directly — this is the
    one place a wrong type (a float NaN into the JSON audit, a string into
    `cpu_ratio`, a negative count) is stopped for all of them."""
    model_field = MinerCapacity._meta.get_field(field)
    if value is None:
        if not model_field.null:
            raise ValueError(f"{field} is not nullable")
        return None
    if isinstance(model_field, models.DecimalField):
        if isinstance(value, bool) or not isinstance(value, (Decimal, int, str)):
            raise ValueError(f"{field}={value!r} is not a decimal")
        dec = Decimal(str(value))
        if not dec.is_finite():
            raise ValueError(f"{field}={value!r} is not finite")
        return dec.quantize(Decimal(1).scaleb(-model_field.decimal_places))
    if isinstance(model_field, models.PositiveIntegerField):
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise ValueError(f"{field}={value!r} is not a non-negative integer")
        return value
    if isinstance(model_field, models.DateTimeField):
        if not isinstance(value, datetime):
            raise ValueError(f"{field}={value!r} is not a datetime")
        return value
    if isinstance(model_field, models.CharField):
        if not isinstance(value, str) or len(value) > model_field.max_length:
            raise ValueError(f"{field}={value!r} is not a string of <= {model_field.max_length}")
        if model_field.choices and value not in {c[0] for c in model_field.choices}:
            raise ValueError(f"{field}={value!r} is not one of the choices")
        return value
    raise ValueError(f"{field}: unsupported column type {type(model_field).__name__}")


def diff(row: MinerCapacity, changes: dict[str, Any]) -> list[FieldChange]:
    """The subset of `changes` that differs from `row`, in a stable order,
    with every value normalised ([`normalise`]).

    Raises `ValueError` for a column outside the closed policy set — a
    typo must not become a silent no-op or a write to a chain column —
    and for a value the column cannot hold."""
    unknown = set(changes) - AUDITED_FIELDS - WORKING_FIELDS
    if unknown:
        raise ValueError(f"not a capacity-policy column: {sorted(unknown)}")
    out: list[FieldChange] = []
    for field in sorted(changes):
        before = getattr(row, field)
        after = normalise(field, changes[field])
        if before != after:
            out.append(FieldChange(field, before, after))
    return out


def audited(changes: list[FieldChange]) -> list[FieldChange]:
    """The decisions among `changes` (what lands in the audit)."""
    return [c for c in changes if c.field in AUDITED_FIELDS]


def apply_capacity_change(
    row: MinerCapacity,
    changes: dict[str, Any],
    *,
    actor: str,
    reason: str,
) -> list[FieldChange]:
    """Write `changes` to `row`'s policy columns and audit them.

    The caller must hold `row` under `select_for_update()` inside an
    atomic block — the diff is computed against it, and a diff taken
    against an unlocked row can audit a `before` that was never true.

    Returns the changes actually applied (audited or not). An empty
    `changes`, or one identical to the row, writes nothing."""
    if not transaction.get_connection().in_atomic_block:
        raise RuntimeError("apply_capacity_change needs a locked row inside transaction.atomic()")
    if not actor:
        raise ValueError("apply_capacity_change needs an actor")
    applied = diff(row, changes)
    if not applied:
        return []
    MinerCapacity.objects.filter(pk=row.pk).update(**{c.field: c.after for c in applied})
    for c in applied:
        setattr(row, c.field, c.after)
    MinerCapacityAudit.objects.bulk_create(
        [
            MinerCapacityAudit(
                miner_node_id=row.miner_node_id,
                actor=actor,
                field=c.field,
                before=to_json(c.before),
                after=to_json(c.after),
                reason=reason,
            )
            for c in audited(applied)
        ]
    )
    return applied


def record_note(node_id: str, *, actor: str, reason: str) -> MinerCapacityAudit:
    """An operator note: an audit row that changes no column — e.g. a
    decision taken before this table existed, recorded retroactively."""
    if not actor or not reason:
        raise ValueError("a note needs an actor and a reason")
    return MinerCapacityAudit.objects.create(
        miner_node_id=node_id, actor=actor, field=NOTE_FIELD, before=None, after=None, reason=reason
    )
