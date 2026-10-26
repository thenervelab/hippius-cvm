"""Who holds a miner's cordon, and the node owner's maintenance cordon.

A cordon (`MinerCapacity.cordoned_at` set) has one of three sources,
read off `cordon_reason`, no extra column:

- `owner` — a maintenance cordon the node's own family set through
  `POST /v1/operator/miners/{node_id}/maintenance`
  (`apps.operator.maintenance_views`). Its reason is stored as
  `owner-maintenance:<the owner's text>`.
- `auto`  — set by a vali state machine; its reason starts with one of
  `AUTO_REASON_PREFIXES` (`disk-tier:` …).
- `staff` — everything else: `vali_set_miner_capacity --cordon`, and any
  cordon whose reason this module does not recognise.

Only an `owner` cordon is the owner's to lift. Classifying by an exact
prefix means every writer that does not know about owners (the staff
command, an older image during a roll, a future automatic writer) lands
on `staff` or `auto` — never on `owner` — so an owner can never lift a
cordon they did not set. The staff command refuses a reason carrying the
owner prefix for the same reason.

A cordon closes the node to NEW placements only (gate (h)): the VMs
already on it run on, nothing is stopped, drained or migrated. An owner
waits for `hosted_vm_count == 0` before touching the host.
"""

from __future__ import annotations

from dataclasses import dataclass

from django.db import transaction
from django.utils import timezone

from . import capacity_admin
from .models import MinerCapacity

OWNER = "owner"
STAFF = "staff"
AUTO = "auto"

OWNER_REASON_PREFIX = "owner-maintenance:"
#: Reason prefixes of the cordons vali's own state machines set.
AUTO_REASON_PREFIXES: tuple[str, ...] = ("disk-tier:", "quarantine:", "auto:")
#: Longest owner-supplied reason (the stored one adds the prefix).
OWNER_REASON_MAX = 200
#: The short code a non-owner cordon is reported under to the owner.
STAFF_PUBLIC_REASON = "operator-hold"


class NotOwnerCordon(Exception):
    """The node is cordoned, but not by its owner — the owner may neither
    lift nor restate that cordon."""

    def __init__(self, source: str) -> None:
        super().__init__(f"the node is under a {source} cordon")
        self.source = source


@dataclass(frozen=True)
class CordonView:
    cordoned: bool
    source: str | None
    #: Owner: the owner's own text. Staff/auto: a short code, never the
    #: operator's free text. `None` when not cordoned.
    public_reason: str | None


def source_of(cordoned_at: object, reason: str) -> str | None:
    if cordoned_at is None:
        return None
    if reason.startswith(OWNER_REASON_PREFIX):
        return OWNER
    if reason.startswith(AUTO_REASON_PREFIXES):
        return AUTO
    return STAFF


def view_of(row: MinerCapacity | None) -> CordonView:
    if row is None or row.cordoned_at is None:
        return CordonView(cordoned=False, source=None, public_reason=None)
    reason = row.cordon_reason or ""
    source = source_of(row.cordoned_at, reason)
    if source == OWNER:
        public = reason[len(OWNER_REASON_PREFIX) :]
    elif source == AUTO:
        # The prefix IS the code (`disk-tier:` → `disk-tier`); what follows
        # is vali-internal detail.
        public = reason.split(":", 1)[0]
    else:
        public = STAFF_PUBLIC_REASON
    return CordonView(cordoned=True, source=source, public_reason=public)


def validate_owner_reason(reason: str) -> str:
    """The owner's reason, stripped; `ValueError` if too long or not
    printable text."""
    reason = reason.strip()
    if len(reason) > OWNER_REASON_MAX:
        raise ValueError(f"reason is at most {OWNER_REASON_MAX} characters")
    if not reason.isprintable():
        raise ValueError("reason must be printable text (no control characters)")
    return reason


@dataclass(frozen=True)
class OwnerCordonResult:
    row: MinerCapacity
    changed: bool


def set_owner_cordon(
    node_id: str, *, cordon: bool, reason: str, actor: str, audit_reason: str
) -> OwnerCordonResult | None:
    """Set (`cordon=True`) or lift (`cordon=False`) the owner's maintenance
    cordon on `node_id`, audited through `capacity_admin`. Idempotent.

    Returns `None` when the node has no `MinerCapacity` row. Raises
    [`NotOwnerCordon`] when a staff or automatic cordon is in force —
    whichever way `cordon` points: lifting it is not the owner's call, and
    restating it as `owner` would make it liftable."""
    with transaction.atomic():
        row = MinerCapacity.objects.select_for_update().filter(miner_node_id=node_id).first()
        if row is None:
            return None
        source = source_of(row.cordoned_at, row.cordon_reason or "")
        if source not in (None, OWNER):
            raise NotOwnerCordon(source)
        if cordon:
            changes = {
                # Restating keeps the instant the cordon began.
                "cordoned_at": row.cordoned_at or timezone.now(),
                "cordon_reason": OWNER_REASON_PREFIX + reason,
            }
        else:
            # On an uncordoned row this diffs to nothing: no write, no audit.
            changes = {"cordoned_at": None, "cordon_reason": ""}
        applied = capacity_admin.apply_capacity_change(
            row, changes, actor=actor, reason=audit_reason
        )
        return OwnerCordonResult(row, changed=bool(applied))
