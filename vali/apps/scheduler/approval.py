"""External-miner approval: pending until approved, then anchored.

A miner the chain refresh first sees while `VALI_MINER_APPROVAL_REQUIRED`
is on gets a `MinerCapacity` row with `approved_at` NULL — PENDING. Until an
operator approves it, it takes no new placement.

Enforcement is the cordon gate, not a new one: [`pending_approval_node_ids`]
is merged into `service.cordoned_node_ids`, which every new-work path
already consults (launch, feasibility, resize / migration / failover /
restore destinations, the price-watch re-placement) and nothing else reads.
That is exactly "no new work, nothing else changes": the miner's chain
status, telemetry and heartbeats flow as usual, which the approve step
needs — it measures the host from them. The approval is its own column,
not a cordon row, so `--uncordon` cannot approve a miner and approving
cannot lift an operator's cordon.

The approve step ([`approve_miner`]) sets the host-size anchor to the
`min` of what the operator declares and what the miner's heartbeat
reports, term by term:

- cpus:      operator `cpus`      vs the v3 `declared_cpu_budget`;
- memory:    operator `memory_mb` vs the v1 `reported_memory_available_mib`;
- data disk: operator `disk_gb`   vs the v4 `reported_data_disk_total_gb`
             (optional: without `disk_gb` an existing `total_disk_gb` is
             the declared side; no figure on either side leaves it NULL).

The heartbeat terms are the miner's own word and only ever LOWER the
operator figure — the same down-only rule admission applies to them. The
cpu and memory terms must be FRESH (inside the liveness window): approving
a host vali cannot currently hear is refused. Until the §18 hardware
inventory exists these heartbeat figures are the only measurement there is.

Every change lands through `capacity_admin.apply_capacity_change`, so the
anchor, the trust class and the approval itself are one transaction with
one `MinerCapacityAudit` row per field, `actor = op:<approver>`.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any

from django.conf import settings
from django.db import transaction
from django.utils import timezone

from . import capacity_admin
from .models import ACTIVE_PLACEMENT_STATES, CapacityTrustClass, MinerCapacity, Placement

log = logging.getLogger("apps.scheduler.approval")

#: The cordon reason a pending miner carries in every gate readout.
PENDING_APPROVAL_REASON = "pending approval"
#: `approved_by` of a row approved on sight while approval is not required.
AUTO_APPROVER = "auto:approval-not-required"

# Same bounds as `vali_set_miner_capacity`.
MIN_CPUS = 1
MAX_CPUS = 1024
MIN_MEMORY_MB = 1024
MAX_MEMORY_MB = 16 * 1024 * 1024
MIN_DISK_GB = 1
MAX_DISK_GB = 1024 * 1024
_TRUST_CHOICES = frozenset(c.value for c in CapacityTrustClass)


class ApprovalRefused(Exception):
    """The approval was not written. `code` is a closed vocabulary the API
    maps to an HTTP status: `not-found`, `already-approved`, `invalid`,
    `not-measured`, `below-committed`."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


@dataclass(frozen=True)
class Measured:
    """The heartbeat's figures, `None` when absent or stale."""

    cpus: int | None
    memory_mb: int | None
    disk_gb: int | None


@dataclass(frozen=True)
class ApprovalResult:
    node_id: str
    approved_at: datetime
    approved_by: str
    total_cpus: int
    total_memory_mb: int
    total_disk_gb: int | None
    trust_class: str
    measured: Measured
    #: `cpus:declared` / `memory:measured` … — which side set each term.
    binding: tuple[str, ...]
    dry_run: bool = False

    def as_dict(self) -> dict[str, Any]:
        return {
            "node_id": self.node_id,
            "approved_at": self.approved_at.isoformat(),
            "approved_by": self.approved_by,
            "total_cpus": self.total_cpus,
            "total_memory_mb": self.total_memory_mb,
            "total_disk_gb": self.total_disk_gb,
            "trust_class": self.trust_class,
            "measured": {
                "cpus": self.measured.cpus,
                "memory_mb": self.measured.memory_mb,
                "disk_gb": self.measured.disk_gb,
            },
            "binding": list(self.binding),
            "dry_run": self.dry_run,
        }


def approval_required() -> bool:
    return bool(getattr(settings, "VALI_MINER_APPROVAL_REQUIRED", False))


def pending_approval_node_ids() -> dict[str, str]:
    """`{lower-case node_id: PENDING_APPROVAL_REASON}` of the miners held
    back for approval; `{}` while approval is not required."""
    if not approval_required():
        return {}
    return {
        nid.lower(): PENDING_APPROVAL_REASON
        for nid in MinerCapacity.objects.filter(approved_at__isnull=True).values_list(
            "miner_node_id", flat=True
        )
    }


def held_back(row: MinerCapacity) -> bool:
    """Whether `row` takes no new work: operator-cordoned, or pending an
    approval that is required. The per-row twin of the
    `service.cordoned_node_ids` set, for readouts that walk rows."""
    return row.cordoned_at is not None or (approval_required() and row.approved_at is None)


def on_sight_approval(now: datetime) -> dict[str, Any]:
    """The approval columns of a row the chain refresh is creating: approved
    on sight while approval is not required, pending otherwise."""
    if approval_required():
        return {}
    return {"approved_at": now, "approved_by": AUTO_APPROVER}


def measured(row: MinerCapacity, *, now: datetime) -> Measured:
    """The heartbeat's host figures on `row`, each `None` when stale."""
    from .service import miner_liveness_timeout_s

    cutoff = now - timedelta(seconds=miner_liveness_timeout_s())

    def fresh(at: datetime | None) -> bool:
        return at is not None and at >= cutoff

    return Measured(
        cpus=row.declared_cpu_budget if fresh(row.declared_at) else None,
        memory_mb=row.reported_memory_available_mib if fresh(row.reported_at) else None,
        disk_gb=row.reported_data_disk_total_gb if fresh(row.disk_reported_at) else None,
    )


def _bounded(name: str, value: int | None, lo: int, hi: int) -> None:
    if value is None:
        return
    if isinstance(value, bool) or not isinstance(value, int) or not lo <= value <= hi:
        raise ApprovalRefused("invalid", f"{name}={value!r} is not an integer in {lo}..{hi}")


def _term(dim: str, declared: int | None, measured_value: int | None) -> tuple[int | None, str]:
    """`min(declared, measured)` over the sides present, and which side won
    (`declared` on a tie: the operator figure is the one being honoured)."""
    if declared is None and measured_value is None:
        return None, f"{dim}:none"
    if measured_value is None or (declared is not None and declared <= measured_value):
        return declared, f"{dim}:declared"
    return measured_value, f"{dim}:measured"


def _committed(node_id: str) -> tuple[int, int, int]:
    """`(placements, memory_mb, cpus)` vali has already placed on the miner —
    the active ledger × the flavor table, as admission counts it."""
    from .service import _committed_resources

    placements = memory_mb = cpus = 0
    for resource_class in Placement.objects.filter(
        miner_node_id=node_id, status__in=ACTIVE_PLACEMENT_STATES
    ).values_list("resource_class", flat=True):
        mem, cpu = _committed_resources(resource_class)
        placements += 1
        memory_mb += mem
        cpus += cpu
    return placements, memory_mb, cpus


def approve_miner(
    node_id: str,
    *,
    cpus: int,
    memory_mb: int,
    disk_gb: int | None,
    approver: str,
    reason: str,
    trust_class: str | None = None,
    dry_run: bool = False,
    now: datetime | None = None,
) -> ApprovalResult:
    """Approve the pending miner `node_id` and set its host-size anchor.

    `cpus` / `memory_mb` / `disk_gb` are what the operator declares;
    each anchor column becomes the `min` of it and the fresh heartbeat
    figure (module docstring). `trust_class` (`operator` | `earned`) is
    left as it is when `None` — a new row is `earned`, so by default the
    anchor is one more clamp on what the miner has PROVEN, and only an
    explicit `operator` sizes it from the anchor alone.

    Raises [`ApprovalRefused`] and writes nothing when the row does not
    exist yet (the chain refresh creates it), is already approved, a value
    is out of range, the heartbeat cpu / memory figure is missing or
    stale, or the anchor is smaller than what vali already placed there."""
    node_id = node_id.strip().lower()
    approver = approver.strip()
    reason = reason.strip()
    if not approver:
        raise ApprovalRefused("invalid", "an approval needs the approver")
    if not reason:
        raise ApprovalRefused("invalid", "an approval needs a reason")
    _bounded("cpus", cpus, MIN_CPUS, MAX_CPUS)
    _bounded("memory_mb", memory_mb, MIN_MEMORY_MB, MAX_MEMORY_MB)
    _bounded("disk_gb", disk_gb, MIN_DISK_GB, MAX_DISK_GB)
    if trust_class is not None and trust_class not in _TRUST_CHOICES:
        raise ApprovalRefused(
            "invalid", f"trust_class={trust_class!r} is not one of {sorted(_TRUST_CHOICES)}"
        )
    actor = f"op:{approver}"
    if len(actor) > MinerCapacity._meta.get_field("approved_by").max_length:
        raise ApprovalRefused("invalid", "approver is too long")
    now = now or timezone.now()

    with transaction.atomic():
        row = MinerCapacity.objects.select_for_update().filter(miner_node_id=node_id).first()
        if row is None:
            raise ApprovalRefused(
                "not-found",
                "no MinerCapacity row for this node id: the chain refresh creates it "
                "once the node is registered on chain",
            )
        if row.approved_at is not None:
            raise ApprovalRefused(
                "already-approved",
                f"approved at {row.approved_at.isoformat()} by {row.approved_by or '?'}; "
                "change the anchor with vali_set_miner_capacity",
            )
        m = measured(row, now=now)
        if m.cpus is None or m.memory_mb is None:
            raise ApprovalRefused(
                "not-measured",
                "no fresh heartbeat cpu budget / available memory for this miner: "
                "approve it while its agent is heartbeating (v3 or later)",
            )
        total_cpus, cpu_bind = _term("cpus", cpus, m.cpus)
        total_memory_mb, mem_bind = _term("memory", memory_mb, m.memory_mb)
        # No declared disk keeps an anchor an operator already set as the
        # declared side, so the heartbeat can never raise it.
        declared_disk = disk_gb if disk_gb is not None else row.total_disk_gb
        total_disk_gb, disk_bind = _term("disk", declared_disk, m.disk_gb)
        assert total_cpus is not None and total_memory_mb is not None
        placements, committed_mb, committed_cpus = _committed(node_id)
        if placements and (total_cpus < committed_cpus or total_memory_mb < committed_mb):
            raise ApprovalRefused(
                "below-committed",
                f"anchor {total_cpus} cpus / {total_memory_mb} MiB is below the "
                f"{placements} placement(s) vali already put there "
                f"({committed_cpus} vCPU / {committed_mb} MiB)",
            )
        changes: dict[str, Any] = {
            "total_cpus": total_cpus,
            "total_memory_mb": total_memory_mb,
            "approved_at": now,
            "approved_by": actor,
        }
        if total_disk_gb is not None:
            changes["total_disk_gb"] = total_disk_gb
        if trust_class is not None:
            changes["trust_class"] = trust_class
        result = ApprovalResult(
            node_id=node_id,
            approved_at=now,
            approved_by=actor,
            total_cpus=total_cpus,
            total_memory_mb=total_memory_mb,
            total_disk_gb=total_disk_gb if total_disk_gb is not None else row.total_disk_gb,
            trust_class=trust_class or row.trust_class,
            measured=m,
            binding=(cpu_bind, mem_bind, disk_bind),
            dry_run=dry_run,
        )
        if dry_run:
            # Validate the column values exactly as the write would.
            capacity_admin.diff(row, changes)
        else:
            capacity_admin.apply_capacity_change(row, changes, actor=actor, reason=reason)
    log.info("miner approval %s", result.as_dict())
    return result


def approval_status(node_id: str, *, now: datetime | None = None) -> dict[str, Any] | None:
    """The approval readout of `node_id` (`None` when it has no row yet):
    whether it is approved, by whom, whether it is held back right now, its
    anchor and what the heartbeat currently measures."""
    row = MinerCapacity.objects.filter(miner_node_id=node_id.strip().lower()).first()
    if row is None:
        return None
    m = measured(row, now=now or timezone.now())
    return {
        "node_id": row.miner_node_id,
        "approved": row.approved_at is not None,
        "approved_at": row.approved_at.isoformat() if row.approved_at else None,
        "approved_by": row.approved_by,
        "approval_required": approval_required(),
        "held_back": approval_required() and row.approved_at is None,
        "total_cpus": row.total_cpus,
        "total_memory_mb": row.total_memory_mb,
        "total_disk_gb": row.total_disk_gb,
        "trust_class": row.trust_class,
        "measured": {"cpus": m.cpus, "memory_mb": m.memory_mb, "disk_gb": m.disk_gb},
    }
