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

AUTOMATIC approval ([`auto_approve_pending`], self-service onboarding) runs
the SAME approval with no operator figure — the declared side is whatever
anchor the row already carries, NULL for a new miner, so the anchor is the
heartbeat's own figure — behind `VALI_MINER_AUTO_APPROVE` (and only while
approval is required), `actor = auto:attested-soak`. A pending miner is
approved automatically only when ALL of [`auto_approval_blocker`] holds:

1. its host-attestor is `attested` (never `pending`), on a desired
   measurement, beaconing, and its AMD-signed CHIP_ID is the miner's
   registered `platform_id` — and no OTHER registered miner's
   `platform_id` names that chip (the prefix rule matches a Turin-length id
   inside a Genoa-length one), so one real host cannot be re-enrolled
   under node after node to collect an approval for each;
2. it registered through `/v1/admin/miner/register` — a real CHIP_ID, not
   the `onchain:<node>` placeholder — with an explicit `snp_generation`,
   and its identity is not quarantined;
3. complete heartbeats (v3 capacity + v4 disk + free RAM) have arrived
   without a gap past the liveness timeout for
   `VALI_MINER_AUTO_APPROVE_SOAK_S` ([`record_heartbeat_soak`]) and are
   fresh now;
4. no operator cordon;
5. the manual approval's own refusals (range, freshness, committed load).

The trust class is never touched, so a new miner stays `earned`: the
anchor only clamps what it goes on to prove with attested VMs, it never
grants capacity by itself.

REVOCATION ([`revoke_approval`]) puts a miner back to pending and marks it
`revoked_at`. That mark is sticky: the automatic approval never approves a
revoked row; only an operator approval clears it.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import TYPE_CHECKING, Any

from django.conf import settings
from django.db import transaction
from django.utils import timezone

from . import capacity_admin
from .models import ACTIVE_PLACEMENT_STATES, CapacityTrustClass, MinerCapacity, Placement

if TYPE_CHECKING:
    from apps.miners.models import MinerIdentity

log = logging.getLogger("apps.scheduler.approval")

#: The cordon reason a pending miner carries in every gate readout.
PENDING_APPROVAL_REASON = "pending approval"
#: `approved_by` of a row approved on sight while approval is not required.
AUTO_APPROVER = "auto:approval-not-required"
#: The audit actor of an automatic approval ([`auto_approve_pending`]).
AUTO_SOAK_ACTOR = "auto:attested-soak"

#: [`auto_approval_blocker`] vocabulary, in the order the conditions are
#: checked. The attestor ones not listed here are the dispatchability gate's
#: own (`attestor-pending`, `cert-expired`, `measurement-stale`,
#: `attestor-stale`, `release-unpinned`, `attestor-missing`).
BLOCK_AUTO_OFF = "auto-approve-off"
BLOCK_APPROVED = "approved"
BLOCK_REVOKED = "revoked"
BLOCK_CORDONED = "cordoned"
BLOCK_NOT_REGISTERED = "not-registered"
BLOCK_IDENTITY_QUARANTINED = "identity-quarantined"
BLOCK_PLATFORM_PLACEHOLDER = "platform-id-placeholder"
BLOCK_SNP_GENERATION_UNSET = "snp-generation-unset"
BLOCK_ATTESTOR_CHIP_MISMATCH = "attestor-chip-mismatch"
BLOCK_CHIP_SHARED = "chip-shared"
BLOCK_ERROR = "error"
BLOCK_SOAK_NOT_STARTED = "soak-not-started"
BLOCK_SOAKING = "soaking"
BLOCK_NOT_MEASURED = "not-measured"

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
    `not-measured`, `below-committed`, `already-revoked`."""

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
        result = _approve_locked(
            row,
            cpus=cpus,
            memory_mb=memory_mb,
            disk_gb=disk_gb,
            actor=actor,
            reason=reason,
            trust_class=trust_class,
            dry_run=dry_run,
            now=now,
        )
    log.info("miner approval %s", result.as_dict())
    return result


@dataclass(frozen=True)
class Anchor:
    """The anchor an approval would set, and how each term was decided."""

    total_cpus: int
    total_memory_mb: int
    #: `None` = neither side has a disk figure (the column is left alone).
    total_disk_gb: int | None
    measured: Measured
    #: The declared side actually used per term (`disk` falls back to the
    #: anchor already on the row).
    declared: tuple[int | None, int | None, int | None]
    binding: tuple[str, str, str]


def _anchor(
    row: MinerCapacity,
    *,
    cpus: int | None,
    memory_mb: int | None,
    disk_gb: int | None,
    now: datetime,
) -> Anchor:
    """The anchor `min(declared, fresh heartbeat)` per term, range-checked
    and checked against what vali already placed on the miner. Read-only;
    raises [`ApprovalRefused`] (`not-measured`, `invalid`,
    `below-committed`)."""
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
    # The anchor itself must be a plausible host, whichever side set it: a
    # heartbeat figure is the miner's own word and carries no range check.
    _bounded("anchor cpus", total_cpus, MIN_CPUS, MAX_CPUS)
    _bounded("anchor memory_mb", total_memory_mb, MIN_MEMORY_MB, MAX_MEMORY_MB)
    _bounded("anchor disk_gb", total_disk_gb, MIN_DISK_GB, MAX_DISK_GB)
    placements, committed_mb, committed_cpus = _committed(row.miner_node_id)
    if placements and (total_cpus < committed_cpus or total_memory_mb < committed_mb):
        raise ApprovalRefused(
            "below-committed",
            f"anchor {total_cpus} cpus / {total_memory_mb} MiB is below the "
            f"{placements} placement(s) vali already put there "
            f"({committed_cpus} vCPU / {committed_mb} MiB)",
        )
    return Anchor(
        total_cpus=total_cpus,
        total_memory_mb=total_memory_mb,
        total_disk_gb=total_disk_gb,
        measured=m,
        declared=(cpus, memory_mb, declared_disk),
        binding=(cpu_bind, mem_bind, disk_bind),
    )


def _approve_locked(
    row: MinerCapacity,
    *,
    cpus: int | None,
    memory_mb: int | None,
    disk_gb: int | None,
    actor: str,
    reason: str,
    trust_class: str | None,
    dry_run: bool,
    now: datetime,
) -> ApprovalResult:
    """The approval itself, on `row` held under `select_for_update()` —
    shared by the operator ([`approve_miner`]) and the automatic approval.
    `cpus` / `memory_mb` / `disk_gb` are the declared side (`None` = no
    declaration: the heartbeat figure stands alone). Approving clears a
    revocation: an approval is the one thing that may."""
    if row.approved_at is not None:
        raise ApprovalRefused(
            "already-approved",
            f"approved at {row.approved_at.isoformat()} by {row.approved_by or '?'}; "
            "change the anchor with vali_set_miner_capacity",
        )
    anchor = _anchor(row, cpus=cpus, memory_mb=memory_mb, disk_gb=disk_gb, now=now)
    total_cpus, total_memory_mb, total_disk_gb = (
        anchor.total_cpus,
        anchor.total_memory_mb,
        anchor.total_disk_gb,
    )
    m = anchor.measured
    changes: dict[str, Any] = {
        "total_cpus": total_cpus,
        "total_memory_mb": total_memory_mb,
        "approved_at": now,
        "approved_by": actor,
        "revoked_at": None,
        "revoked_by": "",
    }
    if total_disk_gb is not None:
        changes["total_disk_gb"] = total_disk_gb
    if trust_class is not None:
        changes["trust_class"] = trust_class
    result = ApprovalResult(
        node_id=row.miner_node_id,
        approved_at=now,
        approved_by=actor,
        total_cpus=total_cpus,
        total_memory_mb=total_memory_mb,
        total_disk_gb=total_disk_gb if total_disk_gb is not None else row.total_disk_gb,
        trust_class=trust_class or row.trust_class,
        measured=m,
        binding=anchor.binding,
        dry_run=dry_run,
    )
    if dry_run:
        # Validate the column values exactly as the write would.
        capacity_admin.diff(row, changes)
    else:
        capacity_admin.apply_capacity_change(row, changes, actor=actor, reason=reason)
    return result


def revoke_approval(
    node_id: str, *, revoker: str, reason: str, now: datetime | None = None
) -> dict[str, Any]:
    """Put `node_id` back to PENDING and mark it revoked.

    Works on an approved row (grandfathered ones included) and on a pending
    one — revoking a pending miner is how an operator stops the automatic
    approval from ever taking it. The anchor is left as it is. While
    approval is required the miner takes no new work from the next
    placement on; the VMs already on it are untouched, as with a cordon.

    Raises [`ApprovalRefused`] (`not-found`, `invalid`, `already-revoked`)
    and writes nothing on refusal."""
    node_id = node_id.strip().lower()
    revoker = revoker.strip()
    reason = reason.strip()
    if not revoker:
        raise ApprovalRefused("invalid", "a revocation needs the revoker")
    if not reason:
        raise ApprovalRefused("invalid", "a revocation needs a reason")
    actor = f"op:{revoker}"
    if len(actor) > MinerCapacity._meta.get_field("revoked_by").max_length:
        raise ApprovalRefused("invalid", "revoker is too long")
    now = now or timezone.now()
    with transaction.atomic():
        row = MinerCapacity.objects.select_for_update().filter(miner_node_id=node_id).first()
        if row is None:
            raise ApprovalRefused("not-found", "no MinerCapacity row for this node id")
        if row.approved_at is None and row.revoked_at is not None:
            raise ApprovalRefused(
                "already-revoked",
                f"revoked at {row.revoked_at.isoformat()} by {row.revoked_by or '?'}",
            )
        capacity_admin.apply_capacity_change(
            row,
            {
                "approved_at": None,
                "approved_by": "",
                "revoked_at": now,
                "revoked_by": actor,
                "approval_soak_since": None,
            },
            actor=actor,
            reason=reason,
        )
    log.warning("miner approval revoked node_id=%s by=%s", node_id, actor)
    return {"node_id": node_id, "revoked_at": now.isoformat(), "revoked_by": actor}


# ─── automatic approval ──────────────────────────────────────────────


def auto_approve_enabled() -> bool:
    """`VALI_MINER_AUTO_APPROVE`, effective only while approval is required
    (with approval off every row is approved on sight anyway)."""
    return approval_required() and bool(getattr(settings, "VALI_MINER_AUTO_APPROVE", False))


def auto_approve_soak_s() -> int:
    return int(getattr(settings, "VALI_MINER_AUTO_APPROVE_SOAK_S", 1800))


def record_heartbeat_soak(node_id: str, *, complete: bool, now: datetime) -> None:
    """Advance the automatic-approval soak of PENDING row `node_id` on an
    accepted heartbeat. Called by the heartbeat ingest BEFORE it stamps this
    heartbeat's `declared_at` / `disk_reported_at`, so those still hold the
    previous complete heartbeat's times.

    A `complete` heartbeat (v3 capacity + v4 disk + free RAM) keeps the
    running soak when the previous one was complete and inside the liveness
    timeout, and starts a new one (`now`) otherwise; an incomplete one ends
    it. One filtered UPDATE: approved rows (the grandfathered fleet
    included) and revoked rows are never written."""
    from django.db.models import Case, F, Q, Value, When

    from .service import miner_liveness_timeout_s

    # Revoked rows are never approved automatically, so they never soak:
    # the revocation's own clearing of the soak stays cleared.
    pending = MinerCapacity.objects.filter(
        miner_node_id=node_id, approved_at__isnull=True, revoked_at__isnull=True
    )
    if not complete:
        pending.filter(approval_soak_since__isnull=False).update(approval_soak_since=None)
        return
    cutoff = now - timedelta(seconds=miner_liveness_timeout_s())
    unbroken = Q(
        approval_soak_since__isnull=False,
        declared_at__gte=cutoff,
        disk_reported_at__gte=cutoff,
    )
    pending.update(
        approval_soak_since=Case(
            When(unbroken, then=F("approval_soak_since")),
            default=Value(now),
        )
    )


def _attestor_blocker(node_id: str, platform_id: str, *, now: datetime) -> str | None:
    """`None` when an `attested` host-attestor row of `node_id` covers it
    (desired measurement, live beacon — the dispatchability gate's own
    predicate) AND its AMD-signed CHIP_ID is the registered `platform_id`.
    Otherwise the reason: no row, a CHIP_ID that is not this miner's, or the
    gate reason of the best row whose chip does match."""
    from apps.telemetry import release_service
    from apps.telemetry.models import HostAttestor
    from apps.telemetry.vm_liveness import chip_matches_platform

    from .reasons import REASON_ATTESTOR_MISSING, REASON_RELEASE_UNPINNED

    rows = list(HostAttestor.objects.filter(node_id__iexact=node_id))
    if not rows:
        return REASON_ATTESTOR_MISSING
    ours = [
        r for r in rows if chip_matches_platform(chip_id_hex=r.chip_id, platform_id=platform_id)
    ]
    if not ours:
        return BLOCK_ATTESTOR_CHIP_MISMATCH
    desired = release_service._desired_measurement_set()
    if not desired:
        return REASON_RELEASE_UNPINNED
    live_cutoff = now - timedelta(seconds=release_service._liveness_window_seconds())
    reasons = [
        release_service._row_coverage_reason(r, desired_set=desired, live_cutoff=live_cutoff)
        for r in ours
    ]
    if None in reasons:
        return None
    return min(reasons, key=lambda r: release_service._REASON_RANK[r])  # type: ignore[index]


def _chip_shared(identity: MinerIdentity) -> bool:
    """Whether another registered miner's `platform_id` names the same chip
    as `identity`'s — equal, or one a prefix of the other (the CHIP_ID
    prefix rule: Turin registers 8 bytes, Milan/Genoa 64). `platform_id` is
    unique only as an exact string, so this is what makes "one chip, one
    miner" hold for the automatic approval."""
    from apps.miners.models import MinerIdentity

    from .service import _is_real_chip_id

    mine = identity.platform_id.strip().lower()
    for other in (
        MinerIdentity.objects.exclude(miner_id=identity.miner_id)
        .values_list("platform_id", flat=True)
        .iterator()
    ):
        theirs = (other or "").strip().lower()
        if _is_real_chip_id(theirs) and (mine.startswith(theirs) or theirs.startswith(mine)):
            return True
    return False


@dataclass(frozen=True)
class Condition:
    """One automatic-approval condition as judged on one miner."""

    name: str
    passed: bool
    #: The [`auto_approval_blocker`] code this condition reports when it fails.
    blocker: str
    detail: str = ""

    def as_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "passed": self.passed,
            "blocker": self.blocker,
            "detail": self.detail,
        }


def _conditions(row: MinerCapacity, *, now: datetime, exhaustive: bool) -> list[Condition]:
    """The automatic-approval conditions on `row`, in the order
    [`auto_approval_blocker`] applies them. `exhaustive=False` stops at the
    first failure (the decision); `True` judges every one (the evaluation),
    an identity-dependent condition failing as `not-registered` when there
    is no identity. Read-only."""
    from apps.miners.models import MinerIdentity, MinerStatus, is_autoprovision_placeholder

    from .service import _is_real_chip_id

    out: list[Condition] = []

    def judge(name: str, passed: bool, blocker: str, detail: str = "") -> bool:
        out.append(Condition(name, passed, blocker, detail))
        return passed or exhaustive

    if not judge("pending", row.approved_at is None, BLOCK_APPROVED, row.approved_by):
        return out
    if not judge("not-revoked", row.revoked_at is None, BLOCK_REVOKED, row.revoked_by):
        return out
    if not judge("not-cordoned", row.cordoned_at is None, BLOCK_CORDONED, row.cordon_reason):
        return out
    if not judge("auto-approve-on", auto_approve_enabled(), BLOCK_AUTO_OFF):
        return out
    node_id = row.miner_node_id.lower()
    identity = MinerIdentity.objects.filter(chain_node_id=node_id).first()
    if not judge(
        "registered",
        identity is not None,
        BLOCK_NOT_REGISTERED,
        identity.miner_id if identity is not None else "",
    ):
        return out
    if identity is None:
        for name in (
            "identity-active",
            "real-chip-id",
            "snp-generation",
            "attestor",
            "chip-not-shared",
        ):
            out.append(Condition(name, False, BLOCK_NOT_REGISTERED, "no identity"))
    else:
        if not judge(
            "identity-active",
            identity.status == MinerStatus.ACTIVE,
            BLOCK_IDENTITY_QUARANTINED,
            identity.status,
        ):
            return out
        real_chip = not is_autoprovision_placeholder(identity.platform_id) and _is_real_chip_id(
            identity.platform_id
        )
        if not judge("real-chip-id", real_chip, BLOCK_PLATFORM_PLACEHOLDER):
            return out
        if not judge(
            "snp-generation",
            bool(identity.snp_generation),
            BLOCK_SNP_GENERATION_UNSET,
            identity.snp_generation,
        ):
            return out
        attestor = _attestor_blocker(node_id, identity.platform_id, now=now)
        if not judge("attestor", attestor is None, attestor or "", attestor or "covered"):
            return out
        if not judge("chip-not-shared", not _chip_shared(identity), BLOCK_CHIP_SHARED):
            return out
    soak_s = auto_approve_soak_s()
    since = row.approval_soak_since
    if since is None:
        soaked, blocker, detail = False, BLOCK_SOAK_NOT_STARTED, f"0s of {soak_s}s"
    else:
        elapsed = int((now - since).total_seconds())
        soaked = since <= now - timedelta(seconds=soak_s)
        blocker, detail = BLOCK_SOAKING, f"{elapsed}s of {soak_s}s since {since.isoformat()}"
    if not judge("soak", soaked, blocker, detail):
        return out
    m = measured(row, now=now)
    stale = [
        d for d, v in (("cpus", m.cpus), ("memory", m.memory_mb), ("disk", m.disk_gb)) if v is None
    ]
    judge(
        "heartbeat-fresh",
        not stale,
        BLOCK_NOT_MEASURED,
        f"missing or stale: {', '.join(stale)}" if stale else "",
    )
    return out


def auto_approval_blocker(row: MinerCapacity, *, now: datetime) -> str | None:
    """The first automatic-approval condition `row` fails, or `None` when
    it may be approved automatically (module docstring, conditions 1-4; the
    approval itself then applies 5). Read-only."""
    for condition in _conditions(row, now=now, exhaustive=False):
        if not condition.passed:
            return condition.blocker
    return None


#: Conditions about the approval STATE and the switch, not the miner: set
#: aside by `would_approve_if_pending` (see [`evaluate_auto_approval`]).
_STATE_CONDITIONS = frozenset({"pending", "not-revoked", "auto-approve-on"})


def _anchor_readout(row: MinerCapacity, *, now: datetime) -> dict[str, Any]:
    """The anchor the real pass would set on `row` (the row's own anchor as
    the declared side), or the approval's refusal."""
    try:
        a = _anchor(row, cpus=row.total_cpus, memory_mb=row.total_memory_mb, disk_gb=None, now=now)
    except ApprovalRefused as exc:
        return {"ok": False, "refusal": exc.code, "detail": exc.message}
    return {
        "ok": True,
        "terms": {
            dim: {
                "declared": declared,
                "heartbeat": heartbeat,
                "result": result,
                "binding": binding.split(":", 1)[1],
            }
            for dim, declared, heartbeat, result, binding in zip(
                ("cpus", "memory_mb", "disk_gb"),
                a.declared,
                (a.measured.cpus, a.measured.memory_mb, a.measured.disk_gb),
                (a.total_cpus, a.total_memory_mb, a.total_disk_gb),
                a.binding,
                strict=True,
            )
        },
    }


#: `cap_source` values of the as-new memory cap.
CAP_HEARTBEAT_BUDGET = "heartbeat-cvm-memory-budget"
CAP_ROW_ANCHOR = "row-anchor"


def _host_memory_cap(row: MinerCapacity, *, now: datetime) -> tuple[int | None, str | None]:
    """The host's memory as vali knows it, for capping the as-new figure:
    the v3 declared CVM memory budget when fresh (the operator's configured
    figure, meant to be at most the physical RAM; nothing enforces it, but
    a cap can only lower the readout), else the row's anchor (which may be
    an earlier, load-reduced figure, so it can under-read), else nothing."""
    from .service import miner_liveness_timeout_s

    cutoff = now - timedelta(seconds=miner_liveness_timeout_s())
    if (
        row.declared_memory_mb_budget is not None
        and row.declared_at is not None
        and row.declared_at >= cutoff
    ):
        return row.declared_memory_mb_budget, CAP_HEARTBEAT_BUDGET
    if row.total_memory_mb is not None:
        return row.total_memory_mb, CAP_ROW_ANCHOR
    return None, None


def _anchor_as_new_readout(row: MinerCapacity, *, now: datetime) -> dict[str, Any]:
    """The anchor a NEW miner on `row`'s hardware would get: no declared
    side, so the heartbeat figures. A new miner hosts nothing, but this one
    may: its free-RAM figure excludes the RAM its VMs hold, so the memory
    added back is vali's own committed figure for them (the placement
    ledger, not a measurement: pending or power-stopped VMs make it read
    high), and there is no committed-load check. The ranges still apply.

    That add-back can overshoot the host (part of a guest's RAM is already
    outside MemAvailable, and pending / stopped VMs hold none), so the sum
    is capped at the host's memory as known: the v3 heartbeat's declared
    CVM memory budget when fresh, else the row's anchor. With neither, it
    is shown uncapped and says so."""
    m = measured(row, now=now)
    if m.cpus is None or m.memory_mb is None:
        return {
            "ok": False,
            "refusal": "not-measured",
            "detail": "no fresh heartbeat cpu budget / available memory",
        }
    placements, committed_mb, _cpus = _committed(row.miner_node_id)
    added_back = m.memory_mb + committed_mb
    cap, cap_source = _host_memory_cap(row, now=now)
    memory_mb = added_back if cap is None else min(added_back, cap)
    try:
        _bounded("anchor cpus", m.cpus, MIN_CPUS, MAX_CPUS)
        _bounded("anchor memory_mb", memory_mb, MIN_MEMORY_MB, MAX_MEMORY_MB)
        _bounded("anchor disk_gb", m.disk_gb, MIN_DISK_GB, MAX_DISK_GB)
    except ApprovalRefused as exc:
        return {"ok": False, "refusal": exc.code, "detail": exc.message}
    return {
        "ok": True,
        "terms": {
            "cpus": {"heartbeat": m.cpus, "result": m.cpus},
            "memory_mb": {
                "heartbeat": m.memory_mb,
                "committed_added": committed_mb,
                "placements": placements,
                "cap": cap,
                "cap_source": cap_source,
                "result": memory_mb,
            },
            "disk_gb": {"heartbeat": m.disk_gb, "result": m.disk_gb},
        },
    }


def _evaluate_row(row: MinerCapacity, *, now: datetime) -> dict[str, Any]:
    conditions = [c.as_dict() for c in _conditions(row, now=now, exhaustive=True)]
    if row.approved_at is not None:
        state = "approved"
    elif row.revoked_at is not None:
        state = "revoked"
    else:
        state = "pending"
    if state != "pending":
        # Only pending rows soak (an approved row has no use for it, a
        # revoked one never auto-approves), so the soak is not a fact about
        # this miner: report it as unknown and judge it on freshness alone.
        for c in conditions:
            if c["name"] == "soak":
                c.update(passed=None, detail="not tracked for an approved or revoked miner")
    anchor = _anchor_readout(row, now=now)
    anchor_as_new = _anchor_as_new_readout(row, now=now)
    return {
        "node_id": row.miner_node_id,
        "state": state,
        "approved_by": row.approved_by,
        "auto_approve_on": auto_approve_enabled(),
        "would_approve": all(c["passed"] for c in conditions) and anchor["ok"],
        "would_approve_if_pending": all(
            c["passed"] is not False for c in conditions if c["name"] not in _STATE_CONDITIONS
        )
        and anchor_as_new["ok"],
        # The anchors' refusals too, so `failed` alone explains a False.
        "failed": [c["name"] for c in conditions if c["passed"] is False]
        + [
            name
            for name, a in (("anchor", anchor), ("anchor_as_new", anchor_as_new))
            if not a["ok"]
        ],
        "conditions": conditions,
        "anchor": anchor,
        "anchor_as_new": anchor_as_new,
        "current_anchor": {
            "cpus": row.total_cpus,
            "memory_mb": row.total_memory_mb,
            "disk_gb": row.total_disk_gb,
        },
    }


def evaluate_auto_approval(*, now: datetime | None = None) -> list[dict[str, Any]]:
    """What the automatic approval WOULD decide for every miner — approved
    ones (the grandfathered fleet) included — and the anchor it would set.
    Writes nothing. One row that raises is reported as `error` and the rest
    are still evaluated.

    Per miner:

    - `state`: `approved` / `pending` / `revoked`;
    - `conditions`: every condition, `passed` true / false — or `null` for
      the soak of an approved or revoked miner, which is never tracked;
      `failed` names the false ones;
    - `would_approve`: what the next pass would actually do (switch as
      configured, soak as recorded);
    - `would_approve_if_pending`: the verdict on the MINER alone, as if it
      were a new pending miner with the switch on — the approval state and
      the switch are set aside, an untracked soak does not count against
      it, and the anchor is `anchor_as_new`;
    - `anchor`: what the real pass would set — per term the declared side
      (the anchor the row already holds), the heartbeat figure, the result
      and which side won, or the approval's refusal;
    - `anchor_as_new`: what a new miner on this hardware gets — the
      heartbeat figures, range-checked, with the RAM vali's own VMs hold on
      it added back to the free-RAM figure (a loaded miner's free RAM is not
      its size), and no committed-load check;
    - `failed`: the false conditions, then `anchor` / `anchor_as_new` when
      that anchor is refused;
    - `current_anchor`: the row's anchor now."""
    now = now or timezone.now()
    out: list[dict[str, Any]] = []
    for row in MinerCapacity.objects.order_by("miner_node_id"):
        try:
            out.append(_evaluate_row(row, now=now))
        except Exception as exc:  # noqa: BLE001 — one bad row must not hide the fleet.
            log.exception("auto-approval evaluation of %s raised", row.miner_node_id)
            out.append({"node_id": row.miner_node_id, "state": "error", "error": repr(exc)[:300]})
    return out


@dataclass(frozen=True)
class AutoApproveReport:
    approved: tuple[str, ...]
    #: `{node_id: blocker}` of every pending row left pending — a blocker
    #: from [`auto_approval_blocker`] or an [`ApprovalRefused`] code.
    blocked: dict[str, str]


def auto_approve_pending(*, now: datetime | None = None) -> AutoApproveReport:
    """Approve every pending, unrevoked, uncordoned miner that meets the
    automatic-approval conditions. Idempotent: an approved row is no longer
    a candidate, and each candidate is re-judged under its row lock, so a
    revocation or a cordon racing this pass wins. Nothing happens unless
    [`auto_approve_enabled`]."""
    if not auto_approve_enabled():
        return AutoApproveReport(approved=(), blocked={})
    now = now or timezone.now()
    soak = auto_approve_soak_s()
    approved: list[str] = []
    blocked: dict[str, str] = {}
    candidates = MinerCapacity.objects.filter(
        approved_at__isnull=True, revoked_at__isnull=True, cordoned_at__isnull=True
    ).values_list("miner_node_id", flat=True)
    for node_id in list(candidates):
        try:
            with transaction.atomic():
                row = MinerCapacity.objects.select_for_update().get(miner_node_id=node_id)
                blocker = auto_approval_blocker(row, now=now)
                if blocker is not None:
                    blocked[node_id] = blocker
                    continue
                result = _approve_locked(
                    row,
                    cpus=row.total_cpus,
                    memory_mb=row.total_memory_mb,
                    disk_gb=None,
                    actor=AUTO_SOAK_ACTOR,
                    reason=(
                        "automatic: attested host-attestor on the registered CHIP_ID, "
                        f"complete heartbeats for >= {soak}s"
                    ),
                    trust_class=None,
                    dry_run=False,
                    now=now,
                )
        except ApprovalRefused as exc:
            blocked[node_id] = exc.code
            continue
        except Exception:  # noqa: BLE001 — one bad row must not stall the rest.
            log.exception("automatic approval of %s raised", node_id)
            blocked[node_id] = BLOCK_ERROR
            continue
        log.warning("miner approved automatically %s", result.as_dict())
        approved.append(node_id)
    return AutoApproveReport(approved=tuple(approved), blocked=blocked)


def approval_status(node_id: str, *, now: datetime | None = None) -> dict[str, Any] | None:
    """The approval readout of `node_id` (`None` when it has no row yet):
    whether it is approved, by whom, whether it is held back right now, its
    anchor and what the heartbeat currently measures."""
    row = MinerCapacity.objects.filter(miner_node_id=node_id.strip().lower()).first()
    if row is None:
        return None
    now = now or timezone.now()
    m = measured(row, now=now)
    return {
        "node_id": row.miner_node_id,
        "approved": row.approved_at is not None,
        "approved_at": row.approved_at.isoformat() if row.approved_at else None,
        "approved_by": row.approved_by,
        "approval_required": approval_required(),
        "held_back": approval_required() and row.approved_at is None,
        "revoked_at": row.revoked_at.isoformat() if row.revoked_at else None,
        "revoked_by": row.revoked_by,
        "auto_approve": auto_approve_enabled(),
        "auto_approval_soak_since": (
            row.approval_soak_since.isoformat() if row.approval_soak_since else None
        ),
        "auto_approval_blocker": auto_approval_blocker(row, now=now),
        "total_cpus": row.total_cpus,
        "total_memory_mb": row.total_memory_mb,
        "total_disk_gb": row.total_disk_gb,
        "trust_class": row.trust_class,
        "measured": {"cpus": m.cpus, "memory_mb": m.memory_mb, "disk_gb": m.disk_gb},
    }
