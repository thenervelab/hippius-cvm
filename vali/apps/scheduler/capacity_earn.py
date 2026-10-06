"""Earned capacity for permissionless (`earned`) miners — capacity v2 §3.

Nobody vali trusts has seen an `earned` miner's hardware, so its budget
is what it has PROVEN, never what it claims:

- It starts at the configured floor (`capacity_config.earn_floor_*`).
- It GROWS only from held proof: a concurrency of attested, live VMs the
  miner kept for the whole hold window (`earn_hold_s`), once that proof
  reaches `earn_util_trigger` of the current ceiling. Growth is
  multiplicative (`earn_growth`) with a minimum step, capped by the hard
  caps — so it follows real fill and cannot jump.
- It SHRINKS on vali-attributed faults, recorded by the write site that
  observed them (`record_event`): a preflight capacity refusal sets the
  ceiling to what the host was holding (honest behaviour, no penalty); a
  start the miner itself answered as failed halves it
  (`earn_penalty_factor`); an observed SNP-incapable host drops to the
  floor; a DATA-disk refusal (507 `insufficient-disk`) cuts the separate
  earned DISK ceiling by the same factor (`DISK_INSUFFICIENT`). Every
  event only ever LOWERS a ceiling; the CPU/RAM ones also invalidate the
  proof in progress. A boot stall is deliberately NOT an event: the same
  verdict comes from a tenant image without the telemetry agent or root
  inside the guest stopping it, which is no evidence against the host.

Every change goes through `capacity_admin.apply_capacity_change`, so it
is audited (`actor = tick:earn` / `event:<kind>`). `operator` rows are
never touched.

## Where proof comes from

`proven_concurrency` is the ONE place a proof is read, and it is gated
by `VALI_CAPACITY_EARN_PROOF`:

- `off` (the default): no proof is trusted, so ceilings never grow — the
  floor, the penalties, the operator grant and the in-flight cap all work.
- `live-attestation`: the host's BOUND placements whose VM has a FRESH
  KBS live attestation bound at RELEASE (schema v2, `binding_source =
  release`) from a guest that has lived here the whole hold window
  (`_live_attested`). The KBS records the SNP `(CHIP_ID, REPORT_ID)` of
  the guest it released each `vm_id`'s disk key to and refuses keepalives
  from any other guest (`kbs-core/src/keepalive_binding.rs`). REPORT_ID is
  assigned by the PSP per guest context, so N proven VMs need N distinct
  guests alive at once — one rented VM can no longer fake N. `first-use`
  bodies (no release on record, e.g. after a KBS restart) are never
  proof, and a guest claimed by two VMs proves neither.

A guest must itself have attested through a full hold before it counts,
and the tick then holds the concurrency for another — so with this source
growth takes about twice `earn_hold_s`. Deliberately conservative.

Enable `live-attestation` only once the KBS runs with
`keepalive_binding = "record"` or `"enforce"`; before that no row is v2
and the proof is simply empty.
"""

from __future__ import annotations

import logging
import math
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any

from django.conf import settings
from django.core.exceptions import ImproperlyConfigured
from django.db import transaction
from django.utils import timezone

from . import capacity_admin, capacity_config
from .models import (
    CapacityTrustClass,
    MinerCapacity,
    MinerCapacityAudit,
    Placement,
    PlacementStatus,
)

log = logging.getLogger("apps.scheduler.capacity_earn")

#: `record_event` kinds — a closed vali-side vocabulary, stored as
#: `earned_last_reason` and in the audit actor.
PREFLIGHT_INSUFFICIENT = "preflight-insufficient"
START_FAILED = "start-failed"
CVM_INCAPABLE = "cvm-incapable"
DISK_INSUFFICIENT = "disk-insufficient"
EVENTS: frozenset[str] = frozenset(
    {PREFLIGHT_INSUFFICIENT, START_FAILED, CVM_INCAPABLE, DISK_INSUFFICIENT}
)

PROOF_OFF = "off"
PROOF_LIVE_ATTESTATION = "live-attestation"
_PROOF_SOURCES = frozenset({PROOF_OFF, PROOF_LIVE_ATTESTATION})

_DIMS = ("vms", "vcpus", "memory_mb")


@dataclass(frozen=True)
class Sample:
    """A concurrency of proven VMs on one host: count, Σ vCPU, Σ RAM."""

    vms: int = 0
    vcpus: int = 0
    memory_mb: int = 0

    def covers(self, other: Sample) -> bool:
        return all(getattr(self, d) >= getattr(other, d) for d in _DIMS)


def proof_source() -> str:
    """`VALI_CAPACITY_EARN_PROOF` — which proof the tick may trust."""
    name = "VALI_CAPACITY_EARN_PROOF"
    value = str(getattr(settings, name, PROOF_OFF) or PROOF_OFF).strip().lower()
    if value not in _PROOF_SOURCES:
        raise ImproperlyConfigured(
            f"{name}={value!r} is not a proof source (expected one of: "
            f"{', '.join(sorted(_PROOF_SOURCES))})"
        )
    return value


def proven_concurrency(node_id: str, *, now: datetime) -> Sample | None:
    """The concurrency of attested, live VMs vali can PROVE on `node_id`
    at `now`, or `None` when no trusted proof source is configured."""
    source = proof_source()
    if source == PROOF_OFF:
        return None
    if source == PROOF_LIVE_ATTESTATION:
        return _live_attested(node_id, now=now)
    raise AssertionError("unreachable: proof_source() validated the value")


def _live_attested(node_id: str, *, now: datetime) -> Sample:
    """Σ over the host's BOUND placements whose VM is PROVEN running here
    for the whole hold window (see the module docs). A VM counts iff its
    newest fresh, release-bound live attestation

    - carries a measurement vali pinned for THAT vm_id (each VM's measured
      cmdline is its own, so another VM's guest cannot stand in),
    - was bound on a chip that is THIS node's registered platform, and
    - names a guest (CHIP_ID, REPORT_ID) that has attested, release-
      bound, since a full hold ago with no gap longer than the coverage
      span. REPORT_ID dies with the guest context, so a miner cannot
      rotate one slot through N relaunched VMs;

    and no other counted VM names the same guest.

    What this cannot prove: that the N guests were RESIDENT at once. A
    paused SNP guest keeps its REPORT_ID (and SNP page swap can move its
    memory out), so a miner could keep N contexts suspended and wake each
    one inside every span to attest. The gap bound makes that a sustained
    effort, not a free one — but it is a limit of liveness sampling, and
    why this source is opt-in."""
    from apps.telemetry.models import VmLiveAttestation
    from apps.telemetry.vm_liveness import (
        chip_matches_node,
        coverage_span_seconds,
        pinned_measurements,
    )

    from .service import _committed_resources

    classes = dict(
        Placement.objects.filter(
            miner_node_id=node_id, status=PlacementStatus.BOUND.value
        ).values_list("vm__vm_id", "resource_class")
    )
    if not classes:
        return Sample()
    now_unix = int(now.timestamp())
    span = coverage_span_seconds()
    fresh_from = now_unix - span
    hold = capacity_config.earn_hold_s()
    held_since = now_unix - hold
    bound = VmLiveAttestation.objects.filter(vm_id__in=list(classes), binding_source="release")
    newest: dict[str, tuple[str, str, str]] = {}
    for vm_id, chip, report, measurement in (
        bound.filter(verified_at_unix__gte=fresh_from)
        .order_by("vm_id", "-verified_at_unix")
        .values_list("vm_id", "chip_id", "report_id", "measurement")
    ):
        newest.setdefault(vm_id, (chip, report, measurement))
    guest_of: dict[str, tuple[str, str]] = {}
    for vm_id, (chip, report, measurement) in newest.items():
        if measurement.lower() not in pinned_measurements(vm_id):
            continue
        if not chip_matches_node(chip_id_hex=chip, node_id_hex=node_id):
            continue
        seen = list(
            bound.filter(
                vm_id=vm_id,
                chip_id=chip,
                report_id=report,
                verified_at_unix__gte=held_since - span,
            )
            .order_by("verified_at_unix")
            .values_list("verified_at_unix", flat=True)
        )
        if _attested_throughout(seen, since=held_since, span=span, hold=hold):
            guest_of[vm_id] = (chip, report)
    claims: dict[tuple[str, str], int] = {}
    for guest in guest_of.values():
        claims[guest] = claims.get(guest, 0) + 1
    vms = vcpus = mem = 0
    for vm_id, guest in guest_of.items():
        if claims[guest] > 1:
            continue  # one guest cannot be two VMs
        m, c = _committed_resources(classes[vm_id])
        vms += 1
        vcpus += c
        mem += m
    return Sample(vms, vcpus, mem)


def _attested_throughout(seen: list[int], *, since: int, span: int, hold: int) -> bool:
    """`seen` (ascending instants) starts at or before `since`, runs at
    least `hold` seconds from first to last sample, and never leaves a gap
    longer than `span` — the guest vouched for the whole window, as the
    uptime coverage meter would credit it. (The run length matters when
    `hold` < `span`: one sample must not count as both ends.)"""
    if not seen or seen[0] > since or seen[-1] - seen[0] < hold:
        return False
    return all(b - a <= span for a, b in zip(seen, seen[1:], strict=False))


# ─── current values (floor-resolved) ────────────────────────────────


def _floors() -> dict[str, int]:
    return {
        "vms": capacity_config.earn_floor_vms(),
        "vcpus": capacity_config.earn_floor_vcpus(),
        "memory_mb": capacity_config.earn_floor_memory_mb(),
    }


def _caps() -> dict[str, int]:
    return {
        "vms": capacity_config.earn_hard_cap_vms(),
        "vcpus": capacity_config.earn_hard_cap_vcpus(),
        "memory_mb": capacity_config.earn_hard_cap_memory_mb(),
    }


def _steps() -> dict[str, int]:
    return {
        "vms": capacity_config.earn_min_step_vms(),
        "vcpus": capacity_config.earn_min_step_vcpus(),
        "memory_mb": capacity_config.earn_min_step_memory_mb(),
    }


def earned_ceiling(row: MinerCapacity) -> dict[str, int]:
    """The row's earned ceiling with NULL resolved to the floor."""
    floors = _floors()
    return {
        d: floors[d] if getattr(row, f"earned_{d}") is None else getattr(row, f"earned_{d}")
        for d in _DIMS
    }


def _held(node_id: str) -> Sample:
    """What the host is actually RUNNING: its BOUND placements. Pending
    ones are excluded — the launch that was just refused is one of them."""
    from .service import _committed_resources

    vms = vcpus = mem = 0
    for rc in Placement.objects.filter(
        miner_node_id=node_id, status=PlacementStatus.BOUND.value
    ).values_list("resource_class", flat=True):
        m, c = _committed_resources(rc)
        vms += 1
        vcpus += c
        mem += m
    return Sample(vms, vcpus, mem)


# ─── events (penalties) ─────────────────────────────────────────────


def record_event(
    node_id: str, kind: str, *, incident: str = "", now: datetime | None = None
) -> bool:
    """Apply a vali-attributed capacity event to an `earned` miner.

    `node_id` MUST come from vali's own decision (the node it dispatched
    to), never from anything the miner sent — exactly as the
    `cvm_capability` ledger requires — so no miner can shrink a rival.
    `incident` makes the event idempotent: the same `(kind, incident)` on
    the same node is charged once, however often the launch that caused
    it retries (the key is kept in the audit row, so it survives
    restarts).

    Returns whether a change was written. `operator` rows and unknown
    nodes are ignored. Never raises into the caller's launch path: a
    failure here is logged, the placement outcome stands."""
    if kind not in EVENTS:
        raise ValueError(f"unknown capacity event {kind!r}")
    try:
        return _record_event(node_id, kind, incident=incident, now=now or timezone.now())
    except Exception:
        log.exception("capacity event %s for node %s could not be recorded", kind, node_id)
        return False


def _record_event(node_id: str, kind: str, *, incident: str, now: datetime) -> bool:
    actor = f"event:{kind}"
    reason = f"{kind} {incident}".strip()
    with transaction.atomic():
        row = MinerCapacity.objects.select_for_update().filter(miner_node_id=node_id).first()
        if row is None or row.trust_class != CapacityTrustClass.EARNED:
            return False
        if (
            incident
            and MinerCapacityAudit.objects.filter(
                miner_node_id=node_id, actor=actor, reason=reason
            ).exists()
        ):
            return False
        if kind == DISK_INSUFFICIENT:
            return _cut_disk_ceiling(row, actor=actor, reason=reason, now=now)
        current = earned_ceiling(row)
        floors = _floors()
        if kind == CVM_INCAPABLE:
            # Down to the floor — never UP to it: a ceiling already below
            # the floor (a refusal lowered it) stays where it is.
            new = {d: min(current[d], floors[d]) for d in _DIMS}
        elif kind == PREFLIGHT_INSUFFICIENT:
            # The host told us its true limit: what it RUNS now. Honest
            # behaviour — no penalty beyond the truth.
            held = _held(node_id)
            new = {d: min(current[d], getattr(held, d)) for d in _DIMS}
        else:  # START_FAILED — multiplicative decrease, floored.
            factor = capacity_config.earn_penalty_factor()
            new = {
                d: min(current[d], max(floors[d], math.ceil(current[d] * float(factor))))
                for d in _DIMS
            }
        changes: dict[str, Any] = {f"earned_{d}": v for d, v in new.items()}
        # A lowered ceiling must be re-earned: the proof cannot sit above
        # it, and the concurrency being held when the fault happened is
        # not proof of anything any more.
        for d in _DIMS:
            changes[f"proven_peak_{d}"] = min(getattr(row, f"proven_peak_{d}"), new[d])
            changes[f"candidate_{d}"] = 0
        changes["candidate_since"] = None
        if not capacity_admin.audited(capacity_admin.diff(row, changes)):
            return False
        changes["earned_last_reason"] = kind
        changes["earned_last_change_at"] = now
        capacity_admin.apply_capacity_change(row, changes, actor=actor, reason=reason)
        log.warning("earned capacity lowered on %s by %s: %s", node_id, kind, new)
        return True


def _cut_disk_ceiling(row: MinerCapacity, *, actor: str, reason: str, now: datetime) -> bool:
    """A disk refusal on a VM vali placed within the host's disk budget
    (checked here: committed, including the refused VM, ≤ budget, and no
    over-claim flagged): the budget the host let vali compute was more
    than it could hold, so the earned disk ceiling drops multiplicatively (`earn_penalty_factor`)
    from the CURRENT budget — the same shape as `START_FAILED` on CPU/RAM.

    Only the disk dimension moves: a full disk says nothing about the
    host's CPU, RAM or SEV. The cut is a new down-only term of the disk
    `min` (never a raise: `min(current, …)`), it is not re-grown by the
    tick (there is no disk proof), and `--earned-reset` clears it. A host
    vali has no disk figure for cannot be cut (there is no number to cut
    from); the refusal is logged and the unknown-disk policy governs."""
    from .service import _committed_by_node, disk_budgets_by_node

    committed = _committed_by_node()
    budget = disk_budgets_by_node(rows=[row], committed=committed)[row.miner_node_id]
    if not budget.known:
        log.warning(
            "disk refusal on %s but vali has no disk budget for it — nothing to cut",
            row.miner_node_id,
        )
        return False
    if budget.committed_gb > budget.budget_gb or budget.over_claim:
        # vali itself over-booked the host (placed past the budget under
        # `record` / `off` / unknown-allow), or the host had already told
        # it the fs was short (over-claim): the refusal is the host being
        # HONEST, and an honest refusal costs nothing — same rule as the
        # CPU/RAM preflight refusal. (The committed figure includes the
        # refused VM's own still-pending placement.)
        log.info(
            "disk refusal on %s is honest (committed %s GiB > budget %s GiB or "
            "over-claim flagged) — no cut",
            row.miner_node_id,
            budget.committed_gb,
            budget.budget_gb,
        )
        return False
    factor = capacity_config.earn_penalty_factor()
    new = min(budget.budget_gb, math.floor(budget.budget_gb * float(factor)))
    changes: dict[str, Any] = {"earned_disk_gb": max(0, new)}
    if not capacity_admin.audited(capacity_admin.diff(row, changes)):
        return False
    changes["earned_last_reason"] = DISK_INSUFFICIENT
    changes["earned_last_change_at"] = now
    capacity_admin.apply_capacity_change(row, changes, actor=actor, reason=reason)
    log.warning(
        "earned disk ceiling lowered on %s: %s -> %s GiB", row.miner_node_id, budget.budget_gb, new
    )
    return True


# ─── the tick (growth) ──────────────────────────────────────────────


@dataclass(frozen=True)
class EarnReport:
    earned_rows: int = 0
    proof_available: bool = False
    grown: int = 0
    held: int = 0
    reset_incapable: int = 0


def _grow(current: dict[str, int], proven: Sample) -> dict[str, int]:
    """Multiplicative increase from a held proof, gated on fill."""
    trigger = float(capacity_config.earn_util_trigger())
    if not any(getattr(proven, d) >= trigger * current[d] for d in _DIMS):
        return current
    growth = float(capacity_config.earn_growth())
    steps, caps = _steps(), _caps()
    return {
        d: min(
            caps[d],
            max(
                current[d],
                math.ceil(getattr(proven, d) * growth),
                getattr(proven, d) + steps[d],
            ),
        )
        for d in _DIMS
    }


def tick(*, now: datetime | None = None, sampler: Any = None) -> EarnReport:
    """One pass over every `earned` row. `sampler(node_id, now)` overrides
    `proven_concurrency` (tests)."""
    from .cvm_capability import INCAPABLE
    from .service import cvm_capability_by_node

    now = now or timezone.now()
    sample_of = sampler or (lambda nid, at: proven_concurrency(nid, now=at))
    capability = cvm_capability_by_node()
    hold = timedelta(seconds=capacity_config.earn_hold_s())
    decay_after = timedelta(seconds=capacity_config.earn_decay_after_s())
    rows = list(
        MinerCapacity.objects.filter(trust_class=CapacityTrustClass.EARNED).values_list(
            "miner_node_id", flat=True
        )
    )
    grown = held = reset = 0
    proof_available = False
    for nid in rows:
        if capability.get(nid) == INCAPABLE:
            reset += int(record_event(nid, CVM_INCAPABLE, now=now))
            continue
        sample = sample_of(nid, now)
        if sample is None:
            continue
        proof_available = True
        with transaction.atomic():
            row = MinerCapacity.objects.select_for_update().get(miner_node_id=nid)
            if row.trust_class != CapacityTrustClass.EARNED:
                continue  # moved to `operator` since the scan
            changes: dict[str, Any] = {}
            candidate = Sample(row.candidate_vms, row.candidate_vcpus, row.candidate_memory_mb)
            since = row.candidate_since
            if since is None or not sample.covers(candidate):
                # The concurrency dropped (or first sight): the hold restarts
                # from what is running now.
                candidate, since = sample, now
                changes.update(
                    candidate_vms=sample.vms,
                    candidate_vcpus=sample.vcpus,
                    candidate_memory_mb=sample.memory_mb,
                    candidate_since=now,
                )
            proven = Sample(row.proven_peak_vms, row.proven_peak_vcpus, row.proven_peak_memory_mb)
            if row.proven_at is not None and now - row.proven_at > decay_after:
                # A proof never renewed goes stale: re-prove from what runs now.
                proven = Sample(*(min(getattr(proven, d), getattr(sample, d)) for d in _DIMS))
                changes.update(
                    proven_peak_vms=proven.vms,
                    proven_peak_vcpus=proven.vcpus,
                    proven_peak_memory_mb=proven.memory_mb,
                    proven_at=now,
                )
            proved_now = now - since >= hold and candidate.vms > 0
            if proved_now:
                held += 1
                reproved = candidate.covers(proven)
                proven = Sample(*(max(getattr(proven, d), getattr(candidate, d)) for d in _DIMS))
                changes.update(
                    proven_peak_vms=proven.vms,
                    proven_peak_vcpus=proven.vcpus,
                    proven_peak_memory_mb=proven.memory_mb,
                )
                if reproved:
                    # Only a hold that reaches the peak renews it; a lower
                    # one must not keep an old peak from ever going stale.
                    changes["proven_at"] = now
                current = earned_ceiling(row)
                target = _grow(current, proven)
                if target != current:
                    grown += 1
                    changes.update(
                        {f"earned_{d}": target[d] for d in _DIMS},
                        earned_last_reason="proof-held",
                        earned_last_change_at=now,
                    )
            if proved_now and sample != candidate:
                # The held level is banked; a HIGHER concurrency now starts
                # its own hold. (A rise before the lower level was proven
                # does not reset the timer — the lower level keeps being
                # tested, so proof is conservative, never optimistic.)
                changes.update(
                    candidate_vms=sample.vms,
                    candidate_vcpus=sample.vcpus,
                    candidate_memory_mb=sample.memory_mb,
                    candidate_since=now,
                )
            if changes:
                capacity_admin.apply_capacity_change(
                    row, changes, actor="tick:earn", reason="proof-held"
                )
    return EarnReport(
        earned_rows=len(rows),
        proof_available=proof_available,
        grown=grown,
        held=held,
        reset_incapable=reset,
    )
