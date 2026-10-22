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

## Self-service hardware ceiling (`VALI_CAPACITY_DECLARED_CEILING`)

A miner nobody anchored still has a size: its own heartbeat-declared #668
budgets (`hardware_ceiling`). With the flag on, that ceiling BOUNDS growth
— a held proof never lifts a ceiling past what the miner says its machine
has, and a dimension it declares nothing for does not grow — but it never
grants anything: only held proof does. Lying high gains nothing beyond what
the miner then proves under load; lying low only throttles itself. The
same flag adds one penalty and the strike record:

- `GUEST_RESOURCE_SHORT`: VMs on the host whose guests ATTEST less than
  their flavor (`telemetry.guest_resources`, PSP-signed figures the miner
  relays but cannot change), from at least
  `VALI_CAPACITY_SHORTFALL_MIN_OWNERS` (≥ 2) distinct tenants, cost the
  host the `START_FAILED` decrease, once per tenant SET. Root inside a
  guest can forge its own figures, hence the corroboration: one tenant
  cannot shrink a rival alone, extra VMs of the same tenants add nothing,
  and even a Sybil campaign (a new tenant account per halving) stops at
  the floor — never exclusion. This is the backstop for CPU overcommit /
  RAM ballooning behind an inflated declaration.
- A charged event (with an incident) that has nothing left to lower
  writes a `strike` audit row instead of nothing.

Staking / slashing is out of scope here: a strike is the hook a future
stake-weighted penalty would read (`MinerCapacityAudit`, `field=strike`
plus every `event:*` actor).

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

import hashlib
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
GUEST_RESOURCE_SHORT = "guest-resource-short"
EVENTS: frozenset[str] = frozenset(
    {PREFLIGHT_INSUFFICIENT, START_FAILED, CVM_INCAPABLE, DISK_INSUFFICIENT, GUEST_RESOURCE_SHORT}
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
    from apps.orchestration.launch_purpose import exclude_purpose
    from apps.telemetry.models import VmLiveAttestation
    from apps.telemetry.vm_liveness import (
        chip_matches_node,
        coverage_span_seconds,
        pinned_measurements,
    )

    from .scoring import _excluded_owners
    from .service import _committed_resources

    # Our own VMs (synthetic probes, disk probes, canaries, rehearsals,
    # load tests — the reward-excluded owners, and any VM launched with a
    # `purpose`) are never proof of fill: a miner earns neither pay nor
    # capacity for hosting them.
    classes = dict(
        exclude_purpose(
            Placement.objects.filter(
                miner_node_id=node_id, status=PlacementStatus.BOUND.value
            ).exclude(owner__in=_excluded_owners())
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


def hardware_ceiling(row: MinerCapacity) -> dict[str, int | None]:
    """The host's self-service HARDWARE CEILING per dimension: the most
    conservative of every hardware figure vali has for it, `None` where it
    has none.

    - vcpus:     the declared `cvm_cpu_budget`; the anchor's
                 `(total_cpus − reserve) × ratio`;
    - memory_mb: the declared `cvm_memory_mb_budget`; the anchor's
                 `total_memory_mb − reserve`;
    - vms:       the declared SEV-ES ASID capacity less the reserve.

    Declared figures count whether fresh or not — the miner's last word
    is its claim until it says otherwise, and a ceiling only ever bounds
    growth. (The §18 hardware report is deliberately NOT a term: it is
    owner-facing only and nothing that decides may read it — pinned by
    the disktier isolation test.)"""
    from .service import _host_reserve_cpus, _host_reserve_memory_mb

    vcpus: list[int] = []
    mem: list[int] = []
    vms: list[int] = []
    if row.declared_cpu_budget is not None:
        vcpus.append(row.declared_cpu_budget)
    if row.declared_memory_mb_budget is not None:
        mem.append(row.declared_memory_mb_budget)
    if row.declared_asid_capacity is not None:
        vms.append(max(0, row.declared_asid_capacity - capacity_config.asid_reserve()))
    if row.total_cpus is not None and row.total_memory_mb is not None:
        ratio = (
            row.cpu_ratio if row.cpu_ratio is not None else capacity_config.cpu_overcommit_default()
        )
        vcpus.append(int(max(0, row.total_cpus - _host_reserve_cpus()) * ratio))
        mem.append(max(0, row.total_memory_mb - _host_reserve_memory_mb()))
    return {
        "vms": min(vms) if vms else None,
        "vcpus": min(vcpus) if vcpus else None,
        "memory_mb": min(mem) if mem else None,
    }


def _bounded_by_ceiling(
    target: dict[str, int], current: dict[str, int], ceiling: dict[str, int | None]
) -> dict[str, int]:
    """`target` with growth stopped at the hardware ceiling. Never below
    `current`: lowering a ceiling is the penalties' job, and the budget
    already takes the fresh declaration as a down-only term. No ceiling
    signal for a dimension ⇒ it does not grow."""
    out: dict[str, int] = {}
    for d in _DIMS:
        cap = ceiling[d]
        out[d] = min(target[d], current[d] if cap is None else max(current[d], cap))
    return out


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
        else:  # START_FAILED / GUEST_RESOURCE_SHORT — multiplicative decrease, floored.
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
            if (
                capacity_config.declared_ceiling_enabled()
                and incident
                and kind != PREFLIGHT_INSUFFICIENT
                and row.cvm_last_ok_at is not None
            ):
                # Nothing left to lower — the fault still goes on record,
                # once per incident (an incident-less event, e.g. the tick's
                # incapable reset, would strike every pass). A preflight
                # refusal is honest behaviour, never a strike. Probation: a
                # host that has never started a CVM is still onboarding —
                # its failures are setup, not misbehaviour, so no strike
                # before its first successful start.
                capacity_admin.record_strike(row, actor=actor, reason=reason)
                log.warning("capacity strike on %s by %s (at the floor)", node_id, kind)
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


#: A finding that the guest ran a STALE launch (`guest_resources`), not one
#: that it was given less than its flavor: evidence of something, but not
#: of missing hardware.
_SUPERSEDED_REASON = "superseded-launch"


def shortfall_owners_by_node(now: datetime) -> dict[str, frozenset[str]]:
    """`{node_id: tenants}` — per host, the distinct tenants whose VMs have
    a fresh guest-resource SHORTFALL there (inside the flag window of
    `telemetry.guest_resources`). Keyed on the node id vali credited the
    VERIFIED attestation to — never a miner field. Superseded-launch
    findings are not shortfalls; a VM vali has no tenant for (no `Vm` row,
    blank `tenant_id`) counts for nobody, so it cannot corroborate."""
    from apps.lifecycle.models import Vm
    from apps.telemetry.guest_resources import flag_window_s
    from apps.telemetry.models import GuestResourceShortfall

    since = now - timedelta(seconds=flag_window_s())
    rows = list(
        GuestResourceShortfall.objects.filter(last_seen_at__gte=since)
        .exclude(reason=_SUPERSEDED_REASON)
        .values_list("node_id_hex", "vm_id")
    )
    if not rows:
        return {}
    owner_of = dict(
        Vm.objects.filter(vm_id__in={vm for _, vm in rows})
        .exclude(tenant_id="")
        .values_list("vm_id", "tenant_id")
    )
    out: dict[str, set[str]] = {}
    for node, vm in rows:
        if vm in owner_of:
            out.setdefault(node.lower(), set()).add(owner_of[vm])
    return {node: frozenset(owners) for node, owners in out.items()}


def shortfall_incident(
    node_id: str, *, now: datetime, owners_by_node: dict[str, frozenset[str]] | None = None
) -> str:
    """The `GUEST_RESOURCE_SHORT` incident to charge `node_id` now, or `""`.

    Charged only once the host's fresh shortfalls span
    `shortfall_min_owners` distinct tenants ([`shortfall_owners_by_node`]).
    The incident is that SET of tenants (hashed — tenant ids stay out of
    the audit): an unchanged set is charged once however many VMs it
    holds, so one tenant forging shortfalls on VM after VM gains nothing
    once corroborated; each further halving needs a tenant set never
    charged before. `owners_by_node` lets the tick compute the fleet once."""
    if owners_by_node is None:
        owners_by_node = shortfall_owners_by_node(now)
    owners = owners_by_node.get(node_id.lower(), frozenset())
    if len(owners) < capacity_config.shortfall_min_owners():
        return ""
    digest = hashlib.sha256("\n".join(sorted(owners)).encode()).hexdigest()[:16]
    return f"tenants={len(owners)} set={digest}"


# ─── the tick (growth) ──────────────────────────────────────────────


@dataclass(frozen=True)
class EarnReport:
    earned_rows: int = 0
    proof_available: bool = False
    grown: int = 0
    held: int = 0
    reset_incapable: int = 0
    shortfall_penalties: int = 0


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
    ceiling_on = capacity_config.declared_ceiling_enabled()
    short_owners = shortfall_owners_by_node(now) if ceiling_on else {}
    grown = held = reset = short = 0
    proof_available = False
    for nid in rows:
        if capability.get(nid) == INCAPABLE:
            reset += int(record_event(nid, CVM_INCAPABLE, now=now))
            continue
        if ceiling_on:
            incident = shortfall_incident(nid, now=now, owners_by_node=short_owners)
            if incident:
                short += int(record_event(nid, GUEST_RESOURCE_SHORT, incident=incident, now=now))
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
                if ceiling_on:
                    target = _bounded_by_ceiling(target, current, hardware_ceiling(row))
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
        shortfall_penalties=short,
    )
