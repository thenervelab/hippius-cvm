"""Operator node-status read model — `GET /v1/operator/nodes`.

One row per requested on-chain `node_id`, assembled from ledgers vali
already keeps and NEVER from a miner's self-report:

- identity + liveness    `miners.MinerIdentity` (keyed by `chain_node_id`)
- attestation            `telemetry.HostAttestor` (best row for the node)
- schedulability         `scheduler.service.dispatchability` — the SAME
                         predicate `dispatchable_node_ids` feeds
                         `decide_placement` with, so the dashboard's
                         "schedulable" and the scheduler's "candidate"
                         cannot disagree
- capacity / load        `scheduler.service.decision_inputs` — the
                         effective admission slots + active placements
- recent refusals        FAILED `Placement` rows that are a judgement
                         about the node, selected by PROVENANCE
                         (`Placement.failure_source`, stamped by the
                         write site) and only then mapped by reason:
                         `scheduler_drain` (the §13 re-eval drained it,
                         minus the VM-side `drain:vm-terminal`) or
                         `launch` with a node-side outcome
                         (`reasons.LAUNCH_REFUSAL_OUTCOMES`). `release`,
                         `manual` (a `/fail` body, whatever it spells),
                         `migration` and `legacy` (ended before
                         provenance existed — unattributable) are never
                         refusals, nor is a `launch` row whose outcome is
                         a control-plane fault.

No tenant data crosses this surface: hosted VMs are a COUNT, placements
contribute `failed_at` + a reason mapped through the closed vocabulary in
`apps.scheduler.reasons` (`Placement.reason` itself is free text vali
writes from launch outcomes, drain causes and the `/fail` body; anything
outside the vocabulary is reported as `unknown`, never echoed).

Access control: this is a service-to-service surface (`OPERATOR_ONLY`
principal — the upstream product API). WHICH nodes a signed-in operator may
see is decided upstream against the chain (`FamilyChildren`); vali holds no
family table and does not re-check it here, by design.
"""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any

from django.db.models import Count, F, Q, QuerySet, Window
from django.db.models.functions import Lower, RowNumber
from django.utils import timezone

from apps.miners import geo
from apps.miners.models import LocationVerdict, MinerIdentity, MinerLocation
from apps.scheduler import service as scheduler_service
from apps.scheduler.models import (
    MinerCapacity,
    Placement,
    PlacementFailureSource,
    PlacementStatus,
)
from apps.scheduler.reasons import (
    LAUNCH_REFUSAL_OUTCOMES,
    NON_NODE_DRAIN_REASONS,
    public_refusal_reason,
)
from apps.telemetry.models import HostAttestor, HostAttestorStatus

#: Cap on `node_id` values per request — bounds the per-node queries.
MAX_NODE_IDS = 100
#: Most recent refusals listed per node.
RECENT_REFUSALS = 10
#: Window of `refusal_count_30d`.
REFUSAL_COUNT_WINDOW = timedelta(days=30)

# Which `HostAttestor` row speaks for a node when several exist (a chip
# re-key can leave two): the most-advanced status, then the freshest beacon.
_ATTESTOR_STATUS_RANK: dict[str, int] = {
    HostAttestorStatus.ATTESTED.value: 0,
    HostAttestorStatus.PENDING.value: 1,
    HostAttestorStatus.EXPIRED.value: 2,
}


def _iso(value: datetime | None) -> str | None:
    return value.isoformat() if value is not None else None


def _attestor_sort_key(row: HostAttestor) -> tuple[int, float]:
    seen = row.last_seen_at.timestamp() if row.last_seen_at is not None else float("-inf")
    return (_ATTESTOR_STATUS_RANK.get(row.status, 9), -seen)


def _best_attestor_by_node(node_ids: list[str]) -> dict[str, HostAttestor]:
    best: dict[str, HostAttestor] = {}
    rows = HostAttestor.objects.annotate(nid=Lower("node_id")).filter(nid__in=node_ids)
    for row in rows:
        key = row.nid  # type: ignore[attr-defined]  # annotated column
        current = best.get(key)
        if current is None or _attestor_sort_key(row) < _attestor_sort_key(current):
            best[key] = row
    return best


def _serialize_attestor(row: HostAttestor | None) -> dict[str, Any] | None:
    if row is None:
        return None
    return {
        "status": row.status,
        "cert_expiry_at": _iso(row.cert_expiry_at),
        "measurement": row.measurement,
        "last_seen_at": _iso(row.last_seen_at),
    }


def _serialize_location(row: MinerLocation | None) -> dict[str, Any] | None:
    """The DETECTED location (`vali_geo_probe`), or `None` before the first
    probe cycle. Every field is evidence vali observed, not a claim the
    miner made — `verdict_reasons` says why a row is not `verified`."""
    if row is None:
        return None
    return {
        "country_code": row.country_code,
        "region": row.region,
        "city": row.city,
        "connection_ip": row.connection_ip,
        "asn": row.asn,
        "as_holder": row.as_holder,
        "rtt_ms": row.rtt_ms,
        "verdict": row.verdict,
        "verdict_reasons": list(row.verdict_reasons or []),
        "observed_at": _iso(row.observed_at),
    }


def _location_of(miner: MinerIdentity) -> MinerLocation | None:
    # Reverse OneToOne: absent ⇒ RelatedObjectDoesNotExist, which is what
    # `select_related("location")` makes a no-query check.
    try:
        return miner.location
    except MinerLocation.DoesNotExist:
        return None


#: The two provenances that are a judgement about the node.
REFUSAL_SOURCES: frozenset[str] = frozenset(
    {PlacementFailureSource.SCHEDULER_DRAIN.value, PlacementFailureSource.LAUNCH.value}
)


def _refusals(node_ids: list[str]) -> QuerySet[Placement]:
    """The FAILED placements that ARE refusals — by WHO wrote them, then by
    what they say:

    - `failure_source = scheduler_drain` (`service.reeval_once`), minus the
      causes that judge the VM rather than the node
      (`NON_NODE_DRAIN_REASONS`);
    - `failure_source = launch` (`launch._fail_placement`) whose outcome is
      one in which the node itself refused, could not be reached or lost
      the VM (exact strings in `LAUNCH_REFUSAL_OUTCOMES`). Any other
      launch outcome is a control-plane fault and is not selected.

    Provenance is the first predicate on purpose: `reason` is free text,
    and a root `/fail` body that literally spells `miner-rejected` is a
    `manual` row — it never enters this set, whatever it says. `release`,
    `migration` and `legacy` rows are excluded the same way; a legacy
    FAILED row is unattributable and is refused rather than guessed."""
    return Placement.objects.filter(
        miner_node_id__in=node_ids,
        status=PlacementStatus.FAILED.value,
        failure_source__in=REFUSAL_SOURCES,
    ).filter(
        (
            Q(failure_source=PlacementFailureSource.SCHEDULER_DRAIN.value)
            & ~Q(reason__in=NON_NODE_DRAIN_REASONS)
        )
        | Q(
            failure_source=PlacementFailureSource.LAUNCH.value,
            reason__in=LAUNCH_REFUSAL_OUTCOMES,
        )
    )


def _recent_refusals_by_node(node_ids: list[str]) -> dict[str, list[dict[str, Any]]]:
    """Newest `RECENT_REFUSALS` refusals per node, ONE query for the whole
    request (window function ranked per `miner_node_id`), so the query
    count is flat in the number of rows. Reasons pass through
    `public_refusal_reason`: the stored text never leaves vali. `detail`
    is reserved and always `null` — the raw string is NEVER put there."""
    ranked = (
        _refusals(node_ids)
        .annotate(
            rank=Window(
                RowNumber(),
                partition_by=[F("miner_node_id")],
                order_by=F("failed_at").desc(nulls_last=True),
            )
        )
        .filter(rank__lte=RECENT_REFUSALS)
        .order_by("miner_node_id", "rank")
        .values_list("miner_node_id", "failed_at", "reason")
    )
    out: dict[str, list[dict[str, Any]]] = {}
    for nid, at, reason in ranked:
        out.setdefault(nid, []).append(
            {"at": _iso(at), "reason": public_refusal_reason(reason), "detail": None}
        )
    return out


def _refusal_breakdown_by_node(
    node_ids: list[str], *, since: datetime
) -> dict[str, dict[str, int]]:
    """`{node_id: {public_reason: n}}` refusals (same selection as
    `_refusals`) with `failed_at >= since` — ONE aggregate query for the
    whole request, grouped by the STORED reason and folded onto the public
    vocabulary here (two stored causes that share a public reason add up).
    Sparse: a reason with no refusal is absent, keys are sorted. The
    group count is bounded by the closed set of strings vali writes, not by
    traffic. `refusal_count_30d` is the sum, so the two cannot disagree."""
    rows = (
        _refusals(node_ids)
        .filter(failed_at__gte=since)
        .values("miner_node_id", "reason")
        .annotate(n=Count("id"))
    )
    folded: dict[str, dict[str, int]] = {}
    for row in rows:
        per_node = folded.setdefault(row["miner_node_id"], {})
        public = public_refusal_reason(row["reason"])
        per_node[public] = per_node.get(public, 0) + row["n"]
    return {nid: dict(sorted(counts.items())) for nid, counts in folded.items()}


def operator_node_rows(node_ids: list[str]) -> list[dict[str, Any]]:
    """The status rows for `node_ids` (64-hex, any case). A `node_id` with
    no `MinerIdentity` bridged to it is simply absent from the result —
    the caller learns nothing about ids it did not already hold.

    `now`, the attestor gate and the capacity/load ledgers are read ONCE
    for the whole request so every row is judged against the same instant.
    """
    wanted = list(dict.fromkeys(n.lower() for n in node_ids))
    if not wanted:
        return []

    now = timezone.now()
    identities = list(
        MinerIdentity.objects.select_related("location")
        .annotate(nid=Lower("chain_node_id"))
        .filter(nid__in=wanted)
    )
    if not identities:
        return []

    attestor_gate = scheduler_service.attestor_gate(now=now)
    failed_over = scheduler_service.failover_quarantined_miner_ids()
    attestors = _best_attestor_by_node(wanted)
    # `vm_family=""` → the global view (the family set only drives
    # anti-affinity, which is per-launch, not a capacity property).
    capacity_by_node, load_by_node, _family = scheduler_service.decision_inputs("")

    by_id = {m.nid: m for m in identities}  # type: ignore[attr-defined]
    refusals_by_node = _recent_refusals_by_node(list(by_id))
    breakdown_by_node = _refusal_breakdown_by_node(list(by_id), since=now - REFUSAL_COUNT_WINDOW)
    rows: list[dict[str, Any]] = []
    for nid in wanted:
        miner = by_id.get(nid)
        if miner is None:
            continue
        verdict = scheduler_service.dispatchability(
            miner, now=now, attestor=attestor_gate, failover_quarantined=failed_over
        )
        load = load_by_node.get(nid, 0)
        total = capacity_by_node.get(nid)
        breakdown = breakdown_by_node.get(nid, {})
        rows.append(
            {
                "node_id": nid,
                "miner_id": miner.miner_id,
                "status": miner.status,
                "last_seen_at": _iso(miner.last_seen_at),
                "attestor": _serialize_attestor(attestors.get(nid)),
                "schedulable": verdict.dispatchable,
                "schedulable_reason": verdict.reason,
                # Active placements (pending + bound) — vali's own ledger of
                # what it put on this host; never the miner's claim.
                "hosted_vm_count": load,
                "capacity": (
                    {"total_units": total, "committed_units": load} if total is not None else None
                ),
                "recent_refusals": refusals_by_node.get(nid, []),
                "refusal_count_30d": sum(breakdown.values()),
                "refusal_breakdown_30d": breakdown,
                "location": _serialize_location(_location_of(miner)),
            }
        )
    return rows


def _empty_region_capacity(model: str) -> dict[str, Any]:
    return {
        "total_units": 0,
        "committed_units": 0,
        "free_units": 0,
        "model": model,
        "unit": {
            "cpus": scheduler_service._slot_ref_cpus(),
            "memory_mb": scheduler_service._slot_ref_memory_mb(),
        },
        "free_vms": None,
        "free_by_flavor": {},
    }


def operator_region_rows(*, verified_only: bool | None = None) -> dict[str, Any]:
    """`GET /v1/operator/regions` — the regions vali has DETECTED miners in,
    with how many are verified / dispatchable and the capacity they add up
    to. A region exists here because a probe measured a miner there; no
    operator typed it.

    Which miners COUNT is one shared rule, `geo.placeable_locations`: fresh
    row, verified (or also unverified with `verified_only=False`), never
    mismatch/unknown — the same rule the scheduler's region gate applies,
    so what this advertises as placeable is what a `region`-constrained
    launch can land on. On top of that, `hosted_vm_count` and `capacity`
    sum only the counted miners that are DISPATCHABLE right now: a
    quarantined or heartbeat-stale host must not inflate a region's
    sellable capacity. `miners_total` / `miners_verified` count every fresh
    located miner regardless, so an operator sees the unverified ones too.
    """
    if verified_only is None:
        verified_only = geo.geo_require_verified()
    now = timezone.now()
    mirror_rows = list(MinerCapacity.objects.all())
    views = scheduler_service.capacity_views(rows=mirror_rows)
    gated = scheduler_service.hard_gated_node_ids(mirror_rows)
    dispatchable = scheduler_service.dispatchable_node_ids()

    placeable_ids = {
        str(loc.miner.chain_node_id).lower()
        for loc in geo.placeable_locations(now=now, verified_only=verified_only).select_related(
            "miner"
        )
    }
    max_age = geo.positive_setting("VALI_GEO_MAX_AGE_S", 7200.0)
    located = list(
        MinerLocation.objects.select_related("miner")
        .filter(
            miner__chain_node_id__isnull=False,
            observed_at__gte=now - timedelta(seconds=max_age),
        )
        .exclude(country_code="")
    )
    bridged_total = MinerIdentity.objects.filter(chain_node_id__isnull=False).count()

    by_region: dict[str, dict[str, Any]] = {}
    for loc in located:
        nid = str(loc.miner.chain_node_id).lower()
        region = loc.region
        row = by_region.setdefault(
            region,
            {
                "region": region,
                "country_code": region,
                "miners_total": 0,
                "miners_verified": 0,
                "miners_dispatchable": 0,
                "hosted_vm_count": 0,
                "capacity": None,
                "node_ids": [],
            },
        )
        row["miners_total"] += 1
        if loc.verdict == LocationVerdict.VERIFIED:
            row["miners_verified"] += 1
        if nid not in placeable_ids:
            continue
        row["node_ids"].append(nid)
        if nid not in dispatchable:
            continue
        row["miners_dispatchable"] += 1
        view = views.get(nid)
        if view is not None:
            row["hosted_vm_count"] += view.placements
            cap = row["capacity"] or _empty_region_capacity(view.model)
            # Units of the ACTIVE admission model (`service.CapacityView`):
            # v1 slots, or v2 resource-true reference-flavor units. Per
            # node, summed — an over-committed node contributes zero free,
            # it does not eat another node's.
            # A host placement would hard-refuse (inactive, epoch-stale,
            # CVM-incapable, zombie) keeps its size but offers nothing:
            # its free counts as committed so `total = committed + free`.
            offers = nid not in gated
            free = view.free_units if offers else 0
            cap["total_units"] += view.total_units
            cap["committed_units"] += view.total_units - free
            cap["free_units"] += free
            if view.free_vms is not None:
                cap["free_vms"] = (cap["free_vms"] or 0) + (view.free_vms if offers else 0)
            for name, n in view.free_by_flavor.items():
                cap["free_by_flavor"][name] = cap["free_by_flavor"].get(name, 0) + (
                    n if offers else 0
                )
            row["capacity"] = cap
    for row in by_region.values():
        row["node_ids"].sort()
    vantage = geo.vantage_from_settings()
    return {
        "regions": [by_region[k] for k in sorted(by_region)],
        "unlocated_miners": max(0, bridged_total - len(located)),
        "require_verified": bool(verified_only),
        "vantage": {
            "name": vantage.name,
            "latitude": vantage.latitude,
            "longitude": vantage.longitude,
        },
        "generated_at": _iso(now),
    }
