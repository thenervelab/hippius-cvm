"""§23 scheduler endpoints.

  POST /v1/scheduler/place
      Body: {"vm_id": "...", "resource_class": "..."}.
      Auth: any authenticated ServiceClient.
      Decides a deterministic placement against a fresh on-chain
      snapshot + the §23 admission / anti-affinity / epoch-freshness
      constraints, writes a Pending `Placement`, kicks the Packer
      trigger. Idempotent: a second call for an already-placed VM
      returns the existing row.
      → 201 created / 200 already-placed / 400 wire / 404 vm /
        409 family-unknown · placement-conflict · no-eligible-miner /
        503 chain unavailable.

  POST /v1/scheduler/<vm_id>/bind
      Body: {"if_version": N, "kbs_release_ref": "..."}.
      Auth: scheduler root principal ONLY.
      CAS Pending→Bound once the KBS release is confirmed.
      → 200 / 400 / 403 / 404 / 409.

  POST /v1/scheduler/<vm_id>/fail
      Body: {"if_version": N, "reason": "..."}.
      Auth: scheduler root principal ONLY.
      CAS Pending→Failed, then best-effort re-place elsewhere.
      → 200 (fail always succeeds; replacement may be null) /
        400 / 403 / 404 / 409.

All decision logic is delegated to `placement.decide_placement` (a
pure, deterministic, clock-free function) and `service` (the I/O
glue). The decision never uses `time` or `random` — review: §23
determinism.
"""

from __future__ import annotations

import json
import logging
import re
from dataclasses import asdict
from typing import Any

from django.conf import settings
from django.core.cache import cache
from django.db import IntegrityError, transaction
from django.http import HttpResponse
from django.utils import timezone
from drf_spectacular.utils import OpenApiParameter, OpenApiResponse, extend_schema
from rest_framework import status
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.request import Request
from rest_framework.response import Response
from rest_framework.views import APIView

from apps.common.schemas import ErrorSerializer
from apps.identity import scoping
from apps.lifecycle.models import Vm
from apps.orchestration.services import flavors
from apps.orders.models import OrderTicketIntake

from . import chain, feasibility, scoring, service
from . import cvm_capability as cvm_cap
from .models import (
    ACTIVE_PLACEMENT_STATES,
    Placement,
    PlacementFailureSource,
    PlacementStatus,
    PriceMigrationRecommendation,
    PriceRecommendationStatus,
)
from .packer_trigger import ensure_guest_image_build
from .permissions import IsRootClient
from .placement import (
    MINER_ACTIVE,
    REGION_RE,
    PlacementError,
    SelectionWeights,
    decide_placement,
)
from .schemas import (
    EdgeRegistryFeedSerializer,
    EpochWeightsSerializer,
    FeasibilityListSerializer,
    IfVersionRequestSerializer,
    PlacementConflictSerializer,
    PlacementSerializer,
    PriceRecommendationApproveSerializer,
    PriceRecommendationListSerializer,
    PriceRecommendationSerializer,
    RecommendationConflictSerializer,
    SchedulerBindRequestSerializer,
    SchedulerCapacitySerializer,
    SchedulerFailRequestSerializer,
    SchedulerFailResponseSerializer,
    SchedulerPlaceRequestSerializer,
)

log = logging.getLogger("apps.scheduler.views")

# Bounds for caller-supplied strings — mirror the model `max_length`s
# so a write never fails with a Postgres `DataError` after the view
# has already done its work.
_MAX_RESOURCE_CLASS = 128
_MAX_REASON = 256
_MAX_RELEASE_REF = 256


class _WireError(Exception):
    """A request body failed a shape check. Surfaced as HTTP 400."""

    def __init__(self, message: str, category: str = "wire") -> None:
        super().__init__(message)
        self.message = message
        self.category = category


# ─── /v1/scheduler/place ─────────────────────────────────────────────


class SchedulerPlaceView(APIView):
    """`POST /v1/scheduler/place` — decide + record a VM placement."""

    # RA-L2 — root-gate to match the sibling write endpoints (bind/fail):
    # /place creates a Placement AND triggers a chain read + capacity
    # refresh + ensure_guest_image_build for an arbitrary vm_id, so any
    # authed client could otherwise force placements / amplify chain-RPC.
    # Nothing internal calls this over HTTP (launch_vm places in-process);
    # it is an operator surface. Also throttled per principal.
    # P2 object-level authorization: admission decision across the whole fleet.
    object_scope = scoping.OPERATOR_ONLY
    permission_classes = [IsAuthenticated, IsRootClient]
    throttle_scope = "scheduler_place"
    http_method_names = ["post", "options"]

    @extend_schema(
        summary="Decide and record a VM placement",
        description=(
            "Root-gated. Decides a deterministic placement against a fresh "
            "on-chain snapshot + the §23 admission / anti-affinity / "
            "epoch-freshness / price / circuit-breaker constraints, writes a "
            "Pending `Placement`, and kicks the guest-image build. Idempotent: "
            "a repeat for an already-placed VM returns the existing row (200), "
            "or 409 if the repeat asks for a different `resource_class`."
        ),
        tags=["Scheduler"],
        request=SchedulerPlaceRequestSerializer,
        responses={
            201: PlacementSerializer,
            200: PlacementSerializer,
            400: OpenApiResponse(ErrorSerializer, "Malformed body / bad field."),
            403: OpenApiResponse(ErrorSerializer, "Not the scheduler root principal."),
            404: OpenApiResponse(ErrorSerializer, "VM not found."),
            409: OpenApiResponse(
                PlacementConflictSerializer,
                "family-unknown · placement-conflict · no-eligible-miner.",
            ),
            503: OpenApiResponse(ErrorSerializer, "Chain read unavailable / insert failed."),
        },
    )
    def post(self, request: Request) -> Response:
        body = request.data
        if not isinstance(body, dict):
            return _error(
                status.HTTP_400_BAD_REQUEST,
                "request body must be a JSON object",
                "wire",
            )

        try:
            vm_id = _require_str(body, "vm_id")
            resource_class = _require_str(body, "resource_class", max_len=_MAX_RESOURCE_CLASS)
        except _WireError as exc:
            return _error(status.HTTP_400_BAD_REQUEST, exc.message, exc.category)

        try:
            vm = Vm.objects.get(vm_id=vm_id)
        except Vm.DoesNotExist:
            return _error(status.HTTP_404_NOT_FOUND, "vm not found", "not-found")
        # A re-placement of a resized VM carries its launch disk.
        carried_disk = service.carried_data_disk_gb(vm)

        # Anti-affinity family = the VM's tenant, taken from its
        # OrderTicket. No ticket ⇒ family unknown ⇒ fail closed: the
        # scheduler will not place a VM it cannot anti-affinity-group.
        # `-id` is a deterministic tie-breaker so two tickets sharing
        # a `received_at` always resolve to the same family.
        ticket = (
            OrderTicketIntake.objects.filter(vm_id=vm_id).order_by("-received_at", "-id").first()
        )
        if ticket is None:
            return _error(
                status.HTTP_409_CONFLICT,
                f"vm {vm_id!r} has no OrderTicket — cannot determine anti-affinity family",
                "family-unknown",
            )
        vm_family = ticket.tenant_id

        # Idempotency: a VM already holding an active placement is
        # returned as-is. A different resource_class on the retry is
        # a caller bug — 409 rather than silently ignore it.
        active = _active_placement(vm)
        if active is not None:
            return _idempotent_or_conflict(active, resource_class)

        # Authoritative on-chain read — fail closed (503) if it fails.
        try:
            snapshot = chain.read_miner_status()
        except chain.ChainReadUnavailable as exc:
            log.error("placement aborted — chain read failed: %s", exc)
            return _error(status.HTTP_503_SERVICE_UNAVAILABLE, str(exc), "internal")

        service.refresh_miner_capacity(snapshot)
        capacity, load, family_load = service.decision_inputs(vm_family)

        try:
            chosen = decide_placement(
                snapshot=snapshot,
                capacity_by_node=capacity,
                load_by_node=load,
                family_load_by_node=family_load,
                max_family_per_node=service.cdn_family_cap(vm_family),
                **service.cdn_edge_arguments(vm_family, vm_id),
                max_epoch_lag=service.max_epoch_lag(),
                dispatchable=service.dispatchable_node_ids(),
                # Gate (f) — the region the VM's launch asked for, if any.
                # `/place` sees no intent of its own, so it is read back
                # from the LaunchJob; a VM with none stays unconstrained.
                **service.region_arguments(service.launch_region_for_vm(vm_id)),
                weights=SelectionWeights.from_settings(),
                max_host_share=service.max_host_share(),
                # §23 marketplace — cheaper announced prices rank up.
                price_by_node=service.price_by_node(snapshot),
                # RA-M3 — the circuit-breaker + per-owner sub-budget must
                # apply on THIS authed create path too, not only launch_vm;
                # otherwise an owner concentrates VMs on one miner via /place.
                recent_failures_by_node=service.recent_failures_by_node(),
                max_recent_failures=service.max_recent_failures(),
                owner_load_by_node=service.owner_load_by_node(ticket.user_id),
                max_owner_placements_per_miner=(service.max_owner_placements_per_miner()),
                # Gate (e) — never place onto a host vali has OBSERVED
                # fail to start a confidential guest.
                cvm_capability_by_node=service.cvm_capability_by_node(),
                # A miner still running a crypto-erased VM takes no new VMs.
                zombie_quarantined=service.zombie_quarantined_node_ids(),
                # Gate (i) — no edge-region miner without a fresh net-policy ack.
                net_policy_unready=service.net_policy_unready_node_ids(),
                cordoned=service.cordoned_node_ids(),
                # Capacity v2 — does THIS resource_class fit (with the VM's
                # own disk when a resize left it another than the flavor's).
                resource_fit=service.resource_fit(
                    resource_class,
                    disk_gb=service.placement_disk_gb(resource_class, carried_disk),
                ),
            )
        except PlacementError as exc:
            return _error(status.HTTP_409_CONFLICT, exc.message, exc.category)

        # Create the Pending placement. The partial unique index on
        # `vm` is the race boundary: if a concurrent scheduler beat
        # us, the INSERT raises IntegrityError and we return the
        # winning row — the call stays idempotent under the race.
        try:
            with transaction.atomic():
                placement = Placement.objects.create(
                    vm=vm,
                    vm_family=vm_family,
                    owner=getattr(ticket, "user_id", "") or "",
                    resource_class=resource_class,
                    data_disk_gb=carried_disk,
                    miner_node_id=chosen,
                    status=PlacementStatus.PENDING.value,
                    chain_epoch=snapshot.current_epoch,
                    decided_by=request.user,
                )
        except IntegrityError:
            winner = (
                Placement.objects.filter(vm=vm, status__in=ACTIVE_PLACEMENT_STATES)
                .select_related("vm", "decided_by")
                .first()
            )
            if winner is not None:
                log.info(
                    "placement race lost: vm=%s winner=%s",
                    vm_id,
                    winner.id,
                )
                # Same contract as the idempotency pre-check: a race
                # winner with a different resource_class is a 409,
                # not a silent 200 for a placement we didn't request.
                return _idempotent_or_conflict(winner, resource_class)
            log.exception("placement IntegrityError with no surviving row")
            return _error(
                status.HTTP_503_SERVICE_UNAVAILABLE,
                "internal: placement insert failed",
                "internal",
            )

        # Best-effort §23 kick — never fails the placement.
        ensure_guest_image_build(request.user)

        log.info(
            "placement decided: vm=%s miner=%s family=%s epoch=%d",
            vm_id,
            chosen,
            vm_family,
            snapshot.current_epoch,
        )
        return Response(_serialize_placement(placement), status=status.HTTP_201_CREATED)


# ─── /v1/scheduler/capacity ──────────────────────────────────────────


class SchedulerCapacityView(APIView):
    """`GET /v1/scheduler/capacity` — #587 Phase 3.

    Read-only pre-launch availability view for the upstream product API:
    "can I offer a launch right now, and roughly where?". Reports, per
    genuinely-dispatchable miner (the SAME `dispatchable_node_ids` gate
    `decide_placement` uses — reachable + attestable + live, on-chain
    `active`, epoch-fresh), its proven `capacity_slots`, current `load`
    (active placements), and resulting `free_slots`, plus cluster totals.

    This is NOT a reservation — capacity is advisory and racey; the
    authoritative admission is still `POST /v1/scheduler/place`. A
    `free_slots` here only means a launch is *likely* to place.

    `IsAuthenticated` service principal (same as the rest of the
    read surface). Fail-closed 503 if the chain read is unavailable —
    a stale capacity view must not be served as fresh.
    """

    # P2 object-level authorization: per-miner fleet load — cross-tenant
    # operational data.
    object_scope = scoping.OPERATOR_ONLY

    permission_classes = [IsAuthenticated]
    http_method_names = ["get", "options"]

    @extend_schema(
        summary="Pre-launch availability (advisory capacity view)",
        description=(
            "Read-only per-dispatchable-miner capacity: proven `capacity_slots`, "
            "current `load`, resulting `free_slots`, plus cluster totals. NOT a "
            "reservation — the authoritative admission is `POST "
            "/v1/scheduler/place`. Fail-closed 503 if the chain read is stale."
        ),
        tags=["Scheduler"],
        responses={
            200: SchedulerCapacitySerializer,
            503: OpenApiResponse(ErrorSerializer, "Chain read unavailable."),
        },
    )
    def get(self, request: Request) -> Response:
        try:
            snapshot = chain.read_miner_status()
        except chain.ChainReadUnavailable as exc:
            log.error("capacity query aborted — chain read failed: %s", exc)
            return _error(status.HTTP_503_SERVICE_UNAVAILABLE, str(exc), "internal")

        service.refresh_miner_capacity(snapshot)
        # `vm_family=""` → a global view (the family set only drives
        # anti-affinity, which is per-launch, not a capacity property).
        # Units of the ACTIVE admission model (v1 slots / v2 resource-true
        # units) — `service.CapacityView`, shared with the regions readout.
        views = service.capacity_views()
        zombies = {z.lower() for z in service.zombie_quarantined_node_ids()}
        dispatchable = service.dispatchable_node_ids()
        max_lag = service.max_epoch_lag()
        # §23 gate (e) — the OBSERVED SNP start-capability verdict. Without
        # it this view reports a host that cannot boot ANY confidential
        # guest as the one with the most free slots, because free capacity
        # is exactly what a host that starts nothing has. That is how a
        # placement failure surfaces as an unexplained `no-eligible-miner`
        # against a capacity view that said everything was fine.
        cvm_capability = service.cvm_capability_by_node()
        # Gate (h) + gate (g)'s per-miner cap, so an operator sees here why
        # a host with room takes nothing (or boots fewer at once).
        cordoned = service.cordoned_node_ids()
        boot_caps = service.max_booting_overrides()
        fleet_boot_cap = service.max_booting_per_miner()

        miners: list[dict[str, Any]] = []
        total_capacity = total_free = incapable = 0
        for miner in snapshot.miners:
            if miner.node_id not in dispatchable:
                continue
            # Mirror the placement eligibility: stale-epoch miners can't
            # actually take a launch, so they contribute 0 free slots.
            epoch_fresh = snapshot.current_epoch - miner.data_epoch <= max_lag
            verdict = cvm_capability.get(miner.node_id, cvm_cap.UNKNOWN)
            # Mirror gate (e) the same way: `decide_placement` HARD-excludes
            # an `incapable` host with no fallback, so its slots are not
            # offerable capacity. Only the hard verdict zeroes them —
            # `degraded` is a soft preference and can still take a launch.
            startable = verdict != cvm_cap.INCAPABLE
            if not startable:
                incapable += 1
            view = views.get(miner.node_id)
            cap = view.total_units if view is not None else 0
            # v1: active placements, exactly as before. v2: committed units,
            # so `capacity_slots = load + free` holds in the unit it reports.
            if view is None:
                ld = 0
            elif view.model == "v1":
                ld = view.placements
            else:
                ld = view.committed_units
            # Every hard gate `decide_placement` applies to an otherwise
            # dispatchable miner: on-chain active, epoch-fresh, not
            # CVM-incapable, not zombie-quarantined, not cordoned.
            is_cordoned = miner.node_id.lower() in cordoned
            offerable = (
                miner.status == MINER_ACTIVE
                and epoch_fresh
                and startable
                and miner.node_id.lower() not in zombies
                and not is_cordoned
                and view is not None
            )
            free = view.free_units if offerable else 0
            total_capacity += cap
            total_free += free
            miners.append(
                {
                    "node_id": miner.node_id,
                    "status": miner.status,
                    "quality": str(miner.quality),
                    "capacity_slots": cap,
                    "load": ld,
                    "free_slots": free,
                    "epoch_fresh": epoch_fresh,
                    "cvm_capability": verdict,
                    "cordoned": is_cordoned,
                    "cordon_reason": cordoned.get(miner.node_id.lower()) if is_cordoned else None,
                    "max_booting": boot_caps.get(miner.node_id, fleet_boot_cap),
                    "model": view.model if view is not None else None,
                    "free_by_flavor": (
                        dict(view.free_by_flavor)
                        if offerable
                        else {name: 0 for name in (view.free_by_flavor if view else {})}
                    ),
                }
            )

        miners.sort(key=lambda m: m["free_slots"], reverse=True)
        return Response(
            {
                "current_epoch": snapshot.current_epoch,
                # Whether `current_epoch` and every miner's `quality` are LIVE
                # chain state or a FOSSIL. When a runtime upgrade drops the
                # configured pallet its storage prefix keeps answering reads,
                # so both fields still have plausible values — frozen at the
                # last close, and drifting further from reality every hour.
                # `/v1/admin/epoch-weights` has surfaced this since #895; this
                # endpoint reported the same numbers WITHOUT the caveat, which
                # is how a fossil gets taken at face value. Placement itself no
                # longer ranks on a dead signal (#917); this is the reporting
                # half of the same fix.
                "pallet_live": snapshot.pallet_live,
                "dispatchable_miners": len(miners),
                "total_capacity_slots": total_capacity,
                "total_free_slots": total_free,
                "has_capacity": total_free > 0,
                # How many otherwise-dispatchable miners are currently
                # HARD-excluded by gate (e). Non-zero here is the operator's
                # cue that the fleet is smaller than the miner count
                # suggests, and why.
                "cvm_incapable_miners": incapable,
                "miners": miners,
            },
            status=status.HTTP_200_OK,
        )


# ─── /v1/admin/epoch-weights ─────────────────────────────────────────


class SchedulerFeasibilityView(APIView):
    """`GET /v1/scheduler/feasibility[?flavor=…]` — "can we place this
    BEFORE we sell it?".

    The complement to `/v1/scheduler/capacity`, which answers in
    admission SLOTS. Slots cannot answer a question about a FLAVOR: a
    slot is sized by the reference flavor and one placement costs one
    slot whatever its size, so a `4xlarge` looks placeable on a host
    with one free slot and is then refused by the miner at preflight.
    This view asks both halves — would the scheduler choose someone,
    AND does the flavor physically fit — and reports them separately.

    The `verdict` is the field to branch on, and the distinction that
    matters commercially is `not-now` (the fleet is full; retry) versus
    `never` (no reachable host is big enough; do not take the money).

    Read-only: no `Vm`, no `Placement`, no chain write. Asking whether a
    VM could be placed must never place one.

    `IsAuthenticated` service principal, same as the rest of the read
    surface. Per-miner free resources are cross-tenant operational data,
    hence `OPERATOR_ONLY`.
    """

    object_scope = scoping.OPERATOR_ONLY

    permission_classes = [IsAuthenticated]
    http_method_names = ["get", "options"]

    @extend_schema(
        summary="Can a VM of this flavor be placed right now?",
        description=(
            "Pre-sale feasibility. For each flavor: `verdict` "
            "(`yes` / `not-now` / `never`), `headroom` (how many more the "
            "fleet could take), and the per-host fit breakdown. `never` means "
            "no reachable host is big enough and retrying cannot help — the "
            "answer that must stop a sale; `not-now` is retryable. "
            "Advisory, NOT a reservation: any concurrent launch consumes the "
            "headroom. The DATA-disk dimension joins the answer only under "
            "`VALI_SCHEDULER_DISK_GATE=enforce` (`disk_checked: true` when every "
            "fitting host had disk data); otherwise per-host disk figures are "
            "reported and disk stays gated by the miner at dispatch."
        ),
        tags=["Scheduler"],
        parameters=[
            OpenApiParameter(
                name="flavor",
                description=(
                    "Restrict to one flavor. Omit for the whole catalogue "
                    "(the 'what can I sell right now' board)."
                ),
                required=False,
                type=str,
            ),
            OpenApiParameter(
                name="tenant_id",
                description=(
                    "Optional. Feeds anti-affinity, so the answer is about "
                    "THIS tenant rather than about anybody."
                ),
                required=False,
                type=str,
            ),
            OpenApiParameter(
                name="user_id",
                description=(
                    "Optional. Feeds the per-owner sub-budget, same rationale "
                    "as `tenant_id`."
                ),
                required=False,
                type=str,
            ),
            OpenApiParameter(
                name="region",
                description=(
                    "Optional ISO 3166-1 alpha-2 country code (`FR`, "
                    "case-insensitive). Answers for the miners the validator "
                    "has DETECTED in that country only — what a launch with "
                    "the same `region` would see. Adds `region-unknown` "
                    "(probe not run; retry), `no-miner-in-region` (`never`) "
                    "and `region-unverified` (miners there, not yet proven; "
                    "retry) to `reason`. 400 on a malformed code."
                ),
                required=False,
                type=str,
            ),
        ],
        responses={
            200: FeasibilityListSerializer,
            400: OpenApiResponse(ErrorSerializer, "Unknown flavor / malformed region."),
        },
    )
    def get(self, request: Request) -> Response:
        flavor = (request.query_params.get("flavor") or "").strip()
        tenant_id = (request.query_params.get("tenant_id") or "").strip()
        user_id = (request.query_params.get("user_id") or "").strip()
        region = (request.query_params.get("region") or "").strip()
        if region and not REGION_RE.match(region):
            # Same rule as the launch intake: a malformed code is a caller
            # error, not "nobody is there" — `never` from a typo would
            # take a whole country off the shelf.
            return _error(
                status.HTTP_400_BAD_REQUEST,
                "region must be an ISO 3166-1 alpha-2 country code (e.g. 'FR')",
                "invalid",
            )

        try:
            if flavor:
                results = [
                    feasibility.assess(
                        flavor, tenant_id=tenant_id, user_id=user_id, region=region
                    )
                ]
            else:
                results = feasibility.assess_catalogue(
                    tenant_id=tenant_id, user_id=user_id, region=region
                )
        except flavors.UnknownFlavor as exc:
            # A flavor that does not exist is a CALLER error, not "cannot
            # place" — flattening the two would have a typo read as a
            # capacity problem and quietly stop a sellable sale.
            return _error(status.HTTP_400_BAD_REQUEST, str(exc), "invalid")

        return Response(
            {"flavors": [asdict(r) for r in results]},
            status=status.HTTP_200_OK,
        )


class EpochWeightsView(APIView):
    """`GET /v1/admin/epoch-weights` — the §23 per-miner reward weights.

    vali is the trustless source of the §23 reward weight: it placed the
    VMs, so it knows the exact flavor bound to each miner. This surfaces
    `scoring.compute_epoch_weights()` — `{node_id_hex: weight}` summed over
    the `Bound` placements — so the off-chain epoch-close worker can submit
    REAL merit weights via `vali_submit_epoch_close` instead of a flat
    value (a miner hosting more/bigger VMs earns proportionally more).

    **The WEIGHTS are unauthenticated by design** (mirrors
    `EdgeRegistryFeedView`): they are non-secret operational data (per-miner
    resource-unit sums, derivable from the on-chain placements), the vali
    Service is in-cluster only (no Ingress), and the CiliumNetworkPolicy
    gates `:8000` ingress to the `epoch-close` component. A node absent from
    `weights` simply earned nothing this window (weight 0 — active but
    unrewarded, per the pallet's own semantics).

    **The `owed_*` BILL is NOT** — it requires authentication. That
    rationale above covers weights only, and it silently stopped covering
    the whole response when the priced bill was added: `owed_usd_micros` is
    vali-internal (attested usage x the miner's price), NOT derivable from
    anything on-chain. Served anonymously it discloses per-miner revenue,
    total platform spend and a node_id roster — financial intelligence, and
    a pre-beta red team demonstrated reading it unauthenticated. The CNP is
    a single control with no cryptographic backstop, and `/v1/` is about to
    be publicly fronted, so the bill is gated on an authenticated principal
    while the weights stay open for the epoch-close worker that needs them.
    """

    # P2 object-level authorization: `AllowAny` weights feed (the priced
    # bill inside is auth-gated).
    object_scope = scoping.PUBLIC

    permission_classes = [AllowAny]
    http_method_names = ["get", "options"]

    @extend_schema(
        summary="§23 per-miner reward weights (+ priced owed bill, authenticated)",
        description=(
            "`{node_id_hex: weight}` summed over Bound placements, so the "
            "epoch-close worker submits REAL merit — served unauthenticated "
            "(CNP-gated, non-secret on-chain-derived data). The priced `owed_*` "
            "bill is returned ONLY to an AUTHENTICATED caller: it is "
            "vali-internal revenue data, not on-chain-derivable."
        ),
        tags=["Scheduler"],
        responses={200: EpochWeightsSerializer},
    )
    def get(self, request: Request) -> Response:
        weights = scoring.compute_epoch_weights()
        body: dict[str, Any] = {
            "weights": {node_id: int(w) for node_id, w in weights.items()},
            "total_weight": int(sum(weights.values())),
            "miners": len(weights),
        }
        # The PRICED bill — how much we owe each miner this epoch, from
        # ATTESTED uptime × the miner's on-chain price. Only surfaced once
        # there is attested usage (a live billing signal); until then the
        # response is byte-identical to the reward-weight-only shape the
        # epoch-close worker already consumes, and no chain read is made.
        # Best-effort: a failed price read omits `owed`, never the weights.
        # AUTHENTICATED CALLERS ONLY — see the class docstring. The
        # epoch-close worker consumes `weights` and never reads `owed_*`,
        # so gating the bill costs it nothing.
        if (
            request.user
            and request.user.is_authenticated
            and scoring.latest_usage_epoch() is not None
        ):
            try:
                snapshot = chain.read_miner_status()
                # Surface the removed-pallet signal where an operator will
                # actually look. Deliberately INSIDE this block: the read
                # already happened here, so it costs no extra RPC — and
                # the unauthenticated `weights` path must stay chain-read
                # free (an anonymous caller must never be able to force an
                # outbound RPC from vali).
                body["pallet_live"] = snapshot.pallet_live
                prices = service.price_by_node(snapshot)
                owed = scoring.compute_owed_micro_usd(prices)
                # The epoch the bill DESCRIBES — the chain epoch usage is
                # accruing into, i.e. the same selector `compute_owed_micro_usd`
                # summed over. Reporting the newest LEDGER bucket here would
                # mislabel the bill whenever accrual has stalled.
                body["usage_epoch"] = scoring.billing_epoch()
                body["owed_usd_micros"] = {n: int(v) for n, v in owed.items()}
                body["owed_total_usd_micros"] = int(sum(owed.values()))
            except chain.ChainReadUnavailable as exc:
                log.warning("epoch-weights: owed omitted — chain unavailable: %s", exc)
                body["owed_usd_micros"] = None

        # Blackbox host-attestor reward-gate PREVIEW (PR-11). When the reward
        # MULTIPLIER is NOT yet armed (`VALI_REWARD_REQUIRE_ATTESTOR` off,
        # default), surface what the emitted `weights` WOULD become if it
        # were — base × host-attestor liveness ratio — so an operator can
        # validate coverage BEFORE flipping the flag. Preview-only: nothing
        # here changes the emitted `weights`. Omitted when the flag is armed
        # (the weights above already reflect it) OR when there is no
        # `attested` host-attestor data (keeps a default deployment's
        # response byte-identical to today).
        if not bool(getattr(settings, "VALI_REWARD_REQUIRE_ATTESTOR", False)):
            from apps.telemetry.models import HostAttestor, HostAttestorStatus

            if HostAttestor.objects.filter(status=HostAttestorStatus.ATTESTED.value).exists():
                preview = scoring.apply_attestor_liveness_multiplier(weights)
                body["attestor_reward_preview"] = {
                    "enforced": False,
                    "weights": {n: int(w) for n, w in preview.items()},
                    "total_weight": int(sum(preview.values())),
                    "miners": len(preview),
                    "note": (
                        "WARN/preview — the weights that WOULD be emitted if "
                        "VALI_REWARD_REQUIRE_ATTESTOR were armed (base × "
                        "host-attestor liveness ratio). NOT applied. SLA≠capacity: "
                        "a liveness ratio proves only the measured attestor "
                        "answered beacons, never host capacity or tenant health. "
                        "Arming inherits the open GA-blockers (M-of-N, "
                        "cosign-admission, C1) + VALI_KBS_L0_VERIFYING_KEY wired."
                    ),
                }
        return Response(body, status=status.HTTP_200_OK)


# ─── /v1/scheduler/<vm_id>/bind ──────────────────────────────────────


class SchedulerBindView(APIView):
    """`POST /v1/scheduler/<vm_id>/bind` — root-only Pending→Bound."""

    # P2 object-level authorization: already root-gated.
    object_scope = scoping.OPERATOR_ONLY

    permission_classes = [IsAuthenticated, IsRootClient]
    http_method_names = ["post", "options"]

    @extend_schema(
        summary="Bind a Pending placement (root-only CAS Pending→Bound)",
        description=(
            "Root-gated. CAS `Pending`→`Bound` once the KBS release is "
            "confirmed; the supplied `kbs_release_ref` is recorded as the audit "
            "trail. A stale `if_version` or concurrent transition loses cleanly "
            "with a 409 version-conflict."
        ),
        tags=["Scheduler"],
        parameters=[
            OpenApiParameter(
                "vm_id", str, OpenApiParameter.PATH, description="VM whose placement to bind."
            )
        ],
        request=SchedulerBindRequestSerializer,
        responses={
            200: PlacementSerializer,
            400: OpenApiResponse(ErrorSerializer, "Malformed body / bad field."),
            403: OpenApiResponse(ErrorSerializer, "Not the scheduler root principal."),
            404: OpenApiResponse(ErrorSerializer, "VM not found."),
            409: OpenApiResponse(
                PlacementConflictSerializer, "No Pending placement / stale if_version."
            ),
        },
    )
    def post(self, request: Request, vm_id: str) -> Response:
        body = request.data
        if not isinstance(body, dict):
            return _error(
                status.HTTP_400_BAD_REQUEST,
                "request body must be a JSON object",
                "wire",
            )
        try:
            if_version = _require_int(body, "if_version")
            # v1: the root caller is responsible for verifying the
            # KBS audit log shows the release succeeded for this VM
            # (live KBS-audit-log integration tracked in #36); vali
            # records the supplied reference as the audit trail.
            kbs_release_ref = _require_str(body, "kbs_release_ref", max_len=_MAX_RELEASE_REF)
        except _WireError as exc:
            return _error(status.HTTP_400_BAD_REQUEST, exc.message, exc.category)

        try:
            vm = Vm.objects.get(vm_id=vm_id)
        except Vm.DoesNotExist:
            return _error(status.HTTP_404_NOT_FOUND, "vm not found", "not-found")

        placement = Placement.objects.filter(vm=vm, status=PlacementStatus.PENDING.value).first()
        if placement is None:
            return _error(
                status.HTTP_409_CONFLICT,
                "vm has no Pending placement to bind",
                "no-pending-placement",
            )

        # CAS Pending→Bound — filter the full pre-image so a stale
        # `if_version` OR a concurrent transition loses cleanly.
        with transaction.atomic():
            updated = Placement.objects.filter(
                id=placement.id,
                version=if_version,
                status=PlacementStatus.PENDING.value,
            ).update(
                status=PlacementStatus.BOUND.value,
                version=if_version + 1,
                bound_at=timezone.now(),
                kbs_release_ref=kbs_release_ref,
            )
        if updated == 0:
            return _version_conflict(placement.id)

        log.info("placement bound: vm=%s placement=%s", vm_id, placement.id)
        return Response(_serialize_placement(_reread(placement.id)), status=status.HTTP_200_OK)


# ─── /v1/scheduler/<vm_id>/fail ──────────────────────────────────────


class SchedulerFailView(APIView):
    """`POST /v1/scheduler/<vm_id>/fail` — root-only Pending→Failed.

    The fail itself always succeeds (200). Re-placement onto a
    different miner is **best-effort**: `replacement` is the new
    `Placement` or `null`, and `replacement_error` carries the
    reason it could not be re-placed (the operator retries `/place`).
    """

    # P2 object-level authorization: already root-gated.
    object_scope = scoping.OPERATOR_ONLY

    permission_classes = [IsAuthenticated, IsRootClient]
    http_method_names = ["post", "options"]

    @extend_schema(
        summary="Fail a Pending placement + best-effort re-place (root-only)",
        description=(
            "Root-gated. CAS `Pending`→`Failed` (always 200 on success), then "
            "best-effort re-places the VM onto a different miner. The response "
            "carries the `failed` row plus either `replacement` (new Pending "
            "placement) or `replacement_error` — never both."
        ),
        tags=["Scheduler"],
        parameters=[
            OpenApiParameter(
                "vm_id", str, OpenApiParameter.PATH, description="VM whose placement to fail."
            )
        ],
        request=SchedulerFailRequestSerializer,
        responses={
            200: SchedulerFailResponseSerializer,
            400: OpenApiResponse(ErrorSerializer, "Malformed body / bad field."),
            403: OpenApiResponse(ErrorSerializer, "Not the scheduler root principal."),
            404: OpenApiResponse(ErrorSerializer, "VM not found."),
            409: OpenApiResponse(
                PlacementConflictSerializer, "No Pending placement / stale if_version."
            ),
        },
    )
    def post(self, request: Request, vm_id: str) -> Response:
        body = request.data
        if not isinstance(body, dict):
            return _error(
                status.HTTP_400_BAD_REQUEST,
                "request body must be a JSON object",
                "wire",
            )
        try:
            if_version = _require_int(body, "if_version")
            reason = _require_str(body, "reason", max_len=_MAX_REASON)
        except _WireError as exc:
            return _error(status.HTTP_400_BAD_REQUEST, exc.message, exc.category)

        try:
            vm = Vm.objects.get(vm_id=vm_id)
        except Vm.DoesNotExist:
            return _error(status.HTTP_404_NOT_FOUND, "vm not found", "not-found")

        placement = Placement.objects.filter(vm=vm, status=PlacementStatus.PENDING.value).first()
        if placement is None:
            return _error(
                status.HTTP_409_CONFLICT,
                "vm has no Pending placement to fail",
                "no-pending-placement",
            )

        with transaction.atomic():
            updated = Placement.objects.filter(
                id=placement.id,
                version=if_version,
                status=PlacementStatus.PENDING.value,
            ).update(
                status=PlacementStatus.FAILED.value,
                version=if_version + 1,
                failed_at=timezone.now(),
                reason=reason,
                # Provenance: a root caller's free text. Whatever it spells
                # — even a launch outcome verbatim — it is never a refusal.
                failure_source=PlacementFailureSource.MANUAL,
            )
        if updated == 0:
            return _version_conflict(placement.id)

        failed = _reread(placement.id)
        log.info(
            "placement failed: vm=%s placement=%s reason=%s",
            vm_id,
            placement.id,
            reason,
        )

        # Re-place elsewhere — excluding the miner just failed off.
        replacement, replacement_error = _replace(vm, failed, request.user)
        return Response(
            {
                "failed": _serialize_placement(failed),
                "replacement": (
                    _serialize_placement(replacement) if replacement is not None else None
                ),
                "replacement_error": replacement_error,
            },
            status=status.HTTP_200_OK,
        )


# ─── Helpers ─────────────────────────────────────────────────────────


def _active_placement(vm: Vm) -> Placement | None:
    """The VM's current active (Pending|Bound) placement, if any.

    Pulled into a module function so the `/place` idempotency
    pre-check is a single, testable seam.
    """
    return (
        Placement.objects.filter(vm=vm, status__in=ACTIVE_PLACEMENT_STATES)
        .select_related("vm", "decided_by")
        .first()
    )


def _idempotent_or_conflict(existing: Placement, resource_class: str) -> Response:
    """Resolve a `/place` call that found an already-active placement.

    Returns the existing row (idempotent 200) when the retry asks for
    the same `resource_class`, or a 409 `placement-conflict` when it
    asks for a different one. Shared by the idempotency pre-check and
    the IntegrityError race-recovery path so both honour one contract.
    """
    if existing.resource_class != resource_class:
        return Response(
            {
                "error": (
                    "vm already has an active placement with a different "
                    f"resource_class ({existing.resource_class!r})"
                ),
                "category": "placement-conflict",
                "current": _serialize_placement(existing),
            },
            status=status.HTTP_409_CONFLICT,
        )
    return Response(_serialize_placement(existing), status=status.HTTP_200_OK)


def _replace(
    vm: Vm, failed: Placement, actor: Any
) -> tuple[Placement | None, dict[str, str] | None]:
    """Best-effort re-placement after a `/fail`.

    Returns `(placement, None)` on success or `(None, error)` if the
    chain read failed or no miner was eligible. Excludes the miner
    the failed placement was on so the VM genuinely moves.
    """
    try:
        snapshot = chain.read_miner_status()
    except chain.ChainReadUnavailable as exc:
        log.warning("re-placement skipped — chain read failed: %s", exc)
        return None, {"error": str(exc), "category": "internal"}

    service.refresh_miner_capacity(snapshot)
    capacity, load, family_load = service.decision_inputs(failed.vm_family)

    try:
        chosen = decide_placement(
            snapshot=snapshot,
            capacity_by_node=capacity,
            load_by_node=load,
            family_load_by_node=family_load,
            max_family_per_node=service.cdn_family_cap(failed.vm_family),
            **service.cdn_edge_arguments(failed.vm_family, vm.vm_id),
            max_epoch_lag=service.max_epoch_lag(),
            excluded=frozenset({failed.miner_node_id}),
            dispatchable=service.dispatchable_node_ids(),
            # Gate (f) — a re-placement must stay in the region the VM was
            # sold in; the failed row does not carry it, the LaunchJob does.
            **service.region_arguments(service.launch_region_for_vm(vm.vm_id)),
            weights=SelectionWeights.from_settings(),
            max_host_share=service.max_host_share(),
            price_by_node=service.price_by_node(snapshot),
            # RA-M3 — carry the circuit-breaker + per-owner sub-budget into
            # re-placement too; the owner is on the failed Placement row, so
            # a churning VM does not silently re-concentrate onto one miner.
            recent_failures_by_node=service.recent_failures_by_node(),
            max_recent_failures=service.max_recent_failures(),
            owner_load_by_node=service.owner_load_by_node(failed.owner),
            max_owner_placements_per_miner=service.max_owner_placements_per_miner(),
            # Gate (e) — a re-placement after a failure is exactly when
            # NOT landing on a CVM-incapable host matters most.
            cvm_capability_by_node=service.cvm_capability_by_node(),
            zombie_quarantined=service.zombie_quarantined_node_ids(),
            # Gate (i) — no edge-region miner without a fresh net-policy ack.
            net_policy_unready=service.net_policy_unready_node_ids(),
            cordoned=service.cordoned_node_ids(),
            resource_fit=service.resource_fit(
                failed.resource_class,
                disk_gb=service.placement_disk_gb(failed.resource_class, failed.data_disk_gb),
            ),
        )
    except PlacementError as exc:
        return None, {"error": exc.message, "category": exc.category}

    try:
        with transaction.atomic():
            placement = Placement.objects.create(
                vm=vm,
                vm_family=failed.vm_family,
                owner=failed.owner,
                resource_class=failed.resource_class,
                data_disk_gb=failed.data_disk_gb,
                miner_node_id=chosen,
                status=PlacementStatus.PENDING.value,
                chain_epoch=snapshot.current_epoch,
                decided_by=actor,
            )
    except IntegrityError:
        # A concurrent /place created an active placement first —
        # return whatever survived rather than fail the /fail.
        winner = (
            Placement.objects.filter(vm=vm, status__in=ACTIVE_PLACEMENT_STATES)
            .select_related("vm", "decided_by")
            .first()
        )
        return winner, None

    ensure_guest_image_build(actor)
    log.info(
        "placement re-placed: vm=%s miner=%s (off %s)",
        vm.vm_id,
        chosen,
        failed.miner_node_id,
    )
    return placement, None


def _reread(placement_id: Any) -> Placement:
    """Re-read a placement post-CAS so the response carries the
    bumped version + updated fields.
    """
    return Placement.objects.select_related("vm", "decided_by").get(id=placement_id)


def _version_conflict(placement_id: Any) -> Response:
    """409 body for a stale-`if_version` / lost-CAS transition."""
    current = Placement.objects.filter(id=placement_id).select_related("vm", "decided_by").first()
    return Response(
        {
            "error": "if_version stale",
            "category": "version-conflict",
            "current": _serialize_placement(current) if current else None,
        },
        status=status.HTTP_409_CONFLICT,
    )


def _require_str(body: dict[str, Any], field: str, *, max_len: int | None = None) -> str:
    """Require a non-empty string body field. Raises `_WireError`."""
    if field not in body:
        raise _WireError(f"missing {field!r}")
    value = body[field]
    if not isinstance(value, str) or not value.strip():
        raise _WireError(f"{field} must be a non-empty string")
    if max_len is not None and len(value) > max_len:
        raise _WireError(f"{field} exceeds {max_len} chars", "bad-field")
    return value


def _require_int(body: dict[str, Any], field: str) -> int:
    """Require a JSON integer ≥ 1. Raises `_WireError`.

    `bool` is an `int` subclass in Python — rejected explicitly so
    `{"if_version": true}` cannot masquerade as `1`.
    """
    if field not in body:
        raise _WireError(f"missing {field!r}")
    value = body[field]
    if isinstance(value, bool) or not isinstance(value, int):
        raise _WireError(f"{field} must be an integer")
    if value < 1:
        raise _WireError(f"{field} must be ≥ 1")
    return value


_EDGE_REGISTRY_CACHE_KEY = "edge_registry_feed_v1"


def _resolve_registry_feed_seed() -> bytes | None:
    """Resolve the registry-feed Ed25519 signing seed (32 bytes), or
    `None` when unconfigured (audit M-registry-mTLS).

    PRODUCTION: `VALI_EDGE_REGISTRY_FEED_SIGNING_SEED_VAULT_PATH` → the
    `seed` field (64-hex) from Vault. TEST/dev: a 64-hex
    `VALI_EDGE_REGISTRY_FEED_SIGNING_SEED_HEX`. `None` ⇒ serve UNSIGNED
    (backward-compat window: deploy vali with the key, then pin the Edge
    pubkey; the Edge only fail-closes once its pubkey is set)."""
    vault_path = getattr(settings, "VALI_EDGE_REGISTRY_FEED_SIGNING_SEED_VAULT_PATH", "")
    seed_hex = ""
    if vault_path:
        from apps.orchestration.services.vault_kv import get_kv_field

        mount = getattr(settings, "VALI_VAULT_KV_MOUNT", "secret")
        seed_hex = get_kv_field(mount, vault_path, "seed").strip().lower()
    else:
        seed_hex = (
            str(getattr(settings, "VALI_EDGE_REGISTRY_FEED_SIGNING_SEED_HEX", "")).strip().lower()
        )
    if not seed_hex:
        return None
    if not re.fullmatch(r"[0-9a-f]{64}", seed_hex):
        raise ValueError("registry-feed signing seed is not 64 lower-case hex")
    return bytes.fromhex(seed_hex)


def _sign_registry_feed(canonical: bytes) -> str:
    """Ed25519-sign the canonical feed bytes → hex, or `""` when no signing
    key is configured (unsigned window)."""
    seed = _resolve_registry_feed_seed()
    if seed is None:
        return ""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey,
    )

    return Ed25519PrivateKey.from_private_bytes(seed).sign(canonical).hex()


class EdgeRegistryFeedView(APIView):
    """GET /v1/edge/registry — the registered+`Active` miner set, re-served
    for the Edge gateway's permissionless-auth poller (PR-2).

    The Edge pod's egress is deliberately locked to vali (it cannot reach
    the external chain RPC); vali — which has internet egress — reads the
    chain (`read-miner-status`) and re-serves the snapshot. The Edge
    polls this over plain in-cluster HTTP and admits a self-signed miner
    cert iff its node_id is in the `active` set.

    **Unauthenticated by design**: the payload is PUBLIC on-chain data
    (node_ids + statuses — no secret), the vali Service is in-cluster
    only (no Ingress) and NetworkPolicy-gated. Cached for
    `VALI_EDGE_REGISTRY_FEED_TTL_S` so an Edge poll every N seconds does
    not trigger a chain read every time. Fail-closed: a chain-read
    failure is a 503 (the Edge then keeps its last good set but flips
    unhealthy → refuses new handshakes), never a silent empty set.

    Wire shape (== `read-miner-status` ok payload, consumed by
    `hippius_onchain_registry::fetch_feed`):
        {"current_epoch": N,
         "miners": [{"node_id_hex", "status", "last_transition_epoch",
                     "data_epoch", "quality_dec"}, …]}
    """

    # P2 object-level authorization: `AllowAny` on-chain-derived registry
    # feed for the Edge.
    object_scope = scoping.PUBLIC

    permission_classes = [AllowAny]
    authentication_classes: list = []

    # The Edge admits a miner cert IFF its node_id is in this feed's
    # `active` set — so the feed is security-critical even though it is
    # PUBLIC data. It is served over plain in-cluster HTTP, so an
    # in-cluster MITM could inject a rogue node_id (admit its cert) or
    # strip legit ones (DoS). Rather than transport mTLS on vali's
    # gunicorn, the feed is SIGNED end-to-end (audit M-registry-mTLS): the
    # exact response bytes are Ed25519-signed with vali's registry-feed
    # key + returned in the `X-Hippius-Registry-Sig` header; the Edge
    # verifies against a pinned pubkey and fail-closed drops a tampered /
    # unsigned feed. Signing is cache-consistent — the SIGNED bytes are
    # exactly the SERVED bytes (a raw `HttpResponse`, not a re-rendered
    # DRF `Response`).
    SIG_HEADER = "X-Hippius-Registry-Sig"

    @extend_schema(
        summary="Edge permissionless-auth registry feed",
        description=(
            "Unauthenticated by design (PUBLIC on-chain data, in-cluster only). "
            "Re-serves the registered+Active miner set for the Edge gateway's "
            "auth poller. Served as a raw signed `HttpResponse` (compact sorted "
            "JSON) with an `X-Hippius-Registry-Sig` Ed25519 header. Fail-closed "
            "503 on a chain-read failure."
        ),
        tags=["Scheduler"],
        responses={
            200: EdgeRegistryFeedSerializer,
            503: OpenApiResponse(ErrorSerializer, "Chain unavailable."),
        },
    )
    def get(self, _request: Request) -> HttpResponse:
        cached = cache.get(_EDGE_REGISTRY_CACHE_KEY)
        if cached is not None:
            canonical, sig_hex = cached
            return self._signed_response(canonical, sig_hex)
        try:
            snapshot = chain.read_miner_status()
        except chain.ChainReadUnavailable as exc:
            log.warning("edge registry feed: chain unavailable: %s", exc)
            return HttpResponse(
                json.dumps({"detail": "chain unavailable"}),
                content_type="application/json",
                status=status.HTTP_503_SERVICE_UNAVAILABLE,
            )
        body = {
            "current_epoch": snapshot.current_epoch,
            "miners": [
                {
                    "node_id_hex": m.node_id,
                    "status": m.status,
                    "last_transition_epoch": m.last_transition_epoch,
                    "data_epoch": m.data_epoch,
                    # u128 — decimal STRING (out of JSON-number range).
                    "quality_dec": str(m.quality),
                }
                for m in snapshot.miners
            ],
        }
        # Canonical bytes: compact + sorted so the signature is over a
        # stable serialization and the Edge verifies the EXACT bytes.
        canonical = json.dumps(body, separators=(",", ":"), sort_keys=True)
        sig_hex = _sign_registry_feed(canonical.encode("utf-8"))
        ttl = float(getattr(settings, "VALI_EDGE_REGISTRY_FEED_TTL_S", 30.0))
        cache.set(_EDGE_REGISTRY_CACHE_KEY, (canonical, sig_hex), ttl)
        return self._signed_response(canonical, sig_hex)

    def _signed_response(self, canonical: str, sig_hex: str) -> HttpResponse:
        resp = HttpResponse(canonical, content_type="application/json")
        if sig_hex:
            resp[self.SIG_HEADER] = sig_hex
        return resp


def _serialize_placement(placement: Placement) -> dict[str, Any]:
    """Render a `Placement` row as the wire response."""
    return {
        "id": str(placement.id),
        "vm_id": placement.vm.vm_id,
        "vm_family": placement.vm_family,
        "resource_class": placement.resource_class,
        "miner_node_id": placement.miner_node_id,
        "status": placement.status,
        "chain_epoch": placement.chain_epoch,
        "reason": placement.reason or None,
        "kbs_release_ref": placement.kbs_release_ref or None,
        "decided_by": placement.decided_by.name,
        "decided_at": placement.decided_at.isoformat(),
        "bound_at": placement.bound_at.isoformat() if placement.bound_at else None,
        "failed_at": placement.failed_at.isoformat() if placement.failed_at else None,
        "version": placement.version,
    }


def _error(http_status: int, message: str, category: str) -> Response:
    return Response({"error": message, "category": category}, status=http_status)


# ─── /v1/price-recommendations (§23 marketplace, vSphere-DRS-manual) ──


def _serialize_recommendation(rec: PriceMigrationRecommendation) -> dict[str, Any]:
    """Render a `PriceMigrationRecommendation` as the wire response."""
    return {
        "recommendation_id": rec.recommendation_id,
        "vm_id": rec.vm.vm_id,
        "current_node_id": rec.current_node_id,
        "suggested_dest_node_id": rec.suggested_dest_node_id or None,
        "new_price": rec.new_price,
        "ceiling": rec.ceiling,
        "effective_block": rec.effective_block,
        "status": rec.status,
        "decided_by": rec.decided_by.name if rec.decided_by else None,
        "decided_at": rec.decided_at.isoformat() if rec.decided_at else None,
        "created_at": rec.created_at.isoformat(),
        "updated_at": rec.updated_at.isoformat(),
        "version": rec.version,
    }


def _recommendation_conflict(recommendation_id: str) -> Response:
    """409 for a stale-`if_version` / already-decided recommendation."""
    current = (
        PriceMigrationRecommendation.objects.filter(recommendation_id=recommendation_id)
        .select_related("vm", "decided_by")
        .first()
    )
    return Response(
        {
            "error": "recommendation is not Pending at if_version",
            "category": "version-conflict",
            "current": _serialize_recommendation(current) if current else None,
        },
        status=status.HTTP_409_CONFLICT,
    )


class PriceRecommendationListView(APIView):
    """`GET /v1/price-recommendations` — the open price-migration alerts.

    A miner that announces a price above a VM's tenant ceiling raises a
    `Pending` recommendation (NOT an automatic migration — that would be
    customer downtime). The operator/tenant lists them here and decides
    per-VM (`approve`/`dismiss`). Optional `?vm_id=` / `?node_id=` are a
    DISPLAY filter; the AUTHZ boundary is P2 object scoping — a
    tenant-scoped principal sees only recommendations for its own VMs.
    """

    # P2 object-level authorization: per-VM price alerts — narrowed via
    # `vm__tenant_id`.
    object_scope = scoping.TENANT_SCOPED

    permission_classes = [IsAuthenticated]
    http_method_names = ["get", "options"]

    @extend_schema(
        summary="List open price-migration recommendations",
        description=(
            "Lists the `Pending` price-breach alerts (a miner announced a price "
            "above a VM's tenant ceiling). NOT an automatic migration. Optional "
            "`vm_id` / `node_id` are a DISPLAY filter, not an authz boundary."
        ),
        tags=["Scheduler"],
        parameters=[
            OpenApiParameter("vm_id", str, OpenApiParameter.QUERY, description="Filter by VM id."),
            OpenApiParameter(
                "node_id",
                str,
                OpenApiParameter.QUERY,
                description="Filter by current miner node id.",
            ),
        ],
        responses={200: PriceRecommendationListSerializer},
    )
    def get(self, request: Request) -> Response:
        # P2: narrowed to the caller's own tenant (via the recommendation's
        # VM) BEFORE the display filters below, which can only narrow more.
        qs = (
            scoping.scope_queryset(
                request,
                PriceMigrationRecommendation.objects.filter(
                    status=PriceRecommendationStatus.PENDING.value
                ),
                tenant_field="vm__tenant_id",
            )
            .select_related("vm", "decided_by")
            .order_by("-created_at")
        )
        vm_id = request.query_params.get("vm_id")
        if vm_id:
            qs = qs.filter(vm__vm_id=vm_id)
        node_id = request.query_params.get("node_id")
        if node_id:
            qs = qs.filter(current_node_id=node_id)
        return Response(
            {"recommendations": [_serialize_recommendation(r) for r in qs]},
            status=status.HTTP_200_OK,
        )


class PriceRecommendationApproveView(APIView):
    """`POST /v1/price-recommendations/<recommendation_id>/approve` —
    root-only: accept the recommendation and start a §25 migration off the
    repricing miner. This is the MANUAL action (vSphere-DRS manual mode);
    the price-watch worker never migrates on its own.

    Body: `{"if_version": N}` (CAS guard). The destination is the
    recommendation's `suggested_dest_node_id`; `start_migration` validates
    it (Active, not same-node). The CAS + migration are one transaction —
    if the migration cannot start, the recommendation stays `Pending`.
    """

    # P2 object-level authorization: already root-gated; starts a §25 migration.
    object_scope = scoping.OPERATOR_ONLY

    permission_classes = [IsAuthenticated, IsRootClient]
    http_method_names = ["post", "options"]

    @extend_schema(
        summary="Approve a price recommendation (root-only → §25 migration)",
        description=(
            "Root-gated MANUAL action: CAS `Pending`→`Approved` and start a §25 "
            "migration to the recommendation's `suggested_dest_node_id`, in one "
            "transaction — if the migration cannot start the recommendation "
            "stays Pending. The price-watch worker never migrates on its own."
        ),
        tags=["Scheduler"],
        parameters=[
            OpenApiParameter(
                "recommendation_id",
                str,
                OpenApiParameter.PATH,
                description="The recommendation to approve.",
            )
        ],
        request=IfVersionRequestSerializer,
        responses={
            200: PriceRecommendationApproveSerializer,
            400: OpenApiResponse(ErrorSerializer, "Malformed body / bad field."),
            403: OpenApiResponse(ErrorSerializer, "Not the scheduler root principal."),
            404: OpenApiResponse(ErrorSerializer, "Recommendation not found."),
            409: OpenApiResponse(
                RecommendationConflictSerializer,
                "no-destination · stale if_version · migration start conflict.",
            ),
        },
    )
    def post(self, request: Request, recommendation_id: str) -> Response:
        from apps.orchestration import service as orch

        body = request.data
        if not isinstance(body, dict):
            return _error(
                status.HTTP_400_BAD_REQUEST,
                "request body must be a JSON object",
                "wire",
            )
        try:
            if_version = _require_int(body, "if_version")
        except _WireError as exc:
            return _error(status.HTTP_400_BAD_REQUEST, exc.message, exc.category)

        rec = (
            PriceMigrationRecommendation.objects.select_related("vm")
            .filter(recommendation_id=recommendation_id)
            .first()
        )
        if rec is None:
            return _error(status.HTTP_404_NOT_FOUND, "recommendation not found", "not-found")
        if not rec.suggested_dest_node_id:
            return _error(
                status.HTTP_409_CONFLICT,
                "recommendation has no suggested destination — retry once the "
                "watcher finds a within-budget miner",
                "no-destination",
            )

        try:
            with transaction.atomic():
                updated = PriceMigrationRecommendation.objects.filter(
                    id=rec.id,
                    version=if_version,
                    status=PriceRecommendationStatus.PENDING.value,
                ).update(
                    status=PriceRecommendationStatus.APPROVED.value,
                    version=if_version + 1,
                    decided_by=request.user,
                    decided_at=timezone.now(),
                )
                if updated == 0:
                    raise _CASLost
                # Start the migration inside the same transaction: a
                # StartError rolls the APPROVE back (rec stays Pending).
                job = orch.start_migration(
                    vm=rec.vm,
                    dest_node_id=rec.suggested_dest_node_id,
                    decided_by=request.user,
                )
        except _CASLost:
            return _recommendation_conflict(recommendation_id)
        except orch.StartError as exc:
            return _error(status.HTTP_409_CONFLICT, exc.message, exc.category)

        log.info(
            "price recommendation approved: rec=%s vm=%s → migration job=%s",
            recommendation_id,
            rec.vm.vm_id,
            job.job_id,
        )
        return Response(
            {
                "recommendation": _serialize_recommendation(
                    PriceMigrationRecommendation.objects.select_related("vm", "decided_by").get(
                        id=rec.id
                    )
                ),
                "migration_job_id": job.job_id,
            },
            status=status.HTTP_200_OK,
        )


class PriceRecommendationDismissView(APIView):
    """`POST /v1/price-recommendations/<recommendation_id>/dismiss` —
    root-only: the tenant accepts the new price; no migration. CAS
    Pending→Dismissed.
    """

    # P2 object-level authorization: already root-gated.
    object_scope = scoping.OPERATOR_ONLY

    permission_classes = [IsAuthenticated, IsRootClient]
    http_method_names = ["post", "options"]

    @extend_schema(
        summary="Dismiss a price recommendation (root-only, no migration)",
        description=(
            "Root-gated: the tenant accepts the new price — no migration. CAS "
            "`Pending`→`Dismissed`. A stale `if_version` loses with a 409 "
            "version-conflict."
        ),
        tags=["Scheduler"],
        parameters=[
            OpenApiParameter(
                "recommendation_id",
                str,
                OpenApiParameter.PATH,
                description="The recommendation to dismiss.",
            )
        ],
        request=IfVersionRequestSerializer,
        responses={
            200: PriceRecommendationSerializer,
            400: OpenApiResponse(ErrorSerializer, "Malformed body / bad field."),
            403: OpenApiResponse(ErrorSerializer, "Not the scheduler root principal."),
            404: OpenApiResponse(ErrorSerializer, "Recommendation not found."),
            409: OpenApiResponse(RecommendationConflictSerializer, "Stale if_version."),
        },
    )
    def post(self, request: Request, recommendation_id: str) -> Response:
        body = request.data
        if not isinstance(body, dict):
            return _error(
                status.HTTP_400_BAD_REQUEST,
                "request body must be a JSON object",
                "wire",
            )
        try:
            if_version = _require_int(body, "if_version")
        except _WireError as exc:
            return _error(status.HTTP_400_BAD_REQUEST, exc.message, exc.category)

        rec = PriceMigrationRecommendation.objects.filter(
            recommendation_id=recommendation_id
        ).first()
        if rec is None:
            return _error(status.HTTP_404_NOT_FOUND, "recommendation not found", "not-found")

        with transaction.atomic():
            updated = PriceMigrationRecommendation.objects.filter(
                id=rec.id,
                version=if_version,
                status=PriceRecommendationStatus.PENDING.value,
            ).update(
                status=PriceRecommendationStatus.DISMISSED.value,
                version=if_version + 1,
                decided_by=request.user,
                decided_at=timezone.now(),
            )
        if updated == 0:
            return _recommendation_conflict(recommendation_id)

        log.info(
            "price recommendation dismissed: rec=%s vm=%s",
            recommendation_id,
            rec.vm.vm_id,
        )
        return Response(
            _serialize_recommendation(
                PriceMigrationRecommendation.objects.select_related("vm", "decided_by").get(
                    id=rec.id
                )
            ),
            status=status.HTTP_200_OK,
        )


class _CASLost(Exception):
    """Internal: a compare-and-swap update matched 0 rows (lost race)."""
