"""`GET /v1/vm/<vm_id>/state` + `POST /v1/vm/<vm_id>/transition`.

The transition view is the only path that mutates a `Vm` row in
PR-G2. It enforces:

  1. Legal source→target pair (per `state_machine.legal`).
  2. Required fields for the target state.
  3. Optimistic concurrency: caller passes `if_version`, we
     `UPDATE … WHERE version=if_version`. Zero rows updated → 409.
  4. For Decommissioning→Destroyed and Migrating→Active: a valid
     guest-signed StoppedAck (shell-out to `verify-stopped-ack`).
  5. For Active→Migrating and Active→Decommissioning: mint a fresh
     EOL nonce on the row (consumed by the next-step ack).

Responses:

  200 — current state (GET) / successful transition (POST).
  400 — illegal transition / missing field / bad ack category.
  401 — unauthenticated (handled by DRF).
  404 — vm_id not found.
  409 — `if_version` stale (concurrent writer beat us).
  503 — validator binary unavailable.
"""

from __future__ import annotations

import logging
import time
from typing import Any

from django.conf import settings
from django.db import transaction
from django.utils import timezone
from drf_spectacular.types import OpenApiTypes
from drf_spectacular.utils import OpenApiParameter, OpenApiResponse, extend_schema
from rest_framework import status
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.request import Request
from rest_framework.response import Response
from rest_framework.views import APIView

from apps.common.schemas import ErrorSerializer
from apps.identity import scoping
from apps.orchestration.effects import EffectError, EffectUnavailable
from apps.orchestration.permissions import IsOrchestrationRoot
from apps.orchestration.services import kbs_evidence
from apps.orders.models import OrderTicketIntake

from . import attestation, boot_stall, validator
from .models import StoppedAckIngest, Vm, VmPowerState, VmState, destroyed_power_fields
from .schemas import (
    StoppedAckAcceptedSerializer,
    VmAttestationSerializer,
    VmListSerializer,
    VmSerializer,
    VmTransitionConflictSerializer,
    VmTransitionRequestSerializer,
)
from .state_machine import (
    CAT_GENERATION,
    CAT_ILLEGAL,
    CAT_MISSING_FIELD,
    TransitionError,
    TransitionRequest,
    legal,
    required_args,
    requires_stopped_ack,
)

log = logging.getLogger("apps.lifecycle.views")

_VM_ID_PARAM = OpenApiParameter(
    "vm_id", str, OpenApiParameter.PATH, description="Target VM id."
)


class VmStateView(APIView):
    """`GET /v1/vm/<vm_id>/state`. Returns the current row."""

    # P2 object-level authorization: one tenant's VM row — gated by `require_tenant_visible`.
    object_scope = scoping.TENANT_SCOPED

    permission_classes = [IsAuthenticated]
    http_method_names = ["get", "options"]

    @extend_schema(
        summary="Get a VM's lifecycle state",
        description="Returns the current `Vm` row (state, generation, host, version).",
        tags=["VM lifecycle"],
        parameters=[_VM_ID_PARAM],
        responses={
            200: VmSerializer,
            404: OpenApiResponse(ErrorSerializer, "VM not found."),
        },
    )
    def get(self, request: Request, vm_id: str) -> Response:
        try:
            vm = Vm.objects.get(vm_id=vm_id)
        except Vm.DoesNotExist:
            return _error(status.HTTP_404_NOT_FOUND, "vm not found", "not-found")
        # P2: a tenant-scoped principal may only see its own VM. Raises a
        # 404 (not a 403) so the response is indistinguishable from a VM
        # that does not exist — a 403 would confirm another tenant's vm_id.
        scoping.require_tenant_visible(request, vm.tenant_id)
        return Response(_serialize_vm(vm), status=status.HTTP_200_OK)


class VmListView(APIView):
    """`GET /v1/vm` — paginated list of VM rows for the upstream API.

    #587 Phase 2. The upstream product API (which owns end-user auth +
    ACLs) calls this with an OPERATOR service principal to render a
    tenant's VMs; for that principal the `tenant_id` / `lease_id` query
    params remain a DISPLAY filter and the upstream's ACL is the gate.

    P2: for a TENANT-scoped principal the list is narrowed to that
    principal's own tenant BEFORE the display filter runs
    (`scoping.scope_queryset`), so `?tenant_id=<someone-else>` returns an
    empty page rather than another tenant's fleet. Paginated by `limit`
    (default 50, max 200) + `offset` (default 0). Ordered by the model
    default (`-updated_at`), so the freshest rows come first.

    Response:

      {
        "vms": [ <_serialize_vm>, … ],
        "limit": 50, "offset": 0, "total": <int>,
      }
    """

    # P2 object-level authorization: tenant VM rows — narrowed by `scope_queryset`.
    object_scope = scoping.TENANT_SCOPED

    permission_classes = [IsAuthenticated]
    http_method_names = ["get", "options"]

    _DEFAULT_LIMIT = 50
    _MAX_LIMIT = 200

    @extend_schema(
        summary="List VM rows (paginated)",
        description=(
            "#587 Phase 2 — paginated VM list for the upstream product API "
            "(called with a service principal). Optional `tenant_id` / "
            "`lease_id` filter for DISPLAY only, NOT an authz boundary. "
            "Ordered by `-updated_at` (freshest first)."
        ),
        tags=["VM lifecycle"],
        parameters=[
            OpenApiParameter(
                "tenant_id", str, OpenApiParameter.QUERY,
                description="Filter by tenant id (display only).",
            ),
            OpenApiParameter(
                "lease_id", str, OpenApiParameter.QUERY,
                description="Filter by lease id (display only).",
            ),
            OpenApiParameter(
                "limit", int, OpenApiParameter.QUERY,
                description="Page size (default 50, clamped to 200).",
            ),
            OpenApiParameter(
                "offset", int, OpenApiParameter.QUERY,
                description="Row offset (default 0).",
            ),
        ],
        responses={
            200: VmListSerializer,
            400: OpenApiResponse(ErrorSerializer, "Non-integer / negative limit/offset."),
        },
    )
    def get(self, request: Request) -> Response:
        limit, offset, err = self._page_params(request)
        if err is not None:
            return err

        # P2: the AUTHORIZATION narrowing happens first and is not
        # negotiable — a tenant-scoped principal's queryset is filtered to
        # its own tenant before any caller-supplied `?tenant_id=` DISPLAY
        # filter is applied below (which can then only narrow further).
        qs = scoping.scope_queryset(request, Vm.objects.all())
        tenant_id = request.query_params.get("tenant_id")
        if tenant_id is not None:
            qs = qs.filter(tenant_id=tenant_id)
        lease_id = request.query_params.get("lease_id")
        if lease_id is not None:
            qs = qs.filter(lease_id=lease_id)

        total = qs.count()
        rows = list(qs[offset : offset + limit])
        return Response(
            {
                "vms": [
                    _serialize_vm(
                        vm, region_by_host, public_ips, backup_states, disks, data_deaths
                    )
                    for region_by_host in [_region_by_host({r.host for r in rows})]
                    for public_ips in [_public_ip_by_vm(rows)]
                    for backup_states in [_backup_state_by_vm(rows)]
                    for disks in [boot_stall.disk_gb_by_vm_id(r.vm_id for r in rows)]
                    for data_deaths in [_data_death_by_vm(rows)]
                    for vm in rows
                ],
                "limit": limit,
                "offset": offset,
                "total": total,
            },
            status=status.HTTP_200_OK,
        )

    def _page_params(
        self, request: Request
    ) -> tuple[int, int, Response | None]:
        """Parse + clamp `limit`/`offset`. Returns `(_, _, error)` with a
        400 Response when a param is non-integer or negative."""
        raw_limit = request.query_params.get("limit")
        raw_offset = request.query_params.get("offset")
        try:
            limit = (
                self._DEFAULT_LIMIT if raw_limit is None else int(raw_limit)
            )
            offset = 0 if raw_offset is None else int(raw_offset)
        except ValueError:
            return 0, 0, _error(
                status.HTTP_400_BAD_REQUEST,
                "limit/offset must be integers",
                "bad-pagination",
            )
        if limit < 0 or offset < 0:
            return 0, 0, _error(
                status.HTTP_400_BAD_REQUEST,
                "limit/offset must be non-negative",
                "bad-pagination",
            )
        return min(limit, self._MAX_LIMIT), offset, None


class VmAttestationView(APIView):
    """`GET /v1/vm/<vm_id>/attestation` — a tenant's proof their VM is
    genuinely running under attested confidential compute, checkable at
    any time.

    Composes vali's lifecycle facts with the KBS-signed
    `SignedEvidenceBundle` (the attested SNP measurement + raw report +
    VCEK chain + boot counter) fetched from the KBS evidence endpoint
    (#280). The bundle is KBS-L0-signed, so the tenant can re-verify the
    SNP report against AMD's root + the pinned KBS key OFFLINE — vali only
    relays it. That bundle does not survive a KBS restart, so the verdict
    (`attestation_state`) rests first on the VM's newest live attestation
    — see `apps.lifecycle.attestation`.

    Auth: `IsAuthenticated` + P2 object scoping. An OPERATOR principal
    (the upstream product API) may fetch any VM's evidence and is
    responsible for authorizing the owning end-user before relaying — the
    response carries `tenant_id` / `user_id` for exactly that. A
    TENANT-scoped principal may fetch only its own VMs; anything else is
    a 404. The principal is still a `ServiceClient`, so this is an
    authorization boundary, not a cryptographic binding to an end user.
    """

    # P2 object-level authorization: one tenant's VM evidence — gated by
    # `require_tenant_visible`.
    object_scope = scoping.TENANT_SCOPED

    permission_classes = [IsAuthenticated]
    http_method_names = ["get", "options"]

    @extend_schema(
        summary="Get a VM's attestation evidence",
        description=(
            "Composes vali's lifecycle facts with the KBS-signed evidence "
            "bundle (attested SNP measurement + raw report + VCEK chain + "
            "boot counter) so a tenant can re-verify the SNP report offline. "
            "vali only relays the KBS-L0-signed bundle. `attestation_state` "
            "rests first on the newest KBS-verified live attestation of the "
            "current launch, which survives a KBS restart; the bundle does not."
        ),
        tags=["VM lifecycle"],
        parameters=[_VM_ID_PARAM],
        responses={
            200: VmAttestationSerializer,
            404: OpenApiResponse(ErrorSerializer, "VM not found."),
        },
    )
    def get(self, request: Request, vm_id: str) -> Response:
        try:
            vm = Vm.objects.get(vm_id=vm_id)
        except Vm.DoesNotExist:
            return _error(status.HTTP_404_NOT_FOUND, "vm not found", "not-found")
        # P2: gate BEFORE the KBS evidence fetch — a cross-tenant caller
        # must not even be able to make vali dial the KBS for someone
        # else's VM (an oracle + an amplification vector). 404, not 403.
        scoping.require_tenant_visible(request, vm.tenant_id)

        # The VM's tenant/user + the attested platform binding live on the
        # latest OrderTicket (absent for a VM launched without an intake row).
        ticket = (
            OrderTicketIntake.objects.filter(vm_id=vm_id)
            .order_by("-received_at", "-id")
            .first()
        )

        evidence: dict[str, Any] | None = None
        evidence_error: dict[str, str] | None = None
        try:
            evidence = kbs_evidence.fetch_evidence(vm_id)
        except EffectUnavailable as exc:
            evidence_error = {"reason": "kbs-unavailable", "detail": str(exc)}
        except EffectError as exc:
            evidence_error = {"reason": "kbs-error", "detail": str(exc)}

        # The live attestation is the primary proof, the release bundle the
        # boot detail — see `apps.lifecycle.attestation`. `attested` stays a
        # POSITIVE claim only: neither source being present is not proof the
        # VM is unattested, so it is null there, never false.
        result = attestation.evaluate(
            vm,
            evidence=evidence,
            evidence_fetch_failed=evidence_error is not None,
            now_unix=int(time.time()),
        )

        vk = bytes(vm.lifecycle_vk) if vm.lifecycle_vk else b""
        out: dict[str, Any] = {
            "vm_id": vm.vm_id,
            "tenant_id": ticket.tenant_id if ticket else None,
            "user_id": ticket.user_id if ticket else None,
            # True when a live attestation or the release bundle proves the
            # VM attested; NULL when unknown. Never false.
            "attested": result.attested,
            "attestation_status": result.legacy_status,
            "attestation_state": result.state.value,
            # The newest KBS-verified live attestation of the current launch.
            "live_attestation": result.live,
            "lifecycle": {
                "state": vm.state,
                "generation": vm.generation,
                "host": vm.host or None,
                "lifecycle_vk_hex": vk.hex() if vk else None,
            },
            # The attested AMD chip_id the ticket pins the VM to.
            "platform_id": ticket.platform_id if ticket else None,
            # The KBS-signed attestation bundle (measurement, snp_report_hex,
            # vcek_chain_pem, boot_counter, kbs_signature_hex, …) or null.
            "kbs_evidence": evidence,
            "kbs_evidence_error": evidence_error,
        }
        return Response(out, status=status.HTTP_200_OK)


class VmTransitionView(APIView):
    """`POST /v1/vm/<vm_id>/transition` — drive the lifecycle state
    machine for a VM.

    Root-only (audit H10). This primitive can force ANY vm
    Active→Decommissioning/Migrating (a cross-tenant availability
    disruption), so it is gated on the orchestration-root principal,
    matching the parallel `/migrate` + `/decommission` orchestration
    endpoints. A plain authenticated `ServiceClient` is no longer
    sufficient. The in-process orchestration workers drive transitions
    directly via the ORM, so nothing legitimate depends on this endpoint
    being open to non-root callers.
    """

    # P2 object-level authorization: already root-gated; can force ANY VM
    # through the lifecycle SM.
    object_scope = scoping.OPERATOR_ONLY

    permission_classes = [IsAuthenticated, IsOrchestrationRoot]
    http_method_names = ["post", "options"]

    @extend_schema(
        summary="Drive the VM lifecycle state machine",
        description=(
            "Root-only (audit H10). Applies a legal §24/§25 transition under "
            "optimistic concurrency (`if_version`). The ack-gated transitions "
            "(Decommissioning→Destroyed, Migrating→Active) require a valid "
            "guest-signed `signed_stopped_ack_hex`."
        ),
        tags=["VM lifecycle"],
        parameters=[_VM_ID_PARAM],
        request=VmTransitionRequestSerializer,
        responses={
            200: VmSerializer,
            400: OpenApiResponse(
                ErrorSerializer, "Illegal transition / missing field / bad ack."
            ),
            403: OpenApiResponse(ErrorSerializer, "Not the orchestration root principal."),
            404: OpenApiResponse(ErrorSerializer, "VM not found."),
            409: OpenApiResponse(
                VmTransitionConflictSerializer, "`if_version` stale (concurrent writer)."
            ),
            503: OpenApiResponse(ErrorSerializer, "Validator binary unavailable."),
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
            req = _parse_request(body)
        except TransitionError as exc:
            return _error(status.HTTP_400_BAD_REQUEST, exc.message, exc.category)

        try:
            vm = Vm.objects.get(vm_id=vm_id)
        except Vm.DoesNotExist:
            return _error(status.HTTP_404_NOT_FOUND, "vm not found", "not-found")

        from_state = VmState(vm.state)
        if not legal(from_state, req.to_state):
            return _error(
                status.HTTP_400_BAD_REQUEST,
                f"illegal transition {from_state.value}→{req.to_state.value}",
                CAT_ILLEGAL,
            )

        try:
            required_args(req.to_state, req)
        except TransitionError as exc:
            return _error(status.HTTP_400_BAD_REQUEST, exc.message, exc.category)

        # Generation arithmetic per §25 + Rust `u64` mirror.
        if req.to_state == VmState.MIGRATING and from_state == VmState.ACTIVE:
            # §25 generation fencing: the destination MUST run on a
            # strictly higher generation so the source is reliably
            # fenced. `new_generation == old` would let a confused
            # orchestrator skip the fence; `<` would invert the
            # fence and re-elect the source as authoritative.
            if (req.new_generation or 0) <= vm.generation:
                return _error(
                    status.HTTP_400_BAD_REQUEST,
                    f"new_generation must be > current generation "
                    f"(got {req.new_generation}, current {vm.generation})",
                    CAT_GENERATION,
                )
            # Never begin a move onto a miner that is still running a VM
            # whose §24 crypto-erase already ran (`apps.lifecycle.zombie`).
            from apps.lifecycle.zombie import miner_is_quarantined

            if miner_is_quarantined(req.migration_dest or ""):
                return _error(
                    status.HTTP_409_CONFLICT,
                    f"migration_dest {req.migration_dest!r} is zombie-quarantined",
                    "dest-zombie-quarantined",
                )
            # Nor onto one the operator cordoned (no new work there).
            from apps.scheduler.service import miner_cordon_reason

            if miner_cordon_reason(req.migration_dest or "") is not None:
                return _error(
                    status.HTTP_409_CONFLICT,
                    f"migration_dest {req.migration_dest!r} is cordoned",
                    "dest-cordoned",
                )
        if req.to_state == VmState.ACTIVE and from_state == VmState.MIGRATING:
            # Completing a migration MUST use the row's stored
            # `new_generation`. A caller that supplies a different
            # new_generation is a confused orchestrator — reject
            # rather than guess.
            if req.new_generation != vm.new_generation:
                return _error(
                    status.HTTP_400_BAD_REQUEST,
                    f"new_generation {req.new_generation} != Vm.new_generation "
                    f"{vm.new_generation}",
                    CAT_GENERATION,
                )

        if requires_stopped_ack(from_state, req.to_state):
            ack_err = _verify_stopped_ack(vm, from_state, req)
            if ack_err is not None:
                return ack_err

        # Compute the new row shape.
        try:
            patch = _patch_for_transition(vm, from_state, req)
        except TransitionError as exc:
            return _error(status.HTTP_400_BAD_REQUEST, exc.message, exc.category)

        # CAS update — single SQL UPDATE filtered on the FULL pre-
        # image (vm_id, version, state, generation). Defense-in-depth
        # vs. PR-G5's orchestration writers: even if a future writer
        # mutates state without bumping `version`, the additional
        # filters reject the stale UPDATE rather than committing it
        # against a row that no longer matches what we verified
        # against. Zero rows updated → 409 (caller re-reads).
        from apps.scheduler.service import PlacementMoveConflict

        try:
            with transaction.atomic():
                updated = Vm.objects.filter(
                    vm_id=vm_id,
                    version=req.if_version,
                    state=from_state.value,
                    generation=vm.generation,
                ).update(version=req.if_version + 1, **patch)
                if updated and _completes_a_migration(from_state, req.to_state):
                    # This endpoint is the OTHER writer of `Vm.host` (the
                    # patch above promotes `migration_dest` to `host`), so
                    # it is the other place the §23 placement ledger would
                    # otherwise be left naming the SOURCE forever. Inside
                    # the CAS transaction for the same reason the §25
                    # driver does it inside its own: host and placement
                    # move together or not at all.
                    _move_placement_to_migration_dest(vm, actor=request.user)
                    # …and the SAME is true of the reboot-recovery
                    # bookkeeping, which is host-scoped (relaunch cap,
                    # backoff window, debounces): left alone, a VM that
                    # exhausted its relaunch budget on the source arrives
                    # at the destination already at the cap and can never
                    # be reboot-recovered there.
                    _rescope_reboot_recovery(vm)
        except PlacementMoveConflict as exc:
            # A concurrent writer holds the VM's active placement; the
            # whole transition rolled back. The caller re-reads and retries
            # — better than a transition that half-moved the VM.
            return _error(status.HTTP_409_CONFLICT, str(exc), "placement-conflict")
        if updated == 0:
            # Re-read so the caller sees the winning version.
            current = Vm.objects.filter(vm_id=vm_id).first()
            return Response(
                {
                    "error": "if_version stale",
                    "category": "version-conflict",
                    "current": _serialize_vm(current) if current else None,
                },
                status=status.HTTP_409_CONFLICT,
            )

        log.info(
            "vm transition: vm_id=%s %s→%s gen=%s if_version=%s",
            vm_id,
            from_state.value,
            req.to_state.value,
            patch.get("generation", vm.generation),
            req.if_version,
        )

        if req.to_state == VmState.DESTROYED:
            # Free the VM's capacity slots the instant it is destroyed —
            # otherwise a `Bound` placement pins the miner's admission bound
            # forever (§13 capacity leak). Lazy import: the lifecycle view
            # must not couple to the scheduler at module-load time.
            from apps.scheduler.service import release_placements_for_vm

            release_placements_for_vm(vm, reason="released:vm-destroyed")

            from apps.network.service import release_for_destroyed_vm

            release_for_destroyed_vm(vm)

        # Re-read so the response carries the post-update row + the
        # bumped version.
        vm = Vm.objects.get(vm_id=vm_id)
        return Response(_serialize_vm(vm), status=status.HTTP_200_OK)


class StoppedAckIngestView(APIView):
    """`POST /v1/lifecycle/stopped?vm_id=…&generation=…`.

    The guest's clean-shutdown ingress (§24 decommission / §25 cold
    migration). The measured guest's baked shutdown hook runs
    `hippius-agent-initramfs eol`, which signs a `StoppedAck` and POSTs
    the opaque canonical-CBOR `SignedStoppedAck` body here over the SAME
    public ingress the KBS / heartbeat path uses.

    This is an **opaque store**, not a verifier (§5.6): vali does NOT
    decode the CBOR body. It bounds the size, records the raw bytes
    keyed by `(vm_id, generation)` — both supplied as URL query params,
    which the guest reads from its measured cmdline — and returns 202.
    The orchestrator's `effects.poll_source_ack` / `poll_eol_ack` read
    these bytes later and hand them to the Rust verifier (`_verify_ack`),
    which is the actual trust gate (signature + nonce + generation). A
    forged / wrong / stale ack stored here is inert: it just fails that
    verification (fail-closed — the migration / decommission never
    advances).

    One exception: the ack of an `Active` VM the power API is stopping is
    verified HERE, while its signed time is fresh, and only the proof is
    kept (`_prove_power_stop`, #1162).

    Auth: `AllowAny`. The guest has no vali ServiceToken — it is the
    measured CVM reaching vali over the public front door. Storing an
    unverified opaque blob is not a trust grant (the verify step is what
    gates state). The body is size-capped to bound the allocation, and
    the row is keyed only by `(vm_id, generation)` (no SSRF, no decode).
    """

    # P2 object-level authorization: `AllowAny` guest ingress — the
    # measured CVM holds no vali token.
    object_scope = scoping.PUBLIC

    permission_classes = [AllowAny]
    # Per-IP throttle on the anon ingress (audit M-StoppedAck). DRF keys
    # an unauthenticated request on its source IP; combined with the
    # identity-bind below (only a VM awaiting an ack is stored) this caps
    # a flood of rejected writes. Generous — a real guest posts one ack
    # per lifecycle event. Rate = `stopped_ack` scope in REST_FRAMEWORK.
    throttle_scope = "stopped_ack"
    http_method_names = ["post", "options"]

    @extend_schema(
        summary="Ingest a guest-signed StoppedAck (opaque store)",
        description=(
            "§24/§25 clean-shutdown ingress. `AllowAny` — the measured guest "
            "holds no vali token. The body is the raw canonical-CBOR "
            "`SignedStoppedAck` (`application/octet-stream`), stored VERBATIM "
            "(never decoded here) keyed by `(vm_id, generation)`; the Rust "
            "verifier is the real trust gate on poll. Identity-bound: only a "
            "VM in MIGRATING/DECOMMISSIONING at the matching generation is "
            "stored (else a uniform 404)."
        ),
        tags=["VM lifecycle"],
        parameters=[
            OpenApiParameter(
                "vm_id", str, OpenApiParameter.QUERY, required=True,
                description="VM id (1..256 chars) — from the guest's measured cmdline.",
            ),
            OpenApiParameter(
                "generation", int, OpenApiParameter.QUERY, required=True,
                description="Generation the ack binds to (must match the row).",
            ),
        ],
        request={"application/octet-stream": OpenApiTypes.BINARY},
        responses={
            202: StoppedAckAcceptedSerializer,
            400: OpenApiResponse(ErrorSerializer, "Missing vm_id/generation / empty body."),
            404: OpenApiResponse(
                ErrorSerializer, "No VM awaiting an ack for this vm_id/generation."
            ),
            413: OpenApiResponse(ErrorSerializer, "Signed-ack body exceeds the size cap."),
        },
    )
    def post(self, request: Request, *args: Any, **kwargs: Any) -> Response:
        vm_id = request.query_params.get("vm_id", "")
        gen_raw = request.query_params.get("generation", "")
        if not vm_id or len(vm_id) > 256:
            return _error(
                status.HTTP_400_BAD_REQUEST,
                "vm_id query param required (1..256 chars)",
                "wire",
            )
        try:
            generation = int(gen_raw)
        except (TypeError, ValueError):
            return _error(
                status.HTTP_400_BAD_REQUEST,
                "generation query param required (integer)",
                "wire",
            )
        if generation < 0 or generation > 0x7FFF_FFFF_FFFF_FFFF:
            return _error(
                status.HTTP_400_BAD_REQUEST,
                "generation out of range",
                "wire",
            )

        # The body is the raw canonical-CBOR `SignedStoppedAck`. Read it
        # verbatim from the request stream — NEVER parsed as CBOR here
        # (the Rust verifier owns that, on poll). Cap the size to the
        # same byte budget the transition wire enforces (hex chars / 2).
        max_bytes = int(getattr(settings, "VALI_STOPPED_ACK_MAX_HEX_LEN", 4096)) // 2
        raw = request.body
        if not raw:
            return _error(
                status.HTTP_400_BAD_REQUEST,
                "empty signed-ack body",
                "stopped-decode",
            )
        if len(raw) > max_bytes:
            return _error(
                status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                f"signed-ack body exceeds {max_bytes} bytes",
                "stopped-decode",
            )

        # Identity-bind (audit M-StoppedAck): this endpoint is `AllowAny`
        # (the measured guest holds no vali token), so without a bind an
        # attacker could POST arbitrary (vm_id, generation) pairs and
        # create unbounded rows. The guest posts its ack AFTER vali has
        # transitioned the VM into MIGRATING/DECOMMISSIONING, at its BAKED
        # `hippius.vm_generation` (the launch / SIGNING generation) — which is
        # exactly what the orchestrator polls (`poll_source_ack`/`poll_eol_ack`
        # read `vm.signing_generation`). So only store an ack for a VM that
        # genuinely exists, is in one of those two ack-awaiting states, AND
        # matches that signing generation. A forged
        # ack for a non-existent / wrong-state / wrong-generation VM is
        # refused BEFORE any DB write. A single uniform 404 avoids leaking
        # which vm_ids / states / generations exist to an anon caller.
        vm = Vm.objects.filter(vm_id=vm_id).first()
        # The guest posts `?generation=<its BAKED hippius.vm_generation>` — the
        # launch (signing) generation, which a §25 migration does NOT re-bake.
        # Gate on `signing_generation`, NOT the live `generation` (bumped by
        # migration): a migrated VM's §24/re-migration guest still signs at its
        # launch generation, so gating on the bumped gen would 404 its ack.
        if (
            vm is not None
            and vm.state == VmState.ACTIVE
            and vm.power_state == VmPowerState.STOPPING
            and generation == vm.signing_generation
        ):
            return _prove_power_stop(vm, raw)
        if (
            vm is None
            or vm.state not in (VmState.MIGRATING, VmState.DECOMMISSIONING)
            or generation != vm.signing_generation
        ):
            return _error(
                status.HTTP_404_NOT_FOUND,
                "no VM awaiting a stopped-ack for this vm_id/generation",
                "not-found",
            )

        # Latest-wins: a re-driven quiesce re-signs a fresh ack for the
        # SAME (vm_id, generation) — overwrite rather than collide on the
        # uniqueness constraint.
        StoppedAckIngest.objects.update_or_create(
            vm_id=vm_id,
            generation=generation,
            defaults={"signed_ack": raw},
        )
        log.info(
            "stopped-ack ingested: vm_id=%s generation=%d bytes=%d",
            vm_id,
            generation,
            len(raw),
        )
        return Response(
            {"ok": True, "vm_id": vm_id, "generation": generation},
            status=status.HTTP_202_ACCEPTED,
        )


def _prove_power_stop(vm: Vm, raw: bytes) -> Response:
    """The ack of a guest shutting down for a power-API stop (#1162).

    Verified NOW, while its signed time is inside the skew window — a later
    §24 of the stopped VM could never verify it (and the row store is GC'd).
    Only the proof is kept: the `eol_nonce` of the boot that shut down, on
    `Vm.power_stop_proof`, and only if nothing moved since it was read (a
    start clears the proof; §24 honours it only while it matches the VM's
    nonce). Without it, that §24 has no guest left to sign and forces a
    reclaim that quarantines a healthy miner. The bytes are not stored, so
    an anonymous junk POST cannot displace the genuine proof.
    """
    if not vm.eol_nonce:
        return _error(
            status.HTTP_404_NOT_FOUND,
            "no VM awaiting a stopped-ack for this vm_id/generation",
            "not-found",
        )
    skew = int(getattr(settings, "VALI_STOPPED_ACK_SKEW_SECS", 600))
    now = int(time.time())
    try:
        validator.verify_stopped_ack(
            signed_bytes=raw,
            lifecycle_vk_hex=vm.lifecycle_vk_hex(),
            vm_id=vm.vm_id,
            lease_id=vm.lease_id,
            vm_generation=vm.signing_generation,
            nonce_hex=bytes(vm.eol_nonce).hex(),
            now_unix_min=now - skew,
            now_unix_max=now + skew,
        )
    except validator.ValidatorFailed as exc:
        log.info(
            "power-stop ack rejected: vm_id=%s category=%s", vm.vm_id, exc.category
        )
        return _error(status.HTTP_400_BAD_REQUEST, exc.message, exc.category)
    except validator.ValidatorUnavailable as exc:
        log.error("power-stop ack: validator unavailable: %s", exc)
        return _error(status.HTTP_503_SERVICE_UNAVAILABLE, str(exc), "internal")
    proven = Vm.objects.filter(
        pk=vm.pk,
        state=VmState.ACTIVE,
        power_state=VmPowerState.STOPPING,
        power_state_at=vm.power_state_at,
        eol_nonce=vm.eol_nonce,
    ).update(power_stop_proof=vm.eol_nonce)
    if not proven:
        return _error(
            status.HTTP_404_NOT_FOUND,
            "no VM awaiting a stopped-ack for this vm_id/generation",
            "not-found",
        )
    log.info("power-stop ack verified: vm_id=%s", vm.vm_id)
    return Response(
        {"ok": True, "vm_id": vm.vm_id, "generation": vm.signing_generation},
        status=status.HTTP_202_ACCEPTED,
    )


# ─── Helpers ────────────────────────────────────────────────────────


def _parse_request(body: dict[str, Any]) -> TransitionRequest:
    """Strict JSON → `TransitionRequest`. Unknown / missing /
    wrongly-typed fields raise `TransitionError` with `wire` category.
    """
    if "to_state" not in body:
        raise TransitionError("missing 'to_state'", "wire")
    if "if_version" not in body:
        raise TransitionError("missing 'if_version'", "wire")
    try:
        to_state = VmState(body["to_state"])
    except ValueError as exc:
        raise TransitionError(f"unknown to_state {body['to_state']!r}", "wire") from exc
    if_version = _coerce_int(body["if_version"], "if_version")
    if if_version < 1:
        raise TransitionError("if_version must be ≥ 1", "wire")
    new_generation_raw = body.get("new_generation")
    new_generation: int | None
    if new_generation_raw is not None:
        new_generation = _coerce_int(new_generation_raw, "new_generation")
        # `kbs_core::lifecycle::VmState` uses `u64`. Postgres BIGINT
        # is signed (i64); the binary CLI takes `u64`. Reject the
        # signed-int and i64-overflow paths AT INTAKE so they never
        # touch the DB or the subprocess.
        if new_generation < 0:
            raise TransitionError("new_generation must be ≥ 0", "wire")
        if new_generation > 0x7FFF_FFFF_FFFF_FFFF:
            raise TransitionError("new_generation overflows i64", "wire")
    else:
        new_generation = None
    migration_dest = body.get("migration_dest")
    if migration_dest is not None and not isinstance(migration_dest, str):
        raise TransitionError("migration_dest must be a string", "wire")
    ack_hex = body.get("signed_stopped_ack_hex")
    if ack_hex is not None and not isinstance(ack_hex, str):
        raise TransitionError("signed_stopped_ack_hex must be a string", "wire")
    return TransitionRequest(
        to_state=to_state,
        if_version=if_version,
        new_generation=new_generation,
        migration_dest=migration_dest,
        signed_stopped_ack_hex=ack_hex,
    )


def _coerce_int(value: Any, field: str) -> int:
    """Strict JSON-integer coercion.

    `bool` is an `int` subclass in Python — `int(True) == 1` quietly.
    Reject explicitly so `{"if_version": true}` doesn't slip past
    the parser.
    """
    if isinstance(value, bool) or not isinstance(value, int):
        # JSON-number → Python `int` is what we accept; everything
        # else (str, float, bool, None) is a wire error.
        if isinstance(value, bool):
            raise TransitionError(
                f"{field} must be an integer (got bool)", "wire"
            )
        try:
            coerced = int(value)
        except (TypeError, ValueError) as exc:
            raise TransitionError(
                f"{field} must be an integer", "wire"
            ) from exc
        # If we landed here via float coercion, reject — JSON sent
        # `1.5` which is not an integer.
        if isinstance(value, float) and not value.is_integer():
            raise TransitionError(
                f"{field} must be an integer (got float)", "wire"
            )
        return coerced
    return value


def _verify_stopped_ack(
    vm: Vm, from_state: VmState, req: TransitionRequest
) -> Response | None:
    """Shell out to `hippius-ticket-validator verify-stopped-ack`.

    Returns `None` on success (the caller proceeds to the CAS
    UPDATE), or a `Response` carrying a 4xx/5xx body on failure.
    """
    if not req.signed_stopped_ack_hex:
        return _error(
            status.HTTP_400_BAD_REQUEST,
            f"signed_stopped_ack_hex required for {from_state.value}→"
            f"{req.to_state.value}",
            CAT_MISSING_FIELD,
        )
    max_hex_len = int(getattr(settings, "VALI_STOPPED_ACK_MAX_HEX_LEN", 4096))
    if len(req.signed_stopped_ack_hex) > max_hex_len:
        # Bound the `bytes.fromhex` allocation BEFORE decoding so an
        # authenticated client can't blow up memory by sending
        # gigabytes of hex chars and then pipe the result to the
        # subprocess.
        return _error(
            status.HTTP_400_BAD_REQUEST,
            f"signed_stopped_ack_hex exceeds {max_hex_len} chars",
            "stopped-decode",
        )
    try:
        signed_bytes = bytes.fromhex(req.signed_stopped_ack_hex)
    except ValueError:
        return _error(
            status.HTTP_400_BAD_REQUEST,
            "signed_stopped_ack_hex is not valid hex",
            "stopped-decode",
        )

    if not vm.eol_nonce:
        # Defensive: a Decommissioning / Migrating row that has no
        # eol_nonce shouldn't exist (the prior transition mints it).
        # Surface explicitly rather than silently accepting any ack.
        return _error(
            status.HTTP_400_BAD_REQUEST,
            "Vm has no eol_nonce — was not prepared for stop",
            "stopped-replay",
        )

    skew = int(getattr(settings, "VALI_STOPPED_ACK_SKEW_SECS", 600))
    now = int(time.time())
    # Generation the ack should bind to: for Decommissioning→Destroyed
    # it's the current `generation`; for Migrating→Active (source ack)
    # it's `generation` (= old_gen) — the source guest signs FOR the
    # old gen, the destination then runs on new_gen.
    expected_gen = vm.generation

    try:
        verified = validator.verify_stopped_ack(
            signed_bytes=signed_bytes,
            lifecycle_vk_hex=vm.lifecycle_vk_hex(),
            vm_id=vm.vm_id,
            lease_id=vm.lease_id,
            vm_generation=expected_gen,
            nonce_hex=bytes(vm.eol_nonce).hex(),
            now_unix_min=now - skew,
            now_unix_max=now + skew,
        )
    except validator.ValidatorFailed as exc:
        log.info(
            "stopped-ack rejected: vm_id=%s category=%s",
            vm.vm_id,
            exc.category,
        )
        return _error(status.HTTP_400_BAD_REQUEST, exc.message, exc.category)
    except validator.ValidatorUnavailable as exc:
        log.error("stopped-ack validator unavailable: %s", exc)
        return _error(
            status.HTTP_503_SERVICE_UNAVAILABLE,
            str(exc),
            "internal",
        )

    log.info(
        "stopped-ack accepted: vm_id=%s gen=%s now_unix=%d",
        vm.vm_id,
        expected_gen,
        verified.now_unix,
    )
    return None


def _completes_a_migration(from_state: VmState, to_state: VmState) -> bool:
    """Is this transition the one that promotes the §25 destination to
    `Vm.host`? (`Migrating → Active` — see `_patch_for_transition`.)"""
    return from_state == VmState.MIGRATING and to_state == VmState.ACTIVE


def _move_placement_to_migration_dest(vm: Vm, *, actor: Any) -> None:
    """Hand the VM's §23 placement custody to the destination it is being
    activated on. Called with the PRE-image row, so `vm.migration_dest` is
    still the destination the patch is promoting to `host`.

    Fail-safe throughout: a destination that resolves to no registered
    chain `node_id`, or a VM with no placement ledger at all, moves NOTHING
    (see `scheduler.service.move_placement_to_node` — leaving a stale
    placement is bounded, leaving NO placement is not).
    """
    from apps.miners.models import MinerIdentity
    from apps.scheduler.service import move_placement_to_node

    node_id = (
        MinerIdentity.objects.filter(miner_id=vm.migration_dest)
        .values_list("chain_node_id", flat=True)
        .first()
        or ""
    )
    move_placement_to_node(
        vm,
        node_id=node_id,
        decided_by=actor,
        reason=f"migrated:transition→{vm.migration_dest}"[:256],
        release_ref=f"transition:{vm.vm_id}@gen{vm.new_generation}",
    )


def _rescope_reboot_recovery(vm: Vm) -> None:
    """Re-scope the VM's reboot-recovery counters to the destination this
    transition is promoting to `Vm.host`.

    Called with the PRE-image row, so `vm.migration_dest` is still the
    destination. A VM with no `RebootRecovery` row (the common case — the
    scan creates it lazily) is a no-op, and so is a "move" to the host the
    counters already name, which is what keeps reboot-recovery's own
    same-host relaunch from resetting the cap it is bounded by.
    """
    from apps.orchestration.service import rescope_reboot_recovery_to_host

    rescope_reboot_recovery_to_host(vm, new_host=vm.migration_dest)


def _patch_for_transition(
    vm: Vm, from_state: VmState, req: TransitionRequest
) -> dict[str, Any]:
    """Build the `UPDATE … SET …` patch for a legal transition.

    The patch INCLUDES the EOL-nonce mint / clear so the CAS UPDATE
    is atomic with respect to other transitions.
    """
    patch: dict[str, Any] = {"state": req.to_state.value}
    if req.to_state == VmState.MIGRATING:
        # Active → Migrating: store the new_gen + dest. The EOL nonce is
        # NOT (re-)minted (GAP 3): the source guest signs its stopped-ack
        # from its launch-baked, MEASURED `hippius.eol_nonce` cmdline
        # token (persisted onto Vm.eol_nonce at launch). Re-minting here
        # would hand the verifier a nonce the running guest never saw →
        # the ack could never verify. The GENERATION is the replay guard.
        patch["new_generation"] = req.new_generation
        patch["migration_dest"] = req.migration_dest
    elif req.to_state == VmState.DECOMMISSIONING:
        # Active|Migrating → Decommissioning: the EOL nonce is PRESERVED
        # (GAP 3 — same reasoning as Migrating above; the guest signs the
        # launch-baked value).
        # Clear migration fields if we're cancelling a Migrating.
        if from_state == VmState.MIGRATING:
            patch["migration_dest"] = ""
            patch["new_generation"] = None
    elif req.to_state == VmState.ACTIVE:
        # Migrating → Active(new_gen, dest): promote new_gen to gen,
        # promote dest to host, clear migration fields + the EOL
        # nonce (consumed).
        patch["generation"] = vm.new_generation
        patch["host"] = vm.migration_dest
        patch["migration_dest"] = ""
        patch["new_generation"] = None
        patch["eol_nonce"] = None
        # The destination's boot is the VM's current boot (boot-stall clock).
        patch["boot_started_at"] = timezone.now()
    elif req.to_state == VmState.DESTROYED:
        # Decommissioning → Destroyed{gen}: keep generation, clear
        # the EOL nonce (consumed), clear host fields (tombstone).
        patch["host"] = ""
        patch["migration_dest"] = ""
        patch["new_generation"] = None
        patch["eol_nonce"] = None
        patch.update(destroyed_power_fields())
    return patch


def _region_by_host(hosts: set[str]) -> dict[str, str]:
    """`{miner_id: ISO alpha-2}` for the hosts whose DETECTED location the
    scheduler would honour (`geo.placeable_locations`: fresh, verified). One
    query for any number of hosts, so a list page costs the same as one VM."""
    hosts = {h for h in hosts if h}
    if not hosts:
        return {}
    from apps.miners import geo

    return {
        miner_id: country.upper()
        for miner_id, country in geo.placeable_locations()
        .filter(miner__miner_id__in=hosts)
        .values_list("miner__miner_id", "country_code")
    }


def _public_ip_by_vm(vms: list[Vm]) -> dict[Any, dict[str, str]]:
    """`{vm pk: {address, edge, region}}` for the VMs holding a public IP —
    one query for a whole page, like `_region_by_host`."""
    from apps.network.service import public_ip_by_vm

    return public_ip_by_vm([vm.pk for vm in vms])


def _backup_state_by_vm(vms: list[Vm]) -> dict[Any, str]:
    """`{vm pk: backup_state}` — one policy query for a whole page."""
    from apps.backup.service import backup_state_by_vm

    return backup_state_by_vm(vms)


def _data_death_by_vm(vms: list[Vm]) -> dict[Any, str]:
    """`{vm pk: data_death}` of the VMs' §24 erase, one query for a page.
    Only VMs in `decommissioning` / `destroyed` can have one."""
    from apps.orchestration.models import DecommissionJob

    dead = [vm.pk for vm in vms if vm.state in (VmState.DECOMMISSIONING, VmState.DESTROYED)]
    if not dead:
        return {}
    out: dict[Any, str] = {}
    rows = (
        DecommissionJob.objects.filter(vm_id__in=dead)
        .exclude(data_death="")
        .order_by("kek_erased_at")
        .values_list("vm_id", "data_death")
    )
    for vm_pk, death in rows:
        out.setdefault(vm_pk, death)
    return out


def _serialize_vm(
    vm: Vm,
    region_by_host: dict[str, str] | None = None,
    public_ip_by_vm: dict[Any, dict[str, str]] | None = None,
    backup_state_by_vm: dict[Any, str] | None = None,
    disk_gb_by_vm_id: dict[str, int] | None = None,
    data_death_by_vm: dict[Any, str] | None = None,
) -> dict[str, Any]:
    """Render a `Vm` row as the wire response. `eol_nonce` is OMITTED
    on purpose — clients shouldn't see it; only the guest sees it via
    the EOL command channel, and only once.

    `region_by_host` / `public_ip_by_vm` / `data_death_by_vm` let a list
    render every row from one query each; a single-VM caller omits them
    and pays its own.
    """
    from . import guardian_wait

    liveness = vm.guest_liveness()
    stall = vm.boot_stall(disk_gb_by_vm_id=disk_gb_by_vm_id)
    if region_by_host is None:
        region_by_host = _region_by_host({vm.host})
    if public_ip_by_vm is None:
        public_ip_by_vm = _public_ip_by_vm([vm])
    if backup_state_by_vm is None:
        backup_state_by_vm = _backup_state_by_vm([vm])
    if data_death_by_vm is None:
        data_death_by_vm = _data_death_by_vm([vm])
    return {
        "vm_id": vm.vm_id,
        "tenant_id": vm.tenant_id,
        "lease_id": vm.lease_id,
        "state": vm.state,
        "generation": vm.generation,
        "new_generation": vm.new_generation,
        "host": vm.host,
        # The country the VM actually RUNS in: its host's detected, verified
        # location (never the region the launch asked for — that is the
        # upstream's record). `null` when the host has no fresh verified
        # location, which includes a VM not placed yet.
        "region": region_by_host.get(vm.host) or None,
        # The public IPv4 attached to the VM (`apps.network`), or `null`.
        "public_ip": public_ip_by_vm.get(vm.pk),
        # Live backups (`apps.backup`): disabled | pending | ok | stale.
        "backup_state": backup_state_by_vm.get(vm.pk, "disabled"),
        "migration_dest": vm.migration_dest,
        "version": vm.version,
        # Guest-boot progress mirror. "" until the first signed milestone;
        # `boot_phase_at` is null until then.
        "boot_phase": vm.boot_phase,
        "boot_phase_at": (
            vm.boot_phase_at.isoformat() if vm.boot_phase_at is not None else None
        ),
        # Boot stall — true when no in-guest signal has landed since the
        # current boot began (`boot_started_at`) for longer than the
        # per-flavor deadline (`apps.lifecycle.boot_stall`). Covers first
        # launches, relaunches and §25 activations alike.
        "boot_stalled": stall.stalled,
        "boot_started_at": (
            stall.boot_started_at.isoformat() if stall.boot_started_at is not None else None
        ),
        # Tenant NetBird overlay IP. "" until resolved from a served
        # receipt after enrolment; a pure DB read (no outbound call here).
        "netbird_ip": vm.netbird_ip,
        # Post-§25 overlay verdict: "" (nothing to verify) | pending | ok |
        # `lost` — the last meaning the guest is running but unreachable on
        # the overlay and cannot re-enrol itself. Read `netbird_ip`
        # TOGETHER with this: the IP is carried across a migration
        # verbatim, so a `lost` VM still shows its last known address.
        "netbird_status": vm.netbird_status,
        # In-guest LIVENESS — alive | wedged | unknown, DERIVED at read
        # time from the `guest_signal_at` watermark (never a stored mirror
        # that could disagree with it). This is the field that separates a
        # booted-and-alive guest from one wedged in its initramfs: `state`
        # and `boot_phase` both stay green for a wedged VM, because the
        # libvirt domain is still `running` and `boot_phase` is monotonic.
        # `unknown` means NEVER emitted a signal — not dead.
        #
        # A boot-stalled VM reads `wedged` HERE, on the wire, so a consumer
        # that already treats `wedged` as broken shows it as failed rather
        # than `unknown`/`alive`. Only the readout changes: the model-level
        # verdict (`Vm.guest_liveness()`, which drives the default-off
        # reboot-recovery WEDGED trigger and the WEDGED sweep) is untouched.
        "guest_liveness": "wedged" if stall.stalled else liveness.state,
        "guest_signal_at": (
            liveness.signal_at.isoformat() if liveness.signal_at is not None else None
        ),
        "guest_signal_age_s": liveness.age_s,
        "guest_signal_kind": liveness.kind,
        # Customer-held keys: who holds the disk key (`hippius` M0, `split`
        # M1, `customer` M2), pinned at launch.
        "key_mode": vm.key_mode,
        # An M1/M2 guest waiting in its initramfs on the customer's key
        # guardian: `{boot: awaiting-guardian, reason, since,
        # last_report_at, terminal}`, else null. DISPLAY-only (the miner can
        # forge or suppress it; the guardian's own audit log is the truth).
        "guardian_wait": guardian_wait.view(vm),
        # What §24 achieved for the tenant's data, once its erase step ran:
        # `crypto-erased` (Hippius destroyed the key the disk needs) or
        # `customer-erase-required` (M2 — Hippius never held the disk key:
        # it deleted what it stores, and only `guardian erase <vm>` makes
        # the data cryptographically unrecoverable). Null before §24.
        "data_death": data_death_by_vm.get(vm.pk) or None,
        "created_at": vm.created_at.isoformat(),
        "updated_at": vm.updated_at.isoformat(),
    }


def _error(http_status: int, message: str, category: str) -> Response:
    return Response(
        {"error": message, "category": category}, status=http_status
    )
