"""§24/§25 orchestration endpoints.

  POST /v1/vm/<vm_id>/migrate
      Body: {"dest_node_id": "..."}.
      Auth: orchestration root principal ONLY.
      Starts a §25 `MigrationJob` (state `Draining`). The
      `vali_orchestration_tick` daemon drives it forward.
      → 202 created / 400 wire · same-node / 403 / 404 vm /
        409 vm-not-active · job-in-flight.

  GET /v1/vm/<vm_id>/migrate/<job_id>
      Auth: any authenticated ServiceClient. → 200 job / 404.

  POST /v1/vm/<vm_id>/decommission
      Auth: orchestration root principal ONLY.
      Starts a §24 `DecommissionJob` (state `Draining`).
      → 202 / 403 / 404 / 409.

  GET /v1/vm/<vm_id>/decommission/<job_id>
      Auth: any authenticated ServiceClient. → 200 job / 404.

The endpoints only *start* + *poll* jobs — all orchestration logic
runs in the `vali_orchestration_tick` daemon, so a slow external
peer never blocks the request thread.
"""

from __future__ import annotations

import logging
from typing import Any

from drf_spectacular.utils import OpenApiParameter, OpenApiResponse, extend_schema
from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from rest_framework.request import Request
from rest_framework.response import Response
from rest_framework.views import APIView

from apps.common.schemas import ErrorSerializer
from apps.identity import scoping
from apps.lifecycle.models import Vm

from . import launch_jobs, service
from .launch_jobs import LaunchIntentError
from .models import DecommissionJob, LaunchJob, MeasurementLedger, MigrationJob
from .permissions import IsOrchestrationRoot
from .schemas import (
    DecommissionJobSerializer,
    LaunchIntentSerializer,
    LaunchJobSerializer,
    MeasurementAuditSerializer,
    MigrateStartRequestSerializer,
    MigrationJobSerializer,
    PowerPolicyRequestSerializer,
    PowerPolicySerializer,
)
from .service import StartError

_VM_ID_PARAM = OpenApiParameter(
    "vm_id", str, OpenApiParameter.PATH, description="Target VM id."
)
_JOB_ID_PARAM = OpenApiParameter(
    "job_id", str, OpenApiParameter.PATH, description="Job id returned by the start call."
)

log = logging.getLogger("apps.orchestration.views")

_MAX_NODE_ID = 64

# `LaunchIntentError` categories that are a caller mistake (400) vs a
# state conflict (409) vs an internal/config fault (503).
_LAUNCH_CONFLICT_CATEGORIES = frozenset({"conflict"})
_LAUNCH_INTERNAL_CATEGORIES = frozenset({"internal"})

# `StartError` categories that are a caller mistake (400) rather than
# a VM-state conflict (409).
_BAD_REQUEST_CATEGORIES = frozenset({"same-node"})
#: A §25 intake refusal that is about the SYSTEM, not the request — the
#: same call is expected to succeed once Vault answers again. 503 says
#: "retry", where the 409 default says "this VM cannot migrate".
_UNAVAILABLE_CATEGORIES = frozenset({"vault-unavailable"})


# ─── POST /v1/vm/<vm_id>/migrate ─────────────────────────────────────


class MigrateStartView(APIView):
    """`POST /v1/vm/<vm_id>/migrate` — root-only; starts a §25 job."""

    # P2 object-level authorization: already root-gated §25 trigger.
    object_scope = scoping.OPERATOR_ONLY

    permission_classes = [IsAuthenticated, IsOrchestrationRoot]
    http_method_names = ["post", "options"]

    @extend_schema(
        summary="Start a §25 live migration",
        description=(
            "Root-only. Starts a §25 `MigrationJob` (state `Draining`); the "
            "`vali_orchestration_tick` daemon drives it forward."
        ),
        tags=["VM orchestration"],
        parameters=[_VM_ID_PARAM],
        request=MigrateStartRequestSerializer,
        responses={
            202: MigrationJobSerializer,
            400: OpenApiResponse(ErrorSerializer, "Malformed body / bad dest_node_id."),
            403: OpenApiResponse(ErrorSerializer, "Not the orchestration root principal."),
            404: OpenApiResponse(ErrorSerializer, "VM not found."),
            409: OpenApiResponse(ErrorSerializer, "VM not Active / job in flight."),
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
        dest_node_id = body.get("dest_node_id")
        if not isinstance(dest_node_id, str) or not dest_node_id.strip():
            return _error(
                status.HTTP_400_BAD_REQUEST,
                "dest_node_id must be a non-empty string",
                "wire",
            )
        if len(dest_node_id) > _MAX_NODE_ID:
            return _error(
                status.HTTP_400_BAD_REQUEST,
                f"dest_node_id exceeds {_MAX_NODE_ID} chars",
                "wire",
            )
        # `cold: true` migrates a tenant-STOPPED VM: started on its source for
        # the warm §25, stopped again at the destination. Without it a
        # stopped VM is refused (`vm-not-running`), as before.
        cold = body.get("cold", False)
        if not isinstance(cold, bool):
            return _error(status.HTTP_400_BAD_REQUEST, "cold must be a boolean", "wire")

        try:
            vm = Vm.objects.get(vm_id=vm_id)
        except Vm.DoesNotExist:
            return _error(status.HTTP_404_NOT_FOUND, "vm not found", "not-found")

        try:
            job = service.start_migration(
                vm=vm,
                dest_node_id=dest_node_id,
                decided_by=request.user,
                cold=cold,
            )
        except StartError as exc:
            return _start_error_response(exc)
        return Response(
            _serialize_migration(job), status=status.HTTP_202_ACCEPTED
        )


class MigrateJobView(APIView):
    """`GET /v1/vm/<vm_id>/migrate/<job_id>` — poll a §25 job."""

    # P2 object-level authorization: one tenant's migration job — gated via
    # `vm__tenant_id`.
    object_scope = scoping.TENANT_SCOPED

    permission_classes = [IsAuthenticated]
    http_method_names = ["get", "options"]

    @extend_schema(
        summary="Poll a §25 migration job",
        tags=["VM orchestration"],
        parameters=[_VM_ID_PARAM, _JOB_ID_PARAM],
        responses={
            200: MigrationJobSerializer,
            404: OpenApiResponse(ErrorSerializer, "Migration job not found."),
        },
    )
    def get(self, request: Request, vm_id: str, job_id: str) -> Response:
        # P2: the scoping filter is part of the LOOKUP, so a job on another
        # tenant's VM is simply not found — same 404 as a bad job_id, no
        # existence oracle.
        job = (
            scoping.scope_queryset(
                request,
                MigrationJob.objects.filter(vm__vm_id=vm_id, job_id=job_id),
                tenant_field="vm__tenant_id",
            )
            .select_related("vm", "decided_by")
            .first()
        )
        if job is None:
            return _error(
                status.HTTP_404_NOT_FOUND, "migration job not found", "not-found"
            )
        return Response(_serialize_migration(job), status=status.HTTP_200_OK)


class MigrateCancelView(APIView):
    """`POST /v1/vm/<vm_id>/migrate/<job_id>/cancel` — root-only (#587
    Phase 3). Abort an in-flight §25 migration that is still pre-`Fencing`
    (the `Vm` is still `Active` on the source) → graceful `Failed` with a
    reason. A migration that has passed the KBS fence is forward-only
    (§25) and returns 409 `past-fence`; an already-terminal job returns
    409 `already-terminal`.
    """

    # P2 object-level authorization: already root-gated §25 action.
    object_scope = scoping.OPERATOR_ONLY

    permission_classes = [IsAuthenticated, IsOrchestrationRoot]
    http_method_names = ["post", "options"]

    @extend_schema(
        summary="Cancel a pre-fence §25 migration",
        description=(
            "Root-only (#587 Phase 3). Aborts an in-flight migration still "
            "pre-`Fencing` → graceful `Failed`. Past the KBS fence is "
            "forward-only (409 `past-fence`); a terminal job returns 409 "
            "`already-terminal`."
        ),
        tags=["VM orchestration"],
        parameters=[_VM_ID_PARAM, _JOB_ID_PARAM],
        request=None,
        responses={
            200: MigrationJobSerializer,
            403: OpenApiResponse(ErrorSerializer, "Not the orchestration root principal."),
            404: OpenApiResponse(ErrorSerializer, "Migration job not found."),
            409: OpenApiResponse(ErrorSerializer, "Past fence / already terminal."),
        },
    )
    def post(self, request: Request, vm_id: str, job_id: str) -> Response:
        job = (
            MigrationJob.objects.filter(vm__vm_id=vm_id, job_id=job_id)
            .select_related("vm", "decided_by")
            .first()
        )
        if job is None:
            return _error(
                status.HTTP_404_NOT_FOUND, "migration job not found", "not-found"
            )
        try:
            job = service.cancel_migration(job=job, decided_by=request.user)
        except StartError as exc:
            return _start_error_response(exc)
        return Response(_serialize_migration(job), status=status.HTTP_200_OK)


# ─── POST /v1/vm/<vm_id>/decommission ────────────────────────────────


class DecommissionStartView(APIView):
    """`POST /v1/vm/<vm_id>/decommission` — root-only; starts a §24 job."""

    # P2 object-level authorization: already root-gated §24 trigger.
    object_scope = scoping.OPERATOR_ONLY

    permission_classes = [IsAuthenticated, IsOrchestrationRoot]
    http_method_names = ["post", "options"]

    @extend_schema(
        summary="Start a §24 decommission",
        description="Root-only. Starts a §24 `DecommissionJob` (state `Draining`).",
        tags=["VM orchestration"],
        parameters=[_VM_ID_PARAM],
        request=None,
        responses={
            202: DecommissionJobSerializer,
            403: OpenApiResponse(ErrorSerializer, "Not the orchestration root principal."),
            404: OpenApiResponse(ErrorSerializer, "VM not found."),
            409: OpenApiResponse(ErrorSerializer, "VM-state conflict / job in flight."),
        },
    )
    def post(self, request: Request, vm_id: str) -> Response:
        try:
            vm = Vm.objects.get(vm_id=vm_id)
        except Vm.DoesNotExist:
            return _error(status.HTTP_404_NOT_FOUND, "vm not found", "not-found")

        try:
            job = service.start_decommission(vm=vm, decided_by=request.user)
        except StartError as exc:
            return _start_error_response(exc)
        return Response(
            _serialize_decommission(job), status=status.HTTP_202_ACCEPTED
        )


class DecommissionJobView(APIView):
    """`GET /v1/vm/<vm_id>/decommission/<job_id>` — poll a §24 job."""

    # P2 object-level authorization: one tenant's decommission job — gated
    # via `vm__tenant_id`.
    object_scope = scoping.TENANT_SCOPED

    permission_classes = [IsAuthenticated]
    http_method_names = ["get", "options"]

    @extend_schema(
        summary="Poll a §24 decommission job",
        tags=["VM orchestration"],
        parameters=[_VM_ID_PARAM, _JOB_ID_PARAM],
        responses={
            200: DecommissionJobSerializer,
            404: OpenApiResponse(ErrorSerializer, "Decommission job not found."),
        },
    )
    def get(self, request: Request, vm_id: str, job_id: str) -> Response:
        # P2: scoped in the LOOKUP — see `MigrateJobView.get`.
        job = (
            scoping.scope_queryset(
                request,
                DecommissionJob.objects.filter(vm__vm_id=vm_id, job_id=job_id),
                tenant_field="vm__tenant_id",
            )
            .select_related("vm", "decided_by")
            .first()
        )
        if job is None:
            return _error(
                status.HTTP_404_NOT_FOUND, "decommission job not found", "not-found"
            )
        return Response(_serialize_decommission(job), status=status.HTTP_200_OK)


# ─── POST /v1/vm/launch  +  GET /v1/vm/launch/<job_id>  (PR-A2) ───────


class LaunchStartView(APIView):
    """`POST /v1/vm/launch` — enqueue an admin-requested VM launch.

    Body: the launch intent (tenant_id, user_id, vm_id, lease_id, flavor,
    cmdline, s3 location + artefact SHAs, kek_vault_path, optional
    netbird / measurement / paths) PLUS `userdata` (the cloud-init
    plaintext, staged to Vault — never stored on the job row).

    Returns 202 + the job. The `vali_launch_tick` worker picks it up
    and drives `launch_vm` (scheduler place → dispatch → re-place).
    """

    # Launch is a privileged operator action — it mints an L1 OrderTicket,
    # stages Vault secrets, registers the VM with the KBS, and dispatches
    # to a miner. Root-only, matching MigrateStartView / DecommissionStartView.
    # P2 object-level authorization: already root-gated; mints an L1 ticket
    # + stages Vault secrets.
    object_scope = scoping.OPERATOR_ONLY
    permission_classes = [IsAuthenticated, IsOrchestrationRoot]
    # Per-client rate limit (audit M-ratelimit): a generous cap so a
    # compromised/buggy root can't spin up VMs without bound. Rate =
    # `vm_launch` scope in REST_FRAMEWORK.
    throttle_scope = "vm_launch"
    http_method_names = ["post", "options"]

    @extend_schema(
        summary="Enqueue an admin-requested VM launch",
        description=(
            "Root-only. Validates the launch intent, stages the cloud-init "
            "`userdata` to Vault, and enqueues a `LaunchJob`. Returns 202 + "
            "the queued job; the `vali_launch_tick` worker drives `launch_vm` "
            "(scheduler place → dispatch → re-place). Poll via "
            "`GET /v1/vm/launch/{job_id}`."
        ),
        tags=["VM orchestration"],
        request=LaunchIntentSerializer,
        responses={
            202: LaunchJobSerializer,
            400: OpenApiResponse(
                ErrorSerializer,
                "Malformed body / bad field (`wire`/`bad-field`), or a flavor above "
                "the largest offered size (`flavor-not-offered`).",
            ),
            403: OpenApiResponse(ErrorSerializer, "Not the orchestration root principal."),
            409: OpenApiResponse(ErrorSerializer, "In-flight launch already exists for this VM."),
            503: OpenApiResponse(ErrorSerializer, "Vault stage / config fault (`internal`)."),
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
        userdata = body.get("userdata")
        if not isinstance(userdata, str) or not userdata:
            return _error(
                status.HTTP_400_BAD_REQUEST,
                "userdata must be a non-empty string (cloud-init plaintext)",
                "wire",
            )
        try:
            job = launch_jobs.start_launch(
                intent=body,
                userdata=userdata.encode("utf-8"),
                decided_by=request.user,
            )
        except LaunchIntentError as exc:
            return _error(_launch_http_status(exc.category), exc.message, exc.category)
        return Response(_serialize_launch(job), status=status.HTTP_202_ACCEPTED)


class LaunchJobView(APIView):
    """`GET /v1/vm/launch/<job_id>` — poll a launch job."""

    # P2 object-level authorization: one tenant's launch job — gated via `tenant_id`.
    object_scope = scoping.TENANT_SCOPED

    permission_classes = [IsAuthenticated]
    http_method_names = ["get", "options"]

    @extend_schema(
        summary="Poll a launch job",
        tags=["VM orchestration"],
        parameters=[_JOB_ID_PARAM],
        responses={
            200: LaunchJobSerializer,
            404: OpenApiResponse(ErrorSerializer, "Launch job not found."),
        },
    )
    def get(self, request: Request, job_id: str) -> Response:
        # P2: `LaunchJob` carries its own `tenant_id` (the VM row may not
        # exist yet — the launch creates it), so scope on that column.
        job = (
            scoping.scope_queryset(request, LaunchJob.objects.filter(job_id=job_id))
            .select_related("decided_by")
            .first()
        )
        if job is None:
            return _error(
                status.HTTP_404_NOT_FOUND, "launch job not found", "not-found"
            )
        return Response(_serialize_launch(job), status=status.HTTP_200_OK)


# ─── GET /v1/admin/audit/measurements (PR-587 Phase 3) ───────────────


class MeasurementAuditView(APIView):
    """`GET /v1/admin/audit/measurements` — the fleet-wide append-only
    ledger of every pinned SNP launch digest (#587 Phase 3).

    Root-only operator audit: returns each pinned `launch_digest` +
    `platform_id` (the miner CHIP_ID) + `node_id` + `allowlist_epoch` +
    `pinned_at`, newest first. Filter by `platform_id` / `launch_digest`
    / `vm_id` for the "which firmware emits what measurement" diagnostics
    (cf. the Turin v4 / reported-tcb investigation). Paginated by `limit`
    (default 100, max 500) + `offset`.
    """

    # P2 object-level authorization: fleet-wide measurement ledger.
    object_scope = scoping.OPERATOR_ONLY

    permission_classes = [IsAuthenticated, IsOrchestrationRoot]
    http_method_names = ["get", "options"]

    _DEFAULT_LIMIT = 100
    _MAX_LIMIT = 500

    @extend_schema(
        summary="Fleet-wide pinned-measurement audit ledger",
        description=(
            "Root-only (#587 Phase 3). Append-only ledger of every pinned SNP "
            "launch digest, newest first."
        ),
        tags=["VM orchestration"],
        parameters=[
            OpenApiParameter("platform_id", str, description="Filter by miner CHIP_ID."),
            OpenApiParameter("vm_id", str, description="Filter by VM id."),
            OpenApiParameter(
                "launch_digest", str, description="Filter by pinned launch digest (hex)."
            ),
            OpenApiParameter("limit", int, description="Page size (default 100, max 500)."),
            OpenApiParameter("offset", int, description="Page offset (default 0)."),
        ],
        responses={
            200: MeasurementAuditSerializer,
            400: OpenApiResponse(ErrorSerializer, "Bad pagination params."),
            403: OpenApiResponse(ErrorSerializer, "Not the orchestration root principal."),
        },
    )
    def get(self, request: Request) -> Response:
        try:
            limit = (
                self._DEFAULT_LIMIT
                if request.query_params.get("limit") is None
                else int(request.query_params["limit"])
            )
            offset = int(request.query_params.get("offset", 0))
        except ValueError:
            return _error(
                status.HTTP_400_BAD_REQUEST,
                "limit/offset must be integers",
                "bad-pagination",
            )
        if limit < 0 or offset < 0:
            return _error(
                status.HTTP_400_BAD_REQUEST,
                "limit/offset must be non-negative",
                "bad-pagination",
            )
        limit = min(limit, self._MAX_LIMIT)

        qs = MeasurementLedger.objects.all()
        for field in ("platform_id", "vm_id"):
            val = request.query_params.get(field)
            if val is not None:
                qs = qs.filter(**{field: val})
        digest = request.query_params.get("launch_digest")
        if digest is not None:
            qs = qs.filter(launch_digest_hex=digest)

        total = qs.count()
        rows = list(qs[offset : offset + limit])
        return Response(
            {
                "measurements": [
                    {
                        "vm_id": r.vm_id,
                        "launch_digest": r.launch_digest_hex,
                        "platform_id": r.platform_id,
                        "node_id": r.node_id,
                        "allowlist_epoch": r.allowlist_epoch,
                        "allowlist_sha256": r.allowlist_sha256,
                        "measurement_class": r.measurement_class,
                        "pinned_at": r.pinned_at.isoformat(),
                    }
                    for r in rows
                ],
                "limit": limit,
                "offset": offset,
                "total": total,
            },
            status=status.HTTP_200_OK,
        )


# ─── helpers ─────────────────────────────────────────────────────────


def _launch_http_status(category: str) -> int:
    if category in _LAUNCH_CONFLICT_CATEGORIES:
        return status.HTTP_409_CONFLICT
    if category in _LAUNCH_INTERNAL_CATEGORIES:
        return status.HTTP_503_SERVICE_UNAVAILABLE
    return status.HTTP_400_BAD_REQUEST


def _serialize_launch(job: LaunchJob) -> dict[str, Any]:
    """Render a `LaunchJob`. No secret is on the model, so none appears
    here — only the Vault REFS, the state, and the result summary.
    """
    return {
        "job_id": job.job_id,
        "vm_id": job.vm_id,
        "tenant_id": job.tenant_id,
        "flavor": job.flavor,
        "state": job.state,
        "phase": job.phase or None,
        "miner_id": job.miner_id or None,
        "placement_id": job.placement_id or None,
        "reason": job.reason or None,
        "result": job.result_json,
        "decided_by": job.decided_by.name,
        "started_at": job.started_at.isoformat(),
        "finished_at": job.finished_at.isoformat() if job.finished_at else None,
        "version": job.version,
    }


def _start_error_response(exc: StartError) -> Response:
    if exc.category in _BAD_REQUEST_CATEGORIES:
        http_status = status.HTTP_400_BAD_REQUEST
    elif exc.category in _UNAVAILABLE_CATEGORIES:
        http_status = status.HTTP_503_SERVICE_UNAVAILABLE
    else:
        http_status = status.HTTP_409_CONFLICT
    return _error(http_status, exc.message, exc.category)


def _serialize_migration(job: MigrationJob) -> dict[str, Any]:
    """Render a `MigrationJob`. No presigned URLs / credentials are
    persisted on the model, so none can appear here.
    """
    return {
        "job_id": job.job_id,
        "vm_id": job.vm.vm_id,
        "source_node_id": job.source_node_id,
        "dest_node_id": job.dest_node_id,
        "source_gen": job.source_gen,
        "new_gen": job.new_gen,
        "state": job.state,
        # A COLD migration (the VM was stopped): started on its source,
        # stopped again at the destination once it proved it runs.
        "cold": job.cold,
        "cold_settle_reason": job.cold_settle_reason or None,
        "source_ack_verified": job.source_ack_verified,
        # P9/#15 — whether the SOURCE host's per-VM artifacts (the tenant's
        # LUKS overlay, the boot-counter disk, the staged boot artifacts)
        # have been reclaimed, and if not, why not.
        "source_reclaim_state": job.source_reclaim_state,
        "source_reclaim_at": (
            job.source_reclaim_at.isoformat() if job.source_reclaim_at else None
        ),
        "source_reclaim_reason": job.source_reclaim_reason or None,
        # §25 strand recovery — the state the job DIED in (which is what
        # says whether the KBS was ever moved to `Migrating{new_gen, dest}`)
        # and what was done about the VM it left fenced.
        "failed_from_state": job.failed_from_state or None,
        "strand_recovery_state": job.strand_recovery_state,
        "strand_recovery_at": (
            job.strand_recovery_at.isoformat() if job.strand_recovery_at else None
        ),
        "strand_recovery_reason": job.strand_recovery_reason or None,
        "snapshot_bucket": job.snapshot_bucket or None,
        "snapshot_key": job.snapshot_key or None,
        "quarantine_node_id": job.quarantine_node_id or None,
        "reason": job.reason or None,
        "decided_by": job.decided_by.name,
        "phase_started_at": job.phase_started_at.isoformat(),
        "started_at": job.started_at.isoformat(),
        "finished_at": job.finished_at.isoformat() if job.finished_at else None,
        "version": job.version,
    }


def _serialize_decommission(job: DecommissionJob) -> dict[str, Any]:
    """Render a `DecommissionJob`."""
    return {
        "job_id": job.job_id,
        "vm_id": job.vm.vm_id,
        "state": job.state,
        "eol_ack_verified": job.eol_ack_verified,
        "forced": job.forced,
        "quarantine_node_id": job.quarantine_node_id or None,
        "reason": job.reason or None,
        "decided_by": job.decided_by.name,
        "phase_started_at": job.phase_started_at.isoformat(),
        "started_at": job.started_at.isoformat(),
        "finished_at": job.finished_at.isoformat() if job.finished_at else None,
        "version": job.version,
        # What the erase step achieved for the data, once it ran (else
        # null): `crypto-erased`, or `customer-erase-required` for an M2
        # VM (Hippius held no disk key; only `guardian erase` crypto-erases).
        "data_death": job.data_death or None,
    }


def _error(http_status: int, message: str, category: str) -> Response:
    return Response({"error": message, "category": category}, status=http_status)


# ── Power operations — stop / start / reboot ──────────────────────────
#
# Same authorization as the other VM-mutating routes: authenticated AND the
# orchestration root principal. These do not change `Vm.state` (the KBS
# lifecycle gate) — they move `Vm.power_state`, a separate axis. See
# `services/power.py` for why the two must not be merged.


_POWER_ERROR_STATUS = {
    "vm-not-active": status.HTTP_409_CONFLICT,
    "already-stopping": status.HTTP_409_CONFLICT,
    "already-running": status.HTTP_409_CONFLICT,
    "already-starting": status.HTTP_409_CONFLICT,
    "start-in-flight": status.HTTP_409_CONFLICT,
    "no-bound-miner": status.HTTP_409_CONFLICT,
    "relaunch-rejected": status.HTTP_503_SERVICE_UNAVAILABLE,
    # transient: other starts held the §22 pin lock — re-ask the start
    "allowlist-pin-busy": status.HTTP_503_SERVICE_UNAVAILABLE,
    "disks-missing": status.HTTP_409_CONFLICT,
    "migration-in-flight": status.HTTP_409_CONFLICT,
    "resize-in-flight": status.HTTP_409_CONFLICT,
}


def _serialize_power(vm: Vm) -> dict:
    return {
        "vm_id": vm.vm_id,
        "state": vm.state,
        "power_state": vm.power_state,
        "power_state_at": vm.power_state_at,
        "host": vm.host,
    }


class _PowerOpView(APIView):
    """Shared plumbing for the three power routes."""

    # P2 object-level authorization: mutates a specific tenant's VM.
    object_scope = scoping.OPERATOR_ONLY

    permission_classes = [IsAuthenticated, IsOrchestrationRoot]
    http_method_names = ["post", "options"]

    #: `power.stop_vm` / `start_vm` / `reboot_vm`
    _op = None

    def post(self, request: Request, vm_id: str) -> Response:
        from apps.orchestration.effects import EffectError
        from apps.orchestration.services import power

        try:
            vm = Vm.objects.get(vm_id=vm_id)
        except Vm.DoesNotExist:
            return _error(status.HTTP_404_NOT_FOUND, "vm not found", "not-found")
        try:
            vm = self._op(vm)
        except power.PowerOpRefused as exc:
            return _error(
                _POWER_ERROR_STATUS.get(exc.reason, status.HTTP_409_CONFLICT),
                exc.detail,
                exc.reason,
            )
        except EffectError as exc:
            # The order did not reach the miner, or it refused. The VM is
            # left in its in-flight power state on purpose — see stop_vm.
            return _error(
                status.HTTP_503_SERVICE_UNAVAILABLE, str(exc), "miner-unreachable"
            )
        return Response(_serialize_power(vm), status=status.HTTP_200_OK)


class VmStopView(_PowerOpView):
    """`POST /v1/vm/<vm_id>/stop` — graceful stop; the reservation is kept."""

    @staticmethod
    def _op(vm):
        from apps.orchestration.services import power

        return power.stop_vm(vm)

    @extend_schema(
        summary="Stop a VM (graceful), keeping its reservation",
        description=(
            "Root-only. Issues the same signed graceful `stop` order §24 uses, "
            "then leaves everything in place: the encrypted overlay, the KEK, "
            "the anti-rollback counter and the slot on this miner all persist, "
            "so `start` can bring the VM back on the SAME host.\n\n"
            "`state` stays `active` — that is the KBS lifecycle gate, and a "
            "stopped VM must still be able to unlock when it restarts. Only "
            "`power_state` moves.\n\n"
            "The miner is NOT paid while stopped: accrual comes from "
            "guest-attested receipts and a stopped guest emits none."
        ),
        tags=["VM orchestration"],
        parameters=[_VM_ID_PARAM],
        request=None,
        responses={
            200: OpenApiResponse(description="Stopped; reservation held."),
            403: OpenApiResponse(ErrorSerializer, "Not the orchestration root principal."),
            404: OpenApiResponse(ErrorSerializer, "VM not found."),
            409: OpenApiResponse(ErrorSerializer, "Not active, or a power op is in flight."),
            503: OpenApiResponse(ErrorSerializer, "The miner could not be reached."),
        },
    )
    def post(self, request: Request, vm_id: str) -> Response:
        return super().post(request, vm_id)


class VmStartView(_PowerOpView):
    """`POST /v1/vm/<vm_id>/start` — relaunch on the same miner."""

    @staticmethod
    def _op(vm):
        from apps.orchestration.services import power

        return power.start_vm(vm)

    @extend_schema(
        summary="Start a stopped VM on its own miner",
        description=(
            "Root-only. Relaunches on the miner that holds this VM's overlay — "
            "never through the scheduler, which could place it on a host whose "
            "disk has no overlay. The existing KEK is re-released to the "
            "re-attested guest; no key is re-provisioned.\n\n"
            "Refused for a VM that has been migrated (`generation > 1`): a "
            "relaunch bakes generation 1, which the KBS anti-rollback fence "
            "declines, so the guest could never unlock. The overlay is intact "
            "— recover such a VM with a migration."
        ),
        tags=["VM orchestration"],
        parameters=[_VM_ID_PARAM],
        request=None,
        responses={
            200: OpenApiResponse(description="Started."),
            403: OpenApiResponse(ErrorSerializer, "Not the orchestration root principal."),
            404: OpenApiResponse(ErrorSerializer, "VM not found."),
            409: OpenApiResponse(ErrorSerializer, "Already running, or cannot be restarted."),
            503: OpenApiResponse(ErrorSerializer, "The miner refused the relaunch."),
        },
    )
    def post(self, request: Request, vm_id: str) -> Response:
        return super().post(request, vm_id)


class VmRebootView(_PowerOpView):
    """`POST /v1/vm/<vm_id>/reboot` — graceful stop, then relaunch."""

    @staticmethod
    def _op(vm):
        from apps.orchestration.services import power

        return power.reboot_vm(vm)

    @extend_schema(
        summary="Reboot a VM (stop, then start on the same miner)",
        description=(
            "Root-only. A guest can also reboot itself from inside — the "
            "domain survives and the miner-agent re-pushes the ticket. This "
            "route exists for when the guest is not cooperating."
        ),
        tags=["VM orchestration"],
        parameters=[_VM_ID_PARAM],
        request=None,
        responses={
            200: OpenApiResponse(description="Rebooted."),
            403: OpenApiResponse(ErrorSerializer, "Not the orchestration root principal."),
            404: OpenApiResponse(ErrorSerializer, "VM not found."),
            409: OpenApiResponse(ErrorSerializer, "Not active, or cannot be restarted."),
            503: OpenApiResponse(ErrorSerializer, "The miner could not be reached."),
        },
    )
    def post(self, request: Request, vm_id: str) -> Response:
        return super().post(request, vm_id)


class VmPowerPolicyView(APIView):
    """`PATCH /v1/vm/<vm_id>/power-policy` — the guest-poweroff policy."""

    object_scope = scoping.OPERATOR_ONLY
    permission_classes = [IsAuthenticated, IsOrchestrationRoot]
    http_method_names = ["patch", "options"]

    @extend_schema(
        summary="Set what happens when the guest powers itself off",
        description=(
            "Root-only. `on_guest_poweroff`: `restart` (start the VM again) or "
            "`stop` (leave it stopped, `stop_reason` `guest-poweroff`). A crash "
            "is restarted either way. Applied to the running instance through "
            "its miner — no relaunch; a stopped VM gets it with its next start. "
            "Until the miner acknowledges, the VM reads "
            "`on_guest_poweroff_pending: true` (`awaiting-ack`) and the order is "
            "re-sent.\n\n"
            "`stop` on a miner whose agent does not support it is refused with "
            "409 `power-policy-unsupported-on-host`."
        ),
        tags=["VM orchestration"],
        parameters=[_VM_ID_PARAM],
        request=PowerPolicyRequestSerializer,
        responses={
            200: PowerPolicySerializer,
            400: OpenApiResponse(ErrorSerializer, "Malformed body (`wire`/`bad-field`)."),
            403: OpenApiResponse(ErrorSerializer, "Not the orchestration root principal."),
            404: OpenApiResponse(ErrorSerializer, "VM not found."),
            409: OpenApiResponse(
                ErrorSerializer,
                "`power-policy-unsupported-on-host`, or the VM is not active.",
            ),
        },
    )
    def patch(self, request: Request, vm_id: str) -> Response:
        from apps.orchestration import power_policy

        body = request.data
        if not isinstance(body, dict):
            return _error(
                status.HTTP_400_BAD_REQUEST, "request body must be a JSON object", "wire"
            )
        unknown = sorted(set(body) - {"on_guest_poweroff"})
        if unknown:
            return _error(
                status.HTTP_400_BAD_REQUEST, f"unknown field(s): {', '.join(unknown)}", "wire"
            )
        try:
            policy = power_policy.parse_policy(body.get("on_guest_poweroff"))
        except ValueError as exc:
            return _error(status.HTTP_400_BAD_REQUEST, str(exc), "bad-field")
        try:
            vm = Vm.objects.get(vm_id=vm_id)
        except Vm.DoesNotExist:
            return _error(status.HTTP_404_NOT_FOUND, "vm not found", "not-found")
        try:
            vm = power_policy.change(vm, policy)
        except power_policy.PowerPolicyRefused as exc:
            return _error(status.HTTP_409_CONFLICT, exc.detail, exc.reason)
        return Response(
            {"vm_id": vm.vm_id, **power_policy.view(vm)}, status=status.HTTP_200_OK
        )
