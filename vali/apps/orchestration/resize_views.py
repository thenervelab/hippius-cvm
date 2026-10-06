"""VM resize endpoints (`apps.orchestration.resize`). Root-only
(`IsOrchestrationRoot`, `OPERATOR_ONLY`): the layer above offers resizes to
its tenants and decides who may ask.

  GET  /v1/vm/<vm_id>/resize/flavors     the flavors this VM can be resized to
  POST /v1/vm/<vm_id>/resize             start a resize  {"flavor": "<name>"}
  GET  /v1/vm/<vm_id>/resize             the VM's latest resize job
  GET  /v1/vm/<vm_id>/resize/<job_id>    one resize job

Refusals answer `{"error": <text>, "category": <stable slug>}` like the
other orchestration routes.
"""

from __future__ import annotations

from dataclasses import asdict
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

from . import resize
from .models import ResizeJob
from .permissions import IsOrchestrationRoot
from .schemas import (
    ResizeFlavorsSerializer,
    ResizeJobSerializer,
    ResizeStartRequestSerializer,
)
from .service import StartError

_TAGS = ["VM orchestration"]

_VM_ID_PARAM = OpenApiParameter("vm_id", str, OpenApiParameter.PATH, description="Target VM id.")
_JOB_ID_PARAM = OpenApiParameter(
    "job_id", str, OpenApiParameter.PATH, description="Job id returned by the start call."
)

#: The refusals that are the CALLER's request (400); every other one is
#: the VM's or the fleet's state right now (409).
_BAD_REQUEST = frozenset({"wire", "unknown-flavor", "flavor-not-offered", "same-flavor"})


def _error(http_status: int, message: str, category: str) -> Response:
    return Response({"error": message, "category": category}, status=http_status)


def _refusal(exc: StartError) -> Response:
    code = status.HTTP_400_BAD_REQUEST if exc.category in _BAD_REQUEST else status.HTTP_409_CONFLICT
    return _error(code, exc.message, exc.category)


def serialize_resize(job: ResizeJob) -> dict[str, Any]:
    return {
        "job_id": job.job_id,
        "vm_id": job.vm.vm_id,
        "from_flavor": job.from_flavor,
        "to_flavor": job.to_flavor,
        "state": job.state,
        "node_id": job.node_id,
        "prior_power_state": job.prior_power_state,
        "migration_job_id": job.migration_job.job_id if job.migration_job_id else None,
        "reserved": job.reserved,
        "relaunched_at": job.relaunched_at.isoformat() if job.relaunched_at else None,
        "rolled_back": job.rolled_back,
        "reason": job.reason or None,
        "decided_by": job.decided_by.name,
        "phase_started_at": job.phase_started_at.isoformat(),
        "started_at": job.started_at.isoformat(),
        "finished_at": job.finished_at.isoformat() if job.finished_at else None,
        "version": job.version,
    }


class _RootView(APIView):
    object_scope = scoping.OPERATOR_ONLY
    permission_classes = [IsAuthenticated, IsOrchestrationRoot]


class VmResizeFlavorsView(_RootView):
    """`GET /v1/vm/<vm_id>/resize/flavors`."""

    http_method_names = ["get", "options"]

    @extend_schema(
        summary="Flavors a VM can be resized to",
        description=(
            "Root-only. Every offered flavor but the current one is listed; only its "
            "vCPU/RAM apply — the VM keeps its own data disk (`data_disk_size_gb`), "
            "which cannot be resized. Each says whether a resize to it "
            "would be admitted now (`available`), and whether it fits on the VM's own "
            "miner or needs a migration. `blocked` names why no resize can start at "
            "all right now (a job in flight, a power operation settling)."
        ),
        tags=_TAGS,
        parameters=[_VM_ID_PARAM],
        responses={
            200: ResizeFlavorsSerializer,
            403: OpenApiResponse(ErrorSerializer, "Not the orchestration root principal."),
            404: OpenApiResponse(ErrorSerializer, "VM not found."),
        },
    )
    def get(self, request: Request, vm_id: str) -> Response:
        vm = Vm.objects.filter(vm_id=vm_id).first()
        if vm is None:
            return _error(status.HTTP_404_NOT_FOUND, "vm not found", "not-found")
        answer = resize.compatible_flavors(vm)
        body = asdict(answer)
        body["current_flavor"] = answer.current_flavor or None
        body["blocked"] = answer.blocked or None
        for option in body["options"]:
            option["reason"] = option["reason"] or None
        return Response(body, status=status.HTTP_200_OK)


class VmResizeView(_RootView):
    """`POST /v1/vm/<vm_id>/resize` + `GET` (the latest job)."""

    http_method_names = ["get", "post", "options"]

    @extend_schema(
        summary="Resize a VM (vCPU/RAM; the data disk is unchanged)",
        description=(
            "Root-only. Admits the resize synchronously — every refusal happens here, "
            "before anything moves — and returns the job (`pending`); "
            "`vali_orchestration_tick` drives it: a running VM is stopped and "
            "relaunched at the new size on its own miner (or migrated first when the "
            "size does not fit there), a stopped VM is resized on the books and stays "
            "stopped. A failure before the new-size relaunch puts the VM back as it was."
        ),
        tags=_TAGS,
        parameters=[_VM_ID_PARAM],
        request=ResizeStartRequestSerializer,
        responses={
            202: ResizeJobSerializer,
            400: OpenApiResponse(
                ErrorSerializer,
                "Bad body / unknown, unoffered or same flavor.",
            ),
            403: OpenApiResponse(ErrorSerializer, "Not the orchestration root principal."),
            404: OpenApiResponse(ErrorSerializer, "VM not found."),
            409: OpenApiResponse(
                ErrorSerializer,
                "VM not active / job or power operation in flight / `resize-no-capacity`.",
            ),
        },
    )
    def post(self, request: Request, vm_id: str) -> Response:
        body = request.data
        flavor = body.get("flavor") if isinstance(body, dict) else None
        if not isinstance(flavor, str) or not flavor.strip() or len(flavor) > 32:
            return _error(status.HTTP_400_BAD_REQUEST, "flavor must be a non-empty string", "wire")
        vm = Vm.objects.filter(vm_id=vm_id).first()
        if vm is None:
            return _error(status.HTTP_404_NOT_FOUND, "vm not found", "not-found")
        try:
            job = resize.start_resize(
                vm=vm, to_flavor=flavor.strip().lower(), decided_by=request.user
            )
        except StartError as exc:
            return _refusal(exc)
        return Response(serialize_resize(job), status=status.HTTP_202_ACCEPTED)

    @extend_schema(
        summary="The VM's latest resize job",
        tags=_TAGS,
        parameters=[_VM_ID_PARAM],
        responses={
            200: ResizeJobSerializer,
            404: OpenApiResponse(ErrorSerializer, "VM not found, or never resized."),
        },
    )
    def get(self, request: Request, vm_id: str) -> Response:
        job = (
            ResizeJob.objects.filter(vm__vm_id=vm_id)
            .select_related("vm", "decided_by", "migration_job")
            .order_by("-started_at")
            .first()
        )
        if job is None:
            return _error(status.HTTP_404_NOT_FOUND, "no resize job", "not-found")
        return Response(serialize_resize(job), status=status.HTTP_200_OK)


class VmResizeJobView(_RootView):
    """`GET /v1/vm/<vm_id>/resize/<job_id>`."""

    http_method_names = ["get", "options"]

    @extend_schema(
        summary="Poll a resize job",
        tags=_TAGS,
        parameters=[_VM_ID_PARAM, _JOB_ID_PARAM],
        responses={
            200: ResizeJobSerializer,
            404: OpenApiResponse(ErrorSerializer, "Resize job not found."),
        },
    )
    def get(self, request: Request, vm_id: str, job_id: str) -> Response:
        job = (
            ResizeJob.objects.filter(vm__vm_id=vm_id, job_id=job_id)
            .select_related("vm", "decided_by", "migration_job")
            .first()
        )
        if job is None:
            return _error(status.HTTP_404_NOT_FOUND, "resize job not found", "not-found")
        return Response(serialize_resize(job), status=status.HTTP_200_OK)
