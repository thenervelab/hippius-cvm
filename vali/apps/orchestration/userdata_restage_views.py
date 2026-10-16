"""Userdata restage endpoints (`apps.orchestration.userdata_restage`). Root-only
(`IsOrchestrationRoot`, `OPERATOR_ONLY`), behind `VALI_USERDATA_RESTAGE_ENABLED`
and the per-VM `VALI_USERDATA_RESTAGE_VM_ALLOWLIST`.

  POST /v1/vm/<vm_id>/userdata/restage            restage, roll back, or revert the last
  GET  /v1/vm/<vm_id>/userdata/restage/<job_id>   one restage job

`/v1/vm` is published as a PREFIX on the public Ingress, so these routes are
reachable from outside: the root-only gate is what keeps them closed (pinned
by `test_userdata_restage_api`).

Refusals answer `{"error": <text>, "category": <stable slug>}` like the
other orchestration routes. No answer, log line or audit entry carries the
userdata: only its size and sha256.
"""

from __future__ import annotations

import re
from typing import Any

from drf_spectacular.utils import OpenApiParameter, OpenApiResponse, extend_schema
from rest_framework import serializers, status
from rest_framework.permissions import IsAuthenticated
from rest_framework.request import Request
from rest_framework.response import Response
from rest_framework.views import APIView

from apps.common.schemas import ErrorSerializer
from apps.identity import scoping
from apps.lifecycle.models import Vm

from . import userdata_restage as restage
from .models import UserdataRestageJob, UserdataRestagePhase
from .permissions import IsOrchestrationRoot

_TAGS = ["VM orchestration"]
_VM_ID_PARAM = OpenApiParameter("vm_id", str, OpenApiParameter.PATH, description="Target VM id.")
_JOB_ID_PARAM = OpenApiParameter(
    "job_id", str, OpenApiParameter.PATH, description="Job id returned by the restage call."
)
_REQUEST_ID_RE = re.compile(r"[A-Za-z0-9._:-]{1,128}")


class RestageRequestSerializer(serializers.Serializer):
    userdata_b64 = serializers.CharField(
        required=False,
        help_text="The COMPLETE new cloud-init userdata, base64. Stored and delivered "
        "byte for byte: no token is required or substituted.",
    )
    rollback_to_version = serializers.IntegerField(
        required=False,
        help_text="Instead of new bytes: point back at this version of the VM's intake template.",
    )
    revert_last = serializers.BooleanField(
        required=False,
        help_text="Instead of new bytes: put back the pointer the latest restage replaced "
        "(legacy paths included).",
    )
    dry_run = serializers.BooleanField(required=False, default=True)
    request_id = serializers.CharField(
        help_text="Idempotency key: replaying it names the same job. `[A-Za-z0-9._:-]{1,128}`."
    )


class RestageDryRunSerializer(serializers.Serializer):
    dry_run = serializers.BooleanField()
    vm_id = serializers.CharField()
    kind = serializers.CharField()
    size = serializers.IntegerField(allow_null=True)
    digest_hex = serializers.CharField(allow_null=True, help_text="sha256 of the userdata.")
    current_path = serializers.CharField()
    current_version = serializers.IntegerField()
    would_be_path = serializers.CharField()
    would_be_version = serializers.IntegerField()
    checks = serializers.DictField(child=serializers.CharField())


class RestageJobSerializer(serializers.Serializer):
    job_id = serializers.CharField()
    vm_id = serializers.CharField()
    request_id = serializers.CharField()
    kind = serializers.CharField()
    phase = serializers.ChoiceField(choices=UserdataRestagePhase.values)
    outcome = serializers.CharField(allow_null=True)
    from_path = serializers.CharField()
    from_version = serializers.IntegerField()
    to_path = serializers.CharField()
    to_version = serializers.IntegerField()
    size = serializers.IntegerField(allow_null=True)
    digest_hex = serializers.CharField(allow_null=True)
    decided_by = serializers.CharField()
    started_at = serializers.DateTimeField()
    finished_at = serializers.DateTimeField(allow_null=True)
    error = serializers.CharField(required=False)


def _error(http_status: int, message: str, category: str) -> Response:
    return Response({"error": message, "category": category}, status=http_status)


def serialize_job(job: UserdataRestageJob) -> dict[str, Any]:
    body: dict[str, Any] = {
        "job_id": job.job_id,
        "vm_id": job.vm.vm_id,
        "request_id": job.request_id,
        "kind": job.kind,
        "phase": job.phase,
        "outcome": job.outcome or None,
        "from_path": job.from_path,
        "from_version": job.from_version,
        "to_path": job.to_path,
        "to_version": job.to_version,
        "size": job.size,
        "digest_hex": job.digest_hex or None,
        "decided_by": job.decided_by.name,
        "started_at": job.started_at.isoformat(),
        "finished_at": job.finished_at.isoformat() if job.finished_at else None,
    }
    if job.error:
        body["error"] = job.error
    return body


class _RootView(APIView):
    object_scope = scoping.OPERATOR_ONLY
    permission_classes = [IsAuthenticated, IsOrchestrationRoot]


class VmUserdataRestageView(_RootView):
    """`POST /v1/vm/<vm_id>/userdata/restage`."""

    http_method_names = ["post", "options"]

    @extend_schema(
        summary="Restage an M0 VM's cloud-init userdata (or roll it back) and relaunch it",
        description=(
            "Root-only, behind `VALI_USERDATA_RESTAGE_ENABLED` and the per-VM allow-list. "
            "`dry_run` (the default) checks everything and writes nothing. Otherwise the "
            "new version is staged (Transit-wrapped, delivered byte for byte at the next "
            "boot) and the launch record pointed at it in this request, and "
            "`vali_orchestration_tick` relaunches the VM. `rollback_to_version` re-points "
            "instead of staging. Replaying a `request_id` returns its job."
        ),
        tags=_TAGS,
        parameters=[_VM_ID_PARAM],
        request=RestageRequestSerializer,
        responses={
            200: RestageDryRunSerializer,
            202: RestageJobSerializer,
            400: OpenApiResponse(ErrorSerializer, "Bad body / malformed base64 / bad userdata."),
            403: OpenApiResponse(
                ErrorSerializer,
                "Not the root principal / `userdata-restage-disabled` / "
                "`userdata-restage-not-allowed`.",
            ),
            404: OpenApiResponse(ErrorSerializer, "VM not found."),
            409: OpenApiResponse(
                ErrorSerializer,
                "`vm-not-restageable` / `userdata-restage-unsupported-key-mode` / "
                "`rollback-unavailable` / `request-id-reused`.",
            ),
            413: OpenApiResponse(ErrorSerializer, "`userdata-too-large`."),
        },
    )
    def post(self, request: Request, vm_id: str) -> Response:
        try:
            restage.check_api_gates(vm_id)
            return self._post(request, vm_id)
        except restage.RestageRefused as exc:
            return _error(exc.http_status, exc.message, exc.category)

    def _post(self, request: Request, vm_id: str) -> Response:
        body = request.data if isinstance(request.data, dict) else None
        if body is None:
            return _error(status.HTTP_400_BAD_REQUEST, "body must be a JSON object", "wire")
        request_id = body.get("request_id")
        if not isinstance(request_id, str) or not _REQUEST_ID_RE.fullmatch(request_id):
            return _error(
                status.HTTP_400_BAD_REQUEST,
                "request_id must match [A-Za-z0-9._:-]{1,128}",
                "wire",
            )
        dry_run = body.get("dry_run", True)
        if not isinstance(dry_run, bool):
            return _error(status.HTTP_400_BAD_REQUEST, "dry_run must be a boolean", "wire")
        has_ud = "userdata_b64" in body
        has_rb = "rollback_to_version" in body
        revert_last = body.get("revert_last", False)
        if not isinstance(revert_last, bool):
            return _error(status.HTTP_400_BAD_REQUEST, "revert_last must be a boolean", "wire")
        if [has_ud, has_rb, revert_last].count(True) != 1:
            return _error(
                status.HTTP_400_BAD_REQUEST,
                "exactly one of userdata_b64 / rollback_to_version / revert_last",
                "wire",
            )
        rollback_to = body.get("rollback_to_version")
        if has_rb and (
            not isinstance(rollback_to, int) or isinstance(rollback_to, bool) or rollback_to <= 0
        ):
            return _error(
                status.HTTP_400_BAD_REQUEST,
                "rollback_to_version must be a positive integer",
                "wire",
            )
        userdata = restage.decode_userdata_b64(body.get("userdata_b64")) if has_ud else b""
        try:
            return self._apply(
                request, vm_id, userdata, rollback_to, request_id, dry_run, revert_last
            )
        finally:
            userdata = b"\x00" * len(userdata)

    def _apply(
        self,
        request: Request,
        vm_id: str,
        userdata: bytes,
        rollback_to: int | None,
        request_id: str,
        dry_run: bool,
        revert_last: bool,
    ) -> Response:
        vm = Vm.objects.filter(vm_id=vm_id).first()
        if vm is None:
            return _error(status.HTTP_404_NOT_FOUND, "vm not found", "not-found")
        if revert_last:
            kind = restage.KIND_REVERT
        elif rollback_to is not None:
            kind = restage.KIND_ROLLBACK
        else:
            kind = restage.KIND_RESTAGE
        if dry_run:
            if kind == restage.KIND_RESTAGE:
                plan = restage.plan_restage(vm, userdata)
            elif kind == restage.KIND_REVERT:
                plan = restage.plan_rollback(vm, revert_last=True)
            else:
                plan = restage.plan_rollback(vm, to_version=rollback_to)
            checks = {
                "feature": "enabled",
                "allowlist": "listed",
                "key_mode": "M0",
                "vm": f"{vm.state}/{vm.power_state}",
                "in_flight": "none",
                "launch_record": plan.job_id,
            }
            if plan.size is not None:
                checks["size"] = f"{plan.size}<={restage.userdata_cap()}"
            return Response(
                {
                    "dry_run": True,
                    "vm_id": vm.vm_id,
                    "kind": kind,
                    "size": plan.size,
                    "digest_hex": plan.digest_hex or None,
                    "current_path": plan.from_path,
                    "current_version": plan.from_version,
                    "would_be_path": plan.to_path,
                    "would_be_version": plan.would_be_version,
                    "checks": checks,
                },
                status=status.HTTP_200_OK,
            )
        job = restage.start_job(
            vm,
            kind=kind,
            userdata=userdata,
            rollback_to_version=rollback_to,
            request_id=request_id,
            decided_by=request.user,
        )
        return Response(serialize_job(job), status=status.HTTP_202_ACCEPTED)


class VmUserdataRestageJobView(_RootView):
    """`GET /v1/vm/<vm_id>/userdata/restage/<job_id>`."""

    http_method_names = ["get", "options"]

    @extend_schema(
        summary="Poll a userdata restage job",
        tags=_TAGS,
        parameters=[_VM_ID_PARAM, _JOB_ID_PARAM],
        responses={
            200: RestageJobSerializer,
            403: OpenApiResponse(ErrorSerializer, "Not the orchestration root principal."),
            404: OpenApiResponse(ErrorSerializer, "Restage job not found."),
        },
    )
    def get(self, request: Request, vm_id: str, job_id: str) -> Response:
        job = (
            UserdataRestageJob.objects.filter(vm__vm_id=vm_id, job_id=job_id)
            .select_related("vm", "decided_by")
            .first()
        )
        if job is None:
            return _error(status.HTTP_404_NOT_FOUND, "restage job not found", "not-found")
        return Response(serialize_job(job), status=status.HTTP_200_OK)
