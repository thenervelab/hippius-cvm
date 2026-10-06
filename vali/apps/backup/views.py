"""Backup endpoints. Root-only (`IsOrchestrationRoot`, `OPERATOR_ONLY`),
like the public-IP routes: the layer above sells the option and bills it.

  GET|PUT|DELETE /v1/vm/<vm_id>/backup-policy
  GET            /v1/vm/<vm_id>/backups

Refusals answer `{"error": <stable code>, "detail": <text>}`.
"""

from __future__ import annotations

from typing import Any

from drf_spectacular.utils import OpenApiParameter, OpenApiResponse, extend_schema
from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from rest_framework.request import Request
from rest_framework.response import Response
from rest_framework.views import APIView

from apps.identity import scoping
from apps.lifecycle.models import Vm
from apps.orchestration.permissions import IsOrchestrationRoot

from . import service
from .models import FailoverMode
from .schemas import (
    BackupErrorSerializer,
    BackupPolicyRequestSerializer,
    BackupPolicySerializer,
    BackupsSerializer,
)
from .service import BackupError

_TAGS = ["Backups"]

_ERROR_STATUS = {
    "vm-not-found": status.HTTP_404_NOT_FOUND,
    "no-backup-policy": status.HTTP_404_NOT_FOUND,
    "not-golden": status.HTTP_409_CONFLICT,
    "disk-too-large": status.HTTP_409_CONFLICT,
    "no-launch-record": status.HTTP_409_CONFLICT,
    "vm-not-live": status.HTTP_409_CONFLICT,
    "backup-unavailable": status.HTTP_503_SERVICE_UNAVAILABLE,
}


def _refuse(exc: BackupError) -> Response:
    return Response(
        {"error": exc.code, "detail": exc.detail},
        status=_ERROR_STATUS.get(exc.code, status.HTTP_400_BAD_REQUEST),
    )


def _get_vm(vm_id: str) -> Vm:
    vm = Vm.objects.filter(vm_id=vm_id).first()
    if vm is None:
        raise BackupError("vm-not-found", "vm not found")
    return vm


def _body(request: Request) -> dict[str, Any]:
    data = request.data
    if not isinstance(data, dict):
        raise BackupError("bad-request", "body must be a JSON object")
    unknown = set(data) - {"interval_s", "retention_days", "failover_mode"}
    if unknown:
        raise BackupError("bad-request", f"unknown field(s): {', '.join(sorted(unknown))}")
    return data


class _RootView(APIView):
    # A tenant VM's backups and the policy that drives them — root only.
    object_scope = scoping.OPERATOR_ONLY
    permission_classes = [IsAuthenticated, IsOrchestrationRoot]


_VM_ID = OpenApiParameter("vm_id", str, OpenApiParameter.PATH)
_COMMON = {
    403: OpenApiResponse(BackupErrorSerializer, "Not the orchestration root principal."),
}


class VmBackupPolicyView(_RootView):
    """`/v1/vm/<vm_id>/backup-policy` — read, set, remove."""

    http_method_names = ["get", "put", "delete", "options"]

    @extend_schema(
        summary="The VM's backup policy",
        tags=_TAGS,
        parameters=[_VM_ID],
        responses={
            200: BackupPolicySerializer,
            404: OpenApiResponse(BackupErrorSerializer, "`vm-not-found` / `no-backup-policy`."),
            **_COMMON,
        },
    )
    def get(self, request: Request, vm_id: str) -> Response:
        try:
            policy = service.get_policy(_get_vm(vm_id))
        except BackupError as exc:
            return _refuse(exc)
        return Response(service.policy_view(policy))

    @extend_schema(
        summary="Back the VM up on a schedule",
        description=(
            "Creates or replaces the policy. The first backup is a full copy of the "
            "VM's disk, taken while it runs; later ones copy only what changed. Every "
            "reboot of the VM makes the earlier backups unrestorable, so a new full "
            "backup follows each boot. Backups are crash-consistent. Golden-image VMs "
            "only."
        ),
        tags=_TAGS,
        parameters=[_VM_ID],
        request=BackupPolicyRequestSerializer,
        responses={
            200: OpenApiResponse(BackupPolicySerializer, "Updated."),
            201: OpenApiResponse(BackupPolicySerializer, "Created (or re-enabled)."),
            400: OpenApiResponse(
                BackupErrorSerializer, "`bad-interval` / `bad-retention` / `bad-failover-mode`."
            ),
            404: OpenApiResponse(BackupErrorSerializer, "`vm-not-found`."),
            409: OpenApiResponse(
                BackupErrorSerializer,
                "`not-golden` / `disk-too-large` / `no-launch-record` / `vm-not-live`.",
            ),
            503: OpenApiResponse(BackupErrorSerializer, "`backup-unavailable`."),
            **_COMMON,
        },
    )
    def put(self, request: Request, vm_id: str) -> Response:
        try:
            body = _body(request)
            policy, created = service.put_policy(
                _get_vm(vm_id),
                interval_s=body.get("interval_s"),
                retention_days=body.get("retention_days", service.DEFAULT_RETENTION_DAYS),
                failover_mode=body.get("failover_mode", FailoverMode.AUTO.value),
            )
        except BackupError as exc:
            return _refuse(exc)
        return Response(
            service.policy_view(policy),
            status=status.HTTP_201_CREATED if created else status.HTTP_200_OK,
        )

    @extend_schema(
        summary="Stop backing the VM up",
        description=(
            "No new backup is taken. Existing backups are kept for the policy's "
            "`retention_days`, then deleted."
        ),
        tags=_TAGS,
        parameters=[_VM_ID],
        request=None,
        responses={
            204: OpenApiResponse(description="Disabled."),
            404: OpenApiResponse(BackupErrorSerializer, "`vm-not-found` / `no-backup-policy`."),
            **_COMMON,
        },
    )
    def delete(self, request: Request, vm_id: str) -> Response:
        try:
            service.disable_policy(_get_vm(vm_id))
        except BackupError as exc:
            return _refuse(exc)
        return Response(status=status.HTTP_204_NO_CONTENT)


class VmBackupsView(_RootView):
    """`/v1/vm/<vm_id>/backups` — restore points, chains and stored bytes."""

    http_method_names = ["get", "options"]

    @extend_schema(
        summary="The VM's backups",
        description=(
            "The backup state, the newest restorable backup, every chain still held "
            "and the bytes stored (for billing)."
        ),
        tags=_TAGS,
        parameters=[_VM_ID],
        responses={
            200: BackupsSerializer,
            404: OpenApiResponse(BackupErrorSerializer, "`vm-not-found`."),
            **_COMMON,
        },
    )
    def get(self, request: Request, vm_id: str) -> Response:
        try:
            vm = _get_vm(vm_id)
        except BackupError as exc:
            return _refuse(exc)
        return Response(service.backups_view(vm))
