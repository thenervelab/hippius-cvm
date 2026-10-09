"""Restore endpoints. Root-only (`IsOrchestrationRoot`, `OPERATOR_ONLY`),
like the backup routes: the layer above offers restores to its tenants.

  POST /v1/vm/<vm_id>/restore                    open a restore job
  GET  /v1/vm/<vm_id>/restore                    the latest one
  GET  /v1/vm/<vm_id>/restore/<job_id>           one job
  POST /v1/vm/<vm_id>/restore/<job_id>/cancel    staging / stopping only
  POST /v1/vm/<vm_id>/restore/<job_id>/revert    put the ORIGINAL back after
                                                 the commit point (superuser)
  POST /v1/vm/<vm_id>/failover                   manual failover off a dead miner

Refusals answer `{"error": <stable code>, "detail": <text>}`.
"""

from __future__ import annotations

from typing import Any

from drf_spectacular.utils import OpenApiParameter, OpenApiResponse, extend_schema
from rest_framework import serializers, status
from rest_framework.permissions import IsAuthenticated
from rest_framework.request import Request
from rest_framework.response import Response
from rest_framework.views import APIView

from apps.identity import scoping
from apps.lifecycle.models import Vm

from . import restore
from .models import MigrationJob
from .permissions import IsOrchestrationRoot
from .restore import RestoreError

_TAGS = ["Backups"]

_ERROR_STATUS = {
    "bad-request": status.HTTP_400_BAD_REQUEST,
    "vm-not-found": status.HTTP_404_NOT_FOUND,
    "no-restore": status.HTTP_404_NOT_FOUND,
    "point-not-restorable": status.HTTP_409_CONFLICT,
    "no-backup-point": status.HTTP_409_CONFLICT,
    "rollback-unsupported": status.HTTP_409_CONFLICT,
    "rollback-not-accepted": status.HTTP_409_CONFLICT,
    "rollback-no-checkpoint": status.HTTP_409_CONFLICT,
    "rollback-not-capable": status.HTTP_409_CONFLICT,
    "customer-rollback-authorization-required": status.HTTP_409_CONFLICT,
    "on-behalf-of-required": status.HTTP_400_BAD_REQUEST,
    "rollback-rate-limited": status.HTTP_429_TOO_MANY_REQUESTS,
    "job-in-flight": status.HTTP_409_CONFLICT,
    "vm-not-restorable": status.HTTP_409_CONFLICT,
    "no-eligible-miner": status.HTTP_409_CONFLICT,
    "request-id-conflict": status.HTTP_409_CONFLICT,
    "not-cancellable": status.HTTP_409_CONFLICT,
    "revert-superuser-only": status.HTTP_403_FORBIDDEN,
    "revert-not-applicable": status.HTTP_409_CONFLICT,
    "revert-cross-host-unsupported": status.HTTP_409_CONFLICT,
    "revert-no-checkpoint": status.HTTP_409_CONFLICT,
    "revert-not-ready": status.HTTP_409_CONFLICT,
    "miner-not-dead": status.HTTP_409_CONFLICT,
    "restore-disabled": status.HTTP_503_SERVICE_UNAVAILABLE,
    "failover-disabled": status.HTTP_503_SERVICE_UNAVAILABLE,
    "restore-unavailable": status.HTTP_503_SERVICE_UNAVAILABLE,
}

_BODY_FIELDS = frozenset(
    {
        "run_id",
        "request_id",
        "dest_node_id",
        "accept_rollback",
        "on_behalf_of",
        "customer_authorized",
    }
)
#: An undo names only who asked (a superuser).
_REVERT_FIELDS = frozenset({"on_behalf_of"})
#: A failover never rolls back: it takes neither rollback field.
_FAILOVER_FIELDS = frozenset({"run_id", "request_id", "dest_node_id"})


class RestoreErrorSerializer(serializers.Serializer):
    error = serializers.CharField(help_text="Stable refusal code, e.g. `point-not-restorable`.")
    detail = serializers.CharField()


class OnBehalfOfSerializer(serializers.Serializer):
    kind = serializers.ChoiceField(choices=["tenant", "superuser"])
    id = serializers.CharField()


class RollbackViewSerializer(serializers.Serializer):
    from_boot_counter = serializers.IntegerField(allow_null=True)
    to_boot_counter = serializers.IntegerField()
    point_taken_at = serializers.DateTimeField()
    requested_by = OnBehalfOfSerializer()
    committed_at = serializers.DateTimeField(
        allow_null=True, help_text="When the KBS consumed the rollback; null until then."
    )


class UndoViewSerializer(serializers.Serializer):
    requested_by = OnBehalfOfSerializer()
    requested_at = serializers.DateTimeField()
    outcome = serializers.ChoiceField(choices=["pending", "done", "failed"])
    reason = serializers.CharField(allow_null=True)
    generation = serializers.IntegerField(help_text="The generation the original relaunches at.")
    rolled_back = serializers.BooleanField(
        allow_null=True,
        help_text=(
            "true: the KBS was armed for a rollback to the original; false: the KBS "
            "counter never moved past the original (no rollback needed); null: not "
            "asked yet."
        ),
    )
    committed_at = serializers.DateTimeField(allow_null=True)


class RevertRequestSerializer(serializers.Serializer):
    on_behalf_of = OnBehalfOfSerializer(help_text="`{kind: superuser, id}` — operator only.")


class RestoreRequestSerializer(serializers.Serializer):
    run_id = serializers.CharField(help_text="The backup run to restore (`GET .../backups`).")
    request_id = serializers.CharField(
        help_text="Idempotency key: the same request_id returns the same job."
    )
    dest_node_id = serializers.CharField(
        required=False,
        help_text="Restore onto this miner instead of the VM's current host.",
    )
    accept_rollback = serializers.BooleanField(
        required=False,
        help_text=(
            "Required (true) to restore a point of an EARLIER boot (`point.class` "
            "`rollback`): the tenant accepted going back past a reboot."
        ),
    )
    on_behalf_of = OnBehalfOfSerializer(
        required=False,
        help_text="Who asked (required for a rollback point); recorded and audited.",
    )
    customer_authorized = serializers.BooleanField(
        required=False,
        help_text=(
            "M2 (`key_mode=customer`) VMs only: the customer ran `guardian "
            "authorize-rollback` for this point on their key guardian. A rollback "
            "of an M2 VM is refused `customer-rollback-authorization-required` "
            "without it; vali never asks the KBS to authorize one."
        ),
    )


class FailoverRequestSerializer(serializers.Serializer):
    request_id = serializers.CharField(
        help_text="Idempotency key: the same request_id returns the same job."
    )
    run_id = serializers.CharField(
        required=False, help_text="The point to restore; the newest current-boot one if absent."
    )
    dest_node_id = serializers.CharField(
        required=False, help_text="The miner to fail over to; chosen by vali if absent."
    )


class MinerNotDeadSerializer(serializers.Serializer):
    error = serializers.CharField(help_text="`miner-not-dead`.")
    detail = serializers.CharField()
    evidence = serializers.DictField(
        help_text="Heartbeat, NetBird peer and Edge reachability as checked."
    )


class DeadMinerEvidenceSerializer(serializers.Serializer):
    heartbeat_silent_s = serializers.IntegerField(allow_null=True)
    netbird_silent_s = serializers.IntegerField(allow_null=True)
    edge_unreachable = serializers.BooleanField()


class RestoreJobSerializer(serializers.Serializer):
    job_id = serializers.CharField()
    vm_id = serializers.CharField()
    kind = serializers.ChoiceField(choices=["restore", "failover"])
    failover_id = serializers.CharField(
        allow_null=True, help_text="The job id, for a failover; null for a restore."
    )
    trigger = serializers.ChoiceField(
        choices=["operator", "auto"],
        help_text="`auto`: opened by the automatic failover worker.",
    )
    outcome = serializers.ChoiceField(
        choices=["committed", "reverted", "failed", "cancelled"],
        allow_null=True,
        help_text="Null while the job runs.",
    )
    started_at = serializers.DateTimeField()
    committed_at = serializers.DateTimeField(
        allow_null=True,
        help_text="The commit point: the restored guest's first key release, proven.",
    )
    restored_point_at = serializers.DateTimeField(
        allow_null=True, help_text="When the restored backup point was taken."
    )
    dead_miner_evidence = DeadMinerEvidenceSerializer(
        allow_null=True,
        help_text="A failover's dead-miner proof (the re-check before the fence when made).",
    )
    run_id = serializers.CharField(allow_null=True)
    chain_id = serializers.CharField(allow_null=True)
    point_taken_at = serializers.DateTimeField(allow_null=True)
    phase = serializers.ChoiceField(
        choices=[
            "pending_capacity",
            "staging",
            "stopping",
            "activating",
            "verifying",
            "settling",
            "done",
            "failed",
            "reverted",
        ],
        help_text=(
            "`pending_capacity`: an automatic failover waiting for a destination "
            "with room (retried every tick). "
            "`verifying`: the restored disk booted, waiting for its key release "
            "to be proven. `settling`: returning to a stopped prior power state. "
            "`reverted`: failed before the point of no return, the original is "
            "back as it was. `failed`: a staging failure (the original was never "
            "touched, the reason starts with `stage-`) or a failure after the "
            "point of no return (the original disk is kept)."
        ),
    )
    pct = serializers.IntegerField(allow_null=True, help_text="Staging progress, null outside it.")
    reason = serializers.CharField(allow_null=True)
    reverted = serializers.BooleanField()
    prior_power_state = serializers.ChoiceField(choices=["running", "stopped"])
    source_node_id = serializers.CharField()
    dest_node_id = serializers.CharField()
    eta_s = serializers.IntegerField(allow_null=True)
    rollback = RollbackViewSerializer(
        allow_null=True, help_text="Set for a restore to a point of an earlier boot."
    )
    undo = UndoViewSerializer(
        allow_null=True,
        help_text="Set once an operator asked to put the original back (`.../revert`).",
    )
    created_at = serializers.DateTimeField()
    finished_at = serializers.DateTimeField(allow_null=True)


class RestoreJobListSerializer(serializers.Serializer):
    jobs = RestoreJobSerializer(many=True)


_LIST_DEFAULT = 20
_LIST_MAX = 100


def _limit(raw: Any) -> int:
    if raw in (None, ""):
        return _LIST_DEFAULT
    try:
        value = int(raw)
    except (TypeError, ValueError):
        value = 0
    if not 1 <= value <= _LIST_MAX:
        raise RestoreError("bad-request", f"limit must be an integer in 1..{_LIST_MAX}")
    return value


def _refuse(exc: RestoreError) -> Response:
    body: dict[str, Any] = {"error": exc.code, "detail": exc.detail, **exc.extra}
    if isinstance(exc, restore.MinerNotDead):
        body["evidence"] = exc.evidence
    return Response(body, status=_ERROR_STATUS.get(exc.code, status.HTTP_400_BAD_REQUEST))


def _get_vm(vm_id: str) -> Vm:
    vm = Vm.objects.filter(vm_id=vm_id).first()
    if vm is None:
        raise RestoreError("vm-not-found", "vm not found")
    return vm


def _body(request: Request) -> dict[str, Any]:
    data = request.data
    if not isinstance(data, dict):
        raise RestoreError("bad-request", "body must be a JSON object")
    unknown = set(data) - _BODY_FIELDS
    if unknown:
        raise RestoreError("bad-request", f"unknown field(s): {', '.join(sorted(unknown))}")
    return data


def _job(vm: Vm, job_id: str) -> MigrationJob:
    job = (
        MigrationJob.objects.filter(vm=vm, job_id=job_id, kind__in=restore.RESTORE_KINDS)
        .select_related("vm", "restore_run", "restore_run__chain", "authorization")
        .first()
    )
    if job is None:
        raise RestoreError("no-restore", "no such restore job")
    return job


class _RootView(APIView):
    object_scope = scoping.OPERATOR_ONLY
    permission_classes = [IsAuthenticated, IsOrchestrationRoot]


_VM_ID = OpenApiParameter("vm_id", str, OpenApiParameter.PATH)
_JOB_ID = OpenApiParameter("job_id", str, OpenApiParameter.PATH)
_COMMON = {403: OpenApiResponse(RestoreErrorSerializer, "Not the orchestration root principal.")}


class VmRestoreView(_RootView):
    """`/v1/vm/<vm_id>/restore` — open a restore, or read the latest."""

    http_method_names = ["get", "post", "options"]

    @extend_schema(
        summary="Restore the VM from one of its backups",
        description=(
            "Restores the VM, in place, to a backup point taken since its last "
            "boot. The backup is downloaded while the VM keeps running; the VM "
            "is then stopped for a few minutes, booted on the restored disk, and "
            "returned to its prior power state. Its current disk is kept until "
            "the restored VM is proven up. Everything written after the point is "
            "lost. Idempotent on `request_id`. A point of an EARLIER boot "
            "(`class: rollback`) is restored through a KBS-authorized rollback: it "
            "needs `accept_rollback: true` and `on_behalf_of`, the run's KBS "
            "checkpoint, and at most one rollback per VM every "
            "`VALI_RESTORE_ROLLBACK_MIN_INTERVAL_S`."
        ),
        tags=_TAGS,
        parameters=[_VM_ID],
        request=RestoreRequestSerializer,
        responses={
            202: RestoreJobSerializer,
            400: OpenApiResponse(
                RestoreErrorSerializer, "`bad-request` / `on-behalf-of-required`."
            ),
            404: OpenApiResponse(RestoreErrorSerializer, "`vm-not-found`."),
            409: OpenApiResponse(
                RestoreErrorSerializer,
                "`point-not-restorable` / `rollback-unsupported` / `rollback-not-accepted` / "
                "`rollback-no-checkpoint` / `rollback-not-capable` / "
                "`customer-rollback-authorization-required` (an M2 VM: the customer "
                "authorizes the rollback on their guardian) / `job-in-flight` / "
                "`vm-not-restorable` / "
                "`no-eligible-miner` / `request-id-conflict`.",
            ),
            429: OpenApiResponse(
                RestoreErrorSerializer, "`rollback-rate-limited` (with `retry_after_s`)."
            ),
            503: OpenApiResponse(
                RestoreErrorSerializer, "`restore-disabled` / `restore-unavailable`."
            ),
            **_COMMON,
        },
    )
    def post(self, request: Request, vm_id: str) -> Response:
        try:
            body = _body(request)
            job, _created = restore.start_restore(
                vm=_get_vm(vm_id),
                run_id=body.get("run_id"),
                request_id=body.get("request_id"),
                dest_node_id=body.get("dest_node_id"),
                accept_rollback=body.get("accept_rollback"),
                on_behalf_of=body.get("on_behalf_of"),
                customer_authorized=body.get("customer_authorized"),
                decided_by=request.user,
            )
        except RestoreError as exc:
            return _refuse(exc)
        return Response(restore.serialize(job), status=status.HTTP_202_ACCEPTED)

    @extend_schema(
        summary="The VM's restores and failovers",
        description="Newest first; `limit` 1..100 (default 20).",
        tags=_TAGS,
        parameters=[
            _VM_ID,
            OpenApiParameter("limit", int, OpenApiParameter.QUERY, required=False),
        ],
        responses={
            200: RestoreJobListSerializer,
            400: OpenApiResponse(RestoreErrorSerializer, "`bad-request` (limit)."),
            404: OpenApiResponse(RestoreErrorSerializer, "`vm-not-found`."),
            **_COMMON,
        },
    )
    def get(self, request: Request, vm_id: str) -> Response:
        try:
            limit = _limit(request.query_params.get("limit"))
            jobs = restore.list_jobs(_get_vm(vm_id), limit=limit)
        except RestoreError as exc:
            return _refuse(exc)
        return Response({"jobs": [restore.serialize(job) for job in jobs]})


class VmRestoreJobView(_RootView):
    """`/v1/vm/<vm_id>/restore/<job_id>` — one restore job."""

    http_method_names = ["get", "options"]

    @extend_schema(
        summary="A restore job",
        tags=_TAGS,
        parameters=[_VM_ID, _JOB_ID],
        responses={
            200: RestoreJobSerializer,
            404: OpenApiResponse(RestoreErrorSerializer, "`vm-not-found` / `no-restore`."),
            **_COMMON,
        },
    )
    def get(self, request: Request, vm_id: str, job_id: str) -> Response:
        try:
            job = _job(_get_vm(vm_id), job_id)
        except RestoreError as exc:
            return _refuse(exc)
        return Response(restore.serialize(job))


class VmRestoreCancelView(_RootView):
    """`/v1/vm/<vm_id>/restore/<job_id>/cancel` — before the VM is touched."""

    http_method_names = ["post", "options"]

    @extend_schema(
        summary="Cancel a restore",
        description=(
            "Only while the backup is being downloaded (`staging`) or the VM "
            "stopped (`stopping`). The VM is left as it was (started again if "
            "the restore had stopped it)."
        ),
        tags=_TAGS,
        parameters=[_VM_ID, _JOB_ID],
        request=None,
        responses={
            200: RestoreJobSerializer,
            404: OpenApiResponse(RestoreErrorSerializer, "`vm-not-found` / `no-restore`."),
            409: OpenApiResponse(RestoreErrorSerializer, "`not-cancellable`."),
            **_COMMON,
        },
    )
    def post(self, request: Request, vm_id: str, job_id: str) -> Response:
        try:
            job = restore.cancel_restore(
                job=_job(_get_vm(vm_id), job_id), decided_by=request.user
            )
        except RestoreError as exc:
            return _refuse(exc)
        return Response(restore.serialize(job))


class VmRestoreRevertView(_RootView):
    """`/v1/vm/<vm_id>/restore/<job_id>/revert` — the original back, after
    the commit point."""

    http_method_names = ["post", "options"]

    @extend_schema(
        summary="Put a failed restore's original back",
        description=(
            "Operator only (`on_behalf_of.kind: superuser`). For a restore that "
            "failed AFTER its point of no return (the restored guest took the VM's "
            "key, the original disk is kept): the original is booted again, through "
            "a KBS-authorized rollback to the checkpoint vali took of it right before "
            "the restore stopped it. Everything the restored VM wrote is lost. "
            "Idempotent: a job already being put back answers itself. Poll "
            "`GET /v1/vm/<id>/restore/<job_id>`: `undo.outcome`."
        ),
        tags=_TAGS,
        parameters=[_VM_ID, _JOB_ID],
        request=RevertRequestSerializer,
        responses={
            202: RestoreJobSerializer,
            400: OpenApiResponse(
                RestoreErrorSerializer, "`bad-request` / `on-behalf-of-required`."
            ),
            403: OpenApiResponse(
                RestoreErrorSerializer,
                "`revert-superuser-only`, or not the orchestration root principal.",
            ),
            404: OpenApiResponse(RestoreErrorSerializer, "`vm-not-found` / `no-restore`."),
            409: OpenApiResponse(
                RestoreErrorSerializer,
                "`revert-not-applicable` / `revert-cross-host-unsupported` / "
                "`revert-no-checkpoint` / `revert-not-ready` / `rollback-unsupported` / "
                "`rollback-not-capable` / `job-in-flight`.",
            ),
            429: OpenApiResponse(
                RestoreErrorSerializer, "`rollback-rate-limited` (with `retry_after_s`)."
            ),
            503: OpenApiResponse(RestoreErrorSerializer, "`restore-unavailable`."),
        },
    )
    def post(self, request: Request, vm_id: str, job_id: str) -> Response:
        try:
            data = request.data
            if not isinstance(data, dict):
                raise RestoreError("bad-request", "body must be a JSON object")
            unknown = set(data) - _REVERT_FIELDS
            if unknown:
                raise RestoreError(
                    "bad-request", f"unknown field(s): {', '.join(sorted(unknown))}"
                )
            job = _job(_get_vm(vm_id), job_id)
            if job.kind != "restore":
                raise RestoreError("revert-not-applicable", "only a restore can be put back")
            job, _started = restore.start_undo(
                job=job, decided_by=request.user, on_behalf_of=data.get("on_behalf_of")
            )
        except RestoreError as exc:
            return _refuse(exc)
        return Response(restore.serialize(job), status=status.HTTP_202_ACCEPTED)


class VmFailoverView(_RootView):
    """`/v1/vm/<vm_id>/failover` — restore the VM elsewhere, its miner dead."""

    http_method_names = ["post", "options"]

    @extend_schema(
        summary="Fail the VM over from its dead miner",
        description=(
            "Operator only. Refused unless the VM's miner is proven dead: its "
            "heartbeat and its NetBird peer silent for "
            "`VALI_FAILOVER_DEAD_AFTER_S` and the Edge unable to reach it. The "
            "VM is restored from its newest backup of the current boot (or "
            "`run_id`) on another miner (or `dest_node_id`); the dead miner is "
            "quarantined until an operator clears it. Idempotent on "
            "`request_id`. Poll `GET /v1/vm/<id>/restore/<job_id>`."
        ),
        tags=_TAGS,
        parameters=[_VM_ID],
        request=FailoverRequestSerializer,
        responses={
            202: RestoreJobSerializer,
            400: OpenApiResponse(RestoreErrorSerializer, "`bad-request`."),
            404: OpenApiResponse(RestoreErrorSerializer, "`vm-not-found`."),
            409: OpenApiResponse(
                MinerNotDeadSerializer,
                "`miner-not-dead` (with the evidence) / `no-backup-point` / "
                "`point-not-restorable` / `rollback-unsupported` / `job-in-flight` / "
                "`vm-not-restorable` / "
                "`no-eligible-miner` / `request-id-conflict`.",
            ),
            503: OpenApiResponse(RestoreErrorSerializer, "`failover-disabled`."),
            **_COMMON,
        },
    )
    def post(self, request: Request, vm_id: str) -> Response:
        try:
            data = request.data
            if not isinstance(data, dict):
                raise RestoreError("bad-request", "body must be a JSON object")
            unknown = set(data) - _FAILOVER_FIELDS
            if unknown:
                raise RestoreError(
                    "bad-request", f"unknown field(s): {', '.join(sorted(unknown))}"
                )
            job, _created = restore.start_failover(
                vm=_get_vm(vm_id),
                request_id=data.get("request_id"),
                run_id=data.get("run_id"),
                dest_node_id=data.get("dest_node_id"),
                decided_by=request.user,
            )
        except RestoreError as exc:
            return _refuse(exc)
        return Response(restore.serialize(job), status=status.HTTP_202_ACCEPTED)
