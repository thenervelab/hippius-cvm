"""Guest upgrade endpoints (`apps.orchestration.guest_upgrade`,
docs/design/guest-component-rollout.md). Root-only (`IsOrchestrationRoot`,
`OPERATOR_ONLY`): the layer above schedules upgrades in its tenants'
maintenance windows and decides who may ask.

  GET  /v1/vm/<vm_id>/guest-components                what the VM runs, its
                                                      epochs, the newest
                                                      release for its base,
                                                      the upgrade in flight
  POST /v1/vm/<vm_id>/guest-upgrade                   schedule an upgrade
                                                      {"release": N,
                                                       "not_before": iso8601?}
  GET  /v1/vm/<vm_id>/guest-upgrade                   the VM's latest job
  GET  /v1/vm/<vm_id>/guest-upgrade/<job_id>          one job
  POST /v1/vm/<vm_id>/guest-upgrade/<job_id>/cancel   cancel a pending job
  POST /v1/vm/<vm_id>/guest-upgrade/<job_id>/recover  {"action": "start-on-target",
                                                       "reason": "..."} — start
                                                      the VM a failed / blocked
                                                      job left stopped, on its
                                                      target (audited)
  POST /v1/guest-rollouts                             start a rollout (waves)
  GET  /v1/guest-rollouts/<id>                        its progress
  POST /v1/guest-rollouts/<id>/{pause,resume,abort}

A POST naming the release of the job already pending for the VM moves its
`not_before` ("upgrade now", a new window) instead of refusing. On a VM
whose latest job ended `upgrade_blocked`, a POST retries it (the same
release again, or a newer one). Refusals
answer `{"error": <text>, "category": <stable slug>}` like the other
orchestration routes.
"""

from __future__ import annotations

import logging
from datetime import datetime
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

from . import guest_upgrade
from .models import TERMINAL_GUEST_UPGRADE_STATES, GuestUpgradeJob, GuestUpgradeState
from .permissions import IsOrchestrationRoot
from .schemas import (
    GuestComponentsSerializer,
    GuestRolloutSerializer,
    GuestRolloutStartRequestSerializer,
    GuestUpgradeJobSerializer,
    GuestUpgradeRecoverRequestSerializer,
    GuestUpgradeStartRequestSerializer,
)
from .service import StartError
from .services import launch_record

log = logging.getLogger("apps.orchestration.guest_upgrade_views")

_TAGS = ["VM orchestration"]

_VM_ID_PARAM = OpenApiParameter("vm_id", str, OpenApiParameter.PATH, description="Target VM id.")
_JOB_ID_PARAM = OpenApiParameter(
    "job_id", str, OpenApiParameter.PATH, description="Job id returned by the schedule call."
)

_ROLLOUT_ID_PARAM = OpenApiParameter(
    "rollout_id", str, OpenApiParameter.PATH, description="Rollout id returned by the start call."
)

#: The refusals that are the CALLER's request (400); every other one is
#: the VM's or the fleet's state right now (409).
_BAD_REQUEST = frozenset(
    {"wire", "no-build", "downgrade", "already-on-target", "below-floor", "other-base"}
)


def _error(http_status: int, message: str, category: str) -> Response:
    return Response({"error": message, "category": category}, status=http_status)


def _refusal(exc: StartError) -> Response:
    code = status.HTTP_400_BAD_REQUEST if exc.category in _BAD_REQUEST else status.HTTP_409_CONFLICT
    return _error(code, exc.message, exc.category)


def _jobs(vm_id: str):  # noqa: ANN202 — a QuerySet
    return GuestUpgradeJob.objects.filter(vm__vm_id=vm_id).select_related(
        "vm", "target", "decided_by", "retry_of"
    )


class _RootView(APIView):
    object_scope = scoping.OPERATOR_ONLY
    permission_classes = [IsAuthenticated, IsOrchestrationRoot]


class VmGuestComponentsView(_RootView):
    """`GET /v1/vm/<vm_id>/guest-components`."""

    http_method_names = ["get", "options"]

    @extend_schema(
        summary="The guest components release a VM runs",
        description=(
            "Root-only. `release` is the guest components release the VM's launch "
            "record boots (`null`: the bare base it was baked with); `required_epoch` is "
            "the floor below which vali never launches it again, `attested_epoch` the "
            "epoch a guest of it last proved it booted. `newest_release` is the newest "
            "release with a registered build for the VM's base; `upgrade` the job in "
            "flight (pending in its window, or running), if any."
        ),
        tags=_TAGS,
        parameters=[_VM_ID_PARAM],
        responses={
            200: GuestComponentsSerializer,
            404: OpenApiResponse(ErrorSerializer, "VM not found."),
        },
    )
    def get(self, request: Request, vm_id: str) -> Response:
        vm = Vm.objects.filter(vm_id=vm_id).first()
        if vm is None:
            return _error(status.HTTP_404_NOT_FOUND, "vm not found", "not-found")
        return Response(guest_upgrade.components_of(vm), status=status.HTTP_200_OK)


def _parse_not_before(body: dict[str, object]) -> datetime | None | Response:
    """`None` only when the key is ABSENT (now); an explicit `null` is a
    wire error — it must never turn a scheduled window into "now"."""
    if "not_before" not in body:
        return None
    raw = body["not_before"]
    if not isinstance(raw, str):
        return _error(status.HTTP_400_BAD_REQUEST, "not_before must be an ISO 8601 time", "wire")
    try:
        when = datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError:
        return _error(status.HTTP_400_BAD_REQUEST, "not_before must be an ISO 8601 time", "wire")
    if when.tzinfo is None:
        return _error(status.HTTP_400_BAD_REQUEST, "not_before must carry a timezone", "wire")
    return when


class VmGuestUpgradeView(_RootView):
    """`POST /v1/vm/<vm_id>/guest-upgrade` + `GET` (the latest job)."""

    http_method_names = ["get", "post", "options"]

    @extend_schema(
        summary="Schedule a guest components upgrade",
        description=(
            "Root-only. Admits the upgrade of the VM onto `release` synchronously — every "
            "refusal happens here — and returns the job (`pending` until `not_before`, "
            "now when omitted). `vali_orchestration_tick` then drives it: one reboot onto "
            "the new release, a live attestation of that boot, a soak; a failure rolls "
            "back when the VM's required epoch allows it. A stopped VM stays pending. "
            "The same `release` for a VM whose job is still pending moves its "
            "`not_before` (200) instead of admitting a second one."
        ),
        tags=_TAGS,
        parameters=[_VM_ID_PARAM],
        request=GuestUpgradeStartRequestSerializer,
        responses={
            200: OpenApiResponse(GuestUpgradeJobSerializer, "The pending job, rescheduled."),
            202: GuestUpgradeJobSerializer,
            400: OpenApiResponse(
                ErrorSerializer,
                "Bad body / no build of the release for the VM's base / "
                "an older release / already on it / below the VM's floor.",
            ),
            404: OpenApiResponse(ErrorSerializer, "VM not found."),
            409: OpenApiResponse(
                ErrorSerializer,
                "VM not active / another operation in flight / not upgradable now.",
            ),
        },
    )
    def post(self, request: Request, vm_id: str) -> Response:
        body = request.data if isinstance(request.data, dict) else {}
        release = body.get("release")
        if not isinstance(release, int) or isinstance(release, bool) or release <= 0:
            return _error(status.HTTP_400_BAD_REQUEST, "release must be a positive integer", "wire")
        not_before = _parse_not_before(body)
        if isinstance(not_before, Response):
            return not_before
        vm = Vm.objects.filter(vm_id=vm_id).first()
        if vm is None:
            return _error(status.HTTP_404_NOT_FOUND, "vm not found", "not-found")
        in_flight = (
            _jobs(vm_id)
            .exclude(state__in=TERMINAL_GUEST_UPGRADE_STATES)
            .order_by("-started_at")
            .first()
        )
        if in_flight is not None and guest_upgrade.cancel_if_doomed(in_flight):
            in_flight = None  # it could never run: it must not block a replacement
        if in_flight is not None:
            if (
                in_flight.state != GuestUpgradeState.PENDING.value
                or int(in_flight.target.release_id) != release
            ):
                return _error(
                    status.HTTP_409_CONFLICT,
                    f"guest upgrade {in_flight.job_id} (release {in_flight.target.release_id}) "
                    f"is {in_flight.state}",
                    "job-in-flight",
                )
            from django.utils import timezone

            try:
                job = guest_upgrade.reschedule(in_flight, not_before or timezone.now())
            except StartError as exc:
                return _refusal(exc)
            return Response(guest_upgrade.serialize_job(job), status=status.HTTP_200_OK)
        if launch_record.latest_record(vm.vm_id) is None:
            return _error(status.HTTP_409_CONFLICT, "vm has no launch record", "no-launch-record")
        build = guest_upgrade.build_for_vm(vm, release)
        if build is None:
            return _error(
                status.HTTP_400_BAD_REQUEST,
                f"no registered build of release {release} for this vm's base",
                "no-build",
            )
        try:
            job = guest_upgrade.start_guest_upgrade(
                vm=vm, build=build, decided_by=request.user, not_before=not_before
            )
        except StartError as exc:
            return _refusal(exc)
        job = _jobs(vm_id).get(pk=job.pk)
        return Response(guest_upgrade.serialize_job(job), status=status.HTTP_202_ACCEPTED)

    @extend_schema(
        summary="The VM's latest guest upgrade job",
        tags=_TAGS,
        parameters=[_VM_ID_PARAM],
        responses={
            200: GuestUpgradeJobSerializer,
            404: OpenApiResponse(ErrorSerializer, "VM not found, or never upgraded."),
        },
    )
    def get(self, request: Request, vm_id: str) -> Response:
        job = _jobs(vm_id).order_by("-started_at").first()
        if job is None:
            return _error(status.HTTP_404_NOT_FOUND, "no guest upgrade job", "not-found")
        return Response(guest_upgrade.serialize_job(job), status=status.HTTP_200_OK)


class VmGuestUpgradeJobView(_RootView):
    """`GET /v1/vm/<vm_id>/guest-upgrade/<job_id>`."""

    http_method_names = ["get", "options"]

    @extend_schema(
        summary="Poll a guest upgrade job",
        tags=_TAGS,
        parameters=[_VM_ID_PARAM, _JOB_ID_PARAM],
        responses={
            200: GuestUpgradeJobSerializer,
            404: OpenApiResponse(ErrorSerializer, "Guest upgrade job not found."),
        },
    )
    def get(self, request: Request, vm_id: str, job_id: str) -> Response:
        job = _jobs(vm_id).filter(job_id=job_id).first()
        if job is None:
            return _error(status.HTTP_404_NOT_FOUND, "guest upgrade job not found", "not-found")
        return Response(guest_upgrade.serialize_job(job), status=status.HTTP_200_OK)


class VmGuestUpgradeCancelView(_RootView):
    """`POST /v1/vm/<vm_id>/guest-upgrade/<job_id>/cancel`."""

    http_method_names = ["post", "options"]

    @extend_schema(
        summary="Cancel a pending guest upgrade",
        description=(
            "Root-only. Only a job still `pending` (waiting for its window, nothing moved) "
            "can be cancelled; once it has taken the VM it ends on its own (done, rolled "
            "back, or blocked for an operator)."
        ),
        tags=_TAGS,
        parameters=[_VM_ID_PARAM, _JOB_ID_PARAM],
        request=None,
        responses={
            200: GuestUpgradeJobSerializer,
            404: OpenApiResponse(ErrorSerializer, "Guest upgrade job not found."),
            409: OpenApiResponse(ErrorSerializer, "`not-pending`: the job holds the VM."),
        },
    )
    def post(self, request: Request, vm_id: str, job_id: str) -> Response:
        job = _jobs(vm_id).filter(job_id=job_id).first()
        if job is None:
            return _error(status.HTTP_404_NOT_FOUND, "guest upgrade job not found", "not-found")
        if job.state in TERMINAL_GUEST_UPGRADE_STATES:
            return _error(
                status.HTTP_409_CONFLICT, f"guest upgrade {job_id} is {job.state}", "not-pending"
            )
        try:
            job = guest_upgrade.cancel_pending(job, by=str(getattr(request.user, "name", "")))
        except StartError as exc:
            return _refusal(exc)
        return Response(guest_upgrade.serialize_job(job), status=status.HTTP_200_OK)


class VmGuestUpgradeRecoverView(_RootView):
    """`POST /v1/vm/<vm_id>/guest-upgrade/<job_id>/recover`."""

    http_method_names = ["post", "options"]

    @extend_schema(
        summary="Recover a VM a guest upgrade left stopped",
        description=(
            "Root-only, audited (the caller and `reason` are recorded on the job). "
            "`start-on-target`: starts the VM a `failed` / `upgrade_blocked` job left "
            "stopped, on the job's TARGET release — never below the VM's required epoch — "
            "through the power API (launch-digest ENFORCE, the auto-pin, a KBS supersede "
            "at register). The boot is not health-gated: the job stays as it ended, and a "
            "retry (`POST .../guest-upgrade` with a release) is what verifies the VM. "
            "Refused while the miner reports the domain running or does not answer, while "
            "the job is still parking, or once a newer job exists."
        ),
        tags=_TAGS,
        parameters=[_VM_ID_PARAM, _JOB_ID_PARAM],
        request=GuestUpgradeRecoverRequestSerializer,
        responses={
            200: GuestUpgradeJobSerializer,
            400: OpenApiResponse(ErrorSerializer, "Bad body / unknown action."),
            404: OpenApiResponse(ErrorSerializer, "Guest upgrade job not found."),
            409: OpenApiResponse(ErrorSerializer, "Not recoverable now (the category says why)."),
            502: OpenApiResponse(
                ErrorSerializer,
                "`dispatch-error`: the start's outcome is unknown — poll the VM's power state.",
            ),
        },
    )
    def post(self, request: Request, vm_id: str, job_id: str) -> Response:
        body = request.data if isinstance(request.data, dict) else {}
        action, reason = body.get("action"), body.get("reason")
        if action not in guest_upgrade.RECOVERY_ACTIONS:
            return _error(
                status.HTTP_400_BAD_REQUEST,
                f"action must be one of {sorted(guest_upgrade.RECOVERY_ACTIONS)}",
                "wire",
            )
        if not isinstance(reason, str) or not reason.strip():
            return _error(status.HTTP_400_BAD_REQUEST, "reason is required (audited)", "wire")
        job = _jobs(vm_id).filter(job_id=job_id).first()
        if job is None:
            return _error(status.HTTP_404_NOT_FOUND, "guest upgrade job not found", "not-found")
        operator = str(getattr(request.user, "name", "") or "")
        try:
            guest_upgrade.recover_start_on_target(job, operator=operator, reason=reason)
        except StartError as exc:
            if exc.category == "wire":
                return _error(status.HTTP_400_BAD_REQUEST, exc.message, exc.category)
            return _error(status.HTTP_409_CONFLICT, exc.message, exc.category)
        except Exception as exc:  # noqa: BLE001 — the start may have landed
            log.exception("guest upgrade %s: recovery start of vm=%s failed", job_id, vm_id)
            return _error(
                status.HTTP_502_BAD_GATEWAY,
                f"the start's outcome is unknown ({type(exc).__name__}) — poll the vm",
                "dispatch-error",
            )
        return Response(
            guest_upgrade.serialize_job(_jobs(vm_id).get(pk=job.pk)), status=status.HTTP_200_OK
        )


# ─── rollouts (`guest_rollout.py`) ───────────────────────────────────


def _rollout_refusal(exc: Any) -> Response:
    code = (
        status.HTTP_400_BAD_REQUEST
        if exc.category in ("wire", "unknown-release", "unknown-canary", "no-health-leg")
        else status.HTTP_409_CONFLICT
    )
    body: dict[str, Any] = {"error": exc.message, "category": exc.category}
    if exc.missing:
        body["vm_ids"] = exc.missing
    return Response(body, status=code)


class GuestRolloutsView(_RootView):
    """`POST /v1/guest-rollouts`."""

    http_method_names = ["post", "options"]

    @extend_schema(
        summary="Start a guest components rollout",
        description=(
            "Root-only. Moves the VMs of `scope` (each key optional, ANDed: `vm_ids`, "
            "`tenant_ids`, `node_ids`, `bake_ids`) onto `release` in waves: the "
            "`canary_vm_ids` first, then cumulative percentages of the rest (`waves`, "
            "default 5/25/50/100), at most `max_concurrent` VMs at a time and one per "
            "miner, `wave_pause_s` between waves. It stops on any canary outcome but "
            "done, any failed or upgrade_blocked job, or rolled_back above "
            "`max_failure_ratio` of a wave. Refused, listing them (`vm_ids`), while a VM "
            "in scope has no build of the release for its base; a release without "
            "health checks is canaries only."
        ),
        tags=_TAGS,
        request=GuestRolloutStartRequestSerializer,
        responses={
            201: GuestRolloutSerializer,
            400: OpenApiResponse(ErrorSerializer, "Bad body / unknown release or canary."),
            409: OpenApiResponse(
                ErrorSerializer, "`missing-builds` / `vm-in-rollout` (with `vm_ids`)."
            ),
        },
    )
    def post(self, request: Request) -> Response:
        from . import guest_rollout

        body = request.data if isinstance(request.data, dict) else {}
        release = body.get("release")
        canary = body.get("canary_vm_ids")
        scope = body.get("scope") or {}
        if (
            not isinstance(release, int)
            or isinstance(release, bool)
            or not isinstance(canary, list)
            or not all(isinstance(v, str) for v in canary)
            or not isinstance(scope, dict)
            or not all(
                isinstance(v, list) and all(isinstance(x, str) for x in v) for v in scope.values()
            )
        ):
            return _error(
                status.HTTP_400_BAD_REQUEST,
                "release (int), canary_vm_ids (list of ids) and scope (object of id lists)",
                "wire",
            )
        not_before = _parse_not_before(body)
        if isinstance(not_before, Response):
            return not_before
        options: dict[str, Any] = {}
        for key, kind in (
            ("waves", list),
            ("max_concurrent", int),
            ("wave_pause_s", int),
            ("max_failure_ratio", (int, float)),
        ):
            if key in body:
                if not isinstance(body[key], kind) or isinstance(body[key], bool):
                    return _error(status.HTTP_400_BAD_REQUEST, f"{key}: wrong type", "wire")
                options[key] = body[key]
        try:
            rollout = guest_rollout.create_rollout(
                release=release,
                canary_vm_ids=canary,
                scope=scope,
                decided_by=request.user,
                not_before=not_before,
                **options,
            )
        except guest_rollout.RolloutRefused as exc:
            return _rollout_refusal(exc)
        return Response(guest_rollout.serialize_rollout(rollout), status=status.HTTP_201_CREATED)


class GuestRolloutView(_RootView):
    """`GET /v1/guest-rollouts/<rollout_id>`."""

    http_method_names = ["get", "options"]

    @extend_schema(
        summary="A guest components rollout",
        tags=_TAGS,
        parameters=[_ROLLOUT_ID_PARAM],
        responses={
            200: GuestRolloutSerializer,
            404: OpenApiResponse(ErrorSerializer, "Rollout not found."),
        },
    )
    def get(self, request: Request, rollout_id: str) -> Response:
        from . import guest_rollout
        from .models import GuestRollout

        rollout = (
            GuestRollout.objects.filter(rollout_id=rollout_id).select_related("decided_by").first()
        )
        if rollout is None:
            return _error(status.HTTP_404_NOT_FOUND, "rollout not found", "not-found")
        return Response(guest_rollout.serialize_rollout(rollout), status=status.HTTP_200_OK)


class GuestRolloutActionView(_RootView):
    """`POST /v1/guest-rollouts/<rollout_id>/{pause,resume,abort}`."""

    http_method_names = ["post", "options"]
    action = ""

    @extend_schema(
        summary="Pause / resume / abort a guest components rollout",
        description=(
            "Root-only. `pause`: no new job (jobs in flight finish). `resume`: acknowledges "
            "what stopped it; only later outcomes stop it again. `abort`: for good — its "
            "pending jobs are cancelled, jobs holding a VM finish on their own."
        ),
        tags=_TAGS,
        parameters=[_ROLLOUT_ID_PARAM],
        request=None,
        responses={
            200: GuestRolloutSerializer,
            404: OpenApiResponse(ErrorSerializer, "Rollout not found."),
            409: OpenApiResponse(ErrorSerializer, "Not in a state that allows it."),
        },
    )
    def post(self, request: Request, rollout_id: str) -> Response:
        from . import guest_rollout
        from .models import GuestRollout

        rollout = (
            GuestRollout.objects.filter(rollout_id=rollout_id).select_related("decided_by").first()
        )
        if rollout is None:
            return _error(status.HTTP_404_NOT_FOUND, "rollout not found", "not-found")
        who = str(getattr(request.user, "name", ""))
        try:
            if self.action == "pause":
                guest_rollout.pause(rollout, f"paused by {who}")
            elif self.action == "resume":
                guest_rollout.resume(rollout)
            else:
                guest_rollout.abort(rollout, by=who)
        except guest_rollout.RolloutRefused as exc:
            return _rollout_refusal(exc)
        rollout.refresh_from_db()
        return Response(guest_rollout.serialize_rollout(rollout), status=status.HTTP_200_OK)
