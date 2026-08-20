"""Packer trigger surface + S3 presigning views.

Endpoints:

  POST /v1/packer/build
      Body: {"image_kind": "kbs"|"edge"|"guest"|"audit-vm"}.
      Auth: any ServiceClient.
      → 202 with the new row's build_id + state.
      → 409 if a Queued/Running row already exists for image_kind.

  GET /v1/packer/build/<build_id>
      Auth: any ServiceClient.
      → 200 with the row's serialized form.
      → 404 if unknown.

  POST /v1/packer/build/<build_id>/finalize
      Body: {"to_state":"succeeded","if_version":N,
             "artifact_sha256":"…","provenance_signed_url":"…"}
        OR  {"to_state":"failed","if_version":N,"failure_reason":"…"}
        OR  {"to_state":"running","if_version":N}     (worker claim)
      Auth: VALI_PACKER_WORKER_PRINCIPAL ONLY.
      → 200 / 400 / 409 with the optimistic-concurrency CAS pattern
        used by the lifecycle app.

  POST /v1/packer/build/<build_id>/presign-image-get
      Body (optional): {"ttl_seconds": int}
      Auth: any ServiceClient.
      → 200 with a presigned GET URL for the artifact on the
        Hippius S3 images bucket.
      → 409 if the build isn't in Succeeded state.
      → 503 if the S3 backend is misconfigured / unreachable.
"""

from __future__ import annotations

import logging
import secrets
from typing import Any

from django.conf import settings
from django.db import IntegrityError, transaction
from drf_spectacular.utils import OpenApiParameter, OpenApiResponse, extend_schema
from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from rest_framework.request import Request
from rest_framework.response import Response
from rest_framework.views import APIView

from apps.common.schemas import ErrorSerializer
from apps.identity import scoping
from apps.storage import s3 as s3_module

from .models import IN_FLIGHT_STATES, PackerBuild, PackerBuildState, PackerImageKind
from .permissions import IsPackerWorker
from .schemas import (
    PackerBuildCreateRequestSerializer,
    PackerBuildFinalizeRequestSerializer,
    PackerBuildSerializer,
    PackerPresignRequestSerializer,
    PackerPresignResponseSerializer,
)
from .state_machine import (
    CAT_BAD_FIELD,
    CAT_ILLEGAL,
    FinalizeError,
    FinalizeRequest,
    legal,
    required_args,
)

log = logging.getLogger("apps.packer.views")

_BUILD_ID_PARAM = OpenApiParameter(
    "build_id", str, OpenApiParameter.PATH, description="Opaque 32-hex-char build id."
)


class PackerBuildCreateView(APIView):
    """`POST /v1/packer/build` — request a new build."""

    # P2 object-level authorization: guest-image builds are fleet infrastructure.
    object_scope = scoping.OPERATOR_ONLY

    permission_classes = [IsAuthenticated]
    http_method_names = ["post", "options"]

    @extend_schema(
        summary="Request a new Packer build",
        description=(
            "Queue a build for `image_kind`. One active build per image_kind "
            "is enforced — a Queued/Running row draws a 409 with the surviving "
            "row attached."
        ),
        tags=["Packer"],
        request=PackerBuildCreateRequestSerializer,
        responses={
            202: PackerBuildSerializer,
            400: OpenApiResponse(ErrorSerializer, "Malformed body / unknown image_kind."),
            409: OpenApiResponse(ErrorSerializer, "A build for image_kind is in flight."),
            503: OpenApiResponse(ErrorSerializer, "build_id collision (retryable)."),
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

        image_kind_raw = body.get("image_kind")
        if not isinstance(image_kind_raw, str):
            return _error(
                status.HTTP_400_BAD_REQUEST,
                "image_kind must be a string",
                "wire",
            )
        try:
            image_kind = PackerImageKind(image_kind_raw)
        except ValueError:
            return _error(
                status.HTTP_400_BAD_REQUEST,
                f"unknown image_kind {image_kind_raw!r}",
                "wire",
            )

        # "One active build per image_kind" — enforced by a partial
        # unique index on the model. Two concurrent POSTs can both
        # observe zero in-flight rows on the pre-check, but at most
        # ONE will pass the INSERT; the loser sees `IntegrityError`,
        # which we turn into a 409 with the surviving row attached.
        # The pre-check is still useful: it surfaces 409 without
        # paying the wasted-INSERT cost on the common (cached) path.
        try:
            with transaction.atomic():
                conflict = PackerBuild.objects.filter(
                    image_kind=image_kind.value,
                    state__in=list(IN_FLIGHT_STATES),
                ).first()
                if conflict is not None:
                    return _in_flight_conflict_response(conflict)
                row = PackerBuild.objects.create(
                    build_id=_mint_build_id(),
                    image_kind=image_kind.value,
                    state=PackerBuildState.QUEUED.value,
                    requested_by=request.user,
                )
        except IntegrityError:
            # Two integrity failures are possible here: the partial
            # unique index (concurrent POST won the race) or the
            # `build_id` unique column (astronomically unlikely
            # CSPRNG collision). Re-read the in-flight row; if it
            # exists, the race is the cause and we 409. Otherwise
            # the collision is the cause and we 503.
            conflict = PackerBuild.objects.filter(
                image_kind=image_kind.value,
                state__in=list(IN_FLIGHT_STATES),
            ).first()
            if conflict is not None:
                log.info(
                    "packer build race lost: image_kind=%s winner=%s",
                    image_kind.value,
                    conflict.build_id,
                )
                return _in_flight_conflict_response(conflict)
            log.exception("PackerBuild build_id collision")
            return _error(
                status.HTTP_503_SERVICE_UNAVAILABLE,
                "internal: build_id collision",
                "internal",
            )

        log.info(
            "packer build queued: build_id=%s image_kind=%s requested_by=%s",
            row.build_id,
            image_kind.value,
            request.user.name,
        )
        return Response(
            _serialize_build(row),
            status=status.HTTP_202_ACCEPTED,
        )


class PackerBuildDetailView(APIView):
    """`GET /v1/packer/build/<build_id>` — current row."""

    # P2 object-level authorization: guest-image builds are fleet infrastructure.
    object_scope = scoping.OPERATOR_ONLY

    permission_classes = [IsAuthenticated]
    http_method_names = ["get", "options"]

    @extend_schema(
        summary="Get a Packer build row",
        tags=["Packer"],
        parameters=[_BUILD_ID_PARAM],
        responses={
            200: PackerBuildSerializer,
            404: OpenApiResponse(ErrorSerializer, "Build not found."),
        },
    )
    def get(self, request: Request, build_id: str) -> Response:
        try:
            row = PackerBuild.objects.get(build_id=build_id)
        except PackerBuild.DoesNotExist:
            return _error(
                status.HTTP_404_NOT_FOUND, "build not found", "not-found"
            )
        return Response(_serialize_build(row), status=status.HTTP_200_OK)


class PackerBuildFinalizeView(APIView):
    """`POST /v1/packer/build/<build_id>/finalize` — worker-only."""

    # P2 object-level authorization: worker-principal callback.
    object_scope = scoping.OPERATOR_ONLY

    permission_classes = [IsAuthenticated, IsPackerWorker]
    http_method_names = ["post", "options"]

    @extend_schema(
        summary="Finalize a Packer build (worker-only CAS)",
        description=(
            "Worker-only optimistic-concurrency transition. `to_state=running` "
            "claims the build; `succeeded` requires `artifact_sha256` + "
            "`provenance_signed_url`; `failed` carries `failure_reason`. A "
            "stale `if_version` returns 409 with the current row."
        ),
        tags=["Packer"],
        parameters=[_BUILD_ID_PARAM],
        request=PackerBuildFinalizeRequestSerializer,
        responses={
            200: PackerBuildSerializer,
            400: OpenApiResponse(ErrorSerializer, "Malformed body / illegal transition."),
            403: OpenApiResponse(ErrorSerializer, "Not the packer worker principal."),
            404: OpenApiResponse(ErrorSerializer, "Build not found."),
            409: OpenApiResponse(ErrorSerializer, "if_version stale (version conflict)."),
        },
    )
    def post(self, request: Request, build_id: str) -> Response:
        body = request.data
        if not isinstance(body, dict):
            return _error(
                status.HTTP_400_BAD_REQUEST,
                "request body must be a JSON object",
                "wire",
            )

        try:
            req = _parse_finalize(body)
        except FinalizeError as exc:
            return _error(status.HTTP_400_BAD_REQUEST, exc.message, exc.category)

        try:
            row = PackerBuild.objects.get(build_id=build_id)
        except PackerBuild.DoesNotExist:
            return _error(
                status.HTTP_404_NOT_FOUND, "build not found", "not-found"
            )

        from_state = PackerBuildState(row.state)
        if not legal(from_state, req.to_state):
            return _error(
                status.HTTP_400_BAD_REQUEST,
                f"illegal transition {from_state.value}→{req.to_state.value}",
                CAT_ILLEGAL,
            )

        try:
            required_args(req.to_state, req)
        except FinalizeError as exc:
            return _error(status.HTTP_400_BAD_REQUEST, exc.message, exc.category)

        patch = _patch_for_transition(req)

        # CAS: UPDATE … WHERE build_id AND version AND state.
        # Filtering on the full pre-image protects against a future
        # writer that mutates `state` without bumping `version`.
        with transaction.atomic():
            updated = PackerBuild.objects.filter(
                build_id=build_id,
                version=req.if_version,
                state=from_state.value,
            ).update(version=req.if_version + 1, **patch)
        if updated == 0:
            current = PackerBuild.objects.filter(build_id=build_id).first()
            return Response(
                {
                    "error": "if_version stale",
                    "category": "version-conflict",
                    "current": _serialize_build(current) if current else None,
                },
                status=status.HTTP_409_CONFLICT,
            )

        log.info(
            "packer build transition: build_id=%s %s→%s if_version=%s",
            build_id,
            from_state.value,
            req.to_state.value,
            req.if_version,
        )
        row = PackerBuild.objects.get(build_id=build_id)
        return Response(_serialize_build(row), status=status.HTTP_200_OK)


class PackerBuildPresignGetView(APIView):
    """`POST /v1/packer/build/<build_id>/presign-image-get`.

    Returns a presigned GET URL for the artifact on the configured
    images bucket — TTL `settings.VALI_PACKER_PRESIGN_TTL_SECS`
    (default 3600). Caller can override via `ttl_seconds` in the body
    (bounded by `apps.storage.s3.MAX_TTL_SECONDS`).

    Only Succeeded builds can be presigned — Queued/Running builds
    have no artifact yet (409); Failed builds never will (409).
    """

    # P2 object-level authorization: presigns a fleet image artifact.
    object_scope = scoping.OPERATOR_ONLY

    permission_classes = [IsAuthenticated]
    http_method_names = ["post", "options"]

    @extend_schema(
        summary="Presign a GET URL for a build artifact",
        description=(
            "Returns a presigned GET URL for a Succeeded build's artifact on "
            "the images bucket. Optional `ttl_seconds` overrides the default "
            "TTL. Only Succeeded builds have an artifact (409 otherwise)."
        ),
        tags=["Packer"],
        parameters=[_BUILD_ID_PARAM],
        request=PackerPresignRequestSerializer,
        responses={
            200: PackerPresignResponseSerializer,
            400: OpenApiResponse(ErrorSerializer, "Malformed body / bad ttl_seconds."),
            404: OpenApiResponse(ErrorSerializer, "Build not found."),
            409: OpenApiResponse(ErrorSerializer, "Build not in Succeeded state."),
            503: OpenApiResponse(ErrorSerializer, "S3 backend misconfigured/unreachable."),
        },
    )
    def post(self, request: Request, build_id: str) -> Response:
        # Wire-shape: only JSON objects are accepted. An empty body
        # (no JSON parsed) is fine — DRF surfaces it as an empty dict.
        # Anything else (list, scalar) is a wire error, consistent
        # with create / finalize.
        if request.data and not isinstance(request.data, dict):
            return _error(
                status.HTTP_400_BAD_REQUEST,
                "request body must be a JSON object",
                "wire",
            )
        body = request.data if isinstance(request.data, dict) else {}
        try:
            row = PackerBuild.objects.get(build_id=build_id)
        except PackerBuild.DoesNotExist:
            return _error(
                status.HTTP_404_NOT_FOUND, "build not found", "not-found"
            )

        if row.state != PackerBuildState.SUCCEEDED.value:
            return Response(
                {
                    "error": (
                        f"build is in state {row.state!r}; only Succeeded "
                        "builds have an artifact to presign"
                    ),
                    "category": "not-ready",
                    "current": _serialize_build(row),
                },
                status=status.HTTP_409_CONFLICT,
            )

        default_ttl = int(getattr(settings, "VALI_PACKER_PRESIGN_TTL_SECS", 3600))
        ttl_raw = body.get("ttl_seconds", default_ttl)
        if isinstance(ttl_raw, bool) or not isinstance(ttl_raw, int):
            return _error(
                status.HTTP_400_BAD_REQUEST,
                "ttl_seconds must be an integer",
                "wire",
            )

        bucket = getattr(settings, "VALI_PACKER_IMAGES_BUCKET", "hippius-compute-images")
        key = _image_key(row)

        try:
            client = s3_module.get_s3_client()
            presigned = client.presign_get(
                bucket=bucket,
                key=key,
                ttl_seconds=ttl_raw,
            )
        except ValueError as exc:
            return _error(status.HTTP_400_BAD_REQUEST, str(exc), "bad-field")
        except s3_module.S3ClientUnavailable as exc:
            log.error("S3 presign failed: %s", exc)
            return _error(
                status.HTTP_503_SERVICE_UNAVAILABLE,
                str(exc),
                "internal",
            )

        log.info(
            "packer image presign: build_id=%s key=%s ttl=%d requested_by=%s",
            build_id,
            key,
            ttl_raw,
            request.user.name,
        )
        return Response(
            {
                "build_id": build_id,
                "url": presigned.url,
                "method": presigned.method,
                "expires_at_unix": presigned.expires_at_unix,
                "bucket": bucket,
                "key": key,
                "artifact_sha256": row.artifact_sha256,
            },
            status=status.HTTP_200_OK,
        )


# ─── Helpers ────────────────────────────────────────────────────────


def _parse_finalize(body: dict[str, Any]) -> FinalizeRequest:
    """Strict JSON → `FinalizeRequest`."""
    if "to_state" not in body:
        raise FinalizeError("missing 'to_state'", "wire")
    if "if_version" not in body:
        raise FinalizeError("missing 'if_version'", "wire")
    try:
        to_state = PackerBuildState(body["to_state"])
    except ValueError as exc:
        raise FinalizeError(
            f"unknown to_state {body['to_state']!r}", "wire"
        ) from exc
    if_version = _coerce_int(body["if_version"], "if_version")
    if if_version < 1:
        raise FinalizeError("if_version must be ≥ 1", "wire")

    artifact = body.get("artifact_sha256")
    if artifact is not None and not isinstance(artifact, str):
        raise FinalizeError("artifact_sha256 must be a string", "wire")
    provenance = body.get("provenance_signed_url")
    if provenance is not None and not isinstance(provenance, str):
        raise FinalizeError("provenance_signed_url must be a string", "wire")
    if provenance is not None and len(provenance) > 2048:
        # Bound the stored URL — matches `PackerBuild.provenance_signed_url`
        # max_length. Reject at parse so the DB INSERT doesn't error.
        raise FinalizeError(
            "provenance_signed_url exceeds 2048 chars", CAT_BAD_FIELD
        )
    failure_reason = body.get("failure_reason")
    if failure_reason is not None and not isinstance(failure_reason, str):
        raise FinalizeError("failure_reason must be a string", "wire")
    if failure_reason is not None and len(failure_reason) > 256:
        raise FinalizeError(
            "failure_reason exceeds 256 chars", CAT_BAD_FIELD
        )

    return FinalizeRequest(
        to_state=to_state,
        if_version=if_version,
        artifact_sha256=artifact,
        provenance_signed_url=provenance,
        failure_reason=failure_reason,
    )


def _coerce_int(value: Any, field: str) -> int:
    """Strict JSON-integer coercion (rejects bool, float, str)."""
    if isinstance(value, bool):
        raise FinalizeError(f"{field} must be an integer (got bool)", "wire")
    if not isinstance(value, int):
        raise FinalizeError(f"{field} must be an integer", "wire")
    return value


def _patch_for_transition(req: FinalizeRequest) -> dict[str, Any]:
    """Build the `UPDATE … SET …` patch for a legal transition.

    Atomic with the CAS so a stale writer can't overwrite the
    timestamps + artifact fields after another writer has already
    flipped the row.
    """
    from django.utils import timezone

    patch: dict[str, Any] = {"state": req.to_state.value}
    if req.to_state == PackerBuildState.RUNNING:
        patch["started_at"] = timezone.now()
    elif req.to_state == PackerBuildState.SUCCEEDED:
        patch["finished_at"] = timezone.now()
        # `required_args` already guaranteed both are non-empty.
        patch["artifact_sha256"] = req.artifact_sha256
        patch["provenance_signed_url"] = req.provenance_signed_url
    elif req.to_state == PackerBuildState.FAILED:
        patch["finished_at"] = timezone.now()
        patch["failure_reason"] = req.failure_reason
    return patch


def _in_flight_conflict_response(conflict: PackerBuild) -> Response:
    """Render the 409 body for a "one active build per image_kind"
    collision. Used by both the pre-check (cached, common path) and
    the IntegrityError post-check (race path) so the wire contract
    is identical regardless of which branch caught it.
    """
    return Response(
        {
            "error": (
                f"a build for image_kind={conflict.image_kind!r} is "
                f"already {conflict.state} (build_id={conflict.build_id})"
            ),
            "category": "already-in-flight",
            "active": _serialize_build(conflict),
        },
        status=status.HTTP_409_CONFLICT,
    )


def _serialize_build(row: PackerBuild) -> dict[str, Any]:
    """Render a `PackerBuild` row as the wire response."""
    return {
        "build_id": row.build_id,
        "image_kind": row.image_kind,
        "state": row.state,
        "requested_by": row.requested_by.name,
        "requested_at": row.requested_at.isoformat() if row.requested_at else None,
        "started_at": row.started_at.isoformat() if row.started_at else None,
        "finished_at": row.finished_at.isoformat() if row.finished_at else None,
        "artifact_sha256": row.artifact_sha256 or None,
        "provenance_signed_url": row.provenance_signed_url or None,
        "failure_reason": row.failure_reason or None,
        "version": row.version,
    }


def _mint_build_id() -> str:
    """32-hex-char id from CSPRNG. Stable, opaque, URL-safe."""
    return secrets.token_hex(16)


def _image_key(row: PackerBuild) -> str:
    """S3 key for a Succeeded build's artifact.

    Format: `<image_kind>/<artifact_sha256>.img`. Putting the digest
    in the key path means the same row's URL always resolves to the
    same byte-exact object even if the bucket isn't versioned — and
    if the bucket IS versioned, this scheme cohabits cleanly with
    `version_id`-scoped presigns once the Hippius S3 cluster
    exposes that knob.
    """
    return f"{row.image_kind}/{row.artifact_sha256}.img"


def _error(http_status: int, message: str, category: str) -> Response:
    return Response(
        {"error": message, "category": category}, status=http_status
    )
