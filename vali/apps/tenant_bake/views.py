"""Per-tenant bake trigger surface.

Endpoints:

  POST /v1/tenant-bakes
      Body: { "vm_id": "...",
              "base_image_url": "https://...",
              "base_image_sha256": "<64 hex>",
              "size_gb": int,
              "kek_vault_path": "secret/.../luks-kek",
              "s3_output_bucket": "...",
              "s3_output_prefix": "tenant/<vm_id>/" }
      Auth: any ServiceClient.
      → 202 with the new row's bake_id + state.
      → 409 if a Queued/Running row already exists for vm_id.
      → 400 on wire / shape error.

  GET /v1/tenant-bakes/<bake_id>
      Auth: any ServiceClient.
      → 200 with the row's serialized form.
      → 404 if unknown.

  POST /v1/tenant-bakes/<bake_id>/finalize
      Body: {"to_state":"succeeded","if_version":N,
             "qcow2_sha256":"…","kernel_sha256":"…",
             "initrd_sha256":"…","measurement_hex":"…"}
        OR  {"to_state":"failed","if_version":N,"failure_reason":"…"}
        OR  {"to_state":"running","if_version":N}     (worker claim)
      Auth: VALI_TENANT_BAKE_WORKER_PRINCIPAL ONLY.
      → 200 / 400 / 409 with the optimistic-concurrency CAS pattern
        used by `apps.packer`.
"""

from __future__ import annotations

import ipaddress
import logging
import re
import secrets
import socket
from typing import Any
from urllib.parse import unquote, urlsplit

from django.db import IntegrityError, transaction
from drf_spectacular.utils import OpenApiParameter, OpenApiResponse, extend_schema
from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from rest_framework.request import Request
from rest_framework.response import Response
from rest_framework.views import APIView

from apps.common.schemas import ErrorSerializer
from apps.identity import scoping

from .locks import bake_queue_lock
from .models import (
    IN_FLIGHT_STATES,
    TenantBake,
    TenantBakeDiskMode,
    TenantBakeState,
)
from .permissions import IsTenantBakeWorker
from .schemas import (
    TenantBakeCreateSerializer,
    TenantBakeFinalizeSerializer,
    TenantBakeInFlightConflictSerializer,
    TenantBakeSerializer,
    TenantBakeVersionConflictSerializer,
)
from .state_machine import (
    CAT_BAD_FIELD,
    CAT_ILLEGAL,
    FinalizeError,
    FinalizeRequest,
    legal,
    required_args,
)

log = logging.getLogger("apps.tenant_bake.views")

_BAKE_ID_PARAM = OpenApiParameter(
    "bake_id",
    str,
    OpenApiParameter.PATH,
    description="Public bake identifier returned by `POST /v1/tenant-bakes`.",
)

# ── Wire-shape validators ─────────────────────────────────────────

# Lowercase 64-hex SHA-256.
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
# `vm_id` accepts the same character set as the OrderTicket (§6) —
# lowercase ASCII alnum + `-`, 1-64 chars. Restricting at the API
# boundary keeps a hostile peer from inserting path-injecting bytes
# into the S3 prefix or shell-active bytes into the baker's argv.
_VM_ID_RE = re.compile(r"^[a-z0-9-]{1,64}$")


class TenantBakeCreateView(APIView):
    """`POST /v1/tenant-bakes` — request a new bake."""

    # P2 object-level authorization: a bake is a fleet artifact, not a
    # tenant-owned object.
    object_scope = scoping.OPERATOR_ONLY

    permission_classes = [IsAuthenticated]
    # Per-client rate limit (audit M-ratelimit): each bake spawns a k8s
    # Job, so this endpoint is the abuse surface (any authenticated client
    # can reach it). Rate = `bake_create` scope in REST_FRAMEWORK.
    throttle_scope = "bake_create"
    http_method_names = ["post", "options"]

    @extend_schema(
        summary="Request a new per-tenant bake",
        description=(
            "Any authenticated ServiceClient. Queues a per-tenant encrypted-"
            "qcow2 bake row (the baker k8s Job is spawned asynchronously by "
            "the `vali_bake_spawn` worker). Enforces one active bake per "
            "`vm_id`."
        ),
        tags=["Tenant bakes"],
        request=TenantBakeCreateSerializer,
        responses={
            202: OpenApiResponse(TenantBakeSerializer, "Bake queued."),
            400: OpenApiResponse(ErrorSerializer, "Malformed body / bad field."),
            409: OpenApiResponse(
                TenantBakeInFlightConflictSerializer,
                "A Queued/Running bake already exists for this vm_id.",
            ),
            503: OpenApiResponse(ErrorSerializer, "Internal bake_id collision."),
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
            parsed = _parse_create(body)
        except FinalizeError as exc:
            # `_parse_create` reuses `FinalizeError` for symmetry with
            # the finalize parser; the category vocabulary is the same.
            return _error(status.HTTP_400_BAD_REQUEST, exc.message, exc.category)

        # "One active bake per vm_id" — enforced by a partial unique
        # index on the model. Two concurrent POSTs can both observe
        # zero in-flight rows on the pre-check, but at most ONE will
        # pass the INSERT; the loser sees `IntegrityError`, which we
        # turn into a 409 with the surviving row attached. The
        # pre-check is still useful: it surfaces 409 without paying
        # the wasted-INSERT cost on the common (cached) path.
        try:
            # `bake_queue_lock` (a transaction of its own) orders this INSERT
            # against the golden re-bake's check-then-insert (F6).
            with bake_queue_lock():
                conflict = TenantBake.objects.filter(
                    vm_id=parsed["vm_id"],
                    state__in=list(IN_FLIGHT_STATES),
                ).first()
                if conflict is not None:
                    return _in_flight_conflict_response(conflict)
                row = TenantBake.objects.create(
                    bake_id=_mint_bake_id(),
                    state=TenantBakeState.QUEUED.value,
                    requested_by=request.user,
                    **parsed,
                )
        except IntegrityError:
            # Either the partial unique index (concurrent POST won the
            # race) or the `bake_id` unique column (astronomically
            # unlikely CSPRNG collision). Re-read the in-flight row;
            # if it exists, the race is the cause and we 409.
            # Otherwise the collision is the cause and we 503.
            conflict = TenantBake.objects.filter(
                vm_id=parsed["vm_id"],
                state__in=list(IN_FLIGHT_STATES),
            ).first()
            if conflict is not None:
                log.info(
                    "tenant_bake race lost: vm_id=%s winner=%s",
                    parsed["vm_id"],
                    conflict.bake_id,
                )
                return _in_flight_conflict_response(conflict)
            log.exception("TenantBake bake_id collision")
            return _error(
                status.HTTP_503_SERVICE_UNAVAILABLE,
                "internal: bake_id collision",
                "internal",
            )

        log.info(
            "tenant_bake queued: bake_id=%s vm_id=%s requested_by=%s",
            row.bake_id,
            row.vm_id,
            request.user.name,
        )

        # RA-N9 — the baker k8s Job is spawned ASYNCHRONOUSLY by the
        # dedicated `vali_bake_spawn` worker, NOT here. The row is the
        # source of truth (a 202 means the bake is tracked + Queued); the
        # worker polls Queued rows and calls the idempotent
        # `spawn_bake_job`. This keeps the k8s `create jobs` capability
        # (→ a privileged bake Job → node escalation) OFF this large
        # HTTP/Django attack surface and confined to a minimal poll-loop
        # worker (see deployment-bake-spawner + rbac-tenant-bake). The
        # vali web pod therefore mounts no ServiceAccount token.
        return Response(
            _serialize_bake(row),
            status=status.HTTP_202_ACCEPTED,
        )


class TenantBakeDetailView(APIView):
    """`GET /v1/tenant-bakes/<bake_id>` — current row."""

    # P2 object-level authorization: a bake is a fleet artifact, not a
    # tenant-owned object.
    object_scope = scoping.OPERATOR_ONLY

    permission_classes = [IsAuthenticated]
    http_method_names = ["get", "options"]

    @extend_schema(
        summary="Fetch a tenant bake",
        description="Any authenticated ServiceClient. Returns the current bake row.",
        tags=["Tenant bakes"],
        parameters=[_BAKE_ID_PARAM],
        responses={
            200: OpenApiResponse(TenantBakeSerializer, "The bake row."),
            404: OpenApiResponse(ErrorSerializer, "Bake not found."),
        },
    )
    def get(self, request: Request, bake_id: str) -> Response:
        try:
            row = TenantBake.objects.get(bake_id=bake_id)
        except TenantBake.DoesNotExist:
            return _error(status.HTTP_404_NOT_FOUND, "bake not found", "not-found")
        return Response(_serialize_bake(row), status=status.HTTP_200_OK)


class TenantBakeFinalizeView(APIView):
    """`POST /v1/tenant-bakes/<bake_id>/finalize` — worker-only."""

    # P2 object-level authorization: worker-principal callback.
    object_scope = scoping.OPERATOR_ONLY

    permission_classes = [IsAuthenticated, IsTenantBakeWorker]
    http_method_names = ["post", "options"]

    @extend_schema(
        summary="Finalize a tenant bake (worker CAS)",
        description=(
            "Worker principal only (`VALI_TENANT_BAKE_WORKER_PRINCIPAL`). "
            "Applies an optimistic-concurrency transition guarded by "
            "`if_version`: queued→running (claim), running→succeeded (all "
            "three artefact SHAs) or running→failed (`failure_reason`)."
        ),
        tags=["Tenant bakes"],
        parameters=[_BAKE_ID_PARAM],
        request=TenantBakeFinalizeSerializer,
        responses={
            200: OpenApiResponse(TenantBakeSerializer, "Transition applied."),
            400: OpenApiResponse(
                ErrorSerializer, "Malformed body / illegal transition / missing field."
            ),
            404: OpenApiResponse(ErrorSerializer, "Bake not found."),
            409: OpenApiResponse(
                TenantBakeVersionConflictSerializer, "`if_version` is stale."
            ),
        },
    )
    def post(self, request: Request, bake_id: str) -> Response:
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
            row = TenantBake.objects.get(bake_id=bake_id)
        except TenantBake.DoesNotExist:
            return _error(status.HTTP_404_NOT_FOUND, "bake not found", "not-found")

        from_state = TenantBakeState(row.state)
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

        with transaction.atomic():
            updated = TenantBake.objects.filter(
                bake_id=bake_id,
                version=req.if_version,
                state=from_state.value,
            ).update(version=req.if_version + 1, **patch)
        if updated == 0:
            current = TenantBake.objects.filter(bake_id=bake_id).first()
            return Response(
                {
                    "error": "if_version stale",
                    "category": "version-conflict",
                    "current": _serialize_bake(current) if current else None,
                },
                status=status.HTTP_409_CONFLICT,
            )

        log.info(
            "tenant_bake transition: bake_id=%s %s→%s if_version=%s",
            bake_id,
            from_state.value,
            req.to_state.value,
            req.if_version,
        )
        row = TenantBake.objects.get(bake_id=bake_id)
        return Response(_serialize_bake(row), status=status.HTTP_200_OK)


# ─── Helpers ────────────────────────────────────────────────────────


# base_image_url is attacker-influenced (an authenticated tenant supplies
# it) and the baker Job performs a server-side GET on it. Only http(s) are
# fetchable schemes; anything else (file://, gopher://, …) is refused.
_ALLOWED_IMAGE_URL_SCHEMES = ("https", "http")

# ── Mutable-path guard (register #48) ──────────────────────────────
#
# Path-segment names upstream mirrors use for a MOVING pointer — a symlink
# or rewrite that retargets whenever upstream publishes. Matched
# case-insensitively against a WHOLE segment, never as a substring, so a
# legitimate name that merely contains one of these (`latestimages/`,
# `translated/`, `nostable/`) is untouched: a gate that refuses valid URLs
# gets switched off, and then it protects nothing.
#
# Scope note: this is a denylist of documented moving-pointer conventions,
# not an allowlist of "looks versioned". Immutability cannot be proven from
# a path — `/images/base.qcow2` may well be write-once — so requiring a
# date/version token would refuse mountains of legitimate URLs to catch
# nothing extra. What actually bit us was a URL upstream ITSELF documents
# as moving; that is exactly what this list names.
_MUTABLE_PATH_SEGMENTS = frozenset(
    {
        "latest",
        "current",
        "newest",
        "daily",
        "dailies",
        "nightly",
        "weekly",
        "monthly",
        "rolling",
        "rawhide",
        "development",
        "stable",
        "oldstable",
        "testing",
        "unstable",
    }
)

# The FINAL path segment (the filename) is additionally split on `-`, `_`
# and `.` before matching, because mirrors spell the moving pointer as a
# filename token rather than a directory:
#   CentOS-Stream-GenericCloud-10-latest.x86_64.qcow2
# Directory segments are NOT token-split — `noble/20260801/` legitimately
# carries an UNVERSIONED filename (`noble-server-cloudimg-amd64.img`) and
# is perfectly immutable, so "the filename must look versioned" is a wrong
# rule that would refuse Ubuntu's dated directories outright.
_FILENAME_TOKEN_SPLIT = re.compile(r"[-_.]+")


def _find_mutable_path_segment(url: str) -> str | None:
    """Return the moving-pointer path segment in `url`, or None.

    Split out from the assertion so the rule is unit-testable on its own
    and reads as a predicate at the call site.
    """
    path = urlsplit(url).path
    segments = [unquote(seg) for seg in path.split("/") if seg]
    if not segments:
        return None
    for seg in segments[:-1]:
        if seg.lower() in _MUTABLE_PATH_SEGMENTS:
            return seg
    filename = segments[-1]
    if filename.lower() in _MUTABLE_PATH_SEGMENTS:
        return filename
    for token in _FILENAME_TOKEN_SPLIT.split(filename):
        if token.lower() in _MUTABLE_PATH_SEGMENTS:
            return token
    return None


def _assert_base_image_url_immutable(url: str) -> None:
    """Refuse a `base_image_url` that points at a MOVING upstream path
    (register #48).

    `base_image_sha256` pins exact bytes; a path segment like `latest/`
    pins "whatever upstream published most recently". Held together they
    are a contradiction that detonates on the next upstream point release
    — and the resulting integrity-check failure is indistinguishable from
    a supply-chain compromise. That ambiguity is the expensive part: it
    cost this programme three cycles of treating a routine Debian point
    release as a possible attack, while the bytes we had already vetted sat
    unchanged at the dated URL the whole time.

    Deliberately runs FIRST — before the SSRF guard's DNS resolution, and
    long before the baker Job pulls ~2 GB. A bake that CANNOT succeed is
    refused without touching the network at all.
    """
    segment = _find_mutable_path_segment(url)
    if segment is None:
        return
    raise FinalizeError(
        f"base_image_url path segment {segment!r} is a MOVING upstream "
        "pointer, so it cannot carry a base_image_sha256 pin: the hash "
        "names exact bytes, the segment names 'whatever is newest'. Every "
        "upstream point release then breaks the bake, and the failure "
        "looks like a compromise when it is not. Mirrors keep each release "
        "in a dated, immutable directory — e.g. "
        ".../trixie/20260712-2537/debian-13-genericcloud-amd64-20260712-2537.qcow2 "
        "— so re-point base_image_url at the dated URL that serves the "
        "bytes you already vetted and keep base_image_sha256 UNCHANGED. "
        "Only if an immutable URL stops matching its hash is this a real "
        "supply-chain event.",
        CAT_BAD_FIELD,
    )


def _assert_base_image_url_safe(url: str) -> None:
    """Reject an SSRF-prone `base_image_url` before it is stored/dispatched
    to the baker (audit M-SSRF).

    The baker fetches this URL server-side, so a URL resolving to a
    private / loopback / link-local address could reach the cloud metadata
    endpoint (169.254.169.254) or internal RFC-1918 services — even though
    the image is SHA256-pinned, the *request* itself is the SSRF. Require
    an http(s) scheme with no embedded credentials, and reject any host
    that resolves to a non-public IP. Every resolved A/AAAA record is
    checked, so a host returning one public + one private address cannot
    slip a private target through.
    """
    try:
        parts = urlsplit(url)
        # `.port` parses the netloc port and raises ValueError on a bad one.
        port = parts.port
    except ValueError as exc:
        raise FinalizeError("base_image_url is malformed", CAT_BAD_FIELD) from exc
    if parts.scheme not in _ALLOWED_IMAGE_URL_SCHEMES:
        raise FinalizeError(
            "base_image_url scheme must be http or https",
            CAT_BAD_FIELD,
        )
    if parts.username or parts.password:
        raise FinalizeError(
            "base_image_url must not embed credentials", CAT_BAD_FIELD
        )
    host = parts.hostname
    if not host:
        raise FinalizeError("base_image_url has no host", CAT_BAD_FIELD)
    try:
        infos = socket.getaddrinfo(host, port or None, proto=socket.IPPROTO_TCP)
    except (socket.gaierror, UnicodeError) as exc:
        raise FinalizeError(
            "base_image_url host does not resolve", CAT_BAD_FIELD
        ) from exc
    for info in infos:
        ip = ipaddress.ip_address(info[4][0])
        if (
            ip.is_private
            or ip.is_loopback
            or ip.is_link_local
            or ip.is_reserved
            or ip.is_multicast
            or ip.is_unspecified
        ):
            raise FinalizeError(
                "base_image_url resolves to a non-public address "
                "(private / loopback / link-local / metadata blocked)",
                CAT_BAD_FIELD,
            )


def _parse_create(body: dict[str, Any]) -> dict[str, Any]:
    """Strict JSON → dict of model-field kwargs.

    Validates wire shape + URL/sha/path lengths. Does NOT touch the
    DB; callers wrap in `transaction.atomic()`.
    """
    required_str = (
        "vm_id",
        "base_image_url",
        "base_image_sha256",
        "kek_vault_path",
        "s3_output_bucket",
        "s3_output_prefix",
    )
    out: dict[str, Any] = {}
    for field in required_str:
        if field not in body:
            raise FinalizeError(f"missing field {field!r}", "wire")
        value = body[field]
        if not isinstance(value, str) or not value:
            raise FinalizeError(f"{field} must be a non-empty string", "wire")
        out[field] = value

    if not _VM_ID_RE.fullmatch(out["vm_id"]):
        raise FinalizeError(
            "vm_id must be 1-64 chars of [a-z0-9-]", CAT_BAD_FIELD
        )
    if not _SHA256_RE.match(out["base_image_sha256"]):
        raise FinalizeError(
            "base_image_sha256 must be 64 lowercase hex chars", CAT_BAD_FIELD
        )
    # Practical URL length cap (matches the model field length). Goes
    # in `URLField` which Django runs through `URLValidator`; an
    # invalid URL would surface at `objects.create` time as
    # `ValidationError`. We pre-check the length here to give a
    # clearer 400 instead of a 500.
    if len(out["base_image_url"]) > 2048:
        raise FinalizeError(
            "base_image_url exceeds 2048 chars", CAT_BAD_FIELD
        )
    # Mutable-path guard (register #48). Ordered BEFORE the SSRF guard on
    # purpose: it is pure string work, so a bake that can never succeed is
    # refused without a DNS lookup, let alone the baker's ~2 GB fetch.
    _assert_base_image_url_immutable(out["base_image_url"])
    # SSRF guard (audit M-SSRF): the baker fetches this URL server-side.
    _assert_base_image_url_safe(out["base_image_url"])
    if len(out["kek_vault_path"]) > 512:
        raise FinalizeError(
            "kek_vault_path exceeds 512 chars", CAT_BAD_FIELD
        )
    if len(out["s3_output_bucket"]) > 256:
        raise FinalizeError(
            "s3_output_bucket exceeds 256 chars", CAT_BAD_FIELD
        )
    if len(out["s3_output_prefix"]) > 512:
        raise FinalizeError(
            "s3_output_prefix exceeds 512 chars", CAT_BAD_FIELD
        )

    if "size_gb" not in body:
        raise FinalizeError("missing field 'size_gb'", "wire")
    size_gb = body["size_gb"]
    if isinstance(size_gb, bool) or not isinstance(size_gb, int):
        raise FinalizeError("size_gb must be an integer", "wire")
    if size_gb <= 0:
        raise FinalizeError("size_gb must be > 0", CAT_BAD_FIELD)
    out["size_gb"] = size_gb

    # golden-bake PR6 — optional boot-disk packaging mode. Absent ⇒
    # `legacy_luks` (the pre-golden default), so every existing caller is
    # byte-identical. `golden_verity_overlay` bakes a shared, non-
    # confidential dm-verity base (no qcow2, no per-VM KEK).
    disk_mode = body.get("disk_mode", TenantBakeDiskMode.LEGACY_LUKS.value)
    if disk_mode not in TenantBakeDiskMode.values:
        raise FinalizeError(
            "disk_mode must be 'legacy_luks' or 'golden_verity_overlay'",
            CAT_BAD_FIELD,
        )
    out["disk_mode"] = disk_mode

    # Reject any unknown field — caught early so a typo doesn't
    # silently drop on the floor.
    allowed = set(required_str) | {"size_gb", "disk_mode"}
    extras = set(body.keys()) - allowed
    if extras:
        raise FinalizeError(
            f"unknown field(s): {sorted(extras)!r}", "wire"
        )

    return out


def _parse_finalize(body: dict[str, Any]) -> FinalizeRequest:
    """Strict JSON → `FinalizeRequest`."""
    if "to_state" not in body:
        raise FinalizeError("missing 'to_state'", "wire")
    if "if_version" not in body:
        raise FinalizeError("missing 'if_version'", "wire")
    try:
        to_state = TenantBakeState(body["to_state"])
    except ValueError as exc:
        raise FinalizeError(
            f"unknown to_state {body['to_state']!r}", "wire"
        ) from exc
    if_version = _coerce_int(body["if_version"], "if_version")
    if if_version < 1:
        raise FinalizeError("if_version must be ≥ 1", "wire")

    optional_str = (
        "qcow2_sha256",
        "kernel_sha256",
        "initrd_sha256",
        "luks_header_sha256",
        "measurement_hex",
        # golden-bake PR6 — a golden bake reports these INSTEAD of qcow2.
        "rootfs_img_sha256",
        "rootfs_verity_sha256",
        "verity_root_hash",
        "failure_reason",
    )
    parsed: dict[str, str | None] = {}
    for field in optional_str:
        value = body.get(field)
        if value is not None and not isinstance(value, str):
            raise FinalizeError(f"{field} must be a string", "wire")
        parsed[field] = value

    # failure_reason bounded by the model's max_length=256.
    if parsed["failure_reason"] is not None and len(parsed["failure_reason"]) > 256:
        raise FinalizeError("failure_reason exceeds 256 chars", CAT_BAD_FIELD)

    # Reject unknown fields so a typo'd `qcow_sha256` doesn't drop
    # silently into the void of "no-op finalize that still flips state".
    allowed = set(optional_str) | {"to_state", "if_version"}
    extras = set(body.keys()) - allowed
    if extras:
        raise FinalizeError(f"unknown field(s): {sorted(extras)!r}", "wire")

    return FinalizeRequest(
        to_state=to_state,
        if_version=if_version,
        qcow2_sha256=parsed["qcow2_sha256"],
        kernel_sha256=parsed["kernel_sha256"],
        initrd_sha256=parsed["initrd_sha256"],
        luks_header_sha256=parsed["luks_header_sha256"],
        measurement_hex=parsed["measurement_hex"],
        rootfs_img_sha256=parsed["rootfs_img_sha256"],
        rootfs_verity_sha256=parsed["rootfs_verity_sha256"],
        verity_root_hash=parsed["verity_root_hash"],
        failure_reason=parsed["failure_reason"],
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
    if req.to_state == TenantBakeState.RUNNING:
        patch["started_at"] = timezone.now()
    elif req.to_state == TenantBakeState.SUCCEEDED:
        patch["finished_at"] = timezone.now()
        # `required_args` already validated the mode-appropriate fields.
        # kernel + initrd are present in both modes. The boot-disk fields
        # are mutually exclusive: a LEGACY bake sets `qcow2_sha256`; a
        # GOLDEN bake sets the three dm-verity fields (and NO qcow2). The
        # "" coalesce keeps the NOT-NULL columns of the OTHER mode empty.
        patch["kernel_sha256"] = req.kernel_sha256
        patch["initrd_sha256"] = req.initrd_sha256
        patch["qcow2_sha256"] = req.qcow2_sha256 or ""
        patch["rootfs_img_sha256"] = req.rootfs_img_sha256 or ""
        patch["rootfs_verity_sha256"] = req.rootfs_verity_sha256 or ""
        patch["verity_root_hash"] = req.verity_root_hash or ""
        # #587 Phase 1C — the LUKS2-header MAC the bake→launch resolver
        # feeds into the launch spec. Optional (bakers predating this
        # field send no value); "" is the model's empty convention.
        patch["luks_header_sha256"] = req.luks_header_sha256 or ""
        # measurement_hex is optional on Succeeded (the bake cannot
        # know the SNP launch digest — see state_machine.py). The
        # model's empty-value convention is "" (NOT NULL column), so
        # coalesce an absent field; a bare None here 500s the
        # IntegrityError path (observed live 2026-06-10, take-12 —
        # the bake's FIRST fully-green run died at the last POST).
        patch["measurement_hex"] = req.measurement_hex or ""
    elif req.to_state == TenantBakeState.FAILED:
        patch["finished_at"] = timezone.now()
        patch["failure_reason"] = req.failure_reason
    return patch


def _in_flight_conflict_response(conflict: TenantBake) -> Response:
    """Render the 409 body for a "one active bake per vm_id" collision.

    Used by both the pre-check (cached, common path) and the
    IntegrityError post-check (race path) so the wire contract is
    identical regardless of which branch caught it.
    """
    return Response(
        {
            "error": (
                f"a bake for vm_id={conflict.vm_id!r} is already "
                f"{conflict.state} (bake_id={conflict.bake_id})"
            ),
            "category": "already-in-flight",
            "active": _serialize_bake(conflict),
        },
        status=status.HTTP_409_CONFLICT,
    )


def _serialize_bake(row: TenantBake) -> dict[str, Any]:
    """Render a `TenantBake` row as the wire response."""
    return {
        "bake_id": row.bake_id,
        "vm_id": row.vm_id,
        "base_image_url": row.base_image_url,
        "base_image_sha256": row.base_image_sha256,
        "size_gb": row.size_gb,
        "kek_vault_path": row.kek_vault_path,
        "s3_output_bucket": row.s3_output_bucket,
        "s3_output_prefix": row.s3_output_prefix,
        "disk_mode": row.disk_mode,
        "state": row.state,
        "requested_by": row.requested_by.name,
        "requested_at": row.requested_at.isoformat() if row.requested_at else None,
        "started_at": row.started_at.isoformat() if row.started_at else None,
        "finished_at": row.finished_at.isoformat() if row.finished_at else None,
        "qcow2_sha256": row.qcow2_sha256 or None,
        "kernel_sha256": row.kernel_sha256 or None,
        "initrd_sha256": row.initrd_sha256 or None,
        "rootfs_img_sha256": row.rootfs_img_sha256 or None,
        "rootfs_verity_sha256": row.rootfs_verity_sha256 or None,
        "verity_root_hash": row.verity_root_hash or None,
        "measurement_hex": row.measurement_hex or None,
        "failure_reason": row.failure_reason or None,
        "version": row.version,
    }


def _mint_bake_id() -> str:
    """32-hex-char id from CSPRNG. Stable, opaque, URL-safe."""
    return secrets.token_hex(16)


def _error(http_status: int, message: str, category: str) -> Response:
    return Response(
        {"error": message, "category": category}, status=http_status
    )
