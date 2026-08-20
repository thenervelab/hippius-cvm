"""Miner-fleet registry endpoints — PR-vali-miner-register.

  POST /v1/admin/miner/register
      Auth: ServiceToken, the miner-admin principal.
      Body (JSON): {miner_id, pubkey_hex, platform_id,
                    netbird_peer_id?, netbird_ip?}.
      Atomically creates a `MinerIdentity` AND its linked
      `telemetry.TelemetrySource` (so the §9 broker accepts the
      miner's signed envelopes). Idempotent: re-registering the
      identical (miner_id, pubkey_hex, platform_id) returns 200 with
      the stored row. A miner_id re-registered with different key
      material — or a pubkey_hex / platform_id that collides with a
      DIFFERENT miner — returns 409.
      → 201 created / 200 idempotent / 400 wire / 403 / 409 conflict.

  GET /v1/admin/miner/list?limit=<N>&offset=<M>
      Auth: ServiceToken, any authenticated ServiceClient (read-only).
      Offset-paginated registry listing, ordered by `miner_id`.
      → 200 {miners, count, limit, offset} / 400 wire / 403.

  POST /v1/admin/miner/<miner_id>/quarantine
      Auth: ServiceToken, the miner-admin principal.
      Marks the miner `quarantined` and deactivates its linked
      `TelemetrySource` — the §9 broker then refuses its telemetry.
      → 200 {miner_id, status} / 403 / 404.

The miner registry is the trust anchor for miner-signed telemetry; it
is never derived from a miner's self-report (§13/§23).
"""

from __future__ import annotations

import ipaddress
import logging
from typing import Any

from django.conf import settings
from django.db import IntegrityError, connection, transaction
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
from apps.identity.authentication import ServiceTokenAuthentication
from apps.telemetry import verifier
from apps.telemetry.models import TelemetrySource

from .models import TELEMETRY_SOURCE_KIND, MinerIdentity, MinerStatus
from .permissions import IsMinerAdmin
from .schemas import (
    MinerGracefulExitResponseSerializer,
    MinerIdentitySerializer,
    MinerListSerializer,
    MinerQuarantineResponseSerializer,
    MinerRegisterRequestSerializer,
)

log = logging.getLogger("apps.miners")

_MINER_ID_PARAM = OpenApiParameter(
    "miner_id", str, OpenApiParameter.PATH, description="Target miner id."
)

# Offset-pagination bounds for the list endpoint.
_DEFAULT_LIMIT = 100
_MAX_LIMIT = 500

# An Ed25519 public key is 32 bytes ⇒ 64 hex chars.
_PUBKEY_HEX_LEN = 64


class _WireError(Exception):
    """A request failed a shape check. Carries the HTTP status."""

    def __init__(
        self, message: str, category: str = "wire", http_status: int = 400
    ) -> None:
        super().__init__(message)
        self.message = message
        self.category = category
        self.http_status = http_status


# ─── POST /v1/admin/miner/register ───────────────────────────────────


class MinerRegisterView(APIView):
    """`POST /v1/admin/miner/register` — register one miner identity."""

    authentication_classes = [ServiceTokenAuthentication]
    # P2 object-level authorization: mutates the fleet trust anchor.
    object_scope = scoping.OPERATOR_ONLY
    permission_classes = [IsAuthenticated, IsMinerAdmin]
    http_method_names = ["post", "options"]

    @extend_schema(
        summary="Register a miner identity",
        description=(
            "Miner-admin only. Atomically creates a `MinerIdentity` and its "
            "linked telemetry source. Idempotent: re-registering identical "
            "key material returns 200 with the stored row; a mismatched key / "
            "platform / chain_node_id is a 409 conflict."
        ),
        tags=["Miners"],
        request=MinerRegisterRequestSerializer,
        responses={
            201: MinerIdentitySerializer,
            200: MinerIdentitySerializer,
            400: OpenApiResponse(ErrorSerializer, "Malformed body / bad field."),
            403: OpenApiResponse(ErrorSerializer, "Not the miner-admin principal."),
            409: OpenApiResponse(
                ErrorSerializer,
                "miner_id / pubkey_hex / platform_id / chain_node_id conflict.",
            ),
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
            miner_id = _require_str(body, "miner_id", max_len=64)
            pubkey_hex = _require_pubkey_hex(body, "pubkey_hex")
            platform_id = _require_str(body, "platform_id", max_len=128)
            netbird_peer_id = _optional_str(body, "netbird_peer_id", max_len=64)
            netbird_ip = _optional_ip(body, "netbird_ip")
            # Optional bridge to the §23 scheduler's on-chain identity —
            # the 64-hex compute node_id the launch pipeline joins on to
            # recover this miner from a placement (see model docstring).
            chain_node_id = _optional_chain_node_id(body, "chain_node_id")
        except _WireError as exc:
            return _error(exc.http_status, exc.message, exc.category)

        # The whole register runs in one transaction, with the
        # `MinerIdentity` row locked (`_lock_miner`): register and
        # quarantine then serialize on the row, so an idempotent
        # re-register can never reconcile the linked source from a
        # `status` a concurrent quarantine has already changed.
        try:
            with transaction.atomic():
                existing = _lock_miner(miner_id)
                if existing is not None:
                    # Idempotency: matching key material ⇒ no-op 200;
                    # mismatched ⇒ a conflict.
                    if (
                        existing.pubkey_hex != pubkey_hex
                        or existing.platform_id != platform_id
                    ):
                        return _error(
                            status.HTTP_409_CONFLICT,
                            "miner_id already registered with different identity",
                            "conflict",
                        )
                    # `chain_node_id` is a backfillable bridge field: an
                    # operator registers the miner first, then learns its
                    # on-chain node_id and re-registers to set it. A value
                    # that DIFFERS from one already stored is a deliberate
                    # mismatch (409); backfilling from NULL is allowed and
                    # may itself collide with another miner's node (409 via
                    # the savepoint).
                    if chain_node_id is not None:
                        if (
                            existing.chain_node_id
                            and existing.chain_node_id != chain_node_id
                        ):
                            return _error(
                                status.HTTP_409_CONFLICT,
                                "miner_id already registered with a different "
                                "chain_node_id",
                                "conflict",
                            )
                        if not existing.chain_node_id:
                            existing.chain_node_id = chain_node_id
                            try:
                                with transaction.atomic():
                                    existing.save(
                                        update_fields=["chain_node_id"]
                                    )
                            except IntegrityError:
                                return _error(
                                    status.HTTP_409_CONFLICT,
                                    "chain_node_id already registered to "
                                    "another miner",
                                    "conflict",
                                )
                    _ensure_telemetry_source(existing)
                    return Response(
                        _serialize(existing), status=status.HTTP_200_OK
                    )
                # New miner — create the identity, then reconcile its
                # linked `TelemetrySource` (one registry of record).
                # `_ensure_telemetry_source` (update-or-create) also
                # heals an orphaned `miner:<id>` source left without an
                # identity — a raw create would collide and 409.
                miner = MinerIdentity.objects.create(
                    miner_id=miner_id,
                    pubkey_hex=pubkey_hex,
                    platform_id=platform_id,
                    netbird_peer_id=netbird_peer_id,
                    netbird_ip=netbird_ip,
                    chain_node_id=chain_node_id,
                )
                _ensure_telemetry_source(miner)
                log.info("miner registered: miner_id=%s", miner_id)
                return Response(
                    _serialize(miner), status=status.HTTP_201_CREATED
                )
        except IntegrityError:
            # `MinerIdentity.create` collided — a pubkey_hex /
            # platform_id already held by ANOTHER miner, or a concurrent
            # register of this miner_id. Re-read under a lock: an
            # identical miner now present ⇒ idempotent 200; otherwise a
            # genuine conflict.
            with transaction.atomic():
                dup = _lock_miner(miner_id)
                if (
                    dup is not None
                    and dup.pubkey_hex == pubkey_hex
                    and dup.platform_id == platform_id
                    and (chain_node_id is None or dup.chain_node_id == chain_node_id)
                ):
                    _ensure_telemetry_source(dup)
                    return Response(
                        _serialize(dup), status=status.HTTP_200_OK
                    )
            return _error(
                status.HTTP_409_CONFLICT,
                "pubkey_hex, platform_id, or chain_node_id already registered "
                "to another miner",
                "conflict",
            )


# ─── GET /v1/admin/miner/list ────────────────────────────────────────


class MinerListView(APIView):
    """`GET /v1/admin/miner/list` — offset-paginated registry listing."""

    authentication_classes = [ServiceTokenAuthentication]
    # P2 object-level authorization: fleet-wide miner registry — not a
    # tenant object.
    object_scope = scoping.OPERATOR_ONLY
    permission_classes = [IsAuthenticated]
    http_method_names = ["get", "options"]

    @extend_schema(
        summary="List registered miners",
        description=(
            "Any authenticated ServiceClient (read-only). Offset-paginated, "
            "ordered by `miner_id`."
        ),
        tags=["Miners"],
        parameters=[
            OpenApiParameter(
                "limit",
                int,
                OpenApiParameter.QUERY,
                description="Page size (default 100, capped at 500).",
            ),
            OpenApiParameter(
                "offset",
                int,
                OpenApiParameter.QUERY,
                description="Row offset (default 0).",
            ),
        ],
        responses={
            200: MinerListSerializer,
            400: OpenApiResponse(ErrorSerializer, "Malformed limit / offset."),
            403: OpenApiResponse(ErrorSerializer, "Not authenticated."),
        },
    )
    def get(self, request: Request) -> Response:
        try:
            limit = _require_int_qp(
                request, "limit", default=_DEFAULT_LIMIT, minimum=1
            )
            offset = _require_int_qp(request, "offset", default=0, minimum=0)
        except _WireError as exc:
            return _error(exc.http_status, exc.message, exc.category)

        limit = min(limit, _MAX_LIMIT)
        total = MinerIdentity.objects.count()
        rows = MinerIdentity.objects.all()[offset : offset + limit]
        return Response(
            {
                "miners": [_serialize(m) for m in rows],
                "count": total,
                "limit": limit,
                "offset": offset,
            },
            status=status.HTTP_200_OK,
        )


# ─── POST /v1/admin/miner/<miner_id>/quarantine ──────────────────────


class MinerQuarantineView(APIView):
    """`POST /v1/admin/miner/<miner_id>/quarantine` — quarantine a miner."""

    authentication_classes = [ServiceTokenAuthentication]
    # P2 object-level authorization: fleet operator action.
    object_scope = scoping.OPERATOR_ONLY
    permission_classes = [IsAuthenticated, IsMinerAdmin]
    http_method_names = ["post", "options"]

    @extend_schema(
        summary="Quarantine a miner",
        description=(
            "Miner-admin only. Marks the miner `quarantined` and deactivates "
            "its linked telemetry source so the §9 broker refuses its "
            "envelopes. Idempotent."
        ),
        tags=["Miners"],
        parameters=[_MINER_ID_PARAM],
        request=None,
        responses={
            200: MinerQuarantineResponseSerializer,
            403: OpenApiResponse(ErrorSerializer, "Not the miner-admin principal."),
            404: OpenApiResponse(ErrorSerializer, "Miner not found."),
        },
    )
    def post(self, request: Request, miner_id: str) -> Response:
        # Quarantine the identity AND deactivate its linked telemetry
        # source together, under a row lock — the §9 broker's
        # registered-source gate then refuses this miner's envelopes
        # (403). The lock serialises against a concurrent register, so
        # the deactivation cannot be undone by a racing reconcile.
        # Idempotent.
        with transaction.atomic():
            miner = _lock_miner(miner_id)
            if miner is None:
                return _error(
                    status.HTTP_404_NOT_FOUND, "miner not found", "not-found"
                )
            if miner.status != MinerStatus.QUARANTINED:
                miner.status = MinerStatus.QUARANTINED
                miner.save(update_fields=["status"])
            TelemetrySource.objects.filter(
                source=TELEMETRY_SOURCE_KIND, source_id=miner_id
            ).update(is_active=False)
        log.warning("miner quarantined: miner_id=%s", miner_id)
        return Response(
            {"miner_id": miner_id, "status": miner.status},
            status=status.HTTP_200_OK,
        )


# Hard cap on the graceful-exit envelope — it is tiny (five small fields
# + a 64-byte signature); a larger blob is rejected before the verifier
# shell-out. Matches the Rust subcommand's MAX_REQUEST_BYTES.
_MAX_GRACEFUL_EXIT_BYTES = 4096


def _graceful_exit_skew_seconds() -> int:
    """Max |miner_clock − vali_clock| accepted on a graceful-exit
    request, seconds. Reuses the heartbeat skew default (300 s)."""
    return int(getattr(settings, "VALI_HEARTBEAT_SKEW_SECONDS", 300))


class MinerGracefulExitView(APIView):
    """`POST /v1/miner/<miner_id>/graceful-exit` — a miner self-requests a
    graceful exit so vali warm-migrates its VMs off before it leaves.

    The Ed25519 signature over the `SignedGracefulExit` envelope IS the
    authentication (no bearer token, like the §K heartbeat): any caller
    may POST, but only one holding the miner's registered identity key
    produces a request that verifies against `MinerIdentity.pubkey_hex`.
    On accept the miner is quarantined (idempotent) — its telemetry
    source is deactivated and the §13/§25 auto-migration loop enrols a
    warm migration of its bound VMs. The miner can leave once they are
    gone (and, where staking is enabled, its stake then unbonds).
    """

    # The signed envelope is the credential — no service-token auth.
    authentication_classes: list[Any] = []
    # P2 object-level authorization: `AllowAny` miner-signed ingress (the
    # signature is the gate).
    object_scope = scoping.PUBLIC
    permission_classes = [AllowAny]
    # RA-M2 — cap the anon flood: the post() shells out to the Rust
    # signature verifier before any auth, so throttle per source IP to
    # bound subprocess amplification. ScopedRateThrottle keys per-IP for
    # an unauthenticated request.
    throttle_scope = "graceful_exit"
    http_method_names = ["post", "options"]

    @extend_schema(
        summary="Miner self-requests a graceful exit",
        description=(
            "Unauthenticated by service token — the request BODY is a raw "
            "CBOR/COSE `SignedGracefulExit` envelope whose Ed25519 signature "
            "IS the credential (verified against the miner's registered "
            "`pubkey_hex`). On accept the miner is quarantined (idempotent) "
            "and the §13/§25 auto-migration loop drains its VMs. Rate-limited "
            "per source IP."
        ),
        tags=["Miners"],
        parameters=[_MINER_ID_PARAM],
        request={"application/octet-stream": OpenApiTypes.BINARY},
        responses={
            200: MinerGracefulExitResponseSerializer,
            400: OpenApiResponse(ErrorSerializer, "Empty body."),
            403: OpenApiResponse(
                ErrorSerializer,
                "Signature / body-miner_id / timestamp-skew verification failed.",
            ),
            404: OpenApiResponse(ErrorSerializer, "Miner not found."),
            413: OpenApiResponse(ErrorSerializer, "Envelope too large."),
            503: OpenApiResponse(ErrorSerializer, "Verifier unavailable."),
        },
    )
    def post(self, request: Request, miner_id: str) -> Response:
        envelope = request.body
        if not envelope:
            return _error(status.HTTP_400_BAD_REQUEST, "empty body", "wire")
        if len(envelope) > _MAX_GRACEFUL_EXIT_BYTES:
            return _error(
                status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                "envelope too large",
                "wire",
            )
        # Resolve the claimed miner's registered key. The verifier proves
        # the envelope was signed by it, so a forged path `miner_id`
        # cannot pass — but a non-existent miner is a clean 404.
        miner = MinerIdentity.objects.filter(miner_id=miner_id).first()
        if miner is None:
            return _error(status.HTTP_404_NOT_FOUND, "miner not found", "not-found")
        try:
            vk = bytes.fromhex(miner.pubkey_hex)
        except ValueError:
            return _error(
                status.HTTP_500_INTERNAL_SERVER_ERROR,
                "registry key malformed",
                "internal",
            )
        try:
            body = verifier.verify_graceful_exit(envelope=envelope, verifying_key=vk)
        except verifier.VerifierFailed as exc:
            return _error(
                status.HTTP_403_FORBIDDEN,
                "graceful-exit verification failed",
                exc.category,
            )
        except verifier.VerifierUnavailable:
            return _error(
                status.HTTP_503_SERVICE_UNAVAILABLE,
                "verifier unavailable",
                "internal",
            )
        # The key already binds the identity; assert the signed body
        # names THIS miner as defence in depth.
        if body.miner_id != miner_id:
            return _error(
                status.HTTP_403_FORBIDDEN, "body miner_id mismatch", "identity"
            )
        # ±skew anti-replay-across-time on the signed timestamp.
        skew = abs(body.timestamp_unix - int(timezone.now().timestamp()))
        if skew > _graceful_exit_skew_seconds():
            return _error(
                status.HTTP_403_FORBIDDEN,
                "timestamp outside skew window",
                "timestamp-skew",
            )
        # Quarantine (idempotent — re-request is a no-op, which also
        # absorbs a signature replay). Shared with the Edge-relayed
        # header-based ingest path (`telemetry.MinerGracefulExitIngestView`)
        # via `apply_graceful_exit_quarantine`.
        if not apply_graceful_exit_quarantine(miner_id, body):
            return _error(status.HTTP_404_NOT_FOUND, "miner not found", "not-found")
        return Response(
            {"miner_id": miner_id, "status": MinerStatus.QUARANTINED, "accepted": True},
            status=status.HTTP_200_OK,
        )


# ─── helpers ─────────────────────────────────────────────────────────


def apply_graceful_exit_quarantine(miner_id: str, body: Any) -> bool:
    """Idempotently quarantine `miner_id` for a verified graceful-exit.

    The shared tail of BOTH graceful-exit entry points — the path-based
    operator endpoint (`MinerGracefulExitView`) and the Edge-relayed
    header-based ingest (`telemetry.MinerGracefulExitIngestView`). The
    caller has already verified the Ed25519 signature, bound the signed
    `body.miner_id` to `miner_id`, and checked ±skew; this runs the
    row-locked status transition + `TelemetrySource` deactivation that
    enrols the §13/§25 auto-migration.

    Idempotent: re-quarantining an already-`QUARANTINED` miner is a
    no-op (which also absorbs a signature replay). Returns `False` iff
    the miner row vanished between resolution and the lock (a clean
    `404` for the caller); `True` on a successful / idempotent
    quarantine. `body` is the verifier's decoded body — only
    `body.sequence` is read, for the audit log.
    """
    with transaction.atomic():
        locked = _lock_miner(miner_id)
        if locked is None:
            return False
        if locked.status != MinerStatus.QUARANTINED:
            locked.status = MinerStatus.QUARANTINED
            locked.save(update_fields=["status"])
        TelemetrySource.objects.filter(
            source=TELEMETRY_SOURCE_KIND, source_id=miner_id
        ).update(is_active=False)
    log.warning(
        "miner self-requested graceful exit → quarantined: miner_id=%s seq=%s",
        miner_id,
        body.sequence,
    )
    return True


def _lock_miner(miner_id: str) -> MinerIdentity | None:
    """Fetch a `MinerIdentity` `FOR UPDATE` so `register` and
    `quarantine` serialise on the row — neither acts on a stale
    `status`, so an idempotent re-register can never reconcile the
    linked source from a `status` a concurrent quarantine has changed.

    Must be called inside `transaction.atomic()`. On a backend without
    row locks (SQLite, the test backend) the lock is skipped — SQLite
    serialises writers at the database level, so the read-modify-write
    stays atomic regardless. Mirrors `telemetry.service._lock_source`.
    """
    qs = MinerIdentity.objects.filter(miner_id=miner_id)
    if connection.features.has_select_for_update:
        qs = qs.select_for_update()
    return qs.first()


def _ensure_telemetry_source(miner: MinerIdentity) -> None:
    """Reconcile the miner's linked `TelemetrySource` to the registry.

    Called on the idempotent register path. `update_or_create` makes
    the source deterministically reflect the `MinerIdentity` — the
    authoritative record: it heals a source deleted out of band AND
    repairs one whose `verifying_key` or `is_active` drifted (a stale
    row would otherwise let `register` return 200 over a desync).
    `is_active` mirrors the miner status, so re-registering a
    quarantined miner never silently re-enables its telemetry; the
    broker's own transient poison-quarantine (`quarantined_until`) is
    a separate field and is left untouched.
    """
    TelemetrySource.objects.update_or_create(
        source=TELEMETRY_SOURCE_KIND,
        source_id=miner.miner_id,
        defaults={
            "verifying_key": bytes.fromhex(miner.pubkey_hex),
            "is_active": miner.status == MinerStatus.ACTIVE,
        },
    )


def _serialize(miner: MinerIdentity) -> dict[str, Any]:
    """Render a `MinerIdentity` for an API response."""
    return {
        "miner_id": miner.miner_id,
        "pubkey_hex": miner.pubkey_hex,
        "platform_id": miner.platform_id,
        "netbird_peer_id": miner.netbird_peer_id,
        "netbird_ip": miner.netbird_ip,
        "chain_node_id": miner.chain_node_id,
        "status": miner.status,
        "registered_at": miner.registered_at.isoformat(),
        "last_seen_at": (
            miner.last_seen_at.isoformat() if miner.last_seen_at else None
        ),
        "telemetry_source": {
            "source": TELEMETRY_SOURCE_KIND,
            "source_id": miner.miner_id,
        },
    }


def _require_str(body: dict[str, Any], field: str, *, max_len: int) -> str:
    if field not in body:
        raise _WireError(f"missing {field!r}")
    value = body[field]
    if not isinstance(value, str) or not value.strip():
        raise _WireError(f"{field} must be a non-empty string")
    if len(value) > max_len:
        raise _WireError(f"{field} exceeds {max_len} chars")
    return value


def _optional_str(body: dict[str, Any], field: str, *, max_len: int) -> str:
    """An optional string field — absent / null / empty ⇒ `""`."""
    if field not in body or body[field] in (None, ""):
        return ""
    value = body[field]
    if not isinstance(value, str):
        raise _WireError(f"{field} must be a string")
    if len(value) > max_len:
        raise _WireError(f"{field} exceeds {max_len} chars")
    return value


def _require_pubkey_hex(body: dict[str, Any], field: str) -> str:
    """Require a 32-byte Ed25519 public key as 64 hex chars.

    Returned lowercased so the DB-unique `pubkey_hex` is canonical —
    `AB..` and `ab..` can never register as two distinct miners.
    """
    value = _require_str(body, field, max_len=_PUBKEY_HEX_LEN)
    lowered = value.lower()
    if len(lowered) != _PUBKEY_HEX_LEN:
        raise _WireError(
            f"{field} must be {_PUBKEY_HEX_LEN} hex chars (32-byte Ed25519 key)"
        )
    try:
        bytes.fromhex(lowered)
    except ValueError as exc:
        raise _WireError(f"{field} is not valid hex") from exc
    return lowered


def _optional_chain_node_id(body: dict[str, Any], field: str) -> str | None:
    """An optional on-chain compute node_id — 64 hex chars, lowercased.

    Absent / null / empty ⇒ `None` (the field stays NULL, to be
    backfilled later). When present it must be exactly 64 hex chars
    (a 32-byte ed25519 key), returned lowercased so the DB-unique
    `chain_node_id` is canonical — mirrors `_require_pubkey_hex`.
    """
    if field not in body or body[field] in (None, ""):
        return None
    value = body[field]
    if not isinstance(value, str):
        raise _WireError(f"{field} must be a string")
    lowered = value.lower()
    if len(lowered) != _PUBKEY_HEX_LEN:
        raise _WireError(
            f"{field} must be {_PUBKEY_HEX_LEN} hex chars "
            "(32-byte on-chain node_id)"
        )
    try:
        bytes.fromhex(lowered)
    except ValueError as exc:
        raise _WireError(f"{field} is not valid hex") from exc
    return lowered


def _optional_ip(body: dict[str, Any], field: str) -> str | None:
    """An optional IP-address field — absent / null / empty ⇒ `None`."""
    if field not in body or body[field] in (None, ""):
        return None
    value = body[field]
    if not isinstance(value, str):
        raise _WireError(f"{field} must be a string IP address")
    try:
        ipaddress.ip_address(value)
    except ValueError as exc:
        raise _WireError(f"{field} is not a valid IP address") from exc
    return value


def _require_int_qp(
    request: Request, field: str, *, default: int, minimum: int = 0
) -> int:
    raw = request.query_params.get(field)
    if raw is None or raw == "":
        return default
    try:
        value = int(raw)
    except (TypeError, ValueError) as exc:
        raise _WireError(f"{field} must be an integer") from exc
    if value < minimum:
        raise _WireError(f"{field} must be ≥ {minimum}")
    return value


def _error(http_status: int, message: str, category: str) -> Response:
    return Response(
        {"error": message, "category": category}, status=http_status
    )
