"""`POST /v1/order_ticket` — OrderTicket intake.

vali transports the ticket opaquely (ARCHITECTURE.md §3 / §4): it
parses the COSE envelope only to extract indexable metadata, stores
the byte-exact blob, and replies to L1. PR-G2..G4 will add the
scheduling / Packer trigger / KBS forwarding paths.

Responses:

- `201 Created`  — first intake of this `ticket_id`.
- `200 OK`        — idempotent re-intake (byte-identical replay).
- `400 Bad Request` — validator rejected the ticket (`category`
  surfaces the reason).
- `409 Conflict`  — `ticket_id` reused with different bytes (replay
  or L1 bug; §13 anomaly).
- `413 Payload Too Large` — body exceeds `VALI_TICKET_MAX_BYTES`.
- `503 Service Unavailable` — validator binary missing / timed out /
  malformed output. Operator problem, not caller's fault.

All response bodies are minimal JSON — never echo the COSE blob /
ticket nonce / vault paths back (§20 logging discipline applies
to responses too).
"""

from __future__ import annotations

import logging

from django.conf import settings
from django.db import IntegrityError, transaction
from drf_spectacular.types import OpenApiTypes
from drf_spectacular.utils import OpenApiResponse, extend_schema
from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from rest_framework.request import Request
from rest_framework.response import Response
from rest_framework.views import APIView

from apps.common.schemas import ErrorSerializer
from apps.identity import scoping

from . import validator
from .models import OrderTicketIntake
from .schemas import OrderTicketAcceptedSerializer

log = logging.getLogger("apps.orders.views")


class OrderTicketIntakeView(APIView):
    """`POST /v1/order_ticket` — accepts a COSE_Sign1 envelope."""

    # P2 object-level authorization: the L1 minter's ingress; a ticket names
    # any tenant.
    object_scope = scoping.OPERATOR_ONLY

    permission_classes = [IsAuthenticated]
    # `parser_classes` are inherited from settings.REST_FRAMEWORK.
    # The view consumes `request.body` directly so it doesn't matter
    # which parser ran — both yield the raw bytes for binary input.

    http_method_names = ["post", "options"]

    @extend_schema(
        summary="Intake a COSE_Sign1 OrderTicket",
        description=(
            "vali is an opaque transport (§3/§4): the request BODY is the "
            "raw CBOR/COSE_Sign1 envelope emitted by L1 (`application/"
            "octet-stream`, NOT JSON). vali parses it only to extract "
            "indexable metadata and stores the byte-exact blob. `201` on "
            "first intake, `200` on a byte-identical idempotent re-intake. "
            "Response bodies never echo the COSE blob / nonce / vault paths."
        ),
        tags=["Orders"],
        request={"application/octet-stream": OpenApiTypes.BINARY},
        responses={
            201: OrderTicketAcceptedSerializer,
            200: OrderTicketAcceptedSerializer,
            400: OpenApiResponse(ErrorSerializer, "Empty body / validator rejected."),
            403: OpenApiResponse(ErrorSerializer, "Not authenticated."),
            409: OpenApiResponse(ErrorSerializer, "ticket_id reused with different bytes."),
            413: OpenApiResponse(ErrorSerializer, "Body exceeds VALI_TICKET_MAX_BYTES."),
            503: OpenApiResponse(ErrorSerializer, "Validator binary missing / timed out."),
        },
    )
    def post(self, request: Request) -> Response:
        body: bytes = request.body
        if not body:
            return _error(status.HTTP_400_BAD_REQUEST, "empty body", "wire")

        max_bytes = int(settings.VALI_TICKET_MAX_BYTES)
        if len(body) > max_bytes:
            return _error(
                status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                f"body exceeds {max_bytes} bytes (got {len(body)})",
                "wire",
            )

        try:
            parsed = validator.validate_ticket(body)
        except validator.ValidatorFailed as exc:
            log.info("ticket rejected: category=%s", exc.category)
            return _error(status.HTTP_400_BAD_REQUEST, exc.message, exc.category)
        except validator.ValidatorUnavailable as exc:
            # 503: ops problem (binary missing / timeout / schema drift).
            # The text of `exc` is operator-facing — no ticket bytes,
            # by `validator.py`'s contract.
            log.error("validator unavailable: %s", exc)
            return _error(
                status.HTTP_503_SERVICE_UNAVAILABLE,
                str(exc),
                "internal",
            )

        principal = _principal_name(request)

        try:
            with transaction.atomic():
                obj = OrderTicketIntake.objects.create(
                    ticket_id=parsed.ticket_id,
                    vm_id=parsed.vm_id,
                    tenant_id=parsed.tenant_id,
                    user_id=parsed.user_id,
                    lease_id=parsed.lease_id,
                    vm_generation=parsed.vm_generation,
                    issue_time=parsed.issue_time,
                    expiry=parsed.expiry,
                    node_id=parsed.node_id,
                    platform_id=parsed.platform_id,
                    resource_class=parsed.resource_class,
                    kid_hex=parsed.kid_hex,
                    cose_blob=body,
                    received_from=principal,
                )
        except IntegrityError:
            # Race / replay on `ticket_id`. Re-read; if the existing
            # row has byte-identical COSE we treat it as idempotent
            # (200), otherwise it's a §13 anomaly (409).
            existing = OrderTicketIntake.objects.filter(ticket_id=parsed.ticket_id).first()
            if existing is not None and bytes(existing.cose_blob) == body:
                log.info("ticket idempotent re-intake: ticket_id=%s", parsed.ticket_id)
                return _ok(existing, created=False)
            log.warning(
                "ticket_id conflict (replay or L1 bug): ticket_id=%s", parsed.ticket_id
            )
            return _error(
                status.HTTP_409_CONFLICT,
                "ticket_id already used with different bytes",
                "replay-conflict",
            )

        log.info(
            "ticket accepted: ticket_id=%s vm_id=%s vm_generation=%d from=%s",
            parsed.ticket_id,
            parsed.vm_id,
            parsed.vm_generation,
            principal,
        )
        return _ok(obj, created=True)


def _ok(obj: OrderTicketIntake, *, created: bool) -> Response:
    return Response(
        {
            "ticket_id": obj.ticket_id,
            "vm_id": obj.vm_id,
            "vm_generation": obj.vm_generation,
            "received_at": obj.received_at.isoformat(),
            "created": created,
        },
        status=status.HTTP_201_CREATED if created else status.HTTP_200_OK,
    )


def _error(http_status: int, message: str, category: str) -> Response:
    return Response(
        {"error": message, "category": category},
        status=http_status,
    )


def _principal_name(request: Request) -> str:
    """Render the authenticated principal as an audit string."""
    user = getattr(request, "user", None)
    name = getattr(user, "name", None)
    if name:
        return str(name)
    return repr(user) if user is not None else "<anonymous>"
