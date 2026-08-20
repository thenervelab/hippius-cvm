"""Permission classes for the telemetry broker.

`POST /v1/telemetry/ingest` (JSON wrapper) is open to any
authenticated `ServiceClient` (a telemetry source forwarding
telemetry). The raw-`application/cbor` §K heartbeat ingress on the
same URL is exempt from token auth — see `IsAuthenticatedOrCborHeartbeat`.
`GET /v1/telemetry/pull` is **root-only** — draining the broker is an
internal-consumer action (sentinel, the scheduler re-eval, …), gated
to the single principal named by `settings.VALI_TELEMETRY_ROOT_PRINCIPAL`.
"""

from __future__ import annotations

from django.conf import settings
from rest_framework.permissions import BasePermission

from apps.identity.models import ServiceClient

# `content-type` the Edge stamps on a forwarded §K miner heartbeat
# (PR-Part4-B). The raw canonical-CBOR `SignedMinerHeartbeat` rides the
# body verbatim — distinct from the JSON-wrapper telemetry ingress.
CBOR_CONTENT_TYPE = "application/cbor"


def is_cbor_request(request) -> bool:
    """True when the request body is a raw `application/cbor` payload —
    the §K heartbeat ingress shape (PR-Part4-B).

    Reads the raw `CONTENT_TYPE` header (not a parsed body), so it is
    safe to call in a permission check, before any body parse.
    """
    raw = request.META.get("CONTENT_TYPE", "") or ""
    return raw.split(";")[0].strip().lower() == CBOR_CONTENT_TYPE


class IsAuthenticatedOrCborHeartbeat(BasePermission):
    """ServiceToken auth for the JSON telemetry-ingest path; the raw-
    CBOR §K heartbeat path is exempt.

    A forwarded heartbeat reaches vali over the Edge's in-cluster
    forward leg, which carries **no bearer token** by design: that
    leg's who-may-call-who control is the Cilium NetworkPolicy (only
    the Edge may reach vali), and the heartbeat's authenticity is the
    Ed25519 signature the Rust verifier checks against the
    out-of-band-registered miner key — not an app-layer token. The
    JSON ingest path (direct telemetry sources, which DO carry a
    token) still requires an authenticated `ServiceClient`.
    """

    message = "authentication is required for JSON telemetry ingest"

    def has_permission(self, request, view) -> bool:
        if is_cbor_request(request):
            return True
        user = getattr(request, "user", None)
        return bool(user and user.is_authenticated)


class IsTelemetryRoot(BasePermission):
    """Allow only the configured telemetry-root principal.

    Fails closed: if the deploy has not pinned a root principal the
    endpoint denies — draining telemetry is too sensitive to fall
    open — and a clear 403 surfaces the misconfiguration.
    """

    message = "only the telemetry root principal may call this endpoint"

    def has_permission(self, request, view) -> bool:
        user = getattr(request, "user", None)
        if not isinstance(user, ServiceClient):
            return False
        # P2: a root/worker grant is a CROSS-TENANT power, so the
        # principal must ALSO carry the explicit operator scope. Without
        # this a tenant-scoped client that happens to be named the
        # configured root principal would inherit fleet-wide authority
        # from a name match alone.
        if not user.is_operator_principal:
            return False
        if not user.is_active:
            return False
        expected = getattr(settings, "VALI_TELEMETRY_ROOT_PRINCIPAL", "")
        if not expected:
            return False
        return user.name == expected


class IsHostAttestorAdmin(BasePermission):
    """Allow only the configured host-attestor-admin principal.

    Gates `POST /v1/admin/host-attestor/release` — publishing a blackbox
    UKI release is a fleet-wide trust-root operator action (it pins the
    measurement every miner boots as its host attestor). Mirrors the
    established root-principal pattern (`IsMinerAdmin`, `IsTelemetryRoot`):
    the caller must be the single `ServiceClient` named by
    `settings.VALI_HOST_ATTESTOR_ADMIN_PRINCIPAL`.

    Fails closed: an unset principal denies (a clear 403 surfaces the
    misconfiguration rather than falling open on a trust root).
    """

    message = "only the host-attestor-admin principal may call this endpoint"

    def has_permission(self, request, view) -> bool:
        user = getattr(request, "user", None)
        if not isinstance(user, ServiceClient):
            return False
        # P2: a root/worker grant is a CROSS-TENANT power, so the
        # principal must ALSO carry the explicit operator scope. Without
        # this a tenant-scoped client that happens to be named the
        # configured root principal would inherit fleet-wide authority
        # from a name match alone.
        if not user.is_operator_principal:
            return False
        if not user.is_active:
            return False
        expected = (
            getattr(settings, "VALI_HOST_ATTESTOR_ADMIN_PRINCIPAL", "") or ""
        ).strip()
        if not expected:
            return False
        return user.name == expected
