"""DRF authentication backends — mTLS + service tokens.

Both backends resolve to a [`ServiceClient`] (apps.identity.models)
which acts as the request principal. `request.user` after success is
the `ServiceClient` instance; `request.auth` is the underlying
credential (the `ServiceToken` row, or `None` for mTLS).
"""

from __future__ import annotations

import hashlib

from django.utils import timezone
from rest_framework import authentication
from rest_framework.exceptions import AuthenticationFailed

from .models import ServiceClient, ServiceToken


def resolve_principal(request) -> ServiceClient | None:
    """Resolve the request's `ServiceClient` WITHOUT any side effect.

    Shared by `PrincipalScopeMiddleware`, which has to know the caller's
    authorization scope *before* the view (and therefore before DRF
    authentication) runs. Mirrors the two backends below — mTLS CN
    first, then the bearer token — but never writes `last_used_at` and
    never raises: an unusable credential simply resolves to `None` and
    the DRF backends produce the authoritative 401.
    """
    cn = getattr(request, "mtls_subject_cn", None)
    if getattr(request, "mtls_present", False) and getattr(
        request, "mtls_verify", ""
    ) == "SUCCESS" and cn:
        return ServiceClient.objects.filter(name=cn, is_active=True).first()

    header = request.META.get("HTTP_AUTHORIZATION", "")
    scheme, _, token = header.partition(" ")
    if scheme != ServiceTokenAuthentication.KEYWORD:
        return None
    token = token.strip()
    if not token:
        return None
    try:
        digest = hashlib.sha256(token.encode("ascii")).hexdigest()
    except UnicodeEncodeError:
        return None
    row = (
        ServiceToken.objects.select_related("client")
        .filter(token_sha256=digest, is_active=True, client__is_active=True)
        .first()
    )
    if row is None:
        return None
    if row.expires_at and row.expires_at < timezone.now():
        return None
    return row.client


class MtlsAuthentication(authentication.BaseAuthentication):
    """Match the `X-SSL-Client-S-DN` CN (set by
    `MtlsClientCertMiddleware`) against a `ServiceClient.name`.

    Returns `None` (DRF: "this backend doesn't apply, try the next
    one") if the middleware didn't see a trusted-proxy request. Raises
    `AuthenticationFailed` if the proxy DID terminate mTLS but the
    cert was bad or the CN is unknown — that's a closed-door for the
    caller, NOT a "try the next backend" case.
    """

    def authenticate(self, request):
        if not getattr(request, "mtls_present", False):
            return None
        verdict = request.mtls_verify
        # `NONE` (and the empty string) = trusted proxy reached us
        # without a client cert. That's a valid posture for callers
        # that only have a service token — fall through to the next
        # backend, don't 401. Only `FAILED:*` is a hard reject.
        if verdict in ("", "NONE"):
            return None
        if verdict != "SUCCESS":
            raise AuthenticationFailed(
                f"mTLS client cert not verified (verdict={verdict!r})"
            )
        cn = getattr(request, "mtls_subject_cn", None)
        if not cn:
            raise AuthenticationFailed("mTLS subject DN has no CN component")
        try:
            client = ServiceClient.objects.get(name=cn, is_active=True)
        except ServiceClient.DoesNotExist as exc:
            raise AuthenticationFailed(f"mTLS CN {cn!r} not a registered ServiceClient") from exc
        return (client, None)

    def authenticate_header(self, _request) -> str:
        # Returned in the WWW-Authenticate response header on 401.
        # nginx (the mTLS terminator) is responsible for prompting the
        # client; vali just describes the scheme.
        return 'mTLS realm="vali"'


class ServiceTokenAuthentication(authentication.BaseAuthentication):
    """`Authorization: Bearer <token>` against `ServiceToken.token_sha256`.

    The token is hashed (SHA-256) on each request and looked up by
    digest — the plaintext never round-trips through the database.
    """

    KEYWORD = "Bearer"

    def authenticate(self, request):
        header = request.META.get("HTTP_AUTHORIZATION", "")
        if not header:
            return None
        # `str.partition` always returns a 3-tuple — no exception path.
        scheme, _, token = header.partition(" ")
        if scheme != self.KEYWORD:
            return None
        token = token.strip()
        if not token:
            return None
        # Tokens are minted via `ServiceToken.issue` (`secrets.token_urlsafe`),
        # which is pure-ASCII. A non-ASCII bearer header is therefore
        # garbage by definition; reject as `AuthenticationFailed` so
        # the wrapper view returns 401 instead of bubbling
        # `UnicodeEncodeError` into a 500.
        try:
            digest = hashlib.sha256(token.encode("ascii")).hexdigest()
        except UnicodeEncodeError as exc:
            raise AuthenticationFailed("bearer token must be ASCII") from exc
        try:
            row = ServiceToken.objects.select_related("client").get(
                token_sha256=digest,
                is_active=True,
                client__is_active=True,
            )
        except ServiceToken.DoesNotExist as exc:
            raise AuthenticationFailed("invalid service token") from exc
        if row.expires_at and row.expires_at < timezone.now():
            raise AuthenticationFailed("service token expired")
        # `update_fields` keeps the write narrow — we do not want a
        # concurrent token change to be overwritten by the last-used
        # bookkeeping.
        row.last_used_at = timezone.now()
        row.save(update_fields=["last_used_at"])
        return (row.client, row)

    def authenticate_header(self, _request) -> str:
        return f'{self.KEYWORD} realm="vali"'


# ── OpenAPI (drf-spectacular) security schemes ────────────────────────
# Register the auth backends so the Swagger UI / ReDoc render the
# "Authorize" button + document how to call the API. drf-spectacular
# auto-discovers `OpenApiAuthenticationExtension` subclasses when this
# module is imported (it always is — it's in DEFAULT_AUTHENTICATION_CLASSES).
try:  # drf-spectacular is a hard dep; guard keeps a minimal env importable
    from drf_spectacular.extensions import OpenApiAuthenticationExtension

    class ServiceTokenScheme(OpenApiAuthenticationExtension):
        target_class = "apps.identity.authentication.ServiceTokenAuthentication"
        name = "ServiceToken"

        def get_security_definition(self, _auto_schema):
            return {
                "type": "http",
                "scheme": "bearer",
                "description": "ServiceToken bearer — `Authorization: Bearer <token>`.",
            }

    class MtlsScheme(OpenApiAuthenticationExtension):
        target_class = "apps.identity.authentication.MtlsAuthentication"
        name = "mTLS"

        def get_security_definition(self, _auto_schema):
            return {
                "type": "mutualTLS",
                "description": "Client-certificate mTLS (Edge-terminated).",
            }
except ImportError:  # pragma: no cover
    pass
