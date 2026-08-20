"""mTLS reverse-proxy header reader.

Locked decision (issue #1 comment 4496539510, Q11): L1↔vali mTLS on a
private control-plane subnet with a dedicated CA, rotation 90 days.
The concrete subnet is deployment config — see
`VALI_MTLS_TRUSTED_PROXIES`. The proxy
(nginx) terminates TLS and forwards:

  - `X-SSL-Client-Verify: SUCCESS` (or `NONE` / `FAILED:<reason>`).
  - `X-SSL-Client-S-DN: <subject DN>` (RFC 2253-style).

This middleware extracts both into `request.mtls_verify` and
`request.mtls_subject_cn`, **gated on the request originating from a
proxy in `VALI_MTLS_TRUSTED_PROXIES`**. Without that gate, any direct
caller could spoof the headers.

`MtlsAuthentication` (apps.identity.authentication) consumes the two
attributes the middleware sets; the middleware itself never raises —
it just attaches metadata.
"""

from __future__ import annotations

import logging
from collections.abc import Callable

from django.conf import settings
from django.http import HttpRequest, HttpResponse, JsonResponse

from .scoping import (
    OPERATOR_ONLY,
    PUBLIC,
    declared_scope,
)

log = logging.getLogger("apps.identity.middleware")


class MtlsClientCertMiddleware:
    """Extract mTLS verdict + subject CN from trusted-proxy headers.

    Attaches three attributes to `request`:

    - `mtls_present` (`bool`) — true iff the request reached Django
      through a trusted proxy that injected the headers.
    - `mtls_verify` (`str`) — verbatim `X-SSL-Client-Verify` value.
    - `mtls_subject_cn` (`str | None`) — parsed CN from the DN; `None`
      if the DN is missing or has no CN component.

    Authentication itself (turning the CN into a principal) lives in
    `MtlsAuthentication` — same separation of concerns Django uses
    between `SessionMiddleware` and `AuthenticationMiddleware`.
    """

    def __init__(self, get_response: Callable[[HttpRequest], HttpResponse]) -> None:
        self.get_response = get_response

    def __call__(self, request: HttpRequest) -> HttpResponse:
        request.mtls_present = False
        request.mtls_verify = ""
        request.mtls_subject_cn = None

        trusted = set(getattr(settings, "VALI_MTLS_TRUSTED_PROXIES", []) or [])
        remote = request.META.get("REMOTE_ADDR", "")
        if not trusted or remote not in trusted:
            return self.get_response(request)

        verify_header = getattr(settings, "VALI_MTLS_HEADER_VERIFY", "X-SSL-Client-Verify")
        subject_header = getattr(settings, "VALI_MTLS_HEADER_SUBJECT", "X-SSL-Client-S-DN")

        request.mtls_present = True
        request.mtls_verify = request.META.get(_meta_key(verify_header), "")
        subject = request.META.get(_meta_key(subject_header), "")
        request.mtls_subject_cn = _parse_cn(subject)

        return self.get_response(request)


#: URL path prefix the scope machinery governs. `/healthz`, `/admin/`
#: (cluster-internal Django admin, its own auth) and anything else are
#: outside it.
_API_PREFIX = "/v1/"

#: Paths under `/v1/` that describe the API rather than serve it. These
#: are third-party (drf-spectacular) views we cannot annotate, and they
#: are already `AllowAny`.
_EXEMPT_PATHS = frozenset(
    {"/v1/schema", "/v1/docs", "/v1/redoc", "/v1/public/schema", "/v1/public/docs"}
)


class PrincipalScopeMiddleware:
    """P2 — refuse cross-tenant reach before the view ever runs.

    This is the layer that cannot be forgotten. Every view in this
    codebase sets `permission_classes` explicitly, so a DRF permission
    class is exactly the thing the next endpoint omits; middleware sits
    on the whole `/v1/` surface unconditionally.

    Three rules, all fail-closed:

    1. An `UNCLASSIFIED` principal (nobody granted it a scope) is
       refused every non-`PUBLIC` endpoint. A new credential is inert
       until someone deliberately scopes it.
    2. A `TENANT` principal is refused every `OPERATOR_ONLY` endpoint.
    3. A `TENANT` principal is refused any endpoint that did not
       DECLARE its `object_scope` at all — so an endpoint added without
       thinking about tenancy is invisible to tenant tokens rather than
       accidentally cross-tenant. (`apps.identity.checks` also fails
       `manage.py check` for such a view; this is the runtime half of
       the same guarantee.)

    An `OPERATOR` principal passes through untouched — the upstream
    product API legitimately acts for every tenant.

    Object-level filtering for `TENANT_SCOPED` endpoints is NOT done
    here (the middleware has no object): see
    `apps.identity.scoping.scope_queryset` / `require_tenant_visible`.
    """

    def __init__(self, get_response: Callable[[HttpRequest], HttpResponse]) -> None:
        self.get_response = get_response

    def __call__(self, request: HttpRequest) -> HttpResponse:
        return self.get_response(request)

    def process_view(self, request, view_func, _view_args, _view_kwargs):
        path = request.path
        if not path.startswith(_API_PREFIX) or path.rstrip("/") in _EXEMPT_PATHS:
            return None

        view_cls = getattr(view_func, "cls", None)
        scope = declared_scope(view_cls) if view_cls is not None else None
        if scope == PUBLIC:
            # Deliberately unauthenticated ingress — the view's own
            # reasoning governs it, and there is no principal to scope.
            return None

        # Resolved WITHOUT side effects; DRF still performs the
        # authoritative authentication (and its 401) inside the view.
        from .authentication import resolve_principal

        client = resolve_principal(request)
        if client is None:
            # Unauthenticated / bad credential — let DRF answer 401 so
            # the response shape and WWW-Authenticate header stay the
            # single source of truth.
            return None

        if client.is_unclassified:
            return self._deny(
                request,
                f"service client {client.name!r} has no authorization scope "
                "(unclassified principals are denied; grant scope=operator or "
                "scope=tenant out-of-band)",
                "principal-unclassified",
            )

        if client.is_tenant_scoped:
            if scope is None:
                return self._deny(
                    request,
                    "endpoint does not declare an object_scope — refused to a "
                    "tenant-scoped principal",
                    "endpoint-undeclared",
                )
            if scope == OPERATOR_ONLY:
                return self._deny(
                    request,
                    "endpoint is operator-only",
                    "operator-only",
                )
        return None

    @staticmethod
    def _deny(request, message: str, category: str) -> JsonResponse:
        log.warning(
            "scope denial: path=%s category=%s message=%s",
            request.path,
            category,
            message,
        )
        return JsonResponse({"error": message, "category": category}, status=403)


def _meta_key(header: str) -> str:
    """Convert an HTTP header name to the `request.META` key.

    Django turns `X-Foo-Bar` into `HTTP_X_FOO_BAR`. We accept either
    form on the way in to make settings forgiving.
    """
    name = header.upper().replace("-", "_")
    if name.startswith("HTTP_"):
        return name
    return f"HTTP_{name}"


def _parse_cn(dn: str) -> str | None:
    """Extract the first `CN=...` component of an RFC 2253 DN.

    A minimal parser: real-world DNs from nginx are already escaped /
    quoted, but for vali's controlled CA the CN is always a simple
    ASCII identifier (e.g. `CN=l1-prod`). Reject empty CNs.
    """
    if not dn:
        return None
    # nginx variants: `CN=l1-prod,O=Hippius` or `/CN=l1-prod/O=Hippius`.
    parts: list[str]
    if dn.startswith("/"):
        parts = [p for p in dn.split("/") if p]
    else:
        parts = [p.strip() for p in dn.split(",")]
    for part in parts:
        if "=" not in part:
            continue
        key, _, value = part.partition("=")
        if key.strip().upper() == "CN":
            cn = value.strip()
            return cn or None
    return None
