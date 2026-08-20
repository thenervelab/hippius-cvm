"""P2 — object-level authorization: the tenant-scoping mechanism.

**The problem this closes.** Until now vali authenticated a caller and
then authorized nothing: any valid `ServiceToken` could read (and, on
the non-root endpoints, act on) every tenant's objects. The deployment
architecture made that survivable — tenants never hold a vali token; an
upstream Django API holds one and performs the ACLs — but it meant the
entire multi-tenant boundary rested on that one caller never making a
mistake, and vali would not have stopped the mistake.

**The model.** Every principal ([`apps.identity.models.ServiceClient`])
carries an explicit [`PrincipalScope`]:

- `OPERATOR`     — acts for all tenants (the upstream API keeps this).
- `TENANT`       — bound to one `tenant_id`.
- `UNCLASSIFIED` — the default; denied on the whole non-public surface.

**The mechanism.** Two layers, deliberately:

1. *Declaration* (structural, checked at startup). Every DRF view
   routed under `/v1/` MUST declare a class attribute `object_scope`
   naming which of the four postures below it has. A Django system
   check (`apps.identity.checks`) FAILS `manage.py check` — and
   therefore CI and the container's startup — if any view forgets. You
   cannot add an endpoint to this service without stating its tenant
   posture.

2. *Enforcement* (runtime, in `PrincipalScopeMiddleware`). The
   middleware resolves the caller's principal BEFORE the view runs and:

   - denies an `UNCLASSIFIED` principal everything but `PUBLIC`;
   - denies a `TENANT` principal any `OPERATOR_ONLY` endpoint;
   - denies a `TENANT` principal any endpoint that did NOT declare —
     so a view added without a declaration is invisible to tenant
     tokens even before the system check is looked at.

   Middleware, not a DRF permission class, precisely because every view
   in this codebase sets `permission_classes` explicitly: a permission
   class is something the next endpoint forgets, middleware is not.

3. *Object filtering* (per tenant-scoped view). `TENANT_SCOPED` views
   funnel their reads through [`scope_queryset`] /
   [`require_tenant_visible`]. There are only a handful, and each has a
   test; the middleware guarantees that a view which is NOT tenant
   scoped can never be reached by a tenant token at all, which is what
   keeps that handful small.

**Cross-tenant reads answer 404, not 403.** A 403 confirms the object
exists, which is itself a cross-tenant disclosure (an attacker could
enumerate another tenant's vm_ids). `require_tenant_visible` therefore
raises the same `NotFound` a genuinely-absent row would.
"""

from __future__ import annotations

from typing import Any

from rest_framework.exceptions import NotFound

from .models import PrincipalScope, ServiceClient

# ── The four view postures ───────────────────────────────────────────

#: Serves per-tenant objects. MUST filter its reads through
#: `scope_queryset` / `require_tenant_visible`. Reachable by both
#: operator and tenant principals.
TENANT_SCOPED = "tenant-scoped"

#: Fleet-wide / cross-tenant / operator-only surface (miner registry,
#: bakes, packer builds, orchestration triggers, telemetry drain,
#: capacity). A tenant principal is refused before the view runs.
OPERATOR_ONLY = "operator-only"

#: Authenticated but carries no per-tenant object at all (nothing a
#: tenant could own leaks through it). Reachable by any classified
#: principal.
NO_TENANT_DATA = "no-tenant-data"

#: Deliberately unauthenticated (`AllowAny`) — guest ingress, the Edge
#: registry feed, the epoch-weight feed, the OpenAPI docs. Not gated by
#: the scope machinery at all; its own view-level reasoning applies.
PUBLIC = "public"

ALL_SCOPES: frozenset[str] = frozenset(
    {TENANT_SCOPED, OPERATOR_ONLY, NO_TENANT_DATA, PUBLIC}
)

#: The class attribute a view declares its posture with.
SCOPE_ATTR = "object_scope"


class CrossTenantDenied(NotFound):
    """A tenant principal asked for an object owned by another tenant.

    Subclasses `NotFound` (404) on purpose — see the module docstring:
    a 403 would confirm the object exists.
    """

    default_detail = "not found"


# ── Principal helpers ────────────────────────────────────────────────


def principal_of(request: Any) -> ServiceClient | None:
    """The authenticated `ServiceClient` on a request, or `None`.

    Tolerates `AnonymousUser` / a Django admin `User` / an unset
    `request.user` — only a real `ServiceClient` counts as a principal
    for authorization purposes.
    """
    user = getattr(request, "user", None)
    return user if isinstance(user, ServiceClient) else None


def caller_tenant_id(request: Any) -> str:
    """The tenant a caller is confined to, or `""` if it isn't confined.

    `""` covers BOTH the operator case and the unauthenticated case —
    callers must therefore not use this alone as a gate. Use
    [`scope_queryset`] / [`require_tenant_visible`], which check
    `is_tenant_scoped` explicitly.
    """
    client = principal_of(request)
    return client.scoped_tenant_id if client else ""


def is_operator(request: Any) -> bool:
    """True iff the request carries an explicit OPERATOR principal."""
    client = principal_of(request)
    return bool(client and client.is_operator_principal)


# ── Object-level filtering, for `TENANT_SCOPED` views ─────────────────


def scope_queryset(request: Any, queryset: Any, *, tenant_field: str = "tenant_id") -> Any:
    """Narrow `queryset` to what the caller is allowed to see.

    - OPERATOR principal → unchanged (it legitimately acts for all
      tenants).
    - TENANT principal → `filter(<tenant_field>=<its tenant>)`.
    - anything else (unclassified / unauthenticated) → `none()`. That
      branch is unreachable through the middleware, which already 403s
      such a caller; it is here so a direct call from a management
      command or a future code path cannot fall open.

    `tenant_field` is an ORM lookup, so a related model works:
    `scope_queryset(request, MigrationJob.objects.all(),
    tenant_field="vm__tenant_id")`.
    """
    client = principal_of(request)
    if client is None:
        return queryset.none()
    if client.is_operator_principal:
        return queryset
    if client.is_tenant_scoped:
        return queryset.filter(**{tenant_field: client.tenant_id})
    return queryset.none()


def require_tenant_visible(request: Any, owner_tenant_id: str | None) -> None:
    """Assert the caller may see an object owned by `owner_tenant_id`.

    Raises [`CrossTenantDenied`] (404) otherwise. Use after a
    single-object fetch, where filtering a queryset is not natural.

    A blank/None `owner_tenant_id` is an UNOWNED object (a row created
    before ownership was stamped, or an infra object). A tenant
    principal is refused those too — an object nobody owns is not an
    object this tenant owns, and silently showing it would reopen the
    hole for every legacy row.
    """
    client = principal_of(request)
    if client is None:
        raise CrossTenantDenied()
    if client.is_operator_principal:
        return
    if client.is_tenant_scoped and owner_tenant_id and owner_tenant_id == client.tenant_id:
        return
    raise CrossTenantDenied()


def bind_tenant_id(principal: Any, claimed_tenant_id: str | None) -> str:
    """Resolve the tenant an object being CREATED belongs to.

    Takes the PRINCIPAL (a `ServiceClient`), not a request — the
    creation paths (`launch_jobs.start_launch`) receive `decided_by`
    rather than the request object.

    The `tenant_id` on a launch body is caller-supplied, so building
    authorization on it unchecked would build nothing. This is the
    binding:

    - TENANT principal → the token's own tenant WINS. A body that
      claims a different tenant is rejected (`ValueError`); a body that
      omits it is filled in. A tenant token therefore cannot create an
      object it would then be unable to see, nor plant one in another
      tenant's namespace.
    - OPERATOR principal → the body value is taken as-is. This is an
      ASSERTION BY A TRUSTED CALLER, not a cryptographic binding: the
      upstream product API authenticated the end user and is telling us
      whose VM this is. vali cannot independently verify it, and says
      so rather than pretending otherwise. (The L1-signed OrderTicket
      path DOES carry a signed `tenant_id`/`user_id`; the async launch
      API does not use it.)
    """
    client = principal if isinstance(principal, ServiceClient) else None
    claimed = (claimed_tenant_id or "").strip()
    if client is not None and client.is_tenant_scoped:
        if claimed and claimed != client.tenant_id:
            raise ValueError(
                f"tenant_id {claimed!r} does not match the caller's bound "
                f"tenant {client.tenant_id!r}"
            )
        return client.tenant_id
    return claimed


# ── Declaration helpers (used by the middleware + the system check) ───


def declared_scope(view_cls: Any) -> str | None:
    """The `object_scope` a view class declared, or `None`.

    `None` means "undeclared" — the middleware treats that as denied
    for tenant principals and the system check errors on it.
    """
    value = getattr(view_cls, SCOPE_ATTR, None)
    return value if value in ALL_SCOPES else None


__all__ = [
    "ALL_SCOPES",
    "NO_TENANT_DATA",
    "OPERATOR_ONLY",
    "PUBLIC",
    "SCOPE_ATTR",
    "TENANT_SCOPED",
    "CrossTenantDenied",
    "PrincipalScope",
    "bind_tenant_id",
    "caller_tenant_id",
    "declared_scope",
    "is_operator",
    "principal_of",
    "require_tenant_visible",
    "scope_queryset",
]
