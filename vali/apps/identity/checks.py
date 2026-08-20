"""P2 — the startup gate that makes tenant scoping unforgettable.

`manage.py check` walks every URL routed under `/v1/` and errors if a
DRF view class has not declared its `object_scope`
(`apps.identity.scoping`). CI runs `manage.py check`, and Django runs
the system checks on `runserver`/`migrate` and on the container's own
management-command entrypoints — so an endpoint added without stating
its tenant posture fails before it can ship.

This is the *structural* half of the mechanism. The runtime half
(`PrincipalScopeMiddleware`) refuses an undeclared endpoint to
tenant-scoped principals, so even a check that somebody skipped cannot
produce a cross-tenant read.
"""

from __future__ import annotations

from typing import Any

from django.core.checks import Error, register
from django.urls import URLPattern, URLResolver, get_resolver

from .scoping import ALL_SCOPES, SCOPE_ATTR, declared_scope

#: Same prefix + exemptions the middleware governs. Kept in sync by
#: `apps.identity.tests.test_scope_checks::test_exempt_sets_agree`.
API_PREFIX = "v1/"
EXEMPT_ROUTES = frozenset(
    {"v1/schema", "v1/docs", "v1/redoc", "v1/public/schema", "v1/public/docs"}
)

CHECK_ID = "identity.E001"


def _walk(patterns: Any, prefix: str = "") -> list[tuple[str, Any]]:
    """Flatten a URLconf into `(route, callback)` pairs."""
    out: list[tuple[str, Any]] = []
    for entry in patterns:
        if isinstance(entry, URLResolver):
            out.extend(_walk(entry.url_patterns, prefix + str(entry.pattern)))
        elif isinstance(entry, URLPattern):
            out.append((prefix + str(entry.pattern), entry.callback))
    return out


def undeclared_api_views(urlconf: str | None = None) -> list[tuple[str, Any]]:
    """`(route, view_class)` for every `/v1/` DRF view missing a scope.

    Exposed (not private) so tests can assert on it directly with an
    overridden `ROOT_URLCONF`.
    """
    resolver = get_resolver(urlconf)
    missing: list[tuple[str, Any]] = []
    for route, callback in _walk(resolver.url_patterns):
        if not route.startswith(API_PREFIX):
            continue
        if route.rstrip("/") in EXEMPT_ROUTES:
            continue
        view_cls = getattr(callback, "cls", None)
        if view_cls is None:
            # A plain function view (there are none under /v1/ today).
            # Nothing to declare on; skip rather than block.
            continue
        if declared_scope(view_cls) is None:
            missing.append((route, view_cls))
    return missing


@register()
def check_api_views_declare_object_scope(app_configs, **_kwargs) -> list[Error]:
    """Error on any `/v1/` view that did not declare `object_scope`."""
    errors: list[Error] = []
    for route, view_cls in undeclared_api_views():
        declared = getattr(view_cls, SCOPE_ATTR, None)
        detail = (
            f"has {SCOPE_ATTR}={declared!r}, which is not one of "
            f"{sorted(ALL_SCOPES)}"
            if declared is not None
            else f"does not set {SCOPE_ATTR}"
        )
        errors.append(
            Error(
                f"/{route} → {view_cls.__module__}.{view_cls.__qualname__} {detail}.",
                hint=(
                    f"Every view under /{API_PREFIX} must declare its tenant "
                    f"posture: set `{SCOPE_ATTR} = <one of "
                    f"{sorted(ALL_SCOPES)}>` (see apps.identity.scoping). A "
                    "TENANT_SCOPED view must also filter its reads through "
                    "scope_queryset()/require_tenant_visible()."
                ),
                obj=view_cls,
                id=CHECK_ID,
            )
        )
    return errors
