"""`/v1/operator/miners` is published as a PREFIX on the public Ingress
(`publicApiIngress.allowedPaths`), so a route added under it later is public
the moment it exists. Pin exactly which routes live there and the gate on
each one."""

from __future__ import annotations

from django.urls import URLPattern, URLResolver, get_resolver

from apps.disktier import storage_views

#: The routes the prefix may serve. A new one fails here until its
#: publication is reviewed (and the values.yaml comment updated).
EXPECTED = {
    "v1/operator/miners/<str:node_id>/storage": "OperatorStorageView",
    "v1/operator/miners/<str:node_id>/storage/pools": "OperatorStoragePoolsView",
    "v1/operator/miners/<str:node_id>/storage/pools/<str:pool_id>": "OperatorStoragePoolView",
    "v1/operator/miners/<str:node_id>/storage/pools/<str:pool_id>/force-remove": (
        "OperatorStoragePoolForceRemoveView"
    ),
    "v1/operator/miners/<str:node_id>/storage/validate": "OperatorStorageValidateView",
    "v1/operator/miners/<str:node_id>/storage/adopt": "OperatorStorageAdoptView",
    "v1/operator/miners/<str:node_id>/storage/history": "OperatorStorageHistoryView",
    "v1/operator/miners/<str:node_id>/disk-tiers": "OperatorDiskTiersView",
    "v1/operator/miners/<str:node_id>/dedicated-disks": "OperatorDedicatedDisksView",
    "v1/operator/miners/<str:node_id>/dedicated-disks/<str:disk_id>/drain": (
        "OperatorDedicatedDiskDrainView"
    ),
    # §18.10 host inventory: read-only, owner-only (serials).
    "v1/operator/miners/<str:node_id>/hardware": "OperatorHardwareView",
    "v1/operator/miners/<str:node_id>/hardware/history": "OperatorHardwareHistoryView",
    "v1/operator/miners/<str:node_id>/disk-inventory": "OperatorDiskInventoryView",
    "v1/operator/miners/<str:node_id>/host-disk-advisories": "OperatorHostDiskAdvisoriesView",
}


def _routes_under(prefix: str) -> dict[str, type]:
    out: dict[str, type] = {}

    def walk(patterns, at: str = "") -> None:
        for p in patterns:
            if isinstance(p, URLResolver):
                walk(p.url_patterns, at + str(p.pattern))
            elif isinstance(p, URLPattern):
                route = at + str(p.pattern)
                if route.startswith(prefix):
                    out[route] = getattr(p.callback, "cls", None)

    walk(get_resolver().url_patterns)
    return out


def test_the_public_miners_prefix_serves_only_the_disktier_storage_routes() -> None:
    routes = _routes_under("v1/operator/miners")
    assert {r: (c.__name__ if c else None) for r, c in routes.items()} == EXPECTED


def test_every_route_under_the_prefix_keeps_its_gates() -> None:
    from rest_framework.permissions import IsAuthenticated

    from apps.identity import scoping
    from apps.operator.permissions import IsOperatorConfigWriter

    for route, cls in _routes_under("v1/operator/miners").items():
        assert issubclass(cls, storage_views._NodeStorageView), route
        assert scoping.declared_scope(cls) == scoping.OPERATOR_ONLY, route
        view = cls()
        for method in ("GET", "PUT", "POST", "PATCH", "DELETE"):
            view.request = type("R", (), {"method": method})()
            kinds = {type(p) for p in view.get_permissions()}
            assert IsAuthenticated in kinds, (route, method)
            if method != "GET":
                assert IsOperatorConfigWriter in kinds, (route, method)
