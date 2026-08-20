"""Top-level URL routing for the vali service.

PR-G1: `/healthz` + `/v1/order_ticket`.
PR-G2: `/v1/vm/<id>/state` + `/v1/vm/<id>/transition` (lifecycle SM).
PR-G3: `/v1/packer/build/...` (Packer trigger + S3 presigning).
PR-G4: `/v1/scheduler/...` (§23 trustless scheduler).
PR-G5: `/v1/vm/<id>/migrate` + `/decommission` (§24/§25 orchestration).
PR-G6: `/v1/telemetry/ingest` + `/pull` (§9 pull-only telemetry broker).
PR-vali-miner-register: `/v1/admin/miner/...` (miner-fleet registry).
"""

from __future__ import annotations

from django.contrib import admin
from django.http import HttpRequest, JsonResponse
from django.urls import include, path
from drf_spectacular.views import (
    SpectacularAPIView,
    SpectacularRedocView,
    SpectacularSwaggerView,
)
from rest_framework.permissions import AllowAny

from vali.public_schema import PublicSchemaView, PublicSwaggerView


def healthz(_request: HttpRequest) -> JsonResponse:
    """Cheap liveness probe.

    Intentionally NOT authenticated — the load balancer needs to reach
    it. Returns only a static literal; no DB, no validator, nothing
    that could surface secrets through a 500.
    """
    return JsonResponse({"status": "ok"})


urlpatterns = [
    path("healthz", healthz, name="healthz"),
    # Ops eyeball admin (#152). Kept OUTSIDE the `/v1/` API prefix so
    # operators / probes / NetworkPolicies can distinguish admin
    # traffic from the L1↔vali API signaling. The vali Service is
    # ClusterIP — the admin is NEVER reachable from outside the
    # cluster (no Ingress); ops reach it via `kubectl port-forward`.
    path("admin/", admin.site.urls),
    path("v1/", include("apps.orders.urls")),
    path("v1/", include("apps.images.urls")),
    path("v1/", include("apps.lifecycle.urls")),
    path("v1/", include("apps.packer.urls")),
    path("v1/", include("apps.tenant_bake.urls")),
    path("v1/", include("apps.scheduler.urls")),
    path("v1/", include("apps.orchestration.urls")),
    path("v1/", include("apps.telemetry.urls")),
    path("v1/", include("apps.miners.urls")),
    # OpenAPI 3 API documentation (drf-spectacular). The schema + docs are
    # unauthenticated *documentation* (they describe the API shape; the
    # endpoints themselves stay auth-gated).
    #
    # These three describe ALL routes and are PRIVATE. They used to be
    # private because vali was ClusterIP with no Ingress; that is no
    # longer what keeps them in — `publicApiIngress` publishes a hostname
    # now, and what keeps these off it is its path allow-list. Adding
    # `/v1/schema` or `/v1/docs` to `allowedPaths` would publish a map of
    # the internal control plane, including the miner-plane routes whose
    # own descriptions state they carry no service-token auth. Publish
    # `/v1/public/docs` below instead — it is the same generator, filtered
    # to what is actually reachable.
    path(
        "v1/schema",
        SpectacularAPIView.as_view(permission_classes=[AllowAny]),
        name="schema",
    ),
    path(
        "v1/docs",
        SpectacularSwaggerView.as_view(url_name="schema", permission_classes=[AllowAny]),
        name="swagger-ui",
    ),
    path(
        "v1/redoc",
        SpectacularRedocView.as_view(url_name="schema", permission_classes=[AllowAny]),
        name="redoc",
    ),
    # The PUBLIC pair, safe to publish through the Ingress: the same
    # generator filtered to `VALI_PUBLIC_API_PATHS`, which the chart
    # renders from the very `publicApiIngress.allowedPaths` that builds
    # the Ingress — so the docs cannot describe a route the Ingress does
    # not serve, nor omit one it does. See `vali/public_schema.py`.
    path(
        "v1/public/schema",
        PublicSchemaView.as_view(),
        name="public-schema",
    ),
    path(
        "v1/public/docs",
        PublicSwaggerView.as_view(),
        name="public-swagger-ui",
    ),
]
