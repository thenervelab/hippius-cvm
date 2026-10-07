from __future__ import annotations

from django.urls import path

from .views import (
    CdnCaBundleView,
    CdnNodeDnsReleasedView,
    CdnNodeDrainView,
    CdnNodesView,
    CdnRegionsView,
    CdnRegionView,
)

urlpatterns = [
    path("cdn/ca.pem", CdnCaBundleView.as_view(), name="cdn_ca_bundle"),
    path("cdn/nodes", CdnNodesView.as_view(), name="cdn_nodes"),
    path(
        "cdn/nodes/<str:node_id>/dns-released",
        CdnNodeDnsReleasedView.as_view(),
        name="cdn_node_dns_released",
    ),
    path("cdn/nodes/<str:node_id>/drain", CdnNodeDrainView.as_view(), name="cdn_node_drain"),
    path("cdn/regions", CdnRegionsView.as_view(), name="cdn_regions"),
    path("cdn/regions/<str:region>", CdnRegionView.as_view(), name="cdn_region"),
]
