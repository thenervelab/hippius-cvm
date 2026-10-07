from __future__ import annotations

from django.urls import path

from .views import (
    AvailabilityView,
    EdgeAddressesView,
    EdgeAppliedView,
    EdgeDesiredView,
    EdgeDetailView,
    EdgeListView,
    EgressRegionDetailView,
    EgressRegionListView,
    PublicIpSmtpView,
    VmPublicIpView,
)

urlpatterns = [
    path("vm/<str:vm_id>/public-ip", VmPublicIpView.as_view(), name="vm_public_ip"),
    path("network/availability", AvailabilityView.as_view(), name="network_availability"),
    path("network/edges", EdgeListView.as_view(), name="network_edges"),
    path("network/edges/<slug:name>", EdgeDetailView.as_view(), name="network_edge"),
    path(
        "network/edges/<slug:name>/addresses",
        EdgeAddressesView.as_view(),
        name="network_edge_addresses",
    ),
    path(
        "network/edges/<slug:name>/desired",
        EdgeDesiredView.as_view(),
        name="network_edge_desired",
    ),
    path(
        "network/edges/<slug:name>/applied",
        EdgeAppliedView.as_view(),
        name="network_edge_applied",
    ),
    path(
        "network/egress-regions", EgressRegionListView.as_view(), name="network_egress_regions"
    ),
    path(
        "network/egress-regions/<str:region>",
        EgressRegionDetailView.as_view(),
        name="network_egress_region",
    ),
    path(
        "network/public-ips/<str:address>/smtp",
        PublicIpSmtpView.as_view(),
        name="network_public_ip_smtp",
    ),
]
