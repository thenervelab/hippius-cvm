from __future__ import annotations

from django.urls import path

from .views import OperatorFleetView, OperatorNodesView, OperatorRegionsView

urlpatterns = [
    path("operator/fleet", OperatorFleetView.as_view(), name="operator_fleet"),
    path("operator/nodes", OperatorNodesView.as_view(), name="operator_nodes"),
    path("operator/regions", OperatorRegionsView.as_view(), name="operator_regions"),
]
