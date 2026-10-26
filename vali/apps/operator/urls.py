from __future__ import annotations

from django.urls import path

from .maintenance_views import OperatorMaintenanceView
from .views import OperatorFleetView, OperatorNodesView, OperatorRegionsView

urlpatterns = [
    path("operator/fleet", OperatorFleetView.as_view(), name="operator_fleet"),
    path("operator/nodes", OperatorNodesView.as_view(), name="operator_nodes"),
    path("operator/regions", OperatorRegionsView.as_view(), name="operator_regions"),
    path(
        "operator/miners/<str:node_id>/maintenance",
        OperatorMaintenanceView.as_view(),
        name="operator_maintenance",
    ),
]
