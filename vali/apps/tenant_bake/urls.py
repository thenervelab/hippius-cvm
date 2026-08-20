from __future__ import annotations

from django.urls import path

from .views import (
    TenantBakeCreateView,
    TenantBakeDetailView,
    TenantBakeFinalizeView,
)

urlpatterns = [
    path(
        "tenant-bakes",
        TenantBakeCreateView.as_view(),
        name="tenant_bake_create",
    ),
    path(
        "tenant-bakes/<str:bake_id>",
        TenantBakeDetailView.as_view(),
        name="tenant_bake_detail",
    ),
    path(
        "tenant-bakes/<str:bake_id>/finalize",
        TenantBakeFinalizeView.as_view(),
        name="tenant_bake_finalize",
    ),
]
