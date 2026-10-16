from __future__ import annotations

from django.urls import path

from .storage_views import (
    OperatorDedicatedDiskDrainView,
    OperatorDedicatedDisksView,
    OperatorDiskTiersView,
    OperatorStorageAdoptView,
    OperatorStorageHistoryView,
    OperatorStoragePoolsView,
    OperatorStoragePoolView,
    OperatorStorageValidateView,
    OperatorStorageView,
)
from .views import OperatorDiskProfilesView

_NODE = "operator/miners/<str:node_id>"

urlpatterns = [
    path(
        "operator/disk-profiles",
        OperatorDiskProfilesView.as_view(),
        name="operator_disk_profiles",
    ),
    path(f"{_NODE}/storage", OperatorStorageView.as_view(), name="operator_storage"),
    path(
        f"{_NODE}/storage/pools",
        OperatorStoragePoolsView.as_view(),
        name="operator_storage_pools",
    ),
    path(
        f"{_NODE}/storage/pools/<str:pool_id>",
        OperatorStoragePoolView.as_view(),
        name="operator_storage_pool",
    ),
    path(
        f"{_NODE}/storage/validate",
        OperatorStorageValidateView.as_view(),
        name="operator_storage_validate",
    ),
    path(
        f"{_NODE}/storage/adopt",
        OperatorStorageAdoptView.as_view(),
        name="operator_storage_adopt",
    ),
    path(
        f"{_NODE}/storage/history",
        OperatorStorageHistoryView.as_view(),
        name="operator_storage_history",
    ),
    path(f"{_NODE}/disk-tiers", OperatorDiskTiersView.as_view(), name="operator_disk_tiers"),
    path(
        f"{_NODE}/dedicated-disks",
        OperatorDedicatedDisksView.as_view(),
        name="operator_dedicated_disks",
    ),
    path(
        f"{_NODE}/dedicated-disks/<str:disk_id>/drain",
        OperatorDedicatedDiskDrainView.as_view(),
        name="operator_dedicated_disk_drain",
    ),
]
