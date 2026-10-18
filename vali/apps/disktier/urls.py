from __future__ import annotations

from django.urls import path

from .hardware_views import (
    OperatorDiskInventoryView,
    OperatorHardwareHistoryView,
    OperatorHardwareView,
    OperatorHostDiskAdvisoriesView,
)
from .storage_views import (
    OperatorDedicatedDiskDrainView,
    OperatorDedicatedDisksView,
    OperatorDiskTiersView,
    OperatorStorageAdoptView,
    OperatorStorageHistoryView,
    OperatorStoragePoolForceRemoveView,
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
        f"{_NODE}/storage/pools/<str:pool_id>/force-remove",
        OperatorStoragePoolForceRemoveView.as_view(),
        name="operator_storage_pool_force_remove",
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
    path(f"{_NODE}/hardware", OperatorHardwareView.as_view(), name="operator_hardware"),
    path(
        f"{_NODE}/hardware/history",
        OperatorHardwareHistoryView.as_view(),
        name="operator_hardware_history",
    ),
    path(
        f"{_NODE}/disk-inventory",
        OperatorDiskInventoryView.as_view(),
        name="operator_disk_inventory",
    ),
    path(
        f"{_NODE}/host-disk-advisories",
        OperatorHostDiskAdvisoriesView.as_view(),
        name="operator_host_disk_advisories",
    ),
]
