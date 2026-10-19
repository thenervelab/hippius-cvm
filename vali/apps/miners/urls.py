from __future__ import annotations

from django.urls import path

from .hardware_views import (
    MinerDiskInventoryView,
    MinerHardwareHistoryView,
    MinerHardwareView,
    MinerHostDiskAdvisoriesView,
)
from .views import (
    MinerApprovalView,
    MinerGracefulExitView,
    MinerListView,
    MinerQuarantineView,
    MinerRegisterView,
)

urlpatterns = [
    path(
        "admin/miner/register",
        MinerRegisterView.as_view(),
        name="miner_register",
    ),
    path(
        "admin/miner/list",
        MinerListView.as_view(),
        name="miner_list",
    ),
    path(
        "admin/miner/<str:miner_id>/quarantine",
        MinerQuarantineView.as_view(),
        name="miner_quarantine",
    ),
    path(
        "admin/miner/<str:miner_id>/approval",
        MinerApprovalView.as_view(),
        name="miner_approval",
    ),
    # Miner-admin support reads of the host inventory, serials withheld
    # (`apps.miners.hardware_views`).
    path(
        "admin/miner/<str:miner_id>/hardware",
        MinerHardwareView.as_view(),
        name="miner_admin_hardware",
    ),
    path(
        "admin/miner/<str:miner_id>/hardware/history",
        MinerHardwareHistoryView.as_view(),
        name="miner_admin_hardware_history",
    ),
    path(
        "admin/miner/<str:miner_id>/disk-inventory",
        MinerDiskInventoryView.as_view(),
        name="miner_admin_disk_inventory",
    ),
    path(
        "admin/miner/<str:miner_id>/host-disk-advisories",
        MinerHostDiskAdvisoriesView.as_view(),
        name="miner_admin_host_disk_advisories",
    ),
    # Miner-self-service (the Ed25519 signature is the credential — NOT
    # under `admin/`, no service token).
    path(
        "miner/<str:miner_id>/graceful-exit",
        MinerGracefulExitView.as_view(),
        name="miner_graceful_exit",
    ),
]
