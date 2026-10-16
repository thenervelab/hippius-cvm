from __future__ import annotations

from django.urls import path

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
    # Miner-self-service (the Ed25519 signature is the credential — NOT
    # under `admin/`, no service token).
    path(
        "miner/<str:miner_id>/graceful-exit",
        MinerGracefulExitView.as_view(),
        name="miner_graceful_exit",
    ),
]
