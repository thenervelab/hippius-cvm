from __future__ import annotations

from django.urls import path

from .views import (
    EdgeRegistryFeedView,
    EpochWeightsView,
    PriceRecommendationApproveView,
    PriceRecommendationDismissView,
    PriceRecommendationListView,
    SchedulerBindView,
    SchedulerCapacityView,
    SchedulerFailView,
    SchedulerPlaceView,
)

urlpatterns = [
    # Edge permissionless-auth registry feed (PR-2): the Edge polls this
    # for the registered+Active node_id set (it cannot reach the chain
    # RPC directly — egress-locked). Public on-chain data, in-cluster.
    path("edge/registry", EdgeRegistryFeedView.as_view(), name="edge_registry_feed"),
    # #587 Phase 3 — the upstream's pre-launch availability view.
    path(
        "scheduler/capacity",
        SchedulerCapacityView.as_view(),
        name="scheduler_capacity",
    ),
    # §23 per-miner reward weights — the epoch-close worker reads these to
    # submit REAL merit (vs a flat weight).
    path(
        "admin/epoch-weights",
        EpochWeightsView.as_view(),
        name="epoch_weights",
    ),
    path("scheduler/place", SchedulerPlaceView.as_view(), name="scheduler_place"),
    path(
        "scheduler/<str:vm_id>/bind",
        SchedulerBindView.as_view(),
        name="scheduler_bind",
    ),
    path(
        "scheduler/<str:vm_id>/fail",
        SchedulerFailView.as_view(),
        name="scheduler_fail",
    ),
    # §23 marketplace price-migration alerts (vSphere-DRS-manual): a price
    # breach raises a recommendation an operator approves (→ migration) or
    # dismisses. The watcher NEVER auto-migrates on price.
    path(
        "price-recommendations",
        PriceRecommendationListView.as_view(),
        name="price_recommendation_list",
    ),
    path(
        "price-recommendations/<str:recommendation_id>/approve",
        PriceRecommendationApproveView.as_view(),
        name="price_recommendation_approve",
    ),
    path(
        "price-recommendations/<str:recommendation_id>/dismiss",
        PriceRecommendationDismissView.as_view(),
        name="price_recommendation_dismiss",
    ),
]
