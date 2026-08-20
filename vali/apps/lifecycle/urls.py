from __future__ import annotations

from django.urls import path

from .views import (
    StoppedAckIngestView,
    VmAttestationView,
    VmListView,
    VmStateView,
    VmTransitionView,
)

urlpatterns = [
    # #587 Phase 2 — the upstream API lists VMs here (service principal).
    path("vm", VmListView.as_view(), name="vm_list"),
    path("vm/<str:vm_id>/state", VmStateView.as_view(), name="vm_state"),
    path(
        "vm/<str:vm_id>/attestation",
        VmAttestationView.as_view(),
        name="vm_attestation",
    ),
    path("vm/<str:vm_id>/transition", VmTransitionView.as_view(), name="vm_transition"),
    # Guest-pushed `SignedStoppedAck` ingress (§24/§25). AllowAny — the
    # measured guest reaches vali over the public front door; the verify
    # step (not this store) is the trust gate.
    path(
        "lifecycle/stopped",
        StoppedAckIngestView.as_view(),
        name="lifecycle_stopped_ack",
    ),
]
