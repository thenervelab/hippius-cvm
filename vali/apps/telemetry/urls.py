from __future__ import annotations

from django.urls import path

from .views import (
    HostAttestorBeaconIngestView,
    HostAttestorCertIngestView,
    HostAttestorChallengeView,
    HostAttestorDesiredView,
    HostAttestorReleaseView,
    MinerGracefulExitIngestView,
    MinerVmProgressIngestView,
    TelemetryIngestView,
    TelemetryPullView,
    VmLiveAttestationIngestView,
)

urlpatterns = [
    path(
        "telemetry/ingest",
        TelemetryIngestView.as_view(),
        name="telemetry_ingest",
    ),
    path(
        "telemetry/graceful-exit",
        MinerGracefulExitIngestView.as_view(),
        name="telemetry_graceful_exit",
    ),
    path(
        "telemetry/vm-progress",
        MinerVmProgressIngestView.as_view(),
        name="telemetry_vm_progress",
    ),
    path(
        "telemetry/host-attestor/cert",
        HostAttestorCertIngestView.as_view(),
        name="telemetry_host_attestor_cert",
    ),
    path(
        "telemetry/host-attestor/heartbeat",
        HostAttestorBeaconIngestView.as_view(),
        name="telemetry_host_attestor_beacon",
    ),
    path(
        "telemetry/host-attestor/challenge",
        HostAttestorChallengeView.as_view(),
        name="telemetry_host_attestor_challenge",
    ),
    # Blackbox host-attestor release + desired (PR-9).
    path(
        "admin/host-attestor/release",
        HostAttestorReleaseView.as_view(),
        name="host_attestor_release",
    ),
    path(
        "miner/<str:node_id>/host-attestor/desired",
        HostAttestorDesiredView.as_view(),
        name="host_attestor_desired",
    ),
    # §23 uptime-liveness coverage — the KBS-signed proof a tenant CVM
    # was genuinely ALIVE, which a killed VM cannot produce.
    path(
        "telemetry/vm-liveness",
        VmLiveAttestationIngestView.as_view(),
        name="telemetry_vm_liveness",
    ),
    path(
        "telemetry/pull",
        TelemetryPullView.as_view(),
        name="telemetry_pull",
    ),
]
