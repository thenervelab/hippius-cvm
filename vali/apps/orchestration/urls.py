from __future__ import annotations

from django.urls import path

from .views import (
    DecommissionJobView,
    DecommissionStartView,
    LaunchJobView,
    LaunchStartView,
    MeasurementAuditView,
    MigrateCancelView,
    MigrateJobView,
    MigrateStartView,
    VmRebootView,
    VmStartView,
    VmStopView,
)

urlpatterns = [
    # Launch (PR-A2) — the static `vm/launch` paths are listed before the
    # `vm/<vm_id>/…` patterns so a job_id can never shadow a vm_id.
    path(
        "vm/launch",
        LaunchStartView.as_view(),
        name="vm_launch",
    ),
    path(
        "vm/launch/<str:job_id>",
        LaunchJobView.as_view(),
        name="vm_launch_job",
    ),
    path(
        "vm/<str:vm_id>/migrate",
        MigrateStartView.as_view(),
        name="vm_migrate",
    ),
    path(
        "vm/<str:vm_id>/migrate/<str:job_id>",
        MigrateJobView.as_view(),
        name="vm_migrate_job",
    ),
    # #587 Phase 3 — abort an in-flight pre-Fencing §25 migration.
    path(
        "vm/<str:vm_id>/migrate/<str:job_id>/cancel",
        MigrateCancelView.as_view(),
        name="vm_migrate_cancel",
    ),
    path(
        "vm/<str:vm_id>/decommission",
        DecommissionStartView.as_view(),
        name="vm_decommission",
    ),
    # Power operations — NOT lifecycle transitions. They move
    # `Vm.power_state`; `Vm.state` (the KBS release gate) is untouched.
    path("vm/<str:vm_id>/stop", VmStopView.as_view(), name="vm_stop"),
    path("vm/<str:vm_id>/start", VmStartView.as_view(), name="vm_start"),
    path("vm/<str:vm_id>/reboot", VmRebootView.as_view(), name="vm_reboot"),
    path(
        "vm/<str:vm_id>/decommission/<str:job_id>",
        DecommissionJobView.as_view(),
        name="vm_decommission_job",
    ),
    # #587 Phase 3 — fleet-wide pinned-measurement audit ledger (root).
    path(
        "admin/audit/measurements",
        MeasurementAuditView.as_view(),
        name="measurement_audit",
    ),
]
