from __future__ import annotations

from django.urls import path

from .guardian_views import GuardianPolicyView, GuardianRevokeView, GuardianSetupKeyView
from .guest_upgrade_views import (
    GuestRolloutActionView,
    GuestRolloutsView,
    GuestRolloutView,
    VmGuestComponentsView,
    VmGuestUpgradeCancelView,
    VmGuestUpgradeJobView,
    VmGuestUpgradeRecoverView,
    VmGuestUpgradeView,
)
from .resize_views import VmResizeFlavorsView, VmResizeJobView, VmResizeView
from .restore_views import (
    VmFailoverView,
    VmRestoreCancelView,
    VmRestoreJobView,
    VmRestoreRevertView,
    VmRestoreView,
)
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
    # Customer-held keys: a tenant's key guardian on the NetBird mesh —
    # operator (root) only, no tenant surface (`guardian_views`).
    path(
        "guardian/<str:tenant_id>/netbird/setup-key",
        GuardianSetupKeyView.as_view(),
        name="guardian_netbird_setup_key",
    ),
    path(
        "guardian/<str:tenant_id>/netbird/policy",
        GuardianPolicyView.as_view(),
        name="guardian_netbird_policy",
    ),
    path(
        "guardian/<str:tenant_id>/netbird",
        GuardianRevokeView.as_view(),
        name="guardian_netbird_revoke",
    ),
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
    # Restore from a backup (`restore.py`) — root-only.
    path("vm/<str:vm_id>/restore", VmRestoreView.as_view(), name="vm_restore"),
    path(
        "vm/<str:vm_id>/restore/<str:job_id>",
        VmRestoreJobView.as_view(),
        name="vm_restore_job",
    ),
    path(
        "vm/<str:vm_id>/restore/<str:job_id>/cancel",
        VmRestoreCancelView.as_view(),
        name="vm_restore_cancel",
    ),
    path(
        "vm/<str:vm_id>/restore/<str:job_id>/revert",
        VmRestoreRevertView.as_view(),
        name="vm_restore_revert",
    ),
    # Manual failover off a dead miner (`restore.start_failover`) — root-only.
    path("vm/<str:vm_id>/failover", VmFailoverView.as_view(), name="vm_failover"),
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
    # Resize (`resize.py`) — root-only. `resize/flavors` is listed before
    # `resize/<job_id>` so it can never be read as a job id.
    path(
        "vm/<str:vm_id>/resize/flavors",
        VmResizeFlavorsView.as_view(),
        name="vm_resize_flavors",
    ),
    path("vm/<str:vm_id>/resize", VmResizeView.as_view(), name="vm_resize"),
    path(
        "vm/<str:vm_id>/resize/<str:job_id>",
        VmResizeJobView.as_view(),
        name="vm_resize_job",
    ),
    # Guest components upgrade (`guest_upgrade.py`) — root-only.
    path(
        "vm/<str:vm_id>/guest-components",
        VmGuestComponentsView.as_view(),
        name="vm_guest_components",
    ),
    path("vm/<str:vm_id>/guest-upgrade", VmGuestUpgradeView.as_view(), name="vm_guest_upgrade"),
    path(
        "vm/<str:vm_id>/guest-upgrade/<str:job_id>",
        VmGuestUpgradeJobView.as_view(),
        name="vm_guest_upgrade_job",
    ),
    path(
        "vm/<str:vm_id>/guest-upgrade/<str:job_id>/cancel",
        VmGuestUpgradeCancelView.as_view(),
        name="vm_guest_upgrade_cancel",
    ),
    path(
        "vm/<str:vm_id>/guest-upgrade/<str:job_id>/recover",
        VmGuestUpgradeRecoverView.as_view(),
        name="vm_guest_upgrade_recover",
    ),
    path("guest-rollouts", GuestRolloutsView.as_view(), name="guest_rollouts"),
    path("guest-rollouts/<str:rollout_id>", GuestRolloutView.as_view(), name="guest_rollout"),
    *(
        path(
            f"guest-rollouts/<str:rollout_id>/{action}",
            GuestRolloutActionView.as_view(action=action),
            name=f"guest_rollout_{action}",
        )
        for action in ("pause", "resume", "abort")
    ),
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
