"""Django admin registrations for `apps.orchestration` (#152).

`MigrationJob` and `DecommissionJob` are durable, idempotent op
records driven by the `vali_orchestration_tick` management command.
Hand-editing a job's `state` from the admin would corrupt the §24
data-death / §25 split-brain invariants — the orchestrator's
optimistic-CAS step is the only sanctioned writer. All lifecycle
columns (state, version, ack flags, phase timestamp, finished_at,
quarantine handoff) are forced read-only.
"""

from __future__ import annotations

from django.contrib import admin

from .models import DecommissionJob, LaunchJob, MigrationJob


@admin.register(LaunchJob)
class LaunchJobAdmin(admin.ModelAdmin):
    list_display = (
        "job_id",
        "vm_id",
        "tenant_id",
        "flavor",
        "state",
        "miner_id",
        "started_at",
        "finished_at",
    )
    list_filter = ("state", "flavor")
    search_fields = ("job_id", "vm_id", "tenant_id", "miner_id")
    raw_id_fields = ("decided_by",)
    readonly_fields = (
        "id",
        # Lifecycle + secret-ref columns — the worker owns these. The
        # admin inspects; it never re-drives a launch or rewrites a ref.
        "state",
        "spec_json",
        "userdata_vault_path",
        "userdata_vault_version",
        "kek_vault_path",
        "result_json",
        "miner_id",
        "placement_id",
        "phase_started_at",
        "started_at",
        "finished_at",
        "version",
    )
    ordering = ("-started_at",)


@admin.register(MigrationJob)
class MigrationJobAdmin(admin.ModelAdmin):
    list_display = (
        "job_id",
        "vm",
        "source_node_id",
        "dest_node_id",
        "source_gen",
        "new_gen",
        "state",
        "source_ack_verified",
        "source_reclaim_state",
        "strand_recovery_state",
        "started_at",
        "finished_at",
    )
    list_filter = (
        "state",
        "source_ack_verified",
        "source_reclaim_state",
        "strand_recovery_state",
    )
    search_fields = (
        "job_id",
        "vm__vm_id",
        "source_node_id",
        "dest_node_id",
        "quarantine_node_id",
    )
    raw_id_fields = ("vm", "decided_by")
    readonly_fields = (
        "id",
        # Lifecycle columns — the orchestrator owns these; the admin
        # exists to inspect, never to retro-edit a job's state.
        "state",
        "source_ack_verified",
        "source_reclaim_state",
        "source_reclaim_at",
        "source_reclaim_reason",
        # `failed_from_state` is the PERMIT input to a §25 source restore
        # (it says whether the KBS was ever moved). Editable, it would be
        # an un-fence-any-VM primitive — read-only, hard.
        "failed_from_state",
        "strand_recovery_state",
        "strand_recovery_at",
        "strand_recovery_reason",
        "quarantine_node_id",
        "phase_started_at",
        "started_at",
        "finished_at",
        "version",
    )
    ordering = ("-started_at",)


@admin.register(DecommissionJob)
class DecommissionJobAdmin(admin.ModelAdmin):
    list_display = (
        "job_id",
        "vm",
        "state",
        "eol_ack_verified",
        "forced",
        "started_at",
        "finished_at",
    )
    list_filter = ("state", "eol_ack_verified", "forced")
    search_fields = ("job_id", "vm__vm_id", "quarantine_node_id")
    raw_id_fields = ("vm", "decided_by")
    readonly_fields = (
        "id",
        "state",
        "eol_ack_verified",
        "forced",
        "quarantine_node_id",
        "phase_started_at",
        "started_at",
        "finished_at",
        "version",
    )
    ordering = ("-started_at",)
