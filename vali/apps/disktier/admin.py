"""Read-only admin for the disk-tier tables. Nothing here is editable: a
tier comes from a probe, an override goes through `vali_set_pool_tier`
(audited), and the rest is written by the agent's reports and the probe
pipeline. An admin edit would bypass all three."""

from __future__ import annotations

from typing import Any

from django.contrib import admin
from django.http import HttpRequest

from .models import (
    DedicatedDisk,
    DiskProbeRun,
    MinerDiskHealthHourly,
    MinerStorageConfig,
    MinerStorageConfigAudit,
    MinerStoragePool,
    PlacementDisk,
    VmDiskIoHourly,
    VmStorageMove,
)


class _ReadOnlyAdmin(admin.ModelAdmin):
    def has_add_permission(self, request: HttpRequest) -> bool:
        return False

    def has_change_permission(self, request: HttpRequest, obj: Any = None) -> bool:
        return False

    def has_delete_permission(self, request: HttpRequest, obj: Any = None) -> bool:
        return False


@admin.register(MinerStoragePool)
class MinerStoragePoolAdmin(_ReadOnlyAdmin):
    list_display = (
        "miner_node_id",
        "pool_id",
        "declared_class",
        "os_disks",
        "tier",
        "operator_override",
        "health",
        "budget_gb",
        "reported_at",
        "retired_at",
    )
    list_filter = ("tier", "operator_override", "health", "declared_class")
    search_fields = ("miner_node_id", "pool_id")


@admin.register(DedicatedDisk)
class DedicatedDiskAdmin(_ReadOnlyAdmin):
    list_display = (
        "miner_node_id",
        "disk_id",
        "size_bytes",
        "state",
        "desired_state",
        "verified_tier",
        "declared_class",
        "assigned_vm",
        "assigned_slot",
        "probed_at",
    )
    list_filter = ("state", "desired_state", "verified_tier", "behind_controller")
    search_fields = ("miner_node_id", "disk_id", "assigned_vm__vm_id")


@admin.register(DiskProbeRun)
class DiskProbeRunAdmin(_ReadOnlyAdmin):
    list_display = (
        "run_id",
        "miner_node_id",
        "vm_id",
        "trigger",
        "state",
        "flavor",
        "scheduled_at",
        "result_at",
        "failure_reason",
    )
    list_filter = ("state", "trigger")
    search_fields = ("run_id", "vm_id", "miner_node_id")
    exclude = ("nonce",)


@admin.register(PlacementDisk)
class PlacementDiskAdmin(_ReadOnlyAdmin):
    list_display = (
        "placement",
        "slot",
        "kind",
        "pool_id",
        "dedicated_disk",
        "size_gb",
        "required_tier",
    )
    list_filter = ("kind", "required_tier")


@admin.register(VmDiskIoHourly)
class VmDiskIoHourlyAdmin(_ReadOnlyAdmin):
    list_display = ("vm_id", "device", "slot", "pool_id", "miner_node_id", "hour", "windows")
    search_fields = ("vm_id", "miner_node_id")


@admin.register(MinerDiskHealthHourly)
class MinerDiskHealthHourlyAdmin(_ReadOnlyAdmin):
    list_display = (
        "miner_node_id",
        "pool_id",
        "disk_id",
        "hour",
        "owners",
        "vms",
        "median_owner_await_us",
        "verdict",
    )
    list_filter = ("verdict",)


@admin.register(MinerStorageConfig)
class MinerStorageConfigAdmin(_ReadOnlyAdmin):
    """Read-only: the desired document changes only through the audited
    operator API (`apps.disktier.storage_views`)."""

    list_display = (
        "miner_node_id",
        "revision",
        "acked_revision",
        "reported_revision",
        "refusal_code",
        "last_error",
        "sent_at",
        "updated_by_family",
        "updated_at",
    )
    search_fields = ("miner_node_id",)


@admin.register(MinerStorageConfigAudit)
class MinerStorageConfigAuditAdmin(_ReadOnlyAdmin):
    list_display = ("miner_node_id", "revision", "action", "outcome", "principal", "family", "at")
    list_filter = ("action",)
    search_fields = ("miner_node_id", "family", "user")


@admin.register(VmStorageMove)
class VmStorageMoveAdmin(_ReadOnlyAdmin):
    list_display = (
        "vm",
        "miner_node_id",
        "source_pool",
        "target_pool",
        "state",
        "agent_phase",
        "code",
        "created_at",
        "finished_at",
    )
    list_filter = ("state",)
    search_fields = ("vm__vm_id", "miner_node_id")
