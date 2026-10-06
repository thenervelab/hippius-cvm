"""Django admin registrations for `apps.scheduler` (#152).

`MinerCapacity` is a cache rebuilt from the chain on every `/place`,
`/fail`, and re-eval cycle — most columns are owned by the
`read-miner-status` shell-out and are forced read-only here.
The capacity-policy columns (`capacity_slots`, the hardware anchor,
the ratio, the trust class, the earned ceiling) are read-only here too:
their one supported writer is `vali_set_miner_capacity`, which audits
every change (`MinerCapacityAudit`). An admin edit would be an
unaudited capacity decision — exactly what that table exists to end.

`Placement` rows are an §23 operator log — the lifecycle columns
(status, timestamps, version, kbs_release_ref) are owned by /place,
/bind, /fail; admin edits would corrupt the partial-unique-active-
placement-per-VM invariant the DB enforces.
"""

from __future__ import annotations

from django.contrib import admin

from .capacity_admin import AUDITED_FIELDS, WORKING_FIELDS
from .models import MinerCapacity, MinerCapacityAudit, Placement


@admin.register(MinerCapacity)
class MinerCapacityAdmin(admin.ModelAdmin):
    list_display = (
        "miner_node_id",
        "status",
        "quality",
        "trust_class",
        "capacity_slots",
        "observed_epoch",
        "data_epoch",
        "refreshed_at",
    )
    list_filter = ("status", "trust_class")
    search_fields = ("miner_node_id",)
    readonly_fields = (
        "id",
        # Cache columns — overwritten by the chain refresh. Mutating
        # them from the admin gives a false reading until the next
        # refresh cycle stomps it.
        "status",
        "quality",
        "observed_epoch",
        "data_epoch",
        "refreshed_at",
        "created_at",
        # Capacity policy — audited writes through the command only.
        *sorted(AUDITED_FIELDS | WORKING_FIELDS),
        # Untrusted heartbeat state — written by the ingest only.
        "reported_memory_available_mib",
        "reported_at",
        "declared_cpu_budget",
        "declared_memory_mb_budget",
        "declared_asid_capacity",
        "declared_asid_used",
        "declared_at",
    )
    ordering = ("miner_node_id",)


@admin.register(MinerCapacityAudit)
class MinerCapacityAuditAdmin(admin.ModelAdmin):
    """Append-only history — viewable, never editable or deletable."""

    list_display = ("created_at", "miner_node_id", "field", "actor", "reason")
    list_filter = ("field", "actor")
    search_fields = ("miner_node_id", "reason")
    ordering = ("-created_at",)

    def has_add_permission(self, request: object) -> bool:
        return False

    def has_change_permission(self, request: object, obj: object = None) -> bool:
        return False

    def has_delete_permission(self, request: object, obj: object = None) -> bool:
        return False


@admin.register(Placement)
class PlacementAdmin(admin.ModelAdmin):
    list_display = (
        "id",
        "vm",
        "vm_family",
        "miner_node_id",
        "status",
        "chain_epoch",
        "decided_at",
        "bound_at",
        "failed_at",
    )
    list_filter = ("status", "failure_source")
    search_fields = (
        "vm__vm_id",
        "vm_family",
        "miner_node_id",
        "kbs_release_ref",
        "reason",
    )
    raw_id_fields = ("vm", "decided_by")
    readonly_fields = (
        "id",
        "status",
        "chain_epoch",
        "decided_at",
        "bound_at",
        "failed_at",
        "kbs_release_ref",
        "reason",
        "failure_source",
        "version",
    )
    ordering = ("-decided_at",)
