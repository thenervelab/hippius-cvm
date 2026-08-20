"""Django admin registrations for `apps.scheduler` (#152).

`MinerCapacity` is a cache rebuilt from the chain on every `/place`,
`/fail`, and re-eval cycle — most columns are owned by the
`read-miner-status` shell-out and are forced read-only here.
`capacity_slots` is the one operator-tunable knob (§23 admission
bound) and is left editable so ops can pin per-miner caps without a
deploy.

`Placement` rows are an §23 operator log — the lifecycle columns
(status, timestamps, version, kbs_release_ref) are owned by /place,
/bind, /fail; admin edits would corrupt the partial-unique-active-
placement-per-VM invariant the DB enforces.
"""

from __future__ import annotations

from django.contrib import admin

from .models import MinerCapacity, Placement


@admin.register(MinerCapacity)
class MinerCapacityAdmin(admin.ModelAdmin):
    list_display = (
        "miner_node_id",
        "status",
        "quality",
        "capacity_slots",
        "observed_epoch",
        "data_epoch",
        "refreshed_at",
    )
    list_filter = ("status",)
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
    )
    ordering = ("miner_node_id",)


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
    list_filter = ("status",)
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
        "version",
    )
    ordering = ("-decided_at",)
