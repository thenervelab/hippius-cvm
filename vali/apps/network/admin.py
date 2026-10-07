from __future__ import annotations

from django.contrib import admin

from .models import EgressRegion, IngressEdge, MinerNetPolicy, PublicIP, VmEgressLease


@admin.register(IngressEdge)
class IngressEdgeAdmin(admin.ModelAdmin):
    list_display = ("name", "region", "status", "netbird_ip", "egress_ip", "desired_revision",
                    "applied_revision", "last_seen_at")
    list_filter = ("status", "region")
    readonly_fields = ("desired_revision", "applied_revision", "last_seen_at", "last_report",
                       "egress_digest", "cdn_feed")


@admin.register(PublicIP)
class PublicIPAdmin(admin.ModelAdmin):
    list_display = ("address", "edge", "pool", "state", "vm", "target_ip", "vm_region", "epoch",
                    "smtp_allowed", "attached_at", "released_at")
    list_filter = ("pool", "state", "edge")
    search_fields = ("address", "vm__vm_id")
    raw_id_fields = ("vm",)
    # Set by `POST /v1/network/edges/<name>/addresses` only: a pool changed
    # in place would hand a CDN address to a tenant, or the reverse, and a
    # cap changed here would not bump the edge's revision.
    readonly_fields = ("pool", "cap_mbps")


@admin.register(EgressRegion)
class EgressRegionAdmin(admin.ModelAdmin):
    list_display = ("region", "mode", "routing_enabled", "enforce", "updated_at")
    list_filter = ("mode",)


@admin.register(VmEgressLease)
class VmEgressLeaseAdmin(admin.ModelAdmin):
    list_display = ("vm", "edge", "region", "target_ip", "epoch", "class_id", "active",
                    "updated_at")
    list_filter = ("active", "region", "edge")
    # Written by the reconcile only: a hand-edited class id or epoch would
    # break the edge's attribution.
    readonly_fields = ("vm", "edge", "region", "target_ip", "epoch", "class_id", "active",
                       "created_at", "updated_at")


@admin.register(MinerNetPolicy)
class MinerNetPolicyAdmin(admin.ModelAdmin):
    list_display = ("miner", "region", "mode", "revision", "acked_revision", "acked_at",
                    "sent_at", "last_error")
    list_filter = ("mode", "region")
    # Written by the reconcile only: a hand-edited revision could fall
    # below the miner's floor.
    readonly_fields = ("miner", "revision", "content_key", "body_sha", "body", "region", "mode",
                       "sent_at", "acked_revision", "acked_sha", "acked_at", "last_error",
                       "edge_unsupported_at", "apply_failures")
