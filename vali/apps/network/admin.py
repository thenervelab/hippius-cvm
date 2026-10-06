from __future__ import annotations

from django.contrib import admin

from .models import IngressEdge, PublicIP


@admin.register(IngressEdge)
class IngressEdgeAdmin(admin.ModelAdmin):
    list_display = ("name", "region", "status", "netbird_ip", "desired_revision",
                    "applied_revision", "last_seen_at")
    list_filter = ("status", "region")
    readonly_fields = ("desired_revision", "applied_revision", "last_seen_at", "last_report")


@admin.register(PublicIP)
class PublicIPAdmin(admin.ModelAdmin):
    list_display = ("address", "edge", "state", "vm", "target_ip", "attached_at", "released_at")
    list_filter = ("state", "edge")
    search_fields = ("address", "vm__vm_id")
    raw_id_fields = ("vm",)
