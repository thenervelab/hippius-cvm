from __future__ import annotations

from django.contrib import admin

from .models import BackupChain, BackupPolicy, BackupRun


@admin.register(BackupPolicy)
class BackupPolicyAdmin(admin.ModelAdmin):
    list_display = ("vm", "enabled", "interval_s", "retention_days", "observed_boot_counter")
    readonly_fields = [f.name for f in BackupPolicy._meta.fields]


@admin.register(BackupChain)
class BackupChainAdmin(admin.ModelAdmin):
    list_display = ("id", "vm", "state", "boot_counter", "incremental_count", "created_at")
    list_filter = ("state",)
    readonly_fields = [f.name for f in BackupChain._meta.fields]


@admin.register(BackupRun)
class BackupRunAdmin(admin.ModelAdmin):
    list_display = ("id", "vm", "kind", "seq", "status", "reason", "disk_bytes", "created_at")
    list_filter = ("status", "kind")
    readonly_fields = [f.name for f in BackupRun._meta.fields]
