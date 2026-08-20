"""Django admin registrations for `apps.packer` (#152).

`PackerBuild` rows are an op record of one image-build request.
Lifecycle columns (state, started/finished timestamps, artifact
digest, provenance URL, version) are owned by the trigger view +
`/finalize` callback; the admin exists for inspection.
"""

from __future__ import annotations

from django.contrib import admin

from .models import PackerBuild


@admin.register(PackerBuild)
class PackerBuildAdmin(admin.ModelAdmin):
    list_display = (
        "build_id",
        "image_kind",
        "state",
        "requested_by",
        "requested_at",
        "started_at",
        "finished_at",
    )
    list_filter = ("image_kind", "state")
    search_fields = ("build_id", "artifact_sha256", "failure_reason")
    raw_id_fields = ("requested_by",)
    readonly_fields = (
        "id",
        # All lifecycle state is owned by the trigger + finalize views;
        # admin edits would race the CAS and corrupt the state machine.
        "state",
        "requested_at",
        "started_at",
        "finished_at",
        "artifact_sha256",
        "provenance_signed_url",
        "failure_reason",
        "version",
    )
    ordering = ("-requested_at",)
