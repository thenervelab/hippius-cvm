"""Django admin registrations for `apps.telemetry` (#152).

The §9 broker's data plane is owned by the ingest service + the pull
view. Admin edits to a `TelemetryEnvelope` would corrupt the
backpressure count, the dedupe partial-unique, or the GC sweep
boundary; everything is read-only.

`payload_cbor` and `signature` are the signed canonical-CBOR body +
its detached Ed25519 signature — §20 forbids logging these as side
effects. They are kept on the change form (operator forensics) but
forced read-only and excluded from `list_display`.

`TelemetrySource.verifying_key` is a 32-byte Ed25519 trust anchor,
provisioned out-of-band by the source-registration path (miners:
`POST /v1/admin/miner/register`). It is read-only here so an operator
can't silently rebind a source to a different signer.
"""

from __future__ import annotations

from django.contrib import admin

from .models import TelemetryEnvelope, TelemetrySource


@admin.register(TelemetrySource)
class TelemetrySourceAdmin(admin.ModelAdmin):
    list_display = (
        "source",
        "source_id",
        "is_active",
        "consecutive_failures",
        "quarantined_until",
        "updated_at",
    )
    list_filter = ("source", "is_active")
    search_fields = ("source_id",)
    readonly_fields = (
        "id",
        # `(source, source_id)` is the lookup key the broker matches
        # an envelope against; editing either column from the admin
        # rebinds an existing Ed25519 trust anchor to a different
        # source identity (silently retrusting `verifying_key` for a
        # source it was never registered for). Registration goes
        # through `vali_telemetry_register_source` — the admin is
        # inspection-only for the identity pair.
        "source",
        "source_id",
        # Trust anchor — set out-of-band by the registration path.
        # Editing it from the admin silently rebinds the source to a
        # different signer and breaks every dedupe + replay invariant.
        "verifying_key",
        # Poison-quarantine counter is owned by `_record_failure` in
        # the service layer; hand edits would mask a misbehaving source.
        "consecutive_failures",
        "failure_window_started_at",
        "quarantined_until",
        "created_at",
        "updated_at",
    )
    ordering = ("source", "source_id")


@admin.register(TelemetryEnvelope)
class TelemetryEnvelopeAdmin(admin.ModelAdmin):
    list_display = (
        "envelope_id",
        "source",
        "source_id",
        "kind",
        "schema_version",
        "processing_status",
        "received_at",
        "processed_at",
    )
    list_filter = ("source", "kind", "processing_status", "schema_version")
    search_fields = ("source_id", "dedupe_digest")
    date_hierarchy = "received_at"
    ordering = ("-envelope_id",)
    # Everything is read-only: the broker writes envelopes; the pull
    # endpoint flips the processing_status. Manual edits would race
    # the pull's atomic claim (`pull_token`) and double-deliver.
    readonly_fields = (
        "envelope_id",
        "source",
        "source_id",
        "kind",
        "schema_version",
        # Signed body + detached signature — §20 forbids casual
        # exposure; kept on the change form for forensics only.
        "payload_cbor",
        "signature",
        "dedupe_digest",
        "processing_status",
        "received_at",
        "processed_at",
        "pull_token",
    )

    def has_add_permission(self, request) -> bool:  # type: ignore[override]
        # Envelopes are created by the ingest view only — a manual
        # admin insert would skip signature verification + dedupe.
        return False

    def has_delete_permission(self, request, obj=None) -> bool:  # type: ignore[override]
        # Append-only by policy — §9 forensics + §20 retention. The
        # GC sweep (`vali_telemetry_gc` management command) is the
        # sanctioned reaper for terminal envelopes; admin delete
        # would bypass GC's age + status guards. Blocking here also
        # removes the `delete_selected` bulk action.
        return False
