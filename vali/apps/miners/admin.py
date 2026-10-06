"""Django admin registrations for `apps.miners` (#152).

The miner registry is the trust anchor for the §9 telemetry broker —
a `MinerIdentity.pubkey_hex` is the verifying key behind every signed
envelope a miner emits. Operator mutations should go through
`POST /v1/admin/miner/register` (which also provisions the linked
`TelemetrySource`); the admin exists for inspection.

`last_heartbeat_sequence` is the §K replay-gate cursor — bumped under
a row lock by the heartbeat ingest path. Forced read-only here so an
operator can't hand-rewind the gate and re-accept replayed envelopes.

`snp_generation` IS editable here: the correction path for a generation
registered wrong (the register endpoint 409s a changed value). The
model's `clean()` refuses a generation inconsistent with the CHIP_ID
length. Changing it re-measures every future guest on that host.
"""

from __future__ import annotations

from django.contrib import admin

from .models import MinerIdentity, MinerLocation


@admin.register(MinerIdentity)
class MinerIdentityAdmin(admin.ModelAdmin):
    list_display = (
        "miner_id",
        "pubkey_hex_short",
        "platform_id",
        "snp_generation",
        "status",
        "last_seen_at",
        "last_heartbeat_sequence",
        "registered_at",
    )
    list_filter = ("status", "snp_generation")
    search_fields = (
        "miner_id",
        "pubkey_hex",
        "platform_id",
        "netbird_peer_id",
        "chain_node_id",
    )
    # Identity/trust columns are read-only from the admin: the
    # canonical writers are `POST /v1/admin/miner/register` (which
    # also provisions the linked `TelemetrySource`) and `POST
    # /v1/admin/miner/<id>/quarantine` (which mirrors `status` onto
    # `TelemetrySource.is_active` in the same transaction).
    # Editing `pubkey_hex` / `platform_id` from the admin would
    # diverge this registry from the §9 broker trust anchor;
    # editing `status` would skip the linked-source toggle and leave
    # a quarantined miner still able to feed verified telemetry.
    readonly_fields = (
        "miner_id",
        "pubkey_hex",
        "platform_id",
        # The scheduler-bridge node_id — canonical writer is the
        # register endpoint; hand-editing it here would silently
        # re-point the launch pipeline at the wrong miner.
        "chain_node_id",
        "status",
        "registered_at",
        "last_seen_at",
        # §K replay-gate cursor — must only be advanced by the ingest
        # gate's row-locked CAS, never edited by hand.
        "last_heartbeat_sequence",
    )

    def has_add_permission(self, request) -> bool:  # type: ignore[override]
        # Registration is done via `POST /v1/admin/miner/register`,
        # which also provisions the linked `TelemetrySource` in the
        # same transaction. Admin-side inserts would skip that link
        # and the broker would refuse the miner's signed telemetry.
        return False

    def has_delete_permission(self, request, obj=None) -> bool:  # type: ignore[override]
        # Deletion would orphan the linked `TelemetrySource` and any
        # `Placement` rows that reference this miner. The sanctioned
        # path is the quarantine endpoint (status flip, telemetry
        # source deactivation, no row removal).
        return False

    ordering = ("miner_id",)

    @admin.display(description="pubkey (short)")
    def pubkey_hex_short(self, obj: MinerIdentity) -> str:
        """Render the first 12 hex chars of the miner's Ed25519
        pubkey for the changelist. The full key is visible on the
        change form; truncating the column keeps the changelist
        scannable on a typical screen.
        """
        return f"{obj.pubkey_hex[:12]}…"


@admin.register(MinerLocation)
class MinerLocationAdmin(admin.ModelAdmin):
    """Read-only: the ONLY writer is `vali_geo_probe`. A hand-edited row
    would be a declared location, which is exactly what this table exists
    to never hold."""

    list_display = (
        "miner",
        "country_code",
        "verdict",
        "connection_ip",
        "asn",
        "rtt_ms",
        "observed_at",
    )
    list_filter = ("verdict", "country_code")
    search_fields = ("miner__miner_id", "connection_ip", "as_holder")
    readonly_fields = tuple(f.name for f in MinerLocation._meta.fields)
    ordering = ("miner",)

    def has_add_permission(self, request) -> bool:  # type: ignore[override]
        return False

    def has_change_permission(self, request, obj=None) -> bool:  # type: ignore[override]
        return False

    def has_delete_permission(self, request, obj=None) -> bool:  # type: ignore[override]
        return False
