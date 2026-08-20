"""Doc-only serializers for the orchestration OpenAPI schema (§24/§25 +
launch). Referenced from `@extend_schema` in `views.py` only — never wired
into request handling. Fields mirror `launch_jobs.start_launch` /
`_build_spec_json` (request) and the `_serialize_*` helpers (response).
"""

from __future__ import annotations

from rest_framework import serializers

from .models import LaunchPhase


class LaunchIntentSerializer(serializers.Serializer):
    """`POST /v1/vm/launch` body — the launch intent + cloud-init userdata.

    Mirrors `launch_jobs._REQUIRED` / `_OPTIONAL` plus `userdata`, `bake_id`
    and `max_price_per_unit`. A `bake_id` naming a Succeeded `TenantBake`
    fills the artifact/KEK/S3 fields the bake determined, so those become
    optional when a bake is supplied.
    """

    # ── secrets / cloud-init ──
    userdata = serializers.CharField(
        help_text=(
            "cloud-init plaintext (staged to Vault, never persisted on the "
            "job row). When NetBird is enabled the userdata MUST carry the "
            "literal `{{NETBIRD_SETUP_KEY}}` placeholder."
        )
    )

    # ── required intent (unless resolved from a bake_id) ──
    tenant_id = serializers.CharField(help_text="Owning tenant id.")
    user_id = serializers.CharField(help_text="Requesting user id.")
    vm_id = serializers.RegexField(
        r"^[a-z0-9-]{1,64}$",
        help_text="VM id — `[a-z0-9-]{1,64}` (interpolated into Vault paths).",
    )
    lease_id = serializers.CharField(help_text="Marketplace lease id.")
    flavor = serializers.CharField(
        help_text="Resource flavor name (must be a known flavor, e.g. `small`)."
    )
    cmdline = serializers.CharField(help_text="Guest kernel cmdline.")
    s3_bucket = serializers.CharField(
        help_text="S3 bucket holding the baked artifacts (from the bake when `bake_id` set)."
    )
    s3_key_prefix = serializers.CharField(help_text="S3 key prefix for the artifacts.")
    luks_disk_sha256_hex = serializers.CharField(help_text="SHA-256 of the LUKS disk image (hex).")
    kernel_sha256_hex = serializers.CharField(help_text="SHA-256 of the guest kernel (hex).")
    initrd_sha256_hex = serializers.CharField(help_text="SHA-256 of the initrd (hex).")
    luks_header_sha256_hex = serializers.CharField(help_text="SHA-256 of the LUKS header (hex).")
    kek_vault_path = serializers.CharField(
        help_text=(
            "Vault KV path of the pre-staged disk KEK — MUST be the canonical "
            "`{prefix}/{vm_id}/luks-kek` the KBS releases from."
        )
    )

    # ── optional intent ──
    image = serializers.CharField(
        required=False,
        help_text=(
            "Launch-by-image (the fast default path): an operator-blessed "
            "golden image NAME (e.g. `ubuntu`) — vali resolves it to the "
            "CURRENT blessed golden `bake_id` for that image, so every fresh "
            "launch reuses the shared golden base (cache-HIT on the miner). "
            "Mutually exclusive with `bake_id`; an unknown image is rejected. "
            "Discover names via `GET /v1/images`."
        ),
    )
    bake_id = serializers.CharField(
        required=False,
        help_text=(
            "Optional Succeeded `TenantBake` id — resolves the artifact SHAs, "
            "LUKS-header MAC, KEK Vault path and S3 location so they can be "
            "omitted above. Caller-supplied values win. Mutually exclusive "
            "with `image`."
        ),
    )
    platform_id = serializers.CharField(
        required=False, help_text="Target miner CHIP_ID (optional)."
    )
    ticket_id = serializers.CharField(required=False)
    order_id = serializers.CharField(required=False)
    rootfs_sha256_hex = serializers.CharField(required=False)
    measurement_hex = serializers.CharField(required=False)
    auto_pin_allowlist = serializers.BooleanField(
        required=False,
        default=False,
        help_text="Pin the miner-computed launch digest into the §22 allowlist.",
    )
    enable_netbird = serializers.BooleanField(
        required=False,
        default=True,
        help_text="NetBird overlay on by default; POST false to opt out.",
    )
    netbird_group = serializers.CharField(required=False, default="vms")
    netbird_key_ttl_seconds = serializers.IntegerField(required=False, default=3600)
    netbird_hostname_template = serializers.CharField(
        required=False, default="hippius-tenant-{vm_id}"
    )
    ovmf_path = serializers.CharField(required=False, default="/var/lib/hippius-miner/ovmf.fd")
    rootfs_data_path = serializers.CharField(
        required=False, default="/var/lib/hippius-miner/rootfs.img"
    )
    rootfs_hash_path = serializers.CharField(
        required=False, default="/var/lib/hippius-miner/rootfs.verity"
    )
    kid = serializers.CharField(required=False, default="l1-order-ticket-v1")
    expiry_seconds = serializers.IntegerField(required=False, default=86400)
    max_price_per_unit = serializers.IntegerField(
        required=False,
        allow_null=True,
        help_text=(
            "Tenant price ceiling (USD/unit ×1e6), positive int or null. Null "
            "⇒ the VM is never migrated on a miner price change."
        ),
    )


class LaunchJobSerializer(serializers.Serializer):
    """A `LaunchJob` row (`_serialize_launch`). No secret appears — only
    Vault refs, state and the result summary."""

    job_id = serializers.CharField()
    vm_id = serializers.CharField()
    tenant_id = serializers.CharField()
    flavor = serializers.CharField()
    state = serializers.CharField(help_text="queued | running | succeeded | failed.")
    phase = serializers.ChoiceField(
        choices=[p.value for p in LaunchPhase],
        allow_null=True,
        allow_blank=True,
        help_text=(
            "Fine-grained progress WITHIN `state` for a live launch UI: "
            "queued → staging → placing → dispatching → launched | failed. "
            "`null` on an older server that does not populate it (fall back "
            "to `state` + `miner_id`)."
        ),
    )
    miner_id = serializers.CharField(allow_null=True)
    placement_id = serializers.CharField(allow_null=True)
    reason = serializers.CharField(allow_null=True)
    result = serializers.JSONField(allow_null=True, help_text="Terminal launch result summary.")
    decided_by = serializers.CharField(help_text="Principal that requested the launch.")
    started_at = serializers.DateTimeField()
    finished_at = serializers.DateTimeField(allow_null=True)
    version = serializers.IntegerField(help_text="Optimistic-concurrency version.")


class MigrateStartRequestSerializer(serializers.Serializer):
    """`POST /v1/vm/<vm_id>/migrate` body."""

    dest_node_id = serializers.CharField(
        max_length=64, help_text="Destination node id (non-empty, ≤64 chars)."
    )


class MigrationJobSerializer(serializers.Serializer):
    """A `MigrationJob` row (`_serialize_migration`)."""

    job_id = serializers.CharField()
    vm_id = serializers.CharField()
    source_node_id = serializers.CharField()
    dest_node_id = serializers.CharField()
    source_gen = serializers.IntegerField()
    new_gen = serializers.IntegerField()
    state = serializers.CharField()
    source_ack_verified = serializers.BooleanField()
    source_reclaim_state = serializers.CharField()
    source_reclaim_at = serializers.DateTimeField(allow_null=True)
    source_reclaim_reason = serializers.CharField(allow_null=True)
    failed_from_state = serializers.CharField(allow_null=True)
    strand_recovery_state = serializers.CharField()
    strand_recovery_at = serializers.DateTimeField(allow_null=True)
    strand_recovery_reason = serializers.CharField(allow_null=True)
    snapshot_bucket = serializers.CharField(allow_null=True)
    snapshot_key = serializers.CharField(allow_null=True)
    quarantine_node_id = serializers.CharField(allow_null=True)
    reason = serializers.CharField(allow_null=True)
    decided_by = serializers.CharField()
    phase_started_at = serializers.DateTimeField()
    started_at = serializers.DateTimeField()
    finished_at = serializers.DateTimeField(allow_null=True)
    version = serializers.IntegerField()


class DecommissionJobSerializer(serializers.Serializer):
    """A `DecommissionJob` row (`_serialize_decommission`)."""

    job_id = serializers.CharField()
    vm_id = serializers.CharField()
    state = serializers.CharField()
    eol_ack_verified = serializers.BooleanField()
    forced = serializers.BooleanField()
    quarantine_node_id = serializers.CharField(allow_null=True)
    reason = serializers.CharField(allow_null=True)
    decided_by = serializers.CharField()
    phase_started_at = serializers.DateTimeField()
    started_at = serializers.DateTimeField()
    finished_at = serializers.DateTimeField(allow_null=True)
    version = serializers.IntegerField()


class MeasurementLedgerRowSerializer(serializers.Serializer):
    """One pinned-measurement ledger row."""

    vm_id = serializers.CharField()
    launch_digest = serializers.CharField(help_text="Pinned SNP launch digest (hex).")
    platform_id = serializers.CharField(help_text="Miner CHIP_ID.")
    node_id = serializers.CharField()
    allowlist_epoch = serializers.IntegerField()
    allowlist_sha256 = serializers.CharField()
    measurement_class = serializers.CharField(
        help_text=(
            "§22 trust class the entry was pinned under "
            "(`tenant` / `host_attestor`; blank on pre-column rows)."
        ),
    )
    pinned_at = serializers.DateTimeField()


class MeasurementAuditSerializer(serializers.Serializer):
    """`GET /v1/admin/audit/measurements` paginated response."""

    measurements = MeasurementLedgerRowSerializer(many=True)
    limit = serializers.IntegerField()
    offset = serializers.IntegerField()
    total = serializers.IntegerField()
