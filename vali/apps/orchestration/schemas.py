"""Doc-only serializers for the orchestration OpenAPI schema (§24/§25 +
launch). Referenced from `@extend_schema` in `views.py` only — never wired
into request handling. Fields mirror `launch_jobs.start_launch` /
`_build_spec_json` (request) and the `_serialize_*` helpers (response).
"""

from __future__ import annotations

from rest_framework import serializers

from .models import GuestUpgradeState, LaunchPhase, ResizeState


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
        help_text=(
            "Resource flavor name (e.g. `small`). Must be in the catalogue (or an "
            "unlisted `runner-*` flavor) AND at or below the largest offered size "
            "(`VALI_SCHEDULER_MAX_FLAVOR`, default `2xlarge`; a runner flavor goes "
            "by its compute class); a larger one is refused 400 `flavor-not-offered`."
        ),
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
    expiry_seconds = serializers.IntegerField(
        required=False,
        default=86400,
        min_value=60,
        max_value=86400,
        help_text=(
            "Lifetime of the minted OrderTicket — the authorization to "
            "release this VM's KEK + userdata to whoever attests. Bounded "
            "rather than free-form for that reason."
        ),
    )
    region = serializers.RegexField(
        r"^[A-Za-z]{2}$",
        required=False,
        default="",
        help_text=(
            "Optional region constraint: an ISO 3166-1 alpha-2 country code "
            "(`FR`, case-insensitive). The VM is placed ONLY on a miner the "
            "validator has DETECTED and verified in that country (nothing is "
            "declared by miners); if none is eligible the launch fails with "
            "`no-miner-in-region` rather than falling back elsewhere. "
            "Discover regions via `GET /v1/operator/regions`; pre-check with "
            "`GET /v1/scheduler/feasibility?region=`."
        ),
    )
    max_price_per_unit = serializers.IntegerField(
        required=False,
        allow_null=True,
        help_text=(
            "Tenant price ceiling (USD/unit ×1e6), positive int or null. Null "
            "⇒ the VM is never migrated on a miner price change."
        ),
    )
    key_mode = serializers.ChoiceField(
        choices=["hippius", "split", "customer"],
        required=False,
        default="hippius",
        help_text=(
            "Who holds the disk key. `hippius` (default): today's launch, "
            "unchanged. `split` (M1): the key needs Hippius' share AND the "
            "customer guardian's. `customer` (M2): the guardian's share only — "
            "Hippius holds no disk key. `split`/`customer` are refused unless "
            "customer keys are enabled on this validator, the launch is a "
            "golden image whose bake is marked capable, and both guardian "
            "fields are set. Fixed for the VM's life."
        ),
    )
    guardian_endpoint = serializers.CharField(
        required=False,
        help_text=(
            "`split`/`customer` only: the customer guardian's canonical "
            "`host:port` (IPv4, `[IPv6]` in RFC 5952 form, or a lowercase DNS "
            "name; no leading zeros). Measured into the guest cmdline."
        ),
    )
    guardian_pubkey = serializers.RegexField(
        r"^[0-9a-f]{64}$",
        required=False,
        help_text=(
            "`split`/`customer` only: the guardian's Ed25519 identity key, 64 "
            "lowercase hex. Measured into the guest cmdline."
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
    data_death = serializers.ChoiceField(
        choices=["crypto-erased", "customer-erase-required"],
        allow_null=True,
        help_text=(
            "Null until the erase step ran. `crypto-erased`: Hippius destroyed the key "
            "the disk needs. `customer-erase-required`: an M2 (`key_mode=customer`) VM — "
            "Hippius never held its disk key; its stored copies are deleted, and only "
            "the customer's `guardian erase <vm>` makes the data unrecoverable."
        ),
    )


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


class ResizeStartRequestSerializer(serializers.Serializer):
    """`POST /v1/vm/<vm_id>/resize` body."""

    flavor = serializers.CharField(
        max_length=32, help_text="Target flavor: its vCPU/RAM; the VM keeps its own data disk."
    )


class ResizeJobSerializer(serializers.Serializer):
    """A `ResizeJob` row (`_serialize_resize`)."""

    job_id = serializers.CharField()
    vm_id = serializers.CharField()
    from_flavor = serializers.CharField()
    to_flavor = serializers.CharField()
    state = serializers.ChoiceField(choices=ResizeState.values)
    node_id = serializers.CharField(help_text="Miner the in-place steps run on.")
    prior_power_state = serializers.CharField()
    migration_job_id = serializers.CharField(allow_null=True)
    reserved = serializers.BooleanField()
    relaunched_at = serializers.DateTimeField(allow_null=True)
    rolled_back = serializers.BooleanField()
    reason = serializers.CharField(allow_null=True)
    decided_by = serializers.CharField()
    phase_started_at = serializers.DateTimeField()
    started_at = serializers.DateTimeField()
    finished_at = serializers.DateTimeField(allow_null=True)
    version = serializers.IntegerField()


class ResizeFlavorOptionSerializer(serializers.Serializer):
    flavor = serializers.CharField()
    cpu_count = serializers.IntegerField()
    memory_mb = serializers.IntegerField()
    data_disk_size_gb = serializers.IntegerField()
    fits_current_host = serializers.BooleanField()
    needs_migration = serializers.BooleanField()
    available = serializers.BooleanField()
    reason = serializers.CharField(allow_null=True)


class ResizeFlavorsSerializer(serializers.Serializer):
    """`GET /v1/vm/<vm_id>/resize/flavors` body."""

    vm_id = serializers.CharField()
    current_flavor = serializers.CharField(allow_null=True)
    power_state = serializers.CharField()
    blocked = serializers.CharField(allow_null=True)
    options = ResizeFlavorOptionSerializer(many=True)


class GuestUpgradeStartRequestSerializer(serializers.Serializer):
    """`POST /v1/vm/<vm_id>/guest-upgrade` body."""

    release = serializers.IntegerField(
        min_value=1, help_text="The guest components release to move the VM onto."
    )
    not_before = serializers.DateTimeField(
        required=False,
        help_text="Not before this time (the tenant's maintenance window); now when omitted.",
    )


class GuestUpgradeRecoverySerializer(serializers.Serializer):
    """One audited operator recovery of a failed / blocked guest upgrade."""

    at = serializers.DateTimeField()
    by = serializers.CharField()
    action = serializers.CharField()
    reason = serializers.CharField()
    attempt = serializers.CharField()
    release = serializers.IntegerField()
    result = serializers.CharField(
        help_text="`started`, `refused:<reason>`, `error:<type>` or `dispatching`."
    )


class GuestUpgradeRecoverRequestSerializer(serializers.Serializer):
    """`POST /v1/vm/<vm_id>/guest-upgrade/<job_id>/recover` body."""

    action = serializers.ChoiceField(choices=["start-on-target"])
    reason = serializers.CharField(help_text="Why (audited on the job).")


class GuestUpgradeJobSerializer(serializers.Serializer):
    """A `GuestUpgradeJob` row (`guest_upgrade.serialize_job`)."""

    job_id = serializers.CharField()
    vm_id = serializers.CharField()
    release = serializers.IntegerField()
    build_prefix = serializers.CharField()
    state = serializers.ChoiceField(choices=GuestUpgradeState.values)
    not_before = serializers.DateTimeField()
    previous_prefix = serializers.CharField()
    previous_epoch = serializers.IntegerField()
    node_id = serializers.CharField(help_text="Miner the upgrade runs on.")
    reason = serializers.CharField(allow_null=True)
    outcome = serializers.CharField(
        allow_null=True,
        help_text="Why the target did not come up (`health-failed`, `health-latched`, "
        "`guest-restarted`, `resources-mismatch`, `no-sample`, `measurement-mismatch`, "
        "`dispatch-failed`, `stop-timeout`, `launch-timeout`, `c2-not-enforced`, "
        "`vm-moved`); null while it has not failed.",
    )
    suspect = serializers.CharField(
        allow_null=True,
        help_text="Whose side the outcome points at: `release`, `miner`, `vali`, `fleet` "
        "(a first lead, not a verdict).",
    )
    retry_of = serializers.CharField(
        allow_null=True, help_text="The upgrade_blocked job this one retries."
    )
    recoveries = GuestUpgradeRecoverySerializer(many=True)
    decided_by = serializers.CharField()
    phase_started_at = serializers.DateTimeField()
    started_at = serializers.DateTimeField()
    finished_at = serializers.DateTimeField(allow_null=True)
    version = serializers.IntegerField()


class GuestComponentsSerializer(serializers.Serializer):
    """`GET /v1/vm/<vm_id>/guest-components` body."""

    vm_id = serializers.CharField()
    release = serializers.IntegerField(
        allow_null=True, help_text="The release the VM boots; null on its bare base."
    )
    security_epoch = serializers.IntegerField()
    build_prefix = serializers.CharField(allow_null=True)
    required_epoch = serializers.IntegerField()
    attested_epoch = serializers.IntegerField()
    newest_release = serializers.IntegerField(allow_null=True)
    newest_security_epoch = serializers.IntegerField(
        allow_null=True,
        help_text="That release's security epoch: above `security_epoch`, the update fixes "
        "a security flaw (a shorter deadline).",
    )
    upgrade = GuestUpgradeJobSerializer(allow_null=True)
    needs_operator = GuestUpgradeJobSerializer(
        allow_null=True,
        help_text="The VM's latest job when it ended failed / upgrade_blocked: the VM "
        "needs an operator (a recovery start, a retry).",
    )


class GuestRolloutScopeSerializer(serializers.Serializer):
    vm_ids = serializers.ListField(child=serializers.CharField(), required=False)
    tenant_ids = serializers.ListField(child=serializers.CharField(), required=False)
    node_ids = serializers.ListField(child=serializers.CharField(), required=False)
    bake_ids = serializers.ListField(child=serializers.CharField(), required=False)


class GuestRolloutStartRequestSerializer(serializers.Serializer):
    """`POST /v1/guest-rollouts` body."""

    release = serializers.IntegerField(min_value=1)
    canary_vm_ids = serializers.ListField(child=serializers.CharField(), min_length=1)
    scope = GuestRolloutScopeSerializer(required=False)
    waves = serializers.ListField(
        child=serializers.IntegerField(min_value=1, max_value=100), required=False
    )
    max_concurrent = serializers.IntegerField(min_value=1, max_value=50, required=False)
    wave_pause_s = serializers.IntegerField(min_value=0, required=False)
    max_failure_ratio = serializers.FloatField(min_value=0, max_value=0.99, required=False)
    not_before = serializers.DateTimeField(required=False)


class GuestRolloutSerializer(serializers.Serializer):
    """A `GuestRollout` (`guest_rollout.serialize_rollout`)."""

    rollout_id = serializers.CharField()
    release = serializers.IntegerField()
    state = serializers.CharField()
    paused_reason = serializers.CharField(allow_null=True)
    current_wave = serializers.IntegerField()
    waves = serializers.ListField(child=serializers.IntegerField())
    canary_vm_ids = serializers.ListField(child=serializers.CharField())
    scope = GuestRolloutScopeSerializer()
    members = serializers.ListField(
        child=serializers.CharField(), help_text="The VMs fixed at creation (canaries apart)."
    )
    population = serializers.IntegerField()
    assigned = serializers.DictField(child=serializers.ListField(child=serializers.CharField()))
    jobs = serializers.DictField(
        child=serializers.DictField(child=serializers.IntegerField()),
        help_text="Per wave, the count of its jobs by state (`pending-stopped`: waiting "
        "for the VM's next start).",
    )
    skipped = serializers.DictField(child=serializers.CharField())
    max_concurrent = serializers.IntegerField()
    wave_pause_s = serializers.IntegerField()
    max_failure_ratio = serializers.FloatField()
    not_before = serializers.DateTimeField(allow_null=True)
    decided_by = serializers.CharField()
    created_at = serializers.DateTimeField()
    finished_at = serializers.DateTimeField(allow_null=True)
