"""Doc-only serializers for the tenant-bake OpenAPI schema (§ per-tenant
qcow2 bake — issue #334). Referenced from `@extend_schema` in `views.py`
only — never wired into request handling. Fields mirror `_parse_create`
(create body), `_parse_finalize` (finalize body) and `_serialize_bake`
(the row response) exactly.
"""

from __future__ import annotations

from rest_framework import serializers


class TenantBakeCreateSerializer(serializers.Serializer):
    """`POST /v1/tenant-bakes` body — request a new per-tenant bake.

    Mirrors `_parse_create`: every field is required. Unknown fields are
    rejected by the handler.
    """

    vm_id = serializers.RegexField(
        r"^[a-z0-9-]{1,64}$",
        help_text="Target VM id — `[a-z0-9-]{1,64}` (same charset as the OrderTicket).",
    )
    base_image_url = serializers.URLField(
        max_length=2048,
        help_text=(
            "URL of the vanilla cloud image to bake. Fetched + sha-verified "
            "server-side by the baker; must be http(s) resolving to a public "
            "address (SSRF-guarded), no embedded credentials. Must point at "
            "an IMMUTABLE upstream path: a moving path segment (`latest/`, "
            "`current/`, `daily/`, a `-latest.` filename token, …) is "
            "refused, because it contradicts the `base_image_sha256` pin "
            "and breaks on every upstream point release. Use the dated "
            "directory upstream publishes alongside it."
        ),
    )
    base_image_sha256 = serializers.RegexField(
        r"^[0-9a-f]{64}$",
        help_text="Expected sha256 of `base_image_url` — 64 lowercase hex chars.",
    )
    size_gb = serializers.IntegerField(
        min_value=1, help_text="Target raw image size in GiB (integer > 0)."
    )
    kek_vault_path = serializers.CharField(
        max_length=512,
        help_text="KV-v2 path the baker reads the disk KEK from (vali stages it first).",
    )
    s3_output_bucket = serializers.CharField(
        max_length=256, help_text="S3 bucket the three artefacts land in on success."
    )
    s3_output_prefix = serializers.CharField(
        max_length=512, help_text="S3 key prefix for the baked artefacts."
    )
    disk_mode = serializers.ChoiceField(
        choices=["legacy_luks", "golden_verity_overlay"],
        required=False,
        help_text=(
            "Boot-disk packaging mode (golden-bake PR6). Absent ⇒ "
            "`legacy_luks` (per-VM LUKS qcow2). `golden_verity_overlay` "
            "bakes a shared, non-confidential dm-verity base (no qcow2, "
            "no per-VM KEK)."
        ),
    )


class TenantBakeFinalizeSerializer(serializers.Serializer):
    """`POST /v1/tenant-bakes/<bake_id>/finalize` body — worker-only CAS.

    Mirrors `_parse_finalize` / `FinalizeRequest`. `to_state` + `if_version`
    are always required; the remaining fields are conditional on the target
    state (Succeeded needs the three artefact SHAs; Failed needs
    `failure_reason`).
    """

    to_state = serializers.ChoiceField(
        choices=["running", "succeeded", "failed"],
        help_text=(
            "Target state. Legal transitions: queued→running, "
            "running→succeeded, running→failed."
        ),
    )
    if_version = serializers.IntegerField(
        min_value=1,
        help_text="Optimistic-concurrency guard — must equal the row's current `version`.",
    )
    qcow2_sha256 = serializers.RegexField(
        r"^[0-9a-f]{64}$",
        required=False,
        help_text=(
            "Baked qcow2 digest — 64 lowercase hex. Required for a LEGACY "
            "`succeeded`; forbidden for a golden one."
        ),
    )
    rootfs_img_sha256 = serializers.RegexField(
        r"^[0-9a-f]{64}$",
        required=False,
        help_text=(
            "golden-bake PR6 — the shared `rootfs.img` squashfs digest "
            "(64 hex). Required for a GOLDEN `succeeded`."
        ),
    )
    rootfs_verity_sha256 = serializers.RegexField(
        r"^[0-9a-f]{64}$",
        required=False,
        help_text=(
            "golden-bake PR6 — the shared `rootfs.verity` hash-tree digest "
            "(64 hex). Required for a GOLDEN `succeeded`."
        ),
    )
    verity_root_hash = serializers.RegexField(
        r"^[0-9a-f]{64}$",
        required=False,
        help_text=(
            "golden-bake PR6 — the UNKEYED dm-verity root hash (64 hex) "
            "vali folds into the measured `dm-verity.root=` cmdline. "
            "Required for a GOLDEN `succeeded`."
        ),
    )
    kernel_sha256 = serializers.RegexField(
        r"^[0-9a-f]{64}$",
        required=False,
        help_text="Guest kernel digest — 64 lowercase hex. Required for `succeeded`.",
    )
    initrd_sha256 = serializers.RegexField(
        r"^[0-9a-f]{64}$",
        required=False,
        help_text="initrd digest — 64 lowercase hex. Required for `succeeded`.",
    )
    luks_header_sha256 = serializers.RegexField(
        r"^[0-9a-f]{64}$",
        required=False,
        help_text=(
            "#296 LUKS2-header MAC (64 hex) vali pins into the measured "
            "cmdline at launch. Optional — older bakers omit it."
        ),
    )
    measurement_hex = serializers.RegexField(
        r"^[0-9a-f]{96}$",
        required=False,
        help_text=(
            "48-byte SNP launch digest — 96 lowercase hex. OPTIONAL even on "
            "`succeeded` (folds OVMF + vcpus the bake cannot know)."
        ),
    )
    failure_reason = serializers.CharField(
        max_length=256,
        required=False,
        help_text="Short operator-facing string. Required for `failed`.",
    )


class TenantBakeSerializer(serializers.Serializer):
    """A `TenantBake` row on the wire (`_serialize_bake`).

    Empty artefact/measurement/failure sentinels are surfaced as `null`.
    No secret appears — only the Vault KEK path reference.
    """

    bake_id = serializers.CharField(help_text="Public stable bake identifier (32 hex).")
    vm_id = serializers.CharField()
    base_image_url = serializers.CharField()
    base_image_sha256 = serializers.CharField()
    size_gb = serializers.IntegerField()
    kek_vault_path = serializers.CharField()
    s3_output_bucket = serializers.CharField()
    s3_output_prefix = serializers.CharField()
    disk_mode = serializers.CharField(
        help_text="legacy_luks | golden_verity_overlay."
    )
    state = serializers.CharField(help_text="queued | running | succeeded | failed.")
    requested_by = serializers.CharField(help_text="Name of the requesting ServiceClient.")
    requested_at = serializers.DateTimeField(allow_null=True)
    started_at = serializers.DateTimeField(allow_null=True)
    finished_at = serializers.DateTimeField(allow_null=True)
    qcow2_sha256 = serializers.CharField(allow_null=True)
    rootfs_img_sha256 = serializers.CharField(allow_null=True)
    rootfs_verity_sha256 = serializers.CharField(allow_null=True)
    verity_root_hash = serializers.CharField(allow_null=True)
    kernel_sha256 = serializers.CharField(allow_null=True)
    initrd_sha256 = serializers.CharField(allow_null=True)
    measurement_hex = serializers.CharField(allow_null=True)
    failure_reason = serializers.CharField(allow_null=True)
    version = serializers.IntegerField(help_text="Optimistic-concurrency counter.")


class TenantBakeInFlightConflictSerializer(serializers.Serializer):
    """409 body for `POST /v1/tenant-bakes` when a bake for the same `vm_id`
    is already Queued/Running (`_in_flight_conflict_response`)."""

    error = serializers.CharField(help_text="Human-readable conflict message.")
    category = serializers.CharField(help_text="Always `already-in-flight`.")
    active = TenantBakeSerializer(help_text="The surviving in-flight bake row.")


class TenantBakeVersionConflictSerializer(serializers.Serializer):
    """409 body for `POST /finalize` when `if_version` is stale (the CAS
    matched zero rows)."""

    error = serializers.CharField(help_text="Human-readable conflict message.")
    category = serializers.CharField(help_text="Always `version-conflict`.")
    current = TenantBakeSerializer(
        allow_null=True, help_text="The current row, or null if it vanished."
    )
