"""Doc-only serializers for the miners OpenAPI schema (miner-fleet
registry + graceful exit). Referenced from `@extend_schema` in `views.py`
only — never wired into request handling. Fields mirror the view's
`_require_*` / `_optional_*` wire checks (request) and the `_serialize`
helper (response).
"""

from __future__ import annotations

from rest_framework import serializers

from .models import SnpGeneration


class MinerRegisterRequestSerializer(serializers.Serializer):
    """`POST /v1/admin/miner/register` body — one miner identity.

    Mirrors the view's `_require_*` / `_optional_*` field checks. The
    registry is operator-curated (§13/§23) — a miner never self-asserts.
    """

    miner_id = serializers.CharField(
        max_length=64, help_text="Human-readable primary key, e.g. `miner-a`."
    )
    pubkey_hex = serializers.CharField(
        max_length=64,
        help_text=(
            "Miner Ed25519 public key — 64 hex chars (32-byte key), "
            "lowercased and DB-unique."
        ),
    )
    platform_id = serializers.CharField(
        max_length=128,
        help_text="AMD platform identity (CHIP_ID / VCEK id). Unique per machine.",
    )
    netbird_peer_id = serializers.CharField(
        required=False,
        max_length=64,
        help_text="NetBird mesh peer id (optional, informational).",
    )
    netbird_ip = serializers.IPAddressField(
        required=False, help_text="NetBird mesh IP (optional, informational)."
    )
    chain_node_id = serializers.CharField(
        required=False,
        max_length=64,
        help_text=(
            "On-chain compute node_id — 64 hex chars (32-byte key), unique "
            "when set. Backfillable bridge to the §23 scheduler; NULL until "
            "the operator supplies it."
        ),
    )
    snp_generation = serializers.ChoiceField(
        choices=SnpGeneration.values,
        required=False,
        allow_null=True,
        help_text=(
            "SEV-SNP CPU generation — selects the launch-digest vCPU model. "
            "Omit / null ⇒ inferred from the CHIP_ID length (8 bytes ⇒ "
            "turin, 64 ⇒ genoa). REQUIRED for Milan (its 64-byte CHIP_ID "
            "is indistinguishable from Genoa's). Must agree with the "
            "platform_id length (400 otherwise). Backfillable from null; "
            "a different stored value is a 409."
        ),
    )


class TelemetrySourceRefSerializer(serializers.Serializer):
    """The linked `TelemetrySource` ref echoed in a miner row."""

    source = serializers.CharField(help_text="Source discriminator — always `miner`.")
    source_id = serializers.CharField(help_text="The miner_id.")


class MinerIdentitySerializer(serializers.Serializer):
    """A `MinerIdentity` row as rendered by `_serialize`."""

    miner_id = serializers.CharField()
    pubkey_hex = serializers.CharField()
    platform_id = serializers.CharField()
    netbird_peer_id = serializers.CharField(allow_blank=True)
    netbird_ip = serializers.IPAddressField(allow_null=True)
    chain_node_id = serializers.CharField(allow_null=True)
    snp_generation = serializers.CharField(
        allow_null=True,
        help_text="`milan` | `genoa` | `turin`, or null (inferred from the CHIP_ID length).",
    )
    status = serializers.CharField(help_text="`active` | `quarantined`.")
    registered_at = serializers.DateTimeField()
    last_seen_at = serializers.DateTimeField(allow_null=True)
    telemetry_source = TelemetrySourceRefSerializer()


class MinerListSerializer(serializers.Serializer):
    """`GET /v1/admin/miner/list` offset-paginated response."""

    miners = MinerIdentitySerializer(many=True)
    count = serializers.IntegerField(help_text="Total rows (unpaginated).")
    limit = serializers.IntegerField()
    offset = serializers.IntegerField()


class MinerQuarantineResponseSerializer(serializers.Serializer):
    """`POST /v1/admin/miner/<miner_id>/quarantine` success body."""

    miner_id = serializers.CharField()
    status = serializers.CharField(help_text="Always `quarantined` on success.")


class MinerGracefulExitResponseSerializer(serializers.Serializer):
    """`POST /v1/miner/<miner_id>/graceful-exit` accepted body."""

    miner_id = serializers.CharField()
    status = serializers.CharField(help_text="Always `quarantined` on accept.")
    accepted = serializers.BooleanField(help_text="Always `true` on accept.")


class MinerApprovalRequestSerializer(serializers.Serializer):
    """`POST /v1/admin/miner/<miner_id>/approval` body — what the operator
    declares about the host. Each anchor column becomes min(this, the
    miner's fresh heartbeat figure)."""

    cpus = serializers.IntegerField(help_text="Declared host threads (1..1024).")
    memory_mb = serializers.IntegerField(help_text="Declared host RAM, MiB.")
    disk_gb = serializers.IntegerField(
        required=False, allow_null=True, help_text="Declared tenant data-disk size, GiB."
    )
    trust_class = serializers.ChoiceField(
        choices=["operator", "earned"],
        required=False,
        allow_null=True,
        help_text="Also set the trust class; omitted = left as is (`earned` for a new miner).",
    )
    approved_by = serializers.CharField(help_text="Who approves (recorded in the audit).")
    reason = serializers.CharField(help_text="Why (recorded in the audit).")


class MinerMeasuredSerializer(serializers.Serializer):
    cpus = serializers.IntegerField(allow_null=True)
    memory_mb = serializers.IntegerField(allow_null=True)
    disk_gb = serializers.IntegerField(allow_null=True)


class MinerApprovalStatusSerializer(serializers.Serializer):
    """`GET /v1/admin/miner/<miner_id>/approval` body."""

    miner_id = serializers.CharField()
    node_id = serializers.CharField()
    approved = serializers.BooleanField()
    approved_at = serializers.DateTimeField(allow_null=True)
    approved_by = serializers.CharField()
    approval_required = serializers.BooleanField()
    held_back = serializers.BooleanField(
        help_text="True while the miner takes no new placement for want of an approval."
    )
    total_cpus = serializers.IntegerField(allow_null=True)
    total_memory_mb = serializers.IntegerField(allow_null=True)
    total_disk_gb = serializers.IntegerField(allow_null=True)
    trust_class = serializers.CharField()
    measured = MinerMeasuredSerializer()


class MinerApprovalResponseSerializer(serializers.Serializer):
    """`POST /v1/admin/miner/<miner_id>/approval` success body."""

    miner_id = serializers.CharField()
    node_id = serializers.CharField()
    approved_at = serializers.DateTimeField()
    approved_by = serializers.CharField()
    total_cpus = serializers.IntegerField()
    total_memory_mb = serializers.IntegerField()
    total_disk_gb = serializers.IntegerField(allow_null=True)
    trust_class = serializers.CharField()
    measured = MinerMeasuredSerializer()
    binding = serializers.ListField(
        child=serializers.CharField(),
        help_text="Which side set each anchor term, e.g. `cpus:declared`, `memory:measured`.",
    )
    dry_run = serializers.BooleanField()
