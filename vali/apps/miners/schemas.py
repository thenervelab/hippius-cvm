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
