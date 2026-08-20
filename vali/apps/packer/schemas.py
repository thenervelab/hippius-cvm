"""Doc-only serializers for the Packer build/presign OpenAPI schema.

Referenced from `@extend_schema` in `views.py` only — NEVER wired into
request handling (every view keeps its own manual `request.data`
parsing + hand-built `Response`). Fields mirror the create/finalize/
presign request bodies (`_parse_finalize` + the inline validation) and
the `_serialize_build` / presign response helpers.
"""

from __future__ import annotations

from rest_framework import serializers

from .models import PackerBuildState, PackerImageKind


class PackerBuildCreateRequestSerializer(serializers.Serializer):
    """`POST /v1/packer/build` body — request a new build."""

    image_kind = serializers.ChoiceField(
        choices=PackerImageKind.values,
        help_text="Image to build (e.g. `kbs`, `edge`, `guest`, `audit-vm`).",
    )


class PackerBuildSerializer(serializers.Serializer):
    """A `PackerBuild` row (`_serialize_build`) — the create 202 body and
    the detail / finalize 200 body.
    """

    build_id = serializers.CharField(help_text="32-hex-char opaque build id.")
    image_kind = serializers.CharField()
    state = serializers.ChoiceField(
        choices=PackerBuildState.values,
        help_text="queued | running | succeeded | failed.",
    )
    requested_by = serializers.CharField(help_text="ServiceClient name that requested it.")
    requested_at = serializers.DateTimeField(allow_null=True)
    started_at = serializers.DateTimeField(allow_null=True)
    finished_at = serializers.DateTimeField(allow_null=True)
    artifact_sha256 = serializers.CharField(
        allow_null=True, help_text="Artifact digest (set on Succeeded)."
    )
    provenance_signed_url = serializers.CharField(
        allow_null=True, help_text="Provenance URL (set on Succeeded)."
    )
    failure_reason = serializers.CharField(
        allow_null=True, help_text="Failure reason (set on Failed)."
    )
    version = serializers.IntegerField(help_text="Optimistic-concurrency version.")


class PackerBuildFinalizeRequestSerializer(serializers.Serializer):
    """`POST /v1/packer/build/<build_id>/finalize` body — worker CAS.

    Mirrors `_parse_finalize`. `to_state=running` is a worker claim;
    `succeeded` requires `artifact_sha256` + `provenance_signed_url`;
    `failed` carries `failure_reason`.
    """

    to_state = serializers.ChoiceField(
        choices=[
            PackerBuildState.RUNNING.value,
            PackerBuildState.SUCCEEDED.value,
            PackerBuildState.FAILED.value,
        ],
        help_text="Target state — a legal transition from the current state.",
    )
    if_version = serializers.IntegerField(
        min_value=1, help_text="Expected current version (optimistic-concurrency CAS)."
    )
    artifact_sha256 = serializers.CharField(
        required=False, help_text="Required when `to_state=succeeded`."
    )
    provenance_signed_url = serializers.CharField(
        required=False,
        max_length=2048,
        help_text="Required when `to_state=succeeded` (≤2048 chars).",
    )
    failure_reason = serializers.CharField(
        required=False,
        max_length=256,
        help_text="Set when `to_state=failed` (≤256 chars).",
    )


class PackerPresignRequestSerializer(serializers.Serializer):
    """`POST /v1/packer/build/<build_id>/presign-image-get` body
    (optional). Omit for the configured default TTL.
    """

    ttl_seconds = serializers.IntegerField(
        required=False,
        help_text=(
            "Presigned-URL TTL override (default VALI_PACKER_PRESIGN_TTL_SECS, "
            "bounded by apps.storage.s3.MAX_TTL_SECONDS)."
        ),
    )


class PackerPresignResponseSerializer(serializers.Serializer):
    """Presign 200 body — a presigned GET URL for a Succeeded build's
    artifact on the images bucket.
    """

    build_id = serializers.CharField()
    url = serializers.CharField(help_text="Presigned GET URL.")
    method = serializers.CharField(help_text="HTTP method (GET).")
    expires_at_unix = serializers.IntegerField(help_text="URL expiry (unix seconds).")
    bucket = serializers.CharField()
    key = serializers.CharField(help_text="`<image_kind>/<artifact_sha256>.img`.")
    artifact_sha256 = serializers.CharField(allow_null=True)
