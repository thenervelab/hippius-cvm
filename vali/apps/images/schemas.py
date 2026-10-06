"""Doc-only serializers for the golden-image catalog OpenAPI schema.

Referenced from `@extend_schema` in `views.py` only — never wired into
request handling (the view renders plain dicts). Fields mirror
`views._serialize_image`.
"""

from __future__ import annotations

from rest_framework import serializers


class GoldenImageSerializer(serializers.Serializer):
    """One catalog row — the current blessed golden bake for an image."""

    image_name = serializers.CharField(help_text="Launchable image name, e.g. `ubuntu`.")
    distro = serializers.CharField(help_text="Human distro label, e.g. `centos-stream-10`.")
    bake_id = serializers.CharField(
        help_text="The currently-blessed golden `TenantBake` id this image resolves to."
    )
    is_golden = serializers.BooleanField(
        help_text=(
            "Whether the blessed bake is a Succeeded `golden_verity_overlay` "
            "bake (the operator only blesses golden bakes; false only if the "
            "referenced bake was removed/altered out-of-band)."
        )
    )
    blessed_at = serializers.DateTimeField(help_text="When this bake was blessed for the image.")
    blessed_by = serializers.CharField(help_text="Operator identity recorded at bless time.")
    guest_release = serializers.IntegerField(
        allow_null=True,
        help_text="The guest components release a new VM of this image boots (null: the "
        "bare bake).",
    )


class GoldenImageListSerializer(serializers.Serializer):
    """`GET /v1/images` response — the full catalog."""

    images = GoldenImageSerializer(many=True)
    total = serializers.IntegerField()
