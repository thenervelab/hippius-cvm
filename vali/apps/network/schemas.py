"""Doc-only serializers for the public-IP OpenAPI schema. Referenced from
`@extend_schema` in `views.py` only — never wired into request handling.
Fields mirror `service.public_ip_view` / `edge_view` / `desired_state` /
`availability`.
"""

from __future__ import annotations

from rest_framework import serializers

from .models import EdgeStatus, PublicIpState

_EDGE_STATUS = sorted(EdgeStatus.values)
_IP_STATE = sorted(PublicIpState.values)


class NetworkErrorSerializer(serializers.Serializer):
    error = serializers.CharField(help_text="Stable refusal code, e.g. `no-free-public-ip`.")
    detail = serializers.CharField()


class PublicIpSerializer(serializers.Serializer):
    vm_id = serializers.CharField()
    address = serializers.IPAddressField(protocol="IPv4")
    edge = serializers.CharField(help_text="Name of the ingress edge serving the address.")
    region = serializers.CharField(help_text="The edge's ISO 3166-1 alpha-2 region.")
    state = serializers.ChoiceField(choices=["attached"])
    attached_at = serializers.DateTimeField()


class VmPublicIpSummarySerializer(serializers.Serializer):
    """`public_ip` on the VM wire shape."""

    address = serializers.IPAddressField(protocol="IPv4")
    edge = serializers.CharField()
    region = serializers.CharField()


class AttachRequestSerializer(serializers.Serializer):
    region = serializers.CharField(
        required=False,
        allow_null=True,
        help_text="Preferred edge region (ISO alpha-2) when the VM's own is unknown.",
    )
    address = serializers.IPAddressField(
        protocol="IPv4",
        required=False,
        allow_null=True,
        help_text=(
            "One specific address: free, or released by one of this tenant's VMs and "
            "still in quarantine. Omit to let vali choose."
        ),
    )


class AvailabilityRegionSerializer(serializers.Serializer):
    region = serializers.CharField()
    free = serializers.IntegerField()
    total = serializers.IntegerField()
    edges = serializers.IntegerField()


class AvailabilitySerializer(serializers.Serializer):
    total_free = serializers.IntegerField()
    regions = AvailabilityRegionSerializer(many=True)


class EdgeAddressSerializer(serializers.Serializer):
    address = serializers.IPAddressField(protocol="IPv4")
    state = serializers.ChoiceField(choices=_IP_STATE)
    vm_id = serializers.CharField(allow_null=True, help_text="Holder, or previous holder.")
    attached_at = serializers.DateTimeField(allow_null=True)
    released_at = serializers.DateTimeField(allow_null=True)
    last_tenant_id = serializers.CharField(
        help_text="While quarantined, the tenant that released it (the only one it can "
        "go back to before the window ends); blank otherwise."
    )
    target_ip = serializers.IPAddressField(
        protocol="IPv4", allow_null=True, help_text="The VM's NetBird address, once known."
    )


class EdgeCountsSerializer(serializers.Serializer):
    free = serializers.IntegerField()
    attached = serializers.IntegerField()
    quarantined = serializers.IntegerField()


class EdgeSerializer(serializers.Serializer):
    name = serializers.CharField()
    provider = serializers.CharField()
    region = serializers.CharField()
    status = serializers.ChoiceField(choices=_EDGE_STATUS)
    netbird_ip = serializers.IPAddressField(protocol="IPv4", allow_null=True)
    netbird_peer_id = serializers.CharField(allow_blank=True)
    bound = serializers.BooleanField(
        help_text="Bound to a NetBird peer. An unbound edge takes no attachment."
    )
    per_ip_mbps = serializers.IntegerField()
    desired_revision = serializers.IntegerField()
    applied_revision = serializers.IntegerField()
    last_seen_at = serializers.DateTimeField(allow_null=True)
    last_report = serializers.DictField()
    counts = EdgeCountsSerializer()
    addresses = EdgeAddressSerializer(many=True)


class EdgeListSerializer(serializers.Serializer):
    edges = EdgeSerializer(many=True)


class EdgeCreateRequestSerializer(serializers.Serializer):
    name = serializers.SlugField(max_length=28)
    provider = serializers.CharField(required=False, max_length=64)
    region = serializers.CharField(help_text="ISO 3166-1 alpha-2.")
    netbird_ip = serializers.IPAddressField(
        protocol="IPv4",
        required=False,
        allow_null=True,
        help_text="The edge's overlay IP. Omit to create the edge unbound.",
    )
    per_ip_mbps = serializers.IntegerField(required=False, min_value=1, default=1000)
    addresses = serializers.ListField(child=serializers.IPAddressField(), required=False)


class EdgePatchRequestSerializer(serializers.Serializer):
    status = serializers.ChoiceField(choices=_EDGE_STATUS, required=False)
    per_ip_mbps = serializers.IntegerField(required=False, min_value=1)
    provider = serializers.CharField(required=False, max_length=64)
    netbird_ip = serializers.IPAddressField(
        protocol="IPv4", required=False, help_text="Re-bind the edge to the peer holding it."
    )


class EdgeAddressesRequestSerializer(serializers.Serializer):
    addresses = serializers.ListField(child=serializers.IPAddressField())


class DesiredAddressSerializer(serializers.Serializer):
    address = serializers.IPAddressField(protocol="IPv4")
    vm_id = serializers.CharField()
    target_ip = serializers.IPAddressField(protocol="IPv4")


class DesiredStateSerializer(serializers.Serializer):
    edge = serializers.CharField()
    revision = serializers.IntegerField()
    per_ip_mbps = serializers.IntegerField()
    addresses = DesiredAddressSerializer(many=True)


class AppliedRequestSerializer(serializers.Serializer):
    revision = serializers.IntegerField(min_value=0)
    report = serializers.DictField(
        required=False, help_text="Agent counters and errors, stored as-is."
    )
