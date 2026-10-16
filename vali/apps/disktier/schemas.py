"""Doc-only serializers for `GET /v1/operator/disk-profiles`. Referenced
from `@extend_schema` only — never wired into request handling. Fields
mirror `service.disk_profile_rows`."""

from __future__ import annotations

from rest_framework import serializers

from .models import DeclaredClass, DedicatedDiskDesiredState, DedicatedDiskState, DiskHealth
from .tiers import DiskTier

_TIERS = sorted(t.value for t in DiskTier)
_OVERRIDES = ["", *sorted(t.value for t in DiskTier if t != DiskTier.UNKNOWN)]


class DiskProfilePoolSerializer(serializers.Serializer):
    pool_id = serializers.CharField()
    declared_class = serializers.ChoiceField(
        choices=["", *sorted(c.value for c in DeclaredClass)],
        help_text="What the miner says the pool is. A hint, never a tier.",
    )
    os_disks = serializers.BooleanField()
    total_gb = serializers.IntegerField(allow_null=True, help_text="Miner-reported, untrusted.")
    available_gb = serializers.IntegerField(allow_null=True, help_text="Miner-reported, untrusted.")
    budget_gb = serializers.IntegerField(allow_null=True, help_text="Miner-declared cap.")
    reported_at = serializers.DateTimeField(allow_null=True)
    tier = serializers.ChoiceField(choices=_TIERS, help_text="The probe-verified tier.")
    tier_since_on = serializers.DateField(allow_null=True)
    operator_override = serializers.ChoiceField(choices=_OVERRIDES)
    override_reason = serializers.CharField(allow_blank=True)
    effective_tier = serializers.ChoiceField(
        choices=_TIERS, help_text="The override while one is set, else `tier`."
    )
    health = serializers.ChoiceField(choices=sorted(h.value for h in DiskHealth))
    health_since_on = serializers.DateField(allow_null=True)
    next_probe_due_on = serializers.DateField(allow_null=True)
    retired = serializers.BooleanField()


class DiskProfileDedicatedDiskSerializer(serializers.Serializer):
    disk_id = serializers.CharField(help_text="The miner's /dev/disk/by-id basename.")
    size_bytes = serializers.IntegerField(allow_null=True)
    desired_state = serializers.ChoiceField(
        choices=sorted(s.value for s in DedicatedDiskDesiredState)
    )
    state = serializers.ChoiceField(choices=sorted(s.value for s in DedicatedDiskState))
    verified_tier = serializers.ChoiceField(choices=_TIERS)
    last_probed_on = serializers.DateField(allow_null=True)
    behind_controller = serializers.BooleanField()
    assigned = serializers.BooleanField()


class DiskProfileNodeSerializer(serializers.Serializer):
    node_id = serializers.CharField()
    pools = DiskProfilePoolSerializer(many=True)
    dedicated_disks = DiskProfileDedicatedDiskSerializer(many=True)


class DiskProfilesSerializer(serializers.Serializer):
    nodes = DiskProfileNodeSerializer(many=True)
    count = serializers.IntegerField()
