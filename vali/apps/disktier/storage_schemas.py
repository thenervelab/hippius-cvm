"""Doc-only serializers for the operator storage API
(`apps.disktier.storage_views`). Referenced from `@extend_schema` only —
never wired into request handling (the document is validated by
`apps.disktier.storage_doc`, with the agent's refusal codes)."""

from __future__ import annotations

from rest_framework import serializers

from .models import DedicatedDiskState, DiskHealth
from .storage_doc import DESIRED_STATES, POOL_CLASSES
from .tiers import DiskTier

_TIERS = sorted(t.value for t in DiskTier)
_OVERRIDES = ["", *sorted(t.value for t in DiskTier if t != DiskTier.UNKNOWN)]


class StoragePoolSerializer(serializers.Serializer):
    id = serializers.CharField(help_text="[a-z0-9-]{1,32}; `default` is the data_disk_root pool.")
    path = serializers.CharField(help_text="Absolute mount point, plain spelling.")
    # `class` is a Python keyword: declared below.
    budget_gb = serializers.IntegerField(min_value=0, help_text="> 0 except for `default`.")
    os_disks = serializers.BooleanField()
    state = serializers.ChoiceField(choices=list(DESIRED_STATES))


StoragePoolSerializer._declared_fields["class"] = serializers.ChoiceField(
    choices=list(POOL_CLASSES), help_text="What the operator says the pool is; a hint."
)


class StoragePoolPatchSerializer(serializers.Serializer):
    path = serializers.CharField(required=False)
    budget_gb = serializers.IntegerField(required=False, min_value=0)
    os_disks = serializers.BooleanField(required=False)
    state = serializers.ChoiceField(choices=list(DESIRED_STATES), required=False)


StoragePoolPatchSerializer._declared_fields["class"] = serializers.ChoiceField(
    choices=list(POOL_CLASSES), required=False
)


class DedicatedDiskSpecSerializer(serializers.Serializer):
    id = serializers.CharField(help_text="/dev/disk/by-id basename: wwn-, ata-, scsi-, nvme-.")
    state = serializers.ChoiceField(choices=list(DESIRED_STATES))


class StorageDocSerializer(serializers.Serializer):
    pools = StoragePoolSerializer(many=True, help_text="1..4, must include `default`.")
    dedicated_disks = DedicatedDiskSpecSerializer(many=True, required=False, help_text="≤ 24.")


class StagedSerializer(serializers.Serializer):
    revision = serializers.IntegerField()
    changed = serializers.BooleanField(help_text="False when the content was already current.")


class _ActorSerializer(serializers.Serializer):
    principal = serializers.CharField()
    family = serializers.CharField()
    user = serializers.CharField()


class DesiredSerializer(serializers.Serializer):
    revision = serializers.IntegerField()
    pools = StoragePoolSerializer(many=True)
    dedicated_disks = DedicatedDiskSpecSerializer(many=True)
    updated_by = _ActorSerializer()
    updated_at = serializers.DateTimeField(allow_null=True)


class AppliedPoolSerializer(serializers.Serializer):
    pool_id = serializers.CharField()
    os_disks = serializers.BooleanField()
    state = serializers.CharField(help_text="active / draining / unavailable, as reported.")
    error = serializers.CharField(help_text="The agent's last refusal code for the pool.")
    total_gb = serializers.IntegerField(allow_null=True)
    available_gb = serializers.IntegerField(allow_null=True)
    budget_gb = serializers.IntegerField(allow_null=True)
    committed_gb = serializers.IntegerField(allow_null=True)
    reported_at = serializers.DateTimeField(allow_null=True)
    retired = serializers.BooleanField()


AppliedPoolSerializer._declared_fields["class"] = serializers.CharField()


class DedicatedDiskRowSerializer(serializers.Serializer):
    disk_id = serializers.CharField()
    size_bytes = serializers.IntegerField(allow_null=True)
    desired_state = serializers.ChoiceField(choices=list(DESIRED_STATES), allow_null=True)
    reported_state = serializers.CharField()
    reported_error = serializers.CharField()
    reported_at = serializers.DateTimeField(allow_null=True)
    state = serializers.ChoiceField(choices=sorted(s.value for s in DedicatedDiskState))
    verified_tier = serializers.ChoiceField(choices=_TIERS)
    last_probed_on = serializers.DateField(allow_null=True)
    behind_controller = serializers.BooleanField()
    assigned = serializers.BooleanField()


class AppliedSerializer(serializers.Serializer):
    storage_config_revision = serializers.IntegerField(
        allow_null=True, help_text="From the latest v7 heartbeat; 0 = local config."
    )
    reported_at = serializers.DateTimeField(allow_null=True)
    pools = AppliedPoolSerializer(many=True)
    dedicated_disks = DedicatedDiskRowSerializer(many=True)


class _RefusalSerializer(serializers.Serializer):
    code = serializers.CharField()
    pool = serializers.CharField()
    disk = serializers.CharField()


class SyncSerializer(serializers.Serializer):
    status = serializers.CharField(
        help_text=(
            "in_sync | pending | refused:<code>:<pool or disk> | agent-unsupported | drift "
            "| held:<reason> (the current revision is not pushed: pool-not-drained:<pool>, "
            "family-changed, chain-unavailable) | unmanaged"
        )
    )
    acked_revision = serializers.IntegerField(required=False)
    acked_at = serializers.DateTimeField(required=False, allow_null=True)
    sent_at = serializers.DateTimeField(required=False, allow_null=True)
    last_error = serializers.CharField(required=False)
    refusal = _RefusalSerializer(required=False, allow_null=True)


class PoolTierSerializer(serializers.Serializer):
    pool_id = serializers.CharField()
    tier = serializers.ChoiceField(choices=_TIERS)
    tier_since_on = serializers.DateField(allow_null=True)
    operator_override = serializers.ChoiceField(choices=_OVERRIDES)
    override_reason = serializers.CharField(allow_blank=True)
    effective_tier = serializers.ChoiceField(choices=_TIERS)
    health = serializers.ChoiceField(choices=sorted(h.value for h in DiskHealth))
    health_since_on = serializers.DateField(allow_null=True)
    next_probe_due_on = serializers.DateField(allow_null=True)
    last_probe_on = serializers.DateField(allow_null=True)
    retired = serializers.BooleanField()


class StorageReadoutSerializer(serializers.Serializer):
    node_id = serializers.CharField()
    desired = DesiredSerializer(allow_null=True)
    applied = AppliedSerializer()
    sync = SyncSerializer()
    tiers = PoolTierSerializer(many=True)


class DryRunSerializer(serializers.Serializer):
    revision = serializers.IntegerField()
    ok = serializers.BooleanField()
    status = serializers.IntegerField(help_text="The agent's HTTP status.")
    code = serializers.CharField(help_text="`dry-run-ok:<rev>:<sha>`, or the refusal code.")
    pool = serializers.CharField(required=False)
    disk = serializers.CharField(required=False)


class _AdoptPoolSerializer(serializers.Serializer):
    path = serializers.CharField()


_AdoptPoolSerializer._declared_fields["class"] = serializers.ChoiceField(
    choices=list(POOL_CLASSES), required=False
)


class AdoptRequestSerializer(serializers.Serializer):
    pools = serializers.DictField(
        child=_AdoptPoolSerializer(), help_text="{pool_id: {path, class?}} per reported pool."
    )
    force = serializers.BooleanField(required=False, default=False)


class HistoryEntrySerializer(serializers.Serializer):
    revision = serializers.IntegerField()
    action = serializers.CharField()
    principal = serializers.CharField()
    family = serializers.CharField()
    user = serializers.CharField()
    at = serializers.DateTimeField()
    outcome = serializers.CharField()
    doc = StorageDocSerializer(allow_null=True)


class HistorySerializer(serializers.Serializer):
    node_id = serializers.CharField()
    entries = HistoryEntrySerializer(many=True)


class DiskTiersSerializer(serializers.Serializer):
    node_id = serializers.CharField()
    pools = PoolTierSerializer(many=True)


class DedicatedDisksSerializer(serializers.Serializer):
    node_id = serializers.CharField()
    disks = DedicatedDiskRowSerializer(many=True)


class ForceRemoveSerializer(serializers.Serializer):
    reason = serializers.CharField(
        max_length=256,
        help_text="Why the pool's disk is gone (audited). Required.",
    )
