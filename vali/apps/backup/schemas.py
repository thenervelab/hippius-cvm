"""Doc-only serializers for the backup OpenAPI schema. Referenced from
`@extend_schema` in `views.py` only — never wired into request handling.
Fields mirror `service.policy_view` / `service.backups_view`.
"""

from __future__ import annotations

from rest_framework import serializers

from .models import BackupInterval, BackupKind, ChainState, FailoverMode, RunStatus
from .service import BackupState

_STATES = [
    BackupState.DISABLED,
    BackupState.PENDING,
    BackupState.OK,
    BackupState.STALE,
]


class BackupErrorSerializer(serializers.Serializer):
    error = serializers.CharField(help_text="Stable refusal code, e.g. `not-golden`.")
    detail = serializers.CharField()


class BackupPolicyRequestSerializer(serializers.Serializer):
    interval_s = serializers.ChoiceField(
        choices=sorted(BackupInterval.values),
        help_text="Backup interval in seconds — the recovery point objective.",
    )
    retention_days = serializers.IntegerField(
        required=False,
        default=7,
        min_value=1,
        max_value=365,
        help_text="How long a superseded chain is kept before it is deleted.",
    )
    failover_mode = serializers.ChoiceField(
        choices=sorted(FailoverMode.values),
        required=False,
        help_text=(
            "`manual` (default on create) or `auto`. Omitted on an update: the stored mode "
            "is kept. `auto` is refused (409 `failover-auto-unavailable`) where automatic "
            "failover is not available for the VM's region."
        ),
    )


class BackupPolicySerializer(serializers.Serializer):
    vm_id = serializers.CharField()
    enabled = serializers.BooleanField()
    interval_s = serializers.IntegerField()
    retention_days = serializers.IntegerField()
    failover_mode = serializers.ChoiceField(choices=sorted(FailoverMode.values))
    failover_auto_eligible = serializers.BooleanField(
        help_text="Automatic failover would act for this VM now."
    )
    failover_auto_blocker = serializers.ChoiceField(
        choices=["no-point", "region-backups-not-local", "no-failover-peer", "disabled"],
        allow_null=True,
        help_text=(
            "Why it would not: `disabled` (the policy is off), "
            "`region-backups-not-local` (the VM's region keeps its backups in another "
            "region; `auto` is refused there), `no-failover-peer` (no other miner in its "
            "region could ever take it), `no-point` (no restorable backup of the "
            "current boot yet). Null when eligible."
        ),
    )
    failover_cross_generation = serializers.BooleanField(
        help_text="A failover may restore the VM on another CPU generation of its region."
    )
    deferred_reason = serializers.ChoiceField(
        choices=["vm-stopped", "first-full-deferred", "boot-in-progress"],
        allow_null=True,
        help_text=(
            "Why no backup starts now although one is due: `vm-stopped` (nothing new to "
            "copy while it is stopped; not a failure), `first-full-deferred` (the first "
            "full waits for the guest to finish booting, at most 15 min), "
            "`boot-in-progress` (after a start, resize or reboot, the next backup waits "
            "the same way). Null when nothing is held back."
        ),
    )
    deferred_since = serializers.DateTimeField(allow_null=True)
    failover_cross_generation_warning = serializers.CharField(
        allow_null=True,
        help_text="Shown to the customer when that generation is older than the VM's: "
        "software built for the newer CPU may crash there. Null otherwise.",
    )
    created_at = serializers.DateTimeField()
    updated_at = serializers.DateTimeField()


class RestorePointClassSerializer(serializers.Serializer):
    restorable = serializers.BooleanField(
        help_text="The run can be restored now (`POST /v1/vm/<id>/restore`)."
    )
    # `class` is a Python keyword: declared below.
    eta_s = serializers.IntegerField(
        allow_null=True,
        help_text="Estimated seconds to download the point to the VM's host; null "
        "when the run is not a point.",
    )


RestorePointClassSerializer._declared_fields["class"] = serializers.ChoiceField(
    choices=["current-boot", "rollback", "unavailable"],
    help_text=(
        "`current-boot`: taken since the VM's last boot, restorable. `rollback`: "
        "taken at an earlier boot, restorable only through a KBS-authorized "
        "rollback (`restorable` is false while `rollback_capable` is false). "
        "`unavailable`: not a point (unfinished run, failed or pruned chain, "
        "missing earlier run)."
    ),
)


class BackupRunSerializer(serializers.Serializer):
    point = RestorePointClassSerializer()
    run_id = serializers.CharField()
    seq = serializers.IntegerField()
    kind = serializers.ChoiceField(choices=sorted(BackupKind.values))
    status = serializers.ChoiceField(choices=sorted(RunStatus.values))
    reason = serializers.CharField(allow_blank=True)
    disk_bytes = serializers.IntegerField()
    state_bytes = serializers.IntegerField()
    boot_counter = serializers.IntegerField(allow_null=True)
    manifest_sha256 = serializers.CharField(
        allow_null=True,
        help_text="sha256 (hex) of the run's manifest.json; null until the run wrote one.",
    )
    has_checkpoint = serializers.BooleanField(
        help_text=(
            "The run carries the KBS's signed checkpoint of its boot counter — what a "
            "rollback restore to it needs."
        )
    )
    boot_settled = serializers.BooleanField(
        allow_null=True,
        help_text=(
            "True: the run was taken after the VM's boot had settled (the guest still "
            "signalling VALI_BACKUP_BOOT_SETTLE_S after it began). Null: cannot be told — "
            "a run from before this was recorded, or one taken when the wait's cap ran out "
            "with no in-guest signal. Never false."
        ),
    )
    created_at = serializers.DateTimeField()
    finished_at = serializers.DateTimeField(allow_null=True)


class BackupChainSerializer(serializers.Serializer):
    chain_id = serializers.CharField()
    state = serializers.ChoiceField(choices=sorted(ChainState.values))
    boot_counter = serializers.IntegerField(allow_null=True)
    restorable = serializers.BooleanField(
        help_text="True for the chain holding the current restore point."
    )
    stored_bytes = serializers.IntegerField()
    created_at = serializers.DateTimeField()
    closed_at = serializers.DateTimeField(allow_null=True)
    runs = BackupRunSerializer(many=True)


class RestorePointSerializer(serializers.Serializer):
    chain_id = serializers.CharField()
    run_id = serializers.CharField()
    seq = serializers.IntegerField()
    boot_counter = serializers.IntegerField()
    taken_at = serializers.DateTimeField()
    finished_at = serializers.DateTimeField(allow_null=True)


class BackupFailureSerializer(serializers.Serializer):
    run_id = serializers.CharField()
    kind = serializers.ChoiceField(choices=sorted(BackupKind.values))
    created_at = serializers.DateTimeField()
    finished_at = serializers.DateTimeField(allow_null=True)
    reason = serializers.CharField(allow_blank=True, help_text="Static classifier.")


class BackupsSerializer(serializers.Serializer):
    vm_id = serializers.CharField()
    rollback_capable = serializers.BooleanField(
        allow_null=True,
        help_text=(
            "The KBS says the VM's guest can be rolled back to an earlier boot "
            "(read at most once a minute). False: no `rollback` point is "
            "restorable. Null: the KBS did not answer, or rollbacks are off."
        ),
    )
    backup_state = serializers.ChoiceField(choices=_STATES)
    policy = BackupPolicySerializer(allow_null=True)
    restore_point = RestorePointSerializer(
        allow_null=True,
        help_text=(
            "The newest restorable backup. Only a backup taken since the VM's "
            "last boot can be restored; null right after a reboot until the "
            "post-boot full backup completes."
        ),
    )
    stored_bytes = serializers.IntegerField(
        help_text="Bytes held for the VM across every chain not yet pruned."
    )
    chains = BackupChainSerializer(many=True)
    last_failure = BackupFailureSerializer(
        allow_null=True,
        help_text=(
            "The newest finished run when it failed (pruned chains included), "
            "null once a later run succeeds or while no policy is enabled. "
            "Independent of `backup_state`: a failed incremental shows here while "
            "the restore point is still fresh."
        ),
    )
