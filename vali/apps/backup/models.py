"""Backup policy, chains and runs.

A **chain** is one full backup plus the incrementals taken after it,
all within ONE boot of the guest. Only a chain taken at the guest's
CURRENT boot can be restored: the KBS refuses a boot counter that went
backwards and the guest refuses an overlay older than its volume stamp,
and every boot moves both forward. So a reboot makes every earlier chain
unrestorable and the tick takes a new full at once.

A **run** is one backup order: one disk piece (the full raw image or an
incremental qcow2) uploaded as a multipart object, plus the 1 MiB
anti-rollback state disk and a manifest vali writes itself.
"""

from __future__ import annotations

import uuid

from django.db import models
from django.db.models import Q

from apps.lifecycle.models import Vm


class BackupInterval(models.IntegerChoices):
    """The offered tiers. The interval is the recovery point objective."""

    DAILY = 86400, "24 h"
    SIX_HOURS = 21600, "6 h"
    HOURLY = 3600, "1 h"
    QUARTER_HOUR = 900, "15 min"


class FailoverMode(models.TextChoices):
    """Whether vali fails the VM over on its own when its miner dies
    (`apps.orchestration.failover_auto`). `manual` (the default) leaves it
    to an operator; `auto` needs the customer's explicit choice and a region
    whose backups are local (`apps.backup.service.failover_auto_status`)."""

    AUTO = "auto", "Automatic"
    MANUAL = "manual", "Manual"


class BackupPolicy(models.Model):
    vm = models.OneToOneField(Vm, on_delete=models.CASCADE, related_name="backup_policy")
    #: `DELETE /v1/vm/<id>/backup-policy` clears it. Existing chains are
    #: then kept for `retention_days` and pruned like any superseded chain.
    enabled = models.BooleanField(default=True)
    interval_s = models.PositiveIntegerField(choices=BackupInterval.choices)
    retention_days = models.PositiveIntegerField(default=7)
    failover_mode = models.CharField(
        max_length=16, choices=FailoverMode.choices, default=FailoverMode.MANUAL
    )
    #: The next run must be a full: nothing restorable yet, a reboot was
    #: seen, or a failure may have left a hole in the dirty bitmap. Set
    #: means "as soon as allowed", not "at the next interval".
    full_required = models.BooleanField(default=True)
    #: The guest's boot counter as last read from its state disk by the
    #: miner (a run report or a probe). Host-read and unattested: it only
    #: tells boots apart. A chain is restorable iff its counter equals this.
    observed_boot_counter = models.BigIntegerField(null=True, blank=True)
    observed_at = models.DateTimeField(null=True, blank=True)
    last_probe_at = models.DateTimeField(null=True, blank=True)
    disabled_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self) -> str:
        return f"backup policy {self.vm.vm_id} every {self.interval_s}s"


class ChainState(models.TextChoices):
    #: Its full is running or done; incrementals are added to it.
    OPEN = "open", "Open"
    #: A newer chain's full is done (or the policy was disabled). Kept for
    #: `retention_days`, then pruned.
    CLOSED = "closed", "Closed"
    #: Its full never landed. Holds nothing restorable; pruned at once.
    FAILED = "failed", "Failed"
    #: Objects deleted.
    PRUNED = "pruned", "Pruned"


class BackupChain(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    vm = models.ForeignKey(Vm, on_delete=models.CASCADE, related_name="backup_chains")
    state = models.CharField(max_length=16, choices=ChainState.choices, default=ChainState.OPEN)
    #: The boot counter the full was taken at; null until the full is done.
    boot_counter = models.BigIntegerField(null=True, blank=True)
    full_bytes = models.BigIntegerField(default=0)
    incremental_bytes = models.BigIntegerField(default=0)
    incremental_count = models.PositiveIntegerField(default=0)
    #: Next `seq` to hand out. Failed runs consume one too, so a retry
    #: never reuses an object key.
    next_seq = models.PositiveIntegerField(default=0)
    created_at = models.DateTimeField(auto_now_add=True)
    closed_at = models.DateTimeField(null=True, blank=True)
    pruned_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ["-created_at"]
        indexes = [models.Index(fields=["vm", "state"])]

    def __str__(self) -> str:
        return f"chain {self.chain_id} ({self.vm.vm_id}, {self.state})"

    @property
    def chain_id(self) -> str:
        return self.id.hex


class BackupKind(models.TextChoices):
    FULL = "full", "Full"
    INCREMENTAL = "incremental", "Incremental"


class RunStatus(models.TextChoices):
    #: Upload opened and row written; the order is not accepted yet.
    PENDING = "pending", "Pending"
    #: The miner accepted the order.
    RUNNING = "running", "Running"
    DONE = "done", "Done"
    FAILED = "failed", "Failed"


ACTIVE_RUN_STATUSES = (RunStatus.PENDING, RunStatus.RUNNING)


class BackupRun(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    vm = models.ForeignKey(Vm, on_delete=models.CASCADE, related_name="backup_runs")
    chain = models.ForeignKey(BackupChain, on_delete=models.CASCADE, related_name="runs")
    seq = models.PositiveIntegerField()
    kind = models.CharField(max_length=16, choices=BackupKind.choices)
    status = models.CharField(max_length=16, choices=RunStatus.choices, default=RunStatus.PENDING)
    #: Static classifier when failed (the miner's, or vali's own).
    reason = models.CharField(max_length=64, blank=True, default="")
    #: The miner the order went to. Polled there even if the VM moves.
    miner_id = models.CharField(max_length=256)
    disk_key = models.CharField(max_length=512)
    #: Indexed: the janitor looks runs up by it.
    state_key = models.CharField(max_length=512, db_index=True)
    manifest_key = models.CharField(max_length=512)
    #: Empty until the multipart upload is opened (the row is written
    #: first, so an upload is never opened without a row to clean it up).
    upload_id = models.CharField(max_length=512, blank=True, default="", db_index=True)
    #: The multipart upload is open on the store: neither completed nor
    #: aborted yet. Pruning retries the abort of any failed run left open.
    upload_open = models.BooleanField(default=False)
    #: The committed run this one is taken from (incremental), or the one a
    #: full keeps alive on the miner (full). Empty for a chain's first full.
    parent_run_id = models.CharField(max_length=64, blank=True, default="")
    part_size = models.BigIntegerField()
    part_count = models.PositiveIntegerField()
    disk_bytes = models.BigIntegerField(default=0)
    disk_sha256_hex = models.CharField(max_length=64, blank=True, default="")
    part_etags = models.JSONField(default=list, blank=True)
    part_sha256_hex = models.JSONField(default=list, blank=True)
    state_bytes = models.BigIntegerField(default=0)
    state_sha256_hex = models.CharField(max_length=64, blank=True, default="")
    boot_counter = models.BigIntegerField(null=True, blank=True)
    bitmap_present = models.BooleanField(null=True, blank=True)
    #: Wall time the miner reports for snapshot + upload.
    miner_duration_s = models.PositiveIntegerField(null=True, blank=True)
    # Consecutive failed status polls; reset by the next successful one.
    poll_misses = models.PositiveIntegerField(default=0)
    #: sha256 of the exact `manifest.json` bytes stored for the run (the
    #: point an authorized rollback binds to). Empty before a DONE.
    manifest_sha256 = models.CharField(max_length=64, blank=True, default="")
    #: The KBS-signed rollback checkpoint taken when the run completed
    #: (`kbs_rollback.Checkpoint.wire()`), kept ONLY when its boot counter is
    #: the run's own. Null ⇒ the run can never be restored as a rollback.
    kbs_checkpoint = models.JSONField(null=True, blank=True)
    #: The EXACT `manifest.json` bytes stored for the run (UTF-8; the
    #: manifest is ASCII JSON), kept so an authorized rollback can hand
    #: them to the KBS (`point_manifest_b64`) without a store round trip.
    #: `sha256(manifest_json) == manifest_sha256`. Empty before a DONE.
    manifest_json = models.TextField(blank=True, default="")
    created_at = models.DateTimeField(auto_now_add=True)
    dispatched_at = models.DateTimeField(null=True, blank=True)
    finished_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ["chain", "seq"]
        constraints = [
            models.UniqueConstraint(fields=["chain", "seq"], name="backup_run_chain_seq"),
            # One run per VM at a time: two concurrent QMP backups of one
            # disk would fight over the dirty bitmap.
            models.UniqueConstraint(
                fields=["vm"],
                condition=Q(status__in=["pending", "running"]),
                name="backup_one_active_run_per_vm",
            ),
        ]

    def __str__(self) -> str:
        return f"backup run {self.run_id} ({self.kind} #{self.seq}, {self.status})"

    @property
    def run_id(self) -> str:
        return self.id.hex

    @property
    def stored_bytes(self) -> int:
        return int(self.disk_bytes) + int(self.state_bytes)


class BackupJanitorState(models.Model):
    """Where the bucket janitor is in its sweeps (a single row, pk=1). The
    janitor handles one page per tick, so a sweep of a large bucket spans
    ticks; the markers are the store's opaque listing positions."""

    #: Next page of `ListMultipartUploads` under `backups/`; null between
    #: sweeps.
    mpu_marker = models.JSONField(null=True, blank=True)
    mpu_sweep_finished_at = models.DateTimeField(null=True, blank=True)
    #: Next page of the object listing under `uploads/`; null between sweeps.
    staging_marker = models.JSONField(null=True, blank=True)
    staging_sweep_finished_at = models.DateTimeField(null=True, blank=True)

    def __str__(self) -> str:
        return "backup janitor state"
