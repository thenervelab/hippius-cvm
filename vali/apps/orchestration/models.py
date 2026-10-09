"""§24/§25 orchestration job models — `MigrationJob` + `DecommissionJob`.

Spec of record: ARCHITECTURE.md §24 (decommission & crypto-erase) /
§25 (miner departure & VM migration).

Both models are **durable, idempotent op records** (§24: "idempotent,
retry-safe ordering ... durable op record with substates"). The
`vali_orchestration_tick` management command drives a job through its
state machine one bounded step per tick; the `state` column IS the
durable substate. Every transition is an optimistic CAS on
`(id, version, state)` so a crashed-then-retried tick — or a second
tick process — cannot double-advance a job.

**Split-brain invariant (§25).** A migration's destination is
activated **only** after a verified source-stopped ack. The
`AwaitingSourceAck` state never advances to `DestActivating` on a
timeout — it fails closed (Job → `Failed`, source §13-quarantined,
destination NOT activated). The VM is therefore never released to two
generations/hosts at once.

**Data-death invariant (§24).** A decommission's `CryptoErasing`
step (erasable-KEK destroy) is reached unconditionally — on a
verified EOL ack OR on an ack timeout (forced reclaim). Crypto-erase
is what guarantees data death; it never depends on miner cooperation.
"""

from __future__ import annotations

import uuid

from django.db import models


class MigrationState(models.TextChoices):
    """§25 migration job lifecycle — a bounded sequential machine.

    Pinned string values (not auto-numbered) so the DB value is
    stable across renames and matches the wire/API representation.
    """

    # COLD migration only: start the tenant-stopped VM on its source and
    # wait for its guest to prove it booted, before the warm §25 proper.
    SOURCE_STARTING = "source_starting", "Source starting"
    DRAINING = "draining", "Draining"
    QUIESCING = "quiescing", "Quiescing"
    SNAPSHOTTING = "snapshotting", "Snapshotting"
    UPLOADING = "uploading", "Uploading"
    FENCING = "fencing", "Fencing"
    AWAITING_SOURCE_ACK = "awaiting_source_ack", "Awaiting source ack"
    DEST_ACTIVATING = "dest_activating", "Dest activating"
    DONE = "done", "Done"
    FAILED = "failed", "Failed"
    # RESTORE only (`kind=restore`, `apps.orchestration.restore`): the
    # destination rebuilds the chosen backup point into a staging directory
    # while the original keeps running.
    RESTORE_STAGING = "restore_staging", "Restore staging"
    # RESTORE only: the original's domain is stopped through the power API
    # and the job waits for its host to report it down.
    RESTORE_STOPPING = "restore_stopping", "Restore stopping"
    # RESTORE / FAILOVER: the destination booted the restored disk; the job
    # waits for the KBS evidence bundle of its release at `new_gen` (the
    # commit point) before activating the VM there.
    RESTORE_VERIFYING = "restore_verifying", "Restore verifying"
    # RESTORE / FAILOVER: a failure BEFORE the commit point — the original
    # is being put back exactly as it was.
    RESTORE_REVERTING = "restore_reverting", "Restore reverting"
    # RESTORE only: an operator put the ORIGINAL back AFTER the commit point
    # (`restore.start_undo`) — through a KBS-authorized rollback to the
    # checkpoint vali took of the original right before the fence.
    RESTORE_UNDOING = "restore_undoing", "Restore undoing"


class MigrationKind(models.TextChoices):
    """What a `MigrationJob` does, and so which justification lets it reach
    `DestActivating` (`service._migration_guard`). None borrows another's.

    - `migrate`  — §25: the source guest's verified signed stopped-ack.
    - `restore`  — restore the VM from one of its backups (same or another
                   miner): an operator `DestAuthorization` plus the source
                   domain confirmed down by its host.
    - `failover` — the VM's miner is dead: an operator `DestAuthorization`
                   carrying the dead-miner evidence snapshot.
    """

    MIGRATE = "migrate", "Migrate"
    RESTORE = "restore", "Restore"
    FAILOVER = "failover", "Failover"


class DestAuthorization(models.Model):
    """Why a restore / failover job may activate a destination without a
    guest-signed source ack. Written once at intake (the `evidence` of a
    restore is extended by the job with the source-down confirmation) and
    read by `service._migration_guard` before `DestActivating`.

    The KBS `activate` to `new_gen` is what makes such an activation safe:
    it fences the old instance from any future key release. This row is
    the record of who asked for it and on what evidence."""

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    kind = models.CharField(max_length=16, choices=MigrationKind.choices)
    requested_by = models.ForeignKey(
        "identity.ServiceClient",
        on_delete=models.PROTECT,
        related_name="dest_authorizations",
    )
    request_id = models.CharField(max_length=128)
    evidence = models.JSONField(default=dict, blank=True)
    #: A2: the caller explicitly accepted restoring a point of an EARLIER
    #: boot (a KBS-authorized rollback). Only a `restore` may carry it.
    accept_rollback = models.BooleanField(default=False)
    #: Who the operator principal acts for: `tenant` / `superuser` and
    #: their id, as the layer above states it. Required for a rollback.
    on_behalf_of_kind = models.CharField(max_length=16, blank=True, default="")
    on_behalf_of_id = models.CharField(max_length=128, blank=True, default="")
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self) -> str:
        return f"DestAuthorization {self.kind} {self.request_id}"

    @property
    def requested_for(self) -> str:
        """`<kind>:<id>` — the `requested_by` the KBS records on an arm."""
        return f"{self.on_behalf_of_kind}:{self.on_behalf_of_id}"


class RollbackOutcome(models.TextChoices):
    #: Opened; the KBS was not asked yet.
    PENDING = "pending", "Pending"
    #: The KBS armed it (`armed_at`).
    ARMED = "armed", "Armed"
    #: The KBS reports the arm consumed by THIS restore: the VM's key was
    #: released to the restored disk of the earlier boot.
    COMMITTED = "committed", "Committed"
    #: The KBS evidence shows the restored disk released at `new_gen` on the
    #: destination — only the arm can have allowed it — but the KBS lost its
    #: `last_rollback` record (a restart) before vali read it delivered.
    COMMITTED_UNVERIFIED = "committed-unverified", "Committed (unverified)"
    #: The KBS refused to arm it (`reason`).
    REFUSED = "refused", "Refused"
    #: The job failed or was cancelled before any rollback committed; any
    #: arm was withdrawn (`disarmed_at`).
    ABANDONED = "abandoned", "Abandoned"


class RollbackPurpose(models.TextChoices):
    #: A restore to a point of an earlier boot.
    RESTORE = "restore", "Restore"
    #: An operator putting a restore's ORIGINAL back after its commit point.
    UNDO = "undo", "Undo"


class RollbackEvent(models.Model):
    """vali's own durable audit copy of one authorized rollback (the KBS's
    admin audit log does not survive a KBS restart). At most one per job
    and purpose, written when asked and followed to its outcome.
    `restore_id` is the id the KBS arm is keyed on."""

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    vm = models.ForeignKey("lifecycle.Vm", on_delete=models.CASCADE, related_name="rollback_events")
    job = models.ForeignKey(
        "orchestration.MigrationJob", on_delete=models.PROTECT, related_name="rollback_events"
    )
    purpose = models.CharField(
        max_length=16, choices=RollbackPurpose.choices, default=RollbackPurpose.RESTORE
    )
    #: The backup run rolled back to; null for an undo (the original).
    run = models.ForeignKey(
        "backup.BackupRun",
        on_delete=models.PROTECT,
        null=True,
        blank=True,
        related_name="rollback_events",
    )
    restore_id = models.CharField(max_length=32)
    #: The VM's boot counter when the rollback was asked (host-read) and the
    #: point's (the KBS-signed checkpoint's).
    from_boot_counter = models.BigIntegerField(null=True, blank=True)
    to_boot_counter = models.BigIntegerField()
    point_taken_at = models.DateTimeField()
    manifest_sha256 = models.CharField(max_length=64)
    requested_by_kind = models.CharField(max_length=16)
    requested_by_id = models.CharField(max_length=128)
    created_at = models.DateTimeField(auto_now_add=True)
    #: Set BEFORE vali asks the KBS to arm: from then on an arm may exist
    #: even if vali crashed before recording `armed_at`.
    arm_requested_at = models.DateTimeField(null=True, blank=True)
    armed_at = models.DateTimeField(null=True, blank=True)
    committed_at = models.DateTimeField(null=True, blank=True)
    #: vali saw its arm live and unconsumed on the KBS, then deleted it:
    #: the positive proof that no release can have consumed it since.
    disarmed_at = models.DateTimeField(null=True, blank=True)
    outcome = models.CharField(
        max_length=24, choices=RollbackOutcome.choices, default=RollbackOutcome.PENDING
    )
    reason = models.CharField(max_length=256, blank=True, default="")
    #: The KBS's `last_rollback` record as read when the commit was seen.
    kbs_record = models.JSONField(null=True, blank=True)

    class Meta:
        ordering = ["-created_at"]
        indexes = [models.Index(fields=["vm", "arm_requested_at"])]
        constraints = [
            models.UniqueConstraint(
                fields=["job", "purpose"], name="orchestration_one_rollback_per_job_purpose"
            )
        ]

    def __str__(self) -> str:
        return f"RollbackEvent {self.restore_id} ({self.outcome})"


class SourceReclaimState(models.TextChoices):
    """Fate of the SOURCE host's per-VM artifacts after a §25 migration.

    §25 is a COPY: the source keeps its `overlay/<vm>.img` (the tenant's
    LUKS ciphertext), its `state/<vm>.raw` (the boot counter) and its
    `staging/<vm>/` boot artifacts, on a host that no longer runs the VM
    and is UNTRUSTED. Nothing in the migration ever removed them.

    Reclaiming them is a fail-SAFE background action, not a step the
    migration's success depends on — hence its own field rather than a
    state in `MigrationState`: a source that cannot be proven safe to
    reclaim must never hold a completed migration open.

    - `pending`    — not yet reclaimed; the sweep re-evaluates each tick.
    - `reclaimed`  — a `destroy` order was accepted by the SOURCE miner.
    - `skipped`    — deliberately NOT reclaimed; `source_reclaim_reason`
                     says why. The artifacts are still on the source and
                     the event is logged at ERROR for an operator.
    """

    PENDING = "pending", "Pending"
    RECLAIMED = "reclaimed", "Reclaimed"
    SKIPPED = "skipped", "Skipped"


class StrandRecoveryState(models.TextChoices):
    """What was done about a §25 migration that STRANDED its VM.

    A migration that fails from `Quiescing` onward leaves the `Vm` row in
    `Migrating` with no domain anywhere: the source guest was gracefully
    stopped and the destination never came up. `reboot_recovery_once`
    scans `Active` VMs only, so such a VM is outside every automatic path
    — it stays down until an operator notices.

    - `none`             — nothing has been done (the default, and the
                           value every non-stranded job keeps).
    - `source_restored`  — the VM was un-fenced back to `Active` on its
                           SOURCE at `source_gen`. Only ever recorded on
                           the PROVEN-safe class: a job that never reached
                           `DestActivating`, so the KBS `VmState` is still
                           `Active{source_gen, source}` and the source is
                           the only host that can unlock. Restoring hands
                           the VM back to reboot-recovery.
    - `redriven`         — a fresh `MigrationJob` was opened to re-drive
                           the SAME destination at the SAME `new_gen`.
                           This is the ONLY recovery once
                           `kbs_activate_dest` has fired: the KBS is then
                           `Migrating{new_gen, dest}` and no admin route
                           moves it anywhere else, so the destination is
                           the only host that can ever unlock the disk.
    """

    NONE = "none", "None"
    SOURCE_RESTORED = "source_restored", "Source restored"
    REDRIVEN = "redriven", "Re-driven to dest"


class DecommissionState(models.TextChoices):
    """§24 decommission job lifecycle."""

    DRAINING = "draining", "Draining"
    AWAITING_EOL_ACK = "awaiting_eol_ack", "Awaiting EOL ack"
    CRYPTO_ERASING = "crypto_erasing", "Crypto erasing"
    REVOKING_NETBIRD = "revoking_netbird", "Revoking NetBird"
    DONE = "done", "Done"
    FAILED = "failed", "Failed"


class KbsFence(models.TextChoices):
    """Where a §24 job stands with the KBS decommission fence
    (`VALI_KBS_FENCE_ENABLED`). Blank ⇒ never attempted (flag off, or not
    reached yet)."""

    NONE = "", "Not attempted"
    # The KBS holds `Decommissioning`: it refuses every release and says
    # "revoked" to the VM's custody lease.
    FENCED = "fenced", "Fenced"
    # The KBS holds `Destroyed{gen}` — the permanent tombstone.
    TOMBSTONED = "tombstoned", "Tombstoned"
    # A fence or tombstone the job could not land in-line; the tick sweep
    # (`sweep_pending_kbs_fences`) keeps re-driving it.
    PENDING = "pending", "Pending"
    # The KBS already holds a tombstone at a DIFFERENT generation. Retrying
    # cannot change that, so the sweep stops and an operator looks.
    CONFLICT = "conflict", "Conflict"


# Terminal states — a job here is never advanced again. Kept here
# (not in the service layer) so the model constraint, the partial
# unique index, and the tick query all read one source.
TERMINAL_MIGRATION_STATES: frozenset[str] = frozenset(
    {MigrationState.DONE.value, MigrationState.FAILED.value}
)
TERMINAL_DECOMMISSION_STATES: frozenset[str] = frozenset(
    {DecommissionState.DONE.value, DecommissionState.FAILED.value}
)


class MigrationJob(models.Model):
    """One §25 VM migration: source_node → dest_node, generation+1.

    Field-by-field:

    - `job_id`            public, opaque, URL-safe identifier (the
                          PK `id` never leaks onto the wire).
    - `vm`               FK to the `lifecycle.Vm` being migrated.
    - `source_node_id`   miner the VM currently runs on.
    - `dest_node_id`     miner the VM is migrating to.
    - `source_gen`       the VM's generation at job start.
    - `new_gen`          `source_gen + 1` — the fenced destination
                          generation (forward-only; §25).
    - `state`            one of `MigrationState`.
    - `snapshot_bucket`/`snapshot_key`
                          S3 location of the LUKS2+dm-integrity
                          snapshot. These are NON-secret references —
                          the short-TTL presigned PUT/GET URLs are
                          generated on demand and **never persisted**
                          (no bearer capability in a job record).
    - `source_ack_verified`
                          set once a guest-signed source-stopped ack
                          has been verified — the §25 split-brain
                          gate before `DestActivating`.
    - `source_reclaim_state` / `source_reclaim_at` / `source_reclaim_reason`
                          fate of the SOURCE host's per-VM artifacts
                          (see `SourceReclaimState`). Driven by the
                          post-`Done` sweep, never by the state machine.
    - `failed_from_state` the state the job was in when it failed. The
                          PERMIT input to a source restore — see the
                          field comment.
    - `strand_recovery_state` / `strand_recovery_at` /
      `strand_recovery_reason`
                          what was done about the VM this job stranded
                          in `Migrating` (see `StrandRecoveryState`).
    - `quarantine_node_id`
                          set to `source_node_id` when the job
                          §13-quarantines the source (ack timeout).
                          The on-chain `MinerStatus::Quarantined`
                          write is the validator-submission layer's
                          job (§I); this field is the durable handoff.
    - `reason`           short operator-facing string on `Failed`.
    - `phase_started_at` wall-clock the current `state` was entered —
                          drives the per-phase timeout.
    - `decided_by`       the root `ServiceClient` that started it.
    - `version`          optimistic-concurrency counter; +1 per CAS.

    Constraints:

    - Partial unique on `vm` for non-terminal states — at most one
      active migration per VM (the DB boundary behind the 409 on a
      concurrent migrate attempt).
    - `terminal ⇒ finished_at IS NOT NULL` (DB CHECK).
    """

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    job_id = models.CharField(max_length=64, unique=True)
    vm = models.ForeignKey(
        "lifecycle.Vm",
        on_delete=models.PROTECT,
        related_name="migration_jobs",
    )
    source_node_id = models.CharField(max_length=64)
    dest_node_id = models.CharField(max_length=64)
    source_gen = models.BigIntegerField()
    new_gen = models.BigIntegerField()
    state = models.CharField(
        max_length=32,
        choices=MigrationState.choices,
        default=MigrationState.DRAINING,
    )
    snapshot_bucket = models.CharField(max_length=256, blank=True, default="")
    snapshot_key = models.CharField(max_length=512, blank=True, default="")
    # S3 key of the source's per-VM anti-rollback state disk (the guest's
    # boot counter). Carried alongside the encrypted volume: without it the
    # destination boots a BLANK counter and the KBS refuses the release
    # before any Vault read, so the migrated guest never unlocks. Blank on
    # jobs created before this field — the dest then falls back to the
    # pre-fix blank-counter behaviour rather than failing.
    snapshot_state_key = models.CharField(max_length=512, blank=True, default="")
    # The snapshot's S3 multipart upload while it is OPEN (empty once
    # completed, and for a single-PUT snapshot), with the part plan its
    # presigned part URLs were cut to.
    snapshot_upload_id = models.CharField(max_length=1024, blank=True, default="")
    snapshot_part_size = models.BigIntegerField(default=0)
    snapshot_part_count = models.IntegerField(default=0)
    # The completed multipart snapshot's length + sha256 as the source
    # uploaded it; the destination verifies its download against both.
    snapshot_size = models.BigIntegerField(default=0)
    snapshot_sha256 = models.CharField(max_length=64, blank=True, default="")
    # When the migration's S3 snapshot objects were deleted (NULL = still
    # there, or never uploaded).
    snapshot_deleted_at = models.DateTimeField(null=True, blank=True)
    # COLD migration: the VM was STOPPED when the migration began; it is
    # started on its source for the warm §25 and stopped again afterwards
    # (`settle_cold_migrations`). `cold_settled_at` marks that stop done (or
    # deliberately abandoned, `cold_settle_reason` says which).
    cold = models.BooleanField(default=False)
    cold_settled_at = models.DateTimeField(null=True, blank=True)
    cold_settle_reason = models.CharField(max_length=128, blank=True, default="")
    source_ack_verified = models.BooleanField(default=False)
    # Fate of the SOURCE host's per-VM artifacts (see `SourceReclaimState`).
    # Driven by the post-Done `reclaim_migrated_sources()` sweep, NOT by the
    # job state machine: the reclaim is fail-safe cleanup and must never be
    # able to hold a completed migration open.
    source_reclaim_state = models.CharField(
        max_length=16,
        choices=SourceReclaimState.choices,
        default=SourceReclaimState.PENDING,
    )
    source_reclaim_at = models.DateTimeField(null=True, blank=True)
    source_reclaim_reason = models.CharField(max_length=256, blank=True, default="")
    # The `MigrationState` this job was in when it FAILED — written by
    # `_fail_migration`, and the single PERMIT input to a source restore.
    #
    # It answers exactly one question: did this migration ever enter
    # `DestActivating`? That state is the only one that calls
    # `effects.kbs_activate_dest`, i.e. the only one that moves the KBS
    # `VmState` to `Migrating{new_gen, dest}` — and once it has moved,
    # NO admin route moves it back (`kbs-core::admin::process_admin_activate`
    # is forward-only: it can only fence the current holder behind a
    # strictly higher generation, never re-admit `source_gen`), so the
    # source can never unlock again and a restore would produce a guest
    # that boots and hangs. Below `DestActivating` the KBS never moved,
    # the source is still the only releasable host, and the restore is safe.
    #
    # Blank on every job created before this field existed, and blank is
    # UNPROVABLE ⇒ no automatic restore. Deliberately NOT backfilled from
    # `reason`: a permit must come from a field only `_fail_migration`
    # writes, never from parsing a free-text string.
    failed_from_state = models.CharField(
        max_length=32, blank=True, default="", choices=MigrationState.choices
    )
    # What was done about a stranded VM (see `StrandRecoveryState`).
    # Bookkeeping for the operator + the sweep, never read by a job CAS.
    strand_recovery_state = models.CharField(
        max_length=16,
        choices=StrandRecoveryState.choices,
        default=StrandRecoveryState.NONE,
    )
    strand_recovery_at = models.DateTimeField(null=True, blank=True)
    strand_recovery_reason = models.CharField(max_length=256, blank=True, default="")
    quarantine_node_id = models.CharField(max_length=64, blank=True, default="")
    reason = models.CharField(max_length=256, blank=True, default="")
    phase_started_at = models.DateTimeField()
    started_at = models.DateTimeField(auto_now_add=True)
    finished_at = models.DateTimeField(null=True, blank=True)
    decided_by = models.ForeignKey(
        "identity.ServiceClient",
        on_delete=models.PROTECT,
        related_name="migration_jobs",
    )
    version = models.PositiveBigIntegerField(default=1)
    # ── restore / failover (`apps.orchestration.restore`) ──────────────
    # A restore reuses this job end to end (the VM's `Migrating` state, the
    # dest activation, the #1206 reclaim gate, the stranded sweep) and the
    # one-active-job-per-VM constraint serialises it against §25 / §24.
    kind = models.CharField(
        max_length=16, choices=MigrationKind.choices, default=MigrationKind.MIGRATE
    )
    #: Who opened a restore / failover: `operator` (the API), or `auto` (the
    #: automatic failover worker, a later part).
    trigger = models.CharField(max_length=16, default="operator", db_default="operator")
    #: When vali saw a restore / failover pass its commit point (the restored
    #: guest's key release at `new_gen`, `restore.h_verifying`); also set on a
    #: job that failed after it (`restore._stamp_committed`).
    committed_at = models.DateTimeField(null=True, blank=True)
    # The backup point restored from. Pins its chain against pruning while
    # the job is not terminal.
    restore_run = models.ForeignKey(
        "backup.BackupRun",
        on_delete=models.PROTECT,
        null=True,
        blank=True,
        related_name="restore_jobs",
    )
    # 32 lower-hex id the destination keys its staging directory and the
    # `.pre-restore-<id>` files on. Blank for a §25 migration.
    restore_id = models.CharField(max_length=32, blank=True, default="")
    # The caller's idempotency key: the same request_id is the same job.
    request_id = models.CharField(max_length=128, null=True, blank=True, unique=True)
    # `running` / `stopped` when the job began; a stopped VM is stopped
    # again once the restored one proved it runs (`cold`, the
    # `settle_cold_migrations` pattern).
    prior_power_state = models.CharField(max_length=16, blank=True, default="")
    authorization = models.ForeignKey(
        DestAuthorization,
        on_delete=models.PROTECT,
        null=True,
        blank=True,
        related_name="jobs",
    )
    # Estimated seconds to stage the point on the destination.
    restore_eta_s = models.PositiveIntegerField(null=True, blank=True)
    # Staging progress as the destination last reported it.
    restore_bytes_done = models.BigIntegerField(default=0)
    restore_bytes_total = models.BigIntegerField(default=0)
    # `restore` op=stage orders sent (a lost staging is re-sent, bounded).
    restore_dispatches = models.PositiveIntegerField(default=0)
    restore_dispatched_at = models.DateTimeField(null=True, blank=True)
    # A pre-commit failure put the original back exactly as it was.
    reverted = models.BooleanField(default=False)
    # A failed restore still owes cleanup on its hosts: the staging
    # directory dropped (`restore` op=abort) and, when the job stopped a
    # running VM, the VM started again.
    restore_cleanup_pending = models.BooleanField(default=False)
    # A failure AFTER the commit point keeps the original disk on the
    # destination until then (and after, until the restored VM is proven).
    restore_keep_original_until = models.DateTimeField(null=True, blank=True)
    # The KBS-signed rollback checkpoint of the ORIGINAL (`Checkpoint.wire()`),
    # taken right before the fence, and the manifest bytes that embed it (the
    # point an operator undo binds its arm to). Null / empty when the KBS gave
    # none: the restore then cannot be undone after its commit point.
    original_checkpoint = models.JSONField(null=True, blank=True)
    original_manifest = models.TextField(blank=True, default="")
    # The operator's post-commit undo (`restore.start_undo`): who asked, the
    # rollback's own restore id, the generation the original relaunches at,
    # and how it went. Null when never asked.
    undo = models.JSONField(null=True, blank=True)
    # ── resize (`apps.orchestration.resize`) ──────────────────────────
    # Set when a `ResizeJob` started this migration because the VM's new
    # flavor does not fit on its current miner: the destination's placement
    # is opened at THIS flavor in the activation CAS (`move_placement_to_node`),
    # so the room the resize was admitted for is reserved from the instant
    # the VM lands — no window in which another launch can take it. The
    # migration itself still boots the OLD flavor (it replays the source's
    # measured boot); the resize relaunches at the new one afterwards.
    resize_to_flavor = models.CharField(max_length=32, blank=True, default="", db_default="")

    class Meta:
        ordering = ["-started_at"]
        indexes = [
            models.Index(fields=["state"]),
        ]
        constraints = [
            models.UniqueConstraint(
                fields=["vm"],
                condition=~models.Q(state__in=["done", "failed"]),
                name="orchestration_one_active_migration_per_vm",
            ),
            models.CheckConstraint(
                name="orchestration_migration_terminal_finished",
                condition=(
                    ~models.Q(state__in=["done", "failed"]) | models.Q(finished_at__isnull=False)
                ),
            ),
        ]

    def __str__(self) -> str:
        return (
            f"MigrationJob {self.job_id} (vm={self.vm_id} "
            f"{self.source_node_id}→{self.dest_node_id}, {self.state})"
        )


class FailoverQuarantine(models.Model):
    """A miner a manual failover declared dead (`kind=failover`). While the
    row is open (`cleared_at` NULL) the miner is not dispatchable: nothing
    is placed on it, and no restore or migration targets it. Only an
    operator clears it (`vali_failover_quarantine --clear`).

    It also drives the reappearance reconciliation: once the miner
    heart-beats again, any domain it still runs for a VM the failover moved
    away is force-stopped, and its disks are reclaimed once the VM is
    proven on its new host (`restore.reconcile_failover_quarantines`)."""

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    miner_id = models.CharField(max_length=64, db_index=True)
    job = models.ForeignKey(
        MigrationJob, on_delete=models.PROTECT, related_name="failover_quarantines"
    )
    created_at = models.DateTimeField(auto_now_add=True)
    cleared_at = models.DateTimeField(null=True, blank=True)
    cleared_by = models.CharField(max_length=128, blank=True, default="")

    class Meta:
        ordering = ["-created_at"]
        constraints = [
            models.UniqueConstraint(
                fields=["job"], name="orchestration_one_failover_quarantine_per_job"
            ),
        ]

    def __str__(self) -> str:
        state = "open" if self.cleared_at is None else "cleared"
        return f"FailoverQuarantine {self.miner_id} ({state})"


class LaunchJobState(models.TextChoices):
    """Admin→API launch job lifecycle (PR-A2).

    `queued` on `POST /v1/vm/launch`; `vali_launch_tick` CAS-claims it
    to `running`, drives `launch_vm` (scheduler place → dispatch →
    re-place), then CAS to `succeeded` / `failed`. Async because the
    miner preflight inside `launch_vm` can take up to 30 min.
    """

    QUEUED = "queued", "Queued"
    RUNNING = "running", "Running"
    SUCCEEDED = "succeeded", "Succeeded"
    FAILED = "failed", "Failed"


class LaunchPhase(models.TextChoices):
    """Fine-grained progress phase for an admin→API launch (live UI).

    Purely-additive instrumentation OVER `LaunchJobState`: `state` remains
    the coarse authoritative CAS machine (queued/running/succeeded/failed),
    while `phase` exposes WHERE inside `running` the `vali_launch_tick`
    worker currently is — the vali-observable steps of ONE launch:

    - `queued`       — stamped at intake (`start_launch`), mirrors `queued`.
    - `staging`      — the worker read the cloud-init userdata back from
                       Vault + built the `LaunchSpec` (secret staging), just
                       before it drives `launch_vm`.
    - `placing`      — inside `launch_vm`: the §23 scheduler is choosing a
                       miner (chain snapshot → `decide_placement` → record a
                       `Placement`). Re-emitted on each re-place attempt.
    - `dispatching`  — inside `launch_vm`: `launch_on_miner` is staging the
                       KEK/userdata refs, minting the L1 ticket, registering
                       with the KBS and dispatching the launch order to the
                       chosen miner.
    - `launched`     — terminal success (mirrors `succeeded`).
    - `failed`       — terminal failure (mirrors `failed`).

    In-guest boot / KEK-release are miner+guest-side and NOT observable
    here — those are the SDK's concern, out of scope for this field.
    """

    QUEUED = "queued", "Queued"
    STAGING = "staging", "Staging secrets"
    PLACING = "placing", "Placing"
    DISPATCHING = "dispatching", "Dispatching"
    LAUNCHED = "launched", "Launched"
    FAILED = "failed", "Failed"


# Terminal launch states — never re-advanced. The partial unique index
# + the tick claim query both read this set.
TERMINAL_LAUNCH_STATES: frozenset[str] = frozenset(
    {LaunchJobState.SUCCEEDED.value, LaunchJobState.FAILED.value}
)


class LaunchJob(models.Model):
    """One admin-requested VM launch, driven asynchronously (PR-A2).

    Unlike `MigrationJob`/`DecommissionJob` this job does NOT FK a
    `lifecycle.Vm` — the launch CREATES that row (`launch_vm` does a
    get-or-create). It is keyed by the `vm_id` string instead.

    §20 secret discipline: NO plaintext secret is stored on this row —
    and, since the userdata wrapping, none in Vault either. The cloud-init
    `userdata` is Transit-wrapped at POST and referenced by
    `userdata_vault_path` + `userdata_vault_version`; the LUKS KEK is
    referenced by `kek_vault_path` (the bake's path) and read back by the
    worker. `spec_json` carries ONLY the non-secret launch intent
    (flavor, artefact SHAs, cmdline, S3 location, paths).

    Field-by-field:

    - `job_id`        public opaque identifier (hex).
    - `vm_id`         the tenant VM this launch provisions (indexed).
    - `tenant_id`     anti-affinity family / audit.
    - `flavor`        the requested size (audit / list filter).
    - `spec_json`     the non-secret `LaunchSpec` fields as JSON.
    - `userdata_vault_path` / `userdata_vault_version`
                      where the POST staged the cloud-init plaintext.
    - `kek_vault_path` Vault path the worker reads the LUKS KEK from.
    - `state`         one of `LaunchJobState`.
    - `result_json`   the `launch_vm` outcome (miner, ticket_id,
                      measurement, attempts) on terminal states.
    - `reason`        operator-facing failure string on `failed`.
    - `miner_id` / `placement_id`
                      the elected miner + its `Placement` on success.
    - `phase_started_at` / `started_at` / `finished_at` / `decided_by`
                      / `version` — as the other job models.

    Constraints: partial unique on `vm_id` for non-terminal states (at
    most one in-flight launch per VM); `terminal ⇒ finished_at NOT NULL`.
    """

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    job_id = models.CharField(max_length=64, unique=True)
    vm_id = models.CharField(max_length=256, db_index=True)
    tenant_id = models.CharField(max_length=256, db_index=True)
    flavor = models.CharField(max_length=32)
    spec_json = models.JSONField(default=dict)
    userdata_vault_path = models.CharField(max_length=512)
    userdata_vault_version = models.BigIntegerField()
    kek_vault_path = models.CharField(max_length=512)
    state = models.CharField(
        max_length=32,
        choices=LaunchJobState.choices,
        default=LaunchJobState.QUEUED,
    )
    # Fine-grained progress WITHIN `state` (queued→staging→placing→
    # dispatching→launched/failed) for a live launch UI. Additive
    # instrumentation only — never part of the CAS invariant. Blank-default
    # so existing rows migrate cleanly (an old row reads `""` ⇒ the API
    # renders `null` ⇒ the SDK falls back to the coarse `state`).
    phase = models.CharField(
        max_length=16,
        choices=LaunchPhase.choices,
        blank=True,
        default="",
    )
    result_json = models.JSONField(null=True, blank=True)
    reason = models.CharField(max_length=256, blank=True, default="")
    miner_id = models.CharField(max_length=64, blank=True, default="")
    placement_id = models.CharField(max_length=64, blank=True, default="")
    phase_started_at = models.DateTimeField()
    started_at = models.DateTimeField(auto_now_add=True)
    finished_at = models.DateTimeField(null=True, blank=True)
    decided_by = models.ForeignKey(
        "identity.ServiceClient",
        on_delete=models.PROTECT,
        related_name="launch_jobs",
    )
    version = models.PositiveBigIntegerField(default=1)

    class Meta:
        ordering = ["-started_at"]
        indexes = [
            models.Index(fields=["state"]),
            models.Index(fields=["vm_id", "state"]),
        ]
        constraints = [
            models.UniqueConstraint(
                fields=["vm_id"],
                condition=~models.Q(state__in=["succeeded", "failed"]),
                name="orchestration_one_active_launch_per_vm",
            ),
            models.CheckConstraint(
                name="orchestration_launch_terminal_finished",
                condition=(
                    ~models.Q(state__in=["succeeded", "failed"])
                    | models.Q(finished_at__isnull=False)
                ),
            ),
        ]

    def __str__(self) -> str:
        return f"LaunchJob {self.job_id} (vm={self.vm_id}, {self.state})"


class RebootRecovery(models.Model):
    """Reboot-recovery bookkeeping for one VM (debounce / attempt cap /
    backoff), kept OFF the hot `lifecycle.Vm` row.

    `service.reboot_recovery_once` relaunches a VM that vali records as
    `Active` but whose bound — and still-ALIVE — miner reports the tenant
    domain DOWN, e.g. after a host reboot powered the CVM off (the
    miner-agent re-adopts only still-running domains, so nothing relaunches
    a powered-off tenant CVM). This row exists purely to make that scan
    SAFE:

    - `consecutive_down` — debounce counter: how many consecutive polls
      reported the VM down. Reset to 0 on a healthy / unavailable signal.
      A relaunch fires only past a threshold, so a transient (a guest soft
      reboot, the host-up→re-adopt window) never triggers one.
    - `consecutive_wedged` — the SAME debounce for the second trigger:
      the domain is running but the guest inside it has gone silent (see
      `apps.lifecycle.guest_liveness`). Kept as its OWN counter rather
      than folded into `consecutive_down`, because the two conditions are
      mutually exclusive per poll (`running is False` vs `running is
      True`) and mixing them would let alternating polls accumulate a
      relaunch neither condition earned. Reset to 0 on any `alive` /
      `unknown` verdict, on an unavailable domain-state signal, and on a
      dispatched relaunch.
    - `attempts` — relaunch attempts in the CURRENT incident (host-down
      episode), capped so a VM that will not come back is not relaunched
      forever. Reset once the relaunched VM has been seen up and not
      wedged `VALI_REBOOT_RECOVERY_STABLE_S` after the relaunch.
    - `next_attempt_at` — exponential-backoff gate between attempts.
    - `last_outcome` / `last_relaunch_at` — audit.
    - `host` — the miner these counters DESCRIBE (`Vm.host` / the resolved
      bound miner). Every field above is host-scoped: a relaunch attempt
      is an attempt against ONE host, and a backoff window paces retries
      on ONE host. Without this stamp the row could not tell the
      difference between "burned its budget here" and "burned its budget
      somewhere it no longer runs" — so a VM that exhausted its relaunch
      cap on a flaky host arrived at a healthy §25 DESTINATION already at
      the cap (`last_outcome="attempts-exhausted"`) and could never be
      reboot-recovered there again. Migration is the remedy for a bad
      host; the counter that says "give up on this VM" must not survive
      the remedy. `service.rescope_reboot_recovery_to_host` resets the
      host-scoped fields whenever this stamp stops matching, INSIDE the
      same CAS that moves `Vm.host` (§25 activation and the
      `Migrating→Active` transition endpoint, the two writers of that
      field), with the scan itself as a lazy backstop for any future
      third writer.

      `seen_running` is deliberately NOT among the fields reset — see its
      entry below.
    - `seen_running` — has the reconcile EVER observed this VM's domain
      running (a `domain-state` poll returned `running:true`)? A relaunch
      fires ONLY once this is set. This scopes reboot-recovery to its real
      purpose — recovering a VM that WAS up and a host reboot powered off —
      and refuses to resurrect a VM that vali records `Active` but that has
      been down the whole time we watched it (a stale/zombie row, or a
      launch that never came up). Those are an operator / §25 concern, not
      a reboot to recover from.

      It is a fact about the VM's PAST, not host-scoped policy, so a host
      change PRESERVES it. Clearing it on a migration would re-arm only by
      observing the destination's domain running — i.e. exactly when
      recovery is NOT needed — and never in the one case where it is: a
      migration that reported `Done` onto a destination whose domain never
      came up would be permanently unrecoverable. That is the same
      availability defect this stamp exists to close, pointed the other
      way. And a §25 VM is definitionally not the zombie the gate guards
      against: activation is reached only after a verified source-stopped
      ack, which a LIVE source guest signs from inside itself.
    - `version` — optimistic CAS: the reconcile claims the row (bumps
      `version`) BEFORE dispatching, so two overlapping ticks can never
      double-dispatch a relaunch.
    """

    vm = models.OneToOneField(
        "lifecycle.Vm",
        on_delete=models.CASCADE,
        primary_key=True,
        related_name="reboot_recovery",
    )
    seen_running = models.BooleanField(default=False)
    # Matches `lifecycle.Vm.host` (max_length=256) — this holds the same
    # value, so it must be able to hold every value that field can.
    host = models.CharField(max_length=256, blank=True, default="")
    consecutive_down = models.PositiveIntegerField(default=0)
    consecutive_wedged = models.PositiveIntegerField(default=0)
    attempts = models.PositiveIntegerField(default=0)
    next_attempt_at = models.DateTimeField(null=True, blank=True)
    last_outcome = models.CharField(max_length=64, blank=True, default="")
    last_relaunch_at = models.DateTimeField(null=True, blank=True)
    version = models.PositiveBigIntegerField(default=1)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self) -> str:
        return (
            f"RebootRecovery(vm={self.vm_id}, down={self.consecutive_down}, "
            f"attempts={self.attempts})"
        )


class DataDeath(models.TextChoices):
    """What a §24 erase achieved for the tenant's data
    (`DecommissionJob.data_death`)."""

    #: Hippius held the disk key (M0 KEK, M1 `share_H`) and destroyed it.
    CRYPTO_ERASED = "crypto-erased", "Crypto-erased"
    #: M2: the disk key is the customer's alone. Hippius deleted its copies
    #: of everything it stores; cryptographic erase is `guardian erase`.
    CUSTOMER_ERASE_REQUIRED = "customer-erase-required", "Customer erase required"


class DecommissionJob(models.Model):
    """One §24 VM end-of-life: crypto-erase + graceful teardown.

    Field-by-field:

    - `job_id`            public opaque identifier.
    - `vm`               FK to the `lifecycle.Vm` being torn down.
    - `state`            one of `DecommissionState`.
    - `eol_ack_verified` set once the guest-signed EOL ack has been
                          verified.
    - `forced`           `True` iff `CryptoErasing` was reached via
                          an EOL-ack timeout (forced reclaim, §24) —
                          crypto-erase runs either way; `forced`
                          records that the miner never acked.
    - `quarantine_node_id`
                          set to the VM's host on a forced reclaim
                          (§13 quarantine — suspected ghost load).
    - `reason`           operator-facing string on `Failed`.
    - `phase_started_at`/`decided_by`/`version` — as `MigrationJob`.

    Constraints: partial unique on `vm` for non-terminal states;
    `terminal ⇒ finished_at IS NOT NULL` (DB CHECK).
    """

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    job_id = models.CharField(max_length=64, unique=True)
    vm = models.ForeignKey(
        "lifecycle.Vm",
        on_delete=models.PROTECT,
        related_name="decommission_jobs",
    )
    state = models.CharField(
        max_length=32,
        choices=DecommissionState.choices,
        default=DecommissionState.DRAINING,
    )
    eol_ack_verified = models.BooleanField(default=False)
    forced = models.BooleanField(default=False)
    quarantine_node_id = models.CharField(max_length=64, blank=True, default="")
    reason = models.CharField(max_length=256, blank=True, default="")
    phase_started_at = models.DateTimeField()
    started_at = models.DateTimeField(auto_now_add=True)
    finished_at = models.DateTimeField(null=True, blank=True)
    # When THIS job's §24 erase step (the per-VM Transit key destroys +
    # KV deletes, `effects.crypto_erase_kek_transit`) completed. From here
    # on the guest has no business running, so any frame it still sends is
    # a ZOMBIE signal (`apps.lifecycle.zombie`). The idempotency store also
    # knows the step ran, but it is a TTL'd shell-out — not something the
    # per-frame ingest path can consult.
    #
    # ⚠️ It records that HIPPIUS'S keys are gone. Whether that made the
    # tenant's DISK unreadable is `data_death`: for an M2 (`customer`) VM
    # Hippius never held the disk key, so this stamp is NOT a disk
    # crypto-erase — only the customer's guardian can do that.
    kek_erased_at = models.DateTimeField(null=True, blank=True)
    # What the erase step achieved for the tenant's DATA (`DataDeath`),
    # set with `kek_erased_at`: `crypto-erased` (M0/M1 — the Transit key
    # that wraps the disk KEK / `share_H` is destroyed, the disk can never
    # be opened again) or `customer-erase-required` (M2 — the disk key is
    # the customer's; Hippius deleted what it stores, and only
    # `guardian erase <vm>` crypto-erases). "" until the step ran.
    data_death = models.CharField(max_length=32, blank=True, default="", db_default="")
    # Where the VM was (`vm.host`, a `MinerIdentity.miner_id`) when THIS job
    # erased it — captured before `_destroy_vm` clears `vm.host`. The miner
    # a later zombie frame is attributed to when the frame names no relay:
    # after a §25 move it is the DESTINATION, which the launch record the
    # destroy resolver falls back to can no longer name.
    erase_host = models.CharField(max_length=128, blank=True, default="")
    # The KBS decommission fence's progress for THIS job (`KbsFence`), and
    # when it last moved. Only ever written with `VALI_KBS_FENCE_ENABLED`.
    kbs_fence = models.CharField(max_length=16, choices=KbsFence.choices, blank=True, default="")
    kbs_fence_at = models.DateTimeField(null=True, blank=True)
    decided_by = models.ForeignKey(
        "identity.ServiceClient",
        on_delete=models.PROTECT,
        related_name="decommission_jobs",
    )
    version = models.PositiveBigIntegerField(default=1)

    class Meta:
        ordering = ["-started_at"]
        indexes = [
            models.Index(fields=["state"]),
            models.Index(fields=["kbs_fence"]),
        ]
        constraints = [
            models.UniqueConstraint(
                fields=["vm"],
                condition=~models.Q(state__in=["done", "failed"]),
                name="orchestration_one_active_decommission_per_vm",
            ),
            models.CheckConstraint(
                name="orchestration_decommission_terminal_finished",
                condition=(
                    ~models.Q(state__in=["done", "failed"]) | models.Q(finished_at__isnull=False)
                ),
            ),
        ]

    def __str__(self) -> str:
        return f"DecommissionJob {self.job_id} (vm={self.vm_id}, {self.state})"


class MeasurementLedger(models.Model):
    """#587 Phase 3 — append-only audit trail of every pinned SNP launch
    digest.

    One row is written per successful §22 auto-pin (`launch_vm` step 6):
    the launch measurement that was admitted into the allowlist, the
    miner CHIP_ID (`platform_id`) + `node_id` it was pinned for, and the
    allowlist epoch/sha it landed at. Surfaced fleet-wide at
    `GET /v1/admin/audit/measurements` for audit + the "which firmware
    emits what measurement" diagnostics (cf. the Turin v4 / reported-tcb
    investigation).

    Append-only: never updated or deleted. The write is best-effort — an
    audit-ledger failure must never fail a launch (the launch's own KBS
    pin is the authoritative record; this is the queryable mirror).
    """

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    vm_id = models.CharField(max_length=256, db_index=True)
    # The 96-hex SNP launch digest that was pinned (the measurement).
    launch_digest_hex = models.CharField(max_length=96, db_index=True)
    # The miner's AMD CHIP_ID (hex) — the "which chip/firmware" axis.
    # Blank if the launch did not carry one.
    platform_id = models.CharField(max_length=128, blank=True, default="", db_index=True)
    # The §23 compute node_id the pin was for.
    node_id = models.CharField(max_length=64, blank=True, default="")
    allowlist_epoch = models.BigIntegerField()
    allowlist_sha256 = models.CharField(max_length=64, blank=True, default="")
    # The §22 trust class the entry was pinned under (`tenant` /
    # `host_attestor`, mirroring `kbs_core::snp::AllowlistClass`). Blank on
    # rows written before the column existed. The allowlist carry-forward
    # (`allowlist_pin._carry_forward_classes`) DERIVES the class from the
    # table it enumerated the measurement from and uses this column only as
    # a VETO — a recorded class that disagrees with the derived one fails
    # the pin closed rather than silently re-emitting a `host_attestor`
    # measurement as `tenant`.
    measurement_class = models.CharField(max_length=32, blank=True, default="")
    # What THIS launch was measured for (`apps.telemetry.guest_resources`
    # judges the guest's attested resources against the launch that
    # produced the measurement, not against whatever the VM is now):
    # the flavor whose vCPU count the digest folds, and whether the
    # measured cmdline asked the guest to attest its resources
    # (`hippius.attest_resources=1`) and to accept all of its memory at
    # boot (`accept_memory=eager`). Blank / false on rows written before.
    flavor = models.CharField(max_length=32, blank=True, default="", db_default="")
    attests_resources = models.BooleanField(default=False, db_default=False)
    accepts_memory_eagerly = models.BooleanField(default=False, db_default=False)
    # When the launch this pin was for was ACCEPTED by the miner (the domain
    # was created) — NULL for a pin whose launch failed after the pin, and
    # on rows written before the column. Only an accepted launch supersedes
    # the VM's earlier ones (`guest_resources`): a failed relaunch attempt
    # must never make a still-running guest look stale.
    launched_at = models.DateTimeField(null=True, blank=True, default=None)
    # The measurement is vali's OWN recompute of the boot it built (C2
    # ENFORCE, no operator override) — not the miner's preflight report.
    # A guest upgrade's gate only ever accepts such a pin.
    recomputed = models.BooleanField(default=False, db_default=False)
    # The caller's reference for the launch this pin was for (a guest
    # upgrade's `GuestUpgradeAttempt.id`): links an attempt to ITS pin
    # explicitly. Blank for every other launch.
    launch_ref = models.CharField(
        max_length=64, blank=True, default="", db_default="", db_index=True
    )
    # When an allowlist install that no longer carried this measurement —
    # because a later launch of the VM was accepted — reached the KBS
    # (`allowlist_pin.evict_superseded_measurements`). From then on no
    # ticket of this launch can release a key. NULL while it is still
    # carried (or still waiting for that install). `evicted_epoch` is that
    # install's allowlist epoch — it advanced the KBS HWM, so the next pin
    # starts past it (`allowlist_pin._installed_epoch_floor`).
    evicted_at = models.DateTimeField(null=True, blank=True, default=None)
    evicted_epoch = models.BigIntegerField(null=True, blank=True, default=None)
    # When the KBS made this launch the VM's current one AT REGISTER (its
    # ticket carried the `supersede` perm and the register was accepted):
    # every earlier launch's ticket has been refused since. A resize stops
    # asking for `supersede` once a register after its start got this far
    # (`resize._superseded`). NULL for a launch that did not supersede.
    superseded_at_register = models.DateTimeField(null=True, blank=True, default=None)
    pinned_at = models.DateTimeField(auto_now_add=True, db_index=True)

    class Meta:
        ordering = ["-pinned_at"]

    def __str__(self) -> str:
        return (
            f"MeasurementLedger {self.launch_digest_hex[:12]}… "
            f"vm={self.vm_id} epoch={self.allowlist_epoch}"
        )


class WebhookDeliveryState(models.TextChoices):
    PENDING = "pending", "Pending"
    DELIVERED = "delivered", "Delivered"
    FAILED = "failed", "Failed"


class WebhookDelivery(models.Model):
    """#587 Phase 3 — an outbound job-event webhook, queued + delivered
    by `vali_webhook_tick`.

    The upstream product API registers ONE callback URL + HMAC secret
    (via `VALI_WEBHOOK_URL` / `VALI_WEBHOOK_SECRET`, both operator-set —
    no dev default). On a terminal job transition (launch
    succeeded/failed today) one row is enqueued `pending`; the worker
    POSTs the canonical JSON body signed `X-Hippius-Signature:
    sha256=<hmac>` and CASes the row `delivered` on a 2xx, else bumps
    `attempts` + schedules a backoff retry until `max_attempts`, then
    `failed`. Append-only audit: every attempt outcome is on the row.

    Enqueue is best-effort + fail-open — a webhook failure must NEVER
    affect the job itself (the job's own state is authoritative; the
    webhook is a courtesy notification the upstream can also poll for).
    """

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    # e.g. "launch.succeeded" / "launch.failed".
    event = models.CharField(max_length=64, db_index=True)
    job_id = models.CharField(max_length=64, db_index=True)
    vm_id = models.CharField(max_length=256, blank=True, default="")
    # The canonical JSON event body (also what the HMAC is computed over).
    payload = models.JSONField()
    state = models.CharField(
        max_length=16,
        choices=WebhookDeliveryState.choices,
        default=WebhookDeliveryState.PENDING.value,
        db_index=True,
    )
    attempts = models.PositiveIntegerField(default=0)
    max_attempts = models.PositiveIntegerField(default=8)
    next_attempt_at = models.DateTimeField(db_index=True)
    last_status = models.IntegerField(null=True, blank=True)
    last_error = models.CharField(max_length=256, blank=True, default="")
    version = models.PositiveBigIntegerField(default=1)
    created_at = models.DateTimeField(auto_now_add=True)
    delivered_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ["next_attempt_at"]
        indexes = [
            models.Index(fields=["state", "next_attempt_at"]),
        ]

    def __str__(self) -> str:
        return f"WebhookDelivery {self.event} job={self.job_id} ({self.state})"


class KbsAuditLog(models.TextChoices):
    """Which KBS hash chain an entry came from (`GET /v1/admin/audit?log=`)."""

    RELEASE = "release", "Release decisions"
    ADMIN = "admin", "Admin operations"


class KbsAuditEntry(models.Model):
    """One record of a KBS hash-chained audit log, copied out of the KBS
    CVM by `apps.orchestration.kbs_audit` (the KBS keeps its chains on an
    emptyDir the host cannot read and a restart wipes).

    `body_cbor` / `sha256` / `prev_hash` are the KBS's persisted bytes,
    verbatim; the ingester re-verifies the chain before storing and a
    record that does not verify is STILL stored, with `chain_ok=False`
    and the reason in `chain_error` — a break is evidence, never dropped.

    `kbs_epoch` is the chain's genesis hash (`sha256` of its `seq=0`
    record): each KBS life starts a new chain at `seq=0`, so `(log,
    kbs_epoch, seq)` names a record uniquely across restarts.

    The decoded columns (`op`, `vm_id`, …) are a query index over
    `body_cbor`, filled at ingest; `body_cbor` stays the authority.

    Retention: kept forever by default (`VALI_KBS_AUDIT_RETENTION_DAYS=0`);
    a positive value prunes verified rows older than that, never a
    `chain_ok=False` one.
    """

    log = models.CharField(max_length=16, choices=KbsAuditLog.choices)
    kbs_epoch = models.CharField(max_length=64)
    seq = models.BigIntegerField()
    body_cbor = models.BinaryField()
    sha256 = models.CharField(max_length=64)
    prev_hash = models.CharField(max_length=64)
    fetched_at = models.DateTimeField()
    chain_ok = models.BooleanField(default=True, db_index=True)
    chain_error = models.CharField(max_length=256, blank=True, default="")

    # ── decoded from body_cbor (query index) ──
    # The KBS's clock at append time (`now_unix`).
    event_unix = models.BigIntegerField(null=True, blank=True)
    # Admin: the op ("register-vm", …); release: "release".
    op = models.CharField(max_length=64, blank=True, default="")
    # The ticket's vm_id, or (admin, pre-parse failure) the URL's.
    vm_id = models.CharField(max_length=64, blank=True, default="", db_index=True)
    ticket_id = models.CharField(max_length=128, blank=True, default="")
    # The FULL reason: rollback rows carry their detail here (e.g.
    # `timeline_from=… timeline_to=…`, the arm's ticket binding), well past
    # any short column width.
    reason = models.TextField(blank=True, default="")
    # Release only.
    granted = models.BooleanField(null=True, blank=True)
    # Admin only.
    status_code = models.IntegerField(null=True, blank=True)
    applied = models.BooleanField(null=True, blank=True)
    peer_san = models.CharField(max_length=256, blank=True, default="")

    class Meta:
        ordering = ["log", "fetched_at", "seq"]
        constraints = [
            models.UniqueConstraint(
                fields=["log", "kbs_epoch", "seq"], name="kbs_audit_entry_unique_seq"
            ),
        ]
        indexes = [
            # The guest report's T4 read: refused releases / keepalives by
            # time (`apps.orchestration.guest_report`). Partial: refusals
            # are a sliver of a log every keepalive grant appends to.
            models.Index(
                fields=["event_unix"],
                name="kbs_audit_refused_idx",
                condition=models.Q(log="release", granted=False),
            ),
            models.Index(fields=["vm_id", "event_unix"]),
            models.Index(fields=["log", "event_unix"]),
        ]

    def __str__(self) -> str:
        return f"KbsAuditEntry {self.log}@{self.kbs_epoch[:12]}#{self.seq}"


class KbsAuditCursor(models.Model):
    """How far vali has ingested one KBS chain: the epoch (genesis hash)
    and the last `(seq, sha256(body))` stored. The next page is asked
    from `last_seq`, and its first record must chain onto `last_hash`.

    `broken_at_seq` is the first record of this epoch that did not
    verify. Once set, every later record of the epoch is stored as
    unverified (`chain_ok=False`): nothing is trusted by chaining onto an
    unverified predecessor. A new epoch (KBS restart) clears it.

    `head_seq` / `checked_at` are the KBS head of this epoch and when an
    ingest run last read it to the end of its budget: `head_seq - last_seq`
    is how far vali is behind, `checked_at` whether the ingest runs at all
    (the `hippius_kbs_audit_*` gauges of the guest report)."""

    log = models.CharField(max_length=16, choices=KbsAuditLog.choices, primary_key=True)
    kbs_epoch = models.CharField(max_length=64)
    last_seq = models.BigIntegerField()
    last_hash = models.CharField(max_length=64)
    broken_at_seq = models.BigIntegerField(null=True, blank=True)
    head_seq = models.BigIntegerField(null=True, blank=True)
    checked_at = models.DateTimeField(null=True, blank=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self) -> str:
        return f"KbsAuditCursor {self.log}@{self.kbs_epoch[:12]}#{self.last_seq}"


class KbsAuditAnomaly(models.Model):
    """A KBS audit-chain break that has no served record of its own to
    flag: a chain CUT (same epoch, head below what vali holds), a head
    REWRITE, an EQUIVOCATION (different bytes for a seq vali already
    holds), a WITHHELD record (empty page below the advertised head), a
    HEAD-MISMATCH, or a GENESIS-MISMATCH (a "new epoch" whose genesis is
    not the hash of the record it serves as `seq=0`). Written by
    `apps.orchestration.kbs_audit`; every one is also an ERROR line.

    One kind is NOT a break: TORN-TAIL-TRUNCATED — the KBS truncated a torn
    trailing record at open (a crash mid-append) and chained an
    `audit-truncated` record in its place, at `seq`. A WARNING line.

    One row per `(log, kbs_epoch, kind, seq, observed)`; seeing it again
    bumps `count` / `last_seen_at`. `seq=-1` ⇔ not tied to a seq. Never
    pruned.
    """

    log = models.CharField(max_length=16, choices=KbsAuditLog.choices)
    kbs_epoch = models.CharField(max_length=64)
    kind = models.CharField(max_length=32)
    seq = models.BigIntegerField()
    observed = models.CharField(max_length=64, blank=True, default="")
    detail = models.CharField(max_length=256, blank=True, default="")
    count = models.PositiveIntegerField(default=1)
    first_seen_at = models.DateTimeField()
    last_seen_at = models.DateTimeField()

    class Meta:
        ordering = ["first_seen_at"]
        constraints = [
            models.UniqueConstraint(
                fields=["log", "kbs_epoch", "kind", "seq", "observed"],
                name="kbs_audit_anomaly_unique",
            ),
        ]

    def __str__(self) -> str:
        return f"KbsAuditAnomaly {self.kind} {self.log}@{self.kbs_epoch[:12]}#{self.seq}"


class ResizeState(models.TextChoices):
    """VM resize job lifecycle (`apps.orchestration.resize`).

    - `pending`      admitted; the next tick reserves and starts.
    - `stopping`     the guest is being stopped through the power API.
    - `migrating`    the new flavor did not fit on the VM's miner: a §25
                     migration (`migration_job`) is moving it to one where
                     it does; the in-place steps run there afterwards.
    - `relaunching`  relaunched at the new flavor on its miner; waiting for
                     the domain to run and the guest to signal.
    - `rolling_back` a failure BEFORE the new-flavor relaunch was accepted:
                     the VM is being put back as it was (old flavor, old
                     power state).
    - `done` / `failed` terminal. A failed job's `reason` says why and
                     `rolled_back` whether the VM is back as it was.
    """

    PENDING = "pending", "Pending"
    STOPPING = "stopping", "Stopping"
    MIGRATING = "migrating", "Migrating"
    RELAUNCHING = "relaunching", "Relaunching"
    ROLLING_BACK = "rolling_back", "Rolling back"
    DONE = "done", "Done"
    FAILED = "failed", "Failed"


TERMINAL_RESIZE_STATES: frozenset[str] = frozenset(
    {ResizeState.DONE.value, ResizeState.FAILED.value}
)


class ResizeJob(models.Model):
    """One CPU/RAM resize of a VM: `from_flavor` → `to_flavor`, data disk
    unchanged. Driven by `vali_orchestration_tick` one bounded step per
    tick, CAS on `(id, version, state)` like the §24/§25 jobs.

    Field-by-field:

    - `job_id`            public opaque identifier.
    - `vm`                the VM being resized.
    - `from_flavor` / `to_flavor`
                          the flavor it ran at when the job started, and
                          the one it is resized to.
    - `node_id`           the miner (`Vm.host`) the in-place steps run on —
                          the VM's host at start, the destination once a
                          migration moved it.
    - `prior_power_state` `running` / `stopped` when the job began. A
                          stopped VM is resized on the books only and stays
                          stopped (its next start boots the new flavor); a
                          failure puts a running VM back running.
    - `migration_job`     the §25 job a `migrating` resize started.
    - `reserved`          the VM's placement already names `to_flavor` (the
                          capacity swap happened); a rollback swaps it back.
    - `attempts` / `attempted_at`
                          power dispatches claimed in the current state.
    - `relaunched_at`     the new-flavor relaunch was ACCEPTED — the point of
                          no rollback: from here a failure leaves the VM at
                          the new flavor and says so.
    - `measurement_before` the launch record's measurement before the
                          relaunch; `done` waits for the record to hold the
                          relaunch's own.
    - `rolled_back`       a failed job put the VM back as it was.
    - `reason`            operator-facing failure slug + detail on `failed`.

    Constraints: at most one non-terminal resize per VM; terminal ⇒
    `finished_at`.
    """

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    job_id = models.CharField(max_length=64, unique=True)
    vm = models.ForeignKey(
        "lifecycle.Vm",
        on_delete=models.PROTECT,
        related_name="resize_jobs",
    )
    from_flavor = models.CharField(max_length=32)
    to_flavor = models.CharField(max_length=32)
    node_id = models.CharField(max_length=64)
    prior_power_state = models.CharField(max_length=16)
    state = models.CharField(
        max_length=32, choices=ResizeState.choices, default=ResizeState.PENDING
    )
    migration_job = models.ForeignKey(
        MigrationJob,
        on_delete=models.PROTECT,
        null=True,
        blank=True,
        related_name="resize_jobs",
    )
    reserved = models.BooleanField(default=False)
    # Power dispatches (stop / relaunch / rollback start) claimed in the
    # CURRENT state, and when the last one was — counted BEFORE dispatching,
    # so a crash after it still paces the retry instead of re-sending at once.
    attempts = models.PositiveIntegerField(default=0)
    attempted_at = models.DateTimeField(null=True, blank=True)
    relaunched_at = models.DateTimeField(null=True, blank=True)
    # The measurement the launch record held before the new-size relaunch:
    # the record is settled only once it holds another one (the relaunch's).
    measurement_before = models.CharField(max_length=128, blank=True, default="")
    rolled_back = models.BooleanField(default=False)
    reason = models.CharField(max_length=256, blank=True, default="")
    phase_started_at = models.DateTimeField()
    started_at = models.DateTimeField(auto_now_add=True)
    finished_at = models.DateTimeField(null=True, blank=True)
    decided_by = models.ForeignKey(
        "identity.ServiceClient",
        on_delete=models.PROTECT,
        related_name="resize_jobs",
    )
    version = models.PositiveBigIntegerField(default=1)

    class Meta:
        ordering = ["-started_at"]
        indexes = [models.Index(fields=["state"])]
        constraints = [
            models.UniqueConstraint(
                fields=["vm"],
                condition=~models.Q(state__in=["done", "failed"]),
                name="orchestration_one_active_resize_per_vm",
            ),
            models.CheckConstraint(
                name="orchestration_resize_terminal_finished",
                condition=(
                    ~models.Q(state__in=["done", "failed"]) | models.Q(finished_at__isnull=False)
                ),
            ),
        ]

    def __str__(self) -> str:
        return (
            f"ResizeJob {self.job_id} (vm={self.vm_id} "
            f"{self.from_flavor}→{self.to_flavor}, {self.state})"
        )


# ─── guest components rollout (docs/design/guest-component-rollout.md) ──


class GuestComponentRelease(models.Model):
    """One guest components release: a version of every Hippius file a
    golden guest runs, cut from one commit
    (`scripts/guest/build-guest-release.sh`). Immutable once registered;
    `withdrawn_at` stops further upgrades onto it (VMs already on it stay).

    `security_epoch` is the floor a VM moves to when it upgrades onto this
    release: vali never launches the VM on a lower-epoch build again
    (`services.guest_components.check_launch_epoch`)."""

    version = models.PositiveIntegerField(primary_key=True)
    commit = models.CharField(max_length=40)
    security_epoch = models.PositiveIntegerField()
    squashfs_sha256 = models.CharField(max_length=64)
    # The release member per initramfs family (`{family: sha256}`), filled
    # by the first build of each family and immutable from then on.
    cpio_sha256 = models.JSONField(default=dict)
    # The health checks the release's keepalive attests
    # (`hippius_types::live_attestation::components_health`); 0 = no
    # health leg, so no gate condition 4 for a launch of it.
    health_mask = models.PositiveBigIntegerField(default=0, db_default=0)
    registered_at = models.DateTimeField(auto_now_add=True)
    withdrawn_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ["-version"]

    def __str__(self) -> str:
        return f"GuestComponentRelease v{self.version} (epoch {self.security_epoch})"


class GuestInitrdBuild(models.Model):
    """A release appended to ONE golden base's initrd
    (`scripts/guest/guest-initrd-build.sh`): the prefix a VM on that base
    is moved to. The kernel, rootfs.img, rootfs.verity and verity root
    hash are the base's own, unchanged; `base_initrd_sha256` is the initrd
    the release was appended to. All five are the base identity: an
    initrd-only rebuild of a bake (`scripts/tenant-initrd-rebuild.sh`) is
    another base, with its own build of each release. Immutable once
    registered."""

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    release = models.ForeignKey(
        GuestComponentRelease, on_delete=models.PROTECT, related_name="builds"
    )
    source_bake_id = models.CharField(max_length=64)
    family = models.CharField(max_length=32)
    kernel_sha256 = models.CharField(max_length=64)
    rootfs_img_sha256 = models.CharField(max_length=64)
    rootfs_verity_sha256 = models.CharField(max_length=64)
    verity_root_hash = models.CharField(max_length=64)
    base_initrd_sha256 = models.CharField(max_length=64)
    release_cpio_sha256 = models.CharField(max_length=64)
    initrd_sha256 = models.CharField(max_length=64, unique=True)
    s3_bucket = models.CharField(max_length=256)
    s3_key_prefix = models.CharField(max_length=512, unique=True)
    measurement = models.JSONField()
    registered_at = models.DateTimeField(auto_now_add=True)
    withdrawn_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ["-registered_at"]
        constraints = [
            models.UniqueConstraint(
                fields=[
                    "release",
                    "kernel_sha256",
                    "rootfs_img_sha256",
                    "rootfs_verity_sha256",
                    "verity_root_hash",
                    "base_initrd_sha256",
                ],
                name="orchestration_one_guest_build_per_release_and_base_initrd",
            )
        ]

    def __str__(self) -> str:
        return f"GuestInitrdBuild v{self.release_id} {self.s3_key_prefix}"


class VmGuestComponents(models.Model):
    """Per-VM guest components floor.

    - `required_epoch`  monotonic: raised to a target's security epoch when
                        an upgrade onto it is decided, BEFORE anything is
                        stopped or launched. Every launch path refuses a
                        build below it. Lowered only by the audited
                        `vali_guest_epoch_lower`.
    - `attested_epoch`  the epoch of the build the VM was last attested
                        live on by an upgrade job (reporting).
    - `history`         every change of `required_epoch`, newest last."""

    vm = models.OneToOneField(
        "lifecycle.Vm", on_delete=models.PROTECT, primary_key=True, related_name="guest_components"
    )
    required_epoch = models.PositiveIntegerField(default=0)
    attested_epoch = models.PositiveIntegerField(default=0)
    # Every change of `required_epoch`, newest last: `{at, from, to, by,
    # reason}` (a raise by an upgrade decision, or the audited lowering).
    history = models.JSONField(default=list)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self) -> str:
        return f"VmGuestComponents {self.vm_id} required={self.required_epoch}"


class VmTicketClock(models.Model):
    """The `issue_time` of the last launch ticket minted for a VM
    (`services.ticket_mint`). The KBS orders a VM's launches by it, in
    seconds, and keeps the current launch when a superseding ticket's
    `issue_time` is not strictly later: vali therefore mints at most one
    ticket per VM per second (docs/design/guest-component-rollout.md,
    "Ticket ordering")."""

    vm_id = models.CharField(max_length=256, primary_key=True)
    last_issue_time = models.BigIntegerField(default=0)

    def __str__(self) -> str:
        return f"VmTicketClock {self.vm_id} {self.last_issue_time}"


class GuestUpgradeState(models.TextChoices):
    """Guest upgrade job lifecycle (`apps.orchestration.guest_upgrade`).

    - `pending`       admitted; waits for `not_before` and no backup
                      running. Does not hold the VM yet (other operations
                      may run; everything is re-checked on leaving).
    - `stopping`      the guest is being stopped (power API, job-owned).
    - `launching`     the record names the target build; relaunching it.
    - `verifying`     relaunch accepted; waiting for a live attestation of
                      THIS launch's measurement.
    - `soaking`       attested; attestations must keep coming for the soak.
    - `rolling_back`  a forward launch of the previous set (only when its
                      epoch is at least the VM's required epoch).
    - `parking`       the job failed with an unverified boot possibly up:
                      it stops the domain and confirms it DOWN before
                      releasing the VM (`park_to` is the terminal state).
    - `done` / `rolled_back` / `failed` / `upgrade_blocked` / `cancelled`
                      terminal.
    """

    PENDING = "pending", "Pending"
    STOPPING = "stopping", "Stopping"
    LAUNCHING = "launching", "Launching"
    VERIFYING = "verifying", "Verifying"
    SOAKING = "soaking", "Soaking"
    ROLLING_BACK = "rolling_back", "Rolling back"
    PARKING = "parking", "Parking"
    DONE = "done", "Done"
    ROLLED_BACK = "rolled_back", "Rolled back"
    FAILED = "failed", "Failed"
    UPGRADE_BLOCKED = "upgrade_blocked", "Upgrade blocked"
    CANCELLED = "cancelled", "Cancelled"


TERMINAL_GUEST_UPGRADE_STATES: frozenset[str] = frozenset(
    {
        GuestUpgradeState.DONE.value,
        GuestUpgradeState.ROLLED_BACK.value,
        GuestUpgradeState.FAILED.value,
        GuestUpgradeState.UPGRADE_BLOCKED.value,
        GuestUpgradeState.CANCELLED.value,
    }
)

#: The states in which a guest upgrade OWNS the VM (its power, its launch
#: record): every other operation refuses while one of these is current.
#: `pending` does not hold it.
HOLDING_GUEST_UPGRADE_STATES: frozenset[str] = frozenset(
    {
        GuestUpgradeState.STOPPING.value,
        GuestUpgradeState.LAUNCHING.value,
        GuestUpgradeState.VERIFYING.value,
        GuestUpgradeState.SOAKING.value,
        GuestUpgradeState.ROLLING_BACK.value,
        GuestUpgradeState.PARKING.value,
    }
)


class GuestUpgradeLock(models.Model):
    """One row (`pk=1`) every decision that lets a guest upgrade take a VM
    locks FIRST (`guest_rollout.global_lock`): a job leaving `pending`, a
    rollout's tick, a rollout's creation, pause, resume or abort. One lock
    order (this row → a rollout row → a VM row) for all of them, and the
    one-per-miner and one-rollout-per-VM checks see a stable fleet."""

    id = models.PositiveSmallIntegerField(primary_key=True, default=1)

    def __str__(self) -> str:
        return "GuestUpgradeLock"


class GuestRolloutState(models.TextChoices):
    ACTIVE = "active", "Active"
    PAUSED = "paused", "Paused"
    ABORTED = "aborted", "Aborted"
    DONE = "done", "Done"


TERMINAL_GUEST_ROLLOUT_STATES: tuple[str, ...] = (
    GuestRolloutState.ABORTED.value,
    GuestRolloutState.DONE.value,
)


class GuestRollout(models.Model):
    """Move a set of VMs onto a guest components release in waves
    (`apps.orchestration.guest_rollout`, docs/design/guest-component-rollout.md).

    - `canary_vm_ids` wave 0, named by the operator (a throwaway per family,
                      then internal VMs); every later wave is a percentage
                      (`waves`) of the rest of the `scope`.
    - `scope`         `{vm_ids, tenant_ids, node_ids, bake_ids}` — each
                      optional, ANDed; VMs already on the release are out.
    - `members`       the scope's VMs when the rollout was created, minus the
                      canaries and the VMs already on the release (fixed;
                      `population` is their count).
    - `assigned`      `{"<wave>": [vm_id, ...]}` — the members a wave took,
                      fixed when the wave starts.
    - `skipped`       `{vm_id: {category, at}}` — VMs whose upgrade could not
                      be admitted (reported, never counted as upgraded).
    - `acknowledged_at` a resume after a stop: only outcomes after it stop
                      the rollout again.
    The rollout's progress IS its job rows (`GuestUpgradeJob.rollout`), so
    it resumes after any restart."""

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    rollout_id = models.CharField(max_length=64, unique=True)
    release = models.ForeignKey(
        GuestComponentRelease, on_delete=models.PROTECT, related_name="rollouts"
    )
    state = models.CharField(
        max_length=16, choices=GuestRolloutState.choices, default=GuestRolloutState.ACTIVE
    )
    canary_vm_ids = models.JSONField(default=list)
    scope = models.JSONField(default=dict)
    waves = models.JSONField(default=list)
    current_wave = models.PositiveSmallIntegerField(default=0)
    members = models.JSONField(default=list)
    assigned = models.JSONField(default=dict)
    population = models.PositiveIntegerField(default=0)
    skipped = models.JSONField(default=dict)
    wave_done_at = models.DateTimeField(null=True, blank=True)
    max_concurrent = models.PositiveSmallIntegerField(default=2)
    wave_pause_s = models.PositiveIntegerField(default=1800)
    max_failure_ratio = models.FloatField(default=0.1)
    not_before = models.DateTimeField(null=True, blank=True)
    paused_reason = models.CharField(max_length=256, blank=True, default="")
    acknowledged_at = models.DateTimeField(null=True, blank=True)
    decided_by = models.ForeignKey(
        "identity.ServiceClient", on_delete=models.PROTECT, related_name="guest_rollouts"
    )
    created_at = models.DateTimeField(auto_now_add=True)
    finished_at = models.DateTimeField(null=True, blank=True)
    version = models.PositiveBigIntegerField(default=1)

    class Meta:
        ordering = ["-created_at"]

    def __str__(self) -> str:
        return f"GuestRollout {self.rollout_id} v{self.release_id} {self.state}"


class GuestUpgradeJob(models.Model):
    """Move ONE VM onto a guest components build (`target`), the way a
    resize moves it to a flavor: stop, point the launch record at the
    target, a superseding relaunch, a live attestation of that launch's own
    measurement, a soak. Driven by the orchestration tick, CAS on
    `(id, version, state)`.

    - `previous_prefix` / `previous_initrd_sha256` the set the record named
      when the job started — what a rollback launches again.
    - `previous_epoch`  that set's security epoch (0 for a base initrd).
    - `not_before`      the job does not leave `pending` before it (the
                        tenant's maintenance window, set by the backend).
    - `start_requested` a power start of the VM was handed to this job.
    - `attempts` / `attempted_at` power dispatches claimed in the state.
    - `relaunched_at`   the current attempt's relaunch was accepted.
    - `measurement_before` the record's measurement before that relaunch.
    - `reason`          failure slug + detail.
    """

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    job_id = models.CharField(max_length=64, unique=True)
    vm = models.ForeignKey(
        "lifecycle.Vm", on_delete=models.PROTECT, related_name="guest_upgrade_jobs"
    )
    target = models.ForeignKey(GuestInitrdBuild, on_delete=models.PROTECT, related_name="jobs")
    previous_prefix = models.CharField(max_length=512)
    previous_initrd_sha256 = models.CharField(max_length=64)
    previous_epoch = models.PositiveIntegerField(default=0)
    node_id = models.CharField(max_length=64)
    prior_power_state = models.CharField(max_length=16)
    state = models.CharField(
        max_length=32, choices=GuestUpgradeState.choices, default=GuestUpgradeState.PENDING
    )
    not_before = models.DateTimeField()
    start_requested = models.BooleanField(default=False)
    attempts = models.PositiveIntegerField(default=0)
    attempted_at = models.DateTimeField(null=True, blank=True)
    relaunched_at = models.DateTimeField(null=True, blank=True)
    measurement_before = models.CharField(max_length=128, blank=True, default="")
    recover_used = models.BooleanField(default=False)
    # `parking`: the terminal state the job takes once the domain is DOWN.
    park_to = models.CharField(max_length=32, blank=True, default="")
    # The live attestation that passed the gate (verifying → soaking): the
    # soak of a release with the health leg holds every later sample to
    # its keepalive instance and failure count. NULL before / without it.
    gate_verified_at_unix = models.BigIntegerField(null=True, blank=True, default=None)
    gate_instance = models.BigIntegerField(null=True, blank=True, default=None)
    gate_unhealthy_ticks = models.BigIntegerField(null=True, blank=True, default=None)
    # The operator who released a PARKING job without a confirmed DOWN
    # (`guest_upgrade.release_parked`) — blank otherwise.
    released_by = models.CharField(max_length=128, blank=True, default="")
    reason = models.CharField(max_length=256, blank=True, default="")
    # Why the target did not come up, machine-readable
    # (`guest_upgrade.OUTCOMES`: `health-failed`, `no-sample`, ...); blank
    # while it has not failed. `reason` carries the detail.
    outcome = models.CharField(max_length=32, blank=True, default="", db_default="")
    # The `upgrade_blocked` job this one retries (the VM's latest job when it
    # was admitted): it may restart the VM that job left stopped, and a
    # retry of the SAME build keeps that job's previous set as its own.
    retry_of = models.ForeignKey(
        "self", on_delete=models.PROTECT, null=True, blank=True, related_name="retries"
    )
    # The audited operator recoveries of a failed / blocked job
    # (`guest_upgrade.recover_start_on_target`): `{at, by, action, reason,
    # attempt, result}`, newest last.
    recoveries = models.JSONField(default=list, db_default=[])
    phase_started_at = models.DateTimeField()
    started_at = models.DateTimeField(auto_now_add=True)
    finished_at = models.DateTimeField(null=True, blank=True)
    decided_by = models.ForeignKey(
        "identity.ServiceClient", on_delete=models.PROTECT, related_name="guest_upgrade_jobs"
    )
    # The rollout (and its wave) that admitted the job; NULL for a job
    # scheduled on its own (`POST /v1/vm/<vm_id>/guest-upgrade`).
    rollout = models.ForeignKey(
        GuestRollout, on_delete=models.PROTECT, null=True, blank=True, related_name="jobs"
    )
    wave = models.PositiveSmallIntegerField(null=True, blank=True)
    version = models.PositiveBigIntegerField(default=1)

    class Meta:
        ordering = ["-started_at"]
        indexes = [models.Index(fields=["state"])]
        constraints = [
            models.UniqueConstraint(
                fields=["vm"],
                condition=~models.Q(
                    state__in=["done", "rolled_back", "failed", "upgrade_blocked", "cancelled"]
                ),
                name="orchestration_one_active_guest_upgrade_per_vm",
            ),
            models.CheckConstraint(
                name="orchestration_guest_upgrade_terminal_finished",
                condition=(
                    ~models.Q(
                        state__in=["done", "rolled_back", "failed", "upgrade_blocked", "cancelled"]
                    )
                    | models.Q(finished_at__isnull=False)
                ),
            ),
        ]

    def __str__(self) -> str:
        return f"GuestUpgradeJob {self.job_id} (vm={self.vm_id} → v{self.target_id}, {self.state})"


class GuestUpgradeAttemptKind(models.TextChoices):
    UPGRADE = "upgrade", "Upgrade"
    RECOVER = "recover", "Recover"
    ROLLBACK = "rollback", "Rollback"
    # An operator's start of a failed / blocked job's target
    # (`guest_upgrade.recover_start_on_target`) — never gated, recorded.
    OPERATOR_START = "operator_start", "Operator start"


class GuestUpgradeAttempt(models.Model):
    """One launch a guest upgrade job dispatched, written BEFORE the
    dispatch. `prefix` / `initrd_sha256` is the set it launches;
    `supersede` whether it asked the KBS to make it current at register.
    `accepted_at` the miner accepted it; `measurement` the launch's own
    measurement (from the launch record / measurement ledger once
    accepted) — the one the gate wants attested live."""

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    job = models.ForeignKey(GuestUpgradeJob, on_delete=models.CASCADE, related_name="attempt_rows")
    kind = models.CharField(max_length=16, choices=GuestUpgradeAttemptKind.choices)
    prefix = models.CharField(max_length=512)
    initrd_sha256 = models.CharField(max_length=64)
    supersede = models.BooleanField(default=False)
    started_at = models.DateTimeField(auto_now_add=True)
    accepted_at = models.DateTimeField(null=True, blank=True)
    measurement = models.CharField(max_length=128, blank=True, default="")
    # The refusal the power API answered for it, while it is still open: an
    # answer lost on the way back may hide a launch that landed, so it only
    # becomes the outcome once the dispatch settled with the domain DOWN.
    answer = models.CharField(max_length=64, blank=True, default="")
    answered_at = models.DateTimeField(null=True, blank=True)
    outcome = models.CharField(max_length=64, blank=True, default="")

    class Meta:
        ordering = ["started_at"]

    def __str__(self) -> str:
        return f"GuestUpgradeAttempt {self.kind} job={self.job_id} {self.outcome or 'open'}"
