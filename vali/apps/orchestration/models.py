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

    DRAINING = "draining", "Draining"
    QUIESCING = "quiescing", "Quiescing"
    SNAPSHOTTING = "snapshotting", "Snapshotting"
    UPLOADING = "uploading", "Uploading"
    FENCING = "fencing", "Fencing"
    AWAITING_SOURCE_ACK = "awaiting_source_ack", "Awaiting source ack"
    DEST_ACTIVATING = "dest_activating", "Dest activating"
    DONE = "done", "Done"
    FAILED = "failed", "Failed"


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
    # is forward-only and refuses every non-`Active` current state), so the
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
                    ~models.Q(state__in=["done", "failed"])
                    | models.Q(finished_at__isnull=False)
                ),
            ),
        ]

    def __str__(self) -> str:
        return (
            f"MigrationJob {self.job_id} (vm={self.vm_id} "
            f"{self.source_node_id}→{self.dest_node_id}, {self.state})"
        )


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

    §20 secret discipline: NO plaintext secret is stored on this row.
    The cloud-init `userdata` is staged to Vault at POST and referenced
    by `userdata_vault_path` + `userdata_vault_version`; the LUKS KEK is
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
    - `attempts` — total relaunch attempts, capped so a VM that will not
      come back is not relaunched forever.
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
                    ~models.Q(state__in=["done", "failed"])
                    | models.Q(finished_at__isnull=False)
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
