"""§23 scheduler models — `Placement` + `MinerCapacity`.

Spec of record: ARCHITECTURE.md §23 (trustless scheduling) / §13
(DoS / admission control, drain + quarantine).

vali's scheduler chooses **placement among on-chain-eligible miners**
— it never derives schedulability from a miner's self-report (§23:
"a hostile miner's self-reported capacity/health is adversarial").
The two models here are:

- `MinerCapacity` — a local mirror cache of the per-miner on-chain
  signals (`MinerStatus`, the §23 reward weight reused as a v1
  "quality" score) plus the operator-managed `capacity_slots`
  admission bound. Refreshed from `pallet-compute-scoring` via the
  `read-miner-status` Rust shell-out. v1 carries **no detailed
  hardware specs** (locked single-operator scope, issue #1 Q13).
- `Placement` — the authoritative off-chain operator log of which
  VM the scheduler bound to which miner. §23 v1: "VM→node placement
  is an off-chain operator log (not committed on-chain)".

Optimistic concurrency: `Placement` carries a `version` counter
bumped on every transition, and a partial unique index guarantees
**at most one active (Pending|Bound) placement per VM** — that index
is what closes the "two schedulers race on the same vm_id" window
at the database, independent of the application-level pre-check.
"""

from __future__ import annotations

import uuid

from django.db import models


class MinerStatusMirror(models.TextChoices):
    """Local mirror of `pallet_compute_scoring::MinerStatus`.

    Pinned strings (not auto-numbered) — the value mirrors the
    on-chain enum the `read-miner-status` shell-out emits.
    """

    ACTIVE = "active", "Active"
    QUARANTINED = "quarantined", "Quarantined"
    DECOMMISSIONED = "decommissioned", "Decommissioned"


class PlacementStatus(models.TextChoices):
    """`Placement` lifecycle.

    `Pending` is the initial state on `POST /v1/scheduler/place`.
    `/bind` (root-only) promotes Pending→Bound once the KBS release
    is confirmed; `/fail` (root-only) marks Pending→Failed; the
    continuous re-eval loop marks Bound→Failed when a miner leaves
    `Active` state (§13 drain/quarantine). `Failed` is terminal —
    re-placement is a fresh `Placement` row.

    `Migrated` is the OTHER terminal close: the VM left this miner
    for a §25 destination, and a fresh `Placement` row was opened on
    that destination in the SAME transaction as the `Vm.host` CAS
    (`orchestration.service._activate_dest_vm`). It is deliberately
    NOT `Failed`:

    - `Failed` feeds the scheduler's circuit-breaker
      (`service.recent_failures_by_node` counts FAILED rows in a
      look-back window), so closing the source as Failed would
      penalise a miner that did nothing wrong — a graceful-exit
      drain would emit one "failure" per VM it hands over and then
      route new work away from every healthy miner it ever handed a
      VM to.
    - the two states answer different questions in the audit log:
      "this placement did not work out" vs "this placement ended
      because the VM moved, and here is the row it moved to".

    Both terminal states leave `ACTIVE_PLACEMENT_STATES`, so a
    migrated-away placement stops consuming the source's admission
    slot the instant the destination takes over.
    """

    PENDING = "pending", "Pending"
    BOUND = "bound", "Bound"
    FAILED = "failed", "Failed"
    MIGRATED = "migrated", "Migrated away"


# Statuses that count as "active" — a VM may hold at most one
# placement in either of these at a time, and these are the rows
# admission/anti-affinity accounting iterates. Kept here (not in
# views) so the model constraint + the service layer read the same
# source.
ACTIVE_PLACEMENT_STATES: frozenset[str] = frozenset(
    {PlacementStatus.PENDING.value, PlacementStatus.BOUND.value}
)


class MinerCapacity(models.Model):
    """Mirror cache of a single registered compute miner.

    Field-by-field:

    - `miner_node_id`   the §23 compute `node_id` — 32-byte ed25519
                        key, stored as 64-char lowercase hex (unique).
    - `status`          mirror of the on-chain `MinerStatus` — only
                        `active` miners are scheduling candidates.
    - `quality`         the §23 reward weight for the miner this
                        epoch (`EpochWeights`), reused as the v1
                        merit/"quality" signal. A `u128` on-chain —
                        stored as a 39-digit `DecimalField` because
                        it exceeds `BIGINT`. `0` = not scored / no
                        reward this epoch.
    - `capacity_slots`  admission bound (§23 "(a) admission bounded
                        by proven capacity") AND the operator UPPER
                        CLAMP on the dynamic capacity. v1 has no
                        detailed hardware specs on-chain, so this is an
                        operator-managed cap (default
                        `VALI_SCHEDULER_DEFAULT_CAPACITY_SLOTS`),
                        **preserved across chain refreshes**. When the
                        trusted-hardware anchors below are UNSET this is
                        the whole story (flat static cap, legacy
                        behaviour); when they are set it is the ceiling
                        the resource-derived dynamic capacity fills up
                        to (a miner is always boundable BELOW its
                        hardware by lowering this).
    - `total_memory_mb` / `total_cpus`
                        the OPERATOR-REGISTERED trusted hardware anchor
                        (NULL until an operator seeds it). This is the
                        immovable ceiling INPUT for the dynamic
                        capacity: it is set by trusted operator config,
                        **never** derived from a miner's self-report. A
                        miner cannot raise it by lying. NULL ⇒ the row
                        falls back to the flat `capacity_slots` (no
                        regression for un-seeded miners).
    - `reported_memory_available_mib` / `reported_at`
                        the LAST self-reported free RAM (MiB) a miner
                        put in its §K heartbeat, plus when it landed.
                        UNTRUSTED — used ONLY as a DOWN-ONLY throttle on
                        the vali-computed free capacity
                        (`effective_free = min(computed_free,
                        reported_free)`), and clamped/flagged when it
                        claims MORE free than physically possible given
                        the VMs vali placed. It can never RAISE a
                        miner's effective capacity. NULL / stale ⇒ no
                        throttle (the trusted computed value stands).
    - `cvm_last_ok_at` / `cvm_last_fail_at` / `cvm_fail_streak` /
      `cvm_fail_streak_started_at` / `cvm_last_fail_reason`
                        the OBSERVED SEV-SNP start-capability ledger (see
                        `scheduler.cvm_capability`): when vali last
                        WATCHED a confidential guest actually start on
                        this host, when it last watched one fail to, and
                        how many CONSECUTIVE in-window failures have run
                        without a success in between. Written only from
                        vali's own terminal dispatch outcomes (a launch
                        order the miner accepted / rejected, a §25 dest
                        activation that reported `done`/`failed`), keyed
                        on the node id from vali's OWN decision — never
                        from any field a miner supplied, so no miner can
                        mark a RIVAL incapable. `cvm_last_fail_reason` is
                        a closed vali-side vocabulary, never miner bytes.

                        The STREAK is the load-bearing part: a single
                        `sev_common_kvm_init … EBUSY` is intermittent and
                        self-recovering (measured across the live fleet),
                        so one failure only de-rates a host softly. Only
                        a run of them hard-excludes it, and any observed
                        success zeroes the counter.

                        This is the ONLY admission input that models the
                        binary precondition under all the others: CPU,
                        RAM and slots are all irrelevant on a host whose
                        SNP state machine has wedged, and such a host
                        reports FULL free capacity while being unable to
                        boot anything. Like `capacity_slots` these
                        fields are NOT chain-sourced and are preserved
                        across every mirror refresh.
    - `observed_epoch`  the on-chain `CurrentEpoch` when this row was
                        last refreshed.
    - `data_epoch`      the epoch the miner's score actually reflects
                        (`CurrentEpoch` if scored this epoch, else
                        the last on-chain transition). The
                        scheduler's fail-closed stale-epoch gate
                        keys off `observed_epoch - data_epoch`.
    - `refreshed_at`    wall-clock of the last chain refresh.

    This row is a cache: it is rebuilt from the chain on every
    `/place`, `/fail`, and re-eval cycle. It is never the authority
    for `status` — the live `read-miner-status` snapshot is.
    """

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    miner_node_id = models.CharField(max_length=64, unique=True)
    status = models.CharField(max_length=32, choices=MinerStatusMirror.choices)
    # u128 reward weight — 39 decimal digits covers the full range.
    quality = models.DecimalField(max_digits=39, decimal_places=0, default=0)
    capacity_slots = models.PositiveIntegerField()
    # Operator-registered TRUSTED hardware anchor (NOT self-reported).
    # NULL ⇒ this row uses the flat static `capacity_slots` (legacy /
    # un-seeded behaviour); set ⇒ the dynamic capacity is sized from it.
    total_memory_mb = models.PositiveIntegerField(null=True, blank=True, default=None)
    total_cpus = models.PositiveIntegerField(null=True, blank=True, default=None)
    # UNTRUSTED self-report from the §K heartbeat — the last free-RAM the
    # miner claimed, and when. Used ONLY as a down-only throttle on the
    # vali-computed free capacity; can never raise it. NULL until the
    # first heartbeat carries it.
    reported_memory_available_mib = models.PositiveIntegerField(
        null=True, blank=True, default=None
    )
    reported_at = models.DateTimeField(null=True, blank=True, default=None)
    # OBSERVED SEV-SNP start capability (see `scheduler.cvm_capability`).
    # NOT self-reported and NOT chain-sourced: written only from vali's own
    # terminal dispatch outcomes, and preserved across mirror refreshes.
    cvm_last_ok_at = models.DateTimeField(null=True, blank=True, default=None)
    cvm_last_fail_at = models.DateTimeField(null=True, blank=True, default=None)
    # CONSECUTIVE in-window observed start failures; any observed success
    # resets it to 0. A single failure is intermittent and must not exclude.
    cvm_fail_streak = models.PositiveIntegerField(default=0)
    cvm_fail_streak_started_at = models.DateTimeField(
        null=True, blank=True, default=None
    )
    cvm_last_fail_reason = models.CharField(max_length=64, blank=True, default="")
    observed_epoch = models.BigIntegerField()
    data_epoch = models.BigIntegerField()
    refreshed_at = models.DateTimeField()
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["miner_node_id"]
        verbose_name_plural = "miner capacities"
        indexes = [
            models.Index(fields=["status"]),
        ]

    def __str__(self) -> str:
        return f"MinerCapacity {self.miner_node_id} ({self.status})"


class Placement(models.Model):
    """A single VM→miner placement decision — the §23 operator log.

    Field-by-field:

    - `vm`                FK to the `lifecycle.Vm` being placed.
    - `vm_family`         anti-affinity grouping key (§23 "(b)
                          anti-affinity across families"). Derived
                          from the VM's `OrderTicketIntake.tenant_id`
                          — two placements sharing a `vm_family`
                          must not land on the same miner.
    - `resource_class`    caller-supplied resource class for the
                          placement. Recorded for the audit trail.
    - `miner_node_id`     the chosen miner's §23 `node_id` (hex).
                          NEVER re-pointed in place: a row records the
                          decision that was TAKEN, and the rest of the
                          row (`decided_by`, `decided_at`,
                          `chain_epoch`, `kbs_release_ref`) is the
                          evidence for it. A VM that moves to a §25
                          destination closes this row `Migrated` and
                          opens a fresh one — see
                          `service.move_placement_to_node`.
    - `status`            one of `PlacementStatus`.
    - `chain_epoch`       the on-chain `CurrentEpoch` the decision
                          was taken against — pins the placement to
                          a concrete, auditable epoch.
    - `reason`            short operator-facing string on Failed
                          (`""` otherwise). For re-eval drains it is
                          `drain:<cause>`; for a §25 hand-over it is
                          `migrated:<job_id>` on the CLOSED source row.
    - `kbs_release_ref`   audit reference the `/bind` caller supplied
                          as evidence the KBS release succeeded for
                          this VM (`""` until Bound).
    - `decided_by`        the `ServiceClient` that triggered the
                          decision. Audit trail per §15.
    - `decided_at`        creation timestamp.
    - `bound_at`          set on Pending→Bound.
    - `failed_at`         set on →Failed.
    - `version`           optimistic-concurrency counter. Starts at
                          1, +1 per successful transition.

    Constraints:

    - Partial unique index on `vm` for `status ∈ {pending, bound}`
      — at most one active placement per VM. This is the database
      boundary that makes `/place` idempotent + race-safe: two
      concurrent schedulers can both pass the application pre-check,
      but only one INSERT survives; the loser catches the
      `IntegrityError` and returns the winning row.
    - `Bound ⇒ bound_at IS NOT NULL` (DB CHECK).
    - `Failed ⇒ failed_at IS NOT NULL AND reason != ""` (DB CHECK).
    - `Migrated ⇒ reason != ""` (DB CHECK) — the reason carries the
      `migrated:<job_id>` back-link to the §25 job that moved the VM,
      which is the only thing tying the closed row to the row that
      replaced it. A `Migrated` row with no reason would be an
      unexplained disappearance from the miner's ledger.
    """

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    vm = models.ForeignKey(
        "lifecycle.Vm",
        on_delete=models.PROTECT,
        related_name="placements",
    )
    vm_family = models.CharField(max_length=256, db_index=True)
    # The OWNER (the OrderTicket `user_id`) this placement belongs to.
    # `vm_family` (= tenant_id) anti-affinity caps ONE family at 1 per
    # miner, but an owner running many families/workloads could otherwise
    # pile them all onto a single miner (noisy-neighbour + correlated
    # blast radius). The scheduler uses this for a per-owner sub-budget
    # per miner (audit M-per-tenant-cap). Blank ⇒ legacy / unknown owner
    # (the cap is inert for it).
    owner = models.CharField(max_length=256, blank=True, default="", db_index=True)
    resource_class = models.CharField(max_length=128)
    miner_node_id = models.CharField(max_length=64, db_index=True)
    status = models.CharField(
        max_length=32,
        choices=PlacementStatus.choices,
        default=PlacementStatus.PENDING,
    )
    chain_epoch = models.BigIntegerField()
    reason = models.CharField(max_length=256, blank=True, default="")
    kbs_release_ref = models.CharField(max_length=256, blank=True, default="")
    decided_by = models.ForeignKey(
        "identity.ServiceClient",
        on_delete=models.PROTECT,
        related_name="scheduler_placements",
    )
    decided_at = models.DateTimeField(auto_now_add=True)
    bound_at = models.DateTimeField(null=True, blank=True)
    failed_at = models.DateTimeField(null=True, blank=True)
    version = models.PositiveBigIntegerField(default=1)

    class Meta:
        ordering = ["-decided_at"]
        indexes = [
            models.Index(fields=["status"]),
            models.Index(fields=["miner_node_id", "status"]),
            models.Index(fields=["vm_family", "status"]),
            # Per-owner-per-miner sub-budget lookup (audit M-per-tenant-cap).
            models.Index(fields=["owner", "miner_node_id", "status"]),
        ]
        constraints = [
            # At most one active placement per VM. Postgres + SQLite
            # (the test backend) both honour partial unique indexes.
            models.UniqueConstraint(
                fields=["vm"],
                condition=models.Q(status__in=["pending", "bound"]),
                name="scheduler_one_active_placement_per_vm",
            ),
            models.CheckConstraint(
                name="scheduler_bound_requires_bound_at",
                condition=(
                    ~models.Q(status=PlacementStatus.BOUND)
                    | models.Q(bound_at__isnull=False)
                ),
            ),
            models.CheckConstraint(
                name="scheduler_failed_requires_failed_at",
                condition=(
                    ~models.Q(status=PlacementStatus.FAILED)
                    | models.Q(failed_at__isnull=False)
                ),
            ),
            models.CheckConstraint(
                name="scheduler_failed_requires_reason",
                condition=(
                    ~models.Q(status=PlacementStatus.FAILED)
                    | ~models.Q(reason="")
                ),
            ),
            models.CheckConstraint(
                name="scheduler_migrated_requires_reason",
                condition=(
                    ~models.Q(status=PlacementStatus.MIGRATED)
                    | ~models.Q(reason="")
                ),
            ),
        ]

    def __str__(self) -> str:
        return f"Placement {self.id} (vm={self.vm_id} → {self.miner_node_id}, {self.status})"


class PriceRecommendationStatus(models.TextChoices):
    """`PriceMigrationRecommendation` lifecycle.

    `Pending` is raised by `vali_price_watch` when a miner announces a
    price that would exceed the VM's tenant ceiling. It is a vSphere-DRS-
    *manual* recommendation — NOT an automatic migration: an operator
    `approve`s it (→ a §25 migration is started) or `dismiss`es it (the
    tenant accepts the new price). The watcher itself marks a stale one
    `Superseded` when the breaching announcement is withdrawn / applied /
    falls back within budget. All non-`Pending` states are terminal.
    """

    PENDING = "pending", "Pending"
    APPROVED = "approved", "Approved"
    DISMISSED = "dismissed", "Dismissed"
    SUPERSEDED = "superseded", "Superseded"


# Recommendation states that are decided (an operator acted, or the
# watcher retired it) — all carry a `decided_at`. `Pending` is the only
# live state; at most one `Pending` per VM (partial-unique below).
DECIDED_RECOMMENDATION_STATES: frozenset[str] = frozenset(
    {
        PriceRecommendationStatus.APPROVED.value,
        PriceRecommendationStatus.DISMISSED.value,
        PriceRecommendationStatus.SUPERSEDED.value,
    }
)


class PriceMigrationRecommendation(models.Model):
    """A §23-marketplace alert: a bound VM's miner announced a price that
    would breach the tenant's `max_price_per_unit` ceiling.

    This is deliberately NOT an automatic migration — migrating a VM is a
    stop+restart (customer downtime), so a price change only *recommends*
    a move (vSphere-DRS manual mode). The operator/tenant decides:

    - `approve` → a §25 `MigrationJob` is started to `suggested_dest_node_id`
      (or a freshly re-evaluated destination), status → `Approved`.
    - `dismiss` → status → `Dismissed` (the tenant accepts the new price).

    The `vali_price_watch` worker upserts at most one `Pending` row per VM
    and `Superseded`s it when the breaching announcement is gone. Genuine
    miner-departure migration (§13 drain / §25 graceful-exit) is a
    SEPARATE, still-automatic path and is unaffected by this model.

    Field-by-field:

    - `recommendation_id`  public, opaque, URL-safe identifier (the PK
                           `id` never leaks onto the wire).
    - `vm`                 FK to the `lifecycle.Vm` at risk.
    - `current_node_id`    miner the VM runs on (the one repricing).
    - `suggested_dest_node_id`
                           best within-budget destination at recommend
                           time (`""` if the watcher found none — the
                           alert still surfaces so the operator can act).
    - `new_price`          the announced price that breaches the ceiling.
    - `ceiling`            the tenant's `max_price_per_unit` at the time.
    - `effective_block`    block at which the new price takes effect.
    - `status`             one of `PriceRecommendationStatus`.
    - `decided_by`         the `ServiceClient` that approved/dismissed
                           (`NULL` while Pending / on watcher-supersede).
    - `decided_at`         set when it leaves `Pending`.
    - `version`            optimistic-concurrency counter (+1 per CAS).

    Constraints:

    - Partial unique on `vm` for `status = pending` — at most one live
      recommendation per VM (the upsert boundary).
    - `decided ⇒ decided_at IS NOT NULL` (DB CHECK).
    """

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    recommendation_id = models.CharField(max_length=64, unique=True)
    vm = models.ForeignKey(
        "lifecycle.Vm",
        on_delete=models.PROTECT,
        related_name="price_recommendations",
    )
    current_node_id = models.CharField(max_length=64, db_index=True)
    suggested_dest_node_id = models.CharField(max_length=64, blank=True, default="")
    new_price = models.BigIntegerField()
    ceiling = models.BigIntegerField()
    effective_block = models.BigIntegerField()
    status = models.CharField(
        max_length=32,
        choices=PriceRecommendationStatus.choices,
        default=PriceRecommendationStatus.PENDING,
    )
    decided_by = models.ForeignKey(
        "identity.ServiceClient",
        on_delete=models.PROTECT,
        related_name="price_recommendations",
        null=True,
        blank=True,
    )
    decided_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    version = models.PositiveBigIntegerField(default=1)

    class Meta:
        ordering = ["-created_at"]
        indexes = [
            models.Index(fields=["status"]),
            models.Index(fields=["current_node_id", "status"]),
        ]
        constraints = [
            models.UniqueConstraint(
                fields=["vm"],
                condition=models.Q(status=PriceRecommendationStatus.PENDING),
                name="scheduler_one_pending_recommendation_per_vm",
            ),
            models.CheckConstraint(
                name="scheduler_recommendation_decided_requires_decided_at",
                condition=(
                    models.Q(status=PriceRecommendationStatus.PENDING)
                    | models.Q(decided_at__isnull=False)
                ),
            ),
        ]

    def __str__(self) -> str:
        return (
            f"PriceMigrationRecommendation {self.recommendation_id} "
            f"(vm={self.vm_id} on {self.current_node_id}, {self.status})"
        )


class UsageAccrual(models.Model):
    """Attested uptime usage for one `(epoch, miner, vm)` — the billing
    ledger.

    We pay a miner only for VM time that is genuinely UP. The `vali_usage_meter`
    worker accrues here from the tenant guest's periodic, Ed25519-signed
    `ServedDeliveryReceipt`s (each an attested "VM X on miner N served during
    [t0,t1]" that the untrusted miner cannot forge). A down VM emits no
    receipts ⇒ accrues nothing ⇒ isn't paid — fail-closed by construction.

    `unit_seconds` = Σ `resource_units(resource_class) × billable_seconds ×
    (1 − degradation)` over the epoch's receipts. `compute_epoch_weights()`
    sums it per miner (uptime-integrated) and the owed amount is
    `unit_seconds × MinerPrice`.

    Field-by-field:

    - `epoch`             the on-chain epoch the receipts attested (bucket
                          key; taken from the signed receipt body, not a
                          wall-clock — correct across rollover).
    - `miner_node_id`     the miner credited (the receipt's `node_id`).
    - `vm_id`             the tenant VM served.
    - `resource_class`    the VM flavour (drives `resource_units`).
    - `lease_id`          the lease the receipts were bound to (audit).
    - `unit_seconds`      Σ resource-unit-seconds accrued this epoch.
    - `billable_seconds`  Σ raw attested up-seconds (pre-unit, for audit).
    - `updated_at`        last accrual wall-clock.

    Unique `(epoch, miner_node_id, vm_id)` — one accrual bucket per VM per
    epoch, upserted as receipts arrive.
    """

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    epoch = models.BigIntegerField()
    miner_node_id = models.CharField(max_length=64, db_index=True)
    vm_id = models.CharField(max_length=128, db_index=True)
    resource_class = models.CharField(max_length=128)
    lease_id = models.CharField(max_length=256, blank=True, default="")
    unit_seconds = models.BigIntegerField(default=0)
    billable_seconds = models.BigIntegerField(default=0)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["-epoch", "miner_node_id"]
        indexes = [
            models.Index(fields=["epoch", "miner_node_id"]),
        ]
        constraints = [
            models.UniqueConstraint(
                fields=["epoch", "miner_node_id", "vm_id"],
                name="scheduler_usage_accrual_unique_epoch_miner_vm",
            ),
        ]

    def __str__(self) -> str:
        return (
            f"UsageAccrual epoch={self.epoch} miner={self.miner_node_id} "
            f"vm={self.vm_id} unit_seconds={self.unit_seconds}"
        )


class ReceiptWatermark(models.Model):
    """The billing frontier for a `(vm_id, lease_id)` — the highest
    `monotonic_seq` consumed AND the highest `period_end` already billed.

    Served receipts carry a per-`(vm,lease)` `monotonic_seq` that the
    guest increments per receipt, plus the window `[period_start,
    period_end]` they claim. Two independent guards, and it matters which
    one holds the money:

    - `last_period_end` is the MONEY guard. The meter bills only the part
      of a window ending AFTER it, and then advances it. Every second is
      therefore billable at most once, no matter what sequence numbers
      arrive in what order.
    - `last_monotonic_seq` is the ORDERING/dedup guard: it drops a
      re-delivered or out-of-order receipt before any ledger work.

    ⚠️ `monotonic_seq` is monotonic only WITHIN ONE BOOT. The guest agent
    holds it in RAM (`agent-tenant-telemetry`'s `ReceiptBuilder`, whose
    `FIRST_SEQ` is 1) so every guest restart — a tenant `reboot`, a host
    reboot + reboot-recovery relaunch, or a §25 migration's destination
    boot — restarts the sequence at 1. A watermark that only ever
    ADVANCED therefore silently stopped billing a rebooted VM until its
    sequence climbed back past the pre-reboot value (from seq 600 at a
    60 s cadence: ~10 hours of unpaid, attested uptime). Proven live.

    So the sequence watermark RE-BASELINES on a restart, and
    `seq_restarts` / `last_restart_at_unix` record it. The re-baseline is
    gated on the receipt's window opening at or after `last_period_end` —
    i.e. on a receipt that can re-bill ZERO already-billed seconds — so it
    is provably worthless as an inflation primitive: a replayed old
    receipt (the only thing an attacker holding the extractable guest key
    can cheaply produce) overlaps the billed frontier and never triggers
    it, and a receipt that does trigger it bills exactly the new seconds
    it would have billed anyway. See `apps.scheduler.usage`.
    """

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    vm_id = models.CharField(max_length=128)
    lease_id = models.CharField(max_length=256, blank=True, default="")
    last_monotonic_seq = models.BigIntegerField(default=0)
    # §23 — the highest `period_end` already billed for this (vm,lease).
    # The meter bills only the part of a new receipt's window that ends
    # AFTER this, so increasing-seq receipts with OVERLAPPING periods
    # cannot double-bill the same seconds (the seq gate alone misses that).
    # NEVER re-baselined: this is the guard that makes the sequence
    # re-baseline safe, so resetting it would be the double-billing hole.
    last_period_end = models.BigIntegerField(default=0)
    # How many times the sequence watermark has been re-baselined for this
    # (vm,lease) — one per observed guest restart. Audit + observability:
    # a re-baseline is a money-path event and must not be silent. A count
    # far above the VM's real reboot count is the signal that something is
    # inducing restarts.
    seq_restarts = models.BigIntegerField(default=0)
    # Wall-clock unix of the newest re-baseline (`0` = never).
    last_restart_at_unix = models.BigIntegerField(default=0)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=["vm_id", "lease_id"],
                name="scheduler_receipt_watermark_unique_vm_lease",
            ),
        ]

    def __str__(self) -> str:
        return (
            f"ReceiptWatermark vm={self.vm_id} lease={self.lease_id} "
            f"seq={self.last_monotonic_seq}"
        )


class VmBillingBinding(models.Model):
    """The authoritative billing identity vali provisioned for a tenant VM
    at launch — the miner `node_id`, `resource_class`, and `lease_id` a
    served receipt MUST match.

    A receipt is signed by the guest's telemetry key, but that key is
    HKDF-derived from the §7 lifecycle seed which lands in the guest's
    `/run` tmpfs — a party with ROOT INSIDE the CVM (the tenant, or a
    miner running its own fake-tenant VM) can read it and forge a receipt
    claiming a bigger `resource_class` (more units) or a different
    `node_id` / `lease_id`. The meter rejects any receipt whose
    self-declared fields do not match THIS binding: vali provisioned it at
    launch, so it — not the guest-signed payload — is authoritative for
    what may be billed. Recorded on every launch path (alongside the
    `telemetry.TelemetrySource`). See the uptime-billing threat model.

    ⚠️ This row is the DECLARED identity, NOT "where the VM runs today".
    `node_id_hex` is the value the guest itself declares, and the guest
    reads it from `hippius.node_id` on its SNP-MEASURED cmdline — which a
    §25 migration carries to the destination VERBATIM (rewriting it would
    change the measurement and the dest would never unlock; see
    `orchestration/effects.py::_migrate_launch_paths`). A migrated guest
    therefore keeps declaring its LAUNCH node forever, in both its served
    receipts AND its KBS-signed live attestations
    (`scripts/guest/hippius-keepalive-start` reads the same cmdline token).
    Re-pointing this row at the destination would make every one of those
    fail the match and bill NOTHING for a VM that is happily running.

    WHO IS PAID is a different question with a different answer, and it
    lives in [`VmBillingAssignment`] — a time-ranged, append-only history
    the meter resolves by the receipt's SERVICE WINDOW.
    """

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    vm_id = models.CharField(max_length=128, unique=True)
    node_id_hex = models.CharField(max_length=64)
    resource_class = models.CharField(max_length=128)
    lease_id = models.CharField(max_length=256, blank=True, default="")
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self) -> str:
        return (
            f"VmBillingBinding vm={self.vm_id} node={self.node_id_hex[:12]} "
            f"rc={self.resource_class}"
        )


class VmBillingAssignment(models.Model):
    """§23/§25 — which miner is CREDITED for a tenant VM's uptime, from
    when. Append-only; one row per change of custody.

    A VM's workload moves: a §25 migration hands it to another miner, and
    from the cutover on it is the DESTINATION that runs the tenant's
    machine. Uptime accrued before the cutover was genuinely served by the
    source and stays the source's; uptime after it is the destination's.
    A single mutable "current miner" field cannot express that — a receipt
    for a PRE-cutover window can be metered AFTER the cutover (the guest
    drains its buffer on the migration shutdown, and the telemetry pull
    broker adds its own lag), and crediting it by whoever holds the field
    at metering time would retroactively move already-served uptime to a
    miner that did not serve it. So the answer is TIME-RANGED, and the
    meter resolves it by the receipt's SERVICE WINDOW, never by wall-clock.

    Rows are append-only and half-open: a row is in force from
    `effective_from_unix` until the next row's `effective_from_unix`
    (`+∞` for the newest). Resolution is therefore "the newest row with
    `effective_from_unix <= t`", and a row's meaning never changes after
    it is written — the ledger of who was paid for what is auditable.

    Field-by-field:

    - `vm_id`               the tenant VM.
    - `node_id_hex`         the 64-hex chain `node_id` credited from
                            `effective_from_unix` on. EMPTY means
                            UNATTRIBUTABLE — the workload moved to a host
                            vali cannot name (no `chain_node_id`), and the
                            meter then credits NOBODY rather than keep
                            paying a miner that no longer runs the VM.
    - `effective_from_unix` when this miner started serving.
    - `reason`              `launch` | `migration` (audit).
    - `created_at`          when the row was written (tie-break only).

    The launch row is written by `launch.py::_persist_billing_binding`
    (before the domain boots, so it precedes the guest's first receipt
    window); the §25 row is written INSIDE the dest-activation CAS in
    `orchestration/service.py::_activate_dest_vm`, so `Vm.host` and the
    credited miner can never disagree.
    """

    LAUNCH = "launch"
    MIGRATION = "migration"

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    vm_id = models.CharField(max_length=128, db_index=True)
    # Blank = unattributable (see the class docstring) — never a silent
    # fallback to the previous miner.
    node_id_hex = models.CharField(max_length=64, blank=True, default="")
    effective_from_unix = models.BigIntegerField()
    reason = models.CharField(max_length=32, default=LAUNCH)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["vm_id", "-effective_from_unix", "-created_at"]
        indexes = [
            models.Index(fields=["vm_id", "effective_from_unix"]),
        ]

    def __str__(self) -> str:
        return (
            f"VmBillingAssignment vm={self.vm_id} "
            f"node={self.node_id_hex[:12] or '<unattributable>'} "
            f"from={self.effective_from_unix} ({self.reason})"
        )
