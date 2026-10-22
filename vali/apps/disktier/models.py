"""Verified disk tiers (docs/design/disk-tier-verification.md §4.3).

- `MinerStoragePool` — one storage pool of a miner (a mounted filesystem
  that holds OS disks), what the miner reports about it (untrusted), and
  the tier a probe verified for it.
- `DedicatedDisk` — one whole physical disk a miner offers for
  passthrough, its state and verified tier.
- `DiskProbeRun` — one probe VM and the per-target results it returned.
- `PlacementDisk` — one disk of a placement: the slot, and the pool or
  dedicated disk it sits on.
- `VmDiskIoHourly` — passive per-(VM, device, hour) I/O accumulator from
  tenant receipts.
- `MinerDiskHealthHourly` — the evaluator's hourly per-pool (or per-disk)
  rollup of that passive signal.
- `DiskIoReceipt` / `DiskIngestCounter` / `DiskPassiveEvent` — the passive
  ingest's replay dedupe and counters, and the evaluator's record-only
  events.

Placement reads none of these tables yet: the passive ingest and the
evaluator only record (design §10, P1/P2). Host-reported sizes are untrusted and only
ever clamp down; a tier comes from a probe (or an audited operator
override, `vali_set_pool_tier`), never from what the host says.
"""

from __future__ import annotations

import uuid

from django.db import models
from django.db.models import Q

from apps.lifecycle.models import Vm
from apps.scheduler.models import Placement
from apps.telemetry.models import TelemetryEnvelope

from .tiers import DiskTier

#: A pool id: the miner's stable slug (design §4.1).
POOL_ID_MAX_LEN = 32
#: A dedicated disk id: a `/dev/disk/by-id/` basename.
DISK_ID_MAX_LEN = 96
#: The OS disk's slot; dedicated disks take `x0`..`x23` (never reused
#: within a VM, so a replacement takes the next free one).
OS_SLOT = "os"
DEDICATED_SLOTS: tuple[str, ...] = tuple(f"x{i}" for i in range(24))


class DeclaredClass(models.TextChoices):
    """What the miner SAYS a pool is. A hint for the probe and the operator;
    never a tier."""

    NVME = "nvme", "nvme"
    SSD = "ssd", "ssd"
    HDD = "hdd", "hdd"


class DiskHealth(models.TextChoices):
    #: No evidence against the disk.
    OK = "ok", "ok"
    #: Passive tenant stats look bad; a probe is scheduled. Never a penalty.
    SUSPECT = "suspect", "suspect"
    #: A probe fell below the current tier's floor.
    DEGRADED = "degraded", "degraded"
    #: `unfit`, `suspect-cache`, or repeated probe timeouts.
    SEVERE = "severe", "severe"


class MinerStoragePool(models.Model):
    """One storage pool of one miner (design §4.1).

    - `declared_class` / `os_disks` / `*_gb` / `reported_at`: the miner's
      report (heartbeat v7), untrusted. Sizes only ever clamp down.
    - `earned_gb`: the per-pool earned ceiling, vali's own figure.
    - `tier` / `tier_since`: the verified tier, set only by probes.
    - `operator_override` / `override_reason`: wins over `tier` while set;
      written only through `apps.disktier.override` (audited).
    - `health` + the pass/fail counters: the probe-driven state machine.
    - `auto_cordoned`: the node was cordoned BY the disk-tier state machine,
      so only it may lift that cordon — never a manual one.
    - `retired_at`: the pool left the miner's report; no new disks, the
      existing ones stay accounted.
    """

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    miner_node_id = models.CharField(max_length=64)
    pool_id = models.CharField(max_length=POOL_ID_MAX_LEN)
    declared_class = models.CharField(
        max_length=8, choices=DeclaredClass.choices, blank=True, default=""
    )
    os_disks = models.BooleanField(default=True)
    total_gb = models.PositiveIntegerField(null=True, blank=True)
    available_gb = models.PositiveIntegerField(null=True, blank=True)
    budget_gb = models.PositiveIntegerField(null=True, blank=True)
    reported_at = models.DateTimeField(null=True, blank=True)
    #: The disk the agent says it has reserved on the pool (heartbeat v7).
    committed_gb = models.PositiveIntegerField(null=True, blank=True)
    #: The agent's own view of the pool (`active` / `draining` /
    #: `unavailable`) and its last refusal code, as reported.
    reported_state = models.CharField(max_length=12, blank=True, default="", db_default="")
    reported_error = models.CharField(max_length=48, blank=True, default="", db_default="")
    #: Since when the node has reported the pool `unavailable` without a
    #: break (off its filesystem, unmounted, …); null while it is not.
    unavailable_since = models.DateTimeField(null=True, blank=True)
    earned_gb = models.PositiveIntegerField(null=True, blank=True)

    tier = models.CharField(
        max_length=8, choices=DiskTier.choices, default=DiskTier.UNKNOWN, db_default="unknown"
    )
    tier_since = models.DateTimeField(null=True, blank=True)
    operator_override = models.CharField(
        max_length=8, choices=DiskTier.choices, blank=True, default="", db_default=""
    )
    override_reason = models.CharField(max_length=512, blank=True, default="", db_default="")

    health = models.CharField(
        max_length=10, choices=DiskHealth.choices, default=DiskHealth.OK, db_default="ok"
    )
    health_since = models.DateTimeField(null=True, blank=True)
    consecutive_fail = models.PositiveSmallIntegerField(default=0, db_default=0)
    consecutive_pass = models.PositiveSmallIntegerField(default=0, db_default=0)
    last_run = models.ForeignKey(
        "DiskProbeRun", null=True, blank=True, on_delete=models.SET_NULL, related_name="+"
    )
    next_probe_due_at = models.DateTimeField(null=True, blank=True)
    probe_agent_version = models.CharField(max_length=64, blank=True, default="", db_default="")
    auto_cordoned = models.BooleanField(default=False, db_default=False)
    retired_at = models.DateTimeField(null=True, blank=True)

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["miner_node_id", "pool_id"]
        constraints = [
            models.UniqueConstraint(
                fields=["miner_node_id", "pool_id"], name="disktier_pool_unique_per_node"
            ),
            models.CheckConstraint(
                condition=~Q(operator_override="unknown"),
                name="disktier_pool_override_not_unknown",
            ),
        ]

    def __str__(self) -> str:
        return f"MinerStoragePool {self.miner_node_id[:12]}/{self.pool_id} {self.effective_tier}"

    @property
    def effective_tier(self) -> str:
        """The tier placement will use: the override while one is set."""
        return self.operator_override or self.tier


class DedicatedDiskDesiredState(models.TextChoices):
    ACTIVE = "active", "active"
    #: No new assignment; leaves placement once released.
    DRAINING = "draining", "draining"


class DedicatedDiskState(models.TextChoices):
    #: Declared or released; waits for a probe. Never placeable.
    PENDING_PROBE = "pending_probe", "pending_probe"
    PROBING = "probing", "probing"
    #: Probed at ≥ the hdd floor; placeable.
    FREE = "free", "free"
    ASSIGNED = "assigned", "assigned"
    #: Its VM was decommissioned (§24): waits for the agent to report it
    #: wiped and free again, then `pending_probe`. Never placeable.
    RELEASED = "released", "released"
    #: Vanished, offline, or I/O errors.
    FAILED = "failed", "failed"
    DRAINING = "draining", "draining"
    #: The by-id name now points at a different physical device.
    REPLACED = "replaced", "replaced"
    #: Probed below the hdd floor.
    UNFIT = "unfit", "unfit"
    RETIRED = "retired", "retired"


class DedicatedDisk(models.Model):
    """One whole physical disk a miner offers for passthrough (design §4.2).

    `disk_id` is the miner's `/dev/disk/by-id/` basename. It is the miner's
    own hardware name: shown to its operator, never to a tenant (tenants
    see virtual slot serials). A released disk goes back to
    `pending_probe`, never straight to `free`."""

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    miner_node_id = models.CharField(max_length=64)
    disk_id = models.CharField(max_length=DISK_ID_MAX_LEN)
    size_bytes = models.PositiveBigIntegerField(null=True, blank=True)
    #: The size the last probe measured (R3 writes it with the tier). What a
    #: disk is sold, measured and billed at — never `size_bytes`, which the
    #: miner rewrites on every heartbeat (a report below it means the disk
    #: is not the one probed). `None` (never probed) is never placeable.
    verified_size_bytes = models.PositiveBigIntegerField(null=True, blank=True)
    declared_at = models.DateTimeField(null=True, blank=True)
    desired_state = models.CharField(
        max_length=10,
        choices=DedicatedDiskDesiredState.choices,
        default=DedicatedDiskDesiredState.ACTIVE,
        db_default="active",
    )
    state = models.CharField(
        max_length=16,
        choices=DedicatedDiskState.choices,
        default=DedicatedDiskState.PENDING_PROBE,
        db_default="pending_probe",
    )
    verified_tier = models.CharField(
        max_length=8, choices=DiskTier.choices, default=DiskTier.UNKNOWN, db_default="unknown"
    )
    last_probe = models.ForeignKey(
        "DiskProbeRun", null=True, blank=True, on_delete=models.SET_NULL, related_name="+"
    )
    probed_at = models.DateTimeField(null=True, blank=True)
    assigned_vm = models.ForeignKey(
        Vm, null=True, blank=True, on_delete=models.SET_NULL, related_name="+"
    )
    assigned_slot = models.CharField(max_length=4, blank=True, default="", db_default="")
    assigned_at = models.DateTimeField(null=True, blank=True)
    freed_at = models.DateTimeField(null=True, blank=True)
    behind_controller = models.BooleanField(default=False, db_default=False)
    #: What the agent last reported (heartbeat v7): its own state for the
    #: disk, its refusal code, and the VM it believes holds it. For
    #: reconciliation only — vali's `state` / `assigned_vm` are the truth.
    reported_state = models.CharField(max_length=16, blank=True, default="", db_default="")
    reported_error = models.CharField(max_length=48, blank=True, default="", db_default="")
    reported_vm_id = models.CharField(max_length=128, blank=True, default="", db_default="")
    reported_at = models.DateTimeField(null=True, blank=True)

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["miner_node_id", "disk_id"]
        constraints = [
            models.UniqueConstraint(
                fields=["miner_node_id", "disk_id"], name="disktier_disk_unique_per_node"
            ),
            # An assigned disk names its VM and slot; any other disk names
            # neither.
            models.CheckConstraint(
                condition=Q(
                    state="assigned",
                    assigned_vm__isnull=False,
                    assigned_slot__in=list(DEDICATED_SLOTS),
                )
                | (~Q(state="assigned") & Q(assigned_vm__isnull=True, assigned_slot="")),
                name="disktier_disk_assignment_consistent",
            ),
            # One disk per slot of a VM.
            models.UniqueConstraint(
                fields=["assigned_vm", "assigned_slot"],
                condition=Q(assigned_vm__isnull=False),
                name="disktier_disk_one_per_vm_slot",
            ),
        ]

    def __str__(self) -> str:
        return f"DedicatedDisk {self.miner_node_id[:12]}/{self.disk_id} {self.state}"


class ProbeTrigger(models.TextChoices):
    ONBOARDING = "onboarding", "onboarding"
    PERIODIC = "periodic", "periodic"
    AGENT_UPGRADE = "agent_upgrade", "agent_upgrade"
    SUSPECT = "suspect", "suspect"
    #: Requested by an operator (announced: may only lower or confirm).
    MANUAL = "manual", "manual"
    #: The hysteresis confirmation probe.
    CONFIRM = "confirm", "confirm"
    #: A dedicated disk was declared.
    DECLARED = "declared", "declared"
    #: A dedicated disk was released by a VM.
    RELEASED = "released", "released"


class ProbeRunState(models.TextChoices):
    SCHEDULED = "scheduled", "scheduled"
    LAUNCHING = "launching", "launching"
    RUNNING = "running", "running"
    #: A result arrived and is being verified.
    RESULT = "result", "result"
    VERIFIED = "verified", "verified"
    FAILED = "failed", "failed"
    TIMEOUT = "timeout", "timeout"
    TORN_DOWN = "torn_down", "torn_down"


class DiskProbeRun(models.Model):
    """One probe VM and what it measured.

    `run_id` + `nonce` + `vm_id` + `owner` + node bind a guest-signed
    result to this row; a result that does not match all of them is not a
    probe result. `targets` holds one entry per disk the run benchmarked:
    `{slot, kind: "pool"|"dedicated", pool_id | disk_id, profile, metrics,
    classified_tier, verdict_detail}`.

    Probe identity (vm_id, owner, exact timestamps) is never served to a
    miner operator: a miner that can recognise a probe can un-throttle for
    it."""

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    run_id = models.UUIDField(default=uuid.uuid4, unique=True, editable=False)
    nonce = models.BinaryField(max_length=32)
    vm_id = models.CharField(max_length=128, unique=True)
    miner_node_id = models.CharField(max_length=64)
    chip_id = models.CharField(max_length=128, blank=True, default="")
    owner = models.CharField(max_length=128)
    trigger = models.CharField(max_length=16, choices=ProbeTrigger.choices)
    state = models.CharField(
        max_length=12,
        choices=ProbeRunState.choices,
        default=ProbeRunState.SCHEDULED,
        db_default="scheduled",
    )
    flavor = models.CharField(max_length=32)
    release_version = models.PositiveIntegerField(null=True, blank=True)
    targets = models.JSONField(default=list, blank=True)
    envelope = models.ForeignKey(
        TelemetryEnvelope, null=True, blank=True, on_delete=models.SET_NULL, related_name="+"
    )
    failure_reason = models.CharField(max_length=128, blank=True, default="", db_default="")
    scheduled_at = models.DateTimeField()
    launched_at = models.DateTimeField(null=True, blank=True)
    result_at = models.DateTimeField(null=True, blank=True)
    torn_down_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    # ── the orchestrator's bookkeeping (R1, `apps.disktier.probe`) ──
    #: The pool the run's OS disk sits on (the `os` target's pool).
    os_pool_id = models.CharField(max_length=POOL_ID_MAX_LEN, blank=True, default="", db_default="")
    #: The first launch attempt (the internal-failure retry window's start).
    first_attempt_at = models.DateTimeField(null=True, blank=True)
    #: The `LaunchJob` that launches the probe VM.
    launch_job_id = models.CharField(max_length=64, blank=True, default="", db_default="")
    #: The request's `start_delay_s` (the guest waits this long before any I/O).
    start_delay_s = models.PositiveIntegerField(null=True, blank=True)
    #: No verdict by then ⇒ `timeout`.
    deadline_at = models.DateTimeField(null=True, blank=True)
    #: When the run reached its verdict (`verified` / `failed` / `timeout`).
    finished_at = models.DateTimeField(null=True, blank=True)
    #: The VM is torn down from then on (the lifetime jitter after a result).
    teardown_after = models.DateTimeField(null=True, blank=True)
    #: When the orchestrator started the VM's §24, and how the teardown ended.
    teardown_started_at = models.DateTimeField(null=True, blank=True)
    teardown_detail = models.CharField(max_length=256, blank=True, default="", db_default="")
    #: SHA-256 of the guest-signed receipt the accepted result came in.
    result_digest = models.CharField(max_length=64, blank=True, default="", db_default="")
    #: The result's run facts: `vcpus`, `kernel`, `started_at`, `finished_at`.
    result_meta = models.JSONField(default=dict, blank=True)

    class Meta:
        ordering = ["-scheduled_at"]
        indexes = [
            models.Index(fields=["miner_node_id", "scheduled_at"]),
            models.Index(fields=["state"]),
        ]

    def __str__(self) -> str:
        return f"DiskProbeRun {self.run_id} {self.miner_node_id[:12]} {self.state}"


class DiskKind(models.TextChoices):
    POOL = "pool", "pool"
    DEDICATED = "dedicated", "dedicated"


class PlacementDisk(models.Model):
    """One disk of one placement: the committed capacity per pool, and the
    dedicated disks a VM holds. A legacy placement without rows is the OS
    disk on pool `default`, sized by `Placement.data_disk_gb`."""

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    placement = models.ForeignKey(Placement, on_delete=models.CASCADE, related_name="disks")
    slot = models.CharField(max_length=4)
    kind = models.CharField(max_length=10, choices=DiskKind.choices)
    pool_id = models.CharField(max_length=POOL_ID_MAX_LEN, blank=True, default="")
    dedicated_disk = models.ForeignKey(
        DedicatedDisk, null=True, blank=True, on_delete=models.PROTECT, related_name="+"
    )
    size_gb = models.PositiveIntegerField()
    required_tier = models.CharField(max_length=8, choices=DiskTier.choices)
    #: A dedicated slot's latest verdict from the guest's signed receipt
    #: (`disk_io`): `ok`, `missing` or `mismatch`; blank until one arrives.
    #: Forgeable by root in the VM: shown as the slot's `guest_state` only, never
    #: its `state` (host evidence decides that, `apps.disktier.dedicated`).
    observed_state = models.CharField(max_length=10, blank=True, default="", db_default="")
    observed_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=["placement", "slot"], name="disktier_placementdisk_one_per_slot"
            ),
            # A pool disk names its pool; a dedicated disk names its disk.
            models.CheckConstraint(
                condition=(Q(kind="pool", dedicated_disk__isnull=True) & ~Q(pool_id=""))
                | Q(kind="dedicated", dedicated_disk__isnull=False, pool_id=""),
                name="disktier_placementdisk_target_matches_kind",
            ),
            # The OS disk lives on a pool; every other slot is a dedicated
            # disk in `x0`..`x23`.
            models.CheckConstraint(
                condition=Q(slot=OS_SLOT, kind="pool")
                | Q(slot__in=list(DEDICATED_SLOTS), kind="dedicated"),
                name="disktier_placementdisk_slot_matches_kind",
            ),
            models.CheckConstraint(
                condition=Q(required_tier__in=["nvme", "ssd", "hdd"]),
                name="disktier_placementdisk_required_tier_sellable",
            ),
        ]

    def __str__(self) -> str:
        return f"PlacementDisk {self.placement_id} {self.slot} {self.kind}"


class VmDiskIoHourly(models.Model):
    """Passive I/O of one tenant device over one hour, summed from the
    `/sys/block` deltas in the VM's receipts (design §3.5). `slot` and the
    pool / dedicated disk are resolved at ingest from `PlacementDisk` and
    the device's virtual serial. Trigger evidence only: never a verdict."""

    id = models.BigAutoField(primary_key=True)
    vm_id = models.CharField(max_length=128)
    miner_node_id = models.CharField(max_length=64)
    owner = models.CharField(max_length=128, blank=True, default="")
    device = models.CharField(max_length=16)
    slot = models.CharField(max_length=4, blank=True, default="")
    pool_id = models.CharField(max_length=POOL_ID_MAX_LEN, blank=True, default="")
    disk_id = models.CharField(max_length=DISK_ID_MAX_LEN, blank=True, default="")
    hour = models.DateTimeField()
    windows = models.PositiveIntegerField(default=0)
    seconds = models.PositiveIntegerField(default=0)
    r_ios = models.PositiveBigIntegerField(default=0)
    w_ios = models.PositiveBigIntegerField(default=0)
    r_sectors = models.PositiveBigIntegerField(default=0)
    w_sectors = models.PositiveBigIntegerField(default=0)
    r_ticks_ms = models.PositiveBigIntegerField(default=0)
    w_ticks_ms = models.PositiveBigIntegerField(default=0)
    io_ticks_ms = models.PositiveBigIntegerField(default=0)
    tiq_ms = models.PositiveBigIntegerField(default=0)
    #: Windows with average QD >= 4 and average I/O size <= 32 KiB: the
    #: only ones whose latency says something about the disk.
    qd4_small_ios = models.PositiveBigIntegerField(default=0)
    qd4_small_ticks_ms = models.PositiveBigIntegerField(default=0)
    #: The READ share of those windows: the evaluator's signal is the read
    #: await of QD >= 4 small-I/O windows (design §3.5), which the r+w
    #: bucket above cannot give back.
    qd4_small_r_ios = models.PositiveBigIntegerField(default=0, db_default=0)
    qd4_small_r_ticks_ms = models.PositiveBigIntegerField(default=0, db_default=0)

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=["vm_id", "device", "hour"], name="disktier_vmio_unique_per_hour"
            ),
        ]
        indexes = [
            models.Index(fields=["miner_node_id", "hour"]),
            # The evaluator reads one hour fleet-wide; the GC reaps by age.
            models.Index(fields=["hour"]),
        ]

    def __str__(self) -> str:
        return f"VmDiskIoHourly {self.vm_id} {self.device} {self.hour:%Y-%m-%dT%H}"


class MinerDiskHealthHourly(models.Model):
    """The evaluator's hourly rollup for one pool (`pool_id`) or one
    dedicated disk (`disk_id`) of a miner. Medians are per owner first,
    then across owners, so one owner is one vote."""

    id = models.BigAutoField(primary_key=True)
    miner_node_id = models.CharField(max_length=64)
    pool_id = models.CharField(max_length=POOL_ID_MAX_LEN, blank=True, default="")
    disk_id = models.CharField(max_length=DISK_ID_MAX_LEN, blank=True, default="")
    hour = models.DateTimeField()
    owners = models.PositiveIntegerField(default=0)
    vms = models.PositiveIntegerField(default=0)
    median_owner_await_us = models.PositiveIntegerField(null=True, blank=True)
    p90_owner_await_us = models.PositiveIntegerField(null=True, blank=True)
    suspect_owners = models.PositiveIntegerField(default=0)
    verdict = models.CharField(max_length=10, choices=DiskHealth.choices, blank=True, default="")
    #: The tier the hour was graded against (the pool's effective tier,
    #: else its declared class; a dedicated disk's verified tier). Blank =
    #: not graded (no tier to grade against): `verdict` is blank too.
    tier = models.CharField(max_length=8, blank=True, default="", db_default="")

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=["miner_node_id", "pool_id", "disk_id", "hour"],
                name="disktier_health_unique_per_hour",
            ),
            # Exactly one of the two targets.
            models.CheckConstraint(
                condition=(~Q(pool_id="") & Q(disk_id="")) | (Q(pool_id="") & ~Q(disk_id="")),
                name="disktier_health_one_target",
            ),
        ]
        indexes = [models.Index(fields=["hour"])]

    def __str__(self) -> str:
        target = self.pool_id or self.disk_id
        return f"MinerDiskHealthHourly {self.miner_node_id[:12]}/{target} {self.hour:%Y-%m-%dT%H}"


class DiskIoReceipt(models.Model):
    """One served receipt whose disk evidence the passive ingest folded in
    (design §3.5): the replay dedupe. Keyed on the SHA-256 of the
    guest-signed receipt body, so it holds whatever the billing watermark
    decides, and a receipt the usage meter re-queues is never counted
    twice. Reaped by `vali_disktier_gc` once older than any receipt the
    ingest still accepts."""

    id = models.BigAutoField(primary_key=True)
    receipt_digest = models.CharField(max_length=64, unique=True)
    vm_id = models.CharField(max_length=128)
    ingested_at = models.DateTimeField()

    class Meta:
        indexes = [models.Index(fields=["ingested_at"])]

    def __str__(self) -> str:
        return f"DiskIoReceipt {self.receipt_digest[:12]} {self.vm_id}"


class DiskIngestCounter(models.Model):
    """Cumulative counters of the passive ingest (`ingested_rows`,
    `dedupe_hits`, `errors`, ...). The usage meter folds its per-cycle
    tallies in; the evaluator pushes them to the Pushgateway."""

    name = models.CharField(max_length=48, primary_key=True)
    value = models.PositiveBigIntegerField(default=0)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self) -> str:
        return f"DiskIngestCounter {self.name}={self.value}"


class DiskPassiveEventKind(models.TextChoices):
    #: The passive signal says a re-probe is due. RECORD ONLY: nothing is
    #: scheduled (the probe orchestrator is phase R1).
    WOULD_REPROBE = "would-reprobe", "would-reprobe"
    #: A lone non-internal owner's suspicion was dropped by the
    #: single-griefer cap.
    GRIEFER_CAPPED = "griefer-capped", "griefer-capped"


class DiskPassiveEvent(models.Model):
    """What the passive evaluator concluded about one pool or dedicated
    disk of a miner. Append-only; never served to a miner operator (a
    miner warned of a re-probe could un-throttle for it).

    `trigger_owner` is set only when a single non-internal owner raised
    the suspicion: the single-griefer cap counts those per owner."""

    id = models.BigAutoField(primary_key=True)
    miner_node_id = models.CharField(max_length=64)
    pool_id = models.CharField(max_length=POOL_ID_MAX_LEN, blank=True, default="")
    disk_id = models.CharField(max_length=DISK_ID_MAX_LEN, blank=True, default="")
    hour = models.DateTimeField()
    kind = models.CharField(max_length=16, choices=DiskPassiveEventKind.choices)
    trigger_owner = models.CharField(max_length=128, blank=True, default="")
    detail = models.JSONField(default=dict, blank=True)
    created_at = models.DateTimeField()

    class Meta:
        ordering = ["-created_at", "-id"]
        indexes = [
            models.Index(fields=["miner_node_id", "kind", "created_at"]),
            models.Index(fields=["trigger_owner", "kind", "created_at"]),
        ]

    def __str__(self) -> str:
        target = self.pool_id or self.disk_id
        return f"DiskPassiveEvent {self.miner_node_id[:12]}/{target} {self.kind}"


class MinerStorageConfig(models.Model):
    """The desired `storage-config` document of one node and its push
    state (design §9; the `MinerNetPolicy` state machine).

    - `body`: the desired document without `revision` / `not_after_unix` /
      `dry_run`: `{"pools": [...], "dedicated_disks": [...]}`, sorted by id.
      Written only through `apps.disktier.storage_config` (audited).
    - `revision`: per node and monotonic, the agent's replay floor. Bumped
      when the content changes (`content_key`), never for a re-send, and
      jumped past the agent's own after a `409`.
    - `body_sha`: the `storage-config-digest` of the current revision (the
      agent acks `applied:<revision>:<body_sha>`); empty until the push
      loop computes it.
    - `acked_*`: what the agent last acked; `reported_*`: the
      `storage_config_revision` of its latest v7 heartbeat (0 = it runs
      its local config).
    - `refusal_*`: the agent's last `422` for the current revision.
    """

    id = models.BigAutoField(primary_key=True)
    miner_node_id = models.CharField(max_length=64, unique=True)
    body = models.JSONField(default=dict, blank=True)
    revision = models.BigIntegerField(default=0)
    #: SHA-256 of the canonical JSON `body`; empty forces a re-stage.
    content_key = models.CharField(max_length=64, blank=True, default="")
    body_sha = models.CharField(max_length=64, blank=True, default="")
    #: Last push attempt, whatever its outcome, and the revision it sent:
    #: a revision never sent yet is due at once.
    sent_at = models.DateTimeField(null=True, blank=True)
    sent_revision = models.BigIntegerField(default=0)
    acked_revision = models.BigIntegerField(default=0)
    acked_sha = models.CharField(max_length=64, blank=True, default="")
    acked_at = models.DateTimeField(null=True, blank=True)
    #: The document the agent last accepted: its paths are known-good
    #: local facts (`default` = the data root) the static checks hold
    #: later edits to.
    acked_body = models.JSONField(default=dict, blank=True)
    #: Why the last attempt did not end in the expected ack; blank once it did.
    last_error = models.CharField(max_length=256, blank=True, default="")
    refusal_code = models.CharField(max_length=64, blank=True, default="")
    refusal_pool = models.CharField(max_length=POOL_ID_MAX_LEN, blank=True, default="")
    refusal_disk = models.CharField(max_length=DISK_ID_MAX_LEN, blank=True, default="")
    #: Consecutive `422` / `500` answers to the current revision: re-sent
    #: with an exponential backoff.
    apply_failures = models.PositiveIntegerField(default=0)
    #: The agent has no `storage-config` route (`404`) or has it switched
    #: off (`503 storage-config-disabled`): nothing is sent for
    #: `VALI_STORAGE_CONFIG_UNSUPPORTED_RETRY_S`. Cleared by an ack.
    agent_unsupported_at = models.DateTimeField(null=True, blank=True)
    reported_revision = models.BigIntegerField(null=True, blank=True)
    reported_at = models.DateTimeField(null=True, blank=True)
    #: The family (32-byte account, hex) whose document this is — the one
    #: the chain check verified at the write. Nothing is pushed while the
    #: node's on-chain family is another, and another family sees no
    #: document (its first write replaces it, from `owner_since`).
    owner_family = models.CharField(max_length=64, blank=True, default="")
    owner_since = models.DateTimeField(null=True, blank=True)
    #: Who last changed the desired document (the service principal, and
    #: the family + backend user it acted for).
    updated_by_principal = models.CharField(max_length=128, blank=True, default="")
    updated_by_family = models.CharField(max_length=64, blank=True, default="")
    updated_by_user = models.CharField(max_length=128, blank=True, default="")
    updated_at = models.DateTimeField(null=True, blank=True)
    #: Why the current revision is not pushed, while it is held
    #: (`pool-not-drained:<pool>`, `family-changed`, `chain-unavailable`);
    #: blank once pushed. Read as `sync_status` `held:<reason>`.
    held = models.CharField(max_length=96, blank=True, default="", db_default="")
    #: Pools an operator force-removed (audited): `{pool_id: {at, principal,
    #: family, user, reason, report}}`. Such a pool leaves the document
    #: once the agent applied it `draining` and still reports it
    #: `unavailable` and empty — it never reports a dead pool `draining`.
    forced_pools = models.JSONField(default=dict, blank=True, db_default={})
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["miner_node_id"]

    def __str__(self) -> str:
        return (
            f"MinerStorageConfig {self.miner_node_id[:12]} r{self.revision} "
            f"(acked r{self.acked_revision})"
        )

    @property
    def acked_current(self) -> bool:
        return (
            self.revision > 0
            and bool(self.body_sha)
            and self.acked_revision == self.revision
            and self.acked_sha == self.body_sha
        )


class MinerStorageConfigAudit(models.Model):
    """Append-only history of a node's desired storage document: every
    operator write (with the document it produced) and every change of the
    agent's verdict on a revision. Never updated, never deleted."""

    id = models.BigAutoField(primary_key=True)
    miner_node_id = models.CharField(max_length=64)
    revision = models.BigIntegerField()
    #: `put`, `pool-add`, `pool-update`, `pool-drain`, `disk-drain`,
    #: `adopt`, `validate`, `pool-removed` (by vali once drained), `push`,
    #: `pool-force` (an operator's statement that a dead pool's disk is
    #: gone: `doc` = `{pool, reason, report}`), `pool-force-drain`.
    action = models.CharField(max_length=24)
    principal = models.CharField(max_length=128, blank=True, default="")
    #: The acting family as sent (SS58) and as verified (account hex).
    family = models.CharField(max_length=64, blank=True, default="")
    family_account = models.CharField(max_length=64, blank=True, default="")
    user = models.CharField(max_length=128, blank=True, default="")
    #: The desired document after the write (empty for a `push` row).
    doc = models.JSONField(default=dict, blank=True)
    #: `staged` / `unchanged` for a write; the agent's verdict for a `push`
    #: or `validate` row (`applied`, `dry-run-ok`, `refused:<code>:<id>`,
    #: `agent-unsupported`, …).
    outcome = models.CharField(max_length=192, blank=True, default="")
    at = models.DateTimeField()

    class Meta:
        ordering = ["-at", "-id"]
        indexes = [models.Index(fields=["miner_node_id", "at"])]

    def __str__(self) -> str:
        return f"MinerStorageConfigAudit {self.miner_node_id[:12]} r{self.revision} {self.action}"


class StorageMoveState(models.TextChoices):
    """vali's side of a live storage move (`apps.disktier.storage_move`)."""

    #: Accepted; `start` not acknowledged by the agent yet.
    REQUESTED = "requested", "requested"
    #: The agent copies / pivots.
    MOVING = "moving", "moving"
    #: The agent redefined the VM onto the target: vali waits for a served
    #: receipt from the guest before it releases the source.
    VERIFYING = "verifying", "verifying"
    #: Verified: `release` sent until the agent reports `done`.
    RELEASING = "releasing", "releasing"
    DONE = "done", "done"
    #: The agent aborted (the VM stays on its source) or refused the start.
    ABORTED = "aborted", "aborted"
    #: A failure an operator must look at (`code`): a verification timeout
    #: (the agent keeps the source), a pivot of unknown outcome.
    FAILED = "failed", "failed"


TERMINAL_MOVE_STATES = (StorageMoveState.DONE, StorageMoveState.ABORTED, StorageMoveState.FAILED)


class VmStorageMove(models.Model):
    """One live storage move of a VM's OS disk to another pool of its host.
    `id` is the `move_id` the agent journals it under (32 hex chars on the
    wire)."""

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    vm = models.ForeignKey(Vm, on_delete=models.CASCADE, related_name="storage_moves")
    miner_node_id = models.CharField(max_length=64)
    miner_id = models.CharField(max_length=256)
    source_pool = models.CharField(max_length=POOL_ID_MAX_LEN)
    target_pool = models.CharField(max_length=POOL_ID_MAX_LEN)
    bandwidth_mib_s = models.PositiveIntegerField()
    state = models.CharField(
        max_length=12, choices=StorageMoveState.choices, default=StorageMoveState.REQUESTED
    )
    #: The agent's last reported phase and code.
    agent_phase = models.CharField(max_length=16, blank=True, default="")
    code = models.CharField(max_length=48, blank=True, default="")
    bytes_total = models.BigIntegerField(default=0)
    bytes_done = models.BigIntegerField(default=0)
    #: When vali first saw the agent report `redefined` (the VM runs and
    #: boots from the target). A served receipt whose window ends after it
    #: proves the guest still runs: then vali releases the source.
    redefined_at = models.DateTimeField(null=True, blank=True)
    verified_at = models.DateTimeField(null=True, blank=True)
    cancel_requested_at = models.DateTimeField(null=True, blank=True)
    last_polled_at = models.DateTimeField(null=True, blank=True)
    #: When the last `start` went out (recorded before it goes): a move
    #: without one never reached the agent.
    start_sent_at = models.DateTimeField(null=True, blank=True)
    #: When vali first saw the VM bound and hosted elsewhere: from then on
    #: the move never holds the VM, books nothing and releases nothing.
    left_host_at = models.DateTimeField(null=True, blank=True)
    #: Orders in a row the agent did not answer (backoff).
    failures = models.PositiveSmallIntegerField(default=0)
    last_error = models.CharField(max_length=256, blank=True, default="")
    requested_by_principal = models.CharField(max_length=128, blank=True, default="")
    requested_by_family = models.CharField(max_length=64, blank=True, default="")
    requested_by_user = models.CharField(max_length=128, blank=True, default="")
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    finished_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ["-created_at"]
        constraints = [
            # One move in flight per VM.
            models.UniqueConstraint(
                fields=["vm"],
                condition=~Q(state__in=["done", "aborted", "failed"]),
                name="disktier_one_live_storage_move_per_vm",
            ),
        ]

    def __str__(self) -> str:
        return f"VmStorageMove {self.vm_id} {self.source_pool}->{self.target_pool} {self.state}"

    @property
    def move_id(self) -> str:
        return self.id.hex


# ─── §18.10 host inventory (UNTRUSTED, owner-facing only) ────────────
#
# What a miner reports about its own machine: shown to the node's owner,
# never read by tiers, placement, cordon, pay, strikes or billing
# (`tests/test_host_inventory.py` pins who may import these).
# Bodies carry serials: never log them, never list them in the admin.


class HostInventorySectionName(models.TextChoices):
    SYSTEM = "system", "system"
    CPU = "cpu", "cpu"
    MEMORY = "memory", "memory"
    STORAGE = "storage", "storage"
    NETWORK = "network", "network"
    PCI = "pci", "pci"
    SENSORS = "sensors", "sensors"
    SOFTWARE = "software", "software"


class HostInventoryState(models.Model):
    """Per node: the replay floor and the hourly report budget."""

    miner_node_id = models.CharField(max_length=64, primary_key=True)
    #: The registry identity whose `sequence` the floor counts: the agent
    #: persists its sequence per identity, so a node re-registered under a
    #: new one starts a new floor.
    miner_id = models.CharField(max_length=64, blank=True, default="")
    #: None until a report is accepted.
    last_sequence = models.PositiveBigIntegerField(null=True, blank=True)
    #: The last accepted report's signed timestamp, and when vali got it.
    last_reported_at = models.DateTimeField(null=True, blank=True)
    received_at = models.DateTimeField(null=True, blank=True)
    #: Reports verified in the current hour window (accepted or not).
    window_started_at = models.DateTimeField()
    window_count = models.PositiveIntegerField(default=0)

    def __str__(self) -> str:
        return f"HostInventoryState {self.miner_node_id[:12]} seq={self.last_sequence}"


class HostInventorySection(models.Model):
    """The latest report of one section of one node, replaced as a whole.
    A section absent from a report is unchanged, never removed."""

    id = models.BigAutoField(primary_key=True)
    miner_node_id = models.CharField(max_length=64)
    section = models.CharField(max_length=16, choices=HostInventorySectionName.choices)
    #: SHA-256 of the section's canonical CBOR (the Rust verifier's).
    digest = models.CharField(max_length=64)
    #: The section as the verifier decoded it (bounds and charsets checked
    #: there). Owner-only: carries serials.
    body = models.JSONField()
    #: The section's own `status` (`ok`, `partial`, `timeout`, …).
    status = models.CharField(max_length=16)
    #: The signed timestamp and sequence of the report it came in.
    reported_at = models.DateTimeField()
    sequence = models.PositiveBigIntegerField()
    received_at = models.DateTimeField()

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=["miner_node_id", "section"], name="disktier_host_inventory_one_per_section"
            ),
        ]

    def __str__(self) -> str:
        return f"HostInventorySection {self.miner_node_id[:12]}/{self.section}"


class HostInventoryChange(models.Model):
    """A section whose content changed: when, and which of its top-level
    fields. Reaped past `VALI_HOST_INVENTORY_CHANGE_RETENTION_DAYS`."""

    id = models.BigAutoField(primary_key=True)
    miner_node_id = models.CharField(max_length=64)
    section = models.CharField(max_length=16, choices=HostInventorySectionName.choices)
    at = models.DateTimeField()
    #: The top-level field names whose value changed, sorted.
    fields = models.JSONField(default=list)

    class Meta:
        indexes = [
            models.Index(fields=["miner_node_id", "at"]),
            models.Index(fields=["at"]),
        ]

    def __str__(self) -> str:
        return f"HostInventoryChange {self.miner_node_id[:12]}/{self.section} {self.at:%Y-%m-%d}"


class AdvisoryTransition(models.TextChoices):
    OPENED = "opened", "opened"
    ESCALATED = "escalated", "escalated"
    DEESCALATED = "deescalated", "deescalated"
    RESOLVED = "resolved", "resolved"


class HostDiskAdvisory(models.Model):
    """One host-reported disk health signal (§18.3/§18.5) of one node,
    upserted from each host inventory's storage section. Absent from a
    complete newer report ⇒ `resolved_at`. UNTRUSTED, owner-facing only."""

    id = models.BigAutoField(primary_key=True)
    miner_node_id = models.CharField(max_length=64)
    #: `pool | dedicated_disk | controller | md | device | collector`.
    subject_kind = models.CharField(max_length=16)
    subject_ref = models.CharField(max_length=DISK_ID_MAX_LEN, blank=True, default="")
    code = models.CharField(max_length=48)
    severity = models.CharField(max_length=8)
    count = models.PositiveBigIntegerField(default=0)
    value = models.BigIntegerField(default=0)
    first_seen = models.DateTimeField()
    last_seen = models.DateTimeField()
    #: Rebuilt from a fixed template by the collector; untrusted text.
    sample = models.CharField(max_length=128, blank=True, default="")
    resolved_at = models.DateTimeField(null=True, blank=True)
    updated_at = models.DateTimeField()

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=["miner_node_id", "subject_kind", "subject_ref", "code"],
                name="disktier_host_advisory_unique",
            ),
        ]
        indexes = [models.Index(fields=["resolved_at"])]

    def __str__(self) -> str:
        return f"HostDiskAdvisory {self.miner_node_id[:12]}/{self.subject_ref}/{self.code}"


class HostDiskAdvisoryEvent(models.Model):
    """An advisory's transition, appended on change only (the feed of the
    backend's "new critical" email). Reaped past 180 d."""

    id = models.BigAutoField(primary_key=True)
    miner_node_id = models.CharField(max_length=64)
    subject_kind = models.CharField(max_length=16)
    subject_ref = models.CharField(max_length=DISK_ID_MAX_LEN, blank=True, default="")
    code = models.CharField(max_length=48)
    transition = models.CharField(max_length=12, choices=AdvisoryTransition.choices)
    severity = models.CharField(max_length=8)
    at = models.DateTimeField()

    class Meta:
        indexes = [
            models.Index(fields=["miner_node_id", "at"]),
            models.Index(fields=["at"]),
        ]

    def __str__(self) -> str:
        return f"HostDiskAdvisoryEvent {self.miner_node_id[:12]}/{self.code} {self.transition}"
