"""§25 → §23 feedback: a destination that cannot start a confidential
guest must not be eligible for the very next placement.

The live failure this pins: a §25 migration reached `DestActivating`,
the destination's SEV-SNP state machine was wedged (`sev_common_kvm_init
… EBUSY`, `SEV-SNP: DF_FLUSH failed`), the dest reported `failed`, and
the migration failed with the VM down — while the destination stayed
heart-beating, on-chain `Active`, inside its #668 fit budget, and fully
eligible for the next launch AND the next migration. `MigrationJob.
quarantine_node_id` was empty, because the only writer of that field is
the AwaitingSourceAck timeout and it names the SOURCE.

Two halves are tested here:

  * the OBSERVATION — a dest-activation `failed` records the destination
    as CVM-incapable; a `done` records it as capable;
  * the GATE — `start_migration` refuses an incapable destination at
    intake, BEFORE the quiesce fences and stops the source.

Deliberately kept out of `test_migration.py`: that module owns the
state-machine + failure-handling behaviour and is being edited
concurrently.
"""

from __future__ import annotations

from datetime import timedelta

import pytest
from django.utils import timezone

from apps.lifecycle.models import VmState
from apps.miners.models import MinerIdentity
from apps.orchestration import service
from apps.orchestration.models import MigrationJob, MigrationState
from apps.scheduler import cvm_capability
from apps.scheduler.models import MinerCapacity

from .conftest import FakeEffects
from .factories import make_launch_record, make_service_client, make_vm

pytestmark = pytest.mark.django_db

SRC_NODE = "11" * 32
DST_NODE = "22" * 32


@pytest.fixture(autouse=True)
def _bridged_same_gen_miners():
    """`node-src` / `node-dst` as SAME-generation (Genoa, 64-byte chip_id)
    miners WITH a bridged `chain_node_id` — the join the capability ledger
    is keyed through (`miner_id → chain_node_id`)."""
    MinerIdentity.objects.update_or_create(
        miner_id="node-src",
        defaults={
            "pubkey_hex": "aa" * 32,
            "platform_id": "11" * 64,
            "chain_node_id": SRC_NODE,
        },
    )
    MinerIdentity.objects.update_or_create(
        miner_id="node-dst",
        defaults={
            "pubkey_hex": "bb" * 32,
            "platform_id": "22" * 64,
            "chain_node_id": DST_NODE,
        },
    )


def _mirror(node: str) -> MinerCapacity:
    return MinerCapacity.objects.create(
        miner_node_id=node,
        status="active",
        capacity_slots=4,
        observed_epoch=10,
        data_epoch=10,
        refreshed_at=timezone.now(),
    )


def _drive_until(job, target: str, *, limit: int = 25) -> None:
    for _ in range(limit):
        service.tick_once()
        job.refresh_from_db()
        if job.state == target:
            return
    raise AssertionError(f"job stuck at {job.state!r}, never reached {target!r}")


def _age_phase(job, seconds: float) -> None:
    """Move the job's phase clock back by `seconds`, which is what drives
    the dest-activation attempt counter (`elapsed // backoff`)."""
    MigrationJob.objects.filter(id=job.id).update(
        phase_started_at=timezone.now() - timedelta(seconds=seconds)
    )
    job.refresh_from_db()


def _activate_dispatches(fx: FakeEffects) -> int:
    return sum(1 for c in fx.calls if c[0] == "dispatch_migrate_activate")


# ─── the RETRY (availability) ────────────────────────────────────────


def test_a_transient_dest_failure_is_retried_not_fatal(fx: FakeEffects) -> None:
    """THE AVAILABILITY HALF. `sev_common_kvm_init … EBUSY` on the dest is
    intermittent and self-recovering, and by `DestActivating` the source
    is already quiesced, stopped and KBS-fenced — so giving up on the
    first `failed` costs the tenant its VM for a fault that clears by
    itself.

    Before the fix a `failed` status was terminal in practice: the handler
    re-ran every tick, but the dispatch idempotency key was CONSTANT, so
    the dest was never actually asked again — the job just re-polled a
    dead answer until the phase deadline."""
    _mirror(DST_NODE)
    vm = make_vm(generation=5, host="node-src")
    job = service.start_migration(
        vm=vm, dest_node_id="node-dst", decided_by=make_service_client()
    )
    fx.dest_activation_status = "failed"
    _drive_until(job, MigrationState.DEST_ACTIVATING.value)

    service.tick_once()  # attempt 0 — dispatched, dest says failed
    assert _activate_dispatches(fx) == 1

    # Same attempt window: NOT re-dispatched (the backoff paces retries).
    service.tick_once()
    assert _activate_dispatches(fx) == 1

    # Past the backoff, the dest is genuinely asked again — and this time
    # the transient has cleared.
    _age_phase(job, 130)
    fx.dest_activation_status = "done"
    service.tick_once()

    job.refresh_from_db()
    vm.refresh_from_db()
    assert _activate_dispatches(fx) == 2
    # The retry is dispatched as a DIFFERENT attempt — `dispatch_migrate_
    # activate` folds it into the order_id, so the dest runs it again
    # instead of replaying the first acceptance.
    attempts = [c[6] for c in fx.calls if c[0] == "dispatch_migrate_activate"]
    assert attempts == [0, 1]
    assert job.state == MigrationState.DONE.value
    assert vm.host == "node-dst"  # the tenant kept its VM
    # ...and the transient left a soft mark, not an exclusion.
    assert cvm_capability.capability_of(DST_NODE) == cvm_capability.PROVEN


def test_a_slow_restore_does_not_spend_the_retry_budget(fx: FakeEffects) -> None:
    """A multi-GB restore runs for many backoff windows. Each is NOT a new
    attempt: with a clock-derived attempt number vali sent a new order per
    window, the dest answered `activate-in-progress` to each, and a
    restore that then failed found every retry already spent."""
    _mirror(DST_NODE)
    vm = make_vm(generation=5, host="node-src")
    job = service.start_migration(
        vm=vm, dest_node_id="node-dst", decided_by=make_service_client()
    )
    fx.dest_activation_status = "running"
    _drive_until(job, MigrationState.DEST_ACTIVATING.value)
    service.tick_once()
    for minutes in (3, 6, 9, 12):
        _age_phase(job, minutes * 60)
        service.tick_once()
    assert _activate_dispatches(fx) == 1, "a running restore is waited on, not re-sent"

    # It fails at minute 15 — the first real failure, so a real retry.
    _age_phase(job, 15 * 60)
    fx.dest_activation_status = "failed"
    service.tick_once()
    job.refresh_from_db()
    assert job.state == MigrationState.DEST_ACTIVATING.value
    fx.dest_activation_status = "done"
    service.tick_once()

    job.refresh_from_db()
    attempts = [c[6] for c in fx.calls if c[0] == "dispatch_migrate_activate"]
    assert attempts == [0, 1]
    assert job.state == MigrationState.DONE.value


def test_every_attempt_carries_the_phase_deadline_as_settle_by(
    fx: FakeEffects, settings
) -> None:
    """The dest's clock used to restart with each attempt while vali's ran
    from entering the phase, so a retry could settle — boot the guest at
    `new_gen` — after vali had failed the job. Every attempt now carries
    vali's own deadline, less the safety margin, taken from
    `phase_started_at`: the same instant for the first order and a retry."""
    settings.VALI_ORCHESTRATION_ACTIVATE_TIMEOUT_S = 1800.0
    settings.VALI_MIGRATION_DEST_ACTIVATE_BACKOFF_S = 0.0
    _mirror(DST_NODE)
    vm = make_vm(generation=5, host="node-src")
    job = service.start_migration(
        vm=vm, dest_node_id="node-dst", decided_by=make_service_client()
    )
    fx.dest_activation_status = "failed"
    _drive_until(job, MigrationState.DEST_ACTIVATING.value)
    # Well into the phase, so "now + timeout" would be a different answer.
    _age_phase(job, 700)

    service.tick_once()  # attempt 0 — dispatched, dest says failed
    service.tick_once()  # attempt 1 — the retry, a new order

    job.refresh_from_db()
    attempts = [c[6] for c in fx.calls if c[0] == "dispatch_migrate_activate"]
    assert attempts == [0, 1]
    expected = int(job.phase_started_at.timestamp() + 1800) - 60
    assert fx.activate_settle_by == [expected, expected]


def test_no_retry_is_sent_once_the_dest_could_not_settle_in_time(
    fx: FakeEffects,
) -> None:
    """Past `settle_by - DEST_LAUNCH_MARGIN` the dest refuses the order
    before doing anything and reports `failed` — which would be booked as
    one more CVM start failure against a host never asked to start. So
    vali stops asking and lets the phase deadline fail the job."""
    _mirror(DST_NODE)
    vm = make_vm(generation=5, host="node-src")
    job = service.start_migration(
        vm=vm, dest_node_id="node-dst", decided_by=make_service_client()
    )
    fx.dest_activation_status = "failed"
    _drive_until(job, MigrationState.DEST_ACTIVATING.value)
    service.tick_once()  # attempt 0 — dispatched, dest says failed
    assert _activate_dispatches(fx) == 1

    # 2700 - 60 - 240 = 2400 s: the last instant a dest accepts an order.
    _age_phase(job, 2410)
    service.tick_once()
    service.tick_once()

    job.refresh_from_db()
    assert _activate_dispatches(fx) == 1, "no order the dest must refuse"
    assert job.state == MigrationState.DEST_ACTIVATING.value


def test_a_done_from_a_dest_that_accepted_no_order_is_not_this_restore(
    fx: FakeEffects, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Live (a migrated VM, A→B→A): the dest was the VM's previous SOURCE and
    refused every activate (`activate-on-source`); its status route then
    reported that old source leg's `done`, and vali activated a VM that
    nothing had restored. A `done` only counts once the dest accepted one
    of THIS job's orders."""
    from apps.orchestration import effects, idempotency

    _mirror(DST_NODE)
    vm = make_vm(generation=5, host="node-src")
    job = service.start_migration(
        vm=vm, dest_node_id="node-dst", decided_by=make_service_client()
    )
    fx.dest_activation_status = "running"
    _drive_until(job, MigrationState.DEST_ACTIVATING.value)
    job.refresh_from_db()

    # Every activate refused by the dest: nothing is recorded as sent.
    def _refused(*_a: object, **_kw: object) -> None:
        raise effects.EffectError("migrate-activate: dest miner rejected (status=409)")

    monkeypatch.setattr(effects, "dispatch_migrate_activate", _refused)
    # Its retries spent (as the pre-fix clock counter spent them).
    for n in range(service._dest_activate_max_attempts()):
        idempotency.record(service._mig_key(job, service._failure_step(n)), "x")
    fx.dest_activation_status = "done"
    for _ in range(3):
        service.tick_once()

    job.refresh_from_db()
    vm.refresh_from_db()
    assert job.state == MigrationState.DEST_ACTIVATING.value
    assert vm.host == "node-src", "never activated on an unrestored dest"


def test_retries_are_bounded(fx: FakeEffects) -> None:
    """The retry is not a loop with no exit: `MAX_ATTEMPTS` dispatches,
    inside the pre-existing `_activate_timeout()` phase deadline."""
    _mirror(DST_NODE)
    vm = make_vm(generation=5, host="node-src")
    job = service.start_migration(
        vm=vm, dest_node_id="node-dst", decided_by=make_service_client()
    )
    fx.dest_activation_status = "failed"
    _drive_until(job, MigrationState.DEST_ACTIVATING.value)

    for attempt in range(6):
        _age_phase(job, 130 * attempt)
        service.tick_once()

    assert _activate_dispatches(fx) == service._dest_activate_max_attempts()


# ─── the OBSERVATION (scheduling correctness) ────────────────────────


def test_one_dest_failure_degrades_but_does_not_exclude(fx: FakeEffects) -> None:
    """THE LIVE BUG, and the corrected response to it. Before this change
    the destination came out of this sequence completely unmarked — every
    §23 signal about it was identical to a healthy host's, and
    `quarantine_node_id` named nobody, so the next placement could pick it
    again immediately.

    It is now recorded — but as DEGRADED, not excluded: one EBUSY is
    intermittent, and hard-excluding on it would repeatedly pull healthy
    miners out of the fleet."""
    _mirror(DST_NODE)
    vm = make_vm(generation=5, host="node-src")
    job = service.start_migration(
        vm=vm, dest_node_id="node-dst", decided_by=make_service_client()
    )
    fx.dest_activation_status = "failed"

    _drive_until(job, MigrationState.DEST_ACTIVATING.value)
    service.tick_once()

    assert cvm_capability.capability_of(DST_NODE) == cvm_capability.DEGRADED
    row = MinerCapacity.objects.get(miner_node_id=DST_NODE)
    assert row.cvm_fail_streak == 1
    assert row.cvm_last_fail_reason == cvm_capability.REASON_DEST_ACTIVATION_FAILED
    # The SOURCE is untouched — the observation is attributed to the host
    # that failed to boot, not to the one that handed the VM over.
    assert cvm_capability.capability_of(SRC_NODE) == cvm_capability.UNKNOWN


def test_the_failure_is_counted_once_per_ATTEMPT_not_once_per_tick(
    fx: FakeEffects,
) -> None:
    """The streak has to count real start attempts. Counting per POLL
    would drive a single transient failure to the exclusion threshold
    within a minute of ticking — reintroducing exactly the over-eager
    exclusion this design rejects."""
    _mirror(DST_NODE)
    vm = make_vm(generation=5, host="node-src")
    job = service.start_migration(
        vm=vm, dest_node_id="node-dst", decided_by=make_service_client()
    )
    fx.dest_activation_status = "failed"
    _drive_until(job, MigrationState.DEST_ACTIVATING.value)

    for _ in range(5):
        service.tick_once()

    assert MinerCapacity.objects.get(miner_node_id=DST_NODE).cvm_fail_streak == 1
    assert cvm_capability.capability_of(DST_NODE) == cvm_capability.DEGRADED


def test_a_dest_that_fails_every_attempt_becomes_incapable(
    fx: FakeEffects,
) -> None:
    """The other direction: a host that fails EVERY attempt of a
    migration has produced exactly the streak that hard-excludes it, so
    the next scheduling decision routes around it. The retry and the
    exclusion are two readings of the same measurement — which is why
    `MAX_ATTEMPTS` and `FAIL_THRESHOLD` are both 3."""
    _mirror(DST_NODE)
    vm = make_vm(generation=5, host="node-src")
    job = service.start_migration(
        vm=vm, dest_node_id="node-dst", decided_by=make_service_client()
    )
    fx.dest_activation_status = "failed"
    _drive_until(job, MigrationState.DEST_ACTIVATING.value)

    for attempt in range(3):
        _age_phase(job, 130 * attempt)
        service.tick_once()

    assert MinerCapacity.objects.get(miner_node_id=DST_NODE).cvm_fail_streak == 3
    assert cvm_capability.capability_of(DST_NODE) == cvm_capability.INCAPABLE


def _fail_one_attempt_with(fx: FakeEffects, failure_class: str) -> MigrationJob:
    """Drive a migration to `DestActivating`, have the dest report attempt 0
    `failed` with `failure_class`, and let the retry go out."""
    _mirror(DST_NODE)
    vm = make_vm(generation=5, host="node-src")
    job = service.start_migration(
        vm=vm, dest_node_id="node-dst", decided_by=make_service_client()
    )
    fx.dest_activation_status = "failed"
    fx.dest_activation_class = failure_class
    _drive_until(job, MigrationState.DEST_ACTIVATING.value)
    service.tick_once()  # attempt 0 — dispatched, dest says failed
    _age_phase(job, 130)
    service.tick_once()  # attempt 1 — the retry
    job.refresh_from_db()
    return job


@pytest.mark.parametrize(
    "failure_class",
    [
        "migration/dest-settle-by-passed",
        "migration/snapshot-download-budget",
        "migration/snapshot-sha256-mismatch",
        "migration/download-send",
        "migration/dest-artifact-sha-mismatch",
        "migration/dest-artifacts-missing",
        "migration/state-disk-size",
        "migration/chain-vm-live",
        "backup/full-size-mismatch",
        "migration/restore-staged-missing",
        "migration/restore-not-staged",
        "migration/staged-restore-conflict",
        "migration/restore-size-mismatch",
        "migration/restore-swap-conflict",
    ],
)
def test_a_failure_before_any_cvm_start_advances_the_attempt_but_is_no_evidence(
    fx: FakeEffects, failure_class: str
) -> None:
    """A migrated VM booked `dest-artifact-sha-mismatch` on miner-c as a CVM start
    failure. A restore that failed before any boot is a real failed attempt
    — the retry goes out — but says nothing about SEV, and this streak
    hard-excludes hosts."""
    _fail_one_attempt_with(fx, failure_class)

    attempts = [c[6] for c in fx.calls if c[0] == "dispatch_migrate_activate"]
    assert attempts == [0, 1], "the excused failure still advances the attempt"
    assert cvm_capability.capability_of(DST_NODE) == cvm_capability.UNKNOWN
    assert MinerCapacity.objects.get(miner_node_id=DST_NODE).cvm_fail_streak == 0


@pytest.mark.parametrize(
    "failure_class",
    ["", "migration/dest-launch-failed", "libvirt-driver/create", "something-new"],
)
def test_a_start_failure_or_an_unexcused_class_is_still_evidence(
    fx: FakeEffects, failure_class: str
) -> None:
    """No class (an agent predating it), a launch failure and anything not
    explicitly excused keep today's behaviour: one failed attempt, one mark."""
    _fail_one_attempt_with(fx, failure_class)

    attempts = [c[6] for c in fx.calls if c[0] == "dispatch_migrate_activate"]
    assert attempts == [0, 1]
    assert cvm_capability.capability_of(DST_NODE) == cvm_capability.DEGRADED
    assert MinerCapacity.objects.get(miner_node_id=DST_NODE).cvm_fail_streak == 2


def test_dest_activation_failure_is_recorded_for_a_golden_vm_too(
    fx: FakeEffects,
) -> None:
    """The `golden-no-quarantine` defence is scoped to the SOURCE on an
    AwaitingSourceAck TIMEOUT. It must not, and does not, extend to a
    DESTINATION that reported it could not boot — different state,
    different node, and the golden path has no bearing on whether a host
    can initialise SEV."""
    _mirror(DST_NODE)
    vm = make_vm(generation=5, host="node-src")
    make_launch_record(
        vm,
        disk_mode="golden_verity_overlay",
        measured_cmdline="ro dm-verity.root=abc hippius.eol_nonce=11",
    )
    job = service.start_migration(
        vm=vm, dest_node_id="node-dst", decided_by=make_service_client()
    )
    fx.dest_activation_status = "failed"

    _drive_until(job, MigrationState.DEST_ACTIVATING.value)
    service.tick_once()

    assert service._is_golden(vm) is True
    assert cvm_capability.capability_of(DST_NODE) == cvm_capability.DEGRADED


def test_successful_activation_records_the_destination_capable(
    fx: FakeEffects,
) -> None:
    """The positive half, and the one that makes every penalty
    self-healing: a later observed success is newer than the failure AND
    zeroes the streak, so it clears both the de-rate and any exclusion
    with no operator action."""
    _mirror(DST_NODE)
    MinerCapacity.objects.filter(miner_node_id=DST_NODE).update(
        cvm_last_fail_at=timezone.now() - timedelta(minutes=1),
        cvm_fail_streak=2,
        cvm_last_fail_reason=cvm_capability.REASON_DEST_ACTIVATION_FAILED,
    )
    assert cvm_capability.capability_of(DST_NODE) == cvm_capability.DEGRADED

    vm = make_vm(generation=5, host="node-src")
    job = service.start_migration(
        vm=vm, dest_node_id="node-dst", decided_by=make_service_client()
    )
    _drive_until(job, MigrationState.DONE.value)

    assert cvm_capability.capability_of(DST_NODE) == cvm_capability.PROVEN
    assert MinerCapacity.objects.get(miner_node_id=DST_NODE).cvm_fail_streak == 0


def test_observation_is_a_no_op_when_the_dest_has_no_bridged_node_id(
    fx: FakeEffects,
) -> None:
    """Fail-open bookkeeping: an unbridged destination has no ledger row
    to write, and that must not turn into an exception inside the
    migration step (the job still fails on the dest's own report)."""
    MinerIdentity.objects.filter(miner_id="node-dst").update(chain_node_id=None)
    vm = make_vm(generation=5, host="node-src")
    job = service.start_migration(
        vm=vm, dest_node_id="node-dst", decided_by=make_service_client()
    )
    fx.dest_activation_status = "failed"

    _drive_until(job, MigrationState.DEST_ACTIVATING.value)
    service.tick_once()  # must not raise

    job.refresh_from_db()
    assert job.state == MigrationState.DEST_ACTIVATING.value


# ─── the intake gate ─────────────────────────────────────────────────


def test_start_migration_refuses_an_incapable_destination() -> None:
    """The half `decide_placement` cannot cover: the API and the CLI name
    the destination explicitly, so the scheduler is never consulted. A
    migration is also the worst place to discover this, because the
    discovery happens after the source is quiesced and fenced — recovery
    is forward-only, so the tenant's VM is simply down."""
    _mirror(DST_NODE)
    for _ in range(cvm_capability.fail_threshold()):
        cvm_capability.record_start_failure(
            DST_NODE, reason=cvm_capability.REASON_DEST_ACTIVATION_FAILED
        )
    vm = make_vm(generation=5, host="node-src")

    with pytest.raises(service.StartError) as exc:
        service.start_migration(
            vm=vm, dest_node_id="node-dst", decided_by=make_service_client()
        )

    assert exc.value.category == "dest-cvm-incapable"
    # The source was never touched: no job, VM still Active on node-src.
    vm.refresh_from_db()
    assert vm.state == VmState.ACTIVE
    assert vm.host == "node-src"
    assert vm.migration_dest == ""


def test_start_migration_refuses_a_destination_without_disk_room(settings) -> None:
    """The same intake, for the DATA-disk gate: under `enforce` a named
    destination that cannot hold the VM's disk is refused before the source
    is touched (under `record` it is only logged)."""
    from apps.scheduler.models import Placement, PlacementStatus

    _mirror(DST_NODE)
    MinerCapacity.objects.filter(miner_node_id=DST_NODE).update(
        declared_disk_gb_budget=10, disk_reported_at=timezone.now()
    )
    vm = make_vm(generation=5, host="node-src")
    Placement.objects.create(
        vm=vm,
        vm_family="t",
        resource_class="large",
        miner_node_id="11" * 32,
        status=PlacementStatus.BOUND.value,
        chain_epoch=1,
        decided_by=make_service_client(),
        bound_at=timezone.now(),
    )
    settings.VALI_SCHEDULER_DISK_GATE = "enforce"
    with pytest.raises(service.StartError) as exc:
        service.start_migration(vm=vm, dest_node_id="node-dst", decided_by=make_service_client())
    assert exc.value.category == "dest-insufficient-disk"
    vm.refresh_from_db()
    assert (vm.state, vm.host, vm.migration_dest) == (VmState.ACTIVE, "node-src", "")

    settings.VALI_SCHEDULER_DISK_GATE = "record"
    job = service.start_migration(vm=vm, dest_node_id="node-dst", decided_by=make_service_client())
    assert job.state == MigrationState.DRAINING.value


def test_start_migration_allows_an_unknown_destination() -> None:
    """Fail-SAFE direction. A destination vali has no evidence about — a
    freshly registered miner, or the whole fleet on a fresh deploy — is
    ALLOWED. Absence of evidence must not block a legitimate move."""
    _mirror(DST_NODE)
    vm = make_vm(generation=5, host="node-src")
    job = service.start_migration(
        vm=vm, dest_node_id="node-dst", decided_by=make_service_client()
    )
    assert job.state == MigrationState.DRAINING.value


def test_start_migration_allows_a_merely_degraded_destination() -> None:
    """A SOFT signal must not veto an explicit operator action. One
    observed failure is probably transient, and the activation now
    retries — which is the right response to an intermittent fault."""
    _mirror(DST_NODE)
    cvm_capability.record_start_failure(
        DST_NODE, reason=cvm_capability.REASON_DEST_ACTIVATION_FAILED
    )
    assert cvm_capability.capability_of(DST_NODE) == cvm_capability.DEGRADED

    vm = make_vm(generation=5, host="node-src")
    job = service.start_migration(
        vm=vm, dest_node_id="node-dst", decided_by=make_service_client()
    )
    assert job.state == MigrationState.DRAINING.value


def test_start_migration_allows_a_destination_whose_streak_aged_out() -> None:
    """Half-open: a host that recovered — with or without a reboot, which
    vali cannot observe either way — must not be stranded on evidence
    from an hour ago."""
    _mirror(DST_NODE)
    MinerCapacity.objects.filter(miner_node_id=DST_NODE).update(
        cvm_last_fail_at=timezone.now() - timedelta(hours=5),
        cvm_fail_streak=9,
        cvm_last_fail_reason=cvm_capability.REASON_DEST_ACTIVATION_FAILED,
    )
    vm = make_vm(generation=5, host="node-src")
    job = service.start_migration(
        vm=vm, dest_node_id="node-dst", decided_by=make_service_client()
    )
    assert job.state == MigrationState.DRAINING.value


def test_start_migration_gate_is_disarmed_by_a_zero_threshold(settings) -> None:
    """The operator dial, end to end."""
    _mirror(DST_NODE)
    for _ in range(cvm_capability.fail_threshold()):
        cvm_capability.record_start_failure(
            DST_NODE, reason=cvm_capability.REASON_DEST_ACTIVATION_FAILED
        )
    settings.VALI_SCHEDULER_CVM_FAIL_THRESHOLD = 0
    vm = make_vm(generation=5, host="node-src")
    job = service.start_migration(
        vm=vm, dest_node_id="node-dst", decided_by=make_service_client()
    )
    assert job.state == MigrationState.DRAINING.value


# ─── the auto-migration picker ───────────────────────────────────────


THIRD_NODE = "33" * 32


def _departing_drain(monkeypatch) -> list[str]:
    """Run the REAL graceful-exit enrolment (real `decide_placement`) with
    `node-src` quarantined and two live candidate destinations, recording
    the destination each enrolment chose."""
    from apps.scheduler.chain import ChainSnapshot, MinerView

    MinerIdentity.objects.update_or_create(
        miner_id="node-third",
        defaults={
            "pubkey_hex": "33" * 32,
            "platform_id": "33" * 64,
            "chain_node_id": THIRD_NODE,
            "netbird_ip": "100.64.0.3",
            "last_seen_at": timezone.now(),
        },
    )
    MinerIdentity.objects.filter(miner_id="node-dst").update(
        netbird_ip="100.64.0.2", last_seen_at=timezone.now()
    )
    for node in (DST_NODE, THIRD_NODE):
        MinerCapacity.objects.get_or_create(
            miner_node_id=node,
            defaults={
                "status": "active",
                "capacity_slots": 4,
                "observed_epoch": 10,
                "data_epoch": 10,
                "refreshed_at": timezone.now(),
            },
        )
    snapshot = ChainSnapshot(
        current_epoch=10,
        miners=tuple(
            MinerView(
                node_id=nid,
                status="quarantined" if nid == SRC_NODE else "active",
                last_transition_epoch=10,
                data_epoch=10,
                quality=1,
            )
            for nid in (SRC_NODE, DST_NODE, THIRD_NODE)
        ),
    )
    monkeypatch.setattr("apps.scheduler.chain.read_miner_status", lambda: snapshot)
    chosen: list[str] = []

    def _fake_start(*, vm, dest_node_id, decided_by, cold=False):
        chosen.append(dest_node_id)
        return type("J", (), {"job_id": "fake-job"})()

    monkeypatch.setattr(service, "start_migration", _fake_start)
    service.enroll_departing_miner_migrations()
    return chosen


def test_auto_migration_never_picks_an_incapable_destination(monkeypatch) -> None:
    """`enroll_departing_miner_migrations` chooses the destination itself
    via `decide_placement`, so gate (e) has to be wired there too —
    otherwise a graceful-exit drain herds every VM off a departing miner
    onto the one host that cannot boot any of them.

    `node-dst` wins on every other signal (identical capacity, identical
    load, lower node_id), and loses only because vali observed it fail."""
    from apps.scheduler.models import Placement, PlacementStatus

    vm = make_vm(generation=5, host="node-src")
    Placement.objects.create(
        vm=vm,
        vm_family="tenant-1",
        owner="user-1",
        resource_class="small",
        miner_node_id=SRC_NODE,
        status=PlacementStatus.BOUND.value,
        chain_epoch=10,
        bound_at=timezone.now(),
        decided_by=make_service_client(),
    )
    _mirror(SRC_NODE)
    _mirror(DST_NODE)
    for _ in range(cvm_capability.fail_threshold()):
        cvm_capability.record_start_failure(
            DST_NODE, reason=cvm_capability.REASON_DEST_ACTIVATION_FAILED
        )
    assert cvm_capability.capability_of(DST_NODE) == cvm_capability.INCAPABLE

    assert _departing_drain(monkeypatch) == ["node-third"]


def test_auto_migration_prefers_away_from_a_merely_degraded_destination(
    monkeypatch,
) -> None:
    """The SOFT half, on the same path. One observed failure does not
    exclude `node-dst`, but it should still not be the drain's first
    choice while a clean alternative exists."""
    from apps.scheduler.models import Placement, PlacementStatus

    vm = make_vm(generation=5, host="node-src")
    Placement.objects.create(
        vm=vm,
        vm_family="tenant-1",
        owner="user-1",
        resource_class="small",
        miner_node_id=SRC_NODE,
        status=PlacementStatus.BOUND.value,
        chain_epoch=10,
        bound_at=timezone.now(),
        decided_by=make_service_client(),
    )
    _mirror(SRC_NODE)
    _mirror(DST_NODE)
    cvm_capability.record_start_failure(
        DST_NODE, reason=cvm_capability.REASON_DEST_ACTIVATION_FAILED
    )
    assert cvm_capability.capability_of(DST_NODE) == cvm_capability.DEGRADED

    assert _departing_drain(monkeypatch) == ["node-third"]


@pytest.mark.parametrize("cdn_node", [False, True])
def test_auto_migration_never_enrols_a_cdn_node(monkeypatch, cdn_node: bool) -> None:
    """A CDN node on a departing miner is replaced by the CDN reconciler,
    never migrated (CDN plan V3)."""
    from apps.cdn.models import CdnNode
    from apps.scheduler.models import Placement, PlacementStatus

    vm = make_vm(generation=5, host="node-src")
    if cdn_node:
        CdnNode.objects.create(node_id=vm.vm_id, region="FR", vm=vm)
    Placement.objects.create(
        vm=vm,
        vm_family="tenant-1",
        owner="user-1",
        resource_class="small",
        miner_node_id=SRC_NODE,
        status=PlacementStatus.BOUND.value,
        chain_epoch=10,
        bound_at=timezone.now(),
        decided_by=make_service_client(),
    )
    _mirror(SRC_NODE)
    _mirror(DST_NODE)
    assert bool(_departing_drain(monkeypatch)) is not cdn_node
