"""§25 — billing custody moves to the destination, atomically with `Vm.host`.

The defect: `VmBillingBinding` was stamped once, at launch, and the
migration never touched it — so after a §25 move the SOURCE miner kept
being credited for every second the DESTINATION served. Uptime billing is
ARMED (`VALI_EPOCH_WEIGHT_SOURCE=usage`), so that is real money on a real
epoch weight, with no compensating action once submitted.

These drive the REAL `start_migration` → `tick_once` choreography, so a
fix that never reaches the migration path fails here. The meter side of
the same change (which miner a given receipt window pays) is pinned in
`apps/scheduler/tests/test_billing_custody.py`.
"""

from __future__ import annotations

import time

import pytest
from django.utils import timezone

from apps.lifecycle.models import Vm, VmState
from apps.orchestration import effects, service
from apps.orchestration.models import MigrationJob, MigrationState
from apps.scheduler import billing
from apps.scheduler.models import VmBillingAssignment, VmBillingBinding

from .conftest import FakeEffects
from .factories import make_service_client, make_vm

pytestmark = pytest.mark.django_db

SRC_NODE = "aa" * 32
DST_NODE = "bb" * 32


@pytest.fixture(autouse=True)
def _registered_miners():
    """Both hosts registered, one CPU generation (§25's same-gen gate
    resolves it from the CHIP_ID length), each with the chain `node_id`
    the usage ledger is keyed by."""
    from apps.miners.models import MinerIdentity

    MinerIdentity.objects.get_or_create(
        miner_id="node-src",
        defaults={
            "pubkey_hex": "11" * 32,
            "platform_id": "aa" * 64,
            "chain_node_id": SRC_NODE,
        },
    )
    MinerIdentity.objects.get_or_create(
        miner_id="node-dst",
        defaults={
            "pubkey_hex": "22" * 32,
            "platform_id": "bb" * 64,
            "chain_node_id": DST_NODE,
        },
    )


def _launched_vm(**kwargs) -> Vm:
    """An Active VM on `node-src` with the rows its launch would have
    written: the DECLARED identity binding and the opening custody row."""
    vm = make_vm(**kwargs)
    VmBillingBinding.objects.create(
        vm_id=vm.vm_id,
        node_id_hex=SRC_NODE,
        resource_class="small",
        lease_id=vm.lease_id,
    )
    billing.record_assignment(
        vm_id=vm.vm_id,
        node_id_hex=SRC_NODE,
        at_unix=int(time.time()) - 3600,
        reason=VmBillingAssignment.LAUNCH,
    )
    return vm


def _assignments(vm: Vm) -> list[VmBillingAssignment]:
    return list(
        VmBillingAssignment.objects.filter(vm_id=vm.vm_id).order_by(
            "effective_from_unix", "created_at"
        )
    )


def _start(vm: Vm) -> MigrationJob:
    return service.start_migration(
        vm=vm, dest_node_id="node-dst", decided_by=make_service_client()
    )


def _drive(job: MigrationJob, ticks: int = 25) -> MigrationJob:
    for _ in range(ticks):
        service.tick_once()
        job.refresh_from_db()
        if job.state in (MigrationState.DONE.value, MigrationState.FAILED.value):
            break
    return job


# ─── the fix ─────────────────────────────────────────────────────────


def test_a_completed_migration_credits_the_destination(fx: FakeEffects) -> None:
    vm = _launched_vm(generation=5, host="node-src")

    job = _drive(_start(vm))

    assert job.state == MigrationState.DONE.value
    vm.refresh_from_db()
    assert vm.host == "node-dst"
    rows = _assignments(vm)
    assert [r.node_id_hex for r in rows] == [SRC_NODE, DST_NODE]
    assert rows[-1].reason == VmBillingAssignment.MIGRATION
    # And that is what the meter now resolves for post-cutover seconds.
    assert (
        billing.credited_node_id(
            vm_id=vm.vm_id,
            at_unix=int(timezone.now().timestamp()) + 60,
            fallback_node_id_hex=SRC_NODE,
        )
        == DST_NODE
    )


def test_the_launch_binding_is_NOT_re_pointed(fx: FakeEffects) -> None:
    """`VmBillingBinding` is the identity the GUEST declares, read from
    its SNP-measured cmdline — which §25 carries to the destination
    verbatim. A migrated guest keeps declaring its launch node in its
    served receipts AND its KBS-signed live attestations, so re-pointing
    this row would make both fail their match and bill NOTHING."""
    vm = _launched_vm(generation=5, host="node-src")

    _drive(_start(vm))

    binding = VmBillingBinding.objects.get(vm_id=vm.vm_id)
    assert binding.node_id_hex == SRC_NODE


# ─── the accrual boundary ────────────────────────────────────────────


def test_the_cutover_lands_between_the_source_stopping_and_the_dest_booting(
    fx: FakeEffects, monkeypatch
) -> None:
    """The load-bearing timing claim: custody moves at the instant the job
    entered `DestActivating` — after the source's VERIFIED stopped-ack,
    and before the destination is even told to restore. No receipt window
    can straddle it, so no receipt has to be split and none is credited to
    a host that did not serve it.

    Using "now" (the activation CAS) instead would put the cutover AFTER
    the destination had booted and begun emitting receipts."""
    dispatched_at: list[float] = []
    original = effects.dispatch_migrate_activate

    def _record(*args, **kwargs):
        dispatched_at.append(time.time())
        return original(*args, **kwargs)

    monkeypatch.setattr(effects, "dispatch_migrate_activate", _record)
    # Hold the destination in its restore so the activation happens on a
    # LATER tick than the dispatch — the gap the wrong timestamp would
    # mis-credit.
    fx.dest_activation_status = "running"

    vm = _launched_vm(generation=5, host="node-src")
    job = _start(vm)
    for _ in range(10):
        service.tick_once()
        job.refresh_from_db()
        if job.state == MigrationState.DEST_ACTIVATING.value and dispatched_at:
            break
    assert job.state == MigrationState.DEST_ACTIVATING.value
    phase_started_at = job.phase_started_at

    time.sleep(1.1)  # the destination's restore + boot
    fx.dest_activation_status = "done"
    job = _drive(job)
    assert job.state == MigrationState.DONE.value

    cutover = _assignments(vm)[-1].effective_from_unix
    # Before the destination was told to boot …
    assert cutover <= int(dispatched_at[0])
    # … and it is the DestActivating stamp, which the polling ticks did
    # not drag forward.
    assert cutover == int(phase_started_at.timestamp())
    assert cutover < int(timezone.now().timestamp())


def test_the_source_keeps_everything_it_served_before_the_cutover(
    fx: FakeEffects,
) -> None:
    """A receipt for a pre-cutover window — the shutdown drain, or a
    backlogged one — still resolves to the source AFTER the migration is
    Done. Fixing the future must not re-attribute the past."""
    vm = _launched_vm(generation=5, host="node-src")

    job = _drive(_start(vm))
    assert job.state == MigrationState.DONE.value

    cutover = _assignments(vm)[-1].effective_from_unix
    assert (
        billing.credited_node_id(
            vm_id=vm.vm_id, at_unix=cutover - 1, fallback_node_id_hex=""
        )
        == SRC_NODE
    )


# ─── nothing rebinds unless the CAS actually moved the VM ────────────


def test_a_failed_migration_does_not_move_custody(fx: FakeEffects) -> None:
    # The destination reports its restore/boot FAILED. §25 fails closed:
    # the VM is never activated (it stays fenced on the source), and the
    # step retries until its phase timeout — at no point may custody move.
    fx.dest_activation_status = "failed"
    vm = _launched_vm(generation=5, host="node-src")

    job = _drive(_start(vm))

    assert job.state != MigrationState.DONE.value
    vm.refresh_from_db()
    assert vm.state == VmState.MIGRATING  # never activated
    assert [r.node_id_hex for r in _assignments(vm)] == [SRC_NODE]


def test_an_aborted_activation_does_not_move_custody(fx: FakeEffects) -> None:
    """The dest never even accepts the order — the VM stays fenced on the
    source, so the source must stay the miner credited."""
    fx.fail.add("dispatch_migrate_activate")
    vm = _launched_vm(generation=5, host="node-src")

    _drive(_start(vm), ticks=10)

    vm.refresh_from_db()
    assert vm.state == VmState.MIGRATING
    assert [r.node_id_hex for r in _assignments(vm)] == [SRC_NODE]


def test_a_lost_cas_moves_neither_the_host_nor_the_custody(
    fx: FakeEffects, monkeypatch
) -> None:
    """Custody rides INSIDE the activation CAS. When the CAS loses (the
    row moved under us), the VM did not activate — and nothing may be
    credited to a destination that may never have taken over.

    Forced by bumping `Vm.version` from inside the UPDATE's own argument
    evaluation, which is the only way to lose that race deterministically.
    """
    vm = _launched_vm(generation=5, host="node-src")
    job = _start(vm)
    for _ in range(10):
        service.tick_once()
        job.refresh_from_db()
        if job.state == MigrationState.AWAITING_SOURCE_ACK.value:
            break
    job.refresh_from_db()

    original = service._mop_up_boot_phase

    def _steal_the_row():
        Vm.objects.filter(id=vm.id).update(version=vm.version + 99)
        return original()

    monkeypatch.setattr(service, "_mop_up_boot_phase", _steal_the_row)

    with pytest.raises(service.EffectError):
        service._activate_dest_vm(
            MigrationJob.objects.get(id=job.id)
        )

    vm.refresh_from_db()
    assert vm.state == VmState.MIGRATING
    assert vm.host == "node-src"
    assert [r.node_id_hex for r in _assignments(vm)] == [SRC_NODE]


def test_an_unnameable_destination_credits_nobody(fx: FakeEffects) -> None:
    """A destination with no registered `chain_node_id` cannot be paid —
    but the tenant's VM must still activate. Custody becomes
    UNATTRIBUTABLE (empty), which the meter reads as "credit nobody",
    rather than being left pointing at a source that no longer runs it."""
    from apps.miners.models import MinerIdentity

    MinerIdentity.objects.filter(miner_id="node-dst").update(chain_node_id="")
    vm = _launched_vm(generation=5, host="node-src")

    job = _drive(_start(vm))

    assert job.state == MigrationState.DONE.value
    vm.refresh_from_db()
    assert vm.host == "node-dst"  # the workload is up
    rows = _assignments(vm)
    assert rows[-1].node_id_hex == ""
    assert (
        billing.credited_node_id(
            vm_id=vm.vm_id,
            at_unix=rows[-1].effective_from_unix + 1,
            fallback_node_id_hex=SRC_NODE,
        )
        == ""
    )


def test_a_re_driven_activation_records_one_move_only(fx: FakeEffects) -> None:
    """Idempotent: re-entering the activation (the early return) appends
    no second custody row."""
    vm = _launched_vm(generation=5, host="node-src")
    job = _drive(_start(vm))

    service._activate_dest_vm(MigrationJob.objects.get(id=job.id))
    service._activate_dest_vm(MigrationJob.objects.get(id=job.id))

    assert [r.node_id_hex for r in _assignments(vm)] == [SRC_NODE, DST_NODE]
