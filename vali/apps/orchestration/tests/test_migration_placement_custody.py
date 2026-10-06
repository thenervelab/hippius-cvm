"""§25 — the §23 `Placement` follows the VM, atomically with `Vm.host`.

The defect: `Placement` was written only by the launch path, so after a
completed migration `Vm.host` named the destination while the BOUND
placement still named the SOURCE — forever. The consequence with real
operational teeth is the graceful-exit drain: it enrols by BOUND
placement, so draining the DESTINATION missed every VM that had been
migrated onto it, and draining the SOURCE chased VMs that had already
left. A miner asking to exit cleanly would simply not be drained.

These drive the REAL `start_migration` → `tick_once` choreography, so a
fix that never reaches the migration path fails here. The ledger
mechanics + the reward/fit-gate consumers are pinned in
`apps/scheduler/tests/test_placement_custody.py`.
"""

from __future__ import annotations

from typing import Any

import pytest
from django.utils import timezone

from apps.lifecycle.models import Vm, VmPowerState, VmState
from apps.orchestration import service
from apps.orchestration.models import MigrationJob, MigrationState
from apps.scheduler.models import (
    ACTIVE_PLACEMENT_STATES,
    Placement,
    PlacementStatus,
)

from .conftest import FakeEffects
from .factories import make_service_client, make_vm

pytestmark = pytest.mark.django_db

SRC_NODE = "aa" * 32
DST_NODE = "bb" * 32
THIRD_NODE = "cc" * 32


@pytest.fixture(autouse=True)
def _registered_miners():
    """Source + destination registered, one CPU generation (§25's same-gen
    gate resolves it from the CHIP_ID length), each with the chain
    `node_id` the §23 placement ledger is keyed by."""
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


def _placed_vm(**kwargs) -> Vm:
    """An Active VM on `node-src` with the §23 placement its launch wrote."""
    vm = make_vm(**kwargs)
    Placement.objects.create(
        vm=vm,
        vm_family="tenant-1",
        owner="user-1",
        resource_class="small",
        miner_node_id=SRC_NODE,
        status=PlacementStatus.BOUND.value,
        chain_epoch=10,
        bound_at=timezone.now(),
        kbs_release_ref="order-launch",
        decided_by=make_service_client(),
    )
    return vm


def _active(vm: Vm) -> list[Placement]:
    return list(
        Placement.objects.filter(
            vm=vm, status__in=ACTIVE_PLACEMENT_STATES
        ).order_by("decided_at")
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


def test_a_completed_migration_moves_the_placement(fx: FakeEffects) -> None:
    vm = _placed_vm(generation=5, host="node-src")

    job = _drive(_start(vm))

    assert job.state == MigrationState.DONE.value
    vm.refresh_from_db()
    assert vm.host == "node-dst"
    active = _active(vm)
    assert [p.miner_node_id for p in active] == [DST_NODE]
    assert active[0].status == PlacementStatus.BOUND.value
    # The launch row is CLOSED, not re-pointed — it keeps its own audit
    # trail and links to the job that moved the VM.
    closed = Placement.objects.get(miner_node_id=SRC_NODE)
    assert closed.status == PlacementStatus.MIGRATED.value
    assert closed.reason == f"migrated:{job.job_id}"
    assert closed.kbs_release_ref == "order-launch"


# ─── consequence 3 — the graceful-exit drain ─────────────────────────


def _drain_enrolments(monkeypatch, *, departing: str) -> list[str]:
    """Run the real graceful-exit enrolment with `departing` quarantined,
    recording which VMs it would migrate.

    `decide_placement` + `start_migration` are stubbed so the test pins
    exactly one thing: WHICH VMs the drain finds. Everything upstream of
    that — the `Bound`-placement query it enrols by — is real.
    """
    from apps.miners.models import MinerIdentity
    from apps.scheduler.chain import ChainSnapshot, MinerView

    MinerIdentity.objects.get_or_create(
        miner_id="node-third",
        defaults={
            "pubkey_hex": "33" * 32,
            "platform_id": "cc" * 64,
            "chain_node_id": THIRD_NODE,
        },
    )
    snapshot = ChainSnapshot(
        current_epoch=10,
        miners=tuple(
            MinerView(
                node_id=nid,
                status="quarantined" if nid == departing else "active",
                last_transition_epoch=10,
                data_epoch=10,
                quality=1,
            )
            for nid in (SRC_NODE, DST_NODE, THIRD_NODE)
        ),
    )
    # `enroll_departing_miner_migrations` imports both of these INSIDE the
    # function, so the module attribute is what it binds at call time.
    monkeypatch.setattr(
        "apps.scheduler.chain.read_miner_status", lambda: snapshot
    )
    monkeypatch.setattr(
        "apps.scheduler.placement.decide_placement", lambda **kw: THIRD_NODE
    )
    seen: list[str] = []

    def _fake_start(*, vm, dest_node_id, decided_by, cold=False):
        seen.append(vm.vm_id + (":cold" if cold else ""))
        return type("J", (), {"job_id": "fake-job"})()

    monkeypatch.setattr(service, "start_migration", _fake_start)
    service.enroll_departing_miner_migrations()
    return seen


def test_the_drain_of_the_destination_finds_the_migrated_vm(
    fx: FakeEffects, monkeypatch
) -> None:
    """THE operational consequence. Before the fix the VM's only Bound
    placement named the SOURCE, so a destination asking to exit cleanly
    was told it held nothing — and its tenant VMs were never vacated."""
    vm = _placed_vm(generation=5, host="node-src")
    assert _drive(_start(vm)).state == MigrationState.DONE.value

    assert _drain_enrolments(monkeypatch, departing=DST_NODE) == [vm.vm_id]


def test_the_drain_of_the_source_no_longer_chases_a_vm_that_left(
    fx: FakeEffects, monkeypatch
) -> None:
    vm = _placed_vm(generation=5, host="node-src")
    assert _drive(_start(vm)).state == MigrationState.DONE.value

    assert _drain_enrolments(monkeypatch, departing=SRC_NODE) == []


# ─── nothing moves unless the CAS actually moved the VM ──────────────


def test_a_failed_migration_does_not_move_the_placement(fx: FakeEffects) -> None:
    # The destination reports its restore/boot FAILED. §25 fails closed:
    # the VM is never activated (it stays fenced on the source), so the
    # placement must stay on the source too.
    fx.dest_activation_status = "failed"
    vm = _placed_vm(generation=5, host="node-src")

    job = _drive(_start(vm))

    assert job.state != MigrationState.DONE.value
    vm.refresh_from_db()
    assert vm.state == VmState.MIGRATING
    assert [p.miner_node_id for p in _active(vm)] == [SRC_NODE]


def test_an_aborted_activation_does_not_move_the_placement(
    fx: FakeEffects,
) -> None:
    """The dest never even accepts the order — the VM stays fenced on the
    source, which therefore keeps holding it on its books."""
    fx.fail.add("dispatch_migrate_activate")
    vm = _placed_vm(generation=5, host="node-src")

    _drive(_start(vm), ticks=10)

    vm.refresh_from_db()
    assert vm.state == VmState.MIGRATING
    assert [p.miner_node_id for p in _active(vm)] == [SRC_NODE]


def test_a_lost_cas_moves_neither_the_host_nor_the_placement(
    fx: FakeEffects, monkeypatch
) -> None:
    """The placement rides INSIDE the activation CAS. When the CAS loses
    (the row moved under us) the VM did not activate — and the ledger must
    not hand the VM to a destination that may never have taken over.

    Forced by bumping `Vm.version` from inside the UPDATE's own argument
    evaluation, which is the only way to lose that race deterministically.
    """
    vm = _placed_vm(generation=5, host="node-src")
    job = _start(vm)
    for _ in range(10):
        service.tick_once()
        job.refresh_from_db()
        if job.state == MigrationState.AWAITING_SOURCE_ACK.value:
            break

    original = service._mop_up_boot_phase

    def _steal_the_row():
        Vm.objects.filter(id=vm.id).update(version=vm.version + 99)
        return original()

    monkeypatch.setattr(service, "_mop_up_boot_phase", _steal_the_row)

    with pytest.raises(service.EffectError):
        service._activate_dest_vm(MigrationJob.objects.get(id=job.id))

    vm.refresh_from_db()
    assert vm.state == VmState.MIGRATING
    assert vm.host == "node-src"
    assert [p.miner_node_id for p in _active(vm)] == [SRC_NODE]


def test_the_host_and_the_placement_move_in_ONE_transaction(
    fx: FakeEffects, monkeypatch
) -> None:
    """The atomicity claim, from the other side: if the placement cannot
    move, `Vm.host` does not move either. A placement written AFTER the
    CAS (or in its own transaction) would leave a window — and, on a
    failure, a permanent state — where the destination runs the VM and the
    scheduler still bills, counts and drains the source."""
    from apps.scheduler import service as sched

    vm = _placed_vm(generation=5, host="node-src")
    job = _start(vm)
    for _ in range(10):
        service.tick_once()
        job.refresh_from_db()
        if job.state == MigrationState.AWAITING_SOURCE_ACK.value:
            break

    def _boom(*args: Any, **kwargs: Any):
        raise sched.PlacementMoveConflict("injected")

    monkeypatch.setattr(sched, "move_placement_to_node", _boom)

    with pytest.raises(service.EffectError):
        service._activate_dest_vm(MigrationJob.objects.get(id=job.id))

    vm.refresh_from_db()
    assert vm.host == "node-src"
    assert vm.state == VmState.MIGRATING
    assert [p.miner_node_id for p in _active(vm)] == [SRC_NODE]


def test_a_re_driven_activation_does_not_duplicate_the_placement(
    fx: FakeEffects,
) -> None:
    vm = _placed_vm(generation=5, host="node-src")
    job = _drive(_start(vm))

    service._activate_dest_vm(MigrationJob.objects.get(id=job.id))
    service._activate_dest_vm(MigrationJob.objects.get(id=job.id))

    assert [p.miner_node_id for p in _active(vm)] == [DST_NODE]
    assert Placement.objects.filter(vm=vm).count() == 2


def test_an_unnameable_destination_keeps_the_source_placement(
    fx: FakeEffects,
) -> None:
    """A destination with no registered `chain_node_id`: the tenant's VM
    must still activate, but the VM must NOT be left with NO active
    placement — that would make it invisible to the #668 fit gate and let
    the destination be oversubscribed by exactly this VM (the #939 hazard
    by another route)."""
    from apps.miners.models import MinerIdentity

    MinerIdentity.objects.filter(miner_id="node-dst").update(chain_node_id="")
    vm = _placed_vm(generation=5, host="node-src")

    job = _drive(_start(vm))

    assert job.state == MigrationState.DONE.value
    vm.refresh_from_db()
    assert vm.host == "node-dst"  # the workload is up
    assert [p.miner_node_id for p in _active(vm)] == [SRC_NODE]


# ─── reboot-recovery must not open a second placement ────────────────


def test_reboot_recovery_relaunch_creates_no_second_placement(
    fx: FakeEffects, monkeypatch
) -> None:
    """Reboot-recovery re-runs `launch_on_miner` on the SAME host. That
    path writes no placement — and must not start, or the VM would be
    counted TWICE against its own miner in the fit gate."""
    from types import SimpleNamespace

    from apps.orchestration.models import LaunchJob, LaunchJobState
    from apps.orchestration.services import launch
    from apps.orchestration.services import vault_kv as vk

    vm = _placed_vm(generation=5, host="node-src")
    assert _drive(_start(vm)).state == MigrationState.DONE.value
    before = list(Placement.objects.filter(vm=vm).values_list("id", flat=True))

    LaunchJob.objects.create(
        job_id="succ1",
        vm_id=vm.vm_id,
        tenant_id="tenant-1",
        flavor="small",
        spec_json={
            "tenant_id": "tenant-1",
            "user_id": "user-1",
            "vm_id": vm.vm_id,
            "lease_id": vm.lease_id,
            "s3_bucket": "b",
            "s3_key_prefix": "p",
            "luks_disk_sha256_hex": "a" * 64,
            "kernel_sha256_hex": "b" * 64,
            "initrd_sha256_hex": "c" * 64,
            "luks_header_sha256_hex": "d" * 64,
            "flavor": "small",
            "cmdline": "console=ttyS0",
        },
        userdata_vault_path=f"x/{vm.vm_id}/userdata",
        userdata_vault_version=1,
        kek_vault_path=f"x/{vm.vm_id}/luks-kek",
        state=LaunchJobState.SUCCEEDED.value,
        phase_started_at=timezone.now(),
        finished_at=timezone.now(),
        decided_by=make_service_client(),
    )
    monkeypatch.setattr(vk, "get_kv", lambda mount, path, version=None: b"user-data")
    monkeypatch.setattr(
        launch,
        "launch_on_miner",
        lambda spec, m, **_kw: SimpleNamespace(disposition=launch.ACCEPTED),
    )

    assert service._reboot_recovery_relaunch(vm, "node-dst") is True

    assert list(Placement.objects.filter(vm=vm).values_list("id", flat=True)) == before


# ── a stopped VM is never put into §25 (#1150) ───────────────────────


@pytest.mark.parametrize(
    "power_state",
    [VmPowerState.STOPPED, VmPowerState.STOPPING, VmPowerState.STARTING],
)
def test_a_vm_that_is_not_running_cannot_be_migrated(
    fx: FakeEffects, power_state
) -> None:
    """§25 activates the destination only on the running source guest's
    signed stopped-ack. A stopped VM has no guest: the job would time out
    with the VM fenced in `Migrating` — unstartable, data behind an
    operator recovery."""
    vm = _placed_vm(generation=5, host="node-src")
    Vm.objects.filter(pk=vm.pk).update(power_state=power_state)
    vm.refresh_from_db()
    with pytest.raises(service.StartError) as exc:
        _start(vm)
    assert exc.value.category == "vm-not-running"
    vm.refresh_from_db()
    assert vm.state == VmState.ACTIVE, "the VM must not be fenced"


def test_the_departing_miner_drain_migrates_a_stopped_vm_cold(
    fx: FakeEffects, monkeypatch
) -> None:
    """A stopped VM no longer stays behind on a departing miner (#1150): it
    is migrated COLD — started on its source, stopped at the destination."""
    running = _placed_vm(vm_id="vm-running", lease_id="lease-r", generation=5, host="node-src")
    stopped = _placed_vm(vm_id="vm-stopped", lease_id="lease-s", generation=5, host="node-src")
    Vm.objects.filter(pk=stopped.pk).update(power_state=VmPowerState.STOPPED)
    assert sorted(_drain_enrolments(monkeypatch, departing=SRC_NODE)) == [
        running.vm_id,
        f"{stopped.vm_id}:cold",
    ]


def test_the_departing_miner_drain_leaves_a_vm_mid_power_op(fx: FakeEffects, monkeypatch) -> None:
    starting = _placed_vm(vm_id="vm-starting", lease_id="lease-t", generation=5, host="node-src")
    Vm.objects.filter(pk=starting.pk).update(power_state=VmPowerState.STARTING)
    assert _drain_enrolments(monkeypatch, departing=SRC_NODE) == []
