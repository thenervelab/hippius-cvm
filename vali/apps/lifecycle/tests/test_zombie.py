"""Zombie VMs — `apps.lifecycle.zombie` and the quarantine it derives.

A frame from a VM past its §24 crypto-erase proves a miner is still
running a VM it was told to kill. These pin: which VMs count as dead,
what an observation records, when a miner is quarantined and — just as
important — when it is NOT (live VMs, migrating VMs, stale signals, a
confirmed destroy).
"""

from __future__ import annotations

import logging
import secrets
from datetime import timedelta

import pytest
from django.utils import timezone

from apps.identity.models import PrincipalScope, ServiceClient
from apps.lifecycle import zombie
from apps.lifecycle.models import Vm, VmState, ZombieObservation
from apps.miners.models import MinerIdentity, MinerStatus
from apps.orchestration.models import DecommissionJob, DecommissionState

pytestmark = pytest.mark.django_db


@pytest.fixture(autouse=True)
def _no_erase_grace(settings):
    # Most tests reason about a frame arriving well after the erase; the
    # grace itself has its own tests below.
    settings.VALI_ZOMBIE_ERASE_GRACE_S = 0


@pytest.fixture
def caplog(caplog, monkeypatch):
    # `LOGGING` pins `apps` with `propagate: False`; caplog listens on the
    # ROOT logger, so let the zombie ERRORs record through.
    monkeypatch.setattr(logging.getLogger("apps"), "propagate", True)
    return caplog


NODE_A = "aa" * 32
NODE_B = "bb" * 32


def _miner(miner_id: str, node_id: str) -> MinerIdentity:
    return MinerIdentity.objects.create(
        miner_id=miner_id,
        pubkey_hex=secrets.token_hex(32),
        platform_id=secrets.token_hex(8),
        chain_node_id=node_id,
        status=MinerStatus.ACTIVE.value,
    )


def _vm(vm_id: str, *, state: str = VmState.ACTIVE, host: str = "miner-a") -> Vm:
    return Vm.objects.create(
        vm_id=vm_id,
        lease_id=f"lease-{vm_id}",
        state=state,
        generation=1,
        new_generation=2 if state == VmState.MIGRATING else None,
        migration_dest="miner-b" if state == VmState.MIGRATING else "",
        host=host,
        lifecycle_vk=bytes(32),
    )


def _job(
    vm: Vm,
    *,
    state: str = DecommissionState.CRYPTO_ERASING.value,
    erased: bool = False,
    finished_at=None,
) -> DecommissionJob:
    now = timezone.now()
    return DecommissionJob.objects.create(
        job_id=secrets.token_hex(16),
        vm=vm,
        state=state,
        phase_started_at=now,
        finished_at=finished_at,
        kek_erased_at=now if erased else None,
        decided_by=ServiceClient.objects.create(
            scope=PrincipalScope.OPERATOR.value, name=f"op-{secrets.token_hex(4)}"
        ),
    )


# ─── which VMs are dead ──────────────────────────────────────────────


def test_active_and_migrating_vms_are_never_erased() -> None:
    assert not zombie.kek_erased(_vm("vm-active"))
    assert not zombie.kek_erased(_vm("vm-mig", state=VmState.MIGRATING))


def test_a_destroyed_vm_is_erased() -> None:
    assert zombie.kek_erased(_vm("vm-dead", state=VmState.DESTROYED, host=""))


def test_a_write_after_the_tombstone_does_not_move_its_erase_time() -> None:
    """With no job to date it, a tombstone is dated by the stamp its CAS
    set — not `updated_at`, which a liveness frame from the zombie itself
    would push forward on every write, keeping it inside its grace."""
    vm = _vm("vm-oob", state=VmState.DESTROYED, host="")
    died = timezone.now() - timedelta(hours=1)
    Vm.objects.filter(pk=vm.pk).update(power_state="off", power_state_at=died)
    Vm.objects.filter(pk=vm.pk).update(guest_signal_at=timezone.now())
    vm.refresh_from_db()
    assert zombie.erased_at(vm) == died


@pytest.mark.parametrize(
    "state",
    [DecommissionState.DRAINING.value, DecommissionState.AWAITING_EOL_ACK.value],
)
def test_a_decommissioning_vm_before_its_erase_is_still_live(state: str) -> None:
    # The guest legitimately runs — and bills — until it acks the stop.
    vm = _vm("vm-drain", state=VmState.DECOMMISSIONING)
    _job(vm, state=state)
    assert not zombie.kek_erased(vm)


def test_a_decommissioning_vm_without_any_job_is_not_ours_to_call_dead() -> None:
    assert not zombie.kek_erased(_vm("vm-orphan", state=VmState.DECOMMISSIONING))


def test_the_erase_stamp_marks_a_decommissioning_vm_dead() -> None:
    vm = _vm("vm-erased", state=VmState.DECOMMISSIONING)
    _job(vm, erased=True)
    assert zombie.kek_erased(vm)


@pytest.mark.parametrize(
    "state", [DecommissionState.REVOKING_NETBIRD.value, DecommissionState.DONE.value]
)
def test_a_job_past_the_erase_step_marks_the_vm_dead_even_without_a_stamp(
    state: str,
) -> None:
    # Jobs that ran their erase before the stamp existed.
    vm = _vm("vm-past", state=VmState.DECOMMISSIONING)
    done = state == DecommissionState.DONE.value
    _job(vm, state=state, finished_at=timezone.now() if done else None)
    assert zombie.kek_erased(vm)


# ─── observations ────────────────────────────────────────────────────


def test_observe_attributes_to_the_relaying_miner_and_counts(caplog) -> None:
    _miner("miner-b", NODE_B)
    vm = _vm("vm-z", state=VmState.DESTROYED, host="")
    with caplog.at_level(logging.ERROR, logger="apps.lifecycle.zombie"):
        zombie.observe(vm, kind="vm_progress", relay_miner_id="miner-b")
        zombie.observe(vm, kind="vm_progress", relay_miner_id="miner-b")
    row = ZombieObservation.objects.get(vm_id="vm-z")
    assert (row.miner_id, row.miner_node_id, row.attribution) == ("miner-b", NODE_B, "peer")
    assert row.count == 2
    # One ERROR per VM per window, not one per frame.
    assert sum("ZOMBIE VM" in r.getMessage() for r in caplog.records) == 1


def test_observe_falls_back_to_the_destroy_target(monkeypatch) -> None:
    _miner("miner-a", NODE_A)
    vm = _vm("vm-z", state=VmState.DECOMMISSIONING, host="miner-a")
    _job(vm, erased=True)
    zombie.observe(vm, kind="vm_live_attestation")
    row = ZombieObservation.objects.get(vm_id="vm-z")
    assert (row.miner_id, row.miner_node_id, row.attribution) == (
        "miner-a",
        NODE_A,
        "destroy-target",
    )


def test_observe_realerts_after_the_window(caplog, settings) -> None:
    settings.VALI_ZOMBIE_WINDOW_S = 60
    _miner("miner-a", NODE_A)
    vm = _vm("vm-z", state=VmState.DESTROYED, host="")
    t0 = timezone.now()
    with caplog.at_level(logging.ERROR, logger="apps.lifecycle.zombie"):
        zombie.observe(vm, kind="vm_live_attestation", relay_miner_id="miner-a", now=t0)
        zombie.observe(
            vm, kind="vm_live_attestation", relay_miner_id="miner-a", now=t0 + timedelta(seconds=30)
        )
        zombie.observe(
            vm, kind="vm_live_attestation", relay_miner_id="miner-a", now=t0 + timedelta(seconds=61)
        )
    assert sum("ZOMBIE VM" in r.getMessage() for r in caplog.records) == 2


# ─── the derived quarantine ──────────────────────────────────────────


def test_a_fresh_signal_quarantines_the_miner() -> None:
    _miner("miner-a", NODE_A)
    vm = _vm("vm-z", state=VmState.DECOMMISSIONING, host="miner-a")
    _job(vm, erased=True)
    zombie.observe(vm, kind="vm_live_attestation")
    assert zombie.quarantined_node_ids() == frozenset({NODE_A})


def test_the_quarantine_lifts_once_the_signal_is_stale(settings) -> None:
    settings.VALI_ZOMBIE_WINDOW_S = 900
    _miner("miner-a", NODE_A)
    vm = _vm("vm-z", state=VmState.DESTROYED, host="")
    zombie.observe(vm, kind="vm_live_attestation", relay_miner_id="miner-a")
    later = timezone.now() + timedelta(seconds=901)
    assert zombie.quarantined_node_ids(later) == frozenset()


def test_a_confirmed_destroy_lifts_the_quarantine() -> None:
    _miner("miner-a", NODE_A)
    vm = _vm("vm-z", state=VmState.DESTROYED, host="")
    t0 = timezone.now()
    zombie.observe(vm, kind="vm_live_attestation", relay_miner_id="miner-a", now=t0)
    # The §24 job finishes AFTER the last frame: the destroy took.
    _job(vm, state=DecommissionState.DONE.value, finished_at=t0 + timedelta(seconds=5))
    assert zombie.quarantined_node_ids(t0 + timedelta(seconds=10)) == frozenset()


def test_a_frame_after_a_done_destroy_keeps_the_quarantine(settings) -> None:
    # The miner acknowledged the destroy and the guest is STILL talking.
    settings.VALI_ZOMBIE_CONFIRM_GRACE_S = 60
    _miner("miner-a", NODE_A)
    vm = _vm("vm-z", state=VmState.DESTROYED, host="")
    t0 = timezone.now()
    _job(vm, state=DecommissionState.DONE.value, finished_at=t0)
    zombie.observe(
        vm, kind="vm_live_attestation", relay_miner_id="miner-a", now=t0 + timedelta(seconds=120)
    )
    assert zombie.quarantined_node_ids(t0 + timedelta(seconds=130)) == frozenset({NODE_A})


def test_a_row_whose_vm_is_live_again_holds_nobody() -> None:
    _miner("miner-a", NODE_A)
    vm = _vm("vm-z", state=VmState.DESTROYED, host="")
    zombie.observe(vm, kind="vm_live_attestation", relay_miner_id="miner-a")
    Vm.objects.filter(pk=vm.pk).update(state=VmState.ACTIVE)
    assert zombie.quarantined_node_ids() == frozenset()


def test_an_unattributable_observation_quarantines_nobody_but_is_counted() -> None:
    vm = _vm("vm-z", state=VmState.DESTROYED, host="")
    zombie.observe(vm, kind="vm_live_attestation", relay_miner_id="unknown-miner")
    assert zombie.quarantined_node_ids() == frozenset()
    assert [r.vm_id for r in zombie.fresh_observations()] == ["vm-z"]


# ─── enforcement points ──────────────────────────────────────────────


def test_placement_skips_a_quarantined_miner_and_says_why() -> None:
    from apps.scheduler.placement import PlacementError, decide_placement
    from apps.scheduler.tests.factories import make_miner, make_snapshot

    miners = [make_miner(NODE_A), make_miner(NODE_B)]

    def decide(**kw) -> str:
        return decide_placement(
            snapshot=make_snapshot(10, miners),
            capacity_by_node={m.node_id: 4 for m in miners},
            load_by_node={},
            family_load_by_node={},
            max_epoch_lag=2,
            **kw,
        )

    assert decide(zombie_quarantined=frozenset({NODE_A})) == NODE_B
    with pytest.raises(PlacementError) as exc:
        decide(zombie_quarantined=frozenset({NODE_A, NODE_B}))
    assert "zombie-quarantined" in exc.value.message
    # Inert when nothing is quarantined.
    assert decide(zombie_quarantined=frozenset()) in {NODE_A, NODE_B}


def test_placement_arguments_carry_the_live_quarantine() -> None:
    # The ONE gate-assembly site the launch path and the feasibility
    # check share — so they can never disagree about a zombie miner.
    from apps.scheduler import service
    from apps.scheduler.tests.factories import make_snapshot

    _miner("miner-a", NODE_A)
    vm = _vm("vm-z", state=VmState.DESTROYED, host="")
    zombie.observe(vm, kind="vm_live_attestation", relay_miner_id="miner-a")
    args = service.placement_arguments(
        snapshot=make_snapshot(10, []), tenant_id="t", user_id="u", flavor="small"
    )
    assert args["zombie_quarantined"] == frozenset({NODE_A})


def test_epoch_weights_withhold_a_quarantined_miner(monkeypatch, settings) -> None:
    from apps.scheduler import scoring

    settings.VALI_EPOCH_WEIGHT_SOURCE = "usage"
    monkeypatch.setattr(scoring, "_usage_weights", lambda: {NODE_A: 100, NODE_B: 50})
    assert scoring.compute_epoch_weights() == {NODE_A: 100, NODE_B: 50}

    _miner("miner-a", NODE_A)
    vm = _vm("vm-z", state=VmState.DESTROYED, host="")
    zombie.observe(vm, kind="vm_live_attestation", relay_miner_id="miner-a")
    assert scoring.compute_epoch_weights() == {NODE_B: 50}


def test_the_tick_reports_zombies() -> None:
    from apps.orchestration import service

    _miner("miner-a", NODE_A)
    vm = _vm("vm-z", state=VmState.DESTROYED, host="")
    zombie.observe(vm, kind="vm_live_attestation", relay_miner_id="miner-a")
    report = service.tick_once()
    assert (report.zombie_vms, report.zombie_quarantined_miners) == (1, 1)


def test_the_synthetic_check_fails_while_a_zombie_persists() -> None:
    from apps.synthetic import checks

    assert checks.check_no_zombie_vms in checks.LIGHT_CHECKS
    assert checks.check_no_zombie_vms().ok is True

    _miner("miner-a", NODE_A)
    vm = _vm("vm-z", state=VmState.DESTROYED, host="")
    zombie.observe(vm, kind="vm_live_attestation", relay_miner_id="miner-a")
    result = checks.check_no_zombie_vms()
    assert result.ok is False
    assert "vm-z" in result.detail


# ─── Review follow-ups ───────────────────────────────────────────────


def test_a_frame_within_the_erase_grace_is_not_a_zombie(settings) -> None:
    # The guest's final drain can land just after the erase (the stop ack
    # raced it): honest, and still billable.
    settings.VALI_ZOMBIE_ERASE_GRACE_S = 300
    vm = _vm("vm-z", state=VmState.DECOMMISSIONING)
    job = _job(vm, erased=True)
    assert zombie.kek_erased(vm)
    assert not zombie.is_zombie(vm, job.kek_erased_at + timedelta(seconds=299))
    assert zombie.is_zombie(vm, job.kek_erased_at + timedelta(seconds=300))


def test_the_erase_is_history_wide_across_a_redriven_job() -> None:
    # A redrive opens a NEW job whose own stamp is still empty; the VM was
    # erased by the earlier one and must stay dead.
    vm = _vm("vm-z", state=VmState.DECOMMISSIONING)
    first = _job(vm, state=DecommissionState.FAILED.value, erased=True, finished_at=timezone.now())
    _job(vm, state=DecommissionState.CRYPTO_ERASING.value, erased=False)
    assert zombie.erased_at(vm) == first.kek_erased_at


def test_a_migrated_vms_zombie_is_pinned_on_the_host_it_was_erased_on() -> None:
    # After a §25 move the launch record still names the SOURCE; the
    # destination is where the VM was killed and where it keeps running.
    from apps.orchestration.tests.factories import make_launch_record

    _miner("miner-a", NODE_A)  # the original (launch) host
    _miner("miner-b", NODE_B)  # the §25 destination
    vm = _vm("vm-z", state=VmState.DESTROYED, host="")
    launch = make_launch_record(vm, disk_mode="golden_verity_overlay")
    type(launch).objects.filter(pk=launch.pk).update(miner_id="miner-a")
    from apps.orchestration.effects import destroy_target_miner_id

    assert destroy_target_miner_id(vm) == "miner-a"  # the stale fallback
    job = _job(vm, state=DecommissionState.DONE.value, erased=True, finished_at=timezone.now())
    DecommissionJob.objects.filter(pk=job.pk).update(erase_host="miner-b")

    zombie.observe(vm, kind="vm_live_attestation", now=timezone.now() + timedelta(minutes=5))

    row = ZombieObservation.objects.get(vm_id="vm-z")
    assert (row.miner_id, row.miner_node_id) == ("miner-b", NODE_B)


def test_an_explicit_migration_refuses_a_zombie_quarantined_destination() -> None:
    # The API / CLI name the destination explicitly, so the scheduler's
    # gate never sees this move — `start_migration` must refuse it itself.
    from apps.orchestration import service
    from apps.orchestration.tests.factories import make_service_client

    _miner("miner-a", NODE_A)
    _miner("miner-b", NODE_B)
    _miner("miner-c", "cc" * 32)
    # Same SNP generation for all three (distinct 8-byte CHIP_IDs ⇒ Turin).
    for i, miner_id in enumerate(("miner-a", "miner-b", "miner-c")):
        MinerIdentity.objects.filter(miner_id=miner_id).update(platform_id=f"{i:02x}23456789abcdef")
    dead = _vm("vm-z", state=VmState.DESTROYED, host="")
    zombie.observe(dead, kind="vm_live_attestation", relay_miner_id="miner-a")

    live = _vm("vm-live", host="miner-b")
    with pytest.raises(service.StartError) as exc:
        service.start_migration(vm=live, dest_node_id="miner-a", decided_by=make_service_client())
    assert exc.value.category == "dest-zombie-quarantined"
    # A clean destination passes the zombie guard (it then stops at a later,
    # unrelated intake check this bare fixture does not satisfy).
    with pytest.raises(service.StartError) as clean:
        service.start_migration(vm=live, dest_node_id="miner-c", decided_by=make_service_client())
    assert clean.value.category != "dest-zombie-quarantined"


def test_erase_done_trusts_the_durable_stamp_over_the_idempotency_store(
    monkeypatch,
) -> None:
    from apps.orchestration import service
    from apps.orchestration.idempotency import IdempotencyUnavailable

    def _down(key: str):
        raise IdempotencyUnavailable("store down")

    monkeypatch.setattr(service.idempotency, "recall", _down)
    vm = _vm("vm-z", state=VmState.DECOMMISSIONING)
    stamped = _job(vm, erased=True)
    assert service._erase_done(stamped) is True
    unstamped = _job(_vm("vm-y", state=VmState.DECOMMISSIONING), erased=False)
    assert service._erase_done(unstamped) is False


def test_a_forgeable_receipt_alone_alerts_but_never_quarantines() -> None:
    # A served receipt is signed with a guest key root can extract: a
    # former tenant could forge one to grief its old host. It is refused
    # and counted — but only unforgeable evidence quarantines a miner.
    _miner("miner-a", NODE_A)
    vm = _vm("vm-z", state=VmState.DESTROYED, host="")
    zombie.observe(vm, kind="served_receipt", relay_miner_id="miner-a")
    assert [r.vm_id for r in zombie.fresh_observations()] == ["vm-z"]
    assert zombie.quarantined_node_ids() == frozenset()
    zombie.observe(vm, kind="vm_progress", relay_miner_id="miner-a")
    assert zombie.quarantined_node_ids() == frozenset({NODE_A})


def test_erase_done_sees_an_earlier_jobs_stamp_across_a_redrive(monkeypatch) -> None:
    from apps.orchestration import service
    from apps.orchestration.idempotency import IdempotencyUnavailable

    def _down(key: str):
        raise IdempotencyUnavailable("store down")

    monkeypatch.setattr(service.idempotency, "recall", _down)
    vm = _vm("vm-z", state=VmState.DECOMMISSIONING)
    _job(vm, state=DecommissionState.FAILED.value, erased=True, finished_at=timezone.now())
    redriven = _job(vm, erased=False)
    assert service._erase_done(redriven) is True


def test_fresh_observations_query_count_is_flat_in_the_number_of_zombies() -> None:
    """The fleet readout and the epoch weights read this on every call; a
    zombie incident must not turn it into one query per VM."""
    from django.db import connection
    from django.test.utils import CaptureQueriesContext

    _miner("miner-a", NODE_A)

    def _zombie(i: int) -> None:
        vm = _vm(f"vm-z{i}", state=VmState.DECOMMISSIONING, host="miner-a")
        _job(vm, erased=True)
        _job(
            vm, state=DecommissionState.DONE.value, finished_at=timezone.now() - timedelta(hours=1)
        )
        zombie.observe(vm, kind="vm_live_attestation")

    _zombie(0)
    with CaptureQueriesContext(connection) as one:
        assert len(zombie.fresh_observations()) == 1
    for i in range(1, 6):
        _zombie(i)
    with CaptureQueriesContext(connection) as six:
        assert len(zombie.fresh_observations()) == 6
    assert len(six) == len(one), (len(one), len(six))


def test_a_tombstone_without_off_is_dated_by_its_last_update() -> None:
    """A pod predating `off` tombstones without the power fields: whatever
    `power_state_at` holds then is a stop/start date, not the erase."""
    vm = _vm("vm-old-pod", state=VmState.DESTROYED, host="")
    Vm.objects.filter(pk=vm.pk).update(
        power_state="stopped", power_state_at=timezone.now() - timedelta(days=3)
    )
    vm.refresh_from_db()
    assert zombie.erased_at(vm) == vm.updated_at
