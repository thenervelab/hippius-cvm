"""COLD §25: migrating a tenant-STOPPED VM (Phase B).

The VM is started on its source until its guest proves it booted, migrated
warm, and stopped again once the destination proved it runs."""

from __future__ import annotations

from datetime import timedelta

import pytest
from django.utils import timezone

from apps.lifecycle.models import Vm, VmPowerState, VmState
from apps.orchestration import service
from apps.orchestration.models import MigrationJob, MigrationState, SourceReclaimState
from apps.orchestration.services import power

from .conftest import FakeEffects
from .factories import make_service_client, make_vm
from .test_migration import _drive_until, _same_gen_miners  # noqa: F401 — autouse fixture

pytestmark = pytest.mark.django_db


def _stopped_vm(**kw) -> Vm:
    vm = make_vm(generation=5, host="node-src", **kw)
    Vm.objects.filter(pk=vm.pk).update(power_state=VmPowerState.STOPPED)
    vm.refresh_from_db()
    return vm


class _Power:
    """The power API, faked at its two entry points."""

    def __init__(self, monkeypatch) -> None:
        self.started: list[str] = []
        self.stopped: list[str] = []
        self.refuse: str | None = None
        monkeypatch.setattr(power, "start_vm", self._start)
        monkeypatch.setattr(power, "stop_vm", self._stop)

    def _start(self, vm: Vm, *, by_migration: bool = False) -> Vm:
        self.started.append(vm.vm_id)
        if self.refuse:
            raise power.PowerOpRefused(self.refuse, "refused")
        Vm.objects.filter(pk=vm.pk).update(
            power_state=VmPowerState.RUNNING, power_state_at=timezone.now()
        )
        return vm

    def _stop(self, vm: Vm, *, by_migration: bool = False) -> Vm:
        if self.refuse:
            raise power.PowerOpRefused(self.refuse, "refused")
        self.stopped.append(vm.vm_id)
        Vm.objects.filter(pk=vm.pk).update(
            power_state=VmPowerState.STOPPED, power_state_at=timezone.now()
        )
        return vm


def _start(vm: Vm, *, cold: bool) -> MigrationJob:
    return service.start_migration(
        vm=vm, dest_node_id="node-dst", decided_by=make_service_client(), cold=cold
    )


def _guest_signals(vm: Vm, *, after: MigrationJob) -> None:
    """An in-guest signal ingested after the start landed."""
    Vm.objects.filter(pk=vm.pk).update(guest_signal_at=timezone.now() + timedelta(seconds=5))


# ── intake ───────────────────────────────────────────────────────────


def test_a_stopped_vm_is_refused_unless_cold() -> None:
    vm = _stopped_vm()
    with pytest.raises(service.StartError) as exc:
        _start(vm, cold=False)
    assert exc.value.category == "vm-not-running"

    job = _start(vm, cold=True)
    assert (job.state, job.cold) == (MigrationState.SOURCE_STARTING.value, True)


def test_cold_on_a_running_vm_is_an_ordinary_migration() -> None:
    job = _start(make_vm(generation=5, host="node-src"), cold=True)
    assert (job.state, job.cold) == (MigrationState.DRAINING.value, False)


@pytest.mark.parametrize("power_state", [VmPowerState.STARTING, VmPowerState.STOPPING])
def test_a_vm_mid_power_op_is_refused_even_cold(power_state) -> None:
    vm = make_vm(generation=5, host="node-src")
    Vm.objects.filter(pk=vm.pk).update(power_state=power_state)
    vm.refresh_from_db()
    with pytest.raises(service.StartError):
        _start(vm, cold=True)


# ── SourceStarting ───────────────────────────────────────────────────


def test_the_source_is_started_and_the_job_waits_for_its_guest(
    fx: FakeEffects, monkeypatch
) -> None:
    p = _Power(monkeypatch)
    vm = _stopped_vm()
    job = _start(vm, cold=True)

    service.advance_migration_job(job)
    job.refresh_from_db()
    assert p.started == [vm.vm_id]
    assert job.state == MigrationState.SOURCE_STARTING.value, "started, not yet proven"

    # A signal ingested before the start LANDED — even after the job began —
    # is not proof of this boot.
    MigrationJob.objects.filter(pk=job.pk).update(started_at=timezone.now() - timedelta(hours=1))
    job.refresh_from_db()
    vm.refresh_from_db()
    Vm.objects.filter(pk=vm.pk).update(guest_signal_at=vm.power_state_at - timedelta(seconds=1))
    service.advance_migration_job(job)
    job.refresh_from_db()
    assert job.state == MigrationState.SOURCE_STARTING.value

    _guest_signals(vm, after=job)
    service.advance_migration_job(job)
    job.refresh_from_db()
    assert job.state == MigrationState.DRAINING.value
    assert p.started == [vm.vm_id], "started once"


def test_a_refused_start_retries_then_fails_before_any_fence(fx: FakeEffects, monkeypatch) -> None:
    p = _Power(monkeypatch)
    p.refuse = "recovery-relaunch-in-flight"
    vm = _stopped_vm()
    job = _start(vm, cold=True)

    service.advance_migration_job(job)
    job.refresh_from_db()
    assert job.state == MigrationState.SOURCE_STARTING.value
    service.advance_migration_job(job)
    assert len(p.started) == 1, "one attempt per pacing window, not per tick"

    MigrationJob.objects.filter(pk=job.pk).update(
        phase_started_at=timezone.now() - timedelta(hours=1)
    )
    job.refresh_from_db()
    service.advance_migration_job(job)
    job.refresh_from_db()
    vm.refresh_from_db()
    assert job.state == MigrationState.FAILED.value
    assert vm.state == VmState.ACTIVE, "never fenced"


# ── end to end + settling ────────────────────────────────────────────


def test_a_cold_migration_runs_warm_and_is_stopped_once_the_dest_is_proven(
    fx: FakeEffects, monkeypatch
) -> None:
    p = _Power(monkeypatch)
    vm = _stopped_vm()
    job = _start(vm, cold=True)
    service.advance_migration_job(job)
    job.refresh_from_db()
    _guest_signals(vm, after=job)
    _drive_until(job, MigrationState.DONE.value)
    vm.refresh_from_db()
    assert (vm.host, vm.power_state) == ("node-dst", VmPowerState.RUNNING)

    service.settle_cold_migrations()
    assert p.stopped == [], "the destination has not proved it runs"

    MigrationJob.objects.filter(pk=job.pk).update(
        source_reclaim_state=SourceReclaimState.RECLAIMED.value
    )
    assert service.settle_cold_migrations() == 1
    job.refresh_from_db()
    vm.refresh_from_db()
    assert p.stopped == [vm.vm_id]
    assert vm.power_state == VmPowerState.STOPPED
    assert job.cold_settle_reason == "stopped-at-dest"

    service.settle_cold_migrations()
    assert p.stopped == [vm.vm_id], "settled once"


def _terminal_cold(vm: Vm, state: str, **fields) -> MigrationJob:
    job = _start(vm, cold=True)
    MigrationJob.objects.filter(pk=job.pk).update(state=state, finished_at=timezone.now(), **fields)
    job.refresh_from_db()
    return job


def test_a_failed_cold_migration_back_on_its_source_is_stopped_again(monkeypatch) -> None:
    p = _Power(monkeypatch)
    vm = _stopped_vm()
    job = _terminal_cold(vm, MigrationState.FAILED.value)
    Vm.objects.filter(pk=vm.pk).update(power_state=VmPowerState.RUNNING)

    service.settle_cold_migrations()

    job.refresh_from_db()
    assert p.stopped == [vm.vm_id]
    assert job.cold_settle_reason == "stopped-at-source"


def test_a_stranded_cold_migration_waits_for_the_restore(monkeypatch) -> None:
    p = _Power(monkeypatch)
    vm = _stopped_vm()
    job = _terminal_cold(vm, MigrationState.FAILED.value)
    Vm.objects.filter(pk=vm.pk).update(
        state=VmState.MIGRATING, migration_dest="node-dst", new_generation=job.new_gen,
        power_state=VmPowerState.RUNNING,
    )

    service.settle_cold_migrations()

    job.refresh_from_db()
    assert p.stopped == [] and job.cold_settled_at is None


def test_a_never_proven_destination_is_left_running(monkeypatch) -> None:
    p = _Power(monkeypatch)
    vm = _stopped_vm()
    job = _terminal_cold(
        vm, MigrationState.DONE.value, source_reclaim_state=SourceReclaimState.SKIPPED.value
    )
    Vm.objects.filter(pk=vm.pk).update(power_state=VmPowerState.RUNNING, host="node-dst")

    service.settle_cold_migrations()

    job.refresh_from_db()
    assert p.stopped == []
    assert job.cold_settle_reason == "dest-never-proven:left-running"


def test_a_destroyed_vm_settles_without_a_stop(monkeypatch) -> None:
    p = _Power(monkeypatch)
    vm = _stopped_vm()
    job = _terminal_cold(vm, MigrationState.FAILED.value)
    Vm.objects.filter(pk=vm.pk).update(state=VmState.DESTROYED)

    service.settle_cold_migrations()

    job.refresh_from_db()
    assert p.stopped == [] and job.cold_settle_reason == "vm-destroyed"


def test_a_refused_stop_is_retried(monkeypatch) -> None:
    p = _Power(monkeypatch)
    vm = _stopped_vm()
    job = _terminal_cold(vm, MigrationState.FAILED.value)
    Vm.objects.filter(pk=vm.pk).update(power_state=VmPowerState.RUNNING)
    p.refuse = "already-stopping"

    service.settle_cold_migrations()
    job.refresh_from_db()
    assert job.cold_settled_at is None

    p.refuse = None
    service.settle_cold_migrations()
    job.refresh_from_db()
    assert job.cold_settle_reason == "stopped-at-source"


# ── the operator API ─────────────────────────────────────────────────


def test_the_migrate_api_takes_a_cold_flag(root_client) -> None:
    from django.urls import reverse

    vm = _stopped_vm()
    url = reverse("vm_migrate", kwargs={"vm_id": vm.vm_id})

    resp = root_client.post(url, {"dest_node_id": "node-dst", "cold": "yes"}, format="json")
    assert resp.status_code == 400

    resp = root_client.post(url, {"dest_node_id": "node-dst"}, format="json")
    assert resp.status_code == 409 and resp.json()["category"] == "vm-not-running"

    resp = root_client.post(url, {"dest_node_id": "node-dst", "cold": True}, format="json")
    assert resp.status_code == 202, resp.content
    assert resp.json()["cold"] is True
    assert MigrationJob.objects.get(vm=vm).cold is True


# ── review hardening ─────────────────────────────────────────────────


def test_the_tenant_cannot_power_a_vm_mid_migration(fx: FakeEffects) -> None:
    """Before the fence the VM is still Active: a stop there would leave the
    quiesce nothing to ack and strand the VM `Migrating`."""
    vm = make_vm(generation=5, host="node-src")
    job = _start(vm, cold=False)
    assert job.state == MigrationState.DRAINING.value
    with pytest.raises(power.PowerOpRefused) as exc:
        power.stop_vm(vm)
    assert exc.value.reason == "migration-in-flight"


def test_a_vm_stopped_before_the_fence_fails_the_job_instead_of_stranding(
    fx: FakeEffects,
) -> None:
    vm = make_vm(generation=5, host="node-src")
    job = _start(vm, cold=False)
    Vm.objects.filter(pk=vm.pk).update(power_state=VmPowerState.STOPPED)

    service.advance_migration_job(job)

    job.refresh_from_db()
    vm.refresh_from_db()
    assert job.state == MigrationState.FAILED.value
    assert vm.state == VmState.ACTIVE, "never fenced"


def test_the_cold_intent_follows_a_later_migration(monkeypatch) -> None:
    """A later (warm) job moved the VM before the cold one settled: the VM is
    stopped only once THAT job finished and proved its destination."""
    p = _Power(monkeypatch)
    vm = _stopped_vm()
    old = _terminal_cold(vm, MigrationState.FAILED.value)
    Vm.objects.filter(pk=vm.pk).update(power_state=VmPowerState.RUNNING)
    vm.refresh_from_db()
    newer = service.start_migration(
        vm=vm, dest_node_id="node-dst", decided_by=make_service_client()
    )

    service.settle_cold_migrations()
    assert p.stopped == [], "the later job is still in flight"

    MigrationJob.objects.filter(pk=newer.pk).update(
        state=MigrationState.DONE.value, finished_at=timezone.now()
    )
    service.settle_cold_migrations()
    assert p.stopped == [], "its destination has not proved it runs"

    MigrationJob.objects.filter(pk=newer.pk).update(
        source_reclaim_state=SourceReclaimState.RECLAIMED.value
    )
    service.settle_cold_migrations()
    old.refresh_from_db()
    assert p.stopped == [vm.vm_id]
    assert old.cold_settle_reason == "stopped-at-dest"


def test_a_vm_the_tenant_powered_after_the_migration_is_left_alone(monkeypatch) -> None:
    p = _Power(monkeypatch)
    vm = _stopped_vm()
    job = _terminal_cold(vm, MigrationState.FAILED.value)
    Vm.objects.filter(pk=vm.pk).update(
        power_state=VmPowerState.RUNNING,
        power_state_at=job.finished_at + timedelta(minutes=1),
    )

    service.settle_cold_migrations()

    job.refresh_from_db()
    assert p.stopped == [] and job.cold_settle_reason == "tenant-took-over"


def test_the_drain_does_not_retry_a_recently_failed_cold_migration(monkeypatch) -> None:
    from .test_migration_placement_custody import SRC_NODE, _drain_enrolments, _placed_vm

    vm = _placed_vm(vm_id="vm-cold", lease_id="lease-c", generation=5, host="node-src")
    Vm.objects.filter(pk=vm.pk).update(power_state=VmPowerState.STOPPED)
    vm.refresh_from_db()
    _terminal_cold(vm, MigrationState.FAILED.value)

    assert _drain_enrolments(monkeypatch, departing=SRC_NODE) == []

    MigrationJob.objects.filter(vm=vm).update(finished_at=timezone.now() - timedelta(hours=7))
    assert _drain_enrolments(monkeypatch, departing=SRC_NODE) == ["vm-cold:cold"]
