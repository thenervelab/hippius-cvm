"""VM-07 and VM-09 (customer QA 2026-10-12).

VM-07: a backup whose VM was stopped, powered off or relaunched under it
ended `failed qmp-no-domain` and counted as a failure. It is now `skipped`
with why, and a stopped VM owes no backup (`deferred_reason: vm-stopped`).

VM-09: the first full was taken 8 s into the first boot, mid cloud-init:
restored, the VM did not come up. A run now waits for the current boot to
finish (`_boot_gate`), at most `VALI_BACKUP_BOOT_WAIT_MAX_S`."""

from __future__ import annotations

from datetime import datetime, timedelta

import pytest
from django.utils import timezone

from apps.backup import service
from apps.backup.models import BackupPolicy, BackupRun, RunStatus
from apps.lifecycle.models import Vm, VmPowerState

from .conftest import FakeMiner, make_vm

pytestmark = pytest.mark.django_db

HOUR = 3600


class Clock:
    def __init__(self) -> None:
        self.now = timezone.now()

    def advance(self, seconds: float) -> datetime:
        self.now += timedelta(seconds=seconds)
        return self.now


@pytest.fixture
def clock() -> Clock:
    return Clock()


def _tick(clock: Clock) -> service.BackupTickReport:
    report = service.tick(now=clock.now)
    assert report.errors == []
    return report


def _policy(vm) -> BackupPolicy:
    policy, _ = service.put_policy(vm, interval_s=HOUR)
    return policy


def _run() -> BackupRun:
    return BackupRun.objects.order_by("-created_at").first()


def _deferred() -> str:
    return BackupPolicy.objects.get().deferred_reason


# ── VM-09: wait for the boot to finish ───────────────────────────────


def test_the_first_full_waits_for_the_guest_to_finish_booting(
    clock: Clock, fake_miner: FakeMiner
) -> None:
    """The QA case: a policy on a VM 8 s into its first boot."""
    vm = make_vm()
    Vm.objects.filter(pk=vm.pk).update(boot_started_at=clock.now, guest_signal_at=None)
    _policy(vm)
    clock.advance(8)
    assert _tick(clock).started == 0
    assert _deferred() == "first-full-deferred"
    view = service.policy_view(BackupPolicy.objects.get())
    assert view["deferred_reason"] == "first-full-deferred" and view["deferred_since"]
    # A receipt early in the boot is not enough: the guest must still be
    # signalling past the settle window.
    Vm.objects.filter(pk=vm.pk).update(guest_signal_at=clock.advance(30))
    assert _tick(clock).started == 0
    Vm.objects.filter(pk=vm.pk).update(
        guest_signal_at=clock.advance(service._boot_settle().total_seconds())
    )
    assert _tick(clock).started == 1
    assert (
        _deferred() == ""
        and service.policy_view(BackupPolicy.objects.get())["deferred_reason"] is None
    )


def test_a_guest_that_never_signals_is_backed_up_after_the_cap(
    clock: Clock, fake_miner: FakeMiner
) -> None:
    vm = make_vm()
    Vm.objects.filter(pk=vm.pk).update(boot_started_at=clock.now, guest_signal_at=None)
    _policy(vm)
    assert _tick(clock).started == 0
    clock.advance(service._boot_wait_max().total_seconds() - 1)
    assert _tick(clock).started == 0
    clock.advance(2)
    assert _tick(clock).started == 1


def test_after_a_relaunch_the_next_backup_waits_for_the_boot(
    clock: Clock, fake_miner: FakeMiner
) -> None:
    vm = make_vm()
    _policy(vm)
    assert _tick(clock).started == 1
    fake_miner.finish("vm-1")
    assert _tick(clock).completed == 1
    # A power start (or resize, reboot recovery) restamps the boot clock.
    started = clock.advance(2 * HOUR)
    Vm.objects.filter(pk=vm.pk).update(boot_started_at=started, guest_signal_at=started)
    assert _tick(clock).started == 0
    assert _deferred() == "boot-in-progress"
    Vm.objects.filter(pk=vm.pk).update(guest_signal_at=clock.advance(200))
    assert _tick(clock).started == 1


def test_a_guest_reboot_seen_by_the_probe_waits_too(clock: Clock, fake_miner: FakeMiner) -> None:
    vm = make_vm()
    _policy(vm)
    # First seen past its first boot (counter 3): that boot cannot be dated,
    # so the first full waits for a signal after it was seen.
    Vm.objects.filter(pk=vm.pk).update(guest_signal_at=clock.now)
    assert _tick(clock).started == 0
    assert BackupPolicy.objects.get().boot_seen_at == clock.now
    Vm.objects.filter(pk=vm.pk).update(guest_signal_at=clock.advance(200))
    assert _tick(clock).started == 1
    fake_miner.finish("vm-1")
    assert _tick(clock).completed == 1
    fake_miner.boot_counter += 1  # the tenant ran `reboot`
    clock.advance(2 * HOUR)
    assert _tick(clock).started == 0, "the reboot's full waits for that boot"
    assert BackupPolicy.objects.get().boot_seen_at == clock.now
    Vm.objects.filter(pk=vm.pk).update(guest_signal_at=clock.advance(200))
    assert _tick(clock).started == 1


# ── VM-07: a stopped VM owes no backup, a VM gone under a run is no failure ─


def test_a_stopped_vm_is_deferred_not_failed(clock: Clock, fake_miner: FakeMiner) -> None:
    vm = make_vm()
    _policy(vm)
    Vm.objects.filter(pk=vm.pk).update(power_state=VmPowerState.STOPPED)
    assert _tick(clock).started == 0
    assert _deferred() == "vm-stopped"
    assert not BackupRun.objects.exists()
    Vm.objects.filter(pk=vm.pk).update(power_state=VmPowerState.RUNNING)
    assert _tick(clock).started == 1
    assert _deferred() == ""


@pytest.mark.parametrize("error", ["qmp-no-domain", "vm-not-running"])
def test_a_run_whose_vm_was_stopped_under_it_is_skipped(
    clock: Clock, fake_miner: FakeMiner, error: str
) -> None:
    vm = make_vm()
    _policy(vm)
    assert _tick(clock).started == 1
    Vm.objects.filter(pk=vm.pk).update(
        power_state=VmPowerState.STOPPED, power_state_at=clock.advance(30)
    )
    fake_miner.finish("vm-1", status="failed", reason=error)
    report = _tick(clock)
    run = _run()
    assert (run.status, run.reason) == (RunStatus.SKIPPED, "vm-stopped")
    assert report.failed == 0
    assert service._last_failure(vm, BackupPolicy.objects.get()) is None


def test_a_run_whose_vm_was_restarted_under_it_is_skipped_and_the_next_one_runs(
    clock: Clock, fake_miner: FakeMiner
) -> None:
    """The QA case: stop + start while a backup ran, then `qmp-no-domain`
    once the domain was back."""
    vm = make_vm()
    _policy(vm)
    assert _tick(clock).started == 1
    restarted = clock.advance(60)
    Vm.objects.filter(pk=vm.pk).update(
        power_state_at=restarted, boot_started_at=restarted, guest_signal_at=restarted
    )
    fake_miner.finish("vm-1", status="failed", reason="qmp-no-domain")
    assert _tick(clock).failed == 0
    run = _run()
    assert (run.status, run.reason) == (RunStatus.SKIPPED, "vm-restarted")
    assert BackupPolicy.objects.get().full_required
    # After the boot, the next backup is a full, at once (no failure backoff).
    Vm.objects.filter(pk=vm.pk).update(guest_signal_at=clock.advance(200))
    assert _tick(clock).started == 1
    assert _run().kind == "full"


def test_a_domain_missing_with_no_power_change_is_still_a_failure(
    clock: Clock, fake_miner: FakeMiner
) -> None:
    vm = make_vm()
    _policy(vm)
    assert _tick(clock).started == 1
    fake_miner.finish("vm-1", status="failed", reason="qmp-no-domain")
    assert _tick(clock).failed == 0, "held open while no sign of why has reached vali"
    clock.advance(service._domain_gone_grace().total_seconds())
    assert _tick(clock).failed == 1
    assert (_run().status, _run().reason) == (RunStatus.FAILED, "qmp-no-domain")
    from apps.operator import fleet

    assert fleet._backup_attention(clock.now).get("vm-1") == "failing"


def test_a_run_lost_because_the_vm_was_stopped_is_skipped(
    clock: Clock, fake_miner: FakeMiner
) -> None:
    """A power stop undefines the domain: the miner answers 404 and the run
    would read `lost`."""
    vm = make_vm()
    _policy(vm)
    assert _tick(clock).started == 1
    Vm.objects.filter(pk=vm.pk).update(power_state=VmPowerState.STOPPED)
    fake_miner.unknown.add("vm-1")
    clock.advance(service._lost_grace().total_seconds() + 1)
    assert _tick(clock).failed == 0
    assert (_run().status, _run().reason) == (RunStatus.SKIPPED, "vm-stopped")


def test_the_fleet_alert_ignores_a_skipped_run(clock: Clock, fake_miner: FakeMiner) -> None:
    from apps.operator import fleet

    vm = make_vm()
    _policy(vm)
    assert _tick(clock).started == 1
    restarted = clock.advance(60)
    Vm.objects.filter(pk=vm.pk).update(power_state_at=restarted)
    fake_miner.finish("vm-1", status="failed", reason="qmp-no-domain")
    _tick(clock)
    assert BackupRun.objects.filter(status=RunStatus.SKIPPED).count() == 1
    assert not BackupRun.objects.filter(status=RunStatus.FAILED).exists()
    assert fleet._backup_attention(clock.now).get("vm-1") != "failing"


def test_a_guest_poweroff_that_reaches_vali_late_is_still_skipped(
    clock: Clock, fake_miner: FakeMiner
) -> None:
    """Under the `restart` policy the agent restarts the guest itself: vali
    reads `running` throughout, and only the boot counter of the new boot —
    written after its key release — says it rebooted. The run is held open
    until that sign arrives."""
    vm = make_vm()
    _policy(vm)
    assert _tick(clock).started == 1
    fake_miner.finish("vm-1", status="failed", reason="qmp-no-domain")
    clock.advance(30)
    assert _tick(clock).failed == 0
    assert _run().status == RunStatus.RUNNING
    fake_miner.boot_counter += 1  # the new boot wrote its counter
    clock.advance(60)
    _tick(clock)
    skipped = BackupRun.objects.get(status=RunStatus.SKIPPED)
    assert skipped.reason == "vm-restarted"
    del vm


def test_policy_view_hides_the_deferral_of_a_disabled_policy(
    clock: Clock, fake_miner: FakeMiner
) -> None:
    vm = make_vm()
    policy = _policy(vm)
    BackupPolicy.objects.filter(pk=policy.pk).update(
        deferred_reason="vm-stopped", deferred_since=clock.now, enabled=False
    )
    view = service.policy_view(BackupPolicy.objects.get())
    assert view["deferred_reason"] is None and view["deferred_since"] is None


# ── boot_settled on each run (Izori QA round 2) ──────────────────────


def test_each_run_records_whether_the_boot_had_settled(clock: Clock, fake_miner: FakeMiner) -> None:
    fake_miner.boot_counter = 1  # its first boot
    vm = make_vm()
    Vm.objects.filter(pk=vm.pk).update(boot_started_at=clock.now, guest_signal_at=None)
    _policy(vm)
    clock.advance(service._boot_wait_max().total_seconds())  # the cap, no signal
    assert _tick(clock).started == 1
    assert _run().boot_settled is None, "at the cap, no signal: unknown, not mid-boot"
    fake_miner.finish("vm-1")
    _tick(clock)
    Vm.objects.filter(pk=vm.pk).update(guest_signal_at=clock.advance(HOUR))
    assert _tick(clock).started == 1
    assert _run().boot_settled is True
    runs = [r for chain in service.backups_view(vm)["chains"] for r in chain["runs"]]
    assert sorted(runs, key=lambda r: r["seq"])[0]["boot_settled"] is None
    assert sorted(runs, key=lambda r: r["seq"])[-1]["boot_settled"] is True


def test_a_run_from_before_the_flag_reads_null(clock: Clock, fake_miner: FakeMiner) -> None:
    vm = make_vm()
    _policy(vm)
    assert _tick(clock).started == 1
    BackupRun.objects.update(boot_settled=None)
    runs = [r for chain in service.backups_view(vm)["chains"] for r in chain["runs"]]
    assert [r["boot_settled"] for r in runs] == [None]
