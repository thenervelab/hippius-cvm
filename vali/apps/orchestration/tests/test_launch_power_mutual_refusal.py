"""Launch intake and the operations that stop/start a VM refuse each other
for the same vm_id, under the Vm row lock.

Pins, per claim:
- `power.launch_in_flight`: a queued launch job, or a running one inside
  the orphan bound, counts; an orphan the janitor left `running` past it
  does not (it must not disable the VM's power for good);
- §25 and restore admission refuse a launch in flight — their own stop/start
  bypass the power API's launch check (`by_migration`); failover does not
  (its host is presumed dead);
- launch intake refuses a VM reboot-recovery is relaunching.
"""

from __future__ import annotations

from datetime import timedelta

import pytest
from django.utils import timezone

from apps.orchestration import launch_jobs, restore, service
from apps.orchestration.models import LaunchJob, LaunchJobState, RebootRecovery
from apps.orchestration.services import power

from .factories import make_service_client, make_vm

pytestmark = [pytest.mark.django_db, pytest.mark.usefixtures("located_fr")]


@pytest.fixture(autouse=True)
def _same_gen_miners():
    from apps.miners.models import MinerIdentity

    MinerIdentity.objects.get_or_create(
        miner_id="node-src", defaults={"pubkey_hex": "aa" * 32, "platform_id": "11" * 64}
    )
    MinerIdentity.objects.get_or_create(
        miner_id="node-dst", defaults={"pubkey_hex": "bb" * 32, "platform_id": "22" * 64}
    )


def _launch_job(vm_id: str, state: str, *, age: timedelta = timedelta(0)) -> LaunchJob:
    started = timezone.now() - age
    return LaunchJob.objects.create(
        job_id=f"lj-{state}-{int(age.total_seconds())}",
        vm_id=vm_id,
        tenant_id="t",
        flavor="small",
        spec_json={},
        userdata_vault_path="x",
        userdata_vault_version=1,
        kek_vault_path="x",
        state=state,
        phase_started_at=started,
        decided_by=make_service_client(),
    )


def test_a_queued_or_fresh_running_launch_counts_an_orphan_does_not(settings) -> None:
    vm = make_vm()
    assert power.launch_in_flight(vm) is False

    queued = _launch_job(vm.vm_id, LaunchJobState.QUEUED.value)
    assert power.launch_in_flight(vm) is True
    queued.delete()

    running = _launch_job(vm.vm_id, LaunchJobState.RUNNING.value)
    assert power.launch_in_flight(vm) is True
    running.delete()

    orphan_age = timedelta(seconds=launch_jobs.launch_job_orphan_after_s() + 60)
    _launch_job(vm.vm_id, LaunchJobState.RUNNING.value, age=orphan_age)
    assert power.launch_in_flight(vm) is False
    # …so it does not hold the VM's power hostage either.
    assert power._claim(vm, "stopping")


def test_migration_admission_refuses_a_launch_in_flight(fx) -> None:
    vm = make_vm(generation=5, host="node-src")
    _launch_job(vm.vm_id, LaunchJobState.QUEUED.value)

    with pytest.raises(service.StartError) as exc:
        service.start_migration(vm=vm, dest_node_id="node-dst", decided_by=make_service_client())
    assert exc.value.category == "job-in-flight"
    assert "launch job in flight" in exc.value.message


def test_restore_and_undo_refuse_a_launch_in_flight_failover_does_not() -> None:
    vm = make_vm()
    _launch_job(vm.vm_id, LaunchJobState.QUEUED.value)

    with pytest.raises(restore.RestoreError, match="launch job in flight"):
        restore._recheck_no_active_job(vm)
    restore._recheck_no_active_job(vm, refuse_launch=False)


def test_launch_intake_refuses_a_vm_reboot_recovery_is_relaunching() -> None:
    vm = make_vm()
    RebootRecovery.objects.create(
        vm=vm, last_outcome=service.RELAUNCH_IN_FLIGHT, last_relaunch_at=timezone.now()
    )

    with pytest.raises(launch_jobs.LaunchIntentError, match="reboot-recovery"):
        launch_jobs._refuse_held(vm)

    # An abandoned mark (older than the power marker bound) does not hold it.
    RebootRecovery.objects.filter(vm=vm).update(
        last_relaunch_at=timezone.now() - power.STALE_POWER_MARKER - timedelta(minutes=1)
    )
    launch_jobs._refuse_held(vm)
