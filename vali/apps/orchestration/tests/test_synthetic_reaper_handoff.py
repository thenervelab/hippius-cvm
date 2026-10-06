"""A forced teardown the synthetic reaper could not deliver is finished by
the orchestration tick: erase → destroy → tombstone, never a zombie."""

from __future__ import annotations

import pytest
from django.test import override_settings

from apps.lifecycle.models import VmState
from apps.orchestration import service
from apps.orchestration.models import DecommissionJob, LaunchJob

from .conftest import FakeEffects
from .factories import make_launch_record, make_service_client, make_vm

pytestmark = pytest.mark.django_db


def _drive(job, n: int = 25) -> None:
    for _ in range(n):
        service.tick_once()
        job.refresh_from_db()
        if job.state in ("done", "failed"):
            return


def _handoff(vm, fx: FakeEffects) -> DecommissionJob:
    from apps.synthetic import e2e

    fx.fail.add("dispatch_destroy")
    detail = e2e._force_destroy(vm.vm_id)
    fx.fail.discard("dispatch_destroy")
    assert "handed-to-tick" in detail, detail
    return DecommissionJob.objects.get(vm=vm)


@pytest.mark.parametrize("fence", [False, True])
def test_the_tick_finishes_a_handed_off_teardown(fx: FakeEffects, fence: bool) -> None:
    with override_settings(VALI_KBS_FENCE_ENABLED=fence):
        vm = make_vm("vm-r1", host="node-src")
        make_launch_record(vm, decided_by=make_service_client())
        fx.calls.clear()
        job = _handoff(vm, fx)
        assert not fx.did("crypto_erase_kek_transit"), "nothing erased in-process"
        _drive(job)
        assert job.state == "done", job.reason
        assert fx.did("crypto_erase_kek_transit") and fx.did("dispatch_destroy")
        vm.refresh_from_db()
        assert vm.state == VmState.DESTROYED


def test_a_vm_no_miner_ever_ran_completes_without_a_destroy(fx: FakeEffects) -> None:
    vm = make_vm("vm-r2", host="")
    lj = make_launch_record(vm, decided_by=make_service_client())
    LaunchJob.objects.filter(id=lj.id).update(miner_id="")
    job = _handoff(vm, fx)
    _drive(job)
    assert job.state == "done"
    assert job.reason == "destroy-skipped:no-miner-ever-recorded"


def test_a_reap_during_the_handed_off_job_leaves_it_alone(fx: FakeEffects) -> None:
    from apps.synthetic import e2e

    vm = make_vm("vm-r4", host="node-src")
    make_launch_record(vm, decided_by=make_service_client())
    _handoff(vm, fx)
    fx.calls.clear()
    assert "left-to-in-flight-job" in e2e._force_destroy(vm.vm_id)
    assert not fx.did("crypto_erase_kek_transit")
    assert not fx.did("dispatch_destroy")


def test_no_decider_still_kills_the_data_but_never_tombstones(fx: FakeEffects) -> None:
    from apps.synthetic import e2e

    vm = make_vm("vm-r3", host="node-src")
    fx.fail.add("dispatch_destroy")
    detail = e2e._force_destroy(vm.vm_id)
    assert "no-decider" in detail
    assert fx.did("crypto_erase_kek_transit")
    vm.refresh_from_db()
    assert vm.state == VmState.DECOMMISSIONING


def test_a_failed_handed_off_job_is_left_to_the_stranded_sweep(fx: FakeEffects) -> None:
    """The sweep re-drives it under its own cap; the reaper opening a new job
    every cycle would bypass that cap."""
    from apps.orchestration.models import DecommissionState
    from apps.synthetic import e2e

    vm = make_vm("vm-r5", host="node-src")
    make_launch_record(vm, decided_by=make_service_client())
    job = _handoff(vm, fx)
    from django.utils import timezone

    DecommissionJob.objects.filter(id=job.id).update(
        state=DecommissionState.FAILED.value, finished_at=timezone.now()
    )
    fx.fail.add("dispatch_destroy")
    assert "left-to-stranded-sweep" in e2e._force_destroy(vm.vm_id)
    assert DecommissionJob.objects.filter(vm=vm).count() == 1
