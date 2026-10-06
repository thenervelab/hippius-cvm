"""`vali_backfill_tombstone_power_at`: legacy tombstones take their finished
§24 job's date; everything else is left alone."""

from __future__ import annotations

import secrets
from datetime import timedelta
from io import StringIO

import pytest
from django.core.management import CommandError, call_command
from django.db import connection
from django.db.migrations.recorder import MigrationRecorder
from django.utils import timezone

from apps.lifecycle.models import Vm, VmPowerState, VmState
from apps.orchestration.models import DecommissionJob, DecommissionState

from .factories import make_service_client, make_vm

pytestmark = pytest.mark.django_db

NOW = timezone.now()
STALE = NOW - timedelta(days=2)
#: When 0017 "ran": legacy rows are dated no later.
APPLIED = NOW - timedelta(hours=1)


@pytest.fixture(autouse=True)
def _applied_at() -> None:
    MigrationRecorder(connection).migration_qs.update_or_create(
        app="lifecycle", name="0017_vm_power_state_off", defaults={"applied": APPLIED}
    )


def _tombstone(vm_id: str, *, power_at=STALE) -> Vm:
    vm = make_vm(vm_id, host="")
    Vm.objects.filter(pk=vm.pk).update(
        state=VmState.DESTROYED,
        power_state=VmPowerState.OFF,
        power_state_at=power_at,
        updated_at=STALE,
    )
    vm.refresh_from_db()
    return vm


def _job(vm: Vm, *, state: str = DecommissionState.DONE.value, finished_at=NOW) -> None:
    DecommissionJob.objects.create(
        job_id=secrets.token_hex(16),
        vm=vm,
        state=state,
        phase_started_at=finished_at,
        finished_at=finished_at,
        decided_by=make_service_client(),
    )


def _run(*args: str) -> str:
    out = StringIO()
    call_command("vali_backfill_tombstone_power_at", *args, stdout=out)
    return out.getvalue()


def test_a_legacy_tombstone_takes_its_jobs_finish_and_keeps_its_updated_at() -> None:
    vm = _tombstone("vm-legacy")
    _job(vm)

    assert "1 row(s) would be written" in _run()
    vm.refresh_from_db()
    assert vm.power_state_at == STALE, "dry-run writes nothing"

    assert "1 row(s) written of 1" in _run("--commit")
    vm.refresh_from_db()
    assert vm.power_state_at == NOW
    assert vm.updated_at == STALE, "must not jump to the top of the listing"
    assert "0 row(s) written of 0" in _run("--commit"), "idempotent"


def test_the_latest_done_job_dates_it() -> None:
    vm = _tombstone("vm-redriven")
    _job(vm, finished_at=NOW - timedelta(hours=3))
    _job(vm)
    _run("--commit")
    vm.refresh_from_db()
    assert vm.power_state_at == NOW


def test_rows_it_must_not_touch() -> None:
    no_job = _tombstone("vm-no-job")
    failed = _tombstone("vm-failed-job")
    _job(failed, state=DecommissionState.FAILED.value)
    # Stamped by today's CAS, its job finished long after (a stalled tick):
    # a real date, never rewritten.
    fresh = _tombstone("vm-fresh", power_at=APPLIED + timedelta(minutes=1))
    _job(fresh, finished_at=NOW + timedelta(hours=2))
    live = make_vm("vm-live")
    _job(live)

    assert "0 row(s) written of 0" in _run("--commit")
    for vm, expected in ((no_job, STALE), (failed, STALE), (fresh, APPLIED + timedelta(minutes=1))):
        vm.refresh_from_db()
        assert vm.power_state_at == expected, vm.vm_id
    live.refresh_from_db()
    assert live.power_state == VmPowerState.RUNNING and live.power_state_at is None


def test_it_refuses_without_the_migration_to_tell_legacy_rows_by() -> None:
    MigrationRecorder(connection).migration_qs.filter(
        app="lifecycle", name="0017_vm_power_state_off"
    ).delete()
    with pytest.raises(CommandError):
        _run()
