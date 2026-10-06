"""After a resize (any accepted relaunch) the KBS refuses the earlier launch.

Every launch pins its own measurement and mints a ticket that allows only
that measurement; the KBS releases a key only to a measurement in both the
ticket and the §22 allowlist (`kbs_core::snp::check_attestation`, and
`kbs_core::allowlist` `an_evicted_launch_measurement_no_longer_releases`).
So the allowlist carrying a VM's CURRENT launch only — not every
measurement it ever pinned — is what makes a pre-resize ticket useless.

These tests drive the real `pin_measurement` / `refresh_allowlist` against
the fake KBS of `fake_allowlist_kbs` (full replace, epoch HWM).
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

import pytest

from apps.lifecycle.models import VmState
from apps.orchestration.models import MeasurementLedger
from apps.orchestration.services import allowlist_pin
from apps.orchestration.tests.factories import make_vm
from apps.orchestration.tests.fake_allowlist_kbs import BASE_M, FakeKbs, install_fake_kbs

pytestmark = pytest.mark.django_db

SMALL_M = "a" * 96  # the pre-resize launch
LARGE_M = "b" * 96  # the resize relaunch
BACK_M = "c" * 96  # the rollback relaunch, at the old size again
OTHER_M = "d" * 96  # another VM, untouched

T0 = datetime(2026, 10, 4, 12, 0, tzinfo=UTC)


def _job(vm_id: str, measurement: str, started_at: datetime) -> None:
    from apps.lifecycle.models import Vm
    from apps.orchestration.models import LaunchJob
    from apps.orchestration.tests.factories import make_launch_record

    job = make_launch_record(Vm.objects.get(vm_id=vm_id), measurement_hex=measurement)
    LaunchJob.objects.filter(pk=job.pk).update(started_at=started_at)


def _launch(vm_id: str, measurement: str, *, at: datetime, accepted: bool) -> None:
    """A launch as `launch_on_miner` records it: the pin, then — once the
    miner accepted the dispatch — `launched_at`."""
    allowlist_pin.pin_measurement(
        measurement_hex=measurement, ledger=allowlist_pin.PinLedger(vm_id=vm_id)
    )
    MeasurementLedger.objects.filter(vm_id=vm_id, launch_digest_hex=measurement).update(
        pinned_at=at, launched_at=at + timedelta(seconds=10) if accepted else None
    )


@pytest.fixture
def kbs(monkeypatch: pytest.MonkeyPatch, tmp_path: Any) -> FakeKbs:
    return install_fake_kbs(monkeypatch, tmp_path)


@pytest.fixture
def vms() -> None:
    make_vm("vm-r", state=VmState.ACTIVE)
    make_vm("vm-o", state=VmState.ACTIVE)


def test_an_accepted_resize_evicts_the_pre_resize_launch(kbs: FakeKbs, vms: None) -> None:
    _launch("vm-o", OTHER_M, at=T0, accepted=True)
    _launch("vm-r", SMALL_M, at=T0, accepted=True)
    _launch("vm-r", LARGE_M, at=T0 + timedelta(hours=1), accepted=True)

    # The relaunch's own pin still carried the old size (it was not
    # accepted yet when it installed) …
    assert SMALL_M in kbs.entries
    # … the eviction right after acceptance drops it.
    assert allowlist_pin.evict_superseded_measurements() == 1
    assert SMALL_M not in kbs.entries, "a pre-resize ticket would still release"
    assert {BASE_M, LARGE_M, OTHER_M} <= kbs.entries
    row = MeasurementLedger.objects.get(launch_digest_hex=SMALL_M)
    assert row.evicted_at is not None
    assert row.evicted_epoch == kbs.epoch
    # The next pin starts past the refresh's epoch: no 409 round-trip.
    assert allowlist_pin._installed_epoch_floor() == kbs.epoch + 1
    # Nothing left to do: no further install.
    epoch = kbs.epoch
    assert allowlist_pin.evict_superseded_measurements() == 0
    assert kbs.epoch == epoch


def test_every_later_pin_keeps_it_evicted(kbs: FakeKbs, vms: None) -> None:
    _launch("vm-r", SMALL_M, at=T0, accepted=True)
    _launch("vm-r", LARGE_M, at=T0 + timedelta(hours=1), accepted=True)
    _launch("vm-o", OTHER_M, at=T0 + timedelta(hours=2), accepted=False)
    assert SMALL_M not in kbs.entries
    assert LARGE_M in kbs.entries


def test_a_relaunch_not_accepted_keeps_the_old_size_valid(kbs: FakeKbs, vms: None) -> None:
    """The rollback case: the resize relaunch was pinned, then failed before
    the miner accepted it. The running pre-resize guest must keep its key."""
    _launch("vm-r", SMALL_M, at=T0, accepted=True)
    _launch("vm-r", LARGE_M, at=T0 + timedelta(hours=1), accepted=False)

    assert allowlist_pin.evict_superseded_measurements() == 0
    assert {SMALL_M, LARGE_M} <= kbs.entries


def test_the_rollback_relaunch_evicts_the_failed_target(kbs: FakeKbs, vms: None) -> None:
    """Rolled back: the VM relaunched at the old size (a new launch, a new
    measurement). Now that is current, and both the pre-resize launch and
    the failed target are gone."""
    _launch("vm-r", SMALL_M, at=T0, accepted=True)
    _launch("vm-r", LARGE_M, at=T0 + timedelta(hours=1), accepted=False)
    _launch("vm-r", BACK_M, at=T0 + timedelta(hours=2), accepted=True)

    assert allowlist_pin.evict_superseded_measurements() == 2
    assert BACK_M in kbs.entries
    assert not {SMALL_M, LARGE_M} & kbs.entries


def test_a_relaunch_in_flight_is_carried(kbs: FakeKbs, vms: None) -> None:
    """A pin newer than the current launch (dispatch not answered yet)
    stays carried: the guest it is for may already be asking for its key."""
    _launch("vm-r", SMALL_M, at=T0, accepted=True)
    _launch("vm-r", LARGE_M, at=T0 + timedelta(hours=1), accepted=True)
    _launch("vm-r", BACK_M, at=T0 + timedelta(hours=2), accepted=False)
    allowlist_pin.evict_superseded_measurements()
    assert {LARGE_M, BACK_M} <= kbs.entries
    assert SMALL_M not in kbs.entries


def test_a_vm_with_no_accepted_launch_on_record_keeps_everything(kbs: FakeKbs, vms: None) -> None:
    """Rows from before `launched_at` existed: nothing says which launch is
    current, so nothing is evicted (as before) until the VM relaunches."""
    _launch("vm-r", SMALL_M, at=T0, accepted=False)
    _launch("vm-r", LARGE_M, at=T0 + timedelta(hours=1), accepted=False)
    assert allowlist_pin.evict_superseded_measurements() == 0
    assert {SMALL_M, LARGE_M} <= kbs.entries


def test_the_launch_job_belt_does_not_bring_a_superseded_launch_back(
    kbs: FakeKbs, vms: None
) -> None:
    _launch("vm-r", SMALL_M, at=T0, accepted=True)
    _launch("vm-r", LARGE_M, at=T0 + timedelta(hours=1), accepted=True)
    # The latest LaunchJob of the VM still names the pre-resize launch
    # (a resize relaunches through the power API, which writes none).
    _job("vm-r", SMALL_M, T0)
    allowlist_pin.evict_superseded_measurements()
    assert SMALL_M not in kbs.entries


def test_the_launch_job_belt_still_rescues_a_lost_ledger_row(kbs: FakeKbs, vms: None) -> None:
    """A launch whose ledger write failed is carried by its LaunchJob when
    the job started after the current launch was pinned."""
    _launch("vm-r", SMALL_M, at=T0, accepted=True)
    _job("vm-r", LARGE_M, T0 + timedelta(hours=1))
    allowlist_pin.refresh_allowlist()
    assert {SMALL_M, LARGE_M} <= kbs.entries


def test_a_destroyed_vm_is_not_swept(kbs: FakeKbs, vms: None) -> None:
    _launch("vm-r", SMALL_M, at=T0, accepted=True)
    _launch("vm-r", LARGE_M, at=T0 + timedelta(hours=1), accepted=True)
    from apps.lifecycle.models import Vm

    Vm.objects.filter(vm_id="vm-r").update(state=VmState.DESTROYED)
    assert allowlist_pin.pending_superseded_pins() == []


def test_the_operator_command_evicts_and_can_force_a_resign(kbs: FakeKbs, vms: None) -> None:
    from io import StringIO

    from django.core.management import call_command

    _launch("vm-r", SMALL_M, at=T0, accepted=True)
    _launch("vm-r", LARGE_M, at=T0 + timedelta(hours=1), accepted=True)
    out = StringIO()
    call_command("vali_allowlist_evict_superseded", "--dry-run", stdout=out)
    assert "1 pending" in out.getvalue() and SMALL_M in kbs.entries
    call_command("vali_allowlist_evict_superseded", stdout=out)
    assert SMALL_M not in kbs.entries
    # An old pod resurrected it: --force re-signs without it.
    kbs.entries.add(SMALL_M)
    epoch = kbs.epoch
    call_command("vali_allowlist_evict_superseded", "--force", stdout=out)
    assert SMALL_M not in kbs.entries and kbs.epoch > epoch
