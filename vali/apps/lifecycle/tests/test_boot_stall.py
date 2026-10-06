"""Boot stall: the classifier, the per-flavor deadline and the API readout.

The failure: a guest whose ticket never arrives never comes up, while its
libvirt domain runs and every other readout stays green. The verdict is
keyed on the in-guest signal since the current boot began, so it also sees
a relaunch (where `boot_phase` still says `running` from the boot before).
Each test names the guard it defends.
"""

from __future__ import annotations

from datetime import timedelta

import pytest
from django.test import override_settings
from django.utils import timezone

from apps.lifecycle import boot_stall
from apps.lifecycle.models import Vm, VmBootPhase, VmPowerState, VmState

pytestmark = pytest.mark.django_db

# small = 40 GiB ⇒ 900 + 15×40 = 1500 s with the defaults.
SMALL_DEADLINE = 1500


def _vm(vm_id: str = "vm-1", *, started_ago_s: int, **fields) -> Vm:
    return Vm.objects.create(
        vm_id=vm_id,
        lease_id=f"lease-{vm_id}",
        state=fields.pop("state", VmState.ACTIVE),
        generation=1,
        host=fields.pop("host", "node-src"),
        lifecycle_vk=bytes(32),
        boot_started_at=timezone.now() - timedelta(seconds=started_ago_s),
        **fields,
    )


def _launch_job(vm_id: str, flavor: str) -> None:
    from apps.orchestration.models import LaunchJob
    from apps.orchestration.tests.factories import make_service_client

    LaunchJob.objects.create(
        job_id=f"job-{vm_id}-{flavor}",
        vm_id=vm_id,
        tenant_id="t",
        flavor=flavor,
        userdata_vault_path="x",
        userdata_vault_version=1,
        kek_vault_path="x",
        phase_started_at=timezone.now(),
        decided_by=make_service_client(),
    )


def _stalled(vm: Vm, disk_gb: int | None = 40) -> bool:
    return boot_stall.classify(vm, disk_gb=disk_gb).stalled


# ─── the deadline ────────────────────────────────────────────────────


@pytest.mark.parametrize(
    ("disk_gb", "expected"),
    [(0, 900), (40, 1500), (320, 5700), (640, 10500), (1280, 11700), (None, 11700)],
)
def test_the_deadline_scales_with_the_disk_and_is_capped(disk_gb, expected) -> None:
    assert boot_stall.deadline_s(disk_gb) == expected


@override_settings(
    VALI_BOOT_STALL_S=100, VALI_BOOT_STALL_PER_DISK_GB_S=2, VALI_BOOT_STALL_DISK_CAP_S=50
)
def test_the_deadline_is_read_from_settings() -> None:
    assert boot_stall.deadline_s(10) == 120
    assert boot_stall.deadline_s(1000) == 150
    assert boot_stall.deadline_s(None) == 150


def test_the_flavor_is_resolved_from_the_latest_launch_job() -> None:
    from apps.orchestration.models import LaunchJob

    _launch_job("vm-a", "small")
    LaunchJob.objects.filter(vm_id="vm-a").update(
        started_at=timezone.now() - timedelta(days=1),
        state="succeeded",
        finished_at=timezone.now() - timedelta(days=1),
    )
    _launch_job("vm-a", "xlarge")
    _launch_job("vm-b", "not-a-flavor")
    assert boot_stall.disk_gb_by_vm_id(["vm-a", "vm-b", "vm-c"]) == {"vm-a": 320}


def test_a_large_flavor_first_boot_inside_its_wipe_allowance_is_not_stalled() -> None:
    """2xlarge on Milan: ~72 min of first-boot wipe."""
    vm = _vm(started_ago_s=72 * 60, boot_phase=VmBootPhase.KEK_RELEASED.value)
    _launch_job(vm.vm_id, "2xlarge")
    assert not vm.boot_stall().stalled
    # ...while the same silence on a small flavor is a stall.
    assert _stalled(vm, disk_gb=40)


# ─── the verdict ─────────────────────────────────────────────────────


@pytest.mark.parametrize("phase", ["", VmBootPhase.BOOTING.value])
def test_no_signal_past_the_deadline_is_stalled(phase: str) -> None:
    vm = _vm(started_ago_s=SMALL_DEADLINE + 60, boot_phase=phase)
    verdict = boot_stall.classify(vm, disk_gb=40)
    assert verdict.stalled
    assert verdict.deadline_s == SMALL_DEADLINE
    assert SMALL_DEADLINE + 59 <= verdict.elapsed_s <= SMALL_DEADLINE + 62


def test_a_slow_boot_inside_the_deadline_is_not_stalled() -> None:
    """A Milan host reaches `kek_released` in ~340 s."""
    assert not _stalled(_vm(started_ago_s=340, boot_phase=VmBootPhase.BOOTING.value))
    assert not _stalled(_vm("vm-2", started_ago_s=SMALL_DEADLINE - 5, boot_phase=""))


@pytest.mark.parametrize("phase", [VmBootPhase.KEK_RELEASED.value, VmBootPhase.RUNNING.value])
def test_boot_phase_does_not_exempt_a_silent_boot(phase: str) -> None:
    """A guest can get its KEK and still hang; and on a relaunch `running`
    is left over from the boot before."""
    assert _stalled(_vm(started_ago_s=SMALL_DEADLINE + 60, boot_phase=phase))


def test_an_in_guest_signal_since_the_boot_began_clears_it() -> None:
    vm = _vm(started_ago_s=SMALL_DEADLINE * 4, boot_phase="")
    vm.guest_signal_at = vm.boot_started_at + timedelta(seconds=1)
    assert not _stalled(vm)


def test_a_signal_from_a_previous_boot_does_not_clear_it() -> None:
    vm = _vm(started_ago_s=SMALL_DEADLINE * 4, boot_phase=VmBootPhase.RUNNING.value)
    vm.guest_signal_at = vm.boot_started_at - timedelta(seconds=1)
    assert _stalled(vm)


def test_a_recent_relaunch_restarts_the_clock() -> None:
    """Launched a week ago, relaunched a minute ago, last signal from the
    old boot: judged on the relaunch."""
    vm = _vm(started_ago_s=60, boot_phase=VmBootPhase.RUNNING.value)
    Vm.objects.filter(pk=vm.pk).update(
        created_at=timezone.now() - timedelta(days=7),
        guest_signal_at=timezone.now() - timedelta(hours=1),
    )
    vm.refresh_from_db()
    assert not _stalled(vm)


def test_a_legacy_row_falls_back_to_created_at() -> None:
    vm = _vm(started_ago_s=0, boot_phase="")
    Vm.objects.filter(pk=vm.pk).update(
        boot_started_at=None, created_at=timezone.now() - timedelta(hours=2)
    )
    vm.refresh_from_db()
    assert _stalled(vm)


def test_not_active_is_never_stalled() -> None:
    vm = _vm(started_ago_s=SMALL_DEADLINE * 4, boot_phase="")
    vm.state = VmState.DECOMMISSIONING
    assert not _stalled(vm)


def test_a_powered_off_vm_is_never_stalled() -> None:
    vm = _vm(started_ago_s=SMALL_DEADLINE * 4, boot_phase="", power_state=VmPowerState.STOPPED)
    assert not _stalled(vm)


def test_a_vm_with_no_host_is_never_stalled() -> None:
    """Not on a host yet (still placing, or an abandoned launch) is a
    different failure with its own sweep."""
    assert not _stalled(_vm(started_ago_s=SMALL_DEADLINE * 4, boot_phase="", host=""))


def test_the_model_level_liveness_verdict_is_unchanged() -> None:
    """Only the API readout says `wedged`: `Vm.guest_liveness()` — what the
    reboot-recovery WEDGED trigger reads — stays `unknown`."""
    vm = _vm(started_ago_s=SMALL_DEADLINE * 4, boot_phase="")
    assert _stalled(vm)
    assert vm.guest_liveness().state == "unknown"


# ─── the API readout ─────────────────────────────────────────────────


def test_serialize_vm_exposes_the_verdict_and_reads_wedged() -> None:
    from apps.lifecycle.views import _serialize_vm

    vm = _vm("vm-api", started_ago_s=SMALL_DEADLINE + 100, boot_phase=VmBootPhase.BOOTING.value)
    _launch_job(vm.vm_id, "small")
    body = _serialize_vm(vm)
    assert body["boot_stalled"] is True
    assert body["boot_started_at"] == vm.boot_started_at.isoformat()
    assert body["guest_liveness"] == "wedged"
    assert body["boot_phase"] == "booting"  # unchanged

    Vm.objects.filter(pk=vm.pk).update(guest_signal_at=timezone.now())
    vm.refresh_from_db()
    body = _serialize_vm(vm)
    assert body["boot_stalled"] is False
    assert body["guest_liveness"] == "alive"


def test_serialize_vm_keeps_unknown_for_a_boot_inside_its_deadline() -> None:
    from apps.lifecycle.views import _serialize_vm

    vm = _vm("vm-new", started_ago_s=60, boot_phase="")
    body = _serialize_vm(vm)
    assert body["boot_stalled"] is False
    assert body["guest_liveness"] == "unknown"


def test_the_list_resolves_each_rows_flavor() -> None:
    from apps.lifecycle.views import _serialize_vm

    vm = _vm("vm-big", started_ago_s=72 * 60, boot_phase="")
    disks = boot_stall.disk_gb_by_vm_id(["vm-big"])
    assert disks == {}
    # No job ⇒ unknown flavor ⇒ the full cap: not stalled at 72 min.
    assert _serialize_vm(vm, disk_gb_by_vm_id=disks)["boot_stalled"] is False
    assert _serialize_vm(vm, disk_gb_by_vm_id={"vm-big": 40})["boot_stalled"] is True


def test_the_schema_documents_the_new_fields() -> None:
    from apps.lifecycle.schemas import VmSerializer

    fields = VmSerializer().fields
    assert "boot_stalled" in fields
    assert "boot_started_at" in fields
