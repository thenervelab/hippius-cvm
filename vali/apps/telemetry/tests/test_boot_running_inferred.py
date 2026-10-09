"""`boot_phase` running inferred from a live attestation, when no served
receipt set it (prod: ~7 % of launches sat at `kek_released` while their
guest attested from ~60 s after launch)."""

from __future__ import annotations

from datetime import timedelta

import pytest
from django.utils import timezone

from apps.lifecycle.models import Vm, VmBootPhase, VmState
from apps.orchestration.models import MeasurementLedger
from apps.telemetry import vm_liveness

from .test_vm_liveness import (  # noqa: F401 — fixtures
    GENOA_CHIP,
    MEASUREMENT,
    REPORT_ID,
    VM,
    FakeVerifier,
    _binding,
    _miner,
    _pin_now,
    _wire_kbs_key,
    fake,
)

pytestmark = pytest.mark.django_db


def _vm(*, boot_phase: str = VmBootPhase.KEK_RELEASED, state: str = VmState.ACTIVE) -> Vm:
    _binding()
    _miner(GENOA_CHIP)
    return Vm.objects.create(
        vm_id=VM,
        lease_id="lease-1",
        state=state,
        generation=1,
        host="miner-live",
        lifecycle_vk=bytes(32),
        boot_phase=boot_phase,
        new_generation=2 if state == VmState.MIGRATING else None,
        migration_dest="miner-dest" if state == VmState.MIGRATING else "",
    )


def _ingest(fake: FakeVerifier, *, chip: str = GENOA_CHIP, seq: int = 1) -> None:  # noqa: F811
    fake.guest = ("release", chip, REPORT_ID)
    fake.attestation_seq = seq
    fake.body_digest_hex = f"{seq:02x}" * 32
    vm_liveness.ingest_live_attestation(envelope=b"\x01")


@pytest.mark.parametrize("phase", ["", VmBootPhase.BOOTING, VmBootPhase.KEK_RELEASED])
def test_a_live_attestation_of_the_current_launch_means_running(
    fake: FakeVerifier,  # noqa: F811
    phase: str,
) -> None:
    vm = _vm(boot_phase=phase)
    _ingest(fake)
    vm.refresh_from_db()
    assert vm.boot_phase == VmBootPhase.RUNNING
    assert vm.boot_phase_inferred_at is not None and vm.boot_phase_at is not None


def test_running_already_is_left_alone(fake: FakeVerifier) -> None:  # noqa: F811
    at = timezone.now() - timedelta(hours=1)
    vm = _vm(boot_phase=VmBootPhase.RUNNING)
    Vm.objects.filter(pk=vm.pk).update(boot_phase_at=at)
    _ingest(fake)
    vm.refresh_from_db()
    assert vm.boot_phase_at == at and vm.boot_phase_inferred_at is None


@pytest.mark.parametrize("state", [VmState.MIGRATING, VmState.DECOMMISSIONING])
def test_never_during_a_move_or_a_decommission(
    fake: FakeVerifier,  # noqa: F811
    state: str,
) -> None:
    """A §25 fence reset `boot_phase` for the destination's milestones; a
    source guest still attesting must not put `running` back."""
    vm = _vm(state=state, boot_phase="")
    _ingest(fake)
    vm.refresh_from_db()
    assert vm.boot_phase == "" and vm.boot_phase_inferred_at is None


def test_not_from_an_earlier_launch(fake: FakeVerifier) -> None:  # noqa: F811
    """A relaunch pinned a new measurement the miner accepted: a sample of
    the old one is not this launch's guest."""
    vm = _vm()
    MeasurementLedger.objects.filter(vm_id=VM).update(
        launched_at=timezone.now() - timedelta(minutes=10)
    )
    MeasurementLedger.objects.create(
        vm_id=VM,
        launch_digest_hex="55" * 48,
        allowlist_epoch=2,
        launched_at=timezone.now() - timedelta(minutes=1),
    )
    _ingest(fake)  # carries MEASUREMENT, the earlier launch
    vm.refresh_from_db()
    assert vm.boot_phase == VmBootPhase.KEK_RELEASED


def test_not_from_another_chip_than_the_current_host(fake: FakeVerifier) -> None:  # noqa: F811
    vm = _vm()
    assert not vm_liveness._chip_is_current_host(vm, "6f" * 64)
    assert vm_liveness._chip_is_current_host(vm, GENOA_CHIP)
    assert vm_liveness._chip_is_current_host(vm, "")


def test_a_superseded_sample_never_advances(fake: FakeVerifier) -> None:  # noqa: F811
    vm = _vm()
    row = type(
        "Row", (), {"vm_id": VM, "measurement": MEASUREMENT, "chip_id": "", "attestation_seq": 1}
    )
    assert vm_liveness._infer_running(row, superseded=True) is False
    vm.refresh_from_db()
    assert vm.boot_phase == VmBootPhase.KEK_RELEASED


def test_a_replay_infers_nothing(fake: FakeVerifier) -> None:  # noqa: F811
    vm = _vm()
    _ingest(fake)
    Vm.objects.filter(pk=vm.pk).update(boot_phase="", boot_phase_inferred_at=None)
    _ingest(fake)  # same body: a replay, not fresh evidence
    vm.refresh_from_db()
    assert vm.boot_phase == "" and vm.boot_phase_inferred_at is None


def test_a_concurrent_fence_wins(fake: FakeVerifier, monkeypatch) -> None:  # noqa: F811
    """The conditional UPDATE re-checks state and phase: a fence that lands
    between the read and the write is never overwritten."""
    vm = _vm()
    real = vm_liveness._current_launch_measurement

    def fence_then(vm_id: str) -> str:
        Vm.objects.filter(pk=vm.pk).update(
            state=VmState.MIGRATING, new_generation=2, migration_dest="miner-dest", boot_phase=""
        )
        return real(vm_id)

    monkeypatch.setattr(vm_liveness, "_current_launch_measurement", fence_then)
    _ingest(fake)
    vm.refresh_from_db()
    assert vm.state == VmState.MIGRATING and vm.boot_phase == ""


def test_the_guest_report_counts_inferences() -> None:
    from apps.orchestration import guest_report

    Vm.objects.create(
        vm_id="vm-inferred",
        lease_id="l",
        state=VmState.ACTIVE,
        generation=1,
        lifecycle_vk=bytes(32),
        boot_phase=VmBootPhase.RUNNING,
        boot_phase_inferred_at=timezone.now(),
    )
    text = guest_report.report_metrics().render()
    assert "hippius_vm_boot_running_inferred_24h 1" in text
