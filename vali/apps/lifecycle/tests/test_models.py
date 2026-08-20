"""Model-level tests: Vm CAS semantics, EOL nonce minting, constraints."""

from __future__ import annotations

import pytest
from django.db import IntegrityError, transaction

from apps.lifecycle.models import Vm, VmBootPhase, VmState

pytestmark = pytest.mark.django_db


def _make_vm(**overrides) -> Vm:
    defaults = {
        "vm_id": "vm-1",
        "lease_id": "lease-1",
        "state": VmState.ACTIVE,
        "generation": 1,
        "host": "host-a",
        "lifecycle_vk": bytes(32),
    }
    defaults.update(overrides)
    return Vm.objects.create(**defaults)


def test_boot_phase_defaults_empty() -> None:
    vm = _make_vm()
    assert vm.boot_phase == ""
    assert vm.boot_phase_at is None


def test_advance_boot_phase_maps_wire_hyphen_to_choice() -> None:
    vm = _make_vm()
    assert vm.advance_boot_phase("kek-released") is True
    assert vm.boot_phase == VmBootPhase.KEK_RELEASED.value


def test_advance_boot_phase_is_monotonic() -> None:
    vm = _make_vm()
    assert vm.advance_boot_phase("booting") is True
    assert vm.advance_boot_phase("running") is True
    assert vm.boot_phase == VmBootPhase.RUNNING.value
    # A late/replayed lower milestone must NOT regress the phase.
    assert vm.advance_boot_phase("booting") is False
    assert vm.boot_phase == VmBootPhase.RUNNING.value
    # An equal milestone is a no-op too (idempotent replay).
    assert vm.advance_boot_phase("running") is False


def test_advance_boot_phase_rejects_unknown_milestone() -> None:
    vm = _make_vm()
    assert vm.advance_boot_phase("bogus") is False
    assert vm.boot_phase == ""


def test_eol_nonce_is_32_fresh_random_bytes() -> None:
    n1 = Vm.issue_eol_nonce()
    n2 = Vm.issue_eol_nonce()
    assert len(n1) == 32
    assert len(n2) == 32
    # token_bytes is CSPRNG → P(collision over 32 bytes) ≈ 2^-256.
    assert n1 != n2


def test_vm_id_unique_constraint() -> None:
    _make_vm()
    with pytest.raises(IntegrityError), transaction.atomic():
        _make_vm()


def test_migrating_without_dest_violates_check_constraint() -> None:
    # `Migrating ⇒ migration_dest != ""` is a DB-level CHECK so even
    # a misbehaving call path (not via the view) can't persist a
    # malformed row.
    with pytest.raises(IntegrityError), transaction.atomic():
        Vm.objects.create(
            vm_id="vm-bad",
            lease_id="l",
            state=VmState.MIGRATING,
            generation=1,
            new_generation=2,
            host="src",
            migration_dest="",  # forbidden
            lifecycle_vk=bytes(32),
        )


def test_migrating_without_new_generation_violates_check() -> None:
    with pytest.raises(IntegrityError), transaction.atomic():
        Vm.objects.create(
            vm_id="vm-bad",
            lease_id="l",
            state=VmState.MIGRATING,
            generation=1,
            new_generation=None,  # forbidden
            host="src",
            migration_dest="dst",
            lifecycle_vk=bytes(32),
        )


def test_version_starts_at_one() -> None:
    vm = _make_vm()
    assert vm.version == 1


def test_cas_update_succeeds_at_matching_version() -> None:
    vm = _make_vm()
    # Simulate the view's CAS UPDATE.
    updated = Vm.objects.filter(vm_id=vm.vm_id, version=1).update(
        state=VmState.DECOMMISSIONING,
        version=2,
    )
    assert updated == 1
    vm.refresh_from_db()
    assert vm.state == VmState.DECOMMISSIONING
    assert vm.version == 2


def test_cas_update_fails_at_stale_version() -> None:
    vm = _make_vm()
    # First writer bumps to v2.
    Vm.objects.filter(vm_id=vm.vm_id, version=1).update(version=2)
    # Second writer with the stale if_version=1 sees zero rows.
    updated = Vm.objects.filter(vm_id=vm.vm_id, version=1).update(version=3)
    assert updated == 0


def test_lifecycle_vk_hex_roundtrip() -> None:
    vk = bytes(range(32))
    vm = _make_vm(lifecycle_vk=vk)
    # The helper hex-encodes; `bytes.fromhex` rehydrates losslessly.
    assert bytes.fromhex(vm.lifecycle_vk_hex()) == vk
