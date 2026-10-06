"""Model-level tests: Vm CAS semantics, EOL nonce minting, constraints."""

from __future__ import annotations

from datetime import datetime, timedelta

import pytest
from django.db import IntegrityError, transaction
from django.utils import timezone

from apps.lifecycle.models import Vm, VmBootPhase, VmPowerState, VmState

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


def _backdated(vm: Vm) -> datetime:
    old = timezone.now() - timedelta(days=2)
    Vm.objects.filter(pk=vm.pk).update(updated_at=old)
    return old


def test_a_queryset_update_stamps_updated_at() -> None:
    """The §24/§25 CAS transitions are queryset updates, which skip
    `auto_now`: without the stamp a destroyed row read its last save's date."""
    vm = _make_vm()
    old = _backdated(vm)
    Vm.objects.filter(pk=vm.pk).update(state=VmState.DECOMMISSIONING)
    vm.refresh_from_db()
    assert vm.updated_at > old + timedelta(days=1)


def test_an_explicit_updated_at_is_kept() -> None:
    vm = _make_vm()
    old = _backdated(vm)
    vm.refresh_from_db()
    assert vm.updated_at == old


def test_a_partial_save_stamps_updated_at() -> None:
    vm = _make_vm()
    old = _backdated(vm)
    vm.refresh_from_db()
    vm.host = "host-b"
    vm.save(update_fields=["host"])
    vm.refresh_from_db()
    assert vm.host == "host-b" and vm.updated_at > old + timedelta(days=1)


def test_the_backfill_turns_destroyed_rows_off_and_leaves_their_date() -> None:
    import importlib

    from django.db import connection
    from django.db.migrations.loader import MigrationLoader

    # The models as the migration sees them (plain manager), not today's.
    apps = MigrationLoader(connection).project_state(
        ("lifecycle", "0017_vm_power_state_off")
    ).apps
    backfill = importlib.import_module("apps.lifecycle.migrations.0017_vm_power_state_off")
    dead = _make_vm(vm_id="vm-dead", state=VmState.DESTROYED, power_stop_proof=b"\x01" * 32)
    live = _make_vm(vm_id="vm-live")
    old = _backdated(dead)

    backfill.destroyed_rows_off(apps, None)

    dead.refresh_from_db()
    live.refresh_from_db()
    assert dead.power_state == VmPowerState.OFF and dead.power_stop_proof is None
    assert live.power_state == VmPowerState.RUNNING
    # Dated by what zombie.py read until now; updated_at itself not moved.
    assert dead.power_state_at == old and dead.updated_at == old


def test_an_empty_partial_save_stays_a_no_op() -> None:
    vm = _make_vm()
    old = _backdated(vm)
    vm.refresh_from_db()
    vm.save(update_fields=[])
    vm.refresh_from_db()
    assert vm.updated_at == old
