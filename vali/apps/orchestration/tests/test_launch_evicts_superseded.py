"""An accepted launch evicts the VM's earlier launches from the allowlist
(`allowlist_pin.evict_superseded_measurements`) — and never fails over it."""

from __future__ import annotations

import pytest

from apps.orchestration import service
from apps.orchestration.effects import EffectError
from apps.orchestration.services import allowlist_pin, launch
from apps.orchestration.tests.test_launch_service import (
    _fake_the_launch_choreography,
    _register_miner,
    _spec,
)

pytestmark = pytest.mark.django_db

_USERDATA = b"#cloud-config\n# {{NETBIRD_SETUP_KEY}}\n"


def _run(
    monkeypatch,
    *,
    dispatch_ok: bool,
    auto_pin: bool,
    evict=None,
    classifier: str = "launched",
    supersede: bool = False,
    minted: list | None = None,
) -> tuple[object, list]:
    from apps.orchestration import order_dispatch
    from apps.orchestration.services import ticket_mint

    _fake_the_launch_choreography(monkeypatch, dispatch_ok=dispatch_ok)
    if dispatch_ok:
        monkeypatch.setattr(
            order_dispatch,
            "dispatch_order",
            lambda *a, **k: order_dispatch.DispatchResult(
                ok=True, status=200, classifier=classifier
            ),
        )
    if minted is not None:

        def _mint(args):
            minted.append(tuple(args.lifecycle_perm))
            return b"cose"

        monkeypatch.setattr(ticket_mint, "mint", _mint)
    monkeypatch.setattr(
        launch.allowlist_pin,
        "pin_measurement",
        lambda **kw: allowlist_pin.PinResult(
            new_epoch=2, new_cose_sha256_hex="e" * 64, s3_url="s3://x"
        ),
    )
    calls: list[str] = []

    def _evict() -> int:
        calls.append("evict")
        if evict is not None:
            raise evict
        return 1

    monkeypatch.setattr(launch.allowlist_pin, "evict_superseded_measurements", _evict)
    out = launch.launch_on_miner(
        _spec(auto_pin_allowlist=auto_pin, userdata=_USERDATA),
        _register_miner(1),
        supersede=supersede,
    )
    return out, calls


def test_an_accepted_launch_evicts_the_earlier_ones(monkeypatch) -> None:
    out, calls = _run(monkeypatch, dispatch_ok=True, auto_pin=True)
    assert out.disposition == launch.ACCEPTED, out.emit
    assert calls == ["evict"]


def test_a_refused_launch_evicts_nothing(monkeypatch) -> None:
    """The rollback case: the relaunch never became current, so the guest
    still running keeps its measurement."""
    out, calls = _run(monkeypatch, dispatch_ok=False, auto_pin=True)
    assert out.disposition != launch.ACCEPTED
    assert calls == []


def test_a_launch_that_pins_nothing_evicts_nothing(monkeypatch) -> None:
    _, calls = _run(monkeypatch, dispatch_ok=True, auto_pin=False)
    assert calls == []


@pytest.mark.parametrize(
    "error", [allowlist_pin.AllowlistPinBusy("busy"), EffectError("kbs-admin-reload: 503")]
)
def test_a_failed_eviction_never_fails_the_accepted_launch(monkeypatch, error) -> None:
    errors: list[str] = []
    monkeypatch.setattr(launch.log, "error", lambda msg, *a: errors.append(msg % a))
    out, calls = _run(monkeypatch, dispatch_ok=True, auto_pin=True, evict=error)
    assert out.disposition == launch.ACCEPTED, out.emit
    assert calls == ["evict"]
    assert any("could not evict the superseded launches" in e for e in errors), errors


def test_the_tick_retries_and_tolerates_a_busy_lock(monkeypatch) -> None:
    def _busy() -> int:
        raise allowlist_pin.AllowlistPinBusy("busy")

    monkeypatch.setattr(allowlist_pin, "evict_superseded_measurements", _busy)
    assert service.sweep_superseded_measurements() == 0
    monkeypatch.setattr(allowlist_pin, "evict_superseded_measurements", lambda: 3)
    assert service.sweep_superseded_measurements() == 3


def test_an_already_launched_answer_marks_nothing_current(monkeypatch) -> None:
    """A same-miner retry inside the ticket re-push window: the domain that
    runs is the earlier attempt's, not this measurement — it must not become
    current nor evict the running one."""
    from apps.orchestration.models import MeasurementLedger

    MeasurementLedger.objects.create(
        vm_id="vm-launch-1", launch_digest_hex="ab" * 48, allowlist_epoch=1
    )
    out, calls = _run(monkeypatch, dispatch_ok=True, auto_pin=True, classifier="already-launched")
    assert out.disposition == launch.ACCEPTED, out.emit
    assert calls == []
    assert MeasurementLedger.objects.get(vm_id="vm-launch-1").launched_at is None


@pytest.mark.parametrize("supersede", [True, False])
def test_only_a_superseding_launch_carries_the_supersede_perm(monkeypatch, supersede: bool) -> None:
    minted: list = []
    _run(monkeypatch, dispatch_ok=True, auto_pin=False, supersede=supersede, minted=minted)
    assert minted == [("launch", "supersede") if supersede else ("launch",)]


def _moved_vm_relaunch(
    monkeypatch, *, register, dispatched: list | None = None
) -> tuple[object, list]:
    """A resize relaunch of a VM §25 moved (generation 2), superseding."""
    from apps.lifecycle.models import Vm
    from apps.orchestration import order_dispatch

    _fake_the_launch_choreography(monkeypatch, dispatch_ok=True)
    if dispatched is not None:

        def _dispatch(*a, **k):
            dispatched.append(1)
            return order_dispatch.DispatchResult(ok=True, status=200, classifier="launched")

        monkeypatch.setattr(order_dispatch, "dispatch_order", _dispatch)
    monkeypatch.setattr(
        launch.allowlist_pin,
        "pin_measurement",
        lambda **kw: allowlist_pin.PinResult(
            new_epoch=2, new_cose_sha256_hex="e" * 64, s3_url="s3://x"
        ),
    )
    monkeypatch.setattr(launch.allowlist_pin, "evict_superseded_measurements", lambda: 0)
    calls: list[str] = []

    def _register(**kw):
        calls.append(kw["vm_id"])
        return register(**kw)

    monkeypatch.setattr(launch.kbs_admin, "register_vm_active_with_vm_id", _register)
    miner = _register_miner(1)
    Vm.objects.update_or_create(
        vm_id="vm-launch-1",
        defaults={
            "tenant_id": "t-launch",
            "state": "active",
            "host": miner.miner_id,
            "generation": 2,
        },
    )
    out = launch.launch_on_miner(
        _spec(auto_pin_allowlist=True, userdata=_USERDATA), miner, generation=2, supersede=True
    )
    return out, calls


class _Admin:
    vm_id = "vm-launch-1"
    vm_generation = 2
    cached = False


def test_a_moved_vms_resize_relaunch_registers_to_supersede(monkeypatch) -> None:
    """Generation > 1 used to skip the register altogether; a SUPERSEDING
    relaunch now registers, so the KBS refuses the pre-resize ticket before
    the relaunch is dispatched — and the pin records it."""
    from apps.orchestration.models import MeasurementLedger

    MeasurementLedger.objects.create(
        vm_id="vm-launch-1", launch_digest_hex="ab" * 48, allowlist_epoch=1
    )
    out, calls = _moved_vm_relaunch(monkeypatch, register=lambda **kw: _Admin())
    assert out.disposition == launch.ACCEPTED, out.emit
    assert calls == ["vm-launch-1"]
    assert MeasurementLedger.objects.get(vm_id="vm-launch-1").superseded_at_register is not None


def test_an_older_kbs_refusing_the_moved_vm_register_fails_the_relaunch(monkeypatch) -> None:
    """A KBS that predates the moved-VM supersede answers 409: the relaunch
    fails like any refused register (KBS first, then vali). Falling back to
    an unregistered launch would let a later retry strand it."""
    from apps.orchestration import kbs_admin
    from apps.orchestration.models import MeasurementLedger

    MeasurementLedger.objects.create(
        vm_id="vm-launch-1", launch_digest_hex="ab" * 48, allowlist_epoch=1
    )
    dispatched: list[int] = []

    def _conflict(**kw):
        raise kbs_admin.KbsAdminConflict("409 state-conflict")

    out, calls = _moved_vm_relaunch(monkeypatch, register=_conflict, dispatched=dispatched)
    assert out.disposition == launch.TERMINAL, out.emit
    assert out.emit["outcome"] == "kbs-admin-conflict"
    assert dispatched == []
    assert MeasurementLedger.objects.get(vm_id="vm-launch-1").superseded_at_register is None


def test_a_superseding_launch_whose_mark_fails_is_not_dispatched(monkeypatch) -> None:
    """The KBS made it current but vali could not record that: dispatching
    it would let a retry supersede again and strand it if it came up."""
    dispatched: list[int] = []
    # No pin row ⇒ nothing to mark.
    out, calls = _moved_vm_relaunch(
        monkeypatch, register=lambda **kw: _Admin(), dispatched=dispatched
    )
    assert out.disposition == launch.TERMINAL, out.emit
    assert dispatched == [], "dispatched without the supersede mark"
    assert out.emit["outcome"] == "supersede-mark-failed"
    assert out.registered is True


@pytest.mark.django_db
def test_the_supersede_mark_carries_the_registers_time_not_the_pins() -> None:
    """A mark landing on an older pin of the same measurement (this launch's
    ledger insert failed) still reads as a register after the resize began."""
    from datetime import timedelta

    from django.utils import timezone

    from apps.orchestration.models import MeasurementLedger

    row = MeasurementLedger.objects.create(
        vm_id="vm-old-pin", launch_digest_hex="cd" * 48, allowlist_epoch=1
    )
    MeasurementLedger.objects.filter(pk=row.pk).update(pinned_at=timezone.now() - timedelta(days=3))
    began = timezone.now()
    assert launch._mark_superseded_at_register("vm-old-pin", "CD" * 48)
    row.refresh_from_db()
    assert row.superseded_at_register is not None and row.superseded_at_register >= began
