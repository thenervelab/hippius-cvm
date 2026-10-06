"""§22 auto-pins are serialized — concurrent pins must not evict each other (#1340).

Each pin installs a FULL replacement allowlist built from the
carry-forward it read. Three power-API starts landing within a second
each read the same carry-forward, appended only their own measurement,
and installed in turn: the last install won, the other two VMs were
denied their KEK (`measurement not in offline KBS allowlist`) and never
booted, while the API had answered `running`.

These tests drive the REAL `pin_measurement` from two threads against a
fake KBS that keeps the installed epoch HWM and entry set, like
`InstalledAllowlist::install` (full replace, 409 at or below the HWM).
"""

from __future__ import annotations

import threading
from contextlib import contextmanager
from typing import Any

import pytest
from django.db import connections

from apps.lifecycle.models import VmState
from apps.orchestration.models import MeasurementLedger
from apps.orchestration.services import allowlist_pin
from apps.orchestration.tests import fake_allowlist_kbs
from apps.orchestration.tests.factories import make_vm

BASE_M = fake_allowlist_kbs.BASE_M
LIVE_M = "2" * 96
A_M = "a" * 96
B_M = "b" * 96
_FakeKbs = fake_allowlist_kbs.FakeKbs


@pytest.fixture()
def kbs(monkeypatch: pytest.MonkeyPatch, tmp_path: Any) -> _FakeKbs:
    return fake_allowlist_kbs.install_fake_kbs(monkeypatch, tmp_path)


def _pin(vm_id: str, measurement: str) -> allowlist_pin.PinResult:
    return allowlist_pin.pin_measurement(
        measurement_hex=measurement, ledger=allowlist_pin.PinLedger(vm_id=vm_id)
    )


def _in_thread(target: Any) -> tuple[threading.Thread, dict[str, Any]]:
    out: dict[str, Any] = {}

    def run() -> None:
        try:
            out["result"] = target()
        except Exception as exc:  # noqa: BLE001 — asserted by the caller
            out["error"] = exc
        finally:
            connections.close_all()

    thread = threading.Thread(target=run)
    thread.start()
    return thread, out


@pytest.mark.django_db(transaction=True)
def test_a_pin_started_during_another_keeps_both_measurements(kbs: _FakeKbs) -> None:
    """THE #1340 regression. Pin B starts while pin A is installing. Before
    the fix B read the carry-forward without A's measurement (A's ledger
    row did not exist yet), installed {B}, and A's 409 retry re-installed
    its own stale set {A}: B's VM was denied its KEK. Serialized, B waits
    for A to install AND record, then carries A forward."""
    live = make_vm("live-1", state=VmState.ACTIVE)
    MeasurementLedger.objects.create(vm_id=live.vm_id, launch_digest_hex=LIVE_M, allowlist_epoch=5)
    make_vm("vm-a", state=VmState.ACTIVE)
    make_vm("vm-b", state=VmState.ACTIVE)

    started: dict[str, Any] = {}

    def start_b_while_a_installs() -> None:
        if started:
            return
        started["thread"], started["out"] = _in_thread(lambda: _pin("vm-b", B_M))
        # Give B every chance to run to completion inside A's install —
        # the interleaving that lost a measurement before the fix.
        started["thread"].join(timeout=2.0)
        started["b_finished_inside_a"] = not started["thread"].is_alive()

    kbs.on_reload.append(start_b_while_a_installs)

    _pin("vm-a", A_M)
    started["thread"].join(timeout=30.0)

    assert "error" not in started["out"], started["out"]
    assert started["b_finished_inside_a"] is False, "pin B ran inside pin A — not serialized"
    assert {BASE_M, LIVE_M, A_M, B_M} <= kbs.entries
    assert set(MeasurementLedger.objects.values_list("vm_id", flat=True)) == {
        "live-1",
        "vm-a",
        "vm-b",
    }


@pytest.mark.django_db(transaction=True)
def test_concurrent_pins_all_stay_installed(kbs: _FakeKbs) -> None:
    """Three starts at once (the #1340 reproduction): every measurement is
    in the final artifact, and each pin landed on its own epoch."""
    vm_ids = ["vm-1", "vm-2", "vm-3"]
    measurements = ["c" * 96, "d" * 96, "e" * 96]
    for vm_id in vm_ids:
        make_vm(vm_id, state=VmState.ACTIVE)
    barrier = threading.Barrier(len(vm_ids))

    def pin_after_barrier(vm_id: str, measurement: str) -> allowlist_pin.PinResult:
        barrier.wait()
        return _pin(vm_id, measurement)

    runs = [
        _in_thread(lambda v=v, m=m: pin_after_barrier(v, m))
        for v, m in zip(vm_ids, measurements, strict=True)
    ]
    for thread, _ in runs:
        thread.join(timeout=30.0)

    assert all("error" not in out for _, out in runs), [out for _, out in runs]
    assert set(measurements) <= kbs.entries
    epochs = sorted(out["result"].new_epoch for _, out in runs)
    assert epochs == [6, 7, 8]
    assert sorted(
        MeasurementLedger.objects.values_list("allowlist_epoch", flat=True)
    ) == [6, 7, 8]


@pytest.mark.django_db()
def test_the_ledger_row_is_recorded_with_the_pin(kbs: _FakeKbs) -> None:
    """The row the next pin's carry-forward reads is written by the pin
    itself, with its epoch, artifact hash and class."""
    make_vm("vm-a", state=VmState.ACTIVE)

    result = allowlist_pin.pin_measurement(
        measurement_hex=A_M,
        ledger=allowlist_pin.PinLedger(vm_id="vm-a", platform_id="chip", node_id="node"),
    )

    row = MeasurementLedger.objects.get(vm_id="vm-a")
    assert (row.launch_digest_hex, row.platform_id, row.node_id) == (A_M, "chip", "node")
    assert row.allowlist_epoch == result.new_epoch
    assert row.allowlist_sha256 == result.new_cose_sha256_hex
    assert row.measurement_class == allowlist_pin.ALLOWLIST_CLASS_TENANT


@pytest.mark.django_db()
def test_a_failed_ledger_write_does_not_fail_an_installed_pin(
    kbs: _FakeKbs, monkeypatch: pytest.MonkeyPatch
) -> None:
    make_vm("vm-a", state=VmState.ACTIVE)

    def boom(**_: Any) -> None:
        raise RuntimeError("db down")

    monkeypatch.setattr(MeasurementLedger.objects, "create", boom)

    result = _pin("vm-a", A_M)

    assert A_M in kbs.entries
    assert result.new_epoch == kbs.epoch


@pytest.mark.django_db(transaction=True)
def test_a_pin_that_cannot_get_the_lock_is_busy(
    kbs: _FakeKbs, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A pin stuck behind another past the timeout fails with the retriable
    `AllowlistPinBusy` instead of waiting out the request, and installs
    nothing. On Postgres the holder is another connection's advisory lock —
    the lock the control plane runs on."""
    make_vm("vm-a", state=VmState.ACTIVE)
    monkeypatch.setattr(allowlist_pin, "PIN_LOCK_TIMEOUT_S", 0.2)
    held = threading.Event()
    release = threading.Event()

    def hold() -> None:
        with allowlist_pin.pin_lock():
            held.set()
            release.wait(timeout=10.0)

    holder, holder_out = _in_thread(hold)
    assert held.wait(timeout=5.0), holder_out
    try:
        with pytest.raises(allowlist_pin.AllowlistPinBusy, match="another pin held the lock"):
            _pin("vm-a", A_M)
    finally:
        release.set()
        holder.join(timeout=5.0)
    assert A_M not in kbs.entries
    assert not MeasurementLedger.objects.filter(vm_id="vm-a").exists()


@pytest.mark.django_db(transaction=True)
def test_a_pin_installed_between_two_retries_is_carried_by_the_retry(
    kbs: _FakeKbs, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The lock covers ONE attempt, so a burst of pins does not queue behind
    another pin's 409s — and the race must not come back through the retry.
    A's first attempt 409s; B pins while A is between attempts (lock
    released); A's retry must re-read the carry-forward under its new hold
    and install B's measurement too, not re-send the set it read first."""
    kbs.epoch = 6  # A's first attempt (epoch 6) is at the HWM → 409
    make_vm("vm-a", state=VmState.ACTIVE)
    make_vm("vm-b", state=VmState.ACTIVE)
    real_lock = allowlist_pin.pin_lock
    main = threading.get_ident()
    a_holds: list[int] = []
    b: dict[str, Any] = {}

    @contextmanager
    def lock_that_lets_b_in_between_a_attempts():  # noqa: ANN202
        if threading.get_ident() == main and len(a_holds) == 1:
            # A is between its attempts, holding nothing: B pins now.
            b["thread"], b["out"] = _in_thread(lambda: _pin("vm-b", B_M))
            b["thread"].join(timeout=30.0)
        with real_lock():
            if threading.get_ident() == main:
                a_holds.append(kbs.epoch)
            yield

    monkeypatch.setattr(allowlist_pin, "pin_lock", lock_that_lets_b_in_between_a_attempts)

    result = _pin("vm-a", A_M)

    assert "error" not in b["out"], b["out"]
    assert len(a_holds) == 2, "one lock hold per attempt"
    assert b["out"]["result"].new_epoch == 7  # B landed between A's attempts
    assert result.new_epoch == 8
    assert {A_M, B_M} <= kbs.entries
