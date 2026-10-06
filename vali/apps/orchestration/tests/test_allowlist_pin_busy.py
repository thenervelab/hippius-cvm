"""A pin that waits out the §22 pin lock is TRANSIENT, never a refusal (#1340).

Pins are serialized (`allowlist_pin.pin_lock`). A pin stuck behind a slow
one — an S3 SlowDown, a slow KBS reload — gives up after
`PIN_LOCK_TIMEOUT_S` with `AllowlistPinBusy`. Nothing has been signed or
registered at that point, so every caller retries it instead of failing
the VM for vali's own queue: the launch re-places without spending a miner
attempt, reboot-recovery hands the attempt back, a power start answers a
distinct re-askable 503.
"""

from __future__ import annotations

import threading
from typing import Any

import pytest
from django.test import override_settings

from apps.identity.models import PrincipalScope, ServiceClient
from apps.lifecycle.models import VmPowerState
from apps.orchestration import service, views
from apps.orchestration.models import MeasurementLedger, RebootRecovery
from apps.orchestration.services import allowlist_pin, launch, power
from apps.orchestration.tests.test_allowlist_pin_concurrency import (  # noqa: F401 — fixture
    _FakeKbs,
    _in_thread,
    kbs,
)
from apps.orchestration.tests.test_launch_service import (
    _fake_the_launch_choreography,
    _register_miner,
    _spec,
)
from apps.orchestration.tests.test_reboot_recovery_disks_missing import (
    _down,
    _miner,
    _succeeded_launch,
)
from apps.scheduler import chain
from apps.scheduler.tests.factories import make_miner, make_snapshot

from .factories import make_vm

_NETBIRD_USERDATA = b"#cloud-config\n# {{NETBIRD_SETUP_KEY}}\n"


def _busy_outcome() -> launch.LaunchOutcome:
    return launch.LaunchOutcome(
        disposition=launch.RETRIABLE,
        emit={"ok": False, "outcome": "allowlist-pin-busy", "error": "busy"},
        exit_code=launch.EXIT_ALLOWLIST_FAILURE,
    )


# Not `transaction=True`: the holder thread only takes the lock (on its own
# connection on Postgres), and a transactional test here would run after
# the migration tests that leave later migrations unapplied.
@pytest.mark.django_db()
def test_a_launch_stuck_behind_a_slow_pin_is_retried_and_lands(
    kbs: _FakeKbs,  # noqa: F811 — the imported fixture
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Pin A holds the lock past B's wait. B's launch is not terminal: it
    is re-placed on the same miner once A is done and lands, pinned and
    ledgered. Real `launch_vm` → `launch_on_miner` → `pin_measurement`;
    only the Vault/KBS-register/dispatch collaborators are faked."""
    actor = ServiceClient.objects.create(scope=PrincipalScope.OPERATOR.value, name="launcher")
    _register_miner(1)
    monkeypatch.setattr(chain, "read_miner_status", lambda: make_snapshot(10, [make_miner(1)]))
    _fake_the_launch_choreography(monkeypatch, dispatch_ok=True)
    monkeypatch.setattr(allowlist_pin, "PIN_LOCK_TIMEOUT_S", 0.3)

    held = threading.Event()
    release_a = threading.Event()

    def slow_pin_a() -> None:
        with allowlist_pin.pin_lock():
            held.set()
            release_a.wait(timeout=10.0)

    real_launch_on_miner = launch.launch_on_miner
    outcomes: list[str] = []

    def observed(spec: launch.LaunchSpec, miner: Any, **kw: Any) -> launch.LaunchOutcome:
        out = real_launch_on_miner(spec, miner, **kw)
        outcomes.append(out.emit.get("outcome", out.disposition))
        release_a.set()  # A finishes only after B has given up once
        return out

    monkeypatch.setattr(launch, "launch_on_miner", observed)

    holder, holder_out = _in_thread(slow_pin_a)
    assert held.wait(timeout=5.0), holder_out
    try:
        result = launch.launch_vm(
            _spec(auto_pin_allowlist=True, userdata=_NETBIRD_USERDATA), actor
        )
    finally:
        release_a.set()
        holder.join(timeout=5.0)

    assert result.ok is True, result.emit
    assert outcomes[0] == "allowlist-pin-busy"
    assert result.miner_id == "miner-a"
    assert "ab" * 48 in kbs.entries
    assert MeasurementLedger.objects.filter(vm_id="vm-launch-1").exists()


@pytest.mark.django_db()
@override_settings(VALI_LAUNCH_MAX_PIN_BUSY_RETRIES=2, VALI_LAUNCH_MAX_REPLACE=1)
def test_a_pin_that_stays_busy_fails_as_busy_after_its_own_cap(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Busy retries neither spend a miner attempt (MAX_REPLACE=1 still
    gets three tries) nor end as `no-capacity-after-replace`."""
    actor = ServiceClient.objects.create(scope=PrincipalScope.OPERATOR.value, name="launcher")
    _register_miner(1)
    monkeypatch.setattr(chain, "read_miner_status", lambda: make_snapshot(10, [make_miner(1)]))
    calls: list[str] = []

    def always_busy(spec: launch.LaunchSpec, miner: Any) -> launch.LaunchOutcome:
        calls.append(miner.miner_id)
        return _busy_outcome()

    monkeypatch.setattr(launch, "launch_on_miner", always_busy)

    result = launch.launch_vm(_spec(), actor)

    assert result.ok is False
    assert result.outcome == "allowlist-pin-busy"
    assert calls == ["miner-a"] * 3


def _relaunch_is_busy(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    from apps.orchestration.services import vault_kv as vk

    monkeypatch.setattr(vk, "get_kv", lambda mount, path, version=None: b"u")
    calls: list[str] = []

    def busy(spec: launch.LaunchSpec, m: Any, **_kw: Any) -> launch.LaunchOutcome:
        calls.append(m.miner_id)
        return _busy_outcome()

    monkeypatch.setattr(launch, "launch_on_miner", busy)
    return calls


@pytest.mark.django_db()
@override_settings(
    VALI_REBOOT_RECOVERY_ENABLED=True,
    VALI_REBOOT_RECOVERY_DEBOUNCE_POLLS=1,
    VALI_REBOOT_RECOVERY_BACKOFF_BASE_S=0,
    VALI_REBOOT_RECOVERY_MAX_ATTEMPTS=1,
)
def test_reboot_recovery_retries_a_busy_pin_without_spending_an_attempt(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """With a budget of ONE attempt, a busy pin must not exhaust it: the
    next tick relaunches again."""
    vm = make_vm()
    _miner()
    _succeeded_launch(vm)
    RebootRecovery.objects.create(vm=vm, seen_running=True, host="node-src")
    _down(monkeypatch)
    calls = _relaunch_is_busy(monkeypatch)

    assert service.reboot_recovery_once() == 0
    rec = RebootRecovery.objects.get(vm=vm)
    assert (rec.attempts, rec.last_outcome) == (0, service.PIN_BUSY_OUTCOME)

    assert service.reboot_recovery_once() == 0
    assert calls == ["node-src", "node-src"]


@pytest.mark.django_db()
def test_a_power_start_behind_a_busy_pin_is_a_distinct_re_askable_refusal(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Not `relaunch-rejected` (a miner verdict): its own reason, a 503, and
    the VM stays stopped with nothing changed."""
    vm = make_vm()
    _miner()
    _succeeded_launch(vm)
    vm.host = "node-src"
    vm.power_state = VmPowerState.STOPPED
    vm.save(update_fields=["host", "power_state"])
    _relaunch_is_busy(monkeypatch)

    with pytest.raises(power.PowerOpRefused) as exc:
        power.start_vm(vm)

    assert exc.value.reason == power.PIN_BUSY_REASON == "allowlist-pin-busy"
    assert views._POWER_ERROR_STATUS[exc.value.reason] == 503
    vm.refresh_from_db()
    assert vm.power_state == VmPowerState.STOPPED
