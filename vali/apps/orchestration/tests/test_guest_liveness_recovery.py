"""Wedged-guest detection in the orchestration tick.

The defect these pin: `effects.poll_domain_running` reports whether a
QEMU process exists, so a tenant VM hung in its initramfs (proved live on
miner-2 2026-08-12 — allowlist eviction → KEK release 403 → the LUKS
overlay never opened) reported `running:true` forever and the control
plane called it healthy.

Two halves are tested here:

  * `sweep_guest_liveness` — always-on observability. Counts + logs the
    Active VMs whose guest has gone silent.
  * the reboot-recovery second trigger — default-OFF, and every
    uncertainty must fail SAFE (do nothing).
"""

from __future__ import annotations

import logging
from datetime import timedelta

import pytest
from django.test import override_settings
from django.utils import timezone

from apps.lifecycle import guest_liveness
from apps.lifecycle.models import Vm, VmBootPhase
from apps.miners.models import MinerIdentity, MinerStatus
from apps.orchestration import service
from apps.orchestration.models import RebootRecovery

from .factories import make_vm

pytestmark = pytest.mark.django_db


def _make_alive_miner(miner_id: str = "node-src") -> MinerIdentity:
    return MinerIdentity.objects.create(
        miner_id=miner_id,
        pubkey_hex=f"{abs(hash(miner_id)) % (16**16):016x}".ljust(64, "0"),
        platform_id=f"plat-{miner_id}",
        chain_node_id=f"{abs(hash(miner_id)) % (16**16):016x}".ljust(64, "1"),
        netbird_ip="100.64.0.9",
        last_seen_at=timezone.now(),
        status=MinerStatus.ACTIVE,
    )


def _silence(vm: Vm, *, ago_s: int) -> None:
    """Give `vm` a stale in-guest watermark — it HAS emitted, but not
    recently. The wedged shape."""
    Vm.objects.filter(vm_id=vm.vm_id).update(
        guest_signal_at=timezone.now() - timedelta(seconds=ago_s),
        guest_signal_kind=guest_liveness.SIGNAL_SERVED_RECEIPT,
        boot_phase=VmBootPhase.RUNNING.value,
    )
    vm.refresh_from_db()


def _alive(vm: Vm) -> None:
    Vm.objects.filter(vm_id=vm.vm_id).update(
        guest_signal_at=timezone.now(),
        guest_signal_kind=guest_liveness.SIGNAL_SERVED_RECEIPT,
        boot_phase=VmBootPhase.RUNNING.value,
    )
    vm.refresh_from_db()


def _set_domain(monkeypatch, value) -> None:
    monkeypatch.setattr(service.effects, "poll_domain_running", lambda vm: value)


@pytest.fixture
def warnings_log():
    """Capture WARNINGs from `apps.orchestration.service`.

    `caplog` alone does not work here: the project's `LOGGING` config
    sets `propagate: False` on the `apps` logger, so records never reach
    the root handler pytest installs. Attach directly instead.
    """
    logger = logging.getLogger("apps.orchestration.service")
    records: list[str] = []

    class _Sink(logging.Handler):
        def emit(self, record: logging.LogRecord) -> None:
            records.append(record.getMessage())

    handler = _Sink(level=logging.WARNING)
    logger.addHandler(handler)
    try:
        yield records
    finally:
        logger.removeHandler(handler)


@pytest.fixture
def stub_relaunch(monkeypatch):
    calls = []

    def fake(vm, node_id):
        calls.append((vm.vm_id, node_id))
        return True

    monkeypatch.setattr(service, "_reboot_recovery_relaunch", fake)
    return calls


# ═══ the sweep — always-on observability ═════════════════════════════


@override_settings(VALI_GUEST_LIVENESS_STALE_S=600)
def test_sweep_counts_a_wedged_vm(warnings_log) -> None:
    """THE defect. The VM looks perfect by every pre-existing measure —
    Active, boot_phase=running — and the sweep still calls it wedged."""
    vm = make_vm("vm-wedged")
    _silence(vm, ago_s=3600)
    assert service.sweep_guest_liveness() == 1
    assert any("WEDGED" in m and "vm-wedged" in m for m in warnings_log)


@override_settings(VALI_GUEST_LIVENESS_STALE_S=600)
def test_sweep_ignores_a_healthy_vm(warnings_log) -> None:
    vm = make_vm("vm-ok")
    _alive(vm)
    assert service.sweep_guest_liveness() == 0
    assert warnings_log == []


@override_settings(VALI_GUEST_LIVENESS_STALE_S=600)
def test_sweep_ignores_a_vm_that_has_never_signalled() -> None:
    """`realtenant-ubuntu-1` on a pre-keepalive image is the live case:
    a signal a VM has never produced is NOT evidence of death."""
    make_vm("vm-never")
    assert service.sweep_guest_liveness() == 0


@override_settings(VALI_GUEST_LIVENESS_STALE_S=600)
def test_sweep_ignores_non_active_vms() -> None:
    vm = make_vm("vm-gone", state="destroyed")
    _silence(vm, ago_s=99999)
    assert service.sweep_guest_liveness() == 0


@override_settings(VALI_GUEST_LIVENESS_STALE_S=600)
def test_tick_reports_and_survives_a_sweep_failure(monkeypatch) -> None:
    vm = make_vm("vm-wedged")
    _silence(vm, ago_s=3600)
    assert service.tick_once().wedged_guests == 1

    def _boom() -> int:
        raise RuntimeError("sweep exploded")

    monkeypatch.setattr(service, "sweep_guest_liveness", _boom)
    # The tick must still complete — observability never breaks the loop.
    assert service.tick_once().wedged_guests == 0


# ═══ the reboot-recovery second trigger ══════════════════════════════
#
# EVERY test below asserts a "do nothing" outcome unless it is the single
# happy path — a false-positive relaunch disrupts a tenant.


@override_settings(
    VALI_REBOOT_RECOVERY_ENABLED=True,
    VALI_REBOOT_RECOVERY_ON_WEDGED_GUEST=False,
    VALI_REBOOT_RECOVERY_DEBOUNCE_POLLS=2,
    VALI_GUEST_LIVENESS_STALE_S=600,
)
def test_wedged_does_not_relaunch_while_the_flag_is_off(
    monkeypatch, stub_relaunch
) -> None:
    """DEFAULT posture: observe, never act. Root inside a guest can stop
    its own telemetry agent, which is indistinguishable from a wedge."""
    vm = make_vm()
    _make_alive_miner()
    _silence(vm, ago_s=3600)
    _set_domain(monkeypatch, True)
    RebootRecovery.objects.create(vm=vm, seen_running=True)
    for _ in range(10):
        assert service.reboot_recovery_once() == 0
    assert stub_relaunch == []
    assert RebootRecovery.objects.get(vm=vm).consecutive_wedged == 0


@override_settings(
    VALI_REBOOT_RECOVERY_ENABLED=True,
    VALI_REBOOT_RECOVERY_ON_WEDGED_GUEST=True,
    VALI_REBOOT_RECOVERY_DEBOUNCE_POLLS=3,
    VALI_GUEST_LIVENESS_STALE_S=600,
)
def test_wedged_relaunches_only_past_the_debounce(
    monkeypatch, stub_relaunch
) -> None:
    """The happy path — and the mutant it kills is "a wedged VM still
    reports healthy": with the old code this branch reset the debounce
    and returned False forever."""
    vm = make_vm()
    _make_alive_miner()
    _silence(vm, ago_s=3600)
    _set_domain(monkeypatch, True)
    RebootRecovery.objects.create(vm=vm, seen_running=True)

    assert service.reboot_recovery_once() == 0
    assert service.reboot_recovery_once() == 0
    assert stub_relaunch == []
    assert RebootRecovery.objects.get(vm=vm).consecutive_wedged == 2

    assert service.reboot_recovery_once() == 1
    assert stub_relaunch == [(vm.vm_id, "node-src")]
    rec = RebootRecovery.objects.get(vm=vm)
    assert rec.attempts == 1
    assert rec.last_outcome == "relaunched"
    assert rec.consecutive_wedged == 0


@override_settings(
    VALI_REBOOT_RECOVERY_ENABLED=True,
    VALI_REBOOT_RECOVERY_ON_WEDGED_GUEST=True,
    VALI_REBOOT_RECOVERY_DEBOUNCE_POLLS=1,
    VALI_GUEST_LIVENESS_STALE_S=600,
)
def test_a_healthy_vm_with_no_signal_history_is_never_relaunched(
    monkeypatch, stub_relaunch
) -> None:
    """THE false positive that would be worse than the bug. A live tenant
    on a pre-keepalive image (`realtenant-ubuntu-1`) has NEVER emitted
    one of the signal classes — `unknown` must never act."""
    vm = make_vm()
    _make_alive_miner()
    _set_domain(monkeypatch, True)
    RebootRecovery.objects.create(vm=vm, seen_running=True)
    assert vm.guest_signal_at is None

    for _ in range(20):
        assert service.reboot_recovery_once() == 0
    assert stub_relaunch == []
    assert RebootRecovery.objects.get(vm=vm).consecutive_wedged == 0


@override_settings(
    VALI_REBOOT_RECOVERY_ENABLED=True,
    VALI_REBOOT_RECOVERY_ON_WEDGED_GUEST=True,
    VALI_REBOOT_RECOVERY_DEBOUNCE_POLLS=1,
    VALI_GUEST_LIVENESS_STALE_S=600,
)
def test_a_fresh_signal_never_relaunches(monkeypatch, stub_relaunch) -> None:
    vm = make_vm()
    _make_alive_miner()
    _alive(vm)
    _set_domain(monkeypatch, True)
    RebootRecovery.objects.create(vm=vm, seen_running=True)
    for _ in range(5):
        assert service.reboot_recovery_once() == 0
    assert stub_relaunch == []


@override_settings(
    VALI_REBOOT_RECOVERY_ENABLED=True,
    VALI_REBOOT_RECOVERY_ON_WEDGED_GUEST=True,
    VALI_REBOOT_RECOVERY_DEBOUNCE_POLLS=1,
    VALI_GUEST_LIVENESS_STALE_S=600,
)
def test_an_unavailable_domain_state_never_relaunches_a_wedged_vm(
    monkeypatch, stub_relaunch
) -> None:
    """A miner we cannot reach / a libvirt we cannot query is `None` —
    the fail-safe boundary. It must stay fail-safe even when the guest
    watermark says wedged (which it will, precisely BECAUSE the miner is
    unreachable and its relay carries the receipts)."""
    vm = make_vm()
    _make_alive_miner()
    _silence(vm, ago_s=3600)
    _set_domain(monkeypatch, None)
    RebootRecovery.objects.create(vm=vm, seen_running=True)
    for _ in range(10):
        assert service.reboot_recovery_once() == 0
    assert stub_relaunch == []
    rec = RebootRecovery.objects.get(vm=vm)
    assert rec.consecutive_wedged == 0
    assert rec.consecutive_down == 0


@override_settings(
    VALI_REBOOT_RECOVERY_ENABLED=True,
    VALI_REBOOT_RECOVERY_ON_WEDGED_GUEST=True,
    VALI_REBOOT_RECOVERY_DEBOUNCE_POLLS=1,
    VALI_GUEST_LIVENESS_STALE_S=600,
)
def test_a_wedged_vm_on_a_dark_miner_is_left_to_migration(
    monkeypatch, stub_relaunch
) -> None:
    """A miner that has gone dark is §25's business. Reboot-recovery's
    alive-gate must still hold on the wedged path."""
    vm = make_vm()
    miner = _make_alive_miner()
    MinerIdentity.objects.filter(pk=miner.pk).update(
        last_seen_at=timezone.now() - timedelta(hours=2)
    )
    _silence(vm, ago_s=3600)
    _set_domain(monkeypatch, True)
    RebootRecovery.objects.create(vm=vm, seen_running=True)
    for _ in range(5):
        assert service.reboot_recovery_once() == 0
    assert stub_relaunch == []


@override_settings(
    VALI_REBOOT_RECOVERY_ENABLED=False,
    VALI_REBOOT_RECOVERY_ON_WEDGED_GUEST=True,
    VALI_REBOOT_RECOVERY_DEBOUNCE_POLLS=1,
    VALI_GUEST_LIVENESS_STALE_S=600,
)
def test_the_master_switch_still_gates_the_wedged_trigger(
    monkeypatch, stub_relaunch
) -> None:
    """The second trigger is nested INSIDE reboot-recovery — it cannot
    resurrect the scan on a fleet where the master switch is off."""
    vm = make_vm()
    _make_alive_miner()
    _silence(vm, ago_s=3600)
    _set_domain(monkeypatch, True)
    RebootRecovery.objects.create(vm=vm, seen_running=True)
    assert service.reboot_recovery_once() == 0
    assert stub_relaunch == []


@override_settings(
    VALI_REBOOT_RECOVERY_ENABLED=True,
    VALI_REBOOT_RECOVERY_ON_WEDGED_GUEST=True,
    VALI_REBOOT_RECOVERY_DEBOUNCE_POLLS=1,
    VALI_REBOOT_RECOVERY_MAX_ATTEMPTS=2,
    VALI_REBOOT_RECOVERY_BACKOFF_BASE_S=0.0,
    VALI_GUEST_LIVENESS_STALE_S=600,
)
def test_the_attempt_cap_bounds_a_wedged_relaunch_loop(
    monkeypatch, stub_relaunch
) -> None:
    """The blast radius of a false positive is bounded by the SAME cap as
    the domain-down trigger — a permanently-silent guest is not
    relaunched forever."""
    vm = make_vm()
    _make_alive_miner()
    _silence(vm, ago_s=3600)
    _set_domain(monkeypatch, True)
    RebootRecovery.objects.create(vm=vm, seen_running=True)
    for _ in range(10):
        service.reboot_recovery_once()
    assert len(stub_relaunch) == 2
    assert RebootRecovery.objects.get(vm=vm).last_outcome == "attempts-exhausted"


@override_settings(
    VALI_REBOOT_RECOVERY_ENABLED=True,
    VALI_REBOOT_RECOVERY_ON_WEDGED_GUEST=True,
    VALI_REBOOT_RECOVERY_DEBOUNCE_POLLS=1,
    VALI_REBOOT_RECOVERY_BACKOFF_BASE_S=3600.0,
    VALI_GUEST_LIVENESS_STALE_S=600,
)
def test_the_backoff_gates_the_wedged_retry(monkeypatch, stub_relaunch) -> None:
    vm = make_vm()
    _make_alive_miner()
    _silence(vm, ago_s=3600)
    _set_domain(monkeypatch, True)
    RebootRecovery.objects.create(vm=vm, seen_running=True)
    assert service.reboot_recovery_once() == 1
    for _ in range(5):
        assert service.reboot_recovery_once() == 0
    assert len(stub_relaunch) == 1


@override_settings(
    VALI_REBOOT_RECOVERY_ENABLED=True,
    VALI_REBOOT_RECOVERY_ON_WEDGED_GUEST=True,
    VALI_REBOOT_RECOVERY_DEBOUNCE_POLLS=1,
    VALI_GUEST_LIVENESS_STALE_S=600,
)
def test_a_fleet_wide_silence_reads_as_a_relay_fault_not_n_wedges(
    monkeypatch, stub_relaunch, warnings_log
) -> None:
    """A served receipt rides guest → vsock → miner-agent → Edge → vali.
    A miner-agent whose vsock relay is broken silences EVERY guest on the
    host at once while its own (non-vsock) heartbeat keeps it "alive".
    N guests hanging in the same poll is not a thing; refuse to act."""
    vm_a = make_vm("vm-a", host="node-src")
    vm_b = make_vm("vm-b", host="node-src")
    _make_alive_miner()
    _silence(vm_a, ago_s=3600)
    _silence(vm_b, ago_s=3600)
    _set_domain(monkeypatch, True)
    RebootRecovery.objects.create(vm=vm_a, seen_running=True)
    RebootRecovery.objects.create(vm=vm_b, seen_running=True)

    for _ in range(5):
        assert service.reboot_recovery_once() == 0
    assert stub_relaunch == []
    assert any("relay fault" in m for m in warnings_log)


@override_settings(
    VALI_REBOOT_RECOVERY_ENABLED=True,
    VALI_REBOOT_RECOVERY_ON_WEDGED_GUEST=True,
    VALI_REBOOT_RECOVERY_DEBOUNCE_POLLS=1,
    VALI_GUEST_LIVENESS_STALE_S=600,
)
def test_one_wedged_vm_among_healthy_peers_still_relaunches(
    monkeypatch, stub_relaunch
) -> None:
    """The relay-fault guard must not swallow a GENUINE single wedge: a
    healthy peer on the same miner proves the relay works."""
    vm_a = make_vm("vm-a", host="node-src")
    vm_b = make_vm("vm-b", host="node-src")
    _make_alive_miner()
    _silence(vm_a, ago_s=3600)
    _alive(vm_b)
    _set_domain(monkeypatch, True)
    RebootRecovery.objects.create(vm=vm_a, seen_running=True)
    RebootRecovery.objects.create(vm=vm_b, seen_running=True)

    assert service.reboot_recovery_once() == 1
    assert stub_relaunch == [("vm-a", "node-src")]


@override_settings(
    VALI_REBOOT_RECOVERY_ENABLED=True,
    VALI_REBOOT_RECOVERY_ON_WEDGED_GUEST=True,
    VALI_REBOOT_RECOVERY_DEBOUNCE_POLLS=1,
    VALI_GUEST_LIVENESS_STALE_S=600,
)
def test_a_wedged_vm_alone_on_its_miner_still_relaunches(
    monkeypatch, stub_relaunch
) -> None:
    """With ONE VM on the host the relay-fault and wedge hypotheses are
    indistinguishable — the guard requires >1 and must not fire."""
    vm = make_vm("vm-solo", host="node-src")
    _make_alive_miner()
    _silence(vm, ago_s=3600)
    _set_domain(monkeypatch, True)
    RebootRecovery.objects.create(vm=vm, seen_running=True)
    assert service.reboot_recovery_once() == 1
    assert stub_relaunch == [("vm-solo", "node-src")]


@override_settings(
    VALI_REBOOT_RECOVERY_ENABLED=True,
    VALI_REBOOT_RECOVERY_ON_WEDGED_GUEST=True,
    VALI_REBOOT_RECOVERY_DEBOUNCE_POLLS=3,
    VALI_GUEST_LIVENESS_STALE_S=600,
)
def test_a_recovering_guest_resets_the_wedged_debounce(
    monkeypatch, stub_relaunch
) -> None:
    """Two wedged polls then a fresh signal must NOT leave the VM one
    poll from a relaunch."""
    vm = make_vm()
    _make_alive_miner()
    _set_domain(monkeypatch, True)
    RebootRecovery.objects.create(vm=vm, seen_running=True)

    _silence(vm, ago_s=3600)
    service.reboot_recovery_once()
    service.reboot_recovery_once()
    assert RebootRecovery.objects.get(vm=vm).consecutive_wedged == 2

    _alive(vm)
    assert service.reboot_recovery_once() == 0
    assert RebootRecovery.objects.get(vm=vm).consecutive_wedged == 0

    _silence(vm, ago_s=3600)
    assert service.reboot_recovery_once() == 0
    assert service.reboot_recovery_once() == 0
    assert stub_relaunch == []


@override_settings(
    VALI_REBOOT_RECOVERY_ENABLED=True,
    VALI_REBOOT_RECOVERY_ON_WEDGED_GUEST=True,
    VALI_REBOOT_RECOVERY_DEBOUNCE_POLLS=1,
    VALI_GUEST_LIVENESS_STALE_S=600,
)
def test_the_two_triggers_do_not_pool_their_debounce(
    monkeypatch, stub_relaunch
) -> None:
    """Alternating `down` / `wedged` polls must not accumulate a relaunch
    neither condition earned — hence two counters, not one."""
    vm = make_vm()
    _make_alive_miner()
    _silence(vm, ago_s=3600)
    RebootRecovery.objects.create(vm=vm, seen_running=True)

    holder = {"v": False}
    monkeypatch.setattr(
        service.effects, "poll_domain_running", lambda vm: holder["v"]
    )
    with override_settings(VALI_REBOOT_RECOVERY_DEBOUNCE_POLLS=4):
        for value in (False, True, False, True):
            holder["v"] = value
            assert service.reboot_recovery_once() == 0
        rec = RebootRecovery.objects.get(vm=vm)
        # Neither counter reached 4 — 2 down polls and 2 wedged polls did
        # not add up to a relaunch.
        assert rec.consecutive_down < 4
        assert rec.consecutive_wedged < 4
    assert stub_relaunch == []


@override_settings(
    VALI_REBOOT_RECOVERY_ENABLED=True,
    VALI_REBOOT_RECOVERY_ON_WEDGED_GUEST=True,
    VALI_REBOOT_RECOVERY_DEBOUNCE_POLLS=1,
    VALI_GUEST_LIVENESS_STALE_S=600,
)
def test_the_domain_down_trigger_is_unchanged(monkeypatch, stub_relaunch) -> None:
    """Regression guard: the original trigger still fires, and it does
    NOT require an in-guest signal (a powered-off CVM has no fresh one by
    definition)."""
    vm = make_vm()
    _make_alive_miner()
    _set_domain(monkeypatch, False)
    RebootRecovery.objects.create(vm=vm, seen_running=True)
    assert vm.guest_signal_at is None  # `unknown`, and still recovered
    assert service.reboot_recovery_once() == 1
    assert stub_relaunch == [(vm.vm_id, "node-src")]
