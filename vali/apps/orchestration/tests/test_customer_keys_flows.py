"""Customer-held keys (H6b) — the lifecycle flows that change with the mode.

- a restore's pre-commit timer, and the reboot-recovery WEDGED trigger,
  hold back while an M1/M2 guest waits on its key guardian (design §6);
- §24 records what it achieved for the data (`data_death`), and never
  claims a disk crypto-erase for M2 (design §3.4);
- an A2 rollback restore of an M2 VM is the CUSTOMER'S guardian decision:
  vali never arms the KBS for it (design §2).

The restore scaffolding (fixtures, the fake power API, the phase helpers)
is the restore suite's own.
"""

from __future__ import annotations

from datetime import timedelta
from types import SimpleNamespace

import pytest
from django.test import override_settings
from django.utils import timezone

from apps.lifecycle import guardian_wait, guest_liveness
from apps.lifecycle.models import Vm, VmBootPhase
from apps.miners.models import MinerIdentity, MinerStatus
from apps.orchestration import service
from apps.orchestration.models import MigrationKind, MigrationState, RebootRecovery

from . import test_restore as _tr
from .conftest import FakeEffects
from .factories import make_vm
from .test_restore import (
    _advance,
    _age_phase,
    _chain,
    _golden_vm,
    _original_grant,
    _Power,
    _start,
    _to_verifying,
)

# The restore suite's fixtures, used here by name.
_restore_env = _tr._restore_env
pwr = _tr.pwr

pytestmark = pytest.mark.django_db


def _waiting(vm: Vm, *, mode: str = "split", reason: str = "unreachable", ago_s: float = 30):
    at = timezone.now() - timedelta(seconds=ago_s)
    Vm.objects.filter(pk=vm.pk).update(
        key_mode=mode, guardian_wait_reason=reason, guardian_wait_since=at, guardian_wait_at=at
    )
    vm.refresh_from_db()


# ── the guardian-wait clock (unit) ───────────────────────────────────


def _vm_ns(**kw):
    base = {
        "key_mode": "split",
        "guardian_wait_reason": "unreachable",
        "guardian_wait_since": None,
        "guardian_wait_at": None,
    }
    base.update(kw)
    return SimpleNamespace(**base)


def test_is_awaiting_needs_a_fresh_non_terminal_report_of_an_m1_m2_vm() -> None:
    now = timezone.now()
    fresh = now - timedelta(seconds=guardian_wait.fresh_s())
    stale = fresh - timedelta(seconds=1)
    assert guardian_wait.is_awaiting(_vm_ns(guardian_wait_at=fresh), now)
    assert not guardian_wait.is_awaiting(_vm_ns(guardian_wait_at=stale), now)
    assert not guardian_wait.is_awaiting(_vm_ns(guardian_wait_at=now, key_mode="hippius"), now)
    assert not guardian_wait.is_awaiting(_vm_ns(guardian_wait_at=now, guardian_wait_reason=""), now)
    assert not guardian_wait.is_awaiting(
        _vm_ns(guardian_wait_at=now, guardian_wait_reason="refused:erased"), now
    )
    assert not guardian_wait.is_awaiting(_vm_ns(), now)


def test_the_timer_restarts_at_the_last_report_capped_by_the_max_pause() -> None:
    start = timezone.now() - timedelta(hours=3)
    cap = start + timedelta(seconds=guardian_wait.max_pause_s())
    at = start + timedelta(minutes=5)
    assert guardian_wait.timer_start(_vm_ns(guardian_wait_at=at), start) == at
    # a report before the phase: no credit
    before = start - timedelta(seconds=1)
    assert guardian_wait.timer_start(_vm_ns(guardian_wait_at=before), start) == start
    # capped
    late = cap + timedelta(hours=1)
    assert guardian_wait.timer_start(_vm_ns(guardian_wait_at=late), start) == cap
    # no credit for M0, for a terminal reason, or with no report
    assert (
        guardian_wait.timer_start(_vm_ns(guardian_wait_at=at, key_mode="hippius"), start) == start
    )
    assert (
        guardian_wait.timer_start(
            _vm_ns(guardian_wait_at=at, guardian_wait_reason="refused:erased"), start
        )
        == start
    )
    assert guardian_wait.timer_start(_vm_ns(), start) == start
    # a cleared wait (reason "") still credits its last report
    assert (
        guardian_wait.timer_start(_vm_ns(guardian_wait_at=at, guardian_wait_reason=""), start) == at
    )


def test_only_a_restore_waiting_on_the_guest_boot_is_paused() -> None:
    """The same waiting M1 VM: a restore/failover in `restore_verifying`
    gets the credit; a §25 migration, or any other phase, never does."""
    vm = make_vm()
    _waiting(vm, ago_s=30)
    start = timezone.now() - timedelta(hours=1)

    def job(kind: str, state: str) -> SimpleNamespace:
        return SimpleNamespace(
            kind=kind, state=state, phase_started_at=start, vm_id=vm.pk, job_id="j"
        )

    verifying = MigrationState.RESTORE_VERIFYING.value
    assert service._timer_start(job(MigrationKind.RESTORE.value, verifying)) == vm.guardian_wait_at
    assert service._timer_start(job(MigrationKind.FAILOVER.value, verifying)) == vm.guardian_wait_at
    assert service._timer_start(job(MigrationKind.MIGRATE.value, verifying)) is start
    for state in (MigrationState.DEST_ACTIVATING.value, MigrationState.RESTORE_STAGING.value):
        assert service._timer_start(job(MigrationKind.RESTORE.value, state)) is start


# ── restore: the pre-commit auto-revert waits for the guardian ────────


@pytest.mark.parametrize("mode", ["split", "customer"])
def test_the_auto_revert_is_paused_while_the_guest_waits_on_its_guardian(
    fx: FakeEffects, pwr: _Power, mode: str
) -> None:
    vm = _golden_vm()
    job = _to_verifying(fx, pwr, _start(vm, _chain(vm)[-1]))
    _original_grant(fx, job)
    _age_phase(job)  # far past the 900 s verify timeout
    _waiting(vm, mode=mode, ago_s=30)
    job = _advance(job)
    assert job.state == MigrationState.RESTORE_VERIFYING.value, job.reason
    # Once the reports stop, the timer runs its full length from the last one.
    _waiting(vm, mode=mode, ago_s=100)
    job = _advance(job)
    assert job.state == MigrationState.RESTORE_VERIFYING.value, job.reason
    _waiting(vm, mode=mode, ago_s=1000)
    job = _advance(job)
    assert job.state == MigrationState.RESTORE_REVERTING.value
    assert job.reason == "verify-timeout"


@pytest.mark.parametrize(
    ("mode", "reason"),
    [("hippius", "unreachable"), ("split", "refused:erased")],
)
def test_an_m0_vm_or_an_erased_key_never_pauses_the_revert(
    fx: FakeEffects, pwr: _Power, mode: str, reason: str
) -> None:
    vm = _golden_vm()
    job = _to_verifying(fx, pwr, _start(vm, _chain(vm)[-1]))
    _original_grant(fx, job)
    _age_phase(job)
    _waiting(vm, mode=mode, reason=reason, ago_s=30)
    job = _advance(job)
    assert job.state == MigrationState.RESTORE_REVERTING.value
    assert job.reason == "verify-timeout"


def test_the_pause_is_bounded(fx: FakeEffects, pwr: _Power) -> None:
    """A forged wait cannot hold a restore fenced forever."""
    vm = _golden_vm()
    job = _to_verifying(fx, pwr, _start(vm, _chain(vm)[-1]))
    _original_grant(fx, job)
    _age_phase(job, seconds=guardian_wait.max_pause_s() + 3600)
    _waiting(vm, ago_s=10)
    job = _advance(job)
    assert job.state == MigrationState.RESTORE_REVERTING.value
    assert job.reason == "verify-timeout"


# ── reboot-recovery: an awaiting guest is not wedged ──────────────────


def _alive_miner() -> None:
    # The restore fixture already registered it; make it alive + bindable.
    MinerIdentity.objects.update_or_create(
        miner_id="node-src",
        defaults={
            "chain_node_id": "cd" * 32,
            "netbird_ip": "100.64.0.9",
            "last_seen_at": timezone.now(),
            "status": MinerStatus.ACTIVE,
        },
    )


def _silent(vm: Vm) -> None:
    Vm.objects.filter(pk=vm.pk).update(
        guest_signal_at=timezone.now() - timedelta(hours=1),
        guest_signal_kind=guest_liveness.SIGNAL_SERVED_RECEIPT,
        boot_phase=VmBootPhase.RUNNING.value,
    )
    vm.refresh_from_db()


@override_settings(
    VALI_REBOOT_RECOVERY_ENABLED=True,
    VALI_REBOOT_RECOVERY_ON_WEDGED_GUEST=True,
    VALI_REBOOT_RECOVERY_DEBOUNCE_POLLS=1,
    VALI_GUEST_LIVENESS_STALE_S=600,
)
@pytest.mark.parametrize(
    ("ago_s", "since_ago_s", "relaunched"),
    [
        (30, 30, False),  # fresh wait
        (3600, 3600, True),  # stale report: not waiting any more
        (30, 86400 - 60, False),  # a long wait, still inside the cap
        (30, 86400 + 60, True),  # fresh reports, but the wait began past the cap
    ],
)
def test_a_wedged_vm_waiting_on_its_guardian_is_not_relaunched(
    monkeypatch, ago_s: float, since_ago_s: float, relaunched: bool
) -> None:
    calls: list[str] = []
    monkeypatch.setattr(
        service, "_reboot_recovery_relaunch", lambda vm, node: calls.append(vm.vm_id) or True
    )
    monkeypatch.setattr(service.effects, "poll_domain_running", lambda vm: True)
    vm = make_vm()
    _alive_miner()
    _silent(vm)
    _waiting(vm, ago_s=ago_s)
    Vm.objects.filter(pk=vm.pk).update(
        guardian_wait_since=timezone.now() - timedelta(seconds=since_ago_s)
    )
    assert guardian_wait.max_pause_s() == 86400
    RebootRecovery.objects.create(vm=vm, seen_running=True, consecutive_wedged=0)
    assert service.reboot_recovery_once() == (1 if relaunched else 0)
    assert calls == ([vm.vm_id] if relaunched else [])
    if not relaunched:
        assert RebootRecovery.objects.get(vm=vm).consecutive_wedged == 0


# ── §24: what the erase achieved for the data ─────────────────────────


def _decommissioned(fx: FakeEffects, mode: str):
    from apps.orchestration.models import DecommissionState

    from .factories import make_launch_record, make_service_client
    from .test_decommission import _drive_until

    vm = make_vm(generation=5, host="node-src")
    Vm.objects.filter(pk=vm.pk).update(key_mode=mode)
    vm.refresh_from_db()
    make_launch_record(vm, disk_mode="golden_verity_overlay")
    job = service.start_decommission(vm=vm, decided_by=make_service_client())
    _drive_until(job, DecommissionState.DONE.value)
    vm.refresh_from_db()
    job.refresh_from_db()
    return vm, job


@pytest.mark.parametrize(
    ("mode", "death"),
    [
        ("hippius", "crypto-erased"),
        ("split", "crypto-erased"),
        ("customer", "customer-erase-required"),
    ],
)
def test_decommission_records_what_the_erase_did_to_the_data(
    fx: FakeEffects, mode: str, death: str
) -> None:
    from apps.lifecycle.models import VmState
    from apps.lifecycle.views import _serialize_vm
    from apps.orchestration.views import _serialize_decommission

    vm, job = _decommissioned(fx, mode)
    # Every mode: the per-VM Transit keys (`kek-<vm>` wraps the userdata an
    # M2 VM has too) are destroyed and the KV copies deleted, the domain is
    # destroyed and the VM tombstoned.
    assert fx.did("crypto_erase_kek_transit")
    assert fx.did("dispatch_destroy")
    assert vm.state == VmState.DESTROYED
    assert job.kek_erased_at is not None
    # …but only M0/M1 may be reported as a crypto-erase of the disk.
    assert job.data_death == death
    assert _serialize_decommission(job)["data_death"] == death
    assert _serialize_vm(vm)["data_death"] == death


def test_a_live_vm_has_no_data_death() -> None:
    from apps.lifecycle.views import _serialize_vm

    vm = make_vm()
    assert _serialize_vm(vm)["data_death"] is None


# ── vm_id charset locks: a trailing newline is not a vm_id ────────────


def test_every_vm_id_lock_refuses_a_trailing_newline(fx: FakeEffects) -> None:
    """`re.match(r"^…$")` accepts `"vm-1\\n"` (`$` matches before a final
    newline); each lock is a `fullmatch` now."""
    from apps.orchestration import effects, launch_jobs
    from apps.orchestration.services import launch
    from apps.tenant_bake import views as bake_views

    for rx in (
        launch._VM_ID_RE,
        launch_jobs._VM_ID_RE,
        effects._VM_ID_RE,
        bake_views._VM_ID_RE,
    ):
        assert rx.match("vm-1\n") is not None  # the hole `fullmatch` closes
        assert rx.fullmatch("vm-1\n") is None
        assert rx.fullmatch("vm-1") is not None
    with pytest.raises(launch_jobs.LaunchIntentError):
        launch_jobs._canonical_kek_path({"vm_id": "vm-1\n"})
    with pytest.raises(effects.EffectError, match="charset lock"):
        fx.real["crypto_erase_kek_transit"](SimpleNamespace(vm_id="vm-1\n"))
    with pytest.raises(launch.LaunchConfigError, match="vm_id must match"):
        launch.launch_on_miner(SimpleNamespace(vm_id="vm-1\n"), SimpleNamespace())
