"""Boot stall in the orchestration tick, and the points that start the
boot clock (`Vm.boot_started_at`).

The sweep turns a boot that produced no in-guest signal within its
per-flavor deadline (e.g. its ticket never arrived, so it never unlocked)
into an ERROR and a `TickReport` count. The clock tests pin every place a
new boot begins, so a relaunched VM is never judged on its original
launch time, and pin the one place it must NOT restart: a same-miner
launch retry on an already-bound host.
"""

from __future__ import annotations

import logging
from datetime import timedelta
from types import SimpleNamespace

import pytest
from django.test import override_settings
from django.utils import timezone

from apps.lifecycle.models import Vm, VmBootPhase, VmState
from apps.miners.models import MinerIdentity
from apps.orchestration import service
from apps.orchestration.models import LaunchJob, LaunchJobState, MigrationState
from apps.orchestration.services import launch

from .factories import make_migration_job, make_service_client, make_vm

pytestmark = pytest.mark.django_db

# A flat 900 s deadline: `make_vm` rows have no LaunchJob, so their flavor
# is unknown and would otherwise get the full disk allowance.
FLAT = override_settings(VALI_BOOT_STALL_S=900, VALI_BOOT_STALL_DISK_CAP_S=0)


def _booting_since(vm: Vm, *, ago_s: int, phase: str = VmBootPhase.BOOTING.value) -> Vm:
    Vm.objects.filter(pk=vm.pk).update(
        boot_phase=phase, boot_started_at=timezone.now() - timedelta(seconds=ago_s)
    )
    vm.refresh_from_db()
    return vm


def _started_ago(vm_id: str) -> float:
    at = Vm.objects.get(vm_id=vm_id).boot_started_at
    assert at is not None
    return (timezone.now() - at).total_seconds()


@pytest.fixture(autouse=True)
def _reset_boot_stall_memo():
    service._boot_stall_warn_memo = (frozenset(), 0.0)
    yield
    service._boot_stall_warn_memo = (frozenset(), 0.0)


@pytest.fixture
def errors_log():
    """ERRORs from `apps.orchestration.service` (the `apps` logger does not
    propagate, so `caplog` sees nothing)."""
    logger = logging.getLogger("apps.orchestration.service")
    records: list[str] = []

    class _Sink(logging.Handler):
        def emit(self, record: logging.LogRecord) -> None:
            records.append(record.getMessage())

    handler = _Sink(level=logging.ERROR)
    logger.addHandler(handler)
    try:
        yield records
    finally:
        logger.removeHandler(handler)


# ═══ the sweep ═══════════════════════════════════════════════════════


@FLAT
def test_a_vm_stuck_in_booting_past_the_bound_is_logged_and_counted(errors_log) -> None:
    _booting_since(make_vm("vm-stuck", host="node-a"), ago_s=1500)
    assert service.sweep_boot_stalls() == 1
    assert len(errors_log) == 1
    line = errors_log[0]
    assert "STALLED" in line
    assert "vm-stuck host=node-a" in line
    assert "for=1500s" in line or "for=1501s" in line
    assert "deadline=900s" in line


@FLAT
def test_a_slow_boot_inside_the_bound_is_silent(errors_log) -> None:
    _booting_since(make_vm("vm-milan"), ago_s=340)
    assert service.sweep_boot_stalls() == 0
    assert errors_log == []


@FLAT
def test_a_boot_that_has_signalled_is_never_swept(errors_log) -> None:
    vm = _booting_since(make_vm("vm-ok"), ago_s=86400, phase=VmBootPhase.RUNNING.value)
    Vm.objects.filter(pk=vm.pk).update(guest_signal_at=timezone.now())
    assert service.sweep_boot_stalls() == 0
    assert errors_log == []


@FLAT
@pytest.mark.parametrize("phase", [VmBootPhase.KEK_RELEASED.value, VmBootPhase.RUNNING.value])
def test_boot_phase_does_not_exempt_a_silent_boot(errors_log, phase: str) -> None:
    _booting_since(make_vm("vm-hung"), ago_s=1500, phase=phase)
    assert service.sweep_boot_stalls() == 1


def test_the_sweep_applies_the_flavor_deadline(errors_log) -> None:
    """2xlarge (640 GiB): ~72 min of first-boot wipe on Milan is inside
    900 + 15×640 = 10 500 s; a small (40 GiB) silent that long is not."""
    for vm_id, flavor in (("vm-2xl", "2xlarge"), ("vm-small", "small")):
        _booting_since(make_vm(vm_id), ago_s=72 * 60)
        LaunchJob.objects.create(
            job_id=f"j-{vm_id}", vm_id=vm_id, tenant_id="t", flavor=flavor,
            userdata_vault_path="x", userdata_vault_version=1, kek_vault_path="x",
            phase_started_at=timezone.now(), decided_by=make_service_client(),
        )
    assert service.sweep_boot_stalls() == 1
    assert "vm-small" in errors_log[0] and "vm-2xl" not in errors_log[0]


@FLAT
def test_the_sweep_skips_rows_without_a_host(errors_log) -> None:
    _booting_since(make_vm("vm-unplaced", host=""), ago_s=5000)
    assert service.sweep_boot_stalls() == 0


@FLAT
def test_the_tick_reports_the_count(monkeypatch) -> None:
    _booting_since(make_vm("vm-stuck"), ago_s=1500)
    monkeypatch.setattr(service.effects, "poll_domain_running", lambda vm: None)
    assert service.tick_once().boot_stalls == 1


# ═══ the boot clock ══════════════════════════════════════════════════


def _unbound_row(vm_id: str) -> Vm:
    return Vm.objects.create(
        vm_id=vm_id, lease_id=f"l-{vm_id}", state=VmState.ACTIVE, generation=1,
        host="", lifecycle_vk=bytes(32),
    )


def test_the_first_host_bind_starts_the_clock() -> None:
    _unbound_row("vm-new")
    launch._bind_vm_host("vm-new", "node-a")
    assert _started_ago("vm-new") < 5


def test_a_same_miner_retry_does_not_restart_the_clock() -> None:
    """An `already-launched` retry reaches `_bind_vm_host` on a bound host:
    it must not push the verdict back."""
    _unbound_row("vm-retry")
    launch._bind_vm_host("vm-retry", "node-a")
    old = timezone.now() - timedelta(seconds=800)
    Vm.objects.filter(vm_id="vm-retry").update(boot_started_at=old)
    launch._bind_vm_host("vm-retry", "node-a")
    assert Vm.objects.get(vm_id="vm-retry").boot_started_at == old


_SPEC = {
    "tenant_id": "tenant-1",
    "user_id": "user-1",
    "vm_id": "vm-1",
    "lease_id": "lease-vm-1",
    "s3_bucket": "b",
    "s3_key_prefix": "p",
    "luks_disk_sha256_hex": "a" * 64,
    "kernel_sha256_hex": "b" * 64,
    "initrd_sha256_hex": "c" * 64,
    "luks_header_sha256_hex": "d" * 64,
    "flavor": "small",
    "cmdline": "console=ttyS0",
}


@pytest.mark.parametrize("disposition", [launch.ACCEPTED, launch.RETRIABLE])
def test_an_accepted_relaunch_restarts_the_clock(monkeypatch, disposition) -> None:
    """Reboot-recovery and the power-API start both relaunch through here."""
    vm = _booting_since(make_vm("vm-1"), ago_s=7 * 86400)
    miner = MinerIdentity.objects.create(
        miner_id="node-src", pubkey_hex="11" * 32, platform_id="ab" * 64,
        chain_node_id="cc" * 32,
    )
    LaunchJob.objects.create(
        job_id="succ-stall", vm_id=vm.vm_id, tenant_id="tenant-1", flavor="small",
        spec_json=dict(_SPEC), userdata_vault_path="x/vm-1/userdata",
        userdata_vault_version=1, kek_vault_path="x/vm-1/luks-kek",
        state=LaunchJobState.SUCCEEDED.value, phase_started_at=timezone.now(),
        finished_at=timezone.now(), decided_by=make_service_client(),
    )
    from apps.orchestration.services import vault_kv as vk

    monkeypatch.setattr(vk, "get_kv", lambda mount, path, version=None: b"u")
    monkeypatch.setattr(
        launch, "launch_on_miner",
        lambda spec, m, **_kw: SimpleNamespace(disposition=disposition, emit={}),
    )
    monkeypatch.setattr(service, "rebind_placement_to_host", lambda *a, **k: None)

    accepted = service._reboot_recovery_relaunch(vm, miner.miner_id)
    assert accepted is (disposition == launch.ACCEPTED)
    if accepted:
        assert _started_ago("vm-1") < 5
    else:
        assert _started_ago("vm-1") > 86400


def _fenced(vm_id: str = "vm-1") -> tuple[Vm, object]:
    vm = make_vm(vm_id, host="node-src", generation=1)
    job = make_migration_job(vm, state=MigrationState.FAILED.value)
    Vm.objects.filter(pk=vm.pk).update(
        state=VmState.MIGRATING.value, migration_dest=job.dest_node_id,
        new_generation=job.new_gen, boot_phase="",
        boot_started_at=timezone.now() - timedelta(days=7),
    )
    return Vm.objects.get(pk=vm.pk), job


@FLAT
def test_a_restore_to_source_does_not_restart_the_clock() -> None:
    """The restore cannot tell whether the source guest is down, so it is
    not a new boot: the VM keeps its old clock (this one never signalled,
    so it reads stalled until a relaunch restamps it)."""
    vm, job = _fenced()
    assert service.restore_source_vm(vm, job) is True
    assert _started_ago("vm-1") > 86400
    vm.refresh_from_db()
    assert vm.boot_stall().stalled


def test_a_dest_activation_restarts_the_clock() -> None:
    vm, job = _fenced()
    service._activate_dest_vm(job)
    vm.refresh_from_db()
    assert vm.state == VmState.ACTIVE and vm.host == job.dest_node_id
    assert _started_ago("vm-1") < 5


# ═══ the log memo ════════════════════════════════════════════════════


@FLAT
@override_settings(VALI_BOOT_STALL_WARN_INTERVAL_S=3600)
def test_the_error_repeats_only_when_the_stalled_set_changes(errors_log) -> None:
    _booting_since(make_vm("vm-a"), ago_s=1500)
    assert service.sweep_boot_stalls() == 1
    assert service.sweep_boot_stalls() == 1  # counted every tick...
    assert len(errors_log) == 1  # ...logged once

    _booting_since(make_vm("vm-b"), ago_s=1500)
    assert service.sweep_boot_stalls() == 2
    assert len(errors_log) == 2
    assert "vm-a" in errors_log[-1] and "vm-b" in errors_log[-1]

    Vm.objects.filter(vm_id="vm-b").update(guest_signal_at=timezone.now())
    assert service.sweep_boot_stalls() == 1
    assert len(errors_log) == 3  # the set shrank: re-logged


@FLAT
@override_settings(VALI_BOOT_STALL_WARN_INTERVAL_S=0)
def test_the_error_repeats_once_the_interval_lapses(errors_log) -> None:
    _booting_since(make_vm("vm-a"), ago_s=1500)
    service.sweep_boot_stalls()
    service.sweep_boot_stalls()
    assert len(errors_log) == 2


@FLAT
@override_settings(VALI_BOOT_STALL_WARN_INTERVAL_S=3600)
def test_a_cleared_then_recurring_stall_is_logged_again(errors_log) -> None:
    vm = _booting_since(make_vm("vm-a"), ago_s=1500)
    service.sweep_boot_stalls()
    Vm.objects.filter(pk=vm.pk).update(guest_signal_at=timezone.now())
    assert service.sweep_boot_stalls() == 0
    Vm.objects.filter(pk=vm.pk).update(guest_signal_at=None)
    service.sweep_boot_stalls()
    assert len(errors_log) == 2


# ═══ relaunches ══════════════════════════════════════════════════════


@FLAT
@pytest.mark.parametrize(
    "prior_phase",
    ["", VmBootPhase.BOOTING.value, VmBootPhase.KEK_RELEASED.value, VmBootPhase.RUNNING.value],
)
def test_a_stuck_relaunch_is_flagged_whatever_the_previous_boot_reached(
    errors_log, prior_phase: str
) -> None:
    """The relaunch blind spot is closed: `boot_phase` is monotonic and
    still says what the PREVIOUS boot reached, but the verdict only asks
    whether THIS boot has produced an in-guest signal."""
    vm = make_vm("vm-r")
    Vm.objects.filter(pk=vm.pk).update(
        boot_phase=prior_phase,
        # The previous boot signalled until the relaunch...
        guest_signal_at=timezone.now() - timedelta(seconds=1600),
        # ...and the relaunch stamped the clock after it.
        boot_started_at=timezone.now() - timedelta(seconds=1500),
    )
    vm.refresh_from_db()
    assert vm.boot_stall().stalled
    assert service.sweep_boot_stalls() == 1


# ═══ no automated action ═════════════════════════════════════════════


@FLAT
@override_settings(
    VALI_REBOOT_RECOVERY_ENABLED=True,
    VALI_REBOOT_RECOVERY_ON_WEDGED_GUEST=True,
    VALI_REBOOT_RECOVERY_DEBOUNCE_POLLS=1,
)
def test_a_stalled_vm_never_arms_the_wedged_relaunch(monkeypatch) -> None:
    """Read-only: with the WEDGED trigger ARMED, a boot-stalled VM that has
    never signalled is still not relaunched — the trigger stays keyed on
    `guest_liveness.classify`, which reads it `unknown`."""
    from apps.miners.models import MinerStatus
    from apps.orchestration.models import RebootRecovery

    vm = _booting_since(make_vm("vm-stuck"), ago_s=5000, phase="")
    assert vm.boot_stall().stalled
    MinerIdentity.objects.create(
        miner_id="node-src", pubkey_hex="11" * 32, platform_id="ab" * 64,
        chain_node_id="cc" * 32, netbird_ip="100.64.0.9",
        last_seen_at=timezone.now(), status=MinerStatus.ACTIVE,
    )
    RebootRecovery.objects.create(vm=vm, seen_running=True)
    monkeypatch.setattr(service.effects, "poll_domain_running", lambda v: True)
    relaunched: list[str] = []
    monkeypatch.setattr(
        service, "_reboot_recovery_relaunch", lambda v, n: relaunched.append(v.vm_id) or True
    )
    for _ in range(5):
        service.reboot_recovery_once()
    assert relaunched == []
    assert RebootRecovery.objects.get(vm=vm).consecutive_wedged == 0
