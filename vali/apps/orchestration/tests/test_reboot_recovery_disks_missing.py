"""Reboot-recovery must never relaunch a VM onto a host that lacks its disks.

Live 2026-09-25 (a migrated VM, golden ubuntu): a §25 migration miner-c → miner-b
reported Done although miner-b had restored nothing. Reboot-recovery then
relaunched the VM on miner-b with a plain launch order, and the miner-agent
CREATED a blank 40 GiB overlay and a blank boot-counter disk and booted.
The KBS answered 403 so nothing was lost that time — but a blank golden
overlay is `luksFormat`ted on the first boot that DOES get a KEK.

A relaunch now asks the miner to require the VM's existing disks; the miner
refuses with `relaunch-disks-missing` and creates nothing. These tests pin
what vali does with that refusal: stop relaunching (no retry loop), log it
loudly with where the data probably is, surface it every tick, and refuse a
power `start` the same way.
"""

from __future__ import annotations

import contextlib
import logging
from collections.abc import Iterator

import pytest
from django.test import override_settings
from django.utils import timezone

from apps.lifecycle.models import VmPowerState
from apps.miners.models import MinerIdentity, MinerStatus
from apps.orchestration import order_dispatch, service
from apps.orchestration.models import (
    LaunchJob,
    LaunchJobState,
    MigrationState,
    RebootRecovery,
)
from apps.orchestration.services import launch, power
from apps.scheduler import cvm_capability

from .factories import make_migration_job, make_service_client, make_vm

pytestmark = pytest.mark.django_db

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


def _miner(miner_id: str = "node-src") -> MinerIdentity:
    return MinerIdentity.objects.create(
        miner_id=miner_id,
        pubkey_hex=f"{abs(hash(miner_id)) % (16**16):016x}".ljust(64, "0"),
        platform_id=f"plat-{miner_id}",
        chain_node_id=f"{abs(hash(miner_id)) % (16**16):016x}".ljust(64, "1"),
        netbird_ip="100.64.0.9",
        last_seen_at=timezone.now(),
        status=MinerStatus.ACTIVE,
    )


def _succeeded_launch(vm) -> None:
    LaunchJob.objects.create(
        job_id=f"succ-{vm.vm_id}",
        vm_id=vm.vm_id,
        tenant_id="tenant-1",
        flavor="small",
        spec_json=dict(_SPEC),
        userdata_vault_path=f"x/{vm.vm_id}/userdata",
        userdata_vault_version=1,
        kek_vault_path=f"x/{vm.vm_id}/luks-kek",
        state=LaunchJobState.SUCCEEDED.value,
        phase_started_at=timezone.now(),
        finished_at=timezone.now(),
        decided_by=make_service_client(),
    )


def _miner_refuses_for_missing_disks(
    monkeypatch, classifier: str = service.RELAUNCH_DISKS_MISSING_CLASS, on_call=None
) -> list[dict]:
    """`launch_on_miner` answering exactly what a guarded miner-agent
    answers: a non-2xx with the `relaunch-disks-missing` class (or
    `classifier`). `on_call` runs inside the dispatch, to model something
    that happens while the relaunch is in flight."""
    from apps.orchestration.services import vault_kv as vk

    monkeypatch.setattr(vk, "get_kv", lambda mount, path, version=None: b"u")
    calls: list[dict] = []

    def fake(spec, m, **kw):
        calls.append({"miner": m.miner_id, **kw})
        if on_call is not None:
            on_call()
        return launch.LaunchOutcome(
            disposition=launch.RETRIABLE,
            emit={"classifier": classifier},
            exit_code=1,
            registered=True,
        )

    monkeypatch.setattr(launch, "launch_on_miner", fake)
    return calls


@contextlib.contextmanager
def _errors() -> Iterator[list[str]]:
    """ERROR records from the service logger. A handler on the named logger,
    not `caplog`: the project's logging config does not propagate `apps.*`
    to the root logger caplog listens on."""
    messages: list[str] = []

    class _Sink(logging.Handler):
        def emit(self, record: logging.LogRecord) -> None:
            messages.append(record.getMessage())

    logger = logging.getLogger("apps.orchestration.service")
    handler = _Sink(level=logging.ERROR)
    logger.addHandler(handler)
    try:
        yield messages
    finally:
        logger.removeHandler(handler)


def _down(monkeypatch) -> None:
    monkeypatch.setattr(service.effects, "poll_domain_running", lambda vm: False)


# ── the wire: a relaunch carries the flag, a first launch does not ────


def test_launch_payload_carries_require_existing_disks_only_for_a_relaunch() -> None:
    kw = dict(
        vm_id="vm-1",
        ovmf_path="/o",
        kernel_path="/k",
        initrd_path="/i",
        cmdline="c",
        luks_disk_path="/l",
        luks_disk_size_gb=10,
        rootfs_data_path="/r",
        rootfs_hash_path="/h",
        cpu_count=2,
        memory_mb=2048,
        cose_ticket=b"t",
    )
    assert "require_existing_disks" not in order_dispatch.build_launch_payload(**kw)
    assert (
        order_dispatch.build_launch_payload(**kw, require_existing_disks=True)[
            "require_existing_disks"
        ]
        is True
    )


def test_relaunch_asks_the_miner_to_require_existing_disks(monkeypatch) -> None:
    vm = make_vm()
    miner = _miner()
    _succeeded_launch(vm)
    calls = _miner_refuses_for_missing_disks(monkeypatch)
    with pytest.raises(service.RelaunchDisksMissing):
        service._reboot_recovery_relaunch(vm, miner.miner_id)
    assert calls == [
        {
            "miner": "node-src",
            "generation": vm.generation,
            "require_existing_disks": True,
            "supersede": False,
        }
    ]


def test_an_ordinary_rejection_is_still_just_false(monkeypatch) -> None:
    """Only the exact class escalates — a full host or a libvirt fault
    stays the retryable `False` it always was."""
    vm = make_vm()
    miner = _miner()
    _succeeded_launch(vm)
    from apps.orchestration.services import vault_kv as vk

    monkeypatch.setattr(vk, "get_kv", lambda mount, path, version=None: b"u")
    monkeypatch.setattr(
        launch,
        "launch_on_miner",
        lambda spec, m, **_kw: launch.LaunchOutcome(
            disposition=launch.RETRIABLE,
            emit={"classifier": "insufficient-resources"},
            exit_code=1,
        ),
    )
    assert service._reboot_recovery_relaunch(vm, miner.miner_id) is False


# ── the scan: refuse once, never retry, surface every tick ────────────


@override_settings(
    VALI_REBOOT_RECOVERY_ENABLED=True,
    VALI_REBOOT_RECOVERY_DEBOUNCE_POLLS=1,
    VALI_REBOOT_RECOVERY_BACKOFF_BASE_S=0,
    VALI_REBOOT_RECOVERY_MAX_ATTEMPTS=10,
)
def test_a_disks_missing_refusal_stops_reboot_recovery_for_good(monkeypatch) -> None:
    vm = make_vm()
    _miner()
    _succeeded_launch(vm)
    RebootRecovery.objects.create(vm=vm, seen_running=True, host="node-src")
    _down(monkeypatch)
    calls = _miner_refuses_for_missing_disks(monkeypatch)

    with _errors() as errors:
        assert service.reboot_recovery_once() == 0
    rec = RebootRecovery.objects.get(vm=vm)
    assert rec.last_outcome == service.DISKS_MISSING_OUTCOME
    assert len(calls) == 1
    assert any("REFUSED" in m and vm.vm_id in m for m in errors)

    # No backoff, a generous attempt budget, the domain still down: without
    # the sticky outcome every one of these ticks would relaunch again.
    for _ in range(5):
        assert service.reboot_recovery_once() == 0
    assert len(calls) == 1, "a VM whose host lacks its disks must not be relaunched again"
    assert RebootRecovery.objects.get(vm=vm).attempts == 1


@override_settings(VALI_REBOOT_RECOVERY_ENABLED=True, VALI_REBOOT_RECOVERY_DEBOUNCE_POLLS=1)
def test_the_refusal_names_the_migration_source_that_holds_the_data(monkeypatch) -> None:
    """The migrated-VM shape: a §25 job reported Done onto this host. The log
    must point the operator at the source, where the data still is."""
    vm = make_vm(host="node-dst")
    _miner("node-dst")
    _succeeded_launch(vm)
    job = make_migration_job(vm, dest_node_id="node-dst", state=MigrationState.DONE.value)
    job.source_node_id = "node-src"
    job.save(update_fields=["source_node_id"])
    RebootRecovery.objects.create(vm=vm, seen_running=True, host="node-dst")
    _down(monkeypatch)
    _miner_refuses_for_missing_disks(monkeypatch)

    with _errors() as errors:
        service.reboot_recovery_once()
    msg = " ".join(errors)
    assert job.job_id in msg
    assert "source=node-src" in msg


@override_settings(VALI_REBOOT_RECOVERY_ENABLED=True, VALI_REBOOT_RECOVERY_DEBOUNCE_POLLS=1)
def test_the_tick_surfaces_every_disks_missing_vm(monkeypatch) -> None:
    vm = make_vm()
    RebootRecovery.objects.create(
        vm=vm, seen_running=True, host="node-src", last_outcome=service.DISKS_MISSING_OUTCOME
    )
    with _errors() as errors:
        assert service.sweep_relaunch_disks_missing() == 1
    assert any(vm.vm_id in m for m in errors)
    assert service.tick_once().relaunch_disks_missing == 1


@override_settings(VALI_REBOOT_RECOVERY_ENABLED=True, VALI_REBOOT_RECOVERY_DEBOUNCE_POLLS=1)
def test_seeing_the_domain_running_again_re_arms_recovery(monkeypatch) -> None:
    """An operator put the disks back and started it: the latch lifts."""
    vm = make_vm()
    _miner()
    RebootRecovery.objects.create(
        vm=vm, seen_running=True, host="node-src", last_outcome=service.DISKS_MISSING_OUTCOME
    )
    monkeypatch.setattr(service.effects, "poll_domain_running", lambda vm: True)
    service.reboot_recovery_once()
    assert RebootRecovery.objects.get(vm=vm).last_outcome == ""


def test_a_host_change_re_arms_recovery() -> None:
    vm = make_vm()
    RebootRecovery.objects.create(
        vm=vm, seen_running=True, host="node-src", last_outcome=service.DISKS_MISSING_OUTCOME
    )
    assert service.rescope_reboot_recovery_to_host(vm, new_host="node-dst")
    assert RebootRecovery.objects.get(vm=vm).last_outcome != service.DISKS_MISSING_OUTCOME


# ── the power API's start is the same relaunch ────────────────────────


def test_power_start_refuses_leaves_the_vm_stopped_and_is_surfaced(monkeypatch) -> None:
    def refuse(vm, node_id):
        raise service.RelaunchDisksMissing("no disks")

    monkeypatch.setattr("apps.orchestration.service._reboot_recovery_relaunch", refuse)
    vm = make_vm()
    vm.power_state = VmPowerState.STOPPED
    vm.save(update_fields=["power_state"])
    with pytest.raises(power.PowerOpRefused) as exc:
        power.start_vm(vm)
    assert exc.value.reason == "disks-missing"
    vm.refresh_from_db()
    assert vm.power_state == VmPowerState.STOPPED
    # Latched like a scan refusal, so the per-tick sweep reports it.
    assert RebootRecovery.objects.get(vm=vm).last_outcome == service.DISKS_MISSING_OUTCOME
    assert service.sweep_relaunch_disks_missing() == 1


# ── §23: not evidence against the host's SEV ─────────────────────────


def test_disks_missing_is_not_a_start_capability_failure() -> None:
    assert not cvm_capability.is_start_capability_failure("relaunch-disks-missing")


# ── review follow-ups ─────────────────────────────────────────────────


@override_settings(
    VALI_REBOOT_RECOVERY_ENABLED=True,
    VALI_REBOOT_RECOVERY_DEBOUNCE_POLLS=1,
    VALI_REBOOT_RECOVERY_BACKOFF_BASE_S=0,
    VALI_REBOOT_RECOVERY_MAX_ATTEMPTS=10,
)
def test_unreadable_disks_are_retried_never_latched(monkeypatch) -> None:
    """EIO / EACCES / a late storage mount proves nothing about presence —
    latching it would abandon a healthy VM for good."""
    vm = make_vm()
    _miner()
    _succeeded_launch(vm)
    RebootRecovery.objects.create(vm=vm, seen_running=True, host="node-src")
    _down(monkeypatch)
    calls = _miner_refuses_for_missing_disks(monkeypatch, classifier="relaunch-disks-unreadable")

    assert service.reboot_recovery_once() == 0
    assert RebootRecovery.objects.get(vm=vm).last_outcome == "relaunch-failed"
    service.reboot_recovery_once()
    assert len(calls) == 2, "an unreadable disk is retried under the normal backoff"
    assert service.sweep_relaunch_disks_missing() == 0


@override_settings(VALI_REBOOT_RECOVERY_ENABLED=True, VALI_REBOOT_RECOVERY_DEBOUNCE_POLLS=1)
def test_a_refusal_never_latches_a_row_re_scoped_during_the_relaunch(monkeypatch) -> None:
    """A §25 activation moved the VM while the relaunch was in flight: the
    refusal is about the OLD host and must not flag the new one."""
    vm = make_vm()
    _miner()
    _succeeded_launch(vm)
    RebootRecovery.objects.create(vm=vm, seen_running=True, host="node-src")
    _down(monkeypatch)
    _miner_refuses_for_missing_disks(
        monkeypatch,
        on_call=lambda: service.rescope_reboot_recovery_to_host(vm, new_host="node-dst"),
    )

    service.reboot_recovery_once()
    rec = RebootRecovery.objects.get(vm=vm)
    assert rec.host == "node-dst"
    assert rec.last_outcome != service.DISKS_MISSING_OUTCOME


def test_cold_migration_source_start_fails_fast_on_disks_missing(monkeypatch) -> None:
    vm = make_vm()
    vm.power_state = VmPowerState.STOPPED
    vm.save(update_fields=["power_state"])
    job = make_migration_job(vm, state=MigrationState.SOURCE_STARTING.value)
    monkeypatch.setattr(service.idempotency, "recall", lambda key: None)
    monkeypatch.setattr(service.idempotency, "record", lambda key, value: None)

    def refuse(vm, **_kw):
        raise power.PowerOpRefused(power.DISKS_MISSING_REASON, "no disks")

    monkeypatch.setattr(power, "start_vm", refuse)
    with pytest.raises(service._StepFailed):
        service._h_mig_source_starting(job)


def test_cold_migration_source_start_still_retries_other_refusals(monkeypatch) -> None:
    vm = make_vm()
    vm.power_state = VmPowerState.STOPPED
    vm.save(update_fields=["power_state"])
    job = make_migration_job(vm, state=MigrationState.SOURCE_STARTING.value)
    monkeypatch.setattr(service.idempotency, "recall", lambda key: None)
    monkeypatch.setattr(service.idempotency, "record", lambda key, value: None)

    def refuse(vm, **_kw):
        raise power.PowerOpRefused("relaunch-rejected", "busy")

    monkeypatch.setattr(power, "start_vm", refuse)
    with pytest.raises(service.EffectError):
        service._h_mig_source_starting(job)


def test_clear_command_is_dry_run_by_default_and_clears_with_commit() -> None:
    from django.core.management import call_command

    vm = make_vm()
    RebootRecovery.objects.create(
        vm=vm, seen_running=True, host="node-src", last_outcome=service.DISKS_MISSING_OUTCOME
    )
    call_command("vali_reboot_recovery_clear_disks_missing", "--vm-id", vm.vm_id)
    assert RebootRecovery.objects.get(vm=vm).last_outcome == service.DISKS_MISSING_OUTCOME
    call_command("vali_reboot_recovery_clear_disks_missing", "--vm-id", vm.vm_id, "--commit")
    assert RebootRecovery.objects.get(vm=vm).last_outcome == ""
    # Nothing left to clear ⇒ a non-zero exit, so a script notices.
    with pytest.raises(SystemExit) as exc:
        call_command("vali_reboot_recovery_clear_disks_missing", "--vm-id", vm.vm_id)
    assert exc.value.code == 1


def test_disks_unreadable_is_not_a_start_capability_failure() -> None:
    assert not cvm_capability.is_start_capability_failure("relaunch-disks-unreadable")


@override_settings(VALI_REBOOT_RECOVERY_ENABLED=True, VALI_REBOOT_RECOVERY_DEBOUNCE_POLLS=1)
def test_a_refusal_never_latches_a_new_stint_on_the_same_host(monkeypatch) -> None:
    """Moved away and back during the relaunch: same host string, but the
    row describes a later stint the refusal knows nothing about. Only the
    version CAS tells the two apart."""
    vm = make_vm()
    _miner()
    _succeeded_launch(vm)
    RebootRecovery.objects.create(vm=vm, seen_running=True, host="node-src")
    _down(monkeypatch)

    def away_and_back() -> None:
        service.rescope_reboot_recovery_to_host(vm, new_host="node-dst")
        service.rescope_reboot_recovery_to_host(vm, new_host="node-src")

    _miner_refuses_for_missing_disks(monkeypatch, on_call=away_and_back)
    service.reboot_recovery_once()
    assert RebootRecovery.objects.get(vm=vm).last_outcome != service.DISKS_MISSING_OUTCOME


def test_power_start_refusal_re_scopes_a_stale_row_before_latching(monkeypatch) -> None:
    def refuse(vm, node_id):
        raise service.RelaunchDisksMissing("no disks")

    monkeypatch.setattr("apps.orchestration.service._reboot_recovery_relaunch", refuse)
    vm = make_vm()
    vm.power_state = VmPowerState.STOPPED
    vm.save(update_fields=["power_state"])
    RebootRecovery.objects.create(vm=vm, seen_running=True, host="node-old", attempts=4)
    with pytest.raises(power.PowerOpRefused):
        power.start_vm(vm)
    rec = RebootRecovery.objects.get(vm=vm)
    assert (rec.host, rec.attempts, rec.last_outcome) == (
        "node-src",
        0,
        service.DISKS_MISSING_OUTCOME,
    )
