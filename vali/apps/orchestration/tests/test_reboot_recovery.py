"""Reboot-recovery reconcile (`service.reboot_recovery_once`).

The scan relaunches a VM that vali records `Active` but whose bound —
still-ALIVE — miner reports the tenant domain DOWN (e.g. a host reboot
powered the CVM off). These tests pin the SAFETY gates: it acts only on a
persistent down signal from an alive miner, never on an unavailable signal,
never against a §25 (dead-miner) case, and never twice.
"""

from __future__ import annotations

from datetime import timedelta
from types import SimpleNamespace

import pytest
from django.test import override_settings
from django.utils import timezone

from apps.miners.models import MinerIdentity, MinerStatus
from apps.orchestration import service
from apps.orchestration.models import (
    LaunchJob,
    LaunchJobState,
    MigrationState,
    RebootRecovery,
)
from apps.orchestration.services import launch

from .factories import make_migration_job, make_service_client, make_vm

pytestmark = pytest.mark.django_db


def _make_alive_miner(miner_id: str = "node-src", *, fresh: bool = True) -> MinerIdentity:
    """A locally-ACTIVE, heart-beating MinerIdentity keyed by `miner_id`
    (== the default `make_vm` host)."""
    return MinerIdentity.objects.create(
        miner_id=miner_id,
        pubkey_hex=f"{abs(hash(miner_id)) % (16**16):016x}".ljust(64, "0"),
        platform_id=f"plat-{miner_id}",
        chain_node_id=f"{abs(hash(miner_id)) % (16**16):016x}".ljust(64, "1"),
        netbird_ip="100.64.0.9",
        last_seen_at=timezone.now() if fresh else timezone.now() - timedelta(hours=1),
        status=MinerStatus.ACTIVE,
    )


@pytest.fixture
def stub_relaunch(monkeypatch):
    """Replace the actual relaunch with a recorder returning ACCEPTED, so
    the gate tests exercise the scan without a full LaunchSpec."""
    calls = []

    def fake(vm, node_id):
        calls.append((vm.vm_id, node_id))
        return True

    monkeypatch.setattr(service, "_reboot_recovery_relaunch", fake)
    return calls


def _set_signal(monkeypatch, value):
    monkeypatch.setattr(service.effects, "poll_domain_running", lambda vm: value)


# ── master switch ────────────────────────────────────────────────────


@override_settings(VALI_REBOOT_RECOVERY_ENABLED=False)
def test_disabled_is_noop(monkeypatch, stub_relaunch):
    make_vm()
    _make_alive_miner()
    _set_signal(monkeypatch, False)
    assert service.reboot_recovery_once() == 0
    assert stub_relaunch == []


# ── the fail-safe signal boundary ────────────────────────────────────


@override_settings(VALI_REBOOT_RECOVERY_ENABLED=True, VALI_REBOOT_RECOVERY_DEBOUNCE_POLLS=3)
def test_signal_unavailable_never_relaunches(monkeypatch, stub_relaunch):
    """`None` (miner unreachable / libvirt unqueryable) MUST never trigger a
    relaunch — that is a §25 concern, not reboot-recovery."""
    vm = make_vm()
    _make_alive_miner()
    _set_signal(monkeypatch, None)
    for _ in range(10):
        assert service.reboot_recovery_once() == 0
    assert stub_relaunch == []
    # Debounce never advanced.
    assert RebootRecovery.objects.get(vm=vm).consecutive_down == 0


@override_settings(VALI_REBOOT_RECOVERY_ENABLED=True, VALI_REBOOT_RECOVERY_DEBOUNCE_POLLS=3)
def test_running_never_relaunches(monkeypatch, stub_relaunch):
    make_vm()
    _make_alive_miner()
    _set_signal(monkeypatch, True)
    for _ in range(5):
        assert service.reboot_recovery_once() == 0
    assert stub_relaunch == []


# ── the happy path (debounced) ───────────────────────────────────────


@override_settings(VALI_REBOOT_RECOVERY_ENABLED=True, VALI_REBOOT_RECOVERY_DEBOUNCE_POLLS=3)
def test_down_relaunches_only_past_debounce(monkeypatch, stub_relaunch):
    vm = make_vm()
    _make_alive_miner()
    # The VM was previously observed running (arms recovery for a reboot).
    RebootRecovery.objects.create(vm=vm, seen_running=True)
    _set_signal(monkeypatch, False)
    # First two down polls: debounce not yet met.
    assert service.reboot_recovery_once() == 0
    assert service.reboot_recovery_once() == 0
    assert stub_relaunch == []
    assert RebootRecovery.objects.get(vm=vm).consecutive_down == 2
    # Third down poll crosses the threshold → one relaunch.
    assert service.reboot_recovery_once() == 1
    assert stub_relaunch == [(vm.vm_id, "node-src")]
    rec = RebootRecovery.objects.get(vm=vm)
    assert rec.attempts == 1
    assert rec.last_outcome == "relaunched"
    assert rec.consecutive_down == 0  # reset on dispatch
    assert rec.next_attempt_at is not None  # backoff armed


@override_settings(VALI_REBOOT_RECOVERY_ENABLED=True, VALI_REBOOT_RECOVERY_DEBOUNCE_POLLS=3)
def test_recovering_signal_resets_debounce(monkeypatch, stub_relaunch):
    """A transient down that recovers (True) BEFORE the threshold resets the
    debounce counter — no relaunch. Exercises the nonzero→0 reset branch."""
    vm = make_vm()
    _make_alive_miner()
    holder = {"v": True}
    monkeypatch.setattr(service.effects, "poll_domain_running", lambda vm: holder["v"])
    # One healthy poll arms recovery (seen_running=True)…
    assert service.reboot_recovery_once() == 0
    assert RebootRecovery.objects.get(vm=vm).seen_running is True
    # …then two down polls build the counter toward the threshold (3)…
    holder["v"] = False
    assert service.reboot_recovery_once() == 0
    assert service.reboot_recovery_once() == 0
    assert RebootRecovery.objects.get(vm=vm).consecutive_down == 2
    # …then the domain comes back → the counter RESETS to 0 (not a relaunch).
    holder["v"] = True
    assert service.reboot_recovery_once() == 0
    assert RebootRecovery.objects.get(vm=vm).consecutive_down == 0
    assert stub_relaunch == []
    # A subsequent single down does NOT immediately fire — the counter
    # restarted from 0, so the debounce must be re-accumulated.
    holder["v"] = False
    assert service.reboot_recovery_once() == 0
    assert RebootRecovery.objects.get(vm=vm).consecutive_down == 1
    assert stub_relaunch == []


# ── §25 disjointness — dead / departing miner is NOT our job ──────────


@override_settings(VALI_REBOOT_RECOVERY_ENABLED=True, VALI_REBOOT_RECOVERY_DEBOUNCE_POLLS=1)
def test_quarantined_miner_skipped(monkeypatch, stub_relaunch):
    vm = make_vm()
    m = _make_alive_miner()
    m.status = MinerStatus.QUARANTINED
    m.save(update_fields=["status"])
    _set_signal(monkeypatch, False)
    assert service.reboot_recovery_once() == 0
    assert stub_relaunch == []
    # The alive-gate returns BEFORE probing → no debounce row churn.
    assert not RebootRecovery.objects.filter(vm=vm).exists()


@override_settings(VALI_REBOOT_RECOVERY_ENABLED=True, VALI_REBOOT_RECOVERY_DEBOUNCE_POLLS=1)
def test_stale_heartbeat_miner_skipped(monkeypatch, stub_relaunch):
    make_vm()
    _make_alive_miner(fresh=False)
    _set_signal(monkeypatch, False)
    assert service.reboot_recovery_once() == 0
    assert stub_relaunch == []


@override_settings(VALI_REBOOT_RECOVERY_ENABLED=True, VALI_REBOOT_RECOVERY_DEBOUNCE_POLLS=1)
def test_unknown_miner_skipped(monkeypatch, stub_relaunch):
    make_vm()  # no MinerIdentity for host="node-src"
    _set_signal(monkeypatch, False)
    assert service.reboot_recovery_once() == 0
    assert stub_relaunch == []


# ── no competing lifecycle job ───────────────────────────────────────


@override_settings(VALI_REBOOT_RECOVERY_ENABLED=True, VALI_REBOOT_RECOVERY_DEBOUNCE_POLLS=1)
def test_in_flight_migration_skipped(monkeypatch, stub_relaunch):
    vm = make_vm()
    _make_alive_miner()
    make_migration_job(vm, state=MigrationState.SNAPSHOTTING)
    _set_signal(monkeypatch, False)
    assert service.reboot_recovery_once() == 0
    assert stub_relaunch == []


@override_settings(VALI_REBOOT_RECOVERY_ENABLED=True, VALI_REBOOT_RECOVERY_DEBOUNCE_POLLS=1)
def test_in_flight_launch_skipped(monkeypatch, stub_relaunch):
    vm = make_vm()
    _make_alive_miner()
    LaunchJob.objects.create(
        job_id="jobinflight",
        vm_id=vm.vm_id,
        tenant_id="t",
        flavor="small",
        spec_json={},
        userdata_vault_path="p",
        userdata_vault_version=1,
        kek_vault_path="k",
        state=LaunchJobState.RUNNING.value,
        phase_started_at=timezone.now(),
        decided_by=make_service_client(),
    )
    _set_signal(monkeypatch, False)
    assert service.reboot_recovery_once() == 0
    assert stub_relaunch == []


# ── attempt cap + backoff ────────────────────────────────────────────


@override_settings(
    VALI_REBOOT_RECOVERY_ENABLED=True,
    VALI_REBOOT_RECOVERY_DEBOUNCE_POLLS=1,
    VALI_REBOOT_RECOVERY_MAX_ATTEMPTS=2,
)
def test_attempt_cap_gives_up(monkeypatch, stub_relaunch):
    vm = make_vm()
    _make_alive_miner()
    RebootRecovery.objects.create(
        vm=vm, seen_running=True, attempts=2, consecutive_down=5
    )
    _set_signal(monkeypatch, False)
    assert service.reboot_recovery_once() == 0
    assert stub_relaunch == []
    assert RebootRecovery.objects.get(vm=vm).last_outcome == "attempts-exhausted"


@override_settings(VALI_REBOOT_RECOVERY_ENABLED=True, VALI_REBOOT_RECOVERY_DEBOUNCE_POLLS=1)
def test_backoff_window_gates_retry(monkeypatch, stub_relaunch):
    vm = make_vm()
    _make_alive_miner()
    RebootRecovery.objects.create(
        vm=vm,
        seen_running=True,
        attempts=1,
        consecutive_down=5,
        next_attempt_at=timezone.now() + timedelta(minutes=10),
    )
    _set_signal(monkeypatch, False)
    assert service.reboot_recovery_once() == 0
    assert stub_relaunch == []


# ── seen-running gate — never resurrect a never-seen-up (zombie) VM ───


@override_settings(VALI_REBOOT_RECOVERY_ENABLED=True, VALI_REBOOT_RECOVERY_DEBOUNCE_POLLS=2)
def test_never_seen_running_not_recovered(monkeypatch, stub_relaunch):
    """A VM that is DOWN on every poll — never observed running — is a
    stale/zombie Active row, NOT a reboot to recover. It must never be
    relaunched, however long it stays down."""
    vm = make_vm()
    _make_alive_miner()
    _set_signal(monkeypatch, False)
    for _ in range(10):
        assert service.reboot_recovery_once() == 0
    assert stub_relaunch == []
    rec = RebootRecovery.objects.get(vm=vm)
    assert rec.seen_running is False
    assert rec.consecutive_down == 0  # never accumulates without seen_running


@override_settings(VALI_REBOOT_RECOVERY_ENABLED=True, VALI_REBOOT_RECOVERY_DEBOUNCE_POLLS=2)
def test_seen_running_then_down_recovers(monkeypatch, stub_relaunch):
    """The real use case: a VM observed running, then a host reboot powers it
    off → recovered after debounce."""
    vm = make_vm()
    _make_alive_miner()
    holder = {"v": True}
    monkeypatch.setattr(service.effects, "poll_domain_running", lambda vm: holder["v"])
    # Observed running → armed.
    assert service.reboot_recovery_once() == 0
    assert RebootRecovery.objects.get(vm=vm).seen_running is True
    # Host reboot → down for the debounce window → recovered.
    holder["v"] = False
    assert service.reboot_recovery_once() == 0
    assert service.reboot_recovery_once() == 1
    assert stub_relaunch == [(vm.vm_id, "node-src")]


# ── host scoping — the counters describe ONE host ─────────────────────


@override_settings(VALI_REBOOT_RECOVERY_ENABLED=True, VALI_REBOOT_RECOVERY_DEBOUNCE_POLLS=1)
def test_a_fresh_row_is_stamped_with_the_bound_host(monkeypatch, stub_relaunch):
    """Every field on the row is host-scoped, so the row records WHICH
    host — otherwise it cannot tell "burned its budget here" from "burned
    it somewhere it no longer runs"."""
    vm = make_vm()
    _make_alive_miner()
    _set_signal(monkeypatch, True)
    assert service.reboot_recovery_once() == 0
    assert RebootRecovery.objects.get(vm=vm).host == "node-src"


@override_settings(
    VALI_REBOOT_RECOVERY_ENABLED=True,
    VALI_REBOOT_RECOVERY_DEBOUNCE_POLLS=1,
    VALI_REBOOT_RECOVERY_MAX_ATTEMPTS=2,
    VALI_REBOOT_RECOVERY_BACKOFF_BASE_S=0.0,
)
def test_the_same_host_relaunch_never_resets_the_cap(monkeypatch, stub_relaunch):
    """Reboot-recovery's OWN relaunch re-runs `launch_on_miner` on the
    SAME host. That must not read as a host change: re-scoping there would
    zero `attempts` between every attempt and the cap — the thing that
    bounds the blast radius of a false positive — would never be reached."""
    vm = make_vm()
    _make_alive_miner()
    RebootRecovery.objects.create(vm=vm, host="node-src", seen_running=True)
    _set_signal(monkeypatch, False)

    assert service.reboot_recovery_once() == 1
    assert RebootRecovery.objects.get(vm=vm).attempts == 1
    assert service.reboot_recovery_once() == 1
    rec = RebootRecovery.objects.get(vm=vm)
    assert rec.attempts == 2
    assert rec.host == "node-src"
    # Budget spent — and it STAYS spent on this host.
    assert service.reboot_recovery_once() == 0
    rec = RebootRecovery.objects.get(vm=vm)
    assert rec.attempts == 2
    assert rec.last_outcome == "attempts-exhausted"
    assert len(stub_relaunch) == 2


@override_settings(VALI_REBOOT_RECOVERY_ENABLED=True, VALI_REBOOT_RECOVERY_DEBOUNCE_POLLS=1)
def test_the_scan_re_scopes_a_row_whose_host_changed(monkeypatch, stub_relaunch):
    """The LAZY backstop. The two writers of `Vm.host` re-scope eagerly
    inside their own CAS; this makes the invariant a property of the DATA,
    so a future third writer gets correct counters even if it never learns
    this row exists."""
    vm = make_vm(host="node-dst")
    _make_alive_miner("node-dst")
    RebootRecovery.objects.create(
        vm=vm,
        host="node-src",  # stale: the VM moved and nobody told the row
        seen_running=True,
        attempts=9,
        consecutive_down=4,
        last_relaunch_at=timezone.now(),
        next_attempt_at=timezone.now() + timedelta(hours=1),
        last_outcome="attempts-exhausted",
    )
    _set_signal(monkeypatch, False)

    assert service.reboot_recovery_once() == 1
    rec = RebootRecovery.objects.get(vm=vm)
    assert rec.host == "node-dst"
    assert rec.attempts == 1  # re-scoped to 0, then this dispatch
    assert rec.seen_running is True  # a fact about the past, preserved
    assert stub_relaunch == [(vm.vm_id, "node-dst")]


@override_settings(
    VALI_REBOOT_RECOVERY_ENABLED=True,
    VALI_REBOOT_RECOVERY_DEBOUNCE_POLLS=1,
    VALI_REBOOT_RECOVERY_MAX_ATTEMPTS=2,
)
def test_an_unstamped_row_is_adopted_without_resetting_the_cap(
    monkeypatch, stub_relaunch
):
    """A row written before the stamp existed (and left unstamped by the
    0012 backfill wherever the evidence was ambiguous) cannot say whether
    its counters describe this host. Under that uncertainty the fail-safe
    direction for an attempt CAP is to KEEP it — so: adopt the host,
    re-scope nothing."""
    vm = make_vm()
    _make_alive_miner()
    RebootRecovery.objects.create(
        vm=vm, host="", seen_running=True, attempts=2, consecutive_down=4
    )
    _set_signal(monkeypatch, False)

    assert service.reboot_recovery_once() == 0
    rec = RebootRecovery.objects.get(vm=vm)
    assert rec.host == "node-src"
    assert rec.attempts == 2
    assert rec.last_outcome == "attempts-exhausted"
    assert stub_relaunch == []


# ── _reboot_recovery_relaunch (spec rebuild + pinned dispatch) ────────


_FULL_SPEC = {
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


@override_settings(VALI_REBOOT_RECOVERY_ENABLED=True)
def test_relaunch_pins_same_miner_and_reuses_kek(monkeypatch):
    vm = make_vm()
    miner = _make_alive_miner()
    LaunchJob.objects.create(
        job_id="succ1",
        vm_id=vm.vm_id,
        tenant_id="tenant-1",
        flavor="small",
        spec_json=dict(_FULL_SPEC),
        userdata_vault_path=f"x/{vm.vm_id}/userdata",
        userdata_vault_version=1,
        kek_vault_path=f"x/{vm.vm_id}/luks-kek",
        state=LaunchJobState.SUCCEEDED.value,
        phase_started_at=timezone.now(),
        finished_at=timezone.now(),
        decided_by=make_service_client(),
    )

    monkeypatch.setattr(
        service.effects, "poll_domain_running", lambda vm: False
    )
    # userdata from Vault (mocked) — the relaunch reads it back.
    from apps.orchestration.services import vault_kv as vk

    monkeypatch.setattr(vk, "get_kv", lambda mount, path, version=None: b"user-data")

    seen = {}

    def fake_launch_on_miner(spec, m):
        seen["vm_id"] = spec.vm_id
        seen["kek_bytes"] = spec.kek_bytes
        seen["miner_id"] = m.miner_id
        return SimpleNamespace(disposition=launch.ACCEPTED)

    monkeypatch.setattr(launch, "launch_on_miner", fake_launch_on_miner)

    ok = service._reboot_recovery_relaunch(vm, miner.miner_id)
    assert ok is True
    # Pinned to the SAME miner, same vm, and NO plaintext KEK (kek_bytes=None
    # → launch_on_miner reads the already-staged datakey version → SAME KEK).
    assert seen == {"vm_id": vm.vm_id, "kek_bytes": None, "miner_id": "node-src"}


@override_settings(VALI_REBOOT_RECOVERY_ENABLED=True)
def test_relaunch_without_succeeded_job_fails_closed(monkeypatch):
    vm = make_vm()
    miner = _make_alive_miner()
    # No SUCCEEDED LaunchJob → cannot rebuild a spec → returns False.
    assert service._reboot_recovery_relaunch(vm, miner.miner_id) is False


@override_settings(VALI_REBOOT_RECOVERY_ENABLED=True)
def test_relaunch_retriable_disposition_is_not_accepted(monkeypatch):
    vm = make_vm()
    miner = _make_alive_miner()
    LaunchJob.objects.create(
        job_id="succ2",
        vm_id=vm.vm_id,
        tenant_id="tenant-1",
        flavor="small",
        spec_json=dict(_FULL_SPEC),
        userdata_vault_path=f"x/{vm.vm_id}/userdata",
        userdata_vault_version=1,
        kek_vault_path=f"x/{vm.vm_id}/luks-kek",
        state=LaunchJobState.SUCCEEDED.value,
        phase_started_at=timezone.now(),
        finished_at=timezone.now(),
        decided_by=make_service_client(),
    )
    from apps.orchestration.services import vault_kv as vk

    monkeypatch.setattr(vk, "get_kv", lambda mount, path, version=None: b"u")
    monkeypatch.setattr(
        launch,
        "launch_on_miner",
        lambda spec, m: SimpleNamespace(disposition=launch.RETRIABLE),
    )
    assert service._reboot_recovery_relaunch(vm, miner.miner_id) is False
