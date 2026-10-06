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

from apps.lifecycle.models import Vm, VmPowerState
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

    def fake_launch_on_miner(spec, m, **_kw):
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
def test_relaunch_unwraps_the_userdata_working_copy(monkeypatch):
    """The working copy is Transit ciphertext at rest now, so recovery has
    to UNWRAP it before rebuilding the spec — `launch_on_miner` needs the
    cloud-init plaintext (it substitutes a NetBird key into it and digests
    it). Hand it the ciphertext and the relaunch stages a `vault:v1:…`
    string as the tenant's cloud-config."""
    vm = make_vm()
    miner = _make_alive_miner()
    LaunchJob.objects.create(
        job_id="succ-wrapped",
        vm_id=vm.vm_id,
        tenant_id="tenant-1",
        flavor="small",
        spec_json=dict(_FULL_SPEC),
        userdata_vault_path=f"x/{vm.vm_id}/userdata-pending",
        userdata_vault_version=2,
        kek_vault_path=f"x/{vm.vm_id}/luks-kek",
        state=LaunchJobState.SUCCEEDED.value,
        phase_started_at=timezone.now(),
        finished_at=timezone.now(),
        decided_by=make_service_client(),
    )
    monkeypatch.setattr(service.effects, "poll_domain_running", lambda vm: False)
    from apps.orchestration.services import vault_kv as vk

    read: dict = {}

    def fake_get_kv(mount, path, version=None):
        read["path"], read["version"] = path, version
        return b"vault:v1:" + b"#cloud-config\nrecovered".hex().encode()

    monkeypatch.setattr(vk, "get_kv", fake_get_kv)
    monkeypatch.setattr(
        vk,
        "transit_decrypt",
        lambda name, ct: bytes.fromhex(ct.removeprefix(b"vault:v1:").decode()),
    )

    seen: dict = {}

    def fake_launch_on_miner(spec, m, **_kw):
        seen["userdata"] = spec.userdata
        return SimpleNamespace(disposition=launch.ACCEPTED)

    monkeypatch.setattr(launch, "launch_on_miner", fake_launch_on_miner)

    assert service._reboot_recovery_relaunch(vm, miner.miner_id) is True
    assert seen["userdata"] == b"#cloud-config\nrecovered"
    # …read at the PINNED version the row recorded, never "latest".
    assert read == {"path": f"x/{vm.vm_id}/userdata-pending", "version": 2}


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
        lambda spec, m, **_kw: SimpleNamespace(disposition=launch.RETRIABLE),
    )
    assert service._reboot_recovery_relaunch(vm, miner.miner_id) is False


@override_settings(VALI_REBOOT_RECOVERY_ENABLED=True)
def test_relaunch_rebuilds_a_spec_written_before_region_existed(monkeypatch):
    """Every LaunchJob on the fleet pre-dates `LaunchSpec.region`. Recovery
    rebuilds the spec with `LaunchSpec(**spec_json, …)`, so a required
    field there would turn every host reboot into an unrecoverable VM. The
    old spec must build, unconstrained."""
    assert "region" not in _FULL_SPEC
    vm = make_vm()
    miner = _make_alive_miner()
    LaunchJob.objects.create(
        job_id="succ-old",
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

    monkeypatch.setattr(vk, "get_kv", lambda mount, path, version=None: b"user-data")
    seen = {}

    def fake_launch_on_miner(spec, m, **_kw):
        seen["region"] = spec.region
        return SimpleNamespace(disposition=launch.ACCEPTED)

    monkeypatch.setattr(launch, "launch_on_miner", fake_launch_on_miner)
    assert service._reboot_recovery_relaunch(vm, miner.miner_id) is True
    assert seen == {"region": ""}


@override_settings(VALI_REBOOT_RECOVERY_ENABLED=True)
def test_a_moved_vm_relaunches_at_its_generation_on_the_miner_it_is_on(monkeypatch):
    """A VM §25 moved: its KEK is releasable only at its CURRENT generation
    and only to the host it is on now — never the miner its recorded launch
    pinned."""
    vm = make_vm(generation=3, host="node-dst", signing_generation=1)
    miner = _make_alive_miner("node-dst")
    LaunchJob.objects.create(
        job_id="succ-moved",
        vm_id=vm.vm_id,
        tenant_id="tenant-1",
        flavor="small",
        spec_json={**_FULL_SPEC, "platform_id": "plat-node-src"},
        userdata_vault_path=f"x/{vm.vm_id}/userdata",
        userdata_vault_version=1,
        kek_vault_path=f"x/{vm.vm_id}/luks-kek",
        state=LaunchJobState.SUCCEEDED.value,
        phase_started_at=timezone.now(),
        finished_at=timezone.now(),
        decided_by=make_service_client(),
    )
    from apps.orchestration.services import vault_kv as vk

    monkeypatch.setattr(vk, "get_kv", lambda mount, path, version=None: b"user-data")
    seen = {}

    def fake_launch_on_miner(spec, m, **kw):
        seen.update(platform_id=spec.platform_id, miner=m.miner_id, **kw)
        return SimpleNamespace(disposition=launch.ACCEPTED)

    monkeypatch.setattr(launch, "launch_on_miner", fake_launch_on_miner)
    assert service._reboot_recovery_relaunch(vm, miner.miner_id) is True
    assert seen == {
        "platform_id": "plat-node-dst",
        "miner": "node-dst",
        "generation": 3,
        # A relaunch must never let the miner blank-create the VM's disks.
        "require_existing_disks": True,
        # Not a resize: it becomes the VM's current launch at its first
        # release, never at register.
        "supersede": False,
    }


@override_settings(VALI_REBOOT_RECOVERY_ENABLED=True)
@pytest.mark.parametrize("platform_id", ["", "onchain", "onchain:" + "ab" * 32])
def test_a_miner_without_a_real_chip_is_never_relaunched_on(monkeypatch, platform_id):
    vm = make_vm(generation=3, host="node-dst")
    miner = _make_alive_miner("node-dst")
    MinerIdentity.objects.filter(pk=miner.pk).update(platform_id=platform_id)
    LaunchJob.objects.create(
        job_id="succ-nochip",
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

    monkeypatch.setattr(vk, "get_kv", lambda mount, path, version=None: b"user-data")
    launched: list[str] = []

    def fake_launch_on_miner(spec, m, **_kw):
        launched.append(m.miner_id)
        return SimpleNamespace(disposition=launch.ACCEPTED)

    monkeypatch.setattr(launch, "launch_on_miner", fake_launch_on_miner)
    assert service._reboot_recovery_relaunch(vm, miner.miner_id) is False
    assert launched == []


# ── power intent: a VM stopped through the power API stays stopped ───


@pytest.mark.parametrize(
    "power_state",
    [VmPowerState.STOPPED, VmPowerState.STOPPING, VmPowerState.STARTING],
)
@override_settings(VALI_REBOOT_RECOVERY_ENABLED=True, VALI_REBOOT_RECOVERY_DEBOUNCE_POLLS=3)
def test_a_vm_the_tenant_did_not_leave_running_is_never_relaunched(
    monkeypatch, stub_relaunch, power_state
):
    """A stopped VM stays `Active` (it must unlock again on start), and its
    domain is down on an alive miner — exactly the reboot signature. Live
    2026-09-25: the scan relaunched an API-stopped VM ~30 s after the stop,
    racing the tenant's own `start` (two relaunches, two EOL nonces, every
    later §24 ack rejected `stopped-body-mismatch`)."""
    vm = make_vm()
    Vm.objects.filter(pk=vm.pk).update(power_state=power_state)
    _make_alive_miner()
    RebootRecovery.objects.create(vm=vm, seen_running=True, consecutive_down=2)
    _set_signal(monkeypatch, False)
    for _ in range(6):
        assert service.reboot_recovery_once() == 0
    assert stub_relaunch == []
    rec = RebootRecovery.objects.get(vm=vm)
    assert rec.consecutive_down == 0, "a stop must not leave a half-armed debounce"
    assert rec.attempts == 0


@override_settings(VALI_REBOOT_RECOVERY_ENABLED=True, VALI_REBOOT_RECOVERY_DEBOUNCE_POLLS=3)
def test_a_stop_landing_between_the_scan_and_the_dispatch_wins(
    monkeypatch, stub_relaunch
):
    """The scan read the VM `running`; the tenant's stop lands before the
    relaunch is dispatched. The fire re-reads the power intent and backs off."""
    vm = make_vm()
    _make_alive_miner()
    RebootRecovery.objects.create(vm=vm, seen_running=True, consecutive_down=2)

    def _down_then_stopped(v):
        # The probe is the last read before the fire: the stop lands here.
        Vm.objects.filter(pk=v.pk).update(power_state=VmPowerState.STOPPED)
        return False

    monkeypatch.setattr(service.effects, "poll_domain_running", _down_then_stopped)
    assert service.reboot_recovery_once() == 0
    assert stub_relaunch == []
    assert RebootRecovery.objects.get(vm=vm).attempts == 0, (
        "an abort must not spend one of the VM's lifetime relaunches"
    )


@override_settings(VALI_REBOOT_RECOVERY_ENABLED=True, VALI_REBOOT_RECOVERY_DEBOUNCE_POLLS=3)
def test_a_started_vm_is_recovered_again(monkeypatch, stub_relaunch):
    """The gate is the power INTENT, not a one-way latch: once the tenant
    starts the VM again, a real outage is recovered as before."""
    vm = make_vm()
    Vm.objects.filter(pk=vm.pk).update(power_state=VmPowerState.STOPPED)
    _make_alive_miner()
    RebootRecovery.objects.create(vm=vm, seen_running=True)
    _set_signal(monkeypatch, False)
    assert service.reboot_recovery_once() == 0
    Vm.objects.filter(pk=vm.pk).update(power_state=VmPowerState.RUNNING)
    for _ in range(2):
        assert service.reboot_recovery_once() == 0
    assert service.reboot_recovery_once() == 1
    assert stub_relaunch == [(vm.vm_id, "node-src")]


# ── an abandoned power marker is settled to what the miner runs ─────


def _marker_since(vm, marker, minutes: int) -> None:
    Vm.objects.filter(pk=vm.pk).update(
        power_state=marker, power_state_at=timezone.now() - timedelta(minutes=minutes)
    )


@override_settings(VALI_REBOOT_RECOVERY_ENABLED=True)
@pytest.mark.parametrize(
    ("marker", "signal", "truth"),
    [
        (VmPowerState.STARTING, True, VmPowerState.RUNNING),  # the start landed
        (VmPowerState.STARTING, False, VmPowerState.STOPPED),  # it never did
        (VmPowerState.STOPPING, True, VmPowerState.RUNNING),  # the stop never landed
        (VmPowerState.STOPPING, False, VmPowerState.STOPPED),  # it did
    ],
)
def test_an_abandoned_marker_is_settled_to_what_the_miner_runs(
    monkeypatch, stub_relaunch, marker, signal, truth
):
    """A request that died past dispatch leaves the marker; after 10 min the
    tenant may override it, and a `start` over a domain that actually runs
    would relaunch on top of it. Settle to the truth first."""
    vm = make_vm()
    _marker_since(vm, marker, 11)
    Vm.objects.filter(pk=vm.pk).update(power_stop_proof=b"p" * 32)
    _make_alive_miner()
    _set_signal(monkeypatch, signal)
    before = timezone.now()
    assert service.reboot_recovery_once() == 0
    vm.refresh_from_db()
    assert vm.power_state == truth
    assert vm.power_state_at >= before
    # A power-stop proof survives only a settle to `stopped` (#1162).
    assert (vm.power_stop_proof is not None) == (truth == VmPowerState.STOPPED)
    assert stub_relaunch == []


@override_settings(VALI_REBOOT_RECOVERY_ENABLED=True)
def test_an_unknown_reading_leaves_the_marker(monkeypatch, stub_relaunch):
    vm = make_vm()
    _marker_since(vm, VmPowerState.STARTING, 11)
    _make_alive_miner()
    _set_signal(monkeypatch, None)
    service.reboot_recovery_once()
    vm.refresh_from_db()
    assert vm.power_state == VmPowerState.STARTING


@override_settings(VALI_REBOOT_RECOVERY_ENABLED=True)
@pytest.mark.parametrize("fresh_miner", [False, None])
def test_a_dead_or_unknown_miner_is_not_probed(monkeypatch, stub_relaunch, fresh_miner):
    vm = make_vm()
    _marker_since(vm, VmPowerState.STARTING, 11)
    if fresh_miner is not None:
        _make_alive_miner(fresh=fresh_miner)
    probed: list[str] = []
    monkeypatch.setattr(
        service.effects, "poll_domain_running", lambda v: probed.append(v.vm_id) or True
    )
    service.reboot_recovery_once()
    assert probed == [], "a dead miner only costs a relay timeout per tick"
    vm.refresh_from_db()
    assert vm.power_state == VmPowerState.STARTING


@override_settings(VALI_REBOOT_RECOVERY_ENABLED=True)
@pytest.mark.parametrize("minutes", [1, None])
def test_a_live_or_untimed_marker_is_not_touched(monkeypatch, stub_relaunch, minutes):
    vm = make_vm()
    if minutes is None:
        Vm.objects.filter(pk=vm.pk).update(power_state=VmPowerState.STARTING)
    else:
        _marker_since(vm, VmPowerState.STARTING, minutes)
    _make_alive_miner()
    probed: list[str] = []
    monkeypatch.setattr(
        service.effects, "poll_domain_running", lambda v: probed.append(v.vm_id) or True
    )
    service.reboot_recovery_once()
    vm.refresh_from_db()
    assert vm.power_state == VmPowerState.STARTING
    assert probed == [], "a live start's marker is its request's to settle"


@override_settings(VALI_REBOOT_RECOVERY_ENABLED=True)
def test_a_tenant_action_during_the_settle_wins(monkeypatch, stub_relaunch):
    vm = make_vm()
    _marker_since(vm, VmPowerState.STARTING, 11)
    _make_alive_miner()

    def _running_but_tenant_stops(v):
        Vm.objects.filter(pk=v.pk).update(
            power_state=VmPowerState.STOPPING, power_state_at=timezone.now()
        )
        return True

    monkeypatch.setattr(service.effects, "poll_domain_running", _running_but_tenant_stops)
    service.reboot_recovery_once()
    vm.refresh_from_db()
    assert vm.power_state == VmPowerState.STOPPING


@override_settings(VALI_REBOOT_RECOVERY_ENABLED=True, VALI_REBOOT_RECOVERY_DEBOUNCE_POLLS=3)
def test_a_settled_vm_is_recovered_normally_afterwards(monkeypatch, stub_relaunch):
    """Settled to running, the VM is an ordinary running VM again: a later
    outage goes through the normal debounced recovery."""
    vm = make_vm()
    _marker_since(vm, VmPowerState.STARTING, 11)
    _make_alive_miner()
    holder = {"v": True}
    monkeypatch.setattr(service.effects, "poll_domain_running", lambda v: holder["v"])
    service.reboot_recovery_once()  # settle → running
    service.reboot_recovery_once()  # healthy poll arms seen_running
    holder["v"] = False
    for _ in range(2):
        assert service.reboot_recovery_once() == 0
    assert service.reboot_recovery_once() == 1
    assert stub_relaunch == [(vm.vm_id, "node-src")]


# ── a stop cannot land inside a recovery relaunch ────────────────────


@override_settings(VALI_REBOOT_RECOVERY_ENABLED=True, VALI_REBOOT_RECOVERY_DEBOUNCE_POLLS=3)
def test_the_relaunch_is_marked_in_flight_during_dispatch_and_cleared_after(monkeypatch):
    vm = make_vm()
    _make_alive_miner()
    RebootRecovery.objects.create(vm=vm, seen_running=True, consecutive_down=2)
    _set_signal(monkeypatch, False)
    during: list[str] = []

    def _relaunch(v, node_id):
        during.append(RebootRecovery.objects.get(vm=v).last_outcome)
        return True

    monkeypatch.setattr(service, "_reboot_recovery_relaunch", _relaunch)
    assert service.reboot_recovery_once() == 1
    assert during == [service.RELAUNCH_IN_FLIGHT]
    assert RebootRecovery.objects.get(vm=vm).last_outcome == "relaunched"


@override_settings(VALI_REBOOT_RECOVERY_ENABLED=True, VALI_REBOOT_RECOVERY_DEBOUNCE_POLLS=3)
def test_a_relaunch_that_raises_clears_the_in_flight_mark(monkeypatch):
    vm = make_vm()
    _make_alive_miner()
    RebootRecovery.objects.create(vm=vm, seen_running=True, consecutive_down=2)
    _set_signal(monkeypatch, False)

    def _boom(v, node_id):
        raise RuntimeError("launch_on_miner exploded")

    monkeypatch.setattr(service, "_reboot_recovery_relaunch", _boom)
    service.reboot_recovery_once()  # per-VM errors are isolated by the scan
    assert RebootRecovery.objects.get(vm=vm).last_outcome == "relaunch-failed"


class TestStopDuringARecoveryRelaunch:
    """A stop that reached the miner before the relaunched domain existed
    answered `not-running`; vali recorded `stopped`, and the relaunch booted
    the guest anyway — a running VM that reads stopped (#1151)."""

    @staticmethod
    def _marked(vm, outcome, minutes_ago: float):
        RebootRecovery.objects.update_or_create(
            vm=vm,
            defaults={
                "last_outcome": outcome,
                "last_relaunch_at": timezone.now() - timedelta(minutes=minutes_ago),
            },
        )

    def test_a_stop_is_refused_while_a_relaunch_is_in_flight(self, monkeypatch):
        from apps.orchestration.services import power

        vm = make_vm()
        self._marked(vm, service.RELAUNCH_IN_FLIGHT, 0.1)
        sent: list[str] = []
        monkeypatch.setattr(
            "apps.orchestration.effects.dispatch_graceful_stop",
            lambda v, **_kw: sent.append(v.vm_id),
        )
        with pytest.raises(power.PowerOpRefused) as exc:
            power.stop_vm(vm)
        assert exc.value.reason == "recovery-relaunch-in-flight"
        assert sent == []
        vm.refresh_from_db()
        assert vm.power_state == VmPowerState.RUNNING

    @pytest.mark.parametrize(
        ("outcome", "minutes_ago"),
        [("relaunched", 0.1), ("relaunch-failed", 0.1), ("relaunching", 11)],
    )
    def test_a_finished_or_abandoned_relaunch_does_not_block_a_stop(
        self, monkeypatch, outcome, minutes_ago
    ):
        from apps.orchestration.services import power

        vm = make_vm()
        self._marked(vm, outcome, minutes_ago)
        monkeypatch.setattr(
            "apps.orchestration.effects.dispatch_graceful_stop", lambda v, **_kw: "stopped"
        )
        assert power.stop_vm(vm).power_state == VmPowerState.STOPPED


@override_settings(VALI_REBOOT_RECOVERY_ENABLED=True, VALI_REBOOT_RECOVERY_DEBOUNCE_POLLS=3)
def test_the_in_flight_mark_is_stamped_at_claim_time_not_tick_start(monkeypatch):
    """One tick relaunches VM after VM after a host reboot; a tick-start stamp
    would make a later VM's fresh in-flight mark look abandoned."""
    vm = make_vm()
    _make_alive_miner()
    RebootRecovery.objects.create(vm=vm, seen_running=True, consecutive_down=2)
    _set_signal(monkeypatch, False)
    monkeypatch.setattr(service, "_reboot_recovery_relaunch", lambda v, n: True)
    tick_start = timezone.now() - timedelta(minutes=30)  # a long, slow tick
    rec = service._reboot_recovery_row(vm, "node-src")
    rec.consecutive_down = 3
    service._reboot_recovery_fire(vm, rec, "node-src", now=tick_start, reason="DOWN", polls=3)
    stamped = RebootRecovery.objects.get(vm=vm).last_relaunch_at
    assert timezone.now() - stamped < timedelta(minutes=1)


@override_settings(VALI_REBOOT_RECOVERY_ENABLED=True)
def test_an_abandoned_marker_on_a_departing_but_alive_miner_is_settled(
    monkeypatch, stub_relaunch
):
    """A quarantined (departing) miner still heart-beats and can answer the
    probe; its VMs are the ones §25 refuses while a marker stands (#1150),
    so the settle must not wait for the miner to be Active again."""
    vm = make_vm()
    _marker_since(vm, VmPowerState.STARTING, 11)
    m = _make_alive_miner()
    MinerIdentity.objects.filter(pk=m.pk).update(status=MinerStatus.QUARANTINED)
    _set_signal(monkeypatch, True)
    service.reboot_recovery_once()
    vm.refresh_from_db()
    assert vm.power_state == VmPowerState.RUNNING
    assert stub_relaunch == [], "relaunching on a departing miner stays §25's job"



# ── the attempt budget is per incident ───────────────────────────────


def _rec_after_relaunch(vm, *, attempts: int, ago_s: float, outcome: str = "relaunched"):
    return RebootRecovery.objects.create(
        vm=vm,
        host="node-src",
        seen_running=True,
        attempts=attempts,
        last_outcome=outcome,
        last_relaunch_at=timezone.now() - timedelta(seconds=ago_s),
    )


def _signal(vm, *, ago_s: float) -> None:
    Vm.objects.filter(pk=vm.pk).update(
        guest_signal_at=timezone.now() - timedelta(seconds=ago_s),
        guest_signal_kind="served_receipt",
    )


@override_settings(VALI_REBOOT_RECOVERY_ENABLED=True)
def test_a_vm_healthy_after_its_relaunch_gets_its_budget_back(monkeypatch, stub_relaunch):
    """Live (miner-c): two VMs sat at attempts=4/5 weeks after the reboot
    that spent them, so ONE failed relaunch after the next host reboot
    would have stranded them for good."""
    vm = make_vm()
    _make_alive_miner()
    _rec_after_relaunch(vm, attempts=4, ago_s=2 * 3600)
    _signal(vm, ago_s=30)
    _set_signal(monkeypatch, True)

    assert service.reboot_recovery_once() == 0
    assert RebootRecovery.objects.get(vm=vm).attempts == 0


@override_settings(VALI_REBOOT_RECOVERY_ENABLED=True)
def test_an_exhausted_vm_that_came_back_is_recoverable_again(monkeypatch, stub_relaunch):
    vm = make_vm()
    _make_alive_miner()
    _rec_after_relaunch(vm, attempts=5, ago_s=2 * 3600, outcome="attempts-exhausted")
    _signal(vm, ago_s=30)
    _set_signal(monkeypatch, True)

    service.reboot_recovery_once()
    rec = RebootRecovery.objects.get(vm=vm)
    assert rec.attempts == 0
    assert rec.last_outcome == ""


@override_settings(VALI_REBOOT_RECOVERY_ENABLED=True, VALI_REBOOT_RECOVERY_DEBOUNCE_POLLS=1)
def test_a_vm_that_dies_right_after_booting_still_hits_the_cap(monkeypatch, stub_relaunch):
    """Boots, sends one receipt, goes down — every cycle. One post-relaunch
    signal must not end the incident, or this relaunches forever."""
    vm = make_vm()
    _make_alive_miner()
    RebootRecovery.objects.create(vm=vm, host="node-src", seen_running=True)
    holder = {"v": False}
    monkeypatch.setattr(service.effects, "poll_domain_running", lambda vm: holder["v"])
    for _ in range(8):
        RebootRecovery.objects.filter(vm=vm).update(next_attempt_at=None)
        holder["v"] = False
        service.reboot_recovery_once()  # down → relaunch (while budget lasts)
        holder["v"] = True
        _signal(vm, ago_s=0)  # the relaunched guest checks in once...
        service.reboot_recovery_once()  # ...seen up and alive
    rec = RebootRecovery.objects.get(vm=vm)
    assert len(stub_relaunch) == service._reboot_recovery_max_attempts()
    assert rec.attempts == service._reboot_recovery_max_attempts()


@override_settings(VALI_REBOOT_RECOVERY_ENABLED=True)
def test_a_claim_since_the_read_is_never_refunded(monkeypatch, stub_relaunch):
    vm = make_vm()
    _make_alive_miner()
    rec = _rec_after_relaunch(vm, attempts=3, ago_s=3600)
    _signal(vm, ago_s=30)
    stale = RebootRecovery.objects.get(pk=rec.pk)
    RebootRecovery.objects.filter(pk=rec.pk).update(attempts=4, version=rec.version + 1)
    Vm.objects.filter(pk=vm.pk).update(guest_signal_at=timezone.now())
    vm.refresh_from_db()

    service._reboot_recovery_wedged_step(vm, stale, "node-src", now=timezone.now())
    assert RebootRecovery.objects.get(pk=rec.pk).attempts == 4


@override_settings(VALI_REBOOT_RECOVERY_ENABLED=True)
def test_a_domain_just_relaunched_without_proof_keeps_the_count(monkeypatch, stub_relaunch):
    """Up for a minute and nothing from inside yet: still the same incident.
    A VM that goes down again from here must spend from the SAME budget."""
    vm = make_vm()
    _make_alive_miner()
    _rec_after_relaunch(vm, attempts=2, ago_s=60)
    _set_signal(monkeypatch, True)  # no guest signal at all → `unknown`

    service.reboot_recovery_once()
    assert RebootRecovery.objects.get(vm=vm).attempts == 2


@override_settings(VALI_REBOOT_RECOVERY_ENABLED=True)
def test_a_silent_guest_counts_as_recovered_once_it_stayed_up(monkeypatch, stub_relaunch):
    vm = make_vm()
    _make_alive_miner()
    _rec_after_relaunch(vm, attempts=3, ago_s=3600)
    _set_signal(monkeypatch, True)  # agentless: never signals

    service.reboot_recovery_once()
    assert RebootRecovery.objects.get(vm=vm).attempts == 0


@override_settings(VALI_REBOOT_RECOVERY_ENABLED=True)
def test_a_wedged_guest_never_ends_its_incident(monkeypatch, stub_relaunch):
    """Domain up, guest silent since before the relaunch: not recovered."""
    vm = make_vm()
    _make_alive_miner()
    _rec_after_relaunch(vm, attempts=3, ago_s=3600)
    _signal(vm, ago_s=3 * 3600)  # last heard from before the relaunch
    _set_signal(monkeypatch, True)

    service.reboot_recovery_once()
    assert RebootRecovery.objects.get(vm=vm).attempts == 3



@override_settings(VALI_REBOOT_RECOVERY_ENABLED=True)
def test_relaunch_re_mints_the_token_on_the_vms_own_golden_bake(monkeypatch):
    """Reboot-recovery (and the power-API start, which relaunches through
    it) runs the REAL `launch_on_miner` on a spec rebuilt from the BASE
    cmdline, so a golden VM launched before #1304 comes back with
    `systemd.import_credentials=no` in its measured cmdline — while its
    kernel/initrd/base stay those of its own bake (its old initramfs has no
    #1305 guard, so the token is harmless there, and a newer blessed golden
    is never swapped in under an existing overlay)."""
    from apps.orchestration.services import launch_record
    from apps.orchestration.services import preflight as preflight_svc
    from apps.orchestration.services import vault_kv as vk

    from .test_launch_service import _fake_the_launch_choreography

    vm = make_vm()
    miner = _make_alive_miner()
    golden = {
        **_FULL_SPEC,
        "vm_id": vm.vm_id,
        "disk_mode": "golden_verity_overlay",
        "luks_header_sha256_hex": "",
        "verity_root_hash_hex": "e" * 64,
        "rootfs_img_sha256_hex": "f" * 64,
        "rootfs_verity_sha256_hex": "9" * 64,
        "cmdline": "ro console=ttyS0",
    }
    stale_measured = "ro console=ttyS0 dm-verity.root=" + "e" * 64 + " boot=hippius-golden"
    LaunchJob.objects.create(
        job_id="succ-token",
        vm_id=vm.vm_id,
        tenant_id="tenant-1",
        flavor="small",
        spec_json=golden,
        userdata_vault_path=f"x/{vm.vm_id}/userdata",
        userdata_vault_version=1,
        kek_vault_path=f"x/{vm.vm_id}/luks-kek",
        state=LaunchJobState.SUCCEEDED.value,
        phase_started_at=timezone.now(),
        finished_at=timezone.now(),
        result_json={"emit": {"measured_cmdline": stale_measured}},
        decided_by=make_service_client(),
    )
    monkeypatch.setattr(service.effects, "poll_domain_running", lambda vm: False)
    monkeypatch.setattr(
        vk,
        "get_kv",
        lambda mount, path, version=None: b"#cloud-config\n# {{NETBIRD_SETUP_KEY}}\n",
    )
    # kek_bytes=None ⇒ the relaunch reads the already-staged KEK's version.
    monkeypatch.setattr(vk, "latest_version", lambda mount, path: 1)
    _fake_the_launch_choreography(monkeypatch, dispatch_ok=True)
    preflight_seen = {}

    def _preflight(**kw):
        preflight_seen.update(kw)
        return preflight_svc.PreflightResult(
            launch_digest_hex="ab" * 48,
            luks_disk_path="/d.img",
            kernel_path="/k",
            initrd_path="/i",
            rootfs_data_path="/staging/vm-1/rootfs.img",
            rootfs_hash_path="/staging/vm-1/rootfs.verity",
        )

    monkeypatch.setattr(preflight_svc, "dispatch_preflight", _preflight)
    recorded = {}
    monkeypatch.setattr(
        launch_record,
        "record_relaunch",
        lambda vm_id, emit, **k: recorded.update(emit) or True,
    )

    out_seen = {}
    real = launch.launch_on_miner

    def _spy(spec, m, **kw):
        out_seen["spec_cmdline"] = spec.cmdline
        out = real(spec, m, **kw)
        out_seen["out"] = out
        return out

    monkeypatch.setattr(launch, "launch_on_miner", _spy)
    ok = service._reboot_recovery_relaunch(vm, miner.miner_id)
    assert ok is True, getattr(out_seen.get("out"), "emit", None)

    assert out_seen["spec_cmdline"] == golden["cmdline"], (
        "the relaunch spec must start from the base cmdline, not the stored measured one"
    )
    sent = preflight_seen["cmdline"]
    assert "systemd.import_credentials=no" in sent.split(), sent
    assert "boot=hippius-golden" in sent.split(), "still a golden boot"
    assert "systemd.import_credentials=no" in recorded["measured_cmdline"].split()
    artifacts = preflight_seen["artifacts"]
    assert artifacts.kernel.sha256_hex == golden["kernel_sha256_hex"]
    assert artifacts.initrd.sha256_hex == golden["initrd_sha256_hex"]
    assert artifacts.initrd.key == "p/tenant.initrd.img"
    assert artifacts.luks_disk.sha256_hex == golden["rootfs_img_sha256_hex"]
