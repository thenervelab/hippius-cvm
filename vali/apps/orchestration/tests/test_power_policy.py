"""Guest-poweroff policy (`apps.orchestration.power_policy`).

What is worth pinning:

- which miners vali believes know the policy (the agent version gate), and
  that a launch NEVER falls back to `restart` for a `stop` VM;
- that `effective` only ever says `stop` for what the VM's current host
  acknowledged and still supports;
- that reboot-recovery records a `stop` VM whose guest powered off as
  stopped — and still relaunches a `restart` VM whatever its miner says;
- the API contract: launch field, PATCH, and the `VmSerializer` fields.
"""

from __future__ import annotations

import json
from datetime import timedelta
from pathlib import Path
from types import SimpleNamespace

import pytest
from django.conf import settings
from django.test import override_settings
from django.urls import reverse
from django.utils import timezone

from apps.lifecycle.models import Vm, VmPowerState, VmState
from apps.miners.models import MinerIdentity, MinerStatus
from apps.orchestration import effects, launch_jobs, order_dispatch, power_policy, service
from apps.orchestration.launch_jobs import LaunchIntentError
from apps.orchestration.models import LaunchJob, LaunchJobState, RebootRecovery
from apps.orchestration.services import launch
from apps.scheduler.models import MinerCapacity, MinerStatusMirror

from .factories import make_service_client, make_vm

pytestmark = pytest.mark.django_db

MIN = "v2026.10.09"
_VECTOR = Path(__file__).resolve().parents[4] / "test_vectors" / "orders" / "power_policy_v1.json"


def _miner(
    miner_id: str = "node-src", *, version: str = "", v5_after: bool = False
) -> MinerIdentity:
    """A locally-ACTIVE, heart-beating miner whose latest heartbeat
    reported `version` (v6) — or, with `v5_after`, a later v5 heartbeat
    that carried no version (agent rolled back / flag off)."""
    node_id = f"{abs(hash(miner_id)) % (16**16):016x}".ljust(64, "1")
    miner = MinerIdentity.objects.create(
        miner_id=miner_id,
        pubkey_hex=f"{abs(hash(miner_id)) % (16**16):016x}".ljust(64, "0"),
        platform_id=f"plat-{miner_id}",
        chain_node_id=node_id,
        netbird_ip="100.64.0.9",
        last_seen_at=timezone.now(),
        status=MinerStatus.ACTIVE,
    )
    now = timezone.now()
    MinerCapacity.objects.create(
        miner_node_id=node_id,
        status=MinerStatusMirror.ACTIVE,
        capacity_slots=8,
        observed_epoch=10,
        data_epoch=10,
        refreshed_at=now,
        agent_version=version,
        agent_version_reported_at=now if version else None,
        host_health_reported_at=(now + timedelta(seconds=60)) if v5_after else now,
    )
    return miner


def _vm(vm_id: str = "vm-pp", **kw) -> Vm:
    vm = make_vm(vm_id)
    if kw:
        Vm.objects.filter(pk=vm.pk).update(**kw)
        vm.refresh_from_db()
    return vm


@pytest.fixture
def sent(monkeypatch):
    """Record `power-policy` dispatches; `sent.ok` decides the answer."""
    calls: list[tuple[str, str]] = []
    holder = SimpleNamespace(ok=True, calls=calls, side_effect=None)

    def fake(vm, policy, deadline_s=None):
        calls.append((vm.vm_id, policy))
        if holder.side_effect is not None:
            holder.side_effect(vm, policy)
        return holder.ok

    monkeypatch.setattr(power_policy, "_dispatch", fake)
    return holder


# ── the agent version gate ──────────────────────────────────────────


def test_release_keys_order_and_reject_non_tags() -> None:
    assert power_policy.release_key("v2026.10.08.1") > power_policy.release_key("v2026.10.08")
    assert power_policy.release_key("v2026.10.09") > power_policy.release_key("v2026.10.08.9")
    for bad in ["", "dev", "2026.10.08", "v2026.1.8", "v2026.10.08-rc1", "v2026.10.08.1.2"]:
        assert power_policy.release_key(bad) is None, bad


@override_settings(VALI_POWER_POLICY_MIN_AGENT_VERSION=MIN)
def test_only_miners_reporting_a_recent_enough_tag_qualify() -> None:
    new = _miner("m-new", version="v2026.10.09.2")
    old = _miner("m-old", version="v2026.10.08.1")
    _miner("m-none")
    rolled_back = _miner("m-v5", version="v2026.10.10", v5_after=True)
    _miner("m-dev", version="dev")
    assert power_policy.capable_node_ids() == frozenset({new.chain_node_id.lower()})
    assert power_policy.capable_hosts({"m-new", "m-old", "m-v5", "m-none", "m-dev", ""}) == {
        "m-new"
    }
    assert power_policy.supports(new)
    assert not power_policy.supports(old)
    assert not power_policy.supports(rolled_back)


@pytest.mark.parametrize("value", ["", "latest", "2026.10.09"])
def test_an_unset_or_bad_minimum_means_no_miner_qualifies(value) -> None:
    _miner("m-new", version="v2026.10.09.2")
    with override_settings(VALI_POWER_POLICY_MIN_AGENT_VERSION=value):
        assert power_policy.capable_node_ids() == frozenset()


# ── launch: never a silent restart ──────────────────────────────────


@override_settings(VALI_POWER_POLICY_MIN_AGENT_VERSION=MIN)
def test_launch_field_is_stop_only_where_supported() -> None:
    new = _miner("m-new", version=MIN)
    old = _miner("m-old", version="v2026.10.01")
    assert power_policy.launch_field("restart", old, relaunch=False) is None
    assert power_policy.launch_field("stop", new, relaunch=False) == "stop"
    with pytest.raises(power_policy.PowerPolicyRefused) as exc:
        power_policy.launch_field("stop", old, relaunch=False)
    assert exc.value.reason == "no-miner-supports-power-policy"
    # A relaunch on its own host that lost the policy still boots the VM.
    assert power_policy.launch_field("stop", old, relaunch=True) is None


def test_the_launch_payload_carries_the_field_only_when_set() -> None:
    kw = dict(
        vm_id="v",
        ovmf_path="/o",
        kernel_path="/k",
        initrd_path="/i",
        cmdline="console=hvc0",
        luks_disk_path="/d",
        luks_disk_size_gb=10,
        rootfs_data_path="/r",
        rootfs_hash_path="/h",
        cpu_count=2,
        memory_mb=2048,
        cose_ticket=b"t",
    )
    assert "on_guest_poweroff" not in order_dispatch.build_launch_payload(**kw)
    assert (
        order_dispatch.build_launch_payload(**kw, on_guest_poweroff="stop")["on_guest_poweroff"]
        == "stop"
    )


_REAL_BIN = Path(settings.VALI_TICKET_VALIDATOR_BIN)
real_binary = pytest.mark.skipif(
    not _REAL_BIN.is_file(),
    reason=f"Rust validator not built at {_REAL_BIN}: cargo build -p hippius-ticket-validator",
)


@real_binary
def test_vali_bodies_match_the_shared_vector() -> None:
    """The bodies the agent and the edge are tested against are the ones
    vali builds: the payload shapes below, through the real encoder."""
    v = json.loads(_VECTOR.read_text())
    cases = {c["name"]: c for c in v["cases"]}
    launch_case = cases["launch-stop"]["payload"]
    payload = order_dispatch.build_launch_payload(
        vm_id=launch_case["vm_id"],
        ovmf_path=launch_case["ovmf_path"],
        kernel_path=launch_case["kernel_path"],
        initrd_path=launch_case["initrd_path"],
        cmdline=launch_case["cmdline"],
        luks_disk_path=launch_case["luks_disk_path"],
        luks_disk_size_gb=launch_case["luks_disk_size_gb"],
        rootfs_data_path="/var/lib/hippius-miner/rootfs.img",
        rootfs_hash_path="/var/lib/hippius-miner/rootfs.verity",
        cpu_count=launch_case["cpu_count"],
        memory_mb=launch_case["memory_mb"],
        cose_ticket=b"fake-cose-ticket-bytes",
        on_guest_poweroff="stop",
    )
    # The vector's launch payload carries no rootfs paths / data disk; the
    # encoder emits rootfs paths verbatim and a 0 data disk not at all, so
    # compare on the vector's own keys.
    for key in ("rootfs_data_path", "rootfs_hash_path"):
        payload.pop(key)
    want = {
        "power-policy-stop": {"vm_id": "tenant-1", "on_guest_poweroff": "stop"},
        "power-policy-restart": {"vm_id": "tenant-1", "on_guest_poweroff": "restart"},
        "launch-stop": payload,
    }
    for name, body in want.items():
        encoded = order_dispatch._encode_order_body(
            order_id=v["order_id"],
            kind=cases[name]["kind"],
            target_miner_id=v["target_miner_id"],
            issued_at_unix=v["issued_at_unix"],
            payload_json=json.dumps(body).encode(),
        )
        assert encoded.hex() == cases[name]["body_hex"], name


def test_the_power_policy_order_is_what_the_agent_decodes(monkeypatch) -> None:
    """`_dispatch` sends kind `power-policy` with exactly `{vm_id,
    on_guest_poweroff}` to the VM's host."""
    _miner("node-src", version=MIN)
    vm = _vm()
    seen: dict = {}

    def fake(**kw):
        seen.update(kw)
        return order_dispatch.DispatchResult(ok=True, status=200, classifier="power-policy:stop")

    monkeypatch.setattr(order_dispatch, "dispatch_order_settled", fake)
    assert power_policy._dispatch(vm, "stop") is True
    assert seen["kind"] == "power-policy"
    assert seen["miner_id"] == "node-src"
    assert json.loads(seen["payload_json"]) == {"vm_id": "vm-pp", "on_guest_poweroff": "stop"}
    assert seen["order_id"].startswith("pwr-policy-vm-pp-")


# ── view: requested / effective / pending / reason ──────────────────


@override_settings(VALI_POWER_POLICY_MIN_AGENT_VERSION=MIN)
def test_view_matrix() -> None:
    _miner("node-src", version=MIN)
    vm = _vm()
    assert power_policy.view(vm) == {
        "on_guest_poweroff": "restart",
        "on_guest_poweroff_effective": "restart",
        "on_guest_poweroff_pending": False,
        "on_guest_poweroff_reason": None,
    }
    vm = _vm("vm-2", on_guest_poweroff="stop")
    assert power_policy.view(vm)["on_guest_poweroff_reason"] == "awaiting-ack"
    vm = _vm(
        "vm-3",
        on_guest_poweroff="stop",
        on_guest_poweroff_effective="stop",
        on_guest_poweroff_effective_host="node-src",
    )
    assert power_policy.view(vm) == {
        "on_guest_poweroff": "stop",
        "on_guest_poweroff_effective": "stop",
        "on_guest_poweroff_pending": False,
        "on_guest_poweroff_reason": None,
    }
    # Acknowledged by ANOTHER host (the VM moved): that ack says nothing here.
    vm = _vm(
        "vm-4",
        on_guest_poweroff="stop",
        on_guest_poweroff_effective="stop",
        on_guest_poweroff_effective_host="node-old",
    )
    assert power_policy.view(vm)["on_guest_poweroff_effective"] == "restart"
    assert power_policy.view(vm)["on_guest_poweroff_reason"] == "awaiting-ack"


@override_settings(VALI_POWER_POLICY_MIN_AGENT_VERSION=MIN)
def test_a_host_that_lost_support_reads_restart_and_host_unsupported() -> None:
    _miner("node-src", version=MIN, v5_after=True)
    vm = _vm(
        on_guest_poweroff="stop",
        on_guest_poweroff_effective="stop",
        on_guest_poweroff_effective_host="node-src",
    )
    assert power_policy.view(vm) == {
        "on_guest_poweroff": "stop",
        "on_guest_poweroff_effective": "restart",
        "on_guest_poweroff_pending": True,
        "on_guest_poweroff_reason": "host-unsupported",
    }


# ── PATCH semantics ─────────────────────────────────────────────────


@override_settings(VALI_POWER_POLICY_MIN_AGENT_VERSION=MIN)
def test_change_to_stop_is_applied_through_the_miner(sent) -> None:
    _miner("node-src", version=MIN)
    vm = power_policy.change(_vm(), "stop")
    assert sent.calls == [("vm-pp", "stop")]
    assert power_policy.view(vm) == {
        "on_guest_poweroff": "stop",
        "on_guest_poweroff_effective": "stop",
        "on_guest_poweroff_pending": False,
        "on_guest_poweroff_reason": None,
    }
    # Back to restart: one more order, acknowledged too.
    vm = power_policy.change(vm, "restart")
    assert sent.calls[-1] == ("vm-pp", "restart")
    assert power_policy.view(vm)["on_guest_poweroff_effective"] == "restart"
    # Asking again for what is acknowledged sends nothing.
    power_policy.change(vm, "restart")
    assert len(sent.calls) == 2


@override_settings(VALI_POWER_POLICY_MIN_AGENT_VERSION=MIN)
def test_change_to_stop_on_an_unsupported_host_is_refused_and_records_nothing(sent) -> None:
    _miner("node-src", version="v2026.10.01")
    with pytest.raises(power_policy.PowerPolicyRefused) as exc:
        power_policy.change(_vm(), "stop")
    assert exc.value.reason == "power-policy-unsupported-on-host"
    assert Vm.objects.get(vm_id="vm-pp").on_guest_poweroff == "restart"
    assert sent.calls == []


@override_settings(VALI_POWER_POLICY_MIN_AGENT_VERSION=MIN)
def test_a_failed_dispatch_leaves_it_pending_and_the_tick_resends(sent) -> None:
    _miner("node-src", version=MIN)
    sent.ok = False
    vm = power_policy.change(_vm(), "stop")
    assert power_policy.view(vm)["on_guest_poweroff_reason"] == "awaiting-ack"
    sent.ok = True
    assert power_policy.reconcile_once() == 1
    assert power_policy.view(Vm.objects.get(pk=vm.pk))["on_guest_poweroff_pending"] is False
    assert sent.calls == [("vm-pp", "stop"), ("vm-pp", "stop")]
    # Nothing left to do.
    assert power_policy.reconcile_once() == 0
    assert len(sent.calls) == 2


@override_settings(VALI_POWER_POLICY_MIN_AGENT_VERSION=MIN)
def test_a_stopped_vm_gets_it_with_its_next_start(sent) -> None:
    _miner("node-src", version=MIN)
    vm = power_policy.change(_vm(power_state=VmPowerState.STOPPED), "stop")
    assert sent.calls == []
    assert power_policy.view(vm)["on_guest_poweroff_reason"] == "awaiting-ack"
    assert power_policy.reconcile_once() == 0


def test_change_refuses_a_vm_that_is_not_active(sent) -> None:
    vm = _vm(state=VmState.DECOMMISSIONING)
    with pytest.raises(power_policy.PowerPolicyRefused) as exc:
        power_policy.change(vm, "restart")
    assert exc.value.reason == "vm-not-active"


@override_settings(VALI_POWER_POLICY_MIN_AGENT_VERSION=MIN)
def test_reconcile_records_restart_for_a_vm_that_moved(sent) -> None:
    """A §25 destination booted without the field: it restarts. Recorded as
    the new host's, with no order."""
    _miner("node-src", version=MIN)
    vm = _vm(on_guest_poweroff_effective="stop", on_guest_poweroff_effective_host="node-old")
    power_policy.reconcile_once()
    vm.refresh_from_db()
    assert (vm.on_guest_poweroff_effective, vm.on_guest_poweroff_effective_host) == (
        "restart",
        "node-src",
    )
    assert sent.calls == []


@override_settings(VALI_POWER_POLICY_MIN_AGENT_VERSION=MIN)
def test_reconcile_pushes_stop_to_a_vm_that_moved(sent) -> None:
    _miner("node-src", version=MIN)
    _vm(
        on_guest_poweroff="stop",
        on_guest_poweroff_effective="stop",
        on_guest_poweroff_effective_host="node-old",
    )
    assert power_policy.reconcile_once() == 1
    assert sent.calls == [("vm-pp", "stop")]
    vm = Vm.objects.get(vm_id="vm-pp")
    assert vm.on_guest_poweroff_effective_host == "node-src"


@override_settings(VALI_POWER_POLICY_MIN_AGENT_VERSION=MIN)
def test_reconcile_waits_for_an_unsupported_host(sent) -> None:
    _miner("node-src", version="v2026.10.01")
    _vm(on_guest_poweroff="stop")
    assert power_policy.reconcile_once() == 0
    assert sent.calls == []


@override_settings(VALI_POWER_POLICY_MIN_AGENT_VERSION=MIN)
def test_reconcile_bounds_its_dispatches(sent) -> None:
    _miner("node-src", version=MIN)
    for i in range(4):
        _vm(f"vm-{i}", on_guest_poweroff="stop")
    power_policy.reconcile_once(max_dispatches=2)
    assert len(sent.calls) == 2


# ── reboot-recovery: a guest poweroff under `stop` is not an outage ───


def _arm_and_go_down(monkeypatch, vm, *, stop_reason: str) -> None:
    holder = {"v": True}
    monkeypatch.setattr(service.effects, "poll_domain_running", lambda _vm: holder["v"])
    monkeypatch.setattr(
        service.effects,
        "poll_domain_state",
        lambda _vm: (holder["v"], "" if holder["v"] else stop_reason),
    )
    assert service.reboot_recovery_once() == 0  # seen running
    holder["v"] = False


@pytest.fixture
def stub_relaunch(monkeypatch):
    calls = []
    monkeypatch.setattr(
        service, "_reboot_recovery_relaunch", lambda vm, node_id: calls.append(vm.vm_id) or True
    )
    return calls


@override_settings(VALI_REBOOT_RECOVERY_ENABLED=True, VALI_REBOOT_RECOVERY_DEBOUNCE_POLLS=1)
def test_a_stop_vm_whose_guest_powered_off_is_recorded_stopped(monkeypatch, stub_relaunch) -> None:
    _miner("node-src")
    vm = _vm(on_guest_poweroff="stop")
    _arm_and_go_down(monkeypatch, vm, stop_reason="guest-poweroff")
    assert service.reboot_recovery_once() == 0
    assert stub_relaunch == [], "a guest poweroff under stop was relaunched"
    vm.refresh_from_db()
    assert vm.power_state == VmPowerState.STOPPED
    assert vm.state == VmState.ACTIVE, "a stopped VM must stay KBS-releasable"
    assert power_policy.stop_reason(vm) == "guest-poweroff"
    assert RebootRecovery.objects.get(vm=vm).consecutive_down == 0
    # It stays stopped on later ticks.
    assert service.reboot_recovery_once() == 0
    assert stub_relaunch == []
    # Any later power write makes the reason stale.
    from apps.orchestration.services import power

    power._set_power(vm, VmPowerState.STARTING)
    vm.refresh_from_db()
    assert power_policy.stop_reason(vm) is None


@override_settings(VALI_REBOOT_RECOVERY_ENABLED=True, VALI_REBOOT_RECOVERY_DEBOUNCE_POLLS=1)
def test_a_restart_vm_is_relaunched_whatever_its_miner_says(monkeypatch, stub_relaunch) -> None:
    """A miner saying `guest-poweroff` cannot keep a `restart` VM down."""
    _miner("node-src")
    vm = _vm()
    _arm_and_go_down(monkeypatch, vm, stop_reason="guest-poweroff")
    assert service.reboot_recovery_once() == 1
    assert stub_relaunch == ["vm-pp"]
    vm.refresh_from_db()
    assert vm.power_state == VmPowerState.RUNNING


@override_settings(VALI_REBOOT_RECOVERY_ENABLED=True, VALI_REBOOT_RECOVERY_DEBOUNCE_POLLS=1)
def test_a_stop_vm_down_for_another_reason_is_relaunched(monkeypatch, stub_relaunch) -> None:
    """A crash the miner could not restart (rate limit, agent down): the
    VM is relaunched like any other."""
    _miner("node-src")
    vm = _vm(on_guest_poweroff="stop")
    _arm_and_go_down(monkeypatch, vm, stop_reason="")
    assert service.reboot_recovery_once() == 1
    assert stub_relaunch == ["vm-pp"]


def test_the_domain_state_probe_reads_the_stop_reason(monkeypatch) -> None:
    vm = _vm()
    answers = iter(
        [
            (200, b'{"running":false,"stop_reason":"guest-poweroff"}'),
            (200, b'{"running":false}'),
            (200, b'{"running":true,"stop_reason":"guest-poweroff"}'),
            (503, b"libvirt-unreachable"),
        ]
    )
    monkeypatch.setattr(effects, "_edge_get_addr", lambda *_a: next(answers))
    assert effects._poll_domain_state_at(vm, "x") == (False, "guest-poweroff")
    assert effects._poll_domain_state_at(vm, "x") == (False, "")
    assert effects._poll_domain_state_at(vm, "x") == (True, "")
    assert effects._poll_domain_state_at(vm, "x") == (None, "")


# ── relaunch carries the tenant's CURRENT choice ────────────────────

_SPEC = {
    "tenant_id": "tenant-1",
    "user_id": "user-1",
    "vm_id": "vm-pp",
    "lease_id": "lease-vm-pp",
    "s3_bucket": "b",
    "s3_key_prefix": "p",
    "luks_disk_sha256_hex": "a" * 64,
    "kernel_sha256_hex": "b" * 64,
    "initrd_sha256_hex": "c" * 64,
    "luks_header_sha256_hex": "d" * 64,
    "flavor": "small",
    "cmdline": "console=ttyS0",
}


@pytest.mark.parametrize("launched_with", [None, "stop"])
@pytest.mark.parametrize("current", ["restart", "stop"])
def test_a_relaunch_uses_the_current_policy(monkeypatch, launched_with, current) -> None:
    vm = _vm(on_guest_poweroff=current)
    miner = _miner("node-src")
    spec_json = dict(_SPEC)
    if launched_with:
        spec_json["on_guest_poweroff"] = launched_with
    LaunchJob.objects.create(
        job_id="succ-pp",
        vm_id=vm.vm_id,
        tenant_id="tenant-1",
        flavor="small",
        spec_json=spec_json,
        userdata_vault_path="x/vm-pp/userdata",
        userdata_vault_version=1,
        kek_vault_path="x/vm-pp/luks-kek",
        state=LaunchJobState.SUCCEEDED.value,
        phase_started_at=timezone.now(),
        finished_at=timezone.now(),
        decided_by=make_service_client(),
    )
    monkeypatch.setattr(launch, "open_userdata_intake_copy", lambda *a, **k: b"u")
    seen = []
    monkeypatch.setattr(
        launch,
        "launch_on_miner",
        lambda spec, m, **kw: (
            seen.append((spec.on_guest_poweroff, kw))
            or SimpleNamespace(disposition=launch.ACCEPTED, emit={})
        ),
    )
    monkeypatch.setattr(service, "rebind_placement_to_host", lambda *a, **k: None)
    assert service._reboot_recovery_relaunch(vm, miner.miner_id) is True
    assert seen[0][0] == current
    assert seen[0][1]["require_existing_disks"] is True


# ── placement gate (l) ──────────────────────────────────────────────


def _snapshot(*node_ids: str):
    from apps.scheduler.placement import MINER_ACTIVE

    return SimpleNamespace(
        current_epoch=10,
        pallet_live=True,
        miners=[
            SimpleNamespace(node_id=n, status=MINER_ACTIVE, data_epoch=10, quality=0)
            for n in node_ids
        ],
    )


def _decide(snapshot, **kw):
    from apps.scheduler.placement import decide_placement

    nodes = [m.node_id for m in snapshot.miners]
    return decide_placement(
        snapshot=snapshot,
        capacity_by_node={n: 4 for n in nodes},
        load_by_node={},
        family_load_by_node={},
        max_epoch_lag=5,
        **kw,
    )


def test_gate_l_places_a_stop_vm_only_where_the_agent_knows_it() -> None:
    from apps.scheduler.placement import PlacementError

    snap = _snapshot("aa", "bb")
    assert _decide(snap, power_policy_capable=frozenset({"bb"})) == "bb"
    with pytest.raises(PlacementError) as exc:
        _decide(snap, power_policy_capable=frozenset())
    assert exc.value.category == "no-miner-supports-power-policy"
    # No gate for a `restart` VM.
    assert _decide(snap) in {"aa", "bb"}


@override_settings(VALI_POWER_POLICY_MIN_AGENT_VERSION=MIN)
def test_placement_arguments_add_gate_l_only_for_stop() -> None:
    from apps.scheduler import service as sched

    new = _miner("m-new", version=MIN)
    snap = SimpleNamespace(current_epoch=10, pallet_live=True, miners=[])
    base = dict(snapshot=snap, tenant_id="t", user_id="u", flavor="small", shadow_log=False)
    assert "power_policy_capable" not in sched.placement_arguments(**base)
    args = sched.placement_arguments(**base, power_policy_stop=True)
    assert args["power_policy_capable"] == frozenset({new.chain_node_id.lower()})


# ── API ─────────────────────────────────────────────────────────────


def _intent(**overrides) -> dict:
    body = {
        "tenant_id": "t-api",
        "user_id": "u-1",
        "vm_id": "vm-api-pp",
        "lease_id": "lease-1",
        "flavor": "small",
        "cmdline": "ro",
        "s3_bucket": "b",
        "s3_key_prefix": "p/",
        "luks_disk_sha256_hex": "a" * 64,
        "kernel_sha256_hex": "a" * 64,
        "initrd_sha256_hex": "a" * 64,
        "luks_header_sha256_hex": "a" * 64,
    }
    body.update(overrides)
    return body


def test_launch_intake_validates_and_records_the_policy() -> None:
    assert "on_guest_poweroff" not in launch_jobs._build_spec_json(_intent())
    assert "on_guest_poweroff" not in launch_jobs._build_spec_json(
        _intent(on_guest_poweroff="restart")
    )
    spec = launch_jobs._build_spec_json(_intent(on_guest_poweroff="stop"))
    assert spec["on_guest_poweroff"] == "stop"
    for bad in ["STOP", "halt", 1, True, ""]:
        with pytest.raises(LaunchIntentError) as exc:
            launch_jobs._build_spec_json(_intent(on_guest_poweroff=bad))
        assert exc.value.category == "bad-field"
    # The worker's `LaunchSpec(**spec_json)` takes it.
    assert launch.LaunchSpec(**spec, kek_bytes=None, userdata=b"").on_guest_poweroff == "stop"


def test_launch_api_400s_a_bad_policy(root_client) -> None:
    body = {
        **_intent(on_guest_poweroff="nope"),
        "kek_vault_path": f"{settings.VALI_VAULT_KV_PREFIX}/vm-api-pp/luks-kek",
        "userdata": "#cloud-config\n# {{NETBIRD_SETUP_KEY}}\n",
    }
    resp = root_client.post(reverse("vm_launch"), body, format="json")
    assert resp.status_code == 400
    assert resp.json()["category"] == "bad-field"
    assert "on_guest_poweroff" in resp.json()["error"]
    assert LaunchJob.objects.count() == 0


def test_a_new_vm_row_carries_the_launch_policy() -> None:
    spec = launch.LaunchSpec(
        **{**_SPEC, "vm_id": "vm-row", "on_guest_poweroff": "stop"},
        kek_bytes=None,
        userdata=b"",
    )
    vm = launch._ensure_vm_row(spec)
    assert vm.on_guest_poweroff == "stop"
    assert vm.on_guest_poweroff_effective == "restart"


@override_settings(VALI_POWER_POLICY_MIN_AGENT_VERSION=MIN)
def test_patch_power_policy(root_client, authed_client, sent) -> None:
    _miner("node-src", version=MIN)
    _vm()
    url = reverse("vm_power_policy", args=["vm-pp"])
    assert authed_client.patch(url, {"on_guest_poweroff": "stop"}, format="json").status_code == 403
    for body in [{}, {"on_guest_poweroff": "Stop"}, {"on_guest_poweroff": None}]:
        resp = root_client.patch(url, body, format="json")
        assert resp.status_code == 400, body
    resp = root_client.patch(url, {"on_guest_poweroff": "stop", "x": 1}, format="json")
    assert resp.status_code == 400
    resp = root_client.patch(
        reverse("vm_power_policy", args=["nope"]), {"on_guest_poweroff": "stop"}, format="json"
    )
    assert resp.status_code == 404
    resp = root_client.patch(url, {"on_guest_poweroff": "stop"}, format="json")
    assert resp.status_code == 200, resp.content
    assert resp.json() == {
        "vm_id": "vm-pp",
        "on_guest_poweroff": "stop",
        "on_guest_poweroff_effective": "stop",
        "on_guest_poweroff_pending": False,
        "on_guest_poweroff_reason": None,
    }


@override_settings(VALI_POWER_POLICY_MIN_AGENT_VERSION=MIN)
def test_patch_stop_on_an_old_agent_is_409(root_client, sent) -> None:
    _miner("node-src", version="v2026.10.01")
    _vm()
    resp = root_client.patch(
        reverse("vm_power_policy", args=["vm-pp"]), {"on_guest_poweroff": "stop"}, format="json"
    )
    assert resp.status_code == 409
    assert resp.json()["category"] == "power-policy-unsupported-on-host"


@override_settings(VALI_POWER_POLICY_MIN_AGENT_VERSION=MIN)
def test_the_vm_serialization_carries_the_policy_and_the_power_axis(root_client) -> None:
    _miner("node-src", version=MIN)
    _vm(on_guest_poweroff="stop")
    for url in [reverse("vm_state", args=["vm-pp"]), reverse("vm_list") + "?tenant_id="]:
        resp = root_client.get(url)
        assert resp.status_code == 200, resp.content
        body = resp.json()
        row = body if "vm_id" in body else next(v for v in body["vms"] if v["vm_id"] == "vm-pp")
        assert row["on_guest_poweroff"] == "stop"
        assert row["on_guest_poweroff_effective"] == "restart"
        assert row["on_guest_poweroff_pending"] is True
        assert row["on_guest_poweroff_reason"] == "awaiting-ack"
        assert row["power_state"] == "running"
        assert row["stop_reason"] is None


# ── launch_on_miner: what it sends, what it records ─────────────────


def _launch_rig(monkeypatch, *, classifier: str = "launched"):
    from apps.scheduler.tests.factories import node_id

    from .test_launch_service import (  # isort: skip
        _fake_the_launch_choreography,
        _register_miner,
    )

    _fake_the_launch_choreography(monkeypatch, dispatch_ok=True)
    payloads: list[dict] = []
    monkeypatch.setattr(
        order_dispatch, "build_launch_payload", lambda *a, **k: payloads.append(k) or {}
    )
    monkeypatch.setattr(
        order_dispatch,
        "dispatch_order",
        lambda *a, **k: order_dispatch.DispatchResult(ok=True, status=200, classifier=classifier),
    )
    miner = _register_miner(1)
    now = timezone.now()
    MinerCapacity.objects.create(
        miner_node_id=node_id(1),
        status="active",
        capacity_slots=4,
        observed_epoch=10,
        data_epoch=10,
        refreshed_at=now,
        agent_version=MIN,
        agent_version_reported_at=now,
        host_health_reported_at=now,
    )
    return miner, payloads


def _launch_spec(**kw):
    from .test_launch_service import _spec  # isort: skip

    return _spec(userdata=b"#cloud-config\n# {{NETBIRD_SETUP_KEY}}\n", **kw)


@override_settings(VALI_POWER_POLICY_MIN_AGENT_VERSION=MIN)
def test_an_accepted_stop_launch_sends_the_field_and_records_the_ack(monkeypatch) -> None:
    miner, payloads = _launch_rig(monkeypatch)
    Vm.objects.create(
        vm_id="vm-launch-1",
        lease_id="lease-1",
        state=VmState.ACTIVE,
        generation=1,
        on_guest_poweroff="stop",
    )
    out = launch.launch_on_miner(_launch_spec(on_guest_poweroff="stop"), miner)
    assert out.disposition == launch.ACCEPTED, out.emit
    assert payloads[-1]["on_guest_poweroff"] == "stop"
    vm = Vm.objects.get(vm_id="vm-launch-1")
    assert (vm.on_guest_poweroff_effective, vm.on_guest_poweroff_effective_host) == (
        "stop",
        miner.miner_id,
    )
    assert power_policy.view(vm)["on_guest_poweroff_pending"] is False


@override_settings(VALI_POWER_POLICY_MIN_AGENT_VERSION=MIN)
def test_an_already_launched_answer_records_nothing(monkeypatch) -> None:
    miner, _ = _launch_rig(monkeypatch, classifier="already-launched")
    Vm.objects.create(
        vm_id="vm-launch-1",
        lease_id="lease-1",
        state=VmState.ACTIVE,
        generation=1,
        on_guest_poweroff="stop",
    )
    launch.launch_on_miner(_launch_spec(on_guest_poweroff="stop"), miner)
    assert Vm.objects.get(vm_id="vm-launch-1").on_guest_poweroff_effective_host == ""


@override_settings(VALI_POWER_POLICY_MIN_AGENT_VERSION="v2099.01.01")
def test_a_first_stop_launch_onto_an_old_agent_is_refused_before_anything(monkeypatch) -> None:
    miner, payloads = _launch_rig(monkeypatch)
    out = launch.launch_on_miner(_launch_spec(on_guest_poweroff="stop"), miner)
    assert out.disposition == launch.TERMINAL
    assert out.emit["outcome"] == "no-miner-supports-power-policy"
    assert payloads == [], "nothing may be dispatched"
    assert not Vm.objects.filter(vm_id="vm-launch-1").exists(), "nothing may be created"


@override_settings(VALI_POWER_POLICY_MIN_AGENT_VERSION="v2099.01.01")
def test_a_relaunch_onto_an_agent_that_lost_it_boots_and_says_so(monkeypatch) -> None:
    miner, payloads = _launch_rig(monkeypatch)
    Vm.objects.create(
        vm_id="vm-launch-1",
        lease_id="lease-1",
        state=VmState.ACTIVE,
        generation=1,
        host=miner.miner_id,
        on_guest_poweroff="stop",
    )
    out = launch.launch_on_miner(
        _launch_spec(on_guest_poweroff="stop"), miner, require_existing_disks=True
    )
    assert out.disposition == launch.ACCEPTED, out.emit
    assert payloads[-1]["on_guest_poweroff"] is None
    vm = Vm.objects.get(vm_id="vm-launch-1")
    assert vm.on_guest_poweroff_effective == "restart"
    assert power_policy.view(vm)["on_guest_poweroff_reason"] == "host-unsupported"


# ── concurrency, liveness, and the §24 proof ────────────────────────


@override_settings(VALI_POWER_POLICY_MIN_AGENT_VERSION=MIN)
def test_a_newer_request_during_a_dispatch_gets_the_last_word(sent) -> None:
    """PATCH stop is in flight; PATCH restart lands meanwhile (its order may
    reach the miner first). The stop must not be recorded, and the newest
    request is sent again so the miner ends on it."""
    _miner("node-src", version=MIN)
    vm = _vm()

    def newer_patch(vm_, policy):
        if policy == "stop":
            Vm.objects.filter(pk=vm_.pk).update(
                on_guest_poweroff="restart",
                on_guest_poweroff_effective="restart",
                on_guest_poweroff_effective_host="node-src",
            )

    sent.side_effect = newer_patch
    vm = power_policy.change(vm, "stop")
    assert sent.calls == [("vm-pp", "stop"), ("vm-pp", "restart")]
    assert (vm.on_guest_poweroff, vm.on_guest_poweroff_effective) == ("restart", "restart")
    assert vm.on_guest_poweroff_effective_host == "node-src"


@override_settings(VALI_POWER_POLICY_MIN_AGENT_VERSION=MIN)
def test_a_lost_race_whose_resend_fails_is_left_for_the_tick(sent) -> None:
    _miner("node-src", version=MIN)
    vm = _vm()

    def newer_patch(vm_, policy):
        if policy == "stop":
            Vm.objects.filter(pk=vm_.pk).update(on_guest_poweroff="restart")
        else:
            sent.ok = False

    sent.side_effect = newer_patch
    power_policy.change(vm, "stop")
    vm.refresh_from_db()
    # The miner may hold the `stop` that landed: pending, never "restart, done".
    assert vm.on_guest_poweroff_effective == "stop"
    assert power_policy.view(vm)["on_guest_poweroff_pending"] is True
    sent.ok, sent.side_effect = True, None
    power_policy.reconcile_once()
    vm.refresh_from_db()
    assert (vm.on_guest_poweroff_effective, vm.on_guest_poweroff_effective_host) == (
        "restart",
        "node-src",
    )
    assert sent.calls == [("vm-pp", "stop"), ("vm-pp", "restart"), ("vm-pp", "restart")]


@override_settings(VALI_POWER_POLICY_MIN_AGENT_VERSION=MIN)
def test_reconcile_skips_dark_miners_and_a_failing_miner_after_one_try(sent) -> None:
    _miner("node-src", version=MIN)
    dark = _miner("node-dark", version=MIN)
    MinerIdentity.objects.filter(pk=dark.pk).update(
        last_seen_at=timezone.now() - timedelta(hours=1)
    )
    for i in range(3):
        _vm(f"vm-src-{i}", on_guest_poweroff="stop")
    _vm("vm-dark", on_guest_poweroff="stop", host="node-dark")
    sent.ok = False
    power_policy.reconcile_once(max_dispatches=10)
    assert len(sent.calls) == 1, sent.calls
    assert sent.calls[0][0].startswith("vm-src-")


def _ack(client, vm_id: str, generation: int):
    return client.post(
        f"/v1/lifecycle/stopped?vm_id={vm_id}&generation={generation}",
        data=b"signed",
        content_type="application/cbor",
    )


@pytest.fixture
def ack_verifies(monkeypatch):
    from apps.lifecycle import validator

    calls: list[dict] = []
    monkeypatch.setattr(validator, "verify_stopped_ack", lambda **kw: calls.append(kw))
    return calls


def test_a_stop_vms_own_shutdown_ack_is_verified_and_noted(ack_verifies) -> None:
    from rest_framework.test import APIClient

    vm = _vm(on_guest_poweroff="stop")
    resp = _ack(APIClient(), vm.vm_id, vm.signing_generation)
    assert resp.status_code == 202, resp.content
    vm.refresh_from_db()
    assert vm.power_guest_ack_at is not None
    assert ack_verifies[0]["nonce_hex"] == bytes(vm.eol_nonce).hex()
    assert vm.power_stop_proof is None, "an ack alone proves no stop"
    # A `restart` VM's ack is refused as before.
    other = _vm("vm-restart")
    assert _ack(APIClient(), other.vm_id, other.signing_generation).status_code == 404
    other.refresh_from_db()
    assert other.power_guest_ack_at is None


def test_a_guest_poweroff_with_a_fresh_ack_is_a_proven_stop() -> None:
    from apps.orchestration.models import DecommissionJob

    vm = _vm(on_guest_poweroff="stop", power_guest_ack_at=timezone.now())
    assert power_policy.settle_guest_poweroff(vm)
    vm.refresh_from_db()
    assert vm.stopped_by_guest
    assert bytes(vm.power_stop_proof) == bytes(vm.eol_nonce)
    # What §24 reads: the stop is proven, no forced reclaim.
    job = DecommissionJob(vm=vm, job_id="j" * 32)
    assert service._power_stop_proven(job)


@pytest.mark.parametrize("age", [None, timedelta(minutes=20)])
def test_a_guest_poweroff_without_a_recent_ack_is_not_proven(age) -> None:
    acked = timezone.now() - age if age is not None else None
    vm = _vm(on_guest_poweroff="stop", power_guest_ack_at=acked)
    assert power_policy.settle_guest_poweroff(vm)
    vm.refresh_from_db()
    assert vm.stopped_by_guest
    assert vm.power_stop_proof is None


def test_an_ack_from_before_the_current_boot_is_not_a_proof() -> None:
    now = timezone.now()
    vm = _vm(
        on_guest_poweroff="stop",
        power_guest_ack_at=now - timedelta(minutes=2),
        power_state_at=now - timedelta(minutes=1),
    )
    assert power_policy.settle_guest_poweroff(vm)
    vm.refresh_from_db()
    assert vm.power_stop_proof is None


def test_settle_refuses_a_restart_vm_or_one_not_running() -> None:
    assert not power_policy.settle_guest_poweroff(_vm("vm-r"))
    assert not power_policy.settle_guest_poweroff(
        _vm("vm-s", on_guest_poweroff="stop", power_state=VmPowerState.STOPPED)
    )
