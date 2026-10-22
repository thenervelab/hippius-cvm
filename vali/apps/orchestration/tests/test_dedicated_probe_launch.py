"""R3 on the launch path: a dedicated-disk probe VM's disks reach its
launch order as `extra_disks` and its measured cmdline as
`hippius.dedicated=` — always together, the same slots — only from its own
run, only while the run holds them `probing` on that node; the intake
reserves `probe_extra_disks` to that run. The run and the state machine:
`apps/disktier/tests/test_dedicated_probe.py`."""

from __future__ import annotations

import secrets
from typing import Any

import pytest
from django.test import override_settings
from django.utils import timezone

from apps.disktier import dedicated, dedicated_probe
from apps.disktier.dedicated import GIB
from apps.disktier.models import (
    DedicatedDisk,
    DedicatedDiskState,
    DiskProbeRun,
    ProbeRunState,
    ProbeTrigger,
)
from apps.disktier.tests.dedicated_helpers import AGENT_MIN, capable
from apps.lifecycle.models import Vm
from apps.orchestration import launch_jobs
from apps.orchestration.services import launch

from .test_dedicated_launch import _assert_order_matches_cmdline, _rig, _spec

pytestmark = pytest.mark.django_db

VM = "vm-launch-1"


def _probe_run(node: str, sizes: tuple[int, ...] = (22354, 16050)) -> DiskProbeRun:
    """A dedicated run on `node` holding one disk per size, `probing`."""
    run = DiskProbeRun.objects.create(
        nonce=secrets.token_bytes(32),
        vm_id=VM,
        miner_node_id=node,
        chip_id="ab" * 32,
        owner="4242",
        trigger=ProbeTrigger.DECLARED,
        state=ProbeRunState.LAUNCHING,
        flavor="medium",
        os_pool_id="default",
        start_delay_s=300,
        targets=[],
        scheduled_at=timezone.now(),
    )
    targets = []
    for i, size in enumerate(sizes):
        disk = DedicatedDisk.objects.create(
            miner_node_id=node,
            disk_id=f"wwn-0x0{i}",
            size_bytes=size * GIB,
            state=DedicatedDiskState.PROBING,
            last_probe=run,
        )
        targets.append(
            {
                "slot": f"x{i}",
                "kind": "dedicated",
                "disk_pk": str(disk.pk),
                "disk_id": disk.disk_id,
                "size_bytes": size * GIB,
                "size_gb": dedicated.size_class_gb(size * GIB),
                "origin": "declared",
                "profile": "d1",
            }
        )
    run.targets = targets
    run.save(update_fields=["targets"])
    return run


def _probe_spec(run: DiskProbeRun) -> launch.LaunchSpec:
    return _spec(vm_id=VM, probe_extra_disks=dedicated_probe.intent_disks(run))


@override_settings(VALI_DEDICATED_MIN_AGENT_VERSION=AGENT_MIN)
def test_the_probe_order_names_its_disks_and_the_cmdline_measures_them(monkeypatch) -> None:
    miner, seen = _rig(monkeypatch)
    capable(miner.chain_node_id)
    run = _probe_run(miner.chain_node_id)
    out = launch.launch_on_miner(_probe_spec(run), miner)
    assert out.disposition == launch.ACCEPTED, out.emit
    (payload,) = seen["payload"]
    assert payload["extra_disks"] == [
        {"slot": "x0", "kind": "dedicated", "disk_id": "wwn-0x00"},
        {"slot": "x1", "kind": "dedicated", "disk_id": "wwn-0x01"},
    ]
    assert "hippius.dedicated=x0:22300,x1:16000" in payload["cmdline"].split()
    assert seen["preflight"] == [payload["cmdline"]]
    assert seen["recompute"] == [payload["cmdline"]]
    _assert_order_matches_cmdline(payload)
    # The probe VM pays 0 dedicated GiB: it was sold none.
    from apps.scheduler.models import VmBillingBinding

    assert VmBillingBinding.objects.get(vm_id=VM).dedicated_gb == 0
    # Never assigned: the disks stay the run's.
    assert set(DedicatedDisk.objects.values_list("state", flat=True)) == {"probing"}
    assert not DedicatedDisk.objects.filter(assigned_vm__isnull=False).exists()
    # A probe VM with disks is pinned (no migration, failover, backup).
    vm = Vm.objects.get(vm_id=VM)
    assert dedicated.is_pinned(vm) is False  # no launch job row in this rig
    monkeypatch.setattr(
        "apps.scheduler.service._launch_spec",
        lambda vm_id: {"probe_extra_disks": dedicated_probe.intent_disks(run)},
    )
    assert dedicated.is_pinned(vm) is True


@pytest.mark.parametrize(
    "break_it",
    [
        "not-probing",
        "other-run",
        "other-node",
        "assigned",
        "run-closed",
        "spec-mismatch",
        "pool-run",
    ],
)
@override_settings(VALI_DEDICATED_MIN_AGENT_VERSION=AGENT_MIN)
def test_a_disk_the_run_does_not_hold_is_never_sent(monkeypatch, break_it: str) -> None:
    miner, seen = _rig(monkeypatch)
    capable(miner.chain_node_id)
    run = _probe_run(miner.chain_node_id)
    spec = _probe_spec(run)
    first = DedicatedDisk.objects.get(disk_id="wwn-0x00")
    if break_it == "not-probing":
        DedicatedDisk.objects.filter(pk=first.pk).update(state=DedicatedDiskState.FREE)
    elif break_it == "other-run":
        other = DiskProbeRun.objects.create(
            nonce=secrets.token_bytes(32),
            vm_id="vm-other",
            miner_node_id=run.miner_node_id,
            owner="4242",
            trigger=ProbeTrigger.DECLARED,
            flavor="medium",
            scheduled_at=timezone.now(),
        )
        DedicatedDisk.objects.filter(pk=first.pk).update(last_probe=other)
    elif break_it == "other-node":
        DedicatedDisk.objects.filter(pk=first.pk).update(miner_node_id="ff" * 32)
    elif break_it == "assigned":
        vm = Vm.objects.create(
            vm_id="vm-tenant", tenant_id="t", state="active", host="", generation=1
        )
        DedicatedDisk.objects.filter(pk=first.pk).update(
            state=DedicatedDiskState.ASSIGNED, assigned_vm=vm, assigned_slot="x0"
        )
    elif break_it == "run-closed":
        DiskProbeRun.objects.filter(pk=run.pk).update(torn_down_at=timezone.now())
    elif break_it == "spec-mismatch":
        spec = _spec(
            vm_id=VM,
            probe_extra_disks=[{"slot": "x0", "disk_id": "wwn-0xstolen", "size_gb": 22300}],
        )
    elif break_it == "pool-run":
        DiskProbeRun.objects.filter(pk=run.pk).update(trigger=ProbeTrigger.ONBOARDING)
    out = launch.launch_on_miner(spec, miner)
    assert out.disposition == launch.TERMINAL
    assert out.emit["outcome"] == launch.DEDICATED_DISKS_UNAVAILABLE
    assert seen["payload"] == [] and seen["preflight"] == []


def test_an_agent_without_extra_disks_gets_no_probe_order(monkeypatch) -> None:
    miner, seen = _rig(monkeypatch)
    capable(miner.chain_node_id, version="v2020.01.01")
    run = _probe_run(miner.chain_node_id)
    with override_settings(VALI_DEDICATED_MIN_AGENT_VERSION=AGENT_MIN):
        out = launch.launch_on_miner(_probe_spec(run), miner)
    assert out.emit["outcome"] == launch.DEDICATED_DISKS_UNAVAILABLE
    assert seen["payload"] == []


def test_the_pre_pin_check_measures_the_probe_disks() -> None:
    run_disks = [
        {"slot": "x0", "disk_id": "wwn-0x00", "size_gb": 22300},
        {"slot": "x1", "disk_id": "wwn-0x01", "size_gb": 16000},
    ]
    spec = _spec(vm_id=VM, probe_extra_disks=run_disks)
    assert launch._pre_pin_dedicated_value(spec) == "x0:22300,x1:16000"
    assert launch._pre_pin_dedicated_value(_spec(vm_id=VM)) is None


# ── intake ───────────────────────────────────────────────────────────


def test_only_the_runs_own_launch_may_name_probe_disks() -> None:
    run = _probe_run("aa" * 32)
    disks = dedicated_probe.intent_disks(run)
    # Any other launch: refused, whoever calls.
    with pytest.raises(launch_jobs.LaunchIntentError) as exc:
        launch_jobs._check_probe_disks({"probe_extra_disks": disks}, None)
    assert exc.value.category == launch_jobs.CATEGORY_PROBE_DISKS_RESERVED
    launch_jobs._check_probe_disks({}, None)
    # The run's own launch: exactly its disks, nothing else.
    launch_jobs._check_probe_disks({"probe_extra_disks": disks}, run)
    for bad in (None, [], disks[:1], list(reversed(disks)), [{**disks[0], "size_gb": 99999}]):
        with pytest.raises(launch_jobs.LaunchIntentError):
            launch_jobs._check_probe_disks({"probe_extra_disks": bad}, run)
    # A pool run names none.
    DiskProbeRun.objects.filter(pk=run.pk).update(
        trigger=ProbeTrigger.ONBOARDING,
        targets=[{"slot": "os", "kind": "pool", "pool_id": "default", "profile": "v1"}],
    )
    run.refresh_from_db()
    launch_jobs._check_probe_disks({}, run)
    with pytest.raises(launch_jobs.LaunchIntentError):
        launch_jobs._check_probe_disks({"probe_extra_disks": disks}, run)


def test_the_spec_keeps_the_probe_disks_only_when_set() -> None:
    from .test_launch_api import _intent

    golden: dict[str, Any] = dict(
        disk_mode="golden_verity_overlay",
        verity_root_hash_hex="e" * 64,
        rootfs_img_sha256_hex="b" * 64,
        rootfs_verity_sha256_hex="c" * 64,
    )
    intent = {**_intent(), **golden}
    assert "probe_extra_disks" not in launch_jobs._build_spec_json(dict(intent))
    disks = [{"slot": "x0", "disk_id": "wwn-0x00", "size_gb": 22300}]
    spec = launch_jobs._build_spec_json({**intent, "probe_extra_disks": disks})
    assert spec["probe_extra_disks"] == disks
    launch.LaunchSpec(**spec, kek_bytes=None, userdata=b"")  # the worker rebuilds it
