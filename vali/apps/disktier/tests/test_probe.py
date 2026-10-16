"""The disk-tier probe orchestrator (`apps.disktier.probe`, phase R1): the
due set and its order, the node gates, run creation and the request it
carries, the launch-job transitions, the timeout, the teardown on every
terminal path, the flag, record-only, the metrics and the command."""

from __future__ import annotations

import json
import re
from datetime import timedelta
from pathlib import Path
from typing import Any

import pytest
import yaml
from django.core.management import call_command
from django.core.management.base import CommandError

from apps.disktier import probe, probe_userdata
from apps.disktier.classify import PROFILE_D1, PROFILE_V1
from apps.disktier.models import (
    DiskProbeRun,
    MinerStoragePool,
    ProbeRunState,
    ProbeTrigger,
)
from apps.lifecycle.models import Vm, VmState
from apps.orchestration.models import DecommissionJob, LaunchJob, LaunchJobState

from .probe_helpers import (
    CHIP,
    NODE,
    NODE2,
    NODE3,
    NOW,
    OWNER,
    TENANT,
    USER,
    FakeIntake,
    gates,
    make_run,
)

pytestmark = pytest.mark.django_db

DAY = timedelta(days=1)


def _due(nodes: tuple[str, ...] = (NODE,), now=NOW) -> tuple[list[probe.Due], probe.TickReport]:
    report = probe.TickReport(enabled=True)
    return probe.due_set(nodes=nodes, now=now, report=report), report


def _pool(node: str, pool_id: str, **kw: Any) -> MinerStoragePool:
    return MinerStoragePool.objects.create(miner_node_id=node, pool_id=pool_id, **kw)


# ─── the flag ────────────────────────────────────────────────────────


def test_flag_off_does_nothing(settings: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    from apps.orchestration import launch_jobs

    settings.VALI_DISK_PROBE_ENABLED = False
    settings.VALI_DISK_PROBE_OWNERS = [OWNER]
    intake = FakeIntake()
    monkeypatch.setattr(launch_jobs, "start_launch", intake)

    def no_gates(flavor: str) -> None:
        raise AssertionError("the scheduler is not read while the probe is off")

    monkeypatch.setattr(probe, "_gates", no_gates)
    report = probe.tick(now=NOW)
    assert report.enabled is False
    assert intake.calls == []
    assert not DiskProbeRun.objects.exists()
    assert not LaunchJob.objects.exists()


def test_flag_off_still_tears_down_a_run_left_in_flight(
    settings: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Turning the probe off never strands a probe VM."""
    settings.VALI_DISK_PROBE_ENABLED = False
    run = make_run(
        state=ProbeRunState.VERIFIED, finished_at=NOW - DAY, teardown_after=NOW - DAY
    )
    Vm.objects.create(
        vm_id=run.vm_id, lease_id=run.vm_id, state=VmState.ACTIVE, generation=1,
        host="host-a", lifecycle_vk=bytes(32),
    )
    report = probe.tick(now=NOW)
    assert report.enabled is False
    assert DecommissionJob.objects.filter(vm__vm_id=run.vm_id).count() == 1
    run.refresh_from_db()
    assert run.teardown_started_at == NOW


def test_the_command_pushes_nothing_while_off(
    settings: Any, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    from apps.synthetic import metrics

    settings.VALI_DISK_PROBE_ENABLED = False

    def no_push(*a: Any, **kw: Any) -> bool:
        raise AssertionError("no push while the probe is off")

    monkeypatch.setattr(metrics, "push", no_push)
    call_command("vali_disk_probe")
    assert "enabled=False" in capsys.readouterr().out
    with pytest.raises(CommandError, match="off"):
        call_command("vali_disk_probe", "--request", NODE)


# ─── the due set ─────────────────────────────────────────────────────


def test_never_probed_first_then_periodic_then_queued(settings: Any) -> None:
    settings.VALI_DISK_PROBE_PERIOD_JITTER_S = 0
    # NODE2: verified 9 days ago (overdue 2 d); NODE3: verified yesterday.
    make_run(node=NODE2, state=ProbeRunState.VERIFIED, finished_at=NOW - 9 * DAY,
             torn_down_at=NOW - 9 * DAY, scheduled_at=NOW - 10 * DAY)
    make_run(node=NODE3, state=ProbeRunState.VERIFIED, finished_at=NOW - DAY,
             torn_down_at=NOW - DAY, scheduled_at=NOW - 2 * DAY)
    queued = make_run(node=node_four(), state=ProbeRunState.SCHEDULED,
                      trigger=ProbeTrigger.MANUAL, scheduled_at=NOW - timedelta(hours=1))
    due, _ = _due((NODE, NODE2, NODE3))
    assert [(d.node_id, d.trigger) for d in due] == [
        (NODE, ProbeTrigger.ONBOARDING),
        (NODE2, ProbeTrigger.PERIODIC),
        (node_four(), ProbeTrigger.MANUAL),
    ]
    assert due[-1].run == queued


def node_four() -> str:
    from apps.scheduler.tests.factories import node_id

    return node_id(4)


def test_periodic_waits_period_plus_its_own_jitter(settings: Any) -> None:
    settings.VALI_DISK_PROBE_PERIOD_JITTER_S = 2 * 86400
    run = make_run(state=ProbeRunState.VERIFIED, finished_at=NOW, torn_down_at=NOW)
    jitter = probe._period_jitter_s(run)
    assert -2 * 86400 <= jitter <= 2 * 86400
    assert probe._period_jitter_s(run) == jitter  # fixed per run
    due_at = NOW + timedelta(seconds=7 * 86400 + jitter)
    assert _due(now=due_at - timedelta(seconds=1))[0] == []
    (item,) = _due(now=due_at)[0]
    assert item.trigger == ProbeTrigger.PERIODIC


def test_jitter_spreads_over_the_window(settings: Any) -> None:
    settings.VALI_DISK_PROBE_PERIOD_JITTER_S = 2 * 86400
    values = {probe._period_jitter_s(make_run(state=ProbeRunState.VERIFIED)) for _ in range(20)}
    assert len(values) > 10
    assert any(v < 0 for v in values) and any(v > 0 for v in values)


@pytest.mark.parametrize("state", [ProbeRunState.FAILED, ProbeRunState.TIMEOUT])
def test_a_failed_attempt_backs_off_before_the_next(state: str) -> None:
    make_run(state=state, finished_at=NOW - timedelta(hours=23), torn_down_at=NOW)
    assert _due()[0] == []
    (item,) = _due(now=NOW + timedelta(hours=2))[0]
    assert item.trigger == ProbeTrigger.ONBOARDING


def test_a_refused_launch_backs_off_too() -> None:
    make_run(state=ProbeRunState.TORN_DOWN, torn_down_at=NOW - timedelta(hours=1),
             failure_reason="launch-refused:bad-field")
    assert _due()[0] == []


def test_a_run_in_flight_is_not_history() -> None:
    """An open run makes its node busy (decided at launch), it does not
    count as an attempt."""
    make_run(state=ProbeRunState.RUNNING)
    (item,) = _due()[0]
    assert item.trigger == ProbeTrigger.ONBOARDING


# ─── pools ───────────────────────────────────────────────────────────


def test_the_os_pool_is_default_today() -> None:
    """TODO(A4): a probe of pool P launches its OS disk on P once the order
    carries `os_pool`; until then only `default` can be probed."""
    assert probe.probe_os_pool("default") == "default"
    assert probe.probe_os_pool("fast") is None


def test_a_node_without_a_storage_report_has_the_implicit_default_pool() -> None:
    (item,) = _due()[0]
    assert item.pool_id == "default"


def test_only_os_eligible_active_pools_are_probed() -> None:
    _pool(NODE, "default", os_disks=True, reported_state="active")
    _pool(NODE, "fast", os_disks=True, reported_state="active")
    _pool(NODE, "bulk", os_disks=False, reported_state="active", declared_class="hdd")
    _pool(NODE, "gone", os_disks=True, retired_at=NOW)
    due, report = _due()
    assert [(d.node_id, d.pool_id) for d in due] == [(NODE, "default")]
    assert report.skipped["needs-os-pool-order"] == 1
    assert report.skipped["not-os-eligible"] == 1


def test_a_draining_default_pool_is_not_probed() -> None:
    _pool(NODE, "default", os_disks=True, reported_state="draining")
    due, report = _due()
    assert due == []
    assert report.skipped["pool-not-active"] == 1


def test_a_node_reporting_pools_without_default_is_skipped() -> None:
    _pool(NODE, "fast", os_disks=True)
    due, report = _due()
    assert due == []
    assert report.skipped["os-pool-unavailable"] == 1


# ─── node gates and concurrency ──────────────────────────────────────


@pytest.mark.parametrize(
    ("g", "reason"),
    [
        (gates(eligible=(), dispatchable=(NODE,)), "gated"),
        (gates(free={NODE: 1}), "capacity"),
        (gates(booting={NODE: 3}, fleet_cap=3), "boot-cap"),
        (gates(booting={NODE: 1}, caps={NODE: 1}), "boot-cap"),
        (gates(chips={NODE: ""}), "no-chip-id"),
    ],
)
def test_a_node_is_skipped_at_capacity_boot_cap_or_gated(
    probe_on: FakeIntake, monkeypatch: pytest.MonkeyPatch, g: probe._Gates, reason: str
) -> None:
    monkeypatch.setattr(probe, "_gates", lambda flavor: g)
    report = probe.tick(now=NOW)
    assert report.skipped[reason] == 1
    assert report.launched == 0
    assert probe_on.calls == []
    assert not DiskProbeRun.objects.exists()


def test_a_boot_cap_of_zero_is_no_cap(probe_on: FakeIntake, monkeypatch) -> None:
    monkeypatch.setattr(probe, "_gates", lambda flavor: gates(booting={NODE: 5}, fleet_cap=0))
    assert probe.tick(now=NOW).launched == 1


def test_one_probe_per_miner(probe_on: FakeIntake) -> None:
    make_run(state=ProbeRunState.VERIFIED, finished_at=NOW, teardown_after=NOW + DAY)
    # Verified but not torn down yet: its VM still holds the node.
    report = probe.tick(now=NOW)
    assert report.launched == 0
    assert probe_on.calls == []


def test_a_queued_request_blocks_the_automatic_probe_of_its_node(probe_on: FakeIntake) -> None:
    queued = make_run(state=ProbeRunState.SCHEDULED, trigger=ProbeTrigger.MANUAL)
    report = probe.tick(now=NOW)
    assert report.skipped["busy"] == 1
    assert report.launched == 1
    (call,) = probe_on.calls
    assert call["intent"]["vm_id"] == queued.vm_id


def test_never_two_launched_runs_on_one_node(probe_on: FakeIntake) -> None:
    """Queued runs bypass the automatic due set, never the 1-per-miner rule."""
    make_run(state=ProbeRunState.SCHEDULED, trigger=ProbeTrigger.MANUAL)
    make_run(state=ProbeRunState.SCHEDULED, trigger=ProbeTrigger.PERIODIC)
    report = probe.tick(now=NOW)
    assert report.launched == 1
    assert report.skipped["busy"] == 2  # the onboarding item and the 2nd queued run


def test_a_queued_run_waits_for_its_nodes_running_probe(probe_on: FakeIntake) -> None:
    make_run(state=ProbeRunState.RUNNING)
    make_run(state=ProbeRunState.SCHEDULED, trigger=ProbeTrigger.MANUAL)
    assert probe.tick(now=NOW).launched == 0
    assert probe_on.calls == []


def test_the_fleet_wide_cap(probe_on: FakeIntake, settings: Any, monkeypatch) -> None:
    settings.VALI_DISK_PROBE_MAX_CONCURRENT = 2
    monkeypatch.setattr(probe, "_gates", lambda flavor: gates(eligible=(NODE, NODE2, NODE3)))
    make_run(node=node_four(), state=ProbeRunState.RUNNING)
    report = probe.tick(now=NOW)
    assert report.launched == 1
    assert report.skipped["concurrency"] == 2
    assert DiskProbeRun.objects.filter(state=ProbeRunState.LAUNCHING).count() == 1


def test_the_real_gates_read_the_scheduler(settings: Any) -> None:
    """`_gates` over a real dispatchable miner: eligible, its chip, the
    free slots of the probe flavor."""
    from apps.scheduler.models import MinerCapacity
    from apps.scheduler.tests.factories import make_dispatchable_identity, node_id

    make_dispatchable_identity(1)
    from django.utils import timezone

    MinerCapacity.objects.create(
        miner_node_id=node_id(1), status="active", capacity_slots=8,
        observed_epoch=10, data_epoch=10, refreshed_at=timezone.now(),
    )
    g = probe._gates("medium")
    assert node_id(1) in g.eligible
    assert g.chip_by_node[node_id(1)]
    assert node_id(1) in g.free_by_node
    assert g.booting == {}


# ─── run creation, the request, the intent ───────────────────────────


def test_a_launch_creates_a_fresh_run_and_launches_it_pinned(
    probe_on: FakeIntake, settings: Any
) -> None:
    report = probe.tick(now=NOW)
    assert report.launched == 1
    run = DiskProbeRun.objects.get()
    assert run.state == ProbeRunState.LAUNCHING
    assert run.trigger == ProbeTrigger.ONBOARDING
    assert run.owner == USER
    assert re.fullmatch(rf"hipc-{USER}-[0-9a-f]{{8}}", run.vm_id)
    assert len(bytes(run.nonce)) == 32
    assert run.flavor == "medium"
    assert run.os_pool_id == "default"
    assert run.targets == [{"slot": "os", "kind": "pool", "pool_id": "default", "profile": "v1"}]
    assert 6 * 3600 <= run.start_delay_s <= 48 * 3600
    assert run.launched_at == NOW
    # The launch window first; re-armed from boot once the launch succeeds.
    assert run.deadline_at == NOW + timedelta(seconds=settings.VALI_DISK_PROBE_LAUNCH_TIMEOUT_S)
    job = LaunchJob.objects.get(vm_id=run.vm_id)
    assert run.launch_job_id == job.job_id

    (call,) = probe_on.calls
    assert call["disk_probe"] is True
    intent = call["intent"]
    assert intent["platform_id"] == CHIP
    assert intent["tenant_id"] == TENANT and intent["user_id"] == USER
    assert intent["vm_id"] == intent["lease_id"] == run.vm_id
    assert intent["flavor"] == "medium"
    assert intent["image"] == "ubuntu"
    assert intent["cmdline"] == "console=ttyS0 root=/dev/vda"
    assert intent["enable_netbird"] is True and intent["auto_pin_allowlist"] is True


def test_every_run_gets_its_own_nonce_and_run_id(probe_on: FakeIntake, monkeypatch) -> None:
    monkeypatch.setattr(probe, "_gates", lambda flavor: gates(eligible=(NODE, NODE2, NODE3)))
    probe.tick(now=NOW)
    runs = list(DiskProbeRun.objects.all())
    assert len(runs) == 3
    assert len({bytes(r.nonce) for r in runs}) == 3
    assert len({r.run_id for r in runs}) == 3
    assert len({r.vm_id for r in runs}) == 3


def test_the_userdata_carries_the_request_and_no_root_path(probe_on: FakeIntake) -> None:
    probe.tick(now=NOW)
    run = DiskProbeRun.objects.get()
    (call,) = probe_on.calls
    raw: bytes = call["userdata"]
    doc = yaml.safe_load(
        raw.replace(b"{{NETBIRD_SETUP_KEY}}", b"k").replace(b"{{NETBIRD_HOSTNAME}}", b"h")
    )
    assert doc["users"] == [] and doc["ssh_pwauth"] is False
    assert "ssh_authorized_keys" not in doc
    files = {f["path"]: f for f in doc["write_files"]}
    req = files["/run/hippius/disk-probe/request.json"]
    assert req["permissions"] == "0600"
    body = json.loads(req["content"])
    # Exactly the guest's closed wire shape (`request.rs`, deny_unknown_fields).
    assert set(body) == {"vm_id", "run_id", "nonce", "start_delay_s", "targets"}
    assert body["vm_id"] == run.vm_id
    assert body["run_id"] == run.run_id.hex and len(body["run_id"]) == 32
    assert body["nonce"] == bytes(run.nonce).hex() and len(body["nonce"]) == 64
    assert body["start_delay_s"] == run.start_delay_s
    assert body["targets"] == [{"slot": "os", "profile": "v1"}]
    # The unit is started after write_files (the boot-order gap).
    assert doc["runcmd"][0] == ["systemctl", "start", "--no-block", "hippius-disk-probe.service"]
    assert b"{{NETBIRD_SETUP_KEY}}" in raw


def test_the_userdata_without_netbird() -> None:
    raw = probe_userdata.render(
        probe_userdata.request_json(
            vm_id="hipc-1-aa", run_id_hex="0" * 32, nonce=b"\1" * 32, start_delay_s=0,
            slots=("os",),
        ),
        netbird=False,
    )
    assert b"NETBIRD" not in raw and b"netbird" not in raw
    assert yaml.safe_load(raw)["runcmd"] == [
        ["systemctl", "start", "--no-block", "hippius-disk-probe.service"]
    ]


def test_the_start_delay_stays_in_its_bounds(settings: Any) -> None:
    samples = [probe.start_delay_s() for _ in range(500)]
    assert min(samples) >= 6 * 3600 and max(samples) <= 48 * 3600
    assert len(set(samples)) > 400
    settings.VALI_DISK_PROBE_START_DELAY_MIN_S = 10
    settings.VALI_DISK_PROBE_START_DELAY_MAX_S = 10
    assert probe.start_delay_s() == 10


@pytest.mark.parametrize(
    ("kw", "match"),
    [
        ({"start_delay_s": 72 * 3600 + 1}, "start_delay_s"),
        ({"slots": ("os", "os")}, "targets"),
        ({"slots": ("x24",)}, "targets"),
        ({"slots": ()}, "targets"),
        ({"nonce": b"\1" * 31}, "nonce"),
        ({"vm_id": "Hipc/../x"}, "vm id"),
    ],
)
def test_a_request_the_guest_would_refuse_is_never_rendered(kw: dict, match: str) -> None:
    args: dict[str, Any] = {
        "vm_id": "hipc-1-aa", "run_id_hex": "0" * 32, "nonce": b"\1" * 32,
        "start_delay_s": 0, "slots": ("os",),
    }
    args.update(kw)
    with pytest.raises(probe_userdata.ProbeUserdataError, match=match):
        probe_userdata.request_json(**args)


def test_dedicated_slots_render_d1() -> None:
    body = json.loads(
        probe_userdata.request_json(
            vm_id="hipc-1-aa", run_id_hex="0" * 32, nonce=b"\1" * 32, start_delay_s=0,
            slots=("x1", "os", "x0"),
        )
    )
    assert body["targets"] == [
        {"slot": "os", "profile": "v1"},
        {"slot": "x0", "profile": "d1"},
        {"slot": "x1", "profile": "d1"},
    ]


def test_no_owner_configured_launches_nothing(probe_on: FakeIntake, settings: Any) -> None:
    settings.VALI_DISK_PROBE_OWNERS = []
    report = probe.tick(now=NOW)
    assert report.skipped["no-probe-owner"] == 1
    assert probe_on.calls == []


def test_an_image_without_the_probe_release_launches_nothing(
    probe_on: FakeIntake, settings: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    from django.utils import timezone

    from apps.images.models import GoldenImage

    monkeypatch.undo()  # the real `_image_ready`
    from apps.orchestration import launch_jobs

    monkeypatch.setattr(launch_jobs, "start_launch", probe_on)
    monkeypatch.setattr(probe, "_gates", lambda flavor: gates())
    settings.VALI_DISK_PROBE_ENABLED = True
    settings.VALI_DISK_PROBE_MIN_GUEST_RELEASE = 4
    assert probe.tick(now=NOW).skipped["image-not-ready"] == 1  # not blessed
    GoldenImage.objects.create(
        image_name="ubuntu", distro="ubuntu", bake_id="b-1", blessed_at=timezone.now(),
        guest_release=4,
    )
    settings.VALI_DISK_PROBE_MIN_GUEST_RELEASE = 0  # unset: refused
    assert probe.tick(now=NOW).skipped["image-not-ready"] == 1
    settings.VALI_DISK_PROBE_MIN_GUEST_RELEASE = 5
    assert probe.tick(now=NOW).skipped["image-not-ready"] == 1
    settings.VALI_DISK_PROBE_MIN_GUEST_RELEASE = 4
    assert probe.tick(now=NOW).launched == 1


def test_a_refused_launch_closes_the_run(probe_on: FakeIntake) -> None:
    probe_on.refuse = "bad-field"
    report = probe.tick(now=NOW)
    assert report.refused == 1 and report.launched == 0
    run = DiskProbeRun.objects.get()
    assert run.state == ProbeRunState.TORN_DOWN
    assert run.failure_reason == "launch-refused:bad-field"
    assert run.torn_down_at == NOW
    # The pool is retried after the back-off, not every tick.
    probe_on.refuse = ""
    assert probe.tick(now=NOW + timedelta(minutes=15)).launched == 0


def test_an_operator_request(probe_on: FakeIntake) -> None:
    from apps.scheduler.tests.factories import make_dispatchable_identity, node_id

    make_dispatchable_identity(1)
    make_dispatchable_identity(2)
    run = probe.request_manual(node_id(1), now=NOW)
    assert run.state == ProbeRunState.SCHEDULED and run.trigger == ProbeTrigger.MANUAL
    with pytest.raises(ValueError, match="this period"):
        probe.request_manual(node_id(1), now=NOW)
    make_run(node=node_id(2), state=ProbeRunState.RUNNING)
    with pytest.raises(ValueError, match="in flight"):
        probe.request_manual(node_id(2), now=NOW)
    with pytest.raises(ValueError, match="chip"):
        probe.request_manual(node_id(9), now=NOW)
    DiskProbeRun.objects.filter(pk=run.pk).update(
        state=ProbeRunState.VERIFIED, torn_down_at=NOW
    )
    with pytest.raises(ValueError, match="this period"):
        probe.request_manual(node_id(1), now=NOW + 6 * DAY)
    probe.request_manual(node_id(1), now=NOW + 8 * DAY)


# ─── launch → running → verdict, the timeout ─────────────────────────


def _job(run: DiskProbeRun, state: str, reason: str = "") -> LaunchJob:
    job = LaunchJob.objects.get(vm_id=run.vm_id)
    LaunchJob.objects.filter(pk=job.pk).update(state=state, reason=reason, finished_at=NOW)
    return job


def test_the_launch_job_drives_the_run(probe_on: FakeIntake, settings: Any) -> None:
    probe.tick(now=NOW)
    run = DiskProbeRun.objects.get()
    job = _job(run, LaunchJobState.SUCCEEDED.value)
    report = probe.tick(now=NOW + timedelta(minutes=15))
    assert report.transitions["running"] == 1
    run.refresh_from_db()
    assert run.state == ProbeRunState.RUNNING
    # Re-armed from the launch's success: the guest's delay runs from boot.
    job.refresh_from_db()
    assert run.deadline_at == job.finished_at + timedelta(
        seconds=run.start_delay_s + settings.VALI_DISK_PROBE_TIMEOUT_S
    )


def test_a_slow_launch_is_not_a_probe_timeout(probe_on: FakeIntake, settings: Any) -> None:
    """A launch that waited past its window but then succeeded runs on."""
    probe.tick(now=NOW)
    run = DiskProbeRun.objects.get()
    late = NOW + timedelta(seconds=settings.VALI_DISK_PROBE_LAUNCH_TIMEOUT_S + 60)
    job = LaunchJob.objects.get(vm_id=run.vm_id)
    LaunchJob.objects.filter(pk=job.pk).update(
        state=LaunchJobState.SUCCEEDED.value, finished_at=late
    )
    probe.tick(now=late)
    run.refresh_from_db()
    assert run.state == ProbeRunState.RUNNING


def test_a_launch_stuck_past_its_window_times_out(probe_on: FakeIntake, settings: Any) -> None:
    probe.tick(now=NOW)
    run = DiskProbeRun.objects.get()
    # Claimed by the launch worker, never finished (the miner preflight).
    LaunchJob.objects.filter(vm_id=run.vm_id).update(state=LaunchJobState.RUNNING.value)
    late = NOW + timedelta(seconds=settings.VALI_DISK_PROBE_LAUNCH_TIMEOUT_S)
    report = probe.tick(now=late)
    assert report.transitions["timeout"] == 1
    run.refresh_from_db()
    assert run.state == ProbeRunState.TIMEOUT
    assert run.failure_reason == "launch-timeout"
    assert run.teardown_after == late


@pytest.mark.parametrize("enabled", [True, False])
def test_a_run_whose_tick_died_after_the_intake_is_adopted(
    probe_on: FakeIntake, settings: Any, enabled: bool
) -> None:
    """The intake committed the job, the tick died before its own update:
    the run is still `scheduled`. The next tick adopts it (flag on or off),
    so the VM is followed and torn down, never stranded."""
    from apps.orchestration.tests.factories import make_service_client

    run = make_run(state=ProbeRunState.SCHEDULED, scheduled_at=NOW - timedelta(minutes=5))
    LaunchJob.objects.create(
        job_id="j-crash", vm_id=run.vm_id, tenant_id=TENANT, flavor="medium",
        spec_json={"vm_id": run.vm_id}, userdata_vault_path="x", userdata_vault_version=1,
        kek_vault_path="x", state=LaunchJobState.RUNNING.value, phase_started_at=NOW,
        decided_by=make_service_client(),
    )
    settings.VALI_DISK_PROBE_ENABLED = enabled
    report = probe.tick(now=NOW)
    assert report.transitions["adopted"] == 1
    run.refresh_from_db()
    assert run.state == ProbeRunState.LAUNCHING and run.launch_job_id == "j-crash"
    assert probe_on.calls == []  # never launched twice


def test_an_old_queued_request_expires(probe_on: FakeIntake, settings: Any) -> None:
    run = make_run(state=ProbeRunState.SCHEDULED, trigger=ProbeTrigger.MANUAL,
                   scheduled_at=NOW - timedelta(seconds=settings.VALI_DISK_PROBE_QUEUE_TTL_S))
    probe.tick(now=NOW)
    run.refresh_from_db()
    assert run.state == ProbeRunState.TORN_DOWN and run.failure_reason == "request-expired"


def test_an_internal_intake_failure_retries_the_same_vm_id(
    probe_on: FakeIntake, settings: Any
) -> None:
    """A Vault hiccup must not strand the KEK the intake may have staged:
    the next tick retries the same run and vm id (first-write-wins KEK)."""
    probe_on.refuse = "internal"
    probe.tick(now=NOW)
    run = DiskProbeRun.objects.get()
    assert run.state == ProbeRunState.SCHEDULED
    assert run.failure_reason == "launch-retry:internal"
    probe_on.refuse = ""
    probe.tick(now=NOW + timedelta(minutes=15))
    assert [c["intent"]["vm_id"] for c in probe_on.calls] == [run.vm_id, run.vm_id]
    run.refresh_from_db()
    assert run.state == ProbeRunState.LAUNCHING and run.failure_reason == ""


def test_internal_failures_give_up_after_the_launch_window(
    probe_on: FakeIntake, settings: Any
) -> None:
    probe_on.refuse = "internal"
    probe.tick(now=NOW)
    later = NOW + timedelta(seconds=settings.VALI_DISK_PROBE_LAUNCH_TIMEOUT_S)
    probe.tick(now=later)
    run = DiskProbeRun.objects.get()
    assert run.state == ProbeRunState.TORN_DOWN
    assert run.failure_reason == "launch-refused:internal"


def test_a_failed_launch_fails_the_run_and_tears_it_down(probe_on: FakeIntake) -> None:
    probe.tick(now=NOW)
    run = DiskProbeRun.objects.get()
    _job(run, LaunchJobState.FAILED.value, "no-eligible-miner")
    later = NOW + timedelta(minutes=15)
    report = probe.tick(now=later)
    assert report.transitions["launch-failed"] == 1
    run.refresh_from_db()
    assert run.state == ProbeRunState.FAILED
    assert run.failure_reason == "launch-failed:no-eligible-miner"
    assert run.teardown_after == later
    # No VM row and no live job: closed by the same tick.
    assert run.torn_down_at == later


def test_timeout_then_teardown(probe_on: FakeIntake) -> None:
    run = make_run(state=ProbeRunState.RUNNING, deadline_at=NOW - timedelta(seconds=1))
    Vm.objects.create(
        vm_id=run.vm_id, lease_id=run.vm_id, state=VmState.ACTIVE, generation=1,
        host="host-a", lifecycle_vk=bytes(32),
    )
    report = probe.tick(now=NOW)
    assert report.transitions["timeout"] == 1
    run.refresh_from_db()
    assert run.state == ProbeRunState.TIMEOUT
    assert run.failure_reason == "probe-timeout"
    assert run.finished_at == NOW
    # Torn down at once: the §24 is started in the same tick.
    assert DecommissionJob.objects.filter(vm__vm_id=run.vm_id).count() == 1


def test_no_timeout_before_the_deadline(probe_on: FakeIntake) -> None:
    run = make_run(state=ProbeRunState.RUNNING, deadline_at=NOW + timedelta(seconds=1))
    probe.tick(now=NOW)
    run.refresh_from_db()
    assert run.state == ProbeRunState.RUNNING


# ─── teardown on every terminal path ─────────────────────────────────


def _vm(run: DiskProbeRun, state: str = VmState.ACTIVE) -> Vm:
    return Vm.objects.create(
        vm_id=run.vm_id, lease_id=run.vm_id, state=state, generation=1, host="host-a",
        lifecycle_vk=bytes(32),
    )


@pytest.mark.parametrize(
    ("state", "reason"),
    [
        (ProbeRunState.VERIFIED, ""),
        (ProbeRunState.FAILED, "suspect-cache"),
        (ProbeRunState.FAILED, "launch-failed:x"),
        (ProbeRunState.TIMEOUT, "probe-timeout"),
    ],
)
def test_every_verdict_is_torn_down_by_section_24(state: str, reason: str) -> None:
    run = make_run(state=state, failure_reason=reason, finished_at=NOW, teardown_after=NOW)
    vm = _vm(run)
    report = probe.TickReport()
    probe.teardown_due(now=NOW, report=report)
    job = DecommissionJob.objects.get(vm=vm)
    assert job.decided_by.name == probe.ACTOR_NAME
    run.refresh_from_db()
    assert run.teardown_started_at == NOW and run.torn_down_at is None
    # The orchestration tick finishes the §24; the next probe tick closes.
    Vm.objects.filter(pk=vm.pk).update(state=VmState.DESTROYED)
    probe.teardown_due(now=NOW + timedelta(minutes=15), report=report)
    run.refresh_from_db()
    assert run.torn_down_at == NOW + timedelta(minutes=15)
    assert report.torn_down == 1 and report.forced == 0


def test_the_lifetime_jitter_is_honoured() -> None:
    run = make_run(state=ProbeRunState.VERIFIED, finished_at=NOW,
                   teardown_after=NOW + timedelta(minutes=30))
    _vm(run)
    probe.teardown_due(now=NOW, report=probe.TickReport())
    assert not DecommissionJob.objects.exists()


def test_a_stuck_section_24_falls_back_to_the_forced_teardown(
    monkeypatch: pytest.MonkeyPatch, settings: Any
) -> None:
    """V0.1's shared teardown: §24 did not finish in time ⇒ force-destroy."""
    settings.VALI_DISK_PROBE_TEARDOWN_TIMEOUT_S = 1800
    run = make_run(state=ProbeRunState.TIMEOUT, finished_at=NOW, teardown_after=NOW)
    vm = _vm(run)
    DiskProbeRun.objects.filter(pk=run.pk).update(teardown_started_at=NOW - timedelta(hours=1))
    forced: list[str] = []

    def fake_force(vm_id: str) -> str:
        forced.append(vm_id)
        Vm.objects.filter(vm_id=vm_id).update(state=VmState.DESTROYED)
        return "forced teardown: domain-destroyed, crypto-erased"

    def no_wait(vm_id: str, deadline: float) -> None:
        raise TimeoutError("still decommissioning")

    monkeypatch.setattr(probe, "_force_destroy", fake_force)
    monkeypatch.setattr(probe, "_wait_decommission", no_wait)
    report = probe.TickReport()
    probe.teardown_due(now=NOW, report=report)
    assert forced == [vm.vm_id]
    run.refresh_from_db()
    assert run.torn_down_at == NOW
    assert "forced" in run.teardown_detail
    assert report.forced == 1


def test_the_fallback_teardowns_per_tick_are_bounded(
    monkeypatch: pytest.MonkeyPatch, settings: Any
) -> None:
    settings.VALI_DISK_PROBE_MAX_FALLBACKS_PER_TICK = 2
    calls: list[str] = []

    def fake_fallback(vm_id: str) -> tuple[str, bool]:
        calls.append(vm_id)
        return "still there", False

    monkeypatch.setattr(probe, "_fallback_teardown", fake_fallback)
    for _ in range(4):
        run = make_run(state=ProbeRunState.TIMEOUT, finished_at=NOW, teardown_after=NOW)
        _vm(run)
        DiskProbeRun.objects.filter(pk=run.pk).update(teardown_started_at=NOW - DAY)
    probe.teardown_due(now=NOW, report=probe.TickReport())
    assert len(calls) == 2


def test_no_force_before_the_timeout(monkeypatch: pytest.MonkeyPatch) -> None:
    run = make_run(state=ProbeRunState.VERIFIED, finished_at=NOW, teardown_after=NOW)
    _vm(run)
    DiskProbeRun.objects.filter(pk=run.pk).update(teardown_started_at=NOW - timedelta(minutes=5))

    def boom(vm_id: str) -> str:
        raise AssertionError("forced too early")

    monkeypatch.setattr(probe, "_force_destroy", boom)
    probe.teardown_due(now=NOW, report=probe.TickReport())
    run.refresh_from_db()
    assert run.torn_down_at is None


def test_a_queued_launch_without_a_vm_is_cancelled(monkeypatch: pytest.MonkeyPatch) -> None:
    """The VM row never materialised: the shared teardown cancels the
    still-queued launch job, and the run closes."""
    from apps.orchestration.tests.factories import make_service_client

    run = make_run(state=ProbeRunState.TIMEOUT, finished_at=NOW, teardown_after=NOW)
    LaunchJob.objects.create(
        job_id="j-1", vm_id=run.vm_id, tenant_id=TENANT, flavor="medium",
        spec_json={"vm_id": run.vm_id}, userdata_vault_path="x", userdata_vault_version=1,
        kek_vault_path="x", state=LaunchJobState.QUEUED.value, phase_started_at=NOW,
        decided_by=make_service_client(),
    )
    probe.teardown_due(now=NOW, report=probe.TickReport())
    assert LaunchJob.objects.get(job_id="j-1").state == LaunchJobState.FAILED.value
    run.refresh_from_db()
    assert run.torn_down_at == NOW
    assert "cancelled" in run.teardown_detail


def test_a_run_with_nothing_launched_closes() -> None:
    run = make_run(state=ProbeRunState.FAILED, failure_reason="launch-failed:x",
                   finished_at=NOW, teardown_after=NOW)
    probe.teardown_due(now=NOW, report=probe.TickReport())
    run.refresh_from_db()
    assert run.torn_down_at == NOW


def test_a_destroyed_vm_closes_at_once() -> None:
    run = make_run(state=ProbeRunState.VERIFIED, finished_at=NOW, teardown_after=NOW)
    _vm(run, VmState.DESTROYED)
    probe.teardown_due(now=NOW, report=probe.TickReport())
    run.refresh_from_db()
    assert run.torn_down_at == NOW


# ─── record only ─────────────────────────────────────────────────────


def test_the_orchestrator_writes_no_pool_cordon_or_placement(probe_on: FakeIntake) -> None:
    from apps.scheduler.models import MinerCapacity, MinerCapacityAudit, Placement

    pool = _pool(NODE, "default", os_disks=True, reported_state="active")
    from django.utils import timezone

    MinerCapacity.objects.create(
        miner_node_id=NODE, status="active", capacity_slots=4, refreshed_at=timezone.now(),
        observed_epoch=10, data_epoch=10,
    )
    before = MinerStoragePool.objects.filter(pk=pool.pk).values().get()
    probe.tick(now=NOW)
    run = DiskProbeRun.objects.get()
    _job(run, LaunchJobState.SUCCEEDED.value)
    DiskProbeRun.objects.filter(pk=run.pk).update(
        state=ProbeRunState.VERIFIED, finished_at=NOW, teardown_after=NOW,
        targets=[{**run.targets[0], "classified_tier": "unfit"}],
    )
    probe.tick(now=NOW + DAY)
    assert MinerStoragePool.objects.filter(pk=pool.pk).values().get() == before
    cap = MinerCapacity.objects.get(miner_node_id=NODE)
    assert cap.cordoned_at is None
    assert not MinerCapacityAudit.objects.exists()
    assert not Placement.objects.exists()


# ─── metrics ─────────────────────────────────────────────────────────


def test_the_metrics(probe_on: FakeIntake, monkeypatch) -> None:
    from apps.disktier.models import DiskIngestCounter

    make_run(node=NODE2, state=ProbeRunState.VERIFIED, finished_at=NOW - DAY,
             torn_down_at=NOW, classified_tier="nvme")
    make_run(node=NODE3, state=ProbeRunState.TIMEOUT, finished_at=NOW - DAY,
             torn_down_at=NOW, failure_reason="probe-timeout",
             scheduled_at=NOW - 3 * DAY)
    make_run(node=NODE3, state=ProbeRunState.TIMEOUT, finished_at=NOW - 2 * DAY,
             torn_down_at=NOW, failure_reason="probe-timeout",
             scheduled_at=NOW - 4 * DAY)
    DiskIngestCounter.objects.create(name="probe_rejected_wrong_nonce", value=3)
    monkeypatch.setattr(probe, "_gates", lambda flavor: gates(free={NODE: 0}))
    report = probe.tick(now=NOW)
    gone = node_four()  # a miner that left: its old verdict is not reported
    make_run(node=gone, state=ProbeRunState.TIMEOUT, finished_at=NOW - DAY, torn_down_at=NOW)
    text = probe.report_metrics(report, now=NOW, nodes=(NODE, NODE2, NODE3)).render()
    assert gone not in text
    # NODE was never verified (always skipped): it reports the watch start,
    # here the fleet's first probe, so DiskProbeStale covers it too.
    first = DiskProbeRun.objects.earliest("scheduled_at")
    (value,) = re.findall(
        rf'hippius_disk_probe_node_last_verified_timestamp_seconds{{node="{NODE}"}} (\S+)', text
    )
    assert float(value) == pytest.approx(first.scheduled_at.timestamp())
    assert "hippius_disk_probe_enabled 1" in text
    assert 'hippius_disk_probe_skipped{reason="capacity"} 1' in text
    assert "hippius_disk_probe_due 1" in text
    assert 'hippius_disk_probe_results_total{outcome="rejected_wrong_nonce"} 3' in text
    assert 'hippius_disk_probe_results_7d{verdict="nvme"} 1' in text
    assert 'hippius_disk_probe_results_7d{verdict="probe-timeout"} 2' in text
    assert f'hippius_disk_probe_node_consecutive_failures{{node="{NODE3}"}} 2' in text
    assert f'hippius_disk_probe_node_would_be_severe{{node="{NODE3}"}} 1' in text
    assert f'hippius_disk_probe_node_would_be_severe{{node="{NODE2}"}} 0' in text
    assert f'hippius_disk_probe_node_last_verified_timestamp_seconds{{node="{NODE2}"}}' in text
    assert (
        f'hippius_disk_probe_node_would_be_tier{{node="{NODE2}",pool="default",tier="nvme"}} 1'
        in text
    )
    # Never a probe's vm id or owner.
    assert USER not in text.replace(NODE, "").replace(NODE2, "").replace(NODE3, "")


def test_the_command_pushes_while_on(
    probe_on: FakeIntake, monkeypatch: pytest.MonkeyPatch, settings: Any
) -> None:
    from apps.synthetic import metrics

    pushed: list[dict] = []

    def fake_push(ms: Any, **kw: Any) -> bool:
        pushed.append(kw)
        return True

    monkeypatch.setattr(metrics, "push", fake_push)
    call_command("vali_disk_probe")
    (kw,) = pushed
    assert kw["job"] == "disk-probe" and kw["replace"] is True


# ─── the guest's metric names ────────────────────────────────────────

#: What `binaries/agent-disk-probe/src/profiles.rs` emits, per profile.
GUEST_V1 = {
    "qd1_p50_us", "qd1_p99_us", "rr_iops", "rr_p99_us", "rw_iops", "rw_p99_us",
    "seq_read_mbps", "seq_write_mbps",
}
GUEST_D1 = {
    "qd1_p50_us", "qd1_p99_us", "rr_iops", "rw_sustained_iops", "seq_read_inner_mbps",
    "seq_read_mid_mbps", "seq_read_outer_mbps", "seq_write_mbps", "surface_errors",
}


def test_classify_reads_exactly_the_guest_metric_names() -> None:
    assert PROFILE_V1.required_metrics <= GUEST_V1 <= PROFILE_V1.known_metrics
    assert PROFILE_D1.required_metrics <= GUEST_D1 <= PROFILE_D1.known_metrics
    assert PROFILE_D1.known_metrics == GUEST_D1
    source = Path(__file__).resolve().parents[4] / "binaries/agent-disk-probe/src/profiles.rs"
    if source.exists():
        emitted = set(re.findall(r'metric\("([a-z0-9_]+)"', source.read_text()))
        emitted |= set(re.findall(r'\("d1-zone-\d+", \d+, "([a-z0-9_]+)"\)', source.read_text()))
        assert emitted == GUEST_V1 | GUEST_D1


# ─── round-2 review cases ────────────────────────────────────────────


def test_a_new_miner_is_watched_from_its_registration() -> None:
    """A node that joined after the probe started does not inherit the
    fleet's first-probe time (it would go DiskProbeStale at once)."""
    from apps.miners.models import MinerIdentity
    from apps.scheduler.tests.factories import make_dispatchable_identity, node_id

    make_run(node=NODE2, state=ProbeRunState.VERIFIED, finished_at=NOW - 30 * DAY,
             torn_down_at=NOW - 30 * DAY, scheduled_at=NOW - 31 * DAY)
    make_dispatchable_identity(7)
    joined = NOW - timedelta(hours=2)
    MinerIdentity.objects.filter(chain_node_id=node_id(7)).update(registered_at=joined)
    text = probe.report_metrics(probe.TickReport(enabled=True), now=NOW,
                                nodes=(node_id(7),)).render()
    (value,) = re.findall(
        rf'hippius_disk_probe_node_last_verified_timestamp_seconds{{node="{node_id(7)}"}} (\S+)',
        text,
    )
    assert float(value) == pytest.approx(joined.timestamp())


def test_the_retry_window_starts_at_the_first_attempt(probe_on: FakeIntake) -> None:
    """A request that waited for capacity still gets its retries."""
    run = make_run(state=ProbeRunState.SCHEDULED, trigger=ProbeTrigger.MANUAL,
                   scheduled_at=NOW - timedelta(hours=5))
    probe_on.refuse = "internal"
    probe.tick(now=NOW)
    run.refresh_from_db()
    assert run.state == ProbeRunState.SCHEDULED
    assert run.first_attempt_at == NOW


def test_a_never_launched_request_does_not_block_the_next(probe_on: FakeIntake) -> None:
    from apps.scheduler.tests.factories import make_dispatchable_identity, node_id

    make_dispatchable_identity(1)
    run = probe.request_manual(node_id(1), now=NOW)
    DiskProbeRun.objects.filter(pk=run.pk).update(
        state=ProbeRunState.TORN_DOWN, failure_reason="request-expired", torn_down_at=NOW
    )
    probe.request_manual(node_id(1), now=NOW + DAY)


def test_a_launch_never_claimed_is_vali_s_failure_not_a_timeout(
    probe_on: FakeIntake, settings: Any
) -> None:
    probe.tick(now=NOW)
    run = DiskProbeRun.objects.get()
    late = NOW + timedelta(seconds=settings.VALI_DISK_PROBE_LAUNCH_TIMEOUT_S)
    probe.tick(now=late)
    run.refresh_from_db()
    assert run.state == ProbeRunState.FAILED
    assert run.failure_reason == "launch-timeout:queued"


def test_vali_s_own_backlog_is_not_a_miner_failure() -> None:
    make_run(state=ProbeRunState.FAILED, failure_reason="launch-timeout:queued",
             finished_at=NOW - DAY, torn_down_at=NOW)
    make_run(state=ProbeRunState.TIMEOUT, failure_reason="probe-timeout",
             finished_at=NOW - 2 * DAY, torn_down_at=NOW, scheduled_at=NOW - 3 * DAY)
    text = probe.report_metrics(probe.TickReport(enabled=True), now=NOW, nodes=(NODE,)).render()
    assert f'hippius_disk_probe_node_consecutive_failures{{node="{NODE}"}} 1' in text
