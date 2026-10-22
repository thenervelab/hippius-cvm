"""R3, the dedicated-disk probe and the disk state machine
(`apps.disktier.dedicated_probe`): its own switch, the selection, the run
and the launch intent it carries, verdict → state once the probe VM is
gone, the backoff, the signature-after-wipe alert, the audit trail and the
metrics. The launch order side: `apps/orchestration/tests/
test_dedicated_probe_launch.py`."""

from __future__ import annotations

import json
from datetime import timedelta
from typing import Any

import pytest
from django.test import override_settings
from django.utils import timezone

from apps.disktier import dedicated, dedicated_probe, probe, probe_results
from apps.disktier.dedicated import GIB
from apps.disktier.models import (
    DedicatedDisk,
    DedicatedDiskDesiredState,
    DedicatedDiskState,
    DiskProbeRun,
    ProbeRunState,
    ProbeTrigger,
)
from apps.lifecycle.models import Vm
from apps.scheduler.models import MinerCapacityAudit
from apps.telemetry.verifier import DiskProbeResult, DiskProbeTarget

from .dedicated_helpers import AGENT_MIN, capable
from .probe_helpers import NODE, NODE2, OWNER, USER, FakeIntake, gates

pytestmark = pytest.mark.django_db

#: A d1 result that clears every hdd floor.
D1_HDD = {
    "seq_read_inner_mbps": 110,
    "seq_read_mid_mbps": 160,
    "seq_read_outer_mbps": 220,
    "rr_iops": 400,
    "qd1_p50_us": 6_000,
    "qd1_p99_us": 30_000,
    "rw_sustained_iops": 250,
    "seq_write_mbps": 200,
    "surface_errors": 0,
    # The size the guest measured (guest release 7): the whole disk.
    "size_mib": 22_354 * 1024,
}
SIZE_GIB = 22_354


def _now():
    return timezone.now()


def pending(disk_id: str, *, node: str = NODE, **kw: Any) -> DedicatedDisk:
    """A declared disk the agent reports free and clean just now."""
    fields: dict[str, Any] = dict(
        size_bytes=SIZE_GIB * GIB,
        state=DedicatedDiskState.PENDING_PROBE,
        reported_state="free",
        reported_vm_id="",
        reported_error="",
        reported_at=_now(),
        declared_at=_now() - timedelta(hours=1),
    )
    fields.update(kw)
    return DedicatedDisk.objects.create(miner_node_id=node, disk_id=disk_id, **fields)


@pytest.fixture
def ded_on(settings: Any, monkeypatch: pytest.MonkeyPatch) -> FakeIntake:
    """R3 on for NODE (pool probing OFF), one probe owner, the image
    ready, a stub intake, NODE eligible with room and an agent that takes
    `extra_disks`."""
    from apps.orchestration import launch_jobs

    settings.VALI_DISK_PROBE_ENABLED = False
    settings.VALI_DEDICATED_PROBE_ENABLED = True
    settings.VALI_DEDICATED_PROBE_MINERS = [NODE]
    settings.VALI_DISK_PROBE_OWNERS = [OWNER]
    settings.VALI_DISK_PROBE_MAX_CONCURRENT = 3
    settings.VALI_DEDICATED_MIN_AGENT_VERSION = AGENT_MIN
    intake = FakeIntake()
    monkeypatch.setattr(launch_jobs, "start_launch", intake)
    monkeypatch.setattr(probe, "_image_ready", lambda minimum=None: True)
    monkeypatch.setattr(probe, "_gates", lambda flavor: gates(eligible=(NODE, NODE2)))
    capable(NODE)
    capable(NODE2)
    return intake


def _run_of(disk: DedicatedDisk) -> DiskProbeRun:
    disk.refresh_from_db()
    assert disk.last_probe is not None
    return disk.last_probe


def _result(run: DiskProbeRun, per_slot: dict[str, dict[str, Any]]) -> DiskProbeResult:
    """A result for `run`: per slot, `{"metrics": ...}` or `{"error": ...}`."""
    return DiskProbeResult(
        run_id_hex=run.run_id.hex,
        nonce_hex=bytes(run.nonce).hex(),
        vm_id=run.vm_id,
        vcpus=2,
        kernel="6.8.0",
        release_version=7,
        started_at=1_000,
        finished_at=1_300,
        targets=tuple(
            DiskProbeTarget(
                slot=slot,
                profile=got.get("profile", "d1"),
                metrics=dict(got.get("metrics", {})),
                hist_qd1=(0,) * 32,
                error=got.get("error", ""),
            )
            for slot, got in per_slot.items()
        ),
    )


def _accept(run: DiskProbeRun, per_slot: dict[str, dict[str, Any]], *, linger_s: int = 0) -> str:
    """Route `per_slot` as the run's signed result (the run running)."""
    DiskProbeRun.objects.filter(pk=run.pk).update(state=ProbeRunState.RUNNING)
    run.refresh_from_db()
    return probe_results.route(
        _result(run, per_slot),
        receipt_node_id=run.miner_node_id,
        placement_node_id=run.miner_node_id,
        placement_owner=run.owner,
        receipt_digest="d" * 64,
        linger_s=linger_s,
    )


def _close(run: DiskProbeRun) -> None:
    """The probe VM is gone (the teardown closed the run)."""
    DiskProbeRun.objects.filter(pk=run.pk).update(torn_down_at=_now())


def _tick() -> probe.TickReport:
    return probe.tick(now=_now())


def _audits(disk: DedicatedDisk) -> list[tuple[str, str, str]]:
    return [
        (a.before["state"], a.after["state"], a.reason)
        for a in MinerCapacityAudit.objects.filter(field=dedicated.AUDIT_FIELD).order_by(
            "created_at"
        )
        if a.after["disk_id"] == disk.disk_id
    ]


# ── the switch ───────────────────────────────────────────────────────


def test_the_dedicated_switch_probes_disks_and_leaves_pool_probing_off(
    ded_on: FakeIntake,
) -> None:
    """VALI_DEDICATED_PROBE_ENABLED alone: one run, dedicated slots only —
    the node's never-probed `default` pool (due for onboarding) is not
    probed."""
    disk = pending("wwn-0x01")
    report = _tick()
    assert report.enabled is False and report.dedicated_enabled is True
    (run,) = DiskProbeRun.objects.all()
    assert run.trigger == ProbeTrigger.DECLARED
    assert [t["slot"] for t in run.targets] == ["x0"]
    assert {t["kind"] for t in run.targets} == {"dedicated"}
    assert report.launched == 0 and report.dedicated_launched == 1
    disk.refresh_from_db()
    assert disk.state == DedicatedDiskState.PROBING and disk.last_probe_id == run.pk
    (call,) = ded_on.calls
    assert call["disk_probe"] is True
    intent = call["intent"]
    # One of OUR VMs, under a probe owner: never billed, paid or counted.
    assert intent["purpose"] == "probe"
    assert intent["user_id"] == USER
    assert intent["os_pool"] == "default"
    assert intent["probe_extra_disks"] == [{"slot": "x0", "disk_id": "wwn-0x01", "size_gb": 22300}]
    # The guest's request names the slot with the d1 profile only.
    request = json.loads(
        next(
            line.strip()
            for line in call["userdata"].decode().splitlines()
            if line.strip().startswith('{"nonce"')
        )
    )
    assert request["targets"] == [{"profile": "d1", "slot": "x0"}]
    assert 120 <= request["start_delay_s"] <= 900


def test_switch_off_launches_nothing_for_a_pending_disk(ded_on: FakeIntake, settings) -> None:
    settings.VALI_DEDICATED_PROBE_ENABLED = False
    disk = pending("wwn-0x01")
    report = _tick()
    assert report.dedicated_enabled is False
    assert ded_on.calls == [] and not DiskProbeRun.objects.exists()
    disk.refresh_from_db()
    assert disk.state == DedicatedDiskState.PENDING_PROBE


def test_pool_probing_on_never_takes_a_dedicated_disk(ded_on: FakeIntake, settings) -> None:
    settings.VALI_DISK_PROBE_ENABLED = True
    settings.VALI_DEDICATED_PROBE_ENABLED = False
    disk = pending("wwn-0x01")
    _tick()
    assert {r.miner_node_id for r in DiskProbeRun.objects.all()} == {NODE, NODE2}
    (run,) = DiskProbeRun.objects.filter(miner_node_id=NODE)
    assert [t["slot"] for t in run.targets] == ["os"]
    assert all("probe_extra_disks" not in c["intent"] for c in ded_on.calls)
    disk.refresh_from_db()
    assert disk.state == DedicatedDiskState.PENDING_PROBE


def test_a_dedicated_run_is_no_pool_probe(ded_on: FakeIntake) -> None:
    """A dedicated run neither satisfies nor delays a pool's probe, and
    never feeds the pool metrics."""
    pending("wwn-0x01")
    _tick()
    (run,) = DiskProbeRun.objects.all()
    DiskProbeRun.objects.filter(pk=run.pk).update(
        state=ProbeRunState.VERIFIED, finished_at=_now(), torn_down_at=_now()
    )
    report = probe.TickReport(enabled=True)
    due = probe.due_set(nodes=[NODE], now=_now(), report=report)
    assert [(d.pool_id, d.trigger) for d in due] == [("default", ProbeTrigger.ONBOARDING)]
    ms = probe.report_metrics(report, now=_now(), nodes=[NODE]).render()
    assert probe.M_NODE_TIER not in ms


def test_without_an_allowed_miner_nothing_is_probed(ded_on: FakeIntake, settings) -> None:
    settings.VALI_DEDICATED_PROBE_MINERS = []
    pending("wwn-0x01")
    report = _tick()
    assert report.dedicated_skipped["no-miner-allowed"] == 1
    assert not DiskProbeRun.objects.exists()
    settings.VALI_DEDICATED_PROBE_MINERS = [NODE2]
    report = _tick()
    assert report.dedicated_skipped["not-allowed"] == 1
    assert not DiskProbeRun.objects.exists()
    settings.VALI_DEDICATED_PROBE_MINERS = ["*"]
    _tick()
    assert DiskProbeRun.objects.count() == 1


def test_an_agent_without_extra_disks_is_skipped(ded_on: FakeIntake) -> None:
    capable(NODE, version="v2020.01.01")
    pending("wwn-0x01")
    report = _tick()
    assert report.dedicated_skipped["agent-without-extra-disks"] == 1
    assert not DiskProbeRun.objects.exists()


# ── selection ────────────────────────────────────────────────────────


def test_selection_takes_only_probeable_disks(ded_on: FakeIntake) -> None:
    """Never an assigned, released, free, draining, replaced, failed, unfit
    or retired disk; never one the agent reports held, refused, stale,
    too small, or still in its backoff."""
    vm = Vm.objects.create(
        vm_id="vm-tenant-1", tenant_id="t-1", state="active", host="", generation=1
    )
    now = _now()
    good = pending("wwn-0xgood")
    others = [
        pending("wwn-0xa", state=DedicatedDiskState.ASSIGNED, assigned_vm=vm, assigned_slot="x0"),
        pending("wwn-0xb", state=DedicatedDiskState.RELEASED, freed_at=now - timedelta(hours=1)),
        pending("wwn-0xc", state=DedicatedDiskState.FREE),
        pending("wwn-0xd", desired_state=DedicatedDiskDesiredState.DRAINING),
        pending("wwn-0xe", state=DedicatedDiskState.DRAINING),
        pending("wwn-0xf", state=DedicatedDiskState.REPLACED),
        pending("wwn-0xg", state=DedicatedDiskState.FAILED),
        pending("wwn-0xh", state=DedicatedDiskState.UNFIT),
        pending("wwn-0xi", state=DedicatedDiskState.RETIRED),
        pending("wwn-0xj", reported_state="assigned", reported_vm_id="vm-x"),
        pending("wwn-0xk", reported_state="unavailable", reported_error="disk-has-signature"),
        pending("wwn-0xl", reported_at=now - timedelta(hours=1)),
        pending("wwn-0xm", size_bytes=999 * GIB),
        pending("wwn-0xn", probe_retry_at=now + timedelta(hours=1)),
        pending("wwn-0xo", reported_state="failed"),
        # Defence in depth: a refusal code on a "free" report.
        pending("wwn-0xp", reported_error="disk-has-signature"),
        # Held before, and no report since that hold ended (the wipe).
        pending("wwn-0xq", freed_at=now + timedelta(seconds=5)),
    ]
    _tick()
    (run,) = DiskProbeRun.objects.all()
    assert [t["disk_id"] for t in run.targets] == ["wwn-0xgood"]
    good.refresh_from_db()
    assert good.state == DedicatedDiskState.PROBING
    for disk in others:
        before = disk.state
        disk.refresh_from_db()
        assert disk.state == before, disk.disk_id
        assert disk.last_probe_id is None, disk.disk_id
    # The assigned disk still belongs to its VM.
    assert DedicatedDisk.objects.get(disk_id="wwn-0xa").assigned_vm_id == vm.pk


def test_at_most_eight_disks_and_one_run_per_node(ded_on: FakeIntake) -> None:
    for i in range(10):
        pending(f"wwn-0x{i:02d}", declared_at=_now() - timedelta(minutes=100 - i))
    pending("wwn-0xother", node=NODE2)
    _tick()
    (run,) = DiskProbeRun.objects.filter(miner_node_id=NODE)
    assert [t["slot"] for t in run.targets] == [f"x{i}" for i in range(8)]
    # Oldest declaration first.
    assert [t["disk_id"] for t in run.targets] == [f"wwn-0x{i:02d}" for i in range(8)]
    assert not DiskProbeRun.objects.filter(miner_node_id=NODE2).exists()  # not allowed
    # The node holds a run: the two left wait for the next one.
    report = _tick()
    assert DiskProbeRun.objects.filter(miner_node_id=NODE).count() == 1
    assert report.dedicated_skipped["busy"] == 1
    assert DedicatedDisk.objects.filter(state=DedicatedDiskState.PENDING_PROBE).count() == 3


def test_a_node_with_a_pool_run_in_flight_is_busy(ded_on: FakeIntake) -> None:
    from .probe_helpers import make_run

    make_run(state=ProbeRunState.RUNNING)
    pending("wwn-0x01")
    report = _tick()
    assert report.dedicated_skipped["busy"] == 1
    assert DiskProbeRun.objects.count() == 1


def test_a_released_disk_runs_with_the_released_trigger(ded_on: FakeIntake) -> None:
    pending("wwn-0x01", freed_at=_now() - timedelta(hours=2))
    _tick()
    (run,) = DiskProbeRun.objects.all()
    assert run.trigger == ProbeTrigger.RELEASED
    assert run.targets[0]["origin"] == "released"


# ── verdict → state ──────────────────────────────────────────────────


def test_a_passing_verdict_frees_the_disk_only_once_the_probe_vm_is_gone(
    ded_on: FakeIntake,
) -> None:
    disk = pending("wwn-0x01")
    _tick()
    run = _run_of(disk)
    # A linger: the probe VM outlives its result for a while.
    assert _accept(run, {"x0": {"metrics": D1_HDD}}, linger_s=3600) == "accepted"
    _tick()
    disk.refresh_from_db()
    # The probe VM may still hold it: still probing.
    assert disk.state == DedicatedDiskState.PROBING
    _close(run)
    report = _tick()
    disk.refresh_from_db()
    assert disk.state == DedicatedDiskState.FREE
    assert disk.verified_tier == "hdd"
    assert disk.verified_size_bytes == SIZE_GIB * GIB
    assert disk.probed_at is not None and disk.last_probe_id == run.pk
    assert disk.probe_failures == 0 and disk.freed_at is not None
    assert report.dedicated_settled[dedicated_probe.PASS] == 1
    assert _audits(disk) == [
        ("pending_probe", "probing", "probe-selected"),
        ("probing", "free", "probe-pass"),
    ]
    (row,) = MinerCapacityAudit.objects.filter(reason="probe-pass")
    assert row.actor == "disk-tier" and row.after["verified_tier"] == "hdd"


def test_the_ticks_own_teardown_closes_the_run_then_the_disk_takes_its_verdict(
    ded_on: FakeIntake,
) -> None:
    """End to end through R1's teardown: the linger over, the tick tears the
    probe VM down (here: a launch that never made a VM, cancelled by the
    no-leak path), closes the run, and only then frees the disk."""
    disk = pending("wwn-0x01")
    _tick()
    run = _run_of(disk)
    _accept(run, {"x0": {"metrics": D1_HDD}}, linger_s=0)
    _tick()
    run.refresh_from_db()
    disk.refresh_from_db()
    assert run.torn_down_at is not None
    assert disk.state == DedicatedDiskState.FREE


def test_one_disk_of_a_run_failing_does_not_hold_the_others(ded_on: FakeIntake) -> None:
    a, b, c = pending("wwn-0x0a"), pending("wwn-0x0b"), pending("wwn-0x0c")
    _tick()
    run = _run_of(a)
    slow = {**D1_HDD, "rr_iops": 50}
    _accept(
        run,
        {"x0": {"metrics": D1_HDD}, "x1": {"error": "io-error"}, "x2": {"metrics": slow}},
    )
    _close(run)
    _tick()
    states = {d.disk_id: d.state for d in DedicatedDisk.objects.all()}
    assert states == {
        "wwn-0x0a": DedicatedDiskState.FREE,
        "wwn-0x0b": DedicatedDiskState.FAILED,
        "wwn-0x0c": DedicatedDiskState.UNFIT,
    }
    assert DedicatedDisk.objects.get(disk_id="wwn-0x0c").verified_tier == "unfit"
    assert {b.disk_id, c.disk_id} <= set(states)


@pytest.mark.parametrize(
    ("got", "state", "reason"),
    [
        ({"error": "io-error"}, DedicatedDiskState.FAILED, "probe-io-error"),
        ({"metrics": {**D1_HDD, "surface_errors": 2}}, DedicatedDiskState.FAILED, "probe-io-error"),
        (
            {"metrics": {**D1_HDD, "rw_sustained_iops": 40}},
            DedicatedDiskState.UNFIT,
            "probe-below-floor",
        ),
        ({"error": "disk-too-small"}, DedicatedDiskState.UNFIT, "probe-disk-too-small"),
        (
            {"error": "crypt-open-failed"},
            DedicatedDiskState.PENDING_PROBE,
            "probe-no-verdict:crypt-open-failed",
        ),
        (
            {"error": "opener-close-failed"},
            DedicatedDiskState.PENDING_PROBE,
            "probe-no-verdict:opener-close-failed",
        ),
        (
            {"error": "disk-not-found"},
            DedicatedDiskState.PENDING_PROBE,
            "probe-no-verdict:disk-not-found",
        ),
        (
            {"error": "probe-timeout"},
            DedicatedDiskState.PENDING_PROBE,
            "probe-no-verdict:probe-timeout",
        ),
        (
            {"metrics": {**D1_HDD, "qd1_p50_us": 5}},
            DedicatedDiskState.PENDING_PROBE,
            "probe-no-verdict:suspect-cache",
        ),
        (
            {"metrics": {"rr_iops": 400}},
            DedicatedDiskState.PENDING_PROBE,
            "probe-no-verdict:malformed-metrics",
        ),
        (
            {"metrics": D1_HDD, "profile": "v1"},
            DedicatedDiskState.PENDING_PROBE,
            "probe-no-verdict:profile-mismatch",
        ),
    ],
)
def test_every_verdict_maps_to_its_state(
    ded_on: FakeIntake, got: dict[str, Any], state: str, reason: str
) -> None:
    disk = pending("wwn-0x01")
    _tick()
    run = _run_of(disk)
    _accept(run, {"x0": got})
    _close(run)
    _tick()
    disk.refresh_from_db()
    assert disk.state == state
    assert _audits(disk)[-1] == ("probing", state, reason)
    if state == DedicatedDiskState.PENDING_PROBE:
        assert disk.probe_failures == 1 and disk.probe_retry_at is not None
        assert disk.verified_tier == "unknown" and disk.verified_size_bytes is None


@pytest.mark.parametrize(
    ("close", "why"),
    [
        (
            dict(state=ProbeRunState.TORN_DOWN, failure_reason="launch-refused:no-capacity"),
            "launch-refused",
        ),
        (dict(state=ProbeRunState.TIMEOUT, failure_reason="probe-timeout"), "probe-timeout"),
        (dict(state=ProbeRunState.FAILED, failure_reason="launch-failed:boom"), "launch-failed"),
    ],
)
def test_a_run_without_a_result_never_frees_its_disks(
    ded_on: FakeIntake, close: dict[str, Any], why: str
) -> None:
    disk = pending("wwn-0x01")
    _tick()
    run = _run_of(disk)
    DiskProbeRun.objects.filter(pk=run.pk).update(torn_down_at=_now(), **close)
    _tick()
    disk.refresh_from_db()
    assert disk.state == DedicatedDiskState.PENDING_PROBE
    assert _audits(disk)[-1] == ("probing", "pending_probe", f"probe-no-verdict:{why}")
    assert disk.probe_failures == 1


def test_a_result_with_slots_the_run_did_not_ask_frees_nothing(ded_on: FakeIntake) -> None:
    a, _b = pending("wwn-0x0a"), pending("wwn-0x0b")
    _tick()
    run = _run_of(a)
    _accept(
        run,
        {"x0": {"metrics": D1_HDD}, "x1": {"metrics": D1_HDD}, "x5": {"metrics": D1_HDD}},
    )
    _close(run)
    _tick()
    assert set(DedicatedDisk.objects.values_list("state", flat=True)) == {"pending_probe"}


def test_a_missing_slot_is_no_verdict_for_that_disk_only(ded_on: FakeIntake) -> None:
    a, b = pending("wwn-0x0a"), pending("wwn-0x0b")
    _tick()
    run = _run_of(a)
    # x0 failed first (the run's summary), x1 left out of the result.
    _accept(run, {"x0": {"error": "io-error"}})
    _close(run)
    _tick()
    a.refresh_from_db()
    b.refresh_from_db()
    assert a.state == DedicatedDiskState.FAILED
    assert b.state == DedicatedDiskState.PENDING_PROBE


def test_an_io_error_wins_over_a_result_with_extra_slots(ded_on: FakeIntake) -> None:
    """A mismatched result grades no disk on sale — but an I/O error is a
    fact about its disk, whatever else came with it."""
    a, b = pending("wwn-0x0a"), pending("wwn-0x0b")
    _tick()
    run = _run_of(a)
    _accept(run, {"x0": {"metrics": D1_HDD}, "x1": {"error": "io-error"}, "x7": {}})
    _close(run)
    _tick()
    a.refresh_from_db()
    b.refresh_from_db()
    assert a.state == DedicatedDiskState.PENDING_PROBE
    assert _audits(a)[-1][2] == "probe-no-verdict:targets-mismatch"
    assert b.state == DedicatedDiskState.FAILED


def test_the_disk_is_sold_at_the_size_the_guest_measured(ded_on: FakeIntake) -> None:
    """Never the miner's own figure: the miner said 22354 GiB, the guest saw
    a bit more — the guest's size is the verified one."""
    disk = pending("wwn-0x01")
    _tick()
    run = _run_of(disk)
    _accept(run, {"x0": {"metrics": {**D1_HDD, "size_mib": 22_400 * 1024}}})
    _close(run)
    _tick()
    disk.refresh_from_db()
    assert disk.state == DedicatedDiskState.FREE
    assert disk.verified_size_bytes == 22_400 * GIB


@pytest.mark.parametrize(
    ("size_mib", "state", "reason"),
    [
        # The miner overstated it: below the size class the run measured.
        (22_299 * 1024, DedicatedDiskState.UNFIT, "probe-size-mismatch"),
        (None, DedicatedDiskState.PENDING_PROBE, "probe-no-verdict:size-unmeasured"),
    ],
)
def test_no_sale_without_a_measured_size_that_holds_the_class(
    ded_on: FakeIntake, size_mib: int | None, state: str, reason: str
) -> None:
    disk = pending("wwn-0x01")
    _tick()
    run = _run_of(disk)
    metrics = {k: v for k, v in D1_HDD.items() if k != "size_mib"}
    if size_mib is not None:
        metrics["size_mib"] = size_mib
    _accept(run, {"x0": {"metrics": metrics}})
    _close(run)
    _tick()
    disk.refresh_from_db()
    assert disk.state == state
    assert _audits(disk)[-1] == ("probing", state, reason)
    assert disk.verified_size_bytes is None


def test_a_second_run_never_starts_on_a_node_with_one_open(ded_on: FakeIntake) -> None:
    """Under the node's lock: a run created by another tick meanwhile wins."""
    from .probe_helpers import make_run

    disk = pending("wwn-0x01")
    make_run(state=ProbeRunState.SCHEDULED)
    assert (
        dedicated_probe.create_run(
            node_id=NODE, chip_id="ab" * 32, disks=[disk], os_pool_id="default", now=_now()
        )
        is None
    )
    disk.refresh_from_db()
    assert disk.state == DedicatedDiskState.PENDING_PROBE


def test_a_disk_whose_report_changed_since_selection_is_left_out(ded_on: FakeIntake) -> None:
    a, b = pending("wwn-0x0a"), pending("wwn-0x0b")
    # Between the candidates read and the run: the agent now reports `a` held.
    DedicatedDisk.objects.filter(pk=a.pk).update(reported_state="assigned", reported_vm_id="vm-z")
    run = dedicated_probe.create_run(
        node_id=NODE, chip_id="ab" * 32, disks=[a, b], os_pool_id="default", now=_now()
    )
    assert run is not None
    assert [t["disk_id"] for t in run.targets] == ["wwn-0x0b"]
    a.refresh_from_db()
    assert a.state == DedicatedDiskState.PENDING_PROBE


def test_a_pending_disk_waits_for_the_post_wipe_report(ded_on: FakeIntake) -> None:
    """After an attempt the probe VM held the disk: the next probe waits for
    a clean report newer than that hold (the agent's release wipe)."""
    disk = pending("wwn-0x01")
    _tick()
    run = _run_of(disk)
    DiskProbeRun.objects.filter(pk=run.pk).update(
        state=ProbeRunState.TIMEOUT, failure_reason="probe-timeout", torn_down_at=_now()
    )
    _tick()
    disk.refresh_from_db()
    DedicatedDisk.objects.filter(pk=disk.pk).update(
        probe_retry_at=None, reported_at=disk.freed_at - timedelta(seconds=1)
    )
    assert _tick().dedicated_due == 0
    DedicatedDisk.objects.filter(pk=disk.pk).update(reported_at=_now())
    assert _tick().dedicated_launched == 1


def test_a_dedicated_runs_deadline_grows_with_its_disks(ded_on: FakeIntake, settings) -> None:
    """One guest target budget per disk plus the margin, after the start
    delay — never the pool probe's flat window."""
    from apps.orchestration.models import LaunchJob, LaunchJobState

    settings.VALI_DEDICATED_PROBE_TARGET_BUDGET_S = 1860
    settings.VALI_DEDICATED_PROBE_MARGIN_S = 3600
    settings.VALI_DISK_PROBE_TIMEOUT_S = 60
    for i in range(8):
        pending(f"wwn-0x{i:02d}")
    _tick()
    (run,) = DiskProbeRun.objects.all()
    booted = _now()
    LaunchJob.objects.filter(job_id=run.launch_job_id).update(
        state=LaunchJobState.SUCCEEDED.value, finished_at=booted
    )
    _tick()
    run.refresh_from_db()
    assert run.state == ProbeRunState.RUNNING
    assert run.deadline_at == booted + timedelta(seconds=run.start_delay_s + 8 * 1860 + 3600)
    assert dedicated_probe.run_timeout_s(run) == 8 * 1860 + 3600


def test_after_a_failed_attempt_a_suspect_disk_goes_alone(ded_on: FakeIntake) -> None:
    """A whole-run timeout must not loop on the same 8 disks: a disk with a
    failed attempt behind it is probed alone, the others after it."""
    pending("wwn-0x0a", probe_failures=1)
    pending("wwn-0x0b")
    pending("wwn-0x0c")
    _tick()
    (run,) = DiskProbeRun.objects.all()
    assert [t["disk_id"] for t in run.targets] == ["wwn-0x0a"]
    assert dedicated_probe.isolate_suspects([]) == []


def test_dedicated_probing_needs_guest_release_7_whatever_the_pool_floor(
    ded_on: FakeIntake, settings, monkeypatch
) -> None:
    asked: list[int | None] = []
    monkeypatch.setattr(probe, "_image_ready", lambda minimum=None: asked.append(minimum) or False)
    settings.VALI_DISK_PROBE_MIN_GUEST_RELEASE = 5
    pending("wwn-0x01")
    report = _tick()
    assert asked == [7]
    assert report.dedicated_skipped["image-not-ready"] == 1
    assert not DiskProbeRun.objects.exists()
    settings.VALI_DISK_PROBE_MIN_GUEST_RELEASE = 9
    assert dedicated_probe.min_guest_release() == 9
    settings.VALI_DEDICATED_PROBE_MIN_GUEST_RELEASE = 3
    settings.VALI_DISK_PROBE_MIN_GUEST_RELEASE = 0
    assert dedicated_probe.min_guest_release() == 7


def test_attempts_without_a_verdict_back_off_exponentially(ded_on: FakeIntake, settings) -> None:
    settings.VALI_DEDICATED_PROBE_RETRY_S = 100
    settings.VALI_DEDICATED_PROBE_RETRY_MAX_S = 350
    assert [dedicated_probe.backoff(n).total_seconds() for n in (1, 2, 3, 4, 9)] == [
        100,
        200,
        350,
        350,
        350,
    ]
    disk = pending("wwn-0x01")
    for attempt in (1, 2):
        _tick()
        run = _run_of(disk)
        DiskProbeRun.objects.filter(pk=run.pk).update(
            state=ProbeRunState.TIMEOUT, failure_reason="probe-timeout", torn_down_at=_now()
        )
        _tick()
        disk.refresh_from_db()
        assert disk.probe_failures == attempt
        # In its backoff: not taken again.
        report = _tick()
        assert report.dedicated_due == 0
        # Backoff over, and the agent reported the disk clean after the wipe.
        DedicatedDisk.objects.filter(pk=disk.pk).update(probe_retry_at=_now(), reported_at=_now())
    # A verdict resets the count.
    _tick()
    run = _run_of(disk)
    _accept(run, {"x0": {"metrics": D1_HDD}})
    _close(run)
    _tick()
    disk.refresh_from_db()
    assert disk.state == DedicatedDiskState.FREE
    assert disk.probe_failures == 0 and disk.probe_retry_at is None


def test_a_disk_the_run_no_longer_holds_is_not_touched(ded_on: FakeIntake) -> None:
    """Compare-and-set: a disk moved off `probing` (or onto another run)
    meanwhile keeps its state."""
    disk = pending("wwn-0x01")
    _tick()
    run = _run_of(disk)
    _accept(run, {"x0": {"metrics": D1_HDD}})
    DedicatedDisk.objects.filter(pk=disk.pk).update(state=DedicatedDiskState.RETIRED)
    _close(run)
    _tick()
    disk.refresh_from_db()
    assert disk.state == DedicatedDiskState.RETIRED


def test_settle_runs_with_the_switch_off(ded_on: FakeIntake, settings) -> None:
    """Turning R3 off never strands a disk in `probing`."""
    disk = pending("wwn-0x01")
    _tick()
    run = _run_of(disk)
    settings.VALI_DEDICATED_PROBE_ENABLED = False
    _accept(run, {"x0": {"metrics": D1_HDD}})
    _close(run)
    _tick()
    disk.refresh_from_db()
    assert disk.state == DedicatedDiskState.FREE


def test_a_freed_disk_is_placeable_only_once_reported_free_after_the_wipe(
    ded_on: FakeIntake, settings
) -> None:
    disk = pending("wwn-0x01")
    _tick()
    run = _run_of(disk)
    _accept(run, {"x0": {"metrics": D1_HDD}})
    # The agent still reports the probe VM's hold, then the release wipe.
    DedicatedDisk.objects.filter(pk=disk.pk).update(
        reported_state="unavailable", reported_error="disk-release-pending"
    )
    _close(run)
    _tick()
    request = dedicated.DedicatedRequest("hdd", 1, 16000)
    assert not dedicated.qualifying(request).exists()
    # A "free" report from before the probe VM's hold ended is not the
    # post-wipe one.
    disk.refresh_from_db()
    DedicatedDisk.objects.filter(pk=disk.pk).update(
        reported_state="free", reported_error="", reported_at=disk.freed_at - timedelta(seconds=1)
    )
    assert not dedicated.qualifying(request).exists()
    DedicatedDisk.objects.filter(pk=disk.pk).update(
        reported_state="free", reported_error="", reported_at=_now()
    )
    assert list(dedicated.qualifying(request)) == [disk]


# ── a signature where a wiped disk was expected ──────────────────────


def _report(node: str, disk_id: str, *, state: str, error: str = "") -> None:
    """One `v7` heartbeat carrying one dedicated disk."""
    from apps.disktier.ingest import record_storage_report
    from apps.telemetry.verifier import DeclaredDedicatedDisk, DeclaredPool, DeclaredStorage

    record_storage_report(
        node,
        DeclaredStorage(
            pools=(
                DeclaredPool(
                    pool_id="default",
                    declared_class="nvme",
                    total_gb=1000,
                    available_gb=500,
                    budget_gb=900,
                    committed_gb=0,
                    os_disks=True,
                    state="active",
                    error="",
                ),
            ),
            dedicated_disks=(
                DeclaredDedicatedDisk(
                    disk_id=disk_id, size_mb=SIZE_GIB * 1024, state=state, vm="", error=error
                ),
            ),
            storage_config_revision=0,
        ),
        _now(),
    )


def test_a_signature_after_the_probe_vms_wipe_takes_the_disk_off_sale(
    ded_on: FakeIntake,
) -> None:
    disk = pending("wwn-0x01")
    _tick()
    run = _run_of(disk)
    _accept(run, {"x0": {"metrics": D1_HDD}})
    _close(run)
    _tick()
    disk.refresh_from_db()
    assert disk.state == DedicatedDiskState.FREE
    # The release wipe left the opener's LUKS header behind.
    _report(NODE, "wwn-0x01", state="unavailable", error="disk-has-signature")
    disk.refresh_from_db()
    assert disk.state == DedicatedDiskState.RELEASED
    assert _audits(disk)[-1] == ("free", "released", "signature-after-wipe")
    assert not dedicated.qualifying(dedicated.DedicatedRequest("hdd", 1, 16000)).exists()
    # The alert's gauge.
    ms = metrics_text(probe.TickReport(dedicated_enabled=True))
    assert f'{dedicated_probe.M_SIGNATURE}{{node="{NODE}"}} 1' in ms
    # A clean report later: back to a probe (never straight to sale).
    _report(NODE, "wwn-0x01", state="free")
    disk.refresh_from_db()
    assert disk.state == DedicatedDiskState.PENDING_PROBE
    assert _audits(disk)[-1] == ("released", "pending_probe", "wiped-and-free")


def test_a_released_disk_with_a_signature_after_its_wipe_stays_released(
    ded_on: FakeIntake,
) -> None:
    disk = pending(
        "wwn-0x01",
        state=DedicatedDiskState.RELEASED,
        freed_at=_now() - timedelta(minutes=5),
        reported_state="unavailable",
        reported_error="disk-release-pending",
    )
    _report(NODE, "wwn-0x01", state="unavailable", error="disk-has-signature")
    disk.refresh_from_db()
    assert disk.state == DedicatedDiskState.RELEASED
    ms = metrics_text(probe.TickReport(dedicated_enabled=True))
    assert f'{dedicated_probe.M_SIGNATURE}{{node="{NODE}"}} 1' in ms


def test_a_declared_disk_with_a_signature_is_no_alert(ded_on: FakeIntake) -> None:
    """The operator has not run `wipefs` yet: the agent refuses the disk,
    the probe never takes it, nothing alerts."""
    disk = pending("wwn-0x01")
    _report(NODE, "wwn-0x01", state="unavailable", error="disk-has-signature")
    disk.refresh_from_db()
    assert disk.state == DedicatedDiskState.PENDING_PROBE
    assert not MinerCapacityAudit.objects.filter(reason="signature-after-wipe").exists()
    ms = metrics_text(probe.TickReport(dedicated_enabled=True))
    assert f'{dedicated_probe.M_SIGNATURE}{{node="{NODE}"}} 0' in ms
    _tick()
    assert not DiskProbeRun.objects.exists()


def test_a_pending_disk_signed_after_its_probe_vms_wipe_goes_back_to_released(
    ded_on: FakeIntake,
) -> None:
    """An attempt without a verdict: the probe VM held (and the opener
    formatted) the disk; a signature after the wipe is the same alert."""
    disk = pending("wwn-0x01")
    _tick()
    run = _run_of(disk)
    DiskProbeRun.objects.filter(pk=run.pk).update(
        state=ProbeRunState.TIMEOUT, failure_reason="probe-timeout", torn_down_at=_now()
    )
    _tick()
    disk.refresh_from_db()
    assert disk.state == DedicatedDiskState.PENDING_PROBE
    _report(NODE, "wwn-0x01", state="unavailable", error="disk-has-signature")
    disk.refresh_from_db()
    assert disk.state == DedicatedDiskState.RELEASED
    assert _audits(disk)[-1] == ("pending_probe", "released", "signature-after-wipe")


def test_a_free_disk_signed_with_no_hold_on_record_is_taken_off_sale(ded_on: FakeIntake) -> None:
    """E4 gave a disk straight back (`revert_unused`: no `freed_at`) and
    something wrote to it since: off sale, and alerted."""
    disk = pending("wwn-0x01", state=DedicatedDiskState.FREE, freed_at=None)
    _report(NODE, "wwn-0x01", state="unavailable", error="disk-has-signature")
    disk.refresh_from_db()
    assert disk.state == DedicatedDiskState.RELEASED
    assert disk.freed_at is not None
    assert _audits(disk)[-1] == ("free", "released", "signature-after-wipe")


def test_a_free_disk_held_by_a_vm_vali_never_gave_it_is_taken_off_sale(
    ded_on: FakeIntake,
) -> None:
    from apps.disktier.ingest import record_storage_report
    from apps.telemetry.verifier import DeclaredDedicatedDisk, DeclaredPool, DeclaredStorage

    disk = pending("wwn-0x01")
    _tick()
    run = _run_of(disk)
    _accept(run, {"x0": {"metrics": D1_HDD}})
    _close(run)
    _tick()
    disk.refresh_from_db()
    assert disk.state == DedicatedDiskState.FREE

    def report(vm: str) -> None:
        record_storage_report(
            NODE,
            DeclaredStorage(
                pools=(
                    DeclaredPool(
                        pool_id="default",
                        declared_class="nvme",
                        total_gb=1000,
                        available_gb=500,
                        budget_gb=900,
                        committed_gb=0,
                        os_disks=True,
                        state="active",
                        error="",
                    ),
                ),
                dedicated_disks=(
                    DeclaredDedicatedDisk(
                        disk_id="wwn-0x01",
                        size_mb=SIZE_GIB * 1024,
                        state="assigned",
                        vm=vm,
                        error="",
                    ),
                ),
                storage_config_revision=0,
            ),
            _now(),
        )

    # A report still in flight showing its own probe VM: nothing to say.
    report(run.vm_id)
    disk.refresh_from_db()
    assert disk.state == DedicatedDiskState.FREE
    report("vm-nobody-gave-it")
    disk.refresh_from_db()
    assert disk.state == DedicatedDiskState.RELEASED
    assert _audits(disk)[-1] == ("free", "released", "held-elsewhere")


def test_a_signature_while_the_probe_vm_holds_the_disk_is_expected(ded_on: FakeIntake) -> None:
    """The opener formats the disk in the probe VM: a `probing` disk is
    never moved or flagged, whatever the agent says."""
    disk = pending("wwn-0x01", freed_at=_now() - timedelta(days=3))
    _tick()
    _report(NODE, "wwn-0x01", state="unavailable", error="disk-has-signature")
    disk.refresh_from_db()
    assert disk.state == DedicatedDiskState.PROBING


# ── the released path (E4's §24 release, audited) ────────────────────


def test_release_and_wipe_report_are_audited(ded_on: FakeIntake) -> None:
    vm = Vm.objects.create(
        vm_id="vm-tenant-1", tenant_id="t-1", state="active", host="", generation=1
    )
    disk = pending(
        "wwn-0x01", state=DedicatedDiskState.ASSIGNED, assigned_vm=vm, assigned_slot="x0"
    )
    assert dedicated.release_for_destroyed_vm(vm) == 1
    _report(NODE, "wwn-0x01", state="free")
    disk.refresh_from_db()
    assert disk.state == DedicatedDiskState.PENDING_PROBE
    assert _audits(disk) == [
        ("assigned", "released", "vm-destroyed"),
        ("released", "pending_probe", "wiped-and-free"),
    ]


# ── metrics and the command ──────────────────────────────────────────


def metrics_text(report: probe.TickReport) -> str:
    ms = probe.base_metrics(report)
    dedicated_probe.report_metrics(ms, report, now=_now())
    return ms.render()


def test_the_metrics_count_states_and_failures(ded_on: FakeIntake) -> None:
    pending("wwn-0x01", probe_failures=4)
    pending("wwn-0x02", state=DedicatedDiskState.FREE)
    text = metrics_text(probe.TickReport(dedicated_enabled=True))
    assert f"{dedicated_probe.M_ENABLED} 1" in text
    assert f'{dedicated_probe.M_FAILURES}{{node="{NODE}"}} 4' in text
    assert f'{dedicated_probe.M_DISKS}{{node="{NODE}",state="free"}} 1' in text
    assert f'{dedicated_probe.M_DISKS}{{node="{NODE}",state="pending_probe"}} 1' in text
    # The pool switch stays 0: the pool alerts cannot fire.
    assert f"{probe.M_ENABLED} 0" in text


def test_the_command_pushes_the_dedicated_series_only_while_on(
    ded_on: FakeIntake, settings, monkeypatch
) -> None:
    from django.core.management import call_command

    from apps.synthetic import metrics

    pushed: list[str] = []
    monkeypatch.setattr(metrics, "push", lambda ms, **kw: pushed.append(ms.render()) or True)
    pending("wwn-0x01")
    call_command("vali_disk_probe")
    (text,) = pushed
    assert f"{dedicated_probe.M_ENABLED} 1" in text
    assert probe.M_NODE_LAST_VERIFIED not in text  # no pool series
    settings.VALI_DEDICATED_PROBE_ENABLED = False
    call_command("vali_disk_probe")
    assert len(pushed) == 1


@override_settings(VALI_DEDICATED_PROBE_ENABLED=True, VALI_DISK_PROBE_ENABLED=False)
def test_results_are_routed_with_only_the_dedicated_switch() -> None:
    assert probe_results.routing_on() is True
    with override_settings(VALI_DEDICATED_PROBE_ENABLED=False):
        assert probe_results.routing_on() is False
