"""`apps.disktier.evaluate` — the passive per-pool / per-disk evaluator
(design §3.5, phase P2), RECORD ONLY: per-owner medians, cross-owner
median / p90, tier thresholds, the sustained rule, the internal-witness
rule, the single-griefer cap and the rate-limited would-reprobe event."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from io import StringIO
from typing import Any

import pytest
from django.core.management import call_command

from apps.disktier import evaluate
from apps.disktier.models import (
    DedicatedDisk,
    DiskPassiveEvent,
    DiskProbeRun,
    MinerDiskHealthHourly,
    MinerStoragePool,
    VmDiskIoHourly,
)
from apps.scheduler.models import MinerCapacityAudit
from apps.scheduler.tests.factories import node_id

pytestmark = pytest.mark.django_db

NODE = node_id(1)
NODE2 = node_id(2)
#: The run happens at 12:17; it grades 11:00 (and 10:00).
NOW = datetime(2026, 10, 16, 12, 17, tzinfo=UTC)
H = datetime(2026, 10, 16, 11, tzinfo=UTC)
H1 = H - timedelta(hours=1)

_vm_seq = iter(range(10_000))


def io(
    await_us: int,
    *,
    owner: str = "user-1",
    hour: datetime = H,
    miner: str = NODE,
    pool: str = "default",
    disk: str = "",
    reads: int = 1000,
    vm: str | None = None,
    device: str = "vdb",
) -> VmDiskIoHourly:
    """One VM device hour whose QD >= 4 small-read await is `await_us`."""
    return VmDiskIoHourly.objects.create(
        vm_id=vm or f"vm-{next(_vm_seq)}",
        miner_node_id=miner,
        owner=owner,
        device=device,
        slot="x0" if disk else "os",
        pool_id="" if disk else pool,
        disk_id=disk,
        hour=hour,
        windows=60,
        seconds=3600,
        qd4_small_r_ios=reads,
        qd4_small_r_ticks_ms=await_us * reads // 1000,
    )


def pool(tier: str = "nvme", *, miner: str = NODE, pool_id: str = "default", **kw: Any) -> None:
    MinerStoragePool.objects.create(miner_node_id=miner, pool_id=pool_id, tier=tier, **kw)


def run(**kw: Any) -> evaluate.EvaluateReport:
    return evaluate.evaluate(now=kw.pop("now", NOW), **kw)


def health(
    hour: datetime = H, miner: str = NODE, pool_id: str = "default"
) -> MinerDiskHealthHourly:
    return MinerDiskHealthHourly.objects.get(miner_node_id=miner, pool_id=pool_id, hour=hour)


def events(kind: str = "would-reprobe") -> list[DiskPassiveEvent]:
    return list(DiskPassiveEvent.objects.filter(kind=kind).order_by("id"))


# ─── medians ─────────────────────────────────────────────────────────


def test_per_owner_median_then_median_and_p90_across_owners() -> None:
    pool("nvme")
    for us in (1000, 2000, 9000):
        io(us, owner="a")
    io(4000, owner="b")
    io(500, owner="c")
    io(700, owner="c")
    # Too few QD>=4 reads to be a sample, still a VM on the pool.
    io(99_000, owner="d", reads=99)
    run(hours=1)
    row = health()
    # Owner medians: a 2000, b 4000, c 600 → median 2000, p90 (nearest rank) 4000.
    assert (row.owners, row.vms) == (3, 7)
    assert (row.median_owner_await_us, row.p90_owner_await_us) == (2000, 4000)
    assert row.tier == "nvme"


def test_one_owner_with_many_vms_is_one_vote() -> None:
    pool("nvme")
    for _ in range(9):
        io(50_000, owner="many", hour=H1)
        io(50_000, owner="many")
    io(100, owner="x", hour=H1)
    io(100, owner="x")
    io(200, owner="y", hour=H1)
    io(200, owner="y")
    run()
    row = health()
    assert row.owners == 3
    assert row.median_owner_await_us == 200


def test_unresolved_devices_are_never_graded() -> None:
    pool("nvme")
    io(50_000, pool="")
    run(hours=1)
    assert not MinerDiskHealthHourly.objects.exists()


# ─── thresholds and the sustained rule ───────────────────────────────


@pytest.mark.parametrize(("tier", "threshold"), [("nvme", 3000), ("ssd", 8000), ("hdd", 80_000)])
def test_tier_thresholds(tier: str, threshold: int) -> None:
    pool(tier)
    for hour in (H1, H):
        io(threshold, owner="at", hour=hour)
        io(threshold + 1, owner="over", hour=hour)
    run()
    row = health()
    assert row.suspect_owners == 1
    assert row.tier == tier


def test_a_single_bad_hour_is_not_sustained() -> None:
    pool("nvme")
    io(1000, owner="a", hour=H1)
    io(50_000, owner="a", hour=H)
    run()
    assert health().suspect_owners == 0
    assert health().verdict == "ok"
    assert not events()


def test_two_bad_hours_make_a_suspect_owner() -> None:
    pool("nvme")
    io(50_000, owner="a", hour=H1)
    io(50_000, owner="a", hour=H)
    run()
    assert health(H1).verdict == "ok"  # nothing before 10:00
    row = health()
    assert (row.suspect_owners, row.verdict) == (1, "suspect")


def test_an_unknown_tier_falls_back_to_the_declared_class() -> None:
    pool("unknown", declared_class="hdd")
    for hour in (H1, H):
        io(50_000, owner="a", hour=hour)  # bad for nvme, fine for hdd
    run()
    row = health()
    assert (row.tier, row.verdict, row.suspect_owners) == ("hdd", "ok", 0)


def test_the_operator_override_wins_over_the_verified_tier() -> None:
    pool("hdd", operator_override="nvme", override_reason="test")
    for hour in (H1, H):
        io(50_000, owner="a", hour=hour)
    run()
    assert health().tier == "nvme"
    assert health().verdict == "suspect"


def test_no_tier_records_the_hour_ungraded() -> None:
    pool("unknown")  # no declared class either
    io(50_000, miner=NODE2)  # no pool row at all
    for hour in (H1, H):
        io(50_000, owner="a", hour=hour)
    run()
    for row in MinerDiskHealthHourly.objects.filter(hour=H):
        assert (row.tier, row.verdict, row.suspect_owners) == ("", "", 0)
        assert row.median_owner_await_us == 50_000
    assert not events()


def test_a_dedicated_disk_is_graded_on_its_verified_tier() -> None:
    DedicatedDisk.objects.create(miner_node_id=NODE, disk_id="wwn-0x1", verified_tier="hdd")
    for hour in (H1, H):
        io(90_000, owner="a", hour=hour, disk="wwn-0x1")
    run()
    row = MinerDiskHealthHourly.objects.get(disk_id="wwn-0x1", hour=H)
    assert (row.pool_id, row.tier, row.verdict) == ("", "hdd", "suspect")


# ─── who may raise a suspicion ───────────────────────────────────────


def _bad(owner: str, *, miner: str = NODE, pool_id: str = "default") -> None:
    for hour in (H1, H):
        io(50_000, owner=owner, hour=hour, miner=miner, pool=pool_id)


def test_an_internal_witness_alone_is_enough_and_never_capped(settings: Any) -> None:
    settings.VALI_DISK_PASSIVE_INTERNAL_OWNERS = ["hipc-internal"]
    pool("nvme")
    pool("nvme", miner=NODE2)
    _bad("hipc-internal")
    _bad("hipc-internal", miner=NODE2)
    run()
    assert health().verdict == "suspect"
    assert health(miner=NODE2).verdict == "suspect"
    reasons = [(e.miner_node_id, e.trigger_owner, e.detail["reason"]) for e in events()]
    assert sorted(reasons) == sorted(
        [(NODE, "", "internal-witness"), (NODE2, "", "internal-witness")]
    )
    assert not events("griefer-capped")


def test_two_non_internal_owners_are_enough() -> None:
    pool("nvme")
    _bad("a")
    _bad("b")
    io(100, owner="c", hour=H1)
    io(100, owner="c")
    run()
    row = health()
    assert (row.suspect_owners, row.verdict) == (2, "suspect")
    (ev,) = events()
    assert (ev.trigger_owner, ev.detail["reason"]) == ("", "owners")


def test_the_single_griefer_cap() -> None:
    """One owner, alone, flags one miner per cooldown; the second miner it
    flags is capped (verdict ok + a griefer-capped event)."""
    pool("nvme")
    pool("nvme", miner=NODE2)
    _bad("griefer")
    run()
    assert health().verdict == "suspect"
    (ev,) = events()
    assert (ev.miner_node_id, ev.trigger_owner, ev.detail["reason"]) == (
        NODE,
        "griefer",
        "lone-owner",
    )
    _bad("griefer", miner=NODE2)
    run()
    assert health(miner=NODE2).verdict == "ok"
    assert health(miner=NODE2).suspect_owners == 1
    assert [e.miner_node_id for e in events()] == [NODE]
    (capped,) = events("griefer-capped")
    assert (capped.miner_node_id, capped.trigger_owner) == (NODE2, "griefer")
    # The first miner stays suspect when re-graded: the cap looks elsewhere.
    run()
    assert health().verdict == "suspect"
    assert len(events("griefer-capped")) == 1


def test_the_cap_is_lifted_after_the_cooldown() -> None:
    pool("nvme")
    pool("nvme", miner=NODE2)
    _bad("griefer")
    run()
    later = NOW + timedelta(days=1, hours=1)
    for hour in (H1 + timedelta(days=1, hours=1), H + timedelta(days=1, hours=1)):
        io(50_000, owner="griefer", hour=hour, miner=NODE2)
    run(now=later)
    assert [e.miner_node_id for e in events()] == [NODE, NODE2]


# ─── the would-reprobe event ─────────────────────────────────────────


def test_would_reprobe_is_rate_limited_per_miner() -> None:
    pool("nvme")
    pool("nvme", pool_id="fast")
    _bad("a")
    _bad("b")
    _bad("a", pool_id="fast")
    _bad("b", pool_id="fast")
    report = run()
    assert health().verdict == health(pool_id="fast").verdict == "suspect"
    assert len(events()) == 1
    assert report.would_reprobe == 1
    assert report.rate_limited == 1
    # A day later the miner may be flagged again.
    day = timedelta(days=1, hours=1)
    for hour in (H1 + day, H + day):
        io(50_000, owner="a", hour=hour)
        io(50_000, owner="b", hour=hour)
    run(now=NOW + day)
    assert len(events()) == 2


def test_re_grading_is_idempotent() -> None:
    pool("nvme")
    _bad("a")
    _bad("b")
    run()
    run()
    assert MinerDiskHealthHourly.objects.filter(hour=H).count() == 1
    assert len(events()) == 1


def test_record_only_nothing_else_changes(settings: Any) -> None:
    settings.VALI_DISK_TIER_CONSEQUENCES = "enforce"
    pool("nvme")
    _bad("a")
    _bad("b")
    run()
    p = MinerStoragePool.objects.get()
    assert (p.tier, p.health, p.health_since, p.next_probe_due_at) == ("nvme", "ok", None, None)
    assert (p.consecutive_fail, p.auto_cordoned) == (0, False)
    assert not DiskProbeRun.objects.exists()
    assert not MinerCapacityAudit.objects.exists()


# ─── metrics + command ───────────────────────────────────────────────


def test_metrics_render(settings: Any) -> None:
    pool("nvme")
    _bad("a")
    _bad("b")
    run()
    text = evaluate.report_metrics(now=NOW).render()
    assert 'hippius_disk_health_targets{verdict="suspect"} 1' in text
    assert f'hippius_disk_target_suspect{{node="{NODE}",scope="pool",target="default"}} 1' in text
    assert 'hippius_disk_passive_events_24h{event="would-reprobe"} 1' in text
    assert "hippius_disk_evaluate_timestamp_seconds" in text
    # Owners and VM ids never reach a label.
    assert "vm-" not in text and '"a"' not in text


def test_the_command_grades_and_prints_without_pushing() -> None:
    out = StringIO()
    call_command("vali_disktier_evaluate", "--no-push", "--hours", "1", stdout=out)
    assert "disktier evaluate: hours=1" in out.getvalue()
    assert "hippius_disk_health_latest_hour_seconds 0" in out.getvalue()


def test_a_long_internal_owner_still_matches_its_stored_key(settings: Any) -> None:
    from apps.disktier.ingest import owner_key

    long_owner = "internal-" + "x" * 200
    settings.VALI_DISK_PASSIVE_INTERNAL_OWNERS = [long_owner]
    pool("nvme")
    _bad(owner_key(long_owner))
    run()
    (ev,) = events()
    assert ev.detail["reason"] == "internal-witness"
