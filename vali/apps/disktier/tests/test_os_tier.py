"""E1: the OS-disk tier — which pools hold it (`routing`), which nodes
(`os_tier.refusals`, gate (n)), and the pool a launch picks for it."""

from __future__ import annotations

import json
import logging
from types import SimpleNamespace

import pytest
from django.test import override_settings
from django.utils import timezone

from apps.disktier import os_tier, routing
from apps.disktier.models import DiskHealth, MinerStoragePool, PlacementDisk
from apps.scheduler import service as sched
from apps.scheduler.models import MinerCapacity
from apps.scheduler.placement import (
    NO_MINER_AT_TIER,
    DiskTierFit,
    PlacementError,
    decide_placement,
)

pytestmark = pytest.mark.django_db

NODE = "6" * 64
MIN = "v2026.10.17"


def _capacity(node_id: str = NODE, version: str = MIN) -> None:
    now = timezone.now()
    MinerCapacity.objects.update_or_create(
        miner_node_id=node_id,
        defaults=dict(
            status="active",
            capacity_slots=4,
            observed_epoch=10,
            data_epoch=10,
            refreshed_at=now,
            agent_version=version,
            agent_version_reported_at=now,
            host_health_reported_at=now,
        ),
    )


def _pool(pool_id: str, *, node_id: str = NODE, **kw) -> MinerStoragePool:
    fields = dict(
        os_disks=True,
        reported_state="active",
        reported_at=timezone.now(),
        declared_class="nvme",
        available_gb=1000,
        budget_gb=None,
        committed_gb=0,
    )
    fields.update(kw)
    return MinerStoragePool.objects.create(miner_node_id=node_id, pool_id=pool_id, **fields)


# ── which pool holds which tier ─────────────────────────────────────


@pytest.mark.parametrize(
    ("fields", "own"),
    [
        (dict(declared_class="nvme"), "nvme"),
        (dict(declared_class="ssd"), "ssd"),
        (dict(declared_class="hdd"), "hdd"),
        (dict(declared_class=""), None),
        # The probe's verdict wins over the declaration, the override over both.
        (dict(declared_class="nvme", tier="ssd"), "ssd"),
        (dict(declared_class="hdd", tier="nvme"), "nvme"),
        (dict(declared_class="nvme", tier="unfit"), None),
        (dict(tier="hdd", operator_override="ssd"), "ssd"),
        # A probe below the floor takes it out; `suspect` (probe pending) not.
        (dict(health=DiskHealth.SUSPECT), "nvme"),
        (dict(health=DiskHealth.DEGRADED), None),
        (dict(health=DiskHealth.SEVERE), None),
    ],
)
def test_the_tier_a_pool_holds_os_disks_at(fields, own) -> None:
    pool = _pool("p0", **fields)
    assert routing.os_disk_tier_of(pool) == own


def test_a_tier_is_a_minimum_and_an_hdd_pool_holds_only_hdd() -> None:
    held = {
        declared: {t for t in ("nvme", "ssd", "hdd") if routing.serves_os_disk_tier(pool, t)}
        for declared, pool in (
            (c, _pool(f"p-{c}", declared_class=c)) for c in ("nvme", "ssd", "hdd")
        )
    }
    assert held == {"nvme": {"nvme", "ssd", "hdd"}, "ssd": {"ssd", "hdd"}, "hdd": {"hdd"}}
    # The nvme reading is today's `sold_as_os_disk_tier`, unchanged.
    for pool in MinerStoragePool.objects.all():
        assert routing.sold_as_os_disk_tier(pool) == routing.serves_os_disk_tier(pool, "nvme")


# ── the pool a launch picks ─────────────────────────────────────────


@override_settings(VALI_POOL_ROUTING_MIN_AGENT_VERSION=MIN)
def test_the_lowest_adequate_tier_wins_then_the_most_free() -> None:
    _capacity()
    _pool("default", available_gb=5000)
    _pool("nvme0", available_gb=3000)
    _pool("ssd0", declared_class="ssd", available_gb=500)
    _pool("ssd1", declared_class="ssd", available_gb=900)
    _pool("hdd0", declared_class="hdd", available_gb=8000)
    assert routing.choose_os_pool(NODE, 50) == "nvme0", "nvme: as ever"
    assert routing.choose_os_pool(NODE, 50, "nvme") == "nvme0"
    assert routing.choose_os_pool(NODE, 50, "ssd") == "ssd1"
    assert routing.choose_os_pool(NODE, 600, "ssd") == "ssd1"
    assert routing.choose_os_pool(NODE, 950, "ssd") == "nvme0", "no ssd pool has room"
    assert routing.choose_os_pool(NODE, 50, "hdd") == "hdd0"
    assert routing.choose_os_pool(NODE, 9000, "hdd") is None, "only default is left"


@override_settings(VALI_POOL_ROUTING_MIN_AGENT_VERSION=MIN)
def test_an_nvme_os_disk_never_lands_on_a_slower_pool() -> None:
    _capacity()
    _pool("ssd0", declared_class="ssd")
    _pool("hdd0", declared_class="hdd")
    assert routing.choose_os_pool(NODE, 10) is None
    assert routing.choose_os_pool(NODE, 10, "ssd") == "ssd0"


@override_settings(VALI_POOL_ROUTING_MIN_AGENT_VERSION=MIN)
def test_default_wins_when_it_is_the_lower_adequate_tier() -> None:
    _capacity()
    _pool("default", declared_class="ssd")
    _pool("nvme0")
    assert routing.choose_os_pool(NODE, 10, "ssd") is None, "default (ssd) before nvme0"
    assert routing.choose_os_pool(NODE, 10) == "nvme0", "an nvme disk is not held by default"
    MinerStoragePool.objects.filter(pool_id="default").delete()
    # Other rows but none for `default`: it holds nothing (only a node with
    # no pool row at all, a pre-v7 single pool, reads it nvme).
    assert routing.default_pool_tier(NODE) is None
    assert routing.choose_os_pool(NODE, 10, "ssd") == "nvme0"
    MinerStoragePool.objects.all().delete()
    assert routing.default_pool_tier(NODE) == "nvme"
    _pool("ssd0", declared_class="ssd")
    assert routing.choose_os_pool(NODE, 10, "ssd") == "ssd0"


# ── gate (n): which nodes hold the tier ─────────────────────────────


def test_a_node_without_pool_rows_holds_every_tier() -> None:
    """A pre-v7 node: one `default`, sold nvme as every OS disk was."""
    assert os_tier.refusals([NODE], "nvme", 100) == {}
    assert os_tier.refusals([NODE], "hdd", 100) == {}


@pytest.mark.parametrize(
    ("default", "held"),
    [
        (dict(declared_class="nvme"), {"nvme", "ssd", "hdd"}),
        (dict(declared_class="ssd"), {"ssd", "hdd"}),
        (dict(declared_class="hdd"), {"hdd"}),
        (dict(declared_class="nvme", tier="ssd"), {"ssd", "hdd"}),
        (dict(declared_class=""), set()),
        (dict(health=DiskHealth.DEGRADED), set()),
        (dict(os_disks=False), set()),
        # Retired: no `default` row any more, the pre-v7 reading.
        (dict(declared_class="hdd", retired_at=timezone.now()), {"nvme", "ssd", "hdd"}),
    ],
)
def test_default_holds_the_tier_it_is(default, held) -> None:
    _pool("default", **default)
    assert {t for t in ("nvme", "ssd", "hdd") if not os_tier.refusal(NODE, t, 50)} == held


@override_settings(VALI_POOL_ROUTING_MIN_AGENT_VERSION=MIN)
def test_another_pool_holds_the_tier_only_with_room_and_an_agent_that_takes_it() -> None:
    _capacity()
    _pool("default", declared_class="hdd")
    _pool("ssd0", declared_class="ssd", available_gb=300)
    assert os_tier.refusal(NODE, "ssd", 200) == ""
    assert "no OS pool at ssd" in os_tier.refusal(NODE, "ssd", 400)
    assert os_tier.refusal(NODE, "nvme", 10), "ssd0 holds no nvme disk"
    with override_settings(VALI_POOL_ROUTING_MIN_AGENT_VERSION=""):
        assert os_tier.refusal(NODE, "ssd", 200), "the agent cannot be sent ssd0"
    MinerStoragePool.objects.filter(pool_id="ssd0").update(reported_state="draining")
    assert os_tier.refusal(NODE, "ssd", 200)


@override_settings(VALI_POOL_ROUTING_MIN_AGENT_VERSION=MIN)
def test_refusals_is_two_queries_for_many_nodes(django_assert_num_queries) -> None:
    other, third = "7" * 64, "8" * 64
    _capacity(other)
    _pool("default", declared_class="ssd")
    _pool("default", node_id=other, declared_class="ssd")
    _pool("nvme0", node_id=other)
    # Its agent reports no version (no `os_pool`), and a node with pool rows
    # but no `default` row holds nothing there: refused.
    _pool("nvme0", node_id=third)
    with django_assert_num_queries(2):
        out = os_tier.refusals([NODE, other, third, "9" * 64], "nvme", 10)
    assert set(out) == {NODE, third}


# ── gate (n) in `decide_placement` ──────────────────────────────────


def _snapshot(*node_ids: str):
    return SimpleNamespace(
        current_epoch=10,
        pallet_live=True,
        miners=[
            SimpleNamespace(node_id=n, status="active", data_epoch=10, quality=0)
            for n in node_ids
        ],
    )


def _decide(snapshot, **kw):
    nodes = [m.node_id for m in snapshot.miners]
    return decide_placement(
        snapshot=snapshot,
        capacity_by_node={n: 4 for n in nodes},
        load_by_node={},
        family_load_by_node={},
        max_epoch_lag=5,
        **kw,
    )


def test_enforced_the_gate_removes_a_node_without_the_tier() -> None:
    snap = _snapshot("aa", "bb")
    fit = DiskTierFit(mode="enforce", tier="ssd", refusal_by_node={"aa": "no ssd pool"})
    assert _decide(snap, disk_tier_fit=fit) == "bb"
    with pytest.raises(PlacementError) as exc:
        _decide(snap, disk_tier_fit=DiskTierFit("enforce", "ssd", {"aa": "x", "bb": "y"}))
    assert exc.value.category == NO_MINER_AT_TIER
    assert "'ssd'" in exc.value.message


def test_recorded_the_gate_logs_and_admits(caplog, monkeypatch) -> None:
    monkeypatch.setattr(logging.getLogger("apps"), "propagate", True)
    snap = _snapshot("aa")
    fit = DiskTierFit(mode="record", tier="nvme", refusal_by_node={"aa": "default pool: ssd"})
    with caplog.at_level(logging.WARNING, logger="apps.scheduler.placement"):
        assert _decide(snap, disk_tier_fit=fit) == "aa"
    events = [json.loads(r.getMessage()) for r in caplog.records if "disk_tier" in r.getMessage()]
    assert events == [
        {
            "event": "disk_tier_gate_would_reject",
            "node_id": "aa",
            "os_disk_tier": "nvme",
            "reason": "default pool: ssd",
        }
    ]


def test_another_gate_emptying_the_set_is_not_blamed_on_the_tier() -> None:
    snap = _snapshot("aa", "bb")
    fit = DiskTierFit(mode="enforce", tier="ssd", refusal_by_node={"aa": "x"})
    with pytest.raises(PlacementError) as exc:
        _decide(snap, disk_tier_fit=fit, region="FR", region_by_node={"aa": "FR"})
    assert exc.value.category == NO_MINER_AT_TIER, "aa was the only one in FR"
    with pytest.raises(PlacementError) as exc:
        _decide(snap, disk_tier_fit=fit, cordoned={"bb": "maintenance"})
    assert exc.value.category == NO_MINER_AT_TIER
    with pytest.raises(PlacementError) as exc:
        _decide(snap, disk_tier_fit=fit, excluded=frozenset({"bb"}), dispatchable=frozenset())
    assert exc.value.category != NO_MINER_AT_TIER, "nothing reached the gate"


# ── the gate's arguments ────────────────────────────────────────────


def _base() -> dict:
    snap = SimpleNamespace(current_epoch=10, pallet_live=True, miners=[])
    return dict(snapshot=snap, tenant_id="t", user_id="u", flavor="small", shadow_log=False)


def test_off_the_gate_adds_nothing_and_reads_nothing(settings, django_assert_num_queries) -> None:
    assert settings.VALI_SCHEDULER_DISK_TIER_GATE == "off"
    assert "disk_tier_fit" not in sched.placement_arguments(**_base(), os_disk_tier="ssd")
    with django_assert_num_queries(0):
        assert sched.disk_tier_arguments("small", vm_id="vm-x", os_disk_tier="ssd") == {}


@override_settings(VALI_SCHEDULER_DISK_TIER_GATE="record")
def test_the_tier_is_the_launchs_unless_named(monkeypatch) -> None:
    from apps.orchestration.tests.factories import make_launch_record, make_vm

    monkeypatch.setattr(sched, "dispatchable_node_ids", lambda: frozenset({NODE}))
    _pool("default", declared_class="ssd")
    plain = sched.disk_tier_arguments("small", vm_id="")["disk_tier_fit"]
    assert (plain.mode, plain.tier, set(plain.refusal_by_node)) == ("record", "nvme", {NODE})
    vm = make_vm("vm-ssd")
    make_launch_record(vm, os_disk_tier="ssd")
    fit = sched.placement_arguments(**_base(), vm_id=vm.vm_id)["disk_tier_fit"]
    assert (fit.tier, dict(fit.refusal_by_node)) == ("ssd", {})
    named = sched.disk_tier_arguments("small", vm_id=vm.vm_id, os_disk_tier="nvme")
    assert named["disk_tier_fit"].tier == "nvme"
    # A legacy record (no key) is nvme.
    legacy = make_vm("vm-legacy")
    make_launch_record(legacy)
    assert os_tier.launch_tier(legacy.vm_id) == "nvme"


# ── the disk rows ───────────────────────────────────────────────────


def test_a_bound_placement_records_the_tier_its_vm_was_sold_at() -> None:
    from apps.orchestration.services import launch
    from apps.orchestration.tests.factories import make_launch_record, make_vm
    from apps.scheduler.tests.factories import make_placement

    vm = make_vm("vm-ssd-disk")
    make_launch_record(vm, os_disk_tier="ssd")
    placement = make_placement(vm, NODE, resource_class="small")
    launch._bind_placement(
        placement,
        launch.LaunchOutcome(
            disposition=launch.ACCEPTED, emit={}, exit_code=0, ticket_id="t", os_pool="ssd0"
        ),
    )
    disk = PlacementDisk.objects.get(placement_id=placement.id)
    assert (disk.pool_id, disk.required_tier) == ("ssd0", "ssd")


def test_node_ids_match_whatever_their_case() -> None:
    lower = "ab" * 32
    _pool("default", node_id=lower, declared_class="ssd")
    upper = lower.upper()
    assert set(os_tier.refusals([upper], "nvme", 10)) == {upper}
    assert os_tier.refusals([upper], "ssd", 10) == {}


@override_settings(VALI_SCHEDULER_DISK_TIER_GATE="record", VALI_POOL_ROUTING_MIN_AGENT_VERSION=MIN)
def test_the_gate_sizes_the_vms_own_disk(monkeypatch) -> None:
    """The flavor's disk plus the rootfs; a resized VM's launch disk."""
    from apps.orchestration.services import flavors, launch_record
    from apps.scheduler.service import placement_disk_gb

    monkeypatch.setattr(sched, "dispatchable_node_ids", lambda: frozenset({NODE}))
    _capacity()
    _pool("default", declared_class="hdd")
    need = placement_disk_gb("small", None)
    assert need == flavors.resolve_flavor("small").data_disk_size_gb + flavors.ROOTFS_DISK_GB
    _pool("ssd0", declared_class="ssd", available_gb=need)
    fit = sched.disk_tier_arguments("small", os_disk_tier="ssd")["disk_tier_fit"]
    assert dict(fit.refusal_by_node) == {}
    MinerStoragePool.objects.filter(pool_id="ssd0").update(available_gb=need - 1)
    fit = sched.disk_tier_arguments("small", os_disk_tier="ssd")["disk_tier_fit"]
    assert set(fit.refusal_by_node) == {NODE}
    # A VM that kept a bigger launch disk is sized at it.
    MinerStoragePool.objects.filter(pool_id="ssd0").update(available_gb=need)
    monkeypatch.setattr(launch_record, "vm_data_disk_gb", lambda vm_id: 500)
    fit = sched.disk_tier_arguments("small", vm_id="vm-big", os_disk_tier="ssd")["disk_tier_fit"]
    assert set(fit.refusal_by_node) == {NODE}
    assert f"with {placement_disk_gb('small', 500)} GiB" in fit.refusal_by_node[NODE]


@override_settings(VALI_SCHEDULER_DISK_TIER_GATE="record", VALI_POOL_ROUTING_MIN_AGENT_VERSION=MIN)
def test_a_legacy_disk_is_judged_on_default_alone(monkeypatch) -> None:
    """A legacy LUKS launch never names a pool: its disk lands on `default`."""
    from apps.orchestration.tests.factories import make_launch_record, make_vm

    monkeypatch.setattr(sched, "dispatchable_node_ids", lambda: frozenset({NODE}))
    _capacity()
    _pool("default", declared_class="hdd")
    _pool("ssd0", declared_class="ssd")
    golden, legacy = make_vm("vm-golden"), make_vm("vm-luks")
    make_launch_record(golden, disk_mode="golden_verity_overlay", os_disk_tier="ssd")
    make_launch_record(legacy, disk_mode="legacy_luks", os_disk_tier="ssd")
    fit = sched.disk_tier_arguments("small", vm_id=golden.vm_id)["disk_tier_fit"]
    assert dict(fit.refusal_by_node) == {}
    fit = sched.disk_tier_arguments("small", vm_id=legacy.vm_id)["disk_tier_fit"]
    assert set(fit.refusal_by_node) == {NODE}
    assert set(os_tier.refusals([NODE], "ssd", 10, default_only=True)) == {NODE}


def test_a_tier_refusal_at_dispatch_never_counts_against_the_miner(settings) -> None:
    """Gate (n)'s own `no-os-pool-at-tier` leaves a FAILED placement; the
    circuit breaker must not route around the miner for it (it would, for
    every VM, nvme included)."""
    from apps.orchestration.services.launch import NO_OS_POOL_AT_TIER
    from apps.orchestration.tests.factories import make_vm
    from apps.scheduler.models import Placement, PlacementStatus
    from apps.scheduler.tests.factories import make_placement

    settings.VALI_SCHEDULER_MAX_RECENT_FAILURES = 1
    settings.VALI_SCHEDULER_FAILURE_WINDOW_S = 600
    rows = [
        make_placement(make_vm(f"vm-t{i}"), NODE, status=PlacementStatus.FAILED.value)
        for i in range(3)
    ]
    Placement.objects.filter(pk__in=[r.pk for r in rows[:2]]).update(reason=NO_OS_POOL_AT_TIER)
    assert sched.recent_failures_by_node() == {NODE: 1}
