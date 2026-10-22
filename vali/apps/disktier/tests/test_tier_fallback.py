"""The OS-disk tier fallback for our own runners (`VALI_DISK_TIER_FALLBACK_OWNERS`,
`os_tier.may_fall_back`): under `enforce`, an owner in the list whose VM no
candidate holds at its sold tier is placed at the first lower tier some
candidate holds — never as a preference, never for a customer — and every
record (disk row, billing binding, log, gauge) says where the disk landed
while `spec_json` keeps the sold tier."""

from __future__ import annotations

import json
import logging
from types import SimpleNamespace

import pytest
from django.test import override_settings

from apps.disktier import os_tier
from apps.disktier.models import MinerStoragePool, PlacementDisk
from apps.disktier.tests.test_os_tier import _capacity, _pool, _snapshot
from apps.scheduler import service as sched
from apps.scheduler.placement import (
    MINERS_BOOTING,
    NO_MINER_AT_TIER,
    DiskTierFit,
    PlacementError,
)

pytestmark = pytest.mark.django_db

RUNNER = "1334"
MIN = "v2026.10.17"
ENFORCE = override_settings(
    VALI_SCHEDULER_DISK_TIER_GATE="enforce",
    VALI_DISK_TIER_FALLBACK_OWNERS=[RUNNER],
    VALI_POOL_ROUTING_MIN_AGENT_VERSION=MIN,
)


@pytest.fixture
def events(caplog, monkeypatch):
    monkeypatch.setattr(logging.getLogger("apps"), "propagate", True)
    caplog.set_level(logging.WARNING, logger="apps.disktier.os_tier")

    def read() -> list[dict]:
        return [
            json.loads(r.getMessage())
            for r in caplog.records
            if '"disk_tier_fallback"' in r.getMessage()
        ]

    return read


# ── who may fall back ───────────────────────────────────────────────


@ENFORCE
@pytest.mark.parametrize(
    ("owner", "allowed"),
    [
        (RUNNER, True),
        # Listed for a different id.
        ("1335", False),
        ("13340", False),
        ("01334", False),
        (" 1334", False),
        # No owner at all.
        ("", False),
        (None, False),
        # The owner vali stores is a string: a number never matches.
        (1334, False),
    ],
)
def test_only_a_listed_owner_may_fall_back(owner, allowed) -> None:
    assert os_tier.may_fall_back(owner) is allowed


@pytest.mark.parametrize("mode", ["off", "record"])
def test_never_unless_the_gate_is_enforced(mode) -> None:
    with override_settings(
        VALI_SCHEDULER_DISK_TIER_GATE=mode, VALI_DISK_TIER_FALLBACK_OWNERS=[RUNNER]
    ):
        assert os_tier.may_fall_back(RUNNER) is False


def test_nobody_by_default(settings) -> None:
    assert settings.VALI_DISK_TIER_FALLBACK_OWNERS == []
    with override_settings(VALI_SCHEDULER_DISK_TIER_GATE="enforce"):
        assert os_tier.may_fall_back(RUNNER) is False


def test_a_numeric_list_entry_is_its_string() -> None:
    with override_settings(
        VALI_SCHEDULER_DISK_TIER_GATE="enforce", VALI_DISK_TIER_FALLBACK_OWNERS=[1334]
    ):
        assert os_tier.may_fall_back("1334") is True
        assert os_tier.may_fall_back(1334) is False


def test_the_tiers_below() -> None:
    assert os_tier.lower_tiers("nvme") == ("ssd", "hdd")
    assert os_tier.lower_tiers("ssd") == ("hdd",)
    assert os_tier.lower_tiers("hdd") == ()


# ── the tier a node takes the disk at ───────────────────────────────

NODE = "6" * 64


@ENFORCE
@pytest.mark.parametrize(
    ("default", "landed"),
    [("nvme", "nvme"), ("ssd", "ssd"), ("hdd", "hdd"), ("", "nvme")],
)
def test_the_landing_tier_is_the_sold_one_else_the_first_lower_held(default, landed) -> None:
    _pool("default", declared_class=default)
    assert os_tier.landing_tier(NODE, "nvme", 50, RUNNER) == landed
    # A customer's never moves: the gate refuses it as ever.
    assert os_tier.landing_tier(NODE, "nvme", 50, "42") == "nvme"


@ENFORCE
def test_the_landing_tier_counts_room_on_a_pool_other_than_default() -> None:
    _capacity()
    _pool("default", declared_class="hdd")
    _pool("ssd0", declared_class="ssd", available_gb=100)
    assert os_tier.landing_tier(NODE, "nvme", 100, RUNNER) == "ssd"
    assert os_tier.landing_tier(NODE, "nvme", 101, RUNNER) == "hdd"
    assert os_tier.landing_tier(NODE, "ssd", 100, RUNNER) == "ssd"


def test_off_the_landing_tier_reads_nothing(django_assert_num_queries) -> None:
    with django_assert_num_queries(0):
        assert os_tier.landing_tier(NODE, "nvme", 50, RUNNER) == "nvme"
        assert os_tier.fallback_owner_of("vm-x") == ""
        assert os_tier.fallback_vm_counts() == {"ssd": 0, "hdd": 0}


# ── gate (n)'s arguments carry the fallbacks for that owner only ────


def _args(owner: str) -> DiskTierFit:
    return sched.disk_tier_arguments("small", owner=owner)["disk_tier_fit"]


@ENFORCE
def test_the_fallbacks_ride_the_gate_for_a_listed_owner_only(monkeypatch) -> None:
    monkeypatch.setattr(sched, "dispatchable_node_ids", lambda: frozenset({NODE}))
    _pool("default", declared_class="ssd")
    runner = _args(RUNNER)
    assert (runner.tier, set(runner.refusal_by_node)) == ("nvme", {NODE})
    assert [(f.tier, dict(f.refusal_by_node), f.fallbacks) for f in runner.fallbacks] == [
        ("ssd", {}, ()),
        ("hdd", {}, ()),
    ]
    for customer in ("42", "", "13340"):
        assert _args(customer).fallbacks == ()
    base = dict(snapshot=_snapshot(), tenant_id="t", flavor="small", shadow_log=False)
    fit = sched.placement_arguments(**base, user_id=RUNNER)["disk_tier_fit"]
    assert [f.tier for f in fit.fallbacks] == ["ssd", "hdd"], "the launch's owner"
    assert sched.placement_arguments(**base, user_id="42")["disk_tier_fit"].fallbacks == ()


@override_settings(VALI_SCHEDULER_DISK_TIER_GATE="record", VALI_DISK_TIER_FALLBACK_OWNERS=[RUNNER])
def test_recorded_no_fallback_rides_the_gate(monkeypatch) -> None:
    monkeypatch.setattr(sched, "dispatchable_node_ids", lambda: frozenset({NODE}))
    assert _args(RUNNER).fallbacks == ()


# ── decide_placement: the sold tier first, then the first lower that fits ──


def _decide(snapshot, **kw):
    from apps.scheduler.placement import decide_placement

    nodes = [m.node_id for m in snapshot.miners]
    args = dict(
        capacity_by_node={n: 4 for n in nodes},
        load_by_node={},
        family_load_by_node={},
        max_epoch_lag=5,
    )
    args.update(kw)
    return decide_placement(snapshot=snapshot, **args)


def _fit(refusals: dict, *fallbacks: DiskTierFit, tier: str = "nvme") -> DiskTierFit:
    return DiskTierFit("enforce", tier, refusals, fallbacks)


def test_a_node_at_the_sold_tier_wins_over_any_lower_one() -> None:
    snap = _snapshot("aa", "bb")
    # bb ranks first (merit) but holds only ssd: aa, at nvme, is chosen.
    snap.miners[1].quality = 1000
    fit = _fit({"bb": "x"}, _fit({}, tier="ssd"))
    assert _decide(snap, disk_tier_fit=fit) == "aa"


def test_with_no_node_at_the_sold_tier_the_first_lower_tier_that_fits_wins() -> None:
    snap = _snapshot("aa", "bb")
    snap.miners[1].quality = 1000  # bb, hdd only, ranks first
    fit = _fit(
        {"aa": "x", "bb": "x"},
        _fit({"bb": "x"}, tier="ssd"),
        _fit({}, tier="hdd"),
    )
    assert _decide(snap, disk_tier_fit=fit) == "aa", "ssd before hdd"
    fit = _fit(
        {"aa": "x", "bb": "x"}, _fit({"aa": "x", "bb": "x"}, tier="ssd"), _fit({}, tier="hdd")
    )
    assert _decide(snap, disk_tier_fit=fit) == "bb"


def test_without_fallbacks_the_gate_refuses_as_ever() -> None:
    snap = _snapshot("aa")
    with pytest.raises(PlacementError) as exc:
        _decide(snap, disk_tier_fit=_fit({"aa": "x"}))
    assert exc.value.category == NO_MINER_AT_TIER


def test_every_tier_refusing_raises_the_sold_tiers_error() -> None:
    snap = _snapshot("aa")
    fit = _fit({"aa": "x"}, _fit({"aa": "x"}, tier="ssd"), _fit({"aa": "x"}, tier="hdd"))
    with pytest.raises(PlacementError) as exc:
        _decide(snap, disk_tier_fit=fit)
    assert exc.value.category == NO_MINER_AT_TIER
    assert "'nvme'" in exc.value.message


def test_a_boot_wait_at_the_sold_tier_waits_rather_than_falls_back() -> None:
    snap = _snapshot("aa", "bb")
    fit = _fit({"bb": "x"}, _fit({}, tier="ssd"))
    with pytest.raises(PlacementError) as exc:
        _decide(
            snap,
            disk_tier_fit=fit,
            booting_by_node={"aa": 3},
            max_booting_per_node=3,
        )
    assert exc.value.category == MINERS_BOOTING


def test_a_boot_wait_at_the_first_lower_tier_waits_rather_than_skips_it() -> None:
    snap = _snapshot("aa", "bb")
    fit = _fit({"aa": "x", "bb": "x"}, _fit({"bb": "x"}, tier="ssd"), _fit({}, tier="hdd"))
    with pytest.raises(PlacementError) as exc:
        _decide(snap, disk_tier_fit=fit, booting_by_node={"aa": 3}, max_booting_per_node=3)
    assert exc.value.category == MINERS_BOOTING, "aa (ssd) is booting: not bb (hdd)"


def test_another_refusal_at_the_sold_tier_still_falls_back() -> None:
    """aa holds nvme but has no slot left: nothing can take the VM at its
    sold tier, so bb (ssd) does."""
    snap = _snapshot("aa", "bb")
    fit = _fit({"bb": "x"}, _fit({}, tier="ssd"))
    full = {"aa": 0, "bb": 4}
    assert _decide(snap, disk_tier_fit=fit, capacity_by_node=full) == "bb"
    with pytest.raises(PlacementError) as exc:
        _decide(snap, disk_tier_fit=_fit({"bb": "x"}), capacity_by_node=full)
    assert exc.value.category != NO_MINER_AT_TIER


# ── the launch ──────────────────────────────────────────────────────


@ENFORCE
def test_the_attempt_carries_the_tier_the_decision_placed_at_and_nothing_else() -> None:
    from apps.disktier.tests.test_routing import _spec
    from apps.orchestration.services import launch

    fit = _fit({"bb": "x", "cc": "x"}, _fit({"cc": "x"}, tier="ssd"), _fit({}, tier="hdd"))
    runner = _spec(user_id=RUNNER)
    assert launch._at_decided_tier(runner, fit, "aa") is runner, "decided at the sold tier"
    assert launch._at_decided_tier(runner, fit, "bb").placed_os_disk_tier == "ssd"
    assert launch._at_decided_tier(runner, fit, "cc").placed_os_disk_tier == "hdd"
    assert launch._at_decided_tier(runner, _fit({"aa": "x"}), "aa") is runner, "no fallbacks"
    assert launch._at_decided_tier(runner, None, "aa") is runner
    customer = _spec(user_id="42")
    assert launch._at_decided_tier(customer, fit, "bb") is customer
    ssd_runner = _spec(user_id=RUNNER, os_disk_tier="ssd")
    assert launch._at_decided_tier(ssd_runner, fit, "bb") is ssd_runner, "ssd is its sold tier"


@ENFORCE
def test_a_node_that_lost_the_sold_tier_after_the_decision_is_replaced_not_fallen_back(
    monkeypatch,
) -> None:
    """The decision placed the VM at its sold tier; by dispatch the node's
    nvme pool is gone. The attempt re-places (as for any VM), it does not
    quietly drop to the node's ssd default."""
    from apps.scheduler import service as scheduler_service

    miner, seen = _launch_rig(monkeypatch, default="ssd", ssd_pool=False)
    _pool("nvme0", node_id=miner.chain_node_id, available_gb=3200)
    real = scheduler_service.placement_arguments

    def then_lose_nvme0(**kw):
        arguments = real(**kw)
        MinerStoragePool.objects.filter(pool_id="nvme0").delete()
        return arguments

    monkeypatch.setattr(scheduler_service, "placement_arguments", then_lose_nvme0)
    _, result = _launch(RUNNER)
    assert not result.ok
    assert result.attempts[0]["disposition"] == "retriable"
    assert seen["launch"] == []
    assert not PlacementDisk.objects.exists()


def _launch_rig(monkeypatch, *, default: str, ssd_pool: bool):
    """The routing rig's miner, its `default` pool at `default`, no nvme
    pool, an ssd pool `ssd0` when asked; one chain miner, dispatchable."""
    from apps.disktier.tests.test_routing import _rig
    from apps.scheduler import chain
    from apps.scheduler.tests.factories import make_miner, make_snapshot

    miner, seen = _rig(monkeypatch)
    MinerStoragePool.objects.filter(pool_id="nvme0").delete()
    MinerStoragePool.objects.filter(pool_id="default").update(declared_class=default)
    if ssd_pool:
        _pool("ssd0", node_id=miner.chain_node_id, declared_class="ssd", available_gb=3200)
    monkeypatch.setattr(chain, "read_miner_status", lambda: make_snapshot(10, [make_miner(1)]))
    return miner, seen


def _launch(owner: str, **kw):
    from apps.disktier.tests.test_routing import _spec
    from apps.identity.models import PrincipalScope, ServiceClient
    from apps.orchestration.services import launch

    actor = ServiceClient.objects.create(scope=PrincipalScope.OPERATOR.value, name="launcher")
    spec = _spec(user_id=owner, **kw)
    return spec, launch.launch_vm(spec, actor)


@ENFORCE
def test_a_runner_launch_falls_back_to_the_pool_the_node_has_and_records_it(
    monkeypatch, events
) -> None:
    from apps.scheduler.models import Placement, VmBillingBinding

    miner, seen = _launch_rig(monkeypatch, default="hdd", ssd_pool=True)
    spec, result = _launch(RUNNER)
    assert result.ok, result.emit
    # The pool at the fallback tier, the same in the preflight and the order.
    assert seen == {"preflight": ["ssd0"], "launch": ["ssd0"]}
    placement = Placement.objects.get(vm__vm_id=spec.vm_id)
    disk = PlacementDisk.objects.get(placement=placement)
    assert (disk.pool_id, disk.required_tier) == ("ssd0", "ssd")
    assert VmBillingBinding.objects.get(vm_id=spec.vm_id).os_disk_tier == "ssd"
    assert spec.os_disk_tier == "" and spec.placed_os_disk_tier == "", "the sold tier is kept"
    assert events() == [
        {
            "event": "disk_tier_fallback",
            "vm_id": spec.vm_id,
            "owner": RUNNER,
            "node_id": miner.chain_node_id,
            "os_disk_tier": "nvme",
            "placed_tier": "ssd",
            "context": "launch",
        }
    ]


@ENFORCE
def test_a_runner_landing_on_default_records_its_tier_there(monkeypatch, events) -> None:
    from apps.scheduler.models import VmBillingBinding

    _launch_rig(monkeypatch, default="hdd", ssd_pool=False)
    spec, result = _launch(RUNNER)
    assert result.ok, result.emit
    disk = PlacementDisk.objects.get()
    assert (disk.pool_id, disk.required_tier) == ("default", "hdd")
    assert VmBillingBinding.objects.get(vm_id=spec.vm_id).os_disk_tier == "hdd"
    assert [e["placed_tier"] for e in events()] == ["hdd"]


@ENFORCE
@pytest.mark.parametrize("owner", ["42", "", "13340", "01334"])
def test_a_customer_launch_never_falls_back(monkeypatch, events, owner) -> None:
    from apps.scheduler.models import VmBillingBinding

    _, seen = _launch_rig(monkeypatch, default="hdd", ssd_pool=True)
    _, result = _launch(owner)
    assert not result.ok
    assert result.outcome == NO_MINER_AT_TIER
    assert seen["launch"] == [] and not VmBillingBinding.objects.exists()
    assert events() == []


@ENFORCE
def test_a_runner_at_a_node_with_its_sold_tier_is_as_before(monkeypatch, events) -> None:
    from apps.scheduler.models import VmBillingBinding

    miner, seen = _launch_rig(monkeypatch, default="nvme", ssd_pool=True)
    spec, result = _launch(RUNNER)
    assert result.ok, result.emit
    assert seen["launch"] == [None], "nvme default before the ssd pool"
    assert not PlacementDisk.objects.exists()
    assert VmBillingBinding.objects.get(vm_id=spec.vm_id).os_disk_tier == "nvme"
    assert events() == []


@ENFORCE
def test_an_ssd_sold_runner_falls_to_hdd_only(monkeypatch) -> None:
    from apps.scheduler.models import VmBillingBinding

    _launch_rig(monkeypatch, default="hdd", ssd_pool=False)
    spec, result = _launch(RUNNER, os_disk_tier="ssd")
    assert result.ok, result.emit
    assert VmBillingBinding.objects.get(vm_id=spec.vm_id).os_disk_tier == "hdd"
    assert PlacementDisk.objects.get().required_tier == "hdd"


# ── a relaunch keeps the tier the disk is at ────────────────────────


@pytest.mark.parametrize(
    ("overrides", "row", "binding"),
    [
        # A runner's disk recorded at ssd: bound at ssd.
        (dict(VALI_DISK_TIER_FALLBACK_OWNERS=[RUNNER]), "ssd", "ssd"),
        # Still where it is once the owner left the list or the gate left
        # `enforce`: the binding follows the disk, not the config.
        (dict(VALI_DISK_TIER_FALLBACK_OWNERS=[]), "ssd", "ssd"),
        (dict(VALI_SCHEDULER_DISK_TIER_GATE="off"), "ssd", "ssd"),
        # A row at the sold tier, or none: the sold tier, as ever.
        (dict(VALI_DISK_TIER_FALLBACK_OWNERS=[RUNNER]), "nvme", "nvme"),
        (dict(VALI_DISK_TIER_FALLBACK_OWNERS=[RUNNER]), None, "nvme"),
    ],
)
def test_a_relaunch_binds_the_tier_its_disk_was_recorded_at(
    monkeypatch, overrides, row, binding
) -> None:
    from apps.disktier.models import DiskKind
    from apps.disktier.tests.test_routing import _rig, _spec
    from apps.orchestration.services import launch
    from apps.orchestration.tests.factories import make_vm
    from apps.scheduler.models import PlacementStatus, VmBillingBinding
    from apps.scheduler.tests.factories import make_placement

    miner, _ = _rig(monkeypatch)
    spec = _spec(user_id=RUNNER)
    vm = make_vm(spec.vm_id, host=miner.miner_id, generation=1)
    placement = make_placement(
        vm, miner.chain_node_id, status=PlacementStatus.BOUND.value, owner=RUNNER
    )
    if row:
        PlacementDisk.objects.create(
            placement=placement,
            slot="os",
            kind=DiskKind.POOL,
            pool_id="ssd0",
            size_gb=50,
            required_tier=row,
        )
    settings = dict(
        VALI_SCHEDULER_DISK_TIER_GATE="enforce", VALI_POOL_ROUTING_MIN_AGENT_VERSION=MIN
    )
    with override_settings(**{**settings, **overrides}):
        out = launch.launch_on_miner(spec, miner, require_existing_disks=True)
    assert out.disposition == launch.ACCEPTED, out.emit
    assert VmBillingBinding.objects.get(vm_id=spec.vm_id).os_disk_tier == binding


# ── §25: destination, arrival pool, record ──────────────────────────


def _vm_on(node: str, owner: str, *, tier: str | None = None):
    from apps.orchestration.tests.factories import make_launch_record, make_vm
    from apps.scheduler.models import PlacementStatus
    from apps.scheduler.tests.factories import make_placement

    vm = make_vm(f"vm-{owner or 'none'}-{tier or 'nvme'}", host="node-src")
    make_launch_record(vm, os_disk_tier=tier)
    placement = make_placement(vm, node, status=PlacementStatus.BOUND.value, owner=owner)
    return vm, placement


def _dest(default: str) -> str:
    from apps.miners.models import MinerIdentity

    dest = "d" * 64
    MinerIdentity.objects.create(
        miner_id="node-dst", pubkey_hex="bb" * 32, platform_id="22" * 64, chain_node_id=dest
    )
    _pool("default", node_id=dest, declared_class=default)
    return dest


@ENFORCE
@pytest.mark.parametrize(
    ("owner", "default", "refused"),
    [
        (RUNNER, "ssd", False),
        (RUNNER, "hdd", False),
        (RUNNER, "", True),  # holds no tier at all
        ("42", "ssd", True),
        ("", "ssd", True),
    ],
)
def test_a_named_destination_below_the_sold_tier_is_taken_for_a_runner_only(
    owner, default, refused
) -> None:
    from apps.orchestration import service

    _dest(default)
    vm, _ = _vm_on("c" * 64, owner)
    if refused:
        with pytest.raises(service.StartError) as exc:
            service._reject_disk_tier_dest(vm, "node-dst")
        assert exc.value.category == os_tier.CATEGORY_NO_MINER_AT_TIER
    else:
        service._reject_disk_tier_dest(vm, "node-dst")


@ENFORCE
def test_a_runner_arrives_on_a_pool_at_the_tier_it_lands_at(monkeypatch) -> None:
    from apps.orchestration import effects

    dest = _dest("hdd")
    _capacity(dest)
    _pool("ssd0", node_id=dest, declared_class="ssd", available_gb=500)
    golden = f"ro dm-verity.root={'e' * 64} hippius.disk_gb=40"
    monkeypatch.setattr(effects, "_launch_paths", lambda vm: {"cmdline": golden})
    runner, _ = _vm_on("c" * 64, RUNNER)
    customer, _ = _vm_on("c" * 64, "42")
    assert effects.arrival_os_pool(runner, "node-dst") == "ssd0"
    assert effects.arrival_os_pool(customer, "node-dst") is None
    assert effects._arrival_os_pool("node-dst", golden, "nvme", RUNNER) == "ssd0"
    assert effects._arrival_os_pool("node-dst", golden, "nvme", "") is None


@ENFORCE
@pytest.mark.parametrize(("pool", "default", "tier"), [("", "ssd", "ssd"), ("", "nvme", "nvme")])
def test_a_runners_arrival_records_its_tier_and_binding(events, pool, default, tier) -> None:
    from apps.orchestration import service
    from apps.scheduler.models import VmBillingBinding

    dest = _dest(default)
    vm, placement = _vm_on(dest, RUNNER)
    VmBillingBinding.objects.create(
        vm_id=vm.vm_id, node_id_hex=dest, resource_class="small", lease_id="l", os_disk_tier="hdd"
    )
    job = SimpleNamespace(vm=vm, dest_os_pool=pool, job_id="job-1")
    service._record_dest_os_pool(job, placement)
    disk = PlacementDisk.objects.get(placement=placement)
    assert (disk.pool_id, disk.required_tier) == ("default", tier)
    assert VmBillingBinding.objects.get(vm_id=vm.vm_id).os_disk_tier == tier
    assert [e["context"] for e in events()] == (["migration"] if tier != "nvme" else [])


@ENFORCE
def test_a_failing_arrival_record_never_fails_the_activation(monkeypatch) -> None:
    from django.db import transaction

    from apps.orchestration import service
    from apps.scheduler.models import Placement

    dest = _dest("ssd")
    vm, placement = _vm_on(dest, RUNNER)

    def broken(*a, **k):
        raise RuntimeError("pool table unreadable")

    monkeypatch.setattr(os_tier, "held_tier", broken)
    with transaction.atomic():
        service._record_dest_os_pool(SimpleNamespace(vm=vm, dest_os_pool="", job_id="j"), placement)
        assert Placement.objects.filter(pk=placement.pk).exists(), "the transaction lives on"
    assert not PlacementDisk.objects.exists()


@ENFORCE
def test_a_customers_arrival_records_as_before(events) -> None:
    from apps.orchestration import service

    dest = _dest("ssd")
    vm, placement = _vm_on(dest, "42", tier="ssd")
    service._record_dest_os_pool(SimpleNamespace(vm=vm, dest_os_pool="", job_id="j"), placement)
    assert not PlacementDisk.objects.exists(), "default: no row, as before"
    service._record_dest_os_pool(SimpleNamespace(vm=vm, dest_os_pool="ssd0", job_id="j"), placement)
    assert PlacementDisk.objects.get().required_tier == "ssd"
    assert events() == []


@ENFORCE
def test_a_failover_ranks_a_runners_hosts_by_the_tier_it_lands_at(monkeypatch) -> None:
    from apps.orchestration import restore

    dest = _dest("ssd")
    nvme, hdd, bare = "e" * 64, "f" * 64, "a" * 64
    _pool("default", node_id=nvme, declared_class="nvme")
    _pool("default", node_id=hdd, declared_class="hdd")
    _pool("default", node_id=bare, declared_class="")
    runner, _ = _vm_on("c" * 64, RUNNER)
    at = restore._landing_rank(runner)
    assert (at(nvme), at(dest), at(hdd), at(bare), at("")) == (3, 2, 1, 0, 0)
    customer, _ = _vm_on("c" * 64, "42")
    at = restore._landing_rank(customer)
    assert (at(nvme), at(dest), at(hdd)) == (0, 0, 0), "never asked for a customer"


# ── the gauge ───────────────────────────────────────────────────────


@ENFORCE
def test_the_gauge_counts_the_live_vms_below_their_sold_tier() -> None:
    from apps.disktier.models import DiskKind
    from apps.scheduler.models import PlacementStatus

    def row(placement, tier: str) -> None:
        PlacementDisk.objects.create(
            placement=placement,
            slot="os",
            kind=DiskKind.POOL,
            pool_id="default",
            size_gb=50,
            required_tier=tier,
        )

    _, a = _vm_on("a" * 64, RUNNER)
    row(a, "ssd")
    _, b = _vm_on("b" * 64, RUNNER, tier="ssd")
    row(b, "ssd")  # sold ssd, at ssd: no fallback
    _, c = _vm_on("c" * 64, "42")
    row(c, "hdd")  # not a runner's
    from apps.orchestration.tests.factories import make_vm
    from apps.scheduler.tests.factories import make_placement

    gone = make_placement(
        make_vm("vm-gone"), "d" * 64, status=PlacementStatus.FAILED.value, owner=RUNNER
    )
    row(gone, "hdd")  # not live
    assert os_tier.fallback_vm_counts() == {"ssd": 1, "hdd": 0}
    with override_settings(VALI_DISK_TIER_FALLBACK_OWNERS=[]):
        assert os_tier.fallback_vm_counts() == {"ssd": 0, "hdd": 0}


@ENFORCE
def test_the_reeval_survey_pushes_the_fallback_gauge(monkeypatch) -> None:
    from apps.scheduler.management.commands import vali_scheduler_reeval as reeval
    from apps.synthetic import metrics

    monkeypatch.setattr(os_tier, "fallback_vm_counts", lambda: {"ssd": 2, "hdd": 0})
    pushed: list[str] = []
    monkeypatch.setattr(metrics, "push", lambda ms, **_k: pushed.append(ms.render()) or True)
    with override_settings(VALI_SYNTHETIC_PUSHGATEWAY_URL="http://pgw"):
        reeval.disk_survey()
    assert 'hippius_disk_tier_fallback_vms{tier="ssd"} 2' in pushed[0]
    assert 'hippius_disk_tier_fallback_vms{tier="hdd"} 0' in pushed[0]


# ── §25 order + failover choice ─────────────────────────────────────


@ENFORCE
def test_the_activate_order_names_the_pool_at_the_runners_landing_tier(monkeypatch) -> None:
    from apps.disktier.tests.test_routing import _activate_rig
    from apps.miners.models import MinerIdentity
    from apps.orchestration import effects

    sent = _activate_rig(monkeypatch)
    dest = "e" * 64
    MinerIdentity.objects.create(
        miner_id="dest-1", pubkey_hex="ab" * 32, platform_id="cd" * 16, chain_node_id=dest
    )
    _capacity(dest)
    _pool("default", node_id=dest, declared_class="hdd")
    _pool("ssd0", node_id=dest, declared_class="ssd", available_gb=500)
    runner, _ = _vm_on("c" * 64, RUNNER)
    customer, _ = _vm_on("c" * 64, "42")
    for vm in (runner, customer):
        effects.dispatch_migrate_activate(
            vm, dest_node_id="dest-1", new_gen=6, get_url="https://s3/x", boot_artifacts=None
        )
    assert sent[0]["os_pool"] == "ssd0"
    assert "os_pool" not in sent[1]


@ENFORCE
def test_a_failover_picks_the_host_at_the_sold_tier_before_a_roomier_lower_one(
    monkeypatch,
) -> None:
    from apps.miners.models import MinerIdentity
    from apps.orchestration import restore
    from apps.orchestration import service as orch

    low, high, lowest = "d" * 64, "e" * 64, "f" * 64
    hosts = (("node-low", low, "ssd"), ("node-high", high, "nvme"), ("node-hdd", lowest, "hdd"))
    for miner_id, chain_id, default in hosts:
        MinerIdentity.objects.create(
            miner_id=miner_id, pubkey_hex=chain_id, platform_id=chain_id, chain_node_id=chain_id
        )
        _pool("default", node_id=chain_id, declared_class=default)
    monkeypatch.setattr(restore, "_validate_other_dest", lambda *a, **k: None)
    monkeypatch.setattr(orch, "_snp_generation", lambda miner_id: "genoa")
    monkeypatch.setattr(sched, "region_by_node", lambda **kw: {low: "FR", high: "FR", lowest: "FR"})
    room = {low: 256, high: 64, lowest: 512}  # GiB free: the lower, the roomier
    monkeypatch.setattr(
        sched,
        "host_resources_by_node",
        lambda: {n: sched.HostResources(gib * 1024, 8, 10**6, 64) for n, gib in room.items()},
    )
    runner, _ = _vm_on("c" * 64, RUNNER)
    customer, _ = _vm_on("c" * 64, "42")
    assert restore._pick_failover_dest(runner, "node-src", region="FR") == "node-high"
    room[high] = 0
    MinerStoragePool.objects.filter(miner_node_id=high).update(declared_class="")
    assert restore._pick_failover_dest(runner, "node-src", region="FR") == "node-low", (
        "ssd before a roomier hdd"
    )
    # Room decides for a customer (a host without its tier is refused before).
    assert restore._pick_failover_dest(customer, "node-src", region="FR") == "node-hdd"
