"""`VALI_OS_TIER_MATCH` `exact`: an OS disk sold at a tier lands only on a
pool at that very tier — an hdd order never gets NVMe at the hdd price —
while our runners' fallback (`VALI_DISK_TIER_FALLBACK_OWNERS`) still takes
the first LOWER tier a candidate holds, exactly. `minimum` (the settings.py
default) is today's placement."""

from __future__ import annotations

import pytest
from django.test import override_settings
from django.utils import timezone

from apps.disktier import os_tier, routing
from apps.disktier.models import MinerStoragePool, PlacementDisk
from apps.disktier.tests.test_os_tier import MIN, NODE, _capacity, _pool
from apps.disktier.tests.test_tier_fallback import RUNNER, _launch, _launch_rig
from apps.disktier.tiers import os_tier_fits, os_tier_match
from apps.scheduler.placement import NO_MINER_AT_TIER

pytestmark = pytest.mark.django_db

TIERS = ("nvme", "ssd", "hdd")
EXACT = override_settings(VALI_OS_TIER_MATCH="exact")
ENFORCE_EXACT = override_settings(
    VALI_OS_TIER_MATCH="exact",
    VALI_SCHEDULER_DISK_TIER_GATE="enforce",
    VALI_DISK_TIER_FALLBACK_OWNERS=[RUNNER],
    VALI_POOL_ROUTING_MIN_AGENT_VERSION=MIN,
)


# ── the helper ──────────────────────────────────────────────────────


def test_minimum_is_the_default(settings) -> None:
    assert settings.VALI_OS_TIER_MATCH == "minimum"
    assert os_tier_match() == "minimum"


def test_minimum_fits_that_tier_or_above() -> None:
    fits = {(own, sold) for own in TIERS for sold in TIERS if os_tier_fits(own, sold)}
    assert fits == {
        ("nvme", "nvme"),
        ("nvme", "ssd"),
        ("nvme", "hdd"),
        ("ssd", "ssd"),
        ("ssd", "hdd"),
        ("hdd", "hdd"),
    }


@EXACT
def test_exact_fits_that_very_tier_only() -> None:
    fits = {(own, sold) for own in TIERS for sold in TIERS if os_tier_fits(own, sold)}
    assert fits == {("nvme", "nvme"), ("ssd", "ssd"), ("hdd", "hdd")}


@pytest.mark.parametrize("match", ["minimum", "exact"])
def test_unfit_and_unknown_fit_nothing_and_a_bad_sold_tier_raises(match) -> None:
    with override_settings(VALI_OS_TIER_MATCH=match):
        for own in ("unfit", "unknown"):
            assert not any(os_tier_fits(own, sold) for sold in TIERS)
        for sold in ("unknown", "unfit", "sata"):
            with pytest.raises(ValueError):
                os_tier_fits("nvme", sold)


# ── which pool holds which tier, and the pool a launch picks ───────


@EXACT
def test_exact_a_pool_holds_only_its_own_tier() -> None:
    pools = {c: _pool(f"p-{c}", declared_class=c) for c in TIERS}
    held = {c: {t for t in TIERS if routing.serves_os_disk_tier(p, t)} for c, p in pools.items()}
    assert held == {"nvme": {"nvme"}, "ssd": {"ssd"}, "hdd": {"hdd"}}


@EXACT
@override_settings(VALI_POOL_ROUTING_MIN_AGENT_VERSION=MIN)
def test_exact_choose_os_pool_never_picks_a_faster_pool() -> None:
    _capacity()
    _pool("default", available_gb=5000)
    _pool("nvme0", available_gb=3000)
    _pool("ssd0", declared_class="ssd", available_gb=500)
    _pool("hdd0", declared_class="hdd", available_gb=8000)
    assert routing.choose_os_pool(NODE, 50) == "nvme0"
    assert routing.choose_os_pool(NODE, 50, "ssd") == "ssd0"
    # Under minimum the ssd disk spilled onto nvme0 here.
    assert routing.choose_os_pool(NODE, 950, "ssd") is None
    assert routing.choose_os_pool(NODE, 50, "hdd") == "hdd0"
    assert routing.choose_os_pool(NODE, 9000, "hdd") is None


# ── the gate (refusals), the "never" judgement ─────────────────────


@pytest.mark.parametrize(
    ("default", "sold", "minimum", "exact"),
    [
        # A customer's hdd / ssd order on an nvme pool, an nvme one on ssd.
        ("nvme", "hdd", True, False),
        ("nvme", "ssd", True, False),
        ("ssd", "hdd", True, False),
        ("ssd", "nvme", False, False),
        ("hdd", "hdd", True, True),
        ("ssd", "ssd", True, True),
        ("nvme", "nvme", True, True),
    ],
)
def test_the_gate_admits_a_default_pool(default, sold, minimum, exact) -> None:
    _pool("default", declared_class=default)
    for match, admitted in (("minimum", minimum), ("exact", exact)):
        with override_settings(VALI_OS_TIER_MATCH=match):
            assert (os_tier.refusal(NODE, sold, 50) == "") is admitted, (match, default, sold)
            assert (NODE in os_tier.ever_holding([NODE], sold)) is admitted, (match, sold)


def test_a_node_with_no_pool_rows_stays_nvme_under_exact() -> None:
    with override_settings(VALI_OS_TIER_MATCH="exact"):
        assert routing.default_pool_tier(NODE) == "nvme"
        assert os_tier.refusal(NODE, "nvme", 50) == ""
        assert os_tier.refusal(NODE, "ssd", 50) != ""
        assert os_tier.ever_holding([NODE], "hdd") == set()
    assert os_tier.refusal(NODE, "hdd", 50) == "", "minimum: as ever"


# ── the runner fallback under exact ────────────────────────────────


@ENFORCE_EXACT
@pytest.mark.parametrize(
    ("pools", "landed"),
    [
        ({"default": "nvme"}, "nvme"),
        ({"default": "ssd"}, "ssd"),
        ({"default": "hdd"}, "hdd"),
        ({"default": "hdd", "ssd0": "ssd"}, "ssd"),
    ],
)
def test_a_runner_sold_nvme_takes_the_first_lower_tier_held_exactly(pools, landed) -> None:
    _capacity()
    for pool_id, declared in pools.items():
        _pool(pool_id, declared_class=declared)
    assert os_tier.landing_tier(NODE, "nvme", 50, RUNNER) == landed
    # A customer never takes another tier: the gate refuses it as ever.
    assert os_tier.landing_tier(NODE, "nvme", 50, "42") == "nvme"


@ENFORCE_EXACT
def test_a_runner_sold_hdd_never_climbs_to_a_faster_pool() -> None:
    _capacity()
    _pool("default", declared_class="nvme")
    assert os_tier.landing_tier(NODE, "hdd", 50, RUNNER) == "hdd"
    assert os_tier.refusal(NODE, "hdd", 50) != ""


# ── the launch ──────────────────────────────────────────────────────


@pytest.mark.parametrize(
    ("default", "sold"), [("nvme", "hdd"), ("nvme", "ssd"), ("ssd", "nvme"), ("ssd", "hdd")]
)
def test_exact_a_customer_launch_never_lands_on_another_tier(monkeypatch, default, sold) -> None:
    from apps.scheduler.models import VmBillingBinding

    with ENFORCE_EXACT:
        _, seen = _launch_rig(monkeypatch, default=default, ssd_pool=False)
        _, result = _launch("42", os_disk_tier=sold)
    assert not result.ok
    assert result.outcome == NO_MINER_AT_TIER
    assert seen["launch"] == [] and not VmBillingBinding.objects.exists()


@pytest.mark.parametrize(("default", "sold"), [("nvme", "hdd"), ("nvme", "ssd"), ("ssd", "hdd")])
def test_minimum_a_customer_launch_lands_on_a_faster_pool_as_before(
    monkeypatch, default, sold
) -> None:
    from apps.scheduler.models import VmBillingBinding

    with override_settings(
        VALI_SCHEDULER_DISK_TIER_GATE="enforce",
        VALI_DISK_TIER_FALLBACK_OWNERS=[RUNNER],
        VALI_POOL_ROUTING_MIN_AGENT_VERSION=MIN,
    ):
        _, seen = _launch_rig(monkeypatch, default=default, ssd_pool=False)
        spec, result = _launch("42", os_disk_tier=sold)
    assert result.ok, result.emit
    assert seen["launch"] == [None], "on default"
    assert VmBillingBinding.objects.get(vm_id=spec.vm_id).os_disk_tier == sold


@ENFORCE_EXACT
def test_exact_a_customer_hdd_launch_takes_the_hdd_pool(monkeypatch) -> None:
    from apps.scheduler.models import VmBillingBinding

    _launch_rig(monkeypatch, default="hdd", ssd_pool=True)
    spec, result = _launch("42", os_disk_tier="hdd")
    assert result.ok, result.emit
    assert VmBillingBinding.objects.get(vm_id=spec.vm_id).os_disk_tier == "hdd"
    assert not PlacementDisk.objects.exists(), "default, at its sold tier"


@ENFORCE_EXACT
@pytest.mark.parametrize(
    ("default", "ssd_pool", "pool", "tier"),
    [("hdd", True, "ssd0", "ssd"), ("hdd", False, "default", "hdd")],
)
def test_exact_a_runner_launch_still_falls_back(monkeypatch, default, ssd_pool, pool, tier) -> None:
    from apps.scheduler.models import VmBillingBinding

    _launch_rig(monkeypatch, default=default, ssd_pool=ssd_pool)
    spec, result = _launch(RUNNER)
    assert result.ok, result.emit
    disk = PlacementDisk.objects.get()
    assert (disk.pool_id, disk.required_tier) == (pool, tier)
    assert VmBillingBinding.objects.get(vm_id=spec.vm_id).os_disk_tier == tier


@pytest.mark.parametrize(
    ("default", "sold", "minimum", "exact"),
    [("nvme", "hdd", "", "refused"), ("hdd", "hdd", "", ""), ("ssd", "nvme", "refused", "refused")],
)
def test_the_dispatch_guard_on_default(monkeypatch, default, sold, minimum, exact) -> None:
    from apps.disktier.tests.test_routing import _rig
    from apps.orchestration.services import launch
    from apps.orchestration.tests.test_os_disk_tier import _base_spec

    miner, _ = _rig(monkeypatch)
    MinerStoragePool.objects.filter(pool_id="default").update(declared_class=default)
    spec = launch.LaunchSpec(**{**_base_spec(), "os_disk_tier": sold})
    for match, want in (("minimum", minimum), ("exact", exact)):
        with override_settings(VALI_SCHEDULER_DISK_TIER_GATE="enforce", VALI_OS_TIER_MATCH=match):
            why = launch._default_pool_refusal(miner, spec)
            assert bool(why) is bool(want), (match, why)


# ── an order naming no pool (`default`): §25 arrivals ───────────────


@pytest.mark.parametrize(
    ("match", "default", "sold", "refused"),
    [
        ("exact", "nvme", "hdd", True),
        ("exact", "nvme", "ssd", True),
        ("exact", "hdd", "hdd", False),
        ("minimum", "nvme", "hdd", False),
        # A downgrade in either mode.
        ("minimum", "ssd", "nvme", True),
        ("exact", "ssd", "nvme", True),
    ],
)
def test_default_refusal(match, default, sold, refused) -> None:
    _pool("default", declared_class=default)
    with override_settings(VALI_SCHEDULER_DISK_TIER_GATE="enforce", VALI_OS_TIER_MATCH=match):
        assert bool(os_tier.default_refusal(NODE, sold, 50)) is refused
    with override_settings(VALI_SCHEDULER_DISK_TIER_GATE="record", VALI_OS_TIER_MATCH=match):
        assert os_tier.default_refusal(NODE, sold, 50) == "", "only under enforce"


@ENFORCE_EXACT
def test_default_refusal_reads_a_runners_landing_tier_and_the_implicit_nvme() -> None:
    _capacity()
    assert os_tier.default_refusal(NODE, "nvme", 50, "42") == "", "no rows: pre-v7 nvme"
    assert os_tier.default_refusal(NODE, "hdd", 50, "42") != ""
    _pool("default", declared_class="hdd")
    assert os_tier.default_refusal(NODE, "nvme", 50, "42") != ""
    assert os_tier.default_refusal(NODE, "nvme", 50, RUNNER) == "", "the runner lands at hdd"
    _pool("ssd0", declared_class="ssd")
    # The runner lands at ssd now: on ssd0, not on the hdd `default`.
    assert os_tier.default_refusal(NODE, "nvme", 50, RUNNER) != ""


@ENFORCE_EXACT
def test_a_node_with_pools_but_no_default_row_holds_nothing_on_default() -> None:
    """Heartbeats need not carry `default` and ingest retires an omitted
    pool: the implicit nvme is only for a node with NO pool row at all."""
    _capacity()
    _pool("hdd0", declared_class="hdd")
    assert routing.default_pool_tier(NODE) is None
    assert os_tier.default_refusal(NODE, "nvme", 50, "42") != ""
    assert os_tier.refusal(NODE, "nvme", 50) != ""
    assert os_tier.ever_holding([NODE], "nvme") == set()
    assert os_tier.refusal(NODE, "hdd", 50) == "", "hdd0 holds it"
    with override_settings(VALI_OS_TIER_MATCH="minimum"):
        assert os_tier.default_refusal(NODE, "hdd", 50, "42") != ""
    # A retired row does not count.
    MinerStoragePool.objects.filter(pool_id="hdd0").update(retired_at=timezone.now())
    assert routing.default_pool_tier(NODE) == "nvme"
    assert os_tier.default_refusal(NODE, "nvme", 50, "42") == ""


@ENFORCE_EXACT
def test_a_v7_node_with_no_pool_row_yet_holds_nothing_on_default() -> None:
    """No pool row is the pre-v7 implicit nvme only for a node that never
    sent a v7 storage report: one whose report did not land (its recording
    failed) holds nothing until it does."""
    from apps.scheduler.models import MinerCapacity

    _capacity()
    assert routing.default_pool_tier(NODE) == "nvme", "never reported: legacy"
    assert os_tier.refusal(NODE, "nvme", 50) == ""
    assert os_tier.ever_holding([NODE], "nvme") == {NODE}
    MinerCapacity.objects.filter(miner_node_id=NODE).update(storage_reported_at=timezone.now())
    assert routing.default_pool_tier(NODE) is None
    assert os_tier.refusal(NODE, "nvme", 50) != ""
    assert os_tier.default_refusal(NODE, "nvme", 50, "42") != ""
    assert os_tier.ever_holding([NODE], "nvme") == set()
    # Its report lands: `default` holds what the row says.
    _pool("default", declared_class="nvme")
    assert routing.default_pool_tier(NODE) == "nvme"
    assert os_tier.refusal(NODE, "nvme", 50) == ""


@ENFORCE_EXACT
def test_the_dispatch_guard_refuses_default_on_a_node_without_its_row(monkeypatch) -> None:
    from apps.disktier.tests.test_routing import _rig
    from apps.orchestration.services import launch
    from apps.orchestration.tests.test_os_disk_tier import _base_spec

    miner, _ = _rig(monkeypatch)
    MinerStoragePool.objects.filter(pool_id="default").delete()
    assert launch._default_pool_refusal(miner, launch.LaunchSpec(**_base_spec())) != ""


def test_a_concurrent_re_pin_wins_and_is_what_is_dispatched(monkeypatch) -> None:
    """Two overlapping ticks re-picking a pool for the same attempt: the
    first persisted choice is the one both dispatch (compare-and-set)."""
    from apps.orchestration import effects, service
    from apps.orchestration.models import MigrationJob
    from apps.orchestration.tests.factories import make_migration_job, make_vm

    job = make_migration_job(make_vm("vm-race"))
    MigrationJob.objects.filter(pk=job.pk).update(dest_os_pool="", dest_os_pool_pinned=True)
    job.refresh_from_db()
    monkeypatch.setattr(effects, "arrival_default_refusal", lambda vm, dest: "default lacks it")

    def racing_choice(vm, dest):
        # The other tick pinned its choice while this one was choosing.
        MigrationJob.objects.filter(pk=job.pk).update(dest_os_pool="other0")
        return "mine0"

    monkeypatch.setattr(effects, "arrival_os_pool", racing_choice)
    assert service._dest_os_pool_for_dispatch(job) == "other0"
    job.refresh_from_db()
    assert job.dest_os_pool == "other0"


@ENFORCE_EXACT
def test_the_arrival_default_refusal_reads_the_measured_cmdline() -> None:
    from apps.miners.models import MinerIdentity
    from apps.orchestration import effects

    MinerIdentity.objects.create(miner_id="dest-1", pubkey_hex="cc" * 32, chain_node_id=NODE)
    _capacity()
    _pool("default", declared_class="nvme")
    _pool("hdd0", declared_class="hdd", available_gb=100)
    golden = f"ro dm-verity.root={'e' * 64} hippius.disk_gb=40"
    assert effects._arrival_default_refusal("dest-1", golden, "hdd") != ""
    assert effects._arrival_os_pool("dest-1", golden, "hdd") == "hdd0"
    assert effects._arrival_default_refusal("dest-1", golden, "nvme") == ""
    # A legacy disk can only land on `default`.
    legacy = "ro hippius.luks_header_sha256=aa"
    assert effects._arrival_default_refusal("dest-1", legacy, "hdd") != ""
    # A dest vali knows no node of: its own gate decides.
    assert effects._arrival_default_refusal("nobody", golden, "hdd") == ""


@ENFORCE_EXACT
@pytest.mark.parametrize("pools", [{"default": "nvme"}, {"default": "nvme", "nvme0": "nvme"}, {}])
def test_exact_an_existing_nvme_customer_vm_still_relaunches(monkeypatch, pools) -> None:
    """Regression: a restart of an nvme customer VM (relaunch onto its own
    disks) is untouched by exact matching, on a node with an nvme default,
    an nvme pool, or no pool rows (the pre-v7 nvme)."""
    from apps.disktier.tests.test_routing import _rig, _spec
    from apps.orchestration.services import launch
    from apps.orchestration.tests.test_os_disk_tier import _base_spec

    miner, seen = _rig(monkeypatch)
    MinerStoragePool.objects.all().delete()
    for pool_id, declared in pools.items():
        _pool(pool_id, node_id=miner.chain_node_id, declared_class=declared)
    assert launch._default_pool_refusal(miner, launch.LaunchSpec(**_base_spec())) == ""
    out = launch.launch_on_miner(_spec(), miner, require_existing_disks=True)
    assert out.disposition == launch.ACCEPTED, out.emit
    assert seen["launch"] == [None], "a relaunch names no pool: its disks are where they are"
