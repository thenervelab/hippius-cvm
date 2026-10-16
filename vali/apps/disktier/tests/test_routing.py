"""A4b: the pool a first golden launch / a §25 arrival puts the OS disk on
(`apps.disktier.routing`), and the orders that carry it."""

from __future__ import annotations

import json
from datetime import timedelta

import pytest
from django.test import override_settings
from django.utils import timezone

from apps.disktier import routing
from apps.disktier.models import OS_SLOT, DiskHealth, MinerStoragePool, PlacementDisk
from apps.orchestration import effects, order_dispatch
from apps.orchestration.services import launch, preflight
from apps.scheduler.models import MinerCapacity

pytestmark = pytest.mark.django_db

NODE = "5" * 64
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


# ── the chooser ─────────────────────────────────────────────────────


@override_settings(VALI_POOL_ROUTING_MIN_AGENT_VERSION=MIN)
def test_the_best_pool_other_than_default_with_room_wins() -> None:
    _capacity()
    _pool("default", available_gb=5000)
    _pool("nvme0", available_gb=900)
    _pool("nvme1", available_gb=3000, budget_gb=1000, committed_gb=200)  # 800 left
    _pool("ssd0", available_gb=2000)
    assert routing.choose_os_pool(NODE, 50) == "ssd0"
    # Room is the budget left, not the free space: nvme1 can't take 850.
    assert routing.choose_os_pool(NODE, 1900) == "ssd0"
    assert routing.choose_os_pool(NODE, 2001) is None, "only default is left"


@override_settings(VALI_POOL_ROUTING_MIN_AGENT_VERSION=MIN)
@pytest.mark.parametrize(
    "excluded",
    [
        dict(reported_state="draining"),
        dict(reported_state="unavailable"),
        dict(os_disks=False),
        dict(retired_at=timezone.now()),
        dict(health=DiskHealth.SEVERE),
        dict(health=DiskHealth.DEGRADED),
        dict(available_gb=None),
        # Not the tier an OS disk is sold as (nvme): verified lower, or
        # unprobed and declared lower.
        dict(tier="hdd"),
        dict(tier="ssd"),
        dict(declared_class="hdd"),
        dict(declared_class=""),
        # Not reported lately (a heartbeat that stopped carrying pools).
        dict(reported_at=timezone.now() - routing.REPORT_MAX_AGE - timedelta(seconds=1)),
        dict(reported_at=None),
        # No room left: committed past its budget, or past vali's ceiling.
        dict(budget_gb=500, committed_gb=600),
        dict(earned_gb=5),
    ],
)
def test_a_pool_that_cannot_take_an_os_disk_is_never_chosen(excluded) -> None:
    _capacity()
    _pool("nvme0", **excluded)
    assert routing.choose_os_pool(NODE, 10) is None


@override_settings(VALI_POOL_ROUTING_MIN_AGENT_VERSION=MIN)
def test_a_verified_or_overridden_nvme_pool_is_routed_to() -> None:
    _capacity()
    _pool("ssd-box", declared_class="ssd", tier="nvme")
    assert routing.choose_os_pool(NODE, 10) == "ssd-box"
    MinerStoragePool.objects.all().delete()
    _pool("ops", tier="hdd", operator_override="nvme", health=DiskHealth.SUSPECT)
    assert routing.choose_os_pool(NODE, 10) == "ops"


@pytest.mark.parametrize(
    ("minimum", "version", "chosen"),
    [
        ("", MIN, None),  # unset: nobody
        (MIN, "v2026.10.16.1", None),  # older agent
        (MIN, "dev", None),  # unparseable
        (MIN, MIN, "nvme0"),
        ("*", "dev", "nvme0"),
    ],
)
def test_only_an_agent_that_takes_os_pool_is_sent_one(minimum, version, chosen) -> None:
    _capacity(version=version)
    _pool("nvme0")
    with override_settings(VALI_POOL_ROUTING_MIN_AGENT_VERSION=minimum):
        assert routing.choose_os_pool(NODE, 10) == chosen


# ── the bodies ──────────────────────────────────────────────────────

_LAUNCH = dict(
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


def test_the_bodies_carry_os_pool_only_when_set() -> None:
    assert "os_pool" not in order_dispatch.build_launch_payload(**_LAUNCH)
    assert "os_pool" not in order_dispatch.build_launch_payload(**_LAUNCH, os_pool=None)
    assert order_dispatch.build_launch_payload(**_LAUNCH, os_pool="nvme0")["os_pool"] == "nvme0"

    activate = dict(_LAUNCH, get_url="https://s3/x", new_gen=2)
    assert "os_pool" not in order_dispatch.build_migrate_activate_payload(**activate)
    assert (
        order_dispatch.build_migrate_activate_payload(**activate, os_pool="nvme0")["os_pool"]
        == "nvme0"
    )

    pre = dict(
        vm_id="v",
        ovmf_path="/o",
        cmdline="ro",
        cpu_count=2,
        luks_disk_url="https://s3/l",
        luks_disk_sha256_hex="a" * 64,
        kernel_url="https://s3/k",
        kernel_sha256_hex="a" * 64,
        initrd_url="https://s3/i",
        initrd_sha256_hex="a" * 64,
    )
    assert "os_pool" not in preflight.build_preflight_payload(**pre)
    assert preflight.build_preflight_payload(**pre, os_pool="nvme0")["os_pool"] == "nvme0"


# ── launch_on_miner ─────────────────────────────────────────────────


def _rig(monkeypatch):
    from apps.orchestration.tests.test_launch_service import (  # isort: skip
        _fake_the_launch_choreography,
        _register_miner,
    )

    _fake_the_launch_choreography(monkeypatch, dispatch_ok=True)
    seen: dict[str, list] = {"launch": [], "preflight": []}

    def fake_preflight(*a, **k):
        seen["preflight"].append(k.get("os_pool"))
        return preflight.PreflightResult(
            launch_digest_hex="ab" * 48,
            luks_disk_path="/d.img",
            kernel_path="/k",
            initrd_path="/i",
            rootfs_data_path="/var/lib/hippius-miner/staging/vm-launch-1/rootfs.img",
            rootfs_hash_path="/var/lib/hippius-miner/staging/vm-launch-1/rootfs.verity",
        )

    monkeypatch.setattr(preflight, "dispatch_preflight", fake_preflight)
    monkeypatch.setattr(
        order_dispatch,
        "build_launch_payload",
        lambda *a, **k: seen["launch"].append(k.get("os_pool")) or {},
    )
    monkeypatch.setattr(
        order_dispatch,
        "dispatch_order",
        lambda *a, **k: order_dispatch.DispatchResult(ok=True, status=200, classifier="launched"),
    )
    miner = _register_miner(1)
    _capacity(miner.chain_node_id)
    _pool("default", node_id=miner.chain_node_id)
    _pool("nvme0", node_id=miner.chain_node_id, available_gb=3200)
    return miner, seen


def _spec(**kw):
    from apps.orchestration.tests.test_launch_service import _spec  # isort: skip

    golden = dict(
        disk_mode="golden_verity_overlay",
        verity_root_hash_hex="e" * 64,
        rootfs_img_sha256_hex="b" * 64,
        rootfs_verity_sha256_hex="c" * 64,
    )
    golden.update(kw)
    return _spec(userdata=b"#cloud-config\n# {{NETBIRD_SETUP_KEY}}\n", **golden)


@override_settings(VALI_POOL_ROUTING_MIN_AGENT_VERSION=MIN)
def test_a_first_golden_launch_names_the_pool_in_the_preflight_and_the_launch(monkeypatch) -> None:
    miner, seen = _rig(monkeypatch)
    out = launch.launch_on_miner(_spec(), miner)
    assert out.disposition == launch.ACCEPTED, out.emit
    assert seen == {"preflight": ["nvme0"], "launch": ["nvme0"]}
    assert out.os_pool == "nvme0"


@override_settings(VALI_POOL_ROUTING_MIN_AGENT_VERSION=MIN)
def test_an_already_launched_answer_records_no_pool(monkeypatch) -> None:
    miner, seen = _rig(monkeypatch)
    monkeypatch.setattr(
        order_dispatch,
        "dispatch_order",
        lambda *a, **k: order_dispatch.DispatchResult(
            ok=True, status=200, classifier="already-launched"
        ),
    )
    out = launch.launch_on_miner(_spec(), miner)
    assert out.disposition == launch.ACCEPTED, out.emit
    assert (out.os_pool, out.chosen_os_pool) == (None, "nvme0")


@override_settings(VALI_POOL_ROUTING_MIN_AGENT_VERSION=MIN)
def test_a_same_miner_retry_names_the_first_pool_unless_it_was_refused(monkeypatch) -> None:
    miner, seen = _rig(monkeypatch)
    # Given: the retry's pool, never a second choice.
    MinerStoragePool.objects.filter(pool_id="nvme0").update(available_gb=1)
    launch.launch_on_miner(_spec(), miner, os_pool="nvme0")
    assert seen["launch"] == ["nvme0"]

    def failed(classifier: str) -> launch.LaunchOutcome:
        return launch.LaunchOutcome(
            disposition=launch.RETRIABLE,
            emit={"classifier": classifier},
            exit_code=1,
            registered=True,
            chosen_os_pool="nvme0",
        )

    assert launch._retry_os_pool(failed("dispatch-failed")) == "nvme0"
    assert launch._retry_os_pool(failed("insufficient-disk:nvme0")) is None
    assert launch._retry_os_pool(failed("pool-unavailable:nvme0")) is None


@override_settings(VALI_POOL_ROUTING_MIN_AGENT_VERSION=MIN)
def test_a_relaunch_or_a_legacy_launch_names_no_pool(monkeypatch) -> None:
    miner, seen = _rig(monkeypatch)
    out = launch.launch_on_miner(_spec(), miner, require_existing_disks=True)
    assert out.disposition == launch.ACCEPTED, out.emit
    out = launch.launch_on_miner(
        _spec(
            disk_mode="legacy_luks",
            verity_root_hash_hex="",
            rootfs_img_sha256_hex="",
            rootfs_verity_sha256_hex="",
        ),
        miner,
    )
    assert out.disposition == launch.ACCEPTED, out.emit
    assert seen == {"preflight": [None, None], "launch": [None, None]}


def test_a_bound_placement_records_its_os_pool() -> None:
    from apps.orchestration.tests.factories import make_vm
    from apps.scheduler.tests.factories import make_placement

    placement = make_placement(make_vm("vm-on-nvme0"), NODE, resource_class="small")
    out = launch.LaunchOutcome(
        disposition=launch.ACCEPTED, emit={}, exit_code=0, ticket_id="t", os_pool="nvme0"
    )
    launch._bind_placement(placement, out)
    disk = PlacementDisk.objects.get(placement_id=placement.id)
    assert (disk.slot, disk.kind, disk.pool_id, disk.required_tier) == (
        OS_SLOT,
        "pool",
        "nvme0",
        "nvme",
    )
    # A placement on `default` gets no row (the legacy reading).
    # Resized in place on its host: the new row keeps the disk's pool.
    from apps.scheduler import service as scheduler_service

    resized = scheduler_service.swap_placement_class(
        placement.vm,
        node_id=NODE,
        new_class="medium",
        reason="test",
        decided_by=placement.decided_by,
        check_fit=False,
    )
    assert PlacementDisk.objects.get(placement_id=resized.id).pool_id == "nvme0"
    other = make_placement(make_vm("vm-on-default"), NODE, resource_class="small")
    launch._bind_placement(
        other, launch.LaunchOutcome(disposition=launch.ACCEPTED, emit={}, exit_code=0)
    )
    assert not PlacementDisk.objects.filter(placement_id=other.id).exists()


# ── §25 arrival ─────────────────────────────────────────────────────


@override_settings(VALI_POOL_ROUTING_MIN_AGENT_VERSION=MIN)
def test_a_golden_arrival_is_sent_the_dest_nodes_pool() -> None:
    from apps.miners.models import MinerIdentity

    MinerIdentity.objects.create(
        miner_id="dest-1", pubkey_hex="ab" * 32, platform_id="cd" * 16, chain_node_id=NODE
    )
    _capacity()
    _pool("nvme0", available_gb=100)
    golden = f"ro dm-verity.root={'e' * 64} hippius.disk_gb=40"
    assert effects._arrival_os_pool("dest-1", golden) == "nvme0"
    # Too big for it (40 + rootfs fits, 95 + rootfs does not).
    assert effects._arrival_os_pool("dest-1", golden.replace("40", "95")) is None
    # Legacy, or an unknown dest: none.
    assert effects._arrival_os_pool("dest-1", "ro hippius.luks_header_sha256=aa") is None
    assert effects._arrival_os_pool("nobody", golden) is None


def test_the_routing_setting_defaults_to_nobody(settings) -> None:
    assert settings.VALI_POOL_ROUTING_MIN_AGENT_VERSION == ""
    _capacity()
    _pool("nvme0")
    assert routing.choose_os_pool(NODE, 10) is None
    assert json.dumps(order_dispatch.build_launch_payload(**_LAUNCH)).find("os_pool") == -1
