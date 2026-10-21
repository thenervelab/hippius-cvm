"""E1: `os_disk_tier` on a launch — intake, what the launch does with it,
and every later placement keeping it (docs/design/disk-tier-verification.md
§10.14). The pool / gate logic itself: `apps/disktier/tests/test_os_tier.py`."""

from __future__ import annotations

import ast
from pathlib import Path

import pytest
from django.conf import settings
from django.test import override_settings
from django.urls import reverse
from django.utils import timezone

from apps.disktier import os_tier
from apps.disktier.models import MinerStoragePool
from apps.miners.models import MinerIdentity
from apps.orchestration import launch_jobs, service
from apps.orchestration.launch_jobs import LaunchIntentError
from apps.orchestration.models import LaunchJob
from apps.orchestration.services import launch

from .factories import make_launch_record, make_service_client, make_vm
from .test_power_policy import _intent

pytestmark = pytest.mark.django_db

SELL_SSD = override_settings(
    VALI_SELLABLE_OS_TIERS=["nvme", "ssd", "hdd"], VALI_SCHEDULER_DISK_TIER_GATE="enforce"
)


# ── intake ──────────────────────────────────────────────────────────


@pytest.mark.parametrize("value", [None, "", "nvme"])
def test_nvme_is_the_default_and_never_recorded(value) -> None:
    body = _intent() if value is None else _intent(os_disk_tier=value)
    spec = launch_jobs._build_spec_json(body)
    assert "os_disk_tier" not in spec
    assert launch.LaunchSpec(**spec, kek_bytes=None, userdata=b"").os_disk_tier == ""


@pytest.mark.parametrize("value", ["NVME", "sata", "unknown", "unfit", 1, True, ["ssd"]])
def test_a_tier_off_the_enum_is_a_400(value) -> None:
    with pytest.raises(LaunchIntentError) as exc:
        launch_jobs._build_spec_json(_intent(os_disk_tier=value))
    assert exc.value.category == "disk-tier-invalid"


@SELL_SSD
def test_a_sold_tier_rides_the_spec_into_the_worker() -> None:
    spec = launch_jobs._build_spec_json(_intent(os_disk_tier="ssd"))
    assert spec["os_disk_tier"] == "ssd"
    assert launch.LaunchSpec(**spec, kek_bytes=None, userdata=b"").os_disk_tier == "ssd"
    spec = launch_jobs._build_spec_json(_intent(os_disk_tier="hdd", flavor="medium"))
    assert spec["os_disk_tier"] == "hdd"


@pytest.mark.parametrize(
    ("overrides", "tier", "flavor"),
    [
        # Not in `VALI_SELLABLE_OS_TIERS` (nvme only by default).
        ({}, "ssd", "small"),
        ({}, "hdd", "small"),
        # Sellable, but vali does not place by the tier (gate not enforced).
        (dict(VALI_SELLABLE_OS_TIERS=["nvme", "ssd"]), "ssd", "small"),
        (
            dict(VALI_SELLABLE_OS_TIERS=["nvme", "ssd"], VALI_SCHEDULER_DISK_TIER_GATE="record"),
            "ssd",
            "small",
        ),
        # hdd above `VALI_HDD_OS_MAX_FLAVOR` (large): its first boot wipes too long.
        (
            dict(VALI_SELLABLE_OS_TIERS=["hdd"], VALI_SCHEDULER_DISK_TIER_GATE="enforce"),
            "hdd",
            "xlarge",
        ),
        # nvme taken off the shelf.
        (dict(VALI_SELLABLE_OS_TIERS=["ssd"]), "nvme", "small"),
    ],
)
def test_a_tier_not_sold_is_a_409(overrides, tier, flavor) -> None:
    with override_settings(**overrides), pytest.raises(LaunchIntentError) as exc:
        launch_jobs._build_spec_json(_intent(os_disk_tier=tier, flavor=flavor))
    assert exc.value.category == "disk-tier-not-offered"


@SELL_SSD
def test_hdd_is_sold_up_to_its_largest_flavor() -> None:
    assert launch_jobs._build_spec_json(_intent(os_disk_tier="hdd", flavor="large"))
    with override_settings(VALI_HDD_OS_MAX_FLAVOR="small"), pytest.raises(LaunchIntentError):
        launch_jobs._build_spec_json(_intent(os_disk_tier="hdd", flavor="medium"))


@pytest.mark.parametrize("value", [{"tier": "hdd", "count": 1, "min_size_gb": 1000}, {}, [], 0])
def test_dedicated_disks_are_reserved_and_refused(value) -> None:
    with pytest.raises(LaunchIntentError) as exc:
        launch_jobs._build_spec_json(_intent(dedicated_disks=value, pinned_ack=True))
    assert exc.value.category == "dedicated-disks-not-offered"


def test_a_null_dedicated_disks_and_a_pinned_ack_are_accepted_and_not_kept() -> None:
    spec = launch_jobs._build_spec_json(_intent(dedicated_disks=None, pinned_ack=False))
    assert "dedicated_disks" not in spec and "pinned_ack" not in spec
    assert spec == launch_jobs._build_spec_json(_intent())
    with pytest.raises(LaunchIntentError) as exc:
        launch_jobs._build_spec_json(_intent(pinned_ack="yes"))
    assert exc.value.category == "bad-field"


def _post(root_client, **overrides):
    body = {
        **_intent(**overrides),
        "kek_vault_path": f"{settings.VALI_VAULT_KV_PREFIX}/vm-api-pp/luks-kek",
        "userdata": "#cloud-config\n# {{NETBIRD_SETUP_KEY}}\n",
    }
    return root_client.post(reverse("vm_launch"), body, format="json")


@pytest.mark.parametrize(
    ("overrides", "status", "category"),
    [
        (dict(os_disk_tier="sata"), 400, "disk-tier-invalid"),
        (dict(os_disk_tier="ssd"), 409, "disk-tier-not-offered"),
        (dict(dedicated_disks={"tier": "hdd", "count": 1}), 409, "dedicated-disks-not-offered"),
    ],
)
def test_the_api_maps_the_refusals(root_client, overrides, status, category) -> None:
    resp = _post(root_client, **overrides)
    assert (resp.status_code, resp.json()["category"]) == (status, category)
    assert LaunchJob.objects.count() == 0


# ── the launch ──────────────────────────────────────────────────────


@override_settings(VALI_POOL_ROUTING_MIN_AGENT_VERSION="v2026.10.17")
def test_the_launch_picks_a_pool_at_the_tier_and_binds_it_for_billing(monkeypatch) -> None:
    from apps.disktier.tests.test_routing import _pool, _rig, _spec
    from apps.scheduler.models import VmBillingBinding

    miner, seen = _rig(monkeypatch)
    _pool("ssd0", node_id=miner.chain_node_id, declared_class="ssd", available_gb=3200)
    out = launch.launch_on_miner(_spec(os_disk_tier="ssd"), miner)
    assert out.disposition == launch.ACCEPTED, out.emit
    assert seen == {"preflight": ["ssd0"], "launch": ["ssd0"]}
    assert VmBillingBinding.objects.get().os_disk_tier == "ssd"


@override_settings(VALI_POOL_ROUTING_MIN_AGENT_VERSION="v2026.10.17")
def test_an_nvme_launch_is_as_before(monkeypatch) -> None:
    from apps.disktier.tests.test_routing import _pool, _rig, _spec
    from apps.scheduler.models import VmBillingBinding

    miner, seen = _rig(monkeypatch)
    _pool("ssd0", node_id=miner.chain_node_id, declared_class="ssd", available_gb=9000)
    out = launch.launch_on_miner(_spec(), miner)
    assert out.disposition == launch.ACCEPTED, out.emit
    assert seen == {"preflight": ["nvme0"], "launch": ["nvme0"]}
    assert VmBillingBinding.objects.get().os_disk_tier == "nvme"


# ── every later placement keeps it ──────────────────────────────────


#: The modules that call `decide_placement`. Each call must carry gate (n):
#: through `placement_arguments` (which adds it) or `disk_tier_arguments`.
_CALLERS = (
    "apps/orchestration/services/launch.py",
    "apps/orchestration/resize.py",
    "apps/orchestration/service.py",
    "apps/scheduler/feasibility.py",
    "apps/scheduler/views.py",
    "apps/scheduler/management/commands/vali_price_watch.py",
)


def test_every_placement_call_carries_the_tier_gate() -> None:
    root = Path(__file__).resolve().parents[3]
    found = set()
    for path in sorted((root / "apps").rglob("*.py")):
        if "/tests/" in str(path):
            continue
        tree = ast.parse(path.read_text())
        for node in ast.walk(tree):
            if not (
                isinstance(node, ast.Call)
                and getattr(node.func, "id", getattr(node.func, "attr", "")) == "decide_placement"
            ):
                continue
            found.add(str(path.relative_to(root)))
            spread = [
                kw.value.func
                for kw in node.keywords
                if kw.arg is None and isinstance(kw.value, ast.Call)
            ]
            names = {getattr(f, "attr", getattr(f, "id", "")) for f in spread}
            assert names & {"placement_arguments", "disk_tier_arguments"} or any(
                kw.arg is None and getattr(kw.value, "id", "") == "arguments"
                for kw in node.keywords
            ), f"{path.relative_to(root)}:{node.lineno} places without gate (n)"
    assert found == set(_CALLERS)


def _dest_with_default_pool(declared: str) -> None:
    MinerIdentity.objects.create(
        miner_id="node-src", pubkey_hex="aa" * 32, platform_id="11" * 64, chain_node_id="c" * 64
    )
    MinerIdentity.objects.create(
        miner_id="node-dst", pubkey_hex="bb" * 32, platform_id="22" * 64, chain_node_id="d" * 64
    )
    MinerStoragePool.objects.create(
        miner_node_id="d" * 64, pool_id="default", declared_class=declared, os_disks=True
    )


@pytest.mark.parametrize(
    ("mode", "tier", "refused"),
    [
        ("off", "nvme", False),
        ("record", "nvme", False),
        ("enforce", "nvme", True),
        ("enforce", "ssd", False),
    ],
)
def test_a_named_destination_without_the_tier_is_refused_when_enforced(
    mode, tier, refused
) -> None:
    _dest_with_default_pool("ssd")
    vm = make_vm(host="node-src")
    make_launch_record(vm, os_disk_tier=None if tier == "nvme" else tier)
    with override_settings(VALI_SCHEDULER_DISK_TIER_GATE=mode):
        if refused:
            with pytest.raises(service.StartError) as exc:
                service._reject_disk_tier_dest(vm, "node-dst")
            assert exc.value.category == os_tier.CATEGORY_NO_MINER_AT_TIER
        else:
            service._reject_disk_tier_dest(vm, "node-dst")


@pytest.mark.usefixtures("located_fr")
def test_a_migration_intake_runs_the_tier_check(monkeypatch) -> None:
    _dest_with_default_pool("ssd")
    vm = make_vm(host="node-src")
    make_launch_record(vm)
    with override_settings(VALI_SCHEDULER_DISK_TIER_GATE="enforce"):
        with pytest.raises(service.StartError) as exc:
            service.start_migration(
                vm=vm, dest_node_id="node-dst", decided_by=make_service_client()
            )
    assert exc.value.category == "no-miner-at-tier"
    job = service.start_migration(vm=vm, dest_node_id="node-dst", decided_by=make_service_client())
    assert job.dest_node_id == "node-dst", "off: as before"


@override_settings(VALI_POOL_ROUTING_MIN_AGENT_VERSION="*")
def test_a_golden_arrival_goes_to_a_pool_at_the_vms_tier() -> None:
    from apps.orchestration import effects

    MinerIdentity.objects.create(
        miner_id="dest-1", pubkey_hex="ab" * 32, platform_id="cd" * 16, chain_node_id="e" * 64
    )
    MinerStoragePool.objects.create(
        miner_node_id="e" * 64,
        pool_id="ssd0",
        declared_class="ssd",
        os_disks=True,
        reported_state="active",
        reported_at=timezone.now(),
        available_gb=500,
    )
    golden = f"ro dm-verity.root={'e' * 64} hippius.disk_gb=40"
    assert effects._arrival_os_pool("dest-1", golden) is None, "nvme: not on ssd0"
    assert effects._arrival_os_pool("dest-1", golden, "ssd") == "ssd0"


def test_every_tier_gate_call_names_the_vm() -> None:
    """The tier is the VM's launch's: a `disk_tier_arguments` without the
    VM would place it as nvme."""
    root = Path(__file__).resolve().parents[3]
    calls = 0
    for path in sorted((root / "apps").rglob("*.py")):
        if "/tests/" in str(path):
            continue
        for node in ast.walk(ast.parse(path.read_text())):
            if isinstance(node, ast.Call) and getattr(
                node.func, "attr", getattr(node.func, "id", "")
            ) == ("disk_tier_arguments"):
                calls += 1
                assert {kw.arg for kw in node.keywords} >= {"vm_id"}, (
                    f"{path.relative_to(root)}:{node.lineno}"
                )
    assert calls == 5  # placement_arguments, /place, re-place, drain, price-watch


@override_settings(VALI_POOL_ROUTING_MIN_AGENT_VERSION="*")
def test_a_migrating_vm_arrives_on_a_pool_at_its_tier(monkeypatch, fx) -> None:
    from apps.orchestration import effects

    MinerIdentity.objects.create(
        miner_id="dest-1", pubkey_hex="ab" * 32, platform_id="cd" * 16, chain_node_id="e" * 64
    )
    MinerStoragePool.objects.create(
        miner_node_id="e" * 64,
        pool_id="ssd0",
        declared_class="ssd",
        os_disks=True,
        reported_state="active",
        reported_at=timezone.now(),
        available_gb=500,
    )
    golden = f"ro dm-verity.root={'e' * 64} hippius.disk_gb=40"
    monkeypatch.setattr(effects, "_launch_paths", lambda vm: {"cmdline": golden})
    nvme_vm, ssd_vm = make_vm("vm-n"), make_vm("vm-s")
    make_launch_record(nvme_vm)
    make_launch_record(ssd_vm, os_disk_tier="ssd")
    arrival_os_pool = fx.real["arrival_os_pool"]
    assert arrival_os_pool(nvme_vm, "dest-1") is None
    assert arrival_os_pool(ssd_vm, "dest-1") == "ssd0"


@override_settings(VALI_STORAGE_MOVE_ENABLED=True)
def test_a_storage_move_target_must_hold_the_vms_tier() -> None:
    from apps.disktier import storage_move

    MinerStoragePool.objects.create(
        miner_node_id="e" * 64,
        pool_id="ssd0",
        declared_class="ssd",
        os_disks=True,
        reported_state="active",
        reported_at=timezone.now(),
        available_gb=500,
    )
    with pytest.raises(storage_move.MoveRefused) as exc:
        storage_move._check_target("e" * 64, "ssd0", 50, "nvme")
    assert exc.value.code == "move-pool-tier"
    storage_move._check_target("e" * 64, "ssd0", 50, "ssd")
    storage_move._check_target("e" * 64, "ssd0", 50, "hdd")


# ── dispatch: `default` must hold the tier too ──────────────────────


@override_settings(
    VALI_POOL_ROUTING_MIN_AGENT_VERSION="v2026.10.17", VALI_SCHEDULER_DISK_TIER_GATE="enforce"
)
def test_an_enforced_launch_never_falls_back_to_a_slower_default(monkeypatch) -> None:
    from apps.disktier.tests.test_routing import _rig, _spec

    miner, seen = _rig(monkeypatch)
    MinerStoragePool.objects.filter(pool_id="default").update(declared_class="hdd")
    # nvme0 (the rig's) takes an nvme disk: dispatched there.
    assert launch.launch_on_miner(_spec(), miner).disposition == launch.ACCEPTED
    # No pool other than `default` holds ssd: the first attempt re-places,
    # touching nothing; a same-miner retry (the pool it named was refused)
    # stops.
    MinerStoragePool.objects.filter(pool_id="nvme0").update(declared_class="hdd")
    seen["launch"].clear()
    first = launch.launch_on_miner(_spec(os_disk_tier="ssd"), miner)
    assert (first.disposition, first.emit["outcome"]) == (launch.RETRIABLE, "no-os-pool-at-tier")
    retry = launch.launch_on_miner(_spec(os_disk_tier="ssd"), miner, os_pool=None)
    assert (retry.disposition, retry.emit["outcome"]) == (launch.TERMINAL, "no-os-pool-at-tier")
    # The retry only follows a registered attempt: the reap must know it.
    assert (first.registered, retry.registered) == (False, True)
    assert seen["launch"] == []
    # hdd is held by `default`: dispatched, no pool named.
    out = launch.launch_on_miner(_spec(os_disk_tier="hdd"), miner)
    assert out.disposition == launch.ACCEPTED, out.emit
    assert seen["launch"] == ["nvme0"], "nvme0 (now hdd) before `default`, as for nvme"


@pytest.mark.parametrize("mode", ["off", "record"])
def test_unenforced_the_launch_guard_reads_nothing(monkeypatch, mode) -> None:
    from apps.disktier.tests.test_routing import _rig, _spec

    with override_settings(
        VALI_POOL_ROUTING_MIN_AGENT_VERSION="v2026.10.17", VALI_SCHEDULER_DISK_TIER_GATE=mode
    ):
        miner, seen = _rig(monkeypatch)
        MinerStoragePool.objects.filter(pool_id="nvme0").delete()
        MinerStoragePool.objects.filter(pool_id="default").update(declared_class="hdd")
        assert launch._default_pool_refusal(miner, launch.LaunchSpec(**_base_spec())) == ""
        out = launch.launch_on_miner(_spec(), miner)
        assert out.disposition == launch.ACCEPTED, out.emit
        assert seen["launch"] == [None]


def _base_spec() -> dict:
    from apps.disktier.tests.test_routing import _spec

    spec = _spec()
    return {f: getattr(spec, f) for f in spec.__dataclass_fields__}


@override_settings(
    VALI_POOL_ROUTING_MIN_AGENT_VERSION="v2026.10.17", VALI_SCHEDULER_DISK_TIER_GATE="enforce"
)
@pytest.mark.parametrize("exempt", ["relaunch", "pinned"])
def test_a_relaunch_or_a_pinned_probe_launch_is_never_held_by_the_guard(
    monkeypatch, exempt
) -> None:
    from apps.disktier.tests.test_routing import _rig, _spec

    miner, seen = _rig(monkeypatch)
    MinerStoragePool.objects.filter(pool_id="nvme0").delete()
    MinerStoragePool.objects.filter(pool_id="default").update(declared_class="hdd")
    if exempt == "relaunch":
        out = launch.launch_on_miner(_spec(), miner, require_existing_disks=True)
    else:
        out = launch.launch_on_miner(_spec(pinned_os_pool="default"), miner)
    assert out.emit.get("outcome") != "no-os-pool-at-tier", out.emit
