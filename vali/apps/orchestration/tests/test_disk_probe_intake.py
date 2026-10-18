"""The disk-tier probe identity at the launch intake (phase R1,
`launch_jobs._check_disk_probe_role`) and the probe owner's exclusion from
rewards and billing (`scoring._excluded_owners`).

- an HTTP launch naming a probe run's vm id, a probe user id or a probe
  tenant id is refused `disk-probe-id-reserved` (400) before anything is
  staged, whoever calls;
- the orchestrator's in-process launch (`disk_probe=True`) passes, through
  the real intake, and must itself name its own run and a probe owner;
- only the probe pins its OS pool (`os_pool`, `_check_os_pool_pin`): any
  other launch naming one is refused `os-pool-reserved`, and the probe's
  launch must pin exactly its run's pool;
- a probe owner's VMs earn no reward weight and no bill."""

from __future__ import annotations

from typing import Any

import pytest
from django.test import override_settings
from django.utils import timezone

from apps.disktier import probe
from apps.disktier.models import DiskProbeRun, ProbeRunState
from apps.disktier.tests.probe_helpers import NODE, OWNER, TENANT, USER, make_run
from apps.images.tests.conftest import make_golden_bake  # noqa: F401 — fixture
from apps.orchestration import launch_jobs
from apps.orchestration.models import LaunchJob
from apps.orchestration.tests.test_launch_api import (  # noqa: F401 — fixtures
    LAUNCH_URL,
    _intent,
    stub_golden_transit,
    stub_vault_put,
)
from apps.scheduler import scoring
from apps.scheduler.models import PlacementStatus, UsageAccrual
from apps.scheduler.tests.factories import (
    make_placement,
    make_vm,
    node_id,
    observe_chain_epoch,
)

pytestmark = pytest.mark.django_db


@pytest.fixture(autouse=True)
def _owners(settings: Any) -> None:
    settings.VALI_DISK_PROBE_OWNERS = [OWNER]


# ─── HTTP: refused ───────────────────────────────────────────────────


@pytest.mark.parametrize(
    "override",
    [
        {"user_id": USER},
        {"tenant_id": TENANT},
        {"user_id": USER, "tenant_id": TENANT},
    ],
)
def test_an_http_launch_with_a_probe_owner_is_refused(
    root_client: Any,
    stub_vault_put: list,  # noqa: F811
    override: dict,
) -> None:
    resp = root_client.post(LAUNCH_URL, _intent(**override), format="json")
    assert resp.status_code == 400, resp.content
    assert resp.json()["category"] == "disk-probe-id-reserved"
    assert stub_vault_put == []
    assert not LaunchJob.objects.exists()


def test_an_http_launch_of_a_probe_vm_id_is_refused(
    root_client: Any,
    stub_vault_put: list,  # noqa: F811
) -> None:
    run = make_run(state=ProbeRunState.LAUNCHING, vm_id="hipc-4242-0a0b0c0d")
    resp = root_client.post(
        LAUNCH_URL,
        _intent(vm_id=run.vm_id, tenant_id="t-other", user_id="u-other"),
        format="json",
    )
    assert resp.status_code == 400, resp.content
    assert resp.json()["category"] == "disk-probe-id-reserved"
    assert stub_vault_put == []


def test_a_closed_probe_vm_id_stays_reserved(
    root_client: Any,
    stub_vault_put: list,  # noqa: F811
) -> None:
    """A probe run's vm id is reserved for good, torn down or not."""
    run = make_run(
        state=ProbeRunState.TORN_DOWN, vm_id="hipc-4242-0e0e0e0e", torn_down_at=timezone.now()
    )
    resp = root_client.post(
        LAUNCH_URL, _intent(vm_id=run.vm_id, tenant_id="t-x", user_id="u-x"), format="json"
    )
    assert resp.status_code == 400
    assert resp.json()["category"] == "disk-probe-id-reserved"


@pytest.mark.parametrize("pool", ["nvme0", "default", "", None, 7])
def test_an_http_launch_naming_an_os_pool_is_refused(
    root_client: Any,
    stub_vault_put: list,  # noqa: F811
    pool: Any,
) -> None:
    """vali chooses every VM's OS pool; the key alone is refused, whatever
    its value (`null` is absent)."""
    resp = root_client.post(LAUNCH_URL, {**_intent(), "os_pool": pool}, format="json")
    if pool is None:
        assert resp.status_code == 202, resp.content
        assert "pinned_os_pool" not in LaunchJob.objects.get().spec_json
        return
    assert resp.status_code == 400, resp.content
    assert resp.json()["category"] == "os-pool-reserved"
    assert stub_vault_put == []
    assert not LaunchJob.objects.exists()


def test_a_tenant_launch_is_untouched(
    root_client: Any,
    stub_vault_put: list,  # noqa: F811
) -> None:
    resp = root_client.post(LAUNCH_URL, _intent(), format="json")
    assert resp.status_code == 202, resp.content


# ─── in-process ──────────────────────────────────────────────────────


def _probe_intent(run: DiskProbeRun) -> dict[str, Any]:
    owner = probe._owner_of(run)
    assert owner is not None
    return probe.launch_intent(run, owner)


def test_the_orchestrator_must_name_its_run_and_a_probe_owner() -> None:
    run = make_run(state=ProbeRunState.SCHEDULED)
    ok = {"vm_id": run.vm_id, "user_id": USER, "tenant_id": TENANT}
    launch_jobs._check_disk_probe_role(ok, disk_probe=True)
    for bad in (
        {**ok, "vm_id": "hipc-4242-ffffffff"},  # no run
        {**ok, "user_id": "77"},  # a real tenant's identity
        {**ok, "tenant_id": "5FHneW46xGXgs5mUiveU4sbTyGBzmstUspZC92UhjJM694ty"},
    ):
        with pytest.raises(launch_jobs.LaunchIntentError) as exc:
            launch_jobs._check_disk_probe_role(bad, disk_probe=True)
        assert exc.value.category == "disk-probe-id-reserved"
    # Without the flag the same intent is the reserved one.
    with pytest.raises(launch_jobs.LaunchIntentError):
        launch_jobs._check_disk_probe_role(ok, disk_probe=False)


def test_the_orchestrator_must_pin_exactly_its_runs_pool_and_chip() -> None:
    run = make_run(state=ProbeRunState.SCHEDULED, pool="nvme0")
    ok = {"vm_id": run.vm_id, "os_pool": "nvme0", "platform_id": run.chip_id}
    launch_jobs._check_os_pool_pin(ok, run)
    for bad in (
        {**ok, "os_pool": "default"},  # another pool than the one recorded
        {**ok, "os_pool": "nvme1"},
        {"vm_id": run.vm_id, "platform_id": run.chip_id},  # unpinned: the chooser picks
        {**ok, "os_pool": ""},
        # A pool is one node's: the launch is bound to the run's chip at intake.
        {**ok, "platform_id": ""},
        {"vm_id": run.vm_id, "os_pool": "nvme0"},
        {**ok, "platform_id": "cd" * 32},
    ):
        with pytest.raises(launch_jobs.LaunchIntentError) as exc:
            launch_jobs._check_os_pool_pin(bad, run)
        assert exc.value.category == "os-pool-reserved"
    # Any other launch (no probe run): the key alone is refused.
    with pytest.raises(launch_jobs.LaunchIntentError) as exc:
        launch_jobs._check_os_pool_pin(ok, None)
    assert exc.value.category == "os-pool-reserved"
    launch_jobs._check_os_pool_pin({"vm_id": "x"}, None)
    # The probe's run comes from the identity check, read once.
    assert launch_jobs._check_disk_probe_role(
        {"vm_id": run.vm_id, "user_id": USER, "tenant_id": TENANT}, disk_probe=True
    ) == run
    assert launch_jobs._check_disk_probe_role({"vm_id": "x"}, disk_probe=False) is None


def test_a_pin_needs_a_golden_launch_and_a_pool_id() -> None:
    """`_build_spec_json` past the identity gates: a legacy launch's OS disk
    is always on `default` (a pin would be silently ignored), and the pin
    is a pool id."""
    with pytest.raises(launch_jobs.LaunchIntentError, match="golden") as exc:
        launch_jobs._build_spec_json({**_intent(), "os_pool": "nvme0"})
    assert exc.value.category == "bad-field"
    with pytest.raises(launch_jobs.LaunchIntentError, match="os_pool") as exc:
        launch_jobs._build_spec_json({**_intent(), "os_pool": "NVMe/0"})
    assert exc.value.category == "bad-field"


def test_the_orchestrator_launches_through_the_real_intake(
    settings: Any,
    make_golden_bake: Any,  # noqa: F811
    stub_vault_put: list,  # noqa: F811
    stub_golden_transit: dict,  # noqa: F811
) -> None:
    """The probe's own intent (a tenant's shape, golden by image name,
    pinned) is accepted by `start_launch` end to end, and the job records
    the probe VM with its pin and the medium flavor."""
    from apps.images.models import GoldenImage

    make_golden_bake("golden-probe-1")
    GoldenImage.objects.create(
        image_name="ubuntu", distro="ubuntu", bake_id="golden-probe-1", blessed_at=timezone.now()
    )
    settings.VALI_DISK_PROBE_ENABLED = True
    for pool in ("default", "nvme0"):
        run = probe.new_run(
            node_id=NODE, pool_id=pool, trigger="onboarding", chip_id="ab" * 32,
            now=timezone.now(),
        )
        assert probe.launch(run, now=timezone.now()) is True
        run.refresh_from_db()
        assert run.state == ProbeRunState.LAUNCHING
        job = LaunchJob.objects.get(job_id=run.launch_job_id)
        assert job.vm_id == run.vm_id
        assert job.tenant_id == TENANT
        assert job.flavor == "medium"
        assert job.spec_json["platform_id"] == "ab" * 32
        assert job.spec_json["user_id"] == USER
        assert job.decided_by.name == probe.ACTOR_NAME
        # The pool under test rides the job to the worker (`LaunchSpec`);
        # `default` pinned ⇒ the order names no pool.
        assert job.spec_json["pinned_os_pool"] == pool
        spec = launch_jobs.launch.LaunchSpec(**job.spec_json, kek_bytes=None, userdata=b"")
        assert spec.pinned_os_pool == pool


# ─── rewards and billing ─────────────────────────────────────────────


def _usage(vm_id: str, node: str, owner: str, units: int) -> None:
    vm = make_vm(vm_id=vm_id, lease_id=vm_id)
    make_placement(
        vm, node, status=PlacementStatus.BOUND.value, owner=owner, resource_class="small"
    )
    UsageAccrual.objects.create(
        epoch=2702, miner_node_id=node, vm_id=vm_id, resource_class="small", lease_id=vm_id,
        unit_seconds=units, billable_seconds=units,
    )


@override_settings(VALI_EPOCH_WEIGHT_SOURCE="usage", VALI_REWARD_EXCLUDED_OWNERS=[])
def test_a_probe_owner_earns_no_weight_and_no_bill() -> None:
    assert USER in scoring._excluded_owners()
    observe_chain_epoch(2702)
    _usage("hipc-4242-0a0b0c0d", node_id(1), USER, 3_600_000)
    _usage("hipc-77-0a0b0c0d", node_id(2), "77", 3_600_000)
    assert scoring.compute_epoch_weights() == {node_id(2): 3_600_000}
    owed = scoring.compute_owed_micro_usd({node_id(1): 1_000_000, node_id(2): 1_000_000})
    assert owed == {node_id(2): 1_000_000}


@override_settings(VALI_EPOCH_WEIGHT_SOURCE="snapshot", VALI_REWARD_EXCLUDED_OWNERS=[])
def test_the_snapshot_source_excludes_probe_placements_too() -> None:
    make_placement(make_vm("hipc-4242-0a0b0c0d"), node_id(1),
                   status=PlacementStatus.BOUND.value, owner=USER, resource_class="small")
    assert scoring._snapshot_weights() == {}


def test_no_probe_owner_configured_excludes_nobody_new(settings: Any) -> None:
    settings.VALI_DISK_PROBE_OWNERS = []
    settings.VALI_REWARD_EXCLUDED_OWNERS = []
    assert scoring._excluded_owners() == frozenset({settings.VALI_SYNTHETIC_TENANT_ID})
