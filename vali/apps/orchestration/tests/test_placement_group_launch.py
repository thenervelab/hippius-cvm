"""`placement_group` on `POST /v1/vm/launch`: shape-checked at intake,
stamped on the Vm, enforced by the scheduler (anti-affinity)."""

from __future__ import annotations

import pytest
from django.utils import timezone

from apps.lifecycle.models import Vm
from apps.orchestration import launch_jobs
from apps.orchestration.models import LaunchJob
from apps.orchestration.services import launch

from .factories import make_vm
from .test_launch_api import LAUNCH_URL, _intent, stub_vault_put  # noqa: F401 — fixture

pytestmark = pytest.mark.django_db


def test_the_group_is_optional(root_client, stub_vault_put) -> None:  # noqa: F811
    resp = root_client.post(LAUNCH_URL, _intent(), format="json")
    assert resp.status_code == 202, resp.content
    assert LaunchJob.objects.get(job_id=resp.json()["job_id"]).spec_json["placement_group"] == ""


def test_the_group_reaches_the_spec(root_client, stub_vault_put) -> None:  # noqa: F811
    resp = root_client.post(LAUNCH_URL, _intent(placement_group="db-1"), format="json")
    assert resp.status_code == 202, resp.content
    job = LaunchJob.objects.get(job_id=resp.json()["job_id"])
    assert job.spec_json["placement_group"] == "db-1"


@pytest.mark.parametrize("bad", ["DB", "db_1", "a" * 65, "db/1", 7, " db"])
def test_a_malformed_group_is_a_400(root_client, stub_vault_put, bad) -> None:  # noqa: F811
    resp = root_client.post(
        LAUNCH_URL, _intent(vm_id="vm-group", placement_group=bad), format="json"
    )
    assert resp.status_code == 400, (bad, resp.content)
    assert resp.json()["category"] == "bad-field"
    assert "placement_group" in resp.json()["error"]
    assert LaunchJob.objects.count() == 0


def test_the_group_survives_into_the_launch_spec_and_onto_the_vm() -> None:
    spec_json = launch_jobs._build_spec_json(_intent(placement_group="web"))
    spec = launch.LaunchSpec(**spec_json, kek_bytes=None, userdata=b"x")
    assert spec.placement_group == "web"
    old = {k: v for k, v in spec_json.items() if k != "placement_group"}
    assert launch.LaunchSpec(**old, kek_bytes=None, userdata=b"x").placement_group == ""
    vm = launch._ensure_vm_row(spec)
    assert (vm.tenant_id, vm.placement_group) == ("t-api", "web")


def test_the_group_is_echoed_on_the_vm(root_client) -> None:
    vm = make_vm("vm-g")
    assert root_client.get("/v1/vm/vm-g/state").json()["placement_group"] is None
    Vm.objects.filter(pk=vm.pk).update(placement_group="web")
    assert root_client.get("/v1/vm/vm-g/state").json()["placement_group"] == "web"


def _launch(monkeypatch, vm_id: str, group: str, seeds: list[int]) -> launch.LaunchResult:
    from apps.identity.models import PrincipalScope, ServiceClient
    from apps.scheduler import chain
    from apps.scheduler.tests.factories import make_miner, make_snapshot

    monkeypatch.setattr(
        chain, "read_miner_status", lambda: make_snapshot(10, [make_miner(s) for s in seeds])
    )
    spec = launch.LaunchSpec(
        **launch_jobs._build_spec_json(_intent(vm_id=vm_id, placement_group=group)),
        kek_bytes=None,
        userdata=b"#cloud-config\n",
    )
    actor = ServiceClient.objects.create(scope=PrincipalScope.OPERATOR.value, name="launcher")
    return launch.launch_vm(spec, actor)


def test_a_launch_no_miner_can_take_fails_anti_affinity(monkeypatch) -> None:
    """End to end through the real scheduler: the only miner already carries
    a VM of the tenant's group, so the launch fails — it never doubles up."""
    from apps.scheduler.models import MinerCapacity
    from apps.scheduler.tests.factories import make_dispatchable_identity, node_id

    miner = make_dispatchable_identity(1)
    MinerCapacity.objects.create(
        miner_node_id=node_id(1),
        status="active",
        capacity_slots=8,
        observed_epoch=10,
        data_epoch=10,
        refreshed_at=timezone.now(),
    )
    first = make_vm("vm-g-1", host=miner.miner_id)
    Vm.objects.filter(pk=first.pk).update(tenant_id="t-api", placement_group="db")
    result = _launch(monkeypatch, "vm-g-2", "db", [1])
    assert result.ok is False
    assert result.outcome == "placement-anti-affinity-unsatisfiable"


def test_another_group_or_tenant_does_not_block(monkeypatch) -> None:
    from apps.scheduler import service as sched
    from apps.scheduler.tests.factories import make_dispatchable_identity

    miner = make_dispatchable_identity(1)
    first = make_vm("vm-g-1", host=miner.miner_id)
    Vm.objects.filter(pk=first.pk).update(tenant_id="t-api", placement_group="db")
    assert sched.group_nodes("t-api", "web") == frozenset()
    assert sched.group_nodes("t-other", "db") == frozenset()
    assert sched.group_nodes("t-api", "db") == frozenset({miner.chain_node_id.lower()})


def test_a_relaunch_cannot_change_the_group(root_client, stub_vault_put) -> None:  # noqa: F811
    make_vm("vm-g")
    Vm.objects.filter(vm_id="vm-g").update(tenant_id="t-api", placement_group="db")
    resp = root_client.post(LAUNCH_URL, _intent(vm_id="vm-g", placement_group="web"), format="json")
    assert resp.status_code == 409, resp.content
    assert "placement group" in resp.json()["error"]
    # Omitted keeps the row's group (the worker reads it off the row).
    resp = root_client.post(LAUNCH_URL, _intent(vm_id="vm-g"), format="json")
    assert resp.status_code != 409, resp.content


def test_a_named_miner_reads_the_group_off_the_row(monkeypatch) -> None:
    """`vali_create_vm` builds a spec without the group: the row's wins."""
    from apps.scheduler.tests.factories import make_dispatchable_identity

    m1 = make_dispatchable_identity(1)
    sibling = make_vm("vm-g-1", host=m1.miner_id)
    Vm.objects.filter(pk=sibling.pk).update(tenant_id="t-api", placement_group="db")
    again = make_vm("vm-g-2")
    Vm.objects.filter(pk=again.pk).update(tenant_id="t-api", placement_group="db")
    spec = launch.LaunchSpec(
        **launch_jobs._build_spec_json(_intent(vm_id="vm-g-2")),
        kek_bytes=None,
        userdata=b"#cloud-config\n",
    )
    monkeypatch.setattr(launch, "_refuse_miner_for_customer_keys", lambda *a, **k: None)
    with pytest.raises(launch.LaunchConfigError, match="anti-affinity"):
        launch.launch_on_named_miner(spec, m1, decided_by=None)
