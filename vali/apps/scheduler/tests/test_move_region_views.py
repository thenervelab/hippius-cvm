"""The fail-closed region gate on the scheduler's move paths: the price
recommendation approve (§25), and `/place` / `/fail` re-placement of a VM
that has run somewhere."""

from __future__ import annotations

import pytest
from django.urls import reverse
from rest_framework import status
from rest_framework.test import APIClient

from apps.orchestration.models import MigrationJob
from apps.orchestration.tests.factories import make_launch_record, make_vm
from apps.orchestration.tests.test_move_region import (  # noqa: F401 — fixture
    _locate,
    _miners,
)
from apps.scheduler import service as sched

from .factories import make_order_ticket

pytestmark = pytest.mark.django_db


def test_a_price_recommendation_approve_resolves_the_chain_node_id(
    root_client: APIClient,
) -> None:
    """The price watch suggests a chain `node_id`; the approve migrates to
    that miner (`start_migration` keys on the `miner_id`)."""
    from apps.scheduler.models import PriceMigrationRecommendation

    vm = make_vm(host="node-src")
    make_launch_record(vm, region="FR")
    rec = PriceMigrationRecommendation.objects.create(
        recommendation_id="rec-1",
        vm=vm,
        current_node_id="c" * 64,
        suggested_dest_node_id="d" * 64,
        new_price=500,
        ceiling=100,
        effective_block=150,
    )
    resp = root_client.post(
        reverse("price_recommendation_approve", args=[rec.recommendation_id]),
        {"if_version": rec.version},
        format="json",
    )
    assert resp.status_code == status.HTTP_200_OK, resp.content
    job = MigrationJob.objects.get()
    assert (job.dest_node_id, job.region) == ("node-fr", "FR")


def test_place_refuses_a_vm_that_ran_somewhere_unknown(root_client: APIClient) -> None:
    make_vm("vm-1", host="node-src")  # no launch region, host never located
    make_order_ticket("vm-1", "tenant-1")
    resp = root_client.post(
        reverse("scheduler_place"), {"vm_id": "vm-1", "resource_class": "std"}, format="json"
    )
    assert resp.status_code == status.HTTP_409_CONFLICT, resp.content
    assert resp.json()["category"] == "region-unknown"


def test_the_placement_region_of_a_vm() -> None:
    """Ran somewhere: its region, `None` when it cannot be told. Never ran:
    only what its launch asked (`""` — nothing to cross)."""
    ran = make_vm("vm-1", host="node-src")
    assert sched.placement_region_for_vm(ran) is None
    _locate("node-src", "FR")
    assert sched.placement_region_for_vm(ran) == "FR"
    fresh = make_vm("vm-2", host="")
    assert sched.placement_region_for_vm(fresh) == ""
    make_launch_record(fresh, region="DE")
    assert sched.placement_region_for_vm(fresh) == "DE"


def test_move_region_falls_back_to_the_node_it_leaves() -> None:
    vm = make_vm("vm-1", host="")
    assert sched.move_region_for_vm(vm) == ""
    assert sched.move_region_for_vm(vm, from_node="d" * 64) == "FR"


def test_fail_does_not_replace_a_vm_of_unknown_region(root_client: APIClient) -> None:
    from apps.scheduler.models import PlacementStatus

    from .factories import make_placement

    vm = make_vm("vm-1", host="node-src")
    placement = make_placement(vm, "c" * 64, status=PlacementStatus.PENDING.value)
    resp = root_client.post(
        reverse("scheduler_fail", args=["vm-1"]),
        {"if_version": placement.version, "reason": "drop"},
        format="json",
    )
    assert resp.status_code == status.HTTP_200_OK, resp.content
    body = resp.json()
    assert body["replacement"] is None
    assert body["replacement_error"]["category"] == "region-unknown"


def test_fail_re_placement_keeps_require_failover_peer(root_client: APIClient, monkeypatch) -> None:
    from apps.scheduler.models import PlacementStatus

    from .factories import make_placement

    vm = make_vm("vm-1", host="node-src")
    make_launch_record(vm, region="FR", require_failover_peer=True)
    monkeypatch.setattr(sched, "failover_capable_node_ids", lambda **kw: {})
    placement = make_placement(vm, "c" * 64, status=PlacementStatus.PENDING.value)
    seen: dict = {}
    real = sched.failover_peer_arguments

    def spy(required: bool, vm_id: str = "") -> dict:
        seen["required"] = required
        return real(required, vm_id)

    monkeypatch.setattr(sched, "failover_peer_arguments", spy)
    from .factories import make_miner, make_snapshot
    from .test_views import _mock_chain

    _mock_chain(monkeypatch, make_snapshot(10, [make_miner(1), make_miner(2)]))
    resp = root_client.post(
        reverse("scheduler_fail", args=["vm-1"]),
        {"if_version": placement.version, "reason": "drop"},
        format="json",
    )
    assert resp.status_code == status.HTTP_200_OK, resp.content
    assert seen == {"required": True}
    assert resp.json()["replacement"] is None
