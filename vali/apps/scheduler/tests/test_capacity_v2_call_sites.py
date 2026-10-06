"""Every placement decision asks capacity v2 about the VM's OWN flavor.

A call site that passed a constant (or nothing) would size every VM as
the reference slot — a `2xlarge` admitted as a `medium`. Each test here
records the `resource_class` handed to `service.resource_fit` on one real
path and checks it is the VM's."""

from __future__ import annotations

import pytest
from rest_framework import status
from rest_framework.test import APIClient

from apps.scheduler import service
from apps.scheduler.models import PlacementStatus
from apps.scheduler.placement import ResourceFit

from .factories import (
    make_dispatchable_identity,
    make_miner,
    make_placement,
    make_snapshot,
    make_vm,
    make_vm_with_ticket,
)
from .test_views import PLACE_URL, _fail_url, _mock_chain

pytestmark = pytest.mark.django_db


@pytest.fixture
def dispatchable() -> None:
    for seed in (1, 2):
        make_dispatchable_identity(seed)


@pytest.fixture
def asked(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    calls: list[str] = []

    def record(resource_class: str, **kw: object) -> ResourceFit:
        calls.append(resource_class)
        return ResourceFit(resource_class, fits_by_node={}, free_fraction_by_node={})

    monkeypatch.setattr(service, "resource_fit", record)
    return calls


def test_place_asks_about_the_requested_resource_class(
    root_client: APIClient, monkeypatch: pytest.MonkeyPatch, asked: list[str], dispatchable: None
) -> None:
    make_vm_with_ticket("vm-1", "tenant-1")
    _mock_chain(monkeypatch, make_snapshot(10, [make_miner(1)]))
    resp = root_client.post(PLACE_URL, {"vm_id": "vm-1", "resource_class": "xlarge"}, format="json")
    assert resp.status_code == status.HTTP_201_CREATED, resp.content
    assert asked == ["xlarge"]


def test_replace_asks_about_the_failed_vms_resource_class(
    root_client: APIClient, monkeypatch: pytest.MonkeyPatch, asked: list[str], dispatchable: None
) -> None:
    vm = make_vm("vm-1")
    make_placement(
        vm,
        make_miner(1).node_id,
        status=PlacementStatus.PENDING.value,
        vm_family="tenant-1",
        resource_class="large",
    )
    _mock_chain(monkeypatch, make_snapshot(10, [make_miner(1), make_miner(2)]))
    resp = root_client.post(_fail_url("vm-1"), {"if_version": 1, "reason": "drop"}, format="json")
    assert resp.status_code == status.HTTP_200_OK, resp.content
    assert asked == ["large"]


def test_launch_asks_about_the_launch_flavor(
    monkeypatch: pytest.MonkeyPatch, asked: list[str]
) -> None:
    from apps.identity.models import PrincipalScope, ServiceClient
    from apps.orchestration.services import launch
    from apps.orchestration.tests.test_launch_service import (
        _outcome,
        _register_miner,
        _spec,
    )
    from apps.scheduler import chain

    actor = ServiceClient.objects.create(scope=PrincipalScope.OPERATOR.value, name="launcher")
    _register_miner(1)
    monkeypatch.setattr(chain, "read_miner_status", lambda: make_snapshot(10, [make_miner(1)]))
    monkeypatch.setattr(
        launch, "launch_on_miner", lambda spec, miner: _outcome(launch.ACCEPTED, miner.miner_id)
    )
    launch.launch_vm(_spec(flavor="large"), actor)
    assert asked == ["large"]
