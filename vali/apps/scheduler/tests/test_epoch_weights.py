"""`GET /v1/admin/epoch-weights` — the §23 per-miner reward weights the
epoch-close worker submits on-chain."""

from __future__ import annotations

import pytest
from django.urls import reverse
from rest_framework import status
from rest_framework.test import APIClient

from apps.scheduler.models import PlacementStatus

from .factories import make_placement, make_vm, node_id

pytestmark = pytest.mark.django_db

URL = reverse("epoch_weights")


def test_unauthenticated_allowed() -> None:
    # AllowAny by design — the CNP (not a token) gates who can reach it.
    resp = APIClient().get(URL)
    assert resp.status_code == status.HTTP_200_OK


def test_empty_when_no_bound_placements(authed_client: APIClient) -> None:
    resp = authed_client.get(URL)
    assert resp.status_code == status.HTTP_200_OK
    assert resp.json() == {"weights": {}, "total_weight": 0, "miners": 0}


def test_weights_sum_bound_placements_per_miner(authed_client: APIClient) -> None:
    # Two bound VMs on miner 1, one on miner 2; a Pending one is ignored.
    # resource_class must be a real catalogue flavor (else units = 0).
    b = dict(status=PlacementStatus.BOUND.value, resource_class="small")
    make_placement(make_vm("vm-a"), node_id(1), **b)
    make_placement(make_vm("vm-b"), node_id(1), **b)
    make_placement(make_vm("vm-c"), node_id(2), **b)
    make_placement(
        make_vm("vm-d"),
        node_id(3),
        status=PlacementStatus.PENDING.value,
        resource_class="small",
    )

    body = authed_client.get(URL).json()
    assert body["miners"] == 2
    w = body["weights"]
    assert node_id(1) in w and node_id(2) in w
    assert node_id(3) not in w  # pending excluded
    # miner 1 hosts twice what miner 2 does (same resource_class) → 2× weight.
    assert w[node_id(1)] == 2 * w[node_id(2)]
    assert body["total_weight"] == w[node_id(1)] + w[node_id(2)]
