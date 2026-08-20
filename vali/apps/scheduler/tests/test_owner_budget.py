"""DB tests for the per-owner sub-budget input (audit M-per-tenant-cap).

`service.owner_load_by_node(owner)` counts an owner's active placements
per miner — the signal `decide_placement` uses to spread one owner's VMs
across the fleet instead of monopolising a single miner.
"""

from __future__ import annotations

import pytest

from apps.scheduler import service
from apps.scheduler.models import PlacementStatus

from .factories import make_placement, make_vm, node_id

pytestmark = pytest.mark.django_db


def test_owner_load_counts_only_that_owners_active_placements() -> None:
    m1, m2 = node_id(1), node_id(2)
    # owner "alice": 2 on m1, 1 on m2.
    make_placement(make_vm("a1"), m1, owner="alice", vm_family="a1")
    make_placement(make_vm("a2"), m1, owner="alice", vm_family="a2")
    make_placement(make_vm("a3"), m2, owner="alice", vm_family="a3")
    # owner "bob": 1 on m1 — must NOT count toward alice.
    make_placement(make_vm("b1"), m1, owner="bob", vm_family="b1")
    # a FAILED (terminal, non-active) alice placement on m2 — excluded.
    make_placement(
        make_vm("a4"),
        m2,
        owner="alice",
        vm_family="a4",
        status=PlacementStatus.FAILED.value,
    )

    load = service.owner_load_by_node("alice")
    assert load == {m1: 2, m2: 1}


def test_owner_load_empty_owner_is_inert() -> None:
    make_placement(make_vm("x1"), node_id(1), owner="", vm_family="x1")
    assert service.owner_load_by_node("") == {}
