"""E4 gate (o): dedicated disks in `decide_placement` and its one assembly
site (`service.placement_arguments`)."""

from __future__ import annotations

import pytest
from django.test import override_settings

from apps.disktier.dedicated import DedicatedRequest
from apps.disktier.tests.dedicated_helpers import ON, capable, make_disk
from apps.scheduler import service
from apps.scheduler.placement import (
    NO_DEDICATED_CAPACITY,
    NO_HOST_FITS_DISKS,
    DedicatedFit,
    PlacementError,
    decide_placement,
)

from .factories import make_dispatchable_identity, make_miner, make_snapshot, node_id

N1, N2 = node_id(1), node_id(2)
SNAP = make_snapshot(10, [make_miner(1), make_miner(2)])


def _decide(fit: DedicatedFit | None, *, capacity=None, **kw) -> str:
    return decide_placement(
        snapshot=SNAP,
        capacity_by_node=capacity if capacity is not None else {N1: 4, N2: 4},
        load_by_node={},
        family_load_by_node={},
        max_epoch_lag=2,
        dedicated_fit=fit,
        **kw,
    )


def test_only_a_node_with_enough_free_disks_is_a_candidate() -> None:
    assert _decide(None) == N1  # the tie-break
    assert _decide(DedicatedFit(count=2, free_by_node={N1: 1, N2: 2})) == N2
    assert _decide(DedicatedFit(count=1, free_by_node={N1: 1})) == N1


@pytest.mark.parametrize("free", [{}, {N1: 1, N2: 1}])
def test_no_node_with_the_disks_is_no_dedicated_capacity(free) -> None:
    with pytest.raises(PlacementError) as exc:
        _decide(DedicatedFit(count=2, free_by_node=free))
    assert exc.value.category == NO_DEDICATED_CAPACITY


@pytest.mark.parametrize(
    "kw",
    [
        dict(capacity={N1: 4, N2: 0}),  # full
        dict(cordoned={N2.lower(): "ops"}),
        dict(excluded=frozenset({N2})),
    ],
)
def test_disks_on_a_node_that_does_not_take_the_vm_is_no_host_fits_disks(kw) -> None:
    with pytest.raises(PlacementError) as exc:
        _decide(DedicatedFit(count=2, free_by_node={N2: 3}), **kw)
    assert exc.value.category == NO_HOST_FITS_DISKS


def test_a_boot_slot_wait_still_comes_first() -> None:
    with pytest.raises(PlacementError) as exc:
        _decide(
            DedicatedFit(count=1, free_by_node={N2: 1}),
            booting_by_node={N2: 3},
            max_booting_per_node=3,
        )
    assert exc.value.category == "miners-booting"


@pytest.mark.django_db
def test_without_a_request_the_arguments_are_byte_identical(django_assert_num_queries) -> None:
    with django_assert_num_queries(0):
        assert service.dedicated_arguments(None) == {}
    args = service.placement_arguments(snapshot=SNAP, tenant_id="t", user_id="u", flavor="small")
    assert "dedicated_fit" not in args


@pytest.mark.django_db
@override_settings(**ON)
def test_the_assembly_counts_the_dispatchable_capable_nodes() -> None:
    make_dispatchable_identity(1)
    make_dispatchable_identity(2)
    capable(N1)
    capable(N2)
    make_disk("wwn-0x01", node=N1)
    make_disk("wwn-0x02", node=N2)
    make_disk("wwn-0x03", node=N2)
    make_disk("wwn-0x04", node=node_id(3))  # not dispatchable
    capable(node_id(3))
    fit = service.placement_arguments(
        snapshot=SNAP,
        tenant_id="t",
        user_id="u",
        flavor="small",
        dedicated=DedicatedRequest("hdd", 2, 16000),
    )["dedicated_fit"]
    assert fit == DedicatedFit(count=2, free_by_node={N1: 1, N2: 2})


# ── a pinned VM is never placed outside its launch (E4 contract §5) ──


def _pinned(vm_id: str = "vm-1"):
    from apps.disktier.models import DedicatedDisk

    from .factories import make_order_ticket, make_vm

    vm = make_vm(vm_id, f"lease-{vm_id}")
    make_order_ticket(vm_id, "tenant-1")
    DedicatedDisk.objects.create(
        miner_node_id=N1,
        disk_id="wwn-0x01",
        state="assigned",
        assigned_vm=vm,
        assigned_slot="x0",
        size_bytes=20000 * 2**30,
        verified_tier="hdd",
    )
    return vm


@pytest.mark.django_db
def test_place_refuses_a_pinned_vm(root_client) -> None:
    from django.urls import reverse

    _pinned()
    resp = root_client.post(
        reverse("scheduler_place"), {"vm_id": "vm-1", "resource_class": "std"}, format="json"
    )
    assert resp.status_code == 409, resp.content
    assert resp.json()["category"] == "dedicated-pinned"


@pytest.mark.django_db
def test_a_failed_placement_of_a_pinned_vm_is_not_replaced() -> None:
    from apps.scheduler import views

    from .factories import make_placement

    vm = _pinned()
    failed = make_placement(vm, N1, status="failed")
    replacement, error = views._replace(vm, failed, None)
    assert replacement is None
    assert error is not None and error["category"] == "dedicated-pinned"
