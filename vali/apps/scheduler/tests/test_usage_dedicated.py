"""E4 / design §8: miner pay for dedicated disks — units per GiB of each
slot its host still serves, carried by `VmBillingBinding`, behind a
default-off rate (`VALI_DEDICATED_MILLIUNITS_PER_GB`): off, accrual is byte
for byte what it was."""

from __future__ import annotations

import pytest
from django.utils import timezone

from apps.disktier.models import DedicatedDisk, PlacementDisk
from apps.scheduler import usage
from apps.scheduler.models import PlacementStatus, UsageAccrual, VmBillingBinding
from apps.scheduler.tests.factories import make_placement, make_vm

from .test_usage import (  # noqa: F401 — the autouse clock fixture
    NODE,
    _envelope,
    _fields,
    _fresh_now,
    _patch_units,
    _patch_verify,
)

pytestmark = pytest.mark.django_db

#: Two slots of 22300 GiB each.
SLOTS = 2 * 22300


def _pinned(*, dedicated_gb: int = SLOTS) -> list[DedicatedDisk]:
    vm = make_vm("vm-1", "lease-1")
    placement = make_placement(vm, NODE, status=PlacementStatus.BOUND.value)
    disks = []
    for slot in ("x0", "x1"):
        disk = DedicatedDisk.objects.create(
            miner_node_id=NODE,
            disk_id=f"wwn-0x{slot}",
            state="assigned",
            assigned_vm=vm,
            assigned_slot=slot,
            size_bytes=22354 * 2**30,
            verified_size_bytes=22354 * 2**30,
            verified_tier="hdd",
            reported_state="assigned",
            reported_vm_id="vm-1",
            reported_at=timezone.now(),
        )
        PlacementDisk.objects.create(
            placement=placement,
            slot=slot,
            kind="dedicated",
            dedicated_disk=disk,
            size_gb=22300,
            required_tier="hdd",
        )
        disks.append(disk)
    VmBillingBinding.objects.create(
        vm_id="vm-1",
        node_id_hex=NODE,
        resource_class="small",
        lease_id="lease-1",
        dedicated_gb=dedicated_gb,
    )
    return disks


def _accrue(monkeypatch) -> tuple[int, int]:
    _envelope()
    _patch_units(monkeypatch, 100)
    _patch_verify(monkeypatch, fixed=_fields(period_start=1000, period_end=1060))
    assert usage.accrue_usage_once().accrued == 1
    a = UsageAccrual.objects.get()
    return a.billable_seconds, a.unit_seconds


def test_off_by_default_and_byte_identical(monkeypatch, settings) -> None:
    assert settings.VALI_DEDICATED_MILLIUNITS_PER_GB == 0
    _pinned()
    assert _accrue(monkeypatch) == (60, 100 * 60)


def test_on_each_served_slot_adds_its_units(monkeypatch, settings) -> None:
    settings.VALI_DEDICATED_MILLIUNITS_PER_GB = 5
    _pinned()
    assert _accrue(monkeypatch) == (60, 100 * 60 + SLOTS * 5 * 60 // 1000)


@pytest.mark.parametrize(
    "host_says",
    [
        dict(reported_state="failed"),
        dict(reported_state="unavailable"),
        dict(reported_state="replaced"),
        dict(size_bytes=1000 * 2**30),  # smaller than probed
        dict(reported_at=None),  # never reported held
        dict(reported_vm_id="vm-other"),  # held for another VM
        dict(reported_state="free", reported_vm_id=""),
    ],
)
def test_a_slot_the_host_no_longer_serves_is_withheld(monkeypatch, settings, host_says) -> None:
    settings.VALI_DEDICATED_MILLIUNITS_PER_GB = 5
    disks = _pinned()
    DedicatedDisk.objects.filter(pk=disks[0].pk).update(**host_says)
    assert _accrue(monkeypatch) == (60, 100 * 60 + 22300 * 5 * 60 // 1000)


def test_the_guests_own_claim_withholds_nothing(monkeypatch, settings) -> None:
    settings.VALI_DEDICATED_MILLIUNITS_PER_GB = 5
    _pinned()
    PlacementDisk.objects.update(observed_state="mismatch")
    assert _accrue(monkeypatch) == (60, 100 * 60 + SLOTS * 5 * 60 // 1000)


def test_never_more_than_the_binding_provisioned(monkeypatch, settings) -> None:
    settings.VALI_DEDICATED_MILLIUNITS_PER_GB = 5
    _pinned(dedicated_gb=22300)
    assert _accrue(monkeypatch) == (60, 100 * 60 + 22300 * 5 * 60 // 1000)


# ── per sold tier (contract §8) ─────────────────────────────────────


def test_the_default_by_tier_setting_is_empty(settings) -> None:
    assert settings.VALI_DEDICATED_MILLIUNITS_PER_GB_BY_TIER == {}


def test_a_by_tier_rate_alone_turns_pay_on(monkeypatch, settings) -> None:
    # The flat rate is 0, but slots sold at hdd have their own rate.
    settings.VALI_DEDICATED_MILLIUNITS_PER_GB_BY_TIER = {"hdd": 4}
    _pinned()
    assert _accrue(monkeypatch) == (60, 100 * 60 + SLOTS * 4 * 60 // 1000)


def test_a_by_tier_rate_for_another_tier_changes_nothing(monkeypatch, settings) -> None:
    settings.VALI_DEDICATED_MILLIUNITS_PER_GB = 5
    settings.VALI_DEDICATED_MILLIUNITS_PER_GB_BY_TIER = {"ssd": 50, "nvme": 90}
    _pinned()
    assert _accrue(monkeypatch) == (60, 100 * 60 + SLOTS * 5 * 60 // 1000)


def test_each_slot_is_paid_at_its_sold_tier_never_the_disks_verified_one(
    monkeypatch, settings
) -> None:
    settings.VALI_DEDICATED_MILLIUNITS_PER_GB = 5
    settings.VALI_DEDICATED_MILLIUNITS_PER_GB_BY_TIER = {"ssd": 20, "nvme": 90}
    disks = _pinned()
    # Both disks verified nvme; x0 sold at ssd, x1 at hdd (the flat rate).
    DedicatedDisk.objects.update(verified_tier="nvme")
    PlacementDisk.objects.filter(dedicated_disk=disks[0]).update(required_tier="ssd")
    assert _accrue(monkeypatch) == (60, 100 * 60 + (22300 * 20 + 22300 * 5) * 60 // 1000)


def test_the_binding_cap_counts_slots_in_slot_order(monkeypatch, settings) -> None:
    settings.VALI_DEDICATED_MILLIUNITS_PER_GB_BY_TIER = {"hdd": 5, "ssd": 20}
    disks = _pinned(dedicated_gb=22300 + 1000)
    PlacementDisk.objects.filter(dedicated_disk=disks[1]).update(required_tier="ssd")
    # x0 (hdd) whole, then 1000 GiB of x1 (ssd).
    assert _accrue(monkeypatch) == (60, 100 * 60 + (22300 * 5 + 1000 * 20) * 60 // 1000)


def test_a_vm_without_dedicated_disks_is_as_before(monkeypatch, settings) -> None:
    settings.VALI_DEDICATED_MILLIUNITS_PER_GB = 5
    VmBillingBinding.objects.create(
        vm_id="vm-1", node_id_hex=NODE, resource_class="small", lease_id="lease-1"
    )
    assert _accrue(monkeypatch) == (60, 100 * 60)
