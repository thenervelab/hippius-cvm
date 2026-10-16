"""The disk-tier tables: their constraints, and a migration that runs both
ways."""

from __future__ import annotations

import uuid

import pytest
from django.db import IntegrityError, connection, transaction
from django.db.migrations.executor import MigrationExecutor
from django.utils import timezone

from apps.disktier.models import (
    DedicatedDisk,
    DedicatedDiskState,
    DiskKind,
    DiskProbeRun,
    MinerDiskHealthHourly,
    MinerStoragePool,
    PlacementDisk,
    ProbeTrigger,
    VmDiskIoHourly,
)
from apps.disktier.tiers import DiskTier
from apps.scheduler.tests.factories import make_placement, make_vm, node_id

_DISKTIER_0001 = ("disktier", "0001_initial")
_TABLES = (
    "disktier_minerstoragepool",
    "disktier_dedicateddisk",
    "disktier_diskproberun",
    "disktier_placementdisk",
    "disktier_vmdiskiohourly",
    "disktier_minerdiskhealthhourly",
)


# ─── MinerStoragePool ────────────────────────────────────────────────


@pytest.mark.django_db
def test_a_new_pool_is_unknown_and_healthy() -> None:
    pool = MinerStoragePool.objects.create(miner_node_id=node_id(1), pool_id="default")
    pool.refresh_from_db()
    assert pool.tier == DiskTier.UNKNOWN
    assert pool.health == "ok"
    assert pool.operator_override == ""
    assert pool.effective_tier == DiskTier.UNKNOWN


@pytest.mark.django_db
def test_the_override_wins_while_set() -> None:
    pool = MinerStoragePool(
        miner_node_id=node_id(1), pool_id="nvme0", tier=DiskTier.NVME, operator_override="unfit"
    )
    assert pool.effective_tier == DiskTier.UNFIT
    pool.operator_override = ""
    assert pool.effective_tier == DiskTier.NVME


@pytest.mark.django_db
def test_one_pool_id_per_node() -> None:
    MinerStoragePool.objects.create(miner_node_id=node_id(1), pool_id="nvme0")
    MinerStoragePool.objects.create(miner_node_id=node_id(2), pool_id="nvme0")
    with pytest.raises(IntegrityError), transaction.atomic():
        MinerStoragePool.objects.create(miner_node_id=node_id(1), pool_id="nvme0")


@pytest.mark.django_db
def test_unknown_is_not_an_override() -> None:
    with pytest.raises(IntegrityError), transaction.atomic():
        MinerStoragePool.objects.create(
            miner_node_id=node_id(1), pool_id="p", operator_override="unknown"
        )


# ─── DedicatedDisk ───────────────────────────────────────────────────


@pytest.mark.django_db
def test_a_declared_disk_waits_for_a_probe() -> None:
    disk = DedicatedDisk.objects.create(miner_node_id=node_id(1), disk_id="wwn-0x5000c500a1b2c3d4")
    disk.refresh_from_db()
    assert disk.state == DedicatedDiskState.PENDING_PROBE
    assert disk.verified_tier == DiskTier.UNKNOWN
    assert disk.desired_state == "active"


@pytest.mark.django_db
def test_one_disk_id_per_node() -> None:
    DedicatedDisk.objects.create(miner_node_id=node_id(1), disk_id="wwn-0x1")
    DedicatedDisk.objects.create(miner_node_id=node_id(2), disk_id="wwn-0x1")
    with pytest.raises(IntegrityError), transaction.atomic():
        DedicatedDisk.objects.create(miner_node_id=node_id(1), disk_id="wwn-0x1")


@pytest.mark.django_db
def test_an_assigned_disk_names_its_vm_and_slot() -> None:
    vm = make_vm("vm-a", "lease-a")
    DedicatedDisk.objects.create(
        miner_node_id=node_id(1),
        disk_id="wwn-0x1",
        state="assigned",
        assigned_vm=vm,
        assigned_slot="x0",
    )
    with pytest.raises(IntegrityError), transaction.atomic():
        DedicatedDisk.objects.create(miner_node_id=node_id(1), disk_id="wwn-0x2", state="assigned")
    with pytest.raises(IntegrityError), transaction.atomic():
        DedicatedDisk.objects.create(
            miner_node_id=node_id(1),
            disk_id="wwn-0x3",
            state="assigned",
            assigned_vm=vm,
        )


@pytest.mark.django_db
def test_only_an_assigned_disk_names_a_vm() -> None:
    vm = make_vm("vm-a", "lease-a")
    with pytest.raises(IntegrityError), transaction.atomic():
        DedicatedDisk.objects.create(
            miner_node_id=node_id(1),
            disk_id="wwn-0x1",
            state="free",
            assigned_vm=vm,
            assigned_slot="x0",
        )
    with pytest.raises(IntegrityError), transaction.atomic():
        DedicatedDisk.objects.create(
            miner_node_id=node_id(1), disk_id="wwn-0x2", state="free", assigned_slot="x0"
        )


@pytest.mark.django_db
def test_one_disk_per_slot_of_a_vm() -> None:
    vm = make_vm("vm-a", "lease-a")
    other = make_vm("vm-b", "lease-b")
    DedicatedDisk.objects.create(
        miner_node_id=node_id(1),
        disk_id="wwn-0x1",
        state="assigned",
        assigned_vm=vm,
        assigned_slot="x0",
    )
    DedicatedDisk.objects.create(
        miner_node_id=node_id(1),
        disk_id="wwn-0x2",
        state="assigned",
        assigned_vm=other,
        assigned_slot="x0",
    )
    with pytest.raises(IntegrityError), transaction.atomic():
        DedicatedDisk.objects.create(
            miner_node_id=node_id(1),
            disk_id="wwn-0x3",
            state="assigned",
            assigned_vm=vm,
            assigned_slot="x0",
        )


# ─── PlacementDisk ───────────────────────────────────────────────────


@pytest.mark.django_db
def test_a_placement_has_one_disk_per_slot() -> None:
    placement = make_placement(make_vm("vm-a", "lease-a"), node_id(1))
    PlacementDisk.objects.create(
        placement=placement,
        slot="os",
        kind=DiskKind.POOL,
        pool_id="default",
        size_gb=80,
        required_tier="nvme",
    )
    with pytest.raises(IntegrityError), transaction.atomic():
        PlacementDisk.objects.create(
            placement=placement,
            slot="os",
            kind=DiskKind.POOL,
            pool_id="nvme0",
            size_gb=80,
            required_tier="nvme",
        )


@pytest.mark.django_db
def test_a_pool_disk_names_a_pool_and_a_dedicated_disk_names_a_disk() -> None:
    placement = make_placement(make_vm("vm-a", "lease-a"), node_id(1))
    disk = DedicatedDisk.objects.create(miner_node_id=node_id(1), disk_id="wwn-0x1")
    PlacementDisk.objects.create(
        placement=placement,
        slot="x0",
        kind=DiskKind.DEDICATED,
        dedicated_disk=disk,
        size_gb=16764,
        required_tier="hdd",
    )
    for bad in (
        {"slot": "x1", "kind": DiskKind.POOL, "pool_id": ""},
        {"slot": "x1", "kind": DiskKind.POOL, "pool_id": "p", "dedicated_disk": disk},
        {"slot": "x1", "kind": DiskKind.DEDICATED},
        {"slot": "x1", "kind": DiskKind.DEDICATED, "dedicated_disk": disk, "pool_id": "p"},
    ):
        with pytest.raises(IntegrityError), transaction.atomic():
            PlacementDisk.objects.create(
                placement=placement, size_gb=10, required_tier="hdd", **bad
            )


@pytest.mark.django_db
def test_the_os_disk_lives_on_a_pool() -> None:
    placement = make_placement(make_vm("vm-a", "lease-a"), node_id(1))
    disk = DedicatedDisk.objects.create(miner_node_id=node_id(1), disk_id="wwn-0x1")
    with pytest.raises(IntegrityError), transaction.atomic():
        PlacementDisk.objects.create(
            placement=placement,
            slot="os",
            kind=DiskKind.DEDICATED,
            dedicated_disk=disk,
            size_gb=80,
            required_tier="nvme",
        )


@pytest.mark.django_db
@pytest.mark.parametrize("slot", ["x0", "x1"])
def test_a_pool_holds_only_the_os_disk(slot: str) -> None:
    placement = make_placement(make_vm("vm-a", "lease-a"), node_id(1))
    with pytest.raises(IntegrityError), transaction.atomic():
        PlacementDisk.objects.create(
            placement=placement,
            slot=slot,
            kind=DiskKind.POOL,
            pool_id="hdd0",
            size_gb=500,
            required_tier="hdd",
        )


@pytest.mark.django_db
@pytest.mark.parametrize("slot", ["x24", "x99", "y0", "x"])
def test_a_dedicated_slot_is_x0_to_x23(slot: str) -> None:
    placement = make_placement(make_vm("vm-a", "lease-a"), node_id(1))
    disk = DedicatedDisk.objects.create(miner_node_id=node_id(1), disk_id="wwn-0x1")
    PlacementDisk.objects.create(
        placement=placement,
        slot="x23",
        kind=DiskKind.DEDICATED,
        dedicated_disk=disk,
        size_gb=16764,
        required_tier="hdd",
    )
    with pytest.raises(IntegrityError), transaction.atomic():
        PlacementDisk.objects.create(
            placement=placement,
            slot=slot,
            kind=DiskKind.DEDICATED,
            dedicated_disk=disk,
            size_gb=16764,
            required_tier="hdd",
        )


@pytest.mark.django_db
@pytest.mark.parametrize("slot", ["os", "x24", "z"])
def test_an_assigned_disk_takes_a_dedicated_slot(slot: str) -> None:
    vm = make_vm("vm-a", "lease-a")
    with pytest.raises(IntegrityError), transaction.atomic():
        DedicatedDisk.objects.create(
            miner_node_id=node_id(1),
            disk_id="wwn-0x1",
            state="assigned",
            assigned_vm=vm,
            assigned_slot=slot,
        )


@pytest.mark.django_db
@pytest.mark.parametrize("tier", ["unknown", "unfit"])
def test_a_placement_disk_requires_a_sellable_tier(tier: str) -> None:
    placement = make_placement(make_vm("vm-a", "lease-a"), node_id(1))
    with pytest.raises(IntegrityError), transaction.atomic():
        PlacementDisk.objects.create(
            placement=placement,
            slot="os",
            kind=DiskKind.POOL,
            pool_id="default",
            size_gb=80,
            required_tier=tier,
        )


@pytest.mark.django_db
def test_a_dedicated_disk_held_by_a_placement_cannot_be_deleted() -> None:
    from django.db.models import ProtectedError

    placement = make_placement(make_vm("vm-a", "lease-a"), node_id(1))
    disk = DedicatedDisk.objects.create(miner_node_id=node_id(1), disk_id="wwn-0x1")
    PlacementDisk.objects.create(
        placement=placement,
        slot="x0",
        kind=DiskKind.DEDICATED,
        dedicated_disk=disk,
        size_gb=16764,
        required_tier="hdd",
    )
    with pytest.raises(ProtectedError):
        disk.delete()


# ─── DiskProbeRun / passive rows ─────────────────────────────────────


@pytest.mark.django_db
def test_a_probe_vm_is_one_run() -> None:
    fields = {
        "nonce": bytes(32),
        "miner_node_id": node_id(1),
        "owner": "owner-a",
        "trigger": ProbeTrigger.ONBOARDING,
        "flavor": "medium",
        "scheduled_at": timezone.now(),
    }
    run = DiskProbeRun.objects.create(vm_id="vm-probe-1", **fields)
    run.refresh_from_db()
    assert run.state == "scheduled"
    assert isinstance(run.run_id, uuid.UUID)
    assert run.targets == []
    with pytest.raises(IntegrityError), transaction.atomic():
        DiskProbeRun.objects.create(vm_id="vm-probe-1", **fields)


@pytest.mark.django_db
def test_one_passive_row_per_vm_device_hour() -> None:
    hour = timezone.now().replace(minute=0, second=0, microsecond=0)
    VmDiskIoHourly.objects.create(vm_id="vm-a", miner_node_id=node_id(1), device="vda", hour=hour)
    VmDiskIoHourly.objects.create(vm_id="vm-a", miner_node_id=node_id(1), device="vdb", hour=hour)
    with pytest.raises(IntegrityError), transaction.atomic():
        VmDiskIoHourly.objects.create(
            vm_id="vm-a", miner_node_id=node_id(1), device="vda", hour=hour
        )


@pytest.mark.django_db
def test_a_health_rollup_targets_exactly_one_pool_or_disk() -> None:
    hour = timezone.now().replace(minute=0, second=0, microsecond=0)
    MinerDiskHealthHourly.objects.create(miner_node_id=node_id(1), pool_id="default", hour=hour)
    MinerDiskHealthHourly.objects.create(miner_node_id=node_id(1), disk_id="wwn-0x1", hour=hour)
    with pytest.raises(IntegrityError), transaction.atomic():
        MinerDiskHealthHourly.objects.create(miner_node_id=node_id(1), hour=hour)
    with pytest.raises(IntegrityError), transaction.atomic():
        MinerDiskHealthHourly.objects.create(
            miner_node_id=node_id(1), pool_id="p", disk_id="wwn-0x2", hour=hour
        )


# ─── migration: forward and backward ─────────────────────────────────


def _tables() -> set[str]:
    with connection.cursor() as cursor:
        return set(connection.introspection.table_names(cursor))


@pytest.mark.django_db(transaction=True)
def test_the_migrations_are_reversible() -> None:
    executor = MigrationExecutor(connection)
    assert set(_TABLES) <= _tables()

    # All the way down…
    executor.migrate([("disktier", None)])
    assert not set(_TABLES) & _tables()

    # …one step up…
    executor = MigrationExecutor(connection)
    executor.migrate([_DISKTIER_0001])
    assert set(_TABLES) <= _tables()

    # …and back to every leaf, as the rest of the suite expects.
    executor = MigrationExecutor(connection)
    executor.migrate(executor.loader.graph.leaf_nodes())
    assert set(_TABLES) <= _tables()

    # The re-created tables work.
    MinerStoragePool.objects.create(miner_node_id=node_id(1), pool_id="default")
    assert MinerStoragePool.objects.get().tier == DiskTier.UNKNOWN
