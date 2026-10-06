"""Builders shared by the scheduler test modules.

Plain importable helpers (NOT a pytest `conftest`) — the row-creating
ones require an active DB (`@pytest.mark.django_db`); the snapshot
builders are pure.
"""

from __future__ import annotations

import uuid
from collections.abc import Iterable

from django.utils import timezone

from apps.identity.models import PrincipalScope, ServiceClient
from apps.lifecycle.models import Vm, VmState
from apps.miners.models import MinerIdentity, MinerStatus
from apps.orders.models import OrderTicketIntake
from apps.scheduler.chain import ChainSnapshot, MinerView
from apps.scheduler.models import (
    MinerCapacity,
    Placement,
    PlacementFailureSource,
    PlacementStatus,
)


def node_id(seed: int) -> str:
    """Deterministic 64-hex-char `node_id` from a small integer seed."""
    return format(seed, "064x")


def observe_chain_epoch(epoch: int, *, seed: int = 99) -> MinerCapacity:
    """Seed the DB-cached on-chain `CurrentEpoch` the scheduler refreshes
    on every chain read.

    `scoring.billing_epoch()` — the selector reward + billing key off —
    reads `max(MinerCapacity.observed_epoch)`, so a test that accrues
    usage without setting this has NO chain position and correctly earns
    nothing.
    """
    row, _ = MinerCapacity.objects.update_or_create(
        miner_node_id=node_id(seed),
        defaults={
            "status": "active",
            "capacity_slots": 1,
            "observed_epoch": epoch,
            "data_epoch": epoch,
            "refreshed_at": timezone.now(),
        },
    )
    return row


def make_dispatchable_identity(seed: int) -> MinerIdentity:
    """A `MinerIdentity` for `node_id(seed)` that passes
    `service.dispatchable_node_ids` — active, bridged (`chain_node_id`),
    reachable (`netbird_ip`), real CHIP_ID (hex, even, ≥16), fresh
    heartbeat. Without one, an on-chain-Active miner is excluded from
    placement (the §23 reachable+attestable+live gate), so the place
    tests need this to have an eligible candidate. Requires `@django_db`.
    """
    nid = node_id(seed)
    return MinerIdentity.objects.create(
        miner_id=f"miner-{seed:02d}",
        pubkey_hex=f"{seed:02x}" + "ab" * 15,
        platform_id=f"{seed:02x}" + "cd" * 15,
        chain_node_id=nid,
        netbird_ip=f"100.64.0.{seed % 256}",
        last_seen_at=timezone.now(),
        last_heartbeat_sequence=1,
        status=MinerStatus.ACTIVE,
    )


# ─── Chain snapshot builders (pure — no DB) ──────────────────────────


def make_miner(
    seed_or_id: int | str,
    *,
    status: str = "active",
    quality: int = 0,
    data_epoch: int = 10,
    last_transition_epoch: int = 10,
) -> MinerView:
    """Build a `MinerView`. `seed_or_id` is an int seed or a raw hex id."""
    nid = seed_or_id if isinstance(seed_or_id, str) else node_id(seed_or_id)
    return MinerView(
        node_id=nid,
        status=status,
        last_transition_epoch=last_transition_epoch,
        data_epoch=data_epoch,
        quality=quality,
    )


def make_snapshot(
    current_epoch: int = 10,
    miners: Iterable[MinerView] = (),
    *,
    pallet_live: bool = True,
) -> ChainSnapshot:
    """Build a `ChainSnapshot`.

    `pallet_live` defaults True (a healthy chain), matching
    `ChainSnapshot`'s own default — pass False to build a FOSSIL
    snapshot (the pallet is gone from the runtime, its orphaned storage
    still answering with the last epoch close's bytes).
    """
    return ChainSnapshot(
        current_epoch=current_epoch, miners=tuple(miners), pallet_live=pallet_live
    )


# ─── DB row builders (require @pytest.mark.django_db) ────────────────


def make_service_client(name: str | None = None) -> ServiceClient:
    return ServiceClient.objects.create(
        scope=PrincipalScope.OPERATOR.value,
        name=name or f"actor-{uuid.uuid4().hex[:12]}",
    )


def make_vm(vm_id: str = "vm-1", lease_id: str = "lease-1") -> Vm:
    return Vm.objects.create(
        vm_id=vm_id,
        lease_id=lease_id,
        state=VmState.ACTIVE,
        generation=1,
        host="host-a",
        lifecycle_vk=bytes(32),
    )


def make_order_ticket(
    vm_id: str, tenant_id: str, *, resource_class: str = "std"
) -> OrderTicketIntake:
    return OrderTicketIntake.objects.create(
        ticket_id=f"ticket-{uuid.uuid4().hex}",
        vm_id=vm_id,
        tenant_id=tenant_id,
        user_id="user-1",
        lease_id="lease-1",
        vm_generation=1,
        issue_time=1,
        expiry=2,
        node_id="chain-node",
        platform_id="chip-1",
        resource_class=resource_class,
        kid_hex="abcd",
        cose_blob=b"cose-bytes",
        received_from="orchestrator",
    )


def make_vm_with_ticket(
    vm_id: str = "vm-1", tenant_id: str = "tenant-1", *, resource_class: str = "std"
) -> Vm:
    """Create a `Vm` plus the `OrderTicketIntake` the scheduler reads
    the anti-affinity family (`tenant_id`) from.
    """
    vm = make_vm(vm_id=vm_id, lease_id=f"lease-{vm_id}")
    make_order_ticket(vm_id, tenant_id, resource_class=resource_class)
    return vm


def make_placement(
    vm: Vm,
    miner_node_id: str,
    *,
    status: str = PlacementStatus.PENDING.value,
    vm_family: str = "tenant-1",
    owner: str = "",
    resource_class: str = "std",
    chain_epoch: int = 10,
    version: int = 1,
    decided_by: ServiceClient | None = None,
    reason: str | None = None,
    failure_source: str | None = None,
) -> Placement:
    """Create a `Placement` directly, satisfying the status CHECKs and the
    model's provenance guard.

    `reason` defaults to the placeholder `"seed"` on a FAILED row (the
    CHECK requires a non-empty reason); pass one of the strings vali really
    writes (`drain:miner-stale`, `released:vm-destroyed`, ...) when the
    test is about how the reason is read back.

    `failure_source` defaults to `manual` on a FAILED row — the placeholder
    reason is exactly what a root `/fail` body looks like, and `manual` is
    never a refusal, so a test that does not care about provenance gets a
    row the operator readout ignores. A test about refusals passes the
    source of the path it is imitating (`scheduler_drain`, `launch`, ...).
    Pass `legacy` explicitly to imitate a pre-provenance row; the guard
    refuses that on `create()`, so the factory writes it with `.update()`.
    """
    actor = decided_by or make_service_client()
    now = timezone.now()
    if reason is None:
        reason = "seed" if status == PlacementStatus.FAILED.value else ""
    failed = status == PlacementStatus.FAILED.value
    if failure_source is None:
        failure_source = (
            PlacementFailureSource.MANUAL.value if failed else PlacementFailureSource.LEGACY.value
        )
    if failed and failure_source == PlacementFailureSource.LEGACY.value:
        # A legacy row is one that ended BEFORE the column existed. The
        # model guard forbids creating one, by design; imitate history the
        # way history happened — write the row, then blank its provenance.
        row = make_placement(
            vm,
            miner_node_id,
            status=status,
            vm_family=vm_family,
            owner=owner,
            resource_class=resource_class,
            chain_epoch=chain_epoch,
            version=version,
            decided_by=actor,
            reason=reason,
            failure_source=PlacementFailureSource.MANUAL.value,
        )
        Placement.objects.filter(id=row.id).update(
            failure_source=PlacementFailureSource.LEGACY.value
        )
        row.refresh_from_db()
        return row
    return Placement.objects.create(
        vm=vm,
        vm_family=vm_family,
        owner=owner,
        resource_class=resource_class,
        miner_node_id=miner_node_id,
        status=status,
        chain_epoch=chain_epoch,
        version=version,
        decided_by=actor,
        bound_at=now if status == PlacementStatus.BOUND.value else None,
        failed_at=now if failed else None,
        reason=reason,
        failure_source=failure_source,
    )
