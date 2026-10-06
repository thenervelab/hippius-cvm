"""§23/§25 — the PLACEMENT follows the VM to its §25 destination.

The defect: `Placement` is written only by the launch path, so after a
completed migration `Vm.host` named the destination while the BOUND
placement still named the SOURCE. Four consumers read that row, and all
four were wrong for the rest of the VM's life:

  1. `scoring._snapshot_weights` — the OTHER `VALI_EPOCH_WEIGHT_SOURCE` —
     paid the SOURCE for a workload the destination was running.
  2. §13 admission counted the VM's slot against the source.
  3. the graceful-exit drain enrols by BOUND placement, so a miner asking
     to leave cleanly was never drained of its migrated-IN VMs (and a
     drain of the source chased a VM that had already left).
  4. the #668 fit gate sums committed RAM/CPU over ACTIVE placements, so
     the destination looked emptier than it was and could be
     oversubscribed by exactly the VM it had just received.

This module pins the ledger move itself + consumers 1, 2 and 4; the §25
choreography and consumer 3 are pinned in
`apps/orchestration/tests/test_migration_placement_custody.py`.
"""

from __future__ import annotations

import pytest
from django.test import override_settings

from apps.scheduler import scoring, service
from apps.scheduler.models import (
    ACTIVE_PLACEMENT_STATES,
    Placement,
    PlacementFailureSource,
    PlacementStatus,
)

from .factories import (
    make_placement,
    make_service_client,
    make_vm_with_ticket,
    node_id,
    observe_chain_epoch,
)

pytestmark = pytest.mark.django_db

SRC = node_id(1)
DST = node_id(2)


def _move(vm, *, to: str = DST, actor=None) -> Placement | None:
    return service.move_placement_to_node(
        vm,
        node_id=to,
        decided_by=actor or make_service_client(),
        reason="migrated:job-abc",
        release_ref="migration:job-abc",
    )


def _active(vm) -> list[Placement]:
    return list(
        Placement.objects.filter(vm=vm, status__in=ACTIVE_PLACEMENT_STATES)
    )


def _run_backfill() -> None:
    """Run migration 0010's data pass against the CURRENT models.

    Imported by path because the module name starts with a digit. The
    historical models 0010 sees are field-identical to these, so calling
    it with the live app registry exercises the same code the deploy
    runs.
    """
    import importlib

    from django.apps import apps as django_apps

    importlib.import_module(
        "apps.scheduler.migrations.0010_placement_migrated_custody"
    )._forward(django_apps, None)


# ─── the move ────────────────────────────────────────────────────────


def test_the_placement_follows_the_vm_to_the_destination() -> None:
    vm = make_vm_with_ticket()
    make_placement(vm, SRC, status=PlacementStatus.BOUND.value)

    moved = _move(vm)

    assert moved is not None
    active = _active(vm)
    assert [p.miner_node_id for p in active] == [DST]
    assert active[0].status == PlacementStatus.BOUND.value
    # Bound, not Pending: the KBS already released the KEK to the dest at
    # `new_gen` and the dest reported its boot done. A Pending row would
    # leave the two `Bound`-filtering consumers (the snapshot reward
    # source, the graceful-exit drain) still broken.
    assert active[0].bound_at is not None
    assert active[0].kbs_release_ref == "migration:job-abc"


def test_the_source_row_is_closed_not_re_pointed() -> None:
    """The launch row is an §23/§15 AUDIT record of a decision that was
    taken. `decided_by`, `decided_at`, `chain_epoch` and `kbs_release_ref`
    all describe the SOURCE decision; re-pointing `miner_node_id` in place
    would leave them describing a destination decision that never
    happened, evidenced by another miner's KBS release."""
    vm = make_vm_with_ticket()
    launch_row = make_placement(vm, SRC, status=PlacementStatus.BOUND.value)
    launch_row.kbs_release_ref = "order-42"
    launch_row.save(update_fields=["kbs_release_ref"])

    _move(vm)

    launch_row.refresh_from_db()
    assert launch_row.miner_node_id == SRC
    assert launch_row.status == PlacementStatus.MIGRATED.value
    assert launch_row.reason == "migrated:job-abc"
    # provenance: a hand-over, never a refusal of the source node
    assert launch_row.failure_source == PlacementFailureSource.MIGRATION
    assert launch_row.kbs_release_ref == "order-42"


def test_the_new_row_carries_the_vms_family_owner_and_flavor() -> None:
    """Those describe the VM, not the decision, so they travel WITH it —
    the anti-affinity family and the per-owner sub-budget must keep
    working on the destination, and a blank `resource_class` would make
    the VM weigh ZERO in both the fit gate and the reward."""
    vm = make_vm_with_ticket()
    make_placement(
        vm,
        SRC,
        status=PlacementStatus.BOUND.value,
        vm_family="tenant-7",
        owner="user-7",
        resource_class="small",
    )

    moved = _move(vm)

    assert (moved.vm_family, moved.owner, moved.resource_class) == (
        "tenant-7",
        "user-7",
        "small",
    )


def test_the_hand_over_is_not_a_placement_FAILURE() -> None:
    """`Migrated`, not `Failed` — `Failed` feeds the scheduler's
    circuit-breaker, so closing the source as failed would penalise a
    miner that did nothing wrong. A graceful-exit drain would emit one
    "failure" per VM handed over and then route new work away from every
    healthy miner it ever handed one to."""
    vm = make_vm_with_ticket()
    make_placement(vm, SRC, status=PlacementStatus.BOUND.value)

    with override_settings(VALI_SCHEDULER_MAX_RECENT_FAILURES=2):
        _move(vm)
        assert service.recent_failures_by_node() == {}


# ─── consequence 1 — the `snapshot` reward source ────────────────────


def test_the_snapshot_reward_source_pays_the_destination() -> None:
    vm = make_vm_with_ticket()
    make_placement(
        vm, SRC, status=PlacementStatus.BOUND.value, resource_class="small"
    )
    before = scoring.compute_epoch_weights()
    assert set(before) == {SRC} and before[SRC] > 0

    _move(vm)

    after = scoring.compute_epoch_weights()
    assert set(after) == {DST}
    # The SAME weight — the VM did not change shape, only hosts.
    assert after[DST] == before[SRC]


# ─── consequences 2 + 4 — §13 admission and the #668 fit gate ────────


def test_the_fit_gate_counts_the_vm_against_the_destination() -> None:
    """`decision_inputs` sums the slot count AND the committed RAM/CPU per
    miner from the ACTIVE placements. Left on the source, the destination
    looked emptier than it was by exactly this VM — and could be
    oversubscribed by it."""
    vm = make_vm_with_ticket()
    make_placement(
        vm, SRC, status=PlacementStatus.BOUND.value, resource_class="small"
    )
    _cap, load_before, _fam = service.decision_inputs("tenant-1")
    assert load_before == {SRC: 1}

    _move(vm)

    _cap, load_after, family = service.decision_inputs("tenant-1")
    assert load_after == {DST: 1}
    # Anti-affinity follows too: the family is now counted against the DEST,
    # so a sibling VM is ranked away from the destination and no longer away
    # from the source. A COUNT, not a set — the count is what lets placement
    # spread without capping a tenant at one VM per host.
    assert family == {DST: 1}


def test_the_committed_memory_moves_with_the_vm() -> None:
    """The RAM/CPU half of the same gate — the one that decides whether
    the destination has room for the NEXT VM."""
    vm = make_vm_with_ticket()
    make_placement(
        vm, SRC, status=PlacementStatus.BOUND.value, resource_class="small"
    )
    for nid in (SRC, DST):
        observe_chain_epoch(10, seed=int(nid, 16))

    _move(vm)

    committed: dict[str, int] = {}
    for row in Placement.objects.filter(status__in=ACTIVE_PLACEMENT_STATES).values(
        "miner_node_id", "resource_class"
    ):
        mem, _cpus = service._committed_resources(row["resource_class"])
        committed[row["miner_node_id"]] = mem
    assert list(committed) == [DST]
    assert committed[DST] > 0


# ─── fail-safe: never leave the VM with NO placement ─────────────────


def test_an_unnameable_destination_leaves_the_placement_alone() -> None:
    """A destination with no registered `chain_node_id` cannot be named in
    the chain-id space `Placement` speaks. Closing the source row anyway
    would leave the VM with NO active placement — invisible to the #668
    fit gate, so the destination could be oversubscribed by exactly this
    VM. Wrong-miner accounting is bounded; missing accounting is not."""
    vm = make_vm_with_ticket()
    make_placement(vm, SRC, status=PlacementStatus.BOUND.value)

    assert _move(vm, to="") is None

    active = _active(vm)
    assert [p.miner_node_id for p in active] == [SRC]
    assert active[0].status == PlacementStatus.BOUND.value


def test_a_vm_with_no_placement_ledger_at_all_is_left_alone() -> None:
    """Nothing to move, and nothing truthful to invent: the flavor,
    family and owner are unknown, and fabricating them would put made-up
    resource figures into the admission maths."""
    vm = make_vm_with_ticket()

    assert _move(vm) is None
    assert Placement.objects.filter(vm=vm).count() == 0


def test_a_drained_placement_still_hands_custody_over() -> None:
    """The graceful-exit reality: the source is quarantined, so the §13
    re-eval drains the VM's Bound placement to `Failed` while the
    migration is still in flight. The VM then has NO active row — and must
    come out of the migration WITH one on the destination, or it is
    invisible to the fit gate forever."""
    vm = make_vm_with_ticket()
    drained = make_placement(
        vm,
        SRC,
        status=PlacementStatus.FAILED.value,
        resource_class="small",
        owner="user-7",
    )

    moved = _move(vm)

    assert moved is not None
    assert [p.miner_node_id for p in _active(vm)] == [DST]
    # The drained row is history — a Failed placement is terminal and this
    # must not resurrect it.
    drained.refresh_from_db()
    assert drained.status == PlacementStatus.FAILED.value
    assert moved.owner == "user-7"
    assert moved.resource_class == "small"


# ─── idempotence + the one-active-placement invariant ────────────────


def test_moving_to_the_node_already_in_custody_records_nothing() -> None:
    """A re-driven activation (and a reboot-recovery relaunch on the SAME
    host) must not open a second placement — that would double-count the
    VM against its own miner in the fit gate."""
    vm = make_vm_with_ticket()
    make_placement(vm, DST, status=PlacementStatus.BOUND.value)

    assert _move(vm, to=DST) is None
    assert Placement.objects.filter(vm=vm).count() == 1


def test_a_second_move_after_a_second_migration_chains() -> None:
    vm = make_vm_with_ticket()
    make_placement(vm, SRC, status=PlacementStatus.BOUND.value)
    third = node_id(3)

    _move(vm, to=DST)
    _move(vm, to=third)

    assert [p.miner_node_id for p in _active(vm)] == [third]
    assert (
        Placement.objects.filter(
            vm=vm, status=PlacementStatus.MIGRATED.value
        ).count()
        == 2
    )


def test_it_refuses_to_open_a_second_active_placement(monkeypatch) -> None:
    """If the source row cannot be CLOSED, the new one must NOT be
    opened: two active placements would count the VM against two miners at
    once. Forced here by making the close write an ACTIVE status — the
    same end state a concurrent writer would leave behind."""

    class _NoOpClose:
        MIGRATED = PlacementStatus.BOUND.value
        BOUND = PlacementStatus.BOUND
        FAILED = PlacementStatus.FAILED
        PENDING = PlacementStatus.PENDING

    vm = make_vm_with_ticket()
    make_placement(vm, SRC, status=PlacementStatus.BOUND.value)
    monkeypatch.setattr(service, "PlacementStatus", _NoOpClose)

    with pytest.raises(service.PlacementMoveConflict):
        _move(vm)

    assert Placement.objects.filter(vm=vm).count() == 1


# ─── the backfill (migration 0010) ───────────────────────────────────


def test_the_backfill_repairs_a_vm_migrated_before_the_fix() -> None:
    """Without it the fix only reaches FUTURE migrations, and every VM
    moved before it keeps paying the wrong miner and stays invisible to a
    graceful-exit drain of the miner that actually holds it."""
    from apps.miners.models import MinerIdentity, MinerStatus

    vm = make_vm_with_ticket()
    launch_row = make_placement(vm, SRC, status=PlacementStatus.BOUND.value)
    # The state a completed pre-fix migration leaves behind.
    vm.host = "miner-dst"
    vm.save(update_fields=["host"])
    MinerIdentity.objects.create(
        miner_id="miner-dst",
        pubkey_hex="ab" * 32,
        platform_id="cd" * 16,
        chain_node_id=DST,
        status=MinerStatus.ACTIVE,
    )

    _run_backfill()

    launch_row.refresh_from_db()
    assert launch_row.status == PlacementStatus.MIGRATED.value
    assert [p.miner_node_id for p in _active(vm)] == [DST]


def test_the_backfill_leaves_an_unresolvable_host_alone() -> None:
    """Same fail-safe as the live path: no chain `node_id` for the host ⇒
    do not strip the VM out of the capacity accounting."""
    vm = make_vm_with_ticket()
    make_placement(vm, SRC, status=PlacementStatus.BOUND.value)
    vm.host = "miner-unregistered"
    vm.save(update_fields=["host"])

    _run_backfill()

    assert [p.miner_node_id for p in _active(vm)] == [SRC]


def test_the_backfill_leaves_a_correctly_placed_vm_alone() -> None:
    from apps.miners.models import MinerIdentity, MinerStatus

    vm = make_vm_with_ticket()
    make_placement(vm, SRC, status=PlacementStatus.BOUND.value)
    vm.host = "miner-src"
    vm.save(update_fields=["host"])
    MinerIdentity.objects.create(
        miner_id="miner-src",
        pubkey_hex="ef" * 32,
        platform_id="12" * 16,
        chain_node_id=SRC,
        status=MinerStatus.ACTIVE,
    )

    _run_backfill()

    assert Placement.objects.filter(vm=vm).count() == 1
    assert [p.miner_node_id for p in _active(vm)] == [SRC]
