"""Tests for the continuous re-evaluation loop (`service.reeval_once`)
and the `vali_scheduler_reeval` management command.

The `read-miner-status` shell-out is mocked at
`apps.scheduler.chain.read_miner_status`.
"""

from __future__ import annotations

import pytest
from django.core.management import call_command

from apps.lifecycle.models import VmState
from apps.scheduler import chain, service
from apps.scheduler.models import MinerCapacity, Placement, PlacementStatus

from .factories import make_miner, make_placement, make_snapshot, make_vm, node_id

pytestmark = pytest.mark.django_db


def _mock_chain(monkeypatch: pytest.MonkeyPatch, snapshot) -> None:
    monkeypatch.setattr(chain, "read_miner_status", lambda: snapshot)


def _bound_placement(vm_id: str, miner_seed: int) -> Placement:
    vm = make_vm(vm_id)
    return make_placement(vm, node_id(miner_seed), status=PlacementStatus.BOUND.value)


# ─── drain triggers ──────────────────────────────────────────────────


def test_reeval_drains_a_bound_placement_when_miner_quarantined(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    placement = _bound_placement("vm-1", 1)
    _mock_chain(
        monkeypatch,
        make_snapshot(10, [make_miner(1, status="quarantined", data_epoch=10)]),
    )
    report = service.reeval_once()

    placement.refresh_from_db()
    assert placement.status == PlacementStatus.FAILED
    assert placement.reason == "drain:miner-quarantined"
    assert placement.failed_at is not None
    assert placement.version == 2
    assert report.drained == 1


def test_reeval_drains_when_miner_decommissioned(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    placement = _bound_placement("vm-1", 1)
    _mock_chain(
        monkeypatch,
        make_snapshot(10, [make_miner(1, status="decommissioned", data_epoch=10)]),
    )
    service.reeval_once()
    placement.refresh_from_db()
    assert placement.reason == "drain:miner-decommissioned"


def test_reeval_drains_when_miner_missing_from_snapshot(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    placement = _bound_placement("vm-1", 1)
    # The miner dropped off-chain entirely.
    _mock_chain(monkeypatch, make_snapshot(10, []))
    service.reeval_once()
    placement.refresh_from_db()
    assert placement.status == PlacementStatus.FAILED
    assert placement.reason == "drain:miner-missing"


def test_reeval_drains_when_miner_score_is_stale(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    placement = _bound_placement("vm-1", 1)
    # Active but its score reflects epoch 2 while the chain is at 10.
    _mock_chain(
        monkeypatch,
        make_snapshot(10, [make_miner(1, status="active", data_epoch=2)]),
    )
    service.reeval_once()
    placement.refresh_from_db()
    assert placement.reason == "drain:miner-stale"


# ─── VM-terminal net (§13 capacity leak) ─────────────────────────────


@pytest.mark.parametrize(
    "terminal_state",
    [VmState.DESTROYED, VmState.DECOMMISSIONING],
)
def test_reeval_drains_bound_placement_when_vm_terminal_even_if_miner_healthy(
    monkeypatch: pytest.MonkeyPatch, terminal_state: VmState
) -> None:
    # A destroyed / decommissioning VM's `Bound` placement must be drained
    # even though the miner is perfectly Active + fresh — otherwise its
    # capacity slot leaks forever (§13). This is the retroactive safety-net
    # that reclaims any already-leaked placement on the next cycle.
    vm = make_vm("vm-1")
    Vm = vm.__class__
    Vm.objects.filter(pk=vm.pk).update(state=terminal_state.value)
    placement = make_placement(vm, node_id(1), status=PlacementStatus.BOUND.value)
    _mock_chain(
        monkeypatch,
        make_snapshot(10, [make_miner(1, status="active", data_epoch=10)]),
    )
    report = service.reeval_once()

    placement.refresh_from_db()
    assert placement.status == PlacementStatus.FAILED
    assert placement.reason == "drain:vm-terminal"
    assert placement.failed_at is not None
    assert report.drained == 1


# ─── release_placements_for_vm helper ────────────────────────────────


def test_release_placements_for_vm_releases_active_placement() -> None:
    # At most one ACTIVE placement exists per VM (partial-unique index), so
    # the helper releases the single Bound one, leaving an already-FAILED
    # row for the same VM and a live placement for a DIFFERENT VM untouched.
    vm = make_vm("vm-1")
    bound = make_placement(vm, node_id(1), status=PlacementStatus.BOUND.value)
    # An earlier, already-terminal placement for the same VM.
    stale_failed = make_placement(vm, node_id(2), status=PlacementStatus.FAILED.value)
    # A live placement for a DIFFERENT VM — must not be touched.
    other = make_placement(make_vm("vm-2"), node_id(3), status=PlacementStatus.BOUND.value)

    released = service.release_placements_for_vm(vm, reason="released:vm-destroyed")

    assert released == 1
    bound.refresh_from_db()
    stale_failed.refresh_from_db()
    other.refresh_from_db()
    assert bound.status == PlacementStatus.FAILED
    assert bound.reason == "released:vm-destroyed"
    assert bound.version == 2
    # The already-FAILED row for the same VM is a no-op (its seed reason).
    assert stale_failed.reason == "seed"
    # The other VM's placement is left alone.
    assert other.status == PlacementStatus.BOUND


def test_release_placements_for_vm_is_idempotent() -> None:
    # Releasing a VM whose placement is already FAILED is a no-op (0 rows).
    vm = make_vm("vm-1")
    placement = make_placement(vm, node_id(1), status=PlacementStatus.BOUND.value)
    first = service.release_placements_for_vm(vm, reason="released:vm-destroyed")
    assert first == 1
    placement.refresh_from_db()
    version_after_release = placement.version

    second = service.release_placements_for_vm(vm, reason="released:vm-destroyed")
    assert second == 0
    placement.refresh_from_db()
    # Untouched by the second call — no spurious version bump.
    assert placement.version == version_after_release


# ─── no-op cases ─────────────────────────────────────────────────────


def test_reeval_keeps_a_healthy_bound_placement(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    placement = _bound_placement("vm-1", 1)
    _mock_chain(
        monkeypatch,
        make_snapshot(10, [make_miner(1, status="active", data_epoch=10)]),
    )
    report = service.reeval_once()
    placement.refresh_from_db()
    assert placement.status == PlacementStatus.BOUND
    assert report.drained == 0
    assert report.bound_checked == 1


def test_reeval_ignores_pending_placements(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # A Pending placement on a quarantined miner is NOT drained —
    # re-eval only acts on Bound placements (a Pending one is the
    # operator's /bind-or-/fail decision, not re-eval's).
    vm = make_vm("vm-1")
    pending = make_placement(vm, node_id(1), status=PlacementStatus.PENDING.value)
    _mock_chain(
        monkeypatch,
        make_snapshot(10, [make_miner(1, status="quarantined", data_epoch=10)]),
    )
    report = service.reeval_once()
    pending.refresh_from_db()
    assert pending.status == PlacementStatus.PENDING
    assert report.drained == 0


# ─── side effects ────────────────────────────────────────────────────


def test_reeval_refreshes_the_miner_capacity_mirror(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _mock_chain(
        monkeypatch,
        make_snapshot(
            5,
            [
                make_miner(1, status="active", data_epoch=5, quality=100),
                make_miner(2, status="quarantined", data_epoch=5),
            ],
        ),
    )
    report = service.reeval_once()
    assert report.current_epoch == 5
    assert report.miners_seen == 2
    assert MinerCapacity.objects.count() == 2
    assert MinerCapacity.objects.get(miner_node_id=node_id(1)).quality == 100


def test_reeval_preserves_operator_capacity_slots_across_refresh(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    snapshot = make_snapshot(5, [make_miner(1, status="active", data_epoch=5)])
    _mock_chain(monkeypatch, snapshot)
    service.reeval_once()
    # Operator tunes the cap …
    MinerCapacity.objects.filter(miner_node_id=node_id(1)).update(capacity_slots=64)
    # … a later refresh must not stomp it back to the default.
    service.reeval_once()
    assert MinerCapacity.objects.get(miner_node_id=node_id(1)).capacity_slots == 64


# ─── management command ──────────────────────────────────────────────


def test_command_once_runs_a_single_cycle(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    placement = _bound_placement("vm-1", 1)
    _mock_chain(
        monkeypatch,
        make_snapshot(10, [make_miner(1, status="quarantined", data_epoch=10)]),
    )
    call_command("vali_scheduler_reeval", once=True)
    placement.refresh_from_db()
    assert placement.status == PlacementStatus.FAILED
    assert placement.reason == "drain:miner-quarantined"


def test_command_skips_cycle_when_chain_unavailable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    placement = _bound_placement("vm-1", 1)

    def _raise():
        raise chain.ChainReadUnavailable("test: chain down")

    monkeypatch.setattr(chain, "read_miner_status", _raise)

    # A failed read must NOT crash the command and must NOT drain —
    # fail-closed: never self-quarantine on an RPC blip.
    call_command("vali_scheduler_reeval", once=True)

    placement.refresh_from_db()
    assert placement.status == PlacementStatus.BOUND
