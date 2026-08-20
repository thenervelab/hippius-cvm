"""Unit tests for `migration_policy.vms_to_migrate` — the pure decision.

No DB, no I/O: every input is explicit (announcements, bound VMs,
ceilings, blocks). Pins the §3.2 rule — a VM migrates iff its miner's
announced price exceeds the VM's ceiling, and the change is upcoming
within the window.
"""

from __future__ import annotations

from apps.scheduler.chain import PriceAnnouncement
from apps.scheduler.migration_policy import BoundVm, vms_to_migrate


def _ann(node: str, price: int, eff: int) -> PriceAnnouncement:
    return PriceAnnouncement(node_id=node, new_price=price, effective_block=eff)


def test_breach_within_window_yields_intent() -> None:
    intents = vms_to_migrate(
        announcements=[_ann("n1", 200, 150)],
        bound=[BoundVm(vm_id="vm-a", node_id="n1")],
        ceiling_by_vm={"vm-a": 100},
        current_block=100,
        lead_blocks=1000,
    )
    assert len(intents) == 1
    i = intents[0]
    assert (i.vm_id, i.node_id, i.new_price, i.ceiling, i.effective_block) == (
        "vm-a",
        "n1",
        200,
        100,
        150,
    )


def test_no_ceiling_is_never_migrated() -> None:
    # The tenant accepted the miner's pricing ⇒ never moved on price.
    intents = vms_to_migrate(
        announcements=[_ann("n1", 999, 150)],
        bound=[BoundVm(vm_id="vm-a", node_id="n1")],
        ceiling_by_vm={},
        current_block=100,
        lead_blocks=1000,
    )
    assert intents == []


def test_price_at_or_below_ceiling_is_kept() -> None:
    for price in (100, 80):  # == and < ceiling
        intents = vms_to_migrate(
            announcements=[_ann("n1", price, 150)],
            bound=[BoundVm(vm_id="vm-a", node_id="n1")],
            ceiling_by_vm={"vm-a": 100},
            current_block=100,
            lead_blocks=1000,
        )
        assert intents == []


def test_vm_on_an_unannounced_node_is_ignored() -> None:
    intents = vms_to_migrate(
        announcements=[_ann("n1", 200, 150)],
        bound=[BoundVm(vm_id="vm-a", node_id="n2")],
        ceiling_by_vm={"vm-a": 100},
        current_block=100,
        lead_blocks=1000,
    )
    assert intents == []


def test_already_effective_change_is_not_preempted() -> None:
    # effective_block <= current ⇒ the window is gone; this pre-emptive
    # path stays out of it.
    for eff in (100, 90):
        intents = vms_to_migrate(
            announcements=[_ann("n1", 200, eff)],
            bound=[BoundVm(vm_id="vm-a", node_id="n1")],
            ceiling_by_vm={"vm-a": 100},
            current_block=100,
            lead_blocks=1000,
        )
        assert intents == []


def test_change_too_far_out_is_deferred() -> None:
    # 500 blocks ahead but lead is 100 ⇒ revisit later, don't churn now.
    intents = vms_to_migrate(
        announcements=[_ann("n1", 200, 600)],
        bound=[BoundVm(vm_id="vm-a", node_id="n1")],
        ceiling_by_vm={"vm-a": 100},
        current_block=100,
        lead_blocks=100,
    )
    assert intents == []


def test_multiple_intents_are_sorted_by_vm_id() -> None:
    intents = vms_to_migrate(
        announcements=[_ann("n1", 200, 150), _ann("n2", 300, 160)],
        bound=[
            BoundVm(vm_id="vm-c", node_id="n2"),
            BoundVm(vm_id="vm-a", node_id="n1"),
            BoundVm(vm_id="vm-b", node_id="n1"),  # under ceiling → dropped
        ],
        ceiling_by_vm={"vm-c": 100, "vm-a": 100, "vm-b": 1000},
        current_block=100,
        lead_blocks=1000,
    )
    assert [i.vm_id for i in intents] == ["vm-a", "vm-c"]
