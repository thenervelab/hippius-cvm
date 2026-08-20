"""Which tenant VMs must migrate ahead of a miner's price change.

Spec of record: docs/design/marketplace-stake-slashing.md §3.2.

When a miner announces a price change on-chain, it does NOT take effect
immediately — it is published `PriceChangeNoticeBlocks` ahead. vali uses
that window to move any VM whose tenant agreed to a price ceiling the new
price would exceed, BEFORE the new price bites. The tenant is never
silently charged above its budget, and the migration happens while the VM
is still healthy.

[`vms_to_migrate`] is a **pure function**: given the announced changes,
the bound placements, and each VM's price ceiling, it returns the migration
intents — no I/O, no clock, no chain access. The watcher does the I/O and
acts on the intents.

A VM is migrated iff ALL hold:
  - its miner has an announced change,
  - the VM has a configured ceiling (no ceiling ⇒ never price-migrated),
  - the new price strictly exceeds that ceiling,
  - the change is not yet effective (we still have a window), and
  - the change is within `lead_blocks` (don't churn far in advance).
"""

from __future__ import annotations

from dataclasses import dataclass

from .chain import PriceAnnouncement


@dataclass(frozen=True)
class BoundVm:
    """A bound placement the watcher considers for migration."""

    vm_id: str
    node_id: str


@dataclass(frozen=True)
class MigrationIntent:
    """A decision to migrate one VM off its (about-to-reprice) miner."""

    vm_id: str
    node_id: str
    new_price: int
    ceiling: int
    effective_block: int


def vms_to_migrate(
    *,
    announcements: tuple[PriceAnnouncement, ...] | list[PriceAnnouncement],
    bound: tuple[BoundVm, ...] | list[BoundVm],
    ceiling_by_vm: dict[str, int],
    current_block: int,
    lead_blocks: int,
) -> list[MigrationIntent]:
    """Return the migration intents (deterministic, sorted by vm_id).

    - `announcements`   the on-chain `PendingPriceChange` read.
    - `bound`           currently-bound VMs `(vm_id, node_id)`.
    - `ceiling_by_vm`   `{vm_id: max price per unit}`; absent ⇒ no
                        ceiling ⇒ the VM is never price-migrated.
    - `current_block`   the chain's current block.
    - `lead_blocks`     only act on changes effective within this many
                        blocks (avoid churning far ahead).
    """
    by_node: dict[str, PriceAnnouncement] = {a.node_id: a for a in announcements}

    intents: list[MigrationIntent] = []
    for vm in bound:
        ann = by_node.get(vm.node_id)
        if ann is None:
            continue
        ceiling = ceiling_by_vm.get(vm.vm_id)
        if ceiling is None:
            # No agreed ceiling ⇒ the tenant accepts the miner's price.
            continue
        if ann.new_price <= ceiling:
            # Still within budget ⇒ no need to move.
            continue
        blocks_ahead = ann.effective_block - current_block
        if blocks_ahead <= 0:
            # Already effective — the window is gone; the §13 re-eval /
            # cost reconciliation handles it, not this pre-emptive path.
            continue
        if blocks_ahead > lead_blocks:
            # Too far out — revisit on a later cycle.
            continue
        intents.append(
            MigrationIntent(
                vm_id=vm.vm_id,
                node_id=vm.node_id,
                new_price=ann.new_price,
                ceiling=ceiling,
                effective_block=ann.effective_block,
            )
        )

    intents.sort(key=lambda i: i.vm_id)
    return intents
