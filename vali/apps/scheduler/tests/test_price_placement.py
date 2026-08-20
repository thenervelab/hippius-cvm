"""§23 marketplace — the announced-price term in `decide_placement`."""

from __future__ import annotations

import pytest

from apps.scheduler import service
from apps.scheduler.chain import ChainSnapshot, MinerView
from apps.scheduler.placement import SelectionWeights, decide_placement

from .factories import make_miner, node_id

pytestmark = pytest.mark.django_db


def _disp(*seeds: int) -> frozenset[str]:
    return frozenset(node_id(s) for s in seeds)


def test_cheaper_miner_wins_among_proven_miners() -> None:
    # Two PROVEN miners (quality>0 ⇒ skin-in-the-game), otherwise equal,
    # differing only in announced price → the cheaper one ranks up via the
    # (gated) price tiebreak. Both have merit, so price is allowed to count.
    snap = ChainSnapshot(
        current_epoch=10,
        miners=(
            make_miner(1, status="active", data_epoch=10, quality=1000),
            make_miner(2, status="active", data_epoch=10, quality=1000),
        ),
    )
    cap = {node_id(1): 8, node_id(2): 8}
    pick = decide_placement(
        snapshot=snap,
        capacity_by_node=cap,
        load_by_node={},
        family_load_by_node={},
        max_epoch_lag=5,
        dispatchable=_disp(1, 2),
        weights=SelectionWeights.from_settings(),
        max_host_share=1.0,
        price_by_node={node_id(1): 1_000_000, node_id(2): 200_000},  # 2 is cheaper
    )
    assert pick == node_id(2)


def test_cheap_newcomer_cannot_beat_a_proven_miner_by_undercutting() -> None:
    # THE anti-hack: a zero-reputation newcomer (quality=0) dumps its price
    # to almost nothing; a proven miner (quality>0) sits at a high price.
    # The price term is GATED on skin-in-the-game, so the newcomer earns NO
    # price credit and cannot win by undercutting — reputation wins. (The
    # newcomer must first earn merit before price helps it.)
    snap = ChainSnapshot(
        current_epoch=10,
        miners=(
            make_miner(1, status="active", data_epoch=10, quality=1000),  # proven
            make_miner(2, status="active", data_epoch=10, quality=0),  # newcomer
        ),
    )
    pick = decide_placement(
        snapshot=snap,
        capacity_by_node={node_id(1): 8, node_id(2): 8},
        load_by_node={},
        family_load_by_node={},
        max_epoch_lag=5,
        dispatchable=_disp(1, 2),
        weights=SelectionWeights.from_settings(),
        max_host_share=1.0,
        # Newcomer dumps to 1; proven is 100x more expensive — must NOT win.
        price_by_node={node_id(1): 1_000_000, node_id(2): 1},
    )
    assert pick == node_id(1)


def test_no_price_is_neutral_not_excluded() -> None:
    # A miner with no announced price is still eligible (price term inert),
    # and with empty price_by_node the pick is the lowest node_id tie-break.
    snap = ChainSnapshot(
        current_epoch=10,
        miners=(
            make_miner(1, status="active", data_epoch=10, quality=0),
            make_miner(2, status="active", data_epoch=10, quality=0),
        ),
    )
    pick = decide_placement(
        snapshot=snap,
        capacity_by_node={node_id(1): 8, node_id(2): 8},
        load_by_node={},
        family_load_by_node={},
        max_epoch_lag=5,
        dispatchable=_disp(1, 2),
        weights=SelectionWeights.from_settings(),
        max_host_share=1.0,
        price_by_node={},  # nobody priced
    )
    assert pick == node_id(1)


def test_price_by_node_helper_only_priced_miners() -> None:
    snap = ChainSnapshot(
        current_epoch=10,
        miners=(
            MinerView(
                node_id=node_id(1),
                status="active",
                last_transition_epoch=10,
                data_epoch=10,
                quality=0,
                price=500_000,
            ),
            MinerView(
                node_id=node_id(2),
                status="active",
                last_transition_epoch=10,
                data_epoch=10,
                quality=0,
                price=None,
            ),
        ),
    )
    p = service.price_by_node(snap)
    assert p == {node_id(1): 500_000}  # the un-priced miner is omitted
