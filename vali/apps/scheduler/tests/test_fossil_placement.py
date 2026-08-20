"""§23 placement vs a FOSSIL chain snapshot (`pallet_live=False`).

The testnet runtime dropped `pallet-compute-scoring`. A runtime upgrade
does not delete storage and the reader derives its keys from the pallet
NAME over raw storage, so the orphaned prefix still answers reads: every
`quality` is the `EpochWeights` value written by the LAST successful
epoch close (2026-08-03), frozen forever. `ChainSnapshot.pallet_live`
is the only field that can tell.

These tests pin what placement does with that. Every test states its
CLAIM; the live-measured three-miner case is reproduced verbatim as a
fixture. Nothing here touches the stale-epoch / dispatchability /
exclusion gates — two tests assert precisely that they are UNCHANGED
under a fossil.

The regression that matters most is the mirror image: with
`pallet_live=True` the ranking must behave EXACTLY as before, so each
fossil case is paired with its live-chain twin.
"""

from __future__ import annotations

import pytest

from apps.scheduler.placement import PlacementError, SelectionWeights, decide_placement

from .factories import make_miner, make_snapshot, node_id

# ─── The live-measured case (testnet, 2026-08-11) ────────────────────
# Synthetic node_ids in the real 64-hex width, standing in for the three
# the live read reported. TENANT hosts realtenant-ubuntu-1 and reads quality=0;
# PROBE's entire history is the validator's own synthetic monitor and it
# reads the 100170 frozen at the last close. The fossil ranks them
# backwards — that inversion is the whole defect.
TENANT = "0123456789ab".ljust(64, "0")
PROBE = "a0a0a0a0a0a0".ljust(64, "0")
THIRD = "b1b1b1b1b1b1".ljust(64, "0")
FOSSIL_LEAD = 100_170


def _decide(snapshot, **kw):
    """`decide_placement` with the boring arguments defaulted."""
    return decide_placement(
        snapshot=snapshot,
        capacity_by_node=kw.pop("capacity"),
        load_by_node=kw.pop("load", None) or {},
        family_load_by_node=kw.pop("family", {}),
        max_epoch_lag=kw.pop("lag", 2),
        **kw,
    )


def _two(*, q1: int, q2: int, pallet_live: bool):
    """Two Active, equally-sized, equally-empty miners differing ONLY in
    `quality` — so merit is the sole differentiator and the outcome is a
    direct read-out of whether merit was trusted."""
    return make_snapshot(
        10,
        [
            make_miner(1, status="active", data_epoch=10, quality=q1),
            make_miner(2, status="active", data_epoch=10, quality=q2),
        ],
        pallet_live=pallet_live,
    )


# ─── CLAIM 1: a fossil lead confers no advantage ─────────────────────


def test_fossil_leader_gets_no_advantage_over_a_zero_quality_miner() -> None:
    # node2 holds the fossil lead; node1 reads 0. Everything else is
    # identical, so under a LIVE chain node2 wins on merit (next test).
    # With the pallet dead the lead buys nothing and the final,
    # merit-free tie-break (lowest node_id) picks node1.
    snap = _two(q1=0, q2=FOSSIL_LEAD, pallet_live=False)
    assert _decide(snap, capacity={node_id(1): 4, node_id(2): 4}) == node_id(1)


def test_same_scenario_on_a_LIVE_chain_is_unchanged_merit_still_wins() -> None:
    # THE regression pin. Identical inputs, `pallet_live=True`: merit
    # (0.30) beats the newcomer grace (0.25) exactly as it always did.
    snap = _two(q1=0, q2=FOSSIL_LEAD, pallet_live=True)
    assert _decide(snap, capacity={node_id(1): 4, node_id(2): 4}) == node_id(2)


def test_the_default_snapshot_is_live_so_no_existing_caller_shifts() -> None:
    # `ChainSnapshot.pallet_live` defaults True; a snapshot built without
    # mentioning it must rank identically to an explicitly-live one.
    cap = {node_id(1): 4, node_id(2): 4}
    default = make_snapshot(
        10,
        [
            make_miner(1, status="active", data_epoch=10, quality=0),
            make_miner(2, status="active", data_epoch=10, quality=FOSSIL_LEAD),
        ],
    )
    assert _decide(default, capacity=cap) == _decide(
        _two(q1=0, q2=FOSSIL_LEAD, pallet_live=True), capacity=cap
    )


# ─── CLAIM 2: neutralisation is DIRECTION-FREE ───────────────────────


@pytest.mark.parametrize("leader", [1, 2, 3])
def test_under_a_fossil_the_decision_ignores_who_holds_the_lead(leader: int) -> None:
    # Whoever the frozen close happened to favour, the answer is the
    # same. This is the property that stops the fossil from silently
    # preferring "whoever was ahead when the chain froze" — it is not
    # enough that the CURRENT leader loses; the ranking must not move at
    # all as the lead is handed around.
    snap = make_snapshot(
        10,
        [
            make_miner(
                seed, status="active", data_epoch=10, quality=FOSSIL_LEAD if seed == leader else 0
            )
            for seed in (1, 2, 3)
        ],
        pallet_live=False,
    )
    cap = {node_id(1): 4, node_id(2): 4, node_id(3): 4}
    assert _decide(snap, capacity=cap) == node_id(1)


@pytest.mark.parametrize("leader", [1, 2, 3])
def test_on_a_live_chain_the_lead_still_decides(leader: int) -> None:
    # The mirror: with the pallet alive, moving the lead moves the
    # placement. Merit is a real signal and keeps working.
    snap = make_snapshot(
        10,
        [
            make_miner(
                seed, status="active", data_epoch=10, quality=FOSSIL_LEAD if seed == leader else 0
            )
            for seed in (1, 2, 3)
        ],
        pallet_live=True,
    )
    cap = {node_id(1): 4, node_id(2): 4, node_id(3): 4}
    assert _decide(snap, capacity=cap) == node_id(leader)


# ─── CLAIM 3: the live three-miner case, reproduced ──────────────────


def _live_case(pallet_live: bool):
    return make_snapshot(
        2702,
        [
            make_miner(TENANT, status="active", data_epoch=2702, quality=0),
            make_miner(PROBE, status="active", data_epoch=2702, quality=FOSSIL_LEAD),
            make_miner(THIRD, status="active", data_epoch=2702, quality=0),
        ],
        pallet_live=pallet_live,
    )


LIVE_CAP = {TENANT: 4, PROBE: 4, THIRD: 4}


def test_live_case_the_tenant_host_is_not_disadvantaged() -> None:
    # The measured fleet: the real tenant's host reads 0, the synthetic
    # monitor's host reads 100170. With the pallet dead, the tenant host
    # is not pushed behind by a number it could not have influenced.
    assert _decide(_live_case(pallet_live=False), capacity=LIVE_CAP) == TENANT


def test_live_case_under_a_LIVE_pallet_the_probe_host_would_win() -> None:
    # Documents the defect being fixed: exactly the same fleet, with the
    # snapshot claiming to be live, hands the placement to the miner
    # whose only history is our own monitoring. That behaviour is
    # CORRECT for a live chain (it is real merit) — it is wrong only
    # because the number is a fossil.
    assert _decide(_live_case(pallet_live=True), capacity=LIVE_CAP) == PROBE


def test_live_case_load_balances_across_all_three_under_a_fossil() -> None:
    # With merit neutralised, free capacity is what is left to rank on —
    # so the fleet spreads instead of concentrating on the frozen leader.
    # Fill the tenant host; the next VM goes to the emptiest miner, and
    # the probe host's fossil lead does not jump it ahead of THIRD.
    snap = _live_case(pallet_live=False)
    chosen = _decide(snap, capacity=LIVE_CAP, load={TENANT: 3, PROBE: 2, THIRD: 1})
    assert chosen == THIRD


# ─── CLAIM 4: anti-undercut survives the dead pallet ─────────────────


def test_a_cheap_unproven_miner_cannot_win_on_price_under_a_fossil() -> None:
    # node2 dumps its price to 1 against node1's 1_000_000. Neither can
    # prove merit (dead pallet), so NEITHER gets price credit and the
    # dump buys nothing — the undercut property that the skin-in-the-game
    # gate exists for holds fleet-wide, not just for newcomers.
    snap = _two(q1=0, q2=0, pallet_live=False)
    chosen = _decide(
        snap,
        capacity={node_id(1): 4, node_id(2): 4},
        price_by_node={node_id(1): 1_000_000, node_id(2): 1},
    )
    assert chosen == node_id(1)


def test_a_fossil_lead_does_not_unlock_the_price_term() -> None:
    # The nastier shape: node2 holds the fossil lead AND undercuts. If
    # `has_skin` were still read off the frozen quality, node2 would
    # collect the price bonus on top. It must not.
    snap = _two(q1=0, q2=FOSSIL_LEAD, pallet_live=False)
    chosen = _decide(
        snap,
        capacity={node_id(1): 4, node_id(2): 4},
        price_by_node={node_id(1): 1_000_000, node_id(2): 1},
    )
    assert chosen == node_id(1)


def test_an_assumed_stake_flag_does_not_unlock_the_price_term_either() -> None:
    # Stake lives on the same dead pallet, so a `stake_sufficient` True
    # is no more verifiable than the quality is. The existing rule — an
    # assumed signal never buys a price BONUS — applies with more force
    # to an unverifiable one, so node2 stays without price credit.
    snap = _two(q1=0, q2=0, pallet_live=False)
    chosen = _decide(
        snap,
        capacity={node_id(1): 4, node_id(2): 4},
        price_by_node={node_id(1): 1_000_000, node_id(2): 1},
        stake_sufficient_by_node={node_id(1): True, node_id(2): True},
    )
    assert chosen == node_id(1)


def test_price_still_ranks_among_proven_miners_on_a_LIVE_chain() -> None:
    # The paired live-chain twin: two proven miners, cheaper one wins.
    # The marketplace is untouched while the chain is alive.
    snap = _two(q1=1000, q2=1000, pallet_live=True)
    chosen = _decide(
        snap,
        capacity={node_id(1): 4, node_id(2): 4},
        price_by_node={node_id(1): 1_000_000, node_id(2): 200_000},
    )
    assert chosen == node_id(2)


@pytest.mark.parametrize("price_w", [0.05, 0.10])
def test_a_cheap_newcomer_still_cannot_undercut_a_proven_miner_when_live(
    price_w: float,
) -> None:
    # The original anti-Sybil case, unchanged by this work — but arranged
    # so the test actually defends the gate. The NEWCOMER holds the lower
    # node_id here, so the final tie-break can never hand this assertion
    # its answer for free. (Its pre-existing twin in `test_price_placement
    # .py` puts the newcomer SECOND: with the gate removed those two
    # miners tie at 0.50 and the proven miner still wins on node_id, so
    # that test passes whether or not the gate exists. Mutation-checked.)
    # `price_w=0.10` additionally gives the kill a margin rather than a
    # tie: ungated, the undercutter would score 0.55 against 0.50.
    snap = _two(q1=0, q2=1000, pallet_live=True)
    chosen = _decide(
        snap,
        capacity={node_id(1): 4, node_id(2): 4},
        price_by_node={node_id(1): 1, node_id(2): 1_000_000},
        weights=SelectionWeights(price=price_w),
    )
    assert chosen == node_id(2)


# ─── CLAIM 5: the merit + grace weights go inert, together ───────────


@pytest.mark.parametrize("merit_w", [0.0, 0.3, 1.0, 50.0])
def test_the_merit_weight_cannot_move_a_fossil_placement(merit_w: float) -> None:
    # Merit is zeroed at the source, so its weight — however large — has
    # nothing to multiply. An operator cranking VALI_SELECT_W_MERIT can
    # no longer re-inflate the fossil.
    snap = _two(q1=0, q2=FOSSIL_LEAD, pallet_live=False)
    chosen = _decide(
        snap,
        capacity={node_id(1): 4, node_id(2): 4},
        weights=SelectionWeights(merit=merit_w),
    )
    assert chosen == node_id(1)


@pytest.mark.parametrize("grace_w", [0.0, 0.25, 5.0])
def test_the_grace_weight_cannot_move_a_fossil_placement_either(grace_w: float) -> None:
    # Under a dead pallet EVERY miner is unproven, so grace is added to
    # every score identically and cancels out of the ordering. The
    # bootstrap boost has nothing to bootstrap against when nobody can
    # earn weight — kept because it is truthful, inert because it is
    # universal.
    snap = _two(q1=0, q2=FOSSIL_LEAD, pallet_live=False)
    chosen = _decide(
        snap,
        capacity={node_id(1): 4, node_id(2): 4},
        weights=SelectionWeights(grace=grace_w),
    )
    assert chosen == node_id(1)


def test_the_merit_weight_still_moves_a_LIVE_placement() -> None:
    # Mirror: with the pallet alive the knob is still wired (turning
    # merit off lets the emptier newcomer's grace decide).
    snap = _two(q1=FOSSIL_LEAD, q2=0, pallet_live=True)
    cap = {node_id(1): 4, node_id(2): 4}
    assert _decide(snap, capacity=cap, weights=SelectionWeights()) == node_id(1)
    assert _decide(snap, capacity=cap, weights=SelectionWeights(merit=0.0)) == node_id(2)


# ─── CLAIM 6: free capacity is what is left to rank on ───────────────


def test_under_a_fossil_the_emptier_miner_wins() -> None:
    # node1 holds the fossil lead AND the lower node_id, but is 1/4 full.
    # On a live chain merit + tie-break give it the VM (next test); with
    # the pallet dead, load-balance is the ranking and node2 wins.
    snap = _two(q1=FOSSIL_LEAD, q2=0, pallet_live=False)
    chosen = _decide(
        snap, capacity={node_id(1): 4, node_id(2): 4}, load={node_id(1): 1}
    )
    assert chosen == node_id(2)


def test_the_same_load_split_on_a_LIVE_chain_still_favours_merit() -> None:
    snap = _two(q1=FOSSIL_LEAD, q2=0, pallet_live=True)
    chosen = _decide(
        snap, capacity={node_id(1): 4, node_id(2): 4}, load={node_id(1): 1}
    )
    assert chosen == node_id(1)


# ─── CLAIM 7: eligibility is untouched (gates unchanged) ─────────────


def test_a_fossil_does_not_loosen_the_stale_epoch_gate() -> None:
    # Neutralising merit must not turn a hard gate into a soft one: the
    # stale-epoch rejection still fails closed under a dead pallet.
    snap = make_snapshot(
        10, [make_miner(1, status="active", data_epoch=5)], pallet_live=False
    )
    with pytest.raises(PlacementError) as exc:
        _decide(snap, capacity={node_id(1): 4}, lag=2)
    assert exc.value.category == "no-eligible-miner"


def test_a_fossil_does_not_loosen_the_stake_deficiency_exclusion() -> None:
    # `has_skin` now ignores `stake_sufficient_by_node`, but the
    # EXCLUSION gate must still honour it: a stake-deficient miner takes
    # no new placements, dead pallet or not.
    snap = _two(q1=0, q2=0, pallet_live=False)
    chosen = _decide(
        snap,
        capacity={node_id(1): 4, node_id(2): 4},
        stake_sufficient_by_node={node_id(1): False, node_id(2): True},
    )
    assert chosen == node_id(2)


def test_a_fossil_does_not_loosen_the_dispatchability_gate() -> None:
    snap = _two(q1=0, q2=0, pallet_live=False)
    with pytest.raises(PlacementError) as exc:
        _decide(
            snap,
            capacity={node_id(1): 4, node_id(2): 4},
            dispatchable=frozenset(),
        )
    assert exc.value.category == "no-eligible-miner"


def test_a_fossil_does_not_loosen_the_capacity_bound() -> None:
    snap = make_snapshot(
        10, [make_miner(1, status="active", data_epoch=10)], pallet_live=False
    )
    with pytest.raises(PlacementError):
        _decide(snap, capacity={node_id(1): 2}, load={node_id(1): 2})


# ─── CLAIM 8: version-skew safety ────────────────────────────────────


def test_a_snapshot_without_pallet_live_is_treated_as_live() -> None:
    # An OLDER `read-miner-status` emits no `pallet_live`, and
    # `chain._coerce_snapshot` defaults it True precisely so a skew never
    # fabricates an alarm. Placement reads it the same defensive way: a
    # duck-typed snapshot missing the attribute must rank as live, not
    # silently drop everyone's merit.
    class _LegacySnapshot:
        def __init__(self, current_epoch, miners):
            self.current_epoch = current_epoch
            self.miners = miners

    snap = _LegacySnapshot(
        10,
        (
            make_miner(1, status="active", data_epoch=10, quality=0),
            make_miner(2, status="active", data_epoch=10, quality=FOSSIL_LEAD),
        ),
    )
    assert not hasattr(snap, "pallet_live")
    assert _decide(snap, capacity={node_id(1): 4, node_id(2): 4}) == node_id(2)
