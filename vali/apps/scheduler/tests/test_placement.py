"""Unit tests for `placement.decide_placement` — the pure §23 decision.

No DB, no I/O: `decide_placement` is a pure function, so these tests
construct snapshots + dicts directly. They pin the three §23
constraints (admission / anti-affinity / stale-epoch) and the
deterministic ranking.
"""

from __future__ import annotations

import pytest

from apps.scheduler.placement import Candidate, PlacementError, decide_placement

from .factories import make_miner, make_snapshot, node_id


def _decide(snapshot, *, capacity, load=None, family=None, lag=2, excluded=frozenset()):
    return decide_placement(
        snapshot=snapshot,
        capacity_by_node=capacity,
        load_by_node=load or {},
        family_load_by_node=family or {},
        max_epoch_lag=lag,
        excluded=excluded,
    )


# ─── Happy path ──────────────────────────────────────────────────────


def test_happy_path_places_on_the_only_active_miner() -> None:
    snap = make_snapshot(10, [make_miner(1, status="active", data_epoch=10)])
    chosen = _decide(snap, capacity={node_id(1): 4})
    assert chosen == node_id(1)


# ─── Constraint: only on-chain Active miners ─────────────────────────


@pytest.mark.parametrize("bad_status", ["quarantined", "decommissioned"])
def test_non_active_miners_are_never_candidates(bad_status: str) -> None:
    snap = make_snapshot(
        10,
        [
            make_miner(1, status=bad_status, data_epoch=10),
            make_miner(2, status="active", data_epoch=10),
        ],
    )
    chosen = _decide(snap, capacity={node_id(1): 4, node_id(2): 4})
    assert chosen == node_id(2)


def test_all_non_active_raises_no_eligible_miner() -> None:
    snap = make_snapshot(10, [make_miner(1, status="quarantined", data_epoch=10)])
    with pytest.raises(PlacementError) as exc:
        _decide(snap, capacity={node_id(1): 4})
    assert exc.value.category == "no-eligible-miner"


# ─── Gate: dispatchability (reachable + attestable + live) ───────────


def test_dispatchable_gate_excludes_active_but_non_dispatchable() -> None:
    # Both Active on-chain, but only miner 2 is in the dispatchable set
    # (complete + live local identity). Miner 1 (e.g. a phantom on-chain
    # registration, or a dark/un-attestable real miner) must be skipped.
    snap = make_snapshot(
        10,
        [
            make_miner(1, status="active", data_epoch=10),
            make_miner(2, status="active", data_epoch=10),
        ],
    )
    chosen = decide_placement(
        snapshot=snap,
        capacity_by_node={node_id(1): 4, node_id(2): 4},
        load_by_node={},
        family_load_by_node={},
        max_epoch_lag=2,
        dispatchable=frozenset({node_id(2)}),
    )
    assert chosen == node_id(2)


def test_dispatchable_empty_raises_no_eligible() -> None:
    # Chain says Active, but vali can dispatch to none of them.
    snap = make_snapshot(10, [make_miner(1, status="active", data_epoch=10)])
    with pytest.raises(PlacementError) as exc:
        decide_placement(
            snapshot=snap,
            capacity_by_node={node_id(1): 4},
            load_by_node={},
            family_load_by_node={},
            max_epoch_lag=2,
            dispatchable=frozenset(),
        )
    assert exc.value.category == "no-eligible-miner"


def test_dispatchable_none_disables_the_gate() -> None:
    # Default (None) preserves legacy behaviour — no dispatchability gate.
    snap = make_snapshot(10, [make_miner(1, status="active", data_epoch=10)])
    chosen = _decide(snap, capacity={node_id(1): 4})  # _decide passes no dispatchable
    assert chosen == node_id(1)


# ─── Constraint (c): fail-closed on stale epoch ──────────────────────


def test_stale_epoch_miner_is_rejected() -> None:
    # current_epoch 10, miner data reflects epoch 5 ⇒ lag 5 > max 2.
    snap = make_snapshot(10, [make_miner(1, status="active", data_epoch=5)])
    with pytest.raises(PlacementError) as exc:
        _decide(snap, capacity={node_id(1): 4}, lag=2)
    assert exc.value.category == "no-eligible-miner"


def test_epoch_lag_exactly_at_threshold_is_still_eligible() -> None:
    # lag == max_epoch_lag is the boundary — still allowed (the gate
    # rejects only `> max`).
    snap = make_snapshot(10, [make_miner(1, status="active", data_epoch=8)])
    assert _decide(snap, capacity={node_id(1): 4}, lag=2) == node_id(1)


def test_stale_miner_skipped_in_favour_of_a_fresh_one() -> None:
    snap = make_snapshot(
        10,
        [
            make_miner(1, status="active", data_epoch=3, quality=1000),
            make_miner(2, status="active", data_epoch=10, quality=1),
        ],
    )
    # node_id(1) has far higher quality but is stale ⇒ node_id(2) wins.
    assert _decide(snap, capacity={node_id(1): 4, node_id(2): 4}, lag=2) == node_id(2)


# ─── Constraint (b): anti-affinity across families ───────────────────


def test_anti_affinity_excludes_a_miner_already_hosting_the_family() -> None:
    snap = make_snapshot(
        10,
        [
            make_miner(1, status="active", data_epoch=10, quality=1000),
            make_miner(2, status="active", data_epoch=10, quality=1),
        ],
    )
    # node_id(1) is best by quality but already hosts the family.
    chosen = _decide(
        snap,
        capacity={node_id(1): 4, node_id(2): 4},
        family={node_id(1): 1},
    )
    assert chosen == node_id(2)


def test_anti_affinity_stacks_when_there_is_no_alternative() -> None:
    """Anti-affinity ranks a host DOWN; it does not make it unusable.

    This test asserted the opposite until 2026-08-20, and that assertion
    was the bug: with the only host excluded, a tenant holding one VM per
    miner could place no more. Three miners meant three concurrent VMs, and
    500 VMs would have needed 500 miners.

    Spreading is still preferred — `test_anti_affinity_*` above proves an
    empty host beats a higher-merit loaded one. What must not happen is a
    refusal when stacking is the only option left.
    """
    snap = make_snapshot(10, [make_miner(1, status="active", data_epoch=10)])
    chosen = _decide(snap, capacity={node_id(1): 4}, family={node_id(1): 1})
    assert chosen == node_id(1)


def test_an_explicit_ceiling_still_refuses() -> None:
    """The hard bound did not disappear, it became opt-in: an operator who
    sets `max_family_per_node` gets a real cap back."""
    snap = make_snapshot(10, [make_miner(1, status="active", data_epoch=10)])
    with pytest.raises(PlacementError) as exc:
        decide_placement(
            snapshot=snap,
            capacity_by_node={node_id(1): 4},
            load_by_node={},
            family_load_by_node={node_id(1): 1},
            max_epoch_lag=2,
            max_family_per_node=1,
        )
    assert exc.value.category == "no-eligible-miner"


# ─── Constraint (a): admission bounded by proven capacity ────────────


def test_a_miner_at_full_capacity_is_excluded() -> None:
    snap = make_snapshot(
        10,
        [
            make_miner(1, status="active", data_epoch=10),
            make_miner(2, status="active", data_epoch=10),
        ],
    )
    chosen = _decide(
        snap,
        capacity={node_id(1): 2, node_id(2): 2},
        load={node_id(1): 2},  # node_id(1) full
    )
    assert chosen == node_id(2)


def test_capacity_is_never_overcommitted() -> None:
    snap = make_snapshot(10, [make_miner(1, status="active", data_epoch=10)])
    with pytest.raises(PlacementError) as exc:
        _decide(snap, capacity={node_id(1): 3}, load={node_id(1): 3})
    assert exc.value.category == "no-eligible-miner"


def test_a_miner_with_no_capacity_row_is_excluded() -> None:
    # No `MinerCapacity` mirror row ⇒ unknown capacity ⇒ fail closed.
    snap = make_snapshot(10, [make_miner(1, status="active", data_epoch=10)])
    with pytest.raises(PlacementError):
        _decide(snap, capacity={})


# ─── `excluded` (used by /fail re-placement) ─────────────────────────


def test_excluded_miner_is_skipped() -> None:
    snap = make_snapshot(
        10,
        [
            make_miner(1, status="active", data_epoch=10, quality=1000),
            make_miner(2, status="active", data_epoch=10, quality=1),
        ],
    )
    chosen = _decide(
        snap,
        capacity={node_id(1): 4, node_id(2): 4},
        excluded=frozenset({node_id(1)}),
    )
    assert chosen == node_id(2)


# ─── Deterministic ranking ───────────────────────────────────────────


def test_ranking_prefers_higher_quality() -> None:
    snap = make_snapshot(
        10,
        [
            make_miner(1, status="active", data_epoch=10, quality=5),
            make_miner(2, status="active", data_epoch=10, quality=99),
            make_miner(3, status="active", data_epoch=10, quality=50),
        ],
    )
    chosen = _decide(snap, capacity={node_id(1): 4, node_id(2): 4, node_id(3): 4})
    assert chosen == node_id(2)


def test_ranking_tiebreaks_equal_quality_by_free_slots() -> None:
    snap = make_snapshot(
        10,
        [
            make_miner(1, status="active", data_epoch=10, quality=7),
            make_miner(2, status="active", data_epoch=10, quality=7),
        ],
    )
    # Equal quality; node_id(2) has more free slots (4 vs 1).
    chosen = _decide(
        snap,
        capacity={node_id(1): 4, node_id(2): 4},
        load={node_id(1): 3},
    )
    assert chosen == node_id(2)


def test_ranking_final_tiebreak_is_lowest_node_id() -> None:
    snap = make_snapshot(
        10,
        [
            make_miner(2, status="active", data_epoch=10, quality=7),
            make_miner(1, status="active", data_epoch=10, quality=7),
        ],
    )
    # Equal quality + equal free slots ⇒ lowest node_id wins.
    chosen = _decide(snap, capacity={node_id(1): 4, node_id(2): 4})
    assert chosen == node_id(1)


def test_decision_is_deterministic_regardless_of_snapshot_order() -> None:
    miners = [
        make_miner(3, status="active", data_epoch=10, quality=10),
        make_miner(1, status="active", data_epoch=10, quality=10),
        make_miner(2, status="active", data_epoch=10, quality=10),
    ]
    capacity = {node_id(1): 4, node_id(2): 4, node_id(3): 4}
    # Same inputs in three different orders ⇒ identical decision.
    results = {
        _decide(make_snapshot(10, order), capacity=capacity)
        for order in (
            miners,
            list(reversed(miners)),
            [miners[1], miners[2], miners[0]],
        )
    }
    assert results == {node_id(1)}


def test_candidate_is_a_frozen_value() -> None:
    # The ranking sorts `Candidate`s — keep it a hashable value type.
    c = Candidate(node_id="aa", quality=1, free_slots=2)
    with pytest.raises(AttributeError):
        c.quality = 9  # type: ignore[misc]


# ─── Composite selection: cold-start + cap + stake + price ───────────
# (docs/design/marketplace-stake-slashing.md — selection ≠ reward)

from apps.scheduler.placement import SelectionWeights  # noqa: E402


def _decide2(snapshot, **kw):
    base = dict(
        capacity_by_node=kw.pop("capacity"),
        load_by_node=kw.pop("load", None) or {},
        family_load_by_node=kw.pop("family", None) or {},
        max_epoch_lag=kw.pop("lag", 2),
    )
    return decide_placement(snapshot=snapshot, **base, **kw)


def test_cold_start_newcomer_beats_a_loaded_proven_miner() -> None:
    # THE fix: node1 is high-merit (quality 1000) but nearly full (1 free);
    # node2 is a brand-new 0-weight miner with a full empty box. The
    # newcomer must win so it can host its first VM and start earning.
    snap = make_snapshot(
        10,
        [
            make_miner(1, status="active", data_epoch=10, quality=1000),
            make_miner(2, status="active", data_epoch=10, quality=0),
        ],
    )
    chosen = _decide2(
        snap,
        capacity={node_id(1): 4, node_id(2): 4},
        load={node_id(1): 3},
    )
    assert chosen == node_id(2)


def test_reputation_leads_proven_outranks_empty_newcomer() -> None:
    # Reputation-first policy: merit (0.30) dominates grace (0.25), so when
    # a proven miner and a newcomer are BOTH idle the PROVEN one wins —
    # reputation leads all else equal. (Onboarding is still preserved when
    # the proven miner is busy — see the loaded-proven test above — and the
    # Sybil price-undercut is gated by the skin-in-the-game price gate, not
    # by starving newcomers.)
    snap = make_snapshot(
        10,
        [
            make_miner(1, status="active", data_epoch=10, quality=1000),
            make_miner(2, status="active", data_epoch=10, quality=0),
        ],
    )
    chosen = _decide2(snap, capacity={node_id(1): 4, node_id(2): 4})
    assert chosen == node_id(1)


def test_among_newcomers_free_capacity_then_node_id_decide() -> None:
    snap = make_snapshot(
        10,
        [
            make_miner(1, status="active", data_epoch=10, quality=0),
            make_miner(2, status="active", data_epoch=10, quality=0),
        ],
    )
    # Both newcomers; node2 has more free capacity (4 vs 1) ⇒ node2.
    chosen = _decide2(
        snap,
        capacity={node_id(1): 4, node_id(2): 4},
        load={node_id(1): 3},
    )
    assert chosen == node_id(2)


def test_stake_deficient_miner_is_excluded() -> None:
    snap = make_snapshot(
        10,
        [
            make_miner(1, status="active", data_epoch=10, quality=1000),
            make_miner(2, status="active", data_epoch=10, quality=1),
        ],
    )
    # node1 would win, but it's stake-deficient (didn't top up after a
    # dump) ⇒ excluded from new placements.
    chosen = _decide2(
        snap,
        capacity={node_id(1): 4, node_id(2): 4},
        stake_sufficient_by_node={node_id(1): False, node_id(2): True},
    )
    assert chosen == node_id(2)


def test_concentration_cap_deprioritises_an_over_share_miner() -> None:
    # 10 active VMs total; node1 already hosts 8 (80% > 40% cap) ⇒ it's
    # deprioritised even though it has a free slot, so the load spreads.
    snap = make_snapshot(
        10,
        [
            make_miner(1, status="active", data_epoch=10, quality=1000),
            make_miner(2, status="active", data_epoch=10, quality=0),
        ],
    )
    chosen = _decide2(
        snap,
        capacity={node_id(1): 12, node_id(2): 4},
        load={node_id(1): 8, node_id(2): 2},
        max_host_share=0.4,
    )
    assert chosen == node_id(2)


def test_concentration_cap_is_soft_never_fails_a_placement() -> None:
    # Only one miner exists and it's over the cap — we still place on it
    # rather than failing (the cap is a preference, not a hard gate).
    snap = make_snapshot(10, [make_miner(1, status="active", data_epoch=10, quality=5)])
    chosen = _decide2(
        snap,
        capacity={node_id(1): 12},
        load={node_id(1): 8},
        max_host_share=0.4,
    )
    assert chosen == node_id(1)


def test_circuit_breaker_routes_around_a_recently_failing_miner() -> None:
    # node1 is the higher-merit / would-win miner, but it has 3 recent
    # launch failures (≥ the threshold), so the breaker routes to node2.
    snap = make_snapshot(
        10,
        [
            make_miner(1, status="active", data_epoch=10, quality=1000),
            make_miner(2, status="active", data_epoch=10, quality=0),
        ],
    )
    chosen = _decide2(
        snap,
        capacity={node_id(1): 4, node_id(2): 4},
        recent_failures_by_node={node_id(1): 3},
        max_recent_failures=3,
    )
    assert chosen == node_id(2)


def test_circuit_breaker_is_soft_never_fails_a_placement() -> None:
    # The only miner is failing — we still place on it (better a shaky
    # miner than no placement at all).
    snap = make_snapshot(10, [make_miner(1, status="active", data_epoch=10, quality=5)])
    chosen = _decide2(
        snap,
        capacity={node_id(1): 4},
        recent_failures_by_node={node_id(1): 9},
        max_recent_failures=3,
    )
    assert chosen == node_id(1)


def test_circuit_breaker_disabled_when_threshold_zero() -> None:
    # max_recent_failures=0 disables the breaker — node1 wins on merit
    # despite its failures.
    snap = make_snapshot(
        10,
        [
            make_miner(1, status="active", data_epoch=10, quality=1000),
            make_miner(2, status="active", data_epoch=10, quality=0),
        ],
    )
    chosen = _decide2(
        snap,
        capacity={node_id(1): 4, node_id(2): 4},
        recent_failures_by_node={node_id(1): 99},
        max_recent_failures=0,
    )
    assert chosen == node_id(1)


def test_price_breaks_ties_among_equal_proven_miners() -> None:
    snap = make_snapshot(
        10,
        [
            make_miner(1, status="active", data_epoch=10, quality=7),
            make_miner(2, status="active", data_epoch=10, quality=7),
        ],
    )
    # Equal merit + free; node2 is cheaper ⇒ node2 wins on the price term.
    chosen = _decide2(
        snap,
        capacity={node_id(1): 4, node_id(2): 4},
        price_by_node={node_id(1): 1000, node_id(2): 500},
    )
    assert chosen == node_id(2)


def test_weights_from_settings_override_defaults(settings) -> None:
    settings.VALI_SELECT_W_GRACE = 0.0  # disable cold-start grace
    settings.VALI_SELECT_W_MERIT = 1.0  # merit dominates
    w = SelectionWeights.from_settings()
    snap = make_snapshot(
        10,
        [
            make_miner(1, status="active", data_epoch=10, quality=1000),
            make_miner(2, status="active", data_epoch=10, quality=0),
        ],
    )
    # With grace off + merit dominant, the proven miner wins over the
    # newcomer even when emptier — proves the knobs are wired.
    chosen = _decide2(
        snap,
        capacity={node_id(1): 4, node_id(2): 4},
        load={node_id(1): 1},
        weights=w,
    )
    assert chosen == node_id(1)


def test_max_host_share_reads_the_scheduler_setting(settings) -> None:
    # §23 — the placement concentration cap is now configurable via
    # VALI_SCHEDULER_MAX_HOST_SHARE (was permanently 1.0 = off before it
    # was defined in settings). Prove `service.max_host_share()` honours it.
    from apps.scheduler import service

    assert service.max_host_share() == 1.0  # settings.py default
    settings.VALI_SCHEDULER_MAX_HOST_SHARE = 0.5
    assert service.max_host_share() == 0.5


# ─── Per-owner sub-budget (soft, audit M-per-tenant-cap) ─────────────


def test_owner_cap_prefers_a_miner_under_the_owner_budget() -> None:
    # Two active miners; the owner already holds 2 placements on miner-1
    # and the cap is 2 → miner-1 is over-budget for this owner, so the
    # placement prefers miner-2 even if miner-1 would otherwise rank.
    snap = make_snapshot(
        10,
        [
            make_miner(1, status="active", data_epoch=10, quality=100),
            make_miner(2, status="active", data_epoch=10, quality=0),
        ],
    )
    chosen = decide_placement(
        snapshot=snap,
        capacity_by_node={node_id(1): 8, node_id(2): 8},
        load_by_node={node_id(1): 2, node_id(2): 0},
        family_load_by_node={},
        max_epoch_lag=2,
        owner_load_by_node={node_id(1): 2},
        max_owner_placements_per_miner=2,
    )
    assert chosen == node_id(2)


def test_owner_cap_falls_back_when_it_would_leave_nobody() -> None:
    # The owner is at the cap on the ONLY eligible miner → soft cap falls
    # back rather than fail the placement (a full fleet beats no placement;
    # capacity_slots stays the hard bound).
    snap = make_snapshot(10, [make_miner(1, status="active", data_epoch=10)])
    chosen = decide_placement(
        snapshot=snap,
        capacity_by_node={node_id(1): 8},
        load_by_node={node_id(1): 2},
        family_load_by_node={},
        max_epoch_lag=2,
        owner_load_by_node={node_id(1): 5},
        max_owner_placements_per_miner=2,
    )
    assert chosen == node_id(1)


def test_owner_cap_disabled_by_zero() -> None:
    # `max_owner_placements_per_miner=0` ⇒ inert; the owner's heavy load on
    # the merit-winner miner-1 does NOT deprioritise it. Equal free
    # capacity + both proven (quality>0, no newcomer grace) so merit
    # decides — miner-1 wins.
    snap = make_snapshot(
        10,
        [
            make_miner(1, status="active", data_epoch=10, quality=100),
            make_miner(2, status="active", data_epoch=10, quality=10),
        ],
    )
    chosen = decide_placement(
        snapshot=snap,
        capacity_by_node={node_id(1): 8, node_id(2): 8},
        load_by_node={node_id(1): 0, node_id(2): 0},
        family_load_by_node={},
        max_epoch_lag=2,
        owner_load_by_node={node_id(1): 5},
        max_owner_placements_per_miner=0,
    )
    assert chosen == node_id(1)


def test_owner_cap_deprioritises_the_merit_winner_when_over_budget() -> None:
    # Same scenario but the cap ENABLED at 2: the owner is over budget on
    # miner-1 (5 ≥ 2), so despite winning on merit it is deprioritised and
    # miner-2 (under budget) is chosen — the cap changed the outcome.
    snap = make_snapshot(
        10,
        [
            make_miner(1, status="active", data_epoch=10, quality=100),
            make_miner(2, status="active", data_epoch=10, quality=10),
        ],
    )
    chosen = decide_placement(
        snapshot=snap,
        capacity_by_node={node_id(1): 8, node_id(2): 8},
        load_by_node={node_id(1): 0, node_id(2): 0},
        family_load_by_node={},
        max_epoch_lag=2,
        owner_load_by_node={node_id(1): 5},
        max_owner_placements_per_miner=2,
    )
    assert chosen == node_id(2)


def test_max_owner_placements_per_miner_default_and_override(settings) -> None:
    from apps.scheduler import service

    assert service.max_owner_placements_per_miner() == 4  # settings.py default
    settings.VALI_SCHEDULER_MAX_OWNER_PLACEMENTS_PER_MINER = 2
    assert service.max_owner_placements_per_miner() == 2
