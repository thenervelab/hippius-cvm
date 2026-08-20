"""Anti-affinity must SPREAD, not cap the fleet at one VM per host.

The rule used to be `if node in family_miners: continue` — a hard exclude.
It read like load-balancing and behaved like a quota: a tenant could hold
at most one VM per miner, so three miners meant three concurrent VMs and
500 VMs would have needed 500 miners. The failure surfaced as
`no-eligible-miner`, which names seven possible gates and points at none.

What is pinned here is both halves of the corrected behaviour, because
either alone is wrong:

- placement must still PREFER an empty host (the spreading was the point);
- placement must still SUCCEED when no empty host is left.
"""

from __future__ import annotations

from apps.scheduler.placement import (
    Candidate,
    SelectionWeights,
    _score,
)


def _c(node: str, *, family_load: int = 0, **kw) -> Candidate:
    base = dict(node_id=node, quality=0, free_slots=10, capacity=10)
    base.update(kw)
    return Candidate(family_load=family_load, **base)


W = SelectionWeights()


class TestSpreadIsPreferred:
    def test_an_empty_host_outranks_one_already_carrying_the_family(self) -> None:
        """The whole point of anti-affinity: one dead host must not be able
        to take every VM a tenant owns."""
        empty = _score(_c("a", family_load=0), max_quality=0, max_price=0, weights=W)
        loaded = _score(_c("b", family_load=1), max_quality=0, max_price=0, weights=W)
        assert empty > loaded

    def test_the_penalty_accumulates(self) -> None:
        """Two same-family VMs must rank a host below one that has one, or
        placement would clump after the first doubling-up."""
        one = _score(_c("a", family_load=1), max_quality=0, max_price=0, weights=W)
        two = _score(_c("b", family_load=2), max_quality=0, max_price=0, weights=W)
        assert one > two

    def test_spread_outweighs_merit(self) -> None:
        """A high-merit host that already holds this tenant's VM must lose
        to an unproven empty one. Spreading is a blast-radius property;
        merit is a preference, and the preference must not eat it."""
        proven_but_loaded = _score(
            _c("a", family_load=1, quality=100), max_quality=100, max_price=0, weights=W
        )
        unproven_empty = _score(
            _c("b", family_load=0, quality=0), max_quality=100, max_price=0, weights=W
        )
        assert unproven_empty > proven_but_loaded


class TestStackingIsAllowed:
    def test_a_loaded_host_still_scores_above_nothing(self) -> None:
        """THE regression. A host already carrying the family is ranked
        DOWN, never excluded — otherwise a tenant with more VMs than
        miners can never place at all."""
        assert _score(
            _c("a", family_load=50), max_quality=0, max_price=0, weights=W
        ) > float("-inf")

    def test_500_vms_fit_on_3_hosts(self) -> None:
        """The user's question, as a test: 500 VMs must not need 500 miners.

        Simulates the placement loop — pick the best-scoring host, put a VM
        on it, repeat — and asserts both that everything places AND that the
        result is balanced rather than piled onto one host.
        """
        load = {"m1": 0, "m2": 0, "m3": 0}
        for _ in range(500):
            best = max(
                load,
                key=lambda n: _score(
                    _c(n, family_load=load[n]), max_quality=0, max_price=0, weights=W
                ),
            )
            load[best] += 1

        assert sum(load.values()) == 500, "every VM must be placed"
        # Round-robin is the ideal; allow one VM of slack for tie-breaking.
        assert max(load.values()) - min(load.values()) <= 1, (
            f"placement clumped instead of spreading: {load}"
        )


class TestTheCapIsOptOut:
    def test_no_cap_by_default(self) -> None:
        """`None` means the ranking alone spreads. A numeric ceiling is a
        capacity policy an operator opts into, not a default that silently
        limits a tenant."""
        from apps.scheduler import service

        assert service.max_family_per_node() is None
