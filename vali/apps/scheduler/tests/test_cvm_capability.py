"""§23 gate (e) — OBSERVED SEV-SNP start capability.

The defect these tests pin, in the shape it was found live: a §25
migration was admitted onto a destination that then could not start the
guest at all (`sev_common_kvm_init: failed ret=-16` / EBUSY). Nothing in
the control plane modelled "can this host start a confidential guest?",
so the #668 fit gate — which sums CPU and memory over active
`Placement`s — waved it through with FULL free capacity, which the host
genuinely had *because* it was booting nothing. The failure surfaced
only at `DestActivating`, after the source had been quiesced and fenced,
and the host stayed a first-class candidate for every subsequent
placement, with `MigrationJob.quarantine_node_id` naming nobody.

The measured base rate is what shapes the RESPONSE. That EBUSY is
intermittent and self-recovering (one host: 1 failure in 105 starts over
22 days; another: 3 in 5 days, each followed by a successful start), so
these tests pin BOTH directions:

- one failure must NOT exclude a host (it de-rates it softly);
- a STREAK of them, with no success in between, must.

Covered here: the pure four-valued classifier as a table; the hard
exclusion and the soft de-rate in `decide_placement`; the fail-safe
UNKNOWN default; the PROVEN bonus and that it is not a filter; and what
a miner's self-assertion can and cannot buy in either direction.

The §25 half (dest-activation retry, the observation, the intake gate)
lives in `apps/orchestration/tests/test_cvm_capability_feedback.py`.
"""

from __future__ import annotations

from datetime import timedelta

import pytest
from django.utils import timezone

from apps.scheduler import cvm_capability, service
from apps.scheduler import placement as placement_mod
from apps.scheduler.cvm_capability import (
    DEGRADED,
    INCAPABLE,
    PROVEN,
    UNKNOWN,
    classify,
)
from apps.scheduler.models import MinerCapacity
from apps.scheduler.placement import PlacementError, decide_placement

from .factories import make_miner, make_snapshot, node_id

NOW = timezone.now()
WINDOW = 3600
THRESHOLD = 3
TTL = 86400
PROBATION = 86400


def _seed_row(seed: int, **fields) -> MinerCapacity:
    return MinerCapacity.objects.create(
        miner_node_id=node_id(seed),
        status="active",
        capacity_slots=4,
        observed_epoch=10,
        data_epoch=10,
        refreshed_at=NOW,
        **fields,
    )


def _classify(
    *,
    ok=None,
    fail=None,
    streak=0,
    window=WINDOW,
    threshold=THRESHOLD,
    ttl=TTL,
    probation=PROBATION,
) -> str:
    return classify(
        last_ok_at=None if ok is None else NOW - ok,
        last_fail_at=None if fail is None else NOW - fail,
        fail_streak=streak,
        now=NOW,
        fail_window_s=window,
        fail_threshold=threshold,
        proof_ttl_s=ttl,
        probation_s=probation,
    )


# ─── the pure classifier ─────────────────────────────────────────────


@pytest.mark.parametrize(
    ("ok", "fail", "streak", "expected"),
    [
        # No evidence at all — the fresh-deploy / newly-registered case.
        (None, None, 0, UNKNOWN),
        # A recent success and nothing else: proven.
        (timedelta(minutes=5), None, 0, PROVEN),
        # A success older than the proof TTL DECAYS — "the last CVM that
        # booted here booted three weeks ago" is not a claim about today.
        (timedelta(days=2), None, 0, UNKNOWN),
        # ONE recent failure: DEGRADED, not excluded. This is the case
        # the live fleet actually produces, and latching on it would have
        # pulled a healthy miner offline three times in five days.
        (None, timedelta(minutes=5), 1, DEGRADED),
        # TWO in a row: still not enough to conclude anything.
        (None, timedelta(minutes=5), 2, DEGRADED),
        # THREE consecutive in-window failures: now it is a statement
        # about the host, not about one unlucky start.
        (None, timedelta(minutes=5), 3, INCAPABLE),
        # The most recent observation wins — a failure AFTER a success
        # means the host regressed, whatever it managed before.
        (timedelta(hours=2), timedelta(minutes=5), 3, INCAPABLE),
        # ...and symmetrically, a success AFTER a failure clears it
        # immediately, with no operator action. (`record_start_ok` also
        # zeroes the streak; the timestamps alone already suffice.)
        (timedelta(minutes=5), timedelta(hours=2), 3, PROVEN),
        # A STREAK whose last failure has aged out of the hard window
        # relaxes to the SOFT de-rate — it does NOT become a clean slate.
        # This is the 2026-08-13 defect: the host hard-excluded at 12:01
        # was fully re-admitted at 13:51 on the clock alone, ranked first
        # (an idle host has the freest capacity) and burned a second
        # tenant launch. Nothing had observed it recover.
        (None, timedelta(hours=5), 5, DEGRADED),
        # Past the probation window, with still no success: full
        # re-admission. Nothing latches — a host that has been left alone
        # for a day is worth one more attempt, and it is the only way a
        # host with no other traffic can ever prove itself again.
        (None, timedelta(hours=30), 5, UNKNOWN),
        # An ISOLATED failure (streak below the threshold) is untouched by
        # probation: it ages out of the window and carries no penalty at
        # all. This is the anti-flap direction, and it is the one that
        # governs the measured live base rate.
        (None, timedelta(hours=5), 1, UNKNOWN),
        (None, timedelta(hours=5), 2, UNKNOWN),
        # An aged-out failure with a still-fresh earlier success: the
        # success stands again once the penalty expires.
        (timedelta(hours=9), timedelta(hours=5), 1, PROVEN),
        # ...but a STALE success does not resurrect: both age out.
        (timedelta(days=2), timedelta(hours=5), 1, UNKNOWN),
        # A success AFTER the streak ends probation on the spot — the
        # penalty is the absence of evidence, not a sentence to serve.
        (timedelta(minutes=1), timedelta(hours=5), 5, PROVEN),
    ],
)
def test_classify_table(ok, fail, streak, expected) -> None:
    assert _classify(ok=ok, fail=fail, streak=streak) == expected


def test_zero_threshold_disarms_the_hard_exclusion() -> None:
    """The operator dial: `VALI_SCHEDULER_CVM_FAIL_THRESHOLD=0` collapses
    INCAPABLE to the soft DEGRADED fleet-wide, with no code change and no
    dev-only bypass path."""
    assert _classify(fail=timedelta(minutes=1), streak=99, threshold=0) == DEGRADED
    # ...and with it the probation, which is defined off the same
    # threshold: a disarmed gate must not leave a penalty behind.
    assert _classify(fail=timedelta(hours=5), streak=99, threshold=0) == UNKNOWN


def test_probation_shorter_than_the_window_is_a_no_op() -> None:
    """The other operator dial. Probation only ever covers the tail AFTER
    the hard window, so a value inside it changes nothing — the host is
    hard-excluded for the window, then fully re-admitted exactly as
    before this change."""
    assert _classify(fail=timedelta(minutes=1), streak=3, probation=60) == INCAPABLE
    assert _classify(fail=timedelta(hours=5), streak=3, probation=60) == UNKNOWN


def test_probation_never_upgrades_a_verdict() -> None:
    """The rule this whole gate lives under: it may only ever ADD a reason
    to refuse a host. Sweep the classifier over a grid of ages and streaks
    and assert probation never returns a verdict LESS restrictive than the
    same input without it."""
    order = {INCAPABLE: 3, DEGRADED: 2, UNKNOWN: 1, PROVEN: 0}
    for hours in (0, 0.5, 1, 2, 5, 23, 25, 48):
        for streak in (0, 1, 2, 3, 9):
            for ok in (None, timedelta(minutes=1), timedelta(days=3)):
                age = timedelta(hours=hours)
                with_probation = _classify(ok=ok, fail=age, streak=streak)
                without = _classify(ok=ok, fail=age, streak=streak, probation=0)
                assert order[with_probation] >= order[without], (
                    hours,
                    streak,
                    ok,
                    with_probation,
                    without,
                )


def test_placement_literals_track_the_capability_module() -> None:
    """`placement` re-declares the verdicts it acts on so it stays a
    pure, ORM-free module. Drift between the two definitions would
    silently disable gate (e) — pin them together."""
    assert placement_mod._CVM_PROVEN == PROVEN
    assert placement_mod._CVM_DEGRADED == DEGRADED
    assert placement_mod._CVM_INCAPABLE == INCAPABLE


# ─── the streak, at WRITE time ───────────────────────────────────────


@pytest.mark.django_db
def test_consecutive_failures_accumulate_into_an_exclusion() -> None:
    _seed_row(1)
    for expected in (DEGRADED, DEGRADED, INCAPABLE):
        cvm_capability.record_start_failure(
            node_id(1), reason=cvm_capability.REASON_LAUNCH_REJECTED
        )
        assert cvm_capability.capability_of(node_id(1)) == expected


@pytest.mark.django_db
def test_an_observed_success_zeroes_the_streak() -> None:
    """THE property that keeps a healthy-but-flaky host in the fleet. On
    the live fleet a host had three of these failures in five days and
    started a CVM successfully between each — its streak must never have
    exceeded one."""
    _seed_row(1)
    for _ in range(3):
        cvm_capability.record_start_failure(
            node_id(1), reason=cvm_capability.REASON_LAUNCH_REJECTED
        )
        assert cvm_capability.capability_of(node_id(1)) == DEGRADED
        cvm_capability.record_start_ok(node_id(1))
        assert cvm_capability.capability_of(node_id(1)) == PROVEN

    row = MinerCapacity.objects.get(miner_node_id=node_id(1))
    assert row.cvm_fail_streak == 0
    assert row.cvm_fail_streak_started_at is None


@pytest.mark.django_db
def test_failures_spread_beyond_the_window_never_sum_into_an_exclusion() -> None:
    """Even with NO success in between, isolated failures days apart are
    not a streak: each one restarts the count at 1. Without this, a host
    with a rare intermittent fault would eventually be excluded for
    something it never did in one sitting."""
    _seed_row(1)
    for _ in range(4):
        cvm_capability.record_start_failure(
            node_id(1), reason=cvm_capability.REASON_LAUNCH_REJECTED
        )
        # Age the failure out of the window before the next one lands.
        MinerCapacity.objects.filter(miner_node_id=node_id(1)).update(
            cvm_last_fail_at=timezone.now() - timedelta(hours=5)
        )
        assert (
            MinerCapacity.objects.get(miner_node_id=node_id(1)).cvm_fail_streak == 1
        )
    assert cvm_capability.capability_of(node_id(1)) == UNKNOWN


# ─── probation: how a hard-excluded host earns its way back ──────────


def _age_last_failure(seed: int, delta: timedelta) -> None:
    MinerCapacity.objects.filter(miner_node_id=node_id(seed)).update(
        cvm_last_fail_at=timezone.now() - delta
    )


@pytest.mark.django_db
def test_a_hard_exclusion_relaxes_to_soft_not_to_a_clean_slate() -> None:
    """2026-08-13, in one test. A host with a full streak was hard-excluded
    at 12:01; by 13:51 the failure had aged past the 1 h window and the
    verdict was UNKNOWN — indistinguishable from a host nobody had ever
    tried. It was picked again and burned a second tenant launch.

    The clock is not evidence of recovery: an aged-out STREAK relaxes to
    the soft last-resort de-rate, not to no penalty at all."""
    _seed_row(1)
    for _ in range(THRESHOLD):
        cvm_capability.record_start_failure(
            node_id(1), reason=cvm_capability.REASON_LAUNCH_REJECTED
        )
    assert cvm_capability.capability_of(node_id(1)) == INCAPABLE

    _age_last_failure(1, timedelta(hours=1, minutes=50))  # the real gap
    assert cvm_capability.capability_of(node_id(1)) == DEGRADED


@pytest.mark.django_db
def test_a_success_ends_probation_immediately() -> None:
    """The fast path back, and the reason probation is not a punishment:
    one OBSERVED start clears the streak and the host is PROVEN again with
    no operator action and no waiting."""
    _seed_row(1)
    for _ in range(THRESHOLD):
        cvm_capability.record_start_failure(
            node_id(1), reason=cvm_capability.REASON_LAUNCH_REJECTED
        )
    _age_last_failure(1, timedelta(hours=2))
    assert cvm_capability.capability_of(node_id(1)) == DEGRADED

    cvm_capability.record_start_ok(node_id(1))

    assert cvm_capability.capability_of(node_id(1)) == PROVEN
    assert MinerCapacity.objects.get(miner_node_id=node_id(1)).cvm_fail_streak == 0


@pytest.mark.django_db
def test_probation_itself_expires_so_nothing_latches() -> None:
    """A host left alone long enough is worth one more attempt — otherwise
    a miner with no other traffic could never prove itself again, since
    capability is only provable BY being placed."""
    _seed_row(1)
    for _ in range(THRESHOLD):
        cvm_capability.record_start_failure(
            node_id(1), reason=cvm_capability.REASON_LAUNCH_REJECTED
        )
    _age_last_failure(1, timedelta(hours=25))

    assert cvm_capability.capability_of(node_id(1)) == UNKNOWN


@pytest.mark.django_db
def test_a_failure_during_probation_re_arms_the_hard_exclusion() -> None:
    """The probation placement is a single-shot PROBE. A host that already
    showed a streak and has not succeeded since does not get to spend two
    more launches re-proving it: one failure inside the probation window
    EXTENDS the streak rather than restarting it at 1.

    This is the deliberate exception to the "isolated failures never sum"
    rule — and it is narrow: it needs a previous streak that reached the
    threshold with no observed success since."""
    _seed_row(1)
    for _ in range(THRESHOLD):
        cvm_capability.record_start_failure(
            node_id(1), reason=cvm_capability.REASON_LAUNCH_REJECTED
        )
    _age_last_failure(1, timedelta(hours=3))
    assert cvm_capability.capability_of(node_id(1)) == DEGRADED

    cvm_capability.record_start_failure(
        node_id(1), reason=cvm_capability.REASON_LAUNCH_REJECTED
    )

    assert cvm_capability.capability_of(node_id(1)) == INCAPABLE
    assert MinerCapacity.objects.get(miner_node_id=node_id(1)).cvm_fail_streak == (
        THRESHOLD + 1
    )


@pytest.mark.django_db
def test_the_re_arm_needs_a_PREVIOUS_streak_not_just_a_previous_failure() -> None:
    """The anti-flap boundary of the re-arm. A host with ONE stale failure
    (never a streak) that fails again days later must still start a fresh
    streak at 1 — otherwise a rare intermittent fault would compound into
    an exclusion, which is exactly what the measured base rate forbids."""
    _seed_row(1)
    cvm_capability.record_start_failure(
        node_id(1), reason=cvm_capability.REASON_LAUNCH_REJECTED
    )
    _age_last_failure(1, timedelta(hours=3))

    cvm_capability.record_start_failure(
        node_id(1), reason=cvm_capability.REASON_LAUNCH_REJECTED
    )

    assert MinerCapacity.objects.get(miner_node_id=node_id(1)).cvm_fail_streak == 1
    assert cvm_capability.capability_of(node_id(1)) == DEGRADED


# ─── the placement gate ──────────────────────────────────────────────


def _decide(capability: dict[str, str] | None, **over):
    kwargs = {
        "snapshot": make_snapshot(10, [make_miner(1), make_miner(2)]),
        "capacity_by_node": {node_id(1): 4, node_id(2): 4},
        "load_by_node": {},
        "family_load_by_node": {},
        "max_epoch_lag": 2,
        "cvm_capability_by_node": capability,
    }
    kwargs.update(over)
    return decide_placement(**kwargs)


def test_incapable_host_is_never_chosen() -> None:
    """TODAY'S BUG. Node 1 wins on every pre-existing signal (lower
    node_id breaks the tie, identical capacity, identical load) — but
    vali OBSERVED it fail to start a CVM three times running."""
    assert _decide({node_id(1): INCAPABLE, node_id(2): UNKNOWN}) == node_id(2)


def test_incapable_exclusion_is_hard_with_no_fallback() -> None:
    """No soft fallback for a STREAK. A shaky miner still beats no
    placement; a host that has failed every recent attempt does NOT — for
    a §25 move, picking it quiesces and fences the source for nothing,
    which is strictly worse than leaving the VM where it runs."""
    with pytest.raises(PlacementError) as exc:
        _decide({node_id(1): INCAPABLE, node_id(2): INCAPABLE})
    assert exc.value.category == "no-eligible-miner"


def test_the_refusal_says_this_gate_is_why() -> None:
    """A fleet that is placeable-empty BECAUSE every host has been watched
    failing to start a confidential guest reads identically, from the
    category alone, to one that is out of capacity or epoch-stale — and
    those call for opposite responses (reboot a host vs. add one). The
    count goes in the message so the launch job's `result_json` carries
    it, not just a log line nobody correlates."""
    with pytest.raises(PlacementError) as exc:
        _decide({node_id(1): INCAPABLE, node_id(2): INCAPABLE})
    assert "2 candidate(s) removed by the OBSERVED SNP-start-capability" in (
        exc.value.message
    )

    # ...and it says nothing when this gate removed nobody, so the message
    # cannot become noise that hides the real reason.
    with pytest.raises(PlacementError) as exc:
        _decide(None, capacity_by_node={})
    assert "SNP-start-capability gate" not in exc.value.message


def test_a_single_failure_de_rates_but_never_excludes() -> None:
    """THE CORRECTION. One observed failure is intermittent, so DEGRADED
    is a preference, not a veto: node 2 wins while it can, and node 1 is
    still chosen when it is the only host left."""
    assert _decide({node_id(1): DEGRADED, node_id(2): UNKNOWN}) == node_id(2)
    assert _decide({node_id(1): DEGRADED, node_id(2): DEGRADED}) == node_id(1)


def test_a_degraded_host_still_wins_when_it_is_the_only_capacity() -> None:
    """The fallback in the concrete case that matters: everyone else is
    full. A transient fault must not turn into an outage."""
    chosen = _decide(
        {node_id(1): DEGRADED, node_id(2): PROVEN},
        capacity_by_node={node_id(1): 4, node_id(2): 1},
        load_by_node={node_id(2): 1},
    )
    assert chosen == node_id(1)


def test_unknown_capability_does_not_empty_the_fleet() -> None:
    """The fail-safe default. A fresh deploy has no evidence about
    anyone; excluding on absence of evidence would place nothing at all,
    and would be self-sealing besides (capability is only provable BY
    being placed)."""
    assert _decide({node_id(1): UNKNOWN, node_id(2): UNKNOWN}) == node_id(1)


def test_no_capability_map_at_all_is_the_pre_change_behaviour() -> None:
    """`None` ⇒ gate inert. Guarantees the five call sites can be wired
    one at a time and that every legacy caller/test is unaffected."""
    assert _decide(None) == node_id(1)


def test_absent_node_is_treated_exactly_like_explicit_unknown() -> None:
    """"No mirror row" and "a row with no evidence" must never diverge —
    both mean the same thing and must be scored the same."""
    assert _decide({}) == _decide({node_id(1): UNKNOWN, node_id(2): UNKNOWN})


def test_proven_outranks_unknown_when_all_else_is_equal() -> None:
    """UNKNOWN is not "assumed capable": node 2 loses the node_id
    tie-break, yet wins because it is the only host vali has actually
    watched boot a confidential guest."""
    assert _decide({node_id(1): UNKNOWN, node_id(2): PROVEN}) == node_id(2)


def test_proven_bonus_never_starves_an_unproven_miner() -> None:
    """The bonus is a ranking term, not a filter. If it were a filter, an
    unproven miner could never be placed while a proven one had capacity,
    so it could never become proven — the cold-start trap. Here the
    proven host is FULL, and the unproven one still gets the work."""
    chosen = _decide(
        {node_id(1): UNKNOWN, node_id(2): PROVEN},
        capacity_by_node={node_id(1): 4, node_id(2): 1},
        load_by_node={node_id(2): 1},
    )
    assert chosen == node_id(1)


def test_proven_weight_equals_grace_so_a_newcomer_stays_viable() -> None:
    """Tuning invariant: a proven incumbent's bonus and a newcomer's
    bootstrap grace cancel exactly, so demonstrated capability does not
    re-create the rich-get-richer spiral the composite score exists to
    break."""
    from apps.scheduler.placement import SelectionWeights

    assert SelectionWeights().proven == SelectionWeights().grace


# ─── what a miner can and cannot assert ──────────────────────────────


@pytest.mark.django_db
def test_a_miner_cannot_self_assert_capability_it_lacks() -> None:
    """There is NO write path from a miner's own claim to PROVEN. The
    heartbeat is the miner's channel into the scheduler and it can move
    exactly one capacity field — `reported_memory_available_mib`, which
    is down-only. Asserting free RAM (however much) leaves the capability
    verdict UNKNOWN: only an outcome vali OBSERVED can set PROVEN."""
    _seed_row(1, reported_memory_available_mib=1_000_000, reported_at=timezone.now())

    assert cvm_capability.capability_by_node() == {node_id(1): UNKNOWN}

    # And the only thing that CAN set PROVEN is a vali-side observation.
    cvm_capability.record_start_ok(node_id(1))
    assert cvm_capability.capability_by_node() == {node_id(1): PROVEN}


@pytest.mark.django_db
def test_a_miner_cannot_mark_a_rival_incapable() -> None:
    """Both writers key the row on the node id from VALI's own decision.
    Recording against node 1 leaves node 2 untouched, and there is no
    argument through which a caller could pass a node the miner named —
    `record_start_failure` takes a single node id, the one vali
    dispatched to."""
    _seed_row(1)
    _seed_row(2)

    for _ in range(THRESHOLD):
        cvm_capability.record_start_failure(
            node_id(1), reason=cvm_capability.REASON_LAUNCH_REJECTED
        )

    verdicts = cvm_capability.capability_by_node()
    assert verdicts[node_id(1)] == INCAPABLE
    assert verdicts[node_id(2)] == UNKNOWN
    # The rival's row is byte-for-byte untouched.
    rival = MinerCapacity.objects.get(miner_node_id=node_id(2))
    assert rival.cvm_last_fail_at is None
    assert rival.cvm_last_ok_at is None
    assert rival.cvm_fail_streak == 0
    assert rival.cvm_last_fail_reason == ""


# ─── which rejections are evidence about the HOST ────────────────────


@pytest.mark.parametrize(
    "classifier",
    [
        # The class the live miner returned on 2026-08-13 — its detail log
        # carried `libvirt-driver/create`, i.e. `virsh start` refused the
        # domain, which is the shape a wedged SEV-SNP subsystem produces.
        "dispatch-failed",
        "DISPATCH-FAILED",
        # Unforeseen / renamed / empty classes count too. The deny-list
        # direction is deliberate: an allow-list would silently switch the
        # gate off the day a miner-side class is renamed.
        "some-class-nobody-has-written-yet",
        "",
    ],
)
def test_these_rejections_count_against_the_host(classifier) -> None:
    assert cvm_capability.is_start_capability_failure(classifier) is True


@pytest.mark.parametrize(
    "classifier",
    [
        # 422 — the ORDER was unprocessable (bad digest / launch inputs).
        # A statement about this VM, not about this host. Counting it
        # would let three bad launch specs in an hour hard-exclude a
        # perfectly healthy miner.
        "launch-input",
        # 503 — the host is FULL. That is capacity (#668's fit gate), and
        # a full host is not an incapable one.
        "insufficient-resources",
        # 503 — CID allocation. The same-miner dispatch retry exists for
        # exactly this, and it says nothing about SEV.
        "vsock-cid-exhausted",
        # 500 — fires only AFTER the domain reached Running: the host
        # demonstrably DID start a confidential guest.
        "ticket-delivery-failed",
        # 501 — miner-agent build skew.
        "not-yet-wired",
        # The order never reached the lifecycle at all. These are usually
        # a VALI-side minting/clock fault that every miner would reject
        # identically — counting them could empty the fleet through a gate
        # that has no fallback.
        "bad-signature",
        "order-stale",
        "order-wrong-miner",
    ],
)
def test_these_rejections_say_nothing_about_the_host(classifier) -> None:
    assert cvm_capability.is_start_capability_failure(classifier) is False


def test_an_excused_class_can_only_ever_remove_a_penalty() -> None:
    """The classifier is miner-controlled, so the direction matters. It is
    read for one membership test and nothing else: it cannot name a rival
    (the node id comes from vali's own decision), it cannot be persisted
    (`cvm_last_fail_reason` is this module's closed vocabulary), and it
    can never buy PROVEN — that is written from a 2xx, never a string.

    What a lying miner CAN do is excuse itself from this ledger forever.
    That is bounded on purpose: it still never earns the PROVEN bonus, and
    the class-INDEPENDENT circuit-breaker
    (`service.recent_failures_by_node`, which counts FAILED placements
    whatever the miner said) still routes around it."""
    assert cvm_capability.REASON_LAUNCH_REJECTED not in (
        cvm_capability.CLASSES_NOT_START_CAPABILITY
    )
    # A class long enough to be a payload is truncated before comparison
    # and still counts (deny-list direction).
    assert cvm_capability.is_start_capability_failure("launch-input" + "x" * 5000)


@pytest.mark.django_db
def test_recorded_failure_reason_is_a_closed_vali_vocabulary() -> None:
    """Persisting a miner-supplied string would hand an untrusted host a
    write primitive into vali's audit trail. The reason is one of this
    module's own constants, and is length-capped regardless."""
    _seed_row(1)
    cvm_capability.record_start_failure(node_id(1), reason="x" * 500)
    row = MinerCapacity.objects.get(miner_node_id=node_id(1))
    assert len(row.cvm_last_fail_reason) <= 64


# ─── the ledger ↔ mirror interaction ─────────────────────────────────


@pytest.mark.django_db
def test_evidence_survives_a_chain_mirror_refresh() -> None:
    """`refresh_miner_capacity` rewrites the chain-sourced fields on every
    `/place`, launch and reeval cycle. If it clobbered the ledger, an
    excluded host would be re-admitted within seconds and the gate would
    be decorative."""
    _seed_row(1)
    for _ in range(THRESHOLD):
        cvm_capability.record_start_failure(
            node_id(1), reason=cvm_capability.REASON_LAUNCH_REJECTED
        )

    service.refresh_miner_capacity(make_snapshot(11, [make_miner(1)]))

    row = MinerCapacity.objects.get(miner_node_id=node_id(1))
    assert row.observed_epoch == 11  # the refresh really ran
    assert row.cvm_fail_streak == THRESHOLD
    assert cvm_capability.capability_of(node_id(1)) == INCAPABLE


@pytest.mark.django_db
def test_recording_against_an_unmirrored_node_is_a_silent_no_op() -> None:
    """Bookkeeping must never raise into a launch or a migration. A node
    with no mirror row is already ineligible (`decide_placement` fails
    closed on `capacity is None`), so there is nothing to record."""
    cvm_capability.record_start_ok(node_id(7))
    cvm_capability.record_start_failure(node_id(7), reason="x")
    cvm_capability.record_start_ok("")
    assert MinerCapacity.objects.count() == 0


@pytest.mark.django_db
def test_capability_of_unknown_node_is_unknown_not_incapable() -> None:
    assert cvm_capability.capability_of(node_id(9)) == UNKNOWN
    assert cvm_capability.capability_of("") == UNKNOWN


@pytest.mark.django_db
def test_service_accessor_matches_the_module() -> None:
    _seed_row(1)
    cvm_capability.record_start_ok(node_id(1))
    assert service.cvm_capability_by_node() == {node_id(1): PROVEN}


@pytest.mark.django_db
def test_windows_and_threshold_are_settings_driven(settings) -> None:
    """The dials are read at call time — a live config change takes
    effect without a restart-time snapshot of the policy."""
    _seed_row(1)
    MinerCapacity.objects.filter(miner_node_id=node_id(1)).update(
        cvm_last_ok_at=timezone.now() - timedelta(seconds=30)
    )
    assert cvm_capability.capability_of(node_id(1)) == PROVEN
    settings.VALI_SCHEDULER_CVM_PROOF_TTL_S = 10
    assert cvm_capability.capability_of(node_id(1)) == UNKNOWN

    MinerCapacity.objects.filter(miner_node_id=node_id(1)).update(
        cvm_last_fail_at=timezone.now() - timedelta(seconds=30), cvm_fail_streak=3
    )
    assert cvm_capability.capability_of(node_id(1)) == INCAPABLE
    settings.VALI_SCHEDULER_CVM_FAIL_THRESHOLD = 4
    assert cvm_capability.capability_of(node_id(1)) == DEGRADED
    settings.VALI_SCHEDULER_CVM_FAIL_WINDOW_S = 10
    assert cvm_capability.capability_of(node_id(1)) == UNKNOWN

    # ...and probation, the same way: with the streak back at/over the
    # threshold and the failure outside the hard window, the host is
    # softly de-rated until the probation dial says otherwise.
    settings.VALI_SCHEDULER_CVM_FAIL_THRESHOLD = 3
    assert cvm_capability.capability_of(node_id(1)) == DEGRADED
    settings.VALI_SCHEDULER_CVM_PROBATION_S = 10
    assert cvm_capability.capability_of(node_id(1)) == UNKNOWN
