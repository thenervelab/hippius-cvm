"""Light-tier acknowledgements (`apps.synthetic.ack`).

Every test below pins ONE claim from the module preamble. The claims that
matter are the ones about how the acknowledgement FAILS: a mute that cannot
lapse, cannot be blanket, cannot outlive the condition, and cannot apply
silently when it is malformed.
"""

from __future__ import annotations

import datetime as dt

import pytest

from apps.synthetic import ack
from apps.synthetic.checks import CheckResult

NOW = dt.datetime(2026, 8, 12, 12, 0, tzinfo=dt.UTC)
REASON = "testnet runtime dropped pallet-compute-scoring; upstream, no date"


def _in(days: int) -> str:
    return (NOW + dt.timedelta(days=days)).date().isoformat()


def _results(**ok_by_name: bool) -> list[CheckResult]:
    return [CheckResult(n, ok, "detail") for n, ok in ok_by_name.items()]


# ── the core claim: an ack keeps the TIER green, a bare failure does not ──


def test_acknowledged_failure_does_not_zero_the_tier() -> None:
    """CLAIM: a validly-acknowledged failing check keeps `light_success` 1.

    This is the whole point — the fossil `epoch_close` pinned the tier at 0
    for two days and made every other light check unreadable.
    """
    out = ack.resolve(
        f"epoch_close | {_in(10)} | {REASON}",
        _results(vali_api=True, epoch_close=False),
        now=NOW,
    )
    assert out.effective_success is True
    assert set(out.applied) == {"epoch_close"}


def test_a_NON_acknowledged_failure_still_zeroes_the_tier() -> None:
    """CLAIM: acknowledging one check does not cover any other.

    The regression that would make this feature worthless: a new,
    different light-tier failure hiding behind a standing ack.
    """
    out = ack.resolve(
        f"epoch_close | {_in(10)} | {REASON}",
        _results(epoch_close=False, stuck_jobs=False),
        now=NOW,
    )
    assert out.effective_success is False
    assert set(out.applied) == {"epoch_close"}
    assert "stuck_jobs" not in out.applied


def test_no_ack_at_all_behaves_exactly_as_before() -> None:
    """CLAIM: the empty default changes nothing."""
    assert ack.resolve("", _results(a=False), now=NOW).effective_success is False
    assert ack.resolve("", _results(a=True), now=NOW).effective_success is True


# ── expiry: the ack must be a deferral, never a decision ─────────────────


def test_an_expired_ack_stops_applying_and_reddens_the_tier() -> None:
    """CLAIM: the ack lapses on its own, forcing a re-decision.

    Forgetting an ack must be SELF-CORRECTING — this is what stops a mute
    from becoming the permanent blind spot this repo has shipped before.
    """
    spec = f"epoch_close | {_in(5)} | {REASON}"
    later = NOW + dt.timedelta(days=6)
    out = ack.resolve(spec, _results(epoch_close=False), now=later)
    assert out.effective_success is False, "an expired ack must not suppress anything"
    assert not out.applied
    assert "EXPIRED" in out.inert["epoch_close"][1]


def test_expiry_boundary_is_midnight_utc_of_the_named_date() -> None:
    """CLAIM: `until=D` means the ack is dead at 00:00 UTC on D."""
    spec = f"epoch_close | {_in(1)} | {REASON}"
    day = (NOW + dt.timedelta(days=1)).replace(hour=0, minute=0, second=0, microsecond=0)
    assert ack.resolve(
        spec, _results(epoch_close=False), now=day - dt.timedelta(seconds=1)
    ).effective_success is True
    assert ack.resolve(spec, _results(epoch_close=False), now=day).effective_success is False


def test_an_ack_without_an_expiry_is_REFUSED() -> None:
    """CLAIM: there is no forever-ack. A missing/garbage expiry is refused,
    and the check keeps failing the tier."""
    for spec in (
        f"epoch_close | | {REASON}",
        f"epoch_close | soon | {REASON}",
        f"epoch_close | 2026-13-45 | {REASON}",
        f"epoch_close | {REASON}",  # only two fields
    ):
        out = ack.resolve(spec, _results(epoch_close=False), now=NOW)
        assert out.effective_success is False, spec
        assert not out.applied, spec
        assert out.errors, spec


def test_an_expiry_beyond_the_horizon_is_REFUSED_not_clamped() -> None:
    """CLAIM: `until=2099-01-01` cannot buy a forever-mute, and the refusal
    is LOUD (an error) rather than a silent clamp to the horizon."""
    out = ack.resolve(
        f"epoch_close | 2099-01-01 | {REASON}", _results(epoch_close=False), now=NOW
    )
    assert out.effective_success is False
    assert not out.applied
    assert any("days out" in e for e in out.errors)


def test_the_horizon_is_exactly_MAX_ACK_DAYS() -> None:
    """CLAIM: the bound is the documented one, not a vague 'a while'."""
    ok = ack.resolve(
        f"c | {_in(ack.MAX_ACK_DAYS)} | {REASON}", _results(c=False), now=NOW
    )
    assert ok.applied, "an expiry exactly at the horizon is allowed"
    too_far = ack.resolve(
        f"c | {_in(ack.MAX_ACK_DAYS + 1)} | {REASON}", _results(c=False), now=NOW
    )
    assert not too_far.applied
    assert too_far.errors


# ── it cannot be a blanket mute ──────────────────────────────────────────


def test_wildcards_are_refused() -> None:
    """CLAIM: an ack names exactly one check. A glob would absorb the NEXT,
    different failure — the exact blind spot being designed against."""
    out = ack.resolve(f"* | {_in(5)} | {REASON}", _results(a=False, b=False), now=NOW)
    assert out.effective_success is False
    assert not out.applied
    assert any("wildcard" in e for e in out.errors)


def test_exceeding_the_hard_cap_VOIDS_THE_WHOLE_SPEC() -> None:
    """CLAIM: a growing ack list fails CLOSED — it does not apply a prefix.

    Voiding everything (rather than honouring the first N) is deliberate:
    a partially-applied cap silently picks winners and the operator never
    learns the list outgrew the design.
    """
    names = [f"c{i}" for i in range(ack.MAX_ACTIVE_ACKS + 1)]
    spec = "\n".join(f"{n} | {_in(5)} | {REASON}" for n in names)
    out = ack.resolve(spec, _results(**{n: False for n in names}), now=NOW)
    assert out.effective_success is False
    assert not out.applied, "the whole spec must be void, not truncated"
    assert all(out.inert[n][1].startswith("spec void") for n in names)
    assert any("hard cap" in e for e in out.errors)


def test_at_the_cap_the_spec_still_applies() -> None:
    """CLAIM: the cap is a cap, not an off-by-one that breaks normal use."""
    names = [f"c{i}" for i in range(ack.MAX_ACTIVE_ACKS)]
    spec = "\n".join(f"{n} | {_in(5)} | {REASON}" for n in names)
    out = ack.resolve(spec, _results(**{n: False for n in names}), now=NOW)
    assert out.effective_success is True
    assert set(out.applied) == set(names)


def test_the_bounds_are_module_constants_not_settings(settings) -> None:
    """CLAIM: the cap/horizon cannot be widened from config.

    A tunable cap IS the blanket mute. Adding `VALI_SYNTHETIC_ACK_MAX`
    would quietly undo every test above, so pin that no such knob is read.
    """
    # Deliberately absurd values: a horizon knob that a mutant might read
    # must be provably NOT read, so the override has to dwarf the expiry
    # under test (9999 days would still refuse a 2099 date by accident and
    # let such a mutant survive).
    settings.VALI_SYNTHETIC_ACK_MAX = 99
    settings.VALI_SYNTHETIC_ACK_MAX_DAYS = 100_000
    settings.VALI_SYNTHETIC_ACK_MAX_ACKS = 99
    settings.VALI_SYNTHETIC_ACK_MIN_REASON = 0
    names = [f"c{i}" for i in range(ack.MAX_ACTIVE_ACKS + 1)]
    spec = "\n".join(f"{n} | {_in(5)} | {REASON}" for n in names)
    assert not ack.resolve(spec, _results(**{n: False for n in names}), now=NOW).applied
    assert not ack.resolve(
        f"c | 2099-01-01 | {REASON}", _results(c=False), now=NOW
    ).applied
    assert not ack.resolve(f"c | {_in(5)} | short", _results(c=False), now=NOW).applied


def test_a_duplicate_entry_for_one_check_is_refused() -> None:
    """CLAIM: two entries for one check (e.g. an old one left above a new
    one) is ambiguous config — refuse rather than pick."""
    spec = f"c | {_in(2)} | {REASON}\nc | {_in(20)} | {REASON}"
    out = ack.resolve(spec, _results(c=False), now=NOW)
    assert any("duplicate" in e for e in out.errors)
    assert out.applied["c"].expires_at.date() == dt.date.fromisoformat(_in(2))


# ── a reason is mandatory ────────────────────────────────────────────────


def test_a_missing_or_thin_reason_is_refused() -> None:
    """CLAIM: an unjustified mute is refused. The reason is what the next
    operator reads before trusting it."""
    for spec in (f"epoch_close | {_in(5)} | ", f"epoch_close | {_in(5)} | wontfix"):
        out = ack.resolve(spec, _results(epoch_close=False), now=NOW)
        assert out.effective_success is False, spec
        assert any("reason" in e for e in out.errors), spec


def test_the_reason_may_contain_pipes() -> None:
    """CLAIM: the reason is free text to end-of-line, so a `|` in prose
    does not silently truncate or invalidate the entry."""
    out = ack.resolve(
        f"c | {_in(5)} | upstream chain work | tracked in the epoch memo",
        _results(c=False),
        now=NOW,
    )
    assert out.applied["c"].reason.endswith("tracked in the epoch memo")


# ── an ack must not outlive the condition ────────────────────────────────


def test_an_acknowledged_check_that_now_PASSES_is_reported_STALE() -> None:
    """CLAIM: a resolved condition does not stay silently acknowledged.

    Otherwise the ack sits pre-armed and swallows the check's NEXT failure
    for the rest of its window.
    """
    out = ack.resolve(f"epoch_close | {_in(10)} | {REASON}", _results(epoch_close=True), now=NOW)
    assert set(out.stale) == {"epoch_close"}
    assert not out.applied
    assert out.effective_success is True


def test_an_ack_for_an_unknown_check_is_an_ERROR_not_a_no_op() -> None:
    """CLAIM: a typo'd / renamed / removed check name is surfaced.

    It also mutes nothing, so the failure direction is 'noticed'.
    """
    out = ack.resolve(
        f"epok_close | {_in(5)} | {REASON}", _results(epoch_close=False), now=NOW
    )
    assert out.effective_success is False
    assert not out.applied
    assert any("unknown check" in e for e in out.errors)
    assert out.inert["epok_close"][1] == "unknown check"


# ── parse hygiene ────────────────────────────────────────────────────────


def test_comments_and_blank_lines_are_ignored() -> None:
    spec = f"# the fossil, see the epoch memo\n\n  epoch_close | {_in(5)} | {REASON}  \n"
    out = ack.resolve(spec, _results(epoch_close=False), now=NOW)
    assert set(out.applied) == {"epoch_close"}
    assert not out.errors


def test_a_malformed_line_never_takes_a_neighbour_down_or_applies() -> None:
    """CLAIM: garbage is dropped with an error; a good sibling entry still
    applies, and the garbage acknowledges nothing."""
    spec = f"garbage-with-no-pipes\nepoch_close | {_in(5)} | {REASON}"
    out = ack.resolve(spec, _results(epoch_close=False), now=NOW)
    assert set(out.applied) == {"epoch_close"}
    assert len(out.errors) == 1


@pytest.mark.parametrize("raw", [None, "", "   \n\n#only a comment\n"])
def test_empty_specs_parse_to_nothing(raw) -> None:
    spec = ack.parse(raw, now=NOW)
    assert spec.entries == []
    assert spec.errors == []
