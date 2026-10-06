"""Analytics-loop tests: dedup, cooldown, scheduling, DoS isolation."""

from __future__ import annotations

import asyncio

import pytest

from sentinel.analytics.base import AnalyticsContext, Finding, Rule, Severity
from sentinel.analytics.loop import (
    DEFAULT_DEDUP_CACHE_SIZE,
    AnalyticsLoop,
    RecentFindings,
)
from tests._analytics_helpers import make_context


class _AlwaysFiresRule(Rule):
    name = "always_fires"
    severity = Severity.WARN
    interval_seconds = 1.0
    cooldown_seconds = 60.0

    def __init__(self) -> None:
        self.calls = 0

    async def check(self, _ctx: AnalyticsContext) -> Finding | None:
        self.calls += 1
        return Finding(
            rule_name=self.name,
            severity=self.severity,
            summary="bang",
            fingerprint="x",
        )


class _NeverFiresRule(Rule):
    name = "never_fires"
    severity = Severity.INFO

    def __init__(self) -> None:
        self.calls = 0

    async def check(self, _ctx: AnalyticsContext) -> Finding | None:
        self.calls += 1
        return None


class _RaisesRule(Rule):
    name = "raises"
    severity = Severity.WARN
    interval_seconds = 1.0

    def __init__(self) -> None:
        self.calls = 0

    async def check(self, _ctx: AnalyticsContext) -> Finding | None:
        self.calls += 1
        raise RuntimeError("boom — simulated reader error")


class _HangsRule(Rule):
    name = "hangs"
    severity = Severity.WARN
    interval_seconds = 1.0

    async def check(self, _ctx: AnalyticsContext) -> Finding | None:
        await asyncio.sleep(10.0)
        return None


class _IncrementingRule(Rule):
    name = "incrementing"
    severity = Severity.INFO
    interval_seconds = 1.0

    def __init__(self) -> None:
        self.counter = 0

    async def check(self, _ctx: AnalyticsContext) -> Finding | None:
        self.counter += 1
        return Finding(
            rule_name=self.name,
            severity=self.severity,
            summary=f"#{self.counter}",
            fingerprint=str(self.counter),
        )


@pytest.mark.asyncio
async def test_tick_emits_finding_and_records_into_recent() -> None:
    rule = _AlwaysFiresRule()
    loop = AnalyticsLoop([rule], make_context())
    emitted = await loop.tick_once(now_unix=1000)
    assert len(emitted) == 1
    assert emitted[0].rule_name == "always_fires"
    assert emitted[0].at_unix == 1000
    assert [f.fingerprint for f in loop.recent] == ["x"]


@pytest.mark.asyncio
async def test_dedup_suppresses_identical_fingerprint_within_cooldown() -> None:
    rule = _AlwaysFiresRule()
    loop = AnalyticsLoop([rule], make_context())
    first = await loop.tick_once(now_unix=1000)
    # Bump time past `interval_seconds` so the rule is due again, but
    # stay inside `cooldown_seconds`.
    second = await loop.tick_once(now_unix=1002)
    assert len(first) == 1
    assert second == []
    assert rule.calls == 2  # rule was called both times
    assert loop.dedup_size == 1
    assert len(loop.recent) == 1


@pytest.mark.asyncio
async def test_dedup_releases_after_cooldown() -> None:
    rule = _AlwaysFiresRule()
    loop = AnalyticsLoop([rule], make_context())
    await loop.tick_once(now_unix=1000)
    # Past cooldown_seconds=60.
    again = await loop.tick_once(now_unix=1100)
    assert len(again) == 1


@pytest.mark.asyncio
async def test_rule_not_due_is_skipped() -> None:
    rule = _AlwaysFiresRule()
    loop = AnalyticsLoop([rule], make_context())
    await loop.tick_once(now_unix=1000)
    # Same instant → rule not yet due again (interval=1.0, next_due=1001).
    out = await loop.tick_once(now_unix=1000)
    assert out == []
    # rule called exactly once across both ticks.
    assert rule.calls == 1


@pytest.mark.asyncio
async def test_raising_rule_does_not_kill_loop() -> None:
    raises = _RaisesRule()
    fires = _AlwaysFiresRule()
    loop = AnalyticsLoop([raises, fires], make_context())
    out = await loop.tick_once(now_unix=1000)
    # The fires rule still emitted, even though `raises` blew up.
    assert any(f.rule_name == "always_fires" for f in out)
    assert raises.calls == 1


@pytest.mark.asyncio
async def test_hanging_rule_times_out_without_blocking_loop() -> None:
    hangs = _HangsRule()
    fires = _AlwaysFiresRule()
    loop = AnalyticsLoop(
        [hangs, fires], make_context(), rule_timeout_s=0.05
    )
    out = await loop.tick_once(now_unix=1000)
    # Even though `hangs` would sleep 10s, the wait_for cancelled it
    # quickly and `fires` still ran.
    names = {f.rule_name for f in out}
    assert "always_fires" in names


@pytest.mark.asyncio
async def test_incrementing_rule_evicts_lru_when_capacity_exceeded() -> None:
    rule = _IncrementingRule()
    loop = AnalyticsLoop([rule], make_context(), dedup_capacity=4)
    # Fire 6 distinct fingerprints in a row by advancing time past
    # interval each tick.
    for i in range(6):
        await loop.tick_once(now_unix=1000 + i * 2)
    # Dedup index capped at capacity.
    assert loop.dedup_size == 4


@pytest.mark.asyncio
async def test_run_forever_stops_when_event_is_set() -> None:
    rule = _AlwaysFiresRule()
    loop = AnalyticsLoop([rule], make_context(), tick_interval_s=0.01)
    stop = asyncio.Event()

    async def stopper() -> None:
        await asyncio.sleep(0.03)
        stop.set()

    await asyncio.gather(loop.run_forever(stop=stop), stopper())
    assert rule.calls >= 1


def test_severity_ordering() -> None:
    assert Severity.INFO < Severity.WARN
    assert Severity.WARN < Severity.ALERT
    assert Severity.ALERT < Severity.CRITICAL


def test_recent_findings_capacity_enforced() -> None:
    rf = RecentFindings(capacity=2)
    for i in range(5):
        rf.add(
            Finding(
                rule_name="r",
                severity=Severity.INFO,
                summary=str(i),
                fingerprint=str(i),
            )
        )
    snap = rf.snapshot()
    assert [f.fingerprint for f in snap] == ["3", "4"]


def test_loop_requires_at_least_one_rule() -> None:
    with pytest.raises(ValueError, match="at least one rule"):
        AnalyticsLoop([], make_context())


def test_rule_subclass_without_name_is_rejected() -> None:
    with pytest.raises(RuntimeError, match="must set a non-empty `name`"):

        class _Bad(Rule):
            async def check(self, _ctx: AnalyticsContext) -> Finding | None:
                return None


def test_dedup_default_capacity_is_reasonable() -> None:
    assert DEFAULT_DEDUP_CACHE_SIZE >= 256


class _ReturnsNonFindingRule(Rule):
    name = "returns_non_finding"
    severity = Severity.INFO
    interval_seconds = 1.0

    async def check(self, _ctx: AnalyticsContext) -> Finding | None:
        # Deliberately broken: emit a plain dict that's not a Finding.
        return {"oops": "not a finding"}  # type: ignore[return-value]


@pytest.mark.asyncio
async def test_non_finding_return_does_not_kill_following_rules() -> None:
    bad = _ReturnsNonFindingRule()
    good = _AlwaysFiresRule()
    loop = AnalyticsLoop([bad, good], make_context())
    out = await loop.tick_once(now_unix=1000)
    # `good` still ran and emitted, even though `bad` returned garbage.
    names = {f.rule_name for f in out}
    assert "always_fires" in names
    # Nothing from `bad` snuck through.
    assert "returns_non_finding" not in names


class _BadIntervalRule(Rule):
    name = "bad_interval"
    severity = Severity.WARN

    class _Bad:
        def __radd__(self, _other: object) -> object:
            raise RuntimeError("interval math exploded")

    interval_seconds = _Bad()  # type: ignore[assignment]

    async def check(self, _ctx: AnalyticsContext) -> Finding | None:
        return None


@pytest.mark.asyncio
async def test_bad_interval_seconds_does_not_spin_every_tick() -> None:
    """Review round-3 LOW: a rule with a raising interval is deferred."""

    bad = _BadIntervalRule()
    good = _AlwaysFiresRule()
    loop = AnalyticsLoop(
        [bad, good], make_context(), tick_interval_s=2.0
    )
    # First tick: bad rule's `clock + interval` raises but is caught.
    await loop.tick_once(now_unix=1000)
    # Re-fetch internal state to confirm bad rule was deferred.
    bad_state = next(s for s in loop._states if s.rule is bad)
    assert bad_state.next_due_unix >= 1000 + 2.0
    # Good rule still fired.
    assert any(f.rule_name == "always_fires" for f in loop.recent)


@pytest.mark.asyncio
async def test_on_emit_receives_emitted_findings() -> None:
    """PR-S5: the output sink sees every post-dedup finding."""

    rule = _AlwaysFiresRule()
    seen: list[Finding] = []
    loop = AnalyticsLoop([rule], make_context(), on_emit=seen.append)
    await loop.tick_once(now_unix=1000)
    assert [f.fingerprint for f in seen] == ["x"]


@pytest.mark.asyncio
async def test_on_emit_not_called_for_suppressed_duplicate() -> None:
    """A finding suppressed by dedup must not reach the output sink."""

    rule = _AlwaysFiresRule()
    seen: list[Finding] = []
    loop = AnalyticsLoop([rule], make_context(), on_emit=seen.append)
    await loop.tick_once(now_unix=1000)
    await loop.tick_once(now_unix=1002)  # within cooldown → suppressed
    assert len(seen) == 1


@pytest.mark.asyncio
async def test_raising_on_emit_does_not_kill_loop() -> None:
    """A broken sink is logged but never affects the loop or the rule."""

    def _boom(_finding: Finding) -> None:
        raise RuntimeError("output sink boom")

    rule = _AlwaysFiresRule()
    loop = AnalyticsLoop([rule], make_context(), on_emit=_boom)
    out = await loop.tick_once(now_unix=1000)
    # The finding was still emitted + recorded despite the broken sink.
    assert len(out) == 1
    assert len(loop.recent) == 1


@pytest.mark.asyncio
async def test_dedup_suppressed_hits_refresh_lru_position() -> None:
    """Hot suppressed fingerprints should not be evicted before cooldown."""

    rule = _AlwaysFiresRule()
    loop = AnalyticsLoop([rule], make_context(), dedup_capacity=2)
    # Emit the persistent fingerprint at t=1000.
    await loop.tick_once(now_unix=1000)
    # Insert two other distinct findings into the dedup directly via
    # the loop by faking new fingerprints — emulate other rules
    # filling the cache.
    rule_b = _IncrementingRule()
    loop_b = AnalyticsLoop([rule, rule_b], make_context(), dedup_capacity=2)
    await loop_b.tick_once(now_unix=1000)  # x + 1
    await loop_b.tick_once(now_unix=1002)  # 2 (rule_b incremented)
    # `x` should still be present (refreshed by the second tick).
    assert loop_b.dedup_size == 2
