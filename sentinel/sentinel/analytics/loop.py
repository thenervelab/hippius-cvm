"""Analytics loop with per-rule isolation + LRU dedup.

Three invariants this module enforces (all reviewed):

  1. **A broken rule must not crash the loop.** Every `rule.check()` is
     awaited inside `try/except Exception` with a hard `asyncio.wait_for`
     timeout, and the exception is logged + counted but never raised
     out of the loop. PR-S4 explicitly calls this out as a review focus.

  2. **No plaintext secrets leak into findings.** The loop redacts
     anything it does not recognize: only the `Finding`'s `summary` and
     `details` fields produced by a rule are surfaced. Rules are the
     trusted boundary — they receive reader outputs (audit records, RPC
     storage values, file mtimes) and project a narrow LLM-safe shape.
     This module's contribution is to keep that shape and not invent
     extra fields from environment / process state.

  3. **Bounded memory.** `RecentFindings` is a fixed-size ring. The
     dedup index is an `OrderedDict` LRU with a fixed cap. Neither
     grows with traffic.
"""

from __future__ import annotations

import asyncio
import logging
import time
from collections import OrderedDict, deque
from collections.abc import Callable, Iterable, Iterator, Sequence
from dataclasses import dataclass
from typing import Any

from sentinel.analytics.base import AnalyticsContext, Finding, Rule

log = logging.getLogger("sentinel.analytics.loop")

# Hard timeout per rule.check() call so a runaway reader (hung
# Postgres replica, blocking RPC) can't stall the patrol cadence.
DEFAULT_RULE_TIMEOUT_S = 30.0

# Cap on the dedup index. ~1k unique fingerprints is generous for the
# v1 ruleset (6 rules, each emits at most a handful of distinct
# fingerprints per day).
DEFAULT_DEDUP_CACHE_SIZE = 1024

# Recent findings ring buffer — kept short because PR-S6 will surface
# this to the LLM and the prompt window matters.
DEFAULT_RECENT_FINDINGS = 64


@dataclass(frozen=True)
class _DedupEntry:
    last_at_unix: int
    cooldown_seconds: float


class RecentFindings:
    """Bounded ring of recent findings, safe to read concurrently.

    Mutation is single-writer (only the analytics loop appends). Reads
    iterate over a snapshot so callers don't observe partial state.
    PR-S6 will wire `snapshot()` into the agent prompt.
    """

    def __init__(self, capacity: int = DEFAULT_RECENT_FINDINGS) -> None:
        if capacity <= 0:
            raise ValueError("capacity must be positive")
        self._buf: deque[Finding] = deque(maxlen=capacity)

    def add(self, finding: Finding) -> None:
        self._buf.append(finding)

    def snapshot(self) -> list[Finding]:
        return list(self._buf)

    def __len__(self) -> int:
        return len(self._buf)

    def __iter__(self) -> Iterator[Finding]:
        return iter(self.snapshot())


class _Dedup:
    """LRU keyed on `(rule_name, fingerprint)` with per-entry cooldown."""

    def __init__(self, capacity: int = DEFAULT_DEDUP_CACHE_SIZE) -> None:
        if capacity <= 0:
            raise ValueError("capacity must be positive")
        self._capacity = capacity
        self._entries: OrderedDict[tuple[str, str], _DedupEntry] = OrderedDict()

    def should_suppress(self, finding: Finding, now_unix: int) -> bool:
        key = finding.dedup_key()
        entry = self._entries.get(key)
        if entry is None:
            return False
        # Refresh LRU position on every hit (suppressed or recorded)
        # so a frequently-suppressed hot fingerprint does not get
        # evicted before its cooldown elapses. `last_at_unix` stays
        # at the original record time — cooldown is measured against
        # when we *emitted*, not against the last suppression.
        self._entries.move_to_end(key, last=True)
        elapsed = now_unix - entry.last_at_unix
        return elapsed < entry.cooldown_seconds

    def record(self, finding: Finding, cooldown_seconds: float, now_unix: int) -> None:
        key = finding.dedup_key()
        # Move-to-end semantics so the LRU eviction prefers stale keys.
        self._entries[key] = _DedupEntry(
            last_at_unix=now_unix, cooldown_seconds=cooldown_seconds
        )
        self._entries.move_to_end(key, last=True)
        while len(self._entries) > self._capacity:
            self._entries.popitem(last=False)

    def __len__(self) -> int:
        return len(self._entries)


@dataclass
class _RuleState:
    """Per-rule scheduler state used by `tick_once` and `run_forever`."""

    rule: Rule
    next_due_unix: float = 0.0
    consecutive_failures: int = 0


class AnalyticsLoop:
    """Drive a set of rules at their configured intervals.

    The loop is built to be unit-testable: `tick_once(now)` runs one
    pass against an explicit clock and returns the list of findings
    emitted (post-dedup). `run_forever()` is the production driver and
    sleeps `tick_interval_s` between passes.
    """

    def __init__(
        self,
        rules: Iterable[Rule],
        ctx: AnalyticsContext,
        *,
        recent: RecentFindings | None = None,
        dedup_capacity: int = DEFAULT_DEDUP_CACHE_SIZE,
        rule_timeout_s: float = DEFAULT_RULE_TIMEOUT_S,
        tick_interval_s: float = 5.0,
        on_emit: Callable[[Finding], None] | None = None,
    ) -> None:
        states = [_RuleState(rule=r) for r in rules]
        if not states:
            raise ValueError("AnalyticsLoop requires at least one rule")
        self._states = states
        self._ctx = ctx
        self._dedup = _Dedup(capacity=dedup_capacity)
        self._recent = recent or RecentFindings()
        self._rule_timeout_s = rule_timeout_s
        self._tick_interval_s = tick_interval_s
        # Optional post-dedup sink. PR-S5 wires this to the output
        # router's queue so emitted findings reach GitHub / Slack / the
        # daily summary. It MUST be cheap and non-blocking (a queue
        # `put_nowait`) — it runs inside `tick_once`, so a slow sink
        # would stall the patrol cadence. A raising sink is caught and
        # logged; it never affects rule scheduling or the loop.
        self._on_emit = on_emit

    @property
    def recent(self) -> RecentFindings:
        return self._recent

    @property
    def dedup_size(self) -> int:
        return len(self._dedup)

    async def tick_once(self, now_unix: int | None = None) -> list[Finding]:
        """Run every rule whose interval has elapsed; return emitted findings.

        Every per-rule body — `check()` invocation **and** the dedup +
        logging post-processing — is wrapped in `try/except` so a
        malformed return value (non-`Finding`, malformed details) from
        one rule cannot abort the rest of the tick.

        Note: `asyncio.wait_for` is a cooperative cancellation boundary.
        Rules MUST yield via `await` regularly; a rule that runs a CPU
        loop without any `await` will block the event loop past the
        timeout. Rule bodies must therefore stay thin — readers run on
        threads via `asyncio.to_thread`, so the rule itself only does
        light work between awaits.
        """

        clock = now_unix if now_unix is not None else int(time.time())
        emitted: list[Finding] = []
        for st in self._states:
            try:
                if clock < st.next_due_unix:
                    continue
                # Schedule the next due time *inside* the try so a
                # malformed `interval_seconds` (raising on arithmetic)
                # can't abort the rest of the tick. Round-2 review.
                st.next_due_unix = clock + st.rule.interval_seconds
                finding = await self._run_rule_isolated(st, clock)
                if finding is None:
                    continue
                if not isinstance(finding, Finding):
                    st.consecutive_failures += 1
                    log.warning(
                        "analytics rule %s returned non-Finding (%r); skipping",
                        st.rule.name,
                        type(finding).__name__,
                    )
                    continue
                if self._dedup.should_suppress(finding, clock):
                    log.debug(
                        "analytics: suppressed duplicate finding rule=%s fp=%s",
                        finding.rule_name,
                        finding.fingerprint,
                    )
                    continue
                self._dedup.record(finding, st.rule.cooldown_seconds, clock)
                self._recent.add(finding)
                log.info(
                    "analytics finding: rule=%s severity=%s fp=%s — %s",
                    finding.rule_name,
                    finding.severity.value,
                    finding.fingerprint,
                    finding.summary,
                )
                emitted.append(finding)
                # Only now is the rule fully successful end-to-end.
                st.consecutive_failures = 0
                # Hand the finding to the optional output sink. Wrapped
                # in its own try/except so a broken sink is neither
                # blamed on the rule (no `consecutive_failures` bump)
                # nor allowed to abort the rest of the tick.
                if self._on_emit is not None:
                    try:
                        self._on_emit(finding)
                    except Exception:  # noqa: BLE001 — sink must not break loop
                        log.exception(
                            "analytics on_emit sink raised for finding rule=%s",
                            finding.rule_name,
                        )
            except Exception:  # noqa: BLE001 — keep loop alive
                st.consecutive_failures += 1
                # Defer the rule by at least one tick interval so a
                # broken rule that raises during scheduling doesn't
                # spin every tick (review round-3 LOW).
                st.next_due_unix = max(
                    st.next_due_unix, clock + max(self._tick_interval_s, 1.0)
                )
                log.exception(
                    "analytics post-check processing failed for rule %s "
                    "(consecutive_failures=%d)",
                    st.rule.name,
                    st.consecutive_failures,
                )
        return emitted

    async def run_forever(self, *, stop: asyncio.Event | None = None) -> None:
        """Production driver. Honours `stop` for graceful shutdown."""

        while True:
            if stop is not None and stop.is_set():
                return
            try:
                await self.tick_once()
            except Exception:  # noqa: BLE001 — guard the outer loop
                log.exception("analytics tick failed; loop will continue")
            await asyncio.sleep(self._tick_interval_s)

    async def _run_rule_isolated(
        self, st: _RuleState, now_unix: int
    ) -> Finding | None:
        rule = st.rule
        try:
            finding = await asyncio.wait_for(
                rule.check(self._ctx), timeout=self._rule_timeout_s
            )
        except TimeoutError:
            st.consecutive_failures += 1
            log.warning(
                "analytics rule %s timed out after %.1fs (consecutive_failures=%d)",
                rule.name,
                self._rule_timeout_s,
                st.consecutive_failures,
            )
            return None
        except Exception:  # noqa: BLE001 — DoS protection
            st.consecutive_failures += 1
            log.exception(
                "analytics rule %s raised (consecutive_failures=%d)",
                rule.name,
                st.consecutive_failures,
            )
            return None
        # The counter is reset by `tick_once` *after* the value is
        # validated as a real Finding (or as a deliberate None). A
        # rule that returns garbage every tick keeps incrementing,
        # which surfaces in the warning log (review round-2 LOW).
        if finding is None:
            st.consecutive_failures = 0
            return None
        # Stamp the finding with our clock if the rule didn't (most don't).
        if finding.at_unix == 0:
            finding = Finding(
                rule_name=finding.rule_name,
                severity=finding.severity,
                summary=finding.summary,
                fingerprint=finding.fingerprint,
                details=dict(finding.details),
                at_unix=now_unix,
            )
        return finding


def severity_max(findings: Sequence[Finding]) -> Any:
    """Convenience for PR-S6 prompt synthesis — pick the highest severity."""

    if not findings:
        return None
    return max((f.severity for f in findings), default=None)
