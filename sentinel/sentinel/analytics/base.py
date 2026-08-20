"""Analytics primitives: Severity, Finding, AnalyticsContext, Rule.

The framework keeps readers behind a small async-callable bundle
(`AnalyticsContext`) so production wires the real PR-S2 / PR-S3
readers while tests inject lightweight async mocks. Rules never reach
into env or globals — every input is funnelled through the context,
which makes the unit tests reproducible and the DoS-isolation story
in `AnalyticsLoop` tractable.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Awaitable, Callable, Mapping, Sequence
from dataclasses import dataclass, field
from enum import StrEnum
from types import MappingProxyType
from typing import Any

from sentinel.tools.kbs_audit import AuditRecord
from sentinel.tools.thebrain_rpc import MinerStatus


class Severity(StrEnum):
    """Finding severity ladder.

    Ordered (least → most) so callers can compare with `<` if they need
    to filter — and stringy so JSON serialization stays human-readable.
    """

    INFO = "INFO"
    WARN = "WARN"
    ALERT = "ALERT"
    CRITICAL = "CRITICAL"

    def __lt__(self, other: object) -> bool:
        if not isinstance(other, Severity):
            return NotImplemented
        order = (Severity.INFO, Severity.WARN, Severity.ALERT, Severity.CRITICAL)
        return order.index(self) < order.index(other)


@dataclass(frozen=True)
class Finding:
    """A single rule output.

    `fingerprint` is the dedup key inside the loop: two findings with
    the same `(rule_name, fingerprint)` collapse to one until the
    cooldown expires. Rules choose fingerprints carefully — bucketing
    by epoch hour for rate spikes, by error-message hash for chain
    breaks, by node-id for per-node anomalies.

    `details` is frozen via `MappingProxyType` so a rule that retains
    a reference cannot retroactively mutate what the LLM sees in
    `RecentFindings` (PR-S4 review round-2 MED).
    """

    rule_name: str
    severity: Severity
    summary: str
    fingerprint: str
    details: Mapping[str, Any] = field(default_factory=dict)
    at_unix: int = 0

    def __post_init__(self) -> None:
        # Always snapshot the incoming mapping (even if it's already a
        # MappingProxyType — that just hides the underlying mutable
        # dict the caller might still be writing to) and wrap the
        # snapshot in a read-only view. PR-S4 rules emit only scalar
        # details (int/str/float/bool), so a shallow copy is sufficient;
        # nested mutables remain mutable, which is documented behavior.
        # Use object.__setattr__ because the dataclass is frozen.
        snapshot = dict(self.details)
        object.__setattr__(self, "details", MappingProxyType(snapshot))

    def dedup_key(self) -> tuple[str, str]:
        return (self.rule_name, self.fingerprint)


# Reader signatures — each is async so the loop can `await` it under a
# per-rule timeout. Production wiring wraps the blocking PR-S2/PR-S3
# readers in `asyncio.to_thread`. Tests pass async mocks directly.
ReadAuditTailFn = Callable[[int], Awaitable[Sequence[AuditRecord]]]
VerifyAuditChainFn = Callable[[], Awaitable[None]]
ReadCurrentEpochFn = Callable[[], Awaitable[int]]
ReadMinerStatusFn = Callable[[bytes], Awaitable[MinerStatus | None]]
ReadKbsAllowlistEpochFn = Callable[[], Awaitable[int | None]]
StatFileFn = Callable[[str], Awaitable[float | None]]
NowUnixFn = Callable[[], int]


@dataclass(frozen=True)
class AnalyticsContext:
    """Bundle of reader callables handed to every rule.

    Constructed once by `wiring.build_production_context()` in
    production and once per test by the unit-test fixtures. The
    callables MUST be safe to invoke concurrently (the loop schedules
    multiple rules in parallel) and MUST NOT raise — failures surface
    as their natural return value (None for absence) or by raising a
    well-typed reader error which the loop's per-rule try/except
    catches and logs without killing the loop.
    """

    read_audit_tail: ReadAuditTailFn
    verify_audit_chain: VerifyAuditChainFn
    read_current_epoch: ReadCurrentEpochFn
    read_miner_status: ReadMinerStatusFn
    read_kbs_allowlist_epoch: ReadKbsAllowlistEpochFn
    stat_mtime: StatFileFn
    now_unix: NowUnixFn


class Rule(ABC):
    """Base class for a sentinel analytics rule.

    Each subclass overrides the four class-level attributes and the
    async `check` method. The class attributes are read once by the
    loop at registration time; `check` is awaited each interval and
    returns `None` (no finding) or a `Finding` (which is then routed
    through dedup + cooldown).
    """

    # Stable, kebab-cased identifier. Used as the dedup namespace and
    # as the `rule_name` on every Finding emitted by this rule.
    name: str = ""

    # Severity is fixed per rule. Mixed severities should be split
    # into separate rules so the dedup namespace stays clean.
    severity: Severity = Severity.WARN

    # How often the loop attempts a `check` call (seconds).
    interval_seconds: float = 60.0

    # After emitting a Finding (post-dedup), suppress subsequent
    # identical findings for this long. Distinct from `interval_seconds`
    # — the rule keeps running, but matching findings stay quiet.
    cooldown_seconds: float = 300.0

    @abstractmethod
    async def check(self, ctx: AnalyticsContext) -> Finding | None:
        """Run one evaluation pass. Return a Finding or None."""

    def __init_subclass__(cls, **kwargs: Any) -> None:
        super().__init_subclass__(**kwargs)
        # Only concrete subclasses must declare a name — intermediate
        # ABCs are exempt so shared helper bases compile cleanly.
        if not getattr(cls, "__abstractmethods__", None) and not cls.name:
            raise RuntimeError(
                f"Rule subclass {cls.__name__} must set a non-empty `name`."
            )
