"""Analytics rules + dedup loop (PR-S4).

Six read-only rules patrol the hippius-compute control plane on top of
the PR-S2 / PR-S3 reader tools and emit `Finding` records. PR-S5 will
add the output channels (GitHub Issues / Slack); for PR-S4 findings are
logged and exposed to the agent through `RecentFindings`. The actual
LLM-facing wire-up (findings as prompt context) lands in PR-S6.

Public surface kept tiny so the security review can audit it:
  - `Severity`, `Finding`, `AnalyticsContext` — value types.
  - `Rule` — the abstract base every rule inherits.
  - `AnalyticsLoop`, `RecentFindings` — run + collect.
  - `build_default_rules`, `build_production_context` — wiring helpers
    used by `sentinel.main`.
"""

from sentinel.analytics.base import (
    AnalyticsContext,
    Finding,
    Rule,
    Severity,
)
from sentinel.analytics.loop import (
    DEFAULT_DEDUP_CACHE_SIZE,
    DEFAULT_RULE_TIMEOUT_S,
    AnalyticsLoop,
    RecentFindings,
)
from sentinel.analytics.wiring import build_default_rules, build_production_context

__all__ = [
    "AnalyticsContext",
    "AnalyticsLoop",
    "DEFAULT_DEDUP_CACHE_SIZE",
    "DEFAULT_RULE_TIMEOUT_S",
    "Finding",
    "RecentFindings",
    "Rule",
    "Severity",
    "build_default_rules",
    "build_production_context",
]
