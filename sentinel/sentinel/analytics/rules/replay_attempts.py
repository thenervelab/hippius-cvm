"""KBS audit replay-attempt counter.

Scans the KBS audit tail for records whose `reason` field starts with
"Replay" (the kbs-core error variant `KbsError::Replay { … }` is
serialized into the audit `reason` field). Emits an ALERT when the
count over the last hour exceeds the configured threshold.

Env knobs:
  * `SENTINEL_REPLAY_THRESHOLD_PER_HOUR` — int, default 10.
  * `SENTINEL_REPLAY_AUDIT_TAIL_N` — int, default 1000.
"""

from __future__ import annotations

import logging
import os
from typing import Final

from sentinel.analytics.base import AnalyticsContext, Finding, Rule, Severity

log = logging.getLogger("sentinel.analytics.replay_attempts")

ENV_THRESHOLD: Final = "SENTINEL_REPLAY_THRESHOLD_PER_HOUR"
ENV_TAIL_N: Final = "SENTINEL_REPLAY_AUDIT_TAIL_N"

_DEFAULT_THRESHOLD = 10
_DEFAULT_TAIL_N = 1000
_WINDOW_SECONDS = 3600

# Matches `KbsError::Replay` serializations. We use a case-insensitive
# startswith so future variant names that share the prefix still count.
_REPLAY_PREFIX = "replay"


def _read_int(env: str, default: int, *, min_value: int = 0) -> int:
    raw = os.environ.get(env, "").strip()
    if not raw:
        return default
    try:
        v = int(raw)
    except ValueError:
        log.warning("%s=%r is not an int; using default %s", env, raw, default)
        return default
    if v < min_value:
        log.warning(
            "%s=%r below min=%d; using default %s", env, raw, min_value, default
        )
        return default
    return v


class ReplayAttemptsRule(Rule):
    """Hourly count of KBS replay-rejected tickets above threshold."""

    name = "replay_attempts"
    severity = Severity.ALERT
    interval_seconds = 60.0
    cooldown_seconds = 1800.0

    def __init__(
        self,
        *,
        threshold_per_hour: int | None = None,
        tail_n: int | None = None,
    ) -> None:
        # Replay threshold must be > 0 — `0` would emit on any single
        # replay, which is too noisy for the default channel.
        self.threshold = (
            threshold_per_hour
            if threshold_per_hour is not None
            else _read_int(ENV_THRESHOLD, _DEFAULT_THRESHOLD, min_value=1)
        )
        self.tail_n = (
            tail_n
            if tail_n is not None
            else _read_int(ENV_TAIL_N, _DEFAULT_TAIL_N, min_value=1)
        )
        if self.threshold < 1 or self.tail_n < 1:
            raise ValueError("threshold_per_hour and tail_n must be >= 1")

    async def check(self, ctx: AnalyticsContext) -> Finding | None:
        records = await ctx.read_audit_tail(self.tail_n)
        if not records:
            return None
        now = ctx.now_unix()
        window_start = now - _WINDOW_SECONDS
        replay_count = 0
        for r in records:
            if r.now_unix < window_start or r.now_unix > now:
                continue
            if isinstance(r.reason, str) and r.reason.lower().startswith(_REPLAY_PREFIX):
                replay_count += 1
        if replay_count <= self.threshold:
            return None
        # Bucket by hour so we emit once per spike, not once per check.
        bucket = now // _WINDOW_SECONDS
        return Finding(
            rule_name=self.name,
            severity=self.severity,
            summary=(
                f"KBS replay attempts: {replay_count} in last hour "
                f"(threshold={self.threshold})"
            ),
            fingerprint=f"replay:{bucket}",
            details={
                "count": replay_count,
                "threshold": self.threshold,
                "window_seconds": _WINDOW_SECONDS,
                "bucket_unix": bucket * _WINDOW_SECONDS,
            },
        )
