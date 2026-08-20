"""Release-rate spike + denial-pattern shift detection.

Two anomaly checks against the KBS audit tail:

  * **Spike**: count of `granted=True` records in the most recent 1h
    bin is compared against the rolling mean+std of the previous 23h
    of 1h bins. Trip if `latest > mean + sigma * std` (default sigma
    = 3.0, configurable). Needs ≥ 4 bins of history before scoring —
    a cold-start KBS will not emit a spurious spike alert.

  * **Denial shift**: fraction of records with `granted=False` over
    the last 5 minutes vs the prior 5-minute window. Trip if the
    absolute difference exceeds the configured percentage (default
    10pp). Needs at least one denial in either window so a quiet
    chain doesn't produce noise.

Thresholds are read from env at construction time so ops can tune
without redeploys:

  * `SENTINEL_RELEASE_SPIKE_SIGMA` — float, default 3.0.
  * `SENTINEL_DENIAL_SHIFT_THRESHOLD_PCT` — float, default 10.0.
  * `SENTINEL_RELEASE_AUDIT_TAIL_N` — int, default 1000.
"""

from __future__ import annotations

import logging
import math
import os
from collections.abc import Callable
from typing import Final

from sentinel.analytics.base import AnalyticsContext, Finding, Rule, Severity

log = logging.getLogger("sentinel.analytics.release_anomaly")

ENV_SIGMA: Final = "SENTINEL_RELEASE_SPIKE_SIGMA"
ENV_DENIAL_PCT: Final = "SENTINEL_DENIAL_SHIFT_THRESHOLD_PCT"
ENV_TAIL_N: Final = "SENTINEL_RELEASE_AUDIT_TAIL_N"

_DEFAULT_SIGMA = 3.0
_DEFAULT_DENIAL_PCT = 10.0
_DEFAULT_TAIL_N = 1000

# Window definitions (seconds).
_BIN_SECONDS = 3600  # 1h
_HISTORY_BINS = 23  # 24h of context, last bin is "current"
_DENIAL_WINDOW = 300  # 5 minutes
_MIN_HISTORY_BINS = 4  # cold-start guard


def _read_float(
    env: str, default: float, *, validate: Callable[[float], bool] = lambda _v: True
) -> float:
    """Parse a float from env. Reject NaN, inf, and validator-rejected values."""

    raw = os.environ.get(env, "").strip()
    if not raw:
        return default
    try:
        v = float(raw)
    except ValueError:
        log.warning("%s=%r is not a float; using default %s", env, raw, default)
        return default
    if not math.isfinite(v) or not validate(v):
        log.warning(
            "%s=%r failed validation (must be finite and in range); using default %s",
            env,
            raw,
            default,
        )
        return default
    return v


def _read_int(
    env: str, default: int, *, validate: Callable[[int], bool] = lambda _v: True
) -> int:
    raw = os.environ.get(env, "").strip()
    if not raw:
        return default
    try:
        v = int(raw)
    except ValueError:
        log.warning("%s=%r is not an int; using default %s", env, raw, default)
        return default
    if not validate(v):
        log.warning(
            "%s=%r failed validation; using default %s", env, raw, default
        )
        return default
    return v


class ReleaseAnomalyRule(Rule):
    """Rate spike + denial pattern shift against KBS audit tail."""

    name = "release_anomaly"
    severity = Severity.ALERT
    interval_seconds = 60.0
    cooldown_seconds = 1800.0  # 30 minutes — spike alerts are loud

    def __init__(
        self,
        *,
        sigma: float | None = None,
        denial_threshold_pct: float | None = None,
        tail_n: int | None = None,
    ) -> None:
        # Sigma must be finite and positive (negative σ would trigger
        # on any data; NaN would silently make comparisons fail-open).
        self.sigma = (
            sigma
            if sigma is not None
            else _read_float(ENV_SIGMA, _DEFAULT_SIGMA, validate=lambda v: v > 0)
        )
        # Denial-shift threshold is a percentage in [0, 100].
        self.denial_threshold_pct = (
            denial_threshold_pct
            if denial_threshold_pct is not None
            else _read_float(
                ENV_DENIAL_PCT,
                _DEFAULT_DENIAL_PCT,
                validate=lambda v: 0.0 <= v <= 100.0,
            )
        )
        self.tail_n = (
            tail_n
            if tail_n is not None
            else _read_int(ENV_TAIL_N, _DEFAULT_TAIL_N, validate=lambda v: v > 0)
        )
        if (
            not math.isfinite(self.sigma)
            or self.sigma <= 0
            or not math.isfinite(self.denial_threshold_pct)
            or not (0.0 <= self.denial_threshold_pct <= 100.0)
            or self.tail_n <= 0
        ):
            raise ValueError(
                "ReleaseAnomalyRule needs sigma>0 (finite), "
                "0<=denial_threshold_pct<=100, tail_n>0"
            )

    async def check(self, ctx: AnalyticsContext) -> Finding | None:
        records = await ctx.read_audit_tail(self.tail_n)
        if not records:
            return None
        now = ctx.now_unix()

        spike = self._score_spike(records, now)
        if spike is not None:
            return spike
        return self._score_denial_shift(records, now)

    def _score_spike(
        self,
        records: object,
        now: int,
    ) -> Finding | None:
        # Bin granted records by `now_unix // 3600`. The "current" bin
        # is `now // 3600`; we score it against the previous 23 bins.
        current_bin = now // _BIN_SECONDS
        first_history_bin = current_bin - _HISTORY_BINS
        counts: dict[int, int] = {}
        for r in records:  # type: ignore[attr-defined]
            if not r.granted:
                continue
            bin_ = r.now_unix // _BIN_SECONDS
            if bin_ < first_history_bin or bin_ > current_bin:
                continue
            counts[bin_] = counts.get(bin_, 0) + 1
        latest_count = counts.get(current_bin, 0)
        history = [counts.get(b, 0) for b in range(first_history_bin, current_bin)]
        if len(history) < _MIN_HISTORY_BINS:
            return None
        # Drop the cold-start zeros at the head — bins entirely before
        # the first observed grant don't carry information.
        first_nonzero = next((i for i, v in enumerate(history) if v > 0), None)
        if first_nonzero is None:
            # No history grants at all → cold start; only fire if the
            # current bin is itself non-trivial (rare; avoid noise).
            return None
        history = history[first_nonzero:]
        if len(history) < _MIN_HISTORY_BINS:
            return None
        mean = sum(history) / len(history)
        var = sum((x - mean) ** 2 for x in history) / len(history)
        std = math.sqrt(var)
        if std == 0:
            # Uniform history. The σ-test is undefined, so fall back to
            # an absolute-deviation gate: trip only when the current
            # bin exceeds the floor by at least `sigma` (clamped ≥ 3)
            # *and* the absolute jump is meaningful.
            absolute_floor = mean + max(self.sigma, 3.0)
            if latest_count <= absolute_floor:
                return None
            threshold = absolute_floor
        else:
            threshold = mean + self.sigma * std
            if latest_count <= threshold:
                return None
        fingerprint = f"spike:{current_bin}"
        return Finding(
            rule_name=self.name,
            severity=self.severity,
            summary=(
                f"KBS grant rate spike: bin={current_bin} grants={latest_count} "
                f"vs mean={mean:.1f} std={std:.1f} (>{self.sigma:.1f}σ)"
            ),
            fingerprint=fingerprint,
            details={
                "bin_unix": current_bin * _BIN_SECONDS,
                "current_count": latest_count,
                "history_mean": round(mean, 3),
                "history_std": round(std, 3),
                "sigma_threshold": self.sigma,
                "history_bins": len(history),
            },
        )

    def _score_denial_shift(
        self,
        records: object,
        now: int,
    ) -> Finding | None:
        cur_start = now - _DENIAL_WINDOW
        prior_start = cur_start - _DENIAL_WINDOW
        cur_total = cur_denied = 0
        prior_total = prior_denied = 0
        for r in records:  # type: ignore[attr-defined]
            if prior_start <= r.now_unix < cur_start:
                prior_total += 1
                if not r.granted:
                    prior_denied += 1
            elif cur_start <= r.now_unix <= now:
                cur_total += 1
                if not r.granted:
                    cur_denied += 1
        if cur_total == 0 or prior_total == 0:
            return None
        if cur_denied == 0 and prior_denied == 0:
            return None
        cur_pct = 100.0 * cur_denied / cur_total
        prior_pct = 100.0 * prior_denied / prior_total
        diff = cur_pct - prior_pct
        if abs(diff) < self.denial_threshold_pct:
            return None
        bucket = now // _DENIAL_WINDOW
        fingerprint = f"denial-shift:{bucket}:{1 if diff > 0 else 0}"
        direction = "up" if diff > 0 else "down"
        return Finding(
            rule_name=self.name,
            severity=Severity.WARN,
            summary=(
                f"KBS denial rate shifted {direction}: {prior_pct:.1f}% → "
                f"{cur_pct:.1f}% over last 5min (Δ={diff:+.1f}pp, "
                f"threshold={self.denial_threshold_pct:.1f}pp)"
            ),
            fingerprint=fingerprint,
            details={
                "cur_total": cur_total,
                "cur_denied": cur_denied,
                "prior_total": prior_total,
                "prior_denied": prior_denied,
                "delta_pp": round(diff, 3),
                "threshold_pp": self.denial_threshold_pct,
            },
        )
