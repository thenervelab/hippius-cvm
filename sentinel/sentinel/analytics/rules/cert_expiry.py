"""Certificate / key freshness monitor.

Checks the mtime of a configurable list of cert + key files (mTLS CA,
KBS response-signing pubkey, sentinel-anchor key, etc.) against a
max-age threshold. mtime is a proxy for the rotation timestamp — for
the §S MVP this is good enough; PR-S5+ may switch to parsing the
PEM's `notAfter` once a cert library is justified.

Env knobs:
  * `SENTINEL_CERT_PATHS` — comma-separated absolute file paths.
  * `SENTINEL_CERT_MAX_AGE_DAYS` — int, default 80 (warns 10 days
    before the typical 90-day rotation).
"""

from __future__ import annotations

import logging
import os
from collections.abc import Sequence
from typing import Final

from sentinel.analytics.base import AnalyticsContext, Finding, Rule, Severity

log = logging.getLogger("sentinel.analytics.cert_expiry")

ENV_PATHS: Final = "SENTINEL_CERT_PATHS"
ENV_MAX_AGE_DAYS: Final = "SENTINEL_CERT_MAX_AGE_DAYS"

_DEFAULT_MAX_AGE_DAYS = 80
_SECONDS_PER_DAY = 86_400


def _read_int(env: str, default: int, *, min_value: int = 1) -> int:
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


def _read_paths() -> tuple[str, ...]:
    raw = os.environ.get(ENV_PATHS, "").strip()
    if not raw:
        return ()
    return tuple(p.strip() for p in raw.split(",") if p.strip())


class CertExpiryRule(Rule):
    """Trip when a watched cert/key file is older than `max_age_days`."""

    name = "cert_expiry"
    severity = Severity.WARN
    interval_seconds = 3600.0  # 1h is fine; rotation cadence is daily-at-best
    cooldown_seconds = 21_600.0  # 6h cooldown per file

    def __init__(
        self,
        *,
        paths: Sequence[str] | None = None,
        max_age_days: int | None = None,
    ) -> None:
        self.paths: tuple[str, ...] = (
            tuple(paths) if paths is not None else _read_paths()
        )
        self.max_age_days = (
            max_age_days
            if max_age_days is not None
            else _read_int(ENV_MAX_AGE_DAYS, _DEFAULT_MAX_AGE_DAYS)
        )
        if self.max_age_days <= 0:
            raise ValueError(
                f"{ENV_MAX_AGE_DAYS}={self.max_age_days} must be positive"
            )

    async def check(self, ctx: AnalyticsContext) -> Finding | None:
        if not self.paths:
            return None
        now = ctx.now_unix()
        max_age_seconds = self.max_age_days * _SECONDS_PER_DAY
        for path in self.paths:
            mtime = await ctx.stat_mtime(path)
            if mtime is None:
                # Missing-file is a separate worry handled out-of-band
                # (k8s pod fails to start). Don't escalate inside a
                # cert-age rule.
                log.debug("cert_expiry: %s not found, skipping", path)
                continue
            age_seconds = now - int(mtime)
            if age_seconds < max_age_seconds:
                continue
            # First finding per check wins — we'll get the next file
            # on the next pass thanks to per-path fingerprint.
            age_days = age_seconds // _SECONDS_PER_DAY
            return Finding(
                rule_name=self.name,
                severity=self.severity,
                summary=(
                    f"Cert/key file {path!r} is {age_days}d old "
                    f"(threshold={self.max_age_days}d) — rotation overdue"
                ),
                fingerprint=f"stale:{path}",
                details={
                    "path": path,
                    "age_days": int(age_days),
                    "max_age_days": self.max_age_days,
                    "mtime_unix": int(mtime),
                },
            )
        return None
