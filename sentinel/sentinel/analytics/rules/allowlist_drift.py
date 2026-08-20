"""Allowlist-epoch drift detector.

Compares thebrain on-chain `CurrentEpoch` (read via PR-S3
`read_current_epoch_tool`) against the epoch number KBS thinks its
allowlist is on. KBS exposes its current allowlist epoch via the file
`KBS_ALLOWLIST_EPOCH_PATH` (a small JSON `{"epoch": N}` or a plain
integer). When the on-chain epoch advances but KBS is still serving
an older allowlist, this rule trips.

If `KBS_ALLOWLIST_EPOCH_PATH` is unset OR the reader returns None
the rule is a no-op (logged at INFO) — the source not yet existing
is not a finding worth alerting on; PR-K will wire the real path.

Env knobs:
  * `SENTINEL_ALLOWLIST_DRIFT_MAX_EPOCHS` — int, default 3.
"""

from __future__ import annotations

import logging
import os
from typing import Final

from sentinel.analytics.base import AnalyticsContext, Finding, Rule, Severity

log = logging.getLogger("sentinel.analytics.allowlist_drift")

ENV_MAX_DRIFT: Final = "SENTINEL_ALLOWLIST_DRIFT_MAX_EPOCHS"

_DEFAULT_MAX_DRIFT = 3


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


class AllowlistDriftRule(Rule):
    """Trip when on-chain epoch leads KBS allowlist epoch by > N."""

    name = "allowlist_drift"
    severity = Severity.ALERT
    interval_seconds = 120.0
    cooldown_seconds = 600.0

    def __init__(self, *, max_drift: int | None = None) -> None:
        self.max_drift = (
            max_drift
            if max_drift is not None
            else _read_int(ENV_MAX_DRIFT, _DEFAULT_MAX_DRIFT, min_value=0)
        )
        if self.max_drift < 0:
            raise ValueError(
                f"{ENV_MAX_DRIFT}={self.max_drift} must be non-negative"
            )

    async def check(self, ctx: AnalyticsContext) -> Finding | None:
        on_chain = await ctx.read_current_epoch()
        kbs_known = await ctx.read_kbs_allowlist_epoch()
        if kbs_known is None:
            log.debug("allowlist_drift: KBS epoch source not configured; skipping")
            return None
        # Only treat positive drift as a problem — KBS being ahead of
        # the chain is a different (and much rarer) anomaly handled by
        # the audit chain break rule when the chain rewinds.
        drift = on_chain - kbs_known
        if drift <= self.max_drift:
            return None
        # Fingerprint bucketed by drift magnitude (clamped) so a single
        # incident emits once even as the gap widens slowly.
        bucket = min(drift, self.max_drift * 4)
        return Finding(
            rule_name=self.name,
            severity=self.severity,
            summary=(
                f"KBS allowlist behind on-chain epoch by {drift} "
                f"(on_chain={on_chain}, kbs={kbs_known}, threshold={self.max_drift})"
            ),
            fingerprint=f"drift:{bucket}",
            details={
                "on_chain_epoch": on_chain,
                "kbs_allowlist_epoch": kbs_known,
                "drift": drift,
                "max_drift_threshold": self.max_drift,
            },
        )


