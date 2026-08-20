"""Miner-quarantine proximity rule.

For each monitored node id, fetches `MinerStatus` via PR-S3
`read_miner_status_tool`. Flags any node that has been in the
non-`Active` state for longer than the configured threshold. The
"how long" is computed from `(current_epoch - last_transition_epoch)`
multiplied by a configurable epoch length, since the chain doesn't
expose wall-clock time directly to the sentinel.

Env knobs:
  * `SENTINEL_MONITORED_NODE_IDS` — comma-separated 32-byte hex ids.
  * `SENTINEL_QUARANTINE_HOURS_THRESHOLD` — int, default 24.
  * `SENTINEL_EPOCH_SECONDS` — int, default 3600 (1h epochs in MVP).
"""

from __future__ import annotations

import logging
import os
from collections.abc import Sequence
from typing import Final

from sentinel.analytics.base import AnalyticsContext, Finding, Rule, Severity

log = logging.getLogger("sentinel.analytics.miner_quarantine_proximity")

ENV_NODE_IDS: Final = "SENTINEL_MONITORED_NODE_IDS"
ENV_HOURS: Final = "SENTINEL_QUARANTINE_HOURS_THRESHOLD"
ENV_EPOCH_SECONDS: Final = "SENTINEL_EPOCH_SECONDS"

_DEFAULT_HOURS = 24
_DEFAULT_EPOCH_SECONDS = 3600


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


def _parse_node_id(raw: str) -> bytes | None:
    s = raw.strip().removeprefix("0x")
    if not s:
        return None
    try:
        nid = bytes.fromhex(s)
    except ValueError:
        log.warning("monitored node id %r is not valid hex", raw)
        return None
    if len(nid) != 32:
        log.warning(
            "monitored node id %r decoded to %d bytes (want 32)", raw, len(nid)
        )
        return None
    return nid


def _read_node_ids() -> tuple[bytes, ...]:
    raw = os.environ.get(ENV_NODE_IDS, "").strip()
    if not raw:
        return ()
    parsed: list[bytes] = []
    for token in raw.split(","):
        nid = _parse_node_id(token)
        if nid is not None:
            parsed.append(nid)
    return tuple(parsed)


class MinerQuarantineProximityRule(Rule):
    """Flag nodes stuck in Quarantined / Decommissioned > threshold hours."""

    name = "miner_quarantine_proximity"
    severity = Severity.WARN
    interval_seconds = 300.0  # 5 minutes — chain state shifts slowly
    cooldown_seconds = 3600.0

    def __init__(
        self,
        *,
        node_ids: Sequence[bytes] | None = None,
        hours_threshold: int | None = None,
        epoch_seconds: int | None = None,
    ) -> None:
        self.node_ids: tuple[bytes, ...] = (
            tuple(node_ids) if node_ids is not None else _read_node_ids()
        )
        self.hours_threshold = (
            hours_threshold
            if hours_threshold is not None
            else _read_int(ENV_HOURS, _DEFAULT_HOURS)
        )
        self.epoch_seconds = (
            epoch_seconds
            if epoch_seconds is not None
            else _read_int(ENV_EPOCH_SECONDS, _DEFAULT_EPOCH_SECONDS)
        )
        if self.hours_threshold <= 0 or self.epoch_seconds <= 0:
            raise ValueError("hours_threshold + epoch_seconds must be positive")

    async def check(self, ctx: AnalyticsContext) -> Finding | None:
        if not self.node_ids:
            return None
        current_epoch = await ctx.read_current_epoch()
        threshold_epochs = (self.hours_threshold * 3600) // self.epoch_seconds
        # Guarantee at least 1 epoch of grace even for unusual configs.
        threshold_epochs = max(threshold_epochs, 1)
        for nid in self.node_ids:
            status = await ctx.read_miner_status(nid)
            if status is None:
                continue
            if status.status == "Active":
                continue
            epochs_in_state = current_epoch - status.last_transition_epoch
            if epochs_in_state < threshold_epochs:
                continue
            nid_hex = nid.hex()
            hours_in_state = (epochs_in_state * self.epoch_seconds) // 3600
            return Finding(
                rule_name=self.name,
                severity=self.severity,
                summary=(
                    f"Miner {nid_hex[:16]}…: {status.status} for "
                    f"~{hours_in_state}h ({epochs_in_state} epochs, "
                    f"threshold={self.hours_threshold}h)"
                ),
                fingerprint=f"stuck:{nid_hex}:{status.status}",
                details={
                    "node_id_hex": nid_hex,
                    "status": status.status,
                    "discriminant": status.discriminant,
                    "last_transition_epoch": status.last_transition_epoch,
                    "current_epoch": current_epoch,
                    "epochs_in_state": epochs_in_state,
                    "approx_hours_in_state": hours_in_state,
                    "hours_threshold": self.hours_threshold,
                },
            )
        return None
