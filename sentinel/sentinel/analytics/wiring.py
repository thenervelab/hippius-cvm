"""Production wiring for the analytics loop.

Builds an `AnalyticsContext` whose async callables wrap the blocking
PR-S2 / PR-S3 readers in `asyncio.to_thread` so the loop's per-rule
timeouts can take effect even when a reader hangs.

This module is the only place env-resolved global state crosses into
the analytics layer; the rules themselves only read env at __init__
time. That separation keeps the dedup / DoS-isolation in `loop.py`
straightforward to audit.
"""

from __future__ import annotations

import asyncio
import logging
import os
import time
from pathlib import Path
from typing import Final

from sentinel.analytics.base import AnalyticsContext, Rule
from sentinel.analytics.rules import (
    AllowlistDriftRule,
    AuditChainBreakRule,
    CertExpiryRule,
    MinerQuarantineProximityRule,
    ReleaseAnomalyRule,
    ReplayAttemptsRule,
)
from sentinel.tools.kbs_audit import read_tail, verify_chain
from sentinel.tools.thebrain_rpc import read_current_epoch, read_miner_status

log = logging.getLogger("sentinel.analytics.wiring")

ENV_KBS_ALLOWLIST_EPOCH_PATH: Final = "KBS_ALLOWLIST_EPOCH_PATH"


def _stat_mtime_sync(path: str) -> float | None:
    try:
        return Path(path).stat().st_mtime
    except FileNotFoundError:
        return None


_U64_MAX = (1 << 64) - 1


def _valid_epoch(v: object) -> int | None:
    """Bounds-check a candidate epoch read from the KBS file.

    Substrate's `CurrentEpoch` is `u64`; the sentinel rejects negative
    or out-of-range values rather than firing spurious drift alerts.
    `bool` is explicitly rejected because `isinstance(True, int)` is
    `True` in Python.
    """

    # `bool` would pass an `isinstance(_, int)` check; reject explicitly.
    if isinstance(v, bool):
        return None
    if not isinstance(v, int):
        return None
    if 0 <= v <= _U64_MAX:
        return v
    return None


def _read_kbs_allowlist_epoch_sync() -> int | None:
    """Read KBS allowlist epoch from `KBS_ALLOWLIST_EPOCH_PATH`.

    Format: either a JSON `{"epoch": N}` / bare integer literal, or a
    plain decimal integer (whitespace tolerated). Returns None when
    the env var is unset, the file is missing, the contents are
    unparseable, or the parsed value is out of `u64` range — the rule
    treats all of these as "source not configured" rather than firing.
    """

    import json

    raw = os.environ.get(ENV_KBS_ALLOWLIST_EPOCH_PATH, "").strip()
    if not raw:
        return None
    p = Path(raw)
    try:
        data = p.read_text(encoding="utf-8")
    except FileNotFoundError:
        return None
    s = data.strip()
    if not s:
        return None
    try:
        obj = json.loads(s)
        # `bool` first (it's an int subclass and would slip past
        # `isinstance(obj, int)`).
        if isinstance(obj, bool):
            return None
        if isinstance(obj, int):
            return _valid_epoch(obj)
        if isinstance(obj, dict) and "epoch" in obj:
            return _valid_epoch(obj["epoch"])
    except json.JSONDecodeError:
        pass
    try:
        return _valid_epoch(int(s))
    except ValueError:
        # Intentionally NEVER log file contents — `KBS_ALLOWLIST_EPOCH_PATH`
        # could be mispointed at a secret file (PR-S4 review HIGH-adjacent
        # concern). Path + length is enough to diagnose the parse failure.
        log.warning(
            "%s=%s: file contents not parseable as epoch (len=%d bytes)",
            ENV_KBS_ALLOWLIST_EPOCH_PATH,
            p,
            len(s),
        )
        return None


def build_production_context() -> AnalyticsContext:
    """Wrap the PR-S2 / PR-S3 readers into the async context shape."""

    async def read_audit_tail(n: int):
        return await asyncio.to_thread(read_tail, n)

    async def verify_audit_chain() -> None:
        await asyncio.to_thread(verify_chain)

    async def read_current_epoch_async() -> int:
        return await asyncio.to_thread(read_current_epoch)

    async def read_miner_status_async(node_id: bytes):
        return await asyncio.to_thread(read_miner_status, node_id)

    async def read_kbs_allowlist_epoch_async() -> int | None:
        return await asyncio.to_thread(_read_kbs_allowlist_epoch_sync)

    async def stat_mtime_async(path: str) -> float | None:
        return await asyncio.to_thread(_stat_mtime_sync, path)

    return AnalyticsContext(
        read_audit_tail=read_audit_tail,
        verify_audit_chain=verify_audit_chain,
        read_current_epoch=read_current_epoch_async,
        read_miner_status=read_miner_status_async,
        read_kbs_allowlist_epoch=read_kbs_allowlist_epoch_async,
        stat_mtime=stat_mtime_async,
        now_unix=lambda: int(time.time()),
    )


def build_default_rules() -> list[Rule]:
    """All six PR-S4 rules with their env-resolved thresholds."""

    return [
        ReleaseAnomalyRule(),
        ReplayAttemptsRule(),
        AllowlistDriftRule(),
        AuditChainBreakRule(),
        CertExpiryRule(),
        MinerQuarantineProximityRule(),
    ]
