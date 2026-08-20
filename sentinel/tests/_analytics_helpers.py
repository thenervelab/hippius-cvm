"""Test fixtures shared across analytics rule + output-channel tests."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

from sentinel.analytics.base import AnalyticsContext, Finding, Severity
from sentinel.tools.kbs_audit import AuditRecord
from sentinel.tools.thebrain_rpc import MinerStatus


def make_audit_record(
    *,
    seq: int = 0,
    granted: bool = True,
    now_unix: int = 1_700_000_000,
    reason: str = "ok",
    ticket_id: str = "tk",
    vm_id: str = "vm",
) -> AuditRecord:
    """Build an AuditRecord with synthetic prev_hash + body_sha256."""

    return AuditRecord(
        seq=seq,
        domain="HIPPIUS_KBS_AUDIT_V1",
        granted=granted,
        now_unix=now_unix,
        prev_hash=bytes(32),
        reason=reason,
        ticket_id=ticket_id,
        vm_id=vm_id,
        body_sha256=bytes(32),
    )


def make_finding(
    *,
    rule_name: str = "test_rule",
    severity: Severity = Severity.ALERT,
    summary: str = "synthetic test finding",
    fingerprint: str = "fp-1",
    details: Mapping[str, Any] | None = None,
    at_unix: int = 1_700_000_000,
) -> Finding:
    """Build a `Finding` for output-channel + router tests."""

    return Finding(
        rule_name=rule_name,
        severity=severity,
        summary=summary,
        fingerprint=fingerprint,
        details=dict(details) if details is not None else {},
        at_unix=at_unix,
    )


def make_context(
    *,
    audit_records: Sequence[AuditRecord] = (),
    verify_audit_chain_raises: BaseException | None = None,
    current_epoch: int = 0,
    miner_statuses: dict[bytes, MinerStatus] | None = None,
    kbs_allowlist_epoch: int | None = None,
    mtimes: dict[str, float] | None = None,
    now_unix: int = 1_700_000_000,
) -> AnalyticsContext:
    """Async-mock AnalyticsContext built from in-memory state."""

    async def read_audit_tail(_n: int) -> Sequence[AuditRecord]:
        return list(audit_records)

    async def verify_audit_chain() -> None:
        if verify_audit_chain_raises is not None:
            raise verify_audit_chain_raises

    async def read_current_epoch() -> int:
        return current_epoch

    statuses = miner_statuses or {}

    async def read_miner_status(node_id: bytes) -> MinerStatus | None:
        return statuses.get(node_id)

    async def read_kbs_allowlist_epoch() -> int | None:
        return kbs_allowlist_epoch

    mtime_map = mtimes or {}

    async def stat_mtime(path: str) -> float | None:
        return mtime_map.get(path)

    return AnalyticsContext(
        read_audit_tail=read_audit_tail,
        verify_audit_chain=verify_audit_chain,
        read_current_epoch=read_current_epoch,
        read_miner_status=read_miner_status,
        read_kbs_allowlist_epoch=read_kbs_allowlist_epoch,
        stat_mtime=stat_mtime,
        now_unix=lambda: now_unix,
    )
