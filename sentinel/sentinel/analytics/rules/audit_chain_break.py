"""KBS audit-chain integrity monitor.

Every interval the rule calls `ctx.verify_audit_chain()` (which wraps
PR-S2 `verify_chain`). Any exception — `AuditVerifyError` or otherwise
— is treated as a CRITICAL finding and surfaces immediately.

Fingerprint is hashed from the error message so the same failure mode
doesn't re-emit every minute, but a different tamper signature still
trips a fresh alert.
"""

from __future__ import annotations

import hashlib
import logging

from sentinel.analytics.base import AnalyticsContext, Finding, Rule, Severity

log = logging.getLogger("sentinel.analytics.audit_chain_break")


class AuditChainBreakRule(Rule):
    """CRITICAL if KBS audit chain verification fails."""

    name = "audit_chain_break"
    severity = Severity.CRITICAL
    interval_seconds = 300.0  # 5 minutes
    cooldown_seconds = 900.0  # 15 minutes per fingerprint

    async def check(self, ctx: AnalyticsContext) -> Finding | None:
        try:
            await ctx.verify_audit_chain()
        except Exception as e:  # noqa: BLE001 — explicitly want everything
            # Hash the message so a recurring tamper signature dedups,
            # but never include any byte of the message in the finding
            # or in logs — reader exceptions can quote arbitrary on-disk
            # bytes (canonical-CBOR rejection echoes the offending
            # record body), which would defeat the §S "no plaintext
            # leak into the LLM stream" invariant.
            msg = str(e) or e.__class__.__name__
            digest = hashlib.sha256(
                msg.encode("utf-8", errors="replace")
            ).hexdigest()[:16]
            log.error(
                "AUDIT CHAIN BREAK detected: class=%s fp=%s",
                e.__class__.__name__,
                digest,
            )
            return Finding(
                rule_name=self.name,
                severity=self.severity,
                summary=(
                    "KBS audit chain verification FAILED — "
                    "external attestation root cannot be trusted"
                ),
                fingerprint=f"break:{digest}",
                details={
                    "error_class": e.__class__.__name__,
                    "error_digest": digest,
                },
            )
        return None
