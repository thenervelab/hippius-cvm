"""Concrete sentinel analytics rules (PR-S4).

Each module here owns exactly one rule and reads its thresholds from
env at construction time. The rules never reach into env or globals
inside `check()` — they receive an `AnalyticsContext` and only call
its reader callables. That keeps the unit tests reproducible and the
DoS-isolation in the loop tractable (one rule's failure can't poison
another).
"""

from sentinel.analytics.rules.allowlist_drift import AllowlistDriftRule
from sentinel.analytics.rules.audit_chain_break import AuditChainBreakRule
from sentinel.analytics.rules.cert_expiry import CertExpiryRule
from sentinel.analytics.rules.miner_quarantine_proximity import (
    MinerQuarantineProximityRule,
)
from sentinel.analytics.rules.release_anomaly import ReleaseAnomalyRule
from sentinel.analytics.rules.replay_attempts import ReplayAttemptsRule

__all__ = [
    "AllowlistDriftRule",
    "AuditChainBreakRule",
    "CertExpiryRule",
    "MinerQuarantineProximityRule",
    "ReleaseAnomalyRule",
    "ReplayAttemptsRule",
]
