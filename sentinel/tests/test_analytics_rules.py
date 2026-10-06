"""Per-rule tests for PR-S4 analytics rules.

Each rule is exercised against the in-memory `make_context()` fixture
with synthetic readers, so the tests are deterministic and offline.
We cover the happy path, the no-finding path, dedup fingerprint
stability, and (where applicable) threshold-edge behaviour.
"""

from __future__ import annotations

import pytest

from sentinel.analytics.rules.allowlist_drift import AllowlistDriftRule
from sentinel.analytics.rules.audit_chain_break import AuditChainBreakRule
from sentinel.analytics.rules.cert_expiry import CertExpiryRule
from sentinel.analytics.rules.miner_quarantine_proximity import (
    MinerQuarantineProximityRule,
)
from sentinel.analytics.rules.release_anomaly import ReleaseAnomalyRule
from sentinel.analytics.rules.replay_attempts import ReplayAttemptsRule
from sentinel.tools.thebrain_rpc import MinerStatus
from tests._analytics_helpers import make_audit_record, make_context

# ---------------------------------------------------------------------------
# ReleaseAnomalyRule
# ---------------------------------------------------------------------------


def _spike_records(now: int, latest_count: int, history_count: int = 1):
    """Build N grants in 23 prior hourly bins + `latest_count` in the current bin."""

    records = []
    seq = 0
    current_bin = now // 3600
    # 23 historical bins, each with `history_count` grants near the bin's start.
    for offset in range(1, 24):
        bin_unix = (current_bin - offset) * 3600
        for _ in range(history_count):
            records.append(
                make_audit_record(seq=seq, granted=True, now_unix=bin_unix + 30)
            )
            seq += 1
    # Current bin grants.
    for _ in range(latest_count):
        records.append(
            make_audit_record(seq=seq, granted=True, now_unix=now - 10)
        )
        seq += 1
    return records


@pytest.mark.asyncio
async def test_release_anomaly_spike_trips() -> None:
    now = 1_700_000_000
    rule = ReleaseAnomalyRule(sigma=3.0, denial_threshold_pct=100.0)
    records = _spike_records(now, latest_count=50, history_count=1)
    ctx = make_context(audit_records=records, now_unix=now)
    finding = await rule.check(ctx)
    assert finding is not None
    assert finding.rule_name == "release_anomaly"
    assert "grant rate spike" in finding.summary
    assert finding.details["current_count"] == 50


@pytest.mark.asyncio
async def test_release_anomaly_steady_state_does_not_trip() -> None:
    now = 1_700_000_000
    rule = ReleaseAnomalyRule(sigma=3.0, denial_threshold_pct=100.0)
    # Same count in current bin as historical mean → not a spike.
    records = _spike_records(now, latest_count=1, history_count=1)
    ctx = make_context(audit_records=records, now_unix=now)
    finding = await rule.check(ctx)
    assert finding is None


@pytest.mark.asyncio
async def test_release_anomaly_cold_start_is_quiet() -> None:
    now = 1_700_000_000
    rule = ReleaseAnomalyRule(sigma=3.0, denial_threshold_pct=100.0)
    # Only 2 history bins of data — below MIN_HISTORY_BINS (4).
    records = [
        make_audit_record(seq=0, granted=True, now_unix=now - 3600 * 2 + 1),
        make_audit_record(seq=1, granted=True, now_unix=now - 3600 + 1),
        make_audit_record(seq=2, granted=True, now_unix=now - 10),
    ]
    ctx = make_context(audit_records=records, now_unix=now)
    finding = await rule.check(ctx)
    assert finding is None


@pytest.mark.asyncio
async def test_release_anomaly_denial_shift_trips() -> None:
    now = 1_700_000_000
    rule = ReleaseAnomalyRule(sigma=999.0, denial_threshold_pct=10.0)
    # Prior 5min: 10 grants, 0 denials → 0% denial.
    # Current 5min: 10 grants, 5 denials → 50% denial. Δ=+50pp.
    records = []
    seq = 0
    prior_start = now - 600
    cur_start = now - 300
    for i in range(10):
        records.append(
            make_audit_record(
                seq=seq, granted=True, now_unix=prior_start + i * 10
            )
        )
        seq += 1
    for i in range(5):
        records.append(
            make_audit_record(
                seq=seq, granted=False, now_unix=cur_start + i * 10, reason="Denied"
            )
        )
        seq += 1
    for i in range(5):
        records.append(
            make_audit_record(
                seq=seq, granted=True, now_unix=cur_start + 60 + i * 10
            )
        )
        seq += 1
    ctx = make_context(audit_records=records, now_unix=now)
    finding = await rule.check(ctx)
    assert finding is not None
    assert "denial rate shifted" in finding.summary
    assert finding.details["delta_pp"] > 10


@pytest.mark.asyncio
async def test_release_anomaly_no_records_returns_none() -> None:
    rule = ReleaseAnomalyRule()
    ctx = make_context(audit_records=())
    assert await rule.check(ctx) is None


# ---------------------------------------------------------------------------
# ReplayAttemptsRule
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_replay_attempts_above_threshold_trips() -> None:
    now = 1_700_000_000
    rule = ReplayAttemptsRule(threshold_per_hour=3)
    records = [
        make_audit_record(seq=i, granted=False, now_unix=now - 100, reason="Replay")
        for i in range(5)
    ]
    ctx = make_context(audit_records=records, now_unix=now)
    finding = await rule.check(ctx)
    assert finding is not None
    assert finding.severity.value == "ALERT"
    assert finding.details["count"] == 5
    assert finding.details["threshold"] == 3


@pytest.mark.asyncio
async def test_replay_attempts_at_threshold_does_not_trip() -> None:
    now = 1_700_000_000
    rule = ReplayAttemptsRule(threshold_per_hour=5)
    records = [
        make_audit_record(seq=i, granted=False, now_unix=now - 100, reason="Replay")
        for i in range(5)
    ]
    ctx = make_context(audit_records=records, now_unix=now)
    assert await rule.check(ctx) is None


@pytest.mark.asyncio
async def test_replay_attempts_outside_window_ignored() -> None:
    now = 1_700_000_000
    rule = ReplayAttemptsRule(threshold_per_hour=3)
    # 5 replays but all from 2h ago → outside the 1h window.
    records = [
        make_audit_record(
            seq=i, granted=False, now_unix=now - 7200, reason="Replay"
        )
        for i in range(5)
    ]
    ctx = make_context(audit_records=records, now_unix=now)
    assert await rule.check(ctx) is None


@pytest.mark.asyncio
async def test_replay_attempts_case_insensitive_prefix() -> None:
    now = 1_700_000_000
    rule = ReplayAttemptsRule(threshold_per_hour=1)
    records = [
        make_audit_record(
            seq=0, granted=False, now_unix=now - 10, reason="replay { kid: 0x… }"
        ),
        make_audit_record(
            seq=1, granted=False, now_unix=now - 20, reason="REPLAY"
        ),
    ]
    ctx = make_context(audit_records=records, now_unix=now)
    finding = await rule.check(ctx)
    assert finding is not None
    assert finding.details["count"] == 2


# ---------------------------------------------------------------------------
# AllowlistDriftRule
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_allowlist_drift_trips_past_threshold() -> None:
    rule = AllowlistDriftRule(max_drift=3)
    ctx = make_context(current_epoch=10, kbs_allowlist_epoch=5)
    finding = await rule.check(ctx)
    assert finding is not None
    assert finding.details["drift"] == 5
    assert finding.details["max_drift_threshold"] == 3


@pytest.mark.asyncio
async def test_allowlist_drift_at_threshold_does_not_trip() -> None:
    rule = AllowlistDriftRule(max_drift=3)
    ctx = make_context(current_epoch=10, kbs_allowlist_epoch=7)
    assert await rule.check(ctx) is None


@pytest.mark.asyncio
async def test_allowlist_drift_source_missing_is_noop() -> None:
    rule = AllowlistDriftRule(max_drift=3)
    ctx = make_context(current_epoch=42, kbs_allowlist_epoch=None)
    assert await rule.check(ctx) is None


@pytest.mark.asyncio
async def test_allowlist_drift_kbs_ahead_does_not_trip() -> None:
    """KBS ahead of chain is a different anomaly — out of scope here."""

    rule = AllowlistDriftRule(max_drift=3)
    ctx = make_context(current_epoch=5, kbs_allowlist_epoch=10)
    assert await rule.check(ctx) is None


# ---------------------------------------------------------------------------
# AuditChainBreakRule
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_audit_chain_break_trips_on_verify_error() -> None:
    rule = AuditChainBreakRule()
    ctx = make_context(verify_audit_chain_raises=RuntimeError("chain broken"))
    finding = await rule.check(ctx)
    assert finding is not None
    assert finding.severity.value == "CRITICAL"
    assert "chain verification FAILED" in finding.summary
    assert finding.details["error_class"] == "RuntimeError"


@pytest.mark.asyncio
async def test_audit_chain_break_silent_when_chain_valid() -> None:
    rule = AuditChainBreakRule()
    ctx = make_context(verify_audit_chain_raises=None)
    assert await rule.check(ctx) is None


@pytest.mark.asyncio
async def test_audit_chain_break_fingerprint_stable_for_same_error() -> None:
    rule = AuditChainBreakRule()
    ctx = make_context(verify_audit_chain_raises=RuntimeError("a"))
    f1 = await rule.check(ctx)
    f2 = await rule.check(ctx)
    assert f1 is not None and f2 is not None
    assert f1.fingerprint == f2.fingerprint


@pytest.mark.asyncio
async def test_audit_chain_break_finding_payload_is_minimal() -> None:
    """Finding only carries class + digest — no excerpt of error bytes."""

    rule = AuditChainBreakRule()
    big = "x" * 5000
    ctx = make_context(verify_audit_chain_raises=RuntimeError(big))
    finding = await rule.check(ctx)
    assert finding is not None
    assert set(finding.details) == {"error_class", "error_digest"}
    assert finding.details["error_class"] == "RuntimeError"
    assert len(finding.details["error_digest"]) == 16


# ---------------------------------------------------------------------------
# CertExpiryRule
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_cert_expiry_trips_past_age() -> None:
    now = 1_700_000_000
    too_old_mtime = now - 100 * 86400
    rule = CertExpiryRule(paths=["/etc/sentinel/anchor.key"], max_age_days=80)
    ctx = make_context(
        mtimes={"/etc/sentinel/anchor.key": too_old_mtime}, now_unix=now
    )
    finding = await rule.check(ctx)
    assert finding is not None
    assert "/etc/sentinel/anchor.key" in finding.summary
    assert finding.details["age_days"] >= 100


@pytest.mark.asyncio
async def test_cert_expiry_fresh_file_does_not_trip() -> None:
    now = 1_700_000_000
    rule = CertExpiryRule(paths=["/etc/sentinel/anchor.key"], max_age_days=80)
    ctx = make_context(
        mtimes={"/etc/sentinel/anchor.key": now - 60 * 86400}, now_unix=now
    )
    assert await rule.check(ctx) is None


@pytest.mark.asyncio
async def test_cert_expiry_skips_missing_files() -> None:
    rule = CertExpiryRule(paths=["/etc/sentinel/missing.pem"], max_age_days=10)
    ctx = make_context(mtimes={}, now_unix=1_700_000_000)
    assert await rule.check(ctx) is None


@pytest.mark.asyncio
async def test_cert_expiry_no_paths_configured_is_noop() -> None:
    rule = CertExpiryRule(paths=[], max_age_days=10)
    ctx = make_context()
    assert await rule.check(ctx) is None


def test_cert_expiry_rejects_zero_max_age() -> None:
    with pytest.raises(ValueError):
        CertExpiryRule(paths=["/x"], max_age_days=0)


# ---------------------------------------------------------------------------
# MinerQuarantineProximityRule
# ---------------------------------------------------------------------------


def _quarantined(epoch: int) -> MinerStatus:
    return MinerStatus(
        status="Quarantined",
        discriminant=1,
        last_transition_block=0,
        last_transition_epoch=epoch,
    )


def _active() -> MinerStatus:
    return MinerStatus(
        status="Active",
        discriminant=0,
        last_transition_block=0,
        last_transition_epoch=0,
    )


@pytest.mark.asyncio
async def test_miner_quarantine_proximity_trips_after_threshold() -> None:
    nid = b"\xaa" * 32
    rule = MinerQuarantineProximityRule(
        node_ids=[nid], hours_threshold=24, epoch_seconds=3600
    )
    # Current epoch 100, last transition 70 → 30 epochs = 30h > 24h.
    ctx = make_context(
        current_epoch=100, miner_statuses={nid: _quarantined(epoch=70)}
    )
    finding = await rule.check(ctx)
    assert finding is not None
    assert finding.details["status"] == "Quarantined"
    assert finding.details["epochs_in_state"] == 30


@pytest.mark.asyncio
async def test_miner_quarantine_proximity_recent_does_not_trip() -> None:
    nid = b"\xbb" * 32
    rule = MinerQuarantineProximityRule(
        node_ids=[nid], hours_threshold=24, epoch_seconds=3600
    )
    ctx = make_context(
        current_epoch=100, miner_statuses={nid: _quarantined(epoch=90)}
    )
    assert await rule.check(ctx) is None


@pytest.mark.asyncio
async def test_miner_quarantine_proximity_active_is_quiet() -> None:
    nid = b"\xcc" * 32
    rule = MinerQuarantineProximityRule(
        node_ids=[nid], hours_threshold=1, epoch_seconds=3600
    )
    ctx = make_context(
        current_epoch=100, miner_statuses={nid: _active()}
    )
    assert await rule.check(ctx) is None


@pytest.mark.asyncio
async def test_miner_quarantine_proximity_no_node_ids_is_noop() -> None:
    rule = MinerQuarantineProximityRule(
        node_ids=[], hours_threshold=24, epoch_seconds=3600
    )
    ctx = make_context(current_epoch=100)
    assert await rule.check(ctx) is None


@pytest.mark.asyncio
async def test_miner_quarantine_proximity_missing_status_skipped() -> None:
    nid = b"\xdd" * 32
    rule = MinerQuarantineProximityRule(
        node_ids=[nid], hours_threshold=24, epoch_seconds=3600
    )
    # No status for the monitored node → rule must not raise, and
    # must not emit.
    ctx = make_context(current_epoch=100, miner_statuses={})
    assert await rule.check(ctx) is None


def test_miner_quarantine_proximity_rejects_zero_epoch_seconds() -> None:
    with pytest.raises(ValueError):
        MinerQuarantineProximityRule(node_ids=[b"\x00" * 32], epoch_seconds=0)


# ---------------------------------------------------------------------------
# Env-validation surfaces (review PR-S4 review MED finding)
# ---------------------------------------------------------------------------


def test_release_anomaly_rejects_nan_sigma(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SENTINEL_RELEASE_SPIKE_SIGMA", "nan")
    rule = ReleaseAnomalyRule()
    # nan input MUST be ignored — rule falls back to default σ=3.0.
    assert rule.sigma == 3.0


def test_release_anomaly_rejects_negative_sigma(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("SENTINEL_RELEASE_SPIKE_SIGMA", "-1.0")
    rule = ReleaseAnomalyRule()
    assert rule.sigma == 3.0


def test_release_anomaly_rejects_oversized_denial_pct(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("SENTINEL_DENIAL_SHIFT_THRESHOLD_PCT", "200")
    rule = ReleaseAnomalyRule()
    assert rule.denial_threshold_pct == 10.0


def test_release_anomaly_rejects_negative_tail(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("SENTINEL_RELEASE_AUDIT_TAIL_N", "-5")
    rule = ReleaseAnomalyRule()
    assert rule.tail_n == 1000


def test_replay_attempts_rejects_zero_threshold(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("SENTINEL_REPLAY_THRESHOLD_PER_HOUR", "0")
    rule = ReplayAttemptsRule()
    # min_value=1 enforced; fallback to the default 10.
    assert rule.threshold == 10


def test_replay_attempts_rejects_negative_threshold(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("SENTINEL_REPLAY_THRESHOLD_PER_HOUR", "-3")
    rule = ReplayAttemptsRule()
    assert rule.threshold == 10


def test_release_anomaly_rejects_oversized_pct_kwarg() -> None:
    """Direct-kwarg path validates too (review round-2 MED)."""

    with pytest.raises(ValueError):
        ReleaseAnomalyRule(denial_threshold_pct=200.0)
    with pytest.raises(ValueError):
        ReleaseAnomalyRule(denial_threshold_pct=-1.0)


def test_finding_details_are_immutable_after_emit() -> None:
    """Review round-2 MED: Finding.details must not be mutable post-emit."""

    from sentinel.analytics.base import Finding, Severity

    f = Finding(
        rule_name="r",
        severity=Severity.INFO,
        summary="s",
        fingerprint="fp",
        details={"k": "v"},
    )
    with pytest.raises(TypeError):
        f.details["k"] = "tampered"  # type: ignore[index]


def test_finding_details_snapshot_decouples_from_caller_dict() -> None:
    """Review round-3 MED: caller mutating backing dict must NOT change details."""

    from sentinel.analytics.base import Finding, Severity

    backing = {"k": "original"}
    f = Finding(
        rule_name="r",
        severity=Severity.INFO,
        summary="s",
        fingerprint="fp",
        details=backing,
    )
    backing["k"] = "tampered"
    assert f.details["k"] == "original"


def test_finding_details_snapshot_decouples_from_mapping_proxy_backing() -> None:
    """Even a MappingProxyType input must be re-snapshotted."""

    from types import MappingProxyType

    from sentinel.analytics.base import Finding, Severity

    backing = {"k": "original"}
    f = Finding(
        rule_name="r",
        severity=Severity.INFO,
        summary="s",
        fingerprint="fp",
        details=MappingProxyType(backing),
    )
    backing["k"] = "tampered"
    assert f.details["k"] == "original"


def test_audit_chain_break_does_not_leak_error_message_into_finding() -> None:
    """Review HIGH: error_excerpt must NOT contain raw error bytes."""

    rule = AuditChainBreakRule()
    secret_like = "BEGIN PRIVATE KEY ...AAAA..."
    ctx = make_context(verify_audit_chain_raises=RuntimeError(secret_like))

    async def _run():
        return await rule.check(ctx)

    import asyncio as _asyncio

    finding = _asyncio.run(_run())
    assert finding is not None
    assert "error_excerpt" not in finding.details
    # Only error_class + digest survive into the finding stream.
    assert set(finding.details) == {"error_class", "error_digest"}
    # And neither field carries any byte of the original message.
    assert secret_like not in finding.details["error_digest"]
    assert secret_like not in finding.summary
