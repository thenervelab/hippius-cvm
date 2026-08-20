"""§K permissionless first-contact auto-provisioning.

A `hippius-node:<id>` heartbeat from a node vali has never seen is
provisioned a MinerIdentity + TelemetrySource on the spot — no operator
step — iff it verifies against the node_id AND the node is on-chain
Active. The verifier + chain reads are mocked (Cargo-/chain-independent).
"""

from __future__ import annotations

import pytest

from apps.miners.models import MinerIdentity
from apps.telemetry import service, verifier
from apps.telemetry.models import SourceType, TelemetrySource
from apps.telemetry.verifier import HeartbeatBody

pytestmark = pytest.mark.django_db

NODE = "aa" * 32


def _mock_verify(monkeypatch, miner_id="miner-x"):
    monkeypatch.setattr(
        verifier,
        "verify_heartbeat",
        lambda *, envelope, verifying_key: HeartbeatBody(
            schema_version=1,
            domain="hb",
            miner_id=miner_id,
            timestamp_unix=0,
            sequence=1,
        ),
    )


def test_autoprovision_creates_identity_and_source(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _mock_verify(monkeypatch, "miner-x")
    monkeypatch.setattr(service, "_node_id_is_onchain_active", lambda h: True)
    mid = service.autoprovision_node_heartbeat_source(NODE, b"env")
    assert mid == "miner-x"
    s = TelemetrySource.objects.get(
        source=SourceType.MINER.value, source_id="miner-x"
    )
    assert bytes(s.verifying_key) == bytes.fromhex(NODE)
    assert s.is_active
    m = MinerIdentity.objects.get(miner_id="miner-x")
    assert m.pubkey_hex == NODE
    assert m.chain_node_id == NODE


def test_accepted_heartbeat_envelope_is_terminal_not_pending(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Regression: a verified heartbeat's WHOLE effect (`last_seen_at` +
    `last_heartbeat_sequence`) is applied synchronously at ingest and
    NOTHING `pull()`s `kind=heartbeat` (only `served_receipt` is drained),
    so its envelope must be created DONE — not PENDING. Left PENDING it
    never drains, piles up unboundedly, and once a source crosses the #742
    per-source backpressure cap its OWN future heartbeats 503 → `last_seen`
    freezes → the miner goes stale + undispatchable (the 2026-07 outage)."""
    from django.utils import timezone

    from apps.miners.models import MinerStatus
    from apps.telemetry.models import ProcessingStatus, TelemetryEnvelope
    from apps.telemetry.verifier import HeartbeatBody

    mid = "hb-terminal-miner"
    monkeypatch.setattr(
        verifier,
        "verify_heartbeat",
        lambda *, envelope, verifying_key: HeartbeatBody(
            schema_version=1,
            domain="hb",
            miner_id=mid,
            timestamp_unix=int(timezone.now().timestamp()),
            sequence=1,
        ),
    )
    MinerIdentity.objects.create(
        miner_id=mid,
        pubkey_hex=("cd" * 32),
        platform_id="p-hb-terminal",
        status=MinerStatus.ACTIVE.value,
    )
    TelemetrySource.objects.create(
        source=SourceType.MINER.value,
        source_id=mid,
        verifying_key=bytes(32),
        is_active=True,
    )

    row, created = service.ingest_heartbeat(miner_id=mid, envelope=b"env")

    assert created is True
    assert row.processing_status == ProcessingStatus.DONE.value
    # liveness is applied at ingest
    m = MinerIdentity.objects.get(miner_id=mid)
    assert m.last_seen_at is not None
    assert m.last_heartbeat_sequence == 1
    # …and the row does NOT accumulate against the per-source PENDING cap
    assert not TelemetryEnvelope.objects.filter(
        source=SourceType.MINER.value,
        source_id=mid,
        processing_status=ProcessingStatus.PENDING.value,
    ).exists()


def test_autoprovision_refused_when_not_onchain(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _mock_verify(monkeypatch)
    monkeypatch.setattr(service, "_node_id_is_onchain_active", lambda h: False)
    assert service.autoprovision_node_heartbeat_source(NODE, b"env") is None
    assert not TelemetrySource.objects.filter(source=SourceType.MINER.value).exists()


def test_autoprovision_refused_on_verify_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def _boom(**_kw):
        raise verifier.VerifierFailed(message="bad sig", category="signature")

    monkeypatch.setattr(verifier, "verify_heartbeat", _boom)
    monkeypatch.setattr(service, "_node_id_is_onchain_active", lambda h: True)
    assert service.autoprovision_node_heartbeat_source(NODE, b"env") is None


def test_autoprovision_refused_on_malformed_node_id() -> None:
    assert service.autoprovision_node_heartbeat_source("zz", b"env") is None
    assert service.autoprovision_node_heartbeat_source("aabb", b"env") is None


def test_autoprovision_is_idempotent(monkeypatch: pytest.MonkeyPatch) -> None:
    _mock_verify(monkeypatch, "miner-y")
    monkeypatch.setattr(service, "_node_id_is_onchain_active", lambda h: True)
    a = service.autoprovision_node_heartbeat_source(NODE, b"env")
    b = service.autoprovision_node_heartbeat_source(NODE, b"env")
    assert a == b == "miner-y"
    assert (
        TelemetrySource.objects.filter(
            source=SourceType.MINER.value, source_id="miner-y"
        ).count()
        == 1
    )
