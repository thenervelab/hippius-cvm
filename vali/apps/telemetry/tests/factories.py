"""DB row builders for the telemetry test suite.

All builders touch the DB — callers need `@pytest.mark.django_db`.
"""

from __future__ import annotations

import hashlib
import uuid

from django.utils import timezone

from apps.telemetry.models import (
    ProcessingStatus,
    TelemetryEnvelope,
    TelemetrySource,
)


def make_source(
    *,
    source: str = "edge_gateway",
    source_id: str = "edge-1",
    verifying_key: bytes | None = None,
    is_active: bool = True,
    consecutive_failures: int = 0,
    failure_window_started_at=None,
    quarantined_until=None,
) -> TelemetrySource:
    """Register a `TelemetrySource`. The verifying key content is
    arbitrary — the verifier is mocked in the app tests.
    """
    return TelemetrySource.objects.create(
        source=source,
        source_id=source_id,
        verifying_key=verifying_key if verifying_key is not None else bytes(32),
        is_active=is_active,
        consecutive_failures=consecutive_failures,
        failure_window_started_at=failure_window_started_at,
        quarantined_until=quarantined_until,
    )


def make_envelope(
    *,
    source: str = "edge_gateway",
    source_id: str = "edge-1",
    kind: str = "edge_telemetry",
    schema_version: int = 1,
    processing_status: str = ProcessingStatus.PENDING.value,
    payload_cbor: bytes | None = None,
    received_at=None,
) -> TelemetryEnvelope:
    """Create a `TelemetryEnvelope` directly (for pull / GC tests).

    `received_at` is `auto_now_add`; when an explicit value is given
    it is written with a follow-up `update()` (GC needs aged rows).
    """
    body = payload_cbor if payload_cbor is not None else uuid.uuid4().bytes
    is_verified = processing_status != ProcessingStatus.FAILED.value
    env = TelemetryEnvelope.objects.create(
        source=source,
        source_id=source_id,
        kind=kind,
        schema_version=schema_version,
        payload_cbor=body,
        signature=b"\x00" * 64,
        dedupe_digest=hashlib.sha256(body).hexdigest() if is_verified else "",
        processing_status=processing_status,
    )
    if received_at is not None:
        TelemetryEnvelope.objects.filter(pk=env.pk).update(received_at=received_at)
        env.refresh_from_db()
    return env


def aged(days: int):
    """A timestamp `days` in the past — for GC retention tests."""
    from datetime import timedelta

    return timezone.now() - timedelta(days=days)
