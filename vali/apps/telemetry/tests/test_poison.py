"""Tests for the §9 poison-message quarantine flow."""

from __future__ import annotations

from datetime import timedelta

import pytest
from django.urls import reverse
from django.utils import timezone
from rest_framework import status
from rest_framework.test import APIClient

from apps.telemetry.models import ProcessingStatus, TelemetryEnvelope, TelemetrySource

from .conftest import FakeVerifier, ingest_payload
from .factories import make_source

pytestmark = pytest.mark.django_db

INGEST_URL = reverse("telemetry_ingest")


def _ingest(client: APIClient, **overrides):
    return client.post(INGEST_URL, ingest_payload(**overrides), format="json")


# ─── the 3-strike quarantine ─────────────────────────────────────────


def test_three_consecutive_failures_quarantine_the_source(
    ingest_client: APIClient, fake_verifier: FakeVerifier
) -> None:
    make_source(source="edge_gateway", source_id="edge-1")
    fake_verifier.outcome = "failed"

    # Three consecutive verification failures (threshold = 3).
    for i in range(3):
        resp = _ingest(ingest_client, body_hex=f"bad-{i}".encode().hex())
        assert resp.status_code == status.HTTP_400_BAD_REQUEST

    src = TelemetrySource.objects.get(source="edge_gateway", source_id="edge-1")
    assert src.consecutive_failures == 3
    assert src.quarantined_until is not None and src.quarantined_until > timezone.now()

    # The next ingest is refused outright — 429, with Retry-After,
    # without even spending a verify.
    fake_verifier.calls.clear()
    resp = _ingest(ingest_client, body_hex=b"after".hex())
    assert resp.status_code == status.HTTP_429_TOO_MANY_REQUESTS
    assert resp.json()["category"] == "source-quarantined"
    assert "Retry-After" in resp.headers
    assert fake_verifier.calls == []  # not verified — refused before


def test_quarantined_source_is_refused_until_the_ttl_expires(
    ingest_client: APIClient,
) -> None:
    # A source already quarantined (TTL still in the future).
    make_source(
        source="edge_gateway",
        source_id="edge-1",
        quarantined_until=timezone.now() + timedelta(hours=1),
    )
    resp = _ingest(ingest_client)
    assert resp.status_code == status.HTTP_429_TOO_MANY_REQUESTS

    # An expired quarantine no longer blocks ingestion.
    TelemetrySource.objects.filter(source="edge_gateway", source_id="edge-1").update(
        quarantined_until=timezone.now() - timedelta(seconds=10)
    )
    resp = _ingest(ingest_client)
    assert resp.status_code == status.HTTP_202_ACCEPTED


# ─── consecutive-ness ────────────────────────────────────────────────


def test_a_success_resets_the_failure_counter(
    ingest_client: APIClient, fake_verifier: FakeVerifier
) -> None:
    make_source(source="edge_gateway", source_id="edge-1")

    fake_verifier.outcome = "failed"
    _ingest(ingest_client, body_hex=b"bad-1".hex())
    _ingest(ingest_client, body_hex=b"bad-2".hex())
    src = TelemetrySource.objects.get(source="edge_gateway", source_id="edge-1")
    assert src.consecutive_failures == 2

    # A verified envelope breaks the run.
    fake_verifier.outcome = "ok"
    assert _ingest(ingest_client, body_hex=b"good".hex()).status_code == 202
    src.refresh_from_db()
    assert src.consecutive_failures == 0

    # Two more failures — counter is 2, NOT 4: the source is not
    # quarantined (the success reset the consecutive run).
    fake_verifier.outcome = "failed"
    _ingest(ingest_client, body_hex=b"bad-3".hex())
    _ingest(ingest_client, body_hex=b"bad-4".hex())
    src.refresh_from_db()
    assert src.consecutive_failures == 2
    assert src.quarantined_until is None


def test_failures_outside_the_window_restart_the_count(
    ingest_client: APIClient, fake_verifier: FakeVerifier
) -> None:
    # A source with 2 strikes whose window opened long ago.
    make_source(
        source="edge_gateway",
        source_id="edge-1",
        consecutive_failures=2,
        failure_window_started_at=timezone.now() - timedelta(hours=1),
    )
    fake_verifier.outcome = "failed"
    _ingest(ingest_client, body_hex=b"late".hex())

    # The stale window reset — the new failure is strike 1, not 3,
    # so the source is NOT quarantined.
    src = TelemetrySource.objects.get(source="edge_gateway", source_id="edge-1")
    assert src.consecutive_failures == 1
    assert src.quarantined_until is None


# ─── reclassification ────────────────────────────────────────────────


def test_quarantine_reclassifies_the_sources_pending_envelopes(
    ingest_client: APIClient, fake_verifier: FakeVerifier
) -> None:
    make_source(source="edge_gateway", source_id="edge-1")

    # Two genuine envelopes land first — queued `Pending`.
    fake_verifier.outcome = "ok"
    _ingest(ingest_client, body_hex=b"good-1".hex())
    _ingest(ingest_client, body_hex=b"good-2".hex())
    assert (
        TelemetryEnvelope.objects.filter(
            processing_status=ProcessingStatus.PENDING
        ).count()
        == 2
    )

    # Then the source goes bad and crosses the quarantine threshold.
    fake_verifier.outcome = "failed"
    for i in range(3):
        _ingest(ingest_client, body_hex=f"bad-{i}".encode().hex())

    # Its still-queued Pending envelopes are pulled out of the
    # deliverable queue — the source is no longer trusted.
    assert (
        TelemetryEnvelope.objects.filter(
            processing_status=ProcessingStatus.PENDING
        ).count()
        == 0
    )
    assert (
        TelemetryEnvelope.objects.filter(
            processing_status=ProcessingStatus.QUARANTINED
        ).count()
        == 2
    )
