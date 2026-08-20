"""Tests for `POST /v1/telemetry/ingest`."""

from __future__ import annotations

import pytest
from django.conf import settings
from django.urls import reverse
from rest_framework import status
from rest_framework.test import APIClient

from apps.telemetry.models import ProcessingStatus, TelemetryEnvelope

from .conftest import FakeVerifier, ingest_payload
from .factories import make_envelope, make_source

pytestmark = pytest.mark.django_db

INGEST_URL = reverse("telemetry_ingest")


# ─── auth ────────────────────────────────────────────────────────────


def test_ingest_unauthenticated_rejected() -> None:
    resp = APIClient().post(INGEST_URL, ingest_payload(), format="json")
    assert resp.status_code in (
        status.HTTP_401_UNAUTHORIZED,
        status.HTTP_403_FORBIDDEN,
    )


# ─── happy path ──────────────────────────────────────────────────────


def test_ingest_happy_path(
    ingest_client: APIClient, fake_verifier: FakeVerifier
) -> None:
    make_source(source="edge_gateway", source_id="edge-1")
    resp = ingest_client.post(INGEST_URL, ingest_payload(), format="json")
    assert resp.status_code == status.HTTP_202_ACCEPTED, resp.content
    body = resp.json()
    assert body["created"] is True
    assert body["processing_status"] == ProcessingStatus.PENDING.value
    env = TelemetryEnvelope.objects.get(envelope_id=body["envelope_id"])
    assert env.processing_status == ProcessingStatus.PENDING
    assert env.kind == "edge_telemetry"
    assert bytes(env.payload_cbor) == b"telemetry-body"
    # The verifier was invoked with the decoded body.
    assert fake_verifier.calls == [
        ("edge_telemetry", b"telemetry-body", bytes(64))
    ]


def test_ingest_served_receipt_kind(ingest_client: APIClient) -> None:
    make_source(source="tenant_vm", source_id="vm-7")
    resp = ingest_client.post(
        INGEST_URL,
        ingest_payload(source="tenant_vm", source_id="vm-7", kind="served_receipt"),
        format="json",
    )
    assert resp.status_code == status.HTTP_202_ACCEPTED, resp.content


# ─── schema versioning ───────────────────────────────────────────────


def test_ingest_unknown_schema_version_is_rejected(
    ingest_client: APIClient,
) -> None:
    make_source(source="edge_gateway", source_id="edge-1")
    resp = ingest_client.post(
        INGEST_URL, ingest_payload(schema_version=999), format="json"
    )
    assert resp.status_code == status.HTTP_400_BAD_REQUEST
    assert resp.json()["category"] == "schema-version"
    # Fail-closed: nothing stored.
    assert TelemetryEnvelope.objects.count() == 0


# ─── source registry ─────────────────────────────────────────────────


def test_ingest_unregistered_source_is_rejected(
    ingest_client: APIClient,
) -> None:
    # No TelemetrySource row — no trusted key, so nothing is verified.
    resp = ingest_client.post(INGEST_URL, ingest_payload(), format="json")
    assert resp.status_code == status.HTTP_403_FORBIDDEN
    assert resp.json()["category"] == "source-not-registered"


def test_ingest_inactive_source_is_rejected(ingest_client: APIClient) -> None:
    make_source(source="edge_gateway", source_id="edge-1", is_active=False)
    resp = ingest_client.post(INGEST_URL, ingest_payload(), format="json")
    assert resp.status_code == status.HTTP_403_FORBIDDEN
    assert resp.json()["category"] == "source-not-registered"


# ─── wire validation ─────────────────────────────────────────────────


def test_ingest_unknown_kind_is_rejected(ingest_client: APIClient) -> None:
    make_source(source="edge_gateway", source_id="edge-1")
    resp = ingest_client.post(
        INGEST_URL, ingest_payload(kind="bogus"), format="json"
    )
    assert resp.status_code == status.HTTP_400_BAD_REQUEST
    assert resp.json()["category"] == "wire"


def test_ingest_missing_field_is_rejected(ingest_client: APIClient) -> None:
    payload = ingest_payload()
    del payload["body_hex"]
    resp = ingest_client.post(INGEST_URL, payload, format="json")
    assert resp.status_code == status.HTTP_400_BAD_REQUEST
    assert resp.json()["category"] == "wire"


def test_ingest_bad_hex_is_rejected(ingest_client: APIClient) -> None:
    make_source(source="edge_gateway", source_id="edge-1")
    resp = ingest_client.post(
        INGEST_URL, ingest_payload(body_hex="zznothex"), format="json"
    )
    assert resp.status_code == status.HTTP_400_BAD_REQUEST
    assert resp.json()["category"] == "wire"


def test_ingest_wrong_signature_length_is_rejected(
    ingest_client: APIClient,
) -> None:
    make_source(source="edge_gateway", source_id="edge-1")
    resp = ingest_client.post(
        INGEST_URL, ingest_payload(sig_hex="00" * 10), format="json"
    )
    assert resp.status_code == status.HTTP_400_BAD_REQUEST
    assert resp.json()["category"] == "wire"


def test_ingest_oversize_body_is_rejected(ingest_client: APIClient) -> None:
    make_source(source="edge_gateway", source_id="edge-1")
    huge = b"\x00" * (16384 + 1)
    resp = ingest_client.post(
        INGEST_URL, ingest_payload(body_hex=huge.hex()), format="json"
    )
    assert resp.status_code == status.HTTP_413_REQUEST_ENTITY_TOO_LARGE
    assert resp.json()["category"] == "too-large"


# ─── verification outcomes ───────────────────────────────────────────


def test_ingest_verification_failure_records_a_failed_envelope(
    ingest_client: APIClient, fake_verifier: FakeVerifier
) -> None:
    src = make_source(source="edge_gateway", source_id="edge-1")
    fake_verifier.outcome = "failed"
    resp = ingest_client.post(INGEST_URL, ingest_payload(), format="json")
    assert resp.status_code == status.HTTP_400_BAD_REQUEST
    assert resp.json()["category"] == "verify-failed"
    # The bad envelope is retained for forensics as `Failed`.
    assert (
        TelemetryEnvelope.objects.filter(
            processing_status=ProcessingStatus.FAILED
        ).count()
        == 1
    )
    # A §9 poison strike was counted.
    src.refresh_from_db()
    assert src.consecutive_failures == 1


def test_ingest_verifier_unavailable_is_503_and_not_a_strike(
    ingest_client: APIClient, fake_verifier: FakeVerifier
) -> None:
    src = make_source(source="edge_gateway", source_id="edge-1")
    fake_verifier.outcome = "unavailable"
    resp = ingest_client.post(INGEST_URL, ingest_payload(), format="json")
    assert resp.status_code == status.HTTP_503_SERVICE_UNAVAILABLE
    assert resp.json()["category"] == "internal"
    # A binary failure is vali's fault — it must NOT poison the source.
    src.refresh_from_db()
    assert src.consecutive_failures == 0


# ─── dedupe ──────────────────────────────────────────────────────────


def test_ingest_is_idempotent_for_an_identical_envelope(
    ingest_client: APIClient,
) -> None:
    make_source(source="edge_gateway", source_id="edge-1")
    first = ingest_client.post(INGEST_URL, ingest_payload(), format="json")
    second = ingest_client.post(INGEST_URL, ingest_payload(), format="json")
    assert first.status_code == status.HTTP_202_ACCEPTED
    # The re-ingest is deduplicated — 200, not-created, same row.
    assert second.status_code == status.HTTP_200_OK
    assert second.json()["created"] is False
    assert second.json()["envelope_id"] == first.json()["envelope_id"]
    assert TelemetryEnvelope.objects.count() == 1


def test_ingest_distinct_sources_sharing_a_body_are_not_deduped(
    ingest_client: APIClient,
) -> None:
    # The dedupe digest binds the source identity — two different
    # sources emitting byte-identical bodies stay separate rows.
    make_source(source="edge_gateway", source_id="edge-1")
    make_source(source="edge_gateway", source_id="edge-2")
    shared = b"identical-telemetry-body".hex()
    first = ingest_client.post(
        INGEST_URL, ingest_payload(source_id="edge-1", body_hex=shared), format="json"
    )
    second = ingest_client.post(
        INGEST_URL, ingest_payload(source_id="edge-2", body_hex=shared), format="json"
    )
    assert first.status_code == status.HTTP_202_ACCEPTED
    assert second.status_code == status.HTTP_202_ACCEPTED, second.content
    assert second.json()["created"] is True
    assert second.json()["envelope_id"] != first.json()["envelope_id"]
    assert TelemetryEnvelope.objects.count() == 2


# ─── backpressure ────────────────────────────────────────────────────


def test_ingest_backpressure_when_queue_full(
    ingest_client: APIClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(settings, "VALI_TELEMETRY_MAX_PENDING", 2)
    # Fill the GLOBAL queue across TWO sources so no single source is at its
    # per-source cap — this exercises the global gate (RA-M4 added a
    # per-source gate that fires first when ONE source fills a tiny queue).
    make_source(source="edge_gateway", source_id="edge-1")
    make_source(source="edge_gateway", source_id="edge-2")
    make_envelope(source="edge_gateway", source_id="edge-1")
    make_envelope(source="edge_gateway", source_id="edge-2")
    # edge-1 has 1 pending (< its per-source cap) but the global queue is full.
    resp = ingest_client.post(INGEST_URL, ingest_payload(), format="json")
    assert resp.status_code == status.HTTP_503_SERVICE_UNAVAILABLE
    assert resp.json()["category"] == "backpressure"
    # Backpressure tells the caller when to retry.
    assert "Retry-After" in resp.headers


def test_backpressure_ignores_non_pending_envelopes(
    ingest_client: APIClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(settings, "VALI_TELEMETRY_MAX_PENDING", 2)
    make_source(source="edge_gateway", source_id="edge-1")
    # Done / Failed envelopes do not count toward the bound.
    make_envelope(processing_status=ProcessingStatus.DONE.value)
    make_envelope(processing_status=ProcessingStatus.FAILED.value)
    resp = ingest_client.post(INGEST_URL, ingest_payload(), format="json")
    assert resp.status_code == status.HTTP_202_ACCEPTED


def test_per_source_backpressure_trips_before_the_global_cap(
    ingest_client: APIClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    # RA-M4 — a single source is capped to its own share even though the
    # GLOBAL queue has plenty of room, so it cannot flood valid envelopes.
    monkeypatch.setattr(settings, "VALI_TELEMETRY_MAX_PENDING", 100)
    monkeypatch.setattr(settings, "VALI_TELEMETRY_MAX_PENDING_PER_SOURCE", 2)
    make_source(source="edge_gateway", source_id="edge-1")
    make_envelope(source="edge_gateway", source_id="edge-1")
    make_envelope(source="edge_gateway", source_id="edge-1")
    resp = ingest_client.post(INGEST_URL, ingest_payload(), format="json")
    assert resp.status_code == status.HTTP_503_SERVICE_UNAVAILABLE
    assert resp.json()["category"] == "backpressure-source"
    assert "Retry-After" in resp.headers


def test_per_source_backpressure_does_not_starve_other_sources(
    ingest_client: APIClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    # RA-M4 — one source over its per-source quota must NOT 503 a DIFFERENT
    # source's ingest (the whole point: no cross-source starvation).
    monkeypatch.setattr(settings, "VALI_TELEMETRY_MAX_PENDING", 100)
    monkeypatch.setattr(settings, "VALI_TELEMETRY_MAX_PENDING_PER_SOURCE", 2)
    # edge-1 is over its own cap …
    make_source(source="edge_gateway", source_id="edge-1")
    make_envelope(source="edge_gateway", source_id="edge-1")
    make_envelope(source="edge_gateway", source_id="edge-1")
    # … but edge-2 (empty) still gets accepted (global queue under cap).
    make_source(source="edge_gateway", source_id="edge-2")
    resp = ingest_client.post(
        INGEST_URL, ingest_payload(source_id="edge-2"), format="json"
    )
    assert resp.status_code == status.HTTP_202_ACCEPTED
