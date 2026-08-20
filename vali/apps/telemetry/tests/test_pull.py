"""Tests for `GET /v1/telemetry/pull`."""

from __future__ import annotations

import pytest
from django.urls import reverse
from rest_framework import status
from rest_framework.test import APIClient

from apps.telemetry.models import ProcessingStatus, TelemetryEnvelope

from .factories import make_envelope

pytestmark = pytest.mark.django_db

PULL_URL = reverse("telemetry_pull")


def _pull(client: APIClient, *, kind: str = "edge_telemetry", since: int = 0,
          limit: int = 100):
    return client.get(
        PULL_URL, {"kind": kind, "since": since, "limit": limit}
    )


# ─── auth ────────────────────────────────────────────────────────────


def test_pull_unauthenticated_rejected() -> None:
    resp = _pull(APIClient())
    assert resp.status_code in (
        status.HTTP_401_UNAUTHORIZED,
        status.HTTP_403_FORBIDDEN,
    )


def test_pull_requires_the_root_principal(ingest_client: APIClient) -> None:
    # A non-root authenticated client cannot drain the broker.
    resp = _pull(ingest_client)
    assert resp.status_code == status.HTTP_403_FORBIDDEN


# ─── happy path ──────────────────────────────────────────────────────


def test_pull_happy_path(root_client: APIClient) -> None:
    a = make_envelope()
    b = make_envelope()
    resp = _pull(root_client)
    assert resp.status_code == status.HTTP_200_OK
    body = resp.json()
    assert body["count"] == 2
    ids = [e["envelope_id"] for e in body["envelopes"]]
    assert ids == sorted([a.envelope_id, b.envelope_id])
    assert body["next_since"] == b.envelope_id
    # The serialized envelope carries the signed payload for the
    # consumer to (optionally) re-verify.
    first = body["envelopes"][0]
    assert set(first) >= {
        "envelope_id",
        "source",
        "source_id",
        "kind",
        "schema_version",
        "payload_cbor_hex",
        "signature_hex",
        "processing_status",
    }


def test_pull_marks_drained_envelopes_done(root_client: APIClient) -> None:
    env = make_envelope()
    _pull(root_client)
    env.refresh_from_db()
    assert env.processing_status == ProcessingStatus.DONE
    assert env.processed_at is not None


def test_pull_empty_queue_returns_the_cursor_unchanged(
    root_client: APIClient,
) -> None:
    resp = _pull(root_client, since=42)
    assert resp.status_code == status.HTTP_200_OK
    assert resp.json()["count"] == 0
    assert resp.json()["next_since"] == 42


# ─── cursor + drain semantics ────────────────────────────────────────


def test_pull_cursor_advances_and_does_not_redeliver(
    root_client: APIClient,
) -> None:
    make_envelope()
    make_envelope()
    first = _pull(root_client, since=0).json()
    assert first["count"] == 2
    # Re-pulling from the advanced cursor yields nothing …
    second = _pull(root_client, since=first["next_since"]).json()
    assert second["count"] == 0
    # … and even re-pulling from the ORIGINAL cursor yields nothing,
    # because the drained rows are no longer `Pending`.
    third = _pull(root_client, since=0).json()
    assert third["count"] == 0


def test_concurrent_pulls_never_double_deliver(root_client: APIClient) -> None:
    for _ in range(6):
        make_envelope()
    # Two pulls from the SAME cursor — each claims a disjoint batch.
    first = _pull(root_client, since=0, limit=3).json()
    second = _pull(root_client, since=0, limit=3).json()
    ids_first = {e["envelope_id"] for e in first["envelopes"]}
    ids_second = {e["envelope_id"] for e in second["envelopes"]}
    assert len(ids_first) == 3
    assert len(ids_second) == 3
    # No envelope appears in both pulls; together they cover all six.
    assert ids_first.isdisjoint(ids_second)
    assert len(ids_first | ids_second) == 6


# ─── filtering ───────────────────────────────────────────────────────


def test_pull_filters_by_kind(root_client: APIClient) -> None:
    edge = make_envelope(kind="edge_telemetry")
    make_envelope(kind="served_receipt", source="tenant_vm", source_id="vm-1")
    resp = _pull(root_client, kind="edge_telemetry")
    ids = [e["envelope_id"] for e in resp.json()["envelopes"]]
    assert ids == [edge.envelope_id]


def test_pull_excludes_non_pending_envelopes(root_client: APIClient) -> None:
    make_envelope(processing_status=ProcessingStatus.DONE.value)
    make_envelope(processing_status=ProcessingStatus.FAILED.value)
    make_envelope(processing_status=ProcessingStatus.QUARANTINED.value)
    pending = make_envelope(processing_status=ProcessingStatus.PENDING.value)
    resp = _pull(root_client)
    ids = [e["envelope_id"] for e in resp.json()["envelopes"]]
    assert ids == [pending.envelope_id]


def test_pull_limit_caps_the_page(root_client: APIClient) -> None:
    for _ in range(5):
        make_envelope()
    resp = _pull(root_client, limit=2)
    assert resp.json()["count"] == 2
    # The remaining three are still Pending.
    assert (
        TelemetryEnvelope.objects.filter(
            processing_status=ProcessingStatus.PENDING
        ).count()
        == 3
    )


def test_pull_missing_kind_is_rejected(root_client: APIClient) -> None:
    resp = root_client.get(PULL_URL, {"since": 0})
    assert resp.status_code == status.HTTP_400_BAD_REQUEST
    assert resp.json()["category"] == "wire"
