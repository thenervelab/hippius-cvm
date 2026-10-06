"""Tests for the miner-registry ↔ §9 telemetry-broker binding.

Registering a miner provisions its `TelemetrySource`, so the broker's
fail-closed ingest path accepts that miner's signed envelopes; a
verified miner envelope refreshes `last_seen_at`; quarantining a miner
makes the broker refuse it. Tenant-signed `served_receipt`s are a
separate trust plane and are NOT gated by this registry.
"""

from __future__ import annotations

from typing import Any

import pytest
from django.urls import reverse
from rest_framework.test import APIClient

from apps.miners.models import MinerIdentity
from apps.telemetry.models import TelemetrySource

from .conftest import FakeVerifier, register_payload

pytestmark = pytest.mark.django_db

REGISTER_URL = reverse("miner_register")
INGEST_URL = reverse("telemetry_ingest")


def _ingest_body(source: str, source_id: str) -> dict[str, Any]:
    """A `/v1/telemetry/ingest` body for a `served_receipt` envelope."""
    return {
        "schema_version": 1,
        "source": source,
        "source_id": source_id,
        "kind": "served_receipt",
        "body_hex": b"miner-telemetry-body".hex(),
        "sig_hex": "00" * 64,
    }


def test_registered_miner_telemetry_is_accepted_and_bumps_last_seen(
    admin_client: APIClient, plain_client: APIClient, fake_verifier: FakeVerifier
) -> None:
    admin_client.post(REGISTER_URL, register_payload(), format="json")
    miner = MinerIdentity.objects.get(miner_id="miner-a")
    assert miner.last_seen_at is None

    resp = plain_client.post(
        INGEST_URL, _ingest_body("miner", "miner-a"), format="json"
    )
    assert resp.status_code == 202, resp.content

    # A verified miner-sourced envelope refreshed the fleet liveness.
    miner.refresh_from_db()
    assert miner.last_seen_at is not None


def test_unregistered_miner_telemetry_is_rejected(
    plain_client: APIClient, fake_verifier: FakeVerifier
) -> None:
    # No MinerIdentity ⇒ no linked TelemetrySource ⇒ fail-closed.
    resp = plain_client.post(
        INGEST_URL, _ingest_body("miner", "ghost-miner"), format="json"
    )
    assert resp.status_code == 403
    assert resp.json()["category"] == "source-not-registered"


def test_quarantined_miner_telemetry_is_rejected_and_last_seen_untouched(
    admin_client: APIClient, plain_client: APIClient, fake_verifier: FakeVerifier
) -> None:
    admin_client.post(REGISTER_URL, register_payload(), format="json")
    admin_client.post(
        reverse("miner_quarantine", args=["miner-a"])
    )

    resp = plain_client.post(
        INGEST_URL, _ingest_body("miner", "miner-a"), format="json"
    )
    # Quarantine deactivated the linked source ⇒ ingest 403; the
    # rejected envelope never reaches the last_seen_at hook.
    assert resp.status_code == 403
    miner = MinerIdentity.objects.get(miner_id="miner-a")
    assert miner.last_seen_at is None


def test_deduplicated_miner_envelope_does_not_rebump_last_seen(
    admin_client: APIClient, plain_client: APIClient, fake_verifier: FakeVerifier
) -> None:
    admin_client.post(REGISTER_URL, register_payload(), format="json")
    body = _ingest_body("miner", "miner-a")

    first = plain_client.post(INGEST_URL, body, format="json")
    assert first.status_code == 202
    seen_after_first = MinerIdentity.objects.get(
        miner_id="miner-a"
    ).last_seen_at
    assert seen_after_first is not None

    # Re-ingesting the byte-identical envelope is deduplicated (200,
    # created=False) — a replay is not fresh telemetry, so last_seen_at
    # must NOT advance.
    second = plain_client.post(INGEST_URL, body, format="json")
    assert second.status_code == 200
    assert second.json()["created"] is False
    seen_after_replay = MinerIdentity.objects.get(
        miner_id="miner-a"
    ).last_seen_at
    assert seen_after_replay == seen_after_first


def test_tenant_served_receipt_is_independent_of_the_miner_registry(
    plain_client: APIClient, fake_verifier: FakeVerifier
) -> None:
    # A tenant-signed served_receipt is a SEPARATE trust plane: its
    # TelemetrySource is provisioned out-of-band with NO MinerIdentity.
    # The miner registry must not gate it.
    TelemetrySource.objects.create(
        source="tenant_vm",
        source_id="vm-42",
        verifying_key=bytes.fromhex("cd" * 32),
        is_active=True,
    )
    resp = plain_client.post(
        INGEST_URL, _ingest_body("tenant_vm", "vm-42"), format="json"
    )
    assert resp.status_code == 202, resp.content
    assert MinerIdentity.objects.count() == 0
