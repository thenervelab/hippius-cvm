"""Tests for `POST /v1/admin/miner/<miner_id>/quarantine`."""

from __future__ import annotations

import pytest
from django.urls import reverse
from rest_framework.test import APIClient

from apps.miners.models import MinerIdentity
from apps.telemetry.models import TelemetrySource

from .conftest import register_payload

pytestmark = pytest.mark.django_db

REGISTER_URL = reverse("miner_register")


def _quarantine_url(miner_id: str) -> str:
    return reverse("miner_quarantine", args=[miner_id])


def test_quarantine_marks_miner_and_deactivates_its_source(
    admin_client: APIClient,
) -> None:
    admin_client.post(REGISTER_URL, register_payload(), format="json")
    resp = admin_client.post(_quarantine_url("miner-a"))
    assert resp.status_code == 200
    assert resp.json()["status"] == "quarantined"

    miner = MinerIdentity.objects.get(miner_id="miner-a")
    assert miner.status == "quarantined"
    # The quarantine propagates to the linked TelemetrySource — the §9
    # broker's registered-source gate then refuses this miner.
    src = TelemetrySource.objects.get(
        source="miner", source_id="miner-a"
    )
    assert src.is_active is False


def test_quarantine_requires_the_admin_principal(
    admin_client: APIClient, plain_client: APIClient
) -> None:
    admin_client.post(REGISTER_URL, register_payload(), format="json")
    resp = plain_client.post(_quarantine_url("miner-a"))
    assert resp.status_code == 403
    # Untouched — a non-admin call changes nothing.
    assert (
        MinerIdentity.objects.get(miner_id="miner-a").status
        == "active"
    )


def test_quarantine_unknown_miner_is_404(admin_client: APIClient) -> None:
    resp = admin_client.post(_quarantine_url("ghost-miner"))
    assert resp.status_code == 404
    assert resp.json()["category"] == "not-found"


def test_quarantine_is_idempotent(admin_client: APIClient) -> None:
    admin_client.post(REGISTER_URL, register_payload(), format="json")
    first = admin_client.post(_quarantine_url("miner-a"))
    second = admin_client.post(_quarantine_url("miner-a"))
    assert first.status_code == 200
    assert second.status_code == 200
    assert second.json()["status"] == "quarantined"
