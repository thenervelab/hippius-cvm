"""Integration tests for `POST /v1/order_ticket`.

These tests use Django's test client + DRF's `APIClient` to hit the
view through the full middleware/auth/parser stack. The Rust
validator is mocked at the `validator.validate_ticket` boundary so
the suite runs without a Cargo build.
"""

from __future__ import annotations

import subprocess
from collections.abc import Iterator
from pathlib import Path

import pytest
from django.conf import settings
from django.urls import reverse
from rest_framework import status
from rest_framework.test import APIClient

from apps.identity.models import (
    PrincipalScope,
    ServiceClient,
    ServiceToken,
    TokenLifetime,
)
from apps.orders import validator
from apps.orders.models import OrderTicketIntake
from apps.orders.tests.test_validator import _ok_payload, _stub_completed

pytestmark = pytest.mark.django_db


# ────────────────────────────────────────────────────────────────────
# Fixtures
# ────────────────────────────────────────────────────────────────────


@pytest.fixture
def fake_binary(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> Iterator[Path]:
    fake = tmp_path / "hippius-ticket-validator"
    fake.write_text("# placeholder\n")
    fake.chmod(0o755)
    monkeypatch.setattr(settings, "VALI_TICKET_VALIDATOR_BIN", str(fake))
    yield fake


@pytest.fixture
def client_principal() -> ServiceClient:
    return ServiceClient.objects.create(
        scope=PrincipalScope.OPERATOR.value,
        name="l1-prod",
        description="L1 minter",
    )


@pytest.fixture
def bearer_token(client_principal: ServiceClient) -> str:
    _row, plaintext = ServiceToken.issue(
        client=client_principal,
        name="l1-prod-token",
        lifetime=TokenLifetime.OPS.value,
    )
    return plaintext


@pytest.fixture
def authed_client(bearer_token: str) -> APIClient:
    c = APIClient()
    c.credentials(HTTP_AUTHORIZATION=f"Bearer {bearer_token}")
    return c


# ────────────────────────────────────────────────────────────────────
# Tests
# ────────────────────────────────────────────────────────────────────


def test_unauthenticated_request_is_rejected(fake_binary: Path) -> None:
    c = APIClient()
    resp = c.post(
        reverse("order_ticket_intake"),
        data=b"any-bytes",
        content_type="application/cose-sign1",
    )
    assert resp.status_code in (status.HTTP_401_UNAUTHORIZED, status.HTTP_403_FORBIDDEN)


def test_valid_ticket_is_created_and_persisted(
    monkeypatch: pytest.MonkeyPatch,
    fake_binary: Path,
    authed_client: APIClient,
    client_principal: ServiceClient,
) -> None:
    import json

    payload = _ok_payload(ticket_id="tk-fresh-1")
    monkeypatch.setattr(
        subprocess,
        "run",
        lambda *a, **kw: _stub_completed(json.dumps(payload).encode(), 0),
    )

    body = b"cose-blob-bytes-deterministic"
    resp = authed_client.post(
        reverse("order_ticket_intake"),
        data=body,
        content_type="application/cose-sign1",
    )
    assert resp.status_code == status.HTTP_201_CREATED, resp.content
    assert resp.json()["ticket_id"] == "tk-fresh-1"
    assert resp.json()["created"] is True

    obj = OrderTicketIntake.objects.get(ticket_id="tk-fresh-1")
    # The COSE blob is stored byte-exact for opaque re-transmission
    # to the KBS — the persisted bytes MUST equal the wire bytes.
    assert bytes(obj.cose_blob) == body
    assert obj.received_from == client_principal.name
    assert obj.vm_generation == 5


def test_idempotent_replay_returns_200_not_409(
    monkeypatch: pytest.MonkeyPatch,
    fake_binary: Path,
    authed_client: APIClient,
) -> None:
    import json

    payload = _ok_payload(ticket_id="tk-idem-1")
    monkeypatch.setattr(
        subprocess,
        "run",
        lambda *a, **kw: _stub_completed(json.dumps(payload).encode(), 0),
    )
    body = b"cose-blob-bytes-A"

    r1 = authed_client.post(
        reverse("order_ticket_intake"),
        data=body,
        content_type="application/cose-sign1",
    )
    r2 = authed_client.post(
        reverse("order_ticket_intake"),
        data=body,  # IDENTICAL bytes
        content_type="application/cose-sign1",
    )
    assert r1.status_code == status.HTTP_201_CREATED
    assert r2.status_code == status.HTTP_200_OK
    assert r2.json()["created"] is False
    # Exactly one row persisted — idempotency does not duplicate.
    assert OrderTicketIntake.objects.filter(ticket_id="tk-idem-1").count() == 1


def test_ticket_id_reuse_with_different_bytes_is_409(
    monkeypatch: pytest.MonkeyPatch,
    fake_binary: Path,
    authed_client: APIClient,
) -> None:
    import json

    payload = _ok_payload(ticket_id="tk-conflict-1")
    monkeypatch.setattr(
        subprocess,
        "run",
        lambda *a, **kw: _stub_completed(json.dumps(payload).encode(), 0),
    )

    r1 = authed_client.post(
        reverse("order_ticket_intake"),
        data=b"cose-blob-A",
        content_type="application/cose-sign1",
    )
    r2 = authed_client.post(
        reverse("order_ticket_intake"),
        data=b"cose-blob-B-DIFFERENT",
        content_type="application/cose-sign1",
    )
    assert r1.status_code == status.HTTP_201_CREATED
    assert r2.status_code == status.HTTP_409_CONFLICT
    assert r2.json()["category"] == "replay-conflict"


def test_oversized_body_is_413(
    fake_binary: Path, authed_client: APIClient
) -> None:
    big = b"\x00" * (settings.VALI_TICKET_MAX_BYTES + 1)
    resp = authed_client.post(
        reverse("order_ticket_intake"),
        data=big,
        content_type="application/cose-sign1",
    )
    assert resp.status_code == status.HTTP_413_REQUEST_ENTITY_TOO_LARGE


def test_empty_body_is_400(
    fake_binary: Path, authed_client: APIClient
) -> None:
    resp = authed_client.post(
        reverse("order_ticket_intake"),
        data=b"",
        content_type="application/cose-sign1",
    )
    assert resp.status_code == status.HTTP_400_BAD_REQUEST
    assert resp.json()["category"] == "wire"


def test_validator_rejection_surfaces_as_400_with_category(
    monkeypatch: pytest.MonkeyPatch,
    fake_binary: Path,
    authed_client: APIClient,
) -> None:
    def _raise(*_a, **_kw):
        raise validator.ValidatorFailed(message="bad sig", category="cose-parse")

    monkeypatch.setattr(validator, "validate_ticket", _raise)
    resp = authed_client.post(
        reverse("order_ticket_intake"),
        data=b"anything",
        content_type="application/cose-sign1",
    )
    assert resp.status_code == status.HTTP_400_BAD_REQUEST
    assert resp.json()["category"] == "cose-parse"


def test_validator_unavailable_surfaces_as_503(
    monkeypatch: pytest.MonkeyPatch,
    fake_binary: Path,
    authed_client: APIClient,
) -> None:
    def _raise(*_a, **_kw):
        raise validator.ValidatorUnavailable("binary missing")

    monkeypatch.setattr(validator, "validate_ticket", _raise)
    resp = authed_client.post(
        reverse("order_ticket_intake"),
        data=b"anything",
        content_type="application/cose-sign1",
    )
    assert resp.status_code == status.HTTP_503_SERVICE_UNAVAILABLE
    assert resp.json()["category"] == "internal"


def test_healthz_unauthenticated() -> None:
    """Liveness probe must be reachable without auth (LB needs it)."""
    c = APIClient()
    resp = c.get("/healthz")
    assert resp.status_code == status.HTTP_200_OK
    assert resp.json() == {"status": "ok"}
