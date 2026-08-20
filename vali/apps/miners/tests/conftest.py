"""Shared fixtures for the miner-registry test suite.

`_miner_settings` (autouse) pins the miner-admin principal. `FakeVerifier`
+ the `fake_verifier` fixture stand in for the telemetry `verify-*`
shell-out — the miner→telemetry binding tests steer verification
without the built Rust binary.
"""

from __future__ import annotations

from typing import Any

import pytest
from django.conf import settings
from rest_framework.test import APIClient

from apps.identity.models import (
    PrincipalScope,
    ServiceClient,
    ServiceToken,
    TokenLifetime,
)
from apps.telemetry import verifier

ADMIN_PRINCIPAL = "miner-admin"


@pytest.fixture(autouse=True)
def _miner_settings(monkeypatch: pytest.MonkeyPatch) -> None:
    """Pin the miner-admin principal deterministically for every test."""
    monkeypatch.setattr(settings, "VALI_MINER_ADMIN_PRINCIPAL", ADMIN_PRINCIPAL)


class FakeVerifier:
    """In-memory stand-in for `telemetry.verifier.verify_envelope`.

    `outcome` ∈ {"ok", "failed", "unavailable"} steers the verdict —
    mirrors `apps/telemetry/tests/conftest.py`'s fake so the binding
    tests run without the built Rust verifier.
    """

    def __init__(self) -> None:
        self.outcome = "ok"

    def verify_envelope(
        self, *, kind: str, body: bytes, sig: bytes, verifying_key: bytes
    ) -> None:
        if self.outcome == "ok":
            return
        if self.outcome == "unavailable":
            raise verifier.VerifierUnavailable("injected unavailable")
        raise verifier.VerifierFailed(
            message="injected verification failure", category="signature"
        )


@pytest.fixture
def fake_verifier(monkeypatch: pytest.MonkeyPatch) -> FakeVerifier:
    """Replace the telemetry verifier shell-out with `FakeVerifier`."""
    fake = FakeVerifier()
    monkeypatch.setattr(verifier, "verify_envelope", fake.verify_envelope)
    return fake


def _bearer_client(name: str) -> APIClient:
    client = ServiceClient.objects.create(scope=PrincipalScope.OPERATOR.value, name=name)
    _row, plaintext = ServiceToken.issue(
        client=client,
        name="ops",
        lifetime=TokenLifetime.OPS.value,
    )
    api = APIClient()
    api.credentials(HTTP_AUTHORIZATION=f"Bearer {plaintext}")
    return api


@pytest.fixture
def admin_client() -> APIClient:
    """The miner-admin principal — accepted by `IsMinerAdmin`."""
    return _bearer_client(ADMIN_PRINCIPAL)


@pytest.fixture
def plain_client() -> APIClient:
    """An authenticated but non-admin `ServiceClient` (sentinel / ops)."""
    return _bearer_client("sentinel-reader")


def register_payload(**overrides: Any) -> dict[str, Any]:
    """Build a `POST /v1/admin/miner/register` JSON body — happy defaults."""
    payload: dict[str, Any] = {
        "miner_id": "miner-1",
        "pubkey_hex": "ab" * 32,
        "platform_id": "amd-chipid-0001",
    }
    payload.update(overrides)
    return payload
