"""Shared fixtures for the telemetry-broker test suite.

`fake_verifier` (autouse) swaps the `verify-*` shell-out for an
in-memory controller — the app tests run without the built Rust
binary and steer verification outcomes directly. `test_verifier.py`
exercises the real `verifier` shell-out wrapper against a fake
binary (it does not use this fixture's outcome).
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

ROOT_PRINCIPAL = "telemetry-root"


@pytest.fixture(autouse=True)
def _telemetry_settings(monkeypatch: pytest.MonkeyPatch) -> None:
    """Pin telemetry settings deterministically for every test."""
    monkeypatch.setattr(settings, "VALI_TELEMETRY_ROOT_PRINCIPAL", ROOT_PRINCIPAL)
    monkeypatch.setattr(settings, "VALI_TELEMETRY_MAX_PENDING", 100_000)
    monkeypatch.setattr(settings, "VALI_TELEMETRY_MAX_ENVELOPE_BYTES", 16384)
    monkeypatch.setattr(settings, "VALI_TELEMETRY_QUARANTINE_THRESHOLD", 3)
    monkeypatch.setattr(settings, "VALI_TELEMETRY_QUARANTINE_WINDOW_S", 300)
    monkeypatch.setattr(settings, "VALI_TELEMETRY_QUARANTINE_TTL_S", 3600)
    monkeypatch.setattr(settings, "VALI_TELEMETRY_GC_AGE_DAYS", 7)
    monkeypatch.setattr(settings, "VALI_TELEMETRY_PULL_MAX_LIMIT", 1000)


class FakeVerifier:
    """In-memory stand-in for `verifier.verify_envelope`.

    - `outcome` ∈ {"ok", "failed", "unavailable"} steers the verdict.
    - `fail_category` is the category reported on a "failed" outcome.
    - `calls` records every `(kind, body, sig)` verified.
    """

    def __init__(self) -> None:
        self.outcome = "ok"
        self.fail_category = "signature"
        self.calls: list[tuple[str, bytes, bytes]] = []

    def verify_envelope(
        self, *, kind: str, body: bytes, sig: bytes, verifying_key: bytes
    ) -> None:
        self.calls.append((kind, bytes(body), bytes(sig)))
        if self.outcome == "ok":
            return
        if self.outcome == "unavailable":
            raise verifier.VerifierUnavailable("injected unavailable")
        raise verifier.VerifierFailed(
            message="injected verification failure",
            category=self.fail_category,
        )


@pytest.fixture(autouse=True)
def fake_verifier(monkeypatch: pytest.MonkeyPatch) -> FakeVerifier:
    """Replace the verifier shell-out with `FakeVerifier`."""
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
def ingest_client() -> APIClient:
    """A ServiceToken-authenticated source (e.g. the Edge forwarder)."""
    return _bearer_client("edge-forwarder")


@pytest.fixture
def root_client() -> APIClient:
    """The telemetry-root principal — accepted by `IsTelemetryRoot`."""
    return _bearer_client(ROOT_PRINCIPAL)


def ingest_payload(**overrides: Any) -> dict[str, Any]:
    """Build a `/v1/telemetry/ingest` JSON body — happy defaults."""
    payload: dict[str, Any] = {
        "schema_version": 1,
        "source": "edge_gateway",
        "source_id": "edge-1",
        "kind": "edge_telemetry",
        "body_hex": b"telemetry-body".hex(),
        "sig_hex": "00" * 64,
    }
    payload.update(overrides)
    return payload
