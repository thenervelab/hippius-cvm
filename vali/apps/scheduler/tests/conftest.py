"""Shared fixtures for the scheduler test suite."""

from __future__ import annotations

import pytest
from django.conf import settings
from rest_framework.test import APIClient

from apps.identity.models import (
    PrincipalScope,
    ServiceClient,
    ServiceToken,
    TokenLifetime,
)

# The principal `IsRootClient` accepts for /bind + /fail in tests.
ROOT_PRINCIPAL = "scheduler-root"


@pytest.fixture(autouse=True)
def _scheduler_settings(monkeypatch: pytest.MonkeyPatch) -> None:
    """Pin scheduler settings deterministically for every test.

    The `read-miner-status` shell-out is mocked in the view + reeval
    suites, so `VALI_THEBRAIN_RPC_URL` only needs to be non-empty;
    the chain-wrapper suite overrides it where it matters.
    """
    monkeypatch.setattr(settings, "VALI_SCHEDULER_ROOT_PRINCIPAL", ROOT_PRINCIPAL)
    monkeypatch.setattr(settings, "VALI_SCHEDULER_MAX_EPOCH_LAG", 2)
    monkeypatch.setattr(settings, "VALI_SCHEDULER_DEFAULT_CAPACITY_SLOTS", 4)
    monkeypatch.setattr(settings, "VALI_THEBRAIN_RPC_URL", "http://thebrain.test:9933")


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
def authed_client() -> APIClient:
    """A non-root authenticated `ServiceClient` (the orchestrator)."""
    return _bearer_client("orchestrator")


@pytest.fixture
def root_client() -> APIClient:
    """The scheduler-root principal — accepted by `IsRootClient`."""
    return _bearer_client(ROOT_PRINCIPAL)
