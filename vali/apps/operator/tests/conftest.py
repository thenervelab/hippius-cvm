"""Fixtures for the operator node-status suite. Node ids, chip ids and
measurements are synthetic (`format(seed, "064x")`)."""

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


@pytest.fixture(autouse=True)
def _operator_settings(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "VALI_SCHEDULER_DEFAULT_CAPACITY_SLOTS", 4)


def _bearer_client(name: str, scope: str, tenant_id: str = "") -> APIClient:
    client = ServiceClient.objects.create(scope=scope, name=name, tenant_id=tenant_id)
    _row, plaintext = ServiceToken.issue(
        client=client, name="ops", lifetime=TokenLifetime.OPS.value
    )
    api = APIClient()
    api.credentials(HTTP_AUTHORIZATION=f"Bearer {plaintext}")
    return api


@pytest.fixture
def operator_client() -> APIClient:
    """The upstream product API's principal — operator-scoped."""
    return _bearer_client("upstream-api", PrincipalScope.OPERATOR.value)


@pytest.fixture
def tenant_client() -> APIClient:
    """A tenant-scoped principal — must be refused (operator-only surface)."""
    return _bearer_client("portal-a", PrincipalScope.TENANT.value, tenant_id="tenant-a")
