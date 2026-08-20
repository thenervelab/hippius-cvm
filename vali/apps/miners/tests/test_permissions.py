"""Tests for `apps.miners.permissions.IsMinerAdmin`.

The permission class gates the miner-admin write endpoints. These
tests pin two contracts that are easy to break in a misconfiguration:

- `VALI_MINER_ADMIN_PRINCIPAL` is `.strip()`-ed before comparison — a
  ConfigMap value with a trailing newline (a real Kubernetes quirk)
  must NOT silently 403 every legitimate caller;
- a `ServiceClient` whose `name` matches but whose `is_active` is
  false is REJECTED — disabling the principal in Django admin must
  immediately lock the endpoints.

The trailing-newline check is the symmetric pair of the `.strip()` in
`vali_identity_seed_miner_admin` — seeding strips, so the permission
must strip too.
"""

from __future__ import annotations

import pytest
from django.conf import settings
from rest_framework.test import APIRequestFactory

from apps.identity.models import PrincipalScope, ServiceClient
from apps.miners.permissions import IsMinerAdmin

pytestmark = pytest.mark.django_db


def _request(user: ServiceClient | None):
    """A DRF request with `user` attached — `IsMinerAdmin` only reads
    `request.user`, so a bare factory request is enough."""
    request = APIRequestFactory().get("/v1/admin/miner/register")
    request.user = user
    return request


def test_trailing_newline_in_setting_still_matches_a_seeded_principal(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """`VALI_MINER_ADMIN_PRINCIPAL` with a trailing newline (a known
    Kubernetes ConfigMap quirk) must still authorize a `ServiceClient`
    seeded under the stripped name — the seed command strips, so the
    permission MUST strip too. Without this, every legitimate request
    silently 403s on a deployment with a slightly-malformed value."""
    monkeypatch.setattr(settings, "VALI_MINER_ADMIN_PRINCIPAL", "miner-admin\n")
    client = ServiceClient.objects.create(scope=PrincipalScope.OPERATOR.value, name="miner-admin")
    assert IsMinerAdmin().has_permission(_request(client), view=None) is True


def test_whitespace_only_setting_fails_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A whitespace-only env value strips to empty → permission denies
    every caller, mirroring the seed command's refusal to seed an
    anonymous principal."""
    monkeypatch.setattr(settings, "VALI_MINER_ADMIN_PRINCIPAL", "   \n\t ")
    client = ServiceClient.objects.create(scope=PrincipalScope.OPERATOR.value, name="miner-admin")
    assert IsMinerAdmin().has_permission(_request(client), view=None) is False


def test_inactive_principal_is_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "VALI_MINER_ADMIN_PRINCIPAL", "miner-admin")
    client = ServiceClient.objects.create(
        scope=PrincipalScope.OPERATOR.value,
        name="miner-admin",
        is_active=False,
    )
    assert IsMinerAdmin().has_permission(_request(client), view=None) is False


def test_wrong_name_is_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "VALI_MINER_ADMIN_PRINCIPAL", "miner-admin")
    client = ServiceClient.objects.create(
        scope=PrincipalScope.OPERATOR.value,
        name="sentinel-reader",
    )
    assert IsMinerAdmin().has_permission(_request(client), view=None) is False


def test_anonymous_user_is_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    """A request without a `ServiceClient` principal (e.g. a Django
    `AnonymousUser` or `None`) MUST be refused — only `ServiceClient`
    instances are eligible callers."""
    monkeypatch.setattr(settings, "VALI_MINER_ADMIN_PRINCIPAL", "miner-admin")
    assert IsMinerAdmin().has_permission(_request(None), view=None) is False
