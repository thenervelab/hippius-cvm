"""Tests for `GET /v1/admin/miner/list`."""

from __future__ import annotations

import pytest
from django.urls import reverse
from rest_framework.test import APIClient

from .conftest import register_payload

pytestmark = pytest.mark.django_db

REGISTER_URL = reverse("miner_register")
LIST_URL = reverse("miner_list")


def _register_n(admin_client: APIClient, n: int) -> None:
    """Register `n` distinct miners — `miner-000`, `miner-001`, …"""
    for i in range(n):
        resp = admin_client.post(
            REGISTER_URL,
            register_payload(
                miner_id=f"miner-{i:03d}",
                pubkey_hex=f"{i:02x}" * 32,
                platform_id=f"plat-{i:03d}",
            ),
            format="json",
        )
        assert resp.status_code == 201, resp.content


def test_list_returns_registered_miners(admin_client: APIClient) -> None:
    _register_n(admin_client, 3)
    resp = admin_client.get(LIST_URL)
    assert resp.status_code == 200
    body = resp.json()
    assert body["count"] == 3
    # Ordered by miner_id.
    assert [m["miner_id"] for m in body["miners"]] == [
        "miner-000",
        "miner-001",
        "miner-002",
    ]


def test_list_paginates_with_limit_and_offset(admin_client: APIClient) -> None:
    _register_n(admin_client, 5)
    resp = admin_client.get(LIST_URL, {"limit": 2, "offset": 2})
    assert resp.status_code == 200
    body = resp.json()
    # `count` is the total registry size, not the page size.
    assert body["count"] == 5
    assert body["limit"] == 2
    assert body["offset"] == 2
    assert [m["miner_id"] for m in body["miners"]] == ["miner-002", "miner-003"]


def test_list_is_open_to_any_authenticated_client(
    admin_client: APIClient, plain_client: APIClient
) -> None:
    _register_n(admin_client, 1)
    # The list endpoint is read-only — a non-admin authenticated client
    # (sentinel / ops) may call it; only register/quarantine are admin.
    resp = plain_client.get(LIST_URL)
    assert resp.status_code == 200
    assert resp.json()["count"] == 1


def test_list_unauthenticated_is_rejected() -> None:
    resp = APIClient().get(LIST_URL)
    assert resp.status_code in (401, 403)


def test_list_rejects_a_non_integer_limit(admin_client: APIClient) -> None:
    resp = admin_client.get(LIST_URL, {"limit": "lots"})
    assert resp.status_code == 400
    assert resp.json()["category"] == "wire"
