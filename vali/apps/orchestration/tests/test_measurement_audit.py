"""`GET /v1/admin/audit/measurements` — the pinned-measurement audit
ledger (#587 Phase 3). Root-only; filter by platform_id / launch_digest
/ vm_id; paginated; newest first.
"""

from __future__ import annotations

import pytest
from django.urls import reverse
from rest_framework import status
from rest_framework.test import APIClient

from apps.orchestration.models import MeasurementLedger

pytestmark = pytest.mark.django_db

AUDIT_URL = reverse("measurement_audit")


def _mk(vm_id: str, *, digest: str, platform_id: str = "", epoch: int = 1) -> None:
    MeasurementLedger.objects.create(
        vm_id=vm_id,
        launch_digest_hex=digest,
        platform_id=platform_id,
        node_id="n" * 64,
        allowlist_epoch=epoch,
        allowlist_sha256="a" * 64,
    )


def test_audit_unauthenticated_rejected() -> None:
    resp = APIClient().get(AUDIT_URL)
    assert resp.status_code in (
        status.HTTP_401_UNAUTHORIZED,
        status.HTTP_403_FORBIDDEN,
    )


def test_audit_requires_root(authed_client: APIClient) -> None:
    resp = authed_client.get(AUDIT_URL)
    assert resp.status_code in (
        status.HTTP_401_UNAUTHORIZED,
        status.HTTP_403_FORBIDDEN,
    )


def test_audit_empty(root_client: APIClient) -> None:
    resp = root_client.get(AUDIT_URL)
    assert resp.status_code == status.HTTP_200_OK
    assert resp.json() == {
        "measurements": [],
        "limit": 100,
        "offset": 0,
        "total": 0,
    }


def test_audit_lists_pinned_rows(root_client: APIClient) -> None:
    _mk("vm-1", digest="a" * 96, platform_id="chip-1", epoch=10)
    _mk("vm-2", digest="b" * 96, platform_id="chip-2", epoch=11)
    body = root_client.get(AUDIT_URL).json()
    assert body["total"] == 2
    row = body["measurements"][0]
    assert set(row.keys()) == {
        "vm_id",
        "launch_digest",
        "platform_id",
        "node_id",
        "allowlist_epoch",
        "allowlist_sha256",
        # The §22 trust class the pin used — the audit surface must show
        # whether a measurement is tenant- or host-attestor-classed.
        "measurement_class",
        "pinned_at",
    }


def test_audit_filter_by_platform_id(root_client: APIClient) -> None:
    _mk("vm-1", digest="a" * 96, platform_id="chip-1")
    _mk("vm-2", digest="b" * 96, platform_id="chip-2")
    _mk("vm-3", digest="c" * 96, platform_id="chip-1")
    body = root_client.get(AUDIT_URL, {"platform_id": "chip-1"}).json()
    assert body["total"] == 2
    assert {r["vm_id"] for r in body["measurements"]} == {"vm-1", "vm-3"}


def test_audit_filter_by_launch_digest(root_client: APIClient) -> None:
    _mk("vm-1", digest="a" * 96)
    _mk("vm-2", digest="b" * 96)
    body = root_client.get(AUDIT_URL, {"launch_digest": "b" * 96}).json()
    assert body["total"] == 1
    assert body["measurements"][0]["vm_id"] == "vm-2"


def test_audit_filter_by_vm_id(root_client: APIClient) -> None:
    _mk("vm-1", digest="a" * 96)
    _mk("vm-1", digest="b" * 96, epoch=2)  # same vm, two pins
    _mk("vm-2", digest="c" * 96)
    body = root_client.get(AUDIT_URL, {"vm_id": "vm-1"}).json()
    assert body["total"] == 2


def test_audit_pagination_and_clamp(root_client: APIClient) -> None:
    for i in range(5):
        _mk(f"vm-{i}", digest=f"{i:096x}")
    body = root_client.get(AUDIT_URL, {"limit": 2, "offset": 0}).json()
    assert body["total"] == 5
    assert body["limit"] == 2
    assert len(body["measurements"]) == 2
    # max-clamp
    assert root_client.get(AUDIT_URL, {"limit": 9999}).json()["limit"] == 500


def test_audit_bad_pagination_400(root_client: APIClient) -> None:
    resp = root_client.get(AUDIT_URL, {"limit": "abc"})
    assert resp.status_code == status.HTTP_400_BAD_REQUEST
    assert resp.json()["category"] == "bad-pagination"
