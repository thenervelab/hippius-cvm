"""`/v1/price-recommendations` — list + approve (→ migration) + dismiss.

The price-watch worker only RECOMMENDS; acting on a recommendation is the
manual operator step tested here. `start_migration` is mocked.
"""

from __future__ import annotations

import pytest
from django.urls import reverse
from rest_framework import status
from rest_framework.test import APIClient

from apps.scheduler.models import (
    PriceMigrationRecommendation,
    PriceRecommendationStatus,
)

from .factories import make_vm, node_id

pytestmark = pytest.mark.django_db

LIST_URL = reverse("price_recommendation_list")


def _approve_url(rec_id: str) -> str:
    return reverse("price_recommendation_approve", kwargs={"recommendation_id": rec_id})


def _dismiss_url(rec_id: str) -> str:
    return reverse("price_recommendation_dismiss", kwargs={"recommendation_id": rec_id})


def _rec(vm_id: str, *, dest: str = "", status_: str | None = None):
    from django.utils import timezone

    vm = make_vm(vm_id)
    st = status_ or PriceRecommendationStatus.PENDING.value
    # A decided state must carry decided_at (DB CHECK).
    decided_at = None if st == PriceRecommendationStatus.PENDING.value else timezone.now()
    return PriceMigrationRecommendation.objects.create(
        recommendation_id=f"rec-{vm_id}",
        vm=vm,
        current_node_id=node_id(1),
        suggested_dest_node_id=dest,
        new_price=500,
        ceiling=100,
        effective_block=150,
        status=st,
        decided_at=decided_at,
    )


# ─── GET list ────────────────────────────────────────────────────────


def test_list_returns_pending_recommendations(authed_client: APIClient) -> None:
    _rec("vm-a", dest=node_id(9))
    _rec("vm-b", status_=PriceRecommendationStatus.DISMISSED.value)
    resp = authed_client.get(LIST_URL)
    assert resp.status_code == status.HTTP_200_OK
    recs = resp.json()["recommendations"]
    assert len(recs) == 1
    assert recs[0]["vm_id"] == "vm-a"
    assert recs[0]["suggested_dest_node_id"] == node_id(9)


def test_list_filters_by_vm_id(authed_client: APIClient) -> None:
    _rec("vm-a", dest=node_id(9))
    _rec("vm-b", dest=node_id(9))
    resp = authed_client.get(LIST_URL, {"vm_id": "vm-b"})
    recs = resp.json()["recommendations"]
    assert [r["vm_id"] for r in recs] == ["vm-b"]


def test_list_requires_auth() -> None:
    resp = APIClient().get(LIST_URL)
    assert resp.status_code in (
        status.HTTP_401_UNAUTHORIZED,
        status.HTTP_403_FORBIDDEN,
    )


# ─── POST approve ────────────────────────────────────────────────────


def test_approve_starts_migration(monkeypatch, root_client: APIClient) -> None:
    rec = _rec("vm-a", dest=node_id(9))
    from apps.orchestration import service as orch

    started: list = []

    def fake_start(*, vm, dest_node_id, decided_by):
        started.append((vm.vm_id, dest_node_id, decided_by.name))
        return type("J", (), {"job_id": "job-1"})()

    monkeypatch.setattr(orch, "start_migration", fake_start)

    resp = root_client.post(_approve_url(rec.recommendation_id), {"if_version": 1}, format="json")
    assert resp.status_code == status.HTTP_200_OK, resp.content
    body = resp.json()
    assert body["migration_job_id"] == "job-1"
    assert body["recommendation"]["status"] == "approved"
    assert started == [("vm-a", node_id(9), "scheduler-root")]
    rec.refresh_from_db()
    assert rec.status == PriceRecommendationStatus.APPROVED.value
    assert rec.decided_at is not None


def test_approve_requires_root(monkeypatch, authed_client: APIClient) -> None:
    rec = _rec("vm-a", dest=node_id(9))
    resp = authed_client.post(_approve_url(rec.recommendation_id), {"if_version": 1}, format="json")
    assert resp.status_code == status.HTTP_403_FORBIDDEN


def test_approve_409_on_stale_version(root_client: APIClient) -> None:
    rec = _rec("vm-a", dest=node_id(9))
    resp = root_client.post(_approve_url(rec.recommendation_id), {"if_version": 99}, format="json")
    assert resp.status_code == status.HTTP_409_CONFLICT
    assert resp.json()["category"] == "version-conflict"


def test_approve_409_when_no_suggested_dest(root_client: APIClient) -> None:
    rec = _rec("vm-a", dest="")  # watcher found no destination
    resp = root_client.post(_approve_url(rec.recommendation_id), {"if_version": 1}, format="json")
    assert resp.status_code == status.HTTP_409_CONFLICT
    assert resp.json()["category"] == "no-destination"


def test_approve_rolls_back_when_migration_cannot_start(
    monkeypatch, root_client: APIClient
) -> None:
    rec = _rec("vm-a", dest=node_id(9))
    from apps.orchestration import service as orch

    def boom(**kw):
        raise orch.StartError("vm is not Active", "vm-not-active")

    monkeypatch.setattr(orch, "start_migration", boom)

    resp = root_client.post(_approve_url(rec.recommendation_id), {"if_version": 1}, format="json")
    assert resp.status_code == status.HTTP_409_CONFLICT
    assert resp.json()["category"] == "vm-not-active"
    rec.refresh_from_db()
    # The CAS rolled back — the recommendation is still actionable.
    assert rec.status == PriceRecommendationStatus.PENDING.value
    assert rec.version == 1


def test_approve_404_unknown(root_client: APIClient) -> None:
    resp = root_client.post(_approve_url("rec-ghost"), {"if_version": 1}, format="json")
    assert resp.status_code == status.HTTP_404_NOT_FOUND


# ─── POST dismiss ────────────────────────────────────────────────────


def test_dismiss_marks_dismissed(root_client: APIClient) -> None:
    rec = _rec("vm-a", dest=node_id(9))
    resp = root_client.post(_dismiss_url(rec.recommendation_id), {"if_version": 1}, format="json")
    assert resp.status_code == status.HTTP_200_OK
    assert resp.json()["status"] == "dismissed"
    rec.refresh_from_db()
    assert rec.status == PriceRecommendationStatus.DISMISSED.value
    assert rec.decided_at is not None


def test_dismiss_requires_root(authed_client: APIClient) -> None:
    rec = _rec("vm-a", dest=node_id(9))
    resp = authed_client.post(_dismiss_url(rec.recommendation_id), {"if_version": 1}, format="json")
    assert resp.status_code == status.HTTP_403_FORBIDDEN
