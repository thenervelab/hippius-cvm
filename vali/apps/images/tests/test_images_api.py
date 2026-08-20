"""`GET /v1/images` — the launch-by-image discovery surface."""

from __future__ import annotations

import pytest
from django.urls import reverse
from django.utils import timezone
from rest_framework.test import APIClient

from apps.images.models import GoldenImage

pytestmark = pytest.mark.django_db

IMAGES_URL = reverse("image_list")


def _bless(image_name: str, bake_id: str, distro: str = "") -> GoldenImage:
    return GoldenImage.objects.create(
        image_name=image_name,
        distro=distro or image_name,
        bake_id=bake_id,
        blessed_at=timezone.now(),
        blessed_by="ops",
    )


def test_images_requires_auth() -> None:
    resp = APIClient().get(IMAGES_URL)
    assert resp.status_code in (401, 403)


def test_images_lists_the_catalog(authed_client, make_golden_bake) -> None:
    make_golden_bake(bake_id="gb-1")
    _bless("ubuntu", "gb-1")
    resp = authed_client.get(IMAGES_URL)
    assert resp.status_code == 200
    body = resp.json()
    assert body["total"] == 1
    row = body["images"][0]
    assert row["image_name"] == "ubuntu"
    assert row["bake_id"] == "gb-1"
    assert row["distro"] == "ubuntu"
    assert row["is_golden"] is True
    assert row["blessed_at"]


def test_images_is_golden_false_when_bake_missing(authed_client) -> None:
    """A blessed image whose bake was removed out-of-band reports
    is_golden=false (diagnostic only, never an authz signal)."""
    _bless("ubuntu", "nonexistent-bake")
    resp = authed_client.get(IMAGES_URL)
    assert resp.status_code == 200
    assert resp.json()["images"][0]["is_golden"] is False


def test_images_empty_catalog(authed_client) -> None:
    resp = authed_client.get(IMAGES_URL)
    assert resp.status_code == 200
    assert resp.json() == {"images": [], "total": 0}
