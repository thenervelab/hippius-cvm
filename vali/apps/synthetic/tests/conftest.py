"""Shared fixtures for the synthetic-monitor tests."""

from __future__ import annotations

import pytest


@pytest.fixture
def blessed_ubuntu(db):
    """The catalog row a real `image=ubuntu` launch resolves to.

    The monitor reads this same row, so stubbing it exercises the
    production lookup instead of a monitor-only config that can drift from
    it — which is precisely the drift this replaced.
    """
    from django.utils import timezone

    from apps.images.models import GoldenImage

    return GoldenImage.objects.create(
        image_name="ubuntu",
        distro="ubuntu",
        bake_id="bake-ubuntu-9",
        blessed_at=timezone.now(),
        blessed_by="test",
    )
