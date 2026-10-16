"""The disk-tier admin renders and is read-only: a tier comes from a probe,
an override from `vali_set_pool_tier` (audited) — never from an admin
form."""

from __future__ import annotations

import pytest
from django.contrib.admin import site as admin_site
from django.contrib.auth import get_user_model
from django.test import Client, RequestFactory
from django.urls import reverse

from apps.disktier.models import (
    DedicatedDisk,
    DiskProbeRun,
    MinerDiskHealthHourly,
    MinerStorageConfig,
    MinerStorageConfigAudit,
    MinerStoragePool,
    PlacementDisk,
    VmDiskIoHourly,
)
from apps.scheduler.tests.factories import node_id

pytestmark = pytest.mark.django_db

_MODELS = (
    MinerStoragePool,
    DedicatedDisk,
    DiskProbeRun,
    PlacementDisk,
    VmDiskIoHourly,
    MinerDiskHealthHourly,
    MinerStorageConfig,
    MinerStorageConfigAudit,
)


@pytest.fixture
def superuser() -> object:
    return get_user_model().objects.create_superuser(
        username="ops-test",
        email="",
        password="irrelevant-uses-force-login",  # noqa: S106
    )


@pytest.mark.parametrize("model", _MODELS, ids=lambda m: m._meta.model_name)
def test_changelist_renders(superuser: object, model: type) -> None:
    MinerStoragePool.objects.create(miner_node_id=node_id(1), pool_id="default")
    client = Client()
    client.force_login(superuser)
    url = reverse(f"admin:disktier_{model._meta.model_name}_changelist")
    assert client.get(url).status_code == 200


@pytest.mark.parametrize("model", _MODELS, ids=lambda m: m._meta.model_name)
def test_nothing_is_editable(superuser: object, model: type) -> None:
    request = RequestFactory().get("/")
    request.user = superuser
    model_admin = admin_site._registry[model]  # noqa: SLF001 — admin has no public lookup
    assert not model_admin.has_add_permission(request)
    assert not model_admin.has_change_permission(request)
    assert not model_admin.has_delete_permission(request)
