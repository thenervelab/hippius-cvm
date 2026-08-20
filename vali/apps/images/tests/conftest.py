"""Shared fixtures for the images (golden-image catalog) test suite."""

from __future__ import annotations

import pytest
from rest_framework.test import APIClient

from apps.identity.models import (
    PrincipalScope,
    ServiceClient,
    ServiceToken,
    TokenLifetime,
)
from apps.tenant_bake.models import TenantBake, TenantBakeDiskMode, TenantBakeState


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
    """Any authenticated `ServiceClient` — the tier `GET /v1/images` accepts."""
    return _bearer_client("image-lister")


@pytest.fixture
def make_golden_bake():
    """Factory: a Succeeded golden `TenantBake` (the blessable shape)."""

    def _make(bake_id: str = "golden-bake-1", **overrides) -> TenantBake:
        sc = ServiceClient.objects.create(
            scope=PrincipalScope.OPERATOR.value,
            name=f"owner-{bake_id}",
        )
        fields = dict(
            bake_id=bake_id,
            vm_id=f"vm-{bake_id}"[:64],
            base_image_url="https://s3.example/base.qcow2",
            base_image_sha256="a" * 64,
            size_gb=10,
            kek_vault_path="",
            s3_output_bucket="hippius-compute-images",
            s3_output_prefix=f"golden/{bake_id}/",
            disk_mode=TenantBakeDiskMode.GOLDEN_VERITY_OVERLAY.value,
            state=TenantBakeState.SUCCEEDED.value,
            kernel_sha256="2" * 64,
            initrd_sha256="3" * 64,
            rootfs_img_sha256="a1" * 32,
            rootfs_verity_sha256="b2" * 32,
            verity_root_hash="c3" * 32,
            requested_by=sc,
        )
        fields.update(overrides)
        return TenantBake.objects.create(**fields)

    return _make
