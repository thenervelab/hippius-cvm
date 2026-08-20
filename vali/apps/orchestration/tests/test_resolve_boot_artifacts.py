"""Direct unit tests for `effects.resolve_boot_artifacts` — the §25 dest
staging bundle. Focus: a GOLDEN VM must stage the shared dm-verity base
(rootfs.img + rootfs.verity), which the golden guest boots the root from and
never self-fetches; a legacy VM must not.

The autouse `fx` fixture (conftest) replaces `effects.resolve_boot_artifacts`
with a fake, so we capture the REAL implementation at import time (before any
per-test patch runs) and call that.
"""

from __future__ import annotations

import secrets

import pytest
from django.utils import timezone

from apps.orchestration import effects
from apps.orchestration.models import LaunchJob, LaunchJobState

from .factories import make_service_client, make_vm

# Captured BEFORE the autouse `fx` fixture monkeypatches the module attribute.
_REAL_RESOLVE = effects.resolve_boot_artifacts

pytestmark = pytest.mark.django_db


class _FakeGet:
    def __init__(self, url: str) -> None:
        self.url = url


class _FakeS3:
    """Presign helper that echoes the key so tests can assert the S3 key."""

    def presign_get(self, *, bucket: str, key: str, ttl_seconds: int) -> _FakeGet:
        return _FakeGet(f"https://s3.example/{bucket}/{key}?sig=x")


def _launch_record(vm_id: str, spec: dict) -> LaunchJob:
    now = timezone.now()
    return LaunchJob.objects.create(
        job_id=secrets.token_hex(16),
        vm_id=vm_id,
        tenant_id="t",
        flavor="small",
        spec_json=spec,
        userdata_vault_path=f"x/{vm_id}/userdata",
        userdata_vault_version=1,
        kek_vault_path=f"x/{vm_id}/luks-kek",
        state=LaunchJobState.SUCCEEDED.value,
        phase_started_at=now,
        finished_at=now,
        decided_by=make_service_client(),
    )


_BASE_SPEC = {
    "s3_bucket": "hippius-compute-images",
    "s3_key_prefix": "tenant/gold-1",
    "kernel_sha256_hex": "ab" * 32,
    "initrd_sha256_hex": "cd" * 32,
}


def test_golden_stages_the_dm_verity_base(monkeypatch):
    from apps.storage import s3

    monkeypatch.setattr(s3, "get_s3_client", lambda: _FakeS3())
    vm = make_vm(vm_id="gold-1", host="node-src")
    _launch_record(
        "gold-1",
        {
            **_BASE_SPEC,
            "disk_mode": "golden_verity_overlay",
            "rootfs_img_sha256_hex": "11" * 32,
            "rootfs_verity_sha256_hex": "22" * 32,
        },
    )

    staging = _REAL_RESOLVE(vm)

    assert staging is not None
    # Kernel + initrd as always…
    assert staging["kernel"]["sha256_hex"] == "ab" * 32
    # …PLUS the shared golden base (rootfs.img data + rootfs.verity hash),
    # keyed by the golden bake SHAs at the golden S3 keys.
    assert staging["rootfs_data"]["sha256_hex"] == "11" * 32
    assert staging["rootfs_data"]["url"].endswith("tenant/gold-1/rootfs.img?sig=x")
    assert staging["rootfs_hash"]["sha256_hex"] == "22" * 32
    assert staging["rootfs_hash"]["url"].endswith("tenant/gold-1/rootfs.verity?sig=x")


def test_golden_without_base_shas_falls_back_to_none(monkeypatch):
    from apps.storage import s3

    monkeypatch.setattr(s3, "get_s3_client", lambda: _FakeS3())
    vm = make_vm(vm_id="gold-2", host="node-src")
    _launch_record(
        "gold-2",
        {**_BASE_SPEC, "disk_mode": "golden_verity_overlay"},  # no base SHAs
    )
    # A golden record that cannot name its base ⇒ None (dest existence-check
    # fails closed) rather than a half-staged boot.
    assert _REAL_RESOLVE(vm) is None


def test_legacy_stages_no_verity_hash(monkeypatch):
    from apps.storage import s3

    monkeypatch.setattr(s3, "get_s3_client", lambda: _FakeS3())
    vm = make_vm(vm_id="legacy-1", host="node-src")
    _launch_record("legacy-1", {**_BASE_SPEC, "disk_mode": "legacy_luks"})

    staging = _REAL_RESOLVE(vm)

    assert staging is not None
    assert "rootfs_hash" not in staging  # legacy has no golden verity base
    assert "rootfs_data" not in staging  # no split-rootfs sha recorded
