"""`vali_bless_golden_image` — the operator bless action.

Pins the trust anchor: only a Succeeded golden bake can be blessed, and the
catalog row is an upsert keyed by image_name.
"""

from __future__ import annotations

import pytest
from django.core.management import call_command
from django.core.management.base import CommandError

from apps.images.models import GoldenImage
from apps.tenant_bake.models import TenantBakeDiskMode, TenantBakeState

pytestmark = pytest.mark.django_db


def test_bless_records_the_golden_bake(make_golden_bake) -> None:
    make_golden_bake(bake_id="gb-1")
    call_command("vali_bless_golden_image", "ubuntu", "gb-1", "--distro", "ubuntu")
    row = GoldenImage.objects.get(image_name="ubuntu")
    assert row.bake_id == "gb-1"
    assert row.distro == "ubuntu"
    assert row.blessed_at is not None


def test_bless_defaults_distro_to_image_name(make_golden_bake) -> None:
    make_golden_bake(bake_id="gb-1")
    call_command("vali_bless_golden_image", "ubuntu", "gb-1")
    assert GoldenImage.objects.get(image_name="ubuntu").distro == "ubuntu"


def test_bless_is_an_upsert(make_golden_bake) -> None:
    """Re-blessing an image points it at the NEW bake (one row, updated)."""
    make_golden_bake(bake_id="gb-1")
    make_golden_bake(bake_id="gb-2")
    call_command("vali_bless_golden_image", "ubuntu", "gb-1")
    call_command("vali_bless_golden_image", "ubuntu", "gb-2")
    rows = GoldenImage.objects.filter(image_name="ubuntu")
    assert rows.count() == 1
    assert rows.first().bake_id == "gb-2"


def test_bless_rejects_unknown_bake() -> None:
    with pytest.raises(SystemExit) as exc:
        call_command("vali_bless_golden_image", "ubuntu", "does-not-exist")
    assert exc.value.code == 9
    assert GoldenImage.objects.count() == 0


def test_bless_rejects_non_succeeded_bake(make_golden_bake) -> None:
    make_golden_bake(bake_id="gb-run", state=TenantBakeState.RUNNING.value)
    with pytest.raises(SystemExit) as exc:
        call_command("vali_bless_golden_image", "ubuntu", "gb-run")
    assert exc.value.code == 9
    assert GoldenImage.objects.count() == 0


def test_bless_rejects_non_golden_bake(make_golden_bake) -> None:
    """A legacy LUKS bake is NOT a launch-by-image target — refused."""
    make_golden_bake(
        bake_id="gb-legacy",
        disk_mode=TenantBakeDiskMode.LEGACY_LUKS.value,
        # A legacy Succeeded bake carries a qcow2 sha, not the verity trio.
        qcow2_sha256="9" * 64,
        rootfs_img_sha256="",
        rootfs_verity_sha256="",
        verity_root_hash="",
    )
    with pytest.raises(SystemExit) as exc:
        call_command("vali_bless_golden_image", "ubuntu", "gb-legacy")
    assert exc.value.code == 9
    assert GoldenImage.objects.count() == 0


def test_bless_rejects_bad_image_name(make_golden_bake) -> None:
    make_golden_bake(bake_id="gb-1")
    with pytest.raises(CommandError):
        call_command("vali_bless_golden_image", "Ubuntu/../x", "gb-1")


def test_seed_defaults_blesses_present_golden_bakes() -> None:
    """`--seed-defaults` blesses the 4 built-in mappings whose bakes exist +
    are Succeeded golden; a missing bake fails closed (exit 9)."""
    from apps.images.management.commands.vali_bless_golden_image import (
        DEFAULT_GOLDEN_IMAGES,
    )

    # Only the first default's bake exists here → seeding must stop (exit 9)
    # rather than silently skipping — fail closed.
    name0, _distro0, bake0 = DEFAULT_GOLDEN_IMAGES[0]
    from apps.identity.models import PrincipalScope, ServiceClient
    from apps.tenant_bake.models import TenantBake

    sc = ServiceClient.objects.create(scope=PrincipalScope.OPERATOR.value, name="seed-owner")
    TenantBake.objects.create(
        bake_id=bake0,
        vm_id="seed-vm",
        base_image_url="https://s3.example/base.qcow2",
        base_image_sha256="a" * 64,
        size_gb=10,
        kek_vault_path="",
        s3_output_bucket="b",
        s3_output_prefix="p/",
        disk_mode=TenantBakeDiskMode.GOLDEN_VERITY_OVERLAY.value,
        state=TenantBakeState.SUCCEEDED.value,
        kernel_sha256="2" * 64,
        initrd_sha256="3" * 64,
        rootfs_img_sha256="a1" * 32,
        rootfs_verity_sha256="b2" * 32,
        verity_root_hash="c3" * 32,
        requested_by=sc,
    )
    with pytest.raises(SystemExit) as exc:
        call_command("vali_bless_golden_image", "--seed-defaults")
    assert exc.value.code == 9
    # The first (present) image was blessed before the missing one aborted.
    assert GoldenImage.objects.filter(image_name=name0).exists()


def test_seed_defaults_rejects_positionals(make_golden_bake) -> None:
    make_golden_bake(bake_id="gb-1")
    with pytest.raises(CommandError):
        call_command("vali_bless_golden_image", "ubuntu", "gb-1", "--seed-defaults")
