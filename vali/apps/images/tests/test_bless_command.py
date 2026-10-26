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


# ── phase 7: the image's guest components release ───────────────────


def _guest_build(release: int, **overrides):
    from apps.orchestration.models import GuestComponentRelease, GuestInitrdBuild

    rel, _ = GuestComponentRelease.objects.get_or_create(
        version=release,
        defaults={"commit": "c" * 40, "security_epoch": 1, "squashfs_sha256": "d" * 64},
    )
    fields = dict(
        release=rel,
        source_bake_id="gb-1",
        family="initramfs-tools",
        kernel_sha256="2" * 64,
        rootfs_img_sha256="a1" * 32,
        rootfs_verity_sha256="b2" * 32,
        verity_root_hash="c3" * 32,
        base_initrd_sha256="3" * 64,
        release_cpio_sha256="e" * 64,
        initrd_sha256=f"{release:02d}" * 32,
        s3_bucket="hippius-compute-images",
        s3_key_prefix=f"golden/gb-1-gr{release}/",
        measurement={},
    )
    fields.update(overrides)
    return GuestInitrdBuild.objects.create(**fields)


def test_bless_guest_release_needs_a_build_of_the_images_bake(make_golden_bake) -> None:
    make_golden_bake(bake_id="gb-1")
    call_command("vali_bless_golden_image", "ubuntu", "gb-1")
    with pytest.raises(CommandError, match="no usable build"):
        call_command("vali_bless_guest_release", "ubuntu", "--release", "2", "--blessed-by", "ops")
    _guest_build(2, kernel_sha256="9" * 64, initrd_sha256="29" * 32)  # another base
    with pytest.raises(CommandError, match="no usable build"):
        call_command("vali_bless_guest_release", "ubuntu", "--release", "2", "--blessed-by", "ops")
    _guest_build(2, s3_key_prefix="golden/gb-1-gr2b/")
    call_command("vali_bless_guest_release", "ubuntu", "--release", "2", "--blessed-by", "ops")
    assert GoldenImage.objects.get(image_name="ubuntu").guest_release == 2
    call_command("vali_bless_guest_release", "ubuntu", "--clear", "--blessed-by", "ops")
    assert GoldenImage.objects.get(image_name="ubuntu").guest_release is None


def test_reblessing_another_bake_clears_the_guest_release(make_golden_bake) -> None:
    make_golden_bake(bake_id="gb-1")
    make_golden_bake(bake_id="gb-2")
    call_command("vali_bless_golden_image", "ubuntu", "gb-1")
    _guest_build(2)
    call_command("vali_bless_guest_release", "ubuntu", "--release", "2", "--blessed-by", "ops")
    call_command("vali_bless_golden_image", "ubuntu", "gb-1")
    assert GoldenImage.objects.get(image_name="ubuntu").guest_release == 2, "same bake"
    call_command("vali_bless_golden_image", "ubuntu", "gb-2")
    assert GoldenImage.objects.get(image_name="ubuntu").guest_release is None


def test_bless_guest_release_for_a_second_bake_sharing_the_initrd(make_golden_bake) -> None:
    """Bake gb-2 reuses gb-1's kernel and initrd (one upstream base) on its
    own rootfs: its build of release 7 is byte-identical to gb-1's. Each
    bake blesses, and launches, its own build — never the other's prefix."""
    from apps.orchestration.launch_jobs import _apply_guest_release

    gb1 = make_golden_bake(bake_id="gb-1")
    gb2 = make_golden_bake(
        bake_id="gb-2",
        rootfs_img_sha256="a9" * 32,
        rootfs_verity_sha256="b9" * 32,
        verity_root_hash="c9" * 32,
    )
    shared = "77" * 32
    _guest_build(7, initrd_sha256=shared)
    _guest_build(
        7,
        initrd_sha256=shared,
        source_bake_id="gb-2",
        rootfs_img_sha256=gb2.rootfs_img_sha256,
        rootfs_verity_sha256=gb2.rootfs_verity_sha256,
        verity_root_hash=gb2.verity_root_hash,
        s3_key_prefix="golden/gb-2-gr7/",
    )
    call_command("vali_bless_golden_image", "ubuntu-b2", "gb-2")
    call_command("vali_bless_guest_release", "ubuntu-b2", "--release", "7", "--blessed-by", "ops")
    assert GoldenImage.objects.get(image_name="ubuntu-b2").guest_release == 7
    for bake, prefix in ((gb1, "golden/gb-1-gr7/"), (gb2, "golden/gb-2-gr7/")):
        intent: dict = {}
        _apply_guest_release(intent, bake, 7)
        assert (intent["s3_key_prefix"], intent["initrd_sha256_hex"]) == (prefix, shared)


def test_release_zero_is_refused(make_golden_bake) -> None:
    make_golden_bake(bake_id="gb-1")
    call_command("vali_bless_golden_image", "ubuntu", "gb-1")
    with pytest.raises(CommandError, match=">= 1"):
        call_command("vali_bless_guest_release", "ubuntu", "--release", "0", "--blessed-by", "ops")


def test_bless_cdn_node_profile_only_under_its_reserved_name(make_golden_bake) -> None:
    """CDN plan I3 — a cdn-node bake is never a tenant image, and nothing
    else may take the name `cdn-node`."""
    make_golden_bake(bake_id="gb-cdn", profile="cdn-node")
    make_golden_bake(bake_id="gb-std")
    for name, bake in (("ubuntu", "gb-cdn"), ("cdn-node", "gb-std")):
        with pytest.raises(SystemExit) as exc:
            call_command("vali_bless_golden_image", name, bake)
        assert exc.value.code == 9
    assert GoldenImage.objects.count() == 0
    call_command(
        "vali_bless_golden_image",
        "cdn-node",
        "gb-cdn",
        "--distro",
        "ubuntu",
        "--restricted-tenant",
        "hippius-cdn",
    )
    assert GoldenImage.objects.get(image_name="cdn-node").bake_id == "gb-cdn"


def test_bless_ubuntu_runner_profile_only_under_its_reserved_name(make_golden_bake) -> None:
    """The CI-runner bake is blessed only as `ubuntu-runner`, and nothing else
    may take that name."""
    make_golden_bake(bake_id="gb-runner", profile="ubuntu-runner")
    make_golden_bake(bake_id="gb-std")
    for name, bake in (("ubuntu", "gb-runner"), ("ubuntu-runner", "gb-std")):
        with pytest.raises(SystemExit) as exc:
            call_command(
                "vali_bless_golden_image", name, bake, "--restricted-tenant", "5Runner"
            )
        assert exc.value.code == 9
    assert GoldenImage.objects.count() == 0
    call_command(
        "vali_bless_golden_image",
        "ubuntu-runner",
        "gb-runner",
        "--distro",
        "ubuntu",
        "--restricted-tenant",
        "5Runner",
    )
    row = GoldenImage.objects.get(image_name="ubuntu-runner")
    assert (row.bake_id, row.distro, row.restricted_tenant) == ("gb-runner", "ubuntu", "5Runner")


@pytest.mark.parametrize("extra", [[], ["--restricted-tenant", " "], ["--unrestrict"]])
def test_bless_ubuntu_runner_needs_a_restricted_tenant(make_golden_bake, extra) -> None:
    """The CI-runner image is never open to every tenant."""
    make_golden_bake(bake_id="gb-runner", profile="ubuntu-runner")
    with pytest.raises(SystemExit) as exc:
        call_command("vali_bless_golden_image", "ubuntu-runner", "gb-runner", *extra)
    assert exc.value.code == 9
    assert not GoldenImage.objects.filter(image_name="ubuntu-runner").exists()


def test_rebless_ubuntu_runner_keeps_its_restriction(make_golden_bake) -> None:
    """A re-bless without the flag keeps the tenant; --unrestrict is refused."""
    make_golden_bake(bake_id="gb-runner-1", profile="ubuntu-runner")
    make_golden_bake(bake_id="gb-runner-2", profile="ubuntu-runner")
    call_command(
        "vali_bless_golden_image", "ubuntu-runner", "gb-runner-1", "--restricted-tenant", "5Runner"
    )
    call_command("vali_bless_golden_image", "ubuntu-runner", "gb-runner-2")
    row = GoldenImage.objects.get(image_name="ubuntu-runner")
    assert (row.bake_id, row.restricted_tenant) == ("gb-runner-2", "5Runner")
    with pytest.raises(SystemExit):
        call_command("vali_bless_golden_image", "ubuntu-runner", "gb-runner-2", "--unrestrict")
    assert GoldenImage.objects.get(image_name="ubuntu-runner").restricted_tenant == "5Runner"
