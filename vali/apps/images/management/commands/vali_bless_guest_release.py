"""`vali_bless_guest_release` — choose the guest components release a NEW VM
of an image boots (docs/design/guest-component-rollout.md, phase 7).

A launch by image then boots the image's blessed bake with that release's
build appended to the bake's initrd (`GuestInitrdBuild`, built by
`scripts/guest/guest-initrd-build.sh` and registered by
`vali_guest_build_register`): same kernel, same dm-verity base, the agents
from the release image. Existing VMs move with guest upgrades, not this.

    python manage.py vali_bless_guest_release ubuntu --release 2 --blessed-by ops@hippius
    python manage.py vali_bless_guest_release ubuntu --clear --blessed-by ops@hippius

Refuses a release without a usable (registered, not withdrawn) build of the
image's CURRENT bake. Re-blessing another bake for the image clears its
guest release (`vali_bless_golden_image`).
"""

from __future__ import annotations

import json
from typing import Any

from django.core.management.base import BaseCommand, CommandError
from django.utils import timezone


class Command(BaseCommand):
    help = "Bless the guest components release new VMs of an image boot."

    def add_arguments(self, parser: Any) -> None:
        parser.add_argument("image_name")
        group = parser.add_mutually_exclusive_group(required=True)
        group.add_argument("--release", type=int, help="a release version (>= 1)")
        group.add_argument("--clear", action="store_true")
        parser.add_argument("--blessed-by", required=True)

    def handle(self, *args: Any, **opts: Any) -> None:
        from apps.images.models import GoldenImage
        from apps.orchestration.models import GuestInitrdBuild
        from apps.tenant_bake.models import TenantBake, TenantBakeDiskMode, TenantBakeState

        image = GoldenImage.objects.filter(image_name=opts["image_name"]).first()
        if image is None:
            raise CommandError(f"no blessed image {opts['image_name']!r}")
        if opts["clear"]:
            image.guest_release = None
        elif opts["release"] < 1:
            raise CommandError("--release must be >= 1")
        else:
            bake = TenantBake.objects.filter(bake_id=image.bake_id).first()
            if (
                bake is None
                or bake.state != TenantBakeState.SUCCEEDED.value
                or bake.disk_mode != TenantBakeDiskMode.GOLDEN_VERITY_OVERLAY.value
            ):
                raise CommandError(
                    f"image {image.image_name!r}: its bake is not a Succeeded golden bake"
                )
            build = GuestInitrdBuild.objects.filter(
                release_id=opts["release"],
                base_initrd_sha256=bake.initrd_sha256,
                kernel_sha256=bake.kernel_sha256,
                rootfs_img_sha256=bake.rootfs_img_sha256,
                rootfs_verity_sha256=bake.rootfs_verity_sha256,
                verity_root_hash=bake.verity_root_hash,
                withdrawn_at__isnull=True,
                release__withdrawn_at__isnull=True,
            ).first()
            if build is None:
                raise CommandError(
                    f"no usable build of release {opts['release']} for bake {bake.bake_id!r} — "
                    "build it (scripts/guest/guest-initrd-build.sh) and register it "
                    "(vali_guest_build_register)"
                )
            image.guest_release = opts["release"]
        image.blessed_at = timezone.now()
        image.blessed_by = opts["blessed_by"]
        image.save(update_fields=["guest_release", "blessed_at", "blessed_by"])
        self.stdout.write(
            json.dumps(
                {
                    "image_name": image.image_name,
                    "bake_id": image.bake_id,
                    "guest_release": image.guest_release,
                    "blessed_at": image.blessed_at.isoformat(),
                }
            )
        )
