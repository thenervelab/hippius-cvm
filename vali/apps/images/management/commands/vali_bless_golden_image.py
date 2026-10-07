"""`vali_bless_golden_image` — the OPERATOR bless action for the
golden-image catalog (launch-by-image / "golden-everywhere").

Sets (or updates) the CURRENT blessed golden bake for a launchable image
name. This is the trust anchor: a tenant launches by image NAME, and vali
maps that name to whatever bake_id this command recorded. Only the operator
runs this command — there is no tenant-writable path — so a tenant can never
point an image at an arbitrary/other bake.

The command REFUSES to bless a bake that is not a Succeeded
`golden_verity_overlay` bake with its shared dm-verity artifacts present, so
the catalog can only ever reference a real, bootable golden base.

## Usage

Bless one image:

    python manage.py vali_bless_golden_image ubuntu 920b04f0bd4965dca293a9e3678973b1 \\
        --distro ubuntu --blessed-by ops@hippius

Seed / re-bless the 4 current golden images in one shot (each is validated
Succeeded+golden before it is blessed):

    python manage.py vali_bless_golden_image --seed-defaults --blessed-by ops@hippius

## Exit codes

    0   Blessed (JSON summary on stdout).
    8   Config / bad-argument error (CommandError).
    9   The named bake is not a blessable Succeeded golden bake.
"""

from __future__ import annotations

import json
import re
import sys
from typing import Any

from django.core.management.base import BaseCommand, CommandError
from django.utils import timezone

EXIT_BAKE_NOT_BLESSABLE = 9

_IMAGE_NAME_RE = re.compile(r"^[a-z0-9-]{1,64}$")

# The 4 current golden bakes (golden-everywhere seed). `--seed-defaults`
# blesses each after validating it is a Succeeded golden bake. Kept here so
# a deploy can seed the catalog with a single command; re-blessing a rotated
# bake is a normal `vali_bless_golden_image <image> <bake_id>` call (no code
# change — that is the whole point of the catalog).
DEFAULT_GOLDEN_IMAGES: tuple[tuple[str, str, str], ...] = (
    # (image_name, distro, bake_id)
    ("ubuntu", "ubuntu", "920b04f0bd4965dca293a9e3678973b1"),
    ("debian", "debian", "812a137934884f1e97ffb4ac929b0517"),
    ("cs10", "centos-stream-10", "4c4b9ddd53c3297fcc39f233e6a94cc8"),
    ("fedora", "fedora", "f8fd2f73805c063e44912483acc62efa"),
)


class Command(BaseCommand):
    help = (
        "Bless (set/update) the current golden bake for a launchable image "
        "name. Validates the bake is a Succeeded golden_verity_overlay bake "
        "before recording it. Operator-only trust anchor for launch-by-image."
    )

    def add_arguments(self, parser: Any) -> None:
        parser.add_argument(
            "image_name",
            nargs="?",
            help="Launchable image name (e.g. `ubuntu`). Omit with --seed-defaults.",
        )
        parser.add_argument(
            "bake_id",
            nargs="?",
            help="The golden TenantBake id to bless. Omit with --seed-defaults.",
        )
        parser.add_argument(
            "--distro",
            default=None,
            help="Human distro label (defaults to image_name).",
        )
        parser.add_argument(
            "--blessed-by",
            default="operator",
            help="Operator identity recorded on the audit field.",
        )
        parser.add_argument(
            "--restricted-tenant",
            default=None,
            help=(
                "Only this tenant may launch the image or see it in the catalog. "
                "Required for a cdn-node bake, and must then be VALI_CDN_TENANT_ID. "
                "Omitted: a re-bless keeps the image's restriction, a first bless "
                "opens it to every tenant."
            ),
        )
        parser.add_argument(
            "--unrestrict",
            action="store_true",
            help="Lift the image's tenant restriction: every tenant may launch it.",
        )
        parser.add_argument(
            "--seed-defaults",
            action="store_true",
            help=(
                "Bless the 4 current golden images (ubuntu/debian/cs10/fedora) "
                "from the built-in mapping. Each is validated Succeeded+golden."
            ),
        )

    def handle(self, *args: Any, **opts: Any) -> None:
        if opts["seed_defaults"]:
            if (
                opts["image_name"]
                or opts["bake_id"]
                or opts["restricted_tenant"] is not None
                or opts["unrestrict"]
            ):
                raise CommandError(
                    "--seed-defaults takes no image_name/bake_id positionals and no "
                    "--restricted-tenant / --unrestrict"
                )
            blessed = [
                self._bless(name, bake_id, distro, opts["blessed_by"])
                for name, distro, bake_id in DEFAULT_GOLDEN_IMAGES
            ]
            self.stdout.write(json.dumps({"blessed": blessed}))
            return

        if not opts["image_name"] or not opts["bake_id"]:
            raise CommandError(
                "image_name and bake_id are required (or pass --seed-defaults)"
            )
        if opts["unrestrict"] and opts["restricted_tenant"] is not None:
            raise CommandError("--restricted-tenant and --unrestrict are exclusive")
        distro = opts["distro"] or opts["image_name"]
        summary = self._bless(
            opts["image_name"],
            opts["bake_id"],
            distro,
            opts["blessed_by"],
            restricted_tenant=(
                ""
                if opts["unrestrict"]
                else None
                if opts["restricted_tenant"] is None
                else str(opts["restricted_tenant"]).strip()
            ),
        )
        self.stdout.write(json.dumps(summary))

    def _bless(
        self,
        image_name: str,
        bake_id: str,
        distro: str,
        blessed_by: str,
        *,
        restricted_tenant: str | None = None,
    ) -> dict[str, Any]:
        """Validate the bake is a Succeeded golden bake, then upsert the row.
        `restricted_tenant=None` keeps the image's current restriction (none
        for a new image); `""` lifts it."""
        from apps.common.cdn import cdn_tenant_id
        from apps.images.models import GoldenImage
        from apps.tenant_bake.models import (
            TenantBake,
            TenantBakeDiskMode,
            TenantBakeState,
        )

        if not _IMAGE_NAME_RE.match(image_name):
            raise CommandError(
                f"image_name {image_name!r} must match [a-z0-9-]{{1,64}}"
            )
        if not distro:
            raise CommandError("distro must be non-empty")

        try:
            bake = TenantBake.objects.get(bake_id=bake_id)
        except TenantBake.DoesNotExist:
            self.stderr.write(
                self.style.ERROR(f"bake_id {bake_id!r} not found")
            )
            sys.exit(EXIT_BAKE_NOT_BLESSABLE)
        if bake.state != TenantBakeState.SUCCEEDED.value:
            self.stderr.write(
                self.style.ERROR(
                    f"bake {bake_id!r} is not Succeeded (state={bake.state!r}) "
                    "— refusing to bless"
                )
            )
            sys.exit(EXIT_BAKE_NOT_BLESSABLE)
        if bake.disk_mode != TenantBakeDiskMode.GOLDEN_VERITY_OVERLAY.value:
            self.stderr.write(
                self.style.ERROR(
                    f"bake {bake_id!r} is not a golden_verity_overlay bake "
                    f"(disk_mode={bake.disk_mode!r}) — only golden bakes are "
                    "blessable as launch-by-image targets"
                )
            )
            sys.exit(EXIT_BAKE_NOT_BLESSABLE)
        # CDN plan I3: a cdn-node bake is blessed only under the reserved
        # name `cdn-node`, and nothing else is.
        if (bake.profile == "cdn-node") != (image_name == "cdn-node"):
            self.stderr.write(
                self.style.ERROR(
                    f"bake {bake_id!r} (profile={bake.profile!r}) cannot be blessed as "
                    f"{image_name!r}: the cdn-node profile and the image name 'cdn-node' "
                    "go together"
                )
            )
            sys.exit(EXIT_BAKE_NOT_BLESSABLE)
        previous = GoldenImage.objects.filter(image_name=image_name).first()
        if restricted_tenant is None:
            restricted_tenant = previous.restricted_tenant if previous is not None else ""
        # CDN plan N2: the cdn-node image is the CDN fleet's alone — it holds
        # the fleet's keys once released.
        if bake.profile == "cdn-node" and (
            not cdn_tenant_id() or restricted_tenant != cdn_tenant_id()
        ):
            self.stderr.write(
                self.style.ERROR(
                    f"bake {bake_id!r} is a cdn-node bake: bless it with "
                    f"--restricted-tenant set to VALI_CDN_TENANT_ID ({cdn_tenant_id()!r}), "
                    f"not {restricted_tenant!r}"
                )
            )
            sys.exit(EXIT_BAKE_NOT_BLESSABLE)
        # One bake, one audience: a bake blessed under two names with two
        # restrictions would be refused for one name or open by the other.
        others = (
            GoldenImage.objects.filter(bake_id=bake_id)
            .exclude(image_name=image_name)
            .exclude(restricted_tenant=restricted_tenant)
            .values_list("image_name", flat=True)
        )
        if others:
            self.stderr.write(
                self.style.ERROR(
                    f"bake {bake_id!r} is blessed as {sorted(others)} with another tenant "
                    "restriction — one bake has one restriction"
                )
            )
            sys.exit(EXIT_BAKE_NOT_BLESSABLE)
        # A Succeeded golden bake must carry its shared dm-verity artifacts
        # (the DB CHECK enforces this, but assert defensively so a malformed
        # row can never enter the catalog).
        if not (
            bake.rootfs_img_sha256
            and bake.rootfs_verity_sha256
            and bake.verity_root_hash
        ):
            self.stderr.write(
                self.style.ERROR(
                    f"bake {bake_id!r} is missing its golden dm-verity "
                    "artifacts — refusing to bless"
                )
            )
            sys.exit(EXIT_BAKE_NOT_BLESSABLE)

        defaults: dict[str, Any] = {
            "distro": distro,
            "bake_id": bake_id,
            "blessed_at": timezone.now(),
            "blessed_by": blessed_by,
            "restricted_tenant": restricted_tenant,
        }
        if previous is not None and previous.restricted_tenant != restricted_tenant:
            widened = "" if restricted_tenant else " — every tenant may now launch it"
            self.stderr.write(
                self.style.WARNING(
                    f"image={image_name}: restricted tenant {previous.restricted_tenant!r} → "
                    f"{restricted_tenant!r}{widened}"
                )
            )
        if (
            previous is not None
            and previous.bake_id != bake_id
            and previous.guest_release is not None
        ):
            # The release was blessed for the OLD bake's base: re-bless it for
            # this one explicitly (`vali_bless_guest_release`).
            defaults["guest_release"] = None
            self.stderr.write(
                self.style.WARNING(
                    f"image={image_name}: guest release {previous.guest_release} cleared — it was "
                    "blessed for the previous bake; run vali_bless_guest_release for this one"
                )
            )
        obj, created = GoldenImage.objects.update_or_create(
            image_name=image_name, defaults=defaults
        )
        self.stderr.write(
            self.style.SUCCESS(
                f"{'blessed' if created else 're-blessed'} image={image_name} "
                f"→ bake_id={bake_id} (distro={distro})"
            )
        )
        return {
            "image_name": obj.image_name,
            "distro": obj.distro,
            "bake_id": obj.bake_id,
            "created": created,
            "blessed_at": obj.blessed_at.isoformat(),
            "restricted_tenant": obj.restricted_tenant,
        }
