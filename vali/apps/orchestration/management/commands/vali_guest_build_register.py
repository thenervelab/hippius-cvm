"""`vali_guest_build_register` — record a guest components release build.

`scripts/guest/guest-initrd-build.sh` appends a release to a golden base's
initrd and publishes the set under a new prefix, with a
`golden.measurement.json` that names that prefix and carries a
`guest_release` object (docs/design/guest-component-rollout.md). This
command READS that document (a GET with vali's S3 client) and records the
build — and its release, the first time one of its builds is seen — so a
guest upgrade job can move VMs onto it:

    manage.py vali_guest_build_register --from-s3-prefix tenant/<base>-gr1-<short>/
        [--s3-bucket hippius-compute-images]     # default VALI_PACKER_IMAGES_BUCKET

Idempotent: the same document again is a no-op. A release version seen
again with another commit, epoch or image, a document that names another
location than the one it was read from, or an initrd already registered
elsewhere, is refused and nothing is written.
"""

from __future__ import annotations

import json
from typing import Any

from django.conf import settings
from django.core.management.base import BaseCommand, CommandError

from apps.orchestration.services import guest_components

MEASUREMENT_OBJECT = "golden.measurement.json"
_SIZE_CAP = 1 << 20


class Command(BaseCommand):
    help = "Record a guest components release build from its published golden.measurement.json."

    def add_arguments(self, parser: Any) -> None:
        parser.add_argument("--from-s3-prefix", required=True, help="the build's S3 key prefix")
        parser.add_argument(
            "--s3-bucket",
            default="",
            help="bucket (default: VALI_PACKER_IMAGES_BUCKET)",
        )

    def handle(self, *args: Any, **opts: Any) -> None:
        from apps.storage import s3

        bucket = opts["s3_bucket"] or str(getattr(settings, "VALI_PACKER_IMAGES_BUCKET", ""))
        prefix = str(opts["from_s3_prefix"]).strip().strip("/")
        if not (bucket and prefix):
            raise CommandError("a bucket and a prefix are required")
        key = f"{prefix}/{MEASUREMENT_OBJECT}"
        try:
            raw = s3.get_s3_client().get_object(bucket=bucket, key=key, max_bytes=_SIZE_CAP)
        except Exception as exc:  # noqa: BLE001 — any S3 failure is a refusal.
            raise CommandError(f"cannot read s3://{bucket}/{key}: {exc}") from exc
        if raw is None:
            raise CommandError(f"s3://{bucket}/{key} does not exist")
        try:
            doc = json.loads(raw)
        except ValueError as exc:
            raise CommandError(f"s3://{bucket}/{key}: {exc}") from exc
        try:
            parsed = guest_components.parse_build(doc, bucket=bucket, prefix=prefix)
            build, created = guest_components.register_build(parsed)
        except guest_components.BuildRejected as exc:
            raise CommandError(f"refused: {exc}") from exc
        self.stdout.write(
            f"{'registered' if created else 'already registered'}: build={build.id} "
            f"release=v{build.release_id} epoch={build.release.security_epoch} "
            f"family={build.family} base_bake={build.source_bake_id} "
            f"initrd={build.initrd_sha256} prefix={build.s3_key_prefix}"
        )
