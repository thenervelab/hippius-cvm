"""`vali_telemetry_register_source` — register a telemetry source.

The broker verifies every envelope against the source's Ed25519
public key — the trust anchor — which it must hold BEFORE accepting
any telemetry (the key is never read from the untrusted envelope).
This command is the v1 operator surface for recording that key.

(The §7/§21 attested-release flow that will auto-provision these
keys is a separate concern — out of scope for the broker itself.)

    manage.py vali_telemetry_register_source \\
        --source edge_gateway --source-id edge-peer-1 \\
        --vk-hex <64 hex chars>
"""

from __future__ import annotations

from typing import Any

from django.core.management.base import BaseCommand, CommandError

from apps.telemetry.models import SourceType, TelemetrySource


class Command(BaseCommand):
    help = "Register (or update) a §9 telemetry source's verifying key."

    def add_arguments(self, parser: Any) -> None:
        parser.add_argument(
            "--source",
            required=True,
            choices=SourceType.values,
            help="Source type.",
        )
        parser.add_argument(
            "--source-id",
            required=True,
            help="Opaque source identifier (peer id / vm_id / node id).",
        )
        parser.add_argument(
            "--vk-hex",
            required=True,
            help="The source's 32-byte Ed25519 public key, hex-encoded.",
        )
        parser.add_argument(
            "--inactive",
            action="store_true",
            help="Register the source disabled (refuses ingestion).",
        )

    def handle(self, *args: Any, **options: Any) -> None:
        source = options["source"]
        source_id = options["source_id"].strip()
        if not source_id:
            raise CommandError("--source-id must not be empty")

        try:
            verifying_key = bytes.fromhex(options["vk_hex"].strip())
        except ValueError as exc:
            raise CommandError(f"--vk-hex is not valid hex: {exc}") from exc
        if len(verifying_key) != 32:
            raise CommandError(
                f"--vk-hex must decode to 32 bytes (got {len(verifying_key)})"
            )

        source_row, created = TelemetrySource.objects.update_or_create(
            source=source,
            source_id=source_id,
            defaults={
                "verifying_key": verifying_key,
                "is_active": not options["inactive"],
            },
        )
        verb = "registered" if created else "updated"
        self.stdout.write(
            f"telemetry source {verb}: {source_row.source}:{source_row.source_id} "
            f"(active={source_row.is_active})"
        )
