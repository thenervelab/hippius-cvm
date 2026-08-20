from __future__ import annotations

import uuid

from django.db import migrations, models


class Migration(migrations.Migration):
    initial = True

    dependencies: list[tuple[str, str]] = []

    operations = [
        migrations.CreateModel(
            name="TelemetryEnvelope",
            fields=[
                (
                    "envelope_id",
                    models.BigAutoField(primary_key=True, serialize=False),
                ),
                (
                    "source",
                    models.CharField(
                        choices=[
                            ("tenant_vm", "Tenant VM"),
                            ("audit_vm", "Audit VM"),
                            ("edge_gateway", "Edge gateway"),
                        ],
                        max_length=32,
                    ),
                ),
                ("source_id", models.CharField(db_index=True, max_length=256)),
                (
                    "kind",
                    models.CharField(
                        choices=[
                            ("edge_telemetry", "Edge telemetry envelope"),
                            ("served_receipt", "Tenant served-delivery receipt"),
                        ],
                        max_length=32,
                    ),
                ),
                ("schema_version", models.PositiveIntegerField()),
                ("payload_cbor", models.BinaryField()),
                ("signature", models.BinaryField(blank=True, default=b"")),
                (
                    "dedupe_digest",
                    models.CharField(blank=True, default="", max_length=64),
                ),
                (
                    "processing_status",
                    models.CharField(
                        choices=[
                            ("pending", "Pending"),
                            ("quarantined", "Quarantined"),
                            ("done", "Done"),
                            ("failed", "Failed"),
                        ],
                        default="pending",
                        max_length=32,
                    ),
                ),
                (
                    "received_at",
                    models.DateTimeField(auto_now_add=True, db_index=True),
                ),
                ("processed_at", models.DateTimeField(blank=True, null=True)),
                (
                    "pull_token",
                    models.CharField(blank=True, default="", max_length=64),
                ),
            ],
            options={"ordering": ["envelope_id"]},
        ),
        migrations.CreateModel(
            name="TelemetrySource",
            fields=[
                (
                    "id",
                    models.UUIDField(
                        default=uuid.uuid4,
                        editable=False,
                        primary_key=True,
                        serialize=False,
                    ),
                ),
                (
                    "source",
                    models.CharField(
                        choices=[
                            ("tenant_vm", "Tenant VM"),
                            ("audit_vm", "Audit VM"),
                            ("edge_gateway", "Edge gateway"),
                        ],
                        max_length=32,
                    ),
                ),
                ("source_id", models.CharField(max_length=256)),
                ("verifying_key", models.BinaryField(max_length=32)),
                ("is_active", models.BooleanField(default=True)),
                ("consecutive_failures", models.PositiveIntegerField(default=0)),
                (
                    "failure_window_started_at",
                    models.DateTimeField(blank=True, null=True),
                ),
                ("quarantined_until", models.DateTimeField(blank=True, null=True)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
            ],
            options={"ordering": ["source", "source_id"]},
        ),
        migrations.AddIndex(
            model_name="telemetryenvelope",
            index=models.Index(
                fields=["processing_status", "received_at"],
                name="telemetry_t_process_d474b1_idx",
            ),
        ),
        migrations.AddIndex(
            model_name="telemetryenvelope",
            index=models.Index(
                fields=["kind", "processing_status"],
                name="telemetry_t_kind_a393f4_idx",
            ),
        ),
        migrations.AddConstraint(
            model_name="telemetryenvelope",
            constraint=models.UniqueConstraint(
                fields=("dedupe_digest",),
                condition=~models.Q(dedupe_digest=""),
                name="telemetry_envelope_dedupe",
            ),
        ),
        migrations.AddConstraint(
            model_name="telemetrysource",
            constraint=models.UniqueConstraint(
                fields=("source", "source_id"),
                name="telemetry_source_unique",
            ),
        ),
    ]
