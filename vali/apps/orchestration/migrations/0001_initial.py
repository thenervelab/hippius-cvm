from __future__ import annotations

import uuid

import django.db.models.deletion
from django.db import migrations, models


class Migration(migrations.Migration):
    initial = True

    dependencies: list[tuple[str, str]] = [
        ("identity", "0001_initial"),
        ("lifecycle", "0001_initial"),
    ]

    operations = [
        migrations.CreateModel(
            name="DecommissionJob",
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
                ("job_id", models.CharField(max_length=64, unique=True)),
                (
                    "state",
                    models.CharField(
                        choices=[
                            ("draining", "Draining"),
                            ("awaiting_eol_ack", "Awaiting EOL ack"),
                            ("crypto_erasing", "Crypto erasing"),
                            ("revoking_netbird", "Revoking NetBird"),
                            ("done", "Done"),
                            ("failed", "Failed"),
                        ],
                        default="draining",
                        max_length=32,
                    ),
                ),
                ("eol_ack_verified", models.BooleanField(default=False)),
                ("forced", models.BooleanField(default=False)),
                (
                    "quarantine_node_id",
                    models.CharField(blank=True, default="", max_length=64),
                ),
                ("reason", models.CharField(blank=True, default="", max_length=256)),
                ("phase_started_at", models.DateTimeField()),
                ("started_at", models.DateTimeField(auto_now_add=True)),
                ("finished_at", models.DateTimeField(blank=True, null=True)),
                ("version", models.PositiveBigIntegerField(default=1)),
                (
                    "decided_by",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.PROTECT,
                        related_name="decommission_jobs",
                        to="identity.serviceclient",
                    ),
                ),
                (
                    "vm",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.PROTECT,
                        related_name="decommission_jobs",
                        to="lifecycle.vm",
                    ),
                ),
            ],
            options={"ordering": ["-started_at"]},
        ),
        migrations.CreateModel(
            name="MigrationJob",
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
                ("job_id", models.CharField(max_length=64, unique=True)),
                ("source_node_id", models.CharField(max_length=64)),
                ("dest_node_id", models.CharField(max_length=64)),
                ("source_gen", models.BigIntegerField()),
                ("new_gen", models.BigIntegerField()),
                (
                    "state",
                    models.CharField(
                        choices=[
                            ("draining", "Draining"),
                            ("quiescing", "Quiescing"),
                            ("snapshotting", "Snapshotting"),
                            ("uploading", "Uploading"),
                            ("fencing", "Fencing"),
                            ("awaiting_source_ack", "Awaiting source ack"),
                            ("dest_activating", "Dest activating"),
                            ("done", "Done"),
                            ("failed", "Failed"),
                        ],
                        default="draining",
                        max_length=32,
                    ),
                ),
                (
                    "snapshot_bucket",
                    models.CharField(blank=True, default="", max_length=256),
                ),
                (
                    "snapshot_key",
                    models.CharField(blank=True, default="", max_length=512),
                ),
                ("source_ack_verified", models.BooleanField(default=False)),
                (
                    "quarantine_node_id",
                    models.CharField(blank=True, default="", max_length=64),
                ),
                ("reason", models.CharField(blank=True, default="", max_length=256)),
                ("phase_started_at", models.DateTimeField()),
                ("started_at", models.DateTimeField(auto_now_add=True)),
                ("finished_at", models.DateTimeField(blank=True, null=True)),
                ("version", models.PositiveBigIntegerField(default=1)),
                (
                    "decided_by",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.PROTECT,
                        related_name="migration_jobs",
                        to="identity.serviceclient",
                    ),
                ),
                (
                    "vm",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.PROTECT,
                        related_name="migration_jobs",
                        to="lifecycle.vm",
                    ),
                ),
            ],
            options={"ordering": ["-started_at"]},
        ),
        migrations.AddIndex(
            model_name="decommissionjob",
            index=models.Index(
                fields=["state"], name="orchestrati_state_a508f6_idx"
            ),
        ),
        migrations.AddIndex(
            model_name="migrationjob",
            index=models.Index(
                fields=["state"], name="orchestrati_state_b26b60_idx"
            ),
        ),
        migrations.AddConstraint(
            model_name="decommissionjob",
            constraint=models.UniqueConstraint(
                fields=("vm",),
                condition=~models.Q(state__in=["done", "failed"]),
                name="orchestration_one_active_decommission_per_vm",
            ),
        ),
        migrations.AddConstraint(
            model_name="decommissionjob",
            constraint=models.CheckConstraint(
                name="orchestration_decommission_terminal_finished",
                condition=(
                    ~models.Q(state__in=["done", "failed"])
                    | models.Q(finished_at__isnull=False)
                ),
            ),
        ),
        migrations.AddConstraint(
            model_name="migrationjob",
            constraint=models.UniqueConstraint(
                fields=("vm",),
                condition=~models.Q(state__in=["done", "failed"]),
                name="orchestration_one_active_migration_per_vm",
            ),
        ),
        migrations.AddConstraint(
            model_name="migrationjob",
            constraint=models.CheckConstraint(
                name="orchestration_migration_terminal_finished",
                condition=(
                    ~models.Q(state__in=["done", "failed"])
                    | models.Q(finished_at__isnull=False)
                ),
            ),
        ),
    ]
