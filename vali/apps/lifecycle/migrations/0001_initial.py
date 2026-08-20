from __future__ import annotations

import uuid

from django.db import migrations, models


class Migration(migrations.Migration):
    initial = True

    dependencies: list[tuple[str, str]] = []

    operations = [
        migrations.CreateModel(
            name="Vm",
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
                ("vm_id", models.CharField(max_length=256, unique=True)),
                ("lease_id", models.CharField(db_index=True, max_length=256)),
                (
                    "state",
                    models.CharField(
                        choices=[
                            ("active", "Active"),
                            ("migrating", "Migrating"),
                            ("decommissioning", "Decommissioning"),
                            ("destroyed", "Destroyed"),
                        ],
                        max_length=32,
                    ),
                ),
                ("generation", models.BigIntegerField()),
                ("new_generation", models.BigIntegerField(blank=True, null=True)),
                ("host", models.CharField(blank=True, max_length=256)),
                ("migration_dest", models.CharField(blank=True, max_length=256)),
                ("lifecycle_vk", models.BinaryField(max_length=32)),
                ("eol_nonce", models.BinaryField(blank=True, max_length=32, null=True)),
                ("version", models.PositiveBigIntegerField(default=1)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
            ],
            options={"ordering": ["-updated_at"]},
        ),
        migrations.AddIndex(
            model_name="vm",
            index=models.Index(fields=["state"], name="lifecycle_v_state_idx"),
        ),
        migrations.AddIndex(
            model_name="vm",
            index=models.Index(fields=["host"], name="lifecycle_v_host_idx"),
        ),
        migrations.AddConstraint(
            model_name="vm",
            constraint=models.CheckConstraint(
                name="lifecycle_vm_migrating_requires_dest",
                condition=(
                    ~models.Q(state="migrating") | ~models.Q(migration_dest="")
                ),
            ),
        ),
        migrations.AddConstraint(
            model_name="vm",
            constraint=models.CheckConstraint(
                name="lifecycle_vm_migrating_requires_new_generation",
                condition=(
                    ~models.Q(state="migrating")
                    | models.Q(new_generation__isnull=False)
                ),
            ),
        ),
    ]
