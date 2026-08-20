from __future__ import annotations

import uuid

import django.db.models.deletion
from django.db import migrations, models


class Migration(migrations.Migration):
    initial = True

    dependencies: list[tuple[str, str]] = [
        ("identity", "0001_initial"),
    ]

    operations = [
        migrations.CreateModel(
            name="TenantBake",
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
                ("bake_id", models.CharField(max_length=64, unique=True)),
                ("vm_id", models.CharField(max_length=64)),
                ("base_image_url", models.URLField(max_length=2048)),
                ("base_image_sha256", models.CharField(max_length=64)),
                ("size_gb", models.PositiveIntegerField()),
                ("kek_vault_path", models.CharField(max_length=512)),
                ("s3_output_bucket", models.CharField(max_length=256)),
                ("s3_output_prefix", models.CharField(max_length=512)),
                (
                    "state",
                    models.CharField(
                        choices=[
                            ("queued", "Queued"),
                            ("running", "Running"),
                            ("succeeded", "Succeeded"),
                            ("failed", "Failed"),
                        ],
                        default="queued",
                        max_length=32,
                    ),
                ),
                ("requested_at", models.DateTimeField(auto_now_add=True)),
                ("started_at", models.DateTimeField(blank=True, null=True)),
                ("finished_at", models.DateTimeField(blank=True, null=True)),
                ("qcow2_sha256", models.CharField(blank=True, default="", max_length=64)),
                ("kernel_sha256", models.CharField(blank=True, default="", max_length=64)),
                ("initrd_sha256", models.CharField(blank=True, default="", max_length=64)),
                ("measurement_hex", models.CharField(blank=True, default="", max_length=96)),
                ("failure_reason", models.CharField(blank=True, default="", max_length=256)),
                ("version", models.PositiveBigIntegerField(default=1)),
                (
                    "requested_by",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.PROTECT,
                        related_name="tenant_bakes",
                        to="identity.serviceclient",
                    ),
                ),
            ],
            options={
                "ordering": ["-requested_at"],
            },
        ),
        migrations.AddIndex(
            model_name="tenantbake",
            index=models.Index(
                fields=["vm_id", "state"],
                name="tenant_bake_vm_id_18a6c4_idx",
            ),
        ),
        migrations.AddIndex(
            model_name="tenantbake",
            index=models.Index(
                fields=["state"],
                name="tenant_bake_state_71e0b5_idx",
            ),
        ),
        migrations.AddConstraint(
            model_name="tenantbake",
            constraint=models.CheckConstraint(
                condition=(
                    models.Q(("state", "succeeded"), _negated=True)
                    | models.Q(("qcow2_sha256", ""), _negated=True)
                ),
                name="tenant_bake_succeeded_requires_qcow2_sha",
            ),
        ),
        migrations.AddConstraint(
            model_name="tenantbake",
            constraint=models.CheckConstraint(
                condition=(
                    models.Q(("state", "succeeded"), _negated=True)
                    | models.Q(("kernel_sha256", ""), _negated=True)
                ),
                name="tenant_bake_succeeded_requires_kernel_sha",
            ),
        ),
        migrations.AddConstraint(
            model_name="tenantbake",
            constraint=models.CheckConstraint(
                condition=(
                    models.Q(("state", "succeeded"), _negated=True)
                    | models.Q(("initrd_sha256", ""), _negated=True)
                ),
                name="tenant_bake_succeeded_requires_initrd_sha",
            ),
        ),
        migrations.AddConstraint(
            model_name="tenantbake",
            constraint=models.CheckConstraint(
                condition=(
                    models.Q(("state", "succeeded"), _negated=True)
                    | models.Q(("measurement_hex", ""), _negated=True)
                ),
                name="tenant_bake_succeeded_requires_measurement",
            ),
        ),
        migrations.AddConstraint(
            model_name="tenantbake",
            constraint=models.UniqueConstraint(
                condition=models.Q(("state__in", ["queued", "running"])),
                fields=("vm_id",),
                name="tenant_bake_one_active_per_vm_id",
            ),
        ),
    ]
