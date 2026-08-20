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
            name="PackerBuild",
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
                ("build_id", models.CharField(max_length=64, unique=True)),
                (
                    "image_kind",
                    models.CharField(
                        choices=[
                            ("kbs", "KBS server"),
                            ("edge", "Edge gateway"),
                            ("guest", "Guest VM base image"),
                            ("audit-vm", "Audit-VM image"),
                        ],
                        max_length=32,
                    ),
                ),
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
                (
                    "artifact_sha256",
                    models.CharField(blank=True, default="", max_length=64),
                ),
                (
                    "provenance_signed_url",
                    models.CharField(blank=True, default="", max_length=2048),
                ),
                (
                    "failure_reason",
                    models.CharField(blank=True, default="", max_length=256),
                ),
                ("version", models.PositiveBigIntegerField(default=1)),
                (
                    "requested_by",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.PROTECT,
                        related_name="packer_builds",
                        to="identity.serviceclient",
                    ),
                ),
            ],
            options={"ordering": ["-requested_at"]},
        ),
        migrations.AddIndex(
            model_name="packerbuild",
            index=models.Index(
                fields=["image_kind", "state"], name="packer_pack_image_k_idx"
            ),
        ),
        migrations.AddIndex(
            model_name="packerbuild",
            index=models.Index(fields=["state"], name="packer_pack_state_idx"),
        ),
        migrations.AddConstraint(
            model_name="packerbuild",
            constraint=models.CheckConstraint(
                name="packer_succeeded_requires_sha",
                condition=(
                    ~models.Q(state="succeeded") | ~models.Q(artifact_sha256="")
                ),
            ),
        ),
        migrations.AddConstraint(
            model_name="packerbuild",
            constraint=models.CheckConstraint(
                name="packer_succeeded_requires_provenance",
                condition=(
                    ~models.Q(state="succeeded")
                    | ~models.Q(provenance_signed_url="")
                ),
            ),
        ),
        migrations.AddConstraint(
            model_name="packerbuild",
            constraint=models.UniqueConstraint(
                fields=("image_kind",),
                condition=models.Q(state__in=["queued", "running"]),
                name="packer_one_active_build_per_image_kind",
            ),
        ),
    ]
