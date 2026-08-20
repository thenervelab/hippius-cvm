from __future__ import annotations

import uuid

from django.db import migrations, models


class Migration(migrations.Migration):
    initial = True

    dependencies: list[tuple[str, str]] = []

    operations = [
        migrations.CreateModel(
            name="ServiceClient",
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
                ("name", models.CharField(max_length=128, unique=True)),
                ("description", models.TextField(blank=True)),
                ("is_active", models.BooleanField(default=True)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
            ],
            options={"ordering": ["name"]},
        ),
        migrations.CreateModel(
            name="ServiceToken",
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
                    "name",
                    models.CharField(
                        max_length=128,
                        help_text=(
                            "Human label for this token (e.g. 'l1-prod-2026q2'). "
                            "Not a secret."
                        ),
                    ),
                ),
                (
                    "token_sha256",
                    models.CharField(db_index=True, max_length=64, unique=True),
                ),
                ("is_active", models.BooleanField(default=True)),
                ("expires_at", models.DateTimeField(blank=True, null=True)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("last_used_at", models.DateTimeField(blank=True, null=True)),
                (
                    "client",
                    models.ForeignKey(
                        on_delete=models.deletion.CASCADE,
                        related_name="tokens",
                        to="identity.serviceclient",
                    ),
                ),
            ],
            options={"ordering": ["-created_at"]},
        ),
        migrations.AddConstraint(
            model_name="servicetoken",
            constraint=models.UniqueConstraint(
                fields=("client", "name"),
                name="identity_servicetoken_client_name_unique",
            ),
        ),
    ]
