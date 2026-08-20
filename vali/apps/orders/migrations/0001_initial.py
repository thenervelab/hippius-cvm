from __future__ import annotations

import uuid

from django.db import migrations, models


class Migration(migrations.Migration):
    initial = True

    dependencies: list[tuple[str, str]] = []

    operations = [
        migrations.CreateModel(
            name="OrderTicketIntake",
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
                ("ticket_id", models.CharField(max_length=256, unique=True)),
                ("vm_id", models.CharField(db_index=True, max_length=256)),
                ("tenant_id", models.CharField(db_index=True, max_length=256)),
                ("user_id", models.CharField(max_length=256)),
                ("lease_id", models.CharField(max_length=256)),
                ("vm_generation", models.BigIntegerField()),
                ("issue_time", models.BigIntegerField()),
                ("expiry", models.BigIntegerField()),
                ("node_id", models.CharField(max_length=256)),
                ("platform_id", models.CharField(max_length=256)),
                ("resource_class", models.CharField(max_length=128)),
                ("kid_hex", models.CharField(max_length=512)),
                ("cose_blob", models.BinaryField()),
                ("received_at", models.DateTimeField(auto_now_add=True, db_index=True)),
                ("received_from", models.CharField(max_length=256)),
            ],
            options={"ordering": ["-received_at"]},
        ),
        migrations.AddIndex(
            model_name="orderticketintake",
            index=models.Index(fields=["expiry"], name="orders_oti_expiry_idx"),
        ),
        migrations.AddIndex(
            model_name="orderticketintake",
            index=models.Index(
                fields=["vm_id", "vm_generation"],
                name="orders_oti_vm_gen_idx",
            ),
        ),
    ]
