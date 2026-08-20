"""Post-§25 NetBird overlay verification state (P9/#17).

A §25 cold migration can leave the tenant off the overlay permanently
(NetBird GCs the `ephemeral: True` peer after ~10 min offline and the
launch-time one-off setup key cannot re-enrol the destination) with
NOTHING reporting it. These two fields carry the signal:
`netbird_status` (""/pending/ok/lost) and the `pending` deadline.

Additive + nullable/blank-defaulted, so existing rows backfill to "no
verification pending" — which is exactly right for a VM that has not
been migrated since the sweep landed.
"""

from __future__ import annotations

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("lifecycle", "0007_vm_signing_generation"),
    ]

    operations = [
        migrations.AddField(
            model_name="vm",
            name="netbird_status",
            field=models.CharField(
                blank=True,
                choices=[
                    ("pending", "Verification pending"),
                    ("ok", "On the overlay"),
                    ("lost", "Off the overlay"),
                ],
                db_index=True,
                default="",
                max_length=16,
            ),
        ),
        migrations.AddField(
            model_name="vm",
            name="netbird_verify_deadline",
            field=models.DateTimeField(blank=True, null=True),
        ),
    ]
