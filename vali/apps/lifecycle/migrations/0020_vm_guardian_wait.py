"""`Vm.guardian_wait_{reason,since,at,signed_at,cleared_at}` — an M1/M2 VM waiting on its
customer key guardian (the signed `awaiting-guardian` vm-progress
milestone). `guardian_wait_reason` is NOT NULL with `db_default=""` so a
pod on the previous image keeps inserting rows; the two timestamps are
nullable. No backfill: no VM has waited yet.
"""

from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("lifecycle", "0019_customer_keys"),
    ]

    operations = [
        migrations.AddField(
            model_name="vm",
            name="guardian_wait_at",
            field=models.DateTimeField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name="vm",
            name="guardian_wait_reason",
            field=models.CharField(blank=True, db_default="", default="", max_length=64),
        ),
        migrations.AddField(
            model_name="vm",
            name="guardian_wait_since",
            field=models.DateTimeField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name="vm",
            name="guardian_wait_signed_at",
            field=models.DateTimeField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name="vm",
            name="guardian_wait_cleared_at",
            field=models.DateTimeField(blank=True, null=True),
        ),
    ]
