"""`DecommissionJob.data_death` — what a §24 erase achieved for the data.

NOT NULL with `db_default=""`, so a pod still on the previous image (which
never names the column in its INSERT) keeps working during the roll.

Backfill: every job that already erased (`kek_erased_at` set) predates
customer-held keys, so its VM was M0 and the Transit destroy was a real
crypto-erase — `crypto-erased`. Nothing else is touched.
"""

from django.db import migrations, models


def _backfill(apps, schema_editor):  # noqa: ARG001 — Django's RunPython signature
    DecommissionJob = apps.get_model("orchestration", "DecommissionJob")
    DecommissionJob.objects.filter(kek_erased_at__isnull=False, data_death="").update(
        data_death="crypto-erased"
    )


class Migration(migrations.Migration):
    dependencies = [
        ("orchestration", "0024_kbs_audit_entry_full_reason"),
    ]

    operations = [
        migrations.AddField(
            model_name="decommissionjob",
            name="data_death",
            field=models.CharField(blank=True, db_default="", default="", max_length=32),
        ),
        migrations.RunPython(_backfill, migrations.RunPython.noop),
    ]
