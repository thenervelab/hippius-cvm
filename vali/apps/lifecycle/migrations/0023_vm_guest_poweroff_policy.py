"""Guest-poweroff policy on `Vm` (`apps.orchestration.power_policy`).

Schema: additive only. The three policy columns are NOT NULL with a
`db_default`, so an older image's INSERTs (which omit them) still satisfy
the constraint during a roll; `power_stopped_by_guest_at` / `power_guest_ack_at` are nullable.
"""

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("lifecycle", "0022_vm_placement_group"),
    ]

    operations = [
        migrations.AddField(
            model_name="vm",
            name="power_stopped_by_guest_at",
            field=models.DateTimeField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name="vm",
            name="power_guest_ack_at",
            field=models.DateTimeField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name="vm",
            name="on_guest_poweroff",
            field=models.CharField(
                choices=[("restart", "restart"), ("stop", "stop")],
                db_default="restart",
                default="restart",
                max_length=8,
            ),
        ),
        migrations.AddField(
            model_name="vm",
            name="on_guest_poweroff_effective",
            field=models.CharField(
                choices=[("restart", "restart"), ("stop", "stop")],
                db_default="restart",
                default="restart",
                max_length=8,
            ),
        ),
        migrations.AddField(
            model_name="vm",
            name="on_guest_poweroff_effective_host",
            field=models.CharField(blank=True, db_default="", default="", max_length=256),
        ),
    ]
