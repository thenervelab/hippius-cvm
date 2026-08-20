# §23 — audit columns for the served-receipt sequence RE-BASELINE.
#
# The guest's `monotonic_seq` is monotonic only within one boot (it lives
# in `agent-tenant-telemetry`'s RAM-resident `ReceiptBuilder`), so every
# reboot restarts it at 1 and the only-ever-advancing watermark silently
# stopped billing the VM until it climbed back. The meter now re-baselines
# the sequence watermark on a restart; these two columns record that a
# re-baseline happened, so a money-path event is never invisible and a
# restart count far above a VM's real reboot count is greppable.
#
# Additive + defaulted: existing rows land on `0` ("never re-baselined"),
# which is the truth for every row written before this. Nothing is
# re-attributed and no `UsageAccrual` row is touched. The meter WRITES
# these columns (they are in its `update_fields`), so this migration must
# be applied before the image that contains it starts metering.

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('scheduler', '0008_vmbillingassignment'),
    ]

    operations = [
        migrations.AddField(
            model_name='receiptwatermark',
            name='seq_restarts',
            field=models.BigIntegerField(default=0),
        ),
        migrations.AddField(
            model_name='receiptwatermark',
            name='last_restart_at_unix',
            field=models.BigIntegerField(default=0),
        ),
    ]
