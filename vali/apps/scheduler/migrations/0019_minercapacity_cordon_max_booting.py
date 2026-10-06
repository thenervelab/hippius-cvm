"""Operator placement controls on `MinerCapacity`: the per-miner boot cap
override and the cordon.

Schema: additive only. The two nullable columns need nothing from an old
image's INSERTs; `cordon_reason` carries a DB default for the same reason
(the running image omits it until it is rolled). No data migration.

Reversible: dropping the columns forgets every override and cordon (the
audit rows in `MinerCapacityAudit` keep the history).
"""

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('scheduler', '0018_host_health'),
    ]

    operations = [
        migrations.AddField(
            model_name='minercapacity',
            name='max_booting',
            field=models.PositiveIntegerField(blank=True, default=None, null=True),
        ),
        migrations.AddField(
            model_name='minercapacity',
            name='cordoned_at',
            field=models.DateTimeField(blank=True, default=None, null=True),
        ),
        migrations.AddField(
            model_name='minercapacity',
            name='cordon_reason',
            field=models.CharField(blank=True, db_default='', default='', max_length=256),
        ),
    ]
