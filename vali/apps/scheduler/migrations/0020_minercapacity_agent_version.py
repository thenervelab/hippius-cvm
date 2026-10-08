"""miner-agent release tag — the v6 heartbeat's `agent_version` on `MinerCapacity`.

Schema: additive only. `agent_version` is NOT NULL with `db_default=''`
('' = no v6 report yet) and `agent_version_reported_at` is nullable, so the
running old image — whose INSERTs omit both — keeps working until it is
rolled (same reasoning as 0018). No data migration.

Reversible: dropping the columns loses only the latest reported tag.
"""

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('scheduler', '0019_minercapacity_cordon_max_booting'),
    ]

    operations = [
        migrations.AddField(
            model_name='minercapacity',
            name='agent_version',
            field=models.CharField(blank=True, db_default='', default='', max_length=32),
        ),
        migrations.AddField(
            model_name='minercapacity',
            name='agent_version_reported_at',
            field=models.DateTimeField(blank=True, default=None, null=True),
        ),
    ]
