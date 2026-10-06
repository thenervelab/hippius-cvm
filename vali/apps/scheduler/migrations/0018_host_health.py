"""SEV-SNP host health — the v5 heartbeat report on `MinerCapacity`.

Schema: additive only, every column nullable (NULL = no v5 report yet), so
the running old image — whose INSERTs omit them — keeps working until it is
rolled (same reasoning as 0015). No data migration.

Reversible: dropping the columns loses only the latest report.
"""

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('scheduler', '0017_placement_data_disk_gb'),
    ]

    operations = [
        migrations.AddField(
            model_name='minercapacity',
            name='host_health_reported_at',
            field=models.DateTimeField(blank=True, default=None, null=True),
        ),
        migrations.AddField(
            model_name='minercapacity',
            name='reported_cpus_offline',
            field=models.PositiveIntegerField(blank=True, default=None, null=True),
        ),
        migrations.AddField(
            model_name='minercapacity',
            name='reported_df_flush_failures',
            field=models.PositiveIntegerField(blank=True, default=None, null=True),
        ),
        migrations.AddField(
            model_name='minercapacity',
            name='reported_snp_enabled',
            field=models.BooleanField(blank=True, default=None, null=True),
        ),
        migrations.AddField(
            model_name='minercapacity',
            name='reported_snp_launches_since_boot',
            field=models.PositiveIntegerField(blank=True, default=None, null=True),
        ),
    ]
