"""Storage-aware placement — DATA-disk columns on `MinerCapacity`.

Schema: additive only, every column nullable (NULL = unknown), so the
running old image — whose INSERTs omit them — keeps working until it is
rolled (same reasoning as 0012/0013). No data migration: no host has a
disk figure until its agent emits heartbeat v4 or an operator seeds
`total_disk_gb`, and unknown is exactly what NULL says.

Reversible: dropping the columns loses only disk policy / report state.
"""

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('scheduler', '0014_capacity_v2_rebackfill'),
    ]

    operations = [
        migrations.AddField(
            model_name='minercapacity',
            name='declared_disk_gb_budget',
            field=models.PositiveIntegerField(blank=True, default=None, null=True),
        ),
        migrations.AddField(
            model_name='minercapacity',
            name='disk_reported_at',
            field=models.DateTimeField(blank=True, default=None, null=True),
        ),
        migrations.AddField(
            model_name='minercapacity',
            name='earned_disk_gb',
            field=models.PositiveIntegerField(blank=True, default=None, null=True),
        ),
        migrations.AddField(
            model_name='minercapacity',
            name='reported_data_disk_available_gb',
            field=models.PositiveIntegerField(blank=True, default=None, null=True),
        ),
        migrations.AddField(
            model_name='minercapacity',
            name='reported_data_disk_total_gb',
            field=models.PositiveIntegerField(blank=True, default=None, null=True),
        ),
        migrations.AddField(
            model_name='minercapacity',
            name='reported_staging_disk_available_gb',
            field=models.PositiveIntegerField(blank=True, default=None, null=True),
        ),
        migrations.AddField(
            model_name='minercapacity',
            name='total_disk_gb',
            field=models.PositiveIntegerField(blank=True, default=None, null=True),
        ),
    ]
