"""`Placement.data_disk_gb` — a resized VM's real data disk, when it is not
its flavor's (the disk never follows a resize). Nullable, additive: NULL
is the flavor's disk, which every existing row and the old image's
INSERTs mean.
"""

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('scheduler', '0016_placement_resized'),
    ]

    operations = [
        migrations.AddField(
            model_name='placement',
            name='data_disk_gb',
            field=models.PositiveIntegerField(blank=True, null=True),
        ),
    ]
