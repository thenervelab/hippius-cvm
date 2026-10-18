"""Automatic miner approval on `MinerCapacity`: the revocation and the soak.

Schema only, additive: two nullable timestamps and a CharField with a DB
default, so the running image's INSERTs need nothing new. No data step: no
row is revoked and no soak is in progress until the new image writes one,
and the grandfathered rows (0021) stay approved.
"""

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('scheduler', '0021_minercapacity_approval'),
    ]

    operations = [
        migrations.AddField(
            model_name='minercapacity',
            name='approval_soak_since',
            field=models.DateTimeField(blank=True, default=None, null=True),
        ),
        migrations.AddField(
            model_name='minercapacity',
            name='revoked_at',
            field=models.DateTimeField(blank=True, default=None, null=True),
        ),
        migrations.AddField(
            model_name='minercapacity',
            name='revoked_by',
            field=models.CharField(blank=True, db_default='', default='', max_length=128),
        ),
    ]
