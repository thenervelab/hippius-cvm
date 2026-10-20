"""The storage requirement's lapse clock: `unhealthy_since`, `lapsed_since`.

Schema only, additive (two nullable timestamps). No data step: the table is
only written while VALI_COMPUTE_REQUIRES_STORAGE is on; a row recorded
before this migration without storage starts its debounce at its next read.
"""

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('scheduler', '0023_family_storage_state'),
    ]

    operations = [
        migrations.AddField(
            model_name='familystoragestate',
            name='lapsed_since',
            field=models.DateTimeField(blank=True, default=None, null=True),
        ),
        migrations.AddField(
            model_name='familystoragestate',
            name='unhealthy_since',
            field=models.DateTimeField(blank=True, default=None, null=True),
        ),
    ]
