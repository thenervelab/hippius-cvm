"""The storage requirement's per-family state (`FamilyStorageState`).

Schema only, additive: a new table nothing reads until
`VALI_COMPUTE_REQUIRES_STORAGE` is on; no data step.
"""

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('scheduler', '0022_minercapacity_auto_approval'),
    ]

    operations = [
        migrations.CreateModel(
            name='FamilyStorageState',
            fields=[
                ('family', models.CharField(max_length=64, primary_key=True, serialize=False)),
                ('compute_node_ids', models.JSONField(default=list)),
                ('storage_counted', models.PositiveIntegerField(default=0)),
                ('has_storage', models.BooleanField(default=False)),
                ('storage_detail', models.JSONField(default=list)),
                ('last_healthy_at', models.DateTimeField(blank=True, default=None, null=True)),
                ('first_seen_at', models.DateTimeField()),
                ('refreshed_at', models.DateTimeField()),
                ('block_hash', models.CharField(blank=True, default='', max_length=66)),
            ],
            options={
                'ordering': ['family'],
            },
        ),
    ]
