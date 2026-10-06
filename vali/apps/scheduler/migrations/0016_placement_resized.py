"""`Placement.status=resized` / `failure_source=resize` — a resize closes
the VM's placement and opens one at the new flavor
(`service.swap_placement_class`).

Choices only: no schema change in the database (Django records the new
choices; the columns are unchanged).
"""

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('scheduler', '0015_disk_budget'),
    ]

    operations = [
        migrations.AlterField(
            model_name='placement',
            name='failure_source',
            field=models.CharField(choices=[('scheduler_drain', 'Scheduler drain (§13 re-eval)'), ('launch', 'Launch outcome'), ('release', 'VM released'), ('manual', 'Manual /fail'), ('migration', 'Migrated away'), ('resize', 'Resized'), ('legacy', 'Legacy (unattributed)')], db_default='legacy', default='legacy', max_length=16),
        ),
        migrations.AlterField(
            model_name='placement',
            name='status',
            field=models.CharField(choices=[('pending', 'Pending'), ('bound', 'Bound'), ('failed', 'Failed'), ('migrated', 'Migrated away'), ('resized', 'Resized')], default='pending', max_length=32),
        ),
    ]
