"""`Vm.key_mode` / `guardian_endpoint` / `guardian_pubkey` — customer-held keys pin.

Deploy ordering: the migrate Job runs BEFORE the Deployment rolls, so old
pods keep INSERTing Vm rows that omit the three columns. An ORM-only
`default` is applied for the duration of the `ALTER TABLE` and then dropped,
after which those INSERTs would fail on NOT NULL. `db_default` makes the
server fill the value for them (same pattern as
`scheduler/0012_placement_failure_source.py`). Reversible: dropping the
columns loses only data the old image never had.
"""

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('lifecycle', '0018_vm_power_stop_ordered_at'),
    ]

    operations = [
        migrations.AddField(
            model_name='vm',
            name='guardian_endpoint',
            field=models.CharField(blank=True, default='', db_default='', max_length=259),
        ),
        migrations.AddField(
            model_name='vm',
            name='guardian_pubkey',
            field=models.CharField(blank=True, default='', db_default='', max_length=64),
        ),
        migrations.AddField(
            model_name='vm',
            name='key_mode',
            field=models.CharField(default='hippius', db_default='hippius', max_length=16),
        ),
    ]
