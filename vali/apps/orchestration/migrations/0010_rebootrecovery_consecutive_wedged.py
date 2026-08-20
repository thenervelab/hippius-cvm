"""Debounce counter for reboot-recovery's SECOND trigger: a guest that
has gone silent behind a still-`running` libvirt domain.

Its own counter rather than a reuse of `consecutive_down`, because the
two conditions are mutually exclusive per poll (`running is False` vs
`running is True`) — sharing one would let alternating polls accumulate
a relaunch that neither condition earned.

Backfills to 0 on every existing row (no VM starts part-way through a
debounce), and the trigger it serves is default-OFF
(`VALI_REBOOT_RECOVERY_ON_WEDGED_GUEST`).
"""

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('orchestration', '0009_measurement_class'),
    ]

    operations = [
        migrations.AddField(
            model_name='rebootrecovery',
            name='consecutive_wedged',
            field=models.PositiveIntegerField(default=0),
        ),
    ]
