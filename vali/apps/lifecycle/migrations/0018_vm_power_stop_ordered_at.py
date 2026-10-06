"""`Vm.power_stop_ordered_at` — the `power_state_at` of a `stopped` reached
by a completed power stop order.

Nullable, no backfill: an existing `stopped` VM reads as not stopped by an
order, the fail-safe side for the one reader (`vali_swap_vm_initrd --revert`
of a relaunched swap), which then asks for a fresh power stop. It is only
meaningful while it equals `power_state_at`, so a pod on the previous image
(which never writes it but always stamps `power_state_at`) cannot leave it
describing a later transition.
"""

from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("lifecycle", "0017_vm_power_state_off"),
    ]

    operations = [
        migrations.AddField(
            model_name="vm",
            name="power_stop_ordered_at",
            field=models.DateTimeField(blank=True, null=True),
        ),
    ]
