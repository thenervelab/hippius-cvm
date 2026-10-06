"""`Vm.boot_started_at` — when the VM's current boot began.

The clock for the boot-stall verdict (`apps.lifecycle.boot_stall`). Nullable
with no backfill: the verdict falls back to `created_at` for existing rows.
"""

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("lifecycle", "0015_vm_netbird_peer_binding"),
    ]

    operations = [
        migrations.AddField(
            model_name="vm",
            name="boot_started_at",
            field=models.DateTimeField(blank=True, null=True),
        ),
    ]
