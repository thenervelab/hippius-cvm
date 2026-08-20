"""Power state — the stop/start axis, orthogonal to the lifecycle `state`.

`state` mirrors `kbs_core::lifecycle::VmState`, which the KBS checks before
every release; a stopped VM stays `active` there so it can unlock again when
it starts. Powering off is therefore a separate axis, not a lifecycle
transition, and it gets its own column.

Every existing row is `running`: the only VMs in the table predate any stop
operation, and a VM that is not `active` (decommissioning / destroyed) never
reads this field.
"""

from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [("lifecycle", "0011_vm_launch_abandoned")]

    operations = [
        migrations.AddField(
            model_name="vm",
            name="power_state",
            field=models.CharField(
                choices=[
                    ("running", "Running"),
                    ("stopping", "Stopping"),
                    ("stopped", "Stopped"),
                    ("starting", "Starting"),
                ],
                db_index=True,
                default="running",
                max_length=16,
            ),
        ),
        migrations.AddField(
            model_name="vm",
            name="power_state_at",
            field=models.DateTimeField(blank=True, null=True),
        ),
    ]
