"""§25 — bookkeeping for a migration that STRANDS its VM in `Migrating`.

Adds four `MigrationJob` columns and backfills NOTHING.

`failed_from_state` is the PERMIT input to an automatic source restore:
it says whether a failed migration ever entered `DestActivating`, the
only state that calls `effects.kbs_activate_dest` and therefore the only
one that moves the KBS `VmState` to `Migrating{new_gen, dest}`. Once the
KBS has moved, no admin route moves it back — `process_admin_activate`
is forward-only and refuses every non-`Active` current state — so the
source can never unlock again and a "restore" would produce a guest that
boots and hangs forever.

**Why there is no backfill.** `_fail_migration` already writes the state
into the free-text `reason` (`f"{job.state}:{…}"`), so a backfill could
be parsed out of it. It is deliberately NOT done: this column is a
security PERMIT, and a permit must originate from a field that only
`_fail_migration` writes. `reason` is a human string that has carried
hand-written values (`"cancelled by …"`) and is editable wherever a row
is. Leaving every pre-existing job blank makes them all UNPROVABLE, which
fails CLOSED — the sweep will never auto-restore one, and an operator
gets the loud `unknown-failure-state` verdict instead. The reason prefix
is still consulted, but only as a VETO (it can block a restore, never
authorise one).

Run `manage.py migrate` BEFORE rolling the vali image: the new sweep
reads these columns on its first tick.
"""

from __future__ import annotations

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("orchestration", "0012_rebootrecovery_host"),
    ]

    operations = [
        migrations.AddField(
            model_name="migrationjob",
            name="failed_from_state",
            field=models.CharField(
                blank=True,
                choices=[
                    ("draining", "Draining"),
                    ("quiescing", "Quiescing"),
                    ("snapshotting", "Snapshotting"),
                    ("uploading", "Uploading"),
                    ("fencing", "Fencing"),
                    ("awaiting_source_ack", "Awaiting source ack"),
                    ("dest_activating", "Dest activating"),
                    ("done", "Done"),
                    ("failed", "Failed"),
                ],
                default="",
                max_length=32,
            ),
        ),
        migrations.AddField(
            model_name="migrationjob",
            name="strand_recovery_state",
            field=models.CharField(
                choices=[
                    ("none", "None"),
                    ("source_restored", "Source restored"),
                    ("redriven", "Re-driven to dest"),
                ],
                default="none",
                max_length=16,
            ),
        ),
        migrations.AddField(
            model_name="migrationjob",
            name="strand_recovery_at",
            field=models.DateTimeField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name="migrationjob",
            name="strand_recovery_reason",
            field=models.CharField(blank=True, default="", max_length=256),
        ),
    ]
