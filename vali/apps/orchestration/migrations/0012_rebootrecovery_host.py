"""§25 — reboot-recovery bookkeeping is scoped to the HOST it describes.

Schema: `RebootRecovery.host`, the miner whose relaunch attempts, backoff
window and debounce counters the row holds. Data: one narrow backfill
pass that stamps it, and re-scopes the rows a completed migration ALREADY
poisoned.

Every field on that row is host-scoped — an attempt is an attempt against
one host, a backoff window paces retries on one host — but nothing said
which host, and no migration path reset any of it. A VM that burned its
relaunch budget on a flaky SOURCE therefore arrived at a healthy
DESTINATION already at the cap, `last_outcome="attempts-exhausted"`, and
could never be reboot-recovered there: it runs fine until the destination
reboots, at which point the recovery that exists for exactly that event
refuses to act.

The data pass is the half that touches live rows, so — as in
`scheduler/0010_placement_migrated_custody` — every uncertainty is a SKIP:

  * every row is STAMPED with its VM's current `Vm.host`. A VM with no
    host is left unstamped (`""`), which the scan adopts later without
    resetting anything.
  * a row's counters are RESET only on POSITIVE evidence that they were
    earned somewhere else: `attempts > 0`, a `last_relaunch_at` to date
    them by, and a `Done` `MigrationJob` for this VM whose destination is
    the VM's current host and which FINISHED AFTER that last relaunch. The
    attempts were burned before the VM moved, on the host it left.
  * anything short of that keeps its counters. Under uncertainty the
    fail-safe direction for an attempt CAP is to KEEP it — a wrongly-kept
    cap is one VM an operator must clear by hand, a wrongly-cleared one is
    a relaunch budget silently re-issued fleet-wide.

`seen_running` is never touched: it records that this VM's domain was
once observed running, which a host change does not falsify (see the
model docstring).

Without the data pass the fix reaches only FUTURE migrations and every VM
moved before it stays un-recoverable on the host it now runs on.
"""

from django.db import migrations, models


def _forward(apps, schema_editor):
    RebootRecovery = apps.get_model("orchestration", "RebootRecovery")
    MigrationJob = apps.get_model("orchestration", "MigrationJob")

    for rec in RebootRecovery.objects.select_related("vm"):
        host = rec.vm.host or ""
        fields = {"host": host}
        poisoned = (
            host
            and rec.attempts
            and rec.last_relaunch_at is not None
            and MigrationJob.objects.filter(
                vm_id=rec.vm_id,
                state="done",
                dest_node_id=host,
                finished_at__gt=rec.last_relaunch_at,
            ).exists()
        )
        if poisoned:
            fields.update(
                attempts=0,
                next_attempt_at=None,
                consecutive_down=0,
                consecutive_wedged=0,
                last_relaunch_at=None,
                last_outcome="host-changed:backfill",
                version=rec.version + 1,
            )
        RebootRecovery.objects.filter(vm_id=rec.vm_id).update(**fields)


class Migration(migrations.Migration):

    dependencies = [
        ("lifecycle", "0010_vm_base_image"),
        ("orchestration", "0011_migration_source_reclaim"),
    ]

    operations = [
        migrations.AddField(
            model_name="rebootrecovery",
            name="host",
            field=models.CharField(blank=True, default="", max_length=256),
        ),
        # Irreversible by design: the reverse drops the column, and the
        # counters the forward pass cleared cannot be reconstructed from
        # it. Re-inflating a cap that was proven to belong to a host the
        # VM has left would re-brick exactly the VMs this repairs, so the
        # data half reverses to a no-op rather than to a guess.
        migrations.RunPython(_forward, migrations.RunPython.noop),
    ]
