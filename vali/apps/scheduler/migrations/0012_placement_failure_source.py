"""`Placement.failure_source` — WHO ended the row, as a column.

Schema: one defaulted `CharField` (`legacy`). Data: one narrow backfill.

`Placement.reason` is free text written by five code paths — the §13
re-eval (`drain:<cause>`), the launch path (the miner-agent's outcome
string), the destroy paths (`released:vm-destroyed`), a §25 hand-over
(`migrated:<job_id>`) and the root-only `/fail` body (anything). The
operator readout must show the node's refusals and NOT a `/fail` body
that happens to spell `miner-rejected`; the value of `reason` cannot tell
those apart, so from this migration on every write site stamps its own
provenance and the readout selects on it.

Backfill — deliberately what is CERTAIN, nothing that is inferred:

  * `status = migrated` rows → `migration`. Only two writers ever produce
    that status (`service.move_placement_to_node` and the 0010 custody
    backfill, `reason = "migrated:backfill-0010"`); the status itself is
    the provenance, no text is read.
  * every other row keeps `legacy`. A FAILED row whose reason starts with
    `drain:` is almost certainly a scheduler drain — but a `/fail` body
    could have spelled it, and "almost certainly" is exactly the guess
    this column exists to remove. Legacy FAILED rows are therefore never
    surfaced as refusals; the operator readout starts counting from the
    first event written by the new code.

Deploy ordering: additive column with a server-side default, safe to apply
to a running old image (it never reads or writes the column). The default
must be a DATABASE default (`db_default`), not only the ORM `default`: an
ORM-only default is applied by Django for the duration of the `ALTER TABLE`
and then dropped, after which the old image's INSERTs — which omit the
column — would fail on NOT NULL until every old worker is rolled. With
`db_default` the server fills `legacy` for them. The new image must not
serve before the column exists (standard `migrate`-then-roll). Reversible:
dropping the column loses only the provenance.
"""

from django.db import migrations, models


def _forward(apps, schema_editor):
    Placement = apps.get_model("scheduler", "Placement")
    Placement.objects.filter(status="migrated").update(failure_source="migration")


def _reverse(apps, schema_editor):
    # The column is dropped by the reversed AddField; nothing to undo.
    pass


class Migration(migrations.Migration):
    dependencies = [
        ("scheduler", "0011_minercapacity_cvm_start_evidence"),
    ]

    operations = [
        migrations.AddField(
            model_name="placement",
            name="failure_source",
            field=models.CharField(
                choices=[
                    ("scheduler_drain", "Scheduler drain (§13 re-eval)"),
                    ("launch", "Launch outcome"),
                    ("release", "VM released"),
                    ("manual", "Manual /fail"),
                    ("migration", "Migrated away"),
                    ("legacy", "Legacy (unattributed)"),
                ],
                default="legacy",
                db_default="legacy",
                max_length=16,
            ),
        ),
        migrations.RunPython(_forward, _reverse),
    ]
