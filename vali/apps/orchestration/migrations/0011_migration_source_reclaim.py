"""§25 source-side reclaim bookkeeping (P9/#15).

Adds the three `MigrationJob` fields the post-`Done` reclaim sweep drives,
then marks every ALREADY-EXISTING job `skipped`.

Why the backfill is `skipped` and not `pending`: the sweep dispatches a
`destroy` order at the SOURCE miner. Leaving historical jobs `pending`
would, on the first tick after deploy, fire reclaims for migrations that
completed weeks ago — against VMs that may since have been decommissioned,
relaunched, or migrated back onto that same host. None of those artifacts
were reclaimed by THIS code path, so none of them are its responsibility;
an operator sweep is the right tool for the backlog. Only migrations that
complete after this deploy carry a reclaim vali actually observed.
"""

from __future__ import annotations

from django.db import migrations, models


def _skip_preexisting_jobs(apps, schema_editor):
    MigrationJob = apps.get_model("orchestration", "MigrationJob")
    MigrationJob.objects.all().update(
        source_reclaim_state="skipped",
        source_reclaim_reason="job-predates-source-reclaim",
    )


def _noop_reverse(apps, schema_editor):
    """No inverse: the forward step only stamps bookkeeping fields that
    the reverse `RemoveField`s drop wholesale."""


class Migration(migrations.Migration):

    dependencies = [
        ("orchestration", "0010_rebootrecovery_consecutive_wedged"),
    ]

    operations = [
        migrations.AddField(
            model_name="migrationjob",
            name="source_reclaim_state",
            field=models.CharField(
                choices=[
                    ("pending", "Pending"),
                    ("reclaimed", "Reclaimed"),
                    ("skipped", "Skipped"),
                ],
                default="pending",
                max_length=16,
            ),
        ),
        migrations.AddField(
            model_name="migrationjob",
            name="source_reclaim_at",
            field=models.DateTimeField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name="migrationjob",
            name="source_reclaim_reason",
            field=models.CharField(blank=True, default="", max_length=256),
        ),
        migrations.RunPython(_skip_preexisting_jobs, _noop_reverse),
    ]
