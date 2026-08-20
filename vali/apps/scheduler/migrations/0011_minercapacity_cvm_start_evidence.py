"""§23 — the OBSERVED SEV-SNP start-capability ledger on `MinerCapacity`.

Pure schema, no data migration. Five nullable/defaulted columns recording
what vali WATCHED happen the last time it asked this host to start a
confidential guest (see `apps.scheduler.cvm_capability`):

  * `cvm_last_ok_at`             — last observed CVM start SUCCESS
  * `cvm_last_fail_at`           — last observed CVM start FAILURE
  * `cvm_fail_streak`            — CONSECUTIVE in-window failures with no
                                   success in between (0 after any success)
  * `cvm_fail_streak_started_at` — when the current streak began (audit)
  * `cvm_last_fail_reason`       — closed vali-side vocabulary, never miner bytes

No backfill is possible and none is wanted. The ledger records
observations, and vali made none before this migration; inventing a
timestamp would manufacture exactly the unearned assertion the whole
change exists to remove. Every existing row therefore starts NULL/0,
which classifies as `UNKNOWN` — eligible but unproven, the documented
fail-safe default — so the fleet's admission behaviour is byte-identical
the instant this lands and only diverges once a real start outcome is
observed.

Deploy ordering: this migration MUST be applied before the image that
reads the columns serves traffic (the standard vali `migrate`-then-roll
order). It is additive-only and safe to apply to a running old image —
nothing writes or reads these columns until the new code is live.
"""

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("scheduler", "0010_placement_migrated_custody"),
    ]

    operations = [
        migrations.AddField(
            model_name="minercapacity",
            name="cvm_last_ok_at",
            field=models.DateTimeField(blank=True, default=None, null=True),
        ),
        migrations.AddField(
            model_name="minercapacity",
            name="cvm_last_fail_at",
            field=models.DateTimeField(blank=True, default=None, null=True),
        ),
        migrations.AddField(
            model_name="minercapacity",
            name="cvm_fail_streak",
            field=models.PositiveIntegerField(default=0),
        ),
        migrations.AddField(
            model_name="minercapacity",
            name="cvm_fail_streak_started_at",
            field=models.DateTimeField(blank=True, default=None, null=True),
        ),
        migrations.AddField(
            model_name="minercapacity",
            name="cvm_last_fail_reason",
            field=models.CharField(blank=True, default="", max_length=64),
        ),
    ]
