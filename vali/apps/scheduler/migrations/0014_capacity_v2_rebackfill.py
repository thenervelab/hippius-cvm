"""Re-run the 0013 trust-class backfill.

0013 ran BEFORE its image rolled. An anchor seeded through the old image
during that window left a fully anchored row `earned`. This is the first
migration shipped with code that READS `trust_class`, so it repeats the
same certain inference once more: a complete operator anchor ⇒
`operator`. Idempotent; it never demotes a row.
"""

from django.db import migrations


def _forward(apps, schema_editor):
    MinerCapacity = apps.get_model("scheduler", "MinerCapacity")
    rows = MinerCapacity.objects.filter(
        total_memory_mb__isnull=False, total_cpus__isnull=False, trust_class="earned"
    )
    promoted = sorted(rows.values_list("miner_node_id", flat=True))
    rows.update(trust_class="operator")
    if promoted:
        # Named, so a row an operator had deliberately set `earned` is
        # visible in the migrate output and can be set back.
        print(f"  0014: promoted to operator: {', '.join(promoted)}")


class Migration(migrations.Migration):
    dependencies = [
        ("scheduler", "0013_capacity_v2"),
    ]

    operations = [
        migrations.RunPython(_forward, migrations.RunPython.noop),
    ]
