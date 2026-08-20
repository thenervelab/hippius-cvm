"""Drop the `Succeeded ⇒ measurement_hex != ""` DB CHECK.

The SNP launch digest folds OVMF + vcpus — launch-time inputs the
bake cannot know; the miner's `tenant-preflight` computes the
authoritative value AFTER the bake. The constraint made every real
in-cluster bake fail at finalize (observed live 2026-06-10).
"""

from django.db import migrations


class Migration(migrations.Migration):
    dependencies = [
        ("tenant_bake", "0001_initial"),
    ]

    operations = [
        migrations.RemoveConstraint(
            model_name="tenantbake",
            name="tenant_bake_succeeded_requires_measurement",
        ),
    ]
