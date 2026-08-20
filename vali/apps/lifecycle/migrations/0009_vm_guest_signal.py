"""In-guest liveness watermark — the signal that a running libvirt
domain is NOT.

Proved live on miner-2 (2026-08-12): a golden VM whose §22 measurement
had been evicted from the allowlist rebooted, its KEK release was
refused (403), and it never left its initramfs — while `state=active`,
`boot_phase=running` and the libvirt domain stayed `running`. Every
probe the control plane had reported GREEN.

`guest_signal_at` records the newest signal that could ONLY have come
from inside a running guest (a §23 served receipt, or a §322 live
attestation); `guest_signal_kind` records which. Unlike `boot_phase`
these GO STALE, which is what makes a wedged guest visible.

Additive + nullable/blank-defaulted: existing rows backfill to NULL,
which classifies as `unknown` — explicitly NOT `wedged`, and never an
automated-action trigger. Every live VM re-arms itself within one
telemetry cadence (~60 s) after this ships.
"""

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('lifecycle', '0008_vm_netbird_status'),
    ]

    operations = [
        migrations.AddField(
            model_name='vm',
            name='guest_signal_at',
            field=models.DateTimeField(blank=True, db_index=True, null=True),
        ),
        migrations.AddField(
            model_name='vm',
            name='guest_signal_kind',
            field=models.CharField(blank=True, default='', max_length=32),
        ),
    ]
