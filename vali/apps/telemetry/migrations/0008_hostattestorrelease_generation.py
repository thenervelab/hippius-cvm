"""Tag every host-attestor release with the SEV-SNP generation it is for.

FORWARD-safe and additive. The attestor launch measurement covers the
VMSA, which carries the vCPU model's CPUID signature, so the same blackbox
UKI measures differently on Genoa / Turin / Milan. The {current, previous}
grace window used to be ONE fleet-wide window over every active release,
so admitting a third generation evicted the oldest one's measurement and
its hosts went `measurement-stale` (2026-09-25). The window is now kept per
generation (`release_service.desired_releases(generation)`).

Rollout: the column carries a DB default of "" so a pod still on the
previous image INSERTs without it; old pods ignore it on read.

Backfill: the measurements known to be live on 2026-09-25 are tagged by
FULL measurement. Anything else stays "" (the legacy group — behaves
exactly like the old fleet-wide window). The backfill only writes
`generation`; it never touches `is_active`.
"""

from django.db import migrations, models

_KNOWN_GENERATIONS: dict[str, str] = {
    # Genoa — reenroll + 0.0.1-blackbox-e2e.
    "107e7a10a5f783b8920a7fccbdcbfc41f9511dd32211b72c8ffa4d8fdd803da6ba276b5419f000a51f44b7337f03fbd3": "genoa",
    "faa6e034b8d494413596b8864187e1477d6fac57fa8a0119865e5e84c05091e12b8caac1b86bd3ea52ea49119ca426d5": "genoa",
    # Turin — reenroll + 0.0.1-blackbox-turin.
    "ce4d2921c9e767f78e70ba895e58f009bae4fe248034167e31c47cb99ab25ef3e08ac4ecc08d5f7408696a599eac550a": "turin",
    "feb4d0f077decebc5bc965cac7c46a6a07309c6a43aae71382c87366b880591dd58d7be6cd3a2683c7d2ea99fbfdcdc9": "turin",
    # Milan — reenroll.
    "51d83b4cdb3bff0558d43cacc539a4ca9a23f1dc7fa21eab5492868af3520491630b9f631dc99b9bd38bfa6e5ed0048c": "milan",
}


def _backfill(apps, schema_editor):  # noqa: ANN001 — Django migration signature
    release = apps.get_model("telemetry", "HostAttestorRelease")
    for measurement, generation in _KNOWN_GENERATIONS.items():
        release.objects.filter(measurement=measurement, generation="").update(
            generation=generation
        )


def _untag(apps, schema_editor):  # noqa: ANN001 — Django migration signature
    """Reverse is a no-op: dropping the column (the AddField reverse) removes
    the tags anyway."""


class Migration(migrations.Migration):

    dependencies = [
        ('telemetry', '0007_live_attestation_chain_epoch'),
    ]

    operations = [
        migrations.AddField(
            model_name='hostattestorrelease',
            name='generation',
            field=models.CharField(blank=True, choices=[('milan', 'Milan (EpycMilan)'), ('genoa', 'Genoa (EpycGenoa)'), ('turin', 'Turin (EpycTurin)')], db_default='', default='', help_text='SEV-SNP CPU generation this measurement is for (the VMSA carries the vCPU CPUID signature, so one UKI measures differently per generation). The {current, previous} grace window is kept per generation. Empty = legacy/untagged group.', max_length=8),
        ),
        migrations.RunPython(_backfill, _untag),
    ]
