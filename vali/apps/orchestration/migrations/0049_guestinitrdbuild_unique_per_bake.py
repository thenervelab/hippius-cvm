# A guest initrd build is unique per (initrd, base bake), no longer per
# initrd: two bakes sharing one upstream kernel + initrd carry
# byte-identical builds of a release, each on its own rootfs / verity.
#
# Live-safe: every existing row has a distinct initrd_sha256 (the old
# unique), so (initrd_sha256, source_bake_id) holds already — no data is
# rewritten. The new constraint is added BEFORE the old unique is dropped,
# so the table is never without one. The composite's leading column serves
# the by-initrd lookups, so no separate index is kept.
#
# A plain atomic migration, no CONCURRENTLY: the table holds a few dozen
# rows, so the ACCESS EXCLUSIVE lock of each step lasts milliseconds.

from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("orchestration", "0048_launchjob_purpose"),
    ]

    operations = [
        migrations.AddConstraint(
            model_name="guestinitrdbuild",
            constraint=models.UniqueConstraint(
                fields=("initrd_sha256", "source_bake_id"),
                name="orchestration_one_guest_build_per_initrd_and_bake",
            ),
        ),
        migrations.AlterField(
            model_name="guestinitrdbuild",
            name="initrd_sha256",
            field=models.CharField(max_length=64),
        ),
    ]
