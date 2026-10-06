# The base a guest initrd build is for includes the initrd the release was
# appended to: an initrd-only rebuild of a bake (#1314) shares its kernel and
# dm-verity base, and carries its own build of each release. The new
# constraint is the old one widened, so every existing row satisfies it; it
# is added before the old one is dropped, and there is no window where two
# builds of a release for one base could be registered.

from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("orchestration", "0035_kbs_audit_refused_index"),
    ]

    operations = [
        migrations.AddConstraint(
            model_name="guestinitrdbuild",
            constraint=models.UniqueConstraint(
                fields=[
                    "release",
                    "kernel_sha256",
                    "rootfs_img_sha256",
                    "rootfs_verity_sha256",
                    "verity_root_hash",
                    "base_initrd_sha256",
                ],
                name="orchestration_one_guest_build_per_release_and_base_initrd",
            ),
        ),
        migrations.RemoveConstraint(
            model_name="guestinitrdbuild",
            name="orchestration_one_guest_build_per_release_and_base",
        ),
    ]
