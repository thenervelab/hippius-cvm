"""`TenantBake.rebake_e2e_passed` — the synthetic e2e verdict on a scheduled
golden re-bake (F6). Nullable (None = not run), so old pods' INSERTs that
omit the column stay valid during the migrate-before-roll window.
Reversible: dropping the column loses only data the old image never had.
"""

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('tenant_bake', '0006_package_refresh'),
    ]

    operations = [
        migrations.AddField(
            model_name='tenantbake',
            name='rebake_e2e_passed',
            field=models.BooleanField(blank=True, default=None, null=True),
        ),
    ]
