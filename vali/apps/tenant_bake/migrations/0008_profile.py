"""`TenantBake.profile` + `cdn_backend_url` — CDN plan I3 bake profile.

Same deploy-ordering posture as `0006_package_refresh`: the migrate Job
runs BEFORE the Deployment rolls, so old pods keep INSERTing rows that
omit the columns; `db_default` fills them. Reversible: dropping the
columns loses only data the old image never had.
"""

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('tenant_bake', '0007_rebake_e2e_passed'),
    ]

    operations = [
        migrations.AddField(
            model_name='tenantbake',
            name='cdn_backend_url',
            field=models.CharField(blank=True, db_default='', default='', max_length=256),
        ),
        migrations.AddField(
            model_name='tenantbake',
            name='profile',
            field=models.CharField(choices=[('standard', 'Standard tenant image'), ('cdn-node', 'CDN cache node')], db_default='standard', default='standard', max_length=16),
        ),
    ]
