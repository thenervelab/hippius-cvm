"""`TenantBakeProfile.UBUNTU_RUNNER` — the CI-runner golden bake profile.

Choices only: no column or default changes, nothing to backfill. An old
pod never writes the new value, and the new value fits the existing
max_length=16.
"""

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('tenant_bake', '0008_profile'),
    ]

    operations = [
        migrations.AlterField(
            model_name='tenantbake',
            name='profile',
            field=models.CharField(choices=[('standard', 'Standard tenant image'), ('cdn-node', 'CDN cache node'), ('ubuntu-runner', 'Ubuntu CI runner')], db_default='standard', default='standard', max_length=16),
        ),
    ]
