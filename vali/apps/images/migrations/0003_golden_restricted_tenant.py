"""`GoldenImage.restricted_tenant` (CDN plan N2). `db_default` so pods on
the old image keep inserting during the rollout; every existing row is
unrestricted."""

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('images', '0002_guest_release'),
    ]

    operations = [
        migrations.AddField(
            model_name='goldenimage',
            name='restricted_tenant',
            field=models.CharField(blank=True, db_default='', default='', max_length=256),
        ),
    ]
