"""`TenantBake.package_refresh` — F6 scheduled golden re-bake stamp.

Same deploy-ordering posture as `0005_customer_keys`: the migrate Job runs
BEFORE the Deployment rolls, so old pods keep INSERTing rows that omit the
column; `db_default` lets the server fill "" for them. Reversible: dropping
the column loses only data the old image never had.
"""

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('tenant_bake', '0005_customer_keys'),
    ]

    operations = [
        migrations.AddField(
            model_name='tenantbake',
            name='package_refresh',
            field=models.CharField(blank=True, db_default='', default='', max_length=64),
        ),
    ]
