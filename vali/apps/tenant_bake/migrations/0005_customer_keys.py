"""`TenantBake.supports_customer_keys` — operator-set capability flag.

Deploy ordering: the migrate Job runs BEFORE the Deployment rolls, so old
pods keep INSERTing TenantBake rows that omit the column. An ORM-only
`default` is applied for the duration of the `ALTER TABLE` and then dropped,
after which those INSERTs would fail on NOT NULL. `db_default` makes the
server fill the value for them (same pattern as
`scheduler/0012_placement_failure_source.py`). Reversible: dropping the
column loses only data the old image never had.
"""

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('tenant_bake', '0004_golden_verity_fields'),
    ]

    operations = [
        migrations.AddField(
            model_name='tenantbake',
            name='supports_customer_keys',
            field=models.BooleanField(default=False, db_default=False),
        ),
    ]
