from django.db import migrations, models


class Migration(migrations.Migration):
    """Add the tenant price ceiling (`Vm.max_price_per_unit`) — a
    nullable, vali-side policy field consumed by the §3.2 price-watch.
    """

    dependencies = [
        ("lifecycle", "0001_initial"),
    ]

    operations = [
        migrations.AddField(
            model_name="vm",
            name="max_price_per_unit",
            field=models.BigIntegerField(blank=True, null=True),
        ),
    ]
