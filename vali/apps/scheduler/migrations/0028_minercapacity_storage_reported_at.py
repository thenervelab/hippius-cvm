from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("scheduler", "0027_vmbillingbinding_dedicated_gb"),
    ]

    operations = [
        migrations.AddField(
            model_name="minercapacity",
            name="storage_reported_at",
            field=models.DateTimeField(blank=True, default=None, null=True),
        ),
    ]
