from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("tenant_bake", "0002_measurement_optional"),
    ]

    operations = [
        migrations.AddField(
            model_name="tenantbake",
            name="luks_header_sha256",
            field=models.CharField(blank=True, default="", max_length=64),
        ),
    ]
