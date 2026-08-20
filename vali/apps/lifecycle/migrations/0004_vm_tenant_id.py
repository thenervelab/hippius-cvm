from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("lifecycle", "0003_stoppedackingest"),
    ]

    operations = [
        migrations.AddField(
            model_name="vm",
            name="tenant_id",
            field=models.CharField(blank=True, db_index=True, default="", max_length=256),
        ),
    ]
