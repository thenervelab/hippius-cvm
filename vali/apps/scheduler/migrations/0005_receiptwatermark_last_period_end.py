from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('scheduler', '0004_vmbillingbinding'),
    ]

    operations = [
        migrations.AddField(
            model_name='receiptwatermark',
            name='last_period_end',
            field=models.BigIntegerField(default=0),
        ),
    ]
