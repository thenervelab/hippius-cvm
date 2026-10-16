from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('orchestration', '0045_migrationjob_cross_generation'),
    ]

    operations = [
        migrations.AddField(
            model_name='launchjob',
            name='cancel_requested_at',
            field=models.DateTimeField(blank=True, null=True),
        ),
    ]
