# The KBS head an ingest run last saw and when, so the guest report can
# export how far vali is behind the KBS audit chains and whether the ingest
# runs at all. Two nullable columns: every existing cursor reads "not yet
# checked" until the next run.

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('orchestration', '0036_guest_build_base_initrd'),
    ]

    operations = [
        migrations.AddField(
            model_name='kbsauditcursor',
            name='checked_at',
            field=models.DateTimeField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name='kbsauditcursor',
            name='head_seq',
            field=models.BigIntegerField(blank=True, null=True),
        ),
    ]
