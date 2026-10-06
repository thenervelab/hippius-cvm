"""`ResizeJob` (VM resize, `apps.orchestration.resize`) and
`MigrationJob.resize_to_flavor`.

Additive only: a new table, and a NOT NULL column with `db_default=""`, so
a pod still on the previous image (whose INSERTs omit it) keeps working
during the roll.
"""

import django.db.models.deletion
import uuid
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('identity', '0004_servicetoken_expires_at_required'),
        ('lifecycle', '0020_vm_guardian_wait'),
        ('orchestration', '0025_decommissionjob_data_death'),
    ]

    operations = [
        migrations.AddField(
            model_name='migrationjob',
            name='resize_to_flavor',
            field=models.CharField(blank=True, db_default='', default='', max_length=32),
        ),
        migrations.CreateModel(
            name='ResizeJob',
            fields=[
                ('id', models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ('job_id', models.CharField(max_length=64, unique=True)),
                ('from_flavor', models.CharField(max_length=32)),
                ('to_flavor', models.CharField(max_length=32)),
                ('node_id', models.CharField(max_length=64)),
                ('prior_power_state', models.CharField(max_length=16)),
                ('state', models.CharField(choices=[('pending', 'Pending'), ('stopping', 'Stopping'), ('migrating', 'Migrating'), ('relaunching', 'Relaunching'), ('rolling_back', 'Rolling back'), ('done', 'Done'), ('failed', 'Failed')], default='pending', max_length=32)),
                ('reserved', models.BooleanField(default=False)),
                ('attempts', models.PositiveIntegerField(default=0)),
                ('attempted_at', models.DateTimeField(blank=True, null=True)),
                ('relaunched_at', models.DateTimeField(blank=True, null=True)),
                ('measurement_before', models.CharField(blank=True, default='', max_length=128)),
                ('rolled_back', models.BooleanField(default=False)),
                ('reason', models.CharField(blank=True, default='', max_length=256)),
                ('phase_started_at', models.DateTimeField()),
                ('started_at', models.DateTimeField(auto_now_add=True)),
                ('finished_at', models.DateTimeField(blank=True, null=True)),
                ('version', models.PositiveBigIntegerField(default=1)),
                ('decided_by', models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, related_name='resize_jobs', to='identity.serviceclient')),
                ('migration_job', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.PROTECT, related_name='resize_jobs', to='orchestration.migrationjob')),
                ('vm', models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, related_name='resize_jobs', to='lifecycle.vm')),
            ],
            options={
                'ordering': ['-started_at'],
                'indexes': [models.Index(fields=['state'], name='orchestrati_state_982ee6_idx')],
                'constraints': [models.UniqueConstraint(condition=models.Q(('state__in', ['done', 'failed']), _negated=True), fields=('vm',), name='orchestration_one_active_resize_per_vm'), models.CheckConstraint(condition=models.Q(models.Q(('state__in', ['done', 'failed']), _negated=True), ('finished_at__isnull', False), _connector='OR'), name='orchestration_resize_terminal_finished')],
            },
        ),
    ]
