"""Capacity v2 — policy columns on `MinerCapacity` + `MinerCapacityAudit`.

Schema: additive only. Every NOT NULL column carries a DATABASE default
(`db_default`) so the running old image, whose INSERTs omit them, keeps
working until it is rolled (same reasoning as 0012). The rest are
nullable. Nothing reads them until the capacity-v2 code ships.

Data: ONE certain backfill. A row with a COMPLETE operator-registered
hardware anchor (`total_memory_mb` AND `total_cpus` set) was seeded by the
fleet operator from the host's own numbers — that is the definition of
the `operator` trust class. A half anchor (memory only — the old admin
allowed it) stays `earned`: the operator class requires both, and the
command refuses to leave an operator row without either. Every other row stays `earned` (the default). A mis-seeded
row (e.g. an orphan node id) is moved back with the audited command, not
guessed at here.

No audit rows are written by this migration: it records no operator
decision, it only names the one that was already taken when the anchor
was seeded.

Reversible: dropping the columns loses only v2 policy state.
"""

import uuid
from django.db import migrations, models


def _forward(apps, schema_editor):
    MinerCapacity = apps.get_model("scheduler", "MinerCapacity")
    MinerCapacity.objects.filter(
        total_memory_mb__isnull=False, total_cpus__isnull=False
    ).update(trust_class="operator")


def _reverse(apps, schema_editor):
    # The column is dropped by the reversed AddField; nothing to undo.
    pass


class Migration(migrations.Migration):

    dependencies = [
        ('scheduler', '0012_placement_failure_source'),
    ]

    operations = [
        migrations.AddField(
            model_name='minercapacity',
            name='candidate_memory_mb',
            field=models.PositiveIntegerField(db_default=0, default=0),
        ),
        migrations.AddField(
            model_name='minercapacity',
            name='candidate_since',
            field=models.DateTimeField(blank=True, default=None, null=True),
        ),
        migrations.AddField(
            model_name='minercapacity',
            name='candidate_vcpus',
            field=models.PositiveIntegerField(db_default=0, default=0),
        ),
        migrations.AddField(
            model_name='minercapacity',
            name='candidate_vms',
            field=models.PositiveIntegerField(db_default=0, default=0),
        ),
        migrations.AddField(
            model_name='minercapacity',
            name='cpu_ratio',
            field=models.DecimalField(blank=True, decimal_places=2, default=None, max_digits=4, null=True),
        ),
        migrations.AddField(
            model_name='minercapacity',
            name='declared_asid_capacity',
            field=models.PositiveIntegerField(blank=True, default=None, null=True),
        ),
        migrations.AddField(
            model_name='minercapacity',
            name='declared_asid_used',
            field=models.PositiveIntegerField(blank=True, default=None, null=True),
        ),
        migrations.AddField(
            model_name='minercapacity',
            name='declared_at',
            field=models.DateTimeField(blank=True, default=None, null=True),
        ),
        migrations.AddField(
            model_name='minercapacity',
            name='declared_cpu_budget',
            field=models.PositiveIntegerField(blank=True, default=None, null=True),
        ),
        migrations.AddField(
            model_name='minercapacity',
            name='declared_memory_mb_budget',
            field=models.PositiveIntegerField(blank=True, default=None, null=True),
        ),
        migrations.AddField(
            model_name='minercapacity',
            name='earned_last_change_at',
            field=models.DateTimeField(blank=True, default=None, null=True),
        ),
        migrations.AddField(
            model_name='minercapacity',
            name='earned_last_reason',
            field=models.CharField(blank=True, db_default='', default='', max_length=64),
        ),
        migrations.AddField(
            model_name='minercapacity',
            name='earned_memory_mb',
            field=models.PositiveIntegerField(blank=True, default=None, null=True),
        ),
        migrations.AddField(
            model_name='minercapacity',
            name='earned_vcpus',
            field=models.PositiveIntegerField(blank=True, default=None, null=True),
        ),
        migrations.AddField(
            model_name='minercapacity',
            name='earned_vms',
            field=models.PositiveIntegerField(blank=True, default=None, null=True),
        ),
        migrations.AddField(
            model_name='minercapacity',
            name='proven_at',
            field=models.DateTimeField(blank=True, default=None, null=True),
        ),
        migrations.AddField(
            model_name='minercapacity',
            name='proven_peak_memory_mb',
            field=models.PositiveIntegerField(db_default=0, default=0),
        ),
        migrations.AddField(
            model_name='minercapacity',
            name='proven_peak_vcpus',
            field=models.PositiveIntegerField(db_default=0, default=0),
        ),
        migrations.AddField(
            model_name='minercapacity',
            name='proven_peak_vms',
            field=models.PositiveIntegerField(db_default=0, default=0),
        ),
        migrations.AddField(
            model_name='minercapacity',
            name='trust_class',
            field=models.CharField(choices=[('operator', 'Operator-anchored'), ('earned', 'Earned by proof')], db_default='earned', default='earned', max_length=16),
        ),
        migrations.CreateModel(
            name='MinerCapacityAudit',
            fields=[
                ('id', models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ('miner_node_id', models.CharField(max_length=64)),
                ('actor', models.CharField(max_length=128)),
                ('field', models.CharField(max_length=64)),
                ('before', models.JSONField(blank=True, null=True)),
                ('after', models.JSONField(blank=True, null=True)),
                ('reason', models.CharField(blank=True, default='', max_length=512)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
            ],
            options={
                'ordering': ['-created_at'],
                'indexes': [models.Index(fields=['miner_node_id', 'created_at'], name='scheduler_m_miner_n_458e12_idx')],
            },
        ),
        migrations.RunPython(_forward, _reverse),
    ]
