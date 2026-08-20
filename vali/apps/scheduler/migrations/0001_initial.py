from __future__ import annotations

import uuid

import django.db.models.deletion
from django.db import migrations, models


class Migration(migrations.Migration):
    initial = True

    dependencies: list[tuple[str, str]] = [
        ("identity", "0001_initial"),
        ("lifecycle", "0001_initial"),
    ]

    operations = [
        migrations.CreateModel(
            name="MinerCapacity",
            fields=[
                (
                    "id",
                    models.UUIDField(
                        default=uuid.uuid4,
                        editable=False,
                        primary_key=True,
                        serialize=False,
                    ),
                ),
                ("miner_node_id", models.CharField(max_length=64, unique=True)),
                (
                    "status",
                    models.CharField(
                        choices=[
                            ("active", "Active"),
                            ("quarantined", "Quarantined"),
                            ("decommissioned", "Decommissioned"),
                        ],
                        max_length=32,
                    ),
                ),
                (
                    "quality",
                    models.DecimalField(decimal_places=0, default=0, max_digits=39),
                ),
                ("capacity_slots", models.PositiveIntegerField()),
                ("observed_epoch", models.BigIntegerField()),
                ("data_epoch", models.BigIntegerField()),
                ("refreshed_at", models.DateTimeField()),
                ("created_at", models.DateTimeField(auto_now_add=True)),
            ],
            options={
                "verbose_name_plural": "miner capacities",
                "ordering": ["miner_node_id"],
            },
        ),
        migrations.CreateModel(
            name="Placement",
            fields=[
                (
                    "id",
                    models.UUIDField(
                        default=uuid.uuid4,
                        editable=False,
                        primary_key=True,
                        serialize=False,
                    ),
                ),
                ("vm_family", models.CharField(db_index=True, max_length=256)),
                ("resource_class", models.CharField(max_length=128)),
                ("miner_node_id", models.CharField(db_index=True, max_length=64)),
                (
                    "status",
                    models.CharField(
                        choices=[
                            ("pending", "Pending"),
                            ("bound", "Bound"),
                            ("failed", "Failed"),
                        ],
                        default="pending",
                        max_length=32,
                    ),
                ),
                ("chain_epoch", models.BigIntegerField()),
                ("reason", models.CharField(blank=True, default="", max_length=256)),
                (
                    "kbs_release_ref",
                    models.CharField(blank=True, default="", max_length=256),
                ),
                ("decided_at", models.DateTimeField(auto_now_add=True)),
                ("bound_at", models.DateTimeField(blank=True, null=True)),
                ("failed_at", models.DateTimeField(blank=True, null=True)),
                ("version", models.PositiveBigIntegerField(default=1)),
                (
                    "decided_by",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.PROTECT,
                        related_name="scheduler_placements",
                        to="identity.serviceclient",
                    ),
                ),
                (
                    "vm",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.PROTECT,
                        related_name="placements",
                        to="lifecycle.vm",
                    ),
                ),
            ],
            options={"ordering": ["-decided_at"]},
        ),
        migrations.AddIndex(
            model_name="minercapacity",
            index=models.Index(
                fields=["status"], name="scheduler_m_status_3220c1_idx"
            ),
        ),
        migrations.AddIndex(
            model_name="placement",
            index=models.Index(
                fields=["status"], name="scheduler_p_status_194347_idx"
            ),
        ),
        migrations.AddIndex(
            model_name="placement",
            index=models.Index(
                fields=["miner_node_id", "status"],
                name="scheduler_p_miner_n_88c5d0_idx",
            ),
        ),
        migrations.AddIndex(
            model_name="placement",
            index=models.Index(
                fields=["vm_family", "status"],
                name="scheduler_p_vm_fami_ddbdce_idx",
            ),
        ),
        migrations.AddConstraint(
            model_name="placement",
            constraint=models.UniqueConstraint(
                fields=("vm",),
                condition=models.Q(status__in=["pending", "bound"]),
                name="scheduler_one_active_placement_per_vm",
            ),
        ),
        migrations.AddConstraint(
            model_name="placement",
            constraint=models.CheckConstraint(
                name="scheduler_bound_requires_bound_at",
                condition=(
                    ~models.Q(status="bound") | models.Q(bound_at__isnull=False)
                ),
            ),
        ),
        migrations.AddConstraint(
            model_name="placement",
            constraint=models.CheckConstraint(
                name="scheduler_failed_requires_failed_at",
                condition=(
                    ~models.Q(status="failed") | models.Q(failed_at__isnull=False)
                ),
            ),
        ),
        migrations.AddConstraint(
            model_name="placement",
            constraint=models.CheckConstraint(
                name="scheduler_failed_requires_reason",
                condition=(~models.Q(status="failed") | ~models.Q(reason="")),
            ),
        ),
    ]
