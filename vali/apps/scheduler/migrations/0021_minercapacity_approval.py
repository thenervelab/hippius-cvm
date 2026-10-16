"""External-miner approval on `MinerCapacity`: `approved_at` / `approved_by`.

Schema: additive. `approved_at` is nullable and `approved_by` carries a DB
default, so the running image's INSERTs need nothing new.

Data: every row that exists when this runs is GRANDFATHERED approved
(`approved_by = "grandfathered"`), with one `MinerCapacityAudit` row each,
so turning `VALI_MINER_APPROVAL_REQUIRED` on never holds back a miner we
already run. A row the OLD image creates after this migration and before the
new image is rolled is left NULL; with the switch off (the default) that
changes nothing, and `vali_approve_miner --list-pending` shows it before
anyone flips the switch.

Reversible: dropping the columns forgets the approvals (the audit rows keep
the history); the reverse of the data step is a no-op.
"""

from django.db import migrations, models
from django.utils import timezone

GRANDFATHERED_ACTOR = "grandfathered"
GRANDFATHERED_REASON = "approved by migration 0021: existed before external-miner approval"


def grandfather(apps, schema_editor):
    MinerCapacity = apps.get_model("scheduler", "MinerCapacity")
    MinerCapacityAudit = apps.get_model("scheduler", "MinerCapacityAudit")
    now = timezone.now()
    node_ids = list(
        MinerCapacity.objects.filter(approved_at__isnull=True).values_list(
            "miner_node_id", flat=True
        )
    )
    MinerCapacity.objects.filter(miner_node_id__in=node_ids).update(
        approved_at=now, approved_by=GRANDFATHERED_ACTOR
    )
    MinerCapacityAudit.objects.bulk_create(
        [
            MinerCapacityAudit(
                miner_node_id=node_id,
                actor=GRANDFATHERED_ACTOR,
                field="approved_at",
                before=None,
                after=now.isoformat(),
                reason=GRANDFATHERED_REASON,
            )
            for node_id in node_ids
        ]
    )


class Migration(migrations.Migration):

    dependencies = [
        ("scheduler", "0020_minercapacity_agent_version"),
    ]

    operations = [
        migrations.AddField(
            model_name="minercapacity",
            name="approved_at",
            field=models.DateTimeField(blank=True, default=None, null=True),
        ),
        migrations.AddField(
            model_name="minercapacity",
            name="approved_by",
            field=models.CharField(blank=True, db_default="", default="", max_length=128),
        ),
        migrations.RunPython(grandfather, migrations.RunPython.noop),
    ]
