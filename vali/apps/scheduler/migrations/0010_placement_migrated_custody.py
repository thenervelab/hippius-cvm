"""§23/§25 — `Placement` custody follows the VM to its destination.

Schema: the new terminal `Migrated` status (+ its reason CHECK). Data:
one backfill pass that repairs the placements ALREADY left behind by a
completed migration.

The backfill is the half that touches live rows, so it is deliberately
narrow and every uncertainty is a SKIP:

  * only ACTIVE (`Pending`|`Bound`) placements of `Active` VMs — a
    `Migrating` VM is mid-move and its activation will do this itself; a
    terminal VM's placement is released by the destroy path.
  * only when `Vm.host` resolves through `MinerIdentity` to a chain
    `node_id` that DIFFERS from the placement's. `Vm.host` has exactly two
    writers — `launch._bind_vm_host` (which fills the blank placeholder
    only) and the §25 dest activation — so on an `Active` VM that
    difference means one thing: the VM was migrated and the ledger was
    never told.
  * a host that resolves to no registered `chain_node_id` is LEFT ALONE.
    Closing its placement without opening a replacement would drop the VM
    out of the #668 fit gate entirely and let the destination be
    oversubscribed by exactly this VM.

Without it the fix only applies to FUTURE migrations, and every VM moved
before it keeps paying the wrong miner, keeps its RAM/CPU counted against
a host it no longer runs on, and — the operational one — stays invisible
to a graceful-exit drain of the miner that actually holds it.
"""

from django.db import migrations, models


def _forward(apps, schema_editor):
    Placement = apps.get_model("scheduler", "Placement")
    MinerIdentity = apps.get_model("miners", "MinerIdentity")
    MinerCapacity = apps.get_model("scheduler", "MinerCapacity")

    chain_by_miner = {
        miner_id: (chain_node_id or "")
        for miner_id, chain_node_id in MinerIdentity.objects.values_list(
            "miner_id", "chain_node_id"
        )
    }
    epoch_by_node = dict(
        MinerCapacity.objects.values_list("miner_node_id", "observed_epoch")
    )

    for placement in Placement.objects.filter(
        status__in=("pending", "bound")
    ).select_related("vm"):
        vm = placement.vm
        if vm.state != "active" or not vm.host:
            continue
        node_id = chain_by_miner.get(vm.host, "")
        if not node_id or node_id == placement.miner_node_id:
            continue
        Placement.objects.filter(id=placement.id, version=placement.version).update(
            status="migrated",
            version=placement.version + 1,
            reason="migrated:backfill-0010",
        )
        Placement.objects.create(
            vm=vm,
            vm_family=placement.vm_family,
            owner=placement.owner,
            resource_class=placement.resource_class,
            miner_node_id=node_id,
            status="bound",
            chain_epoch=int(epoch_by_node.get(node_id) or 0),
            bound_at=placement.bound_at or placement.decided_at,
            # The audit trail of where this row came from. The §25
            # activation writes `migration:<job_id>` here; a backfilled row
            # cannot name the job (the placement never referenced one), so
            # it names the backfill instead of inventing evidence.
            kbs_release_ref="backfill:0010-placement-custody",
            # The closest TRUE attribution available: the principal whose
            # decision put this VM where it is. The field is non-null, and
            # inventing a synthetic principal would be less honest than
            # carrying the one already on the row.
            decided_by_id=placement.decided_by_id,
        )


def _reverse(apps, schema_editor):
    """Re-point the backfilled rows' predecessors back to active.

    Only the rows THIS migration wrote (`migrated:backfill-0010`) are
    touched — a real §25 hand-over is history, not something a schema
    rollback may rewrite.
    """
    Placement = apps.get_model("scheduler", "Placement")
    for placement in Placement.objects.filter(reason="migrated:backfill-0010"):
        Placement.objects.filter(
            vm_id=placement.vm_id,
            status="bound",
            kbs_release_ref="backfill:0010-placement-custody",
        ).delete()
        Placement.objects.filter(id=placement.id).update(
            status="bound" if placement.bound_at else "pending", reason=""
        )


class Migration(migrations.Migration):

    dependencies = [
        ('identity', '0003_serviceclient_authorization_scope'),
        ('lifecycle', '0009_vm_guest_signal'),
        ('miners', '0003_mineridentity_chain_node_id'),
        ('scheduler', '0009_receiptwatermark_seq_restart'),
    ]

    operations = [
        migrations.AlterField(
            model_name='placement',
            name='status',
            field=models.CharField(choices=[('pending', 'Pending'), ('bound', 'Bound'), ('failed', 'Failed'), ('migrated', 'Migrated away')], default='pending', max_length=32),
        ),
        migrations.AddConstraint(
            model_name='placement',
            constraint=models.CheckConstraint(condition=models.Q(models.Q(('status', 'migrated'), _negated=True), models.Q(('reason', ''), _negated=True), _connector='OR'), name='scheduler_migrated_requires_reason'),
        ),
        migrations.RunPython(_forward, _reverse),
    ]
