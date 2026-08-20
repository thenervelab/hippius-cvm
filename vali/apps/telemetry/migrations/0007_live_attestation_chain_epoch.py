"""Scope the live-attestation seq axis to the KBS CHAIN it is monotonic in.

FORWARD-ONLY and additive. `(vm_id, attestation_seq)` assumed the KBS's
per-VM sequence was durable for the VM's life; it is not (the chain state
is an emptyDir inside the KBS's Kata CVM, reseeded to genesis on every
restart), so every post-restart attestation collided with a row from the
previous chain and was written off as a replay — a running tenant earning
nothing, silently. See `apps.telemetry.vm_liveness._resolve_chain`.

Backfill semantics: every existing row takes `chain_epoch=0`, i.e. the
VM's FIRST lineage, and `prev_attestation_hash=''`. A blank back-pointer
can never be the target of a later link (`_resolve_chain` only matches on
`body_digest`, which is populated), so a pre-migration row can only be a
lineage ancestor — an unlinkable parent opens a NEW chain_epoch rather
than dropping the attestation. Which is exactly the recovery path for a
VM stuck mid-incident.

Dropping the old constraint cannot lose data: it only ever REFUSED rows.
"""

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('telemetry', '0006_vmliveattestation'),
    ]

    operations = [
        migrations.RemoveConstraint(
            model_name='vmliveattestation',
            name='telemetry_vm_live_attestation_unique_vm_seq',
        ),
        migrations.AddField(
            model_name='vmliveattestation',
            name='chain_epoch',
            field=models.BigIntegerField(default=0),
        ),
        migrations.AddField(
            model_name='vmliveattestation',
            name='prev_attestation_hash',
            field=models.CharField(blank=True, default='', max_length=64),
        ),
        migrations.AddIndex(
            model_name='vmliveattestation',
            index=models.Index(fields=['vm_id', 'chain_epoch', 'attestation_seq'], name='telemetry_v_vm_id_b28497_idx'),
        ),
        migrations.AddConstraint(
            model_name='vmliveattestation',
            constraint=models.UniqueConstraint(fields=('vm_id', 'chain_epoch', 'attestation_seq'), name='telemetry_vm_live_attestation_unique_vm_chain_seq'),
        ),
    ]
