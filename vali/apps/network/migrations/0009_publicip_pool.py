"""CDN address pool: `PublicIP.pool` / `cap_mbps`, `IngressEdge.cdn_feed`.

Deploy ordering: the migrate Job runs BEFORE the Deployment rolls, so old
pods keep INSERTing rows that omit the new columns. `db_default` makes the
server fill `pool` and `cdn_feed` for them (same pattern as
`tenant_bake/0005_customer_keys.py`); `cap_mbps` is nullable. Every existing
row is `general` with no cap, which the new constraint accepts. Reversible
while no `cdn` row exists.
"""

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('lifecycle', '0020_vm_guardian_wait'),
        ('network', '0008_egress_class_id_max'),
    ]

    operations = [
        migrations.AddField(
            model_name='ingressedge',
            name='cdn_feed',
            field=models.BooleanField(db_default=False, default=False),
        ),
        migrations.AddField(
            model_name='publicip',
            name='cap_mbps',
            field=models.PositiveIntegerField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name='publicip',
            name='pool',
            field=models.CharField(choices=[('general', 'General'), ('cdn', 'CDN')], db_default='general', db_index=True, default='general', max_length=16),
        ),
        migrations.AddConstraint(
            model_name='publicip',
            constraint=models.CheckConstraint(condition=models.Q(models.Q(('cap_mbps__isnull', True), ('pool', 'general')), models.Q(('cap_mbps__gte', 1), ('cap_mbps__isnull', False), ('pool', 'cdn')), _connector='OR'), name='network_public_ip_cap_only_on_cdn'),
        ),
    ]
