"""P2 — object-level authorization scope on `ServiceClient`.

Adds `scope` + `tenant_id` and GRANDFATHERS every principal that
already exists at migrate time to `OPERATOR`.

Why grandfather: before this migration vali had no object-level
authorization at all — every registered principal was, in effect, an
operator. Writing that fact down explicitly (one auditable row per
principal) preserves the deployed behaviour EXACTLY while making the
grant visible and revocable. It is not a default: the column default
for principals created AFTER this migration is `unclassified`, which
is denied. Operators should now review the grandfathered rows and
demote anything that does not genuinely need cross-tenant reach.

DEPLOY ORDER: a vali rollout does NOT run migrations — a separate Job
does. This migration MUST run BEFORE the code that reads `scope` is
deployed, or every request 500s on a missing column.
"""

from __future__ import annotations

from django.db import migrations, models


def grandfather_existing_principals(apps, schema_editor):
    """Pre-existing principals were de-facto operators — record it."""
    ServiceClient = apps.get_model("identity", "ServiceClient")
    ServiceClient.objects.all().update(scope="operator", tenant_id="")


def unset_scopes(apps, schema_editor):
    """Reverse: drop every classification (the columns go away next)."""
    ServiceClient = apps.get_model("identity", "ServiceClient")
    ServiceClient.objects.all().update(scope="unclassified", tenant_id="")


class Migration(migrations.Migration):

    dependencies = [
        ("identity", "0002_throttle_cache_table"),
    ]

    operations = [
        migrations.AddField(
            model_name="serviceclient",
            name="scope",
            field=models.CharField(
                choices=[
                    ("unclassified", "Unclassified (denied)"),
                    ("operator", "Operator (all tenants)"),
                    ("tenant", "Tenant-scoped"),
                ],
                db_index=True,
                default="unclassified",
                max_length=16,
            ),
        ),
        migrations.AddField(
            model_name="serviceclient",
            name="tenant_id",
            field=models.CharField(blank=True, db_index=True, default="", max_length=256),
        ),
        migrations.RunPython(
            grandfather_existing_principals,
            unset_scopes,
        ),
        migrations.AddConstraint(
            model_name="serviceclient",
            constraint=models.CheckConstraint(
                condition=(
                    models.Q(scope="tenant") & ~models.Q(tenant_id="")
                )
                | (~models.Q(scope="tenant") & models.Q(tenant_id="")),
                name="identity_serviceclient_tenant_scope_consistent",
            ),
        ),
    ]
