"""#32 — `ServiceToken.expires_at` becomes NOT NULL.

Before this migration a bearer token could live forever, and in
production every one of them did: the three ACTIVE tokens
(`orchestration-root`, `tenant-baker-worker`, `edge-telemetry-relay`)
carried `expires_at = NULL`. `orchestration-root` mints L1 OrderTickets,
stages Vault secrets, registers VMs with the KBS and dispatches
launches — a non-expiring bearer token for it is a permanent skeleton
key whose only kill switch is somebody remembering to flip
`is_active`.

Expiry was ALREADY enforced at authentication (see
`apps.identity.authentication`: both `ServiceTokenAuthentication` and
`resolve_principal` refuse a past `expires_at`). What was missing was
that anything ever SET it. This migration closes the representation:
after it, "never expires" is not a state the database can hold.

═══ WHAT THIS DOES TO EXISTING ROWS ═══

Two branches, because the two populations have opposite risk:

1. `is_active=True` AND `expires_at IS NULL`
       → `now() + GRACE_DAYS` (90 days from the moment the migration
         runs).
   These are the LIVE control-plane credentials. Dating them at
   `now()` — the naive "backfill as expired" — would 401 the synthetic
   monitor, the bake path and the Edge telemetry relay the instant the
   migration Job completes, i.e. an instant control-plane outage
   BEFORE the new image even rolls. 90 days instead: nothing changes
   today, and the rotation runbook
   (`docs/operator/vali-service-token-rotation-runbook.md`) has a real
   deadline instead of a good intention.
   On the production database this branch touches exactly 3 rows.

2. `is_active=False` AND `expires_at IS NULL`
       → `created_at` (i.e. already expired).
   These 138 rows are dead test artifacts that were already
   deactivated; the auth path filters on `is_active=True`, so they
   cannot authenticate today and they cannot after this. Dating them
   in the past is simply truthful, keeps the admin from showing 139
   fake future expiries, and is fail-closed if one is ever
   re-activated by mistake.

Measured on the production database (read-only, 2026-08-13):

    total rows          142
    expires_at IS NULL  141
      ACTIVE   + NULL     3   → now() + 90 days
      INACTIVE + NULL   138   → created_at (already expired)
    already bounded       1   → untouched

So the answer to "is this safe to merge": yes — no credential that
works today stops working today, and no credential that is dead today
comes back.

DEPLOY ORDER: a vali rollout does NOT run migrations — the chart's
`job-django-migrations` Sync hook (wave 2) does, before the Deployment
(wave 3). Old code between the two is fine: nothing in the request path
mints a token (`apps.identity` has no urls/views), so the new NOT NULL
cannot be hit by a running old pod.

FORWARD-ONLY: the data step has no reverse. Which rows were NULL is not
recoverable once backfilled, and re-NULLing everything would erase
legitimately-set expiries. Rolling back means restoring a dump.
"""

from __future__ import annotations

from datetime import timedelta

from django.db import migrations, models
from django.utils import timezone

#: How long the live, non-expiring credentials get from the moment this
#: migration runs. Matches `TokenLifetime.SERVICE` (90 days) because all
#: three live principals are in-cluster machine identities — it is the
#: window the operator has to run the rotation runbook.
GRACE_DAYS = 90


def backfill_missing_expiries(apps, schema_editor):
    """Give every NULL `expires_at` a value — see the module docstring
    for why the two populations get different ones."""
    ServiceToken = apps.get_model("identity", "ServiceToken")
    now = timezone.now()

    # Live credentials: a grace window, NOT `now()`. Backfilling these
    # as already-expired is the one change here that would take the
    # control plane down on deploy.
    live = ServiceToken.objects.filter(expires_at__isnull=True, is_active=True)
    n_live = live.update(expires_at=now + timedelta(days=GRACE_DAYS))

    # Already-revoked rows: date them at creation. They cannot
    # authenticate (the auth path filters `is_active=True`), so this
    # grants nothing and refuses everything.
    dead = ServiceToken.objects.filter(expires_at__isnull=True, is_active=False)
    n_dead = dead.update(expires_at=models.F("created_at"))

    if n_live or n_dead:
        # Printed by `manage.py migrate` into the Job log, so the
        # rotation deadline is recorded at the moment it is created.
        print(
            f"\n  identity.0004: backfilled {n_live} ACTIVE token(s) to "
            f"{(now + timedelta(days=GRACE_DAYS)).isoformat()} "
            f"(rotate before then) and {n_dead} inactive token(s) to "
            "their created_at (already expired)."
        )


class Migration(migrations.Migration):

    dependencies = [
        ("identity", "0003_serviceclient_authorization_scope"),
    ]

    operations = [
        migrations.RunPython(
            backfill_missing_expiries,
            # Forward-only: see the module docstring.
            migrations.RunPython.noop,
        ),
        migrations.AlterField(
            model_name="servicetoken",
            name="expires_at",
            field=models.DateTimeField(
                help_text=(
                    "Hard expiry. Enforced at authentication "
                    "(apps.identity.authentication), NOT NULL at the database."
                ),
            ),
        ),
    ]
