"""RA-L1 — create the DB cache table backing the DRF ScopedRateThrottle.

`settings.CACHES["default"]` is a `DatabaseCache` on `vali_throttle_cache`
so the throttle buckets are shared across all gunicorn workers + replicas
(the LocMemCache default was per-process ⇒ effective rate ×workers). This
runs `createcachetable` (idempotent — it no-ops when the table already
exists) via the migrate Job, so no separate init step is needed.
"""

from __future__ import annotations

from django.core.management import call_command
from django.db import migrations


def _create_cache_table(apps, schema_editor):
    # Reads settings.CACHES and creates any DB-backed cache table that does
    # not yet exist. Scoped to the migration's DB connection alias.
    call_command(
        "createcachetable",
        database=schema_editor.connection.alias,
        verbosity=0,
    )


class Migration(migrations.Migration):
    dependencies = [
        ("identity", "0001_initial"),
    ]

    operations = [
        migrations.RunPython(_create_cache_table, migrations.RunPython.noop),
    ]
