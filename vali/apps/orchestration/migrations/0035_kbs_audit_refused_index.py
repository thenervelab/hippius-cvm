# The guest report's partial index on refused KBS release-log entries
# (`apps.orchestration.guest_report`, the KBS T4 signal). Built
# CONCURRENTLY on PostgreSQL: the audit log takes an entry per keepalive
# grant, and a plain CREATE INDEX would block the ingest's inserts for the
# whole scan. An interrupted concurrent build leaves an INVALID index under
# the name, which `IF NOT EXISTS` would then accept: it is dropped first.
# Hence non-atomic, with the state change kept separate.

from django.db import migrations, models

_INDEX = "kbs_audit_refused_idx"


def _index() -> models.Index:
    return models.Index(
        fields=["event_unix"],
        name=_INDEX,
        condition=models.Q(log="release", granted=False),
    )


def _create(apps, schema_editor):  # noqa: ANN001
    model = apps.get_model("orchestration", "KbsAuditEntry")
    if schema_editor.connection.vendor != "postgresql":
        schema_editor.add_index(model, _index())
        return
    table = model._meta.db_table
    with schema_editor.connection.cursor() as cur:
        # The index of THIS table in the current schema (names are
        # schema-local).
        cur.execute(
            "SELECT n.nspname, NOT i.indisvalid FROM pg_index i "
            "JOIN pg_class c ON c.oid = i.indexrelid "
            "JOIN pg_namespace n ON n.oid = c.relnamespace "
            "WHERE c.relname = %s AND n.nspname = current_schema() "
            "AND i.indrelid = %s::regclass",
            [_INDEX, table],
        )
        row = cur.fetchone()
    if row is not None and row[1]:
        qualified = f"{schema_editor.quote_name(row[0])}.{schema_editor.quote_name(_INDEX)}"
        schema_editor.execute(f"DROP INDEX CONCURRENTLY IF EXISTS {qualified}")
    table = schema_editor.quote_name(table)
    schema_editor.execute(
        f"CREATE INDEX CONCURRENTLY IF NOT EXISTS {_INDEX} ON {table} "
        "(event_unix) WHERE log = 'release' AND granted = false"
    )


def _drop(apps, schema_editor):  # noqa: ANN001
    model = apps.get_model("orchestration", "KbsAuditEntry")
    if schema_editor.connection.vendor == "postgresql":
        schema_editor.execute(f"DROP INDEX CONCURRENTLY IF EXISTS {_INDEX}")
    else:
        schema_editor.remove_index(model, _index())


class Migration(migrations.Migration):
    atomic = False

    dependencies = [
        ("orchestration", "0034_guest_upgrade_recovery"),
    ]

    operations = [
        migrations.SeparateDatabaseAndState(
            state_operations=[migrations.AddIndex(model_name="kbsauditentry", index=_index())],
            database_operations=[migrations.RunPython(_create, _drop)],
        ),
    ]
