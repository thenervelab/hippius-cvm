# The guest report's partial index on superseded live attestations
# (`apps.orchestration.guest_report`). Built CONCURRENTLY on PostgreSQL:
# the attestation table is append-only and live, and a plain CREATE INDEX
# would block the ingest's inserts for the whole scan. Hence non-atomic,
# and the state change kept separate from the database one.

from django.db import migrations, models

_INDEX = "telemetry_vla_superseded_idx"


def _index() -> models.Index:
    return models.Index(
        fields=["verified_at_unix"],
        name=_INDEX,
        condition=models.Q(resource_verdict="superseded"),
    )


def _create(apps, schema_editor):  # noqa: ANN001
    model = apps.get_model("telemetry", "VmLiveAttestation")
    if schema_editor.connection.vendor == "postgresql":
        table = schema_editor.quote_name(model._meta.db_table)
        schema_editor.execute(
            f"CREATE INDEX CONCURRENTLY IF NOT EXISTS {_INDEX} ON {table} "
            "(verified_at_unix) WHERE resource_verdict = 'superseded'"
        )
    else:
        schema_editor.add_index(model, _index())


def _drop(apps, schema_editor):  # noqa: ANN001
    model = apps.get_model("telemetry", "VmLiveAttestation")
    if schema_editor.connection.vendor == "postgresql":
        schema_editor.execute(f"DROP INDEX CONCURRENTLY IF EXISTS {_INDEX}")
    else:
        schema_editor.remove_index(model, _index())


class Migration(migrations.Migration):
    atomic = False

    dependencies = [
        ("telemetry", "0011_guest_health"),
    ]

    operations = [
        migrations.SeparateDatabaseAndState(
            state_operations=[migrations.AddIndex(model_name="vmliveattestation", index=_index())],
            database_operations=[migrations.RunPython(_create, _drop)],
        ),
    ]
