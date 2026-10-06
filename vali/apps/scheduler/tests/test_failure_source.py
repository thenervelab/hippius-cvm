"""`Placement.failure_source` — provenance of a placement's end.

The operator readout (`apps.operator.service._refusals`) selects refusals
on this column, never on the text of `reason`. These tests pin the two
things that make that selection trustworthy:

  * the model guard: no NEW failed row, and no row newly stamped
    `failed_at`, may carry `legacy` — the write site must say who it is.
    The five real write sites are each pinned in their own module
    (`test_reeval.py` drain + release, `test_views.py` `/fail`,
    `test_placement_custody.py` move, `orchestration/test_launch_service.py`
    `_fail_placement`); this file is about the sites nobody has written yet.
  * the backfill of migration 0012: `status = migrated` → `migration`,
    everything else stays `legacy` — including a FAILED row whose text
    starts with `drain:`.
  * the deploy window of migration 0012: the column has a DATABASE default,
    so the old image's INSERTs (which do not know the column) keep working
    between `migrate` and the roll.
"""

from __future__ import annotations

import importlib
import uuid

import pytest
from django.apps import apps as django_apps
from django.db import connection, migrations
from django.utils import timezone

from apps.scheduler.models import (
    Placement,
    PlacementFailureSource,
    PlacementFailureSourceMissing,
    PlacementStatus,
)

from .factories import make_placement, make_service_client, make_vm, node_id

pytestmark = pytest.mark.django_db

LEGACY = PlacementFailureSource.LEGACY.value


def _run_0012_backfill() -> None:
    importlib.import_module("apps.scheduler.migrations.0012_placement_failure_source")._forward(
        django_apps, None
    )


# ─── the model guard ─────────────────────────────────────────────────


def test_a_new_failed_row_without_a_source_is_refused() -> None:
    actor = make_service_client()
    with pytest.raises(PlacementFailureSourceMissing) as exc:
        Placement.objects.create(
            vm=make_vm("vm-1"),
            vm_family="tenant-1",
            owner="",
            resource_class="std",
            miner_node_id=node_id(1),
            status=PlacementStatus.FAILED.value,
            chain_epoch=10,
            version=1,
            decided_by=actor,
            failed_at=timezone.now(),
            reason="drain:miner-stale",
        )
    # the message names the fix, not the enum's repr
    assert "'legacy'" in str(exc.value)
    assert "PlacementFailureSource" in str(exc.value)
    # nothing was written
    assert not Placement.objects.filter(status=PlacementStatus.FAILED.value).exists()


@pytest.mark.parametrize(
    "source",
    [s.value for s in PlacementFailureSource if s is not PlacementFailureSource.LEGACY],
)
def test_a_new_failed_row_with_any_real_source_is_accepted(source: str) -> None:
    vm = make_vm("vm-1")
    row = make_placement(vm, node_id(1), status=PlacementStatus.FAILED.value, failure_source=source)
    row.refresh_from_db()
    assert row.failure_source == source


def test_newly_stamping_failed_at_on_a_legacy_row_is_refused() -> None:
    """The CAS write sites use `.update()` and bypass the guard by design;
    a `save()` site that flips an active row to failed must name itself."""
    vm = make_vm("vm-1")
    row = make_placement(vm, node_id(1), status=PlacementStatus.BOUND.value)
    assert row.failure_source == LEGACY  # active rows have no provenance yet
    row.status = PlacementStatus.FAILED.value
    row.failed_at = timezone.now()
    row.reason = "released:vm-destroyed"
    with pytest.raises(PlacementFailureSourceMissing):
        row.save()
    row.refresh_from_db()
    assert row.status == PlacementStatus.BOUND
    assert row.failed_at is None


def test_newly_stamping_failed_at_with_a_source_is_accepted() -> None:
    vm = make_vm("vm-1")
    row = make_placement(vm, node_id(1), status=PlacementStatus.BOUND.value)
    row.status = PlacementStatus.FAILED.value
    row.failed_at = timezone.now()
    row.reason = "released:vm-destroyed"
    row.failure_source = PlacementFailureSource.RELEASE.value
    row.save()
    row.refresh_from_db()
    assert row.status == PlacementStatus.FAILED
    assert row.failure_source == PlacementFailureSource.RELEASE


def test_an_existing_legacy_failed_row_can_still_be_saved() -> None:
    """History is not refused: a pre-provenance FAILED row (`legacy`,
    `failed_at` already in the DB) may be re-saved for any other field —
    the guard only fires when `failed_at` is NEWLY set."""
    vm = make_vm("vm-1")
    row = make_placement(vm, node_id(1), status=PlacementStatus.FAILED.value, failure_source=LEGACY)
    assert row.failure_source == LEGACY
    assert row.failed_at is not None
    row.kbs_release_ref = "order-42"
    row.save()  # full save, not update_fields
    row.save(update_fields=["kbs_release_ref"])
    row.refresh_from_db()
    assert row.failure_source == LEGACY
    assert row.kbs_release_ref == "order-42"


def test_active_rows_carry_legacy_and_save_freely() -> None:
    for status in (PlacementStatus.PENDING.value, PlacementStatus.BOUND.value):
        row = make_placement(make_vm(f"vm-{status}"), node_id(1), status=status)
        assert row.failure_source == LEGACY
        row.kbs_release_ref = "x"
        row.save()


def test_the_factory_default_for_a_failed_row_is_manual() -> None:
    """A test that does not care about provenance gets a row the operator
    readout ignores — `manual` is never a refusal."""
    row = make_placement(make_vm("vm-1"), node_id(1), status=PlacementStatus.FAILED.value)
    assert row.failure_source == PlacementFailureSource.MANUAL
    assert row.reason == "seed"


# ─── the guard when `failed_at` was deferred ────────────────────────
#
# A row loaded with `.only()` / `.defer()` does not know its stored
# `failed_at`. Assigning the attribute skips the deferred load, so the
# instance never learns it; the guard must treat "unknown" as "look it
# up", never as "already failed".


def test_deferred_failed_at_then_assigned_is_still_refused() -> None:
    vm = make_vm("vm-1")
    make_placement(vm, node_id(1), status=PlacementStatus.BOUND.value)
    row = Placement.objects.only("id", "status", "version", "reason").get(vm=vm)
    assert "failed_at" in row.get_deferred_fields()
    row.status = PlacementStatus.FAILED.value
    row.failed_at = timezone.now()  # assigned, never read: no deferred load
    row.reason = "released:vm-destroyed"
    with pytest.raises(PlacementFailureSourceMissing):
        row.save()
    stored = Placement.objects.get(vm=vm)
    assert stored.status == PlacementStatus.BOUND
    assert stored.failed_at is None
    assert stored.failure_source == LEGACY


def test_deferred_failed_at_then_assigned_with_a_source_is_accepted() -> None:
    vm = make_vm("vm-1")
    make_placement(vm, node_id(1), status=PlacementStatus.BOUND.value)
    row = Placement.objects.only("id", "status", "version", "reason").get(vm=vm)
    row.status = PlacementStatus.FAILED.value
    row.failed_at = timezone.now()
    row.reason = "released:vm-destroyed"
    row.failure_source = PlacementFailureSource.RELEASE.value
    row.save()
    stored = Placement.objects.get(vm=vm)
    assert stored.status == PlacementStatus.FAILED
    assert stored.failure_source == PlacementFailureSource.RELEASE


def test_deferred_legacy_failed_row_is_still_history() -> None:
    """A pre-provenance FAILED row re-saved through a deferred instance —
    even one that re-assigns `failed_at` — is not refused: the database
    already carries `failed_at`, the guard resolves it and lets go."""
    vm = make_vm("vm-1")
    make_placement(vm, node_id(1), status=PlacementStatus.FAILED.value, failure_source=LEGACY)
    row = Placement.objects.only("id", "kbs_release_ref").get(vm=vm)
    assert "failed_at" in row.get_deferred_fields()
    later = timezone.now()
    row.kbs_release_ref = "order-42"
    row.failed_at = later
    row.save()
    stored = Placement.objects.get(vm=vm)
    assert stored.failure_source == LEGACY
    assert stored.kbs_release_ref == "order-42"
    assert stored.failed_at == later


def test_deferred_failed_at_read_before_assignment_is_resolved() -> None:
    """Reading the deferred attribute goes through Django's deferred load
    (`refresh_from_db(fields=["failed_at"])`), which must record the stored
    value — `None` here — so the guard fires without a second query.

    `failure_source` is deferred too, and the guard reads it INSIDE `save`:
    that is a `refresh_from_db(fields=["failure_source"])` after `failed_at`
    was assigned, and it must not overwrite the recorded `None` with the
    local value (it did, before the `fields` check in `refresh_from_db`)."""
    vm = make_vm("vm-1")
    make_placement(vm, node_id(1), status=PlacementStatus.BOUND.value)
    row = Placement.objects.only("id", "status", "version", "reason").get(vm=vm)
    assert row.failed_at is None  # deferred load
    assert row._failed_at_in_db is None
    row.status = PlacementStatus.FAILED.value
    row.failed_at = timezone.now()
    row.reason = "released:vm-destroyed"
    with pytest.raises(PlacementFailureSourceMissing):
        row.save()


def test_partial_refresh_does_not_launder_a_local_failed_at() -> None:
    """`refresh_from_db(fields=[...])` without `failed_at` re-reads nothing
    about it; a locally assigned value left in `__dict__` must not be
    mistaken for the stored one."""
    vm = make_vm("vm-1")
    row = make_placement(vm, node_id(1), status=PlacementStatus.BOUND.value)
    row.failed_at = timezone.now()
    row.refresh_from_db(fields=["kbs_release_ref"])
    assert row._failed_at_in_db is None
    row.status = PlacementStatus.FAILED.value
    row.reason = "released:vm-destroyed"
    with pytest.raises(PlacementFailureSourceMissing):
        row.save()
    stored = Placement.objects.get(vm=vm)
    assert stored.status == PlacementStatus.BOUND


# ─── the 0012 backfill ───────────────────────────────────────────────


def test_backfill_stamps_migrated_rows_and_nothing_else() -> None:
    vm_m = make_vm("vm-m")
    migrated = make_placement(vm_m, node_id(1), status=PlacementStatus.BOUND.value)
    Placement.objects.filter(id=migrated.id).update(
        status=PlacementStatus.MIGRATED.value, reason="migrated:backfill-0010"
    )
    # pre-provenance FAILED rows of every spelling — all stay legacy
    drained = make_placement(
        make_vm("vm-d"),
        node_id(1),
        status=PlacementStatus.FAILED.value,
        reason="drain:miner-stale",
        failure_source=LEGACY,
    )
    launched = make_placement(
        make_vm("vm-l"),
        node_id(1),
        status=PlacementStatus.FAILED.value,
        reason="miner-rejected",
        failure_source=LEGACY,
    )
    released = make_placement(
        make_vm("vm-r"),
        node_id(1),
        status=PlacementStatus.FAILED.value,
        reason="released:vm-destroyed",
        failure_source=LEGACY,
    )
    bound = make_placement(make_vm("vm-b"), node_id(2), status=PlacementStatus.BOUND.value)

    _run_0012_backfill()

    by_id = {p.id: p.failure_source for p in Placement.objects.all()}
    assert by_id[migrated.id] == PlacementFailureSource.MIGRATION
    assert by_id[drained.id] == LEGACY
    assert by_id[launched.id] == LEGACY
    assert by_id[released.id] == LEGACY
    assert by_id[bound.id] == LEGACY


def test_backfill_is_idempotent_and_does_not_touch_new_rows() -> None:
    new_drain = make_placement(
        make_vm("vm-n"),
        node_id(1),
        status=PlacementStatus.FAILED.value,
        reason="drain:miner-stale",
        failure_source=PlacementFailureSource.SCHEDULER_DRAIN.value,
    )
    _run_0012_backfill()
    _run_0012_backfill()
    new_drain.refresh_from_db()
    assert new_drain.failure_source == PlacementFailureSource.SCHEDULER_DRAIN


# ─── the 0012 deploy window ──────────────────────────────────────────
#
# `migrate` runs before the new image rolls; until the roll completes the
# OLD image is still inserting placements and its INSERT does not name
# `failure_source`. That only works if the DATABASE supplies the default.
# A plain ORM `default` does not: Django uses it for the `ALTER TABLE`,
# then drops it server-side (`BaseDatabaseSchemaEditor.add_field`, "Drop
# the default if we need to", skipped only when `has_db_default()`).


def test_migration_0012_declares_a_database_default() -> None:
    module = importlib.import_module("apps.scheduler.migrations.0012_placement_failure_source")
    add_field = [
        op
        for op in module.Migration.operations
        if isinstance(op, migrations.AddField) and op.name == "failure_source"
    ]
    assert len(add_field) == 1
    field = add_field[0].field
    assert field.has_db_default()
    assert field.db_default == LEGACY
    # and the live model agrees, so `makemigrations --check` stays quiet
    assert Placement._meta.get_field("failure_source").has_db_default()


def test_an_old_image_insert_that_omits_failure_source_succeeds() -> None:
    """The INSERT exactly as the pre-0012 image issues it: every column it
    knows, nothing it does not. Written through the DB-API, not the ORM,
    so the ORM `default` cannot help — only the column's own default can."""
    vm = make_vm("vm-1")
    actor = make_service_client()
    meta = Placement._meta
    col = {f.name: f.column for f in meta.concrete_fields}
    pk = meta.pk.get_db_prep_value(uuid.uuid4(), connection)
    now = timezone.now()
    columns = [
        col["id"],
        col["vm"],
        col["vm_family"],
        col["owner"],
        col["resource_class"],
        col["miner_node_id"],
        col["status"],
        col["chain_epoch"],
        col["reason"],
        col["kbs_release_ref"],
        col["decided_by"],
        col["decided_at"],
        col["version"],
    ]
    assert col["failure_source"] not in columns
    params = [
        pk,
        meta.get_field("vm").get_db_prep_value(vm.pk, connection),
        "tenant-1",
        "",
        "std",
        node_id(1),
        PlacementStatus.BOUND.value,
        10,
        "",
        "",
        meta.get_field("decided_by").get_db_prep_value(actor.pk, connection),
        connection.ops.adapt_datetimefield_value(now),
        1,
    ]
    # BOUND needs bound_at (CHECK); still omit failed_at and failure_source
    columns.append(col["bound_at"])
    params.append(connection.ops.adapt_datetimefield_value(now))
    quote = connection.ops.quote_name
    sql = "INSERT INTO {table} ({cols}) VALUES ({vals})".format(
        table=quote(meta.db_table),
        cols=", ".join(quote(c) for c in columns),
        vals=", ".join(["%s"] * len(columns)),
    )
    with connection.cursor() as cur:
        cur.execute(sql, params)

    stored = Placement.objects.get(vm=vm)
    assert stored.status == PlacementStatus.BOUND
    assert stored.failure_source == LEGACY
    assert stored.failed_at is None
