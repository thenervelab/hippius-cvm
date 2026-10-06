"""`vali_backfill_tombstone_power_at` — date the power axis of VMs destroyed
before the tombstone stamped it.

Migration `lifecycle.0017` turned every destroyed row `off` and gave it
`power_state_at = updated_at`, the best date it had. For rows tombstoned by
the old CAS that date is stale — the transition never bumped `updated_at`
(seen in production: destroyed 09-27 03:02, read 09-25 15:47). A row whose
§24 job finished knows better: that job's `finished_at`.

Touches only a destroyed, `off` row with a `done` DecommissionJob, and only
a LEGACY one: its `power_state_at` no later than when 0017 was applied (the
backfill copied an older `updated_at`; every tombstone since stamps its own
CAS time, after that). A real tombstone date is never rewritten, however
long its job took to finish — the billing layer reads it. Rows without a
finished job are left unchanged. `updated_at` is kept: these
rows must not jump to the top of the `-updated_at` listing.

    manage.py vali_backfill_tombstone_power_at [--commit]

Dry-run is the DEFAULT: nothing is written without `--commit`. Idempotent.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from django.core.management.base import BaseCommand, CommandError, CommandParser
from django.db import connection
from django.db.migrations.recorder import MigrationRecorder
from django.db.models import F, Max

from apps.lifecycle.models import Vm, VmPowerState, VmState
from apps.orchestration.models import DecommissionJob, DecommissionState

#: The migration that stamped legacy tombstones with their `updated_at`.
BACKFILL_MIGRATION = ("lifecycle", "0017_vm_power_state_off")


def legacy_cutoff() -> datetime:
    """When 0017 ran: a tombstone dated no later is a legacy one."""
    app, name = BACKFILL_MIGRATION
    row = MigrationRecorder(connection).migration_qs.filter(app=app, name=name).first()
    if row is None:
        raise CommandError(f"{app}.{name} is not applied: nothing to tell legacy rows by")
    return row.applied


def planned() -> list[tuple[Vm, Any]]:
    """`(vm, finished_at)` for every row the backfill would change."""
    cutoff = legacy_cutoff()
    finished = dict(
        DecommissionJob.objects.filter(
            state=DecommissionState.DONE.value,
            finished_at__isnull=False,
            vm__state=VmState.DESTROYED.value,
            vm__power_state=VmPowerState.OFF.value,
        )
        .values("vm")
        .annotate(t=Max("finished_at"))
        .values_list("vm", "t")
    )
    out = []
    for vm in Vm.objects.filter(pk__in=finished).order_by("vm_id"):
        at = finished[vm.pk]
        legacy = vm.power_state_at is None or vm.power_state_at <= cutoff
        if legacy and vm.power_state_at != at:
            out.append((vm, at))
    return out


class Command(BaseCommand):
    help = "Date destroyed VMs' power_state_at from their finished §24 job (dry-run by default)."

    def add_arguments(self, parser: CommandParser) -> None:
        parser.add_argument(
            "--commit", action="store_true", help="Write the change (default: dry-run)."
        )

    def handle(self, *args: Any, **opts: Any) -> None:
        commit: bool = opts["commit"]
        rows = planned()
        written = 0
        for vm, at in rows:
            self.stdout.write(
                f"{vm.vm_id}: power_state_at {vm.power_state_at} -> {at}"
                + ("" if commit else " (dry-run)")
            )
            if commit:
                # Filtered on the value read, so a concurrent write wins.
                written += Vm.objects.filter(
                    pk=vm.pk,
                    state=VmState.DESTROYED.value,
                    power_state=VmPowerState.OFF.value,
                    power_state_at=vm.power_state_at,
                ).update(power_state_at=at, updated_at=F("updated_at"))
        self.stdout.write(
            f"{written} row(s) written of {len(rows)}"
            if commit
            else f"{len(rows)} row(s) would be written (dry-run; --commit to write)"
        )
