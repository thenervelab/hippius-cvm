"""`vali_tenant_bake_close_orphan` — close a Running bake whose pod is gone.

    python manage.py vali_tenant_bake_close_orphan <bake_id> --reason "pod gone since 2026-07-08"

A baker pod that dies before its `/finalize` leaves the row Running
forever (e.g. a bake left Running for weeks). The golden re-bake's serial
gate already stops counting a Running row claimed more than
`VALI_TENANT_BAKE_ORPHAN_RUNNING_S` ago, but that is an age rule; this is
the explicit close an operator runs after checking the bake's Job/pod is
really gone (`kubectl -n vali get job tenant-bake-<bake_id>`):

- only a **Running** row, claimed (`started_at`) at least `--min-age-hours`
  ago (default 6). A Queued row is never closed here: `vali_bake_spawn`
  may start it at any moment;
- CAS on `version` → `Failed` with `failure_reason="orphan closed by
  operator: <reason>"`. Terminal rows are immutable, so a pod that was in
  fact alive gets a 409 on its finalize instead of resurrecting the row.

Exit codes: 0 closed (JSON on stdout), 8 refused (CommandError).
"""

from __future__ import annotations

import json
from datetime import timedelta
from typing import Any

from django.core.management.base import BaseCommand, CommandError
from django.db.models import F
from django.utils import timezone

from apps.tenant_bake.models import TenantBake, TenantBakeState


class Command(BaseCommand):
    help = "Mark an orphaned Running tenant bake Failed (operator, explicit)."

    def add_arguments(self, parser: Any) -> None:
        parser.add_argument("bake_id")
        parser.add_argument("--reason", required=True, help="Why it is an orphan (audit).")
        parser.add_argument("--min-age-hours", type=float, default=6.0)

    def handle(self, *args: Any, **opts: Any) -> None:
        reason = opts["reason"].strip()
        if not reason:
            raise CommandError("--reason must be non-empty")
        try:
            bake = TenantBake.objects.get(bake_id=opts["bake_id"])
        except TenantBake.DoesNotExist:
            raise CommandError(f"bake_id {opts['bake_id']!r} not found") from None
        if bake.state != TenantBakeState.RUNNING.value:
            raise CommandError(
                f"bake {bake.bake_id} is {bake.state!r}, not running — only a Running "
                "orphan can be closed (a Queued row may still be spawned)"
            )
        min_age = timedelta(hours=float(opts["min_age_hours"]))
        if bake.started_at is None or timezone.now() - bake.started_at < min_age:
            raise CommandError(
                f"bake {bake.bake_id} was claimed at {bake.started_at} — younger than "
                f"{opts['min_age_hours']}h, it may still be baking"
            )
        failure_reason = f"orphan closed by operator: {reason}"[:256]
        now = timezone.now()
        updated = TenantBake.objects.filter(
            pk=bake.pk, state=TenantBakeState.RUNNING.value, version=bake.version
        ).update(
            state=TenantBakeState.FAILED.value,
            failure_reason=failure_reason,
            finished_at=now,
            version=F("version") + 1,
        )
        if updated != 1:
            raise CommandError(f"bake {bake.bake_id} changed while closing it — re-read and retry")
        self.stdout.write(
            json.dumps(
                {
                    "bake_id": bake.bake_id,
                    "vm_id": bake.vm_id,
                    "state": TenantBakeState.FAILED.value,
                    "failure_reason": failure_reason,
                    "started_at": bake.started_at.isoformat(),
                }
            )
        )
