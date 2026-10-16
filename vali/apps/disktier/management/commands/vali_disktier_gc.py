"""`vali_disktier_gc` — one bounded retention sweep of the passive disk
tables (`apps.disktier.gc`). Run by the `disktier-gc` CronJob (suspended
until the passive ingest is turned on).

    manage.py vali_disktier_gc
"""

from __future__ import annotations

from typing import Any

from django.core.management.base import BaseCommand

from apps.disktier import gc


class Command(BaseCommand):
    help = "Reap passive disk rows past their retention (bounded batches)."

    def handle(self, *args: Any, **opts: Any) -> None:
        deleted = gc.gc()
        self.stdout.write("disktier gc: " + " ".join(f"{name}={n}" for name, n in deleted.items()))
