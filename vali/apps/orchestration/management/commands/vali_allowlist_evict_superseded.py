"""`vali_allowlist_evict_superseded` — drop every superseded launch from the
§22 allowlist now (`allowlist_pin.evict_superseded_measurements`).

The orchestration tick does the same every cycle; this is for the operator:

- after a vali rollout: a pod of the previous image re-carries every
  measurement a live VM ever pinned, so a measurement it reinstalled after
  the new code evicted it is not retried by the tick (the row is already
  stamped). `--force` re-signs `base ∪ carry-forward` regardless — run it
  once every old pod is gone;
- to check: `--dry-run` lists what is pending, installs nothing.
"""

from __future__ import annotations

from typing import Any

from django.core.management.base import BaseCommand

from apps.orchestration.services import allowlist_pin


class Command(BaseCommand):
    help = "Evict superseded launch measurements from the §22 allowlist."

    def add_arguments(self, parser: Any) -> None:
        parser.add_argument("--dry-run", action="store_true", help="List, install nothing.")
        parser.add_argument(
            "--force",
            action="store_true",
            help="Re-sign base ∪ carry-forward even when nothing is pending.",
        )

    def handle(self, *args: Any, **opts: Any) -> None:
        pending = allowlist_pin.pending_superseded_pins()
        for row in pending:
            self.stdout.write(
                f"pending vm={row.vm_id} measurement={row.launch_digest_hex[:16]}… "
                f"pinned_at={row.pinned_at.isoformat()}"
            )
        if opts["dry_run"]:
            self.stdout.write(f"{len(pending)} pending (dry run, nothing installed)")
            return
        evicted = allowlist_pin.evict_superseded_measurements()
        if not evicted and opts["force"]:
            result = allowlist_pin.refresh_allowlist()
            self.stdout.write(f"re-signed base ∪ carry-forward at epoch {result.new_epoch}")
        self.stdout.write(f"evicted {evicted}")
