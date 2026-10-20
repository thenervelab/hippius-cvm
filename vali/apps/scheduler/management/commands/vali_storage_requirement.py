"""`vali_storage_requirement` — read-only view of "compute requires storage".

    python manage.py vali_storage_requirement --evaluate [--json]

Reads the chain NOW (`read-storage-families`) and prints, for every compute
family: its compute nodes, its Arion storage children and why each did or did
not count, whether the family is healthy, and the state the requirement gives
it (`ok`, `exempt`, `grace`, `lapsed`) with `lapsed_since` / `grace_until` —
whether or not `VALI_COMPUTE_REQUIRES_STORAGE` is on. It writes nothing; a family vali
has no recorded state for is judged as new (no grace), as the first refresh
after turning the requirement on would. Run it before turning it on, and copy
any family to exempt from the `family_ss58` column into
`VALI_COMPUTE_STORAGE_EXEMPT_FAMILIES`.
"""

from __future__ import annotations

import json
from typing import Any

from django.core.management.base import BaseCommand, CommandError

from apps.scheduler import storage_requirement
from apps.scheduler.chain import ChainReadUnavailable


class Command(BaseCommand):
    help = "Read-only: what the compute-requires-storage rule decides for every compute family."

    def add_arguments(self, parser: Any) -> None:
        parser.add_argument(
            "--evaluate", action="store_true", required=True, help="Evaluate (read-only)."
        )
        parser.add_argument("--json", action="store_true", help="One JSON object.")

    def handle(self, *args: Any, **options: Any) -> None:
        try:
            report = storage_requirement.evaluate()
        except ChainReadUnavailable as exc:
            raise CommandError(f"chain read failed: {exc}") from exc
        if options["json"]:
            self.stdout.write(json.dumps(report, sort_keys=True))
            return
        for f in report["families"]:
            uncounted = ",".join(
                f"{c['child'][:8]}[{c['reason']}]" for c in f["children"] if not c["counted"]
            )
            lapse = "".join(
                f" {k}={f[k]}" for k in ("unhealthy_since", "lapsed_since", "grace_until") if f[k]
            )
            self.stdout.write(
                f"{f['family_ss58']} compute={len(f['compute_node_ids'])} "
                f"storage={f['family_storage_children']}/{f['storage_required']} "
                f"healthy={f['healthy']} tracked={f['tracked']} "
                f"state={f['state']}{lapse}"
                + (f" not-counted={uncounted}" if uncounted else "")
            )
        cut = sum(1 for f in report["families"] if not f["allowed"])
        self.stdout.write(
            f"{len(report['families'])} compute family(ies), {cut} cut; "
            f"requirement on={report['requirement_on']}"
            + ("; GATE INERT: " + report["exemption_error"] if report["gate_inert"] else "")
            + "; nothing written"
        )
