"""`vali_cdn_fleet` — the CDN fleet keyring (`apps.cdn.fleet`).

    manage.py vali_cdn_fleet list
    manage.py vali_cdn_fleet mint             # a new version, recorded pending
    manage.py vali_cdn_fleet state <v> <active|retiring|retired>

`mint` needs the merged K2 KBS live with `[cdn_fleet] enabled`, the Transit
key `cdn-fleet`, and `VALI_CDN_KBS_RESPONSE_VK_HEX`. A pending version
becomes active on its own once every live node was launched after it
(`apps.cdn.reconcile`); `state` is the operator's override. Retire a
version only once the backend confirms no sealed blob references it.
"""

from __future__ import annotations

from typing import Any

from django.core.management.base import BaseCommand, CommandError

from apps.cdn import fleet
from apps.cdn.models import CdnFleetKey


class Command(BaseCommand):
    help = "List, mint or move CDN fleet key versions."

    def add_arguments(self, parser: Any) -> None:
        sub = parser.add_subparsers(dest="action", required=True)
        sub.add_parser("list")
        sub.add_parser("mint")
        state = sub.add_parser("state")
        state.add_argument("version", type=int)
        state.add_argument("state", choices=["active", "retiring", "retired"])

    def handle(self, *args: Any, **options: Any) -> None:
        action = options["action"]
        try:
            if action == "list":
                for row in CdnFleetKey.objects.all():
                    self.stdout.write(f"v{row.version}\t{row.state}\t{row.created_at:%Y-%m-%d}")
            elif action == "mint":
                row = fleet.record(fleet.source().mint())
                self.stdout.write(f"v{row.version} minted (pending)")
            elif action == "state":
                row = fleet.set_state(options["version"], options["state"])
                self.stdout.write(f"v{row.version} {row.state}")
        except fleet.FleetKeyError as exc:
            raise CommandError(f"{exc.code}: {exc.detail}") from exc
        except Exception as exc:  # noqa: BLE001 — surfaced, never swallowed
            raise CommandError(f"fleet key {action} failed: {exc}") from exc
