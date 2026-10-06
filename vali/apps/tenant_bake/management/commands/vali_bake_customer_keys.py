"""`vali_bake_customer_keys` — the OPERATOR switch that marks a golden bake
as able to boot customer-held-key VMs (`key_mode=split|customer`).

A bake is capable only if its initramfs carries the guest's guardian leg
(`guest-release` with the customer-keys support). vali cannot see that from
the bake row, so the operator asserts it here, per bake, once the re-bake
that includes it has been verified. A launch with `key_mode=split|customer`
is refused unless the golden bake it resolves to is marked (and the
`VALI_CUSTOMER_KEYS_ENABLED` flag is on).

Only a Succeeded `golden_verity_overlay` bake can be marked.

## Usage

    python manage.py vali_bake_customer_keys <bake_id> --enable
    python manage.py vali_bake_customer_keys <bake_id> --disable

`--disable` only stops NEW customer-keys launches off the bake; VMs already
running M1/M2 keep relaunching under their pinned mode.

## Exit codes

    0   Updated (JSON summary on stdout).
    8   Bad argument / unknown bake (CommandError).
    9   The bake is not a Succeeded golden bake.
"""

from __future__ import annotations

import json
import sys
from typing import Any

from django.core.management.base import BaseCommand, CommandError

EXIT_BAKE_NOT_GOLDEN = 9


class Command(BaseCommand):
    help = "Mark (or unmark) a golden bake as supporting customer-held disk keys."

    def add_arguments(self, parser: Any) -> None:
        parser.add_argument("bake_id")
        group = parser.add_mutually_exclusive_group(required=True)
        group.add_argument("--enable", action="store_true")
        group.add_argument("--disable", action="store_true")

    def handle(self, *args: Any, **opts: Any) -> None:
        from apps.tenant_bake.models import TenantBake, TenantBakeDiskMode, TenantBakeState

        bake_id = str(opts["bake_id"])
        bake = TenantBake.objects.filter(bake_id=bake_id).first()
        if bake is None:
            raise CommandError(f"bake {bake_id!r} not found")
        if (
            bake.state != TenantBakeState.SUCCEEDED.value
            or bake.disk_mode != TenantBakeDiskMode.GOLDEN_VERITY_OVERLAY.value
        ):
            self.stderr.write(
                f"bake {bake_id!r} is not a Succeeded golden_verity_overlay bake "
                f"(state={bake.state!r} disk_mode={bake.disk_mode!r})"
            )
            sys.exit(EXIT_BAKE_NOT_GOLDEN)
        enable = bool(opts["enable"])
        previous = bool(bake.supports_customer_keys)
        TenantBake.objects.filter(pk=bake.pk).update(supports_customer_keys=enable)
        self.stdout.write(
            json.dumps(
                {
                    "bake_id": bake_id,
                    "supports_customer_keys": enable,
                    "previous": previous,
                }
            )
        )
