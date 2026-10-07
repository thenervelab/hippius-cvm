"""`vali_cdn_ca` — the CDN CA (`apps.cdn.ca`).

    manage.py vali_cdn_ca init              # CA certificate for the Transit key's latest version
    manage.py vali_cdn_ca export [--out F]  # the CA bundle PEM (what GET /v1/cdn/ca.pem serves)
    manage.py vali_cdn_ca status
    manage.py vali_cdn_ca activate <kid>    # pending → active; the old active → retiring
    manage.py vali_cdn_ca retire <kid>      # retiring → retired (out of the bundle)

The private key is the Vault Transit key `VALI_CDN_CA_TRANSIT_KEY`, which an
operator creates first, non-exportable:

    vault write transit/keys/cdn-ca type=ed25519 exportable=false allow_plaintext_backup=false

Rotation: `vault write -f transit/keys/cdn-ca/rotate`, `init` (the new CA is
published as pending), let the backend pick up the bundle, `activate`, and
`retire` the old one once its node certificates have expired.

These run whatever `VALI_CDN_ENABLED` says: the CA and its bundle must exist
before the first node, and the backend installs the bundle before then.
Nothing here issues a node certificate.
"""

from __future__ import annotations

import os
from typing import Any

from django.core.management.base import BaseCommand, CommandError

from apps.cdn import ca
from apps.cdn.models import CdnCaKey


class Command(BaseCommand):
    help = "Manage the CDN CA: init, export, status, activate, retire."

    def add_arguments(self, parser: Any) -> None:
        sub = parser.add_subparsers(dest="action", required=True)
        sub.add_parser("init", help="CA certificate for the Transit key's latest version.")
        export = sub.add_parser("export", help="Print the CA bundle PEM.")
        export.add_argument("--out", default="", help="Write to this file instead of stdout.")
        sub.add_parser("status", help="List the CA versions.")
        activate = sub.add_parser("activate", help="Make a pending CA the signing one.")
        activate.add_argument("kid")
        retire = sub.add_parser("retire", help="Drop a retiring CA from the bundle.")
        retire.add_argument("kid")

    def handle(self, *args: Any, **options: Any) -> None:
        action = options["action"]
        try:
            if action == "init":
                row, created = ca.init_ca()
                verb = "created" if created else "already exists"
                self.stdout.write(f"{row.kid} {verb} ({row.state}, until {row.not_after:%Y-%m-%d})")
            elif action == "export":
                self._export(options["out"])
            elif action == "status":
                for row in CdnCaKey.objects.all():
                    self.stdout.write(
                        f"{row.kid}\t{row.state}\t{row.transit_key} v{row.transit_key_version}"
                        f"\t{row.not_before:%Y-%m-%d}..{row.not_after:%Y-%m-%d}"
                    )
            elif action == "activate":
                row = ca.activate_ca(options["kid"])
                self.stdout.write(f"{row.kid} active")
            elif action == "retire":
                row = ca.retire_ca(options["kid"])
                self.stdout.write(f"{row.kid} retired")
        except ca.CaError as exc:
            raise CommandError(f"{exc.code}: {exc.detail}") from exc

    def _export(self, out: str) -> None:
        pem = ca.bundle_pem()
        if not pem:
            raise CommandError("ca-not-initialised: run `vali_cdn_ca init` first")
        if not out:
            self.stdout.write(pem, ending="")
            return
        tmp = f"{out}.new"
        with open(tmp, "w", encoding="ascii") as fh:
            fh.write(pem)
        os.replace(tmp, out)
        self.stdout.write(
            f"wrote {len(ca.published_cas())} certificate(s) to {out}", self.style.SUCCESS
        )
