"""`vali_cdn_region` — the CDN regions.

    manage.py vali_cdn_region list
    manage.py vali_cdn_region create <XX> [--flavor xlarge] [--failover-region YY]

A region is created inactive with no nodes; `PATCH /v1/cdn/regions/<XX>`
(or `--desired-nodes` / `--active` below) sets its target.
"""

from __future__ import annotations

import re
from typing import Any

from django.core.management.base import BaseCommand, CommandError
from django.db import transaction

from apps.cdn.models import CdnRegion, CdnRevision
from apps.orchestration.services.flavors import is_offered

_REGION_RE = re.compile(r"[A-Z]{2}")


class Command(BaseCommand):
    help = "List or create CDN regions."

    def add_arguments(self, parser: Any) -> None:
        sub = parser.add_subparsers(dest="action", required=True)
        sub.add_parser("list")
        create = sub.add_parser("create")
        create.add_argument("region")
        create.add_argument("--flavor", default="xlarge")
        create.add_argument("--failover-region", default="")

    def handle(self, *args: Any, **options: Any) -> None:
        if options["action"] == "list":
            for r in CdnRegion.objects.all():
                self.stdout.write(
                    f"{r.region}\tactive={r.active}\tdesired={r.desired_nodes}\t{r.flavor}"
                    f"\tfailover={r.failover_region or '-'}"
                )
            return
        region = options["region"].upper()
        failover = options["failover_region"].upper()
        if not _REGION_RE.fullmatch(region) or (failover and not _REGION_RE.fullmatch(failover)):
            raise CommandError("regions are ISO 3166-1 alpha-2 codes")
        if not is_offered(options["flavor"]):
            raise CommandError(f"flavor {options['flavor']!r} is not offered")
        with transaction.atomic():
            _, created = CdnRegion.objects.get_or_create(
                region=region,
                defaults={"flavor": options["flavor"], "failover_region": failover},
            )
            if created:
                CdnRevision.bump()
        self.stdout.write(f"{region}: {'created (inactive, 0 nodes)' if created else 'exists'}")
