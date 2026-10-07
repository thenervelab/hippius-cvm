"""`vali_cdn_node` — the CDN nodes (`apps.cdn.reconcile`).

    manage.py vali_cdn_node list
    manage.py vali_cdn_node drain <node_id>          # replace it (reason: operator)
    manage.py vali_cdn_node force-drained <node_id>  # stand in for the backend's dns-released

`force-drained` is the operator override of the decommission gate: it records
that the node's DNS record is gone without the backend's ack, so the node is
decommissioned after `VALI_CDN_DRAIN_GRACE_S`. Use it only once you have
checked the record is gone; it is logged and marked on the node
(`dns_release_forced`).
"""

from __future__ import annotations

import logging
from typing import Any

from django.core.management.base import BaseCommand, CommandError
from django.db import transaction
from django.utils import timezone

from apps.cdn import reconcile
from apps.cdn.models import CdnNode, CdnNodeState, CdnRevision, DrainReason

log = logging.getLogger("apps.cdn")


class Command(BaseCommand):
    help = "List, drain or force-drain CDN nodes."

    def add_arguments(self, parser: Any) -> None:
        sub = parser.add_subparsers(dest="action", required=True)
        sub.add_parser("list", help="List the nodes.")
        drain = sub.add_parser("drain", help="Replace a node.")
        drain.add_argument("node_id")
        forced = sub.add_parser("force-drained", help="Record a node's DNS record as gone.")
        forced.add_argument("node_id")

    def handle(self, *args: Any, **options: Any) -> None:
        action = options["action"]
        if action == "list":
            for n in CdnNode.objects.all():
                ready = f"{n.ready_at:%Y-%m-%dT%H:%MZ}" if n.ready_at else "-"
                released = (
                    "forced" if n.dns_release_forced else ("yes" if n.dns_released_at else "-")
                )
                self.stdout.write(
                    f"{n.node_id}\t{n.region}\t{n.state}\tready={ready}"
                    f"\tdrain={n.drain_reason or '-'}\tdns_released={released}"
                )
        elif action == "drain":
            try:
                reconcile.request_drain(options["node_id"], DrainReason.OPERATOR)
            except LookupError as exc:
                raise CommandError(f"no CDN node {options['node_id']!r}") from exc
            except ValueError as exc:
                raise CommandError(f"node {options['node_id']!r} is not drainable") from exc
            self.stdout.write(f"{options['node_id']}: drain requested")
        elif action == "force-drained":
            self._force(options["node_id"])

    def _force(self, node_id: str) -> None:
        with transaction.atomic():
            node = CdnNode.objects.select_for_update().filter(node_id=node_id).first()
            if node is None:
                raise CommandError(f"no CDN node {node_id!r}")
            if node.state not in (CdnNodeState.DRAINING, CdnNodeState.FAILED):
                raise CommandError(f"node {node_id!r} is {node.state}: drain it first")
            if node.dns_released_at is not None:
                self.stdout.write(f"{node_id}: DNS already released")
                return
            node.dns_released_at = timezone.now()
            node.dns_release_forced = True
            node.save(update_fields=["dns_released_at", "dns_release_forced", "updated_at"])
            CdnRevision.bump()
        log.warning("cdn: node %s DNS release FORCED by an operator", node_id)
        self.stdout.write(f"{node_id}: DNS release recorded (forced)")
