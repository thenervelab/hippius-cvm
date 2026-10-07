"""`vali_net_policy` — read the guest network policy state
(docs/design/egress-and-bandwidth.md §7).

    manage.py vali_net_policy [--show]
        # one line per miner: region, mode, revision, acked revision and
        # age, placement readiness, last error; then the egress regions

    manage.py vali_net_policy --body <miner_id>
        # the policy content vali would push that miner now (JSON, no
        # revision or expiry). Writes nothing, sends nothing.

    manage.py vali_net_policy --retry <miner_id>
        # after an agent upgrade: lift the hold on a miner that refused
        # edge mode as unsupported and reset the apply backoff; the next
        # tick sends its current revision.

Pushing happens in the orchestration tick (VALI_NET_POLICY_PUSH,
VALI_NET_POLICY_MINERS).
"""

from __future__ import annotations

import json
from typing import Any

from django.conf import settings
from django.core.management.base import BaseCommand, CommandError
from django.utils import timezone

from apps.miners.models import MinerIdentity
from apps.network import net_policy
from apps.network.models import EgressMode, EgressRegion, MinerNetPolicy


class Command(BaseCommand):
    help = "Show the per-miner net-policy state, or the body a miner would get."

    def add_arguments(self, parser: Any) -> None:
        group = parser.add_mutually_exclusive_group()
        group.add_argument("--show", action="store_true", help="per-miner state (default)")
        group.add_argument("--body", metavar="MINER_ID", help="the content a miner would get now")
        group.add_argument(
            "--retry", metavar="MINER_ID", help="lift the unsupported hold and apply backoff"
        )

    def handle(self, *args: Any, **options: Any) -> None:
        if options["body"]:
            self._body(options["body"])
        elif options["retry"]:
            self._retry(options["retry"])
        else:
            self._show()

    def _body(self, miner_id: str) -> None:
        miner = MinerIdentity.objects.select_related("location").filter(miner_id=miner_id).first()
        if miner is None:
            raise CommandError(f"no miner {miner_id!r}")
        region = net_policy.miner_region(miner)
        if not region:
            raise CommandError(f"miner {miner_id!r} has no detected country")
        try:
            content = net_policy.build_content(miner, region)
        except net_policy.PolicyError as exc:
            raise CommandError(f"build: {exc}") from exc
        self.stdout.write(json.dumps(content, indent=2, sort_keys=True))

    def _retry(self, miner_id: str) -> None:
        n = MinerNetPolicy.objects.filter(miner_id=miner_id).update(
            edge_unsupported_at=None, apply_failures=0, sent_at=None
        )
        if not n:
            raise CommandError(f"no net-policy row for miner {miner_id!r}")
        self.stdout.write(f"{miner_id}: hold lifted; the next tick sends its current revision")

    def _show(self) -> None:
        now = timezone.now()
        self.stdout.write(
            f"push={'on' if settings.VALI_NET_POLICY_PUSH else 'off'} "
            f"miners={','.join(settings.VALI_NET_POLICY_MINERS) or '-'} "
            f"local_action={settings.VALI_NET_POLICY_LOCAL_ACTION}"
        )
        edge_regions = set(
            EgressRegion.objects.filter(mode=EgressMode.EDGE).values_list("region", flat=True)
        )
        header = (
            f"{'miner':<20} {'sel':<3} {'region':<6} {'mode':<5} {'rev':>5} {'acked':>5} "
            f"{'ack age':>8} {'placeable':<22} last_error"
        )
        self.stdout.write(header)
        for miner in MinerIdentity.objects.select_related("location").order_by("miner_id"):
            policy = MinerNetPolicy.objects.filter(miner=miner).first()
            region = net_policy.miner_region(miner)
            age = "-"
            if policy is not None and policy.acked_at is not None:
                age = f"{int((now - policy.acked_at).total_seconds())}s"
            if region in edge_regions:
                placeable = net_policy.readiness(policy, region=region, now=now) or "yes"
            else:
                placeable = "yes (local region)"
            self.stdout.write(
                f"{miner.miner_id:<20} {'y' if net_policy.selected(miner.miner_id) else 'n':<3} "
                f"{region or '??':<6} {(policy.mode if policy else '-'):<5} "
                f"{(policy.revision if policy else 0):>5} "
                f"{(policy.acked_revision if policy else 0):>5} {age:>8} {placeable:<22} "
                f"{(policy.last_error if policy else '')}"
            )
        self.stdout.write("")
        self.stdout.write("egress regions (absent = local):")
        for row in EgressRegion.objects.all():
            self.stdout.write(
                f"  {row.region} mode={row.mode} routing_enabled={row.routing_enabled} "
                f"enforce={row.enforce}"
            )
