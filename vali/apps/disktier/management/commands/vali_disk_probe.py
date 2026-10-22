"""`vali_disk_probe` — one tick of the disk-tier probe orchestrator
(`apps.disktier.probe`, design §4.4, phase R1). RECORD ONLY. Run by the
`disktier-probe` CronJob (suspended until the probe is turned on).

    manage.py vali_disk_probe [--no-push]
    manage.py vali_disk_probe --request <node_id> [--pool <pool_id>]
        # queue an operator probe of the node's pool (default `default`)

While `VALI_DISK_PROBE_ENABLED` is off the tick launches nothing and
pushes nothing; a run left in flight by turning it off is still torn
down.
"""

from __future__ import annotations

import re
from typing import Any

from django.conf import settings
from django.core.management.base import BaseCommand, CommandError
from django.utils import timezone

from apps.disktier import dedicated_probe, probe
from apps.synthetic import metrics

_NODE_ID_RE = re.compile(r"[0-9a-f]{64}")


class Command(BaseCommand):
    help = "One disk-tier probe orchestrator tick (record only), then push its gauges."

    def add_arguments(self, parser: Any) -> None:
        parser.add_argument("--no-push", action="store_true", help="Print the metrics instead.")
        parser.add_argument(
            "--request",
            metavar="NODE_ID",
            default=None,
            help="Queue an operator-requested probe of the node's pool (1 per 7 days).",
        )
        parser.add_argument(
            "--pool",
            metavar="POOL_ID",
            default=None,
            help=(
                "With --request: the pool to probe (default `default`); its OS disk goes on "
                "it. The 1-per-7-days limit is per node, whichever pool."
            ),
        )

    def handle(self, *args: Any, **opts: Any) -> None:
        if opts["request"] is not None:
            self._request(opts["request"], opts["pool"] or probe.DEFAULT_POOL_ID)
            return
        if opts["pool"] is not None:
            raise CommandError("--pool only goes with --request")
        report = probe.tick()
        self.stdout.write(
            f"disk probe: enabled={report.enabled} due={report.due} launched={report.launched} "
            f"refused={report.refused} transitions={dict(report.transitions)} "
            f"torn_down={report.torn_down} forced={report.forced} skipped={dict(report.skipped)}"
        )
        self.stdout.write(
            f"dedicated probe: enabled={report.dedicated_enabled} due={report.dedicated_due} "
            f"launched={report.dedicated_launched} refused={report.dedicated_refused} "
            f"settled={dict(report.dedicated_settled)} skipped={dict(report.dedicated_skipped)}"
        )
        if not report.enabled and not report.dedicated_enabled:
            # Nothing pushed: the alert rules key on a fresh push with
            # `hippius_disk_probe_enabled == 1` (pools) or
            # `hippius_dedicated_probe_enabled == 1` (R3), so they stay silent.
            return
        if report.enabled:
            ms = probe.report_metrics(report)
        else:
            # Dedicated disks only: the pool series stay out of the push (and
            # `hippius_disk_probe_enabled` 0 keeps the pool alerts silent).
            ms = probe.base_metrics(report)
        if report.dedicated_enabled:
            dedicated_probe.report_metrics(ms, report, now=timezone.now())
        if opts["no_push"]:
            self.stdout.write(ms.render())
            return
        pushed = metrics.push(
            ms,
            gateway_url=settings.VALI_SYNTHETIC_PUSHGATEWAY_URL,
            job=settings.VALI_DISK_PROBE_PUSH_JOB,
            grouping_key={"report": "disk-probe"},
            replace=True,
            timeout_s=float(settings.VALI_SYNTHETIC_HTTP_TIMEOUT_S),
        )
        if not pushed:
            raise CommandError("disk probe: the Pushgateway refused or did not answer")

    def _request(self, node_id: str, pool_id: str) -> None:
        if not settings.VALI_DISK_PROBE_ENABLED:
            raise CommandError("VALI_DISK_PROBE_ENABLED is off: no probe is queued")
        nid = node_id.strip().lower()
        if not _NODE_ID_RE.fullmatch(nid):
            raise CommandError(f"{node_id!r} is not a 64-hex node id")
        try:
            run = probe.request_manual(nid, pool_id=pool_id)
        except (ValueError, RuntimeError) as exc:
            raise CommandError(str(exc)) from exc
        # The run id only: the vm id and owner are the probe's identity.
        self.stdout.write(
            f"disk probe: queued run {run.run_id} for node {nid[:12]} pool {run.os_pool_id}"
        )
