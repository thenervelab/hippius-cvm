"""`vali_scheduler_reeval` — continuous §23/§13 re-evaluation loop.

Spec of record: ARCHITECTURE.md §23 ("continuous re-evaluation") /
§13 (drain + quarantine).

Runs [`service.reeval_once`] on a fixed interval. Each cycle reads a
fresh on-chain snapshot, refreshes the `MinerCapacity` mirror, and
§13-drains any `Bound` placement whose miner has left `Active` state
(quarantined / decommissioned / gone) or whose score has gone stale.

Fail-closed: a cycle whose chain read fails is **skipped** with an
error log — the loop never drains on a failed read (that would be a
self-inflicted mass-quarantine on a transient RPC blip) and never
crashes the daemon.

`--once` runs a single cycle and exits — useful for a cron-driven
deployment and for tests.

Each cycle also surveys the DATA-disk dimension (`disk_survey`): every
host's disk over-claim is logged (the disk twin of the RAM over-claim
warning), and — when `VALI_SYNTHETIC_PUSHGATEWAY_URL` is set, the same
convention as the geo-probe — per-host gauges are pushed:
`hippius_vali_disk_budget_gb` / `_committed_gb` / `_free_gb` (known hosts),
`hippius_vali_disk_known`, `hippius_vali_disk_over_claim`, and
`hippius_vali_disk_gate_would_refuse{flavor}` (1 when `enforce` would
refuse that offered flavor there right now, whatever the mode — the
`record`-mode metric). Per-decision would-rejects are the structured
`disk_gate_would_reject` log lines.

It also pushes each miner's SEV-SNP host-health report from the v5
heartbeat (`host_health_survey`, job `vali-host-health`):
`hippius_miner_snp_enabled`, `hippius_miner_cpus_offline`,
`hippius_miner_snp_launches_since_boot`, `hippius_miner_df_flush_failures`
and `hippius_miner_host_health_reported_timestamp_seconds`, labelled
`node_id` + `miner_id`, for every ACTIVE registered miner, plus
`hippius_miner_host_health_reporting` (0 until its first v5 report). The
`hippius-miner-host-health` PrometheusRule alerts on them.
"""

from __future__ import annotations

import logging
import signal
import time
from typing import Any

from django.conf import settings
from django.core.management.base import BaseCommand

from apps.scheduler import service
from apps.scheduler.chain import ChainReadUnavailable

log = logging.getLogger("apps.scheduler.reeval")

M_DISK_BUDGET = "hippius_vali_disk_budget_gb"
M_DISK_COMMITTED = "hippius_vali_disk_committed_gb"
M_DISK_FREE = "hippius_vali_disk_free_gb"
M_DISK_KNOWN = "hippius_vali_disk_known"
M_DISK_OVER_CLAIM = "hippius_vali_disk_over_claim"
M_DISK_WOULD_REFUSE = "hippius_vali_disk_gate_would_refuse"


def disk_survey() -> None:
    """Log disk over-claims and push the per-host disk gauges. Never raises:
    observability must not stop the re-evaluation it rides on."""
    try:
        from apps.orchestration.services import flavors

        budgets = service.disk_budgets_by_node()
        service.warn_disk_over_claims(budgets)
        gateway = str(getattr(settings, "VALI_SYNTHETIC_PUSHGATEWAY_URL", "") or "")
        if not gateway:
            return
        from apps.synthetic import metrics

        offered = [n for n in flavors.FLAVOR_NAMES if flavors.is_offered(n)]
        ms = metrics.MetricSet()
        for nid, d in sorted(budgets.items()):
            ms.gauge(M_DISK_KNOWN, 1.0 if d.known else 0.0, node_id=nid)
            ms.gauge(M_DISK_OVER_CLAIM, 1.0 if d.over_claim else 0.0, node_id=nid)
            ms.gauge(M_DISK_COMMITTED, d.committed_gb, node_id=nid)
            if d.known:
                ms.gauge(M_DISK_BUDGET, d.budget_gb, node_id=nid)
                ms.gauge(M_DISK_FREE, d.free_gb, node_id=nid)
            for name in offered:
                refused = bool(service.disk_refusal(d, service.flavor_disk_gb(name)))
                ms.gauge(M_DISK_WOULD_REFUSE, 1.0 if refused else 0.0, node_id=nid, flavor=name)
        metrics.push(ms, gateway_url=gateway, job="vali-disk", grouping_key={}, replace=True)
    except Exception:  # noqa: BLE001 — observability must never break the loop.
        log.exception("disk survey failed")


M_SNP_ENABLED = "hippius_miner_snp_enabled"
M_CPUS_OFFLINE = "hippius_miner_cpus_offline"
M_SNP_LAUNCHES = "hippius_miner_snp_launches_since_boot"
M_DF_FLUSH_FAILURES = "hippius_miner_df_flush_failures"
M_HOST_HEALTH_TS = "hippius_miner_host_health_reported_timestamp_seconds"
M_HOST_HEALTH_REPORTING = "hippius_miner_host_health_reporting"

# The survey must never hold the drain loop up for long on a dead gateway.
_HOST_HEALTH_PUSH_TIMEOUT_S = 3.0


def host_health_survey() -> None:
    """Push the latest v5 host-health report of every ACTIVE registered
    miner. The whole group is replaced each cycle, so a miner that leaves
    the active set drops out at once, and one that stops reporting keeps
    an ageing timestamp (`MinerHostHealthReportStale`). Never raises:
    observability must not stop the re-evaluation."""
    try:
        gateway = str(getattr(settings, "VALI_SYNTHETIC_PUSHGATEWAY_URL", "") or "")
        if not gateway:
            return
        from apps.miners.models import MinerIdentity, MinerStatus
        from apps.scheduler.models import MinerCapacity
        from apps.synthetic import metrics

        active = dict(
            MinerIdentity.objects.filter(status=MinerStatus.ACTIVE.value)
            .exclude(chain_node_id="")
            .values_list("chain_node_id", "miner_id")
        )
        reports = {
            row.miner_node_id: row
            for row in MinerCapacity.objects.filter(
                miner_node_id__in=active, host_health_reported_at__isnull=False
            )
        }
        ms = metrics.MetricSet()
        for nid in sorted(active):
            labels = {"node_id": nid, "miner_id": active[nid]}
            row = reports.get(nid)
            ms.gauge(M_HOST_HEALTH_REPORTING, 0.0 if row is None else 1.0, **labels)
            if row is None:
                continue
            ms.gauge(M_HOST_HEALTH_TS, row.host_health_reported_at.timestamp(), **labels)
            if row.reported_snp_enabled is not None:
                ms.gauge(M_SNP_ENABLED, 1.0 if row.reported_snp_enabled else 0.0, **labels)
            for name, value in (
                (M_CPUS_OFFLINE, row.reported_cpus_offline),
                (M_SNP_LAUNCHES, row.reported_snp_launches_since_boot),
                (M_DF_FLUSH_FAILURES, row.reported_df_flush_failures),
            ):
                if value is not None:
                    ms.gauge(name, value, **labels)
        metrics.push(
            ms,
            gateway_url=gateway,
            job="vali-host-health",
            grouping_key={},
            replace=True,
            timeout_s=_HOST_HEALTH_PUSH_TIMEOUT_S,
        )
    except Exception:  # noqa: BLE001 — observability must never break the loop.
        log.exception("host-health survey failed")


class Command(BaseCommand):
    help = (
        "Continuously re-evaluate Bound placements; §13-drain miners "
        "that leave Active state (ARCHITECTURE.md §23/§13)."
    )

    def add_arguments(self, parser: Any) -> None:
        parser.add_argument(
            "--once",
            action="store_true",
            help="Run a single re-evaluation cycle and exit.",
        )

    def handle(self, *args: Any, **options: Any) -> None:
        once: bool = options["once"]
        interval = float(getattr(settings, "VALI_SCHEDULER_REEVAL_INTERVAL_S", 30.0))

        self._running = True

        def _stop(signum: int, _frame: Any) -> None:
            # Finish the in-flight cycle, then exit cleanly — never
            # abandon a cycle mid-drain.
            self._running = False
            log.info(
                "vali_scheduler_reeval received signal %s — stopping after "
                "this cycle",
                signum,
            )

        signal.signal(signal.SIGTERM, _stop)
        signal.signal(signal.SIGINT, _stop)

        log.info(
            "vali_scheduler_reeval started (interval=%.1fs once=%s)",
            interval,
            once,
        )
        while self._running:
            try:
                report = service.reeval_once()
                log.info(
                    "reeval cycle: epoch=%d miners=%d bound_checked=%d drained=%d held=%d",
                    report.current_epoch,
                    report.miners_seen,
                    report.bound_checked,
                    report.drained,
                    # Unhealthy-miner placements kept because their VM is
                    # still live there (`service.reeval_once`).
                    report.held,
                )
            except ChainReadUnavailable as exc:
                # Fail-closed: skip the cycle, do NOT drain.
                log.error("reeval cycle skipped — chain read failed: %s", exc)
            except Exception:  # noqa: BLE001 — daemon loop must survive.
                log.exception("reeval cycle raised — continuing")
            disk_survey()
            host_health_survey()

            if once:
                break
            self._sleep(interval)

        log.info("vali_scheduler_reeval stopped")

    def _sleep(self, interval: float) -> None:
        """Interruptible sleep — a SIGTERM ends the loop within ~0.5s
        instead of waiting out the full interval.
        """
        slept = 0.0
        while self._running and slept < interval:
            step = min(0.5, interval - slept)
            time.sleep(step)
            slept += step
