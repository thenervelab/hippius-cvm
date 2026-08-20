"""`vali_host_attestor_reconcile` — WARN-ONLY host-attestor coverage report.

Blackbox host-attestor chantier PR-9. Computes, for each on-chain-Active
miner, whether there is an `attested` (NEVER `pending` — the HARD
CONSTRAINT) host-attestor seen within the liveness window on a DESIRED
measurement ({current, previous}). Emits advisory logs (warn) for miners
MISSING coverage or on a STALE measurement.

It MUST NOT gate, dispatch, or reward — this is purely observational (that
arms in PR-11). Default-inert: the findings are advisory. If the KBS L0
verifying key is unwired, every ingested cert stays `pending`, so this
honestly reports zero coverage (logged clearly) — the correct state.

Runs a SINGLE reconcile and exits (CronJob-driven). `--json` prints the
report as JSON for machine consumption / metrics scraping.
"""

from __future__ import annotations

import json
import logging
from typing import Any

from django.core.management.base import BaseCommand

log = logging.getLogger("apps.telemetry.host_attestor_reconcile")


class Command(BaseCommand):
    help = "WARN-ONLY host-attestor fleet coverage report (gates nothing)."

    def add_arguments(self, parser: Any) -> None:
        parser.add_argument(
            "--json",
            action="store_true",
            help="Emit the coverage report as a JSON line on stdout.",
        )

    def handle(self, *args: Any, **options: Any) -> None:
        # Imported here so a missing/misconfigured chain reader raises at
        # run time (not import time), keeping the command loadable.
        from apps.scheduler import chain
        from apps.telemetry import release_service

        try:
            report = release_service.reconcile_coverage()
        except chain.ChainReadUnavailable as exc:
            # Warn-only: a chain-read failure is non-fatal (the report is
            # advisory). Log + exit 0 so the CronJob does not alarm-loop.
            log.warning(
                "host-attestor reconcile skipped — on-chain fleet unreadable: %s",
                exc,
            )
            self.stdout.write("host-attestor reconcile skipped (chain unreadable)")
            return

        if not report.desired_measurements:
            log.warning(
                "host-attestor reconcile: NO active release pinned yet — "
                "nothing desired, %d active miner(s) all reported MISSING "
                "(WARN-ONLY, gates nothing)",
                report.total_active_miners,
            )

        log.info(
            "host-attestor coverage: active_miners=%d covered=%d missing=%d "
            "stale=%d desired=%s (WARN-ONLY)",
            report.total_active_miners,
            report.covered,
            report.missing,
            report.stale,
            [m[:16] + "…" for m in report.desired_measurements],
        )
        # Per-miner warnings for the operator dashboard — every non-covered
        # Active miner is called out, but NOTHING is gated.
        for cov in report.per_miner:
            if cov.covered:
                continue
            level = log.warning
            level(
                "host-attestor coverage gap: node_id=%s %s%s",
                cov.node_id,
                "STALE-measurement " if cov.stale_measurement else "MISSING ",
                f"({cov.reason})",
            )

        if options["json"]:
            self.stdout.write(
                json.dumps(
                    {
                        "total_active_miners": report.total_active_miners,
                        "covered": report.covered,
                        "missing": report.missing,
                        "stale": report.stale,
                        "desired_measurements": list(report.desired_measurements),
                        "per_miner": [
                            {
                                "node_id": c.node_id,
                                "covered": c.covered,
                                "stale_measurement": c.stale_measurement,
                                "reason": c.reason,
                            }
                            for c in report.per_miner
                        ],
                    }
                )
            )
        else:
            self.stdout.write(
                f"host-attestor coverage: active={report.total_active_miners} "
                f"covered={report.covered} missing={report.missing} "
                f"stale={report.stale}"
            )
