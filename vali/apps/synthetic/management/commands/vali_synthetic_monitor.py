"""`vali_synthetic_monitor` — periodic self-test of the live control plane.

    python manage.py vali_synthetic_monitor --tier light
    python manage.py vali_synthetic_monitor --tier full [--distro ubuntu]

Two tiers (see `apps.synthetic`): `light` is read-only fleet health;
`full` launches a THROWAWAY golden VM through the real public API and
ALWAYS decommissions it. Both push result metrics to the Pushgateway;
the `synthetic-monitor` PrometheusRule alerts on `success==0`/staleness
and routes to the Alertmanager Slack receiver.

Exit is 0 by default even on a probe FAILURE — the failure is signalled
via metrics (so alerting is single-sourced through Prometheus, not
duplicated by CronJob pod failures). Pass `--strict` to exit non-zero on
failure for manual debugging.
"""

from __future__ import annotations

import json
import logging
import time
from typing import Any

from django.conf import settings
from django.core.management.base import BaseCommand, CommandError
from django.utils import timezone

from apps.synthetic import ack, checks, e2e, metrics

log = logging.getLogger("apps.synthetic.command")

# Canonical full-e2e stages, in order — every run reports all of them
# (missing ⇒ 0) so a POST update never leaves a stale stage gauge behind.
_E2E_STAGES = (
    "launch",
    "launch_complete",
    "release",
    # The positive control for `crypto_erase` — the KEK observed ALIVE
    # before the decommission. A 0 here means the later "the KEK is gone"
    # would have proved nothing, so it is alertable in its own right.
    "kek_alive",
    "boot",
    "netbird",
    "decommission",
    "crypto_erase",
)


class Command(BaseCommand):
    help = "Synthetic monitor — light (read-only health) or full (e2e VM probe)."

    def add_arguments(self, parser: Any) -> None:
        parser.add_argument("--tier", required=True, choices=["light", "full"])
        parser.add_argument(
            "--distro",
            default="",
            choices=["", *e2e.DISTRO_ROTATION],
            help="Full tier only — override the time-rotated distro.",
        )
        parser.add_argument("--json", action="store_true", help="Emit the result as JSON.")
        parser.add_argument("--no-push", action="store_true", help="Skip the Pushgateway push.")
        parser.add_argument(
            "--strict",
            action="store_true",
            help="Exit non-zero on a probe failure (default: exit 0, alert via metrics).",
        )

    def handle(self, *args: Any, **opts: Any) -> None:
        if opts["tier"] == "light":
            success, payload = self._run_light(opts)
        else:
            success, payload = self._run_full(opts)

        if opts["json"]:
            self.stdout.write(json.dumps(payload))
        else:
            # The headline never says a bare "OK" while something is muted:
            # the count of acknowledged checks rides along with the verdict.
            acked = len(payload.get("ack", {}).get("applied", []))
            note = f" ({acked} ACKNOWLEDGED)" if acked else ""
            self.stdout.write(
                f"synthetic {opts['tier']}: {'OK' if success else 'FAIL'}{note} — {payload}"
            )
        if not success and opts["strict"]:
            raise CommandError(f"synthetic {opts['tier']} probe FAILED")

    # ── light tier ───────────────────────────────────────────────────

    def _run_light(self, opts: dict) -> tuple[bool, dict]:
        results = checks.run_light()
        # Tier roll-up = every check that is NOT validly acknowledged. A
        # standing, accepted failure (today: the fossil `epoch_close`) would
        # otherwise pin `light_success` at 0 forever and make the tier alert
        # unreadable — the same blind spot as an always-OK check, inverted.
        # The per-check verdict below is NOT touched by the ack: the failing
        # check still publishes 0, still logs at WARNING, still appears in
        # the payload. See `apps.synthetic.ack` for why every ack must be
        # named, reasoned and time-boxed.
        outcome = ack.resolve(
            getattr(settings, "VALI_SYNTHETIC_ACK", "") or "",
            results,
            now=timezone.now(),
        )
        success = outcome.effective_success
        # Backstop reaper: catch any synthetic VM / pending launch a killed
        # run (SIGKILL/OOM/eviction) left behind — its finally teardown could
        # not run. Surfaced via `reaped_total` + the SyntheticLeak alert; a
        # reaped resource means a PRIOR run leaked. It never affects
        # `success` (the fleet is healthy NOW), so the staleness timestamp
        # keeps advancing. A reaper crash must never fail the light run.
        try:
            reaper = e2e.run_reaper()
        except Exception as exc:  # defensive — the reaper is a backstop
            log.exception("synthetic reaper crashed")
            reaper = e2e.ReaperResult(detail=f"reaper crashed: {exc}")
        ms = metrics.MetricSet()
        ms.gauge(
            metrics.M_LIGHT_SUCCESS,
            1 if success else 0,
            help_text=(
                "1 if every light-tier check that is not validly "
                "acknowledged passed this run."
            ),
        )
        for r in results:
            ms.gauge(
                metrics.M_LIGHT_CHECK_SUCCESS,
                1 if r.ok else 0,
                help_text="Per-check light-tier pass/fail (NEVER masked by an ack).",
                check=r.name,
            )
            ms.gauge(
                metrics.M_LIGHT_CHECK_ACKED,
                1 if r.name in outcome.applied else 0,
                help_text="1 if this check's failure is validly acknowledged.",
                check=r.name,
            )
            for gname, gval in r.gauges.items():
                ms.gauge(gname, gval)
        # Make the acknowledgements themselves observable: when each expires
        # (so a lapse is warned about BEFORE it reddens the tier), which ones
        # now cover a RESOLVED condition, and how many entries were refused.
        for entry in outcome.entries:
            ms.gauge(
                metrics.M_ACK_EXPIRES_TS,
                entry.expires_ts(),
                help_text="Unix ts at which this check's acknowledgement lapses.",
                check=entry.check,
            )
            ms.gauge(
                metrics.M_ACK_STALE,
                1 if entry.check in outcome.stale else 0,
                help_text="1 if an acknowledged check has since PASSED (remove the ack).",
                check=entry.check,
            )
        ms.gauge(
            metrics.M_ACK_INVALID,
            len(outcome.errors),
            help_text="Acknowledgement entries REFUSED this run (>0 ⇒ the spec is broken).",
        )
        ms.gauge(
            metrics.M_REAPED,
            reaper.reaped_total,
            help_text="Synthetic leaks force-reaped this run (>0 ⇒ a prior run leaked).",
        )
        ms.gauge(metrics.M_RUN_TIMESTAMP, metrics.now())
        if success:
            ms.gauge(
                metrics.M_LAST_SUCCESS_TS,
                metrics.now(),
                help_text="Unix ts of the last fully-successful light run.",
            )
        self._push(opts, ms, grouping_key={"tier": "light"}, replace=success)

        payload = {
            "tier": "light",
            "success": success,
            # An acknowledged check stays in `checks` with its true `ok:
            # false` — it is annotated, never removed. A mute you cannot see
            # in the output is the blind spot we are trying not to build.
            "checks": [
                {
                    "name": r.name,
                    "ok": r.ok,
                    "detail": r.detail,
                    "acknowledged": r.name in outcome.applied,
                    **(
                        {
                            "ack_expires": outcome.applied[r.name].expires_at.isoformat(),
                            "ack_reason": outcome.applied[r.name].reason,
                        }
                        if r.name in outcome.applied
                        else {}
                    ),
                }
                for r in results
            ],
            "ack": {
                "applied": sorted(outcome.applied),
                "stale": sorted(outcome.stale),
                "inert": {k: why for k, (_a, why) in sorted(outcome.inert.items())},
                "errors": outcome.errors,
            },
            "reaped_total": reaper.reaped_total,
            "reaper_detail": reaper.detail,
        }
        for r in results:
            if r.ok:
                log.info("light check %s: OK (%s)", r.name, r.detail)
            elif r.name in outcome.applied:
                a = outcome.applied[r.name]
                log.warning(
                    "light check %s: FAIL [ACKNOWLEDGED until %s — %s] (%s)",
                    r.name,
                    a.expires_at.date(),
                    a.reason,
                    r.detail,
                )
            else:
                log.warning("light check %s: FAIL (%s)", r.name, r.detail)
        for name in sorted(outcome.stale):
            log.warning(
                "acknowledgement for %s is STALE — the check now PASSES; "
                "remove it from VALI_SYNTHETIC_ACK",
                name,
            )
        for name, (_a, why) in sorted(outcome.inert.items()):
            log.warning("acknowledgement for %s did NOT apply: %s", name, why)
        for err in outcome.errors:
            log.error("acknowledgement REFUSED: %s", err)
        if reaper.reaped_total:
            log.warning("synthetic reaper: %s", reaper.detail)
        return success, payload

    # ── full tier ────────────────────────────────────────────────────

    def _run_full(self, opts: dict) -> tuple[bool, dict]:
        distro = opts["distro"] or e2e.distro_for(time.time())
        try:
            api = e2e.ApiClient(
                base=settings.VALI_SYNTHETIC_API_BASE,
                token=settings.VALI_SYNTHETIC_ROOT_TOKEN,
                timeout_s=float(settings.VALI_SYNTHETIC_HTTP_TIMEOUT_S),
            )
        except e2e.ConfigError as exc:
            # Mis-config is a failure we still want to alert on — push a 0.
            log.error("synthetic full tier mis-configured: %s", exc)
            self._push_e2e_failure(opts, distro, detail=str(exc))
            return False, {"tier": "full", "distro": distro, "error": str(exc)}

        outcome = e2e.run_e2e(
            api=api,
            distro=distro,
            budget_s=float(settings.VALI_SYNTHETIC_E2E_BUDGET_S),
        )

        ms = metrics.MetricSet()
        ms.gauge(
            metrics.M_E2E_SUCCESS,
            1 if outcome.success else 0,
            help_text="1 if the full e2e launch→decommission cycle passed.",
        )
        by_stage = {s.name: s for s in outcome.stages}
        for name in _E2E_STAGES:
            s = by_stage.get(name)
            ms.gauge(
                metrics.M_E2E_STAGE_SUCCESS,
                1 if (s and s.ok) else 0,
                help_text="Per-stage e2e pass/fail.",
                stage=name,
            )
            ms.gauge(
                metrics.M_E2E_DURATION,
                s.duration_s if s else 0.0,
                help_text="Per-stage e2e duration (seconds).",
                stage=name,
            )
        ms.gauge(
            "hippius_synthetic_teardown_forced",
            1 if outcome.teardown_forced else 0,
            help_text="1 if the in-process force-teardown fallback had to run (alertable).",
        )
        ms.gauge(metrics.M_RUN_TIMESTAMP, metrics.now())
        if outcome.success:
            ms.gauge(
                metrics.M_LAST_SUCCESS_TS,
                metrics.now(),
                help_text="Unix ts of the last fully-successful e2e run for this distro.",
            )
        self._push(
            opts, ms, grouping_key={"tier": "full", "distro": distro}, replace=outcome.success
        )

        payload = {
            "tier": "full",
            "distro": distro,
            "vm_id": outcome.vm_id,
            "success": outcome.success,
            "teardown_detail": outcome.teardown_detail,
            "teardown_forced": outcome.teardown_forced,
            "stages": [
                {
                    "name": s.name,
                    "ok": s.ok,
                    "duration_s": round(s.duration_s, 2),
                    "detail": s.detail,
                }
                for s in outcome.stages
            ],
        }
        log.info(
            "synthetic full e2e distro=%s vm=%s success=%s teardown=%s",
            distro,
            outcome.vm_id,
            outcome.success,
            outcome.teardown_detail,
        )
        return outcome.success, payload

    def _push_e2e_failure(self, opts: dict, distro: str, *, detail: str) -> None:
        ms = metrics.MetricSet()
        ms.gauge(metrics.M_E2E_SUCCESS, 0, help_text="1 if the full e2e passed.")
        ms.gauge(metrics.M_RUN_TIMESTAMP, metrics.now())
        self._push(opts, ms, grouping_key={"tier": "full", "distro": distro}, replace=False)

    def _push(
        self, opts: dict, ms: metrics.MetricSet, *, grouping_key: dict, replace: bool
    ) -> None:
        if opts["no_push"]:
            self.stdout.write(ms.render())
            return
        metrics.push(
            ms,
            gateway_url=settings.VALI_SYNTHETIC_PUSHGATEWAY_URL,
            job=settings.VALI_SYNTHETIC_PUSH_JOB,
            grouping_key=grouping_key,
            replace=replace,
            timeout_s=float(settings.VALI_SYNTHETIC_HTTP_TIMEOUT_S),
        )
