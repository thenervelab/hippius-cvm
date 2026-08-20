"""Dependency-free Prometheus Pushgateway client for the synthetic monitor.

CronJob/batch runs are short-lived, so the metrics are PUSHed to a
Pushgateway (Prometheus scrapes the gateway) rather than scraped from the
job. We hand-roll the tiny text-exposition + HTTP surface with `urllib`
(the same approach as `sentinel/sentinel/metrics.py`) so the vali image
gains no new third-party dependency.

Grouping-key discipline (staleness-safe):

- The Pushgateway stamps the `job` + grouping-key labels onto EVERY
  metric in a group, and a group is addressed by its grouping key. The
  full tier groups by `{tier=full, distro=<d>}` so each distro's series
  persists independently; the light tier groups by `{tier=light}`.
- A SUCCESSFUL run pushes the whole group with `PUT` (full replace),
  stamping a fresh `hippius_synthetic_last_success_timestamp`.
- A FAILED run pushes with `POST` (partial update) and OMITS the
  timestamp, so the last-good timestamp is preserved. This is what makes
  the `SyntheticE2EStale` alert meaningful: the timestamp only ever
  advances on success, even while `success` flaps to 0.
"""

from __future__ import annotations

import logging
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field

log = logging.getLogger("apps.synthetic.metrics")

# Metric names (stable — the PrometheusRule + Grafana dashboard key off
# these). tier/distro are grouping-key labels stamped by the gateway.
M_E2E_SUCCESS = "hippius_synthetic_e2e_success"
M_E2E_STAGE_SUCCESS = "hippius_synthetic_e2e_stage_success"
M_E2E_DURATION = "hippius_synthetic_e2e_duration_seconds"
M_LIGHT_SUCCESS = "hippius_synthetic_light_success"
M_LIGHT_CHECK_SUCCESS = "hippius_synthetic_light_check_success"
M_LAST_SUCCESS_TS = "hippius_synthetic_last_success_timestamp"
M_RUN_TIMESTAMP = "hippius_synthetic_run_timestamp"
# Count of leaked synthetic resources the LIGHT-tier reaper force-tore-down
# this run. >0 ⇒ a prior run leaked (its finally teardown could not run) —
# the `SyntheticLeak` alert fires on it.
M_REAPED = "hippius_synthetic_reaped_total"
# ── Acknowledgement surface (apps.synthetic.ack) ──────────────────────
# `light_success` excludes a validly-acknowledged failing check, so these
# make the mute itself visible and alertable. `light_check_success` keeps
# reporting the UNVARNISHED per-check verdict — an ack never rewrites it.
#
# All four are emitted on EVERY light run, including a 0 for checks that
# are not acknowledged. A failed run pushes with POST (partial update), so
# a sample we stop emitting would linger in the Pushgateway at its last
# value — an ack removed from config would otherwise look permanently
# active. Emitting the explicit 0 is what makes removal observable.
M_LIGHT_CHECK_ACKED = "hippius_synthetic_light_check_acknowledged"
M_ACK_EXPIRES_TS = "hippius_synthetic_ack_expires_timestamp"
M_ACK_STALE = "hippius_synthetic_ack_stale"
M_ACK_INVALID = "hippius_synthetic_ack_invalid"


@dataclass
class _Sample:
    name: str
    value: float
    labels: dict[str, str]
    help_text: str
    metric_type: str


@dataclass
class MetricSet:
    """An accumulator of gauge samples, rendered to Prometheus text."""

    samples: list[_Sample] = field(default_factory=list)

    def gauge(
        self,
        name: str,
        value: float,
        *,
        help_text: str = "",
        **labels: str,
    ) -> None:
        self.samples.append(_Sample(name, float(value), dict(labels), help_text, "gauge"))

    def render(self) -> str:
        """Render exposition text. Emits one `# HELP`/`# TYPE` per metric
        name, then every sample line."""
        lines: list[str] = []
        seen: set[str] = set()
        for s in self.samples:
            if s.name not in seen:
                seen.add(s.name)
                if s.help_text:
                    lines.append(f"# HELP {s.name} {s.help_text}")
                lines.append(f"# TYPE {s.name} {s.metric_type}")
            lines.append(f"{s.name}{_fmt_labels(s.labels)} {_fmt_value(s.value)}")
        return "\n".join(lines) + "\n"


def _fmt_value(v: float) -> str:
    # Integers render without a trailing `.0` for readability.
    if v == int(v):
        return str(int(v))
    return repr(v)


def _fmt_labels(labels: dict[str, str]) -> str:
    if not labels:
        return ""
    inner = ",".join(f'{k}="{_escape(v)}"' for k, v in sorted(labels.items()))
    return "{" + inner + "}"


def _escape(v: str) -> str:
    return v.replace("\\", "\\\\").replace("\n", "\\n").replace('"', '\\"')


def _grouping_path(job: str, grouping_key: dict[str, str]) -> str:
    """Pushgateway URL path: /metrics/job/<job>/<k>/<v>/... — each segment
    URL-encoded. An empty value uses the base64 form the gateway accepts."""
    parts = ["metrics", "job", urllib.parse.quote(job, safe="")]
    for k in sorted(grouping_key):
        v = grouping_key[k]
        parts.append(urllib.parse.quote(k, safe=""))
        parts.append(urllib.parse.quote(v, safe="") if v else "=")
    return "/".join(parts)


def push(
    metrics: MetricSet,
    *,
    gateway_url: str,
    job: str,
    grouping_key: dict[str, str],
    replace: bool,
    timeout_s: float = 10.0,
) -> bool:
    """Push `metrics` to the gateway. `replace=True` → PUT (full group
    replace, for a successful run that stamps a fresh timestamp);
    `replace=False` → POST (partial update, for a failed run — preserves
    the previously-pushed last-success timestamp).

    Returns True on a 2xx. Never raises — a metrics-push failure must not
    mask the underlying probe result (it is logged loudly instead). An
    empty `gateway_url` logs the exposition text and returns True (tests /
    pre-gateway boot).
    """
    body = metrics.render()
    if not gateway_url:
        log.info("synthetic metrics (no gateway configured):\n%s", body)
        return True
    url = f"{gateway_url.rstrip('/')}/{_grouping_path(job, grouping_key)}"
    method = "PUT" if replace else "POST"
    req = urllib.request.Request(
        url,
        data=body.encode("utf-8"),
        method=method,
        headers={"Content-Type": "text/plain; version=0.0.4"},
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout_s) as resp:
            ok = 200 <= resp.status < 300
            if not ok:
                log.warning("pushgateway %s %s → HTTP %s", method, url, resp.status)
            return ok
    except (urllib.error.URLError, OSError) as exc:  # pragma: no cover - net
        log.warning("pushgateway %s %s failed: %s", method, url, exc)
        return False


def now() -> float:
    return time.time()
