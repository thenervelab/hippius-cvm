"""Prometheus-format metrics for the sentinel LLM agent (PR-S6).

A deliberately tiny, dependency-free metrics registry — the sentinel
runtime keeps its surface small (the `/healthz` server is hand-rolled
stdlib too, see `healthz.py`). It records the Anthropic-API
observability signals PR-S6 cares about: agent-turn count, error
count, token usage, per-call latency, rate-limiter activity, and
finding aggregation.

The registry is process-global (`REGISTRY`) and thread-safe: the agent
loop writes from the asyncio event-loop thread, while the healthz
server renders `/metrics` from its own `ThreadingHTTPServer` handler
thread. Every metric/label series is pre-seeded to 0 so a scrape taken
before the first agent turn still returns the full, well-formed series.
"""

from __future__ import annotations

import threading

# metric name -> (prometheus type, help text).
_METRIC_META: dict[str, tuple[str, str]] = {
    "sentinel_llm_calls_total": (
        "counter",
        "Anthropic API agent turns attempted.",
    ),
    "sentinel_llm_call_errors_total": (
        "counter",
        "Agent turns that ended in an error.",
    ),
    "sentinel_llm_tokens_total": (
        "counter",
        "Anthropic API tokens consumed, by direction.",
    ),
    "sentinel_llm_call_latency_seconds_last": (
        "gauge",
        "Wall-clock latency of the most recent agent turn.",
    ),
    "sentinel_llm_call_latency_seconds_total": (
        "counter",
        "Cumulative wall-clock latency across all agent turns.",
    ),
    "sentinel_llm_rate_limited_total": (
        "counter",
        "Agent turns delayed by the per-minute rate limiter.",
    ),
    "sentinel_findings_aggregated_total": (
        "counter",
        "Findings processed via the aggregated (over-context-budget) prompt path.",
    ),
    "sentinel_llm_last_call_unixtime": (
        "gauge",
        "Unix time at which the last agent turn completed.",
    ),
}

# (name, label-tuple) series pre-seeded to 0 at startup.
_SEED_SERIES: tuple[tuple[str, tuple[tuple[str, str], ...]], ...] = (
    ("sentinel_llm_calls_total", ()),
    ("sentinel_llm_call_errors_total", ()),
    ("sentinel_llm_tokens_total", (("direction", "input"),)),
    ("sentinel_llm_tokens_total", (("direction", "output"),)),
    ("sentinel_llm_call_latency_seconds_last", ()),
    ("sentinel_llm_call_latency_seconds_total", ()),
    ("sentinel_llm_rate_limited_total", ()),
    ("sentinel_findings_aggregated_total", ()),
    ("sentinel_llm_last_call_unixtime", ()),
)

_Series = tuple[str, tuple[tuple[str, str], ...]]


def _escape_label(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")


def _fmt(value: float) -> str:
    # Render whole numbers without a trailing `.0` for a tidy scrape.
    if value == int(value):
        return str(int(value))
    return repr(value)


class MetricsRegistry:
    """Thread-safe counter/gauge store with Prometheus text rendering."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._values: dict[_Series, float] = {key: 0.0 for key in _SEED_SERIES}

    @staticmethod
    def _key(name: str, labels: dict[str, str]) -> _Series:
        if name not in _METRIC_META:
            raise KeyError(f"unknown metric {name!r}")
        return (name, tuple(sorted(labels.items())))

    def inc(self, name: str, amount: float = 1.0, **labels: str) -> None:
        """Add `amount` to a counter series (creating it if unseen)."""

        key = self._key(name, labels)
        with self._lock:
            self._values[key] = self._values.get(key, 0.0) + amount

    def set(self, name: str, value: float, **labels: str) -> None:
        """Set a gauge series to `value`."""

        key = self._key(name, labels)
        with self._lock:
            self._values[key] = float(value)

    def value(self, name: str, **labels: str) -> float:
        """Read one series — for tests + inspection."""

        with self._lock:
            return self._values.get(self._key(name, labels), 0.0)

    def render(self) -> str:
        """Render the whole registry in Prometheus text exposition format."""

        with self._lock:
            snapshot = dict(self._values)
        lines: list[str] = []
        for name, (mtype, helptext) in _METRIC_META.items():
            lines.append(f"# HELP {name} {helptext}")
            lines.append(f"# TYPE {name} {mtype}")
            series = sorted((k, v) for k, v in snapshot.items() if k[0] == name)
            for (_, labels), val in series:
                if labels:
                    rendered = ",".join(
                        f'{k}="{_escape_label(v)}"' for k, v in labels
                    )
                    lines.append(f"{name}{{{rendered}}} {_fmt(val)}")
                else:
                    lines.append(f"{name} {_fmt(val)}")
        return "\n".join(lines) + "\n"


# Process-global registry. The agent loop writes here; `healthz` reads
# it to serve `/metrics`. Tests construct their own `MetricsRegistry`.
REGISTRY = MetricsRegistry()
