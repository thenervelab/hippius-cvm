"""Tests for `sentinel.metrics` — the Prometheus agent-observability registry."""

from __future__ import annotations

import pytest

from sentinel.metrics import MetricsRegistry


def test_seeded_series_render_at_zero() -> None:
    out = MetricsRegistry().render()
    assert "sentinel_llm_calls_total 0" in out
    assert 'sentinel_llm_tokens_total{direction="input"} 0' in out
    assert 'sentinel_llm_tokens_total{direction="output"} 0' in out


def test_inc_counter() -> None:
    r = MetricsRegistry()
    r.inc("sentinel_llm_calls_total")
    r.inc("sentinel_llm_calls_total", 2)
    assert r.value("sentinel_llm_calls_total") == 3


def test_inc_counter_with_labels() -> None:
    r = MetricsRegistry()
    r.inc("sentinel_llm_tokens_total", 120, direction="input")
    r.inc("sentinel_llm_tokens_total", 45, direction="output")
    assert r.value("sentinel_llm_tokens_total", direction="input") == 120
    assert r.value("sentinel_llm_tokens_total", direction="output") == 45


def test_set_gauge() -> None:
    r = MetricsRegistry()
    r.set("sentinel_llm_call_latency_seconds_last", 1.5)
    assert r.value("sentinel_llm_call_latency_seconds_last") == 1.5
    r.set("sentinel_llm_call_latency_seconds_last", 0.25)
    assert r.value("sentinel_llm_call_latency_seconds_last") == 0.25


def test_render_emits_help_and_type() -> None:
    out = MetricsRegistry().render()
    assert "# HELP sentinel_llm_calls_total" in out
    assert "# TYPE sentinel_llm_calls_total counter" in out
    assert "# TYPE sentinel_llm_call_latency_seconds_last gauge" in out


def test_render_reflects_recorded_values() -> None:
    r = MetricsRegistry()
    r.inc("sentinel_llm_calls_total", 5)
    r.inc("sentinel_llm_tokens_total", 1000, direction="input")
    out = r.render()
    assert "sentinel_llm_calls_total 5" in out
    assert 'sentinel_llm_tokens_total{direction="input"} 1000' in out


def test_unknown_metric_is_rejected() -> None:
    r = MetricsRegistry()
    with pytest.raises(KeyError):
        r.inc("sentinel_not_a_real_metric")
    with pytest.raises(KeyError):
        r.value("sentinel_not_a_real_metric")


def test_render_lines_are_well_formed() -> None:
    r = MetricsRegistry()
    r.inc("sentinel_llm_calls_total", 3)
    r.set("sentinel_llm_call_latency_seconds_last", 2.5)
    for line in r.render().splitlines():
        # Every non-blank line is either a comment or `name[...] value`.
        assert line == "" or line.startswith("# ") or " " in line
