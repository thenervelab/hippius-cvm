"""Tests for the PR-S6 prompt-engineered patrol loop — `agent.AgentLoop`.

No Anthropic API: a fake `turn_runner` stands in for the LLM call, so
the loop's rate limiting, aggregation, streaming, metrics, and graceful
shutdown are all exercised deterministically and offline.
"""

from __future__ import annotations

import asyncio
import io

from sentinel.agent import AgentConfig, AgentLoop, FindingBuffer, TurnResult
from sentinel.metrics import MetricsRegistry
from tests._analytics_helpers import make_finding


def _config(**overrides: object) -> AgentConfig:
    params: dict[str, object] = {"api_key": "test-key", "min_seconds_between_calls": 0.0}
    params.update(overrides)
    return AgentConfig(**params)  # type: ignore[arg-type]


class _CapturingRunner:
    """Fake turn runner — records prompts, streams a fixed reply.

    With `reinject` set, it re-buffers a finding after each turn so the
    loop always has work (used by the rate-limit test).
    """

    def __init__(
        self, *, text: str = "senior-sre assessment", reinject: FindingBuffer | None = None
    ) -> None:
        self.prompts: list[str] = []
        self._text = text
        self._reinject = reinject

    async def __call__(self, prompt: str, on_text):  # type: ignore[no-untyped-def]
        self.prompts.append(prompt)
        if on_text is not None:
            on_text(self._text)
        if self._reinject is not None:
            self._reinject.add(make_finding())
        return TurnResult(
            ok=True, latency_s=0.01, input_tokens=7, output_tokens=3, text=self._text
        )

    @property
    def calls(self) -> int:
        return len(self.prompts)


class _SlowRunner:
    """Fake turn runner whose turn takes `delay` seconds to complete."""

    def __init__(self, delay: float) -> None:
        self.delay = delay
        self.started = 0
        self.completed = 0

    async def __call__(self, prompt: str, on_text):  # type: ignore[no-untyped-def]
        self.started += 1
        await asyncio.sleep(self.delay)
        self.completed += 1
        return TurnResult(
            ok=True, latency_s=self.delay, input_tokens=0, output_tokens=0, text=""
        )


async def _run_until(loop_obj: AgentLoop, stop_after_s: float) -> None:
    """Drive `loop_obj.run_forever` and set its stop event after a delay."""

    stop = asyncio.Event()

    async def _stopper() -> None:
        await asyncio.sleep(stop_after_s)
        stop.set()

    await asyncio.gather(loop_obj.run_forever(stop), _stopper())


async def test_loop_skips_turn_when_no_findings() -> None:
    runner = _CapturingRunner()
    loop_obj = AgentLoop(
        _config(),
        FindingBuffer(),
        turn_runner=runner,
        writer=io.StringIO(),
        metrics=MetricsRegistry(),
        poll_interval_s=0.02,
    )
    await _run_until(loop_obj, 0.1)
    assert runner.calls == 0  # empty buffer → no API call is ever made


async def test_loop_runs_a_turn_when_findings_present() -> None:
    buf = FindingBuffer()
    buf.add(make_finding())
    runner = _CapturingRunner()
    metrics = MetricsRegistry()
    loop_obj = AgentLoop(
        _config(),
        buf,
        turn_runner=runner,
        writer=io.StringIO(),
        metrics=metrics,
        poll_interval_s=0.02,
    )
    await _run_until(loop_obj, 0.1)
    assert runner.calls >= 1
    assert metrics.value("sentinel_llm_calls_total") >= 1


async def test_loop_honors_rate_limit() -> None:
    buf = FindingBuffer()
    buf.add(make_finding())
    # The runner re-feeds the buffer so the loop never idles — without
    # the rate limit it would spin and call hundreds of times.
    runner = _CapturingRunner(reinject=buf)
    metrics = MetricsRegistry()
    loop_obj = AgentLoop(
        _config(min_seconds_between_calls=0.08),
        buf,
        turn_runner=runner,
        writer=io.StringIO(),
        metrics=metrics,
        poll_interval_s=0.02,
    )
    await _run_until(loop_obj, 0.45)
    # ~0.45s / 0.08s ≈ 5 turns — the rate limit keeps it far below a spin.
    assert 2 <= runner.calls <= 9
    assert metrics.value("sentinel_llm_rate_limited_total") >= 1


async def test_loop_aggregates_batch_over_threshold() -> None:
    buf = FindingBuffer()
    for i in range(6):
        buf.add(make_finding(fingerprint=f"f{i}"))
    runner = _CapturingRunner()
    metrics = MetricsRegistry()
    loop_obj = AgentLoop(
        _config(aggregate_threshold=3),
        buf,
        turn_runner=runner,
        writer=io.StringIO(),
        metrics=metrics,
        poll_interval_s=0.02,
    )
    await _run_until(loop_obj, 0.1)
    assert runner.calls >= 1
    assert "aggregated" in runner.prompts[0].lower()
    assert metrics.value("sentinel_findings_aggregated_total") == 6


async def test_loop_drains_in_flight_turn_on_shutdown() -> None:
    buf = FindingBuffer()
    buf.add(make_finding())
    runner = _SlowRunner(delay=0.15)
    loop_obj = AgentLoop(
        _config(),
        buf,
        turn_runner=runner,
        writer=io.StringIO(),
        metrics=MetricsRegistry(),
        poll_interval_s=0.02,
    )
    # stop fires 0.05s in — while the turn is still running.
    await _run_until(loop_obj, 0.05)
    # The in-flight turn was allowed to finish, not cancelled mid-call.
    assert runner.started == 1
    assert runner.completed == 1


async def test_loop_streams_response_to_writer() -> None:
    buf = FindingBuffer()
    buf.add(make_finding())
    writer = io.StringIO()
    runner = _CapturingRunner(text="AUDIT CHAIN OK — no action required")
    loop_obj = AgentLoop(
        _config(),
        buf,
        turn_runner=runner,
        writer=writer,
        metrics=MetricsRegistry(),
        poll_interval_s=0.02,
    )
    await _run_until(loop_obj, 0.1)
    out = writer.getvalue()
    assert "AUDIT CHAIN OK — no action required" in out
    assert "agent turn" in out


async def test_loop_records_token_and_latency_metrics() -> None:
    buf = FindingBuffer()
    buf.add(make_finding())
    metrics = MetricsRegistry()
    loop_obj = AgentLoop(
        _config(),
        buf,
        turn_runner=_CapturingRunner(),
        writer=io.StringIO(),
        metrics=metrics,
        poll_interval_s=0.02,
    )
    await _run_until(loop_obj, 0.1)
    assert metrics.value("sentinel_llm_tokens_total", direction="input") >= 7
    assert metrics.value("sentinel_llm_tokens_total", direction="output") >= 3
    assert metrics.value("sentinel_llm_call_latency_seconds_last") > 0


async def test_on_finding_buffers_for_the_next_turn() -> None:
    buf = FindingBuffer()
    runner = _CapturingRunner()
    loop_obj = AgentLoop(
        _config(),
        buf,
        turn_runner=runner,
        writer=io.StringIO(),
        metrics=MetricsRegistry(),
        poll_interval_s=0.02,
    )
    loop_obj.on_finding(make_finding())
    assert len(buf) == 1
    await _run_until(loop_obj, 0.08)
    assert runner.calls >= 1
