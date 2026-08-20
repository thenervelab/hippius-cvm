"""Sentinel main loop.

Starts the healthz + metrics HTTP server (so the k8s liveness probe
fires as soon as the pod is up), then runs the concurrent task set:
the PR-S6 prompt-engineered agent patrol loop, the PR-S4 analytics
loop, the PR-S5 output dispatcher + daily-summary scheduler, and the
PR-S2 external-attestation anchor publisher.
"""

from __future__ import annotations

import asyncio
import datetime as dt
import logging
import os
import signal
from collections.abc import Callable
from typing import Any

from sentinel.agent import AgentLoop, FindingBuffer, load_config
from sentinel.analytics import (
    AnalyticsLoop,
    Finding,
    RecentFindings,
    Severity,
    build_default_rules,
    build_production_context,
)
from sentinel.healthz import DEFAULT_HEALTHZ_PORT, serve_healthz
from sentinel.output import FindingRouter, build_router_from_env, signature
from sentinel.output.daily_summary import DailySummaryChannel
from sentinel.tools.anchor import (
    DEFAULT_ANCHOR_INTERVAL_S,
    AnchorConfig,
    publish_anchor,
)
from sentinel.tools.kbs_audit import AuditVerifyError

log = logging.getLogger("sentinel.main")

# Analytics loop tick. Individual rules run at their own configured
# intervals; this just bounds how often the loop wakes up to check
# which rules are due.
DEFAULT_ANALYTICS_TICK_S = 5.0

# Hour (UTC) at which the PR-S5 daily incident summary is rendered,
# committed and pushed. 09:00 UTC: "yesterday" is by then a complete
# UTC day.
DEFAULT_DAILY_SUMMARY_HOUR_UTC = 9

# Bound on the in-memory finding→output queue. A burst beyond this is
# shed at enqueue time (and logged) — except a CRITICAL finding, which
# evicts the oldest entry rather than being dropped. The PR-S4 dedup
# and the router's token bucket already cap sustained volume; this only
# guards a spike.
OUTPUT_QUEUE_MAXSIZE = 256

# Shutdown drain windows: after `stop` fires, the analytics loop and
# the output dispatcher each get a bounded window to finish in-flight
# work. The agent loop is awaited WITHOUT a timeout here (see
# `_graceful_shutdown`) — a `wait_for` timeout would cancel a running
# LLM turn mid-request. The turn instead self-bounds via the agent
# turn timeout (`SENTINEL_AGENT_TURN_TIMEOUT_S`); the k8s Deployment's
# `terminationGracePeriodSeconds` is the hard backstop and should
# allow for one full agent turn.
ANALYTICS_DRAIN_TIMEOUT_S = 10.0
OUTPUT_DRAIN_TIMEOUT_S = 20.0


def _setup_logging() -> None:
    logging.basicConfig(
        level=os.environ.get("SENTINEL_LOG_LEVEL", "INFO").upper(),
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )


async def _agent_driver(stop: asyncio.Event, findings: FindingBuffer) -> None:
    """Drive the PR-S6 prompt-engineered patrol loop.

    `load_config` runs here (not at import) so a missing Anthropic API
    key is a runtime failure logged on this task rather than an import
    crash. On a config failure the sentinel continues without the LLM
    agent — the analytics, anchoring and output layers are independent
    of it. The `AgentLoop` shares `findings` with the `on_emit` sink:
    every emitted finding is buffered there for the next turn.
    """

    try:
        config = load_config()
    except Exception:
        log.exception(
            "agent config failed to load; sentinel will run without the LLM agent"
        )
        return
    agent = AgentLoop(config, findings)
    await agent.run_forever(stop)


async def _anchor_loop(interval_s: float) -> None:
    """Periodically publish the signed `(timestamp, record_count, head)` anchor.

    Best-effort: a single failure (Vault down, S3 unreachable, chain
    tampered) is logged and the next tick retries. The anchor publisher
    is in its own task so an Anthropic API outage doesn't stop the §15
    external attestation root from advancing.

    `AnchorConfig.from_env` is called inside the loop on the first
    iteration so a missing env var fails the loop (and the pod via
    crash-loop) rather than silently disabling anchoring.
    """

    cfg: AnchorConfig | None = None
    while True:
        try:
            if cfg is None:
                cfg = AnchorConfig.from_env()
            result = await asyncio.to_thread(publish_anchor, config=cfg)
            log.info(
                "audit anchor published: bucket=%s key=%s records=%d head=%s",
                result.bucket,
                result.key,
                result.record_count,
                result.head_hex,
            )
        except AuditVerifyError:
            log.exception("REFUSING TO ANCHOR — KBS audit chain verification failed")
        except Exception:
            log.exception("anchor publish failed; will retry after interval")
        await asyncio.sleep(interval_s)


async def _analytics_driver(
    stop: asyncio.Event,
    recent: RecentFindings,
    on_emit: Callable[[Finding], None] | None,
) -> None:
    """Drive the PR-S4 analytics rules under the same lifecycle.

    Constructed inside the running loop because `build_production_context`
    binds the readers with `asyncio.to_thread`. The loop itself
    isolates each rule with try/except + timeout (see `analytics.loop`),
    so a single broken rule cannot kill this task. Outermost guard
    here covers reader-config errors at construction time.

    `on_emit` (PR-S5) is the post-dedup sink — it enqueues each emitted
    finding for the output router. `None` disables routing.
    """

    try:
        ctx = build_production_context()
        analytics = AnalyticsLoop(
            build_default_rules(),
            ctx,
            recent=recent,
            tick_interval_s=DEFAULT_ANALYTICS_TICK_S,
            on_emit=on_emit,
        )
    except Exception:
        log.exception(
            "analytics loop failed to start; sentinel will continue without it"
        )
        return
    await analytics.run_forever(stop=stop)


def _seconds_until_utc_hour(hour: int) -> float:
    """Seconds from now until the next occurrence of `hour`:00:00 UTC."""

    now = dt.datetime.now(tz=dt.UTC)
    target = now.replace(hour=hour, minute=0, second=0, microsecond=0)
    if target <= now:
        target += dt.timedelta(days=1)
    return (target - now).total_seconds()


async def _output_dispatcher(
    stop: asyncio.Event,
    queue: asyncio.Queue[Finding],
    router: FindingRouter,
) -> None:
    """Drain emitted findings and route them to the PR-S5 output channels.

    Decoupled from the analytics loop by `queue` so a slow channel
    (a `gh` subprocess, an HTTP POST, a git push) never stalls the
    patrol cadence. The channels are synchronous, so routing runs on a
    worker thread. On shutdown the queue is drained before exit.
    """

    while not (stop.is_set() and queue.empty()):
        try:
            finding = await asyncio.wait_for(queue.get(), timeout=1.0)
        except TimeoutError:
            continue
        try:
            result = await asyncio.to_thread(router.route, finding)
            if result.any_failed:
                log.warning(
                    "output routing for rule=%s had channel failures: %s",
                    finding.rule_name,
                    [f"{r.channel}: {r.detail}" for r in result.results if not r.ok],
                )
        except Exception:
            log.exception(
                "output dispatch failed for finding rule=%s", finding.rule_name
            )
        finally:
            queue.task_done()


async def _daily_summary_loop(
    stop: asyncio.Event, channel: DailySummaryChannel, hour_utc: int
) -> None:
    """Flush the daily incident summary once per day at `hour_utc` UTC."""

    while not stop.is_set():
        delay = _seconds_until_utc_hour(hour_utc)
        try:
            await asyncio.wait_for(stop.wait(), timeout=delay)
            return  # stop fired before the scheduled hour
        except TimeoutError:
            pass  # reached the scheduled hour
        try:
            result = await asyncio.to_thread(channel.flush)
            log.info(
                "daily summary flush: %s — %s", result.status.value, result.detail
            )
        except Exception:
            log.exception("daily summary flush failed; will retry tomorrow")


async def _graceful_shutdown(
    analytics_task: asyncio.Task[Any],
    output_task: asyncio.Task[Any] | None,
    agent_task: asyncio.Task[Any],
    tasks: list[asyncio.Task[Any]],
) -> None:
    """Drain in-flight work before cancelling, then cancel everything.

    `stop` is already set by the caller. The analytics, output and
    agent tasks all watch it and exit on their own — they are awaited
    (bounded) so nothing in flight is lost to an abrupt cancel:

      1. Analytics first — it must stop producing before the queue and
         the agent buffer can be considered fully drainable.
      2. Output dispatcher — its loop exits once `stop` is set and the
         finding queue is empty.
      3. Agent loop — it checks `stop` only between turns, so awaiting
         it lets an in-flight LLM call run to completion. This is a
         plain `await`, not a `wait_for`: a `wait_for` timeout would
         cancel the task — and the Anthropic request — mid-call. The
         turn self-bounds via the agent turn timeout (`run_turn`'s
         `asyncio.timeout`); the k8s grace period is the hard backstop.
      4. Cancel the remaining sleep-loops (and anything that overran
         its drain window).
    """

    try:
        await asyncio.wait_for(analytics_task, timeout=ANALYTICS_DRAIN_TIMEOUT_S)
    except Exception:  # noqa: BLE001 — timeout or task error: proceed to drain
        pass
    if output_task is not None:
        try:
            await asyncio.wait_for(output_task, timeout=OUTPUT_DRAIN_TIMEOUT_S)
        except Exception:  # noqa: BLE001 — timeout or task error: proceed to drain
            pass
    try:
        await agent_task
    except Exception:  # noqa: BLE001 — a task error must not block cancellation
        pass
    for task in tasks:
        task.cancel()


async def _amain() -> None:
    _setup_logging()
    port = int(os.environ.get("SENTINEL_HEALTHZ_PORT", str(DEFAULT_HEALTHZ_PORT)))
    anchor_interval = float(
        os.environ.get("SENTINEL_ANCHOR_INTERVAL_S", str(DEFAULT_ANCHOR_INTERVAL_S))
    )

    healthz = serve_healthz(port=port)
    loop = asyncio.get_running_loop()
    stop = asyncio.Event()
    for sig in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(sig, stop.set)

    # Recent-findings ring — kept for healthz / log inspection.
    recent_findings = RecentFindings()

    # PR-S6 agent finding buffer — the `on_emit` sink feeds it; the
    # agent patrol loop drains it once per (rate-limited) turn.
    agent_findings = FindingBuffer()

    # PR-S5 output router. A misconfigured channel (e.g. a non-https
    # Slack webhook) must not take the whole sentinel down — log it and
    # run without routing, mirroring the analytics loop's start guard.
    router: FindingRouter | None = None
    try:
        router = build_router_from_env()
    except Exception:
        log.exception(
            "output router failed to build; sentinel will run without "
            "GitHub / Slack / daily-summary output"
        )

    output_queue: asyncio.Queue[Finding] = asyncio.Queue(maxsize=OUTPUT_QUEUE_MAXSIZE)

    def _enqueue_finding(finding: Finding) -> None:
        # Called synchronously from inside the analytics tick — it must
        # never block. A full queue means a burst beyond what the
        # downstream channels can absorb. The event loop is single
        # threaded, so the get/put pair below cannot interleave with
        # the dispatcher's `get`.
        try:
            output_queue.put_nowait(finding)
            return
        except asyncio.QueueFull:
            pass
        if finding.severity is Severity.CRITICAL:
            # A CRITICAL finding must never be silently shed. Evict the
            # oldest queued finding (most likely already stale / lower
            # severity) to make room for it.
            try:
                evicted = output_queue.get_nowait()
                # Keep the Queue's unfinished-task accounting balanced —
                # the dispatcher will never see this evicted item.
                output_queue.task_done()
                output_queue.put_nowait(finding)
                log.error(
                    "output queue full (%d); evicted %s finding rule=%s to "
                    "make room for CRITICAL rule=%s sig=%s",
                    OUTPUT_QUEUE_MAXSIZE,
                    evicted.severity.value,
                    evicted.rule_name,
                    finding.rule_name,
                    signature(finding),
                )
            except (asyncio.QueueEmpty, asyncio.QueueFull):
                log.error(
                    "output queue full; could not enqueue CRITICAL finding "
                    "rule=%s sig=%s",
                    finding.rule_name,
                    signature(finding),
                )
            return
        # `sig` (a hash), never the raw fingerprint — fingerprints are
        # redactable, secret-bearing fields.
        log.warning(
            "output queue full (%d); dropping %s finding rule=%s sig=%s",
            OUTPUT_QUEUE_MAXSIZE,
            finding.severity.value,
            finding.rule_name,
            signature(finding),
        )

    def _on_finding(finding: Finding) -> None:
        # Fan-out for every emitted finding: the PR-S6 agent buffer
        # always, and the PR-S5 output channels when a router is wired.
        # Both calls are synchronous and non-blocking — this runs inside
        # the analytics tick.
        agent_findings.add(finding)
        if router is not None:
            _enqueue_finding(finding)

    analytics_task = asyncio.create_task(
        _analytics_driver(stop, recent_findings, _on_finding), name="sentinel-analytics"
    )
    agent_task = asyncio.create_task(
        _agent_driver(stop, agent_findings), name="sentinel-agent"
    )
    tasks: list[asyncio.Task[Any]] = [
        asyncio.create_task(_anchor_loop(anchor_interval), name="sentinel-anchor"),
        analytics_task,
        agent_task,
    ]
    output_task: asyncio.Task[Any] | None = None
    if router is not None:
        output_task = asyncio.create_task(
            _output_dispatcher(stop, output_queue, router), name="sentinel-output"
        )
        tasks.append(output_task)
        daily = router.daily
        if isinstance(daily, DailySummaryChannel):
            tasks.append(
                asyncio.create_task(
                    _daily_summary_loop(
                        stop, daily, DEFAULT_DAILY_SUMMARY_HOUR_UTC
                    ),
                    name="sentinel-daily-summary",
                )
            )

    try:
        await stop.wait()
    finally:
        await _graceful_shutdown(analytics_task, output_task, agent_task, tasks)
        healthz.shutdown()


def main() -> None:
    """Console-script entrypoint."""

    asyncio.run(_amain())


if __name__ == "__main__":
    main()
