"""Sentinel agent — prompt-engineered patrol loop (PR-S6).

PR-S1 wired a smoke-test loop; PR-S4/S5 added the deterministic
analytics + output layers. PR-S6 makes the LLM agent real: a
senior-SRE system prompt with few-shot calibration, and a tuned patrol
loop that turns the stream of findings into human-grade assessments.

## Layers in this module

1. **SDK surface** — `build_mcp_server` / `build_options` / `run_once`.
   The locked-down, read-only `ClaudeAgentOptions` and the one-turn
   message driver.
2. **One turn** — `run_turn` wraps `run_once`, streams the response
   text out, and captures latency + token usage into a `TurnResult`.
3. **Patrol loop** — `FindingBuffer` accumulates findings; `AgentLoop`
   drives rate-limited, context-budgeted turns and drains cleanly on
   shutdown.

## Read-only posture

The agent is a strict observer. Read-only is enforced in three layers,
on top of the §S invariants in issue #57:

1. **Tool surface**: only sentinel-defined MCP tools are pre-approved
   via `allowed_tools`.
2. **Built-in deny**: every Claude Code built-in that could touch the
   filesystem / shell / network is listed in `disallowed_tools`.
3. **No settings inheritance**: `setting_sources` is left at the SDK
   default so a stray `.claude/` directory cannot widen the surface.

## Anthropic exposure posture

The §S MVP runs against the Anthropic API directly (posture 1, locked
2026-05-20 on issue #57). The system prompt + few-shot examples carry
no secrets, and live findings are passed through `redact_finding`
before they enter a prompt (see `prompts.render`).
"""

from __future__ import annotations

import asyncio
import logging
import os
import sys
import time
from collections import deque
from collections.abc import AsyncIterator, Awaitable, Callable, Mapping
from dataclasses import dataclass
from typing import Any, TextIO

from claude_agent_sdk import (
    ClaudeAgentOptions,
    ClaudeSDKClient,
    create_sdk_mcp_server,
)

from sentinel.analytics.base import Finding
from sentinel.metrics import REGISTRY, MetricsRegistry
from sentinel.prompts import build_system_prompt, build_user_prompt
from sentinel.tools import (
    count_pending_tickets_tool,
    get_peer_status_tool,
    hello_kbs,
    list_peers_tool,
    list_recent_state_transitions_tool,
    query_vm_state_tool,
    read_current_epoch_tool,
    read_epoch_weights_tool,
    read_kbs_audit_tail,
    read_miner_status_tool,
    verify_kbs_audit_chain,
)

# `publish_audit_anchor` is deliberately NOT imported / exposed to the
# LLM. It is an externally-visible write (an immutable S3 anchor under
# Object Lock); the §S posture is that the agent is a strict read-only
# observer — "an analyst, not an actor". Anchoring runs on its own
# deterministic schedule in `sentinel.main._anchor_loop`, never on the
# model's discretion. (PR-S6 review — codex HIGH.)

log = logging.getLogger("sentinel.agent")

# §S MVP model (issue #57). Escalation to Opus for incident triage is a
# future concern — keep the patrol loop on Sonnet.
DEFAULT_MODEL = "claude-sonnet-4-6"

# MCP server identity. The auto-approve allowlist references tools by
# their fully-qualified MCP name, so a rename here must update
# `_ALLOWED_TOOLS` below.
MCP_SERVER_NAME = "sentinel"

ENV_API_KEY = "SENTINEL_ANTHROPIC_API_KEY"
ENV_MODEL = "SENTINEL_AGENT_MODEL"
ENV_MIN_CALL_INTERVAL = "SENTINEL_AGENT_MIN_CALL_INTERVAL_S"
ENV_AGGREGATE_THRESHOLD = "SENTINEL_AGENT_AGGREGATE_THRESHOLD"
ENV_TURN_TIMEOUT = "SENTINEL_AGENT_TURN_TIMEOUT_S"

# Agent-loop tuning defaults (PR-S6). All overridable via env.
DEFAULT_MIN_CALL_INTERVAL_S = 60.0
DEFAULT_AGGREGATE_THRESHOLD = 20
DEFAULT_POLL_INTERVAL_S = 5.0
DEFAULT_FINDING_BUFFER_CAPACITY = 512
# Hard ceiling on one agent turn (LLM thinking + tool calls). Generous
# enough that a real turn never hits it; its job is to guarantee a
# wedged Anthropic request cannot hang the turn — and therefore the
# graceful-shutdown drain — indefinitely.
DEFAULT_TURN_TIMEOUT_S = 300.0

_ALLOWED_TOOLS: tuple[str, ...] = (
    f"mcp__{MCP_SERVER_NAME}__hello_kbs",
    # PR-S2 — KBS audit chain (read-only; anchoring is NOT agent-driven).
    f"mcp__{MCP_SERVER_NAME}__read_kbs_audit_tail",
    f"mcp__{MCP_SERVER_NAME}__verify_kbs_audit_chain",
    # PR-S3 — vali Postgres reader.
    f"mcp__{MCP_SERVER_NAME}__query_vm_state",
    f"mcp__{MCP_SERVER_NAME}__count_pending_tickets",
    f"mcp__{MCP_SERVER_NAME}__list_recent_state_transitions",
    # PR-S3 — thebrain Substrate JSON-RPC.
    f"mcp__{MCP_SERVER_NAME}__read_current_epoch",
    f"mcp__{MCP_SERVER_NAME}__read_miner_status",
    f"mcp__{MCP_SERVER_NAME}__read_epoch_weights",
    # PR-S3 — NetBird API.
    f"mcp__{MCP_SERVER_NAME}__list_peers",
    f"mcp__{MCP_SERVER_NAME}__get_peer_status",
)

# Explicit deny-list for Claude Code built-ins that could let the agent
# mutate state. The SDK auto-loads its full toolset by default.
_DISALLOWED_BUILTINS: tuple[str, ...] = (
    "Bash",
    "BashOutput",
    "KillBash",
    "Edit",
    "Write",
    "NotebookEdit",
    "WebFetch",
    "WebSearch",
    "Task",
)

# The full system prompt — base role/rules + few-shot examples —
# assembled once from the `sentinel.prompts` Markdown assets. A missing
# or empty asset raises here, at import: the prompt is essential, so
# failing loud is correct.
SYSTEM_PROMPT = build_system_prompt()


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------


def _read_float(src: Mapping[str, str], key: str, default: float, *, minimum: float) -> float:
    raw = src.get(key, "").strip()
    if not raw:
        return default
    try:
        value = float(raw)
    except ValueError:
        log.warning("%s=%r is not a number; using default %s", key, raw, default)
        return default
    if value < minimum:
        log.warning("%s=%r below minimum %s; using default %s", key, raw, minimum, default)
        return default
    return value


def _read_int(src: Mapping[str, str], key: str, default: int, *, minimum: int) -> int:
    raw = src.get(key, "").strip()
    if not raw:
        return default
    try:
        value = int(raw)
    except ValueError:
        log.warning("%s=%r is not an integer; using default %s", key, raw, default)
        return default
    if value < minimum:
        log.warning("%s=%r below minimum %d; using default %s", key, raw, minimum, default)
        return default
    return value


@dataclass(frozen=True)
class AgentConfig:
    """Resolved runtime configuration for the sentinel agent."""

    api_key: str
    model: str = DEFAULT_MODEL
    system_prompt: str = SYSTEM_PROMPT
    # PR-S6 loop tuning.
    min_seconds_between_calls: float = DEFAULT_MIN_CALL_INTERVAL_S
    aggregate_threshold: int = DEFAULT_AGGREGATE_THRESHOLD
    turn_timeout_s: float = DEFAULT_TURN_TIMEOUT_S


def load_config(env: dict[str, str] | None = None) -> AgentConfig:
    """Read runtime config from process env (or the supplied mapping).

    Fails loudly if the Anthropic API key is missing — the agent has
    nothing useful to do without it, and silently degrading would make
    the k8s liveness probe lie.
    """

    src = env if env is not None else os.environ
    api_key = src.get(ENV_API_KEY, "").strip()
    if not api_key:
        raise RuntimeError(
            f"{ENV_API_KEY} is not set; the sentinel agent requires an "
            "Anthropic API key to run (issue #57, posture 1)."
        )
    return AgentConfig(
        api_key=api_key,
        model=src.get(ENV_MODEL, "").strip() or DEFAULT_MODEL,
        min_seconds_between_calls=_read_float(
            src, ENV_MIN_CALL_INTERVAL, DEFAULT_MIN_CALL_INTERVAL_S, minimum=0.0
        ),
        aggregate_threshold=_read_int(
            src, ENV_AGGREGATE_THRESHOLD, DEFAULT_AGGREGATE_THRESHOLD, minimum=1
        ),
        turn_timeout_s=_read_float(
            src, ENV_TURN_TIMEOUT, DEFAULT_TURN_TIMEOUT_S, minimum=1.0
        ),
    )


# ---------------------------------------------------------------------------
# SDK surface
# ---------------------------------------------------------------------------


def build_mcp_server() -> Any:
    """Build the in-process MCP server exposing the sentinel tool surface."""

    return create_sdk_mcp_server(
        name=MCP_SERVER_NAME,
        version="0.0.1",
        tools=[
            hello_kbs,
            read_kbs_audit_tail,
            verify_kbs_audit_chain,
            # publish_audit_anchor is intentionally absent — see the note
            # by the `sentinel.tools` import: anchoring is deterministic,
            # never an LLM-discretion write.
            query_vm_state_tool,
            count_pending_tickets_tool,
            list_recent_state_transitions_tool,
            read_current_epoch_tool,
            read_miner_status_tool,
            read_epoch_weights_tool,
            list_peers_tool,
            get_peer_status_tool,
        ],
    )


def build_options(config: AgentConfig) -> ClaudeAgentOptions:
    """Construct the locked-down, read-only `ClaudeAgentOptions`."""

    return ClaudeAgentOptions(
        model=config.model,
        system_prompt=config.system_prompt,
        mcp_servers={MCP_SERVER_NAME: build_mcp_server()},
        allowed_tools=list(_ALLOWED_TOOLS),
        disallowed_tools=list(_DISALLOWED_BUILTINS),
    )


async def run_once(
    prompt: str,
    *,
    config: AgentConfig | None = None,
    client_factory: Any = None,
) -> AsyncIterator[Any]:
    """Drive one agent turn and yield the SDK messages back to the caller.

    `client_factory` is an injection seam for tests — production leaves
    it `None` and gets the real `ClaudeSDKClient`. The factory must
    return an async context manager whose value exposes `query(prompt)`
    and `receive_response()`.
    """

    cfg = config or load_config()
    # The SDK reads the key from `ANTHROPIC_API_KEY`. Set it explicitly
    # (not `setdefault`) so the sentinel's configured key always wins —
    # a stale `ANTHROPIC_API_KEY` inherited from the pod environment
    # must never silently override it. The sentinel process is
    # single-purpose, so owning this env var outright is safe.
    os.environ["ANTHROPIC_API_KEY"] = cfg.api_key

    factory = client_factory or ClaudeSDKClient
    options = build_options(cfg)

    async with factory(options=options) as client:
        await client.query(prompt)
        async for message in client.receive_response():
            yield message


# ---------------------------------------------------------------------------
# One turn — text streaming + token/latency observability
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class TurnResult:
    """Outcome of one agent turn — the unit of observability."""

    ok: bool
    latency_s: float
    input_tokens: int
    output_tokens: int
    text: str


def _message_text(message: Any) -> str:
    """Extract human-readable text from one SDK message (duck-typed)."""

    content = getattr(message, "content", None)
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        return "".join(
            block.text
            for block in content
            if isinstance(getattr(block, "text", None), str)
        )
    return ""


def _message_usage(message: Any) -> dict[str, Any] | None:
    """Token usage from the terminal `ResultMessage` only.

    `ResultMessage.usage` is the cumulative turn total; it is the one
    message type carrying `duration_ms`, which is how we duck-type it
    without importing the SDK class (keeps the test fakes trivial).
    """

    if not hasattr(message, "duration_ms"):
        return None
    usage = getattr(message, "usage", None)
    return usage if isinstance(usage, dict) else None


def _message_is_error(message: Any) -> bool:
    if getattr(message, "is_error", False):
        return True
    err = getattr(message, "error", None)
    return bool(err)


def _as_int(value: Any) -> int:
    return int(value) if isinstance(value, (int, float)) else 0


async def run_turn(
    prompt: str,
    *,
    config: AgentConfig,
    client_factory: Any = None,
    on_text: Callable[[str], None] | None = None,
) -> TurnResult:
    """Run one agent turn: stream the text out, capture latency + tokens.

    Never raises — an SDK / network failure surfaces as
    `TurnResult(ok=False)` so the patrol loop stays alive.
    """

    start = time.monotonic()
    parts: list[str] = []
    usage: dict[str, Any] = {}
    ok = True
    try:
        # Hard per-turn timeout: the Anthropic SDK is not assumed to
        # self-bound, so a wedged request becomes a failed turn after
        # `turn_timeout_s` rather than hanging the loop — and the
        # graceful-shutdown drain — forever.
        async with asyncio.timeout(config.turn_timeout_s):
            async for message in run_once(
                prompt, config=config, client_factory=client_factory
            ):
                chunk = _message_text(message)
                if chunk:
                    parts.append(chunk)
                    if on_text is not None:
                        on_text(chunk)
                message_usage = _message_usage(message)
                if message_usage is not None:
                    # Last-wins: `_message_usage` only returns for the
                    # terminal ResultMessage, whose `usage` is the
                    # turn's cumulative total — at most one to take.
                    usage = message_usage
                if _message_is_error(message):
                    ok = False
    except TimeoutError:
        log.warning(
            "agent turn exceeded its %.0fs timeout — marking the turn failed",
            config.turn_timeout_s,
        )
        ok = False
    except Exception:  # noqa: BLE001 — a failed turn must not kill the loop
        log.exception("agent turn raised")
        ok = False
    latency_s = time.monotonic() - start
    return TurnResult(
        ok=ok,
        latency_s=latency_s,
        input_tokens=_as_int(usage.get("input_tokens")),
        output_tokens=_as_int(usage.get("output_tokens")),
        text="".join(parts),
    )


# ---------------------------------------------------------------------------
# Finding buffer
# ---------------------------------------------------------------------------


class FindingBuffer:
    """Accumulator of findings awaiting the next agent turn.

    A bounded `deque`: when full, the oldest finding is evicted and
    counted, and `drain()` reports that drop count so the prompt can
    tell the model its view is incomplete. Single-writer (the analytics
    `on_emit` sink) / single-reader (the agent loop), both on the
    asyncio event-loop thread — so no lock is needed.
    """

    def __init__(self, capacity: int = DEFAULT_FINDING_BUFFER_CAPACITY) -> None:
        if capacity <= 0:
            raise ValueError("FindingBuffer capacity must be positive")
        self._capacity = capacity
        self._buf: deque[Finding] = deque(maxlen=capacity)
        self._dropped = 0

    def add(self, finding: Finding) -> None:
        if len(self._buf) == self._capacity:
            # The deque will silently evict the oldest on append; count it.
            self._dropped += 1
        self._buf.append(finding)

    def drain(self) -> tuple[list[Finding], int]:
        """Return (all buffered findings, dropped-since-last-drain) and reset."""

        items = list(self._buf)
        dropped = self._dropped
        self._buf.clear()
        self._dropped = 0
        return items, dropped

    def __len__(self) -> int:
        return len(self._buf)


# ---------------------------------------------------------------------------
# Patrol loop
# ---------------------------------------------------------------------------

# A turn runner: `async (prompt, on_text) -> TurnResult`. The loop binds
# `config` in; tests inject a fake to drive the loop without the SDK.
TurnRunner = Callable[[str, "Callable[[str], None] | None"], Awaitable[TurnResult]]


class AgentLoop:
    """The prompt-engineered patrol loop (PR-S6).

    Each iteration:

      1. **Rate limit** — wait until ``min_seconds_between_calls`` have
         elapsed since the last LLM call. The wait is `asyncio.sleep`
         based, so it never blocks the event loop; findings keep
         arriving via `on_finding` throughout, and `stop` interrupts
         the wait at once. The rate limit caps API spend — a storm of
         1000 findings still triggers at most one call per window.
      2. **Drain** the buffered findings. Empty → poll again, no call.
      3. **Context budget** — `build_user_prompt` aggregates the batch
         into a per-(severity, rule) summary when it exceeds
         ``aggregate_threshold``, so a flood cannot blow the prompt.
      4. **Turn** — run one LLM turn, stream the reply to `writer` for
         ops visibility, and record latency + token metrics.

    Graceful shutdown: `stop` is only checked *between* turns, so an
    in-flight LLM call is always allowed to finish (drained) rather
    than cancelled mid-request.
    """

    def __init__(
        self,
        config: AgentConfig,
        findings: FindingBuffer,
        *,
        turn_runner: TurnRunner | None = None,
        writer: TextIO | None = None,
        metrics: MetricsRegistry | None = None,
        clock: Callable[[], float] = time.monotonic,
        poll_interval_s: float = DEFAULT_POLL_INTERVAL_S,
    ) -> None:
        self._config = config
        self._findings = findings
        self._writer = writer if writer is not None else sys.stdout
        self._metrics = metrics if metrics is not None else REGISTRY
        self._clock = clock
        self._poll_interval_s = poll_interval_s
        self._last_call_at: float | None = None

        if turn_runner is not None:
            self._turn_runner: TurnRunner = turn_runner
        else:

            async def _default_runner(
                prompt: str, on_text: Callable[[str], None] | None
            ) -> TurnResult:
                return await run_turn(prompt, config=config, on_text=on_text)

            self._turn_runner = _default_runner

    def on_finding(self, finding: Finding) -> None:
        """Buffer a finding for the next turn. Cheap, non-blocking."""

        self._findings.add(finding)

    async def run_forever(self, stop: asyncio.Event) -> None:
        """Drive turns until `stop` is set. Never raises."""

        log.info(
            "agent loop started: model=%s min_call_interval=%.0fs "
            "aggregate_threshold=%d",
            self._config.model,
            self._config.min_seconds_between_calls,
            self._config.aggregate_threshold,
        )
        while not stop.is_set():
            try:
                await self._respect_rate_limit(stop)
                if stop.is_set():
                    break
                batch, dropped = self._findings.drain()
                if not batch:
                    # Nothing to analyse — never spend an API call on
                    # an empty turn. Poll again after a short sleep.
                    await self._interruptible_sleep(stop, self._poll_interval_s)
                    continue
                await self._run_turn(batch, dropped)
            except Exception:  # noqa: BLE001 — one bad turn must not kill the loop
                log.exception("agent loop iteration failed; continuing")
                await self._interruptible_sleep(stop, self._poll_interval_s)
        log.info("agent loop stopped")

    async def _respect_rate_limit(self, stop: asyncio.Event) -> None:
        if self._last_call_at is None:
            return  # first turn — no wait
        remaining = self._config.min_seconds_between_calls - (
            self._clock() - self._last_call_at
        )
        if remaining > 0:
            self._metrics.inc("sentinel_llm_rate_limited_total")
            await self._interruptible_sleep(stop, remaining)

    async def _interruptible_sleep(self, stop: asyncio.Event, delay: float) -> None:
        if delay <= 0:
            return
        try:
            await asyncio.wait_for(stop.wait(), timeout=delay)
        except TimeoutError:
            pass  # slept the full delay — expected

    async def _run_turn(self, batch: list[Finding], dropped: int) -> None:
        prompt = build_user_prompt(
            batch, dropped=dropped, aggregate_threshold=self._config.aggregate_threshold
        )
        if len(batch) > self._config.aggregate_threshold:
            self._metrics.inc("sentinel_findings_aggregated_total", len(batch))
        self._write(f"\n=== sentinel agent turn — {len(batch)} finding(s) ===\n")
        result = await self._turn_runner(prompt, self._write)
        # `_last_call_at` advances even on a failed turn — a failing API
        # must still be rate-limited, never retry-stormed.
        self._last_call_at = self._clock()
        self._record(result)
        self._write(
            f"\n=== turn done: ok={result.ok} latency={result.latency_s:.1f}s "
            f"tokens in/out={result.input_tokens}/{result.output_tokens} ===\n"
        )

    def _write(self, text: str) -> None:
        # Stream the agent's output to stdout for ops visibility. A
        # broken stdout must never take down the patrol loop.
        try:
            self._writer.write(text)
            self._writer.flush()
        except Exception:  # noqa: BLE001
            log.debug("agent loop writer failed", exc_info=True)

    def _record(self, result: TurnResult) -> None:
        m = self._metrics
        m.inc("sentinel_llm_calls_total")
        if not result.ok:
            m.inc("sentinel_llm_call_errors_total")
        m.inc("sentinel_llm_tokens_total", result.input_tokens, direction="input")
        m.inc("sentinel_llm_tokens_total", result.output_tokens, direction="output")
        m.set("sentinel_llm_call_latency_seconds_last", result.latency_s)
        m.inc("sentinel_llm_call_latency_seconds_total", result.latency_s)
        m.set("sentinel_llm_last_call_unixtime", time.time())
        log.log(
            logging.INFO if result.ok else logging.WARNING,
            "agent turn: ok=%s latency=%.2fs tokens in=%d out=%d",
            result.ok,
            result.latency_s,
            result.input_tokens,
            result.output_tokens,
        )
