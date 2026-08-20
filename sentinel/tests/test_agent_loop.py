"""PR-S1 smoke test for the sentinel agent loop.

The real `ClaudeSDKClient` is stubbed out so this test runs offline (no
Anthropic API call). The test verifies four things end-to-end:

  1. `load_config` reads the API key from `SENTINEL_ANTHROPIC_API_KEY`.
  2. `build_options` wires the `hello_kbs` tool into the MCP server and
     leaves the agent on a strict read-only allowlist.
  3. `run_once` opens the client, queries it, drains
     `receive_response()`, and yields the messages back to the caller.
  4. The dummy `hello_kbs` tool returns the canonical status string —
     this is the surface PR-S2 will replace with the real KBS reader.
"""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
from typing import Any

import pytest

from sentinel.agent import (
    ENV_API_KEY,
    MCP_SERVER_NAME,
    AgentConfig,
    FindingBuffer,
    TurnResult,
    build_options,
    load_config,
    run_once,
    run_turn,
)
from sentinel.tools.hello import HELLO_STATUS, hello_kbs_impl
from tests._analytics_helpers import make_finding


class _FakeMessage:
    def __init__(self, content: str) -> None:
        self.content = content

    def __repr__(self) -> str:
        return f"_FakeMessage({self.content!r})"


class _FakeClient:
    """Minimal ClaudeSDKClient stand-in.

    Records the prompt + options, then yields a synthetic message that
    quotes the `hello_kbs` tool result. That gives the test something
    concrete to assert on without depending on Anthropic.
    """

    instances: list[_FakeClient] = []

    def __init__(self, *, options: Any) -> None:
        self.options = options
        self.queries: list[str] = []
        _FakeClient.instances.append(self)

    async def __aenter__(self) -> _FakeClient:
        return self

    async def __aexit__(self, *_exc: Any) -> None:
        return None

    async def query(self, prompt: str) -> None:
        self.queries.append(prompt)

    async def receive_response(self) -> AsyncIterator[_FakeMessage]:
        tool_result = await hello_kbs_impl({})
        text = tool_result["content"][0]["text"]
        yield _FakeMessage(text)


@pytest.fixture(autouse=True)
def _reset_fake_clients() -> None:
    _FakeClient.instances.clear()


async def test_agent_loop_responds_with_hello_call(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(ENV_API_KEY, "test-key-not-for-prod")

    config = load_config()
    options = build_options(config)

    # Read-only posture: only sentinel MCP tools are auto-approved, and
    # the dangerous Claude Code built-ins are explicitly denied. The
    # specific tool set grows per PR (hello_kbs from PR-S1; KBS audit +
    # anchor from PR-S2); the invariants asserted here are that every
    # entry is sentinel-scoped and nothing on the built-in deny-list
    # leaked into `allowed_tools`.
    assert options.allowed_tools, "allowed_tools must not be empty"
    assert all(t.startswith(f"mcp__{MCP_SERVER_NAME}__") for t in options.allowed_tools)
    assert f"mcp__{MCP_SERVER_NAME}__hello_kbs" in options.allowed_tools
    for denied in ("Bash", "Edit", "Write", "WebFetch", "WebSearch"):
        assert denied in options.disallowed_tools
        assert denied not in options.allowed_tools

    messages: list[_FakeMessage] = []
    async for msg in run_once(
        "smoke: call hello_kbs",
        config=config,
        client_factory=_FakeClient,
    ):
        messages.append(msg)

    # Exactly one client was instantiated, with the smoke prompt queued.
    assert len(_FakeClient.instances) == 1
    assert _FakeClient.instances[0].queries == ["smoke: call hello_kbs"]

    # The agent loop yielded a message whose content surfaces the
    # canonical hello status — proving the tool call wiring is intact.
    assert any(HELLO_STATUS in msg.content for msg in messages)


async def test_hello_kbs_tool_returns_canonical_status() -> None:
    result = await hello_kbs_impl({})
    assert result == {"content": [{"type": "text", "text": HELLO_STATUS}]}


def test_load_config_requires_api_key(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(ENV_API_KEY, raising=False)
    with pytest.raises(RuntimeError, match=ENV_API_KEY):
        load_config(env={})


def test_run_once_is_async_iterable() -> None:
    """Belt-and-suspenders: confirm the public entrypoint is an async iter."""

    async def _drive() -> int:
        seen = 0
        async for _ in run_once(
            "noop",
            config=load_config(env={ENV_API_KEY: "k"}),
            client_factory=_FakeClient,
        ):
            seen += 1
        return seen

    assert asyncio.run(_drive()) >= 1


# ---------------------------------------------------------------------------
# PR-S6 — run_turn observability + FindingBuffer
# ---------------------------------------------------------------------------


class _Block:
    """A TextBlock-shaped object."""

    def __init__(self, text: str) -> None:
        self.text = text


class _Assistant:
    """An AssistantMessage-shaped object — `content` is a block list."""

    def __init__(self, text: str) -> None:
        self.content = [_Block(text)]


class _Result:
    """A ResultMessage-shaped object — duck-typed via `duration_ms`."""

    def __init__(self, *, usage: dict[str, Any] | None = None, is_error: bool = False) -> None:
        self.duration_ms = 1234
        self.usage = usage
        self.is_error = is_error


class _TurnSDKClient:
    """Fake SDK client yielding SDK-shaped messages for `run_turn` tests."""

    def __init__(self, *, options: Any) -> None:
        self.options = options
        self.queries: list[str] = []
        self.messages: list[Any] = [
            _Assistant("hello "),
            _Assistant("world"),
            _Result(usage={"input_tokens": 120, "output_tokens": 45}),
        ]

    async def __aenter__(self) -> _TurnSDKClient:
        return self

    async def __aexit__(self, *_exc: Any) -> None:
        return None

    async def query(self, prompt: str) -> None:
        self.queries.append(prompt)

    async def receive_response(self) -> AsyncIterator[Any]:
        for message in self.messages:
            yield message


class _RaisingSDKClient(_TurnSDKClient):
    async def receive_response(self) -> AsyncIterator[Any]:
        raise RuntimeError("simulated Anthropic API failure")
        yield  # pragma: no cover — keeps this a valid async generator


class _HangingSDKClient(_TurnSDKClient):
    async def receive_response(self) -> AsyncIterator[Any]:
        await asyncio.sleep(10.0)  # far longer than the test's turn timeout
        yield _Assistant("never reached")  # pragma: no cover


async def test_run_turn_captures_text_latency_and_usage() -> None:
    config = load_config(env={ENV_API_KEY: "k"})
    result = await run_turn(
        "analyze the findings", config=config, client_factory=_TurnSDKClient
    )
    assert result.ok
    assert result.text == "hello world"
    assert result.input_tokens == 120
    assert result.output_tokens == 45
    assert result.latency_s >= 0.0


async def test_run_turn_streams_text_to_callback() -> None:
    config = load_config(env={ENV_API_KEY: "k"})
    chunks: list[str] = []
    await run_turn(
        "x", config=config, client_factory=_TurnSDKClient, on_text=chunks.append
    )
    assert "".join(chunks) == "hello world"


async def test_run_turn_survives_sdk_failure() -> None:
    config = load_config(env={ENV_API_KEY: "k"})
    result = await run_turn("x", config=config, client_factory=_RaisingSDKClient)
    assert result.ok is False
    assert result.input_tokens == 0


async def test_run_turn_enforces_turn_timeout() -> None:
    """A wedged Anthropic request becomes a failed turn, bounded in time."""

    config = AgentConfig(api_key="k", turn_timeout_s=0.05)
    result = await run_turn("x", config=config, client_factory=_HangingSDKClient)
    assert result.ok is False
    # Bounded by the 0.05s turn timeout, not the 10s hang.
    assert result.latency_s < 5.0


async def test_run_turn_marks_error_result() -> None:
    config = load_config(env={ENV_API_KEY: "k"})

    class _ErrClient(_TurnSDKClient):
        def __init__(self, *, options: Any) -> None:
            super().__init__(options=options)
            self.messages = [_Assistant("partial"), _Result(usage={}, is_error=True)]

    result = await run_turn("x", config=config, client_factory=_ErrClient)
    assert result.ok is False
    assert isinstance(result, TurnResult)


def test_finding_buffer_drain_returns_and_clears() -> None:
    buf = FindingBuffer(capacity=10)
    for i in range(3):
        buf.add(make_finding(fingerprint=f"f{i}"))
    items, dropped = buf.drain()
    assert len(items) == 3
    assert dropped == 0
    assert len(buf) == 0
    again, again_dropped = buf.drain()
    assert again == []
    assert again_dropped == 0


def test_finding_buffer_overflow_counts_dropped() -> None:
    buf = FindingBuffer(capacity=2)
    for i in range(5):
        buf.add(make_finding(fingerprint=f"f{i}"))
    items, dropped = buf.drain()
    assert len(items) == 2  # only the capacity is retained
    assert dropped == 3  # the three oldest were evicted + counted


def test_finding_buffer_rejects_nonpositive_capacity() -> None:
    with pytest.raises(ValueError):
        FindingBuffer(capacity=0)
