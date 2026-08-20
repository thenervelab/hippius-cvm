"""Dummy `hello_kbs` tool — PR-S1 wiring smoke test.

The agent loop is plumbed end-to-end (LLM → tool call → response)
without yet touching any real subsystem. PR-S2 replaces this with the
actual KBS `FileAuditSink` reader + signed-head publisher.
"""

from __future__ import annotations

from typing import Any

from claude_agent_sdk import tool

HELLO_STATUS = "hippius-sentinel: hello from the agent loop (PR-S1 skeleton)"


async def hello_kbs_impl(_args: dict[str, Any]) -> dict[str, Any]:
    """The raw handler. Exposed for direct invocation from tests and
    from future internal callers; the `hello_kbs` SDK wrapper below is
    what the agent sees as a tool."""

    return {"content": [{"type": "text", "text": HELLO_STATUS}]}


hello_kbs = tool(
    "hello_kbs",
    "Smoke-test tool. Returns a fixed status string so the agent loop can be "
    "validated end-to-end before real reader tools (KBS audit chain, vali, "
    "chain RPC, NetBird, Vault audit) land in PR-S2+.",
    {},
)(hello_kbs_impl)
