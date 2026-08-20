"""PR-S3: NetBird API reader tests.

Uses `httpx.MockTransport` for canned-response mocking — same approach
as the thebrain RPC tests. Pins:

  - Auth header carries the configured PAT.
  - Projection drops fields outside the documented allowlist and
    trims `groups` to `{id, name}`.
  - `list_peers` truncates to `MAX_PEERS_RETURNED`.
  - 404 on a missing peer surfaces as `None` (not an exception).
  - Non-2xx, non-json, malformed payloads all raise `NetBirdError`.
"""

from __future__ import annotations

import json
from typing import Any

import httpx
import pytest

import sentinel.tools.netbird as nb
from sentinel.tools.netbird import (
    MAX_PEERS_RETURNED,
    NetBirdClient,
    NetBirdError,
    get_peer_status,
    list_peers,
)


def _client(handler: Any) -> NetBirdClient:
    return NetBirdClient(
        base_url="https://api.netbird.test",
        token="pat-test-readonly",
        transport=httpx.MockTransport(handler),
    )


def _peer(idx: int, *, connected: bool = True) -> dict[str, Any]:
    return {
        "id": f"peer-{idx:03d}",
        "name": f"miner-{idx}",
        "ip": f"100.64.0.{idx}",
        "dns_label": f"miner-{idx}.netbird.cloud",
        "hostname": f"host-{idx}",
        "user_id": "u-1",
        "os": "linux",
        "connected": connected,
        "last_seen": "2026-05-21T01:23:45Z",
        "version": "0.32.0",
        "groups": [
            {"id": "g-miner", "name": "miner", "peers_count": 99, "extra": "drop-me"},
            {"id": "g-vali", "name": "validator", "peers_count": 5},
        ],
        # Fields outside the projection allowlist — must NOT appear
        # in the LLM-facing output.
        "ssh_enabled": True,
        "internal_only_field": "secret",
    }


# ---------------------------------------------------------------------------
# Happy paths
# ---------------------------------------------------------------------------


def test_list_peers_projects_and_attaches_auth_header() -> None:
    seen_auth: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen_auth.append(request.headers.get("Authorization", ""))
        assert request.method == "GET"
        assert request.url.path == "/api/peers"
        return httpx.Response(200, json=[_peer(1), _peer(2, connected=False)])

    peers = list_peers(client=_client(handler))
    assert len(peers) == 2
    assert seen_auth == ["Token pat-test-readonly"]
    # Projection: only allowlisted keys present.
    allowed = {
        "id", "name", "ip", "dns_label", "hostname", "user_id", "os",
        "connected", "last_seen", "version", "groups",
    }
    for p in peers:
        assert set(p) <= allowed
        for g in p["groups"]:
            assert set(g) == {"id", "name"}
    assert peers[0]["connected"] is True
    assert peers[1]["connected"] is False


def test_get_peer_status_returns_projected_peer() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/api/peers/peer-007"
        return httpx.Response(200, json=_peer(7))

    p = get_peer_status("peer-007", client=_client(handler))
    assert p is not None
    assert p["id"] == "peer-007"
    assert "ssh_enabled" not in p
    assert "internal_only_field" not in p


def test_get_peer_status_returns_none_on_404() -> None:
    def handler(_req: httpx.Request) -> httpx.Response:
        return httpx.Response(404, json={"message": "not found"})

    assert get_peer_status("peer-missing", client=_client(handler)) is None


def test_list_peers_truncates_oversized_response() -> None:
    big = [_peer(i) for i in range(MAX_PEERS_RETURNED + 50)]

    def handler(_req: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=big)

    peers = list_peers(client=_client(handler))
    assert len(peers) == MAX_PEERS_RETURNED


def test_list_peers_handles_empty_fleet() -> None:
    def handler(_req: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=[])

    assert list_peers(client=_client(handler)) == []


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


def test_list_peers_rejects_non_list_response() -> None:
    def handler(_req: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"unexpected": "object"})

    with pytest.raises(NetBirdError, match="non-list"):
        list_peers(client=_client(handler))


def test_get_peer_status_rejects_non_dict_response() -> None:
    def handler(_req: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=["should-be-object"])

    with pytest.raises(NetBirdError, match="non-dict"):
        get_peer_status("peer-x", client=_client(handler))


def test_http_5xx_surfaces_netbirderror() -> None:
    def handler(_req: httpx.Request) -> httpx.Response:
        return httpx.Response(503, text="overloaded")

    with pytest.raises(NetBirdError, match="HTTP 503"):
        list_peers(client=_client(handler))


def test_non_json_body_surfaces_netbirderror() -> None:
    def handler(_req: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=b"not json")

    with pytest.raises(NetBirdError, match="non-json"):
        list_peers(client=_client(handler))


def test_client_factory_requires_token(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(nb.ENV_TOKEN, raising=False)
    with pytest.raises(NetBirdError, match=nb.ENV_TOKEN):
        nb._client()


def test_client_factory_picks_up_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(nb.ENV_TOKEN, "pat-from-env")
    monkeypatch.setenv(nb.ENV_BASE, "https://nb.example.com")
    c = nb._client()
    assert c.token == "pat-from-env"
    assert c.base_url == "https://nb.example.com"


def test_get_peer_status_rejects_empty_peer_id() -> None:
    # Empty peer_id should not hit the API at all — the client
    # short-circuits with an error.
    def handler(_req: httpx.Request) -> httpx.Response:
        raise AssertionError("should not be called")

    with pytest.raises(NetBirdError, match="non-empty"):
        nb.NetBirdClient(
            base_url="https://x",
            token="t",
            transport=httpx.MockTransport(handler),
        ).get_peer("")


# ---------------------------------------------------------------------------
# Tool wrappers (structured responses)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_list_peers_tool_returns_structured_payload(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def handler(_req: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=[_peer(1)])

    monkeypatch.setattr(nb, "_client", lambda: _client(handler))
    result = await nb._list_peers_impl({})
    assert "isError" not in result
    parsed = json.loads(result["content"][0]["text"])
    assert parsed["returned_count"] == 1
    assert parsed["peers"][0]["id"] == "peer-001"


@pytest.mark.asyncio
async def test_get_peer_status_tool_handles_404(monkeypatch: pytest.MonkeyPatch) -> None:
    def handler(_req: httpx.Request) -> httpx.Response:
        return httpx.Response(404)

    monkeypatch.setattr(nb, "_client", lambda: _client(handler))
    result = await nb._get_peer_status_impl({"peer_id": "missing"})
    parsed = json.loads(result["content"][0]["text"])
    assert parsed == {"found": False, "peer_id": "missing"}


@pytest.mark.asyncio
async def test_get_peer_status_tool_rejects_missing_argument() -> None:
    result = await nb._get_peer_status_impl({})
    assert result.get("isError") is True
    assert "peer_id" in result["content"][0]["text"]
