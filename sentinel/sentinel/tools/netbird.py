"""NetBird API reader (PR-S3).

Two read-only tools — fleet view + per-peer status — backed by the
NetBird management API. Authentication is a Personal Access Token in
the `NETBIRD_API_TOKEN` env var, scoped read-only at provisioning time
(the §S invariant — see #57 — is that the sentinel never holds an
admin token).

API base default is `https://api.netbird.io` (the SaaS deployment),
overridable via `NETBIRD_API_BASE` for self-hosted control planes.

Endpoints used:

  - `GET /api/peers`            — list every peer the token can see.
  - `GET /api/peers/{peer_id}`  — single-peer detail.

Both are documented at https://docs.netbird.io/api. We do not
exhaustively type the response — the agent gets a small projection of
the fields useful for fleet observability (id, name, ip, connected,
last_seen, os, hostname, groups). Anything else is dropped to keep
the LLM prompt window small.
"""

from __future__ import annotations

import json
import logging
import os
from dataclasses import dataclass
from typing import Any

import httpx
from claude_agent_sdk import tool

log = logging.getLogger("sentinel.tools.netbird")

ENV_TOKEN = "NETBIRD_API_TOKEN"
ENV_BASE = "NETBIRD_API_BASE"
DEFAULT_BASE = "https://api.netbird.io"

REQUEST_TIMEOUT_S = 15.0

# Cap peer count returned to the agent so we don't blow the prompt
# window if the fleet grows. Sentinel can re-call with pagination
# in PR-S4 if the cap is hit; for now, log when truncating.
MAX_PEERS_RETURNED = 500


class NetBirdError(RuntimeError):
    """Raised when the NetBird API returns a non-2xx or unparseable response."""


@dataclass(frozen=True)
class NetBirdClient:
    """Thin wrapper around `httpx.Client` for the NetBird REST API.

    Per-call connection so a flaky control plane doesn't pin a dead
    socket to the sentinel pod.
    """

    base_url: str
    token: str
    transport: httpx.BaseTransport | None = None

    def _get(self, path: str) -> Any:
        url = self.base_url.rstrip("/") + path
        headers = {
            "Authorization": f"Token {self.token}",
            "Accept": "application/json",
        }
        with httpx.Client(transport=self.transport, timeout=REQUEST_TIMEOUT_S) as c:
            r = c.get(url, headers=headers)
        if r.status_code == httpx.codes.NOT_FOUND:
            return None
        if r.status_code != httpx.codes.OK:
            # Don't leak the token even if it sneaks into the body —
            # NetBird's API doesn't echo it, but be paranoid.
            raise NetBirdError(
                f"GET {path}: HTTP {r.status_code}: {r.text[:200]}"
            )
        try:
            return r.json()
        except json.JSONDecodeError as e:
            raise NetBirdError(f"GET {path}: non-json response: {e}") from e

    def list_peers(self) -> list[dict[str, Any]]:
        data = self._get("/api/peers")
        if data is None:
            return []
        if not isinstance(data, list):
            raise NetBirdError(f"/api/peers returned non-list: {type(data).__name__}")
        return data

    def get_peer(self, peer_id: str) -> dict[str, Any] | None:
        if not peer_id:
            raise NetBirdError("peer_id must be non-empty")
        data = self._get(f"/api/peers/{peer_id}")
        if data is None:
            return None
        if not isinstance(data, dict):
            raise NetBirdError(
                f"/api/peers/{peer_id} returned non-dict: {type(data).__name__}"
            )
        return data


def _client(transport: httpx.BaseTransport | None = None) -> NetBirdClient:
    token = os.environ.get(ENV_TOKEN, "").strip()
    if not token:
        raise NetBirdError(
            f"{ENV_TOKEN} is not set; PR-S3 NetBird reader cannot authenticate."
        )
    base = os.environ.get(ENV_BASE, DEFAULT_BASE).strip() or DEFAULT_BASE
    return NetBirdClient(base_url=base, token=token, transport=transport)


# ---------------------------------------------------------------------------
# Projections
# ---------------------------------------------------------------------------


# Fields we pass through to the agent. Anything not in this list is
# dropped — keeps the prompt small and avoids leaking schema changes.
_PEER_PROJECTION_KEYS = (
    "id",
    "name",
    "ip",
    "dns_label",
    "hostname",
    "user_id",
    "os",
    "connected",
    "last_seen",
    "version",
    "groups",
)


def _project_peer(p: dict[str, Any]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for k in _PEER_PROJECTION_KEYS:
        if k in p:
            v = p[k]
            if k == "groups" and isinstance(v, list):
                # Each group is `{id, name, peers_count, ...}`. Project
                # down to `{id, name}` for the agent.
                out[k] = [
                    {"id": g.get("id"), "name": g.get("name")}
                    for g in v
                    if isinstance(g, dict)
                ]
            else:
                out[k] = v
    return out


def list_peers(
    *, client: NetBirdClient | None = None
) -> list[dict[str, Any]]:
    c = client or _client()
    peers = c.list_peers()
    if len(peers) > MAX_PEERS_RETURNED:
        log.warning(
            "NetBird list_peers: %d peers, truncating to %d for LLM context budget",
            len(peers),
            MAX_PEERS_RETURNED,
        )
        peers = peers[:MAX_PEERS_RETURNED]
    return [_project_peer(p) for p in peers if isinstance(p, dict)]


def get_peer_status(
    peer_id: str, *, client: NetBirdClient | None = None
) -> dict[str, Any] | None:
    c = client or _client()
    p = c.get_peer(peer_id)
    if p is None:
        return None
    return _project_peer(p)


# ---------------------------------------------------------------------------
# Agent-facing MCP tool wrappers
# ---------------------------------------------------------------------------


def _structured_error(msg: str) -> dict[str, Any]:
    return {"content": [{"type": "text", "text": msg}], "isError": True}


def _structured_json(payload: Any) -> dict[str, Any]:
    return {
        "content": [
            {"type": "text", "text": json.dumps(payload, sort_keys=True, default=str)}
        ]
    }


async def _list_peers_impl(_args: dict[str, Any]) -> dict[str, Any]:
    try:
        peers = list_peers()
    except NetBirdError as e:
        log.warning("list_peers: %s", e)
        return _structured_error(f"netbird api error: {e}")
    except Exception as e:  # noqa: BLE001
        log.exception("list_peers: unexpected failure")
        return _structured_error(f"list_peers failed: {e}")
    return _structured_json({"returned_count": len(peers), "peers": peers})


async def _get_peer_status_impl(args: dict[str, Any]) -> dict[str, Any]:
    peer_id = args.get("peer_id")
    if not isinstance(peer_id, str) or not peer_id:
        return _structured_error("get_peer_status requires a non-empty peer_id string")
    try:
        peer = get_peer_status(peer_id)
    except NetBirdError as e:
        log.warning("get_peer_status: %s", e)
        return _structured_error(f"netbird api error: {e}")
    except Exception as e:  # noqa: BLE001
        log.exception("get_peer_status: unexpected failure")
        return _structured_error(f"get_peer_status failed: {e}")
    if peer is None:
        return _structured_json({"found": False, "peer_id": peer_id})
    return _structured_json({"found": True, "peer": peer})


list_peers_tool = tool(
    "list_peers",
    "List NetBird peers visible to the sentinel's read-only PAT. "
    "Projects each peer down to {id, name, ip, dns_label, hostname, "
    "user_id, os, connected, last_seen, version, groups[{id,name}]}. "
    "Truncated to 500 entries for the LLM context budget.",
    {},
)(_list_peers_impl)


get_peer_status_tool = tool(
    "get_peer_status",
    "Get the status of a single NetBird peer by id. Same projection "
    "as list_peers. Returns {found: false} if the peer is not visible.",
    {"peer_id": str},
)(_get_peer_status_impl)
