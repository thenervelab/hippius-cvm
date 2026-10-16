"""Which family runs a compute node — read on chain, fail closed.

The operator storage API (`apps.disktier.storage_views`) is called by the
upstream backend for a signed-in miner family. The backend already
resolved the family's nodes on chain; vali checks again (defence in
depth: a leaked backend token can then only touch the nodes of the
family it names). The read is `hippius-ticket-validator
read-node-family` (`NodeIdToChild[node_id]` → `ChildRegistrations[child]`
at the finalized head, `hippius-onchain-registry::fetch_node_family`);
this module is the thin Python boundary, with the same contract as
`apps.scheduler.chain`:

- the RPC URL travels in the `THEBRAIN_RPC_URL` environment variable,
  never argv;
- stdout is one JSON object, `tag` = `ok` | `err`; exit 0 ok, 2
  structured failure, anything else internal;
- EVERY failure (no URL, no binary, timeout, structured error, schema
  drift) raises `FamilyCheckUnavailable` — the view answers 503, never
  "allowed".

A successful read is cached per node for `VALI_OPERATOR_FAMILY_CACHE_S`
(30 s) for READS: a dashboard page issues a handful of calls, and a
family change on chain shows in them at most that late. Writes and pushes
read the chain afresh (`fresh=True`). Failures are never cached.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import subprocess
import threading
import time
from dataclasses import dataclass
from pathlib import Path

from django.conf import settings

log = logging.getLogger("apps.disktier.node_family")

_B58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
_B58_INDEX = {c: i for i, c in enumerate(_B58_ALPHABET)}
_SS58_PREFIX = b"SS58PRE"
#: Formats `sp_core` refuses to decode (reserved by the SS58 registry).
_SS58_RESERVED = frozenset({46, 47})
_HEX64 = frozenset("0123456789abcdef")


class FamilyCheckUnavailable(Exception):
    """The chain could not be read: the caller fails closed (503)."""


@dataclass(frozen=True)
class NodeFamily:
    """One node's on-chain family binding at `block_hash`."""

    node_id: str
    block_hash: str
    bound: bool
    family_hex: str = ""
    status: str = ""
    #: Why the node is not bound (`no-child`, `no-registration`,
    #: `node-mismatch`).
    reason: str = ""

    @property
    def active(self) -> bool:
        return self.bound and self.status == "active"


def ss58_decode(address: str) -> bytes:
    """The 32-byte account id of an SS58 `address`, any network prefix.
    Raises `ValueError` on anything else (bad base58, bad checksum, not a
    32-byte account)."""
    if not address or len(address) > 64:
        raise ValueError("not an SS58 address")
    num = 0
    for ch in address:
        if ch not in _B58_INDEX:
            raise ValueError("not an SS58 address")
        num = num * 58 + _B58_INDEX[ch]
    raw = num.to_bytes((num.bit_length() + 7) // 8, "big") if num else b""
    pad = len(address) - len(address.lstrip("1"))
    data = b"\x00" * pad + raw
    if not data:
        raise ValueError("not an SS58 address")
    # A 1-byte prefix (0..63) or a 2-byte one (64..16383, first byte
    # 0b01xxxxxx), then the 32-byte account and a 2-byte checksum.
    prefix_len = 1 if data[0] < 64 else 2 if data[0] < 128 else 0
    if prefix_len == 0 or len(data) != prefix_len + 32 + 2:
        raise ValueError("not an SS58 account address")
    if prefix_len == 1:
        ident = data[0]
    else:
        ident = ((data[0] & 0x3F) << 2) | (data[1] >> 6) | ((data[1] & 0x3F) << 8)
        if ident < 64:
            raise ValueError("SS58 2-byte prefix encodes a 1-byte format")
    if ident in _SS58_RESERVED:
        raise ValueError("SS58 format is reserved")
    body, checksum = data[:-2], data[-2:]
    if hashlib.blake2b(_SS58_PREFIX + body, digest_size=64).digest()[:2] != checksum:
        raise ValueError("SS58 checksum mismatch")
    return body[prefix_len:]


_cache: dict[str, tuple[float, NodeFamily]] = {}
_cache_lock = threading.Lock()


def clear_cache() -> None:
    with _cache_lock:
        _cache.clear()


def node_family(node_id: str, *, fresh: bool = False) -> NodeFamily:
    """`node_id`'s binding, from the cache when recent, else from the
    chain. `fresh` always reads the chain (and refreshes the cache): a
    write, and a push, must not act on a family the node no longer has.
    Raises `FamilyCheckUnavailable`."""
    ttl = float(getattr(settings, "VALI_OPERATOR_FAMILY_CACHE_S", 30))
    now = time.monotonic()
    if not fresh:
        with _cache_lock:
            hit = _cache.get(node_id)
            if hit is not None and hit[0] > now:
                return hit[1]
    result = read_node_family(node_id)
    if ttl > 0:
        with _cache_lock:
            _cache[node_id] = (now + ttl, result)
    return result


def family_runs_node(node_id: str, family_ss58: str, *, fresh: bool = False) -> bool:
    """Whether the family `family_ss58` runs `node_id` right now: the
    node's child is registered to it and `Active`. Raises `ValueError` on
    a malformed address and `FamilyCheckUnavailable` when the chain cannot
    say."""
    account = ss58_decode(family_ss58).hex()
    binding = node_family(node_id, fresh=fresh)
    return binding.active and binding.family_hex == account


def read_node_family(node_id: str) -> NodeFamily:
    """Shell out to `read-node-family`. Raises `FamilyCheckUnavailable` on
    any failure; never logs the RPC URL."""
    if len(node_id) != 64 or not set(node_id) <= _HEX64:
        raise FamilyCheckUnavailable("node_id is not 64 lower-case hex")
    rpc_url = str(getattr(settings, "VALI_THEBRAIN_RPC_URL", "") or "").strip()
    if not rpc_url:
        raise FamilyCheckUnavailable("VALI_THEBRAIN_RPC_URL is not configured")
    bin_path = Path(settings.VALI_TICKET_VALIDATOR_BIN)
    if not bin_path.is_file():
        raise FamilyCheckUnavailable(f"validator binary not found at {bin_path}")
    pallet = str(getattr(settings, "VALI_THEBRAIN_PALLET_NAME", "ComputeScoring"))
    timeout = float(getattr(settings, "VALI_OPERATOR_FAMILY_RPC_TIMEOUT_S", 15.0))
    try:
        completed = subprocess.run(  # noqa: S603 — argv list, no shell.
            [str(bin_path), "read-node-family", "--pallet-name", pallet, "--node-id", node_id],
            input=b"",
            capture_output=True,
            timeout=timeout,
            check=False,
            env={**os.environ, "THEBRAIN_RPC_URL": rpc_url},
        )
    except subprocess.TimeoutExpired as exc:
        raise FamilyCheckUnavailable(f"read-node-family timed out after {timeout:.0f}s") from exc
    except OSError as exc:
        raise FamilyCheckUnavailable(f"read-node-family spawn failed: {exc}") from exc
    if completed.returncode not in (0, 2):
        log.error("read-node-family internal failure: rc=%s", completed.returncode)
        raise FamilyCheckUnavailable(f"read-node-family exited with {completed.returncode}")
    try:
        payload = json.loads(completed.stdout)
    except (json.JSONDecodeError, UnicodeDecodeError, ValueError) as exc:
        raise FamilyCheckUnavailable("read-node-family stdout is not JSON") from exc
    if not isinstance(payload, dict):
        raise FamilyCheckUnavailable("read-node-family stdout is not an object")
    if payload.get("tag") == "err":
        category = str(payload.get("category", "unknown"))
        log.error("read-node-family failed: category=%s", category)
        raise FamilyCheckUnavailable(f"[{category}] {payload.get('error', 'chain read failed')}")
    if payload.get("tag") != "ok" or completed.returncode != 0:
        raise FamilyCheckUnavailable("read-node-family returned no ok result")
    try:
        return _coerce(payload, node_id)
    except (KeyError, TypeError, ValueError) as exc:
        raise FamilyCheckUnavailable(
            f"read-node-family output has unexpected shape: {exc}"
        ) from exc


def _hex64(value: object, name: str) -> str:
    if not isinstance(value, str) or len(value) != 64 or not set(value) <= _HEX64:
        raise ValueError(f"{name} is not 64 lower-case hex")
    return value


def _coerce(payload: dict[str, object], node_id: str) -> NodeFamily:
    if _hex64(payload["node_id_hex"], "node_id_hex") != node_id:
        raise ValueError("node_id_hex is not the node asked about")
    block_hash = payload["block_hash"]
    if not isinstance(block_hash, str):
        raise TypeError("block_hash is not a string")
    bound = payload["bound"]
    if not isinstance(bound, bool):
        raise TypeError("bound is not a boolean")
    if not bound:
        return NodeFamily(
            node_id=node_id, block_hash=block_hash, bound=False, reason=str(payload["reason"])
        )
    status = payload["status"]
    if status not in ("active", "unbonding"):
        raise ValueError(f"unknown child status {status!r}")
    return NodeFamily(
        node_id=node_id,
        block_hash=block_hash,
        bound=True,
        family_hex=_hex64(payload["family_hex"], "family_hex"),
        status=str(status),
    )
