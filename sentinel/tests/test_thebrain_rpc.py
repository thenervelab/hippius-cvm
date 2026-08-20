"""PR-S3: thebrain Substrate JSON-RPC reader tests.

Uses `httpx.MockTransport` so no network calls happen. The mock dispatches
on JSON-RPC method + params and serves canned hex blobs that the
reader is expected to decode into the documented LLM-facing shape.

Coverage:

  - `twox128` + `blake2_128_concat` against known Substrate vectors.
  - Storage key derivation for the three storage items we read.
  - `read_current_epoch` happy path + null response → 0.
  - `read_miner_status` happy path (Active/Quarantined) + 32-bit and
    64-bit BlockNumber widths.
  - `read_epoch_weights` paging + decoding.
  - Errors: missing env, bad node_id length, HTTP 500, JSON-RPC error.
"""

from __future__ import annotations

import json
from typing import Any

import httpx
import pytest

import sentinel.tools.thebrain_rpc as tb
from sentinel.tools.thebrain_rpc import (
    PALLET_NAME,
    STORAGE_CURRENT_EPOCH,
    STORAGE_EPOCH_WEIGHTS,
    STORAGE_MINER_STATUSES,
    SubstrateClient,
    SubstrateRpcError,
    blake2_128_concat,
    encode_u64_le,
    read_current_epoch,
    read_epoch_weights,
    read_miner_status,
    storage_double_map_partial_key,
    storage_map_key,
    storage_value_key,
    twox128,
)

# ---------------------------------------------------------------------------
# Substrate vector tests — pinned reference values
# ---------------------------------------------------------------------------


def test_twox128_substrate_vectors() -> None:
    # Canonical Substrate vectors: see polkadot-sdk's
    # `frame_support::storage::storage_prefix` tests.
    assert twox128(b"System").hex() == "26aa394eea5630e07c48ae0c9558cef7"
    assert twox128(b"Account").hex() == "b99d880ec681799c0cf30e8886371da9"


def test_storage_value_key_for_system_number() -> None:
    # `System.Number` is the well-known canonical example.
    expected = (
        "26aa394eea5630e07c48ae0c9558cef7"  # twox128("System")
        "02a5c1b19ab7a04f536c519aca4983ac"  # twox128("Number")
    )
    assert storage_value_key("System", "Number").hex() == expected


def test_blake2_128_concat_layout() -> None:
    # blake2_128_concat(x) = blake2_128(x) || x
    out = blake2_128_concat(b"abc")
    assert out.endswith(b"abc")
    assert len(out) == 16 + 3


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _u64_hex_le(n: int) -> str:
    return "0x" + n.to_bytes(8, "little").hex()


def _u128_hex_le(n: int) -> str:
    return "0x" + n.to_bytes(16, "little").hex()


def _make_handler(routes: dict[str, Any]) -> Any:
    """Build an httpx MockTransport handler.

    `routes` maps a *predicate* (method_name, optional params matcher)
    to a JSON-RPC response payload. Predicates are keyed by
    `(method, key_hex_prefix)` so we can dispatch on which storage
    key the caller asked for.
    """

    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        method = body.get("method")
        params = body.get("params") or []
        first = params[0] if params else None
        # Try most-specific key, then method-only fallback.
        for (m, prefix), payload in routes.items():
            if m != method:
                continue
            if prefix is None:
                return httpx.Response(200, json=payload(body))
            if isinstance(first, str) and first.startswith(prefix):
                return httpx.Response(200, json=payload(body))
        return httpx.Response(
            200,
            json={"jsonrpc": "2.0", "id": body.get("id"), "result": None},
        )

    return handler


def _client_with(routes: dict[str, Any]) -> SubstrateClient:
    transport = httpx.MockTransport(_make_handler(routes))
    return SubstrateClient(url="http://test.invalid", transport=transport)


# ---------------------------------------------------------------------------
# read_current_epoch
# ---------------------------------------------------------------------------


def test_read_current_epoch_happy_path() -> None:
    key = storage_value_key(PALLET_NAME, STORAGE_CURRENT_EPOCH)
    routes = {
        ("state_getStorage", "0x" + key.hex()): lambda b: {
            "jsonrpc": "2.0",
            "id": b["id"],
            "result": _u64_hex_le(7),
        }
    }
    assert read_current_epoch(client=_client_with(routes)) == 7


def test_read_current_epoch_null_means_zero() -> None:
    routes: dict[Any, Any] = {
        ("state_getStorage", None): lambda b: {
            "jsonrpc": "2.0",
            "id": b["id"],
            "result": None,
        }
    }
    assert read_current_epoch(client=_client_with(routes)) == 0


# ---------------------------------------------------------------------------
# read_miner_status
# ---------------------------------------------------------------------------


def _encode_miner_status_entry(
    discriminant: int, block: int, epoch: int, *, bn_bytes: int = 4
) -> str:
    blob = (
        bytes([discriminant])
        + block.to_bytes(bn_bytes, "little")
        + epoch.to_bytes(8, "little")
    )
    return "0x" + blob.hex()


def test_read_miner_status_active(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(tb.ENV_BLOCK_NUMBER_BITS, "32")
    nid = b"\x11" * 32
    key = storage_map_key(PALLET_NAME, STORAGE_MINER_STATUSES, nid)
    routes = {
        ("state_getStorage", "0x" + key.hex()): lambda b: {
            "jsonrpc": "2.0",
            "id": b["id"],
            "result": _encode_miner_status_entry(0, 12_345, 6, bn_bytes=4),
        }
    }
    ms = read_miner_status(nid, client=_client_with(routes))
    assert ms is not None
    assert ms.status == "Active"
    assert ms.discriminant == 0
    assert ms.last_transition_block == 12_345
    assert ms.last_transition_epoch == 6


def test_read_miner_status_quarantined_with_64bit_block_number(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv(tb.ENV_BLOCK_NUMBER_BITS, "64")
    nid = b"\x22" * 32
    routes: dict[Any, Any] = {
        ("state_getStorage", None): lambda b: {
            "jsonrpc": "2.0",
            "id": b["id"],
            "result": _encode_miner_status_entry(1, 1 << 40, 99, bn_bytes=8),
        }
    }
    ms = read_miner_status(nid, client=_client_with(routes))
    assert ms is not None
    assert ms.status == "Quarantined"
    assert ms.last_transition_block == 1 << 40
    assert ms.last_transition_epoch == 99


def test_read_miner_status_not_found() -> None:
    nid = b"\x33" * 32
    routes: dict[Any, Any] = {
        ("state_getStorage", None): lambda b: {
            "jsonrpc": "2.0",
            "id": b["id"],
            "result": None,
        }
    }
    assert read_miner_status(nid, client=_client_with(routes)) is None


def test_read_miner_status_rejects_wrong_length_node_id() -> None:
    with pytest.raises(SubstrateRpcError, match="32 bytes"):
        read_miner_status(b"\x44" * 16, client=_client_with({}))


def test_read_miner_status_accepts_hex_string() -> None:
    nid_hex = "0x" + ("55" * 32)
    routes: dict[Any, Any] = {
        ("state_getStorage", None): lambda b: {
            "jsonrpc": "2.0",
            "id": b["id"],
            "result": None,
        }
    }
    assert read_miner_status(nid_hex, client=_client_with(routes)) is None


def test_decode_miner_status_entry_rejects_short_blob(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv(tb.ENV_BLOCK_NUMBER_BITS, "32")
    with pytest.raises(SubstrateRpcError, match="MinerStatusEntry"):
        tb.decode_miner_status_entry(b"\x00" * 5)


# ---------------------------------------------------------------------------
# read_epoch_weights
# ---------------------------------------------------------------------------


def test_read_epoch_weights_returns_decoded_rows() -> None:
    epoch = 5
    prefix = storage_double_map_partial_key(
        PALLET_NAME, STORAGE_EPOCH_WEIGHTS, encode_u64_le(epoch)
    )
    # Build two synthetic full keys: prefix || blake2_128(nid) || nid.
    node_a = b"\xaa" * 32
    node_b = b"\xbb" * 32
    key_a = prefix + blake2_128_concat(node_a)
    key_b = prefix + blake2_128_concat(node_b)
    keys_called: list[Any] = []

    def keys_handler(b: dict[str, Any]) -> dict[str, Any]:
        params = b["params"]
        # Pagination call shape: [prefix, count, optional start_key].
        keys_called.append(params)
        if len(params) == 2:
            # First page — return both keys, full page size triggers another call.
            page = ["0x" + key_a.hex(), "0x" + key_b.hex()]
        else:
            # Second call — empty page, terminates loop.
            page = []
        return {"jsonrpc": "2.0", "id": b["id"], "result": page}

    def storage_handler(b: dict[str, Any]) -> dict[str, Any]:
        param = b["params"][0]
        if param == "0x" + key_a.hex():
            return {
                "jsonrpc": "2.0",
                "id": b["id"],
                "result": _u128_hex_le(1_000_000),
            }
        if param == "0x" + key_b.hex():
            return {
                "jsonrpc": "2.0",
                "id": b["id"],
                "result": _u128_hex_le(2_500_000),
            }
        return {"jsonrpc": "2.0", "id": b["id"], "result": None}

    routes = {
        ("state_getKeysPaged", None): keys_handler,
        ("state_getStorage", None): storage_handler,
    }
    rows = read_epoch_weights(epoch, client=_client_with(routes))
    rows.sort(key=lambda r: r[0])
    assert rows == [(node_a, 1_000_000), (node_b, 2_500_000)]
    # First (and only) keys call has shape [prefix, count] — pagination
    # is short-circuited because the page is smaller than the bound.
    assert len(keys_called) == 1
    assert len(keys_called[0]) == 2


def test_read_epoch_weights_empty() -> None:
    routes: dict[Any, Any] = {
        ("state_getKeysPaged", None): lambda b: {
            "jsonrpc": "2.0",
            "id": b["id"],
            "result": [],
        }
    }
    assert read_epoch_weights(42, client=_client_with(routes)) == []


def test_read_epoch_weights_rejects_negative_or_oversized_epoch() -> None:
    with pytest.raises(SubstrateRpcError, match="out of range"):
        read_epoch_weights(-1, client=_client_with({}))
    with pytest.raises(SubstrateRpcError, match="out of range"):
        read_epoch_weights(1 << 64, client=_client_with({}))


# ---------------------------------------------------------------------------
# Error surfaces
# ---------------------------------------------------------------------------


def test_rpc_http_error_surfaces_substraterpcerror() -> None:
    def handler(_req: httpx.Request) -> httpx.Response:
        return httpx.Response(500, text="boom")

    client = SubstrateClient(
        url="http://test.invalid", transport=httpx.MockTransport(handler)
    )
    with pytest.raises(SubstrateRpcError, match="HTTP 500"):
        read_current_epoch(client=client)


def test_rpc_jsonrpc_error_surfaces_substraterpcerror() -> None:
    routes: dict[Any, Any] = {
        ("state_getStorage", None): lambda b: {
            "jsonrpc": "2.0",
            "id": b["id"],
            "error": {"code": -32601, "message": "Method not found"},
        }
    }
    with pytest.raises(SubstrateRpcError, match="Method not found"):
        read_current_epoch(client=_client_with(routes))


def test_client_factory_requires_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(tb.ENV_RPC_URL, raising=False)
    with pytest.raises(SubstrateRpcError, match=tb.ENV_RPC_URL):
        tb._client()


def test_block_number_bits_validation(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(tb.ENV_BLOCK_NUMBER_BITS, "16")
    with pytest.raises(SubstrateRpcError, match="32 or 64"):
        tb.decode_miner_status_entry(b"\x00" * 13)
