"""thebrain (Substrate) JSON-RPC reader (PR-S3).

Minimal hand-rolled Substrate client over plain HTTPS JSON-RPC. We
intentionally do NOT depend on `py-substrate-interface` — its surface
area is large, it fetches and caches chain metadata at construction
time (awkward for our read-only patrol cadence), and the §S posture
favours small auditable code paths.

Three storage items the agent can read:

  - `read_current_epoch()` — `CurrentEpoch: StorageValue<u64>` from
    `pallet-compute-scoring`. 8 bytes LE.
  - `read_miner_status(node_id)` —
    `MinerStatuses: StorageMap<Blake2_128Concat, [u8;32],
    MinerStatusEntry<BlockNumber>>`. SCALE: 1 byte discriminant +
    BlockNumber (4 bytes LE, FRAME default) + u64 LE.
  - `read_epoch_weights(epoch)` —
    `EpochWeights: StorageDoubleMap<Blake2_128Concat, u64,
    Blake2_128Concat, [u8;32], u128>`. Iterates the partial-key
    prefix `(twox128 pallet || twox128 storage || blake2_128_concat
    epoch)` via `state_getKeysPaged` and decodes each value as a
    16-byte LE u128.

`BlockNumber` width is configurable via `THEBRAIN_BLOCK_NUMBER_BITS`
(default 32 to match the FRAME default polkadot-sdk stable2407 uses;
flip to 64 if the chain runtime declares `BlockNumber = u64`). Decoding
fails loudly if the on-disk blob doesn't match the configured width.

See `pallets/compute-scoring/src/lib.rs` for the canonical storage
declarations:

    CurrentEpoch:   StorageValue<_, u64, ValueQuery>             (line 626)
    MinerStatuses:  StorageMap<_, Blake2_128Concat, [u8;32],
                               MinerStatusEntry<BlockNumberFor<T>>,
                               OptionQuery>                       (line 634)
    EpochWeights:   StorageDoubleMap<_, Blake2_128Concat, u64,
                                     Blake2_128Concat, [u8;32],
                                     u128, OptionQuery>           (line 651)
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
from dataclasses import dataclass
from typing import Any

import httpx
import xxhash
from claude_agent_sdk import tool

log = logging.getLogger("sentinel.tools.thebrain_rpc")

ENV_RPC_URL = "THEBRAIN_RPC_URL"
ENV_BLOCK_NUMBER_BITS = "THEBRAIN_BLOCK_NUMBER_BITS"

# Pallet + storage names. The runtime's `construct_runtime!` pallet
# instance name MUST match this exactly — typically "ComputeScoring".
# If the thebrain runtime registers the pallet under a different name
# we'd surface a "no such storage" response (storage_keys returns
# empty); document via `SENTINEL_PALLET_NAME_OVERRIDE` for future
# flexibility but default to the canonical name.
PALLET_NAME = os.environ.get("SENTINEL_PALLET_NAME_OVERRIDE", "ComputeScoring")
STORAGE_CURRENT_EPOCH = "CurrentEpoch"
STORAGE_MINER_STATUSES = "MinerStatuses"
STORAGE_EPOCH_WEIGHTS = "EpochWeights"

# Bound the page size for state_getKeysPaged so a hostile / large
# epoch can't OOM the sentinel. 256 ≫ realistic miner count for v1.
MAX_KEYS_PER_PAGE = 256

# MinerStatus enum discriminants (see pallet line 240).
_MINER_STATUS_NAMES = {
    0: "Active",
    1: "Quarantined",
    2: "Decommissioned",
}


class SubstrateRpcError(RuntimeError):
    """Raised when an RPC call returns an error or invalid encoding."""


@dataclass(frozen=True)
class MinerStatus:
    status: str  # one of MinerStatus enum names; "Unknown(<n>)" for unrecognized discriminants
    discriminant: int
    last_transition_block: int
    last_transition_epoch: int


# ---------------------------------------------------------------------------
# Hash helpers — Substrate storage-key derivation
# ---------------------------------------------------------------------------


def twox128(s: bytes) -> bytes:
    """Substrate `twox_128` = LE-concat of `xxh64(s, seed=0)` + `xxh64(s, seed=1)`."""

    return (
        xxhash.xxh64(s, seed=0).intdigest().to_bytes(8, "little")
        + xxhash.xxh64(s, seed=1).intdigest().to_bytes(8, "little")
    )


def blake2_128_concat(key: bytes) -> bytes:
    """Substrate `Blake2_128Concat(key) = blake2_128(key) || key`."""

    return hashlib.blake2b(key, digest_size=16).digest() + key


def pallet_prefix(pallet: str, storage: str) -> bytes:
    return twox128(pallet.encode("utf-8")) + twox128(storage.encode("utf-8"))


def storage_value_key(pallet: str, storage: str) -> bytes:
    return pallet_prefix(pallet, storage)


def storage_map_key(pallet: str, storage: str, key_bytes: bytes) -> bytes:
    return pallet_prefix(pallet, storage) + blake2_128_concat(key_bytes)


def storage_double_map_partial_key(
    pallet: str, storage: str, k1_bytes: bytes
) -> bytes:
    """Prefix key used to iterate a `StorageDoubleMap` by its first key."""

    return pallet_prefix(pallet, storage) + blake2_128_concat(k1_bytes)


# ---------------------------------------------------------------------------
# Tiny SCALE decoders for the exact types we read
# ---------------------------------------------------------------------------


def _block_number_bytes() -> int:
    raw = os.environ.get(ENV_BLOCK_NUMBER_BITS, "32").strip()
    if raw not in {"32", "64"}:
        raise SubstrateRpcError(
            f"{ENV_BLOCK_NUMBER_BITS} must be 32 or 64, got {raw!r}"
        )
    return 4 if raw == "32" else 8


def decode_u64_le(b: bytes) -> int:
    if len(b) != 8:
        raise SubstrateRpcError(f"expected 8 bytes for u64, got {len(b)}")
    return int.from_bytes(b, "little")


def decode_u128_le(b: bytes) -> int:
    if len(b) != 16:
        raise SubstrateRpcError(f"expected 16 bytes for u128, got {len(b)}")
    return int.from_bytes(b, "little")


def decode_miner_status_entry(b: bytes) -> MinerStatus:
    bn_bytes = _block_number_bytes()
    expected_len = 1 + bn_bytes + 8
    if len(b) != expected_len:
        raise SubstrateRpcError(
            f"MinerStatusEntry: expected {expected_len} bytes (BlockNumber={bn_bytes*8} "
            f"bits + u64 epoch), got {len(b)}"
        )
    disc = b[0]
    block = int.from_bytes(b[1 : 1 + bn_bytes], "little")
    epoch = int.from_bytes(b[1 + bn_bytes : 1 + bn_bytes + 8], "little")
    name = _MINER_STATUS_NAMES.get(disc, f"Unknown({disc})")
    return MinerStatus(
        status=name,
        discriminant=disc,
        last_transition_block=block,
        last_transition_epoch=epoch,
    )


def encode_u64_le(n: int) -> bytes:
    if n < 0 or n >= 1 << 64:
        raise SubstrateRpcError(f"u64 out of range: {n}")
    return n.to_bytes(8, "little")


def split_double_map_key(
    pallet: str, storage: str, k1_bytes: bytes, full_key: bytes
) -> bytes:
    """Extract the second key (32-byte node_id) out of a full storage key.

    The on-disk layout is::

        twox128(pallet) || twox128(storage)
          || blake2_128(k1) || k1            # 16+8 bytes for u64 epoch
          || blake2_128(k2) || k2            # 16+32 bytes for [u8;32] node_id

    Anything that doesn't match this layout is treated as a malformed
    response from the RPC node.
    """

    prefix = storage_double_map_partial_key(pallet, storage, k1_bytes)
    if not full_key.startswith(prefix):
        raise SubstrateRpcError("double-map key does not carry expected prefix")
    rest = full_key[len(prefix) :]
    if len(rest) != 16 + 32:
        raise SubstrateRpcError(
            f"double-map secondary key has unexpected length {len(rest)} (want 48)"
        )
    return rest[16:]


# ---------------------------------------------------------------------------
# JSON-RPC client
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class SubstrateClient:
    """Thin JSON-RPC v2 wrapper over httpx.

    Two RPCs are used:
      - `state_getStorage(key)` — returns hex-encoded value or null.
      - `state_getKeysPaged(prefix, count, start_key=None)` — returns
        the next `count` keys whose prefix matches.

    Connection is per-call (no persistent client). Sentinel patrols
    every few minutes; a stale HTTP connection adds operational risk
    without saving meaningful latency.
    """

    url: str
    timeout_s: float = 10.0
    transport: httpx.BaseTransport | None = None

    def _rpc(self, method: str, params: list[Any]) -> Any:
        body = {"jsonrpc": "2.0", "id": 1, "method": method, "params": params}
        with httpx.Client(transport=self.transport, timeout=self.timeout_s) as c:
            r = c.post(self.url, json=body)
        if r.status_code != httpx.codes.OK:
            raise SubstrateRpcError(
                f"rpc {method}: HTTP {r.status_code}: {r.text[:200]}"
            )
        try:
            payload = r.json()
        except json.JSONDecodeError as e:
            raise SubstrateRpcError(f"rpc {method}: non-json response: {e}") from e
        if "error" in payload:
            raise SubstrateRpcError(f"rpc {method}: {payload['error']}")
        return payload.get("result")

    def get_storage(self, key: bytes) -> bytes | None:
        hex_key = "0x" + key.hex()
        result = self._rpc("state_getStorage", [hex_key])
        if result is None:
            return None
        if not isinstance(result, str) or not result.startswith("0x"):
            raise SubstrateRpcError(f"state_getStorage returned non-hex: {result!r}")
        return bytes.fromhex(result[2:])

    def get_keys_paged(
        self, prefix: bytes, *, count: int, start_key: bytes | None = None
    ) -> list[bytes]:
        if count <= 0 or count > MAX_KEYS_PER_PAGE:
            raise SubstrateRpcError(
                f"count must be in 1..{MAX_KEYS_PER_PAGE}, got {count}"
            )
        params: list[Any] = ["0x" + prefix.hex(), count]
        if start_key is not None:
            params.append("0x" + start_key.hex())
        result = self._rpc("state_getKeysPaged", params)
        if result is None:
            return []
        if not isinstance(result, list):
            raise SubstrateRpcError(
                f"state_getKeysPaged returned non-list: {type(result).__name__}"
            )
        out: list[bytes] = []
        for k in result:
            if not isinstance(k, str) or not k.startswith("0x"):
                raise SubstrateRpcError(f"state_getKeysPaged key not hex: {k!r}")
            out.append(bytes.fromhex(k[2:]))
        return out


def _client(transport: httpx.BaseTransport | None = None) -> SubstrateClient:
    url = os.environ.get(ENV_RPC_URL, "").strip()
    if not url:
        raise SubstrateRpcError(
            f"{ENV_RPC_URL} is not set; PR-S3 thebrain RPC reader cannot connect."
        )
    return SubstrateClient(url=url, transport=transport)


# ---------------------------------------------------------------------------
# High-level reads
# ---------------------------------------------------------------------------


def read_current_epoch(*, client: SubstrateClient | None = None) -> int:
    c = client or _client()
    key = storage_value_key(PALLET_NAME, STORAGE_CURRENT_EPOCH)
    raw = c.get_storage(key)
    if raw is None:
        # `ValueQuery` with default 0 means a missing key SHOULD be
        # treated as zero. The chain returns the encoded default only
        # if it's been written at least once; a never-touched chain
        # responds with null.
        return 0
    return decode_u64_le(raw)


def read_miner_status(
    node_id: bytes | str, *, client: SubstrateClient | None = None
) -> MinerStatus | None:
    if isinstance(node_id, str):
        nid = bytes.fromhex(node_id.removeprefix("0x"))
    else:
        nid = bytes(node_id)
    if len(nid) != 32:
        raise SubstrateRpcError(f"node_id must be 32 bytes, got {len(nid)}")
    c = client or _client()
    key = storage_map_key(PALLET_NAME, STORAGE_MINER_STATUSES, nid)
    raw = c.get_storage(key)
    if raw is None:
        return None
    return decode_miner_status_entry(raw)


def read_epoch_weights(
    epoch: int, *, client: SubstrateClient | None = None
) -> list[tuple[bytes, int]]:
    """Return the list of `(node_id, weight)` rows for the given epoch.

    Pages through `state_getKeysPaged` then resolves each key with
    `state_getStorage`. The page bound (256 entries) is high enough
    for the v1 miner fleet — if it ever isn't, this will surface as
    a paged-incomplete log entry rather than silently truncate.
    """

    if epoch < 0 or epoch >= 1 << 64:
        raise SubstrateRpcError(f"epoch out of range: {epoch}")
    c = client or _client()
    prefix = storage_double_map_partial_key(
        PALLET_NAME, STORAGE_EPOCH_WEIGHTS, encode_u64_le(epoch)
    )
    keys: list[bytes] = []
    start: bytes | None = None
    while True:
        page = c.get_keys_paged(prefix, count=MAX_KEYS_PER_PAGE, start_key=start)
        if not page:
            break
        keys.extend(page)
        if len(page) < MAX_KEYS_PER_PAGE:
            break
        start = page[-1]
        if len(keys) >= MAX_KEYS_PER_PAGE * 8:
            # Hard ceiling — protects against an RPC node that returns
            # the same page indefinitely.
            log.warning(
                "epoch_weights: hit hard page ceiling (%d), truncating", len(keys)
            )
            break

    out: list[tuple[bytes, int]] = []
    for k in keys:
        node_id = split_double_map_key(
            PALLET_NAME, STORAGE_EPOCH_WEIGHTS, encode_u64_le(epoch), k
        )
        raw = c.get_storage(k)
        if raw is None:
            continue
        out.append((node_id, decode_u128_le(raw)))
    return out


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


async def _read_current_epoch_impl(_args: dict[str, Any]) -> dict[str, Any]:
    try:
        e = read_current_epoch()
    except SubstrateRpcError as err:
        log.warning("read_current_epoch: %s", err)
        return _structured_error(f"thebrain rpc error: {err}")
    except Exception as err:  # noqa: BLE001
        log.exception("read_current_epoch: unexpected failure")
        return _structured_error(f"read_current_epoch failed: {err}")
    return _structured_json({"current_epoch": e})


async def _read_miner_status_impl(args: dict[str, Any]) -> dict[str, Any]:
    node_id = args.get("node_id")
    if not isinstance(node_id, str) or not node_id:
        return _structured_error("read_miner_status requires a 32-byte hex node_id")
    try:
        status = read_miner_status(node_id)
    except SubstrateRpcError as err:
        log.warning("read_miner_status: %s", err)
        return _structured_error(f"thebrain rpc error: {err}")
    except Exception as err:  # noqa: BLE001
        log.exception("read_miner_status: unexpected failure")
        return _structured_error(f"read_miner_status failed: {err}")
    if status is None:
        return _structured_json({"found": False, "node_id": node_id})
    return _structured_json(
        {
            "found": True,
            "node_id": node_id,
            "status": status.status,
            "discriminant": status.discriminant,
            "last_transition_block": status.last_transition_block,
            "last_transition_epoch": status.last_transition_epoch,
        }
    )


async def _read_epoch_weights_impl(args: dict[str, Any]) -> dict[str, Any]:
    raw_epoch = args.get("epoch")
    try:
        epoch = int(raw_epoch)
    except (TypeError, ValueError):
        return _structured_error(f"epoch must be an int, got {raw_epoch!r}")
    try:
        rows = read_epoch_weights(epoch)
    except SubstrateRpcError as err:
        log.warning("read_epoch_weights: %s", err)
        return _structured_error(f"thebrain rpc error: {err}")
    except Exception as err:  # noqa: BLE001
        log.exception("read_epoch_weights: unexpected failure")
        return _structured_error(f"read_epoch_weights failed: {err}")
    return _structured_json(
        {
            "epoch": epoch,
            "returned_count": len(rows),
            "rows": [
                {"node_id_hex": nid.hex(), "weight": w} for nid, w in rows
            ],
        }
    )


read_current_epoch_tool = tool(
    "read_current_epoch",
    "Read pallet-compute-scoring `CurrentEpoch` storage on thebrain. "
    "Returns the current u64 epoch number.",
    {},
)(_read_current_epoch_impl)


read_miner_status_tool = tool(
    "read_miner_status",
    "Read pallet-compute-scoring `MinerStatuses[node_id]` on thebrain. "
    "Node id is a 32-byte hex string. Returns "
    "{found, status (Active|Quarantined|Decommissioned), discriminant, "
    "last_transition_block, last_transition_epoch}.",
    {"node_id": str},
)(_read_miner_status_impl)


read_epoch_weights_tool = tool(
    "read_epoch_weights",
    "Read pallet-compute-scoring `EpochWeights[epoch][*]` on thebrain. "
    "Iterates the partial-key prefix via `state_getKeysPaged` and "
    "returns `{node_id_hex, weight (u128)}` per row.",
    {"epoch": int},
)(_read_epoch_weights_impl)
