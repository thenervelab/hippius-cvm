"""The `storage-config` order kind through the real encoder: vali's
`encode-order` and `storage-config-digest` reproduce the shared vector
(`test_vectors/orders/storage_config_v1.json`) the Edge and the agent test
against. No sender exists yet. Skips when the binary is not built."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from django.conf import settings

from apps.orchestration import order_dispatch

_REAL_BIN = Path(settings.VALI_TICKET_VALIDATOR_BIN)
_VECTOR = Path(__file__).resolve().parents[4] / "test_vectors" / "orders" / "storage_config_v1.json"
pytestmark = pytest.mark.skipif(
    not _REAL_BIN.is_file(),
    reason=f"Rust validator not built at {_REAL_BIN}: cargo build -p hippius-ticket-validator",
)


def _vector() -> dict:
    return json.loads(_VECTOR.read_text())


def test_the_body_matches_the_shared_vector() -> None:
    v = _vector()
    for case in v["cases"]:
        body = order_dispatch._encode_order_body(
            order_id=v["order_id"],
            kind="storage-config",
            target_miner_id=v["target_miner_id"],
            issued_at_unix=v["issued_at_unix"],
            payload_json=json.dumps(case["payload"]).encode(),
        )
        assert body.hex() == case["body_hex"], case["name"]


def test_the_digest_matches_the_shared_vector() -> None:
    for case in _vector()["cases"]:
        payload = json.dumps(case["payload"]).encode()
        assert order_dispatch.storage_config_digest(payload) == case["content_sha256"], case["name"]


def test_an_unknown_key_is_refused_not_dropped() -> None:
    payload = dict(_vector()["cases"][0]["payload"])
    payload["vm_id"] = "tenant-1"
    with pytest.raises(order_dispatch.OrderDispatchError, match="storage-config-unknown-field"):
        order_dispatch.storage_config_digest(json.dumps(payload).encode())
