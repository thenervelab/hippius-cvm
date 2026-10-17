"""The `move-vm-storage` order kind (disk-tier live storage move) through the real
encoder: vali's payload reproduces the shared vector
(`test_vectors/orders/move_vm_storage_v1.json`) the Edge and the agent test
against. No sender exists yet. Skips when the binary is not built."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from django.conf import settings

from apps.orchestration import order_dispatch

_REAL_BIN = Path(settings.VALI_TICKET_VALIDATOR_BIN)
_VECTOR = (
    Path(__file__).resolve().parents[4] / "test_vectors" / "orders" / "move_vm_storage_v1.json"
)


def _vector() -> dict:
    return json.loads(_VECTOR.read_text())


def test_the_builder_produces_the_vector_payloads() -> None:
    for case in _vector()["cases"]:
        p = case["payload"]
        built = order_dispatch.build_move_vm_storage_payload(
            vm_id=p["vm_id"],
            move_id=p["move_id"],
            action=p["action"],
            not_after_unix=p["not_after_unix"],
            target_pool=p.get("target_pool"),
            expected_source_pool=p.get("expected_source_pool"),
            bandwidth_mib_s=p.get("bandwidth_mib_s"),
        )
        assert built == p, case["name"]


@pytest.mark.skipif(
    not _REAL_BIN.is_file(),
    reason=f"Rust validator not built at {_REAL_BIN}: cargo build -p hippius-ticket-validator",
)
def test_the_body_matches_the_shared_vector() -> None:
    v = _vector()
    for case in v["cases"]:
        body = order_dispatch._encode_order_body(
            order_id=v["order_id"],
            kind="move-vm-storage",
            target_miner_id=v["target_miner_id"],
            issued_at_unix=v["issued_at_unix"],
            payload_json=json.dumps(case["payload"]).encode(),
        )
        assert body.hex() == case["body_hex"], case["name"]


@pytest.mark.skipif(not _REAL_BIN.is_file(), reason="Rust validator not built")
def test_a_start_field_on_status_is_refused_not_dropped() -> None:
    payload = dict(_vector()["cases"][1]["payload"], target_pool="nvme0")
    with pytest.raises(order_dispatch.OrderDispatchError, match="move-start-field-on-other-action"):
        order_dispatch._encode_order_body(
            order_id="o",
            kind="move-vm-storage",
            target_miner_id="miner-1",
            issued_at_unix=1,
            payload_json=json.dumps(payload).encode(),
        )


def test_the_builder_refuses_a_start_without_its_fields_or_a_status_with_them() -> None:
    base = dict(vm_id="v", move_id="a" * 32, not_after_unix=1)
    with pytest.raises(ValueError):
        order_dispatch.build_move_vm_storage_payload(
            **base, action="start", target_pool="nvme0", expected_source_pool="default"
        )
    with pytest.raises(ValueError):
        order_dispatch.build_move_vm_storage_payload(**base, action="status", target_pool="nvme0")
