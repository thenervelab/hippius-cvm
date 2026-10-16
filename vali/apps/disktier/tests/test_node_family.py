"""The on-chain node → family read: SS58, the subprocess contract
(stubbed — no network), fail-closed, the cache."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import Any

import pytest
from django.conf import settings

from apps.disktier import node_family
from apps.disktier.node_family import FamilyCheckUnavailable, NodeFamily
from apps.scheduler.tests.factories import node_id

from .conftest import FAMILY_A, ss58_encode

ALICE = "5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY"
ALICE_HEX = "d43593c715fdd31c61141abd04a99fd6822c8558854ccde39a5684e7a56da27d"


def test_ss58_decodes_the_published_alice_address() -> None:
    assert node_family.ss58_decode(ALICE).hex() == ALICE_HEX


def test_ss58_is_prefix_agnostic_and_round_trips() -> None:
    for prefix in (0, 2, 42):
        assert node_family.ss58_decode(ss58_encode(FAMILY_A, prefix)) == FAMILY_A


@pytest.mark.parametrize(
    "bad",
    ["", "0OIl", ALICE[:-1] + ("R" if ALICE[-1] != "R" else "S"), ALICE[:-3], "1" * 48, "x" * 80],
)
def test_ss58_refuses_anything_else(bad: str) -> None:
    with pytest.raises(ValueError):
        node_family.ss58_decode(bad)


# ─── subprocess contract ─────────────────────────────────────────────


class _Completed:
    def __init__(self, rc: int, stdout: bytes) -> None:
        self.returncode = rc
        self.stdout = stdout
        self.stderr = b""


@pytest.fixture
def validator(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> dict[str, Any]:
    binary = tmp_path / "hippius-ticket-validator"
    binary.write_text("")
    monkeypatch.setattr(settings, "VALI_TICKET_VALIDATOR_BIN", str(binary))
    monkeypatch.setattr(settings, "VALI_THEBRAIN_RPC_URL", "http://rpc.invalid:9933")
    state: dict[str, Any] = {"calls": [], "answer": (0, b"{}")}

    def _run(argv: list[str], **kw: Any) -> _Completed:
        state["calls"].append({"argv": argv, "env": kw["env"]})
        answer = state["answer"]
        if isinstance(answer, Exception):
            raise answer
        return _Completed(*answer)

    monkeypatch.setattr(subprocess, "run", _run)
    node_family.clear_cache()
    yield state
    node_family.clear_cache()


def _ok(node: str, **over: Any) -> bytes:
    body = {
        "tag": "ok",
        "block_hash": "0x" + "ab" * 32,
        "node_id_hex": node,
        "bound": True,
        "child_hex": "22" * 32,
        "family_hex": FAMILY_A.hex(),
        "status": "active",
    }
    body.update(over)
    return json.dumps(body).encode()


def test_a_bound_node_is_read_with_the_url_in_the_environment(validator: dict[str, Any]) -> None:
    node = node_id(5)
    validator["answer"] = (0, _ok(node))
    got = node_family.read_node_family(node)
    assert got == NodeFamily(
        node_id=node,
        block_hash="0x" + "ab" * 32,
        bound=True,
        family_hex=FAMILY_A.hex(),
        status="active",
    )
    call = validator["calls"][0]
    assert call["argv"][1:] == [
        "read-node-family",
        "--pallet-name",
        "ComputeScoring",
        "--node-id",
        node,
    ]
    assert call["env"]["THEBRAIN_RPC_URL"] == "http://rpc.invalid:9933"
    assert all("rpc.invalid" not in arg for arg in call["argv"])


def test_an_unbound_node_is_an_answer_not_an_error(validator: dict[str, Any]) -> None:
    node = node_id(5)
    validator["answer"] = (
        0,
        json.dumps(
            {
                "tag": "ok",
                "block_hash": "0x00",
                "node_id_hex": node,
                "bound": False,
                "reason": "no-child",
            }
        ).encode(),
    )
    got = node_family.read_node_family(node)
    assert not got.bound and got.reason == "no-child" and not got.active


@pytest.mark.parametrize(
    "answer",
    [
        (2, b'{"tag":"err","error":"x","category":"rpc-request"}'),
        (1, b""),
        (0, b"not json"),
        (0, b"[]"),
        (0, b'{"tag":"what"}'),
        (2, b'{"tag":"ok"}'),
        subprocess.TimeoutExpired(cmd="x", timeout=1),
        OSError("no exec"),
    ],
)
def test_every_failure_is_unavailable(validator: dict[str, Any], answer: Any) -> None:
    validator["answer"] = answer
    with pytest.raises(FamilyCheckUnavailable):
        node_family.read_node_family(node_id(5))


@pytest.mark.parametrize(
    "over",
    [
        {"node_id_hex": node_id(6)},
        {"family_hex": "zz"},
        {"status": "frozen"},
        {"bound": "yes"},
        {"block_hash": 5},
    ],
)
def test_schema_drift_is_unavailable(validator: dict[str, Any], over: dict[str, Any]) -> None:
    validator["answer"] = (0, _ok(node_id(5), **over))
    with pytest.raises(FamilyCheckUnavailable):
        node_family.read_node_family(node_id(5))


def test_no_rpc_url_or_binary_is_unavailable(
    validator: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(settings, "VALI_THEBRAIN_RPC_URL", "")
    with pytest.raises(FamilyCheckUnavailable, match="RPC_URL"):
        node_family.read_node_family(node_id(5))
    monkeypatch.setattr(settings, "VALI_THEBRAIN_RPC_URL", "http://x.invalid")
    monkeypatch.setattr(settings, "VALI_TICKET_VALIDATOR_BIN", "/nonexistent/validator")
    with pytest.raises(FamilyCheckUnavailable, match="binary"):
        node_family.read_node_family(node_id(5))
    assert validator["calls"] == []


def test_family_runs_node_needs_the_same_account_and_active(validator: dict[str, Any]) -> None:
    node = node_id(5)
    validator["answer"] = (0, _ok(node))
    assert node_family.family_runs_node(node, ss58_encode(FAMILY_A))
    assert not node_family.family_runs_node(node, ALICE)
    node_family.clear_cache()
    validator["answer"] = (0, _ok(node, status="unbonding"))
    assert not node_family.family_runs_node(node, ss58_encode(FAMILY_A))


def test_a_read_is_cached_and_a_failure_is_not(
    validator: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    node = node_id(5)
    validator["answer"] = OSError("down")
    with pytest.raises(FamilyCheckUnavailable):
        node_family.node_family(node)
    validator["answer"] = (0, _ok(node))
    node_family.node_family(node)
    node_family.node_family(node)
    assert len(validator["calls"]) == 2  # the failure + one read
    monkeypatch.setattr(settings, "VALI_OPERATOR_FAMILY_CACHE_S", 0)
    node_family.clear_cache()
    node_family.node_family(node)
    node_family.node_family(node)
    assert len(validator["calls"]) == 4


@pytest.mark.parametrize("prefix", [46, 47])
def test_ss58_refuses_reserved_formats(prefix: int) -> None:
    with pytest.raises(ValueError, match="reserved"):
        node_family.ss58_decode(ss58_encode(FAMILY_A, prefix))


def test_ss58_two_byte_prefixes() -> None:
    import hashlib

    def encode2(ident: int) -> str:
        first = ((ident & 0xFC) >> 2) | 0x40
        second = (ident >> 8) | ((ident & 0x03) << 6)
        body = bytes([first, second]) + FAMILY_A
        data = body + hashlib.blake2b(b"SS58PRE" + body, digest_size=64).digest()[:2]
        num, out = int.from_bytes(data, "big"), ""
        alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
        while num:
            num, rem = divmod(num, 58)
            out = alphabet[rem] + out
        return out

    assert node_family.ss58_decode(encode2(255)) == FAMILY_A
    assert node_family.ss58_decode(encode2(16383)) == FAMILY_A
    with pytest.raises(ValueError):
        node_family.ss58_decode(encode2(5))  # a 1-byte format in the 2-byte form
