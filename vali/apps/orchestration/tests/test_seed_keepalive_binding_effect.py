"""`effects.seed_keepalive_binding` — the KBS admin seed-keepalive-binding
client. Patches only `effects._http`, so the real effect body runs.

- `200` is the only write and must confirm the vm_id and `seeded: true`;
- `409` (`binding-already-recorded`) is a no-op, never a failure;
- `404` is a distinct route-missing error, `400` a contract mismatch;
- inputs are checked BEFORE the request, so a malformed value never
  reaches the KBS;
- non-2xx bodies are CBOR and are never decoded.
"""

from __future__ import annotations

import json
from typing import Any

import pytest

from apps.orchestration import effects

CHIP = "5e" * 64
REPORT = "7a" * 32


@pytest.fixture
def http(monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    state: dict[str, Any] = {"status": 200, "body": b"", "calls": []}

    def fake_http(
        method: str,
        url: str,
        *,
        label: str,
        json_body: dict[str, Any] | None = None,
        headers: dict[str, str] | None = None,
        context: object = None,
    ) -> tuple[int, bytes]:
        state["calls"].append({"method": method, "url": url, "json": json_body})
        return state["status"], state["body"]

    monkeypatch.setattr(effects, "_http", fake_http)
    return state


def _seed() -> str:
    return effects.seed_keepalive_binding("vm-a", chip_id_hex=CHIP, report_id_hex=REPORT)


def test_a_200_posts_the_guest_to_the_admin_route(http: dict[str, Any]) -> None:
    http["body"] = json.dumps({"v": 1, "vm_id": "vm-a", "seeded": True, "matched": False}).encode()
    assert _seed() == "seeded"
    call = http["calls"][0]
    assert call["method"] == "POST"
    assert call["url"] == "http://kbs.test/v1/admin/vm/vm-a/seed-keepalive-binding"
    assert call["json"] == {"chip_id_hex": CHIP, "report_id_hex": REPORT}


def test_a_200_that_does_not_confirm_the_seed_is_an_error(http: dict[str, Any]) -> None:
    http["body"] = json.dumps({"v": 1, "vm_id": "vm-b", "seeded": True}).encode()
    with pytest.raises(effects.EffectError):
        _seed()


def test_the_same_guest_already_on_record_is_matched(http: dict[str, Any]) -> None:
    http["body"] = json.dumps({"v": 1, "vm_id": "vm-a", "seeded": False, "matched": True}).encode()
    assert _seed() == "matched"


def test_a_200_that_is_neither_seeded_nor_matched_is_an_error(http: dict[str, Any]) -> None:
    http["body"] = json.dumps({"v": 1, "vm_id": "vm-a", "seeded": False}).encode()
    with pytest.raises(effects.EffectError):
        _seed()


@pytest.mark.parametrize(
    ("status", "error"),
    [
        (404, effects.KbsRouteMissing),
        (409, effects.KbsBindingConflict),
        (412, effects.KbsBindingPrecondition),
        (400, effects.KbsAdminContractMismatch),
        (500, effects.EffectError),
        (429, effects.EffectError),
    ],
)
def test_other_statuses(http: dict[str, Any], status: int, error: type[Exception]) -> None:
    http["status"] = status
    with pytest.raises(error):
        _seed()


@pytest.mark.parametrize(
    ("vm_id", "chip", "report"),
    [
        ("", CHIP, REPORT),
        ("vm-a", CHIP[:-2], REPORT),
        ("vm-a", CHIP.upper(), REPORT),
        ("vm-a", CHIP, REPORT[:-2]),
        ("vm-a", CHIP, "00" * 32),
        ("vm-a", "00" * 64, REPORT),
    ],
)
def test_bad_inputs_never_reach_the_kbs(
    http: dict[str, Any], vm_id: str, chip: str, report: str
) -> None:
    with pytest.raises(effects.EffectError):
        effects.seed_keepalive_binding(vm_id, chip_id_hex=chip, report_id_hex=report)
    assert http["calls"] == []
