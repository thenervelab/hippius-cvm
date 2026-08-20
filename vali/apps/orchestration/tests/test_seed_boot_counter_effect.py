"""`effects.seed_boot_counter` — the KBS admin seed-boot-counter client.

The endpoint is ONE-SHOT per VM (the KBS refuses every seed after the first),
so the client's contract matters:

- `200` is the only write; its body is JSON.
- `409` (`seed-already-recovered`) means a PRIOR seed landed — success with a
  note, never a failure to retry.
- `404` means the route is not in the deployed KBS image. The caller renders
  that as a non-fatal skip, so `vm_id` is charset-checked BEFORE the request:
  an empty/invalid vm_id would otherwise also 404 (no route match) and the
  two would be indistinguishable.
- non-2xx bodies are CBOR, not JSON — they must never be JSON-decoded.

These patch only `effects._http`, so the real effect body runs.
"""

from __future__ import annotations

import json
from typing import Any

import pytest

from apps.orchestration import effects


@pytest.fixture
def http(monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    """Capture the single HTTP round-trip; `status`/`body` steer the reply."""
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
        state["calls"].append(
            {"method": method, "url": url, "json": json_body, "context": context}
        )
        return state["status"], state["body"]

    monkeypatch.setattr(effects, "_http", fake_http)
    return state


def _ok_body(counter: int, previous: int = 0) -> bytes:
    return json.dumps({"v": 1, "vm_id": "vm-a", "previous": previous, "counter": counter}).encode()


def test_a_200_posts_the_counter_to_the_admin_route(http: dict[str, Any]) -> None:
    http["body"] = _ok_body(5)
    res = effects.seed_boot_counter("vm-a", counter=5)

    assert res == effects.SeedBootCounterOk(counter=5, previous=0, already_recovered=False)
    call = http["calls"][0]
    assert call["method"] == "POST"
    assert call["url"] == "http://kbs.test/v1/admin/vm/vm-a/seed-boot-counter"
    assert call["json"] == {"counter": 5}


def test_a_404_is_a_distinct_route_missing_error(http: dict[str, Any]) -> None:
    http["status"] = 404
    with pytest.raises(effects.KbsRouteMissing):
        effects.seed_boot_counter("vm-a", counter=5)


def test_a_409_is_reported_as_already_recovered_not_a_failure(
    http: dict[str, Any],
) -> None:
    # The body is CBOR here — a JSON decode would raise, so this also pins
    # that the 409 path never parses the body.
    http["status"] = 409
    http["body"] = b"\xa1\x66reason\x76seed-already-recovered"
    res = effects.seed_boot_counter("vm-a", counter=5)
    assert res.already_recovered is True


@pytest.mark.parametrize("status", [413, 429, 500])
def test_other_non_2xx_statuses_fail_without_decoding_the_cbor_body(
    http: dict[str, Any], status: int
) -> None:
    http["status"] = status
    http["body"] = b"\xa1\x66reason\x6ccounter-zero"
    with pytest.raises(effects.EffectError, match=f"HTTP {status}"):
        effects.seed_boot_counter("vm-a", counter=5)


def test_a_400_is_a_distinct_contract_mismatch(http: dict[str, Any]) -> None:
    # Every client-side precondition here exists to make a 400 unreachable,
    # so one means vali and the deployed KBS disagree about the contract
    # (e.g. the server lowered its cap below ours). The caller must abort the
    # run rather than iterate — hence its own type, not a bare EffectError.
    http["status"] = 400
    http["body"] = b"\xa1\x66reason\x6eseed-above-cap"
    with pytest.raises(effects.KbsAdminContractMismatch, match="ABORT"):
        effects.seed_boot_counter("vm-a", counter=5)


@pytest.mark.parametrize("vm_id", ["", "VM-A", "vm/a", "../x", "a" * 65])
def test_an_invalid_vm_id_is_refused_before_the_request(http: dict[str, Any], vm_id: str) -> None:
    # Otherwise an empty/invalid vm_id 404s at the router and would be
    # misreported as "the route is not deployed".
    with pytest.raises(effects.EffectError, match="charset lock"):
        effects.seed_boot_counter(vm_id, counter=5)
    assert http["calls"] == []


@pytest.mark.parametrize("counter", [0, -1])
def test_a_non_positive_counter_never_leaves_vali(http: dict[str, Any], counter: int) -> None:
    with pytest.raises(effects.EffectError, match="counter-zero"):
        effects.seed_boot_counter("vm-a", counter=counter)
    assert http["calls"] == []


def test_a_counter_above_the_cap_never_leaves_vali(http: dict[str, Any]) -> None:
    with pytest.raises(effects.EffectError, match="seed-above-cap"):
        effects.seed_boot_counter("vm-a", counter=effects.MAX_SEED_COUNTER + 1)
    assert http["calls"] == []


def test_the_cap_itself_is_accepted(http: dict[str, Any]) -> None:
    http["body"] = _ok_body(effects.MAX_SEED_COUNTER)
    res = effects.seed_boot_counter("vm-a", counter=effects.MAX_SEED_COUNTER)
    assert res.counter == effects.MAX_SEED_COUNTER


def test_a_200_without_a_counter_field_is_a_failure(http: dict[str, Any]) -> None:
    http["body"] = b'{"v":1,"vm_id":"vm-a"}'
    with pytest.raises(effects.EffectError, match="missing `counter`"):
        effects.seed_boot_counter("vm-a", counter=5)
