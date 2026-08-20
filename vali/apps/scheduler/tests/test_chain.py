"""Tests for `chain.read_miner_status` — the `read-miner-status`
shell-out wrapper.

A fake binary (a tiny generated Python script) stands in for the
Rust validator so the suite is fast + Cargo-independent. The fake
also records its argv + environment so the "RPC URL never lands in
argv" property is asserted directly.
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest import mock

import pytest
from django.conf import settings

from apps.scheduler import chain

# `read_miner_status` only touches settings + a subprocess — no DB.
RPC_URL = "http://thebrain.test:9933"

_OK_PAYLOAD = {
    "tag": "ok",
    "current_epoch": 12,
    "miners": [
        {
            "node_id_hex": "aa" * 32,
            "status": "active",
            "last_transition_epoch": 9,
            "data_epoch": 12,
            "quality_dec": "340282366920938463463374607431768211455",
        },
        {
            "node_id_hex": "bb" * 32,
            "status": "quarantined",
            "last_transition_epoch": 11,
            "data_epoch": 11,
            "quality_dec": "0",
        },
    ],
}


def _fake_binary(
    tmp_path: Path,
    *,
    stdout: str,
    exit_code: int = 0,
    record_path: Path | None = None,
) -> Path:
    """Write an executable fake `hippius-ticket-validator`.

    Emits `stdout`, exits `exit_code`. If `record_path` is given the
    fake first dumps its argv + `THEBRAIN_RPC_URL` env var there.
    """
    lines = ["#!/usr/bin/env python3", "import sys, os, json"]
    if record_path is not None:
        lines.append(
            f"open({str(record_path)!r}, 'w').write(json.dumps("
            "{'argv': sys.argv, "
            "'thebrain_rpc_url': os.environ.get('THEBRAIN_RPC_URL')}))"
        )
    lines.append(f"sys.stdout.write({stdout!r})")
    lines.append(f"sys.exit({exit_code})")
    path = tmp_path / "hippius-ticket-validator"
    path.write_text("\n".join(lines) + "\n")
    path.chmod(0o755)
    return path


def _use_binary(monkeypatch: pytest.MonkeyPatch, path: Path) -> None:
    monkeypatch.setattr(settings, "VALI_TICKET_VALIDATOR_BIN", str(path))


# ─── Happy path ──────────────────────────────────────────────────────


def test_read_ok_parses_snapshot(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _use_binary(monkeypatch, _fake_binary(tmp_path, stdout=json.dumps(_OK_PAYLOAD)))
    snapshot = chain.read_miner_status()
    assert snapshot.current_epoch == 12
    assert len(snapshot.miners) == 2
    first = snapshot.miners[0]
    assert first.node_id == "aa" * 32
    assert first.status == "active"
    assert first.data_epoch == 12
    # `quality_dec` is a u128 decimal string — rehydrated to a Python int.
    assert first.quality == 340282366920938463463374607431768211455
    assert snapshot.miners[1].status == "quarantined"


def test_read_ok_with_no_miners(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    payload = {"tag": "ok", "current_epoch": 3, "miners": []}
    _use_binary(monkeypatch, _fake_binary(tmp_path, stdout=json.dumps(payload)))
    snapshot = chain.read_miner_status()
    assert snapshot.current_epoch == 3
    assert snapshot.miners == ()


# ─── Fail-closed paths ───────────────────────────────────────────────


def test_structured_error_envelope_raises_unavailable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    err = {"tag": "err", "error": "node unreachable", "category": "rpc-request"}
    _use_binary(
        monkeypatch,
        _fake_binary(tmp_path, stdout=json.dumps(err), exit_code=2),
    )
    with pytest.raises(chain.ChainReadUnavailable) as exc:
        chain.read_miner_status()
    assert "rpc-request" in str(exc.value)


def test_internal_exit_code_raises_unavailable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _use_binary(monkeypatch, _fake_binary(tmp_path, stdout="", exit_code=1))
    with pytest.raises(chain.ChainReadUnavailable):
        chain.read_miner_status()


def test_non_json_stdout_raises_unavailable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _use_binary(monkeypatch, _fake_binary(tmp_path, stdout="this is not json"))
    with pytest.raises(chain.ChainReadUnavailable):
        chain.read_miner_status()


def test_missing_rpc_url_raises_without_spawning(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # An empty RPC URL must fail closed BEFORE any subprocess spawn.
    monkeypatch.setattr(settings, "VALI_THEBRAIN_RPC_URL", "")
    _use_binary(monkeypatch, _fake_binary(tmp_path, stdout=json.dumps(_OK_PAYLOAD)))
    with pytest.raises(chain.ChainReadUnavailable) as exc:
        chain.read_miner_status()
    assert "VALI_THEBRAIN_RPC_URL" in str(exc.value)


def test_missing_binary_raises_unavailable(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _use_binary(monkeypatch, tmp_path / "does-not-exist")
    with pytest.raises(chain.ChainReadUnavailable):
        chain.read_miner_status()


def test_schema_drift_in_ok_payload_raises_unavailable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # `current_epoch` missing — a Rust/Python schema disagreement is
    # still fail-closed (503), never a silent placement.
    bad = {"tag": "ok", "miners": []}
    _use_binary(monkeypatch, _fake_binary(tmp_path, stdout=json.dumps(bad)))
    with pytest.raises(chain.ChainReadUnavailable):
        chain.read_miner_status()


# ─── §20: the RPC URL is passed via env, never argv ──────────────────


def test_rpc_url_is_passed_via_env_not_argv(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    record = tmp_path / "record.json"
    _use_binary(
        monkeypatch,
        _fake_binary(
            tmp_path,
            stdout=json.dumps(_OK_PAYLOAD),
            record_path=record,
        ),
    )
    chain.read_miner_status()

    captured = json.loads(record.read_text())
    # The URL reaches the binary through the environment …
    assert captured["thebrain_rpc_url"] == RPC_URL
    # … and is absent from every argv token (no `ps` leak — §20).
    assert all(RPC_URL not in arg for arg in captured["argv"])
    assert "--pallet-name" in captured["argv"]


# ─── Removed-pallet (orphaned storage prefix) detection ──────────────
#
# The failure: a runtime upgrade drops `pallet-compute-scoring` but not
# its storage, so the twox-128-derived reads keep returning the pallet's
# last-written bytes forever. `read-miner-status` reports `ok` every 30 s
# against a fossil. `pallet_live` is the only field that can tell.


def _payload(**overrides: object) -> dict:
    """The `ok` envelope with no miners, plus overrides."""
    return {"tag": "ok", "current_epoch": 2702, "miners": [], **overrides}


def test_the_pallet_live_gate_ships_disabled() -> None:
    # The whole change is safe to deploy ONLY because this default is
    # False: vali is placing production workloads off the fossil read
    # right now, and flipping it closed on deploy would stop every
    # placement and empty the Edge admission feed. Arming it is an
    # operator action, taken once the chain side is resolved.
    from vali import settings as vali_settings

    assert vali_settings.VALI_CHAIN_REQUIRE_PALLET_LIVE is False


def test_absent_pallet_live_key_defaults_true(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # SKEW SAFETY: an OLDER validator binary emits no `pallet_live`. A
    # vali/validator version skew must never fabricate a fossil alarm —
    # absent reads as True, i.e. exactly today's behaviour.
    payload = _payload()
    assert "pallet_live" not in payload
    _use_binary(monkeypatch, _fake_binary(tmp_path, stdout=json.dumps(payload)))
    snapshot = chain.read_miner_status()
    assert snapshot.pallet_live is True


def test_pallet_live_false_logs_error_and_still_returns_the_snapshot(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # With the gate OFF (the default) the fossil is LOUD but not fatal:
    # placement keeps running exactly as it does in production today.
    #
    # Asserts on the logger call rather than via caplog: the project sets
    # `propagate: False` on the `apps` logger, so caplog's root handler
    # never sees the record.
    monkeypatch.setattr(settings, "VALI_CHAIN_REQUIRE_PALLET_LIVE", False)
    _use_binary(
        monkeypatch,
        _fake_binary(tmp_path, stdout=json.dumps(_payload(pallet_live=False))),
    )
    with mock.patch.object(chain.log, "error") as logged:
        snapshot = chain.read_miner_status()

    assert snapshot.pallet_live is False
    assert snapshot.current_epoch == 2702
    assert logged.call_count == 1, "exactly one ERROR per call"
    # The message must name the failure precisely — an operator reading
    # it should not need this diff to understand what is wrong.
    rendered = logged.call_args.args[0] % logged.call_args.args[1:]
    assert "metadata" in rendered
    assert "ComputeScoring" in rendered
    assert "2702" in rendered


def test_pallet_live_true_logs_no_error(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # The alarm must not fire on a healthy chain, or it is noise.
    _use_binary(
        monkeypatch,
        _fake_binary(tmp_path, stdout=json.dumps(_payload(pallet_live=True))),
    )
    with mock.patch.object(chain.log, "error") as logged:
        snapshot = chain.read_miner_status()
    assert snapshot.pallet_live is True
    assert logged.call_count == 0


def test_pallet_live_false_fails_closed_when_the_operator_arms_the_gate(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # The operator's switch: same fossil payload, gate ON ⇒ hard 503.
    monkeypatch.setattr(settings, "VALI_CHAIN_REQUIRE_PALLET_LIVE", True)
    _use_binary(
        monkeypatch,
        _fake_binary(tmp_path, stdout=json.dumps(_payload(pallet_live=False))),
    )
    with pytest.raises(chain.ChainReadUnavailable) as exc:
        chain.read_miner_status()
    assert "metadata" in str(exc.value)


def test_pallet_live_true_is_unaffected_by_the_armed_gate(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Arming the gate must not break a healthy read.
    monkeypatch.setattr(settings, "VALI_CHAIN_REQUIRE_PALLET_LIVE", True)
    _use_binary(
        monkeypatch,
        _fake_binary(tmp_path, stdout=json.dumps(_payload(pallet_live=True))),
    )
    assert chain.read_miner_status().pallet_live is True


@pytest.mark.parametrize("value", [1, 0, "false", "true", None, [], {}])
def test_non_bool_pallet_live_raises_unavailable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, value: object
) -> None:
    # Shape drift fails closed. Notably `0`/`1` and `"false"` must NOT be
    # truthiness-cast into a health claim — a wrong claim about whether
    # the chain is live is worse than no read at all.
    _use_binary(
        monkeypatch,
        _fake_binary(tmp_path, stdout=json.dumps(_payload(pallet_live=value))),
    )
    with pytest.raises(chain.ChainReadUnavailable) as exc:
        chain.read_miner_status()
    assert "pallet_live" in str(exc.value)
