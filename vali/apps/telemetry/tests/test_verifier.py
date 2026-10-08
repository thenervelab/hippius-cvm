"""Shell-out wrapper tests for `apps.telemetry.verifier`.

Same pattern as `apps.lifecycle.tests.test_validator`: mock tests
(always run) + a real-binary smoke test (auto-skip if the Rust
binary is absent).

The telemetry suite's autouse `fake_verifier` fixture monkeypatches
`verifier.verify_envelope` away — these tests want the *real*
wrapper, so they capture it at import time (before any fixture runs)
and call that reference directly.
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import Any

import pytest
from django.conf import settings

from apps.telemetry import verifier
from apps.telemetry.models import EnvelopeKind

# Captured before the autouse `fake_verifier` fixture can swap it.
_REAL_VERIFY = verifier.verify_envelope


def _stub_completed(
    stdout: bytes, returncode: int, stderr: bytes = b""
) -> subprocess.CompletedProcess:
    return subprocess.CompletedProcess(
        args=["bin", "verify-edge-telemetry"],
        returncode=returncode,
        stdout=stdout,
        stderr=stderr,
    )


@pytest.fixture
def fake_binary(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    fake = tmp_path / "hippius-ticket-validator"
    fake.write_text("# placeholder\n")
    fake.chmod(0o755)
    monkeypatch.setattr(settings, "VALI_TICKET_VALIDATOR_BIN", str(fake))
    return fake


def _kwargs(**override: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "kind": EnvelopeKind.EDGE_TELEMETRY.value,
        "body": b"canonical-cbor-telemetry-body",
        "sig": b"\x00" * 64,
        "verifying_key": b"\x11" * 32,
    }
    base.update(override)
    return base


# ─── pre-spawn gates ─────────────────────────────────────────────────


def test_unknown_kind_raises_unavailable() -> None:
    # An unmapped kind has no subcommand — refused before any spawn.
    with pytest.raises(verifier.VerifierUnavailable, match="no verifier subcommand"):
        _REAL_VERIFY(**_kwargs(kind="bogus_kind"))


def test_missing_binary_raises_unavailable(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(
        settings,
        "VALI_TICKET_VALIDATOR_BIN",
        str(tmp_path / "does-not-exist"),
    )
    with pytest.raises(verifier.VerifierUnavailable, match="not found"):
        _REAL_VERIFY(**_kwargs())


def test_empty_body_short_circuits_to_failed(fake_binary: Path) -> None:
    # An empty body is rejected WITHOUT spawning, with the same
    # `decode` category the binary would have reported.
    with pytest.raises(verifier.VerifierFailed) as exc_info:
        _REAL_VERIFY(**_kwargs(body=b""))
    assert exc_info.value.category == "decode"


# ─── verdict mapping ─────────────────────────────────────────────────


def test_ok_exit_returns_none(
    monkeypatch: pytest.MonkeyPatch, fake_binary: Path
) -> None:
    monkeypatch.setattr(
        subprocess,
        "run",
        lambda *a, **kw: _stub_completed(json.dumps({"tag": "ok"}).encode(), 0),
    )
    assert _REAL_VERIFY(**_kwargs()) is None


def test_err_exit_two_raises_verifier_failed(
    monkeypatch: pytest.MonkeyPatch, fake_binary: Path
) -> None:
    err = {"tag": "err", "error": "bad signature", "category": "signature"}
    monkeypatch.setattr(
        subprocess,
        "run",
        lambda *a, **kw: _stub_completed(json.dumps(err).encode(), 2),
    )
    with pytest.raises(verifier.VerifierFailed) as exc_info:
        _REAL_VERIFY(**_kwargs())
    assert exc_info.value.category == "signature"
    assert exc_info.value.message == "bad signature"


def test_internal_exit_one_raises_unavailable(
    monkeypatch: pytest.MonkeyPatch, fake_binary: Path
) -> None:
    monkeypatch.setattr(
        subprocess,
        "run",
        lambda *a, **kw: _stub_completed(b"", 1, stderr=b"oh no"),
    )
    with pytest.raises(verifier.VerifierUnavailable, match="exited with code 1"):
        _REAL_VERIFY(**_kwargs())


def test_non_json_stdout_raises_unavailable(
    monkeypatch: pytest.MonkeyPatch, fake_binary: Path
) -> None:
    monkeypatch.setattr(
        subprocess,
        "run",
        lambda *a, **kw: _stub_completed(b"not json at all", 0),
    )
    with pytest.raises(verifier.VerifierUnavailable, match="not JSON"):
        _REAL_VERIFY(**_kwargs())


def test_stdout_missing_tag_raises_unavailable(
    monkeypatch: pytest.MonkeyPatch, fake_binary: Path
) -> None:
    monkeypatch.setattr(
        subprocess,
        "run",
        lambda *a, **kw: _stub_completed(json.dumps({"no": "tag"}).encode(), 0),
    )
    with pytest.raises(verifier.VerifierUnavailable, match="missing 'tag'"):
        _REAL_VERIFY(**_kwargs())


def test_unknown_tag_raises_unavailable(
    monkeypatch: pytest.MonkeyPatch, fake_binary: Path
) -> None:
    monkeypatch.setattr(
        subprocess,
        "run",
        lambda *a, **kw: _stub_completed(json.dumps({"tag": "maybe"}).encode(), 0),
    )
    with pytest.raises(verifier.VerifierUnavailable, match="unknown tag"):
        _REAL_VERIFY(**_kwargs())


def test_timeout_raises_unavailable(
    monkeypatch: pytest.MonkeyPatch, fake_binary: Path
) -> None:
    def _raise(*_a: Any, **_kw: Any) -> None:
        raise subprocess.TimeoutExpired(cmd="bin", timeout=0.1)

    monkeypatch.setattr(subprocess, "run", _raise)
    with pytest.raises(verifier.VerifierUnavailable, match="timed out"):
        _REAL_VERIFY(**_kwargs())


def test_spawn_oserror_raises_unavailable(
    monkeypatch: pytest.MonkeyPatch, fake_binary: Path
) -> None:
    def _raise(*_a: Any, **_kw: Any) -> None:
        raise OSError("exec format error")

    monkeypatch.setattr(subprocess, "run", _raise)
    with pytest.raises(verifier.VerifierUnavailable, match="spawn failed"):
        _REAL_VERIFY(**_kwargs())


# ─── argv / stdin contract ───────────────────────────────────────────


def test_argv_carries_only_public_material_body_rides_stdin(
    monkeypatch: pytest.MonkeyPatch, fake_binary: Path
) -> None:
    """The wrapper builds the argv list; the binary's `clap` parser
    needs the exact flag spellings. Pin the argv shape so a typo here
    flips a test instead of surfacing as a cryptic clap parse error.

    Also asserts the parser-hardening contract: the hostile-origin
    `body` is piped via stdin, never spliced into argv.
    """
    captured: dict[str, Any] = {}

    def _capture(argv: list[str], **kwargs: Any) -> subprocess.CompletedProcess:
        captured["argv"] = argv
        captured["input"] = kwargs.get("input")
        return _stub_completed(json.dumps({"tag": "ok"}).encode(), 0)

    monkeypatch.setattr(subprocess, "run", _capture)
    body = b"the-canonical-cbor-body"
    _REAL_VERIFY(**_kwargs(body=body))

    argv = captured["argv"]
    assert "verify-edge-telemetry" in argv
    assert "--vk-hex" in argv
    assert "--sig-hex" in argv
    # argv carries only PUBLIC crypto material — the vk + the sig.
    assert ("11" * 32) in argv
    assert ("00" * 64) in argv
    # The body is piped on stdin, NEVER placed on argv.
    assert captured["input"] == body
    assert body.hex() not in argv
    assert all(body.hex() not in arg for arg in argv)


def test_served_receipt_kind_selects_its_subcommand(
    monkeypatch: pytest.MonkeyPatch, fake_binary: Path
) -> None:
    captured: dict[str, Any] = {}

    def _capture(argv: list[str], **kwargs: Any) -> subprocess.CompletedProcess:
        captured["argv"] = argv
        return _stub_completed(json.dumps({"tag": "ok"}).encode(), 0)

    monkeypatch.setattr(subprocess, "run", _capture)
    _REAL_VERIFY(**_kwargs(kind=EnvelopeKind.SERVED_RECEIPT.value))
    assert "verify-served-receipt" in captured["argv"]


# ─── real-binary integration ─────────────────────────────────────────


_REAL_BIN = Path(settings.VALI_TICKET_VALIDATOR_BIN)
_KNOWN_CATEGORIES = {"decode", "non-canonical", "signature", "cbor", "domain"}


@pytest.mark.skipif(
    not _REAL_BIN.is_file(),
    reason=(
        f"Rust validator not built at {_REAL_BIN} — run "
        "`cargo build -p hippius-ticket-validator --release`"
    ),
)
def test_real_binary_rejects_garbage_telemetry() -> None:
    """End-to-end smoke: pipe obviously-bad bytes through the real
    `verify-edge-telemetry`. Expect a structured rejection, not a
    crash (`VerifierFailed`, not `VerifierUnavailable`).
    """
    with pytest.raises(verifier.VerifierFailed) as exc_info:
        _REAL_VERIFY(**_kwargs(body=b"\xff\xff\xff\xff"))
    assert exc_info.value.category in _KNOWN_CATEGORIES


# ─── verify_heartbeat wrapper (§K / PR-Part4-B) ───────────────────────
#
# The data-bearing `verify-heartbeat` shell-out: a SEPARATE contract
# from `verify_envelope` — the whole envelope rides stdin, only
# `--vk-hex` on argv, and a success returns the decoded body.

_HEARTBEAT_OK_BODY = {
    "schema_version": 1,
    "domain": "HIPPIUS_MINER_HEARTBEAT_V1",
    "miner_id": "miner-a",
    "timestamp_unix": 1_700_000_000,
    "sequence": 42,
}


def _hb_kwargs(**override: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "envelope": b"canonical-cbor-signed-heartbeat",
        "verifying_key": b"\x11" * 32,
    }
    base.update(override)
    return base


def test_heartbeat_ok_returns_the_decoded_body(
    monkeypatch: pytest.MonkeyPatch, fake_binary: Path
) -> None:
    monkeypatch.setattr(
        subprocess,
        "run",
        lambda *a, **kw: _stub_completed(
            json.dumps({"ok": True, "body": _HEARTBEAT_OK_BODY}).encode(), 0
        ),
    )
    hb = verifier.verify_heartbeat(**_hb_kwargs())
    assert hb.miner_id == "miner-a"
    assert hb.sequence == 42
    assert hb.timestamp_unix == 1_700_000_000
    assert hb.schema_version == 1
    # The v1 body carries NO `graceful_exit_requested` key — it parses
    # with the backward-compatible False default (a v1-era verifier
    # output still deserialises unchanged).
    assert hb.graceful_exit_requested is False


def test_heartbeat_v2_body_parses_the_graceful_exit_flag(
    monkeypatch: pytest.MonkeyPatch, fake_binary: Path
) -> None:
    # A v2 verifier body carries the flag — it is parsed onto
    # `HeartbeatBody.graceful_exit_requested`.
    body = {**_HEARTBEAT_OK_BODY, "schema_version": 2, "graceful_exit_requested": True}
    monkeypatch.setattr(
        subprocess,
        "run",
        lambda *a, **kw: _stub_completed(
            json.dumps({"ok": True, "body": body}).encode(), 0
        ),
    )
    hb = verifier.verify_heartbeat(**_hb_kwargs())
    assert hb.schema_version == 2
    assert hb.graceful_exit_requested is True


def test_heartbeat_parses_reported_free_memory(
    monkeypatch: pytest.MonkeyPatch, fake_binary: Path
) -> None:
    # The accept body echoes `memory_available_mib` — parsed onto the
    # dataclass for the DOWN-only dynamic-capacity throttle.
    body = {**_HEARTBEAT_OK_BODY, "memory_available_mib": 94_000}
    monkeypatch.setattr(
        subprocess,
        "run",
        lambda *a, **kw: _stub_completed(
            json.dumps({"ok": True, "body": body}).encode(), 0
        ),
    )
    hb = verifier.verify_heartbeat(**_hb_kwargs())
    assert hb.memory_available_mib == 94_000


def test_heartbeat_absent_memory_is_none(
    monkeypatch: pytest.MonkeyPatch, fake_binary: Path
) -> None:
    # A body with no metrics (e.g. the 5-field graceful-exit body) → None,
    # so the shared decoder stays backward-compatible.
    monkeypatch.setattr(
        subprocess,
        "run",
        lambda *a, **kw: _stub_completed(
            json.dumps({"ok": True, "body": _HEARTBEAT_OK_BODY}).encode(), 0
        ),
    )
    hb = verifier.verify_heartbeat(**_hb_kwargs())
    assert hb.memory_available_mib is None


def test_heartbeat_negative_memory_raises_unavailable(
    monkeypatch: pytest.MonkeyPatch, fake_binary: Path
) -> None:
    # A negative metric means the binary's contract drifted (u32 on the
    # wire) — vali-side VerifierUnavailable, not a miner fault.
    body = {**_HEARTBEAT_OK_BODY, "memory_available_mib": -1}
    monkeypatch.setattr(
        subprocess,
        "run",
        lambda *a, **kw: _stub_completed(
            json.dumps({"ok": True, "body": body}).encode(), 0
        ),
    )
    with pytest.raises(verifier.VerifierUnavailable):
        verifier.verify_heartbeat(**_hb_kwargs())


def test_heartbeat_non_bool_flag_raises_unavailable(
    monkeypatch: pytest.MonkeyPatch, fake_binary: Path
) -> None:
    # The flag MUST be a genuine JSON bool — a non-bool means the
    # binary's contract drifted (vali-side: VerifierUnavailable).
    body = {**_HEARTBEAT_OK_BODY, "graceful_exit_requested": 1}
    monkeypatch.setattr(
        subprocess,
        "run",
        lambda *a, **kw: _stub_completed(
            json.dumps({"ok": True, "body": body}).encode(), 0
        ),
    )
    with pytest.raises(verifier.VerifierUnavailable):
        verifier.verify_heartbeat(**_hb_kwargs())


_V3_CAPACITY = {
    "cvm_cpu_budget": 44,
    "cvm_memory_mb_budget": 120_000,
    "asid_capacity": 99,
    "asid_used": 2,
}


def _stub_heartbeat_body(monkeypatch: pytest.MonkeyPatch, body: dict[str, Any]) -> None:
    monkeypatch.setattr(
        subprocess,
        "run",
        lambda *a, **kw: _stub_completed(
            json.dumps({"ok": True, "body": body}).encode(), 0
        ),
    )


def test_heartbeat_v3_body_parses_the_capacity_declaration(
    monkeypatch: pytest.MonkeyPatch, fake_binary: Path
) -> None:
    body = {
        **_HEARTBEAT_OK_BODY,
        "schema_version": 3,
        "graceful_exit_requested": False,
        **_V3_CAPACITY,
    }
    _stub_heartbeat_body(monkeypatch, body)
    hb = verifier.verify_heartbeat(**_hb_kwargs())
    assert hb.declared_capacity == verifier.DeclaredCapacity(
        cvm_cpu_budget=44, cvm_memory_mb_budget=120_000, asid_capacity=99, asid_used=2
    )


def test_heartbeat_v3_zero_capacity_is_parsed_raw(
    monkeypatch: pytest.MonkeyPatch, fake_binary: Path
) -> None:
    # `0` (unknown) is carried raw here; the ingest maps it to NULL.
    body = {**_HEARTBEAT_OK_BODY, "schema_version": 3, **dict.fromkeys(_V3_CAPACITY, 0)}
    _stub_heartbeat_body(monkeypatch, body)
    hb = verifier.verify_heartbeat(**_hb_kwargs())
    assert hb.declared_capacity == verifier.DeclaredCapacity(0, 0, 0, 0)


@pytest.mark.parametrize("schema_version", [1, 2])
def test_heartbeat_pre_v3_body_has_no_capacity_declaration(
    monkeypatch: pytest.MonkeyPatch, fake_binary: Path, schema_version: int
) -> None:
    _stub_heartbeat_body(monkeypatch, {**_HEARTBEAT_OK_BODY, "schema_version": schema_version})
    assert verifier.verify_heartbeat(**_hb_kwargs()).declared_capacity is None


@pytest.mark.parametrize("missing", sorted(_V3_CAPACITY))
def test_heartbeat_partial_capacity_declaration_raises_unavailable(
    monkeypatch: pytest.MonkeyPatch, fake_binary: Path, missing: str
) -> None:
    capacity = {k: v for k, v in _V3_CAPACITY.items() if k != missing}
    _stub_heartbeat_body(monkeypatch, {**_HEARTBEAT_OK_BODY, "schema_version": 3, **capacity})
    with pytest.raises(verifier.VerifierUnavailable, match="partial"):
        verifier.verify_heartbeat(**_hb_kwargs())


@pytest.mark.parametrize("bad", [-1, True, "4", None])
def test_heartbeat_malformed_capacity_value_raises_unavailable(
    monkeypatch: pytest.MonkeyPatch, fake_binary: Path, bad: object
) -> None:
    body = {**_HEARTBEAT_OK_BODY, "schema_version": 3, **_V3_CAPACITY, "asid_used": bad}
    _stub_heartbeat_body(monkeypatch, body)
    with pytest.raises(verifier.VerifierUnavailable):
        verifier.verify_heartbeat(**_hb_kwargs())


_V4_DISK = {
    "cvm_disk_gb_budget": 3000,
    "data_disk_total_gb": 3500,
    "data_disk_available_gb": 3200,
    "staging_disk_available_gb": 400,
}


def test_heartbeat_v4_body_parses_the_disk_figures(
    monkeypatch: pytest.MonkeyPatch, fake_binary: Path
) -> None:
    body = {**_HEARTBEAT_OK_BODY, "schema_version": 4, **_V3_CAPACITY, **_V4_DISK}
    _stub_heartbeat_body(monkeypatch, body)
    hb = verifier.verify_heartbeat(**_hb_kwargs())
    assert hb.schema_version == 4
    assert hb.declared_capacity == verifier.DeclaredCapacity(44, 120_000, 99, 2)
    assert hb.declared_disk == verifier.DeclaredDisk(
        cvm_disk_gb_budget=3000,
        data_disk_total_gb=3500,
        data_disk_available_gb=3200,
        staging_disk_available_gb=400,
    )


@pytest.mark.parametrize("schema_version", [1, 2, 3])
def test_heartbeat_pre_v4_body_has_no_disk_figures(
    monkeypatch: pytest.MonkeyPatch, fake_binary: Path, schema_version: int
) -> None:
    extra = _V3_CAPACITY if schema_version == 3 else {}
    _stub_heartbeat_body(
        monkeypatch, {**_HEARTBEAT_OK_BODY, "schema_version": schema_version, **extra}
    )
    assert verifier.verify_heartbeat(**_hb_kwargs()).declared_disk is None


@pytest.mark.parametrize("missing", sorted(_V4_DISK))
def test_heartbeat_partial_disk_figures_raise_unavailable(
    monkeypatch: pytest.MonkeyPatch, fake_binary: Path, missing: str
) -> None:
    disk = {k: v for k, v in _V4_DISK.items() if k != missing}
    body = {**_HEARTBEAT_OK_BODY, "schema_version": 4, **_V3_CAPACITY, **disk}
    _stub_heartbeat_body(monkeypatch, body)
    with pytest.raises(verifier.VerifierUnavailable, match="partial disk"):
        verifier.verify_heartbeat(**_hb_kwargs())


@pytest.mark.parametrize("bad", [-1, True, "4", None])
def test_heartbeat_malformed_disk_value_raises_unavailable(
    monkeypatch: pytest.MonkeyPatch, fake_binary: Path, bad: object
) -> None:
    body = {
        **_HEARTBEAT_OK_BODY,
        "schema_version": 4,
        **_V3_CAPACITY,
        **_V4_DISK,
        "data_disk_available_gb": bad,
    }
    _stub_heartbeat_body(monkeypatch, body)
    with pytest.raises(verifier.VerifierUnavailable):
        verifier.verify_heartbeat(**_hb_kwargs())


_V5_HOST_HEALTH = {
    "snp_enabled": True,
    "cpus_offline": 24,
    "snp_launches_since_boot": 97,
    "df_flush_failures": 3,
}


def _v5_body(**overrides: object) -> dict[str, object]:
    return {
        **_HEARTBEAT_OK_BODY,
        "schema_version": 5,
        **_V3_CAPACITY,
        **_V4_DISK,
        **_V5_HOST_HEALTH,
        **overrides,
    }


def test_heartbeat_v5_body_parses_the_host_health_report(
    monkeypatch: pytest.MonkeyPatch, fake_binary: Path
) -> None:
    _stub_heartbeat_body(monkeypatch, _v5_body())
    hb = verifier.verify_heartbeat(**_hb_kwargs())
    assert hb.schema_version == 5
    assert hb.declared_disk is not None
    assert hb.declared_host_health == verifier.DeclaredHostHealth(
        snp_enabled=True,
        cpus_offline=24,
        snp_launches_since_boot=97,
        df_flush_failures=3,
    )


@pytest.mark.parametrize("schema_version", [1, 3, 4])
def test_heartbeat_pre_v5_body_has_no_host_health_report(
    monkeypatch: pytest.MonkeyPatch, fake_binary: Path, schema_version: int
) -> None:
    extra: dict[str, object] = {}
    if schema_version >= 3:
        extra.update(_V3_CAPACITY)
    if schema_version == 4:
        extra.update(_V4_DISK)
    _stub_heartbeat_body(
        monkeypatch, {**_HEARTBEAT_OK_BODY, "schema_version": schema_version, **extra}
    )
    assert verifier.verify_heartbeat(**_hb_kwargs()).declared_host_health is None


@pytest.mark.parametrize("missing", sorted(_V5_HOST_HEALTH))
def test_heartbeat_partial_host_health_report_raises_unavailable(
    monkeypatch: pytest.MonkeyPatch, fake_binary: Path, missing: str
) -> None:
    body = _v5_body()
    del body[missing]
    _stub_heartbeat_body(monkeypatch, body)
    with pytest.raises(verifier.VerifierUnavailable, match="partial host-health"):
        verifier.verify_heartbeat(**_hb_kwargs())


@pytest.mark.parametrize(
    "field,bad",
    [
        ("snp_enabled", 1),
        ("snp_enabled", None),
        ("cpus_offline", -1),
        ("cpus_offline", True),
        ("df_flush_failures", "3"),
        ("snp_launches_since_boot", None),
    ],
)
def test_heartbeat_malformed_host_health_value_raises_unavailable(
    monkeypatch: pytest.MonkeyPatch, fake_binary: Path, field: str, bad: object
) -> None:
    _stub_heartbeat_body(monkeypatch, _v5_body(**{field: bad}))
    with pytest.raises(verifier.VerifierUnavailable):
        verifier.verify_heartbeat(**_hb_kwargs())


def _v6_body(**overrides: object) -> dict[str, object]:
    return {**_v5_body(), "schema_version": 6, "agent_version": "v2026.10.08", **overrides}


def test_heartbeat_v6_body_parses_the_agent_version(
    monkeypatch: pytest.MonkeyPatch, fake_binary: Path
) -> None:
    _stub_heartbeat_body(monkeypatch, _v6_body())
    hb = verifier.verify_heartbeat(**_hb_kwargs())
    assert hb.schema_version == 6
    assert hb.agent_version == "v2026.10.08"
    assert hb.declared_host_health is not None
    assert hb.declared_disk is not None


@pytest.mark.parametrize("tag", ["dev", "A", "x" * 32, "v1.2.3-rc_1"])
def test_heartbeat_v6_accepts_the_full_charset(
    monkeypatch: pytest.MonkeyPatch, fake_binary: Path, tag: str
) -> None:
    _stub_heartbeat_body(monkeypatch, _v6_body(agent_version=tag))
    assert verifier.verify_heartbeat(**_hb_kwargs()).agent_version == tag


def test_heartbeat_pre_v6_body_has_no_agent_version(
    monkeypatch: pytest.MonkeyPatch, fake_binary: Path
) -> None:
    _stub_heartbeat_body(monkeypatch, _v5_body())
    assert verifier.verify_heartbeat(**_hb_kwargs()).agent_version is None


@pytest.mark.parametrize(
    "bad", ["", "x" * 33, "v1 2", "v1/2", "v1\n", "é", "v1\x1b[31m", None, 6, True]
)
def test_heartbeat_malformed_agent_version_raises_unavailable(
    monkeypatch: pytest.MonkeyPatch, fake_binary: Path, bad: object
) -> None:
    _stub_heartbeat_body(monkeypatch, _v6_body(agent_version=bad))
    with pytest.raises(verifier.VerifierUnavailable, match="agent_version"):
        verifier.verify_heartbeat(**_hb_kwargs())


def test_heartbeat_agent_version_without_host_health_raises_unavailable(
    monkeypatch: pytest.MonkeyPatch, fake_binary: Path
) -> None:
    body = {**_HEARTBEAT_OK_BODY, "schema_version": 6, "agent_version": "dev"}
    _stub_heartbeat_body(monkeypatch, body)
    with pytest.raises(verifier.VerifierUnavailable, match="without a host-health"):
        verifier.verify_heartbeat(**_hb_kwargs())


def test_heartbeat_agent_version_invalid_is_a_known_reject(
    monkeypatch: pytest.MonkeyPatch, fake_binary: Path
) -> None:
    # The binary's v6 charset reject is a miner fault (VerifierFailed), not
    # a contract drift (VerifierUnavailable).
    monkeypatch.setattr(
        subprocess,
        "run",
        lambda *a, **kw: _stub_completed(
            json.dumps({"ok": False, "error_class": "agent_version_invalid"}).encode(), 0
        ),
    )
    with pytest.raises(verifier.VerifierFailed) as exc_info:
        verifier.verify_heartbeat(**_hb_kwargs())
    assert exc_info.value.category == "agent_version_invalid"


def test_heartbeat_capacity_invalid_is_a_known_reject(
    monkeypatch: pytest.MonkeyPatch, fake_binary: Path
) -> None:
    # The v3 `asid_used > asid_capacity` reject is a miner fault
    # (VerifierFailed), not a contract drift (VerifierUnavailable).
    monkeypatch.setattr(
        subprocess,
        "run",
        lambda *a, **kw: _stub_completed(
            json.dumps({"ok": False, "error_class": "capacity_invalid"}).encode(), 0
        ),
    )
    with pytest.raises(verifier.VerifierFailed) as exc_info:
        verifier.verify_heartbeat(**_hb_kwargs())
    assert exc_info.value.category == "capacity_invalid"


def test_heartbeat_ok_false_raises_verifier_failed(
    monkeypatch: pytest.MonkeyPatch, fake_binary: Path
) -> None:
    # exit 0 + `{"ok":false}` is a structured reject — the closed
    # `error_class` becomes the `VerifierFailed.category`.
    monkeypatch.setattr(
        subprocess,
        "run",
        lambda *a, **kw: _stub_completed(
            json.dumps({"ok": False, "error_class": "signature_invalid"}).encode(),
            0,
        ),
    )
    with pytest.raises(verifier.VerifierFailed) as exc_info:
        verifier.verify_heartbeat(**_hb_kwargs())
    assert exc_info.value.category == "signature_invalid"


def test_heartbeat_unknown_error_class_raises_unavailable(
    monkeypatch: pytest.MonkeyPatch, fake_binary: Path
) -> None:
    # An `error_class` outside the closed vocabulary means the binary's
    # contract drifted — a vali-side `VerifierUnavailable`.
    monkeypatch.setattr(
        subprocess,
        "run",
        lambda *a, **kw: _stub_completed(
            json.dumps({"ok": False, "error_class": "made_up"}).encode(), 0
        ),
    )
    with pytest.raises(verifier.VerifierUnavailable, match="unknown error_class"):
        verifier.verify_heartbeat(**_hb_kwargs())


def test_heartbeat_exit_two_raises_unavailable(
    monkeypatch: pytest.MonkeyPatch, fake_binary: Path
) -> None:
    # exit 2 = vali built a malformed --vk-hex (a vali bug) — no JSON.
    monkeypatch.setattr(
        subprocess,
        "run",
        lambda *a, **kw: _stub_completed(b"", 2, stderr=b"bad vk-hex"),
    )
    with pytest.raises(verifier.VerifierUnavailable, match="exited with code 2"):
        verifier.verify_heartbeat(**_hb_kwargs())


def test_heartbeat_exit_one_raises_unavailable(
    monkeypatch: pytest.MonkeyPatch, fake_binary: Path
) -> None:
    monkeypatch.setattr(
        subprocess,
        "run",
        lambda *a, **kw: _stub_completed(b"", 1),
    )
    with pytest.raises(verifier.VerifierUnavailable, match="exited with code 1"):
        verifier.verify_heartbeat(**_hb_kwargs())


def test_heartbeat_non_json_stdout_raises_unavailable(
    monkeypatch: pytest.MonkeyPatch, fake_binary: Path
) -> None:
    monkeypatch.setattr(
        subprocess,
        "run",
        lambda *a, **kw: _stub_completed(b"not json at all", 0),
    )
    with pytest.raises(verifier.VerifierUnavailable, match="not JSON"):
        verifier.verify_heartbeat(**_hb_kwargs())


def test_heartbeat_empty_envelope_short_circuits_to_failed(
    fake_binary: Path,
) -> None:
    # An empty envelope is rejected WITHOUT spawning.
    with pytest.raises(verifier.VerifierFailed) as exc_info:
        verifier.verify_heartbeat(envelope=b"", verifying_key=b"\x11" * 32)
    assert exc_info.value.category == "envelope_decode_failed"


def test_heartbeat_argv_carries_vk_envelope_rides_stdin(
    monkeypatch: pytest.MonkeyPatch, fake_binary: Path
) -> None:
    """Pin the `verify-heartbeat` argv/stdin contract: the public vk on
    argv, the (hostile-origin) envelope piped on stdin — never argv.
    """
    captured: dict[str, Any] = {}

    def _capture(argv: list[str], **kwargs: Any) -> subprocess.CompletedProcess:
        captured["argv"] = argv
        captured["input"] = kwargs.get("input")
        return _stub_completed(
            json.dumps({"ok": True, "body": _HEARTBEAT_OK_BODY}).encode(), 0
        )

    monkeypatch.setattr(subprocess, "run", _capture)
    envelope = b"the-canonical-signed-heartbeat"
    verifier.verify_heartbeat(envelope=envelope, verifying_key=b"\x11" * 32)

    argv = captured["argv"]
    assert "verify-heartbeat" in argv
    assert "--vk-hex" in argv
    assert ("11" * 32) in argv
    # `verify-heartbeat` takes NO `--sig-hex` — the sig is inside the
    # envelope on stdin.
    assert "--sig-hex" not in argv
    assert captured["input"] == envelope
    assert all(envelope.hex() not in arg for arg in argv)


@pytest.mark.skipif(
    not _REAL_BIN.is_file(),
    reason=(
        f"Rust validator not built at {_REAL_BIN} — run "
        "`cargo build -p hippius-ticket-validator --release`"
    ),
)
def test_real_binary_rejects_garbage_heartbeat() -> None:
    """End-to-end smoke: pipe obviously-bad bytes through the real
    `verify-heartbeat`. Expect a structured reject (`VerifierFailed`),
    not a crash.
    """
    with pytest.raises(verifier.VerifierFailed) as exc_info:
        verifier.verify_heartbeat(
            envelope=b"\xff\xff\xff\xff", verifying_key=bytes(32)
        )
    assert exc_info.value.category in verifier.HEARTBEAT_ERROR_CLASSES


# ─── host-attestor wrappers (blackbox host-attestor PR-8) ─────────────
#
# The data-bearing `verify-host-attestor-cert` / `verify-host-beacon`
# shell-outs: whole envelope on stdin, `--vk-hex` on argv (OPTIONAL for
# the cert — the KBS-L0-not-wired seam), success returns the decoded body.

_HOST_CERT_OK_BODY = {
    "schema_version": 1,
    "node_id": "aa" * 32,
    "chip_id_hex": "33" * 64,
    "attestor_pubkey_hex": "22" * 32,
    "measurement_hex": "44" * 48,
    "tcb": 0x0708_0000_0000_000B,
    "nonce_hex": "11" * 32,
    "expiry_unix": 1_800_000_900,
}

_HOST_BEACON_OK_BODY = {
    "schema_version": 1,
    "chip_id_hex": "33" * 64,
    "measurement_hex": "44" * 48,
    "node_id": "aa" * 32,
    "boot_id": "boot-1",
    "seq": 7,
    "observed_at_unix": 1_800_000_000,
    "policy": 0x30000,
    "nonce_hex": "11" * 32,
    "signer_pubkey_hex": "22" * 32,
    "expiry_unix": 1_800_000_900,
}


def test_host_cert_verified_true_when_vk_supplied(
    monkeypatch: pytest.MonkeyPatch, fake_binary: Path
) -> None:
    captured: dict[str, Any] = {}

    def _run(*a: Any, **kw: Any) -> subprocess.CompletedProcess:
        captured["argv"] = a[0]
        return _stub_completed(
            json.dumps({"ok": True, "verified": True, "body": _HOST_CERT_OK_BODY}).encode(),
            0,
        )

    monkeypatch.setattr(subprocess, "run", _run)
    fields = verifier.verify_host_attestor_cert(
        envelope=b"cert-cbor", verifying_key=b"\x11" * 32
    )
    assert fields.verified is True
    assert fields.node_id == "aa" * 32
    assert fields.chip_id_hex == "33" * 64
    assert fields.tcb == 0x0708_0000_0000_000B
    # The KBS L0 key rode argv as --vk-hex (public material).
    assert "--vk-hex" in captured["argv"]


def test_host_cert_decode_only_when_vk_none(
    monkeypatch: pytest.MonkeyPatch, fake_binary: Path
) -> None:
    captured: dict[str, Any] = {}

    def _run(*a: Any, **kw: Any) -> subprocess.CompletedProcess:
        captured["argv"] = a[0]
        return _stub_completed(
            json.dumps({"ok": True, "verified": False, "body": _HOST_CERT_OK_BODY}).encode(),
            0,
        )

    monkeypatch.setattr(subprocess, "run", _run)
    fields = verifier.verify_host_attestor_cert(
        envelope=b"cert-cbor", verifying_key=None
    )
    assert fields.verified is False
    # No --vk-hex when the KBS L0 key is not wired (the seam).
    assert "--vk-hex" not in captured["argv"]


def test_host_cert_reject_raises_verifier_failed(
    monkeypatch: pytest.MonkeyPatch, fake_binary: Path
) -> None:
    monkeypatch.setattr(
        subprocess,
        "run",
        lambda *a, **kw: _stub_completed(
            json.dumps({"ok": False, "error_class": "signature_invalid"}).encode(), 0
        ),
    )
    with pytest.raises(verifier.VerifierFailed) as exc:
        verifier.verify_host_attestor_cert(envelope=b"cert", verifying_key=bytes(32))
    assert exc.value.category == "signature_invalid"


def test_host_cert_unknown_error_class_is_unavailable(
    monkeypatch: pytest.MonkeyPatch, fake_binary: Path
) -> None:
    monkeypatch.setattr(
        subprocess,
        "run",
        lambda *a, **kw: _stub_completed(
            json.dumps({"ok": False, "error_class": "made_up"}).encode(), 0
        ),
    )
    with pytest.raises(verifier.VerifierUnavailable):
        verifier.verify_host_attestor_cert(envelope=b"cert", verifying_key=None)


def test_host_beacon_ok_returns_decoded_body(
    monkeypatch: pytest.MonkeyPatch, fake_binary: Path
) -> None:
    monkeypatch.setattr(
        subprocess,
        "run",
        lambda *a, **kw: _stub_completed(
            json.dumps({"ok": True, "body": _HOST_BEACON_OK_BODY}).encode(), 0
        ),
    )
    beacon = verifier.verify_host_beacon(
        envelope=b"beacon-cbor", verifying_key=b"\x22" * 32
    )
    assert beacon.seq == 7
    assert beacon.chip_id_hex == "33" * 64
    assert beacon.node_id == "aa" * 32
    assert beacon.expiry_unix == 1_800_000_900


def test_host_beacon_reject_raises_verifier_failed(
    monkeypatch: pytest.MonkeyPatch, fake_binary: Path
) -> None:
    monkeypatch.setattr(
        subprocess,
        "run",
        lambda *a, **kw: _stub_completed(
            json.dumps({"ok": False, "error_class": "signature_invalid"}).encode(), 0
        ),
    )
    with pytest.raises(verifier.VerifierFailed) as exc:
        verifier.verify_host_beacon(envelope=b"beacon", verifying_key=bytes(32))
    assert exc.value.category == "signature_invalid"


@pytest.mark.skipif(
    not _REAL_BIN.is_file(),
    reason=(
        f"Rust validator not built at {_REAL_BIN} — run "
        "`cargo build -p hippius-ticket-validator --release`"
    ),
)
def test_real_binary_rejects_garbage_host_cert() -> None:
    """End-to-end smoke: garbage through the real `verify-host-attestor-cert`
    (decode-only, no vk) is a structured reject, not a crash."""
    with pytest.raises(verifier.VerifierFailed) as exc:
        verifier.verify_host_attestor_cert(
            envelope=b"\xff\xff\xff\xff", verifying_key=None
        )
    assert exc.value.category in verifier.HOST_ATTESTOR_ERROR_CLASSES


@pytest.mark.skipif(
    not _REAL_BIN.is_file(),
    reason=(
        f"Rust validator not built at {_REAL_BIN} — run "
        "`cargo build -p hippius-ticket-validator --release`"
    ),
)
def test_real_binary_rejects_garbage_host_beacon() -> None:
    """End-to-end smoke: garbage through the real `verify-host-beacon` is a
    structured reject, not a crash."""
    with pytest.raises(verifier.VerifierFailed) as exc:
        verifier.verify_host_beacon(envelope=b"\xff\xff\xff\xff", verifying_key=bytes(32))
    assert exc.value.category in verifier.HOST_ATTESTOR_ERROR_CLASSES


def test_host_challenge_request_surfaces_pubkey(
    monkeypatch: pytest.MonkeyPatch, fake_binary: Path
) -> None:
    """The mock wrapper surfaces the decoded `signer_pubkey_hex` (PR-10)."""
    monkeypatch.setattr(
        subprocess,
        "run",
        lambda *a, **kw: _stub_completed(
            json.dumps(
                {"ok": True, "body": {"schema_version": 1, "signer_pubkey_hex": "22" * 32}}
            ).encode(),
            0,
        ),
    )
    fields = verifier.verify_host_challenge_request(envelope=b"challenge")
    assert fields.schema_version == 1
    assert fields.signer_pubkey_hex == "22" * 32


def test_host_challenge_request_reject_is_verifier_failed(
    monkeypatch: pytest.MonkeyPatch, fake_binary: Path
) -> None:
    monkeypatch.setattr(
        subprocess,
        "run",
        lambda *a, **kw: _stub_completed(
            json.dumps({"ok": False, "error_class": "body_decode_failed"}).encode(), 0
        ),
    )
    with pytest.raises(verifier.VerifierFailed) as exc:
        verifier.verify_host_challenge_request(envelope=b"garbage")
    assert exc.value.category == "body_decode_failed"


@pytest.mark.skipif(
    not _REAL_BIN.is_file(),
    reason=(
        f"Rust validator not built at {_REAL_BIN} — run "
        "`cargo build -p hippius-ticket-validator --release`"
    ),
)
def test_real_binary_rejects_garbage_host_challenge_request() -> None:
    """End-to-end smoke: garbage through the real
    `verify-host-challenge-request` is a structured reject, not a crash."""
    with pytest.raises(verifier.VerifierFailed) as exc:
        verifier.verify_host_challenge_request(envelope=b"\xff\xff\xff\xff")
    assert exc.value.category in verifier.HOST_ATTESTOR_ERROR_CLASSES


# ─── verify_live_attestation wrapper (§23 uptime coverage) ────────────


def test_live_attestation_requires_a_key_and_never_shells_out(
    monkeypatch: pytest.MonkeyPatch, fake_binary: Path
) -> None:
    """No decode-only seam: without the pinned KBS L0 key the wrapper
    refuses BEFORE spawning, so there is no shape of result vali could
    mistake for coverage."""

    def explode(*a, **kw):  # pragma: no cover — must never run
        raise AssertionError("shelled out without a verifying key")

    monkeypatch.setattr(subprocess, "run", explode)
    for bad_key in (None, b"", b"\x11" * 31, b"\x11" * 33):
        with pytest.raises(verifier.VerifierUnavailable):
            verifier.verify_live_attestation(envelope=b"x", verifying_key=bad_key)


def test_live_attestation_accept_surfaces_the_body(
    monkeypatch: pytest.MonkeyPatch, fake_binary: Path
) -> None:
    body = {
        "schema_version": 1,
        "vm_id": "tn-live-1",
        "node_id_hex": "bb" * 32,
        "attestation_seq": 7,
        "epoch": 4242,
        "observed_at_unix": 1_800_000_000,
        "verified_at_unix": 1_800_000_005,
        "expiry_unix": 1_800_000_900,
        "measurement_hex": "33" * 48,
        "snp_report_digest_hex": "11" * 32,
        "vcek_chain_digest_hex": "22" * 32,
        "prev_attestation_hash_hex": "44" * 32,
        "signer_pubkey_hex": "55" * 32,
        "chain_genesis_hex": "66" * 32,
        "pallet_instance_hex": "77" * 32,
        "body_digest_hex": "88" * 32,
    }
    monkeypatch.setattr(
        subprocess,
        "run",
        lambda *a, **kw: _stub_completed(
            json.dumps({"ok": True, "body": body}).encode(), 0
        ),
    )
    fields = verifier.verify_live_attestation(
        envelope=b"cbor", verifying_key=b"\x55" * 32
    )
    assert fields.vm_id == "tn-live-1"
    assert fields.attestation_seq == 7
    assert fields.verified_at_unix == 1_800_000_005
    assert fields.body_digest_hex == "88" * 32


def test_live_attestation_reject_is_verifier_failed(
    monkeypatch: pytest.MonkeyPatch, fake_binary: Path
) -> None:
    monkeypatch.setattr(
        subprocess,
        "run",
        lambda *a, **kw: _stub_completed(
            json.dumps({"ok": False, "error_class": "signature_invalid"}).encode(), 0
        ),
    )
    with pytest.raises(verifier.VerifierFailed) as exc:
        verifier.verify_live_attestation(
            envelope=b"garbage", verifying_key=b"\x55" * 32
        )
    assert exc.value.category == "signature_invalid"


@pytest.mark.skipif(
    not _REAL_BIN.is_file(),
    reason=(
        f"Rust validator not built at {_REAL_BIN} — run "
        "`cargo build -p hippius-ticket-validator --release`"
    ),
)
def test_real_binary_rejects_garbage_live_attestation() -> None:
    """End-to-end smoke: garbage through the real
    `verify-live-attestation` is a structured reject, not a crash."""
    with pytest.raises(verifier.VerifierFailed) as exc:
        verifier.verify_live_attestation(
            envelope=b"\xff\xff\xff\xff", verifying_key=b"\x55" * 32
        )
    assert exc.value.category in verifier.LIVE_ATTESTATION_ERROR_CLASSES


def test_declared_capacity_above_the_column_range_is_no_clamp() -> None:
    """A u32 the heartbeat schema allows but Postgres' signed integer cannot
    hold must not 500 the ingest — it is stored as unknown (no clamp)."""
    from apps.telemetry.service import declared_capacity_columns
    from apps.telemetry.verifier import DeclaredCapacity

    cols = declared_capacity_columns(
        DeclaredCapacity(
            cvm_cpu_budget=2**32 - 1,
            cvm_memory_mb_budget=2_147_483_647,
            asid_capacity=2_147_483_648,
            asid_used=0,
        )
    )
    assert cols == {
        "declared_cpu_budget": None,
        "declared_memory_mb_budget": 2_147_483_647,
        "declared_asid_capacity": None,
        "declared_asid_used": None,
    }


# ─── verify-live-attestation: the v2 guest binding ──────────────────


def _live_body(**over: object) -> dict[str, object]:
    body: dict[str, object] = {
        "schema_version": 1,
        "vm_id": "vm-1",
        "node_id_hex": "aa" * 32,
        "attestation_seq": 1,
        "epoch": 7,
        "observed_at_unix": 1,
        "verified_at_unix": 2,
        "expiry_unix": 3,
        "measurement_hex": "44" * 48,
        "snp_report_digest_hex": "11" * 32,
        "vcek_chain_digest_hex": "22" * 32,
        "prev_attestation_hash_hex": "00" * 32,
        "signer_pubkey_hex": "ab" * 32,
        "chain_genesis_hex": "33" * 32,
        "pallet_instance_hex": "dd" * 32,
        "body_digest_hex": "cc" * 32,
        "binding_source": None,
        "chip_id_hex": None,
        "report_id_hex": None,
    }
    body.update(over)
    return body


def _live(
    monkeypatch: pytest.MonkeyPatch, body: dict[str, object]
) -> verifier.LiveAttestationFields:
    monkeypatch.setattr(
        verifier, "_run_host_attestor", lambda *_a, **_k: {"ok": True, "body": body}
    )
    return verifier.verify_live_attestation(envelope=b"\x01", verifying_key=bytes(32))


def test_live_attestation_v1_has_no_guest(monkeypatch: pytest.MonkeyPatch) -> None:
    f = _live(monkeypatch, _live_body())
    assert (f.binding_source, f.chip_id_hex, f.report_id_hex) == (None, None, None)


def test_live_attestation_v2_carries_the_guest(monkeypatch: pytest.MonkeyPatch) -> None:
    f = _live(
        monkeypatch,
        _live_body(
            schema_version=2,
            binding_source="release",
            chip_id_hex="5e" * 64,
            report_id_hex="7a" * 32,
        ),
    )
    assert (f.binding_source, f.chip_id_hex, f.report_id_hex) == (
        "release",
        "5e" * 64,
        "7a" * 32,
    )


_CHIP = "5e" * 64
_REPORT = "7a" * 32


@pytest.mark.parametrize(
    "over",
    [
        # v2 without the binding, or with a malformed one
        {"schema_version": 2},
        {"binding_source": "trust-me"},
        {"chip_id_hex": "5e" * 8},
        {"chip_id_hex": "5E" * 64},
        {"report_id_hex": "7a" * 31},
        # v1 claiming a binding
        {"schema_version": 1, "binding_source": None, "report_id_hex": None},
    ],
)
def test_live_attestation_binding_drift_is_vali_side(
    monkeypatch: pytest.MonkeyPatch, over: dict[str, object]
) -> None:
    bound = {
        "schema_version": 2,
        "binding_source": "release",
        "chip_id_hex": _CHIP,
        "report_id_hex": _REPORT,
    }
    if over == {"schema_version": 2}:
        bound = {}
    with pytest.raises(verifier.VerifierUnavailable):
        _live(monkeypatch, _live_body(**{**bound, **over}))


# ─── verify-live-attestation: the v4 guest components ───────────────

_COMPONENTS = {
    "components_release_version": 2,
    "components_security_epoch": 1,
    "components_health": 15,
    "components_instance": 7,
    "components_unhealthy_ticks": 0,
}
_RESOURCES = {
    "vcpus_online": 4,
    "mem_firmware_kib": 1,
    "mem_total_kib": 2,
    "mem_unaccepted_kib": 0,
}


def test_live_attestation_v4_carries_the_components_alone(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """v4: components required, the binding and the resources optional."""
    f = _live(monkeypatch, _live_body(schema_version=4, **_COMPONENTS))
    assert (
        f.components_release_version,
        f.components_security_epoch,
        f.components_health,
        f.components_instance,
        f.components_unhealthy_ticks,
    ) == (2, 1, 15, 7, 0)
    assert f.binding_source is None and f.vcpus_online is None


def test_live_attestation_v4_with_binding_and_resources(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    f = _live(
        monkeypatch,
        _live_body(
            schema_version=4,
            binding_source="release",
            chip_id_hex=_CHIP,
            report_id_hex=_REPORT,
            **_RESOURCES,
            **_COMPONENTS,
        ),
    )
    assert (f.binding_source, f.vcpus_online, f.components_health) == ("release", 4, 15)


@pytest.mark.parametrize(
    "body",
    [
        # v4 without components, or with one missing / out of range
        {"schema_version": 4},
        {"schema_version": 4, **{**_COMPONENTS, "components_health": None}},
        {"schema_version": 4, **{**_COMPONENTS, "components_instance": 2**32}},
        {"schema_version": 4, **{**_COMPONENTS, "components_unhealthy_ticks": -1}},
        # components on a pre-v4 body
        {"schema_version": 1, **_COMPONENTS},
        {"schema_version": 3, **_RESOURCES, **_COMPONENTS},
    ],
)
def test_live_attestation_components_drift_is_vali_side(
    monkeypatch: pytest.MonkeyPatch, body: dict[str, object]
) -> None:
    with pytest.raises(verifier.VerifierUnavailable):
        _live(monkeypatch, _live_body(**body))
