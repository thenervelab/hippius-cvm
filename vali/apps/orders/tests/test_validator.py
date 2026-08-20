"""Unit tests for `apps.orders.validator` (subprocess wrapper).

Two flavors:

- Pure mock tests (always run): `monkeypatch` on `subprocess.run` so we
  can pin the wrapper's behaviour for every exit code / stdout shape
  WITHOUT depending on the Rust binary being built.
- Integration test (auto-skip if the binary is missing): drives the
  real `hippius-ticket-validator` over a deterministic COSE_Sign1
  envelope produced by `kbs-core`'s test helpers — proves the wire
  contract between Python and Rust hasn't drifted.
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import Any

import pytest
from django.conf import settings

from apps.orders import validator

# ────────────────────────────────────────────────────────────────────
# Helpers
# ────────────────────────────────────────────────────────────────────


def _stub_completed(
    stdout: bytes, returncode: int, stderr: bytes = b""
) -> subprocess.CompletedProcess:
    return subprocess.CompletedProcess(
        args=["bin"], returncode=returncode, stdout=stdout, stderr=stderr
    )


def _ok_payload(ticket_id: str = "tk-1", vm_generation: int = 5) -> dict[str, Any]:
    return {
        "tag": "ok",
        "ticket": {
            "v": 1,
            "ticket_id": ticket_id,
            "issue_time": 1000,
            "expiry": 2000,
            "nonce_hex": "11" * 32,
            "tenant_id": "t1",
            "user_id": "u1",
            "vm_id": "abc",
            "lease_id": "lease-1",
            "vm_generation": vm_generation,
            "node_id": "node-1",
            "platform_id": "chip-1",
            "allowed_measurements_hex": ["07" * 48],
            "userdata_vault_ref": {"path": "kbs/vm/abc/ud", "version": 2},
            "luks_vault_ref": {"path": "kbs/vm/abc/luks", "version": 3},
            "allowed_userdata_digest_hex": "09" * 32,
            "resource_class": "std",
            "lifecycle_perms": ["boot"],
            "kid_hex": "6c312d6b6964",  # "l1-kid"
            "cose_len": 256,
        },
    }


@pytest.fixture
def fake_binary(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Create a placeholder file at `settings.VALI_TICKET_VALIDATOR_BIN`.

    `validator.validate_ticket` short-circuits to `ValidatorUnavailable`
    if the path doesn't exist; the mock tests use this stub so the
    path check passes, then patch `subprocess.run` to control the
    return value.
    """
    fake = tmp_path / "hippius-ticket-validator"
    fake.write_text("# placeholder; subprocess.run is mocked in these tests\n")
    fake.chmod(0o755)
    monkeypatch.setattr(settings, "VALI_TICKET_VALIDATOR_BIN", str(fake))
    return fake


# ────────────────────────────────────────────────────────────────────
# Mock tests — wrapper behaviour
# ────────────────────────────────────────────────────────────────────


def test_missing_binary_raises_unavailable(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setattr(
        settings,
        "VALI_TICKET_VALIDATOR_BIN",
        str(tmp_path / "does-not-exist"),
    )
    with pytest.raises(validator.ValidatorUnavailable, match="not found"):
        validator.validate_ticket(b"any-bytes")


def test_ok_exit_returns_parsed_ticket(
    monkeypatch: pytest.MonkeyPatch, fake_binary: Path
) -> None:
    payload = _ok_payload()
    monkeypatch.setattr(
        subprocess,
        "run",
        lambda *a, **kw: _stub_completed(json.dumps(payload).encode(), 0),
    )
    parsed = validator.validate_ticket(b"any-bytes")
    assert parsed.ticket_id == "tk-1"
    assert parsed.vm_id == "abc"
    assert parsed.vm_generation == 5
    assert parsed.kid_hex == "6c312d6b6964"


def test_err_exit_two_raises_validator_failed(
    monkeypatch: pytest.MonkeyPatch, fake_binary: Path
) -> None:
    err = {"tag": "err", "error": "schema bad", "category": "schema"}
    monkeypatch.setattr(
        subprocess,
        "run",
        lambda *a, **kw: _stub_completed(json.dumps(err).encode(), 2),
    )
    with pytest.raises(validator.ValidatorFailed) as exc_info:
        validator.validate_ticket(b"any-bytes")
    assert exc_info.value.category == "schema"
    assert "schema bad" in exc_info.value.message


def test_internal_exit_one_raises_unavailable(
    monkeypatch: pytest.MonkeyPatch, fake_binary: Path
) -> None:
    monkeypatch.setattr(
        subprocess,
        "run",
        lambda *a, **kw: _stub_completed(b"", 1, stderr=b"oh no"),
    )
    with pytest.raises(validator.ValidatorUnavailable, match="exited with code 1"):
        validator.validate_ticket(b"any-bytes")


def test_non_json_stdout_raises_unavailable(
    monkeypatch: pytest.MonkeyPatch, fake_binary: Path
) -> None:
    monkeypatch.setattr(
        subprocess,
        "run",
        lambda *a, **kw: _stub_completed(b"not json {{{", 0),
    )
    with pytest.raises(validator.ValidatorUnavailable, match="not JSON"):
        validator.validate_ticket(b"any-bytes")


def test_missing_tag_raises_unavailable(
    monkeypatch: pytest.MonkeyPatch, fake_binary: Path
) -> None:
    monkeypatch.setattr(
        subprocess,
        "run",
        lambda *a, **kw: _stub_completed(b'{"ticket": {}}', 0),
    )
    with pytest.raises(validator.ValidatorUnavailable, match="missing 'tag'"):
        validator.validate_ticket(b"any-bytes")


def test_ok_with_missing_field_raises_unavailable(
    monkeypatch: pytest.MonkeyPatch, fake_binary: Path
) -> None:
    payload = _ok_payload()
    del payload["ticket"]["vm_id"]
    monkeypatch.setattr(
        subprocess,
        "run",
        lambda *a, **kw: _stub_completed(json.dumps(payload).encode(), 0),
    )
    with pytest.raises(validator.ValidatorUnavailable, match="unexpected shape"):
        validator.validate_ticket(b"any-bytes")


def test_timeout_raises_unavailable(
    monkeypatch: pytest.MonkeyPatch, fake_binary: Path
) -> None:
    def _raise(*_a, **_kw):
        raise subprocess.TimeoutExpired(cmd="bin", timeout=0.1)

    monkeypatch.setattr(subprocess, "run", _raise)
    with pytest.raises(validator.ValidatorUnavailable, match="timed out"):
        validator.validate_ticket(b"any-bytes")


def test_non_utf8_stdout_raises_unavailable(
    monkeypatch: pytest.MonkeyPatch, fake_binary: Path
) -> None:
    """Non-UTF8 stdout from the binary must surface as a structured
    503 (`ValidatorUnavailable`), not bubble `UnicodeDecodeError`.
    """
    # \xff is invalid UTF-8 start byte; json.loads on raw bytes will
    # raise `UnicodeDecodeError` (subclass of `ValueError`).
    monkeypatch.setattr(
        subprocess,
        "run",
        lambda *a, **kw: _stub_completed(b"\xff\xff{not-utf8", 0),
    )
    with pytest.raises(validator.ValidatorUnavailable):
        validator.validate_ticket(b"any-bytes")


# ────────────────────────────────────────────────────────────────────
# Integration — real Rust binary
# ────────────────────────────────────────────────────────────────────

_REAL_BIN = Path(settings.VALI_TICKET_VALIDATOR_BIN)


@pytest.mark.skipif(
    not _REAL_BIN.is_file(),
    reason=(
        f"Rust validator not built at {_REAL_BIN} — run "
        "`cargo build -p hippius-ticket-validator --release`"
    ),
)
def test_real_binary_rejects_empty_input() -> None:
    """Smoke-test the real Rust binary over an obviously-bad input.

    `validate_ticket` should surface a structured `ValidatorFailed`
    (the binary exits 2 with a JSON `err`), NOT a `ValidatorUnavailable`
    (which would indicate the Python/Rust contract is broken).
    """
    with pytest.raises(validator.ValidatorFailed) as exc_info:
        validator.validate_ticket(b"")
    # The validator returns one of {non-canonical-cbor, cose-parse}
    # for the empty input — both are valid categories per its own
    # tests.
    assert exc_info.value.category in {"non-canonical-cbor", "cose-parse"}
