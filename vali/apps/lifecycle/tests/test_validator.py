"""Shell-out wrapper tests for `apps.lifecycle.validator`.

Same pattern as `apps.orders.tests.test_validator`: mock tests (always
run) + a real-binary smoke test (auto-skip if the Rust binary is
absent).
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import Any

import pytest
from django.conf import settings

from apps.lifecycle import validator


def _stub_completed(
    stdout: bytes, returncode: int, stderr: bytes = b""
) -> subprocess.CompletedProcess:
    return subprocess.CompletedProcess(
        args=["bin", "verify-stopped-ack"],
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
        "signed_bytes": b"any-bytes",
        "lifecycle_vk_hex": "00" * 32,
        "vm_id": "vm-1",
        "lease_id": "lease-1",
        "vm_generation": 5,
        "nonce_hex": "11" * 32,
        "now_unix_min": 0,
        "now_unix_max": 9_999_999_999,
    }
    base.update(override)
    return base


def test_missing_binary_raises_unavailable(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(
        settings,
        "VALI_TICKET_VALIDATOR_BIN",
        str(tmp_path / "does-not-exist"),
    )
    with pytest.raises(validator.ValidatorUnavailable, match="not found"):
        validator.verify_stopped_ack(**_kwargs())


def test_empty_signed_bytes_short_circuit_to_failed(
    fake_binary: Path,
) -> None:
    # The wrapper rejects empty input WITHOUT spawning, but still
    # returns the same `stopped-decode` category the binary would.
    with pytest.raises(validator.ValidatorFailed) as exc_info:
        validator.verify_stopped_ack(**_kwargs(signed_bytes=b""))
    assert exc_info.value.category == "stopped-decode"


def test_ok_exit_returns_verified_now_unix(
    monkeypatch: pytest.MonkeyPatch, fake_binary: Path
) -> None:
    payload = {"tag": "ok", "now_unix": 1_234_567}
    monkeypatch.setattr(
        subprocess,
        "run",
        lambda *a, **kw: _stub_completed(json.dumps(payload).encode(), 0),
    )
    out = validator.verify_stopped_ack(**_kwargs())
    assert out.now_unix == 1_234_567


def test_err_exit_two_raises_validator_failed(
    monkeypatch: pytest.MonkeyPatch, fake_binary: Path
) -> None:
    err = {"tag": "err", "error": "body mismatch", "category": "stopped-body-mismatch"}
    monkeypatch.setattr(
        subprocess,
        "run",
        lambda *a, **kw: _stub_completed(json.dumps(err).encode(), 2),
    )
    with pytest.raises(validator.ValidatorFailed) as exc_info:
        validator.verify_stopped_ack(**_kwargs())
    assert exc_info.value.category == "stopped-body-mismatch"


def test_internal_exit_one_raises_unavailable(
    monkeypatch: pytest.MonkeyPatch, fake_binary: Path
) -> None:
    monkeypatch.setattr(
        subprocess,
        "run",
        lambda *a, **kw: _stub_completed(b"", 1, stderr=b"oh no"),
    )
    with pytest.raises(validator.ValidatorUnavailable, match="exited with code 1"):
        validator.verify_stopped_ack(**_kwargs())


def test_non_json_stdout_raises_unavailable(
    monkeypatch: pytest.MonkeyPatch, fake_binary: Path
) -> None:
    monkeypatch.setattr(
        subprocess,
        "run",
        lambda *a, **kw: _stub_completed(b"not json", 0),
    )
    with pytest.raises(validator.ValidatorUnavailable, match="not JSON"):
        validator.verify_stopped_ack(**_kwargs())


def test_timeout_raises_unavailable(
    monkeypatch: pytest.MonkeyPatch, fake_binary: Path
) -> None:
    def _raise(*_a, **_kw):
        raise subprocess.TimeoutExpired(cmd="bin", timeout=0.1)

    monkeypatch.setattr(subprocess, "run", _raise)
    with pytest.raises(validator.ValidatorUnavailable, match="timed out"):
        validator.verify_stopped_ack(**_kwargs())


def test_argv_passes_subcommand_and_flags(
    monkeypatch: pytest.MonkeyPatch, fake_binary: Path
) -> None:
    """The wrapper builds the argv list; the binary's `clap` parser
    needs the exact flag spellings. A typo in the wrapper would only
    surface as a (cryptic) clap parse error → exit-code 2; pin the
    argv shape so a typo here flips a test instead.
    """
    captured: dict[str, Any] = {}

    def _capture(argv, **kwargs):
        captured["argv"] = argv
        captured["input"] = kwargs.get("input")
        payload = {"tag": "ok", "now_unix": 1}
        return _stub_completed(json.dumps(payload).encode(), 0)

    monkeypatch.setattr(subprocess, "run", _capture)
    validator.verify_stopped_ack(**_kwargs())
    argv = captured["argv"]
    assert "verify-stopped-ack" in argv
    assert "--vk-hex" in argv
    assert "--vm-id" in argv
    assert "--lease-id" in argv
    assert "--vm-generation" in argv
    assert "--nonce-hex" in argv
    assert "--now-unix-min" in argv
    assert "--now-unix-max" in argv


# ─── Real-binary integration ─────────────────────────────────────────


_REAL_BIN = Path(settings.VALI_TICKET_VALIDATOR_BIN)


@pytest.mark.skipif(
    not _REAL_BIN.is_file(),
    reason=(
        f"Rust validator not built at {_REAL_BIN} — run "
        "`cargo build -p hippius-ticket-validator --release`"
    ),
)
def test_real_binary_rejects_garbage_signed_ack() -> None:
    """End-to-end smoke: pipe obviously-bad bytes through the real
    binary. Expect a structured `stopped-decode`."""
    with pytest.raises(validator.ValidatorFailed) as exc_info:
        validator.verify_stopped_ack(**_kwargs(signed_bytes=b"\xff\xff"))
    assert exc_info.value.category == "stopped-decode"
