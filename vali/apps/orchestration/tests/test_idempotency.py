"""Tests for the §14 idempotency shell-out wrapper.

The `record` / `recall` round-trip tests exercise the REAL
`hippius-ticket-validator idempotency-*` subcommands against a real
temp store — they are skipped when the binary has not been built.
The error-handling tests need no binary.

`real_idempotency` opts these tests out of the in-memory
`_mock_idempotency` autouse fixture.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from django.conf import settings

from apps.orchestration import idempotency
from apps.orchestration.idempotency import IdempotencyUnavailable

pytestmark = pytest.mark.real_idempotency


def _require_binary() -> None:
    bin_path = Path(settings.VALI_TICKET_VALIDATOR_BIN)
    if not bin_path.is_file():
        pytest.skip(f"validator binary not built at {bin_path}")


# ─── real shell-out round-trips (skipped if the binary is absent) ────


def test_record_then_recall_round_trips() -> None:
    _require_binary()
    key = "migration:job-abc:fencing"
    response_hash = idempotency.marker_hash(key)
    assert idempotency.record(key, response_hash) is True
    assert idempotency.recall(key) == response_hash


def test_recall_of_an_unknown_key_is_none() -> None:
    _require_binary()
    assert idempotency.recall("migration:never-recorded:step") is None


def test_recording_the_same_key_twice_reports_replay() -> None:
    _require_binary()
    key = "decommission:job-xyz:crypto-erase"
    assert idempotency.record(key, idempotency.marker_hash(key)) is True
    # The second record is a benign replay — `recorded` is False.
    assert idempotency.record(key, idempotency.marker_hash(key)) is False


# ─── fail-loud error handling (no binary needed) ─────────────────────


def test_missing_binary_raises_unavailable(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
) -> None:
    monkeypatch.setattr(
        settings, "VALI_TICKET_VALIDATOR_BIN", str(tmp_path / "does-not-exist")
    )
    with pytest.raises(IdempotencyUnavailable):
        idempotency.recall("any-key")


def test_unconfigured_store_dir_raises_unavailable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(settings, "VALI_IDEMPOTENCY_DIR", "")
    with pytest.raises(IdempotencyUnavailable) as exc:
        idempotency.recall("any-key")
    assert "VALI_IDEMPOTENCY_DIR" in str(exc.value)


# ─── marker hash ─────────────────────────────────────────────────────


def test_marker_hash_is_deterministic_and_32_bytes() -> None:
    key = "migration:job-1:quiescing"
    h1 = idempotency.marker_hash(key)
    h2 = idempotency.marker_hash(key)
    assert h1 == h2
    assert len(h1) == 64  # 32 bytes, hex
    assert idempotency.marker_hash("other-key") != h1
