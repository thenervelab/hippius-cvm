"""Tests for `sentinel.analytics.wiring`.

The production wiring just hands the PR-S2 / PR-S3 readers to the
rules behind an async surface. We cover the file-based KBS allowlist
epoch reader and confirm `build_default_rules()` produces all six.
"""

from __future__ import annotations

from pathlib import Path

import pytest

import sentinel.analytics.wiring as wiring
from sentinel.analytics.wiring import build_default_rules


def test_build_default_rules_includes_six_rules() -> None:
    rules = build_default_rules()
    names = {r.name for r in rules}
    assert names == {
        "release_anomaly",
        "replay_attempts",
        "allowlist_drift",
        "audit_chain_break",
        "cert_expiry",
        "miner_quarantine_proximity",
    }


def test_kbs_allowlist_epoch_reader_unset_returns_none(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv(wiring.ENV_KBS_ALLOWLIST_EPOCH_PATH, raising=False)
    assert wiring._read_kbs_allowlist_epoch_sync() is None


def test_kbs_allowlist_epoch_reader_missing_file_returns_none(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setenv(
        wiring.ENV_KBS_ALLOWLIST_EPOCH_PATH, str(tmp_path / "missing.json")
    )
    assert wiring._read_kbs_allowlist_epoch_sync() is None


def test_kbs_allowlist_epoch_reader_plain_int(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    p = tmp_path / "epoch"
    p.write_text("  42  \n")
    monkeypatch.setenv(wiring.ENV_KBS_ALLOWLIST_EPOCH_PATH, str(p))
    assert wiring._read_kbs_allowlist_epoch_sync() == 42


def test_kbs_allowlist_epoch_reader_json_object(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    p = tmp_path / "epoch.json"
    p.write_text('{"epoch": 7, "rotated_at": "ignored"}')
    monkeypatch.setenv(wiring.ENV_KBS_ALLOWLIST_EPOCH_PATH, str(p))
    assert wiring._read_kbs_allowlist_epoch_sync() == 7


def test_kbs_allowlist_epoch_reader_invalid_returns_none(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    p = tmp_path / "epoch"
    p.write_text("not a number")
    monkeypatch.setenv(wiring.ENV_KBS_ALLOWLIST_EPOCH_PATH, str(p))
    assert wiring._read_kbs_allowlist_epoch_sync() is None


def test_kbs_allowlist_epoch_reader_empty_returns_none(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    p = tmp_path / "epoch"
    p.write_text("   \n")
    monkeypatch.setenv(wiring.ENV_KBS_ALLOWLIST_EPOCH_PATH, str(p))
    assert wiring._read_kbs_allowlist_epoch_sync() is None


def test_kbs_allowlist_epoch_reader_rejects_bool_json(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    p = tmp_path / "epoch"
    p.write_text("true")
    monkeypatch.setenv(wiring.ENV_KBS_ALLOWLIST_EPOCH_PATH, str(p))
    assert wiring._read_kbs_allowlist_epoch_sync() is None


def test_kbs_allowlist_epoch_reader_rejects_negative_int(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Review round-2 MED: u64 bounds enforced."""

    p = tmp_path / "epoch"
    p.write_text("-5")
    monkeypatch.setenv(wiring.ENV_KBS_ALLOWLIST_EPOCH_PATH, str(p))
    assert wiring._read_kbs_allowlist_epoch_sync() is None


def test_kbs_allowlist_epoch_reader_rejects_huge_int(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    p = tmp_path / "epoch"
    p.write_text(str(1 << 100))
    monkeypatch.setenv(wiring.ENV_KBS_ALLOWLIST_EPOCH_PATH, str(p))
    assert wiring._read_kbs_allowlist_epoch_sync() is None


def test_kbs_allowlist_epoch_reader_rejects_json_bool_field(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    p = tmp_path / "epoch.json"
    p.write_text('{"epoch": true}')
    monkeypatch.setenv(wiring.ENV_KBS_ALLOWLIST_EPOCH_PATH, str(p))
    assert wiring._read_kbs_allowlist_epoch_sync() is None


def test_kbs_allowlist_epoch_reader_rejects_json_negative(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    p = tmp_path / "epoch.json"
    p.write_text('{"epoch": -3}')
    monkeypatch.setenv(wiring.ENV_KBS_ALLOWLIST_EPOCH_PATH, str(p))
    assert wiring._read_kbs_allowlist_epoch_sync() is None


def test_stat_mtime_returns_none_for_missing(tmp_path: Path) -> None:
    assert wiring._stat_mtime_sync(str(tmp_path / "nope")) is None


def test_stat_mtime_returns_float_for_existing(tmp_path: Path) -> None:
    p = tmp_path / "f"
    p.write_text("x")
    mtime = wiring._stat_mtime_sync(str(p))
    assert isinstance(mtime, float) and mtime > 0
