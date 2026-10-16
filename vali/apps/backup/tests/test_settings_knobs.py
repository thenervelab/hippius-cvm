"""The #1584 backup waits are settings read from the environment (an
operator can tune them without a new image), with the code defaults, and
vali refuses to start on a negative one."""

from __future__ import annotations

import importlib.util
from types import ModuleType

import pytest

from apps.backup import service

KNOBS = {
    "VALI_BACKUP_BOOT_SETTLE_S": 180,
    "VALI_BACKUP_BOOT_WAIT_MAX_S": 900,
    "VALI_BACKUP_DOMAIN_GONE_GRACE_S": 900,
}


def _load_settings() -> ModuleType:
    """A fresh copy of `vali/settings.py`, never over the live settings."""
    from vali import settings as vali_settings

    spec = importlib.util.spec_from_file_location("_settings_copy", vali_settings.__file__)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_the_defaults_are_unchanged(monkeypatch) -> None:
    for name in KNOBS:
        monkeypatch.delenv(name, raising=False)
    loaded = _load_settings()
    assert {name: getattr(loaded, name) for name in KNOBS} == KNOBS


def test_the_environment_is_read(monkeypatch) -> None:
    monkeypatch.setenv("VALI_BACKUP_BOOT_SETTLE_S", "60")
    monkeypatch.setenv("VALI_BACKUP_BOOT_WAIT_MAX_S", "0")
    monkeypatch.setenv("VALI_BACKUP_DOMAIN_GONE_GRACE_S", "1200")
    loaded = _load_settings()
    assert loaded.VALI_BACKUP_BOOT_SETTLE_S == 60
    assert loaded.VALI_BACKUP_BOOT_WAIT_MAX_S == 0
    assert loaded.VALI_BACKUP_DOMAIN_GONE_GRACE_S == 1200


@pytest.mark.parametrize("name", sorted(KNOBS))
def test_a_negative_value_refuses_to_start(monkeypatch, name: str) -> None:
    monkeypatch.setenv(name, "-1")
    with pytest.raises(RuntimeError, match=name):
        _load_settings()


def test_the_service_reads_the_settings(settings) -> None:
    settings.VALI_BACKUP_BOOT_SETTLE_S = 61
    settings.VALI_BACKUP_BOOT_WAIT_MAX_S = 62
    settings.VALI_BACKUP_DOMAIN_GONE_GRACE_S = 63
    assert service._boot_settle().total_seconds() == 61
    assert service._boot_wait_max().total_seconds() == 62
    assert service._domain_gone_grace().total_seconds() == 63
