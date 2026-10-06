"""The orchestration tick drives the backup tick and survives its failure."""

from __future__ import annotations

import pytest

from apps.backup import service as backup_service
from apps.orchestration import service

pytestmark = pytest.mark.django_db


def test_tick_once_runs_the_backup_tick(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(backup_service, "tick", lambda: backup_service.BackupTickReport(started=2))
    assert service.tick_once().backup_runs_started == 2


def test_a_backup_tick_crash_does_not_break_the_orchestration_tick(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def boom() -> backup_service.BackupTickReport:
        raise RuntimeError("boom")

    monkeypatch.setattr(backup_service, "tick", boom)
    assert service.tick_once().backup_runs_started == 0
