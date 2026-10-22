"""`vali_synthetic_monitor --tier per-miner`: off pushes nothing; on, a
probe that reached its miner pushes the per-miner run group, and every
run pushes the fleet readout — under names the full tier's alerts never
match."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import Any

import pytest
from django.core.management import call_command

from apps.scheduler.tests.factories import node_id
from apps.synthetic import e2e, per_miner
from apps.synthetic import metrics as metrics_mod

pytestmark = pytest.mark.django_db

AT = datetime(2026, 10, 21, 12, 0, tzinfo=UTC)


@pytest.fixture
def pushed(monkeypatch: pytest.MonkeyPatch) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []

    def fake_push(ms: metrics_mod.MetricSet, **kw: Any) -> bool:
        out.append(
            {"grouping_key": kw["grouping_key"], "replace": kw["replace"], "text": ms.render()}
        )
        return True

    monkeypatch.setattr(metrics_mod, "push", fake_push)
    return out


def _view(seed: int, *, blocked: str = "", probed: datetime | None = None) -> per_miner.MinerView:
    return per_miner.MinerView(
        node_id=node_id(seed),
        miner_id=f"miner-{seed:02d}",
        platform_id="ab" * 16,
        blocked=blocked,
        last_attempt_at=probed,
        last_probe_at=probed,
    )


def _report(verdict: str, *, success: bool, stage: str = "boot") -> per_miner.TickReport:
    view = _view(1)
    stages = [e2e.StageResult("launch", True, 1.0, "ok")]
    if not success:
        stages.append(e2e.StageResult(stage, False, 2.0, "boom"))
    outcome = e2e.E2EOutcome("ubuntu", "synmon-pm-x-1", success=success, stages=stages)
    return per_miner.TickReport(
        enabled=True,
        universe=2,
        claim=per_miner.Claim(view=view, vm_id="synmon-pm-x-1"),
        outcome=outcome,
        verdict=verdict,
    )


def _fleet(monkeypatch: pytest.MonkeyPatch) -> None:
    rows = [
        per_miner.FleetRow(view=_view(1, probed=AT), fail_streak=2, last_ok=False),
        per_miner.FleetRow(view=_view(2, blocked="capacity"), fail_streak=0, last_ok=None),
    ]
    monkeypatch.setattr(per_miner, "fleet_readout", lambda now: rows)


def test_off_pushes_nothing(settings: Any, pushed: list, monkeypatch) -> None:
    settings.VALI_SYNTHETIC_PER_MINER = False
    monkeypatch.setattr(per_miner, "tick", lambda **k: pytest.fail("ran while off"))
    call_command("vali_synthetic_monitor", "--tier", "per-miner")
    assert pushed == []


def test_a_failed_probe_pushes_the_miner_group_and_the_fleet(
    settings: Any, pushed: list, monkeypatch, capsys
) -> None:
    settings.VALI_SYNTHETIC_PER_MINER = True
    settings.VALI_GUEST_ATTEST_RESOURCES = True
    monkeypatch.setattr(
        per_miner, "tick", lambda **k: _report(per_miner.VERDICT_FAILED, success=False)
    )
    _fleet(monkeypatch)
    call_command("vali_synthetic_monitor", "--tier", "per-miner", "--json")

    run, fleet = pushed
    assert run["grouping_key"] == {"tier": "per-miner", "miner": "miner-01"}
    assert run["replace"] is False  # failure → POST, the last-success ts survives
    assert "hippius_synthetic_miner_probe_success 0" in run["text"]
    assert 'hippius_synthetic_miner_probe_stage_success{stage="boot"} 0' in run["text"]
    assert 'hippius_synthetic_miner_probe_stage_success{stage="launch"} 1' in run["text"]
    assert 'stage="resources"' in run["text"]  # checked ⇒ reported
    assert "hippius_synthetic_miner_probe_last_success_timestamp" not in run["text"]
    # Never the full tier's names: its critical alerts key on them.
    assert "hippius_synthetic_e2e_success" not in run["text"]
    assert "hippius_synthetic_last_success_timestamp" not in run["text"]

    assert fleet["grouping_key"] == {"tier": "per-miner-fleet"}
    assert fleet["replace"] is True
    text = fleet["text"]
    ts = int(AT.timestamp())
    assert f'hippius_synthetic_miner_last_probe_timestamp{{miner="miner-01"}} {ts}' in text
    assert 'hippius_synthetic_miner_last_probe_timestamp{miner="miner-02"} 0' in text
    assert 'hippius_synthetic_miner_probe_fail_streak{miner="miner-01"} 2' in text
    assert 'hippius_synthetic_miner_probe_blocked{miner="miner-02",reason="capacity"} 1' in text
    assert 'miner="miner-01",reason=' not in text
    assert "hippius_synthetic_per_miner_universe 2" in text
    assert "hippius_synthetic_per_miner_config_error 0" in text

    payload = json.loads(capsys.readouterr().out)
    assert payload["verdict"] == "failed" and payload["miner_id"] == "miner-01"


def test_a_pass_replaces_the_miner_group(settings: Any, pushed: list, monkeypatch) -> None:
    settings.VALI_SYNTHETIC_PER_MINER = True
    settings.VALI_GUEST_ATTEST_RESOURCES = False
    monkeypatch.setattr(per_miner, "tick", lambda **k: _report(per_miner.VERDICT_OK, success=True))
    _fleet(monkeypatch)
    call_command("vali_synthetic_monitor", "--tier", "per-miner")
    run = pushed[0]
    assert run["replace"] is True
    assert "hippius_synthetic_miner_probe_success 1" in run["text"]
    assert "hippius_synthetic_miner_probe_last_success_timestamp" in run["text"]
    assert 'stage="resources"' not in run["text"]  # not checked ⇒ not reported as 0


def test_an_inconclusive_probe_touches_no_miner_series(
    settings: Any, pushed: list, monkeypatch
) -> None:
    settings.VALI_SYNTHETIC_PER_MINER = True
    monkeypatch.setattr(
        per_miner,
        "tick",
        lambda **k: _report(per_miner.VERDICT_INCONCLUSIVE, success=False, stage="launch_complete"),
    )
    _fleet(monkeypatch)
    call_command("vali_synthetic_monitor", "--tier", "per-miner")
    assert [p["grouping_key"] for p in pushed] == [{"tier": "per-miner-fleet"}]


def test_a_misconfiguration_is_alertable(settings: Any, pushed: list, monkeypatch) -> None:
    settings.VALI_SYNTHETIC_PER_MINER = True
    monkeypatch.setattr(
        per_miner, "tick", lambda **k: per_miner.TickReport(enabled=True, error="no token")
    )
    _fleet(monkeypatch)
    call_command("vali_synthetic_monitor", "--tier", "per-miner")
    assert "hippius_synthetic_per_miner_config_error 1" in pushed[0]["text"]
