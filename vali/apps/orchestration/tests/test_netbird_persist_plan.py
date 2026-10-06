"""`vali_netbird_persist_plan`: only an active VM's connected ephemeral
peer qualifies; the command is read-only."""

from __future__ import annotations

from io import StringIO

import pytest
from django.core.management import call_command

from apps.orchestration import effects
from apps.orchestration.management.commands import vali_netbird_persist_plan as cmd

pytestmark = pytest.mark.django_db

ID = "daqgm6336cos73bu2ao0"


def _peer(**kw):
    base = {"id": ID, "name": "hippius-tenant-vm-a", "ephemeral": True, "connected": True}
    base.update(kw)
    return base


@pytest.mark.parametrize(
    ("peer", "states", "action", "reason"),
    [
        (_peer(), {"vm-a": "active"}, "convert", "active-connected-ephemeral"),
        (
            _peer(connected=False),
            {"vm-a": "active"},
            "skip",
            "disconnected-may-be-queued-for-deletion",
        ),
        (_peer(ephemeral=False), {"vm-a": "active"}, "skip", "already-persistent"),
        (_peer(), {"vm-a": "destroyed"}, "skip", "vm-not-active:destroyed"),
        (_peer(), {}, "skip", "vm-not-active:no-row"),
        (_peer(id="x'; DROP TABLE peers;--"), {"vm-a": "active"}, "skip", "malformed-peer-id"),
    ],
)
def test_the_plan(peer, states, action, reason) -> None:
    (v,) = cmd.plan([peer], states)
    assert (v.action, v.reason) == (action, reason)


def test_non_tenant_peers_are_ignored() -> None:
    assert cmd.plan([_peer(name="miner-a")], {"vm-a": "active"}) == []


def test_the_sql_is_guarded_and_reversible() -> None:
    assert cmd.sql([ID], ephemeral=False) == (
        f"UPDATE peers SET ephemeral = false WHERE id IN ('{ID}') AND ephemeral = true;"
    )
    assert cmd.sql([ID], ephemeral=True).endswith("AND ephemeral = false;")


def test_the_command_prints_the_plan_and_changes_nothing(monkeypatch) -> None:
    from apps.orchestration.tests.factories import make_vm

    make_vm("vm-a")
    monkeypatch.setattr(effects, "list_netbird_peers", lambda: [_peer()])
    deleted: list = []
    monkeypatch.setattr(
        effects, "delete_netbird_peer", lambda *a, **k: deleted.append(a), raising=False
    )
    out = StringIO()
    call_command("vali_netbird_persist_plan", stdout=out)
    text = out.getvalue()
    assert "READ-ONLY: 1 peer(s) qualify" in text
    assert f"WHERE id IN ('{ID}') AND ephemeral = true;" in text
    assert deleted == []
