"""PR-S3: vali Postgres reader tests with a stubbed connection.

We don't spin up a real Postgres in CI — instead we hand the reader a
fake `psycopg`-compatible connection that returns canned rows. The
queries are SQL-string-asserted only loosely (specific predicates +
table names) so the LLM-facing output shape is what the test pins
down.
"""

from __future__ import annotations

import datetime as dt
from collections.abc import Sequence
from typing import Any

import pytest

import sentinel.tools.vali_postgres as vp

# ---------------------------------------------------------------------------
# Tiny psycopg stub
# ---------------------------------------------------------------------------


class _FakeCursor:
    """Cursor stub. `rows_for` is a callback that returns canned rows
    based on the SQL the test runs — keeps a single fake able to
    handle whichever query the helper issues."""

    def __init__(self, *, rows_for: Any, row_factory: Any = None) -> None:
        self._rows_for = rows_for
        self._rows: list[Any] = []
        self.last_sql: str | None = None
        self.last_params: tuple[Any, ...] | None = None

    def __enter__(self) -> _FakeCursor:
        return self

    def __exit__(self, *_exc: Any) -> None:
        return None

    def execute(self, sql: str, params: tuple[Any, ...] = ()) -> None:
        self.last_sql = sql
        self.last_params = tuple(params)
        self._rows = list(self._rows_for(sql))

    def fetchone(self) -> Any:
        return self._rows[0] if self._rows else None

    def fetchall(self) -> list[Any]:
        return list(self._rows)


class _FakeConn:
    """Records calls + returns canned rows depending on which SQL ran."""

    def __init__(
        self,
        *,
        vm_rows: Sequence[Any] = (),
        pending_count: int = 0,
        transitions: Sequence[Any] = (),
    ) -> None:
        self._vm_rows = list(vm_rows)
        self._pending_count = pending_count
        self._transitions = list(transitions)
        self.cursors: list[_FakeCursor] = []
        self.closed = False

    def _rows_for(self, sql: str) -> list[Any]:
        s = sql.lower()
        if "where vm_id = %s" in s:
            return self._vm_rows
        if "count(*)" in s:
            return [(self._pending_count,)]
        if "order by updated_at desc" in s:
            return self._transitions
        return []

    def cursor(self, row_factory: Any = None) -> _FakeCursor:
        cur = _FakeCursor(rows_for=self._rows_for, row_factory=row_factory)
        self.cursors.append(cur)
        return cur

    def close(self) -> None:
        self.closed = True


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def patched_connector(
    monkeypatch: pytest.MonkeyPatch,
) -> list[_FakeConn]:
    """Patch the module-level `_open()` to return whatever the test
    pushes into the returned list. Tests `append` a `_FakeConn`
    per intended query."""

    conns: list[_FakeConn] = []

    def fake_open() -> _FakeConn:
        if not conns:
            raise AssertionError("test did not push a fake connection")
        return conns.pop(0)

    monkeypatch.setattr(vp, "_open", fake_open)
    return conns


# ---------------------------------------------------------------------------
# query_vm_state
# ---------------------------------------------------------------------------


def test_query_vm_state_found(patched_connector: list[_FakeConn]) -> None:
    ts = dt.datetime(2026, 5, 20, 12, 0, 0, tzinfo=dt.UTC)
    patched_connector.append(
        _FakeConn(
            vm_rows=[
                {
                    "vm_id": "vm-1",
                    "state": "active",
                    "generation": 4,
                    "host": "host-a",
                    "migration_dest": "",
                    "new_generation": None,
                    "lease_id": "lease-xyz",
                    "version": 7,
                    "updated_at": ts,
                }
            ]
        )
    )
    out = vp.query_vm_state("vm-1")
    assert out["found"] is True
    assert out["vm_id"] == "vm-1"
    assert out["state"] == "active"
    assert out["generation"] == 4
    assert out["host"] == "host-a"
    assert out["migration_dest"] is None  # empty string normalized to None
    assert out["new_generation"] is None
    assert out["lease_id"] == "lease-xyz"
    assert out["version"] == 7
    assert out["updated_at"] == ts.isoformat()


def test_query_vm_state_not_found(patched_connector: list[_FakeConn]) -> None:
    patched_connector.append(_FakeConn(vm_rows=[]))  # empty result set
    out = vp.query_vm_state("vm-missing")
    assert out == {"found": False, "vm_id": "vm-missing"}


def test_query_vm_state_sql_targets_lifecycle_vm(
    patched_connector: list[_FakeConn],
) -> None:
    fake = _FakeConn(vm_rows=[])
    patched_connector.append(fake)
    vp.query_vm_state("vm-x")
    assert len(fake.cursors) == 1
    sql = fake.cursors[0].last_sql or ""
    assert "lifecycle_vm" in sql
    assert "WHERE vm_id = %s" in sql
    assert fake.cursors[0].last_params == ("vm-x",)


# ---------------------------------------------------------------------------
# count_pending_tickets
# ---------------------------------------------------------------------------


def test_count_pending_tickets_returns_int(patched_connector: list[_FakeConn]) -> None:
    fake = _FakeConn(pending_count=42)
    patched_connector.append(fake)
    out = vp.count_pending_tickets()
    assert out == {"pending_count": 42}
    sql = (fake.cursors[0].last_sql or "").lower()
    # The proxy query joins ticket intake with lifecycle_vm and filters
    # on expiry. Spot-check those invariants.
    assert "orders_orderticketintake" in sql
    assert "lifecycle_vm" in sql
    assert "left join" in sql
    assert "expiry" in sql


# ---------------------------------------------------------------------------
# list_recent_state_transitions
# ---------------------------------------------------------------------------


def test_list_recent_state_transitions_caps_limit(
    patched_connector: list[_FakeConn],
) -> None:
    ts = dt.datetime(2026, 5, 20, 12, 0, 0, tzinfo=dt.UTC)
    rows = [
        {
            "vm_id": f"vm-{i}",
            "state": "active",
            "generation": 1,
            "host": "host-a",
            "migration_dest": "",
            "new_generation": None,
            "version": 1,
            "updated_at": ts,
        }
        for i in range(3)
    ]
    fake = _FakeConn(transitions=rows)
    patched_connector.append(fake)
    out = vp.list_recent_state_transitions(50)
    assert len(out) == 3
    assert out[0]["vm_id"] == "vm-0"
    assert out[0]["migration_dest"] is None
    assert (fake.cursors[0].last_params or ())[0] == 50

    # Limit is bounded.
    fake2 = _FakeConn(transitions=rows)
    patched_connector.append(fake2)
    vp.list_recent_state_transitions(10_000)
    assert (fake2.cursors[0].last_params or ())[0] == vp.MAX_TRANSITIONS_LIMIT


def test_list_recent_state_transitions_zero_or_negative_returns_empty(
    patched_connector: list[_FakeConn],
) -> None:
    # No connection should be opened when limit <= 0.
    assert vp.list_recent_state_transitions(0) == []
    assert vp.list_recent_state_transitions(-5) == []


def test_query_helpers_close_owned_connection(
    patched_connector: list[_FakeConn],
) -> None:
    """Each top-level helper owns its connection and closes it."""

    fake = _FakeConn(vm_rows=[])
    patched_connector.append(fake)
    vp.query_vm_state("vm-x")
    assert fake.closed is True

    fake2 = _FakeConn(pending_count=0)
    patched_connector.append(fake2)
    vp.count_pending_tickets()
    assert fake2.closed is True

    fake3 = _FakeConn(transitions=[])
    patched_connector.append(fake3)
    vp.list_recent_state_transitions(1)
    assert fake3.closed is True


# ---------------------------------------------------------------------------
# Config / env validation
# ---------------------------------------------------------------------------


def test_connector_requires_env_var(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(vp.ENV_DSN, raising=False)
    with pytest.raises(RuntimeError, match=vp.ENV_DSN):
        vp._connector()


def test_connector_uses_env_dsn(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(vp.ENV_DSN, "postgresql://ro:ro@replica/vali")
    c = vp._connector()
    assert c.dsn == "postgresql://ro:ro@replica/vali"
