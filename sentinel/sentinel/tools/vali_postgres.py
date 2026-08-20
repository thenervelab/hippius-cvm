"""Vali Postgres read-only reader (PR-S3).

Connects to the vali Postgres via a read-only DSN
(`VALI_DATABASE_READONLY_URL`). The expectation is that the DSN already
points at a replica OR at a role with no write grants — but as a
belt-and-suspenders precaution every connection is opened with
`default_transaction_read_only=on`, so even a misconfigured DSN
(pointing at primary as a write-able role) still cannot mutate state
from the sentinel pod.

## Tools (registered on the agent)

  - `query_vm_state(vm_id)` — current row from `lifecycle_vm` (see
    `vali/apps/lifecycle/models.py::Vm`), or {found: false} if absent.
  - `count_pending_tickets()` — OrderTicketIntake rows whose `vm_id`
    has no matching `lifecycle_vm` row and whose `expiry > now()`.
    PR-G5+ will own a dedicated state column; until then this LEFT
    JOIN is the closest proxy for "intake recorded, not yet
    provisioned" — see the discussion in #57 PR-S3.
  - `list_recent_state_transitions(limit=50)` — last N rows of
    `lifecycle_vm` ordered by `updated_at DESC`. The schema doesn't
    keep a transition log; this is the standing proxy until one is
    added.

## Pool

`psycopg.connect` is invoked per call. That's intentional for PR-S3 —
the sentinel patrol cadence is in the minutes, not the seconds, and a
short-lived connection keeps the failure mode obvious (DSN bad =
error every call, not a stale pool). PR-S6 will revisit if cadence
tightens.
"""

from __future__ import annotations

import json
import logging
import os
from dataclasses import dataclass
from typing import Any

import psycopg
from claude_agent_sdk import tool
from psycopg.rows import dict_row

log = logging.getLogger("sentinel.tools.vali_postgres")

ENV_DSN = "VALI_DATABASE_READONLY_URL"

# Tables we read. Matching `vali/apps/lifecycle/models.py` +
# `vali/apps/orders/models.py` Django default naming.
TBL_VM = "lifecycle_vm"
TBL_ORDER = "orders_orderticketintake"

# Bounded fan-out on list endpoints.
MAX_TRANSITIONS_LIMIT = 500


@dataclass(frozen=True)
class _Connector:
    """Injection seam — production passes `_DefaultConnector`, tests
    pass a fake that hands back a stub psycopg-compatible connection.
    """

    dsn: str

    def connect(self) -> psycopg.Connection:
        # `autocommit=True` so the read-only flag below applies to
        # every statement, not just whatever a manual BEGIN would
        # cover. We never write, so commit/rollback distinctions are
        # moot, but the autocommit flag avoids opening an idle txn
        # against the replica.
        return psycopg.connect(
            self.dsn,
            autocommit=True,
            options="-c default_transaction_read_only=on",
        )


def _connector(override: str | None = None) -> _Connector:
    if override is not None:
        return _Connector(dsn=override)
    raw = os.environ.get(ENV_DSN, "").strip()
    if not raw:
        raise RuntimeError(
            f"{ENV_DSN} is not set; PR-S3 vali Postgres reader cannot connect."
        )
    return _Connector(dsn=raw)


# Test seam — set in `tests/conftest.py` to a callable that returns a
# psycopg-compatible Connection. Production code never sets this.
_OVERRIDE_CONNECTOR: _Connector | None = None


def _open() -> psycopg.Connection:
    if _OVERRIDE_CONNECTOR is not None:
        return _OVERRIDE_CONNECTOR.connect()
    return _connector().connect()


# ---------------------------------------------------------------------------
# Query helpers
# ---------------------------------------------------------------------------


def query_vm_state(vm_id: str, *, conn: psycopg.Connection | None = None) -> dict[str, Any]:
    """Return the current `lifecycle_vm` row for `vm_id`.

    Output schema (stable; LLM-facing):

        {
          "found": bool,
          "vm_id": str,
          "state": str|None,
          "generation": int|None,
          "host": str|None,
          "migration_dest": str|None,
          "new_generation": int|None,
          "lease_id": str|None,
          "version": int|None,
          "updated_at": str|None,   # ISO-8601 UTC
        }
    """

    sql = (
        f'SELECT vm_id, state, generation, host, migration_dest, '
        f'new_generation, lease_id, version, updated_at '
        f'FROM {TBL_VM} WHERE vm_id = %s LIMIT 1'
    )
    own_conn = conn is None
    c = conn or _open()
    try:
        with c.cursor(row_factory=dict_row) as cur:
            cur.execute(sql, (vm_id,))
            row = cur.fetchone()
    finally:
        if own_conn:
            c.close()
    if row is None:
        return {"found": False, "vm_id": vm_id}
    return {
        "found": True,
        "vm_id": row["vm_id"],
        "state": row["state"],
        "generation": int(row["generation"]) if row["generation"] is not None else None,
        "host": row["host"] or None,
        "migration_dest": row["migration_dest"] or None,
        "new_generation": (
            int(row["new_generation"]) if row["new_generation"] is not None else None
        ),
        "lease_id": row["lease_id"] or None,
        "version": int(row["version"]) if row["version"] is not None else None,
        "updated_at": row["updated_at"].isoformat() if row["updated_at"] else None,
    }


def count_pending_tickets(*, conn: psycopg.Connection | None = None) -> dict[str, Any]:
    """Count OrderTicketIntake rows that look pending.

    "Pending" = no matching `lifecycle_vm.vm_id` AND `expiry` is in
    the future. This is the closest proxy until PR-G5+ adds an
    explicit ticket-status column (see #57 / PR-S3 discussion).
    """

    sql = (
        f"SELECT count(*) AS n FROM {TBL_ORDER} o "
        f"LEFT JOIN {TBL_VM} v ON v.vm_id = o.vm_id "
        f"WHERE v.id IS NULL "
        f"  AND o.expiry > EXTRACT(EPOCH FROM NOW())::bigint"
    )
    own_conn = conn is None
    c = conn or _open()
    try:
        with c.cursor() as cur:
            cur.execute(sql)
            (n,) = cur.fetchone()
    finally:
        if own_conn:
            c.close()
    return {"pending_count": int(n)}


def list_recent_state_transitions(
    limit: int = 50, *, conn: psycopg.Connection | None = None
) -> list[dict[str, Any]]:
    """Return the most-recently-updated `lifecycle_vm` rows."""

    if limit <= 0:
        return []
    limit = min(limit, MAX_TRANSITIONS_LIMIT)
    sql = (
        f"SELECT vm_id, state, generation, host, migration_dest, "
        f"new_generation, version, updated_at "
        f"FROM {TBL_VM} ORDER BY updated_at DESC LIMIT %s"
    )
    own_conn = conn is None
    c = conn or _open()
    try:
        with c.cursor(row_factory=dict_row) as cur:
            cur.execute(sql, (limit,))
            rows = cur.fetchall()
    finally:
        if own_conn:
            c.close()
    return [
        {
            "vm_id": r["vm_id"],
            "state": r["state"],
            "generation": int(r["generation"]) if r["generation"] is not None else None,
            "host": r["host"] or None,
            "migration_dest": r["migration_dest"] or None,
            "new_generation": (
                int(r["new_generation"]) if r["new_generation"] is not None else None
            ),
            "version": int(r["version"]) if r["version"] is not None else None,
            "updated_at": r["updated_at"].isoformat() if r["updated_at"] else None,
        }
        for r in rows
    ]


# ---------------------------------------------------------------------------
# Agent-facing MCP tool wrappers
# ---------------------------------------------------------------------------


def _structured_error(msg: str) -> dict[str, Any]:
    return {"content": [{"type": "text", "text": msg}], "isError": True}


def _structured_text(payload: Any) -> dict[str, Any]:
    return {
        "content": [
            {"type": "text", "text": json.dumps(payload, sort_keys=True, default=str)}
        ]
    }


async def _query_vm_state_impl(args: dict[str, Any]) -> dict[str, Any]:
    vm_id = args.get("vm_id")
    if not isinstance(vm_id, str) or not vm_id:
        return _structured_error("query_vm_state requires a non-empty vm_id string")
    try:
        row = query_vm_state(vm_id)
    except psycopg.Error as e:
        log.warning("query_vm_state: database error: %s", e)
        return _structured_error(f"vali postgres error: {e}")
    except Exception as e:  # noqa: BLE001
        log.exception("query_vm_state: unexpected failure")
        return _structured_error(f"query_vm_state failed: {e}")
    return _structured_text(row)


async def _count_pending_tickets_impl(_args: dict[str, Any]) -> dict[str, Any]:
    try:
        result = count_pending_tickets()
    except psycopg.Error as e:
        log.warning("count_pending_tickets: database error: %s", e)
        return _structured_error(f"vali postgres error: {e}")
    except Exception as e:  # noqa: BLE001
        log.exception("count_pending_tickets: unexpected failure")
        return _structured_error(f"count_pending_tickets failed: {e}")
    return _structured_text(result)


async def _list_recent_state_transitions_impl(args: dict[str, Any]) -> dict[str, Any]:
    raw_limit = args.get("limit", 50)
    try:
        limit = int(raw_limit)
    except (TypeError, ValueError):
        return _structured_error(f"limit must be an int, got {raw_limit!r}")
    try:
        rows = list_recent_state_transitions(limit)
    except psycopg.Error as e:
        log.warning("list_recent_state_transitions: database error: %s", e)
        return _structured_error(f"vali postgres error: {e}")
    except Exception as e:  # noqa: BLE001
        log.exception("list_recent_state_transitions: unexpected failure")
        return _structured_error(f"list_recent_state_transitions failed: {e}")
    return _structured_text({"returned_count": len(rows), "rows": rows})


query_vm_state_tool = tool(
    "query_vm_state",
    "Return the current vali lifecycle row for a VM. Reads "
    "`lifecycle_vm` read-only. Output is `{found, vm_id, state, "
    "generation, host, migration_dest, new_generation, lease_id, "
    "version, updated_at}`.",
    {"vm_id": str},
)(_query_vm_state_impl)


count_pending_tickets_tool = tool(
    "count_pending_tickets",
    "Count OrderTicketIntake rows whose vm_id has no matching "
    "lifecycle_vm row and whose expiry is in the future. Proxy "
    "for 'tickets received but not yet provisioned'.",
    {},
)(_count_pending_tickets_impl)


list_recent_state_transitions_tool = tool(
    "list_recent_state_transitions",
    "Return the N most-recently-updated lifecycle_vm rows (default "
    "50, max 500). Approximates a transition log — schema doesn't "
    "store one yet.",
    {"limit": int},
)(_list_recent_state_transitions_impl)
