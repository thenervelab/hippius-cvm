"""`placement_decision_lock` — serializes "count the fleet" + "record the placement".

A scheduled launch decides on counts read at decision time — the boot cap
(gate (g), `booting_by_node`), the host's capacity / RAM / CPU / disk
budgets (`decision_inputs`, `host_budgets_by_node`, `disk_budgets_by_node`),
the owner sub-budget per miner (`owner_load_by_node`), the dedicated
disks still free — and then writes the `Pending` `Placement` that the next
decision counts. That is a read-then-write: two decisions interleaved
between the read and the write would both see the same free slot and both
take it.

The launch path (`launch._place_and_launch`) therefore takes this lock
around its decide → `Placement` INSERT step, and ONLY that step: the chain
snapshot read before it, and the Vault reads, the miner preflight and the
dispatch after it, all run unlocked and concurrently. The lock is released
by the COMMIT that publishes the `Pending` row, so the next holder always
counts it (READ COMMITTED: every statement after the lock sees it).

Postgres: a transaction-scoped advisory lock, so it is correct across
threads AND processes (a second launch-tick replica would serialize on
it too), and the server drops it if the holder dies. Waiting longer than
`DECISION_LOCK_TIMEOUT_S` raises `PlacementDecisionBusy` — a decision takes
well under a second, so a wait that long means a stuck holder, and the
launch should fail loudly rather than queue forever. Other backends (the
SQLite test DB): a process-local stand-in, like `allowlist_pin.pin_lock`.

Take it OUTSIDE any caller `atomic()` block: nested in one, it would be a
savepoint, and the lock would only be released by the OUTER commit.
"""

from __future__ import annotations

import threading
from collections.abc import Iterator
from contextlib import contextmanager

from django.db import OperationalError, connection, transaction

#: `pg_advisory_xact_lock` key, unique to this purpose ("plcdecd1" in ASCII).
#: Distinct from `allowlist_pin._PIN_LOCK_KEY`, `tenant_bake.locks` and
#: `synthetic.per_miner`.
_DECISION_LOCK_KEY = 0x706C636465636431

#: SQLSTATE of a `lock_timeout` expiry (`lock_not_available`).
_LOCK_NOT_AVAILABLE = "55P03"

#: Longest wait for the lock before a launch gives up on it.
DECISION_LOCK_TIMEOUT_S = 60.0

_PROCESS_LOCK = threading.Lock()


class PlacementDecisionBusy(RuntimeError):
    """Another placement decision held the lock past `DECISION_LOCK_TIMEOUT_S`."""


def _busy() -> PlacementDecisionBusy:
    return PlacementDecisionBusy(
        f"placement decision lock: held by another decision for over {DECISION_LOCK_TIMEOUT_S:.0f}s"
    )


@contextmanager
def placement_decision_lock() -> Iterator[None]:
    """Hold the placement-decision lock for the enclosed block, inside a
    transaction that commits when the block exits normally."""
    if connection.vendor != "postgresql":
        if not _PROCESS_LOCK.acquire(timeout=DECISION_LOCK_TIMEOUT_S):
            raise _busy()
        try:
            with transaction.atomic():
                yield
        finally:
            _PROCESS_LOCK.release()
        return
    with transaction.atomic():
        try:
            with connection.cursor() as cursor:
                cursor.execute(
                    "SELECT set_config('lock_timeout', %s, true)",
                    [f"{int(DECISION_LOCK_TIMEOUT_S * 1000)}ms"],
                )
                cursor.execute("SELECT pg_advisory_xact_lock(%s)", [_DECISION_LOCK_KEY])
                # The timeout is for THIS wait only: the row locks taken
                # under the lock (dedicated disks) keep the session's own.
                cursor.execute("SET LOCAL lock_timeout TO DEFAULT")
        except OperationalError as exc:
            # Only a lock timeout is "busy"; a dropped connection is itself.
            if getattr(exc.__cause__, "sqlstate", None) != _LOCK_NOT_AVAILABLE:
                raise
            raise _busy() from exc
        yield
