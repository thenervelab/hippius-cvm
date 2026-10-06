"""`bake_queue_lock` — serializes "is a bake in flight?" + "INSERT a bake".

The scheduled golden re-bake (F6) must never queue a bake next to another
one: concurrent baker pods race on loop devices and fail. Its "nothing in
flight → INSERT" is a read-then-write, so another creator inserting in
between would slip a second bake in. Every creator therefore inserts
under this lock:

- `apps.images.rebake` holds it across the in-flight check AND its INSERT;
- `TenantBakeCreateView` (`POST /v1/tenant-bakes`) and
  `vali_tenant_bake_create` hold it around their INSERT.

A creator that does not check (the HTTP view) is still ordered: its row
lands either before the re-bake's check (which then sees it and waits) or
after the re-bake's INSERT (and `vali_bake_spawn`'s serial gate holds it
until the re-bake is terminal). The lock is held only for a SELECT + an
INSERT, never across a bake.

Postgres: a transaction-scoped advisory lock (released by the COMMIT that
publishes the row, or by the server if the process dies). Other backends
(the SQLite test DB): a process-local lock — the same stand-in
`allowlist_pin.pin_lock` uses.
"""

from __future__ import annotations

import threading
from collections.abc import Iterator
from contextlib import contextmanager

from django.db import connection, transaction

# Distinct from allowlist_pin._PIN_LOCK_KEY. ASCII "bakeque1".
_BAKE_QUEUE_LOCK_KEY = 0x62616B6571756531
_PROCESS_LOCK = threading.Lock()


@contextmanager
def bake_queue_lock() -> Iterator[None]:
    """Hold the bake-queue lock for the enclosed block, inside a
    transaction. Take it OUTSIDE any caller `atomic()` block, so the lock
    and the INSERT commit together."""
    if connection.vendor != "postgresql":
        with _PROCESS_LOCK, transaction.atomic():
            yield
        return
    with transaction.atomic():
        with connection.cursor() as cursor:
            cursor.execute("SELECT pg_advisory_xact_lock(%s)", [_BAKE_QUEUE_LOCK_KEY])
        yield
