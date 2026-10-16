"""The §14 idempotency-key store, in vali's Postgres.

The §24/§25 orchestrator advances a job one step per tick. A tick that
crashes after an external side-effect but before the job's state CAS would
re-run the side-effect. Every side-effectful step is therefore wrapped:
`recall` before (skip if already done), `record` after.

The store used to be `kbs_core::persist::FileIdempotencyStore` behind a
shell-out, on the tick pod's `/tmp` — an emptyDir every pod replacement
wiped, and that no other pod (a management command, the web pod) could
read. It is now a table (`IdempotencyRecord`): durable across restarts,
shared by every vali pod, with the same semantics:

- `record` creates the entry atomically — exactly one of several racing
  writers gets `True` (the primary key decides); the others `False`, a
  benign replay;
- `recall` answers the recorded hash while the entry is younger than
  `VALI_IDEMPOTENCY_TTL_SECS`, else `None` (an expired entry reads as
  absent, and the next `record` of its key takes it over);
- `purge_expired` deletes what no `recall` can return any more (the
  orchestration tick runs it, at most hourly).

A database failure raises `IdempotencyUnavailable`, as a store I/O error did:
the orchestrator treats the guarded step as failed this tick and retries.
"""

from __future__ import annotations

import hashlib
import logging
import time
from datetime import timedelta

from django.conf import settings
from django.db import DatabaseError, IntegrityError, transaction
from django.utils import timezone

log = logging.getLogger("apps.orchestration.idempotency")

#: The longest key the table holds (`IdempotencyRecord.key`).
MAX_KEY_LEN = 255
#: How often `purge_expired_throttled` actually purges.
PURGE_INTERVAL_S = 3600.0

_last_purge: float | None = None


class IdempotencyUnavailable(Exception):
    """The idempotency store could not be reached (a database error, a key
    it cannot hold). The orchestrator treats a guarded step as
    failed-this-tick and retries.
    """


def _ttl() -> timedelta:
    return timedelta(seconds=int(getattr(settings, "VALI_IDEMPOTENCY_TTL_SECS", 86_400)))


def _check(key: str) -> None:
    if not isinstance(key, str) or not key or len(key) > MAX_KEY_LEN:
        size = len(key) if isinstance(key, str) else 0
        raise IdempotencyUnavailable(f"idempotency key of {size} chars (1..{MAX_KEY_LEN})")


def recall(key: str) -> str | None:
    """Return the recorded response-hash hex for `key`, or `None` if the key
    was never recorded (or its TTL elapsed)."""
    from .models import IdempotencyRecord

    _check(key)
    try:
        return (
            IdempotencyRecord.objects.filter(
                key=key, recorded_at__gte=timezone.now() - _ttl()
            )
            .values_list("response_hash", flat=True)
            .first()
        )
    except DatabaseError as exc:
        raise IdempotencyUnavailable(f"idempotency recall failed: {exc}") from exc


def record(key: str, response_hash_hex: str) -> bool:
    """Record `(key → response_hash)`. Returns `True` when THIS call wrote
    the entry, `False` when the key was already present (a benign
    concurrent-tick replay — the step is already done). An expired entry is
    taken over, as if absent (the file store refused it, and nothing reads
    this return value). A purge removing the expired row between the
    create and the takeover is retried once, so the step is recorded."""
    from .models import IdempotencyRecord

    _check(key)
    try:
        # Twice at most: a purge can delete the expired row between the
        # failed create and the takeover UPDATE — the second pass then
        # creates it.
        for _ in range(2):
            now = timezone.now()
            try:
                # A savepoint: a duplicate key must not break a caller's
                # transaction.
                with transaction.atomic():
                    IdempotencyRecord.objects.create(
                        key=key, response_hash=response_hash_hex, recorded_at=now
                    )
                return True
            except IntegrityError:
                pass
            # Present. Taken over only if it expired — a conditional UPDATE,
            # so two writers racing for an expired key cannot both win.
            if IdempotencyRecord.objects.filter(key=key, recorded_at__lt=now - _ttl()).update(
                response_hash=response_hash_hex, recorded_at=now
            ):
                return True
            if IdempotencyRecord.objects.filter(key=key).exists():
                return False  # a live entry: a replay
        return False
    except DatabaseError as exc:
        raise IdempotencyUnavailable(f"idempotency record failed: {exc}") from exc


def purge_expired() -> int:
    """Delete the entries no `recall` can return any more. Returns how many."""
    from .models import IdempotencyRecord

    deleted, _ = IdempotencyRecord.objects.filter(
        recorded_at__lt=timezone.now() - _ttl()
    ).delete()
    return deleted


def purge_expired_throttled() -> int:
    """`purge_expired`, at most once per `PURGE_INTERVAL_S` per process."""
    global _last_purge
    if _last_purge is not None and time.monotonic() - _last_purge < PURGE_INTERVAL_S:
        return 0
    _last_purge = time.monotonic()
    n = purge_expired()
    if n:
        log.info("idempotency: purged %d expired entries", n)
    return n


def marker_hash(key: str) -> str:
    """Deterministic 32-byte (hex) marker for steps with no meaningful
    response to dedup against — the idempotency entry only needs to
    record *that the step ran*, not a re-derivable response.
    """
    return hashlib.sha256(f"orchestration-step:{key}".encode()).hexdigest()
