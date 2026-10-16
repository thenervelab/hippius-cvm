"""The §14 idempotency store (`IdempotencyRecord`, Postgres).

`real_idempotency` opts these tests out of the in-memory
`_mock_idempotency` autouse fixture.
"""

from __future__ import annotations

import threading
from datetime import timedelta

import pytest
from django.db import connection, connections
from django.utils import timezone

from apps.orchestration import idempotency
from apps.orchestration.idempotency import IdempotencyUnavailable
from apps.orchestration.models import IdempotencyRecord

pytestmark = [pytest.mark.real_idempotency, pytest.mark.django_db]


def test_recall_of_an_unknown_key_is_none() -> None:
    assert idempotency.recall("migration:never-recorded:step") is None


def test_record_then_recall_round_trips() -> None:
    key = "migration:job-abc:fencing"
    response_hash = idempotency.marker_hash(key)
    assert idempotency.record(key, response_hash) is True
    assert idempotency.recall(key) == response_hash


def test_recording_the_same_key_twice_reports_replay() -> None:
    key = "decommission:job-xyz:crypto-erase"
    assert idempotency.record(key, idempotency.marker_hash(key)) is True
    # The second record is a benign replay — `recorded` is False.
    assert idempotency.record(key, "0" * 64) is False
    assert idempotency.recall(key) == idempotency.marker_hash(key), "the first one stands"


def test_a_duplicate_does_not_break_the_callers_transaction() -> None:
    from django.db import transaction

    key = "migration:job-tx:step"
    idempotency.record(key, "a" * 64)
    with transaction.atomic():
        assert idempotency.record(key, "b" * 64) is False
        # The transaction is still usable.
        assert IdempotencyRecord.objects.filter(key=key).count() == 1


def test_an_expired_entry_reads_absent_and_is_taken_over(settings) -> None:
    settings.VALI_IDEMPOTENCY_TTL_SECS = 60
    key = "migration:job-old:step"
    idempotency.record(key, "a" * 64)
    IdempotencyRecord.objects.filter(key=key).update(
        recorded_at=timezone.now() - timedelta(seconds=61)
    )
    assert idempotency.recall(key) is None
    assert idempotency.record(key, "b" * 64) is True
    assert idempotency.recall(key) == "b" * 64


def test_purge_deletes_only_expired_entries(settings) -> None:
    settings.VALI_IDEMPOTENCY_TTL_SECS = 60
    idempotency.record("k:fresh", "a" * 64)
    idempotency.record("k:old", "a" * 64)
    IdempotencyRecord.objects.filter(key="k:old").update(
        recorded_at=timezone.now() - timedelta(seconds=120)
    )
    assert idempotency.purge_expired() == 1
    assert list(IdempotencyRecord.objects.values_list("key", flat=True)) == ["k:fresh"]


def test_the_purge_is_throttled(monkeypatch) -> None:
    monkeypatch.setattr(idempotency, "_last_purge", None)
    calls: list[int] = []
    monkeypatch.setattr(idempotency, "purge_expired", lambda: calls.append(1) or 0)
    idempotency.purge_expired_throttled()
    idempotency.purge_expired_throttled()
    assert calls == [1]


@pytest.mark.parametrize("key", ["", None, "k" * (idempotency.MAX_KEY_LEN + 1)])
def test_a_key_the_table_cannot_hold_is_unavailable(key: str) -> None:
    with pytest.raises(IdempotencyUnavailable):
        idempotency.recall(key)
    with pytest.raises(IdempotencyUnavailable):
        idempotency.record(key, "a" * 64)


def test_a_database_failure_is_unavailable(monkeypatch) -> None:
    from django.db import DatabaseError

    def boom(*a, **k):
        raise DatabaseError("db down")

    monkeypatch.setattr(IdempotencyRecord.objects, "filter", boom)
    with pytest.raises(IdempotencyUnavailable):
        idempotency.recall("k:any")


def test_marker_hash_is_deterministic_and_32_bytes() -> None:
    key = "migration:job-1:quiescing"
    h1 = idempotency.marker_hash(key)
    h2 = idempotency.marker_hash(key)
    assert h1 == h2
    assert len(h1) == 64  # 32 bytes, hex
    assert idempotency.marker_hash("other-key") != h1


@pytest.mark.django_db(transaction=True)
def test_two_pods_racing_for_one_key_exactly_one_wins() -> None:
    """Two processes (here two connections) record the same step at once:
    the primary key lets exactly one write it."""
    if connection.vendor != "postgresql":
        pytest.skip("needs two connections to one DB (Postgres lane)")
    key = "migration:job-race:dispatch"
    barrier = threading.Barrier(8)
    results: list[bool] = []
    lock = threading.Lock()

    def racer(i: int) -> None:
        try:
            barrier.wait(5)
            won = idempotency.record(key, f"{i:064x}")
            with lock:
                results.append(won)
        finally:
            connections.close_all()

    threads = [threading.Thread(target=racer, args=(i,)) for i in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(10)
    assert sorted(results) == [False] * 7 + [True]
    assert IdempotencyRecord.objects.filter(key=key).count() == 1


@pytest.mark.django_db(transaction=True)
def test_two_pods_racing_to_take_over_an_expired_key_exactly_one_wins(settings) -> None:
    if connection.vendor != "postgresql":
        pytest.skip("needs two connections to one DB (Postgres lane)")
    settings.VALI_IDEMPOTENCY_TTL_SECS = 60
    key = "migration:job-race:expired"
    idempotency.record(key, "0" * 64)
    IdempotencyRecord.objects.filter(key=key).update(
        recorded_at=timezone.now() - timedelta(seconds=120)
    )
    barrier = threading.Barrier(8)
    results: list[bool] = []
    lock = threading.Lock()

    def racer(i: int) -> None:
        try:
            barrier.wait(5)
            won = idempotency.record(key, f"{i + 1:064x}")
            with lock:
                results.append(won)
        finally:
            connections.close_all()

    threads = [threading.Thread(target=racer, args=(i,)) for i in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(10)
    assert sorted(results) == [False] * 7 + [True]


def test_a_purge_between_the_create_and_the_takeover_still_records(
    settings, monkeypatch
) -> None:
    """The expired row exists at the create, is purged before the takeover
    UPDATE: the second pass creates it — the step is recorded, not lost."""
    settings.VALI_IDEMPOTENCY_TTL_SECS = 60
    key = "migration:job-purged:step"
    idempotency.record(key, "0" * 64)
    IdempotencyRecord.objects.filter(key=key).update(
        recorded_at=timezone.now() - timedelta(seconds=120)
    )
    real_filter = IdempotencyRecord.objects.filter
    purged = []

    def filter_then_purge(*args, **kwargs):
        if "recorded_at__lt" in kwargs and not purged:
            purged.append(1)
            idempotency.purge_expired()
        return real_filter(*args, **kwargs)

    monkeypatch.setattr(IdempotencyRecord.objects, "filter", filter_then_purge)
    assert idempotency.record(key, "b" * 64) is True
    # Not `monkeypatch.undo()`: it would also undo every autouse fixture's
    # patches of this test.
    monkeypatch.setattr(IdempotencyRecord.objects, "filter", real_filter)
    assert idempotency.recall(key) == "b" * 64
