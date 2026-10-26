"""`vali_launch_tick` with `VALI_LAUNCH_TICK_CONCURRENCY`.

At `1` (the default) the worker is the serial loop it always was. Above
it the main thread stays the only claimer and runs up to N claimed jobs
at once on a thread pool; SIGTERM stops the claiming and the jobs in
flight finish before the process exits. The placement decision under
concurrency is `test_launch_decision_race.py` (Postgres lane).
"""

from __future__ import annotations

import signal
import threading
import time
from collections.abc import Iterator
from types import SimpleNamespace
from typing import Any

import pytest
from django.core.management import call_command
from django.test import override_settings

from apps.orchestration import launch_jobs
from apps.orchestration.management.commands import vali_launch_tick


@pytest.fixture(autouse=True)
def _restore_signals() -> Iterator[None]:
    saved = {s: signal.getsignal(s) for s in (signal.SIGTERM, signal.SIGINT)}
    yield
    for s, handler in saved.items():
        signal.signal(s, handler)


@pytest.fixture(autouse=True)
def _no_db(monkeypatch: pytest.MonkeyPatch) -> None:
    """These tests fake the queue: the claiming loop's connection recycle
    has no database to touch."""
    monkeypatch.setattr(vali_launch_tick, "close_old_connections", lambda: None)


class _Queue:
    """`claim_one` over `n` fake jobs; `run_claimed_job` records overlap."""

    def __init__(self, monkeypatch: pytest.MonkeyPatch, n: int, *, work_s: float = 0.05) -> None:
        self.pending = [SimpleNamespace(job_id=f"job-{i}") for i in range(n)]
        self.claimed: list[str] = []
        self.finished: list[str] = []
        self.running = 0
        self.peak = 0
        self.work_s = work_s
        self.lock = threading.Lock()
        self.on_start: Any = None
        self.saw_stop: list[bool] = []
        monkeypatch.setattr(launch_jobs, "claim_one", self.claim_one)
        monkeypatch.setattr(launch_jobs, "run_claimed_job", self.run)
        monkeypatch.setattr(launch_jobs, "tick_once", lambda: pytest.fail("serial loop at N>1"))

    def claim_one(self) -> SimpleNamespace | None:
        assert threading.current_thread() is threading.main_thread(), "only main claims"
        if not self.pending:
            return None
        job = self.pending.pop(0)
        self.claimed.append(job.job_id)
        return job

    def run(self, job: SimpleNamespace, stopping: Any) -> None:
        with self.lock:
            self.running += 1
            self.peak = max(self.peak, self.running)
        if self.on_start is not None:
            self.on_start()
        time.sleep(self.work_s)
        with self.lock:
            self.running -= 1
            self.finished.append(job.job_id)
            self.saw_stop.append(stopping())


@override_settings(VALI_LAUNCH_TICK_INTERVAL_S=0.05)
def test_the_default_is_the_serial_loop(monkeypatch: pytest.MonkeyPatch) -> None:
    ran = iter([True, True, False])
    monkeypatch.setattr(launch_jobs, "tick_once", lambda: next(ran))
    monkeypatch.setattr(
        vali_launch_tick.Command,
        "_run_concurrent",
        lambda *a, **k: pytest.fail("the pool must not run at concurrency 1"),
    )

    call_command("vali_launch_tick", "--once")

    assert next(ran, "drained") == "drained"


@override_settings(VALI_LAUNCH_TICK_CONCURRENCY=3, VALI_LAUNCH_TICK_INTERVAL_S=0.05)
def test_up_to_n_jobs_run_at_once_and_once_drains_them_all(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    q = _Queue(monkeypatch, 7, work_s=0.2)

    call_command("vali_launch_tick", "--once")

    assert sorted(q.finished) == sorted(f"job-{i}" for i in range(7))
    assert q.peak == 3


@override_settings(VALI_LAUNCH_TICK_CONCURRENCY=3, VALI_LAUNCH_TICK_INTERVAL_S=0.05)
def test_sigterm_stops_claiming_and_drains_the_jobs_in_flight(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    q = _Queue(monkeypatch, 10, work_s=0.3)
    fired = threading.Event()

    def sigterm_once() -> None:
        if not fired.is_set():
            fired.set()
            signal.getsignal(signal.SIGTERM)(signal.SIGTERM, None)

    q.on_start = sigterm_once

    # No `--once`: only the signal ends the loop.
    call_command("vali_launch_tick")

    assert fired.is_set()
    assert 1 <= len(q.claimed) <= 3
    # Every job it claimed reached its end before the command returned.
    assert sorted(q.finished) == sorted(q.claimed)
    assert len(q.pending) == 10 - len(q.claimed)
    # The jobs were told: one waiting for a boot slot would end at once.
    assert q.saw_stop == [True] * len(q.claimed)


@override_settings(VALI_LAUNCH_TICK_CONCURRENCY=2, VALI_LAUNCH_TICK_INTERVAL_S=0.05)
def test_a_job_raising_does_not_stop_the_pool(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(launch_jobs, "close_old_connections", lambda: None)
    monkeypatch.setattr(launch_jobs.connections, "close_all", lambda: None)
    jobs = [SimpleNamespace(job_id=f"job-{i}") for i in range(4)]
    monkeypatch.setattr(launch_jobs, "claim_one", lambda: jobs.pop(0) if jobs else None)
    ran: list[str] = []

    def run_job(job: SimpleNamespace, *, stopping: Any) -> None:
        ran.append(job.job_id)
        if job.job_id == "job-1":
            raise RuntimeError("boom")

    monkeypatch.setattr(launch_jobs, "run_job", run_job)

    call_command("vali_launch_tick", "--once")

    assert sorted(ran) == ["job-0", "job-1", "job-2", "job-3"]


def test_run_claimed_job_owns_its_connections(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[str] = []
    monkeypatch.setattr(launch_jobs, "close_old_connections", lambda: calls.append("old"))
    monkeypatch.setattr(launch_jobs.connections, "close_all", lambda: calls.append("close"))

    def run_job(job: SimpleNamespace, *, stopping: Any) -> None:
        calls.append("run")
        raise RuntimeError("boom")

    monkeypatch.setattr(launch_jobs, "run_job", run_job)

    launch_jobs.run_claimed_job(SimpleNamespace(job_id="job-x"), lambda: False)  # no raise

    assert calls == ["old", "run", "close"]


@pytest.mark.parametrize("value", [0, -1, launch_jobs.MAX_LAUNCH_TICK_CONCURRENCY + 1])
def test_an_out_of_range_concurrency_refuses_to_start(value: int) -> None:
    with override_settings(VALI_LAUNCH_TICK_CONCURRENCY=value):
        with pytest.raises(ValueError, match="VALI_LAUNCH_TICK_CONCURRENCY"):
            launch_jobs.launch_tick_concurrency()


def test_the_concurrency_defaults_to_one() -> None:
    assert launch_jobs.launch_tick_concurrency() == 1
