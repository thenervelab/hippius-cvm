"""`apps.miners.launch_errors` — the sanitizer and the per-miner ledger."""

from __future__ import annotations

import pytest

from apps.miners import launch_errors
from apps.miners.models import MinerLaunchErrors
from apps.scheduler.tests.factories import make_dispatchable_identity


@pytest.mark.parametrize(
    "raw",
    [
        "dispatch-failed",
        "libvirt-driver/define",
        "tenant-preflight/ovmf-missing",
        "insufficient-disk:nvme0",
        "relaunch-disks-missing/overlay-missing:default",
        "config-parse/line.3",
    ],
)
def test_a_static_code_passes_unchanged(raw: str) -> None:
    assert launch_errors.sanitize_code(raw) == raw


@pytest.mark.parametrize(
    "raw",
    [
        "Dispatch-Failed",  # upper case: not a code an agent sends
        "libvirt: error: /var/lib/hippius-miner/x.img not found",
        "dispatch-failed\nset-cookie: x",
        "-leading-dash",
        "x" * (launch_errors.MAX_CODE_LEN + 1),
        '{"code": "pool-unknown"}',
        "dispatch-failed\x00",
        "café",
    ],
)
def test_anything_else_becomes_invalid_never_a_trimmed_copy(raw: str) -> None:
    assert launch_errors.sanitize_code(raw) == launch_errors.CODE_INVALID


def test_empty_is_empty() -> None:
    assert launch_errors.sanitize_code("") == ""
    assert launch_errors.sanitize_code(None) == ""
    assert launch_errors.sanitize_code("  \n") == ""


def test_the_reason_is_preferred_over_the_class() -> None:
    entry = launch_errors.failure_entry(
        stage="launch",
        http_status=500,
        classifier="dispatch-failed",
        reason="libvirt-driver/define",
        order_id="ord-vm-1-abcd1234",
    )
    assert entry == {
        "code": "libvirt-driver/define",
        "class": "dispatch-failed",
        "http_status": 500,
        "stage": "launch",
        "order_id": "ord-vm-1-abcd1234",
    }


def test_an_older_agent_without_a_reason_reports_its_class() -> None:
    entry = launch_errors.failure_entry(
        stage="preflight", http_status=503, classifier="insufficient-resources"
    )
    assert entry["code"] == "insufficient-resources"
    assert entry["order_id"] is None


@pytest.mark.parametrize("status", [502, 504])
def test_a_bodiless_edge_answer_is_miner_unreachable(status: int) -> None:
    entry = launch_errors.failure_entry(stage="launch", http_status=status, classifier="")
    assert entry["code"] == launch_errors.CODE_UNREACHABLE
    assert entry["class"] is None


def test_a_bodiless_miner_answer_is_unclassified() -> None:
    entry = launch_errors.failure_entry(stage="launch", http_status=500, classifier="")
    assert entry["code"] == launch_errors.CODE_UNCLASSIFIED


def test_a_bad_reason_does_not_hide_a_good_class() -> None:
    """`invalid` is itself a code: a junk header is reported as junk, not
    silently replaced by the class."""
    entry = launch_errors.failure_entry(
        stage="launch", http_status=500, classifier="dispatch-failed", reason="Not A Code"
    )
    assert entry["code"] == launch_errors.CODE_INVALID
    assert entry["class"] == "dispatch-failed"


def test_a_malformed_order_id_is_dropped() -> None:
    entry = launch_errors.failure_entry(
        stage="launch", http_status=500, classifier="x", order_id="ord 1\n"
    )
    assert entry["order_id"] is None


@pytest.mark.django_db
def test_the_ledger_keeps_the_newest_and_counts_the_streak() -> None:
    miner = make_dispatchable_identity(1)
    for i in range(launch_errors.MAX_RECENT + 2):
        launch_errors.record_failure(
            miner,
            launch_errors.failure_entry(
                stage="launch", http_status=500, classifier=f"code-{i}"
            ),
        )
    row = MinerLaunchErrors.objects.get(miner=miner)
    assert row.fail_streak == launch_errors.MAX_RECENT + 2
    assert [e["code"] for e in row.errors] == [
        f"code-{i}" for i in reversed(range(2, launch_errors.MAX_RECENT + 2))
    ]
    assert all(e["at"] for e in row.errors)

    launch_errors.record_ok(miner)
    row.refresh_from_db()
    assert row.fail_streak == 0
    assert row.last_ok_at is not None
    assert len(row.errors) == launch_errors.MAX_RECENT


@pytest.mark.django_db
def test_a_success_on_a_fresh_miner_creates_an_empty_row() -> None:
    miner = make_dispatchable_identity(1)
    launch_errors.record_ok(miner)
    row = MinerLaunchErrors.objects.get(miner=miner)
    assert (row.fail_streak, row.errors) == (0, [])
    assert launch_errors.readout(row) == {
        "last_launch_error": None,
        "launch_fail_streak": 0,
        "recent_launch_errors": [],
    }


def test_readout_of_no_row() -> None:
    assert launch_errors.readout(None) == {
        "last_launch_error": None,
        "launch_fail_streak": 0,
        "recent_launch_errors": [],
    }


@pytest.mark.django_db
def test_a_write_failure_never_raises(monkeypatch) -> None:
    miner = make_dispatchable_identity(1)

    def _boom(*a, **k):
        raise RuntimeError("db down")

    monkeypatch.setattr(MinerLaunchErrors.objects, "select_for_update", _boom)
    launch_errors.record_failure(
        miner, launch_errors.failure_entry(stage="launch", http_status=500, classifier="x")
    )
    launch_errors.record_ok(miner)


def test_printable_keeps_a_class_and_neutralises_the_rest() -> None:
    assert launch_errors.printable("relaunch-disks-missing") == "relaunch-disks-missing"
    assert launch_errors.printable("a\nb\x00cé") == "a?b?c?"
    assert len(launch_errors.printable("x" * 5000)) == launch_errors.MAX_CODE_LEN
