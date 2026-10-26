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
def test_a_bodiless_edge_answer_at_launch_is_a_launch_timeout(status: int) -> None:
    entry = launch_errors.failure_entry(stage="launch", http_status=status, classifier="")
    assert entry["code"] == launch_errors.CODE_LAUNCH_TIMEOUT == "launch-timeout"
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
    for i in range(launch_errors.MAX_STORED + 2):
        launch_errors.record_failure(
            miner,
            launch_errors.failure_entry(stage="launch", http_status=500, classifier=f"code-{i}"),
        )
    row = MinerLaunchErrors.objects.get(miner=miner)
    assert row.fail_streak == launch_errors.MAX_STORED + 2
    assert [e["code"] for e in row.errors] == [
        f"code-{i}" for i in reversed(range(2, launch_errors.MAX_STORED + 2))
    ]
    assert all(e["at"] for e in row.errors)
    shown = launch_errors.readout(row)["recent_launch_errors"]
    assert [e["code"] for e in shown] == [e["code"] for e in row.errors[: launch_errors.MAX_RECENT]]

    launch_errors.record_ok(miner)
    row.refresh_from_db()
    assert row.fail_streak == 0
    assert row.last_ok_at is not None
    assert len(row.errors) == launch_errors.MAX_STORED


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


# ── preflight-timeout ────────────────────────────────────────────────


def _edge_timeout(stage: str = launch_errors.STAGE_PREFLIGHT, status: int = 504) -> dict:
    return launch_errors.failure_entry(stage=stage, http_status=status, classifier="")


def _codes(view: dict) -> list[str]:
    return [e["code"] for e in view["recent_launch_errors"]]


@pytest.mark.parametrize("status", [502, 504])
def test_a_bodiless_edge_answer_to_a_preflight_is_a_preflight_timeout(status: int) -> None:
    entry = _edge_timeout(status=status)
    assert entry["code"] == "preflight-timeout"
    assert entry["code"] == launch_errors.CODE_PREFLIGHT_TIMEOUT
    assert entry["class"] is None
    assert entry["stage"] == "preflight"


@pytest.mark.parametrize("status", [502, 504])
def test_a_bodiless_edge_answer_to_a_launch_stays_miner_unreachable(status: int) -> None:
    assert _edge_timeout(launch_errors.STAGE_LAUNCH, status)["code"] == "launch-timeout"


def test_a_preflight_answer_with_a_class_is_never_a_timeout() -> None:
    entry = launch_errors.failure_entry(
        stage=launch_errors.STAGE_PREFLIGHT, http_status=502, classifier="dispatch-failed"
    )
    assert entry["code"] == "dispatch-failed"


def test_a_bodiless_non_edge_preflight_answer_is_unclassified() -> None:
    entry = launch_errors.failure_entry(
        stage=launch_errors.STAGE_PREFLIGHT, http_status=500, classifier=""
    )
    assert entry["code"] == "unclassified"


@pytest.mark.django_db
def test_isolated_preflight_timeouts_are_stored_but_hidden_and_not_counted() -> None:
    miner = make_dispatchable_identity(1)
    real = launch_errors.failure_entry(
        stage="launch", http_status=500, classifier="dispatch-failed"
    )
    launch_errors.record_failure(miner, real)
    for _ in range(launch_errors.PREFLIGHT_TIMEOUT_RUN - 1):
        launch_errors.record_failure(miner, _edge_timeout())
    row = MinerLaunchErrors.objects.get(miner=miner)
    assert row.fail_streak == 1
    assert [e["code"] for e in row.errors] == [
        *["preflight-timeout"] * (launch_errors.PREFLIGHT_TIMEOUT_RUN - 1),
        "dispatch-failed",
    ]
    view = launch_errors.readout(row)
    assert _codes(view) == ["dispatch-failed"]
    assert view["last_launch_error"]["code"] == "dispatch-failed"
    assert view["launch_fail_streak"] == 1


@pytest.mark.django_db
def test_a_run_of_preflight_timeouts_is_shown_and_counted() -> None:
    miner = make_dispatchable_identity(1)
    for _ in range(launch_errors.PREFLIGHT_TIMEOUT_RUN):
        launch_errors.record_failure(miner, _edge_timeout())
    view = launch_errors.readout(MinerLaunchErrors.objects.get(miner=miner))
    assert _codes(view) == ["preflight-timeout"] * launch_errors.PREFLIGHT_TIMEOUT_RUN
    assert view["last_launch_error"]["code"] == "preflight-timeout"
    assert view["launch_fail_streak"] == launch_errors.PREFLIGHT_TIMEOUT_RUN


@pytest.mark.django_db
def test_another_error_breaks_a_run_of_preflight_timeouts() -> None:
    miner = make_dispatchable_identity(1)
    launch_errors.record_failure(miner, _edge_timeout())
    launch_errors.record_failure(miner, _edge_timeout())
    launch_errors.record_failure(miner, _edge_timeout(launch_errors.STAGE_LAUNCH))
    launch_errors.record_failure(miner, _edge_timeout())
    view = launch_errors.readout(MinerLaunchErrors.objects.get(miner=miner))
    assert _codes(view) == ["launch-timeout"]
    assert view["launch_fail_streak"] == 1


@pytest.mark.django_db
def test_a_stored_pre_rename_miner_unreachable_reads_as_launch_timeout() -> None:
    """Rows written before the rename keep `miner-unreachable` in the DB;
    the operator view shows the current code, the row is not rewritten."""
    miner = make_dispatchable_identity(1)
    launch_errors.record_failure(miner, _edge_timeout(launch_errors.STAGE_LAUNCH))
    row = MinerLaunchErrors.objects.get(miner=miner)
    row.errors = [{**row.errors[0], "code": "miner-unreachable"}]
    row.save(update_fields=["errors"])
    view = launch_errors.readout(MinerLaunchErrors.objects.get(miner=miner))
    assert _codes(view) == ["launch-timeout"]
    assert view["last_launch_error"]["code"] == "launch-timeout"
    assert MinerLaunchErrors.objects.get(miner=miner).errors[0]["code"] == "miner-unreachable"


@pytest.mark.django_db
def test_an_accepted_launch_breaks_a_run_and_resets_its_count() -> None:
    miner = make_dispatchable_identity(1)
    for _ in range(2):
        launch_errors.record_failure(miner, _edge_timeout())
    launch_errors.record_ok(miner)
    for _ in range(2):
        launch_errors.record_failure(miner, _edge_timeout())
    row = MinerLaunchErrors.objects.get(miner=miner)
    view = launch_errors.readout(row)
    assert _codes(view) == []
    assert view["launch_fail_streak"] == 0

    # A run that completed BEFORE the accepted launch stays visible as
    # history, but the streak only counts what came after it.
    for _ in range(launch_errors.PREFLIGHT_TIMEOUT_RUN):
        launch_errors.record_failure(miner, _edge_timeout())
    launch_errors.record_ok(miner)
    view = launch_errors.readout(MinerLaunchErrors.objects.get(miner=miner))
    assert len(_codes(view)) == launch_errors.MAX_RECENT
    assert view["launch_fail_streak"] == 0
