"""`vali_set_miner_capacity` — the operator write path for the trusted
hardware anchor (`MinerCapacity.total_cpus` / `total_memory_mb`)."""

from __future__ import annotations

import json
import logging
from datetime import timedelta
from io import StringIO

import pytest
from django.core.management import CommandError, call_command
from django.utils import timezone

from apps.scheduler.management.commands import vali_set_miner_capacity as cmd
from apps.scheduler.models import MinerCapacity, PlacementStatus

from .factories import make_dispatchable_identity, make_placement, make_vm, node_id

pytestmark = pytest.mark.django_db

AUDIT_LOGGER = "apps.scheduler.capacity_admin"


@pytest.fixture(autouse=True)
def _propagate_apps_logs(monkeypatch: pytest.MonkeyPatch) -> None:
    # `LOGGING` pins `apps` with `propagate: False`; caplog listens on root.
    monkeypatch.setattr(logging.getLogger("apps"), "propagate", True)


def _row(seed: int = 4, **over: object) -> MinerCapacity:
    fields: dict[str, object] = dict(
        miner_node_id=node_id(seed),
        status="active",
        capacity_slots=8,
        observed_epoch=10,
        data_epoch=10,
        refreshed_at=timezone.now(),
    )
    fields.update(over)
    return MinerCapacity.objects.create(**fields)


def _run(*args: str, by: str | None = "ops", reason: str | None = "test") -> tuple[str, str]:
    out, err = StringIO(), StringIO()
    extra = ["--by", by] if by is not None else []
    extra += ["--reason", reason] if reason is not None else []
    call_command("vali_set_miner_capacity", *args, *extra, stdout=out, stderr=err)
    return out.getvalue(), err.getvalue()


def _audit(caplog: pytest.LogCaptureFixture) -> list[dict[str, object]]:
    return [
        json.loads(r.getMessage().split(": ", 1)[1])
        for r in caplog.records
        if r.name == AUDIT_LOGGER
    ]


def _place(seed: int, resource_class: str, status: str = PlacementStatus.BOUND.value) -> None:
    make_placement(
        make_vm(f"vm-{seed}", f"lease-{seed}"),
        node_id(4),
        status=status,
        resource_class=resource_class,
    )


# ─── the write ──────────────────────────────────────────────────────


def test_set_by_node_id_writes_anchor_and_audits(caplog: pytest.LogCaptureFixture) -> None:
    row = _row()
    caplog.set_level(logging.INFO, logger=AUDIT_LOGGER)

    out, _ = _run("--node-id", node_id(4), "--cpus", "64", "--memory-mb", "256180")

    row.refresh_from_db()
    assert (row.total_cpus, row.total_memory_mb) == (64, 256180)
    assert "before total_cpus=None total_memory_mb=None" in out
    assert "after  total_cpus=64 total_memory_mb=256180" in out
    expected = {
        "event": "miner_capacity_change",
        "by": "ops",
        "node_id": node_id(4),
        "miner_id": None,
        "dry_run": False,
        "reason": "test",
        "note": False,
        "changes": [
            {"field": "total_cpus", "before": None, "after": 64},
            {"field": "total_memory_mb", "before": None, "after": 256180},
        ],
    }
    assert _audit(caplog) == [expected]
    # The same record is echoed to stdout — `kubectl exec` output is the
    # only place the operator is guaranteed to see it.
    assert json.loads(out.strip().splitlines()[-1]) == expected


def test_real_write_requires_by() -> None:
    row = _row()
    with pytest.raises(CommandError, match="--by"):
        _run("--node-id", node_id(4), "--cpus", "64", "--memory-mb", "256180", by=None)
    with pytest.raises(CommandError, match="--by"):
        _run("--node-id", node_id(4), "--cpus", "64", "--memory-mb", "256180", by="  ")
    row.refresh_from_db()
    assert row.total_memory_mb is None


def test_write_does_not_roll_back_a_concurrent_chain_refresh(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Only the two anchor columns are written. A chain-refresh / heartbeat
    write landing after the command read the row must survive — a full
    `row.save()` would put back the values it read."""
    row = _row(total_cpus=24, total_memory_mb=125000, quality=7, capacity_slots=3)
    real = cmd._committed_on

    def refresh_mid_command(nid: str) -> cmd.Committed:
        MinerCapacity.objects.filter(miner_node_id=nid).update(
            quality=99, reported_memory_available_mib=100000, status="inactive"
        )
        return real(nid)

    monkeypatch.setattr(cmd, "_committed_on", refresh_mid_command)
    _run("--node-id", node_id(4), "--cpus", "32", "--memory-mb", "128000")

    row.refresh_from_db()
    assert (row.total_cpus, row.total_memory_mb) == (32, 128000)
    assert (row.quality, row.reported_memory_available_mib, row.status) == (
        99,
        100000,
        "inactive",
    )
    assert row.capacity_slots == 3


def test_miner_id_resolves_via_chain_node_id(caplog: pytest.LogCaptureFixture) -> None:
    make_dispatchable_identity(4)
    row = _row()
    caplog.set_level(logging.INFO, logger=AUDIT_LOGGER)

    _run("--miner-id", "miner-04", "--cpus", "64", "--memory-mb", "256180")

    row.refresh_from_db()
    assert (row.total_cpus, row.total_memory_mb) == (64, 256180)
    [event] = _audit(caplog)
    assert event["miner_id"] == "miner-04"
    assert event["node_id"] == node_id(4)


def test_dry_run_writes_nothing_and_needs_no_by(caplog: pytest.LogCaptureFixture) -> None:
    row = _row()
    caplog.set_level(logging.INFO, logger=AUDIT_LOGGER)

    out, _ = _run(
        "--node-id",
        node_id(4),
        "--cpus",
        "64",
        "--memory-mb",
        "256180",
        "--dry-run",
        by=None,
        reason=None,
    )

    row.refresh_from_db()
    assert row.total_cpus is None and row.total_memory_mb is None
    assert "dry run" in out
    [event] = _audit(caplog)
    assert event["dry_run"] is True


def test_clear_unsets_both_anchors() -> None:
    row = _row(total_cpus=64, total_memory_mb=256180)
    out, _ = _run("--node-id", node_id(4), "--clear")
    row.refresh_from_db()
    assert row.total_cpus is None and row.total_memory_mb is None
    assert "after  total_cpus=None total_memory_mb=None" in out


def test_clear_is_allowed_with_placements() -> None:
    """Clearing falls back to the flat cap; the committed-load guard is for
    anchors too small for the load, not for removing one."""
    row = _row(total_cpus=4, total_memory_mb=16384)
    _place(1, "large")
    _run("--node-id", node_id(4), "--clear")
    row.refresh_from_db()
    assert row.total_memory_mb is None


def test_idempotent_rerun_is_a_no_op(caplog: pytest.LogCaptureFixture) -> None:
    _row(total_cpus=64, total_memory_mb=256180)
    caplog.set_level(logging.INFO, logger=AUDIT_LOGGER)

    out, _ = _run("--node-id", node_id(4), "--cpus", "64", "--memory-mb", "256180")

    assert "no change" in out
    assert _audit(caplog) == []


# ─── refusals ───────────────────────────────────────────────────────


def test_unknown_node_fails_and_never_creates_the_row() -> None:
    with pytest.raises(CommandError, match="no MinerCapacity row"):
        _run("--node-id", node_id(5), "--cpus", "64", "--memory-mb", "256180")
    assert not MinerCapacity.objects.filter(miner_node_id=node_id(5)).exists()


def test_unknown_miner_id_fails() -> None:
    with pytest.raises(CommandError, match="no MinerIdentity"):
        _run("--miner-id", "miner-nope", "--cpus", "64", "--memory-mb", "256180")


def test_miner_id_without_chain_node_id_fails() -> None:
    identity = make_dispatchable_identity(4)
    identity.chain_node_id = None
    identity.save(update_fields=["chain_node_id"])
    with pytest.raises(CommandError, match="no chain_node_id"):
        _run("--miner-id", "miner-04", "--cpus", "64", "--memory-mb", "256180")


@pytest.mark.parametrize(
    ("args", "match"),
    [
        (["--cpus", "0", "--memory-mb", "256180"], "--cpus 0 out of range"),
        (["--cpus", "1025", "--memory-mb", "256180"], "--cpus 1025 out of range"),
        (["--cpus", "-3", "--memory-mb", "256180"], "out of range"),
        (["--cpus", "64", "--memory-mb", "1023"], "--memory-mb 1023 out of range"),
        (["--cpus", "64", "--memory-mb", str(16 * 1024 * 1024 + 1)], "out of range"),
        (["--cpus", "64"], "both required"),
        (["--memory-mb", "256180"], "both required"),
        (["--clear", "--cpus", "64"], "--clear takes no"),
    ],
)
def test_validation_errors_write_nothing(args: list[str], match: str) -> None:
    row = _row()
    with pytest.raises(CommandError, match=match):
        _run("--node-id", node_id(4), *args)
    row.refresh_from_db()
    assert row.total_cpus is None and row.total_memory_mb is None


def test_malformed_node_id_fails() -> None:
    with pytest.raises(CommandError, match="not 64 lowercase hex"):
        _run("--node-id", "abc", "--cpus", "64", "--memory-mb", "256180")


def test_node_id_and_miner_id_are_mutually_exclusive() -> None:
    with pytest.raises(CommandError):
        _run("--node-id", node_id(4), "--miner-id", "miner-04", "--cpus", "1", "--memory-mb", "2048")


# ─── committed load ─────────────────────────────────────────────────


def test_refuses_anchor_smaller_than_committed_load() -> None:
    """Two `large` placements commit 2 × 16384 MiB / 4 vCPU."""
    row = _row(total_cpus=64, total_memory_mb=256180)
    _place(1, "large")
    _place(2, "large")

    with pytest.raises(CommandError, match="smaller than the load"):
        _run("--node-id", node_id(4), "--cpus", "64", "--memory-mb", "32767")
    with pytest.raises(CommandError, match="8 vCPU"):
        _run("--node-id", node_id(4), "--cpus", "7", "--memory-mb", "256180")
    row.refresh_from_db()
    assert (row.total_cpus, row.total_memory_mb) == (64, 256180)


def test_anchor_holding_load_but_not_reserve_warns_and_writes() -> None:
    """A host loaded under the flat fallback must still be able to register
    its true size — admission clamps free at 0, so this is safe."""
    row = _row()
    _place(1, "large")
    _place(2, "large")

    _, err = _run("--node-id", node_id(4), "--cpus", "8", "--memory-mb", "32768")

    assert "less than the host reserve" in err
    row.refresh_from_db()
    assert (row.total_cpus, row.total_memory_mb) == (8, 32768)


def test_anchor_holding_load_and_reserve_is_silent() -> None:
    _row()
    _place(1, "large")
    _place(2, "large")
    reserve = cmd._host_reserve_memory_mb()
    _, err = _run("--node-id", node_id(4), "--cpus", "10", "--memory-mb", str(32768 + reserve))
    assert err == ""


def test_unknown_resource_class_counts_as_the_reference_slot() -> None:
    """Fail-closed like admission: a legacy `std` row still commits the
    reference flavor (8192 MiB / 4 vCPU)."""
    _row()
    _place(1, "std")
    with pytest.raises(CommandError, match="8192 MiB / 4 vCPU"):
        _run("--node-id", node_id(4), "--cpus", "64", "--memory-mb", "8191")


def test_failed_placements_do_not_count_as_load() -> None:
    row = _row()
    _place(1, "large", status=PlacementStatus.FAILED.value)
    _run("--node-id", node_id(4), "--cpus", "1", "--memory-mb", "1024")
    row.refresh_from_db()
    assert row.total_memory_mb == 1024


# ─── heartbeat cross-check ──────────────────────────────────────────


def test_warns_when_report_exceeds_the_anchor() -> None:
    """Same threshold as admission's over-claim alarm: more than `total`."""
    row = _row(reported_memory_available_mib=128001, reported_at=timezone.now())
    _, err = _run("--node-id", node_id(4), "--cpus", "32", "--memory-mb", "128000")
    assert "anchor too small" in err
    row.refresh_from_db()
    assert row.total_memory_mb == 128000  # a warning, not a refusal


def test_warns_when_report_far_below_anchor() -> None:
    _row(reported_memory_available_mib=60000, reported_at=timezone.now())
    _, err = _run("--node-id", node_id(4), "--cpus", "64", "--memory-mb", "256180")
    assert "anchor too large" in err


def test_no_warning_for_plausible_report() -> None:
    _row(reported_memory_available_mib=240000, reported_at=timezone.now())
    _, err = _run("--node-id", node_id(4), "--cpus", "64", "--memory-mb", "256180")
    assert err == ""


def test_stale_report_is_not_cross_checked() -> None:
    """Admission ignores a report older than the liveness timeout; so does
    the cross-check."""
    _row(
        reported_memory_available_mib=60000,
        reported_at=timezone.now() - timedelta(days=7),
    )
    out, err = _run("--node-id", node_id(4), "--cpus", "64", "--memory-mb", "256180")
    assert err == ""
    assert "stale" in out


def test_no_warning_for_an_idle_host_reporting_nearly_all_its_ram() -> None:
    """Above `anchor − reserve` but within the anchor: honest, no warning."""
    _row(reported_memory_available_mib=126_000, reported_at=timezone.now())
    _, err = _run("--node-id", node_id(4), "--cpus", "32", "--memory-mb", "128000")
    assert err == ""
