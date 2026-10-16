"""The passive disk ingest hook in the usage meter (design §3.5, P1): one
call per verified receipt, and nothing it does can cost a receipt its
billing."""

from __future__ import annotations

import time
from dataclasses import replace
from typing import Any

import pytest

from apps.disktier import ingest as disktier_ingest
from apps.disktier.models import VmDiskIoHourly
from apps.scheduler import usage
from apps.scheduler.models import PlacementStatus, UsageAccrual
from apps.scheduler.tests.factories import make_placement, make_vm
from apps.scheduler.tests.test_usage import NODE, _binding, _envelope, _fields, _patch_units
from apps.telemetry.verifier import DiskIoDelta

pytestmark = pytest.mark.django_db

_DELTA = DiskIoDelta(
    dev="vdb",
    serial="hippius-os",
    state="ok",
    r_ios=10,
    r_sectors=80,
    r_ticks_ms=5,
    w_ios=1,
    w_sectors=8,
    w_ticks_ms=1,
    io_ticks_ms=20,
    tiq_ms=30,
    inflight=0,
)


@pytest.fixture
def receipt(monkeypatch: pytest.MonkeyPatch, settings: Any):
    """A fresh (real-clock) receipt with disk evidence, for a VM with a
    billing binding and an active placement."""
    settings.VALI_DISK_IO_INGEST = True
    disktier_ingest.drain_counters()
    now = int(time.time())
    monkeypatch.setattr(usage, "_now_unix", lambda: now)
    vm = make_vm("vm-1", "lease-1")
    make_placement(vm, NODE, status=PlacementStatus.BOUND.value, owner="user-1")
    _binding()
    _envelope()
    _patch_units(monkeypatch, 100)
    fields = replace(_fields(period_start=now - 70, period_end=now - 10), disk_io=(_DELTA,))
    monkeypatch.setattr(
        usage.verifier, "verify_served_receipt", lambda *, body, sig, verifying_key: fields
    )
    return fields


def test_a_verified_receipt_reaches_the_disk_ingest_and_is_billed(receipt: Any) -> None:
    report = usage.accrue_usage_once()
    assert report.accrued == 1
    assert UsageAccrual.objects.get().billable_seconds == 60
    row = VmDiskIoHourly.objects.get()
    assert (row.slot, row.pool_id, row.r_ios) == ("os", "default", 10)


def test_a_failing_disk_ingest_never_costs_the_receipt(
    receipt: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    def boom(*_a: object, **_kw: object) -> str:
        raise RuntimeError("disk ingest exploded")

    monkeypatch.setattr(disktier_ingest, "on_verified_receipt", boom)
    report = usage.accrue_usage_once()
    assert report.accrued == 1
    assert UsageAccrual.objects.get().billable_seconds == 60
    assert not VmDiskIoHourly.objects.exists()


def test_a_failing_counter_flush_never_costs_the_cycle(
    receipt: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    def boom(**_kw: object) -> None:
        raise RuntimeError("counter table gone")

    monkeypatch.setattr(disktier_ingest.DiskIngestCounter.objects, "get_or_create", boom)
    report = usage.accrue_usage_once()
    assert report.accrued == 1


def test_flag_off_the_meter_bills_and_the_disk_tables_stay_empty(
    receipt: Any, settings: Any
) -> None:
    settings.VALI_DISK_IO_INGEST = False
    report = usage.accrue_usage_once()
    assert report.accrued == 1
    assert not VmDiskIoHourly.objects.exists()


def test_a_requeued_envelope_is_folded_once(receipt: Any) -> None:
    from apps.telemetry.models import TelemetryEnvelope

    usage.accrue_usage_once()
    usage._requeue(TelemetryEnvelope.objects.get())
    usage.accrue_usage_once()
    assert VmDiskIoHourly.objects.get().windows == 1
