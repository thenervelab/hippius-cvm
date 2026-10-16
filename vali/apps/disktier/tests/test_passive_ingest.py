"""`apps.disktier.ingest.on_verified_receipt` — the passive receipt ingest
(design §3.5, phase P1): slot / pool / disk resolution, hour attribution,
accumulation, the QD >= 4 small-I/O bucket, replay dedupe, the flag, and
the safe wrapper."""

from __future__ import annotations

import time
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest

from apps.disktier import ingest, probe_results
from apps.disktier.ingest import (
    drain_counters,
    flush_counters_safe,
    hour_of_window,
    on_verified_receipt,
    on_verified_receipt_safe,
    qd4_small,
)
from apps.disktier.models import (
    DedicatedDisk,
    DiskIngestCounter,
    DiskIoReceipt,
    DiskProbeRun,
    PlacementDisk,
    VmDiskIoHourly,
)
from apps.scheduler.models import Placement, PlacementStatus
from apps.scheduler.tests.factories import make_placement, make_vm, node_id
from apps.telemetry.verifier import (
    DiskIoDelta,
    DiskProbeResult,
    DiskProbeTarget,
    ServedReceiptFields,
)

pytestmark = pytest.mark.django_db

NODE = node_id(1)
#: 12:30 UTC: windows a few minutes before it are fresh.
NOW = datetime(2026, 10, 16, 12, 30, tzinfo=UTC)
T0 = int(NOW.timestamp()) - 600


@pytest.fixture(autouse=True)
def _ingest_on(settings: Any) -> None:
    settings.VALI_DISK_IO_INGEST = True
    drain_counters()


def placement(vm_id: str = "vm-1", *, owner: str = "user-1", miner: str = NODE) -> Placement:
    vm = make_vm(vm_id, f"lease-{vm_id}")
    return make_placement(vm, miner, status=PlacementStatus.BOUND.value, owner=owner)


def delta(dev: str = "vdb", serial: str = "hippius-os", **counters: int) -> DiskIoDelta:
    fields: dict[str, Any] = {
        "dev": dev,
        "serial": serial,
        "state": "ok",
        "r_ios": 100,
        "r_sectors": 800,
        "r_ticks_ms": 50,
        "w_ios": 20,
        "w_sectors": 160,
        "w_ticks_ms": 30,
        "io_ticks_ms": 900,
        "tiq_ms": 1000,
        "inflight": 0,
    }
    fields.update(counters)
    return DiskIoDelta(**fields)


def receipt(
    *devices: DiskIoDelta,
    vm_id: str = "vm-1",
    start: int = T0,
    end: int | None = None,
    seq: int = 1,
    probe: DiskProbeResult | None = None,
) -> ServedReceiptFields:
    return ServedReceiptFields(
        vm_id=vm_id,
        lease_id=f"lease-{vm_id}",
        node_id_hex=NODE,
        epoch=5,
        resource_class="small",
        period_start=start,
        period_end=start + 60 if end is None else end,
        monotonic_seq=seq,
        observed_degradation_bps=0,
        disk_io=tuple(devices),
        disk_probe=probe,
    )


def ingest_one(fields: ServedReceiptFields, body: bytes | None = None) -> str:
    body = body if body is not None else f"{fields.vm_id}:{fields.monotonic_seq}".encode()
    return on_verified_receipt(fields, body=body, source_id=fields.vm_id, now=NOW)


# ─── the flag ────────────────────────────────────────────────────────


def test_flag_off_writes_nothing(settings: Any) -> None:
    settings.VALI_DISK_IO_INGEST = False
    placement()
    assert ingest_one(receipt(delta())) == "off"
    assert not VmDiskIoHourly.objects.exists()
    assert not DiskIoReceipt.objects.exists()
    # Tallied in-process only; the flush leaves the database alone too.
    assert flush_counters_safe() == {"skipped_flag_off": 1}
    assert not DiskIngestCounter.objects.exists()


def test_a_receipt_without_disk_evidence_writes_nothing() -> None:
    placement()
    assert ingest_one(receipt()) == "empty"
    assert not DiskIoReceipt.objects.exists()


# ─── slot → pool / disk ──────────────────────────────────────────────


def test_a_legacy_placement_maps_the_os_slot_to_pool_default() -> None:
    placement(owner="user-7")
    assert ingest_one(receipt(delta("vdb", "hippius-os"))) == "ingested"
    row = VmDiskIoHourly.objects.get()
    assert (row.vm_id, row.device, row.slot, row.pool_id, row.disk_id) == (
        "vm-1",
        "vdb",
        "os",
        "default",
        "",
    )
    assert (row.miner_node_id, row.owner) == (NODE, "user-7")


def test_placement_disks_map_pools_and_dedicated_disks() -> None:
    p = placement()
    disk = DedicatedDisk.objects.create(
        miner_node_id=NODE,
        disk_id="wwn-0xabc",
        state="assigned",
        assigned_vm=p.vm,
        assigned_slot="x0",
    )
    PlacementDisk.objects.create(
        placement=p, slot="os", kind="pool", pool_id="fast", size_gb=40, required_tier="nvme"
    )
    PlacementDisk.objects.create(
        placement=p,
        slot="x0",
        kind="dedicated",
        dedicated_disk=disk,
        size_gb=1000,
        required_tier="hdd",
    )
    ingest_one(
        receipt(
            delta("vda", "hippius-os"),
            delta("vdb", "hippius-x0"),
            # A slot this placement does not hold.
            delta("vdc", "hippius-x3"),
        )
    )
    rows = {r.device: (r.slot, r.pool_id, r.disk_id) for r in VmDiskIoHourly.objects.all()}
    assert rows == {
        "vda": ("os", "fast", ""),
        "vdb": ("x0", "", "wwn-0xabc"),
        "vdc": ("x3", "", ""),
    }
    assert drain_counters()["unresolved_slots"] == 1


def test_a_device_without_a_slot_serial_is_recorded_unresolved() -> None:
    placement()
    ingest_one(receipt(delta("vda", ""), delta("vdb", "hippius-os")))
    rows = {r.device: (r.slot, r.pool_id) for r in VmDiskIoHourly.objects.all()}
    assert rows == {"vda": ("", ""), "vdb": ("os", "default")}
    counters = drain_counters()
    assert counters["unresolved_slots"] == 1
    assert counters["ingested_rows"] == 2


def test_slot_verdicts_are_counted_not_folded() -> None:
    placement()
    zero = {k: 0 for k in ("r_ios", "r_sectors", "r_ticks_ms", "w_ios", "w_sectors")}
    ingest_one(
        receipt(
            delta("", "hippius-x1", state="missing", **zero, w_ticks_ms=0, io_ticks_ms=0, tiq_ms=0),
            delta("vdc", "hippius-x2", state="mismatch"),
            delta("vdb", "hippius-os"),
        )
    )
    assert list(VmDiskIoHourly.objects.values_list("device", flat=True)) == ["vdb"]
    assert drain_counters()["slot_verdicts"] == 2


# ─── hours and accumulation ──────────────────────────────────────────


def test_a_window_goes_to_the_hour_of_its_midpoint() -> None:
    h14 = int(datetime(2026, 10, 16, 14, tzinfo=UTC).timestamp())
    assert hour_of_window(h14 - 20, h14 + 40) == datetime(2026, 10, 16, 14, tzinfo=UTC)
    assert hour_of_window(h14 - 60, h14) == datetime(2026, 10, 16, 13, tzinfo=UTC)
    # Exactly on the boundary: the later hour.
    assert hour_of_window(h14 - 30, h14 + 30) == datetime(2026, 10, 16, 14, tzinfo=UTC)


def test_receipts_straddling_an_hour_land_in_two_rows() -> None:
    placement()
    h12 = int(datetime(2026, 10, 16, 12, tzinfo=UTC).timestamp())
    ingest_one(receipt(delta(), start=h12 - 50, seq=1))  # mid 11:59:40
    ingest_one(receipt(delta(), start=h12 - 20, seq=2))  # mid 12:00:10
    hours = sorted(VmDiskIoHourly.objects.values_list("hour", flat=True))
    assert hours == [
        datetime(2026, 10, 16, 11, tzinfo=UTC),
        datetime(2026, 10, 16, 12, tzinfo=UTC),
    ]


def test_counters_accumulate_within_an_hour() -> None:
    placement()
    ingest_one(receipt(delta(r_ios=10, w_ios=1, tiq_ms=5), start=T0, seq=1))
    ingest_one(receipt(delta(r_ios=30, w_ios=2, tiq_ms=7), start=T0 + 60, end=T0 + 90, seq=2))
    row = VmDiskIoHourly.objects.get()
    assert (row.windows, row.seconds) == (2, 90)
    assert (row.r_ios, row.w_ios, row.tiq_ms) == (40, 3, 12)
    assert (row.r_sectors, row.w_sectors) == (1600, 320)
    assert (row.r_ticks_ms, row.w_ticks_ms, row.io_ticks_ms) == (100, 60, 1800)


# ─── the QD >= 4 small-I/O bucket ────────────────────────────────────


@pytest.mark.parametrize(
    ("tiq_ms", "sectors_per_io", "extra_sector", "expected"),
    [
        # avg QD exactly 4 (240 s of queue time over 60 s), avg size exactly 32 KiB.
        (240_000, 64, 0, True),
        # QD just under 4.
        (239_999, 64, 0, False),
        # Average size one sector over 32 KiB (summed over the window).
        (240_000, 64, 1, False),
        # Deep queue, small reads.
        (600_000, 8, 0, True),
    ],
)
def test_qd4_small_bounds(
    tiq_ms: int, sectors_per_io: int, extra_sector: int, expected: bool
) -> None:
    d = delta(
        r_ios=90,
        w_ios=10,
        r_sectors=90 * sectors_per_io + extra_sector,
        w_sectors=10 * sectors_per_io,
        tiq_ms=tiq_ms,
    )
    assert qd4_small(d, 60) is expected


def test_qd4_small_needs_io() -> None:
    assert qd4_small(delta(r_ios=0, w_ios=0, r_sectors=0, w_sectors=0, tiq_ms=10**9), 60) is False
    assert qd4_small(delta(tiq_ms=10**9), 0) is False


def test_the_bucket_holds_reads_and_writes_and_reads_alone() -> None:
    placement()
    deep = {"tiq_ms": 300_000, "r_sectors": 8 * 100, "w_sectors": 8 * 20}
    ingest_one(receipt(delta(r_ticks_ms=400, w_ticks_ms=100, **deep), seq=1))
    # A shallow window adds nothing to the bucket.
    ingest_one(receipt(delta(tiq_ms=10), start=T0 + 60, seq=2))
    row = VmDiskIoHourly.objects.get()
    assert (row.qd4_small_ios, row.qd4_small_ticks_ms) == (120, 500)
    assert (row.qd4_small_r_ios, row.qd4_small_r_ticks_ms) == (100, 400)
    assert row.windows == 2
    assert drain_counters()["qd4_small_windows"] == 1


# ─── replay, freshness, provenance ───────────────────────────────────


def test_a_replayed_receipt_is_not_counted_twice() -> None:
    placement()
    fields = receipt(delta())
    assert ingest_one(fields, b"body-1") == "ingested"
    assert ingest_one(fields, b"body-1") == "duplicate"
    # Same counters, another receipt body: a different receipt.
    assert ingest_one(fields, b"body-2") == "ingested"
    row = VmDiskIoHourly.objects.get()
    assert row.windows == 2
    assert DiskIoReceipt.objects.count() == 2
    assert drain_counters()["dedupe_hits"] == 1


@pytest.mark.parametrize(
    ("start", "end"),
    [
        (T0, T0),  # empty window
        (T0, T0 - 1),  # negative
        (T0 - 3601, T0),  # longer than VALI_DISK_IO_MAX_WINDOW_S
        (T0 - 7 * 3600, T0 - 7 * 3600 + 60),  # older than VALI_DISK_IO_MAX_AGE_S
        (T0 + 3600, T0 + 3660),  # in the future beyond the skew
    ],
)
def test_implausible_windows_are_dropped(start: int, end: int) -> None:
    placement()
    assert ingest_one(receipt(delta(), start=start, end=end)) == "rejected-window"
    assert not DiskIoReceipt.objects.exists()
    assert not VmDiskIoHourly.objects.exists()


def test_a_receipt_about_another_vm_is_dropped() -> None:
    placement()
    fields = receipt(delta())
    assert on_verified_receipt(fields, body=b"x", source_id="vm-2", now=NOW) == "rejected-source"
    assert not VmDiskIoHourly.objects.exists()


def test_a_vm_without_an_active_placement_is_dropped() -> None:
    p = placement()
    Placement.objects.filter(pk=p.pk).update(
        status=PlacementStatus.FAILED.value, failed_at=NOW, reason="seed"
    )
    assert ingest_one(receipt(delta())) == "rejected-no-placement"
    assert not VmDiskIoHourly.objects.exists()


# ─── disk_probe stub ─────────────────────────────────────────────────


def _probe() -> DiskProbeResult:
    return DiskProbeResult(
        run_id_hex="ab" * 16,
        nonce_hex="cd" * 32,
        vm_id="vm-1",
        vcpus=2,
        kernel="6.8",
        release_version=5,
        started_at=T0,
        finished_at=T0 + 50,
        targets=(
            DiskProbeTarget(
                slot="os", profile="v1", metrics={"rand_read_iops": 1}, hist_qd1=(0,) * 32, error=""
            ),
        ),
    )


def test_a_probe_result_is_only_counted(monkeypatch: pytest.MonkeyPatch) -> None:
    placement()
    seen: list[str] = []
    real = probe_results.record_unverified

    def spy(probe: DiskProbeResult, **kw: str) -> None:
        seen.append(probe.run_id_hex)
        real(probe, **kw)

    monkeypatch.setattr(probe_results, "record_unverified", spy)
    assert ingest_one(receipt(probe=_probe())) == "ingested"
    assert seen == ["ab" * 16]
    assert not DiskProbeRun.objects.exists()
    assert not VmDiskIoHourly.objects.exists()
    assert drain_counters()["probe_results"] == 1


# ─── never fails the receipt path ────────────────────────────────────


def test_the_safe_wrapper_swallows_counts_and_rolls_back(monkeypatch: pytest.MonkeyPatch) -> None:
    placement()

    def boom(**_kw: object) -> None:
        raise RuntimeError("db on fire")

    monkeypatch.setattr(ingest, "_upsert", boom)
    # The safe wrapper judges freshness against the real clock.
    fields = receipt(delta(), start=int(time.time()) - 120)
    assert on_verified_receipt_safe(fields, body=b"b", source_id="vm-1") == "error"
    assert drain_counters()["errors"] == 1
    # The dedupe row went with the transaction: a retry is not a replay.
    assert not DiskIoReceipt.objects.exists()


def test_counters_flush_cumulatively() -> None:
    placement()
    ingest_one(receipt(delta(), seq=1))
    flush_counters_safe()
    ingest_one(receipt(delta(), start=T0 + 60, seq=2))
    ingest_one(receipt(delta(), start=T0 + 60, seq=2))  # replay
    flushed = flush_counters_safe()
    assert flushed["dedupe_hits"] == 1
    values = dict(DiskIngestCounter.objects.values_list("name", "value"))
    assert values["receipts_ingested"] == 2
    assert values["ingested_rows"] == 2
    assert values["dedupe_hits"] == 1
    assert "skipped_flag_off" not in values


def test_dedupe_rows_outlive_every_receipt_the_ingest_accepts(settings: Any) -> None:
    keep = ingest.dedupe_keep()
    assert keep > timedelta(
        seconds=settings.VALI_DISK_IO_MAX_AGE_S + settings.VALI_DISK_IO_MAX_SKEW_S
    )


# ─── review fixes: custody, bounds, owner key, query-free off ────────

NODE_B = node_id(2)


def _migrate(p: Placement, cutover: int) -> Placement:
    """Close `p` as migrated and open the destination placement on NODE_B,
    with the custody history billing reads."""
    from apps.scheduler.models import VmBillingAssignment

    Placement.objects.filter(pk=p.pk).update(
        status=PlacementStatus.MIGRATED.value, reason="migrated:job-1"
    )
    dest = make_placement(p.vm, NODE_B, status=PlacementStatus.BOUND.value, owner=p.owner)
    VmBillingAssignment.objects.create(vm_id="vm-1", node_id_hex=NODE, effective_from_unix=0)
    VmBillingAssignment.objects.create(
        vm_id="vm-1", node_id_hex=NODE_B, effective_from_unix=cutover, reason="migration"
    )
    return dest


def test_a_pre_cutover_window_metered_late_stays_on_the_source() -> None:
    src = placement()
    PlacementDisk.objects.create(
        placement=src, slot="os", kind="pool", pool_id="src-pool", size_gb=40, required_tier="nvme"
    )
    dest = _migrate(src, cutover=T0 + 300)
    PlacementDisk.objects.create(
        placement=dest, slot="os", kind="pool", pool_id="dst-pool", size_gb=40, required_tier="nvme"
    )
    # The source's buffered window, ingested after the cutover.
    assert ingest_one(receipt(delta(), start=T0, seq=1)) == "ingested"
    row = VmDiskIoHourly.objects.get()
    assert (row.miner_node_id, row.pool_id) == (NODE, "src-pool")
    # The destination's window in the same hour: never folded into the
    # source's pool.
    assert ingest_one(receipt(delta(), start=T0 + 360, seq=2)) == "ingested"
    row.refresh_from_db()
    assert (row.miner_node_id, row.pool_id, row.windows) == (NODE, "src-pool", 1)
    assert drain_counters()["straddled_move"] == 1


def test_unattributable_custody_is_dropped() -> None:
    from apps.scheduler.models import VmBillingAssignment

    placement()
    VmBillingAssignment.objects.create(vm_id="vm-1", node_id_hex="", effective_from_unix=0)
    assert ingest_one(receipt(delta())) == "rejected-no-placement"


def test_an_implausible_counter_skips_the_device() -> None:
    placement()
    ingest_one(receipt(delta("vda", "", r_ios=2**40 + 1), delta("vdb", "hippius-os")))
    assert list(VmDiskIoHourly.objects.values_list("device", flat=True)) == ["vdb"]
    assert drain_counters()["rejected_counters"] == 1


def test_a_long_owner_is_hashed_not_truncated() -> None:
    a, b = "o" * 200 + "a", "o" * 200 + "b"
    assert ingest.owner_key("user-1") == "user-1"
    assert ingest.owner_key(a) != ingest.owner_key(b)
    assert len(ingest.owner_key(a)) <= 128


def test_flag_off_is_query_free(settings: Any, django_assert_num_queries: Any) -> None:
    settings.VALI_DISK_IO_INGEST = False
    fields = receipt(delta())
    with django_assert_num_queries(0):
        assert ingest_one(fields) == "off"
        flush_counters_safe()
