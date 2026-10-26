"""Contract §9: dedicated disks with integrity — the intake
(`dedicated_disks.integrity`), the slot's integrity mode fixed by its first
assignment, the `x<N>:<GiB>:i` anchor (byte-identical without integrity),
the read-back's `integrity` / `initializing` / `init_percent`, and the
receipt's `initializing` verdict with its optional progress. (Launch path:
`apps/orchestration/tests/test_dedicated_integrity_launch.py`; feasibility:
`apps/scheduler/tests/test_feasibility_dedicated.py`.)"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from django.test import override_settings
from django.utils import timezone

from apps.disktier import dedicated
from apps.disktier.dedicated import DedicatedError, DedicatedRequest, ExtraDisk
from apps.disktier.models import DedicatedDisk, PlacementDisk
from apps.scheduler.models import PlacementStatus
from apps.scheduler.tests.factories import make_placement, make_vm, node_id
from apps.telemetry.verifier import DiskIoDelta

from .dedicated_helpers import ON, capable, make_disk

pytestmark = pytest.mark.django_db

NODE = node_id(1)
SSD = {"tier": "ssd", "count": 2, "min_size_gb": 16000}
#: Integrity sold: ssd + nvme on sale, integrity on, guest release 8.
INTEGRITY_ON: dict[str, Any] = dict(
    ON,
    VALI_DEDICATED_SELLABLE_TIERS=["hdd", "ssd", "nvme"],
    VALI_DEDICATED_INTEGRITY_ENABLED=True,
    VALI_DEDICATED_INTEGRITY_MIN_GUEST_RELEASE=8,
)


def _check(raw: Any, **kw: Any) -> DedicatedRequest:
    args: dict[str, Any] = dict(
        pinned_ack=True,
        tenant_id="t-1",
        user_id="u-1",
        require_failover_peer=False,
        guest_release=8,
    )
    args.update(kw)
    return dedicated.check_launch(raw, **args)


# ── intake ──────────────────────────────────────────────────────────


def test_integrity_is_optional_and_false_by_default() -> None:
    plain = dedicated.parse_request(SSD)
    assert plain.integrity is False
    assert dedicated.parse_request({**SSD, "integrity": False}) == plain
    # The stored / echoed request without integrity is byte-identical.
    assert plain.as_spec() == SSD
    assert dedicated.parse_request({**SSD, "integrity": False}).as_spec() == SSD
    on = dedicated.parse_request({**SSD, "integrity": True})
    assert on.integrity is True
    assert on.as_spec() == {**SSD, "integrity": True}


@pytest.mark.parametrize("value", [1, 0, "true", "false", None, [], {}, 1.0])
def test_a_non_bool_integrity_is_dedicated_invalid(value) -> None:
    with pytest.raises(DedicatedError) as exc:
        dedicated.parse_request({**SSD, "integrity": value})
    assert exc.value.category == "dedicated-invalid"


@override_settings(**INTEGRITY_ON)
def test_a_non_bool_integrity_is_400_before_any_409() -> None:
    with pytest.raises(DedicatedError) as exc:
        _check({**SSD, "tier": "hdd", "integrity": "yes"}, guest_release=1)
    assert exc.value.category == "dedicated-invalid"


@pytest.mark.parametrize(
    ("flags", "raw", "release", "category"),
    [
        # The switch off: any integrity: true is not offered, at any tier.
        ({**INTEGRITY_ON, "VALI_DEDICATED_INTEGRITY_ENABLED": False}, SSD, 8, "x"),
        (
            {**INTEGRITY_ON, "VALI_DEDICATED_INTEGRITY_ENABLED": False},
            {**SSD, "tier": "nvme"},
            8,
            "x",
        ),
        # hdd never takes integrity.
        (INTEGRITY_ON, {**SSD, "tier": "hdd"}, 8, "x"),
        # The release gate: integrity needs release >= 8.
        (INTEGRITY_ON, SSD, 7, "dedicated-needs-release"),
        (INTEGRITY_ON, SSD, None, "dedicated-needs-release"),
        (
            {**INTEGRITY_ON, "VALI_DEDICATED_INTEGRITY_MIN_GUEST_RELEASE": 9},
            SSD,
            8,
            "dedicated-needs-release",
        ),
        # The plain floor still applies when it is the higher one.
        (
            {**INTEGRITY_ON, "VALI_DEDICATED_MIN_GUEST_RELEASE": 10},
            SSD,
            9,
            "dedicated-needs-release",
        ),
        (
            {**INTEGRITY_ON, "VALI_DEDICATED_MIN_GUEST_RELEASE": None},
            SSD,
            99,
            "dedicated-needs-release",
        ),
        # Admitted.
        (INTEGRITY_ON, SSD, 8, ""),
        (INTEGRITY_ON, {**SSD, "tier": "nvme"}, 8, ""),
        (INTEGRITY_ON, SSD, 12, ""),
    ],
)
def test_the_integrity_intake_matrix(flags, raw, release, category) -> None:
    category = "dedicated-integrity-not-offered" if category == "x" else category
    with override_settings(**flags):
        if not category:
            assert _check({**raw, "integrity": True}, guest_release=release).integrity is True
            return
        with pytest.raises(DedicatedError) as exc:
            _check({**raw, "integrity": True}, guest_release=release)
    assert exc.value.category == category
    assert category in dedicated.CONFLICT_CATEGORIES


@override_settings(**INTEGRITY_ON)
def test_without_integrity_the_old_release_floor_and_tiers_still_launch() -> None:
    """A launch without integrity is untouched by §9: hdd, release 5."""
    assert _check({**SSD, "tier": "hdd"}, guest_release=5).integrity is False
    with override_settings(VALI_DEDICATED_INTEGRITY_ENABLED=False):
        assert _check(SSD, guest_release=5) == DedicatedRequest("ssd", 2, 16000)


@override_settings(**{**INTEGRITY_ON, "VALI_DEDICATED_SELLABLE_TIERS": ["hdd"]})
def test_a_tier_not_on_sale_is_disks_not_offered_before_integrity() -> None:
    with pytest.raises(DedicatedError) as exc:
        _check({**SSD, "integrity": True})
    assert exc.value.category == "dedicated-disks-not-offered"


@override_settings(**INTEGRITY_ON)
def test_integrity_not_offered_comes_before_the_failover_and_release_409s() -> None:
    with (
        override_settings(VALI_DEDICATED_INTEGRITY_ENABLED=False),
        pytest.raises(DedicatedError) as exc,
    ):
        _check({**SSD, "integrity": True}, require_failover_peer=True, guest_release=1)
    assert exc.value.category == "dedicated-integrity-not-offered"


def test_the_spec_round_trips_integrity_and_refuses_a_bad_value() -> None:
    assert dedicated.spec_request({"dedicated_disks": SSD}).integrity is False
    req = dedicated.spec_request({"dedicated_disks": {**SSD, "integrity": True}})
    assert req == DedicatedRequest("ssd", 2, 16000, integrity=True)
    with pytest.raises(ValueError):
        dedicated.spec_request({"dedicated_disks": {**SSD, "integrity": "yes"}})


def test_the_settings_defaults(settings) -> None:
    assert settings.VALI_DEDICATED_INTEGRITY_ENABLED is False
    assert settings.VALI_DEDICATED_INTEGRITY_MIN_GUEST_RELEASE == 8
    assert dedicated.integrity_enabled() is False
    assert dedicated.integrity_min_guest_release() == 8


def test_the_settings_read_the_env(monkeypatch) -> None:
    import importlib

    import vali.settings as prod_settings

    monkeypatch.setenv("VALI_DEDICATED_INTEGRITY_ENABLED", "true")
    monkeypatch.setenv("VALI_DEDICATED_INTEGRITY_MIN_GUEST_RELEASE", "9")
    try:
        got = importlib.reload(prod_settings)
        assert got.VALI_DEDICATED_INTEGRITY_ENABLED is True
        assert got.VALI_DEDICATED_INTEGRITY_MIN_GUEST_RELEASE == 9
        monkeypatch.setenv("VALI_DEDICATED_INTEGRITY_MIN_GUEST_RELEASE", "0")
        with pytest.raises(RuntimeError):
            importlib.reload(prod_settings)
    finally:
        monkeypatch.delenv("VALI_DEDICATED_INTEGRITY_ENABLED")
        monkeypatch.delenv("VALI_DEDICATED_INTEGRITY_MIN_GUEST_RELEASE")
        importlib.reload(prod_settings)


# ── the anchor ──────────────────────────────────────────────────────


def test_the_anchor_suffixes_integrity_slots_only() -> None:
    plain = [ExtraDisk("x0", "wwn-0x1", 22300), ExtraDisk("x1", "wwn-0x2", 16000)]
    assert dedicated.cmdline_value(plain) == "x0:22300,x1:16000"
    both = [ExtraDisk(d.slot, d.disk_id, d.size_gb, integrity=True) for d in plain]
    assert dedicated.cmdline_value(both) == "x0:22300:i,x1:16000:i"
    mixed = [plain[0], both[1]]
    assert dedicated.cmdline_value(mixed) == "x0:22300,x1:16000:i"
    # The order's entries never change (the agent opens the same disks).
    assert dedicated.order_entries(both) == dedicated.order_entries(plain)


def test_the_stand_in_covers_the_longest_integrity_anchor() -> None:
    plain = DedicatedRequest("ssd", 8, 16000)
    integ = DedicatedRequest("ssd", 8, 16000, integrity=True)
    # Without integrity the stand-in is exactly what it was.
    assert dedicated.stand_in_cmdline_value(plain) == ",".join(["x23:1048576"] * 8)
    widest = [
        ExtraDisk(f"x{16 + i}", f"wwn-0x{i}", dedicated.MAX_SIZE_CLASS_GIB, integrity=True)
        for i in range(8)
    ]
    assert len(dedicated.stand_in_cmdline_value(integ)) >= len(dedicated.cmdline_value(widest))


def _assigned(request: DedicatedRequest, sizes=(22354, 16050)) -> tuple[Any, Any]:
    capable(NODE)
    vm = make_vm("vm-int", "lease-int")
    placement = make_placement(vm, NODE, status=PlacementStatus.BOUND.value)
    for i, size in enumerate(sizes):
        make_disk(f"wwn-0x0{i}", node=NODE, size_gib=size, tier=request.tier)
    with override_settings(**INTEGRITY_ON):
        dedicated.assign(placement, vm, request)
    return vm, placement


def test_assign_records_the_integrity_of_every_slot() -> None:
    vm, placement = _assigned(DedicatedRequest("ssd", 2, 16000, integrity=True))
    assert sorted(
        PlacementDisk.objects.filter(placement=placement).values_list("slot", "integrity")
    ) == [("x0", True), ("x1", True)]
    disks = dedicated.extra_disks(vm.vm_id, NODE)
    assert [d.integrity for d in disks] == [True, True]
    assert dedicated.cmdline_value(disks) == "x0:16000:i,x1:22300:i"


def test_a_plain_assignment_measures_the_anchor_as_before() -> None:
    vm, placement = _assigned(DedicatedRequest("ssd", 2, 16000))
    assert not PlacementDisk.objects.filter(placement=placement, integrity=True).exists()
    assert dedicated.cmdline_value(dedicated.extra_disks(vm.vm_id, NODE)) == "x0:16000,x1:22300"


@pytest.mark.parametrize("first", [True, False])
def test_a_later_placement_keeps_each_slots_first_integrity(first: bool) -> None:
    """`_reuse` (a relaunch's / a retried launch's new placement of held
    disks) copies the slot's FIRST mode, whatever the request now says:
    the guest formatted the disk so."""
    vm, placement = _assigned(DedicatedRequest("ssd", 2, 16000, integrity=first))
    PlacementDisk.objects.filter(placement=placement).update(created_at=timezone.now())
    from apps.scheduler.models import Placement

    Placement.objects.filter(pk=placement.pk).update(
        status=PlacementStatus.FAILED.value, failed_at=timezone.now(), reason="test"
    )
    again = make_placement(vm, NODE, status=PlacementStatus.BOUND.value)
    with override_settings(**INTEGRITY_ON):
        rows = dedicated.assign(again, vm, DedicatedRequest("ssd", 2, 16000, integrity=not first))
    assert [r.integrity for r in rows] == [first, first]
    assert [d.integrity for d in dedicated.extra_disks(vm.vm_id, NODE)] == [first, first]


# ── the read-back ───────────────────────────────────────────────────


def _held(vm: Any) -> None:
    DedicatedDisk.objects.filter(assigned_vm=vm).update(
        reported_state="assigned", reported_vm_id=vm.vm_id, reported_at=timezone.now()
    )


def test_the_read_back_marks_integrity_slots_only() -> None:
    vm, _p = _assigned(DedicatedRequest("ssd", 2, 16000, integrity=True))
    _held(vm)
    disks = dedicated.read_back(vm, os_disk=(40, "nvme"))["disks"]
    assert disks[0] == {
        "slot": "os",
        "kind": "pool",
        "size_gb": 40,
        "tier": "nvme",
        "state": "attached",
    }
    assert [d.get("integrity") for d in disks[1:]] == [True, True]
    assert all(d["state"] == "attached" for d in disks[1:])


def test_a_plain_read_back_is_byte_identical() -> None:
    vm, _p = _assigned(DedicatedRequest("ssd", 1, 16000), sizes=(22354,))
    _held(vm)
    assert dedicated.read_back(vm, os_disk=(40, "nvme"))["disks"][1] == {
        "slot": "x0",
        "kind": "dedicated",
        "size_gb": 22300,
        "tier": "ssd",
        "state": "attached",
    }


def test_initializing_then_attached_with_its_progress() -> None:
    vm, placement = _assigned(DedicatedRequest("ssd", 1, 16000, integrity=True), sizes=(22354,))
    _held(vm)
    t0 = datetime(2026, 10, 23, 12, 0, tzinfo=UTC)

    def slot() -> dict[str, Any]:
        return dedicated.read_back(vm, os_disk=(40, "nvme"))["disks"][1]

    assert "guest_state" not in slot() and "init_percent" not in slot()
    dedicated.record_slot_verdicts(placement.pk, {"x0": "initializing"}, t0, {"x0": 12})
    assert (slot()["guest_state"], slot()["init_percent"], slot()["state"]) == (
        "initializing",
        12,
        "attached",
    )
    # A window without progress: initializing, init_percent null.
    dedicated.record_slot_verdicts(placement.pk, {"x0": "initializing"}, t0 + timedelta(minutes=1))
    assert (slot()["guest_state"], slot()["init_percent"]) == ("initializing", None)
    assert "init_percent" in slot()
    # An older window never rolls it back.
    dedicated.record_slot_verdicts(placement.pk, {"x0": "initializing"}, t0, {"x0": 99})
    assert slot()["init_percent"] is None
    dedicated.record_slot_verdicts(
        placement.pk, {"x0": "ok"}, t0 + timedelta(minutes=2), {"x0": 100}
    )
    assert slot() == {
        "slot": "x0",
        "kind": "dedicated",
        "size_gb": 22300,
        "tier": "ssd",
        "state": "attached",
        "integrity": True,
        "guest_state": "attached",
    }
    assert PlacementDisk.objects.get(placement=placement).observed_percent is None


def test_initializing_on_a_slot_without_integrity_is_not_shown() -> None:
    """Forgeable, and meaningless without a wipe: a plain slot's read-back
    keeps its pre-§9 shape."""
    vm, placement = _assigned(DedicatedRequest("ssd", 1, 16000), sizes=(22354,))
    _held(vm)
    dedicated.record_slot_verdicts(
        placement.pk, {"x0": "initializing"}, datetime(2026, 10, 23, tzinfo=UTC), {"x0": 5}
    )
    entry = dedicated.read_back(vm, os_disk=(40, "nvme"))["disks"][1]
    assert "guest_state" not in entry and "init_percent" not in entry


def test_initializing_never_drives_state_or_pay() -> None:
    vm, placement = _assigned(DedicatedRequest("ssd", 1, 16000, integrity=True), sizes=(22354,))
    dedicated.record_slot_verdicts(
        placement.pk, {"x0": "initializing"}, datetime(2026, 10, 23, tzinfo=UTC), {"x0": 50}
    )
    # No host evidence yet: missing, and not payable, whatever the guest says.
    assert dedicated.read_back(vm, os_disk=(40, "nvme"))["disks"][1]["state"] == "missing"
    assert dedicated.payable_gb(vm.vm_id) == 0
    _held(vm)
    assert dedicated.payable_gb(vm.vm_id) == 22300


# ── the receipt ─────────────────────────────────────────────────────


def _delta(serial: str, state: str, init_percent: int | None = None) -> DiskIoDelta:
    return DiskIoDelta(
        dev="vdb" if state != "missing" else "",
        serial=serial,
        state=state,
        r_ios=0,
        r_sectors=0,
        r_ticks_ms=0,
        w_ios=0,
        w_sectors=0,
        w_ticks_ms=0,
        io_ticks_ms=0,
        tiq_ms=0,
        inflight=0,
        init_percent=init_percent,
    )


def test_the_receipt_reads_initializing_and_its_optional_progress() -> None:
    io = [
        _delta("hippius-x0", "initializing", 40),
        _delta("hippius-x1", "initializing"),
        _delta("hippius-x2", "ok"),
        _delta("hippius-os", "initializing", 7),
        # A progress on any other state is no wipe's.
        _delta("hippius-x3", "ok", 9),
    ]
    assert dedicated.slot_verdicts(io) == {
        "x0": "initializing",
        "x1": "initializing",
        "x2": "ok",
        "x3": "ok",
    }
    assert dedicated.slot_progress(io) == {"x0": 40}


def test_the_ingest_stores_initializing_and_its_progress_then_attached(settings) -> None:
    """A verified receipt's `initializing` entry, with or without its
    `init_percent`, lands on the slot; never folded into the I/O hours (the
    wipe's own writes are no tier evidence)."""
    from apps.disktier.ingest import on_verified_receipt
    from apps.disktier.models import VmDiskIoHourly
    from apps.telemetry.verifier import ServedReceiptFields

    settings.VALI_DISK_IO_INGEST = True
    vm, placement = _assigned(DedicatedRequest("ssd", 2, 16000, integrity=True))
    _held(vm)
    now = timezone.now()
    end = int(now.timestamp()) - 60

    def receipt(seq: int, *io: DiskIoDelta) -> str:
        fields = ServedReceiptFields(
            vm_id=vm.vm_id,
            lease_id=vm.lease_id,
            node_id_hex=NODE,
            epoch=5,
            resource_class="small",
            period_start=end - 60 + seq,
            period_end=end + seq,
            monotonic_seq=seq,
            observed_degradation_bps=0,
            disk_io=io,
            disk_probe=None,
        )
        return on_verified_receipt(fields, body=f"r{seq}".encode(), source_id=vm.vm_id, now=now)

    assert (
        receipt(1, _delta("hippius-x0", "initializing", 61), _delta("hippius-x1", "initializing"))
        == "ingested"
    )
    slots = {d["slot"]: d for d in dedicated.read_back(vm, os_disk=(40, "nvme"))["disks"]}
    assert (slots["x0"]["guest_state"], slots["x0"]["init_percent"]) == ("initializing", 61)
    assert (slots["x1"]["guest_state"], slots["x1"]["init_percent"]) == ("initializing", None)
    assert not VmDiskIoHourly.objects.exists()
    receipt(2, _delta("hippius-x0", "ok"), _delta("hippius-x1", "initializing", 5))
    slots = {d["slot"]: d for d in dedicated.read_back(vm, os_disk=(40, "nvme"))["disks"]}
    assert slots["x0"]["guest_state"] == "attached" and "init_percent" not in slots["x0"]
    assert slots["x1"]["init_percent"] == 5


def test_a_placement_reopened_on_the_host_carries_integrity_and_progress() -> None:
    """`open_placement_on_node` (a live VM whose placement was drained) and
    the in-place resize's swap copy the slot rows (`_carry_placement_disks`):
    the integrity mode and the wipe progress come along."""
    from apps.scheduler import service as sched
    from apps.scheduler.models import Placement
    from apps.scheduler.tests.factories import make_service_client

    vm, placement = _assigned(DedicatedRequest("ssd", 2, 16000, integrity=True))
    dedicated.record_slot_verdicts(
        placement.pk, {"x0": "initializing"}, datetime(2026, 10, 23, tzinfo=UTC), {"x0": 33}
    )
    Placement.objects.filter(pk=placement.pk).update(
        status=PlacementStatus.FAILED.value, failed_at=timezone.now(), reason="drained"
    )
    reopened = sched.open_placement_on_node(
        vm, node_id=NODE, decided_by=make_service_client(), reason="t"
    )
    assert reopened is not None and reopened.pk != placement.pk
    rows = {
        r.slot: (r.integrity, r.observed_state, r.observed_percent)
        for r in PlacementDisk.objects.filter(placement=reopened)
    }
    assert rows == {"x0": (True, "initializing", 33), "x1": (True, "", None)}
    assert dedicated.cmdline_value(dedicated.extra_disks(vm.vm_id, NODE)) == (
        "x0:16000:i,x1:22300:i"
    )


def test_a_forged_initializing_on_a_plain_slot_keeps_its_last_verdict() -> None:
    vm, placement = _assigned(DedicatedRequest("ssd", 1, 16000), sizes=(22354,))
    _held(vm)
    t0 = datetime(2026, 10, 23, tzinfo=UTC)
    dedicated.record_slot_verdicts(placement.pk, {"x0": "ok"}, t0)
    assert (
        dedicated.record_slot_verdicts(
            placement.pk, {"x0": "initializing"}, t0 + timedelta(minutes=1), {"x0": 5}
        )
        == 0
    )
    entry = dedicated.read_back(vm, os_disk=(40, "nvme"))["disks"][1]
    assert entry["guest_state"] == "attached" and "init_percent" not in entry


def test_initializing_windows_are_neither_counted_nor_folded(settings) -> None:
    from apps.disktier.ingest import drain_counters, on_verified_receipt
    from apps.telemetry.verifier import ServedReceiptFields

    settings.VALI_DISK_IO_INGEST = True
    vm, _placement = _assigned(DedicatedRequest("ssd", 1, 16000, integrity=True), sizes=(22354,))
    drain_counters()
    now = timezone.now()
    end = int(now.timestamp()) - 60
    fields = ServedReceiptFields(
        vm_id=vm.vm_id,
        lease_id=vm.lease_id,
        node_id_hex=NODE,
        epoch=5,
        resource_class="small",
        period_start=end - 60,
        period_end=end,
        monotonic_seq=1,
        observed_degradation_bps=0,
        disk_io=(_delta("hippius-x0", "initializing", 3),),
        disk_probe=None,
    )
    assert on_verified_receipt(fields, body=b"r", source_id=vm.vm_id, now=now) == "ingested"
    counters = drain_counters()
    assert counters.get("slot_verdicts", 0) == 0
    assert counters.get("unresolved_slots", 0) == 0


@pytest.mark.parametrize(
    ("integrity", "release", "refused"),
    [(False, 6, False), (False, 7, False), (True, 6, True), (True, 7, True), (True, 8, False)],
)
def test_a_vm_with_integrity_slots_never_boots_a_guest_below_the_integrity_floor(
    settings, integrity, release, refused
) -> None:
    """Guest upgrades and initrd swaps (`guest_release_refusal`): an
    integrity slot raises the floor to `VALI_DEDICATED_INTEGRITY_MIN_GUEST_RELEASE`."""
    settings.VALI_DEDICATED_MIN_GUEST_RELEASE = 6
    settings.VALI_DEDICATED_INTEGRITY_MIN_GUEST_RELEASE = 8
    vm, _p = _assigned(DedicatedRequest("ssd", 1, 16000, integrity=integrity), sizes=(22354,))
    assert dedicated.has_integrity_slot(vm) is integrity
    assert bool(dedicated.guest_release_refusal(vm, release)) is refused


def test_a_launch_record_sold_with_integrity_counts_before_any_slot() -> None:
    from apps.orchestration.models import LaunchJob, LaunchJobState
    from apps.orchestration.tests.factories import make_service_client

    vm = make_vm("vm-int-spec", "lease-is")
    LaunchJob.objects.create(
        job_id="job-int-spec",
        vm_id=vm.vm_id,
        tenant_id="t",
        flavor="small",
        spec_json={"dedicated_disks": {**SSD, "integrity": True}},
        userdata_vault_path="x",
        userdata_vault_version=1,
        kek_vault_path="k",
        state=LaunchJobState.SUCCEEDED.value,
        phase_started_at=timezone.now(),
        finished_at=timezone.now(),
        decided_by=make_service_client(),
    )
    assert dedicated.has_integrity_slot(vm) is True
    assert dedicated.has_integrity_slot(make_vm("vm-plain-spec", "lease-ps")) is False
