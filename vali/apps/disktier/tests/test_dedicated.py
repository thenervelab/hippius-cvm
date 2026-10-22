"""E4 dedicated disks — `apps.disktier.dedicated` (the frozen contract,
docs/design/dedicated-disks-contract.md): intake, capacity, assignment,
the order/cmdline values, the read-back and the receipt's slot verdicts."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from django.test import override_settings
from django.utils import timezone

from apps.disktier import dedicated
from apps.disktier.dedicated import DedicatedError, DedicatedRequest, DisksTaken, ExtraDisk
from apps.disktier.models import (
    DedicatedDisk,
    DedicatedDiskDesiredState,
    DedicatedDiskState,
    DiskKind,
    PlacementDisk,
)
from apps.lifecycle.models import VmState
from apps.scheduler.models import PlacementStatus
from apps.scheduler.tests.factories import make_placement, make_vm, node_id

from .dedicated_helpers import ON, capable, make_disk

pytestmark = pytest.mark.django_db

NODE = node_id(1)
OTHER = node_id(2)
REQ = DedicatedRequest(tier="hdd", count=2, min_size_gb=16000)
GOOD = {"tier": "hdd", "count": 2, "min_size_gb": 16000}


def _check(raw: Any = None, **kw: Any) -> DedicatedRequest:
    args: dict[str, Any] = dict(
        pinned_ack=True,
        tenant_id="t-1",
        user_id="u-1",
        require_failover_peer=False,
        guest_release=5,
    )
    args.update(kw)
    return dedicated.check_launch(GOOD if raw is None else raw, **args)


# ── intake ──────────────────────────────────────────────────────────


def test_a_good_request_parses() -> None:
    assert dedicated.parse_request(GOOD) == REQ
    assert REQ.as_spec() == GOOD
    assert dedicated.parse_request({**GOOD, "count": 8, "min_size_gb": 1000}).count == 8


@pytest.mark.parametrize(
    "raw",
    [
        [],
        "hdd",
        0,
        True,
        {},
        {"tier": "hdd", "count": 2},
        {**GOOD, "extra": 1},
        {**GOOD, "tier": "ssd"},
        {**GOOD, "tier": "HDD"},
        {**GOOD, "tier": None},
        {**GOOD, "count": "2"},
        {**GOOD, "count": True},
        {**GOOD, "count": 2.0},
        {**GOOD, "min_size_gb": "16000"},
        {**GOOD, "min_size_gb": False},
    ],
)
def test_a_malformed_request_is_dedicated_invalid(raw) -> None:
    with pytest.raises(DedicatedError) as exc:
        dedicated.parse_request(raw)
    assert exc.value.category == "dedicated-invalid"


@pytest.mark.parametrize("count", [0, -1, 9, 100])
def test_a_count_off_1_to_8_is_count_invalid(count) -> None:
    with pytest.raises(DedicatedError) as exc:
        dedicated.parse_request({**GOOD, "count": count})
    assert exc.value.category == "dedicated-count-invalid"


@override_settings(VALI_DEDICATED_MAX_PER_VM=2)
def test_the_count_bound_is_the_flag() -> None:
    assert dedicated.parse_request({**GOOD, "count": 2}).count == 2
    with pytest.raises(DedicatedError) as exc:
        dedicated.parse_request({**GOOD, "count": 3})
    assert exc.value.category == "dedicated-count-invalid"


@pytest.mark.parametrize("size", [0, 999, -1000])
def test_a_size_below_1000_gib_is_size_invalid(size) -> None:
    with pytest.raises(DedicatedError) as exc:
        dedicated.parse_request({**GOOD, "min_size_gb": size})
    assert exc.value.category == "dedicated-size-invalid"


@pytest.mark.parametrize("raw", [GOOD, {}, [], "garbage"])
def test_off_every_request_is_not_offered_whatever_its_shape(raw) -> None:
    with pytest.raises(DedicatedError) as exc:
        _check(raw)
    assert exc.value.category == "dedicated-disks-not-offered"


@override_settings(**ON, VALI_DEDICATED_ALLOWED_OWNERS=["canary-tenant", "canary-user"])
def test_the_allowlist_admits_its_owners_only_and_before_the_body() -> None:
    with pytest.raises(DedicatedError) as exc:
        _check({"junk": 1}, tenant_id="t-1", user_id="u-1")
    assert exc.value.category == "dedicated-disks-not-offered"
    assert _check(tenant_id="canary-tenant") == REQ
    assert _check(user_id="canary-user") == REQ


@override_settings(**ON)
def test_on_with_no_allowlist_every_owner_may() -> None:
    assert _check() == REQ


@override_settings(**ON)
@pytest.mark.parametrize("ack", [None, False, "true", 1])
def test_without_a_true_ack_it_is_ack_required(ack) -> None:
    with pytest.raises(DedicatedError) as exc:
        _check(pinned_ack=ack)
    assert exc.value.category == "dedicated-ack-required"


@override_settings(**ON)
def test_the_body_is_checked_before_the_ack() -> None:
    with pytest.raises(DedicatedError) as exc:
        _check({**GOOD, "count": 0}, pinned_ack=None)
    assert exc.value.category == "dedicated-count-invalid"


@override_settings(**ON)
def test_with_require_failover_peer_it_is_no_failover() -> None:
    with pytest.raises(DedicatedError) as exc:
        _check(require_failover_peer=True)
    assert exc.value.category == "dedicated-no-failover"


@override_settings(**ON)
@pytest.mark.parametrize("release", [None, 1, 4])
def test_an_image_below_the_release_is_needs_release(release) -> None:
    with pytest.raises(DedicatedError) as exc:
        _check(guest_release=release)
    assert exc.value.category == "dedicated-needs-release"
    assert _check(guest_release=5) == REQ
    assert _check(guest_release=9) == REQ


@override_settings(**{**ON, "VALI_DEDICATED_MIN_GUEST_RELEASE": None})
def test_no_release_set_refuses_every_image() -> None:
    with pytest.raises(DedicatedError) as exc:
        _check(guest_release=10**6)
    assert exc.value.category == "dedicated-needs-release"


def test_the_spec_reads_back() -> None:
    assert dedicated.spec_request({}) is None
    assert dedicated.spec_request({"dedicated_disks": None}) is None
    assert dedicated.spec_request({"dedicated_disks": GOOD}) == REQ
    with pytest.raises(ValueError):
        dedicated.spec_request({"dedicated_disks": {"tier": "hdd"}})
    with pytest.raises(ValueError):
        dedicated.spec_request({"dedicated_disks": "x"})


# ── capacity ────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    ("size_bytes", "klass"),
    [(None, 0), (0, 0), (99 * 2**30, 0), (22354 * 2**30, 22300), (16000 * 2**30, 16000)],
)
def test_the_size_class_is_floored_to_100_gib(size_bytes, klass) -> None:
    assert dedicated.size_class_gb(size_bytes) == klass


@override_settings(**ON)
def test_free_counts_take_every_qualifying_disk_of_a_capable_node() -> None:
    capable(NODE)
    capable(OTHER, version="v2026.10.01")  # too old
    make_disk("wwn-0x01", size_gib=16000)
    make_disk("wwn-0x02", tier="ssd")
    make_disk("wwn-0x03", tier="nvme")
    make_disk("wwn-0x04", node=OTHER)
    assert dedicated.free_counts(REQ, [NODE, OTHER]) == {NODE: 3}


@override_settings(**ON)
@pytest.mark.parametrize(
    "excluded",
    [
        dict(state=DedicatedDiskState.PENDING_PROBE),
        dict(state=DedicatedDiskState.RELEASED),
        dict(state=DedicatedDiskState.FAILED),
        dict(desired_state=DedicatedDiskDesiredState.DRAINING),
        dict(tier="unknown"),
        dict(tier="unfit"),
        dict(size_gib=15999),
        dict(size_gib=1_048_676),  # a size class past what the guest measures
        dict(reported_state="assigned", reported_vm_id="vm-x"),
        dict(reported_state="failed"),
        dict(reported_vm_id="vm-x"),
        dict(reported_at=timezone.now() - timedelta(minutes=16)),
        dict(reported_at=None),
        dict(size_bytes=None),
    ],
)
def test_a_disk_that_does_not_qualify_is_not_counted(excluded) -> None:
    capable(NODE)
    make_disk("wwn-0x01", **excluded)
    assert dedicated.free_counts(REQ, [NODE]) == {}


@pytest.mark.parametrize("minimum", ["", "v2099.01.01"])
def test_no_node_qualifies_without_an_agent_at_the_minimum(minimum) -> None:
    capable(NODE)
    make_disk("wwn-0x01")
    with override_settings(**{**ON, "VALI_DEDICATED_MIN_AGENT_VERSION": minimum}):
        assert dedicated.free_counts(REQ, [NODE]) == {}
        assert dedicated.capable_node_ids([NODE]) == frozenset()
    with override_settings(**ON):
        assert dedicated.free_counts(REQ, [NODE]) == {NODE: 1}


# ── assignment ──────────────────────────────────────────────────────


def _placement(vm_id: str = "vm-d1", node: str = NODE, **kw: Any):
    vm = make_vm(vm_id, f"lease-{vm_id}")
    return make_placement(vm, node, **kw), vm


@override_settings(**ON)
def test_assign_takes_the_smallest_then_the_most_recently_probed() -> None:
    capable(NODE)
    now = timezone.now()
    make_disk("wwn-0xbig", size_gib=30000)
    make_disk("wwn-0xold", size_gib=20000, probed_at=now - timedelta(days=9))
    make_disk("wwn-0xnew", size_gib=20000, probed_at=now - timedelta(days=1))
    make_disk("wwn-0xsmall", size_gib=18000)
    placement, vm = _placement()
    rows = dedicated.assign(placement, vm, REQ)
    assert [(r.slot, r.dedicated_disk.disk_id) for r in rows] == [
        ("x0", "wwn-0xsmall"),
        ("x1", "wwn-0xnew"),
    ]
    assert [(r.kind, r.size_gb, r.required_tier) for r in rows] == [
        (DiskKind.DEDICATED, 18000, "hdd"),
        (DiskKind.DEDICATED, 20000, "hdd"),
    ]
    taken = DedicatedDisk.objects.get(disk_id="wwn-0xsmall")
    assert (taken.state, taken.assigned_vm_id, taken.assigned_slot) == ("assigned", vm.pk, "x0")
    assert taken.assigned_at is not None
    left = set(DedicatedDisk.objects.filter(state="free").values_list("disk_id", flat=True))
    assert left == {"wwn-0xbig", "wwn-0xold"}


@override_settings(**ON)
def test_a_disk_is_never_assigned_twice() -> None:
    capable(NODE)
    make_disk("wwn-0x01")
    make_disk("wwn-0x02")
    first, vm1 = _placement("vm-a")
    dedicated.assign(first, vm1, REQ)
    second, vm2 = _placement("vm-b", status=PlacementStatus.PENDING.value)
    with pytest.raises(DisksTaken):
        dedicated.assign(second, vm2, REQ)
    assert set(DedicatedDisk.objects.values_list("assigned_vm__vm_id", flat=True)) == {"vm-a"}
    assert not PlacementDisk.objects.filter(placement=second).exists()


@override_settings(**ON)
def test_assign_refuses_a_node_whose_agent_does_not_take_the_disks() -> None:
    capable(NODE, version="v2020.01.01")
    make_disk("wwn-0x01")
    make_disk("wwn-0x02")
    placement, vm = _placement()
    with pytest.raises(DisksTaken):
        dedicated.assign(placement, vm, REQ)
    assert DedicatedDisk.objects.filter(state="free").count() == 2


@override_settings(**ON)
def test_a_slot_is_never_reused() -> None:
    capable(NODE)
    for i in range(4):
        make_disk(f"wwn-0x0{i}")
    placement, vm = _placement()
    dedicated.assign(placement, vm, REQ)
    # The VM's first disks were given back (an attempt before the register);
    # their rows are gone, so their slots are free again...
    dedicated.revert_unused(placement)
    assert [r.slot for r in dedicated.assign(placement, vm, REQ)] == ["x0", "x1"]
    # ...but a slot the VM still has a row for is never handed out again
    # (its disks failed: the VM no longer holds them).
    DedicatedDisk.objects.filter(assigned_vm=vm).update(
        state="failed", assigned_vm=None, assigned_slot=""
    )
    later = make_placement(vm, NODE, status=PlacementStatus.FAILED.value)
    assert [r.slot for r in dedicated.assign(later, vm, REQ)] == ["x2", "x3"]


@override_settings(**ON)
def test_a_vm_that_holds_disks_takes_them_again_never_a_second_set() -> None:
    capable(NODE)
    capable(OTHER)
    for i in range(4):
        make_disk(f"wwn-0x0{i}")
    make_disk("wwn-0x10", node=OTHER)
    make_disk("wwn-0x11", node=OTHER)
    first, vm = _placement()
    held = {r.dedicated_disk_id: r.slot for r in dedicated.assign(first, vm, REQ)}
    again = make_placement(vm, NODE, status=PlacementStatus.FAILED.value)
    rows = dedicated.assign(again, vm, REQ)
    assert {r.dedicated_disk_id: r.slot for r in rows} == held
    assert {r.size_gb for r in rows} == {22300}
    assert DedicatedDisk.objects.filter(state="free", miner_node_id=NODE).count() == 2
    # Never on another node, never at another count.
    with pytest.raises(DisksTaken):
        dedicated.assign(make_placement(vm, OTHER, status="failed"), vm, REQ)
    with pytest.raises(DisksTaken):
        dedicated.assign(
            make_placement(vm, NODE, status="failed"), vm, DedicatedRequest("hdd", 3, 16000)
        )
    assert dedicated.held_counts(vm.vm_id) == {NODE: 2}
    assert dedicated.held_counts("vm-nobody") is None


@override_settings(**ON)
def test_the_size_sold_is_the_probed_one_never_the_miners_report() -> None:
    capable(NODE)
    # The miner now claims a bigger disk than the probe measured.
    make_disk("wwn-0x01", size_gib=40000, verified_size_bytes=16050 * 2**30)
    make_disk("wwn-0x02", verified_size_bytes=None)  # never probed
    make_disk("wwn-0x03", size_gib=16000, verified_size_bytes=20000 * 2**30)  # shrunk
    assert dedicated.free_counts(DedicatedRequest("hdd", 1, 20000), [NODE]) == {}
    placement, vm = _placement()
    (row,) = dedicated.assign(placement, vm, DedicatedRequest("hdd", 1, 16000))
    assert (row.dedicated_disk.disk_id, row.size_gb) == ("wwn-0x01", 16000)
    # Held, the miner then reports it smaller than probed: not the disk sold.
    DedicatedDisk.objects.filter(disk_id="wwn-0x01").update(size_bytes=1000 * 2**30)
    assert dedicated.read_back(vm, os_disk=(40, "nvme"))["disks"][1]["state"] == "mismatch"


@override_settings(**ON)
def test_revert_gives_the_disks_back_free_and_drops_the_rows() -> None:
    capable(NODE)
    make_disk("wwn-0x01")
    make_disk("wwn-0x02")
    placement, vm = _placement()
    dedicated.assign(placement, vm, REQ)
    assert dedicated.revert_unused(placement) == 2
    assert set(DedicatedDisk.objects.values_list("state", flat=True)) == {"free"}
    assert not DedicatedDisk.objects.filter(assigned_vm__isnull=False).exists()
    assert not PlacementDisk.objects.exists()


@override_settings(**ON)
def test_revert_never_frees_a_disk_another_vm_holds() -> None:
    capable(NODE)
    make_disk("wwn-0x01")
    make_disk("wwn-0x02")
    placement, vm = _placement()
    dedicated.assign(placement, vm, REQ)
    other = make_vm("vm-other", "lease-o")
    DedicatedDisk.objects.filter(disk_id="wwn-0x01").update(assigned_vm=other)
    assert dedicated.revert_unused(placement) == 1
    assert DedicatedDisk.objects.get(disk_id="wwn-0x01").state == "assigned"


# ── the order and the cmdline ───────────────────────────────────────


@override_settings(**ON)
def test_extra_disks_are_the_active_placements_rows_on_that_node_in_slot_order() -> None:
    capable(NODE)
    placement, vm = _placement()
    for slot, disk_id in (("x10", "wwn-0x0a"), ("x2", "wwn-0x02")):
        disk = make_disk(disk_id, state="assigned", assigned_vm=vm, assigned_slot=slot)
        PlacementDisk.objects.create(
            placement=placement,
            slot=slot,
            kind="dedicated",
            dedicated_disk=disk,
            size_gb=22300,
            required_tier="hdd",
        )
    assert dedicated.extra_disks("vm-d1", NODE.upper()) == [
        ExtraDisk("x2", "wwn-0x02", 22300),
        ExtraDisk("x10", "wwn-0x0a", 22300),
    ]
    assert dedicated.extra_disks("vm-d1", OTHER) == []
    _close(placement, "drain:miner-stale")
    assert dedicated.extra_disks("vm-d1", NODE) == []


def _close(placement, reason: str) -> None:
    from apps.scheduler.models import Placement

    Placement.objects.filter(pk=placement.pk).update(
        status=PlacementStatus.FAILED.value,
        failed_at=timezone.now(),
        reason=reason,
        failure_source="manual",
    )


def test_the_cmdline_value_is_the_guests_grammar() -> None:
    disks = [ExtraDisk("x0", "a", 22300), ExtraDisk("x1", "b", 16000)]
    assert dedicated.cmdline_value(disks) == "x0:22300,x1:16000"
    assert dedicated.cmdline_value([]) is None
    assert dedicated.order_entries(disks) == [
        {"slot": "x0", "kind": "dedicated", "disk_id": "a"},
        {"slot": "x1", "kind": "dedicated", "disk_id": "b"},
    ]
    for bad in (
        [ExtraDisk(f"x{i}", "a", 1000) for i in range(9)],
        [ExtraDisk("x0", "a", 1000), ExtraDisk("x0", "b", 1000)],
        [ExtraDisk("y0", "a", 1000)],
        [ExtraDisk("x100", "a", 1000)],
        [ExtraDisk("x0", "a", 0)],
        [ExtraDisk("x0", "a", 999)],
        [ExtraDisk("x0", "a", 1_048_577)],
        [ExtraDisk("x24", "a", 1000)],
        [ExtraDisk("x01", "a", 1000)],
    ):
        with pytest.raises(ValueError):
            dedicated.cmdline_value(bad)


def test_the_stand_in_is_never_shorter_than_a_real_value() -> None:
    real = dedicated.cmdline_value([ExtraDisk(f"x{i}", "a", 1_048_576) for i in range(16, 24)])
    stand_in = dedicated.stand_in_cmdline_value(DedicatedRequest("hdd", 8, 1000))
    assert len(stand_in) >= len(real or "")


# ── the read-back ───────────────────────────────────────────────────


def _pinned_vm(**disk_kw: Any):
    capable(NODE)
    placement, vm = _placement(status=PlacementStatus.BOUND.value)
    disks = []
    for slot in ("x0", "x1"):
        fields: dict[str, Any] = dict(
            state="assigned",
            assigned_vm=vm,
            assigned_slot=slot,
            # The agent's fresh report: it holds the disk for this VM.
            reported_state="assigned",
            reported_vm_id=vm.vm_id,
        )
        fields.update(disk_kw)
        disk = make_disk(f"wwn-0x{slot}", **fields)
        disks.append(disk)
        PlacementDisk.objects.create(
            placement=placement,
            slot=slot,
            kind="dedicated",
            dedicated_disk=disk,
            size_gb=22300,
            required_tier="hdd",
        )
    return vm, placement, disks


def test_a_vm_without_dedicated_disks_reads_nothing() -> None:
    _placement(status=PlacementStatus.BOUND.value)
    vm = make_vm("vm-plain", "lease-p")
    assert dedicated.read_back(vm) == {}
    assert dedicated.read_back_many([vm]) == {}


def test_the_read_back_shape() -> None:
    vm, _placement_row, _disks = _pinned_vm()
    body = dedicated.read_back(vm, os_disk=(40, "nvme"))
    assert body == {
        "pinned": True,
        "disks": [
            {"slot": "os", "kind": "pool", "size_gb": 40, "tier": "nvme", "state": "attached"},
            {
                "slot": "x0",
                "kind": "dedicated",
                "size_gb": 22300,
                "tier": "hdd",
                "state": "attached",
            },
            {
                "slot": "x1",
                "kind": "dedicated",
                "size_gb": 22300,
                "tier": "hdd",
                "state": "attached",
            },
        ],
    }
    assert "wwn" not in repr(body)


def test_slot_states_come_from_host_evidence_only() -> None:
    vm, placement, disks = _pinned_vm()
    now = timezone.now()
    stale = now - timedelta(minutes=16)
    # `attached` only on the agent's fresh report that it holds the disk for
    # THIS VM; failed / replaced are its own negative evidence; anything
    # else — held for another VM, free, unavailable, stale, never reported —
    # is not proof of service.
    for report, state in (
        (dict(reported_state="assigned", reported_vm_id="vm-d1", reported_at=now), "attached"),
        (dict(reported_state="assigned", reported_vm_id="vm-x", reported_at=now), "mismatch"),
        (dict(reported_state="assigned", reported_vm_id="vm-d1", reported_at=stale), "missing"),
        (dict(reported_state="assigned", reported_vm_id="vm-d1", reported_at=None), "missing"),
        (dict(reported_state="free", reported_vm_id="", reported_at=now), "missing"),
        (dict(reported_state="unavailable", reported_vm_id="", reported_at=now), "missing"),
        (dict(reported_state="draining", reported_vm_id="", reported_at=now), "missing"),
        (dict(reported_state="", reported_vm_id="", reported_at=None), "missing"),
        (dict(reported_state="failed", reported_vm_id="", reported_at=now), "failed"),
        (dict(reported_state="failed", reported_vm_id="", reported_at=stale), "failed"),
        (dict(reported_state="replaced", reported_vm_id="", reported_at=now), "mismatch"),
    ):
        DedicatedDisk.objects.filter(pk=disks[0].pk).update(**report)
        assert _states(vm)[0] == state, report
    DedicatedDisk.objects.filter(pk=disks[0].pk).update(
        reported_state="assigned", reported_vm_id="vm-d1", reported_at=now
    )
    # The disk failed while held (vanished): `failed`; a by-id now naming
    # another device: `mismatch`.
    DedicatedDisk.objects.filter(pk=disks[0].pk).update(
        state="failed", assigned_vm=None, assigned_slot=""
    )
    DedicatedDisk.objects.filter(pk=disks[1].pk).update(
        state="replaced", assigned_vm=None, assigned_slot=""
    )
    assert _states(vm) == ["failed", "mismatch"]
    # §24 released them.
    DedicatedDisk.objects.update(state="released", freed_at=timezone.now())
    assert _states(vm) == ["released", "released"]


def test_the_guests_claim_is_shown_apart_and_never_sets_the_state() -> None:
    """Root in the VM can forge its receipt verdicts (a `mismatch` would
    stop a slot's billing): `state` stays the host's word, the claim is
    `guest_state`."""
    vm, _placement, _disks = _pinned_vm()
    disks = dedicated.read_back(vm, os_disk=(40, "nvme"))["disks"]
    assert all("guest_state" not in d for d in disks), "no claim yet, no key"
    PlacementDisk.objects.filter(slot="x0").update(observed_state="missing")
    PlacementDisk.objects.filter(slot="x1").update(observed_state="mismatch")
    x0, x1 = dedicated.read_back(vm, os_disk=(40, "nvme"))["disks"][1:]
    assert (x0["state"], x0["guest_state"]) == ("attached", "missing")
    assert (x1["state"], x1["guest_state"]) == ("attached", "mismatch")
    PlacementDisk.objects.update(observed_state="ok")
    assert [d["guest_state"] for d in dedicated.read_back(vm)["disks"][1:]] == [
        "attached",
        "attached",
    ]
    assert "guest_state" not in dedicated.read_back(vm)["disks"][0]


def test_a_carried_placement_keeps_the_guests_last_claim() -> None:
    """A resize / rebind copies the disk rows to the new placement: the
    slot's `guest_state` must not blank."""
    from apps.scheduler import service as sched

    vm, placement, _disks = _pinned_vm()
    at = timezone.now()
    PlacementDisk.objects.filter(placement=placement).update(
        observed_state="missing", observed_at=at
    )
    _close(placement, "resized")
    carried = make_placement(vm, NODE, status=PlacementStatus.BOUND.value)
    sched._carry_placement_disks(placement, carried)
    rows = PlacementDisk.objects.filter(placement=carried)
    assert {(r.observed_state, r.observed_at) for r in rows} == {("missing", at)}
    assert [d.get("guest_state") for d in dedicated.read_back(vm)["disks"][1:]] == [
        "missing",
        "missing",
    ]


def test_a_destroyed_vm_shows_its_slots_released() -> None:
    vm, placement, _disks = _pinned_vm()
    vm.state = VmState.DESTROYED
    vm.save()
    _close(placement, "released:vm-destroyed")
    assert _states(vm) == ["released", "released"]


def _states(vm) -> list[str]:
    return [d["state"] for d in dedicated.read_back(vm, os_disk=(40, "nvme"))["disks"][1:]]


# ── slot verdicts ───────────────────────────────────────────────────


def test_slot_verdicts_parse_only_dedicated_slots() -> None:
    class D:
        def __init__(self, serial: str, state: str) -> None:
            self.serial, self.state = serial, state

    got = dedicated.slot_verdicts(
        [D("hippius-os", "ok"), D("hippius-x0", "ok"), D("hippius-x1", "missing"), D("", "ok")]
    )
    assert got == {"x0": "ok", "x1": "missing"}


def test_an_older_verdict_never_overwrites_a_newer_one() -> None:
    _vm, placement, _disks = _pinned_vm()
    t1 = datetime(2026, 10, 20, 12, 0, tzinfo=UTC)
    assert dedicated.record_slot_verdicts(placement.pk, {"x0": "missing"}, t1) == 1
    assert (
        dedicated.record_slot_verdicts(placement.pk, {"x0": "ok"}, t1 - timedelta(minutes=1)) == 0
    )
    assert PlacementDisk.objects.get(slot="x0").observed_state == "missing"
    assert (
        dedicated.record_slot_verdicts(placement.pk, {"x0": "ok"}, t1 + timedelta(minutes=1)) == 1
    )
    assert PlacementDisk.objects.get(slot="x0").observed_state == "ok"


def test_the_same_verdict_still_advances_its_freshness() -> None:
    """ok@t1, ok@t3, then a late missing@t2: the slot stays ok (the t3
    window advanced it, though its verdict did not change)."""
    _vm, placement, _disks = _pinned_vm()
    t1 = datetime(2026, 10, 20, 12, 0, tzinfo=UTC)
    dedicated.record_slot_verdicts(placement.pk, {"x0": "ok"}, t1)
    dedicated.record_slot_verdicts(placement.pk, {"x0": "ok"}, t1 + timedelta(minutes=2))
    dedicated.record_slot_verdicts(placement.pk, {"x0": "missing"}, t1 + timedelta(minutes=1))
    row = PlacementDisk.objects.get(slot="x0")
    assert (row.observed_state, row.observed_at) == ("ok", t1 + timedelta(minutes=2))


# ── the receipt ingest records them ─────────────────────────────────


@pytest.mark.parametrize(
    ("io", "on", "outcome", "recorded"),
    [
        (False, False, "off", ""),
        (False, True, "slot-verdicts", "missing"),
        (True, False, "ingested", "missing"),
    ],
)
def test_the_receipt_ingest_records_the_slot_verdict(settings, io, on, outcome, recorded) -> None:
    from dataclasses import replace

    from apps.disktier.ingest import on_verified_receipt
    from apps.disktier.tests.test_passive_ingest import NOW, T0, delta, receipt

    settings.VALI_DISK_IO_INGEST = io
    settings.VALI_DEDICATED_ENABLED = on
    vm, _placement_row, _disks = _pinned_vm()
    zero = dict.fromkeys(
        ("r_ios", "r_sectors", "r_ticks_ms", "w_ios", "w_sectors", "w_ticks_ms"), 0
    )
    missing = replace(
        delta(dev="", serial="hippius-x0", io_ticks_ms=0, tiq_ms=0, **zero), state="missing"
    )
    fields = receipt(missing, vm_id=vm.vm_id, start=T0)
    assert on_verified_receipt(fields, body=b"r1", source_id=vm.vm_id, now=NOW) == outcome
    assert PlacementDisk.objects.get(slot="x0").observed_state == recorded
