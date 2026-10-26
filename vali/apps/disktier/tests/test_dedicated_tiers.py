"""Contract §8: dedicated disks sold at hdd | ssd | nvme — the intake and
`VALI_DEDICATED_SELLABLE_TIERS`, the lowest-qualifying-tier placement,
the sold tier on read-back, the declared-class cap on a probe pass, and the
operator re-probe. (Feasibility: `apps/scheduler/tests/
test_feasibility_dedicated.py`; regions: `apps/operator/tests/
test_regions_dedicated.py`; pay: `apps/scheduler/tests/
test_usage_dedicated.py`; the declared class in the storage document:
`test_storage_config.py`.)"""

from __future__ import annotations

from io import StringIO
from typing import Any

import pytest
from django.core.management import CommandError, call_command
from django.test import override_settings

from apps.disktier import dedicated
from apps.disktier.dedicated import DedicatedError, DedicatedRequest
from apps.disktier.models import DedicatedDisk, DedicatedDiskState
from apps.disktier.tiers import capped
from apps.scheduler.models import MinerCapacityAudit
from apps.scheduler.tests.factories import make_placement, make_vm

from .dedicated_helpers import ON, capable, make_disk
from .probe_helpers import NODE, FakeIntake
from .test_dedicated_probe import (  # noqa: F401 — `ded_on` is a fixture
    D1_HDD,
    _accept,
    _close,
    _run_of,
    _tick,
    ded_on,
    pending,
)

pytestmark = pytest.mark.django_db

ALL = ["hdd", "ssd", "nvme"]
#: The default is `exact`; the `minimum` tests pin the #1780 behaviour.
MINIMUM = {**ON, "VALI_DEDICATED_TIER_MATCH": "minimum"}
GOOD = {"tier": "hdd", "count": 2, "min_size_gb": 16000}


def _check(raw: dict[str, Any], **kw: Any) -> DedicatedRequest:
    args: dict[str, Any] = dict(
        pinned_ack=True,
        tenant_id="t-1",
        user_id="u-1",
        require_failover_peer=False,
        guest_release=5,
    )
    args.update(kw)
    return dedicated.check_launch(raw, **args)


# ── intake ──────────────────────────────────────────────────────────


def test_the_default_sells_hdd_only(settings) -> None:
    assert settings.VALI_DEDICATED_SELLABLE_TIERS == ["hdd"]
    assert dedicated.sellable_tiers() == ("hdd",)


def _reloaded(monkeypatch: pytest.MonkeyPatch, **env: str) -> Any:
    """The two settings as `vali.settings` reads them under `env`."""
    import importlib
    from types import SimpleNamespace

    import vali.settings as prod_settings

    for name, value in env.items():
        monkeypatch.setenv(name, value)
    try:
        got = importlib.reload(prod_settings)
        return SimpleNamespace(
            VALI_DEDICATED_SELLABLE_TIERS=got.VALI_DEDICATED_SELLABLE_TIERS,
            VALI_DEDICATED_MILLIUNITS_PER_GB_BY_TIER=got.VALI_DEDICATED_MILLIUNITS_PER_GB_BY_TIER,
            VALI_DEDICATED_TIER_MATCH=got.VALI_DEDICATED_TIER_MATCH,
        )
    finally:
        for name in env:
            monkeypatch.delenv(name)
        importlib.reload(prod_settings)


def test_the_settings_parse_the_tier_lists(monkeypatch: pytest.MonkeyPatch) -> None:
    got = _reloaded(
        monkeypatch,
        VALI_DEDICATED_SELLABLE_TIERS="hdd, NVMe",
        VALI_DEDICATED_MILLIUNITS_PER_GB_BY_TIER="ssd:150, nvme:250",
        VALI_DEDICATED_TIER_MATCH=" Minimum ",
    )
    assert got.VALI_DEDICATED_SELLABLE_TIERS == ["hdd", "nvme"]
    assert got.VALI_DEDICATED_MILLIUNITS_PER_GB_BY_TIER == {"ssd": 150, "nvme": 250}
    assert got.VALI_DEDICATED_TIER_MATCH == "minimum"
    shipped = _reloaded(monkeypatch)
    assert shipped.VALI_DEDICATED_SELLABLE_TIERS == ["hdd"]
    assert shipped.VALI_DEDICATED_MILLIUNITS_PER_GB_BY_TIER == {}
    assert shipped.VALI_DEDICATED_TIER_MATCH == "exact"


@pytest.mark.parametrize(
    "env",
    [
        {"VALI_DEDICATED_SELLABLE_TIERS": "hdd,sas"},
        {"VALI_DEDICATED_MILLIUNITS_PER_GB_BY_TIER": "ssd"},
        {"VALI_DEDICATED_MILLIUNITS_PER_GB_BY_TIER": "sas:1"},
        {"VALI_DEDICATED_MILLIUNITS_PER_GB_BY_TIER": "ssd:-1"},
        {"VALI_DEDICATED_MILLIUNITS_PER_GB_BY_TIER": "ssd:1,ssd:2"},
        {"VALI_DEDICATED_TIER_MATCH": "at-least"},
    ],
)
def test_the_settings_refuse_a_bad_value(monkeypatch: pytest.MonkeyPatch, env: dict) -> None:
    with pytest.raises(RuntimeError):
        _reloaded(monkeypatch, **env)


@pytest.mark.parametrize("tier", ALL)
def test_every_tier_parses(tier: str) -> None:
    assert dedicated.parse_request({**GOOD, "tier": tier}).tier == tier


@override_settings(**ON)
@pytest.mark.parametrize("tier", ["ssd", "nvme"])
def test_a_valid_tier_not_on_sale_is_409_not_offered(tier: str) -> None:
    with pytest.raises(DedicatedError) as exc:
        _check({**GOOD, "tier": tier})
    assert exc.value.category == dedicated.CATEGORY_NOT_OFFERED
    assert dedicated.CATEGORY_NOT_OFFERED in dedicated.CONFLICT_CATEGORIES
    assert _check(GOOD).tier == "hdd"


@override_settings(**{**ON, "VALI_DEDICATED_SELLABLE_TIERS": ALL})
@pytest.mark.parametrize("tier", ALL)
def test_a_tier_on_sale_is_taken(tier: str) -> None:
    assert _check({**GOOD, "tier": tier}).as_spec() == {**GOOD, "tier": tier}


@override_settings(**{**ON, "VALI_DEDICATED_SELLABLE_TIERS": ["nvme"]})
def test_the_setting_is_the_list_not_a_floor() -> None:
    with pytest.raises(DedicatedError) as exc:
        _check(GOOD)
    assert exc.value.category == dedicated.CATEGORY_NOT_OFFERED
    assert _check({**GOOD, "tier": "nvme"}).tier == "nvme"


@override_settings(**ON)
def test_the_body_and_the_ack_come_before_the_tier_on_sale() -> None:
    with pytest.raises(DedicatedError) as exc:
        _check({**GOOD, "tier": "sas"})
    assert exc.value.category == dedicated.CATEGORY_INVALID
    with pytest.raises(DedicatedError) as exc:
        _check({**GOOD, "tier": "nvme"}, pinned_ack=False)
    assert exc.value.category == dedicated.CATEGORY_ACK_REQUIRED
    # ...and the tier before the other conflicts.
    with pytest.raises(DedicatedError) as exc:
        _check({**GOOD, "tier": "nvme"}, require_failover_peer=True)
    assert exc.value.category == dedicated.CATEGORY_NOT_OFFERED


@override_settings(**{**ON, "VALI_DEDICATED_SELLABLE_TIERS": []})
def test_an_empty_list_sells_nothing() -> None:
    for tier in ALL:
        with pytest.raises(DedicatedError) as exc:
            _check({**GOOD, "tier": tier})
        assert exc.value.category == dedicated.CATEGORY_NOT_OFFERED


def test_the_spec_reads_back_every_tier() -> None:
    for tier in ALL:
        spec = {"dedicated_disks": {**GOOD, "tier": tier}}
        assert dedicated.spec_request(spec) == DedicatedRequest(tier, 2, 16000)


# ── placement ───────────────────────────────────────────────────────


def _placement(vm_id: str = "vm-t1"):
    vm = make_vm(vm_id, f"lease-{vm_id}")
    return make_placement(vm, NODE), vm


def _taken(rows: list[Any]) -> list[tuple[str, str, str]]:
    return [(r.slot, r.dedicated_disk.disk_id, r.required_tier) for r in rows]


@override_settings(**MINIMUM)
def test_the_lowest_qualifying_tier_goes_first_whatever_its_size() -> None:
    capable(NODE)
    make_disk("wwn-0xnvme", tier="nvme", size_gib=16000)
    make_disk("wwn-0xssd", tier="ssd", size_gib=18000)
    make_disk("wwn-0xhdd", tier="hdd", size_gib=30000)
    placement, vm = _placement()
    rows = dedicated.assign(placement, vm, DedicatedRequest("hdd", 2, 16000))
    assert _taken(rows) == [("x0", "wwn-0xhdd", "hdd"), ("x1", "wwn-0xssd", "hdd")]
    assert DedicatedDisk.objects.get(disk_id="wwn-0xnvme").state == "free"


@override_settings(**MINIMUM)
def test_within_a_tier_the_smallest_goes_first() -> None:
    capable(NODE)
    make_disk("wwn-0xn1", tier="nvme", size_gib=20000)
    make_disk("wwn-0xs1", tier="ssd", size_gib=30000)
    make_disk("wwn-0xs2", tier="ssd", size_gib=18000)
    make_disk("wwn-0xh1", tier="hdd", size_gib=16000)
    placement, vm = _placement()
    rows = dedicated.assign(placement, vm, DedicatedRequest("ssd", 3, 16000))
    # hdd does not qualify; ssd smallest first, then nvme.
    assert _taken(rows) == [
        ("x0", "wwn-0xs2", "ssd"),
        ("x1", "wwn-0xs1", "ssd"),
        ("x2", "wwn-0xn1", "ssd"),
    ]


@override_settings(**MINIMUM)
def test_a_tier_above_every_free_disk_is_not_placed() -> None:
    capable(NODE)
    make_disk("wwn-0xs1", tier="ssd")
    make_disk("wwn-0xh1", tier="hdd")
    placement, vm = _placement()
    with pytest.raises(dedicated.DisksTaken):
        dedicated.assign(placement, vm, DedicatedRequest("nvme", 1, 16000))
    assert dedicated.free_counts(DedicatedRequest("nvme", 1, 16000), [NODE]) == {}
    assert dedicated.free_counts(DedicatedRequest("ssd", 1, 16000), [NODE]) == {NODE: 1}


@override_settings(**MINIMUM)
def test_the_read_back_carries_the_sold_tier_never_the_disks() -> None:
    capable(NODE)
    make_disk("wwn-0xnvme", tier="nvme")
    placement, vm = _placement()
    dedicated.assign(placement, vm, DedicatedRequest("hdd", 1, 16000))
    body = dedicated.read_back(vm, os_disk=(40, "nvme"))
    (slot,) = [d for d in body["disks"] if d["kind"] == "dedicated"]
    assert (slot["slot"], slot["tier"]) == ("x0", "hdd")
    assert DedicatedDisk.objects.get().verified_tier == "nvme"


def test_the_default_matches_the_tier_exactly(settings) -> None:
    assert settings.VALI_DEDICATED_TIER_MATCH == "exact"
    assert dedicated.tier_match() == "exact"


@override_settings(**ON)
def test_exact_an_hdd_order_never_takes_a_faster_disk() -> None:
    capable(NODE)
    make_disk("wwn-0xnvme", tier="nvme")
    make_disk("wwn-0xssd", tier="ssd")
    placement, vm = _placement()
    with pytest.raises(dedicated.DisksTaken):
        dedicated.assign(placement, vm, DedicatedRequest("hdd", 1, 16000))
    assert dedicated.free_counts(DedicatedRequest("hdd", 1, 16000), [NODE]) == {}
    assert set(DedicatedDisk.objects.values_list("state", flat=True)) == {"free"}


@override_settings(**ON)
@pytest.mark.parametrize("tier", ALL)
def test_exact_mixed_stock_takes_only_the_requested_tier(tier: str) -> None:
    capable(NODE)
    for t in ALL:
        make_disk(f"wwn-0x{t}1", tier=t, size_gib=16000)
        make_disk(f"wwn-0x{t}2", tier=t, size_gib=18000)
    placement, vm = _placement()
    rows = dedicated.assign(placement, vm, DedicatedRequest(tier, 2, 16000))
    assert _taken(rows) == [("x0", f"wwn-0x{tier}1", tier), ("x1", f"wwn-0x{tier}2", tier)]
    left = {t: dedicated.free_counts(DedicatedRequest(t, 1, 16000), [NODE]) for t in ALL}
    assert left == {t: ({} if t == tier else {NODE: 2}) for t in ALL}


@override_settings(**ON)
def test_exact_a_disk_without_a_declared_class_sells_as_hdd() -> None:
    """The verified tier is min(probe grade, declared class); no class = hdd."""
    capable(NODE)
    make_disk("wwn-0xundeclared", tier=capped("nvme", None))
    assert dedicated.free_counts(DedicatedRequest("hdd", 1, 16000), [NODE]) == {NODE: 1}
    assert dedicated.free_counts(DedicatedRequest("nvme", 1, 16000), [NODE]) == {}


# ── the declared cap (R3) ───────────────────────────────────────────


@pytest.mark.parametrize(
    ("classified", "declared", "verified"),
    [
        ("nvme", None, "hdd"),
        ("nvme", "hdd", "hdd"),
        ("nvme", "ssd", "ssd"),
        ("nvme", "nvme", "nvme"),
        ("ssd", "nvme", "ssd"),
        ("hdd", "nvme", "hdd"),
        ("unfit", "nvme", "unfit"),
        ("unknown", None, "unknown"),
    ],
)
def test_the_verified_tier_is_the_lower_of_grade_and_class(
    classified: str, declared: str | None, verified: str
) -> None:
    assert capped(classified, declared) == verified


#: A d1 result that clears every nvme floor (a PM9A3).
D1_NVME = {
    **D1_HDD,
    "seq_read_inner_mbps": 2_190,
    "seq_read_mid_mbps": 2_300,
    "seq_read_outer_mbps": 2_380,
    "rr_iops": 181_000,
    "qd1_p50_us": 24,
    "qd1_p99_us": 44,
    "rw_sustained_iops": 136_000,
    "seq_write_mbps": 1_800,
}


def _probe_pass(declared: str | None) -> DedicatedDisk:
    disk = pending("wwn-0x01", declared_class=declared)
    _tick()
    run = _run_of(disk)
    assert _accept(run, {"x0": {"metrics": D1_NVME}}) == "accepted"
    _close(run)
    _tick()
    disk.refresh_from_db()
    return disk


@pytest.mark.parametrize(
    ("declared", "verified"), [(None, "hdd"), ("hdd", "hdd"), ("ssd", "ssd"), ("nvme", "nvme")]
)
def test_a_probe_pass_is_capped_by_the_declared_class(
    ded_on: FakeIntake,  # noqa: F811
    declared: str | None,
    verified: str,
) -> None:
    disk = _probe_pass(declared)
    assert (disk.state, disk.verified_tier) == ("free", verified)
    (row,) = MinerCapacityAudit.objects.filter(reason="probe-pass")
    assert row.after["verified_tier"] == verified
    assert row.after["classified_tier"] == "nvme"
    assert row.after["declared_class"] == (declared or "")


def test_a_class_changed_during_the_probe_waits_for_the_next_pass(
    ded_on: FakeIntake,  # noqa: F811
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from apps.disktier import dedicated_probe

    disk = pending("wwn-0x01", declared_class="nvme")
    _tick()
    run = _run_of(disk)
    assert _accept(run, {"x0": {"metrics": D1_NVME}}) == "accepted"
    _close(run)
    # The row settle read says nvme; the class drops to hdd before its write.
    real = dedicated_probe.verdict_for

    def racing(d: DedicatedDisk, r: Any) -> Any:
        DedicatedDisk.objects.filter(pk=d.pk).update(declared_class="hdd")
        return real(d, r)

    monkeypatch.setattr(dedicated_probe, "verdict_for", racing)
    _tick()
    disk.refresh_from_db()
    assert disk.state == DedicatedDiskState.PROBING
    monkeypatch.setattr(dedicated_probe, "verdict_for", real)
    _tick()
    disk.refresh_from_db()
    assert (disk.state, disk.verified_tier) == ("free", "hdd")


# ── the operator re-probe ───────────────────────────────────────────


def _reprobe(*args: str) -> str:
    out = StringIO()
    call_command("vali_dedicated_reprobe", "--node-id", NODE, *args, stdout=out)
    return out.getvalue()


@pytest.mark.parametrize("state", ["free", "unfit"])
def test_the_command_sends_a_disk_back_to_the_probe_audited(state: str) -> None:
    make_disk("wwn-0x1", tier="hdd", state=state, probe_failures=2)
    out = _reprobe("--disk", "wwn-0x1", "--by", "ops@x", "--reason", "re-grade")
    disk = DedicatedDisk.objects.get()
    assert (disk.state, disk.verified_tier, disk.probe_failures) == ("pending_probe", "hdd", 0)
    (row,) = MinerCapacityAudit.objects.filter(field=dedicated.AUDIT_FIELD)
    assert (row.actor, row.reason) == ("op:ops@x", "operator-reprobe: re-grade")
    assert (row.before["state"], row.after["state"]) == (state, "pending_probe")
    assert '"event": "dedicated_disk_reprobe"' in out


def test_a_dry_run_writes_nothing() -> None:
    make_disk("wwn-0x1")
    assert "dry run" in _reprobe("--disk", "wwn-0x1", "--dry-run")
    assert DedicatedDisk.objects.get().state == "free"
    assert not MinerCapacityAudit.objects.exists()


@pytest.mark.parametrize(
    "args",
    [
        ("--disk", "wwn-0x1", "--reason", "r"),  # no --by
        ("--disk", "wwn-0x1", "--by", "ops"),  # no --reason
        ("--disk", "wwn-0xnone", "--by", "ops", "--reason", "r"),
    ],
)
def test_refusals_write_nothing(args: tuple[str, ...]) -> None:
    make_disk("wwn-0x1")
    with pytest.raises(CommandError):
        _reprobe(*args)
    assert DedicatedDisk.objects.get().state == "free"


@pytest.mark.parametrize("state", ["pending_probe", "probing", "released", "failed", "assigned"])
def test_a_held_or_unsettled_disk_is_never_re_probed(state: str) -> None:
    kw: dict[str, Any] = {}
    if state == "assigned":
        kw = dict(assigned_vm=make_vm("vm-r", "lease-r"), assigned_slot="x0")
    make_disk("wwn-0x1", state=state, **kw)
    with pytest.raises(CommandError):
        _reprobe("--disk", "wwn-0x1", "--by", "ops", "--reason", "r")
    assert DedicatedDisk.objects.get().state == state
    assert not dedicated.request_reprobe(DedicatedDisk.objects.get(), reason="x")
