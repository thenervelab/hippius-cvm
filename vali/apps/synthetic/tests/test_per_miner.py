"""Per-miner probe (`apps.synthetic.per_miner`): which miner, the budget,
the record, and the run.

The scheduler's gate reads are scripted (`_Fleet`) for the selection
rules; one test runs them for real, so a renamed or re-shaped service
function cannot leave the scripted tests green over a broken tier.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from django.utils import timezone

from apps.lifecycle.models import VmState
from apps.scheduler.models import MinerCapacity, PlacementFailureSource, PlacementStatus
from apps.scheduler.tests.factories import (
    make_dispatchable_identity,
    make_placement,
    make_vm,
    node_id,
)
from apps.synthetic import e2e, per_miner
from apps.synthetic.models import MinerProbe

pytestmark = pytest.mark.django_db

NOW = datetime(2026, 10, 21, 12, 0, tzinfo=UTC)
H = timedelta(hours=1)


@dataclass
class _Fleet:
    """Scripted scheduler reads for `fleet_views`."""

    dispatchable: set[str] = field(default_factory=set)
    gated: set[str] = field(default_factory=set)
    cordoned: dict[str, str] = field(default_factory=dict)
    net_unready: dict[str, str] = field(default_factory=dict)
    free: dict[str, int] = field(default_factory=dict)
    booting: dict[str, int] = field(default_factory=dict)
    caps: dict[str, int] = field(default_factory=dict)
    fleet_cap: int = 3


@dataclass(frozen=True)
class _View:
    free_by_flavor: dict[str, int]


@pytest.fixture
def fleet(monkeypatch: pytest.MonkeyPatch, settings: Any) -> _Fleet:
    from apps.scheduler import service

    settings.VALI_SYNTHETIC_PER_MINER = True
    settings.VALI_SYNTHETIC_PER_MINER_MINERS = []
    settings.VALI_SYNTHETIC_PER_MINER_MAX_CONCURRENT = 1
    settings.VALI_SYNTHETIC_PER_MINER_INTERVAL_S = 6 * 3600
    settings.VALI_SYNTHETIC_PER_MINER_MIN_FREE_SLOTS = 2
    settings.VALI_SYNTHETIC_PER_MINER_FLAVOR = "small"
    settings.VALI_SYNTHETIC_REAP_AGE_S = 5400
    f = _Fleet()
    monkeypatch.setattr(service, "dispatchable_node_ids", lambda: frozenset(f.dispatchable))
    monkeypatch.setattr(service, "hard_gated_node_ids", lambda: frozenset(f.gated))
    monkeypatch.setattr(service, "cordoned_node_ids", lambda: dict(f.cordoned))
    monkeypatch.setattr(service, "net_policy_unready_node_ids", lambda: dict(f.net_unready))
    monkeypatch.setattr(
        service,
        "capacity_views",
        lambda: {n: _View({"small": c}) for n, c in f.free.items()},
    )
    monkeypatch.setattr(service, "booting_by_node", lambda now=None: dict(f.booting))
    monkeypatch.setattr(service, "max_booting_overrides", lambda: dict(f.caps))
    monkeypatch.setattr(service, "max_booting_per_miner", lambda: f.fleet_cap)
    return f


def _miner(f: _Fleet, seed: int, *, free: int = 5) -> str:
    make_dispatchable_identity(seed)
    nid = node_id(seed)
    f.dispatchable.add(nid)
    f.free[nid] = free
    return nid


def _probe(nid: str, **kw: Any) -> MinerProbe:
    return MinerProbe.objects.create(miner_node_id=nid, **kw)


def _views(now: datetime = NOW) -> list[per_miner.MinerView]:
    probes = {p.miner_node_id: p for p in MinerProbe.objects.all()}
    return per_miner.fleet_views(flavor="small", now=now, probes=probes)


# ─── the universe and the gates ──────────────────────────────────────


def test_the_universe_is_the_dispatchable_set(fleet: _Fleet) -> None:
    a = _miner(fleet, 1)
    make_dispatchable_identity(2)  # registered, not dispatchable
    views = _views()
    assert [v.node_id for v in views] == [a]
    assert views[0].miner_id == "miner-01"
    assert views[0].platform_id == "01" + "cd" * 15
    assert views[0].blocked == ""


@pytest.mark.parametrize(
    ("setup", "reason"),
    [
        (lambda f, n: f.gated.add(n), per_miner.BLOCKED_GATED),
        (lambda f, n: f.cordoned.update({n: "maintenance"}), per_miner.BLOCKED_CORDONED),
        (lambda f, n: f.cordoned.update({n: "pending approval"}), per_miner.BLOCKED_CORDONED),
        (lambda f, n: f.net_unready.update({n: "stale"}), per_miner.BLOCKED_NET_POLICY),
        (lambda f, n: f.booting.update({n: 1}), per_miner.BLOCKED_BOOTING),
        (lambda f, n: f.caps.update({n: 0}), per_miner.BLOCKED_BOOTING),
        (lambda f, n: f.free.update({n: 1}), per_miner.BLOCKED_CAPACITY),
        (lambda f, n: f.free.pop(n), per_miner.BLOCKED_CAPACITY),
    ],
)
def test_a_miner_placement_would_refuse_or_that_is_busy_is_blocked(
    fleet: _Fleet, setup: Any, reason: str
) -> None:
    nid = _miner(fleet, 1)
    setup(fleet, nid)
    assert _views()[0].blocked == reason


def test_the_probe_never_takes_the_last_free_slot(fleet: _Fleet) -> None:
    nid = _miner(fleet, 1, free=2)
    assert _views()[0].blocked == ""
    fleet.free[nid] = 1
    assert _views()[0].blocked == per_miner.BLOCKED_CAPACITY


def test_a_fresh_claim_is_busy_and_a_stale_one_is_not(fleet: _Fleet) -> None:
    nid = _miner(fleet, 1)
    _probe(nid, in_flight_vm_id="synmon-pm-x-1", in_flight_since=NOW - H)
    assert _views()[0].blocked == per_miner.BLOCKED_BUSY
    # Older than the reap age, its VM gone: a killed run's claim.
    assert _views(NOW + timedelta(seconds=5400))[0].blocked == ""


def test_a_stale_claim_whose_vm_is_alive_stays_busy(fleet: _Fleet) -> None:
    """The reaper keys on the VM's own age, which starts after the claim:
    until the VM is destroyed the miner holds a probe, whatever the clock."""
    nid = _miner(fleet, 1)
    _probe(nid, in_flight_vm_id="synmon-pm-x-1", in_flight_since=NOW - H)
    vm = make_vm("synmon-pm-x-1", lease_id="l")
    later = NOW + timedelta(hours=10)
    assert _views(later)[0].blocked == per_miner.BLOCKED_BUSY
    vm.state = VmState.DESTROYED
    vm.save(update_fields=["state"])
    assert _views(later)[0].blocked == ""


def test_the_canary_allowlist_restricts_the_universe(fleet: _Fleet, settings: Any) -> None:
    _miner(fleet, 1)
    b = _miner(fleet, 2)
    c = _miner(fleet, 3)
    settings.VALI_SYNTHETIC_PER_MINER_MINERS = [b.upper(), "MINER-03"]
    assert [v.node_id for v in _views()] == [b, c]


def test_the_real_scheduler_reads_drive_the_views(settings: Any) -> None:
    """No scripted gates: a dispatchable identity with a mirror row and
    room is probeable; a cordon blocks it."""
    settings.VALI_SYNTHETIC_PER_MINER_MIN_FREE_SLOTS = 2
    make_dispatchable_identity(1)
    row = MinerCapacity.objects.create(
        miner_node_id=node_id(1),
        status="active",
        capacity_slots=4,
        observed_epoch=10,
        data_epoch=10,
        refreshed_at=timezone.now(),
    )
    now = timezone.now()
    views = per_miner.fleet_views(flavor="small", now=now, probes={})
    assert [(v.node_id, v.blocked) for v in views] == [(node_id(1), "")]
    MinerCapacity.objects.filter(pk=row.pk).update(cordoned_at=now, cordon_reason="test")
    views = per_miner.fleet_views(flavor="small", now=now, probes={})
    assert views[0].blocked == per_miner.BLOCKED_CORDONED


# ─── due order ───────────────────────────────────────────────────────


def _v(seed: int, *, attempt: datetime | None = None, now_fp: str = "fp-a", seen_fp: str = ""):
    return per_miner.MinerView(
        node_id=node_id(seed),
        miner_id=f"miner-{seed:02d}",
        platform_id="ab" * 16,
        blocked="",
        last_attempt_at=attempt,
        last_probe_at=attempt,
        attestor_fingerprint=now_fp,
        seen_fingerprint=seen_fp,
    )


def test_never_attempted_then_changed_host_then_oldest_first(fleet: _Fleet) -> None:
    views = [
        _v(1, attempt=NOW - 7 * H, seen_fp="fp-a"),  # overdue
        _v(2, attempt=NOW - 30 * H, seen_fp="fp-a"),  # more overdue
        _v(3),  # never attempted
        _v(4, attempt=NOW - 2 * H, now_fp="fp-b", seen_fp="fp-a"),  # host changed since
        _v(5, attempt=NOW - 2 * H, seen_fp="fp-a"),  # not due
        _v(6, attempt=NOW - 2 * H, seen_fp=""),  # nothing recorded yet: not "changed"
        _v(7, attempt=NOW - 2 * H, now_fp="", seen_fp="fp-a"),  # attestor gone: not a change
    ]
    order = [v.node_id for v in per_miner.due_order(views, now=NOW)]
    assert order == [node_id(3), node_id(4), node_id(2), node_id(1)]


def _attestor(seed: int, *, boot_id: str, measurement: str = "a1" * 48) -> Any:
    from apps.telemetry.models import HostAttestor, HostAttestorStatus

    row, _ = HostAttestor.objects.update_or_create(
        chip_id=format(seed, "0128x"),
        defaults=dict(
            node_id=node_id(seed),
            signer_pubkey=bytes(32),
            measurement=measurement,
            cert_expiry_at=timezone.now() + timedelta(days=1),
            status=HostAttestorStatus.ATTESTED,
            last_seen_at=timezone.now(),
            boot_id=boot_id,
            enrolled_at=timezone.now(),
        ),
    )
    return row


def _due_after_claim(f: _Fleet, *, change: dict[str, str]) -> list[str]:
    """Claim the miner (records its fingerprint), re-enrol its attestor with
    `change`, two hours later: is it due?"""
    nid = _miner(f, 1)
    _attestor(1, boot_id="boot-1")
    claim = per_miner.claim_next(flavor="small", now=NOW, report=per_miner.TickReport())
    assert claim is not None
    MinerProbe.objects.filter(miner_node_id=nid).update(in_flight_vm_id="", in_flight_since=None)
    _attestor(1, **{"boot_id": "boot-1", **change})  # re-enrolment: cert renewed, enrolled_at now
    return [v.node_id for v in per_miner.due_order(_views(NOW + 2 * H), now=NOW + 2 * H)]


def test_the_routine_reenrolment_does_not_jump_the_queue(fleet: _Fleet) -> None:
    """Every miner re-enrols ~daily with the same boot: not a changed host."""
    assert _due_after_claim(fleet, change={}) == []


@pytest.mark.parametrize(
    "change", [{"boot_id": "boot-2"}, {"measurement": "b2" * 48}], ids=["reboot", "new-image"]
)
def test_a_changed_boot_jumps_the_queue(fleet: _Fleet, change: dict[str, str]) -> None:
    assert _due_after_claim(fleet, change=change) == [node_id(1)]


def test_the_claim_records_the_fingerprint(fleet: _Fleet) -> None:
    nid = _miner(fleet, 1)
    _attestor(1, boot_id="boot-1")
    per_miner.claim_next(flavor="small", now=NOW, report=per_miner.TickReport())
    recorded = MinerProbe.objects.get(miner_node_id=nid).attestor_fingerprint
    assert recorded == per_miner.attestor_fingerprints([nid])[nid] and len(recorded) == 32


def test_every_miner_is_due_within_a_day(fleet: _Fleet) -> None:
    """The interval (6 h) is well inside 24 h: a miner probed a day ago is
    always due, whatever else is."""
    views = [_v(1, attempt=NOW - 24 * H)]
    assert per_miner.due_order(views, now=NOW) == views


# ─── claim: budget and one per miner ─────────────────────────────────


def test_claim_pins_the_most_urgent_probeable_miner(fleet: _Fleet) -> None:
    a = _miner(fleet, 1)
    b = _miner(fleet, 2)
    _probe(a, last_attempt_at=NOW - 7 * H)
    report = per_miner.TickReport()
    claim = per_miner.claim_next(flavor="small", now=NOW, report=report)
    assert claim is not None
    assert claim.view.node_id == b  # never attempted beats overdue
    assert claim.vm_id == f"synmon-pm-{b[:12]}-{int(NOW.timestamp())}"
    row = MinerProbe.objects.get(miner_node_id=b)
    assert (row.in_flight_vm_id, row.in_flight_since, row.last_attempt_at) == (
        claim.vm_id,
        NOW,
        NOW,
    )
    assert report.due == 2 and report.universe == 2


def test_blocked_miners_are_skipped_and_counted(fleet: _Fleet) -> None:
    a = _miner(fleet, 1)
    b = _miner(fleet, 2)
    fleet.cordoned[a] = "maintenance"
    report = per_miner.TickReport()
    claim = per_miner.claim_next(flavor="small", now=NOW, report=report)
    assert claim is not None and claim.view.node_id == b
    assert report.skipped == {per_miner.BLOCKED_CORDONED: 1}


def test_the_fleet_cap_holds_across_miners(fleet: _Fleet, settings: Any) -> None:
    a = _miner(fleet, 1)
    _miner(fleet, 2)
    _probe(a, in_flight_vm_id="synmon-pm-a-1", in_flight_since=NOW - H, last_attempt_at=NOW - H)
    report = per_miner.TickReport()
    assert per_miner.claim_next(flavor="small", now=NOW, report=report) is None
    assert report.in_flight == 1
    assert report.skipped["concurrency"] == 1
    settings.VALI_SYNTHETIC_PER_MINER_MAX_CONCURRENT = 2
    claim = per_miner.claim_next(flavor="small", now=NOW, report=per_miner.TickReport())
    assert claim is not None and claim.view.node_id == node_id(2)


def test_two_runs_never_claim_the_same_miner(fleet: _Fleet, settings: Any) -> None:
    settings.VALI_SYNTHETIC_PER_MINER_MAX_CONCURRENT = 5
    _miner(fleet, 1)
    first = per_miner.claim_next(flavor="small", now=NOW, report=per_miner.TickReport())
    report = per_miner.TickReport()
    second = per_miner.claim_next(flavor="small", now=NOW, report=report)
    assert first is not None and second is None
    assert MinerProbe.objects.get().in_flight_vm_id == first.vm_id


def test_an_overdue_miner_with_a_probe_in_flight_is_busy(fleet: _Fleet, settings: Any) -> None:
    settings.VALI_SYNTHETIC_PER_MINER_MAX_CONCURRENT = 5
    nid = _miner(fleet, 1)
    _probe(
        nid,
        in_flight_vm_id="synmon-pm-a-1",
        in_flight_since=NOW - H,
        last_attempt_at=NOW - 7 * H,
    )
    report = per_miner.TickReport()
    assert per_miner.claim_next(flavor="small", now=NOW, report=report) is None
    assert report.skipped == {per_miner.BLOCKED_BUSY: 1}


def test_a_zero_cap_launches_nothing(fleet: _Fleet, settings: Any) -> None:
    settings.VALI_SYNTHETIC_PER_MINER_MAX_CONCURRENT = 0
    _miner(fleet, 1)
    assert per_miner.claim_next(flavor="small", now=NOW, report=per_miner.TickReport()) is None
    assert not MinerProbe.objects.exists()


# ─── record ──────────────────────────────────────────────────────────


def _outcome(vm_id: str, failed: str | None = None) -> e2e.E2EOutcome:
    stages = [e2e.StageResult("launch", True, 1.0, "job=j state=queued")]
    if failed:
        stages.append(e2e.StageResult(failed, False, 2.0, "boom"))
    return e2e.E2EOutcome("ubuntu", vm_id, success=failed is None, stages=stages)


def _claimed(f: _Fleet, seed: int, **probe_kw: Any) -> per_miner.Claim:
    nid = _miner(f, seed)
    _probe(nid, **probe_kw)
    claim = per_miner.claim_next(flavor="small", now=NOW, report=per_miner.TickReport())
    assert claim is not None
    return claim


def _placed(
    claim: per_miner.Claim, status: str = PlacementStatus.BOUND.value, *, destroyed: bool = False
) -> None:
    vm = make_vm(claim.vm_id, lease_id=f"synmon-{claim.vm_id}")
    make_placement(vm, claim.view.node_id, status=status)
    if destroyed:  # the run's own teardown
        vm.state = VmState.DESTROYED
        vm.save(update_fields=["state"])


def test_a_pass_on_another_host_credits_nobody(fleet: _Fleet) -> None:
    claim = _claimed(fleet, 1)
    vm = make_vm(claim.vm_id, lease_id="l")
    make_placement(vm, node_id(9), status=PlacementStatus.BOUND.value)
    assert per_miner.record(claim, _outcome(claim.vm_id), now=NOW) == (
        per_miner.VERDICT_INCONCLUSIVE
    )
    assert MinerProbe.objects.get(miner_node_id=claim.view.node_id).last_ok is None


def test_a_pass_resets_the_streak(fleet: _Fleet) -> None:
    claim = _claimed(fleet, 1, fail_streak=2, last_attempt_at=NOW - 7 * H)
    _placed(claim, destroyed=True)
    later = NOW + 30 * timedelta(minutes=1)
    assert per_miner.record(claim, _outcome(claim.vm_id), now=later) == per_miner.VERDICT_OK
    row = MinerProbe.objects.get(miner_node_id=claim.view.node_id)
    assert (row.last_ok, row.fail_streak, row.last_stage, row.last_vm_id) == (
        True,
        0,
        "",
        claim.vm_id,
    )
    assert row.last_probe_at == later and row.last_ok_at == later
    assert row.in_flight_vm_id == "" and row.in_flight_since is None


def test_a_failure_that_reached_the_miner_counts(fleet: _Fleet) -> None:
    claim = _claimed(fleet, 1, fail_streak=1, last_attempt_at=NOW - 7 * H)
    _placed(claim, status=PlacementStatus.FAILED.value)
    verdict = per_miner.record(claim, _outcome(claim.vm_id, failed="boot"), now=NOW)
    assert verdict == per_miner.VERDICT_FAILED
    row = MinerProbe.objects.get(miner_node_id=claim.view.node_id)
    assert (row.last_ok, row.fail_streak, row.last_stage, row.last_detail) == (
        False,
        2,
        "boot",
        "boom",
    )
    assert row.last_ok_at is None


def test_a_failure_that_never_reached_the_miner_is_not_its_fault(fleet: _Fleet) -> None:
    """No placement on the miner: vali refused the pinned launch (or never
    got that far). The record and the streak stay; the claim is released;
    the attempt still moves the rotation on."""
    claim = _claimed(fleet, 1, fail_streak=1, last_ok=True, last_attempt_at=NOW - 7 * H)
    other = make_vm(claim.vm_id, lease_id="l")
    make_placement(other, node_id(9))  # placed elsewhere ⇒ still not this miner's
    other.state = VmState.DESTROYED  # and torn down by the run
    other.save(update_fields=["state"])
    verdict = per_miner.record(claim, _outcome(claim.vm_id, failed="launch_complete"), now=NOW)
    assert verdict == per_miner.VERDICT_INCONCLUSIVE
    row = MinerProbe.objects.get(miner_node_id=claim.view.node_id)
    assert (row.last_ok, row.fail_streak, row.last_probe_at) == (True, 1, None)
    assert row.in_flight_vm_id == "" and row.last_attempt_at == NOW


@pytest.mark.parametrize("stage", ["launch", "kek_alive", "decommission", "crypto_erase"])
def test_a_vali_side_stage_is_never_charged(fleet: _Fleet, stage: str) -> None:
    """The API POST and the two Vault checks are vali's own: a failure
    there says nothing about the miner, even with the VM placed on it."""
    claim = _claimed(fleet, 1, fail_streak=1, last_ok=True, last_attempt_at=NOW - 7 * H)
    _placed(claim, status=PlacementStatus.BOUND.value)
    assert per_miner.record(claim, _outcome(claim.vm_id, failed=stage), now=NOW) == (
        per_miner.VERDICT_INCONCLUSIVE
    )
    row = MinerProbe.objects.get(miner_node_id=claim.view.node_id)
    assert (row.fail_streak, row.last_ok) == (1, True)


@pytest.mark.parametrize(
    ("reason", "source", "charged"),
    [
        ("miner-rejected", PlacementFailureSource.LAUNCH, True),
        ("edge-unreachable", PlacementFailureSource.LAUNCH, True),
        ("vault-failure", PlacementFailureSource.LAUNCH, False),  # vali's side
        ("miner-rejected", PlacementFailureSource.MANUAL, False),  # not a launch outcome
    ],
)
def test_a_failed_launch_is_charged_only_when_the_node_refused(
    fleet: _Fleet, reason: str, source: str, charged: bool
) -> None:
    claim = _claimed(fleet, 1)
    vm = make_vm(claim.vm_id, lease_id="l")
    make_placement(
        vm,
        claim.view.node_id,
        status=PlacementStatus.FAILED.value,
        reason=reason,
        failure_source=source,
    )
    verdict = per_miner.record(claim, _outcome(claim.vm_id, failed="launch_complete"), now=NOW)
    assert verdict == (per_miner.VERDICT_FAILED if charged else per_miner.VERDICT_INCONCLUSIVE)


def test_a_vm_still_alive_after_the_run_keeps_the_miner_busy(fleet: _Fleet) -> None:
    """A teardown that handed the VM off: the claim stays until the VM is
    gone, so the budget cannot be exceeded by the next run."""
    claim = _claimed(fleet, 1)
    _placed(claim)  # the VM row is ACTIVE
    per_miner.record(claim, _outcome(claim.vm_id), now=NOW)
    row = MinerProbe.objects.get(miner_node_id=claim.view.node_id)
    assert row.in_flight_vm_id == claim.vm_id and row.last_ok is True
    assert _views()[0].blocked == per_miner.BLOCKED_BUSY
    # …and free again the moment the VM is destroyed, not at the reap age.
    from apps.lifecycle.models import Vm

    Vm.objects.filter(vm_id=claim.vm_id).update(state=VmState.DESTROYED)
    assert _views()[0].blocked == ""


def test_a_claim_taken_over_writes_nothing(fleet: _Fleet) -> None:
    claim = _claimed(fleet, 1, fail_streak=4)
    MinerProbe.objects.filter(miner_node_id=claim.view.node_id).update(
        in_flight_vm_id="synmon-pm-newer-2"
    )
    assert per_miner.record(claim, _outcome(claim.vm_id), now=NOW) == (
        per_miner.VERDICT_INCONCLUSIVE
    )
    row = MinerProbe.objects.get(miner_node_id=claim.view.node_id)
    assert (row.in_flight_vm_id, row.fail_streak, row.last_probe_at) == (
        "synmon-pm-newer-2",
        4,
        None,
    )


def test_a_run_that_crashed_releases_its_claim(fleet: _Fleet) -> None:
    claim = _claimed(fleet, 1)
    assert per_miner.record(claim, None, now=NOW) == per_miner.VERDICT_INCONCLUSIVE
    assert MinerProbe.objects.get(miner_node_id=claim.view.node_id).in_flight_vm_id == ""


# ─── one run ─────────────────────────────────────────────────────────


def test_off_launches_nothing(fleet: _Fleet, settings: Any, monkeypatch) -> None:
    settings.VALI_SYNTHETIC_PER_MINER = False
    _miner(fleet, 1)
    monkeypatch.setattr(e2e, "run_e2e", lambda **k: pytest.fail("launched while off"))
    report = per_miner.tick(api_factory=lambda: pytest.fail("api built while off"))
    assert report.enabled is False
    assert not MinerProbe.objects.exists()


def test_a_misconfiguration_never_lands_on_a_miner(fleet: _Fleet, monkeypatch) -> None:
    """No blessed image for the probe distro: refused before any claim."""
    _miner(fleet, 1)
    monkeypatch.setattr(e2e, "run_e2e", lambda **k: pytest.fail("launched"))
    report = per_miner.tick(api_factory=lambda: object())
    assert "not a blessed golden image" in report.error
    assert not MinerProbe.objects.exists()


def test_a_run_probes_the_claimed_miner_pinned_to_its_chip(
    fleet: _Fleet, blessed_ubuntu, settings: Any, monkeypatch
) -> None:
    settings.VALI_GUEST_ATTEST_RESOURCES = True
    settings.VALI_SYNTHETIC_PER_MINER_BUDGET_S = 2400
    nid = _miner(fleet, 1)
    seen: dict[str, Any] = {}

    def fake_run(**kw: Any) -> e2e.E2EOutcome:
        seen.update(kw)
        target = kw["target"]
        vm = make_vm(target.vm_id, lease_id="l")
        make_placement(vm, nid, status=PlacementStatus.BOUND.value)
        vm.state = VmState.DESTROYED  # the run's teardown
        vm.save(update_fields=["state"])
        return _outcome(target.vm_id, failed="resources")

    monkeypatch.setattr(e2e, "run_e2e", fake_run)
    api = object()
    report = per_miner.tick(api_factory=lambda: api, now=lambda: NOW)
    target = seen["target"]
    assert seen["api"] is api and seen["budget_s"] == 2400.0 and seen["distro"] == "ubuntu"
    assert target.platform_id == "01" + "cd" * 15
    assert target.flavor == "small" and target.check_resources is True
    assert target.vm_id.startswith("synmon-pm-")
    assert report.verdict == per_miner.VERDICT_FAILED
    row = MinerProbe.objects.get(miner_node_id=nid)
    assert (row.last_stage, row.fail_streak, row.in_flight_vm_id) == ("resources", 1, "")


def test_a_run_that_raises_still_releases_its_claim(
    fleet: _Fleet, blessed_ubuntu, monkeypatch
) -> None:
    nid = _miner(fleet, 1)

    def boom(**kw: Any) -> e2e.E2EOutcome:
        raise RuntimeError("crash")

    monkeypatch.setattr(e2e, "run_e2e", boom)
    with pytest.raises(RuntimeError):
        per_miner.tick(api_factory=lambda: object(), now=lambda: NOW)
    row = MinerProbe.objects.get(miner_node_id=nid)
    assert row.in_flight_vm_id == "" and row.last_probe_at is None


# ─── readouts ────────────────────────────────────────────────────────


def test_the_operator_readout_hides_the_internal_detail() -> None:
    _probe(
        node_id(1),
        last_probe_at=NOW,
        last_ok=False,
        last_stage="release",
        last_vm_id="synmon-pm-x-1",
        last_detail="vault: HTTP 403 at secret/...",
    )
    _probe(node_id(2), last_attempt_at=NOW)  # attempted, never reached
    _probe(node_id(3), last_probe_at=NOW, last_ok=True, last_vm_id="synmon-pm-y-1")
    out = per_miner.operator_readout([node_id(1).upper(), node_id(2), node_id(3)])
    assert out == {
        node_id(1): {
            "at": NOW.isoformat(),
            "ok": False,
            "stage": "release",
            "vm_id": "synmon-pm-x-1",
        },
        node_id(3): {"at": NOW.isoformat(), "ok": True, "stage": None, "vm_id": "synmon-pm-y-1"},
    }


def test_the_fleet_readout_lists_never_probed_miners(fleet: _Fleet) -> None:
    a = _miner(fleet, 1)
    b = _miner(fleet, 2)
    _probe(a, last_probe_at=NOW, last_ok=False, fail_streak=3)
    rows = {r.view.node_id: r for r in per_miner.fleet_readout(now=NOW)}
    assert rows[a].fail_streak == 3 and rows[a].last_ok is False
    assert rows[b].fail_streak == 0 and rows[b].view.last_probe_at is None
