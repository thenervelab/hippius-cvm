"""Earned capacity (capacity v2 §3): penalties, the growth tick, the
in-flight cap, and the launch-path hooks that feed them."""

from __future__ import annotations

import hashlib
import json
from datetime import timedelta
from io import StringIO

import pytest
from django.core.management import call_command
from django.test import override_settings
from django.utils import timezone

from apps.scheduler import capacity_earn, service
from apps.scheduler.capacity_earn import Sample
from apps.scheduler.models import (
    CapacityTrustClass,
    MinerCapacity,
    MinerCapacityAudit,
    PlacementStatus,
)

from .factories import make_placement, make_vm, node_id

pytestmark = pytest.mark.django_db

NODE = node_id(7)


def _row(**over: object) -> MinerCapacity:
    fields: dict[str, object] = dict(
        miner_node_id=NODE,
        status="active",
        capacity_slots=64,
        observed_epoch=10,
        data_epoch=10,
        refreshed_at=timezone.now(),
        trust_class=CapacityTrustClass.EARNED,
    )
    fields.update(over)
    return MinerCapacity.objects.create(**fields)


def _place(n: int, flavor: str = "medium", status: str = PlacementStatus.BOUND.value) -> None:
    for i in range(n):
        make_placement(
            make_vm(f"vm-{flavor}-{status}-{i}", f"lease-{flavor}-{status}-{i}"),
            NODE,
            status=status,
            resource_class=flavor,
        )


def _ceiling() -> tuple[int | None, int | None, int | None]:
    r = MinerCapacity.objects.get(miner_node_id=NODE)
    return (r.earned_vms, r.earned_vcpus, r.earned_memory_mb)


# ─── events ─────────────────────────────────────────────────────────


def test_a_preflight_refusal_sets_the_ceiling_to_what_the_host_holds() -> None:
    _row(earned_vms=10, earned_vcpus=20, earned_memory_mb=81920, proven_peak_vms=8)
    _place(3, "medium")  # 3 VMs, 6 vCPU, 24 GiB RUNNING
    # The refused launch (and any other not-yet-started one) is pending:
    # the host said it cannot hold it, so it is not "held".
    _place(1, "xlarge", status=PlacementStatus.PENDING.value)
    assert capacity_earn.record_event(NODE, capacity_earn.PREFLIGHT_INSUFFICIENT)
    assert _ceiling() == (3, 6, 3 * 8192)
    row = MinerCapacity.objects.get()
    assert row.proven_peak_vms == 3  # the proof cannot sit above the ceiling
    assert row.earned_last_reason == "preflight-insufficient"
    actors = set(MinerCapacityAudit.objects.values_list("actor", flat=True))
    assert actors == {"event:preflight-insufficient"}


def test_a_refusal_never_raises_the_ceiling() -> None:
    _row(earned_vms=2, earned_vcpus=4, earned_memory_mb=16384)
    _place(3, "medium")  # holds more than its ceiling (placed before a penalty)
    capacity_earn.record_event(NODE, capacity_earn.PREFLIGHT_INSUFFICIENT)
    assert _ceiling() == (2, 4, 16384)


def test_a_failed_start_halves_the_ceiling_down_to_the_floor() -> None:
    _row(earned_vms=20, earned_vcpus=40, earned_memory_mb=163840)
    capacity_earn.record_event(NODE, capacity_earn.START_FAILED)
    assert _ceiling() == (10, 20, 81920)
    for _ in range(6):
        capacity_earn.record_event(NODE, capacity_earn.START_FAILED)
    assert _ceiling() == (4, 8, 32768)  # the floor, never below


def test_one_incident_is_charged_once_however_often_it_retries() -> None:
    _row(earned_vms=20, earned_vcpus=40, earned_memory_mb=163840)
    for _ in range(3):
        capacity_earn.record_event(NODE, capacity_earn.START_FAILED, incident="vm=vm-1")
    assert _ceiling() == (10, 20, 81920)
    capacity_earn.record_event(NODE, capacity_earn.START_FAILED, incident="vm=vm-2")
    assert _ceiling() == (5, 10, 40960)


def test_a_penalty_invalidates_the_proof_in_progress() -> None:
    _row(
        earned_vms=20,
        earned_vcpus=40,
        earned_memory_mb=163840,
        candidate_vms=18,
        candidate_vcpus=36,
        candidate_memory_mb=147456,
        candidate_since=timezone.now() - timedelta(hours=1),
    )
    capacity_earn.record_event(NODE, capacity_earn.START_FAILED)
    row = MinerCapacity.objects.get()
    assert (row.candidate_vms, row.candidate_since) == (0, None)


def test_an_incapable_host_drops_to_the_floor() -> None:
    _row(earned_vms=20, earned_vcpus=40, earned_memory_mb=163840, proven_peak_vms=18)
    capacity_earn.record_event(NODE, capacity_earn.CVM_INCAPABLE)
    assert _ceiling() == (4, 8, 32768)
    assert MinerCapacity.objects.get().proven_peak_vms == 4


def test_no_event_ever_raises_a_ceiling() -> None:
    """A refusal can take a ceiling BELOW the floor; being declared
    incapable afterwards must not lift it back up to the floor."""
    _row(earned_vms=2, earned_vcpus=4, earned_memory_mb=16384)
    capacity_earn.record_event(NODE, capacity_earn.PREFLIGHT_INSUFFICIENT)  # holds 0
    assert _ceiling() == (0, 0, 0)
    for kind in (capacity_earn.CVM_INCAPABLE, capacity_earn.START_FAILED):
        capacity_earn.record_event(NODE, kind)
        assert _ceiling() == (0, 0, 0)


def test_events_never_touch_an_operator_miner() -> None:
    _row(trust_class=CapacityTrustClass.OPERATOR, total_cpus=24, total_memory_mb=125000)
    for kind in capacity_earn.EVENTS:
        assert not capacity_earn.record_event(NODE, kind)
    assert MinerCapacityAudit.objects.count() == 0


def test_an_unknown_event_kind_is_a_programming_error() -> None:
    with pytest.raises(ValueError):
        capacity_earn.record_event(NODE, "bad-vibes")


def test_a_failing_event_write_never_breaks_the_launch_path(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def boom(*_a: object, **_k: object) -> bool:
        raise RuntimeError("db down")

    monkeypatch.setattr(capacity_earn, "_record_event", boom)
    assert capacity_earn.record_event(NODE, capacity_earn.START_FAILED) is False


# ─── the tick ───────────────────────────────────────────────────────


def _tick(sample: Sample | None, at: object) -> capacity_earn.EarnReport:
    return capacity_earn.tick(now=at, sampler=lambda _nid, _at: sample)


def test_no_trusted_proof_source_means_no_growth() -> None:
    _row()
    report = capacity_earn.tick()  # the real sampler: VALI_CAPACITY_EARN_PROOF=off
    assert report.proof_available is False and report.grown == 0
    assert _ceiling() == (None, None, None)
    assert capacity_earn.proof_source() == "off"


def test_a_held_full_floor_grows_the_ceiling_once() -> None:
    _row()
    t0 = timezone.now()
    full = Sample(vms=4, vcpus=8, memory_mb=32768)
    _tick(full, t0)
    assert _ceiling() == (None, None, None)  # held for 0 s: nothing yet
    _tick(full, t0 + timedelta(minutes=29))
    assert _ceiling() == (None, None, None)
    report = _tick(full, t0 + timedelta(minutes=31))
    assert report.grown == 1
    # max(ceil(4 × 1.5), 4 + 2) = 6 VMs; max(12, 8 + 4) = 12 vCPU; 48 GiB.
    assert _ceiling() == (6, 12, 49152)
    row = MinerCapacity.objects.get()
    assert (row.proven_peak_vms, row.earned_last_reason) == (4, "proof-held")
    assert MinerCapacityAudit.objects.filter(actor="tick:earn", field="earned_vms").exists()


def test_a_spike_shorter_than_the_hold_does_not_count() -> None:
    _row()
    t0 = timezone.now()
    _tick(Sample(4, 8, 32768), t0)
    _tick(Sample(1, 2, 8192), t0 + timedelta(minutes=20))  # dropped: hold restarts at 1
    _tick(Sample(4, 8, 32768), t0 + timedelta(minutes=40))  # rise: 1 is still being held
    _tick(Sample(4, 8, 32768), t0 + timedelta(minutes=60))  # 1 proven; 4 starts its hold
    assert MinerCapacity.objects.get().proven_peak_vms == 1
    assert _ceiling() == (None, None, None)  # 1 of 4 is below the fill trigger
    _tick(Sample(4, 8, 32768), t0 + timedelta(minutes=80))
    assert _ceiling() == (None, None, None)  # 4 held for 20 min only
    _tick(Sample(4, 8, 32768), t0 + timedelta(minutes=91))
    assert _ceiling() == (6, 12, 49152)


def test_growth_follows_fill_only() -> None:
    """A proof below `earn_util_trigger` of the ceiling grows nothing."""
    _row(earned_vms=10, earned_vcpus=20, earned_memory_mb=81920)
    t0 = timezone.now()
    # 70 % in every dimension: × 1.5 would exceed the ceiling, but the
    # miner is not full enough to have earned it.
    most = Sample(vms=7, vcpus=14, memory_mb=57344)
    _tick(most, t0)
    _tick(most, t0 + timedelta(minutes=31))
    assert _ceiling() == (10, 20, 81920)
    assert MinerCapacity.objects.get().proven_peak_vms == 7


def test_growth_is_multiplicative_above_the_minimum_step() -> None:
    _row(earned_vms=12, earned_vcpus=24, earned_memory_mb=98304)
    t0 = timezone.now()
    full = Sample(vms=10, vcpus=20, memory_mb=81920)  # ≥ 80 % of 12 / 24 / 96 GiB
    _tick(full, t0)
    _tick(full, t0 + timedelta(minutes=31))
    # ceil(10 × 1.5) = 15 beats 10 + 2; 30 vCPU beats 24; 120 GiB beats 96.
    assert _ceiling() == (15, 30, 122880)


@override_settings(VALI_CAPACITY_EARN_HARD_CAP_VMS=5)
def test_growth_stops_at_the_hard_cap() -> None:
    _row()
    t0 = timezone.now()
    full = Sample(4, 8, 32768)
    _tick(full, t0)
    _tick(full, t0 + timedelta(minutes=31))
    assert _ceiling()[0] == 5


def test_a_stale_proof_is_re_proven_from_what_runs_now() -> None:
    old = timezone.now() - timedelta(days=20)
    _row(proven_peak_vms=10, proven_peak_vcpus=20, proven_peak_memory_mb=81920, proven_at=old)
    _tick(Sample(2, 4, 16384), timezone.now())
    row = MinerCapacity.objects.get()
    assert (row.proven_peak_vms, row.proven_peak_vcpus) == (2, 4)


def test_the_tick_resets_an_incapable_earned_host(monkeypatch: pytest.MonkeyPatch) -> None:
    _row(earned_vms=12, earned_vcpus=24, earned_memory_mb=98304)
    monkeypatch.setattr(service, "cvm_capability_by_node", lambda: {NODE: "incapable"})
    report = _tick(Sample(4, 8, 32768), timezone.now())
    assert report.reset_incapable == 1
    assert _ceiling() == (4, 8, 32768)


def test_a_lower_hold_does_not_keep_an_old_peak_fresh() -> None:
    old = timezone.now() - timedelta(days=13)
    _row(proven_peak_vms=10, proven_peak_vcpus=20, proven_peak_memory_mb=81920, proven_at=old)
    t0 = timezone.now()
    _tick(Sample(2, 4, 16384), t0)
    _tick(Sample(2, 4, 16384), t0 + timedelta(minutes=31))
    row = MinerCapacity.objects.get()
    assert row.proven_peak_vms == 10
    assert row.proven_at == old  # not renewed by a hold that did not reach it


def test_the_tick_skips_a_row_that_became_operator_meanwhile() -> None:
    _row()

    def flip_then_sample(nid: str, _at: object) -> Sample:
        MinerCapacity.objects.filter(miner_node_id=nid).update(
            trust_class=CapacityTrustClass.OPERATOR, total_cpus=24, total_memory_mb=125000
        )
        return Sample(4, 8, 32768)

    capacity_earn.tick(now=timezone.now(), sampler=flip_then_sample)
    assert MinerCapacityAudit.objects.count() == 0
    assert MinerCapacity.objects.get().candidate_since is None


def test_the_tick_ignores_operator_miners() -> None:
    _row(trust_class=CapacityTrustClass.OPERATOR, total_cpus=24, total_memory_mb=125000)
    t0 = timezone.now()
    _tick(Sample(30, 60, 200000), t0)
    report = _tick(Sample(30, 60, 200000), t0 + timedelta(hours=1))
    assert report.earned_rows == 0
    assert MinerCapacityAudit.objects.count() == 0


@override_settings(VALI_CAPACITY_EARN_PROOF="served-receipts")
def test_an_untrusted_proof_source_is_refused_loudly() -> None:
    from django.core.exceptions import ImproperlyConfigured

    with pytest.raises(ImproperlyConfigured, match="not a proof source"):
        capacity_earn.proof_source()


def test_the_command_reports_the_pass() -> None:
    _row()
    out = StringIO()
    call_command("vali_capacity_earn", stdout=out)
    line = json.loads(out.getvalue())
    assert line["event"] == "capacity_earn_tick"
    assert (line["proof"], line["earned_rows"], line["grown"]) == ("off", 1, 0)


# ─── in-flight cap ──────────────────────────────────────────────────


def test_an_earned_miner_takes_nothing_more_with_two_launches_in_flight() -> None:
    _row(earned_vms=10, earned_vcpus=20, earned_memory_mb=81920)
    _place(1, "small", status=PlacementStatus.PENDING.value)
    assert service.resource_fit("small").fits_by_node[NODE] is True
    _place(2, "medium", status=PlacementStatus.PENDING.value)
    assert service.resource_fit("small").fits_by_node[NODE] is False


def test_the_in_flight_cap_never_applies_to_an_operator_miner() -> None:
    _row(trust_class=CapacityTrustClass.OPERATOR, total_cpus=24, total_memory_mb=125000)
    _place(5, "small", status=PlacementStatus.PENDING.value)
    assert service.resource_fit("small").fits_by_node[NODE] is True


# ─── launch-path hooks ──────────────────────────────────────────────


def _miner() -> object:
    from .factories import make_dispatchable_identity

    identity = make_dispatchable_identity(7)
    return identity


@pytest.mark.parametrize(
    ("status", "classifier", "charged"),
    [
        (500, "launch-failed", True),  # the miner answered: the start failed
        (502, "", False),  # Edge, no body: the outcome is unknown
        (502, "launch-failed", False),  # an Edge status is never the miner's word
        (504, "", False),
        (409, "order-in-flight", False),  # a replay, not a failure
        (422, "launch-input", False),  # a bad order, not the host
        (503, "insufficient-resources", False),  # full, charged elsewhere
        (500, "", False),  # no miner class at all
    ],
)
def test_only_a_start_failure_the_miner_answered_is_charged(
    status: int, classifier: str, charged: bool
) -> None:
    from apps.orchestration.services import launch

    assert launch._start_failure_is_miner_attributable(status, classifier) is charged


def test_a_preflight_capacity_refusal_charges_the_dispatched_node(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from apps.orchestration.services import launch
    from apps.orchestration.services import preflight as preflight_svc

    seen: list[tuple[str, str]] = []
    monkeypatch.setattr(
        capacity_earn, "record_event", lambda nid, kind, **_k: seen.append((nid, kind)) or True
    )
    miner = _miner()
    assert launch._preflight_refusal_is_capacity(
        preflight_svc.PreflightRejected("x", classifier="insufficient-resources")
    )
    assert not launch._preflight_refusal_is_capacity(
        preflight_svc.PreflightRejected("x", classifier="preflight-sha-mismatch")
    )
    launch._record_capacity_event(miner, "preflight-insufficient")
    assert seen == [(NODE, "preflight-insufficient")]


# ─── the live-attestation proof source ──────────────────────────────

CHIP = "66" * 64
HOLD = 1800


def _measurement(vm_id: str) -> str:
    return hashlib.sha384(vm_id.encode()).hexdigest()


def _pin(vm_id: str) -> None:
    from apps.orchestration.models import MeasurementLedger

    MeasurementLedger.objects.create(
        vm_id=vm_id,
        launch_digest_hex=_measurement(vm_id),
        allowlist_epoch=1,
    )


def _platform(node: str = NODE, chip: str = CHIP) -> None:
    from apps.miners.models import MinerIdentity

    MinerIdentity.objects.create(
        miner_id=f"miner-{node[-4:]}",
        pubkey_hex="ab" * 32,
        platform_id=chip,
        chain_node_id=node,
    )


def _attest(
    vm_id: str,
    *,
    report: str,
    at: int,
    source: str = "release",
    chip: str = CHIP,
    measurement: str | None = None,
) -> None:
    from apps.telemetry.models import VmLiveAttestation

    VmLiveAttestation.objects.create(
        vm_id=vm_id,
        node_id_hex=node_id(1),  # the declared LAUNCH node — never the proof axis
        attestation_seq=at,
        epoch=1,
        observed_at_unix=at,
        verified_at_unix=at,
        expiry_unix=at + 900,
        measurement=measurement or _measurement(vm_id),
        snp_report_digest="11" * 32,
        body_digest=hashlib.sha256(f"{vm_id}/{report}/{at}".encode()).hexdigest(),
        binding_source=source,
        chip_id=chip,
        report_id=report * 32,
    )


def _alive(vm_id: str, *, report: str, now: int, since: int | None = None, **kw: object) -> None:
    """A guest that has attested every 10 min from `since` (default: a
    full hold ago) up to `now`."""
    at = now - HOLD - 60 if since is None else since
    while at < now:
        _attest(vm_id, report=report, at=at, **kw)
        at += 600
    _attest(vm_id, report=report, at=now, **kw)


def _proof_setup(n: int) -> int:
    _platform()
    _place(n, "small")
    for i in range(n):
        _pin(f"vm-small-bound-{i}")
    return int(timezone.now().timestamp())


@override_settings(VALI_CAPACITY_EARN_PROOF="live-attestation", VALI_CAPACITY_EARN_HOLD_S=HOLD)
def test_live_attestation_proof_counts_distinct_guests_alive_the_whole_hold() -> None:
    now = _proof_setup(4)
    _alive("vm-small-bound-0", report="a1", now=now)
    _alive("vm-small-bound-1", report="a2", now=now)
    # One guest's samples presented for a second vm_id (same measurement
    # is impossible — shown here with the second VM's own pin): counted
    # for neither.
    _alive("vm-small-bound-2", report="a3", now=now)
    _alive("vm-small-bound-3", report="a3", now=now)
    sample = capacity_earn.proven_concurrency(NODE, now=timezone.now())
    assert sample is not None and sample.vms == 2
    m, c = service._committed_resources("small")
    assert (sample.vcpus, sample.memory_mb) == (2 * c, 2 * m)


@override_settings(VALI_CAPACITY_EARN_PROOF="live-attestation", VALI_CAPACITY_EARN_HOLD_S=HOLD)
def test_live_attestation_proof_ignores_what_is_not_proof() -> None:
    now = _proof_setup(8)
    _place(1, "small", status=PlacementStatus.PENDING.value)
    _pin("vm-small-pending-0")
    _alive("vm-small-bound-0", report="b1", now=now, source="first-use")
    _alive("vm-small-bound-1", report="b2", now=now, source="")  # v1 body
    _attest("vm-small-bound-2", report="b3", at=now - HOLD - 60)  # stale: no fresh sample
    _alive("vm-small-bound-3", report="b4", now=now, chip="77" * 64)  # another chip
    _alive("vm-small-bound-4", report="b5", now=now, measurement="99" * 48)  # another VM's guest
    _attest("vm-small-bound-5", report="b6", at=now)  # younger than the hold
    # Sighted a hold ago and now, but silent in between (suspended).
    _attest("vm-small-bound-7", report="ba", at=now - HOLD - 60)
    _attest("vm-small-bound-7", report="ba", at=now)
    # Rotation: vm-6 was alive a hold ago, but as a DIFFERENT guest.
    _attest("vm-small-bound-6", report="b7", at=now - HOLD - 60)
    _attest("vm-small-bound-6", report="b8", at=now)
    _alive("vm-small-pending-0", report="b9", now=now)  # not BOUND
    assert capacity_earn.proven_concurrency(NODE, now=timezone.now()) == Sample()


@override_settings(VALI_CAPACITY_EARN_PROOF="live-attestation", VALI_CAPACITY_EARN_HOLD_S=HOLD)
def test_live_attestation_proof_needs_a_pinned_measurement() -> None:
    _platform()
    _place(1, "small")  # never pinned in the ledger
    now = int(timezone.now().timestamp())
    _alive("vm-small-bound-0", report="c1", now=now)
    assert capacity_earn.proven_concurrency(NODE, now=timezone.now()) == Sample()


@override_settings(VALI_CAPACITY_EARN_PROOF="live-attestation", VALI_CAPACITY_EARN_HOLD_S=HOLD)
def test_live_attestation_proof_uses_each_vms_newest_guest() -> None:
    now = _proof_setup(2)
    # vm-0 rebooted a while ago: its old guest (c1) is superseded by c9,
    # which has itself lived the whole hold. vm-1's CURRENT guest is c1 —
    # not a collision with vm-0's past.
    _attest("vm-small-bound-0", report="c1", at=now - 3 * HOLD)
    _alive("vm-small-bound-0", report="c9", now=now)
    _alive("vm-small-bound-1", report="c1", now=now)
    sample = capacity_earn.proven_concurrency(NODE, now=timezone.now())
    assert sample is not None and sample.vms == 2


@override_settings(VALI_CAPACITY_EARN_PROOF="live-attestation", VALI_CAPACITY_EARN_HOLD_S=HOLD)
def test_a_live_attestation_proof_held_grows_the_ceiling() -> None:
    _row()
    t0 = timezone.now()
    now = _proof_setup(4)
    for i in range(4):
        _alive(f"vm-small-bound-{i}", report=f"d{i}", now=now)
    capacity_earn.tick(now=t0)
    t1 = t0 + timedelta(seconds=HOLD + 1)
    for i in range(4):
        _alive(f"vm-small-bound-{i}", report=f"d{i}", now=int(t1.timestamp()), since=now + 600)
    report = capacity_earn.tick(now=t1)
    assert report.proof_available is True and report.grown == 1
    assert _ceiling()[0] is not None and _ceiling()[0] > 4


@override_settings(VALI_CAPACITY_EARN_PROOF="live-attestation", VALI_CAPACITY_EARN_HOLD_S=60)
def test_one_sample_is_not_a_held_run_when_the_hold_is_shorter_than_the_span() -> None:
    now = _proof_setup(1)
    _attest("vm-small-bound-0", report="e1", at=now - 120)  # fresh AND a hold ago
    assert capacity_earn.proven_concurrency(NODE, now=timezone.now()) == Sample()
    _attest("vm-small-bound-0", report="e1", at=now)
    sample = capacity_earn.proven_concurrency(NODE, now=timezone.now())
    assert sample is not None and sample.vms == 1
