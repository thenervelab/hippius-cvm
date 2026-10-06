"""Untrusted-miner-safe DYNAMIC capacity — the make-or-break invariant.

Two layers:

- Pure `capacity.effective_capacity` unit tests (no DB) — the adversarial
  cases that prove self-reported data can only THROTTLE DOWN, never raise
  a miner's admission bound past `committed + f(trusted_free)`.
- `service.decision_inputs` integration — the dynamic bound is computed
  from vali's OWN `Placement` ledger × the flavor table, and the
  heartbeat self-report is applied down-only via the mirror row.
"""

from __future__ import annotations

import pytest
from django.utils import timezone

from apps.scheduler import service
from apps.scheduler.capacity import CapacityInputs, effective_capacity
from apps.scheduler.models import MinerCapacity, MinerStatusMirror, PlacementStatus

from .factories import make_placement, make_vm, node_id

# `large` flavor reference: 8192 MiB / 4 vCPU per slot (the defaults).
REF_MB = 8192
REF_CPUS = 4


def _inp(**over: object) -> CapacityInputs:
    """A trusted-anchored miner with generous headroom; override per-case."""
    base: dict[str, object] = dict(
        operator_max=64,
        total_memory_mb=125_000,  # an EPYC 9254 class host
        total_cpus=24,
        committed_memory_mb=0,
        committed_cpus=0,
        committed_slots=0,
        reported_free_mib=None,
        reserve_memory_mb=4096,
        reserve_cpus=2,
        slot_ref_memory_mb=REF_MB,
        slot_ref_cpus=REF_CPUS,
    )
    base.update(over)
    return CapacityInputs(**base)  # type: ignore[arg-type]


# ─── Pure: fallback + no-regression ──────────────────────────────────


def test_no_anchor_falls_back_to_flat_operator_max() -> None:
    """An un-seeded miner (no trusted hardware) keeps the exact legacy
    flat cap — zero regression."""
    r = effective_capacity(_inp(total_memory_mb=None, operator_max=8))
    assert r.slots == 8
    assert r.dynamic is False
    assert r.over_claim is False


def test_seeded_miner_gets_dynamic_uplift() -> None:
    """A 125 GB host: 125 GB total, 4 GB reserve, nothing committed ⇒ RAM
    bounds (125000-4096)/8192 = 14 slots; CPU bounds (24-2)/4 = 5 slots.
    min(14,5)=5 additional slots. (CPU-bound, as SMT-off silicon is.)"""
    r = effective_capacity(_inp())
    assert r.dynamic is True
    # committed_slots(0) + min(free_mem_slots=14, free_cpu_slots=5) = 5.
    assert r.slots == 5


def test_ram_bound_when_cpu_plentiful() -> None:
    """With abundant vCPU the RAM dimension binds — proves both
    dimensions gate (neither is oversubscribed)."""
    r = effective_capacity(_inp(total_cpus=256, total_memory_mb=32_768))
    # free_mem = (32768-4096)/8192 = 3 ; free_cpu = (256-2)/4 = 63 ⇒ 3.
    assert r.slots == 3


# ─── Pure: ADVERSARIAL self-report ───────────────────────────────────


def test_over_report_gains_zero_extra_capacity() -> None:
    """A miner claiming 900 GB free wins NOTHING — capped by the trusted
    computed value. THE make-or-break invariant."""
    honest = effective_capacity(_inp(total_cpus=256))  # RAM-bound baseline
    liar = effective_capacity(_inp(total_cpus=256, reported_free_mib=900_000))
    assert liar.slots == honest.slots  # no uplift from over-reporting
    assert liar.over_claim is True  # and it is flagged


def test_impossible_claim_is_clamped_and_flagged() -> None:
    """reported_free > total (physically impossible) ⇒ clamp to trusted,
    flag. Claims more free RAM than the machine has."""
    r = effective_capacity(
        _inp(
            total_cpus=256,
            total_memory_mb=32_768,
            committed_memory_mb=16_384,  # half already committed
            committed_slots=2,
            reported_free_mib=32_769,  # more than the whole box
        )
    )
    # trusted_free = 32768-16384-4096 = 12288 ⇒ 1 slot. + committed 2 = 3.
    assert r.slots == 3
    assert r.over_claim is True


def test_an_idle_host_reporting_nearly_all_its_ram_is_not_flagged() -> None:
    """The reserve is POLICY, not memory the host OS occupies: an idle
    256 GB host reports ~253 GB available, far above `total − reserve`
    with an 8 GiB reserve. That is honest and must not alarm (it did on
    every scheduler call once the reserve went to 8192)."""
    r = effective_capacity(
        _inp(total_cpus=64, total_memory_mb=256_180, reserve_memory_mb=8192,
             reported_free_mib=253_073)
    )
    assert r.over_claim is False


def test_plausible_band_report_not_flagged_capacity_still_clamps() -> None:
    """THE honest-buff/cache case (PR-2). A report in the plausible band
    `[total-committed-reserve, total-reserve]` — legitimate because placed
    VMs under-use their nominal committed RAM (host counts buff/cache as
    `available`) — must NOT alarm, AND capacity is UNCHANGED: it still
    clamps to the trusted computed free (`min`)."""
    committed = 8192  # one large VM committed
    reported = 116_000  # > trusted_free (112712) but < total-reserve (120904)
    r = effective_capacity(
        _inp(
            total_cpus=256,
            committed_memory_mb=committed,
            committed_slots=1,
            reported_free_mib=reported,
        )
    )
    # trusted_free = 125000-8192-4096 = 112712; 116000 is in the plausible
    # band [112712, 120904] ⇒ NO alarm (previously false-positived here).
    assert r.over_claim is False
    # Capacity is UNAFFECTED by the report: it clamps DOWN to computed_free.
    # min(112712, 116000)=112712 ⇒ 112712//8192 = 13 slots + committed 1 = 14.
    honest = effective_capacity(
        _inp(total_cpus=256, committed_memory_mb=committed, committed_slots=1)
    )
    assert r.slots == honest.slots == 14


def test_report_at_physical_max_is_not_flagged() -> None:
    """The alarm boundary: `reported == total` (the whole machine free) is
    plausible — not flagged. One MiB more is."""
    phys_max = 125_000  # total
    ok = effective_capacity(_inp(total_cpus=256, reported_free_mib=phys_max))
    assert ok.over_claim is False
    liar = effective_capacity(_inp(total_cpus=256, reported_free_mib=phys_max + 1))
    assert liar.over_claim is True
    # Alarm did NOT change capacity — the over-claim clamps to trusted_free.
    assert liar.slots == ok.slots


def test_under_report_throttles_itself_down() -> None:
    """A miner reporting LESS free than trusted honestly throttles itself
    (min()) — the down-only clamp in the honest direction."""
    r = effective_capacity(_inp(total_cpus=256, reported_free_mib=8192))
    # effective_free = min(trusted, 8192) = 8192 ⇒ 1 slot (RAM-bound).
    assert r.slots == 1
    assert r.over_claim is False


def test_report_exactly_at_trusted_is_not_over_claim() -> None:
    """reported == trusted_free is the boundary — honoured, not flagged."""
    # trusted_free with defaults + 256 cpu = 125000-4096 = 120904.
    r = effective_capacity(_inp(total_cpus=256, reported_free_mib=120_904))
    assert r.over_claim is False
    assert r.slots == 120_904 // REF_MB  # 14


# ─── Pure: operator clamp + fail-closed ──────────────────────────────


def test_operator_max_clamps_dynamic_down() -> None:
    """The operator ceiling always wins DOWN — a miner is boundable below
    its hardware."""
    r = effective_capacity(_inp(total_cpus=256, operator_max=3))
    assert r.slots == 3  # would be 14 on RAM alone, clamped to 3


def test_overcommitted_miner_admits_no_new_vms() -> None:
    """Committed already exceeds trusted total ⇒ 0 free slots ⇒ capacity
    == current load (fail-closed, never negative)."""
    r = effective_capacity(
        _inp(
            total_cpus=8,
            total_memory_mb=16_384,
            committed_memory_mb=20_000,  # over-committed
            committed_cpus=8,
            committed_slots=3,
        )
    )
    assert r.slots == 3  # == load; no additional slots


# ─── Integration: committed comes from vali's OWN ledger ─────────────


def _mirror(seed: int, **fields: object) -> MinerCapacity:
    return MinerCapacity.objects.create(
        miner_node_id=node_id(seed),
        status=MinerStatusMirror.ACTIVE,
        capacity_slots=fields.pop("capacity_slots", 64),
        observed_epoch=10,
        data_epoch=10,
        refreshed_at=timezone.now(),
        **fields,
    )


@pytest.mark.django_db
def test_decision_inputs_computes_committed_from_own_ledger() -> None:
    """Capacity shrinks as vali places VMs — committed is Σ over vali's
    OWN Placement rows × the flavor table, not the miner's word."""
    _mirror(1, total_memory_mb=125_000, total_cpus=256)  # RAM-bound
    # No placements yet: free_mem = (125000-4096)/8192 = 14 slots.
    cap, _load, _fam = service.decision_inputs("")
    assert cap[node_id(1)] == 14

    # vali places two `large` VMs itself. Their size is READ from the flavor
    # catalogue rather than copied here: this test asserts the ARITHMETIC of
    # `committed = Σ own placements × flavor`, and hardcoding the flavor made
    # a catalogue change (the 2026-08-20 grid) look like a capacity bug.
    from apps.orchestration.services import flavors

    large_mb = flavors.resolve_flavor("large").memory_mb
    make_placement(
        make_vm("vm-a"),
        node_id(1),
        status=PlacementStatus.BOUND.value,
        resource_class="large",
    )
    make_placement(
        make_vm("vm-b"),
        node_id(1),
        status=PlacementStatus.BOUND.value,
        resource_class="large",
    )
    cap, load, _fam = service.decision_inputs("")
    assert load[node_id(1)] == 2
    # committed = 2 × large ⇒ the free RAM left buys
    # (125000 - 2*large_mb - 4096) // 8192 further slots, and the 2 already
    # committed still count. 8192 is the SLOT REFERENCE (settings, not a
    # flavor) — one admission slot's worth of RAM.
    expected = (125_000 - 2 * large_mb - 4096) // 8192 + 2
    assert cap[node_id(1)] == expected
    # free_slots the scheduler sees = capacity - load (the real headroom).
    assert cap[node_id(1)] - load[node_id(1)] == expected - 2


@pytest.mark.django_db
def test_decision_inputs_unseeded_row_is_flat_capacity() -> None:
    """A mirror row with no trusted anchor keeps its flat capacity_slots
    (no regression)."""
    _mirror(2, capacity_slots=8)  # total_memory_mb stays NULL
    cap, _load, _fam = service.decision_inputs("")
    assert cap[node_id(2)] == 8


@pytest.mark.django_db
def test_decision_inputs_fresh_report_throttles_down(settings) -> None:
    """A FRESH low self-report on the mirror throttles capacity down;
    an over-report is ignored (clamped to trusted)."""
    settings.VALI_MINER_LIVENESS_TIMEOUT_S = 180
    now = timezone.now()
    # Honest low report: 8192 MiB free ⇒ 1 slot.
    _mirror(
        3,
        total_memory_mb=125_000,
        total_cpus=256,
        reported_memory_available_mib=8192,
        reported_at=now,
    )
    # Over-report: claims 900 GB free — ignored, trusted 14 stands.
    _mirror(
        4,
        total_memory_mb=125_000,
        total_cpus=256,
        reported_memory_available_mib=900_000,
        reported_at=now,
    )
    cap, _load, _fam = service.decision_inputs("")
    assert cap[node_id(3)] == 1  # throttled down
    assert cap[node_id(4)] == 14  # over-report gained nothing


@pytest.mark.django_db
def test_decision_inputs_stale_report_is_ignored(settings) -> None:
    """A STALE self-report is dropped — the trusted computed value
    stands (ignoring it can only keep the bound at/above reported, never
    above trusted)."""
    from datetime import timedelta

    settings.VALI_MINER_LIVENESS_TIMEOUT_S = 180
    stale = timezone.now() - timedelta(seconds=600)
    _mirror(
        5,
        total_memory_mb=125_000,
        total_cpus=256,
        reported_memory_available_mib=8192,
        reported_at=stale,
    )
    cap, _load, _fam = service.decision_inputs("")
    assert cap[node_id(5)] == 14  # stale 8192-report ignored


@pytest.mark.django_db
def test_decision_inputs_unknown_resource_class_counts_as_reference() -> None:
    """A legacy `std` placement (not a flavor) still consumes committed
    capacity — fail-closed (unknown load reduces free, never inflates)."""
    _mirror(6, total_memory_mb=125_000, total_cpus=256)
    make_placement(
        make_vm("vm-legacy"),
        node_id(6),
        status=PlacementStatus.BOUND.value,
        resource_class="std",
    )
    cap, load, _fam = service.decision_inputs("")
    assert load[node_id(6)] == 1
    # committed = reference 8192 MiB ⇒ free_mem = (125000-8192-4096)/8192 = 13
    # additional + 1 committed = 14.
    assert cap[node_id(6)] == 14
