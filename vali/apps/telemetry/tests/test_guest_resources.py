"""Attested guest resources vs the launch's flavor (`apps.telemetry.guest_resources`).

The guest's vCPU / RAM figures arrive inside a KBS-signed live attestation
(schema v3); the verifier is faked here exactly as in `test_vm_liveness`.
What a launch was measured for is the `MeasurementLedger` row its pin wrote.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from apps.orchestration.models import MeasurementLedger
from apps.scheduler.models import VmBillingBinding
from apps.telemetry import guest_resources, vm_liveness
from apps.telemetry.guest_resources import Attested, judge
from apps.telemetry.models import GuestResourceShortfall, VmLiveAttestation
from apps.telemetry.tests.test_vm_liveness import (
    KBS_L0,
    MEASUREMENT,
    NODE_ID,
    NOW,
    VM,
    FakeVerifier,
)

pytestmark = pytest.mark.django_db

MIB = 1024
GIB = 1024 * MIB

# An honest `large` (4 vCPU / 16 GiB) SEV-SNP guest: the firmware keeps a
# few MiB for itself, the kernel takes the struct page array and a 1 GiB
# swiotlb, OVMF left the RAM above 4 GiB for the kernel to accept lazily.
HONEST_LARGE = Attested(
    vcpus_online=4,
    mem_firmware_kib=16 * GIB - 12 * MIB,
    mem_total_kib=15_337_812,
    mem_unaccepted_kib=11 * GIB,
)
# The same VM started by a miner at the `medium` size (a VMM run with
# -smp 2 -m 8G; or the pre-resize launch booted again).
MEDIUM_SIZED = Attested(
    vcpus_online=2,
    mem_firmware_kib=8 * GIB - 12 * MIB,
    mem_total_kib=7_600_000,
    mem_unaccepted_kib=0,
)


@pytest.fixture(autouse=True)
def _pin_now(monkeypatch):
    monkeypatch.setattr(vm_liveness, "_now_unix", lambda: NOW)


@pytest.fixture(autouse=True)
def _wire_kbs_key(settings):
    settings.VALI_KBS_L0_VERIFYING_KEY = KBS_L0
    # ENFORCE acts through the armed uptime gate (as in production) and
    # pays only launches that asked for the attestation.
    settings.VALI_UPTIME_REQUIRE_LIVENESS_ATTESTATION = True
    settings.VALI_GUEST_ATTEST_RESOURCES = True


@pytest.fixture
def fake(monkeypatch) -> FakeVerifier:
    f = FakeVerifier()
    monkeypatch.setattr(vm_liveness.verifier, "verify_live_attestation", f)
    return f


def _pin(
    measurement: str = MEASUREMENT,
    *,
    flavor: str = "large",
    attests: bool = True,
    eager: bool = False,
    at: int = NOW - 3600,
    launched: bool = True,
) -> None:
    """What a launch's auto-pin writes (`allowlist_pin._record_ledger`) —
    and, once the miner accepted the launch, its `launched_at` stamp
    (`launch._mark_measurement_launched`), 10 s after the pin."""
    row = MeasurementLedger.objects.create(
        vm_id=VM,
        launch_digest_hex=measurement,
        allowlist_epoch=1,
        flavor=flavor,
        attests_resources=attests,
        accepts_memory_eagerly=eager,
    )
    MeasurementLedger.objects.filter(pk=row.pk).update(
        pinned_at=datetime.fromtimestamp(at, tz=UTC),
        launched_at=datetime.fromtimestamp(at + 10, tz=UTC) if launched else None,
    )


def _binding(flavor: str = "large") -> VmBillingBinding:
    return VmBillingBinding.objects.create(
        vm_id=VM, node_id_hex=NODE_ID, resource_class=flavor, lease_id="lease-1"
    )


def _attest(
    fake: FakeVerifier, a: Attested | None, *, seq: int = 1, measurement: str = MEASUREMENT
) -> VmLiveAttestation:
    fake.resources = (
        None
        if a is None
        else (a.vcpus_online, a.mem_firmware_kib, a.mem_total_kib, a.mem_unaccepted_kib)
    )
    fake.attestation_seq = seq
    fake.body_digest_hex = f"{seq:064x}"
    fake.prev_attestation_hash_hex = "00" * 32 if seq == 1 else f"{seq - 1:064x}"
    fake.measurement_hex = measurement
    row, created = vm_liveness.ingest_live_attestation(envelope=b"\x01")
    assert created
    return row


def _window_covered() -> int:
    return vm_liveness.covered_seconds(vm_id=VM, start_unix=NOW - 600, end_unix=NOW)


# ─── the verdict ─────────────────────────────────────────────────────


def test_an_honest_guest_is_ok_on_every_flavor() -> None:
    from apps.orchestration.services.flavors import FLAVOR_NAMES, resolve_flavor

    for name in FLAVOR_NAMES:
        size = resolve_flavor(name)
        want = size.memory_mb * MIB
        honest = Attested(
            vcpus_online=size.cpu_count,
            mem_firmware_kib=want - 12 * MIB,
            # memmap 1.6 % + swiotlb 6 % capped at 1 GiB + kernel ~64 MiB
            mem_total_kib=int(want - want * 0.016 - min(want * 0.06, GIB) - 64 * MIB),
            mem_unaccepted_kib=max(0, want - 4 * GIB),
        )
        v = judge(cpu_count=size.cpu_count, memory_mb=size.memory_mb, attested=honest)
        assert v.verdict == guest_resources.VERDICT_OK, (name, v)
        # Without a firmware map the MemTotal fallback still passes it.
        no_map = Attested(honest.vcpus_online, 0, honest.mem_total_kib, 0)
        assert (
            judge(cpu_count=size.cpu_count, memory_mb=size.memory_mb, attested=no_map).verdict
            == guest_resources.VERDICT_OK
        ), name


def test_the_firmware_slack_is_absolute_not_a_share(settings) -> None:
    settings.VALI_GUEST_MEM_FIRMWARE_SLACK_MIB = 64
    want = 131072  # 4xlarge, 128 GiB
    ok = Attested(32, want * MIB - 64 * MIB, 1, 0)
    assert judge(cpu_count=32, memory_mb=want, attested=ok).verdict == "ok"
    # 1 % of a 4xlarge is 1.3 GiB — a ratio would let that through.
    short = Attested(32, want * MIB - 65 * MIB, 1, 0)
    v = judge(cpu_count=32, memory_mb=want, attested=short)
    assert (v.verdict, v.reason) == ("short", "mem-firmware")


def test_mem_total_is_only_judged_without_a_firmware_map(settings) -> None:
    settings.VALI_GUEST_MEM_TOTAL_SLACK_MIB = 256
    want = 4096
    # A firmware map that says 4 GiB wins over a low MemTotal.
    full = Attested(1, want * MIB, 1, 0)
    assert judge(cpu_count=1, memory_mb=want, attested=full).verdict == "ok"
    floor = guest_resources.mem_total_floor_kib(want * MIB)
    assert judge(cpu_count=1, memory_mb=want, attested=Attested(1, 0, floor, 0)).verdict == "ok"
    low = Attested(1, 0, floor - 1, 0)
    assert judge(cpu_count=1, memory_mb=want, attested=low).reason == "mem-total"


def test_the_mem_total_floor_follows_the_kernels_reservations(settings) -> None:
    """2 % struct pages + the SEV swiotlb (6 %, capped at 1 GiB) + slack:
    ~86 % of a small, ~97 % of a 4xlarge — not one loose ratio that would
    let a 4xlarge lose 19 GiB."""
    settings.VALI_GUEST_MEM_TOTAL_SLACK_MIB = 256
    small, x4 = 4096 * MIB, 131072 * MIB
    assert 0.85 < guest_resources.mem_total_floor_kib(small) / small < 0.87
    assert 0.96 < guest_resources.mem_total_floor_kib(x4) / x4 < 0.98


def test_unaccepted_ram_only_counts_under_eager_acceptance(settings) -> None:
    """Lazily accepted RAM is normal (OVMF leaves everything above 4 GiB
    to the kernel). With `accept_memory=eager` the guest accepted it all
    at boot — RAM still unaccepted is RAM the host never backed."""
    settings.VALI_GUEST_MEM_FIRMWARE_SLACK_MIB = 64
    assert judge(cpu_count=4, memory_mb=16384, attested=HONEST_LARGE).verdict == "ok"
    v = judge(cpu_count=4, memory_mb=16384, attested=HONEST_LARGE, eager=True)
    assert (v.verdict, v.reason) == ("short", "mem-unaccepted")
    accepted = Attested(4, 16 * GIB - 12 * MIB, 15_337_812, 2 * MIB)
    assert judge(cpu_count=4, memory_mb=16384, attested=accepted, eager=True).verdict == "ok"


def test_fewer_cpus_online_is_short_and_reasons_combine() -> None:
    v = judge(cpu_count=4, memory_mb=16384, attested=MEDIUM_SIZED)
    assert (v.verdict, v.reason) == ("short", "vcpus+mem-firmware")
    v = judge(cpu_count=4, memory_mb=16384, attested=Attested(3, 16 * GIB, 1, 0))
    assert v.reason == "vcpus"


def test_more_than_the_flavor_is_not_a_finding() -> None:
    assert judge(cpu_count=2, memory_mb=8192, attested=HONEST_LARGE).verdict == "ok"


# ─── ingest ──────────────────────────────────────────────────────────


def test_a_launch_that_did_not_ask_is_not_judged(fake) -> None:
    _pin(attests=False)
    _binding()
    row = _attest(fake, None)
    assert row.resource_verdict == ""
    assert row.vcpus_online is None
    assert _window_covered() > 0
    assert not GuestResourceShortfall.objects.exists()


def test_under_enforce_a_vm_must_prove_its_size_to_be_paid(fake, settings) -> None:
    """ENFORCE pays only `ok`: a VM launched before the attestation was
    switched on is alive but unproven — no coverage until relaunched."""
    settings.VALI_GUEST_RESOURCES_ENFORCE = True
    _pin(attests=False)
    _binding()
    _attest(fake, None)
    assert _window_covered() == 0


def test_an_honest_v3_sample_records_its_figures(fake) -> None:
    _pin()
    _binding()
    row = _attest(fake, HONEST_LARGE)
    assert row.resource_verdict == "ok"
    assert (
        row.vcpus_online,
        row.mem_firmware_kib,
        row.mem_total_kib,
        row.mem_unaccepted_kib,
    ) == (4, HONEST_LARGE.mem_firmware_kib, HONEST_LARGE.mem_total_kib, 11 * GIB)
    assert not GuestResourceShortfall.objects.exists()


def test_a_short_vm_leaves_evidence_against_the_miner(fake) -> None:
    """THE attack: the miner runs a `large` with a `medium`'s RAM."""
    _pin()
    _binding()
    row = _attest(fake, MEDIUM_SIZED)
    assert row.resource_verdict == "short"
    ev = GuestResourceShortfall.objects.get()
    assert (ev.vm_id, ev.node_id_hex, ev.flavor) == (VM, NODE_ID, "large")
    assert (ev.want_vcpus, ev.want_memory_mb) == (4, 16384)
    assert (ev.vcpus_online, ev.reason, ev.samples) == (2, "vcpus+mem-firmware", 1)
    assert ev.last_body_digest == row.body_digest
    _attest(fake, MEDIUM_SIZED, seq=2)
    ev.refresh_from_db()
    assert ev.samples == 2
    assert VM in guest_resources.flagged()


def test_the_launchs_flavor_is_judged_not_the_bindings(fake) -> None:
    """A resize rewrites the binding before the new guest boots: the old
    guest's samples are judged against the flavor its own launch was
    measured for, so they are not mistaken for a shortfall."""
    _pin(flavor="medium")
    _binding("large")
    assert _attest(fake, MEDIUM_SIZED).resource_verdict == "ok"


def test_a_replayed_short_sample_is_not_a_second_finding(fake) -> None:
    _pin()
    _binding()
    _attest(fake, MEDIUM_SIZED)
    _, created = vm_liveness.ingest_live_attestation(envelope=b"\x01")
    assert created is False
    assert GuestResourceShortfall.objects.get().samples == 1


def test_observe_mode_still_credits_a_short_sample(fake, settings) -> None:
    settings.VALI_GUEST_RESOURCES_ENFORCE = False
    settings.VALI_UPTIME_LIVENESS_COVERAGE_S = 900
    _pin()
    _binding()
    _attest(fake, MEDIUM_SIZED)
    assert _window_covered() == 600


def test_enforce_withholds_coverage_for_a_short_vm_only(fake, settings) -> None:
    settings.VALI_GUEST_RESOURCES_ENFORCE = True
    settings.VALI_UPTIME_LIVENESS_COVERAGE_S = 900
    _pin()
    _binding()
    _attest(fake, MEDIUM_SIZED)
    assert _window_covered() == 0, "a short VM must earn nothing under ENFORCE"
    # The guest comes back at its real size: credited again from then on.
    fake.verified_at_unix = NOW + 200
    _attest(fake, HONEST_LARGE, seq=2)
    assert vm_liveness.covered_seconds(vm_id=VM, start_unix=NOW, end_unix=NOW + 200) == 200


def test_a_launch_that_asked_but_got_no_resources_is_withheld(fake, settings) -> None:
    """An image too old to attest, launched with the token: alive, but
    nothing to pay on once ENFORCE is armed. Not the miner's doing (the
    image is measured), so no evidence."""
    settings.VALI_GUEST_RESOURCES_ENFORCE = True
    _pin(attests=True)
    _binding()
    row = _attest(fake, None)
    assert row.resource_verdict == "unattested"
    assert _window_covered() == 0
    assert not GuestResourceShortfall.objects.exists()


OLD_LAUNCH = "55" * 48


def test_a_bad_sample_is_a_barrier_not_just_a_gap(fake, settings) -> None:
    """Alternating short / honest samples must not keep full coverage: the
    honest sample after a short one vouches back only to the short one."""
    settings.VALI_GUEST_RESOURCES_ENFORCE = True
    settings.VALI_UPTIME_LIVENESS_COVERAGE_S = 900
    _pin()
    _binding()
    fake.verified_at_unix = NOW - 300
    _attest(fake, MEDIUM_SIZED)
    fake.verified_at_unix = NOW
    _attest(fake, HONEST_LARGE, seq=2)
    covered = vm_liveness.covered_seconds(vm_id=VM, start_unix=NOW - 900, end_unix=NOW)
    assert covered == 300, "only the time after the short sample is creditable"


def test_unattributable_custody_blames_nobody(fake) -> None:
    from apps.scheduler.models import VmBillingAssignment

    _pin()
    _binding()
    VmBillingAssignment.objects.create(vm_id=VM, node_id_hex="", effective_from_unix=NOW - 60)
    _attest(fake, MEDIUM_SIZED)
    assert GuestResourceShortfall.objects.get().node_id_hex == ""


def test_enforce_without_the_uptime_gate_is_reported_not_silent(fake, settings) -> None:
    """ENFORCE acts through the uptime-coverage meter; without the gate it
    withholds nothing — say so instead of looking armed."""
    from apps.synthetic import checks

    settings.VALI_GUEST_RESOURCES_ENFORCE = True
    settings.VALI_UPTIME_REQUIRE_LIVENESS_ATTESTATION = False
    assert guest_resources.enforce() is False
    _pin()
    _binding()
    _attest(fake, HONEST_LARGE)
    result = checks.check_guest_resources()
    assert result.ok is False
    assert "VALI_UPTIME_REQUIRE_LIVENESS_ATTESTATION" in result.detail
    assert result.gauges["hippius_synthetic_guest_resources_enforced"] == 0.0


def test_evidence_names_the_miner_credited_at_that_instant(fake) -> None:
    """After a §25 cutover the body's `node_id` still names the launch
    node (the measured cmdline is replayed verbatim); the finding is the
    destination's, the miner vali credits at that instant."""
    from apps.scheduler.models import VmBillingAssignment

    dest = "dd" * 32
    _pin()
    _binding()
    VmBillingAssignment.objects.create(vm_id=VM, node_id_hex=dest, effective_from_unix=NOW - 60)
    _attest(fake, MEDIUM_SIZED)
    assert GuestResourceShortfall.objects.get().node_id_hex == dest


def test_a_guest_of_a_superseded_launch_is_found_out(fake, settings) -> None:
    """The resize replay: vali relaunched the VM at `large` (newest pin);
    the miner boots the PRE-resize launch again with its still-valid
    ticket — a measurement vali pinned before, without the resource token.
    Its fresh keepalives are refused coverage and leave evidence, whatever
    they carry."""
    settings.VALI_GUEST_RESOURCES_ENFORCE = True
    _pin(OLD_LAUNCH, flavor="medium", attests=False, at=NOW - 7200)
    _pin(MEASUREMENT, flavor="large", at=NOW - 600)
    _binding("large")
    row = _attest(fake, None, measurement=OLD_LAUNCH)
    assert row.resource_verdict == "superseded"
    assert _window_covered() == 0
    ev = GuestResourceShortfall.objects.get()
    # Filed under what the VM is sold as now.
    assert (ev.reason, ev.flavor, ev.vcpus_online) == ("superseded-launch", "large", None)
    assert VM in guest_resources.flagged()


def test_an_old_launchs_sample_from_before_the_relaunch_is_not_superseded(fake, settings) -> None:
    """An attestation the old guest took before vali's relaunch was
    accepted (in flight while it was stopped, or a KBS clock ahead of
    vali's within the skew bound) is honest history."""
    settings.VALI_GUEST_SUPERSEDED_GRACE_S = 300
    _pin(OLD_LAUNCH, flavor="large", at=NOW - 7200)
    _pin(MEASUREMENT, flavor="large", at=NOW - 200)  # accepted at NOW - 190
    _binding("large")
    row = _attest(fake, HONEST_LARGE, measurement=OLD_LAUNCH)
    assert row.resource_verdict == "ok"


def test_a_relaunch_that_failed_after_its_pin_supersedes_nothing(fake, settings) -> None:
    """vali pinned a relaunch, then the ticket/register/dispatch failed
    while the previous domain still ran: that guest is still the VM."""
    settings.VALI_GUEST_RESOURCES_ENFORCE = True
    _pin(OLD_LAUNCH, flavor="large", at=NOW - 7200)
    _pin(MEASUREMENT, flavor="large", at=NOW - 3600, launched=False)
    _binding("large")
    row = _attest(fake, HONEST_LARGE, measurement=OLD_LAUNCH)
    assert row.resource_verdict == "ok"
    assert _window_covered() == 600


def test_an_unknown_launch_flavor_never_drops_the_sample(fake) -> None:
    _pin(flavor="")
    _binding("legacy-standard")
    row = _attest(fake, MEDIUM_SIZED)
    assert row.resource_verdict == ""
    assert VmLiveAttestation.objects.count() == 1


def test_a_ledger_row_without_a_flavor_falls_back_to_the_binding(fake) -> None:
    _pin(flavor="")
    _binding("large")
    assert _attest(fake, MEDIUM_SIZED).resource_verdict == "short"


def test_out_of_range_figures_are_refused_not_stored(fake) -> None:
    _pin()
    _binding()
    with pytest.raises(vm_liveness.LiveAttestationRefused) as exc:
        _attest(fake, Attested(2**32 - 1, 2**64 - 1, 1, 0))
    assert exc.value.category == "out-of-range"


def test_the_flag_expires(fake, settings) -> None:
    settings.VALI_GUEST_RESOURCES_FLAG_S = 3600
    _pin()
    _binding()
    _attest(fake, MEDIUM_SIZED)
    GuestResourceShortfall.objects.update(
        last_seen_at=datetime.now(tz=UTC) - timedelta(seconds=3601)
    )
    assert guest_resources.flagged() == {}


# ─── operator surfaces ───────────────────────────────────────────────


def test_the_synthetic_check_fails_while_a_vm_is_short(fake, settings) -> None:
    from apps.synthetic import checks

    assert checks.check_guest_resources in checks.LIGHT_CHECKS
    _pin()
    _binding()
    _attest(fake, HONEST_LARGE)
    ok = checks.check_guest_resources()
    assert ok.ok is True
    assert ok.gauges["hippius_synthetic_guest_resource_short_vms"] == 0.0

    settings.VALI_GUEST_RESOURCES_ENFORCE = True
    _attest(fake, MEDIUM_SIZED, seq=2)
    bad = checks.check_guest_resources()
    assert bad.ok is False
    assert bad.gauges["hippius_synthetic_guest_resource_short_vms"] == 1.0
    assert bad.gauges["hippius_synthetic_guest_resources_enforced"] == 1.0
    assert VM in bad.detail and "vcpus+mem-firmware" in bad.detail


def test_unproven_vms_are_a_readiness_gauge_then_a_failure(fake, settings) -> None:
    """A live VM whose latest sample is not `ok` (launched before the
    attestation was on): counted in observe mode, a failure under ENFORCE."""
    from apps.orchestration.tests.factories import make_vm
    from apps.synthetic import checks

    make_vm(VM)
    _pin(attests=False)
    _binding()
    _attest(fake, None)
    observe = checks.check_guest_resources()
    assert observe.ok is True
    assert observe.gauges["hippius_synthetic_guest_resources_unproven_vms"] == 1.0
    settings.VALI_GUEST_RESOURCES_ENFORCE = True
    armed = checks.check_guest_resources()
    assert armed.ok is False and "earning nothing" in armed.detail
