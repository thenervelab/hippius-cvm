"""`service.dispatchability` — the per-node predicate behind
`dispatchable_node_ids`.

Three things are proven here:

- the SET is unchanged AGAINST THE LEGACY IMPLEMENTATION: the body of
  `dispatchable_node_ids` / `attestor_covered_node_ids` as they were before
  the predicate refactor is frozen verbatim below (`_legacy_*`) and run on
  the same fixture — one node per gate, every gate — with the attestor gate
  off AND on. This is the actual equivalence proof; the fixture is built so
  that any single gate being dropped or reordered flips at least one node;
- the SET equals the predicate's own projection (internal consistency);
- the REASON names the first gate a node fails, in scheduler order.
"""

from __future__ import annotations

from datetime import datetime, timedelta

import pytest
from django.conf import settings
from django.test import override_settings
from django.utils import timezone

from apps.miners.models import MinerIdentity, MinerStatus
from apps.scheduler import service
from apps.scheduler.service import miner_liveness_timeout_s
from apps.telemetry import release_service
from apps.telemetry.models import HostAttestor, HostAttestorRelease, HostAttestorStatus

from .factories import make_dispatchable_identity, node_id

pytestmark = pytest.mark.django_db

MEAS_A = "a1" * 48
MEAS_B = "b2" * 48


# ─── LEGACY bodies, frozen verbatim from before the predicate refactor ──
# (`git show <pre-refactor>:vali/apps/scheduler/service.py` and
# `…/telemetry/release_service.py`). Do NOT "fix" these to match new code:
# their whole value is that they did not move.


def _legacy_is_real_chip_id(platform_id: str) -> bool:
    pid = (platform_id or "").strip()
    if len(pid) < 16 or len(pid) % 2:
        return False
    try:
        bytes.fromhex(pid)
    except ValueError:
        return False
    return True


def _legacy_attestor_covered_node_ids(*, now: datetime | None = None) -> frozenset[str]:
    now = now or timezone.now()
    desired_set = release_service._desired_measurement_set()
    if not desired_set:
        return frozenset()
    window = timedelta(seconds=release_service._liveness_window_seconds())
    live_cutoff = now - window
    covered: set[str] = set()
    for row in HostAttestor.objects.filter(status=HostAttestorStatus.ATTESTED.value):
        if row.measurement not in desired_set:
            continue
        if row.last_seen_at is not None and row.last_seen_at >= live_cutoff:
            covered.add(row.node_id.lower())
    return frozenset(covered)


def _legacy_dispatchable_node_ids() -> frozenset[str]:
    cutoff = timezone.now() - timedelta(seconds=miner_liveness_timeout_s())
    ok: set[str] = set()
    rows = MinerIdentity.objects.filter(
        status=MinerStatus.ACTIVE,
        chain_node_id__isnull=False,
        netbird_ip__isnull=False,
        last_seen_at__gte=cutoff,
    ).only("chain_node_id", "platform_id")
    for m in rows:
        if m.chain_node_id and _legacy_is_real_chip_id(m.platform_id):
            ok.add(m.chain_node_id.lower())
    if bool(getattr(settings, "VALI_HOST_ATTESTOR_GATE_ENFORCE", False)):
        ok &= _legacy_attestor_covered_node_ids()
    return frozenset(ok)


def _release(measurement: str = MEAS_A) -> None:
    HostAttestorRelease.objects.create(measurement=measurement, version="v1", is_active=True)


def _attestor(
    seed: int,
    *,
    measurement: str = MEAS_A,
    status: str = HostAttestorStatus.ATTESTED.value,
    last_seen_at=None,
    chip_suffix: str = "",
) -> HostAttestor:
    return HostAttestor.objects.create(
        chip_id=format(seed, "0128x") + chip_suffix,
        node_id=node_id(seed),
        signer_pubkey=bytes(32),
        measurement=measurement,
        cert_expiry_at=timezone.now() + timedelta(days=1),
        status=status,
        last_seen_at=timezone.now() if last_seen_at is None else last_seen_at,
    )


def _verdict(seed: int) -> service.Dispatchability:
    miner = MinerIdentity.objects.get(chain_node_id=node_id(seed))
    return service.dispatchability(miner, now=timezone.now(), attestor=service.attestor_gate())


def _seed_mixed_fleet() -> None:
    """Every single-gate failure + two healthy nodes."""
    make_dispatchable_identity(1)
    make_dispatchable_identity(2)
    m = make_dispatchable_identity(3)
    m.status = MinerStatus.QUARANTINED
    m.save(update_fields=["status"])
    m = make_dispatchable_identity(4)
    m.netbird_ip = None
    m.save(update_fields=["netbird_ip"])
    m = make_dispatchable_identity(5)
    m.last_seen_at = timezone.now() - timedelta(hours=1)
    m.save(update_fields=["last_seen_at"])
    m = make_dispatchable_identity(6)
    m.platform_id = "epyc-9255-label"
    m.save(update_fields=["platform_id"])
    m = make_dispatchable_identity(7)
    m.last_seen_at = None
    m.save(update_fields=["last_seen_at"])


def _set_from_predicate() -> frozenset[str]:
    now = timezone.now()
    gate = service.attestor_gate(now=now)
    return frozenset(
        m.chain_node_id.lower()
        for m in MinerIdentity.objects.all()
        if m.chain_node_id and service.dispatchability(m, now=now, attestor=gate).dispatchable
    )


UPPER_SEED = 0xABC


def _seed_all_gates_fleet() -> dict[str, str]:
    """One node per gate — registry AND attestor — plus edge cases the
    legacy code treated specially (upper-case `chain_node_id`, odd-length /
    short / whitespace-padded `platform_id`, several attestor rows). Returns
    {node_id: label} so a failing assertion names the node.
    """
    fleet: dict[str, str] = {}

    def add(seed: int, label: str, **fields) -> MinerIdentity:
        m = make_dispatchable_identity(seed)
        for k, v in fields.items():
            setattr(m, k, v)
        if fields:
            m.save(update_fields=list(fields))
        fleet[node_id(seed)] = label
        return m

    # healthy — both gates on → attestor rows below
    add(1, "healthy")
    # seed with letters, otherwise `.upper()` would be a no-op on "000…002"
    add(
        UPPER_SEED,
        "healthy-upper-case-id",
        chain_node_id=node_id(UPPER_SEED).upper(),
        platform_id="0abc" + "cd" * 15,  # factory's odd-length hex for this seed
    )
    add(3, "healthy-padded-chip", platform_id="  " + "cd" * 16 + " ")
    add(4, "healthy-several-attestor-rows")
    # registry gates
    add(10, "quarantined", status=MinerStatus.QUARANTINED)
    add(11, "unreachable", netbird_ip=None)
    add(12, "heartbeat-stale", last_seen_at=timezone.now() - timedelta(hours=1))
    add(13, "never-seen", last_seen_at=None)
    add(14, "platform-label", platform_id="epyc-9255-label")
    add(15, "platform-odd-hex", platform_id="abc")
    add(16, "platform-short-hex", platform_id="ab" * 7)
    add(17, "platform-empty", platform_id="")
    add(18, "quarantined-and-stale", status=MinerStatus.QUARANTINED, last_seen_at=None)
    # attestor gates (only bite when the gate is ON)
    add(20, "attestor-missing")
    add(21, "attestor-pending")
    add(22, "cert-expired")
    add(23, "measurement-stale")
    add(24, "attestor-stale")
    add(25, "attestor-never-beaconed")
    add(26, "attestor-pending-and-attested-stale")
    # not bridged: lives in the DB but has no node id — never in any set
    m = make_dispatchable_identity(30)
    m.chain_node_id = None
    m.save(update_fields=["chain_node_id"])

    _attestor(1)
    _attestor(UPPER_SEED)
    _attestor(3)
    _attestor(4, status=HostAttestorStatus.PENDING.value)
    _attestor(4, chip_suffix="ee")  # one covering row among several
    _attestor(10)  # covered but quarantined
    _attestor(12)  # covered but stale heartbeat
    _attestor(14)  # covered but label platform id
    _attestor(21, status=HostAttestorStatus.PENDING.value)
    _attestor(22, status=HostAttestorStatus.EXPIRED.value)
    _attestor(23, measurement=MEAS_B)
    _attestor(24, last_seen_at=timezone.now() - timedelta(hours=2))
    row = _attestor(25)
    row.last_seen_at = None
    row.save(update_fields=["last_seen_at"])
    _attestor(26, status=HostAttestorStatus.PENDING.value)
    _attestor(26, last_seen_at=timezone.now() - timedelta(hours=2), chip_suffix="ff")
    return fleet


HEALTHY_REGISTRY = frozenset(
    {node_id(s) for s in (1, UPPER_SEED, 3, 4)} | {node_id(s) for s in range(20, 27)}
)
HEALTHY_BOTH = frozenset(node_id(s) for s in (1, UPPER_SEED, 3, 4))


def _labels(fleet: dict[str, str], ids: frozenset[str]) -> set[str]:
    return {fleet[i] for i in ids}


# ─── set equals the LEGACY implementation ───────────────────────────


def test_legacy_equivalence_gate_off() -> None:
    fleet = _seed_all_gates_fleet()
    legacy = _legacy_dispatchable_node_ids()
    assert _labels(fleet, legacy) == _labels(fleet, HEALTHY_REGISTRY)  # fixture sanity
    assert service.dispatchable_node_ids() == legacy
    assert _set_from_predicate() == legacy


@override_settings(VALI_HOST_ATTESTOR_GATE_ENFORCE=True)
def test_legacy_equivalence_gate_on() -> None:
    fleet = _seed_all_gates_fleet()
    _release(MEAS_A)
    legacy = _legacy_dispatchable_node_ids()
    assert _labels(fleet, legacy) == _labels(fleet, HEALTHY_BOTH)  # fixture sanity
    assert service.dispatchable_node_ids() == legacy
    assert _set_from_predicate() == legacy


@override_settings(VALI_HOST_ATTESTOR_GATE_ENFORCE=True)
def test_legacy_equivalence_gate_on_no_release() -> None:
    _seed_all_gates_fleet()
    assert _legacy_dispatchable_node_ids() == frozenset()
    assert service.dispatchable_node_ids() == frozenset()
    assert _set_from_predicate() == frozenset()


@override_settings(VALI_HOST_ATTESTOR_GATE_ENFORCE=True)
def test_legacy_equivalence_two_desired_releases() -> None:
    _seed_all_gates_fleet()
    _release(MEAS_A)
    _release(MEAS_B)  # now measurement-stale (23) is covered too
    legacy = _legacy_dispatchable_node_ids()
    assert node_id(23) in legacy
    assert service.dispatchable_node_ids() == legacy


def test_fixture_flips_on_every_gate() -> None:
    """Meta-check: each not-schedulable node in the fixture is refused for
    a DIFFERENT first gate (or a deliberate duplicate), so a dropped or
    reordered gate cannot hide behind another one."""
    fleet = _seed_all_gates_fleet()
    _release(MEAS_A)
    with override_settings(VALI_HOST_ATTESTOR_GATE_ENFORCE=True):
        now = timezone.now()
        gate = service.attestor_gate(now=now)
        reasons = {
            fleet[m.chain_node_id.lower()]: service.dispatchability(
                m, now=now, attestor=gate
            ).reason
            for m in MinerIdentity.objects.exclude(chain_node_id__isnull=True)
        }
    assert reasons == {
        "healthy": None,
        "healthy-upper-case-id": None,
        "healthy-padded-chip": None,
        "healthy-several-attestor-rows": None,
        "quarantined": "quarantined",
        "unreachable": "unreachable",
        "heartbeat-stale": "heartbeat-stale",
        "never-seen": "heartbeat-stale",
        "platform-label": "platform-id-invalid",
        "platform-odd-hex": "platform-id-invalid",
        "platform-short-hex": "platform-id-invalid",
        "platform-empty": "platform-id-invalid",
        "quarantined-and-stale": "quarantined",
        "attestor-missing": "attestor-missing",
        "attestor-pending": "attestor-pending",
        "cert-expired": "cert-expired",
        "measurement-stale": "measurement-stale",
        "attestor-stale": "attestor-stale",
        "attestor-never-beaconed": "attestor-stale",
        "attestor-pending-and-attested-stale": "attestor-stale",
    }
    assert set(reasons.values()) - {None} == {
        "quarantined",
        "unreachable",
        "heartbeat-stale",
        "platform-id-invalid",
        "attestor-missing",
        "attestor-pending",
        "cert-expired",
        "measurement-stale",
        "attestor-stale",
    }  # every gate that a bridged node can fail (not-bridged/not-active tested apart)


# ─── set is unchanged ────────────────────────────────────────────────


def test_set_equals_predicate_gate_off() -> None:
    _seed_mixed_fleet()
    expected = frozenset({node_id(1), node_id(2)})
    assert service.dispatchable_node_ids() == expected
    assert _set_from_predicate() == expected


@override_settings(VALI_HOST_ATTESTOR_GATE_ENFORCE=True)
def test_set_equals_predicate_gate_on() -> None:
    _seed_mixed_fleet()
    _release(MEAS_A)
    _attestor(1)  # covered
    _attestor(2, measurement=MEAS_B)  # stale measurement → dropped
    _attestor(3)  # covered but quarantined → still dropped
    expected = frozenset({node_id(1)})
    assert service.dispatchable_node_ids() == expected
    assert _set_from_predicate() == expected


@override_settings(VALI_HOST_ATTESTOR_GATE_ENFORCE=True)
def test_set_equals_predicate_gate_on_no_release() -> None:
    _seed_mixed_fleet()
    _attestor(1)
    assert service.dispatchable_node_ids() == frozenset()
    assert _set_from_predicate() == frozenset()


# ─── reasons, in gate order ──────────────────────────────────────────


def test_healthy_node_has_no_reason() -> None:
    make_dispatchable_identity(1)
    assert _verdict(1) == service.Dispatchability(True, None)


def test_reason_quarantined() -> None:
    _seed_mixed_fleet()
    assert _verdict(3) == service.Dispatchability(False, "quarantined")


def test_reason_unreachable() -> None:
    _seed_mixed_fleet()
    assert _verdict(4) == service.Dispatchability(False, "unreachable")


def test_reason_heartbeat_stale_and_never_seen() -> None:
    _seed_mixed_fleet()
    assert _verdict(5) == service.Dispatchability(False, "heartbeat-stale")
    assert _verdict(7) == service.Dispatchability(False, "heartbeat-stale")


def test_reason_platform_id_invalid() -> None:
    _seed_mixed_fleet()
    assert _verdict(6) == service.Dispatchability(False, "platform-id-invalid")


def test_reason_not_bridged() -> None:
    m = make_dispatchable_identity(1)
    m.chain_node_id = None
    m.save(update_fields=["chain_node_id"])
    assert service.dispatchability(m) == service.Dispatchability(False, "not-bridged")


def test_first_failing_gate_wins() -> None:
    # Quarantined AND unreachable AND stale — the scheduler's first gate is
    # the local status, so that is the reason reported.
    m = make_dispatchable_identity(1)
    m.status = MinerStatus.QUARANTINED
    m.netbird_ip = None
    m.last_seen_at = None
    m.save()
    assert _verdict(1).reason == "quarantined"


def test_gate_off_ignores_attestor_state() -> None:
    make_dispatchable_identity(1)  # no attestor row at all
    assert _verdict(1) == service.Dispatchability(True, None)
    assert service.attestor_gate() is None


@override_settings(VALI_HOST_ATTESTOR_GATE_ENFORCE=True)
def test_gate_on_attestor_reasons() -> None:
    for seed in range(1, 7):
        make_dispatchable_identity(seed)
    # No release pinned yet → every node, whatever its rows, is release-unpinned.
    _attestor(1)
    assert _verdict(1) == service.Dispatchability(False, "release-unpinned")

    _release(MEAS_A)
    assert _verdict(1) == service.Dispatchability(True, None)
    assert _verdict(2) == service.Dispatchability(False, "attestor-missing")
    _attestor(3, status=HostAttestorStatus.PENDING.value)
    assert _verdict(3) == service.Dispatchability(False, "attestor-pending")
    _attestor(4, status=HostAttestorStatus.EXPIRED.value)
    assert _verdict(4) == service.Dispatchability(False, "cert-expired")
    _attestor(5, measurement=MEAS_B)
    assert _verdict(5) == service.Dispatchability(False, "measurement-stale")
    _attestor(6, last_seen_at=timezone.now() - timedelta(hours=2))
    assert _verdict(6) == service.Dispatchability(False, "attestor-stale")


@override_settings(VALI_HOST_ATTESTOR_GATE_ENFORCE=True)
def test_gate_on_several_rows_report_most_advanced() -> None:
    make_dispatchable_identity(1)
    _release(MEAS_A)
    # A pending row and a stale-beacon attested row for the same node (chip
    # re-key): the attested-but-stale row got further through the gate.
    _attestor(1, status=HostAttestorStatus.PENDING.value)
    _attestor(1, last_seen_at=timezone.now() - timedelta(hours=2), chip_suffix="ff")
    assert _verdict(1) == service.Dispatchability(False, "attestor-stale")
    # …and one covering row makes the node covered whatever else is there.
    _attestor(1, chip_suffix="ee")
    assert _verdict(1) == service.Dispatchability(True, None)


def test_covered_node_ids_is_projection_of_coverage_map() -> None:
    _release(MEAS_A)
    _attestor(1)
    _attestor(2, measurement=MEAS_B)
    _attestor(3, status=HostAttestorStatus.PENDING.value)
    coverage = release_service.attestor_coverage_by_node()
    assert coverage.release_pinned is True
    assert coverage.by_node == {
        node_id(1): None,
        node_id(2): "measurement-stale",
        node_id(3): "attestor-pending",
    }
    assert coverage.covered_node_ids() == frozenset({node_id(1)})
    assert release_service.attestor_covered_node_ids() == frozenset({node_id(1)})
    assert coverage.reason_for(node_id(99)) == "attestor-missing"
    assert coverage.reason_for(node_id(1).upper()) is None
