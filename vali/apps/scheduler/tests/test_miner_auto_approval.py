"""Automatic miner approval and revocation (`apps.scheduler.approval`).

With `VALI_MINER_APPROVAL_REQUIRED` and `VALI_MINER_AUTO_APPROVE` on, a
pending miner is approved by `auto_approve_pending` (`actor =
auto:attested-soak`) once its host-attestor is attested on its registered
CHIP_ID, it registered with an explicit snp_generation, its complete
heartbeats have soaked, it is not cordoned and the manual approval's own
refusals pass. A revoked miner is never approved automatically again.

Each condition has a test that starts from a miner the pass DOES approve
and breaks exactly that one condition.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from datetime import timedelta
from io import StringIO

import pytest
from django.core.management import CommandError, call_command
from django.utils import timezone

from apps.miners.models import MinerIdentity, MinerStatus, autoprovision_platform_id
from apps.scheduler import approval, service
from apps.scheduler.models import MinerCapacity, MinerCapacityAudit
from apps.telemetry.models import HostAttestor, HostAttestorRelease, HostAttestorStatus

from .factories import make_placement, make_vm, node_id

pytestmark = pytest.mark.django_db()

MEAS = "a1" * 48
SEED = 7


def _chip(seed: int) -> str:
    return format(0xC0FFEE00 + seed, "0128x")


def _eligible(seed: int = SEED, **row_over: object) -> MinerCapacity:
    """A pending miner every automatic-approval condition accepts: a
    registered identity (real CHIP_ID, genoa), an attested host-attestor on
    that chip on a pinned release, beaconing, and an hour-old soak of fresh
    complete heartbeats."""
    now = timezone.now()
    nid = node_id(seed)
    HostAttestorRelease.objects.get_or_create(
        measurement=MEAS, defaults={"version": "v1", "is_active": True}
    )
    MinerIdentity.objects.create(
        miner_id=f"miner-{seed}",
        pubkey_hex=f"{seed:02x}" + "ab" * 31,
        platform_id=_chip(seed),
        chain_node_id=nid,
        netbird_ip=f"100.64.0.{seed}",
        last_seen_at=now,
        status=MinerStatus.ACTIVE,
        snp_generation="genoa",
    )
    HostAttestor.objects.create(
        chip_id=_chip(seed),
        node_id=nid,
        signer_pubkey=bytes(32),
        measurement=MEAS,
        cert_expiry_at=now + timedelta(days=1),
        status=HostAttestorStatus.ATTESTED.value,
        last_seen_at=now,
    )
    fields: dict[str, object] = dict(
        miner_node_id=nid,
        status="active",
        capacity_slots=8,
        observed_epoch=10,
        data_epoch=10,
        refreshed_at=now,
        declared_cpu_budget=60,
        declared_at=now,
        reported_memory_available_mib=250_000,
        reported_at=now,
        reported_data_disk_total_gb=4000,
        disk_reported_at=now,
        approval_soak_since=now - timedelta(hours=1),
    )
    fields.update(row_over)
    return MinerCapacity.objects.create(**fields)


@pytest.fixture(autouse=True)
def _armed(settings) -> None:
    settings.VALI_MINER_APPROVAL_REQUIRED = True
    settings.VALI_MINER_AUTO_APPROVE = True
    settings.VALI_MINER_AUTO_APPROVE_SOAK_S = 1800


def _row(seed: int = SEED) -> MinerCapacity:
    return MinerCapacity.objects.get(miner_node_id=node_id(seed))


# ─── the happy path ──────────────────────────────────────────────────


def test_an_eligible_miner_is_approved_on_its_heartbeat_figures() -> None:
    _eligible()
    report = approval.auto_approve_pending()
    assert report.approved == (node_id(SEED),)
    row = _row()
    assert row.approved_at is not None
    assert row.approved_by == approval.AUTO_SOAK_ACTOR
    # No operator figure: the anchor is the heartbeat's own.
    assert (row.total_cpus, row.total_memory_mb, row.total_disk_gb) == (60, 250_000, 4000)
    # Never promoted: the anchor clamps what it proves, it grants nothing.
    assert row.trust_class == "earned"
    assert node_id(SEED) not in service.cordoned_node_ids()
    audits = MinerCapacityAudit.objects.filter(miner_node_id=node_id(SEED))
    assert {a.field for a in audits} == {
        "total_cpus",
        "total_memory_mb",
        "total_disk_gb",
        "approved_at",
        "approved_by",
    }
    assert {a.actor for a in audits} == {approval.AUTO_SOAK_ACTOR}


def test_the_pass_is_idempotent() -> None:
    _eligible()
    approval.auto_approve_pending()
    audits = MinerCapacityAudit.objects.count()
    assert approval.auto_approve_pending().approved == ()
    assert MinerCapacityAudit.objects.count() == audits


def test_an_anchor_already_on_the_row_is_the_declared_side() -> None:
    """An operator anchor seeded before the approval is never raised by
    the miner's own figure."""
    _eligible(total_cpus=32, total_memory_mb=128_000, total_disk_gb=2000)
    approval.auto_approve_pending()
    row = _row()
    assert (row.total_cpus, row.total_memory_mb, row.total_disk_gb) == (32, 128_000, 2000)


# ─── the switches ────────────────────────────────────────────────────


def test_off_by_default(settings) -> None:
    del settings.VALI_MINER_AUTO_APPROVE
    _eligible()
    # Off is a no-op, not a pass that judges every row.
    assert approval.auto_approve_pending() == approval.AutoApproveReport(approved=(), blocked={})
    assert _row().approved_at is None
    assert approval.auto_approval_blocker(_row(), now=timezone.now()) == approval.BLOCK_AUTO_OFF


def test_inert_while_approval_is_not_required(settings) -> None:
    settings.VALI_MINER_APPROVAL_REQUIRED = False
    _eligible()
    assert approval.auto_approve_pending().approved == ()
    assert _row().approved_at is None


# ─── each condition, broken alone ────────────────────────────────────


def _identity(seed: int = SEED) -> MinerIdentity:
    return MinerIdentity.objects.get(chain_node_id=node_id(seed))


def _attestor(seed: int = SEED) -> HostAttestor:
    return HostAttestor.objects.get(node_id=node_id(seed))


def _set(obj: object, **fields: object) -> None:
    type(obj).objects.filter(pk=obj.pk).update(**fields)  # type: ignore[attr-defined]


_BREAKS: dict[str, tuple[Callable[[], None], str]] = {
    "attestor pending": (
        lambda: _set(_attestor(), status=HostAttestorStatus.PENDING.value),
        "attestor-pending",
    ),
    "attestor expired": (
        lambda: _set(_attestor(), status=HostAttestorStatus.EXPIRED.value),
        "cert-expired",
    ),
    "no attestor": (lambda: _attestor().delete(), "attestor-missing"),
    "attestor on another chip": (
        lambda: _set(_attestor(), chip_id=_chip(99)),
        approval.BLOCK_ATTESTOR_CHIP_MISMATCH,
    ),
    "attestor beacon stale": (
        lambda: _set(_attestor(), last_seen_at=timezone.now() - timedelta(hours=2)),
        "attestor-stale",
    ),
    "attestor on an undesired measurement": (
        lambda: _set(_attestor(), measurement="b2" * 48),
        "measurement-stale",
    ),
    "no release pinned": (
        lambda: HostAttestorRelease.objects.all().delete(),
        "release-unpinned",
    ),
    "never registered": (lambda: _identity().delete(), approval.BLOCK_NOT_REGISTERED),
    # The same chip under a second identity (a Turin-length prefix of this
    # Genoa-length CHIP_ID — `platform_id` is unique only as a string).
    "chip registered to another miner too": (
        lambda: MinerIdentity.objects.create(
            miner_id="miner-other",
            pubkey_hex="ee" * 32,
            platform_id=_chip(SEED)[:16],
            snp_generation="turin",
        ),
        approval.BLOCK_CHIP_SHARED,
    ),
    "identity quarantined": (
        lambda: _set(_identity(), status=MinerStatus.QUARANTINED),
        approval.BLOCK_IDENTITY_QUARANTINED,
    ),
    "auto-provision placeholder": (
        lambda: _set(_identity(), platform_id=autoprovision_platform_id(node_id(SEED))),
        approval.BLOCK_PLATFORM_PLACEHOLDER,
    ),
    "no snp_generation": (
        lambda: _set(_identity(), snp_generation=""),
        approval.BLOCK_SNP_GENERATION_UNSET,
    ),
    "no soak": (
        lambda: _set(_row(), approval_soak_since=None),
        approval.BLOCK_SOAK_NOT_STARTED,
    ),
    "soak too short": (
        lambda: _set(_row(), approval_soak_since=timezone.now() - timedelta(seconds=1700)),
        approval.BLOCK_SOAKING,
    ),
    "cpu figure stale": (
        lambda: _set(_row(), declared_at=timezone.now() - timedelta(hours=1)),
        approval.BLOCK_NOT_MEASURED,
    ),
    "memory figure stale": (
        lambda: _set(_row(), reported_at=timezone.now() - timedelta(hours=1)),
        approval.BLOCK_NOT_MEASURED,
    ),
    "disk figure stale": (
        lambda: _set(_row(), disk_reported_at=timezone.now() - timedelta(hours=1)),
        approval.BLOCK_NOT_MEASURED,
    ),
    "no disk figure": (
        lambda: _set(_row(), reported_data_disk_total_gb=None),
        approval.BLOCK_NOT_MEASURED,
    ),
    "cpu figure out of range": (
        lambda: _set(_row(), declared_cpu_budget=4096),
        "invalid",
    ),
    "memory figure out of range": (
        lambda: _set(_row(), reported_memory_available_mib=512),
        "invalid",
    ),
}


@pytest.mark.parametrize("name", sorted(_BREAKS))
def test_each_condition_blocks_alone(name: str) -> None:
    _eligible()
    breaker, blocker = _BREAKS[name]
    breaker()
    report = approval.auto_approve_pending()
    assert report.approved == ()
    assert report.blocked == {node_id(SEED): blocker}
    row = _row()
    assert row.approved_at is None
    assert row.total_cpus is None
    assert not MinerCapacityAudit.objects.filter(miner_node_id=node_id(SEED)).exists()


def test_the_soak_boundary_is_inclusive() -> None:
    now = timezone.now()
    _eligible(approval_soak_since=now - timedelta(seconds=1800))
    assert approval.auto_approval_blocker(_row(), now=now) is None


@pytest.mark.parametrize(
    ("ours", "other_platform_id"),
    [
        pytest.param(None, _chip(SEED)[:16], id="a-prefix-of-ours"),
        # Ours the Turin-length id (still this chip by the prefix rule).
        pytest.param(_chip(SEED)[:16], _chip(SEED), id="ours-is-a-prefix-of-it"),
        pytest.param(None, _chip(SEED).upper(), id="ours-in-another-case"),
    ],
)
@pytest.mark.parametrize("bound", [True, False], ids=["bridged-quarantined", "unbridged"])
def test_any_other_identity_naming_the_chip_blocks(
    ours: str | None, other_platform_id: str, bound: bool
) -> None:
    _eligible()
    if ours is not None:
        _set(_identity(), platform_id=ours, snp_generation="turin")
        assert approval.auto_approval_blocker(_row(), now=timezone.now()) is None
    MinerIdentity.objects.create(
        miner_id="miner-other",
        pubkey_hex="ee" * 32,
        platform_id=other_platform_id,
        chain_node_id=node_id(99) if bound else None,
        status=MinerStatus.QUARANTINED if bound else MinerStatus.ACTIVE,
    )
    assert approval.auto_approve_pending().blocked == {node_id(SEED): approval.BLOCK_CHIP_SHARED}


def test_an_unrelated_miner_does_not_share_the_chip() -> None:
    _eligible()
    _eligible(seed=8)
    assert set(approval.auto_approve_pending().approved) == {node_id(SEED), node_id(8)}


def test_one_failing_row_does_not_stall_the_others(monkeypatch) -> None:
    _eligible(seed=1)
    _eligible(seed=2)
    real = approval._approve_locked

    def flaky(row: MinerCapacity, **kw: object):
        if row.miner_node_id == node_id(1):
            raise ValueError("boom")
        return real(row, **kw)  # type: ignore[arg-type]

    monkeypatch.setattr(approval, "_approve_locked", flaky)
    report = approval.auto_approve_pending()
    assert report.approved == (node_id(2),)
    assert report.blocked == {node_id(1): approval.BLOCK_ERROR}


def test_a_cordoned_miner_is_not_a_candidate() -> None:
    _eligible(cordoned_at=timezone.now(), cordon_reason="disk")
    report = approval.auto_approve_pending()
    assert report.approved == ()
    assert _row().approved_at is None
    assert approval.auto_approval_blocker(_row(), now=timezone.now()) == approval.BLOCK_CORDONED


def test_below_what_vali_already_placed_is_refused() -> None:
    _eligible(declared_cpu_budget=2)
    make_placement(make_vm(), node_id(SEED), resource_class="large")
    report = approval.auto_approve_pending()
    assert report.blocked == {node_id(SEED): "below-committed"}
    assert _row().approved_at is None


def test_a_cordon_landing_under_the_lock_wins(monkeypatch) -> None:
    """The candidate list is read before the row lock; the conditions are
    re-judged on the locked row, so a cordon written in between wins."""
    _eligible()
    real = MinerCapacity.objects.select_for_update

    def cordon_then_lock(*a: object, **k: object):
        MinerCapacity.objects.filter(miner_node_id=node_id(SEED)).update(
            cordoned_at=timezone.now()
        )
        return real(*a, **k)

    monkeypatch.setattr(MinerCapacity.objects, "select_for_update", cordon_then_lock)
    assert approval.auto_approve_pending().blocked == {node_id(SEED): approval.BLOCK_CORDONED}
    assert _row().approved_at is None


# ─── the grandfathered fleet ─────────────────────────────────────────


def test_grandfathered_miners_are_untouched() -> None:
    then = timezone.now() - timedelta(days=30)
    _eligible(approved_at=then, approved_by="grandfathered", total_cpus=96)
    report = approval.auto_approve_pending()
    assert report == approval.AutoApproveReport(approved=(), blocked={})
    row = _row()
    assert (row.approved_at, row.approved_by, row.total_cpus) == (then, "grandfathered", 96)
    assert not MinerCapacityAudit.objects.exists()


# ─── revocation ──────────────────────────────────────────────────────


def test_revoke_puts_an_approved_miner_back_to_pending_and_audits_it() -> None:
    _eligible(approved_at=timezone.now(), approved_by="grandfathered")
    out = approval.revoke_approval(node_id(SEED), revoker="ops@x", reason="host swapped")
    assert out["revoked_by"] == "op:ops@x"
    row = _row()
    assert row.approved_at is None and row.approved_by == ""
    assert row.revoked_at is not None and row.revoked_by == "op:ops@x"
    assert service.cordoned_node_ids() == {node_id(SEED): approval.PENDING_APPROVAL_REASON}
    audits = MinerCapacityAudit.objects.filter(miner_node_id=node_id(SEED))
    assert {a.field for a in audits} == {"approved_at", "approved_by", "revoked_at", "revoked_by"}
    assert {(a.actor, a.reason) for a in audits} == {("op:ops@x", "host swapped")}


def test_revoke_ends_a_running_soak() -> None:
    _eligible()
    approval.revoke_approval(node_id(SEED), revoker="ops@x", reason="r")
    assert _row().approval_soak_since is None


def test_a_revoked_miner_reads_revoked_even_with_auto_approval_off(settings) -> None:
    settings.VALI_MINER_AUTO_APPROVE = False
    _eligible()
    approval.revoke_approval(node_id(SEED), revoker="ops@x", reason="r")
    assert approval.auto_approval_blocker(_row(), now=timezone.now()) == approval.BLOCK_REVOKED


def test_a_revoked_miner_is_never_approved_automatically() -> None:
    _eligible(approved_at=timezone.now(), approved_by=approval.AUTO_SOAK_ACTOR)
    approval.revoke_approval(node_id(SEED), revoker="ops@x", reason="r")
    for _ in range(3):
        assert approval.auto_approve_pending().approved == ()
    assert _row().approved_at is None
    assert approval.auto_approval_blocker(_row(), now=timezone.now()) == approval.BLOCK_REVOKED


def test_revoking_a_pending_miner_keeps_it_from_auto_approval() -> None:
    _eligible()
    approval.revoke_approval(node_id(SEED), revoker="ops@x", reason="not this one")
    assert approval.auto_approve_pending().approved == ()
    assert _row().approved_at is None


def test_only_an_operator_approval_clears_a_revocation() -> None:
    _eligible(approved_at=timezone.now(), approved_by="grandfathered")
    approval.revoke_approval(node_id(SEED), revoker="ops@x", reason="r")
    approval.approve_miner(
        node_id(SEED), cpus=64, memory_mb=256_000, disk_gb=None, approver="ops@x", reason="ok"
    )
    row = _row()
    assert row.approved_by == "op:ops@x"
    assert row.revoked_at is None and row.revoked_by == ""


def test_revoke_twice_is_refused() -> None:
    _eligible(approved_at=timezone.now(), approved_by="grandfathered")
    approval.revoke_approval(node_id(SEED), revoker="ops@x", reason="r")
    with pytest.raises(approval.ApprovalRefused) as exc:
        approval.revoke_approval(node_id(SEED), revoker="ops@x", reason="r")
    assert exc.value.code == "already-revoked"


@pytest.mark.parametrize(
    ("seed", "revoker", "reason", "code"),
    [(SEED, "", "r", "invalid"), (SEED, "ops", "", "invalid"), (99, "ops", "r", "not-found")],
)
def test_revoke_refusals_write_nothing(seed: int, revoker: str, reason: str, code: str) -> None:
    _eligible(approved_at=timezone.now(), approved_by="grandfathered")
    with pytest.raises(approval.ApprovalRefused) as exc:
        approval.revoke_approval(node_id(seed), revoker=revoker, reason=reason)
    assert exc.value.code == code
    assert _row().approved_at is not None
    assert not MinerCapacityAudit.objects.exists()


# ─── the heartbeat soak ──────────────────────────────────────────────


def _beat(*, complete: bool = True, at=None) -> None:
    """One accepted heartbeat as the ingest applies it: the soak first,
    then the v3 / v4 stamps."""
    now = at or timezone.now()
    approval.record_heartbeat_soak(node_id(SEED), complete=complete, now=now)
    if complete:
        MinerCapacity.objects.filter(miner_node_id=node_id(SEED)).update(
            declared_at=now, disk_reported_at=now, reported_at=now
        )


def test_a_soak_starts_runs_and_breaks_on_a_gap() -> None:
    t0 = timezone.now() - timedelta(hours=2)
    _eligible(approval_soak_since=None, declared_at=None, disk_reported_at=None)
    _beat(at=t0)
    assert _row().approval_soak_since == t0
    _beat(at=t0 + timedelta(seconds=60))
    assert _row().approval_soak_since == t0  # unbroken
    # A gap past the liveness timeout (180 s) starts a new run.
    late = t0 + timedelta(seconds=60 + 181)
    _beat(at=late)
    assert _row().approval_soak_since == late


@pytest.mark.parametrize("stamp", ["declared_at", "disk_reported_at"])
def test_either_figure_going_quiet_breaks_the_soak(stamp: str) -> None:
    """The run is of COMPLETE heartbeats: a gap in the v3 capacity or in
    the v4 disk figures alone is a gap."""
    t0 = timezone.now() - timedelta(hours=2)
    _eligible(approval_soak_since=None, declared_at=None, disk_reported_at=None)
    _beat(at=t0)
    later = t0 + timedelta(seconds=60)
    MinerCapacity.objects.filter(miner_node_id=node_id(SEED)).update(
        **{stamp: t0 - timedelta(hours=1)}
    )
    _beat(at=later)
    assert _row().approval_soak_since == later


def test_an_incomplete_heartbeat_ends_the_soak() -> None:
    _eligible()
    _beat(complete=False)
    assert _row().approval_soak_since is None


def test_the_soak_never_writes_an_approved_row() -> None:
    _eligible(approved_at=timezone.now(), approved_by="grandfathered", approval_soak_since=None)
    _beat()
    assert _row().approval_soak_since is None
    _set(_row(), approval_soak_since=timezone.now())
    _beat(complete=False)
    assert _row().approval_soak_since is not None


# ─── the readout + the command ───────────────────────────────────────


def test_the_readout_names_the_blocker() -> None:
    _eligible(approval_soak_since=None)
    status = approval.approval_status(node_id(SEED))
    assert status is not None
    assert status["auto_approve"] is True
    assert status["auto_approval_blocker"] == approval.BLOCK_SOAK_NOT_STARTED
    assert status["revoked_at"] is None


def test_command_revoke_and_list_pending() -> None:
    _eligible(approved_at=timezone.now(), approved_by="grandfathered")
    out = StringIO()
    call_command(
        "vali_approve_miner", "--node-id", node_id(SEED), "--revoke", "--by", "ops", "--reason",
        "r", stdout=out,
    )
    assert json.loads(out.getvalue().strip().splitlines()[-1])["revoked_by"] == "op:ops"
    listing = StringIO()
    call_command("vali_approve_miner", "--list-pending", stdout=listing)
    assert f"{node_id(SEED)} " in listing.getvalue()
    assert "auto=revoked" in listing.getvalue()
    with pytest.raises(CommandError, match="takes no --cpus"):
        call_command(
            "vali_approve_miner", "--node-id", node_id(SEED), "--revoke", "--cpus", "8",
            "--by", "ops", "--reason", "r",
        )
    with pytest.raises(CommandError, match="already-revoked"):
        call_command(
            "vali_approve_miner", "--node-id", node_id(SEED), "--revoke", "--by", "ops",
            "--reason", "r",
        )


def test_reeval_runs_the_automatic_approval() -> None:
    from apps.scheduler.management.commands import vali_scheduler_reeval

    _eligible()
    vali_scheduler_reeval.auto_approval()
    assert _row().approved_by == approval.AUTO_SOAK_ACTOR


# ─── read-only evaluation (--auto-evaluate) ──────────────────────────


def _verdict(seed: int = SEED) -> dict:
    (v,) = [v for v in approval.evaluate_auto_approval() if v["node_id"] == node_id(seed)]
    return v


def _terms(cpus: tuple, memory: tuple, disk: tuple) -> dict:
    def term(t: tuple) -> dict:
        return dict(zip(("declared", "heartbeat", "result", "binding"), t, strict=True))

    return {"ok": True, "terms": {"cpus": term(cpus), "memory_mb": term(memory),
                                  "disk_gb": term(disk)}}


def _grandfathered(seed: int = SEED, **over: object) -> MinerCapacity:
    """A miner as the live fleet holds it: approved by migration 0021, an
    operator anchor, and NO soak — approved rows never soak."""
    fields: dict[str, object] = dict(
        approved_at=timezone.now() - timedelta(days=30),
        approved_by="grandfathered",
        approval_soak_since=None,
        total_cpus=96,
        total_memory_mb=300_000,
        total_disk_gb=5000,
    )
    fields.update(over)
    return _eligible(seed, **fields)


def test_evaluate_an_eligible_miner_with_its_anchor() -> None:
    _eligible(total_cpus=32)
    v = _verdict()
    assert v["state"] == "pending" and v["auto_approve_on"] is True
    assert v["would_approve"] is True and v["would_approve_if_pending"] is True
    assert v["failed"] == []
    assert v["anchor"] == _terms(
        (32, 60, 32, "declared"), (None, 250_000, 250_000, "measured"),
        (None, 4000, 4000, "measured"),
    )
    assert v["anchor_as_new"] == {
        "ok": True,
        "terms": {
            "cpus": {"heartbeat": 60, "result": 60},
            "memory_mb": {
                "heartbeat": 250_000,
                "committed_added": 0,
                "placements": 0,
                "cap": None,
                "cap_source": None,
                "result": 250_000,
            },
            "disk_gb": {"heartbeat": 4000, "result": 4000},
        },
    }
    # The decision and the evaluation are the same computation.
    assert approval.auto_approve_pending().approved == (node_id(SEED),)


@pytest.mark.parametrize("switch_on", [True, False], ids=["switch-on", "switch-off"])
def test_evaluate_a_grandfathered_miner_as_the_fleet_holds_it(settings, switch_on: bool) -> None:
    """The production check: switch off (it runs before the flip), no soak.
    The verdict on the miner itself must still be computable."""
    settings.VALI_MINER_AUTO_APPROVE = switch_on
    _grandfathered()
    v = _verdict()
    assert v["state"] == "approved" and v["approved_by"] == "grandfathered"
    assert v["would_approve"] is False
    assert v["would_approve_if_pending"] is True
    expected_failed = ["pending"] if switch_on else ["pending", "auto-approve-on"]
    assert v["failed"] == expected_failed
    (soak,) = [c for c in v["conditions"] if c["name"] == "soak"]
    assert soak["passed"] is None
    assert v["current_anchor"] == {"cpus": 96, "memory_mb": 300_000, "disk_gb": 5000}
    # The real pass keeps the operator anchor as the declared side …
    assert v["anchor"]["terms"]["cpus"] == {
        "declared": 96, "heartbeat": 60, "result": 60, "binding": "measured",
    }
    assert v["anchor"]["terms"]["disk_gb"]["declared"] == 5000
    # … a new miner on this hardware gets the heartbeat alone.
    assert v["anchor_as_new"]["terms"]["disk_gb"] == {"heartbeat": 4000, "result": 4000}


def test_evaluate_a_grandfathered_miner_still_fails_on_the_miner_itself(settings) -> None:
    settings.VALI_MINER_AUTO_APPROVE = False
    _grandfathered()
    _set(_attestor(), status=HostAttestorStatus.PENDING.value)
    _set(_row(), disk_reported_at=timezone.now() - timedelta(hours=1))
    v = _verdict()
    assert v["would_approve_if_pending"] is False
    assert v["failed"] == ["pending", "auto-approve-on", "attestor", "heartbeat-fresh"]
    (attestor,) = [c for c in v["conditions"] if c["name"] == "attestor"]
    assert attestor["blocker"] == "attestor-pending"


def test_evaluate_a_revoked_miner_through_the_real_path() -> None:
    """Revoked by the API path, then heartbeating: the soak stays cleared,
    the verdict on the miner itself does not depend on it."""
    _grandfathered()
    approval.revoke_approval(node_id(SEED), revoker="ops@x", reason="r")
    _beat()
    v = _verdict()
    assert v["state"] == "revoked"
    assert v["would_approve"] is False
    assert v["would_approve_if_pending"] is True
    assert v["failed"] == ["not-revoked"]


@pytest.mark.parametrize("name", sorted(_BREAKS))
def test_evaluate_names_the_broken_condition(name: str) -> None:
    _eligible()
    breaker, blocker = _BREAKS[name]
    breaker()
    v = _verdict()
    assert v["would_approve"] is False and v["would_approve_if_pending"] is False
    failing = [c for c in v["conditions"] if c["passed"] is False]
    if failing:
        # The first failure is the blocker the decision reports.
        assert failing[0]["blocker"] == blocker
    else:
        # Every condition holds; the approval's own check refuses.
        assert v["anchor"] == {"ok": False, "refusal": blocker, "detail": v["anchor"]["detail"]}


def test_evaluate_reports_every_failure_not_just_the_first() -> None:
    _eligible(approval_soak_since=None, disk_reported_at=None)
    _identity().delete()
    v = _verdict()
    assert v["failed"] == [
        "registered",
        "identity-active",
        "real-chip-id",
        "snp-generation",
        "attestor",
        "chip-not-shared",
        "soak",
        "heartbeat-fresh",
    ]


def test_evaluate_reports_a_raising_row_and_goes_on(monkeypatch) -> None:
    _eligible(seed=1)
    _eligible(seed=2)
    real = approval._evaluate_row

    def flaky(row: MinerCapacity, **kw: object) -> dict:
        if row.miner_node_id == node_id(1):
            raise RuntimeError("boom")
        return real(row, **kw)  # type: ignore[arg-type]

    monkeypatch.setattr(approval, "_evaluate_row", flaky)
    out = approval.evaluate_auto_approval()
    assert [(v["node_id"], v["state"]) for v in out] == [
        (node_id(1), "error"),
        (node_id(2), "pending"),
    ]
    text = StringIO()
    call_command("vali_approve_miner", "--auto-evaluate", stdout=text)
    assert f"{node_id(1)} state=error RuntimeError('boom')" in text.getvalue()


def test_evaluate_writes_nothing(settings) -> None:
    from django.db import connection
    from django.test.utils import CaptureQueriesContext

    settings.VALI_MINER_AUTO_APPROVE = False
    _eligible(seed=1)
    _grandfathered(seed=2)
    _eligible(seed=3, revoked_at=timezone.now(), revoked_by="op:x")
    before = list(MinerCapacity.objects.order_by("pk").values())
    with CaptureQueriesContext(connection) as ctx:
        out = StringIO()
        call_command("vali_approve_miner", "--auto-evaluate", "--json", stdout=out)
        call_command("vali_approve_miner", "--auto-evaluate", stdout=StringIO())
        approval.evaluate_auto_approval()
    writes = [
        q["sql"]
        for q in ctx.captured_queries
        if q["sql"].lstrip().upper().startswith(("INSERT", "UPDATE", "DELETE"))
    ]
    assert writes == []
    assert list(MinerCapacity.objects.order_by("pk").values()) == before
    assert not MinerCapacityAudit.objects.exists()
    lines = [json.loads(line) for line in out.getvalue().splitlines()]
    assert [(v["node_id"], v["state"], v["would_approve"]) for v in lines] == [
        (node_id(1), "pending", False),
        (node_id(2), "approved", False),
        (node_id(3), "revoked", False),
    ]


def test_evaluate_human_output() -> None:
    _eligible()
    _set(_attestor(), status=HostAttestorStatus.PENDING.value)
    out = StringIO()
    call_command("vali_approve_miner", "--auto-evaluate", stdout=out)
    text = out.getvalue()
    assert f"{node_id(SEED)} state=pending would_approve=False" in text
    assert "failed=attestor[attestor-pending]" in text
    assert "anchor_as_new: cpus=60(heartbeat=60)" in text
    assert "anchor:        cpus=60(declared=None heartbeat=60 binding=measured)" in text
    assert "1 miner(s) evaluated; auto-approve on=True; nothing written" in text


def test_json_needs_auto_evaluate() -> None:
    with pytest.raises(CommandError, match="--json goes with --auto-evaluate"):
        call_command("vali_approve_miner", "--node-id", node_id(SEED), "--show", "--json")


def test_a_revoked_miner_does_not_soak_again() -> None:
    _eligible()
    approval.revoke_approval(node_id(SEED), revoker="ops@x", reason="r")
    _beat()
    assert _row().approval_soak_since is None


def test_if_pending_is_judged_on_the_anchor_a_new_miner_gets() -> None:
    """A loaded grandfathered miner: its free RAM is net of the VM vali put
    there, and its retained anchor is below that VM. The real pass would
    refuse (`below-committed`); as a new miner its hardware — the free RAM
    plus what vali's VMs hold — still qualifies."""
    from apps.scheduler.approval import _committed

    _grandfathered(total_cpus=2)
    make_placement(make_vm(), node_id(SEED), resource_class="large")
    _n, committed_mb, _c = _committed(node_id(SEED))
    assert committed_mb > 0
    _set(_row(), reported_memory_available_mib=250_000 - committed_mb)
    v = _verdict()
    assert v["anchor"]["ok"] is False and v["anchor"]["refusal"] == "below-committed"
    assert v["anchor_as_new"]["terms"]["memory_mb"] == {
        "heartbeat": 250_000 - committed_mb,
        "committed_added": committed_mb,
        "placements": 1,
        # The grandfathered row's anchor (300 000) caps it; not reached here.
        "cap": 300_000,
        "cap_source": approval.CAP_ROW_ANCHOR,
        "result": 250_000,
    }
    assert v["would_approve_if_pending"] is True
    # `failed` alone explains the False of the real pass.
    assert v["failed"] == ["pending", "anchor"]
    text = StringIO()
    call_command("vali_approve_miner", "--auto-evaluate", stdout=text)
    assert "failed=pending[approved],anchor[below-committed]" in text.getvalue()


def test_an_as_new_anchor_out_of_range_fails_if_pending() -> None:
    _grandfathered()
    _set(_row(), declared_cpu_budget=4096)
    v = _verdict()
    assert v["anchor_as_new"]["ok"] is False and v["anchor_as_new"]["refusal"] == "invalid"
    assert v["would_approve_if_pending"] is False
    assert "anchor_as_new" in v["failed"]


# ─── the as-new memory cap (a grandfathered host) ────────────────────

M1_FREE, M1_COMMITTED, M1_DECLARED = 227_320, 73_728, 256_623


def _m1(monkeypatch, **over: object) -> None:
    """A busy host: 227 320 MiB free with 73 728 MiB of vali VMs on it,
    a 256 GB host — free + committed (301 048) overshoots it."""
    fields: dict[str, object] = dict(
        reported_memory_available_mib=M1_FREE,
        declared_memory_mb_budget=M1_DECLARED,
        total_memory_mb=None,
    )
    fields.update(over)
    _grandfathered(**fields)
    real = approval._committed
    monkeypatch.setattr(
        approval,
        "_committed",
        lambda nid: (3, M1_COMMITTED, 24) if nid == node_id(SEED) else real(nid),
    )


def test_as_new_memory_is_capped_at_the_heartbeat_budget(monkeypatch) -> None:
    _m1(monkeypatch)
    term = _verdict()["anchor_as_new"]["terms"]["memory_mb"]
    assert M1_FREE + M1_COMMITTED == 301_048
    assert term == {
        "heartbeat": M1_FREE,
        "committed_added": M1_COMMITTED,
        "placements": 3,
        "cap": M1_DECLARED,
        "cap_source": approval.CAP_HEARTBEAT_BUDGET,
        "result": M1_DECLARED,
    }


def test_as_new_memory_falls_back_to_the_row_anchor(monkeypatch) -> None:
    """A v3 heartbeat that could not read its budget (stored NULL)."""
    _m1(monkeypatch, declared_memory_mb_budget=None, total_memory_mb=M1_DECLARED)
    term = _verdict()["anchor_as_new"]["terms"]["memory_mb"]
    assert (term["cap"], term["cap_source"], term["result"]) == (
        M1_DECLARED,
        approval.CAP_ROW_ANCHOR,
        M1_DECLARED,
    )


def test_a_stale_budget_is_not_the_cap(monkeypatch) -> None:
    """The cap follows the same freshness as the figures it caps; a stale
    v3 stamp also leaves no cpu figure, so the anchor is not measured."""
    _m1(monkeypatch, declared_at=timezone.now() - timedelta(hours=1), total_memory_mb=M1_DECLARED)
    v = _verdict()
    assert v["anchor_as_new"]["refusal"] == "not-measured"
    from apps.scheduler.approval import _host_memory_cap

    assert _host_memory_cap(_row(), now=timezone.now()) == (M1_DECLARED, approval.CAP_ROW_ANCHOR)


def test_as_new_memory_under_the_cap_is_left_alone(monkeypatch) -> None:
    _m1(monkeypatch, declared_memory_mb_budget=400_000)
    term = _verdict()["anchor_as_new"]["terms"]["memory_mb"]
    assert term["result"] == M1_FREE + M1_COMMITTED


def test_with_no_host_figure_the_sum_is_shown_uncapped(monkeypatch) -> None:
    _m1(monkeypatch, declared_memory_mb_budget=None, total_memory_mb=None)
    term = _verdict()["anchor_as_new"]["terms"]["memory_mb"]
    assert (term["cap"], term["cap_source"], term["result"]) == (None, None, 301_048)


@pytest.mark.parametrize("retained", [None, 200_000, 256_623, 400_000])
def test_the_real_pass_memory_anchor_never_exceeds_the_heartbeat_figure(
    retained: int | None,
) -> None:
    """The real pass (no add-back) takes min(retained anchor, MemAvailable):
    never above what the host's kernel reports free, itself below its
    MemTotal, nor above an anchor the row already holds."""
    _eligible(reported_memory_available_mib=M1_FREE, total_memory_mb=retained)
    assert approval.auto_approve_pending().approved == (node_id(SEED),)
    got = _row().total_memory_mb
    assert got == min(x for x in (retained, M1_FREE) if x is not None)
    assert got <= M1_FREE
