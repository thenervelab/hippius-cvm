"""Compute requires storage (`apps.scheduler.storage_requirement`).

A compute family must also run a healthy Arion storage node, or its compute
nodes take no new VM and earn no weight; a family that loses its storage
keeps its rights for the grace; exempt families are never cut; off (the
default) changes nothing. The chain read itself is the Rust reader's
(`hippius-onchain-registry::fetch_storage_families`, tested there); here the
snapshot is built directly.
"""

from __future__ import annotations

import json
import subprocess
from dataclasses import replace
from datetime import timedelta
from io import StringIO
from typing import Any

import pytest
from django.core.management import CommandError, call_command
from django.utils import timezone

from apps.scheduler import service, storage_requirement
from apps.scheduler.chain import ChainReadUnavailable
from apps.scheduler.models import FamilyStorageState, MinerCapacity
from apps.scheduler.placement import PlacementError, decide_placement
from apps.scheduler.storage_requirement import (
    ComputeFamily,
    StorageChild,
    StorageSnapshot,
)

from .factories import make_miner, make_snapshot, node_id

pytestmark = pytest.mark.django_db()

BUCKET = 1000
STALE = 4


def h(byte: int) -> str:
    return f"{byte:02x}" * 32


FAMILY_A, FAMILY_B = h(0xA1), h(0xB1)


def storage(child: int, family: str = FAMILY_A, **over: Any) -> StorageChild:
    """An Arion child the pallet would pay: Active, fresh, quality, weight."""
    fields: dict[str, Any] = dict(
        child=h(child),
        reg_family=family,
        reg_node_id=h(child + 1),
        reg_status="active",
        node_weight=50_000,
        last_bucket=BUCKET,
        has_quality=True,
        uptime_permille=1000,
    )
    fields.update(over)
    return StorageChild(**fields)


def family(fam: str, compute_seeds: tuple[int, ...], *children: StorageChild) -> ComputeFamily:
    return ComputeFamily(
        family=fam,
        compute=tuple((node_id(s), h(0xC0 + s)) for s in compute_seeds),
        storage=tuple(children),
    )


def snapshot(*families: ComputeFamily) -> StorageSnapshot:
    return StorageSnapshot(
        block_hash="0x" + "ab" * 32,
        current_weight_bucket=BUCKET,
        stale_child_buckets=STALE,
        families=tuple(families),
    )


@pytest.fixture
def on(settings) -> None:
    settings.VALI_COMPUTE_REQUIRES_STORAGE = True
    settings.VALI_COMPUTE_STORAGE_EXEMPT_FAMILIES = []
    settings.VALI_COMPUTE_STORAGE_GRACE_S = 259200


# ─── what counts as healthy storage ──────────────────────────────────


_CHILD_CASES = {
    "paid by the pallet": (storage(0xD1), None),
    "no registration": (
        storage(0xD1, reg_family=None, reg_node_id=None, reg_status=None),
        storage_requirement.CHILD_NOT_REGISTERED,
    ),
    "another family's child": (
        storage(0xD1, reg_family=FAMILY_B),
        storage_requirement.CHILD_OTHER_FAMILY,
    ),
    "unbonding": (storage(0xD1, reg_status="unbonding"), storage_requirement.CHILD_NOT_ACTIVE),
    # The compute machine is its own storage alibi: by account …
    "the compute child itself": (storage(0xC1), storage_requirement.CHILD_COMPUTE),
    # … or registered with the compute node's id.
    "the compute node id": (
        storage(0xD1, reg_node_id=node_id(1)),
        storage_requirement.CHILD_COMPUTE,
    ),
    "stale by one bucket": (
        storage(0xD1, last_bucket=BUCKET - STALE - 1),
        storage_requirement.CHILD_STALE,
    ),
    "never reported": (storage(0xD1, last_bucket=0), storage_requirement.CHILD_STALE),
    "no quality on record": (
        storage(0xD1, has_quality=False, uptime_permille=None),
        storage_requirement.CHILD_NO_QUALITY,
    ),
    "zero weight": (storage(0xD1, node_weight=0), storage_requirement.CHILD_ZERO_WEIGHT),
}


@pytest.mark.parametrize("name", sorted(_CHILD_CASES))
def test_each_child_condition(name: str) -> None:
    child, reason = _CHILD_CASES[name]
    fam = family(FAMILY_A, (1,), child)
    assert (
        storage_requirement.judge_child(child, fam, current_bucket=BUCKET, stale_buckets=STALE)
        == reason
    )
    (verdict,) = storage_requirement.judge(snapshot(fam))
    assert verdict.healthy is (reason is None)


def test_freshness_is_inclusive_at_stale_child_buckets() -> None:
    child = storage(0xD1, last_bucket=BUCKET - STALE)
    fam = family(FAMILY_A, (1,), child)
    assert (
        storage_requirement.judge_child(child, fam, current_bucket=BUCKET, stale_buckets=STALE)
        is None
    )


def test_one_good_node_among_bad_ones_is_enough(settings) -> None:
    fam = family(FAMILY_A, (1,), storage(0xC1), storage(0xD1, node_weight=0), storage(0xD3))
    (verdict,) = storage_requirement.judge(snapshot(fam))
    assert (verdict.counted, verdict.healthy) == (1, True)
    settings.VALI_COMPUTE_STORAGE_MIN_NODES = 2
    assert storage_requirement.judge(snapshot(fam))[0].healthy is False


# ─── the decision ────────────────────────────────────────────────────


def test_a_family_without_storage_is_cut_at_once(on: None) -> None:
    storage_requirement.refresh(
        snapshot(family(FAMILY_A, (1, 2)), family(FAMILY_B, (3,), storage(0xD1, FAMILY_B)))
    )
    assert storage_requirement.denied_node_ids() == {
        node_id(1): "no-storage",
        node_id(2): "no-storage",
    }


@pytest.mark.parametrize(
    "child",
    [
        storage(0xD1, reg_status="unbonding"),  # Arion storage inactive
        storage(0xC1),  # the compute child as its own storage
    ],
    ids=["storage-inactive", "storage-is-the-compute-child"],
)
def test_storage_that_does_not_count_cuts_the_family(on: None, child: StorageChild) -> None:
    storage_requirement.refresh(snapshot(family(FAMILY_A, (1,), child)))
    assert storage_requirement.denied_node_ids() == {node_id(1): "no-storage"}


def test_healthy_storage_keeps_the_family(on: None) -> None:
    storage_requirement.refresh(snapshot(family(FAMILY_A, (1,), storage(0xD1))))
    assert storage_requirement.denied_node_ids() == {}


def test_a_family_that_loses_its_storage_keeps_its_rights_for_the_grace(on: None) -> None:
    t0 = timezone.now()
    storage_requirement.refresh(snapshot(family(FAMILY_A, (1,), storage(0xD1))), now=t0)
    lost = snapshot(family(FAMILY_A, (1,), storage(0xD1, node_weight=0)))
    storage_requirement.refresh(lost, now=t0 + timedelta(hours=1))
    row = FamilyStorageState.objects.get(family=FAMILY_A)
    assert row.has_storage is False and row.last_healthy_at == t0
    grace_end = t0 + timedelta(seconds=259200)
    assert storage_requirement.denied_node_ids(now=grace_end) == {}
    assert storage_requirement.denied_node_ids(now=grace_end + timedelta(seconds=1)) == {
        node_id(1): "no-storage"
    }
    # Storage back: rights back, grace clock reset.
    storage_requirement.refresh(
        snapshot(family(FAMILY_A, (1,), storage(0xD1))), now=grace_end + timedelta(hours=1)
    )
    assert storage_requirement.denied_node_ids(now=grace_end + timedelta(hours=2)) == {}


def test_the_grace_counts_from_the_last_healthy_read(on: None) -> None:
    t0 = timezone.now() - timedelta(days=10)
    healthy = snapshot(family(FAMILY_A, (1,), storage(0xD1)))
    storage_requirement.refresh(healthy, now=t0)
    t1 = t0 + timedelta(days=5)
    storage_requirement.refresh(healthy, now=t1)
    storage_requirement.refresh(snapshot(family(FAMILY_A, (1,))), now=t1 + timedelta(minutes=5))
    assert FamilyStorageState.objects.get(family=FAMILY_A).last_healthy_at == t1
    # 72 h after t1 — long past t0 + 72 h — it is still in grace.
    assert storage_requirement.denied_node_ids(now=t1 + timedelta(hours=71)) == {}


def test_a_failed_read_keeps_the_last_decision(on: None, monkeypatch) -> None:
    storage_requirement.refresh(snapshot(family(FAMILY_A, (1,))))

    def boom() -> StorageSnapshot:
        raise ChainReadUnavailable("rpc down")

    monkeypatch.setattr(storage_requirement, "read_storage_families", boom)
    with pytest.raises(ChainReadUnavailable):
        storage_requirement.refresh()
    assert storage_requirement.denied_node_ids() == {node_id(1): "no-storage"}


def test_a_family_gone_from_chain_is_forgotten(on: None) -> None:
    storage_requirement.refresh(snapshot(family(FAMILY_A, (1,)), family(FAMILY_B, (2,))))
    storage_requirement.refresh(snapshot(family(FAMILY_B, (2,))))
    assert list(FamilyStorageState.objects.values_list("family", flat=True)) == [FAMILY_B]
    assert storage_requirement.denied_node_ids() == {node_id(2): "no-storage"}


def test_an_exempt_family_is_never_cut(on: None, settings) -> None:
    storage_requirement.refresh(snapshot(family(FAMILY_A, (1,)), family(FAMILY_B, (2,))))
    settings.VALI_COMPUTE_STORAGE_EXEMPT_FAMILIES = [storage_requirement.ss58_encode(FAMILY_A)]
    assert storage_requirement.denied_node_ids() == {node_id(2): "no-storage"}


def test_an_invalid_exemption_makes_the_gate_inert(on: None, settings) -> None:
    storage_requirement.refresh(snapshot(family(FAMILY_A, (1,))))
    settings.VALI_COMPUTE_STORAGE_EXEMPT_FAMILIES = ["not-an-address"]
    assert storage_requirement.denied_node_ids() == {}


def test_ss58_round_trips_through_the_decoder() -> None:
    from apps.disktier.node_family import ss58_decode

    assert ss58_decode(storage_requirement.ss58_encode(FAMILY_A)).hex() == FAMILY_A


def test_flag_off_changes_nothing(settings) -> None:
    settings.VALI_COMPUTE_REQUIRES_STORAGE = True
    storage_requirement.refresh(snapshot(family(FAMILY_A, (1,))))
    settings.VALI_COMPUTE_REQUIRES_STORAGE = False
    assert storage_requirement.denied_node_ids() == {}
    assert service.cordoned_node_ids() == {}
    assert storage_requirement.withhold_weights({node_id(1): 7}) == {node_id(1): 7}


# ─── where it bites: placement, readouts, rewards ────────────────────


def _mirror(seed: int, **over: Any) -> MinerCapacity:
    now = timezone.now()
    fields: dict[str, Any] = dict(
        miner_node_id=node_id(seed),
        status="active",
        capacity_slots=8,
        observed_epoch=10,
        data_epoch=10,
        refreshed_at=now,
        approved_at=now,
        approved_by="grandfathered",
    )
    fields.update(over)
    return MinerCapacity.objects.create(**fields)


def test_a_cut_node_is_cordoned_and_never_placed_on(on: None) -> None:
    _mirror(1)
    _mirror(2)
    storage_requirement.refresh(
        snapshot(family(FAMILY_A, (1,)), family(FAMILY_B, (2,), storage(0xD1, FAMILY_B)))
    )
    assert service.cordoned_node_ids() == {node_id(1): "no-storage"}
    assert node_id(1) in service.hard_gated_node_ids()
    assert node_id(2) not in service.hard_gated_node_ids()
    snap = make_snapshot(10, [make_miner(1), make_miner(2)])
    kw: dict[str, Any] = dict(
        snapshot=snap,
        capacity_by_node={m.node_id: 8 for m in snap.miners},
        load_by_node={},
        family_load_by_node={},
        max_epoch_lag=2,
    )
    assert decide_placement(**kw, cordoned=service.cordoned_node_ids()) == node_id(2)
    FamilyStorageState.objects.filter(family=FAMILY_B).update(
        has_storage=False, last_healthy_at=None
    )
    with pytest.raises(PlacementError) as exc:
        decide_placement(**kw, cordoned=service.cordoned_node_ids())
    assert exc.value.category == "no-eligible-miner"


def test_an_operator_cordon_keeps_its_own_reason(on: None) -> None:
    _mirror(1, cordoned_at=timezone.now(), cordon_reason="disk")
    storage_requirement.refresh(snapshot(family(FAMILY_A, (1,))))
    assert service.cordoned_node_ids() == {node_id(1): "disk"}


def test_a_cut_node_earns_no_weight(on: None, settings) -> None:
    from apps.scheduler import scoring

    storage_requirement.refresh(
        snapshot(family(FAMILY_A, (1,)), family(FAMILY_B, (2,), storage(0xD1, FAMILY_B)))
    )
    assert storage_requirement.withhold_weights({node_id(1): 5, node_id(2): 7}) == {node_id(2): 7}

    def base() -> dict[str, int]:
        return {node_id(1): 5, node_id(2): 7}

    settings.VALI_EPOCH_WEIGHT_SOURCE = "snapshot"
    import unittest.mock as mock

    with mock.patch.object(scoring, "_snapshot_weights", base):
        assert scoring.compute_epoch_weights() == {node_id(2): 7}
        settings.VALI_COMPUTE_REQUIRES_STORAGE = False
        assert scoring.compute_epoch_weights() == base()


def test_the_fleet_verdict_names_no_storage() -> None:
    from apps.operator.fleet import _placement_verdict

    kw: dict[str, Any] = dict(
        dispatchable=True,
        dispatch_reason=None,
        zombie_quarantined=False,
        chain_row={"status": "active", "data_epoch": 10},
        on_chain=True,
        current_epoch=10,
        cvm_verdict="capable",
        cap={"model": "v1", "free_slots": 3},
    )
    assert _placement_verdict(**kw) == (True, None)
    assert _placement_verdict(**kw, no_storage=True) == (False, "no-storage")
    # An earlier gate keeps its own reason.
    assert _placement_verdict(
        **{**kw, "dispatchable": False, "dispatch_reason": "unreachable"}, no_storage=True
    ) == (False, "unreachable")


def test_operator_nodes_says_no_storage(on: None, authed_client) -> None:
    from django.urls import reverse

    from .factories import make_dispatchable_identity

    make_dispatchable_identity(1)
    make_dispatchable_identity(2)
    storage_requirement.refresh(
        snapshot(family(FAMILY_A, (1,)), family(FAMILY_B, (2,), storage(0xD1, FAMILY_B)))
    )
    resp = authed_client.get(reverse("operator_nodes"), {"node_id": [node_id(1), node_id(2)]})
    assert resp.status_code == 200, resp.content
    rows = {r["node_id"]: r for r in resp.json()["nodes"]}
    assert (rows[node_id(1)]["schedulable"], rows[node_id(1)]["schedulable_reason"]) == (
        False,
        "no-storage",
    )
    assert rows[node_id(2)]["schedulable_reason"] != "no-storage"


# ─── the chain read boundary ─────────────────────────────────────────


_WIRE: dict[str, Any] = {
    "tag": "ok",
    "block_hash": "0x" + "ab" * 32,
    "current_weight_bucket": BUCKET,
    "stale_child_buckets": STALE,
    "families": [
        {
            "family_hex": FAMILY_A,
            "compute": [{"node_id_hex": node_id(1), "child_hex": h(0xC1)}],
            "storage": [
                {
                    "child_hex": h(0xD1),
                    "registration": {
                        "family_hex": FAMILY_A,
                        "node_id_hex": h(0xD2),
                        "status": "active",
                    },
                    "node_weight": 900,
                    "last_bucket": BUCKET,
                    "quality": {
                        "shard_data_bytes_dec": str(2**100),
                        "bandwidth_bytes_dec": "7",
                        "uptime_permille": 990,
                        "strikes": 0,
                        "integrity_fails": 0,
                    },
                },
                {
                    "child_hex": h(0xD3),
                    "registration": None,
                    "node_weight": 0,
                    "last_bucket": 0,
                    "quality": None,
                },
            ],
        }
    ],
}


@pytest.fixture
def binary(settings, tmp_path, monkeypatch):
    bin_path = tmp_path / "validator"
    bin_path.write_text("")
    settings.VALI_TICKET_VALIDATOR_BIN = str(bin_path)
    settings.VALI_THEBRAIN_RPC_URL = "https://rpc.invalid"
    calls: list[list[str]] = []

    def run(argv: list[str], **kw: Any) -> subprocess.CompletedProcess[bytes]:
        calls.append(argv)
        assert "rpc.invalid" not in " ".join(argv), "the RPC URL never travels in argv"
        assert kw["env"]["THEBRAIN_RPC_URL"] == "https://rpc.invalid"
        payload = run.payload  # type: ignore[attr-defined]
        return subprocess.CompletedProcess(argv, run.rc, json.dumps(payload).encode(), b"")  # type: ignore[attr-defined]

    run.payload = _WIRE  # type: ignore[attr-defined]
    run.rc = 0  # type: ignore[attr-defined]
    monkeypatch.setattr(storage_requirement.subprocess, "run", run)
    return run


def test_reads_the_wire_contract(binary) -> None:
    snap = storage_requirement.read_storage_families()
    assert snap.current_weight_bucket == BUCKET and snap.stale_child_buckets == STALE
    (fam,) = snap.families
    assert fam.compute == ((node_id(1), h(0xC1)),)
    good, bare = fam.storage
    assert (good.reg_status, good.node_weight, good.has_quality, good.uptime_permille) == (
        "active",
        900,
        True,
        990,
    )
    assert (bare.reg_family, bare.has_quality) == (None, False)
    assert storage_requirement.judge(snap)[0].counted == 1


@pytest.mark.parametrize(
    ("payload", "rc"),
    [
        ({"tag": "err", "error": "gone", "category": "pallet-absent"}, 2),
        ({"tag": "ok"}, 0),
        ({**_WIRE, "families": [{**_WIRE["families"][0], "family_hex": "XY"}]}, 0),
        (_WIRE, 1),
    ],
    ids=["structured-error", "missing-keys", "bad-hex", "internal-exit"],
)
def test_every_read_failure_raises(binary, payload: dict, rc: int) -> None:
    binary.payload, binary.rc = payload, rc
    with pytest.raises(ChainReadUnavailable):
        storage_requirement.read_storage_families()


def test_the_reeval_hook_reads_only_when_on_and_is_throttled(binary, settings) -> None:
    settings.VALI_SYNTHETIC_PUSHGATEWAY_URL = ""
    storage_requirement._last_refresh_attempt = None
    settings.VALI_COMPUTE_REQUIRES_STORAGE = False
    storage_requirement.refresh_if_due()
    assert not FamilyStorageState.objects.exists()
    settings.VALI_COMPUTE_REQUIRES_STORAGE = True
    settings.VALI_COMPUTE_STORAGE_REFRESH_S = 300
    storage_requirement.refresh_if_due()
    assert FamilyStorageState.objects.count() == 1
    FamilyStorageState.objects.all().delete()
    storage_requirement.refresh_if_due()  # inside the period: no second read
    assert not FamilyStorageState.objects.exists()
    storage_requirement._last_refresh_attempt = None


# ─── the read-only evaluation ────────────────────────────────────────


def _evaluated(monkeypatch, snap: StorageSnapshot) -> None:
    monkeypatch.setattr(storage_requirement, "read_storage_families", lambda: snap)


def test_evaluate_reports_every_family_and_writes_nothing(on: None, monkeypatch, settings) -> None:
    from django.db import connection
    from django.test.utils import CaptureQueriesContext

    t0 = timezone.now() - timedelta(hours=10)
    # A lost its storage 10 h ago (in grace); B never had any; C is healthy;
    # D is exempt.
    fam_c, fam_d = h(0xC9), h(0xD9)
    FamilyStorageState.objects.create(
        family=FAMILY_A,
        compute_node_ids=[node_id(1)],
        has_storage=False,
        last_healthy_at=t0,
        first_seen_at=t0,
        refreshed_at=t0,
    )
    settings.VALI_COMPUTE_STORAGE_EXEMPT_FAMILIES = [storage_requirement.ss58_encode(fam_d)]
    snap = snapshot(
        family(FAMILY_A, (1,), storage(0xD1, node_weight=0)),
        family(FAMILY_B, (2,), storage(0xC2, FAMILY_B)),
        family(fam_c, (3,), storage(0xE1, fam_c)),
        family(fam_d, (4,)),
    )
    _evaluated(monkeypatch, snap)
    before = list(FamilyStorageState.objects.values())
    with CaptureQueriesContext(connection) as ctx:
        out = StringIO()
        call_command("vali_storage_requirement", "--evaluate", "--json", stdout=out)
        human = StringIO()
        call_command("vali_storage_requirement", "--evaluate", stdout=human)
    writes = [
        q["sql"]
        for q in ctx.captured_queries
        if q["sql"].lstrip().upper().startswith(("INSERT", "UPDATE", "DELETE"))
    ]
    assert writes == []
    assert list(FamilyStorageState.objects.values()) == before
    report = json.loads(out.getvalue())
    by = {f["family"]: f for f in report["families"]}
    assert (by[FAMILY_A]["decision"], by[FAMILY_A]["tracked"]) == ("grace", True)
    assert by[FAMILY_A]["grace_until"] is not None
    assert by[FAMILY_A]["children"] == [
        {"child": h(0xD1), "counted": False, "reason": "zero-weight"}
    ]
    assert (by[FAMILY_B]["decision"], by[FAMILY_B]["allowed"]) == ("no-storage", False)
    assert by[FAMILY_B]["children"][0]["reason"] == "compute-child"
    assert (by[fam_c]["decision"], by[fam_c]["storage_counted"]) == ("storage-ok", 1)
    assert by[fam_d]["decision"] == "exempt"
    assert by[fam_d]["family_ss58"] == storage_requirement.ss58_encode(fam_d)
    text = human.getvalue()
    assert "decision=no-storage" in text and "[compute-child]" in text
    assert "4 compute family(ies), 1 cut; requirement on=True; nothing written" in text


def test_evaluate_shows_an_inert_gate(monkeypatch, settings) -> None:
    settings.VALI_COMPUTE_STORAGE_EXEMPT_FAMILIES = ["bad"]
    _evaluated(monkeypatch, snapshot(family(FAMILY_A, (1,))))
    report = storage_requirement.evaluate()
    assert report["gate_inert"] is True and "bad" in report["exemption_error"]


def test_evaluate_fails_loudly_on_a_failed_read(monkeypatch) -> None:
    def boom() -> StorageSnapshot:
        raise ChainReadUnavailable("down")

    monkeypatch.setattr(storage_requirement, "read_storage_families", boom)
    with pytest.raises(CommandError, match="chain read failed"):
        call_command("vali_storage_requirement", "--evaluate")


def test_a_new_family_is_judged_without_grace(monkeypatch) -> None:
    _evaluated(monkeypatch, snapshot(family(FAMILY_A, (1,))))
    (fam,) = storage_requirement.evaluate()["families"]
    assert (fam["tracked"], fam["decision"], fam["grace_until"]) == (False, "no-storage", None)


def test_snapshot_dataclass_is_frozen() -> None:
    snap = snapshot(family(FAMILY_A, (1,)))
    assert replace(snap, block_hash="x").block_hash == "x"


def test_a_named_miner_launch_says_why(on: None) -> None:
    from apps.orchestration.services.launch import LaunchConfigError, _refuse_cordoned_miner

    from .factories import make_dispatchable_identity

    miner = make_dispatchable_identity(1)
    storage_requirement.refresh(snapshot(family(FAMILY_A, (1,))))
    with pytest.raises(LaunchConfigError, match="no healthy Arion storage node"):
        _refuse_cordoned_miner(miner)


def test_evaluate_reports_the_age_of_the_last_read(on: None, monkeypatch) -> None:
    t0 = timezone.now() - timedelta(hours=3)
    storage_requirement.refresh(snapshot(family(FAMILY_A, (1,))), now=t0)
    _evaluated(monkeypatch, snapshot(family(FAMILY_A, (1,))))
    assert storage_requirement.evaluate()["last_refresh_at"] == t0.isoformat()


def test_the_refresh_pushes_the_age_and_the_cut(binary, settings, monkeypatch) -> None:
    from apps.synthetic import metrics

    pushed: list[tuple[Any, dict[str, Any]]] = []
    monkeypatch.setattr(metrics, "push", lambda ms, **kw: pushed.append((ms, kw)))
    settings.VALI_SYNTHETIC_PUSHGATEWAY_URL = "http://pgw.invalid"
    settings.VALI_COMPUTE_REQUIRES_STORAGE = True
    storage_requirement._last_refresh_attempt = None
    storage_requirement.refresh_if_due()
    storage_requirement._last_refresh_attempt = None
    ((ms, kw),) = pushed
    assert kw["job"] == "vali-storage-requirement"
    text = ms.render()
    assert storage_requirement.M_REFRESH_TS in text
    assert storage_requirement.M_CUT_NODES in text
