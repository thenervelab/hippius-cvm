"""Contract §9 on the launch path: `dedicated_disks.integrity` at the
intake (every refusal before any Vault write), kept in the spec only when
true, the measured `x<N>:<GiB>:i` anchor on the first launch and on
relaunch paths (same-placement relaunch, a new placement of held disks;
in-place resize and reboot recovery: `test_dedicated_integrity_relaunch.py`),
and `integrity` on the job result. The disk logic itself:
`apps/disktier/tests/test_dedicated_integrity.py`."""

from __future__ import annotations

import json
from typing import Any

import pytest
from django.test import override_settings
from django.utils import timezone

from apps.disktier import dedicated
from apps.disktier.models import DedicatedDisk, PlacementDisk
from apps.disktier.tests.dedicated_helpers import ON, make_disk
from apps.orchestration import launch_jobs, order_dispatch
from apps.orchestration.models import LaunchJob, LaunchJobState
from apps.orchestration.services import launch
from apps.scheduler.models import Placement, PlacementStatus

from .test_dedicated_launch import (
    _REAL_BIN,
    _actor,
    _assigned,
    _blessed,
    _fleet,
    _image_body,
    _launched,
    _ok_launch_vm_with_disks,
    _outcome,
    _queued,
    _rig,
    _spec,
    _spy_writes,
)
from .test_launch_api import LAUNCH_URL, stub_vault_put  # noqa: F401 — a fixture
from .test_launch_service import _spec as service_spec

pytestmark = pytest.mark.django_db

SSD = {"tier": "ssd", "count": 2, "min_size_gb": 16000}
SSD_I = {**SSD, "integrity": True}
INTEGRITY_ON: dict[str, Any] = dict(
    ON,
    VALI_DEDICATED_SELLABLE_TIERS=["hdd", "ssd", "nvme"],
    VALI_DEDICATED_INTEGRITY_ENABLED=True,
    VALI_DEDICATED_INTEGRITY_MIN_GUEST_RELEASE=8,
)
INTEGRITY_OFF = {**INTEGRITY_ON, "VALI_DEDICATED_INTEGRITY_ENABLED": False}


def _token(cmdline: str) -> list[str]:
    return [t for t in cmdline.split() if t.startswith("hippius.dedicated=")]


# ── intake ──────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    ("flags", "release", "body", "status", "category"),
    [
        (INTEGRITY_OFF, 8, SSD_I, 409, "dedicated-integrity-not-offered"),
        (INTEGRITY_ON, 8, {**SSD_I, "tier": "hdd"}, 409, "dedicated-integrity-not-offered"),
        (INTEGRITY_ON, 8, {**SSD, "integrity": "true"}, 400, "dedicated-invalid"),
        (INTEGRITY_ON, 8, {**SSD, "integrity": 1}, 400, "dedicated-invalid"),
        (INTEGRITY_ON, 8, {**SSD, "integrity": None}, 400, "dedicated-invalid"),
        (INTEGRITY_ON, 7, SSD_I, 409, "dedicated-needs-release"),
        (
            {**INTEGRITY_ON, "VALI_DEDICATED_INTEGRITY_MIN_GUEST_RELEASE": 9},
            8,
            SSD_I,
            409,
            "dedicated-needs-release",
        ),
    ],
)
def test_every_integrity_refusal_maps_to_its_status_and_stages_nothing(
    root_client, monkeypatch, flags, release, body, status, category
) -> None:
    _blessed(release)
    touched = _spy_writes(monkeypatch)
    with override_settings(**flags):
        resp = root_client.post(
            LAUNCH_URL,
            _image_body("vm-int-refused", dedicated_disks=body, pinned_ack=True),
            format="json",
        )
    assert (resp.status_code, resp.json()["category"]) == (status, category), resp.content
    assert touched == []
    assert LaunchJob.objects.count() == 0


def _accept(root_client, monkeypatch, vm_id: str, body: dict[str, Any]) -> dict[str, Any]:
    monkeypatch.setattr(
        launch_jobs,
        "_provision_golden_overlay_kek",
        lambda intent: intent.__setitem__(
            "kek_vault_path", launch_jobs._canonical_kek_path(intent)
        ),
    )
    resp = root_client.post(
        LAUNCH_URL, _image_body(vm_id, dedicated_disks=body, pinned_ack=True), format="json"
    )
    assert resp.status_code == 202, resp.content
    return LaunchJob.objects.get(vm_id=vm_id).spec_json


@override_settings(**INTEGRITY_ON)
def test_an_accepted_integrity_launch_keeps_it_in_the_spec(
    root_client,
    monkeypatch,
    stub_vault_put,  # noqa: F811
) -> None:
    _blessed(8)
    spec = _accept(root_client, monkeypatch, "vm-int-ok", SSD_I)
    assert spec["dedicated_disks"] == SSD_I


@override_settings(**INTEGRITY_ON)
def test_integrity_false_stores_the_request_byte_identical(
    root_client,
    monkeypatch,
    stub_vault_put,  # noqa: F811
) -> None:
    """`integrity: false` (or absent) is the pre-§9 launch: same record, and
    the release floor of plain dedicated disks (5), not 8."""
    _blessed(5)
    spec = _accept(root_client, monkeypatch, "vm-int-off", {**SSD, "integrity": False})
    assert spec["dedicated_disks"] == SSD
    assert "integrity" not in json.dumps(spec["dedicated_disks"])


@pytest.mark.parametrize(
    ("first", "again", "refused"),
    [
        (SSD_I, SSD_I, False),
        (SSD, {**SSD, "integrity": False}, False),
        (SSD, SSD_I, True),
        (SSD_I, SSD, True),
    ],
)
def test_a_re_post_must_ask_the_same_integrity(first, again, refused) -> None:
    vm = _launched("vm-int-again", first)
    spec = {"dedicated_disks": dedicated.parse_request(again).as_spec()}
    if refused:
        with pytest.raises(launch_jobs.LaunchIntentError) as exc:
            launch_jobs._check_dedicated_fixed(vm, spec)
        assert exc.value.category == "conflict"
    else:
        launch_jobs._check_dedicated_fixed(vm, spec)


# ── launch_on_miner: the measured anchor ────────────────────────────


def _assigned_integrity(miner, vm_id: str = "vm-launch-1") -> Placement:
    placement = _assigned(miner, vm_id)
    PlacementDisk.objects.filter(placement=placement).update(integrity=True)
    return placement


@override_settings(**INTEGRITY_ON)
def test_the_first_launch_measures_the_integrity_anchor(monkeypatch) -> None:
    miner, seen = _rig(monkeypatch)
    _assigned_integrity(miner)
    out = launch.launch_on_miner(_spec(dedicated_disks=SSD_I, pinned_ack=True), miner)
    assert out.disposition == launch.ACCEPTED, out.emit
    payload = seen["payload"][0]
    cmdline = payload["cmdline"]
    assert _token(cmdline) == ["hippius.dedicated=x0:16000:i,x1:22300:i"]
    # The same measured cmdline the preflight measures and C2 recomputes.
    assert seen["preflight"] == [cmdline]
    assert seen["recompute"] == [cmdline]
    # The order's extra_disks are the plain entries.
    assert [set(d) for d in payload["extra_disks"]] == [{"slot", "kind", "disk_id"}] * 2


@override_settings(**INTEGRITY_ON)
def test_a_plain_launch_measures_the_anchor_byte_identical(monkeypatch) -> None:
    miner, seen = _rig(monkeypatch)
    _assigned(miner)
    launch.launch_on_miner(_spec(dedicated_disks=SSD, pinned_ack=True), miner)
    assert _token(seen["payload"][0]["cmdline"]) == ["hippius.dedicated=x0:16000,x1:22300"]


@override_settings(**INTEGRITY_ON)
def test_a_same_placement_relaunch_sends_the_same_integrity_anchor(monkeypatch) -> None:
    miner, seen = _rig(monkeypatch)
    placement = _assigned_integrity(miner)
    spec = _spec(dedicated_disks=SSD_I, pinned_ack=True)
    launch.launch_on_miner(spec, miner)
    Placement.objects.filter(pk=placement.pk).update(
        status=PlacementStatus.BOUND.value, bound_at=timezone.now()
    )
    # Never refused for a flag change: integrity switched off meanwhile.
    with override_settings(
        VALI_DEDICATED_INTEGRITY_ENABLED=False,
        VALI_DEDICATED_ENABLED=False,
        VALI_DEDICATED_MIN_AGENT_VERSION="",
    ):
        out = launch.launch_on_miner(spec, miner, require_existing_disks=True)
    assert out.disposition == launch.ACCEPTED, out.emit
    first, again = seen["payload"]
    assert _token(again["cmdline"]) == _token(first["cmdline"])
    assert _token(again["cmdline"]) == ["hippius.dedicated=x0:16000:i,x1:22300:i"]


@override_settings(**INTEGRITY_ON)
def test_a_second_placement_of_held_disks_keeps_their_integrity(monkeypatch) -> None:
    """`launch_vm` again after an attempt that kept its disks: the new
    placement (`_reuse`) re-records the same slots WITH integrity."""
    m1, _m2 = _fleet(monkeypatch, 1, 2)
    for i in range(2):
        make_disk(f"wwn-0x1{i}", node=m1.chain_node_id, tier="ssd")
    monkeypatch.setattr(
        launch, "launch_on_miner", lambda *a, **k: _outcome(launch.TERMINAL, registered=True)
    )
    actor = _actor()
    spec = service_spec(dedicated_disks=SSD_I, pinned_ack=True)
    launch.launch_vm(spec, actor)
    seen: list[list] = []

    def fake(spec, miner, **_k):
        seen.append(dedicated.extra_disks(spec.vm_id, miner.chain_node_id))
        return _outcome(launch.TERMINAL, registered=False)

    monkeypatch.setattr(launch, "launch_on_miner", fake)
    launch.launch_vm(spec, actor)
    assert [d.integrity for d in seen[0]] == [True, True]
    assert dedicated.cmdline_value(seen[0]).endswith(":i")
    assert PlacementDisk.objects.filter(integrity=True).count() == 4
    assert not PlacementDisk.objects.filter(integrity=False).exists()


def test_the_pre_pin_length_check_covers_the_integrity_anchor() -> None:
    plain = launch._pre_pin_dedicated_value(_spec(dedicated_disks=SSD, pinned_ack=True))
    integ = launch._pre_pin_dedicated_value(_spec(dedicated_disks=SSD_I, pinned_ack=True))
    assert plain == ",".join(["x23:1048576"] * 2)
    assert integ == ",".join(["x23:1048576:i"] * 2)


# ── the job result ──────────────────────────────────────────────────


def _ok_with_integrity(spec, decided_by, **kw):
    result = _ok_launch_vm_with_disks(spec, decided_by, **kw)
    PlacementDisk.objects.filter(placement_id=result.placement_id).update(integrity=True)
    return result


@override_settings(**INTEGRITY_ON)
def test_the_job_result_marks_integrity_slots(monkeypatch) -> None:
    job = _queued({"dedicated_disks": {**SSD_I, "tier": "hdd"}, "pinned_ack": True})
    monkeypatch.setattr(launch, "open_userdata_intake_copy", lambda *a, **k: b"#cloud-config\n")
    monkeypatch.setattr(launch_jobs.launch, "launch_vm", _ok_with_integrity)
    assert launch_jobs.tick_once() is True
    job.refresh_from_db()
    assert job.state == LaunchJobState.SUCCEEDED.value, job.reason
    disks = job.result_json["disks"]
    assert "integrity" not in disks[0]
    assert [d.get("integrity") for d in disks[1:]] == [True, True]
    assert "wwn-" not in str(job.result_json)


@pytest.mark.skipif(not _REAL_BIN.is_file(), reason=f"Rust validator not built at {_REAL_BIN}")
def test_the_real_encoder_carries_an_integrity_anchor() -> None:
    disks = [{"slot": "x0", "kind": "dedicated", "disk_id": "wwn-0x5000c500a1b2c3d4"}]
    payload = order_dispatch.build_launch_payload(
        vm_id="v",
        ovmf_path="/o",
        kernel_path="/k",
        initrd_path="/i",
        luks_disk_path="/l",
        luks_disk_size_gb=1,
        rootfs_data_path="/r",
        rootfs_hash_path="/h",
        cpu_count=1,
        memory_mb=1,
        cose_ticket=b"c",
        extra_disks=disks,
        cmdline="ro hippius.dedicated=x0:22300:i",
    )
    body = order_dispatch._encode_order_body(
        order_id="o",
        kind="launch",
        target_miner_id="m",
        issued_at_unix=1_770_000_000,
        payload_json=json.dumps(payload).encode(),
    )
    assert b"x0:22300:i" in body and b"wwn-0x5000c500a1b2c3d4" in body


def test_no_integrity_row_without_a_dedicated_disk() -> None:
    """The model refuses integrity on a pool (OS) disk row."""
    from django.db import IntegrityError, transaction

    from apps.scheduler.tests.factories import make_placement, make_vm, node_id

    vm = make_vm("vm-int-pool", "lease-ip")
    placement = make_placement(vm, node_id(1))
    with pytest.raises(IntegrityError), transaction.atomic():
        PlacementDisk.objects.create(
            placement=placement,
            slot="os",
            kind="pool",
            pool_id="default",
            size_gb=40,
            required_tier="nvme",
            integrity=True,
        )
    assert DedicatedDisk.objects.count() == 0
