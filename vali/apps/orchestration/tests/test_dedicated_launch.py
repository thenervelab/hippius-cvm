"""E4 dedicated disks on the launch path (frozen contract
docs/design/dedicated-disks-contract.md): the intake and its ordering
before any Vault write, the placement that assigns the disks, the order's
`extra_disks` and the measured `hippius.dedicated=` token (in what C2
recomputes), the read-back on the job and the VM, and byte-identity for
every VM without dedicated disks. The disk logic itself:
`apps/disktier/tests/test_dedicated.py`."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from django.conf import settings
from django.test import override_settings
from django.urls import reverse
from django.utils import timezone

from apps.disktier import dedicated
from apps.disktier.models import DedicatedDisk, PlacementDisk
from apps.disktier.tests.dedicated_helpers import ON, capable, make_disk
from apps.identity.models import PrincipalScope, ServiceClient
from apps.lifecycle.models import Vm
from apps.orchestration import launch_jobs, order_dispatch
from apps.orchestration.models import LaunchJob, LaunchJobState
from apps.orchestration.services import launch, vault_kv
from apps.scheduler import chain
from apps.scheduler.models import MinerCapacity, Placement, PlacementStatus
from apps.scheduler.tests.factories import (
    make_miner,
    make_placement,
    make_snapshot,
    make_vm,
    node_id,
)

from .test_launch_api import (  # noqa: F401 — `stub_vault_put` is a fixture
    LAUNCH_URL,
    _bless_golden_image,
    _guest_build,
    _intent,
    _make_golden_bake,
    stub_vault_put,
)
from .test_launch_service import _register_miner

pytestmark = pytest.mark.django_db

GOOD = {"tier": "hdd", "count": 2, "min_size_gb": 16000}
#: The artifact fields a launch by image takes from the catalog only.
_ARTIFACTS = (
    "s3_bucket",
    "s3_key_prefix",
    "luks_disk_sha256_hex",
    "kernel_sha256_hex",
    "initrd_sha256_hex",
    "luks_header_sha256_hex",
)


# ── intake ──────────────────────────────────────────────────────────


def _spec_body(**kw: Any) -> dict[str, Any]:
    return _intent(dedicated_disks=GOOD, pinned_ack=True, **kw)


@override_settings(**ON)
def test_a_dedicated_launch_rides_the_spec_into_the_worker() -> None:
    spec = launch_jobs._build_spec_json(_spec_body(), guest_release=5)
    assert spec["dedicated_disks"] == GOOD
    assert spec["pinned_ack"] is True
    worker = launch.LaunchSpec(**spec, kek_bytes=None, userdata=b"")
    assert dedicated.spec_request(worker) == dedicated.DedicatedRequest("hdd", 2, 16000)


@pytest.mark.parametrize("flags", [{}, ON])
def test_without_dedicated_disks_the_spec_is_byte_identical(flags) -> None:
    with override_settings(**flags):
        spec = launch_jobs._build_spec_json(_intent(), guest_release=5)
        assert spec == launch_jobs._build_spec_json(_intent(dedicated_disks=None))
    assert "dedicated_disks" not in spec and "pinned_ack" not in spec
    assert launch.LaunchSpec(**spec, kek_bytes=None, userdata=b"").dedicated_disks is None


def _image_body(vm_id: str, **kw: Any) -> dict[str, Any]:
    body = _intent(vm_id=vm_id, image="ubuntu", **kw)
    for key in (*_ARTIFACTS, "kek_vault_path"):
        body.pop(key, None)
    return body


def _blessed(release: int | None) -> None:
    from apps.images.models import GoldenImage

    _make_golden_bake(bake_id="gb-ubuntu")
    _bless_golden_image("ubuntu", "gb-ubuntu")
    if release is not None:
        _guest_build(release)
        GoldenImage.objects.filter(image_name="ubuntu").update(guest_release=release)


def _spy_writes(monkeypatch) -> list[str]:
    touched: list[str] = []

    def spy(name: str):
        def fail(*_a: object, **_k: object) -> None:
            touched.append(name)
            raise AssertionError(f"{name} reached for a refused launch")

        return fail

    monkeypatch.setattr(launch_jobs, "_provision_golden_overlay_kek", spy("provision"))
    for fn in ("put_kv", "ensure_transit_key", "transit_datakey_wrapped", "transit_encrypt"):
        monkeypatch.setattr(vault_kv, fn, spy(fn))
    monkeypatch.setattr(launch, "stage_userdata_intake_copy", spy("stage-userdata"))
    return touched


@pytest.mark.parametrize(
    ("flags", "release", "overrides", "status", "category"),
    [
        # Off: today's 409, whatever the body.
        ({}, 5, dict(dedicated_disks=GOOD, pinned_ack=True), 409, "dedicated-disks-not-offered"),
        ({}, 5, dict(dedicated_disks={}), 409, "dedicated-disks-not-offered"),
        # On, an owner off the allowlist.
        (
            {**ON, "VALI_DEDICATED_ALLOWED_OWNERS": ["canary"]},
            5,
            dict(dedicated_disks=GOOD, pinned_ack=True),
            409,
            "dedicated-disks-not-offered",
        ),
        (ON, 5, dict(dedicated_disks=[], pinned_ack=True), 400, "dedicated-invalid"),
        (ON, 5, dict(dedicated_disks={**GOOD, "x": 1}), 400, "dedicated-invalid"),
        (ON, 5, dict(dedicated_disks={**GOOD, "tier": "ssd"}), 400, "dedicated-invalid"),
        (ON, 5, dict(dedicated_disks={**GOOD, "count": 9}), 400, "dedicated-count-invalid"),
        (ON, 5, dict(dedicated_disks={**GOOD, "min_size_gb": 999}), 400, "dedicated-size-invalid"),
        (ON, 5, dict(dedicated_disks=GOOD), 400, "dedicated-ack-required"),
        (ON, 5, dict(dedicated_disks=GOOD, pinned_ack=False), 400, "dedicated-ack-required"),
        (
            ON,
            5,
            dict(dedicated_disks=GOOD, pinned_ack=True, require_failover_peer=True),
            409,
            "dedicated-no-failover",
        ),
        (ON, 4, dict(dedicated_disks=GOOD, pinned_ack=True), 409, "dedicated-needs-release"),
        (ON, None, dict(dedicated_disks=GOOD, pinned_ack=True), 409, "dedicated-needs-release"),
        (
            {**ON, "VALI_DEDICATED_MIN_GUEST_RELEASE": None},
            5,
            dict(dedicated_disks=GOOD, pinned_ack=True),
            409,
            "dedicated-needs-release",
        ),
    ],
)
def test_every_refusal_maps_to_its_status_and_stages_nothing(
    root_client, monkeypatch, flags, release, overrides, status, category
) -> None:
    """Every dedicated-disk refusal of the body comes BEFORE the first
    Vault write (the golden overlay KEK, the userdata): the #1718 lesson."""
    _blessed(release)
    touched = _spy_writes(monkeypatch)
    with override_settings(**flags):
        resp = root_client.post(
            LAUNCH_URL, _image_body("vm-ded-refused", **overrides), format="json"
        )
    assert (resp.status_code, resp.json()["category"]) == (status, category), resp.content
    assert touched == []
    assert LaunchJob.objects.count() == 0


@override_settings(**ON)
def test_an_accepted_launch_by_image_keeps_the_request(
    root_client,
    monkeypatch,
    stub_vault_put,  # noqa: F811 — the imported fixture
) -> None:
    _blessed(5)
    monkeypatch.setattr(
        launch_jobs,
        "_provision_golden_overlay_kek",
        lambda intent: intent.__setitem__(
            "kek_vault_path", launch_jobs._canonical_kek_path(intent)
        ),
    )
    resp = root_client.post(
        LAUNCH_URL, _image_body("vm-ded-ok", dedicated_disks=GOOD, pinned_ack=True), format="json"
    )
    assert resp.status_code == 202, resp.content
    spec = LaunchJob.objects.get(vm_id="vm-ded-ok").spec_json
    assert (spec["dedicated_disks"], spec["pinned_ack"]) == (GOOD, True)


def _launched(vm_id: str, dedicated_disks: dict | None) -> Vm:
    from .factories import make_launch_record
    from .factories import make_vm as make_orch_vm

    vm = make_orch_vm(vm_id)
    job = make_launch_record(vm)
    if dedicated_disks is not None:
        job.spec_json = {**job.spec_json, "dedicated_disks": dedicated_disks}
        job.save()
    return vm


@pytest.mark.parametrize(
    ("first", "again", "refused"),
    [
        (None, None, False),
        (GOOD, GOOD, False),
        (None, GOOD, True),
        (GOOD, None, True),
        (GOOD, {**GOOD, "count": 1}, True),
    ],
)
def test_a_vms_dedicated_disks_are_fixed_by_its_first_launch(first, again, refused) -> None:
    vm = _launched("vm-again", first)
    spec = {} if again is None else {"dedicated_disks": again}
    if refused:
        with pytest.raises(launch_jobs.LaunchIntentError) as exc:
            launch_jobs._check_dedicated_fixed(vm, spec)
        assert exc.value.category == "conflict"
    else:
        launch_jobs._check_dedicated_fixed(vm, spec)


@override_settings(**ON)
def test_a_re_post_asking_other_disks_stages_nothing(root_client, monkeypatch) -> None:
    _blessed(5)
    _launched("vm-ded-again", None)
    touched = _spy_writes(monkeypatch)
    resp = root_client.post(
        LAUNCH_URL,
        _image_body("vm-ded-again", dedicated_disks=GOOD, pinned_ack=True),
        format="json",
    )
    assert (resp.status_code, resp.json()["category"]) == (409, "conflict"), resp.content
    assert touched == []


def test_resolve_bake_returns_the_images_guest_release() -> None:
    _blessed(5)
    assert launch_jobs._resolve_bake({"image": "ubuntu"}) == 5
    assert launch_jobs._resolve_bake({}) is None
    assert launch_jobs._resolve_bake({"bake_id": "gb-ubuntu"}) is None


# ── launch_on_miner: the order and the measured cmdline ─────────────


def _rig(monkeypatch) -> tuple[Any, dict[str, list]]:
    from apps.disktier.tests.test_routing import _rig as routing_rig
    from apps.orchestration.services import launch_digest, preflight

    miner, _seen = routing_rig(monkeypatch)
    seen: dict[str, list] = {"payload": [], "preflight": [], "recompute": []}

    def payload(*a: Any, **k: Any) -> dict[str, Any]:
        seen["payload"].append(k)
        return {}

    monkeypatch.setattr(order_dispatch, "build_launch_payload", payload)
    real_preflight = preflight.dispatch_preflight

    def preflight_spy(*a: Any, **k: Any):
        seen["preflight"].append(k["cmdline"])
        return real_preflight(*a, **k)

    monkeypatch.setattr(preflight, "dispatch_preflight", preflight_spy)
    monkeypatch.setattr(launch_digest, "is_enabled", lambda: True)
    monkeypatch.setattr(launch_digest, "enforce", lambda: False)

    def recompute(**k: Any) -> str:
        seen["recompute"].append(k["cmdline"])
        return "ab" * 48

    monkeypatch.setattr(launch_digest, "recompute_expected_digest", recompute)
    return miner, seen


def _spec(**kw: Any) -> launch.LaunchSpec:
    from apps.disktier.tests.test_routing import _spec as routing_spec

    return routing_spec(**kw)


def _assigned(miner, vm_id: str = "vm-launch-1", sizes=(22354, 16050)) -> Placement:
    capable(miner.chain_node_id)
    vm = Vm.objects.filter(vm_id=vm_id).first() or Vm.objects.create(
        vm_id=vm_id, tenant_id="t-launch", state="active", host="", generation=1
    )
    placement = make_placement(vm, miner.chain_node_id)
    for i, size in enumerate(sizes):
        make_disk(f"wwn-0x0{i}", node=miner.chain_node_id, size_gib=size)
    dedicated.assign(placement, vm, dedicated.DedicatedRequest("hdd", len(sizes), 16000))
    return placement


@override_settings(**ON)
def test_the_order_names_the_disks_and_the_cmdline_measures_them(monkeypatch) -> None:
    miner, seen = _rig(monkeypatch)
    _assigned(miner)
    out = launch.launch_on_miner(_spec(dedicated_disks=GOOD, pinned_ack=True), miner)
    assert out.disposition == launch.ACCEPTED, out.emit
    sizes = {
        r.slot: r.dedicated_disk.disk_id
        for r in PlacementDisk.objects.select_related("dedicated_disk")
    }
    assert seen["payload"][0]["extra_disks"] == [
        {"slot": "x0", "kind": "dedicated", "disk_id": sizes["x0"]},
        {"slot": "x1", "kind": "dedicated", "disk_id": sizes["x1"]},
    ]
    token = "hippius.dedicated=x0:16000,x1:22300"
    cmdline = seen["payload"][0]["cmdline"]
    assert token in cmdline.split()
    # The same measured cmdline the preflight measures and C2 recomputes.
    assert seen["preflight"] == [cmdline]
    assert seen["recompute"] == [cmdline]
    assert out.emit.get("measured_cmdline", cmdline) == cmdline
    _assert_order_matches_cmdline(seen["payload"][0])


def _assert_order_matches_cmdline(payload: dict[str, Any]) -> None:
    """What the agent (A4) accepts: the measured token names exactly the
    order's slots, in the same order, each at its disk's size class."""
    (token,) = [t for t in payload["cmdline"].split() if t.startswith("hippius.dedicated=")]
    measured = [entry.split(":") for entry in token.split("=", 1)[1].split(",")]
    assert [slot for slot, _ in measured] == [d["slot"] for d in payload["extra_disks"]]
    by_id = {d.disk_id: d for d in DedicatedDisk.objects.all()}
    for (slot, gib), entry in zip(measured, payload["extra_disks"], strict=True):
        disk = by_id[entry["disk_id"]]
        assert int(gib) == (disk.size_bytes // 2**30 // 100) * 100, slot


@override_settings(**ON)
def test_a_relaunch_sends_the_same_disks_and_token(monkeypatch) -> None:
    miner, seen = _rig(monkeypatch)
    placement = _assigned(miner)
    spec = _spec(dedicated_disks=GOOD, pinned_ack=True)
    launch.launch_on_miner(spec, miner)
    Placement.objects.filter(pk=placement.pk).update(
        status=PlacementStatus.BOUND.value, bound_at=timezone.now()
    )
    # A relaunch is never refused for the agent version (a flag change must
    # not strand a pinned VM).
    with override_settings(VALI_DEDICATED_MIN_AGENT_VERSION="", VALI_DEDICATED_ENABLED=False):
        out = launch.launch_on_miner(spec, miner, require_existing_disks=True)
    assert out.disposition == launch.ACCEPTED, out.emit
    first, again = seen["payload"]
    assert again["extra_disks"] == first["extra_disks"]
    token = [t for t in first["cmdline"].split() if t.startswith("hippius.dedicated=")]
    assert token and token == [
        t for t in again["cmdline"].split() if t.startswith("hippius.dedicated=")
    ]
    _assert_order_matches_cmdline(again)


@override_settings(**ON)
def test_a_dedicated_vm_without_its_disks_here_is_refused_before_any_row(monkeypatch) -> None:
    miner, seen = _rig(monkeypatch)
    capable(miner.chain_node_id)  # the agent would take them: it is the rows that lack
    out = launch.launch_on_miner(_spec(dedicated_disks=GOOD, pinned_ack=True), miner)
    assert out.disposition == launch.TERMINAL
    assert out.emit["outcome"] == launch.DEDICATED_DISKS_UNAVAILABLE
    assert seen == {"payload": [], "preflight": [], "recompute": []}
    assert not Vm.objects.filter(vm_id="vm-launch-1").exists()


@override_settings(**ON)
def test_a_first_launch_on_an_agent_that_does_not_take_the_disks_is_refused(monkeypatch) -> None:
    miner, seen = _rig(monkeypatch)
    _assigned(miner)
    capable(miner.chain_node_id, version="v2020.01.01")
    out = launch.launch_on_miner(_spec(dedicated_disks=GOOD, pinned_ack=True), miner)
    assert out.emit["outcome"] == launch.DEDICATED_DISKS_UNAVAILABLE
    assert seen["payload"] == []


@pytest.mark.parametrize("flags", [{}, ON])
def test_a_vm_without_dedicated_disks_carries_no_disks_and_no_token(monkeypatch, flags) -> None:
    miner, seen = _rig(monkeypatch)
    with override_settings(**flags):
        out = launch.launch_on_miner(_spec(), miner)
    assert out.disposition == launch.ACCEPTED, out.emit
    kwargs = seen["payload"][0]
    assert kwargs["extra_disks"] == []
    assert "hippius.dedicated" not in kwargs["cmdline"]
    assert "hippius.dedicated" not in seen["preflight"][0]


def test_the_measured_cmdline_is_unchanged_without_dedicated_disks() -> None:
    """`_derive_measured_cmdline` with no dedicated disks is exactly what it
    was before the parameter existed (same inputs, same bytes)."""
    spec = _spec()
    kw: dict[str, Any] = dict(
        disk_gb=40,
        node_id_hex="ab" * 32,
        validator_nonce_hex="cd" * 32,
        telemetry_epoch=7,
        eol_nonce_hex="ef" * 32,
    )
    plain = launch._derive_measured_cmdline(spec, None, **kw)
    assert launch._derive_measured_cmdline(spec, None, dedicated=None, **kw) == plain
    assert "hippius.dedicated" not in plain
    with_disks = launch._derive_measured_cmdline(spec, None, dedicated="x0:22300", **kw)
    tokens = with_disks.split()
    assert tokens.count("hippius.dedicated=x0:22300") == 1
    assert [t for t in tokens if t != "hippius.dedicated=x0:22300"] == plain.split()


def test_a_base_cmdline_cannot_inject_the_token(monkeypatch) -> None:
    """vali alone decides `hippius.dedicated=`: a VM without dedicated
    disks never measures one, whatever its base cmdline carried."""
    miner, seen = _rig(monkeypatch)
    out = launch.launch_on_miner(_spec(cmdline="ro hippius.dedicated=x0:99999"), miner)
    assert out.disposition == launch.ACCEPTED, out.emit
    assert "hippius.dedicated" not in seen["payload"][0]["cmdline"]


def _sized(length: int, token: str) -> str:
    filler = length - len(f"ro  {token}")
    return f"ro {'k' * filler} {token}"


@pytest.mark.parametrize("length", [1984, 2033])
def test_a_dedicated_anchor_keeps_well_under_the_kernel_limit(length: int) -> None:
    """The guest refuses an anchor that could be a truncated tail at the
    2047-byte limit: with the token, the measured cmdline stays <= 1983."""
    with_token = _sized(length, "hippius.dedicated=x0:1000")
    assert len(with_token) == length
    refusal = launch._measured_cmdline_refusal(with_token, None)
    assert refusal is not None and refusal[0] == "cmdline-too-long"
    # The same length without the anchor is as before; 1983 with it passes.
    assert launch._measured_cmdline_refusal(_sized(1984, "hippius.zzzzzzzzz=x0:1000"), None) is None
    assert launch._measured_cmdline_refusal(_sized(1983, "hippius.dedicated=x0:1000"), None) is None


def test_the_real_payload_carries_extra_disks_only_when_non_empty() -> None:
    module = order_dispatch
    base = dict(
        vm_id="v",
        ovmf_path="/o",
        kernel_path="/k",
        initrd_path="/i",
        cmdline="ro",
        luks_disk_path="/l",
        luks_disk_size_gb=1,
        rootfs_data_path="/r",
        rootfs_hash_path="/h",
        cpu_count=1,
        memory_mb=1,
        cose_ticket=b"c",
    )
    plain = module.build_launch_payload(**base)
    assert module.build_launch_payload(**base, extra_disks=[]) == plain
    assert "extra_disks" not in plain
    disks = [{"slot": "x0", "kind": "dedicated", "disk_id": "wwn-0x01"}]
    assert module.build_launch_payload(**base, extra_disks=disks) == {**plain, "extra_disks": disks}


_REAL_BIN = Path(settings.VALI_TICKET_VALIDATOR_BIN)


@pytest.mark.skipif(not _REAL_BIN.is_file(), reason=f"Rust validator not built at {_REAL_BIN}")
def test_the_real_encoder_carries_the_disks_and_refuses_them_out_of_step() -> None:
    """The order bridge re-serialises field by field: it must carry
    `extra_disks` (never drop them, the #365 lesson) and only with the
    measured slots."""
    disks = [{"slot": "x0", "kind": "dedicated", "disk_id": "wwn-0x5000c500a1b2c3d4"}]
    base = dict(
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
    )

    def encode(cmdline: str) -> bytes:
        payload = order_dispatch.build_launch_payload(**base, cmdline=cmdline)
        return order_dispatch._encode_order_body(
            order_id="o",
            kind="launch",
            target_miner_id="m",
            issued_at_unix=1_770_000_000,
            payload_json=json.dumps(payload).encode(),
        )

    body = encode("ro hippius.dedicated=x0:22300")
    assert b"extra_disks" in body and b"wwn-0x5000c500a1b2c3d4" in body
    with pytest.raises(order_dispatch.OrderDispatchError):
        encode("ro")


# ── the placement ───────────────────────────────────────────────────


def _actor() -> ServiceClient:
    return ServiceClient.objects.create(scope=PrincipalScope.OPERATOR.value, name="launcher")


def _fleet(monkeypatch, *seeds: int) -> list[Any]:
    miners = [_register_miner(s) for s in seeds]
    for m in miners:
        capable(m.chain_node_id)
    monkeypatch.setattr(
        chain, "read_miner_status", lambda: make_snapshot(10, [make_miner(s) for s in seeds])
    )
    return miners


def _plain_spec(**kw: Any) -> launch.LaunchSpec:
    from .test_launch_service import _spec as service_spec

    return service_spec(dedicated_disks=GOOD, pinned_ack=True, **kw)


def _outcome(disposition: str, *, registered: bool = False) -> launch.LaunchOutcome:
    return launch.LaunchOutcome(
        disposition=disposition,
        emit={"ok": disposition == launch.ACCEPTED, "outcome": "x"},
        exit_code=0,
        cose_ticket=b"cose" if disposition == launch.ACCEPTED else None,
        ticket_id="tk" if disposition == launch.ACCEPTED else None,
        registered=registered,
    )


@override_settings(**ON)
def test_the_placement_assigns_the_disks_of_the_chosen_node(monkeypatch) -> None:
    m1, m2 = _fleet(monkeypatch, 1, 2)
    make_disk("wwn-0x11", node=m1.chain_node_id)
    make_disk("wwn-0x21", node=m2.chain_node_id)
    make_disk("wwn-0x22", node=m2.chain_node_id)
    seen: list[list] = []

    def fake(spec, miner, **_k):
        seen.append(dedicated.extra_disks(spec.vm_id, miner.chain_node_id))
        return _outcome(launch.ACCEPTED)

    monkeypatch.setattr(launch, "launch_on_miner", fake)
    result = launch.launch_vm(_plain_spec(), _actor())
    assert result.ok and result.miner_node_id == m2.chain_node_id
    assert sorted(d.disk_id for d in seen[0]) == ["wwn-0x21", "wwn-0x22"]
    placement = Placement.objects.get(status=PlacementStatus.BOUND.value)
    assert set(
        PlacementDisk.objects.filter(placement=placement).values_list("slot", flat=True)
    ) == {"x0", "x1"}
    assert DedicatedDisk.objects.get(disk_id="wwn-0x11").state == "free"


@override_settings(**ON)
@pytest.mark.parametrize(
    ("disks", "cordon", "outcome"),
    [
        ((), False, "no-dedicated-capacity"),
        (("wwn-0x11",), False, "no-dedicated-capacity"),
        (("wwn-0x11", "wwn-0x12"), True, "no-host-fits-disks"),
    ],
)
def test_the_async_placement_failures(monkeypatch, disks, cordon, outcome) -> None:
    (m1,) = _fleet(monkeypatch, 1)
    for d in disks:
        make_disk(d, node=m1.chain_node_id)
    if cordon:
        MinerCapacity.objects.filter(miner_node_id=m1.chain_node_id).update(
            cordoned_at=timezone.now(), cordon_reason="ops"
        )
    monkeypatch.setattr(launch, "launch_on_miner", lambda *a, **k: pytest.fail("dispatched"))
    result = launch.launch_vm(_plain_spec(), _actor())
    assert (result.ok, result.outcome) == (False, outcome)
    assert not Placement.objects.exists()


@override_settings(**ON)
def test_an_attempt_that_failed_before_the_register_gives_its_disks_back(monkeypatch) -> None:
    m1, m2 = _fleet(monkeypatch, 1, 2)
    for seed, node in ((1, m1), (2, m2)):
        make_disk(f"wwn-0x{seed}1", node=node.chain_node_id)
        make_disk(f"wwn-0x{seed}2", node=node.chain_node_id)
    calls: list[str] = []

    def fake(spec, miner, **_k):
        calls.append(miner.chain_node_id)
        if len(calls) == 1:
            return _outcome(launch.RETRIABLE)
        return _outcome(launch.ACCEPTED)

    monkeypatch.setattr(launch, "launch_on_miner", fake)
    result = launch.launch_vm(_plain_spec(), _actor())
    assert result.ok
    first, second = calls
    assert set(
        DedicatedDisk.objects.filter(miner_node_id=first).values_list("state", flat=True)
    ) == {"free"}
    assert set(
        DedicatedDisk.objects.filter(miner_node_id=second).values_list("state", flat=True)
    ) == {"assigned"}
    failed = Placement.objects.get(status=PlacementStatus.FAILED.value)
    assert not PlacementDisk.objects.filter(placement=failed).exists()


@override_settings(**ON)
def test_an_attempt_that_failed_after_the_register_keeps_its_disks(monkeypatch) -> None:
    (m1,) = _fleet(monkeypatch, 1)
    make_disk("wwn-0x11", node=m1.chain_node_id)
    make_disk("wwn-0x12", node=m1.chain_node_id)
    monkeypatch.setattr(
        launch, "launch_on_miner", lambda *a, **k: _outcome(launch.TERMINAL, registered=True)
    )
    result = launch.launch_vm(_plain_spec(), _actor())
    assert not result.ok
    assert set(DedicatedDisk.objects.values_list("state", flat=True)) == {"assigned"}


@override_settings(**ON)
def test_disks_taken_by_a_concurrent_placement_place_elsewhere_and_write_nothing(
    monkeypatch,
) -> None:
    m1, m2 = _fleet(monkeypatch, 1, 2)
    for seed, node in ((1, m1), (2, m2)):
        make_disk(f"wwn-0x{seed}1", node=node.chain_node_id)
        make_disk(f"wwn-0x{seed}2", node=node.chain_node_id)
    # A concurrent placement took one of the miner's disks after the
    # scheduler counted them: the first count is stale.
    DedicatedDisk.objects.filter(disk_id="wwn-0x11").update(
        state="assigned", assigned_vm=make_vm("vm-rival", "lease-r"), assigned_slot="x0"
    )
    real_counts = dedicated.free_counts
    counts: list[int] = []

    def stale(request, node_ids):
        counts.append(1)
        live = real_counts(request, node_ids)
        return {**live, m1.chain_node_id: 2} if len(counts) == 1 else live

    monkeypatch.setattr(dedicated, "free_counts", stale)
    monkeypatch.setattr(launch, "launch_on_miner", lambda *a, **k: _outcome(launch.ACCEPTED))
    # One miner attempt is enough: a lost race does not spend one.
    result = launch.launch_vm(_plain_spec(), _actor(), max_attempts=1)
    assert result.ok and result.miner_node_id == m2.chain_node_id
    assert [a["disposition"] for a in result.attempts] == ["dedicated-disks-taken", "accepted"]
    # The raced attempt's placement was rolled back with its disks.
    assert [p.miner_node_id for p in Placement.objects.all()] == [m2.chain_node_id]
    assert DedicatedDisk.objects.get(disk_id="wwn-0x12").state == "free"


@override_settings(**ON)
def test_a_node_that_still_has_enough_after_a_lost_race_is_asked_again(monkeypatch) -> None:
    (m1,) = _fleet(monkeypatch, 1)
    make_disk("wwn-0x11", node=m1.chain_node_id)
    make_disk("wwn-0x12", node=m1.chain_node_id)
    real = dedicated.assign
    lost: list[int] = []

    def assign(placement, vm, request):
        if not lost:
            lost.append(1)
            raise dedicated.DisksTaken("lost a race")
        return real(placement, vm, request)

    monkeypatch.setattr(dedicated, "assign", assign)
    monkeypatch.setattr(launch, "launch_on_miner", lambda *a, **k: _outcome(launch.ACCEPTED))
    result = launch.launch_vm(_plain_spec(), _actor(), max_attempts=1)
    assert result.ok and result.miner_node_id == m1.chain_node_id


@override_settings(**ON)
def test_a_node_lost_again_and_again_is_finally_excluded(monkeypatch) -> None:
    (m1,) = _fleet(monkeypatch, 1)
    make_disk("wwn-0x11", node=m1.chain_node_id)
    make_disk("wwn-0x12", node=m1.chain_node_id)

    def assign(placement, vm, request):
        raise dedicated.DisksTaken("lost a race")

    monkeypatch.setattr(dedicated, "assign", assign)
    monkeypatch.setattr(launch, "launch_on_miner", lambda *a, **k: pytest.fail("dispatched"))
    result = launch.launch_vm(_plain_spec(), _actor(), max_attempts=1)
    assert not result.ok
    assert len(result.attempts) == launch._MAX_DEDICATED_RACES + 1
    assert not Placement.objects.exists()


@override_settings(**ON)
def test_a_retry_after_a_registered_attempt_never_gives_the_disks_back(monkeypatch) -> None:
    """The first attempt got past the KBS register (its order named the
    disks); its same-miner retry then fails before the register: the disks
    stay with the VM, whatever the last retry's own flag says."""
    (m1,) = _fleet(monkeypatch, 1)
    make_disk("wwn-0x11", node=m1.chain_node_id)
    make_disk("wwn-0x12", node=m1.chain_node_id)
    monkeypatch.setattr(launch, "dispatch_retry_backoff_s", lambda: 0.0)
    outcomes = iter(
        [_outcome(launch.RETRIABLE, registered=True), _outcome(launch.TERMINAL, registered=False)]
    )
    monkeypatch.setattr(launch, "launch_on_miner", lambda *a, **k: next(outcomes))
    result = launch.launch_vm(_plain_spec(), _actor())
    assert not result.ok
    assert set(DedicatedDisk.objects.values_list("state", flat=True)) == {"assigned"}


@override_settings(**ON)
def test_a_second_launch_of_the_vm_takes_its_own_disks_again(monkeypatch) -> None:
    """A VM whose earlier attempt kept its disks is placed only on their
    node, with the same disks and slots — never a second set."""
    m1, m2 = _fleet(monkeypatch, 1, 2)
    for i in range(3):
        make_disk(f"wwn-0x1{i}", node=m1.chain_node_id)
    make_disk("wwn-0x21", node=m2.chain_node_id)
    make_disk("wwn-0x22", node=m2.chain_node_id)
    monkeypatch.setattr(
        launch, "launch_on_miner", lambda *a, **k: _outcome(launch.TERMINAL, registered=True)
    )
    actor = _actor()
    launch.launch_vm(_plain_spec(), actor)
    held = dict(
        DedicatedDisk.objects.filter(state="assigned").values_list("disk_id", "assigned_slot")
    )
    assert len(held) == 2
    seen: list[list] = []

    def fake(spec, miner, **_k):
        seen.append(dedicated.extra_disks(spec.vm_id, miner.chain_node_id))
        return _outcome(launch.TERMINAL, registered=False)

    monkeypatch.setattr(launch, "launch_on_miner", fake)
    launch.launch_vm(_plain_spec(), actor)
    assert {d.disk_id: d.slot for d in seen[0]} == held
    # The failed attempt did not give back the disks it reused.
    assert (
        dict(DedicatedDisk.objects.filter(state="assigned").values_list("disk_id", "assigned_slot"))
        == held
    )
    assert DedicatedDisk.objects.filter(state="free").count() == 3


def test_a_forced_launch_refuses_a_vm_with_dedicated_disks() -> None:
    _plain = _plain_spec()
    with pytest.raises(launch.LaunchConfigError, match="dedicated disks"):
        launch._refuse_pinned_forced_launch(_plain)
    from .test_launch_service import _spec as service_spec

    plain = service_spec(vm_id="vm-plain-forced")
    launch._refuse_pinned_forced_launch(plain)  # nothing to refuse
    vm = make_vm("vm-plain-forced", "lease-f")
    make_disk("wwn-0x01", state="assigned", assigned_vm=vm, assigned_slot="x0")
    with pytest.raises(launch.LaunchConfigError):
        launch._refuse_pinned_forced_launch(plain)


def test_the_operator_forced_launch_refuses_before_any_row(monkeypatch) -> None:
    miner = _register_miner(6)
    monkeypatch.setattr(launch, "launch_on_miner", lambda *a, **k: pytest.fail("launched"))
    with pytest.raises(launch.LaunchConfigError, match="dedicated disks"):
        launch.launch_on_named_miner(_plain_spec(), miner, decided_by=_actor())
    assert not Placement.objects.exists()


def test_the_hand_built_launch_command_refuses_a_pinned_vm(tmp_path) -> None:
    from django.core.management import CommandError, call_command

    miner = _register_miner(5)
    vm = make_vm("vm-cmd", "lease-c")
    make_disk("wwn-0x01", state="assigned", assigned_vm=vm, assigned_slot="x0")
    ticket = tmp_path / "t.cose"
    ticket.write_bytes(b"cose")
    with pytest.raises(CommandError, match="dedicated disks"):
        call_command(
            "vali_dispatch_launch",
            miner_id=miner.miner_id,
            vm_id="vm-cmd",
            order_id="o-1",
            cpu_count=1,
            memory_mb=1024,
            cose_ticket_path=str(ticket),
        )


def test_a_forced_teardown_releases_the_disks(monkeypatch) -> None:
    from apps.orchestration import effects, teardown

    vm = make_vm("vm-td", "lease-td")
    make_disk("wwn-0x01", state="assigned", assigned_vm=vm, assigned_slot="x0")
    for fn in ("dispatch_destroy", "crypto_erase_kek_transit", "revoke_netbird"):
        monkeypatch.setattr(effects, fn, lambda *_a, **_k: None)
    teardown.force_destroy("vm-td", handoff_reason="t", label="t")
    assert DedicatedDisk.objects.get(disk_id="wwn-0x01").state == "released"


# ── the read-back ───────────────────────────────────────────────────


def _agent_reports_held(vm: Vm) -> None:
    """The agent's v7 report after the launch: it holds the VM's disks."""
    DedicatedDisk.objects.filter(assigned_vm=vm).update(
        reported_state="assigned", reported_vm_id=vm.vm_id, reported_at=timezone.now()
    )


def test_before_the_agent_reports_the_disks_held_they_read_missing() -> None:
    capable(node_id(1))
    vm = make_vm("vm-fresh", "lease-f")
    placement = make_placement(vm, node_id(1), status=PlacementStatus.BOUND.value)
    make_disk("wwn-0x01")
    with override_settings(**ON):
        dedicated.assign(placement, vm, dedicated.DedicatedRequest("hdd", 1, 16000))
    assert dedicated.read_back(vm, os_disk=(40, "nvme"))["disks"][1]["state"] == "missing"
    _agent_reports_held(vm)
    assert dedicated.read_back(vm, os_disk=(40, "nvme"))["disks"][1]["state"] == "attached"


def _ok_launch_vm_with_disks(spec, decided_by, *, on_phase=None, queued_for_s=0.0):
    miner = _register_miner(7)
    capable(miner.chain_node_id)
    vm = Vm.objects.get(vm_id=spec.vm_id)
    placement = make_placement(vm, miner.chain_node_id, status=PlacementStatus.BOUND.value)
    make_disk("wwn-0x71", node=miner.chain_node_id, size_gib=22354)
    make_disk("wwn-0x72", node=miner.chain_node_id, size_gib=22354)
    dedicated.assign(placement, vm, dedicated.DedicatedRequest("hdd", 2, 16000))
    _agent_reports_held(vm)
    return launch.LaunchResult(
        ok=True,
        outcome="miner-accepted",
        vm_id=spec.vm_id,
        miner_id=miner.miner_id,
        miner_node_id=miner.chain_node_id,
        ticket_id="tk-1",
        placement_id=str(placement.id),
        emit={"ok": True},
    )


def _queued(spec_extra: dict[str, Any]) -> LaunchJob:
    actor = _actor()
    Vm.objects.create(vm_id="vm-rb", tenant_id="t-api", state="active", host="", generation=1)
    spec = launch_jobs._build_spec_json(_intent(vm_id="vm-rb"))
    spec.update(spec_extra)
    return LaunchJob.objects.create(
        job_id="job-rb",
        vm_id="vm-rb",
        tenant_id="t-api",
        flavor="small",
        spec_json=spec,
        userdata_vault_path="secret/x",
        userdata_vault_version=1,
        kek_vault_path="secret/k",
        state=LaunchJobState.QUEUED.value,
        phase="queued",
        phase_started_at=timezone.now(),
        decided_by=actor,
    )


@override_settings(**ON)
@pytest.mark.parametrize("pinned", [True, False])
def test_the_job_result_carries_pinned_and_disks_only_with_dedicated_disks(
    monkeypatch, pinned
) -> None:
    job = _queued({"dedicated_disks": GOOD, "pinned_ack": True} if pinned else {})
    monkeypatch.setattr(launch, "open_userdata_intake_copy", lambda *a, **k: b"#cloud-config\n")
    monkeypatch.setattr(launch_jobs.launch, "launch_vm", _ok_launch_vm_with_disks)
    assert launch_jobs.tick_once() is True
    job.refresh_from_db()
    assert job.state == LaunchJobState.SUCCEEDED.value, job.reason
    result = job.result_json
    if not pinned:
        assert "pinned" not in result and "disks" not in result
        return
    assert result["pinned"] is True
    assert result["disks"] == [
        {"slot": "os", "kind": "pool", "size_gb": 40, "tier": "nvme", "state": "attached"},
        {"slot": "x0", "kind": "dedicated", "size_gb": 22300, "tier": "hdd", "state": "attached"},
        {"slot": "x1", "kind": "dedicated", "size_gb": 22300, "tier": "hdd", "state": "attached"},
    ]
    assert "wwn-" not in str(result)


def test_get_vm_state_carries_pinned_and_disks_only_with_dedicated_disks(root_client) -> None:

    plain = make_vm("vm-plain", "lease-p")
    pinned = make_vm("vm-pinned", "lease-q")
    capable(node_id(1))
    placement = make_placement(pinned, node_id(1), status=PlacementStatus.BOUND.value)
    make_disk("wwn-0x01")
    with override_settings(**ON):
        dedicated.assign(placement, pinned, dedicated.DedicatedRequest("hdd", 1, 16000))
    _agent_reports_held(pinned)
    with override_settings(**ON):
        body = root_client.get(reverse("vm_state", args=["vm-pinned"])).json()
        before = root_client.get(reverse("vm_state", args=["vm-plain"])).json()
    assert body["pinned"] is True
    assert [d["slot"] for d in body["disks"]] == ["os", "x0"]
    assert body["disks"][1] == {
        "slot": "x0",
        "kind": "dedicated",
        "size_gb": 22300,
        "tier": "hdd",
        "state": "attached",
    }
    assert "pinned" not in before and "disks" not in before
    listed = {v["vm_id"]: v for v in root_client.get(reverse("vm_list")).json()["vms"]}
    assert listed["vm-pinned"]["disks"] == body["disks"]
    assert "disks" not in listed[plain.vm_id]
    assert "wwn-" not in str(body)
