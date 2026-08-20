"""P9/#16 — the base image is a per-VM lifecycle value, resolved by
CONTENT, never a shared mutable path.

## The defect

`LaunchSpec.rootfs_data_path` defaults to `/var/lib/hippius-miner/
rootfs.img`: fixed, shared and MUTABLE. Verified live on 2026-08-13:

  - `miner-2` — that path is a SYMLINK to `staging/rootfs.img`
    (17 MB, 2026-06-29, the legacy base every legacy VM boots);
  - `miner-3` — that path is a REAL 709 MB file dated
    2026-07-29 14:20 whose sha256 (`c6ffbc4a…`) is byte-identical to
    `staging/realtenant-ubuntu-1/rootfs.img`.

One spec, two miners, two different operating systems — and a §25
dest-activation was what put the 709 MB file there, because
`effects._launch_paths` resolved `rootfs_data_path` from the SPEC and the
dest miner STAGES to whatever path the order names. The same order aimed
at miner-2 would have followed the symlink and replaced the shared legacy
base under every VM booting it.

These tests kill exactly that, one mutation at a time.
"""

from __future__ import annotations

import secrets

import pytest
from django.utils import timezone

from apps.lifecycle.models import VmBaseImage
from apps.orchestration import effects
from apps.orchestration.models import LaunchJob, LaunchJobState
from apps.orchestration.services import launch

from .factories import make_service_client, make_vm

pytestmark = pytest.mark.django_db

_GOLDEN = "golden_verity_overlay"
_LEGACY = "legacy_luks"
_SHARED_IMG = "/var/lib/hippius-miner/rootfs.img"
_SHARED_VERITY = "/var/lib/hippius-miner/rootfs.verity"


def _spec(**overrides) -> launch.LaunchSpec:
    base = dict(
        tenant_id="t-1",
        user_id="u-1",
        vm_id="realtenant-ubuntu-1",
        lease_id="lease-1",
        s3_bucket="b",
        s3_key_prefix="tenant/x/",
        luks_disk_sha256_hex="a" * 64,
        kernel_sha256_hex="a" * 64,
        initrd_sha256_hex="a" * 64,
        luks_header_sha256_hex="",
        flavor="small",
        cmdline="ro quiet",
        kek_bytes=b"\x00" * 32,
        userdata=b"#cloud-config\n",
        disk_mode=_GOLDEN,
        verity_root_hash_hex="b3" * 32,
        rootfs_img_sha256_hex="c" * 64,
        rootfs_verity_sha256_hex="d" * 64,
    )
    base.update(overrides)
    return launch.LaunchSpec(**base)


# ─── MUTATION: two miners resolve the same spec to different content ──


def test_a_shared_base_path_is_refused_for_a_golden_launch() -> None:
    # The exact value the spec defaults to — and the exact path that means
    # a 17 MB legacy base on miner-2 and a 709 MB golden base on miner-3.
    with pytest.raises(ValueError, match="shared, mutable base image"):
        launch._assert_per_vm_base(
            "realtenant-ubuntu-1", _SHARED_IMG, _SHARED_VERITY
        )


def test_another_vms_staged_base_is_refused() -> None:
    # A per-VM-SHAPED path that belongs to a DIFFERENT VM. Booting it
    # would be cross-tenant, and staging onto it is a clobber.
    with pytest.raises(ValueError, match="not inside this VM's own staging"):
        launch._assert_per_vm_base(
            "realtenant-ubuntu-1",
            "/var/lib/hippius-miner/staging/p1-liveness-1/rootfs.img",
            "/var/lib/hippius-miner/staging/p1-liveness-1/rootfs.verity",
        )


def test_a_missing_base_path_is_refused_rather_than_defaulted() -> None:
    # An agent too old to resolve the base per-VM returns nothing. The old
    # code silently fell back to the shared path; there is nothing to fall
    # back TO, so this must be terminal.
    with pytest.raises(ValueError, match="did not\n?\\s*return a per-VM staged base"):
        launch._assert_per_vm_base("realtenant-ubuntu-1", "", "")


def test_the_vms_own_staged_base_is_accepted() -> None:
    launch._assert_per_vm_base(
        "realtenant-ubuntu-1",
        "/var/lib/hippius-miner/staging/realtenant-ubuntu-1/rootfs.img",
        "/var/lib/hippius-miner/staging/realtenant-ubuntu-1/rootfs.verity",
    )


def test_path_traversal_cannot_dress_a_shared_path_as_per_vm() -> None:
    # `…/staging/realtenant-ubuntu-1/../rootfs.img` normalises to the
    # SHARED path. A naive "does it contain the vm_id" check would pass it.
    with pytest.raises(ValueError):
        launch._assert_per_vm_base(
            "realtenant-ubuntu-1",
            "/var/lib/hippius-miner/staging/realtenant-ubuntu-1/../rootfs.img",
            "/var/lib/hippius-miner/staging/realtenant-ubuntu-1/rootfs.verity",
        )


def test_a_legacy_launch_still_uses_its_operator_staged_shared_rootfs() -> None:
    # BACKWARD COMPATIBILITY: on the legacy path the rootfs really IS an
    # operator-pre-staged shared file the miner never fetches. The gate is
    # golden-only and must not break legacy VMs.
    spec = _spec(disk_mode=_LEGACY, luks_header_sha256_hex="a" * 64)
    assert spec.rootfs_data_path == _SHARED_IMG


# ─── the per-VM base record ───────────────────────────────────────────


def test_the_dispatched_base_is_recorded_by_content() -> None:
    spec = _spec(bake_id="bake-abc", image_name="ubuntu")
    launch._record_base_image(
        spec,
        rootfs_data_path="/var/lib/hippius-miner/staging/realtenant-ubuntu-1/rootfs.img",
        rootfs_hash_path="/var/lib/hippius-miner/staging/realtenant-ubuntu-1/rootfs.verity",
    )
    row = VmBaseImage.objects.get(vm_id="realtenant-ubuntu-1")
    # CONTENT is the identity…
    assert row.rootfs_img_sha256_hex == "c" * 64
    assert row.rootfs_verity_sha256_hex == "d" * 64
    assert row.verity_root_hash_hex == "b3" * 32
    # …and the NAMED base is what P1 needs to move the VM onto a
    # keepalive-bearing image.
    assert row.bake_id == "bake-abc"
    assert row.image_name == "ubuntu"
    assert row.disk_mode == _GOLDEN
    # The paths are recorded as evidence of the per-VM layout.
    assert row.rootfs_data_path.endswith("/realtenant-ubuntu-1/rootfs.img")


def test_a_relaunch_onto_a_newer_base_updates_the_record() -> None:
    # Without this the record would freeze at the FIRST base a VM ever
    # booted — i.e. it would still claim `realtenant-ubuntu-1` is on the
    # 2026-07-29 image after P1 moved it.
    launch._record_base_image(
        _spec(bake_id="bake-old", rootfs_img_sha256_hex="1" * 64),
        rootfs_data_path="/var/lib/hippius-miner/staging/realtenant-ubuntu-1/rootfs.img",
        rootfs_hash_path="/var/lib/hippius-miner/staging/realtenant-ubuntu-1/rootfs.verity",
    )
    launch._record_base_image(
        _spec(bake_id="bake-keepalive", rootfs_img_sha256_hex="2" * 64),
        rootfs_data_path="/var/lib/hippius-miner/staging/realtenant-ubuntu-1/rootfs.img",
        rootfs_hash_path="/var/lib/hippius-miner/staging/realtenant-ubuntu-1/rootfs.verity",
    )
    assert VmBaseImage.objects.filter(vm_id="realtenant-ubuntu-1").count() == 1
    row = VmBaseImage.objects.get(vm_id="realtenant-ubuntu-1")
    assert row.rootfs_img_sha256_hex == "2" * 64
    assert row.bake_id == "bake-keepalive"


def test_which_vms_boot_a_given_base_is_answerable() -> None:
    # The P1 query: enumerate every VM on a base that predates the
    # `hippius-agent-keepalive` shim. Impossible before this record — the
    # only per-VM value was a path shared by every VM on the host.
    stale, fresh = "9" * 64, "f" * 64
    for vm_id, sha in (("vm-a", stale), ("vm-b", stale), ("vm-c", fresh)):
        launch._record_base_image(
            _spec(vm_id=vm_id, rootfs_img_sha256_hex=sha),
            rootfs_data_path=f"/var/lib/hippius-miner/staging/{vm_id}/rootfs.img",
            rootfs_hash_path=f"/var/lib/hippius-miner/staging/{vm_id}/rootfs.verity",
        )
    on_stale = set(
        VmBaseImage.objects.filter(rootfs_img_sha256_hex=stale).values_list(
            "vm_id", flat=True
        )
    )
    assert on_stale == {"vm-a", "vm-b"}


def test_a_record_failure_never_fails_an_accepted_launch(monkeypatch) -> None:
    # The dispatch has already been ACCEPTED by the miner when this runs.
    # A bookkeeping write must not turn a live VM into a failed launch.
    from apps.lifecycle import models as lifecycle_models

    class Boom:
        @staticmethod
        def update_or_create(**_kw):
            raise RuntimeError("db down")

    monkeypatch.setattr(lifecycle_models.VmBaseImage, "objects", Boom)
    launch._record_base_image(_spec(), rootfs_data_path="x", rootfs_hash_path="y")


# ─── MUTATION: §25 stages a base onto a SHARED path ───────────────────


def _record(vm_id: str, *, disk_mode: str, emit: dict) -> LaunchJob:
    now = timezone.now()
    return LaunchJob.objects.create(
        job_id=secrets.token_hex(16),
        vm_id=vm_id,
        tenant_id="t",
        flavor="small",
        spec_json={
            "disk_mode": disk_mode,
            "vm_id": vm_id,
            "cmdline": "ro quiet",
            "flavor": "small",
            # The shared, mutable defaults every launch record carries.
            "rootfs_data_path": _SHARED_IMG,
            "rootfs_hash_path": _SHARED_VERITY,
        },
        userdata_vault_path=f"x/{vm_id}/userdata",
        userdata_vault_version=1,
        kek_vault_path=f"x/{vm_id}/luks-kek",
        state=LaunchJobState.SUCCEEDED.value,
        phase_started_at=now,
        finished_at=now,
        result_json={"emit": emit},
        decided_by=make_service_client(),
    )


_MEASURED_GOLDEN = "ro quiet dm-verity.root=" + "ab" * 32 + " boot=hippius-golden"


def test_migrate_activate_never_aims_a_golden_base_at_a_shared_path() -> None:
    # THE LIVE DATA-LOSS EVENT. The dest miner stages to the path this
    # dict names; naming the shared one is how miner-3 ended up with a
    # 709 MB `/var/lib/hippius-miner/rootfs.img`, and how the same order
    # would have overwritten miner-2's shared legacy base through a
    # symlink.
    vm = make_vm(vm_id="realtenant-ubuntu-1")
    _record(
        vm.vm_id,
        disk_mode=_GOLDEN,
        emit={
            "measured_cmdline": _MEASURED_GOLDEN,
            "rootfs_data_path": (
                "/var/lib/hippius-miner/staging/realtenant-ubuntu-1/rootfs.img"
            ),
            "rootfs_hash_path": (
                "/var/lib/hippius-miner/staging/realtenant-ubuntu-1/rootfs.verity"
            ),
        },
    )
    paths = effects._launch_paths(vm)
    assert paths["rootfs_data_path"] == (
        "/var/lib/hippius-miner/staging/realtenant-ubuntu-1/rootfs.img"
    )
    assert paths["rootfs_hash_path"] == (
        "/var/lib/hippius-miner/staging/realtenant-ubuntu-1/rootfs.verity"
    )
    for key in ("rootfs_data_path", "rootfs_hash_path", "kernel_path", "initrd_path"):
        assert paths[key] != _SHARED_IMG
        assert paths[key].startswith(
            "/var/lib/hippius-miner/staging/realtenant-ubuntu-1/"
        ), f"{key} escaped the per-VM staging dir: {paths[key]}"


def test_a_golden_record_from_before_this_fix_falls_back_per_vm_not_shared() -> None:
    # Every VM on the fleet TODAY was launched before `rootfs_data_path`
    # was echoed onto the emit. Those records must NOT fall back to the
    # spec's shared path — that is precisely the bytes-clobbering order.
    vm = make_vm(vm_id="realtenant-ubuntu-1")
    _record(vm.vm_id, disk_mode=_GOLDEN, emit={"measured_cmdline": _MEASURED_GOLDEN})
    paths = effects._launch_paths(vm)
    assert paths["rootfs_data_path"] == (
        "/var/lib/hippius-miner/staging/realtenant-ubuntu-1/rootfs.img"
    )
    assert paths["rootfs_hash_path"] == (
        "/var/lib/hippius-miner/staging/realtenant-ubuntu-1/rootfs.verity"
    )
    assert paths["kernel_path"] == (
        "/var/lib/hippius-miner/staging/realtenant-ubuntu-1/tenant.vmlinuz"
    )
    assert paths["initrd_path"] == (
        "/var/lib/hippius-miner/staging/realtenant-ubuntu-1/tenant.initrd.img"
    )


def test_legacy_migration_paths_are_unchanged() -> None:
    # BACKWARD COMPATIBILITY. A legacy VM's rootfs really is the shared
    # operator-pre-staged file, and no `rootfs_data` descriptor is emitted
    # for it unless the launch recorded a sha — so nothing stages onto it
    # and the shared path stays correct. Narrowing the fix to golden is
    # deliberate, and pinned here.
    vm = make_vm(vm_id="legacy-vm-1")
    _record(vm.vm_id, disk_mode=_LEGACY, emit={"measured_cmdline": "ro quiet"})
    paths = effects._launch_paths(vm)
    assert paths["rootfs_data_path"] == _SHARED_IMG
    assert paths["rootfs_hash_path"] == _SHARED_VERITY


# ─── the CALL SITE — a unit test on the helper cannot kill these ──────
#
# Mutation-checked: deleting the `_assert_per_vm_base` call, or restoring
# the `or spec.rootfs_data_path` fallback, leaves every test above green.
# These drive the REAL `launch_on_miner`.


def _golden_launch_spec(**overrides) -> launch.LaunchSpec:
    return _spec(
        vm_id="vm-launch-1",
        userdata=b"#cloud-config\n# {{NETBIRD_SETUP_KEY}}\n",
        **overrides,
    )


def _register_miner():
    from apps.miners.models import MinerIdentity, MinerStatus

    return MinerIdentity.objects.create(
        miner_id="miner-1",
        pubkey_hex=format(1, "064x"),
        platform_id="01" + "cd" * 15,
        netbird_ip="100.64.0.1",
        chain_node_id="ab" * 32,
        last_seen_at=timezone.now(),
        last_heartbeat_sequence=1,
        status=MinerStatus.ACTIVE,
    )


def _stub_choreography(monkeypatch, *, preflight_rootfs) -> None:
    """Reuse `test_launch_service`'s collaborator stubs, then override the
    preflight reply's staged golden base paths."""
    from apps.orchestration.services import preflight as preflight_svc

    from .test_launch_service import _fake_the_launch_choreography

    _fake_the_launch_choreography(monkeypatch, dispatch_ok=True)
    data, hash_ = preflight_rootfs
    monkeypatch.setattr(
        preflight_svc,
        "dispatch_preflight",
        lambda *a, **k: preflight_svc.PreflightResult(
            launch_digest_hex="ab" * 48,
            luks_disk_path="/d.img",
            kernel_path="/k",
            initrd_path="/i",
            rootfs_data_path=data,
            rootfs_hash_path=hash_,
        ),
    )


def test_a_golden_launch_fails_closed_when_the_base_is_not_per_vm(monkeypatch) -> None:
    # An agent too old to stage per-VM returns no base paths. The old code
    # fell back to `/var/lib/hippius-miner/rootfs.img` and dispatched — the
    # VM would boot whatever that path happened to be on THAT miner.
    miner = _register_miner()
    _stub_choreography(monkeypatch, preflight_rootfs=(None, None))

    out = launch.launch_on_miner(_golden_launch_spec(), miner)

    assert out.disposition == launch.TERMINAL, out.emit
    assert out.emit["outcome"] == "golden-base-unresolved"
    # And nothing was recorded as this VM's base.
    assert not VmBaseImage.objects.filter(vm_id="vm-launch-1").exists()


def test_a_golden_launch_fails_closed_on_a_shared_base_path(monkeypatch) -> None:
    miner = _register_miner()
    _stub_choreography(monkeypatch, preflight_rootfs=(_SHARED_IMG, _SHARED_VERITY))

    out = launch.launch_on_miner(_golden_launch_spec(), miner)

    assert out.disposition == launch.TERMINAL, out.emit
    assert out.emit["outcome"] == "golden-base-unresolved"


def test_an_accepted_golden_launch_records_and_echoes_its_per_vm_base(
    monkeypatch,
) -> None:
    miner = _register_miner()
    data = "/var/lib/hippius-miner/staging/vm-launch-1/rootfs.img"
    hash_ = "/var/lib/hippius-miner/staging/vm-launch-1/rootfs.verity"
    _stub_choreography(monkeypatch, preflight_rootfs=(data, hash_))

    out = launch.launch_on_miner(
        _golden_launch_spec(bake_id="bake-abc", image_name="ubuntu"), miner
    )

    assert out.disposition == launch.ACCEPTED, out.emit
    # Echoed onto the launch record — this is what `_launch_paths` reads
    # so a §25 dest stages into the VM's own dir.
    assert out.emit["rootfs_data_path"] == data
    assert out.emit["rootfs_hash_path"] == hash_
    # …and recorded as the VM's base, by content.
    row = VmBaseImage.objects.get(vm_id="vm-launch-1")
    assert row.rootfs_img_sha256_hex == "c" * 64
    assert row.bake_id == "bake-abc"
    assert row.image_name == "ubuntu"
