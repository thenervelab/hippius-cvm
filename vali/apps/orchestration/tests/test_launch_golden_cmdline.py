"""golden-bake (option b) — the MEASURED disk-integrity cmdline binding.

`launch._augment_disk_binding` folds the boot disk's integrity anchor into
the measured kernel cmdline, gated on `LaunchSpec.disk_mode`:

  - `legacy_luks` (default) → `hippius.luks_header_sha256=<hex>`, the
    per-VM LUKS header MAC. MUST stay byte-identical to the pre-golden
    behaviour — the launch digest covers the cmdline bytes, so any drift
    changes every legacy VM's measurement.
  - `golden_verity_overlay` → `dm-verity.root=<64-hex>`, the shared
    read-only dm-verity golden base's root hash. The LUKS-header token is
    DROPPED (the base is unkeyed dm-verity, not LUKS). `dm-verity.root` is
    the EXACT token the guest's §21 verity stage reads
    (`agent-initramfs::stages::verity::CMDLINE_VERITY_ROOT_KEY`).

The golden branch is plumbed-but-inert (no caller passes golden yet), so
these pure-function tests are the correctness gate until the E2E.
"""

from __future__ import annotations

import pytest

from apps.orchestration.services import launch

# A LUKS-header-shaped 64-hex and a distinct verity-root-shaped 64-hex.
_LUKS_HEADER = "a" * 64
_VERITY_ROOT = "b3" * 32  # 64 lowercase hex


def _spec(**overrides) -> launch.LaunchSpec:
    base = dict(
        tenant_id="t-golden",
        user_id="u-1",
        vm_id="vm-golden-1",
        lease_id="lease-1",
        s3_bucket="b",
        s3_key_prefix="tenant/x/",
        luks_disk_sha256_hex="a" * 64,
        kernel_sha256_hex="a" * 64,
        initrd_sha256_hex="a" * 64,
        luks_header_sha256_hex=_LUKS_HEADER,
        flavor="small",
        cmdline="ro quiet",
        kek_bytes=b"\x00" * 32,
        userdata=b"#cloud-config\n",
    )
    base.update(overrides)
    return launch.LaunchSpec(**base)


# ─── legacy_luks (default) — byte-identical to the pre-golden path ─────


def test_default_disk_mode_is_legacy_luks() -> None:
    assert _spec().disk_mode == launch._DISK_MODE_LEGACY_LUKS
    assert _spec().disk_mode == "legacy_luks"


def test_legacy_binds_luks_header_and_not_verity() -> None:
    out = launch._augment_disk_binding("ro quiet", _spec())
    # The LUKS header MAC is appended (byte-identical to the old direct
    # `_augment_cmdline_with_token(_LUKS_HEADER_CMDLINE_KEY, …)` call).
    assert out == f"ro quiet hippius.luks_header_sha256={_LUKS_HEADER}"
    assert "dm-verity.root=" not in out


def test_legacy_is_byte_identical_to_the_direct_augment() -> None:
    # The refactor MUST NOT change the emitted bytes for legacy VMs.
    spec = _spec()
    via_helper = launch._augment_disk_binding(spec.cmdline, spec)
    direct = launch._augment_cmdline_with_token(
        spec.cmdline,
        launch._LUKS_HEADER_CMDLINE_KEY,
        spec.luks_header_sha256_hex,
    )
    assert via_helper == direct


def test_legacy_leaves_an_operator_baked_header_untouched() -> None:
    pre = f"ro hippius.luks_header_sha256={'c' * 64}"
    out = launch._augment_disk_binding(pre, _spec())
    assert out == pre  # idempotent — first token wins


# ─── golden_verity_overlay — dm-verity.root, no luks header ───────────


def test_golden_binds_verity_root_and_drops_luks_header() -> None:
    spec = _spec(
        disk_mode="golden_verity_overlay", verity_root_hash_hex=_VERITY_ROOT
    )
    out = launch._augment_disk_binding("ro quiet", spec)
    # The verity root hash the guest reads is bound + the golden boot
    # selector so the guest owns root assembly (PR3)…
    assert out == f"ro quiet dm-verity.root={_VERITY_ROOT} boot=hippius-golden"
    # …and the LUKS-header token is NOT present (the base is not LUKS).
    assert "hippius.luks_header_sha256=" not in out


def test_golden_token_key_matches_the_guest_parser() -> None:
    # The guest reads exactly `dm-verity.root=` (no `hippius.` prefix) —
    # `agent-initramfs::stages::verity::CMDLINE_VERITY_ROOT_KEY`.
    assert launch._VERITY_ROOT_CMDLINE_KEY == "dm-verity.root"


def test_golden_rejects_a_malformed_root_hash() -> None:
    for bad in ("", "abc", "z" * 64, "A" * 64, "b3" * 31):
        spec = _spec(disk_mode="golden_verity_overlay", verity_root_hash_hex=bad)
        with pytest.raises(launch.LaunchConfigError):
            launch._augment_disk_binding("ro quiet", spec)


def test_golden_requires_a_root_hash() -> None:
    # disk_mode golden but the field left at its empty default → fail closed.
    spec = _spec(disk_mode="golden_verity_overlay")
    assert spec.verity_root_hash_hex == ""
    with pytest.raises(launch.LaunchConfigError):
        launch._augment_disk_binding("ro quiet", spec)


def test_golden_leaves_an_operator_baked_verity_root_untouched() -> None:
    pre = f"ro dm-verity.root={'d' * 64}"
    spec = _spec(
        disk_mode="golden_verity_overlay", verity_root_hash_hex=_VERITY_ROOT
    )
    out = launch._augment_disk_binding(pre, spec)
    # The pre-baked verity root wins (idempotent); the golden boot
    # selector is still appended (it was absent).
    assert out == f"{pre} boot=hippius-golden"
    assert out.count("dm-verity.root=") == 1


# ─── unknown mode — fail closed ───────────────────────────────────────


# ─── golden-bake PR4: preflight artifact selection ────────────────────


def test_legacy_preflight_fetches_the_per_vm_qcow2() -> None:
    arts = launch._select_preflight_artifacts(_spec())
    assert arts.luks_disk.key.endswith("/tenant.qcow2")
    assert arts.rootfs_hash is None
    assert arts.kernel.key.endswith("/tenant.vmlinuz")
    assert arts.initrd.key.endswith("/tenant.initrd.img")


def test_golden_preflight_fetches_the_shared_base_not_a_qcow2() -> None:
    spec = _spec(
        disk_mode="golden_verity_overlay",
        verity_root_hash_hex=_VERITY_ROOT,
        rootfs_img_sha256_hex="c" * 64,
        rootfs_verity_sha256_hex="d" * 64,
    )
    arts = launch._select_preflight_artifacts(spec)
    # NO per-VM qcow2: the boot disk slot is the SHARED golden rootfs.img.
    assert arts.luks_disk.key.endswith("/rootfs.img")
    assert arts.luks_disk.sha256_hex == "c" * 64
    assert arts.rootfs_hash is not None
    assert arts.rootfs_hash.key.endswith("/rootfs.verity")
    assert arts.rootfs_hash.sha256_hex == "d" * 64
    # kernel/initrd unchanged.
    assert arts.kernel.key.endswith("/tenant.vmlinuz")


def test_golden_preflight_requires_the_base_shas() -> None:
    spec = _spec(
        disk_mode="golden_verity_overlay",
        verity_root_hash_hex=_VERITY_ROOT,
        # rootfs_img/verity shas left empty ⇒ fail closed.
    )
    with pytest.raises(ValueError, match="rootfs_img_sha256_hex"):
        launch._select_preflight_artifacts(spec)


def test_unknown_disk_mode_raises() -> None:
    spec = _spec(disk_mode="something_else")
    with pytest.raises(launch.LaunchConfigError):
        launch._augment_disk_binding("ro quiet", spec)
