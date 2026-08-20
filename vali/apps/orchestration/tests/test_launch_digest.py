"""C2 — tests for vali's independent SNP launch-digest recompute."""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest
from django.conf import settings

from apps.orchestration.effects import EffectError
from apps.orchestration.services import launch_digest as ld


def _configure(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "VALI_LAUNCH_DIGEST_BIN", "/usr/local/bin/hippius-launch-digest")
    monkeypatch.setattr(settings, "VALI_SNP_OVMF_S3_URI", "s3://b/ovmf/ovmf.fd")
    monkeypatch.setattr(settings, "VALI_SNP_OVMF_SHA256", "ab" * 32)
    monkeypatch.setattr(settings, "VALI_SNP_GUEST_FEATURES", "0x1")


def test_is_enabled_requires_bin_and_ovmf_pin(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "VALI_LAUNCH_DIGEST_BIN", "")
    monkeypatch.setattr(settings, "VALI_SNP_OVMF_S3_URI", "")
    monkeypatch.setattr(settings, "VALI_SNP_OVMF_SHA256", "")
    assert ld.is_enabled() is False
    _configure(monkeypatch)
    assert ld.is_enabled() is True


def test_vcpu_type_maps_chip_id_length_to_generation() -> None:
    assert ld._vcpu_type_for_platform("11" * 8) == "EpycTurin"  # 8-byte chip_id
    assert ld._vcpu_type_for_platform("22" * 64) == "EpycGenoa"  # 64-byte chip_id
    with pytest.raises(EffectError):
        ld._vcpu_type_for_platform("33" * 16)  # unknown length
    with pytest.raises(EffectError):
        ld._vcpu_type_for_platform("nothex")


def test_recompute_disabled_raises_unavailable(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "VALI_LAUNCH_DIGEST_BIN", "")
    monkeypatch.setattr(settings, "VALI_SNP_OVMF_S3_URI", "")
    monkeypatch.setattr(settings, "VALI_SNP_OVMF_SHA256", "")
    with pytest.raises(ld.LaunchDigestUnavailable):
        ld.recompute_expected_digest(
            s3_bucket="b", s3_key_prefix="p", kernel_sha256_hex="a" * 64,
            initrd_sha256_hex="b" * 64, cmdline="root=/dev/vda", cpu_count=2,
            platform_id="11" * 8,
        )


def _fake_fetch(known_sha: dict[str, str]):
    """Return an `_s3_cp` stub that writes bytes whose sha256 the caller
    pinned, keyed by the destination basename."""

    def _cp(s3_uri: str, dest: Path) -> None:
        # Write the exact preimage the test wants for this file so the
        # SHA-verify passes/fails deterministically without real S3.
        name = dest.name
        dest.write_bytes(known_sha.get(name, b"default"))

    return _cp


def test_recompute_happy_path_shells_out_and_returns_digest(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _configure(monkeypatch)
    import hashlib

    # Bytes for each fetched file + their real sha256, so _fetch_verify passes.
    ovmf_b, kernel_b, initrd_b = b"OVMF-bytes", b"KERNEL-bytes", b"INITRD-bytes"
    monkeypatch.setattr(settings, "VALI_SNP_OVMF_SHA256", hashlib.sha256(ovmf_b).hexdigest())
    contents = {"ovmf.fd": ovmf_b, "kernel": kernel_b, "initrd": initrd_b}
    monkeypatch.setattr(ld, "_s3_cp", lambda uri, dest: dest.write_bytes(contents[dest.name]))

    expected = "cd" * 48  # 96-hex

    def _fake_run(argv, **kwargs):
        # Assert the recompute passes the right pinned params to the binary.
        assert "--vcpu-type" in argv and argv[argv.index("--vcpu-type") + 1] == "EpycTurin"
        assert argv[argv.index("--vcpus") + 1] == "2"
        assert argv[argv.index("--guest-features") + 1] == "0x1"
        return subprocess.CompletedProcess(argv, 0, stdout=(expected + "\n").encode(), stderr=b"")

    monkeypatch.setattr(subprocess, "run", _fake_run)

    got = ld.recompute_expected_digest(
        s3_bucket="bkt",
        s3_key_prefix="tenant/vm-1/",
        kernel_sha256_hex=hashlib.sha256(kernel_b).hexdigest(),
        initrd_sha256_hex=hashlib.sha256(initrd_b).hexdigest(),
        cmdline="root=/dev/vda ro",
        cpu_count=2,
        platform_id="11" * 8,  # Turin
    )
    assert got == expected


def test_recompute_kernel_sha_mismatch_fails_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _configure(monkeypatch)
    import hashlib

    ovmf_b = b"OVMF"
    monkeypatch.setattr(settings, "VALI_SNP_OVMF_SHA256", hashlib.sha256(ovmf_b).hexdigest())
    # kernel bytes won't match the pinned kernel sha the caller passes.
    monkeypatch.setattr(
        ld, "_s3_cp",
        lambda uri, dest: dest.write_bytes(ovmf_b if dest.name == "ovmf.fd" else b"WRONG"),
    )
    with pytest.raises(EffectError, match="kernel-sha-mismatch"):
        ld.recompute_expected_digest(
            s3_bucket="b", s3_key_prefix="p", kernel_sha256_hex="a" * 64,
            initrd_sha256_hex="b" * 64, cmdline="x", cpu_count=1,
            platform_id="11" * 8,
        )
