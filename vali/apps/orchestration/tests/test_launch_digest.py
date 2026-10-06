"""C2 — tests for vali's independent SNP launch-digest recompute."""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest
from django.conf import settings

from apps.orchestration.effects import EffectError
from apps.orchestration.services import launch_digest as ld


@pytest.fixture(autouse=True)
def _isolated_artifact_cache(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    # The fetches go through the per-pod sha-keyed cache; give every test
    # its own so a cached entry never leaks between tests.
    monkeypatch.setattr(settings, "VALI_ARTIFACT_CACHE_DIR", str(tmp_path / "artifact-cache"))


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


_TURIN_CHIP = "11" * 8
_64B_CHIP = "22" * 64  # Genoa AND Milan both report a 64-byte CHIP_ID


@pytest.mark.parametrize("unset", [None, ""])
def test_unset_generation_is_exactly_the_legacy_length_inference(unset) -> None:
    # The live fleet (miner-a Genoa, miner-b/3 Turin) has NO registered
    # generation: its vCPU model must stay byte-for-byte what it was.
    assert ld._vcpu_type_for_platform(_TURIN_CHIP, unset) == "EpycTurin"
    assert ld._vcpu_type_for_platform(_64B_CHIP, unset) == "EpycGenoa"
    for bad in ("33" * 16, "nothex"):
        with pytest.raises(EffectError):
            ld._vcpu_type_for_platform(bad, unset)


@pytest.mark.parametrize(
    ("generation", "platform_id", "vcpu_type"),
    [
        ("turin", _TURIN_CHIP, "EpycTurin"),
        ("genoa", _64B_CHIP, "EpycGenoa"),
        ("milan", _64B_CHIP, "EpycMilan"),
    ],
)
def test_explicit_generation_selects_the_vcpu_model(
    generation: str, platform_id: str, vcpu_type: str
) -> None:
    assert ld._vcpu_type_for_platform(platform_id, generation) == vcpu_type


@pytest.mark.parametrize(
    ("generation", "platform_id"),
    [
        ("turin", _64B_CHIP),
        ("genoa", _TURIN_CHIP),
        ("milan", _TURIN_CHIP),
        ("milan", "33" * 16),
    ],
)
def test_generation_inconsistent_with_chip_id_length_fails_closed(
    generation: str, platform_id: str
) -> None:
    with pytest.raises(EffectError, match="snp-generation-chip-id-mismatch"):
        ld._vcpu_type_for_platform(platform_id, generation)


def test_unknown_generation_and_non_hex_chip_fail_closed() -> None:
    with pytest.raises(EffectError, match="snp-generation-unknown"):
        ld._vcpu_type_for_platform(_64B_CHIP, "bergamo")
    with pytest.raises(EffectError, match="platform-id-not-hex"):
        ld._vcpu_type_for_platform("nothex", "milan")


def test_generation_table_matches_the_model_choices() -> None:
    # One generation the model accepts but the recompute does not know would
    # register cleanly and then refuse every launch.
    from apps.miners.models import SnpGeneration

    assert set(ld.SNP_GENERATION_VCPU) == set(SnpGeneration.values)


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
    pinned, keyed by the object's basename."""

    def _cp(s3_uri: str, dest: Path, **_kw: object) -> None:
        # Write the exact preimage the test wants for this file so the
        # SHA-verify passes/fails deterministically without real S3.
        name = Path(s3_uri).name
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
    contents = {"ovmf.fd": ovmf_b, "tenant.vmlinuz": kernel_b, "tenant.initrd.img": initrd_b}
    monkeypatch.setattr(
        ld, "_s3_cp", lambda uri, dest, **_kw: dest.write_bytes(contents[Path(uri).name])
    )

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


@pytest.mark.parametrize(
    ("generation", "vcpu_type"),
    [(None, "EpycGenoa"), ("genoa", "EpycGenoa"), ("milan", "EpycMilan")],
)
def test_recompute_passes_the_registered_generation_to_the_binary(
    monkeypatch: pytest.MonkeyPatch, generation: str | None, vcpu_type: str
) -> None:
    # A 64-byte CHIP_ID: without a registered generation it is measured as
    # Genoa (unchanged); a Milan host must be measured as EpycMilan.
    _configure(monkeypatch)
    import hashlib

    ovmf_b, kernel_b, initrd_b = b"OVMF-bytes", b"KERNEL-bytes", b"INITRD-bytes"
    monkeypatch.setattr(settings, "VALI_SNP_OVMF_SHA256", hashlib.sha256(ovmf_b).hexdigest())
    contents = {"ovmf.fd": ovmf_b, "tenant.vmlinuz": kernel_b, "tenant.initrd.img": initrd_b}
    monkeypatch.setattr(
        ld, "_s3_cp", lambda uri, dest, **_kw: dest.write_bytes(contents[Path(uri).name])
    )
    seen: list[str] = []

    def _fake_run(argv, **kwargs):
        seen.append(argv[argv.index("--vcpu-type") + 1])
        return subprocess.CompletedProcess(argv, 0, stdout=b"cd" * 48, stderr=b"")

    monkeypatch.setattr(subprocess, "run", _fake_run)
    ld.recompute_expected_digest(
        s3_bucket="bkt",
        s3_key_prefix="tenant/vm-1",
        kernel_sha256_hex=hashlib.sha256(kernel_b).hexdigest(),
        initrd_sha256_hex=hashlib.sha256(initrd_b).hexdigest(),
        cmdline="root=/dev/vda ro",
        cpu_count=2,
        platform_id=_64B_CHIP,
        snp_generation=generation,
    )
    assert seen == [vcpu_type]


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
        lambda uri, dest, **_kw: dest.write_bytes(ovmf_b if uri.endswith("/ovmf.fd") else b"WRONG"),
    )
    with pytest.raises(EffectError, match="kernel-sha-mismatch"):
        ld.recompute_expected_digest(
            s3_bucket="b", s3_key_prefix="p", kernel_sha256_hex="a" * 64,
            initrd_sha256_hex="b" * 64, cmdline="x", cpu_count=1,
            platform_id="11" * 8,
        )
