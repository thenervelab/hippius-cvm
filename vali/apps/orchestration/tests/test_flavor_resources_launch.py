"""The flavor's vCPU count is what the KBS will release the KEK to.

SEV-SNP folds one VMSA per vCPU into the launch digest. vali recomputes
the digest from the FLAVOR's `cpu_count` (never from the miner), pins only
that value in the §22 allowlist and the ticket's `allowed_measurements`,
and the KBS releases only to a report carrying a measurement in both
(`kbs_core::snp::check_attestation`). These tests pin the vali half: the
recompute is handed the flavor's vCPU count, a miner digest for any other
count is refused before anything is pinned or minted, and what IS pinned
and minted is vali's own value. That the digest really moves with the
vCPU count is proven against the real binary in
`binaries/launch-digest/tests/vcpu_count.rs`.
"""

from __future__ import annotations

from typing import Any

import pytest

from apps.orchestration.services import allowlist_pin, flavors, launch, ticket_mint
from apps.orchestration.tests.test_launch_service import (
    _fake_the_launch_choreography,
    _register_miner,
    _spec,
)

pytestmark = pytest.mark.django_db


def _digest_for(vcpus: int) -> str:
    """Stand-in for the real recompute: a distinct digest per vCPU count."""
    return f"{vcpus:02x}" * 48


@pytest.fixture
def launch_env(monkeypatch) -> dict[str, Any]:
    _fake_the_launch_choreography(monkeypatch, dispatch_ok=True)
    seen: dict[str, Any] = {"recompute": [], "pinned": [], "minted": []}
    monkeypatch.setattr(launch.launch_digest_svc, "enforce", lambda: True)
    monkeypatch.setattr(launch.launch_digest_svc, "is_enabled", lambda: True)

    def _recompute(**kw: Any) -> str:
        seen["recompute"].append(kw)
        return _digest_for(kw["cpu_count"])

    monkeypatch.setattr(launch.launch_digest_svc, "recompute_expected_digest", _recompute)

    def _pin(*, measurement_hex: str, **_: Any) -> allowlist_pin.PinResult:
        seen["pinned"].append(measurement_hex)
        return allowlist_pin.PinResult(new_epoch=2, new_cose_sha256_hex="e" * 64, s3_url="s3://x")

    monkeypatch.setattr(launch.allowlist_pin, "pin_measurement", _pin)

    def _mint(args: ticket_mint.MintArgs) -> bytes:
        seen["minted"].append(args.allowed_measurement_hex)
        return b"cose"

    monkeypatch.setattr(ticket_mint, "mint", _mint)
    return seen


def _miner_reports(monkeypatch, digest: str) -> None:
    from apps.orchestration.services import preflight as preflight_svc

    monkeypatch.setattr(
        preflight_svc,
        "dispatch_preflight",
        lambda *a, **k: preflight_svc.PreflightResult(
            launch_digest_hex=digest,
            luks_disk_path="/d.img",
            kernel_path="/k",
            initrd_path="/i",
        ),
    )


_USERDATA = b"#cloud-config\n# {{NETBIRD_SETUP_KEY}}\n"


def _miner():
    miner = _register_miner(1)
    miner.platform_id = "ef" * 64
    miner.save(update_fields=["platform_id"])
    return miner


@pytest.mark.parametrize("flavor", ["small", "large", "4xlarge"])
def test_only_the_flavors_vcpu_digest_is_pinned_and_ticketed(
    monkeypatch, launch_env, flavor: str
) -> None:
    want = flavors.resolve_flavor(flavor).cpu_count
    _miner_reports(monkeypatch, _digest_for(want))

    spec = _spec(flavor=flavor, auto_pin_allowlist=True, userdata=_USERDATA)
    out = launch.launch_on_miner(spec, _miner())

    assert out.disposition == launch.ACCEPTED, out.emit
    assert [kw["cpu_count"] for kw in launch_env["recompute"]] == [want]
    assert launch_env["pinned"] == [_digest_for(want)]
    assert launch_env["minted"] == [_digest_for(want)]


@pytest.mark.parametrize("delta", [-1, +1])
def test_a_miner_digest_for_another_vcpu_count_is_refused(
    monkeypatch, launch_env, delta: int
) -> None:
    """A miner preparing to start the guest with N±1 vCPUs reports the
    digest of THAT launch. vali refuses before pinning or minting, so no
    allowlist entry and no ticket ever names that measurement — the KBS
    would deny the KEK to such a guest anyway."""
    want = flavors.resolve_flavor("large").cpu_count
    _miner_reports(monkeypatch, _digest_for(want + delta))

    spec = _spec(flavor="large", auto_pin_allowlist=True, userdata=_USERDATA)
    out = launch.launch_on_miner(spec, _miner())

    assert out.disposition == launch.TERMINAL, out.emit
    assert out.emit["outcome"] == "launch-digest-mismatch"
    assert launch_env["pinned"] == []
    assert launch_env["minted"] == []
