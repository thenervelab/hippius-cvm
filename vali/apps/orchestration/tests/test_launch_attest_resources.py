"""The measured-cmdline tokens of the guest-resource attestation
(`apps.telemetry.guest_resources`), and what the pin records about them.

`hippius.attest_resources=1` (`VALI_GUEST_ATTEST_RESOURCES`) makes a
keepalive image attest its vCPU / RAM; `accept_memory=eager`
(`VALI_GUEST_ACCEPT_MEMORY_EAGER`) makes it accept all of its RAM at boot.
Both are measured, so the miner cannot strip them, and both are vali's
decision alone: a base cmdline never turns them on or off. The
`MeasurementLedger` row of the pin records them with the flavor, so a
live attestation is judged against the launch that produced it.
"""

from __future__ import annotations

from typing import Any

import pytest

from apps.orchestration.services import allowlist_pin, launch
from apps.orchestration.tests.test_launch_service import (
    _fake_the_launch_choreography,
    _register_miner,
    _spec,
)


def _measured(**spec_overrides: Any) -> list[str]:
    return launch._derive_measured_cmdline(
        _spec(**spec_overrides),
        None,
        disk_gb=40,
        node_id_hex="aa" * 32,
        validator_nonce_hex="bb" * 32,
        telemetry_epoch=7,
        eol_nonce_hex="cc" * 32,
    ).split()


@pytest.mark.parametrize("on", [True, False])
def test_the_flags_put_the_tokens_on_the_measured_cmdline(settings, on: bool) -> None:
    settings.VALI_GUEST_ATTEST_RESOURCES = on
    settings.VALI_GUEST_ACCEPT_MEMORY_EAGER = on
    measured = _measured()
    assert ("hippius.attest_resources=1" in measured) is on
    assert ("accept_memory=eager" in measured) is on


@pytest.mark.parametrize("on", [True, False])
def test_a_base_cmdline_never_overrides_the_flags(settings, on: bool) -> None:
    """`=0` must not keep the attestation off once vali asks for it, and
    `=1` must not turn it on before the KBS accepts the field."""
    settings.VALI_GUEST_ATTEST_RESOURCES = on
    settings.VALI_GUEST_ACCEPT_MEMORY_EAGER = on
    base = "ro hippius.attest_resources=0 accept_memory=lazy x.hippius.attest_resources=1"
    measured = _measured(cmdline=base)
    attest = [t for t in measured if t.startswith("hippius.attest_resources=")]
    accept = [t for t in measured if t.startswith("accept_memory=")]
    assert attest == (["hippius.attest_resources=1"] if on else [])
    assert accept == (["accept_memory=eager"] if on else [])
    # A look-alike key is someone else's token, left alone.
    assert "x.hippius.attest_resources=1" in measured


def test_the_tokens_are_byte_stable_across_relaunches(settings) -> None:
    settings.VALI_GUEST_ATTEST_RESOURCES = True
    settings.VALI_GUEST_ACCEPT_MEMORY_EAGER = True
    assert _measured() == _measured()


@pytest.mark.django_db
@pytest.mark.parametrize(("attest", "eager"), [(True, False), (True, True), (False, False)])
def test_the_pin_records_what_the_launch_was_measured_for(
    monkeypatch, settings, attest: bool, eager: bool
) -> None:
    settings.VALI_GUEST_ATTEST_RESOURCES = attest
    settings.VALI_GUEST_ACCEPT_MEMORY_EAGER = eager
    _fake_the_launch_choreography(monkeypatch, dispatch_ok=True)
    ledgers: list[allowlist_pin.PinLedger] = []

    def _pin(*, measurement_hex: str, ledger: allowlist_pin.PinLedger) -> allowlist_pin.PinResult:
        ledgers.append(ledger)
        return allowlist_pin.PinResult(new_epoch=2, new_cose_sha256_hex="e" * 64, s3_url="s3://x")

    monkeypatch.setattr(launch.allowlist_pin, "pin_measurement", _pin)
    miner = _register_miner(1)
    spec = _spec(
        flavor="large",
        auto_pin_allowlist=True,
        userdata=b"#cloud-config\n# {{NETBIRD_SETUP_KEY}}\n",
    )

    out = launch.launch_on_miner(spec, miner)

    assert out.disposition == launch.ACCEPTED, out.emit
    (ledger,) = ledgers
    assert (ledger.flavor, ledger.attests_resources, ledger.accepts_memory_eagerly) == (
        "large",
        attest,
        eager,
    )


@pytest.mark.django_db
@pytest.mark.parametrize("dispatch_ok", [True, False])
def test_only_an_accepted_launch_stamps_its_pin_launched(monkeypatch, dispatch_ok: bool) -> None:
    """`launched_at` is what makes a launch the VM's current one — a guest
    of an earlier launch is then `superseded`. A launch the miner refused
    after its pin must not supersede the guest still running."""
    from apps.orchestration.models import MeasurementLedger

    _fake_the_launch_choreography(monkeypatch, dispatch_ok=dispatch_ok)
    # What the (faked) pin would have recorded for the preflight digest.
    MeasurementLedger.objects.create(
        vm_id="vm-launch-1", launch_digest_hex="ab" * 48, allowlist_epoch=1
    )
    launch.launch_on_miner(
        _spec(userdata=b"#cloud-config\n# {{NETBIRD_SETUP_KEY}}\n"), _register_miner(1)
    )
    row = MeasurementLedger.objects.get(vm_id="vm-launch-1")
    assert (row.launched_at is not None) is dispatch_ok
