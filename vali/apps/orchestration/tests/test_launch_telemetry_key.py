"""§23 — the launch-time tenant telemetry-key wiring (uptime billing).

`launch.launch_on_miner`, right after the §7 lifecycle key, derives the
tenant telemetry PUBLIC key from the lifecycle seed (via the
`hippius-ticket-validator derive-telemetry-key` subprocess, wrapped in
`telemetry_keygen`) and provisions a `TelemetrySource(tenant_vm, vm_id)`
so the guest's served-receipts verify + accrue billable uptime.

These tests pin the keygen-wrapper parse, the `_persist_telemetry_source`
seam, and (with the real binary) that the derivation matches the shared
HKDF the guest uses.
"""

from __future__ import annotations

import json
from unittest import mock

import pytest

from apps.lifecycle.models import Vm, VmState
from apps.orchestration.services import launch, telemetry_keygen
from apps.telemetry.models import SourceType, TelemetrySource

pytestmark = pytest.mark.django_db


def _fake_completed(stdout: bytes, returncode: int = 0, stderr: bytes = b""):
    m = mock.Mock()
    m.stdout = stdout
    m.stderr = stderr
    m.returncode = returncode
    return m


# ─── telemetry_keygen wrapper ─────────────────────────────────────────


def test_derive_parses_vk(settings, tmp_path) -> None:
    binpath = tmp_path / "validator"
    binpath.write_text("#!/bin/true\n")
    settings.VALI_TICKET_VALIDATOR_BIN = str(binpath)
    vk = "7b" * 32
    out = json.dumps({"vk_hex": vk}).encode()
    with mock.patch("subprocess.run", return_value=_fake_completed(out)) as run:
        got = telemetry_keygen.derive_telemetry_vk(bytes(range(32)))
    assert got == bytes.fromhex(vk)
    # The lifecycle seed is passed on STDIN (never argv) — §20.
    assert run.call_args.kwargs["input"] == bytes(range(32)).hex().encode()


def test_derive_rejects_non_32_byte_seed(settings) -> None:
    with pytest.raises(telemetry_keygen.TelemetryKeygenError):
        telemetry_keygen.derive_telemetry_vk(b"short")


def test_derive_raises_on_nonzero_exit(settings, tmp_path) -> None:
    binpath = tmp_path / "validator"
    binpath.write_text("#!/bin/true\n")
    settings.VALI_TICKET_VALIDATOR_BIN = str(binpath)
    with mock.patch(
        "subprocess.run", return_value=_fake_completed(b"", 2, b"bad seed")
    ):
        with pytest.raises(telemetry_keygen.TelemetryKeygenError):
            telemetry_keygen.derive_telemetry_vk(bytes(32))


def test_derive_rejects_short_vk(settings, tmp_path) -> None:
    binpath = tmp_path / "validator"
    binpath.write_text("#!/bin/true\n")
    settings.VALI_TICKET_VALIDATOR_BIN = str(binpath)
    out = json.dumps({"vk_hex": "abcd"}).encode()
    with mock.patch("subprocess.run", return_value=_fake_completed(out)):
        with pytest.raises(telemetry_keygen.TelemetryKeygenError):
            telemetry_keygen.derive_telemetry_vk(bytes(32))


# ─── _persist_telemetry_source ────────────────────────────────────────


def _vm(vm_id: str = "vm-tel") -> Vm:
    return Vm.objects.create(
        vm_id=vm_id,
        lease_id="lease-tel",
        state=VmState.ACTIVE,
        generation=1,
        host="",
        lifecycle_vk=bytes(32),
    )


def test_persist_creates_the_tenant_vm_source() -> None:
    vm = _vm()
    vk = bytes(range(32))
    launch._persist_telemetry_source(vm.vm_id, vk)
    src = TelemetrySource.objects.get(
        source=SourceType.TENANT_VM.value, source_id=vm.vm_id
    )
    assert bytes(src.verifying_key) == vk
    assert src.is_active is True


def test_persist_is_idempotent_and_overwrites_on_relaunch() -> None:
    vm = _vm()
    launch._persist_telemetry_source(vm.vm_id, bytes(range(32)))
    launch._persist_telemetry_source(vm.vm_id, bytes(range(32, 64)))  # relaunch
    src = TelemetrySource.objects.get(
        source=SourceType.TENANT_VM.value, source_id=vm.vm_id
    )
    assert bytes(src.verifying_key) == bytes(range(32, 64))
    assert (
        TelemetrySource.objects.filter(
            source=SourceType.TENANT_VM.value, source_id=vm.vm_id
        ).count()
        == 1
    )


def test_persist_provisions_without_a_vm_row() -> None:
    # The TelemetrySource is keyed independently by (tenant_vm, vm_id) and
    # does NOT reference the Vm row, so the CLI path (`vali_create_vm`, which
    # skips `_ensure_vm_row`) still provisions billing — a running guest that
    # emits attested uptime must accrue regardless of how it was launched.
    launch._persist_telemetry_source("vm-absent", bytes(range(32)))
    src = TelemetrySource.objects.get(
        source=SourceType.TENANT_VM.value, source_id="vm-absent"
    )
    assert bytes(src.verifying_key) == bytes(range(32))
    assert src.is_active is True


def test_persist_skips_a_malformed_vk() -> None:
    vm = _vm()
    launch._persist_telemetry_source(vm.vm_id, b"too-short")
    assert not TelemetrySource.objects.filter(source_id=vm.vm_id).exists()


def test_persist_clears_a_stale_quarantine_on_relaunch() -> None:
    # A prior instance of this vm_id poisoned + quarantined the source
    # (its receipts failed verify against a now-superseded key). A fresh
    # launch provisions a NEW key → a fresh trust anchor → the poison
    # counter + quarantine MUST reset, or the new guest's valid receipts
    # are refused 429 until the stale window expires (a silent billing gap).
    from datetime import timedelta

    from django.utils import timezone

    vm = _vm()
    launch._persist_telemetry_source(vm.vm_id, bytes(range(32)))
    src = TelemetrySource.objects.get(
        source=SourceType.TENANT_VM.value, source_id=vm.vm_id
    )
    src.consecutive_failures = 3
    src.failure_window_started_at = timezone.now()
    src.quarantined_until = timezone.now() + timedelta(hours=1)
    src.is_active = False
    src.save()

    # Relaunch with a fresh key.
    launch._persist_telemetry_source(vm.vm_id, bytes(range(32, 64)))

    src.refresh_from_db()
    assert bytes(src.verifying_key) == bytes(range(32, 64))
    assert src.is_active is True
    assert src.consecutive_failures == 0
    assert src.failure_window_started_at is None
    assert src.quarantined_until is None


def test_persist_billing_binding_records_the_launch_identity() -> None:
    from apps.scheduler.models import VmBillingBinding

    launch._persist_billing_binding("vm-1", "ab" * 32, "small", "lease-1")
    b = VmBillingBinding.objects.get(vm_id="vm-1")
    assert b.node_id_hex == "ab" * 32
    assert b.resource_class == "small"
    assert b.lease_id == "lease-1"
    # Idempotent: a re-launch overwrites in lockstep.
    launch._persist_billing_binding("vm-1", "cd" * 32, "large", "lease-2")
    b.refresh_from_db()
    assert b.resource_class == "large"
    assert VmBillingBinding.objects.filter(vm_id="vm-1").count() == 1


def test_persist_billing_binding_opens_the_custody_history() -> None:
    """§25 — the launch also OPENS the VM's billing custody (who is PAID,
    from when). Written here, before the domain is dispatched, so it
    precedes the guest's very first receipt window and there is never an
    instant where a running VM has no answer.

    Append-if-changed: reboot-recovery re-runs this whole path on the SAME
    host and must record no custody change (the history is evidence of
    moves that HAPPENED); a re-placement onto a DIFFERENT miner is a real
    move and is appended."""
    from apps.scheduler.models import VmBillingAssignment

    launch._persist_billing_binding("vm-1", "ab" * 32, "small", "lease-1")
    rows = VmBillingAssignment.objects.filter(vm_id="vm-1")
    assert [r.node_id_hex for r in rows] == ["ab" * 32]
    assert rows[0].reason == VmBillingAssignment.LAUNCH

    # Reboot-recovery: same host, same everything ⇒ no new row.
    launch._persist_billing_binding("vm-1", "ab" * 32, "small", "lease-1")
    assert VmBillingAssignment.objects.filter(vm_id="vm-1").count() == 1

    # Re-placed onto another miner ⇒ a real change of custody.
    launch._persist_billing_binding("vm-1", "cd" * 32, "small", "lease-1")
    assert VmBillingAssignment.objects.filter(vm_id="vm-1").count() == 2


# ─── round-trip: vali-derived vk ⇄ the guest's shared HKDF ────────────


def test_derived_vk_matches_the_shared_hkdf(settings) -> None:
    """The vk vali provisions MUST equal the pubkey the guest derives from
    the same lifecycle seed (the shared `hippius_guest::telemetry_key`
    HKDF) — otherwise every served-receipt fails verification. Runs the
    real binary if built; the Rust KAT
    (`telemetry_key::tests::derivation_is_a_stable_known_answer`) pins the
    derivation itself.
    """
    from pathlib import Path

    binpath = (
        Path(__file__).resolve().parents[4]
        / "target"
        / "debug"
        / "hippius-ticket-validator"
    )
    if not binpath.is_file():
        pytest.skip("hippius-ticket-validator binary not built")
    settings.VALI_TICKET_VALIDATOR_BIN = str(binpath)

    # lifecycle seed = [7;32] ⇒ the KAT telemetry seed 3d86f5… ⇒ its pubkey.
    vk = telemetry_keygen.derive_telemetry_vk(bytes([7]) * 32)
    assert len(vk) == 32
    # Deterministic: same seed ⇒ same vk (the whole point).
    assert telemetry_keygen.derive_telemetry_vk(bytes([7]) * 32) == vk
    # Different lifecycle seed ⇒ different telemetry key.
    assert telemetry_keygen.derive_telemetry_vk(bytes([8]) * 32) != vk
