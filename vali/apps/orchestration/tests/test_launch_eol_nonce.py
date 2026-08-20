"""GAP 3 — the launch-time EOL nonce wiring (§24/§25).

`launch.launch_on_miner` bakes a single-use `hippius.eol_nonce` token
into the MEASURED cmdline AND persists the SAME value onto
`Vm.eol_nonce`, so the guest signs (from its baked cmdline) exactly the
nonce vali's `_verify_ack` checks against. These tests pin the helper
contracts + the persist seam directly (the full `launch_on_miner` chain
talks to Vault / preflight / KBS and is exercised live, not here).
"""

from __future__ import annotations

import pytest

from apps.lifecycle.models import Vm, VmState
from apps.orchestration.services import launch

pytestmark = pytest.mark.django_db


# ─── cmdline token helpers ────────────────────────────────────────────


def test_augment_appends_nonce_when_absent() -> None:
    out = launch._augment_cmdline_with_token(
        "ro quiet", launch._EOL_NONCE_CMDLINE_KEY, "ab" * 32
    )
    assert out == "ro quiet hippius.eol_nonce=" + "ab" * 32


def test_augment_leaves_operator_supplied_nonce_untouched() -> None:
    # An operator who already baked the token (measured) keeps it — the
    # value is byte-stable across re-place attempts.
    cmdline = "ro hippius.eol_nonce=" + "cd" * 32
    out = launch._augment_cmdline_with_token(
        cmdline, launch._EOL_NONCE_CMDLINE_KEY, "ab" * 32
    )
    assert out == cmdline


def test_extract_returns_the_token_value() -> None:
    cmdline = "ro hippius.eol_nonce=" + "ef" * 32 + " quiet"
    assert (
        launch._extract_cmdline_token(cmdline, launch._EOL_NONCE_CMDLINE_KEY)
        == "ef" * 32
    )


def test_extract_returns_none_when_absent() -> None:
    assert (
        launch._extract_cmdline_token("ro quiet", launch._EOL_NONCE_CMDLINE_KEY)
        is None
    )


# ─── _persist_eol_nonce ───────────────────────────────────────────────


def _vm(vm_id: str = "vm-n") -> Vm:
    return Vm.objects.create(
        vm_id=vm_id,
        lease_id="lease-n",
        state=VmState.ACTIVE,
        generation=1,
        host="",
        lifecycle_vk=bytes(32),
    )


def test_persist_stamps_the_nonce_on_the_vm_row() -> None:
    vm = _vm()
    nonce_hex = "ab" * 32
    launch._persist_eol_nonce(vm.vm_id, nonce_hex)
    vm.refresh_from_db()
    assert bytes(vm.eol_nonce) == bytes.fromhex(nonce_hex)


def test_persist_noops_without_a_vm_row() -> None:
    # CLI / dev path: no Vm row yet — the persist is a no-op (the cmdline
    # still carries the nonce). Must not raise.
    launch._persist_eol_nonce("vm-does-not-exist", "ab" * 32)


def test_persist_skips_a_malformed_nonce() -> None:
    vm = _vm()
    launch._persist_eol_nonce(vm.vm_id, "not-hex-or-wrong-length")
    vm.refresh_from_db()
    # Left unset — the EOL ack path then fails closed (no nonce to verify).
    assert vm.eol_nonce is None


def test_cmdline_and_vm_row_are_kept_in_lockstep() -> None:
    # The whole point of GAP 3: whatever nonce ends up in the cmdline is
    # exactly what is persisted on the Vm row, so the guest signs a value
    # `_verify_ack` will match. Simulate the launch_on_miner resolution.
    vm = _vm("vm-lockstep")
    spec_cmdline = "ro"
    augmented = launch._augment_cmdline_with_token(
        spec_cmdline, launch._EOL_NONCE_CMDLINE_KEY, "12" * 32
    )
    effective = launch._extract_cmdline_token(
        augmented, launch._EOL_NONCE_CMDLINE_KEY
    )
    launch._persist_eol_nonce(vm.vm_id, effective)
    vm.refresh_from_db()
    assert effective == "12" * 32
    assert bytes(vm.eol_nonce).hex() == effective
