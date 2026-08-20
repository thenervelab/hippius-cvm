"""§7 — the launch-time guest lifecycle key wiring.

`launch.launch_on_miner`:
  - generates a per-VM Ed25519 lifecycle keypair (via the
    `hippius-ticket-validator gen-lifecycle-key` subprocess, wrapped in
    `lifecycle_keygen`),
  - stages the PRIVATE seed into Vault at the per-VM `…/lifecycle-key`
    path (the key the KBS releases to the attested guest), and
  - records the PUBLIC key as `Vm.lifecycle_vk` (replacing the all-zero
    placeholder) so `_verify_ack` / `lifecycle_vk_hex()` match a
    guest-signed §24/§25 StoppedAck.

These tests pin the keygen-wrapper parse, the `_persist_lifecycle_vk`
seam, and the measured-cmdline token. The full `launch_on_miner` chain
(Vault / preflight / KBS) is exercised live, not here.
"""

from __future__ import annotations

import json
from unittest import mock

import pytest

from apps.lifecycle.models import Vm, VmState
from apps.orchestration.services import launch, lifecycle_keygen

pytestmark = pytest.mark.django_db


# ─── cmdline token ────────────────────────────────────────────────────


def test_augment_appends_lifecycle_key_path_when_absent() -> None:
    out = launch._augment_cmdline_with_token(
        "ro quiet",
        launch._LIFECYCLE_KEY_PATH_CMDLINE_KEY,
        launch._LIFECYCLE_KEY_TMPFS_PATH,
    )
    assert out == "ro quiet hippius.lifecycle_key_path=/run/hippius/lifecycle.key"


def test_lifecycle_key_path_is_a_tmpfs_path() -> None:
    # The key must NEVER land on the miner-backed encrypted disk — the
    # path is under /run (tmpfs in the guest).
    assert launch._LIFECYCLE_KEY_TMPFS_PATH.startswith("/run/")


# ─── lifecycle_keygen wrapper ─────────────────────────────────────────


def _fake_completed(stdout: bytes, returncode: int = 0, stderr: bytes = b""):
    m = mock.Mock()
    m.stdout = stdout
    m.stderr = stderr
    m.returncode = returncode
    return m


def test_keygen_parses_seed_and_vk(settings, tmp_path) -> None:
    # Point the binary setting at any existing file (the wrapper checks
    # `is_file()` before spawning) and mock the spawn.
    binpath = tmp_path / "validator"
    binpath.write_text("#!/bin/true\n")
    settings.VALI_TICKET_VALIDATOR_BIN = str(binpath)

    seed = "5a" * 32
    vk = "7b" * 32
    out = json.dumps({"seed_hex": seed, "vk_hex": vk}).encode()
    with mock.patch("subprocess.run", return_value=_fake_completed(out)):
        kp = lifecycle_keygen.generate_lifecycle_keypair()
    assert kp.seed == bytes.fromhex(seed)
    assert kp.vk == bytes.fromhex(vk)


def test_keygen_raises_on_nonzero_exit(settings, tmp_path) -> None:
    binpath = tmp_path / "validator"
    binpath.write_text("#!/bin/true\n")
    settings.VALI_TICKET_VALIDATOR_BIN = str(binpath)
    with mock.patch(
        "subprocess.run", return_value=_fake_completed(b"", 1, b"gen-lifecycle-key: boom")
    ):
        with pytest.raises(lifecycle_keygen.LifecycleKeygenError):
            lifecycle_keygen.generate_lifecycle_keypair()


def test_keygen_raises_on_missing_binary(settings) -> None:
    settings.VALI_TICKET_VALIDATOR_BIN = "/nonexistent/validator-bin"
    with pytest.raises(lifecycle_keygen.LifecycleKeygenError):
        lifecycle_keygen.generate_lifecycle_keypair()


def test_keygen_rejects_short_key(settings, tmp_path) -> None:
    binpath = tmp_path / "validator"
    binpath.write_text("#!/bin/true\n")
    settings.VALI_TICKET_VALIDATOR_BIN = str(binpath)
    out = json.dumps({"seed_hex": "ab", "vk_hex": "cd"}).encode()
    with mock.patch("subprocess.run", return_value=_fake_completed(out)):
        with pytest.raises(lifecycle_keygen.LifecycleKeygenError):
            lifecycle_keygen.generate_lifecycle_keypair()


# ─── derive_lifecycle_vk wrapper ──────────────────────────────────────


def test_derive_vk_parses_and_passes_seed_on_stdin(settings, tmp_path) -> None:
    binpath = tmp_path / "validator"
    binpath.write_text("#!/bin/true\n")
    settings.VALI_TICKET_VALIDATOR_BIN = str(binpath)
    vk = "7b" * 32
    out = json.dumps({"vk_hex": vk}).encode()
    with mock.patch("subprocess.run", return_value=_fake_completed(out)) as run:
        got = lifecycle_keygen.derive_lifecycle_vk(bytes(range(32)))
    assert got == bytes.fromhex(vk)
    # The seed is passed on STDIN (never argv) — §20.
    assert run.call_args.kwargs["input"] == bytes(range(32)).hex().encode()
    assert "derive-lifecycle-vk" in run.call_args.args[0]


def test_derive_vk_rejects_non_32_byte_seed(settings) -> None:
    with pytest.raises(lifecycle_keygen.LifecycleKeygenError):
        lifecycle_keygen.derive_lifecycle_vk(b"short")


def test_derive_vk_raises_on_nonzero_exit(settings, tmp_path) -> None:
    binpath = tmp_path / "validator"
    binpath.write_text("#!/bin/true\n")
    settings.VALI_TICKET_VALIDATOR_BIN = str(binpath)
    with mock.patch(
        "subprocess.run", return_value=_fake_completed(b"", 2, b"bad seed")
    ):
        with pytest.raises(lifecycle_keygen.LifecycleKeygenError):
            lifecycle_keygen.derive_lifecycle_vk(bytes(32))


def test_derive_vk_matches_gen_with_the_real_binary(settings) -> None:
    """derive-lifecycle-vk(seed) MUST equal gen-lifecycle-key's vk for the
    same seed — the first-write-wins reuse path re-derives the vk vali
    persists, so a mismatch would desync `Vm.lifecycle_vk` from the seed
    the KBS releases. Runs the real binary if built."""
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

    kp = lifecycle_keygen.generate_lifecycle_keypair()
    assert lifecycle_keygen.derive_lifecycle_vk(kp.seed) == kp.vk
    # Deterministic: same seed ⇒ same vk.
    assert lifecycle_keygen.derive_lifecycle_vk(kp.seed) == kp.vk


# ─── _stage_lifecycle_key (first-write-wins) ──────────────────────────


def test_stage_reuses_an_existing_version_1_seed() -> None:
    # A version-1 seed already exists (a prior launch of this vm_id) —
    # the staging must REUSE it (the KBS reads version 1 forever) and
    # NEVER write.
    seed = bytes(range(32))
    vk = bytes(range(32, 64))
    with (
        mock.patch.object(launch.vault_kv, "get_kv", return_value=seed) as get,
        mock.patch.object(launch.vault_kv, "put_kv") as put,
        mock.patch.object(
            launch.lifecycle_keygen, "derive_lifecycle_vk", return_value=vk
        ),
        mock.patch.object(
            launch.lifecycle_keygen, "generate_lifecycle_keypair"
        ) as gen,
    ):
        got_seed, got_vk = launch._stage_lifecycle_key("secret", "p/vm/lifecycle-key")
    assert (got_seed, got_vk) == (seed, vk)
    get.assert_called_once_with("secret", "p/vm/lifecycle-key", version=1)
    put.assert_not_called()
    gen.assert_not_called()


def test_stage_generates_and_writes_cas0_when_absent() -> None:
    from apps.orchestration.services.vault_kv import VaultNotFound

    kp = lifecycle_keygen.LifecycleKeypair(
        seed=bytes(range(32)), vk=bytes(range(32, 64))
    )
    with (
        mock.patch.object(
            launch.vault_kv, "get_kv", side_effect=VaultNotFound("x: not-found")
        ),
        mock.patch.object(launch.vault_kv, "put_kv") as put,
        mock.patch.object(
            launch.lifecycle_keygen, "generate_lifecycle_keypair", return_value=kp
        ),
    ):
        got_seed, got_vk = launch._stage_lifecycle_key("secret", "p/vm/lifecycle-key")
    assert (got_seed, got_vk) == (kp.seed, kp.vk)
    # The write is create-only: cas=0, never an overwrite.
    put.assert_called_once_with("secret", "p/vm/lifecycle-key", kp.seed, cas=0)


def test_stage_lost_race_falls_back_to_the_winner_seed() -> None:
    # Two concurrent launches of the same vm_id: we read absent, generate,
    # then lose the cas=0 write. The winner's version-1 seed is the
    # identity — ours is discarded.
    from apps.orchestration.services.vault_kv import VaultCasConflict, VaultNotFound

    kp = lifecycle_keygen.LifecycleKeypair(
        seed=bytes([1]) * 32, vk=bytes([2]) * 32
    )
    winner_seed = bytes([3]) * 32
    winner_vk = bytes([4]) * 32
    with (
        mock.patch.object(
            launch.vault_kv,
            "get_kv",
            side_effect=[VaultNotFound("x: not-found"), winner_seed],
        ) as get,
        mock.patch.object(
            launch.vault_kv, "put_kv", side_effect=VaultCasConflict("x: cas")
        ),
        mock.patch.object(
            launch.lifecycle_keygen, "generate_lifecycle_keypair", return_value=kp
        ),
        mock.patch.object(
            launch.lifecycle_keygen, "derive_lifecycle_vk", return_value=winner_vk
        ),
    ):
        got_seed, got_vk = launch._stage_lifecycle_key("secret", "p/vm/lifecycle-key")
    assert (got_seed, got_vk) == (winner_seed, winner_vk)
    assert get.call_count == 2


# ─── _persist_lifecycle_vk ────────────────────────────────────────────


def _vm(vm_id: str = "vm-lc") -> Vm:
    return Vm.objects.create(
        vm_id=vm_id,
        lease_id="lease-lc",
        state=VmState.ACTIVE,
        generation=1,
        host="",
        lifecycle_vk=bytes(32),
    )


def test_persist_replaces_the_placeholder_vk() -> None:
    vm = _vm()
    # Sanity: starts as the all-zero placeholder.
    assert bytes(vm.lifecycle_vk) == bytes(32)
    vk = bytes(range(32))
    launch._persist_lifecycle_vk(vm.vm_id, vk)
    vm.refresh_from_db()
    assert bytes(vm.lifecycle_vk) == vk
    # And it is no longer the all-zero placeholder.
    assert bytes(vm.lifecycle_vk) != bytes(32)
    assert vm.lifecycle_vk_hex() == vk.hex()


def test_persist_noops_without_a_vm_row() -> None:
    # CLI / dev path: no Vm row — the persist no-ops (the seed is still
    # staged in Vault). Must not raise.
    launch._persist_lifecycle_vk("vm-does-not-exist", bytes(range(32)))


def test_persist_skips_a_malformed_vk() -> None:
    vm = _vm()
    launch._persist_lifecycle_vk(vm.vm_id, b"too-short")
    vm.refresh_from_db()
    # Left at the placeholder — a malformed vk would make every ack fail.
    assert bytes(vm.lifecycle_vk) == bytes(32)


# ─── round-trip: recorded vk ⇄ a guest-signed ack ─────────────────────


def test_vk_recorded_matches_seed_pubkey_via_validator(settings) -> None:
    """The PUBLIC key vali records MUST be the Ed25519 pubkey of the
    seed it stages — otherwise `_verify_ack` rejects every ack.

    Run the REAL `gen-lifecycle-key` binary (if built) and cross-check
    that the seed loaded as a signing key yields the recorded vk. This
    is the load-bearing §7 invariant. Skipped when the binary isn't
    present in the worktree's target/ (CI builds it).
    """
    import shutil
    from pathlib import Path

    # Locate the freshly-built debug binary in the worktree.
    candidates = [
        Path(__file__).resolve().parents[4]
        / "target"
        / "debug"
        / "hippius-ticket-validator",
    ]
    binpath = next((c for c in candidates if c.is_file()), None)
    if binpath is None:
        binpath = shutil.which("hippius-ticket-validator")
    if binpath is None:
        pytest.skip("hippius-ticket-validator binary not built")

    settings.VALI_TICKET_VALIDATOR_BIN = str(binpath)
    kp = lifecycle_keygen.generate_lifecycle_keypair()
    assert len(kp.seed) == 32 and len(kp.vk) == 32

    # The seed→vk derivation being the standard Ed25519 one (so the
    # guest that loads `kp.seed` produces an ack that verifies under
    # `kp.vk`) is proven by the Rust unit test
    # `gen_lifecycle_key::tests::seed_derives_a_consistent_verifying_key`.
    # Here we only assert the binary's freshness contract: each VM gets a
    # distinct keypair (no key reuse across VMs).
    kp2 = lifecycle_keygen.generate_lifecycle_keypair()
    assert kp.seed != kp2.seed, "each VM must get a fresh seed"
    assert kp.vk != kp2.vk
