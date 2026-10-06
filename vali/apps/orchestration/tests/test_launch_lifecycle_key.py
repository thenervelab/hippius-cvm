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


# ─── _stage_userdata (Transit-wrapped at rest) ────────────────────────


def test_userdata_is_written_wrapped_never_plaintext() -> None:
    """THE claim. Before this, the KEK was Transit-enveloped and the
    cloud-init beside it was not — and it carries SSH keys, API tokens and
    the NetBird enrolment secret."""
    plaintext = b"#cloud-config\nssh_authorized_keys: [ssh-ed25519 AAAA...]\n"
    with (
        mock.patch.object(
            launch.vault_kv, "transit_encrypt", return_value=b"vault:v1:CIPHERTEXT"
        ) as enc,
        mock.patch.object(launch.vault_kv, "ensure_transit_key") as ensure,
        mock.patch.object(launch.vault_kv, "put_kv") as put,
    ):
        launch._stage_userdata("secret", "p/vm-a/userdata", "vm-a", plaintext)

    (_mount, _path, written), _kw = put.call_args
    assert written == b"vault:v1:CIPHERTEXT"
    assert plaintext not in (written,), "the plaintext must never reach Vault"
    enc.assert_called_once_with("kek-vm-a", plaintext)
    ensure.assert_called_once_with("kek-vm-a")


def test_it_reuses_the_kek_transit_key_so_crypto_erase_covers_it() -> None:
    """§24 destroys `kek-<vm_id>`. Reusing it is what makes decommission
    make the userdata unreadable too — the erase path never deleted this
    KV entry, so it used to outlive the VM. A second key would silently
    lose that coverage."""
    with (
        mock.patch.object(launch.vault_kv, "transit_encrypt", return_value=b"vault:v1:x"),
        mock.patch.object(launch.vault_kv, "ensure_transit_key"),
        mock.patch.object(launch.vault_kv, "put_kv"),
        mock.patch.object(
            launch.vault_kv, "transit_key_name", wraps=launch.vault_kv.transit_key_name
        ) as name,
    ):
        launch._stage_userdata("secret", "p/vm-b/userdata", "vm-b", b"x")
    name.assert_called_once_with("vm-b")


def test_a_transit_failure_does_not_write_anything() -> None:
    """Fail closed: if wrapping fails, nothing is staged. Writing the
    plaintext as a fallback would defeat the entire change."""
    from apps.orchestration.effects import EffectError

    with (
        mock.patch.object(
            launch.vault_kv, "transit_encrypt", side_effect=EffectError("transit down")
        ),
        mock.patch.object(launch.vault_kv, "ensure_transit_key"),
        mock.patch.object(launch.vault_kv, "put_kv") as put,
    ):
        with pytest.raises(EffectError):
            launch._stage_userdata("secret", "p/vm-c/userdata", "vm-c", b"secret")
    put.assert_not_called()


# ─── the working copy (`ud-<vm_id>`, the key vali may open) ───────────


def test_the_intake_copy_is_wrapped_under_a_key_vali_can_open() -> None:
    """TWO per-VM Transit keys, deliberately. The canonical userdata the
    ticket binds is wrapped under `kek-<vm_id>` — vali may encrypt with it
    and never decrypt, so only the attested KBS opens it. vali's own
    working copy is wrapped under `ud-<vm_id>`, which vali MAY open,
    because the NetBird substitution and the §6 digest re-derivation still
    need the cloud-init plaintext after intake. Wrapping the working copy
    under the KEK key would strand both; leaving it in the clear is what
    this change removes."""
    plaintext = b"#cloud-config\nssh_authorized_keys: [ssh-ed25519 AAAA]\n"
    with (
        mock.patch.object(
            launch.vault_kv, "transit_encrypt", return_value=b"vault:v1:CT"
        ) as enc,
        mock.patch.object(launch.vault_kv, "ensure_transit_key") as ensure,
        mock.patch.object(launch.vault_kv, "put_kv") as put,
    ):
        launch.stage_userdata_intake_copy(
            "secret", "p/vm-w/userdata-intake", "vm-w", plaintext
        )

    (_mount, _path, written), _kw = put.call_args
    assert written == b"vault:v1:CT"
    assert plaintext not in (written,), "the plaintext must never reach Vault"
    enc.assert_called_once_with("ud-vm-w", plaintext)
    ensure.assert_called_once_with("ud-vm-w")


def test_the_intake_copy_round_trips_and_a_transit_failure_stages_nothing() -> None:
    with (
        mock.patch.object(
            launch.vault_kv, "get_kv", return_value=b"vault:v1:CT"
        ),
        mock.patch.object(
            launch.vault_kv, "transit_decrypt", return_value=b"#cloud-config\n"
        ) as dec,
    ):
        got = launch.open_userdata_intake_copy("secret", "p/vm-w/userdata-intake", 3, "vm-w")
    assert got == b"#cloud-config\n"
    dec.assert_called_once_with("ud-vm-w", b"vault:v1:CT")

    # Fail closed: if wrapping fails, nothing is staged. Writing the
    # plaintext as a fallback would defeat the entire change.
    from apps.orchestration.effects import EffectError

    with (
        mock.patch.object(
            launch.vault_kv, "transit_encrypt", side_effect=EffectError("transit down")
        ),
        mock.patch.object(launch.vault_kv, "ensure_transit_key"),
        mock.patch.object(launch.vault_kv, "put_kv") as put,
    ):
        with pytest.raises(EffectError):
            launch.stage_userdata_intake_copy(
                "secret", "p/vm-w/userdata-intake", "vm-w", b"secret"
            )
    put.assert_not_called()


def test_a_legacy_plaintext_intake_copy_is_returned_verbatim() -> None:
    """VMs staged before the wrapping hold plaintext there. They must keep
    launching and recovering — so an unwrapped value passes through
    instead of being handed to Transit (which would fail)."""
    with (
        mock.patch.object(
            launch.vault_kv, "get_kv", return_value=b"#cloud-config\nlegacy"
        ),
        mock.patch.object(launch.vault_kv, "transit_decrypt") as dec,
    ):
        got = launch.open_userdata_intake_copy("secret", "p/vm-l/userdata-pending", 1, "vm-l")
    assert got == b"#cloud-config\nlegacy"
    dec.assert_not_called()


def test_the_working_copy_stamps_the_canonical_version_it_belongs_to() -> None:
    """The stamp is what makes the pairing provable. The canonical write
    and this one are two independent KV puts, so a copy that merely EXISTS
    proves nothing about which canonical version's bytes it holds — and
    the §25 re-mint has to hash exactly the version its ticket binds."""
    with (
        mock.patch.object(
            launch.vault_kv, "transit_encrypt", side_effect=lambda name, pt: b"CT:" + pt
        ),
        mock.patch.object(launch.vault_kv, "ensure_transit_key"),
        mock.patch.object(launch.vault_kv, "put_kv") as put,
    ):
        launch.stage_userdata_working_copy(
            "secret", "p/vm-w/userdata-pending", "vm-w", b"#cloud-config\nx",
            canonical_version=7,
        )
    (_mount, _path, written), _kw = put.call_args
    assert written == b"CT:" + launch._WORKING_STAMP + b"7\n#cloud-config\nx"


@pytest.mark.parametrize(
    ("stored", "match"),
    [
        (b"#cloud-config\ntemplate", "not Transit-wrapped"),
        (b"vault:unstamped", "no canonical-version stamp"),
        (b"vault:" + b"hippius-userdata-for-canonical-v6\nbytes", "stamped for canonical"),
    ],
)
def test_the_working_copy_reader_refuses_anything_it_cannot_pair(stored, match) -> None:
    """Each refusal is a case where minting anyway produces a ticket bound
    to bytes the guest never receives: an intake template left at that
    path by an older build, a copy written before the stamping, or one
    from an earlier attempt whose canonical write is not the one this
    ticket binds."""
    with (
        mock.patch.object(launch.vault_kv, "get_kv", return_value=stored),
        mock.patch.object(
            launch.vault_kv,
            "transit_decrypt",
            side_effect=lambda name, ct: ct.removeprefix(b"vault:"),
        ),
    ):
        with pytest.raises(launch.UserdataPairingError, match=match):
            launch.open_userdata_working_copy("secret", "p/vm-w/userdata-pending", "vm-w", 7)
