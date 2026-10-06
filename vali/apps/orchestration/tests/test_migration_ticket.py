"""§25 new_gen dest-ticket re-mint tests.

Covers the part-B fence: the dest ticket is re-minted at `new_gen` (so the
KBS releases the KEK to the destination), reusing the launch record's
measurement (NOT a rewritten cmdline) and re-deriving the §6 userdata
digest. The Rust `order-ticket-mint` binary is shelled out via a mock so the
tests need no built binary or Vault.
"""

from __future__ import annotations

from typing import Any

import pytest
from django.conf import settings
from django.utils import timezone

from apps.orchestration.effects import EffectError
from apps.orchestration.models import LaunchJob, LaunchJobState
from apps.orchestration.services import migration_ticket, ticket_mint, vault_kv

from .factories import make_service_client, make_vm

pytestmark = pytest.mark.django_db


def _launch_record(vm: Any, *, measurement_hex: str = "ab" * 48) -> LaunchJob:
    """A SUCCEEDED launch record whose result emit carries the final
    measurement (the common preflight-auto case).
    """
    now = timezone.now()
    return LaunchJob.objects.create(
        job_id=f"lj-{vm.vm_id}",
        vm_id=vm.vm_id,
        tenant_id="tenant-a",
        flavor="small",
        spec_json={
            "tenant_id": "tenant-a",
            "user_id": "user-a",
            "flavor": "small",
            "platform_id": "chip-1",
            "kid": "l1-order-ticket-dev-v1",
            "cmdline": "ro quiet console=ttyS0 panic=1 ds=nocloud",
            "expiry_seconds": 86400,
        },
        result_json={"emit": {"measurement_hex": measurement_hex}},
        userdata_vault_path="secret/x/userdata",
        userdata_vault_version=1,
        kek_vault_path="secret/x/luks-kek",
        state=LaunchJobState.SUCCEEDED.value,
        phase_started_at=now,
        finished_at=now,
        decided_by=make_service_client(),
    )


#: vali's working copy at rest — the canonical bytes, STAMPED with the
#: canonical KV version they correspond to, wrapped under `ud-<vm_id>`.
#: The stamp is what makes "this is that version's plaintext" provable:
#: the two KV writes are not atomic, so a copy without it could be some
#: earlier attempt's bytes.
_CANONICAL_VERSION = 4


def _stamped(plaintext: bytes, version: int = _CANONICAL_VERSION) -> bytes:
    from apps.orchestration.services import launch

    body = launch._WORKING_STAMP + str(version).encode() + b"\n" + plaintext
    return b"vault:v1:" + body.hex().encode("ascii")


_WRAPPED_WORKING_COPY = _stamped(b"#cloud-config\n")


@pytest.fixture
def _vault_and_mint(monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    """Stub the Vault reads + the mint shell-out. Captures the MintArgs the
    re-mint passed so a test can assert `vm_generation == new_gen`.
    """
    captured: dict[str, Any] = {}
    # DIFFERENT numbers per path, so a test cannot pass by reading the
    # wrong one: the canonical version is what the ticket binds and what
    # the working copy must be pinned to.
    monkeypatch.setattr(
        vault_kv,
        "latest_version",
        lambda mount, path, *a, **k: 9 if path.endswith("-pending") else _CANONICAL_VERSION,
    )
    # Production shape: the canonical userdata is wrapped under the
    # KBS-only `kek-<vm_id>` and vali's working copy under `ud-<vm_id>`.
    # The re-mint must read the copy it can OPEN — hashing what a read of
    # the canonical path returns is a digest over ciphertext, and a ticket
    # that denies at release.
    def _get_kv(mount, path, **k):
        captured.setdefault("reads", []).append((path, k.get("version")))
        if path.endswith("-pending"):
            return _WRAPPED_WORKING_COPY
        return b"vault:v1:" + b"#cloud-config\n".hex().encode("ascii")

    monkeypatch.setattr(vault_kv, "get_kv", _get_kv)
    monkeypatch.setattr(
        vault_kv, "transit_decrypt", lambda name, ct: bytes.fromhex(
            ct.removeprefix(b"vault:v1:").decode()
        )
    )

    def _fake_mint(args: ticket_mint.MintArgs) -> bytes:
        captured["args"] = args
        return b"\xa1\x00cose-blob"

    monkeypatch.setattr(ticket_mint, "mint", _fake_mint)
    return captured


def test_remint_mints_at_new_gen_with_same_measurement(
    monkeypatch: pytest.MonkeyPatch, _vault_and_mint: dict[str, Any]
) -> None:
    from apps.miners.models import MinerIdentity

    vm = make_vm(generation=5, host="node-src")
    _launch_record(vm, measurement_hex="cd" * 48)
    # The DEST miner's registered SNP chip identity — `start_migration`
    # validates this at intake, so it is always present by remint time.
    MinerIdentity.objects.create(
        miner_id="node-dst", pubkey_hex="bb" * 32, platform_id="22" * 64
    )

    # Stub the intake persistence (validate + store) — the mint blob is a
    # stand-in, not a real COSE the validator would accept.
    stored: dict[str, Any] = {}
    monkeypatch.setattr(
        migration_ticket,
        "persist_intake",
        lambda blob, **kw: stored.update({"blob": blob, **kw}),
    )

    blob = migration_ticket.remint_dest_ticket(
        vm, dest_node_id="node-dst", new_gen=6
    )
    assert blob == b"\xa1\x00cose-blob"

    args = _vault_and_mint["args"]
    # The fence: the dest ticket binds new_gen + the dest node.
    assert args.vm_generation == 6
    assert args.node_id == "node-dst"
    # Same measurement as launch — the dest boots the byte-identical guest.
    assert args.allowed_measurement_hex == "cd" * 48
    # Identity echoed from the launch record.
    assert args.tenant_id == "tenant-a"
    assert args.user_id == "user-a"
    # THE gate that makes the ticket releasable: the dest ticket must carry
    # the DESTINATION miner's chip identity. `kbs_core::release` compares the
    # attested chip_id against this and fails closed (403) when it is empty —
    # a ticket minted without it boots a guest that can never unlock.
    assert args.platform_id == "22" * 64
    # Persisted for the dispatch to resolve + a re-drive to be idempotent.
    assert stored["generation"] == 6


def test_remint_fails_closed_when_the_dest_has_no_platform_id(
    monkeypatch: pytest.MonkeyPatch, _vault_and_mint: dict[str, Any]
) -> None:
    # An unresolvable / empty dest platform_id must FAIL the remint rather
    # than mint a ticket the KBS can never release. Minting it anyway is what
    # produced a migration that reported success while the destination guest
    # hung unable to unlock its disk.
    from apps.miners.models import MinerIdentity

    vm = make_vm(generation=5, host="node-src")
    _launch_record(vm, measurement_hex="cd" * 48)
    MinerIdentity.objects.create(
        miner_id="node-nochip", pubkey_hex="cc" * 32, platform_id=""
    )
    monkeypatch.setattr(migration_ticket, "persist_intake", lambda blob, **kw: None)

    with pytest.raises(EffectError, match="empty platform_id"):
        migration_ticket.remint_dest_ticket(
            vm, dest_node_id="node-nochip", new_gen=6
        )


def test_remint_fails_closed_when_the_dest_miner_is_unknown(
    monkeypatch: pytest.MonkeyPatch, _vault_and_mint: dict[str, Any]
) -> None:
    vm = make_vm(generation=5, host="node-src")
    _launch_record(vm, measurement_hex="cd" * 48)
    monkeypatch.setattr(migration_ticket, "persist_intake", lambda blob, **kw: None)

    with pytest.raises(EffectError, match="no MinerIdentity"):
        migration_ticket.remint_dest_ticket(
            vm, dest_node_id="ghost-dest", new_gen=6
        )


def test_remint_is_idempotent_returns_existing_new_gen_ticket(
    monkeypatch: pytest.MonkeyPatch, _vault_and_mint: dict[str, Any]
) -> None:
    from apps.orders.models import OrderTicketIntake

    vm = make_vm(generation=5, host="node-src")
    _launch_record(vm)
    # A prior tick already persisted the new_gen intake.
    OrderTicketIntake.objects.create(
        ticket_id="tk-existing",
        vm_id=vm.vm_id,
        tenant_id="tenant-a",
        user_id="user-a",
        lease_id=vm.lease_id,
        vm_generation=6,
        issue_time=1,
        expiry=2,
        node_id="node-dst",
        platform_id="chip-1",
        resource_class="small",
        kid_hex="6b6964",
        cose_blob=b"existing-blob",
        received_from="system:migration-remint",
    )

    # The stored ticket decodes, with the VM's (M0) key mode.
    from types import SimpleNamespace

    from apps.orders import validator

    monkeypatch.setattr(
        validator, "validate_ticket", lambda cose: SimpleNamespace(key_mode="hippius")
    )
    blob = migration_ticket.remint_dest_ticket(
        vm, dest_node_id="node-dst", new_gen=6
    )
    # The existing blob is returned verbatim — the mint was NOT re-run.
    assert blob == b"existing-blob"
    assert "args" not in _vault_and_mint


def test_remint_discards_a_pre_fix_ticket_with_an_empty_platform_id(
    monkeypatch: pytest.MonkeyPatch, _vault_and_mint: dict[str, Any]
) -> None:
    # A ticket minted BEFORE the dest-chip binding has platform_id="" and the
    # KBS denies it unconditionally (id_len == 0). The idempotent fast-path
    # must NOT hand it back — a retried migration recomputes the same new_gen,
    # so returning it would 403 at the key release again while still reporting
    # success, bypassing this fix for exactly the VMs it exists to repair.
    from apps.miners.models import MinerIdentity
    from apps.orders.models import OrderTicketIntake

    vm = make_vm(generation=5, host="node-src")
    _launch_record(vm)
    MinerIdentity.objects.create(
        miner_id="node-dst", pubkey_hex="bb" * 32, platform_id="22" * 64
    )
    OrderTicketIntake.objects.create(
        ticket_id="tk-poisoned",
        vm_id=vm.vm_id,
        tenant_id="tenant-a",
        user_id="user-a",
        lease_id=vm.lease_id,
        vm_generation=6,
        issue_time=1,
        expiry=2,
        node_id="node-dst",
        platform_id="",  # the pre-fix defect
        resource_class="small",
        kid_hex="6b6964",
        cose_blob=b"poisoned-blob",
        received_from="system:migration-remint",
    )
    monkeypatch.setattr(migration_ticket, "persist_intake", lambda blob, **kw: None)

    blob = migration_ticket.remint_dest_ticket(
        vm, dest_node_id="node-dst", new_gen=6
    )
    # Re-minted rather than reused, and the fresh ticket carries the dest chip.
    assert blob != b"poisoned-blob"
    assert _vault_and_mint["args"].platform_id == "22" * 64


def test_remint_fails_closed_on_a_malformed_dest_platform_id(
    monkeypatch: pytest.MonkeyPatch, _vault_and_mint: dict[str, Any]
) -> None:
    # The KBS compares against lowercase hex of the attested chip_id and
    # truncates to the ticket's byte-length, so a registered value that is not
    # valid hex of a CHIP_ID length would mint cleanly then 403 at release —
    # the same silent failure. Refuse it at mint time instead.
    from apps.miners.models import MinerIdentity

    vm = make_vm(generation=5, host="node-src")
    _launch_record(vm)
    MinerIdentity.objects.create(
        miner_id="node-badhex", pubkey_hex="cc" * 32, platform_id="nothex" * 4
    )
    monkeypatch.setattr(migration_ticket, "persist_intake", lambda blob, **kw: None)

    with pytest.raises(EffectError, match="malformed platform_id"):
        migration_ticket.remint_dest_ticket(
            vm, dest_node_id="node-badhex", new_gen=6
        )


def test_remint_fails_closed_on_a_dest_generation_inconsistent_with_its_chip(
    monkeypatch: pytest.MonkeyPatch, _vault_and_mint: dict[str, Any]
) -> None:
    # A dest registered `turin` with a 64-byte chip cannot be measured: the
    # remint refuses instead of minting a ticket for an unresolvable host.
    from apps.miners.models import MinerIdentity

    vm = make_vm(generation=5, host="node-src")
    _launch_record(vm)
    MinerIdentity.objects.create(
        miner_id="node-badgen",
        pubkey_hex="cc" * 32,
        platform_id="ab" * 64,
        snp_generation="turin",
    )
    monkeypatch.setattr(migration_ticket, "persist_intake", lambda blob, **kw: None)

    with pytest.raises(EffectError, match="snp-generation-chip-id-mismatch"):
        migration_ticket.remint_dest_ticket(
            vm, dest_node_id="node-badgen", new_gen=6
        )


def test_remint_fails_closed_without_a_launch_record(
    _vault_and_mint: dict[str, Any],
) -> None:
    from apps.orchestration.effects import EffectError

    vm = make_vm(generation=5, host="node-src")  # no launch record
    with pytest.raises(EffectError, match="no successful launch record"):
        migration_ticket.remint_dest_ticket(vm, dest_node_id="node-dst", new_gen=6)


def test_remint_fails_closed_without_a_measurement(
    monkeypatch: pytest.MonkeyPatch, _vault_and_mint: dict[str, Any]
) -> None:
    from apps.orchestration.effects import EffectError

    vm = make_vm(generation=5, host="node-src")
    rec = _launch_record(vm)
    # A record with neither a spec nor an emit measurement cannot mint a
    # ticket the KBS would gate — fail closed.
    rec.result_json = {"emit": {}}
    rec.save(update_fields=["result_json"])
    with pytest.raises(EffectError, match="no measurement_hex"):
        migration_ticket.remint_dest_ticket(vm, dest_node_id="node-dst", new_gen=6)


def test_mint_argv_carries_vm_generation(monkeypatch: pytest.MonkeyPatch) -> None:
    # The mint shell-out passes `--vm-generation <new_gen>` so the binary
    # binds the ticket to the migration generation (the binary defaults to 1).
    captured: dict[str, Any] = {}

    class _Proc:
        returncode = 0
        stderr = b""

    def _fake_run(argv: list[str], **kwargs: Any) -> Any:
        # Emulate the binary writing the COSE bytes to the `--out` path so
        # `mint`'s read-back succeeds.
        captured["argv"] = argv
        out_path = argv[argv.index("--out") + 1]
        with open(out_path, "wb") as fh:
            fh.write(b"cose-blob")
        return _Proc()

    monkeypatch.setattr(ticket_mint, "_bin_path", lambda: "/usr/local/bin/mint")
    # File-path mode: the resolver returns None and `mint` passes the
    # configured `VALI_L1_SIGNING_KEY_PATH` straight to `--signing-key`.
    monkeypatch.setattr(ticket_mint, "_resolve_l1_seed", lambda: None)
    monkeypatch.setattr(settings, "VALI_L1_SIGNING_KEY_PATH", "/keys/l1")
    monkeypatch.setattr(ticket_mint.subprocess, "run", _fake_run)

    args = ticket_mint.MintArgs(
        kid="k",
        ticket_id="t",
        tenant_id="te",
        user_id="u",
        vm_id="v",
        lease_id="l",
        node_id="n",
        platform_id="p",
        allowed_measurement_hex="ab" * 48,
        userdata_vault_path="secret/x/userdata",
        userdata_vault_version=1,
        luks_vault_path="secret/x/luks-kek",
        luks_vault_version=1,
        allowed_userdata_digest_hex="cd" * 32,
        flavor="small",
        vm_generation=6,
    )
    blob = ticket_mint.mint(args)
    assert blob == b"cose-blob"
    argv = captured["argv"]
    assert "--vm-generation" in argv
    assert argv[argv.index("--vm-generation") + 1] == "6"


# ── the §25 call sites after the recovery generalisation ───────────────
#
# `remint_dest_ticket` is now a thin wrapper over the shared `remint_ticket`
# (so KBS-state recovery reuses ONE implementation of ticket-minting rather
# than a second, divergent copy — the empty-`platform_id` defect came from
# exactly such a copy). These pin that §25 is behaviourally unchanged.


def test_dest_remint_keeps_the_migration_ticket_namespace_and_audit_string(
    monkeypatch: pytest.MonkeyPatch, _vault_and_mint: dict[str, Any]
) -> None:
    from apps.miners.models import MinerIdentity

    vm = make_vm(generation=5, host="node-src")
    _launch_record(vm)
    MinerIdentity.objects.create(miner_id="node-dst", pubkey_hex="bb" * 32, platform_id="22" * 64)
    persisted: dict[str, Any] = {}
    monkeypatch.setattr(
        migration_ticket, "persist_intake", lambda blob, **kw: persisted.update(kw)
    )

    migration_ticket.remint_dest_ticket(vm, dest_node_id="node-dst", new_gen=6)

    args = _vault_and_mint["args"]
    assert args.ticket_id.startswith("tk-mig-")
    assert persisted["generation"] == 6
    # The stored audit string is unchanged for migration rows.
    assert persisted["received_from"] == "system:migration-remint"


def test_recovery_remint_binds_the_vms_own_gen_and_host(
    monkeypatch: pytest.MonkeyPatch, _vault_and_mint: dict[str, Any]
) -> None:
    """The recovery entry point mints at the VM's CURRENT generation on its
    CURRENT host — never `new_gen`, never a destination.
    """
    from apps.miners.models import MinerIdentity

    vm = make_vm(generation=5, host="node-src")
    _launch_record(vm)
    MinerIdentity.objects.create(miner_id="node-src", pubkey_hex="aa" * 32, platform_id="11" * 64)
    persisted: dict[str, Any] = {}
    monkeypatch.setattr(
        migration_ticket, "persist_intake", lambda blob, **kw: persisted.update(kw)
    )

    migration_ticket.remint_current_ticket(vm)

    args = _vault_and_mint["args"]
    assert args.vm_generation == 5
    assert args.node_id == "node-src"
    assert args.platform_id == "11" * 64
    assert args.ticket_id.startswith("tk-rec-")
    assert persisted["received_from"] == "system:kbs-recover-remint"


def test_recovery_remint_never_replays_a_stored_current_gen_ticket(
    monkeypatch: pytest.MonkeyPatch, _vault_and_mint: dict[str, Any]
) -> None:
    """Tickets expire after 24h, so the stored launch-time ticket for the
    current generation CANNOT be replayed (the live KBS answers 400) — the
    recovery must always mint fresh, unlike the §25 re-drive.
    """
    from apps.miners.models import MinerIdentity
    from apps.orders.models import OrderTicketIntake

    vm = make_vm(generation=5, host="node-src")
    _launch_record(vm)
    MinerIdentity.objects.create(miner_id="node-src", pubkey_hex="aa" * 32, platform_id="11" * 64)
    OrderTicketIntake.objects.create(
        ticket_id="tk-launch-time",
        vm_id=vm.vm_id,
        tenant_id="tenant-a",
        user_id="user-a",
        lease_id=vm.lease_id,
        vm_generation=5,
        issue_time=1,
        expiry=2,
        node_id="node-src",
        platform_id="11" * 64,
        resource_class="small",
        kid_hex="6b6964",
        cose_blob=b"stale-launch-blob",
        received_from="system:launch",
    )
    monkeypatch.setattr(migration_ticket, "persist_intake", lambda blob, **kw: None)

    blob = migration_ticket.remint_current_ticket(vm)

    assert blob != b"stale-launch-blob"
    assert _vault_and_mint["args"].vm_generation == 5


def test_recovery_remint_fails_closed_without_a_host(
    _vault_and_mint: dict[str, Any],
) -> None:
    vm = make_vm(generation=5, host="")
    _launch_record(vm)
    with pytest.raises(EffectError, match="no bound host"):
        migration_ticket.remint_current_ticket(vm)
    assert "args" not in _vault_and_mint


def test_resolve_ticket_inputs_touches_no_vault_secret_and_writes_nothing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The dry-run path resolves EXACTLY what the committing path resolves,
    without reading a §20 secret or minting/persisting anything.
    """
    from apps.miners.models import MinerIdentity
    from apps.orders.models import OrderTicketIntake

    vm = make_vm(generation=5, host="node-src")
    _launch_record(vm, measurement_hex="cd" * 48)
    MinerIdentity.objects.create(miner_id="node-src", pubkey_hex="aa" * 32, platform_id="11" * 64)

    def _boom(*a: Any, **k: Any) -> Any:  # pragma: no cover — must not run
        raise AssertionError("resolution must not touch Vault or mint")

    monkeypatch.setattr(vault_kv, "get_kv", _boom)
    monkeypatch.setattr(ticket_mint, "mint", _boom)

    inputs = migration_ticket.resolve_ticket_inputs(vm, node_id="node-src", generation=5)

    assert inputs.generation == 5
    assert inputs.node_id == "node-src"
    assert inputs.platform_id == "11" * 64
    assert inputs.measurement_hex == "cd" * 48
    assert OrderTicketIntake.objects.count() == 0


def test_remint_digests_the_plaintext_from_the_copy_vali_can_open(
    monkeypatch: pytest.MonkeyPatch, _vault_and_mint: dict[str, Any]
) -> None:
    """THE §25 / KBS-recovery claim.

    The §6 digest is over the cloud-init PLAINTEXT — the guest re-derives
    it that way and refuses the release otherwise — and it binds a FRESH
    ticket_id, so it cannot be reused from the launch. vali therefore has
    to hash the plaintext again, from the only copy it can open: the
    working copy under `ud-<vm_id>`. Reading the canonical path instead
    (what this did once that copy started being wrapped) hashes ciphertext
    and mints a ticket that denies at release — a migration that reports
    Done and a VM that never unlocks.
    """
    from apps.miners.models import MinerIdentity
    from apps.orchestration.services import userdata_digest

    vm = make_vm(generation=5, host="node-src")
    _launch_record(vm, measurement_hex="cd" * 48)
    MinerIdentity.objects.create(
        miner_id="node-dst", pubkey_hex="bb" * 32, platform_id="22" * 64
    )
    monkeypatch.setattr(migration_ticket, "persist_intake", lambda blob, **kw: None)

    migration_ticket.remint_dest_ticket(vm, dest_node_id="node-dst", new_gen=6)
    args = _vault_and_mint["args"]

    assert args.allowed_userdata_digest_hex == userdata_digest.userdata_digest_hex(
        tenant_id="tenant-a",
        vm_id=vm.vm_id,
        ticket_id=args.ticket_id,
        secret_type=userdata_digest.SECRET_TYPE_USERDATA,
        path=args.userdata_vault_path,
        version=args.userdata_vault_version,
        plaintext=b"#cloud-config\n",
    )
    # …and NOT over the ciphertext a read of either path returns.
    assert args.allowed_userdata_digest_hex != userdata_digest.userdata_digest_hex(
        tenant_id="tenant-a",
        vm_id=vm.vm_id,
        ticket_id=args.ticket_id,
        secret_type=userdata_digest.SECRET_TYPE_USERDATA,
        path=args.userdata_vault_path,
        version=args.userdata_vault_version,
        plaintext=_WRAPPED_WORKING_COPY,
    )
    # The ticket binds the CANONICAL version, and the working copy was
    # read AT THAT SAME version — the pairing is what makes "these bytes
    # are what that canonical version holds" provable. `launch_on_miner`
    # writes both in one step, so the numbers line up; reading the working
    # copy at "latest" instead would hash whatever a later attempt left.
    # The ticket binds the CANONICAL version, and the working copy it
    # hashed STAMPS that same version — which is what makes "these bytes
    # are what that canonical version holds" provable rather than assumed
    # (the two staging writes are not atomic).
    assert args.userdata_vault_version == _CANONICAL_VERSION


def test_remint_refuses_when_only_a_wrapped_canonical_copy_exists(
    monkeypatch: pytest.MonkeyPatch, _vault_and_mint: dict[str, Any]
) -> None:
    """No working copy (a VM staged by hand, or one whose copy was
    removed) and a canonical copy wrapped under the KBS-only key: vali
    cannot obtain the plaintext at all. Refuse — the alternative is
    hashing ciphertext and minting a ticket nobody can redeem."""
    from apps.miners.models import MinerIdentity

    vm = make_vm(generation=5, host="node-src")
    _launch_record(vm, measurement_hex="cd" * 48)
    MinerIdentity.objects.create(
        miner_id="node-dst", pubkey_hex="bb" * 32, platform_id="22" * 64
    )

    def kv(mount, path, **k):
        if path.endswith("-pending"):
            raise vault_kv.VaultNotFound("no working copy")
        return b"vault:v1:" + b"#cloud-config\n".hex().encode("ascii")

    monkeypatch.setattr(vault_kv, "get_kv", kv)
    with pytest.raises(EffectError, match="no usable working copy"):
        migration_ticket.remint_dest_ticket(vm, dest_node_id="node-dst", new_gen=6)
    assert "args" not in _vault_and_mint


def test_remint_refuses_a_working_copy_stamped_for_another_version(
    monkeypatch: pytest.MonkeyPatch, _vault_and_mint: dict[str, Any]
) -> None:
    """The canonical write and the working-copy write are two independent
    KV puts. A canonical success followed by a failure here leaves the
    working copy holding an EARLIER attempt's bytes — with a different
    NetBird key in them. Hashing those mints a ticket the guest denies at
    release, so the stamp mismatch has to fail closed instead."""
    from apps.miners.models import MinerIdentity

    vm = make_vm(generation=5, host="node-src")
    _launch_record(vm, measurement_hex="cd" * 48)
    MinerIdentity.objects.create(
        miner_id="node-dst", pubkey_hex="bb" * 32, platform_id="22" * 64
    )

    def kv(mount, path, **k):
        if path.endswith("-pending"):
            return _stamped(b"#cloud-config\nolder-attempt", _CANONICAL_VERSION - 1)
        return b"vault:v1:" + b"#cloud-config\n".hex().encode("ascii")

    monkeypatch.setattr(vault_kv, "get_kv", kv)
    with pytest.raises(EffectError, match="stamped for canonical version"):
        migration_ticket.remint_dest_ticket(vm, dest_node_id="node-dst", new_gen=6)
    assert "args" not in _vault_and_mint


def test_remint_falls_back_to_a_legacy_plaintext_canonical_copy(
    monkeypatch: pytest.MonkeyPatch, _vault_and_mint: dict[str, Any]
) -> None:
    """A VM from before the wrapping stores its cloud-init in the clear at
    the canonical path and has no working copy. The plaintext IS readable,
    so it still migrates — that is what keeps those VMs recoverable."""
    from apps.miners.models import MinerIdentity
    from apps.orchestration.services import userdata_digest

    vm = make_vm(generation=5, host="node-src")
    _launch_record(vm, measurement_hex="cd" * 48)
    MinerIdentity.objects.create(
        miner_id="node-dst", pubkey_hex="bb" * 32, platform_id="22" * 64
    )
    monkeypatch.setattr(migration_ticket, "persist_intake", lambda blob, **kw: None)

    def kv(mount, path, **k):
        if path.endswith("-pending"):
            raise vault_kv.VaultNotFound("no working copy")
        return b"#cloud-config\nlegacy"

    monkeypatch.setattr(vault_kv, "get_kv", kv)
    migration_ticket.remint_dest_ticket(vm, dest_node_id="node-dst", new_gen=6)
    args = _vault_and_mint["args"]
    assert args.allowed_userdata_digest_hex == userdata_digest.userdata_digest_hex(
        tenant_id="tenant-a",
        vm_id=vm.vm_id,
        ticket_id=args.ticket_id,
        secret_type=userdata_digest.SECRET_TYPE_USERDATA,
        path=args.userdata_vault_path,
        version=args.userdata_vault_version,
        plaintext=b"#cloud-config\nlegacy",
    )


def test_remint_refuses_a_plaintext_value_at_the_working_path(
    monkeypatch: pytest.MonkeyPatch, _vault_and_mint: dict[str, Any]
) -> None:
    """A VM launched between the canonical wrapping (#1065) and the
    working copy has a PLAINTEXT value at `…/userdata-pending`: the
    pre-substitution template an older intake wrote there. It is not a
    copy of the canonical bytes — it still carries `{{NETBIRD_SETUP_KEY}}`
    — so digesting it mints a ticket bound to bytes the guest never
    receives. Refuse rather than pass it through as a legacy plaintext."""
    from apps.miners.models import MinerIdentity

    vm = make_vm(generation=5, host="node-src")
    _launch_record(vm, measurement_hex="cd" * 48)
    MinerIdentity.objects.create(
        miner_id="node-dst", pubkey_hex="bb" * 32, platform_id="22" * 64
    )

    def kv(mount, path, **k):
        if path.endswith("-pending"):
            return b"#cloud-config\n# {{NETBIRD_SETUP_KEY}}\n"  # the template
        return b"vault:v1:" + b"#cloud-config\nsubstituted".hex().encode("ascii")

    monkeypatch.setattr(vault_kv, "get_kv", kv)
    with pytest.raises(EffectError, match="no usable working copy"):
        migration_ticket.remint_dest_ticket(vm, dest_node_id="node-dst", new_gen=6)
    assert "args" not in _vault_and_mint
