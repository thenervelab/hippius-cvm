"""`vali_kbs_recover` — KBS-state recovery after a KBS restart wiped it.

One test per CLAIM the command makes, not per function:

1. dry-run (the DEFAULT) mutates NOTHING — no mint, no intake row, no
   register, no seed.
2. a committed recovery re-mints at the VM's OWN generation + OWN host
   (never `new_gen`, never a destination) and registers that exact blob.
3. the re-mint is always FRESH — a stored (24h-expiring) intake for the
   current generation is never replayed.
4. a VM with no measurement is refused WITHOUT minting anything.
5. one VM's failure does not stop the next VM from being processed, and the
   command exits non-zero.
6. `--boot-counter` omitted ⇒ the seed endpoint is never called.
7. the seed happens BEFORE the register (registering first lets a guest boot
   race the seed across `check_only`/`commit` and desynchronise the counter,
   which the KBS's `stored != 0` guard then makes uncorrectable), and a seed
   that did not succeed SKIPS the register.
8. a 404 from the (undeployed) seed route is a clear, NON-fatal per-VM
   message rather than a crash.
9. a `409` is disambiguated by whether THIS run already got a 200: our own
   retry is a benign no-op, a row that was never wiped is NOT success (its
   own bucket, and the register is skipped).
10. a `400` aborts the whole run instead of being iterated past.
11. the counter reaches the KBS VERBATIM (no +1/-1).
12. the counter file is parsed STRICTLY and a malformed/truncated/empty one
    refuses BEFORE any network call.
13. the one-shot seed refuses to commit without `--yes`.
"""

from __future__ import annotations

from typing import Any
from unittest import mock

import pytest
from django.conf import settings
from django.core.management import CommandError, call_command
from django.utils import timezone

from apps.lifecycle.models import VmState
from apps.miners.models import MinerIdentity
from apps.orchestration import effects, kbs_admin
from apps.orchestration.models import LaunchJob, LaunchJobState
from apps.orchestration.services import migration_ticket, ticket_mint, vault_kv
from apps.orders.models import OrderTicketIntake

from .factories import make_service_client, make_vm

pytestmark = pytest.mark.django_db

COMMAND = "vali_kbs_recover"


def _launch_record(vm: Any, *, measurement_hex: str = "ab" * 48) -> LaunchJob:
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
            "kid": "l1-order-ticket-dev-v1",
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


class Spy:
    """Records every mutating effect the command can perform."""

    def __init__(self) -> None:
        self.mint_args: list[ticket_mint.MintArgs] = []
        self.registered: list[tuple[str, bytes]] = []
        self.seeded: list[tuple[str, int]] = []
        #: Every mutating call in the order it happened (`seed:<vm>` /
        #: `register:<vm>`) — the seed MUST precede the register.
        self.order: list[str] = []
        self.register_error: Exception | None = None
        self.seed_error: Exception | None = None
        self.seed_result: effects.SeedBootCounterOk | None = None
        self.register_error_for: set[str] = set()


@pytest.fixture
def spy(monkeypatch: pytest.MonkeyPatch, tmp_path: Any) -> Spy:
    """Stub Vault + the mint shell-out + the two KBS admin calls."""
    s = Spy()
    monkeypatch.setattr(settings, "VALI_VAULT_KV_MOUNT", "secret", raising=False)
    monkeypatch.setattr(settings, "VALI_VAULT_KV_PREFIX", "hc/tenants", raising=False)
    monkeypatch.setattr(vault_kv, "latest_version", lambda *a, **k: 1)
    monkeypatch.setattr(vault_kv, "get_kv", lambda *a, **k: b"#cloud-config\n")

    def _fake_mint(args: ticket_mint.MintArgs) -> bytes:
        s.mint_args.append(args)
        return f"cose-{args.vm_id}-{args.vm_generation}".encode()

    monkeypatch.setattr(ticket_mint, "mint", _fake_mint)
    # The intake persistence shells out to the ticket-validator binary; the
    # mint blob above is a stand-in, so stub the store.
    monkeypatch.setattr(migration_ticket, "persist_intake", lambda blob, **kw: None)

    def _fake_register(*, vm_id: str, cose_ticket: bytes) -> Any:
        if s.register_error is not None and vm_id in s.register_error_for:
            raise s.register_error
        s.order.append(f"register:{vm_id}")
        s.registered.append((vm_id, cose_ticket))
        return kbs_admin.KbsAdminRegisterOk(
            ticket_id=f"tk-{vm_id}", vm_id=vm_id, vm_generation=7, cached=False
        )

    monkeypatch.setattr(kbs_admin, "register_vm_active_with_vm_id", _fake_register)

    def _fake_seed(vm_id: str, *, counter: int) -> Any:
        s.order.append(f"seed:{vm_id}")
        s.seeded.append((vm_id, counter))
        if s.seed_error is not None:
            raise s.seed_error
        return s.seed_result or effects.SeedBootCounterOk(
            counter=counter, previous=0, already_recovered=False
        )

    monkeypatch.setattr(effects, "seed_boot_counter", _fake_seed)
    return s


def _vm_with_launch(vm_id: str = "vm-a", *, gen: int = 7, host: str = "miner-a"):
    vm = make_vm(vm_id, generation=gen, host=host)
    _launch_record(vm)
    MinerIdentity.objects.get_or_create(
        miner_id=host, defaults={"pubkey_hex": "bb" * 32, "platform_id": "22" * 64}
    )
    return vm


# ── CLAIM 0: a VM whose digest cannot be re-derived is refused up front ──
#
# The re-mint hashes the cloud-init plaintext. For a VM staged before the
# working copy existed, the canonical copy is Transit-wrapped under the
# KBS-only key and the working path holds the pre-substitution template —
# nothing vali can re-derive the §6 digest from. Live on 2026-09-21: the
# dry-run said `would-recover`, the commit seeded the one-shot boot counter
# and THEN failed the mint, leaving three tenant VMs seeded but
# unregistered in a fresh KBS. Both paths must refuse before any write.


def _pre_wrapping_vm(monkeypatch: pytest.MonkeyPatch, vm_id: str = "vm-legacy") -> None:
    _vm_with_launch(vm_id)
    monkeypatch.setattr(settings, "VALI_VAULT_ADDR", "https://vault.invalid:8200", raising=False)

    def get_kv(mount: str, path: str, **kw: Any) -> bytes:
        if path.endswith("-pending"):
            return b"#cloud-config\n# {{NETBIRD_SETUP_KEY}}\n"  # plaintext template
        return b"vault:v1:" + b"#cloud-config\n".hex().encode("ascii")  # wrapped

    monkeypatch.setattr(vault_kv, "get_kv", get_kv)


def test_dry_run_refuses_a_vm_whose_digest_cannot_be_rederived(
    spy: Spy, monkeypatch: pytest.MonkeyPatch, capsys: Any
) -> None:
    _pre_wrapping_vm(monkeypatch)
    with pytest.raises(SystemExit):
        call_command(COMMAND, "--vm-id", "vm-legacy")
    out = capsys.readouterr().out
    assert "outcome=failed" in out
    assert "would-recover" not in out
    assert "Re-stage the userdata" in out


def test_commit_refuses_such_a_vm_before_the_one_shot_seed(
    spy: Spy, monkeypatch: pytest.MonkeyPatch, tmp_path: Any, capsys: Any
) -> None:
    _pre_wrapping_vm(monkeypatch)
    counter_file = tmp_path / "bc"
    counter_file.write_text("1")
    with pytest.raises(SystemExit):
        call_command(
            COMMAND,
            "--vm-id",
            "vm-legacy",
            "--boot-counter-file",
            str(counter_file),
            "--counter-source",
            "miner-a",
            "--commit",
            "--yes",
        )
    out = capsys.readouterr().out
    assert "outcome=failed" in out
    assert spy.seeded == []  # the one-shot seed never happened
    assert spy.mint_args == [] and spy.registered == []


# ── CLAIM 1: dry-run is the default and mutates nothing ────────────────


def test_dry_run_is_the_default_and_mutates_nothing(spy: Spy) -> None:
    _vm_with_launch()
    call_command(COMMAND, "--vm-id", "vm-a")

    assert spy.mint_args == []
    assert spy.registered == []  # THE register effect was never called
    assert spy.seeded == []
    assert OrderTicketIntake.objects.count() == 0


def test_dry_run_still_reports_the_resolved_plan(spy: Spy, capsys: Any) -> None:
    _vm_with_launch()
    call_command(COMMAND, "--vm-id", "vm-a")
    out = capsys.readouterr().out
    assert "outcome=would-recover" in out
    assert "gen=7" in out and "node=miner-a" in out
    assert "mode=dry-run" in out


def test_dry_run_and_commit_together_are_refused(spy: Spy) -> None:
    _vm_with_launch()
    with pytest.raises(CommandError, match="contradictory"):
        call_command(COMMAND, "--vm-id", "vm-a", "--dry-run", "--commit")
    assert spy.registered == []


# ── CLAIM 2: same-gen / same-node re-mint ──────────────────────────────


def test_commit_remints_at_the_vms_own_generation_and_host(spy: Spy) -> None:
    _vm_with_launch(gen=7, host="miner-a")
    # A second miner exists so "picked the VM's own host" is a real assertion.
    MinerIdentity.objects.create(miner_id="miner-i", pubkey_hex="cc" * 32, platform_id="33" * 64)

    call_command(COMMAND, "--vm-id", "vm-a", "--commit")

    assert len(spy.mint_args) == 1
    args = spy.mint_args[0]
    # NOT new_gen (8), NOT a destination — the VM's CURRENT placement.
    assert args.vm_generation == 7
    assert args.node_id == "miner-a"
    assert args.platform_id == "22" * 64
    assert args.allowed_measurement_hex == "ab" * 48
    # ...and exactly that blob is what gets registered.
    assert spy.registered == [("vm-a", b"cose-vm-a-7")]


def test_recovery_ticket_uses_the_recovery_namespace(spy: Spy) -> None:
    _vm_with_launch()
    call_command(COMMAND, "--vm-id", "vm-a", "--commit")
    assert spy.mint_args[0].ticket_id.startswith(migration_ticket.TICKET_PREFIX_RECOVERY)


# ── CLAIM 3: never replay a stored (expiring) ticket ───────────────────


def test_commit_remints_even_when_a_stored_same_gen_ticket_exists(spy: Spy) -> None:
    vm = _vm_with_launch(gen=7)
    OrderTicketIntake.objects.create(
        ticket_id="tk-launch-time",
        vm_id=vm.vm_id,
        tenant_id="tenant-a",
        user_id="user-a",
        lease_id=vm.lease_id,
        vm_generation=7,
        issue_time=1,
        expiry=2,  # long expired — tickets live 24h
        node_id="miner-a",
        platform_id="22" * 64,
        resource_class="small",
        kid_hex="6b6964",
        cose_blob=b"stale-launch-blob",
        received_from="system:launch",
    )

    call_command(COMMAND, "--vm-id", "vm-a", "--commit")

    assert len(spy.mint_args) == 1, "recovery must mint fresh, never replay"
    assert spy.registered == [("vm-a", b"cose-vm-a-7")]


# ── CLAIM 4: fail closed, never mint against a guess ───────────────────


def test_a_vm_without_a_measurement_is_refused_without_minting(spy: Spy) -> None:
    vm = make_vm("vm-nomeas", generation=7, host="miner-a")
    rec = _launch_record(vm)
    rec.result_json = {"emit": {}}
    rec.save(update_fields=["result_json"])
    MinerIdentity.objects.create(miner_id="miner-a", pubkey_hex="bb" * 32, platform_id="22" * 64)

    with pytest.raises(SystemExit) as exc:
        call_command(COMMAND, "--vm-id", "vm-nomeas", "--commit")

    assert exc.value.code == 1
    assert spy.mint_args == []
    assert spy.registered == []


def test_a_vm_without_a_host_is_refused_without_minting(spy: Spy) -> None:
    vm = make_vm("vm-nohost", generation=7, host="")
    _launch_record(vm)

    with pytest.raises(SystemExit):
        call_command(COMMAND, "--vm-id", "vm-nohost", "--commit")

    assert spy.mint_args == []
    assert spy.registered == []


def test_a_vm_without_a_launch_record_is_refused_without_minting(spy: Spy) -> None:
    make_vm("vm-nolaunch", generation=7, host="miner-a")
    MinerIdentity.objects.create(miner_id="miner-a", pubkey_hex="bb" * 32, platform_id="22" * 64)

    with pytest.raises(SystemExit):
        call_command(COMMAND, "--vm-id", "vm-nolaunch", "--commit")

    assert spy.mint_args == []


# ── CLAIM 5: per-VM isolation ──────────────────────────────────────────


def test_one_vms_failure_does_not_prevent_the_next(spy: Spy, capsys: Any) -> None:
    # vm-bad has no measurement (fails resolution); vm-ok is healthy.
    bad = make_vm("vm-bad", generation=7, host="miner-a")
    rec = _launch_record(bad)
    rec.result_json = {"emit": {}}
    rec.save(update_fields=["result_json"])
    _vm_with_launch("vm-ok", gen=7, host="miner-a")

    with pytest.raises(SystemExit) as exc:
        call_command(COMMAND, "--vm-id", "vm-bad", "--vm-id", "vm-ok", "--commit")

    assert exc.value.code == 1  # non-zero because one failed
    assert spy.registered == [("vm-ok", b"cose-vm-ok-7")]  # the next one ran
    out = capsys.readouterr().out
    assert "vm=vm-bad outcome=failed" in out
    assert "vm=vm-ok outcome=registered" in out
    assert "total=2 ok=1 warned=0 failed=1" in out


def test_a_register_failure_does_not_prevent_the_next(spy: Spy, capsys: Any) -> None:
    _vm_with_launch("vm-1", gen=7, host="miner-a")
    _vm_with_launch("vm-2", gen=7, host="miner-a")
    spy.register_error = kbs_admin.KbsAdminConflict("409 conflict — state drift")
    spy.register_error_for = {"vm-1"}

    with pytest.raises(SystemExit):
        call_command(COMMAND, "--vm-id", "vm-1", "--vm-id", "vm-2", "--commit")

    assert spy.registered == [("vm-2", b"cose-vm-2-7")]
    assert "vm=vm-1 outcome=failed" in capsys.readouterr().out


def test_all_active_selects_every_active_vm(spy: Spy) -> None:
    _vm_with_launch("vm-act-1", host="miner-a")
    _vm_with_launch("vm-act-2", host="miner-a")
    gone = make_vm("vm-dead", generation=7, host="miner-a", state=VmState.DESTROYED)
    _launch_record(gone)

    call_command(COMMAND, "--all-active", "--commit")

    assert sorted(v for v, _ in spy.registered) == ["vm-act-1", "vm-act-2"]


# ── CLAIM 6: no --boot-counter ⇒ no seed call ──────────────────────────


def test_boot_counter_omitted_means_no_seed_call(spy: Spy) -> None:
    _vm_with_launch()
    call_command(COMMAND, "--vm-id", "vm-a", "--commit")
    assert spy.registered  # the register half ran
    assert spy.seeded == []  # ...and the seed was never attempted


def test_boot_counter_seeds_when_supplied(spy: Spy, tmp_path: Any) -> None:
    _vm_with_launch()
    counter_file = tmp_path / "boot-counter"
    counter_file.write_bytes(b"3\n")

    call_command(
        COMMAND,
        "--vm-id",
        "vm-a",
        "--commit",
        "--boot-counter-file",
        str(counter_file),
        "--yes",
    )

    assert spy.seeded == [("vm-a", 3)]


def test_dry_run_never_seeds(spy: Spy, tmp_path: Any, capsys: Any) -> None:
    _vm_with_launch()
    counter_file = tmp_path / "boot-counter"
    counter_file.write_bytes(b"3\n")

    call_command(COMMAND, "--vm-id", "vm-a", "--boot-counter-file", str(counter_file))

    assert spy.seeded == []
    out = capsys.readouterr().out
    assert "seed-plan vm=vm-a counter=3" in out
    # The plan states the ORDER explicitly.
    assert "order=1:seed-counter(3) 2:remint+register" in out


# ── CLAIM 7: seed BEFORE register; a bad seed skips the register ───────


def test_the_seed_happens_before_the_register(spy: Spy, tmp_path: Any) -> None:
    # Registering first would let a guest boot race the seed: check_only(1)
    # passes on the wiped store, we seed to N, then commit(1) fails (1 <= N)
    # — the guest booted, the KBS counter did not move, and guard 1 blocks
    # every correction. A VM that is not registered cannot be released to.
    _vm_with_launch()
    counter_file = tmp_path / "boot-counter"
    counter_file.write_bytes(b"3\n")

    call_command(
        COMMAND,
        "--vm-id",
        "vm-a",
        "--commit",
        "--boot-counter-file",
        str(counter_file),
        "--yes",
    )

    assert spy.order == ["seed:vm-a", "register:vm-a"]


def test_a_failed_seed_skips_the_register(spy: Spy, tmp_path: Any, capsys: Any) -> None:
    _vm_with_launch()
    counter_file = tmp_path / "boot-counter"
    counter_file.write_bytes(b"3\n")
    spy.seed_error = effects.EffectError("kbs-admin: KBS returned HTTP 500")

    with pytest.raises(SystemExit):
        call_command(
            COMMAND,
            "--vm-id",
            "vm-a",
            "--commit",
            "--boot-counter-file",
            str(counter_file),
            "--yes",
        )

    # Unregistered is inert + retryable; registered-with-an-unseeded-counter
    # is the desynchronisation window.
    assert spy.registered == []
    assert "register SKIPPED" in capsys.readouterr().out


# ── CLAIM 8/9: the seed route's absence is non-fatal; 409 is a no-op ───


def test_a_missing_seed_route_is_a_clear_non_fatal_message(
    spy: Spy, tmp_path: Any, capsys: Any
) -> None:
    _vm_with_launch()
    counter_file = tmp_path / "boot-counter"
    counter_file.write_bytes(b"5")
    spy.seed_error = effects.KbsRouteMissing("404")

    # No SystemExit / traceback — a missing route is a WARNING.
    call_command(
        COMMAND,
        "--vm-id",
        "vm-a",
        "--commit",
        "--boot-counter-file",
        str(counter_file),
        "--yes",
    )

    out = capsys.readouterr().out
    assert "outcome=seed-route-missing+register-skipped" in out
    assert "not deployed" in out
    assert "total=1 ok=0 warned=1 failed=0" in out
    # The counter could not be recovered, so the register is not attempted.
    assert spy.registered == []


def test_a_409_with_no_prior_200_is_not_reported_as_success(
    spy: Spy, tmp_path: Any, capsys: Any
) -> None:
    # The KBS's guard 1 fires on `stored != 0`, so a 409 says only "the row
    # is not wiped". With no 200 from US earlier in this run, the row was
    # already populated before we started: nothing was done, the operator's
    # premise was false, and calling that a recovery mid-lockout is the wrong
    # conclusion at the worst moment.
    _vm_with_launch()
    counter_file = tmp_path / "boot-counter"
    counter_file.write_bytes(b"5")
    spy.seed_result = effects.SeedBootCounterOk(counter=5, previous=0, already_recovered=True)

    call_command(
        COMMAND,
        "--vm-id",
        "vm-a",
        "--commit",
        "--boot-counter-file",
        str(counter_file),
        "--yes",
    )

    out = capsys.readouterr().out
    assert "outcome=seed-refused-not-wiped+register-skipped" in out
    assert "NO recovery happened" in out
    # Its OWN bucket — never folded into the success count.
    assert "total=1 ok=0 warned=1 failed=0" in out
    # ...and we do not half-act on a premise already known to be false.
    assert spy.registered == []


def test_a_409_after_our_own_200_in_the_same_run_is_a_benign_noop() -> None:
    # The other 409: our own seed landed earlier in THIS invocation and we
    # re-observed it on a retry. Only the run-local record distinguishes the
    # two — the wire response is identical and `previous` is always 0.
    from apps.orchestration.management.commands.vali_kbs_recover import (
        _OK_SEED_NOOP_REGISTERED,
        _WARN_SEED_NOT_WIPED,
        Command,
        SeedInput,
    )

    seed = SeedInput(counter=5, provenance="test")
    ok_200 = effects.SeedBootCounterOk(counter=5, previous=0, already_recovered=False)
    conflict_409 = effects.SeedBootCounterOk(counter=5, previous=0, already_recovered=True)

    # A FRESH run that sees a 409 first has no evidence it did anything.
    fresh = Command()
    fresh._seeded_ok = set()
    with mock.patch.object(effects, "seed_boot_counter", return_value=conflict_409):
        fresh_outcome, _ = fresh._seed_one("vm-a", seed)
    assert fresh_outcome == _WARN_SEED_NOT_WIPED

    # A run whose OWN 200 landed first — and the record of that 200 must be
    # made by the 200 path itself, not by the test.
    ours = Command()
    ours._seeded_ok = set()
    with mock.patch.object(effects, "seed_boot_counter", side_effect=[ok_200, conflict_409]):
        first_outcome, _ = ours._seed_one("vm-a", seed)
        retry_outcome, retry_detail = ours._seed_one("vm-a", seed)

    assert first_outcome == "seeded+registered"
    assert retry_outcome == _OK_SEED_NOOP_REGISTERED
    assert "OUR OWN seed" in retry_detail


def test_a_400_aborts_the_whole_run_rather_than_iterating(spy: Spy, tmp_path: Any) -> None:
    # vali's own preconditions make a 400 unreachable, so it means vali and
    # the deployed KBS disagree about the contract (e.g. a lowered server
    # cap). Every later VM would fail identically — abort, do not iterate.
    _vm_with_launch()
    counter_file = tmp_path / "boot-counter"
    counter_file.write_bytes(b"5")
    spy.seed_error = effects.KbsAdminContractMismatch("400 seed-above-cap")

    with pytest.raises(CommandError, match="ABORTING"):
        call_command(
            COMMAND,
            "--vm-id",
            "vm-a",
            "--commit",
            "--boot-counter-file",
            str(counter_file),
            "--yes",
        )

    assert spy.registered == []


def test_the_counter_is_seeded_verbatim(spy: Spy, tmp_path: Any) -> None:
    # `guest-release::read_last_counter` returns `prev + 1` from this file,
    # so the file holds the LAST KBS-COMMITTED value and the KBS must be
    # seeded with it UNCHANGED. An off-by-one here is the unrecoverable case.
    _vm_with_launch()
    counter_file = tmp_path / "boot-counter"
    counter_file.write_bytes(b"7\n")

    call_command(
        COMMAND,
        "--vm-id",
        "vm-a",
        "--commit",
        "--boot-counter-file",
        str(counter_file),
        "--yes",
    )

    assert spy.seeded == [("vm-a", 7)]  # not 6, not 8


def test_a_real_seed_failure_is_a_failure(spy: Spy, tmp_path: Any) -> None:
    _vm_with_launch()
    counter_file = tmp_path / "boot-counter"
    counter_file.write_bytes(b"5")
    spy.seed_error = effects.EffectError("kbs-admin: KBS returned HTTP 500")

    with pytest.raises(SystemExit) as exc:
        call_command(
            COMMAND,
            "--vm-id",
            "vm-a",
            "--commit",
            "--boot-counter-file",
            str(counter_file),
            "--yes",
        )
    assert exc.value.code == 1


# ── CLAIM 10: strict counter parsing, BEFORE any network call ──────────


@pytest.mark.parametrize(
    "content",
    [
        b"",  # empty
        b"\n",  # whitespace only
        b"  \n",
        b"12\n34\n",  # multi-line
        b"+12",  # signed
        b"-12",
        b"012",  # leading zero (a truncated/padded read)
        b"12abc",
        b"abc",
        b"1 2",
        b"\xff\xfe",  # non-ASCII / binary garbage
    ],
)
def test_a_malformed_counter_file_refuses_before_any_network_call(
    spy: Spy, tmp_path: Any, content: bytes
) -> None:
    _vm_with_launch()
    counter_file = tmp_path / "boot-counter"
    counter_file.write_bytes(content)

    with pytest.raises(CommandError):
        call_command(
            COMMAND,
            "--vm-id",
            "vm-a",
            "--commit",
            "--boot-counter-file",
            str(counter_file),
            "--yes",
        )

    # The refusal happened BEFORE anything left vali.
    assert spy.seeded == []
    assert spy.registered == []
    assert spy.mint_args == []


def test_an_empty_counter_file_says_so_distinctly(spy: Spy, tmp_path: Any) -> None:
    # A zero-byte read is a materially different operator situation from
    # garbage in the file (wrong path / the state disk was not mounted), and
    # it is the most likely truncation. It gets its OWN message rather than
    # falling through to the generic "not a bare unsigned integer" — and that
    # message must steer AWAY from the tempting wrong move: `read_last_counter`
    # treats an absent/empty file as prev=0 and submits 1, which a wiped KBS
    # row already accepts, so the right action is to seed NOTHING. Seeding 1
    # would burn the VM's single attempt and guard-1-lock any later recovery.
    _vm_with_launch()
    counter_file = tmp_path / "boot-counter"
    counter_file.write_bytes(b"")
    with pytest.raises(CommandError, match="do NOT substitute --boot-counter 1"):
        call_command(
            COMMAND,
            "--vm-id",
            "vm-a",
            "--commit",
            "--boot-counter-file",
            str(counter_file),
            "--yes",
        )
    assert spy.seeded == []


def test_an_unreadable_counter_file_refuses(spy: Spy, tmp_path: Any) -> None:
    # Same corollary as the empty file: an absent one means the guest submits
    # 1 against a wiped row, so there is no seed value to derive.
    _vm_with_launch()
    with pytest.raises(CommandError, match="do NOT substitute"):
        call_command(
            COMMAND,
            "--vm-id",
            "vm-a",
            "--commit",
            "--boot-counter-file",
            str(tmp_path / "nope"),
            "--yes",
        )
    assert spy.registered == []


@pytest.mark.parametrize("content", [b"0", b"0\n"])
def test_a_zero_counter_is_refused(spy: Spy, tmp_path: Any, content: bytes) -> None:
    _vm_with_launch()
    counter_file = tmp_path / "boot-counter"
    counter_file.write_bytes(content)
    with pytest.raises(CommandError, match="counter-zero"):
        call_command(
            COMMAND,
            "--vm-id",
            "vm-a",
            "--commit",
            "--boot-counter-file",
            str(counter_file),
            "--yes",
        )
    assert spy.seeded == []


def test_a_counter_above_the_kbs_cap_is_refused(spy: Spy, tmp_path: Any) -> None:
    _vm_with_launch()
    counter_file = tmp_path / "boot-counter"
    counter_file.write_bytes(str(effects.MAX_SEED_COUNTER + 1).encode())
    with pytest.raises(CommandError, match="seed-above-cap"):
        call_command(
            COMMAND,
            "--vm-id",
            "vm-a",
            "--commit",
            "--boot-counter-file",
            str(counter_file),
            "--yes",
        )
    assert spy.seeded == []


def test_a_valid_counter_file_parses_exactly(spy: Spy, tmp_path: Any) -> None:
    _vm_with_launch()
    counter_file = tmp_path / "boot-counter"
    counter_file.write_bytes(b"4096\n")  # the cap itself is legal
    call_command(
        COMMAND,
        "--vm-id",
        "vm-a",
        "--commit",
        "--boot-counter-file",
        str(counter_file),
        "--yes",
    )
    assert spy.seeded == [("vm-a", 4096)]


# ── CLAIM 11: the one-shot seed demands explicit confirmation ─────────


def test_committing_a_seed_without_yes_is_refused(spy: Spy, tmp_path: Any) -> None:
    _vm_with_launch()
    counter_file = tmp_path / "boot-counter"
    counter_file.write_bytes(b"3")

    with pytest.raises(CommandError, match="--yes"):
        call_command(
            COMMAND,
            "--vm-id",
            "vm-a",
            "--commit",
            "--boot-counter-file",
            str(counter_file),
        )

    assert spy.seeded == []
    assert spy.registered == []  # refused before ANY mutation


def test_a_seed_across_many_vms_is_refused(spy: Spy, tmp_path: Any) -> None:
    _vm_with_launch("vm-1", host="miner-a")
    _vm_with_launch("vm-2", host="miner-a")
    counter_file = tmp_path / "boot-counter"
    counter_file.write_bytes(b"3")

    with pytest.raises(CommandError, match="exactly ONE VM"):
        call_command(
            COMMAND,
            "--vm-id",
            "vm-1",
            "--vm-id",
            "vm-2",
            "--commit",
            "--boot-counter-file",
            str(counter_file),
            "--yes",
        )
    assert spy.registered == []


def test_the_hand_typed_counter_still_works_but_warns(spy: Spy, capsys: Any) -> None:
    _vm_with_launch()
    call_command(COMMAND, "--vm-id", "vm-a", "--commit", "--boot-counter", "2", "--yes")
    assert spy.seeded == [("vm-a", 2)]
    captured = capsys.readouterr()
    assert "hand-typed" in captured.err
    assert "provenance=cli:--boot-counter" in captured.out


def test_both_counter_inputs_together_are_refused(spy: Spy, tmp_path: Any) -> None:
    _vm_with_launch()
    counter_file = tmp_path / "boot-counter"
    counter_file.write_bytes(b"3")
    with pytest.raises(CommandError, match="mutually exclusive"):
        call_command(
            COMMAND,
            "--vm-id",
            "vm-a",
            "--commit",
            "--boot-counter-file",
            str(counter_file),
            "--boot-counter",
            "3",
            "--yes",
        )


# ── selection guards ───────────────────────────────────────────────────


def test_no_selector_is_refused(spy: Spy) -> None:
    with pytest.raises(CommandError, match="--all-active"):
        call_command(COMMAND)


def test_vm_id_and_all_active_together_are_refused(spy: Spy) -> None:
    _vm_with_launch()
    with pytest.raises(CommandError, match="mutually exclusive"):
        call_command(COMMAND, "--vm-id", "vm-a", "--all-active")


def test_an_unknown_vm_id_is_refused_loudly(spy: Spy) -> None:
    with pytest.raises(CommandError, match="unknown vm_id"):
        call_command(COMMAND, "--vm-id", "vm-ghost")


# ── CLAIM 14: only an ACTIVE VM is ever re-registered ──────────────────
#
# Seed + register re-creates `Active{gen, host}` in a wiped KBS. For a
# decommissioning/destroyed VM that re-opens a release vali already killed;
# for a migrating one it re-admits the fenced-out source. Refused before any
# write, and re-checked from the DB right before the seed and the register.


def _set_state(vm: Any, state: str) -> None:
    extra: dict[str, Any] = {}
    if state == VmState.MIGRATING:
        extra = {"migration_dest": "miner-b", "new_generation": vm.generation + 1}
    type(vm).objects.filter(id=vm.id).update(state=state, **extra)


def _counter(tmp_path: Any, value: str = "3") -> str:
    f = tmp_path / "bc"
    f.write_text(value)
    return str(f)


@pytest.mark.parametrize(
    "state", [VmState.DECOMMISSIONING, VmState.DESTROYED, VmState.MIGRATING]
)
def test_a_vm_that_is_not_active_is_refused_before_any_write(
    spy: Spy, tmp_path: Any, capsys: Any, state: str
) -> None:
    vm = _vm_with_launch()
    _set_state(vm, state)
    with pytest.raises(SystemExit) as info:
        call_command(
            COMMAND,
            "--vm-id",
            "vm-a",
            "--boot-counter-file",
            _counter(tmp_path),
            "--commit",
            "--yes",
        )
    assert info.value.code == 1
    out = capsys.readouterr().out
    assert "outcome=refused-not-active" in out
    assert spy.seeded == [] and spy.mint_args == [] and spy.registered == []


def test_the_dry_run_refuses_it_too(spy: Spy, capsys: Any) -> None:
    vm = _vm_with_launch()
    type(vm).objects.filter(id=vm.id).update(state=VmState.DESTROYED)
    with pytest.raises(SystemExit):
        call_command(COMMAND, "--vm-id", "vm-a")
    out = capsys.readouterr().out
    assert "outcome=refused-not-active" in out
    assert "would-recover" not in out
    assert "--reinstall-tombstones" in out


def test_a_migrating_vm_is_sent_to_the_migration_tooling(spy: Spy, capsys: Any) -> None:
    vm = _vm_with_launch()
    _set_state(vm, VmState.MIGRATING)
    with pytest.raises(SystemExit):
        call_command(COMMAND, "--vm-id", "vm-a", "--commit")
    assert "recover the migration first" in capsys.readouterr().out
    assert spy.registered == []


def test_a_vm_decommissioned_mid_run_is_not_seeded(
    spy: Spy, tmp_path: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    vm = _vm_with_launch()
    real = migration_ticket.assert_userdata_rebindable

    def and_decommission(v: Any) -> None:
        real(v)
        type(vm).objects.filter(id=vm.id).update(state=VmState.DECOMMISSIONING)

    monkeypatch.setattr(migration_ticket, "assert_userdata_rebindable", and_decommission)
    with pytest.raises(SystemExit):
        call_command(
            COMMAND,
            "--vm-id",
            "vm-a",
            "--boot-counter-file",
            _counter(tmp_path),
            "--commit",
            "--yes",
        )
    assert spy.seeded == [] and spy.registered == []


def test_a_vm_decommissioned_after_its_seed_is_not_registered(
    spy: Spy, tmp_path: Any, monkeypatch: pytest.MonkeyPatch, capsys: Any
) -> None:
    vm = _vm_with_launch()
    real_seed = effects.seed_boot_counter

    def seed_then_decommission(vm_id: str, *, counter: int) -> Any:
        res = real_seed(vm_id, counter=counter)
        type(vm).objects.filter(id=vm.id).update(state=VmState.DECOMMISSIONING)
        return res

    monkeypatch.setattr(effects, "seed_boot_counter", seed_then_decommission)
    with pytest.raises(SystemExit):
        call_command(
            COMMAND,
            "--vm-id",
            "vm-a",
            "--boot-counter-file",
            _counter(tmp_path),
            "--commit",
            "--yes",
        )
    assert spy.seeded == [("vm-a", 3)]
    assert spy.mint_args == [] and spy.registered == []
    assert "before-register" in capsys.readouterr().out


def test_a_vm_decommissioned_mid_run_without_a_seed_is_not_registered(
    spy: Spy, monkeypatch: pytest.MonkeyPatch
) -> None:
    vm = _vm_with_launch()
    real = migration_ticket.assert_userdata_rebindable

    def and_decommission(v: Any) -> None:
        real(v)
        type(vm).objects.filter(id=vm.id).update(state=VmState.DESTROYED)

    monkeypatch.setattr(migration_ticket, "assert_userdata_rebindable", and_decommission)
    with pytest.raises(SystemExit):
        call_command(COMMAND, "--vm-id", "vm-a", "--commit")
    assert spy.mint_args == [] and spy.registered == []


def test_current_placement_refuses_a_vm_that_is_not_active() -> None:
    vm = make_vm("vm-x", state=VmState.DECOMMISSIONING, host="miner-a")
    with pytest.raises(effects.EffectError, match="not 'active'"):
        migration_ticket.current_placement(vm)


def test_a_vm_decommissioned_during_the_remint_is_not_registered(
    spy: Spy, monkeypatch: pytest.MonkeyPatch, capsys: Any
) -> None:
    vm = _vm_with_launch()
    real_mint = ticket_mint.mint

    def mint_then_decommission(args: Any) -> bytes:
        out = real_mint(args)
        type(vm).objects.filter(id=vm.id).update(state=VmState.DECOMMISSIONING)
        return out

    monkeypatch.setattr(ticket_mint, "mint", mint_then_decommission)
    with pytest.raises(SystemExit):
        call_command(COMMAND, "--vm-id", "vm-a", "--commit")
    assert spy.mint_args  # the remint ran…
    assert spy.registered == []  # …but its ticket was never registered
    assert "before-register" in capsys.readouterr().out


def test_a_ticket_minted_for_a_placement_that_moved_is_not_registered(
    spy: Spy, monkeypatch: pytest.MonkeyPatch, capsys: Any
) -> None:
    # A §25 move that completed during the remint leaves the VM `active` —
    # at a NEW generation and host. The ticket in hand is for the old ones.
    vm = _vm_with_launch(gen=7, host="miner-a")
    real_mint = ticket_mint.mint

    def mint_then_move(args: Any) -> bytes:
        out = real_mint(args)
        type(vm).objects.filter(id=vm.id).update(generation=8, host="miner-b")
        return out

    monkeypatch.setattr(ticket_mint, "mint", mint_then_move)
    with pytest.raises(SystemExit):
        call_command(COMMAND, "--vm-id", "vm-a", "--commit")
    assert spy.registered == []
    assert "vm moved since the plan" in capsys.readouterr().out


def test_a_rate_limited_reinstall_is_retried_not_failed() -> None:
    # 2026-09-25: 400 of 440 tombstones came back 429 and had to be redone
    # by hand. A 429 is "later": it is retried with backoff until it lands.
    from apps.orchestration.management.commands import vali_kbs_recover as rec

    answers = [
        rec.VmOutcome("vm", 1, "", rec._FAILED, "tombstone error=... KBS returned HTTP 429"),
        rec.VmOutcome("vm", 1, "", rec._FAILED, "tombstone error=... KBS returned HTTP 429"),
        rec.VmOutcome("vm", 1, "", rec._OK_TOMBSTONED, "ok"),
    ]
    slept: list[float] = []
    got = rec._paced(lambda: answers.pop(0), sleep=slept.append)
    assert got.outcome == rec._OK_TOMBSTONED
    assert slept == [rec._RATE_LIMIT_BACKOFF_S, rec._RATE_LIMIT_BACKOFF_S * 2]


def test_a_non_rate_limit_failure_is_not_retried() -> None:
    from apps.orchestration.management.commands import vali_kbs_recover as rec

    calls: list[int] = []

    def attempt() -> rec.VmOutcome:
        calls.append(1)
        return rec.VmOutcome("vm", 1, "", rec._FAILED, "tombstone error=... HTTP 500")

    assert rec._paced(attempt, sleep=lambda _s: None).outcome == rec._FAILED
    assert len(calls) == 1


# ── step 3: the keepalive-binding re-seed ──────────────────────────────

BIND_CHIP = "22" * 64  # the platform `_vm_with_launch` registers for miner-a


def _released(vm_id: str = "vm-a", *, report: str = "7a") -> None:
    """A guest the KBS released to, attesting a minute ago, whose
    measurement is the VM's current launch (`_launch_record`'s "ab"*48)."""
    import hashlib
    import time

    from apps.telemetry.models import VmLiveAttestation

    at = int(time.time()) - 60
    VmLiveAttestation.objects.create(
        vm_id=vm_id,
        node_id_hex="aa" * 32,
        attestation_seq=1,
        epoch=1,
        observed_at_unix=at,
        verified_at_unix=at,
        expiry_unix=at + 900,
        measurement="ab" * 48,
        snp_report_digest="11" * 32,
        body_digest=hashlib.sha256(f"{vm_id}/{report}".encode()).hexdigest(),
        binding_source="release",
        chip_id=BIND_CHIP,
        report_id=report * 32,
    )


_BIND_STATE: dict[str, Any] = {}


@pytest.fixture
def bindings(monkeypatch: pytest.MonkeyPatch, spy: Spy) -> list[tuple[str, str, str]]:
    """Stub the binding seed; `_BIND_STATE` steers its answer."""
    calls: list[tuple[str, str, str]] = []
    _BIND_STATE.clear()
    _BIND_STATE.update(result="seeded", error=None)

    def _fake(vm_id: str, *, chip_id_hex: str, report_id_hex: str) -> str:
        spy.order.append(f"binding:{vm_id}")
        calls.append((vm_id, chip_id_hex, report_id_hex))
        if _BIND_STATE["error"] is not None:
            raise _BIND_STATE["error"]
        return str(_BIND_STATE["result"])

    monkeypatch.setattr(effects, "seed_keepalive_binding", _fake)
    return calls


def test_the_released_guest_is_seeded_right_after_the_register(
    spy: Spy, bindings: list[tuple[str, str, str]], capsys: Any
) -> None:
    _vm_with_launch()
    _released()
    call_command(COMMAND, "--vm-id", "vm-a", "--commit")
    assert bindings == [("vm-a", BIND_CHIP, "7a" * 32)]
    assert spy.order == ["register:vm-a", "binding:vm-a"]
    out = capsys.readouterr().out
    assert "binding=seeded" in out
    assert "keepalive binding: skipped=0 problems=0" in out


def test_the_dry_run_plans_the_binding_but_never_seeds(
    spy: Spy, bindings: list[tuple[str, str, str]], capsys: Any
) -> None:
    _vm_with_launch()
    _released()
    call_command(COMMAND, "--vm-id", "vm-a")
    assert bindings == []
    assert "3:seed-binding(report=" in capsys.readouterr().out


def test_no_vouchable_guest_skips_the_binding_and_still_succeeds(
    spy: Spy, bindings: list[tuple[str, str, str]], capsys: Any
) -> None:
    _vm_with_launch()  # no release-bound sample at all
    call_command(COMMAND, "--vm-id", "vm-a", "--commit")  # exit 0
    assert bindings == []
    out = capsys.readouterr().out
    assert spy.registered and "binding=skipped(no release-bound sample)" in out
    assert "skipped=1 problems=0" in out


def test_a_matched_guest_is_not_a_problem(
    spy: Spy, bindings: list[tuple[str, str, str]], capsys: Any
) -> None:
    _vm_with_launch()
    _released()
    _BIND_STATE.update(result="matched")
    call_command(COMMAND, "--vm-id", "vm-a", "--commit")  # exit 0
    assert "binding=matched" in capsys.readouterr().out


@pytest.mark.parametrize(
    ("error", "text"),
    [
        (effects.KbsBindingConflict("409"), "binding=CONFLICT"),
        (effects.KbsBindingPrecondition("412"), "binding=REFUSED"),
        (effects.EffectError("boom"), "binding=FAILED"),
    ],
)
def test_a_binding_problem_keeps_the_register_but_fails_the_run(
    spy: Spy,
    bindings: list[tuple[str, str, str]],
    capsys: Any,
    error: Exception,
    text: str,
) -> None:
    _vm_with_launch()
    _released()
    _BIND_STATE.update(error=error)
    with pytest.raises(SystemExit) as exit_:
        call_command(COMMAND, "--vm-id", "vm-a", "--commit")
    assert exit_.value.code != 0
    out = capsys.readouterr().out
    assert text in out and "problems=1 (vm-a)" in out
    assert spy.registered


def test_a_400_from_the_binding_route_aborts_the_run(
    spy: Spy, bindings: list[tuple[str, str, str]]
) -> None:
    _vm_with_launch()
    _released()
    _BIND_STATE.update(error=effects.KbsAdminContractMismatch("400"))
    with pytest.raises(CommandError, match="ABORTING"):
        call_command(COMMAND, "--vm-id", "vm-a", "--commit")


def test_a_relaunch_during_the_recovery_is_never_vouched_for(
    spy: Spy,
    bindings: list[tuple[str, str, str]],
    capsys: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The plan read measurement A; by the time the row lock is held the
    VM's launch record says B. The old guest (A) must not be seeded."""
    _vm_with_launch()
    _released()
    real = migration_ticket.resolve_ticket_inputs
    calls = {"n": 0}

    def _moving(vm: Any, **kw: Any) -> Any:
        calls["n"] += 1
        inputs = real(vm, **kw)
        if calls["n"] >= 3:  # plan, re-mint, then the in-lock re-read
            from dataclasses import replace

            return replace(inputs, measurement_hex="cd" * 48)
        return inputs

    monkeypatch.setattr(migration_ticket, "resolve_ticket_inputs", _moving)
    with pytest.raises(SystemExit):
        call_command(COMMAND, "--vm-id", "vm-a", "--commit")
    assert bindings == []
    assert "measurement changed during the recovery" in capsys.readouterr().out


def test_the_launch_record_is_locked_before_the_measurement_is_re_read(
    spy: Spy, bindings: list[tuple[str, str, str]], monkeypatch: pytest.MonkeyPatch
) -> None:
    """The Vm row lock does not cover the launch record; `record_relaunch`
    writes it under its own row lock, so the recovery must take that lock
    before its in-lock re-read (sqlite has no row locks — assert the call)."""
    from django.db import connection

    from apps.orchestration.services import launch_record

    _vm_with_launch()
    _released()
    seen: list[tuple[str, bool]] = []
    real_lock = launch_record.lock_latest_succeeded
    real_resolve = migration_ticket.resolve_ticket_inputs

    def _lock(vm_id: str) -> None:
        seen.append(("lock", connection.in_atomic_block))
        real_lock(vm_id)

    def _resolve(vm: Any, **kw: Any) -> Any:
        seen.append(("resolve", connection.in_atomic_block))
        return real_resolve(vm, **kw)

    monkeypatch.setattr(launch_record, "lock_latest_succeeded", _lock)
    monkeypatch.setattr(migration_ticket, "resolve_ticket_inputs", _resolve)
    call_command(COMMAND, "--vm-id", "vm-a", "--commit")
    i = seen.index(("lock", True))
    assert ("resolve", True) in seen[i + 1 :]
    assert bindings


def test_a_kbs_without_the_binding_route_is_a_skip_not_a_failure(
    spy: Spy, bindings: list[tuple[str, str, str]], capsys: Any
) -> None:
    """Against a KBS image from before binding persistence the recovery
    behaves exactly as it did before step 3 existed."""
    _vm_with_launch()
    _released()
    _BIND_STATE.update(error=effects.KbsRouteMissing("404"))
    call_command(COMMAND, "--vm-id", "vm-a", "--commit")  # exit 0
    out = capsys.readouterr().out
    assert "binding=skipped(KBS 404" in out and "skipped=1 problems=0" in out


def test_a_different_guest_since_the_release_is_an_anomaly_not_a_skip(
    spy: Spy, bindings: list[tuple[str, str, str]], capsys: Any, caplog: Any
) -> None:
    """Inside enforce's post-restart grace window a VM with no record is
    served first-use by whichever guest asks. If that guest is NOT the one
    the KBS released to, the re-seed must refuse it LOUDLY."""
    import hashlib
    import time

    from apps.telemetry.models import VmLiveAttestation

    _vm_with_launch()
    _released()  # the released guest, "7a"
    at = int(time.time()) - 10
    VmLiveAttestation.objects.create(
        vm_id="vm-a",
        node_id_hex="aa" * 32,
        attestation_seq=2,
        epoch=1,
        observed_at_unix=at,
        verified_at_unix=at,
        expiry_unix=at + 900,
        measurement="ab" * 48,
        snp_report_digest="11" * 32,
        body_digest=hashlib.sha256(b"squatter").hexdigest(),
        binding_source="first-use",
        chip_id=BIND_CHIP,
        report_id="7b" * 32,
    )
    import logging

    # `LOGGING` pins `apps` with `propagate: False`; caplog listens on root.
    monkeypatch_propagate = logging.getLogger("apps")
    old = monkeypatch_propagate.propagate
    monkeypatch_propagate.propagate = True
    try:
        with pytest.raises(SystemExit):
            call_command(COMMAND, "--vm-id", "vm-a", "--commit")
    finally:
        monkeypatch_propagate.propagate = old
    assert bindings == []
    out = capsys.readouterr().out
    assert "binding=ANOMALY" in out and "problems=1 (vm-a)" in out
    assert "keepalive-binding ANOMALY vm=vm-a" in caplog.text
