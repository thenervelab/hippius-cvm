"""`vali_migration_recover` — the operator half of §25 strand recovery.

One test per CLAIM the command makes:

1. dry-run (the DEFAULT) mutates NOTHING.
2. a committed restore lands the VM `active` on its SOURCE at `source_gen`.
3. `--action` NARROWS the evidence verdict; it never overrides it. Neither
   direction can be forced — not a restore onto a KBS-committed migration
   (the split-brain case), nor a re-drive of a VM the evidence says to
   restore.
4. a re-drive re-mints the destination ticket FRESH (a stored one is
   24h-expired and the KBS answers 400) and opens a job at
   `DestActivating` carrying the failed job's snapshot + verified ack.
5. a re-drive refuses a job with NO verified source ack — the §25
   split-brain gate, restated at the intake.
6. a re-drive refuses while the destination reports a restore RUNNING (a
   second concurrent restore of one VM) or DONE (the tick should activate
   it, not re-run it). An UNREACHABLE destination is not a refusal: that
   is the post-agent-restart state a re-drive is for.
7. selecting a VM that is not stranded fails loudly rather than acting on
   something else.
8. a refusal exits non-zero.
"""

from __future__ import annotations

from typing import Any

import pytest
from django.core.management import CommandError, call_command

from apps.lifecycle.models import Vm, VmState
from apps.orchestration.models import (
    MigrationJob,
    MigrationState,
    SourceReclaimState,
    StrandRecoveryState,
)
from apps.orchestration.services import migration_ticket

from .conftest import FakeEffects
from .factories import make_migration_job, make_vm

pytestmark = pytest.mark.django_db

COMMAND = "vali_migration_recover"

_SRC_PLATFORM = "11" * 64
_DEST_PLATFORM = "22" * 64


@pytest.fixture(autouse=True)
def _miners():
    from apps.miners.models import MinerIdentity

    MinerIdentity.objects.get_or_create(
        miner_id="node-src",
        defaults={
            "pubkey_hex": "aa" * 32,
            "platform_id": _SRC_PLATFORM,
            "netbird_ip": "100.0.0.1",
        },
    )
    MinerIdentity.objects.get_or_create(
        miner_id="node-dst",
        defaults={
            "pubkey_hex": "bb" * 32,
            "platform_id": _DEST_PLATFORM,
            "netbird_ip": "100.0.0.2",
        },
    )


@pytest.fixture(autouse=True)
def _no_kbs(monkeypatch: pytest.MonkeyPatch):
    """No recorded evidence bundle — the ambiguous default (a KBS restart
    erases the emptyDir sink), so the verdict rests on the job record."""
    from apps.orchestration.services import kbs_evidence

    monkeypatch.setattr(kbs_evidence, "fetch_evidence", lambda vm_id: None)


@pytest.fixture
def minted(monkeypatch: pytest.MonkeyPatch) -> list[dict[str, Any]]:
    """Record every dest-ticket re-mint the command performs."""
    calls: list[dict[str, Any]] = []

    def _remint(vm, *, node_id, generation, reuse_existing=True, **kw):
        calls.append(
            {
                "vm_id": vm.vm_id,
                "node_id": node_id,
                "generation": generation,
                "reuse_existing": reuse_existing,
            }
        )
        return b"cose"

    monkeypatch.setattr(migration_ticket, "remint_ticket", _remint)
    return calls


def _stranded(
    *,
    failed_from: str = MigrationState.QUIESCING.value,
    reason: str = "quiescing:boom",
    source_ack_verified: bool = False,
    vm_id: str = "vm-1",
) -> tuple[Vm, MigrationJob]:
    vm = make_vm(vm_id, host="node-src", generation=1)
    job = make_migration_job(vm, state=MigrationState.FAILED.value)
    MigrationJob.objects.filter(id=job.id).update(
        failed_from_state=failed_from,
        reason=reason,
        source_ack_verified=source_ack_verified,
        snapshot_bucket="snaps",
        snapshot_key=f"migrations/{vm_id}/x.luks",
        snapshot_state_key=f"migrations/{vm_id}/x.state",
    )
    Vm.objects.filter(id=vm.id).update(
        state=VmState.MIGRATING.value,
        migration_dest=job.dest_node_id,
        new_generation=job.new_gen,
    )
    return Vm.objects.get(id=vm.id), MigrationJob.objects.get(id=job.id)


def _dest_activating_stranded(**kw) -> tuple[Vm, MigrationJob]:
    """The class the REAL stranded VM is in: the job died in
    `DestActivating`, so the KBS is already `Migrating{new_gen, dest}`."""
    return _stranded(
        failed_from=MigrationState.DEST_ACTIVATING.value,
        reason="dest_activating:dest miner reported migration failure",
        source_ack_verified=True,
        **kw,
    )


# ─── 1-2: dry-run, then the restore ──────────────────────────────────


def test_dry_run_mutates_nothing():
    vm, job = _stranded()

    call_command(COMMAND, "--vm-id", vm.vm_id)

    vm.refresh_from_db()
    job.refresh_from_db()
    assert vm.state == VmState.MIGRATING.value
    assert job.strand_recovery_state == StrandRecoveryState.NONE.value


def test_commit_restores_the_vm_to_its_source():
    vm, job = _stranded()

    call_command(COMMAND, "--vm-id", vm.vm_id, "--commit")

    vm.refresh_from_db()
    job.refresh_from_db()
    assert vm.state == VmState.ACTIVE.value
    assert vm.host == "node-src"
    assert vm.generation == job.source_gen
    assert vm.migration_dest == ""
    assert vm.new_generation is None
    assert job.strand_recovery_state == StrandRecoveryState.SOURCE_RESTORED.value
    # The source now holds the VM's ONLY copy — #936 must never reclaim it.
    assert job.source_reclaim_state == SourceReclaimState.SKIPPED.value


# ─── 3: the verdict is never overridden ──────────────────────────────


def test_action_cannot_force_a_restore_onto_a_committed_migration():
    """The split-brain case, through the operator surface: the KBS is
    `Migrating{new_gen, dest}` and no flag may un-fence the source."""
    vm, _job = _dest_activating_stranded()

    with pytest.raises(SystemExit):
        call_command(
            COMMAND, "--vm-id", vm.vm_id, "--action", "restore-source", "--commit"
        )

    vm.refresh_from_db()
    assert vm.state == VmState.MIGRATING.value


def test_action_cannot_force_a_redrive_of_a_restorable_vm(minted):
    vm, _job = _stranded()

    with pytest.raises(SystemExit):
        call_command(
            COMMAND, "--vm-id", vm.vm_id, "--action", "redrive-dest", "--commit"
        )

    assert minted == []
    assert MigrationJob.objects.filter(
        vm=vm, state=MigrationState.DEST_ACTIVATING.value
    ).count() == 0


# ─── 4: the forward re-drive ─────────────────────────────────────────


def test_redrive_mints_a_fresh_ticket_and_opens_a_dest_activating_job(
    minted, fx: FakeEffects
):
    fx.dest_activation_status = "failed"
    vm, job = _dest_activating_stranded()

    call_command(COMMAND, "--vm-id", vm.vm_id, "--commit")

    # FRESH, not the stored one: OrderTickets expire in 24h, so re-driving a
    # day-old migration with a reused intake hands the dest a ticket the KBS
    # answers 400 to — the same trap `vali_kbs_recover` documents.
    assert minted == [
        {
            "vm_id": vm.vm_id,
            "node_id": "node-dst",
            "generation": job.new_gen,
            "reuse_existing": False,
        }
    ]
    new = MigrationJob.objects.get(state=MigrationState.DEST_ACTIVATING.value)
    assert new.dest_node_id == job.dest_node_id
    assert new.new_gen == job.new_gen
    assert new.source_gen == job.source_gen
    assert new.source_node_id == job.source_node_id
    assert new.snapshot_bucket == job.snapshot_bucket
    assert new.snapshot_key == job.snapshot_key
    assert new.snapshot_state_key == job.snapshot_state_key
    assert new.source_ack_verified is True
    job.refresh_from_db()
    assert job.strand_recovery_state == StrandRecoveryState.REDRIVEN.value
    # The VM stays fenced — only a completed dest activation un-fences it.
    vm.refresh_from_db()
    assert vm.state == VmState.MIGRATING.value


def test_redrive_dry_run_mints_nothing(minted, fx: FakeEffects):
    fx.dest_activation_status = "failed"
    vm, _job = _dest_activating_stranded()

    call_command(COMMAND, "--vm-id", vm.vm_id)

    assert minted == []
    assert not MigrationJob.objects.filter(
        state=MigrationState.DEST_ACTIVATING.value
    ).exists()


# ─── 5: the split-brain gate, restated at the intake ─────────────────


def test_redrive_refuses_a_job_with_no_verified_source_ack(
    minted, fx: FakeEffects
):
    fx.dest_activation_status = "failed"
    vm, _job = _stranded(
        failed_from=MigrationState.DEST_ACTIVATING.value,
        reason="dest_activating:boom",
        source_ack_verified=False,
    )

    with pytest.raises(SystemExit):
        call_command(COMMAND, "--vm-id", vm.vm_id, "--commit")

    assert minted == []
    assert not MigrationJob.objects.filter(
        state=MigrationState.DEST_ACTIVATING.value
    ).exists()


def test_redrive_refuses_a_destination_its_placement_group_took_since(
    minted, fx: FakeEffects
):
    """The failed job's destination stopped counting for the VM's group
    when the job ended; a sibling that landed there since blocks the
    re-drive (anti-affinity)."""
    from apps.miners.models import MinerIdentity

    fx.dest_activation_status = "failed"
    vm, _job = _dest_activating_stranded()
    MinerIdentity.objects.filter(miner_id="node-dst").update(chain_node_id="d" * 64)
    Vm.objects.filter(pk=vm.pk).update(tenant_id="t-g", placement_group="db")
    sibling = make_vm("vm-sibling", host="node-dst")
    Vm.objects.filter(pk=sibling.pk).update(tenant_id="t-g", placement_group="db")

    with pytest.raises(SystemExit):
        call_command(COMMAND, "--vm-id", vm.vm_id, "--commit")

    assert minted == []
    assert not MigrationJob.objects.filter(
        state=MigrationState.DEST_ACTIVATING.value
    ).exists()


# ─── 6: never race the destination ───────────────────────────────────


@pytest.mark.parametrize("status", ["running", "done"])
def test_redrive_refuses_while_the_dest_is_busy_or_finished(
    minted, fx: FakeEffects, status: str
):
    fx.dest_activation_status = status
    vm, _job = _dest_activating_stranded()

    with pytest.raises(SystemExit):
        call_command(COMMAND, "--vm-id", vm.vm_id, "--commit")

    assert minted == []


def test_an_unreachable_dest_does_not_block_the_redrive(
    minted, fx: FakeEffects
):
    """A 404/unreachable status store is the post-agent-restart state — the
    one a re-drive most needs to work in. A genuinely dead destination
    fails later, at the dispatch, having mutated nothing on the VM."""
    fx.fail.add("poll_dest_activation")
    vm, _job = _dest_activating_stranded()

    call_command(COMMAND, "--vm-id", vm.vm_id, "--commit")

    assert len(minted) == 1


# ─── 7-8: selection + exit code ──────────────────────────────────────


def test_selecting_a_non_stranded_vm_is_an_error():
    vm = make_vm(host="node-src", generation=1)

    with pytest.raises(CommandError, match="not stranded"):
        call_command(COMMAND, "--vm-id", vm.vm_id, "--commit")


def test_selecting_an_unknown_vm_is_an_error():
    with pytest.raises(CommandError, match="no such Vm"):
        call_command(COMMAND, "--vm-id", "nope", "--commit")


def test_a_blocked_verdict_exits_non_zero():
    vm, _job = _stranded(failed_from="", reason="")

    with pytest.raises(SystemExit) as exc:
        call_command(COMMAND, "--vm-id", vm.vm_id, "--commit")

    assert exc.value.code == 1
    vm.refresh_from_db()
    assert vm.state == VmState.MIGRATING.value


def test_all_stranded_selects_every_stranded_vm():
    _stranded(vm_id="vm-a")
    _stranded(vm_id="vm-b")

    call_command(COMMAND, "--all-stranded", "--commit")

    assert Vm.objects.filter(state=VmState.ACTIVE).count() == 2


def test_commit_and_dry_run_are_mutually_exclusive():
    with pytest.raises(CommandError):
        call_command(COMMAND, "--all-stranded", "--commit", "--dry-run")
