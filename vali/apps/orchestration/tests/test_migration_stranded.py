"""§25 — a migration that fails must not STRAND its VM in `migrating`.

## What is being defended

`_fail_migration` from `Quiescing` onward leaves the `Vm` row `migrating`
with no domain on either host: the source guest was gracefully stopped and
the destination never came up. `reboot_recovery_once` iterates `Active`
VMs, `reclaim_migrated_sources` iterates `Done` jobs and
`sweep_guest_liveness` iterates `Active` VMs — so such a VM was outside
EVERY automatic path, and nothing logged it. It stayed down indefinitely.

## The asymmetry every test below pins

Un-fencing a VM is only safe while the KBS `VmState` is still
`Active{source_gen, source}`. Once `effects.kbs_activate_dest` has fired
the KBS is `Migrating{new_gen, dest}` and — because its `activate` is
forward-only and refuses every non-`Active` current state, and
`register-vm` on a divergent state is a 409-with-no-write — there is NO
route back. A "restore" there produces a guest that can never obtain its
KEK AND a vali row that disagrees with the KBS about who owns the VM.

So: a restore requires POSITIVE proof the job never entered
`DestActivating`, and every hint to the contrary — however weak — is a
veto. The tests are written as the two failure directions:

  * a stranded VM goes UNDETECTED (the availability bug), and
  * a restore fires without that proof (the split-brain bug).
"""

from __future__ import annotations

import logging
from datetime import timedelta
from typing import Any

import pytest
from django.utils import timezone

from apps.lifecycle.models import Vm, VmState
from apps.orchestration import effects, idempotency, service
from apps.orchestration.models import (
    MigrationJob,
    MigrationState,
    SourceReclaimState,
    StrandRecoveryState,
)
from apps.orders.models import OrderTicketIntake

from .factories import make_migration_job, make_vm

pytestmark = pytest.mark.django_db

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
def _reset_warn_memo():
    """The stranded-VM alarm is throttled by a module-level memo; a test
    must never inherit another test's."""
    service._strand_warn_memo = (frozenset(), 0.0)
    yield
    service._strand_warn_memo = (frozenset(), 0.0)


def _stub_evidence(monkeypatch: pytest.MonkeyPatch, payload: Any) -> None:
    """Point `kbs_evidence.fetch_evidence` at a fixed answer. `payload`
    may be a dict, `None` (no bundle recorded), or an exception to raise.
    """
    from apps.orchestration.services import kbs_evidence

    def _fetch(vm_id: str) -> Any:
        if isinstance(payload, Exception):
            raise payload
        return payload

    monkeypatch.setattr(kbs_evidence, "fetch_evidence", _fetch)


def _stranded(
    *,
    failed_from: str = MigrationState.QUIESCING.value,
    reason: str = "quiescing:injected failure",
    source_ack_verified: bool = False,
    vm_id: str = "vm-1",
) -> tuple[Vm, MigrationJob]:
    """A VM left exactly as a failed post-fence migration leaves it: the
    `Vm` fenced `migrating` for a job that is now `Failed`.
    """
    vm = make_vm(vm_id, host="node-src", generation=1)
    job = make_migration_job(vm, state=MigrationState.FAILED.value)
    MigrationJob.objects.filter(id=job.id).update(
        failed_from_state=failed_from,
        reason=reason,
        source_ack_verified=source_ack_verified,
        snapshot_bucket="snaps",
        snapshot_key=f"migrations/{vm_id}/x.luks",
    )
    Vm.objects.filter(id=vm.id).update(
        state=VmState.MIGRATING.value,
        migration_dest=job.dest_node_id,
        new_generation=job.new_gen,
        boot_phase="",
    )
    return Vm.objects.get(id=vm.id), MigrationJob.objects.get(id=job.id)


def _intake(vm: Vm, *, ticket_id: str, generation: int, node_id: str) -> None:
    OrderTicketIntake.objects.create(
        ticket_id=ticket_id,
        vm_id=vm.vm_id,
        tenant_id="t",
        user_id="u",
        lease_id="l",
        vm_generation=generation,
        issue_time=0,
        expiry=0,
        node_id=node_id,
        platform_id=_DEST_PLATFORM if node_id == "node-dst" else _SRC_PLATFORM,
        resource_class="small",
        kid_hex="00",
        cose_blob=b"",
        received_from="test",
    )


# ─── DETECTION — the availability half ───────────────────────────────


def test_stranded_vm_is_detected(monkeypatch: pytest.MonkeyPatch):
    """MUTATION TARGET: "a stranded VM is never detected".

    A `migrating` VM whose only migration job is terminal has nobody
    driving it. It must appear in the sweep's count.
    """
    _stub_evidence(monkeypatch, None)
    vm, job = _stranded()

    assert [v.vm_id for v, _ in service.stranded_migrations()] == [vm.vm_id]


def test_stranded_count_reaches_the_tick_report(monkeypatch: pytest.MonkeyPatch):
    """The counter an operator/alert actually reads. Restore is disabled
    here so the VM STAYS stranded and the count is the count of a real,
    persisting outage."""
    _stub_evidence(monkeypatch, None)
    monkeypatch.setattr(
        service.settings, "VALI_MIGRATION_STRAND_RESTORE_ENABLED", False
    )
    _stranded()

    report = service.tick_once()

    assert report.stranded_migrations == 1


def test_stranded_vm_is_loud(monkeypatch: pytest.MonkeyPatch, caplog):
    """Detection that does not SAY anything is how this sat silently. A
    VM the sweep cannot recover must produce an ERROR naming it."""
    _stub_evidence(monkeypatch, None)
    monkeypatch.setattr(
        service.settings, "VALI_MIGRATION_STRAND_RESTORE_ENABLED", False
    )
    # `LOGGING` pins `apps` with `propagate: False`; caplog installs its
    # handler on the ROOT logger, so let this one record through.
    monkeypatch.setattr(logging.getLogger("apps"), "propagate", True)
    vm, _ = _stranded()

    with caplog.at_level(logging.ERROR, logger="apps.orchestration.service"):
        service.sweep_stranded_migrations()

    errors = [r for r in caplog.records if r.levelno >= logging.ERROR]
    assert any(vm.vm_id in r.getMessage() for r in errors), (
        "the stranded VM must be named in an ERROR — a silent counter is "
        "what let this sit indefinitely"
    )


def test_a_vm_with_a_live_migration_is_not_stranded():
    """A `migrating` VM is legitimate exactly while a non-terminal job
    owns it. Counting those would make the alarm meaningless."""
    vm = make_vm(host="node-src", generation=1)
    job = make_migration_job(vm, state=MigrationState.UPLOADING.value)
    Vm.objects.filter(id=vm.id).update(
        state=VmState.MIGRATING.value,
        migration_dest=job.dest_node_id,
        new_generation=job.new_gen,
    )

    assert service.stranded_migrations() == []


def test_an_active_vm_is_not_stranded():
    make_vm(host="node-src", generation=1)

    assert service.stranded_migrations() == []


def test_fail_migration_records_the_state_it_died_in():
    """`failed_from_state` is the ONLY permit input to a restore. If
    `_fail_migration` stops writing it, every stranded VM degrades to the
    operator path — fail-closed, but the automatic recovery silently
    disappears."""
    vm = make_vm(host="node-src", generation=1)
    job = make_migration_job(vm, state=MigrationState.UPLOADING.value)
    MigrationJob.objects.filter(id=job.id).update(finished_at=None)
    job.refresh_from_db()

    service._fail_migration(job, reason="uploading:timeout")

    job.refresh_from_db()
    assert job.state == MigrationState.FAILED.value
    assert job.failed_from_state == MigrationState.UPLOADING.value


# ─── THE PERMIT — a restore only on positive proof ───────────────────


@pytest.mark.parametrize(
    "state",
    sorted(service._PRE_KBS_ACTIVATION_STATES),
)
def test_every_pre_activation_failure_is_restorable(
    monkeypatch: pytest.MonkeyPatch, state: str
):
    """`DestActivating` is the sole caller of `effects.kbs_activate_dest`,
    so a job that died in any state below it PROVABLY never moved the KBS
    — the source is still the only host that can unlock."""
    _stub_evidence(monkeypatch, None)
    vm, job = _stranded(failed_from=state, reason=f"{state}:boom")

    verdict = service.stranded_recovery_verdict(vm, job)

    assert verdict.action == service.STRAND_RESTORE_SOURCE


def test_restore_returns_the_vm_to_the_source_at_the_source_generation(
    monkeypatch: pytest.MonkeyPatch,
):
    """MUTATION TARGET: "the stranded VM is transitioned to a state that
    makes §24/§25 unsafe".

    The ONLY correct landing state is `Active` on the SOURCE at
    `source_gen` with the fence fields cleared. Landing on the dest, or at
    `new_gen`, would contradict the KBS (which still says
    `Active{source_gen, source}`) and hand §24/§25 a VM whose host and
    generation are fiction.
    """
    _stub_evidence(monkeypatch, None)
    vm, job = _stranded()

    service.sweep_stranded_migrations()

    vm.refresh_from_db()
    assert vm.state == VmState.ACTIVE.value
    assert vm.host == job.source_node_id
    assert vm.generation == job.source_gen
    assert vm.migration_dest == ""
    assert vm.new_generation is None


def test_restore_preserves_the_eol_nonce(monkeypatch: pytest.MonkeyPatch):
    """The launch-baked, SNP-measured nonce is per-VM-for-life. Clearing
    it here would break every FUTURE §24 EOL ack and re-migration of this
    VM — the §25/§24 GAP-3 invariant."""
    _stub_evidence(monkeypatch, None)
    vm, _ = _stranded()
    before = bytes(vm.eol_nonce)

    service.sweep_stranded_migrations()

    vm.refresh_from_db()
    assert bytes(vm.eol_nonce) == before


def test_restored_vm_is_visible_to_reboot_recovery(monkeypatch: pytest.MonkeyPatch):
    """The whole point of the landing state: `reboot_recovery_once`
    iterates `Active` VMs, so a restored VM is back inside the sweep that
    relaunches a down guest. Before the restore it is invisible to it."""
    _stub_evidence(monkeypatch, None)
    vm, _ = _stranded()

    assert list(Vm.objects.filter(state=VmState.ACTIVE)) == []
    service.sweep_stranded_migrations()
    assert [v.vm_id for v in Vm.objects.filter(state=VmState.ACTIVE)] == [vm.vm_id]


def test_a_restored_vm_is_actually_relaunched_by_the_same_tick(
    monkeypatch: pytest.MonkeyPatch,
):
    """The claim the restore rests on, end to end: un-fencing is only a
    recovery if something then brings the guest back. The sweep runs
    BEFORE `reboot_recovery_once` in the tick precisely so the same cycle
    that restores the VM also relaunches it on the source."""
    from django.test import override_settings

    from apps.miners.models import MinerIdentity, MinerStatus
    from apps.orchestration.models import RebootRecovery

    _stub_evidence(monkeypatch, None)
    vm, job = _stranded()
    MinerIdentity.objects.filter(miner_id="node-src").update(
        status=MinerStatus.ACTIVE, last_seen_at=timezone.now()
    )
    # The VM was observed running on the source before the migration — the
    # #854 gate that makes reboot-recovery safe fleet-wide.
    RebootRecovery.objects.create(vm=vm, seen_running=True, host="node-src")
    monkeypatch.setattr(effects, "poll_domain_running", lambda vm: False)
    relaunched: list[tuple[str, str]] = []
    monkeypatch.setattr(
        service,
        "_reboot_recovery_relaunch",
        lambda vm, node_id: bool(relaunched.append((vm.vm_id, node_id))) or True,
    )

    with override_settings(
        VALI_REBOOT_RECOVERY_ENABLED=True, VALI_REBOOT_RECOVERY_DEBOUNCE_POLLS=1
    ):
        service.tick_once()

    assert relaunched == [(vm.vm_id, "node-src")], (
        "the restored VM must be relaunched on the SOURCE — the only host "
        "the KBS will release its KEK to"
    )
    assert job.source_gen == 1


def test_restore_is_recorded_on_the_job(monkeypatch: pytest.MonkeyPatch):
    _stub_evidence(monkeypatch, None)
    _vm, job = _stranded()

    service.sweep_stranded_migrations()

    job.refresh_from_db()
    assert job.strand_recovery_state == StrandRecoveryState.SOURCE_RESTORED.value
    assert job.strand_recovery_at is not None


def test_absent_kbs_evidence_is_ambiguous_not_a_veto(
    monkeypatch: pytest.MonkeyPatch,
):
    """The KBS evidence sink is an emptyDir — a KBS restart erases
    bundles. Treating absence as a veto would make the automatic restore
    stop working the first time the KBS pod cycled; treating it as a
    PERMIT would be unsound. It is neither: the permit rests on
    `failed_from_state`."""
    _stub_evidence(monkeypatch, None)
    vm, job = _stranded()

    assert service.stranded_recovery_verdict(vm, job).restorable


def test_a_source_grant_at_the_source_generation_is_not_a_veto(
    monkeypatch: pytest.MonkeyPatch,
):
    """The VM's last KBS grant being its OWN, on the source, at
    `source_gen` is exactly what a never-activated migration looks like."""
    vm, job = _stranded()
    _intake(vm, ticket_id="tk-src", generation=job.source_gen, node_id="node-src")
    _stub_evidence(monkeypatch, {"ticket_id": "tk-src"})

    assert service.stranded_recovery_verdict(vm, job).restorable


# ─── THE VETOES — every way a restore must NOT fire ──────────────────


def test_no_restore_without_a_recorded_failure_state(
    monkeypatch: pytest.MonkeyPatch,
):
    """MUTATION TARGET: "restore fires WITHOUT evidence the destination
    stayed dark".

    Every job that predates the `failed_from_state` column is blank, and
    blank is UNPROVABLE. It must fail closed — including for the real
    stranded VM this work was written for.
    """
    _stub_evidence(monkeypatch, None)
    vm, job = _stranded(failed_from="", reason="")

    verdict = service.stranded_recovery_verdict(vm, job)

    assert verdict.action == service.STRAND_BLOCKED
    assert "unknown-failure-state" in verdict.reason
    service.sweep_stranded_migrations()
    vm.refresh_from_db()
    assert vm.state == VmState.MIGRATING.value


def test_no_restore_when_the_job_died_in_dest_activating(
    monkeypatch: pytest.MonkeyPatch,
):
    """The KBS was moved to `Migrating{new_gen, dest}` in that state and
    no admin route moves it back. Un-fencing the source would produce a
    guest that boots and can never unlock."""
    _stub_evidence(monkeypatch, None)
    # The `reason` deliberately does NOT name the state: this pins the
    # AUTHORITATIVE column on its own, with no help from the string veto.
    vm, job = _stranded(
        failed_from=MigrationState.DEST_ACTIVATING.value,
        reason="dest miner reported migration failure",
    )

    verdict = service.stranded_recovery_verdict(vm, job)

    assert verdict.action == service.STRAND_REDRIVE_DEST
    assert verdict.reason == "failed-from-dest-activating"
    service.sweep_stranded_migrations()
    vm.refresh_from_db()
    assert vm.state == VmState.MIGRATING.value


def test_the_reason_prefix_alone_vetoes_a_pre_column_job(
    monkeypatch: pytest.MonkeyPatch,
):
    """A job written before `failed_from_state` existed still names its
    state in `reason` (`f"{job.state}:{…}"`). That string may never
    PERMIT — but it must always VETO, which is what classifies the real
    stranded VM correctly instead of merely `unknown`."""
    _stub_evidence(monkeypatch, None)
    vm, job = _stranded(
        failed_from="",
        reason="dest_activating:dest miner reported migration failure",
    )

    verdict = service.stranded_recovery_verdict(vm, job)

    assert verdict.action == service.STRAND_REDRIVE_DEST
    assert verdict.reason == "reason-names-dest-activating"


def test_a_dest_ticket_at_new_gen_vetoes(monkeypatch: pytest.MonkeyPatch):
    """Only `dispatch_migrate_activate` mints one, and it runs AFTER
    `kbs_activate_dest` in the same state — so the row's existence means
    the KBS activate had already succeeded, whatever the job's own fields
    say."""
    _stub_evidence(monkeypatch, None)
    vm, job = _stranded()
    _intake(vm, ticket_id="tk-mig", generation=job.new_gen, node_id="node-dst")

    verdict = service.stranded_recovery_verdict(vm, job)

    assert verdict.action == service.STRAND_REDRIVE_DEST
    assert verdict.reason == "dest-ticket-minted-at-new-gen"


@pytest.mark.parametrize("step", ["dest-activating", "dispatch-migrate-activate"])
def test_an_idempotency_marker_vetoes(monkeypatch: pytest.MonkeyPatch, step: str):
    """`_guarded` records AFTER the effect, so PRESENCE proves the effect
    ran even when the job's state was never persisted."""
    _stub_evidence(monkeypatch, None)
    vm, job = _stranded()
    idempotency.record(service._mig_key(job, step), "x")

    verdict = service.stranded_recovery_verdict(vm, job)

    assert verdict.action == service.STRAND_REDRIVE_DEST
    assert verdict.reason == f"idempotency-marker:{step}"


def test_an_unreadable_idempotency_store_vetoes(monkeypatch: pytest.MonkeyPatch):
    """An input that cannot be verified is never a pass."""
    _stub_evidence(monkeypatch, None)
    vm, job = _stranded()

    def _boom(key: str) -> None:
        raise service.IdempotencyUnavailable("store down")

    monkeypatch.setattr(idempotency, "recall", _boom)

    verdict = service.stranded_recovery_verdict(vm, job)

    assert verdict.action == service.STRAND_REDRIVE_DEST
    assert verdict.reason == "idempotency-store-unreadable"


def test_a_grant_at_new_gen_on_the_dest_vetoes(monkeypatch: pytest.MonkeyPatch):
    """MUTATION TARGET: "restore fires while the destination actually
    activated" — the split-brain case.

    A KBS grant at `new_gen` bound to the destination means the
    destination DID obtain the KEK. Restoring the source on top of that is
    the exact two-live-copies outcome the §25 fence exists to prevent. The
    intake row is written under a ticket_id the job's own fields do not
    mention, so ONLY the KBS-side check catches it.
    """
    vm, job = _stranded()
    # Deliberately NOT the `vm_generation=new_gen` row the local veto
    # already catches: this intake is keyed by a ticket the KBS names, at
    # a generation the local checks do not scan for.
    _intake(vm, ticket_id="tk-dst", generation=job.new_gen + 7, node_id="node-dst")
    _stub_evidence(monkeypatch, {"ticket_id": "tk-dst"})

    verdict = service.stranded_recovery_verdict(vm, job)

    assert verdict.action == service.STRAND_REDRIVE_DEST
    service.sweep_stranded_migrations()
    vm.refresh_from_db()
    assert vm.state == VmState.MIGRATING.value, "the source must stay fenced"


def test_a_grant_on_another_node_vetoes(monkeypatch: pytest.MonkeyPatch):
    vm, job = _stranded()
    _intake(vm, ticket_id="tk-x", generation=job.source_gen, node_id="node-dst")
    _stub_evidence(monkeypatch, {"ticket_id": "tk-x"})

    verdict = service.stranded_recovery_verdict(vm, job)

    assert verdict.action == service.STRAND_REDRIVE_DEST
    assert verdict.reason.startswith("evidence-grant-off-source")


def test_an_unreadable_kbs_vetoes(monkeypatch: pytest.MonkeyPatch):
    """The KBS is the authority on who may unlock. If vali cannot read
    it, vali does not un-fence."""
    vm, job = _stranded()
    _stub_evidence(monkeypatch, effects.EffectUnavailable("kbs down"))

    verdict = service.stranded_recovery_verdict(vm, job)

    assert verdict.action == service.STRAND_REDRIVE_DEST
    assert verdict.reason == "kbs-evidence-unreadable"


def test_an_evidence_ticket_vali_does_not_know_vetoes(
    monkeypatch: pytest.MonkeyPatch,
):
    vm, job = _stranded()
    _stub_evidence(monkeypatch, {"ticket_id": "tk-unknown"})

    verdict = service.stranded_recovery_verdict(vm, job)

    assert verdict.action == service.STRAND_REDRIVE_DEST
    assert verdict.reason == "evidence-ticket-unknown-to-vali"


def test_a_vm_fenced_for_another_migration_is_never_restored(
    monkeypatch: pytest.MonkeyPatch,
):
    """The row we are about to un-fence must be the one THIS job fenced."""
    _stub_evidence(monkeypatch, None)
    vm, job = _stranded()
    Vm.objects.filter(id=vm.id).update(migration_dest="node-other")
    vm.refresh_from_db()

    verdict = service.stranded_recovery_verdict(vm, job)

    assert verdict.action == service.STRAND_BLOCKED
    assert verdict.reason.startswith("fenced-for-another-migration")


def test_a_vm_already_on_the_dest_is_never_restored(monkeypatch: pytest.MonkeyPatch):
    """If `_activate_dest_vm` already moved `Vm.host`, a "restore" would
    aim the VM back at a host that no longer owns it."""
    _stub_evidence(monkeypatch, None)
    vm, job = _stranded()
    Vm.objects.filter(id=vm.id).update(host="node-dst")
    vm.refresh_from_db()

    verdict = service.stranded_recovery_verdict(vm, job)

    assert verdict.action == service.STRAND_BLOCKED
    assert verdict.reason.startswith("vm-not-on-source")


def test_a_stranded_vm_with_no_job_at_all_is_blocked(
    monkeypatch: pytest.MonkeyPatch,
):
    """No job ⇒ no source, no generations, no evidence. Detected and
    reported; never acted on."""
    _stub_evidence(monkeypatch, None)
    vm = make_vm(host="node-src", generation=1)
    # The `lifecycle_vm_migrating_requires_dest` / `…_new_generation` CHECK
    # constraints mean a fenced row always carries these, even when the job
    # that wrote them is gone.
    Vm.objects.filter(id=vm.id).update(
        state=VmState.MIGRATING.value,
        migration_dest="node-dst",
        new_generation=2,
    )
    vm.refresh_from_db()

    assert service.sweep_stranded_migrations() == 1
    verdict = service.stranded_recovery_verdict(vm, None)
    assert verdict.action == service.STRAND_BLOCKED
    vm.refresh_from_db()
    assert vm.state == VmState.MIGRATING.value


def test_the_restore_cas_pins_the_row_it_judged(monkeypatch: pytest.MonkeyPatch):
    """A concurrent writer that moved the VM between the verdict and the
    write must LOSE — the verdict was computed against a row that no
    longer exists."""
    _stub_evidence(monkeypatch, None)
    vm, job = _stranded()
    Vm.objects.filter(id=vm.id).update(version=vm.version + 1)

    assert service.restore_source_vm(vm, job) is False
    vm.refresh_from_db()
    assert vm.state == VmState.MIGRATING.value


def test_repeated_failures_stop_the_AUTOMATIC_restore_but_not_the_verdict(
    monkeypatch: pytest.MonkeyPatch,
):
    """The loop this recovery could otherwise create: an ack-timeout
    quarantines the source, `enroll_departing_miner_migrations` enrols a
    fresh migration for every Active VM on a quarantined miner, and a
    restore hands the VM straight back to it — each cycle costing an ack
    timeout and a full snapshot upload.

    The cap gates only the AUTOMATIC action. The verdict stays
    `restore-source`, because the restore is still SAFE — it is just no
    longer something to keep doing unattended.
    """
    _stub_evidence(monkeypatch, None)
    monkeypatch.setattr(service.settings, "VALI_MIGRATION_STRAND_MAX_FAILURES", 1)
    vm, job = _stranded()
    # Older siblings — the sweep must still judge the LATEST job (the one
    # that stranded the VM), so these only move the failure COUNT.
    older = timezone.now() - timedelta(hours=1)
    for _ in range(2):
        sibling = make_migration_job(vm, state=MigrationState.FAILED.value)
        MigrationJob.objects.filter(id=sibling.id).update(started_at=older)

    assert service.stranded_recovery_verdict(vm, job).restorable
    service.sweep_stranded_migrations()

    vm.refresh_from_db()
    assert vm.state == VmState.MIGRATING.value


def test_the_restore_flag_gates_only_the_action_not_the_detection(
    monkeypatch: pytest.MonkeyPatch,
):
    _stub_evidence(monkeypatch, None)
    monkeypatch.setattr(
        service.settings, "VALI_MIGRATION_STRAND_RESTORE_ENABLED", False
    )
    vm, _ = _stranded()

    assert service.sweep_stranded_migrations() == 1
    vm.refresh_from_db()
    assert vm.state == VmState.MIGRATING.value


# ─── #936 INTERACTION — the reclaim gate must not loosen ─────────────


def test_a_restore_marks_the_source_reclaim_skipped_never_reclaimed(
    monkeypatch: pytest.MonkeyPatch,
):
    """MUTATION TARGET: "the reclaim gate is loosened as a side effect".

    After a restore the SOURCE holds the VM's only copy. `skipped` is the
    terminal that never dispatches a destroy; `reclaimed`/`pending` would
    put the tenant's only disk on a deletion path.
    """
    _stub_evidence(monkeypatch, None)
    _vm, job = _stranded()

    service.sweep_stranded_migrations()

    job.refresh_from_db()
    assert job.source_reclaim_state == SourceReclaimState.SKIPPED.value
    assert job.source_reclaim_reason == "source-restored"


def test_a_failed_migration_never_reaches_the_reclaim_sweep(
    monkeypatch: pytest.MonkeyPatch,
):
    """#936's sweep is `state=Done`-filtered, and a restored VM's job is
    `Failed`. Pinned here because a widening of that filter would turn
    this recovery into a data-loss primitive."""
    _stub_evidence(monkeypatch, None)
    dispatched: list[str] = []
    monkeypatch.setattr(
        effects,
        "dispatch_source_reclaim",
        lambda vm, *, source_node_id, job_id: dispatched.append(source_node_id),
    )
    _vm, _job = _stranded()

    service.sweep_stranded_migrations()
    service.reclaim_migrated_sources()

    assert dispatched == []


def test_the_reclaim_gate_still_holds_pending_for_an_unproven_dest(
    monkeypatch: pytest.MonkeyPatch,
):
    """Regression fence around #936 itself: this work must not relax the
    proof a COMPLETED migration needs before its source is reclaimed."""
    _stub_evidence(monkeypatch, None)
    dispatched: list[str] = []
    monkeypatch.setattr(
        effects,
        "dispatch_source_reclaim",
        lambda vm, *, source_node_id, job_id: dispatched.append(source_node_id),
    )
    vm = make_vm("vm-done", host="node-src", generation=1)
    job = make_migration_job(vm, state=MigrationState.DONE.value)
    Vm.objects.filter(id=vm.id).update(
        state=VmState.ACTIVE.value, host="node-dst", generation=job.new_gen
    )

    service.reclaim_migrated_sources()

    job.refresh_from_db()
    assert dispatched == []
    assert job.source_reclaim_state == SourceReclaimState.PENDING.value


# ─── the re-drive must reach the destination at all ──────────────────


def test_the_dest_order_id_is_scoped_to_the_job(monkeypatch: pytest.MonkeyPatch, fx):
    """MUTATION TARGET: a re-drive that the destination swallows.

    `migrate-activate` ACKs IMMEDIATELY (the multi-GB restore runs on a
    background task), so the dest miner's `IdempotencyStore` records
    `Done(true)` for the order_id the instant it accepts — whatever the
    restore later does. A `(vm_id, new_gen)`-only key therefore makes every
    RE-DRIVE an `idempotent-replay` no-op: 200, nothing restored, and
    vali's poll reads the stale `Failed` phase. The key must vary with the
    JOB (stable across a job's own tick retries, distinct across jobs).
    """
    from apps.orchestration import order_dispatch

    vm, job = _stranded()
    seen: list[str] = []

    monkeypatch.setattr(effects, "_miner_identity", lambda n: (n, "100.0.0.2"))
    monkeypatch.setattr(
        effects, "_launch_paths", lambda vm: dict.fromkeys(
            (
                "ovmf_path",
                "kernel_path",
                "initrd_path",
                "cmdline",
                "luks_disk_path",
                "luks_disk_size_gb",
                "rootfs_data_path",
                "rootfs_hash_path",
                "cpu_count",
                "memory_mb",
            ),
            "",
        )
    )
    from apps.orchestration.services import migration_ticket

    monkeypatch.setattr(
        migration_ticket, "remint_dest_ticket", lambda vm, **kw: b"cose"
    )
    monkeypatch.setattr(
        order_dispatch, "build_migrate_activate_payload", lambda **kw: {}
    )

    class _Ok:
        ok = True
        status = 200
        classifier = ""

    def _dispatch(*, miner_id, netbird_ip, order_id, kind, payload_json):
        seen.append(order_id)
        return _Ok()

    monkeypatch.setattr(order_dispatch, "dispatch_order", _dispatch)

    dispatch_migrate_activate = fx.real["dispatch_migrate_activate"]
    for job_id in (job.job_id, job.job_id, "redrive-job"):
        dispatch_migrate_activate(
            vm,
            dest_node_id="node-dst",
            new_gen=job.new_gen,
            get_url="https://s3/x",
            boot_artifacts=None,
            job_id=job_id,
        )

    assert seen[0] == seen[1], "a job's own retries must reuse ONE order_id"
    assert seen[2] != seen[0], (
        "a re-drive must present a DISTINCT order_id, or the destination "
        "answers `idempotent-replay` and restores nothing"
    )


# ─── the failure the recovery is FOR, end to end ─────────────────────


def test_a_quiesce_failure_no_longer_strands_the_vm(
    monkeypatch: pytest.MonkeyPatch, fx
):
    """The whole arc, driven through the real state machine: a migration
    that dies at the quiesce leaves the VM fenced, and the very next tick
    restores it to the source instead of leaving it there forever."""
    _stub_evidence(monkeypatch, None)
    from apps.identity.models import PrincipalScope, ServiceClient

    vm = make_vm(host="node-src", generation=1)
    actor = ServiceClient.objects.create(
        scope=PrincipalScope.OPERATOR.value, name="ops-strand"
    )
    job = service.start_migration(vm=vm, dest_node_id="node-dst", decided_by=actor)
    fx.fail.add("relay_quiesce")

    service.tick_once()  # Draining → Quiescing
    # `Quiescing` FENCES first (`_fence_vm`, so the guest's stopped-ack can
    # ingest) and only then dispatches the quiesce — which fails here. The
    # VM is left fenced with the job stuck retrying.
    service.tick_once()
    vm.refresh_from_db()
    assert vm.state == VmState.MIGRATING.value

    # Age the phase past its deadline so the retry window is exhausted.
    MigrationJob.objects.filter(id=job.id).update(
        phase_started_at=timezone.now() - timezone.timedelta(seconds=3600)
    )
    service.tick_once()  # the quiesce fails closed AND the sweep restores

    job.refresh_from_db()
    vm.refresh_from_db()
    assert job.state == MigrationState.FAILED.value
    assert job.failed_from_state == MigrationState.QUIESCING.value
    assert vm.state == VmState.ACTIVE.value
    assert vm.host == "node-src"
    assert vm.generation == 1
