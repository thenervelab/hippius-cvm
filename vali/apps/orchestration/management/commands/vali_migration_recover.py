"""`vali_migration_recover` — recover a VM STRANDED by a failed §25 migration.

## The failure this exists for

A §25 migration that fails from `Quiescing` onward leaves the `Vm` row in
`migrating`: the source guest was gracefully stopped (it signed its
`stopped{}` ack) and the destination never came up. There is then no
domain on either host, the tenant is DOWN, and — before the sweep that
ships with this command — nothing looked at it: `reboot_recovery_once`
scans `active` VMs, `reclaim_migrated_sources` scans `done` jobs,
`sweep_guest_liveness` scans `active` VMs. The VM stayed down until a
human happened to query the database.

## The two recoveries, and why the choice is NOT ours to make

`effects.kbs_activate_dest` moves the KBS `VmState` to
`Migrating{old_gen, new_gen, source, dest}`. From that instant
`kbs_core::lifecycle::check_releasable` releases the tenant KEK to
`(new_gen, dest-chip)` and to NOTHING else. That is not a fence vali can
lift: the KBS admin surface has three lifecycle writes (`register-vm`,
`activate`, `seed-boot-counter`); `activate` is forward-only AND refuses
every non-`Active` current state, and `register-vm` on a divergent state
is a 409-with-no-write. **There is no route from `Migrating` back to
`Active{source}`.** So:

* **before** `DestActivating` — the KBS never moved. The source is still
  the only host that can unlock, and the destination was never even told
  to restore. `restore-source` flips vali's row back to
  `Active{source_gen, source}` so its intent agrees with the KBS's
  authoritative state, and reboot-recovery relaunches the guest on the
  source. The tick sweep does this AUTOMATICALLY; this command exists for
  the case where the automatic path is disabled or its CAS lost.

* **at or after** `DestActivating` — the KBS is committed to
  `(new_gen, dest)`. Restoring the source would un-fence a guest that can
  never obtain its KEK (it boots and hangs in its initramfs) AND leave
  vali claiming `Active{source}` while the KBS says the destination owns
  the VM — so a destination that later recovered would activate at
  `new_gen` behind vali's back. The ONLY recovery is FORWARD:
  `redrive-dest` opens a fresh `MigrationJob` at `DestActivating` for the
  SAME destination at the SAME `new_gen`, which the orchestration tick
  then drives to completion.

The verdict is computed by `service.stranded_recovery_verdict` — the SAME
function the automatic sweep uses — so an operator cannot reach a
`restore-source` the sweep would refuse. `--action` may only NARROW the
verdict, never override it.

## Safety posture

- **Dry-run is the DEFAULT.** Nothing mutates without `--commit`. The
  dry-run computes the REAL verdict (including the KBS evidence read), so
  its answer is the answer.
- **The #936 reclaim gate is untouched.** A restore settles the failed
  job's `source_reclaim_state` to `skipped` — the terminal that never
  dispatches a destroy — because after a restore the source holds the
  VM's ONLY copy. Nothing here can move a job to `reclaimed`.
- **A re-drive never invents a source ack.** `_migration_guard` refuses
  `DestActivating` without `source_ack_verified`, and the new job's flag
  is COPIED from the failed job's durable record; a job that never
  verified an ack cannot be re-driven.
- **A re-drive refuses to race a live restore.** The destination's own
  migration status is polled first: `running` (a restore is in flight) or
  `done` (it actually finished — the tick should activate it, not
  re-drive) both refuse. An unreachable / 404 status is treated as "no
  restore in flight", which is the post-agent-restart case that most
  needs a re-drive.
- **§20.** Only non-secret identifiers reach stdout. The re-minted COSE
  ticket is never printed.

## CLI

    manage.py vali_migration_recover --vm-id VM [--vm-id VM ...] | --all-stranded
                                     [--action auto|restore-source|redrive-dest]
                                     [--commit] [--dry-run]

Exit 0 when every selected VM was recovered (or would be); 1 when any was
refused.
"""

from __future__ import annotations

import secrets
import sys
from dataclasses import dataclass
from typing import Any

from django.core.management.base import BaseCommand, CommandError
from django.db import IntegrityError, transaction
from django.utils import timezone

from apps.lifecycle.models import Vm
from apps.orchestration import effects, service
from apps.orchestration.models import (
    MigrationJob,
    MigrationState,
    StrandRecoveryState,
)

#: Exit code when at least one selected VM was NOT recovered.
EXIT_SOME_FAILED = 1

ACTION_AUTO = "auto"
_ACTIONS = (ACTION_AUTO, service.STRAND_RESTORE_SOURCE, service.STRAND_REDRIVE_DEST)

_OK_RESTORED = "restored-source"
_OK_REDRIVEN = "redriven-dest"
_WOULD = "would-"
_REFUSED = "refused"


@dataclass
class VmOutcome:
    """One row of the per-VM outcome table."""

    vm_id: str
    verdict: str
    outcome: str
    detail: str

    @property
    def failed(self) -> bool:
        return self.outcome == _REFUSED


class Command(BaseCommand):
    help = (
        "Recover a VM stranded in `migrating` by a failed §25 migration. "
        "Dry-run by default — pass --commit to mutate. The action is chosen "
        "by the SAME evidence rule the automatic sweep uses: a source restore "
        "is permitted ONLY when vali's durable record proves the migration "
        "never entered DestActivating (so the KBS `VmState` is still "
        "Active{source} and the source is the only host that can unlock); "
        "otherwise the only recovery is a forward re-drive of the same "
        "destination at the same generation."
    )

    def add_arguments(self, parser: Any) -> None:
        parser.add_argument(
            "--vm-id",
            action="append",
            default=[],
            help="VM to recover. Repeatable. Mutually exclusive with --all-stranded.",
        )
        parser.add_argument(
            "--all-stranded",
            action="store_true",
            help="Select every VM the stranded-migration sweep detects.",
        )
        parser.add_argument(
            "--action",
            choices=_ACTIONS,
            default=ACTION_AUTO,
            help=(
                "auto (default) = do what the evidence verdict says. Naming an "
                "action NARROWS it: a VM whose verdict differs is REFUSED, "
                "never forced."
            ),
        )
        parser.add_argument(
            "--commit",
            action="store_true",
            help="Actually recover. Without it nothing mutates.",
        )
        parser.add_argument(
            "--dry-run",
            action="store_true",
            help="Explicitly request the default no-mutation mode (rejects --commit).",
        )

    # ── entry point ─────────────────────────────────────────────────────

    def handle(self, *args: Any, **options: Any) -> None:
        vm_ids: list[str] = list(options["vm_id"])
        all_stranded: bool = options["all_stranded"]
        commit: bool = options["commit"]
        dry_run: bool = options["dry_run"]
        action: str = options["action"]

        if commit and dry_run:
            raise CommandError("--commit and --dry-run are mutually exclusive")
        if bool(vm_ids) == all_stranded:
            raise CommandError("pass exactly one of --vm-id / --all-stranded")

        pairs = self._select(vm_ids, all_stranded)
        if not pairs:
            self.stdout.write("no stranded VMs selected — nothing to do")
            return

        outcomes = [self._recover_one(vm, job, action, commit) for vm, job in pairs]
        self._report(outcomes, commit=commit)
        if any(o.failed for o in outcomes):
            sys.exit(EXIT_SOME_FAILED)

    # ── selection ───────────────────────────────────────────────────────

    def _select(
        self, vm_ids: list[str], all_stranded: bool
    ) -> list[tuple[Vm, MigrationJob | None]]:
        stranded = service.stranded_migrations()
        if all_stranded:
            return stranded
        by_id = {vm.vm_id: (vm, job) for vm, job in stranded}
        selected: list[tuple[Vm, MigrationJob | None]] = []
        for vm_id in vm_ids:
            if vm_id in by_id:
                selected.append(by_id[vm_id])
                continue
            # Say precisely WHY a named VM is not selectable — "not stranded"
            # and "does not exist" are very different operator situations.
            vm = Vm.objects.filter(vm_id=vm_id).first()
            if vm is None:
                raise CommandError(f"{vm_id}: no such Vm")
            raise CommandError(
                f"{vm_id}: not stranded (state={vm.state!r}) — this command only "
                "recovers a VM fenced in `migrating` behind a TERMINAL migration "
                "job. A VM with a LIVE migration job is being driven by the tick."
            )
        return selected

    # ── per-VM recovery ─────────────────────────────────────────────────

    def _recover_one(
        self,
        vm: Vm,
        job: MigrationJob | None,
        action: str,
        commit: bool,
    ) -> VmOutcome:
        try:
            verdict = service.stranded_recovery_verdict(vm, job)
        except Exception as exc:  # noqa: BLE001 — one VM must not abort the run.
            return VmOutcome(vm.vm_id, "error", _REFUSED, f"verdict failed: {exc}")

        label = f"{verdict.action}:{verdict.reason}"
        if verdict.action == service.STRAND_BLOCKED:
            return VmOutcome(vm.vm_id, label, _REFUSED, verdict.reason)
        if action != ACTION_AUTO and action != verdict.action:
            return VmOutcome(
                vm.vm_id,
                label,
                _REFUSED,
                f"--action {action} does not match the evidence verdict "
                f"({verdict.action}); the verdict is never overridden",
            )
        assert job is not None  # every non-blocked verdict requires a job

        if verdict.action == service.STRAND_RESTORE_SOURCE:
            if not commit:
                return VmOutcome(
                    vm.vm_id,
                    label,
                    f"{_WOULD}restore-source",
                    f"un-fence to active on {job.source_node_id} at generation "
                    f"{job.source_gen}; reboot-recovery then relaunches the guest",
                )
            if not service.restore_source_vm(vm, job):
                return VmOutcome(
                    vm.vm_id, label, _REFUSED, "restore CAS lost — re-run to retry"
                )
            return VmOutcome(
                vm.vm_id,
                label,
                _OK_RESTORED,
                f"active on {job.source_node_id} at generation {job.source_gen}",
            )

        # redrive-dest
        blocker = self._redrive_blocker(vm, job)
        if blocker is not None:
            return VmOutcome(vm.vm_id, label, _REFUSED, blocker)
        if not commit:
            return VmOutcome(
                vm.vm_id,
                label,
                f"{_WOULD}redrive-dest",
                f"re-mint the dest ticket at generation {job.new_gen} and open a "
                f"fresh migration job at dest_activating for {job.dest_node_id}",
            )
        try:
            new_job = self._redrive(vm, job)
        except Exception as exc:  # noqa: BLE001 — report, never traceback.
            return VmOutcome(vm.vm_id, label, _REFUSED, f"re-drive failed: {exc}")
        return VmOutcome(
            vm.vm_id,
            label,
            _OK_REDRIVEN,
            f"job {new_job.job_id} → {job.dest_node_id} at generation "
            f"{job.new_gen}; the orchestration tick drives it from here",
        )

    # ── re-drive ────────────────────────────────────────────────────────

    def _redrive_blocker(self, vm: Vm, job: MigrationJob) -> str | None:
        """`None` iff a forward re-drive is safe to open; else why not."""
        if not job.source_ack_verified:
            # The §25 split-brain gate, restated at the intake: a job that
            # never verified the source's signed `stopped{}` ack cannot be
            # re-driven, because `_migration_guard` would (correctly) fail
            # the new job the instant it ticked.
            return (
                "the failed job has no VERIFIED source-stopped ack — the §25 "
                "split-brain gate refuses DestActivating without one"
            )
        if not job.snapshot_bucket or not job.snapshot_key:
            return (
                "the failed job records no snapshot object — there is nothing "
                "for the destination to restore"
            )
        if service._has_active_job(vm):
            return "the VM already has an in-flight orchestration job"
        # Never race a restore that is still running on the destination.
        try:
            status = effects.poll_dest_activation(vm, dest_node_id=job.dest_node_id)
        except effects.EffectError:
            # Unreachable dest, or a 404 from a status store the agent lost on
            # restart. Both mean "no restore is in flight there", which is the
            # state a re-drive is FOR. A genuinely unreachable dest fails at
            # the dispatch, loudly, without having mutated anything.
            status = ""
        if status == "running":
            return (
                "the destination reports a restore still RUNNING — re-driving "
                "would start a second concurrent restore of the same VM"
            )
        if status == "done":
            return (
                "the destination reports the restore DONE — this is not a "
                "re-drive case; investigate why the job failed instead of "
                "re-running the restore"
            )
        return None

    def _redrive(self, vm: Vm, job: MigrationJob) -> MigrationJob:
        """Mint a FRESH dest ticket at `new_gen`, then open a new
        `MigrationJob` directly in `DestActivating`.

        The fresh mint is mandatory, not hygiene: OrderTickets carry a 24h
        expiry, and `remint_dest_ticket` REUSES a stored same-generation
        intake. A re-drive more than a day after the original migration
        would otherwise hand the destination an expired ticket, the KBS
        would answer 400, and the re-drive would fail exactly like the
        original — the same trap `vali_kbs_recover` documents. Minting here
        with `reuse_existing=False` persists a newer intake row, which the
        dispatch's own `remint_dest_ticket` then picks up (it orders by
        `-received_at`).

        Opening the job at `DestActivating` rather than re-running the
        migration from `Draining` is the whole point: the source guest is
        already stopped, its ack is already verified, and its volume is
        already in S3 — and the KBS is already `Migrating{new_gen, dest}`,
        which `Quiescing` could not re-establish anyway (`_fence_vm`
        requires an `Active` VM).
        """
        from apps.orchestration.services import migration_ticket

        migration_ticket.remint_ticket(
            vm,
            node_id=job.dest_node_id,
            generation=job.new_gen,
            reuse_existing=False,
        )
        now = timezone.now()
        try:
            with transaction.atomic():
                new_job = MigrationJob.objects.create(
                    job_id=secrets.token_hex(16),
                    vm=vm,
                    source_node_id=job.source_node_id,
                    dest_node_id=job.dest_node_id,
                    source_gen=job.source_gen,
                    new_gen=job.new_gen,
                    state=MigrationState.DEST_ACTIVATING.value,
                    snapshot_bucket=job.snapshot_bucket,
                    snapshot_key=job.snapshot_key,
                    snapshot_state_key=job.snapshot_state_key,
                    # COPIED from the failed job's durable record, never
                    # asserted here — see `_redrive_blocker`.
                    source_ack_verified=True,
                    phase_started_at=now,
                    decided_by=job.decided_by,
                    reason=f"redrive of {job.job_id}"[:256],
                )
        except IntegrityError as exc:
            raise CommandError(
                f"{vm.vm_id}: a migration job was opened concurrently"
            ) from exc
        MigrationJob.objects.filter(
            id=job.id, strand_recovery_state=StrandRecoveryState.NONE.value
        ).update(
            strand_recovery_state=StrandRecoveryState.REDRIVEN.value,
            strand_recovery_at=now,
            strand_recovery_reason=f"redriven as {new_job.job_id}"[:256],
        )
        return new_job

    # ── reporting ───────────────────────────────────────────────────────

    def _report(self, outcomes: list[VmOutcome], *, commit: bool) -> None:
        mode = "COMMIT" if commit else "DRY-RUN (nothing mutated)"
        self.stdout.write(f"§25 stranded-migration recovery — {mode}")
        for o in outcomes:
            self.stdout.write(
                f"  {o.vm_id}: verdict={o.verdict} outcome={o.outcome} — {o.detail}"
            )
        failed = sum(1 for o in outcomes if o.failed)
        self.stdout.write(f"{len(outcomes)} VM(s), {failed} refused")
        if not commit and failed < len(outcomes):
            self.stdout.write("re-run with --commit to apply")
        # A restored VM is `Active` with no domain; reboot-recovery is what
        # brings the guest back, and it is flag-gated.
        if commit and any(o.outcome == _OK_RESTORED for o in outcomes):
            self.stdout.write(
                "NOTE: a restored VM is `active` with NO running domain. "
                "reboot-recovery relaunches it on the source — confirm "
                "VALI_REBOOT_RECOVERY_ENABLED is on, and that the source miner "
                "is on-chain-Active and heart-beating."
            )
