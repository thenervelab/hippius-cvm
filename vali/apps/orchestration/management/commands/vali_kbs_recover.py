"""`vali_kbs_recover` — re-establish KBS VM state after a KBS restart.

## Why this exists

The KBS runs as a SEV-SNP Kata CVM and its `state_dir` is an emptyDir whose
encryption key lives INSIDE the CVM. A pod restart therefore wipes
`vm-states.json` (and `boot-counters.json`) irrecoverably — no volume, no
backup, no in-place preservation is possible, by design. Every running
tenant VM then has NO KBS record: its next KEK release (a reboot, a §25
dest activation, a reboot-recovery relaunch) is refused, and the disk stays
locked.

The only way back is to re-establish that state from OUTSIDE, through the
admin API, IN THIS ORDER:

1. *(when a counter was supplied)* **re-seed the boot counter** — the per-VM
   anti-rollback counter the KBS also lost. See the one-shot warning below.
2. **re-register the VM state** — mint a FRESH OrderTicket at the VM's
   CURRENT generation bound to its CURRENT host, and `register-vm` it. The
   KBS `VmStateRegister::register` is absent ⇒ insert, identical ⇒ no-op,
   different ⇒ 409-with-no-write, so re-running is safe.

## SEED FIRST — the order is a correctness requirement, not a preference

The release path does NOT use `check_and_advance`: it calls `check_only`
at step 5b and `commit` at step 11c (`kbs-core/src/release.rs`), with the
Vault/broker KEK read, the nonce spend and the release-once commit in
between. That gap contains a network round-trip, so it is on the order of
SECONDS, not microseconds. On a WIPED store (`stored = 0`) registering
FIRST opens that gap to our own recovery:

    stored=0 → guest boots, check_only(1) passes → we seed to N
             → the release commits(1): 1 <= N ⇒ fail closed

The guest got its KEK and advanced its OWN on-disk counter; the KBS's did
not. The two are now desynchronised, the next boot is refused, and guard 1
(`stored != 0` ⇒ 409) blocks any correction — a brick produced by the
recovery procedure itself.

Seeding first does not merely narrow that gap, it makes it UNREACHABLE:
release step 5 does `deps.vm_states.get(&ticket.vm_id)?` and the store
errors on an absent row, so an unregistered VM never reaches the step-5b
counter check at all. No guest can be in flight against a counter we are
about to seed. Hence: seed, then register.

For the same reason, a VM whose seed did not land is NOT registered:
leaving it unregistered is inert and retryable; registering it on the
strength of a seed that did not happen is what re-opens the gap. That
includes `409 not-wiped` (below) — a refused seed means the operator's
premise about this VM is wrong, and the answer to that is to stop and let
them look, not to half-recover it. Seeding is independent of the lifecycle
store — `process_admin_seed_boot_counter` consults ONLY the boot-counter
store — so seeding an unregistered vm_id is accepted.

A stored / launch-time ticket CANNOT be replayed: tickets carry a 24h
expiry, so the KBS answers 400. The re-mint is mandatory, and it is the
SAME code §25 uses (`services.migration_ticket`), parameterised — never a
second copy.

## The boot counter is a ONE-SHOT, IRREVERSIBLE input

`--boot-counter-file` / `--boot-counter` seeds the KBS's per-VM counter.
Semantics: seeding N means "N boots already consumed", so the guest's next
boot submits N+1. The KBS refuses EVERY subsequent seed for that VM
(`409 seed-already-recovered`) — deliberately, because silently overwriting
a live counter would be a brick-the-tenant primitive. Consequences:

- a WRONG value cannot be corrected through any API;
- a too-LOW value locks the VM out permanently.

So the value must be READ from the authoritative source, not typed from
memory: the miner's per-VM state disk `/var/lib/hippius-miner/state/<vm>.raw`
(plain ext4, containing a text file `boot-counter`). vali has no path to the
miner and must NEVER guess it. Prefer `--boot-counter-file` (the bytes as
read); `--boot-counter N` is the second-class hand-typed path and warns
loudly. Omitting both simply skips seeding.

### The value is passed through VERBATIM — no +1, no -1

Derived from the guest side (`binaries/guest-release/src/main.rs::
read_last_counter`), which returns `prev + 1` from the file and `1` when the
file is missing or empty:

- the file holds the LAST KBS-COMMITTED counter;
- the guest submits `file + 1`;
- the KBS expects `stored + 1`;
- ⇒ the KBS must be seeded with the file's value EXACTLY as read.

Confirmed end-to-end on the real tenant (file = 1 ⇒ the KBS must hold 1 and
the next boot submits 2), and independently re-read from
`guest-release/src/main.rs:362` (`prev.checked_add(1)`). An off-by-one here
is the unrecoverable failure mode this command's `--yes` gate exists to
prevent, so the parse never adjusts the number and a test pins the
pass-through.

### A MISSING or EMPTY counter file means "seed NOTHING", not "seed 1"

`read_last_counter` returns `1` when the file is missing or empty — it
treats `prev` as 0. So such a VM will submit `1`, which a WIPED KBS row
(`stored = 0`) already accepts: there is nothing to restore, and no
legitimate seed value can be derived from an absent file.

This is why the strict parser refuses empty/truncated files for a second
reason beyond caution — not merely "we can't trust this number", but "there
is no number here to want". Forcing `--boot-counter 1` in that situation is
actively harmful: it consumes the VM's single seed attempt to set a row
that did not need setting, and guard 1 then locks out any later REAL
recovery. (The nearest wrong move fails safely: seeding 0 is a clean
`400 counter-zero`.)

## Safety posture

- **Dry-run is the DEFAULT.** Nothing is minted, written or POSTed without
  an explicit `--commit`. The dry-run runs the SAME fail-closed resolution
  the committing path runs (`migration_ticket.resolve_ticket_inputs`), so
  its verdict is the real verdict.
- **Fail CLOSED, per VM.** No launch record / no measurement / no host / no
  miner chip identity ⇒ that VM is refused loudly and NOTHING is minted for
  it. One VM's failure never aborts the others.
- **§20.** The COSE ticket bytes and the userdata plaintext (read inside the
  re-mint to re-derive the §6 digest) are never printed. Only non-secret
  identifiers, the public measurement, and Vault PATHS reach stdout.

## CLI

    python manage.py vali_kbs_recover --vm-id VM [--vm-id VM ...] | --all-active
                                      [--commit] [--dry-run]
                                      [--boot-counter-file PATH | --boot-counter N]
                                      [--counter-source HOST] [--yes]

Exit 0 when every selected VM succeeded, 1 when any failed.
"""

from __future__ import annotations

import re
import sys
from dataclasses import dataclass
from typing import Any

from django.core.management.base import BaseCommand, CommandError

from apps.lifecycle.models import Vm, VmState
from apps.orchestration import effects, kbs_admin
from apps.orchestration.services import migration_ticket

#: Exit code when at least one selected VM was NOT recovered — a wrapper
#: script gates on this. A clean run returns normally (exit 0).
EXIT_SOME_FAILED = 1

#: A boot counter read off the miner's state disk is an unsigned decimal
#: integer with at most one trailing newline. NOTHING else parses: a
#: truncated/partial read must FAIL rather than silently yield a smaller
#: number — a smaller number is exactly the permanent lock-out.
_COUNTER_RE = re.compile(r"^(0|[1-9][0-9]*)\n?$")

#: Per-VM outcome slugs (greppable, stable). The seed half precedes the
#: register half, so the slugs read in execution order.
_OK_REGISTERED = "registered"
_OK_SEEDED_REGISTERED = "seeded+registered"
#: Our OWN earlier 200 in this same run, re-observed as a 409 on a retry.
_OK_SEED_NOOP_REGISTERED = "seed-noop-our-retry+registered"
_WARN_SEED_NOT_DEPLOYED = "seed-route-missing+register-skipped"
#: 409 with NO prior 200 from us: the row was already non-zero before we
#: started, so the operator's premise ("this VM lost its counter") is false.
#: Its own label precisely because it must not read as a recovery.
_WARN_SEED_NOT_WIPED = "seed-refused-not-wiped+register-skipped"
_WOULD = "would-recover"
_FAILED = "failed"

#: Outcomes that count as a warning (reported, but not an exit-code failure).
_WARN_OUTCOMES = frozenset({_WARN_SEED_NOT_DEPLOYED, _WARN_SEED_NOT_WIPED})

#: Seed outcomes after which the register MUST NOT run — the counter was not
#: established by us, so registering would re-open the release-path gap (and,
#: for `not-wiped`, would half-act on a premise that is already known false).
_SEED_OUTCOMES_BLOCKING_REGISTER = frozenset(
    {_FAILED, _WARN_SEED_NOT_DEPLOYED, _WARN_SEED_NOT_WIPED}
)


@dataclass
class VmOutcome:
    """One row of the per-VM outcome table."""

    vm_id: str
    generation: int | None
    node_id: str
    outcome: str
    detail: str

    @property
    def failed(self) -> bool:
        return self.outcome == _FAILED

    @property
    def warned(self) -> bool:
        return self.outcome in _WARN_OUTCOMES


@dataclass(frozen=True)
class SeedInput:
    """A validated boot-counter seed request + where its value came from."""

    counter: int
    provenance: str


class Command(BaseCommand):
    help = (
        "Re-establish KBS VM state after a KBS restart wiped it: (1) optionally "
        "seed the boot counter, then (2) re-mint an OrderTicket at the VM's "
        "CURRENT generation + host and register-vm it. Dry-run by default — pass "
        "--commit to mutate. SEED FIRST: registering first lets a guest boot race "
        "the seed (check_only and commit are separate lock acquisitions) and "
        "desynchronise the counter, which guard 1 then makes uncorrectable. The "
        "seed is ONE-SHOT PER VM: a wrong value cannot be corrected and "
        "permanently locks the VM out, so read it from the miner's "
        "/var/lib/hippius-miner/state/<vm>.raw:boot-counter — never from memory."
    )

    # ── arguments ───────────────────────────────────────────────────────

    def add_arguments(self, parser: Any) -> None:
        parser.add_argument(
            "--vm-id",
            action="append",
            default=[],
            help="VM to recover. Repeatable. Mutually exclusive with --all-active.",
        )
        parser.add_argument(
            "--all-active",
            action="store_true",
            help="Recover every Vm in state 'active'.",
        )
        parser.add_argument(
            "--commit",
            action="store_true",
            help="Actually mint + register (and seed). Without it nothing mutates.",
        )
        parser.add_argument(
            "--dry-run",
            action="store_true",
            help="Explicitly request the default no-mutation mode (rejects --commit).",
        )
        parser.add_argument(
            "--boot-counter-file",
            default="",
            help=(
                "PREFERRED. Path to the bytes read from the miner's per-VM state "
                "disk (/var/lib/hippius-miner/state/<vm>.raw → 'boot-counter'). "
                "Must be a bare unsigned integer; a truncated/empty/multi-line "
                "file is REFUSED. Requires exactly one --vm-id."
            ),
        )
        parser.add_argument(
            "--boot-counter",
            type=int,
            default=None,
            help=(
                "SECOND-CLASS, hand-typed counter. Prefer --boot-counter-file: "
                "seeding is ONE-SHOT per VM and a typo bricks the VM."
            ),
        )
        parser.add_argument(
            "--counter-source",
            default="",
            help="Host the counter was read from, recorded in the output for audit.",
        )
        parser.add_argument(
            "--yes",
            action="store_true",
            help="Confirm the irreversible one-shot boot-counter seed.",
        )

    # ── entry point ─────────────────────────────────────────────────────

    def handle(self, *args: Any, **opts: Any) -> None:
        commit: bool = bool(opts["commit"])
        if opts["dry_run"] and commit:
            raise CommandError("--dry-run and --commit are contradictory")

        #: vm_ids for which THIS invocation received a seed 200. The only
        #: thing that distinguishes "my own retry" from "was never wiped"
        #: when the KBS answers 409 (see `_seed_one`). Run-local by design:
        #: a 409 in a FRESH run is never evidence that we did anything.
        self._seeded_ok: set[str] = set()

        vms = self._select_vms(opts)
        # Parse + validate the seed BEFORE any network call, so a malformed
        # counter file can never consume a VM's single seed attempt (and
        # never even reaches the register step).
        seed = self._resolve_seed(opts, vms=vms, commit=commit)

        mode = "commit" if commit else "dry-run"
        self.stdout.write(
            f"vali-kbs-recover: mode={mode} selected={len(vms)}"
            + (f" seed_counter={seed.counter}" if seed else " seed_counter=none")
        )
        if seed is not None:
            self.stdout.write(
                f"vali-kbs-recover: seed provenance={seed.provenance} "
                "ONE-SHOT — this can be done once per VM; a wrong value cannot "
                "be corrected and locks the VM out permanently"
            )

        try:
            outcomes = [self._recover_one(vm, commit=commit, seed=seed) for vm in vms]
        except effects.KbsAdminContractMismatch as exc:
            # NOT a per-VM failure to iterate past: vali and the deployed KBS
            # disagree about the seed contract, so every remaining VM would
            # fail identically. Abort the run and surface it.
            raise CommandError(f"ABORTING the run — {exc}. No further VM was touched.") from exc
        self._report(outcomes, mode=mode)

        if any(o.failed for o in outcomes):
            sys.exit(EXIT_SOME_FAILED)

    # ── selection ───────────────────────────────────────────────────────

    def _select_vms(self, opts: dict[str, Any]) -> list[Vm]:
        vm_ids: list[str] = list(opts["vm_id"] or [])
        all_active: bool = bool(opts["all_active"])
        if vm_ids and all_active:
            raise CommandError("--vm-id and --all-active are mutually exclusive")
        if not vm_ids and not all_active:
            raise CommandError("pass --vm-id (repeatable) or --all-active")

        if all_active:
            return list(Vm.objects.filter(state=VmState.ACTIVE).order_by("vm_id"))

        # Preserve the operator's order + refuse an unknown id LOUDLY rather
        # than silently recovering a subset.
        rows = {vm.vm_id: vm for vm in Vm.objects.filter(vm_id__in=vm_ids)}
        missing = [v for v in vm_ids if v not in rows]
        if missing:
            raise CommandError(f"unknown vm_id(s): {', '.join(sorted(missing))}")
        # De-duplicate a repeated --vm-id while keeping first-seen order.
        seen: set[str] = set()
        ordered: list[Vm] = []
        for vm_id in vm_ids:
            if vm_id not in seen:
                seen.add(vm_id)
                ordered.append(rows[vm_id])
        return ordered

    # ── boot-counter input ──────────────────────────────────────────────

    def _resolve_seed(
        self, opts: dict[str, Any], *, vms: list[Vm], commit: bool
    ) -> SeedInput | None:
        """Validate the operator-supplied counter, or `None` when seeding was
        not requested. Omitting it SKIPS seeding — never guesses a value.
        """
        path: str = str(opts["boot_counter_file"] or "")
        literal: int | None = opts["boot_counter"]
        if not path and literal is None:
            return None
        if path and literal is not None:
            raise CommandError("--boot-counter-file and --boot-counter are mutually exclusive")
        if opts["all_active"] or len(vms) != 1:
            raise CommandError(
                "a boot-counter seed applies to exactly ONE VM — pass a single "
                "--vm-id (the counter is read per-VM from that miner's state disk)"
            )

        if path:
            counter = self._parse_counter_file(path)
            provenance = f"file:{path}"
        else:
            counter = int(literal)  # type: ignore[arg-type]
            provenance = "cli:--boot-counter (hand-typed)"
            self.stderr.write(
                self.style.WARNING(
                    "WARNING: --boot-counter is the hand-typed path. The seed is "
                    "ONE-SHOT per VM and a typo permanently locks the VM out. "
                    "Prefer --boot-counter-file with the bytes read from "
                    "/var/lib/hippius-miner/state/<vm>.raw ('boot-counter')."
                )
            )
        source = str(opts["counter_source"] or "")
        if source:
            provenance = f"{provenance}@{source}"

        if counter <= 0:
            raise CommandError(
                f"boot counter {counter} is not a legitimate recovered value "
                "(the KBS refuses 0 — 'counter-zero')"
            )
        if counter > effects.MAX_SEED_COUNTER:
            raise CommandError(
                f"boot counter {counter} exceeds the KBS cap "
                f"{effects.MAX_SEED_COUNTER} ('seed-above-cap') — check for a "
                "fat-fingered extra digit"
            )

        # Echo the exact plan, then demand explicit confirmation. Only the
        # committing path can consume the single attempt, so --yes is
        # required only there; a dry-run prints the plan and stops.
        vm_id = vms[0].vm_id
        self.stdout.write(
            f"vali-kbs-recover: seed-plan vm={vm_id} counter={counter} "
            f"provenance={provenance} "
            f"(means {counter} boots consumed; next guest boot submits "
            f"{counter + 1})"
        )
        if commit and not opts["yes"]:
            raise CommandError(
                f"refusing to seed vm={vm_id} counter={counter} without --yes: "
                "this can be done ONCE per VM and a wrong value cannot be "
                "corrected (every later seed is refused and the VM stays locked)"
            )
        return SeedInput(counter=counter, provenance=provenance)

    def _parse_counter_file(self, path: str) -> int:
        """Strictly parse the counter file. Anything that is not exactly an
        unsigned decimal integer (optionally one trailing newline) is
        REFUSED — a partial read must never silently parse as a smaller
        number, because a smaller number is the permanent lock-out.

        A MISSING or EMPTY file is refused with its own message, and that
        message must steer the operator to seed NOTHING rather than to
        substitute 1: `read_last_counter` treats an absent file as `prev = 0`
        and submits 1, which a wiped KBS row already accepts, so there is
        nothing to restore and no value to derive. Seeding 1 anyway would
        burn the VM's single attempt and guard-1-lock any later real
        recovery.
        """
        try:
            with open(path, "rb") as fh:
                raw = fh.read()
        except OSError as exc:
            raise CommandError(
                f"--boot-counter-file unreadable: {exc}. If the file genuinely "
                "does not exist, seed NOTHING for this VM — do NOT substitute "
                "--boot-counter 1: the guest treats an absent file as 0 boots "
                "and submits 1, which a wiped KBS row already accepts."
            ) from exc
        if not raw:
            raise CommandError(
                f"--boot-counter-file {path!r} is empty — seed NOTHING for this "
                "VM, do NOT substitute --boot-counter 1. An empty file means "
                "the guest submits 1, which a wiped KBS row already accepts, so "
                "there is nothing to restore; seeding 1 would consume this VM's "
                "single attempt and lock out any later real recovery."
            )
        try:
            text = raw.decode("ascii")
        except UnicodeDecodeError as exc:
            raise CommandError(
                f"--boot-counter-file {path!r} is not ASCII — refusing to guess"
            ) from exc
        if not _COUNTER_RE.match(text):
            raise CommandError(
                f"--boot-counter-file {path!r} is not a bare unsigned integer "
                f"(got {text!r}) — refusing a partial / malformed read"
            )
        # VERBATIM — never +1, never -1. `guest-release::read_last_counter`
        # returns `prev + 1` from this file (and 1 when it is missing/empty),
        # so the file holds the LAST KBS-COMMITTED value, the guest submits
        # `file + 1`, and the KBS expects `stored + 1`: seeding the file's
        # value unchanged is what makes those agree. Verified end-to-end on
        # the real tenant (file = 1 ⇒ KBS holds 1 ⇒ next boot submits 2).
        return int(text)

    # ── per-VM recovery ─────────────────────────────────────────────────

    def _recover_one(self, vm: Vm, *, commit: bool, seed: SeedInput | None) -> VmOutcome:
        """Recover ONE VM. Never raises — every failure becomes a row so the
        next VM is still processed.
        """
        vm_id = vm.vm_id
        try:
            node_id, generation = migration_ticket.current_placement(vm)
            inputs = migration_ticket.resolve_ticket_inputs(
                vm, node_id=node_id, generation=generation
            )
        except effects.EffectError as exc:
            self._line(vm_id, _FAILED, detail=str(exc))
            return VmOutcome(vm_id, None, "", _FAILED, str(exc))

        plan = (
            f"gen={inputs.generation} node={inputs.node_id} "
            f"platform_id={_short(inputs.platform_id)} "
            f"measurement={_short(inputs.measurement_hex)} "
            f"flavor={inputs.flavor}"
        )
        if not commit:
            steps = (
                f"1:seed-counter({seed.counter}) 2:remint+register"
                if seed is not None
                else "1:seed=skipped(no counter supplied) 2:remint+register"
            )
            detail = f"{plan} order={steps}"
            self._line(vm_id, _WOULD, detail=detail)
            return VmOutcome(vm_id, inputs.generation, inputs.node_id, _WOULD, detail)

        # ── step 1: the boot-counter seed, BEFORE the register ──────────
        # An unregistered VM cannot be released to (release step 5 fails on
        # the absent vm-state row), so no guest boot can be in flight across
        # the step-5b `check_only` / step-11c `commit` gap while we seed. A
        # seed that did not land therefore SKIPS the register: unregistered
        # is inert and retryable, registered-with-an-unseeded-counter is not.
        seed_outcome = _OK_REGISTERED
        seed_detail = ""
        if seed is not None:
            seed_outcome, seed_detail = self._seed_one(vm_id, seed)
            if seed_outcome in _SEED_OUTCOMES_BLOCKING_REGISTER:
                self._line(vm_id, seed_outcome, detail=f"{plan} {seed_detail}")
                return VmOutcome(
                    vm_id,
                    inputs.generation,
                    inputs.node_id,
                    seed_outcome,
                    seed_detail,
                )

        # ── step 2: re-mint at (current gen, current host) + register ────
        try:
            cose = migration_ticket.remint_current_ticket(vm)
            ok = kbs_admin.register_vm_active_with_vm_id(vm_id=vm_id, cose_ticket=cose)
        except effects.EffectError as exc:
            # Covers KbsAdminConflict (409 — the KBS holds a DIFFERENT state
            # for this VM; an operator must reconcile), KbsAdminTerminal, and
            # EffectUnavailable (Vault / mint / KBS unreachable).
            self._line(vm_id, _FAILED, detail=f"{plan} {seed_detail} error={exc}")
            return VmOutcome(vm_id, inputs.generation, inputs.node_id, _FAILED, str(exc))

        detail = (
            f"{plan} {seed_detail} ticket_id={ok.ticket_id} "
            f"registered_gen={ok.vm_generation} cached={str(ok.cached).lower()}"
        )
        self._line(vm_id, seed_outcome, detail=detail)
        return VmOutcome(vm_id, inputs.generation, inputs.node_id, seed_outcome, detail)

    def _seed_one(self, vm_id: str, seed: SeedInput) -> tuple[str, str]:
        """POST the one-shot boot-counter seed. Returns `(outcome, detail)`.

        ## The two 409s

        The KBS's guard 1 fires on `stored != 0`, so a 409 says only "the row
        is not wiped" — and the wire response is IDENTICAL whether that is
        our own earlier 200 (a retry) or a row that was never wiped at all.
        The second is not success: nothing was done, the operator's premise
        was false, and telling them "recovered" mid-lockout is the wrong
        conclusion at the worst moment.

        They are separated WITHOUT decoding any body, by the only thing that
        actually carries the signal: whether THIS invocation already saw a
        200 for this vm_id (`self._seeded_ok`). The 200 body's `previous` is
        0 by construction, so it cannot be used for this.

        A missing route (404) is likewise a WARNING rather than a failure —
        the KBS image simply does not serve it yet. Both warnings, and any
        hard failure, skip the register (the caller enforces that): the
        counter was not established by us, so registering would re-open the
        release-path gap.

        A `KbsAdminContractMismatch` (400) is deliberately NOT caught: vali's
        own preconditions make it unreachable, so it means vali and the
        deployed KBS disagree about the contract. Every later VM would fail
        identically, so it propagates and aborts the whole run.
        """
        try:
            res = effects.seed_boot_counter(vm_id, counter=seed.counter)
        except effects.KbsRouteMissing:
            return (
                _WARN_SEED_NOT_DEPLOYED,
                "seed=SKIPPED (KBS 404: the seed-boot-counter route is not in "
                "the deployed KBS image; the vm_id passed vali's charset check, "
                "so this is 'not deployed', not 'bad vm_id'). Counter NOT "
                "recovered ⇒ register SKIPPED too — re-run once the KBS "
                "serving that route is deployed.",
            )
        except effects.KbsAdminContractMismatch:
            raise
        except effects.EffectError as exc:
            return _FAILED, f"seed=FAILED ({exc}) ⇒ register SKIPPED"

        if not res.already_recovered:
            self._seeded_ok.add(vm_id)
            return (
                _OK_SEEDED_REGISTERED,
                f"seed=OK counter={res.counter} previous={res.previous}",
            )
        if vm_id in self._seeded_ok:
            return (
                _OK_SEED_NOOP_REGISTERED,
                "seed=NOOP (KBS 409 — OUR OWN seed earlier in this run already "
                "landed; nothing was overwritten)",
            )
        return (
            _WARN_SEED_NOT_WIPED,
            "seed=REFUSED (KBS 409: the counter row was ALREADY non-zero "
            "before this run — nothing was written and NO recovery happened). "
            "This VM's counter was not lost, or your counter source disagrees "
            "with the KBS. Register SKIPPED — investigate before re-running.",
        )

    # ── output ──────────────────────────────────────────────────────────

    def _line(self, vm_id: str, outcome: str, *, detail: str) -> None:
        """One greppable per-VM line, emitted as the VM is processed."""
        self.stdout.write(f"vm={vm_id} outcome={outcome} {detail}")

    def _report(self, outcomes: list[VmOutcome], *, mode: str) -> None:
        failed = sum(1 for o in outcomes if o.failed)
        warned = sum(1 for o in outcomes if o.warned)
        ok = len(outcomes) - failed - warned

        self.stdout.write("")
        self.stdout.write(f"{'VM':<28} {'GEN':>6} {'NODE':<18} OUTCOME")
        for o in outcomes:
            gen = "-" if o.generation is None else str(o.generation)
            self.stdout.write(f"{o.vm_id:<28} {gen:>6} {(o.node_id or '-'):<18} {o.outcome}")
        summary = (
            f"vali-kbs-recover: summary mode={mode} total={len(outcomes)} "
            f"ok={ok} warned={warned} failed={failed}"
        )
        self.stdout.write("")
        self.stdout.write(self.style.ERROR(summary) if failed else self.style.SUCCESS(summary))


def _short(value: str, keep: int = 16) -> str:
    """Truncate a long public hex identifier for display (never a secret —
    the measurement + platform_id are both public)."""
    if len(value) <= keep:
        return value
    return f"{value[:keep]}…(len={len(value)})"
