"""`vali_set_miner_capacity` — the operator write path for a miner's
capacity policy.

What it sets (any combination in one call, applied atomically):

- the TRUSTED hardware anchor `total_cpus` / `total_memory_mb`
  (`--cpus` + `--memory-mb`, or `--clear`);
- the TRUSTED size of the tenant DATA-disk filesystem `total_disk_gb`
  (`--disk-gb`, or `--disk-clear`) — one down-only term of the disk
  budget (`apps.scheduler.capacity.disk_budget`), never a raise;
- the operator VM-count ceiling `capacity_slots` (`--slots`);
- the per-miner vCPU:thread overcommit `cpu_ratio` (`--cpu-ratio`, or
  `--cpu-ratio-default` to follow `VALI_SCHEDULER_CPU_OVERCOMMIT`);
- the trust class (`--trust operator|earned`);
- the earned ceiling of a permissionless miner (`--earned-reset` back to
  the floor, `--earned-grant VMS VCPUS MEMORY_MB` to vouch for one);
- the per-miner concurrent-boot cap `max_booting` (`--max-booting N`, or
  `--max-booting-default` to follow `VALI_SCHEDULER_MAX_BOOTING_PER_MINER`);
- the cordon (`--cordon` / `--uncordon`): a cordoned miner takes no new
  placement from any caller, while everything already on it runs on —
  no status change, no telemetry change, no drain or migration (that is
  what `QUARANTINED` is for). `--reason` becomes the `cordon_reason`;
- an operator note that changes nothing (`--note`), e.g. to record a
  decision retroactively.

`--show` prints the row's current policy and writes nothing.

The anchor is the input dynamic capacity and the `/v1/scheduler/feasibility`
verdicts are sized from (see `apps.scheduler.capacity`). It is never
self-reported and never chain-sourced — the chain refresh leaves every
column this command writes untouched. The numbers must come from the
FLEET OPERATOR's own knowledge of the hardware, never from the miner
operator's word — an anchor copied from an untrusted report is a
self-report with extra steps.

## Usage

    python manage.py vali_set_miner_capacity --miner-id miner-d \\
        --cpus 64 --memory-mb 256180 --by ops@example.com --reason "seeded from nproc/MemTotal"

    python manage.py vali_set_miner_capacity --node-id <64-hex> --slots 48 \\
        --by ops@example.com --reason "fill test past 32"

    python manage.py vali_set_miner_capacity --miner-id miner-b --cpu-ratio 2.0 \\
        --dry-run

    python manage.py vali_set_miner_capacity --miner-id miner-d --cordon \\
        --by ops@example.com --reason "load ~350 after the 2026-10-05 runner burst"

    python manage.py vali_set_miner_capacity --miner-id miner-d --max-booting 2 \\
        --by ops@example.com --reason "slow SATA RAID-1: integrity wipes serialise"

    python manage.py vali_set_miner_capacity --miner-id miner-d --show

## Refusals (CommandError, nothing written)

- the `MinerCapacity` row does not exist — the chain refresh creates it the
  first time it sees the node on chain; this command never does;
- `--miner-id` is unknown or has no `chain_node_id`;
- a value is out of range (cpus 1..1024, memory 1024..16 TiB in MiB,
  disk 1..1 PiB in GiB,
  slots 1..1024, ratio 1.0..4.0, earned grant 1..the earned hard caps,
  max-booting 1..64);
- `--by` or `--reason` is missing on a real (non-dry-run) write;
- no change was asked for, or `--show` is combined with a change;
- the new anchor is SMALLER than the load vali has ALREADY placed on the
  miner (its own active `Placement` ledger × the flavor table — the same
  committed figure admission uses): a host cannot be running more than it
  has;
- `--slots` below the number of VMs vali has already placed there;
- `--disk-gb` below the DATA disk vali has already committed there;
- `--trust operator` on a row that would be left without an anchor — the
  operator class IS "the operator knows the hardware".

## Warnings (the change is written anyway)

- the anchor holds the committed load but not the host reserve on top of
  it. Admission copes (free clamps to 0, no new placements until load
  drains), and it is the honest anchor for a host loaded under the flat
  `capacity_slots` fallback — refusing it would leave the miner on the
  LESS safe flat cap;
- a FRESH heartbeat self-report is inconsistent with the memory anchor. A
  stale one is ignored, exactly as admission ignores it. The self-report
  is untrusted by design; the anchor is what bounds it.

## Audit

Every applied change lands one `MinerCapacityAudit` row per changed
policy field (`actor = op:<--by>`, `reason = --reason`) in the same
transaction, via `apps.scheduler.capacity_admin`. Every change and every
dry run also emits one structured INFO line on the
`apps.scheduler.capacity_admin` logger and echoes the same JSON as the last
line of stdout.
"""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass
from datetime import timedelta
from typing import Any

from django.core.management.base import BaseCommand, CommandError
from django.db import transaction
from django.utils import timezone

from apps.scheduler import capacity_admin, capacity_config
from apps.scheduler.models import (
    ACTIVE_PLACEMENT_STATES,
    CapacityTrustClass,
    MinerCapacity,
    Placement,
)
from apps.scheduler.service import (
    _committed_resources,
    _host_reserve_cpus,
    _host_reserve_memory_mb,
    miner_liveness_timeout_s,
)

log = logging.getLogger("apps.scheduler.capacity_admin")

_NODE_ID_RE = re.compile(r"^[0-9a-f]{64}$")

MIN_CPUS = 1
MAX_CPUS = 1024
MIN_MEMORY_MB = 1024
MAX_MEMORY_MB = 16 * 1024 * 1024  # 16 TiB, in MiB
MIN_SLOTS = 1
MAX_SLOTS = 1024
MIN_DISK_GB = 1
MAX_DISK_GB = 1024 * 1024  # 1 PiB, in GiB
# `0` is refused on purpose: "no new boots here" is a cordon, which says so.
MIN_MAX_BOOTING = 1
MAX_MAX_BOOTING = 64

# The heartbeat reports AVAILABLE memory, not total, so it is legitimately
# lower than the anchor. Two shapes are still worth a warning:
#   - available > anchor: more free RAM than the anchor says the machine
#     has — the anchor is too small (or a unit slip). This is the exact
#     threshold of admission's over-claim alarm.
#   - available + vali-committed far below the anchor: the host has much
#     less than the anchor even after accounting for the VMs vali placed —
#     the anchor is too large (wrong host, GB/GiB or kB/MiB slip).
_LOW_REPORT_RATIO = 0.5

#: Every column `--show` prints, in display order.
_SHOW_FIELDS: tuple[str, ...] = (
    "status",
    "trust_class",
    "total_cpus",
    "total_memory_mb",
    "capacity_slots",
    "cpu_ratio",
    "earned_vms",
    "earned_vcpus",
    "earned_memory_mb",
    "proven_peak_vms",
    "proven_peak_vcpus",
    "proven_peak_memory_mb",
    "proven_at",
    "earned_last_reason",
    "earned_last_change_at",
    "declared_cpu_budget",
    "declared_memory_mb_budget",
    "declared_asid_capacity",
    "declared_asid_used",
    "declared_at",
    "reported_memory_available_mib",
    "reported_at",
    "total_disk_gb",
    "earned_disk_gb",
    "declared_disk_gb_budget",
    "reported_data_disk_total_gb",
    "reported_data_disk_available_gb",
    "reported_staging_disk_available_gb",
    "disk_reported_at",
    "max_booting",
    "cordoned_at",
    "cordon_reason",
)


@dataclass(frozen=True)
class Anchor:
    total_cpus: int | None
    total_memory_mb: int | None

    def render(self) -> str:
        return f"total_cpus={self.total_cpus} total_memory_mb={self.total_memory_mb}"


@dataclass(frozen=True)
class Committed:
    """What vali ITSELF has placed on a miner — its active `Placement`
    ledger × the flavor table, the same figure admission subtracts."""

    placements: int
    memory_mb: int
    cpus: int


def _committed_on(node_id: str) -> Committed:
    placements = 0
    memory_mb = 0
    cpus = 0
    for resource_class in Placement.objects.filter(
        miner_node_id=node_id, status__in=ACTIVE_PLACEMENT_STATES
    ).values_list("resource_class", flat=True):
        mem, cpu = _committed_resources(resource_class)
        placements += 1
        memory_mb += mem
        cpus += cpu
    return Committed(placements, memory_mb, cpus)


class Command(BaseCommand):
    help = (
        "Set a miner's capacity policy — hardware anchor, VM ceiling, CPU "
        "overcommit, trust class, earned ceiling, boot cap, cordon — with an audit row per "
        "change; or --show it."
    )

    def add_arguments(self, parser: Any) -> None:
        target = parser.add_mutually_exclusive_group(required=True)
        target.add_argument("--node-id", help="The miner's 64-hex chain node id.")
        target.add_argument(
            "--miner-id",
            help="The MinerIdentity id (e.g. miner-a); resolved via chain_node_id.",
        )
        parser.add_argument("--cpus", type=int, help="Host vCPU count (`nproc`).")
        parser.add_argument(
            "--memory-mb",
            type=int,
            help="Host RAM in MiB (`MemTotal` kB / 1024).",
        )
        parser.add_argument(
            "--clear",
            action="store_true",
            help="Unset both anchors (back to the flat capacity_slots fallback).",
        )
        parser.add_argument(
            "--slots",
            type=int,
            help="Operator VM-count ceiling (capacity_slots).",
        )
        disk = parser.add_mutually_exclusive_group()
        disk.add_argument(
            "--disk-gb",
            type=int,
            help="Size (GiB) of the host's tenant DATA-disk filesystem (`df -BG`).",
        )
        disk.add_argument(
            "--disk-clear",
            action="store_true",
            help="Unset the DATA-disk anchor (the heartbeat terms alone size disk).",
        )
        ratio = parser.add_mutually_exclusive_group()
        ratio.add_argument(
            "--cpu-ratio",
            help="Per-miner vCPU:thread overcommit, 1.0..4.0.",
        )
        ratio.add_argument(
            "--cpu-ratio-default",
            action="store_true",
            help="Drop the per-miner ratio; follow VALI_SCHEDULER_CPU_OVERCOMMIT.",
        )
        parser.add_argument(
            "--trust",
            choices=[c.value for c in CapacityTrustClass],
            help="Trust class: operator (anchored) or earned (proof-based).",
        )
        earned = parser.add_mutually_exclusive_group()
        earned.add_argument(
            "--earned-reset",
            action="store_true",
            help="Reset the earned ceiling and its proof to the floor.",
        )
        earned.add_argument(
            "--earned-grant",
            nargs=3,
            type=int,
            metavar=("VMS", "VCPUS", "MEMORY_MB"),
            help="Set the earned ceiling (vouch for a known-good miner).",
        )
        booting = parser.add_mutually_exclusive_group()
        booting.add_argument(
            "--max-booting",
            type=int,
            help=f"Per-miner concurrent-boot cap, {MIN_MAX_BOOTING}..{MAX_MAX_BOOTING}.",
        )
        booting.add_argument(
            "--max-booting-default",
            action="store_true",
            help="Drop the per-miner cap; follow VALI_SCHEDULER_MAX_BOOTING_PER_MINER.",
        )
        cordon = parser.add_mutually_exclusive_group()
        cordon.add_argument(
            "--cordon",
            action="store_true",
            help="No new placements on this miner (the running VMs are untouched).",
        )
        cordon.add_argument(
            "--uncordon",
            action="store_true",
            help="Lift the cordon.",
        )
        parser.add_argument(
            "--note",
            action="store_true",
            help="Record --reason as an audit note; may be the only action.",
        )
        parser.add_argument(
            "--show",
            action="store_true",
            help="Print the current capacity policy and write nothing.",
        )
        parser.add_argument(
            "--dry-run",
            action="store_true",
            help="Validate and print the change without writing it.",
        )
        parser.add_argument(
            "--by",
            default="",
            help="Operator identity recorded in the audit (required unless --dry-run).",
        )
        parser.add_argument(
            "--reason",
            default="",
            help="Why — recorded on every audit row (required unless --dry-run).",
        )

    def handle(self, *args: Any, **opts: Any) -> None:
        wants_write = self._wants_write(opts)
        if opts["show"]:
            if wants_write or opts["note"]:
                raise CommandError("--show writes nothing; pass it alone")
            self._show(self._resolve_node_id(opts))
            return
        if not wants_write and not opts["note"]:
            raise CommandError(
                "nothing to do — pass an anchor (--cpus/--memory-mb or --clear), "
                "--slots, --disk-gb/--disk-clear, --cpu-ratio(-default), --trust, "
                "--earned-reset, --earned-grant, --max-booting(-default), "
                "--cordon/--uncordon, --note, or --show"
            )

        dry_run: bool = opts["dry_run"]
        by: str = opts["by"].strip()
        reason: str = opts["reason"].strip()
        if not dry_run and not by:
            raise CommandError("--by <operator identity> is required for a real write")
        if not dry_run and not reason:
            raise CommandError("--reason <why> is required for a real write")
        if opts["note"] and not reason:
            raise CommandError("--note records --reason; pass one")
        if opts["cordon"] and not reason:
            raise CommandError("--cordon records --reason as the cordon_reason; pass one")
        anchor = self._desired_anchor(opts)
        static = self._static_changes(opts)
        node_id = self._resolve_node_id(opts)

        with transaction.atomic():
            row = (
                MinerCapacity.objects.select_for_update()
                .filter(miner_node_id=node_id)
                .first()
            )
            if row is None:
                raise CommandError(
                    f"no MinerCapacity row for node {node_id} — it is created by "
                    "the chain refresh once the node is on chain; this command "
                    "does not create it"
                )
            self.stdout.write(f"node   {node_id}")
            changes: dict[str, Any] = dict(static)
            if anchor is not None:
                before = Anchor(row.total_cpus, row.total_memory_mb)
                self.stdout.write(f"before {before.render()}")
                self.stdout.write(f"after  {anchor.render()}")
                if before != anchor:
                    if anchor.total_memory_mb is not None:
                        # Advisory against a concurrent placement landing
                        # between this count and the write: admission
                        # recomputes against the new anchor on every decision
                        # and clamps free at 0.
                        committed = _committed_on(node_id)
                        self._check_committed_load(committed, anchor)
                        self._warn_on_report_mismatch(row, committed, anchor)
                    changes["total_cpus"] = anchor.total_cpus
                    changes["total_memory_mb"] = anchor.total_memory_mb
            if "capacity_slots" in changes:
                self._check_slots(node_id, changes["capacity_slots"])
            if changes.get("total_disk_gb") is not None:
                self._check_disk(node_id, changes["total_disk_gb"])
            if {"trust_class", "total_cpus", "total_memory_mb"} & changes.keys():
                self._check_trust(row, changes)
            if opts["earned_reset"]:
                changes.update(self._earned_reset_changes())
            if opts["cordon"]:
                # Re-cordoning keeps the original instant: the cordon has
                # been in force since then, only its reason is restated.
                changes["cordoned_at"] = row.cordoned_at or timezone.now()
                changes["cordon_reason"] = reason[:256]

            pending = capacity_admin.diff(row, changes)
            if not capacity_admin.audited(pending):
                # Only bookkeeping would move (a repeated reset/grant
                # restamps its timestamp) — that is not a change.
                pending = []
            for c in pending:
                self.stdout.write(
                    f"{c.field}: {capacity_admin.to_json(c.before)} -> "
                    f"{capacity_admin.to_json(c.after)}"
                )
            if not pending and not opts["note"]:
                self.stdout.write("no change (already set to these values)")
                return

            if not dry_run:
                if pending:
                    capacity_admin.apply_capacity_change(
                        row, changes, actor=f"op:{by}", reason=reason
                    )
                if opts["note"]:
                    capacity_admin.record_note(node_id, actor=f"op:{by}", reason=reason)

        audit = json.dumps(
            {
                "event": "miner_capacity_change",
                "by": by,
                "node_id": node_id,
                "miner_id": opts["miner_id"],
                "dry_run": dry_run,
                "reason": reason,
                "note": bool(opts["note"]),
                "changes": [
                    {
                        "field": c.field,
                        "before": capacity_admin.to_json(c.before),
                        "after": capacity_admin.to_json(c.after),
                    }
                    for c in pending
                ],
            },
            sort_keys=True,
        )
        log.info("miner capacity %s: %s", "dry-run" if dry_run else "set", audit)
        if dry_run:
            self.stdout.write("dry run — nothing written")
        else:
            self.stdout.write(self.style.SUCCESS("capacity policy updated"))
        self.stdout.write(audit)

    # ─── argument handling ──────────────────────────────────────────

    @staticmethod
    def _wants_write(opts: dict[str, Any]) -> bool:
        return any(
            (
                opts["cpus"] is not None,
                opts["memory_mb"] is not None,
                opts["clear"],
                opts["slots"] is not None,
                opts["disk_gb"] is not None,
                opts["disk_clear"],
                opts["cpu_ratio"] is not None,
                opts["cpu_ratio_default"],
                opts["trust"] is not None,
                opts["earned_reset"],
                opts["earned_grant"] is not None,
                opts["max_booting"] is not None,
                opts["max_booting_default"],
                opts["cordon"],
                opts["uncordon"],
            )
        )

    def _desired_anchor(self, opts: dict[str, Any]) -> Anchor | None:
        """The anchor this call sets, or `None` when it leaves it alone."""
        cpus: int | None = opts["cpus"]
        memory_mb: int | None = opts["memory_mb"]
        if opts["clear"]:
            if cpus is not None or memory_mb is not None:
                raise CommandError("--clear takes no --cpus / --memory-mb")
            return Anchor(None, None)
        if cpus is None and memory_mb is None:
            return None
        if cpus is None or memory_mb is None:
            raise CommandError("--cpus and --memory-mb are both required (or pass --clear)")
        if not MIN_CPUS <= cpus <= MAX_CPUS:
            raise CommandError(f"--cpus {cpus} out of range [{MIN_CPUS}, {MAX_CPUS}]")
        if not MIN_MEMORY_MB <= memory_mb <= MAX_MEMORY_MB:
            raise CommandError(
                f"--memory-mb {memory_mb} out of range [{MIN_MEMORY_MB}, {MAX_MEMORY_MB}]"
            )
        return Anchor(cpus, memory_mb)

    def _static_changes(self, opts: dict[str, Any]) -> dict[str, Any]:
        """The changes that need no row to validate."""
        out: dict[str, Any] = {}
        slots: int | None = opts["slots"]
        if slots is not None:
            if not MIN_SLOTS <= slots <= MAX_SLOTS:
                raise CommandError(f"--slots {slots} out of range [{MIN_SLOTS}, {MAX_SLOTS}]")
            out["capacity_slots"] = slots
        disk_gb: int | None = opts["disk_gb"]
        if disk_gb is not None:
            if not MIN_DISK_GB <= disk_gb <= MAX_DISK_GB:
                raise CommandError(
                    f"--disk-gb {disk_gb} out of range [{MIN_DISK_GB}, {MAX_DISK_GB}]"
                )
            out["total_disk_gb"] = disk_gb
        if opts["disk_clear"]:
            out["total_disk_gb"] = None
        if opts["cpu_ratio"] is not None:
            try:
                out["cpu_ratio"] = capacity_config.parse_cpu_ratio(opts["cpu_ratio"])
            except ValueError as exc:
                raise CommandError(f"--cpu-ratio {exc}") from exc
        if opts["cpu_ratio_default"]:
            out["cpu_ratio"] = None
        if opts["trust"] is not None:
            out["trust_class"] = opts["trust"]
        max_booting: int | None = opts["max_booting"]
        if max_booting is not None:
            if not MIN_MAX_BOOTING <= max_booting <= MAX_MAX_BOOTING:
                raise CommandError(
                    f"--max-booting {max_booting} out of range "
                    f"[{MIN_MAX_BOOTING}, {MAX_MAX_BOOTING}] (use --cordon for 'none')"
                )
            out["max_booting"] = max_booting
        if opts["max_booting_default"]:
            out["max_booting"] = None
        if opts["uncordon"]:
            out["cordoned_at"] = None
            out["cordon_reason"] = ""
        if opts["earned_grant"] is not None:
            vms, vcpus, memory_mb = opts["earned_grant"]
            caps = (
                ("VMS", vms, capacity_config.earn_hard_cap_vms()),
                ("VCPUS", vcpus, capacity_config.earn_hard_cap_vcpus()),
                ("MEMORY_MB", memory_mb, capacity_config.earn_hard_cap_memory_mb()),
            )
            for name, value, cap in caps:
                if not 1 <= value <= cap:
                    raise CommandError(f"--earned-grant {name} {value} out of range [1, {cap}]")
            out.update(
                earned_vms=vms,
                earned_vcpus=vcpus,
                earned_memory_mb=memory_mb,
                earned_last_reason="op-grant",
                earned_last_change_at=timezone.now(),
            )
        return out

    @staticmethod
    def _earned_reset_changes() -> dict[str, Any]:
        """Back to the floor: `earned_* = NULL` IS the floor (read from
        settings at compute time), and the proof starts over."""
        return {
            "earned_vms": None,
            "earned_vcpus": None,
            "earned_memory_mb": None,
            # The disk ceiling is part of the earned policy: a reset
            # forgives the disk cuts too.
            "earned_disk_gb": None,
            "proven_peak_vms": 0,
            "proven_peak_vcpus": 0,
            "proven_peak_memory_mb": 0,
            "proven_at": None,
            "candidate_vms": 0,
            "candidate_vcpus": 0,
            "candidate_memory_mb": 0,
            "candidate_since": None,
            "earned_last_reason": "op-reset",
            "earned_last_change_at": timezone.now(),
        }

    def _resolve_node_id(self, opts: dict[str, Any]) -> str:
        if opts["node_id"] is not None:
            node_id = opts["node_id"].strip().lower()
            if not _NODE_ID_RE.match(node_id):
                raise CommandError(f"--node-id {opts['node_id']!r} is not 64 lowercase hex")
            return node_id

        from apps.miners.models import MinerIdentity

        miner_id: str = opts["miner_id"]
        identity = MinerIdentity.objects.filter(miner_id=miner_id).first()
        if identity is None:
            raise CommandError(f"no MinerIdentity {miner_id!r}")
        if not identity.chain_node_id:
            raise CommandError(
                f"MinerIdentity {miner_id!r} has no chain_node_id — bridge it first "
                "(POST /v1/admin/miner/register) or pass --node-id"
            )
        return identity.chain_node_id

    # ─── read-only ──────────────────────────────────────────────────

    def _show(self, node_id: str) -> None:
        row = MinerCapacity.objects.filter(miner_node_id=node_id).first()
        if row is None:
            raise CommandError(f"no MinerCapacity row for node {node_id}")
        self.stdout.write(f"node   {node_id}")
        for field in _SHOW_FIELDS:
            self.stdout.write(f"{field:<30} {capacity_admin.to_json(getattr(row, field))}")
        committed = _committed_on(node_id)
        self.stdout.write(
            f"{'committed (vali ledger)':<30} {committed.placements} VMs / "
            f"{committed.cpus} vCPU / {committed.memory_mb} MiB"
        )
        self.stdout.write(
            f"{'global cpu ratio':<30} {capacity_config.cpu_overcommit_default()}"
        )
        from apps.scheduler import capacity_report

        for report in capacity_report.fleet_report(node_ids={node_id}):
            for line in capacity_report.render(report):
                self.stdout.write(line)

    # ─── safety checks ──────────────────────────────────────────────

    def _check_committed_load(self, committed: Committed, target: Anchor) -> None:
        """Refuse an anchor smaller than what vali already placed here; warn
        when it holds the load but not the host reserve on top of it."""
        if committed.placements == 0:
            return
        assert target.total_memory_mb is not None and target.total_cpus is not None
        load = (
            f"the {committed.placements} active placement(s) vali already put on "
            f"this miner commit {committed.memory_mb} MiB / {committed.cpus} vCPU"
        )
        if target.total_memory_mb < committed.memory_mb or target.total_cpus < committed.cpus:
            raise CommandError(f"refusing: the new anchor is smaller than the load — {load}")

        reserve_mb = _host_reserve_memory_mb()
        reserve_cpus = _host_reserve_cpus()
        if (
            target.total_memory_mb - reserve_mb < committed.memory_mb
            or target.total_cpus - reserve_cpus < committed.cpus
        ):
            self.stderr.write(
                self.style.WARNING(
                    f"WARNING: {load}, which leaves less than the host reserve "
                    f"({reserve_mb} MiB / {reserve_cpus} vCPU) — no new placements "
                    "on this miner until load drains"
                )
            )

    @staticmethod
    def _check_slots(node_id: str, slots: int) -> None:
        """A ceiling below the VMs already placed would not evict them — it
        would only make the readout lie about the host being over its
        ceiling. Drain first, then lower it."""
        placed = Placement.objects.filter(
            miner_node_id=node_id, status__in=ACTIVE_PLACEMENT_STATES
        ).count()
        if slots < placed:
            raise CommandError(
                f"refusing: --slots {slots} is below the {placed} VM(s) vali has "
                "already placed on this miner — drain it first"
            )

    @staticmethod
    def _check_disk(node_id: str, disk_gb: int) -> None:
        """An anchor below the disk vali already committed there could not
        be the real filesystem. Drain first, or fix the number."""
        from apps.scheduler.service import _committed_disk_gb

        committed = sum(
            _committed_disk_gb(rc)
            for rc in Placement.objects.filter(
                miner_node_id=node_id, status__in=ACTIVE_PLACEMENT_STATES
            ).values_list("resource_class", flat=True)
        )
        if disk_gb < committed:
            raise CommandError(
                f"refusing: --disk-gb {disk_gb} is below the {committed} GiB of DATA "
                "disk vali has already committed on this miner"
            )

    @staticmethod
    def _check_trust(row: MinerCapacity, changes: dict[str, Any]) -> None:
        """`operator` means the fleet operator knows the hardware; a row
        left without an anchor cannot be in that class."""
        trust = changes.get("trust_class", row.trust_class)
        memory = changes.get("total_memory_mb", row.total_memory_mb)
        cpus = changes.get("total_cpus", row.total_cpus)
        if trust == CapacityTrustClass.OPERATOR and (memory is None or cpus is None):
            raise CommandError(
                "refusing: the operator trust class needs a hardware anchor — pass "
                "--cpus/--memory-mb on the same call, or --trust earned"
            )

    def _warn_on_report_mismatch(
        self, row: MinerCapacity, committed: Committed, target: Anchor
    ) -> None:
        """Cross-check the heartbeat exactly as admission reads it: a report
        older than the liveness timeout is ignored."""
        reported = row.reported_memory_available_mib
        if reported is None or row.reported_at is None:
            return
        assert target.total_memory_mb is not None
        seen = f"(heartbeat at {row.reported_at.isoformat()})"
        stale_cutoff = timezone.now() - timedelta(seconds=miner_liveness_timeout_s())
        if row.reported_at < stale_cutoff:
            self.stdout.write(f"heartbeat report is stale {seen} — not cross-checked")
            return
        if reported > target.total_memory_mb:
            self.stderr.write(
                self.style.WARNING(
                    f"WARNING: the miner reports {reported} MiB AVAILABLE, more than "
                    f"the whole {target.total_memory_mb} MiB anchor "
                    f"{seen} — anchor too small or a unit slip? Admission will flag "
                    "this miner as over-claiming."
                )
            )
        elif reported + committed.memory_mb < target.total_memory_mb * _LOW_REPORT_RATIO:
            self.stderr.write(
                self.style.WARNING(
                    f"WARNING: the miner reports only {reported} MiB available "
                    f"(+ {committed.memory_mb} MiB vali-committed) against a "
                    f"{target.total_memory_mb} MiB anchor {seen} — anchor too large "
                    "or the wrong host?"
                )
            )

