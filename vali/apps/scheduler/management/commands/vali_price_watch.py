"""`vali_price_watch` — raise migration RECOMMENDATIONS on price hikes.

Each cycle reads the on-chain `PendingPriceChange` announcements, and for
every bound VM whose tenant agreed to a price ceiling the new price would
exceed, raises a **recommendation** (`PriceMigrationRecommendation`) that
an operator/tenant can `approve` (→ a §25 migration is started) or
`dismiss` (the tenant accepts the new price).

This is vSphere-DRS-**manual** behaviour, on purpose: migrating a VM is a
stop+restart (customer downtime), so a price change must NOT silently
churn VMs. The watcher only *recommends*; the migration is a deliberate
action. Genuine miner-departure migration (§13 drain / §25 graceful-exit)
is a SEPARATE, still-automatic path and is untouched by this worker.

The decision of WHICH VMs are over-ceiling is the pure
`migration_policy.vms_to_migrate`; this command is the I/O shell: read
chain → gather DB → decide → upsert recommendations → supersede stale
ones, best-effort and fail-closed (a chain-read failure skips the cycle,
never mis-recommends).
"""

from __future__ import annotations

import logging
import signal
import time
import uuid
from typing import Any

from django.conf import settings
from django.core.management.base import BaseCommand
from django.db import IntegrityError, transaction
from django.utils import timezone

from apps.scheduler import chain, service
from apps.scheduler.migration_policy import BoundVm, MigrationIntent, vms_to_migrate
from apps.scheduler.models import (
    Placement,
    PlacementStatus,
    PriceMigrationRecommendation,
    PriceRecommendationStatus,
)
from apps.scheduler.placement import (
    PlacementError,
    SelectionWeights,
    decide_placement,
)

log = logging.getLogger("apps.scheduler.price_watch")


def _ceiling_by_vm(vm_ids: list[str]) -> dict[str, int]:
    """`{vm_id: max price per unit}` the tenant agreed to.

    Reads the per-VM ceiling set at launch (`Vm.max_price_per_unit`, a
    vali-side policy field). A VM with no ceiling (`NULL`) is omitted ⇒
    never recommended for price-migration (the tenant accepts any price).
    """
    from apps.lifecycle.models import Vm

    rows = Vm.objects.filter(
        vm_id__in=vm_ids, max_price_per_unit__isnull=False
    ).values_list("vm_id", "max_price_per_unit")
    return {vm_id: ceiling for vm_id, ceiling in rows}


def _new_recommendation_id() -> str:
    return f"rec-{uuid.uuid4().hex}"


class Command(BaseCommand):
    help = (
        "Watch on-chain price announcements and RECOMMEND (not auto-migrate) "
        "moving VMs whose tenant ceiling the new price would exceed."
    )

    def add_arguments(self, parser: Any) -> None:
        parser.add_argument(
            "--once",
            action="store_true",
            help="Run a single watch cycle and exit.",
        )
        parser.add_argument(
            "--dry-run",
            action="store_true",
            help="Log the recommendations but do NOT write them.",
        )

    def handle(self, *args: Any, **options: Any) -> None:
        once: bool = options["once"]
        dry_run: bool = options["dry_run"]
        interval = float(getattr(settings, "VALI_PRICE_WATCH_INTERVAL_S", 60.0))

        self._running = True

        def _stop(signum: int, _frame: Any) -> None:
            self._running = False
            log.info("vali_price_watch received signal %s — stopping", signum)

        signal.signal(signal.SIGTERM, _stop)
        signal.signal(signal.SIGINT, _stop)

        log.info(
            "vali_price_watch started (interval=%.1fs once=%s dry_run=%s)",
            interval,
            once,
            dry_run,
        )
        while self._running:
            try:
                self._run_once(dry_run=dry_run)
            except chain.ChainReadUnavailable as exc:
                # Best-effort: a chain-read failure skips the cycle.
                log.warning("price-watch skipped — chain unavailable: %s", exc)
            except Exception:  # noqa: BLE001 — daemon loop must survive.
                log.exception("price-watch cycle raised — continuing")

            if once:
                break
            self._sleep(interval)

        log.info("vali_price_watch stopped")

    def _run_once(self, *, dry_run: bool) -> None:
        report = chain.read_pending_price_changes()
        announced = {a.node_id for a in report.announcements}

        rows = (
            list(
                Placement.objects.filter(
                    status=PlacementStatus.BOUND.value,
                    miner_node_id__in=announced,
                ).select_related("vm")
            )
            if announced
            else []
        )
        bound = [BoundVm(vm_id=p.vm.vm_id, node_id=p.miner_node_id) for p in rows]
        family_by_vm = {p.vm.vm_id: p.vm_family for p in rows}
        # RA-M3 — the owner of each bound VM, so the dest suggestion honours
        # the per-owner spread (same as the real migration path).
        owner_by_vm = {p.vm.vm_id: p.owner for p in rows}
        ceilings = _ceiling_by_vm([b.vm_id for b in bound])

        lead = int(getattr(settings, "VALI_PRICE_WATCH_LEAD_BLOCKS", 1_000_000))
        intents = vms_to_migrate(
            announcements=report.announcements,
            bound=bound,
            ceiling_by_vm=ceilings,
            current_block=report.current_block,
            lead_blocks=lead,
        )
        over_ceiling = {i.vm_id for i in intents}

        if dry_run:
            for i in intents:
                log.info(
                    "would recommend migrating vm=%s off %s (new_price=%d > "
                    "ceiling=%d, effective@%d)",
                    i.vm_id,
                    i.node_id,
                    i.new_price,
                    i.ceiling,
                    i.effective_block,
                )
            stale = self._stale_pending(keep_vm_ids=over_ceiling)
            for rec_id, vm_id in stale:
                log.info(
                    "would supersede stale recommendation %s (vm=%s)", rec_id, vm_id
                )
            return

        # One chain read for dest suggestion across all intents this cycle.
        snapshot = None
        if intents:
            snapshot = chain.read_miner_status()
            service.refresh_miner_capacity(snapshot)
        raised = 0
        for intent in intents:
            dest = self._suggest_dest(
                intent,
                snapshot=snapshot,
                family=family_by_vm[intent.vm_id],
                owner=owner_by_vm.get(intent.vm_id, ""),
            )
            if self._upsert_recommendation(intent, suggested_dest=dest):
                raised += 1

        superseded = self._supersede_stale(keep_vm_ids=over_ceiling)
        if raised or superseded:
            log.info(
                "price-watch: %d recommendation(s) raised/updated, %d superseded",
                raised,
                superseded,
            )

    def _suggest_dest(
        self, intent: MigrationIntent, *, snapshot: Any, family: str, owner: str = ""
    ) -> str:
        """Best within-budget destination off the repricing miner, or `""`
        if the watcher cannot find one (the alert still surfaces — the
        operator can act once capacity frees up)."""
        if snapshot is None:
            return ""
        cap, load, fam = service.decision_inputs(family)
        try:
            return decide_placement(
                snapshot=snapshot,
                capacity_by_node=cap,
                load_by_node=load,
                family_load_by_node=fam,
                max_epoch_lag=service.max_epoch_lag(),
                excluded=frozenset({intent.node_id}),
                weights=SelectionWeights.from_settings(),
                max_host_share=service.max_host_share(),
                # Price-aware suggestion: don't point at an equally-pricey miner.
                price_by_node=service.price_by_node(snapshot),
                # RA-M3 — suggest a dest that also honours the per-owner
                # spread + circuit-breaker, matching the real migration path.
                recent_failures_by_node=service.recent_failures_by_node(),
                max_recent_failures=service.max_recent_failures(),
                owner_load_by_node=service.owner_load_by_node(owner),
                max_owner_placements_per_miner=(
                    service.max_owner_placements_per_miner()
                ),
                # Gate (e) — never RECOMMEND a destination vali has
                # observed fail to start a confidential guest; the
                # operator would act on it and strand the VM.
                cvm_capability_by_node=service.cvm_capability_by_node(),
            )
        except PlacementError as exc:
            log.info(
                "price-watch: no destination for vm %s yet: %s", intent.vm_id, exc
            )
            return ""

    def _upsert_recommendation(
        self, intent: MigrationIntent, *, suggested_dest: str
    ) -> bool:
        """Create or refresh the single PENDING recommendation for this VM.

        Idempotent: an existing PENDING row is updated only when a field
        actually changed (so `updated_at` does not churn every cycle).
        Returns True when a row was created or changed.
        """
        from apps.lifecycle.models import Vm

        vm = Vm.objects.filter(vm_id=intent.vm_id).first()
        if vm is None:
            log.warning("price-watch: vm %s vanished — skipping", intent.vm_id)
            return False

        existing = PriceMigrationRecommendation.objects.filter(
            vm=vm, status=PriceRecommendationStatus.PENDING.value
        ).first()
        if existing is not None:
            unchanged = (
                existing.current_node_id == intent.node_id
                and existing.new_price == intent.new_price
                and existing.ceiling == intent.ceiling
                and existing.effective_block == intent.effective_block
                and existing.suggested_dest_node_id == suggested_dest
            )
            if unchanged:
                return False
            PriceMigrationRecommendation.objects.filter(
                id=existing.id, version=existing.version
            ).update(
                current_node_id=intent.node_id,
                suggested_dest_node_id=suggested_dest,
                new_price=intent.new_price,
                ceiling=intent.ceiling,
                effective_block=intent.effective_block,
                version=existing.version + 1,
            )
            return True

        try:
            PriceMigrationRecommendation.objects.create(
                recommendation_id=_new_recommendation_id(),
                vm=vm,
                current_node_id=intent.node_id,
                suggested_dest_node_id=suggested_dest,
                new_price=intent.new_price,
                ceiling=intent.ceiling,
                effective_block=intent.effective_block,
                status=PriceRecommendationStatus.PENDING.value,
            )
        except IntegrityError:
            # A concurrent cycle raised it between the SELECT and INSERT —
            # the partial-unique (one Pending per VM) caught it. Fine.
            return False
        log.info(
            "price-watch: recommend migrating vm=%s off %s (new_price=%d > "
            "ceiling=%d, effective@%d) → suggested %s",
            intent.vm_id,
            intent.node_id,
            intent.new_price,
            intent.ceiling,
            intent.effective_block,
            suggested_dest or "(none yet)",
        )
        return True

    def _stale_pending(self, *, keep_vm_ids: set[str]) -> list[tuple[str, str]]:
        """`(recommendation_id, vm_id)` of PENDING recs whose breach is gone
        (the VM is not over-ceiling this cycle). Read-only (for dry-run)."""
        return [
            (r.recommendation_id, r.vm.vm_id)
            for r in PriceMigrationRecommendation.objects.filter(
                status=PriceRecommendationStatus.PENDING.value
            )
            .select_related("vm")
            .exclude(vm__vm_id__in=keep_vm_ids)
        ]

    def _supersede_stale(self, *, keep_vm_ids: set[str]) -> int:
        """Mark PENDING recs whose breach is gone as SUPERSEDED. Returns the
        count superseded. The announcement was withdrawn / applied / fell
        back within budget, so the alert no longer applies."""
        stale = (
            PriceMigrationRecommendation.objects.filter(
                status=PriceRecommendationStatus.PENDING.value
            )
            .select_related("vm")
            .exclude(vm__vm_id__in=keep_vm_ids)
        )
        count = 0
        for rec in stale:
            with transaction.atomic():
                updated = PriceMigrationRecommendation.objects.filter(
                    id=rec.id,
                    version=rec.version,
                    status=PriceRecommendationStatus.PENDING.value,
                ).update(
                    status=PriceRecommendationStatus.SUPERSEDED.value,
                    version=rec.version + 1,
                    decided_at=timezone.now(),
                )
            if updated:
                count += 1
                log.info(
                    "price-watch: superseded recommendation %s (vm=%s — breach "
                    "gone)",
                    rec.recommendation_id,
                    rec.vm.vm_id,
                )
        return count

    def _sleep(self, interval: float) -> None:
        slept = 0.0
        while self._running and slept < interval:
            step = min(0.5, interval - slept)
            time.sleep(step)
            slept += step
