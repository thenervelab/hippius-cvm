"""Tests for the `vali_price_watch` command — the I/O shell that raises
price-migration RECOMMENDATIONS (vSphere-DRS-manual), never auto-migrates.
The chain reads + dest suggestion are mocked; the focus is the watcher's
wiring: a ceiling breach upserts one PENDING recommendation, a gone breach
supersedes it, and it NEVER starts a migration.
"""

from __future__ import annotations

import pytest
from django.core.management import call_command

from apps.scheduler import chain
from apps.scheduler.chain import PendingPriceReport, PriceAnnouncement
from apps.scheduler.management.commands import vali_price_watch as cmd
from apps.scheduler.models import (
    PlacementStatus,
    PriceMigrationRecommendation,
    PriceRecommendationStatus,
)

from .factories import make_placement, make_vm, node_id

pytestmark = pytest.mark.django_db


def _bind(vm_id: str, node: str):
    return make_placement(
        make_vm(vm_id),
        node,
        status=PlacementStatus.BOUND.value,
        vm_family="tenant-1",
    )


def _report(*anns: PriceAnnouncement, block: int = 100) -> PendingPriceReport:
    return PendingPriceReport(current_block=block, announcements=tuple(anns))


def _pending():
    return PriceMigrationRecommendation.objects.filter(
        status=PriceRecommendationStatus.PENDING.value
    )


def _patch_common(monkeypatch, *, ceilings, dest=None):
    """Wire the chain + scheduler seams to fakes. `dest` is the suggested
    destination decide_placement returns (None ⇒ raise PlacementError)."""
    from apps.scheduler.placement import PlacementError

    monkeypatch.setattr(cmd, "_ceiling_by_vm", lambda vm_ids: ceilings)
    monkeypatch.setattr(cmd.chain, "read_miner_status", lambda: object())
    monkeypatch.setattr(cmd.service, "refresh_miner_capacity", lambda snap: None)
    monkeypatch.setattr(cmd.service, "decision_inputs", lambda fam: ({}, {}, frozenset()))
    monkeypatch.setattr(cmd.service, "max_epoch_lag", lambda: 2)
    monkeypatch.setattr(cmd.service, "max_host_share", lambda: 1.0)
    monkeypatch.setattr(cmd.service, "price_by_node", lambda snap: {})

    def fake_decide(**kw):
        if dest is None:
            raise PlacementError("no dest", "no-eligible-miner")
        return dest

    monkeypatch.setattr(cmd, "decide_placement", fake_decide)


def _no_migration(monkeypatch) -> list:
    """Assert the watcher NEVER calls start_migration — spy on it."""
    from apps.orchestration import service as orch

    calls: list = []
    monkeypatch.setattr(
        orch,
        "start_migration",
        lambda **kw: (
            calls.append(kw)
            or (_ for _ in ()).throw(AssertionError("price-watch must not start a migration"))
        ),
    )
    return calls


def test_breach_raises_a_pending_recommendation_not_a_migration(monkeypatch) -> None:
    _bind("vm-a", node_id(1))
    _patch_common(monkeypatch, ceilings={"vm-a": 100}, dest=node_id(9))
    _no_migration(monkeypatch)
    monkeypatch.setattr(
        cmd.chain,
        "read_pending_price_changes",
        lambda: _report(PriceAnnouncement(node_id(1), 500, 150)),
    )

    call_command("vali_price_watch", once=True)

    rec = _pending().get()
    assert rec.vm.vm_id == "vm-a"
    assert rec.current_node_id == node_id(1)
    assert rec.suggested_dest_node_id == node_id(9)
    assert rec.new_price == 500
    assert rec.ceiling == 100
    assert rec.effective_block == 150


def test_no_destination_still_raises_recommendation_with_empty_dest(monkeypatch) -> None:
    _bind("vm-a", node_id(1))
    _patch_common(monkeypatch, ceilings={"vm-a": 100}, dest=None)  # PlacementError
    _no_migration(monkeypatch)
    monkeypatch.setattr(
        cmd.chain,
        "read_pending_price_changes",
        lambda: _report(PriceAnnouncement(node_id(1), 500, 150)),
    )

    call_command("vali_price_watch", once=True)

    rec = _pending().get()
    assert rec.suggested_dest_node_id == ""


def test_dry_run_writes_nothing(monkeypatch) -> None:
    _bind("vm-a", node_id(1))
    _patch_common(monkeypatch, ceilings={"vm-a": 100}, dest=node_id(9))
    _no_migration(monkeypatch)
    monkeypatch.setattr(
        cmd.chain,
        "read_pending_price_changes",
        lambda: _report(PriceAnnouncement(node_id(1), 500, 150)),
    )

    call_command("vali_price_watch", once=True, dry_run=True)

    assert _pending().count() == 0


def test_no_ceiling_means_no_recommendation(monkeypatch) -> None:
    _bind("vm-a", node_id(1))
    _patch_common(monkeypatch, ceilings={}, dest=node_id(9))
    _no_migration(monkeypatch)
    monkeypatch.setattr(
        cmd.chain,
        "read_pending_price_changes",
        lambda: _report(PriceAnnouncement(node_id(1), 500, 150)),
    )

    call_command("vali_price_watch", once=True)
    assert _pending().count() == 0


def test_idempotent_no_duplicate_no_version_churn(monkeypatch) -> None:
    _bind("vm-a", node_id(1))
    _patch_common(monkeypatch, ceilings={"vm-a": 100}, dest=node_id(9))
    _no_migration(monkeypatch)
    monkeypatch.setattr(
        cmd.chain,
        "read_pending_price_changes",
        lambda: _report(PriceAnnouncement(node_id(1), 500, 150)),
    )

    call_command("vali_price_watch", once=True)
    v1 = _pending().get().version
    call_command("vali_price_watch", once=True)  # same intent again
    assert _pending().count() == 1
    assert _pending().get().version == v1  # unchanged → no churn


def test_breach_gone_supersedes_the_pending_recommendation(monkeypatch) -> None:
    _bind("vm-a", node_id(1))
    _patch_common(monkeypatch, ceilings={"vm-a": 100}, dest=node_id(9))
    _no_migration(monkeypatch)
    monkeypatch.setattr(
        cmd.chain,
        "read_pending_price_changes",
        lambda: _report(PriceAnnouncement(node_id(1), 500, 150)),
    )
    call_command("vali_price_watch", once=True)
    assert _pending().count() == 1

    # Next cycle: the announcement is gone (withdrawn / applied).
    monkeypatch.setattr(cmd.chain, "read_pending_price_changes", lambda: _report())
    call_command("vali_price_watch", once=True)

    assert _pending().count() == 0
    rec = PriceMigrationRecommendation.objects.get(vm__vm_id="vm-a")
    assert rec.status == PriceRecommendationStatus.SUPERSEDED.value
    assert rec.decided_at is not None


def test_chain_unavailable_is_swallowed(monkeypatch) -> None:
    _bind("vm-a", node_id(1))
    _patch_common(monkeypatch, ceilings={"vm-a": 100}, dest=node_id(9))

    def boom():
        raise chain.ChainReadUnavailable("reader not built")

    monkeypatch.setattr(cmd.chain, "read_pending_price_changes", boom)

    call_command("vali_price_watch", once=True)  # must not raise
    assert _pending().count() == 0


# ─── Real ceiling source: Vm.max_price_per_unit ──────────────────────


def test_ceiling_by_vm_reads_vm_rows() -> None:
    from apps.lifecycle.models import Vm

    a = make_vm("vm-a")
    Vm.objects.filter(pk=a.pk).update(max_price_per_unit=100)
    make_vm("vm-b")  # no ceiling ⇒ omitted
    c = make_vm("vm-c")
    Vm.objects.filter(pk=c.pk).update(max_price_per_unit=250)

    assert cmd._ceiling_by_vm(["vm-a", "vm-b", "vm-c"]) == {"vm-a": 100, "vm-c": 250}


def test_end_to_end_recommends_on_real_vm_ceiling(monkeypatch) -> None:
    from apps.lifecycle.models import Vm

    p = _bind("vm-a", node_id(1))
    Vm.objects.filter(pk=p.vm.pk).update(max_price_per_unit=100)

    # NOTE: _ceiling_by_vm is NOT patched — it reads the real Vm row.
    monkeypatch.setattr(cmd.chain, "read_miner_status", lambda: object())
    monkeypatch.setattr(cmd.service, "refresh_miner_capacity", lambda snap: None)
    monkeypatch.setattr(cmd.service, "decision_inputs", lambda fam: ({}, {}, frozenset()))
    monkeypatch.setattr(cmd.service, "max_epoch_lag", lambda: 2)
    monkeypatch.setattr(cmd.service, "max_host_share", lambda: 1.0)
    monkeypatch.setattr(cmd.service, "price_by_node", lambda snap: {})
    monkeypatch.setattr(cmd, "decide_placement", lambda **kw: node_id(9))
    _no_migration(monkeypatch)
    monkeypatch.setattr(
        cmd.chain,
        "read_pending_price_changes",
        lambda: _report(PriceAnnouncement(node_id(1), 500, 150)),
    )

    call_command("vali_price_watch", once=True)

    rec = _pending().get()
    assert rec.vm.vm_id == "vm-a"
    assert rec.ceiling == 100
    assert rec.new_price == 500
