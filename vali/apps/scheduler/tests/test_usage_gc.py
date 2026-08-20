"""Tests for the UsageAccrual garbage-collector (audit M-GC)."""

from __future__ import annotations

import pytest

from apps.scheduler.management.commands.vali_usage_gc import gc_usage_accruals
from apps.scheduler.models import UsageAccrual

from .factories import node_id

pytestmark = pytest.mark.django_db


def _accrue(epoch: int, vm_id: str) -> None:
    UsageAccrual.objects.create(
        epoch=epoch,
        miner_node_id=node_id(1),
        vm_id=vm_id,
        resource_class="small",
        unit_seconds=10,
        billable_seconds=10,
    )


def test_gc_keeps_the_last_k_epochs_and_reaps_older() -> None:
    # Epochs 1..10; keep_epochs=3 ⇒ keep {8,9,10}, reap {1..7}.
    for e in range(1, 11):
        _accrue(e, f"vm-{e}")
    deleted = gc_usage_accruals(keep_epochs=3)
    assert deleted == 7
    remaining = set(UsageAccrual.objects.values_list("epoch", flat=True))
    assert remaining == {8, 9, 10}


def test_gc_always_retains_the_latest_epoch_even_with_keep_one() -> None:
    _accrue(5, "vm-a")
    _accrue(6, "vm-b")
    # keep_epochs is clamped to ≥1 so the latest (6) survives.
    assert gc_usage_accruals(keep_epochs=1) == 1
    assert set(UsageAccrual.objects.values_list("epoch", flat=True)) == {6}
    # A zero/negative keep is clamped, not a wipe.
    _accrue(7, "vm-c")
    assert gc_usage_accruals(keep_epochs=0) == 1  # reaps 6, keeps latest 7
    assert set(UsageAccrual.objects.values_list("epoch", flat=True)) == {7}


def test_gc_empty_ledger_is_a_noop() -> None:
    assert gc_usage_accruals(keep_epochs=8) == 0
