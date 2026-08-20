"""Uptime-integrated epoch weights + the owed-per-miner readout
(`scoring._usage_weights` / `compute_owed_micro_usd` + `EpochWeightsView`).
"""

from __future__ import annotations

import pytest
from django.test import override_settings
from django.urls import reverse
from django.utils import timezone
from rest_framework import status
from rest_framework.test import APIClient

from apps.scheduler import scoring
from apps.scheduler.models import MinerCapacity, PlacementStatus, UsageAccrual

from .factories import make_placement, make_vm, node_id, observe_chain_epoch

pytestmark = pytest.mark.django_db

URL = reverse("epoch_weights")


def _accrue(node: str, vm_id: str, *, epoch: int, unit_seconds: int) -> None:
    UsageAccrual.objects.create(
        epoch=epoch,
        miner_node_id=node,
        vm_id=vm_id,
        resource_class="small",
        unit_seconds=unit_seconds,
        billable_seconds=unit_seconds,
    )


def test_latest_usage_epoch_is_the_newest_bucket() -> None:
    assert scoring.latest_usage_epoch() is None
    _accrue(node_id(1), "vm-a", epoch=4, unit_seconds=10)
    _accrue(node_id(1), "vm-b", epoch=7, unit_seconds=10)
    assert scoring.latest_usage_epoch() == 7


@override_settings(VALI_EPOCH_WEIGHT_SOURCE="usage")
def test_usage_mode_sums_unit_seconds_of_the_current_epoch() -> None:
    # miner1 hosts two VMs this epoch; miner2 one. An older-epoch row is
    # excluded — only the CHAIN's current epoch feeds the weight.
    observe_chain_epoch(9)
    _accrue(node_id(1), "vm-a", epoch=9, unit_seconds=300)
    _accrue(node_id(1), "vm-b", epoch=9, unit_seconds=120)
    _accrue(node_id(2), "vm-c", epoch=9, unit_seconds=60)
    _accrue(node_id(1), "vm-old", epoch=8, unit_seconds=99999)

    weights = scoring.compute_epoch_weights()
    assert weights == {node_id(1): 420, node_id(2): 60}


@override_settings(VALI_EPOCH_WEIGHT_SOURCE="snapshot")
def test_snapshot_mode_ignores_the_usage_ledger() -> None:
    # Default source is the bound-placement snapshot — usage rows do NOT
    # feed it (guards the safe-rollout gate).
    make_placement(
        make_vm("vm-a"),
        node_id(1),
        status=PlacementStatus.BOUND.value,
        resource_class="small",
    )
    _accrue(node_id(2), "vm-c", epoch=9, unit_seconds=60)
    weights = scoring.compute_epoch_weights()
    assert weights == {node_id(1): 1590}  # small; the usage row is ignored


def test_owed_is_unit_seconds_times_price_over_period_and_scale() -> None:
    """CLAIM: the bill divides the RANKING scale back out.

    `unit_seconds` carries `VALI_SCORING_SCALE` (1000) because
    `resource_units` scales its blend to keep the on-chain u128 integral.
    Pricing must not treat that scaled number as real units — doing so
    overbilled by exactly 1000x live.
    """
    observe_chain_epoch(9)
    # 7200 SCALED unit-seconds = 7.2 real unit-seconds = 0.002 unit-hours
    _accrue(node_id(1), "vm-a", epoch=9, unit_seconds=7_200_000)  # 2 real unit-hours
    _accrue(node_id(2), "vm-c", epoch=9, unit_seconds=3_600_000)  # 1 real unit-hour
    # price = 1_000_000 micro-USD / REAL unit / hour; period 3600s, scale 1000.
    prices = {node_id(1): 1_000_000, node_id(2): 500_000}
    owed = scoring.compute_owed_micro_usd(prices)
    # miner1: 7.2e6 * 1e6 / (3600*1000) = 2_000_000 ; miner2: 3.6e6*5e5/3.6e6 = 500_000
    assert owed == {node_id(1): 2_000_000, node_id(2): 500_000}


def test_owed_no_longer_overbills_by_the_scale_factor() -> None:
    """CLAIM: reproduces the live overbill and pins the corrected figure.

    A `small` VM is 1590 SCALED units (1.59 real). One hour at a 5e6
    micro-USD per-real-unit-hour price is ~7.95 USD, not ~7,950 — the
    three-orders-of-magnitude error seen on the live testnet.
    """
    observe_chain_epoch(9)
    _accrue(node_id(1), "vm-small", epoch=9, unit_seconds=1590 * 3600)
    owed = scoring.compute_owed_micro_usd({node_id(1): 5_000_000})
    usd = owed[node_id(1)] / 1_000_000
    assert 7.9 < usd < 8.0, f"expected ~7.95 USD for one small-VM-hour, got {usd}"


def test_the_reward_weight_keeps_the_scale() -> None:
    """CLAIM: only the BILL is unscaled; the on-chain weight is not.

    The chain wants the scaled integer — that is why the scale exists.
    A fix that unscaled the weight too would silently change every
    miner's reward share.
    """
    observe_chain_epoch(9)
    _accrue(node_id(1), "vm-a", epoch=9, unit_seconds=1590 * 3600)
    with override_settings(VALI_EPOCH_WEIGHT_SOURCE="usage"):
        assert scoring.compute_epoch_weights() == {node_id(1): 1590 * 3600}


def test_owed_omits_unpriced_miner() -> None:
    _accrue(node_id(1), "vm-a", epoch=9, unit_seconds=3_600_000)
    owed = scoring.compute_owed_micro_usd({})  # nobody priced
    assert owed == {}


def test_owed_empty_when_no_usage() -> None:
    assert scoring.compute_owed_micro_usd({node_id(1): 1_000_000}) == {}


def test_view_omits_owed_when_no_usage(authed_client: APIClient) -> None:
    # No usage rows ⇒ response is the unchanged reward-weight shape, no
    # chain read attempted.
    resp = authed_client.get(URL)
    assert resp.status_code == status.HTTP_200_OK
    assert "owed_usd_micros" not in resp.json()


@override_settings(VALI_EPOCH_WEIGHT_SOURCE="usage")
def test_view_surfaces_owed_when_usage_exists(monkeypatch, authed_client) -> None:
    observe_chain_epoch(9)
    _accrue(node_id(1), "vm-a", epoch=9, unit_seconds=3_600_000)

    # Mock the chain price read the owed path performs.
    from apps.scheduler import chain, views

    # A REAL ChainSnapshot, not a bare stub — a hand-rolled double drifts
    # silently the moment the dataclass gains a field.
    snap = chain.ChainSnapshot(current_epoch=9, miners=())
    monkeypatch.setattr(views.chain, "read_miner_status", lambda: snap)
    monkeypatch.setattr(views.service, "price_by_node", lambda snap: {node_id(1): 1_000_000})

    resp = authed_client.get(URL)
    assert resp.status_code == status.HTTP_200_OK
    body = resp.json()
    assert body["usage_epoch"] == 9
    assert body["owed_usd_micros"] == {node_id(1): 1_000_000}
    assert body["owed_total_usd_micros"] == 1_000_000
    # usage-mode weight = the SCALED unit_seconds, verbatim — the bill is
    # unscaled, the on-chain weight is not.
    assert body["weights"] == {node_id(1): 3_600_000}
    # The removed-pallet signal rides along on the read that already
    # happened — an operator looking at the bill sees whether the chain
    # data behind it is live or a frozen orphaned-prefix fossil.
    assert body["pallet_live"] is True


@override_settings(VALI_EPOCH_WEIGHT_SOURCE="usage")
def test_view_surfaces_a_dead_pallet_alongside_the_bill(monkeypatch, authed_client) -> None:
    """CLAIM: `pallet_live` is CARRIED from the chain read, not hardcoded."""
    observe_chain_epoch(9)
    _accrue(node_id(1), "vm-a", epoch=9, unit_seconds=3600)
    from apps.scheduler import chain, views

    snap = chain.ChainSnapshot(current_epoch=2702, miners=(), pallet_live=False)
    monkeypatch.setattr(views.chain, "read_miner_status", lambda: snap)
    monkeypatch.setattr(views.service, "price_by_node", lambda snap: {})

    assert authed_client.get(URL).json()["pallet_live"] is False


@override_settings(VALI_EPOCH_WEIGHT_SOURCE="usage")
def test_anonymous_epoch_weights_never_triggers_a_chain_read(monkeypatch, client) -> None:
    """CLAIM: the unauthenticated weights path stays chain-read-FREE.

    An anonymous caller must not be able to make vali issue an outbound
    RPC (nor learn `pallet_live`, which only rides the authenticated
    read). Pins the placement of the new field inside the authed block.
    """
    observe_chain_epoch(9)
    _accrue(node_id(1), "vm-a", epoch=9, unit_seconds=3600)
    from apps.scheduler import views

    def forbidden():
        raise AssertionError("anonymous caller forced an outbound chain read")

    monkeypatch.setattr(views.chain, "read_miner_status", forbidden)

    resp = client.get(URL)
    assert resp.status_code == status.HTTP_200_OK
    assert "pallet_live" not in resp.json()


@override_settings(VALI_EPOCH_WEIGHT_SOURCE="usage")
def test_view_owed_none_when_chain_unavailable(monkeypatch, authed_client) -> None:
    observe_chain_epoch(9)
    _accrue(node_id(1), "vm-a", epoch=9, unit_seconds=3600)
    from apps.scheduler import chain, views

    def boom():
        raise chain.ChainReadUnavailable("rpc down")

    monkeypatch.setattr(views.chain, "read_miner_status", boom)
    resp = authed_client.get(URL)
    assert resp.status_code == status.HTTP_200_OK
    assert resp.json()["owed_usd_micros"] is None


# ─── the priced bill must never be served anonymously ────────────────────
#
# The class docstring's "unauthenticated by design" rationale covers the
# WEIGHTS (on-chain-derivable). It silently stopped covering the whole
# response when `owed_*` was added: that is vali-internal revenue data. A
# pre-beta red team read it unauthenticated from a cluster node. These pin
# the split.


@override_settings(VALI_EPOCH_WEIGHT_SOURCE="usage")
def test_anonymous_gets_weights_but_never_the_priced_bill(monkeypatch, client) -> None:
    """CLAIM: an unauthenticated caller still gets everything the
    epoch-close worker needs, and NONE of the financial fields."""
    observe_chain_epoch(9)
    _accrue(node_id(1), "vm-a", epoch=9, unit_seconds=3600)
    from apps.scheduler import chain, views

    # A REAL ChainSnapshot, not a bare stub — a hand-rolled double drifts
    # silently the moment the dataclass gains a field.
    snap = chain.ChainSnapshot(current_epoch=9, miners=())
    monkeypatch.setattr(views.chain, "read_miner_status", lambda: snap)
    monkeypatch.setattr(views.service, "price_by_node", lambda snap: {node_id(1): 1_000_000})

    resp = client.get(URL)
    assert resp.status_code == status.HTTP_200_OK
    body = resp.json()
    # the epoch-close worker's contract is intact
    assert body["weights"] == {node_id(1): 3600}
    assert "total_weight" in body and "miners" in body
    # …and not one byte of revenue data
    for leaked in ("owed_usd_micros", "owed_total_usd_micros"):
        assert leaked not in body, f"{leaked} served ANONYMOUSLY"


@override_settings(VALI_EPOCH_WEIGHT_SOURCE="usage")
def test_an_authenticated_caller_still_gets_the_bill(monkeypatch, authed_client) -> None:
    """CLAIM: gating the bill did not delete it.

    Without this, a mutation dropping `owed_*` unconditionally would pass
    the anonymous test above and silently remove the feature.
    """
    observe_chain_epoch(9)
    _accrue(node_id(1), "vm-a", epoch=9, unit_seconds=3_600_000)
    from apps.scheduler import chain, views

    # A REAL ChainSnapshot, not a bare stub — a hand-rolled double drifts
    # silently the moment the dataclass gains a field.
    snap = chain.ChainSnapshot(current_epoch=9, miners=())
    monkeypatch.setattr(views.chain, "read_miner_status", lambda: snap)
    monkeypatch.setattr(views.service, "price_by_node", lambda snap: {node_id(1): 1_000_000})

    body = authed_client.get(URL).json()
    assert body["owed_usd_micros"] == {node_id(1): 1_000_000}


# ─── the epoch SELECTOR: chain position, not newest ledger bucket ────────
#
# `_usage_weights` used to key off `latest_usage_epoch()` = max(epoch) in
# the ledger. That is a property of the LEDGER, not of the chain: when
# accrual stalls the ledger stops rolling over while the chain epoch keeps
# advancing, so the same bucket is handed to every subsequent close and
# PAID AGAIN each time. These pin the fix.


@override_settings(VALI_EPOCH_WEIGHT_SOURCE="usage")
def test_a_stalled_ledger_is_not_re_paid_at_every_new_chain_epoch() -> None:
    """CLAIM: one bucket of proven uptime is rewarded ONCE.

    Replays the production incident of 2026-08-03: the ledger held a
    single row for epoch 2696 (100170 unit_seconds) and no receipts
    arrived after it, while the closer advanced the chain 2700 → 2701 →
    2702. Under the old max(epoch) selector every one of those closes was
    handed the SAME 100170 — one bucket paid three times. Now each close
    reads its OWN epoch's bucket, finds it empty, and submits nothing.
    """
    _accrue(node_id(1), "vm-stalled", epoch=2696, unit_seconds=100_170)

    for chain_epoch in (2700, 2701, 2702):
        observe_chain_epoch(chain_epoch)
        assert scoring.compute_epoch_weights() == {}, (
            f"epoch {chain_epoch} re-paid the frozen 2696 bucket"
        )

    # …and the bucket is still rewarded for the epoch it BELONGS to.
    observe_chain_epoch(2696)
    assert scoring.compute_epoch_weights() == {node_id(1): 100_170}


@override_settings(VALI_EPOCH_WEIGHT_SOURCE="usage")
def test_a_newer_ledger_bucket_does_not_override_the_chain_epoch() -> None:
    """CLAIM: the CHAIN decides which bucket is being closed.

    Directional: with rows in two epochs, the weight follows the chain's
    position, never the newest row. Kills a mutant that reads max(epoch)
    whenever it is greater.
    """
    _accrue(node_id(1), "vm-a", epoch=9, unit_seconds=300)
    _accrue(node_id(2), "vm-b", epoch=10, unit_seconds=999)

    observe_chain_epoch(9)
    assert scoring.compute_epoch_weights() == {node_id(1): 300}


@override_settings(VALI_EPOCH_WEIGHT_SOURCE="usage")
def test_a_cold_chain_cache_pays_nobody() -> None:
    """CLAIM: unknown chain position ⇒ fail CLOSED.

    With no `MinerCapacity` row vali does not know which epoch is open.
    Emitting weights from an unknown position risks re-paying a closed
    epoch, so it emits none — even though the ledger is non-empty.
    """
    _accrue(node_id(1), "vm-a", epoch=9, unit_seconds=300)
    assert scoring.billing_epoch() is None
    assert scoring.compute_epoch_weights() == {}


def test_the_bill_uses_the_same_epoch_selector_as_the_reward() -> None:
    """CLAIM: a bill and a reward never disagree about WHICH epoch.

    A stale ledger bucket must not keep billing the operator either.
    """
    _accrue(node_id(1), "vm-a", epoch=2696, unit_seconds=7_200_000)
    observe_chain_epoch(2702)
    assert scoring.compute_owed_micro_usd({node_id(1): 1_000_000}) == {}

    observe_chain_epoch(2696)
    assert scoring.compute_owed_micro_usd({node_id(1): 1_000_000}) == {node_id(1): 2_000_000}


def test_billing_epoch_reads_the_highest_observed_chain_epoch() -> None:
    """CLAIM: `billing_epoch` is the cached on-chain CurrentEpoch.

    The cache is per-miner and refreshed on every chain read; a lagging
    row must not drag the billing epoch backwards.
    """
    assert scoring.billing_epoch() is None
    observe_chain_epoch(2702)
    assert scoring.billing_epoch() == 2702
    MinerCapacity.objects.create(
        miner_node_id=node_id(98),
        status="active",
        capacity_slots=1,
        observed_epoch=2701,
        data_epoch=2701,
        refreshed_at=timezone.now(),
    )
    assert scoring.billing_epoch() == 2702


@override_settings(VALI_EPOCH_WEIGHT_SOURCE="usage")
def test_view_labels_the_bill_with_the_chain_epoch_not_the_ledger(
    monkeypatch, authed_client
) -> None:
    """CLAIM: `usage_epoch` names the epoch the bill DESCRIBES.

    Ledger frozen at 2696, chain at 2702. Reporting the newest ledger
    bucket would label an empty bill "2696" — an operator would read it
    as "we owe nothing for 2696", when the truth is "nothing was proven
    for 2702".
    """
    observe_chain_epoch(2702)
    _accrue(node_id(1), "vm-a", epoch=2696, unit_seconds=3600)
    from apps.scheduler import chain, views

    snap = chain.ChainSnapshot(current_epoch=2702, miners=())
    monkeypatch.setattr(views.chain, "read_miner_status", lambda: snap)
    monkeypatch.setattr(views.service, "price_by_node", lambda snap: {node_id(1): 1_000_000})

    body = authed_client.get(URL).json()
    assert body["usage_epoch"] == 2702
    assert body["owed_usd_micros"] == {}


@override_settings(VALI_SCORING_SCALE=250.0)
def test_the_bill_follows_a_RETUNED_scale_rather_than_a_hardcoded_1000() -> None:
    """CLAIM: the divisor is read from the same knob `resource_units`
    scaled BY, so the two can never drift.

    Found by mutation: hardcoding `1000` passed every other test. If an
    operator retunes `VALI_SCORING_SCALE`, `unit_seconds` changes scale
    and a hardcoded divisor would silently misprice by the ratio.
    """
    observe_chain_epoch(9)
    # 3600 real unit-seconds at the retuned scale of 250.
    _accrue(node_id(1), "vm-a", epoch=9, unit_seconds=3600 * 250)
    owed = scoring.compute_owed_micro_usd({node_id(1): 1_000_000})
    # 900_000 * 1e6 / (3600 * 250) = 1_000_000 — one real unit-hour.
    assert owed == {node_id(1): 1_000_000}


@override_settings(VALI_SCORING_SCALE=0.0)
def test_a_zero_scale_does_not_divide_by_zero() -> None:
    """CLAIM: a misconfigured scale degrades, it does not crash.

    Found by mutation: removing the `scale <= 0` floor passed everything.
    `int(0.0)` is a legal setting value and would make the divisor zero,
    turning the whole admin bill readout into a 500.
    """
    observe_chain_epoch(9)
    _accrue(node_id(1), "vm-a", epoch=9, unit_seconds=3600)
    owed = scoring.compute_owed_micro_usd({node_id(1): 1_000_000})
    # scale floored to 1 ⇒ behaves as an unscaled ledger, no exception.
    assert owed == {node_id(1): 1_000_000}
