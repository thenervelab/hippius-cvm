"""Blackbox host-attestor dispatchability + reward-multiplier gates (PR-11).

All mechanism ships DEFAULT-OFF. This suite proves:

- gate OFF (default) ⇒ dispatch + epoch-weights are BYTE-IDENTICAL to today
  (the regression guard — a default deployment never changes behaviour);
- `VALI_HOST_ATTESTOR_GATE_ENFORCE` ON ⇒ a miner is dispatchable only with
  an `attested` (NEVER `pending`) host-attestor, live on a desired
  measurement — fail-closed;
- `VALI_REWARD_REQUIRE_ATTESTOR` ON ⇒ epoch-weight = usage × liveness ratio
  (idle-alive → 0, usage+dead → 0, usage+alive → usage×ratio) — a MULTIPLIER,
  never additive;
- the SLA liveness meter computes the ratio from the beacon-recency history
  and consumes `attested` rows only;
- the admin epoch-weights readout previews the would-be effect while off.
"""

from __future__ import annotations

from datetime import timedelta

import pytest
from django.test import override_settings
from django.urls import reverse
from django.utils import timezone
from rest_framework import status
from rest_framework.test import APIClient

from apps.scheduler import scoring, service
from apps.scheduler.models import UsageAccrual
from apps.telemetry import release_service
from apps.telemetry.models import (
    HostAttestor,
    HostAttestorRelease,
    HostAttestorStatus,
)

from .factories import make_dispatchable_identity, node_id, observe_chain_epoch

pytestmark = pytest.mark.django_db

MEAS_A = "a1" * 48  # 96 hex — the desired host-attestor measurement
MEAS_B = "b2" * 48  # a stale (non-desired) measurement
SIGNER = "ee" * 32


def _chip(seed: int) -> str:
    return format(seed, "0128x")


def _release(measurement: str = MEAS_A) -> None:
    HostAttestorRelease.objects.create(measurement=measurement, version="v1", is_active=True)


def _attestor(
    seed: int,
    *,
    measurement: str = MEAS_A,
    status: str = HostAttestorStatus.ATTESTED.value,
    last_seen_at=None,
) -> HostAttestor:
    now = timezone.now()
    return HostAttestor.objects.create(
        chip_id=_chip(seed),
        node_id=node_id(seed),
        signer_pubkey=bytes.fromhex(SIGNER),
        measurement=measurement,
        cert_expiry_at=now + timedelta(days=1),
        status=status,
        last_seen_at=now if last_seen_at is None else last_seen_at,
    )


def _accrue(seed: int, vm_id: str, *, epoch: int, unit_seconds: int) -> None:
    UsageAccrual.objects.create(
        epoch=epoch,
        miner_node_id=node_id(seed),
        vm_id=vm_id,
        resource_class="small",
        unit_seconds=unit_seconds,
        billable_seconds=unit_seconds,
    )


# ─── SLA / liveness meter (pure) ─────────────────────────────────────


def test_liveness_ratio_fresh_beacon_is_full() -> None:
    now = timezone.now()
    r = release_service.liveness_ratio(
        now - timedelta(seconds=30), now=now, cadence_s=60, window_s=600
    )
    assert r == 1.0


def test_liveness_ratio_never_seen_is_zero() -> None:
    assert (
        release_service.liveness_ratio(None, now=timezone.now(), cadence_s=60, window_s=600) == 0.0
    )


def test_liveness_ratio_far_past_window_is_zero() -> None:
    now = timezone.now()
    r = release_service.liveness_ratio(
        now - timedelta(seconds=10_000), now=now, cadence_s=60, window_s=600
    )
    assert r == 0.0


def test_liveness_ratio_decays_linearly_over_the_window() -> None:
    now = timezone.now()
    # staleness 360s: alive = 600 - (360 - 60) = 300 ⇒ 300/600 = 0.5
    r = release_service.liveness_ratio(
        now - timedelta(seconds=360), now=now, cadence_s=60, window_s=600
    )
    assert r == pytest.approx(0.5)


def test_liveness_ratios_consumes_attested_only() -> None:
    _release()
    _attestor(1, status=HostAttestorStatus.ATTESTED.value)
    _attestor(2, status=HostAttestorStatus.PENDING.value)  # never coverage
    ratios = release_service.attestor_liveness_ratios()
    assert set(ratios) == {node_id(1)}
    assert ratios[node_id(1)] == 1.0


def test_liveness_ratios_ignores_stale_and_absent_release() -> None:
    # No release admitted ⇒ nothing is on a desired measurement ⇒ empty.
    _attestor(1)
    assert release_service.attestor_liveness_ratios() == {}
    # With a release, a row on a NON-desired measurement is excluded.
    _release(MEAS_A)
    _attestor(2, measurement=MEAS_B)
    assert set(release_service.attestor_liveness_ratios()) == {node_id(1)}


# ─── dispatchability gate ────────────────────────────────────────────


def test_dispatchable_default_off_is_byte_identical() -> None:
    # Two dispatchable miners, NO host-attestor data at all. Default-off ⇒
    # the host-attestor requirement is absent → both stay dispatchable.
    make_dispatchable_identity(1)
    make_dispatchable_identity(2)
    assert service.dispatchable_node_ids() == frozenset({node_id(1), node_id(2)})


@override_settings(VALI_HOST_ATTESTOR_GATE_ENFORCE=True)
def test_gate_on_requires_attested_live_desired_row() -> None:
    make_dispatchable_identity(1)
    make_dispatchable_identity(2)
    _release(MEAS_A)
    _attestor(1)  # attested + live + desired → stays dispatchable
    # miner 2 has NO host-attestor → dropped under the ON gate (fail-closed).
    assert service.dispatchable_node_ids() == frozenset({node_id(1)})


@override_settings(VALI_HOST_ATTESTOR_GATE_ENFORCE=True)
def test_gate_on_pending_row_is_not_dispatchable() -> None:
    make_dispatchable_identity(1)
    _release(MEAS_A)
    _attestor(1, status=HostAttestorStatus.PENDING.value)  # HARD CONSTRAINT
    assert service.dispatchable_node_ids() == frozenset()


@override_settings(VALI_HOST_ATTESTOR_GATE_ENFORCE=True)
def test_gate_on_stale_measurement_and_dead_beacon_excluded() -> None:
    make_dispatchable_identity(1)
    make_dispatchable_identity(2)
    _release(MEAS_A)
    # miner 1: attested but on a NON-desired measurement → excluded.
    _attestor(1, measurement=MEAS_B)
    # miner 2: attested + desired but last beacon 2h ago → excluded.
    _attestor(2, last_seen_at=timezone.now() - timedelta(hours=2))
    assert service.dispatchable_node_ids() == frozenset()


@override_settings(VALI_HOST_ATTESTOR_GATE_ENFORCE=True)
def test_gate_on_no_release_fails_closed() -> None:
    make_dispatchable_identity(1)
    _attestor(1)  # attested + live but NO desired release pinned
    assert service.dispatchable_node_ids() == frozenset()


# ─── reward MULTIPLIER (never additive) ──────────────────────────────


@override_settings(VALI_EPOCH_WEIGHT_SOURCE="usage")
def test_reward_default_off_is_byte_identical() -> None:
    # Usage present, attestor DEAD — with the flag OFF the weight is the raw
    # usage (byte-identical to pre-PR-11), NOT zeroed.
    observe_chain_epoch(9)
    _accrue(1, "vm-a", epoch=9, unit_seconds=1000)
    _release()
    _attestor(1, last_seen_at=timezone.now() - timedelta(hours=2))  # dead
    assert scoring.compute_epoch_weights() == {node_id(1): 1000}


@override_settings(VALI_EPOCH_WEIGHT_SOURCE="usage", VALI_REWARD_REQUIRE_ATTESTOR=True)
def test_reward_idle_but_alive_attestor_earns_zero() -> None:
    # Alive attestor, NO tenant usage ⇒ ratio × 0 = 0. Liveness alone never
    # mints reward (SLA must-have #5 — the multiplier is never additive).
    _release()
    _attestor(1)  # alive, but no UsageAccrual row
    assert scoring.compute_epoch_weights() == {}


@override_settings(VALI_EPOCH_WEIGHT_SOURCE="usage", VALI_REWARD_REQUIRE_ATTESTOR=True)
def test_reward_usage_with_dead_attestor_is_zeroed() -> None:
    observe_chain_epoch(9)
    _accrue(1, "vm-a", epoch=9, unit_seconds=1000)
    _release()
    _attestor(1, last_seen_at=timezone.now() - timedelta(hours=2))  # dead
    assert scoring.compute_epoch_weights() == {}


@override_settings(VALI_EPOCH_WEIGHT_SOURCE="usage", VALI_REWARD_REQUIRE_ATTESTOR=True)
def test_reward_usage_with_pending_attestor_is_zeroed() -> None:
    observe_chain_epoch(9)
    _accrue(1, "vm-a", epoch=9, unit_seconds=1000)
    _release()
    _attestor(1, status=HostAttestorStatus.PENDING.value)  # never consumed
    assert scoring.compute_epoch_weights() == {}


@override_settings(VALI_EPOCH_WEIGHT_SOURCE="usage", VALI_REWARD_REQUIRE_ATTESTOR=True)
def test_reward_usage_with_alive_attestor_is_full_usage() -> None:
    observe_chain_epoch(9)
    _accrue(1, "vm-a", epoch=9, unit_seconds=1000)
    _release()
    _attestor(1)  # fresh beacon ⇒ ratio 1.0 ⇒ usage × 1.0
    assert scoring.compute_epoch_weights() == {node_id(1): 1000}


@override_settings(
    VALI_EPOCH_WEIGHT_SOURCE="usage",
    VALI_REWARD_REQUIRE_ATTESTOR=True,
    VALI_HOST_ATTESTOR_LIVENESS_WINDOW_S=600,
    VALI_HOST_ATTESTOR_BEACON_CADENCE_S=60,
)
def test_reward_usage_scaled_by_partial_liveness_ratio() -> None:
    observe_chain_epoch(9)
    _accrue(1, "vm-a", epoch=9, unit_seconds=1000)
    _release()
    # last beacon 360s ago ⇒ ratio ≈ 0.5 ⇒ 1000 × 0.5 ≈ 500. A partial
    # multiplier: strictly between 0 and full usage (a few units of
    # sub-second wall-clock drift move the floored product by ±1-2).
    _attestor(1, last_seen_at=timezone.now() - timedelta(seconds=360))
    weights = scoring.compute_epoch_weights()
    assert set(weights) == {node_id(1)}
    assert 498 <= weights[node_id(1)] <= 500  # ≈ 1000 × 0.5, partial


# ─── admin epoch-weights readout preview ─────────────────────────────


URL = reverse("epoch_weights")


def _authed() -> APIClient:
    from apps.identity.models import (
        PrincipalScope,
        ServiceClient,
        ServiceToken,
        TokenLifetime,
    )

    client = ServiceClient.objects.create(scope=PrincipalScope.OPERATOR.value, name="epoch-reader")
    _row, plaintext = ServiceToken.issue(
        client=client,
        name="ops",
        lifetime=TokenLifetime.OPS.value,
    )
    api = APIClient()
    api.credentials(HTTP_AUTHORIZATION=f"Bearer {plaintext}")
    return api


@override_settings(VALI_EPOCH_WEIGHT_SOURCE="usage")
def test_view_omits_preview_without_attestor_rows() -> None:
    # Default prod (no host-attestor data) ⇒ NO preview key (byte-identical).
    observe_chain_epoch(9)
    _accrue(1, "vm-a", epoch=9, unit_seconds=1000)
    resp = _authed().get(URL)
    assert resp.status_code == status.HTTP_200_OK
    assert "attestor_reward_preview" not in resp.json()


@override_settings(VALI_EPOCH_WEIGHT_SOURCE="usage")
def test_view_previews_would_be_weights_while_off(monkeypatch) -> None:
    observe_chain_epoch(9)
    _accrue(1, "vm-a", epoch=9, unit_seconds=1000)
    _release()
    _attestor(1, last_seen_at=timezone.now() - timedelta(seconds=360))  # 0.5

    # The owed path does a chain read — stub it (irrelevant to the preview).
    from apps.scheduler import views

    monkeypatch.setattr(
        views.chain,
        "read_miner_status",
        lambda: views.chain.ChainSnapshot(current_epoch=1, miners=()),
    )
    monkeypatch.setattr(views.service, "price_by_node", lambda snap: {})

    body = _authed().get(URL).json()
    # Emitted weights are UNCHANGED (flag off) — the multiplier is preview-only.
    assert body["weights"] == {node_id(1): 1000}
    preview = body["attestor_reward_preview"]
    assert preview["enforced"] is False
    # ≈ 1000 × 0.5 (partial ratio); tolerate ±sub-second wall-clock drift.
    assert 498 <= preview["weights"][node_id(1)] <= 500
    assert preview["total_weight"] == preview["weights"][node_id(1)]


@override_settings(VALI_EPOCH_WEIGHT_SOURCE="usage", VALI_REWARD_REQUIRE_ATTESTOR=True)
def test_view_omits_preview_when_gate_armed(monkeypatch) -> None:
    # When armed, `weights` already reflect the multiplier — no preview.
    observe_chain_epoch(9)
    _accrue(1, "vm-a", epoch=9, unit_seconds=1000)
    _release()
    _attestor(1)

    from apps.scheduler import views

    monkeypatch.setattr(
        views.chain,
        "read_miner_status",
        lambda: views.chain.ChainSnapshot(current_epoch=1, miners=()),
    )
    monkeypatch.setattr(views.service, "price_by_node", lambda snap: {})

    body = _authed().get(URL).json()
    assert body["weights"] == {node_id(1): 1000}  # 1000 × 1.0
    assert "attestor_reward_preview" not in body
