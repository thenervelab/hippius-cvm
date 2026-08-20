"""Tests for the §9 auto-GC sweep (`service.gc` + `vali_telemetry_gc`).

Terminal envelopes (`Done` / `Failed` / `Quarantined`) older than
`VALI_TELEMETRY_GC_AGE_DAYS` are reaped; `Pending` envelopes are
never GC'd regardless of age.
"""

from __future__ import annotations

from datetime import timedelta

import pytest
from django.conf import settings
from django.core.management import call_command
from django.utils import timezone

from apps.telemetry import service
from apps.telemetry.models import (
    HostAttestorNonce,
    ProcessingStatus,
    TelemetryEnvelope,
)

from .factories import aged, make_envelope

pytestmark = pytest.mark.django_db


def _mint_nonce(tag: int, *, expires_at, spent_at=None) -> HostAttestorNonce:
    return HostAttestorNonce.objects.create(
        nonce=tag.to_bytes(32, "big"),
        node_id="aa" * 32,
        signer_pubkey=b"\x11" * 32,
        expires_at=expires_at,
        spent_at=spent_at,
    )


# ─── service.gc() ────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "terminal_status",
    [
        ProcessingStatus.DONE.value,
        ProcessingStatus.FAILED.value,
        ProcessingStatus.QUARANTINED.value,
    ],
)
def test_gc_deletes_aged_terminal_envelopes(terminal_status: str) -> None:
    make_envelope(processing_status=terminal_status, received_at=aged(8))
    deleted = service.gc()
    assert deleted == 1
    assert TelemetryEnvelope.objects.count() == 0


def test_gc_keeps_recent_terminal_envelopes() -> None:
    # One day old — well inside the 7-day retention window.
    fresh = make_envelope(
        processing_status=ProcessingStatus.DONE.value, received_at=aged(1)
    )
    deleted = service.gc()
    assert deleted == 0
    assert TelemetryEnvelope.objects.filter(pk=fresh.pk).exists()


def test_gc_never_reaps_pending_envelopes_however_old() -> None:
    # An ancient but still-undrained envelope must survive GC — it
    # leaves the table only via a pull or a quarantine reclassify.
    old_pending = make_envelope(
        processing_status=ProcessingStatus.PENDING.value, received_at=aged(90)
    )
    deleted = service.gc()
    assert deleted == 0
    assert TelemetryEnvelope.objects.filter(pk=old_pending.pk).exists()


def test_gc_retention_boundary_is_exclusive() -> None:
    # `received_at < now - GC_AGE_DAYS` — `now` is pinned so the
    # boundary is exact: a row precisely at the cutoff is kept, one a
    # second past it is reaped.
    from datetime import timedelta

    from django.utils import timezone

    pinned = timezone.now()
    cutoff = pinned - timedelta(days=7)
    at_boundary = make_envelope(
        processing_status=ProcessingStatus.DONE.value, received_at=cutoff
    )
    past_boundary = make_envelope(
        processing_status=ProcessingStatus.DONE.value,
        received_at=cutoff - timedelta(seconds=1),
    )
    deleted = service.gc(now=pinned)
    assert deleted == 1
    assert TelemetryEnvelope.objects.filter(pk=at_boundary.pk).exists()
    assert not TelemetryEnvelope.objects.filter(pk=past_boundary.pk).exists()


def test_gc_sweeps_a_mixed_table() -> None:
    # Aged terminals → reaped.
    make_envelope(processing_status=ProcessingStatus.DONE.value, received_at=aged(10))
    make_envelope(processing_status=ProcessingStatus.FAILED.value, received_at=aged(20))
    make_envelope(
        processing_status=ProcessingStatus.QUARANTINED.value, received_at=aged(30)
    )
    # Survivors: a recent terminal + an old Pending.
    recent = make_envelope(
        processing_status=ProcessingStatus.DONE.value, received_at=aged(2)
    )
    pending = make_envelope(
        processing_status=ProcessingStatus.PENDING.value, received_at=aged(99)
    )
    deleted = service.gc()
    assert deleted == 3
    survivors = set(TelemetryEnvelope.objects.values_list("pk", flat=True))
    assert survivors == {recent.pk, pending.pk}


def test_gc_age_days_setting_is_honoured(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "VALI_TELEMETRY_GC_AGE_DAYS", 1)
    # Two days old — kept under the default 7d, reaped under 1d.
    make_envelope(processing_status=ProcessingStatus.DONE.value, received_at=aged(2))
    deleted = service.gc()
    assert deleted == 1


def test_gc_accepts_an_explicit_now() -> None:
    # `gc(now=...)` lets a caller pin the clock; an envelope 8 days
    # before that pinned `now` is reaped.
    make_envelope(processing_status=ProcessingStatus.DONE.value, received_at=aged(8))
    from django.utils import timezone

    deleted = service.gc(now=timezone.now())
    assert deleted == 1


def test_gc_on_an_empty_table_is_a_noop() -> None:
    assert service.gc() == 0


# ─── vali_telemetry_gc --once ────────────────────────────────────────


def test_management_command_once_runs_a_single_sweep() -> None:
    make_envelope(processing_status=ProcessingStatus.DONE.value, received_at=aged(8))
    keep = make_envelope(
        processing_status=ProcessingStatus.PENDING.value, received_at=aged(8)
    )
    call_command("vali_telemetry_gc", "--once")
    # The aged Done row is gone; the Pending row survives.
    assert TelemetryEnvelope.objects.count() == 1
    assert TelemetryEnvelope.objects.filter(pk=keep.pk).exists()


# ─── host-attestor nonce reaper (PR-10) ──────────────────────────────


def test_gc_reaps_spent_and_expired_nonces_but_keeps_live_unspent() -> None:
    now = timezone.now()
    grace = timedelta(seconds=service._nonce_gc_grace_s())
    live_ttl = now + timedelta(seconds=300)
    past_grace = now - grace - timedelta(seconds=1)
    # Live unspent nonce, well inside its TTL — must survive.
    live = _mint_nonce(1, expires_at=live_ttl)
    # Spent long ago (past the grace) — reaped.
    _mint_nonce(2, expires_at=live_ttl, spent_at=past_grace)
    # Expired unspent past the grace — reaped (permanently unclaimable).
    _mint_nonce(3, expires_at=past_grace)
    # Just-spent inside the grace — kept for the brief audit trail.
    recent_spent = _mint_nonce(
        4, expires_at=now + timedelta(seconds=300), spent_at=now
    )

    deleted = service.gc(now=now)

    assert deleted == 2
    surviving = set(HostAttestorNonce.objects.values_list("pk", flat=True))
    assert surviving == {live.pk, recent_spent.pk}
