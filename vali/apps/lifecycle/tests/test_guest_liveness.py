"""In-guest liveness — the classifier, the watermark recorder, and the
API surface.

Each test names the CLAIM it defends, because the point of this module
is a set of claims the old code silently violated: a wedged VM read
GREEN, and any replacement must not over-correct into flagging a healthy
VM as broken.
"""

from __future__ import annotations

from datetime import timedelta

import pytest
from django.test import override_settings
from django.utils import timezone

from apps.lifecycle import guest_liveness
from apps.lifecycle.models import Vm, VmBootPhase, VmGuestLiveness, VmState

pytestmark = pytest.mark.django_db


def _make_vm(vm_id: str = "vm-1", **kwargs) -> Vm:
    return Vm.objects.create(
        vm_id=vm_id,
        lease_id=f"lease-{vm_id}",
        state=kwargs.pop("state", VmState.ACTIVE),
        generation=1,
        host="node-src",
        lifecycle_vk=bytes(32),
        **kwargs,
    )


# ─── CLAIM 1 — a fresh in-guest signal reads `alive` ─────────────────


@override_settings(VALI_GUEST_LIVENESS_STALE_S=600)
def test_fresh_signal_is_alive() -> None:
    now = timezone.now()
    verdict = guest_liveness.classify(now - timedelta(seconds=59), now=now)
    assert verdict.state == guest_liveness.ALIVE
    assert verdict.is_alive and not verdict.is_wedged
    assert verdict.age_s == 59


@override_settings(VALI_GUEST_LIVENESS_STALE_S=600)
def test_signal_exactly_at_the_bound_is_still_alive() -> None:
    """The bound is INCLUSIVE — a signal at exactly `stale_s` is alive.
    Sized generously on purpose (see `staleness_bound_s`)."""
    now = timezone.now()
    assert (
        guest_liveness.classify(now - timedelta(seconds=600), now=now).state
        == guest_liveness.ALIVE
    )


# ─── CLAIM 2 — a SILENT guest reads `wedged`, not `alive` ────────────
#
# This is the defect. Proved live on miner-2 2026-08-12: the VM's libvirt
# domain stayed `running` and `boot_phase` stayed `running` while the
# guest sat wedged in its initramfs.


@override_settings(VALI_GUEST_LIVENESS_STALE_S=600)
def test_stale_signal_is_wedged() -> None:
    now = timezone.now()
    verdict = guest_liveness.classify(now - timedelta(seconds=601), now=now)
    assert verdict.state == guest_liveness.WEDGED
    assert verdict.is_wedged and not verdict.is_alive


@override_settings(VALI_GUEST_LIVENESS_STALE_S=600)
def test_the_staleness_bound_is_actually_applied() -> None:
    """Kills the mutant that ignores the bound and calls everything with
    a non-null watermark `alive`: a signal from a week ago is WEDGED."""
    now = timezone.now()
    assert (
        guest_liveness.classify(now - timedelta(days=7), now=now).state
        == guest_liveness.WEDGED
    )


@override_settings(VALI_GUEST_LIVENESS_STALE_S=60)
def test_the_bound_is_configurable_and_read_from_settings() -> None:
    """Kills the mutant that hardcodes the bound: at 60 s, a 120 s-old
    signal is wedged (it would be `alive` under the 600 s default)."""
    now = timezone.now()
    assert guest_liveness.staleness_bound_s() == 60
    assert (
        guest_liveness.classify(now - timedelta(seconds=120), now=now).state
        == guest_liveness.WEDGED
    )


def test_a_non_positive_bound_is_floored_not_disabled() -> None:
    """A misconfigured `0`/negative bound must not become "infinite
    freshness" — it is floored to 1 s (strictest), never ignored."""
    with override_settings(VALI_GUEST_LIVENESS_STALE_S=0):
        assert guest_liveness.staleness_bound_s() == 1
    with override_settings(VALI_GUEST_LIVENESS_STALE_S=-99):
        assert guest_liveness.staleness_bound_s() == 1


# ─── CLAIM 3 — NEVER-emitted is `unknown`, NOT `wedged` ──────────────
#
# The false positive that would be WORSE than the bug: `realtenant-
# ubuntu-1` is a live tenant on a pre-keepalive image with 0 live
# attestations. A signal a VM has never produced is not evidence of
# death, and must never drive an automated action.


def test_never_emitted_is_unknown() -> None:
    verdict = guest_liveness.classify(None, now=timezone.now())
    assert verdict.state == guest_liveness.UNKNOWN
    assert verdict.signal_at is None
    assert verdict.age_s is None
    assert verdict.kind == ""
    # Explicitly NOT wedged — the whole point of the third verdict.
    assert not verdict.is_wedged


def test_unknown_is_not_reachable_by_any_bound() -> None:
    """No staleness bound, however strict, can turn `unknown` into
    `wedged` — the distinction is the presence of a watermark, not its
    age."""
    for bound in (1, 60, 600, 10**9):
        with override_settings(VALI_GUEST_LIVENESS_STALE_S=bound):
            assert (
                guest_liveness.classify(None, now=timezone.now()).state
                == guest_liveness.UNKNOWN
            )


def test_a_vm_row_with_no_watermark_is_unknown() -> None:
    vm = _make_vm("vm-fresh")
    assert vm.guest_signal_at is None
    assert vm.guest_liveness().state == VmGuestLiveness.UNKNOWN.value


# ─── CLAIM 4 — a future-dated signal never reads negative ────────────


@override_settings(VALI_GUEST_LIVENESS_STALE_S=600)
def test_future_dated_signal_is_alive_with_zero_age() -> None:
    """Clock skew between vali and the ingest stamp must not produce a
    negative age or an absurd verdict."""
    now = timezone.now()
    verdict = guest_liveness.classify(now + timedelta(seconds=30), now=now)
    assert verdict.state == guest_liveness.ALIVE
    assert verdict.age_s == 0


# ─── CLAIM 5 — the watermark advances MONOTONICALLY ──────────────────


def test_record_signal_sets_the_watermark() -> None:
    vm = _make_vm("vm-rec")
    at = timezone.now()
    assert guest_liveness.record_signal("vm-rec", "served_receipt", at=at) is True
    vm.refresh_from_db()
    assert vm.guest_signal_at == at
    assert vm.guest_signal_kind == "served_receipt"


def test_record_signal_never_moves_the_watermark_backwards() -> None:
    """A late / replayed / out-of-order signal must not be able to
    manufacture a wedge by pulling the watermark into the past."""
    vm = _make_vm("vm-mono")
    now = timezone.now()
    guest_liveness.record_signal("vm-mono", "served_receipt", at=now)
    assert (
        guest_liveness.record_signal(
            "vm-mono", "live_attestation", at=now - timedelta(hours=1)
        )
        is False
    )
    vm.refresh_from_db()
    assert vm.guest_signal_at == now
    assert vm.guest_signal_kind == "served_receipt"


def test_the_freshest_of_the_two_signal_classes_wins() -> None:
    """Both classes feed ONE watermark, so a keepalive-only image and a
    served-receipt-only image are both covered."""
    vm = _make_vm("vm-both")
    t0 = timezone.now() - timedelta(minutes=5)
    guest_liveness.record_signal("vm-both", "served_receipt", at=t0)
    guest_liveness.record_signal(
        "vm-both", "live_attestation", at=t0 + timedelta(minutes=1)
    )
    vm.refresh_from_db()
    assert vm.guest_signal_kind == "live_attestation"
    assert vm.guest_signal_at == t0 + timedelta(minutes=1)


def test_record_signal_rejects_an_unknown_kind() -> None:
    _make_vm("vm-kind")
    assert guest_liveness.record_signal("vm-kind", "totally-made-up") is False
    assert Vm.objects.get(vm_id="vm-kind").guest_signal_at is None


def test_record_signal_for_a_missing_vm_is_a_benign_noop() -> None:
    assert guest_liveness.record_signal("no-such-vm", "served_receipt") is False


def test_record_signal_never_raises_when_the_db_blows_up(monkeypatch) -> None:
    """It rides the SYNCHRONOUS telemetry-ingest path — a display-only
    watermark must never be able to fail a tenant's ingest."""
    _make_vm("vm-boom")

    class _Boom:
        def filter(self, *a, **k):
            raise RuntimeError("db is on fire")

    monkeypatch.setattr(Vm, "objects", _Boom())
    assert guest_liveness.record_signal("vm-boom", "served_receipt") is False


def test_record_signal_does_not_bump_the_concurrency_version() -> None:
    """A liveness beat must not invalidate an in-flight §24/§25 CAS."""
    vm = _make_vm("vm-ver")
    before = vm.version
    guest_liveness.record_signal("vm-ver", "served_receipt")
    vm.refresh_from_db()
    assert vm.version == before


def test_record_signal_does_not_touch_lifecycle_state() -> None:
    vm = _make_vm("vm-state", state=VmState.DECOMMISSIONING)
    guest_liveness.record_signal("vm-state", "served_receipt")
    vm.refresh_from_db()
    assert vm.state == VmState.DECOMMISSIONING


# ─── CLAIM 6 — the verdict is what `boot_phase` cannot be ────────────


@override_settings(VALI_GUEST_LIVENESS_STALE_S=600)
def test_a_wedged_vm_still_reports_boot_phase_running() -> None:
    """The exact live symptom: `state=active`, `boot_phase=running`, and
    yet the guest is dead. `boot_phase` is monotonic so it can NEVER
    report this; `guest_liveness` does."""
    vm = _make_vm("vm-wedged", boot_phase=VmBootPhase.RUNNING.value)
    Vm.objects.filter(vm_id="vm-wedged").update(
        guest_signal_at=timezone.now() - timedelta(hours=3),
        guest_signal_kind="served_receipt",
    )
    vm.refresh_from_db()
    assert vm.state == VmState.ACTIVE
    assert vm.boot_phase == VmBootPhase.RUNNING.value
    assert vm.guest_liveness().state == VmGuestLiveness.WEDGED.value


# ─── CLAIM 7 — the API surfaces it ───────────────────────────────────


@override_settings(VALI_GUEST_LIVENESS_STALE_S=600)
def test_serialize_vm_exposes_the_verdict() -> None:
    from apps.lifecycle.views import _serialize_vm

    vm = _make_vm("vm-api")
    body = _serialize_vm(vm)
    assert body["guest_liveness"] == "unknown"
    assert body["guest_signal_at"] is None
    assert body["guest_signal_age_s"] is None
    assert body["guest_signal_kind"] == ""

    at = timezone.now() - timedelta(seconds=30)
    Vm.objects.filter(vm_id="vm-api").update(
        guest_signal_at=at, guest_signal_kind="served_receipt"
    )
    vm.refresh_from_db()
    body = _serialize_vm(vm)
    assert body["guest_liveness"] == "alive"
    assert body["guest_signal_at"] == at.isoformat()
    assert 29 <= body["guest_signal_age_s"] <= 32
    assert body["guest_signal_kind"] == "served_receipt"

    Vm.objects.filter(vm_id="vm-api").update(
        guest_signal_at=timezone.now() - timedelta(hours=2)
    )
    vm.refresh_from_db()
    assert _serialize_vm(vm)["guest_liveness"] == "wedged"


@override_settings(VALI_GUEST_LIVENESS_STALE_S=600)
def test_admin_column_renders_the_verdict_with_its_age() -> None:
    from apps.lifecycle.admin import VmAdmin

    vm = _make_vm("vm-admin")
    admin_obj = VmAdmin(Vm, None)
    assert admin_obj.guest_liveness_display(vm) == "unknown"

    Vm.objects.filter(vm_id="vm-admin").update(
        guest_signal_at=timezone.now() - timedelta(hours=2),
        guest_signal_kind="served_receipt",
    )
    vm.refresh_from_db()
    rendered = admin_obj.guest_liveness_display(vm)
    assert rendered.startswith("wedged (")
