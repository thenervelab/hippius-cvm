"""A verified `served_receipt` from a `tenant_vm` advances that VM's
display-only `boot_phase` to `running` (and self-heals its NetBird IP).

The hook lives in `service.ingest` (the served_receipt ingest path, NOT
the drain); these drive it end-to-end through `POST /v1/telemetry/ingest`
with the autouse `fake_verifier` steering the verdict.
"""

from __future__ import annotations

import pytest
from django.urls import reverse
from rest_framework import status
from rest_framework.test import APIClient

from apps.lifecycle.models import Vm, VmBootPhase, VmState
from apps.orchestration import effects

from .conftest import FakeVerifier, ingest_payload
from .factories import make_source

pytestmark = pytest.mark.django_db

INGEST_URL = reverse("telemetry_ingest")


def _make_vm(vm_id: str, *, boot_phase: str = "") -> Vm:
    vm = Vm.objects.create(
        vm_id=vm_id,
        lease_id=f"lease-{vm_id}",
        state=VmState.ACTIVE,
        generation=1,
        host="node-src",
        lifecycle_vk=bytes(32),
        boot_phase=boot_phase,
    )
    return vm


def _ingest_served_receipt(
    client: APIClient, vm_id: str, *, body: bytes = b"receipt-1"
) -> None:
    resp = client.post(
        INGEST_URL,
        ingest_payload(
            source="tenant_vm",
            source_id=vm_id,
            kind="served_receipt",
            body_hex=body.hex(),
        ),
        format="json",
    )
    assert resp.status_code == status.HTTP_202_ACCEPTED, resp.content


@pytest.fixture(autouse=True)
def _no_netbird(monkeypatch: pytest.MonkeyPatch) -> None:
    """Default: NetBird resolution finds no peer yet (returns None), so the
    boot-progress tests never touch the network. Tests that assert the IP
    self-heal override this."""
    monkeypatch.setattr(
        effects, "resolve_netbird_peer_ip", lambda vm_id: None
    )


# ─── Feature 1 — `running` milestone ─────────────────────────────────


def test_served_receipt_advances_boot_phase_to_running(
    ingest_client: APIClient,
) -> None:
    make_source(source="tenant_vm", source_id="vm-run")
    _make_vm("vm-run", boot_phase=VmBootPhase.KEK_RELEASED.value)

    _ingest_served_receipt(ingest_client, "vm-run")

    vm = Vm.objects.get(vm_id="vm-run")
    assert vm.boot_phase == VmBootPhase.RUNNING.value
    assert vm.boot_phase_at is not None


def test_served_receipt_advances_from_blank(ingest_client: APIClient) -> None:
    make_source(source="tenant_vm", source_id="vm-blank")
    _make_vm("vm-blank", boot_phase="")

    _ingest_served_receipt(ingest_client, "vm-blank")

    assert Vm.objects.get(vm_id="vm-blank").boot_phase == VmBootPhase.RUNNING.value


def test_no_vm_row_is_benign(ingest_client: APIClient) -> None:
    # A tenant_vm source with no matching Vm row still ingests cleanly.
    make_source(source="tenant_vm", source_id="vm-ghost")
    _ingest_served_receipt(ingest_client, "vm-ghost")
    assert not Vm.objects.filter(vm_id="vm-ghost").exists()


def test_idempotent_no_write_once_running(
    ingest_client: APIClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    make_source(source="tenant_vm", source_id="vm-idem")
    _make_vm("vm-idem", boot_phase=VmBootPhase.RUNNING.value)
    before = Vm.objects.get(vm_id="vm-idem")

    # Guard: `save()` must not be called on the already-running row.
    from apps.lifecycle import models as lifecycle_models

    original_save = lifecycle_models.Vm.save
    saves: list[list[str] | None] = []

    def _spy_save(self, *args, **kwargs):  # type: ignore[no-untyped-def]
        saves.append(kwargs.get("update_fields"))
        return original_save(self, *args, **kwargs)

    monkeypatch.setattr(lifecycle_models.Vm, "save", _spy_save)

    _ingest_served_receipt(ingest_client, "vm-idem")

    after = Vm.objects.get(vm_id="vm-idem")
    assert after.boot_phase == VmBootPhase.RUNNING.value
    # No boot_phase write happened (already running); the row is untouched.
    assert all("boot_phase" not in (f or []) for f in saves)
    assert after.boot_phase_at == before.boot_phase_at


def test_late_kek_released_receipt_does_not_regress_running(
    ingest_client: APIClient,
) -> None:
    """A served_receipt only ever advances to `running`; once there, no
    envelope regresses it (monotonic)."""
    make_source(source="tenant_vm", source_id="vm-mono")
    _make_vm("vm-mono", boot_phase=VmBootPhase.RUNNING.value)

    # Even a fresh served_receipt (which maps to `running`) is a no-op.
    _ingest_served_receipt(ingest_client, "vm-mono", body=b"receipt-late")

    assert Vm.objects.get(vm_id="vm-mono").boot_phase == VmBootPhase.RUNNING.value


def test_non_served_receipt_does_not_advance(
    ingest_client: APIClient, fake_verifier: FakeVerifier
) -> None:
    make_source(source="tenant_vm", source_id="vm-other")
    _make_vm("vm-other", boot_phase=VmBootPhase.KEK_RELEASED.value)
    # A non-served_receipt kind from the same source is NOT a running proof.
    resp = ingest_client.post(
        INGEST_URL,
        ingest_payload(
            source="tenant_vm",
            source_id="vm-other",
            kind="edge_telemetry",
            body_hex=b"x".hex(),
        ),
        format="json",
    )
    assert resp.status_code == status.HTTP_202_ACCEPTED, resp.content
    assert (
        Vm.objects.get(vm_id="vm-other").boot_phase
        == VmBootPhase.KEK_RELEASED.value
    )


def test_verify_failed_receipt_does_not_advance(
    ingest_client: APIClient, fake_verifier: FakeVerifier
) -> None:
    make_source(source="tenant_vm", source_id="vm-bad")
    _make_vm("vm-bad", boot_phase=VmBootPhase.KEK_RELEASED.value)
    fake_verifier.outcome = "failed"
    resp = ingest_client.post(
        INGEST_URL,
        ingest_payload(
            source="tenant_vm", source_id="vm-bad", kind="served_receipt"
        ),
        format="json",
    )
    assert resp.status_code == status.HTTP_400_BAD_REQUEST
    # A rejected envelope never advances the phase.
    assert (
        Vm.objects.get(vm_id="vm-bad").boot_phase
        == VmBootPhase.KEK_RELEASED.value
    )


# ─── Feature 2 — NetBird IP self-heal on ingest ──────────────────────


def test_netbird_ip_resolves_and_persists(
    ingest_client: APIClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    make_source(source="tenant_vm", source_id="vm-nb")
    _make_vm("vm-nb")

    calls: list[str] = []

    def _resolve(vm_id: str) -> str:
        calls.append(vm_id)
        return "100.64.0.20"

    monkeypatch.setattr(effects, "resolve_netbird_peer_ip", _resolve)

    _ingest_served_receipt(ingest_client, "vm-nb", body=b"r1")

    vm = Vm.objects.get(vm_id="vm-nb")
    assert vm.netbird_ip == "100.64.0.20"
    assert calls == ["vm-nb"]


def test_netbird_ip_retries_until_resolved_then_stops(
    ingest_client: APIClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    make_source(source="tenant_vm", source_id="vm-heal")
    _make_vm("vm-heal")

    results = iter([None, "100.64.0.40"])
    calls: list[str] = []

    def _resolve(vm_id: str):  # type: ignore[no-untyped-def]
        calls.append(vm_id)
        return next(results)

    monkeypatch.setattr(effects, "resolve_netbird_peer_ip", _resolve)

    # First receipt: peer not enrolled yet → still empty.
    _ingest_served_receipt(ingest_client, "vm-heal", body=b"r1")
    assert Vm.objects.get(vm_id="vm-heal").netbird_ip == ""

    # Second receipt: resolves + persists.
    _ingest_served_receipt(ingest_client, "vm-heal", body=b"r2")
    assert Vm.objects.get(vm_id="vm-heal").netbird_ip == "100.64.0.40"

    # Third receipt: already resolved → no further resolve call.
    _ingest_served_receipt(ingest_client, "vm-heal", body=b"r3")
    assert calls == ["vm-heal", "vm-heal"]


def test_netbird_resolve_stops_after_window(
    ingest_client: APIClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    from datetime import timedelta

    from django.utils import timezone

    make_source(source="tenant_vm", source_id="vm-old")
    _make_vm("vm-old")
    # Age the VM past the resolve window (created_at is auto_now_add → set via
    # .update to bypass it). A never-enrolling VM must stop probing NetBird.
    Vm.objects.filter(vm_id="vm-old").update(
        created_at=timezone.now() - timedelta(hours=1)
    )

    calls: list[str] = []
    monkeypatch.setattr(
        effects, "resolve_netbird_peer_ip", lambda vm_id: calls.append(vm_id)
    )

    _ingest_served_receipt(ingest_client, "vm-old")

    vm = Vm.objects.get(vm_id="vm-old")
    # boot_phase still advances, but NO NetBird call is made past the window.
    assert vm.boot_phase == VmBootPhase.RUNNING.value
    assert vm.netbird_ip == ""
    assert calls == []


def test_netbird_failure_does_not_break_ingest(
    ingest_client: APIClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    make_source(source="tenant_vm", source_id="vm-nbfail")
    _make_vm("vm-nbfail", boot_phase=VmBootPhase.KEK_RELEASED.value)

    def _boom(vm_id: str) -> str:
        raise effects.EffectUnavailable("netbird unreachable")

    monkeypatch.setattr(effects, "resolve_netbird_peer_ip", _boom)

    # Ingest still succeeds AND the boot_phase still advances.
    _ingest_served_receipt(ingest_client, "vm-nbfail")

    vm = Vm.objects.get(vm_id="vm-nbfail")
    assert vm.boot_phase == VmBootPhase.RUNNING.value
    assert vm.netbird_ip == ""


def test_netbird_resolve_never_overwrites_an_address_written_meanwhile(
    ingest_client: APIClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The tick's refresh may write a newer address while the resolve call
    is out: the self-heal only fills an empty field."""
    make_source(source="tenant_vm", source_id="vm-race")
    _make_vm("vm-race")

    def _resolve(vm_id: str) -> str:
        Vm.objects.filter(vm_id=vm_id).update(netbird_ip="100.64.0.99")
        return "100.64.0.20"

    monkeypatch.setattr(effects, "resolve_netbird_peer_ip", _resolve)

    _ingest_served_receipt(ingest_client, "vm-race", body=b"r1")

    assert Vm.objects.get(vm_id="vm-race").netbird_ip == "100.64.0.99"
