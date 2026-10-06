"""The two ingest paths that FEED the in-guest liveness watermark.

The classifier is worthless if nothing arms it. These drive the real
ingest endpoints end-to-end and assert `Vm.guest_signal_at` advances —
and, for the served-receipt path, that it advances even when the
best-effort boot-progress / NetBird work beside it fails.
"""

from __future__ import annotations

from datetime import timedelta

import pytest
from django.test import override_settings
from django.urls import reverse
from django.utils import timezone
from rest_framework import status
from rest_framework.test import APIClient

from apps.lifecycle import guest_liveness
from apps.lifecycle.models import Vm, VmGuestLiveness, VmState
from apps.orchestration import effects

from .conftest import ingest_payload
from .factories import make_source

pytestmark = pytest.mark.django_db

INGEST_URL = reverse("telemetry_ingest")


def _make_vm(vm_id: str) -> Vm:
    return Vm.objects.create(
        vm_id=vm_id,
        lease_id=f"lease-{vm_id}",
        state=VmState.ACTIVE,
        generation=1,
        host="node-src",
        lifecycle_vk=bytes(32),
    )


@pytest.fixture(autouse=True)
def _no_netbird(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(effects, "resolve_netbird_peer_ip", lambda vm_id: None)


def _ingest_receipt(client: APIClient, vm_id: str, *, body: bytes) -> None:
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


# ─── the §23 served receipt — the UNIVERSAL signal ───────────────────
#
# Measured on the live fleet 2026-08-12: BOTH Active tenant VMs emit it
# (tenant-vm-1 = 30 690 receipts, p1-liveness-1 = 460), while
# only the newer image emits a §322 live attestation. That is why the
# served receipt is the primary feed.


@override_settings(VALI_GUEST_LIVENESS_STALE_S=600)
def test_served_receipt_arms_the_watermark(ingest_client: APIClient) -> None:
    make_source(source="tenant_vm", source_id="vm-sr")
    vm = _make_vm("vm-sr")
    assert vm.guest_liveness().state == VmGuestLiveness.UNKNOWN.value

    _ingest_receipt(ingest_client, "vm-sr", body=b"receipt-1")

    vm.refresh_from_db()
    assert vm.guest_signal_at is not None
    assert vm.guest_signal_kind == guest_liveness.SIGNAL_SERVED_RECEIPT
    assert vm.guest_liveness().state == VmGuestLiveness.ALIVE.value


@override_settings(VALI_GUEST_LIVENESS_STALE_S=600)
def test_a_later_receipt_refreshes_a_stale_watermark(
    ingest_client: APIClient,
) -> None:
    """A VM that was wedged and came back must read `alive` again."""
    make_source(source="tenant_vm", source_id="vm-back")
    vm = _make_vm("vm-back")
    Vm.objects.filter(vm_id="vm-back").update(
        guest_signal_at=timezone.now() - timedelta(hours=2),
        guest_signal_kind=guest_liveness.SIGNAL_SERVED_RECEIPT,
    )
    vm.refresh_from_db()
    assert vm.guest_liveness().state == VmGuestLiveness.WEDGED.value

    _ingest_receipt(ingest_client, "vm-back", body=b"receipt-back")

    vm.refresh_from_db()
    assert vm.guest_liveness().state == VmGuestLiveness.ALIVE.value


def test_the_watermark_is_armed_even_if_boot_progress_blows_up(
    ingest_client: APIClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The liveness beat is recorded FIRST and independently: a failure
    in the best-effort boot-progress / NetBird work beside it must not
    cost us the evidence that the guest is alive."""
    make_source(source="tenant_vm", source_id="vm-brk")
    vm = _make_vm("vm-brk")

    def _boom(self, milestone_wire: str) -> bool:  # noqa: ANN001
        raise RuntimeError("boot-progress exploded")

    monkeypatch.setattr(Vm, "advance_boot_phase", _boom)

    _ingest_receipt(ingest_client, "vm-brk", body=b"receipt-brk")

    vm.refresh_from_db()
    assert vm.guest_signal_at is not None


def test_a_receipt_for_an_unknown_vm_id_is_a_benign_noop(
    ingest_client: APIClient,
) -> None:
    make_source(source="tenant_vm", source_id="vm-ghost")
    _ingest_receipt(ingest_client, "vm-ghost", body=b"receipt-ghost")
    assert not Vm.objects.filter(vm_id="vm-ghost").exists()


def test_a_miner_heartbeat_does_not_arm_any_vm_watermark(
    ingest_client: APIClient,
) -> None:
    """Only GUEST-originated signals count. A miner-plane envelope proves
    the host is up, which is exactly the thing that already lied."""
    make_source(source="miner", source_id="node-src")
    vm = _make_vm("node-src")  # same id on purpose — must still not arm
    resp = ingest_client.post(
        INGEST_URL,
        ingest_payload(
            source="miner",
            source_id="node-src",
            kind="edge_telemetry",
            body_hex=b"hb".hex(),
        ),
        format="json",
    )
    assert resp.status_code == status.HTTP_202_ACCEPTED, resp.content
    vm.refresh_from_db()
    assert vm.guest_signal_at is None


# ─── the §322 live attestation — the STRONGER, non-universal signal ──


@pytest.fixture
def live_attestation(monkeypatch, settings):
    """`vm_liveness.ingest_live_attestation` with the Rust verifier +
    clock faked — mirrors `test_vm_liveness.py`'s harness."""
    from apps.scheduler.models import VmBillingBinding
    from apps.telemetry import verifier, vm_liveness

    node_id = "aa" * 32
    settings.VALI_KBS_L0_VERIFYING_KEY = "ab" * 32
    now_unix = int(timezone.now().timestamp())
    monkeypatch.setattr(vm_liveness, "_now_unix", lambda: now_unix)

    state = {"seq": 0}

    def _fake(*, envelope: bytes, verifying_key: bytes | None):
        state["seq"] += 1
        return verifier.LiveAttestationFields(
            schema_version=1,
            vm_id="vm-la",
            node_id_hex=node_id,
            attestation_seq=state["seq"],
            epoch=7,
            observed_at_unix=now_unix - 1,
            verified_at_unix=now_unix,
            expiry_unix=now_unix + 900,
            measurement_hex="44" * 48,
            snp_report_digest_hex="11" * 32,
            vcek_chain_digest_hex="22" * 32,
            prev_attestation_hash_hex="00" * 32,
            signer_pubkey_hex="ab" * 32,
            chain_genesis_hex="33" * 32,
            pallet_instance_hex="dd" * 32,
            body_digest_hex=f"{state['seq']:064x}",
        )

    monkeypatch.setattr(vm_liveness.verifier, "verify_live_attestation", _fake)
    from apps.orchestration.models import MeasurementLedger

    MeasurementLedger.objects.create(vm_id="vm-la", launch_digest_hex="44" * 48, allowlist_epoch=1)
    VmBillingBinding.objects.create(
        vm_id="vm-la",
        node_id_hex=node_id,
        resource_class="small",
        lease_id="lease-la",
    )
    return vm_liveness


@override_settings(VALI_GUEST_LIVENESS_STALE_S=600)
def test_live_attestation_arms_the_watermark(live_attestation) -> None:
    """A keepalive-only image (no telemetry agent) is covered by the SAME
    watermark — the freshest of the two signals wins, so neither image
    generation is left without a liveness signal."""
    vm = _make_vm("vm-la")
    assert vm.guest_liveness().state == VmGuestLiveness.UNKNOWN.value

    _, created = live_attestation.ingest_live_attestation(envelope=b"\x01\x02")
    assert created is True

    vm.refresh_from_db()
    assert vm.guest_signal_kind == guest_liveness.SIGNAL_LIVE_ATTESTATION
    assert vm.guest_liveness().state == VmGuestLiveness.ALIVE.value


def test_a_replayed_live_attestation_does_not_refresh_the_watermark(
    live_attestation, monkeypatch
) -> None:
    """A replay is not fresh evidence of life — exactly as it extends no
    billing coverage. Otherwise a miner holding one old attestation could
    keep a dead VM looking alive forever."""
    vm = _make_vm("vm-la")
    live_attestation.ingest_live_attestation(envelope=b"\x01\x02")
    vm.refresh_from_db()
    armed_at = vm.guest_signal_at
    assert armed_at is not None

    # Re-submit the SAME body: the verifier fake is pinned to one seq/digest.
    from apps.telemetry import verifier

    fields = live_attestation.verifier.verify_live_attestation(
        envelope=b"\x01\x02", verifying_key=b"\x00" * 32
    )
    monkeypatch.setattr(
        live_attestation.verifier,
        "verify_live_attestation",
        lambda *, envelope, verifying_key: verifier.LiveAttestationFields(
            **{**fields.__dict__, "attestation_seq": 1, "body_digest_hex": f"{1:064x}"}
        ),
    )
    _, created = live_attestation.ingest_live_attestation(envelope=b"\x01\x02")
    assert created is False

    vm.refresh_from_db()
    assert vm.guest_signal_at == armed_at
