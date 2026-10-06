"""Zombie gate on the guest-frame ingest paths.

A frame for a VM past its §24 crypto-erase must be REFUSED (never billed,
never uptime coverage) and recorded; a frame for a live VM — including a
decommissioning one still draining, and a migrating one — must behave
exactly as before.
"""

from __future__ import annotations

import secrets

import pytest
from django.urls import reverse
from django.utils import timezone
from rest_framework import status
from rest_framework.test import APIClient

from apps.identity.models import PrincipalScope, ServiceClient
from apps.lifecycle.models import Vm, VmState, ZombieObservation
from apps.miners.models import MinerIdentity, MinerStatus
from apps.orchestration import effects
from apps.orchestration.models import DecommissionJob, DecommissionState
from apps.scheduler.models import VmBillingBinding
from apps.telemetry import vm_liveness
from apps.telemetry.models import EnvelopeKind, TelemetryEnvelope, VmLiveAttestation

from .conftest import ingest_payload
from .factories import make_source
from .test_vm_liveness import KBS_L0, NODE_ID, NOW, FakeVerifier

pytestmark = pytest.mark.django_db

INGEST_URL = reverse("telemetry_ingest")
LIVENESS_URL = reverse("telemetry_vm_liveness")


@pytest.fixture(autouse=True)
def _no_erase_grace(settings) -> None:
    settings.VALI_ZOMBIE_ERASE_GRACE_S = 0


@pytest.fixture(autouse=True)
def _no_netbird(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(effects, "resolve_netbird_peer_ip", lambda vm_id: None)


@pytest.fixture
def miner_a() -> MinerIdentity:
    return MinerIdentity.objects.create(
        miner_id="miner-a",
        pubkey_hex=secrets.token_hex(32),
        platform_id=secrets.token_hex(8),
        chain_node_id="aa" * 32,
        status=MinerStatus.ACTIVE.value,
    )


def _vm(vm_id: str, state: str, *, host: str = "miner-a") -> Vm:
    return Vm.objects.create(
        vm_id=vm_id,
        lease_id=f"lease-{vm_id}",
        state=state,
        generation=1,
        new_generation=2 if state == VmState.MIGRATING else None,
        migration_dest="miner-b" if state == VmState.MIGRATING else "",
        host=host,
        lifecycle_vk=bytes(32),
    )


def _job(vm: Vm, *, state: str, erased: bool) -> DecommissionJob:
    now = timezone.now()
    return DecommissionJob.objects.create(
        job_id=secrets.token_hex(16),
        vm=vm,
        state=state,
        phase_started_at=now,
        kek_erased_at=now if erased else None,
        decided_by=ServiceClient.objects.create(
            scope=PrincipalScope.OPERATOR.value, name=f"op-{secrets.token_hex(4)}"
        ),
    )


def _receipt(client: APIClient, vm_id: str, body: bytes = b"receipt-1"):
    return client.post(
        INGEST_URL,
        ingest_payload(
            source="tenant_vm",
            source_id=vm_id,
            kind="served_receipt",
            body_hex=body.hex(),
        ),
        format="json",
    )


def _queued_receipts(vm_id: str) -> int:
    return TelemetryEnvelope.objects.filter(
        source_id=vm_id, kind=EnvelopeKind.SERVED_RECEIPT.value
    ).count()


# ─── served receipts ─────────────────────────────────────────────────


def test_a_live_vms_receipt_is_accepted_and_queued_for_billing(
    ingest_client: APIClient, miner_a
) -> None:
    make_source(source="tenant_vm", source_id="vm-live")
    _vm("vm-live", VmState.ACTIVE)
    assert _receipt(ingest_client, "vm-live").status_code == status.HTTP_202_ACCEPTED
    assert _queued_receipts("vm-live") == 1
    assert not ZombieObservation.objects.exists()


def test_a_migrating_vms_receipt_is_accepted(ingest_client: APIClient, miner_a) -> None:
    make_source(source="tenant_vm", source_id="vm-mig")
    _vm("vm-mig", VmState.MIGRATING)
    assert _receipt(ingest_client, "vm-mig").status_code == status.HTTP_202_ACCEPTED
    assert not ZombieObservation.objects.exists()


def test_a_draining_vms_receipt_is_still_billable(ingest_client: APIClient, miner_a) -> None:
    # §24 in progress but BEFORE the erase: the guest is legitimately up
    # until it acks the stop, and those final minutes are billable.
    make_source(source="tenant_vm", source_id="vm-drain")
    vm = _vm("vm-drain", VmState.DECOMMISSIONING)
    _job(vm, state=DecommissionState.AWAITING_EOL_ACK.value, erased=False)
    assert _receipt(ingest_client, "vm-drain").status_code == status.HTTP_202_ACCEPTED
    assert _queued_receipts("vm-drain") == 1
    assert not ZombieObservation.objects.exists()


def test_an_erased_vms_receipt_is_refused_unbilled_and_observed(
    ingest_client: APIClient, miner_a
) -> None:
    make_source(source="tenant_vm", source_id="vm-z")
    vm = _vm("vm-z", VmState.DECOMMISSIONING)
    _job(vm, state=DecommissionState.CRYPTO_ERASING.value, erased=True)

    resp = _receipt(ingest_client, "vm-z")

    assert resp.status_code == status.HTTP_410_GONE
    assert resp.json()["category"] == "vm-not-live"
    assert _queued_receipts("vm-z") == 0  # never enqueued ⇒ never billed
    row = ZombieObservation.objects.get(vm_id="vm-z")
    assert (row.miner_id, row.attribution, row.last_kind) == (
        "miner-a",
        "destroy-target",
        "served_receipt",
    )


def test_a_destroyed_vms_receipt_is_refused(ingest_client: APIClient, miner_a) -> None:
    make_source(source="tenant_vm", source_id="vm-dead")
    _vm("vm-dead", VmState.DESTROYED, host="")
    assert _receipt(ingest_client, "vm-dead").status_code == status.HTTP_410_GONE
    assert ZombieObservation.objects.filter(vm_id="vm-dead").exists()


def test_a_replay_of_a_receipt_accepted_while_live_is_not_a_zombie(
    ingest_client: APIClient, miner_a
) -> None:
    make_source(source="tenant_vm", source_id="vm-r")
    vm = _vm("vm-r", VmState.ACTIVE)
    assert _receipt(ingest_client, "vm-r").status_code == status.HTTP_202_ACCEPTED

    Vm.objects.filter(pk=vm.pk).update(state=VmState.DESTROYED, host="")
    resp = _receipt(ingest_client, "vm-r")  # byte-identical

    assert resp.status_code == status.HTTP_200_OK  # the old idempotent path
    assert not ZombieObservation.objects.exists()


# ─── live attestations ───────────────────────────────────────────────


@pytest.fixture
def fake_liveness(monkeypatch, settings) -> FakeVerifier:
    settings.VALI_KBS_L0_VERIFYING_KEY = KBS_L0
    monkeypatch.setattr(vm_liveness, "_now_unix", lambda: NOW)
    fake = FakeVerifier()
    monkeypatch.setattr(vm_liveness.verifier, "verify_live_attestation", fake)
    return fake


def _bind(vm_id: str) -> None:
    from apps.orchestration.models import MeasurementLedger

    MeasurementLedger.objects.create(vm_id=vm_id, launch_digest_hex="44" * 48, allowlist_epoch=1)
    VmBillingBinding.objects.create(
        vm_id=vm_id, node_id_hex=NODE_ID, resource_class="small", lease_id="lease-1"
    )


def test_a_live_vms_attestation_still_becomes_coverage(fake_liveness, miner_a) -> None:
    fake_liveness.vm_id = "vm-live"
    _bind("vm-live")
    _vm("vm-live", VmState.ACTIVE)
    resp = APIClient().post(LIVENESS_URL, data=b"\x01", content_type="application/cbor")
    assert resp.status_code == status.HTTP_200_OK
    assert VmLiveAttestation.objects.filter(vm_id="vm-live").count() == 1


def test_an_erased_vms_attestation_is_refused_and_observed(fake_liveness, miner_a) -> None:
    fake_liveness.vm_id = "vm-z"
    _bind("vm-z")
    vm = _vm("vm-z", VmState.DECOMMISSIONING)
    _job(vm, state=DecommissionState.CRYPTO_ERASING.value, erased=True)

    resp = APIClient().post(LIVENESS_URL, data=b"\x01", content_type="application/cbor")

    assert resp.status_code == status.HTTP_410_GONE
    assert not VmLiveAttestation.objects.filter(vm_id="vm-z").exists()  # no coverage
    assert ZombieObservation.objects.get(vm_id="vm-z").last_kind == "vm_live_attestation"


def test_a_receipt_just_after_the_erase_is_still_billed(
    ingest_client: APIClient, miner_a, settings
) -> None:
    # The final drain raced the stop ack: honest, billable, not a zombie.
    settings.VALI_ZOMBIE_ERASE_GRACE_S = 300
    make_source(source="tenant_vm", source_id="vm-flush")
    vm = _vm("vm-flush", VmState.DECOMMISSIONING)
    _job(vm, state=DecommissionState.CRYPTO_ERASING.value, erased=True)
    assert _receipt(ingest_client, "vm-flush").status_code == status.HTTP_202_ACCEPTED
    assert _queued_receipts("vm-flush") == 1
    assert not ZombieObservation.objects.exists()
