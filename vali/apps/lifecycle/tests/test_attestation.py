"""Tests for `GET /v1/vm/<id>/attestation` — the tenant attestation view.

The KBS evidence fetch (`kbs_evidence.fetch_evidence`) is mocked so the
suite runs without a live KBS.
"""

from __future__ import annotations

import pytest
from django.urls import reverse
from rest_framework.test import APIClient

from apps.identity.models import (
    PrincipalScope,
    ServiceClient,
    ServiceToken,
    TokenLifetime,
)
from apps.lifecycle import views as lifecycle_views
from apps.lifecycle.models import Vm, VmState
from apps.orchestration.effects import EffectUnavailable
from apps.orders.models import OrderTicketIntake

pytestmark = pytest.mark.django_db


@pytest.fixture
def authed_client() -> APIClient:
    client = ServiceClient.objects.create(scope=PrincipalScope.OPERATOR.value, name="orchestrator")
    _row, plaintext = ServiceToken.issue(
        client=client,
        name="ops",
        lifetime=TokenLifetime.OPS.value,
    )
    c = APIClient()
    c.credentials(HTTP_AUTHORIZATION=f"Bearer {plaintext}")
    return c


def _vm(vm_id: str = "vm-att-1") -> Vm:
    return Vm.objects.create(
        vm_id=vm_id,
        lease_id="lease-1",
        state=VmState.ACTIVE,
        generation=2,
        host="miner-1",
        lifecycle_vk=bytes(range(32)),
    )


def _ticket(vm_id: str = "vm-att-1") -> OrderTicketIntake:
    return OrderTicketIntake.objects.create(
        ticket_id=f"tk-{vm_id}",
        vm_id=vm_id,
        tenant_id="t-acme",
        user_id="u-7",
        lease_id="lease-1",
        vm_generation=2,
        issue_time=1,
        expiry=2,
        node_id="miner-1",
        platform_id="aa" * 32,
        resource_class="small",
        kid_hex="ab",
        cose_blob=b"\x00",
        received_from="admin",
    )


_FAKE_EVIDENCE = {
    "vm_id": "vm-att-1",
    "measurement_hex": "eb" * 48,
    "snp_report_hex": "00" * 1184,
    "vcek_chain_pem": "-----BEGIN CERTIFICATE-----\n...",
    "boot_counter": 3,
    "kbs_signature_hex": "cd" * 64,
}


def test_attestation_requires_auth() -> None:
    resp = APIClient().get(reverse("vm_attestation", args=["vm-att-1"]))
    assert resp.status_code in (401, 403)


def test_attestation_unknown_vm_is_404(authed_client) -> None:
    resp = authed_client.get(reverse("vm_attestation", args=["nope"]))
    assert resp.status_code == 404


def test_attestation_composes_db_and_kbs_evidence(authed_client, monkeypatch) -> None:
    _vm()
    _ticket()
    monkeypatch.setattr(
        lifecycle_views.kbs_evidence, "fetch_evidence", lambda vm_id: _FAKE_EVIDENCE
    )

    resp = authed_client.get(reverse("vm_attestation", args=["vm-att-1"]))
    assert resp.status_code == 200, resp.content
    body = resp.json()
    assert body["attested"] is True
    # The only status that is a POSITIVE proof — a signed bundle exists.
    assert body["attestation_status"] == "evidence-recorded"
    assert body["tenant_id"] == "t-acme"
    assert body["user_id"] == "u-7"
    assert body["platform_id"] == "aa" * 32
    assert body["lifecycle"]["generation"] == 2
    assert body["lifecycle"]["lifecycle_vk_hex"] == bytes(range(32)).hex()
    # The KBS-signed cryptographic evidence is relayed verbatim.
    assert body["kbs_evidence"]["measurement_hex"] == "eb" * 48
    assert body["kbs_evidence"]["boot_counter"] == 3
    assert body["kbs_evidence_error"] is None


def test_attestation_is_unknown_not_false_when_no_kbs_bundle(
    authed_client, monkeypatch
) -> None:
    # Absent evidence is AMBIGUOUS — the KBS records a bundle only when its
    # §280 sink is configured, and the archive does not survive a restart. So
    # it must NOT be rendered as "this VM is not attested"; that told tenants
    # their genuinely-attested VM was unattested.
    _vm()
    monkeypatch.setattr(
        lifecycle_views.kbs_evidence, "fetch_evidence", lambda vm_id: None
    )
    resp = authed_client.get(reverse("vm_attestation", args=["vm-att-1"]))
    assert resp.status_code == 200
    body = resp.json()
    assert body["attested"] is None, "unknown must never be reported as false"
    assert body["attestation_status"] == "no-evidence-recorded"
    assert body["kbs_evidence"] is None
    # No intake row → tenant/user are null but the view still serves.
    assert body["tenant_id"] is None


def test_attestation_surfaces_kbs_unavailable(authed_client, monkeypatch) -> None:
    _vm()

    def _boom(vm_id):
        raise EffectUnavailable("kbs down")

    monkeypatch.setattr(lifecycle_views.kbs_evidence, "fetch_evidence", _boom)
    resp = authed_client.get(reverse("vm_attestation", args=["vm-att-1"]))
    assert resp.status_code == 200
    body = resp.json()
    # A failed fetch is likewise unknown, not a negative verdict.
    assert body["attested"] is None
    assert body["attestation_status"] == "evidence-unavailable"
    assert body["kbs_evidence_error"]["reason"] == "kbs-unavailable"

def test_attestation_status_values_match_the_published_schema() -> None:
    # The serializer is schema-only — the view returns a plain dict, so
    # `ChoiceField` never validates at runtime. Without this, adding a fourth
    # status in views.py without touching schemas.py would make the published
    # OpenAPI schema silently lie to generated clients.
    import inspect
    import re

    from apps.lifecycle import views as lifecycle_views_mod
    from apps.lifecycle.schemas import VmAttestationSerializer

    src = inspect.getsource(lifecycle_views_mod.VmAttestationView.get)
    emitted = set(re.findall(r'attestation_status = "([a-z-]+)"', src))
    published = set(VmAttestationSerializer().fields["attestation_status"].choices)
    assert emitted, "no attestation_status literals found — did the view change?"
    assert emitted == published, (
        f"view emits {sorted(emitted)} but the schema publishes "
        f"{sorted(published)} — update schemas.py"
    )
