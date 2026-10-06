"""Tests for `GET /v1/vm/<id>/attestation` — the tenant attestation view.

The KBS evidence fetch (`kbs_evidence.fetch_evidence`) is mocked so the
suite runs without a live KBS.
"""

from __future__ import annotations

import time

import pytest
from django.urls import reverse
from rest_framework.test import APIClient

from apps.identity.models import (
    PrincipalScope,
    ServiceClient,
    ServiceToken,
    TokenLifetime,
)
from apps.lifecycle import attestation
from apps.lifecycle import views as lifecycle_views
from apps.lifecycle.attestation import AttestationState
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
        host="miner-a",
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
        node_id="miner-a",
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

def test_attestation_values_match_the_published_schema() -> None:
    # The serializer is schema-only — the view returns a plain dict, so
    # `ChoiceField` never validates at runtime. Without this, adding a state
    # without touching schemas.py would make the published OpenAPI schema
    # silently lie to generated clients.
    from apps.lifecycle.schemas import VmAttestationSerializer

    fields = VmAttestationSerializer().fields
    assert set(fields["attestation_state"].choices) == {s.value for s in AttestationState}
    # The legacy field keeps exactly the three values hippius-backend maps
    # (`compute.services.ATTESTATION_VERDICTS`); anything else reads there
    # as "unknown".
    legacy = {
        attestation.AttestationVerdict(state=s, live=None).legacy_status
        for s in AttestationState
    }
    assert legacy == set(fields["attestation_status"].choices) == {
        "evidence-recorded",
        "no-evidence-recorded",
        "evidence-unavailable",
    }


# ── live attestation (survives a KBS restart) ────────────────────────────

_MEASUREMENT = "ab" * 48
_CHIP = "cc" * 64
_REPORT = "7a" * 32


def _launch(vm_id: str = "vm-att-1", *, measurement: str = _MEASUREMENT) -> None:
    from django.utils import timezone

    from apps.orchestration.models import LaunchJob, LaunchJobState
    from apps.orchestration.tests.factories import make_service_client

    LaunchJob.objects.create(
        job_id=f"j-{vm_id}-{measurement[:4]}",
        vm_id=vm_id,
        tenant_id="t-acme",
        flavor="small",
        userdata_vault_path="x",
        userdata_vault_version=1,
        kek_vault_path="x",
        phase_started_at=timezone.now(),
        decided_by=make_service_client(),
        state=LaunchJobState.SUCCEEDED.value,
        finished_at=timezone.now(),
        result_json={"emit": {"measurement_hex": measurement}},
    )


def _host(miner_id: str = "miner-a", *, chip: str = _CHIP) -> None:
    from apps.miners.models import MinerIdentity

    MinerIdentity.objects.create(
        miner_id=miner_id, pubkey_hex="ab" * 16, platform_id=chip[:64]
    )


_SEQ = iter(range(1, 10_000))


def _live(
    vm_id: str = "vm-att-1",
    *,
    age_s: int,
    source: str = "release",
    measurement: str = _MEASUREMENT,
    chip: str = _CHIP,
    report: str = _REPORT,
    expiry_in_s: int = 600,
) -> int:
    import hashlib

    from apps.telemetry.models import VmLiveAttestation

    seq = next(_SEQ)
    at = int(time.time()) - age_s
    VmLiveAttestation.objects.create(
        vm_id=vm_id,
        node_id_hex="aa" * 32,
        attestation_seq=seq,
        epoch=1,
        observed_at_unix=at,
        verified_at_unix=at,
        expiry_unix=at + expiry_in_s,
        measurement=measurement,
        snp_report_digest="11" * 32,
        body_digest=hashlib.sha256(f"{vm_id}/{seq}".encode()).hexdigest(),
        binding_source=source,
        chip_id=chip,
        report_id=report,
    )
    return seq


@pytest.fixture
def live_vm() -> Vm:
    """An active VM on `miner-a` whose current launch measured `_MEASUREMENT`."""
    vm = _vm()
    _host()
    _launch()
    return vm


def _get(authed_client, monkeypatch, *, evidence: object = None) -> dict:
    def _fetch(vm_id):
        if isinstance(evidence, Exception):
            raise evidence
        return evidence

    monkeypatch.setattr(lifecycle_views.kbs_evidence, "fetch_evidence", _fetch)
    resp = authed_client.get(reverse("vm_attestation", args=["vm-att-1"]))
    assert resp.status_code == 200, resp.content
    return resp.json()


_CURRENT_EVIDENCE = {**_FAKE_EVIDENCE, "measurement_hex": _MEASUREMENT}


def test_released_guest_attesting_after_a_kbs_restart_is_attested_live(
    authed_client, monkeypatch, live_vm
) -> None:
    # The 2026-10-04 incident: the KBS restarted, its release archive was
    # empty (404 for every VM), and every VM read "no-evidence-recorded"
    # while all of them were still attesting every keepalive — as
    # `first-use`, the restarted KBS having lost the release binding.
    _live(age_s=3600, source="release")
    seq = _live(age_s=60, source="first-use")
    body = _get(authed_client, monkeypatch, evidence=None)
    assert body["attestation_state"] == "attested-live"
    assert body["attested"] is True
    assert body["attestation_status"] == "evidence-recorded"
    assert body["kbs_evidence"] is None
    live = body["live_attestation"]
    assert live["attestation_seq"] == seq, "the NEWEST sample is reported"
    assert live["fresh"] is True
    assert 60 <= live["age_s"] < 120
    assert live["max_age_s"] == 600
    assert live["measurement_hex"] == _MEASUREMENT
    assert live["binding_source"] == "first-use"
    assert live["report_id_hex"] == _REPORT


def test_first_use_from_a_guest_never_released_to_proves_nothing(
    authed_client, monkeypatch, live_vm
) -> None:
    # Same chip, same image, but not the guest the KBS released the disk key
    # to — e.g. a second guest the miner booted itself after a KBS restart.
    _live(age_s=3600, source="release")
    _live(age_s=30, source="first-use", report="99" * 32)
    body = _get(authed_client, monkeypatch, evidence=None)
    assert body["attestation_state"] == "stale"
    assert body["live_attestation"]["report_id_hex"] == _REPORT


def test_first_use_without_any_release_on_record_proves_nothing(
    authed_client, monkeypatch, live_vm
) -> None:
    _live(age_s=30, source="first-use")
    body = _get(authed_client, monkeypatch, evidence=None)
    assert body["attestation_state"] == "unproven"
    assert body["live_attestation"] is None


def test_first_use_matching_a_release_of_a_previous_launch_proves_nothing(
    authed_client, monkeypatch, live_vm
) -> None:
    # The release binding must be of THIS launch, not any launch of the VM.
    _live(age_s=3600, source="release", measurement="ef" * 48)
    _live(age_s=30, source="first-use")
    assert _get(authed_client, monkeypatch)["attestation_state"] == "unproven"


def test_samples_from_before_the_current_boot_do_not_vouch(
    authed_client, monkeypatch, live_vm
) -> None:
    # A §25 round trip back to a host: the previous residency's guest
    # attested minutes ago, the current boot has not attested yet.
    from datetime import timedelta

    from django.utils import timezone

    _live(age_s=300)
    Vm.objects.filter(pk=live_vm.pk).update(
        boot_started_at=timezone.now() - timedelta(seconds=120)
    )
    assert _get(authed_client, monkeypatch)["attestation_state"] == "unproven"
    _live(age_s=30)
    assert _get(authed_client, monkeypatch)["attestation_state"] == "attested-live"


def test_unbound_v1_sample_proves_nothing(authed_client, monkeypatch, live_vm) -> None:
    _live(age_s=30, source="")
    assert _get(authed_client, monkeypatch)["attestation_state"] == "unproven"


def test_fresh_live_attestation_wins_over_a_failed_kbs_fetch(
    authed_client, monkeypatch, live_vm
) -> None:
    _live(age_s=60)
    body = _get(authed_client, monkeypatch, evidence=EffectUnavailable("kbs down"))
    assert body["attestation_state"] == "attested-live"
    assert body["attestation_status"] == "evidence-recorded"
    assert body["kbs_evidence_error"]["reason"] == "kbs-unavailable"


def test_live_attestation_of_a_previous_launch_does_not_count(
    authed_client, monkeypatch
) -> None:
    # A relaunch mints a fresh measured nonce: a sample of the old
    # measurement says nothing about the guest running now.
    _vm()
    _host()
    _launch(measurement="cd" * 48)
    _live(age_s=30, measurement=_MEASUREMENT)
    body = _get(authed_client, monkeypatch, evidence=None)
    assert body["attestation_state"] == "unproven"
    assert body["attested"] is None
    assert body["live_attestation"] is None


def test_live_attestation_matches_the_measurement_case_insensitively(
    authed_client, monkeypatch
) -> None:
    _vm()
    _host()
    _launch(measurement=_MEASUREMENT.upper())
    _live(age_s=30)
    assert _get(authed_client, monkeypatch)["attestation_state"] == "attested-live"


def test_no_launch_record_means_no_live_proof(authed_client, monkeypatch) -> None:
    _vm()
    _host()
    _live(age_s=30)
    assert _get(authed_client, monkeypatch)["attestation_state"] == "unproven"


def test_samples_from_another_host_do_not_vouch(authed_client, monkeypatch) -> None:
    # §25 keeps the measurement: right after the cutover the SOURCE guest's
    # samples are still fresh, and must not vouch for the destination.
    _vm()
    _host(chip="dd" * 64)
    _launch()
    _live(age_s=30)
    assert _get(authed_client, monkeypatch)["attestation_state"] == "unproven"


def test_host_without_identity_means_no_live_proof(authed_client, monkeypatch) -> None:
    _vm()
    _launch()
    _live(age_s=30)
    assert _get(authed_client, monkeypatch)["attestation_state"] == "unproven"


@pytest.mark.parametrize(
    ("state", "power"),
    [
        (VmState.ACTIVE, "stopped"),
        (VmState.ACTIVE, "off"),
        (VmState.MIGRATING, ""),
        (VmState.DECOMMISSIONING, ""),
    ],
)
def test_a_vm_not_meant_to_run_is_never_attested_live(
    authed_client, monkeypatch, live_vm, state, power
) -> None:
    extra = {"migration_dest": "miner-b", "new_generation": 3} if state == VmState.MIGRATING else {}
    Vm.objects.filter(pk=live_vm.pk).update(state=state, power_state=power, **extra)
    _live(age_s=30)
    body = _get(authed_client, monkeypatch, evidence=None)
    assert body["attestation_state"] == "stale"
    assert body["live_attestation"]["fresh"] is True


def test_a_sample_past_its_signed_expiry_is_not_fresh(
    authed_client, monkeypatch, live_vm
) -> None:
    _live(age_s=200, expiry_in_s=150)
    body = _get(authed_client, monkeypatch, evidence=None)
    assert body["attestation_state"] == "stale"
    assert body["live_attestation"]["fresh"] is False


def test_max_age_is_configurable(authed_client, monkeypatch, settings, live_vm) -> None:
    settings.VALI_ATTESTATION_LIVE_MAX_AGE_S = 120
    _live(age_s=300, expiry_in_s=900)
    body = _get(authed_client, monkeypatch, evidence=None)
    assert body["attestation_state"] == "stale"
    assert body["live_attestation"]["max_age_s"] == 120


def test_stale_live_attestation_with_release_bundle_is_attested_at_boot(
    authed_client, monkeypatch, live_vm
) -> None:
    # e.g. a stopped VM: it booted attested, it is not attesting now.
    _live(age_s=601)
    body = _get(authed_client, monkeypatch, evidence=_CURRENT_EVIDENCE)
    assert body["attestation_state"] == "attested-at-boot"
    assert body["attested"] is True
    assert body["attestation_status"] == "evidence-recorded"
    assert body["live_attestation"]["fresh"] is False


def test_release_bundle_of_a_previous_launch_does_not_count(
    authed_client, monkeypatch, live_vm
) -> None:
    previous = {**_FAKE_EVIDENCE, "measurement_hex": "ef" * 48}
    body = _get(authed_client, monkeypatch, evidence=previous)
    assert body["attestation_state"] == "unproven"
    assert body["attested"] is None
    # Still relayed verbatim.
    assert body["kbs_evidence"]["measurement_hex"] == "ef" * 48


def test_stale_live_attestation_without_release_bundle_is_stale(
    authed_client, monkeypatch, live_vm
) -> None:
    _live(age_s=3600)
    body = _get(authed_client, monkeypatch, evidence=None)
    assert body["attestation_state"] == "stale"
    assert body["attested"] is None, "stale is unknown, never false"
    assert body["attestation_status"] == "no-evidence-recorded"


def test_a_failed_kbs_fetch_beats_a_stale_sample(authed_client, monkeypatch, live_vm) -> None:
    # The legacy status must still say the KBS could not be asked.
    _live(age_s=3600)
    body = _get(authed_client, monkeypatch, evidence=EffectUnavailable("kbs down"))
    assert body["attestation_state"] == "unavailable"
    assert body["attestation_status"] == "evidence-unavailable"
    assert body["live_attestation"]["fresh"] is False


def test_release_states_without_live_attestation(authed_client, monkeypatch, live_vm) -> None:
    assert _get(authed_client, monkeypatch, evidence=_CURRENT_EVIDENCE)["attestation_state"] == (
        "attested-at-boot"
    )
    assert _get(authed_client, monkeypatch, evidence=None)["attestation_state"] == "unproven"
    assert (
        _get(authed_client, monkeypatch, evidence=EffectUnavailable("x"))["attestation_state"]
        == "unavailable"
    )
