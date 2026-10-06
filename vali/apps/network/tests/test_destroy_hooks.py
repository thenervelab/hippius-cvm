"""A destroyed VM releases its public IP on both destroy paths — without
waiting for `reconcile`, whose sweep is only the backstop."""

from __future__ import annotations

from pathlib import Path

import pytest
from django.conf import settings
from django.urls import reverse
from rest_framework.test import APIClient

from apps.lifecycle import validator
from apps.lifecycle.models import Vm, VmPowerState, VmState
from apps.network import service
from apps.network.models import PublicIpState
from apps.orchestration import service as orchestration
from apps.orchestration.tests.factories import make_service_client

from .conftest import make_edge, make_vm

pytestmark = pytest.mark.django_db


def _attached_vm() -> tuple[Vm, int]:
    make_edge()
    vm = make_vm(host="host-a")
    ip, _ = service.attach(vm)
    return vm, ip.pk


def test_the_decommission_destroy_releases_the_address() -> None:
    vm, ip_pk = _attached_vm()
    job = orchestration.start_decommission(vm=vm, decided_by=make_service_client())
    Vm.objects.filter(pk=vm.pk).update(state=VmState.DECOMMISSIONING)

    orchestration._destroy_vm(job)

    vm.refresh_from_db()
    assert vm.state == VmState.DESTROYED
    assert service.get_attached(vm) is None
    assert vm.public_ips.get(pk=ip_pk).state == PublicIpState.QUARANTINED


def test_the_transition_to_destroyed_releases_the_address(
    root_client: APIClient, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    vm, ip_pk = _attached_vm()
    Vm.objects.filter(pk=vm.pk).update(state=VmState.DECOMMISSIONING, eol_nonce=b"\x11" * 32)
    fake = tmp_path / "validator"
    fake.write_text("")
    fake.chmod(0o755)
    monkeypatch.setattr(settings, "VALI_TICKET_VALIDATOR_BIN", str(fake))
    monkeypatch.setattr(
        validator,
        "verify_stopped_ack",
        lambda **_kw: validator.VerifiedStoppedAck(now_unix=1_700_000_000),
    )

    r = root_client.post(
        reverse("vm_transition", kwargs={"vm_id": vm.vm_id}),
        {"to_state": "destroyed", "if_version": vm.version, "signed_stopped_ack_hex": "00" * 8},
        format="json",
    )

    assert r.status_code == 200, r.content
    assert r.json()["public_ip"] is None
    vm.refresh_from_db()
    assert vm.power_state == VmPowerState.OFF and vm.power_state_at is not None
    assert vm.public_ips.get(pk=ip_pk).state == PublicIpState.QUARANTINED


def test_a_failing_release_never_fails_the_destroy(monkeypatch: pytest.MonkeyPatch) -> None:
    vm, _ = _attached_vm()

    def _boom(*_a, **_kw):
        raise RuntimeError("db hiccup")

    monkeypatch.setattr(service, "detach", _boom)
    service.release_for_destroyed_vm(vm)  # logged, not raised
