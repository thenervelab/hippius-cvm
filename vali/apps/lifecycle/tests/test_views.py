"""Integration tests for `/v1/vm/<id>/state` + `/v1/vm/<id>/transition`.

Uses DRF's `APIClient`. The Rust validator is mocked at the
`apps.lifecycle.validator.verify_stopped_ack` boundary so the suite
runs fast and doesn't depend on the Cargo build.
"""

from __future__ import annotations

from collections.abc import Iterator
from datetime import timedelta
from pathlib import Path

import pytest
from django.conf import settings
from django.urls import reverse
from rest_framework import status
from rest_framework.test import APIClient

from apps.identity.models import (
    PrincipalScope,
    ServiceClient,
    ServiceToken,
    TokenLifetime,
)
from apps.lifecycle import validator
from apps.lifecycle.models import Vm, VmNetbirdStatus, VmState

pytestmark = pytest.mark.django_db


# ─── Fixtures ────────────────────────────────────────────────────────


@pytest.fixture
def fake_binary(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> Iterator[Path]:
    fake = tmp_path / "hippius-ticket-validator"
    fake.write_text("# placeholder\n")
    fake.chmod(0o755)
    monkeypatch.setattr(settings, "VALI_TICKET_VALIDATOR_BIN", str(fake))
    yield fake


# The `/transition` SM primitive is root-gated (audit H10), matching the
# parallel `/migrate` + `/decommission` orchestration endpoints.
ROOT_PRINCIPAL = "orchestration-root"


@pytest.fixture
def authed_client(monkeypatch: pytest.MonkeyPatch) -> APIClient:
    """Authenticated AS the orchestration-root principal — required for
    the root-gated `/transition` endpoint (audit H10)."""
    monkeypatch.setattr(
        settings, "VALI_ORCHESTRATION_ROOT_PRINCIPAL", ROOT_PRINCIPAL
    )
    client = ServiceClient.objects.create(scope=PrincipalScope.OPERATOR.value, name=ROOT_PRINCIPAL)
    _row, plaintext = ServiceToken.issue(
        client=client,
        name="ops",
        lifetime=TokenLifetime.OPS.value,
    )
    c = APIClient()
    c.credentials(HTTP_AUTHORIZATION=f"Bearer {plaintext}")
    return c


@pytest.fixture
def non_root_client(monkeypatch: pytest.MonkeyPatch) -> APIClient:
    """An authenticated but NON-root `ServiceClient` — must be rejected by
    the root gate on `/transition` (audit H10)."""
    monkeypatch.setattr(
        settings, "VALI_ORCHESTRATION_ROOT_PRINCIPAL", ROOT_PRINCIPAL
    )
    client = ServiceClient.objects.create(
        scope=PrincipalScope.OPERATOR.value,
        name="some-other-tenant-client",
    )
    _row, plaintext = ServiceToken.issue(
        client=client,
        name="ops",
        lifetime=TokenLifetime.OPS.value,
    )
    c = APIClient()
    c.credentials(HTTP_AUTHORIZATION=f"Bearer {plaintext}")
    return c


@pytest.fixture
def active_vm() -> Vm:
    return Vm.objects.create(
        vm_id="vm-1",
        lease_id="lease-1",
        state=VmState.ACTIVE,
        generation=5,
        host="host-a",
        lifecycle_vk=bytes(range(32)),
        # GAP 3: a launched VM carries the launch-baked EOL nonce (set in
        # the measured cmdline + persisted at launch). The transition view
        # PRESERVES it across Active→Migrating / Active→Decommissioning —
        # the guest signs THIS value, so re-minting would break the ack.
        eol_nonce=bytes(range(32, 64)),
    )


def _mock_ack_ok(monkeypatch: pytest.MonkeyPatch) -> None:
    def _ok(**_kw):
        return validator.VerifiedStoppedAck(now_unix=1_700_000_000)

    monkeypatch.setattr(validator, "verify_stopped_ack", _ok)


def _mock_ack_fail(
    monkeypatch: pytest.MonkeyPatch, *, category: str = "stopped-signature"
) -> None:
    def _fail(**_kw):
        raise validator.ValidatorFailed(message="bad sig", category=category)

    monkeypatch.setattr(validator, "verify_stopped_ack", _fail)


# ─── GET /v1/vm/<id>/state ───────────────────────────────────────────


def test_get_state_unauthenticated_rejected() -> None:
    c = APIClient()
    resp = c.get(reverse("vm_state", kwargs={"vm_id": "any"}))
    assert resp.status_code in (status.HTTP_401_UNAUTHORIZED, status.HTTP_403_FORBIDDEN)


def test_get_state_404_unknown_vm(authed_client: APIClient) -> None:
    resp = authed_client.get(reverse("vm_state", kwargs={"vm_id": "missing"}))
    assert resp.status_code == status.HTTP_404_NOT_FOUND
    assert resp.json()["category"] == "not-found"


def test_get_state_returns_serialized_row(
    authed_client: APIClient, active_vm: Vm
) -> None:
    resp = authed_client.get(reverse("vm_state", kwargs={"vm_id": active_vm.vm_id}))
    assert resp.status_code == status.HTTP_200_OK
    body = resp.json()
    assert body["vm_id"] == "vm-1"
    assert body["state"] == "active"
    assert body["generation"] == 5
    assert body["version"] == 1
    # eol_nonce MUST NOT be in the response (server-side secret).
    assert "eol_nonce" not in body
    # The tenant NetBird overlay IP is exposed; empty until resolved.
    assert body["netbird_ip"] == ""


def test_get_state_exposes_resolved_netbird_ip(
    authed_client: APIClient, active_vm: Vm
) -> None:
    active_vm.netbird_ip = "100.64.0.20"
    active_vm.save(update_fields=["netbird_ip"])
    resp = authed_client.get(reverse("vm_state", kwargs={"vm_id": active_vm.vm_id}))
    assert resp.status_code == status.HTTP_200_OK
    assert resp.json()["netbird_ip"] == "100.64.0.20"


def test_get_state_exposes_the_post_migration_overlay_verdict(
    authed_client: APIClient, active_vm: Vm
) -> None:
    """P9/#17 — a §25-migrated VM that lost its NetBird peer is Active and
    reports a (now stale) `netbird_ip`. `netbird_status` is the ONLY field
    that tells a reader the tenant cannot actually reach it."""
    active_vm.netbird_ip = "100.64.0.20"
    active_vm.netbird_status = VmNetbirdStatus.LOST.value
    active_vm.save(update_fields=["netbird_ip", "netbird_status"])
    resp = authed_client.get(reverse("vm_state", kwargs={"vm_id": active_vm.vm_id}))
    assert resp.status_code == status.HTTP_200_OK
    body = resp.json()
    assert body["state"] == "active"
    assert body["netbird_ip"] == "100.64.0.20"  # stale, but preserved
    assert body["netbird_status"] == "lost"


def test_get_state_overlay_verdict_is_empty_by_default(
    authed_client: APIClient, active_vm: Vm
) -> None:
    resp = authed_client.get(reverse("vm_state", kwargs={"vm_id": active_vm.vm_id}))
    assert resp.json()["netbird_status"] == ""


# ─── POST /v1/vm/<id>/transition ─────────────────────────────────────


def test_transition_unauthenticated_rejected(active_vm: Vm) -> None:
    c = APIClient()
    resp = c.post(
        reverse("vm_transition", kwargs={"vm_id": active_vm.vm_id}),
        {"to_state": "decommissioning", "if_version": 1},
        format="json",
    )
    assert resp.status_code in (status.HTTP_401_UNAUTHORIZED, status.HTTP_403_FORBIDDEN)


def test_transition_non_root_service_client_forbidden(
    non_root_client: APIClient, active_vm: Vm
) -> None:
    # Audit H10: a merely-authenticated (non-root) ServiceClient must NOT
    # be able to force a state transition on any VM.
    resp = non_root_client.post(
        reverse("vm_transition", kwargs={"vm_id": active_vm.vm_id}),
        {"to_state": "decommissioning", "if_version": 1},
        format="json",
    )
    assert resp.status_code == status.HTTP_403_FORBIDDEN
    # The VM is untouched — still Active at version 1.
    active_vm.refresh_from_db()
    assert active_vm.state == VmState.ACTIVE
    assert active_vm.version == 1


def test_active_to_decommissioning_preserves_the_launch_baked_eol_nonce(
    authed_client: APIClient, active_vm: Vm
) -> None:
    nonce_before = bytes(active_vm.eol_nonce)
    resp = authed_client.post(
        reverse("vm_transition", kwargs={"vm_id": active_vm.vm_id}),
        {"to_state": "decommissioning", "if_version": 1},
        format="json",
    )
    assert resp.status_code == status.HTTP_200_OK, resp.content
    assert resp.json()["state"] == "decommissioning"
    assert resp.json()["version"] == 2
    active_vm.refresh_from_db()
    # GAP 3: the launch-baked EOL nonce is PRESERVED (NOT re-minted) — it
    # is the value the guest signs its stopped-ack with, which the next
    # step (Decommissioning → Destroyed) verifies against.
    assert active_vm.eol_nonce is not None
    assert bytes(active_vm.eol_nonce) == nonce_before


def test_active_to_migrating_requires_new_generation_and_dest(
    authed_client: APIClient, active_vm: Vm
) -> None:
    resp = authed_client.post(
        reverse("vm_transition", kwargs={"vm_id": active_vm.vm_id}),
        {"to_state": "migrating", "if_version": 1},
        format="json",
    )
    assert resp.status_code == status.HTTP_400_BAD_REQUEST
    assert resp.json()["category"] == "missing-field"


def test_active_to_migrating_happy_path(
    authed_client: APIClient, active_vm: Vm
) -> None:
    resp = authed_client.post(
        reverse("vm_transition", kwargs={"vm_id": active_vm.vm_id}),
        {
            "to_state": "migrating",
            "if_version": 1,
            "new_generation": 6,
            "migration_dest": "host-b",
        },
        format="json",
    )
    assert resp.status_code == status.HTTP_200_OK, resp.content
    body = resp.json()
    assert body["state"] == "migrating"
    assert body["generation"] == 5
    assert body["new_generation"] == 6
    assert body["host"] == "host-a"
    assert body["migration_dest"] == "host-b"
    assert body["version"] == 2


def test_illegal_transition_rejected(
    authed_client: APIClient, active_vm: Vm
) -> None:
    # Active → Destroyed is illegal; the EOL nonce path requires
    # going through Decommissioning first.
    resp = authed_client.post(
        reverse("vm_transition", kwargs={"vm_id": active_vm.vm_id}),
        {"to_state": "destroyed", "if_version": 1},
        format="json",
    )
    assert resp.status_code == status.HTTP_400_BAD_REQUEST
    assert resp.json()["category"] == "illegal-transition"


def test_stale_if_version_returns_409(
    authed_client: APIClient, active_vm: Vm
) -> None:
    # Simulate the TOCTOU race: a concurrent writer bumped the
    # version between the caller's GET and POST. Legality is fine
    # (state is still Active), but the CAS WHERE version=1 finds
    # zero rows.
    Vm.objects.filter(vm_id=active_vm.vm_id, version=1).update(version=2)
    resp = authed_client.post(
        reverse("vm_transition", kwargs={"vm_id": active_vm.vm_id}),
        {"to_state": "decommissioning", "if_version": 1},
        format="json",
    )
    assert resp.status_code == status.HTTP_409_CONFLICT
    assert resp.json()["category"] == "version-conflict"
    # The 409 body echoes the current row so the caller can re-attempt
    # without an extra GET.
    assert resp.json()["current"]["version"] == 2


def test_decommissioning_to_destroyed_requires_signed_ack(
    monkeypatch: pytest.MonkeyPatch,
    fake_binary: Path,
    authed_client: APIClient,
    active_vm: Vm,
) -> None:
    # Step 1: Active → Decommissioning (no ack required).
    r1 = authed_client.post(
        reverse("vm_transition", kwargs={"vm_id": active_vm.vm_id}),
        {"to_state": "decommissioning", "if_version": 1},
        format="json",
    )
    assert r1.status_code == status.HTTP_200_OK
    # Step 2: Decommissioning → Destroyed WITHOUT ack — 400.
    r2 = authed_client.post(
        reverse("vm_transition", kwargs={"vm_id": active_vm.vm_id}),
        {"to_state": "destroyed", "if_version": 2},
        format="json",
    )
    assert r2.status_code == status.HTTP_400_BAD_REQUEST
    assert r2.json()["category"] == "missing-field"

    # Step 3: same transition WITH a valid (mocked) ack → 200.
    _mock_ack_ok(monkeypatch)
    r3 = authed_client.post(
        reverse("vm_transition", kwargs={"vm_id": active_vm.vm_id}),
        {
            "to_state": "destroyed",
            "if_version": 2,
            "signed_stopped_ack_hex": "00" * 8,
        },
        format="json",
    )
    assert r3.status_code == status.HTTP_200_OK, r3.content
    body = r3.json()
    assert body["state"] == "destroyed"
    assert body["host"] == ""  # tombstone
    assert body["version"] == 3

    active_vm.refresh_from_db()
    # EOL nonce MUST be cleared on Destroyed commit.
    assert active_vm.eol_nonce is None


def test_decommissioning_to_destroyed_bad_signature_returns_400(
    monkeypatch: pytest.MonkeyPatch,
    fake_binary: Path,
    authed_client: APIClient,
    active_vm: Vm,
) -> None:
    authed_client.post(
        reverse("vm_transition", kwargs={"vm_id": active_vm.vm_id}),
        {"to_state": "decommissioning", "if_version": 1},
        format="json",
    )
    _mock_ack_fail(monkeypatch, category="stopped-signature")
    resp = authed_client.post(
        reverse("vm_transition", kwargs={"vm_id": active_vm.vm_id}),
        {
            "to_state": "destroyed",
            "if_version": 2,
            "signed_stopped_ack_hex": "00" * 8,
        },
        format="json",
    )
    assert resp.status_code == status.HTTP_400_BAD_REQUEST
    assert resp.json()["category"] == "stopped-signature"


def test_migrating_to_active_requires_signed_ack(
    monkeypatch: pytest.MonkeyPatch,
    fake_binary: Path,
    authed_client: APIClient,
    active_vm: Vm,
) -> None:
    # Active → Migrating(new_gen=6, dest=host-b)
    r1 = authed_client.post(
        reverse("vm_transition", kwargs={"vm_id": active_vm.vm_id}),
        {
            "to_state": "migrating",
            "if_version": 1,
            "new_generation": 6,
            "migration_dest": "host-b",
        },
        format="json",
    )
    assert r1.status_code == status.HTTP_200_OK
    # Complete WITHOUT ack → 400.
    r2 = authed_client.post(
        reverse("vm_transition", kwargs={"vm_id": active_vm.vm_id}),
        {
            "to_state": "active",
            "if_version": 2,
            "new_generation": 6,
        },
        format="json",
    )
    assert r2.status_code == status.HTTP_400_BAD_REQUEST
    assert r2.json()["category"] == "missing-field"

    # Complete WITH ack → 200; gen promotes, host becomes migration_dest.
    _mock_ack_ok(monkeypatch)
    r3 = authed_client.post(
        reverse("vm_transition", kwargs={"vm_id": active_vm.vm_id}),
        {
            "to_state": "active",
            "if_version": 2,
            "new_generation": 6,
            "signed_stopped_ack_hex": "00" * 8,
        },
        format="json",
    )
    assert r3.status_code == status.HTTP_200_OK, r3.content
    body = r3.json()
    assert body["state"] == "active"
    assert body["generation"] == 6
    assert body["host"] == "host-b"
    assert body["migration_dest"] == ""
    assert body["new_generation"] is None


def test_api_migrating_to_active_restarts_the_boot_stall_clock(
    monkeypatch: pytest.MonkeyPatch,
    fake_binary: Path,
    authed_client: APIClient,
    active_vm: Vm,
) -> None:
    """The API §25 completion is a new boot on the destination: the VM must
    be judged on it, not on its original launch time."""
    from django.utils import timezone

    week_ago = timezone.now() - timedelta(days=7)
    Vm.objects.filter(pk=active_vm.pk).update(boot_started_at=week_ago)
    url = reverse("vm_transition", kwargs={"vm_id": active_vm.vm_id})
    r1 = authed_client.post(
        url,
        {"to_state": "migrating", "if_version": 1, "new_generation": 6,
         "migration_dest": "host-b"},
        format="json",
    )
    assert r1.status_code == status.HTTP_200_OK
    assert Vm.objects.get(pk=active_vm.pk).boot_started_at == week_ago

    _mock_ack_ok(monkeypatch)
    r2 = authed_client.post(
        url,
        {"to_state": "active", "if_version": 2, "new_generation": 6,
         "signed_stopped_ack_hex": "00" * 8},
        format="json",
    )
    assert r2.status_code == status.HTTP_200_OK, r2.content
    started = Vm.objects.get(pk=active_vm.pk).boot_started_at
    assert started is not None
    assert (timezone.now() - started).total_seconds() < 5


def test_migrating_to_active_with_wrong_new_generation_rejected(
    monkeypatch: pytest.MonkeyPatch,
    fake_binary: Path,
    authed_client: APIClient,
    active_vm: Vm,
) -> None:
    # Active → Migrating(new_gen=6, dest=host-b)
    authed_client.post(
        reverse("vm_transition", kwargs={"vm_id": active_vm.vm_id}),
        {
            "to_state": "migrating",
            "if_version": 1,
            "new_generation": 6,
            "migration_dest": "host-b",
        },
        format="json",
    )
    _mock_ack_ok(monkeypatch)
    # Caller claims new_generation=7 — disagrees with the stored row.
    resp = authed_client.post(
        reverse("vm_transition", kwargs={"vm_id": active_vm.vm_id}),
        {
            "to_state": "active",
            "if_version": 2,
            "new_generation": 7,
            "signed_stopped_ack_hex": "00" * 8,
        },
        format="json",
    )
    assert resp.status_code == status.HTTP_400_BAD_REQUEST
    assert resp.json()["category"] == "generation-mismatch"


def test_destroyed_is_terminal(
    monkeypatch: pytest.MonkeyPatch,
    fake_binary: Path,
    authed_client: APIClient,
    active_vm: Vm,
) -> None:
    # Drive Active → Decommissioning → Destroyed.
    authed_client.post(
        reverse("vm_transition", kwargs={"vm_id": active_vm.vm_id}),
        {"to_state": "decommissioning", "if_version": 1},
        format="json",
    )
    _mock_ack_ok(monkeypatch)
    authed_client.post(
        reverse("vm_transition", kwargs={"vm_id": active_vm.vm_id}),
        {
            "to_state": "destroyed",
            "if_version": 2,
            "signed_stopped_ack_hex": "00" * 8,
        },
        format="json",
    )
    # Now try to transition OUT of Destroyed.
    resp = authed_client.post(
        reverse("vm_transition", kwargs={"vm_id": active_vm.vm_id}),
        {"to_state": "active", "if_version": 3, "new_generation": 100},
        format="json",
    )
    assert resp.status_code == status.HTTP_400_BAD_REQUEST
    assert resp.json()["category"] == "illegal-transition"


def test_malformed_body_returns_400(
    authed_client: APIClient, active_vm: Vm
) -> None:
    resp = authed_client.post(
        reverse("vm_transition", kwargs={"vm_id": active_vm.vm_id}),
        {"if_version": 1},  # missing to_state
        format="json",
    )
    assert resp.status_code == status.HTTP_400_BAD_REQUEST
    assert resp.json()["category"] == "wire"


# ─── PR-G2 review fixes ──────────────────────────────────────────────


def test_migrating_with_non_monotonic_new_generation_rejected(
    authed_client: APIClient, active_vm: Vm
) -> None:
    # §25 generation fencing: new_generation MUST be > current.
    # `==` would skip the fence; `<` inverts it.
    resp = authed_client.post(
        reverse("vm_transition", kwargs={"vm_id": active_vm.vm_id}),
        {
            "to_state": "migrating",
            "if_version": 1,
            "new_generation": active_vm.generation,  # ==, must be >
            "migration_dest": "host-b",
        },
        format="json",
    )
    assert resp.status_code == status.HTTP_400_BAD_REQUEST
    assert resp.json()["category"] == "generation-mismatch"


def test_migrating_with_lower_new_generation_rejected(
    authed_client: APIClient, active_vm: Vm
) -> None:
    resp = authed_client.post(
        reverse("vm_transition", kwargs={"vm_id": active_vm.vm_id}),
        {
            "to_state": "migrating",
            "if_version": 1,
            "new_generation": active_vm.generation - 1,
            "migration_dest": "host-b",
        },
        format="json",
    )
    assert resp.status_code == status.HTTP_400_BAD_REQUEST
    assert resp.json()["category"] == "generation-mismatch"


def test_negative_new_generation_rejected_at_wire(
    authed_client: APIClient, active_vm: Vm
) -> None:
    # Rust mirror is `u64`; negatives are rejected at intake so they
    # never touch the DB or the subprocess.
    resp = authed_client.post(
        reverse("vm_transition", kwargs={"vm_id": active_vm.vm_id}),
        {
            "to_state": "migrating",
            "if_version": 1,
            "new_generation": -1,
            "migration_dest": "host-b",
        },
        format="json",
    )
    assert resp.status_code == status.HTTP_400_BAD_REQUEST
    assert resp.json()["category"] == "wire"


def test_oversized_new_generation_rejected_at_wire(
    authed_client: APIClient, active_vm: Vm
) -> None:
    # Postgres BIGINT is signed i64. `u64::MAX` would overflow.
    resp = authed_client.post(
        reverse("vm_transition", kwargs={"vm_id": active_vm.vm_id}),
        {
            "to_state": "migrating",
            "if_version": 1,
            "new_generation": 2**63,
            "migration_dest": "host-b",
        },
        format="json",
    )
    assert resp.status_code == status.HTTP_400_BAD_REQUEST
    assert resp.json()["category"] == "wire"


def test_if_version_bool_rejected_at_wire(
    authed_client: APIClient, active_vm: Vm
) -> None:
    # JSON `true` arrives as Python `bool`. `int(True) == 1` would
    # silently match an `if_version=1` row; reject explicitly.
    resp = authed_client.post(
        reverse("vm_transition", kwargs={"vm_id": active_vm.vm_id}),
        {"to_state": "decommissioning", "if_version": True},
        format="json",
    )
    assert resp.status_code == status.HTTP_400_BAD_REQUEST
    assert resp.json()["category"] == "wire"


def test_oversized_signed_stopped_ack_hex_rejected_at_wire(
    fake_binary: Path, authed_client: APIClient, active_vm: Vm
) -> None:
    # Active → Decommissioning so an EOL nonce is minted.
    authed_client.post(
        reverse("vm_transition", kwargs={"vm_id": active_vm.vm_id}),
        {"to_state": "decommissioning", "if_version": 1},
        format="json",
    )
    # Then send an over-cap hex string — must be rejected BEFORE
    # `bytes.fromhex` allocates and BEFORE subprocess spawns.
    over_cap = "ab" * (settings.VALI_STOPPED_ACK_MAX_HEX_LEN)  # 2× the cap
    resp = authed_client.post(
        reverse("vm_transition", kwargs={"vm_id": active_vm.vm_id}),
        {
            "to_state": "destroyed",
            "if_version": 2,
            "signed_stopped_ack_hex": over_cap,
        },
        format="json",
    )
    assert resp.status_code == status.HTTP_400_BAD_REQUEST
    assert resp.json()["category"] == "stopped-decode"


def test_cas_rejects_when_state_mutated_out_of_band(
    authed_client: APIClient, active_vm: Vm
) -> None:
    # Defense-in-depth: even if a future writer DOESN'T bump
    # `version`, the CAS WHERE clause requires the state to match.
    # Simulate: state mutated to Decommissioning out-of-band but
    # version stays at 1. The caller still holds if_version=1 +
    # expects state=Active for the Active→Decommissioning
    # transition — but the row is already Decommissioning, so the
    # legality check rejects the transition (since
    # Decommissioning→Decommissioning is illegal).
    Vm.objects.filter(vm_id=active_vm.vm_id).update(state=VmState.DECOMMISSIONING)
    resp = authed_client.post(
        reverse("vm_transition", kwargs={"vm_id": active_vm.vm_id}),
        {"to_state": "decommissioning", "if_version": 1},
        format="json",
    )
    # `legal()` fires before CAS so this is illegal-transition.
    # The CAS-state-pin is the defense for the case where two
    # writers race after BOTH passed legality on the old state —
    # the next test below covers that.
    assert resp.status_code == status.HTTP_400_BAD_REQUEST
    assert resp.json()["category"] == "illegal-transition"


def test_cas_rejects_when_state_mutated_during_request(
    monkeypatch: pytest.MonkeyPatch,
    fake_binary: Path,
    authed_client: APIClient,
    active_vm: Vm,
) -> None:
    # Race scenario the CAS state-pin defends against: the view has
    # loaded `vm` (state=Active), is mid-stopped-ack-verify, and a
    # concurrent writer flips state to Decommissioning + version
    # bumps. The CAS UPDATE with state=Active should now match 0
    # rows — 409 instead of corrupting the row.
    #
    # We simulate by triggering the state mutation inside the
    # ack-verify mock — runs BEFORE the CAS.
    active_vm.state = VmState.DECOMMISSIONING
    active_vm.version = 1  # version stays!
    active_vm.eol_nonce = bytes(32)
    active_vm.save(update_fields=["state", "version", "eol_nonce"])

    def _verify_and_race(**_kw):
        # Concurrent writer mutates the row to a NEW state but does
        # NOT bump version (simulating a misbehaving PR-G5 writer).
        Vm.objects.filter(vm_id=active_vm.vm_id).update(state=VmState.DESTROYED)
        return validator.VerifiedStoppedAck(now_unix=1_700_000_000)

    monkeypatch.setattr(validator, "verify_stopped_ack", _verify_and_race)
    resp = authed_client.post(
        reverse("vm_transition", kwargs={"vm_id": active_vm.vm_id}),
        {
            "to_state": "destroyed",
            "if_version": 1,
            "signed_stopped_ack_hex": "00" * 8,
        },
        format="json",
    )
    # CAS rejects because state no longer matches the pre-image.
    assert resp.status_code == status.HTTP_409_CONFLICT
    assert resp.json()["category"] == "version-conflict"


# ─── §23 placement custody on the manual migration completion ────────
#
# `/transition` Migrating→Active is the OTHER writer of `Vm.host` (it
# promotes `migration_dest`), so it is the other door through which the
# §23 placement ledger could be left naming the SOURCE forever.


def _seed_placement(vm: Vm, miner_node_id: str):
    from apps.scheduler.models import Placement, PlacementStatus

    return Placement.objects.create(
        vm=vm,
        vm_family="tenant-1",
        owner="user-1",
        resource_class="small",
        miner_node_id=miner_node_id,
        status=PlacementStatus.BOUND.value,
        chain_epoch=10,
        bound_at=vm.created_at,
        decided_by=ServiceClient.objects.create(
            scope=PrincipalScope.OPERATOR.value, name="launcher"
        ),
    )


def _complete_migration(
    client: APIClient, vm: Vm, monkeypatch: pytest.MonkeyPatch, dest: str
):
    client.post(
        reverse("vm_transition", kwargs={"vm_id": vm.vm_id}),
        {
            "to_state": "migrating",
            "if_version": 1,
            "new_generation": 6,
            "migration_dest": dest,
        },
        format="json",
    )
    _mock_ack_ok(monkeypatch)
    return client.post(
        reverse("vm_transition", kwargs={"vm_id": vm.vm_id}),
        {
            "to_state": "active",
            "if_version": 2,
            "new_generation": 6,
            "signed_stopped_ack_hex": "00" * 8,
        },
        format="json",
    )


def test_transition_completing_a_migration_moves_the_placement(
    monkeypatch: pytest.MonkeyPatch,
    fake_binary: Path,
    authed_client: APIClient,
    active_vm: Vm,
) -> None:
    from apps.miners.models import MinerIdentity
    from apps.scheduler.models import ACTIVE_PLACEMENT_STATES, Placement

    src, dst = "aa" * 32, "bb" * 32
    _seed_placement(active_vm, src)
    MinerIdentity.objects.create(
        miner_id="host-b",
        pubkey_hex="11" * 32,
        platform_id="22" * 16,
        chain_node_id=dst,
    )

    resp = _complete_migration(authed_client, active_vm, monkeypatch, "host-b")

    assert resp.status_code == status.HTTP_200_OK, resp.content
    assert resp.json()["host"] == "host-b"
    active = list(
        Placement.objects.filter(vm=active_vm, status__in=ACTIVE_PLACEMENT_STATES)
    )
    assert [p.miner_node_id for p in active] == [dst]


def test_transition_with_an_unnameable_dest_keeps_the_placement(
    monkeypatch: pytest.MonkeyPatch,
    fake_binary: Path,
    authed_client: APIClient,
    active_vm: Vm,
) -> None:
    """Fail-safe: an unregistered destination must not strip the VM out of
    the §13 admission / #668 fit-gate accounting altogether."""
    from apps.scheduler.models import ACTIVE_PLACEMENT_STATES, Placement

    src = "aa" * 32
    _seed_placement(active_vm, src)

    resp = _complete_migration(authed_client, active_vm, monkeypatch, "host-b")

    assert resp.status_code == status.HTTP_200_OK, resp.content
    active = list(
        Placement.objects.filter(vm=active_vm, status__in=ACTIVE_PLACEMENT_STATES)
    )
    assert [p.miner_node_id for p in active] == [src]


# ─── reboot-recovery scope on the manual migration completion ────────
#
# The SAME door. `RebootRecovery` holds HOST-scoped state (the relaunch
# cap, the backoff window, the debounces), so this writer of `Vm.host`
# must re-scope it too — or a VM that exhausted its relaunch budget on the
# source arrives at the destination already at the cap and can never be
# reboot-recovered there.


def _seed_exhausted_recovery(vm: Vm, host: str):
    from apps.orchestration.models import RebootRecovery

    return RebootRecovery.objects.create(
        vm=vm,
        host=host,
        seen_running=True,
        consecutive_down=4,
        attempts=5,
        last_relaunch_at=vm.created_at,
        next_attempt_at=vm.created_at + timedelta(hours=1),
        last_outcome="attempts-exhausted",
    )


def test_transition_completing_a_migration_re_scopes_reboot_recovery(
    monkeypatch: pytest.MonkeyPatch,
    fake_binary: Path,
    authed_client: APIClient,
    active_vm: Vm,
) -> None:
    from apps.orchestration.models import RebootRecovery

    before = _seed_exhausted_recovery(active_vm, "host-a")

    resp = _complete_migration(authed_client, active_vm, monkeypatch, "host-b")

    assert resp.status_code == status.HTTP_200_OK, resp.content
    assert resp.json()["host"] == "host-b"
    rec = RebootRecovery.objects.get(vm=active_vm)
    assert rec.host == "host-b"
    assert rec.attempts == 0
    assert rec.next_attempt_at is None
    assert rec.consecutive_down == 0
    assert rec.last_outcome == "host-changed"
    assert rec.version > before.version
    # A fact about the VM's PAST — a host change does not falsify it, and
    # clearing it would leave a destination that never comes up with no
    # automated remedy at all.
    assert rec.seen_running is True


def test_a_rejected_transition_re_scopes_nothing(
    monkeypatch: pytest.MonkeyPatch,
    fake_binary: Path,
    authed_client: APIClient,
    active_vm: Vm,
) -> None:
    """A stale `if_version` loses the CAS, so the VM never moves — and its
    relaunch budget must not be re-issued either."""
    from apps.orchestration.models import RebootRecovery

    before = _seed_exhausted_recovery(active_vm, "host-a")
    authed_client.post(
        reverse("vm_transition", kwargs={"vm_id": active_vm.vm_id}),
        {
            "to_state": "migrating",
            "if_version": 1,
            "new_generation": 6,
            "migration_dest": "host-b",
        },
        format="json",
    )
    _mock_ack_ok(monkeypatch)

    resp = authed_client.post(
        reverse("vm_transition", kwargs={"vm_id": active_vm.vm_id}),
        {
            "to_state": "active",
            "if_version": 99,
            "new_generation": 6,
            "signed_stopped_ack_hex": "00" * 8,
        },
        format="json",
    )

    assert resp.status_code == status.HTTP_409_CONFLICT
    rec = RebootRecovery.objects.get(vm=active_vm)
    assert (rec.host, rec.attempts, rec.version) == (
        "host-a",
        before.attempts,
        before.version,
    )


def test_active_to_migrating_refuses_a_zombie_quarantined_destination(
    authed_client: APIClient, active_vm: Vm
) -> None:
    # The root transition primitive names the destination explicitly, so
    # the scheduler's zombie gate never sees it — it must refuse itself.
    from apps.lifecycle import zombie
    from apps.miners.models import MinerIdentity, MinerStatus

    MinerIdentity.objects.create(
        miner_id="host-b",
        pubkey_hex="ab" * 32,
        platform_id="0123456789abcdef",
        chain_node_id="bb" * 32,
        status=MinerStatus.ACTIVE.value,
    )
    dead = Vm.objects.create(
        vm_id="vm-dead",
        lease_id="lease-dead",
        state=VmState.DESTROYED,
        generation=1,
        host="",
        lifecycle_vk=bytes(32),
    )
    zombie.observe(dead, kind="vm_live_attestation", relay_miner_id="host-b")

    resp = authed_client.post(
        reverse("vm_transition", kwargs={"vm_id": active_vm.vm_id}),
        {
            "to_state": "migrating",
            "if_version": 1,
            "new_generation": 6,
            "migration_dest": "host-b",
        },
        format="json",
    )
    assert resp.status_code == status.HTTP_409_CONFLICT, resp.content
    assert resp.json()["category"] == "dest-zombie-quarantined"
    active_vm.refresh_from_db()
    assert active_vm.state == VmState.ACTIVE
