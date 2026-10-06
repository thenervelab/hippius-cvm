"""Blackbox host-attestor admin-release + desired + reconcile (PR-9).

Covers the four PR-9 make-or-break behaviours:

- `POST /v1/admin/host-attestor/release` cosign-verify happy-path (mocked
  cosign) pins the measurement under class=host_attestor + records an
  active release;
- an unsigned / identity-unpinned cosign verdict is REJECTED (no pin, no
  release row) — fail-closed;
- `GET /v1/miner/<node>/host-attestor/desired` returns the active release
  and the {current, previous} grace window across a rolling update;
- the reconcile computes coverage from `attested` rows ONLY (a `pending`
  row is NEVER coverage — the HARD CONSTRAINT).

The cosign shell-out (`cosign_verify.verify_blob`), the §22 pin
(`allowlist_pin.pin_measurement`), and the on-chain fleet read
(`chain.read_miner_status`) are all mocked so the gate + persistence logic
runs without cosign / a signing seed / an RPC.
"""

from __future__ import annotations

import base64
from datetime import timedelta
from typing import Any

import pytest
from django.conf import settings
from django.urls import reverse
from django.utils import timezone
from rest_framework.test import APIClient

from apps.identity.models import (
    PrincipalScope,
    ServiceClient,
    ServiceToken,
    TokenLifetime,
)
from apps.orchestration.services import allowlist_pin
from apps.telemetry import cosign_verify, release_service
from apps.telemetry.models import (
    HostAttestor,
    HostAttestorRelease,
    HostAttestorStatus,
)

pytestmark = pytest.mark.django_db

ADMIN_PRINCIPAL = "host-attestor-admin"
RELEASE_URL = reverse("host_attestor_release")

MEAS_A = "a1" * 48  # 96 hex
MEAS_B = "b2" * 48
NODE_1 = "11" * 32
NODE_2 = "22" * 32
CHIP_1 = "c1" * 64
CHIP_2 = "c2" * 64
SIGNER = "ee" * 32

_CERT_PEM = "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n"
_SIG_B64 = base64.b64encode(b"a-detached-signature").decode()
_ARTIFACT_B64 = base64.b64encode(b"a-blackbox-uki-blob").decode()


# ─── fixtures ────────────────────────────────────────────────────────


@pytest.fixture(autouse=True)
def _pin_settings(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        settings, "VALI_HOST_ATTESTOR_ADMIN_PRINCIPAL", ADMIN_PRINCIPAL
    )
    monkeypatch.setattr(
        settings, "VALI_HOST_ATTESTOR_COSIGN_IDENTITY", "https://ci/workflow.yml@refs/heads/main"
    )
    monkeypatch.setattr(
        settings,
        "VALI_HOST_ATTESTOR_COSIGN_ISSUER",
        "https://token.actions.githubusercontent.com",
    )


def _bearer_client(name: str) -> APIClient:
    client = ServiceClient.objects.create(scope=PrincipalScope.OPERATOR.value, name=name)
    _row, plaintext = ServiceToken.issue(
        client=client,
        name="ops",
        lifetime=TokenLifetime.OPS.value,
    )
    api = APIClient()
    api.credentials(HTTP_AUTHORIZATION=f"Bearer {plaintext}")
    return api


@pytest.fixture
def admin_client() -> APIClient:
    return _bearer_client(ADMIN_PRINCIPAL)


class FakeCosign:
    """Stand-in for `cosign_verify.verify_blob`. `outcome` steers it."""

    def __init__(self) -> None:
        self.outcome = "ok"  # "ok" | "failed" | "unpinned" | "unavailable"
        self.calls: list[dict[str, Any]] = []

    def verify_blob(
        self, *, artifact: bytes, signature_b64: str, certificate_pem: str
    ) -> cosign_verify.CosignPins:
        self.calls.append(
            {
                "artifact": artifact,
                "signature_b64": signature_b64,
                "certificate_pem": certificate_pem,
            }
        )
        if self.outcome == "ok":
            return cosign_verify.CosignPins(
                identity="https://ci/workflow.yml@refs/heads/main",
                issuer="https://token.actions.githubusercontent.com",
            )
        if self.outcome == "unavailable":
            raise cosign_verify.CosignUnavailable("injected unavailable")
        if self.outcome == "unpinned":
            raise cosign_verify.CosignVerifyFailed(
                "identity unpinned", category="identity-unpinned"
            )
        raise cosign_verify.CosignVerifyFailed(
            "signature invalid", category="cosign-rejected"
        )


class FakePin:
    """Stand-in for `allowlist_pin.pin_measurement` — records the class."""

    def __init__(self) -> None:
        self.calls: list[dict[str, Any]] = []
        self.epoch = 99_000

    def pin_measurement(
        self,
        *,
        measurement_hex: str,
        measurement_class: str = allowlist_pin.ALLOWLIST_CLASS_TENANT,
        ledger: allowlist_pin.PinLedger | None = None,
        **_: Any,
    ) -> allowlist_pin.PinResult:
        self.calls.append(
            {
                "measurement_hex": measurement_hex,
                "measurement_class": measurement_class,
                "ledger": ledger,
            }
        )
        self.epoch += 1
        result = allowlist_pin.PinResult(
            new_epoch=self.epoch,
            new_cose_sha256_hex="00" * 32,
            s3_url="s3://x/y",
        )
        if ledger is not None:
            # What the real pin does under its lock once the KBS installed.
            allowlist_pin._record_ledger(ledger, measurement_hex, measurement_class, result)
        return result


@pytest.fixture
def fake_cosign(monkeypatch: pytest.MonkeyPatch) -> FakeCosign:
    fake = FakeCosign()
    monkeypatch.setattr(cosign_verify, "verify_blob", fake.verify_blob)
    # release_service imported the symbol into its own namespace's module ref.
    monkeypatch.setattr(release_service.cosign_verify, "verify_blob", fake.verify_blob)
    return fake


@pytest.fixture
def fake_pin(monkeypatch: pytest.MonkeyPatch) -> FakePin:
    fake = FakePin()
    monkeypatch.setattr(allowlist_pin, "pin_measurement", fake.pin_measurement)
    monkeypatch.setattr(
        release_service.allowlist_pin, "pin_measurement", fake.pin_measurement
    )
    return fake


def _release_body(**overrides: Any) -> dict[str, Any]:
    body = {
        "measurement_hex": MEAS_A,
        "version": "v1",
        "generation": "genoa",
        "artifact_b64": _ARTIFACT_B64,
        "cosign_signature_b64": _SIG_B64,
        "cosign_certificate_pem": _CERT_PEM,
    }
    body.update(overrides)
    return body


# ─── admin-release: happy path + class pin ───────────────────────────


def test_release_cosign_ok_pins_host_attestor_class(
    admin_client: APIClient, fake_cosign: FakeCosign, fake_pin: FakePin
) -> None:
    resp = admin_client.post(RELEASE_URL, _release_body(), format="json")
    assert resp.status_code == 201, resp.data
    # The pin landed under the host_attestor CLASS (never tenant).
    assert len(fake_pin.calls) == 1
    assert fake_pin.calls[0]["measurement_class"] == "host_attestor"
    assert fake_pin.calls[0]["measurement_hex"] == MEAS_A
    # An active release row exists.
    row = HostAttestorRelease.objects.get(measurement=MEAS_A)
    assert row.is_active is True
    assert row.cosign_identity == "https://ci/workflow.yml@refs/heads/main"
    assert resp.data["allowlist_epoch"] == fake_pin.epoch
    # The pin records the audit-ledger row (under its lock, with the pin's
    # HOST-ATTESTOR class — the §22 carry-forward reads that column as a
    # veto: a blank/`tenant` value would let a later re-pin re-emit this
    # measurement as tenant).
    assert fake_pin.calls[0]["ledger"] == allowlist_pin.PinLedger(
        vm_id="host-attestor-release"
    )


def test_a_release_row_failure_after_the_install_keeps_the_ledger_row(
    fake_cosign: FakeCosign, fake_pin: FakePin, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Step 3 fails AFTER the KBS installed the measurement: the pin's
    ledger row must still commit — it is the epoch floor and the class
    veto that stops a later pin re-emitting this measurement as tenant —
    while the half-written release row rolls back and the error surfaces."""
    from apps.orchestration.models import MeasurementLedger

    def boom(generation: str) -> None:
        raise RuntimeError("db hiccup in step 3")

    monkeypatch.setattr(release_service, "_trim_grace_window", boom)

    with pytest.raises(RuntimeError, match="db hiccup in step 3"):
        release_service.admit_release(
            measurement_hex=MEAS_A,
            version="v1",
            generation="genoa",
            artifact=b"a-blackbox-uki-blob",
            signature_b64=_SIG_B64,
            certificate_pem=_CERT_PEM,
        )

    assert len(fake_pin.calls) == 1
    row = MeasurementLedger.objects.get(vm_id="host-attestor-release")
    assert row.launch_digest_hex == MEAS_A
    assert row.measurement_class == allowlist_pin.ALLOWLIST_CLASS_HOST_ATTESTOR
    assert not HostAttestorRelease.objects.filter(measurement=MEAS_A).exists()


def test_a_generation_conflict_raced_in_before_the_lock_is_refused_unpinned(
    admin_client: APIClient,
    fake_cosign: FakeCosign,
    fake_pin: FakePin,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The generation pre-check runs before cosign, outside the pin lock. A
    conflicting release recorded in that window is caught UNDER the lock,
    before the pin — not in step 3, after the KBS already installed it."""
    real_verify = fake_cosign.verify_blob

    def verify_while_milan_is_admitted(**kwargs: Any) -> cosign_verify.CosignPins:
        _active_release(MEAS_A, generation="milan")
        return real_verify(**kwargs)

    monkeypatch.setattr(
        release_service.cosign_verify, "verify_blob", verify_while_milan_is_admitted
    )

    resp = admin_client.post(RELEASE_URL, _release_body(generation="genoa"), format="json")

    assert resp.status_code == 409, resp.data
    assert resp.data["category"] == "generation-conflict"
    assert fake_pin.calls == []


def test_release_rejects_unsigned_no_pin_no_row(
    admin_client: APIClient, fake_cosign: FakeCosign, fake_pin: FakePin
) -> None:
    fake_cosign.outcome = "failed"
    resp = admin_client.post(RELEASE_URL, _release_body(), format="json")
    assert resp.status_code == 400
    assert resp.data["category"] == "cosign-rejected"
    # Fail-closed: no pin, no release row.
    assert fake_pin.calls == []
    assert not HostAttestorRelease.objects.filter(measurement=MEAS_A).exists()


def test_release_rejects_identity_unpinned(
    admin_client: APIClient, fake_cosign: FakeCosign, fake_pin: FakePin
) -> None:
    fake_cosign.outcome = "unpinned"
    resp = admin_client.post(RELEASE_URL, _release_body(), format="json")
    assert resp.status_code == 400
    assert resp.data["category"] == "identity-unpinned"
    assert fake_pin.calls == []


def test_release_requires_admin_principal(
    fake_cosign: FakeCosign, fake_pin: FakePin
) -> None:
    non_admin = _bearer_client("sentinel-reader")
    resp = non_admin.post(RELEASE_URL, _release_body(), format="json")
    assert resp.status_code == 403
    assert fake_pin.calls == []


def test_release_bad_measurement_rejected(
    admin_client: APIClient, fake_cosign: FakeCosign, fake_pin: FakePin
) -> None:
    resp = admin_client.post(
        RELEASE_URL, _release_body(measurement_hex="zz" * 48), format="json"
    )
    assert resp.status_code == 400
    # A malformed measurement is refused before the §22 pin — no pin happens.
    assert fake_pin.calls == []


# ─── desired + grace window ──────────────────────────────────────────


def test_desired_returns_current_and_previous_grace_window(
    admin_client: APIClient, fake_cosign: FakeCosign, fake_pin: FakePin
) -> None:
    # Admit A then B — B is current, A is previous (both active).
    a = admin_client.post(RELEASE_URL, _release_body(measurement_hex=MEAS_A), format="json")
    assert a.status_code == 201
    b = admin_client.post(
        RELEASE_URL, _release_body(measurement_hex=MEAS_B, version="v2"), format="json"
    )
    assert b.status_code == 201

    # The window served is the miner's generation's: register NODE_1 as a
    # 64-byte-CHIP_ID (⇒ genoa) host, the generation both were admitted for.
    from apps.miners.models import MinerIdentity

    MinerIdentity.objects.create(
        miner_id="miner-a", pubkey_hex="ab" * 32, platform_id=CHIP_1, chain_node_id=NODE_1
    )
    url = reverse("host_attestor_desired", args=[NODE_1])
    resp = APIClient().get(url)
    assert resp.status_code == 200
    assert resp.data["current"]["measurement"] == MEAS_B
    assert resp.data["previous"]["measurement"] == MEAS_A


def test_desired_empty_before_any_release() -> None:
    url = reverse("host_attestor_desired", args=[NODE_1])
    resp = APIClient().get(url)
    assert resp.status_code == 200
    assert resp.data["current"] is None
    assert resp.data["previous"] is None


def test_third_release_evicts_oldest_from_grace_window(
    admin_client: APIClient, fake_cosign: FakeCosign, fake_pin: FakePin
) -> None:
    meas_c = "c3" * 48
    for m in (MEAS_A, MEAS_B, meas_c):
        resp = admin_client.post(
            RELEASE_URL, _release_body(measurement_hex=m), format="json"
        )
        assert resp.status_code == 201
    # Only the two newest stay active (C current, B previous); A deactivated.
    active = set(
        HostAttestorRelease.objects.filter(is_active=True).values_list(
            "measurement", flat=True
        )
    )
    assert active == {MEAS_B, meas_c}
    assert HostAttestorRelease.objects.get(measurement=MEAS_A).is_active is False


# ─── reconcile: attested-only coverage ───────────────────────────────


def _mk_host(
    node_id: str, chip_id: str, measurement: str, status: str, *, live: bool
) -> HostAttestor:
    now = timezone.now()
    return HostAttestor.objects.create(
        chip_id=chip_id,
        node_id=node_id,
        signer_pubkey=bytes.fromhex(SIGNER),
        measurement=measurement,
        cert_expiry_at=now + timedelta(days=1),
        status=status,
        last_seen_at=(now if live else now - timedelta(hours=2)),
    )


def _fake_chain(monkeypatch: pytest.MonkeyPatch, node_ids: list[str]) -> None:
    from apps.scheduler import chain

    miners = tuple(
        chain.MinerView(
            node_id=n,
            status="active",
            last_transition_epoch=1,
            data_epoch=1,
            quality=1,
        )
        for n in node_ids
    )
    monkeypatch.setattr(
        chain,
        "read_miner_status",
        lambda: chain.ChainSnapshot(current_epoch=1, miners=miners),
    )


def _active_release(measurement: str, generation: str = "") -> None:
    HostAttestorRelease.objects.create(
        measurement=measurement, version="v1", is_active=True, generation=generation
    )


def test_reconcile_counts_attested_only_not_pending(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _active_release(MEAS_A)
    _fake_chain(monkeypatch, [NODE_1, NODE_2])
    # NODE_1: attested + live on the desired measurement → COVERED.
    _mk_host(NODE_1, CHIP_1, MEAS_A, HostAttestorStatus.ATTESTED.value, live=True)
    # NODE_2: pending (even though live on the desired measurement) → the
    # HARD CONSTRAINT: a pending row is NEVER coverage → MISSING.
    _mk_host(NODE_2, CHIP_2, MEAS_A, HostAttestorStatus.PENDING.value, live=True)

    report = release_service.reconcile_coverage()
    assert report.total_active_miners == 2
    assert report.covered == 1
    assert report.missing == 1
    assert report.stale == 0
    covered_nodes = {c.node_id for c in report.per_miner if c.covered}
    assert covered_nodes == {NODE_1}


def test_reconcile_flags_stale_measurement(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _active_release(MEAS_A)  # desired = A only
    _fake_chain(monkeypatch, [NODE_1])
    # attested + live but on an OLD (non-desired) measurement → STALE.
    _mk_host(NODE_1, CHIP_1, MEAS_B, HostAttestorStatus.ATTESTED.value, live=True)
    report = release_service.reconcile_coverage()
    assert report.covered == 0
    assert report.stale == 1
    assert report.per_miner[0].stale_measurement is True


def test_reconcile_stale_liveness_is_missing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _active_release(MEAS_A)
    _fake_chain(monkeypatch, [NODE_1])
    # attested + on the desired measurement but last-seen 2h ago → MISSING.
    _mk_host(NODE_1, CHIP_1, MEAS_A, HostAttestorStatus.ATTESTED.value, live=False)
    report = release_service.reconcile_coverage()
    assert report.covered == 0
    assert report.missing == 1


def test_reconcile_grace_window_previous_counts_as_covered(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Two active releases (current B, previous A). A miner on the PREVIOUS
    # measurement mid-rolling-update is still covered.
    _active_release(MEAS_A)
    _active_release(MEAS_B)
    _fake_chain(monkeypatch, [NODE_1])
    _mk_host(NODE_1, CHIP_1, MEAS_A, HostAttestorStatus.ATTESTED.value, live=True)
    report = release_service.reconcile_coverage()
    assert report.covered == 1
    assert report.stale == 0
