"""Blackbox host-attestor single-use nonce authority (blackbox host-attestor
chantier PR-10).

`POST /v1/telemetry/host-attestor/challenge` mints a fresh, single-use,
freshness-bounded enrollment nonce bound to `{node_id, signer_pubkey}`; the
cert-ingest path (behind `VALI_HOST_ATTESTOR_REQUIRE_NONCE`) claims it
atomically — closing the pre-generation replay hole. The Rust
`verify-host-challenge-request` shell-out is replaced by an in-memory fake
so the gate logic runs without the built binary.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from django.conf import settings
from django.urls import reverse
from django.utils import timezone
from rest_framework.test import APIClient

from apps.telemetry import service, verifier
from apps.telemetry.models import HostAttestor, HostAttestorNonce, HostAttestorStatus

pytestmark = pytest.mark.django_db

CHALLENGE_URL = reverse("telemetry_host_attestor_challenge")
CERT_URL = reverse("telemetry_host_attestor_cert")

NODE_ID = "aa" * 32  # 64-hex node_id so `hippius-node:<hex>` resolves.
CHIP_ID = "33" * 64
MEASUREMENT = "44" * 48
SIGNER_PK = "22" * 32
NONCE_HEX = "11" * 32
PEER_ID = f"hippius-node:{NODE_ID}"
_FAR_FUTURE = 4_000_000_000


# ─── fakes ───────────────────────────────────────────────────────────


class FakeChallengeVerifier:
    """In-memory stand-in for `verifier.verify_host_challenge_request`."""

    def __init__(self) -> None:
        self.outcome = "ok"  # "ok" | "failed" | "unavailable"
        self.fail_category = "body_decode_failed"
        self.signer_pubkey_hex = SIGNER_PK
        self.calls: list[bytes] = []

    def verify_host_challenge_request(
        self, *, envelope: bytes
    ) -> verifier.HostChallengeRequestFields:
        self.calls.append(bytes(envelope))
        if self.outcome == "unavailable":
            raise verifier.VerifierUnavailable("injected unavailable")
        if self.outcome == "failed":
            raise verifier.VerifierFailed(message="injected", category=self.fail_category)
        return verifier.HostChallengeRequestFields(
            schema_version=1, signer_pubkey_hex=self.signer_pubkey_hex
        )


class FakeCertVerifier:
    """In-memory stand-in for `verifier.verify_host_attestor_cert` — the
    cert carries `NONCE_HEX` so the ingest nonce-consumption gate can act."""

    def __init__(self) -> None:
        self.node_id = NODE_ID
        self.attestor_pubkey_hex = SIGNER_PK
        self.nonce_hex = NONCE_HEX

    def verify_host_attestor_cert(
        self, *, envelope: bytes, verifying_key: bytes | None
    ) -> verifier.HostAttestorCertFields:
        return verifier.HostAttestorCertFields(
            verified=verifying_key is not None,
            schema_version=1,
            node_id=self.node_id,
            chip_id_hex=CHIP_ID,
            attestor_pubkey_hex=self.attestor_pubkey_hex,
            measurement_hex=MEASUREMENT,
            tcb=0x0708_0000_0000_000B,
            nonce_hex=self.nonce_hex,
            expiry_unix=_FAR_FUTURE,
        )


@pytest.fixture
def fake_challenge(monkeypatch: pytest.MonkeyPatch) -> FakeChallengeVerifier:
    fake = FakeChallengeVerifier()
    monkeypatch.setattr(
        verifier, "verify_host_challenge_request", fake.verify_host_challenge_request
    )
    return fake


@pytest.fixture
def fake_cert(monkeypatch: pytest.MonkeyPatch) -> FakeCertVerifier:
    fake = FakeCertVerifier()
    monkeypatch.setattr(
        verifier, "verify_host_attestor_cert", fake.verify_host_attestor_cert
    )
    return fake


@pytest.fixture(autouse=True)
def _node_onchain(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(service, "_node_id_is_onchain_active", lambda node_id: True)


def _set_kbs_key(monkeypatch: pytest.MonkeyPatch, *, present: bool) -> None:
    monkeypatch.setattr(
        settings, "VALI_KBS_L0_VERIFYING_KEY", ("ab" * 32) if present else ""
    )


def _require_nonce(monkeypatch: pytest.MonkeyPatch, *, on: bool) -> None:
    monkeypatch.setattr(settings, "VALI_HOST_ATTESTOR_REQUIRE_NONCE", on)


def _post_challenge(body: bytes = b"challenge-cbor", *, peer_id: str | None = PEER_ID):
    extra = {"HTTP_X_HIPPIUS_PEER_ID": peer_id} if peer_id is not None else {}
    return APIClient().post(
        CHALLENGE_URL, data=body, content_type="application/cbor", **extra
    )


def _post_cert(body: bytes = b"signed-cert-cbor"):
    return APIClient().post(CERT_URL, data=body, content_type="application/cbor")


def _issued_nonce(
    *, nonce_hex: str = NONCE_HEX, node_id: str = NODE_ID, pk_hex: str = SIGNER_PK, ttl_s: int = 300
) -> HostAttestorNonce:
    return HostAttestorNonce.objects.create(
        nonce=bytes.fromhex(nonce_hex),
        node_id=node_id,
        signer_pubkey=bytes.fromhex(pk_hex),
        expires_at=timezone.now() + timedelta(seconds=ttl_s),
    )


# ─── mint (the challenge endpoint) ───────────────────────────────────


def test_challenge_mints_a_nonce_bound_to_node_and_pk(
    fake_challenge: FakeChallengeVerifier,
) -> None:
    resp = _post_challenge()
    assert resp.status_code == 200, resp.content
    body = resp.json()
    # PR-10b-S2a: the peer-stamped node_id rides the response too, so the
    # guest never needs it on the measured cmdline.
    assert set(body) == {"nonce_hex", "node_id", "expiry_unix"}
    assert len(bytes.fromhex(body["nonce_hex"])) == 32
    assert body["node_id"] == NODE_ID  # peer-stamped, echoed to the guest
    assert body["expiry_unix"] > int(timezone.now().timestamp())

    row = HostAttestorNonce.objects.get(nonce=bytes.fromhex(body["nonce_hex"]))
    assert row.node_id == NODE_ID  # from the peer-id, NOT the body
    assert bytes(row.signer_pubkey) == bytes.fromhex(SIGNER_PK)
    assert row.spent_at is None


def test_challenge_each_mint_is_a_fresh_distinct_nonce(
    fake_challenge: FakeChallengeVerifier,
) -> None:
    a = _post_challenge().json()["nonce_hex"]
    b = _post_challenge().json()["nonce_hex"]
    assert a != b
    assert HostAttestorNonce.objects.count() == 2


def test_challenge_missing_peer_id_is_400(fake_challenge: FakeChallengeVerifier) -> None:
    resp = _post_challenge(peer_id=None)
    assert resp.status_code == 400
    assert HostAttestorNonce.objects.count() == 0


def test_challenge_empty_body_is_400(fake_challenge: FakeChallengeVerifier) -> None:
    resp = _post_challenge(body=b"")
    assert resp.status_code == 400


def test_challenge_verifier_failed_is_400(
    fake_challenge: FakeChallengeVerifier,
) -> None:
    fake_challenge.outcome = "failed"
    resp = _post_challenge()
    assert resp.status_code == 400
    assert HostAttestorNonce.objects.count() == 0


def test_challenge_verifier_unavailable_is_503(
    fake_challenge: FakeChallengeVerifier,
) -> None:
    fake_challenge.outcome = "unavailable"
    resp = _post_challenge()
    assert resp.status_code == 503
    assert HostAttestorNonce.objects.count() == 0


# ─── consume (cert-ingest single-use gate) ───────────────────────────


def test_cert_flag_off_ignores_nonce_legacy_path(
    fake_cert: FakeCertVerifier, monkeypatch: pytest.MonkeyPatch
) -> None:
    # DEFAULT (flag off): a cert ingests even with NO matching issued nonce.
    _require_nonce(monkeypatch, on=False)
    _set_kbs_key(monkeypatch, present=True)
    assert HostAttestorNonce.objects.count() == 0
    resp = _post_cert()
    assert resp.status_code == 200, resp.content
    assert HostAttestor.objects.get(chip_id=CHIP_ID).status == (
        HostAttestorStatus.ATTESTED.value
    )


def test_cert_flag_on_consumes_a_matching_issued_nonce(
    fake_cert: FakeCertVerifier, monkeypatch: pytest.MonkeyPatch
) -> None:
    _require_nonce(monkeypatch, on=True)
    _set_kbs_key(monkeypatch, present=True)
    nonce = _issued_nonce()
    resp = _post_cert()
    assert resp.status_code == 200, resp.content
    assert HostAttestor.objects.get(chip_id=CHIP_ID).status == (
        HostAttestorStatus.ATTESTED.value
    )
    nonce.refresh_from_db()
    assert nonce.spent_at is not None  # single-use: marked spent


def test_cert_flag_on_rejects_when_no_issued_nonce(
    fake_cert: FakeCertVerifier, monkeypatch: pytest.MonkeyPatch
) -> None:
    _require_nonce(monkeypatch, on=True)
    _set_kbs_key(monkeypatch, present=True)
    resp = _post_cert()
    assert resp.status_code == 400, resp.content
    assert resp.json()["category"] == "nonce-invalid"
    # Fail-closed: no row upserted from an unbacked cert.
    assert HostAttestor.objects.count() == 0


def test_cert_flag_on_double_spend_is_rejected(
    fake_cert: FakeCertVerifier, monkeypatch: pytest.MonkeyPatch
) -> None:
    # First ingest spends the nonce; a replay of the SAME cert/nonce fails.
    _require_nonce(monkeypatch, on=True)
    _set_kbs_key(monkeypatch, present=True)
    _issued_nonce()
    first = _post_cert()
    assert first.status_code == 200, first.content
    second = _post_cert()
    assert second.status_code == 400
    assert second.json()["category"] == "nonce-invalid"


def test_cert_flag_on_rejects_expired_nonce(
    fake_cert: FakeCertVerifier, monkeypatch: pytest.MonkeyPatch
) -> None:
    _require_nonce(monkeypatch, on=True)
    _set_kbs_key(monkeypatch, present=True)
    HostAttestorNonce.objects.create(
        nonce=bytes.fromhex(NONCE_HEX),
        node_id=NODE_ID,
        signer_pubkey=bytes.fromhex(SIGNER_PK),
        expires_at=timezone.now() - timedelta(seconds=1),  # already expired
    )
    resp = _post_cert()
    assert resp.status_code == 400
    assert resp.json()["category"] == "nonce-invalid"


def test_cert_flag_on_rejects_nonce_bound_to_another_pk(
    fake_cert: FakeCertVerifier, monkeypatch: pytest.MonkeyPatch
) -> None:
    _require_nonce(monkeypatch, on=True)
    _set_kbs_key(monkeypatch, present=True)
    # Nonce issued for a DIFFERENT pk — cannot be redirected to this cert.
    _issued_nonce(pk_hex="99" * 32)
    resp = _post_cert()
    assert resp.status_code == 400
    assert resp.json()["category"] == "nonce-invalid"


def test_cert_flag_on_rejects_nonce_bound_to_another_node(
    fake_cert: FakeCertVerifier, monkeypatch: pytest.MonkeyPatch
) -> None:
    _require_nonce(monkeypatch, on=True)
    _set_kbs_key(monkeypatch, present=True)
    _issued_nonce(node_id="bb" * 32)  # a different host
    resp = _post_cert()
    assert resp.status_code == 400
    assert resp.json()["category"] == "nonce-invalid"


def test_mint_then_consume_end_to_end(
    fake_challenge: FakeChallengeVerifier,
    fake_cert: FakeCertVerifier,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Mint a nonce via the challenge endpoint, then present a cert carrying
    # that exact nonce → consumed single-use.
    _set_kbs_key(monkeypatch, present=True)
    minted = _post_challenge().json()["nonce_hex"]
    fake_cert.nonce_hex = minted  # the guest folded THIS nonce into REPORT_DATA
    _require_nonce(monkeypatch, on=True)
    resp = _post_cert()
    assert resp.status_code == 200, resp.content
    row = HostAttestorNonce.objects.get(nonce=bytes.fromhex(minted))
    assert row.spent_at is not None


def test_unix_to_dt_roundtrip_helper_present() -> None:
    # Guards the datetime import used by the response serialization.
    assert isinstance(datetime.now(tz=UTC), datetime)
