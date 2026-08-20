"""Blackbox host-attestor ingest gates (blackbox host-attestor PR-8).

`POST /v1/telemetry/host-attestor/cert` ingests a KBS-minted
`SignedHostAttestorCert`; `POST /v1/telemetry/host-attestor/heartbeat`
ingests a `SignedHostBeacon`. Both shell out to the data-bearing Rust
`verify-host-attestor-cert` / `verify-host-beacon` subcommands; here those
shell-outs are replaced by in-memory fakes so the gate logic runs without
the built binary (`test_verifier.py` covers the real wrappers).

These tests drive the verification chain: cert-vs-KBS-L0 (attested vs the
KBS-key-not-wired `pending` seam + on-chain-Active gate), the enrollment
upsert + key-rotation reset, beacon verify against the CERTIFIED pk,
monotonic-seq replay, unknown-host / chip-mismatch / node-mismatch, and
the fail-closed size / verifier-unavailable gates.
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from django.urls import reverse
from rest_framework.test import APIClient

from apps.telemetry import service, verifier
from apps.telemetry.models import HostAttestor, HostAttestorStatus

pytestmark = pytest.mark.django_db

CERT_URL = reverse("telemetry_host_attestor_cert")
BEACON_URL = reverse("telemetry_host_attestor_beacon")

# A 64-hex (32-byte) node_id so the `hippius-node:<hex>` peer-id resolves.
NODE_ID = "aa" * 32
CHIP_ID = "33" * 64  # 64-byte CHIP_ID ⇒ 128 hex chars.
MEASUREMENT = "44" * 48  # 48-byte measurement ⇒ 96 hex chars.
SIGNER_PK = "22" * 32  # 32-byte attestor pubkey ⇒ 64 hex chars.
PEER_ID = f"hippius-node:{NODE_ID}"

_FAR_FUTURE = 4_000_000_000  # well past any test wall-clock


# ─── fakes ───────────────────────────────────────────────────────────


class FakeCertVerifier:
    """In-memory stand-in for `verifier.verify_host_attestor_cert`."""

    def __init__(self) -> None:
        self.outcome = "ok"  # "ok" | "failed" | "unavailable"
        self.verified = True
        self.fail_category = "signature_invalid"
        self.node_id = NODE_ID
        self.chip_id_hex = CHIP_ID
        self.attestor_pubkey_hex = SIGNER_PK
        self.measurement_hex = MEASUREMENT
        self.tcb = 0x0708_0000_0000_000B
        self.nonce_hex = "11" * 32
        self.expiry_unix = _FAR_FUTURE
        self.calls: list[bytes | None] = []

    def verify_host_attestor_cert(
        self, *, envelope: bytes, verifying_key: bytes | None
    ) -> verifier.HostAttestorCertFields:
        self.calls.append(verifying_key)
        if self.outcome == "unavailable":
            raise verifier.VerifierUnavailable("injected unavailable")
        if self.outcome == "failed":
            raise verifier.VerifierFailed(
                message="injected", category=self.fail_category
            )
        # A missing KBS key forces decode-only (verified=False), matching
        # the real binary's seam behaviour.
        verified = self.verified and verifying_key is not None
        return verifier.HostAttestorCertFields(
            verified=verified,
            schema_version=1,
            node_id=self.node_id,
            chip_id_hex=self.chip_id_hex,
            attestor_pubkey_hex=self.attestor_pubkey_hex,
            measurement_hex=self.measurement_hex,
            tcb=self.tcb,
            nonce_hex=self.nonce_hex,
            expiry_unix=self.expiry_unix,
        )


class FakeBeaconVerifier:
    """In-memory stand-in for `verifier.verify_host_beacon`."""

    def __init__(self) -> None:
        self.outcome = "ok"
        self.fail_category = "signature_invalid"
        self.node_id = NODE_ID
        self.chip_id_hex = CHIP_ID
        self.seq = 1
        self.expiry_unix = _FAR_FUTURE
        self.boot_id = "boot-1"
        self.calls: list[bytes] = []

    def verify_host_beacon(
        self, *, envelope: bytes, verifying_key: bytes
    ) -> verifier.HostBeaconFields:
        self.calls.append(bytes(verifying_key))
        if self.outcome == "unavailable":
            raise verifier.VerifierUnavailable("injected unavailable")
        if self.outcome == "failed":
            raise verifier.VerifierFailed(
                message="injected", category=self.fail_category
            )
        return verifier.HostBeaconFields(
            schema_version=1,
            chip_id_hex=self.chip_id_hex,
            measurement_hex=MEASUREMENT,
            node_id=self.node_id,
            boot_id=self.boot_id,
            seq=self.seq,
            observed_at_unix=1_800_000_000,
            policy=0x30000,
            nonce_hex="11" * 32,
            signer_pubkey_hex=SIGNER_PK,
            expiry_unix=self.expiry_unix,
        )


@pytest.fixture
def fake_cert(monkeypatch: pytest.MonkeyPatch) -> FakeCertVerifier:
    fake = FakeCertVerifier()
    monkeypatch.setattr(
        verifier, "verify_host_attestor_cert", fake.verify_host_attestor_cert
    )
    return fake


@pytest.fixture
def fake_beacon(monkeypatch: pytest.MonkeyPatch) -> FakeBeaconVerifier:
    fake = FakeBeaconVerifier()
    monkeypatch.setattr(verifier, "verify_host_beacon", fake.verify_host_beacon)
    return fake


@pytest.fixture(autouse=True)
def _node_onchain(monkeypatch: pytest.MonkeyPatch):
    """Default: the node is on-chain Active. Individual tests override."""
    monkeypatch.setattr(service, "_node_id_is_onchain_active", lambda node_id: True)


def _set_kbs_key(monkeypatch: pytest.MonkeyPatch, *, present: bool) -> None:
    from django.conf import settings

    monkeypatch.setattr(
        settings, "VALI_KBS_L0_VERIFYING_KEY", ("ab" * 32) if present else ""
    )


def _post_cert(body: bytes = b"signed-cert-cbor"):
    return APIClient().post(CERT_URL, data=body, content_type="application/cbor")


def _post_beacon(body: bytes = b"signed-beacon-cbor", *, peer_id: str | None = PEER_ID):
    extra = {"HTTP_X_HIPPIUS_PEER_ID": peer_id} if peer_id is not None else {}
    return APIClient().post(
        BEACON_URL, data=body, content_type="application/cbor", **extra
    )


def _enroll_row(**overrides) -> HostAttestor:
    """Create an enrolled `HostAttestor` row directly (for beacon tests)."""
    defaults = dict(
        chip_id=CHIP_ID,
        node_id=NODE_ID,
        signer_pubkey=bytes.fromhex(SIGNER_PK),
        measurement=MEASUREMENT,
        tcb=1,
        cert_expiry_at=datetime.fromtimestamp(_FAR_FUTURE, tz=UTC),
        status=HostAttestorStatus.ATTESTED.value,
        # Matches the fake beacon's default boot_id so the monotonic-`seq`
        # tests exercise SAME-boot behaviour; the reboot re-baseline is
        # covered by `test_beacon_new_boot_id_rebaselines_seq`.
        boot_id="boot-1",
    )
    defaults.update(overrides)
    return HostAttestor.objects.create(**defaults)


# ─── cert ingest ─────────────────────────────────────────────────────


def test_cert_attested_when_verified_and_node_active(
    fake_cert: FakeCertVerifier, monkeypatch: pytest.MonkeyPatch
) -> None:
    _set_kbs_key(monkeypatch, present=True)
    resp = _post_cert()
    assert resp.status_code == 200, resp.content
    body = resp.json()
    assert body["status"] == HostAttestorStatus.ATTESTED.value
    assert body["created"] is True
    assert body["chip_id"] == CHIP_ID
    row = HostAttestor.objects.get(chip_id=CHIP_ID)
    assert row.status == HostAttestorStatus.ATTESTED.value
    assert bytes(row.signer_pubkey) == bytes.fromhex(SIGNER_PK)
    assert row.node_id == NODE_ID
    # The KBS L0 key was passed to the verifier (32 bytes).
    assert fake_cert.calls == [bytes.fromhex("ab" * 32)]


def test_cert_pending_when_kbs_key_not_wired(
    fake_cert: FakeCertVerifier, monkeypatch: pytest.MonkeyPatch
) -> None:
    # SEAM: no KBS L0 key configured ⇒ decode-only ⇒ pending, never attested.
    _set_kbs_key(monkeypatch, present=False)
    resp = _post_cert()
    assert resp.status_code == 200, resp.content
    assert resp.json()["status"] == HostAttestorStatus.PENDING.value
    assert HostAttestor.objects.get(chip_id=CHIP_ID).status == (
        HostAttestorStatus.PENDING.value
    )
    # verifying_key was None (the seam).
    assert fake_cert.calls == [None]


def test_cert_pending_when_node_not_onchain_active(
    fake_cert: FakeCertVerifier, monkeypatch: pytest.MonkeyPatch
) -> None:
    # A self-declared node that is NOT on-chain Active is not trusted:
    # even a KBS-L0-verified cert stays pending.
    _set_kbs_key(monkeypatch, present=True)
    monkeypatch.setattr(service, "_node_id_is_onchain_active", lambda node_id: False)
    resp = _post_cert()
    assert resp.status_code == 200, resp.content
    assert resp.json()["status"] == HostAttestorStatus.PENDING.value


def test_cert_bad_signature_is_rejected(
    fake_cert: FakeCertVerifier, monkeypatch: pytest.MonkeyPatch
) -> None:
    _set_kbs_key(monkeypatch, present=True)
    fake_cert.outcome = "failed"
    fake_cert.fail_category = "signature_invalid"
    resp = _post_cert()
    assert resp.status_code == 400
    assert resp.json()["category"] == "verify-failed"
    assert not HostAttestor.objects.exists()


def test_cert_expired_is_rejected(fake_cert: FakeCertVerifier) -> None:
    fake_cert.expiry_unix = 1  # long past
    resp = _post_cert()
    assert resp.status_code == 400
    assert resp.json()["category"] == "cert-expired"
    assert not HostAttestor.objects.exists()


def test_cert_verifier_unavailable_is_503(fake_cert: FakeCertVerifier) -> None:
    fake_cert.outcome = "unavailable"
    resp = _post_cert()
    assert resp.status_code == 503


def test_cert_reenroll_rotates_key_and_resets_seq(
    fake_cert: FakeCertVerifier, monkeypatch: pytest.MonkeyPatch
) -> None:
    _set_kbs_key(monkeypatch, present=True)
    # First enrollment + a beacon that advances last_seq.
    _post_cert()
    row = HostAttestor.objects.get(chip_id=CHIP_ID)
    HostAttestor.objects.filter(pk=row.pk).update(last_seq=5, boot_id="old-boot")
    # Re-enroll with a NEW derived key (new boot) — same chip.
    new_pk = "55" * 32
    fake_cert.attestor_pubkey_hex = new_pk
    resp = _post_cert()
    assert resp.status_code == 200, resp.content
    assert resp.json()["created"] is False
    row.refresh_from_db()
    assert bytes(row.signer_pubkey) == bytes.fromhex(new_pk)
    # The monotonic beacon counter reset for the new boot.
    assert row.last_seq is None
    assert row.boot_id == ""


# ─── beacon ingest ───────────────────────────────────────────────────


def test_beacon_verifies_against_certified_pk_and_updates_liveness(
    fake_beacon: FakeBeaconVerifier,
) -> None:
    _enroll_row()
    fake_beacon.seq = 3
    resp = _post_beacon()
    assert resp.status_code == 200, resp.content
    body = resp.json()
    assert body["last_seq"] == 3
    assert body["chip_id"] == CHIP_ID
    row = HostAttestor.objects.get(chip_id=CHIP_ID)
    assert row.last_seq == 3
    assert row.last_seen_at is not None
    assert row.boot_id == "boot-1"
    # Verified against the CERTIFIED signer_pubkey stored on the row.
    assert fake_beacon.calls == [bytes.fromhex(SIGNER_PK)]


def test_beacon_non_monotonic_seq_is_rejected(
    fake_beacon: FakeBeaconVerifier,
) -> None:
    _enroll_row(last_seq=10)
    fake_beacon.seq = 10  # equal ⇒ replay
    resp = _post_beacon()
    assert resp.status_code == 400
    assert resp.json()["category"] == "seq-replay"
    # A regression is also rejected, and liveness untouched.
    fake_beacon.seq = 4
    assert _post_beacon().json()["category"] == "seq-replay"
    assert HostAttestor.objects.get(chip_id=CHIP_ID).last_seq == 10


def test_beacon_new_boot_id_rebaselines_seq(
    fake_beacon: FakeBeaconVerifier,
) -> None:
    # A host restart re-seeds the beacon `seq` at 1, but the reboot-stable
    # derived key keeps `signer_pubkey` (and the cert) unchanged — so the
    # cert-ingest key-rotation reset never fires. Without the boot_id
    # re-baseline the new boot would be rejected until its `seq` climbed
    # back past the pre-restart high-water-mark (a dark window as long as
    # the prior uptime). A CHANGED boot_id on the (already key-verified,
    # unexpired) beacon re-baselines the gate: the new boot's low `seq` is
    # accepted immediately.
    _enroll_row(last_seq=75, boot_id="boot-before-restart")
    fake_beacon.seq = 1
    fake_beacon.boot_id = "boot-after-restart"
    resp = _post_beacon()
    assert resp.status_code == 200, resp.content
    row = HostAttestor.objects.get(chip_id=CHIP_ID)
    assert row.last_seq == 1
    assert row.boot_id == "boot-after-restart"
    # Within the NEW boot the monotonic gate is back in force: a replay of
    # the same low seq is refused.
    assert _post_beacon().json()["category"] == "seq-replay"
    assert HostAttestor.objects.get(chip_id=CHIP_ID).last_seq == 1


def test_beacon_unknown_host_is_404(fake_beacon: FakeBeaconVerifier) -> None:
    # No enrolled HostAttestor for the peer's node — reject, verify never runs.
    resp = _post_beacon()
    assert resp.status_code == 404
    assert resp.json()["category"] == "host-not-enrolled"
    assert fake_beacon.calls == []


def test_beacon_chip_mismatch_is_rejected(
    fake_beacon: FakeBeaconVerifier,
) -> None:
    # A verified beacon whose self-declared chip differs from the enrolled
    # cert's chip is refused (credit the cert chip, never the beacon's).
    _enroll_row()
    fake_beacon.chip_id_hex = "99" * 64
    resp = _post_beacon()
    assert resp.status_code == 400
    assert resp.json()["category"] == "chip-mismatch"


def test_beacon_node_mismatch_is_rejected(
    fake_beacon: FakeBeaconVerifier,
) -> None:
    _enroll_row()
    fake_beacon.node_id = "bb" * 32  # body node != peer/row node
    resp = _post_beacon()
    assert resp.status_code == 400
    assert resp.json()["category"] == "node-mismatch"


def test_beacon_expired_cert_marks_row_and_rejects(
    fake_beacon: FakeBeaconVerifier,
) -> None:
    _enroll_row(cert_expiry_at=datetime.fromtimestamp(1, tz=UTC))
    resp = _post_beacon()
    assert resp.status_code == 400
    assert resp.json()["category"] == "cert-expired"
    assert HostAttestor.objects.get(chip_id=CHIP_ID).status == (
        HostAttestorStatus.EXPIRED.value
    )


def test_beacon_verify_failed_is_400(fake_beacon: FakeBeaconVerifier) -> None:
    _enroll_row()
    fake_beacon.outcome = "failed"
    resp = _post_beacon()
    assert resp.status_code == 400
    assert resp.json()["category"] == "verify-failed"


def test_beacon_verifier_unavailable_is_503(
    fake_beacon: FakeBeaconVerifier,
) -> None:
    _enroll_row()
    fake_beacon.outcome = "unavailable"
    assert _post_beacon().status_code == 503


def test_beacon_missing_peer_id_is_400(fake_beacon: FakeBeaconVerifier) -> None:
    _enroll_row()
    resp = _post_beacon(peer_id=None)
    assert resp.status_code == 400
    assert resp.json()["category"] == "wire"


# ─── shared fail-closed gates ────────────────────────────────────────


def test_cert_empty_body_is_400() -> None:
    assert _post_cert(body=b"").status_code == 400


def test_cert_oversize_body_is_413() -> None:
    resp = _post_cert(body=b"x" * 4097)
    assert resp.status_code == 413
    assert resp.json()["category"] == "too-large"


def test_beacon_empty_body_is_400() -> None:
    assert _post_beacon(body=b"").status_code == 400


def test_beacon_oversize_body_is_413() -> None:
    resp = _post_beacon(body=b"x" * 4097)
    assert resp.status_code == 413
    assert resp.json()["category"] == "too-large"
