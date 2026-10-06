"""Edge-relayed miner graceful-exit ingest gates.

`POST /v1/telemetry/graceful-exit` with `content-type: application/cbor`
is the Edge-relayed graceful-exit ingress: a real miner box cannot reach
vali directly, so it POSTs a `SignedGracefulExit` to the Edge
`/v1/edge/graceful-exit` route over mTLS and the Edge forwards the raw
CBOR here, stamping the miner's mTLS identity on the `X-Hippius-Peer-Id`
header (mirrors the §K heartbeat ingress exactly).

These tests drive every fail-closed gate — peer-id resolution, miner
lookup, signature verify, peer-vs-body `miner_id` match, ±skew, the
oversize cap, the empty body — plus the happy-path quarantine and its
idempotency. The data-bearing `verify-graceful-exit` shell-out is
replaced by `FakeGracefulExitVerifier`, so the gate logic runs without
the built Rust binary (`apps/telemetry/tests/test_verifier.py` covers
the real shell-out).
"""

from __future__ import annotations

import time
from typing import Any

import pytest
from django.urls import reverse
from rest_framework.test import APIClient

from apps.miners.models import MinerIdentity, MinerStatus
from apps.telemetry import verifier
from apps.telemetry.models import SourceType, TelemetrySource

pytestmark = pytest.mark.django_db

INGEST_URL = reverse("telemetry_graceful_exit")

MINER_ID = "miner-a"
PEER_ID = f"hippius-miner:{MINER_ID}"
DOMAIN = "HIPPIUS_MINER_GRACEFUL_EXIT_V1"


# ─── verify-graceful-exit fake ───────────────────────────────────────


class FakeGracefulExitVerifier:
    """In-memory stand-in for `telemetry.verifier.verify_graceful_exit`.

    - `outcome` ∈ {"ok", "failed", "unavailable"} steers the verdict.
    - on "ok" the returned body is built from the steerable `miner_id`
      / `sequence` / `timestamp_unix` attrs (`timestamp_unix=None` ⇒
      vali's current clock — inside the skew window).
    - `calls` records every `(envelope, verifying_key)` verified.
    """

    def __init__(self) -> None:
        self.outcome = "ok"
        self.miner_id = MINER_ID
        self.sequence = 1
        self.timestamp_unix: int | None = None
        self.schema_version = 1
        self.fail_category = "signature_invalid"
        self.calls: list[tuple[bytes, bytes]] = []

    def verify_graceful_exit(
        self, *, envelope: bytes, verifying_key: bytes
    ) -> verifier.HeartbeatBody:
        self.calls.append((bytes(envelope), bytes(verifying_key)))
        if self.outcome == "unavailable":
            raise verifier.VerifierUnavailable("injected unavailable")
        if self.outcome == "failed":
            raise verifier.VerifierFailed(
                message="injected verification failure",
                category=self.fail_category,
            )
        ts = self.timestamp_unix
        if ts is None:
            ts = int(time.time())
        return verifier.HeartbeatBody(
            schema_version=self.schema_version,
            domain=DOMAIN,
            miner_id=self.miner_id,
            timestamp_unix=ts,
            sequence=self.sequence,
        )


@pytest.fixture(autouse=True)
def fake_verifier(monkeypatch: pytest.MonkeyPatch) -> FakeGracefulExitVerifier:
    fake = FakeGracefulExitVerifier()
    monkeypatch.setattr(verifier, "verify_graceful_exit", fake.verify_graceful_exit)
    return fake


# ─── helpers ─────────────────────────────────────────────────────────


def _make_miner(
    *,
    miner_id: str = MINER_ID,
    status: str = MinerStatus.ACTIVE.value,
    source_active: bool = True,
) -> MinerIdentity:
    miner = MinerIdentity.objects.create(
        miner_id=miner_id,
        pubkey_hex=("ab" * 32),
        platform_id=f"amd-chipid-{miner_id}",
        status=status,
    )
    TelemetrySource.objects.create(
        source=SourceType.MINER.value,
        source_id=miner_id,
        verifying_key=bytes(32),
        is_active=source_active,
    )
    return miner


def _post(
    body: bytes = b"signed-graceful-exit-cbor",
    *,
    peer_id: str | None = PEER_ID,
):
    """POST a raw-CBOR graceful-exit. The CBOR ingress carries no bearer
    token, so an unauthenticated client is the default.
    """
    extra: dict[str, Any] = {}
    if peer_id is not None:
        extra["HTTP_X_HIPPIUS_PEER_ID"] = peer_id
    return APIClient().post(
        INGEST_URL, data=body, content_type="application/cbor", **extra
    )


# ─── happy path ──────────────────────────────────────────────────────


def test_quarantines_miner_on_valid_request(
    fake_verifier: FakeGracefulExitVerifier,
) -> None:
    miner = _make_miner()

    resp = _post()

    assert resp.status_code == 200, resp.content
    body = resp.json()
    assert body == {
        "miner_id": MINER_ID,
        "status": MinerStatus.QUARANTINED.value,
        "accepted": True,
    }
    miner.refresh_from_db()
    assert miner.status == MinerStatus.QUARANTINED.value
    # The §13/§25 auto-migration enrolment: the linked source is off.
    src = TelemetrySource.objects.get(
        source=SourceType.MINER.value, source_id=MINER_ID
    )
    assert src.is_active is False
    # The verifier saw the raw envelope + the registered key. The key is
    # the miner's `MinerIdentity.pubkey_hex` (the registry trust anchor),
    # not the linked source's `verifying_key`.
    assert fake_verifier.calls == [
        (b"signed-graceful-exit-cbor", bytes.fromhex("ab" * 32))
    ]


def test_ingress_needs_no_bearer_token() -> None:
    # The Edge's forward leg carries no token — a plain (unauthenticated)
    # client must still be accepted on the CBOR path.
    _make_miner()
    resp = APIClient().post(
        INGEST_URL,
        data=b"ge",
        content_type="application/cbor",
        HTTP_X_HIPPIUS_PEER_ID=PEER_ID,
    )
    assert resp.status_code == 200, resp.content


def test_requantine_is_idempotent(
    fake_verifier: FakeGracefulExitVerifier,
) -> None:
    # A re-request (e.g. a signature replay) is a no-op 200, never an
    # error — the quarantine is already in place.
    miner = _make_miner()
    assert _post().status_code == 200
    assert _post().status_code == 200
    miner.refresh_from_db()
    assert miner.status == MinerStatus.QUARANTINED.value


def test_resolves_permissionless_node_peer(
    fake_verifier: FakeGracefulExitVerifier,
) -> None:
    # `hippius-node:<node_id_hex>` SAN scheme: the miner is resolved by
    # matching the node_id against the registered source verifying_key.
    node_id = b"\x11" * 32
    miner = _make_miner()
    TelemetrySource.objects.filter(
        source=SourceType.MINER.value, source_id=MINER_ID
    ).update(verifying_key=node_id)

    resp = _post(peer_id=f"hippius-node:{node_id.hex()}")

    assert resp.status_code == 200, resp.content
    miner.refresh_from_db()
    assert miner.status == MinerStatus.QUARANTINED.value


# ─── fail-closed gates ───────────────────────────────────────────────


def test_rejects_missing_peer_id_header() -> None:
    _make_miner()
    resp = _post(peer_id=None)
    assert resp.status_code == 400
    assert resp.json()["category"] == "wire"


def test_rejects_malformed_peer_id_header() -> None:
    _make_miner()
    resp = _post(peer_id="spiffe://something/else")
    assert resp.status_code == 400


def test_rejects_unknown_miner() -> None:
    # A well-formed peer-id for a miner that is not registered.
    resp = _post(peer_id="hippius-miner:nope")
    assert resp.status_code == 404


def test_rejects_empty_body() -> None:
    _make_miner()
    resp = _post(body=b"")
    assert resp.status_code == 400
    assert resp.json()["category"] == "wire"


def test_rejects_oversize_body() -> None:
    _make_miner()
    resp = _post(body=b"x" * 4097)
    assert resp.status_code == 413
    assert resp.json()["category"] == "too-large"


def test_rejects_body_miner_id_mismatch(
    fake_verifier: FakeGracefulExitVerifier,
) -> None:
    # Defence in depth: the signed body names a DIFFERENT miner than the
    # mTLS peer identity resolved — reject even though the signature is
    # valid for the resolved key.
    _make_miner()
    fake_verifier.miner_id = "some-other-miner"
    resp = _post()
    assert resp.status_code == 403
    assert resp.json()["category"] == "identity"


def test_rejects_timestamp_outside_skew(
    fake_verifier: FakeGracefulExitVerifier,
) -> None:
    _make_miner()
    fake_verifier.timestamp_unix = int(time.time()) - 10_000
    resp = _post()
    assert resp.status_code == 403
    assert resp.json()["category"] == "timestamp-skew"


def test_verify_failed_is_403(
    fake_verifier: FakeGracefulExitVerifier,
) -> None:
    _make_miner()
    fake_verifier.outcome = "failed"
    fake_verifier.fail_category = "signature_invalid"
    resp = _post()
    assert resp.status_code == 403
    assert resp.json()["category"] == "signature_invalid"
    # A failed verify must NOT quarantine.
    assert (
        MinerIdentity.objects.get(miner_id=MINER_ID).status
        == MinerStatus.ACTIVE.value
    )


def test_verifier_unavailable_is_503(
    fake_verifier: FakeGracefulExitVerifier,
) -> None:
    _make_miner()
    fake_verifier.outcome = "unavailable"
    resp = _post()
    assert resp.status_code == 503
    assert (
        MinerIdentity.objects.get(miner_id=MINER_ID).status
        == MinerStatus.ACTIVE.value
    )
