"""§K miner-heartbeat ingest gates (PR-Part4-B).

`POST /v1/telemetry/ingest` with `content-type: application/cbor` is
the heartbeat ingress: the Edge forwards a raw `SignedMinerHeartbeat`
verbatim and stamps the miner's mTLS identity on the
`X-Hippius-Peer-Id` header. These tests drive every fail-closed gate —
peer-id resolution, registered source, quarantine, signature verify,
peer-vs-body `miner_id` match, ±300 s skew, the monotonic-`sequence`
replay defence — plus the happy path and the orthogonality of the
tenant `served_receipt` trust plane.

The data-bearing `verify-heartbeat` shell-out is replaced by
`FakeHeartbeatVerifier`, so the gate logic runs without the built Rust
binary; `apps/telemetry/tests/test_verifier.py` covers the real
shell-out wrapper.
"""

from __future__ import annotations

import time
from typing import Any

import pytest
from django.conf import settings
from django.urls import reverse
from rest_framework.test import APIClient

from apps.miners.models import MinerIdentity, MinerStatus
from apps.telemetry import verifier
from apps.telemetry.models import (
    EnvelopeKind,
    ProcessingStatus,
    SourceType,
    TelemetryEnvelope,
    TelemetrySource,
)

pytestmark = pytest.mark.django_db

INGEST_URL = reverse("telemetry_ingest")

MINER_ID = "miner-1"
PEER_ID = f"hippius-miner:{MINER_ID}"
DOMAIN = "HIPPIUS_MINER_HEARTBEAT_V1"


# ─── verify-heartbeat fake ───────────────────────────────────────────


class FakeHeartbeatVerifier:
    """In-memory stand-in for `telemetry.verifier.verify_heartbeat`.

    - `outcome` ∈ {"ok", "failed", "unavailable"} steers the verdict.
    - on "ok" the returned `HeartbeatBody` is built from the steerable
      `miner_id` / `sequence` / `timestamp_unix` / `schema_version`
      attributes (`timestamp_unix=None` ⇒ vali's current clock).
    - `fail_category` is the `error_class` reported on "failed".
    - `calls` records every `(envelope, verifying_key)` verified.
    """

    def __init__(self) -> None:
        self.outcome = "ok"
        self.miner_id = MINER_ID
        self.sequence = 1
        self.timestamp_unix: int | None = None
        self.schema_version = 1
        self.graceful_exit_requested = False
        self.memory_available_mib: int | None = None
        self.fail_category = "signature_invalid"
        self.calls: list[tuple[bytes, bytes]] = []

    def verify_heartbeat(
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
            memory_available_mib=self.memory_available_mib,
            graceful_exit_requested=self.graceful_exit_requested,
        )


@pytest.fixture(autouse=True)
def fake_heartbeat_verifier(
    monkeypatch: pytest.MonkeyPatch,
) -> FakeHeartbeatVerifier:
    """Replace the `verify-heartbeat` shell-out with `FakeHeartbeatVerifier`."""
    fake = FakeHeartbeatVerifier()
    monkeypatch.setattr(verifier, "verify_heartbeat", fake.verify_heartbeat)
    return fake


# ─── helpers ─────────────────────────────────────────────────────────


def _make_miner(
    *,
    miner_id: str = MINER_ID,
    status: str = MinerStatus.ACTIVE.value,
    source_active: bool = True,
    quarantined_until=None,
    consecutive_failures: int = 0,
) -> MinerIdentity:
    """Register a `MinerIdentity` + its linked miner `TelemetrySource`
    — the two rows a real `POST /v1/admin/miner/register` provisions.
    """
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
        quarantined_until=quarantined_until,
        consecutive_failures=consecutive_failures,
    )
    return miner


def _post_heartbeat(
    body: bytes = b"signed-heartbeat-cbor",
    *,
    peer_id: str | None = PEER_ID,
    client: APIClient | None = None,
):
    """POST a raw-CBOR heartbeat. The CBOR ingress carries no bearer
    token, so an unauthenticated `APIClient` is the default.
    """
    api = client if client is not None else APIClient()
    extra: dict[str, Any] = {}
    if peer_id is not None:
        extra["HTTP_X_HIPPIUS_PEER_ID"] = peer_id
    return api.post(
        INGEST_URL, data=body, content_type="application/cbor", **extra
    )


# ─── happy path ──────────────────────────────────────────────────────


def test_heartbeat_accepts_first_valid_sequence(
    fake_heartbeat_verifier: FakeHeartbeatVerifier,
) -> None:
    miner = _make_miner()
    fake_heartbeat_verifier.sequence = 7

    resp = _post_heartbeat()

    assert resp.status_code == 202, resp.content
    body = resp.json()
    assert body["created"] is True
    # The replay cursor + liveness clock are bumped on accept.
    miner.refresh_from_db()
    assert miner.last_heartbeat_sequence == 7
    assert miner.last_seen_at is not None
    # The heartbeat is recorded as a TERMINAL (DONE) audit envelope — its
    # whole effect (last_seen_at + sequence) is applied at ingest and
    # nothing pull()s kind=heartbeat, so it stays out of the backpressure
    # count and is GC-reaped.
    env = TelemetryEnvelope.objects.get(envelope_id=body["envelope_id"])
    assert env.kind == EnvelopeKind.HEARTBEAT.value
    assert env.source == SourceType.MINER.value
    assert env.source_id == MINER_ID
    assert env.processing_status == ProcessingStatus.DONE.value
    # The verifier saw the raw envelope + the registered key.
    assert fake_heartbeat_verifier.calls == [(b"signed-heartbeat-cbor", bytes(32))]


def test_heartbeat_ingress_needs_no_bearer_token() -> None:
    # The Edge's forward leg carries no token — a plain (unauthenticated)
    # client must still be accepted on the CBOR path.
    _make_miner()
    resp = APIClient().post(
        INGEST_URL,
        data=b"hb",
        content_type="application/cbor",
        HTTP_X_HIPPIUS_PEER_ID=PEER_ID,
    )
    assert resp.status_code == 202, resp.content


def test_heartbeat_accepts_monotonic_increments(
    fake_heartbeat_verifier: FakeHeartbeatVerifier,
) -> None:
    # Sequences need not be contiguous — only strictly increasing.
    miner = _make_miner()
    for seq in (1, 2, 5, 100):
        fake_heartbeat_verifier.sequence = seq
        assert _post_heartbeat().status_code == 202
    miner.refresh_from_db()
    assert miner.last_heartbeat_sequence == 100
    assert (
        TelemetryEnvelope.objects.filter(
            kind=EnvelopeKind.HEARTBEAT.value
        ).count()
        == 4
    )


# ─── timestamp skew ──────────────────────────────────────────────────


def test_heartbeat_rejects_timestamp_too_old(
    fake_heartbeat_verifier: FakeHeartbeatVerifier,
) -> None:
    _make_miner()
    fake_heartbeat_verifier.timestamp_unix = int(time.time()) - 400
    resp = _post_heartbeat()
    assert resp.status_code == 400
    assert resp.json()["category"] == "timestamp-skew"
    assert not TelemetryEnvelope.objects.exists()


def test_heartbeat_rejects_timestamp_too_new(
    fake_heartbeat_verifier: FakeHeartbeatVerifier,
) -> None:
    _make_miner()
    fake_heartbeat_verifier.timestamp_unix = int(time.time()) + 400
    resp = _post_heartbeat()
    assert resp.status_code == 400
    assert resp.json()["category"] == "timestamp-skew"


# ─── monotonic sequence replay defence ───────────────────────────────


def test_heartbeat_rejects_sequence_replay(
    fake_heartbeat_verifier: FakeHeartbeatVerifier,
) -> None:
    miner = _make_miner()
    fake_heartbeat_verifier.sequence = 5
    assert _post_heartbeat().status_code == 202
    # The same sequence again — `5 <= 5` — is a replay.
    resp = _post_heartbeat()
    assert resp.status_code == 400
    assert resp.json()["category"] == "sequence-replay"
    miner.refresh_from_db()
    assert miner.last_heartbeat_sequence == 5
    # Only the first heartbeat was enqueued.
    assert TelemetryEnvelope.objects.count() == 1


def test_heartbeat_rejects_sequence_regression(
    fake_heartbeat_verifier: FakeHeartbeatVerifier,
) -> None:
    miner = _make_miner()
    fake_heartbeat_verifier.sequence = 10
    assert _post_heartbeat().status_code == 202
    # A lower sequence — `5 < 10` — is a regression / replay.
    fake_heartbeat_verifier.sequence = 5
    resp = _post_heartbeat()
    assert resp.status_code == 400
    assert resp.json()["category"] == "sequence-replay"
    miner.refresh_from_db()
    assert miner.last_heartbeat_sequence == 10


def test_heartbeat_rejects_sequence_out_of_i64_range(
    fake_heartbeat_verifier: FakeHeartbeatVerifier,
) -> None:
    # The signed `sequence` is a Rust u64; `last_heartbeat_sequence` is
    # a Postgres signed bigint. A value past i64::MAX must be refused
    # with a clean 400 — never an unhandled DataError / 500.
    _make_miner()
    fake_heartbeat_verifier.sequence = 2**63
    resp = _post_heartbeat()
    assert resp.status_code == 400
    assert resp.json()["category"] == "sequence-out-of-range"
    assert not TelemetryEnvelope.objects.exists()


# ─── source / identity gates ─────────────────────────────────────────


def test_heartbeat_rejects_unknown_miner_source() -> None:
    # No TelemetrySource row at all — nothing to verify against.
    resp = _post_heartbeat()
    assert resp.status_code == 403
    assert resp.json()["category"] == "source-not-registered"


def test_heartbeat_rejects_inactive_source() -> None:
    # A quarantined miner's linked source is deactivated — refused at
    # the registered-source gate before any verify is spent.
    _make_miner(status=MinerStatus.QUARANTINED.value, source_active=False)
    resp = _post_heartbeat()
    assert resp.status_code == 403
    assert resp.json()["category"] == "source-not-registered"


def test_heartbeat_rejects_miner_not_in_registry() -> None:
    # Defence in depth: a miner `TelemetrySource` with no matching
    # `MinerIdentity` row (an inconsistent state) is refused 404 by the
    # in-transaction registry lookup.
    TelemetrySource.objects.create(
        source=SourceType.MINER.value,
        source_id=MINER_ID,
        verifying_key=bytes(32),
        is_active=True,
    )
    resp = _post_heartbeat()
    assert resp.status_code == 404
    assert resp.json()["category"] == "miner-not-registered"


def test_heartbeat_rejects_quarantined_miner_identity() -> None:
    # Defence in depth: the in-transaction lifecycle gate refuses a
    # quarantined `MinerIdentity` even if its source row is (in an
    # inconsistent state) still active.
    _make_miner(status=MinerStatus.QUARANTINED.value, source_active=True)
    resp = _post_heartbeat()
    assert resp.status_code == 403
    assert resp.json()["category"] == "miner-quarantined"


def test_heartbeat_rejects_miner_id_mismatch(
    fake_heartbeat_verifier: FakeHeartbeatVerifier,
) -> None:
    # The signed body's miner_id disagrees with the authenticated peer.
    _make_miner()
    fake_heartbeat_verifier.miner_id = "a-different-miner"
    resp = _post_heartbeat()
    assert resp.status_code == 400
    assert resp.json()["category"] == "miner-id-mismatch"


def test_heartbeat_rejects_missing_peer_id_header() -> None:
    _make_miner()
    resp = _post_heartbeat(peer_id=None)
    assert resp.status_code == 400
    assert resp.json()["category"] == "wire"


def test_heartbeat_rejects_malformed_peer_id_header() -> None:
    # A peer-id without the `hippius-miner:` SAN prefix is malformed.
    _make_miner()
    resp = _post_heartbeat(peer_id="spiffe://something/else")
    assert resp.status_code == 400
    assert resp.json()["category"] == "wire"


# ─── body shape ──────────────────────────────────────────────────────


def test_heartbeat_rejects_empty_body() -> None:
    _make_miner()
    resp = _post_heartbeat(body=b"")
    assert resp.status_code == 400


def test_heartbeat_rejects_oversize_body() -> None:
    _make_miner()
    resp = _post_heartbeat(body=b"\x00" * 9000)
    assert resp.status_code == 413
    assert resp.json()["category"] == "too-large"


# ─── verifier outcomes ───────────────────────────────────────────────


def test_heartbeat_verification_failure_records_failed_and_poisons(
    fake_heartbeat_verifier: FakeHeartbeatVerifier,
) -> None:
    _make_miner()
    fake_heartbeat_verifier.outcome = "failed"
    resp = _post_heartbeat()
    assert resp.status_code == 400
    assert resp.json()["category"] == "verify-failed"
    # The bad envelope is retained `Failed` for forensics.
    assert (
        TelemetryEnvelope.objects.filter(
            processing_status=ProcessingStatus.FAILED.value
        ).count()
        == 1
    )
    # A §9 poison strike was counted on the miner's source.
    src = TelemetrySource.objects.get(
        source=SourceType.MINER.value, source_id=MINER_ID
    )
    assert src.consecutive_failures == 1


def test_heartbeat_verifier_unavailable_is_503_and_not_a_strike(
    fake_heartbeat_verifier: FakeHeartbeatVerifier,
) -> None:
    _make_miner()
    fake_heartbeat_verifier.outcome = "unavailable"
    resp = _post_heartbeat()
    assert resp.status_code == 503
    assert resp.json()["category"] == "internal"
    # A binary failure is vali's fault — never a poison strike.
    src = TelemetrySource.objects.get(
        source=SourceType.MINER.value, source_id=MINER_ID
    )
    assert src.consecutive_failures == 0
    assert not TelemetryEnvelope.objects.exists()


def test_heartbeat_policy_reject_does_not_reset_poison(
    fake_heartbeat_verifier: FakeHeartbeatVerifier,
) -> None:
    # A heartbeat that VERIFIES but is then policy-rejected (here:
    # timestamp skew) must leave the §9 poison counter untouched — a
    # captured-and-replayed valid heartbeat must not clear strikes.
    _make_miner(consecutive_failures=2)
    fake_heartbeat_verifier.timestamp_unix = int(time.time()) - 400
    resp = _post_heartbeat()
    assert resp.status_code == 400
    src = TelemetrySource.objects.get(
        source=SourceType.MINER.value, source_id=MINER_ID
    )
    assert src.consecutive_failures == 2


def test_heartbeat_full_accept_resets_poison(
    fake_heartbeat_verifier: FakeHeartbeatVerifier,
) -> None:
    # A genuinely delivered heartbeat breaks the consecutive-failure run.
    _make_miner(consecutive_failures=2)
    assert _post_heartbeat().status_code == 202
    src = TelemetrySource.objects.get(
        source=SourceType.MINER.value, source_id=MINER_ID
    )
    assert src.consecutive_failures == 0


def test_heartbeat_rejects_quarantined_source(
    fake_heartbeat_verifier: FakeHeartbeatVerifier,
) -> None:
    # A §9-poison-quarantined source is refused outright (429).
    from datetime import timedelta

    from django.utils import timezone

    _make_miner(
        quarantined_until=timezone.now() + timedelta(hours=1),
    )
    resp = _post_heartbeat()
    assert resp.status_code == 429
    assert resp.json()["category"] == "source-quarantined"


def test_heartbeat_backpressure_when_queue_full(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(settings, "VALI_TELEMETRY_MAX_PENDING", 1)
    _make_miner()
    # Fill the GLOBAL queue with a DIFFERENT source's Pending envelope, so
    # the posting miner is not at its own per-source cap — this exercises
    # the global gate (RA-M4 added a per-source gate that fires first when
    # ONE source fills a tiny queue).
    TelemetryEnvelope.objects.create(
        source=SourceType.EDGE_GATEWAY.value,
        source_id="other-source",
        kind=EnvelopeKind.EDGE_TELEMETRY.value,
        schema_version=1,
        payload_cbor=b"x",
        processing_status=ProcessingStatus.PENDING.value,
    )
    resp = _post_heartbeat()
    assert resp.status_code == 503
    assert resp.json()["category"] == "backpressure"


# ─── trust-plane orthogonality ───────────────────────────────────────


def test_kind_heartbeat_via_json_wrapper_is_rejected(
    plain_client: APIClient, fake_verifier
) -> None:
    # A heartbeat is a raw-CBOR ingress — the JSON wrapper must not
    # accept `kind=heartbeat` (it would never reach the heartbeat
    # gates). Driven with an authenticated client so the rejection is
    # the wire-shape gate, not the JSON path's token auth.
    _make_miner()
    resp = plain_client.post(
        INGEST_URL,
        {
            "schema_version": 1,
            "source": "miner",
            "source_id": MINER_ID,
            "kind": "heartbeat",
            "body_hex": b"x".hex(),
            "sig_hex": "00" * 64,
        },
        format="json",
    )
    assert resp.status_code == 400


def test_served_receipt_unaffected_by_heartbeat_logic(
    plain_client: APIClient, fake_verifier
) -> None:
    # The tenant served-receipt plane is orthogonal: a JSON-wrapper
    # `served_receipt` ingest must succeed and never touch the miner
    # identity registry.
    TelemetrySource.objects.create(
        source=SourceType.TENANT_VM.value,
        source_id="vm-42",
        verifying_key=bytes(32),
    )
    resp = plain_client.post(
        INGEST_URL,
        {
            "schema_version": 1,
            "source": "tenant_vm",
            "source_id": "vm-42",
            "kind": "served_receipt",
            "body_hex": b"served-body".hex(),
            "sig_hex": "00" * 64,
        },
        format="json",
    )
    assert resp.status_code == 202, resp.content
    assert MinerIdentity.objects.count() == 0


# ─── v2 graceful-exit flag (transport (B)) ───────────────────────────


def test_v2_graceful_exit_flag_accepts_heartbeat_and_quarantines(
    fake_heartbeat_verifier: FakeHeartbeatVerifier,
) -> None:
    # A v2 heartbeat carrying graceful_exit_requested=true is ACCEPTED
    # (the miner is alive — liveness is recorded) AND the miner is
    # quarantined so the §13/§25 auto-migration warm-migrates its VMs
    # off. The heartbeat is NOT rejected.
    miner = _make_miner()
    fake_heartbeat_verifier.schema_version = 2
    fake_heartbeat_verifier.graceful_exit_requested = True
    fake_heartbeat_verifier.sequence = 9

    resp = _post_heartbeat()

    # Accepted: 202, the envelope is enqueued, liveness is recorded.
    assert resp.status_code == 202, resp.content
    body = resp.json()
    assert body["created"] is True
    miner.refresh_from_db()
    assert miner.last_heartbeat_sequence == 9
    assert miner.last_seen_at is not None
    # Quarantined: the SAME row-locked transition the Edge-relayed
    # graceful-exit path runs.
    assert miner.status == MinerStatus.QUARANTINED.value
    # The §13/§25 auto-migration enrolment — the linked source is off.
    src = TelemetrySource.objects.get(
        source=SourceType.MINER.value, source_id=MINER_ID
    )
    assert src.is_active is False
    # The accepted heartbeat is recorded as a terminal (DONE) envelope.
    env = TelemetryEnvelope.objects.get(envelope_id=body["envelope_id"])
    assert env.kind == EnvelopeKind.HEARTBEAT.value


def test_v2_flag_false_does_not_quarantine(
    fake_heartbeat_verifier: FakeHeartbeatVerifier,
) -> None:
    # A v2 heartbeat with the flag FALSE is an ordinary (non-exiting)
    # heartbeat — accepted, NEVER quarantined.
    miner = _make_miner()
    fake_heartbeat_verifier.schema_version = 2
    fake_heartbeat_verifier.graceful_exit_requested = False

    assert _post_heartbeat().status_code == 202
    miner.refresh_from_db()
    assert miner.status == MinerStatus.ACTIVE.value
    src = TelemetrySource.objects.get(
        source=SourceType.MINER.value, source_id=MINER_ID
    )
    assert src.is_active is True


def test_v1_heartbeat_never_quarantines(
    fake_heartbeat_verifier: FakeHeartbeatVerifier,
) -> None:
    # A v1 heartbeat carries no flag (HeartbeatBody defaults it false),
    # so the quarantine path is never taken — backward-compat sanity.
    miner = _make_miner()
    fake_heartbeat_verifier.schema_version = 1
    # graceful_exit_requested stays the default False.

    assert _post_heartbeat().status_code == 202
    miner.refresh_from_db()
    assert miner.status == MinerStatus.ACTIVE.value


def test_v2_graceful_exit_then_next_heartbeat_is_refused(
    fake_heartbeat_verifier: FakeHeartbeatVerifier,
) -> None:
    # The first graceful-exit heartbeat quarantines the miner — which
    # ALSO deactivates its linked `TelemetrySource` (the §13/§25
    # auto-migration enrolment). A LATER heartbeat from the now-exiting
    # miner is therefore refused at the very first gate (the inactive
    # source, 403 `source-not-registered`), never re-accepted — the
    # graceful exit is a one-way transition. The quarantine stays put.
    miner = _make_miner()
    fake_heartbeat_verifier.schema_version = 2
    fake_heartbeat_verifier.graceful_exit_requested = True
    fake_heartbeat_verifier.sequence = 1
    assert _post_heartbeat().status_code == 202
    miner.refresh_from_db()
    assert miner.status == MinerStatus.QUARANTINED.value

    fake_heartbeat_verifier.sequence = 2
    resp = _post_heartbeat()
    assert resp.status_code == 403
    assert resp.json()["category"] == "source-not-registered"
    miner.refresh_from_db()
    assert miner.status == MinerStatus.QUARANTINED.value


# ─── self-reported free RAM → scheduler mirror (dynamic capacity) ─────


def _make_bridged_miner(node_id_hex: str):
    """A `_make_miner` whose `chain_node_id` is set + a matching
    `MinerCapacity` mirror row — the bridge the self-report update keys on.
    """
    from django.utils import timezone

    from apps.scheduler.models import MinerCapacity, MinerStatusMirror

    miner = _make_miner()
    miner.chain_node_id = node_id_hex
    miner.save(update_fields=["chain_node_id"])
    MinerCapacity.objects.create(
        miner_node_id=node_id_hex,
        status=MinerStatusMirror.ACTIVE,
        capacity_slots=8,
        observed_epoch=10,
        data_epoch=10,
        refreshed_at=timezone.now(),
    )
    return miner


def test_heartbeat_records_reported_free_memory_on_mirror(
    fake_heartbeat_verifier: FakeHeartbeatVerifier,
) -> None:
    """A fresh heartbeat's UNTRUSTED `memory_available_mib` is stored on
    the scheduler mirror (keyed by chain_node_id) for the down-only
    dynamic-capacity throttle."""
    from apps.scheduler.models import MinerCapacity

    node = "aa" * 32
    _make_bridged_miner(node)
    fake_heartbeat_verifier.sequence = 3
    fake_heartbeat_verifier.memory_available_mib = 94_000

    assert _post_heartbeat().status_code == 202
    mc = MinerCapacity.objects.get(miner_node_id=node)
    assert mc.reported_memory_available_mib == 94_000
    assert mc.reported_at is not None


def test_heartbeat_without_bridge_does_not_write_mirror(
    fake_heartbeat_verifier: FakeHeartbeatVerifier,
) -> None:
    """No `chain_node_id` bridge ⇒ the self-report update no-ops (a miner
    not yet bridged to the scheduler simply carries no reported value)."""
    from apps.scheduler.models import MinerCapacity

    _make_miner()  # no chain_node_id
    fake_heartbeat_verifier.sequence = 4
    fake_heartbeat_verifier.memory_available_mib = 94_000

    assert _post_heartbeat().status_code == 202
    assert not MinerCapacity.objects.filter(
        reported_memory_available_mib__isnull=False
    ).exists()
