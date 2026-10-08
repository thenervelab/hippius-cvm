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

MINER_ID = "miner-a"
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
        self.declared_capacity: verifier.DeclaredCapacity | None = None
        self.declared_disk: verifier.DeclaredDisk | None = None
        self.declared_host_health: verifier.DeclaredHostHealth | None = None
        self.agent_version: str | None = None
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
            declared_capacity=self.declared_capacity,
            declared_disk=self.declared_disk,
            declared_host_health=self.declared_host_health,
            agent_version=self.agent_version,
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


# ─── v3 capacity declarations → scheduler mirror (capacity v2 §4.2) ───

_DECLARED_COLUMNS = (
    "declared_cpu_budget",
    "declared_memory_mb_budget",
    "declared_asid_capacity",
    "declared_asid_used",
)


def _declared(mc) -> tuple:
    return tuple(getattr(mc, c) for c in _DECLARED_COLUMNS)


def test_v3_heartbeat_records_the_capacity_declaration(
    fake_heartbeat_verifier: FakeHeartbeatVerifier,
) -> None:
    from apps.scheduler.models import MinerCapacity

    node = "ab" * 32
    _make_bridged_miner(node)
    fake_heartbeat_verifier.schema_version = 3
    fake_heartbeat_verifier.memory_available_mib = 94_000
    fake_heartbeat_verifier.declared_capacity = verifier.DeclaredCapacity(
        cvm_cpu_budget=44, cvm_memory_mb_budget=120_000, asid_capacity=99, asid_used=2
    )

    assert _post_heartbeat().status_code == 202
    mc = MinerCapacity.objects.get(miner_node_id=node)
    assert _declared(mc) == (44, 120_000, 99, 2)
    assert mc.declared_at is not None
    assert mc.declared_at == mc.reported_at
    assert mc.reported_memory_available_mib == 94_000


def test_v3_unknown_zero_values_are_stored_as_null(
    fake_heartbeat_verifier: FakeHeartbeatVerifier,
) -> None:
    """`0` on the wire = the miner could not read it ⇒ NULL (no clamp),
    never a literal 0 that would read as a zero budget."""
    from apps.scheduler.models import MinerCapacity

    node = "ac" * 32
    _make_bridged_miner(node)
    MinerCapacity.objects.filter(miner_node_id=node).update(
        declared_cpu_budget=10,
        declared_memory_mb_budget=10,
        declared_asid_capacity=10,
        declared_asid_used=10,
    )
    fake_heartbeat_verifier.schema_version = 3
    fake_heartbeat_verifier.declared_capacity = verifier.DeclaredCapacity(
        cvm_cpu_budget=0, cvm_memory_mb_budget=64_000, asid_capacity=0, asid_used=0
    )

    assert _post_heartbeat().status_code == 202
    mc = MinerCapacity.objects.get(miner_node_id=node)
    assert _declared(mc) == (None, 64_000, None, None)
    assert mc.declared_at is not None


@pytest.mark.parametrize("schema_version", [1, 2])
def test_pre_v3_heartbeat_leaves_the_declaration_untouched(
    fake_heartbeat_verifier: FakeHeartbeatVerifier, schema_version: int
) -> None:
    """A `v1`/`v2` heartbeat carries no declaration: the stored one (and
    its `declared_at`) is left exactly as it was — neither refreshed nor
    NULLed — so it ages out through the staleness window on its own."""
    from datetime import timedelta

    from django.utils import timezone

    from apps.scheduler.models import MinerCapacity

    node = "ad" * 32
    _make_bridged_miner(node)
    stamped = timezone.now() - timedelta(minutes=3)
    MinerCapacity.objects.filter(miner_node_id=node).update(
        declared_cpu_budget=44,
        declared_memory_mb_budget=120_000,
        declared_asid_capacity=99,
        declared_asid_used=2,
        declared_at=stamped,
    )
    fake_heartbeat_verifier.schema_version = schema_version
    fake_heartbeat_verifier.memory_available_mib = 90_000

    assert _post_heartbeat().status_code == 202
    mc = MinerCapacity.objects.get(miner_node_id=node)
    assert _declared(mc) == (44, 120_000, 99, 2)
    assert mc.declared_at == stamped
    # The RAM report on the same heartbeat still landed.
    assert mc.reported_memory_available_mib == 90_000


def test_v3_declaration_write_is_a_targeted_update(
    fake_heartbeat_verifier: FakeHeartbeatVerifier,
) -> None:
    """The declaration lands through a filtered UPDATE that sets ONLY the
    `declared_*` columns — never a full-row save that could roll back a
    concurrent chain refresh / policy write on the same row."""
    from django.db import connection
    from django.test.utils import CaptureQueriesContext

    from apps.scheduler.models import MinerCapacity

    node = "ae" * 32
    _make_bridged_miner(node)
    fake_heartbeat_verifier.schema_version = 3
    fake_heartbeat_verifier.declared_capacity = verifier.DeclaredCapacity(
        cvm_cpu_budget=44, cvm_memory_mb_budget=120_000, asid_capacity=99, asid_used=2
    )

    with CaptureQueriesContext(connection) as ctx:
        assert _post_heartbeat().status_code == 202
    table = MinerCapacity._meta.db_table
    declared_updates = [
        q["sql"]
        for q in ctx.captured_queries
        if q["sql"].startswith(f'UPDATE "{table}"') and "declared_at" in q["sql"]
    ]
    assert len(declared_updates) == 1, declared_updates
    set_clause = declared_updates[0].split(" SET ", 1)[1].split(" WHERE ", 1)[0]
    columns = sorted(part.split(" = ")[0].strip('"') for part in set_clause.split(", "))
    assert columns == sorted([*_DECLARED_COLUMNS, "declared_at"])


def test_v3_heartbeat_without_bridge_writes_no_declaration(
    fake_heartbeat_verifier: FakeHeartbeatVerifier,
) -> None:
    from apps.scheduler.models import MinerCapacity

    _make_miner()  # no chain_node_id
    fake_heartbeat_verifier.schema_version = 3
    fake_heartbeat_verifier.declared_capacity = verifier.DeclaredCapacity(44, 120_000, 99, 2)

    assert _post_heartbeat().status_code == 202
    assert not MinerCapacity.objects.filter(declared_at__isnull=False).exists()


def test_v3_declaration_reaches_the_scheduler_budget_as_a_clamp(
    fake_heartbeat_verifier: FakeHeartbeatVerifier,
) -> None:
    """The ingested declaration is what `budget_inputs` reads (fresh-only)."""
    from apps.scheduler.models import MinerCapacity
    from apps.scheduler.service import _Committed, budget_inputs

    node = "af" * 32
    _make_bridged_miner(node)
    fake_heartbeat_verifier.schema_version = 3
    fake_heartbeat_verifier.declared_capacity = verifier.DeclaredCapacity(44, 120_000, 99, 2)

    assert _post_heartbeat().status_code == 202
    inp = budget_inputs(MinerCapacity.objects.get(miner_node_id=node), _Committed(0, 0, 0))
    assert inp.declared_cpu_budget == 44
    assert inp.declared_memory_mb_budget == 120_000
    assert inp.declared_asid_capacity == 99


# ─── v4 DATA-disk figures → scheduler mirror (storage-aware placement) ───

_DISK_COLUMNS = (
    "declared_disk_gb_budget",
    "reported_data_disk_total_gb",
    "reported_data_disk_available_gb",
    "reported_staging_disk_available_gb",
)


def _disk(mc) -> tuple:
    return tuple(getattr(mc, c) for c in _DISK_COLUMNS)


def test_v4_heartbeat_records_the_disk_figures(
    fake_heartbeat_verifier: FakeHeartbeatVerifier,
) -> None:
    from apps.scheduler.models import MinerCapacity

    node = "b1" * 32
    _make_bridged_miner(node)
    fake_heartbeat_verifier.schema_version = 4
    fake_heartbeat_verifier.declared_capacity = verifier.DeclaredCapacity(44, 120_000, 99, 2)
    fake_heartbeat_verifier.declared_disk = verifier.DeclaredDisk(3000, 3500, 3200, 400)

    assert _post_heartbeat().status_code == 202
    mc = MinerCapacity.objects.get(miner_node_id=node)
    assert _disk(mc) == (3000, 3500, 3200, 400)
    assert mc.disk_reported_at is not None
    assert mc.declared_cpu_budget == 44  # the v3 half of a v4 body still lands


def test_v4_unknown_zero_disk_values_are_stored_as_null(
    fake_heartbeat_verifier: FakeHeartbeatVerifier,
) -> None:
    from apps.scheduler.models import MinerCapacity

    node = "b2" * 32
    _make_bridged_miner(node)
    MinerCapacity.objects.filter(miner_node_id=node).update(
        declared_disk_gb_budget=1, reported_data_disk_total_gb=1
    )
    fake_heartbeat_verifier.schema_version = 4
    fake_heartbeat_verifier.declared_disk = verifier.DeclaredDisk(0, 0, 3200, 2**32 - 1)

    assert _post_heartbeat().status_code == 202
    mc = MinerCapacity.objects.get(miner_node_id=node)
    # 0 = unknown; a u32 above the column's range is not a real host either.
    assert _disk(mc) == (None, None, 3200, None)


def test_v4_zero_available_next_to_a_total_is_a_full_disk_not_unknown(
    fake_heartbeat_verifier: FakeHeartbeatVerifier,
) -> None:
    """statvfs rounds down: a full data fs reports available 0. Next to a
    known total that 0 is kept — it is the figure that stops placements."""
    from apps.scheduler.models import MinerCapacity

    node = "b5" * 32
    _make_bridged_miner(node)
    fake_heartbeat_verifier.schema_version = 4
    fake_heartbeat_verifier.declared_disk = verifier.DeclaredDisk(3000, 3500, 0, 0)

    assert _post_heartbeat().status_code == 202
    assert _disk(MinerCapacity.objects.get(miner_node_id=node)) == (3000, 3500, 0, None)


@pytest.mark.parametrize("schema_version", [1, 2, 3])
def test_pre_v4_heartbeat_leaves_the_disk_figures_unknown_or_untouched(
    fake_heartbeat_verifier: FakeHeartbeatVerifier, schema_version: int
) -> None:
    from datetime import timedelta

    from django.utils import timezone

    from apps.scheduler.models import MinerCapacity

    fresh = "b3" * 32
    _make_bridged_miner(fresh)
    fake_heartbeat_verifier.schema_version = schema_version
    if schema_version == 3:
        fake_heartbeat_verifier.declared_capacity = verifier.DeclaredCapacity(44, 1, 99, 2)
    assert _post_heartbeat().status_code == 202
    mc = MinerCapacity.objects.get(miner_node_id=fresh)
    assert _disk(mc) == (None, None, None, None)
    assert mc.disk_reported_at is None

    # A stored v4 report is left exactly as it was (it ages out on its own).
    stamped = timezone.now() - timedelta(minutes=3)
    MinerCapacity.objects.filter(miner_node_id=fresh).update(
        declared_disk_gb_budget=3000, disk_reported_at=stamped
    )
    fake_heartbeat_verifier.sequence += 1
    assert _post_heartbeat().status_code == 202
    mc = MinerCapacity.objects.get(miner_node_id=fresh)
    assert mc.declared_disk_gb_budget == 3000 and mc.disk_reported_at == stamped


def test_v4_disk_figures_reach_the_scheduler_disk_budget(
    fake_heartbeat_verifier: FakeHeartbeatVerifier,
) -> None:
    from apps.scheduler import service

    node = "b4" * 32
    _make_bridged_miner(node)
    fake_heartbeat_verifier.schema_version = 4
    fake_heartbeat_verifier.declared_disk = verifier.DeclaredDisk(3000, 3500, 3200, 400)

    assert _post_heartbeat().status_code == 202
    d = service.disk_budgets_by_node()[node]
    assert (d.known, d.budget_gb, d.binding) == (True, 3000, "disk:declared")


# ─── v5 SEV-SNP host health → scheduler mirror (observability) ───────────

_HOST_HEALTH_COLUMNS = (
    "reported_snp_enabled",
    "reported_cpus_offline",
    "reported_snp_launches_since_boot",
    "reported_df_flush_failures",
)


def _host_health(mc) -> tuple:
    return tuple(getattr(mc, c) for c in _HOST_HEALTH_COLUMNS)


def test_v5_heartbeat_records_the_host_health_report(
    fake_heartbeat_verifier: FakeHeartbeatVerifier,
) -> None:
    from apps.scheduler.models import MinerCapacity

    node = "c1" * 32
    _make_bridged_miner(node)
    fake_heartbeat_verifier.schema_version = 5
    fake_heartbeat_verifier.declared_capacity = verifier.DeclaredCapacity(44, 120_000, 99, 4)
    fake_heartbeat_verifier.declared_disk = verifier.DeclaredDisk(3000, 3500, 3200, 400)
    fake_heartbeat_verifier.declared_host_health = verifier.DeclaredHostHealth(
        snp_enabled=True, cpus_offline=24, snp_launches_since_boot=97, df_flush_failures=3
    )

    assert _post_heartbeat().status_code == 202
    mc = MinerCapacity.objects.get(miner_node_id=node)
    assert _host_health(mc) == (True, 24, 97, 3)
    assert mc.host_health_reported_at is not None
    # The v3 and v4 halves of a v5 body still land.
    assert mc.declared_asid_used == 4
    assert mc.reported_data_disk_total_gb == 3500


def test_v5_zero_is_a_real_reading_and_an_out_of_range_count_is_null(
    fake_heartbeat_verifier: FakeHeartbeatVerifier,
) -> None:
    from apps.scheduler.models import MinerCapacity

    node = "c2" * 32
    _make_bridged_miner(node)
    fake_heartbeat_verifier.schema_version = 5
    fake_heartbeat_verifier.declared_host_health = verifier.DeclaredHostHealth(
        snp_enabled=False, cpus_offline=0, snp_launches_since_boot=2**32 - 1, df_flush_failures=0
    )

    assert _post_heartbeat().status_code == 202
    mc = MinerCapacity.objects.get(miner_node_id=node)
    assert _host_health(mc) == (False, 0, None, 0)


@pytest.mark.parametrize("schema_version", [1, 3, 4])
def test_pre_v5_heartbeat_leaves_the_host_health_report_untouched(
    fake_heartbeat_verifier: FakeHeartbeatVerifier, schema_version: int
) -> None:
    from datetime import timedelta

    from django.utils import timezone

    from apps.scheduler.models import MinerCapacity

    node = "c3" * 32
    _make_bridged_miner(node)
    stamped = timezone.now() - timedelta(minutes=3)
    MinerCapacity.objects.filter(miner_node_id=node).update(
        reported_snp_enabled=True,
        reported_cpus_offline=24,
        reported_snp_launches_since_boot=50,
        reported_df_flush_failures=0,
        host_health_reported_at=stamped,
    )
    fake_heartbeat_verifier.schema_version = schema_version
    assert _post_heartbeat().status_code == 202
    mc = MinerCapacity.objects.get(miner_node_id=node)
    assert _host_health(mc) == (True, 24, 50, 0)
    assert mc.host_health_reported_at == stamped


def test_the_reeval_survey_pushes_the_stored_host_health_report(
    fake_heartbeat_verifier: FakeHeartbeatVerifier, monkeypatch: pytest.MonkeyPatch
) -> None:
    from django.test import override_settings

    from apps.scheduler.management.commands import vali_scheduler_reeval as reeval
    from apps.synthetic import metrics

    node = "c4" * 32
    _make_bridged_miner(node)
    fake_heartbeat_verifier.schema_version = 5
    fake_heartbeat_verifier.declared_host_health = verifier.DeclaredHostHealth(
        snp_enabled=True, cpus_offline=24, snp_launches_since_boot=97, df_flush_failures=3
    )
    assert _post_heartbeat().status_code == 202

    pushed: list[tuple[str, str]] = []
    monkeypatch.setattr(
        metrics, "push", lambda ms, **k: pushed.append((k["job"], ms.render())) or True
    )
    with override_settings(VALI_SYNTHETIC_PUSHGATEWAY_URL="http://pgw"):
        reeval.host_health_survey()
    assert [job for job, _ in pushed] == ["vali-host-health"]
    body = pushed[0][1]
    labels = f'{{miner_id="{MINER_ID}",node_id="{node}"}}'
    assert f"hippius_miner_snp_enabled{labels} 1" in body
    assert f"hippius_miner_cpus_offline{labels} 24" in body
    assert f"hippius_miner_snp_launches_since_boot{labels} 97" in body
    assert f"hippius_miner_df_flush_failures{labels} 3" in body
    assert f"hippius_miner_host_health_reported_timestamp_seconds{labels} " in body
    assert f"hippius_miner_host_health_reporting{labels} 1" in body


def test_the_reeval_survey_marks_an_active_miner_without_a_v5_report(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from django.test import override_settings

    from apps.scheduler.management.commands import vali_scheduler_reeval as reeval
    from apps.synthetic import metrics

    node = "c5" * 32
    _make_bridged_miner(node)
    pushed: list[str] = []
    monkeypatch.setattr(metrics, "push", lambda ms, **_k: pushed.append(ms.render()) or True)
    with override_settings(VALI_SYNTHETIC_PUSHGATEWAY_URL="http://pgw"):
        reeval.host_health_survey()
    assert len(pushed) == 1
    labels = f'{{miner_id="{MINER_ID}",node_id="{node}"}}'
    assert f"hippius_miner_host_health_reporting{labels} 0" in pushed[0]
    assert "hippius_miner_cpus_offline" not in pushed[0]


def test_the_reeval_survey_drops_a_miner_that_left_the_active_set(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A quarantined / retired miner's last report must not keep alerting."""
    from django.test import override_settings
    from django.utils import timezone

    from apps.scheduler.management.commands import vali_scheduler_reeval as reeval
    from apps.scheduler.models import MinerCapacity
    from apps.synthetic import metrics

    node = "c6" * 32
    miner = _make_bridged_miner(node)
    MinerCapacity.objects.filter(miner_node_id=node).update(
        reported_snp_enabled=True,
        reported_cpus_offline=24,
        reported_df_flush_failures=3,
        host_health_reported_at=timezone.now(),
    )
    miner.status = MinerStatus.QUARANTINED.value
    miner.save(update_fields=["status"])
    pushed: list[str] = []
    monkeypatch.setattr(metrics, "push", lambda ms, **_k: pushed.append(ms.render()) or True)
    with override_settings(VALI_SYNTHETIC_PUSHGATEWAY_URL="http://pgw"):
        reeval.host_health_survey()
    # The group is still replaced (empty), so the old series go away.
    assert len(pushed) == 1
    assert node not in pushed[0]


# ─── v6 miner-agent release tag → scheduler mirror (observability) ───────


def _v6(fake: FakeHeartbeatVerifier, tag: str = "v2026.10.08") -> None:
    fake.schema_version = 6
    fake.declared_capacity = verifier.DeclaredCapacity(44, 120_000, 99, 4)
    fake.declared_disk = verifier.DeclaredDisk(3000, 3500, 3200, 400)
    fake.declared_host_health = verifier.DeclaredHostHealth(
        snp_enabled=True, cpus_offline=0, snp_launches_since_boot=7, df_flush_failures=0
    )
    fake.agent_version = tag


def test_v6_heartbeat_records_the_agent_version(
    fake_heartbeat_verifier: FakeHeartbeatVerifier,
) -> None:
    from apps.scheduler.models import MinerCapacity

    node = "d1" * 32
    _make_bridged_miner(node)
    _v6(fake_heartbeat_verifier)

    assert _post_heartbeat().status_code == 202
    mc = MinerCapacity.objects.get(miner_node_id=node)
    assert mc.agent_version == "v2026.10.08"
    assert mc.agent_version_reported_at is not None
    # The v5 half of a v6 body still lands.
    assert _host_health(mc) == (True, 0, 7, 0)
    assert mc.reported_data_disk_total_gb == 3500


@pytest.mark.parametrize("schema_version", [1, 4, 5])
def test_pre_v6_heartbeat_leaves_the_agent_version_untouched(
    fake_heartbeat_verifier: FakeHeartbeatVerifier, schema_version: int
) -> None:
    from datetime import timedelta

    from django.utils import timezone

    from apps.scheduler.models import MinerCapacity

    node = "d2" * 32
    _make_bridged_miner(node)
    stamped = timezone.now() - timedelta(minutes=3)
    MinerCapacity.objects.filter(miner_node_id=node).update(
        agent_version="dev", agent_version_reported_at=stamped
    )
    fake_heartbeat_verifier.schema_version = schema_version
    if schema_version == 5:
        fake_heartbeat_verifier.declared_host_health = verifier.DeclaredHostHealth(
            snp_enabled=True, cpus_offline=0, snp_launches_since_boot=1, df_flush_failures=0
        )
    assert _post_heartbeat().status_code == 202
    mc = MinerCapacity.objects.get(miner_node_id=node)
    assert mc.agent_version == "dev"
    assert mc.agent_version_reported_at == stamped


def test_the_reeval_survey_pushes_the_agent_version_info(
    fake_heartbeat_verifier: FakeHeartbeatVerifier, monkeypatch: pytest.MonkeyPatch
) -> None:
    from django.test import override_settings

    from apps.scheduler.management.commands import vali_scheduler_reeval as reeval
    from apps.synthetic import metrics

    node = "d3" * 32
    _make_bridged_miner(node)
    _v6(fake_heartbeat_verifier)
    assert _post_heartbeat().status_code == 202

    pushed: list[str] = []
    monkeypatch.setattr(metrics, "push", lambda ms, **_k: pushed.append(ms.render()) or True)
    with override_settings(VALI_SYNTHETIC_PUSHGATEWAY_URL="http://pgw"):
        reeval.host_health_survey()
    assert len(pushed) == 1
    labels = f'{{miner_id="{MINER_ID}",node_id="{node}",version="v2026.10.08"}}'
    assert f"hippius_miner_agent_version_info{labels} 1" in pushed[0]
    # The host-health series are still there.
    assert f'hippius_miner_host_health_reporting{{miner_id="{MINER_ID}",node_id="{node}"}} 1' in (
        pushed[0]
    )


def test_the_reeval_survey_has_no_version_info_without_a_v6_report(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from django.test import override_settings

    from apps.scheduler.management.commands import vali_scheduler_reeval as reeval
    from apps.synthetic import metrics

    node = "d4" * 32
    _make_bridged_miner(node)
    pushed: list[str] = []
    monkeypatch.setattr(metrics, "push", lambda ms, **_k: pushed.append(ms.render()) or True)
    with override_settings(VALI_SYNTHETIC_PUSHGATEWAY_URL="http://pgw"):
        reeval.host_health_survey()
    assert len(pushed) == 1
    assert "hippius_miner_agent_version_info" not in pushed[0]
    labels = f'{{miner_id="{MINER_ID}",node_id="{node}"}}'
    assert f"hippius_miner_host_health_reporting{labels} 0" in pushed[0]


def test_the_reeval_survey_drops_the_version_info_after_a_downgrade_to_v5(
    fake_heartbeat_verifier: FakeHeartbeatVerifier, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A miner that stops sending v6 must not keep advertising its old tag."""
    from django.test import override_settings

    from apps.scheduler.management.commands import vali_scheduler_reeval as reeval
    from apps.scheduler.models import MinerCapacity
    from apps.synthetic import metrics

    node = "d5" * 32
    _make_bridged_miner(node)
    _v6(fake_heartbeat_verifier)
    assert _post_heartbeat().status_code == 202
    fake_heartbeat_verifier.schema_version = 5
    fake_heartbeat_verifier.agent_version = None
    fake_heartbeat_verifier.sequence += 1
    assert _post_heartbeat().status_code == 202
    mc = MinerCapacity.objects.get(miner_node_id=node)
    assert mc.agent_version == "v2026.10.08"  # kept, for the operator
    assert mc.host_health_reported_at > mc.agent_version_reported_at

    pushed: list[str] = []
    monkeypatch.setattr(metrics, "push", lambda ms, **_k: pushed.append(ms.render()) or True)
    with override_settings(VALI_SYNTHETIC_PUSHGATEWAY_URL="http://pgw"):
        reeval.host_health_survey()
    assert len(pushed) == 1
    assert "hippius_miner_agent_version_info" not in pushed[0]
