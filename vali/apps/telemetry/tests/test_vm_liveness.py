"""Tenant-CVM live-attestation ingest + the uptime COVERAGE meter.

`POST /v1/telemetry/vm-liveness` records a KBS-L0-signed
`SignedLiveAttestation` — the proof a tenant CVM was genuinely ALIVE
that a killed VM cannot produce. `vm_liveness.covered_seconds` turns the
recorded samples into the creditable subset of a receipt window.

The Rust `verify-live-attestation` shell-out is replaced by an in-memory
fake here so the gate logic runs without the built binary
(`test_verifier.py`-style real-wrapper coverage lives in the Rust
crate's own unit tests, which drive the signature semantics directly).
"""

from __future__ import annotations

import contextlib
import logging

import pytest
from django.urls import reverse
from rest_framework.test import APIClient

from apps.scheduler.models import VmBillingBinding
from apps.telemetry import verifier, vm_liveness
from apps.telemetry.models import VmLiveAttestation

pytestmark = pytest.mark.django_db

URL = reverse("telemetry_vm_liveness")

NODE_ID = "aa" * 32
MEASUREMENT = "44" * 48
KBS_L0 = "ab" * 32
VM = "vm-live-1"

# The pinned "now" every test runs against.
NOW = 1_800_000_000


@pytest.fixture(autouse=True)
def _pin_now(monkeypatch):
    monkeypatch.setattr(vm_liveness, "_now_unix", lambda: NOW)


@pytest.fixture(autouse=True)
def _wire_kbs_key(settings):
    settings.VALI_KBS_L0_VERIFYING_KEY = KBS_L0


class FakeVerifier:
    """In-memory stand-in for `verifier.verify_live_attestation`."""

    def __init__(self) -> None:
        self.outcome = "ok"  # "ok" | "failed" | "unavailable"
        self.vm_id = VM
        self.node_id_hex = NODE_ID
        self.attestation_seq = 1
        self.verified_at_unix = NOW
        self.expiry_unix = NOW + 900
        self.body_digest_hex = "cc" * 32
        self.measurement_hex = MEASUREMENT
        # The KBS hash-chain back-pointer. All-zero == this attestation is
        # the genesis of a chain (a fresh VM, or a KBS that just restarted).
        self.prev_attestation_hash_hex = "00" * 32
        # `(binding_source, chip_id_hex, report_id_hex)` ⇒ a schema v2 body.
        self.guest: tuple[str, str, str] | None = None
        # `(vcpus_online, mem_firmware_kib, mem_total_kib, mem_unaccepted_kib)`
        # ⇒ a schema v3 body.
        self.resources: tuple[int, int, int, int] | None = None
        self.keys_seen: list[bytes | None] = []

    def __call__(self, *, envelope: bytes, verifying_key: bytes | None):
        self.keys_seen.append(verifying_key)
        if self.outcome == "failed":
            raise verifier.VerifierFailed(
                message="bad", category="signature_invalid"
            )
        if self.outcome == "unavailable":
            raise verifier.VerifierUnavailable("no binary")
        source, chip, report = self.guest or (None, None, None)
        vcpus, mem_fw, mem_total, mem_unaccepted = self.resources or (None, None, None, None)
        if self.resources is not None:
            schema_version = 3
        else:
            schema_version = 1 if self.guest is None else 2
        return verifier.LiveAttestationFields(
            schema_version=schema_version,
            vm_id=self.vm_id,
            node_id_hex=self.node_id_hex,
            attestation_seq=self.attestation_seq,
            epoch=7,
            observed_at_unix=self.verified_at_unix - 1,
            verified_at_unix=self.verified_at_unix,
            expiry_unix=self.expiry_unix,
            measurement_hex=self.measurement_hex,
            snp_report_digest_hex="11" * 32,
            vcek_chain_digest_hex="22" * 32,
            prev_attestation_hash_hex=self.prev_attestation_hash_hex,
            signer_pubkey_hex=KBS_L0,
            chain_genesis_hex="33" * 32,
            pallet_instance_hex="dd" * 32,
            body_digest_hex=self.body_digest_hex,
            binding_source=source,
            chip_id_hex=chip,
            report_id_hex=report,
            vcpus_online=vcpus,
            mem_firmware_kib=mem_fw,
            mem_total_kib=mem_total,
            mem_unaccepted_kib=mem_unaccepted,
        )


@pytest.fixture
def fake(monkeypatch) -> FakeVerifier:
    f = FakeVerifier()
    monkeypatch.setattr(vm_liveness.verifier, "verify_live_attestation", f)
    return f


def _pin_launch_measurement(vm_id: str, measurement: str) -> None:
    """What a launch's §22 auto-pin writes — the ingest refuses a VM with
    no pinned measurement."""
    from apps.orchestration.models import MeasurementLedger

    MeasurementLedger.objects.create(
        vm_id=vm_id, launch_digest_hex=measurement, allowlist_epoch=1
    )


def _binding(*, vm_id: str = VM, node_id_hex: str = NODE_ID) -> VmBillingBinding:
    _pin_launch_measurement(vm_id, MEASUREMENT)
    return VmBillingBinding.objects.create(
        vm_id=vm_id,
        node_id_hex=node_id_hex,
        resource_class="small",
        lease_id="lease-1",
    )


# ─── ingest gates ────────────────────────────────────────────────────


GENOA_CHIP = "5e" * 64
REPORT_ID = "7a" * 32


def _miner(platform_id: str, *, node_id_hex: str = NODE_ID) -> None:
    from apps.miners.models import MinerIdentity

    MinerIdentity.objects.create(
        miner_id="miner-live",
        pubkey_hex="ab" * 32,
        platform_id=platform_id,
        chain_node_id=node_id_hex,
    )


def test_a_v2_body_on_its_registered_chip_records_the_guest(fake) -> None:
    _binding()
    _miner(GENOA_CHIP)
    fake.guest = ("release", GENOA_CHIP, REPORT_ID)
    row, created = vm_liveness.ingest_live_attestation(envelope=b"\x01")
    assert created is True
    assert (row.binding_source, row.chip_id, row.report_id) == ("release", GENOA_CHIP, REPORT_ID)


def test_a_turin_platform_id_matches_as_a_prefix(fake) -> None:
    # Turin registers the 8-byte id; the report's CHIP_ID is zero-padded
    # to 64 — the same prefix rule the KBS release applies.
    _binding()
    _miner("c0ffee0012345678")
    fake.guest = ("release", "c0ffee0012345678" + "00" * 56, REPORT_ID)
    _, created = vm_liveness.ingest_live_attestation(envelope=b"\x01")
    assert created is True


@pytest.mark.parametrize(
    "platform_id",
    [
        "6f" * 64,  # another machine
        None,  # no MinerIdentity for the node at all
        "onchain:" + NODE_ID,  # auto-provision placeholder, no real chip
    ],
)
def test_a_v2_body_off_the_nodes_chip_is_refused(fake, platform_id) -> None:
    _binding()
    if platform_id is not None:
        _miner(platform_id)
    fake.guest = ("release", GENOA_CHIP, REPORT_ID)
    with pytest.raises(vm_liveness.LiveAttestationRefused) as exc:
        vm_liveness.ingest_live_attestation(envelope=b"\x01")
    assert exc.value.category == "chip-mismatch"
    assert VmLiveAttestation.objects.count() == 0


def _pin(measurement: str, *, vm_id: str = VM) -> None:
    from apps.orchestration.models import MeasurementLedger

    MeasurementLedger.objects.create(
        vm_id=vm_id, launch_digest_hex=measurement, allowlist_epoch=1
    )


@pytest.mark.parametrize("schema", ["v1", "v2"])
def test_another_vms_guest_attesting_for_this_vm_is_refused(fake, schema) -> None:
    # The original hole: root in ONE guest mints for ANY vm_id. Each VM's
    # measured cmdline is its own, so the other guest's measurement is not
    # one pinned for this vm_id — refused whatever the KBS binding state.
    _binding()
    _miner(GENOA_CHIP)
    # This VM's own launch measurement is "55…"; the guest attesting
    # carries another VM's.
    from apps.orchestration.models import MeasurementLedger

    MeasurementLedger.objects.filter(vm_id=VM).update(launch_digest_hex="55" * 48)
    if schema == "v2":
        fake.guest = ("first-use", GENOA_CHIP, REPORT_ID)
    with pytest.raises(vm_liveness.LiveAttestationRefused) as exc:
        vm_liveness.ingest_live_attestation(envelope=b"\x01")
    assert exc.value.category == "measurement-mismatch"
    assert VmLiveAttestation.objects.count() == 0


def test_a_pinned_measurement_is_accepted(fake) -> None:
    from apps.orchestration.models import MeasurementLedger

    _binding()
    MeasurementLedger.objects.filter(vm_id=VM).update(launch_digest_hex=MEASUREMENT.upper())
    _pin("55" * 48)  # a later relaunch of the same VM
    _, created = vm_liveness.ingest_live_attestation(envelope=b"\x01")
    assert created is True


def test_a_vm_with_no_pinned_measurement_is_refused(fake) -> None:
    from apps.orchestration.models import MeasurementLedger

    _binding()
    MeasurementLedger.objects.all().delete()
    with pytest.raises(vm_liveness.LiveAttestationRefused) as exc:
        vm_liveness.ingest_live_attestation(envelope=b"\x01")
    assert exc.value.category == "measurement-unpinned"
    assert VmLiveAttestation.objects.count() == 0


def test_a_migrated_vm_is_held_to_the_destination_chip(fake) -> None:
    # After a §25 cutover the body still declares the LAUNCH node (measured
    # cmdline), but the guest runs on the destination's chip.
    from apps.miners.models import MinerIdentity
    from apps.scheduler.models import VmBillingAssignment

    _binding()
    _miner(GENOA_CHIP)  # the launch node
    dest = "bb" * 32
    MinerIdentity.objects.create(
        miner_id="miner-dest", pubkey_hex="cd" * 32, platform_id="6f" * 64, chain_node_id=dest
    )
    VmBillingAssignment.objects.create(
        vm_id=VM, node_id_hex=dest, effective_from_unix=NOW - 60, reason="migration"
    )
    fake.guest = ("release", "6f" * 64, REPORT_ID)
    _, created = vm_liveness.ingest_live_attestation(envelope=b"\x01")
    assert created is True
    # …and the SOURCE chip is no longer where this VM may attest from.
    fake.guest = ("release", GENOA_CHIP, REPORT_ID)
    fake.body_digest_hex = "cd" * 32
    fake.attestation_seq = 2
    with pytest.raises(vm_liveness.LiveAttestationRefused) as exc:
        vm_liveness.ingest_live_attestation(envelope=b"\x01")
    assert exc.value.category == "chip-mismatch"


def test_a_v1_body_needs_no_registered_chip(fake) -> None:
    # Legacy bodies carry no chip: the gate is the v2 contract only.
    _binding()
    row, created = vm_liveness.ingest_live_attestation(envelope=b"\x01")
    assert created is True
    assert (row.binding_source, row.chip_id, row.report_id) == ("", "", "")


def test_records_a_verified_attestation(fake) -> None:
    _binding()
    row, created = vm_liveness.ingest_live_attestation(envelope=b"\x01\x02")
    assert created is True
    assert row.vm_id == VM
    assert row.attestation_seq == 1
    assert row.verified_at_unix == NOW
    # The pinned KBS L0 key is what the verifier was handed — never a
    # key taken from the (hostile) envelope.
    assert fake.keys_seen == [bytes.fromhex(KBS_L0)]


def test_refuses_to_record_anything_when_the_kbs_key_is_unwired(
    fake, settings
) -> None:
    # No KBS L0 key ⇒ nothing can be verified ⇒ nothing is recorded. An
    # unverified attestation is worth nothing (a miner could mint one).
    settings.VALI_KBS_L0_VERIFYING_KEY = ""
    _binding()
    with pytest.raises(vm_liveness.LiveAttestationRefused) as exc:
        vm_liveness.ingest_live_attestation(envelope=b"\x01")
    assert exc.value.category == "kbs-key-unwired"
    assert exc.value.http_status == 503
    assert VmLiveAttestation.objects.count() == 0
    # The verifier was never even called.
    assert fake.keys_seen == []


def test_refuses_a_bad_signature(fake) -> None:
    _binding()
    fake.outcome = "failed"
    with pytest.raises(vm_liveness.LiveAttestationRefused) as exc:
        vm_liveness.ingest_live_attestation(envelope=b"\x01")
    assert exc.value.category == "verify-failed"
    assert VmLiveAttestation.objects.count() == 0


def test_verifier_outage_is_a_503_not_a_silent_pass(fake) -> None:
    _binding()
    fake.outcome = "unavailable"
    with pytest.raises(vm_liveness.LiveAttestationRefused) as exc:
        vm_liveness.ingest_live_attestation(envelope=b"\x01")
    assert exc.value.http_status == 503
    assert VmLiveAttestation.objects.count() == 0


def test_refuses_an_expired_attestation(fake) -> None:
    _binding()
    fake.expiry_unix = NOW - 1
    with pytest.raises(vm_liveness.LiveAttestationRefused) as exc:
        vm_liveness.ingest_live_attestation(envelope=b"\x01")
    assert exc.value.category == "expired"
    assert VmLiveAttestation.objects.count() == 0


def test_refuses_a_future_dated_attestation(fake, settings) -> None:
    settings.VALI_UPTIME_LIVENESS_SKEW_S = 300
    _binding()
    fake.verified_at_unix = NOW + 301
    fake.expiry_unix = NOW + 10_000
    with pytest.raises(vm_liveness.LiveAttestationRefused) as exc:
        vm_liveness.ingest_live_attestation(envelope=b"\x01")
    assert exc.value.category == "future-dated"


def test_refuses_a_stale_hoarded_attestation(fake, settings) -> None:
    settings.VALI_UPTIME_LIVENESS_SKEW_S = 300
    _binding()
    fake.verified_at_unix = NOW - 301
    with pytest.raises(vm_liveness.LiveAttestationRefused) as exc:
        vm_liveness.ingest_live_attestation(envelope=b"\x01")
    assert exc.value.category == "stale"


def test_refuses_an_attestation_for_an_unbound_vm(fake) -> None:
    # No launch binding ⇒ vali could not credit this VM anyway.
    with pytest.raises(vm_liveness.LiveAttestationRefused) as exc:
        vm_liveness.ingest_live_attestation(envelope=b"\x01")
    assert exc.value.category == "no-binding"


def test_refuses_an_attestation_naming_another_node(fake) -> None:
    _binding(node_id_hex="bb" * 32)
    with pytest.raises(vm_liveness.LiveAttestationRefused) as exc:
        vm_liveness.ingest_live_attestation(envelope=b"\x01")
    assert exc.value.category == "node-mismatch"


def test_a_replayed_attestation_extends_no_coverage(fake) -> None:
    """The load-bearing anti-replay property: re-POSTing a captured,
    perfectly-valid live attestation must not buy a second window of
    uptime. Same body ⇒ same `(vm_id, seq)` and same `body_digest` ⇒
    idempotent."""
    _binding()
    row, created = vm_liveness.ingest_live_attestation(envelope=b"\x01")
    assert created is True
    before = vm_liveness.covered_seconds(
        vm_id=VM, start_unix=NOW - 900, end_unix=NOW
    )
    for _ in range(5):
        again, created_again = vm_liveness.ingest_live_attestation(envelope=b"\x01")
        assert created_again is False
        assert again.pk == row.pk
    assert VmLiveAttestation.objects.count() == 1
    assert (
        vm_liveness.covered_seconds(vm_id=VM, start_unix=NOW - 900, end_unix=NOW)
        == before
    )


def test_a_replay_under_a_new_seq_but_same_body_is_still_a_replay(fake) -> None:
    # Second dedupe axis: the exact signed body. Even if the seq index
    # were relaxed, byte-identical bytes record once.
    _binding()
    vm_liveness.ingest_live_attestation(envelope=b"\x01")
    fake.attestation_seq = 2  # different seq, SAME body_digest
    _, created = vm_liveness.ingest_live_attestation(envelope=b"\x01")
    assert created is False
    assert VmLiveAttestation.objects.count() == 1


# ─── the KBS chain lineage (the 2026-08-13 zero-uptime incident) ─────
#
# The KBS mints `attestation_seq` from state held in its CVM's emptyDir,
# so a KBS restart reseeds the per-VM chain to genesis. Deduping on
# `(vm_id, attestation_seq)` therefore mistook every post-restart
# attestation for a replay of the OLD chain's same-numbered one — a live
# tenant earning nothing, silently, for as long as the fresh sequence took
# to climb past the old maximum.


@contextlib.contextmanager
def _now_at(t: int):
    """Run the block with vali's ingest clock pinned at `t`."""
    original = vm_liveness._now_unix
    vm_liveness._now_unix = lambda: t
    try:
        yield
    finally:
        vm_liveness._now_unix = original


@contextlib.contextmanager
def _liveness_logs():
    """Capture `apps.telemetry.vm_liveness` records.

    The project's LOGGING config sets `propagate = False` on the app
    loggers, so pytest's `caplog` (which handles at the ROOT) sees
    nothing — attach directly to the logger instead. Getting this wrong
    is how a "the failure is now loud" assertion passes vacuously.
    """
    records: list[logging.LogRecord] = []

    class _Sink(logging.Handler):
        def emit(self, record: logging.LogRecord) -> None:
            records.append(record)

    logger = logging.getLogger("apps.telemetry.vm_liveness")
    handler = _Sink(level=logging.WARNING)
    logger.addHandler(handler)
    try:
        yield records
    finally:
        logger.removeHandler(handler)


def _chain(vm_id: str, upto: int, *, chain_epoch: int = 0, tag: str = "old") -> str:
    """Seed a KBS chain of `upto` attestations, properly hash-linked.

    Returns the `body_digest` of the last one — the back-pointer the NEXT
    attestation of that chain would carry.
    """
    prev = "00" * 32
    for seq in range(1, upto + 1):
        digest = f"{tag}{seq:04d}".encode().hex().ljust(64, "0")[:64]
        VmLiveAttestation.objects.create(
            vm_id=vm_id,
            node_id_hex=NODE_ID,
            attestation_seq=seq,
            epoch=7,
            observed_at_unix=NOW - 1,
            verified_at_unix=NOW,
            expiry_unix=NOW + 900,
            measurement=MEASUREMENT,
            snp_report_digest="11" * 32,
            body_digest=digest,
            prev_attestation_hash=prev,
            chain_epoch=chain_epoch,
        )
        prev = digest
    return prev


def test_a_post_restart_attestation_at_a_low_seq_is_recorded_not_ignored(
    fake,
) -> None:
    """THE live scenario. Rows exist at seq 1..43 from before a KBS
    restart; the guest is now at seq 11 of a FRESH chain with a genuinely
    different body. It must be RECORDED — it is new proof of life, not a
    replay — and it must extend coverage."""
    _binding()
    _chain(VM, 43)
    assert VmLiveAttestation.objects.count() == 43

    # The post-restart attestation: seq 11 (well below the recorded max),
    # a body vali has never seen, chained off a seq-10 body vali also
    # never saw (it was dropped by the very bug under test).
    fake.attestation_seq = 11
    fake.body_digest_hex = b"new0011".hex().ljust(64, "0")[:64]
    fake.prev_attestation_hash_hex = b"new0010".hex().ljust(64, "0")[:64]

    with _liveness_logs() as records:
        row, created = vm_liveness.ingest_live_attestation(envelope=b"\x01")

    assert created is True, "a post-KBS-restart attestation was dropped as a replay"
    assert row.attestation_seq == 11
    assert row.chain_epoch == 1, "it must open a NEW lineage, not join the old one"
    assert VmLiveAttestation.objects.count() == 44
    # And it is not silent.
    assert any(
        "chain RESET" in r.getMessage() for r in records
    ), "a lineage reset must be logged at WARNING"


def test_the_first_attestation_after_a_restart_is_recorded_too(fake) -> None:
    """The genesis case: seq back to 1 with the all-zero back-pointer.
    A key that names no parent must not silently collide with the VM's
    original seq 1 — that is one whole keepalive interval of lost uptime
    on EVERY KBS restart."""
    _binding()
    _chain(VM, 43)
    fake.attestation_seq = 1
    fake.body_digest_hex = b"restarted-genesis".hex().ljust(64, "0")[:64]
    fake.prev_attestation_hash_hex = "00" * 32  # genesis of the new chain
    row, created = vm_liveness.ingest_live_attestation(envelope=b"\x01")
    assert created is True
    assert row.chain_epoch == 1


def test_a_continuing_attestation_stays_in_its_lineage(fake) -> None:
    """A normal in-chain attestation links onto the row it names and does
    NOT churn the lineage — otherwise `chain_epoch` would be noise and the
    seq axis would protect nothing."""
    _binding()
    last = _chain(VM, 5)
    fake.attestation_seq = 6
    fake.body_digest_hex = b"old0006".hex().ljust(64, "0")[:64]
    fake.prev_attestation_hash_hex = last
    row, created = vm_liveness.ingest_live_attestation(envelope=b"\x01")
    assert created is True
    assert row.chain_epoch == 0


def test_a_resubmitted_post_restart_attestation_is_still_ignored(fake) -> None:
    """⛔ THE anti-overshoot property. Opening a new lineage must not make
    duplicates acceptable: the SAME signed attestation — byte-identical
    body, same seq — is still refused, before AND after a chain reset.

    This is the property the fix may never trade away: a miner that
    captured one valid attestation must not be able to re-post it to bill
    for a VM it killed."""
    _binding()
    _chain(VM, 43)
    fake.attestation_seq = 11
    fake.body_digest_hex = b"new0011".hex().ljust(64, "0")[:64]
    fake.prev_attestation_hash_hex = b"new0010".hex().ljust(64, "0")[:64]
    first, created = vm_liveness.ingest_live_attestation(envelope=b"\x01")
    assert created is True
    before = vm_liveness.covered_seconds(vm_id=VM, start_unix=NOW - 900, end_unix=NOW)

    # Re-POST the very same signed bytes, ten times, exactly as a hostile
    # relay would. Every one must be a no-op.
    for _ in range(10):
        again, created_again = vm_liveness.ingest_live_attestation(envelope=b"\x01")
        assert created_again is False, "a byte-identical replay was RECORDED"
        assert again.pk == first.pk
    assert VmLiveAttestation.objects.count() == 44
    assert (
        vm_liveness.covered_seconds(vm_id=VM, start_unix=NOW - 900, end_unix=NOW)
        == before
    ), "a replay bought coverage"


def test_a_captured_old_attestation_replayed_later_is_still_refused(
    fake, settings
) -> None:
    """A captured attestation re-sent LATER — the hoarding attack — never
    reaches the dedupe layer at all: it is stale beyond the skew window.
    The chain-lineage fix does not touch that gate, and this pins it.

    Belt and braces: even if its `verified_at_unix` were somehow fresh,
    the body_digest constraint above refuses the bytes."""
    settings.VALI_UPTIME_LIVENESS_SKEW_S = 300
    _binding()
    fake.body_digest_hex = b"captured".hex().ljust(64, "0")[:64]
    row, created = vm_liveness.ingest_live_attestation(envelope=b"\x01")
    assert created is True

    # An hour later the miner re-sends the captured bytes. The signed
    # `verified_at_unix` / `expiry_unix` are fixed in the body, so both
    # time gates now refuse it before any DB lookup. A real KBS sets a
    # ~10 min expiry, so `expired` is what fires in practice…
    with _now_at(NOW + 3600):
        with pytest.raises(vm_liveness.LiveAttestationRefused) as exc:
            vm_liveness.ingest_live_attestation(envelope=b"\x01")
    assert exc.value.category == "expired"

    # …and the skew gate is the independent backstop: even a body whose
    # expiry had been minted absurdly far out is still refused, because
    # `verified_at_unix` is an hour stale.
    fake.expiry_unix = NOW + 10_000_000
    fake.body_digest_hex = b"captured-long-expiry".hex().ljust(64, "0")[:64]
    vm_liveness.ingest_live_attestation(envelope=b"\x02")
    with _now_at(NOW + 3600):
        with pytest.raises(vm_liveness.LiveAttestationRefused) as exc:
            vm_liveness.ingest_live_attestation(envelope=b"\x02")
    assert exc.value.category == "stale"

    assert VmLiveAttestation.objects.count() == 2
    assert VmLiveAttestation.objects.filter(pk=row.pk).exists()


def test_a_fork_is_recorded_in_its_own_lineage_and_logged_loudly(fake) -> None:
    """Two DIFFERENT bodies claiming the same position in one chain. The
    KBS should never mint that (its advance is a CAS), but the answer is
    still not to drop a KBS-signed proof of life — record it in a fresh
    lineage and say so."""
    _binding()
    last = _chain(VM, 5)
    fake.attestation_seq = 6
    fake.body_digest_hex = b"fork-a".hex().ljust(64, "0")[:64]
    fake.prev_attestation_hash_hex = last
    vm_liveness.ingest_live_attestation(envelope=b"\x01")

    fake.body_digest_hex = b"fork-b".hex().ljust(64, "0")[:64]
    with _liveness_logs() as records:
        row, created = vm_liveness.ingest_live_attestation(envelope=b"\x02")
    assert created is True
    assert row.chain_epoch == 1
    assert any("chain FORK" in r.getMessage() for r in records)


# ─── the HTTP surface ────────────────────────────────────────────────


def test_endpoint_records_and_reports(fake) -> None:
    _binding()
    resp = APIClient().post(URL, data=b"\x01\x02", content_type="application/cbor")
    assert resp.status_code == 200
    assert resp.json() == {
        "vm_id": VM,
        "attestation_seq": 1,
        "verified_at_unix": NOW,
        "recorded": True,
    }


def test_endpoint_rejects_an_empty_body(fake) -> None:
    resp = APIClient().post(URL, data=b"", content_type="application/cbor")
    assert resp.status_code == 400


def test_endpoint_rejects_an_oversize_body(fake) -> None:
    resp = APIClient().post(
        URL, data=b"\x00" * 4097, content_type="application/cbor"
    )
    assert resp.status_code == 413


def test_endpoint_surfaces_the_unwired_key_as_503(fake, settings) -> None:
    settings.VALI_KBS_L0_VERIFYING_KEY = ""
    _binding()
    resp = APIClient().post(URL, data=b"\x01", content_type="application/cbor")
    assert resp.status_code == 503


# ─── the coverage meter ──────────────────────────────────────────────


def _sample(t: int, *, vm_id: str = VM, seq: int | None = None) -> None:
    seq = seq if seq is not None else t
    VmLiveAttestation.objects.create(
        vm_id=vm_id,
        node_id_hex=NODE_ID,
        attestation_seq=seq,
        epoch=7,
        observed_at_unix=t - 1,
        verified_at_unix=t,
        expiry_unix=t + 900,
        measurement=MEASUREMENT,
        snp_report_digest="11" * 32,
        body_digest=f"{vm_id}-{seq}".encode().hex().ljust(64, "0")[:64],
    )


def test_no_samples_means_zero_coverage() -> None:
    assert vm_liveness.covered_seconds(vm_id=VM, start_unix=1000, end_unix=1060) == 0


def test_a_sample_covers_backwards_by_the_span(settings) -> None:
    settings.VALI_UPTIME_LIVENESS_COVERAGE_S = 900
    _sample(1060)
    assert vm_liveness.covered_seconds(vm_id=VM, start_unix=1000, end_unix=1060) == 60


def test_a_sample_never_covers_forwards(settings) -> None:
    """THE security property. A last attestation before the kill must not
    vouch for anything after it — otherwise holding the telemetry key
    plus one stale attestation would keep paying forever."""
    settings.VALI_UPTIME_LIVENESS_COVERAGE_S = 900
    _sample(1000)
    assert vm_liveness.covered_seconds(vm_id=VM, start_unix=1000, end_unix=1060) == 0


def test_span_bounds_the_look_back(settings) -> None:
    settings.VALI_UPTIME_LIVENESS_COVERAGE_S = 30
    _sample(1060)
    # Only [1030,1060] of the requested [1000,1060] is vouched for.
    assert vm_liveness.covered_seconds(vm_id=VM, start_unix=1000, end_unix=1060) == 30


def test_floor_clips_the_look_back_to_the_vms_existence(settings) -> None:
    settings.VALI_UPTIME_LIVENESS_COVERAGE_S = 900
    _sample(1060)
    # The VM only existed from 1040 ⇒ at most 20 s can be credited.
    assert (
        vm_liveness.covered_seconds(
            vm_id=VM, start_unix=1000, end_unix=1060, floor_unix=1040
        )
        == 20
    )


def test_overlapping_samples_are_merged_not_summed(settings) -> None:
    settings.VALI_UPTIME_LIVENESS_COVERAGE_S = 900
    for t in (1010, 1020, 1030, 1040, 1050, 1060):
        _sample(t)
    # Six samples all vouching for the same 60 s must credit 60, not 360.
    assert vm_liveness.covered_seconds(vm_id=VM, start_unix=1000, end_unix=1060) == 60


def test_a_gap_between_samples_is_not_covered(settings) -> None:
    settings.VALI_UPTIME_LIVENESS_COVERAGE_S = 10
    _sample(1010)  # covers [1000,1010]
    _sample(1060)  # covers [1050,1060]
    assert vm_liveness.covered_seconds(vm_id=VM, start_unix=1000, end_unix=1060) == 20


def test_a_sample_after_the_window_still_vouches_backwards(settings) -> None:
    # The normal case: the attestation for a window lands just after the
    # window closed.
    settings.VALI_UPTIME_LIVENESS_COVERAGE_S = 900
    _sample(1100)
    assert vm_liveness.covered_seconds(vm_id=VM, start_unix=1000, end_unix=1060) == 60


def test_another_vms_samples_do_not_cover_this_one(settings) -> None:
    settings.VALI_UPTIME_LIVENESS_COVERAGE_S = 900
    _sample(1060, vm_id="vm-other")
    assert vm_liveness.covered_seconds(vm_id=VM, start_unix=1000, end_unix=1060) == 0


def test_inverted_window_is_zero(settings) -> None:
    # With a sample that WOULD cover [1000,1060] — an inverted window
    # must still yield nothing, never a negative or wrapped span.
    settings.VALI_UPTIME_LIVENESS_COVERAGE_S = 900
    _sample(1060)
    assert vm_liveness.covered_seconds(vm_id=VM, start_unix=1060, end_unix=1000) == 0
    assert vm_liveness.covered_intervals(vm_id=VM, start_unix=1060, end_unix=1000) == []


def _released_row(report: str, at: int, source: str = "release") -> None:
    VmLiveAttestation.objects.create(
        vm_id=VM,
        node_id_hex=NODE_ID,
        attestation_seq=at,
        epoch=1,
        observed_at_unix=at,
        verified_at_unix=at,
        expiry_unix=at + 900,
        measurement=MEASUREMENT,
        snp_report_digest="11" * 32,
        body_digest=f"{at:064x}",
        binding_source=source,
        chip_id=GENOA_CHIP,
        report_id=report,
    )


def test_a_first_use_duplicate_of_a_live_released_guest_is_refused(fake) -> None:
    _binding()
    _miner(GENOA_CHIP)
    _released_row("7a" * 32, NOW - 120)  # the released guest, still attesting
    fake.guest = ("first-use", GENOA_CHIP, "7b" * 32)  # a second instance
    with pytest.raises(vm_liveness.LiveAttestationRefused) as exc:
        vm_liveness.ingest_live_attestation(envelope=b"\x01")
    assert exc.value.category == "guest-conflict"


@pytest.mark.parametrize(
    ("report", "released_at"),
    [
        ("7a" * 32, NOW - 120),  # the released guest itself, first-use after a KBS restart
        ("7b" * 32, NOW - 7200),  # a new guest while the released one went silent (reboot)
    ],
)
def test_a_first_use_that_is_not_a_live_duplicate_is_accepted(fake, report, released_at) -> None:
    _binding()
    _miner(GENOA_CHIP)
    _released_row("7a" * 32, released_at)
    fake.guest = ("first-use", GENOA_CHIP, report)
    _, created = vm_liveness.ingest_live_attestation(envelope=b"\x01")
    assert created is True


def test_a_duplicate_after_a_pod_replacement_is_refused_while_the_released_guest_lives(
    fake,
) -> None:
    """After a KBS pod replacement the honest released guest has no record
    and attests `first-use` too; its last RELEASE sample ages past the
    coverage span while it is fully alive. A duplicate instance on the same
    chip must still be refused — liveness is judged from ANY-source samples
    of the released guest."""
    _binding()
    _miner(GENOA_CHIP)
    _released_row("7a" * 32, NOW - 3600)  # released an hour ago, before the pod replacement
    _released_row("7a" * 32, NOW - 120, source="first-use")  # still alive, unbound
    fake.guest = ("first-use", GENOA_CHIP, "7b" * 32)  # the duplicate
    with pytest.raises(vm_liveness.LiveAttestationRefused) as exc:
        vm_liveness.ingest_live_attestation(envelope=b"\x01")
    assert exc.value.category == "guest-conflict"
