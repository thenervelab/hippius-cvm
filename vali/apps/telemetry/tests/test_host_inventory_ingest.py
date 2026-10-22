"""Edge-relayed §18.10 host-inventory ingest gates.

`POST /v1/telemetry/host-inventory`: raw `application/cbor`, the miner
resolved from the Edge-stamped `X-Hippius-Peer-Id`, the signature the
credential. The gate logic runs against `FakeHostInventoryVerifier`; the
last tests drive the REAL `verify-host-inventory` with the frozen KAT
vectors (`test_vectors/host_inventory/`), end to end into the merge.
"""

from __future__ import annotations

import time
from pathlib import Path
from typing import Any

import pytest
from django.conf import settings
from django.urls import reverse
from rest_framework.test import APIClient

from apps.disktier.models import HostInventoryChange, HostInventorySection, HostInventoryState
from apps.miners.models import MinerIdentity
from apps.telemetry import verifier
from apps.telemetry.models import SourceType, TelemetrySource

pytestmark = pytest.mark.django_db

URL = reverse("telemetry_host_inventory")
MINER_ID = "miner-kat-1"
PEER_ID = f"hippius-miner:{MINER_ID}"
NODE_ID = "ab" * 32
DIGEST = "0" * 64

_VECTORS = Path(settings.BASE_DIR).parent / "test_vectors" / "host_inventory"
_REAL_VERIFY = verifier.verify_host_inventory
_REAL_BIN = Path(settings.VALI_TICKET_VALIDATOR_BIN)


@pytest.fixture(autouse=True)
def _no_pushgateway(settings: Any) -> None:
    # A report pushes the node's metrics; tests that want it set the URL.
    settings.VALI_SYNTHETIC_PUSHGATEWAY_URL = ""


class FakeHostInventoryVerifier:
    def __init__(self) -> None:
        self.outcome = "ok"
        self.miner_id = MINER_ID
        self.sequence = 1
        self.timestamp_unix: int | None = None
        self.sections: dict[str, Any] = {"cpu": {"status": "ok", "cores": 24}}
        self.calls: list[tuple[bytes, bytes]] = []

    def verify_host_inventory(
        self, *, envelope: bytes, verifying_key: bytes
    ) -> verifier.HostInventoryReport:
        self.calls.append((bytes(envelope), bytes(verifying_key)))
        if self.outcome == "unavailable":
            raise verifier.VerifierUnavailable("injected")
        if self.outcome == "failed":
            raise verifier.VerifierFailed(message="injected", category="body_invalid")
        ts = int(time.time()) if self.timestamp_unix is None else self.timestamp_unix
        body = {
            "miner_id": self.miner_id,
            "timestamp_unix": ts,
            "sequence": self.sequence,
            "report": "change",
            "sections": self.sections,
        }
        return verifier.HostInventoryReport(
            miner_id=self.miner_id,
            timestamp_unix=ts,
            sequence=self.sequence,
            body=body,
            section_digests={name: DIGEST for name in self.sections},
        )


@pytest.fixture(autouse=True)
def on(settings: Any) -> None:
    settings.VALI_HOST_INVENTORY_INGEST = True


@pytest.fixture
def fake(monkeypatch: pytest.MonkeyPatch) -> FakeHostInventoryVerifier:
    f = FakeHostInventoryVerifier()
    monkeypatch.setattr(verifier, "verify_host_inventory", f.verify_host_inventory)
    return f


def _miner(*, node_id: str | None = NODE_ID, pubkey_hex: str = "cd" * 32) -> MinerIdentity:
    miner = MinerIdentity.objects.create(
        miner_id=MINER_ID,
        pubkey_hex=pubkey_hex,
        platform_id=f"amd-chipid-{MINER_ID}",
        chain_node_id=node_id,
    )
    TelemetrySource.objects.create(
        source=SourceType.MINER.value, source_id=MINER_ID, verifying_key=bytes(32)
    )
    return miner


def _post(body: bytes = b"signed-host-inventory", *, peer_id: str | None = PEER_ID) -> Any:
    extra = {"HTTP_X_HIPPIUS_PEER_ID": peer_id} if peer_id is not None else {}
    return APIClient().post(URL, data=body, content_type="application/cbor", **extra)


def test_accepts_and_merges_with_the_registered_key(fake: FakeHostInventoryVerifier) -> None:
    _miner()
    resp = _post()
    assert resp.status_code == 200, resp.content
    assert resp.json() == {"accepted": True, "sequence": 1, "sections": ["cpu"], "changed": []}
    assert fake.calls == [(b"signed-host-inventory", bytes.fromhex("cd" * 32))]
    row = HostInventorySection.objects.get(miner_node_id=NODE_ID, section="cpu")
    assert row.body == {"status": "ok", "cores": 24}
    assert row.status == "ok"


def test_off_by_default_answers_404_before_any_verify(
    settings: Any, fake: FakeHostInventoryVerifier
) -> None:
    settings.VALI_HOST_INVENTORY_INGEST = False
    _miner()
    resp = _post()
    assert resp.status_code == 404
    assert resp.json()["category"] == "disabled"
    assert fake.calls == []


@pytest.mark.parametrize(
    ("setup", "status", "category"),
    [
        ("empty", 400, "wire"),
        ("too-large", 413, "too-large"),
        ("no-peer", 400, "wire"),
        ("unknown-miner", 404, "not-found"),
        ("failed", 403, "body_invalid"),
        ("unavailable", 503, "internal"),
        ("other-miner", 403, "identity"),
        ("skew", 403, "timestamp-skew"),
        ("no-node-id", 409, "no-node-id"),
    ],
)
def test_gates_fail_closed(
    settings: Any, fake: FakeHostInventoryVerifier, setup: str, status: int, category: str
) -> None:
    body = b"signed-host-inventory"
    peer: str | None = PEER_ID
    if setup != "unknown-miner":
        _miner(node_id=None if setup == "no-node-id" else NODE_ID)
    if setup == "empty":
        body = b""
    elif setup == "too-large":
        # The view's own cap, should Django's ever be raised above it.
        settings.DATA_UPLOAD_MAX_MEMORY_SIZE = 2**20
        body = b"x" * (64 * 1024 + 1)
    elif setup == "no-peer":
        peer = None
    elif setup in ("failed", "unavailable"):
        fake.outcome = setup
    elif setup == "other-miner":
        fake.miner_id = "miner-2"
    elif setup == "skew":
        fake.timestamp_unix = int(time.time()) - 301
    resp = _post(body, peer_id=peer)
    assert resp.status_code == status, resp.content
    assert resp.json()["category"] == category
    assert not HostInventorySection.objects.exists()


def test_an_envelope_at_the_cap_passes_the_transport(fake: FakeHostInventoryVerifier) -> None:
    # The crate's MAX_ENVELOPE_BYTES is Django's DATA_UPLOAD_MAX_MEMORY_SIZE.
    _miner()
    assert _post(b"x" * (64 * 1024)).status_code == 200
    assert len(fake.calls[0][0]) == 64 * 1024


def test_a_replayed_sequence_is_409_and_changes_nothing(fake: FakeHostInventoryVerifier) -> None:
    _miner()
    assert _post().status_code == 200
    fake.sections = {"cpu": {"status": "ok", "cores": 48}}
    resp = _post()
    assert resp.status_code == 409
    assert resp.json()["category"] == "replay"
    assert HostInventorySection.objects.get(section="cpu").body["cores"] == 24


def test_past_the_hourly_budget_is_429_with_retry_after(
    settings: Any, fake: FakeHostInventoryVerifier
) -> None:
    settings.VALI_HOST_INVENTORY_MAX_PER_HOUR = 2
    _miner()
    for seq in (1, 2):
        fake.sequence = seq
        assert _post().status_code == 200
    fake.sequence = 3
    resp = _post()
    assert resp.status_code == 429
    assert 0 < int(resp["Retry-After"]) <= 3600
    assert HostInventoryState.objects.get(pk=NODE_ID).last_sequence == 2


# ─── the real verifier, end to end ───────────────────────────────────

real = pytest.mark.skipif(
    not _REAL_BIN.is_file(),
    reason=f"Rust validator not built at {_REAL_BIN} — `cargo build -p hippius-ticket-validator`",
)


@pytest.fixture
def kat_miner(settings: Any, monkeypatch: pytest.MonkeyPatch) -> MinerIdentity:
    monkeypatch.setattr(verifier, "verify_host_inventory", _REAL_VERIFY)
    # The vectors are signed at a fixed time.
    settings.VALI_HOST_INVENTORY_MAX_SKEW_S = 10**10
    return _miner(pubkey_hex=(_VECTORS / "kat_vk.hex").read_text().strip())


@real
def test_the_real_verifier_takes_the_kat_reports_end_to_end(kat_miner: MinerIdentity) -> None:
    full = (_VECTORS / "signed_host_inventory_full.cbor").read_bytes()
    counters = (_VECTORS / "signed_host_inventory_counters.cbor").read_bytes()

    resp = _post(full)
    assert resp.status_code == 200, resp.content
    assert resp.json()["sections"] == [
        "system",
        "cpu",
        "memory",
        "storage",
        "network",
        "pci",
        "sensors",
        "software",
    ]
    memory = HostInventorySection.objects.get(miner_node_id=NODE_ID, section="memory")
    assert memory.body["dimms"][0]["locator"] == "DIMM 0"
    assert len(memory.digest) == 64

    resp = _post(counters)
    assert resp.status_code == 200, resp.content
    assert set(resp.json()["sections"]) == {"memory", "storage", "sensors", "software"}
    changed = set(resp.json()["changed"])
    assert changed == set(
        HostInventoryChange.objects.filter(miner_node_id=NODE_ID).values_list("section", flat=True)
    )
    # Untouched sections keep the full report's sequence.
    assert HostInventorySection.objects.get(section="cpu").sequence == 3
    assert HostInventorySection.objects.get(section="memory").sequence == 4

    # The full report again: a replay.
    assert _post(full).status_code == 409


@real
def test_the_real_verifier_takes_a_report_with_auto_update(kat_miner: MinerIdentity) -> None:
    """Claim: this vali's verifier accepts `software.auto_update` (an older
    one refuses the whole report), and the block lands in the section."""
    resp = _post((_VECTORS / "signed_host_inventory_auto_update.cbor").read_bytes())
    assert resp.status_code == 200, resp.content
    software = HostInventorySection.objects.get(miner_node_id=NODE_ID, section="software")
    assert software.body["auto_update"] == {
        "enabled": False,
        "disabled_reason": "no_auto_update_file",
        "last_check_unix": 1_792_200_000,
        "failed_tag": "v2026.10.18.1",
    }


@real
def test_the_real_verifier_refuses_another_key(kat_miner: MinerIdentity) -> None:
    MinerIdentity.objects.filter(pk=MINER_ID).update(
        pubkey_hex="d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
    )
    resp = _post((_VECTORS / "signed_host_inventory_full.cbor").read_bytes())
    assert resp.status_code == 403
    assert resp.json()["category"] == "signature_invalid"
