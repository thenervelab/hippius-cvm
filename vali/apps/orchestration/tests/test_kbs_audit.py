"""The KBS audit-log ingester (`apps.orchestration.kbs_audit`), driven by
the KBS's OWN bytes.

`hippius-types/tests/fixtures/kbs_audit_wire_v1.json` is produced by the
real KBS sinks through the real `GET /v1/admin/audit` serialisation
(`kbs-core/tests/kbs_audit_wire_fixture.rs`, pinned byte for byte there).
It holds two lives of one KBS: epoch a (release + admin chains) and epoch
b (the release chain after a restart). `FakeKbs` serves any page of a
chain; its first test proves it reproduces every fixture page exactly,
so everything below runs on what the KBS really emits.
"""

from __future__ import annotations

import copy
import dataclasses
import hashlib
import json
import logging
from datetime import timedelta
from pathlib import Path
from typing import Any

import pytest
from django.core.management import call_command
from django.utils import timezone

from apps.orchestration import kbs_audit
from apps.orchestration.effects import EffectError, EffectUnavailable
from apps.orchestration.models import KbsAuditAnomaly, KbsAuditCursor, KbsAuditEntry

FIXTURE = (
    Path(__file__).resolve().parents[4]
    / "hippius-types"
    / "tests"
    / "fixtures"
    / "kbs_audit_wire_v1.json"
)

pytestmark = pytest.mark.django_db


@pytest.fixture(scope="module")
def wire() -> dict[str, Any]:
    doc = json.loads(FIXTURE.read_text(encoding="utf-8"))
    assert doc["v"] == 1, "a new fixture version needs a new vali pin"
    return doc


class FakeKbs:
    """One KBS chain, served with the route's semantics: records after
    `after_seq`, at most `limit`, plus genesis/head."""

    def __init__(self, pages: list[dict[str, Any]]) -> None:
        bodies = [json.loads(p["body_text"]) for p in pages]
        self.log = bodies[0]["log"]
        self.genesis = bodies[0]["genesis_hash_hex"]
        self.entries: list[dict[str, Any]] = [e for b in bodies for e in b["entries"]]
        self.calls: list[tuple[str, int | None, int]] = []

    def page(self, after_seq: int | None, limit: int) -> dict[str, Any]:
        start = 0 if after_seq is None else after_seq + 1
        head = self.entries[-1] if self.entries else None
        return {
            "v": 1,
            "log": self.log,
            "genesis_hash_hex": self.genesis if self.entries else None,
            "head_seq": head["seq"] if head else None,
            "head_hash_hex": head["sha256_hex"] if head else kbs_audit.ZERO_HASH,
            "entries": copy.deepcopy(self.entries[start : start + min(limit, 500)]),
        }

    def __call__(self, log_name: str, after_seq: int | None, limit: int) -> dict[str, Any]:
        assert log_name == self.log, f"asked {log_name} of a {self.log} chain"
        self.calls.append((log_name, after_seq, limit))
        return self.page(after_seq, limit)


def _compact(value: Any) -> str:
    return json.dumps(value, separators=(",", ":"), ensure_ascii=False)


@pytest.fixture(autouse=True)
def _cfg(settings, monkeypatch: pytest.MonkeyPatch) -> None:
    # `LOGGING` pins `apps` with `propagate: False`; caplog listens on root.
    monkeypatch.setattr(logging.getLogger("apps"), "propagate", True)
    settings.VALI_KBS_AUDIT_INGEST_ENABLED = True
    settings.VALI_KBS_AUDIT_PAGE_LIMIT = 2  # the fixture's page size
    settings.VALI_KBS_AUDIT_MAX_PAGES_PER_RUN = 10
    settings.VALI_KBS_AUDIT_INGEST_INTERVAL_S = 60.0
    settings.VALI_KBS_AUDIT_RETENTION_DAYS = 0
    kbs_audit._last_run_monotonic = None


def _rows(log_name: str) -> list[KbsAuditEntry]:
    return list(KbsAuditEntry.objects.filter(log=log_name).order_by("kbs_epoch", "seq"))


# ─── the fake is the KBS ─────────────────────────────────────────────


def test_the_fake_reproduces_every_fixture_page_byte_for_byte(wire: dict[str, Any]) -> None:
    for chain in (
        "release_epoch_a", "admin_epoch_a", "release_epoch_b", "release_torn", "admin_torn"
    ):
        kbs = FakeKbs(wire[chain])
        for p in wire[chain]:
            assert _compact(kbs.page(p["after_seq"], p["limit"])) == p["body_text"], chain


# ─── a clean chain ───────────────────────────────────────────────────


def test_ingests_and_verifies_the_release_chain(wire: dict[str, Any]) -> None:
    kbs = FakeKbs(wire["release_epoch_a"])
    r = kbs_audit.ingest_log("release", fetch=kbs)
    assert (r.stored, r.breaks, r.new_epochs) == (4, 0, 1)
    rows = _rows("release")
    assert [e.seq for e in rows] == [0, 1, 2, 3]
    assert all(e.chain_ok and e.chain_error == "" for e in rows)
    assert {e.kbs_epoch for e in rows} == {kbs.genesis}
    # Stored verbatim.
    for e, served in zip(rows, kbs.entries, strict=True):
        assert bytes(e.body_cbor).hex() == served["body_cbor_hex"]
        assert e.sha256 == served["sha256_hex"]
        assert e.prev_hash == served["prev_hash_hex"]
    # Decoded: the canary's release said `released`.
    canary = wire["canary_vm_id"]
    released = KbsAuditEntry.objects.get(vm_id=canary, reason="released")
    assert (released.op, released.granted, released.ticket_id) == ("release", True, "tk-0002")
    assert released.event_unix == 1_790_000_060
    denied = KbsAuditEntry.objects.get(vm_id=canary, granted=False)
    assert denied.reason == "measurement_not_allowed"
    cursor = KbsAuditCursor.objects.get(log="release")
    assert (cursor.kbs_epoch, cursor.last_seq) == (kbs.genesis, 3)
    assert cursor.last_hash == kbs.entries[-1]["sha256_hex"]
    # Paged: 2 + 2, then the caught-up stop (head reached).
    assert [c[1] for c in kbs.calls] == [None, 1]


def test_ingests_the_admin_chain_with_its_attribution(wire: dict[str, Any]) -> None:
    r = kbs_audit.ingest_log("admin", fetch=FakeKbs(wire["admin_epoch_a"]))
    assert (r.stored, r.breaks) == (3, 0)
    ops = [(e.op, e.status_code, e.applied, e.reason) for e in _rows("admin")]
    assert ops == [
        ("register-vm", 200, True, ""),
        ("activate", 409, False, "state-divergent"),
        ("decommission", 200, True, ""),
    ]
    assert {e.peer_san for e in _rows("admin")} == {"spiffe://hippius.network/vali"}


def test_re_ingest_is_idempotent(wire: dict[str, Any]) -> None:
    kbs = FakeKbs(wire["release_epoch_a"])
    kbs_audit.ingest_log("release", fetch=kbs)
    again = kbs_audit.ingest_log("release", fetch=kbs)
    assert (again.stored, again.breaks, again.new_epochs) == (0, 0, 0)
    # Losing the cursor re-reads from seq 0 — nothing duplicated, no alarm.
    KbsAuditCursor.objects.all().delete()
    replay = kbs_audit.ingest_log("release", fetch=kbs)
    assert (replay.stored, replay.breaks) == (0, 0)
    assert KbsAuditEntry.objects.count() == 4
    assert KbsAuditCursor.objects.get(log="release").last_seq == 3


def test_new_records_after_a_caught_up_cursor_chain_on(wire: dict[str, Any]) -> None:
    kbs = FakeKbs(wire["release_epoch_a"])
    held = kbs.entries[2:]
    kbs.entries = kbs.entries[:2]
    kbs_audit.ingest_log("release", fetch=kbs)
    kbs.entries += held
    r = kbs_audit.ingest_log("release", fetch=kbs)
    assert (r.stored, r.breaks) == (2, 0)
    assert kbs.calls[-1][1] == 1, "asked after the last seq it holds"


# ─── a KBS crash mid-append (torn tail truncated at open) ─────────────


@pytest.mark.parametrize(("chain", "log_name", "seq", "records"), [
    ("release_torn", "release", 2, 4),
    ("admin_torn", "admin", 1, 3),
])
def test_a_truncated_torn_tail_is_a_warning_anomaly_not_a_break(
    wire: dict[str, Any], caplog: pytest.LogCaptureFixture,
    chain: str, log_name: str, seq: int, records: int,
) -> None:
    kbs = FakeKbs(wire[chain])
    with caplog.at_level(logging.WARNING, logger="apps.orchestration.kbs_audit"):
        r = kbs_audit.ingest_log(log_name, fetch=kbs)
    assert (r.stored, r.breaks) == (records, 0)
    rows = _rows(log_name)
    assert all(e.chain_ok for e in rows), "the marker is an ordinary verified record"
    assert KbsAuditCursor.objects.get(log=log_name).broken_at_seq is None
    anomaly = KbsAuditAnomaly.objects.get()
    assert (anomaly.log, anomaly.kind, anomaly.seq) == (log_name, "torn-tail-truncated", seq)
    assert anomaly.kbs_epoch == kbs.genesis
    assert anomaly.observed == rows[seq].sha256
    assert "audit-truncated:seq=" in anomaly.detail
    torn = [rec for rec in caplog.records if "TORN-TAIL-TRUNCATED" in rec.getMessage()]
    assert [rec.levelno for rec in torn] == [logging.WARNING]
    assert not [rec for rec in caplog.records if rec.levelno >= logging.ERROR]
    # Re-reading the same record does not re-count it.
    KbsAuditCursor.objects.all().delete()
    kbs_audit.ingest_log(log_name, fetch=kbs)
    assert KbsAuditAnomaly.objects.get().count == 1


def test_a_clean_chain_records_no_torn_tail(wire: dict[str, Any]) -> None:
    for chain, log_name in (("release_epoch_a", "release"), ("admin_epoch_a", "admin")):
        kbs_audit.ingest_log(log_name, fetch=FakeKbs(wire[chain]))
    assert not KbsAuditAnomaly.objects.exists()


def test_the_marker_shape_is_exact() -> None:
    marker = {
        "granted": False, "ticket_id": "", "vm_id": "",
        "reason": "audit-truncated:seq=2:len=7:sha256=0011223344556677",
    }
    assert kbs_audit.truncation_marker(marker, "release") == marker["reason"]
    # A real release decision that happens to carry such a reason is not one.
    for key, value in (("granted", True), ("vm_id", "vm-1"), ("ticket_id", "tk")):
        assert kbs_audit.truncation_marker({**marker, key: value}, "release") is None
    assert kbs_audit.truncation_marker({**marker, "reason": "audit-truncated"}, "release") is None
    admin = {"op": "audit-truncated", "applied": False, "reason": marker["reason"]}
    assert kbs_audit.truncation_marker(admin, "admin") == marker["reason"]
    assert kbs_audit.truncation_marker({**admin, "op": "register-vm"}, "admin") is None
    assert kbs_audit.truncation_marker({**admin, "applied": True}, "admin") is None
    assert kbs_audit.truncation_marker(None, "admin") is None


def test_a_marker_that_does_not_verify_is_a_break_not_a_torn_tail(
    wire: dict[str, Any],
) -> None:
    kbs = FakeKbs(wire["release_torn"])
    # The marker's body still decodes as a marker; only its stored hash lies.
    kbs.entries[2]["sha256_hex"] = "ab" * 32
    r = kbs_audit.ingest_log("release", fetch=kbs)
    assert KbsAuditEntry.objects.get(log="release", seq=2).reason.startswith("audit-truncated:")
    assert r.breaks >= 1
    assert not KbsAuditAnomaly.objects.filter(kind="torn-tail-truncated").exists()
    assert KbsAuditCursor.objects.get(log="release").broken_at_seq == 2


# ─── tamper ──────────────────────────────────────────────────────────


def _flip_body(entry: dict[str, Any], *, rehash: bool) -> None:
    body = bytearray.fromhex(entry["body_cbor_hex"])
    # Last byte of the release body is inside the vm_id text — still
    # canonical CBOR, different content.
    body[-1] ^= 0x01
    entry["body_cbor_hex"] = body.hex()
    if rehash:
        entry["sha256_hex"] = hashlib.sha256(bytes(body)).hexdigest()


def test_a_tampered_body_is_stored_flagged_and_alerts(
    wire: dict[str, Any], caplog: pytest.LogCaptureFixture
) -> None:
    kbs = FakeKbs(wire["release_epoch_a"])
    _flip_body(kbs.entries[1], rehash=False)
    with caplog.at_level(logging.ERROR, logger="apps.orchestration.kbs_audit"):
        r = kbs_audit.ingest_log("release", fetch=kbs)
    assert r.stored == 4, "a broken record is stored, never skipped"
    rows = {e.seq: e for e in _rows("release")}
    assert rows[0].chain_ok
    assert rows[1].chain_ok is False and "hash-mismatch" in rows[1].chain_error
    # Its successor chains onto the ORIGINAL hash, not the tampered body's.
    assert rows[2].chain_ok is False and "chain-broken" in rows[2].chain_error
    # And nothing after a break is trusted, even if it chains locally.
    assert rows[3].chain_ok is False and "unverified" in rows[3].chain_error
    assert r.breaks == 2
    assert KbsAuditCursor.objects.get(log="release").broken_at_seq == 1
    assert "KBS AUDIT CHAIN BREAK" in caplog.text


def test_a_tamper_inside_a_page_breaks_its_in_page_successor(wire: dict[str, Any]) -> None:
    # seq 2 opens the second page, so its successor seq 3 is checked
    # against it inside the SAME page.
    kbs = FakeKbs(wire["release_epoch_a"])
    _flip_body(kbs.entries[2], rehash=False)
    kbs_audit.ingest_log("release", fetch=kbs)
    rows = {e.seq: e for e in _rows("release")}
    assert rows[0].chain_ok and rows[1].chain_ok
    assert "hash-mismatch" in rows[2].chain_error
    assert "chain-broken" in rows[3].chain_error


def test_a_consistently_rehashed_rewrite_still_breaks_the_chain(wire: dict[str, Any]) -> None:
    kbs = FakeKbs(wire["release_epoch_a"])
    _flip_body(kbs.entries[1], rehash=True)
    kbs_audit.ingest_log("release", fetch=kbs)
    rows = {e.seq: e for e in _rows("release")}
    assert rows[1].chain_ok, "self-consistent in isolation"
    assert rows[2].chain_ok is False and "chain-broken" in rows[2].chain_error


def test_a_withheld_record_holds_the_cursor_before_the_hole(
    wire: dict[str, Any],
) -> None:
    kbs = FakeKbs(wire["release_epoch_a"])
    del kbs.entries[1]  # the KBS serves 0, 2, 3
    kbs.page = _by_seq(kbs)  # type: ignore[method-assign]
    r = kbs_audit.ingest_log("release", fetch=kbs)
    # Nothing past the hole is taken; the hole is a durable anomaly.
    assert [e.seq for e in _rows("release")] == [0]
    assert r.breaks == 1
    withheld = KbsAuditAnomaly.objects.get(kind="withheld")
    assert withheld.seq == 1
    assert KbsAuditCursor.objects.get(log="release").last_seq == 0
    # The next run asks for seq 1 again; once the KBS serves it, it still
    # has to chain onto the verified prefix — and does.
    kbs.entries = FakeKbs(wire["release_epoch_a"]).entries
    kbs_audit.ingest_log("release", fetch=kbs)
    rows = {e.seq: e for e in _rows("release")}
    assert sorted(rows) == [0, 1, 2, 3]
    assert all(e.chain_ok for e in rows.values())


def test_a_page_that_jumps_far_ahead_does_not_move_the_cursor(wire: dict[str, Any]) -> None:
    kbs = FakeKbs(wire["release_epoch_a"])
    kbs_audit.ingest_log("release", fetch=kbs)

    def jump(log_name: str, after: int | None, limit: int) -> dict[str, Any]:
        page = kbs(log_name, after, limit)
        page["entries"] = [dict(kbs.entries[-1], seq=100)]
        page["head_seq"] = 100
        return page

    r = kbs_audit.ingest_log("release", fetch=jump)
    assert r.breaks == 1 and r.stored == 0
    assert KbsAuditCursor.objects.get(log="release").last_seq == 3
    assert KbsAuditAnomaly.objects.get(kind="withheld").seq == 4


def test_a_page_repeating_a_seq_is_an_anomaly_not_a_crash(wire: dict[str, Any]) -> None:
    kbs = FakeKbs(wire["release_epoch_a"])

    def repeat(log_name: str, after: int | None, limit: int) -> dict[str, Any]:
        page = kbs(log_name, after, limit)
        page["entries"] = [page["entries"][0], page["entries"][0]]
        return page

    r = kbs_audit.ingest_log("release", fetch=repeat)
    assert r.breaks == 1
    assert [e.seq for e in _rows("release")] == [0]
    assert KbsAuditAnomaly.objects.get(kind="duplicate").seq == 1


def _reencode(entry: dict[str, Any], mutate) -> None:
    """Re-encode a release body through `mutate(dict)`, keeping it
    self-consistent (hash recomputed) — a forger's best effort."""
    body = kbs_audit.decode_body(bytes.fromhex(entry["body_cbor_hex"]))
    assert body is not None
    items = mutate(body)
    raw = _cbor_map(items)
    entry["body_cbor_hex"] = raw.hex()
    entry["sha256_hex"] = hashlib.sha256(raw).hexdigest()


def _cbor_head(major: int, n: int) -> bytes:
    if n < 24:
        return bytes([major << 5 | n])
    if n < 256:
        return bytes([major << 5 | 24, n])
    if n < 65536:
        return bytes([major << 5 | 25]) + n.to_bytes(2, "big")
    return bytes([major << 5 | 26]) + n.to_bytes(4, "big")


def _cbor_item(v: Any) -> bytes:
    if isinstance(v, bool):
        return b"\xf5" if v else b"\xf4"
    if isinstance(v, int):
        return _cbor_head(0, v)
    if isinstance(v, bytes):
        return _cbor_head(2, len(v)) + v
    if isinstance(v, str):
        return _cbor_head(3, len(v.encode())) + v.encode()
    raise TypeError(v)


def _cbor_map(items: list[tuple[str, Any]]) -> bytes:
    return _cbor_head(5, len(items)) + b"".join(_cbor_item(k) + _cbor_item(v) for k, v in items)


def test_a_body_missing_schema_fields_does_not_verify(wire: dict[str, Any]) -> None:
    kbs = FakeKbs(wire["release_epoch_a"])
    keep = {"domain", "prev_hash", "seq"}
    for e in kbs.entries:
        _reencode(e, lambda d: [(k, v) for k, v in d.items() if k in keep])
    # Re-chain the forged bodies so ONLY the schema can object.
    prev = kbs_audit.ZERO_HASH
    for e in kbs.entries:
        _reencode(e, lambda d, p=prev: [(k, bytes.fromhex(p) if k == "prev_hash" else v)
                                        for k, v in d.items()])
        e["prev_hash_hex"] = prev
        prev = e["sha256_hex"]
    kbs.genesis = kbs.entries[0]["sha256_hex"]
    kbs_audit.ingest_log("release", fetch=kbs)
    rows = _rows("release")
    assert rows and all(not e.chain_ok for e in rows)
    assert "schema-mismatch" in rows[0].chain_error


def test_a_body_with_unsorted_keys_does_not_verify(wire: dict[str, Any]) -> None:
    kbs = FakeKbs(wire["release_epoch_a"])
    _reencode(kbs.entries[0], lambda d: list(reversed(list(d.items()))))
    kbs.genesis = kbs.entries[0]["sha256_hex"]
    kbs_audit.ingest_log("release", fetch=kbs)
    assert "non-canonical-key-order" in _rows("release")[0].chain_error


def _by_seq(kbs: FakeKbs):
    """`kbs.page` that slices by seq (for a chain with a hole)."""

    def page(after_seq: int | None, limit: int) -> dict[str, Any]:
        start = -1 if after_seq is None else after_seq
        head = kbs.entries[-1]
        return {
            "v": 1,
            "log": kbs.log,
            "genesis_hash_hex": kbs.genesis,
            "head_seq": head["seq"],
            "head_hash_hex": head["sha256_hex"],
            "entries": copy.deepcopy([e for e in kbs.entries if e["seq"] > start][:limit]),
        }

    return page


def test_a_forged_genesis_is_not_accepted_as_a_restart(wire: dict[str, Any]) -> None:
    """The KBS keeps its real seq 0 (whose hash IS the old epoch), rewrites
    the tail, and names a fresh genesis to pass the fork off as a restart."""
    kbs = FakeKbs(wire["release_epoch_a"])
    kbs_audit.ingest_log("release", fetch=kbs)
    old = kbs.genesis
    _flip_body(kbs.entries[3], rehash=True)
    kbs.genesis = "ee" * 32
    r = kbs_audit.ingest_log("release", fetch=kbs)
    assert (r.stored, r.new_epochs, r.breaks) == (0, 0, 1)
    assert KbsAuditAnomaly.objects.filter(kind="genesis-mismatch").count() == 1
    assert not KbsAuditEntry.objects.filter(kbs_epoch="ee" * 32).exists()
    assert KbsAuditCursor.objects.get(log="release").kbs_epoch == old


def test_a_self_contradictory_page_is_refused_not_read_as_empty(wire: dict[str, Any]) -> None:
    kbs = FakeKbs(wire["release_epoch_a"])

    def lying(log_name: str, after: int | None, limit: int) -> dict[str, Any]:
        page = kbs(log_name, after, limit)
        # An "empty log" in every field … that still carries entries.
        page.update(genesis_hash_hex=None, head_seq=None, head_hash_hex=kbs_audit.ZERO_HASH)
        return page

    with pytest.raises(EffectError):
        kbs_audit.ingest_log("release", fetch=lying)
    assert KbsAuditEntry.objects.count() == 0


def test_an_empty_page_below_the_advertised_head_is_withheld(wire: dict[str, Any]) -> None:
    kbs = FakeKbs(wire["release_epoch_a"])
    kbs_audit.ingest_log("release", fetch=kbs)
    kbs.entries.append(dict(kbs.entries[-1], seq=4))  # head says 4 …

    def withholding(log_name: str, after: int | None, limit: int) -> dict[str, Any]:
        return dict(kbs(log_name, after, limit), entries=[])  # … and serves nothing

    r = kbs_audit.ingest_log("release", fetch=withholding)
    assert r.breaks == 1
    assert KbsAuditAnomaly.objects.get(kind="withheld").seq == 4


def test_a_head_hash_that_is_not_the_last_record_is_flagged(wire: dict[str, Any]) -> None:
    kbs = FakeKbs(wire["release_epoch_a"])

    def lying_head(log_name: str, after: int | None, limit: int) -> dict[str, Any]:
        return dict(kbs(log_name, after, limit), head_hash_hex="ab" * 32)

    r = kbs_audit.ingest_log("release", fetch=lying_head)
    assert r.breaks == 1
    assert KbsAuditAnomaly.objects.get(kind="head-mismatch").seq == 3


def test_equivocation_keeps_the_held_row_and_breaks_the_epoch(wire: dict[str, Any]) -> None:
    kbs = FakeKbs(wire["release_epoch_a"])
    kbs_audit.ingest_log("release", fetch=kbs)
    held = bytes(KbsAuditEntry.objects.get(log="release", seq=2).body_cbor)
    KbsAuditCursor.objects.all().delete()  # force a re-read from seq 0
    _flip_body(kbs.entries[2], rehash=False)  # different bytes, SAME claimed hash
    r = kbs_audit.ingest_log("release", fetch=kbs)
    assert r.breaks >= 1
    assert KbsAuditAnomaly.objects.get(kind="equivocation").seq == 2
    assert bytes(KbsAuditEntry.objects.get(log="release", seq=2).body_cbor) == held
    assert KbsAuditCursor.objects.get(log="release").broken_at_seq == 2


def test_breaks_query_lists_anomalies(wire: dict[str, Any], capsys) -> None:
    kbs = FakeKbs(wire["release_epoch_a"])
    kbs_audit.ingest_log("release", fetch=kbs)
    kbs.entries = kbs.entries[:2]
    kbs_audit.ingest_log("release", fetch=kbs)
    call_command("vali_kbs_audit", "--breaks")
    assert "ANOMALY cut release" in capsys.readouterr().out


def test_a_record_of_the_other_chain_is_refused(wire: dict[str, Any]) -> None:
    rel = FakeKbs(wire["release_epoch_a"])
    adm = FakeKbs(wire["admin_epoch_a"])
    rel.entries[1] = adm.entries[1]  # an admin record served as seq 1 of release
    kbs_audit.ingest_log("release", fetch=rel)
    assert "wrong-domain" in _rows("release")[1].chain_error


def test_a_served_prev_hash_that_disagrees_with_the_body_is_flagged(
    wire: dict[str, Any],
) -> None:
    kbs = FakeKbs(wire["release_epoch_a"])
    kbs.entries[2]["prev_hash_hex"] = "ab" * 32
    kbs_audit.ingest_log("release", fetch=kbs)
    assert "served-prev-hash-disagrees" in _rows("release")[2].chain_error


def test_a_chain_cut_within_an_epoch_alerts_and_holds_the_cursor(
    wire: dict[str, Any], caplog: pytest.LogCaptureFixture
) -> None:
    kbs = FakeKbs(wire["release_epoch_a"])
    kbs_audit.ingest_log("release", fetch=kbs)
    kbs.entries = kbs.entries[:2]  # same genesis, head now below vali's
    with caplog.at_level(logging.ERROR, logger="apps.orchestration.kbs_audit"):
        r = kbs_audit.ingest_log("release", fetch=kbs)
    assert (r.breaks, r.stored, r.new_epochs) == (1, 0, 0)
    assert "KBS AUDIT CUT" in caplog.text
    assert KbsAuditCursor.objects.get(log="release").last_seq == 3
    # Durable, and deduplicated when seen again.
    kbs_audit.ingest_log("release", fetch=kbs)
    cut = KbsAuditAnomaly.objects.get(kind="cut")
    assert (cut.seq, cut.count) == (3, 2)


def test_a_rewritten_head_at_the_same_seq_alerts(wire: dict[str, Any]) -> None:
    kbs = FakeKbs(wire["release_epoch_a"])
    kbs_audit.ingest_log("release", fetch=kbs)
    kbs.entries[-1]["sha256_hex"] = "cd" * 32
    r = kbs_audit.ingest_log("release", fetch=kbs)
    assert r.breaks == 1


# ─── restart ─────────────────────────────────────────────────────────


def test_a_kbs_restart_opens_a_new_epoch_without_a_tamper_alarm(
    wire: dict[str, Any], caplog: pytest.LogCaptureFixture
) -> None:
    kbs_audit.ingest_log("release", fetch=FakeKbs(wire["release_epoch_a"]))
    b = FakeKbs(wire["release_epoch_b"])
    with caplog.at_level(logging.WARNING, logger="apps.orchestration.kbs_audit"):
        r = kbs_audit.ingest_log("release", fetch=b)
    assert (r.stored, r.breaks, r.new_epochs) == (2, 0, 1)
    assert "NEW KBS epoch" in caplog.text
    assert not [rec for rec in caplog.records if rec.levelno >= logging.ERROR]
    # It asked after vali's old seq, saw the new genesis, re-read from 0.
    assert [c[1] for c in b.calls] == [3, None]
    epochs = {e.kbs_epoch for e in _rows("release")}
    assert len(epochs) == 2 and b.genesis in epochs
    assert [e.seq for e in _rows("release") if e.kbs_epoch == b.genesis] == [0, 1]
    assert all(e.chain_ok for e in _rows("release"))
    assert KbsAuditCursor.objects.get(log="release").kbs_epoch == b.genesis


def test_an_emptied_log_after_a_restart_waits_for_the_new_genesis(
    wire: dict[str, Any], caplog: pytest.LogCaptureFixture
) -> None:
    kbs = FakeKbs(wire["release_epoch_a"])
    kbs_audit.ingest_log("release", fetch=kbs)
    kbs.entries = []
    with caplog.at_level(logging.WARNING, logger="apps.orchestration.kbs_audit"):
        r = kbs_audit.ingest_log("release", fetch=kbs)
    assert (r.stored, r.breaks) == (0, 0)
    assert "restarted" in caplog.text
    assert KbsAuditCursor.objects.get(log="release").last_seq == 3


# ─── the tick hook ───────────────────────────────────────────────────


class _Both:
    def __init__(self, *chains: FakeKbs) -> None:
        self.by_log = {c.log: c for c in chains}

    def __call__(self, log_name: str, after: int | None, limit: int) -> dict[str, Any]:
        return self.by_log[log_name](log_name, after, limit)


def test_tick_ingests_both_chains(wire: dict[str, Any]) -> None:
    both = _Both(FakeKbs(wire["release_epoch_a"]), FakeKbs(wire["admin_epoch_a"]))
    r = kbs_audit.ingest_tick(fetch=both, now=lambda: 1000.0)
    assert (r.stored, r.breaks) == (7, 0)


def test_tick_is_inert_with_the_flag_off(settings, wire: dict[str, Any]) -> None:
    settings.VALI_KBS_AUDIT_INGEST_ENABLED = False

    def boom(*_a: Any) -> dict[str, Any]:
        raise AssertionError("fetched with the flag off")

    assert kbs_audit.ingest_tick(fetch=boom).stored == 0


def test_tick_skips_quietly_when_the_kbs_has_no_route(
    caplog: pytest.LogCaptureFixture,
) -> None:
    def missing(*_a: Any) -> dict[str, Any]:
        raise kbs_audit.KbsAuditRouteMissing("404")

    with caplog.at_level(logging.INFO, logger="apps.orchestration.kbs_audit"):
        r = kbs_audit.ingest_tick(fetch=missing, now=lambda: 1000.0)
    assert r.skipped == "route-missing" and r.stored == 0
    assert not [rec for rec in caplog.records if rec.levelno >= logging.INFO]
    assert KbsAuditEntry.objects.count() == 0


def test_tick_survives_an_unreachable_kbs(caplog: pytest.LogCaptureFixture) -> None:
    def down(*_a: Any) -> dict[str, Any]:
        raise EffectUnavailable("kbs-audit: peer unreachable")

    with caplog.at_level(logging.WARNING, logger="apps.orchestration.kbs_audit"):
        r = kbs_audit.ingest_tick(fetch=down, now=lambda: 1000.0)
    assert r.stored == 0 and "resuming next run" in caplog.text


def test_tick_stops_at_the_first_unreachable_log_instead_of_trying_both(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """A down KBS is down for every log — `EffectUnavailable` on the first
    (`release`) must not spend a second HTTP timeout probing `admin`."""
    calls: list[str] = []

    def down(log_name: str, *_a: Any) -> dict[str, Any]:
        calls.append(log_name)
        raise EffectUnavailable("kbs-audit: peer unreachable")

    with caplog.at_level(logging.WARNING, logger="apps.orchestration.kbs_audit"):
        r = kbs_audit.ingest_tick(fetch=down, now=lambda: 1000.0)
    assert calls == ["release"]
    assert r.skipped == "unavailable" and r.stored == 0


def test_tick_moves_on_to_the_next_log_on_a_plain_effect_error(
    wire: dict[str, Any], caplog: pytest.LogCaptureFixture
) -> None:
    """A non-`EffectUnavailable` `EffectError` is scoped to the one log
    (e.g. a malformed page) — the other chain still gets ingested."""
    admin = FakeKbs(wire["admin_epoch_a"])

    def flaky(log_name: str, after: int | None, limit: int) -> dict[str, Any]:
        if log_name == "release":
            raise EffectError("kbs-audit: malformed page")
        return admin(log_name, after, limit)

    with caplog.at_level(logging.WARNING, logger="apps.orchestration.kbs_audit"):
        r = kbs_audit.ingest_tick(fetch=flaky, now=lambda: 1000.0)
    assert r.skipped == "" and "ingest failed, retrying next run" in caplog.text
    assert r.per_log.get("admin", 0) > 0


def test_tick_is_throttled(wire: dict[str, Any]) -> None:
    both = _Both(FakeKbs(wire["release_epoch_a"]), FakeKbs(wire["admin_epoch_a"]))
    assert kbs_audit.ingest_tick(fetch=both, now=lambda: 1000.0).stored == 7
    assert kbs_audit.ingest_tick(fetch=both, now=lambda: 1030.0).skipped == "throttled"
    assert kbs_audit.ingest_tick(fetch=both, now=lambda: 1061.0).skipped == ""


def test_the_page_budget_bounds_one_run(settings, wire: dict[str, Any]) -> None:
    settings.VALI_KBS_AUDIT_MAX_PAGES_PER_RUN = 1
    kbs = FakeKbs(wire["release_epoch_a"])
    assert kbs_audit.ingest_log("release", fetch=kbs).stored == 2
    assert kbs_audit.ingest_log("release", fetch=kbs).stored == 2
    assert len(kbs.calls) == 2


# ─── retention ───────────────────────────────────────────────────────


def test_retention_keeps_everything_by_default_and_never_prunes_a_break(
    settings, wire: dict[str, Any]
) -> None:
    kbs = FakeKbs(wire["release_epoch_a"])
    _flip_body(kbs.entries[3], rehash=False)
    kbs_audit.ingest_log("release", fetch=kbs)
    KbsAuditEntry.objects.update(fetched_at=timezone.now() - timedelta(days=400))
    assert kbs_audit.prune() == 0
    settings.VALI_KBS_AUDIT_RETENTION_DAYS = 30
    assert kbs_audit.prune() == 3
    left = _rows("release")
    assert [(e.seq, e.chain_ok) for e in left] == [(3, False)]


# ─── the transport ───────────────────────────────────────────────────


def test_fetch_page_speaks_the_route(monkeypatch: pytest.MonkeyPatch, settings) -> None:
    settings.VALI_KBS_ADMIN_URL = "http://kbs-admin.test:8001"
    seen: list[str] = []

    def http(method: str, url: str, **kw: Any) -> tuple[int, bytes]:
        seen.append(f"{method} {url}")
        return 200, b'{"v":1}'

    monkeypatch.setattr(kbs_audit.effects, "_http", http)
    assert kbs_audit.fetch_page("release", 41, 500) == {"v": 1}
    assert kbs_audit.fetch_page("admin", None, 7) == {"v": 1}
    assert seen == [
        "GET http://kbs-admin.test:8001/v1/admin/audit?log=release&limit=500&after_seq=41",
        "GET http://kbs-admin.test:8001/v1/admin/audit?log=admin&limit=7",
    ]


@pytest.mark.parametrize(
    ("status", "exc"),
    [
        (404, kbs_audit.KbsAuditRouteMissing),
        (429, kbs_audit.KbsAuditRateLimited),
        (403, kbs_audit.EffectError),
        (500, kbs_audit.EffectError),
    ],
)
def test_fetch_page_classifies_refusals(
    monkeypatch: pytest.MonkeyPatch, settings, status: int, exc: type
) -> None:
    settings.VALI_KBS_ADMIN_URL = "http://kbs-admin.test:8001"
    monkeypatch.setattr(kbs_audit.effects, "_http", lambda *a, **k: (status, b""))
    with pytest.raises(exc):
        kbs_audit.fetch_page("release", None, 1)


# ─── the operator query ──────────────────────────────────────────────


def test_query_proves_the_canary_release(wire: dict[str, Any], capsys) -> None:
    kbs_audit.ingest_log("release", fetch=FakeKbs(wire["release_epoch_a"]))
    kbs_audit.ingest_log("admin", fetch=FakeKbs(wire["admin_epoch_a"]))
    call_command(
        "vali_kbs_audit", "--vm", wire["canary_vm_id"], "--log", "release", "--reason", "released"
    )
    out = capsys.readouterr().out.strip().splitlines()
    assert len(out) == 1
    assert "reason=released" in out[0] and "granted=True" in out[0] and "chain=ok" in out[0]

    call_command("vali_kbs_audit", "--vm", wire["canary_vm_id"], "--json")
    lines = [json.loads(x) for x in capsys.readouterr().out.strip().splitlines()]
    assert {(x["log"], x["body"]["reason"]) for x in lines} >= {
        ("release", "released"),
        ("admin", "state-divergent"),
    }
    assert all(x["body"]["vm_id"] == wire["canary_vm_id"] for x in lines)

    call_command("vali_kbs_audit", "--since", "2026-09-21T14:15:00Z", "--log", "release")
    since = capsys.readouterr().out.strip().splitlines()
    assert [x.split()[3] for x in since] == ["seq=2", "seq=3"]


def test_query_with_no_match_exits_nonzero(wire: dict[str, Any]) -> None:
    kbs_audit.ingest_log("release", fetch=FakeKbs(wire["release_epoch_a"]))
    with pytest.raises(SystemExit) as exc:
        call_command("vali_kbs_audit", "--vm", "no-such-vm")
    assert exc.value.code == 1


# ─── the reason column is the WHOLE reason (N3) ──────────────────────


def test_a_long_rollback_reason_is_stored_whole_and_searchable(capsys) -> None:
    """A rollback audit row's reason carries `timeline_from=… timeline_to=…`
    and the arm's ticket binding well past 128 chars; the column keeps all
    of it, and `--reason-contains` finds the row by the tail."""
    tail = "timeline_to=" + "b2" * 32
    reason = (
        "intent to_counter=7 token_epoch=1 timeline_from=" + "a1" * 32 + " " + tail
        + " ticket_id=tk-0042 restore_id=r-0001"
    )
    assert tail not in reason[:128], "the tail is exactly what a 128-char cut lost"
    checked = kbs_audit.CheckedEntry(
        seq=0,
        body=b"\xa0",
        sha256="00" * 32,
        prev_hash="00" * 32,
        actual_hash="00" * 32,
        decoded={"op": "rollback-consume-intent", "url_vm_id": "vm-long", "reason": reason},
        errors=(),
    )
    other = dataclasses.replace(
        checked, seq=1, decoded={"op": "register-vm", "url_vm_id": "vm-other", "reason": "ok"}
    )
    for c in (checked, other):
        kbs_audit._row(
            c, log_name="admin", epoch="e" * 64, fetched_at=timezone.now(), errors=[]
        ).save()
    row = KbsAuditEntry.objects.get(vm_id="vm-long")
    assert row.reason == reason
    assert KbsAuditEntry.objects.filter(reason__contains=tail).count() == 1
    call_command("vali_kbs_audit", "--reason-contains", tail)
    lines = capsys.readouterr().out.strip().splitlines()
    assert len(lines) == 1 and "vm=vm-long" in lines[0] and tail in lines[0]
