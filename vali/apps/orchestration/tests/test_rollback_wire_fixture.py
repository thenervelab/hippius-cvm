"""The C-4 rollback wire, pinned against the KBS's own bytes.

`hippius-types/tests/fixtures/rollback_wire_v1.json` is produced by the
real KBS code (`kbs-core/tests/rollback_wire_fixture.rs`) and pinned byte
for byte on the Rust side. This suite loads the SAME file and proves vali
reads and writes exactly that wire: the checkpoint 200, the
`authorize-rollback` request vali builds, the 201 arm, the `GET .../rollback`
status, and every refusal body with its status. A change on either side
that the other does not follow fails CI here."""

from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path
from typing import Any

import pytest

from apps.orchestration import effects
from apps.orchestration.effects import EffectError, KbsRouteMissing
from apps.orchestration.services import kbs_rollback

#: Relative to the repository root (this file is vali/apps/orchestration/tests/).
FIXTURES = Path(__file__).resolve().parents[4] / "hippius-types" / "tests" / "fixtures"
#: v2 = what the KBS produces now (V2 checkpoints, naming the VM's volume-
#: stamp timeline); v1 = the frozen pre-v2 wire, which vali must keep
#: reading (backups taken before V2 carry V1 checkpoints).
FIXTURE_VERSIONS = (1, 2)


def _compact(value: Any) -> str:
    """serde_json's encoding: no whitespace, keys in the order given."""
    return json.dumps(value, separators=(",", ":"), ensure_ascii=False)


@pytest.fixture(scope="module", params=FIXTURE_VERSIONS, ids=lambda v: f"v{v}")
def wire(request: pytest.FixtureRequest) -> dict[str, Any]:
    doc = json.loads((FIXTURES / f"rollback_wire_v{request.param}.json").read_text("utf-8"))
    assert doc["version"] == request.param, "a new fixture version needs a new vali pin"
    return doc


class _Http:
    """`effects._http`: one canned answer, every call recorded."""

    def __init__(self, status: int, text: str) -> None:
        self.answer = (status, text.encode("utf-8"))
        self.calls: list[tuple[str, str, Any]] = []

    def __call__(self, method: str, url: str, **kw: Any) -> tuple[int, bytes]:
        self.calls.append((method, url, kw.get("json_body")))
        return self.answer


@pytest.fixture
def http(monkeypatch: pytest.MonkeyPatch, settings) -> Any:
    settings.VALI_KBS_ADMIN_URL = "http://kbs.test:8001"

    def install(status: int, text: str) -> _Http:
        fake = _Http(status, text)
        monkeypatch.setattr(effects, "_http", fake)
        return fake

    return install


# ── every entry's body_text IS its body ──────────────────────────────


def test_every_body_text_is_its_body(wire: dict[str, Any]) -> None:
    entries = [
        wire["rollback_checkpoint_response"],
        wire["authorize_rollback_request"],
        wire["authorize_rollback_response"],
        wire["rollback_status_response"],
        *wire["refusals"],
    ]
    for entry in entries:
        assert json.loads(entry["body_text"]) == entry["body"]


# ── refusals ─────────────────────────────────────────────────────────

#: vali's classification of every KBS refusal the fixture carries:
#: `(status, exception class)`. `RollbackRefused` is terminal (a restore
#: fails before its commit point), `KbsRateLimited` and a plain
#: `EffectError` are retried, `RollbackUnavailable` reads as a KBS without
#: rollbacks. A reason the KBS adds or drops fails
#: `test_the_classification_covers_exactly_the_fixtures_refusals`.
CLASSIFICATION: dict[str, tuple[int, type[EffectError]]] = {
    "vm-id-empty": (400, kbs_rollback.RollbackRefused),
    "bad-restore-id": (400, kbs_rollback.RollbackRefused),
    "bad-manifest-sha256": (400, kbs_rollback.RollbackRefused),
    "bad-dest-platform-id": (400, kbs_rollback.RollbackRefused),
    "bad-requested-by": (400, kbs_rollback.RollbackRefused),
    "bad-new-gen": (400, kbs_rollback.RollbackRefused),
    "bad-point-manifest": (400, kbs_rollback.RollbackRefused),
    "bad-checkpoint-signature": (400, kbs_rollback.RollbackRefused),
    "checkpoint-vm-mismatch": (400, kbs_rollback.RollbackRefused),
    "not-a-rollback": (409, kbs_rollback.RollbackRefused),
    "row-not-activated": (409, kbs_rollback.RollbackRefused),
    "arm-exists": (409, kbs_rollback.RollbackRefused),
    # Per VM: terminal, NOT the gateway's retryable limiter below.
    "rollback-rate-limited": (429, kbs_rollback.RollbackRefused),
    "ttl-out-of-range": (400, kbs_rollback.RollbackRefused),
    # A 404 WITH a reason is the KBS speaking, never a missing route.
    "no-vm-row": (404, kbs_rollback.RollbackRefused),
    "no-boot-counter": (409, kbs_rollback.RollbackRefused),
    "vm-fenced": (409, kbs_rollback.RollbackRefused),
    "restore-id-consumed": (409, kbs_rollback.RollbackRefused),
    "rollback-pending": (409, kbs_rollback.RollbackRefused),
    "admin-client-cert-required": (403, kbs_rollback.RollbackRefused),
    "checkpoint-unstamped": (409, kbs_rollback.RollbackRefused),
    "manifest-mismatch": (400, kbs_rollback.RollbackRefused),
    "guest-not-rollback-capable": (409, kbs_rollback.RollbackRefused),
    # v2: a V1 checkpoint names no timeline — terminal.
    kbs_rollback.REASON_CHECKPOINT_NOT_TIMELINE_BOUND: (409, kbs_rollback.RollbackRefused),
    # The admin gateway's shared limiter: retried.
    "rate-limited": (429, kbs_rollback.KbsRateLimited),
    "body-too-large": (413, kbs_rollback.RollbackRefused),
    "clock-unavailable": (500, EffectError),
    "rollback-unavailable": (503, kbs_rollback.RollbackUnavailable),
    "checkpoint-body-decode": (400, kbs_rollback.RollbackRefused),
    "authorize-body-decode": (400, kbs_rollback.RollbackRefused),
    "audit-unavailable": (500, EffectError),
    "internal-error": (500, EffectError),
}


def test_the_classification_covers_exactly_the_fixtures_refusals(wire: dict[str, Any]) -> None:
    reasons = [r["reason"] for r in wire["refusals"]]
    want = set(CLASSIFICATION)
    if wire["version"] == 1:
        want.discard(kbs_rollback.REASON_CHECKPOINT_NOT_TIMELINE_BOUND)
    assert len(reasons) == len(set(reasons)) == len(want)
    assert set(reasons) == want


def test_the_checkpoint_version_decides_rollback_capability(wire: dict[str, Any]) -> None:
    """V2 (the KBS's current wire) names the timeline and is the only kind
    the KBS arms; V1 still parses, is never offered for a rollback."""
    body = wire["rollback_checkpoint_response"]["body"]
    cp = kbs_rollback.parse_checkpoint(body, vm_id=wire["vm_id"])
    v2 = wire["version"] == 2
    assert cp.timeline_bound is v2
    assert kbs_rollback.checkpoint_is_timeline_bound(cp.wire()) is v2
    if v2:
        assert cp.volume_stamp_timeline_id_hex == body["checkpoint"]["volume_stamp_timeline_id_hex"]
        assert body["checkpoint"]["domain"] == kbs_rollback.CHECKPOINT_DOMAIN_V2


def test_a_v2_checkpoint_whose_signed_timeline_disagrees_is_refused(
    wire: dict[str, Any],
) -> None:
    if wire["version"] != 2:
        pytest.skip("V2 only")
    body = json.loads(wire["rollback_checkpoint_response"]["body_text"])
    body["checkpoint"]["volume_stamp_timeline_id_hex"] = "00" * 32
    with pytest.raises(ValueError, match="volume_stamp_timeline_id"):
        kbs_rollback.parse_checkpoint(body, vm_id=wire["vm_id"])
    del body["checkpoint"]["volume_stamp_timeline_id_hex"]
    with pytest.raises(ValueError):
        kbs_rollback.parse_checkpoint(body, vm_id=wire["vm_id"])


def test_every_refusal_body_parses_to_its_vali_classification(wire: dict[str, Any]) -> None:
    for entry in wire["refusals"]:
        reason, status = entry["reason"], entry["status"]
        want_status, want_class = CLASSIFICATION[reason]
        assert status == want_status, reason
        assert entry["body"]["reason"] == reason
        err = kbs_rollback.refusal_error("t", status, entry["body_text"].encode("utf-8"))
        # Exact class: a RollbackUnavailable is also a KbsRouteMissing, and
        # every class is an EffectError — only the exact one is right.
        assert type(err) is want_class, (reason, type(err).__name__)
        retry = entry["body"].get("retry_after_s")
        assert (retry is not None) == (status == 429), reason
        if isinstance(err, kbs_rollback.RollbackRefused):
            assert (err.status, err.reason, err.retry_after_s) == (status, reason, retry)
        if isinstance(err, kbs_rollback.KbsRateLimited):
            assert err.retry_after_s == retry


def test_the_two_429s_are_told_apart(wire: dict[str, Any]) -> None:
    by_reason = {r["reason"]: r for r in wire["refusals"]}
    gateway, per_vm = by_reason["rate-limited"], by_reason["rollback-rate-limited"]
    assert gateway["status"] == per_vm["status"] == 429
    busy = kbs_rollback.refusal_error("t", 429, gateway["body_text"].encode())
    limited = kbs_rollback.refusal_error("t", 429, per_vm["body_text"].encode())
    assert isinstance(busy, kbs_rollback.KbsRateLimited)
    assert isinstance(limited, kbs_rollback.RollbackRefused)
    assert limited.retry_after_s == per_vm["body"]["retry_after_s"]


def test_a_bare_404_is_still_a_missing_route() -> None:
    assert type(kbs_rollback.refusal_error("t", 404, b"")) is KbsRouteMissing


# ── the checkpoint ───────────────────────────────────────────────────


def test_the_checkpoint_parses_and_round_trips_byte_for_byte(
    wire: dict[str, Any], http: Any
) -> None:
    entry = wire["rollback_checkpoint_response"]
    assert entry["status"] == 200
    cp = kbs_rollback.parse_checkpoint(entry["body"], vm_id=wire["vm_id"])
    assert cp.wire() == entry["body"]
    assert _compact(cp.wire()) == entry["body_text"]
    # vali stores `wire()` and parses it back: a fixed point.
    assert kbs_rollback.parse_checkpoint(cp.wire(), vm_id=wire["vm_id"]) == cp
    # And through the route itself.
    fake = http(200, entry["body_text"])
    assert kbs_rollback.fetch_checkpoint(wire["vm_id"]) == cp
    method, url, _ = fake.calls[-1]
    assert (method, url) == (
        "POST",
        f"http://kbs.test:8001/v1/admin/vm/{wire['vm_id']}/rollback-checkpoint",
    )


def test_the_checkpoint_of_another_vm_is_refused(wire: dict[str, Any]) -> None:
    with pytest.raises(ValueError):
        kbs_rollback.parse_checkpoint(
            wire["rollback_checkpoint_response"]["body"], vm_id="another-vm"
        )


# ── the authorize-rollback request vali builds ───────────────────────


def _request_args(wire: dict[str, Any]) -> dict[str, Any]:
    body = wire["authorize_rollback_request"]["body"]
    return {
        "checkpoint_cbor_hex": body["checkpoint_cbor_hex"],
        "signature_hex": body["signature_hex"],
        "manifest_sha256_hex": body["point_manifest_sha256_hex"],
        "manifest": wire["point_manifest_text"].encode("utf-8"),
        "new_gen": body["new_gen"],
        "dest_platform_id_hex": body["dest_platform_id_hex"],
        "restore_id": body["restore_id"],
        "requested_by": body["requested_by"],
        "ttl_s": body["ttl_s"],
    }


def test_the_request_builder_produces_the_fixtures_request_exactly(
    wire: dict[str, Any],
) -> None:
    entry = wire["authorize_rollback_request"]
    built = kbs_rollback.authorize_request_body(**_request_args(wire))
    assert built == entry["body"]
    # Field names, field order, base64 form: the KBS's own bytes.
    assert _compact(built) == entry["body_text"]


def test_the_request_embeds_the_points_manifest_and_its_checkpoint(
    wire: dict[str, Any],
) -> None:
    body = wire["authorize_rollback_request"]["body"]
    manifest = base64.b64decode(body[kbs_rollback.WIRE_MANIFEST_B64], validate=True)
    # Standard alphabet with padding, the exact manifest bytes.
    assert base64.b64encode(manifest).decode() == body[kbs_rollback.WIRE_MANIFEST_B64]
    assert manifest == wire["point_manifest_text"].encode("utf-8")
    assert hashlib.sha256(manifest).hexdigest() == body["point_manifest_sha256_hex"]
    doc = json.loads(manifest)
    checkpoint = wire["rollback_checkpoint_response"]["body"]
    assert doc[kbs_rollback.MANIFEST_CHECKPOINT_KEY] == checkpoint
    assert body["checkpoint_cbor_hex"] == checkpoint["checkpoint_cbor_hex"]
    assert body["signature_hex"] == checkpoint["signature_hex"]
    # vali's own pre-flight accepts exactly this point.
    kbs_rollback.check_point_manifest(
        manifest,
        vm_id=wire["vm_id"],
        sha256_hex=body["point_manifest_sha256_hex"],
        checkpoint_cbor_hex=body["checkpoint_cbor_hex"],
    )


def test_authorize_rollback_sends_the_builders_body_and_reads_the_201_arm(
    wire: dict[str, Any], http: Any
) -> None:
    entry = wire["authorize_rollback_response"]
    assert entry["status"] == 201 and set(entry["body"]) == {"arm"}
    fake = http(201, entry["body_text"])
    # vali mints 32-hex restore ids (the fixture's is illustrative).
    args = {**_request_args(wire), "restore_id": "ab" * 16}
    arm = kbs_rollback.authorize_rollback(wire["vm_id"], **args)
    assert arm == entry["body"]["arm"]
    method, url, sent = fake.calls[-1]
    assert (method, url) == (
        "POST",
        f"http://kbs.test:8001/v1/admin/vm/{wire['vm_id']}/authorize-rollback",
    )
    assert sent == {**wire["authorize_rollback_request"]["body"], "restore_id": "ab" * 16}


# ── GET /rollback ────────────────────────────────────────────────────

ARM_FIELDS = {
    "vm_id": str,
    "restore_id": str,
    "point_manifest_sha256_hex": str,
    "new_gen": int,
    "dest_platform_id_hex": str,
    "from_counter": int,
    "to_stamp": int,
    "armed_at_unix": int,
    "expires_at_unix": int,
    "requested_by": str,
}
LAST_ROLLBACK_FIELDS = {
    "restore_id": str,
    "manifest_sha256_hex": str,
    "from_counter": int,
    "to_counter": int,
    "stamp": int,
    "consumed_at_unix": int,
    "requested_by": str,
    kbs_rollback.WIRE_DELIVERED: bool,
    kbs_rollback.WIRE_REVERTED: bool,
}
LAST_CLEAR_FIELDS = {
    kbs_rollback.WIRE_LAST_CLEAR_RESTORE_ID: str,
    kbs_rollback.WIRE_LAST_CLEAR_REASON: str,
    kbs_rollback.WIRE_LAST_CLEAR_AT: int,
}


def _types(record: dict[str, Any]) -> dict[str, type]:
    return {k: type(v) for k, v in record.items()}


def test_the_rollback_status_parses_every_field(wire: dict[str, Any], http: Any) -> None:
    entry = wire["rollback_status_response"]
    assert entry["status"] == 200
    http(200, entry["body_text"])
    got = kbs_rollback.rollback_status(wire["vm_id"])
    # Every field the KBS sends is one vali reads — nothing more, nothing less.
    assert got == entry["body"]
    assert set(got) == {
        "arm",
        "last_rollback",
        kbs_rollback.WIRE_LAST_CLEAR,
        kbs_rollback.WIRE_ROLLBACK_CAPABLE,
    }
    # The nested records, field for field and typed: vali correlates arms
    # by `restore_id` and rate-limits on `consumed_at_unix`.
    assert _types(got["arm"]) == ARM_FIELDS
    assert _types(got["last_rollback"]) == LAST_ROLLBACK_FIELDS
    assert _types(got[kbs_rollback.WIRE_LAST_CLEAR]) == LAST_CLEAR_FIELDS
    assert _types(wire["authorize_rollback_response"]["body"]["arm"]) == ARM_FIELDS
    last = got["last_rollback"]
    assert last[kbs_rollback.WIRE_DELIVERED] is True
    assert last[kbs_rollback.WIRE_REVERTED] is False
    assert kbs_rollback.delivered(last) and not kbs_rollback.in_flight(last)
    clear = got[kbs_rollback.WIRE_LAST_CLEAR]
    assert set(clear) == {
        kbs_rollback.WIRE_LAST_CLEAR_RESTORE_ID,
        kbs_rollback.WIRE_LAST_CLEAR_REASON,
        kbs_rollback.WIRE_LAST_CLEAR_AT,
    }
    assert not kbs_rollback.cleared_by_boot(clear, clear["restore_id"])  # rollback-disarmed
    assert got[kbs_rollback.WIRE_ROLLBACK_CAPABLE] is True
    assert (
        got["arm"]["restore_id"] == wire["authorize_rollback_response"]["body"]["arm"]["restore_id"]
    )


@pytest.mark.parametrize("capable", ["missing", None, 1, "true"])
def test_a_status_without_a_boolean_rollback_capable_decides_nothing(
    wire: dict[str, Any], http: Any, capable: Any
) -> None:
    body = dict(wire["rollback_status_response"]["body"])
    if capable == "missing":
        del body[kbs_rollback.WIRE_ROLLBACK_CAPABLE]
    else:
        body[kbs_rollback.WIRE_ROLLBACK_CAPABLE] = capable
    http(200, json.dumps(body))
    with pytest.raises(EffectError, match="rollback_capable"):
        kbs_rollback.rollback_status(wire["vm_id"])


def test_the_manifest_travels_in_the_standard_alphabet(wire: dict[str, Any]) -> None:
    """The fixture's manifest happens to encode without `+`, `/`: pin the
    alphabet the KBS decodes (`general_purpose::STANDARD`) on bytes that
    need both, and the padding."""
    body = kbs_rollback.authorize_request_body(**{**_request_args(wire), "manifest": b"\xfb\xff"})
    assert body[kbs_rollback.WIRE_MANIFEST_B64] == "+/8="
