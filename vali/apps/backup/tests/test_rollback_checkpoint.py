"""A2: the KBS rollback checkpoint taken when a backup run completes, and
its client (`apps.orchestration.services.kbs_rollback`).

Claims: a checkpoint is kept only when it describes the run's own boot;
it lands in the manifest and the run stores the manifest's sha256; no KBS
answer ever fails or blocks a backup; a checkpoint whose signed CBOR does
not say what its JSON says is rejected LOUDLY."""

from __future__ import annotations

import base64
import hashlib
import json
import logging
from typing import Any

import pytest

from apps.backup import service
from apps.backup.models import RunStatus
from apps.orchestration import effects
from apps.orchestration.services import kbs_rollback
from apps.storage import s3

from . import test_service as _ts
from .conftest import FakeMiner, make_vm
from .test_service import Clock, _full_done, _incremental_done, _policy

clock = _ts.clock

pytestmark = pytest.mark.django_db


# ── a tiny canonical-CBOR encoder (test side) ────────────────────────


def _head(major: int, n: int) -> bytes:
    if n < 24:
        return bytes([major << 5 | n])
    for info, width in ((24, 1), (25, 2), (26, 4), (27, 8)):
        if n < 1 << (8 * width):
            return bytes([major << 5 | info]) + n.to_bytes(width, "big")
    raise ValueError(n)


def cbor(v: Any) -> bytes:
    if isinstance(v, bool):
        return bytes([0xF5 if v else 0xF4])
    if isinstance(v, int):
        return _head(0, v) if v >= 0 else _head(1, -1 - v)
    if isinstance(v, str):
        raw = v.encode()
        return _head(3, len(raw)) + raw
    if isinstance(v, bytes):
        return _head(2, len(v)) + v
    if isinstance(v, list):
        return _head(4, len(v)) + b"".join(cbor(x) for x in v)
    if isinstance(v, dict):
        return _head(5, len(v)) + b"".join(cbor(k) + cbor(x) for k, x in v.items())
    raise TypeError(v)


TIMELINE_HEX = "5c" * 32


def _body(vm_id: str, counter: int, *, v1: bool = False, **over: Any) -> dict[str, Any]:
    """A KBS checkpoint response: V2 (every checkpoint the KBS signs now)
    unless `v1`, the shape backups taken before V2 carry."""
    cp: dict[str, Any] = {
        "domain": kbs_rollback.CHECKPOINT_DOMAIN if v1 else kbs_rollback.CHECKPOINT_DOMAIN_V2,
        "vm_id": vm_id,
        "boot_counter": counter,
        "volume_stamp": 4,
    }
    if not v1:
        cp[kbs_rollback.WIRE_CHECKPOINT_TIMELINE] = TIMELINE_HEX
    cp.update({"unconfirmed_releases": 0, "generation": 1, "issued_at_unix": 1_760_000_000})
    default_signed = dict(cp)
    if not v1:
        del default_signed[kbs_rollback.WIRE_CHECKPOINT_TIMELINE]
        default_signed["volume_stamp_timeline_id"] = bytes.fromhex(TIMELINE_HEX)
    signed = over.pop("signed", default_signed)
    return {
        "checkpoint": cp,
        "checkpoint_cbor_hex": cbor(signed).hex(),
        "signature_hex": "ab" * 64,
        "signer_pubkey_hex": "cd" * 32,
        **over,
    }


class FakeKbsHttp:
    """`effects._http` for the KBS admin routes: answers per path."""

    def __init__(self) -> None:
        self.answers: dict[str, tuple[int, bytes]] = {}
        self.calls: list[tuple[str, str, Any]] = []

    def __call__(self, method: str, url: str, **kw: Any) -> tuple[int, bytes]:
        self.calls.append((method, url, kw.get("json_body")))
        for suffix, answer in self.answers.items():
            if url.endswith(suffix):
                return answer
        return 404, b""


@pytest.fixture
def kbs_http(monkeypatch: pytest.MonkeyPatch, settings) -> FakeKbsHttp:
    settings.VALI_KBS_ADMIN_URL = "http://kbs.test:8001"
    fake = FakeKbsHttp()
    monkeypatch.setattr(effects, "_http", fake)
    service._CHECKPOINT_LOGGED.clear()
    return fake


@pytest.fixture
def caplog(caplog: pytest.LogCaptureFixture):  # noqa: F811 — `apps` does not propagate
    logger = logging.getLogger("apps")
    logger.addHandler(caplog.handler)
    try:
        yield caplog
    finally:
        logger.removeHandler(caplog.handler)


def _ok(body: dict[str, Any]) -> tuple[int, bytes]:
    return 200, json.dumps(body).encode()


# ── the checkpoint on a completed run ────────────────────────────────


def test_a_checkpoint_of_the_runs_boot_is_kept_and_in_the_manifest(
    clock: Clock, fake_miner: FakeMiner, mock_s3: s3.MockHippiusS3Client, kbs_http: FakeKbsHttp
) -> None:
    vm = make_vm()
    _policy(vm)
    kbs_http.answers["/rollback-checkpoint"] = _ok(_body("vm-1", fake_miner.boot_counter))
    run = _full_done(clock, fake_miner)
    assert run.kbs_checkpoint["checkpoint"]["boot_counter"] == fake_miner.boot_counter
    assert service.checkpoint_of(run) is not None
    stored = mock_s3.get_object(bucket="vm-backups", key=run.manifest_key, max_bytes=1 << 20)
    assert hashlib.sha256(stored).hexdigest() == run.manifest_sha256
    manifest = json.loads(stored)
    assert manifest["kbs_rollback_checkpoint"] == run.kbs_checkpoint
    assert ("POST", "http://kbs.test:8001/v1/admin/vm/vm-1/rollback-checkpoint", {}) in (
        kbs_http.calls
    )


def test_a_checkpoint_of_another_boot_is_dropped(
    clock: Clock, fake_miner: FakeMiner, mock_s3: s3.MockHippiusS3Client, kbs_http: FakeKbsHttp
) -> None:
    """The guest rebooted between the snapshot and the completion: the KBS
    counter is one higher than the run's."""
    vm = make_vm()
    _policy(vm)
    kbs_http.answers["/rollback-checkpoint"] = _ok(_body("vm-1", fake_miner.boot_counter + 1))
    run = _full_done(clock, fake_miner)
    assert run.status == RunStatus.DONE
    assert run.kbs_checkpoint is None and service.checkpoint_of(run) is None
    stored = mock_s3.get_object(bucket="vm-backups", key=run.manifest_key, max_bytes=1 << 20)
    assert json.loads(stored)["kbs_rollback_checkpoint"] is None
    assert hashlib.sha256(stored).hexdigest() == run.manifest_sha256


@pytest.mark.parametrize(
    "answer",
    [
        (404, b""),  # a KBS without the route
        (404, cbor({"reason": "no-vm-row"})),
        (409, cbor({"reason": "no-boot-counter"})),
        (500, b"boom"),
        (200, b"not json"),
    ],
)
def test_no_kbs_answer_ever_fails_the_backup(
    clock: Clock,
    fake_miner: FakeMiner,
    mock_s3: s3.MockHippiusS3Client,
    kbs_http: FakeKbsHttp,
    answer,
) -> None:
    vm = make_vm()
    _policy(vm)
    kbs_http.answers["/rollback-checkpoint"] = answer
    run = _full_done(clock, fake_miner)
    assert run.status == RunStatus.DONE and run.kbs_checkpoint is None
    assert len(run.manifest_sha256) == 64
    assert service.restore_point(vm) is not None


def test_an_unconfigured_kbs_never_fails_the_backup(
    clock: Clock, fake_miner: FakeMiner, mock_s3: s3.MockHippiusS3Client, settings
) -> None:
    settings.VALI_KBS_ADMIN_URL = ""
    vm = make_vm()
    _policy(vm)
    run = _full_done(clock, fake_miner)
    assert run.status == RunStatus.DONE and run.kbs_checkpoint is None


def test_a_missing_route_is_logged_once_not_per_run(
    clock: Clock,
    fake_miner: FakeMiner,
    mock_s3: s3.MockHippiusS3Client,
    kbs_http: FakeKbsHttp,
    caplog,
) -> None:
    vm = make_vm()
    _policy(vm)
    with caplog.at_level(logging.INFO, logger="apps.backup"):
        _full_done(clock, fake_miner)
        _incremental_done(clock, fake_miner)
        _incremental_done(clock, fake_miner)
    said = [r for r in caplog.records if "rollback-checkpoint route" in r.getMessage()]
    assert len(said) == 1 and said[0].levelno == logging.INFO


@pytest.mark.parametrize(
    "signed",
    [
        pytest.param("array", id="cbor-array"),
        pytest.param("int-keys", id="cbor-integer-keys"),
        pytest.param("disagrees", id="cbor-says-another-counter"),
    ],
)
def test_a_checkpoint_whose_cbor_does_not_match_is_rejected_loudly(
    clock: Clock,
    fake_miner: FakeMiner,
    mock_s3: s3.MockHippiusS3Client,
    kbs_http: FakeKbsHttp,
    caplog,
    signed: str,
) -> None:
    """C-4 drift between vali and the KBS must never be a silent "no
    checkpoint": it is rejected, and said at ERROR on every run."""
    vm = make_vm()
    _policy(vm)
    good = _body("vm-1", fake_miner.boot_counter)["checkpoint"]
    shape: Any = {
        "array": list(good.values()),
        "int-keys": {i: v for i, v in enumerate(good.values())},
        "disagrees": {**good, "boot_counter": good["boot_counter"] - 1},
    }[signed]
    kbs_http.answers["/rollback-checkpoint"] = _ok(
        _body("vm-1", fake_miner.boot_counter, signed=shape)
    )
    with caplog.at_level(logging.INFO, logger="apps.backup"):
        run = _full_done(clock, fake_miner)
        _incremental_done(clock, fake_miner)
    assert run.status == RunStatus.DONE and run.kbs_checkpoint is None
    errors = [
        r for r in caplog.records if r.levelno == logging.ERROR and "REJECTED" in r.getMessage()
    ]
    assert len(errors) == 2, "at ERROR, on every run"


# ── the client ──────────────────────────────────────────────────────


def test_parse_checkpoint_accepts_the_contract_shape() -> None:
    cp = kbs_rollback.parse_checkpoint(_body("vm-1", 3), vm_id="vm-1")
    assert (cp.boot_counter, cp.volume_stamp, cp.generation) == (3, 4, 1)
    assert cp.wire()["checkpoint_cbor_hex"] == _body("vm-1", 3)["checkpoint_cbor_hex"]


@pytest.mark.parametrize(
    ("mutate", "why"),
    [
        (lambda b: b["checkpoint"].update(vm_id="vm-2"), "another vm"),
        (lambda b: b["checkpoint"].update(domain="X"), "domain"),
        (lambda b: b["checkpoint"].update(boot_counter=-1), "non-negative"),
        (lambda b: b["checkpoint"].update(boot_counter=0), ">= 1"),
        (lambda b: b.update(signature_hex="XYZ"), "hex"),
        (lambda b: b.update(checkpoint_cbor_hex="ff"), "not canonical CBOR"),
        (lambda b: b.update(signature_hex="ab" * 63), "right length"),
        (lambda b: b.update(signer_pubkey_hex="cd" * 33), "right length"),
        (lambda b: b.update(checkpoint_cbor_hex=cbor({"a": 1}).hex()), "disagrees"),
    ],
)
def test_parse_checkpoint_refuses_anything_else(mutate, why) -> None:
    body = _body("vm-1", 3)
    mutate(body)
    with pytest.raises(ValueError, match=why):
        kbs_rollback.parse_checkpoint(body, vm_id="vm-1")


def _signed(**over: Any) -> dict[str, Any]:
    return {**_body("vm-1", 3)["checkpoint"], **over}


@pytest.mark.parametrize(
    ("raw", "why"),
    [
        # boot_counter 3 as a one-byte argument (0x18 0x03): not the shortest form.
        (
            cbor(_signed()).replace(
                cbor("boot_counter") + b"\x03", cbor("boot_counter") + b"\x18\x03"
            ),
            "canonical",
        ),
        (b"\xc0" + cbor(_signed()), "canonical"),  # a tag around the map
        (cbor({**_signed(), "extra": 1}), "field set"),
    ],
)
def test_the_signed_checkpoint_must_be_canonical_and_exact(raw: bytes, why: str) -> None:
    body = _body("vm-1", 3)
    body["checkpoint_cbor_hex"] = raw.hex()
    with pytest.raises(ValueError, match=why):
        kbs_rollback.parse_checkpoint(body, vm_id="vm-1")


def test_decode_cbor_reads_the_kbs_error_body() -> None:
    assert kbs_rollback.decode_cbor(cbor({"reason": "arm-exists", "vm_id": "vm-1"})) == {
        "reason": "arm-exists",
        "vm_id": "vm-1",
    }
    for bad in (b"", b"\xa1", b"\x9f\xff", cbor([1]) + b"\x00"):
        with pytest.raises(kbs_rollback.CborError):
            kbs_rollback.decode_cbor(bad)


#: A point's manifest.json bytes embedding the checkpoint `a0`, and their sha.
_POINT = json.dumps(
    {"vm_id": "vm-1", "kbs_rollback_checkpoint": {"checkpoint_cbor_hex": "a0"}}
).encode()
_POINT_SHA = hashlib.sha256(_POINT).hexdigest()
_OTHER_POINT = json.dumps(
    {"vm_id": "vm-1", "kbs_rollback_checkpoint": {"checkpoint_cbor_hex": "a1"}}
).encode()


@pytest.mark.parametrize("encode", [cbor, lambda d: json.dumps(d).encode()])
def test_a_refusal_carries_its_reason_and_retry_after(kbs_http: FakeKbsHttp, encode) -> None:
    kbs_http.answers["/authorize-rollback"] = (
        429,
        encode({"reason": "rollback-rate-limited", "retry_after_s": 120}),
    )
    with pytest.raises(kbs_rollback.RollbackRefused) as exc:
        kbs_rollback.authorize_rollback(
            "vm-1",
            checkpoint_cbor_hex="a0",
            signature_hex="aa",
            manifest_sha256_hex=_POINT_SHA,
            manifest=_POINT,
            new_gen=6,
            dest_platform_id_hex="22" * 64,
            restore_id="ab" * 16,
            requested_by="tenant:u",
        )
    assert (exc.value.status, exc.value.reason, exc.value.retry_after_s) == (
        429,
        "rollback-rate-limited",
        120,
    )


def test_the_arm_request_is_the_c4_body(kbs_http: FakeKbsHttp) -> None:
    kbs_http.answers["/authorize-rollback"] = (201, json.dumps({"arm": {"x": 1}}).encode())
    assert kbs_rollback.authorize_rollback(
        "vm-1",
        checkpoint_cbor_hex="a0",
        signature_hex="aa",
        manifest_sha256_hex=_POINT_SHA,
        manifest=_POINT,
        new_gen=6,
        dest_platform_id_hex="22" * 64,
        restore_id="ab" * 16,
        requested_by="tenant:u",
    ) == {"x": 1}
    method, url, body = kbs_http.calls[-1]
    assert (method, url) == ("POST", "http://kbs.test:8001/v1/admin/vm/vm-1/authorize-rollback")
    assert body == {
        "checkpoint_cbor_hex": "a0",
        "signature_hex": "aa",
        "point_manifest_sha256_hex": _POINT_SHA,
        "point_manifest_b64": base64.b64encode(_POINT).decode(),
        "new_gen": 6,
        "dest_platform_id_hex": "22" * 64,
        "restore_id": "ab" * 16,
        "ttl_s": 3600,
        "requested_by": "tenant:u",
    }


def test_a_bare_404_is_a_missing_route_a_reasoned_one_a_refusal(kbs_http: FakeKbsHttp) -> None:
    with pytest.raises(effects.KbsRouteMissing):
        kbs_rollback.rollback_status("vm-1")
    kbs_http.answers["/rollback"] = (404, cbor({"reason": "no-vm-row"}))
    with pytest.raises(kbs_rollback.RollbackRefused) as exc:
        kbs_rollback.rollback_status("vm-1")
    assert exc.value.reason == "no-vm-row"


def test_disarm_is_idempotent(kbs_http: FakeKbsHttp) -> None:
    kbs_http.answers["/authorize-rollback/" + "ab" * 16] = (204, b"")
    kbs_rollback.disarm("vm-1", "ab" * 16)
    assert kbs_http.calls[-1][:2] == (
        "DELETE",
        "http://kbs.test:8001/v1/admin/vm/vm-1/authorize-rollback/" + "ab" * 16,
    )
    kbs_http.answers.clear()
    kbs_rollback.disarm("vm-1", "ab" * 16)  # a KBS without the route has no arms
    kbs_http.answers["/authorize-rollback/" + "ab" * 16] = (503, b"")
    with pytest.raises(effects.EffectError):
        kbs_rollback.disarm("vm-1", "ab" * 16)


# ── security review: unstamped checkpoints, manifest bytes, refusals ──


def test_an_unstamped_checkpoint_is_not_kept(
    clock: Clock, fake_miner: FakeMiner, mock_s3: s3.MockHippiusS3Client, kbs_http: FakeKbsHttp
) -> None:
    """`volume_stamp == 0`: the KBS refuses to arm it (`checkpoint-unstamped`),
    so the run is not rollback-capable."""
    vm = make_vm()
    _policy(vm)
    body = _body("vm-1", fake_miner.boot_counter)
    body["checkpoint"]["volume_stamp"] = 0
    body["checkpoint_cbor_hex"] = cbor(body["checkpoint"]).hex()
    kbs_http.answers["/rollback-checkpoint"] = _ok(body)
    run = _full_done(clock, fake_miner)
    assert run.status == RunStatus.DONE
    assert run.kbs_checkpoint is None and service.checkpoint_of(run) is None


def test_the_run_keeps_the_exact_manifest_bytes(
    clock: Clock, fake_miner: FakeMiner, mock_s3: s3.MockHippiusS3Client, kbs_http: FakeKbsHttp
) -> None:
    vm = make_vm()
    _policy(vm)
    kbs_http.answers["/rollback-checkpoint"] = _ok(_body("vm-1", fake_miner.boot_counter))
    run = _full_done(clock, fake_miner)
    stored = mock_s3.get_object(bucket="vm-backups", key=run.manifest_key, max_bytes=1 << 20)
    assert run.manifest_json.encode("utf-8") == stored
    assert kbs_rollback.manifest_checkpoint_cbor_hex(stored) == (
        run.kbs_checkpoint["checkpoint_cbor_hex"]
    )


@pytest.mark.parametrize(
    "tamper",
    [
        lambda run: {"manifest_json": ""},  # bytes not kept
        lambda run: {"manifest_json": run.manifest_json + " "},  # not the hashed bytes
        lambda run: {  # hashes right but embeds another checkpoint
            "manifest_json": _OTHER_POINT.decode(),
            "manifest_sha256": hashlib.sha256(_OTHER_POINT).hexdigest(),
        },
        lambda run: {  # a stored checkpoint claiming stamp 0
            "kbs_checkpoint": {
                **run.kbs_checkpoint,
                "checkpoint": {**run.kbs_checkpoint["checkpoint"], "volume_stamp": 0},
            }
        },
        lambda run: {  # a stored checkpoint that is V1 (no timeline)
            "kbs_checkpoint": {
                **run.kbs_checkpoint,
                "checkpoint": {
                    **run.kbs_checkpoint["checkpoint"],
                    "domain": kbs_rollback.CHECKPOINT_DOMAIN,
                },
            }
        },
    ],
)
def test_checkpoint_of_needs_a_stamped_checkpoint_in_the_hashed_manifest(
    clock: Clock,
    fake_miner: FakeMiner,
    mock_s3: s3.MockHippiusS3Client,
    kbs_http: FakeKbsHttp,
    tamper,
) -> None:
    from apps.backup.models import BackupRun

    vm = make_vm()
    _policy(vm)
    kbs_http.answers["/rollback-checkpoint"] = _ok(_body("vm-1", fake_miner.boot_counter))
    run = _full_done(clock, fake_miner)
    assert service.checkpoint_of(run) is not None
    BackupRun.objects.filter(pk=run.pk).update(**tamper(run))
    run.refresh_from_db()
    assert service.checkpoint_of(run) is None


def test_a_manifest_that_does_not_bind_the_checkpoint_is_never_sent(
    kbs_http: FakeKbsHttp,
) -> None:
    big = json.dumps(
        {
            "vm_id": "vm-1",
            "kbs_rollback_checkpoint": {"checkpoint_cbor_hex": "a0"},
            "pad": "x" * kbs_rollback.MAX_POINT_MANIFEST_BYTES,
        }
    ).encode()
    other_vm = json.dumps(
        {"vm_id": "vm-2", "kbs_rollback_checkpoint": {"checkpoint_cbor_hex": "a0"}}
    ).encode()
    for manifest, sha in (
        (_POINT, "e" * 64),  # not its sha
        (b"{}", hashlib.sha256(b"{}").hexdigest()),  # embeds no checkpoint
        (b"", hashlib.sha256(b"").hexdigest()),  # empty
        (big, hashlib.sha256(big).hexdigest()),  # past the KBS's 256 KiB bound
        (other_vm, hashlib.sha256(other_vm).hexdigest()),  # names another vm
    ):
        with pytest.raises(kbs_rollback.PointManifestInvalid):
            kbs_rollback.authorize_rollback(
                "vm-1",
                checkpoint_cbor_hex="a0",
                signature_hex="aa",
                manifest_sha256_hex=sha,
                manifest=manifest,
                new_gen=6,
                dest_platform_id_hex="22" * 64,
                restore_id="ab" * 16,
                requested_by="tenant:u",
            )
    assert kbs_http.calls == []


def _arm_call() -> dict[str, Any]:
    return kbs_rollback.authorize_rollback(
        "vm-1",
        checkpoint_cbor_hex="a0",
        signature_hex="aa",
        manifest_sha256_hex=_POINT_SHA,
        manifest=_POINT,
        new_gen=6,
        dest_platform_id_hex="22" * 64,
        restore_id="ab" * 16,
        requested_by="tenant:u",
    )


def test_the_gateway_limiter_is_retryable_the_per_vm_limit_is_not(
    kbs_http: FakeKbsHttp,
) -> None:
    kbs_http.answers["/authorize-rollback"] = (
        429,
        cbor({"reason": "rate-limited", "vm_id": "vm-1", "retry_after_s": 1}),
    )
    with pytest.raises(kbs_rollback.KbsRateLimited) as busy:
        _arm_call()
    assert busy.value.retry_after_s == 1
    assert not isinstance(busy.value, kbs_rollback.RollbackRefused)
    kbs_http.answers["/authorize-rollback"] = (
        429,
        cbor({"reason": "rollback-rate-limited", "retry_after_s": 900}),
    )
    with pytest.raises(kbs_rollback.RollbackRefused) as limited:
        _arm_call()
    assert (limited.value.reason, limited.value.retry_after_s) == ("rollback-rate-limited", 900)


@pytest.mark.parametrize(
    "call",
    [
        _arm_call,
        lambda: kbs_rollback.rollback_status("vm-1"),
        lambda: kbs_rollback.fetch_checkpoint("vm-1"),
    ],
)
def test_rollback_unavailable_is_a_missing_route_other_503s_are_not(
    kbs_http: FakeKbsHttp, call
) -> None:
    for path in ("/authorize-rollback", "/rollback", "/rollback-checkpoint"):
        kbs_http.answers[path] = (503, cbor({"reason": "rollback-unavailable"}))
    with pytest.raises(kbs_rollback.RollbackUnavailable) as exc:
        call()
    assert isinstance(exc.value, effects.KbsRouteMissing)
    for path in ("/authorize-rollback", "/rollback", "/rollback-checkpoint"):
        kbs_http.answers[path] = (503, b"upstream")
    with pytest.raises(effects.EffectError) as other:
        call()
    assert not isinstance(other.value, effects.KbsRouteMissing)


def test_the_disarm_treats_rollback_unavailable_as_no_arm(kbs_http: FakeKbsHttp) -> None:
    kbs_http.answers["/authorize-rollback/" + "ab" * 16] = (
        503,
        cbor({"reason": "rollback-unavailable"}),
    )
    kbs_rollback.disarm("vm-1", "ab" * 16)


_LAST = {
    "reverted": False,
    "restore_id": "ab" * 16,
    "manifest_sha256_hex": "d" * 64,
    "from_counter": 3,
    "to_counter": 8,
    "stamp": 2,
    "consumed_at_unix": 1,
    "requested_by": "tenant:u",
}


def test_the_rollback_status_says_delivered_and_last_clear(kbs_http: FakeKbsHttp) -> None:
    # The KBS's own JSON (`AdminRollbackStatusResponse`), field for field.
    clear = {"restore_id": "cd" * 16, "reason": "rollback-cleared-by-boot", "at": 50}
    kbs_http.answers["/rollback"] = _ok(
        {
            "arm": None,
            "last_rollback": {**_LAST, "delivered": True},
            "last_clear": clear,
            "rollback_capable": True,
        }
    )
    got = kbs_rollback.rollback_status("vm-1")
    assert kbs_rollback.delivered(got["last_rollback"])
    assert not kbs_rollback.in_flight(got["last_rollback"])
    assert got["last_clear"] == clear
    assert kbs_rollback.cleared_by_boot(got["last_clear"], "cd" * 16)
    assert not kbs_rollback.cleared_by_boot(got["last_clear"], "ab" * 16)
    assert not kbs_rollback.cleared_by_boot({**clear, "reason": "rollback-expired"}, "cd" * 16)
    assert not kbs_rollback.delivered({**_LAST, "delivered": False})
    assert kbs_rollback.in_flight({**_LAST, "delivered": False})
    assert not kbs_rollback.in_flight({**_LAST, "delivered": False, "reverted": True})
    assert not kbs_rollback.delivered({**_LAST, "delivered": True, "reverted": True})
    assert not kbs_rollback.delivered(None)


_NO_REVERTED = {k: v for k, v in {**_LAST, "delivered": True}.items() if k != "reverted"}


@pytest.mark.parametrize(
    "body",
    [
        {"arm": None, "last_rollback": dict(_LAST)},  # delivered missing: never "no"
        {"arm": None, "last_rollback": {**_LAST, "delivered": "yes"}},
        {"arm": {"vm_id": "vm-1"}, "last_rollback": None},  # an arm without its id
        {"arm": "x", "last_rollback": None},
        {
            "arm": None,
            "last_rollback": {
                k: v for k, v in {**_LAST, "delivered": True}.items() if k != "restore_id"
            },
        },
        {"arm": None, "last_rollback": {**_LAST, "delivered": True, "consumed_at_unix": True}},
        {"arm": None, "last_rollback": {**_LAST, "delivered": True, "consumed_at_unix": "1"}},
        {"arm": None, "last_rollback": {**_LAST, "delivered": True, "reverted": 1}},
        {"arm": None, "last_rollback": _NO_REVERTED},  # reverted missing
        {"arm": None, "last_rollback": None, "last_clear": {"restore_id": "x", "reason": "x"}},
        {
            "arm": None,
            "last_rollback": None,
            "last_clear": {"restore_id": "x", "reason": "x", "at": True},
        },
        {"arm": None, "last_rollback": None, "last_clear": {"reason": "x", "at": 1}},
        {"arm": None, "last_rollback": None, "last_clear": "x"},
    ],
)
def test_an_off_shape_rollback_status_decides_nothing(kbs_http: FakeKbsHttp, body) -> None:
    # A well-formed `rollback_capable`: each body is off-shape for ONE reason.
    kbs_http.answers["/rollback"] = _ok({**body, "rollback_capable": True})
    with pytest.raises(effects.EffectError):
        kbs_rollback.rollback_status("vm-1")


def test_a_v1_checkpoint_is_kept_but_never_makes_the_run_rollback_restorable(
    clock: Clock, fake_miner: FakeMiner, mock_s3: s3.MockHippiusS3Client, kbs_http: FakeKbsHttp
) -> None:
    """A KBS that still signs V1 checkpoints (before stamp protocol v2):
    the checkpoint parses and is kept (it is a true statement), but it
    names no volume-stamp timeline, so the KBS would refuse to arm it
    (`checkpoint-not-timeline-bound`) — refused at intake instead, before a
    VM is stopped for a restore that cannot happen."""
    vm = make_vm()
    _policy(vm)
    kbs_http.answers["/rollback-checkpoint"] = _ok(
        _body("vm-1", fake_miner.boot_counter, v1=True)
    )
    run = _full_done(clock, fake_miner)
    assert run.kbs_checkpoint["checkpoint"]["domain"] == kbs_rollback.CHECKPOINT_DOMAIN
    assert service.checkpoint_of(run) is None
