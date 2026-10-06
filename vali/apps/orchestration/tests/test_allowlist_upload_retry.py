"""The allowlist upload sits on the launch path: a transient S3 error
(`SlowDown`, 5xx, throttling) is retried instead of failing the launch as
`allowlist-pin-failure` (#1152). A permanent one fails at once."""

from __future__ import annotations

import subprocess

import pytest
from django.test import override_settings

from apps.orchestration.effects import EffectError
from apps.orchestration.services import allowlist_pin

SLOWDOWN = (
    b"upload failed: dev.cose to s3://hippius-compute-images/allowlist/v1/dev.cose "
    b"An error occurred (SlowDown) when calling the PutObject operation (reached max "
    b"retries: 2): Billing service is temporarily unavailable. Please retry."
)
DENIED = b"upload failed: An error occurred (AccessDenied) when calling the PutObject operation"


def _proc(rc: int, stderr: bytes = b"") -> subprocess.CompletedProcess:
    return subprocess.CompletedProcess(args=[], returncode=rc, stdout=b"", stderr=stderr)


@pytest.fixture
def runs(monkeypatch):
    """Script `_run`'s answers; record the pauses."""
    state: dict = {"answers": [], "calls": 0, "pauses": []}

    def _run(argv, **_kw):
        state["calls"] += 1
        return state["answers"].pop(0)

    monkeypatch.setattr(allowlist_pin, "_run", _run)
    monkeypatch.setattr(allowlist_pin.time, "sleep", state["pauses"].append)
    return state


URL = "https://s3.hippius.com/hippius-compute-images/allowlist/v1/dev.cose"


@override_settings(VALI_S3_ENDPOINT_URL="https://s3.hippius.com")
def test_a_slowdown_is_retried_until_the_upload_lands(runs) -> None:
    runs["answers"] = [_proc(1, SLOWDOWN), _proc(0)]
    allowlist_pin._s3_upload("/tmp/dev.cose", URL)
    assert runs["calls"] == 2
    assert runs["pauses"] == [allowlist_pin.S3_UPLOAD_RETRY_PAUSES_S[0]]


@override_settings(VALI_S3_ENDPOINT_URL="https://s3.hippius.com")
def test_a_transient_error_that_persists_fails_after_the_retries(runs) -> None:
    runs["answers"] = [_proc(1, SLOWDOWN)] * 3
    with pytest.raises(EffectError, match="SlowDown"):
        allowlist_pin._s3_upload("/tmp/dev.cose", URL)
    assert runs["calls"] == 3
    assert runs["pauses"] == list(allowlist_pin.S3_UPLOAD_RETRY_PAUSES_S)


@override_settings(VALI_S3_ENDPOINT_URL="https://s3.hippius.com")
def test_a_permanent_error_fails_at_once(runs) -> None:
    runs["answers"] = [_proc(1, DENIED)]
    with pytest.raises(EffectError, match="AccessDenied"):
        allowlist_pin._s3_upload("/tmp/dev.cose", URL)
    assert runs["calls"] == 1
    assert runs["pauses"] == []


@pytest.mark.parametrize(
    "stderr",
    [
        b"(503) Service Unavailable",
        b"InternalError",
        b"RequestTimeout",
        b"Throttling",
        b'Could not connect to the endpoint URL: "https://s3.hippius.com/..."',
        b"Read timeout on endpoint URL",
        b"Connection was closed before we received a valid response",
    ],
)
def test_the_transient_classes(stderr: bytes) -> None:
    assert allowlist_pin._S3_TRANSIENT.search(stderr.decode())


@override_settings(VALI_S3_ENDPOINT_URL="https://s3.hippius.com")
def test_a_permanent_error_after_a_transient_one_stops_at_once(runs) -> None:
    runs["answers"] = [_proc(1, SLOWDOWN), _proc(1, DENIED)]
    with pytest.raises(EffectError, match="AccessDenied"):
        allowlist_pin._s3_upload("/tmp/dev.cose", URL)
    assert runs["calls"] == 2

