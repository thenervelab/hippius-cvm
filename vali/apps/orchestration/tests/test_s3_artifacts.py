"""Launch-path S3 reads: the sha-keyed artifact cache and the transient-
error retry (`apps.orchestration.services.s3_artifacts`).

The 2026-09-26 synthetic launch died on one `SlowDown` fetching the
pinned OVMF for the C2 recompute. These pin that such an error is
retried, that the pinned artifacts are fetched once per pod, and that the
cache can never hand out bytes that do not match the pin."""

from __future__ import annotations

import hashlib
import os
import subprocess
from pathlib import Path

import pytest
from django.conf import settings

from apps.orchestration.effects import EffectError, EffectUnavailable
from apps.orchestration.services import launch_digest as ld
from apps.orchestration.services import s3_artifacts

OVMF = b"OVMF-bytes" * 100
OVMF_SHA = hashlib.sha256(OVMF).hexdigest()
URI = "s3://hippius-compute-images/ovmf/snp-ovmf.fd"
SLOWDOWN = (
    "download failed: s3://hippius-compute-images/ovmf/snp-ovmf-162aa41b.fd to "
    "../tmp/c2-digest-1ntpu9_d/ovmf.fd An error occurred (SlowDown) when calling the "
    "GetObject operation (reached max retries: 2): Object not ready for download yet. "
    "Please retry."
)


@pytest.fixture(autouse=True)
def cache(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Path:
    root = tmp_path / "cache"
    monkeypatch.setattr(settings, "VALI_ARTIFACT_CACHE_DIR", str(root))
    return root


class Fetcher:
    """An `_s3_cp` stand-in that counts calls and writes `payload`."""

    def __init__(self, payload: bytes = OVMF) -> None:
        self.payload = payload
        self.calls = 0

    def __call__(self, uri: str, dest: Path) -> None:
        self.calls += 1
        dest.write_bytes(self.payload)


# ── cache ────────────────────────────────────────────────────────────


def test_the_pinned_artifact_is_fetched_once_then_served_from_the_cache(tmp_path, cache) -> None:
    fetch = Fetcher()
    for i in range(3):
        dest = tmp_path / f"ovmf-{i}.fd"
        s3_artifacts.fetch_verified(URI, dest, OVMF_SHA, "ovmf", fetch=fetch)
        assert dest.read_bytes() == OVMF
    assert fetch.calls == 1
    assert (cache / OVMF_SHA).read_bytes() == OVMF


def test_a_corrupt_cache_entry_is_never_served_and_is_replaced(tmp_path, cache) -> None:
    cache.mkdir(parents=True)
    (cache / OVMF_SHA).write_bytes(b"tampered")
    fetch = Fetcher()
    dest = tmp_path / "ovmf.fd"
    s3_artifacts.fetch_verified(URI, dest, OVMF_SHA, "ovmf", fetch=fetch)
    assert dest.read_bytes() == OVMF
    assert fetch.calls == 1
    assert (cache / OVMF_SHA).read_bytes() == OVMF


def test_a_fetch_that_does_not_match_the_pin_fails_and_caches_nothing(tmp_path, cache) -> None:
    fetch = Fetcher(payload=b"something else")
    with pytest.raises(EffectError, match="ovmf-sha-mismatch"):
        s3_artifacts.fetch_verified(URI, tmp_path / "ovmf.fd", OVMF_SHA, "ovmf", fetch=fetch)
    assert not (cache / OVMF_SHA).exists()
    assert list(cache.iterdir()) == []  # no download directory left behind


def test_the_entry_is_reverified_on_every_load(tmp_path, cache) -> None:
    fetch = Fetcher()
    s3_artifacts.fetch_verified(URI, tmp_path / "a", OVMF_SHA, "ovmf", fetch=fetch)
    # Corrupt the entry after it was installed: the next load must notice.
    (cache / OVMF_SHA).write_bytes(b"flipped after install")
    s3_artifacts.fetch_verified(URI, tmp_path / "b", OVMF_SHA, "ovmf", fetch=fetch)
    assert (tmp_path / "b").read_bytes() == OVMF
    assert fetch.calls == 2


def test_a_cache_dir_that_cannot_be_created_degrades_to_a_verified_direct_fetch(
    monkeypatch, tmp_path
) -> None:
    blocker = tmp_path / "not-a-dir"
    blocker.write_bytes(b"")
    monkeypatch.setattr(settings, "VALI_ARTIFACT_CACHE_DIR", str(blocker / "cache"))
    dest = tmp_path / "ovmf.fd"
    s3_artifacts.fetch_verified(URI, dest, OVMF_SHA, "ovmf", fetch=Fetcher())
    assert dest.read_bytes() == OVMF
    with pytest.raises(EffectError, match="ovmf-sha-mismatch"):
        s3_artifacts.fetch_verified(URI, dest, OVMF_SHA, "ovmf", fetch=Fetcher(b"bad"))


def test_a_malformed_pin_is_refused_before_any_fetch(tmp_path) -> None:
    fetch = Fetcher()
    with pytest.raises(EffectError, match="ovmf-sha-invalid"):
        s3_artifacts.fetch_verified(URI, tmp_path / "x", "../../etc/passwd", "ovmf", fetch=fetch)
    assert fetch.calls == 0


def test_the_cache_evicts_least_recently_used_entries_to_its_cap(
    monkeypatch, tmp_path, cache
) -> None:
    monkeypatch.setattr(settings, "VALI_ARTIFACT_CACHE_MAX_BYTES", 2500)
    blobs = [bytes([i]) * 1000 for i in range(3)]
    shas = [hashlib.sha256(b).hexdigest() for b in blobs]
    for i, (blob, sha) in enumerate(zip(blobs, shas, strict=True)):
        s3_artifacts.fetch_verified(URI, tmp_path / f"d{i}", sha, "x", fetch=Fetcher(blob))
        os.utime(cache / sha, (1000 + i, 1000 + i))
    # 3 000 bytes > 2 500: the oldest entry went, the newest two stayed.
    assert not (cache / shas[0]).exists()
    assert (cache / shas[1]).exists() and (cache / shas[2]).exists()


# ── retry ────────────────────────────────────────────────────────────


@pytest.fixture
def aws(monkeypatch):
    """Script `aws s3 cp` answers; record the pauses."""
    state: dict = {"answers": [], "calls": 0, "pauses": []}

    def _run(argv, **_kw):
        state["calls"] += 1
        answer = state["answers"].pop(0)
        if isinstance(answer, BaseException):
            raise answer
        rc, stderr = answer
        if rc == 0:
            Path(argv[-1]).write_bytes(OVMF)
        return subprocess.CompletedProcess(argv, rc, stdout=b"", stderr=stderr.encode())

    monkeypatch.setattr(ld.subprocess, "run", _run)
    monkeypatch.setattr(s3_artifacts.time, "sleep", state["pauses"].append)
    return state


def test_a_slowdown_on_the_ovmf_fetch_is_retried(aws, tmp_path) -> None:
    aws["answers"] = [(1, SLOWDOWN), (0, "")]
    ld._s3_cp(URI, tmp_path / "ovmf.fd")
    assert aws["calls"] == 2
    assert aws["pauses"] == [s3_artifacts.RETRY_PAUSES_S[0]]


def test_a_timeout_is_transient_too(aws, tmp_path) -> None:
    aws["answers"] = [subprocess.TimeoutExpired(cmd="aws", timeout=120), (0, "")]
    ld._s3_cp(URI, tmp_path / "ovmf.fd")
    assert aws["calls"] == 2


def test_a_transient_error_that_persists_fails_after_the_retries(aws, tmp_path) -> None:
    aws["answers"] = [(1, SLOWDOWN)] * 3
    with pytest.raises(EffectError, match="SlowDown"):
        ld._s3_cp(URI, tmp_path / "ovmf.fd")
    assert aws["calls"] == 3
    assert aws["pauses"] == list(s3_artifacts.RETRY_PAUSES_S)


def test_a_permanent_error_fails_at_once(aws, tmp_path) -> None:
    aws["answers"] = [
        (1, "fatal error: An error occurred (404) when calling the HeadObject operation: Not Found")
    ]
    with pytest.raises(EffectError, match="404"):
        ld._s3_cp(URI, tmp_path / "ovmf.fd")
    assert aws["calls"] == 1
    assert aws["pauses"] == []


def test_a_missing_aws_binary_is_unavailable_not_retried(aws, tmp_path) -> None:
    aws["answers"] = [FileNotFoundError("aws")]
    with pytest.raises(EffectUnavailable):
        ld._s3_cp(URI, tmp_path / "ovmf.fd")
    assert aws["calls"] == 1


def test_upload_and_download_share_one_definition_of_transient() -> None:
    from apps.orchestration.services import allowlist_pin

    assert allowlist_pin._S3_TRANSIENT is s3_artifacts.TRANSIENT_S3_ERROR
    assert s3_artifacts.is_transient(SLOWDOWN)


# ── review follow-ups ────────────────────────────────────────────────


@pytest.mark.skipif(os.geteuid() == 0, reason="root ignores directory permissions")
def test_an_existing_but_unwritable_cache_degrades_to_a_direct_fetch(tmp_path, cache) -> None:
    cache.mkdir(parents=True)
    cache.chmod(0o500)
    try:
        dest = tmp_path / "ovmf.fd"
        s3_artifacts.fetch_verified(URI, dest, OVMF_SHA, "ovmf", fetch=Fetcher())
        assert dest.read_bytes() == OVMF
    finally:
        cache.chmod(0o700)


def test_an_entry_evicted_right_after_install_does_not_fail_the_load(
    monkeypatch, tmp_path, cache
) -> None:
    # Another process's eviction removes the fresh entry before this call
    # would have re-read it: `dest` is filled from the verified download.
    monkeypatch.setattr(
        s3_artifacts, "_evict", lambda root, keep: keep.unlink(missing_ok=True)
    )
    dest = tmp_path / "ovmf.fd"
    s3_artifacts.fetch_verified(URI, dest, OVMF_SHA, "ovmf", fetch=Fetcher())
    assert dest.read_bytes() == OVMF


def test_a_failed_fetch_leaves_neither_an_entry_nor_a_temp_file(tmp_path, cache) -> None:
    def failing(uri: str, dest: Path) -> None:
        dest.write_bytes(b"partial")
        raise EffectError("aws-s3-cp: exit=1 stderr='AccessDenied'")

    with pytest.raises(EffectError, match="AccessDenied"):
        s3_artifacts.fetch_verified(URI, tmp_path / "x", OVMF_SHA, "ovmf", fetch=failing)
    assert list(cache.iterdir()) == []


def test_stale_download_leftovers_are_swept(tmp_path, cache) -> None:
    cache.mkdir(parents=True)
    stale = cache / ".dl-crashed"
    stale.mkdir()
    (stale / "blob").write_bytes(b"x" * 10)
    os.utime(stale, (1, 1))
    fresh = cache / ".dl-in-flight"
    fresh.mkdir()
    s3_artifacts.fetch_verified(URI, tmp_path / "d", OVMF_SHA, "ovmf", fetch=Fetcher())
    assert not stale.exists()
    assert fresh.exists()  # a concurrent download in progress is left alone


def test_a_cache_hit_refreshes_lru_recency(tmp_path, cache) -> None:
    s3_artifacts.fetch_verified(URI, tmp_path / "a", OVMF_SHA, "ovmf", fetch=Fetcher())
    os.utime(cache / OVMF_SHA, (1000, 1000))
    s3_artifacts.fetch_verified(URI, tmp_path / "b", OVMF_SHA, "ovmf", fetch=Fetcher())
    assert (cache / OVMF_SHA).stat().st_mtime > 1000


def test_no_retry_is_started_past_the_deadline(aws, tmp_path) -> None:
    import time as _time

    aws["answers"] = [(1, SLOWDOWN), (0, "")]
    with pytest.raises(EffectError, match="no time left to retry"):
        ld._s3_cp(URI, tmp_path / "ovmf.fd", deadline=_time.monotonic() + 5)
    assert aws["calls"] == 1
    assert aws["pauses"] == []


def test_each_attempt_is_bounded_by_what_is_left_of_the_budget(monkeypatch, tmp_path) -> None:
    import time as _time

    seen: list[float] = []

    def _run(argv, **kw):
        seen.append(kw["timeout"])
        Path(argv[-1]).write_bytes(OVMF)
        return subprocess.CompletedProcess(argv, 0, stdout=b"", stderr=b"")

    monkeypatch.setattr(ld.subprocess, "run", _run)
    ld._s3_cp(URI, tmp_path / "ovmf.fd", deadline=_time.monotonic() + 30)
    assert seen and seen[0] <= 30


@pytest.mark.parametrize(
    "stderr",
    [
        "An error occurred (502) when calling the GetObject operation: Bad Gateway",
        "An error occurred (504) when calling the GetObject operation: Gateway Timeout",
        "Connection broken: IncompleteRead(1024 bytes read, 2048 more expected)",
        "ResponseStreamingError: An error occurred while reading from response stream",
        "SSL: UNEXPECTED_EOF_WHILE_READING",
    ],
)
def test_more_transient_errors_are_recognised(stderr: str) -> None:
    assert s3_artifacts.is_transient(stderr)


@pytest.mark.parametrize(
    "stderr",
    [
        "An error occurred (403) when calling the GetObject operation: Forbidden",
        "An error occurred (NoSuchKey) when calling the GetObject operation",
        "An error occurred (RequestTimeTooSkewed) when calling the GetObject operation",
        "An error occurred (SignatureDoesNotMatch) when calling the GetObject operation",
    ],
)
def test_permanent_errors_are_not_retried(stderr: str) -> None:
    assert not s3_artifacts.is_transient(stderr)


def test_an_attempt_is_not_started_once_the_budget_is_spent(aws, tmp_path) -> None:
    import time as _time

    aws["answers"] = [(0, "")]
    with pytest.raises(EffectError, match="fetch budget exhausted"):
        ld._s3_cp(URI, tmp_path / "ovmf.fd", deadline=_time.monotonic() - 1)
    assert aws["calls"] == 0
