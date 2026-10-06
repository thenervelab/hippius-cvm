"""Launch-path S3 reads that must not fail a launch on a hiccup.

Two things, both for artifacts vali fetches by a PINNED sha256 (the C2
launch-digest recompute: the pinned OVMF and each bake's kernel/initrd):

- **Transient S3 errors are retried.** hippius-s3 answers `SlowDown`
  ("Object not ready for download yet. Please retry."), 5xx and
  throttling under load; one of those used to fail the whole launch as
  `launch-digest-recompute-failure`. The classifier is shared with the
  allowlist upload (`allowlist_pin._s3_upload`, #1172), so both sides of
  the launch path agree on what "transient" means.
- **A content-addressed local cache, keyed by the pinned sha.** The OVMF
  is the same bytes for every launch, and a bake's kernel/initrd for
  every launch of that bake, so vali fetches each once per pod.

The cache is never trusted: every load re-hashes the bytes while copying
them out and compares against the pin, and a mismatching entry is dropped
and fetched again. A cache that cannot be used (unwritable directory)
degrades to a direct fetch, never to an unverified one.
"""

from __future__ import annotations

import hashlib
import logging
import os
import re
import shutil
import tempfile
import time
from collections.abc import Callable
from pathlib import Path

from django.conf import settings

from apps.orchestration.effects import EffectError

log = logging.getLogger("apps.orchestration.s3_artifacts")

#: Pauses between attempts on a TRANSIENT S3 error (three attempts in all).
RETRY_PAUSES_S: tuple[float, ...] = (2.0, 5.0)

#: A retry is only worth starting with at least this much time left.
_MIN_ATTEMPT_S = 10.0

#: stderr markers of an S3 error that is transient by definition (S3's own
#: retry guidance: SlowDown, 5xx, request timeout, throttling). A signature,
#: permission or missing-object error is NOT retried — it would only fail
#: again, slower.
TRANSIENT_S3_ERROR = re.compile(
    r"SlowDown|ServiceUnavailable|Service Unavailable|InternalError|"
    r"RequestTimeout|Throttl|temporarily unavailable|\(500\)|\(502\)|\(503\)|\(504\)|"
    r"Bad Gateway|Gateway ?Time-?out|"
    r"Could not connect to the endpoint URL|Read timeout|Connection was closed|"
    r"Connection reset|Connection broken|IncompleteRead|ResponseStreamingError|"
    r"UNEXPECTED_EOF|EOF occurred in violation of protocol",
    re.IGNORECASE,
)

_SHA256_RE = re.compile(r"[0-9a-f]{64}")
_DEFAULT_MAX_BYTES = 300 << 20
#: A download directory older than this is left over from a crash or a
#: killed `aws` and is swept.
_STALE_DOWNLOAD_S = 600.0


def is_transient(stderr: str) -> bool:
    return bool(TRANSIENT_S3_ERROR.search(stderr))


def cache_dir() -> Path:
    configured = str(getattr(settings, "VALI_ARTIFACT_CACHE_DIR", "") or "").strip()
    return Path(configured) if configured else Path(tempfile.gettempdir()) / "vali-artifact-cache"


def _max_bytes() -> int:
    return int(getattr(settings, "VALI_ARTIFACT_CACHE_MAX_BYTES", _DEFAULT_MAX_BYTES))


def _copy_hashing(src: Path, dest: Path) -> str:
    """Copy `src` to `dest` and return the sha256 of the bytes written."""
    h = hashlib.sha256()
    with open(src, "rb") as fin, open(dest, "wb") as fout:
        for chunk in iter(lambda: fin.read(1 << 20), b""):
            h.update(chunk)
            fout.write(chunk)
    return h.hexdigest()


def _mismatch(label: str, got: str, want: str) -> EffectError:
    return EffectError(f"{label}-sha-mismatch: fetched {got}, pinned {want}")


def _serve_from_cache(entry: Path, dest: Path, want: str) -> bool:
    """Copy a cache entry to `dest` if it verifies. Any miss — absent,
    evicted mid-read, unreadable, corrupt — returns False; a corrupt entry
    is dropped."""
    try:
        got = _copy_hashing(entry, dest)
    except OSError:
        return False
    if got != want:
        log.warning("artifact-cache: entry %s is corrupt (%s) — refetching", want, got)
        entry.unlink(missing_ok=True)
        return False
    try:
        os.utime(entry)  # LRU recency; the entry may already be gone
    except OSError:
        pass
    return True


def _evict(root: Path, keep: Path) -> None:
    """Drop least-recently-used entries until the cache fits its cap, and
    sweep download directories a crash or a killed `aws` left behind. A
    failure here only means the cache stays a little large."""
    try:
        now = time.time()
        for p in root.iterdir():
            if p.name.startswith(".dl-") and now - p.stat().st_mtime > _STALE_DOWNLOAD_S:
                shutil.rmtree(p, ignore_errors=True)
        entries = []
        for p in root.iterdir():
            if _SHA256_RE.fullmatch(p.name) and p != keep:
                st = p.stat()
                entries.append((st.st_mtime, st.st_size, p))
        total = sum(size for _, size, _ in entries) + keep.stat().st_size
        for _, size, p in sorted(entries):
            if total <= _max_bytes():
                break
            total -= size
            p.unlink(missing_ok=True)
    except OSError as exc:
        log.warning("artifact-cache: eviction skipped: %s", exc)


def _fetch_into_cache(
    s3_uri: str, dest: Path, want: str, label: str, root: Path, fetch: Callable[[str, Path], None]
) -> None:
    """Download into a private directory under the cache, verify, fill
    `dest` from the verified copy, then install the entry atomically."""
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    work = Path(tempfile.mkdtemp(prefix=".dl-", dir=root))
    try:
        blob = work / "blob"
        fetch(s3_uri, blob)
        got = _copy_hashing(blob, dest)
        if got != want:
            raise _mismatch(label, got, want)
        os.replace(blob, root / want)
    finally:
        shutil.rmtree(work, ignore_errors=True)
    _evict(root, keep=root / want)


def _fetch_direct(
    s3_uri: str, dest: Path, want: str, label: str, fetch: Callable[[str, Path], None]
) -> None:
    fetch(s3_uri, dest)
    h = hashlib.sha256()
    with open(dest, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    if h.hexdigest() != want:
        raise _mismatch(label, h.hexdigest(), want)


def fetch_verified(
    s3_uri: str,
    dest: Path,
    expected_sha256_hex: str,
    label: str,
    fetch: Callable[[str, Path], None],
) -> None:
    """Put the bytes pinned by `expected_sha256_hex` at `dest`.

    Served from the cache when an entry verifies; otherwise `fetch` (which
    retries transient errors itself) downloads into the cache, the bytes
    are verified, and the entry is installed with an atomic rename. `dest`
    is only ever written by a hashing copy (or verified right after a
    direct fetch), so it holds exactly the pinned bytes or this raises
    `EffectError` (`<label>-sha-mismatch`). A local cache failure raised
    in this process (directory unwritable or missing, entry gone) falls
    back to a verified direct fetch; an error `aws` itself reports while
    writing (e.g. a full disk) surfaces as the fetch's `EffectError`."""
    want = expected_sha256_hex.strip().lower()
    if not _SHA256_RE.fullmatch(want):
        raise EffectError(f"{label}-sha-invalid: pinned value is not 64-hex")

    root = cache_dir()
    if _serve_from_cache(root / want, dest, want):
        return
    try:
        _fetch_into_cache(s3_uri, dest, want, label, root, fetch)
        return
    except EffectError:
        raise
    except OSError as exc:
        log.warning("artifact-cache: unusable (%s) — fetching %s directly", exc, label)
    _fetch_direct(s3_uri, dest, want, label, fetch)


def retry_transient(
    attempt: Callable[[float], str | None],
    *,
    what: str,
    deadline: float,
    attempt_timeout_s: float,
    pauses: tuple[float, ...] = RETRY_PAUSES_S,
) -> None:
    """Run `attempt(timeout_s)` until it succeeds, retrying only transient
    failures, and never past `deadline` (a `time.monotonic()` value).

    `attempt` returns `None` on success, else the error text. Each attempt
    gets `attempt_timeout_s` or what is left before the deadline, whichever
    is smaller. A non-transient error, a transient one after the last
    pause, or one with no time left for another attempt raises
    `EffectError(error_text)`."""
    remaining = list(pauses)
    while True:
        left = deadline - time.monotonic()
        if left < 1.0:
            raise EffectError(f"{what}: fetch budget exhausted before the attempt")
        error = attempt(min(attempt_timeout_s, left))
        if error is None:
            return
        if not remaining or not is_transient(error):
            raise EffectError(error)
        pause = remaining.pop(0)
        if time.monotonic() + pause + _MIN_ATTEMPT_S > deadline:
            raise EffectError(f"{error} (no time left to retry)")
        log.warning("%s: transient S3 error (%s) — retrying in %.0f s", what, error[-160:], pause)
        time.sleep(pause)
