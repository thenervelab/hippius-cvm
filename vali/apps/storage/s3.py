"""Hippius S3 client abstraction.

Locked decision (issue #1 comment 4496539510, Q12): vali distributes
Packer-produced images via **Hippius S3 (dogfooding)**. Four
operational details are still tracked open in issue #54:

  1. Does the Hippius S3 deployment support **Object Lock** (needed
     for §22 allowlist OOB delivery and for SLSA provenance write-
     once-read-many storage)? Assumption pending: yes.
  2. What is the real **endpoint URL** in prod / staging? — placeholder
     `https://s3.hippius.invalid` until the cluster is provisioned.
  3. **Credential path**: `Vault transit` proxying to short-lived STS
     creds vs. static keys in env. Assumption: env vars for now, with
     a `VALI_S3_CREDENTIALS_PROVIDER` setting prepared to route to
     `apps.storage.vault_provider` once the Vault path lands.
  4. **Presign support**: does the Hippius S3 implementation correctly
     emit and accept SigV4 presigned URLs? Assumption: yes (boto3-
     compatible).

Until those are answered, vali ships with:

  - `HippiusS3Client` abstract base — the only API surface the rest
    of vali consumes.
  - `BotoHippiusS3Client` — boto3 implementation, endpoint-URL +
    creds via settings/env.
  - `MockHippiusS3Client` — deterministic, no network. Used by the
    test suite AND can be wired in dev (`VALI_S3_CLIENT_FACTORY =
    "apps.storage.s3.mock_factory"`).

Switching to the real wiring is a single env-var change once the four
questions resolve; no code in `apps.packer` knows the difference.
"""

from __future__ import annotations

import abc
import importlib
import logging
import threading
import urllib.parse
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

log = logging.getLogger("apps.storage.s3")


def _resolve_boto_presign_errors() -> tuple[type[BaseException], ...]:
    """Tuple of exception classes the boto presign path raises.

    Resolved lazily so the module imports cleanly when botocore is
    absent (test env without boto3). When botocore IS installed,
    `ClientError` covers configuration / signing failures and
    `BotoCoreError` covers transport-level issues. Falling back to
    `(ValueError, RuntimeError, OSError)` if neither is importable
    is preferred over `Exception` so a programmer error in our own
    code still propagates as a 500.
    """
    classes: list[type[BaseException]] = []
    try:
        botocore_exceptions = importlib.import_module("botocore.exceptions")
        classes.append(botocore_exceptions.ClientError)
        classes.append(botocore_exceptions.BotoCoreError)
    except ImportError:
        pass
    classes.extend((ValueError, RuntimeError, OSError))
    return tuple(classes)


_BOTO_PRESIGN_ERRORS = _resolve_boto_presign_errors()


class S3ClientUnavailable(RuntimeError):
    """Raised by `BotoHippiusS3Client` when boto3 isn't installed or
    when the underlying client errors out at presign time.

    Views catch this and surface 503 — it's an ops problem (missing
    package / unreachable endpoint), not the caller's fault.
    """


class S3RequestRejected(S3ClientUnavailable):
    #: The store's error code (`NoSuchKey`, `AccessDenied`, …; for a HEAD,
    #: which has no body, the bare HTTP status like `404`). Empty when not
    #: from the store.
    code: str = ""

    """The object store answered a direct (non-presigned) call with a 4xx —
    e.g. `CompleteMultipartUpload` refusing an ETag that matches no
    uploaded part. Retrying the same request cannot succeed, so callers
    fail the operation instead of retrying it. Subclasses
    `S3ClientUnavailable` so a caller that treats every S3 failure alike
    keeps working.
    """


@dataclass(frozen=True)
class CompletedPart:
    """One part of a multipart upload, as `complete_multipart_upload`
    needs it: the 1-based part number and the ETag the store returned
    for it (verbatim, quotes included)."""

    part_number: int
    etag: str


@dataclass(frozen=True)
class MultipartUploadInfo:
    """One in-progress multipart upload, from `list_multipart_uploads`."""

    key: str
    upload_id: str
    initiated: datetime


@dataclass(frozen=True)
class ObjectInfo:
    """One object, from `list_objects`."""

    key: str
    last_modified: datetime
    size: int


@dataclass(frozen=True)
class ListPage:
    """One page of a listing. `next_marker` is opaque: hand it back to get
    the next page; None when the listing is complete."""

    items: list[Any]
    next_marker: tuple[str, ...] | None


@dataclass(frozen=True)
class PresignedRequest:
    """Materialized presigned request descriptor.

    `url` is the full URL the caller hands to its S3 client. `method`
    distinguishes GET (download) from PUT (upload). `expires_at_unix`
    is the wall-clock expiry; vali computes it from `time.time() +
    ttl_seconds` at sign time so callers don't have to.
    """

    url: str
    method: str
    expires_at_unix: int


class HippiusS3Client(abc.ABC):
    """The single surface vali depends on.

    All implementations MUST be safe to call from multiple Django
    workers (i.e. they hold no per-process state that mutates on
    each call). boto3 clients are thread-safe; the mock is trivially
    so.
    """

    @abc.abstractmethod
    def presign_get(
        self,
        *,
        bucket: str,
        key: str,
        version_id: str | None = None,
        ttl_seconds: int,
    ) -> PresignedRequest:
        """Presign a GET against `s3://bucket/key`.

        `version_id` pins the exact object version — §17.5 calls for
        version-scoped presigns so a later overwrite of `key` doesn't
        retroactively change what the holder of the URL can read.
        `None` means "current version" (only acceptable when the
        bucket isn't versioned).
        """

    @abc.abstractmethod
    def presign_put(
        self,
        *,
        bucket: str,
        key: str,
        ttl_seconds: int,
    ) -> PresignedRequest:
        """Presign a PUT against `s3://bucket/key`. Used by the
        Packer Job to upload its artifact.
        """

    # ── Multipart + direct object calls (VM backups) ──────────────────
    #
    # Unlike the presigns above, these are DIRECT calls made with vali's
    # own credentials: vali opens and closes a multipart upload itself and
    # hands the uploader (a miner) only presigned `UploadPart` URLs, so the
    # uploader never holds a credential and cannot complete, abort or
    # overwrite anything.

    @abc.abstractmethod
    def create_multipart_upload(self, *, bucket: str, key: str) -> str:
        """Open a multipart upload for `s3://bucket/key`; returns its
        upload id."""

    @abc.abstractmethod
    def presign_upload_part(
        self,
        *,
        bucket: str,
        key: str,
        upload_id: str,
        part_number: int,
        ttl_seconds: int,
    ) -> PresignedRequest:
        """Presign a PUT of part `part_number` (1..10000) of `upload_id`."""

    @abc.abstractmethod
    def complete_multipart_upload(
        self, *, bucket: str, key: str, upload_id: str, parts: list[CompletedPart]
    ) -> None:
        """Assemble `parts` (ascending part numbers) into the object.
        Raises `S3RequestRejected` when the store refuses the part list."""

    @abc.abstractmethod
    def abort_multipart_upload(self, *, bucket: str, key: str, upload_id: str) -> None:
        """Discard an upload and its parts. An unknown upload id is not an
        error (the abort is idempotent)."""

    @abc.abstractmethod
    def put_object(self, *, bucket: str, key: str, body: bytes, content_type: str) -> None:
        """Write a small object directly."""

    @abc.abstractmethod
    def delete_object(self, *, bucket: str, key: str) -> None:
        """Delete one object. A missing key is not an error."""

    @abc.abstractmethod
    def head_object(self, *, bucket: str, key: str) -> int | None:
        """The object's size in bytes, or None when it does not exist."""

    @abc.abstractmethod
    def get_object(self, *, bucket: str, key: str, max_bytes: int) -> bytes | None:
        """A small object's bytes, or None when it does not exist. Raises
        `S3RequestRejected` when it is larger than `max_bytes` — the
        caller asked for something small and must not buffer more."""

    @abc.abstractmethod
    def list_multipart_uploads(
        self, *, bucket: str, prefix: str, marker: tuple[str, ...] | None, max_items: int
    ) -> ListPage:
        """One page (at most `max_items`) of the in-progress multipart
        uploads under `prefix`, as `MultipartUploadInfo`s."""

    @abc.abstractmethod
    def list_objects(
        self, *, bucket: str, prefix: str, marker: tuple[str, ...] | None, max_items: int
    ) -> ListPage:
        """One page (at most `max_items`) of the objects under `prefix`, as
        `ObjectInfo`s."""


# ───────────────────────────────────────────────────────────────────
# Mock implementation (tests + dev)
# ───────────────────────────────────────────────────────────────────


class MockHippiusS3Client(HippiusS3Client):
    """Deterministic, no-network S3 client.

    Emits URLs of the form
    `mock-s3://<bucket>/<key>?op=get&expires_at=…&version_id=…`
    which are stable across runs given the same inputs (modulo the
    expiry timestamp which uses an injectable clock). The tests
    pattern-match on these strings rather than parsing real S3
    responses.

    Thread-safe: the only mutable state is the optional `_clock`
    callable, which the tests inject once at construction.
    """

    SCHEME = "mock-s3"

    def __init__(self, *, clock: callable | None = None) -> None:  # type: ignore[type-arg]
        # `clock` returns the current unix time. Default: `time.time`.
        # Tests inject a frozen clock to assert `expires_at_unix`
        # values exactly.
        import time as _time

        self._clock = clock or _time.time
        # In-memory multipart + object store for the backup paths. Keyed
        # `(bucket, key)`; guarded by a lock because the tick and the views
        # can share the singleton.
        self._lock = threading.Lock()
        self.objects: dict[tuple[str, str], bytes] = {}
        #: Size of every object, including completed multipart objects whose
        #: bytes the mock does not keep.
        self.sizes: dict[tuple[str, str], int] = {}
        self.uploads: dict[str, tuple[str, str]] = {}
        #: `upload_id → {part_number: size}` — what an uploader PUT through
        #: its presigned part URLs (see `record_part`).
        self.parts: dict[str, dict[int, int]] = {}
        #: When each upload was opened / each object last written (from the
        #: injectable clock). Tests may backdate entries.
        self.initiated: dict[str, datetime] = {}
        self.modified: dict[tuple[str, str], datetime] = {}
        self.completed: dict[str, list[CompletedPart]] = {}
        self.aborted: set[str] = set()
        self._upload_seq = 0

    def create_multipart_upload(self, *, bucket: str, key: str) -> str:
        _validate_inputs(bucket=bucket, key=key, ttl_seconds=1)
        with self._lock:
            self._upload_seq += 1
            upload_id = f"mock-upload-{self._upload_seq}"
            self.uploads[upload_id] = (bucket, key)
            self.initiated[upload_id] = self._now()
        return upload_id

    def presign_upload_part(
        self,
        *,
        bucket: str,
        key: str,
        upload_id: str,
        part_number: int,
        ttl_seconds: int,
    ) -> PresignedRequest:
        _validate_inputs(bucket=bucket, key=key, ttl_seconds=ttl_seconds)
        _validate_part_number(part_number)
        expires_at = int(self._clock()) + ttl_seconds
        params = {
            "op": "upload_part",
            "upload_id": upload_id,
            "part_number": str(part_number),
            "expires_at": str(expires_at),
        }
        url = self._build_url(bucket=bucket, key=key, params=params)
        return PresignedRequest(url=url, method="PUT", expires_at_unix=expires_at)

    def record_part(self, *, upload_id: str, part_number: int, size: int) -> None:
        """Stand-in for an uploader's PUT to a presigned part URL."""
        with self._lock:
            if upload_id not in self.uploads:
                raise S3RequestRejected("upload_part: NoSuchUpload")
            self.parts.setdefault(upload_id, {})[part_number] = size

    def complete_multipart_upload(
        self, *, bucket: str, key: str, upload_id: str, parts: list[CompletedPart]
    ) -> None:
        _validate_completed_parts(parts)
        with self._lock:
            if self.uploads.get(upload_id) != (bucket, key) or upload_id in self.aborted:
                raise S3RequestRejected("complete_multipart_upload: NoSuchUpload")
            uploaded = self.parts.get(upload_id, {})
            if any(p.part_number not in uploaded for p in parts):
                raise S3RequestRejected("complete_multipart_upload: InvalidPart")
            self.completed[upload_id] = list(parts)
            self.objects[(bucket, key)] = b""
            self.sizes[(bucket, key)] = sum(uploaded[p.part_number] for p in parts)
            del self.uploads[upload_id]

    def abort_multipart_upload(self, *, bucket: str, key: str, upload_id: str) -> None:
        with self._lock:
            self.aborted.add(upload_id)
            self.uploads.pop(upload_id, None)

    def put_object(self, *, bucket: str, key: str, body: bytes, content_type: str) -> None:
        _validate_inputs(bucket=bucket, key=key, ttl_seconds=1)
        with self._lock:
            self.objects[(bucket, key)] = bytes(body)
            self.sizes[(bucket, key)] = len(body)
            self.modified[(bucket, key)] = self._now()

    def delete_object(self, *, bucket: str, key: str) -> None:
        with self._lock:
            self.objects.pop((bucket, key), None)
            self.sizes.pop((bucket, key), None)
            self.modified.pop((bucket, key), None)

    def head_object(self, *, bucket: str, key: str) -> int | None:
        with self._lock:
            return self.sizes.get((bucket, key))

    def _now(self) -> datetime:
        return datetime.fromtimestamp(self._clock(), UTC)

    def list_multipart_uploads(
        self, *, bucket: str, prefix: str, marker: tuple[str, ...] | None, max_items: int
    ) -> ListPage:
        with self._lock:
            rows = sorted(
                (key, uid)
                for uid, (b, key) in self.uploads.items()
                if b == bucket and key.startswith(prefix) and uid not in self.aborted
            )
            items = [
                MultipartUploadInfo(key=k, upload_id=u, initiated=self.initiated[u])
                for k, u in rows
                if marker is None or (k, u) > marker
            ]
        page = items[:max_items]
        more = len(items) > max_items
        return ListPage(page, (page[-1].key, page[-1].upload_id) if more else None)

    def list_objects(
        self, *, bucket: str, prefix: str, marker: tuple[str, ...] | None, max_items: int
    ) -> ListPage:
        with self._lock:
            keys = sorted(
                k for (b, k) in self.sizes if b == bucket and k.startswith(prefix)
            )
            items = [
                ObjectInfo(
                    key=k,
                    last_modified=self.modified.get((bucket, k), self._now()),
                    size=self.sizes[(bucket, k)],
                )
                for k in keys
                if marker is None or k > marker[0]
            ]
        page = items[:max_items]
        more = len(items) > max_items
        return ListPage(page, (page[-1].key,) if more else None)

    def get_object(self, *, bucket: str, key: str, max_bytes: int) -> bytes | None:
        with self._lock:
            data = self.objects.get((bucket, key))
        if data is not None and len(data) > max_bytes:
            raise S3RequestRejected("get_object: object larger than expected")
        return data

    def presign_get(
        self,
        *,
        bucket: str,
        key: str,
        version_id: str | None = None,
        ttl_seconds: int,
    ) -> PresignedRequest:
        _validate_inputs(bucket=bucket, key=key, ttl_seconds=ttl_seconds)
        expires_at = int(self._clock()) + ttl_seconds
        params = {"op": "get", "expires_at": str(expires_at)}
        if version_id is not None:
            params["version_id"] = version_id
        url = self._build_url(bucket=bucket, key=key, params=params)
        return PresignedRequest(url=url, method="GET", expires_at_unix=expires_at)

    def presign_put(
        self,
        *,
        bucket: str,
        key: str,
        ttl_seconds: int,
    ) -> PresignedRequest:
        _validate_inputs(bucket=bucket, key=key, ttl_seconds=ttl_seconds)
        expires_at = int(self._clock()) + ttl_seconds
        params = {"op": "put", "expires_at": str(expires_at)}
        url = self._build_url(bucket=bucket, key=key, params=params)
        return PresignedRequest(url=url, method="PUT", expires_at_unix=expires_at)

    def _build_url(
        self, *, bucket: str, key: str, params: dict[str, str]
    ) -> str:
        # `urllib.parse.quote` with empty `safe` so `/` in keys is
        # encoded — keeps the mock URL output stable regardless of
        # the key shape.
        encoded_key = urllib.parse.quote(key, safe="")
        query = urllib.parse.urlencode(params)
        return f"{self.SCHEME}://{bucket}/{encoded_key}?{query}"


# ───────────────────────────────────────────────────────────────────
# Boto3 implementation (real wiring)
# ───────────────────────────────────────────────────────────────────


class BotoHippiusS3Client(HippiusS3Client):
    """boto3-backed S3 client targeting the Hippius S3 endpoint.

    The endpoint URL is supplied at construction (the factory reads
    it from `settings.HIPPIUS_S3_ENDPOINT_URL`). Credentials are
    pulled from the default boto3 chain — typically env vars in this
    deployment, eventually a Vault-transit-issued STS pair once the
    Vault path lands (Q6 follow-up).

    Note: this class only imports `boto3` lazily, inside `__init__`,
    so the test suite can construct a `MockHippiusS3Client` without
    boto3 being installed. Production deployments install it as part
    of the vali container image.
    """

    def __init__(
        self,
        *,
        endpoint_url: str,
        region_name: str | None = None,
        boto3_module: Any = None,
        botocore_config: Any = None,
        aws_access_key_id: str | None = None,
        aws_secret_access_key: str | None = None,
    ) -> None:
        # Explicit credentials are for a client that must NOT use the default
        # boto chain — e.g. the backup bucket's dedicated key. Both or none.
        # `boto3_module` is an injection seam so the small unit test
        # for this class can pass a fake module without paying the
        # cost of installing boto3 in the test image.
        if boto3_module is None:
            try:
                boto3_module = importlib.import_module("boto3")
            except ImportError as exc:
                raise S3ClientUnavailable(
                    "boto3 is not installed — install it OR switch "
                    "VALI_S3_CLIENT_FACTORY to apps.storage.s3.mock_factory"
                ) from exc
        # SigV4 is the only signing mode Hippius S3 will commit to
        # (Q12 follow-up #54 has presign compatibility tracked). Pin
        # it explicitly here so a host-side boto3 config can't quietly
        # downgrade to SigV2 / pre-signed-headers-only. Caller can
        # override by passing their own `botocore_config`.
        if botocore_config is None:
            try:
                botocore_config_module = importlib.import_module("botocore.config")
                # Hippius S3 is MinIO-compatible: virtual-host addressing
                # and SigV2 BOTH fail against it — path-style + SigV4 is the
                # only combination that produces a presigned URL the object
                # store accepts (see ops note s3_operator_creds). Pin both
                # explicitly so a host-side boto3 config can't downgrade.
                botocore_config = botocore_config_module.Config(
                    signature_version="s3v4",
                    s3={"addressing_style": "path"},
                )
            except ImportError:
                # `botocore` ships transitively with `boto3`; an
                # installation that has boto3 but not botocore is
                # broken. Continue without an explicit Config rather
                # than 503 — boto3 will still default to SigV4 for
                # `s3` in practice.
                botocore_config = None
        self._endpoint_url = endpoint_url
        client_kwargs: dict[str, Any] = {
            "endpoint_url": endpoint_url,
            "region_name": region_name,
        }
        if botocore_config is not None:
            client_kwargs["config"] = botocore_config
        if (aws_access_key_id is None) != (aws_secret_access_key is None):
            raise S3ClientUnavailable("S3 credentials need both an access key id and a secret")
        if aws_access_key_id is not None:
            client_kwargs["aws_access_key_id"] = aws_access_key_id
            client_kwargs["aws_secret_access_key"] = aws_secret_access_key
        self._client = boto3_module.client("s3", **client_kwargs)

    def presign_get(
        self,
        *,
        bucket: str,
        key: str,
        version_id: str | None = None,
        ttl_seconds: int,
    ) -> PresignedRequest:
        _validate_inputs(bucket=bucket, key=key, ttl_seconds=ttl_seconds)
        import time as _time

        params: dict[str, Any] = {"Bucket": bucket, "Key": key}
        if version_id is not None:
            params["VersionId"] = version_id
        try:
            url = self._client.generate_presigned_url(
                ClientMethod="get_object",
                Params=params,
                ExpiresIn=ttl_seconds,
                HttpMethod="GET",
            )
        except _BOTO_PRESIGN_ERRORS as exc:
            raise S3ClientUnavailable(f"presign_get failed: {exc}") from exc
        return PresignedRequest(
            url=url,
            method="GET",
            expires_at_unix=int(_time.time()) + ttl_seconds,
        )

    def presign_put(
        self,
        *,
        bucket: str,
        key: str,
        ttl_seconds: int,
    ) -> PresignedRequest:
        _validate_inputs(bucket=bucket, key=key, ttl_seconds=ttl_seconds)
        import time as _time

        try:
            url = self._client.generate_presigned_url(
                ClientMethod="put_object",
                Params={"Bucket": bucket, "Key": key},
                ExpiresIn=ttl_seconds,
                HttpMethod="PUT",
            )
        except _BOTO_PRESIGN_ERRORS as exc:
            raise S3ClientUnavailable(f"presign_put failed: {exc}") from exc
        return PresignedRequest(
            url=url,
            method="PUT",
            expires_at_unix=int(_time.time()) + ttl_seconds,
        )

    def _call(self, op: str, **params: Any) -> Any:
        """One direct S3 call. A 4xx answer becomes `S3RequestRejected`
        (retrying cannot help); anything else `S3ClientUnavailable`. The
        message names the operation and the S3 error code only — never a
        credential."""
        try:
            return getattr(self._client, op)(**params)
        except _BOTO_PRESIGN_ERRORS as exc:
            response = getattr(exc, "response", None) or {}
            http_status = int((response.get("ResponseMetadata") or {}).get("HTTPStatusCode") or 0)
            code = str((response.get("Error") or {}).get("Code") or type(exc).__name__)
            if 400 <= http_status < 500:
                rejected = S3RequestRejected(f"{op} rejected: {code}")
                rejected.code = code
                raise rejected from exc
            raise S3ClientUnavailable(f"{op} failed: {code}") from exc

    def create_multipart_upload(self, *, bucket: str, key: str) -> str:
        _validate_inputs(bucket=bucket, key=key, ttl_seconds=1)
        out = self._call("create_multipart_upload", Bucket=bucket, Key=key)
        upload_id = str((out or {}).get("UploadId") or "")
        if not upload_id:
            raise S3ClientUnavailable("create_multipart_upload: no UploadId returned")
        return upload_id

    def presign_upload_part(
        self,
        *,
        bucket: str,
        key: str,
        upload_id: str,
        part_number: int,
        ttl_seconds: int,
    ) -> PresignedRequest:
        _validate_inputs(bucket=bucket, key=key, ttl_seconds=ttl_seconds)
        _validate_part_number(part_number)
        import time as _time

        try:
            url = self._client.generate_presigned_url(
                ClientMethod="upload_part",
                Params={
                    "Bucket": bucket,
                    "Key": key,
                    "UploadId": upload_id,
                    "PartNumber": part_number,
                },
                ExpiresIn=ttl_seconds,
                HttpMethod="PUT",
            )
        except _BOTO_PRESIGN_ERRORS as exc:
            raise S3ClientUnavailable(f"presign_upload_part failed: {exc}") from exc
        return PresignedRequest(
            url=url,
            method="PUT",
            expires_at_unix=int(_time.time()) + ttl_seconds,
        )

    def complete_multipart_upload(
        self, *, bucket: str, key: str, upload_id: str, parts: list[CompletedPart]
    ) -> None:
        _validate_completed_parts(parts)
        self._call(
            "complete_multipart_upload",
            Bucket=bucket,
            Key=key,
            UploadId=upload_id,
            MultipartUpload={
                "Parts": [{"ETag": p.etag, "PartNumber": p.part_number} for p in parts]
            },
        )

    def abort_multipart_upload(self, *, bucket: str, key: str, upload_id: str) -> None:
        try:
            self._call("abort_multipart_upload", Bucket=bucket, Key=key, UploadId=upload_id)
        except S3RequestRejected as exc:
            # NoSuchUpload: already completed, aborted or expired — done.
            if "NoSuchUpload" not in str(exc):
                raise

    def put_object(self, *, bucket: str, key: str, body: bytes, content_type: str) -> None:
        _validate_inputs(bucket=bucket, key=key, ttl_seconds=1)
        self._call("put_object", Bucket=bucket, Key=key, Body=bytes(body), ContentType=content_type)

    def delete_object(self, *, bucket: str, key: str) -> None:
        # S3 answers 204 for a missing key too, so this is idempotent.
        self._call("delete_object", Bucket=bucket, Key=key)

    def head_object(self, *, bucket: str, key: str) -> int | None:
        try:
            out = self._call("head_object", Bucket=bucket, Key=key)
        except S3RequestRejected as exc:
            if "404" in str(exc) or "NoSuchKey" in str(exc) or "NotFound" in str(exc):
                return None
            raise
        return int((out or {}).get("ContentLength") or 0)

    def get_object(self, *, bucket: str, key: str, max_bytes: int) -> bytes | None:
        try:
            out = self._call("get_object", Bucket=bucket, Key=key)
        except S3RequestRejected as exc:
            # Only the store's own "no such key": a bare 404 (a proxy, a
            # wrong endpoint) or NoSuchBucket must not read as "absent".
            if exc.code == "NoSuchKey":
                return None
            raise
        if int(out.get("ContentLength") or 0) > max_bytes:
            raise S3RequestRejected("get_object: object larger than expected")
        body = out["Body"]
        try:
            data = body.read(max_bytes + 1)
        finally:
            body.close()
        if len(data) > max_bytes:
            raise S3RequestRejected("get_object: object larger than expected")
        return bytes(data)

    def list_multipart_uploads(
        self, *, bucket: str, prefix: str, marker: tuple[str, ...] | None, max_items: int
    ) -> ListPage:
        """Two paging modes, told apart by the answer and carried in the
        marker's first element:

        - `"s"` — the store paged (`IsTruncated`): its own `NextKeyMarker` /
          `NextUploadIdMarker` are replayed verbatim, the S3 contract.
        - `"c"` — the store ignored `MaxUploads` and answered more than asked
          without truncating (Hippius S3 answers everything and ignores the
          markers). vali pages the full answer itself, in its own
          `(key, upload_id)` order, and sends no marker to the store.
        """
        params: dict[str, Any] = {"Bucket": bucket, "Prefix": prefix, "MaxUploads": max_items}
        mode = marker[0] if marker else ""
        if mode == "s":
            params["KeyMarker"], params["UploadIdMarker"] = marker[1], marker[2]
        out = self._call("list_multipart_uploads", **params) or {}
        items = [
            MultipartUploadInfo(
                key=str(u["Key"]), upload_id=str(u["UploadId"]), initiated=_aware(u["Initiated"])
            )
            for u in out.get("Uploads") or []
            if str(u["Key"]).startswith(prefix)
        ]
        if out.get("IsTruncated") and mode != "c":
            key_marker = str(out.get("NextKeyMarker") or "")
            if not key_marker:
                raise S3ClientUnavailable("list_multipart_uploads: truncated without a marker")
            return ListPage(
                items[:max_items], ("s", key_marker, str(out.get("NextUploadIdMarker") or ""))
            )
        items.sort(key=lambda u: (u.key, u.upload_id))
        if mode == "c":
            items = [u for u in items if (u.key, u.upload_id) > (marker[1], marker[2])]
        if len(items) > max_items:
            items = items[:max_items]
            return ListPage(items, ("c", items[-1].key, items[-1].upload_id))
        return ListPage(items, None)

    def list_objects(
        self, *, bucket: str, prefix: str, marker: tuple[str, ...] | None, max_items: int
    ) -> ListPage:
        # `StartAfter` + a client-side cut, for the same reason as above.
        params: dict[str, Any] = {"Bucket": bucket, "Prefix": prefix, "MaxKeys": max_items}
        if marker is not None:
            params["StartAfter"] = marker[0]
        out = self._call("list_objects_v2", **params) or {}
        items = sorted(
            (
                ObjectInfo(
                    key=str(o["Key"]),
                    last_modified=_aware(o["LastModified"]),
                    size=int(o.get("Size") or 0),
                )
                for o in out.get("Contents") or []
                if str(o["Key"]).startswith(prefix)
            ),
            key=lambda o: o.key,
        )
        if marker is not None:
            items = [o for o in items if o.key > marker[0]]
        if len(items) > max_items:
            items = items[:max_items]
            return ListPage(items, (items[-1].key,))
        if out.get("IsTruncated") and items:
            return ListPage(items, (items[-1].key,))
        return ListPage(items, None)


def _aware(value: Any) -> datetime:
    """boto hands back timezone-aware datetimes; be strict about it."""
    if not isinstance(value, datetime):
        raise S3ClientUnavailable("listing returned a non-datetime timestamp")
    return value if value.tzinfo is not None else value.replace(tzinfo=UTC)


# ───────────────────────────────────────────────────────────────────
# Validation helpers
# ───────────────────────────────────────────────────────────────────


# Max TTL is bounded so a bug in the caller can't issue a years-long
# URL by accident. 24 h is a generous ceiling for image distribution
# — the Packer trigger uses 1 h in practice, but ops scripts may
# pre-stage things up to a day in advance.
MAX_TTL_SECONDS = 24 * 60 * 60


def _validate_inputs(*, bucket: str, key: str, ttl_seconds: int) -> None:
    if not bucket or not isinstance(bucket, str):
        raise ValueError("bucket must be a non-empty string")
    if not key or not isinstance(key, str):
        raise ValueError("key must be a non-empty string")
    if not isinstance(ttl_seconds, int) or isinstance(ttl_seconds, bool):
        raise ValueError("ttl_seconds must be an integer")
    if ttl_seconds < 1:
        raise ValueError("ttl_seconds must be ≥ 1")
    if ttl_seconds > MAX_TTL_SECONDS:
        raise ValueError(
            f"ttl_seconds must be ≤ {MAX_TTL_SECONDS} (got {ttl_seconds})"
        )


#: S3's multipart part-number range.
MAX_PART_NUMBER = 10_000
#: S3's floor on every multipart part but the last.
MIN_PART_BYTES = 5 * 1024**2
#: hippius-s3's ceiling on one multipart part: it answers `EntityTooLarge`
#: above 512 MiB (not S3's 5 GiB).
MAX_PART_BYTES = 512 * 1024**2
#: The most presigned part URLs one signed multipart order (`backup`,
#: `migrate-snapshot`) carries: `encode_order.rs` `MAX_MULTIPART_PARTS`,
#: sized to the 2 MiB body the Edge and the miner give those kinds. At
#: `MAX_PART_BYTES` the largest flavor (1280 GiB) needs ~2,600.
MAX_ORDER_PARTS = 3000


def _validate_part_number(part_number: int) -> None:
    if isinstance(part_number, bool) or not isinstance(part_number, int):
        raise ValueError("part_number must be an integer")
    if not 1 <= part_number <= MAX_PART_NUMBER:
        raise ValueError(f"part_number must be in 1..{MAX_PART_NUMBER}")


def _validate_completed_parts(parts: list[CompletedPart]) -> None:
    if not parts:
        raise ValueError("a multipart upload needs at least one part")
    numbers = [p.part_number for p in parts]
    for n in numbers:
        _validate_part_number(n)
    if numbers != sorted(set(numbers)):
        raise ValueError("part numbers must be strictly ascending")
    if any(not p.etag for p in parts):
        raise ValueError("every part needs an ETag")


# ───────────────────────────────────────────────────────────────────
# DI factories
# ───────────────────────────────────────────────────────────────────


def boto_factory() -> HippiusS3Client:
    """Default production factory.

    Resolves Django settings lazily so importing this module doesn't
    drag in Django at test-collection time. Reads:

    - `HIPPIUS_S3_ENDPOINT_URL` (required for boto).
    - `HIPPIUS_S3_REGION_NAME` (optional; defaults to None → boto3
      picks up `AWS_DEFAULT_REGION` from env).
    """
    from django.conf import settings

    endpoint = getattr(settings, "HIPPIUS_S3_ENDPOINT_URL", None)
    if not endpoint:
        raise S3ClientUnavailable(
            "HIPPIUS_S3_ENDPOINT_URL is not set — set it OR switch "
            "VALI_S3_CLIENT_FACTORY to apps.storage.s3.mock_factory"
        )
    region = getattr(settings, "HIPPIUS_S3_REGION_NAME", None) or None
    return BotoHippiusS3Client(endpoint_url=endpoint, region_name=region)


def mock_factory() -> HippiusS3Client:
    """Test/dev factory that emits deterministic mock URLs."""
    return MockHippiusS3Client()


_RESOLVED_CLIENT_CACHE: HippiusS3Client | None = None
_CACHE_LOCK = threading.Lock()


def get_s3_client() -> HippiusS3Client:
    """Resolve the configured factory and return its singleton client.

    Reads `settings.VALI_S3_CLIENT_FACTORY` — a dotted-path string
    pointing at a zero-arg callable returning a `HippiusS3Client`.
    The result is cached process-wide; callers in tests should
    `monkeypatch` `apps.storage.s3.get_s3_client` rather than reach
    for the cache directly.
    """
    global _RESOLVED_CLIENT_CACHE
    if _RESOLVED_CLIENT_CACHE is not None:
        return _RESOLVED_CLIENT_CACHE
    with _CACHE_LOCK:
        if _RESOLVED_CLIENT_CACHE is not None:
            return _RESOLVED_CLIENT_CACHE
        from django.conf import settings

        dotted = getattr(
            settings,
            "VALI_S3_CLIENT_FACTORY",
            "apps.storage.s3.mock_factory",
        )
        module_path, _, attr = dotted.rpartition(".")
        if not module_path:
            raise S3ClientUnavailable(
                f"VALI_S3_CLIENT_FACTORY {dotted!r} is not a dotted path"
            )
        try:
            module = importlib.import_module(module_path)
        except ImportError as exc:
            raise S3ClientUnavailable(
                f"VALI_S3_CLIENT_FACTORY {dotted!r}: module not importable ({exc})"
            ) from exc
        factory = getattr(module, attr, None)
        if factory is None or not callable(factory):
            raise S3ClientUnavailable(
                f"VALI_S3_CLIENT_FACTORY {dotted!r} is not callable"
            )
        client = factory()
        if not isinstance(client, HippiusS3Client):
            raise S3ClientUnavailable(
                f"factory {dotted!r} returned {type(client).__name__}, "
                "expected HippiusS3Client subclass"
            )
        _RESOLVED_CLIENT_CACHE = client
        return client


def reset_s3_client_cache() -> None:
    """Drop the cached client. For tests + reload paths only."""
    global _RESOLVED_CLIENT_CACHE
    with _CACHE_LOCK:
        _RESOLVED_CLIENT_CACHE = None
