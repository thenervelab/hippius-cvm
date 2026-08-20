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
    ) -> None:
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
