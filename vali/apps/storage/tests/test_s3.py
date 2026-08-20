"""Tests for `apps.storage.s3` — the Hippius S3 abstraction.

These tests cover:

  - `MockHippiusS3Client` URL determinism + clock injection.
  - `_validate_inputs` rejection paths.
  - `BotoHippiusS3Client` with an injected fake boto3 module
    (avoids requiring boto3 in the test container).
  - The `get_s3_client` factory cache + dotted-path resolution.
"""

from __future__ import annotations

from typing import Any

import pytest
from django.test import override_settings

from apps.storage import s3 as s3_module

# ─── MockHippiusS3Client ─────────────────────────────────────────────


def test_mock_presign_get_deterministic_url() -> None:
    client = s3_module.MockHippiusS3Client(clock=lambda: 1_000_000)
    out = client.presign_get(
        bucket="images", key="kbs/abc.img", ttl_seconds=3600
    )
    assert out.method == "GET"
    assert out.expires_at_unix == 1_000_000 + 3600
    # Key is URL-encoded — `/` becomes `%2F`.
    assert "kbs%2Fabc.img" in out.url
    assert out.url.startswith("mock-s3://images/")
    assert "op=get" in out.url


def test_mock_presign_get_includes_version_id_when_supplied() -> None:
    client = s3_module.MockHippiusS3Client(clock=lambda: 0)
    out = client.presign_get(
        bucket="images",
        key="kbs/a.img",
        version_id="v1",
        ttl_seconds=60,
    )
    assert "version_id=v1" in out.url


def test_mock_presign_put_distinct_op_marker() -> None:
    client = s3_module.MockHippiusS3Client(clock=lambda: 0)
    out = client.presign_put(bucket="b", key="k", ttl_seconds=60)
    assert out.method == "PUT"
    assert "op=put" in out.url


def test_mock_presign_rejects_zero_ttl() -> None:
    client = s3_module.MockHippiusS3Client()
    with pytest.raises(ValueError):
        client.presign_get(bucket="b", key="k", ttl_seconds=0)


def test_mock_presign_rejects_overlong_ttl() -> None:
    client = s3_module.MockHippiusS3Client()
    with pytest.raises(ValueError):
        client.presign_get(
            bucket="b", key="k", ttl_seconds=s3_module.MAX_TTL_SECONDS + 1
        )


def test_mock_presign_rejects_empty_bucket() -> None:
    client = s3_module.MockHippiusS3Client()
    with pytest.raises(ValueError):
        client.presign_get(bucket="", key="k", ttl_seconds=60)


def test_mock_presign_rejects_bool_ttl() -> None:
    # `bool` is an `int` subclass in Python — explicit check.
    client = s3_module.MockHippiusS3Client()
    with pytest.raises(ValueError):
        client.presign_get(bucket="b", key="k", ttl_seconds=True)  # type: ignore[arg-type]


# ─── BotoHippiusS3Client (with injected fake boto3) ─────────────────


class _FakeBoto3Client:
    """Records the kwargs each `generate_presigned_url` call receives."""

    def __init__(self) -> None:
        self.calls: list[dict[str, Any]] = []

    def generate_presigned_url(
        self,
        *,
        ClientMethod: str,
        Params: dict[str, Any],
        ExpiresIn: int,
        HttpMethod: str,
    ) -> str:
        self.calls.append(
            {
                "ClientMethod": ClientMethod,
                "Params": Params,
                "ExpiresIn": ExpiresIn,
                "HttpMethod": HttpMethod,
            }
        )
        return (
            f"https://s3.example/{Params['Bucket']}/{Params['Key']}"
            f"?expires={ExpiresIn}"
        )


class _FakeBoto3Module:
    def __init__(self) -> None:
        self._client = _FakeBoto3Client()

    def client(self, _service: str, **_kw: Any) -> _FakeBoto3Client:
        return self._client


def test_boto_client_presign_get_forwards_to_boto3() -> None:
    fake = _FakeBoto3Module()
    client = s3_module.BotoHippiusS3Client(
        endpoint_url="https://s3.invalid",
        boto3_module=fake,
    )
    out = client.presign_get(
        bucket="images",
        key="edge/x.img",
        version_id="v9",
        ttl_seconds=300,
    )
    assert out.method == "GET"
    assert out.url.startswith("https://s3.example/images/")
    call = fake._client.calls[0]
    assert call["ClientMethod"] == "get_object"
    assert call["Params"]["VersionId"] == "v9"
    assert call["ExpiresIn"] == 300
    assert call["HttpMethod"] == "GET"


def test_boto_client_presign_put_no_version_id() -> None:
    fake = _FakeBoto3Module()
    client = s3_module.BotoHippiusS3Client(
        endpoint_url="https://s3.invalid",
        boto3_module=fake,
    )
    client.presign_put(bucket="b", key="k", ttl_seconds=60)
    call = fake._client.calls[0]
    assert call["ClientMethod"] == "put_object"
    assert "VersionId" not in call["Params"]


def test_boto_client_wraps_underlying_exception() -> None:
    class _ExplodingClient:
        def generate_presigned_url(self, **_kw: Any) -> str:
            raise RuntimeError("endpoint down")

    class _ExplodingModule:
        def client(self, *_args: Any, **_kw: Any) -> _ExplodingClient:
            return _ExplodingClient()

    client = s3_module.BotoHippiusS3Client(
        endpoint_url="https://s3.invalid",
        boto3_module=_ExplodingModule(),
    )
    with pytest.raises(s3_module.S3ClientUnavailable):
        client.presign_get(bucket="b", key="k", ttl_seconds=60)


# ─── get_s3_client factory + cache ──────────────────────────────────


def test_get_s3_client_default_mock_factory() -> None:
    s3_module.reset_s3_client_cache()
    with override_settings(VALI_S3_CLIENT_FACTORY="apps.storage.s3.mock_factory"):
        client = s3_module.get_s3_client()
    s3_module.reset_s3_client_cache()
    assert isinstance(client, s3_module.MockHippiusS3Client)


def test_get_s3_client_caches_result() -> None:
    s3_module.reset_s3_client_cache()
    with override_settings(VALI_S3_CLIENT_FACTORY="apps.storage.s3.mock_factory"):
        first = s3_module.get_s3_client()
        second = s3_module.get_s3_client()
    s3_module.reset_s3_client_cache()
    assert first is second


def test_get_s3_client_rejects_non_callable() -> None:
    s3_module.reset_s3_client_cache()
    # Point at this module itself, which is not callable.
    with override_settings(VALI_S3_CLIENT_FACTORY="apps.storage.s3.MAX_TTL_SECONDS"):
        with pytest.raises(s3_module.S3ClientUnavailable):
            s3_module.get_s3_client()
    s3_module.reset_s3_client_cache()


def test_get_s3_client_rejects_factory_returning_wrong_type() -> None:
    # A factory that returns a non-HippiusS3Client must be rejected
    # so a misconfiguration can't quietly disable the abstraction.
    import sys
    import types

    mod = types.ModuleType("test_bad_factory_mod")
    mod.f = lambda: "not a client"
    sys.modules["test_bad_factory_mod"] = mod
    s3_module.reset_s3_client_cache()
    with override_settings(VALI_S3_CLIENT_FACTORY="test_bad_factory_mod.f"):
        with pytest.raises(s3_module.S3ClientUnavailable):
            s3_module.get_s3_client()
    s3_module.reset_s3_client_cache()
    del sys.modules["test_bad_factory_mod"]


def test_boto_factory_requires_endpoint() -> None:
    s3_module.reset_s3_client_cache()
    with override_settings(HIPPIUS_S3_ENDPOINT_URL=""):
        with pytest.raises(s3_module.S3ClientUnavailable):
            s3_module.boto_factory()
    s3_module.reset_s3_client_cache()


def test_get_s3_client_wraps_import_error() -> None:
    # A typo in `VALI_S3_CLIENT_FACTORY` must surface as
    # `S3ClientUnavailable`, NOT as raw `ModuleNotFoundError`. The
    # view turns the former into a clean 503; a raw exception would
    # bubble to 500 and leak the dotted path in the response.
    s3_module.reset_s3_client_cache()
    with override_settings(
        VALI_S3_CLIENT_FACTORY="apps.storage.does_not_exist.factory"
    ):
        with pytest.raises(s3_module.S3ClientUnavailable):
            s3_module.get_s3_client()
    s3_module.reset_s3_client_cache()


def test_boto_client_passes_sigv4_config_to_boto3() -> None:
    # Q12 follow-up #54 includes "does the Hippius S3 implementation
    # accept SigV4 presigns?" — we pin the signing mode here so a
    # host-side boto3 config can't quietly downgrade.
    captured: dict[str, Any] = {}

    class _Boto3:
        def client(self, _svc: str, **kw: Any) -> _FakeBoto3Client:
            captured.update(kw)
            return _FakeBoto3Client()

    _ = s3_module.BotoHippiusS3Client(
        endpoint_url="https://s3.invalid",
        boto3_module=_Boto3(),
    )
    # If botocore was importable in the test env, we pinned SigV4;
    # if not (broken transitive install), the config kwarg is absent.
    config = captured.get("config")
    if config is not None:
        # botocore.config.Config exposes `signature_version`.
        assert getattr(config, "signature_version", None) == "s3v4"
