"""Multipart + direct object calls (VM backups): the mock store's
bookkeeping and the boto client's request shapes / error mapping."""

from __future__ import annotations

from typing import Any

import pytest

from apps.storage import s3

botocore_exceptions = pytest.importorskip("botocore.exceptions")


def _client_error(status: int, code: str) -> Exception:
    return botocore_exceptions.ClientError(
        {"Error": {"Code": code}, "ResponseMetadata": {"HTTPStatusCode": status}}, "op"
    )


class _FakeClient:
    def __init__(self) -> None:
        self.calls: list[tuple[str, dict[str, Any]]] = []
        self.fail: dict[str, Exception] = {}

    def __getattr__(self, op: str):
        def call(**params: Any) -> Any:
            self.calls.append((op, params))
            if op in self.fail:
                raise self.fail[op]
            if op == "create_multipart_upload":
                return {"UploadId": "up-1"}
            if op == "generate_presigned_url":
                return f"https://s3.example/{params['Params']['Key']}?part={params['Params']['PartNumber']}"
            return {}

        return call


class _FakeModule:
    def __init__(self) -> None:
        self.client_obj = _FakeClient()

    def client(self, *_a: Any, **_kw: Any) -> _FakeClient:
        return self.client_obj


def _boto() -> tuple[s3.BotoHippiusS3Client, _FakeClient]:
    mod = _FakeModule()
    return s3.BotoHippiusS3Client(
        endpoint_url="https://s3.invalid", boto3_module=mod
    ), mod.client_obj


def test_boto_multipart_round_trip_request_shapes() -> None:
    client, fake = _boto()
    assert client.create_multipart_upload(bucket="b", key="k") == "up-1"
    url = client.presign_upload_part(
        bucket="b", key="k", upload_id="up-1", part_number=3, ttl_seconds=60
    )
    assert url.method == "PUT" and url.url.endswith("part=3")
    client.complete_multipart_upload(
        bucket="b",
        key="k",
        upload_id="up-1",
        parts=[s3.CompletedPart(1, '"e1"'), s3.CompletedPart(2, '"e2"')],
    )
    client.put_object(bucket="b", key="m", body=b"{}", content_type="application/json")
    client.delete_object(bucket="b", key="m")
    ops = [op for op, _ in fake.calls]
    assert ops == [
        "create_multipart_upload",
        "generate_presigned_url",
        "complete_multipart_upload",
        "put_object",
        "delete_object",
    ]
    presign = fake.calls[1][1]
    assert presign["ClientMethod"] == "upload_part"
    assert presign["Params"] == {"Bucket": "b", "Key": "k", "UploadId": "up-1", "PartNumber": 3}
    complete = fake.calls[2][1]
    assert complete["MultipartUpload"]["Parts"] == [
        {"ETag": '"e1"', "PartNumber": 1},
        {"ETag": '"e2"', "PartNumber": 2},
    ]


def test_boto_4xx_is_a_rejection_and_5xx_is_unavailable() -> None:
    client, fake = _boto()
    fake.fail["complete_multipart_upload"] = _client_error(400, "InvalidPart")
    with pytest.raises(s3.S3RequestRejected, match="InvalidPart"):
        client.complete_multipart_upload(
            bucket="b", key="k", upload_id="u", parts=[s3.CompletedPart(1, "e")]
        )
    fake.fail["put_object"] = _client_error(503, "SlowDown")
    with pytest.raises(s3.S3ClientUnavailable) as exc:
        client.put_object(bucket="b", key="k", body=b"", content_type="x")
    assert not isinstance(exc.value, s3.S3RequestRejected)


def test_boto_abort_of_an_unknown_upload_is_idempotent() -> None:
    client, fake = _boto()
    fake.fail["abort_multipart_upload"] = _client_error(404, "NoSuchUpload")
    client.abort_multipart_upload(bucket="b", key="k", upload_id="gone")
    fake.fail["abort_multipart_upload"] = _client_error(403, "AccessDenied")
    with pytest.raises(s3.S3RequestRejected):
        client.abort_multipart_upload(bucket="b", key="k", upload_id="u")


@pytest.mark.parametrize(
    "parts",
    [
        [],
        [s3.CompletedPart(2, "e"), s3.CompletedPart(1, "e")],
        [s3.CompletedPart(1, "e"), s3.CompletedPart(1, "e")],
        [s3.CompletedPart(0, "e")],
        [s3.CompletedPart(1, "")],
    ],
)
def test_complete_validates_the_part_list(parts: list[s3.CompletedPart]) -> None:
    client = s3.MockHippiusS3Client()
    upload = client.create_multipart_upload(bucket="b", key="k")
    with pytest.raises(ValueError):
        client.complete_multipart_upload(bucket="b", key="k", upload_id=upload, parts=parts)


def test_mock_multipart_lifecycle() -> None:
    client = s3.MockHippiusS3Client()
    upload = client.create_multipart_upload(bucket="b", key="k")
    url = client.presign_upload_part(
        bucket="b", key="k", upload_id=upload, part_number=1, ttl_seconds=60
    )
    assert "op=upload_part" in url.url and upload in url.url
    # Completing a part nobody uploaded is refused, like a real store.
    with pytest.raises(s3.S3RequestRejected, match="InvalidPart"):
        client.complete_multipart_upload(
            bucket="b", key="k", upload_id=upload, parts=[s3.CompletedPart(1, "e")]
        )
    client.record_part(upload_id=upload, part_number=1, size=7)
    client.complete_multipart_upload(
        bucket="b", key="k", upload_id=upload, parts=[s3.CompletedPart(1, "e")]
    )
    assert client.head_object(bucket="b", key="k") == 7
    assert client.head_object(bucket="b", key="missing") is None
    # Completing twice, or an aborted upload, is refused like a real store.
    with pytest.raises(s3.S3RequestRejected):
        client.complete_multipart_upload(
            bucket="b", key="k", upload_id=upload, parts=[s3.CompletedPart(1, "e")]
        )
    other = client.create_multipart_upload(bucket="b", key="k2")
    client.abort_multipart_upload(bucket="b", key="k2", upload_id=other)
    with pytest.raises(s3.S3RequestRejected):
        client.complete_multipart_upload(
            bucket="b", key="k2", upload_id=other, parts=[s3.CompletedPart(1, "e")]
        )


def test_part_numbers_are_bounded() -> None:
    client = s3.MockHippiusS3Client()
    for bad in (0, 10_001, True):
        with pytest.raises(ValueError):
            client.presign_upload_part(
                bucket="b", key="k", upload_id="u", part_number=bad, ttl_seconds=60
            )


def test_mock_get_object_is_bounded() -> None:
    client = s3.MockHippiusS3Client()
    client.put_object(bucket="b", key="k", body=b"12345", content_type="x")
    assert client.get_object(bucket="b", key="k", max_bytes=5) == b"12345"
    assert client.get_object(bucket="b", key="nope", max_bytes=5) is None
    with pytest.raises(s3.S3RequestRejected):
        client.get_object(bucket="b", key="k", max_bytes=4)


class _Body:
    def __init__(self, data: bytes) -> None:
        self.data = data
        self.closed = False

    def read(self, n: int) -> bytes:
        return self.data[:n]

    def close(self) -> None:
        self.closed = True


def test_boto_head_and_get_map_missing_objects_to_none() -> None:
    client, fake = _boto()
    fake.fail["head_object"] = _client_error(404, "404")
    assert client.head_object(bucket="b", key="k") is None
    fake.fail["get_object"] = _client_error(404, "NoSuchKey")
    assert client.get_object(bucket="b", key="k", max_bytes=10) is None


@pytest.mark.parametrize(
    ("status", "code"), [(404, "404"), (404, "NoSuchBucket"), (403, "AccessDenied")]
)
def test_boto_get_object_only_reads_no_such_key_as_absent(status: int, code: str) -> None:
    """A bare 404 (a proxy, a wrong endpoint) or a missing bucket must not
    look like a reachable bucket with no such object."""
    client, fake = _boto()
    fake.fail["get_object"] = _client_error(status, code)
    with pytest.raises(s3.S3RequestRejected) as exc:
        client.get_object(bucket="b", key="k", max_bytes=10)
    assert exc.value.code == code


def test_boto_get_object_refuses_an_oversized_object() -> None:
    client, fake = _boto()
    body = _Body(b"x" * 11)

    def get_object(**_kw: Any) -> dict[str, Any]:
        return {"ContentLength": 0, "Body": body}  # a lying length

    fake.get_object = get_object  # type: ignore[attr-defined]
    with pytest.raises(s3.S3RequestRejected):
        client.get_object(bucket="b", key="k", max_bytes=10)
    assert body.closed


def test_boto_listings_page_with_the_store_markers() -> None:
    from datetime import UTC, datetime

    client, fake = _boto()
    when = datetime(2026, 9, 1, tzinfo=UTC)
    answers = {
        "list_multipart_uploads": {
            "Uploads": [{"Key": "backups/a", "UploadId": "u1", "Initiated": when}],
            "IsTruncated": True,
            "NextKeyMarker": "backups/a",
            "NextUploadIdMarker": "u1",
        },
        "list_objects_v2": {
            "Contents": [{"Key": "uploads/a", "LastModified": when, "Size": 5}],
            "IsTruncated": False,
        },
    }
    for op, out in answers.items():
        setattr(fake, op, lambda _op=op, _out=out, **kw: (fake.calls.append((_op, kw)), _out)[1])

    page = client.list_multipart_uploads(bucket="b", prefix="backups/", marker=None, max_items=5)
    assert page.items == [s3.MultipartUploadInfo("backups/a", "u1", when)]
    assert page.next_marker == ("s", "backups/a", "u1")
    client.list_multipart_uploads(
        bucket="b", prefix="backups/", marker=page.next_marker, max_items=5
    )
    assert fake.calls[-1][1]["KeyMarker"] == "backups/a"
    assert fake.calls[-1][1]["UploadIdMarker"] == "u1"

    objs = client.list_objects(bucket="b", prefix="uploads/", marker=("uploads/",), max_items=5)
    assert objs.items == [s3.ObjectInfo("uploads/a", when, 5)] and objs.next_marker is None
    assert fake.calls[-1][1]["StartAfter"] == "uploads/"
    assert fake.calls[-1][1]["Prefix"] == "uploads/"


def test_boto_listings_are_bounded_even_when_the_store_ignores_limits_and_markers() -> None:
    """Hippius S3 answers every upload, ignores MaxUploads / KeyMarker, and
    says IsTruncated=false. The client must still page."""
    from datetime import UTC, datetime

    client, fake = _boto()
    when = datetime(2026, 9, 1, tzinfo=UTC)
    everything = {
        "Uploads": [
            {"Key": f"backups/{i}", "UploadId": f"u{i}", "Initiated": when} for i in (3, 0, 2, 1, 4)
        ]
        + [{"Key": "elsewhere/x", "UploadId": "ux", "Initiated": when}],
        "IsTruncated": False,
    }
    fake.list_multipart_uploads = lambda **_kw: everything  # type: ignore[attr-defined]
    seen: list[str] = []
    marker = None
    for _ in range(10):
        page = client.list_multipart_uploads(
            bucket="b", prefix="backups/", marker=marker, max_items=2
        )
        assert len(page.items) <= 2
        seen += [u.key for u in page.items]
        marker = page.next_marker
        if marker is None:
            break
    assert seen == [f"backups/{i}" for i in range(5)]

    objects = {
        "Contents": [{"Key": f"uploads/{i}", "LastModified": when, "Size": 1} for i in range(5)],
        "IsTruncated": False,
    }
    fake.list_objects_v2 = lambda **_kw: objects  # type: ignore[attr-defined]
    keys: list[str] = []
    marker = None
    for _ in range(10):
        page = client.list_objects(bucket="b", prefix="uploads/", marker=marker, max_items=2)
        keys += [o.key for o in page.items]
        marker = page.next_marker
        if marker is None:
            break
    assert keys == [f"uploads/{i}" for i in range(5)]


def test_mock_listings_page() -> None:
    client = s3.MockHippiusS3Client()
    for i in range(3):
        client.create_multipart_upload(bucket="b", key=f"backups/{i}")
        client.put_object(bucket="b", key=f"uploads/{i}", body=b"x", content_type="x")
    first = client.list_multipart_uploads(bucket="b", prefix="backups/", marker=None, max_items=2)
    assert len(first.items) == 2 and first.next_marker is not None
    rest = client.list_multipart_uploads(
        bucket="b", prefix="backups/", marker=first.next_marker, max_items=2
    )
    assert len(rest.items) == 1 and rest.next_marker is None
    objs = client.list_objects(bucket="b", prefix="uploads/", marker=None, max_items=10)
    assert [o.key for o in objs.items] == ["uploads/0", "uploads/1", "uploads/2"]


def test_boto_replays_the_store_markers_when_it_pages() -> None:
    """Two uploads of one key straddling a page: the store's own markers are
    replayed verbatim, never re-derived."""
    from datetime import UTC, datetime

    client, fake = _boto()
    when = datetime(2026, 9, 1, tzinfo=UTC)
    pages = [
        {
            "Uploads": [{"Key": "backups/k", "UploadId": "zzz", "Initiated": when}],
            "IsTruncated": True,
            "NextKeyMarker": "backups/k",
            "NextUploadIdMarker": "opaque-1",
        },
        {
            "Uploads": [{"Key": "backups/k", "UploadId": "aaa", "Initiated": when}],
            "IsTruncated": False,
        },
    ]
    seen_params: list[dict[str, Any]] = []

    def answer(**kw: Any) -> dict[str, Any]:
        seen_params.append(kw)
        return pages[len(seen_params) - 1]

    fake.list_multipart_uploads = answer  # type: ignore[attr-defined]
    first = client.list_multipart_uploads(bucket="b", prefix="backups/", marker=None, max_items=1)
    second = client.list_multipart_uploads(
        bucket="b", prefix="backups/", marker=first.next_marker, max_items=1
    )
    assert [u.upload_id for u in first.items + second.items] == ["zzz", "aaa"]
    assert seen_params[1]["KeyMarker"] == "backups/k"
    assert seen_params[1]["UploadIdMarker"] == "opaque-1"
    assert second.next_marker is None
