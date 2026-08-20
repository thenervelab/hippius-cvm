"""Integration tests for the packer endpoints.

Uses DRF's `APIClient`. The Hippius S3 client is replaced with a
`MockHippiusS3Client` via the factory cache so tests are network-free
AND can assert deterministic URLs.
"""

from __future__ import annotations

import pytest
from django.test import override_settings
from django.urls import reverse
from rest_framework import status
from rest_framework.test import APIClient

from apps.identity.models import (
    PrincipalScope,
    ServiceClient,
    ServiceToken,
    TokenLifetime,
)
from apps.packer.models import IN_FLIGHT_STATES, PackerBuild, PackerBuildState
from apps.storage import s3 as s3_module

pytestmark = pytest.mark.django_db


GOOD_SHA = "a" * 64
GOOD_URL = "https://s3.example/provenance/abc.jsonl"


# ─── Fixtures ───────────────────────────────────────────────────────


@pytest.fixture(autouse=True)
def _mock_s3(monkeypatch: pytest.MonkeyPatch) -> None:
    """Point `apps.storage.s3.get_s3_client` at a fresh mock for each test.

    Using a per-test mock with a frozen clock keeps the asserted
    `expires_at_unix` values exact across runs and CI clock drift.
    """
    mock = s3_module.MockHippiusS3Client(clock=lambda: 1_700_000_000)
    monkeypatch.setattr(s3_module, "get_s3_client", lambda: mock)


def _make_client(name: str = "orchestrator") -> tuple[APIClient, ServiceClient]:
    client = ServiceClient.objects.create(scope=PrincipalScope.OPERATOR.value, name=name)
    _row, plaintext = ServiceToken.issue(
        client=client,
        name="ops",
        lifetime=TokenLifetime.OPS.value,
    )
    c = APIClient()
    c.credentials(HTTP_AUTHORIZATION=f"Bearer {plaintext}")
    return c, client


@pytest.fixture
def authed_client() -> APIClient:
    c, _ = _make_client("orchestrator")
    return c


@pytest.fixture
def worker_client() -> APIClient:
    # Worker principal name matches `VALI_PACKER_WORKER_PRINCIPAL`
    # set per-test via `override_settings`.
    c, _ = _make_client("packer-worker")
    return c


# ─── POST /v1/packer/build ──────────────────────────────────────────


def test_create_build_unauthenticated_rejected() -> None:
    c = APIClient()
    resp = c.post(
        reverse("packer_build_create"), {"image_kind": "kbs"}, format="json"
    )
    assert resp.status_code in (
        status.HTTP_401_UNAUTHORIZED,
        status.HTTP_403_FORBIDDEN,
    )


def test_create_build_happy_path(authed_client: APIClient) -> None:
    resp = authed_client.post(
        reverse("packer_build_create"), {"image_kind": "kbs"}, format="json"
    )
    assert resp.status_code == status.HTTP_202_ACCEPTED, resp.content
    body = resp.json()
    assert body["image_kind"] == "kbs"
    assert body["state"] == "queued"
    assert body["version"] == 1
    assert body["artifact_sha256"] is None
    assert PackerBuild.objects.count() == 1


def test_create_build_rejects_unknown_image_kind(authed_client: APIClient) -> None:
    resp = authed_client.post(
        reverse("packer_build_create"),
        {"image_kind": "totally-bogus"},
        format="json",
    )
    assert resp.status_code == status.HTTP_400_BAD_REQUEST
    assert resp.json()["category"] == "wire"


def test_create_build_rejects_missing_image_kind(authed_client: APIClient) -> None:
    resp = authed_client.post(reverse("packer_build_create"), {}, format="json")
    assert resp.status_code == status.HTTP_400_BAD_REQUEST


def test_create_build_409_if_in_flight_exists(authed_client: APIClient) -> None:
    # First build → Queued.
    authed_client.post(
        reverse("packer_build_create"), {"image_kind": "edge"}, format="json"
    )
    # Second build for same image_kind while first is Queued → 409.
    resp = authed_client.post(
        reverse("packer_build_create"), {"image_kind": "edge"}, format="json"
    )
    assert resp.status_code == status.HTTP_409_CONFLICT
    body = resp.json()
    assert body["category"] == "already-in-flight"
    assert body["active"]["image_kind"] == "edge"


def test_create_build_allows_distinct_image_kinds_in_parallel(
    authed_client: APIClient,
) -> None:
    for kind in ("kbs", "edge", "guest", "audit-vm"):
        resp = authed_client.post(
            reverse("packer_build_create"),
            {"image_kind": kind},
            format="json",
        )
        assert resp.status_code == status.HTTP_202_ACCEPTED, (kind, resp.content)
    assert PackerBuild.objects.count() == 4


def test_create_build_allows_new_after_terminal(authed_client: APIClient) -> None:
    # Queue, then mark Failed manually (simulating finalize). A new
    # POST for the same image_kind MUST succeed because the prior
    # row is no longer in-flight.
    resp = authed_client.post(
        reverse("packer_build_create"), {"image_kind": "guest"}, format="json"
    )
    build_id = resp.json()["build_id"]
    PackerBuild.objects.filter(build_id=build_id).update(
        state=PackerBuildState.FAILED.value, failure_reason="manual"
    )
    resp = authed_client.post(
        reverse("packer_build_create"), {"image_kind": "guest"}, format="json"
    )
    assert resp.status_code == status.HTTP_202_ACCEPTED


# ─── GET /v1/packer/build/<id> ──────────────────────────────────────


def test_get_build_404_unknown(authed_client: APIClient) -> None:
    resp = authed_client.get(
        reverse("packer_build_detail", kwargs={"build_id": "missing"})
    )
    assert resp.status_code == status.HTTP_404_NOT_FOUND


def test_get_build_returns_row(authed_client: APIClient) -> None:
    create = authed_client.post(
        reverse("packer_build_create"), {"image_kind": "kbs"}, format="json"
    )
    build_id = create.json()["build_id"]
    resp = authed_client.get(
        reverse("packer_build_detail", kwargs={"build_id": build_id})
    )
    assert resp.status_code == status.HTTP_200_OK
    assert resp.json()["build_id"] == build_id


# ─── POST /v1/packer/build/<id>/finalize (worker-only) ──────────────


@override_settings(VALI_PACKER_WORKER_PRINCIPAL="packer-worker")
def test_finalize_rejects_non_worker_principal(
    authed_client: APIClient,
) -> None:
    create = authed_client.post(
        reverse("packer_build_create"), {"image_kind": "kbs"}, format="json"
    )
    build_id = create.json()["build_id"]
    resp = authed_client.post(
        reverse("packer_build_finalize", kwargs={"build_id": build_id}),
        {"to_state": "running", "if_version": 1},
        format="json",
    )
    assert resp.status_code == status.HTTP_403_FORBIDDEN


@override_settings(VALI_PACKER_WORKER_PRINCIPAL="")
def test_finalize_rejects_when_worker_principal_unset(
    worker_client: APIClient,
    authed_client: APIClient,
) -> None:
    # Empty principal config → permission fails closed for everyone,
    # including a client named "packer-worker". Surfaces
    # misconfiguration as a clear 403.
    create = authed_client.post(
        reverse("packer_build_create"), {"image_kind": "kbs"}, format="json"
    )
    build_id = create.json()["build_id"]
    resp = worker_client.post(
        reverse("packer_build_finalize", kwargs={"build_id": build_id}),
        {"to_state": "running", "if_version": 1},
        format="json",
    )
    assert resp.status_code == status.HTTP_403_FORBIDDEN


@override_settings(VALI_PACKER_WORKER_PRINCIPAL="packer-worker")
def test_finalize_queued_to_running_happy(
    worker_client: APIClient, authed_client: APIClient
) -> None:
    create = authed_client.post(
        reverse("packer_build_create"), {"image_kind": "kbs"}, format="json"
    )
    build_id = create.json()["build_id"]

    resp = worker_client.post(
        reverse("packer_build_finalize", kwargs={"build_id": build_id}),
        {"to_state": "running", "if_version": 1},
        format="json",
    )
    assert resp.status_code == status.HTTP_200_OK, resp.content
    body = resp.json()
    assert body["state"] == "running"
    assert body["version"] == 2
    assert body["started_at"] is not None


@override_settings(VALI_PACKER_WORKER_PRINCIPAL="packer-worker")
def test_finalize_running_to_succeeded_records_artifact(
    worker_client: APIClient, authed_client: APIClient
) -> None:
    create = authed_client.post(
        reverse("packer_build_create"), {"image_kind": "kbs"}, format="json"
    )
    build_id = create.json()["build_id"]
    worker_client.post(
        reverse("packer_build_finalize", kwargs={"build_id": build_id}),
        {"to_state": "running", "if_version": 1},
        format="json",
    )
    resp = worker_client.post(
        reverse("packer_build_finalize", kwargs={"build_id": build_id}),
        {
            "to_state": "succeeded",
            "if_version": 2,
            "artifact_sha256": GOOD_SHA,
            "provenance_signed_url": GOOD_URL,
        },
        format="json",
    )
    assert resp.status_code == status.HTTP_200_OK, resp.content
    body = resp.json()
    assert body["state"] == "succeeded"
    assert body["version"] == 3
    assert body["artifact_sha256"] == GOOD_SHA
    assert body["provenance_signed_url"] == GOOD_URL


@override_settings(VALI_PACKER_WORKER_PRINCIPAL="packer-worker")
def test_finalize_running_to_failed_records_reason(
    worker_client: APIClient, authed_client: APIClient
) -> None:
    create = authed_client.post(
        reverse("packer_build_create"), {"image_kind": "guest"}, format="json"
    )
    build_id = create.json()["build_id"]
    worker_client.post(
        reverse("packer_build_finalize", kwargs={"build_id": build_id}),
        {"to_state": "running", "if_version": 1},
        format="json",
    )
    resp = worker_client.post(
        reverse("packer_build_finalize", kwargs={"build_id": build_id}),
        {
            "to_state": "failed",
            "if_version": 2,
            "failure_reason": "packer step 3 exited 1",
        },
        format="json",
    )
    assert resp.status_code == status.HTTP_200_OK
    body = resp.json()
    assert body["state"] == "failed"
    assert body["failure_reason"] == "packer step 3 exited 1"


@override_settings(VALI_PACKER_WORKER_PRINCIPAL="packer-worker")
def test_finalize_409_on_stale_version(
    worker_client: APIClient, authed_client: APIClient
) -> None:
    # Caller's pre-image version is older than the actual row's,
    # even though the source→target pair is legal. The CAS UPDATE
    # filter on `version` rejects the write and the view returns
    # 409 with the current row attached.
    create = authed_client.post(
        reverse("packer_build_create"), {"image_kind": "edge"}, format="json"
    )
    build_id = create.json()["build_id"]
    worker_client.post(
        reverse("packer_build_finalize", kwargs={"build_id": build_id}),
        {"to_state": "running", "if_version": 1},
        format="json",
    )
    # Row is now Running at version 2. A worker that still thinks
    # the row is at version 1 must lose the CAS race even though
    # `Running → Succeeded` is a legal pair.
    resp = worker_client.post(
        reverse("packer_build_finalize", kwargs={"build_id": build_id}),
        {
            "to_state": "succeeded",
            "if_version": 1,
            "artifact_sha256": GOOD_SHA,
            "provenance_signed_url": GOOD_URL,
        },
        format="json",
    )
    assert resp.status_code == status.HTTP_409_CONFLICT
    body = resp.json()
    assert body["category"] == "version-conflict"
    assert body["current"]["state"] == "running"
    assert body["current"]["version"] == 2


@override_settings(VALI_PACKER_WORKER_PRINCIPAL="packer-worker")
def test_finalize_400_on_illegal_transition(
    worker_client: APIClient, authed_client: APIClient
) -> None:
    create = authed_client.post(
        reverse("packer_build_create"), {"image_kind": "kbs"}, format="json"
    )
    build_id = create.json()["build_id"]
    # Queued → Succeeded skipping Running is rejected.
    resp = worker_client.post(
        reverse("packer_build_finalize", kwargs={"build_id": build_id}),
        {
            "to_state": "succeeded",
            "if_version": 1,
            "artifact_sha256": GOOD_SHA,
            "provenance_signed_url": GOOD_URL,
        },
        format="json",
    )
    assert resp.status_code == status.HTTP_400_BAD_REQUEST
    assert resp.json()["category"] == "illegal-transition"


@override_settings(VALI_PACKER_WORKER_PRINCIPAL="packer-worker")
def test_finalize_400_when_succeeded_missing_artifact(
    worker_client: APIClient, authed_client: APIClient
) -> None:
    create = authed_client.post(
        reverse("packer_build_create"), {"image_kind": "kbs"}, format="json"
    )
    build_id = create.json()["build_id"]
    worker_client.post(
        reverse("packer_build_finalize", kwargs={"build_id": build_id}),
        {"to_state": "running", "if_version": 1},
        format="json",
    )
    resp = worker_client.post(
        reverse("packer_build_finalize", kwargs={"build_id": build_id}),
        {"to_state": "succeeded", "if_version": 2},
        format="json",
    )
    assert resp.status_code == status.HTTP_400_BAD_REQUEST
    assert resp.json()["category"] == "missing-field"


@override_settings(VALI_PACKER_WORKER_PRINCIPAL="packer-worker")
def test_finalize_400_on_bool_if_version(
    worker_client: APIClient, authed_client: APIClient
) -> None:
    # JSON `true` mustn't quietly coerce to `1`.
    create = authed_client.post(
        reverse("packer_build_create"), {"image_kind": "kbs"}, format="json"
    )
    build_id = create.json()["build_id"]
    resp = worker_client.post(
        reverse("packer_build_finalize", kwargs={"build_id": build_id}),
        {"to_state": "running", "if_version": True},
        format="json",
    )
    assert resp.status_code == status.HTTP_400_BAD_REQUEST


# ─── POST /v1/packer/build/<id>/presign-image-get ───────────────────


def test_presign_404_unknown(authed_client: APIClient) -> None:
    resp = authed_client.post(
        reverse("packer_build_presign_get", kwargs={"build_id": "missing"}),
        {},
        format="json",
    )
    assert resp.status_code == status.HTTP_404_NOT_FOUND


def test_presign_409_when_not_succeeded(authed_client: APIClient) -> None:
    create = authed_client.post(
        reverse("packer_build_create"), {"image_kind": "kbs"}, format="json"
    )
    build_id = create.json()["build_id"]
    resp = authed_client.post(
        reverse("packer_build_presign_get", kwargs={"build_id": build_id}),
        {},
        format="json",
    )
    assert resp.status_code == status.HTTP_409_CONFLICT
    assert resp.json()["category"] == "not-ready"


def test_presign_happy_path_emits_mock_url(authed_client: APIClient) -> None:
    # Hand-shape a Succeeded row so we don't have to thread the
    # worker permission for this test (the presign endpoint is
    # what's under test, not the finalize flow).
    create = authed_client.post(
        reverse("packer_build_create"), {"image_kind": "kbs"}, format="json"
    )
    build_id = create.json()["build_id"]
    PackerBuild.objects.filter(build_id=build_id).update(
        state=PackerBuildState.SUCCEEDED.value,
        artifact_sha256=GOOD_SHA,
        provenance_signed_url=GOOD_URL,
    )

    resp = authed_client.post(
        reverse("packer_build_presign_get", kwargs={"build_id": build_id}),
        {"ttl_seconds": 3600},
        format="json",
    )
    assert resp.status_code == status.HTTP_200_OK, resp.content
    body = resp.json()
    assert body["method"] == "GET"
    assert body["bucket"] == "hippius-compute-images"
    assert body["key"] == f"kbs/{GOOD_SHA}.img"
    assert body["url"].startswith("mock-s3://hippius-compute-images/")
    assert body["expires_at_unix"] == 1_700_000_000 + 3600
    assert body["artifact_sha256"] == GOOD_SHA


def test_presign_uses_default_ttl_when_omitted(authed_client: APIClient) -> None:
    create = authed_client.post(
        reverse("packer_build_create"), {"image_kind": "kbs"}, format="json"
    )
    build_id = create.json()["build_id"]
    PackerBuild.objects.filter(build_id=build_id).update(
        state=PackerBuildState.SUCCEEDED.value,
        artifact_sha256=GOOD_SHA,
        provenance_signed_url=GOOD_URL,
    )
    resp = authed_client.post(
        reverse("packer_build_presign_get", kwargs={"build_id": build_id}),
        {},
        format="json",
    )
    assert resp.status_code == status.HTTP_200_OK
    # Default `VALI_PACKER_PRESIGN_TTL_SECS` is 3600.
    assert resp.json()["expires_at_unix"] == 1_700_000_000 + 3600


def test_presign_400_on_bad_ttl(authed_client: APIClient) -> None:
    create = authed_client.post(
        reverse("packer_build_create"), {"image_kind": "kbs"}, format="json"
    )
    build_id = create.json()["build_id"]
    PackerBuild.objects.filter(build_id=build_id).update(
        state=PackerBuildState.SUCCEEDED.value,
        artifact_sha256=GOOD_SHA,
        provenance_signed_url=GOOD_URL,
    )
    resp = authed_client.post(
        reverse("packer_build_presign_get", kwargs={"build_id": build_id}),
        {"ttl_seconds": 0},
        format="json",
    )
    assert resp.status_code == status.HTTP_400_BAD_REQUEST


def test_presign_400_on_non_object_body(authed_client: APIClient) -> None:
    # Wire-shape parity with create/finalize: non-object bodies are
    # rejected explicitly rather than silently treated as `{}`.
    create = authed_client.post(
        reverse("packer_build_create"), {"image_kind": "kbs"}, format="json"
    )
    build_id = create.json()["build_id"]
    PackerBuild.objects.filter(build_id=build_id).update(
        state=PackerBuildState.SUCCEEDED.value,
        artifact_sha256=GOOD_SHA,
        provenance_signed_url=GOOD_URL,
    )
    resp = authed_client.post(
        reverse("packer_build_presign_get", kwargs={"build_id": build_id}),
        ["not", "an", "object"],
        format="json",
    )
    assert resp.status_code == status.HTTP_400_BAD_REQUEST
    assert resp.json()["category"] == "wire"


def test_partial_unique_index_blocks_duplicate_in_flight_rows() -> None:
    # Direct DB-level proof that the "one active build per image_kind"
    # rule is enforced by a partial unique constraint, not just by
    # the view-layer pre-check. Two raw inserts for the same
    # image_kind in `queued` state must collide on the index —
    # this is what makes the view's TOCTOU defense correct under
    # READ COMMITTED concurrent inserts.
    from django.db import IntegrityError as _IE

    client = ServiceClient.objects.create(scope=PrincipalScope.OPERATOR.value, name="packer-tester")
    PackerBuild.objects.create(
        build_id="row-1",
        image_kind="kbs",
        state=PackerBuildState.QUEUED.value,
        requested_by=client,
    )
    with pytest.raises(_IE):
        PackerBuild.objects.create(
            build_id="row-2",
            image_kind="kbs",
            state=PackerBuildState.QUEUED.value,
            requested_by=client,
        )


def test_partial_unique_index_allows_terminal_then_new(
    authed_client: APIClient,
) -> None:
    # The partial index covers only `queued/running`; a Failed or
    # Succeeded row must NOT block a new build of the same kind.
    client = ServiceClient.objects.create(
        scope=PrincipalScope.OPERATOR.value,
        name="packer-tester-2",
    )
    PackerBuild.objects.create(
        build_id="terminal-row",
        image_kind="kbs",
        state=PackerBuildState.FAILED.value,
        failure_reason="prior failure",
        requested_by=client,
    )
    # A fresh insert for the same image_kind in `queued` must succeed.
    new_row = PackerBuild.objects.create(
        build_id="fresh-row",
        image_kind="kbs",
        state=PackerBuildState.QUEUED.value,
        requested_by=client,
    )
    assert new_row.pk is not None


def test_presign_503_when_s3_backend_unavailable(
    authed_client: APIClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    create = authed_client.post(
        reverse("packer_build_create"), {"image_kind": "kbs"}, format="json"
    )
    build_id = create.json()["build_id"]
    PackerBuild.objects.filter(build_id=build_id).update(
        state=PackerBuildState.SUCCEEDED.value,
        artifact_sha256=GOOD_SHA,
        provenance_signed_url=GOOD_URL,
    )

    def _boom() -> None:
        raise s3_module.S3ClientUnavailable("simulated outage")

    monkeypatch.setattr(s3_module, "get_s3_client", _boom)
    resp = authed_client.post(
        reverse("packer_build_presign_get", kwargs={"build_id": build_id}),
        {},
        format="json",
    )
    assert resp.status_code == status.HTTP_503_SERVICE_UNAVAILABLE
    assert resp.json()["category"] == "internal"


# ─── Model-layer sanity checks (CHECK constraint) ───────────────────


def test_in_flight_states_constant() -> None:
    # Sanity check: the constant the view uses MUST cover both
    # pre-terminal states. A regression here would let a second
    # build kick off while one is Running.
    assert IN_FLIGHT_STATES == {"queued", "running"}
