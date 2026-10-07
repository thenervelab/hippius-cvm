"""Integration tests for the tenant_bake endpoints.

Uses DRF's `APIClient`. Mirrors `apps.packer.tests.test_views`
patterns deliberately — a reviewer who knows that file reads this
one in O(1).
"""

from __future__ import annotations

import socket

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
from apps.tenant_bake.models import TenantBake

pytestmark = pytest.mark.django_db


GOOD_SHA = "a" * 64
GOOD_MEASUREMENT = "b" * 96


# ─── Fixtures ───────────────────────────────────────────────────────


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
    # Worker principal name matches the override_settings used in the
    # finalize tests.
    c, _ = _make_client("tenant-baker-worker")
    return c


def _create_payload(vm_id: str = "myvm-1") -> dict:
    return {
        "vm_id": vm_id,
        # DATED (immutable) upstream directory, not `noble/current/` —
        # register #48. `current/` is refused at intake now.
        "base_image_url": "https://cloud-images.ubuntu.com/noble/20260801/noble-server-cloudimg-amd64.img",
        "base_image_sha256": GOOD_SHA,
        "size_gb": 10,
        "kek_vault_path": f"secret/hippius-compute/kbs/tenants/{vm_id}/luks-kek",
        "s3_output_bucket": "hippius-compute-images",
        "s3_output_prefix": f"tenant/{vm_id}/",
    }


# ─── POST /v1/tenant-bakes ──────────────────────────────────────────


def test_create_bake_unauthenticated_rejected() -> None:
    c = APIClient()
    resp = c.post(reverse("tenant_bake_create"), _create_payload(), format="json")
    assert resp.status_code in (
        status.HTTP_401_UNAUTHORIZED,
        status.HTTP_403_FORBIDDEN,
    )


def test_create_bake_happy_path(authed_client: APIClient) -> None:
    resp = authed_client.post(
        reverse("tenant_bake_create"), _create_payload(), format="json"
    )
    assert resp.status_code == status.HTTP_202_ACCEPTED, resp.content
    body = resp.json()
    assert body["vm_id"] == "myvm-1"
    assert body["state"] == "queued"
    assert body["version"] == 1
    assert body["qcow2_sha256"] is None
    assert body["measurement_hex"] is None
    assert TenantBake.objects.count() == 1


def test_create_bake_does_not_spawn_inline(
    authed_client: APIClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    # RA-N9 — the HTTP create path must NOT create the (privileged) baker
    # k8s Job; it only queues the row. The vali web pod holds no k8s
    # token, so a web-tier RCE can't spawn a privileged Job to escalate.
    from apps.tenant_bake import k8s_jobs

    calls: list = []
    monkeypatch.setattr(k8s_jobs, "spawn_bake_job", lambda row: calls.append(row))
    resp = authed_client.post(
        reverse("tenant_bake_create"), _create_payload(), format="json"
    )
    assert resp.status_code == status.HTTP_202_ACCEPTED, resp.content
    assert resp.json()["state"] == "queued"
    assert TenantBake.objects.count() == 1
    assert calls == [], "the view must not spawn the Job inline (RA-N9)"


def test_bake_spawn_worker_spawns_queued(
    authed_client: APIClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    # RA-N9 — the dedicated vali_bake_spawn worker (the sole holder of the
    # create-jobs SA) spawns Queued bakes; the view does not.
    from apps.tenant_bake import k8s_jobs
    from apps.tenant_bake.management.commands.vali_bake_spawn import (
        spawn_queued_bakes,
    )

    calls: list = []
    monkeypatch.setattr(
        k8s_jobs, "spawn_bake_job", lambda row: calls.append(row.bake_id)
    )
    resp = authed_client.post(
        reverse("tenant_bake_create"), _create_payload(), format="json"
    )
    assert resp.status_code == status.HTTP_202_ACCEPTED
    assert calls == []  # not spawned by the view

    assert spawn_queued_bakes() == 1  # the worker sweep spawns it
    row = TenantBake.objects.get()
    assert calls == [row.bake_id]


def test_create_bake_rejects_missing_required_field(
    authed_client: APIClient,
) -> None:
    payload = _create_payload()
    del payload["base_image_sha256"]
    resp = authed_client.post(reverse("tenant_bake_create"), payload, format="json")
    assert resp.status_code == status.HTTP_400_BAD_REQUEST
    assert resp.json()["category"] == "wire"


@pytest.mark.parametrize(
    "bad_url",
    [
        # Cloud metadata. NB the real IMDS path is `/latest/meta-data/`,
        # but `latest/` now trips the register #48 mutable-URL gate first
        # — which would make this case pass for the WRONG reason. Keep
        # every URL here free of moving-pointer segments so each one
        # actually exercises the SSRF rule it is here to test.
        "http://169.254.169.254/imds/meta-data/",
        "https://169.254.169.254/",  # metadata over TLS
        "http://10.0.0.5/img.qcow2",  # RFC-1918
        "https://192.168.1.10/img",  # RFC-1918
        "http://172.16.0.1/img",  # RFC-1918
        "http://127.0.0.1:8200/v1/secret",  # loopback (Vault!)
        "http://[::1]/img",  # IPv6 loopback
        "http://[fd00::1]/img",  # IPv6 ULA (is_private)
        "https://0.0.0.0/img",  # unspecified
        "file:///etc/passwd",  # non-http scheme
        "gopher://evil/img",  # non-http scheme
        "https://user:pass@cloud-images.ubuntu.com/img",  # embedded creds
        "https://cloud-images.ubuntu.com:notaport/img",  # malformed port
    ],
)
def test_create_bake_rejects_ssrf_base_image_url(
    authed_client: APIClient, bad_url: str
) -> None:
    # Audit M-SSRF: the baker fetches base_image_url server-side, so a URL
    # targeting the metadata endpoint / RFC-1918 / loopback / a non-http
    # scheme / embedded creds must be refused BEFORE any bake row/Job.
    payload = _create_payload()
    payload["base_image_url"] = bad_url
    resp = authed_client.post(
        reverse("tenant_bake_create"), payload, format="json"
    )
    assert resp.status_code == status.HTTP_400_BAD_REQUEST, (bad_url, resp.content)
    assert resp.json()["category"] == "bad-field", bad_url
    assert TenantBake.objects.count() == 0, bad_url


# ─── register #48 — mutable base_image_url is refused at intake ─────
#
# A `base_image_sha256` pin and a moving upstream path are contradictory:
# the pin says "these exact bytes", `latest/` says "whatever is newest".
# The pair breaks on every upstream point release, and the break is
# indistinguishable from a supply-chain compromise — which is what cost
# three cycles. Refuse it at intake, before 2 GB is pulled.


@pytest.mark.parametrize(
    "mutable_url",
    [
        # The exact URL that bit us (Debian trixie moving symlink).
        "https://gemmei.ftp.acc.umu.se/images/cloud/trixie/latest/debian-13-genericcloud-amd64.qcow2",
        # The one still in the live catalog at the time of writing.
        "https://cloud-images.ubuntu.com/noble/current/noble-server-cloudimg-amd64.img",
        # Moving pointer spelled as a FILENAME token on an otherwise
        # static path — CentOS publishes exactly this.
        "https://cloud.centos.org/centos/10-stream/x86_64/images/CentOS-Stream-GenericCloud-10-latest.x86_64.qcow2",
        # Other conventional moving directories.
        "https://cloud-images.ubuntu.com/daily/server/noble/20260801/img.qcow2",
        "https://mirror.example/images/nightly/base.qcow2",
        "https://deb.example.org/debian/dists/stable/main/base.qcow2",
        "https://mirror.example/fedora/linux/development/rawhide/base.qcow2",
        # Case is not an escape hatch.
        "https://mirror.example/images/LATEST/base.qcow2",
        # Nor is percent-encoding (`%6C` = 'l').
        "https://mirror.example/images/%6Catest/base.qcow2",
    ],
)
def test_create_bake_rejects_mutable_base_image_url(
    authed_client: APIClient, mutable_url: str
) -> None:
    payload = _create_payload()
    payload["base_image_url"] = mutable_url
    resp = authed_client.post(
        reverse("tenant_bake_create"), payload, format="json"
    )
    assert resp.status_code == status.HTTP_400_BAD_REQUEST, (
        mutable_url,
        resp.content,
    )
    body = resp.json()
    assert body["category"] == "bad-field", mutable_url
    # The message must explain WHY — an operator who hits this needs to go
    # looking for the dated URL, not conclude that upstream moved on them.
    error = body["error"].lower()
    assert "moving" in error, body["error"]
    assert "dated" in error, body["error"]
    assert "base_image_sha256" in body["error"], body["error"]
    assert TenantBake.objects.count() == 0, mutable_url


@pytest.mark.parametrize(
    "immutable_url",
    [
        # Debian: dated directory AND versioned filename.
        "https://gemmei.ftp.acc.umu.se/images/cloud/trixie/20260712-2537/debian-13-genericcloud-amd64-20260712-2537.qcow2",
        # Ubuntu: dated directory, UNVERSIONED filename. Immutable all the
        # same — so "the filename must look versioned" would be a wrong
        # rule that refuses every Ubuntu dated URL.
        "https://cloud-images.ubuntu.com/noble/20260801/noble-server-cloudimg-amd64.img",
        # CentOS: dated filename on a static path.
        "https://cloud.centos.org/centos/10-stream/x86_64/images/CentOS-Stream-GenericCloud-10-20260713.0.x86_64.qcow2",
        # Fedora: versioned release directory + versioned filename.
        "https://dl.fedoraproject.org/pub/fedora/linux/releases/43/Cloud/x86_64/images/Fedora-Cloud-Base-Generic-43-1.6.x86_64.qcow2",
        # An unadorned path. Not provably immutable, but nothing upstream
        # documents it as moving — an ALLOWLIST of "looks versioned" would
        # refuse this, and a gate that refuses valid URLs gets disabled.
        "https://s3.example/hippius/base.qcow2",
    ],
)
def test_create_bake_accepts_immutable_base_image_url(
    authed_client: APIClient, immutable_url: str
) -> None:
    # The false-positive direction, and the one that decides whether the
    # gate survives contact with operators.
    payload = _create_payload()
    payload["base_image_url"] = immutable_url
    resp = authed_client.post(
        reverse("tenant_bake_create"), payload, format="json"
    )
    assert resp.status_code == status.HTTP_202_ACCEPTED, (
        immutable_url,
        resp.content,
    )
    assert TenantBake.objects.count() == 1, immutable_url


@pytest.mark.parametrize(
    "url",
    [
        # "latest" inside a longer DIRECTORY name.
        "https://mirror.example/latestimages/20260801/base.qcow2",
        "https://mirror.example/testingground/20260801/base.qcow2",
        # "latest" inside a longer FILENAME word (filename tokens split on
        # -, _ and . only, so this is one token: `nolatestpin`).
        "https://mirror.example/images/20260801/nolatestpin-cloudimg-amd64.img",
        # "current"/"stable" likewise embedded in longer words.
        "https://mirror.example/concurrent/20260801/base.qcow2",
        "https://mirror.example/images/20260801/unstableized-amd64.img",
    ],
)
def test_create_bake_accepts_mutable_word_inside_longer_segment(
    authed_client: APIClient, url: str
) -> None:
    # Substring matching would refuse all of these. The rule matches whole
    # path SEGMENTS (and, for the filename only, whole -/_/. tokens).
    payload = _create_payload()
    payload["base_image_url"] = url
    resp = authed_client.post(reverse("tenant_bake_create"), payload, format="json")
    assert resp.status_code == status.HTTP_202_ACCEPTED, (url, resp.content)
    assert TenantBake.objects.count() == 1, url


def test_create_bake_mutable_url_refused_before_any_fetch(
    authed_client: APIClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    # The whole point of gating at INTAKE is that a bake which cannot
    # succeed never reaches the network. Prove the refusal happens before
    # even DNS resolution (the earliest network touch on this path), let
    # alone the baker Job's ~2 GB GET.
    from apps.tenant_bake import k8s_jobs

    dns_calls: list = []
    spawns: list = []

    def _recording_getaddrinfo(host, port, *a, **k):
        dns_calls.append(host)
        raise AssertionError(f"DNS resolved {host!r} for a mutable URL")

    monkeypatch.setattr(socket, "getaddrinfo", _recording_getaddrinfo)
    monkeypatch.setattr(k8s_jobs, "spawn_bake_job", lambda row: spawns.append(row))

    payload = _create_payload()
    payload["base_image_url"] = (
        "https://gemmei.ftp.acc.umu.se/images/cloud/trixie/latest/"
        "debian-13-genericcloud-amd64.qcow2"
    )
    resp = authed_client.post(reverse("tenant_bake_create"), payload, format="json")

    assert resp.status_code == status.HTTP_400_BAD_REQUEST, resp.content
    assert dns_calls == [], dns_calls
    assert spawns == []
    assert TenantBake.objects.count() == 0


def test_create_bake_is_rate_limited(
    authed_client: APIClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Audit M-ratelimit: the bake-create endpoint is per-client rate
    # limited. `SimpleRateThrottle.THROTTLE_RATES` is a CLASS attribute
    # bound at import, so `override_settings` can't reach it — patch the
    # class rate to a tiny value so the 3rd request trips the throttle.
    from rest_framework.throttling import ScopedRateThrottle

    monkeypatch.setattr(
        ScopedRateThrottle,
        "THROTTLE_RATES",
        {"bake_create": "2/min", "vm_launch": "2/min"},
    )
    codes = []
    for i in range(3):
        resp = authed_client.post(
            reverse("tenant_bake_create"),
            _create_payload(vm_id=f"rl-{i}"),
            format="json",
        )
        codes.append(resp.status_code)
    # The throttle is checked at dispatch (before the handler), so the
    # first two consume the 2/min budget regardless of their body outcome,
    # and the third is refused.
    assert status.HTTP_429_TOO_MANY_REQUESTS not in codes[:2], codes
    assert codes[2] == status.HTTP_429_TOO_MANY_REQUESTS, codes


def test_create_bake_rejects_hostname_resolving_to_private(
    authed_client: APIClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    # A public-looking hostname that RESOLVES to a private IP must be
    # blocked (DNS-based SSRF), and every A/AAAA record is checked.
    def _resolves_private(host, port, *a, **k):
        return [
            (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("93.184.216.34", 0)),
            (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("169.254.169.254", 0)),
        ]

    monkeypatch.setattr(socket, "getaddrinfo", _resolves_private)
    payload = _create_payload()
    payload["base_image_url"] = "https://images.evil.example/img.qcow2"
    resp = authed_client.post(
        reverse("tenant_bake_create"), payload, format="json"
    )
    assert resp.status_code == status.HTTP_400_BAD_REQUEST, resp.content
    assert resp.json()["category"] == "bad-field"
    assert TenantBake.objects.count() == 0


def test_create_bake_rejects_invalid_vm_id_chars(authed_client: APIClient) -> None:
    payload = _create_payload(vm_id="my VM 1")  # space is invalid
    resp = authed_client.post(reverse("tenant_bake_create"), payload, format="json")
    assert resp.status_code == status.HTTP_400_BAD_REQUEST
    assert resp.json()["category"] == "bad-field"


def test_create_bake_rejects_invalid_sha(authed_client: APIClient) -> None:
    payload = _create_payload()
    payload["base_image_sha256"] = "G" * 64  # not lowercase hex
    resp = authed_client.post(reverse("tenant_bake_create"), payload, format="json")
    assert resp.status_code == status.HTTP_400_BAD_REQUEST
    assert resp.json()["category"] == "bad-field"


def test_create_bake_rejects_zero_size(authed_client: APIClient) -> None:
    payload = _create_payload()
    payload["size_gb"] = 0
    resp = authed_client.post(reverse("tenant_bake_create"), payload, format="json")
    assert resp.status_code == status.HTTP_400_BAD_REQUEST
    assert resp.json()["category"] == "bad-field"


def test_create_bake_rejects_unknown_field(authed_client: APIClient) -> None:
    payload = _create_payload()
    payload["bonus_field"] = "should-be-rejected"
    resp = authed_client.post(reverse("tenant_bake_create"), payload, format="json")
    assert resp.status_code == status.HTTP_400_BAD_REQUEST
    body = resp.json()
    assert body["category"] == "wire"
    assert "bonus_field" in body["error"]


def test_create_bake_409_when_active_for_same_vm_id(
    authed_client: APIClient,
) -> None:
    resp1 = authed_client.post(
        reverse("tenant_bake_create"), _create_payload(), format="json"
    )
    assert resp1.status_code == status.HTTP_202_ACCEPTED
    first_id = resp1.json()["bake_id"]

    resp2 = authed_client.post(
        reverse("tenant_bake_create"), _create_payload(), format="json"
    )
    assert resp2.status_code == status.HTTP_409_CONFLICT
    body = resp2.json()
    assert body["category"] == "already-in-flight"
    assert body["active"]["bake_id"] == first_id


def test_create_bake_allows_concurrent_bakes_for_distinct_vm_ids(
    authed_client: APIClient,
) -> None:
    # vm_id regex enforces lowercase only — test fixture mirrors that.
    resp1 = authed_client.post(
        reverse("tenant_bake_create"), _create_payload("vm-a"), format="json"
    )
    resp2 = authed_client.post(
        reverse("tenant_bake_create"), _create_payload("vm-b"), format="json"
    )
    assert resp1.status_code == status.HTTP_202_ACCEPTED
    assert resp2.status_code == status.HTTP_202_ACCEPTED
    assert TenantBake.objects.count() == 2


# ─── GET /v1/tenant-bakes/<bake_id> ─────────────────────────────────


def test_detail_happy_path(authed_client: APIClient) -> None:
    create_resp = authed_client.post(
        reverse("tenant_bake_create"), _create_payload(), format="json"
    )
    bake_id = create_resp.json()["bake_id"]
    resp = authed_client.get(reverse("tenant_bake_detail", args=[bake_id]))
    assert resp.status_code == status.HTTP_200_OK
    body = resp.json()
    assert body["bake_id"] == bake_id
    assert body["state"] == "queued"


def test_detail_404_for_unknown(authed_client: APIClient) -> None:
    resp = authed_client.get(reverse("tenant_bake_detail", args=["deadbeef"]))
    assert resp.status_code == status.HTTP_404_NOT_FOUND


# ─── POST /v1/tenant-bakes/<bake_id>/finalize ──────────────────────


@override_settings(VALI_TENANT_BAKE_WORKER_PRINCIPAL="tenant-baker-worker")
def test_finalize_non_worker_rejected(
    authed_client: APIClient, worker_client: APIClient
) -> None:
    # Create as the orchestrator …
    resp = authed_client.post(
        reverse("tenant_bake_create"), _create_payload(), format="json"
    )
    bake_id = resp.json()["bake_id"]

    # … then try to finalize as the SAME non-worker client.
    resp = authed_client.post(
        reverse("tenant_bake_finalize", args=[bake_id]),
        {"to_state": "running", "if_version": 1},
        format="json",
    )
    assert resp.status_code == status.HTTP_403_FORBIDDEN


@override_settings(VALI_TENANT_BAKE_WORKER_PRINCIPAL="tenant-baker-worker")
def test_finalize_running_happy_path(
    authed_client: APIClient, worker_client: APIClient
) -> None:
    resp = authed_client.post(
        reverse("tenant_bake_create"), _create_payload(), format="json"
    )
    bake_id = resp.json()["bake_id"]
    resp = worker_client.post(
        reverse("tenant_bake_finalize", args=[bake_id]),
        {"to_state": "running", "if_version": 1},
        format="json",
    )
    assert resp.status_code == status.HTTP_200_OK, resp.content
    body = resp.json()
    assert body["state"] == "running"
    assert body["version"] == 2
    assert body["started_at"] is not None


@override_settings(VALI_TENANT_BAKE_WORKER_PRINCIPAL="tenant-baker-worker")
def test_finalize_succeeded_happy_path(
    authed_client: APIClient, worker_client: APIClient
) -> None:
    resp = authed_client.post(
        reverse("tenant_bake_create"), _create_payload(), format="json"
    )
    bake_id = resp.json()["bake_id"]
    # Claim → Running
    worker_client.post(
        reverse("tenant_bake_finalize", args=[bake_id]),
        {"to_state": "running", "if_version": 1},
        format="json",
    )
    # Running → Succeeded
    resp = worker_client.post(
        reverse("tenant_bake_finalize", args=[bake_id]),
        {
            "to_state": "succeeded",
            "if_version": 2,
            "qcow2_sha256": GOOD_SHA,
            "kernel_sha256": GOOD_SHA,
            "initrd_sha256": GOOD_SHA,
            "measurement_hex": GOOD_MEASUREMENT,
        },
        format="json",
    )
    assert resp.status_code == status.HTTP_200_OK, resp.content
    body = resp.json()
    assert body["state"] == "succeeded"
    assert body["version"] == 3
    assert body["qcow2_sha256"] == GOOD_SHA
    assert body["measurement_hex"] == GOOD_MEASUREMENT
    assert body["finished_at"] is not None


@override_settings(VALI_TENANT_BAKE_WORKER_PRINCIPAL="tenant-baker-worker")
def test_finalize_failed_happy_path(
    authed_client: APIClient, worker_client: APIClient
) -> None:
    resp = authed_client.post(
        reverse("tenant_bake_create"), _create_payload(), format="json"
    )
    bake_id = resp.json()["bake_id"]
    worker_client.post(
        reverse("tenant_bake_finalize", args=[bake_id]),
        {"to_state": "running", "if_version": 1},
        format="json",
    )
    resp = worker_client.post(
        reverse("tenant_bake_finalize", args=[bake_id]),
        {
            "to_state": "failed",
            "if_version": 2,
            "failure_reason": "qemu-img convert returned 1",
        },
        format="json",
    )
    assert resp.status_code == status.HTTP_200_OK, resp.content
    body = resp.json()
    assert body["state"] == "failed"
    assert body["failure_reason"] == "qemu-img convert returned 1"


@override_settings(VALI_TENANT_BAKE_WORKER_PRINCIPAL="tenant-baker-worker")
def test_finalize_rejects_stale_if_version(
    authed_client: APIClient, worker_client: APIClient
) -> None:
    resp = authed_client.post(
        reverse("tenant_bake_create"), _create_payload(), format="json"
    )
    bake_id = resp.json()["bake_id"]
    # Claim → Running (version 1 → 2).
    resp = worker_client.post(
        reverse("tenant_bake_finalize", args=[bake_id]),
        {"to_state": "running", "if_version": 1},
        format="json",
    )
    assert resp.status_code == status.HTTP_200_OK
    # Running → Succeeded is a LEGAL transition, but with the stale
    # if_version=1 the CAS must lose with 409 (not 400 — the
    # illegal-transition check passes first, the CAS gate fails second).
    resp = worker_client.post(
        reverse("tenant_bake_finalize", args=[bake_id]),
        {
            "to_state": "succeeded",
            "if_version": 1,
            "qcow2_sha256": GOOD_SHA,
            "kernel_sha256": GOOD_SHA,
            "initrd_sha256": GOOD_SHA,
            "measurement_hex": GOOD_MEASUREMENT,
        },
        format="json",
    )
    assert resp.status_code == status.HTTP_409_CONFLICT
    assert resp.json()["category"] == "version-conflict"


@override_settings(VALI_TENANT_BAKE_WORKER_PRINCIPAL="tenant-baker-worker")
def test_finalize_rejects_illegal_transition(
    authed_client: APIClient, worker_client: APIClient
) -> None:
    resp = authed_client.post(
        reverse("tenant_bake_create"), _create_payload(), format="json"
    )
    bake_id = resp.json()["bake_id"]
    # Queued → Succeeded is illegal (must claim Running first).
    resp = worker_client.post(
        reverse("tenant_bake_finalize", args=[bake_id]),
        {
            "to_state": "succeeded",
            "if_version": 1,
            "qcow2_sha256": GOOD_SHA,
            "kernel_sha256": GOOD_SHA,
            "initrd_sha256": GOOD_SHA,
            "measurement_hex": GOOD_MEASUREMENT,
        },
        format="json",
    )
    assert resp.status_code == status.HTTP_400_BAD_REQUEST
    assert resp.json()["category"] == "illegal-transition"


@override_settings(VALI_TENANT_BAKE_WORKER_PRINCIPAL="tenant-baker-worker")
def test_finalize_running_does_not_require_artifacts(
    authed_client: APIClient, worker_client: APIClient
) -> None:
    # The Queued→Running worker-claim must NOT require artefact SHAs;
    # those land at Running→Succeeded.
    resp = authed_client.post(
        reverse("tenant_bake_create"), _create_payload(), format="json"
    )
    bake_id = resp.json()["bake_id"]
    resp = worker_client.post(
        reverse("tenant_bake_finalize", args=[bake_id]),
        {"to_state": "running", "if_version": 1},
        format="json",
    )
    assert resp.status_code == status.HTTP_200_OK


@override_settings(VALI_TENANT_BAKE_WORKER_PRINCIPAL="tenant-baker-worker")
def test_finalize_rejects_unknown_field(
    authed_client: APIClient, worker_client: APIClient
) -> None:
    resp = authed_client.post(
        reverse("tenant_bake_create"), _create_payload(), format="json"
    )
    bake_id = resp.json()["bake_id"]
    resp = worker_client.post(
        reverse("tenant_bake_finalize", args=[bake_id]),
        {"to_state": "running", "if_version": 1, "rogue": True},
        format="json",
    )
    assert resp.status_code == status.HTTP_400_BAD_REQUEST
    assert resp.json()["category"] == "wire"


# ─── After-succeeded reuse / state isolation ───────────────────────


@override_settings(VALI_TENANT_BAKE_WORKER_PRINCIPAL="tenant-baker-worker")
def test_create_then_finalize_full_lifecycle_e2e(
    authed_client: APIClient,
    worker_client: APIClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """End-to-end happy path with the k8s spawn enabled — exercises
    the create→spawn→running→succeeded chain and asserts the spawn
    actually fires when `VALI_TENANT_BAKE_K8S_ENABLED=true`.

    The kubernetes SDK is mocked at the import boundary inside the
    spawn module — `test_k8s_jobs.py` covers the rest of that
    surface. Here we just need the spawn call to succeed so the
    view can return 202.
    """
    from apps.tenant_bake.tests.test_k8s_jobs import _install_fake_kubernetes

    fake = _install_fake_kubernetes(monkeypatch, behaviour="ok")
    monkeypatch.setenv("KUBERNETES_SERVICE_HOST", "10.0.0.1")
    from apps.tenant_bake.management.commands.vali_bake_spawn import (
        spawn_queued_bakes,
    )

    with override_settings(VALI_TENANT_BAKE_K8S_ENABLED=True):
        # 1. Operator (authed_client) requests a bake — the view QUEUES
        #    the row but does NOT spawn the k8s Job (RA-N9).
        resp = authed_client.post(
            reverse("tenant_bake_create"), _create_payload(), format="json"
        )
        assert resp.status_code == status.HTTP_202_ACCEPTED, resp.content
        bake_id = resp.json()["bake_id"]
        fake["BatchV1Api"]._instance.create_namespaced_job.assert_not_called()

        # 2. The vali_bake_spawn worker (the sole create-jobs holder)
        #    spawns the Queued bake's Job carrying its parameters in env.
        assert spawn_queued_bakes() == 1
        fake["BatchV1Api"]._instance.create_namespaced_job.assert_called_once()
        body = fake["BatchV1Api"]._instance.create_namespaced_job.call_args.kwargs[
            "body"
        ]
        assert body["metadata"]["name"] == f"tenant-bake-{bake_id}"

    # 3. Baker pod claims the row via /finalize → Running.
    resp = worker_client.post(
        reverse("tenant_bake_finalize", args=[bake_id]),
        {"to_state": "running", "if_version": 1},
        format="json",
    )
    assert resp.status_code == status.HTTP_200_OK

    # 4. Baker pod completes + POSTs the artefacts.
    resp = worker_client.post(
        reverse("tenant_bake_finalize", args=[bake_id]),
        {
            "to_state": "succeeded",
            "if_version": 2,
            "qcow2_sha256": GOOD_SHA,
            "kernel_sha256": GOOD_SHA,
            "initrd_sha256": GOOD_SHA,
            "measurement_hex": GOOD_MEASUREMENT,
        },
        format="json",
    )
    assert resp.status_code == status.HTTP_200_OK
    final = resp.json()
    assert final["state"] == "succeeded"
    assert final["qcow2_sha256"] == GOOD_SHA
    assert final["measurement_hex"] == GOOD_MEASUREMENT


def test_create_queues_even_when_k8s_unavailable(
    authed_client: APIClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    """RA-N9 — the view NEVER touches k8s (it does not spawn), so it
    queues the row (202) even when k8s is down. Spawning — and any k8s
    failure — is the `vali_bake_spawn` worker's concern, and the row
    stays Queued for it to (idempotently) retry.
    """
    from apps.tenant_bake.tests.test_k8s_jobs import _install_fake_kubernetes

    fake = _install_fake_kubernetes(monkeypatch, behaviour="server-error")
    monkeypatch.setenv("KUBERNETES_SERVICE_HOST", "10.0.0.1")
    with override_settings(VALI_TENANT_BAKE_K8S_ENABLED=True):
        resp = authed_client.post(
            reverse("tenant_bake_create"), _create_payload(), format="json"
        )
        assert resp.status_code == status.HTTP_202_ACCEPTED, resp.content
        assert resp.json()["state"] == "queued"
        assert TenantBake.objects.count() == 1
        # The view did not call the k8s API at all.
        fake["BatchV1Api"]._instance.create_namespaced_job.assert_not_called()


@override_settings(VALI_TENANT_BAKE_WORKER_PRINCIPAL="tenant-baker-worker")
def test_new_bake_allowed_after_previous_terminal(
    authed_client: APIClient, worker_client: APIClient
) -> None:
    # First bake completes …
    resp = authed_client.post(
        reverse("tenant_bake_create"), _create_payload(), format="json"
    )
    bake_id = resp.json()["bake_id"]
    worker_client.post(
        reverse("tenant_bake_finalize", args=[bake_id]),
        {"to_state": "running", "if_version": 1},
        format="json",
    )
    worker_client.post(
        reverse("tenant_bake_finalize", args=[bake_id]),
        {
            "to_state": "succeeded",
            "if_version": 2,
            "qcow2_sha256": GOOD_SHA,
            "kernel_sha256": GOOD_SHA,
            "initrd_sha256": GOOD_SHA,
            "measurement_hex": GOOD_MEASUREMENT,
        },
        format="json",
    )
    # … then a fresh bake for the SAME vm_id is allowed (the previous
    # row is terminal, so the partial unique index doesn't fire).
    resp = authed_client.post(
        reverse("tenant_bake_create"), _create_payload(), format="json"
    )
    assert resp.status_code == status.HTTP_202_ACCEPTED, resp.content
    assert TenantBake.objects.count() == 2


# ─── golden-bake PR6 — disk_mode create + golden finalize ───────────


def _golden_create_payload(vm_id: str = "golden-ubuntu-1") -> dict:
    p = _create_payload(vm_id)
    p["disk_mode"] = "golden_verity_overlay"
    return p


def test_create_golden_persists_disk_mode(authed_client: APIClient) -> None:
    resp = authed_client.post(
        reverse("tenant_bake_create"), _golden_create_payload(), format="json"
    )
    assert resp.status_code == status.HTTP_202_ACCEPTED, resp.content
    body = resp.json()
    assert body["disk_mode"] == "golden_verity_overlay"
    row = TenantBake.objects.get(bake_id=body["bake_id"])
    assert row.disk_mode == "golden_verity_overlay"


def test_create_defaults_disk_mode_legacy(authed_client: APIClient) -> None:
    resp = authed_client.post(
        reverse("tenant_bake_create"), _create_payload(), format="json"
    )
    assert resp.json()["disk_mode"] == "legacy_luks"


def test_create_rejects_bad_disk_mode(authed_client: APIClient) -> None:
    payload = _create_payload()
    payload["disk_mode"] = "bogus"
    resp = authed_client.post(
        reverse("tenant_bake_create"), payload, format="json"
    )
    assert resp.status_code == status.HTTP_400_BAD_REQUEST


@override_settings(VALI_TENANT_BAKE_WORKER_PRINCIPAL="tenant-baker-worker")
def test_finalize_golden_succeeded_happy_path(
    authed_client: APIClient, worker_client: APIClient
) -> None:
    resp = authed_client.post(
        reverse("tenant_bake_create"), _golden_create_payload(), format="json"
    )
    bake_id = resp.json()["bake_id"]
    worker_client.post(
        reverse("tenant_bake_finalize", args=[bake_id]),
        {"to_state": "running", "if_version": 1},
        format="json",
    )
    # Golden finalize: verity fields + kernel + initrd, NO qcow2.
    resp = worker_client.post(
        reverse("tenant_bake_finalize", args=[bake_id]),
        {
            "to_state": "succeeded",
            "if_version": 2,
            "rootfs_img_sha256": "a1" * 32,
            "rootfs_verity_sha256": "b2" * 32,
            "verity_root_hash": "c3" * 32,
            "kernel_sha256": GOOD_SHA,
            "initrd_sha256": GOOD_SHA,
        },
        format="json",
    )
    assert resp.status_code == status.HTTP_200_OK, resp.content
    body = resp.json()
    assert body["state"] == "succeeded"
    assert body["rootfs_img_sha256"] == "a1" * 32
    assert body["rootfs_verity_sha256"] == "b2" * 32
    assert body["verity_root_hash"] == "c3" * 32
    assert body["qcow2_sha256"] is None
    row = TenantBake.objects.get(bake_id=bake_id)
    assert row.qcow2_sha256 == ""  # golden stores no qcow2


@override_settings(VALI_TENANT_BAKE_WORKER_PRINCIPAL="tenant-baker-worker")
def test_finalize_golden_rejects_missing_verity(
    authed_client: APIClient, worker_client: APIClient
) -> None:
    resp = authed_client.post(
        reverse("tenant_bake_create"), _golden_create_payload(), format="json"
    )
    bake_id = resp.json()["bake_id"]
    worker_client.post(
        reverse("tenant_bake_finalize", args=[bake_id]),
        {"to_state": "running", "if_version": 1},
        format="json",
    )
    # verity_root_hash present (selects golden) but rootfs shas missing.
    resp = worker_client.post(
        reverse("tenant_bake_finalize", args=[bake_id]),
        {
            "to_state": "succeeded",
            "if_version": 2,
            "verity_root_hash": "c3" * 32,
            "kernel_sha256": GOOD_SHA,
            "initrd_sha256": GOOD_SHA,
        },
        format="json",
    )
    assert resp.status_code == status.HTTP_400_BAD_REQUEST


# ─── CDN plan I3 — bake profile ──────────────────────────────────────


def test_create_defaults_profile_standard(authed_client: APIClient) -> None:
    resp = authed_client.post(
        reverse("tenant_bake_create"), _golden_create_payload("prof-default-1"), format="json"
    )
    assert resp.status_code == status.HTTP_202_ACCEPTED, resp.content
    assert resp.json()["profile"] == "standard"
    assert TenantBake.objects.get(bake_id=resp.json()["bake_id"]).profile == "standard"


def test_create_cdn_node_profile(authed_client: APIClient, settings) -> None:
    settings.VALI_CDN_BACKEND_URL = "https://api.example.invalid"
    p = _golden_create_payload("cdn-node-bake-1")
    p["profile"] = "cdn-node"
    resp = authed_client.post(reverse("tenant_bake_create"), p, format="json")
    assert resp.status_code == status.HTTP_202_ACCEPTED, resp.content
    assert resp.json()["profile"] == "cdn-node"
    row = TenantBake.objects.get(bake_id=resp.json()["bake_id"])
    assert row.cdn_backend_url == "https://api.example.invalid"


@pytest.mark.parametrize(
    "mutate,backend",
    [
        # Not golden.
        (lambda p: p.update(profile="cdn-node"), "https://api.example.invalid"),
        # Golden but no backend URL configured.
        (lambda p: p.update(profile="cdn-node", disk_mode="golden_verity_overlay"), ""),
        # Unknown profile.
        (lambda p: p.update(profile="vpn", disk_mode="golden_verity_overlay"), "https://x.invalid"),
    ],
)
def test_create_refuses_bad_profiles(authed_client: APIClient, settings, mutate, backend) -> None:
    settings.VALI_CDN_BACKEND_URL = backend
    p = _create_payload("cdn-bad-1")
    mutate(p)
    resp = authed_client.post(reverse("tenant_bake_create"), p, format="json")
    assert resp.status_code == status.HTTP_400_BAD_REQUEST, resp.content
    assert not TenantBake.objects.filter(vm_id="cdn-bad-1").exists()


@pytest.mark.parametrize(
    "backend",
    [
        "https://api.hippius.com/",  # trailing slash: the agent appends /api/cdn/node/...
        "https://api.hippius.com/api",  # a path
        "http://api.hippius.com",  # not https
        "https://API.hippius.com",  # not lower case
        "https://user@api.hippius.com",  # userinfo
        "https://api.hippius.com?x=1",  # query
        "https://api.hippius.com#f",  # fragment
        " https://api.hippius.com",  # whitespace
        "https://localhost",  # not a dotted host
    ],
)
def test_a_cdn_node_bake_needs_a_bare_https_origin(
    authed_client: APIClient, settings, backend: str
) -> None:
    """VALI_CDN_BACKEND_URL is measured into the image: anything but a bare
    origin would bake a wrong URL (a double slash) for the node's life."""
    settings.VALI_CDN_BACKEND_URL = backend
    p = _golden_create_payload("cdn-origin-1")
    p["profile"] = "cdn-node"
    resp = authed_client.post(reverse("tenant_bake_create"), p, format="json")
    assert resp.status_code == status.HTTP_400_BAD_REQUEST, resp.content
    assert "bare https origin" in resp.content.decode()
    assert not TenantBake.objects.filter(vm_id="cdn-origin-1").exists()


@pytest.mark.parametrize("backend", ["https://api.hippius.com", "https://api.example.test:8443"])
def test_a_bare_origin_is_accepted(authed_client: APIClient, settings, backend: str) -> None:
    settings.VALI_CDN_BACKEND_URL = backend
    p = _golden_create_payload("cdn-origin-ok")
    p["profile"] = "cdn-node"
    resp = authed_client.post(reverse("tenant_bake_create"), p, format="json")
    assert resp.status_code == status.HTTP_202_ACCEPTED, resp.content
    assert TenantBake.objects.get(bake_id=resp.json()["bake_id"]).cdn_backend_url == backend
