"""`bake_queue_lock` — the golden re-bake's "nothing in flight → INSERT"
cannot be interleaved by another bake creator (F6).

Two threads, two DB connections: the re-bake is paused INSIDE its locked
check-then-insert while a `POST /v1/tenant-bakes` races it. The POST must
not commit until the re-bake has. Runs on both backends: Postgres takes
the real advisory lock (the CI Postgres lane), SQLite the process-local
stand-in. On SQLite the in-memory test DB is per connection, so the race
test needs Postgres and is skipped there.
"""

from __future__ import annotations

import socket
import threading
from datetime import timedelta
from typing import Any

import pytest
from django.db import connection, connections
from django.utils import timezone

from apps.images import rebake
from apps.images.models import GoldenImage
from apps.images.tests.conftest import _bearer_client
from apps.tenant_bake.models import TenantBake

STAMP = "20261101"


_REAL_GETADDRINFO = socket.getaddrinfo


def _public_dns(host, port, *args, **kwargs):
    """The SSRF guard resolves the base-image host; answer it with a public
    IP and leave every other name (the Postgres host!) to the resolver."""
    if host == "cloud-images.ubuntu.com":
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", port or 443))]
    return _REAL_GETADDRINFO(host, port, *args, **kwargs)


def _in_thread(target: Any) -> tuple[threading.Thread, dict[str, Any]]:
    out: dict[str, Any] = {}

    def run() -> None:
        try:
            out["result"] = target()
        except BaseException as exc:  # surfaced by the assertion below
            out["error"] = exc
        finally:
            connections.close_all()

    thread = threading.Thread(target=run)
    thread.start()
    return thread, out


@pytest.mark.django_db(transaction=True)
def test_a_post_cannot_insert_inside_the_rebake_check_to_insert(
    make_golden_bake, monkeypatch
) -> None:
    if connection.vendor != "postgresql":
        pytest.skip("needs two connections to one DB (Postgres lane)")
    monkeypatch.setattr(socket, "getaddrinfo", _public_dns)
    blessed = make_golden_bake(bake_id="blessed-ubuntu", vm_id="golden-ubuntu-dp")
    GoldenImage.objects.create(
        image_name="ubuntu", distro="ubuntu", bake_id=blessed.bake_id, blessed_at=timezone.now()
    )
    api = _bearer_client("racer")

    in_section = threading.Event()
    release = threading.Event()
    real_queue = rebake._queue

    def paused_queue(b, vm_id, stamp):
        in_section.set()
        assert release.wait(10)
        return real_queue(b, vm_id, stamp)

    monkeypatch.setattr(rebake, "_queue", paused_queue)
    timing = rebake.Timing(
        poll_interval_s=0.01, idle_timeout_s=5, bake_timeout_s=5, orphan_running_after_s=21600
    )
    vm_id = f"golden-ubuntu-rebake-{STAMP}"
    r_thread, r_out = _in_thread(
        lambda: rebake._queue_when_idle(blessed, vm_id, STAMP, timing, "ubuntu")
    )
    assert in_section.wait(10)

    body = {
        "vm_id": "tenant-racer",
        "base_image_url": "https://cloud-images.ubuntu.com/noble/20260801/noble-server-cloudimg-amd64.img",
        "base_image_sha256": "a" * 64,
        "size_gb": 10,
        "kek_vault_path": "secret/x/luks-kek",
        "s3_output_bucket": "hippius-compute-images",
        "s3_output_prefix": "tenant/tenant-racer/",
    }
    h_thread, h_out = _in_thread(lambda: api.post("/v1/tenant-bakes", body, format="json"))
    h_thread.join(timeout=1.0)
    assert h_thread.is_alive(), "the POST committed while the re-bake held the lock"
    assert not TenantBake.objects.filter(vm_id="tenant-racer").exists()

    release.set()
    r_thread.join(timeout=10)
    h_thread.join(timeout=10)
    assert "error" not in r_out and "error" not in h_out, (r_out, h_out)
    assert h_out["result"].status_code == 202
    ours = TenantBake.objects.get(vm_id=f"golden-ubuntu-rebake-{STAMP}")
    theirs = TenantBake.objects.get(vm_id="tenant-racer")
    # The POST landed AFTER the re-bake row — the spawner's serial gate then
    # holds it until the re-bake is terminal.
    assert theirs.requested_at > ours.requested_at


@pytest.mark.django_db
def test_lock_is_taken_by_the_http_create_path(monkeypatch) -> None:
    """The HTTP create goes through `bake_queue_lock` (both backends)."""
    from apps.tenant_bake import views

    monkeypatch.setattr(socket, "getaddrinfo", _public_dns)
    taken: list[bool] = []
    real = views.bake_queue_lock

    def spy():
        taken.append(True)
        return real()

    monkeypatch.setattr(views, "bake_queue_lock", spy)
    api = _bearer_client("poster")
    resp = api.post(
        "/v1/tenant-bakes",
        {
            "vm_id": "tenant-a",
            "base_image_url": "https://cloud-images.ubuntu.com/noble/20260801/noble-server-cloudimg-amd64.img",
            "base_image_sha256": "a" * 64,
            "size_gb": 10,
            "kek_vault_path": "secret/x/luks-kek",
            "s3_output_bucket": "hippius-compute-images",
            "s3_output_prefix": "tenant/tenant-a/",
        },
        format="json",
    )
    assert resp.status_code == 202, resp.content
    assert taken == [True]


@pytest.mark.django_db
def test_close_orphan_closes_an_old_running_bake(make_golden_bake) -> None:
    from django.core.management import call_command

    bake = make_golden_bake(bake_id="p4", vm_id="bake-orphan", state="running")
    TenantBake.objects.filter(pk=bake.pk).update(started_at=timezone.now() - timedelta(days=80))
    call_command("vali_tenant_bake_close_orphan", "p4", "--reason", "pod gone since 2026-07-08")
    bake.refresh_from_db()
    assert bake.state == "failed"
    assert bake.failure_reason.startswith("orphan closed by operator: pod gone")
    assert bake.version == 2


@pytest.mark.django_db
@pytest.mark.parametrize(
    ("state", "age"),
    [("queued", timedelta(days=80)), ("running", timedelta(minutes=5)), ("succeeded", None)],
)
def test_close_orphan_refuses(make_golden_bake, state: str, age: timedelta | None) -> None:
    from django.core.management import call_command
    from django.core.management.base import CommandError

    bake = make_golden_bake(bake_id="x", vm_id="x", state=state)
    if age is not None:
        TenantBake.objects.filter(pk=bake.pk).update(started_at=timezone.now() - age)
    with pytest.raises(CommandError):
        call_command("vali_tenant_bake_close_orphan", "x", "--reason", "test")
    bake.refresh_from_db()
    assert bake.state == state
