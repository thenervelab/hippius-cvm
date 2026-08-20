"""Outbound job-event webhooks (#587 Phase 3)."""

from __future__ import annotations

import hashlib
import hmac

import pytest
from django.conf import settings
from django.utils import timezone

from apps.identity.models import PrincipalScope, ServiceClient
from apps.orchestration import webhook
from apps.orchestration.models import (
    LaunchJob,
    LaunchJobState,
    LaunchPhase,
    WebhookDelivery,
    WebhookDeliveryState,
)

pytestmark = pytest.mark.django_db

URL = "https://upstream.test/hooks/hippius"
SECRET = "s3cr3t-not-a-default"


@pytest.fixture
def _webhook_on(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "VALI_WEBHOOK_URL", URL)
    monkeypatch.setattr(settings, "VALI_WEBHOOK_SECRET", SECRET)


def _mk_job(state: str = LaunchJobState.SUCCEEDED.value) -> LaunchJob:
    sc = ServiceClient.objects.create(
        scope=PrincipalScope.OPERATOR.value,
        name="orchestration-root",
    )
    return LaunchJob.objects.create(
        job_id="job-1",
        vm_id="vm-1",
        tenant_id="tenant-1",
        flavor="small",
        spec_json={},
        userdata_vault_path="p",
        userdata_vault_version=1,
        kek_vault_path="k",
        state=state,
        phase_started_at=timezone.now(),
        finished_at=timezone.now(),
        miner_id="miner-1",
        decided_by=sc,
    )


def _mk_delivery(**kw) -> WebhookDelivery:
    base = dict(
        event="launch.succeeded",
        job_id="job-1",
        vm_id="vm-1",
        payload={"event": "launch.succeeded", "job_id": "job-1"},
        next_attempt_at=timezone.now(),
        max_attempts=3,
    )
    base.update(kw)
    return WebhookDelivery.objects.create(**base)


# ─── config / signing ────────────────────────────────────────────────


def test_disabled_when_unconfigured() -> None:
    assert webhook.is_enabled() is False
    assert webhook.enqueue_launch_terminal(_mk_job()) is None
    assert WebhookDelivery.objects.count() == 0


def test_sign_matches_hmac_sha256() -> None:
    body = b'{"a":1}'
    expected = "sha256=" + hmac.new(b"k", body, hashlib.sha256).hexdigest()
    assert webhook.sign(b"k", body) == expected


# ─── enqueue ─────────────────────────────────────────────────────────


def test_enqueue_creates_pending_delivery(_webhook_on: None) -> None:
    job = _mk_job(LaunchJobState.SUCCEEDED.value)
    d = webhook.enqueue_launch_terminal(job)
    assert d is not None
    assert d.event == "launch.succeeded"
    assert d.state == WebhookDeliveryState.PENDING.value
    assert d.payload["vm_id"] == "vm-1"
    assert d.payload["miner_id"] == "miner-1"


def test_enqueue_failed_job_event_name(_webhook_on: None) -> None:
    job = _mk_job(LaunchJobState.FAILED.value)
    d = webhook.enqueue_launch_terminal(job)
    assert d.event == "launch.failed"


# ─── delivery ────────────────────────────────────────────────────────


def test_deliver_one_2xx_marks_delivered(
    _webhook_on: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    seen = {}

    def fake_post(url, body, sig, event, delivery_id):
        seen["url"], seen["body"], seen["sig"] = url, body, sig
        return 200

    monkeypatch.setattr(webhook, "_post", fake_post)
    d = _mk_delivery()
    assert webhook.deliver_one(d) is True
    d.refresh_from_db()
    assert d.state == WebhookDeliveryState.DELIVERED.value
    assert d.attempts == 1
    assert d.last_status == 200
    assert d.delivered_at is not None
    # the signature the upstream will verify is HMAC over the exact body
    assert seen["sig"] == webhook.sign(SECRET.encode(), seen["body"])


def test_deliver_one_non_2xx_retries_then_fails(
    _webhook_on: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(webhook, "_post", lambda *a, **k: 500)
    d = _mk_delivery(max_attempts=2)

    assert webhook.deliver_one(d) is False
    d.refresh_from_db()
    assert d.state == WebhookDeliveryState.PENDING.value  # one retry left
    assert d.attempts == 1
    assert d.last_status == 500
    assert d.next_attempt_at > timezone.now()  # backoff scheduled

    # second (final) attempt exhausts max_attempts → failed
    d.next_attempt_at = timezone.now()
    d.save(update_fields=["next_attempt_at"])
    assert webhook.deliver_one(d) is False
    d.refresh_from_db()
    assert d.state == WebhookDeliveryState.FAILED.value
    assert d.attempts == 2


def test_deliver_one_transport_error_retries(
    _webhook_on: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    def boom(*a, **k):
        raise OSError("connection refused")

    monkeypatch.setattr(webhook, "_post", boom)
    d = _mk_delivery(max_attempts=5)
    assert webhook.deliver_one(d) is False
    d.refresh_from_db()
    assert d.state == WebhookDeliveryState.PENDING.value
    assert "transport" in d.last_error


def test_deliver_pending_only_due_rows(
    _webhook_on: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(webhook, "_post", lambda *a, **k: 200)
    _mk_delivery(job_id="due")
    from datetime import timedelta

    _mk_delivery(
        job_id="future", next_attempt_at=timezone.now() + timedelta(hours=1)
    )
    delivered = webhook.deliver_pending()
    assert delivered == 1
    assert (
        WebhookDelivery.objects.filter(state=WebhookDeliveryState.DELIVERED.value)
        .get()
        .job_id
        == "due"
    )


# ─── integration: _finish enqueues ───────────────────────────────────


def test_finish_enqueues_webhook(
    _webhook_on: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    from apps.orchestration import launch_jobs

    job = _mk_job(LaunchJobState.RUNNING.value)
    launch_jobs._finish(
        job,
        LaunchJobState.SUCCEEDED,
        reason="",
        result={"ok": True},
        miner_id="miner-1",
        phase=LaunchPhase.LAUNCHED,
    )
    d = WebhookDelivery.objects.get()
    assert d.event == "launch.succeeded"
    assert d.payload["job_id"] == "job-1"


def test_finish_no_webhook_when_disabled() -> None:
    from apps.orchestration import launch_jobs

    job = _mk_job(LaunchJobState.RUNNING.value)
    launch_jobs._finish(
        job,
        LaunchJobState.SUCCEEDED,
        reason="",
        result={"ok": True},
        phase=LaunchPhase.LAUNCHED,
    )
    assert WebhookDelivery.objects.count() == 0
