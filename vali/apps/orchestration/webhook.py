"""Outbound job-event webhooks (#587 Phase 3).

The upstream product API registers ONE callback URL + HMAC secret via
`VALI_WEBHOOK_URL` / `VALI_WEBHOOK_SECRET` (operator-set; no dev default —
if either is unset, webhooks are simply OFF and enqueue is a no-op). On a
terminal job transition vali enqueues a [`WebhookDelivery`]; the
`vali_webhook_tick` worker POSTs the canonical JSON body signed
`X-Hippius-Signature: sha256=<hmac-sha256>` and retries with backoff
until `max_attempts`.

Fail-open: a webhook is a courtesy notification on top of the
authoritative job state (which the upstream can also poll). Nothing here
may raise into a job's own transition.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import urllib.error
import urllib.request
from datetime import timedelta

from django.conf import settings
from django.db.models import F
from django.utils import timezone

from .models import LaunchJob, WebhookDelivery, WebhookDeliveryState

log = logging.getLogger("apps.orchestration.webhook")

# Exponential backoff (seconds) per attempt index, capped. attempts=1 →
# 5 min, doubling, max ~1 h — generous enough to ride a brief upstream
# outage without hammering it.
_BACKOFF_BASE_S = 300
_BACKOFF_MAX_S = 3600


def _config() -> tuple[str, bytes] | None:
    """`(url, secret_bytes)` if BOTH are configured, else None (off)."""
    url = str(getattr(settings, "VALI_WEBHOOK_URL", "") or "").strip()
    secret = str(getattr(settings, "VALI_WEBHOOK_SECRET", "") or "")
    if not url or not secret:
        return None
    return url, secret.encode("utf-8")


def is_enabled() -> bool:
    return _config() is not None


def sign(secret: bytes, body: bytes) -> str:
    """`sha256=<hex>` HMAC over the exact body bytes — what the upstream
    recomputes to authenticate the call."""
    return "sha256=" + hmac.new(secret, body, hashlib.sha256).hexdigest()


def enqueue_launch_terminal(job: LaunchJob) -> WebhookDelivery | None:
    """Enqueue a `launch.<state>` delivery for a terminal launch job.

    No-op (returns None) when webhooks are unconfigured. Best-effort: any
    failure is swallowed + logged so a webhook can never break a launch.
    """
    if not is_enabled():
        return None
    event = f"launch.{job.state}"
    payload = {
        "event": event,
        "job_id": job.job_id,
        "vm_id": job.vm_id,
        "tenant_id": job.tenant_id,
        "state": job.state,
        "miner_id": job.miner_id or None,
        "reason": job.reason or None,
        "occurred_at": (job.finished_at or timezone.now()).isoformat(),
    }
    try:
        return WebhookDelivery.objects.create(
            event=event,
            job_id=job.job_id,
            vm_id=job.vm_id,
            payload=payload,
            next_attempt_at=timezone.now(),
            max_attempts=int(getattr(settings, "VALI_WEBHOOK_MAX_ATTEMPTS", 8)),
        )
    except Exception as exc:  # noqa: BLE001 — webhook is non-load-bearing
        log.warning("webhook enqueue failed (non-fatal) job=%s: %s", job.job_id, exc)
        return None


def _backoff(attempts: int) -> int:
    return min(_BACKOFF_BASE_S * (2 ** max(0, attempts - 1)), _BACKOFF_MAX_S)


def _post(url: str, body: bytes, sig: str, event: str, delivery_id: str) -> int:
    timeout = float(getattr(settings, "VALI_WEBHOOK_TIMEOUT_S", 10.0))
    req = urllib.request.Request(
        url,
        data=body,
        method="POST",
        headers={
            "Content-Type": "application/json",
            "X-Hippius-Event": event,
            "X-Hippius-Delivery": delivery_id,
            "X-Hippius-Signature": sig,
        },
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310
        return int(resp.status)


def deliver_one(delivery: WebhookDelivery) -> bool:
    """Attempt one delivery. CAS `delivered` on 2xx; else bump attempts +
    schedule a backoff retry, or `failed` once `max_attempts` is hit.
    Returns True iff delivered. Never raises."""
    cfg = _config()
    if cfg is None:
        return False
    url, secret = cfg
    body = json.dumps(delivery.payload, separators=(",", ":"), sort_keys=True).encode()
    sig = sign(secret, body)
    now = timezone.now()
    status: int | None = None
    err = ""
    try:
        status = _post(url, body, sig, delivery.event, str(delivery.id))
        ok = 200 <= status < 300
    except urllib.error.HTTPError as exc:
        status, ok, err = exc.code, False, f"http {exc.code}"
    except (urllib.error.URLError, OSError, ValueError) as exc:
        ok, err = False, f"transport: {type(exc).__name__}"

    if ok:
        updated = WebhookDelivery.objects.filter(
            id=delivery.id, version=delivery.version
        ).update(
            state=WebhookDeliveryState.DELIVERED.value,
            version=F("version") + 1,
            attempts=F("attempts") + 1,
            last_status=status,
            last_error="",
            delivered_at=now,
        )
        if updated:
            log.info("webhook delivered: %s job=%s", delivery.event, delivery.job_id)
        return bool(updated)

    attempts = delivery.attempts + 1
    exhausted = attempts >= delivery.max_attempts
    WebhookDelivery.objects.filter(id=delivery.id, version=delivery.version).update(
        state=(
            WebhookDeliveryState.FAILED.value
            if exhausted
            else WebhookDeliveryState.PENDING.value
        ),
        version=F("version") + 1,
        attempts=F("attempts") + 1,
        last_status=status,
        last_error=err[:256],
        next_attempt_at=now + timedelta(seconds=_backoff(attempts)),
    )
    log.warning(
        "webhook attempt %d/%d failed (%s) job=%s%s",
        attempts,
        delivery.max_attempts,
        err,
        delivery.job_id,
        " — giving up" if exhausted else "",
    )
    return False


def deliver_pending(limit: int = 20) -> int:
    """Deliver up to `limit` due pending deliveries. Returns the count
    delivered. The worker (`vali_webhook_tick`) calls this each cycle."""
    if not is_enabled():
        return 0
    now = timezone.now()
    due = list(
        WebhookDelivery.objects.filter(
            state=WebhookDeliveryState.PENDING.value,
            next_attempt_at__lte=now,
        ).order_by("next_attempt_at")[:limit]
    )
    delivered = 0
    for d in due:
        if deliver_one(d):
            delivered += 1
    return delivered
