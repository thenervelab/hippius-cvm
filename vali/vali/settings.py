"""Django settings for the vali orchestration service.

Spec of record: ARCHITECTURE.md §3 / §4 / §17.5.

PR-G1 scope: OrderTicket intake endpoint only. No scheduler, no
Packer trigger, no §24/§25 lifecycle yet — those land in PR-G2..G5.

Locked decisions (issue #1 comment 4496539510, 2026-05-20):

- Q5: vali auth = **minimal own auth (mTLS + service tokens)** — NOT
  hippius-backend SSO. Implemented in `apps.identity`.
- Q9: vali static egress IP = configurable via env var, placeholder
  default. Surfaced as `VALI_STATIC_EGRESS_IP` (informational; vali
  never sources outbound calls in PR-G1).
- Q10: the control plane runs on a private subnet; the ops layer
  (nginx ingress) enforces the actual ACL. No subnet is hard-coded
  here — see `VALI_MTLS_TRUSTED_PROXIES`.
- Q11: L1↔vali mTLS on that private subnet with a dedicated CA, 90-day
  rotation. Django reads the cert verdict from the reverse-proxy
  headers (`X-SSL-Client-Verify` + `X-SSL-Client-S-DN`); only honored
  when `REMOTE_ADDR` ∈ `VALI_MTLS_TRUSTED_PROXIES` (env var).

DEPLOYMENT NOTE — every setting below whose value identifies YOUR
infrastructure (Vault address, chain RPC, object store, Edge URLs,
bucket names, image references) is read from an environment variable
and defaults to either an empty string that fails LOUD at first use, or
an obvious `<PLACEHOLDER>`. There is no default that silently points at
someone else's deployment. `docs/operator/` documents what to put in
each one.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

import dj_database_url

BASE_DIR = Path(__file__).resolve().parent.parent


def _env_bool(name: str, default: bool = False) -> bool:
    v = os.environ.get(name)
    if v is None:
        return default
    return v.strip().lower() in {"1", "true", "yes", "on"}


def _env_list(name: str, default: list[str] | None = None) -> list[str]:
    v = os.environ.get(name)
    if v is None:
        return default or []
    return [p.strip() for p in v.split(",") if p.strip()]


def _env_int(name: str, default: int) -> int:
    v = os.environ.get(name)
    if v is None:
        return default
    return int(v)


def _env_float(name: str, default: float) -> float:
    v = os.environ.get(name)
    if v is None:
        return default
    return float(v)


# ──────────────────────────────────────────────────────────────────
# Core Django
# ──────────────────────────────────────────────────────────────────

# `SECRET_KEY` must be supplied in any non-test environment. The
# placeholder default is fail-LOUD: containing "INSECURE" makes
# accidental production deployment obvious in logs AND raises at
# import time if `DEBUG=False` (i.e. prod) without an explicit key.
DEBUG = _env_bool("DJANGO_DEBUG", default=False)
SECRET_KEY = os.environ.get(
    "DJANGO_SECRET_KEY",
    "INSECURE-vali-dev-secret-do-not-use-in-prod",
)
if not DEBUG and SECRET_KEY.startswith("INSECURE"):
    raise RuntimeError(
        "DJANGO_SECRET_KEY must be set in production (DEBUG=False) — "
        "refusing to start with the placeholder dev key."
    )
ALLOWED_HOSTS = _env_list("DJANGO_ALLOWED_HOSTS", default=["localhost", "127.0.0.1"])

# Bound Django's request-body read for non-form payloads. The intake
# view does its own check on `request.body`, but the parser's
# `stream.read(limit)` is what actually caps memory before the body
# is materialized. Mirrors `VALI_TICKET_MAX_BYTES` (set below).
DATA_UPLOAD_MAX_MEMORY_SIZE = _env_int(
    "DJANGO_DATA_UPLOAD_MAX_MEMORY_SIZE",
    default=64 * 1024,
)

INSTALLED_APPS = [
    # `django.contrib.admin` is the ops eyeball surface (#152). It is
    # mounted at `/admin/` (OUTSIDE the `/v1/` API prefix, see
    # `vali.urls`) and is intentionally kept cluster-internal — the
    # vali Service is ClusterIP, never exposed through an Ingress. The
    # contrib stack below (auth, contenttypes, sessions, messages,
    # staticfiles) is the admin's required dependency chain; none of
    # them are part of the L1↔vali wire surface.
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    "rest_framework",
    "drf_spectacular",
    "apps.identity",
    "apps.cdn",
    "apps.images",
    "apps.lifecycle",
    "apps.miners",
    "apps.network",
    "apps.backup",
    "apps.operator",
    "apps.orchestration",
    "apps.orders",
    "apps.packer",
    "apps.scheduler",
    "apps.storage",
    "apps.telemetry",
    "apps.tenant_bake",
    # Synthetic monitor — periodic light health-check + full e2e
    # launch→decommission probe on the LIVE infra (model-less; CronJob
    # driven). It only READS the DB in the light tier and drives the real
    # public API in the full tier. See `apps.synthetic`.
    "apps.synthetic",
]

# Canonical Django middleware order for the admin: Security → Session
# → Common → Csrf → Authentication → Message → XFrame, with vali's
# mTLS gate appended last (it runs AFTER Django auth so the API path
# still resolves a `ServiceClient` principal via DRF — the admin path
# is unaffected, as the mTLS middleware only attaches request.user on
# the API surface; the admin uses the session-cookie auth that
# AuthenticationMiddleware installs).
# WhiteNoise serves the admin's static assets (CSS / JS) directly
# from gunicorn — the production pod runs `readOnlyRootFilesystem:
# true` with no nginx sidecar, so an external static server is not an
# option. The import is conditional: the test env may not install
# `whitenoise` (it's an optional runtime dep), and the admin smoke
# tests don't fetch static assets so leaving it out keeps `pytest`
# green when the wheel is absent. Production installs the wheel via
# the Dockerfile.
import importlib.util as _importlib_util  # noqa: E402 — deliberate late import

_WHITENOISE_PRESENT = _importlib_util.find_spec("whitenoise") is not None

MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    # WhiteNoise must immediately follow SecurityMiddleware (its
    # docs are explicit about this — it has to wrap responses before
    # any later middleware mutates them).
    *(["whitenoise.middleware.WhiteNoiseMiddleware"] if _WHITENOISE_PRESENT else []),
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
    "apps.identity.middleware.MtlsClientCertMiddleware",
    # P2 object-level authorization. MUST follow MtlsClientCertMiddleware
    # (it reads the mTLS attributes that one attaches) and is the layer a
    # new endpoint cannot forget — see apps.identity.scoping.
    "apps.identity.middleware.PrincipalScopeMiddleware",
]

ROOT_URLCONF = "vali.urls"
WSGI_APPLICATION = "vali.wsgi.application"
ASGI_APPLICATION = "vali.asgi.application"

DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"
USE_TZ = True
TIME_ZONE = "UTC"

# vali does not serve a user-facing UI on the API surface — the only
# template consumer is the cluster-internal Django admin (#152). The
# `APP_DIRS=True` discovery is bounded to the contrib apps' built-in
# templates plus any per-app `templates/` dir (none today); the API
# views always emit JSON via DRF and never reach the template layer.
TEMPLATES: list[dict] = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
            ],
        },
    },
]

# Static-file serving — the admin needs `/static/` for its CSS / JS.
# The Dockerfile runs `collectstatic` at image build into `STATIC_ROOT`
# (baked into the read-only image layer); WhiteNoise (mounted above)
# serves them from gunicorn at runtime. The default storage backend
# is intentionally NOT the Manifest variant: a manifest lookup at
# template-render time errors hard when `collectstatic` has not run,
# which would break the in-process test suite that exercises the
# admin without running collectstatic. WhiteNoise still gzip/brotli
# encodes on the fly via its middleware regardless of the storage
# backend — the cache-busting hashed filenames are the only thing
# we forgo, and the admin is cluster-internal (no edge cache).
STATIC_URL = "/static/"
# `BASE_DIR` resolves to the directory holding the `vali` package — in
# the prod container that's `/usr/local/lib/python3.12/site-packages`
# because vali is `pip install`ed, not source-mounted. The Dockerfile
# overrides this to `/app/staticfiles` via the env var below so the
# `chown -R 65532:65532` step (and the pod's volumeMount story) sees a
# predictable, top-level path instead of a site-packages-buried one.
STATIC_ROOT = Path(os.environ.get("DJANGO_STATIC_ROOT", str(BASE_DIR / "staticfiles")))

# ──────────────────────────────────────────────────────────────────
# Database
# ──────────────────────────────────────────────────────────────────
# Prod: Postgres (psycopg3). Tests: SQLite in-memory (configured via
# DATABASE_URL=sqlite:///:memory: in conftest.py / CI env).

DATABASES = {
    "default": dj_database_url.config(
        env="DATABASE_URL",
        default="postgres://vali:vali@127.0.0.1:5432/vali",
        conn_max_age=600,
        conn_health_checks=True,
    ),
}

# ──────────────────────────────────────────────────────────────────
# Cache — backs the DRF ScopedRateThrottle (audit RA-L1)
# ──────────────────────────────────────────────────────────────────
# The default LocMemCache is PER-PROCESS: with `gunicorn --workers 4`
# each worker keeps its own throttle bucket, so a scoped rate of N/min
# is really N×workers/min (and worse with >1 replica). A DB-backed cache
# makes the throttle state GLOBAL across every worker + replica with no
# new infra (Postgres is already the datastore) and no new secret. The
# `vali_throttle_cache` table is created by an `identity` migration
# (`createcachetable`, run by the migrate Job). The scoped CREATE + the
# anon signed-envelope ingress endpoints (heartbeat / telemetry /
# graceful-exit / stopped-ack) touch the cache; the per-peer key + a
# generous rate keep the hot heartbeat path's cache load bounded.
CACHES = {
    "default": {
        "BACKEND": "django.core.cache.backends.db.DatabaseCache",
        "LOCATION": "vali_throttle_cache",
    },
}

# ──────────────────────────────────────────────────────────────────
# Django REST Framework
# ──────────────────────────────────────────────────────────────────
REST_FRAMEWORK = {
    "DEFAULT_AUTHENTICATION_CLASSES": [
        "apps.identity.authentication.MtlsAuthentication",
        "apps.identity.authentication.ServiceTokenAuthentication",
    ],
    "DEFAULT_PERMISSION_CLASSES": [
        "rest_framework.permissions.IsAuthenticated",
    ],
    # drf-spectacular: OpenAPI 3 schema for the validator API
    # (Swagger UI at /v1/docs, ReDoc at /v1/redoc, raw schema at /v1/schema).
    "DEFAULT_SCHEMA_CLASS": "drf_spectacular.openapi.AutoSchema",
    # vali ingests CBOR / COSE_Sign1 bodies — register a parser that
    # surfaces the raw bytes via `request.body`. DRF's default JSON
    # parser would try to decode and fail.
    "DEFAULT_PARSER_CLASSES": [
        "rest_framework.parsers.JSONParser",
        "apps.orders.parsers.CoseSign1OctetStreamParser",
    ],
    # Map Django's `RequestDataTooBig` (raised pre-body-read when
    # `Content-Length > DATA_UPLOAD_MAX_MEMORY_SIZE`) onto a
    # structured 413 instead of letting it bubble as 500.
    "EXCEPTION_HANDLER": "apps.orders.exceptions.vali_exception_handler",
    "UNAUTHENTICATED_USER": None,
    # `NUM_PROXIES = 0` (RA-N4): trust ONLY the direct peer address
    # (`REMOTE_ADDR`) for throttle keys, NEVER the client-supplied
    # `X-Forwarded-For`. vali is Edge-only (CiliumNetworkPolicy) and the
    # Edge builds a fresh upstream request without copying inbound headers,
    # so an attacker's XFF never reaches vali — but pinning this to 0 makes
    # the "ignore XFF" contract explicit and fail-safe against a future
    # proxy that might inject one. The anon ingress throttles below key on
    # the Edge-stamped `x-hippius-peer-id` (see PeerIdScopedRateThrottle),
    # not the IP, so this only governs the peer-id-absent fallback.
    "NUM_PROXIES": 0,
    # Rate limiting (audit M-ratelimit / RA-M2 / RA-N4 / RA-N5).
    # `ScopedRateThrottle` ONLY acts on views that declare a
    # `throttle_scope`. Authenticated CREATE endpoints key per principal
    # (`request.user.pk`); the anonymous, signed-envelope ingress endpoints
    # (heartbeat / telemetry / graceful-exit / stopped-ack) key per
    # Edge-stamped mTLS identity via PeerIdScopedRateThrottle — a caller
    # cannot rotate the key to escape the cap. Rates are env-tunable.
    "DEFAULT_THROTTLE_CLASSES": [
        "vali.throttling.PeerIdScopedRateThrottle",
    ],
    "DEFAULT_THROTTLE_RATES": {
        "bake_create": os.environ.get("VALI_THROTTLE_BAKE_CREATE", "60/min"),
        "vm_launch": os.environ.get("VALI_THROTTLE_VM_LAUNCH", "120/min"),
        # Anon guest ingress, keyed per Edge-stamped peer-id. Generous — a
        # real guest posts one stopped-ack per lifecycle event; the identity
        # bind is the primary control, this caps a per-source flood.
        "stopped_ack": os.environ.get("VALI_THROTTLE_STOPPED_ACK", "300/min"),
        # Anon miner graceful-exit ingress (Edge-relayed), keyed per peer-id
        # (RA-M2/RA-N4). Each request shells out to the Rust signature
        # verifier BEFORE any auth (the signed envelope IS the credential),
        # so an unthrottled flood spawns unbounded validator subprocesses. A
        # real miner sends ONE graceful-exit when leaving, so this is very
        # generous while still bounding the subprocess amplification.
        "graceful_exit": os.environ.get("VALI_THROTTLE_GRACEFUL_EXIT", "120/min"),
        # Anon telemetry/heartbeat ingress (Edge-relayed, CBOR path is
        # token-exempt), keyed per peer-id (RA-N5). Each ingest shells out to
        # the Rust heartbeat verifier BEFORE any backpressure/quarantine, so
        # an un-throttled valid-replay or unknown-node autoprovision flood
        # from one miner exhausts the (4 sync) gunicorn workers. Set well
        # above a real miner's heartbeat cadence (a few per minute) so it
        # only bites a flood.
        "telemetry_ingest": os.environ.get("VALI_THROTTLE_TELEMETRY_INGEST", "300/min"),
        # Anon guest-boot progress ingress (Edge-relayed), keyed per
        # peer-id. Each milestone shells out to the Rust signature
        # verifier BEFORE any auth (the signed envelope IS the
        # credential), so cap the subprocess amplification. A real guest
        # emits a handful of milestones per boot, so this is generous.
        "vm_progress": os.environ.get("VALI_THROTTLE_VM_PROGRESS", "300/min"),
        # Blackbox host-attestor ingress (PR-8), keyed per source. Each
        # cert/beacon shells out to the Rust verifier (the signed envelope
        # IS the credential), so cap the subprocess amplification. A host
        # emits one cert per boot + a beacon per minute — generous caps.
        "host_attestor_cert": os.environ.get("VALI_THROTTLE_HOST_ATTESTOR_CERT", "120/min"),
        "host_attestor_beacon": os.environ.get("VALI_THROTTLE_HOST_ATTESTOR_BEACON", "300/min"),
        # Blackbox host-attestor nonce-challenge (PR-10). A host requests
        # one fresh enrollment nonce per boot; the mint is a CSPRNG draw +
        # a row write (no subprocess), so the cap can be generous.
        "host_attestor_challenge": os.environ.get(
            "VALI_THROTTLE_HOST_ATTESTOR_CHALLENGE", "120/min"
        ),
        # §23 tenant-CVM live-attestation ingress. Each POST shells out to
        # `verify-live-attestation` (the KBS L0 signature IS the
        # credential), so cap the subprocess amplification. One tenant VM
        # emits a keepalive every few minutes; the whole fleet shares this
        # scope, so the cap is generous.
        "vm_liveness": os.environ.get("VALI_THROTTLE_VM_LIVENESS", "600/min"),
        # Root-only scheduler placement (RA-L2). Each call is a chain read +
        # capacity refresh + possible image build for an arbitrary vm_id, so
        # cap it per principal even though it is already root-gated.
        "scheduler_place": os.environ.get("VALI_THROTTLE_SCHEDULER_PLACE", "120/min"),
    },
}

# drf-spectacular — OpenAPI 3 doc for the validator API. The generated
# schema + Swagger-UI/ReDoc are UNAUTHENTICATED read-only *documentation*
# (no live calls made server-side); the endpoints themselves stay auth-gated.
SPECTACULAR_SETTINGS = {
    "TITLE": "Hippius Validator API",
    "DESCRIPTION": (
        "The Hippius confidential-compute validator (vali) HTTP API — "
        "VM launch/lifecycle, tenant bakes, scheduler, telemetry, and the "
        "miner-fleet registry. Auth: bearer `ServiceToken` (or mTLS)."
    ),
    "VERSION": "1.0.0",
    "SERVE_INCLUDE_SCHEMA": False,
    # Only document the public `/v1/` API surface (skip /admin, /healthz).
    "SCHEMA_PATH_PREFIX": "/v1",
    "COMPONENT_SPLIT_REQUEST": True,
    # Several doc-only serializers expose a `to_state` ChoiceField with a
    # DIFFERENT legal-transition set per resource (VM lifecycle vs bake/build
    # finalize). Without distinct names drf-spectacular collides them into an
    # auto-numbered `ToStateNNNEnum`; name each set explicitly for a stable,
    # readable schema.
    "ENUM_NAME_OVERRIDES": {
        "VmTransitionToStateEnum": [
            "active",
            "migrating",
            "decommissioning",
            "destroyed",
        ],
        "BuildFinalizeToStateEnum": ["running", "succeeded", "failed"],
    },
}

# ──────────────────────────────────────────────────────────────────
# vali-specific
# ──────────────────────────────────────────────────────────────────

# Path to the Rust validator binary (workspace `target/release/` by
# default; CI / prod override via env). The intake view shells out
# to this binary for COSE_Sign1 parsing.
VALI_TICKET_VALIDATOR_BIN = os.environ.get(
    "VALI_TICKET_VALIDATOR_BIN",
    str(BASE_DIR.parent / "target" / "release" / "hippius-ticket-validator"),
)
VALI_TICKET_VALIDATOR_TIMEOUT_S = _env_float("VALI_TICKET_VALIDATOR_TIMEOUT_S", 2.0)

# PR-G2: max ± skew (seconds) allowed between vali's wall clock and
# the guest-supplied `now_unix` inside a StoppedAck (§24/§25).
# 600 s (10 min) is a generous window — the guest agent generates
# the ack at EOL, so clock drift is bounded by the VM's lifetime
# and the host's NTP discipline.
VALI_STOPPED_ACK_SKEW_SECS = _env_int("VALI_STOPPED_ACK_SKEW_SECS", 600)

# PR-G2: max hex length of `signed_stopped_ack_hex` accepted on the
# transition wire. A `SignedStoppedAck` is ~100 bytes (canonical-CBOR
# 6-field map + 64-byte Ed25519 sig), so 4 096 hex chars = 2 KiB
# binary is a generous cap that still bounds the bytes.fromhex
# allocation before subprocess spawn.
VALI_STOPPED_ACK_MAX_HEX_LEN = _env_int("VALI_STOPPED_ACK_MAX_HEX_LEN", 4096)

# §24/§25 — the vali-reach baked into a launched guest's MEASURED cmdline
# as `hippius.vali_url`, where the guest POSTs its signed `stopped{}` ack
# (`agent-initramfs::main::eol_push_inputs`). The confidential guest has
# NO IP route to vali, so the default is the host vsock-proxy authority
# (`vsock://<host-cid>:<port>`): the miner-agent forwards the OPAQUE ack
# to vali's `/v1/lifecycle/stopped` ingress over its own network. The
# PORT mirrors the KBS-over-vsock proxy port (0x4B42 = 19266) — the
# stopped-ack rides the SAME proxy, routed by path. Override only to pin
# a non-default vsock port, or an `https://` base where a direct route to
# vali exists.
VALI_GUEST_VSOCK_URL = os.environ.get("VALI_GUEST_VSOCK_URL", "vsock://2:19266")

# Hard cap on inbound OrderTicket body size. Mirrors
# `kbs_server::wire::MAX_REQUEST_BYTES` (64 KiB) so a ticket vali
# accepts will also fit through the KBS front door — a smaller cap
# here would silently drop traffic the KBS can handle.
VALI_TICKET_MAX_BYTES = _env_int("VALI_TICKET_MAX_BYTES", 64 * 1024)

# mTLS reverse-proxy gating (Q11). The middleware reads the cert
# verdict + subject only when the request reaches Django from one of
# these IPs. Empty list = mTLS auth disabled (e.g. test env).
VALI_MTLS_TRUSTED_PROXIES = _env_list("VALI_MTLS_TRUSTED_PROXIES", default=[])
VALI_MTLS_HEADER_VERIFY = os.environ.get("VALI_MTLS_HEADER_VERIFY", "X-SSL-Client-Verify")
VALI_MTLS_HEADER_SUBJECT = os.environ.get("VALI_MTLS_HEADER_SUBJECT", "X-SSL-Client-S-DN")

# Q9 informational — vali doesn't initiate outbound calls in PR-G1.
# Default is an unambiguous placeholder string (NOT empty) so a
# missing env value can't be confused with "0.0.0.0" or a real
# IP after string-concat downstream.
VALI_STATIC_EGRESS_IP = os.environ.get(
    "VALI_STATIC_EGRESS_IP",
    "<placeholder-unset>",
)

# ──────────────────────────────────────────────────────────────────
# PR-G3: Packer trigger surface + Hippius S3 client
# ──────────────────────────────────────────────────────────────────
# Locked decision (issue #1 comment 4496539510, Q12): vali distributes
# Packer-produced images via Hippius S3 (dogfooding). Four operational
# details still tracked open in issue #54 (Object Lock, endpoint URL,
# credential path, presign compatibility) — see
# `apps/packer/README.md` for the migration plan.

# `ServiceClient.name` whose tokens may call `POST /finalize`. Empty
# default fails closed (the permission class denies if unset).
VALI_PACKER_WORKER_PRINCIPAL = os.environ.get("VALI_PACKER_WORKER_PRINCIPAL", "")

# `ServiceClient.name` whose tokens may call
# `POST /v1/tenant-bakes/<id>/finalize`. Empty default fails closed
# (the permission class denies if unset). Same posture as
# `VALI_PACKER_WORKER_PRINCIPAL` — the bake worker is a separate
# principal so the existing packer worker (which builds the shared
# fleet images) cannot impersonate the per-tenant baker pod.
VALI_TENANT_BAKE_WORKER_PRINCIPAL = os.environ.get("VALI_TENANT_BAKE_WORKER_PRINCIPAL", "")

# #334 Phase 2 — when True (production), the create view spawns a
# k8s Job after the row INSERT commits. When False (dev / unit
# tests), `spawn_bake_job` short-circuits; the operator drives the
# bake out-of-band. The default is False so a fresh deploy doesn't
# silently try to talk to the k8s API on a host that hasn't
# configured the SA + RBAC yet.
VALI_TENANT_BAKE_K8S_ENABLED = (
    os.environ.get("VALI_TENANT_BAKE_K8S_ENABLED", "false").lower() == "true"
)

# k8s deploy knobs — all defaulted, all env-overridable. Mirror the
# `apps.packer` posture: code holds the contract, deploy holds the
# concrete values. See `apps.tenant_bake.k8s_jobs.spec_from_settings`
# for the per-field meaning.
VALI_TENANT_BAKE_NAMESPACE = os.environ.get("VALI_TENANT_BAKE_NAMESPACE", "vali")
# CDN plan I3 — the backend base URL a `profile=cdn-node` bake writes into
# the measured agent config (`/etc/hippius/cdn-agent.toml`). Empty (the
# default) refuses every cdn-node bake; standard bakes never read it.
VALI_CDN_BACKEND_URL = os.environ.get("VALI_CDN_BACKEND_URL", "")
VALI_TENANT_BAKE_IMAGE = os.environ.get(
    "VALI_TENANT_BAKE_IMAGE",
    # Pinned-by-digest GHCR image. The digest pin defends against
    # tag-mutation between Job spec emit + Job pod schedule.
    "ghcr.io/thenervelab/hippius-tenant-baker"
    "@sha256:344a156b02558451eea985249e0e0be8e2a3a771cec9588f2de2ee592b76349a",
)
# `ghcr-pull-secret` (ExternalSecret-materialised) authenticates the
# pull from ghcr.io. If you host the baker image on a private
# registry, point this at an imagePullSecret carrying THAT registry's
# credentials — a mismatch surfaces as `ErrImagePull: unauthorized`
# on every bake Job pod.
VALI_TENANT_BAKE_IMAGE_PULL_SECRET = os.environ.get(
    "VALI_TENANT_BAKE_IMAGE_PULL_SECRET", "ghcr-pull-secret"
)
# Stage-1 bake cache PVC name (perf). Empty = disabled (no cache
# volume on bake Jobs). When set, Jobs mount the PVC at /cache and
# `tenant-image-bake.sh` reuses the tenant-independent half of the
# bake across tenants — see `apps.tenant_bake.k8s_jobs.JobSpec.
# cache_pvc_name` for the manifest shape.
VALI_TENANT_BAKE_CACHE_PVC = os.environ.get("VALI_TENANT_BAKE_CACHE_PVC", "")
# A Running bake whose worker claimed it longer ago than this is an orphan
# (its pod died without finalizing) and no longer counts as in flight for
# the golden re-bake's serial gate (`live_in_flight_q`). A bake takes
# minutes; 6 h is far past any real one.
VALI_TENANT_BAKE_ORPHAN_RUNNING_S = _env_int("VALI_TENANT_BAKE_ORPHAN_RUNNING_S", 6 * 3600)
# Vault `jwt` auth for the bake Job (M-k8sauth, #94). Empty role ⇒ the
# static `bake-vault-token` Secret, unchanged. The Vault role is bound to
# `system:serviceaccount:vali:hippius-tenant-baker` — the SA the Job
# already ran as, so no new identity was needed.
VALI_TENANT_BAKE_VAULT_JWT_ROLE = os.environ.get("VALI_TENANT_BAKE_VAULT_JWT_ROLE", "")
VALI_TENANT_BAKE_VAULT_JWT_AUTH_PATH = os.environ.get("VALI_TENANT_BAKE_VAULT_JWT_AUTH_PATH", "jwt")
VALI_TENANT_BAKE_VAULT_JWT_AUDIENCE = os.environ.get("VALI_TENANT_BAKE_VAULT_JWT_AUDIENCE", "vault")
VALI_TENANT_BAKE_VAULT_JWT_MOUNT_PATH = os.environ.get(
    "VALI_TENANT_BAKE_VAULT_JWT_MOUNT_PATH", "/var/run/secrets/vault"
)

VALI_TENANT_BAKE_SERVICE_ACCOUNT = os.environ.get(
    "VALI_TENANT_BAKE_SERVICE_ACCOUNT", "hippius-tenant-baker"
)
VALI_TENANT_BAKE_VALI_INTERNAL_URL = os.environ.get(
    "VALI_TENANT_BAKE_VALI_INTERNAL_URL",
    "http://vali.vali.svc.cluster.local:8000",
)
VALI_TENANT_BAKE_WORKER_TOKEN_SECRET = os.environ.get(
    "VALI_TENANT_BAKE_WORKER_TOKEN_SECRET", "vali-tenant-baker-worker-token"
)
VALI_TENANT_BAKE_WORKER_TOKEN_KEY = os.environ.get("VALI_TENANT_BAKE_WORKER_TOKEN_KEY", "token")
VALI_TENANT_BAKE_VAULT_ADDR_SECRET = os.environ.get(
    "VALI_TENANT_BAKE_VAULT_ADDR_SECRET", "vali-vault"
)
VALI_TENANT_BAKE_VAULT_ADDR_KEY = os.environ.get("VALI_TENANT_BAKE_VAULT_ADDR_KEY", "address")
# KEK-HSM Phase 4 part 2 — the bake Job uses a DEDICATED `tenant-baker` token
# (NOT vali's), scoped to transit/datakey/plaintext + transit/keys + write
# tenants/* with NO transit/decrypt and NO luks-kek read. The baker GENERATES the
# KEK inside Vault Transit and stages the ciphertext, so no online component can
# decrypt a tenant disk. (Also fixes a latent breakage: since KEK-HSM Phase 1,
# vali's own token can no longer read luks-kek, so the old default `vali-vault`
# token would 403 a fresh bake.)
VALI_TENANT_BAKE_VAULT_TOKEN_SECRET = os.environ.get(
    "VALI_TENANT_BAKE_VAULT_TOKEN_SECRET", "bake-vault-token"
)
VALI_TENANT_BAKE_VAULT_TOKEN_KEY = os.environ.get("VALI_TENANT_BAKE_VAULT_TOKEN_KEY", "token")
VALI_TENANT_BAKE_AWS_CREDS_SECRET = os.environ.get("VALI_TENANT_BAKE_AWS_CREDS_SECRET", "vali-s3")
VALI_TENANT_BAKE_WORK_DIR_SIZE = os.environ.get("VALI_TENANT_BAKE_WORK_DIR_SIZE", "32Gi")
VALI_TENANT_BAKE_BACKOFF_LIMIT = int(os.environ.get("VALI_TENANT_BAKE_BACKOFF_LIMIT", "0"))

# Bucket that holds finished Packer artifacts. Default is the
# canonical name; env override lets staging/prod use distinct
# buckets without code changes.
VALI_PACKER_IMAGES_BUCKET = os.environ.get("VALI_PACKER_IMAGES_BUCKET", "hippius-compute-images")

# Default TTL for `POST /presign-image-get`. Per spec: 1 hour.
VALI_PACKER_PRESIGN_TTL_SECS = _env_int("VALI_PACKER_PRESIGN_TTL_SECS", 3600)

# S3 client factory — dotted path to a zero-arg callable returning
# a `HippiusS3Client`. Default = mock; production overrides to
# `apps.storage.s3.boto_factory` once HIPPIUS_S3_ENDPOINT_URL is
# pinned (Q12 follow-up #54).
VALI_S3_CLIENT_FACTORY = os.environ.get("VALI_S3_CLIENT_FACTORY", "apps.storage.s3.mock_factory")

# Hippius S3 endpoint URL. Required only when `VALI_S3_CLIENT_FACTORY`
# resolves to the boto factory. Default placeholder is fail-loud —
# a misconfigured prod deploy raises `S3ClientUnavailable` at first
# presign instead of silently signing against AWS.
HIPPIUS_S3_ENDPOINT_URL = os.environ.get("HIPPIUS_S3_ENDPOINT_URL", "")
HIPPIUS_S3_REGION_NAME = os.environ.get("HIPPIUS_S3_REGION_NAME", "")

# ──────────────────────────────────────────────────────────────────
# PR-G4: §23 trustless scheduler
# ──────────────────────────────────────────────────────────────────
# The scheduler reads the authoritative on-chain miner state from
# `pallet-compute-scoring` on a thebrain node — never a miner's
# self-report (§23). It shells out to the `read-miner-status`
# subcommand of the same Rust binary used for ticket validation.

# Substrate JSON-RPC endpoint of the chain node — a plain-HTTP service
# on the private control-plane network (§B Q10; e.g.
# `http://<CHAIN_RPC_HOST>:9933`). Empty default fails closed
# AND loud: the chain wrapper raises (→ HTTP 503) rather than let a
# misconfigured deploy behave as "no miners" and 409 every
# placement. The URL is handed to the binary via the
# `THEBRAIN_RPC_URL` env var (never argv — it may embed a
# credential, §20).
VALI_THEBRAIN_RPC_URL = os.environ.get("VALI_THEBRAIN_RPC_URL", "")

# Pallet name as wired into thebrain's `construct_runtime!` — drives
# the twox-128 storage-prefix derivation in the Rust reader.
VALI_THEBRAIN_PALLET_NAME = os.environ.get("VALI_THEBRAIN_PALLET_NAME", "ComputeScoring")

# Should a chain read FAIL when the configured pallet is no longer in
# the runtime metadata?
#
# A runtime upgrade that drops a pallet does NOT delete its storage, and
# the Rust reader derives its keys from the pallet NAME (twox-128) over
# raw storage — so a removed pallet keeps answering with its last-written
# bytes indefinitely and every read looks perfectly healthy. The reader
# now probes `state_getMetadata` and reports `pallet_live`; a `false` is
# logged at ERROR on every `read_miner_status` call regardless of this
# setting.
#
# **Default False — today's behaviour, byte-identical.** vali is placing
# production workloads off this read right now; flipping it closed here
# would stop every placement and empty the Edge admission feed the moment
# the fix deployed. That is an operator decision, not a code default.
# Set True once the chain side is resolved, to turn the fossil into a
# hard `ChainReadUnavailable` (HTTP 503) instead of a log line.
VALI_CHAIN_REQUIRE_PALLET_LIVE = _env_bool("VALI_CHAIN_REQUIRE_PALLET_LIVE", False)

# Outer subprocess timeout for the `read-miner-status` shell-out.
# Must exceed the binary's per-RPC-call timeout (8 s) with headroom
# for `MinerStatuses` map pagination.
VALI_THEBRAIN_RPC_TIMEOUT_S = _env_float("VALI_THEBRAIN_RPC_TIMEOUT_S", 30.0)

# TTL (seconds) for the `GET /v1/edge/registry` feed cache. The Edge
# gateway's permissionless-auth poller (PR-2) hits this every N s; the
# cache coalesces those polls into one chain read per window so a fleet
# of Edge replicas cannot stampede the RPC. Keep well under the Edge's
# `EDGE_REGISTRY_REFRESH_SECS` so each Edge poll still sees fresh data.
VALI_EDGE_REGISTRY_FEED_TTL_S = _env_float("VALI_EDGE_REGISTRY_FEED_TTL_S", 15.0)

# Registry-feed signing (audit M-registry-mTLS). The Edge admits a miner
# cert iff its node_id is in this feed's `active` set, so a tampered feed
# (in-cluster MITM of the plain-HTTP hop) could admit a rogue node or DoS
# legit ones. vali Ed25519-signs the exact feed bytes with the seed at
# this Vault path (`seed` = 64-hex); the Edge verifies against a pinned
# pubkey. Unset ⇒ served UNSIGNED (the pre-key-provisioning window; the
# Edge only fail-closes once ITS pubkey is pinned). `_HEX` is a dev/test
# override.
VALI_EDGE_REGISTRY_FEED_SIGNING_SEED_VAULT_PATH = os.environ.get(
    "VALI_EDGE_REGISTRY_FEED_SIGNING_SEED_VAULT_PATH", ""
)
VALI_EDGE_REGISTRY_FEED_SIGNING_SEED_HEX = os.environ.get(
    "VALI_EDGE_REGISTRY_FEED_SIGNING_SEED_HEX", ""
)

# §23 fail-closed stale-epoch gate: a miner whose score reflects an
# epoch more than this many behind the chain's `CurrentEpoch` is
# treated as ineligible (don't trust a stale score).
VALI_SCHEDULER_MAX_EPOCH_LAG = _env_int("VALI_SCHEDULER_MAX_EPOCH_LAG", 2)

# How long the §13 drain keeps a live VM's placement after its host's last
# heartbeat (`scheduler.service.placement_hold_grace_s`, floored at twice
# the liveness timeout) — longer than a host reboot.
VALI_PLACEMENT_HOLD_GRACE_S = _env_int("VALI_PLACEMENT_HOLD_GRACE_S", 1800)
# Age past which a `Pending` placement is no longer a launch in flight
# (`scheduler.service.stale_pending_after_s`).
VALI_PENDING_PLACEMENT_STALE_S = _env_int("VALI_PENDING_PLACEMENT_STALE_S", 7200)
# Age of a `running` LaunchJob's CURRENT phase past which the launch
# worker is presumed dead (`launch_jobs.reap_orphaned_launch_jobs`),
# floored at twice the longest phase (1 + retries preflights).
VALI_LAUNCH_JOB_ORPHAN_S = _env_int("VALI_LAUNCH_JOB_ORPHAN_S", 10800)
# Silence (no boot milestone, no in-guest frame) after which a launch that
# died in `dispatching` with no host is concluded to have started no guest.
VALI_LAUNCH_JOB_SILENT_GUEST_S = _env_int("VALI_LAUNCH_JOB_SILENT_GUEST_S", 86400)

# §23 placement concentration cap (soft): a miner already hosting
# `≥ this fraction` of ALL active placements is de-prioritised so tenant
# VMs spread across the fleet instead of piling on the single cheapest
# miner (`decide_placement` marketplace ranks by price). `1.0` = no cap
# (all VMs may land on one miner). `service.max_host_share()` reads this;
# it was previously undefined here so the cap was permanently off.
VALI_SCHEDULER_MAX_HOST_SHARE = _env_float("VALI_SCHEDULER_MAX_HOST_SHARE", 1.0)

# §23 per-owner sub-budget (soft, audit M-per-tenant-cap): a miner where a
# single OWNER already holds `≥ this many` active placements is
# de-prioritised for that owner's next VM, so one owner's workloads spread
# across the fleet (bounded noisy-neighbour + correlated blast radius)
# instead of monopolising one miner via many families/tenant_ids. Soft —
# never fails a placement (falls back to the full eligible set on a full
# fleet). `0` = disabled.
VALI_SCHEDULER_MAX_OWNER_PLACEMENTS_PER_MINER = _env_int(
    "VALI_SCHEDULER_MAX_OWNER_PLACEMENTS_PER_MINER", 4
)

# §23 gate (g), concurrent boots per miner (launch path only): a miner
# already booting this many guests (a launch being dispatched, or a guest
# with no in-guest signal yet since its current boot began, inside the
# boot-stall deadline) is skipped. When every eligible miner is at the cap
# the launch WAITS up to BOOT_WAIT_S for a slot, re-asking every
# BOOT_WAIT_POLL_S, then fails `miners-booting`. Admission only prices the
# reserved vCPU, so without this a burst all lands on the roomiest host and
# boots at once (2026-10-05: 13 boots on one host). `0` = no cap.
VALI_SCHEDULER_MAX_BOOTING_PER_MINER = _env_int("VALI_SCHEDULER_MAX_BOOTING_PER_MINER", 3)
VALI_SCHEDULER_BOOT_WAIT_S = _env_int("VALI_SCHEDULER_BOOT_WAIT_S", 900)
VALI_SCHEDULER_BOOT_WAIT_POLL_S = _env_int("VALI_SCHEDULER_BOOT_WAIT_POLL_S", 15)

# §23 admission bound — default per-miner VM-slot cap seeded into a
# fresh `MinerCapacity` mirror row. v1 carries no detailed hardware
# specs on-chain; operators tune `capacity_slots` per miner after.
VALI_SCHEDULER_DEFAULT_CAPACITY_SLOTS = _env_int("VALI_SCHEDULER_DEFAULT_CAPACITY_SLOTS", 8)

# §23 DYNAMIC capacity (untrusted-miner-safe). When a `MinerCapacity`
# row carries an operator-registered TRUSTED hardware anchor
# (`total_memory_mb` / `total_cpus`, never self-reported), the admission
# bound is sized from `total − vali_committed − reserve`, converted into
# slots by a reference-flavor size, throttled DOWN-only by the miner's
# self-reported free RAM, and clamped by `capacity_slots` (the operator
# ceiling). A row with NO anchor falls back to the flat `capacity_slots`
# (no regression). `scheduler.capacity.effective_capacity` proves the
# self-report can never RAISE the bound.
#
#   HOST_RESERVE_* — RAM/vCPU withheld for the host OS / hypervisor.
#   SLOT_REF_*     — the reference-flavor size one admission slot is
#                    worth (default = the `large` flavor: 8 GiB / 4 vCPU).
VALI_SCHEDULER_HOST_RESERVE_MEMORY_MB = _env_int("VALI_SCHEDULER_HOST_RESERVE_MEMORY_MB", 8192)
VALI_SCHEDULER_HOST_RESERVE_CPUS = _env_int("VALI_SCHEDULER_HOST_RESERVE_CPUS", 2)
VALI_SCHEDULER_SLOT_REF_MEMORY_MB = _env_int("VALI_SCHEDULER_SLOT_REF_MEMORY_MB", 8192)
VALI_SCHEDULER_SLOT_REF_CPUS = _env_int("VALI_SCHEDULER_SLOT_REF_CPUS", 4)

# The largest flavor a tenant may launch (`flavors.max_offered_flavor`
# validates it). Empty (the default) = no cap: every catalogue flavor is
# sold wherever a host can hold it. A flavor name withdraws the larger
# sizes, independently of whether a host could hold them.
VALI_SCHEDULER_MAX_FLAVOR = os.environ.get("VALI_SCHEDULER_MAX_FLAVOR", "")

# Capacity v2 (`scheduler.capacity_config` documents and validates each
# knob; the getters there own the defaults — these only carry the env).
# Resource-true admission is FLAG-FIRST: with RESOURCE_ADMISSION off, v2
# runs in shadow (computed + diff-logged) and v1 slots decide.
_CAPACITY_V2_ENV = (
    "VALI_SCHEDULER_RESOURCE_ADMISSION",
    "VALI_SCHEDULER_CPU_OVERCOMMIT",
    "VALI_SCHEDULER_PER_VM_OVERHEAD_MB",
    "VALI_SCHEDULER_ASID_RESERVE",
    "VALI_SCHEDULER_OPERATOR_VM_HARD_CAP",
    "VALI_CAPACITY_EARN_FLOOR_VMS",
    "VALI_CAPACITY_EARN_FLOOR_VCPUS",
    "VALI_CAPACITY_EARN_FLOOR_MEMORY_MB",
    "VALI_CAPACITY_EARN_HARD_CAP_VMS",
    "VALI_CAPACITY_EARN_HARD_CAP_VCPUS",
    "VALI_CAPACITY_EARN_HARD_CAP_MEMORY_MB",
    "VALI_CAPACITY_EARN_GROWTH",
    "VALI_CAPACITY_EARN_MIN_STEP_VMS",
    "VALI_CAPACITY_EARN_MIN_STEP_VCPUS",
    "VALI_CAPACITY_EARN_MIN_STEP_MEMORY_MB",
    "VALI_CAPACITY_EARN_UTIL_TRIGGER",
    "VALI_CAPACITY_EARN_HOLD_S",
    "VALI_CAPACITY_EARN_PENALTY_FACTOR",
    "VALI_CAPACITY_EARNED_INFLIGHT_MAX",
    "VALI_CAPACITY_EARN_DECAY_AFTER_S",
    "VALI_CAPACITY_EARN_PROOF",
    # Storage-aware placement — the DATA-disk gate and its knobs.
    "VALI_SCHEDULER_DISK_GATE",
    "VALI_SCHEDULER_DISK_UNKNOWN",
    "VALI_DISK_RESERVE_GB",
    "VALI_DISK_OVERCLAIM_SLACK_GB",
    "VALI_SCHEDULER_SLOT_REF_DISK_GB",
)


def _capacity_v2_env(environ: dict[str, str] | os._Environ[str]) -> dict[str, str]:
    """The capacity v2 knobs PRESENT in `environ`, as raw strings. Unset
    knobs are omitted so the `capacity_config` getter default applies;
    the getters parse and validate (a malformed value raises there)."""
    return {name: environ[name] for name in _CAPACITY_V2_ENV if name in environ}


globals().update(_capacity_v2_env(os.environ))

# §23 gate (e) — OBSERVED SEV-SNP start capability
# (`scheduler.cvm_capability`). Every other admission input models a
# QUANTITY (CPU, RAM, slots, epoch, stake, price); a host whose SEV-SNP
# state machine has wedged passes all of them with room to spare —
# its resources read as fully FREE precisely because it can boot nothing
# — so the scheduler kept choosing it for launches AND for §25
# destinations, where the failure only surfaces after the source has
# been quiesced and fenced.
#
# The ledger is written ONLY from vali's own observed dispatch outcomes
# (a launch order the miner accepted/rejected, a §25 dest activation
# that reported done/failed), keyed on the node id from vali's own
# decision — so a miner can neither claim capability it lacks nor mark
# a rival incapable.
#
# A SINGLE failure is NOT an exclusion. `sev_common_kvm_init … EBUSY` is
# measurably intermittent and self-recovering on this fleet (one host:
# 1 failure in 105 starts over 22 days; another: 3 in 5 days, each
# followed by a successful start), so latching on one would repeatedly
# pull healthy miners out of service for a fault they clear unaided.
#
#   CVM_FAIL_WINDOW_S — how long a recent observed failure keeps a host
#       softly DEGRADED, and how close together consecutive failures
#       must land to accumulate into a streak at all. Failures older
#       than this carry no penalty and cannot extend a streak.
#   CVM_FAIL_THRESHOLD — how many CONSECUTIVE in-window failures (no
#       observed success in between) it takes to HARD-exclude a host.
#       Any observed success zeroes the streak. `0` DISARMS the hard
#       exclusion fleet-wide, leaving only the soft de-rate — the
#       operator dial, no dev-only bypass.
#   CVM_PROOF_TTL_S — how long an OBSERVED start success counts as proof
#       before decaying to UNKNOWN. "The last CVM that booted here
#       booted three weeks ago" is not a claim about today.
#   CVM_PROBATION_S — how long a host that REACHED the threshold stays
#       softly de-rated after its hard window elapses. The hard
#       exclusion must not relax straight back to full eligibility on
#       the clock alone: on 2026-08-13 a host hard-excluded at 12:01
#       (streak 3) was chosen again at 13:51 — the window had aged out,
#       nothing had observed it recover, and an idle host has the FREEST
#       capacity — and burned a second tenant launch. During probation
#       it is chosen only when nothing better exists, and ANY observed
#       success ends it immediately. Symmetric with CVM_PROOF_TTL_S:
#       a success is proof for a day, a streak is doubt for a day.
#       `<= CVM_FAIL_WINDOW_S` (or a 0 threshold) disables it.
#
# UNKNOWN is eligible-but-unproven: never excluded (that would empty a
# fresh fleet, and is self-sealing since capability is only provable BY
# being placed) and never assumed capable (it earns no ranking bonus).
VALI_SCHEDULER_CVM_FAIL_WINDOW_S = _env_int(
    "VALI_SCHEDULER_CVM_FAIL_WINDOW_S", 3600
)
VALI_SCHEDULER_CVM_FAIL_THRESHOLD = _env_int(
    "VALI_SCHEDULER_CVM_FAIL_THRESHOLD", 3
)
VALI_SCHEDULER_CVM_PROOF_TTL_S = _env_int("VALI_SCHEDULER_CVM_PROOF_TTL_S", 86400)
VALI_SCHEDULER_CVM_PROBATION_S = _env_int("VALI_SCHEDULER_CVM_PROBATION_S", 86400)

# §25 dest-activation RETRY. The source is already quiesced, stopped and
# KBS-fenced by the time the destination is asked to boot, so a transient
# EBUSY there costs the tenant its VM. vali re-dispatches the
# `migrate-activate` order up to MAX_ATTEMPTS times, paced by BACKOFF_S,
# all inside the existing `VALI_ORCHESTRATION_ACTIVATE_TIMEOUT_S` phase
# deadline. MAX_ATTEMPTS matches `VALI_SCHEDULER_CVM_FAIL_THRESHOLD` on
# purpose: a migration that exhausts its retries leaves behind exactly the
# failure streak that keeps the next placement off that host.
VALI_MIGRATION_DEST_ACTIVATE_BACKOFF_S = _env_float(
    "VALI_MIGRATION_DEST_ACTIVATE_BACKOFF_S", 120.0
)
VALI_MIGRATION_DEST_ACTIVATE_MAX_ATTEMPTS = _env_int(
    "VALI_MIGRATION_DEST_ACTIVATE_MAX_ATTEMPTS", 3
)

# Composite-selection weight for the PROVEN capability bonus. Set equal
# to `VALI_SELECT_W_GRACE`'s default (0.25) so a proven incumbent and a
# never-placed newcomer cancel exactly and the cold-start trap does not
# reappear (see `placement.SelectionWeights.proven`).
VALI_SELECT_W_PROVEN = _env_float("VALI_SELECT_W_PROVEN", 0.25)

# Interval (seconds) between continuous re-evaluation cycles run by
# the `vali_scheduler_reeval` management command.
VALI_SCHEDULER_REEVAL_INTERVAL_S = _env_float("VALI_SCHEDULER_REEVAL_INTERVAL_S", 30.0)

# ─── Uptime usage meter (`vali_usage_meter`) ─────────────────────────
# Interval (seconds) between usage-accrual cycles; the batch of served-
# receipt envelopes drained per cycle; and the clamp on a single
# receipt's billable window (defensive — the signer already bounds it).
VALI_USAGE_METER_INTERVAL_S = _env_float("VALI_USAGE_METER_INTERVAL_S", 30.0)
VALI_USAGE_METER_BATCH = _env_int("VALI_USAGE_METER_BATCH", 500)

# UsageAccrual GC (audit M-GC — state bloat). scoring.py only reads the
# LATEST epoch, so accruals for epochs older than the last
# `VALI_USAGE_GC_KEEP_EPOCHS` (a generous audit / dispute window) are dead
# weight; `vali_usage_gc` reaps them. The latest epoch is always retained.
VALI_USAGE_GC_KEEP_EPOCHS = _env_int("VALI_USAGE_GC_KEEP_EPOCHS", 8)
VALI_USAGE_GC_INTERVAL_S = _env_float("VALI_USAGE_GC_INTERVAL_S", 3600.0)
VALI_USAGE_METER_MAX_PERIOD_S = _env_int("VALI_USAGE_METER_MAX_PERIOD_S", 3600)

# ──────────────────────────────────────────────────────────────────
# §23 uptime-LIVENESS gate — credit only SNP-PROVEN-ALIVE time
# ──────────────────────────────────────────────────────────────────
# A `ServedDeliveryReceipt` is signed by the guest telemetry key, which
# is HKDF-derived from the §7 lifecycle key and READABLE BY ROOT INSIDE
# THE CVM. A miner may legitimately launch a tenant VM on its own node,
# lift that key, KILL the VM, and keep signing well-formed uptime
# receipts forever, from anywhere. Possession of the key IS the
# signature; nothing in a receipt requires the VM to still exist.
#
# When this is TRUE the meter credits only the part of a receipt window
# COVERED by a KBS-L0-signed `LiveAttestation` — minted only after the
# KBS verified a fresh `SNP_GET_REPORT` (VCEK→ASK→ARK against AMD
# silicon root, `measurement ∈ §22 allowlist`) whose REPORT_DATA bound a
# single-use KBS nonce to that vm_id. An extracted software key cannot
# produce one; a dead VM cannot produce one at all. Uncovered time
# accrues ZERO — fail closed.
#
# DEFAULT FALSE, and false is the SAFE value here: guests that do not
# yet run the keepalive agent answer no challenges, so arming this
# before they do would stop ALL reward accrual fleet-wide. The chart
# renders the value EXPLICITLY (helm `required`) so which regime is live
# is readable off the ConfigMap rather than inferred from an absent key.
#
# ARMING SEQUENCE — do these IN ORDER, do not skip a verification:
#   1. wire `VALI_KBS_L0_VERIFYING_KEY` (the ingest refuses to record
#      any coverage at all without it — 503, fail closed);
#   2. ship a tenant image that runs `hippius-agent-keepalive` against
#      KBS `/v1/attest/keepalive`, and relays the returned
#      `SignedLiveAttestation` to `POST /v1/telemetry/vm-liveness`;
#      re-bake + re-pin the §22 allowlist for the new measurement;
#   3. LEAVE THIS FALSE and watch `VmLiveAttestation` rows appear for
#      every actively-billing vm_id — confirm coverage exists for the
#      whole fleet, not a sample of it;
#   4. only THEN set `uptimeLiveness.requireAttestation: true` in the
#      chart. Any VM still not answering stops accruing the moment you
#      do — that is the intended semantics, and the reason step 3 is
#      not optional.
VALI_UPTIME_REQUIRE_LIVENESS_ATTESTATION = _env_bool(
    "VALI_UPTIME_REQUIRE_LIVENESS_ATTESTATION", False
)

# How far BACK one liveness sample vouches, in seconds. MUST be >= the
# guest keepalive cadence or honest uptime falls in the gaps between
# samples and goes uncredited. Never forward: a sample says nothing
# about the future, which is exactly why a killed VM stops earning.
VALI_UPTIME_LIVENESS_COVERAGE_S = _env_int("VALI_UPTIME_LIVENESS_COVERAGE_S", 900)

# How recently a receipt's window may have closed for the armed gate to
# DEFER (re-queue the envelope) instead of judging it uncovered. The
# receipt and its covering attestation travel independently, so a
# receipt can arrive first; without this the meter would burn its
# sequence on a verdict that was merely early. Keep well under
# VALI_BILLING_RECEIPT_MAX_LAG_S so a deferral cannot loop forever.
VALI_UPTIME_LIVENESS_GRACE_S = _env_int("VALI_UPTIME_LIVENESS_GRACE_S", 300)

# ±window (seconds) a live attestation's `verified_at_unix` may differ
# from vali's clock at ingest — bounds both a pre-forged future sample
# and a hoarded stale one.
VALI_UPTIME_LIVENESS_SKEW_S = _env_int("VALI_UPTIME_LIVENESS_SKEW_S", 300)

# How long a bound, billable VM that HAS attested before may go without a
# new live attestation before `apps.synthetic.checks.check_uptime_liveness`
# calls it STALLED — i.e. "running and earning nothing".
#
# Default 1800 s = SIX missed beats of the 300 s keepalive cadence. Sized
# well above the cadence on purpose: this alerts on a real revenue stop,
# and one dropped sample is not that. It must stay comfortably ABOVE
# VALI_UPTIME_LIVENESS_COVERAGE_S — inside the coverage span an honest VM
# is still fully credited, so alerting there would page for a fleet that
# is being paid correctly.
VALI_UPTIME_LIVENESS_STALL_S = _env_int("VALI_UPTIME_LIVENESS_STALL_S", 1800)

# How old a VM's newest live attestation may be for
# `GET /v1/vm/<id>/attestation` to report it `attested-live` (the guest is
# running now). Default 600 s = two 300 s keepalives, so one dropped beat
# does not flip the verdict; a sample past its signed `expiry_unix` never
# counts regardless. See `apps.lifecycle.attestation`.
VALI_ATTESTATION_LIVE_MAX_AGE_S = _env_int("VALI_ATTESTATION_LIVE_MAX_AGE_S", 600)

# ── Attested guest resources (`apps.telemetry.guest_resources`) ───────
# SEV-SNP measures the vCPU count but NOT the RAM, so a guest on a
# keepalive image that understands it attests both in its live
# attestation (schema v3) and vali compares them with the flavor the
# launch was measured for.
#
# ARMING SEQUENCE — in order:
#   1. deploy vali (decodes v3 bodies) and the KBS (accepts the field) —
#      EVERY replica: an old pod refuses what step 3 starts sending;
#   2. re-bake the golden images (new keepalive agent + shim);
#   3. set VALI_GUEST_ATTEST_RESOURCES=true: launches and relaunches put
#      the MEASURED `hippius.attest_resources=1` token on the cmdline (an
#      older image ignores it). Not before step 1;
#   4. LEAVE ENFORCE FALSE and read the attested figures fleet-wide
#      (`VmLiveAttestation.mem_*`, `resource_verdict`) — calibrate the
#      thresholds below on every distro and flavor; relaunch every VM whose
#      latest sample is not `ok` (launched before step 3, or `unattested`)
#      until `hippius_synthetic_guest_resources_unproven_vms` reads 0;
#   5. only then set VALI_GUEST_RESOURCES_ENFORCE=true: only an `ok`
#      sample is coverage, so a VM that does not prove its size earns its
#      miner nothing. Evidence (`GuestResourceShortfall`) and the alert
#      fire in both modes.
VALI_GUEST_ATTEST_RESOURCES = _env_bool("VALI_GUEST_ATTEST_RESOURCES", False)
VALI_GUEST_RESOURCES_ENFORCE = _env_bool("VALI_GUEST_RESOURCES_ENFORCE", False)
# `accept_memory=eager` on the measured cmdline: the guest accepts all of
# its RAM at boot, so the host must back the whole flavor up front (no
# lazily-promised memory to overcommit), and RAM still unaccepted is a
# finding. Separate from the attestation because boot time grows with the
# RAM size — measure it on the largest flavor before turning it on.
VALI_GUEST_ACCEPT_MEMORY_EAGER = _env_bool("VALI_GUEST_ACCEPT_MEMORY_EAGER", False)
# Guest upgrades (`apps.orchestration.guest_upgrade`,
# docs/design/guest-component-rollout.md): the orchestration tick advances
# the `GuestUpgradeJob`s an operator admitted (`vali_guest_upgrade`). Off:
# admitted jobs wait in `pending`. Each state's deadline, the soak, the
# dispatch pacing and the window an ambiguous dispatch may still land in.
VALI_GUEST_UPGRADE_ENABLED = _env_bool("VALI_GUEST_UPGRADE_ENABLED", False)
VALI_GUEST_UPGRADE_STOP_TIMEOUT_S = _env_float("VALI_GUEST_UPGRADE_STOP_TIMEOUT_S", 1500.0)
VALI_GUEST_UPGRADE_LAUNCH_TIMEOUT_S = _env_float("VALI_GUEST_UPGRADE_LAUNCH_TIMEOUT_S", 1800.0)
VALI_GUEST_UPGRADE_GUEST_TIMEOUT_S = _env_float("VALI_GUEST_UPGRADE_GUEST_TIMEOUT_S", 1200.0)
VALI_GUEST_UPGRADE_SOAK_S = _env_float("VALI_GUEST_UPGRADE_SOAK_S", 900.0)
VALI_GUEST_UPGRADE_ROLLBACK_TIMEOUT_S = _env_float("VALI_GUEST_UPGRADE_ROLLBACK_TIMEOUT_S", 2400.0)
VALI_GUEST_UPGRADE_PARK_TIMEOUT_S = _env_float("VALI_GUEST_UPGRADE_PARK_TIMEOUT_S", 1500.0)
VALI_GUEST_UPGRADE_ATTESTATION_FRESH_S = _env_float(
    "VALI_GUEST_UPGRADE_ATTESTATION_FRESH_S", 600.0
)
VALI_GUEST_UPGRADE_DISPATCH_PACING_S = _env_float("VALI_GUEST_UPGRADE_DISPATCH_PACING_S", 60.0)
VALI_GUEST_UPGRADE_DISPATCH_SETTLE_S = _env_float("VALI_GUEST_UPGRADE_DISPATCH_SETTLE_S", 300.0)
# The firmware memory map's `System RAM` may fall short of the flavor by
# what the firmware keeps for itself (holes below 1 MiB, ACPI, runtime
# services) — a fixed amount, not a share, so the slack is absolute. Also
# the unaccepted RAM tolerated under eager acceptance.
VALI_GUEST_MEM_FIRMWARE_SLACK_MIB = _env_int("VALI_GUEST_MEM_FIRMWARE_SLACK_MIB", 64)
# Only for a guest kernel with no firmware map: `MemTotal` may fall short
# of the flavor by the kernel's own reservations — the struct page array
# (2 %) and the SEV swiotlb (6 %, capped at 1 GiB), modelled — plus this
# slack for the rest (kernel image, firmware ranges).
VALI_GUEST_MEM_TOTAL_SLACK_MIB = _env_int("VALI_GUEST_MEM_TOTAL_SLACK_MIB", 256)
# How long after vali's newer launch of a VM was accepted a sample from an
# older launch is still accepted (an attestation in flight when the old
# guest was stopped). It compares vali's clock with the KBS's, so it is the
# ingest skew bound (VALI_UPTIME_LIVENESS_SKEW_S), not less.
VALI_GUEST_SUPERSEDED_GRACE_S = _env_int("VALI_GUEST_SUPERSEDED_GRACE_S", 300)
# How long a finding keeps a VM flagged after its last occurrence.
VALI_GUEST_RESOURCES_FLAG_S = _env_int("VALI_GUEST_RESOURCES_FLAG_S", 3600)

# Source of the on-chain epoch reward weight (`compute_epoch_weights`):
#   `snapshot` — the instantaneous Σ resource_units of BOUND placements
#                (v1; pays a bound-but-down VM in full);
#   `usage`    — uptime-integrated Σ unit_seconds from the attested
#                `UsageAccrual` ledger (pays only for proven-up time).
# Default `snapshot` so the deployed reward flow is unchanged until
# served receipts are confirmed flowing live, then flip to `usage`.
VALI_EPOCH_WEIGHT_SOURCE = os.environ.get("VALI_EPOCH_WEIGHT_SOURCE", "snapshot")

# Zombie VMs (`apps.lifecycle.zombie`): a guest frame for a VM past its §24
# crypto-erase quarantines the relaying miner (no placement, no epoch
# weight) for this long, and re-alerts at most once per window per VM.
VALI_ZOMBIE_WINDOW_S = int(os.environ.get("VALI_ZOMBIE_WINDOW_S", "900"))
# Relay-lag slack after a §24 job reports `done` during which a last
# in-flight frame is not held against the miner.
VALI_ZOMBIE_CONFIRM_GRACE_S = int(os.environ.get("VALI_ZOMBIE_CONFIRM_GRACE_S", "120"))
# Frames arriving this soon after a VM's erase are still taken at face value
# (and billed): the guest's final telemetry drain can race the stop ack.
VALI_ZOMBIE_ERASE_GRACE_S = int(os.environ.get("VALI_ZOMBIE_ERASE_GRACE_S", "300"))

# VM owners (`Placement.owner`, i.e. the launch spec's `user_id`) whose
# hosting earns NO reward weight and NO bill — OUR OWN infrastructure, not
# tenants. With `VALI_EPOCH_WEIGHT_SOURCE=usage` the ledger IS the reward,
# and without this filter an operator VM could hold a large share of the
# epoch's units (even a destroyed synthetic-monitor probe). Paying
# ourselves out of the miner pot dilutes every honest miner.
#
# Comma-separated. EMPTY IS A STRICT NO-OP — the default cannot zero a real
# fleet. `VALI_SYNTHETIC_TENANT_ID` is always unioned in by
# `scoring._excluded_owners`, so editing this list to add a one-off
# rehearsal identity can never drop the probe fleet back into the pot.
# Live, this needs the operator identities that are NOT the synthetic
# tenant — e.g. a one-off operator harness identity.
VALI_REWARD_EXCLUDED_OWNERS = _env_list("VALI_REWARD_EXCLUDED_OWNERS", [])

# Time basis of `MinerPrice`: USD-micros per resource-unit per this many
# seconds (default 3600 ⇒ a per-resource-unit-hour price). Drives the
# owed-per-miner readout: owed_micro_usd = Σ unit_seconds × price / period.
VALI_BILLING_PRICE_PERIOD_S = _env_int("VALI_BILLING_PRICE_PERIOD_S", 3600)

# `ServiceClient.name` permitted to call the root-only scheduler
# endpoints (`/bind`, `/fail`). Empty default fails closed — the
# `IsRootClient` permission denies when unset.
VALI_SCHEDULER_ROOT_PRINCIPAL = os.environ.get("VALI_SCHEDULER_ROOT_PRINCIPAL", "")

# ──────────────────────────────────────────────────────────────────
# PR-G5: §24/§25 migration + decommission orchestration
# ──────────────────────────────────────────────────────────────────
# The `vali_orchestration_tick` management command drives jobs; the
# endpoints only start + poll them. External peers are reached via
# `apps.orchestration.effects` — an unset endpoint fails loud (the
# effect raises `EffectUnavailable` and the step retries).

# `ServiceClient.name` permitted to call the root-only migrate /
# decommission triggers. Empty default fails closed.
VALI_ORCHESTRATION_ROOT_PRINCIPAL = os.environ.get("VALI_ORCHESTRATION_ROOT_PRINCIPAL", "")

# ── Reboot-recovery — relaunch a tenant CVM that a host reboot powered
#    off, on its SAME still-alive miner, reusing the existing encrypted
#    overlay (the miner-agent re-adopts only still-running domains, so a
#    powered-off tenant CVM is otherwise never relaunched). Driven by the
#    `vali_orchestration_tick` scan (`service.reboot_recovery_once`).
#    DEFAULT-OFF (dark launch) — flip to true only after the live e2e.
VALI_REBOOT_RECOVERY_ENABLED = _env_bool("VALI_REBOOT_RECOVERY_ENABLED", False)
# Consecutive `down` polls required before a relaunch fires (debounce — a
# guest soft-reboot / the host-up→re-adopt window must not trigger one).
VALI_REBOOT_RECOVERY_DEBOUNCE_POLLS = _env_int("VALI_REBOOT_RECOVERY_DEBOUNCE_POLLS", 3)
# Per-VM relaunch attempt cap (a VM that will not come back is not
# relaunched forever — dispatch-health backstop).
VALI_REBOOT_RECOVERY_MAX_ATTEMPTS = _env_int("VALI_REBOOT_RECOVERY_MAX_ATTEMPTS", 5)
# Exponential-backoff base (seconds) between relaunch attempts.
VALI_REBOOT_RECOVERY_BACKOFF_BASE_S = _env_float("VALI_REBOOT_RECOVERY_BACKOFF_BASE_S", 120.0)
# How long after its last relaunch a VM must be seen up (and not wedged)
# before its relaunch budget resets — one budget per host-down incident.
VALI_REBOOT_RECOVERY_STABLE_S = _env_float("VALI_REBOOT_RECOVERY_STABLE_S", 1800.0)

# ── In-guest liveness — "is there positive evidence from INSIDE the
#    guest, recently?". `poll_domain_running` only proves a QEMU process
#    exists, so a guest wedged in its initramfs (refused KEK release,
#    corrupt overlay, unreachable KBS, boot-counter refusal) reports GREEN.
#    `apps.lifecycle.guest_liveness` classifies the per-VM watermark
#    (`Vm.guest_signal_at`, fed by §23 served receipts + §322 live
#    attestations) as alive | wedged | unknown.
#
# How old the newest in-guest signal may be and still read `alive`.
# Default 600 s = TEN missed beats of the ~60 s served-receipt cadence
# measured on the live fleet — a healthy VM must never be called wedged.
VALI_GUEST_LIVENESS_STALE_S = _env_int("VALI_GUEST_LIVENESS_STALE_S", 600)

# ── Boot stall — an Active, running VM with NO in-guest signal since its
#    current boot began (`Vm.boot_started_at`) for longer than
#        VALI_BOOT_STALL_S + min(VALI_BOOT_STALL_PER_DISK_GB_S × disk_gb,
#                                VALI_BOOT_STALL_DISK_CAP_S)
#    reads `boot_stalled` (and `guest_liveness=wedged` on the API) and is
#    logged (`apps.lifecycle.boot_stall`). The base covers the boot to
#    `kek_released` (~340 s on Milan) + the first receipt; the per-GiB term
#    covers the golden first-boot integrity wipe (~6.8 s/GiB measured on
#    Milan, doubled — the backend's own boot budget), capped at 3 h.
VALI_BOOT_STALL_S = _env_int("VALI_BOOT_STALL_S", 900)
VALI_BOOT_STALL_PER_DISK_GB_S = _env_int("VALI_BOOT_STALL_PER_DISK_GB_S", 15)
VALI_BOOT_STALL_DISK_CAP_S = _env_int("VALI_BOOT_STALL_DISK_CAP_S", 10800)
# How often the boot-stall ERROR may repeat for an UNCHANGED set of stalled
# VMs (any change re-logs immediately).
VALI_BOOT_STALL_WARN_INTERVAL_S = _env_float("VALI_BOOT_STALL_WARN_INTERVAL_S", 3600.0)

# ── Unbound-launch surfacing (P9/#18) — how often `sweep_unbound_launches`
#    may repeat its WARNING for an UNCHANGED set of orphaned vm_ids. The
#    condition is permanent until an operator acts and the tick runs every
#    ~10 s, so an unthrottled warning would emit ~8.6k identical lines a
#    day. Any CHANGE to the set re-warns immediately regardless.
VALI_UNBOUND_LAUNCH_WARN_INTERVAL_S = _env_float(
    "VALI_UNBOUND_LAUNCH_WARN_INTERVAL_S", 3600.0
)

# ── Abandoned-launch reap — the PHANTOM leak. `launch_on_miner` creates
#    the `Vm` row, stages the per-VM KEK and KBS-registers the vm_id
#    BEFORE it dispatches; a launch that fails after that leaves the row
#    `state=active host=""` with a LIVE Vault-Transit KEK and no VM
#    anywhere (seen in production 2026-08-13). Nothing reaped
#    them, and every sweep filtering `exclude(state='destroyed')` counted
#    them as running tenants.
#
# How long an abandoned launch must sit before it may be reaped, measured
# from the LAST failed attempt. Its job is to give a guest that started
# DESPITE the failed dispatch (the Edge 502 / vali 45 s timeout window —
# the miner awaits domain creation, so a slow host fails the dispatch
# while the guest goes on to boot) time to announce itself. 900 s is ~15×
# the 60 s served-receipt cadence and far past the first `booting`
# milestone. The window is a courtesy, not the safety property:
# `_abandoned_reap_veto` requires POSITIVE evidence of absence (a live
# domain-state probe answering False) before anything is erased.
VALI_ABANDONED_LAUNCH_GRACE_S = _env_float("VALI_ABANDONED_LAUNCH_GRACE_S", 900.0)
# Kill switch for the ACTION half only — detection + the WARNING always
# run. DEFAULT-ON, unlike reboot-recovery: the reap acts exclusively on
# rows vali's OWN launch path declared failed after the KBS register (so
# the vm_id is already un-relaunchable — the anti-migration fence — and
# nothing recoverable can be discarded), it re-uses the §24 teardown
# rather than a bespoke erase, and every unanswerable question vetoes it.
# Set false to leave the phantoms in place and merely be told about them.
VALI_ABANDONED_LAUNCH_REAP_ENABLED = _env_bool(
    "VALI_ABANDONED_LAUNCH_REAP_ENABLED", True
)
# How often the sweep may repeat its WARNING for an UNCHANGED set (same
# throttle + reason as the unbound-launch one above).
VALI_ABANDONED_LAUNCH_WARN_INTERVAL_S = _env_float(
    "VALI_ABANDONED_LAUNCH_WARN_INTERVAL_S", 3600.0
)

# Let reboot-recovery ALSO act on a WEDGED guest — a VM whose libvirt
# domain is running but which has emitted no in-guest signal inside the
# staleness bound. DEFAULT-OFF, and deliberately so: root inside a guest
# can stop its own telemetry agent, which would read as `wedged` and
# relaunch a VM the tenant is happily using. Arm only on a fleet where
# every image runs the agent. `unknown` NEVER acts, whatever this is set
# to. When armed the action reuses the SAME debounce, attempt cap,
# backoff and seen-running gates as the domain-down path.
VALI_REBOOT_RECOVERY_ON_WEDGED_GUEST = _env_bool(
    "VALI_REBOOT_RECOVERY_ON_WEDGED_GUEST", False
)

# #587 Phase 3 — outbound job-event webhooks. BOTH must be set (operator,
# no dev default) for webhooks to fire; otherwise enqueue + the
# `vali_webhook_tick` worker are no-ops. The secret is the HMAC-SHA256 key
# the upstream uses to authenticate `X-Hippius-Signature`; it is delivered
# as a k8s Secret from Vault (never committed).
VALI_WEBHOOK_URL = os.environ.get("VALI_WEBHOOK_URL", "")
VALI_WEBHOOK_SECRET = os.environ.get("VALI_WEBHOOK_SECRET", "")
VALI_WEBHOOK_MAX_ATTEMPTS = int(os.environ.get("VALI_WEBHOOK_MAX_ATTEMPTS", "8"))
VALI_WEBHOOK_TIMEOUT_S = _env_float("VALI_WEBHOOK_TIMEOUT_S", 10.0)
VALI_WEBHOOK_TICK_INTERVAL_S = _env_float("VALI_WEBHOOK_TICK_INTERVAL_S", 5.0)

# Interval (seconds) between `vali_orchestration_tick` cycles.
VALI_ORCHESTRATION_TICK_INTERVAL_S = _env_float("VALI_ORCHESTRATION_TICK_INTERVAL_S", 10.0)

# Per-phase deadline for action steps + the snapshot-upload poll — a
# step that keeps failing past this fails the job. Must be sized for
# the slowest plausible snapshot+upload.
VALI_ORCHESTRATION_STEP_TIMEOUT_S = _env_float("VALI_ORCHESTRATION_STEP_TIMEOUT_S", 300.0)

# Deadline for the guest-signed ack waits (§25 source-stopped ack,
# §24 EOL ack). On expiry: a migration fails closed + §13-quarantines
# the source (destination never activated — §25 no split-brain); a
# decommission forces the reclaim (§24 — crypto-erase runs anyway).
VALI_ORCHESTRATION_ACK_TIMEOUT_S = _env_float("VALI_ORCHESTRATION_ACK_TIMEOUT_S", 600.0)

# ── §24 KBS decommission fence. When on, a decommission tells the KBS
#    the VM is decommissioning (`/v1/admin/vm/<id>/decommission`) right
#    after vali freezes the ticket, BEFORE the KEK is erased, and
#    tombstones it (`/tombstone`) once it is destroyed. The KBS row
#    otherwise stays `Active` for good after §24, so nothing the KBS
#    issues (a release, a custody lease) can tell the VM is dead.
#    DEFAULT-OFF: the routes only exist once the KBS that serves them is
#    deployed; until then they 404 and every call would be wasted.
VALI_KBS_FENCE_ENABLED = _env_bool("VALI_KBS_FENCE_ENABLED", False)
# How long, from the start of the decommission, a failing fence may hold
# the crypto-erase back. Past it the erase proceeds anyway — the erase is
# the data-death guarantee, the fence only brings it forward — and the job
# is marked `kbs_fence=pending` for the tick sweep to re-drive. Clamped to
# `VALI_ORCHESTRATION_STEP_TIMEOUT_S`, so the wait can never fail the job.
VALI_KBS_FENCE_WINDOW_S = _env_float("VALI_KBS_FENCE_WINDOW_S", 600.0)

# ── KBS audit-log ingest (`apps.orchestration.kbs_audit`). The KBS keeps
#    its hash-chained release + admin audit logs on an emptyDir inside
#    its CVM (unreadable from the host, wiped by a restart); the tick
#    copies them out through `GET /v1/admin/audit` on the mTLS admin
#    listener, re-verifies the chain, and stores `KbsAuditEntry` rows.
#    DEFAULT-OFF: turn on only once the KBS serving the route is deployed
#    (a KBS without it answers 404 and the ingest skips quietly).
VALI_KBS_AUDIT_INGEST_ENABLED = _env_bool("VALI_KBS_AUDIT_INGEST_ENABLED", False)
# Minimum seconds between two ingest runs (the tick runs every ~10 s).
VALI_KBS_AUDIT_INGEST_INTERVAL_S = _env_float("VALI_KBS_AUDIT_INGEST_INTERVAL_S", 60.0)
# Records per page (the KBS clamps to 500) and pages per log per run —
# every page is one token of the KBS admin rate-limit bucket that
# launches also draw on, so a backlog catches up over several runs.
VALI_KBS_AUDIT_PAGE_LIMIT = _env_int("VALI_KBS_AUDIT_PAGE_LIMIT", 500)
VALI_KBS_AUDIT_MAX_PAGES_PER_RUN = _env_int("VALI_KBS_AUDIT_MAX_PAGES_PER_RUN", 4)
# Retention, explicit: 0 = keep every entry forever (the default — the
# copy in vali is the ONLY one that survives a KBS restart). N > 0 prunes
# verified entries fetched more than N days ago; an entry flagged as a
# chain break is never pruned.
VALI_KBS_AUDIT_RETENTION_DAYS = _env_int("VALI_KBS_AUDIT_RETENTION_DAYS", 0)

# S3 bucket holding §25 LUKS2+dm-integrity migration snapshots + the
# TTL of the presigned PUT/GET URLs. The signed URLs are short-lived
# capabilities — generated on demand, NEVER persisted in a job row.
VALI_ORCHESTRATION_SNAPSHOT_BUCKET = os.environ.get(
    "VALI_ORCHESTRATION_SNAPSHOT_BUCKET", "hippius-compute-migrations"
)
VALI_ORCHESTRATION_PRESIGN_TTL_SECS = _env_int("VALI_ORCHESTRATION_PRESIGN_TTL_SECS", 3600)
# §25 snapshot upload: how long `Uploading` waits for the source miner's
# multi-GB upload (every part URL is presigned for the TTL above, so keep
# this within it), and the multipart part size. vali's operator S3 account
# refuses any single request over ~10 GiB, and the store any part over
# 512 MiB.
VALI_ORCHESTRATION_UPLOAD_TIMEOUT_S = _env_float("VALI_ORCHESTRATION_UPLOAD_TIMEOUT_S", 3600.0)
# §25 `DestActivating`: the dest downloads the snapshot, verifies its length
# + sha256 (and re-downloads, up to 3 times, one that does not verify), then
# boots. A 40 GiB overlay takes ~4 min to fetch and ~1-2 min to hash.
VALI_ORCHESTRATION_ACTIVATE_TIMEOUT_S = _env_float("VALI_ORCHESTRATION_ACTIVATE_TIMEOUT_S", 2700.0)
VALI_ORCHESTRATION_SNAPSHOT_PART_BYTES = _env_int(
    "VALI_ORCHESTRATION_SNAPSHOT_PART_BYTES", 512 * 1024**2
)

# Per-HTTP-call timeout for the `effects` peer calls.
VALI_ORCHESTRATION_EFFECT_TIMEOUT_S = _env_float("VALI_ORCHESTRATION_EFFECT_TIMEOUT_S", 15.0)

# §14 idempotency store — a directory shared with the
# `idempotency-record` / `idempotency-recall` subcommands of the
# validator binary. Empty default fails loud: the orchestrator
# cannot safely run a side-effecting step without retry-dedup.
VALI_IDEMPOTENCY_DIR = os.environ.get("VALI_IDEMPOTENCY_DIR", "")
VALI_IDEMPOTENCY_TTL_SECS = _env_int("VALI_IDEMPOTENCY_TTL_SECS", 86400)

# Peer endpoints the orchestrator's effects reach. An unset endpoint
# fails loud per effect (`EffectUnavailable`).
VALI_EDGE_GATEWAY_URL = os.environ.get("VALI_EDGE_GATEWAY_URL", "")
# §H phase-2 — the cluster-internal Edge inner-listener for
# lifecycle-order dispatch (vali → Edge sign → miner verify chain).
# Distinct from VALI_EDGE_GATEWAY_URL (the mTLS miner-facing service
# vali never directly hits — only the §K telemetry broker does, via
# the Edge → vali leg). The inner listener is plain HTTP on a
# cluster-internal Service that is NetworkPolicy-gated to the vali
# pod's PodSelector. Unset ⇒ `order_dispatch.dispatch_order` raises
# OrderDispatchMisconfigured — the orchestrator must not be wired to
# call dispatch_order without this set.
VALI_EDGE_ORDER_URL = os.environ.get("VALI_EDGE_ORDER_URL", "")
VALI_KBS_ADMIN_URL = os.environ.get("VALI_KBS_ADMIN_URL", "")
# Path to the `hippius-kbs-admin-client` binary the orchestration
# subprocesses to register `VmState::Active` with the KBS before each
# launch (§24 lifecycle pre-registration). Pre-baked into the vali
# image under `/usr/local/bin/hippius-kbs-admin-client`. Unset ⇒
# `kbs_admin.register_vm_active` raises `EffectUnavailable`; the
# launch dispatch then refuses to proceed (a downstream §7 release
# would fail closed at `vm_states.get` anyway).
VALI_KBS_ADMIN_CLIENT_BIN = os.environ.get(
    "VALI_KBS_ADMIN_CLIENT_BIN", "/usr/local/bin/hippius-kbs-admin-client"
)
# Bounded timeout for the kbs-admin-client subprocess, seconds. The
# admin path is in-memory on the KBS side (ticket verify + CAS); 5 s
# is generous. Operator override via env.
VALI_KBS_ADMIN_TIMEOUT_SECS = int(os.environ.get("VALI_KBS_ADMIN_TIMEOUT_SECS", "5"))

# ── `vali_create_vm` operator-tier settings (DEV ONLY) ──────────────
#
# These power the `vali_create_vm` management command, which folds
# `tenant-secrets-stage.sh` + the §22 allowlist re-pin ceremony +
# `hippius-order-ticket-mint` + the existing `vali_dispatch_launch`
# flow into a single CLI invocation. `vali_create_vm` is the operator
# CLI; production launches go through the `POST /v1/vm/launch` API. The
# §22 auto-pin signs with the prod root seed from Vault (no committed
# dev seed), so there is no dev-pin gate.

# Hard kill-switch for the entire `vali_create_vm` CLI surface. Set to
# `"true"` to DISABLE the dev/operator CLI on a cluster where launches
# must go through the API instead.
VALI_ALLOW_PROD = os.environ.get("VALI_ALLOW_PROD", "").strip().lower() == "true"

# Vault KV v2 server vali writes the LUKS KEK + cloud-init userdata to
# before minting the ticket. Vali holds NO token in its long-lived
# state — the operator passes the `VAULT_TOKEN` env var when invoking
# the management command. `VAULT_CACERT` (the self-signed dev Vault
# CA) is pinned by config rather than env so a tampered token cannot
# disable cert verification.
VALI_VAULT_ADDR = os.environ.get("VALI_VAULT_ADDR", "")
VALI_VAULT_CACERT = os.environ.get("VALI_VAULT_CACERT", "")

# Vault `jwt`-auth login (M-k8sauth, #94). When a role is set AND the
# projected ServiceAccount token exists at the path below, vali logs in
# per-process and caches the SHORT-lived Vault token it gets back —
# instead of carrying a long-lived `VAULT_TOKEN` that must be renewed
# forever (an unrenewed one expiring is what locked every rebooting
# miner out of the Edge on 2026-08-06).
#
# The token is a PROJECTED volume with `audience: vault`, deliberately
# NOT the default API-audience token: Vault's role pins `bound_audiences`
# to `vault`, so this credential is useless against the Kubernetes API
# and the API token is useless against Vault (proven live — the API-
# audience token is rejected with HTTP 400).
#
# Unset role ⇒ the static `VAULT_TOKEN` path, unchanged (the operator
# CLI, tests, and any not-yet-migrated caller).
VALI_VAULT_JWT_ROLE = os.environ.get("VALI_VAULT_JWT_ROLE", "")
VALI_VAULT_JWT_AUTH_PATH = os.environ.get("VALI_VAULT_JWT_AUTH_PATH", "jwt")
VALI_VAULT_JWT_TOKEN_PATH = os.environ.get(
    "VALI_VAULT_JWT_TOKEN_PATH", "/var/run/secrets/vault/token"
)

# Mount + path-prefix vali writes tenant secrets under. The KBS reads
# from the SAME `secret/data/${PREFIX}/<vm-id>/{luks-kek,userdata}`
# shape on release; both sides must agree.
VALI_VAULT_KV_MOUNT = os.environ.get("VALI_VAULT_KV_MOUNT", "secret")
VALI_VAULT_KV_PREFIX = os.environ.get("VALI_VAULT_KV_PREFIX", "hippius-compute/kbs/tenants")

# L1 OrderTicket signing seed (Ed25519) — PRODUCTION source: a Vault KV
# v2 path under `VALI_VAULT_KV_MOUNT` holding the 32-byte seed as a
# `seed=<64-hex>` field (e.g. `hippius-compute/vali/l1-order-ticket`).
# vali (the trusted control plane) holds the L1 signing seed online so
# the mint stays automatic, mirroring the §22 allowlist-root seed; the
# matching pubkey is pinned in the KBS `l1Keys` keyring. When set, this
# takes precedence over the file path below. #587 Phase 1A.
VALI_L1_SIGNING_KEY_VAULT_PATH = os.environ.get("VALI_L1_SIGNING_KEY_VAULT_PATH", "")
# Operator-supplied L1 ticket signing seed (32-byte Ed25519, hex on a
# single line — the format `packer/keys/dev/l1-order-ticket.dev.ed25519`
# uses) via a FILE path — TEST/dev affordance only. Mounted into the
# vali pod as a Secret + Volume; the path here is where the volume
# lands. Vali NEVER reads the seed bytes — the
# `hippius-order-ticket-mint` binary opens it. Production uses the Vault
# path above; if neither is set the mint fails closed.
VALI_L1_SIGNING_KEY_PATH = os.environ.get("VALI_L1_SIGNING_KEY_PATH", "")
# Cross-built `hippius-order-ticket-mint` binary, pinned into the vali
# image at build time. Distinct from `VALI_KBS_ADMIN_CLIENT_BIN`
# because the two binaries serve different §22 chains (mint vs admin).
VALI_ORDER_TICKET_MINT_BIN = os.environ.get(
    "VALI_ORDER_TICKET_MINT_BIN",
    "/usr/local/bin/hippius-order-ticket-mint",
)

# Customer-held disk keys (M1 `split` / M2 `customer`, see
# `apps.orchestration.services.customer_keys`). OFF by default: while off,
# a launch intent naming `key_mode=split|customer` is refused at intake.
# Gates only NEW launches — a relaunch / re-mint of an existing M1/M2 VM is
# held to the mode pinned on its `Vm` row, so turning this off never
# strands a running customer-keys VM.
VALI_CUSTOMER_KEYS_ENABLED = _env_bool("VALI_CUSTOMER_KEYS_ENABLED", False)
# The NetBird group every miner's peer is in (a name or an id): the SOURCE
# of each tenant's `miners -> key guardian` policy
# (`services.guardian_netbird`). Empty = the guardian endpoints refuse
# `guardian-netbird-misconfigured` rather than guess.
VALI_NETBIRD_MINERS_GROUP = os.environ.get("VALI_NETBIRD_MINERS_GROUP", "")
# The guardian's TCP port when the operator names none (design §1.1).
VALI_GUARDIAN_DEFAULT_PORT = _env_int("VALI_GUARDIAN_DEFAULT_PORT", 7443)
# An M1/M2 guest waiting on its guardian (`apps.lifecycle.guardian_wait`):
# how long one `awaiting-guardian` report stays fresh, and the most such a
# wait can hold back a restore's auto-revert past its own deadline (bounds a
# forged wait).
VALI_GUARDIAN_WAIT_FRESH_S = float(os.environ.get("VALI_GUARDIAN_WAIT_FRESH_S", "600"))
VALI_GUARDIAN_WAIT_MAX_PAUSE_S = float(
    os.environ.get("VALI_GUARDIAN_WAIT_MAX_PAUSE_S", "86400")
)

# §22 allowlist signing seed (Ed25519) — PRODUCTION source: a Vault KV
# v2 path under `VALI_VAULT_KV_MOUNT` holding the 32-byte seed as a
# `seed=<64-hex>` field (e.g. `hippius-compute/vali/allowlist-root`).
# vali (the trusted control plane) holds the §22 root seed online so the
# auto-pin is fully automatic; the matching pubkey is pinned in KBS
# config. When set, this takes precedence over the file path below.
VALI_KBS_ALLOWLIST_ROOT_SEED_VAULT_PATH = os.environ.get(
    "VALI_KBS_ALLOWLIST_ROOT_SEED_VAULT_PATH", ""
)
# §22 allowlist signing seed via a FILE path — TEST/dev affordance only
# (a 64-hex seed file). Production uses the Vault path above; if neither
# is set the auto-pin fails closed.
VALI_KBS_ALLOWLIST_ROOT_SEED_PATH = os.environ.get("VALI_KBS_ALLOWLIST_ROOT_SEED_PATH", "")
# Cross-built `hippius-kbs-allowlist-tool` binary path.
VALI_KBS_ALLOWLIST_TOOL_BIN = os.environ.get(
    "VALI_KBS_ALLOWLIST_TOOL_BIN",
    "/usr/local/bin/hippius-kbs-allowlist-tool",
)

# ── C2: independent SNP launch-digest recompute ─────────────────────
# vali recomputes the expected launch_digest from its OWN LaunchOrder
# inputs (pinned OVMF + the kernel/initrd/cmdline/vcpus/vcpu-type it
# built) and refuses any miner-asserted value that differs, so a miner
# booting a backdoored guest cannot auto-pin its measurement into §22.
# The recompute shells out to this snp-featured binary (baked in the
# image). Empty ⇒ recompute disabled (fail-open — the pre-rollout state).
VALI_LAUNCH_DIGEST_BIN = os.environ.get(
    "VALI_LAUNCH_DIGEST_BIN", "/usr/local/bin/hippius-launch-digest"
)
# The pinned OVMF the miners boot with (audit C2). vali fetches it from
# S3 and SHA256-verifies against this pin before feeding it to the
# recompute — a fleet-wide constant (identical Genoa + Turin). Empty ⇒
# recompute disabled.
VALI_SNP_OVMF_S3_URI = os.environ.get("VALI_SNP_OVMF_S3_URI", "")
VALI_SNP_OVMF_SHA256 = os.environ.get("VALI_SNP_OVMF_SHA256", "")
# SEV-SNP guest-features bitmap the miner measures with (`SNP_GUEST_
# FEATURES` = 0x1 = SNPActive). MUST match the miner-agent constant.
VALI_SNP_GUEST_FEATURES = os.environ.get("VALI_SNP_GUEST_FEATURES", "0x1")
# Per-pod cache of the sha-pinned launch artifacts the C2 recompute fetches
# (OVMF, each bake's kernel/initrd), keyed by sha and re-verified on every
# load (`apps.orchestration.services.s3_artifacts`). Empty ⇒ a directory
# under the system temp dir. LRU-capped at MAX_BYTES.
VALI_ARTIFACT_CACHE_DIR = os.environ.get("VALI_ARTIFACT_CACHE_DIR", "")
VALI_ARTIFACT_CACHE_MAX_BYTES = _env_int("VALI_ARTIFACT_CACHE_MAX_BYTES", 300 << 20)
# ENFORCE gate. `False` (default) ⇒ WARN mode: recompute + compare +
# loud-log a mismatch but still pin the miner value (validation window).
# `True` ⇒ fail-closed: a mismatch REFUSES the launch (no pin, no KEK)
# and vali pins ONLY its own recomputed value.
VALI_LAUNCH_DIGEST_ENFORCE = os.environ.get("VALI_LAUNCH_DIGEST_ENFORCE", "false").lower() == "true"
# In-cluster filesystem path to the manifest TOML the allowlist tool
# signs. Mounted into the vali pod as a Volume / ConfigMap so it can
# be edited in place; the auto-pin reads + bumps `epoch` + appends one
# `[[entries]]` block, writes a temp copy, and signs it.
VALI_ALLOWLIST_MANIFEST_PATH = os.environ.get(
    "VALI_ALLOWLIST_MANIFEST_PATH",
    "/etc/hippius/allowlist/dev-manifest.toml",
)
# S3 URL the KBS init container fetches the signed COSE from. MUST
# equal `deploy/gitops/apps/kbs/values.yaml::allowlist.url`. Vali
# subprocesses `aws s3 cp` (env-supplied creds) to overwrite the
# object, then patches the KBS deployment to expect the new sha.
#
# NO DEFAULT, deliberately. This is a WRITE target: the auto-pin
# OVERWRITES the object at this URL on every launch. A default pointing
# at any real bucket would make a fresh deployment try to overwrite
# somebody else's allowlist. Unset ⇒ `pin_measurement` raises
# `EffectUnavailable: VALI_KBS_ALLOWLIST_S3_URL is not configured`.
# Set it to YOUR bucket, e.g.
# `https://<S3_ENDPOINT_HOST>/<YOUR_BUCKET>/allowlist/v1/prod.cose`.
VALI_KBS_ALLOWLIST_S3_URL = os.environ.get("VALI_KBS_ALLOWLIST_S3_URL", "")
# Object-store endpoint every `aws` shell-out is pointed at (allowlist
# pin, preflight presign, OVMF fetch, tenant-bake Jobs). Empty ⇒ the
# `aws` CLI's own default, i.e. real AWS S3 — so set this explicitly to
# your own endpoint (`https://<S3_ENDPOINT_HOST>`) when running against
# a MinIO-compatible / self-hosted object store.
VALI_S3_ENDPOINT_URL = os.environ.get("VALI_S3_ENDPOINT_URL", "")
VALI_AWS_CLI_BIN = os.environ.get("VALI_AWS_CLI_BIN", "aws")

# ── KBS admin mTLS material (see services/kbs_admin_tls.py) ─────────
#
# The lifecycle admin API's ONLY authentication is mTLS at the listener
# (`kbs-server/src/admin_tls.rs`) — none of its routes carries a
# per-request credential, and every one of them mutates the state that
# decides which host may unlock a tenant's disk. These three paths are
# vali's half of that gate and are required TOGETHER whenever
# `VALI_KBS_ADMIN_URL` is `https://`; `services.kbs_admin_tls` refuses
# to dial rather than fall back to system roots + no client cert.
#
# The CA bundle PINS the admin listener's server cert: it REPLACES the
# system trust store for this hop (CPython only loads the default certs
# when no cafile is given), so no public CA can satisfy an internal
# service — the coupling that #776 had to undo elsewhere.
VALI_KBS_ADMIN_CACERT = os.environ.get("VALI_KBS_ADMIN_CACERT", "")
# vali's client identity on the admin hop. The leaf's SAN URI
# (`spiffe://hippius.network/vali`) becomes the `peer_san` recorded in
# every KBS admin audit row, which is what makes those rows attributable
# — before this, `peer_san` was always None.
VALI_KBS_ADMIN_CLIENT_CERT = os.environ.get("VALI_KBS_ADMIN_CLIENT_CERT", "")
# Private key for the cert above. Mounted from a Secret (Vault → ESO);
# read by OpenSSL inside `load_cert_chain`, never into a Python string,
# never logged.
VALI_KBS_ADMIN_CLIENT_KEY = os.environ.get("VALI_KBS_ADMIN_CLIENT_KEY", "")

VALI_NETBIRD_API_BASE = os.environ.get("VALI_NETBIRD_API_BASE", "https://api.netbird.io")
# The NetBird admin token is a secret — it rides the `Authorization`
# header of the peer-revoke call only; never logged, never persisted.
VALI_NETBIRD_API_TOKEN = os.environ.get("VALI_NETBIRD_API_TOKEN", "")

# ─── Tenant NetBird peer janitor (`apps.orchestration.netbird_janitor`) ───
# Tenant peers are PERSISTENT (NetBird never GCs them), so a §24 revoke that
# failed would leak one forever. The janitor deletes `hippius-tenant-<vm_id>`
# peers whose VM is Destroyed, or has no `Vm` row and has been offline past
# the grace below. Kill switch:
VALI_NETBIRD_PEER_JANITOR_ENABLED = _env_bool("VALI_NETBIRD_PEER_JANITOR_ENABLED", True)
# Log what WOULD be deleted, delete nothing.
VALI_NETBIRD_PEER_JANITOR_DRY_RUN = _env_bool("VALI_NETBIRD_PEER_JANITOR_DRY_RUN", False)
# One pass (one `GET /api/peers`) at most every this many seconds.
VALI_NETBIRD_PEER_JANITOR_INTERVAL_S = _env_int("VALI_NETBIRD_PEER_JANITOR_INTERVAL_S", 300)
# At most this many deletions per pass — a bad listing or a bad join can
# never sweep the account in one go.
VALI_NETBIRD_PEER_JANITOR_MAX_DELETES = _env_int("VALI_NETBIRD_PEER_JANITOR_MAX_DELETES", 5)
# A peer with NO `Vm` row is deleted only once it is disconnected AND NetBird
# last saw it at least this long ago. Longer than any launch (the row exists
# before dispatch anyway) and far longer than the ~10 min an ephemeral peer
# used to survive offline.
VALI_NETBIRD_PEER_JANITOR_ORPHAN_GRACE_S = _env_int(
    "VALI_NETBIRD_PEER_JANITOR_ORPHAN_GRACE_S", 3600
)
# ASSUMPTION: this vali is the ONLY control plane enrolling
# `hippius-tenant-*` peers in its NetBird account (true since the testnet
# was abandoned — one vali, one account). Another vali's VMs would have no
# `Vm` row here, so the "no row" rule would delete their peers. Set False if
# the account is ever shared: then only peers of Destroyed VMs are deleted.
VALI_NETBIRD_PEER_JANITOR_SOLE_OWNER = _env_bool(
    "VALI_NETBIRD_PEER_JANITOR_SOLE_OWNER", True
)

# ─── Miner geo-probe (`vali_geo_probe`) — DETECTED location, nothing declared ───
# Every input is measured by a party the miner does not control: the public
# IP its NetBird peer connects FROM (management server), GeoIP/ASN of that
# IP (RIPEstat), the round-trip time vali measures to it, and the egress IP
# its tenant CVMs report. `apps/miners/geo.py` explains each.
VALI_GEO_PROBE_INTERVAL_S = _env_float("VALI_GEO_PROBE_INTERVAL_S", 600.0)
# RIPEstat data API (public, key-free). Empty ⇒ every lookup fails and
# every miner stays `unknown` — never silently "verified".
VALI_GEO_RIPESTAT_BASE = os.environ.get("VALI_GEO_RIPESTAT_BASE", "https://stat.ripe.net")
# Outbound HTTP timeout for the NetBird + RIPEstat calls.
VALI_GEO_HTTP_TIMEOUT_S = _env_float("VALI_GEO_HTTP_TIMEOUT_S", 10.0)
# WHERE the RTT is measured from — the control plane's own coordinates.
# The latency bound is `distance(vantage, geo) <= rtt_ms * KM_PER_MS +
# SLACK_KM`; a wrong vantage flips every miner to `latency-inconsistent`
# (fail-closed, visible), never to a false `verified`. Set these to the
# control plane's own location.
VALI_GEO_VANTAGE_NAME = os.environ.get("VALI_GEO_VANTAGE_NAME", "vali")
VALI_GEO_VANTAGE_LAT = _env_float("VALI_GEO_VANTAGE_LAT", 0.0)
VALI_GEO_VANTAGE_LON = _env_float("VALI_GEO_VANTAGE_LON", 0.0)
# Light in fibre ≈ 200 km/ms one way ⇒ ~100 km per ms of ROUND-TRIP. Raising
# this loosens the bound (more tunnels pass); it is physics, leave it.
VALI_GEO_KM_PER_MS = _env_float("VALI_GEO_KM_PER_MS", 100.0)
# Tolerance for GeoIP centroid error + queueing: a country-level GeoLite
# point (a provider's ranges may resolve to its capital whatever the DC)
# needs a few hundred km.
VALI_GEO_SLACK_KM = _env_float("VALI_GEO_SLACK_KM", 300.0)
# A peer not seen by NetBird within this window is `peer-stale`
# (unverified) — its connection_ip may be history.
VALI_GEO_PEER_STALE_S = _env_float("VALI_GEO_PEER_STALE_S", 900.0)
# Re-ask RIPEstat only when the observed IP changed or the row is older
# than this; the RTT is re-measured every cycle regardless.
VALI_GEO_GEOIP_TTL_S = _env_float("VALI_GEO_GEOIP_TTL_S", 86400.0)
VALI_GEO_RTT_SAMPLES = _env_int("VALI_GEO_RTT_SAMPLES", 5)
# The OTHER side of the latency check — a nearby claim must answer with a
# nearby round-trip: `rtt <= (distance / KM_PER_MS) * PATH_FACTOR + EXTRA_MS`.
# Real paths wander ~2-2.5× the great circle and queue a few tens of ms;
# a host on another continent tunnelling through a nearby VPN exit cannot
# get under this because its packets still travel to where it really is.
# Loosening these is what lets a VPN pass.
VALI_GEO_RTT_PATH_FACTOR = _env_float("VALI_GEO_RTT_PATH_FACTOR", 2.5)
VALI_GEO_RTT_EXTRA_MS = _env_float("VALI_GEO_RTT_EXTRA_MS", 30.0)
# A `MinerLocation` older than this is not in ANY region for the scheduler
# or the regions API — a probe that stopped, or a miner that vanished from
# NetBird, must not leave a `verified` verdict standing. 12 probe cycles.
VALI_GEO_MAX_AGE_S = _env_float("VALI_GEO_MAX_AGE_S", 7200.0)
# The scheduler's region gate and `GET /v1/operator/regions` count a miner
# as being in a region only when its verdict is `verified`. False widens
# both to `unverified` rows as well (never `mismatch` — a contradiction —
# nor `unknown`) — a debugging posture, not a production one.
VALI_GEO_REQUIRE_VERIFIED = _env_bool("VALI_GEO_REQUIRE_VERIFIED", True)

# Grace window a §25-migrated VM's NetBird peer gets to come back
# CONNECTED before `orchestration.service.verify_netbird_enrolments`
# declares it `lost` (P9/#17). Only bounds the AMBIGUOUS case (the peer
# record still exists but the guest has not dialled in yet) — a DELETED
# peer record is terminal the moment it is observed, since the guest's
# one-off launch setup key cannot re-register it.
VALI_NETBIRD_VERIFY_GRACE_S = float(
    os.environ.get("VALI_NETBIRD_VERIFY_GRACE_S", "900")
)

# Public IPs (`apps.network`). A released address is held out of the pool
# this long before another TENANT can get it (the tenant that released it
# may take it back at once), so traffic still aimed at the previous holder
# never reaches someone else. The edge drops the address's rules and flushes
# its conntrack entries on its next render, so no established flow outlives
# the detach; what the window still covers is DNS records and caches that
# point at the address (TTLs of minutes, rarely more than an hour).
VALI_PUBLIC_IP_QUARANTINE_S = _env_float("VALI_PUBLIC_IP_QUARANTINE_S", 3600.0)
# How often the orchestration tick re-reads NetBird to follow attached
# VMs' overlay addresses and fix the edges' exit routing. An attach or a
# detach forces the next tick regardless.
VALI_PUBLIC_IP_NETBIRD_SYNC_S = _env_int("VALI_PUBLIC_IP_NETBIRD_SYNC_S", 30)
# When set, an ingress edge's NetBird peer must belong to this group (the
# group its setup key enrols it in) to be registered or routed through.
# A tenant VM's peer is refused either way.
VALI_PUBLIC_IP_EDGE_PEER_GROUP = os.environ.get("VALI_PUBLIC_IP_EDGE_PEER_GROUP", "")

# Guest network policy (`apps.network.net_policy`, egress design §7): the
# host-wide `net-policy` order each miner gets — guest bandwidth caps,
# port 25, the edge-mode allowlist. Off by default: while off nothing is
# pushed. On, only the miners in VALI_NET_POLICY_MINERS get it (explicit
# miner ids, or `*` for all), so a canary goes first. The agents must carry
# the net-policy order before any miner is listed.
VALI_NET_POLICY_PUSH = _env_bool("VALI_NET_POLICY_PUSH", False)
VALI_NET_POLICY_MINERS = _env_list("VALI_NET_POLICY_MINERS")
# What the local-mode rules do with a matching packet: `count` or `drop`.
VALI_NET_POLICY_LOCAL_ACTION = os.environ.get("VALI_NET_POLICY_LOCAL_ACTION", "count")
# A policy is re-sent this often (drift repair, expiry renewal), and retried
# this often while its current revision is not acked.
VALI_NET_POLICY_SYNC_S = _env_int("VALI_NET_POLICY_SYNC_S", 600)
VALI_NET_POLICY_RETRY_S = _env_int("VALI_NET_POLICY_RETRY_S", 60)
# A miner whose agent failed to install the rules (500 `net-policy-apply`)
# gets the SAME revision again, every RETRY_S doubled per failure, capped
# here.
VALI_NET_POLICY_APPLY_BACKOFF_MAX_S = _env_int("VALI_NET_POLICY_APPLY_BACKOFF_MAX_S", 1800)
# An agent that refused an edge-mode policy as unsupported (422
# `net-policy-unsupported`) is not sent edge mode again for this long. vali
# sees no agent version, so this is the probe interval after an upgrade;
# `manage.py vali_net_policy --retry <miner>` re-offers it at once.
VALI_NET_POLICY_UNSUPPORTED_RETRY_S = _env_int("VALI_NET_POLICY_UNSUPPORTED_RETRY_S", 21600)
# The policy's own validity (`not_after`). The miner refuses more than 7 days.
VALI_NET_POLICY_TTL_S = _env_int("VALI_NET_POLICY_TTL_S", 86400)
# Edge mode: a miner whose ack of its current revision is older than this
# takes no new placement.
VALI_NET_POLICY_ACK_STALE_S = _env_int("VALI_NET_POLICY_ACK_STALE_S", 1800)
# Wall-clock budget of one reconcile pass in the orchestration tick; the
# miners not reached go first on the next pass.
VALI_NET_POLICY_TICK_BUDGET_S = _env_float("VALI_NET_POLICY_TICK_BUDGET_S", 120.0)
# Per-tap DNS budget, packets per second.
VALI_NET_POLICY_DNS_LIMIT_PPS = _env_int("VALI_NET_POLICY_DNS_LIMIT_PPS", 20)
# Edge mode only: the infra WireGuard endpoints and the NetBird management /
# signal / STUN endpoints the miners allow, JSON `[{"ip", "proto", "port"}]`.
VALI_NET_POLICY_INFRA = json.loads(os.environ.get("VALI_NET_POLICY_INFRA", "[]"))
VALI_NET_POLICY_NB_CONTROL = json.loads(os.environ.get("VALI_NET_POLICY_NB_CONTROL", "[]"))
# Per-VM bandwidth cap, Mbit/s, by flavor (§7.1). A `runner-*` flavor takes
# its base flavor's cap; a flavor not listed takes the default. A VM holding
# a public IP gets at least VALI_NET_CAP_PUBLIC_IP_MBPS. The xlarge and up
# values are provisional.
VALI_NET_CAP_MBPS_BY_FLAVOR = json.loads(
    os.environ.get(
        "VALI_NET_CAP_MBPS_BY_FLAVOR",
        '{"small": 100, "medium": 250, "large": 500, '
        '"xlarge": 500, "2xlarge": 500, "4xlarge": 500}',
    )
)
VALI_NET_CAP_DEFAULT_MBPS = _env_int("VALI_NET_CAP_DEFAULT_MBPS", 100)
# Launch, relaunch and §25 orders carry the guest NIC spec (`net`: the cap,
# a deterministic tap name, libvirt's `clean-traffic` filter, and an
# isolated bridge port when VALI_NET_LAUNCH_ISOLATE). Off by default. On,
# only to the miners in VALI_NET_LAUNCH_SPEC_MINERS (explicit ids, or `*`)
# that have acked a net-policy. List a miner only once it runs an agent
# that knows `net` (an older one refuses every launch that carries it; a
# net-policy ack alone does not prove it) and `virsh nwfilter-list` shows
# `clean-traffic` with a working nwfilter driver (else its launches fail).
VALI_NET_LAUNCH_SPEC = _env_bool("VALI_NET_LAUNCH_SPEC", False)
VALI_NET_LAUNCH_SPEC_MINERS = _env_list("VALI_NET_LAUNCH_SPEC_MINERS")
VALI_NET_LAUNCH_ISOLATE = _env_bool("VALI_NET_LAUNCH_ISOLATE", True)
VALI_NET_CAP_PUBLIC_IP_MBPS = _env_int("VALI_NET_CAP_PUBLIC_IP_MBPS", 250)
# Egress feed (`apps.network.egress`, egress design §5.2): an edge of an
# `edge`-mode region with an `egress_ip` is told which overlay address is
# which VM (with an epoch and a tc class each), and its address table gains
# vm_region/epoch/cap_mbps/smtp_allowed. Off by default: while off every
# edge's feed is exactly what it was.
VALI_EGRESS_FEED_ENABLED = _env_bool("VALI_EGRESS_FEED_ENABLED", False)
# The VMs that may be put in an egress feed (comma-separated vm ids, `*` =
# all), on top of the region's `routing_enabled`. Empty = none, so a canary
# goes first.
VALI_EGRESS_VMS = _env_list("VALI_EGRESS_VMS")
# Every bound edge's address table carries each address's vm_region (when
# known) and epoch, local-mode edges included, so the backend can price an
# address's bandwidth by region. Never cap_mbps or smtp_allowed outside
# egress mode. Off by default: while off every feed is exactly what it was.
# A flip bumps the revision of the edges it changes.
VALI_FEED_ADDRESS_REGION = _env_bool("VALI_FEED_ADDRESS_REGION", False)
# Every bound edge's feed carries a top-level `block_smtp: true` (the edge
# drops TCP 25 from every public-IP VM), and each address whose port 25 was
# unblocked carries `smtp_allowed: true`, local-mode edges included. Off by
# default: while off every feed is exactly what it was. A flip bumps the
# revision of every bound edge.
VALI_FEED_BLOCK_SMTP = _env_bool("VALI_FEED_BLOCK_SMTP", False)
# CDN fleet (docs/design/cdn.md). Off by default: while off no CDN address
# is attached (`apps.network.service.attach_cdn` refuses) and every edge's
# feed is exactly what it was — `pool` and the per-address `cap_mbps` of
# the `cdn` addresses are served only while on (applied per edge by the
# orchestration tick, with a revision bump). Detach the CDN nodes before
# turning it off: an attached CDN address is then fed as a plain one.
VALI_CDN_ENABLED = _env_bool("VALI_CDN_ENABLED", False)
# The internal tenant every CDN node runs as. Only its VMs take a `cdn`
# address, and they never take a general one.
VALI_CDN_TENANT_ID = os.environ.get("VALI_CDN_TENANT_ID", "hippius-cdn").strip()
# The miner-side bandwidth cap of a CDN node, Mbit/s, in place of
# VALI_NET_CAP_MBPS_BY_FLAVOR (CDN plan N2); edge mode adds the same tunnel
# room as a flavor cap. 0 (the default) = no cap. Only while
# VALI_CDN_ENABLED is on.
VALI_CDN_NET_CAP_MBPS = _env_int("VALI_CDN_NET_CAP_MBPS", 0)
# Launching CDN nodes (CDN plan V2, `apps.cdn.identity`): a CDN node's
# launch carries the `cdn-node` ticket perm, the measured role tokens and a
# `cdn_node`-class pin. Off by default: while off such a launch refuses
# (`cdn-role-disabled`) and no `cdn_node` pin is written. Turn on only once
# the KBS that knows the `cdn_node` class (K1) is live — an older one
# rejects the whole allowlist. Turning it off later keeps live CDN VMs
# running and pinned (the carry-forward classes them by their node), but
# every relaunch of one (reboot recovery, power start, resize) refuses too:
# a CDN node is replaced, not relaunched.
VALI_CDN_LAUNCH_ROLE = _env_bool("VALI_CDN_LAUNCH_ROLE", False)
# The CDN fleet reconciler (CDN plan V3, `apps.cdn.reconcile`), run by the
# orchestration tick: launches, readies, drains and replaces nodes per
# `CdnRegion`. Off by default: while off the fleet is frozen as it is.
VALI_CDN_RECONCILE_ENABLED = _env_bool("VALI_CDN_RECONCILE_ENABLED", False)
# After the backend's dns-released ack, wait this long before the §24
# decommission (90 s + 2 × the 60 s record TTL). Without an ack a node is
# never decommissioned; past VALI_CDN_DRAIN_ACK_TIMEOUT_S vali alerts.
VALI_CDN_DRAIN_GRACE_S = _env_int("VALI_CDN_DRAIN_GRACE_S", 210)
VALI_CDN_DRAIN_ACK_TIMEOUT_S = _env_int("VALI_CDN_DRAIN_ACK_TIMEOUT_S", 1800)
# A ready node whose guest stayed wedged (no in-guest signal) this long
# fails and is replaced; a node not ready this long after its launch, too.
VALI_CDN_WEDGED_S = _env_int("VALI_CDN_WEDGED_S", 600)
VALI_CDN_BOOT_TIMEOUT_S = _env_int("VALI_CDN_BOOT_TIMEOUT_S", 1800)
# Nodes launching or booting at once, per region.
VALI_CDN_MAX_PARALLEL_LAUNCH = _env_int("VALI_CDN_MAX_PARALLEL_LAUNCH", 1)
# A replacement must have been ready this long (so the backend has its
# record) before the node it replaces drains.
VALI_CDN_READY_SETTLE_S = _env_int("VALI_CDN_READY_SETTLE_S", 600)
# After a failed launch in a region, wait this long before the next one.
VALI_CDN_LAUNCH_BACKOFF_S = _env_int("VALI_CDN_LAUNCH_BACKOFF_S", 600)
# The reconciler's outage breakers: they compare against the VMs and miners
# heard from in this window, and the liveness hold lasts at most this long.
VALI_CDN_BREAKER_CONTROL_WINDOW_S = _env_int("VALI_CDN_BREAKER_CONTROL_WINDOW_S", 86400)
# 4 h: long, because while held the domain-down and host-gone checks still
# fail the nodes that are really dead, so a hold mostly protects live ones.
VALI_CDN_BREAKER_MAX_HOLD_S = _env_int("VALI_CDN_BREAKER_MAX_HOLD_S", 14400)
# What a node launches: the blessed image name (restricted to the CDN
# tenant).
VALI_CDN_IMAGE_NAME = os.environ.get("VALI_CDN_IMAGE_NAME", "cdn-node").strip()
# The base cmdline of every CDN node's launch, and the only one a CDN launch
# is accepted with. A node's relaunch must carry the same base cmdline,
# user-data (VALI_CDN_BACKEND_URL, its region) and image as its launch:
# changing any of them refuses it — nodes are replaced, not relaunched.
VALI_CDN_CMDLINE = os.environ.get(
    "VALI_CDN_CMDLINE",
    "console=ttyS0,115200 hippius.kbs_url=vsock://2:19266 ds=nocloud;s=/run/cloud-init/seed/",
)
# The CDN fleet keyring (`apps.cdn.fleet`, docs/operator/cdn-fleet-keyring.md):
# the KBS response key vali checks each version's public-key signature
# under (pinned out of band, 32-byte hex; empty refuses every mint), and
# where a minted version's ciphertext goes.
VALI_CDN_KBS_RESPONSE_VK_HEX = os.environ.get("VALI_CDN_KBS_RESPONSE_VK_HEX", "").strip()
VALI_CDN_FLEET_TRANSIT_KEY = os.environ.get("VALI_CDN_FLEET_TRANSIT_KEY", "cdn-fleet").strip()
VALI_CDN_FLEET_KV_PREFIX = os.environ.get(
    "VALI_CDN_FLEET_KV_PREFIX", "hippius-compute/kbs/cdn-fleet"
).strip()
# The CDN CA (`apps.cdn.ca`). Its Ed25519 private key is the Vault Transit
# key named here, created by an operator as non-exportable: vali only ever
# asks Transit to sign and reads its public half, never the key itself.
VALI_CDN_CA_TRANSIT_KEY = os.environ.get("VALI_CDN_CA_TRANSIT_KEY", "cdn-ca").strip()
# Lifetime of the self-signed CA certificate vali makes for a Transit key
# version, and of a node certificate (renewed at 2/3 of it).
VALI_CDN_CA_VALIDITY_DAYS = _env_int("VALI_CDN_CA_VALIDITY_DAYS", 1825)
VALI_CDN_NODE_CERT_DAYS = _env_int("VALI_CDN_NODE_CERT_DAYS", 7)
# SPIFFE trust domain of the node certificate SAN URI
# (`spiffe://<domain>/cdn/<region>/<vm_id>/g<generation>`); the cdn-agent
# bakes the same value.
VALI_CDN_TRUST_DOMAIN = os.environ.get("VALI_CDN_TRUST_DOMAIN", "hippius.network").strip()

# Live VM backups (`apps.backup`, docs/design/backup-failover.md). Off by
# default: while off the backup tick does nothing and a new backup policy
# is refused; existing policies and restore points are kept as they are.
VALI_BACKUP_ENABLED = _env_bool("VALI_BACKUP_ENABLED", False)
# vali's own bucket on its own S3 account — never a tenant's. The tenant has
# no right on it, so it can neither delete nor hide a backup. No default: it
# must be a DEDICATED private bucket, and vali refuses the images or the
# migration-snapshot bucket (the images one is public-read). The tick checks
# it is reachable before doing anything and logs an ERROR when it is not.
VALI_BACKUP_BUCKET = os.environ.get("VALI_BACKUP_BUCKET", "")
# The backup bucket's OWN key (e.g. `hippius-vm-backup`), separate from the
# default boto chain vali's images key rides: an object-level token scoped
# to that one bucket (object read/write + multipart; no bucket-admin calls).
# Fed from the `vali-backup-s3` Secret by the chart. Never logged.
VALI_BACKUP_S3_ACCESS_KEY_ID = os.environ.get("VALI_BACKUP_S3_ACCESS_KEY_ID", "")
VALI_BACKUP_S3_SECRET_ACCESS_KEY = os.environ.get("VALI_BACKUP_S3_SECRET_ACCESS_KEY", "")
VALI_BACKUP_S3_ENDPOINT_URL = os.environ.get("VALI_BACKUP_S3_ENDPOINT_URL", "")
# A chain is rebased (a new full is taken) once it holds this many
# incrementals, or once its incrementals add up to more than half the full.
VALI_BACKUP_MAX_CHAIN = _env_int("VALI_BACKUP_MAX_CHAIN", 24)
# Smallest multipart part vali hands out, clamped to the store's 512 MiB
# ceiling. The default IS the ceiling: the fewest parts (a 40 GiB disk
# stays within 100), so the smallest orders and status polls.
VALI_BACKUP_MIN_PART_BYTES = _env_int("VALI_BACKUP_MIN_PART_BYTES", 512 * 1024 * 1024)
# A run not done by then is failed (and its upload aborted). Also the TTL of
# the presigned part URLs, so it is capped at 24 h.
VALI_BACKUP_RUN_TIMEOUT_S = _env_int("VALI_BACKUP_RUN_TIMEOUT_S", 6 * 3600)
# A miner that no longer knows a run it accepted (agent restart) gets this
# long before the run is declared lost.
VALI_BACKUP_LOST_GRACE_S = _env_int("VALI_BACKUP_LOST_GRACE_S", 180)
# Consecutive failed status polls of a running backup before it is logged as
# a WARNING (fewer are INFO). A single miss is normal: while a run sets up its
# QMP job, libvirt serialises the status route's own monitor query behind it.
VALI_BACKUP_POLL_MISS_WARN = _env_int("VALI_BACKUP_POLL_MISS_WARN", 3)
# Client timeout of one status poll. Just above the Edge relay's own 30 s
# request cap, so a slow miner surfaces as the Edge's answer rather than a
# vali-side timeout (the generic effect timeout is 15 s).
VALI_BACKUP_POLL_TIMEOUT_S = _env_float("VALI_BACKUP_POLL_TIMEOUT_S", 32.0)
# How often an idle backed-up VM is probed for a reboot (new boot counter or
# a vanished dirty bitmap). A reboot makes every earlier backup
# unrestorable, so the post-boot full is taken as soon as one is seen.
VALI_BACKUP_PROBE_INTERVAL_S = _env_int("VALI_BACKUP_PROBE_INTERVAL_S", 300)
# Wait after a failed run before the next attempt (the next interval wins if
# it is sooner).
VALI_BACKUP_RETRY_AFTER_S = _env_int("VALI_BACKUP_RETRY_AFTER_S", 900)
# The backup janitor — what bucket lifecycle rules would do, done by vali
# because Hippius S3 acknowledges PutBucketLifecycle without enforcing it.
# Multipart uploads under `backups/` older than this that no active run
# owns are aborted; staged state disks under `uploads/` older than this
# that no active run owns are deleted.
VALI_BACKUP_MPU_MAX_AGE_S = _env_int("VALI_BACKUP_MPU_MAX_AGE_S", 2 * 86400)
VALI_BACKUP_STAGING_MAX_AGE_S = _env_int("VALI_BACKUP_STAGING_MAX_AGE_S", 2 * 86400)
# Items the janitor handles per tick per listing, and how often it starts a
# new sweep of the bucket once the previous one finished.
VALI_BACKUP_JANITOR_BATCH = _env_int("VALI_BACKUP_JANITOR_BATCH", 100)
VALI_BACKUP_JANITOR_INTERVAL_S = _env_int("VALI_BACKUP_JANITOR_INTERVAL_S", 3600)

# Restore a VM from one of its backups (`apps.orchestration.restore`,
# docs/design/backup-failover.md). Off by default: `POST /v1/vm/<id>/restore`
# answers `restore-disabled`; jobs already open keep being driven.
VALI_RESTORE_ENABLED = _env_bool("VALI_RESTORE_ENABLED", False)
# Parallel ranged GETs the destination opens per object while staging.
VALI_RESTORE_STREAMS = _env_int("VALI_RESTORE_STREAMS", 8)
# Throughput assumed for a destination with no measured full backup (the
# ETA), in bytes per second.
VALI_RESTORE_DEFAULT_THROUGHPUT_BPS = _env_int("VALI_RESTORE_DEFAULT_THROUGHPUT_BPS", 100_000_000)
# Phase deadlines. Staging gets three times its ETA, at least this, at most
# 12 h (the presigned URLs' cap).
VALI_RESTORE_STAGE_TIMEOUT_S = _env_float("VALI_RESTORE_STAGE_TIMEOUT_S", 3600.0)
VALI_RESTORE_STOP_TIMEOUT_S = _env_float("VALI_RESTORE_STOP_TIMEOUT_S", 600.0)
# How long the restored guest has to release its key (the commit point, read
# from the KBS evidence) once the destination booted it; past it with no
# sign of a release, the restore reverts.
VALI_RESTORE_VERIFY_TIMEOUT_S = _env_float("VALI_RESTORE_VERIFY_TIMEOUT_S", 900.0)
VALI_RESTORE_REVERT_TIMEOUT_S = _env_float("VALI_RESTORE_REVERT_TIMEOUT_S", 1800.0)
# A restore that fails AFTER its commit point keeps the original disk on the
# destination at least this long (and after it, until the restored VM is
# proven on the destination and alive).
VALI_RESTORE_KEEP_ORIGINAL_S = _env_float("VALI_RESTORE_KEEP_ORIGINAL_S", 86400.0)
# A2: restore a point of an EARLIER boot through a KBS-authorized rollback
# (`authorize-rollback`). Off by default: such points answer
# `rollback-unsupported`. Needs a KBS serving the rollback routes. Turning it
# off also fails a rollback restore that has not armed the KBS yet.
VALI_RESTORE_ROLLBACK_ENABLED = _env_bool("VALI_RESTORE_ROLLBACK_ENABLED", False)
# At most one rollback per VM this often (the KBS enforces its own too).
VALI_RESTORE_ROLLBACK_MIN_INTERVAL_S = _env_float("VALI_RESTORE_ROLLBACK_MIN_INTERVAL_S", 1800.0)
# An operator undo whose KBS arm is refused past its fence retries it this long
# (capped at half the undo phase's deadline), then gives the VM back to the
# restored disk at `undo_gen + 1` instead of leaving it fenced.
VALI_RESTORE_UNDO_ARM_RETRY_S = _env_float("VALI_RESTORE_UNDO_ARM_RETRY_S", 300.0)
# Operator-only manual failover of a VM whose miner is dead
# (`POST /v1/vm/<id>/failover`). Off by default: the route answers
# `failover-disabled`.
VALI_FAILOVER_MANUAL_ENABLED = _env_bool("VALI_FAILOVER_MANUAL_ENABLED", False)
# A miner is dead for a failover only when its heartbeat AND its NetBird peer
# have both been silent at least this long, and the Edge cannot reach it.
VALI_FAILOVER_DEAD_AFTER_S = _env_float("VALI_FAILOVER_DEAD_AFTER_S", 600.0)

# §25 SOURCE-side reclaim (P9/#15). A migration is a COPY: the source host
# keeps the tenant's LUKS overlay, the boot-counter state disk and the
# staged boot artifacts on a machine that no longer runs the VM and is
# UNTRUSTED. `orchestration.service.reclaim_migrated_sources` dispatches
# the §24 `destroy` order at the SOURCE once — and only once — the KBS's
# own evidence bundle proves it GRANTED the KEK to the destination chip at
# the migration generation.
#
# Default ON: every path that is not a positive proof already leaves the
# artifacts alone, so the flag is an operator kill-switch, not the safety.
VALI_MIGRATION_SOURCE_RECLAIM_ENABLED = _env_bool(
    "VALI_MIGRATION_SOURCE_RECLAIM_ENABLED", True
)
# How long a completed migration waits for that proof before the reclaim is
# abandoned with a LOUD `skipped` (the artifacts stay put). Generous: the
# cost of waiting is idle disk, the cost of giving up early is nothing.
# A §25 source is reclaimed only once the DESTINATION guest has proved it is
# running — an in-guest signal (served receipt / live attestation) at least
# this long after the migration finished — on top of the KBS grant proof. A
# destination that dies after its unlock (a volume the length/sha check did
# not catch) then never costs the source copy. Same gate for deleting the
# migration's S3 snapshot.
VALI_MIGRATION_RECLAIM_LIVENESS_GRACE_S = _env_float(
    "VALI_MIGRATION_RECLAIM_LIVENESS_GRACE_S", 600.0
)
# How long a FAILED migration's S3 snapshot is kept once its VM is back on
# its source (a re-drive is then impossible, so the snapshot is dead weight).
VALI_MIGRATION_SNAPSHOT_RETENTION_S = _env_float(
    "VALI_MIGRATION_SNAPSHOT_RETENTION_S", 3 * 86400.0
)
VALI_MIGRATION_SOURCE_RECLAIM_WINDOW_S = _env_float(
    "VALI_MIGRATION_SOURCE_RECLAIM_WINDOW_S", 6 * 3600.0
)

# §25 STRANDED-migration recovery. A migration that fails from `Quiescing`
# onward leaves the `Vm` fenced in `migrating` with no domain on either
# host — down, and outside every automatic sweep (`reboot_recovery_once`
# scans `active` only). `orchestration.service.sweep_stranded_migrations`
# always DETECTS + reports those; this flag governs only the automatic
# SOURCE RESTORE, and only for the class where vali's own durable record
# PROVES the job never entered `DestActivating` — i.e. `kbs_activate_dest`
# was never called, the KBS `VmState` is still `Active{source_gen, source}`
# and the source remains the only host that can unlock the disk. Once the
# KBS has moved there is no route back (its `activate` is forward-only and
# refuses every non-`Active` state), so that class is operator-only:
# `manage.py vali_migration_recover --action redrive-dest`.
#
# Default ON, same posture as the reclaim above: the evidence gate is the
# safety, the flag is an operator kill-switch.
VALI_MIGRATION_STRAND_RESTORE_ENABLED = _env_bool(
    "VALI_MIGRATION_STRAND_RESTORE_ENABLED", True
)
# Kill-switch for AUTOMATIC §25 enrolment (`enroll_departing_miner_migrations`:
# every Active VM on a quarantined / decommissioned / exiting miner). Off, a
# departing miner's VMs stay where they are; operator-started migrations are
# unaffected. For when §25 itself cannot succeed (e.g. an upload path that
# refuses the volume), so VMs do not cycle fence → fail → restore.
VALI_MIGRATION_AUTO_ENROL_ENABLED = _env_bool("VALI_MIGRATION_AUTO_ENROL_ENABLED", True)
# How often the stranded-VM ERROR line repeats while the condition
# persists (it is permanent until an operator acts, and the tick runs
# every ~10 s). A change to the stranded SET always re-warns immediately.
VALI_MIGRATION_STRAND_WARN_INTERVAL_S = _env_float(
    "VALI_MIGRATION_STRAND_WARN_INTERVAL_S", 900.0
)
# How many FAILED migrations a VM may accumulate before the sweep stops
# restoring it AUTOMATICALLY. Bounds the one loop this recovery can create:
# an ack-timeout §13-quarantines the source, `enroll_departing_miner_
# migrations` auto-enrols a fresh migration for every Active VM on a
# quarantined miner, and a restore hands the VM straight back to it. That
# direction is correct — a VM on a departing miner should keep trying to
# leave — so the cap is generous, and it gates only the automatic action:
# past it the VM is reported for an operator, who can still run the same
# restore explicitly.
VALI_MIGRATION_STRAND_MAX_FAILURES = _env_int(
    "VALI_MIGRATION_STRAND_MAX_FAILURES", 3
)

# ──────────────────────────────────────────────────────────────────
# PR-G6: §9 pull-only telemetry broker
# ──────────────────────────────────────────────────────────────────
# Sources POST signed envelopes to /v1/telemetry/ingest; internal
# consumers drain via GET /v1/telemetry/pull. Strictly pull-only —
# the broker never makes an outbound request to a source.

# `ServiceClient.name` permitted to drain the broker via the
# root-only /pull endpoint. Empty default fails closed.
VALI_TELEMETRY_ROOT_PRINCIPAL = os.environ.get("VALI_TELEMETRY_ROOT_PRINCIPAL", "")

# Bounded queue: once this many envelopes are `Pending`, /ingest
# returns 503 + Retry-After (backpressure). The check is a plain
# COUNT — it takes no lock.
VALI_TELEMETRY_MAX_PENDING = _env_int("VALI_TELEMETRY_MAX_PENDING", 100_000)

# Per-source share of the pending queue (RA-M4). A single telemetry source
# holding a valid key could otherwise flood VALID envelopes until the GLOBAL
# `MAX_PENDING` cap 503s every other source's heartbeats + billing receipts.
# Each source is capped to this many un-drained envelopes (clamped to the
# global budget), so one flooder can starve at most its own share. A real
# source has ~1 pending envelope between meter cycles, so 1000 is generous.
VALI_TELEMETRY_MAX_PENDING_PER_SOURCE = _env_int("VALI_TELEMETRY_MAX_PENDING_PER_SOURCE", 1000)

# Hard cap on a single decoded telemetry payload. Kept small —
# telemetry envelopes are tiny — so the hex-encoded JSON ingest body
# stays well under `DATA_UPLOAD_MAX_MEMORY_SIZE`.
VALI_TELEMETRY_MAX_ENVELOPE_BYTES = _env_int("VALI_TELEMETRY_MAX_ENVELOPE_BYTES", 16384)

# §9 poison-message quarantine: this many CONSECUTIVE verification
# failures from one source inside the rolling window quarantines
# that source for the TTL (every further ingest refused, 429).
VALI_TELEMETRY_QUARANTINE_THRESHOLD = _env_int("VALI_TELEMETRY_QUARANTINE_THRESHOLD", 3)
VALI_TELEMETRY_QUARANTINE_WINDOW_S = _env_int("VALI_TELEMETRY_QUARANTINE_WINDOW_S", 300)
VALI_TELEMETRY_QUARANTINE_TTL_S = _env_int("VALI_TELEMETRY_QUARANTINE_TTL_S", 3600)

# Retry-After (seconds) returned with a backpressure 503.
VALI_TELEMETRY_BACKPRESSURE_RETRY_AFTER_S = _env_int(
    "VALI_TELEMETRY_BACKPRESSURE_RETRY_AFTER_S", 30
)

# Max page size of one /pull; terminal-envelope GC retention +
# sweep interval.
VALI_TELEMETRY_PULL_MAX_LIMIT = _env_int("VALI_TELEMETRY_PULL_MAX_LIMIT", 1000)
VALI_TELEMETRY_GC_AGE_DAYS = _env_int("VALI_TELEMETRY_GC_AGE_DAYS", 7)
VALI_TELEMETRY_GC_INTERVAL_S = _env_float("VALI_TELEMETRY_GC_INTERVAL_S", 3600.0)

# §K heartbeat ingest (PR-Part4-B): the ±window, in seconds, a signed
# heartbeat's `timestamp_unix` may differ from vali's clock before the
# ingest gate rejects it (anti-replay-across-time).
VALI_HEARTBEAT_SKEW_SECONDS = _env_int("VALI_HEARTBEAT_SKEW_SECONDS", 300)

# ──────────────────────────────────────────────────────────────────
# Blackbox host-attestor telemetry (blackbox host-attestor chantier PR-8)
# ──────────────────────────────────────────────────────────────────
# The KBS L0 Ed25519 PUBLIC verifying key (64 hex chars) vali checks a
# `SignedHostAttestorCert` signature against. SEAM — vali does not
# universally hold the KBS L0 pubkey today (it relays other L0-signed
# artifacts to tenants for offline re-verification), so this defaults
# UNSET: while unset, an ingested cert is decode-only and persisted
# `pending`, NEVER `attested`. An operator wires the real key (staged in
# Vault/k8s) for certs to reach `attested`. A malformed value fail-closes
# to unset. This is a PUBLIC key — never a secret.
VALI_KBS_L0_VERIFYING_KEY = os.environ.get("VALI_KBS_L0_VERIFYING_KEY", "")

# ±window (seconds) a host-attestor beacon's `observed_at_unix` /
# `expiry_unix` may differ from vali's clock (anti-replay-across-time).
VALI_HOST_ATTESTOR_SKEW_SECONDS = _env_int("VALI_HOST_ATTESTOR_SKEW_SECONDS", 300)

# ──────────────────────────────────────────────────────────────────
# Blackbox host-attestor single-use nonce authority (PR-10)
# ──────────────────────────────────────────────────────────────────
# When TRUE, the host-attestor cert-ingest REQUIRES the report's nonce to
# match a vali-issued, unspent, unexpired nonce bound to the cert's
# {node_id, attestor_pubkey}, and marks it spent atomically (single-use).
# DEFAULT FALSE so an INERT deployment still ingests certs on the legacy
# (informational-nonce) path until the channel is armed. This flag is the
# teeth of security-must-have #3 (fresh nonce channel) and MUST be turned
# ON in lockstep with arming host-attestor consumption (PR-11/PR-13) — a
# fresh vali nonce is worthless if the ingest never checks it.
VALI_HOST_ATTESTOR_REQUIRE_NONCE = _env_bool("VALI_HOST_ATTESTOR_REQUIRE_NONCE", False)

# TTL (seconds) of a minted enrollment nonce. The attestor derives its key
# and enrols within a couple of seconds of pulling the nonce; a short
# window bounds the freshness. A nonce past its `expires_at` is rejected at
# cert-ingest even if unspent.
VALI_HOST_ATTESTOR_NONCE_TTL_S = _env_int("VALI_HOST_ATTESTOR_NONCE_TTL_S", 300)

# ──────────────────────────────────────────────────────────────────
# Blackbox host-attestor admin-release + reconcile (PR-9)
# ──────────────────────────────────────────────────────────────────
# The single `ServiceClient.name` that `IsHostAttestorAdmin` accepts on
# `POST /v1/admin/host-attestor/release` (publishing a blackbox UKI release
# is a fleet-wide trust-root operator action). Empty fails closed.
VALI_HOST_ATTESTOR_ADMIN_PRINCIPAL = os.environ.get("VALI_HOST_ATTESTOR_ADMIN_PRINCIPAL", "")

# Keyless cosign verification of the release artifact (security must-have
# #4). The `cosign` CLI (shelled out), and the PINNED signing identity +
# OIDC issuer of PR-6's `blackbox-uki-build.yml`. Empty identity/issuer
# fail closed — vali refuses to verify an unpinned identity (any Fulcio
# cert would otherwise pass). NOT secrets — public CI-workflow identity.
VALI_COSIGN_BIN = os.environ.get("VALI_COSIGN_BIN", "cosign")
VALI_HOST_ATTESTOR_COSIGN_IDENTITY = os.environ.get("VALI_HOST_ATTESTOR_COSIGN_IDENTITY", "")
VALI_HOST_ATTESTOR_COSIGN_ISSUER = os.environ.get(
    "VALI_HOST_ATTESTOR_COSIGN_ISSUER",
    # The keyless GitHub-Actions OIDC issuer (not a secret; the SAN
    # identity is the real pin and MUST be set explicitly).
    "https://token.actions.githubusercontent.com",
)
VALI_COSIGN_TIMEOUT_S = float(os.environ.get("VALI_COSIGN_TIMEOUT_S", "60"))

# Cap on the inline base64 blackbox-UKI blob the release POSTs (bytes).
VALI_HOST_ATTESTOR_MAX_ARTIFACT_BYTES = _env_int(
    "VALI_HOST_ATTESTOR_MAX_ARTIFACT_BYTES", 64 * 1024 * 1024
)

# Reconcile CronJob: how recently an `attested` host-attestor must have
# been seen to count as covered (seconds). WARN-ONLY — gates nothing.
VALI_HOST_ATTESTOR_LIVENESS_WINDOW_S = _env_int("VALI_HOST_ATTESTOR_LIVENESS_WINDOW_S", 600)

# ──────────────────────────────────────────────────────────────────
# Blackbox host-attestor dispatchability + reward gates (PR-11)
# ──────────────────────────────────────────────────────────────────
# BOTH default FALSE ⇒ the mechanism ships INERT: a default deployment
# produces BYTE-IDENTICAL dispatch + epoch weights as before. Flipping
# either flag is a deliberate operator action at PR-13 arming and INHERITS
# the open GA-blockers (M-of-N release signing, cosign-admission, C1 online
# allowlist-root) AND requires `VALI_KBS_L0_VERIFYING_KEY` wired so an
# `attested` row is meaningful (until then EVERY ingested cert is `pending`,
# which these gates NEVER consume — the PR-8 HARD CONSTRAINT). Do NOT flip
# in gitops without those closed.
#
# When TRUE, the §23 dispatchability gate ADDS a requirement (never loosens
# the existing on-chain-Active + heartbeat + reachable gates): a miner is
# dispatchable only if it also has an `attested` (NEVER `pending`)
# host-attestor row, seen within `VALI_HOST_ATTESTOR_LIVENESS_WINDOW_S`, on
# a currently-desired ({current, previous}) release measurement. Fail-closed
# — a miner with no attestor data is NOT dispatchable under an ON gate.
VALI_HOST_ATTESTOR_GATE_ENFORCE = _env_bool("VALI_HOST_ATTESTOR_GATE_ENFORCE", False)

# When TRUE, a miner's §23 epoch-weight is MULTIPLIED by its host-attestor
# liveness ratio (fraction of the epoch its attestor was alive/beaconing on
# a desired measurement). CRITICAL (SLA must-have #5): a MULTIPLIER on the
# existing tenant-usage weight, NEVER additive — an idle-but-alive attestor
# earns ratio×0 = 0 (liveness alone earns nothing), and real usage under a
# dead/absent attestor earns usage×0 = 0. DEFAULT FALSE ⇒ epoch-weight is
# exactly as today (no multiplier).
VALI_REWARD_REQUIRE_ATTESTOR = _env_bool("VALI_REWARD_REQUIRE_ATTESTOR", False)

# The nominal host-attestor beacon cadence (seconds) — the SLA liveness
# meter gives full credit (ratio 1.0) to a row seen within one cadence of
# `now`, then decays linearly to 0 over the liveness window. Matches the
# ~60 s beacon loop the attestor agent runs.
VALI_HOST_ATTESTOR_BEACON_CADENCE_S = _env_int("VALI_HOST_ATTESTOR_BEACON_CADENCE_S", 60)

# ──────────────────────────────────────────────────────────────────
# PR-vali-miner-register: miner-fleet identity registry
# ──────────────────────────────────────────────────────────────────
# Operators register compute miners via POST /v1/admin/miner/register;
# registration also provisions the miner's `telemetry.TelemetrySource`,
# so the §9 broker accepts that miner's signed envelopes. The registry
# is the trust anchor for miner-signed telemetry (§13/§23).

# `ServiceClient.name` permitted to register / quarantine miners.
# Empty default fails closed — the `IsMinerAdmin` permission denies
# when unset (registering an identity establishes a trust anchor).
VALI_MINER_ADMIN_PRINCIPAL = os.environ.get("VALI_MINER_ADMIN_PRINCIPAL", "")

# ──────────────────────────────────────────────────────────────────
# Logging
# ──────────────────────────────────────────────────────────────────
# ── Synthetic monitor (apps.synthetic) ───────────────────────────────
# Periodic self-test of the LIVE control plane. Two tiers, both CronJob
# driven and default-safe (every knob has a code default so the command
# is runnable with zero config in tests). NON-DISRUPTIVE: the light tier
# is read-only; the full tier launches a THROWAWAY golden VM through the
# real public API and ALWAYS decommissions it (self-cleaning).

# In-cluster base URL of the vali public API the full-e2e drives (the
# real `POST /v1/vm/launch` + `POST /v1/vm/<id>/decommission`).
VALI_SYNTHETIC_API_BASE = os.environ.get(
    "VALI_SYNTHETIC_API_BASE", "http://vali.vali.svc.cluster.local:8000"
)
# Bearer token for the orchestration-root ServiceClient (see
# VALI_ORCHESTRATION_ROOT_PRINCIPAL). NEVER inline — mounted from a
# k8s Secret / Vault. Empty ⇒ the full tier fails loud at start.
VALI_SYNTHETIC_ROOT_TOKEN = os.environ.get("VALI_SYNTHETIC_ROOT_TOKEN", "")
# KBS admin base the light tier reachability-probes (a live server
# answering — even 404/405 — proves liveness; connection refused = down).
VALI_SYNTHETIC_KBS_URL = os.environ.get(
    "VALI_SYNTHETIC_KBS_URL",
    os.environ.get("VALI_KBS_ADMIN_URL", "http://kbs-server-admin.kbs.svc.cluster.local:8001"),
)
# Pushgateway the metrics are pushed to (Prometheus scrapes it). Empty ⇒
# metrics are logged only (tests + first-boot before the gateway lands).
VALI_SYNTHETIC_PUSHGATEWAY_URL = os.environ.get(
    "VALI_SYNTHETIC_PUSHGATEWAY_URL",
    "http://prometheus-pushgateway.observability.svc.cluster.local:9091",
)
VALI_SYNTHETIC_PUSH_JOB = os.environ.get("VALI_SYNTHETIC_PUSH_JOB", "synthetic-monitor")
# Per-distro golden bake_ids the full-e2e rotates through (JSON object,
# distro → Succeeded golden TenantBake bake_id). Operational values that
# change on re-bake, so config-driven. Rotation order is fixed.
# Base kernel cmdline the golden launch carries. `hippius.kbs_url` (the
# in-guest vsock authority) + the NoCloud seed are load-bearing; the
# launch service appends the measured dm-verity root for golden bakes.
VALI_SYNTHETIC_CMDLINE = os.environ.get(
    "VALI_SYNTHETIC_CMDLINE",
    "console=ttyS0,115200 hippius.kbs_url=vsock://2:19266 ds=nocloud;s=/run/cloud-init/seed/",
)
# Cloud-init userdata template for the throwaway VM. `{{NETBIRD_SETUP_KEY}}`
# / `{{NETBIRD_HOSTNAME}}` placeholders are filled by the launch service.
VALI_SYNTHETIC_USERDATA = os.environ.get("VALI_SYNTHETIC_USERDATA", "")
VALI_SYNTHETIC_FLAVOR = os.environ.get("VALI_SYNTHETIC_FLAVOR", "small")
# Owner/tenant tag — makes synthetic VMs unmistakable in every ledger.
VALI_SYNTHETIC_TENANT_ID = os.environ.get("VALI_SYNTHETIC_TENANT_ID", "synthetic-monitor")
# Bounds (seconds). The whole e2e is hard-capped so a stuck launch can
# never hang the CronJob past its activeDeadline.
VALI_SYNTHETIC_E2E_BUDGET_S = _env_int("VALI_SYNTHETIC_E2E_BUDGET_S", 1800)
VALI_SYNTHETIC_LAUNCH_TIMEOUT_S = _env_int("VALI_SYNTHETIC_LAUNCH_TIMEOUT_S", 420)
# Fresh per-wait cap for the `release`, `boot` (-> `running`) and NetBird
# waits; the whole run is still hard-capped by E2E_BUDGET_S. Measured
# 2026-09-25: an Ubuntu golden VM reaches `running` in ~150-250 s on the
# NVMe hosts and ~340 s on a Milan host with rotational disks — 300 s failed
# a healthy slow host. The budget holds a slow run: launch (≤420) + boot
# (≤600, release included) + decommission (≤720) = 1740 s < 1800 s; NetBird
# lands seconds after `running`.
VALI_SYNTHETIC_BOOT_TIMEOUT_S = _env_int("VALI_SYNTHETIC_BOOT_TIMEOUT_S", 600)
# The golden §24 decommission includes a ~10-min FORCED-RECLAIM before the
# crypto-erase (live full-run measured ~630s), so the timeout must clear
# that with margin — the old 240s tripped on every golden decommission.
VALI_SYNTHETIC_DECOMMISSION_TIMEOUT_S = _env_int("VALI_SYNTHETIC_DECOMMISSION_TIMEOUT_S", 720)
VALI_SYNTHETIC_POLL_INTERVAL_S = _env_float("VALI_SYNTHETIC_POLL_INTERVAL_S", 5.0)
# `POST /v1/vm/launch` synchronously provisions the golden overlay KEK
# (several Vault Transit/KV round-trips) + stages userdata under load, so
# the request can take tens of seconds — 15s was too tight. (Follow-up,
# out of scope: move golden-KEK provisioning off the sync request path.)
VALI_SYNTHETIC_HTTP_TIMEOUT_S = _env_float("VALI_SYNTHETIC_HTTP_TIMEOUT_S", 90.0)
# Light-tier stuck-job age threshold (a non-terminal LaunchJob /
# DecommissionJob older than this is alarm-worthy).
VALI_SYNTHETIC_STUCK_JOB_AGE_S = _env_int("VALI_SYNTHETIC_STUCK_JOB_AGE_S", 1800)
# Reaper age threshold (seconds): a synthetic-tenant VM / non-terminal
# LaunchJob older than this is a LEAK a killed run left behind, and the
# light-tier reaper force-tears it down. MUST exceed the max lifetime of a
# HEALTHY in-flight run so the reaper can never kill one: worst case ≈
# E2E_BUDGET_S (1800) + a fresh finally-teardown DECOMMISSION_TIMEOUT_S
# (720) ≈ 2520s ≈ the full CronJob activeDeadline. Set to ~2× that (5400s
# ≈ 90m) so a healthy run — even a slow forced-reclaim one — is never
# reaped, while a true leak is still caught within one light cycle.
VALI_SYNTHETIC_REAP_AGE_S = _env_int("VALI_SYNTHETIC_REAP_AGE_S", 5400)
# Light-tier acknowledgements: named, reasoned, time-boxed declarations
# that a specific check's CURRENT failure is known and accepted, so it does
# not pin `hippius_synthetic_light_success` at 0 and drown every OTHER
# light-tier failure. Newline-separated `check | YYYY-MM-DD | reason`;
# `#` comments allowed. Empty default = nothing acknowledged (fail loud).
#
# An acknowledged check is still RUN, still reported, still logged WARNING
# and still publishes `hippius_synthetic_light_check_success{check} == 0`.
# The bounds that keep this from becoming a permanent blind spot (mandatory
# ≤30-day expiry, one named check per entry, no wildcards, hard cap of 3,
# mandatory substantive reason, stale-ack alerting) are MODULE CONSTANTS in
# `apps.synthetic.ack` — deliberately not configurable from here, because a
# tunable cap or horizon is itself the blanket mute. Read that module's
# preamble before adding an entry.
VALI_SYNTHETIC_ACK = os.environ.get("VALI_SYNTHETIC_ACK", "")

# ── Scheduled golden re-bake (F6, apps.images.rebake) ────────────────
# `vali_scheduled_golden_rebake` re-bakes every golden image with a
# package refresh, one bake at a time, and NEVER blesses. Off by default:
# with the flag off the command queues nothing (`--report-only` is
# read-only and runs regardless).
VALI_GOLDEN_REBAKE_ENABLED = _env_bool("VALI_GOLDEN_REBAKE_ENABLED", False)
VALI_GOLDEN_REBAKE_IMAGES = _env_list(
    "VALI_GOLDEN_REBAKE_IMAGES", ["ubuntu", "debian", "cs10", "fedora"]
)
# Run the synthetic full e2e against each new, unblessed bake.
VALI_GOLDEN_REBAKE_E2E = _env_bool("VALI_GOLDEN_REBAKE_E2E", False)
VALI_GOLDEN_REBAKE_POLL_INTERVAL_S = _env_float("VALI_GOLDEN_REBAKE_POLL_INTERVAL_S", 30.0)
# Per-bake wait. A warm golden bake is ~3 min; a refreshed one is a cache
# MISS (download + chroot + upgrade), measured ~7-15 min cold.
VALI_GOLDEN_REBAKE_BAKE_TIMEOUT_S = _env_int("VALI_GOLDEN_REBAKE_BAKE_TIMEOUT_S", 3600)
# How long to wait for an unrelated in-flight bake before giving up.
VALI_GOLDEN_REBAKE_IDLE_TIMEOUT_S = _env_int("VALI_GOLDEN_REBAKE_IDLE_TIMEOUT_S", 3600)
VALI_GOLDEN_REBAKE_PUSH_JOB = os.environ.get("VALI_GOLDEN_REBAKE_PUSH_JOB", "golden-rebake")
# Pushgateway job of the guest upgrade report (`vali_guest_report`).
VALI_GUEST_REPORT_PUSH_JOB = os.environ.get("VALI_GUEST_REPORT_PUSH_JOB", "guest-upgrade")
# The guest report's KBS T4 signal (keepalives refused as the VM's own
# superseded guest). Turn on only once the KBS carries #1405 (it checks the
# guest binding before `superseded-launch`); needs the audit ingest.
VALI_GUEST_KBS_T4_ENABLED = _env_bool("VALI_GUEST_KBS_T4_ENABLED", False)
# Must equal the KBS's `nonce_ttl_secs` (chart `kbs.nonceTtlSecs`): the
# grace a request in flight at a hand-over gets before it counts as T4.
VALI_KBS_NONCE_TTL_S = _env_int("VALI_KBS_NONCE_TTL_S", 300)

# ── What the KBS process is SUPPOSED to be enforcing ─────────────────
# JSON object of posture key → expected value, diffed every ~15 min
# against what the RUNNING kbs-server reports (`apps.synthetic.checks.
# check_kbs_config_drift`, via `GET /v1/admin/volume-stamp` today and
# `GET /v1/admin/config` once the KBS is next restarted).
#
# WHY A DECLARATION AND NOT A ConfigMap READ. `Config::load` runs once
# at kbs-server start and the KBS Deployment carries no
# `checksum/config` annotation — correctly, because rolling that pod
# wipes its state/audit/evidence emptyDirs inside a Kata CVM. So an
# edited ConfigMap can sit next to a process that never read it while
# ArgoCD reports Synced + Healthy (it happened on 2026-08-13 to the
# suppressed-confirm anti-rollback gate). The uncovered gap is
# git → running process; the ConfigMap → git half IS what the gitops
# badge checks honestly. So this declares the git side, and CI pins it
# to the KBS chart's OWN rendered `config.toml`
# (`binaries/kbs-server/tests/chart_deploy_safety.rs`) so the two can
# never silently disagree — which is why this is not "a second source
# of truth" but a CI-verified mirror of the first.
#
# Keys are the field names of `AdminConfigPostureResponse`. Declare
# only what you want alarmed: an undeclared key is not compared, and a
# declared key the running KBS does not report is counted as
# not-yet-observable (never as drift). Empty ⇒ the check FAILS loudly,
# because "nothing declared" is indistinguishable from "nothing
# checked".
VALI_KBS_EXPECTED_POSTURE = os.environ.get("VALI_KBS_EXPECTED_POSTURE", "")

# §20 logging discipline: never log COSE blobs / Vault refs /
# user-data digests at INFO. Application code uses structured logs
# with the ticket_id only — see `apps.orders.views`.

LOGGING = {
    "version": 1,
    "disable_existing_loggers": False,
    "formatters": {
        "default": {
            "format": "%(asctime)s %(levelname)s %(name)s %(message)s",
        },
    },
    "handlers": {
        "console": {
            "class": "logging.StreamHandler",
            "formatter": "default",
        },
    },
    "loggers": {
        "vali": {"handlers": ["console"], "level": "INFO", "propagate": False},
        "apps": {"handlers": ["console"], "level": "INFO", "propagate": False},
        "django.security": {"handlers": ["console"], "level": "WARNING", "propagate": False},
    },
}

# ── the PUBLIC OpenAPI document's path filter (see vali/public_schema.py) ──
#
# Comma-separated path prefixes that `publicApiIngress` actually serves.
# The chart renders this straight from `publicApiIngress.allowedPaths`, so
# the public docs and the public route are driven by one value and cannot
# disagree.
#
# Default EMPTY, and empty means the public document is empty. That is the
# safe direction: an unset variable must never fall back to publishing the
# full internal schema, which is precisely what this filter exists to
# prevent.
VALI_PUBLIC_API_PATHS = os.environ.get("VALI_PUBLIC_API_PATHS", "")

# Hard ceiling on same-family VMs per host. Empty ⇒ no cap, which is the
# default: `SelectionWeights.spread` already fills empty hosts first, and a
# numeric ceiling is a capacity policy rather than a safety property.
#
# This replaced a HARD anti-affinity exclude that capped a tenant at one VM
# per miner — three miners meant three concurrent VMs, and 500 would have
# needed 500 miners.
#
# The CDN fleet's one-node-per-host rule does not read it (CDN plan N2).
VALI_MAX_FAMILY_PER_NODE = os.environ.get("VALI_MAX_FAMILY_PER_NODE", "")
