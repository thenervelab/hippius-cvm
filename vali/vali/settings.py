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
    "apps.images",
    "apps.lifecycle",
    "apps.miners",
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
VALI_SCHEDULER_HOST_RESERVE_MEMORY_MB = _env_int("VALI_SCHEDULER_HOST_RESERVE_MEMORY_MB", 4096)
VALI_SCHEDULER_HOST_RESERVE_CPUS = _env_int("VALI_SCHEDULER_HOST_RESERVE_CPUS", 2)
VALI_SCHEDULER_SLOT_REF_MEMORY_MB = _env_int("VALI_SCHEDULER_SLOT_REF_MEMORY_MB", 8192)
VALI_SCHEDULER_SLOT_REF_CPUS = _env_int("VALI_SCHEDULER_SLOT_REF_CPUS", 4)

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

# Source of the on-chain epoch reward weight (`compute_epoch_weights`):
#   `snapshot` — the instantaneous Σ resource_units of BOUND placements
#                (v1; pays a bound-but-down VM in full);
#   `usage`    — uptime-integrated Σ unit_seconds from the attested
#                `UsageAccrual` ledger (pays only for proven-up time).
# Default `snapshot` so the deployed reward flow is unchanged until
# served receipts are confirmed flowing live, then flip to `usage`.
VALI_EPOCH_WEIGHT_SOURCE = os.environ.get("VALI_EPOCH_WEIGHT_SOURCE", "snapshot")

# VM owners (`Placement.owner`, i.e. the launch spec's `user_id`) whose
# hosting earns NO reward weight and NO bill — OUR OWN infrastructure, not
# tenants. With `VALI_EPOCH_WEIGHT_SOURCE=usage` the ledger IS the reward,
# and measured live on 2026-08-11 our own VMs held 30.6 % of the whole pot
# (one destroyed synthetic-monitor probe carried 30 % by itself). Paying
# ourselves out of the miner pot dilutes every honest miner.
#
# Comma-separated. EMPTY IS A STRICT NO-OP — the default cannot zero a real
# fleet. `VALI_SYNTHETIC_TENANT_ID` is always unioned in by
# `scoring._excluded_owners`, so editing this list to add a one-off
# rehearsal identity can never drop the probe fleet back into the pot.
# Live, this needs the operator identities that are NOT the synthetic
# tenant — e.g. `kbsrehearse`.
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
#    anywhere (proved live 2026-08-13: p1final-1/2/3). Nothing reaped
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

# S3 bucket holding §25 LUKS2+dm-integrity migration snapshots + the
# TTL of the presigned PUT/GET URLs. The signed URLs are short-lived
# capabilities — generated on demand, NEVER persisted in a job row.
VALI_ORCHESTRATION_SNAPSHOT_BUCKET = os.environ.get(
    "VALI_ORCHESTRATION_SNAPSHOT_BUCKET", "hippius-compute-migrations"
)
VALI_ORCHESTRATION_PRESIGN_TTL_SECS = _env_int("VALI_ORCHESTRATION_PRESIGN_TTL_SECS", 3600)

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

# Grace window a §25-migrated VM's NetBird peer gets to come back
# CONNECTED before `orchestration.service.verify_netbird_enrolments`
# declares it `lost` (P9/#17). Only bounds the AMBIGUOUS case (the peer
# record still exists but the guest has not dialled in yet) — a DELETED
# peer record is terminal the moment it is observed, since the guest's
# one-off launch setup key cannot re-register it.
VALI_NETBIRD_VERIFY_GRACE_S = float(
    os.environ.get("VALI_NETBIRD_VERIFY_GRACE_S", "900")
)

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
VALI_SYNTHETIC_BOOT_TIMEOUT_S = _env_int("VALI_SYNTHETIC_BOOT_TIMEOUT_S", 300)
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
VALI_MAX_FAMILY_PER_NODE = os.environ.get("VALI_MAX_FAMILY_PER_NODE", "")
