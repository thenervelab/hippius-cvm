# hippius-vali — vali Django orchestration service image. PR-K7, §K (#54).
#
# vali is a NON-confidential runc workload (#1 locked topology) — a
# standard Django app behind gunicorn. The image is PRIVATE (GHCR +
# an imagePullSecret), unlike the confidential KBS image.
#
# Three stages:
#  1. rust-build   — builds `hippius-ticket-validator`, the Rust binary
#     the OrderTicket intake view shells out to for COSE_Sign1 parsing
#     (vali never verifies the L1 signature itself — see settings.py
#     `VALI_TICKET_VALIDATOR_BIN`).
#  2. python-build — installs the `vali` package (+ `apps` + Django
#     deps + gunicorn) into an isolated prefix.
#  3. runtime      — python:3.12-slim with the installed packages, the
#     validator binary, and `manage.py`; non-root, read-only-rootfs-safe.
#
# Build context is the REPO ROOT (the Rust stage needs the workspace):
#   docker buildx build --platform linux/amd64 \
#     -f vali/Dockerfile -t ghcr.io/thenervelab/hippius-vali:<tag> .

# ── stage 1: Rust validator binary ──────────────────────────────────
# Rust 1.93.0 — matches rust-toolchain.toml. Digest-pinned (§F).
FROM rust:1.93.0-bookworm@sha256:d0a4aa3ca2e1088ac0c81690914a0d810f2eee188197034edf366ed010a2b382 AS rust-build
WORKDIR /src
COPY . .
# `--locked` builds strictly from the committed Cargo.lock.
# Four Rust binaries are baked into the vali image:
#   * `hippius-ticket-validator` — the OrderTicket COSE_Sign1 parser
#     the intake view shells out to (`VALI_TICKET_VALIDATOR_BIN`).
#   * `hippius-kbs-admin-client`  — the §24 lifecycle pre-registration
#     subprocess `apps/orchestration/kbs_admin.py` invokes before each
#     launch dispatch (`VALI_KBS_ADMIN_CLIENT_BIN`). Without it the
#     KBS release path fails closed at `vm_states.get`.
#   * `hippius-order-ticket-mint` — minted OrderTicket COSE_Sign1
#     bytes the `vali_create_vm` command pipes into kbs-admin +
#     Edge. `VALI_ORDER_TICKET_MINT_BIN` points here.
#   * `hippius-kbs-allowlist-tool` — signs the freshly-minted §22
#     allowlist body with the dev seed when
#     `vali_create_vm --auto-pin-allowlist` runs.
#     `VALI_KBS_ALLOWLIST_TOOL_BIN` points here.
# `hippius-ticket-validator` is built `--features tls` so its
# `read-miner-status` (§23 chain read + the Edge registry feed) can
# reach the HTTPS RPC endpoint (the public testnet is Cloudflare-
# fronted; vali has the `world:443` egress). Built on its own line
# because the sibling binaries below have no `tls` feature.
RUN cargo build --locked --release --features tls \
        -p hippius-ticket-validator
RUN cargo build --locked --release \
        -p hippius-kbs-admin-client \
        -p hippius-order-ticket-mint \
        -p hippius-kbs-allowlist-tool
# `hippius-launch-digest` — vali's INDEPENDENT SEV-SNP launch-digest
# recompute (audit C2): vali recomputes the expected digest from its own
# LaunchOrder inputs and refuses any miner-asserted value that differs, so
# a miner booting a backdoored guest cannot auto-pin its measurement. Built
# `--features snp` (the real `sev::…::snp_calc_launch_digest`, byte-
# identical to the miner-agent) — which needs pkg-config + libssl-dev for
# the `sev` openssl feature (same as binaries/miner-agent/Dockerfile).
RUN apt-get update && apt-get install --no-install-recommends -y \
        pkg-config libssl-dev \
    && rm -rf /var/lib/apt/lists/*
RUN cargo build --locked --release --features snp \
        -p hippius-launch-digest

# ── stage 2: Python package + deps ──────────────────────────────────
FROM python:3.12-slim-bookworm@sha256:93ab4b7fa528b25124c97bcc755415e60eb671a86b4dbe0328df2fe2d1c1193d AS python-build
ENV PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1
WORKDIR /src
# `pip install` the vali package — pyproject.toml's setuptools
# `packages.find` picks up the `vali*` + `apps*` packages, and the
# deps (Django, DRF, psycopg[binary], dj-database-url) resolve from the
# wheel. `psycopg[binary]` ships a self-contained wheel — no libpq /
# build toolchain needed. gunicorn is the production WSGI server (not a
# project dependency — pinned here).
COPY vali/ ./vali/
# `whitenoise` is a project dependency (pyproject.toml) — pip pulls
# it transitively. Pinning gunicorn here keeps it out of the project
# deps (it's only the prod WSGI server, not an app dep).
RUN pip install --prefix=/install ./vali "gunicorn>=23,<24"

# ── stage 3: runtime ────────────────────────────────────────────────
FROM python:3.12-slim-bookworm@sha256:93ab4b7fa528b25124c97bcc755415e60eb671a86b4dbe0328df2fe2d1c1193d
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    DJANGO_SETTINGS_MODULE=vali.settings

# Non-root system user — uid/gid 65532, the fleet convention. The pod
# also pins this via securityContext.
RUN groupadd --system --gid 65532 vali \
    && useradd --system --uid 65532 --gid 65532 --home /app vali

# The installed Python packages (vali, apps, Django, DRF, gunicorn …).
COPY --from=python-build /install /usr/local
# `manage.py` — the project entrypoint script for migrations +
# management commands (not part of the installed package).
COPY vali/manage.py /app/manage.py
# The COSE_Sign1 ticket validator the intake view shells out to.
# `VALI_TICKET_VALIDATOR_BIN` in the chart points the app at this path.
COPY --from=rust-build /src/target/release/hippius-ticket-validator /usr/local/bin/hippius-ticket-validator
# The KBS admin client `vali_dispatch_launch` invokes before each
# launch dispatch. `VALI_KBS_ADMIN_CLIENT_BIN` in settings.py points
# here.
COPY --from=rust-build /src/target/release/hippius-kbs-admin-client /usr/local/bin/hippius-kbs-admin-client
# The OrderTicket minter the `vali_create_vm` mgmt command
# subprocesses (`services/ticket_mint.py`).
COPY --from=rust-build /src/target/release/hippius-order-ticket-mint /usr/local/bin/hippius-order-ticket-mint
# The §22 allowlist signer the auto-pin step subprocesses
# (`services/allowlist_pin.py`).
COPY --from=rust-build /src/target/release/hippius-kbs-allowlist-tool /usr/local/bin/hippius-kbs-allowlist-tool
# vali's independent SNP launch-digest recompute (audit C2). The
# `services/launch_digest.py` recompute shells out here
# (`VALI_LAUNCH_DIGEST_BIN`).
COPY --from=rust-build /src/target/release/hippius-launch-digest /usr/local/bin/hippius-launch-digest

# aws-cli — `vali_create_vm` subprocesses `aws s3 presign` (one URL
# per artifact, short TTL) and `aws s3 cp` (operator-side mirror of
# the freshly-signed allowlist to S3). The official upstream Debian
# package is `awscli`. Lock the apt lists to a deterministic mtime
# for layer reproducibility (same discipline as
# `collectstatic` below).
USER root
RUN apt-get update \
    && apt-get install -y --no-install-recommends awscli \
    && rm -rf /var/lib/apt/lists/* \
    && find /var/cache /var/log -exec touch -h -d "@${SOURCE_DATE_EPOCH:-0}" {} + 2>/dev/null || true

WORKDIR /app

# Bake the Django admin's static assets into the image (#152). The
# prod pod runs `readOnlyRootFilesystem: true`, so `collectstatic`
# CANNOT run at entrypoint — it must produce `/app/staticfiles/`
# at image build time, where WhiteNoise (mounted in settings.py
# right after SecurityMiddleware) then serves them from gunicorn.
#
# `DJANGO_STATIC_ROOT=/app/staticfiles` pins the output path —
# without it `STATIC_ROOT` defaults to `BASE_DIR / "staticfiles"`,
# which inside the container resolves to a site-packages-buried
# path (the vali package is `pip install`ed) and the chown below
# would fail.
#
# The other build-time env vars are NOT secrets: `DJANGO_DEBUG=1`
# skips the production-only fail-loud check on `SECRET_KEY`, and the
# placeholder key itself is never used to sign anything (no requests
# are served during `collectstatic`). They are scoped to the RUN
# step so the runtime layer does not inherit them.
ENV DJANGO_STATIC_ROOT=/app/staticfiles
# Reproducibility: Django's default `FileSystemStorage` stamps each
# copied file with the *current* wall-clock as its mtime, which would
# perturb the image layer digest across rebuilds even when the file
# bytes are identical. `touch -h -d @${SOURCE_DATE_EPOCH:-0}` rewrites
# every file + directory mtime to the deterministic epoch so the cosign
# keyless signature (PR #58) verifies the same digest across rebuilds.
RUN DJANGO_DEBUG=1 \
    DJANGO_SECRET_KEY=build-time-collectstatic-placeholder-not-a-secret \
    python manage.py collectstatic --no-input --clear \
    && find /app/staticfiles -exec touch -h -d "@${SOURCE_DATE_EPOCH:-0}" {} + \
    && chown -R 65532:65532 /app/staticfiles

USER 65532:65532

# /healthz + /v1/* — the vali HTTP API (gunicorn).
EXPOSE 8000

# Default: the gunicorn WSGI server. The migration Job + any management
# command override `command:` with `python manage.py …`.
ENTRYPOINT ["gunicorn", "vali.wsgi:application"]
CMD ["--bind", "0.0.0.0:8000", "--workers", "4", "--timeout", "60", "--access-logfile", "-"]
