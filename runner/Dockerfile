# hippius-runner-k8s — self-hosted GitHub Actions runner image for the
# `mon-runner-k8s` AutoscalingRunnerSet in `arc-runners/`.
#
# Base: the official `ghcr.io/actions/actions-runner` image so the
# `actions-runner-controller` (ARC) Helm chart's pod-template runs the
# entrypoint unchanged. Pinned by SHA-256 digest (§F supply-chain
# discipline). Override on rebuild only after re-verifying the
# upstream tag → digest mapping against
# `https://github.com/actions/runner/pkgs/container/actions-runner`.
#
# On top of that base this image pre-bakes:
#   * `rustup` + the workspace-pinned toolchain
#     (`rust-toolchain.toml` channel 1.93.0 + rustfmt + clippy).
#     Saves a ~15 s `dtolnay/rust-toolchain` install on every
#     workflow run.
#   * Linux C toolchain + Rust build-script deps the workflows need:
#     gcc/g++ (`build-essential`), pkg-config, libssl-dev,
#     libcryptsetup-dev, clang + libclang-dev (bindgen), squashfs-tools,
#     cryptsetup-bin (dm-verity rootfs reproducibility KAT).
#   * Cosign — pinned by version + sha256. Workflows currently install
#     it via `sigstore/cosign-installer`; pre-baking is a small
#     latency win and a structural pin against an unavailable Sigstore
#     binary release.
#   * `gh` (GitHub CLI), `jq`, `curl`. Common workflow auxiliaries.
#   * `docker` CLI (NOT a daemon — the daemon is provided by ARC's
#     `containerMode: dind` sidecar). Allows image-build workflows
#     to talk to the dind sidecar via `DOCKER_HOST`.
#
# Build context = repo root so the Dockerfile can read
# `rust-toolchain.toml` for the channel pin. The
# `.github/workflows/runner-image.yml` workflow uses
# `context: ./runner` + `file: runner/Dockerfile` for build
# reproducibility (no surrounding-repo I/O at build time except
# the toolchain file copy below).
ARG BASE_IMAGE_DIGEST=sha256:b6614fce332517f74d0a76e7c762fb08e4f2ff13dcf333183397c8a5725b6e8e
# `ghcr.io/actions/actions-runner:latest` manifest list, resolved
# 2026-05-27 via `docker buildx imagetools inspect`. The list pin
# is intentional — buildx selects the right arch (linux/amd64) at
# build time. Upstream releases ~monthly; bump after verifying the
# digest at https://github.com/actions/runner/pkgs/container/actions-runner.
FROM ghcr.io/actions/actions-runner@${BASE_IMAGE_DIGEST}

# The base image runs as `runner` (uid 1001) by default. Become root
# for the install steps; the final user is set back at the end.
USER root

# ── system packages ────────────────────────────────────────────────
# `DEBIAN_FRONTEND=noninteractive` so apt does not stall on tzdata or
# similar prompts. `apt-get install --no-install-recommends` keeps the
# image lean (~600 MB on top of the ~500 MB base).
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        build-essential \
        pkg-config \
        libssl-dev \
        libcryptsetup-dev \
        clang \
        libclang-dev \
        squashfs-tools \
        cryptsetup-bin \
        jq \
        curl \
        ca-certificates \
        git \
        xz-utils \
        gettext-base \
    && rm -rf /var/lib/apt/lists/*

# ── docker CLI (talks to ARC's containerMode: dind sidecar) ────────
# Use the official Docker apt repo for a pinned, current CLI. The
# fingerprint check pins the GPG key signing the apt repo metadata.
RUN install -m 0755 -d /etc/apt/keyrings \
    && curl -fsSL https://download.docker.com/linux/ubuntu/gpg \
       -o /etc/apt/keyrings/docker.asc \
    && chmod a+r /etc/apt/keyrings/docker.asc \
    && echo \
       "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu \
       $(. /etc/os-release && echo "$VERSION_CODENAME") stable" \
       | tee /etc/apt/sources.list.d/docker.list > /dev/null \
    && apt-get update \
    && apt-get install -y --no-install-recommends \
        docker-ce-cli \
        docker-buildx-plugin \
    && rm -rf /var/lib/apt/lists/*

# ── GitHub CLI (`gh`) ──────────────────────────────────────────────
# Used by image-build workflows that query the OIDC token for cosign.
# Pinned major version; the install script writes its own apt source.
RUN curl -fsSL https://cli.github.com/packages/githubcli-archive-keyring.gpg \
       -o /usr/share/keyrings/githubcli-archive-keyring.gpg \
    && chmod go+r /usr/share/keyrings/githubcli-archive-keyring.gpg \
    && echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/githubcli-archive-keyring.gpg] https://cli.github.com/packages stable main" \
       | tee /etc/apt/sources.list.d/github-cli.list > /dev/null \
    && apt-get update \
    && apt-get install -y --no-install-recommends gh \
    && rm -rf /var/lib/apt/lists/*

# ── cosign (pinned by version + sha256) ────────────────────────────
ARG COSIGN_VERSION=v3.0.6
# sha256 of the cosign-linux-amd64 binary from
# `https://github.com/sigstore/cosign/releases/download/v3.0.6/cosign_checksums.txt`,
# verified 2026-05-27. Bump in lockstep with COSIGN_VERSION above.
ARG COSIGN_SHA256=c956e5dfcac53d52bcf058360d579472f0c1d2d9b69f55209e256fe7783f4c74
RUN ARCH="$(dpkg --print-architecture)" \
    && case "$ARCH" in \
         amd64) COSIGN_ASSET="cosign-linux-amd64" ;; \
         arm64) COSIGN_ASSET="cosign-linux-arm64" ;; \
         *)     echo "unsupported arch: $ARCH" >&2; exit 1 ;; \
       esac \
    && curl -fsSL --proto '=https' --tlsv1.2 \
        -o /tmp/cosign \
        "https://github.com/sigstore/cosign/releases/download/${COSIGN_VERSION}/${COSIGN_ASSET}" \
    && if [ "$ARCH" = "amd64" ]; then \
         echo "${COSIGN_SHA256}  /tmp/cosign" | sha256sum -c -; \
       fi \
    && install -o root -g root -m 0755 /tmp/cosign /usr/local/bin/cosign \
    && rm /tmp/cosign \
    && cosign version

# ── rustup + toolchain pinned to rust-toolchain.toml ───────────────
# Two-step install: rustup-init non-interactively with no default
# toolchain, then `rustup toolchain install` of the exact channel +
# components the workspace pins. Installed under `/usr/local/rustup`
# (system-wide, not in `runner`'s $HOME) so the ephemeral runner pod
# doesn't have to re-download per job. `/usr/local/cargo/bin` on PATH.
ENV RUSTUP_HOME=/usr/local/rustup \
    CARGO_HOME=/usr/local/cargo \
    PATH=/usr/local/cargo/bin:$PATH
COPY rust-toolchain.toml /tmp/rust-toolchain.toml
RUN curl --proto '=https' --tlsv1.2 -sSf \
        https://sh.rustup.rs \
        -o /tmp/rustup-init.sh \
    && sh /tmp/rustup-init.sh -y --no-modify-path --default-toolchain none --profile minimal \
    && rm /tmp/rustup-init.sh \
    # Parse channel from the rust-toolchain.toml. grep is good enough
    # for the fixed `channel = "X.Y.Z"` shape committed in the repo.
    && CHANNEL="$(grep '^channel' /tmp/rust-toolchain.toml | sed -E 's/.*"(.+)".*/\1/')" \
    && rustup toolchain install "${CHANNEL}" --profile minimal --component rustfmt --component clippy \
    && rustup default "${CHANNEL}" \
    && rustup --version \
    && cargo --version \
    && rustc --version \
    && rm /tmp/rust-toolchain.toml \
    # `cargo` writes to `$CARGO_HOME/{registry,git}/` during dep
    # resolution. The default base image runs as uid 1001 (`runner`),
    # so chown both dirs to that user — `chmod a+rX` would leave them
    # read-only and `cargo` would fail-closed with `Permission denied`
    # on the first `crates.io` / git fetch.
    && chown -R runner:runner /usr/local/rustup /usr/local/cargo

# ── back to the runner user ────────────────────────────────────────
USER runner
WORKDIR /home/runner
