# `packer/tenant-uki/uki/Dockerfile` — Linux build environment for the
# tenant UKI assembly flow.
#
# Identical reproducibility regime to `packer/kbs-uki/uki/Dockerfile`
# (same Debian trixie base + same apt pins + same `ldd`-bundling
# discipline); the tenant flavour adds ONE extra cargo build in the
# agent-builder stage — `hippius-agent-tenant-telemetry` — and one
# extra COPY into the runtime stage so `build-rootfs.sh` can install
# it into the verity-protected tenant rootfs.
#
# Multi-stage:
#   - Stage 1 (`agent-builder`): `rust:1.93-slim-trixie` builds
#     `hippius-agent-initramfs` for x86_64-unknown-linux-gnu. PR-F2
#     review (codex) flagged that a host-built binary may be
#     Mach-O/arm64 on macOS — building inside the pinned Linux/amd64
#     image is the only way to keep the agent binary's bytes inside
#     the reproducibility boundary.
#   - Stage 2 (runtime): `debian:trixie-slim` with `ukify` +
#     `sbsigntool` + `cpio` + `binutils` + `curl` + `dpkg` for
#     fetch / initramfs / assemble / sign / measure. Trixie (Debian
#     13) ships `systemd-ukify` natively — bookworm does NOT (PR-F UKI
#     pin resolution switched the base to trixie for that reason).
#
# Reproducibility discipline:
#   - Each base pinned BY DIGEST (placeholder zero — operator pins
#     via `make pin-base` before first prod build).
#   - Apt packages have explicit `=PLACEHOLDER-PIN-VIA-MAKE-PIN-APT`
#     suffixes so `apt-get install` fails closed until the operator
#     records snapshot.debian.org versions via `make pin-apt`.
#   - `--platform=linux/amd64` so macOS Apple Silicon dev reproduces
#     CI Linux/amd64 byte-for-byte.
#   - Locale + timezone fixed (`LC_ALL=C`, `TZ=UTC`).
#
# Operator-facing build:
#   docker buildx build --platform linux/amd64 \
#     --build-arg DEBIAN_BASE_DIGEST=sha256:<pinned> \
#     --build-arg RUST_BUILDER_DIGEST=sha256:<pinned> \
#     -f packer/kbs-uki/uki/Dockerfile \
#     -t hippius-uki-builder:<image-version> .   # context = repo root

# syntax=docker/dockerfile:1.7

# ── Global ARGs (consumed by FROM directives below) ────────────────
#
# Both digests must be declared in the **global** ARG section — an
# ARG between two FROMs is stage-local and `FROM ${ARG}` cannot see
# it. PR-F2 sidestepped that by shipping placeholder zeros (never
# CI-built); the PR-F UKI pin-resolution run is the first real build,
# which surfaced the scoping bug and required this restructure.
ARG RUST_BUILDER_DIGEST=sha256:c0a38f5662afdb298898da1d70b909af4bda4e0acff2dc52aea6360a9b9c6956
ARG DEBIAN_BASE_DIGEST=sha256:b6e2a152f22a40ff69d92cb397223c906017e1391a73c952b588e51af8883bf8

# Freeze apt to a snapshot.debian.org timestamp. The measured UKI must
# be byte-reproducible, and a frozen index delivers that MORE robustly
# than per-package `=<version>` pins: the snapshot fixes the ENTIRE
# dependency closure (transitive deps included), so `apt-get install`
# resolves identical bytes on every rebuild — and can never rot as the
# live Debian repo advances (which is what silently broke the old
# hand-maintained pins). To move the baseline, bump this to another
# valid snapshot.debian.org archive stamp; nothing else changes.
ARG APT_SNAPSHOT=20260601T000000Z

# ── Stage 1: build the agent + measure binaries for Linux/amd64 ────
#
# NOTE: the tag is `rust:1.93-slim-trixie` — `<version>-slim-<suite>`
# is the order Docker Hub's `rust` images use. PR-F2 shipped the
# transposed `rust:1.93-bookworm-slim`, which does not exist; it was
# never caught because `make uki` is not CI-run yet (PR-F6).
FROM --platform=linux/amd64 rust:1.93-slim-trixie@${RUST_BUILDER_DIGEST} AS agent-builder

# Reproducibility env — same set the runtime stage applies, repeated
# here so the cargo build itself isn't sensitive to host locale.
#
# Note: PR-F2 originally pinned `RUSTFLAGS="-C target-feature=+crt-static"`
# so the agent-initramfs binary would be PID1-with-no-libc. PR-E1.4
# then added `libcryptsetup-rs` (LUKS unlock), whose `-sys` crate
# links `-lcryptsetup` — Debian ships no `libcryptsetup.a`, so the
# static-PIE link fails at `make uki` time. The first PR-F UKI build
# resolves this by dropping `+crt-static` and bundling the binary's
# `.so` deps into the initramfs (`build-initramfs.sh` runs `ldd` +
# copies). The trixie base is pinned by digest, so the resulting
# `.so` bytes are still deterministic across runs.
ENV LC_ALL=C
ENV LANG=C
ENV TZ=UTC
ENV CARGO_TERM_COLOR=never

# Build-side libraries pinned to the same trixie baseline as the
# runtime stage:
#   `pkg-config` + `libssl-dev` — `hippius-uki-measure --features snp`
#     (PR-F3) links the `sev` crate's `measurement` module, which needs
#     OpenSSL.
#   `libcryptsetup-dev` — `hippius-agent-initramfs` links
#     `libcryptsetup-rs-sys` (PR-E1.4 LUKS unlock) which `pkg-config`s
#     against `libcryptsetup.pc`. The `-sys` crate's `bindgen` step
#     additionally needs `libclang.so` to generate Rust FFI bindings
#     from the `cryptsetup.h` headers at build time — hence
#     `libclang-19-dev` here.
ARG APT_SNAPSHOT
RUN umask 022 \
    && printf 'deb [check-valid-until=no] http://snapshot.debian.org/archive/debian/%s trixie main\ndeb [check-valid-until=no] http://snapshot.debian.org/archive/debian-security/%s trixie-security main\n' "${APT_SNAPSHOT}" "${APT_SNAPSHOT}" > /etc/apt/sources.list \
    && rm -f /etc/apt/sources.list.d/debian.sources \
    && apt-get -o Acquire::Check-Valid-Until=false update && apt-get install --no-install-recommends -y \
        pkg-config \
        libssl-dev \
        libcryptsetup-dev \
        libclang-19-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src
# Copy the whole workspace context; Docker's `.dockerignore` excludes
# `target/`, `.git/`, the Django venv, etc. The cargo build is
# pinned by `rust-toolchain.toml` (1.93) so the toolchain doesn't
# drift even if the rust:1.93-slim-bookworm digest moves between
# rebuilds.
COPY . /src

# agent-initramfs: a dynamically-linked binary the initramfs ships
# alongside the `.so` deps `build-initramfs.sh` bundles via `ldd` (see
# the ENV comment above for the PR-F UKI / PR-E1.4 reconciliation).
#
# `--locked` is intentionally omitted (mirrors the `uki-measure` build
# below): the resolver scans every workspace Cargo.toml, including the
# pinned `thebrain` vendored dep `pallet-staking-reward-fn`, whose
# Cargo.toml has both inline `repository = "..."` and
# `repository.workspace = true`. The current strict cargo rejects that
# mid-parse — without `--locked` it surfaces as a warning + falls back
# to the committed lockfile, but `--locked` upgrades it to a fatal
# "cannot update the lock file" error. The lockfile is still committed
# and pinned; the workspace CI gates assert `Cargo.lock` byte-unchanged.
RUN cargo build --release --bin hippius-agent-initramfs

# agent-tenant-telemetry (PR-E2.x) — the §23 per-VM telemetry-signer
# service the tenant rootfs runs after `switch_root`. Built INSIDE this
# pinned Linux/amd64 stage for the same reproducibility reason as the
# agent-initramfs above (a host-built binary may be Mach-O/arm64). Same
# `--locked`-omitted posture too: the workspace resolver scans the
# `thebrain` vendored `pallet-staking-reward-fn` whose Cargo.toml the
# current strict cargo rejects under `--locked`.
RUN cargo build --release --bin hippius-agent-tenant-telemetry

# agent-tenant-init — the PID-1 binary the initramfs agent `execv`s
# after `switch_root` into the dm-verity rootfs. Replaces the prior
# `#!/bin/sh` placeholder, which fail-closed at `switch-root-failed:
# execv` once the rest of the chain was unblocked (the deterministic
# rootfs ships no `/bin/sh`). Same reproducibility envelope as the
# two binaries above; `build-rootfs.sh` reads it from
# `/opt/hippius/tenant-init` and installs it as `/sbin/init`.
RUN cargo build --release --bin hippius-agent-tenant-init

# uki-measure --features snp: built into a SEPARATE target dir to
# isolate its cargo fingerprints from the agent-initramfs build. It
# dynamically links system libssl (via `sev`'s openssl dep) and runs
# inside the glibc runtime stage — NOT the initramfs — so it's a
# standard dynamically-linked binary.
#
# `--locked` is intentionally omitted on THIS build only: enabling a
# cargo feature forces a full dependency re-resolve, and the pinned
# `thebrain` vendored dep `pallet-staking-reward-fn` has a Cargo.toml
# (`repository` set as a string AND `repository.workspace`) that the
# current strict cargo rejects mid-resolve — fatal under `--locked`.
# The lockfile is still committed and pinned; the `packer-f3` CI job
# asserts the snp build leaves `Cargo.lock` byte-unchanged.
RUN RUSTFLAGS= CARGO_TARGET_DIR=/measure-target \
    cargo build --release --features snp -p hippius-uki-measure

# ── Stage 2: minimal UKI assembly runtime ─────────────────────────

FROM --platform=linux/amd64 debian:trixie-slim@${DEBIAN_BASE_DIGEST}

ENV LC_ALL=C
ENV LANG=C
ENV DEBIAN_FRONTEND=noninteractive
ENV TZ=UTC

# Apt packages pinned to the exact versions of the trixie base image
# (sha256:b6e2a152…), recorded via `make pin-apt`. A package without
# a `=<version>` suffix would silently accept whatever drift the
# Debian repo serves; the explicit pin makes a drift loud.
# `squashfs-tools` (mksquashfs) + `cryptsetup-bin` (veritysetup) are
# PR-F3 additions for `build-rootfs.sh` — the dm-verity rootfs build.
# `libssl3t64` (the t64-transition name for the OpenSSL 3 runtime in
# Debian trixie; the source pkg is still `openssl`) is pinned
# explicitly (not left transitive): the COPY'd
# `/opt/hippius/uki-measure` is built `--features snp` and dynamically
# links the `sev` crate's OpenSSL, so its runtime libssl must be a
# pinned, deliberate dependency of this stage.
ARG APT_SNAPSHOT
RUN umask 022 \
    && printf 'deb [check-valid-until=no] http://snapshot.debian.org/archive/debian/%s trixie main\ndeb [check-valid-until=no] http://snapshot.debian.org/archive/debian-security/%s trixie-security main\n' "${APT_SNAPSHOT}" "${APT_SNAPSHOT}" > /etc/apt/sources.list \
    && rm -f /etc/apt/sources.list.d/debian.sources \
    && apt-get -o Acquire::Check-Valid-Until=false update && apt-get install --no-install-recommends -y \
        ca-certificates \
        curl \
        cpio \
        dpkg \
        binutils \
        sbsigntool \
        systemd-boot-efi \
        systemd-ukify \
        squashfs-tools \
        cryptsetup-bin \
        libssl3t64 \
        xz-utils \
    && rm -rf /var/lib/apt/lists/*

# Bring the build binaries across from stage 1 at fixed in-container
# paths so the Makefile / scripts don't need to know cargo's layout.
#   - agent-initramfs → staged into the initramfs by build-initramfs.sh
#   - uki-measure     → run by the `measure` step (built --features snp,
#                       so it emits the real snp_launch_digest_v1).
COPY --from=agent-builder /src/target/release/hippius-agent-initramfs \
                          /opt/hippius/agent-initramfs
# tenant-telemetry binary — `build-rootfs.sh` reads it from this path
# and installs it at `/sbin/hippius-agent-tenant-telemetry` in the
# verity-protected rootfs.
COPY --from=agent-builder /src/target/release/hippius-agent-tenant-telemetry \
                          /opt/hippius/tenant-telemetry
# tenant-init binary — `build-rootfs.sh` reads it from this path and
# installs it as `/sbin/init` in the verity-protected rootfs (the
# PID-1 entry point the initramfs agent `execv`s after switch_root).
COPY --from=agent-builder /src/target/release/hippius-agent-tenant-init \
                          /opt/hippius/tenant-init
COPY --from=agent-builder /measure-target/release/hippius-uki-measure \
                          /opt/hippius/uki-measure

WORKDIR /build
ENTRYPOINT ["/bin/bash"]
