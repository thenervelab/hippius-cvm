# `packer/tenant-uki-debian/uki/Dockerfile` — Linux build environment
# for the Debian 13 tenant UKI assembly flow (EPIC #186 Phase 1).
#
# Sibling factory to `packer/tenant-uki/uki/Dockerfile`. Same
# reproducibility regime — pinned base + apt + multi-stage layout —
# with one critical delta: the runtime stage adds `debootstrap` +
# `mmdebstrap` (chroot tooling) + `xz-utils` (already present) +
# `gnupg` (debootstrap verifies the bootstrap mirror's `Release.gpg`)
# so `build-rootfs.sh` can stand up a FULL Debian 13 userspace inside
# a chroot before squashing it into the dm-verity image.
#
# Multi-stage layout matches the placeholder tenant factory:
#   - Stage 1 (`agent-builder`): `rust:1.93-slim-trixie` builds
#     `hippius-agent-initramfs` + `hippius-agent-tenant-telemetry`
#     for x86_64-unknown-linux-gnu. PR-F2 review (codex) flagged that
#     a host-built binary may be Mach-O/arm64 on macOS — building
#     inside the pinned Linux/amd64 image is the only way to keep the
#     binary bytes inside the reproducibility boundary.
#   - Stage 2 (runtime): `debian:trixie-slim` with `ukify` +
#     `sbsigntool` + `cpio` + `binutils` + `curl` + `dpkg` +
#     `debootstrap` + `mmdebstrap` for fetch / initramfs / rootfs /
#     assemble / sign / measure.
#
# Reproducibility discipline:
#   - Each base pinned BY DIGEST (matches the placeholder pins).
#   - Apt packages have explicit `=<version>` suffixes — a missing
#     pin would silently accept whatever drift the Debian repo
#     serves; the explicit pin makes drift loud.
#   - `--platform=linux/amd64` so macOS Apple Silicon dev reproduces
#     CI Linux/amd64 byte-for-byte.
#   - Locale + timezone fixed (`LC_ALL=C`, `TZ=UTC`).
#
# Operator-facing build:
#   docker buildx build --platform linux/amd64 \
#     --build-arg DEBIAN_BASE_DIGEST=sha256:<pinned> \
#     --build-arg RUST_BUILDER_DIGEST=sha256:<pinned> \
#     -f packer/tenant-uki-debian/uki/Dockerfile \
#     -t hippius-tenant-uki-debian-builder:<image-version> .   # context = repo root

# syntax=docker/dockerfile:1.7

# ── Global ARGs (consumed by FROM directives below) ────────────────
#
# Both digests must be declared in the **global** ARG section — an
# ARG between two FROMs is stage-local and `FROM ${ARG}` cannot see
# it. Values match `packer/tenant-uki/uki/Dockerfile` so a future
# digest bump lands in lockstep across both factories.
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
# Identical to the placeholder tenant factory's Stage 1: same Rust
# toolchain image, same workspace COPY, same `--locked`-omitted
# posture for the cargo builds (the workspace resolver scans the
# `thebrain` vendored `pallet-staking-reward-fn` whose Cargo.toml the
# current strict cargo rejects mid-resolve under `--locked`; the
# lockfile IS committed + pinned + CI-gated, so the lookups are still
# deterministic).
FROM --platform=linux/amd64 rust:1.93-slim-trixie@${RUST_BUILDER_DIGEST} AS agent-builder

ENV LC_ALL=C
ENV LANG=C
ENV TZ=UTC
ENV CARGO_TERM_COLOR=never

# Build-side libraries pinned to the same trixie baseline as the
# runtime stage. See `packer/tenant-uki/uki/Dockerfile` for the
# per-package rationale (libcryptsetup-dev for the agent-initramfs
# LUKS unlock; libclang-19-dev for libcryptsetup-rs's bindgen step;
# libssl-dev for `hippius-uki-measure --features snp`'s `sev` crate).
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
COPY . /src

# agent-initramfs (PID 1) — same dynamically-linked binary the
# placeholder factory ships; `build-initramfs.sh` bundles its `.so`
# deps + the AF_VSOCK / virtio_net kernel modules.
RUN cargo build --release --bin hippius-agent-initramfs

# agent-tenant-telemetry (§23) — runs inside the booted Debian rootfs
# as a systemd unit (`hippius-tenant-telemetry.service`); written to
# `/usr/local/sbin/hippius-agent-tenant-telemetry` by `build-rootfs.sh`.
RUN cargo build --release --bin hippius-agent-tenant-telemetry

# uki-measure --features snp — same isolated target dir as the
# placeholder factory so the cargo fingerprints don't collide with
# the agent builds.
RUN RUSTFLAGS= CARGO_TARGET_DIR=/measure-target \
    cargo build --release --features snp -p hippius-uki-measure

# ── Stage 2: UKI assembly + Debian chroot runtime ─────────────────

FROM --platform=linux/amd64 debian:trixie-slim@${DEBIAN_BASE_DIGEST}

ENV LC_ALL=C
ENV LANG=C
ENV DEBIAN_FRONTEND=noninteractive
ENV TZ=UTC

# Apt packages pinned to the exact versions of the trixie base image
# (sha256:b6e2a152…). The set is the placeholder factory's set PLUS
# `debootstrap` + `mmdebstrap` + `gnupg` + `debian-archive-keyring`
# for the Debian 13 chroot stand-up.
#
# `debootstrap` runs the first-stage bootstrap (it shells out to
# `wget` and `ar`, but those are already inherent to the Debian
# environment); `mmdebstrap` is the more modern, faster, AND more
# reproducible alternative we prefer for the actual chroot creation
# (mmdebstrap pins the local time and explicitly accepts
# `SOURCE_DATE_EPOCH`).
# `debian-archive-keyring` provides /usr/share/keyrings/
# debian-archive-keyring.gpg — debootstrap verifies the snapshot
# mirror's `Release.gpg` against it; without it the bootstrap aborts
# with "Couldn't find keyring".
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
        debootstrap \
        mmdebstrap \
        gnupg \
        debian-archive-keyring \
    && rm -rf /var/lib/apt/lists/*

# Bring the build binaries across from stage 1 at fixed in-container
# paths so the Makefile / scripts don't need to know cargo's layout.
COPY --from=agent-builder /src/target/release/hippius-agent-initramfs \
                          /opt/hippius/agent-initramfs
COPY --from=agent-builder /src/target/release/hippius-agent-tenant-telemetry \
                          /opt/hippius/tenant-telemetry
COPY --from=agent-builder /measure-target/release/hippius-uki-measure \
                          /opt/hippius/uki-measure

WORKDIR /build
ENTRYPOINT ["/bin/bash"]
