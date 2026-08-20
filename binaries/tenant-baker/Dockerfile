# syntax=docker/dockerfile:1.7
#
# hippius-tenant-baker — the per-tenant qcow2 baker pod image
# (#334 Phase 2). Runs as a one-shot k8s Job spawned by the
# `apps.tenant_bake` POST endpoint in vali.
#
# What it does at runtime
# -----------------------
# entrypoint.sh, given the BAKE_* env vars the Job manifest passes
# in, drives the lifecycle:
#   1. POST /v1/tenant-bakes/<bake_id>/finalize {"to_state":"running",...}
#      so the row reflects "claimed".
#   2. Read the LUKS KEK out of Vault at $BAKE_KEK_VAULT_PATH.
#   3. Run /usr/local/bin/tenant-image-bake.sh with the BAKE_*
#      params (the same script the legacy workstation flow ran —
#      copied into the image at build time so the bake logic stays
#      in one place + readable).
#   4. SHA-256 the three outputs (qcow2 + vmlinuz + initrd) +
#      extract `measurement_hex` from the bake's measurement.json.
#   5. `aws s3 cp` the outputs to $BAKE_S3_OUTPUT_BUCKET /
#      $BAKE_S3_OUTPUT_PREFIX with sha-named keys.
#   6. POST /finalize {"to_state":"succeeded","qcow2_sha256":...,
#      "kernel_sha256":...,"initrd_sha256":...,"measurement_hex":...}.
#   On any non-zero exit: POST /finalize {"to_state":"failed",
#   "failure_reason":<stderr tail>}.
#
# Privileged-pod note
# -------------------
# The Job spec sets `privileged: true` because losetup + cryptsetup
# + mount + chroot need root in the kernel namespace. The
# NetworkPolicy that the helm chart ships restricts egress to
# Vault + S3 + vali's own Service (no lateral cluster reach), so
# the privilege is bounded to "operations the bake itself needs".
#
# What the image must carry
# -------------------------
# `tenant-image-bake.sh` requires four things on disk at bake time:
#   - the keyscript + initramfs hook + net-teardown scripts under
#     `${SCRIPT_DIR}/initramfs/` (where SCRIPT_DIR is the dir holding
#     `tenant-image-bake.sh`),
#   - `hippius-guest-release` — the §21 release exchange CLI the
#     keyscript invokes inside the tenant's distro initramfs to
#     fetch the LUKS KEK + cloud-init userdata from KBS,
#   - `hippius-vsock-ticket` — the vsock receiver that pulls the
#     L1-signed COSE OrderTicket from the host miner-agent push
#     channel inside the tenant initramfs,
#   - the bake-time chroot tooling (cryptsetup / debootstrap / etc.).
#
# A previous revision of this Dockerfile only copied the bake script
# itself — production bakes immediately fail at `--hippius-release-bin
# not executable` because /usr/sbin/hippius-guest-release didn't
# exist. This image now cross-compiles both binaries from the
# workspace in a Stage 1 builder using the same `rust:1.93-slim-trixie@sha256:c0a38f5662afdb298898da1d70b909af4bda4e0acff2dc52aea6360a9b9c6956`
# envelope `packer/tenant-uki/uki/Dockerfile` uses, and stages every
# input the bake script needs.

# ───────────────────────────────────────────────────────────────────
# Stage 1 — agent-builder: cross-build the two release-flow binaries
#
# Same Rust / Debian envelope as `packer/tenant-uki/uki/Dockerfile`
# (Rust 1.93-slim-trixie). Both binaries are built as FULLY STATIC
# `x86_64-unknown-linux-musl` binaries — no dynamic deps, no glibc
# coupling — so the SAME bytes stage into any distro's initramfs: the
# bake `install`s them into the tenant rootfs's `/usr/sbin/`, then the
# Debian-family `initramfs-tools` hook `copy_exec`s them (zero ldd
# deps) OR the RHEL-family dracut module `inst`s them.
#
# `--locked` is intentionally omitted (mirrors the tenant-uki build):
# the workspace resolver scans `pallet-staking-reward-fn` whose
# Cargo.toml the current strict cargo rejects under `--locked`. The
# lockfile is still committed; CI gates assert it's byte-unchanged.
# ───────────────────────────────────────────────────────────────────
FROM --platform=linux/amd64 rust:1.93-slim-trixie@sha256:c0a38f5662afdb298898da1d70b909af4bda4e0acff2dc52aea6360a9b9c6956 AS agent-builder

ENV DEBIAN_FRONTEND=noninteractive
ENV CARGO_TERM_COLOR=never

# `musl-tools` provides `musl-gcc` (ring's C shim links against it for
# the musl target). No libcryptsetup-dev / libssl-dev needed for the
# slim CLIs: they build with `default-features = false` (the
# `cryptsetup` feature is OFF → no `-lcryptsetup`) and use rustls+ring
# (no OpenSSL). pkg-config kept for ring's build script.
RUN apt-get update && apt-get install --no-install-recommends -y \
        pkg-config \
        musl-tools \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src
# `.dockerignore` excludes `target/`, `.git/`, vali venv, etc., so the
# context transfer is the workspace source tree only.
COPY . /src

# Add the musl std AFTER the COPY so `rust-toolchain.toml` (channel
# 1.93.0) is the active toolchain — otherwise the target lands on the
# image's default toolchain and cargo (driven by the toml) can't find
# the musl `core`/`std` (CI-observed E0463). WORKDIR is /src so rustup
# reads the toml.
RUN rustup target add x86_64-unknown-linux-musl

# `hippius-guest-release` + `hippius-vsock-ticket` — the §21 release CLI
# the unlock path invokes inside the tenant initramfs, and the vsock
# receiver for the L1-signed OrderTicket. Built as FULLY STATIC
# x86_64-unknown-linux-musl binaries (no dynamic deps, no glibc
# coupling) so the SAME bytes run in ANY distro's initramfs — Ubuntu /
# Debian (initramfs-tools `copy_exec`) AND CentOS Stream 10 / Fedora
# (dracut `inst`) — regardless of the guest's glibc. `--locked` omitted
# per the rationale above (the committed lockfile is the anchor).
# `-p` (package-scoped), NOT `--bin`: at the workspace root `--bin X`
# resolves features across the whole workspace and unifies the
# `cryptsetup` feature ON (some member enables it), which drags in
# libcryptsetup-rs and breaks the static musl link. `-p` scopes
# feature resolution to just these two packages' dep closures (neither
# enables `cryptsetup`), so libcryptsetup is never built.
RUN cargo build --release --target x86_64-unknown-linux-musl \
        -p hippius-guest-release -p hippius-vsock-ticket

# ───────────────────────────────────────────────────────────────────
# Stage 1b — eol-builder: build the FULL `hippius-agent-initramfs`
#
# This is the §24/§25 guest shutdown-sign binary the bake stages into
# the tenant ROOTFS (NOT the initramfs) and runs from
# `hippius-eol-sign.service` (`eol --sign-only`) on a clean shutdown.
# Unlike the two slim CLIs above, the full agent binary's `[[bin]]`
# carries `required-features = ["cryptsetup"]`, so it links
# `libcryptsetup-rs` and CANNOT be a static musl artifact — it is a
# DYNAMIC glibc binary that runs in the tenant distro's userspace,
# where `libcryptsetup` is already installed by the bake's package
# step. This mirrors the canonical packer/tenant-uki build:
#   `cargo build --release --bin hippius-agent-initramfs`
# (the bake-script `--hippius-eol-bin` help documents exactly this).
#
# glibc-FLOOR rationale: the binary must run on the OLDEST glibc any
# supported tenant base ships — Debian 12 (glibc 2.36). glibc is
# forward-compatible (a 2.36-linked binary runs on 2.39/2.41) but NOT
# backward — a trixie-built (2.41) binary would die with
# `GLIBC_2.41 not found` on CS10 (2.39) / Ubuntu 24.04 (2.39) /
# Debian 12 (2.36). So this stage pins `rust:1.93-slim-bookworm@sha256:5b9332190bb3b9ece73b810cd1f1e9f06343b294ce184bcb067f0747d7d333ea`
# (glibc 2.36), the lowest common floor across every bake target.
#
# Build deps mirror the packer agent-builder: `libcryptsetup-dev`
# (the `-sys` crate `pkg-config`s `libcryptsetup.pc`), `libclang`
# (its bindgen step generates the FFI from `cryptsetup.h`),
# `pkg-config`, plus `libssl-dev` for the `sev` crate's OpenSSL link.
FROM --platform=linux/amd64 rust:1.93-slim-bookworm@sha256:5b9332190bb3b9ece73b810cd1f1e9f06343b294ce184bcb067f0747d7d333ea AS eol-builder

ENV DEBIAN_FRONTEND=noninteractive
ENV CARGO_TERM_COLOR=never

RUN apt-get update && apt-get install --no-install-recommends -y \
        pkg-config \
        libssl-dev \
        libcryptsetup-dev \
        libclang-dev \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src
COPY . /src

# `--locked` omitted for the same workspace-resolver reason documented
# in Stage 1 (the committed lockfile is the anchor; CI gates it). The
# default `x86_64-unknown-linux-gnu` target (glibc dynamic) is what the
# tenant rootfs runs — no `--target` needed since the builder's own
# host triple IS gnu.
# Also build the §23 served-receipt telemetry agent
# (`hippius-agent-tenant-telemetry`) in the SAME glibc stage — it runs in
# the tenant rootfs userspace exactly like the shutdown-sign agent, so it
# shares the Debian-12 (glibc 2.36) floor rationale above. It does NOT use
# `libcryptsetup` (HKDF + ed25519 + vsock only); building it in one cargo
# invocation shares the dep compilation with the initramfs agent.
# Same for the §23 SNP live-attestation keepalive agent
# (`hippius-agent-keepalive`): a long-running rootfs daemon on the same
# glibc floor. It depends on the `hippius-agent-initramfs` LIB (for the
# `/dev/sev-guest` report provider and the vsock KBS transport), which is
# already being compiled here, so it is nearly free to add.
RUN cargo build --release \
        --bin hippius-agent-initramfs \
        --bin hippius-agent-tenant-telemetry \
        --bin hippius-agent-keepalive

# ───────────────────────────────────────────────────────────────────
# Stage 2 — runtime: the actual k8s Job image
# ───────────────────────────────────────────────────────────────────
FROM --platform=linux/amd64 debian:trixie-slim@sha256:28de0877c2189802884ccd20f15ee41c203573bd87bb6b883f5f46362d24c5c2

ENV DEBIAN_FRONTEND=noninteractive
# Cache busted by the package list, not by the date — pin trixie
# upstream changes via the explicit apt versions if reproducibility
# becomes a CI requirement (the bake's qcow2 sha is the actual
# reproducibility anchor; the baker image's drift only affects
# build-time perf).
RUN apt-get update && apt-get install --no-install-recommends -y \
        ca-certificates \
        curl \
        jq \
        qemu-utils \
        cryptsetup-bin \
        util-linux \
        mount \
        debootstrap \
        cloud-guest-utils \
        parted \
        e2fsprogs \
        squashfs-tools \
        xfsprogs \
        btrfs-progs \
        rsync \
        attr \
        policycoreutils \
        xz-utils \
        zstd \
        coreutils \
        bash \
        python3 \
        awscli \
        initramfs-tools-core \
        dracut-core \
    && rm -rf /var/lib/apt/lists/*
# initramfs-tools-core (lsinitramfs) + dracut-core (lsinitrd) back the
# bake script's stage-5 fail-closed audit: the EXTRACTED initrd must
# carry the hippius release core or the bake refuses to ship (the
# 2026-07-04 stale-loop /boot bug shipped a pristine hookless initrd
# that hung every guest at cryptroot).
# policycoreutils (setfiles) backs the RHEL-family SELinux offline
# relabel: the bake writes guest files from this non-SELinux container,
# so it relabels the mounted rootfs from the host against the GUEST's own
# binary policy (`setfiles -c`) instead of shipping an `.autorelabel`
# image (whose first-boot relabel force-REBOOTS and breaks the SNP
# measured-boot/single-use-KBS-nonce chain).
# squashfs-tools (mksquashfs) backs the golden_verity_overlay bake mode:
# `build_golden_verity_base()` packs the root tree into a reproducible
# read-only squashfs `rootfs.img`, then `veritysetup format` (from
# cryptsetup-bin) builds the dm-verity hash tree over it. Without this
# the golden bake fails the host-tool preflight ("missing host tools:
# mksquashfs"). Legacy LUKS bakes don't reference it.

# The bake script + entrypoint live at canonical paths so the Job
# spec can reference them without leaking the in-image layout.
COPY scripts/tenant-image-bake.sh   /usr/local/bin/tenant-image-bake.sh
COPY binaries/tenant-baker/entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod 0755 /usr/local/bin/tenant-image-bake.sh /usr/local/bin/entrypoint.sh

# initramfs assets: the bake script computes `SCRIPT_DIR` from its
# own location (`/usr/local/bin`) and reads
# `${SCRIPT_DIR}/initramfs/{hippius-luks-keyscript,hippius-luks-hook,
# hippius-net-teardown}`. Stage them under that exact path so the
# script's relative lookups resolve inside the pod without env-var
# plumbing.
COPY scripts/initramfs/hippius-luks-keyscript \
     scripts/initramfs/hippius-luks-hook \
     scripts/initramfs/hippius-net-teardown \
     scripts/initramfs/hippius-release-core.sh \
     scripts/initramfs/hippius-golden-overlay.sh \
     scripts/initramfs/hippius-golden-boot \
     scripts/initramfs/hippius-golden-hook \
     /usr/local/bin/initramfs/
RUN chmod 0755 \
        /usr/local/bin/initramfs/hippius-luks-keyscript \
        /usr/local/bin/initramfs/hippius-luks-hook \
        /usr/local/bin/initramfs/hippius-net-teardown \
        /usr/local/bin/initramfs/hippius-release-core.sh \
        /usr/local/bin/initramfs/hippius-golden-overlay.sh \
        /usr/local/bin/initramfs/hippius-golden-boot \
        /usr/local/bin/initramfs/hippius-golden-hook

# The RHEL-family dracut module (multi-OS series). The bake script's
# RHEL arm installs it into the guest at
# /usr/lib/dracut/modules.d/90hippius-luks/; staged here so the baker
# image is self-contained for every distro family.
COPY scripts/dracut/90hippius-luks/ /usr/local/bin/dracut/90hippius-luks/
RUN chmod 0755 /usr/local/bin/dracut/90hippius-luks/*.sh

# The RHEL-family GOLDEN dracut module (95hippius-golden, golden-bake
# dracut counterpart of the initramfs-tools golden boot). The bake
# script's RHEL golden arm stages it into the guest at
# /usr/lib/dracut/modules.d/95hippius-golden/ (`GOLDEN_DRACUT_MODULE_SRC=
# ${SCRIPT_DIR}/dracut/95hippius-golden`); staged here so the baker image
# carries every distro-family golden asset. Only the `.sh` scripts are
# +x — the `.service` units are declarative (no execute bit).
COPY scripts/dracut/95hippius-golden/ /usr/local/bin/dracut/95hippius-golden/

# §23 keepalive ExecStart shim. `tenant-image-bake.sh` reads it from
# `${SCRIPT_DIR}/guest/hippius-keepalive-start` and `install`s it into the
# tenant rootfs; without it the bake dies at
# "keepalive shim missing" — which is exactly what the first real bake on
# the #908 image did. #908 shipped the bake logic, the agent binary above
# and a CI test that EXECUTES the staging block against a temp rootfs, but
# nothing ever asserted the baker IMAGE carried the shim, so the gap was
# invisible until a live bake ran. `scripts/dev/baker-assets-test.sh` now
# pins every `${SCRIPT_DIR}/...` path the bake script reads against a COPY
# in this file.
COPY scripts/guest/hippius-keepalive-start /usr/local/bin/guest/hippius-keepalive-start
RUN chmod 0755 /usr/local/bin/guest/hippius-keepalive-start
RUN chmod 0755 /usr/local/bin/dracut/95hippius-golden/*.sh

# The two release-flow binaries the keyscript invokes inside the
# tenant initramfs. `entrypoint.sh:194-195` passes their absolute
# paths to `tenant-image-bake.sh --hippius-release-bin /usr/sbin/...`
# which then `install`s them into the tenant rootfs's `/usr/sbin/`.
COPY --from=agent-builder /src/target/x86_64-unknown-linux-musl/release/hippius-guest-release  /usr/sbin/hippius-guest-release
COPY --from=agent-builder /src/target/x86_64-unknown-linux-musl/release/hippius-vsock-ticket   /usr/sbin/hippius-vsock-ticket
RUN chmod 0755 /usr/sbin/hippius-guest-release /usr/sbin/hippius-vsock-ticket

# The §24/§25 guest shutdown-sign binary (DYNAMIC glibc, built in the
# bookworm `eol-builder` stage above). `entrypoint.sh` passes its
# absolute path to `tenant-image-bake.sh --hippius-eol-bin`, which then
# `install`s it into the tenant rootfs's `/usr/sbin/` + wires
# `hippius-eol-sign.service` (Before=shutdown.target → `eol --sign-only`)
# so a clean shutdown signs + pushes the §25 StoppedAck to vali.
COPY --from=eol-builder /src/target/release/hippius-agent-initramfs  /usr/sbin/hippius-agent-initramfs
RUN chmod 0755 /usr/sbin/hippius-agent-initramfs

# The §23 served-receipt telemetry agent (DYNAMIC glibc, built in the same
# bookworm `eol-builder` stage). `entrypoint.sh` passes its absolute path to
# `tenant-image-bake.sh --hippius-telemetry-bin`, which `install`s it into
# the tenant rootfs's `/usr/sbin/` + wires `hippius-tenant-telemetry.service`
# so the guest emits guest-signed ServedDeliveryReceipts over vsock for
# uptime billing.
COPY --from=eol-builder /src/target/release/hippius-agent-tenant-telemetry /usr/sbin/hippius-agent-tenant-telemetry
RUN chmod 0755 /usr/sbin/hippius-agent-tenant-telemetry

# The §23 SNP live-attestation keepalive agent (DYNAMIC glibc, same
# `eol-builder` stage). `entrypoint.sh` passes its absolute path to
# `tenant-image-bake.sh --hippius-keepalive-bin`, which `install`s it into
# the tenant rootfs's `/usr/sbin/` + installs AND ENABLES
# `hippius-keepalive.service`. This is what makes the served receipts above
# creditable: without a guest emitting SNP-rooted liveness proofs, a miner
# can lift the (root-readable) telemetry key, kill the VM and bill forever.
COPY --from=eol-builder /src/target/release/hippius-agent-keepalive /usr/sbin/hippius-agent-keepalive
RUN chmod 0755 /usr/sbin/hippius-agent-keepalive

WORKDIR /work

# The Job runs as root inside the pod (privileged) so no USER
# directive — the cluster's pod-security stance is what gates
# whether a Job with `privileged: true` may run, NOT a Dockerfile
# user.
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
