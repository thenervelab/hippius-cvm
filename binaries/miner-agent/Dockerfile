# syntax=docker/dockerfile:1.7
#
# hippius-miner-agent — the per-miner-host orchestrator that
# accepts §6/§14 LaunchOrders + drives libvirt to provision tenant
# SEV-SNP CVMs.
#
# Why a Docker image at all
# -------------------------
# A miner is a standalone EPYC bare-metal host, NOT a k8s
# node — historically the binary was scp'd in by hand + deployed as a
# systemd service. That workflow violates the "all operations from the
# validator, no SSH to the miner" discipline (see USER constraint
# 2026-06-07 and CLAUDE.md global notes). Publishing this image to
# GHCR lets the operator pull a digest-pinned build into the miner's
# container runtime (systemd-podman quadlet, or `docker pull` + a
# systemd Unit File) from the validator side without ever touching
# the miner shell. The §20 secret-discipline + every `closed-vocab
# &'static str` sub-classifier in the agent's error model are
# unchanged by the packaging boundary.
#
# Multi-stage
# -----------
#   1. `agent-builder`: `rust:1.93-slim-trixie@sha256:c0a38f5662afdb298898da1d70b909af4bda4e0acff2dc52aea6360a9b9c6956` cross-builds
#      `hippius-miner-agent` for `x86_64-unknown-linux-gnu`. Same
#      reproducibility envelope as `binaries/tenant-baker/Dockerfile`'s
#      stage 1 — no `--locked` (the workspace `pallet-staking-reward-fn`
#      rejects strict resolve; lockfile still pinned).
#   2. runtime: `debian:trixie-slim@sha256:28de0877c2189802884ccd20f15ee41c203573bd87bb6b883f5f46362d24c5c2` with the runtime tooling the
#      miner-agent shells out to (libvirt CLI for `virsh`-driver,
#      qemu-utils + cryptsetup for the Phase 2B state-disk module,
#      coreutils + bash for general posture). The miner-agent itself
#      lands at `/usr/local/bin/hippius-miner-agent`.

FROM --platform=linux/amd64 rust:1.93-slim-trixie@sha256:c0a38f5662afdb298898da1d70b909af4bda4e0acff2dc52aea6360a9b9c6956 AS agent-builder

ENV DEBIAN_FRONTEND=noninteractive
ENV CARGO_TERM_COLOR=never

RUN apt-get update && apt-get install --no-install-recommends -y \
        pkg-config \
        libssl-dev \
        libcryptsetup-dev \
        libclang-19-dev \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src
# `.dockerignore` excludes `target/`, `.git/`, vali venv, etc.
COPY . /src

# `--features snp` is REQUIRED for a real SNP miner: without it
# `compute_launch_digest` is the fail-closed stub that returns
# `cvm-launch-digest/feature-disabled`, and `serve` exits 2 on the
# first launch order (observed live 2026-06-10 deploying the #349
# image to a real SNP miner — the binary refused every launch). The `sev`
# crate is Linux-only + needs openssl (pkg-config + libssl-dev,
# installed above); this stage is already linux/amd64 so the dep
# resolves. Mirrors `packer/tenant-uki/uki/Dockerfile`'s
# `cargo build --release --features snp -p hippius-uki-measure`.
RUN cargo build --release -p hippius-miner-agent --features snp --bin hippius-miner-agent

# ───────────────────────────────────────────────────────────────────
# Runtime image
# ───────────────────────────────────────────────────────────────────
FROM --platform=linux/amd64 debian:trixie-slim@sha256:28de0877c2189802884ccd20f15ee41c203573bd87bb6b883f5f46362d24c5c2

ENV DEBIAN_FRONTEND=noninteractive

# The miner-agent shells out to:
#   - `virsh`              (libvirt-clients) — define / create / destroy
#                          the tenant domain (`lifecycle::libvirt_driver`).
#   - `mkfs.ext4` + `mount` (e2fsprogs + util-linux) — Phase 2B state
#                          disk provisioning (`lifecycle::state_disk`).
#   - `qemu-img`           (qemu-utils) — probe disk magic + create
#                          per-VM data disks (`lifecycle::qemu_config`).
#   - `cryptsetup`         (cryptsetup-bin) — host-side LUKS ops the
#                          tenant lifecycle doesn't run today but may
#                          in a future PR; bundled for parity with
#                          the operator workstation environment.
#   - `bash` + `coreutils` — every shell pipeline the agent assumes
#                          in its `Command::new(...)` shell-outs.
#   - `ca-certificates`    — TLS trust anchors the HTTP clients use
#                          (Edge mTLS, KBS admin).
RUN apt-get update && apt-get install --no-install-recommends -y \
        ca-certificates \
        libvirt-clients \
        qemu-utils \
        e2fsprogs \
        util-linux \
        cryptsetup-bin \
        bash \
        coreutils \
    && rm -rf /var/lib/apt/lists/*

COPY --from=agent-builder /src/target/release/hippius-miner-agent /usr/local/bin/hippius-miner-agent
RUN chmod 0755 /usr/local/bin/hippius-miner-agent

WORKDIR /var/lib/hippius-miner

# No USER directive — the agent needs root inside its (privileged)
# host container to talk to libvirt's UNIX socket + `mount` the state
# disk before bake. The miner's container runtime constrains this
# privilege via the Unit File / Pod manifest, not the Dockerfile.
ENTRYPOINT ["/usr/local/bin/hippius-miner-agent"]
