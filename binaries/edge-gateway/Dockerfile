# hippius-edge-gateway — container image. PR-K8, §K (#54).
#
# The Edge gateway runs as a non-confidential runc pod — it is the
# opaque relay, NOT a Tier-0 confidential workload (#1 locked
# topology: "Opaque relay, pas besoin d'être confidential"). So no
# Kata, no kata-qemu-snp RuntimeClass.
#
# Multi-stage: a digest-pinned Rust toolchain builds the release
# binary from the workspace; the runtime stage is distroless — the
# image carries the binary, glibc, and nothing else (no shell, no
# package manager).
#
# Build (linux/amd64, to match the k3s cluster) — context is the
# REPO ROOT, because the crate is a workspace member (`hippius-types`
# path dependency + `[workspace.lints]`):
#
#   docker buildx build --platform linux/amd64 \
#     -f binaries/edge-gateway/Dockerfile \
#     -t ghcr.io/thenervelab/hippius-edge-gateway:<tag> .

# ── builder ─────────────────────────────────────────────────────────
# Rust 1.93.0 — matches rust-toolchain.toml. Pinned by digest (§F
# supply-chain discipline: never a floating tag).
FROM rust:1.93.0-bookworm@sha256:d0a4aa3ca2e1088ac0c81690914a0d810f2eee188197034edf366ed010a2b382 AS builder

WORKDIR /src
# The whole workspace — cargo must parse every member manifest to
# resolve the workspace, but `-p hippius-edge-gateway` compiles only
# this crate's subtree (the Substrate / polkadot-sdk deps belong to
# `pallets/compute-scoring` and are never fetched). `.dockerignore`
# keeps `target/` + `.git/` out of the build context.
COPY . .
# `--locked` — build strictly from the committed Cargo.lock; a drift
# fails the build loudly rather than silently resolving something new.
RUN cargo build --locked --release -p hippius-edge-gateway

# ── runtime ─────────────────────────────────────────────────────────
# distroless/cc — glibc + libgcc for the dynamically-linked Rust
# binary, and nothing else. `:nonroot` runs as uid 65532. Pinned by
# digest.
FROM gcr.io/distroless/cc-debian12:nonroot@sha256:bd2899c12b335c827750ccf2359879eab09c09b206023dcebea408947d54127c

COPY --from=builder /src/target/release/hippius-edge-gateway /usr/local/bin/hippius-edge-gateway

# uid 65532 (distroless `nonroot`). The pod also pins this via
# securityContext.runAsNonRoot; declaring it in the image keeps the
# binary non-root even if run outside that securityContext. The Edge
# writes only to `$EDGE_AUDIT_DIR` (a mounted emptyDir), so the pod
# can — and does — run with a read-only root filesystem.
USER 65532:65532

# Listeners (see ARCHITECTURE.md §5 and the chart's service.yaml):
#   9465 — read-only telemetry API  (/v1/edge/{pubkey,audit/verify})
#   9443 — HA peer link (mTLS)      — bound only when EDGE_PEER_ENDPOINT is set
#   9464 — Prometheus /metrics      — bound only when HA is enabled
EXPOSE 9465 9443 9464

ENTRYPOINT ["/usr/local/bin/hippius-edge-gateway"]
