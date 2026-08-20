# hippius-kbs-server — Tier-0 KBS container image. PR-K6, §K (#54).
#
# The KBS is a CONFIDENTIAL workload: the pod runs under the
# `kata-qemu-snp` RuntimeClass inside an AMD SEV-SNP CVM (#1 locked
# topology — "le launch_digest du pod EST la mesure attestée"). The
# confidential isolation is the pod runtime's job; this image carries
# only the binary.
#
# Multi-stage: a digest-pinned Rust toolchain builds the release binary
# from the workspace; the runtime stage is distroless — the image holds
# the binary, glibc, and nothing else (no shell, no package manager).
#
# Build (linux/amd64, to match the k3s cluster) — the context is the
# REPO ROOT because the crate is a workspace member:
#
#   docker buildx build --platform linux/amd64 \
#     -f binaries/kbs-server/Dockerfile \
#     -t ghcr.io/thenervelab/hippius-kbs-server:<tag> .

# ── builder ─────────────────────────────────────────────────────────
# Rust 1.93.0 — matches rust-toolchain.toml. Pinned by digest (§F
# supply-chain discipline: never a floating tag).
FROM rust:1.93.0-bookworm@sha256:d0a4aa3ca2e1088ac0c81690914a0d810f2eee188197034edf366ed010a2b382 AS builder

WORKDIR /src
# The whole workspace — cargo must parse every member manifest to
# resolve the workspace, but `-p hippius-kbs-server` compiles only this
# crate's subtree. `.dockerignore` keeps `target/` + `.git/` out of the
# build context.
COPY . .
# `--locked` — build strictly from the committed Cargo.lock; a drift
# fails the build loudly rather than silently resolving something new.
RUN cargo build --locked --release -p hippius-kbs-server

# ── runtime ─────────────────────────────────────────────────────────
# distroless/cc — glibc + libgcc for the dynamically-linked Rust
# binary, and nothing else. `:nonroot` runs as uid 65532. Pinned by
# digest.
FROM gcr.io/distroless/cc-debian12:nonroot@sha256:bd2899c12b335c827750ccf2359879eab09c09b206023dcebea408947d54127c

COPY --from=builder /src/target/release/hippius-kbs-server /usr/local/bin/hippius-kbs-server

# uid 65532 (distroless `nonroot`). The pod also pins this via
# securityContext.runAsNonRoot; declaring it in the image keeps the
# binary non-root even if run outside that securityContext. The KBS
# writes only to the mounted state + audit volumes, so the pod runs
# with a read-only root filesystem.
USER 65532:65532

# The §17 HTTP transport — /healthz, /readyz, /v1/kbs/{nonce,release}.
EXPOSE 8000

ENTRYPOINT ["/usr/local/bin/hippius-kbs-server"]
