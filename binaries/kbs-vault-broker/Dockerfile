# hippius-kbs-vault-broker — SNP-attestation-bound Vault broker (#102).
#
# The broker is a CONFIDENTIAL workload: the pod runs under the
# `kata-qemu-snp` RuntimeClass inside an AMD SEV-SNP CVM, like the KBS
# it serves. It is the ONLY holder of a privileged Vault credential —
# the KBS authenticates with its SNP self-report and receives a
# per-VM-scoped short-TTL child token instead.
#
# Multi-stage: a digest-pinned Rust toolchain builds the release binary
# from the workspace; the runtime stage is distroless — the image holds
# the binary, glibc, and nothing else (no shell, no package manager).
# The image is PUBLIC (kata guest-pull); it carries no secrets — the
# privileged token arrives via the BROKER_VAULT_TOKEN env (mounted
# Secret), the config via a ConfigMap.
#
# Build (linux/amd64, to match the k3s cluster) — the context is the
# REPO ROOT because the crate is a workspace member:
#
#   docker buildx build --platform linux/amd64 \
#     -f binaries/kbs-vault-broker/Dockerfile \
#     -t ghcr.io/thenervelab/hippius-kbs-vault-broker:<tag> .

# ── builder ─────────────────────────────────────────────────────────
# Rust 1.93.0 — matches rust-toolchain.toml. Pinned by digest (§F
# supply-chain discipline: never a floating tag).
FROM rust:1.93.0-bookworm@sha256:d0a4aa3ca2e1088ac0c81690914a0d810f2eee188197034edf366ed010a2b382 AS builder

WORKDIR /src
# The whole workspace — cargo must parse every member manifest to
# resolve the workspace, but `-p hippius-kbs-vault-broker` compiles
# only this crate's subtree. `.dockerignore` keeps `target/` + `.git/`
# out of the build context.
COPY . .
# `--locked` — build strictly from the committed Cargo.lock; a drift
# fails the build loudly rather than silently resolving something new.
RUN cargo build --locked --release -p hippius-kbs-vault-broker

# ── runtime ─────────────────────────────────────────────────────────
# distroless/cc — glibc + libgcc for the dynamically-linked Rust
# binary, and nothing else. `:nonroot` runs as uid 65532. Pinned by
# digest.
FROM gcr.io/distroless/cc-debian12:nonroot@sha256:bd2899c12b335c827750ccf2359879eab09c09b206023dcebea408947d54127c

COPY --from=builder /src/target/release/hippius-kbs-vault-broker /usr/local/bin/hippius-kbs-vault-broker

# uid 65532 (distroless `nonroot`). The pod also pins this via
# securityContext.runAsNonRoot; declaring it in the image keeps the
# binary non-root even if run outside that securityContext. The broker
# is stateless (in-memory challenge store) — the pod runs with a
# read-only root filesystem and no writable volumes.
USER 65532:65532

# Canonical-CBOR challenge/redeem transport + /healthz.
EXPOSE 8100

# argv[1] is the config path (defaults to this exact path in main.rs;
# stated explicitly so the contract is visible in `docker inspect`).
ENTRYPOINT ["/usr/local/bin/hippius-kbs-vault-broker", "/etc/kbs-vault-broker/config.toml"]
