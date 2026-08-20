# hippius-compute

**Confidential computing for a permissionless miner fleet.**

Hippius Compute is the control plane for a DePIN cloud in which tenant
VMs run under **AMD SEV-SNP** on hardware owned by third parties — and
the machine's operator, with full root on the bare metal, still cannot
read the tenant's data.

That property is not a policy. It is enforced by attestation: the
tenant's disk-encryption key is released **only** to a guest that has
produced a hardware-signed SEV-SNP report whose measurement is on a
signed allowlist, and it is released **wrapped to an X25519 key
generated inside the SEV-SNP-encrypted guest RAM**. The miner host
relays ciphertext it cannot open, and the LUKS volume on its disks is
AES-XTS ciphertext with no key on the machine.

If that claim is what you came to check, read
[`docs/security/data-visibility.md`](./docs/security/data-visibility.md)
— the load-bearing security contract, stating exactly what each party
sees in plaintext at each stage, with code cross-references.

## The parts

| | |
| --- | --- |
| **tenant** | launches a confidential VM through the validator API and gets a machine nobody else can read |
| **miner** | supplies SEV-SNP-capable hardware, runs `hippius-miner-agent`, earns for attested uptime — see [onboarding](./docs/operator/onboarding-a-miner.md) |
| **validator (`vali`)** | Django control plane: placement, lifecycle, telemetry, billing |
| **KBS** | Rust Key Broker Service; the only component that can release a tenant key, and it does so only against a verified SEV-SNP report |
| **chain** | the registry of record — who is a miner, who is active, what they charge |

## Running a miner

Miner **authentication** is permissionless and CA-free: the agent
generates its own Ed25519 identity, presents a self-signed client
certificate carrying that identity, and the Edge gateway admits it if and
only if that node id is registered and `active` on chain. No operator
ever issues you a certificate, and nobody can revoke your identity by
revoking a certificate they signed.

**That is not the same as needing nothing from anyone.** Joining an
existing fleet still requires six things its operator has to give you —
a registered and funded family account on chain, a NetBird setup key for
that fleet's mesh, the Edge server CA, the order-signing public key, the
Edge/KBS/object-store endpoints, and one admin token for a single
registration call. None of them lets the fleet operator read your
tenants' data or gives them authority over your identity; they are
routing and mesh membership. But you cannot obtain them from this
repository, so read
[**"What you cannot self-supply"**](./docs/operator/onboarding-a-miner.md#what-you-cannot-self-supply)
BEFORE you buy hardware.

If you are standing up your own fleet rather than joining one, you
generate all six yourself — and note that of the six first-party
container images this repository builds, **`hippius-vali`,
`hippius-edge-gateway`, `hippius-tenant-baker` and
`hippius-epoch-closer` are not published publicly** (verified
unauthenticated against GHCR). The miner path does not need them — it
builds `hippius-miner-agent` from source and pulls no first-party image —
but the validator side you would have to build yourself.

Start here: [**`docs/operator/onboarding-a-miner.md`**](./docs/operator/onboarding-a-miner.md).

## Reading order

| Document | What it is |
| --- | --- |
| [`ARCHITECTURE.md`](./ARCHITECTURE.md) | design of record, §§1–26 — the specification everything else implements |
| [`DIAGRAMS.md`](./DIAGRAMS.md) | visual overview of the zones and the trust boundaries between them |
| [`docs/security/data-visibility.md`](./docs/security/data-visibility.md) | the security contract (start here if you are auditing) |
| [`docs/operator/`](./docs/operator/) | runbooks: onboarding a miner, launching a VM, baking an image, recovery procedures, cutting the public repository |
| [`docs/design/`](./docs/design/) | design notes for individual subsystems |
| [`test_vectors/README.md`](./test_vectors/README.md) | conformance vectors `v1` for parallel implementations |

## Crates

| Crate | Role |
| --- | --- |
| **`hippius-types`** | Canonical-CBOR wire schemas shared by chain / KBS / vali / guest: `OrderTicket`, `ReleaseContext`, `KbsResponse`, `StoppedAck`, `ServedDeliveryReceipt`, `ServedDeliveryAggregate`, `REPORT_DATA` layouts, `userdata_digest` preimage. Reference encoder + `assert_canonical` decoder. Single source of truth — no schema drift across impls. |
| **`kbs-core`** | Tier-0 Key Broker Service core (Rust, deny-by-default): §6 OrderTicket COSE/Ed25519 verify, §7 release pipeline (commit-before-emit + signed denial), §8 attestation-bound Vault seam, §19 exact path@version, §20 HPKE wrap + Ed25519 response, §22 offline-allowlist with monotonic high-water + ARK-pinned root, §24 unified VM lifecycle, real AMD SEV-SNP cert-chain + TCB verifier, durable `ReleaseStore` / `VmStateStore` / `KbsNonceStore` with cross-process race-safety, §15 durable hash-chained `FileAuditSink`. |
| **`hippius-guest`** | The guest-side protocol half that runs INSIDE the attested SEV-SNP VM: `verify_and_unwrap_release` (the single trust gate before LUKS mount), `sign_stopped_ack` (§24/§25 end-of-life), `sign_aggregate` / `verify_aggregate` (§23 Audit-VM `ServedDeliveryAggregate`), `sign_served_receipt` + `verify_receipt_in_aggregate_window` (§23 anti-teleportation gate). Pure-Rust crypto, no kernel/cryptsetup pieces. |

## Binaries

| Binary | Role |
| --- | --- |
| **`hippius-kbs-server`** | Production KBS HTTP front door (axum) — `/healthz`, `/v1/kbs/nonce`, `/v1/kbs/release`. SEV-SNP `RealSnpVerifier` (ARK→ASK→VEK), §22 signed-allowlist enforcement, Vault KV read for release secrets. Runs inside an attested Confidential VM. |
| **`hippius-edge-gateway`** | Opaque relay between the miner fleet and the internal control plane. mTLS listener on the miner side, inner listener for vali → Edge → miner order dispatch (Ed25519 signed). Enforces miner admission (`EDGE_MINER_AUTH`). |
| **`hippius-miner-agent`** | Bare-metal control plane on each miner: receives signed orders from the Edge, drives libvirt for SEV-SNP CVM lifecycle (launch/stop/destroy), heartbeats to vali, self-generates its node identity. |
| **`hippius-agent-initramfs`** | The `/init` PID 1 inside every tenant SEV-SNP CVM. §21 boot pipeline: mount procfs/sysfs/devtmpfs → SNP report → KBS release → HPKE unwrap → LUKS unlock → NoCloud seed → `switch_root`. Fail-closed poweroff on any deviation. |
| **`hippius-agent-audit-vm`** | The §23 anti-cheating Audit-VM agent — RDTSC drift detect, anti-suspension, `ServedDeliveryAggregate` co-sign. |
| **`hippius-agent-tenant-telemetry`** | Signed-telemetry signer inside the tenant CVM; the vali telemetry broker validates its receipts. |
| **`hippius-ticket-validator`** | vali's Rust shell-out helper — parses COSE_Sign1 OrderTickets, verifies StoppedAck envelopes, decodes orders for the dispatch chain, reads §23 pallet state over JSON-RPC. |
| **`hippius-kbs-allowlist-tool`** | Mints the COSE_Sign1 §22 allowlist artifact from a TOML manifest + the offline root seed. Used in CI (KAT re-mint + `diff -q`) and by operators for allowlist rotation. |
| **`hippius-image-provenance`** | The §F provenance signer — produces `provenance.cbor` next to every published UKI. |
| **`hippius-order-ticket-mint`** | Mints signed COSE_Sign1 `OrderTicket` envelopes. |
| **`hippius-miner-uki-fetch`** | Miner-side helper that fetches a content-addressed UKI from the §F object store, verifies the sha, and stages it under `/var/lib/hippius-miner/staging/<sha>/`. |
| **`hippius-uki-measure`** | Recomputes the SEV-SNP `launch_digest` from a built UKI; used in the §F build factory + KAT verification. |

## Deployment

GitOps — Argo CD app-of-apps, with the deployment branch as the source
of truth for the cluster. See
[`deploy/gitops/README.md`](./deploy/gitops/README.md) for the workflow
(edit YAML → merge → Argo CD syncs), the repo layout and the bootstrap
procedure. Host provisioning lives in
[`deploy/ansible/`](./deploy/ansible/).

Every endpoint, address, bucket, credential path and signing key in
this repository is **configuration**, expressed as an environment
variable or a Helm value. There are no defaults pointing at anyone's
running deployment: a value that identifies infrastructure is either
unset (and fails loudly at first use) or an obvious `<PLACEHOLDER>`.
You supply your own.

## Test gate

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
```

[`scripts/run-ci-locally.sh`](./scripts/run-ci-locally.sh) runs the
OFFLINE checks of the `rust`, `vali` and `sentinel` jobs and prints what
it skipped — network steps, docker jobs and the wasm32 targets. A green
run there is a cheap filter, not a verdict. The validator service also
has its own suite:

```sh
cd vali && ruff check . && pytest -q
```

## Operator scripts

| Script | Purpose |
| --- | --- |
| [`scripts/run-ci-locally.sh`](./scripts/run-ci-locally.sh) | Reproduce CI locally on a Linux host (rust fmt/clippy/build/test + sentinel pytest) |
| [`scripts/check-no-seed-logging.sh`](./scripts/check-no-seed-logging.sh) | §20 grep gate — refuses any source line that logs a known-sensitive symbol (seed, KEK, setup-key, …) |
| [`scripts/tenant-secrets-stage.sh`](./scripts/tenant-secrets-stage.sh) | Stage per-tenant release secrets in Vault (LUKS KEK + sealed user-data) |
| [`scripts/tenant-image-bake.sh`](./scripts/tenant-image-bake.sh) | Bake an encrypted Hippius-ready qcow2 from a vanilla cloud image, with no miner access. Uploaded to the object store; the miner-agent fetches it via a `tenant-preflight` order |
| [`scripts/tenant-rootfs-build.sh`](./scripts/tenant-rootfs-build.sh) | Stage 1 of the split bake pipeline (rootfs build) |
| [`scripts/tenant-uki-stage-miner.sh`](./scripts/tenant-uki-stage-miner.sh) | Fetch + verify + extract a content-addressed tenant UKI on a target miner (legacy SSH path) |
| [`scripts/post-merge-tracking.py`](./scripts/post-merge-tracking.py) | Sync tracking issues after a PR merges |

## Licence

[Apache License 2.0](./LICENSE).

Every first-party crate inherits it through `license.workspace = true`, so
the workspace `Cargo.toml` is the single place it is declared.

The dependency graph imposes no copyleft obligation: of 590 crates reachable
from the workspace, exactly two carry a GPL option (`array-bytes`,
`proc-macro-warning`) and both are dual-licensed with Apache-2.0 available.
The miner-agent's own 272-crate closure has one copyleft-bearing crate,
`r-efi`, which is tri-licensed. Measured with `cargo metadata --locked`, not
assumed.
