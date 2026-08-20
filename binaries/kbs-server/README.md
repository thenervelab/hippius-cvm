# `hippius-kbs-server` — Tier-0 KBS production binary (§D)

The runnable **Key Broker Service**. `kbs-core` is the pure release-flow
logic and `kbs-server` is the axum HTTP transport — both are **libraries**.
This crate is the **binary entrypoint** that wires them into a process:
TOML config, durable file-backed stores, the hash-chained audit log, the
§22 signed allowlist, and graceful shutdown.

Spec of record: `ARCHITECTURE.md` §7 (release contract), §8 (CVM-KBS +
attestation-bound Vault), §17 (production wiring), §22 (offline
allowlist).

```sh
cargo build --release -p hippius-kbs-server
hippius-kbs-server --config /etc/kbs/config.toml      # VAULT_TOKEN in env
```

## Status — what is real, what is a transitional MVP

The SNP guest-report verifier + the §22 signed allowlist are **real**.
One transitional seam remains — the static-token Vault KV client —
tracked by the SNP-attested broker follow-up (#102). The production-
grade per-CHIP_ID VEK fetch from AMD KDS is the §17 follow-up; until
then the operator stages the VEK PEM into Vault, and ESO materialises
it as the `kbs-server-vek` Secret the binary reads via
`[snp].vek_pem_path`.

| Area | State |
|---|---|
| TOML config — `deny_unknown_fields`, fail-closed load | **real** |
| Durable stores — release / VM-state / KBS-nonce | **real** (`kbs-core` file stores) |
| Hash-chained audit log | **real** (`FileAuditSink`, exclusive lock) |
| §22 signed measurement allowlist (COSE_Sign1) | **real** (`InstalledAllowlist`) |
| Allowlist epoch high-water-mark | **real** (durable file-backed, this crate) |
| HTTP transport `/healthz`, `/v1/kbs/{nonce,release}`, `/readyz` | **real** |
| KBS response signing (in-process Ed25519) | **real** |
| SIGTERM / SIGINT graceful shutdown | **real** |
| SNP guest-report verifier (`RealSnpVerifier` + `SevChainVerifier`) | **real** when `[snp].vek_pem_path` is set; **deny-closed** (`UnconfiguredChainVerifier`) when absent. |
| Per-CHIP_ID VEK acquisition | **operator-staged** today; AMD-KDS in-cluster fetch + cache lands as the §17 follow-up. |
| **Vault access** | **MVP — static `VAULT_TOKEN`.** The SNP-attestation-bound broker (§8) lands in the broker follow-up. |

**Consequence:** when the chart's `[snp]` branch is enabled and a VEK
is mounted, `POST /v1/kbs/release` performs real AMD chain
verification on the guest report. The release pipeline still fails
closed at the downstream Vault step (`ChallengeVaultAuth` with
`kbs_measurement_ok: |_| false` + `min_tcb: u64::MAX`) because the
SNP-attested Vault broker is the follow-up that lights up the secret
release itself. With `[snp]` absent the binary still boots, but every
release fails closed at the chain step with the explicit
`UNCONFIGURED_CHAIN_MSG` classifier.

## Configuration

`--config` points at a TOML file. Every key is mandatory unless marked
optional; an unknown or misspelt key aborts startup (`deny_unknown_fields`).

```toml
[listen]
addr = "0.0.0.0:8000"            # HTTP bind address

[storage]
state_dir      = "/var/lib/kbs/state"   # releases/, nonces/, vm-states.json, allowlist-hwm
audit_dir      = "/var/lib/kbs/audit"   # hash-chained audit log (its own volume)
nonce_ttl_secs = 300                    # KBS-nonce TTL, must be > 0

[allowlist]
root_pubkey_hex = "<64 hex chars>"      # §22 allowlist-root Ed25519 public key
# signed_path  = "/var/lib/kbs/allowlist/allowlist.signed.cbor"   # optional COSE_Sign1 artifact

[keys]
signing_key_path = "/etc/kbs/signing.key"   # 32-byte Ed25519 seed (mounted secret)
kid_hex          = "<hex>"                  # KBS response-signing kid
auth_pubkey_hex  = "<hex>"                  # KBS channel / TLS-exporter public key

[vault]
address  = "https://vault.hippius.internal:8200"
kv_mount = "secret"

[launch_policy]
min_tcb       = 0
required_bits = 0
allowed_mask  = 0

# Zero or more L1 OrderTicket-signing keys:
# [[l1_keys]]
# kid_hex    = "<hex>"
# pubkey_hex = "<64 hex chars>"
```

No secret value is ever placed in this file: the response-signing key is
a mounted file referenced by path, and the Vault token is the
`VAULT_TOKEN` environment variable.

## Operator bootstrap

Before the binary can serve:

1. **`VAULT_TOKEN`** — exported in the environment. In the K6 deployment
   this is projected from Vault by the External Secrets Operator. Absent
   or empty ⇒ the binary fails closed.
2. **Response-signing key** — a 32-byte Ed25519 seed at
   `keys.signing_key_path` (a mounted secret).
3. **§22 allowlist** (optional but required for any release to succeed) —
   the COSE_Sign1 artifact from the `hippius-compute-allowlist` S3 bucket
   (provisioned by PR-K1). In K6 an init container fetches it to
   `allowlist.signed_path`; this binary then reads and verifies it
   against `allowlist.root_pubkey_hex`. With no artifact the binary still
   boots, but every release fails closed.
4. **State / audit directories** — `storage.state_dir` and
   `storage.audit_dir`. In K6 these are PVCs. The audit directory is
   opened with an **exclusive lock**, so only one KBS process may use it.

## Lifecycle

- **Startup** is fail-closed: bad arguments, an unreadable or invalid
  config, a missing `VAULT_TOKEN`, or any wiring fault aborts with a
  non-zero exit code — the orchestrator restarts the pod rather than
  running a half-wired KBS.
- **Shutdown** is graceful: on SIGTERM (k8s pod stop) or SIGINT the
  server stops accepting, drains in-flight requests, then drops the
  service — releasing the audit log's exclusive lock.
- The KBS runs as a **single replica** (K6: `replicas: 1` + a
  PodDisruptionBudget). The audit-log lock and the file-backed allowlist
  high-water-mark both assume single-process ownership.

## Follow-ups

- **SNP-attested Vault broker (#102)** — replaces the static-
  `VAULT_TOKEN` MVP with the locked SNP-attestation-bound broker (§8:
  "no static KBS AppRole secret"). The SNP verifier itself is already
  real (this binary wires `RealSnpVerifier` + `SevChainVerifier`
  against the binary-built-in AMD ARK + the operator-mounted VEK); the
  broker work is purely on the secret-release side.
- **§17 — per-CHIP_ID VEK fetch from AMD KDS** — replaces the
  operator-staged VEK Secret with an in-cluster sidecar that fetches
  the VEK per `CHIP_ID/TCB` from `kdsintf.amd.com` and refreshes it on
  TCB rotation. Until then the chart enables the SNP branch with one
  manually-staged VEK per host.
- **§22-ceremony in-binary root** — the allowlist root pubkey is
  currently in the operator ConfigMap; the production ceremony bakes
  it into the binary as a `const` (rotation = binary redeploy).
