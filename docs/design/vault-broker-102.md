# Issue #102 — SNP-attestation-bound Vault broker

Status: **design approved 2026-06-10; implementation in phased PRs (below).**

## Problem

The deployed KBS releases LUKS KEKs with two DEV overrides
(`binaries/kbs-server/src/wiring.rs:280-318`):
`dev_allow_any_kbs_measurement=true` (the KBS-side measurement / TCB /
launch-policy gates are bypassed) and `dev_skip_tls_verify=true`. In
prod posture those gates are fail-closed (`measurement_predicate =
|_| false`, `min_tcb = u64::MAX`) — so **no release can complete
without the dev override**, because the attestation-bound Vault broker
(#102) does not exist yet. Today the KBS reads KEKs from Vault with a
**static token**; KEK release is not bound to attestation at the Vault
layer.

§8 (ARCHITECTURE.md:252-280) locks the target: no static KBS Vault
credential; a Tier-0 authenticator issues a single-use challenge nonce
and verifies the KBS SNP evidence (measurement ∈ allowlist, TCB ≥
policy, AMD chain) before minting a per-VM-scoped, short-TTL,
response-wrapped capability; the KBS `REPORT_DATA` binds
`{challenge_nonce, per-VM scope, KBS auth pubkey}`.

## Decisions (2026-06-10)

- **Minimal Rust broker**, not a Vault Go plugin (reuse our
  `RealSnpVerifier` + built-in AMD roots; we own + test it).
- Broker runs **in-cluster as a kata-snp pod** (confidential runtime),
  not on the Tier-0 Vault VM.

## Trust model + honest v1 residual

**Closes:** the KBS→KEK path becomes genuinely attestation-gated. A
compromised non-CC host or a fake/tampered KBS cannot obtain a
capability — it cannot produce a valid SNP report with an allowlisted
KBS measurement bound to a fresh broker nonce. The KBS static Vault
token is removed. Every capability mint is attested, scoped to the
exact `path@version`, short-TTL, and audited.

**Does NOT close (residual):** the broker's own Vault bootstrap
credential. With the broker in-cluster and no Vault SNP-auth plugin,
its privileged Vault token is delivered via an ExternalSecret (k8s
Secret) — readable by a compromised cc-1 control plane. The broker's
*runtime* is confidential (kata-snp), but its token *bootstrap*
transits the host. Closing this needs the Vault SNP-auth plugin
(declined) or confidential secret provisioning — a follow-up. v1 is
still a major improvement: one confidential broker pod holds the only
privileged token, and the KBS→capability leg is fully attested.

## The seam (already built — reuse, do not rebuild)

- `kbs-core/src/vault.rs`: `AttestedVaultAuth`
  (`issue_challenge`/`redeem`), `VaultChallenge`, `KbsAuthEvidence`,
  `VaultCapability`, `VaultScope`, `VaultKv`. Reference
  `ChallengeVaultAuth` shows the redeem gate order.
- `kbs-core/src/release.rs:289-310` already calls
  `issue_challenge → redeem → read_exact` after SNP verify + §22
  allowlist + lifecycle + boot counter. **`process_release` is
  unchanged.**
- `kbs-core/src/snp.rs` `VerifiedReport`; `RealSnpVerifier` /
  `SevChainVerifier` (`snp_real.rs`, `binaries/kbs-server/src/attest.rs`)
  reused by the broker to verify the KBS report. AMD ARK/ASK built-in
  (`vendor/sev`); VEK operator-mounted.
- `binaries/agent-initramfs/src/stages/snp_ioctl.rs` `SevGuestProvider`
  + the `ReportData` structural-enforcement pattern in `snp_report.rs`
  — the KBS self-report reuses both.

## Key design point — fresh report per release

`process_release` passes `deps.kbs_attestation` as a **static**
`&VerifiedReport`, but a remote broker issues a **fresh** nonce that
the KBS report's `REPORT_DATA` must bind. So the `RemoteBrokerVaultAuth`
client produces a fresh self-report **inside `redeem`** (binding
`challenge.nonce(32) ‖ auth_pubkey(32)`) and POSTs the raw report to
the broker; the broker verifies it. `ev.verified` (the static
placeholder) is unused on the broker path — keeping `process_release`
unchanged. The broker's `redeem` verification — NOT the KBS — is the
authority on the report.

## Phased PRs

**PR A — broker core (`binaries/kbs-vault-broker`).** Wire protocol
(canonical-CBOR, fail-closed, domain-separated — mirror
`hippius-types/src/evidence_bundle.rs`): `challenge` + `redeem`
request/response. Challenge store: CSPRNG 32-byte nonces, single-use,
short TTL, fail-closed CAS (mirror the KBS replay store). `redeem`:
verify the raw report via `RealSnpVerifier`; check
`report_data == nonce ‖ auth_pubkey`; check measurement ∈ broker
KBS-measurement allowlist (signed, monotonic HWM, analogous to §22
`InstalledAllowlist`); check TCB ≥ floor + policy bits; mint a
per-VM-scoped short-TTL Vault token (`token create`, child policy
read-only on exactly `secret/data/<luks_path>` + `<userdata_path>`,
`ttl≈60s`, `num_uses=2`, `no_default_policy`). axum transport + the
closed-vocab error model. Full gate-matrix tests with mock Vault + mock
reports. Holds the only privileged Vault token (§20 discipline).

**PR B — KBS side.** `kbs_self_report` producer (`SevGuestSelfReport`,
`cfg(linux+x86_64)`, mock for tests; structural `REPORT_DATA` helper)
+ `RemoteBrokerVaultAuth` client implementing `AttestedVaultAuth`
against the broker over TLS. Wire into `wiring.rs` behind a new
`vault.broker_url` config; the dev static path stays as fallback until
the broker deploys. `config.rs`: `broker_url` set ⇒ refuse the dev
flags. Mount `/dev/sev-guest` into the KBS kata pod.

**PR C — deploy + flip.** `deploy/gitops/apps/kbs-vault-broker`
(kata-snp), ExternalSecret for its Vault token, NetworkPolicy
(KBS→broker, broker→Vault only), the KBS-measurement allowlist
artifact + the live KBS measurement. Set `vault.broker_url`, flip both
dev flags off, mount the prod Vault CA, bump digests, ArgoCD sync.

## Verification

1. `cargo test -p kbs-core -p hippius-kbs-server -p hippius-kbs-vault-broker`
   — redeem gate matrix (good, bad measurement, stale nonce, replay,
   wrong report_data, TCB floor), self-report, client round-trip.
2. `cargo clippy --workspace --no-deps -- -D warnings`, `cargo fmt`.
3. Broker + kbs-server image builds green.
4. **Live (post-deploy):** launch a tenant VM (smoke path proven
   2026-06-10) with the broker wired + dev flags OFF; confirm
   `/v1/kbs/release` returns 200 — the KBS self-attested to the broker,
   got a scoped Vault token, read the KEK, released it. Negative: a KBS
   measurement NOT in the broker allowlist → release denied.

## Out of scope

- Vault SNP-auth plugin (declined).
- Closing the broker-token bootstrap residual (follow-up).
