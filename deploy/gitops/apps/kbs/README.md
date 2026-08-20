# `apps/kbs` — Tier-0 Key Broker Service (PR-K6, §K)

Deploys the `hippius-kbs-server` binary (§D #101) as the cluster's
**first confidential workload** — a `kata-qemu-snp` pod running inside
an AMD SEV-SNP CVM. Spec of record: `ARCHITECTURE.md` §7/§8/§17;
locked topology — [issue #1 comment](https://github.com/thenervelab/hippius-compute/issues/1#issuecomment-4505904116).

## Layout

| File | Purpose |
|---|---|
| `application.yaml` | Argo CD Application — sync wave 10. |
| `Chart.yaml` / `values.yaml` | In-house Helm chart (no upstream dep). |
| `templates/configmap-kbs.yaml` | `config.toml` for the binary. |
| `templates/deployment.yaml` | `kata-qemu-snp` confidential Deployment. |
| `templates/service.yaml` | ClusterIP — internal only. |
| `templates/external-secret-vault-creds.yaml` | `VAULT_TOKEN` from Vault. |
| `templates/external-secret-signing-key.yaml` | Ed25519 response-signing seed from Vault. |
| `templates/networkpolicy.yaml` | `CiliumNetworkPolicy` — default-deny. |
| `templates/poddisruptionbudget.yaml` | `maxUnavailable: 1`. |

## Confidential pod

`runtimeClassName: kata-qemu-snp` (PR-K5) runs the pod inside an AMD
SEV-SNP CVM, pinned to the SEV-SNP node via
`nodeSelector: node-role.hippius.network/confidential-compute=true`.
The pod's launch digest **is** the attested measurement (#1 locked
topology). The container is non-root (uid 65532), read-only rootfs,
all capabilities dropped, `seccompProfile: RuntimeDefault`,
`automountServiceAccountToken: false`.

A `kata-qemu-snp` guest **guest-pulls** its image (inside the CVM) and
cannot reach k8s ClusterIP VIPs (PR-K5 "Guest-pull + DNS", confirmed
live in PR-K6) — so the pod sets `dnsPolicy: None` with public
resolvers, and the image is public (see "Image").

## MVP scope — the release path is fail-closed

The §D binary now wires the **real** AMD SEV-SNP attestation verifier
(`kbs_core::snp_real::RealSnpVerifier`) under both branches of the new
`[snp]` operator-config seam:

- `[snp]` absent ⇒ `attest::UnconfiguredChainVerifier` — every chain
  check fails with the explicit `UNCONFIGURED_CHAIN_MSG` classifier
  (`release fails closed until per-CHIP_ID VEK is mounted`).
- `[snp]` present + a readable VEK PEM ⇒ `SevChainVerifier` anchored
  to the binary-built-in AMD ARK (Milan or Genoa per
  `snp.generation`) + the matching ASK + the operator-mounted VEK.
  Turin is gated on the §D verifier widening `SUPPORTED_REPORT_VERSION`
  past v2 (Turin guests emit v3+ reports).

The chart **enables** the SNP branch by default (`snp.enabled: true`,
`snp.generation: genoa`) — set it to the SEV-SNP generation of YOUR
miner fleet (`genoa` / `turin`), and the operator stages each host's
VEK PEM into Vault at
`${kbsSecretPath}/vek::pem` for ESO to materialise as
`kbs-server-vek`. Flip `snp.enabled: false` for a deny-closed
preview / regression deploy. The production-grade per-CHIP_ID VEK
fetch from AMD KDS — refreshing automatically on TCB rotation — is the
§17 follow-up; until then the VEK is staged manually per host.

The §22 signed allowlist is now **wired**:

- a small `curlimages/curl` init container fetches the artifact from
  `allowlist.url` and drops it on a shared emptyDir at
  `/etc/kbs-allowlist/allowlist.cose` (the KBS's `[allowlist].signed_path`)
  — it does NOT pin a sha256 (#587 Phase 1A: that was redundant with the
  signature + epoch and forced a manual gitops bump after every auto-pin);
- the KBS verifies the artifact entirely itself: COSE_Sign1 EdDSA verify
  against the in-binary `allowlistRootPubkeyHex` PLUS a durable
  monotonic-epoch HWM that rejects rollback — enforced identically at
  startup and at the `/v1/admin/allowlist/reload` path. The auto-pin may
  rewrite the S3 object freely; a restart re-fetches the latest signed,
  higher-epoch artifact and boots without any gitops change.

The Vault seam is still the static-token MVP — `vault_mvp::Static
TokenVaultKv` plus `kbs_measurement_ok: |_| false` / `min_tcb:
u64::MAX`. The release pipeline therefore still fails closed at the
Vault step regardless of SNP / allowlist outcome; the SNP-attested
broker (#102) replaces both. That is the agreed sequencing.

## Configuration vs the §D binary

The K6 design brief predated the §D #101 binary; the chart is wired to
the binary's **actual** interface:

- **Vault address + CA** — the binary reads the Vault address from
  `config.toml` `[vault].address`, not a `VAULT_ADDR` env var, and the
  §D static-token client has no CA-cert option (it is never reached).
  So there is no `VAULT_ADDR` / `VAULT_CACERT_PATH` env and no
  `vault-ca` mount — the broker (#102) wires a CA-pinned client.
- **Response signing is in-process Ed25519**, not Vault transit. The
  binary needs a 32-byte seed file (`keys.signing_key_path`) — provided
  by the `kbs-signing-key` ExternalSecret. There is no
  `transit/sign/kbs-response` dependency in this build.
- **`VAULT_TOKEN`** is NOT injected (RA-KBS-L3). In broker mode the static
  token is never used for reads (each release mints a per-VM broker
  capability token), and the binary now treats it as optional there, so the
  attested KBS pod holds no resident Vault credential. It stays required
  only in the non-broker fallback build.

## Storage — `emptyDir` (interim)

The durable stores and the hash-chained audit log are on `emptyDir`
volumes, **not PVCs** — PR-K4 (the `local-path` provisioner) has not
shipped. Because the release path is fail-closed, the stores stay
empty and the durability gap is inert. **The PVC swap MUST land
together with the broker (#102)**, which lights up releases — see the
`TODO(PR-K4)` in `deployment.yaml`.

## Image — public, guest-pulled

`ghcr.io/thenervelab/hippius-kbs-server` is a **public** package, pinned
in `values.yaml` by SHA-256 digest (never a tag — §F supply-chain
discipline) and cosign-signed keyless by `.github/workflows/kbs-image.yml`.
On a `pull_request` the workflow pushes a `sha-<commit>` image so the
chart can be pinned and live-tested before merge.

A `kata-qemu-snp` confidential pod **guest-pulls** its image — the image
is fetched *inside* the SEV-SNP CVM by the in-guest image service, which
**cannot** use a Kubernetes `imagePullSecret`. So the image must be
pullable without a credential — i.e. public. This is sound: the image
is a release-build Rust binary on `distroless/cc` with **no secret baked
in** — every secret (Vault token, signing seed, config) arrives at
runtime via Vault / a ConfigMap. Security rests on SEV-SNP attestation
+ the §22 signature + Vault, never on image privacy (Kerckhoffs). The
cosign keyless attestation is the image's integrity anchor:

```sh
cosign verify ghcr.io/thenervelab/hippius-kbs-server@<digest> \
  --certificate-identity-regexp='https://github.com/thenervelab/hippius-compute' \
  --certificate-oidc-issuer='https://token.actions.githubusercontent.com'
```

Cluster convention: **confidential (`kata-qemu-snp`) pods → public
image + cosign; non-confidential (runc) pods → private GHCR + an
`ExternalSecret` pull credential** — see `deploy/gitops/README.md`.

## What the KBS measurement does **not** cover (P3)

The KBS's SEV-SNP launch measurement is what every downstream trust
decision rests on — the broker's `kbsMeasurementAllowlist` is the only
runtime gate on the KBS's own identity, and the KBS is what releases
every tenant disk KEK. **That measurement binds the CVM shape, not the
code inside it.**

What is measured: OVMF (`/opt/kata/share/ovmf/AMDSEV.fd`), the guest
kernel, the initrd, the kernel cmdline — the Kata `qemu-snp` VM. What is
**not** measured: the container image. A `kata-qemu-snp` pod
*guest-pulls* its image at runtime, from a reference the (untrusted)
host hands to the guest over vsock. Two different `kbs-server` binaries
in the same CVM shape therefore produce the **same** launch measurement,
and the broker cannot tell them apart. Neither can the tenant guests: the
KBS response-signing seed comes from Vault at runtime, so a substituted
binary signs with the same `kid` the §22 allowlist pins.

Consequence: anyone who can change what the pod runs — a gitops digest
edit, a `kubectl set image`, a compromised Argo CD — can run a different
KBS inside a CVM that still attests correctly. This is the highest-value
code substitution in the system.

Nothing in the current codebase closes that. What exists is a
*deployment-path* chain, and it is worth being exact about its limits:

| control | what it proves | what it does not |
|---|---|---|
| digest pin in `values.yaml` | the chart names one content-addressed image | nothing about the pod that is actually running |
| `verify-gitops-signatures.yml` (repo-wide) | the pinned digest was cosign-signed by *some* `*-image.yml` build of this repo, on *any* ref | which source; a PR build of an unreviewed branch qualifies |
| `image.provenance` + `verify_image_provenance.py` (P3 — every first-party gitops image, not just this chart) | the pinned digest was built by an exactly-named workflow **ref** from an exactly-named **commit**, and an unmerged-source build must be acknowledged in the diff | that the cluster pulled that digest; nothing at runtime |
| broker `kbsMeasurementAllowlist` | the KBS is a CVM of the expected *shape*, on real AMD silicon | **not** which binary is inside it |

`report.host_data` — the one SNP field that could carry an image binding
— is not populated and is not verified anywhere: `kbs_core::snp::
VerifiedReport` does not even parse it.

### The real closure: initdata → `HOST_DATA`

This is **not** blocked on a runtime feature we do not control. Verified
on the live confidential node (Kata 3.31.0):

- `configuration-qemu-snp.toml` ships `enable_annotations = [… ,
  "cc_init_data"]`, i.e. the `io.katacontainers.config.hypervisor.
  cc_init_data` annotation is accepted;
- `containerd-shim-kata-v2` carries `setupInitdata` /
  `prepareInitdataImage` / `buildInitdataDevice` / `InitdataDigest` —
  the shim hashes the initdata and passes it as the `sev-snp-guest`
  object's `host-data`, so it lands in **every** SNP report;
- the confidential guest rootfs (`kata-containers-confidential.img`)
  carries the agent's `initdata.rs` + `policy.rego` + `agent_policy`
  handling, so an initdata-carried agent policy is enforced *inside* the
  CVM — including on the `PullImage` request that guest-pull issues.

So the chain is available end to end: pin the allowed image digest in an
agent policy → ship it as initdata → its digest is measured into
`HOST_DATA` → the broker verifies `host_data` alongside `measurement`.
That would make "which binary is in the KBS CVM" an attested fact rather
than a deployment claim.

It is not done here because it cannot be done without redeploying and
**restarting** the KBS (new `HOST_DATA` ⇒ new pin at the broker ⇒ a
release outage window), and a live tenant depends on this KBS. Doing it
needs, in order: (1) an agent policy pinning the image digest; (2) the
`cc_init_data` annotation on the Deployment; (3) `host_data` plumbed
through `VerifiedReport` and gated in the broker; (4) capture the new
`HOST_DATA` + measurement and pin both, in lockstep with the rollout.
Steps (1)–(3) are ordinary work in this repo; step (4) is the ceremony.

## Operator setup — Vault secrets

`secret/hippius-compute/kbs` (KV-v2) must exist in the Tier-0 Vault
**before** the app syncs — the values are never in Git. External
Secrets Operator reads it with the `hippius-vault` ClusterSecretStore's
*own* Vault credential (provisioned by PR-K11) — no extra Vault policy
is needed for ESO. (The image is public — there is no GHCR pull
credential to provision.)

- **`secret/hippius-compute/kbs`** — the KBS's own secrets:
  - `vault-token` — the KBS's *own* least-privilege Vault token. The
    §D-MVP binary requires it at boot but never calls Vault (the
    release path is fail-closed); the broker (#102) makes it
    load-bearing.
  - `signing-key` — the **base64**-encoded 32-byte Ed25519
    response-signing seed.

- **`secret/hippius-compute/kbs/vek`** (key `pem`) — AMD-signed
  Versioned Chip Endorsement Key for the SEV-SNP host whose guest
  attests to this KBS. Public certificate, not confidential — kept in
  Vault for ESO's uniform delivery shape. The KBS-side `[snp]` chain
  anchors on the matching built-in ARK + ASK (see `snp.generation` in
  `values.yaml`) and trusts a guest report iff the chain ARK→ASK→VEK
  → report signature path verifies. The per-CHIP_ID VEK is per-host
  + per-TCB; re-stage on TCB rotation.

Provisioned as:

```sh
# The KBS's OWN token policy — lets the KBS read per-VM release secrets
# stored UNDER secret/hippius-compute/kbs/... once the broker (#102)
# lights up the release path. This policy is for the KBS token only;
# it is NOT what ESO uses to read the path below.
vault policy write hippius-compute-kbs-read - <<'EOF'
path "secret/data/hippius-compute/kbs/*"     { capabilities = ["read"] }
path "secret/metadata/hippius-compute/kbs/*" { capabilities = ["read", "list"] }
EOF
KBS_TOKEN=$(vault token create -policy=hippius-compute-kbs-read \
  -period=768h -orphan -display-name=kbs-$(hostname) \
  -format=json | jq -r '.auth.client_token')
SEED=$(openssl rand 32 | base64)          # 32-byte Ed25519 seed
vault kv put secret/hippius-compute/kbs \
  vault-token="$KBS_TOKEN" signing-key="$SEED"
unset KBS_TOKEN SEED

# Per-host VEK PEM — fetched from AMD KDS for the chip whose guests
# attest. Public; kept in Vault for ESO's uniform delivery shape.
# `virtee/snphost` writes the fetched cert as `vcek.pem`:
#   sudo snphost fetch vek pem /tmp/vek   # → /tmp/vek/vcek.pem
# then those PEM bytes go into Vault as the `pem` property. End-to-end
# the wiring is greppable:
#   Vault property name  = `pem`
#   ESO `secretKey`      = `vek.pem`  (key under the materialised Secret)
#   `items.path` mount   = `vek.pem`  (filename inside the volume)
#   in-pod absolute path = `/etc/kbs-vek/vek.pem`
# `external-secret-vek.yaml` maps `property: pem` → `secretKey: vek.pem`
# so the Vault-side name (`pem`) and the in-cluster name (`vek.pem`) line
# up byte-for-byte with what the binary's `[snp].vek_pem_path` reads.
vault kv put secret/hippius-compute/kbs/vek \
  pem=@/tmp/vek/vcek.pem
```

The signing seed here is an MVP key — the real response-signing key is
established by a ceremony alongside the broker (#102).

The `kbs` namespace carries the `hippius.network/vault-secrets: enabled`
label (set by the Application's `managedNamespaceMetadata`) so the
`hippius-vault` ClusterSecretStore admits these ExternalSecrets.

## Networking

`CiliumNetworkPolicy`, default-deny. **Ingress**: the node's kubelet
(health probes) and the `edge-gateway` pods only — no `world` ingress.
**Egress**: public DNS; `world:443` — the kata guest-pull of the public
image (`ghcr.io` + GitHub's blob CDN) and AMD KDS; and Vault
(`vault.egressCidr:vault.egressPort`). The `world:443` rule is
deliberately broad — an
external-registry guest-pull cannot be served by a reliable `toFQDNs`
set; the §K networking follow-up mirrors the image to an in-cluster
registry to drop it. The §D binary itself makes no outbound traffic
(the release path is fail-closed).

## Admin listener authentication (mTLS)

The admin listener on `:8001` serves `register-vm`, `activate`,
`seed-boot-counter`, `arm-boot-counter-resync`,
`reset-volume-stamp-suppression` and `allowlist/reload` — all of them
mutate the state that decides which host may unlock a tenant disk, and
none carries a per-request credential. mTLS against a **pinned client
CA** is its authentication.

It also serves one READ route, `GET /v1/admin/volume-stamp` (the
suppressed-confirm arming report — see `config.maxUnconfirmedReleases`
in `values.yaml`). That route is **stricter** than its siblings: it
answers only when the request carries a client certificate the listener
verified, so it returns `403 admin-client-cert-required` for as long as
`requireMtls` is off. That is deliberate — it discloses per-tenant
operational state (which VMs exist, and which are one release away from
being refused once the gate is armed), and issuing the admin PKI is a
prerequisite of the arming cutover rather than a casualty of it.

**It is currently OFF** (`admin.requireMtls: false`, `admin.mtls.secretName: ""`)
and the pod says so at every start: `the lifecycle admin API on 0.0.0.0:8001
is served UNAUTHENTICATED`. A CiliumNetworkPolicy label match is the only
control.

Turning it on is an ordered operator procedure, not a values flip — see
**`docs/operator/kbs-admin-mtls-cutover-runbook.md`**. The two facts that
dictate the order:

- **Mounting `admin.mtls.secretName` IS the cutover.** `AdminListenerMode::
  decide` enforces mTLS whenever the material is present, *regardless* of
  `requireMtls`; that flag only covers the ABSENT case, where `true` means
  "refuse to bind" and `false` means "plaintext + warning". So there is no
  rehearsal state on this side, and vali must be able to present a client
  cert before the Secret is mounted.
- **`requireMtls: true` goes LAST.** It changes no behaviour while material
  is present — it removes the plaintext fallback so a later mount failure
  closes the listener instead of reopening it unauthenticated. The chart
  refuses to render `requireMtls: true` with no `mtls.secretName`, because
  that combination leaves the admin API unbound (no launches, no migrations).

The material comes from Vault via ESO (`external-secret-admin-tls.yaml`,
`admin.mtls.vaultPath` → `cert` / `key` / `ca`), mirroring how the Edge's
mTLS material is provisioned. The CA's **private key never enters the
cluster** — which is why this does not use a cert-manager `CA` Issuer:
that would keep the key that mints admin identities in a Secret inside the
cluster it is protecting.

⚠️ The cutover requires a KBS restart, and the state/audit/evidence dirs are
`emptyDir` inside the CVM. Read the restart-cost table in the runbook and
have the boot-counter recovery ready **before** you start.

## A config change here is INERT until the pod restarts

`Config::load` runs exactly once, at process start
(`binaries/kbs-server/src/main.rs`) — there is no SIGHUP and no reload
route. The Deployment carries **no `checksum/config` annotation**, on
purpose: `state` / `audit` / `evidence` are `emptyDir`s inside the CVM,
so rolling the pod destroys boot counters, volume stamps, the
hash-chained audit log and every evidence bundle. Auto-rolling on each
config edit would make routine chart hygiene destructive.

The cost is that **editing this chart does not change what the KBS is
doing.** The ConfigMap re-renders, ArgoCD reports `Synced` + `Healthy`,
and the running process keeps its old value for as long as the pod
lives. This is not theoretical: on 2026-08-13 `maxUnconfirmedReleases`
was raised `0 → 3` (arming the suppressed-confirm anti-rollback gate),
merged and synced — and the 152-minute-old process was still reporting
`gate_armed: false`. Believing the ConfigMap would have recorded a
security gate as ARMED while it was not.

So:

- **Never take the rendered ConfigMap as evidence that a KBS setting is
  in force.** Ask the process: `GET /v1/admin/volume-stamp` reports
  `configured_bound` / `gate_armed`, and `GET /v1/admin/config` reports
  the whole security posture (`require_wrapped_kek`, the admin listener
  mode `AdminListenerMode::decide` actually chose, the launch-policy
  floor, whether the evidence + live-attestation sinks are wired, the
  allowlist root fingerprint). Both are read-only, both need a verified
  client certificate.
- **A config change is applied by a deliberate restart**, taken with the
  restart-cost table in
  `docs/operator/kbs-admin-mtls-cutover-runbook.md` in front of you.
- **Drift is watched.** `apps.synthetic.checks.check_kbs_config_drift`
  (vali light tier, ~15 min) diffs the vali chart's
  `syntheticMonitor.light.kbsExpectedPosture` — CI-pinned to THIS
  chart's rendered `config.toml` by
  `binaries/kbs-server/tests/chart_deploy_safety.rs` — against what the
  running process reports, and fires `KbsRunningConfigDrift` (critical)
  when they diverge. **Changing a posture key here means changing it in
  the vali chart too**, or CI fails; that is the mechanism, not an
  inconvenience.

## Follow-ups

- **#102** — SNP-attested Vault broker: replaces the deny-closed
  verifier + static-token client; lights up the release path. The
  `emptyDir → PVC` swap lands with it.
- **PR-K4** — `local-path` provisioner → the state + audit PVCs.
- **PR-K14** — `kube-prometheus-stack`: a `/metrics` endpoint on the
  binary + a `ServiceMonitor` (deferred — the §D binary exposes no
  metrics endpoint yet).
