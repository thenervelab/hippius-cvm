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

## Audit log refused at start

The release and admin audit chains (`/var/lib/kbs/audit/audit.log` and
`…/audit/admin/admin.log`, each with its `*.head.sha256`) live on the `audit`
emptyDir, which **survives a container restart inside the same pod** (OOM
kill, liveness restart). The KBS opens them with journal semantics
(`kbs-core/src/audit_journal.rs`):

- **A crash mid-append never stops the KBS.** A torn trailing record (a
  partial last line, a last line whose hash does not verify) is truncated at
  open and the KBS starts; a head one record behind the log, or one ahead
  naming the torn record, is rewritten to the log's tail. The pod log
  says `ERROR kbs-core::audit: TORN TRAILING RECORD truncated at open: … seq=…
  offset=… len=… sha256=…`, and an `audit-truncated` record is chained at that
  seq. vali ingests it as a `KbsAuditAnomaly` of kind `torn-tail-truncated`
  (a WARNING, not a break — `manage.py vali_kbs_audit --breaks` lists it with
  the breaks). Nothing to do
  beyond reading the log line; a whole last record missing only its newline
  is kept, not dropped.
- **Only a state no crash produces refuses.** A chain break in the middle
  (a bad record with records after it, a verified record whose `prev_hash`
  or `seq` does not follow), a rewritten earlier record, a seq gap, a
  self-consistent record that does not chain even at the tail, a head that
  names no record of the log (more than one torn append missing, or a
  rewritten tail), a missing/emptied log under a live head, a malformed head.

A refusal is one line, and the container exits non-zero (CrashLoopBackOff):

```
kbs-server: FATAL: wiring: audit sink: vault: audit: REFUSING TO START — audit.log in
/var/lib/kbs/audit is inconsistent in a way no crash produces: <reason>. Nothing
was modified. Preserve the directory as evidence and follow
deploy/gitops/apps/kbs/README.md § "Audit log refused at start"; never hand-edit the log.
```

(`wiring: admin audit sink: vault: admin-audit: REFUSING TO START — admin.log in
/var/lib/kbs/audit/admin …` for the admin chain.)
The whole fleet has lost key release from that moment; the procedure is:

1. **Preserve the evidence — BEFORE touching the pod.** The directory is
   inside the CVM: the host cannot read it, and the refusing container never
   runs long enough to `kubectl exec`. What survives outside is:
   - the refusal and every earlier line: `kubectl -n kbs logs deploy/kbs-server
     -c kbs-server --previous > kbs-refusal-$(date +%s).log` (and without
     `--previous`), plus `kubectl -n kbs describe pod -l app.kubernetes.io/name=kbs-server`;
   - vali's verified copy of both chains up to its last poll, which the refusal
     does not touch: `manage.py vali_kbs_audit --log release --json --limit
     100000000`, the same with `--log admin`, and `--breaks --json --limit
     100000000`, into files kept with the log above (`--limit` defaults to 200
     — without it you keep only the oldest 200 records).
   The refusal modified nothing, so as long as the POD is not deleted the
   directory is intact for whoever investigates.
2. **Decide it is tamper, not a KBS bug** (the reason names the seq; compare it
   with vali's copy). Either way the only way back to service is step 3.
3. **Delete the pod.** A new pod gets a FRESH emptyDir: this is a KBS restart
   with every consequence in `docs/operator/kbs-admin-mtls-cutover-runbook.md`
   ("What the KBS restart … costs") — all VM state, boot counters and both
   audit chains are gone. Run the full recovery ceremony at once: read each
   live VM's boot counter off its miner, then `vali_kbs_recover` (SEED the
   counter, THEN register — the command enforces the order) and
   `vali_kbs_recover --reinstall-tombstones` for the dead VMs the restart forgot.
   vali opens a new audit epoch on the new genesis.

An open that fails with an I/O error (`… truncate: …`, `… terminator: …`,
`… head …: No space left on device`) instead of `REFUSING TO START` is not a
refusal: the recovery could not write (the emptyDir is full or failing). It is
retried at every container restart and loses nothing; if it persists, preserve
the evidence (step 1) and delete the pod (step 3).

**Never hand-edit the log or the head** to get the old pod to start: an edit
that the walker accepts destroys the evidence and launders the break into a
chain vali will verify; one it does not accept just moves the refusal.

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

## Never roll the KBS image below stamp protocol v2 once v2 guests exist

Stamp protocol v2 (#1320) binds a golden guest's in-volume stamp to a
TIMELINE. Only a guest RUNNING AN R6 INITRAMFS attests v2 (a new launch
from the R6 golden bake, or an existing VM deliberately swapped onto an R6
initrd). **A VM whose guest runs a pre-R6 initramfs attests v1, stays on the
zero timeline, and releases exactly as before, forever**: its protocol is
read only from the SNP-signed REPORT_DATA (`attested_guest_stamp_protocol`),
gate 5c' moves only v2 guests, a rollback arm needs a v2 guest, and a KBS
restart resets every timeline to zero. The byte-identical v1 KAT
(`a_v1_guest_release_is_byte_identical_to_the_pre_v2_kat`) pins that.

**After its first v2 release, a VM running an R6 guest is on a non-zero
timeline and is v2-only**: that release moves it to a fresh timeline (at
`E = 0`, including after every KBS restart), and from then on

- the KBS refuses any v1 release of it (gate 5a-t), and
- the guest refuses v1 too: `hippius-guest-release` never retries a denied
  v2 release as v1 (a denial is a denial: every KBS refusal is the same
  403, so a miner could forge one and, after a store wipe, get a v1 adopt
  of an old zero-timeline disk), and the golden initramfs refuses an
  M0/M1 release that carried no timeline transition.

A KBS image from before v2 refuses every v2-attested release with a 403, so
the boot simply fails. M2 (`customer`) is unchanged: it attests v1 only
(its stamp is the guardian's).

Consequences:

- **Never roll the KBS below v2 once the R6 bake is live.** A pre-v2 KBS
  boots none of those VMs until it is rolled forward again, and it also
  ignores the timelines file, which re-opens B1 for rolled-back VMs. A
  rollback KBS image that predates v2 (e.g. the ceremony-2 rollback image)
  is only a valid target BEFORE the R6 golden bake is blessed. After that
  it is not a rollback target: roll forward.
- **Deploy order is vali → KBS → bake.** vali first (it must read what a v2
  KBS emits: the v2 rollback wire, full-length audit reasons), then the
  KBS at v2, and only then bless the R6 golden bake. A v2 guest booted
  against a pre-v2 KBS does not boot.
- **Never remove a live v1 VM's measurement.** Measurements are pinned PER
  VM (every launch auto-pins its own), so there is no fleet-wide "v1
  measurement" to retire, and removing a running pre-R6 VM's pin bricks it.
  A VM's old pin becomes dead weight only AFTER that same VM has been
  swapped onto an R6 initrd (and released as v2); only then may that one
  pin be dropped.
- **Legacy (non-golden) guests running an R6 guest that never confirm pay a
  durable write per release.** They attest v2 but never confirm a stamp, so they stay at
  `E = 0` and every release is a gate 5c' fresh-timeline move: the KBS
  rewrites and fsyncs its timelines file (tmp + rename + directory fsync,
  a whole-file rewrite under the stamp-store locks) before replying. The
  move buys such a VM nothing (it has no in-volume stamp), and the VM is
  v2-only from its first release. Cheap at today's fleet size and release
  rate; watch it if release volume grows.

## KBS roll ceremony checklist

Every KBS roll is the full restart ceremony (`emptyDir` — see above and the
restart-cost table in `docs/operator/kbs-admin-mtls-cutover-runbook.md`).
Before the roll, on top of that runbook:

- [ ] **#1326: the admin listener admits only URI-SAN `spiffe://` client
      leaves.** Any admin client with a DNS/IP/email SAN or no SAN is dropped.
      Check every admin client leaf before the roll
      (`openssl x509 -noout -ext subjectAltName -in <leaf>.pem` must print only
      `URI:spiffe://…`).
- [ ] **Stamp protocol v2: the target image is at v2 or later** whenever
      any v2 guest (the R6 golden bake) has booted. A pre-v2 image —
      including the ceremony-2 rollback image — is only a valid target
      BEFORE the R6 bake is blessed; the deploy order is vali → KBS → bake
      (see "Never roll the KBS image below stamp protocol v2" above).
- [ ] Each live VM's boot counter read off its miner, ready for
      `vali_kbs_recover` (SEED, then register), plus
      `vali_kbs_recover --reinstall-tombstones`.
- [ ] vali's audit ingest caught up: for each log, `KbsAuditCursor.last_seq`
      equals the `head_seq` the KBS reports (`GET /v1/admin/audit?log=<log>&limit=1`)
      — whatever the old life appended after vali's last read is gone with the
      old emptyDir. Review `manage.py vali_kbs_audit --breaks --limit 100000000`:
      `torn-tail-truncated` rows are crashes (expected after an OOM kill);
      anything else is investigated BEFORE the roll destroys the chain.

## Follow-ups

- **#102** — SNP-attested Vault broker: replaces the deny-closed
  verifier + static-token client; lights up the release path. The
  `emptyDir → PVC` swap lands with it.
- **PR-K4** — `local-path` provisioner → the state + audit PVCs.
- **PR-K14** — `kube-prometheus-stack`: a `/metrics` endpoint on the
  binary + a `ServiceMonitor` (deferred — the §D binary exposes no
  metrics endpoint yet).
