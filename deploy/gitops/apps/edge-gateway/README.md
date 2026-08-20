# `apps/edge-gateway` — Hippius Edge gateway

PR-K8, §K ([#54](https://github.com/thenervelab/hippius-compute/issues/54)).
The **opaque relay** between the untrusted miner NetBird mesh and the
internal control plane (`ARCHITECTURE.md` §5 / §9 / §10). Deployed as
an HA pair of plain runc pods on the k3s cluster.

## Layout

A plain Helm chart — the Edge is a first-party binary, so there is no
upstream chart, every manifest is local:

```
apps/edge-gateway/
  application.yaml              Argo CD Application (sync wave 11)
  Chart.yaml / values.yaml
  templates/
    deployment.yaml             the HA pair (replicaCount: 2)
    service.yaml                ClusterIP — edge-api (9465)
    external-secret.yaml        mTLS CA + cert + key from Vault
    poddisruptionbudget.yaml    maxUnavailable: 1
    networkpolicy.yaml          CiliumNetworkPolicy — default-deny
```

## Sub-decision — runc pods, not KubeVirt VMs

§54 left PR-K8 to choose between KubeVirt VMs and runc pods. **Decision:
runc pods.**

- The Edge is **not confidential** (#1 locked topology: *"Opaque relay,
  pas besoin d'être confidential"*) — it never sees plaintext secrets,
  so it gains nothing from VM-level isolation. Its security properties
  live in the binary: the typestate-locked wire gate
  (`RawEnvelope → validate → ValidatedEnvelope`), mTLS termination, and
  the hash-chained audit log — none of which a VM wrapper strengthens.
- runc pods are far simpler ops: no KubeVirt operator to install and
  run, no Kata/KubeVirt node-coexistence concerns, native k8s HA.
- KubeVirt remains a clean follow-up **if** a future need for
  kernel-level isolation appears — nothing here forecloses it.

## ⚠️ Scope — the Edge does not yet accept miner traffic

PR-K8 found that the `hippius-edge-gateway` binary, although §H
(PR-H1..H6) is "closed", was **not a long-running service**: `main`
booted every subsystem then ran a fixed mock-accept sweep and exited.
PR-K8 adds the minimal `main.rs` wiring to keep the process up — this
is **strictly wiring of primitives PR-H1 → PR-H6 already shipped, no
new §H logic** (see the commit `serverify edge-gateway main`).

What this deployment ships: a running, mTLS-secured, audit-logged Edge
that serves its read-only telemetry API and runs its HA / CRL
machinery, and **responds to health probes**. What it does **not** yet
do: accept production miner traffic. The real miner-facing TCP accept
loop and the non-stub `forward` egress were never implemented (the
PR-H5 comment *"swaps this for a real TcpListener"* never landed — H5
became the HA peer link). They are tracked as **§H phase 2 / PR-H7**
([follow-up issue](https://github.com/thenervelab/hippius-compute/issues/54)).

## HA model

HA is provided at the **Kubernetes layer**: `replicaCount: 2`, Service
load-balancing, a PodDisruptionBudget, soft pod anti-affinity, and
ReplicaSet self-healing. The binary's own `EDGE_PEER_ENDPOINT` peer
link — the active/active health-beat channel from the bare-metal
2-VM design — is **left unset** (single-instance mode per pod): wiring
it needs per-pod peer identity (a StatefulSet + a peer-resolution
step), which is new logic beyond PR-K8's scope. Consequence: the HA
peer link (9443) and the Prometheus `/metrics` endpoint (9464) do not
bind, so the Service publishes only the telemetry API (9465). Wiring
the peer link is part of the §H phase 2 follow-up.

## Networking — ClusterIP, NetBird-only

`service.yaml` is `type: ClusterIP` — **no MetalLB LoadBalancer**.
Per #1 locked, the MVP is NetBird-only: miners join the NetBird mesh,
they do not reach a public IP. The Edge's only consumers today are
in-cluster (the Sentinel + the Validator read the telemetry API). A
LoadBalancer with no miner-facing relay listener behind it would be a
dead port — so the MetalLB pool allocation, the public
`:443` relay port, and the `world` ingress rule all ship together in
PR-H7, in lockstep with the relay listener.

`networkpolicy.yaml` is a default-deny `CiliumNetworkPolicy`: ingress
to `9465` only, from the host (kubelet probes) and the
`sentinel` / `vali` / same namespaces — **no `world` entity**. Egress
is DNS-only (the Edge makes no outbound application traffic yet).

## Image

`ghcr.io/thenervelab/hippius-edge-gateway`, built by
[`.github/workflows/edge-image.yml`](../../../../.github/workflows/edge-image.yml)
from [`binaries/edge-gateway/Dockerfile`](../../../../binaries/edge-gateway/Dockerfile)
— multi-stage, distroless runtime, non-root (uid 65532), base layers
digest-pinned. `values.yaml` pins the deployed image by **SHA-256
digest**, never a tag (§F supply-chain discipline). The pod runs with
`readOnlyRootFilesystem`, all capabilities dropped, no privilege
escalation, `seccompProfile: RuntimeDefault`. No `hostPath`, no
`NodePort`, no privileged container — none are needed.

## Operator setup — Vault secrets

Two secrets are **operator-provisioned into Vault, never in Git** (#1
anti-pattern 4). Each is materialised into the `edge-gateway` namespace
by an `ExternalSecret` via the `hippius-vault` ClusterSecretStore
(PR-K11). The `hippius-compute-eso-read` Vault policy already covers
`secret/data/hippius-compute/*`, so no policy change is needed.

### 1. GHCR image-pull credential

The Edge image is in the **private** `ghcr.io/thenervelab` registry.
Create a GitHub PAT with **`read:packages` only** (least privilege;
1-year expiry, rotate yearly) and store it:

```
vault kv put secret/hippius-compute/ghcr \
  username='<github-username>' \
  pull-token='<the-read:packages-PAT>'
```

`external-secret-regcred.yaml` renders this into the
`ghcr-pull-secret` dockerconfigjson Secret; `deployment.yaml`
references it via `imagePullSecrets`. This `hippius-compute/ghcr` path
is fleet-wide — KBS, Sentinel, and every future private image reuse
the same credential.

### 2. mTLS material

`external-secret.yaml` pulls the Edge CA + cert + key from the KV path
`hippius-compute/edge-gateway/mtls` (properties `ca` / `cert` / `key`)
into the `edge-gateway-mtls` Secret. Until the dedicated
`hippius-compute` CA lands (PR-K13), the operator seeds a bootstrap
CA + Edge cert/key:

```
vault kv put secret/hippius-compute/edge-gateway/mtls \
  ca=@ca.pem cert=@cert.pem key=@key.pem
```

The Edge cert SHOULD carry `edge-ha-peer.hippius.internal` as a SAN
(the fixed peer-link SNI) so PR-H7 can enable the HA peer link without
re-minting. PR-K13 replaces the bootstrap material with the real CA.
