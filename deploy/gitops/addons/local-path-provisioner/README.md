# `addons/local-path-provisioner` — default StorageClass

PR-K4, §K (issue #54). Installs [Rancher local-path-provisioner][lpp]
and its `StorageClass` named `local-path` — **the cluster's default
StorageClass**. A `PersistentVolumeClaim` with no explicit
`storageClassName` binds here; the provisioner backs each PV with a
directory on the node's RAID1 NVMe data volume.

It unblocks every stateful workload — PR-K7 (vali Postgres PVC), KBS
state stores, the audit hash-chain, sentinel state.

## Why a vendored chart (not a remote dependency)

Every other addon pins a *remote* upstream Helm chart (`cilium`,
`cert-manager`, …). Rancher publishes **no official Helm repository**
for local-path-provisioner — the chart only exists as source in the
GitHub repo, and the one OCI chart (SUSE Application Collection) needs
authentication, so it is not GitOps-viable.

The chart is therefore **vendored** under `charts/local-path-provisioner/`
— committed, content-pinned via Git. `Chart.yaml` declares it as a
`file://` dependency and a `Chart.lock` pins it; Argo CD's repo-server
runs `helm dependency build` at render time — the same step as every
other addon — except here it repackages the *vendored* directory rather
than fetching from a remote repo. The upstream commit + tag pin and the
re-vendoring procedure live in [`PROVENANCE.md`](PROVENANCE.md).

> The addon `charts/` git-ignore rule (which treats fetched charts as
> build artifacts) is overridden in `.gitignore` for this addon — here
> `charts/local-path-provisioner/` is **source**. Only the repackaged
> `charts/*.tgz` stays ignored.

## What is deployed

| Resource | Purpose |
| --- | --- |
| `Deployment` local-path-provisioner | the provisioner controller (namespace `local-path-storage`) |
| `StorageClass/local-path` | the cluster-default StorageClass |
| `ConfigMap/local-path-config` | node path map + helper-pod setup/teardown scripts |
| ServiceAccount + RBAC | the controller's API access |
| `PodDisruptionBudget` | drain safety for the single-replica controller |

## StorageClass `local-path` — the invariants

| Setting | Value | Why |
| --- | --- | --- |
| `is-default-class` | `true` | THE default — un-classed PVCs bind here |
| `reclaimPolicy` | `Retain` | a deleted PVC leaves its data on disk; never auto-wiped |
| `volumeBindingMode` | `WaitForFirstConsumer` | the PV is provisioned only once a consuming Pod is scheduled, so it lands on the right node |
| `provisioner` | `cluster.local/hippius-local-path` | explicit, stable — PVs record it |
| `allowVolumeExpansion` | `true` | upstream chart default |

## Data path

PVs are backed by directories under
**`/var/lib/hippius-data/local-path-provisioner/`**.
`/var/lib/hippius-data` is the RAID1 NVMe data volume mounted by PR-K2
Ansible (`data_mount_path`). The `local-path-provisioner/` subdirectory
keeps this provisioner's volumes from overlapping other future
consumers of the same mount.

`nodePathMap` (`values.yaml`) is an explicit per-node **allow-list** —
deliberately not the chart's `DEFAULT_PATH_FOR_NON_LISTED_NODES`
catch-all. Only nodes proven to carry the RAID1 data mount are listed.
A PVC consumer that lands on an unlisted node makes the provisioner
**refuse** — the PVC stays `Pending` (fail loud) — rather than silently
`mkdir`-ing the path on that node's OS disk. The shipped value is a
placeholder: replace it with YOUR node names (`kubectl get nodes`), and
on scale-out add each new SEV-SNP node once its data mount is
confirmed; never a general worker that lacks `/var/lib/hippius-data`.

> **Anti-pattern #1 (no direct `hostPath` in pods).** Backing PVs with
> host directories is the provisioner's *internal mechanism* — it is
> precisely what lets workloads avoid `hostPath`. Consumer pods only ever
> reference a `PersistentVolumeClaim`; none of them carry a `hostPath`
> volume. That is the rule satisfied, not broken.

## Scheduling

The provisioner controller is pinned to the confidential-compute node
pool (`nodeSelector: node-role.hippius.network/confidential-compute=true`)
— the single-node MVP. Helper pods (the short-lived `mkdir`/`rm` pods)
are **not** affected by that selector: they always run on the node a PVC
is being provisioned for — which is why the `nodePathMap` allow-list
(above) is the real guard on *where* volumes may land. On scale-out,
update both the controller `nodeSelector` and `nodePathMap` deliberately
as nodes join.

## Live validation (PR-K4)

```sh
export KUBECONFIG=~/.config/hippius/kubeconfig.yaml

kubectl get application hippius-compute-local-path-provisioner -n argocd
kubectl get pods -n local-path-storage
kubectl get storageclass            # local-path (default)

# dynamic provisioning: a PVC + a Pod that writes to it
kubectl apply -f /tmp/test-pvc-local-path.yaml
kubectl wait --for=condition=Ready pod/test-pvc-consumer --timeout=60s
kubectl exec test-pvc-consumer -- cat /data/test.txt   # → hello from local-path
```

[lpp]: https://github.com/rancher/local-path-provisioner
