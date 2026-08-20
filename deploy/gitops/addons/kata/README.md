# `addons/kata` — Kata Containers confidential runtime

PR-K5, §K ([#54](https://github.com/thenervelab/hippius-compute/issues/54)).
The **first confidential runtime** on the cluster — installs Kata
Containers and the `kata-qemu-snp` RuntimeClass, the prerequisite for
every §23 confidential pod (the KBS in PR-K6, the Audit-VM agent).

A pod with `runtimeClassName: kata-qemu-snp` boots inside a lightweight
QEMU VM whose memory is **AMD SEV-SNP**-encrypted and attestable —
`/dev/sev-guest` is present inside the guest. That is the §11/§20/§21
trust boundary the rest of the design rests on.

## Layout

Standard addon wrapper chart (see `../README.md`):

```
addons/kata/
  Chart.yaml                wrapper — pins the upstream kata-deploy chart
  Chart.lock                resolved dependency (committed)
  values.yaml               values for the kata-deploy subchart
  templates/runtimeclass.yaml   the hippius-owned RuntimeClasses
  application.yaml          the Argo CD Application (sync wave 5)
```

## Upstream chart + SEV-SNP compatibility

| | |
|---|---|
| Chart | `kata-deploy`, pinned **`3.31.0`** |
| Source | `oci://ghcr.io/kata-containers/kata-deploy-charts` (OCI artifact) |
| Released | 2026-05-19 — current Kata stable |

Kata 3.31.0 ships the `qemu-snp` shim and its `kata-qemu-snp` containerd
handler; AMD SEV-SNP has been a CI-gated, required configuration across
the 3.2x/3.3x line. The chart version tracks the Kata version.

`kata-deploy` is a node-level **installer**: a DaemonSet drops the Kata
binaries (its own QEMU / OVMF / guest kernel — the guest stack is
self-contained, no host QEMU dependency) onto each confidential node and
registers the kata runtime handlers with containerd.

## k3s

`values.yaml` sets `k8sDistribution: k3s`. The cluster runs **k3s**
(verified live: `k3s.service` active on the control-plane node, containerd
config at `/var/lib/rancher/k3s/agent/etc/containerd/config.toml`) —
**not** the vanilla-k8s path. A wrong distro setting silently breaks
everything: the kata handlers never reach containerd and every kata pod
fails to start. This is the single most load-bearing value here.

> **Discovery — the locked-topology notes say "RKE2", the live cluster
> is k3s.** PR-K5 found this when kata-deploy failed against the RKE2
> containerd path. The `§K` tracking should be reconciled; flagged in
> the PR description (memory / locked-decisions are read-only here).

## RuntimeClasses

`templates/runtimeclass.yaml` defines two — owned here (not by the
kata-deploy chart, whose RuntimeClass objects are disabled via
`runtimeClasses.enabled: false`) so they carry the fleet labels and the
node pinning:

- **`kata-qemu-snp`** — the confidential runtime. Production §23 pods.
- **`kata-qemu`** — a non-confidential debug sibling: same Kata VM
  isolation, plain QEMU, no SEV-SNP. Kept to isolate "the kata pod
  plumbing is broken" from "SNP attestation is broken" when triaging.

Both pin `scheduling.nodeSelector:
node-role.hippius.network/confidential-compute: "true"` — kata-deploy
installs the runtime only on confidential-compute nodes, so a kata pod
scheduled anywhere else would fail. Both declare a `podFixed` overhead
so the scheduler reserves the Kata VM's own footprint.

## Guest-pull + DNS

`kata-qemu-snp` is a TEE shim, so kata-deploy wires it to the
`nydus-for-kata-tee` snapshotter and **guest-pull**: a confidential
pod's container image is pulled *inside* the SEV-SNP guest by the
in-guest image service, never staged decrypted on the host. That is the
correct confidential-containers posture and — verified live — it is not
a chart toggle: kata-deploy hardwires it for the snp/tdx/se shims.
`kata-qemu` (non-TEE) keeps the ordinary host-pull / overlayfs path.

The guest resolves and pulls the image over the **pod network**. A kata
SEV-SNP guest reaches pod IPs and the public internet, but **not k8s
ClusterIP VIPs** — so it cannot use the CoreDNS ClusterIP (`10.43.0.10`)
that the kubelet writes into a pod's `resolv.conf` by default. A
guest-pull pod must therefore be given a resolver it can actually reach:

```yaml
spec:
  runtimeClassName: kata-qemu-snp
  dnsPolicy: None
  dnsConfig:
    nameservers: ["1.1.1.1", "8.8.8.8"]
```

A public resolver is acceptable **only** for guest-pulling a public
registry image — the hostname is public either way. It is not a general
answer: pointing a confidential pod's DNS at a public resolver leaks
in-cluster service-name lookups off-cluster. A confidential pod that
must resolve *internal* names needs a resolver reachable without a
ClusterIP (a node-local DNS cache, or CoreDNS exposed on a host/pod
IP) — part of the §K networking follow-up below.

> **Discovery — kata SEV-SNP guests cannot reach ClusterIP VIPs.**
> PR-K5 found this debugging guest-pull (`[CDH] Image Pull error … error
> sending request`). Egress and pod-IP traffic work; only ClusterIP
> DNAT does not reach the guest. The §K KBS work (PR-K6) must account
> for it — a confidential pod that needs an in-cluster Service should
> not assume ClusterIP reachability. Tracked as a §K networking
> follow-up; flagged in the PR description.

## Privileged + hostPath — justified

The `kata-deploy` DaemonSet runs **privileged** and mounts several
**hostPath** volumes. This is intrinsic and unavoidable for a
node-level runtime installer — it must write the Kata binaries to the
host filesystem and rewrite the host's containerd configuration, then
signal containerd to reload. It is the same posture as the Cilium agent
(also privileged + hostPath). The "no hostPath / no privileged"
anti-pattern (locked topology, #1) targets **application** pods using
hostPath as ad-hoc storage — not node-level infrastructure DaemonSets,
for which there is no other mechanism. The DaemonSet is pinned to
confidential-compute nodes and runs as `system-node-critical` (the
chart default) so node pressure cannot evict the runtime installer.

On Argo CD prune / delete, kata-deploy's pod-termination hook cleanly
removes the kata runtime config from containerd — a prune is a clean
uninstall.

## Host prerequisite — k3s containerd drop-in

kata-deploy installs the kata runtimes by writing a drop-in
(`config-v3.toml.d/kata-deploy.toml`) and requires k3s's containerd
config to `import` that directory. k3s only emits the `imports` line if
a `config-v3.toml.tmpl` (and `config.toml.tmpl`) template exists:

```
imports = ["/var/lib/rancher/k3s/agent/etc/containerd/config-v3.toml.d/*.toml"]

{{ template "base" . }}
```

This is **host-level node bootstrap**, not GitOps — it belongs in the
PR-K2 node-bootstrap runbook. Without it kata-deploy crash-loops with
`rendered config … does not import the drop-in dir`.

## Live validation

PR-K5 was validated end-to-end on the confidential node: the kata-deploy
DaemonSet `Ready`, both RuntimeClasses present, and a test pod
(`runtimeClassName: kata-qemu-snp`, public `dnsConfig` per "Guest-pull +
DNS") reaching `Running`. Inside the guest: `/dev/sev-guest` present and
`dmesg` reporting `Memory Encryption Features active: AMD SEV SEV-ES
SEV-SNP` / `SNP running at VMPL0`; the QEMU launch carries
`confidential-guest-support=snp` + a `sev-snp-guest` object — proof of a
live AMD SEV-SNP confidential VM. See the PR description for the
captured outputs.
