# Ansible bootstrap — `hippius-compute` bare-metal hosts

Idempotent host-side configuration for SEV-SNP capable bare-metal nodes that
host the k3s confidential compute control plane.

This is the **host bootstrap** layer. Once Ansible has prepared a node
(SEV-SNP kernel params, private-segment networking, data RAID, k3s install), the
**Argo CD GitOps** layer (`deploy/gitops/`) takes over for everything
in-cluster (addons, applications, secrets).

## Scope

| Layer | Tool | Responsibility |
| --- | --- | --- |
| Cloud resources (DNS, Vault policies, S3 buckets) | Terraform | `deploy/terraform/` |
| **Host config (this dir)** | **Ansible** | **OS, kernel, network, RAID, k3s install** |
| In-cluster manifests | Argo CD + Helm | `deploy/gitops/` |

## Quickstart

```sh
# Prereqs:
#   - Ansible 2.16+ installed locally
#   - Required collections (one-time):
ansible-galaxy install -r requirements.yml

#   - Host reachable via SSH (public IP for first run, NetBird IP once joined)
#   - Host reachable over the private L2 segment your cc_nodes share
#     (configure it in your provider's console before running 03)

# Dry-run (no changes):
ansible-playbook -i inventory.yml playbooks/site.yml --check --diff

# Real run:
ansible-playbook -i inventory.yml playbooks/site.yml

# Run a single playbook:
ansible-playbook -i inventory.yml playbooks/02-snp-kernel-prep.yml
```

## Playbooks

Run in this order (`site.yml` does it for you):

| Order | Playbook | Reboot? | Idempotent |
| --- | --- | --- | --- |
| 00 | `00-preflight.yml` — verify CPU/kernel/SEV-SNP capability | No | Yes |
| 02 | `02-snp-kernel-prep.yml` — GRUB cmdline (drop `iommu=pt`, add `kvm_amd.sev*=1 mem_encrypt=on`) | **Yes if diff** | Yes |
| 03 | `03-private-network.yml` — netplan LACP bond on the private-segment NICs, static `privnet_static_cidr` from host_vars | Network reload | Yes |
| 04 | `04-data-raid.yml` — mdadm RAID1 on the NVMe data disks (`data_raid_devices` in host_vars — verify with `lsblk` first), mount `/var/lib/hippius-data` | No | Yes |
| 05 | `05-k3s-install.yml` — k3s server install with our flags (no flannel/traefik/servicelb/local-storage) | No | Yes |

`01-os-hardening.yml` and `06-netbird-agent.yml` are intentionally deferred to follow-up PRs — see issue #54.

## Idempotence

Every task is structured to produce **zero diff** on a second run. CI runs
`ansible-playbook --check --diff` in the GitHub Action to catch regressions.

## Reboot behaviour

`02-snp-kernel-prep.yml` reboots the host **only if** the GRUB cmdline
actually changed (handler-driven). Subsequent runs are no-op.

## Inventory + variables

- `inventory.yml` declares hosts in groups (`cc_nodes`, `miner_nodes`, `general_workers`).
  It is **git-ignored** — copy `inventory.example.yml` to `inventory.yml` and fill it in.
- `group_vars/all.yml` — workspace-wide defaults (pinned versions, common labels).
- `host_vars/<hostname>.yml` — per-host overrides (IPs, MAC addresses, disk layout).
  Also **git-ignored**; see `host_vars/README.md` for the schema and the two
  tracked `*.example.yml` templates.

Adding a new SEV-SNP node:
1. `cp host_vars/cc-node.example.yml host_vars/<hostname>.yml` and fill in its IP/MACs.
2. Add the hostname to `inventory.yml` under `cc_nodes`.
3. Run `ansible-playbook -i inventory.yml playbooks/site.yml --limit <hostname>`.

That is the whole procedure. There used to be a fourth step pointing at
`deploy/runbooks/` for the k3s join — that directory no longer exists, and
the join needs no separate runbook: `site.yml` imports
`playbooks/05-k3s-install.yml`, which installs and joins k3s itself.

## Secrets

This directory contains **no secrets**. Future playbooks that need NetBird
setup keys, provider API tokens, or Vault tokens will read them via
`lookup('file', '{{ operator_secret_dir }}/...')` at run time, from the
operator workstation's `~/.config/hippius/` (resolved via the
`operator_secret_dir` variable in `group_vars/all.yml`). The current
playbooks in this PR do not yet need any secrets — NetBird agent is
installed manually for the bootstrap, and provider/Vault wiring lands in
later §K PRs.

The `.gitignore` excludes any file matching `*-secret.yml`, `vault.yml`,
`*.pem`, `*.key`, `kubeconfig*`, plus `vault/` and `keys/` directories.

If you ever need to ship sensitive operational state into a host, use
`ansible-vault encrypt` and check the encrypted file in — never plaintext.

## Pinned versions

See `group_vars/all.yml`:
- k3s : v1.34.x
- NetBird agent : latest stable at the time of writing, bumped explicitly
- Ansible collections : pinned in `requirements.yml`

## Miner node bootstrap (`miner_nodes` group)

Miners are **UNTRUSTED** by design — a different trust profile from the
cc-nodes. The `miner_nodes` group + `playbooks/06-miner-bootstrap.yml`
bootstrap a miner host: SEV-SNP kernel cmdline, libvirt/QEMU, the
tenant-CVM network, the NetBird agent, and the `hippius-miner-agent`
systemd service. It is a **separate orchestrator** — deliberately NOT
wired into `site.yml` — and it **never** touches Vault or installs k3s
(both asserted absent at preflight).

**Supported host OS:** Ubuntu **24.04** or **25.10** (both validated;
25.10 ships kernel 6.17). The set lives in
`group_vars/miner_nodes.yml::miner_supported_ubuntu_versions`. The
NetBird apt repo + the agent source-build are codename-independent.
Any SEV-SNP capable AMD EPYC box works; copy
`host_vars/miner.example.yml` to add one.

### Pre-delivery operator checklist

1. Order a bare-metal AMD EPYC box with **SEV-SNP enabled in BIOS**.
   Get that confirmed in writing by the provider before you pay —
   SEV-SNP is frequently a BIOS toggle they do not expose, and a box
   without it is useless here. `00-preflight.yml` verifies it.
2. Create a NetBird setup key in your NetBird dashboard, bound to the
   **`miner`** group (`network.netbird_group` in
   `group_vars/miner_nodes.yml`), single-use, short expiry. Save it to
   `~/.config/hippius/<filename>` on the operator workstation and put
   that filename in `host_vars/<hostname>.yml::netbird_setup_key_file`.
3. Obtain the Edge gateway's server CA from the operator of the network
   you are joining and save it at `edge_ca_cert_file` (default
   `~/.config/hippius/edge-ca.crt`). See "Permissionless" below.

### Post-delivery bootstrap

1. Push the operator SSH key (provider rescue mode / initial install) and verify
   `ssh ubuntu@<miner-ip>`.
2. `cp host_vars/miner.example.yml host_vars/<hostname>.yml`, fill the
   connection details, and verify the disk layout with `lsblk` (the
   `nvme_*` lists — the preflight fails closed if they are wrong).
3. Confirm the hostname is under `miner_nodes` in `inventory.yml`.
4. Dry-run:
   `ansible-playbook -i inventory.yml playbooks/06-miner-bootstrap.yml --limit <hostname> --check --diff`
5. Real run (drop `--check --diff`). The SEV-SNP cmdline play reboots
   the box **only if** the GRUB line changed.
6. **Capture the printed miner node_id** (the agent's Ed25519 public
   key) — `sudo cat /var/lib/hippius-miner/identity.pub`. This IS the
   on-chain identity.

The remaining steps depend on `miner_edge_auth` (group_vars, default
**`onchain`**):

**Permissionless (`onchain`, default) — no operator certs, no manual
vali step:**

7. The playbook already installed the Edge **server** CA
   (from the operator-supplied `edge_ca_cert_file` → `ca.crt`) and
   rendered a **self-sign** config
   (no `client_cert`/`client_key`) — nothing to `scp`. The agent mints
   its own client cert from `identity.key` at boot.
8. **Register the node_id on-chain** with `deploy/register-miner/`
   (`register_child` + the agent's `sign-registration` node_sig). The
   Edge (`EDGE_MINER_AUTH=onchain`) then admits the self-signed cert
   once the node is `Active`. See
   `docs/design/permissionless-miner-auth.md`.
9. vali auto-provisions the miner's heartbeat `TelemetrySource` on the
   first Edge-vouched heartbeat — **no `POST /v1/miner/register`**.
10. Start + monitor:
    `systemctl start hippius-miner-agent && journalctl -u hippius-miner-agent -f`.

**Legacy operator-CA (`miner_edge_auth: ca`):**

7. Register the pubkey with vali (`POST /v1/admin/miner/register`).
8. Provision the mTLS material into `/var/lib/hippius-miner/mtls/`
   (`client.crt`, `client.key`, `ca.crt`) — `scp` it onto the miner;
   the play only created the dir + SAN-checks `client.crt`. The Edge
   `WebPkiClientVerifier` accepts any cert chaining to the bootstrap CA
   (`CN=hippius-compute-edge-bootstrap-ca`). CA + a client cert/key live
   in Vault at `secret/hippius-compute/edge-gateway/mtls`.
9. Start + monitor as above.

### Invariants — do not break

- Miners **never** touch the hippius-compute Vault (`vault_addr` /
  `vault_token` asserted undefined at preflight).
- Miners **never** run k3s.
- The miner identity is **self-generated** on the box — never imported.
- The mTLS cert content is **pushed by the operator**, never pulled by
  the miner or generated by Ansible.
- NetBird group is **`miner`** only (`network.netbird_group`).

## Related issues

- #54 (§K) — full deployment automation backlog
- #1 comment 4505904116 — locked infrastructure topology decisions
