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

**Supported host OS:** Ubuntu **26.04** or **25.10**. What decides it
is the distro hypervisor, not the kernel: the miner-agent always renders
`<launchSecurity type='sev-snp'>`, which needs **libvirt >= 10.5 and
QEMU >= 9.1**. 26.04 ships libvirt 12.0 / QEMU 10.2, 25.10 ships 11.6 /
10.1. **24.04 is not supported** — libvirt 10.0 / QEMU 8.2 boot no SNP
guest, and its HWE kernel passes every kernel check, so such a host
looks ready until its first launch. Upgrade it in place
(`do-release-upgrade` to 26.04; set `Prompt=normal` in
`/etc/update-manager/release-upgrades` if the LTS path is not open yet).
25.10 is end of life since 2026-07: new hosts go on 26.04. Play 00
checks the libvirt/QEMU versions apt resolves to, play 02 re-checks the
installed ones (`miner_min_libvirt_version` / `miner_min_qemu_version`).
The set lives in `group_vars/miner_nodes.yml::miner_supported_ubuntu_versions`.

Any SEV-SNP capable AMD EPYC (Milan, Genoa or Turin) works; copy
`host_vars/miner.example.yml` to add one. Each host declares
`snp_generation` (`genoa` | `turin` | `milan`), which selects its
host-attestor measurement — see [Host attestor](#host-attestor) below.

### Pre-delivery operator checklist

1. Order a bare-metal AMD EPYC box with **SEV-SNP enabled in BIOS**.
   Get that confirmed in writing by the provider before you pay —
   SEV-SNP is frequently a BIOS toggle they do not expose, and a box
   without it is useless here. `00-preflight.yml` verifies it. If you
   have in-band access to a Dell, you can do it yourself — see
   [Enabling SEV-SNP on a Dell (racadm)](#enabling-sev-snp-on-a-dell-racadm).
2. Create a NetBird setup key in your NetBird dashboard, bound to the
   **`miner`** group (`network.netbird_group` in
   `group_vars/miner_nodes.yml`), single-use, short expiry. Save it to
   `~/.config/hippius/<filename>` on the operator workstation and put
   that filename in `host_vars/<hostname>.yml::netbird_setup_key_file`.

### Post-delivery bootstrap

1. Push the operator SSH key (provider rescue / initial install) and
   verify `ssh <user>@<miner-ip>` (`ansible_user` in host_vars; the
   playbook works as `root` too — set `libvirt.user_can_access: false`
   then, there is no login user to add to the `libvirt` group).
   Upgrade a 24.04 install to 26.04 first (see Supported host OS).
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
    Expect `infra host-attestor launch_digest=<measurement> (pin OK)`,
    then `host-attestor-challenge: cid=N delivered`, then the vali
    `HostAttestor` row for the node goes `attested`.
11. Declare the miner to vali with its real CHIP_ID, mesh IP **and**
    `snp_generation` (`POST /v1/admin/miner/register`, see
    `docs/operator/onboarding-a-miner.md` §6) — the auto-provisioned row
    carries the `onchain:<node_id>` placeholder and is never scheduled.

**Legacy operator-CA (`miner_edge_auth: ca`):**

7. Register the pubkey with vali (`POST /v1/admin/miner/register`).
8. Provision the mTLS material into `/var/lib/hippius-miner/mtls/`
   (`client.crt`, `client.key`, `ca.crt`) — `scp` it onto the miner;
   the play only created the dir + SAN-checks `client.crt`. The Edge
   `WebPkiClientVerifier` accepts any cert chaining to the bootstrap CA
   (`CN=hippius-compute-edge-bootstrap-ca`). The CA and the client
   cert/key come from the fleet operator's secret store.
9. Start + monitor as above.

### Host attestor

Every miner runs a measured SNP "host-attestor" guest; with vali's
host-attestor GATE_ENFORCE on, a host without an attested one receives
no tenant VM. `miner_host_attestor` (group_vars) pins the three boot
components by sha256 and lists one launch measurement per CPU
generation — the components are identical, but the BSP VMSA carries the
host's CPUID signature, so the measurement differs per generation.
`snp_generation` in host_vars selects the entry rendered into
`[host_attestor]`.

The components are not published at a public URL. Stage them into
`/var/lib/hippius-miner/host-attestor/{ovmf.fd,linux.bin,initrd.bin}`
before play 05 (it refuses to render the section on a missing or
different file). A measurement for a NEW generation must be computed
over exactly those files and admitted before a host of that generation
can enroll:

```sh
hippius-launch-digest --ovmf ovmf.fd --kernel linux.bin --initrd initrd.bin \
    --cmdline cmdline.txt --vcpus 1 --vcpu-type EpycMilan   # EpycGenoa | EpycTurin
```

It reproduces the existing Genoa/Turin entries byte for byte — check
that first. Admission = a §22 pin with class `host_attestor` plus an
active `HostAttestorRelease` row in vali.

### Enabling SEV-SNP on a Dell (racadm)

Applies to AMD PowerEdge servers with an iDRAC9. In-band racadm is Dell's `srvadmin-idracadm8` package from
`https://linux.dell.com/repo/community/openmanage/11100/jammy` (https —
plain http times out). Attributes live in `BIOS.ProcSettings`:

| Attribute | Value |
|---|---|
| `Sme` | `Enabled` (leave `TransparentSme` disabled) |
| `Snp` | `Enabled` |
| `CpuMinSevAsid` | `100` — ASIDs 1-99 for SEV-ES/SNP, the rest plain SEV |
| `Rmp` | `Enabled` — SNP memory (RMP table) coverage |
| `IommuSupport`, `ProcX2Apic` | `Enabled` (default) |

The iDRAC evaluates a dependent attribute against the APPLIED value of
its parent, not the pending one: `Snp`/`CpuMinSevAsid` stay read-only
until `Sme` is applied, and `Rmp` until `Snp` is. That is three BIOS
jobs and three reboots:

```sh
racadm set BIOS.ProcSettings.Sme Enabled
sync; racadm jobqueue create BIOS.Setup.1-1 -r graceful -s TIME_NOW
# after reboot:
racadm set BIOS.ProcSettings.Snp Enabled
racadm set BIOS.ProcSettings.CpuMinSevAsid 100
sync; racadm jobqueue create BIOS.Setup.1-1 -r graceful -s TIME_NOW
# after reboot:
racadm set BIOS.ProcSettings.Rmp Enabled
sync; racadm jobqueue create BIOS.Setup.1-1 -r graceful -s TIME_NOW
```

Use `-r graceful` after a `sync`: `-r pwrcycle` cuts power at once, and
a `grub.cfg` written seconds earlier was not on disk yet — the box
booted the old kernel. Done when `dmesg` shows `SEV-SNP: RMP table
physical range` and `kvm_amd: SEV-SNP enabled`.

### Enabling SEV-SNP over a serial console (AMI Aptio)

For a rented server whose BMC you cannot reach and whose provider has no
BIOS-settings API, the provider's serial-over-LAN console (if offered)
usually reaches the firmware setup screen. Reboot the host from a second
shell and press `Delete` repeatedly in the serial session. In setup:
**Chipset → AMD CBS → CPU Common Options**:

| Setting | Often delivered as | Set to |
|---|---|---|
| SEV-ES ASID Space Limit | `1` | `100` (type the number) — ASIDs 1-99 for SEV-ES/SNP |
| SNP Memory (RMP Table) Coverage | `Auto` | `Enabled` |
| SEV Control | `Enabled` | unchanged |

Check these too: CPU → SMEE `Enabled`, Chipset → AMD CBS → NBIO Common
Options → IOMMU `Enabled` and `SEV-SNP Support` `Enabled`. `F4` saves
and reboots. One pass, no dependency chain as on the iDRAC.

How to tell before touching anything: a host with SEV-ES/SNP off logs
`SEV-SNP: Memory for the RMP table has not been reserved by BIOS` and
`kvm_amd: SEV-ES disabled (ASIDs 0 - 0)`. After the change it logs
`SEV-SNP: RMP table physical range …` and SEV-ES `1 - 99`; SNP itself
stays disabled until play 01 has removed any `iommu=pt` from the kernel
command line and rebooted. A dump of the setup variable (`cat
/sys/firmware/efi/efivars/AmdSetup-*`; `cp` fails on efivarfs) before
and after is a cheap record of what changed.

### SMT: BIOS only, never offlined at runtime

SMT can stay on. To run an SEV-SNP host without it, disable it in the
BIOS: **AMD CBS > CPU Common Options > CCD/Core/Thread Enablement > SMT
Control = Disable** (`/sys/devices/system/cpu/smt/control` then reads
`notsupported`).

Never take CPUs offline from the OS on an SNP host: no `nosmt` or
`maxcpus=` on the cmdline, no write to `smt/control`, no unit like a
hand-installed `hippius-smt-off.service`.
The kernel runs `WBINVD` only on online CPUs before `SNP_DF_FLUSH`, and
the firmware refuses the flush (`DF_FLUSH failed ... error=0xe`,
`WBINVD_REQUIRED`) while a CPU it counted at `SNP_INIT` is offline.
Destroyed guests' ASIDs are then never recycled: after one pool (~99
launches since boot) every new CVM fails with `EBUSY` until the host
reboots.

Play 01 enforces it: it stops, disables and deletes
`hippius-smt-off.service` where it exists, and once SEV-SNP is on it
fails the run if any present CPU is offline. On a live host the v5
heartbeat reports the same count (`cpus_offline`, present minus online;
alerts `MinerSnpCpusOffline`, `MinerSevDfFlushFailing`) once the agent
runs with `[heartbeat] schema_host_health = true`. The bootstrap renders
it when `miner_heartbeat_schema_host_health` is true, off by default
until the fleet runs an agent that knows the key (see
`group_vars/miner_nodes.yml`).

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
