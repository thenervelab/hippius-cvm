# Running a Hippius compute miner (external operators)

This guide is for an operator who brings their own AMD SEV-SNP server to
the Hippius compute network. You keep the machine, its keys, and your
wallet. Hippius approves your family account once, sets a capacity anchor
for each host, and routes confidential VMs to you.

Background and design detail are in
[`onboarding-a-miner.md`](./onboarding-a-miner.md). This page is the path
through it, in order.

```
 wallet + family request ─▶ dashboard "Add a node" ─▶ Ansible (06-miner-bootstrap.yml)
                                                              │
        node visible + attested ◀─ start agent ◀─ family-signed registration
                 │
     capacity anchor (Hippius) ─▶ schedulable ─▶ pools / price
```

---

## 1. Prerequisites

The bootstrap's preflight (play 00) checks all of this before it changes
anything. A host that fails a check stops with a code: see
[Preflight codes](#preflight-codes).

### Hardware

| Item | Requirement |
|---|---|
| CPU | AMD EPYC with SEV-SNP: **Milan** (7003, Zen 3), **Genoa** (9004, Zen 4) or **Turin** (9005, Zen 5). Nothing else. |
| Machine | **Bare metal.** SNP host support cannot run inside a VM. |
| CPU / RAM | At least **16 online hardware threads** and **64 GiB** of RAM (`miner_preflight_min` in `group_vars/miner_nodes.yml`; below them the play stops with `CPU_TOO_FEW` or `RAM_TOO_LOW`). Two hardware threads and 8 GiB of RAM are kept for the host. Everything else is offered to tenants. **RAM sets how many VMs you can host.** SNP guest memory is pinned and encrypted, so it can't be oversubscribed. Adding cores without RAM won't add slots. |
| Disks | NVMe recommended. Point the tenant data root at a dedicated NVMe if you have one: it takes the heaviest I/O, and the first boot of every VM writes its whole data disk. The system disk also holds base images, several GiB per distro, at the fixed path `/var/lib/hippius-miner/staging`. The data filesystem needs more than 100 GiB beyond what you offer, for migrations, backups and staging; the preflight wants at least 300 GiB in total (100 reserve + 200 for tenant disks) and 30 GiB free under the staging path. A rotational disk works but makes first boots slow. |
| Network | Outbound internet. Inbound `22/tcp` (your SSH) and `51820/udp` (mesh). The play's firewall allows exactly those, plus the mesh interface. |

### BIOS / firmware

Have the datacentre confirm these **in writing before you pay** for the
machine. SEV-SNP that is fused off or disabled in firmware can't be fixed
remotely, and it is the most common way onboarding fails.

| Setting (names vary by vendor) | Value |
|---|---|
| SMEE / "SME" / memory encryption | Enabled |
| SEV-SNP support ("SNP", "SEV-SNP Support") | Enabled |
| SNP Memory (RMP Table) Coverage | Enabled (not `Auto`). `dmesg` saying `Memory for the RMP table has not been reserved by BIOS` means it is off. |
| SEV-ES ASID Space Limit | Above 1, e.g. `100`. ASIDs below this limit are the only ones SNP guests can use. A limit of `1` leaves none (`SNP_NO_ES_ASIDS`). |
| IOMMU | Enabled. SNP requires it, and not in passthrough mode. |

Kernel command line: play 01 sets `kvm_amd.sev=1 kvm_amd.sev_es=1
kvm_amd.sev_snp=1 mem_encrypt=on`, removes `iommu=pt`, and reboots only if
the line changed.

### SMT: leave it on, or turn it off in the BIOS only

SMT **may stay on**. The rule is about how CPUs are taken offline:

- **Never offline CPUs at runtime.** That means no `nosmt`, `maxcpus=` or
  `nr_cpus=` on the kernel command line, no writes to
  `/sys/devices/system/cpu/smt/control`, and no unit that offlines CPUs.
  The firmware still counts the offlined threads, so it refuses
  `SNP_DF_FLUSH` (`error 0xe`, `DF_FLUSH failed`). Freed SNP ASIDs are
  then never recycled, and the host stops launching VMs after about 99
  launches since boot. The preflight refuses this (`CMDLINE_CPU_LIMIT`,
  `CPU_OFFLINE`), and play 01 removes a known SMT-off unit if it finds one.
- **If you want SMT off, disable it in the BIOS.** On AMD CBS menus it is
  under CPU Common Options > CCD/Core/Thread Enablement > SMT Control.
  `SMT_ON` is only a warning. A future network policy may require SMT off
  through the SNP guest policy. If that happens it will be announced, and
  the BIOS is the only supported place to change it.

### Operating system

| Item | Requirement |
|---|---|
| Distribution | **Ubuntu 26.04 LTS**. Not 24.04: its libvirt 10.0 and QEMU 8.2 can't boot an SNP guest. Upgrade in place first. |
| Kernel | ≥ 6.11, with SNP host support in `kvm_amd` (26.04's kernel has it). |
| Hypervisor | libvirt ≥ 10.5 and QEMU ≥ 9.1, from the distro. Play 02 installs them. |
| Clock | Synchronised (systemd-timesyncd or chrony). Heartbeats more than 300 s off are refused. |

---

## 2. What you hold, what you're given, what Hippius does

**Stays yours. Never send these to anyone, including Hippius:**

| Key | Where | Used for |
|---|---|---|
| Node identity | `/var/lib/hippius-miner/identity.key` on the host (generated there) | The machine's identity on chain and at the gateway. It signs heartbeats, the registration and the graceful exit. Back it up offline. Never copy it to a second host. |
| Family account | Your wallet extension (polkadot.js, Talisman or SubWallet; a hardware/air-gapped signer attached to the extension works) | Owns your nodes on chain. Signs node registration and deregistration. |
| Child account (one per node) | Your wallet extension | Signs the node's price changes. Create a fresh one per host. |

**Given to you:**

| Item | How you get it |
|---|---|
| NetBird setup key (mesh membership) | Shown **once** by the dashboard when you prepare a host. Save it to a file on your workstation; it is never committed and never copied to the host. |
| Gateway server CA, gateway endpoint, order-signing public key, mesh management URL, tenant firmware URL + digest | Fleet values shipped in the Ansible checkout (`deploy/ansible/group_vars/miner_nodes.yml`, `miner-tasks/files/edge-ca.crt`). Don't edit them. |
| KBS CA certificate and the host-attestor boot components | Provided by Hippius on request if they aren't in your checkout. Stage them as described in [`deploy/ansible/README.md`](../../deploy/ansible/README.md#host-attestor). The play refuses files whose digest isn't the pinned one. |

None of these lets anyone read your tenants' data or act as your node.
They are routing and mesh membership.

**Done by Hippius:**

- **Family approval.** Your family account is registered once, after you
  request it (§3, step 2).
- **Capacity anchor.** For each new host, Hippius records its CPU/RAM size
  from hardware facts it can check itself, never from a figure you send.
  Until it is set, the network sizes the host with a conservative
  fallback and doesn't count it in capacity quotes. The anchor caps what
  the network will ask of your host.
- Releases of the miner agent, the host attestor and the tenant firmware.

---

## 3. Onboarding, step by step

### Step 1: Wallet and accounts

1. Install a wallet extension and create (or import) your **family**
   account. Create one fresh **child** account per host you plan to run.
2. In the providers dashboard, open **Accounts** → **Link an account**.
   Pick the family account, role **Compute family**, and sign the
   one-time message. Signing moves no funds.
3. Fund the family with a small balance for fees. The registration itself
   is free, but the batch that registers a node also creates the child's
   proxy entry.

### Step 2: Request the family

In **Accounts**, the **Family** column of your linked account shows
**Request onboarding**. Click it. This opens a support ticket naming the
account, and Hippius answers there. Once approved, the column reads
**Registered**.

If the account already owns a node registered on the Hippius chain (for
example as an existing storage-miner family), it is already a family:
skip the approval itself, but still open the ticket if the dashboard
shows "Compute registration is in private beta" — compute registration
is open to approved operators only for now, and the same ticket gets
your login added.

### Step 3: Prepare the host (dashboard)

**Add a node** → **Compute node** → **+ Add compute miner**. The wizard's
steps are **Choose the accounts**, **Save the setup key**, **Paste the
host identity**, **Register on chain**, **Declare to the validator** and
**Miner status**.

1. **Choose the accounts**: the **Family account**, the **Child
   account**, and a **Hostname** (lower-case letters, digits and dashes,
   2 to 63 characters). Then **Prepare host**.
2. **Save the setup key**. The dashboard shows:
   - the **NetBird setup key**, once. Save it on your workstation at
     `~/.config/hippius/<setup key file name shown>` (that is where the
     play reads it), then tick **I have saved the setup key**;
   - the **Host variables** (`host_vars/<hostname>.yml`);
   - the **Ansible command**;
   - the **sign-registration command**.

### Step 4: Bootstrap the host (Ansible)

From your Ansible checkout (`deploy/ansible`):

0. On the host, install the release `hippius-miner-agent`
   ([`onboarding-a-miner.md`](./onboarding-a-miner.md#prebuilt-binary),
   "Prebuilt binary") and stage the host-attestor files
   ([`deploy/ansible/README.md`](../../deploy/ansible/README.md#host-attestor)).
   Play 05 does not build the agent: it refuses to run without the
   binary (`MINER_AGENT_BINARY_MISSING`) or with attestor files that do
   not match their pinned digests.
1. Save the generated file as `host_vars/<hostname>.yml`:
   - Fill the connection details and the disks, by
     `/dev/disk/by-id/...`, never `/dev/nvmeXn1`.
   - Delete the `snp_generation`, `cpu_model_expected` and
     `ram_gb_expected` placeholder lines unless you want them: the
     preflight derives `snp_generation` from the CPU (and refuses a value
     that disagrees), and the other two are optional stricter checks
     (a substring of the CPU model name; a RAM minimum checked as "≥").
   - Leave `miner_id` unset. It is derived from the node identity.
2. Add `<hostname>: {}` under `miner_nodes:` → `hosts:` in
   `inventory.yml`.
3. Run the preflight alone first. With `--check` it changes nothing;
   without it, the only change it makes is removing a conflicting legacy
   NetBird apt source:
   ```sh
   ansible-playbook -i inventory.yml playbooks/06-miner-bootstrap.yml \
       --limit <hostname> --tags preflight --check
   ```
   It prints a `HIPPIUS_PREFLIGHT {...}` line: the verdict, the derived
   `snp_generation`, the CPU, the SNP firmware version, and the failure /
   warning codes. It also needs the setup-key file from step 3.
4. Run the play with the command the dashboard gave you:
   ```sh
   ansible-playbook -i inventory.yml playbooks/06-miner-bootstrap.yml --limit <hostname>
   ```
   Plays 00-08 cover: preflight, SNP kernel command line (may reboot),
   libvirt/QEMU plus the tenant firmware, the VM network, NetBird join,
   the miner agent and identity, the gateway CA, the firewall, and SSH
   hardening (key-only).
5. Play 04 reads this host's mesh address from `netbird status` after the
   join, and the agent's order server binds to it. Check that the
   `bind_ip=` it prints matches `netbird status`. Without a mesh address
   the agent never receives an order, and nothing else looks wrong.
6. Keep the **JSON block play 05 prints**: node id, CHIP_ID, miner id,
   mesh address and processor generation:
   ```json
   {"miner_id": "m-<16 hex>", "node_id": "<64 hex>", "platform_id": "<128 hex>",
    "netbird_ip": "<mesh address>", "snp_generation": "milan | genoa | turin"}
   ```
   `snp_generation` is the one play 00 derived from the CPU. When play 00
   did not run in the same invocation (`--skip-tags preflight`,
   `--start-at-task` past it), play 05 withholds the JSON and prints
   `WARN [SNP_GENERATION_NOT_DERIVED]` instead: run the full command
   again.

The agent is installed **enabled but stopped**. Leave it stopped until
step 6. Auto-update is on by default (§6).

### Step 5: Sign the registration (on the host)

Run the **sign-registration command** from the dashboard on the host, as
root. It carries your family and your child:

```sh
hippius-miner-agent sign-registration --family 0x<FAMILY_HEX> --child 0x<CHILD_HEX> --nonce 0
```

It prints `{"node_id": ..., "node_sig": ..., "nonce": ...}`. This is the
node key vouching for the pairing. The key never leaves the host. If the
chain expects another nonce, the wizard tells you which; run it again
with that value.

### Step 6: Register on chain (dashboard)

Back in the wizard:

1. **Paste the host identity**: the **Bootstrap output** (play 05's JSON)
   and the **sign-registration** output. Check the node id, platform id
   (CHIP_ID), **Processor generation** and **NetBird address**; the
   **NetBird peer id** is optional.
2. **Register on chain**: your extension signs one atomic batch with the
   family: add the child as a `NonTransfer` proxy, `register_child`,
   remove the proxy (or `register_child` alone if the child is already a
   proxy). Registration reserves no deposit while on-chain lockup is
   off (today). If lockup is enabled, a family's first three
   registrations stay free and later ones reserve a deposit on the
   family, which the wizard shows before you sign.
3. **Declare to the validator** runs by itself once the batch is
   included: it binds your node to its real CHIP_ID, mesh address and
   processor generation. If it fails, the wizard offers **Retry
   declaration**.

Then start the agent on the host:

```sh
sudo systemctl start hippius-miner-agent
journalctl -u hippius-miner-agent -f
```

Expect `serve — up (miner_id=m-…, identity=…, orders=<mesh-ip>:9700)`,
then the host attestor launching (`infra host-attestor launch_digest=…
(pin OK)`).

### Step 7: See the node

**My fleet** lists the node. Its page shows its status, **Last seen**,
**Hosted VMs**, **Region**, the **Placement** panel (schedulable or not,
with the reason) and the last 30 days of **Refusals**. A new node
normally passes through `attestor-pending` for a few minutes, then
becomes schedulable. Hippius sets its capacity anchor shortly after it
appears.

The region is **detected**, not declared, within about 10 minutes of the
first heartbeat. A VPN or tunnel in front of the host prevents it from
being verified.

### Step 8: Storage pools and dedicated disks (preview)

Rolling out: these controls appear on the node page (**Storage
configuration**) once the dashboard and your agent both support pushed
storage configuration.

- **Add a pool:** a filesystem of its own (ext4, xfs or btrfs) mounted at
  `/var/lib/hippius-miner/pools/<pool id>`. Set its declared class and a
  budget in GB. If you give a path outside that directory, the dialog
  shows the bind-mount commands (`mkdir`, `/etc/fstab` line, mount).
- **Declare a dedicated disk:** a whole, blank disk named by its
  `/dev/disk/by-id/` name. Run `wipefs -a` on it yourself; the agent
  never formats, mounts or wipes anything.
- To remove a pool, **Drain** it: it is removed once no VM disk is left
  on it. A dedicated disk is drained, then **Retired**.

The dashboard signs a document and sends it to the agent. The panel shows
whether the agent applied it, or why it refused it (see
[Pool refusals](#pool-and-storage-refusals)). Probes measure each pool
and set its *verified* tier, so a declared class that the probe
contradicts is flagged. Pool and disk tiers are a preview: VM OS disks
still always land on the `default` pool (the data root).

### Step 9: Set your price

Node page → **Actions** → **Announce price**. Your extension signs it
with the **node's child account**. Rules the chain enforces (the numbers
are network defaults, which can change):

- one price per node, in USD per resource unit;
- it must sit within the network's bounds, shown in the dialog;
- after the first price, each change moves it by at most ×1.5 either way;
- it takes effect after a notice period (about a day);
- the next announcement can come no sooner than about 12 h after the
  previous one, and replaces a pending one.

Once the change is due, **Apply price** writes it on chain. Anyone can
submit the apply, and the dashboard offers it.

---

## 4. Troubleshooting

### Preflight codes

Play 00 first runs the generic host checks and reports every failure at
once, one line each: `FAIL [CODE] what it found -- fix: how`. Warnings
(`WARN [CODE] ...`) don't stop the play. The last six codes of the table
are separate checks that follow it and stop the run one at a time. On a
host that already runs the miner-agent, `DATA_ROOT_TOO_SMALL`,
`STAGING_ROOT_LOW`, `CLOCK_NOT_SYNCED` and `NETBIRD_MGMT_UNREACHABLE`
only warn, so an update run is not blocked by them. Rerun the preflight
alone with `--tags preflight --check` after each fix.

| Code | Meaning | Fix |
|---|---|---|
| `CPU_NOT_AMD_X86` | Not an x86_64 AMD CPU. | SEV-SNP needs AMD EPYC. Use another machine. |
| `CPU_UNSUPPORTED` | AMD, but not an EPYC Milan, Genoa or Turin (judged on CPU family/model, the same table the agent measures with). | Use an EPYC 7003, 9004 or 9005. |
| `SNP_GENERATION_MISMATCH` | `snp_generation` in host_vars doesn't match the CPU. | Remove it (it is derived) or set the generation the message names. |
| `VIRTUALIZED` | Running under a hypervisor. | Bare metal only. |
| `OS_UNSUPPORTED` | Not a supported Ubuntu release. | Install Ubuntu 26.04 LTS, or upgrade in place, then rerun. |
| `KERNEL_TOO_OLD` | Kernel older than 6.11. | Boot the release's current kernel (`apt full-upgrade`, reboot). |
| `HYPERVISOR_TOO_OLD` | The libvirt / QEMU apt would install can't boot an SNP guest. | Upgrade the OS to 26.04. |
| `SNP_KERNEL_UNSUPPORTED` | `kvm_amd` is not loaded or has no SEV-SNP host support. | Enable SVM Mode (AMD-V) in the BIOS, boot a stock Ubuntu 26.04 kernel; check `modprobe kvm_amd`. |
| `SNP_BIOS_DISABLED` | The CPU doesn't advertise `sev_snp`: the firmware didn't enable SNP (SNP off, SMEE off, or no RMP table reserved). | Set SMEE, SEV-SNP and SNP Memory (RMP) Coverage in the BIOS (§1), reboot. |
| `SNP_PENDING_REBOOT` (warning) | `kvm_amd sev_snp` ≠ `Y` and the SNP kernel command line isn't active yet (or `iommu=pt` is on it). | Nothing: play 01 fixes the command line and reboots once; if SNP is still off after that, its check says what to look at. |
| `SNP_NOT_ENABLED` | The SNP command line is active but `kvm_amd sev_snp` is still not `Y`. | SNP failed to initialise: `dmesg \| grep -iE 'sev\|snp\|rmp\|ccp'`, recheck the BIOS, update BIOS / SEV firmware. |
| `SEV_DEVICE_MISSING` | SNP is on but there is no `/dev/sev`. | The AMD Secure Processor didn't come up: `dmesg \| grep -i ccp`, update BIOS / SEV firmware. |
| `SNP_NO_ES_ASIDS` | No ASIDs for SEV-ES/SNP guests (`sev_es` in `/sys/fs/cgroup/misc.capacity`). | Raise "SEV-ES ASID Space Limit" in the BIOS (e.g. `100`), reboot. |
| `SNP_FIRMWARE_UNKNOWN` (warning) | No `SEV-SNP API:` line in the kernel log. | Informational: `journalctl -k -b \| grep 'SEV-SNP API'`. |
| `IOMMU_DISABLED` | No IOMMU unit, or `amd_iommu=off` / `iommu=off`. | Enable it in the BIOS; remove the command-line token. |
| `IOMMU_PASSTHROUGH` (warning) | `iommu=pt` on the command line. | Nothing: play 01 removes it. |
| `CMDLINE_CPU_LIMIT` | `nosmt`, `maxcpus=` or `nr_cpus=` on the kernel command line. | Remove it, `update-grub`, reboot. To run without SMT, disable SMT in the BIOS. |
| `CPU_OFFLINE` | A present CPU is offline (offline list, online ≠ present, or `smt/control` set to `off` / `forceoff` by the OS). SMT disabled in the BIOS (`notsupported`, every present CPU online) passes. | Bring it back online and remove whatever offlined it. See §1, SMT. (A warning only when the legacy `hippius-smt-off.service` is the cause: play 01 removes it.) |
| `SMT_ON` (warning) | SMT is enabled. | Allowed. Disable it in the BIOS only, if you choose to. |
| `CPU_TOO_FEW` | Fewer online hardware threads than the minimum (16). | Use a larger CPU. |
| `RAM_TOO_LOW` | Less RAM than the minimum (64 GiB, with a 10% firmware allowance). | Add memory. |
| `CPU_MODEL_MISMATCH` | The CPU model differs from `cpu_model_expected`. | Fix host_vars, or you are pointing at the wrong machine. |
| `RAM_MISMATCH` | Less RAM than `ram_gb_expected`. | Fix host_vars, or check for a failed DIMM. |
| `DATA_ROOT_MISSING` | A non-default `miner_data_disk_root` / `miner_state_disk_root` doesn't exist. | Create and **mount** it before the play. The play never creates it, so VM disks can't end up hidden under an unmounted mount point. |
| `DATA_ROOT_ON_SYSTEM_FS` (warning) | A non-default data root sits on the root filesystem. | If it should be a dedicated disk, it isn't mounted: check `/etc/fstab` and `findmnt`. |
| `DATA_ROOT_TOO_SMALL` | The filesystem holding the data root is smaller than the reserve + tenant minimum (300 GiB). | Point the data root at a bigger filesystem. |
| `STAGING_ROOT_LOW` | Less than 30 GiB free for `/var/lib/hippius-miner/staging` (base images). | Free space on, or grow, that filesystem. |
| `CLOCK_NOT_SYNCED` | The clock isn't NTP-synchronised. | `timedatectl set-ntp true` (timesyncd or chrony), allow outbound NTP, wait. |
| `NETBIRD_MGMT_UNREACHABLE` | No HTTPS answer from the mesh management URL (TLS verified). | Allow outbound HTTPS. Check DNS, the clock and any intercepting proxy. |
| `NETBIRD_DISCONNECTED` (warning) | NetBird is installed but not connected. | Expected before play 04, which (re)joins. Otherwise check `netbird status`. |
| `NVME_LAYOUT` | A disk listed in host_vars isn't a block device. | Fix the `/dev/disk/by-id/` names in host_vars (`lsblk`). |
| `DATA_DISK_BUSY` | A disk listed as a data disk has a partition table, a filesystem, or backs a system mount. | List only blank disks as data disks. Never list a system disk. |
| `NETBIRD_SETUP_KEY_MISSING` | The setup-key file isn't on your workstation. | Save the key from the dashboard to the path the message gives. |
| `MINER_AGENT_BINARY_MISSING` (play 05) | `/usr/local/bin/hippius-miner-agent` is missing, or its `--version` does not report `versions.miner_agent`. | Install the release binary as the message says (`onboarding-a-miner.md`, "Prebuilt binary"), then re-run. |
| `PLACEHOLDER_VALUE` (play 05) | A variable is still a `<…>` placeholder (the message names the config key or the variable). | Set it in host_vars (the dashboard's generated file carries the fleet values), then re-run. |
| `VAULT_CREDENTIALS_SET`, `K3S_PRESENT` | The host or its variables look like a control-plane node. | A miner host carries neither; use a clean machine and the generated host_vars. |

### Heartbeats

The agent heartbeats every 60 s. If **Last seen** doesn't move:

1. `journalctl -u hippius-miner-agent | grep heartbeat-pusher` shows
   `outcome=delivered`, `outcome=rejected` or `outcome=transport-failed`.
2. **`transport-failed`** means the agent can't reach the gateway. The
   gateway is reached through the mesh, so check `netbird status` first:
   it needs `Management: Connected` and an address in `100.64.0.0/10`. A
   setup key from another mesh logs you into the wrong network.
3. **`rejected`** means the gateway answered and refused. The usual
   causes:
   - The node isn't (or no longer) active on chain: registration hasn't
     landed, or the node was deregistered.
   - The node is quarantined. This is expected after a graceful exit.
   - The clock is skewed. (`stale-dropped` is different: the agent
     dropped a heartbeat that aged in its queue during an outage.)
   - The sequence file was restored from a backup. Never restore
     `/var/lib/hippius-miner/heartbeat.seq`: the validator refuses a
     sequence that goes backwards as a replay.
4. `hippius-miner-agent platform-id` must print the CHIP_ID. If it fails,
   SNP isn't live on the host.

### Host attestor

Every host runs a small measured SNP VM, the **host attestor**, that
proves the host runs the expected stack. While it isn't attested, the
node shows one of these as its **Schedulable** reason:

| Reason | Meaning | Fix |
|---|---|---|
| `attestor-missing` | The validator has never heard from this host's attestor. | Check `journalctl -u hippius-miner-agent \| grep -i attestor` for a launch failure. Check that the three components are staged with the pinned digests and that `snp_generation` is right. |
| `attestor-pending` | Enrolled, not attested yet. | Normal for a few minutes after the first start. If it persists, the measurement probably doesn't match your generation: check `snp_generation`. |
| `cert-expired` | Its enrolment certificate lapsed and no fresh one has arrived. | Check the agent journal for attestor errors and that the mesh is up. If it persists, contact support. |
| `measurement-stale` | Attested, but on an attestor release the network no longer accepts. | Stage the current host-attestor components and rerun the play. |
| `attestor-stale` | Attested, but no recent beacon. | Check the domain is running (`virsh list` shows `hippius-infra-host-attestor`) and the agent is up. |
| `release-unpinned` | The network has no active attestor release. | Not about your host. Wait, or ask Hippius. |

Other **Schedulable** reasons:

| Reason | Meaning | Fix |
|---|---|---|
| `heartbeat-stale` | No recent heartbeat. | See [Heartbeats](#heartbeats). |
| `platform-id-invalid` | The node wasn't declared with its real CHIP_ID. | Rerun the dashboard's **Declare to the validator**. |
| `unreachable` | No mesh address on record. | Redo the declaration with the correct NetBird address. |
| `quarantined` | Quarantined: graceful exit, or by Hippius. | Expected while leaving. Otherwise contact support. |
| `failover-quarantined` | Held out after a failover off this host. | Contact support. |
| `not-bridged` | No chain node id bound yet. | Normal before **Declare to the validator** completes; otherwise retry it. |
| `not-active` | The node is not active on chain. | Check the registration landed and the node wasn't deregistered. |

If the node shows schedulable but launches fail, look at **Refusals** on
the node page and `dispatch-failed-detail` lines in the agent journal.
Common classes:

- `tenant-preflight/ovmf-missing`: the tenant firmware is missing or has
  the wrong digest. Rerun the play.
- `refused kbs-transport`: the KBS CA is missing.
- `*-disk/mkdir`: a data root outside the agent's writable paths. Set it
  in host_vars and rerun the play.
- `507 insufficient-disk`: the disk budget is exhausted. This is a
  capacity event, not a fault.

### Pool and storage refusals

The dashboard's **Storage configuration** panel shows the agent's code.
`storage-check` reproduces the check on the host, as described in
[`onboarding-a-miner.md`](./onboarding-a-miner.md) §5c.

| Code | Meaning / fix |
|---|---|
| `pool-outside-pools-root` | A pool other than `default` must live at `/var/lib/hippius-miner/pools/<id>`. Mount or bind-mount it there. |
| `pool-path-missing` | The path doesn't exist or isn't a directory. |
| `pool-path-invalid` | The path isn't plain and absolute, or it goes through a symlink. |
| `pool-path-perms` | The directory must be owned by root and not group- or world-writable. |
| `pool-not-a-mount` | The path isn't itself a mount point. Mount a filesystem exactly there. |
| `pool-on-root-fs` | The pool is on the root filesystem. Give it its own. |
| `pool-fstype-unsupported` | Use ext4, xfs or btrfs. |
| `pool-path-read-only` | The agent can't write there: a read-only mount, or outside its sandbox. |
| `pool-odirect-unsupported` | The filesystem doesn't support direct I/O. |
| `pool-budget-exceeds-fs` | The budget is larger than the filesystem minus its reserve (the larger of 5% and 20 GiB). |
| `pool-budget-below-committed` | The budget is lower than what VM disks already use there. |
| `pool-budget-invalid` | A non-default pool needs a budget above 0. |
| `pool-shared-fs` | Two pools on one filesystem. Each pool needs its own. |
| `pool-id-invalid` | Lower-case letters, digits and dashes, up to 32 characters. |
| `pool-default-required` / `pool-conflicts-local` | The `default` pool must stay at the data root, with the host budget, holding OS disks. A pool's path can't differ from the host's local config. |
| `pool-has-disks` | You can't remove or move a pool that holds VM disks. Drain it, wait until it's empty, then remove it. |
| `pool-fs-changed` | A different filesystem is now mounted at the pool's path. Remount the right one. If the swap is deliberate, see §5c. |
| `pool-unbound` | The pool wasn't mounted when the agent started. It binds at the next agent restart. |
| `pool-unavailable:<pool>` (launch, HTTP 507) | The pool is draining, closed to OS disks, or off its filesystem. The network places the VM elsewhere. |
| `too-many-pools`, `storage-config-*` | The document itself was refused: too many pools, an expired or stale revision, a malformed document. Re-save it from the dashboard. `storage-config-disabled` means this agent has pushed configs turned off; update the agent. |
| `vm-pool-record` | A VM's record of which pool holds its disks is missing or unreadable. The agent refuses rather than create a blank disk. Contact support; never delete files under `vm-pool/`. |

---

## 5. Leaving the network

There is **no stake** to withdraw today, so leaving has nothing to do with
unstaking. Leaving means drain, deregister, then power off, in that order.
**Deregistering a node that still hosts VMs** removes it from the control
plane, so its VMs are rebuilt elsewhere rather than migrated with their
state.

1. **Start the graceful exit on the host.** Keep the agent running: it
   does the migrations.
   ```sh
   sudo hippius-miner-agent request-graceful-exit
   ```
   It reads the miner id, the Edge endpoint, its CA, the identity key
   (and a legacy client cert/key pair, if configured) from
   `/etc/hippius-miner/config.toml`, the file the play rendered;
   `--miner-id`, `--edge-url` and `--ca-cert` override them. Agents up
   to v2026.10.16.2 do not read the file and need all three passed
   (`--ca-cert /var/lib/hippius-miner/mtls/ca.crt`). Or
   `sudo hippius-miner-agent graceful-exit-heartbeat`, which reads the
   same file. Either one
   quarantines the node: no new VMs land on it, and the VMs it hosts are
   migrated off live. After this the agent's regular heartbeats show as
   `rejected` (quarantined). That is expected.
2. **Wait** until the node page shows **Quarantined** and **Hosted VMs: 0**.
3. **Deregister** from the node page (**Actions** → **Deregister**),
   signed by the family. One transaction deregisters the child and frees
   it (when no deposit is held; otherwise contact support). The node id
   and the child account then wait out a cooldown of about 12 h (7,200
   blocks) before either can register again.
4. Only now stop the agent and wipe or repurpose the machine. A stopped
   agent no longer manages any VM still on the host, and wiping the
   machine destroys them: never stop before **Hosted VMs: 0**.

To re-key a host (new identity on the same machine), do the same drain and
deregister, then **Add a node** again with a fresh child account.

---

## 6. Auto-update

On by default. A timer (every 30 min, plus up to 6 h of random delay)
installs a newer agent release from
[`thenervelab/hippius-cvm` releases](https://github.com/thenervelab/hippius-cvm/releases)
only when all of these hold:

- the release is newer than the installed one (never a downgrade);
- it has been published for at least 24 h;
- the binary matches `SHA256SUMS`;
- its build-provenance attestation verifies with cosign against that
  repository's release workflow at that exact tag;
- `--version` names the tag.

It never stops your VMs. It swaps the binary and kills the agent, systemd
restarts it, and the new agent re-adopts the running VMs. If no heartbeat
follows within 5 minutes it puts the previous binary back and never
retries that tag.

```sh
journalctl -t hippius-miner-update -n 50       # what it did and why
cat /var/lib/hippius-miner/installed-release
```

**Opting out:**

- Right away: `sudo touch /var/lib/hippius-miner/.no-auto-update`.
- Durably: set `miner_auto_update_enabled: false` in host_vars and run the
  play with `--tags miner_auto_update`.

Then upgrade by hand as described in
[`miner-tasks/AUTO_UPDATE.md`](../../deploy/ansible/playbooks/miner-tasks/AUTO_UPDATE.md).
To verify a release yourself, follow
[Verifying a release by hand](./onboarding-a-miner.md#verifying-a-release-by-hand).

---

## See also

- [`onboarding-a-miner.md`](./onboarding-a-miner.md): full reference,
  including the manual (non-dashboard) registration path
- [`deploy/ansible/README.md`](../../deploy/ansible/README.md): the bootstrap in detail
- [`docs/design/permissionless-miner-auth.md`](../design/permissionless-miner-auth.md): why no certificate authority vouches for your node
- [`docs/security/data-visibility.md`](../security/data-visibility.md): what you, as host operator, can and cannot see
